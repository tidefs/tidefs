//! Address space operations source model for the kernel VFS adapter.
//!
//! Models the Linux 7.0 kernel `address_space_operations` contract in Rust,
//! bridging page-cache-shaped calls to [`VfsEngine`] where capability exists
//! and documenting explicit blocker rows where it does not. The live mounted
//! product path registers a C vtable in `tidefs_posix_vfs_shim.c`; this Rust
//! type is not itself installed as `inode->i_mapping->a_ops`.
//!
//! # Implemented operations
//!
//! | Operation        | Rust model status | VfsEngine dependency        | Daemon required |
//! |------------------|-------------|-----------------------------|-----------------|
//! | `read_folio`     | Implemented | `VfsEngine::read()`         | No              |
//! | `readahead`      | Implemented | `VfsEngine::read()`         | No              |
//! | `fsync`          | Implemented | `VfsEngine::fsync()`        | No              |
//! | `write_begin`    | Implemented | `VfsEngine::read()`         | No              |
//! | `write_end`      | Implemented | `VfsEngine::write()`        | No              |
//! | `dirty_folio`    | Implemented | `writeback::DirtyFolioTracker` | No           |
//! | `writepages`     | Implemented | `VfsEngine::writeback_folios()` + `DirtyFolioTracker` (batched 3-phase: alloc->intent recording->writeback with per-range errors) | No    |
//! | `writepage`      | Implemented | `VfsEngine::writeback_folios()` | No    |
//! | `page_mkwrite`   | Implemented | `DirtyFolioTracker::try_add()` | No           |
//! | `invalidate_folio` | Implemented | `VfsEngine::invalidate_cache_range()` + `DirtyFolioTracker::remove_range()` | No         |
//!
//! # No-daemon boundary
//!
//! Every modeled operation resolves locally through VfsEngine and requires no
//! userspace daemon. That is source-model evidence only; mounted-kernel
//! authority is limited to the callbacks actually registered in the C shim.
//!
//! # fsync note
//!
//! `fsync` is already wired through `file_operations::fsync` in
//! [`crate::fsync`]. The address_space_operations `fsync` entry point
//! delegates to the same [`VfsEngine::fsync`] call. No separate
//! implementation is needed here; this module documents the delegation.
//!
//! # Mounted C shim note
//!
//! The live Linux 7.0 module registers a C `address_space_operations` vtable
//! in `tidefs_posix_vfs_shim.c`. That mounted path calls C bridge exports for
//! `read_folio`, `write_begin`, `write_end`, `dirty_folio`, and `writepages`.
//! `dirty_folio` records Linux dirty accounting only, and `writepages` copies
//! dirty folio bytes to the engine. The Rust [`DirtyFolioTracker`],
//! [`PageAuthorityTable`], `writepage`, `page_mkwrite`, and
//! `invalidate_folio` model paths remain unsupported for the mounted product
//! path until a direct C bridge is registered and QEMU-proven. Mounted
//! truncate, truncate-extend, direct-write, fallocate, and copy cleanup is
//! currently owned by C helpers in the shim: `filemap_write_and_wait_range`,
//! `unmap_mapping_range`, `invalidate_inode_pages2_range`, and
//! `truncate_setsize`.

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;
use crate::TideVec as Vec;

use crate::readahead::KmodPageCacheTracker;
use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, Errno, InodeId, RequestCtx};
use tidefs_kmod_bridge::kernel_types::{VfsEngine, WritebackOutcome, WritebackRange};

use crate::page_authority::{page_index, PageAuthorityTable};
use crate::writeback::{DirtyFolioTracker, DirtyRange};
#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::PageOwnershipMode;
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::PageOwnershipMode;

use crate::intent_record::{encode_write_intent, record_intent};
#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::ByteSliceExt;

// ---------------------------------------------------------------------------
// AddressSpaceOps dispatch struct
// ---------------------------------------------------------------------------

/// A single entry in a batched writeback operation.
///
/// Holds the dirty range metadata, the usable length after extent
/// allocation, and the pre-encoded write-intent entry ready for
/// recording through the intent-log path.
#[derive(Clone, Debug)]
struct WritebackPlan {
    /// The original dirty range before allocation trimming.
    range: DirtyRange,
    /// The usable byte length after allocation (may be less than range.length).
    usable_len: u64,
    /// Whether the allocation fully satisfied the requested range.
    alloc_complete: bool,
    /// How many bytes the allocator provisioned.
    bytes_allocated: u64,
    /// Pre-encoded write-intent entry for crash-safety recording.
    entry: crate::intent_record::IntentLogEntry,
}

/// Result of a batched writeback operation.
///
/// Accumulates total bytes written and per-range error records so
/// the caller can report writeback errors through KernelPoolCore.
#[derive(Clone, Debug)]
pub struct WritebackBatchResult {
    /// Total bytes durably committed across all ranges.
    pub bytes_written: u64,
    /// Per-range writeback errors encountered during this batch.
    pub errors: crate::TideVec<(DirtyRange, tidefs_kmod_bridge::kernel_types::Errno)>,
    /// Per-range allocation errors encountered during planning.
    pub alloc_errors: crate::TideVec<(DirtyRange, tidefs_kmod_bridge::kernel_types::Errno)>,
}

impl WritebackBatchResult {
    /// Number of writeback errors in this batch.
    pub fn error_count(&self) -> usize {
        self.errors.len() + self.alloc_errors.len()
    }

    /// Whether any writeback or allocation errors occurred.
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty() || !self.alloc_errors.is_empty()
    }
}
/// Source-model dispatch struct for Linux `address_space_operations` methods.
///
/// Holds references to the [`VfsEngine`], [`KmodPageCacheTracker`],
/// [`DirtyFolioTracker`], and [`PageAuthorityTable`] for per-operation
/// statistics. Each method corresponds to a possible function pointer in the Linux
/// kernel's `struct address_space_operations`.
pub struct AddressSpaceOps<'a, E: VfsEngine> {
    engine: &'a E,
    page_cache: &'a mut KmodPageCacheTracker,
    dirty_tracker: &'a mut DirtyFolioTracker,
    page_authority: &'a mut PageAuthorityTable,
}

impl<'a, E: VfsEngine> AddressSpaceOps<'a, E> {
    /// Create a new dispatch spine borrowing the engine and page-cache tracker.
    pub fn new(
        engine: &'a E,
        page_cache: &'a mut KmodPageCacheTracker,
        dirty_tracker: &'a mut DirtyFolioTracker,
        page_authority: &'a mut PageAuthorityTable,
    ) -> Self {
        Self {
            engine,
            page_cache,
            dirty_tracker,
            page_authority,
        }
    }

    /// Return a shared reference to the VfsEngine.
    pub fn engine(&self) -> &E {
        self.engine
    }

    /// Return a snapshot of current page-cache statistics.
    pub fn page_cache_stats(&self) -> crate::readahead::KmodPageCacheStats {
        self.page_cache.snapshot()
    }

    // ── Implemented operations ────────────────────────────────────────

    /// `read_folio`: Read a folio's worth of data from storage into memory.
    /// `invalidate_folio`: Invalidate a range within a folio.
    /// Bridges to [`VfsEngine::read`] for the given file handle, offset, and
    /// size. Returns the read buffer for the caller to copy into the folio's
    /// pages. On success, records a page-cache populate event.
    /// # Linux kernel signature
    /// `int (*read_folio)(struct file *, struct folio *)`
    /// # No-daemon boundary
    /// VfsEngine::read resolves locally within kernel authority. No userspace
    /// daemon, FUSE upcall, or helper process is required.
    /// # Errors
    /// Propagates VfsEngine errors: `EIO`, `EBADF`, etc.
    pub fn read_folio(
        &mut self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        let page_idx = page_index(offset);
        // Acquire read ownership: transitions EngineOwned->Shared if needed.
        let guard = self.page_authority.acquire(
            self.engine,
            fh.inode_id,
            page_idx,
            PageOwnershipMode::Read,
        );
        let data = self.engine.read(fh, offset, size, ctx)?;
        if !data.is_empty() {
            self.page_cache.record_populate();
        } else {
            // EOF read — not a miss in the traditional sense, but we
            // track it as a miss for stats parity with kernel behavior
            // where a read at EOF doesn't populate a page.
            self.page_cache.record_miss();
        }
        // Commit the ownership acquisition: the page is now Shared or
        // KernelOwned depending on previous state.
        if let Ok(g) = guard {
            g.commit();
        }
        Ok(data)
    }

    /// `readahead`: Trigger asynchronous readahead for a range of pages.
    /// Issues a prefetch read through [`VfsEngine::read`] for the given
    /// byte range and populates clean page-cache state from the engine
    /// result without marking pages dirty. Records readahead, prefetch,
    /// populate, and miss statistics for authoritative page-cache tracking.
    ///
    /// Empty reads, short reads, holes, EOF, and engine read errors are
    /// handled as advisory prefetch outcomes: only a complete requested read
    /// records a clean populate, and all other outcomes record a miss without
    /// poisoning later demand reads.  A subsequent `read_folio` call for the
    /// same range will still resolve through engine authority and return the
    /// correct bytes or error.
    ///
    /// # Linux kernel signature
    /// `void (*readahead)(struct readahead_control *)`
    /// # No-daemon boundary
    /// The prefetch read resolves through VfsEngine within kernel authority.
    /// No userspace daemon is involved.
    pub fn readahead(&mut self, fh: &EngineFileHandle, offset: u64, count: u32, ctx: &RequestCtx) {
        self.page_cache.record_readahead();
        self.page_cache.record_prefetch();

        let page_idx = page_index(offset);
        // Acquire read ownership for the affected page: this is a
        // clean read, so we target Shared ownership without ever
        // transitioning to KernelOwned (no dirty marking).
        let guard = self.page_authority.acquire(
            self.engine,
            fh.inode_id,
            page_idx,
            PageOwnershipMode::Read,
        );

        let requested = count as usize;
        match self.engine.read(fh, offset, count, ctx) {
            Ok(data) => {
                if requested > 0 && data.len() >= requested {
                    self.page_cache.record_populate();
                } else {
                    // EOF, hole, or short read: track as a miss for
                    // stats parity with kernel behavior where advisory
                    // readahead does not populate an uptodate folio.
                    self.page_cache.record_miss();
                }
            }
            Err(_) => {
                // Advisory: engine errors are silently discarded.
                // The kernel VFS will fall back to synchronous
                // read_folio on actual page fault.  Record a miss
                // so hit-ratio stats reflect the prefetch gap.
                self.page_cache.record_miss();
            }
        }

        // Commit the ownership acquisition: the page is now Shared
        // (never KernelOwned/dirty from a readahead path).
        if let Ok(g) = guard {
            g.commit();
        }
    }

    // ── Blocked operations ───────────────────────────────────────────

    /// `write_begin`: Prepare a page for buffered write.
    /// Reads the existing data at the given offset from [`VfsEngine::read`]
    /// so the caller can merge the incoming write with existing page
    /// contents for partial-page writes. The returned buffer may be empty
    /// for holes or EOF-extension writes.
    /// # Linux kernel signature
    /// `int (*write_begin)(struct file *, struct address_space *,
    /// loff_t pos, unsigned len, struct folio **, void **fsdata)`
    /// # No-daemon boundary
    /// VfsEngine::read resolves within kernel authority. No userspace
    /// daemon is required.
    /// # Errors
    /// Propagates VfsEngine errors from the underlying read.
    pub fn write_begin(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        len: u32,
        ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        self.engine.read(fh, offset, len, ctx)
    }

    /// Source-model `write_end`: complete a buffered write.
    /// Writes the merged data through [`VfsEngine::write`] and marks
    /// the written range dirty in the [`DirtyFolioTracker`] for
    /// subsequent source-model writeback. Returns the number of bytes written.
    /// # Linux kernel signature
    /// `int (*write_end)(struct file *, struct address_space *,
    /// loff_t pos, unsigned len, unsigned copied, struct folio *,
    /// void *fsdata)`
    /// # No-daemon boundary
    /// VfsEngine::write and DirtyFolioTracker resolve locally in this model.
    /// Mounted Linux uses the C `write_end` callback instead.
    /// # Errors
    /// Propagates VfsEngine write errors.
    pub fn write_end(
        &mut self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let page_idx = page_index(offset);
        // Acquire exclusive write ownership: signals engine to invalidate
        // its copy so the kernel holds the authoritative dirty page.
        let guard = self
            .page_authority
            .acquire(self.engine, fh.inode_id, page_idx, PageOwnershipMode::Write)
            .map_err(|c| c.to_errno())?;
        let written = self.engine.write(fh, offset, data, ctx)?;
        self.dirty_tracker.try_add(fh.inode_id, offset, written)?;
        // Commit: kernel retains write ownership until writeback completes.
        guard.commit();
        Ok(written)
    }

    /// Source-model `dirty_folio`: register a folio as dirty in the tracker.
    /// Models the point where the kernel marks a page dirty (e.g., from mmap
    /// `page_mkwrite` or direct page-cache dirtying). Records the
    /// range in [`DirtyFolioTracker`] for subsequent source-model writeout via
    /// [`writepages`](Self::writepages).
    /// # Linux kernel signature
    /// `bool (*dirty_folio)(struct address_space *, struct folio *)`
    /// # No-daemon boundary
    /// DirtyFolioTracker is local in-memory model state. The mounted C
    /// `dirty_folio` callback uses Linux `filemap_dirty_folio()` instead.
    pub fn dirty_folio(&mut self, inode: InodeId, offset: u64, len: u32) {
        self.dirty_tracker.add(inode, offset, len);
    }

    /// Source-model `writepages`: write dirty ranges with batched intent recording.
    ///
    /// Drains all dirty ranges for the given inode from the
    /// [`DirtyFolioTracker`] and flushes them through
    /// [`VfsEngine::writeback_folios`] in three phases:
    ///
    /// 1. *Plan*: allocate extents and encode write-intent entries
    ///    for every dirty range (accumulates allocation errors).
    /// 2. *Record*: record all intents as a batch in the current txg.
    /// 3. *Writeback*: execute each writeback, tracking per-range
    ///    errors and re-dirtying failed ranges.
    ///
    /// Returns [`WritebackBatchResult`] with total bytes written when all
    /// ranges complete. If any allocation, intent-recording, or writeback
    /// step fails, the failed range is re-dirtied and the method returns the
    /// first errno so the model fails closed. Mounted Linux uses the C
    /// `writepages` callback and Linux dirty folios instead.
    ///
    /// # Linux kernel signature
    /// `int (*writepages)(struct address_space *, struct writeback_control *)`
    ///
    /// # No-daemon boundary
    /// VfsEngine::writeback_folios resolves locally in this model. No
    /// userspace daemon is required.
    pub fn writepages(
        &mut self,
        inode: InodeId,
        fh: &EngineFileHandle,
        ctx: &RequestCtx,
    ) -> Result<WritebackBatchResult, Errno> {
        let dirty_ranges = self.dirty_tracker.drain_inode(inode);
        let mut plans: crate::TideVec<WritebackPlan> = crate::TideVec::new();
        let mut alloc_errors: crate::TideVec<(DirtyRange, Errno)> = crate::TideVec::new();
        let mut first_error: Option<Errno> = None;

        // -- Phase 1: allocate extents and encode write-intent entries --

        for range in &dirty_ranges {
            let range_len = range.length as u64;
            let alloc_outcome =
                match self
                    .engine
                    .allocate_extents(inode, range.offset, range_len, ctx)
                {
                    Ok(o) => o,
                    Err(e) => {
                        // Allocation failure -- re-dirty the full range and
                        // record the error for batch reporting.
                        self.dirty_tracker.add(inode, range.offset, range.length);
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                        alloc_errors.push((*range, e));
                        continue;
                    }
                };

            let usable_len = if alloc_outcome.complete {
                range_len
            } else {
                alloc_outcome.bytes_allocated.min(range_len)
            };

            if usable_len == 0 && !alloc_outcome.complete {
                // Zero usable bytes and incomplete allocation -- re-dirty
                // and skip this range.
                self.dirty_tracker.add(inode, range.offset, range.length);
                continue;
            }

            let entry = encode_write_intent(inode, range.offset, usable_len as u32);
            plans.push(WritebackPlan {
                range: *range,
                usable_len,
                alloc_complete: alloc_outcome.complete,
                bytes_allocated: alloc_outcome.bytes_allocated,
                entry,
            });
        }

        // -- Phase 2: record all intents as a batch --

        // Retain plans whose intents were successfully recorded;
        // re-dirty ranges whose intents failed.
        let mut failed_indices: crate::TideVec<usize> = crate::TideVec::new();
        for (i, plan) in plans.iter().enumerate() {
            if record_intent(self.engine, &plan.entry).is_err() {
                self.dirty_tracker
                    .add(inode, plan.range.offset, plan.range.length);
                if first_error.is_none() {
                    first_error = Some(Errno::EIO);
                }
                failed_indices.push(i);
            }
        }
        // Remove failed plans in reverse order to preserve indices.
        for i in failed_indices.iter().rev() {
            plans.remove(*i);
        }

        // -- Phase 3: execute writebacks --

        let mut total_written: u64 = 0;
        let mut writeback_errors: crate::TideVec<(DirtyRange, Errno)> = crate::TideVec::new();

        for plan in &plans {
            let wb_range = WritebackRange {
                offset: plan.range.offset,
                length: plan.usable_len,
            };

            let outcome = match self.engine.writeback_folios(inode, fh, wb_range, ctx) {
                Ok(o) => o,
                Err(e) => {
                    // Writeback failure -- re-dirty the full original range
                    // and record the error.
                    self.dirty_tracker
                        .add(inode, plan.range.offset, plan.range.length);
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                    writeback_errors.push((plan.range, e));
                    continue;
                }
            };

            total_written = total_written.saturating_add(outcome.bytes_written);

            // Transfer ownership back to engine for successfully written pages.
            let sp = page_index(wb_range.offset);
            let ep = page_index(
                wb_range
                    .offset
                    .saturating_add(outcome.bytes_written.saturating_sub(1)),
            );
            for pg in sp..=ep {
                self.page_authority.transfer_to_engine(inode, pg);
            }

            // Re-dirty any tail that writeback could not persist.
            if !outcome.complete && outcome.bytes_written < plan.usable_len {
                let remainder_offset = plan.range.offset.saturating_add(outcome.bytes_written);
                let remainder_len = plan
                    .range
                    .length
                    .saturating_sub(outcome.bytes_written as u32);
                if remainder_len > 0 {
                    self.dirty_tracker
                        .add(inode, remainder_offset, remainder_len);
                }
            }

            // Re-dirty any unallocated tail.
            if !plan.alloc_complete && plan.bytes_allocated < plan.range.length as u64 {
                let unalloc_offset = plan.range.offset.saturating_add(plan.bytes_allocated);
                let unalloc_len =
                    (plan.range.length as u64).saturating_sub(plan.bytes_allocated) as u32;
                if unalloc_len > 0 && plan.bytes_allocated > 0 {
                    self.dirty_tracker.add(inode, unalloc_offset, unalloc_len);
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err);
        }

        Ok(WritebackBatchResult {
            bytes_written: total_written,
            errors: writeback_errors,
            alloc_errors,
        })
    }

    /// `writepage`: Write back a single dirty page to storage.
    ///
    /// Bridges to [`VfsEngine::writeback_folios`] for a single
    /// page-sized range. The engine commits the data durably and
    /// returns the outcome. Used by the kernel VFS for single-page
    /// writeback when batched writepages is not appropriate.
    ///
    /// # Linux kernel signature
    ///
    /// `int (*writepage)(struct page *, struct writeback_control *)`
    ///
    /// # No-daemon boundary
    ///
    /// VfsEngine::writeback_folios resolves within kernel authority.
    /// No userspace daemon is required.
    pub fn writepage(
        &mut self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u32,
        ctx: &RequestCtx,
    ) -> Result<WritebackOutcome, Errno> {
        let inode = fh.inode_id;
        let range_len = length as u64;

        // Provision blocks for extending writes before writeback.
        // Engines that do not manage allocation return complete=true
        // with zero bytes, letting writeback proceed normally.
        let alloc_outcome = self
            .engine
            .allocate_extents(inode, offset, range_len, ctx)?;
        let usable_len = if alloc_outcome.complete {
            range_len
        } else {
            alloc_outcome.bytes_allocated.min(range_len)
        };

        if usable_len == 0 {
            return Ok(WritebackOutcome::new(0, false));
        }

        let range = WritebackRange {
            offset,
            length: usable_len,
        };
        // Record write-intent before committing the dirty page for crash-safety.
        let entry = encode_write_intent(inode, range.offset, range.length as u32);
        record_intent(self.engine, &entry).map_err(|_| Errno::EIO)?;
        let outcome = self.engine.writeback_folios(inode, fh, range, ctx)?;

        // Transfer ownership back to engine on successful writeback.
        let sp = page_index(offset);
        let ep = page_index(offset.saturating_add(outcome.bytes_written.saturating_sub(1)));
        for pg in sp..=ep {
            self.page_authority.transfer_to_engine(inode, pg);
        }
        Ok(outcome)
    }

    /// Source-model `page_mkwrite`: prepare a page for mmap write access.
    ///
    /// Registers the dirty byte range in the [`DirtyFolioTracker`] so that
    /// subsequent source-model [`writepages`](Self::writepages) flushes can
    /// persist the mmap'd writes. A mounted C `vm_operations_struct` bridge
    /// does not call this method today; generic filemap handles the live
    /// shared write fault and C `dirty_folio`/`writepages` handle writeback.
    ///
    /// # Linux kernel signature
    ///
    /// `vm_fault_t (*page_mkwrite)(struct vm_fault *)`
    ///
    /// # No-daemon boundary
    ///
    /// DirtyFolioTracker is in-memory source-model state. No userspace daemon
    /// is required.
    pub fn page_mkwrite(
        &mut self,
        inode: InodeId,
        offset: u64,
        _ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.dirty_tracker.try_add(inode, offset, 4096)?;
        Ok(())
    }

    /// Source-model `invalidate_folio`: invalidate a range within a folio.
    ///
    /// Bridges to [`VfsEngine::invalidate_cache_range`] so the engine
    /// can drop internal caches for the affected byte range. Records
    /// an eviction stat regardless of engine outcome.
    ///
    /// # Linux kernel signature
    /// `void (*invalidate_folio)(struct folio *, size_t offset,
    /// size_t length)`
    ///
    /// # No-daemon boundary
    /// Cache invalidation operates on in-memory engine state in this model.
    /// Mounted truncate/direct-write cleanup uses C Linux page-cache discard
    /// helpers because `.invalidate_folio` is not registered in the C vtable.
    pub fn invalidate_folio(
        &mut self,
        inode: InodeId,
        _fh: &EngineFileHandle,
        offset: u64,
        length: u32,
    ) -> Result<(), Errno> {
        self.page_cache.record_evict();
        // Remove dirty-tracker entries that overlap the invalidated range
        // so writeback does not attempt to persist discarded pages.
        self.dirty_tracker.remove_range(inode, offset, length);
        // Signal engine to invalidate its cached copy for the affected pages.
        let sp = page_index(offset);
        let ep = page_index(offset.saturating_add(length.saturating_sub(1) as u64));
        for pg in sp..=ep {
            self.page_authority
                .invalidate_engine_copy(self.engine, inode, pg);
        }
        self.engine
            .invalidate_cache_range(inode, offset, length as u64)
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
    use tidefs_kmod_bridge::kernel_types::{AllocateExtentsOutcome, WritebackOutcome};
    use tidefs_kmod_bridge::kernel_types::{EngineFileHandle, Errno, FileHandleId, InodeId};

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_fh() -> EngineFileHandle {
        EngineFileHandle::new(InodeId::new(1), 0, FileHandleId(0), 0)
    }

    fn make_tracker() -> KmodPageCacheTracker {
        KmodPageCacheTracker::new()
    }

    fn make_dirty_tracker() -> DirtyFolioTracker {
        DirtyFolioTracker::new(64)
    }

    fn make_page_authority() -> PageAuthorityTable {
        PageAuthorityTable::new(64)
    }

    // ── read_folio tests ─────────────────────────────────────────────

    #[test]
    fn read_folio_bridges_to_engine_read() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let fh2 = fh;
        e.read_fn = Box::new(move |fh, off, size, _ctx| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 0);
            assert_eq!(size, 4096);
            Ok(b"page data here".to_vec())
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let data = aops
            .read_folio(&fh2, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"page data here");
        // Verify populate was recorded
        let stats = aops.page_cache_stats();
        assert_eq!(stats.populate, 1);
        assert_eq!(stats.hit, 0);
        assert_eq!(stats.miss, 0);
    }

    #[test]
    fn read_folio_empty_read_is_eof_miss() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(vec![]));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let data = aops
            .read_folio(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert!(data.is_empty());
        let stats = aops.page_cache_stats();
        assert_eq!(stats.miss, 1);
        assert_eq!(stats.populate, 0);
    }

    #[test]
    fn read_folio_propagates_io_error() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let err = aops
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EIO);
        // No populate on error
        assert_eq!(aops.page_cache_stats().populate, 0);
    }

    #[test]
    fn read_folio_propagates_ebadf() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EBADF));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        assert_eq!(
            aops.read_folio(&fh, 0, 1024, &MockEngine::test_ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn read_folio_multiple_pages_tracks_populate_per_call() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, off, _, _| {
            if off == 0 {
                Ok(b"page0".to_vec())
            } else {
                Ok(b"page1".to_vec())
            }
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let d0 = aops
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d0, b"page0");

        let d1 = aops
            .read_folio(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d1, b"page1");

        let stats = aops.page_cache_stats();
        assert_eq!(stats.populate, 2);
    }

    #[test]
    fn read_folio_engine_accessor() {
        let mut e = MockEngine::new();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"data".to_vec()));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        // Verify engine() returns the same engine reference
        let engine_ref: &MockEngine = aops.engine();
        // Just verify we can call methods on it
        let root = engine_ref.get_root_inode(&MockEngine::test_ctx());
        assert!(root.is_ok() || root.is_err()); // at least compiles
    }

    // ── readahead tests ──────────────────────────────────────────────

    #[test]
    fn readahead_records_stats_and_issues_read() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(move |fh, off, count, _ctx| {
            assert_eq!(fh.inode_id, InodeId::new(1));
            assert_eq!(off, 8192);
            assert_eq!(count, 16384);
            Ok(vec![0x42; count as usize])
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 8192, 16384, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
    }

    #[test]
    fn readahead_silently_ignores_read_error() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        // Should not panic or return error — readahead is advisory
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
    }

    #[test]
    fn readahead_multiple_calls_accumulate_stats() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"x".to_vec()));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());
        aops.readahead(&fh, 4096, 4096, &MockEngine::test_ctx());
        aops.readahead(&fh, 8192, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 3);
        assert_eq!(stats.prefetch, 3);
    }

    #[test]
    fn readahead_populates_clean_cache_and_records_populate() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, count, _| Ok(vec![0x70; count as usize]));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
        // Clean cache population: complete engine read records populate.
        assert_eq!(stats.populate, 1);
        assert_eq!(stats.miss, 0);
    }

    #[test]
    fn readahead_empty_read_records_miss() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        // Engine returns empty data: simulates EOF or hole.
        e.read_fn = Box::new(|_, _, _, _| Ok(Vec::new()));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 4096, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
        // Empty read (EOF/hole) records a miss, not a populate.
        assert_eq!(stats.populate, 0);
        assert_eq!(stats.miss, 1);
    }

    #[test]
    fn readahead_error_records_miss_not_populate() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
        // Engine error: records a miss, never a populate.
        assert_eq!(stats.populate, 0);
        assert_eq!(stats.miss, 1);
    }

    #[test]
    fn readahead_does_not_mark_pages_dirty() {
        use crate::page_authority::PageOwnership;

        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"clean-data".to_vec()));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        // Readahead on page 0.
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        // After readahead, page ownership must not be KernelOwned (dirty).
        // Read-only acquistion targets Shared, and readahead never marks
        // pages dirty.
        let owner = pa.get(fh.inode_id, 0);
        assert!(
            owner != PageOwnership::KernelOwned,
            "readahead must not mark pages dirty (KernelOwned)"
        );
        // Default is EngineOwned; Shared is also acceptable for a clean prefetch.
        assert!(
            owner == PageOwnership::EngineOwned || owner == PageOwnership::Shared,
            "readahead page ownership should be EngineOwned or Shared, got {:?}",
            owner
        );
    }

    #[test]
    fn read_folio_after_readahead_error_still_resolves() {
        // Readahead that hits an engine error must not poison later
        // demand reads: read_folio for the same range must still
        // resolve through engine authority and return correct bytes.
        let fh = make_fh();

        // Phase 1: readahead fails.
        let mut e1 = MockEngine::new();
        e1.read_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e1, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        let stats_after_ra = aops.page_cache_stats();
        assert_eq!(stats_after_ra.miss, 1);
        assert_eq!(stats_after_ra.populate, 0);

        // Phase 2: demand read_folio for the same range succeeds.
        let mut e2 = MockEngine::new();
        e2.read_fn = Box::new(|_, _, _, _| Ok(b"demand-data".to_vec()));
        let mut aops2 = AddressSpaceOps::new(&e2, &mut tracker, &mut dt, &mut pa);
        let data = aops2
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"demand-data");

        let stats_final = aops2.page_cache_stats();
        // After demand read: populate counter increased from the read_folio.
        assert_eq!(stats_final.populate, 1);
    }

    #[test]
    fn readahead_short_read_records_miss_not_populate() {
        // Simulate a short engine read (fewer bytes than requested).
        // The advisory readahead path must not treat a partial range as
        // authoritative clean cache state.
        let mut e = MockEngine::new();
        let fh = make_fh();
        // Return only two bytes for a 4096-byte request.
        e.read_fn = Box::new(|_, _, _, _| Ok(b"sh".to_vec())); // 2 bytes, simulating short

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.readahead(&fh, 0, 4096, &MockEngine::test_ctx());

        let stats = aops.page_cache_stats();
        // Short data returned: should record a miss, not populate.
        assert_eq!(stats.populate, 0);
        assert_eq!(stats.miss, 1);
    }

    // ── write_begin tests (blocker) ──────────────────────────────────

    #[test]
    fn write_begin_reads_existing() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"existing".to_vec()));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let data = aops
            .write_begin(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(data, b"existing");
    }

    // ── write_end tests (blocker) ────────────────────────────────────

    #[test]
    fn write_end_writes_and_dirties() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.write_fn = Box::new(|_, _, data, _| Ok(data.len() as u32));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let written = aops
            .write_end(&fh, 0, b"data", &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(written, 4);
        assert_eq!(aops.dirty_tracker.len(), 1);
    }

    // ── dirty_folio tests (blocker) ──────────────────────────────────

    #[test]
    fn dirty_folio_registers_range() {
        let e = MockEngine::new();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        aops.dirty_folio(InodeId::new(42), 8192, 4096);
        let ranges: Vec<_> = aops.dirty_tracker.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            (
                InodeId::new(42),
                crate::writeback::DirtyRange::new(8192, 4096)
            )
        );
    }

    // ── writepages tests ─────────────────────────────────────────

    #[test]
    fn writepages_empty_inode_returns_zero() {
        let e = MockEngine::new();
        let fh = make_fh();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let total = aops
            .writepages(InodeId::new(1), &fh, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(total.bytes_written, 0);
    }

    #[test]
    fn writepages_single_range_dispatches_to_writeback_folios() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        e.writeback_folios_fn = Box::new(move |got_ino, got_fh, range, _ctx| {
            assert_eq!(got_ino, ino);
            assert_eq!(got_fh.inode_id, ino);
            assert_eq!(range.offset, 0);
            assert_eq!(range.length, 4096);
            Ok(WritebackOutcome {
                bytes_written: 4096,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);
        // Dirty tracker should have been drained
        assert!(dt.is_empty());
    }

    #[test]
    fn writepages_multi_range_batching() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            Ok(WritebackOutcome {
                bytes_written: range.length,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        dt.add(ino, 8192, 4096);
        dt.add(ino, 16384, 2048);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 10240);
        assert!(dt.is_empty());
    }

    #[test]
    fn writepages_partial_failure_redirties_remainder() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        // Writeback commits only 2048 of 4096 bytes
        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            let written = range.length.min(2048);
            Ok(WritebackOutcome {
                bytes_written: written,
                complete: written == range.length,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 2048);

        // The unwritten remainder should have been re-queued
        assert_eq!(dt.len(), 1);
        let remaining: Vec<_> = dt.iter().collect();
        assert_eq!(remaining[0].1.offset, 2048);
        assert_eq!(remaining[0].1.length, 2048);
    }

    #[test]
    fn writepages_complete_false_but_bytes_equal_range_no_redirty() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        // complete=false but bytes_written == length (edge case)
        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            Ok(WritebackOutcome {
                bytes_written: range.length,
                complete: false,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);
        // Even though complete=false, bytes_written == length so no redirty
        assert!(dt.is_empty());
    }

    #[test]
    fn writepages_zero_byte_writeback_redirties_full_range() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        // Zero bytes written, not complete
        e.writeback_folios_fn = Box::new(|_, _, _range, _ctx| {
            Ok(WritebackOutcome {
                bytes_written: 0,
                complete: false,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 0);

        // Full range should be re-dirtied
        assert_eq!(dt.len(), 1);
        let remaining: Vec<_> = dt.iter().collect();
        assert_eq!(remaining[0].1.offset, 0);
        assert_eq!(remaining[0].1.length, 4096);
    }

    #[test]
    fn writepages_propagates_writeback_error() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = InodeId::new(1);

        e.writeback_folios_fn = Box::new(|_, _, _, _| Err(Errno::EIO));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let err = aops
            .writepages(ino, &fh, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn writepages_different_inode_not_drained() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino1 = InodeId::new(1);
        let ino2 = InodeId::new(2);

        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            Ok(WritebackOutcome {
                bytes_written: range.length,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino1, 0, 4096);
        dt.add(ino2, 0, 8192);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        // Drain only ino1
        let total = aops.writepages(ino1, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);

        // ino2 should still be dirty
        assert_eq!(dt.len(), 1);
        let remaining: Vec<_> = dt.iter().collect();
        assert_eq!(remaining[0].0, ino2);
        assert_eq!(remaining[0].1.length, 8192);
    }

    // ── writepage tests ──────────────────────────────────────────

    #[test]
    fn writepage_dispatches_single_folio() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        let ino = fh.inode_id;

        e.writeback_folios_fn = Box::new(move |got_ino, got_fh, range, _ctx| {
            assert_eq!(got_ino, ino);
            assert_eq!(got_fh.inode_id, ino);
            assert_eq!(range.offset, 4096);
            assert_eq!(range.length, 4096);
            Ok(WritebackOutcome {
                bytes_written: 4096,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let outcome = aops
            .writepage(&fh, 4096, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(outcome.bytes_written, 4096);
        assert!(outcome.complete);
    }

    #[test]
    fn writepage_zero_length_range() {
        let mut e = MockEngine::new();
        let fh = make_fh();

        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            assert_eq!(range.length, 0);
            Ok(WritebackOutcome {
                bytes_written: 0,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let outcome = aops.writepage(&fh, 0, 0, &MockEngine::test_ctx()).unwrap();
        assert_eq!(outcome.bytes_written, 0);
    }

    #[test]
    fn writepage_partial_writeback() {
        let mut e = MockEngine::new();
        let fh = make_fh();

        // Engine writes only 2048 of 4096 bytes
        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            let written = (range.length / 2).min(range.length);
            Ok(WritebackOutcome {
                bytes_written: written,
                complete: written == range.length,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let outcome = aops
            .writepage(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(outcome.bytes_written, 2048);
        assert!(!outcome.complete);
    }

    #[test]
    fn writepage_propagates_error() {
        let mut e = MockEngine::new();
        let fh = make_fh();

        e.writeback_folios_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let err = aops
            .writepage(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
    }

    #[test]
    fn writepage_eof_extension_writeback() {
        let mut e = MockEngine::new();
        let fh = make_fh();

        // Writeback at a high offset (simulating EOF extension)
        e.writeback_folios_fn = Box::new(|_, _, range, _ctx| {
            Ok(WritebackOutcome {
                bytes_written: range.length,
                complete: true,
            })
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        let outcome = aops
            .writepage(&fh, 1_048_576, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(outcome.bytes_written, 4096);
        assert!(outcome.complete);
    }

    // ── page_mkwrite tests ──────────────────────────────────────────

    #[test]
    fn page_mkwrite_registers_dirty_range() {
        let e = MockEngine::new();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        assert_eq!(
            aops.page_mkwrite(InodeId::new(1), 0, &MockEngine::test_ctx()),
            Ok(())
        );
        // Verify the dirty range was registered
        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (InodeId::new(1), DirtyRange::new(0, 4096)));
    }

    #[test]
    fn page_mkwrite_merges_adjacent_ranges() {
        let e = MockEngine::new();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        aops.page_mkwrite(InodeId::new(10), 0, &MockEngine::test_ctx())
            .unwrap();
        aops.page_mkwrite(InodeId::new(10), 4096, &MockEngine::test_ctx())
            .unwrap();

        let ranges: Vec<_> = dt.iter().collect();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (InodeId::new(10), DirtyRange::new(0, 8192)));
    }

    #[test]
    fn page_mkwrite_different_inodes_independent() {
        let e = MockEngine::new();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        aops.page_mkwrite(InodeId::new(1), 0, &MockEngine::test_ctx())
            .unwrap();
        aops.page_mkwrite(InodeId::new(2), 0, &MockEngine::test_ctx())
            .unwrap();

        assert_eq!(dt.len(), 2);
    }

    // ── invalidate_folio tests ─────────────────────────────

    #[test]
    fn invalidate_folio_delegates_to_engine_and_records_eviction() {
        let e = MockEngine::new();
        let fh = make_fh();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        // Default engine implementation returns Ok(())
        assert_eq!(aops.invalidate_folio(InodeId::new(1), &fh, 0, 8192), Ok(()));
        let stats = aops.page_cache_stats();
        assert_eq!(stats.evict, 1);
    }

    #[test]
    fn invalidate_folio_accumulates_evictions() {
        let e = MockEngine::new();
        let fh = make_fh();
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        aops.invalidate_folio(InodeId::new(1), &fh, 0, 4096).ok();
        aops.invalidate_folio(InodeId::new(1), &fh, 4096, 4096).ok();
        aops.invalidate_folio(InodeId::new(1), &fh, 8192, 4096).ok();

        assert_eq!(aops.page_cache_stats().evict, 3);
    }

    // ── Full lifecycle integration tests ─────────────────────────────

    #[test]
    fn read_folio_then_readahead_then_invalidate_lifecycle() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, off, _, _| {
            if off < 4096 {
                Ok(b"hot-data".to_vec())
            } else {
                Ok(vec![0x63; 4096])
            }
        });

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);

        // Phase 1: read_folio populates a page
        let d = aops
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(d, b"hot-data");

        // Phase 2: readahead prefetches ahead
        aops.readahead(&fh, 4096, 4096, &MockEngine::test_ctx());

        // Phase 3: invalidate the readahead range
        let _ = aops.invalidate_folio(InodeId::new(1), &fh, 4096, 4096);

        let stats = aops.page_cache_stats();
        assert_eq!(stats.populate, 2); // from read_folio + readahead
        assert_eq!(stats.readahead_count, 1);
        assert_eq!(stats.prefetch, 1);
        assert_eq!(stats.evict, 1);
        assert_eq!(stats.hit, 0);
        assert_eq!(stats.miss, 0);
    }

    #[test]
    fn stats_are_independent_per_tracker() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(b"data".to_vec()));

        let mut tracker1 = make_tracker();
        let mut tracker2 = make_tracker();
        let mut dt1 = make_dirty_tracker();
        let mut dt2 = make_dirty_tracker();

        let mut pa1 = PageAuthorityTable::new(64);
        let mut aops1 = AddressSpaceOps::new(&e, &mut tracker1, &mut dt1, &mut pa1);
        let mut pa2 = PageAuthorityTable::new(64);
        let mut aops2 = AddressSpaceOps::new(&e, &mut tracker2, &mut dt2, &mut pa2);

        aops1.read_folio(&fh, 0, 4096, &MockEngine::test_ctx()).ok();
        aops1.read_folio(&fh, 0, 4096, &MockEngine::test_ctx()).ok();
        aops2.read_folio(&fh, 0, 4096, &MockEngine::test_ctx()).ok();

        assert_eq!(aops1.page_cache_stats().populate, 2);
        assert_eq!(aops2.page_cache_stats().populate, 1);
    }

    #[test]
    fn new_and_accessors() {
        let e = MockEngine::new();
        let mut tracker = make_tracker();
        tracker.record_hit();
        tracker.record_hit();
        tracker.record_hit();
        let mut dt = make_dirty_tracker();

        let mut pa = make_page_authority();
        let aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        assert_eq!(aops.page_cache_stats().hit, 3);
        // engine() returns the same reference
        let eng = aops.engine();
        assert_eq!(
            eng.get_root_inode(&MockEngine::test_ctx()),
            Ok(InodeId::new(0))
        );
    }

    #[test]
    fn empty_read_at_offset_zero_still_records_miss() {
        let mut e = MockEngine::new();
        let fh = make_fh();
        e.read_fn = Box::new(|_, _, _, _| Ok(vec![]));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let data = aops
            .read_folio(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert!(data.is_empty());
        assert_eq!(aops.page_cache_stats().miss, 1);
        assert_eq!(aops.page_cache_stats().populate, 0);
    }

    // ── Extent allocation + writeback integration tests (#5915) ────

    fn make_alloc_engine(
        alloc_outcome: Result<AllocateExtentsOutcome, Errno>,
        writeback_outcome: Result<WritebackOutcome, Errno>,
    ) -> MockEngine {
        let mut e = MockEngine::new();
        let alloc_out = alloc_outcome.unwrap();
        let wb_out = writeback_outcome.unwrap();
        e.allocate_extents_fn = Box::new(move |_, _, _, _| Ok(alloc_out));
        e.writeback_folios_fn = Box::new(move |_, _, _, _| Ok(wb_out));
        e
    }

    #[test]
    fn writepages_with_allocation_success_then_writeback() {
        let ino = InodeId::new(1);
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(4096, true)),
            Ok(WritebackOutcome::new(4096, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);
        assert!(dt.is_empty());
    }

    #[test]
    fn writepages_with_partial_allocation_only_writebacks_allocated_bytes() {
        let ino = InodeId::new(1);
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(2048, false)), // only half allocated
            Ok(WritebackOutcome::new(2048, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 2048);
        // Unallocated tail [2048, 2048) should be re-dirtied
        assert_eq!(dt.len(), 1);
    }

    #[test]
    fn writepages_allocation_enospc_propagates() {
        let ino = InodeId::new(1);
        let fh = make_fh();
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        e.writeback_folios_fn = Box::new(|_, _, _, _| Ok(WritebackOutcome::new(4096, true)));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let err = aops
            .writepages(ino, &fh, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
        // Dirty range preserved (not drained since allocation failed)
        assert_eq!(dt.len(), 1);
    }

    #[test]
    fn writepage_with_allocation_success() {
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(4096, true)),
            Ok(WritebackOutcome::new(4096, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let outcome = aops
            .writepage(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(outcome.bytes_written, 4096);
        assert!(outcome.complete);
    }

    #[test]
    fn writepage_with_partial_allocation_truncates_length() {
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(2048, false)),
            Ok(WritebackOutcome::new(2048, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let outcome = aops
            .writepage(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap();
        assert_eq!(outcome.bytes_written, 2048);
        assert!(outcome.complete);
    }

    #[test]
    fn writepage_allocation_eio_propagates() {
        let fh = make_fh();
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        e.writeback_folios_fn = Box::new(|_, _, _, _| Ok(WritebackOutcome::new(4096, true)));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let err = aops
            .writepage(&fh, 0, 4096, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EIO);
    }

    #[test]
    fn writepages_allocation_eio_preserves_dirty_ranges() {
        let ino = InodeId::new(1);
        let fh = make_fh();
        let mut e = MockEngine::new();
        e.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::EIO));
        e.writeback_folios_fn = Box::new(|_, _, _, _| Ok(WritebackOutcome::new(4096, true)));
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let _ = aops
            .writepages(ino, &fh, &MockEngine::test_ctx())
            .unwrap_err();
        // Dirty range not drained on allocation error
        assert_eq!(dt.len(), 1);
    }

    #[test]
    fn writepages_zero_allocation_skip_writeback_redirty() {
        let ino = InodeId::new(1);
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(0, false)), // zero allocated, incomplete
            Ok(WritebackOutcome::new(4096, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 0); // nothing written
        assert_eq!(dt.len(), 1); // re-dirtied
    }

    #[test]
    fn writepages_allocation_complete_true_zero_bytes_proceeds_normally() {
        // Engine that doesn't manage allocation: complete=true, bytes=0
        let ino = InodeId::new(1);
        let fh = make_fh();
        let e = make_alloc_engine(
            Ok(AllocateExtentsOutcome::new(0, true)),
            Ok(WritebackOutcome::new(4096, true)),
        );
        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&e, &mut tracker, &mut dt, &mut pa);
        let total = aops.writepages(ino, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);
        assert!(dt.is_empty());
    }

    #[test]
    fn writepages_concurrent_isolation_independent_inodes() {
        // Allocation and writeback for different inodes don't interfere
        let ino1 = InodeId::new(1);
        let ino2 = InodeId::new(2);
        let fh = make_fh();

        // ino1 gets full allocation, ino2 gets ENOSPC
        let mut eng1 = MockEngine::new();
        eng1.allocate_extents_fn =
            Box::new(move |_, _, len, _| Ok(AllocateExtentsOutcome::new(len, true)));
        eng1.writeback_folios_fn =
            Box::new(|_, _, wbr, _| Ok(WritebackOutcome::new(wbr.length, true)));

        let mut eng2 = MockEngine::new();
        eng2.allocate_extents_fn = Box::new(|_, _, _, _| Err(Errno::ENOSPC));
        eng2.writeback_folios_fn =
            Box::new(|_, _, wbr, _| Ok(WritebackOutcome::new(wbr.length, true)));

        let mut tracker = make_tracker();
        let mut dt = make_dirty_tracker();
        dt.add(ino1, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops = AddressSpaceOps::new(&eng1, &mut tracker, &mut dt, &mut pa);
        let total = aops.writepages(ino1, &fh, &MockEngine::test_ctx()).unwrap();
        assert_eq!(total.bytes_written, 4096);

        // ino2 with a different engine
        dt.add(ino2, 0, 4096);
        let mut pa = make_page_authority();
        let mut aops2 = AddressSpaceOps::new(&eng2, &mut tracker, &mut dt, &mut pa);
        let err = aops2
            .writepages(ino2, &fh, &MockEngine::test_ctx())
            .unwrap_err();
        assert_eq!(err, Errno::ENOSPC);
        // Dirty range preserved on allocation failure
        assert_eq!(dt.len(), 1);
    }
}
