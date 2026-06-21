// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Page-cache ownership protocol for the kernel VFS adapter.
//!
//! Arbitrates dirty-page authority between the Linux kernel page cache
//! and [`VfsEngine`].  Tracks which entity owns the authoritative copy
//! of each cached page, handles invalidation on ownership transfer,
//! and resolves conflicts when both the kernel and engine hold dirty
//! copies.
//!
//! # Ownership model
//!
//! | State         | Meaning                                           |
//! |---------------|---------------------------------------------------|
//! | `EngineOwned` | Engine holds the authoritative (possibly dirty) copy. |
//! | `KernelOwned` | Kernel page cache holds the authoritative dirty copy. |
//! | `Shared`      | Both hold a clean copy; either may read without transfer. |
//!
//! # Transition rules
//!
//! - `EngineOwned → KernelOwned`: Kernel acquires write authority;
//!   engine invalidates its copy before returning.
//! - `KernelOwned → EngineOwned`: Writeback completes; kernel transfers
//!   authority back to engine.
//! - `Shared → KernelOwned`: Kernel wants to write; engine invalidates
//!   its copy.
//! - `Shared → EngineOwned`: Engine wants to modify (via external
//!   mutation); kernel invalidates its copy.
//!
//! # Lock ordering
//!
//! When multiple inodes or page indices are involved, always acquire
//! locks in (inode, page_idx) ascending order to prevent deadlock.
//!
//! # No-daemon boundary
//!
//! All ownership tracking is in-memory kernel-resident state.  The
//! engine callbacks (`page_ownership_acquired`, etc.) resolve within
//! kernel authority through [`VfsEngine`] default methods.
//!
//! # Mounted callback status
//!
//! The live Linux 7.0 C shim does not register this table or call it from
//! `vm_operations_struct`/`address_space_operations` callbacks. Mounted mmap
//! and writeback currently use Linux filemap state plus the registered C
//! `read_folio`, `dirty_folio`, and `writepages` callbacks. This module is a
//! Rust source model until a direct C bridge is added and validated.

// Kbuild: use crate::TideVec;
#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge;

#[cfg(CONFIG_RUST)]
use tidefs_kmod_bridge::kernel_types::PageOwnershipMode;
use tidefs_kmod_bridge::kernel_types::VfsEngine;
use tidefs_kmod_bridge::kernel_types::{Errno, InodeId};
#[cfg(not(CONFIG_RUST))]
use tidefs_vfs_engine::PageOwnershipMode;

/// Page size for ownership tracking (Linux PAGE_SIZE on amd64).
pub const PAGE_SIZE: u64 = 4096;

/// Convert a byte offset to a page index.
#[inline]
pub const fn page_index(offset: u64) -> u64 {
    offset / PAGE_SIZE
}

/// Page ownership state — which entity holds the authoritative copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageOwnership {
    /// Engine holds the authoritative (possibly dirty) copy.
    /// The kernel page cache must not hold a dirty copy.
    EngineOwned,
    /// Kernel page cache holds the authoritative dirty copy.
    /// The engine must invalidate its cached copy when this is set.
    KernelOwned,
    /// Both hold equivalent clean copies; either may read.
    /// Neither may modify until ownership is acquired.
    Shared,
    /// A newer dataset/inode/range generation superseded this page.
    /// The kernel page cache must not serve or clean this entry until
    /// the page is refilled or the dirty/writeback owner reconciles it.
    Fenced,
}

impl PageOwnership {
    /// Whether this state permits the kernel to read the page.
    pub const fn kernel_can_read(self) -> bool {
        matches!(self, PageOwnership::KernelOwned | PageOwnership::Shared)
    }

    /// Whether this state permits the kernel to write the page.
    pub const fn kernel_can_write(self) -> bool {
        matches!(self, PageOwnership::KernelOwned)
    }
}

/// Generation tuple for one kernel page-cache authority entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageGeneration {
    /// File-size generation that was current when the page was populated.
    pub file_size_generation: u64,
    /// Byte-range generation that was current when the page was populated.
    pub range_generation: u64,
    /// Local lease epoch that authorized the cached access.
    pub lease_epoch: u64,
}

impl PageGeneration {
    /// Construct a generation tuple whose file-size and range generations
    /// advance together for a destructive byte-range mutation.
    pub const fn range_fence(generation: u64) -> Self {
        Self {
            file_size_generation: generation,
            range_generation: generation,
            lease_epoch: 0,
        }
    }
}

/// Generation snapshot taken when a read, mmap fault, or writeback starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageGenerationSnapshot {
    inode: InodeId,
    page_idx: u64,
    generation: PageGeneration,
}

impl PageGenerationSnapshot {
    /// Inode covered by this snapshot.
    pub const fn inode(self) -> InodeId {
        self.inode
    }

    /// Page index covered by this snapshot.
    pub const fn page_idx(self) -> u64 {
        self.page_idx
    }

    /// Generation captured by this snapshot.
    pub const fn generation(self) -> PageGeneration {
        self.generation
    }
}

/// Error returned when an ownership acquisition fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnershipConflict {
    /// Write attempted when engine already holds a dirty copy that
    /// cannot be invalidated (e.g., engine-side mutation in progress).
    StaleWrite,
    /// Both kernel and engine hold dirty copies for the same page
    /// (programming error or race condition).
    DoubleDirty,
    /// Engine invalidation raced with an engine-side modification.
    InvalidationRace,
    /// The page index does not exist (out of range for the inode).
    OutOfRange,
    /// A generation fence superseded the cached page while it was in use.
    StaleGeneration,
    /// Requested mode upgrade (Shared→Write) failed because another
    /// thread holds a conflicting read lock (simplified model).
    UpgradeConflict,
}

impl OwnershipConflict {
    /// Convert to the closest POSIX errno.
    pub const fn to_errno(self) -> Errno {
        match self {
            OwnershipConflict::StaleWrite
            | OwnershipConflict::StaleGeneration
            | OwnershipConflict::DoubleDirty
            | OwnershipConflict::InvalidationRace
            | OwnershipConflict::OutOfRange => Errno::EIO,
            OwnershipConflict::UpgradeConflict => Errno::EAGAIN,
        }
    }
}

/// An RAII guard that tracks an active ownership acquisition for a
/// single (inode, page_idx).  When the guard is dropped without
/// being explicitly committed or aborted, ownership reverts to
/// the previous state.
///
/// # Drop semantics
///
/// On drop, the guard releases the ownership held back to the
/// engine unless [`OwnershipGuard::commit`] or
/// [`OwnershipGuard::abort`] was called first.  The table
/// reference is borrowed immutably at this point, so the drop
/// implementation records the release via an explicit method
/// call rather than an automatic `Drop` impl.
///
/// Callers must call either `commit()` or `abort()` before the
/// guard goes out of scope to avoid leaking the ownership state.
#[derive(Debug)]
pub struct OwnershipGuard<'a, E: VfsEngine> {
    engine: &'a E,
    table: &'a mut PageAuthorityTable,
    inode: InodeId,
    page_idx: u64,
    new_ownership: PageOwnership,
    prev_ownership: PageOwnership,
    mode: PageOwnershipMode,
    committed: bool,
}

impl<'a, E: VfsEngine> OwnershipGuard<'a, E> {
    fn new(
        engine: &'a E,
        table: &'a mut PageAuthorityTable,
        inode: InodeId,
        page_idx: u64,
        new_ownership: PageOwnership,
        prev_ownership: PageOwnership,
        mode: PageOwnershipMode,
    ) -> Self {
        Self {
            engine,
            table,
            inode,
            page_idx,
            new_ownership,
            prev_ownership,
            mode,
            committed: false,
        }
    }

    /// The inode this guard covers.
    pub const fn inode(&self) -> InodeId {
        self.inode
    }

    /// The page index this guard covers.
    pub const fn page_idx(&self) -> u64 {
        self.page_idx
    }

    /// The byte offset of the page start.
    pub const fn offset(&self) -> u64 {
        self.page_idx * PAGE_SIZE
    }

    /// The access mode (Read or Write).
    pub const fn mode(&self) -> PageOwnershipMode {
        self.mode
    }

    /// The current ownership state after acquisition.
    pub const fn ownership(&self) -> PageOwnership {
        self.new_ownership
    }

    /// Commit the ownership change: the kernel retains the acquired
    /// ownership.
    ///
    /// After `commit()`, the guard will not revert ownership on drop.
    pub fn commit(mut self) {
        self.committed = true;
        // Guard drop will be a no-op.
    }

    /// Abort the acquisition: revert ownership to the previous state.
    ///
    /// Signals the engine that the ownership change is cancelled.
    pub fn abort(mut self) {
        self.table
            .insert(self.inode, self.page_idx, self.prev_ownership);
        self.committed = true;
        // Signal engine if we previously told it about the acquisition.
        if self.prev_ownership != self.new_ownership {
            match self.prev_ownership {
                PageOwnership::EngineOwned | PageOwnership::Shared => {
                    // If we took KernelOwned, the engine might have invalidated.
                    // Notify engine that kernel is releasing ownership back.
                    self.engine
                        .page_ownership_transferred(self.inode, self.page_idx);
                }
                PageOwnership::KernelOwned | PageOwnership::Fenced => {
                    // Already kernel-owned; no signal needed.
                }
            }
        }
    }
}

/// Per-inode page-authority table.
///
/// Tracks the [`PageOwnership`] state for every active page in an
/// inode's address space.  The table uses the crate's kernel-compatible
/// vector facade so the same source compiles under Cargo and Kbuild.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageAuthorityEntry {
    inode: InodeId,
    page_idx: u64,
    state: PageOwnership,
    generation: PageGeneration,
}

#[derive(Clone, Debug)]
pub struct PageAuthorityTable {
    entries: crate::TideVec<PageAuthorityEntry>,
    max_entries: usize,
    next_generation: u64,
}

impl PageAuthorityTable {
    /// Create a new table with the given maximum entry count.
    ///
    /// When the table is full, the least-recently-used (lowest page
    /// index for an unrelated inode) entry is evicted before the
    /// new entry is inserted.  Default maximum is 65 536 entries
    /// (~256 MiB of tracked pages at 4 KiB each).
    pub const fn new(max_entries: usize) -> Self {
        Self {
            entries: crate::TideVec::new(),
            max_entries,
            next_generation: 1,
        }
    }

    /// Create a table with the production default (65536 entries).
    pub const fn default_production() -> Self {
        Self::new(65536)
    }

    /// Number of tracked entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maximum capacity.
    pub const fn capacity(&self) -> usize {
        self.max_entries
    }

    /// Look up the ownership state for (inode, page_idx).
    pub fn get(&self, inode: InodeId, page_idx: u64) -> PageOwnership {
        self.entries
            .iter()
            .find(|entry| entry.inode == inode && entry.page_idx == page_idx)
            .map(|entry| entry.state)
            .unwrap_or(PageOwnership::EngineOwned)
    }

    /// Look up the generation tuple for (inode, page_idx).
    pub fn generation(&self, inode: InodeId, page_idx: u64) -> PageGeneration {
        self.entries
            .iter()
            .find(|entry| entry.inode == inode && entry.page_idx == page_idx)
            .map(|entry| entry.generation)
            .unwrap_or_default()
    }

    /// Insert (or update) an ownership entry.
    pub(crate) fn insert(&mut self, inode: InodeId, page_idx: u64, state: PageOwnership) {
        let generation = self.generation(inode, page_idx);
        self.insert_with_generation(inode, page_idx, state, generation);
    }

    fn insert_with_generation(
        &mut self,
        inode: InodeId,
        page_idx: u64,
        state: PageOwnership,
        generation: PageGeneration,
    ) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.inode == inode && entry.page_idx == page_idx)
        {
            entry.state = state;
            entry.generation = generation;
            return;
        }
        if self.max_entries == 0 {
            return;
        }
        // Evict if at capacity.
        while self.entries.len() >= self.max_entries {
            let evict_idx = self
                .entries
                .iter()
                .position(|entry| entry.inode != inode)
                .unwrap_or(0);
            self.entries.remove(evict_idx);
        }
        self.entries.push(PageAuthorityEntry {
            inode,
            page_idx,
            state,
            generation,
        });
    }

    /// Remove a tracked entry (e.g., on inode eviction).
    pub fn remove(&mut self, inode: InodeId, page_idx: u64) {
        if let Some(idx) = self
            .entries
            .iter()
            .position(|entry| entry.inode == inode && entry.page_idx == page_idx)
        {
            self.entries.remove(idx);
        }
    }

    /// Clear all entries for an inode.
    pub fn clear_inode(&mut self, inode: InodeId) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| entry.inode != inode);
        before - self.entries.len()
    }

    /// Iterate over all tracked (inode, page_idx, state) tuples.
    pub fn iter(&self) -> impl Iterator<Item = (InodeId, u64, PageOwnership)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.inode, entry.page_idx, entry.state))
    }

    /// Iterate over all tracked entries with their generation tuple.
    pub fn iter_with_generation(
        &self,
    ) -> impl Iterator<Item = (InodeId, u64, PageOwnership, PageGeneration)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.inode, entry.page_idx, entry.state, entry.generation))
    }

    /// Take the generation snapshot that a read, mmap fault, or writeback
    /// must prove before publishing its page-cache result.
    pub fn generation_snapshot(
        &self,
        inode: InodeId,
        page_idx: u64,
    ) -> PageGenerationSnapshot {
        PageGenerationSnapshot {
            inode,
            page_idx,
            generation: self.generation(inode, page_idx),
        }
    }

    /// Check that a snapshot still matches the current page generation.
    pub fn check_generation(
        &self,
        snapshot: PageGenerationSnapshot,
    ) -> Result<(), OwnershipConflict> {
        if self.generation(snapshot.inode, snapshot.page_idx) == snapshot.generation {
            Ok(())
        } else {
            Err(OwnershipConflict::StaleGeneration)
        }
    }

    /// Raise a generation fence over a byte range.
    ///
    /// Clean shared entries become fenced so they cannot satisfy later reads
    /// without a refill. Dirty/kernel-owned entries are also fenced; writeback
    /// completion must prove a pre-fence snapshot before it can mark them
    /// clean. The engine is notified for every affected page, but notification
    /// delivery is advisory: the generation tuple owns correctness.
    pub fn raise_range_fence(
        &mut self,
        engine: &impl VfsEngine,
        inode: InodeId,
        offset: u64,
        length: u64,
    ) -> Option<PageGeneration> {
        if length == 0 {
            return None;
        }

        let first = page_index(offset);
        let last = page_index(offset.saturating_add(length.saturating_sub(1)));
        let generation = PageGeneration::range_fence(self.next_generation);
        self.next_generation = self.next_generation.saturating_add(1).max(1);

        for page_idx in first..=last {
            engine.page_invalidation_needed(inode, page_idx);
            self.insert_with_generation(inode, page_idx, PageOwnership::Fenced, generation);
        }

        Some(generation)
    }

    // ── Ownership protocol methods ──────────────────────────────────

    /// Acquire ownership for the given access mode.
    ///
    /// Returns an [`OwnershipGuard`] that tracks the acquisition
    /// lifecycle.  The caller must either [`OwnershipGuard::commit`]
    /// or [`OwnershipGuard::abort`] the guard.
    ///
    /// # Transition logic
    ///
    /// | Current state | Mode  | Action                                    | New state |
    /// |---------------|-------|-------------------------------------------|-----------|
    /// | EngineOwned   | Read  | No invalidation; kernel reads from engine | Shared    |
    /// | EngineOwned   | Write | Invalidate engine copy; kernel takes      | KernelOwned |
    /// | KernelOwned   | Read  | Already owned; no transition              | KernelOwned |
    /// | KernelOwned   | Write | Already owned; no transition              | KernelOwned |
    /// | Shared        | Read  | No transition                             | Shared    |
    /// | Shared        | Write | Invalidate engine copy; kernel takes      | KernelOwned |
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipConflict`] when the engine cannot invalidate
    /// its copy (e.g., engine-side mutation in progress).
    pub fn acquire<'a, E: VfsEngine>(
        &'a mut self,
        engine: &'a E,
        inode: InodeId,
        page_idx: u64,
        mode: PageOwnershipMode,
    ) -> Result<OwnershipGuard<'a, E>, OwnershipConflict> {
        let current = self.get(inode, page_idx);

        match (current, mode) {
            // Already in the desired state — fast path.
            (PageOwnership::KernelOwned, _) => Ok(OwnershipGuard::new(
                engine, self, inode, page_idx, current, current, mode,
            )),
            (PageOwnership::Shared, PageOwnershipMode::Read) => Ok(OwnershipGuard::new(
                engine, self, inode, page_idx, current, current, mode,
            )),

            // EngineOwned/Fenced → Shared (read): kernel refills from engine.
            (PageOwnership::EngineOwned | PageOwnership::Fenced, PageOwnershipMode::Read) => {
                self.insert(inode, page_idx, PageOwnership::Shared);
                Ok(OwnershipGuard::new(
                    engine,
                    self,
                    inode,
                    page_idx,
                    PageOwnership::Shared,
                    current,
                    mode,
                ))
            }

            // EngineOwned/Fenced → KernelOwned (write): must invalidate engine copy.
            (PageOwnership::EngineOwned | PageOwnership::Fenced, PageOwnershipMode::Write) => {
                engine.page_invalidation_needed(inode, page_idx);
                self.insert(inode, page_idx, PageOwnership::KernelOwned);
                engine.page_ownership_acquired(inode, page_idx, mode);
                Ok(OwnershipGuard::new(
                    engine,
                    self,
                    inode,
                    page_idx,
                    PageOwnership::KernelOwned,
                    current,
                    mode,
                ))
            }

            // Shared → KernelOwned (write): must invalidate engine copy.
            (PageOwnership::Shared, PageOwnershipMode::Write) => {
                engine.page_invalidation_needed(inode, page_idx);
                self.insert(inode, page_idx, PageOwnership::KernelOwned);
                engine.page_ownership_acquired(inode, page_idx, mode);
                Ok(OwnershipGuard::new(
                    engine,
                    self,
                    inode,
                    page_idx,
                    PageOwnership::KernelOwned,
                    PageOwnership::Shared,
                    mode,
                ))
            }
        }
    }

    /// Transfer ownership back to the engine after writeback completes.
    ///
    /// Called after a successful writeback flush to return the page
    /// to engine authority.  The kernel page cache may retain a clean
    /// copy for reads.
    ///
    /// # Panics
    ///
    /// Does not panic.  Silently ignores pages that are not tracked
    /// or are already `EngineOwned`.
    pub fn transfer_to_engine(&mut self, inode: InodeId, page_idx: u64) {
        let current = self.get(inode, page_idx);
        if current == PageOwnership::EngineOwned {
            return;
        }
        self.insert(inode, page_idx, PageOwnership::EngineOwned);
    }

    /// Transfer ownership back to the engine only if the writeback-start
    /// generation is still current.
    pub fn transfer_to_engine_if_current(
        &mut self,
        snapshot: PageGenerationSnapshot,
    ) -> Result<(), OwnershipConflict> {
        self.check_generation(snapshot)?;
        self.transfer_to_engine(snapshot.inode, snapshot.page_idx);
        Ok(())
    }

    /// Remove source-model page-authority entries for all pages at or beyond
    /// `page_threshold` for the given inode.
    ///
    /// Each affected page signals the engine to invalidate its copy
    /// before the entry is removed. This is used by the Rust truncate-down
    /// model to discard tracking for pages the kernel would have freed via
    /// setattr(FATTR_SIZE) shrink. The mounted C truncate path uses Linux
    /// page-cache invalidation helpers instead of this table.
    ///
    /// Returns the number of entries removed.
    pub fn truncate_down(
        &mut self,
        engine: &impl VfsEngine,
        inode: InodeId,
        page_threshold: u64,
    ) -> usize {
        let mut removed: usize = 0;
        // Drain all entries for this inode with page_idx >= threshold.
        self.entries.retain(|entry| {
            if entry.inode == inode && entry.page_idx >= page_threshold {
                // Signal engine invalidation for the discarded page.
                engine.page_invalidation_needed(inode, entry.page_idx);
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }

    /// Signal the engine to invalidate its copy for a page.
    ///
    /// Called when the kernel invalidates a folio range (e.g., page
    /// reclaim, truncate).  The engine must drop any cached copy
    /// for the affected range.
    pub fn invalidate_engine_copy(
        &mut self,
        engine: &impl VfsEngine,
        inode: InodeId,
        page_idx: u64,
    ) {
        let current = self.get(inode, page_idx);
        match current {
            PageOwnership::EngineOwned | PageOwnership::Shared => {
                engine.page_invalidation_needed(inode, page_idx);
            }
            PageOwnership::KernelOwned => {
                // Kernel owns the page; engine shouldn't have a copy,
                // but signal invalidation anyway for safety.
                engine.page_invalidation_needed(inode, page_idx);
            }
            PageOwnership::Fenced => {}
        }
    }

    /// Check whether a given access mode is compatible with the
    /// current ownership state.
    pub fn check_access(
        &self,
        inode: InodeId,
        page_idx: u64,
        mode: PageOwnershipMode,
    ) -> Result<(), OwnershipConflict> {
        let current = self.get(inode, page_idx);
        match (current, mode) {
            (PageOwnership::KernelOwned, _) => Ok(()),
            (PageOwnership::Shared, PageOwnershipMode::Read) => Ok(()),
            (PageOwnership::EngineOwned, PageOwnershipMode::Read) => Ok(()),
            (PageOwnership::Fenced, _) => Err(OwnershipConflict::StaleGeneration),
            (PageOwnership::EngineOwned, PageOwnershipMode::Write) => {
                Err(OwnershipConflict::StaleWrite)
            }
            (PageOwnership::Shared, PageOwnershipMode::Write) => {
                Err(OwnershipConflict::UpgradeConflict)
            }
        }
    }
}

impl Default for PageAuthorityTable {
    fn default() -> Self {
        Self::default_production()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::MockEngine;
    use alloc::vec::Vec;
    use tidefs_kmod_bridge::kernel_types::InodeId;

    fn ino(id: u64) -> InodeId {
        InodeId::new(id)
    }

    fn make_table() -> PageAuthorityTable {
        PageAuthorityTable::new(1024)
    }

    // ── page_index tests ─────────────────────────────────────────────

    #[test]
    fn page_index_zero() {
        assert_eq!(page_index(0), 0);
    }

    #[test]
    fn page_index_mid_page() {
        assert_eq!(page_index(4095), 0);
    }

    #[test]
    fn page_index_next_page() {
        assert_eq!(page_index(4096), 1);
    }

    #[test]
    fn page_index_large_offset() {
        assert_eq!(page_index(4096 * 1000), 1000);
    }

    // ── PageOwnership tests ──────────────────────────────────────────

    #[test]
    fn ownership_kernel_can_read_write() {
        assert!(PageOwnership::KernelOwned.kernel_can_read());
        assert!(PageOwnership::KernelOwned.kernel_can_write());
    }

    #[test]
    fn ownership_engine_owned_read_only() {
        assert!(!PageOwnership::EngineOwned.kernel_can_read());
        assert!(!PageOwnership::EngineOwned.kernel_can_write());
    }

    #[test]
    fn ownership_shared_read_only() {
        assert!(PageOwnership::Shared.kernel_can_read());
        assert!(!PageOwnership::Shared.kernel_can_write());
    }

    #[test]
    fn ownership_enum_variants() {
        assert_ne!(PageOwnership::EngineOwned, PageOwnership::KernelOwned);
        assert_ne!(PageOwnership::KernelOwned, PageOwnership::Shared);
        assert_ne!(PageOwnership::Shared, PageOwnership::EngineOwned);
        assert_ne!(PageOwnership::Fenced, PageOwnership::Shared);
    }

    // ── OwnershipConflict tests ──────────────────────────────────────

    #[test]
    fn conflict_to_errno() {
        assert_eq!(OwnershipConflict::StaleWrite.to_errno(), Errno::EIO);
        assert_eq!(OwnershipConflict::StaleGeneration.to_errno(), Errno::EIO);
        assert_eq!(OwnershipConflict::DoubleDirty.to_errno(), Errno::EIO);
        assert_eq!(OwnershipConflict::UpgradeConflict.to_errno(), Errno::EAGAIN);
    }

    // ── PageAuthorityTable basic tests ───────────────────────────────

    #[test]
    fn table_new_empty() {
        let t = make_table();
        assert!(t.is_empty());
        assert_eq!(t.capacity(), 1024);
        assert_eq!(PageAuthorityTable::default_production().capacity(), 65536);
    }

    #[test]
    fn table_default_is_engine_owned() {
        let t = make_table();
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
        assert_eq!(t.get(ino(1), 100), PageOwnership::EngineOwned);
    }

    #[test]
    fn table_insert_and_get() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
        assert_eq!(t.get(ino(1), 1), PageOwnership::EngineOwned);
    }

    #[test]
    fn table_remove_entry() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        assert_eq!(t.len(), 1);
        t.remove(ino(1), 0);
        assert!(t.is_empty());
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn table_clear_inode() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        t.insert(ino(1), 1, PageOwnership::Shared);
        t.insert(ino(2), 0, PageOwnership::KernelOwned);
        assert_eq!(t.len(), 3);
        let removed = t.clear_inode(ino(1));
        assert_eq!(removed, 2);
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
        assert_eq!(t.get(ino(2), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn table_iter() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        t.insert(ino(1), 1, PageOwnership::Shared);
        t.insert(ino(2), 0, PageOwnership::EngineOwned);
        let v: Vec<_> = t.iter().collect();
        assert_eq!(v.len(), 3);
        // The vector-backed table preserves insertion order.
        assert_eq!(v[0], (ino(1), 0, PageOwnership::KernelOwned));
        assert_eq!(v[1], (ino(1), 1, PageOwnership::Shared));
        assert_eq!(v[2], (ino(2), 0, PageOwnership::EngineOwned));
    }

    #[test]
    fn table_capacity_eviction() {
        let mut t = PageAuthorityTable::new(2);
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        t.insert(ino(1), 1, PageOwnership::Shared);
        assert_eq!(t.len(), 2);
        // Insert a third entry for a different inode — should evict ino1,0
        t.insert(ino(2), 0, PageOwnership::KernelOwned);
        assert_eq!(t.len(), 2);
        // ino(1) page 1 should still be present
        assert_eq!(t.get(ino(1), 1), PageOwnership::Shared);
        assert_eq!(t.get(ino(2), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn table_capacity_same_inode_eviction() {
        let mut t = PageAuthorityTable::new(2);
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        t.insert(ino(2), 0, PageOwnership::Shared);
        // Insert another entry for ino1 — cannot evict ino2 (different inode),
        // must evict the smallest key overall
        t.insert(ino(1), 1, PageOwnership::KernelOwned);
        assert_eq!(t.len(), 2);
        // ino1,0 likely evicted (smallest key)
    }

    // ── Ownership acquisition tests ──────────────────────────────────

    #[test]
    fn acquire_read_from_engine_owned() {
        let e = MockEngine::new();
        let mut t = make_table();
        // Default is EngineOwned; read should transition to Shared.
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Read).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::Shared);
        assert_eq!(guard.mode(), PageOwnershipMode::Read);
        guard.commit();
        // After commit, ownership stays Shared.
        assert_eq!(t.get(ino(1), 0), PageOwnership::Shared);
    }

    #[test]
    fn acquire_write_from_engine_owned() {
        let e = MockEngine::new();
        let mut t = make_table();
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::KernelOwned);
        assert_eq!(guard.mode(), PageOwnershipMode::Write);
        guard.commit();
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn acquire_write_from_shared() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::KernelOwned);
        guard.commit();
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn acquire_read_when_already_kernel_owned() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Read).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::KernelOwned);
        guard.commit();
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn acquire_write_when_already_kernel_owned() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::KernelOwned);
        guard.commit();
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
    }

    #[test]
    fn acquire_read_when_already_shared() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Read).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::Shared);
        guard.commit();
        assert_eq!(t.get(ino(1), 0), PageOwnership::Shared);
    }

    // ── Guard abort/revert tests ─────────────────────────────────────

    #[test]
    fn guard_abort_reverts_to_engine_owned() {
        let e = MockEngine::new();
        let mut t = make_table();
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        guard.abort();
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn guard_abort_reverts_to_shared() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        guard.abort();
        assert_eq!(t.get(ino(1), 0), PageOwnership::Shared);
    }

    #[test]
    fn guard_commit_is_stable() {
        let e = MockEngine::new();
        let mut t = make_table();
        {
            let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
            guard.commit();
        }
        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
    }

    // ── transfer_to_engine tests ─────────────────────────────────────

    #[test]
    fn transfer_to_engine_from_kernel_owned() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        t.transfer_to_engine(ino(1), 0);
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn transfer_to_engine_from_shared() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);
        t.transfer_to_engine(ino(1), 0);
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn transfer_to_engine_idempotent() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::EngineOwned);
        t.transfer_to_engine(ino(1), 0);
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn transfer_to_engine_untracked_is_noop() {
        let mut t = make_table();
        t.transfer_to_engine(ino(1), 42);
        assert_eq!(t.get(ino(1), 42), PageOwnership::EngineOwned);
    }

    // ── Generation fence tests ──────────────────────────────────────

    #[test]
    fn range_fence_marks_clean_cache_stale() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);

        let before = t.generation_snapshot(ino(1), 0);
        let generation = t.raise_range_fence(&e, ino(1), 0, PAGE_SIZE).unwrap();

        assert_eq!(t.get(ino(1), 0), PageOwnership::Fenced);
        assert_eq!(t.generation(ino(1), 0), generation);
        assert_eq!(
            t.check_generation(before),
            Err(OwnershipConflict::StaleGeneration)
        );
    }

    #[test]
    fn fence_refill_read_records_current_generation() {
        let e = MockEngine::new();
        let mut t = make_table();
        let generation = t.raise_range_fence(&e, ino(1), 0, PAGE_SIZE).unwrap();

        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Read).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::Shared);
        guard.commit();

        assert_eq!(t.get(ino(1), 0), PageOwnership::Shared);
        assert_eq!(t.generation(ino(1), 0), generation);
    }

    #[test]
    fn aborting_fenced_read_restores_fence() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.raise_range_fence(&e, ino(1), 0, PAGE_SIZE).unwrap();

        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Read).unwrap();
        guard.abort();

        assert_eq!(t.get(ino(1), 0), PageOwnership::Fenced);
    }

    #[test]
    fn writeback_completion_refuses_superseded_generation() {
        let e = MockEngine::new();
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        let writeback_started = t.generation_snapshot(ino(1), 0);

        t.raise_range_fence(&e, ino(1), 0, PAGE_SIZE).unwrap();

        assert_eq!(
            t.transfer_to_engine_if_current(writeback_started),
            Err(OwnershipConflict::StaleGeneration)
        );
        assert_ne!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn writeback_completion_marks_clean_when_generation_matches() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        let writeback_started = t.generation_snapshot(ino(1), 0);

        t.transfer_to_engine_if_current(writeback_started).unwrap();

        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    // ── Check access tests ───────────────────────────────────────────

    #[test]
    fn check_access_kernel_owned_allows_all() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::KernelOwned);
        assert!(t.check_access(ino(1), 0, PageOwnershipMode::Read).is_ok());
        assert!(t.check_access(ino(1), 0, PageOwnershipMode::Write).is_ok());
    }

    #[test]
    fn check_access_engine_owned_read_only() {
        let t = make_table(); // default EngineOwned
        assert!(t.check_access(ino(1), 0, PageOwnershipMode::Read).is_ok());
        assert_eq!(
            t.check_access(ino(1), 0, PageOwnershipMode::Write),
            Err(OwnershipConflict::StaleWrite)
        );
    }

    #[test]
    fn check_access_shared_read_only() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Shared);
        assert!(t.check_access(ino(1), 0, PageOwnershipMode::Read).is_ok());
        assert_eq!(
            t.check_access(ino(1), 0, PageOwnershipMode::Write),
            Err(OwnershipConflict::UpgradeConflict)
        );
    }

    #[test]
    fn check_access_fenced_refuses_cached_read() {
        let mut t = make_table();
        t.insert(ino(1), 0, PageOwnership::Fenced);
        assert_eq!(
            t.check_access(ino(1), 0, PageOwnershipMode::Read),
            Err(OwnershipConflict::StaleGeneration)
        );
    }

    // ── Integration: multi-page ownership lifecycle ──────────────────

    #[test]
    fn full_writeback_lifecycle() {
        let e = MockEngine::new();
        let mut t = make_table();

        // Step 1: Engine has ownership by default.
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);

        // Step 2: Kernel acquires write ownership.
        let guard = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        assert_eq!(guard.ownership(), PageOwnership::KernelOwned);
        guard.commit();

        // Step 3: Writeback completes — transfer to engine.
        t.transfer_to_engine(ino(1), 0);
        assert_eq!(t.get(ino(1), 0), PageOwnership::EngineOwned);
    }

    #[test]
    fn multi_page_independent_ownership() {
        let e = MockEngine::new();
        let mut t = make_table();

        // Page 0: write
        let g0 = t.acquire(&e, ino(1), 0, PageOwnershipMode::Write).unwrap();
        assert_eq!(g0.ownership(), PageOwnership::KernelOwned);
        g0.commit();

        // Page 1: read-only
        let g1 = t.acquire(&e, ino(1), 1, PageOwnershipMode::Read).unwrap();
        assert_eq!(g1.ownership(), PageOwnership::Shared);
        g1.commit();

        assert_eq!(t.get(ino(1), 0), PageOwnership::KernelOwned);
        assert_eq!(t.get(ino(1), 1), PageOwnership::Shared);
    }

    #[test]
    fn multi_inode_ownership_isolation() {
        let e = MockEngine::new();
        let mut t = make_table();

        let g_a = t.acquire(&e, ino(10), 0, PageOwnershipMode::Write).unwrap();
        g_a.commit();

        let g_b = t.acquire(&e, ino(20), 0, PageOwnershipMode::Read).unwrap();
        g_b.commit();

        assert_eq!(t.get(ino(10), 0), PageOwnership::KernelOwned);
        assert_eq!(t.get(ino(20), 0), PageOwnership::Shared);
    }

    #[test]
    fn guard_offset_computation() {
        let e = MockEngine::new();
        let mut t = make_table();
        let guard = t.acquire(&e, ino(1), 5, PageOwnershipMode::Read).unwrap();
        assert_eq!(guard.page_idx(), 5);
        assert_eq!(guard.offset(), 5 * 4096);
        guard.commit();
    }

    #[test]
    fn guard_inode_accessor() {
        let e = MockEngine::new();
        let mut t = make_table();
        let guard = t.acquire(&e, ino(42), 3, PageOwnershipMode::Write).unwrap();
        assert_eq!(guard.inode(), ino(42));
        guard.commit();
    }

    #[test]
    fn ownership_mode_maps_to_correct_state() {
        // Read maps to Shared, Write maps to KernelOwned
        let read_target = match PageOwnershipMode::Read {
            PageOwnershipMode::Read => PageOwnership::Shared,
            PageOwnershipMode::Write => PageOwnership::KernelOwned,
        };
        assert_eq!(read_target, PageOwnership::Shared);
        let write_target = match PageOwnershipMode::Write {
            PageOwnershipMode::Read => PageOwnership::Shared,
            PageOwnershipMode::Write => PageOwnership::KernelOwned,
        };
        assert_eq!(write_target, PageOwnership::KernelOwned);
    }

    #[test]
    fn page_authority_table_default() {
        let t = PageAuthorityTable::default();
        assert_eq!(t.capacity(), 65536);
        assert!(t.is_empty());
    }
}
