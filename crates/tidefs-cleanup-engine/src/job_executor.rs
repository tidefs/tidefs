//! Job executor trait and concrete implementations for deferred cleanup work items.
//!
//! The [`JobExecutor`] trait abstracts execution of [`CleanupWorkItemV1`]
//! records. Concrete implementations route work items to the appropriate
//! subsystem (extent map, dir index, space accounting, orphan index) based
//! on the work item kind.

use tidefs_cleanup_job_core::{CleanupContext, CleanupError, CleanupPhase, JobOutcome};
use tidefs_types_deferred_cleanup_core::{CleanupWorkItemV1, WorkItemKind};

// ---------------------------------------------------------------------------
// Trait abstractions for subsystem access (testable with mocks)
// ---------------------------------------------------------------------------

/// Access to the extent map for freeing per-inode data extents.
pub trait ExtentMapAccess {
    /// Free all extents belonging to an inode.
    ///
    /// Returns the number of extents freed, or an error message on failure.
    fn free_all_extents(&mut self, inode_id: u64) -> Result<u64, String>;
}

/// Access to link-count tracking for inodes.
pub trait LinkCountAccess {
    /// Get the current link count for an inode.
    fn get_link_count(&self, inode_id: u64) -> Result<u64, String>;

    /// Decrement the link count and return the new value.
    fn decrement_link_count(&mut self, inode_id: u64) -> Result<u64, String>;
}

/// Access to the orphan index for tracking nlink==0 inodes.
pub trait OrphanIndexAccess {
    /// Register an inode as orphaned (nlink reached 0, may have open fds).
    fn add_orphan(&mut self, inode_id: u64) -> Result<(), String>;
}

/// Access to directory operations for rmdir cleanup.
pub trait DirAccess {
    /// Check whether a directory is empty (no entries besides "." and "..").
    fn is_empty(&self, inode_id: u64) -> Result<bool, String>;

    /// Remove a directory entry from the parent directory.
    fn remove_entry(&mut self, parent_inode: u64, name: &str) -> Result<(), String>;
}

/// Access to space accounting for returning freed blocks to the free pool.
pub trait SpaceAccess {
    /// Return bytes to the free pool.
    fn free_space(&mut self, bytes: u64) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// JobExecutor trait
// ---------------------------------------------------------------------------

/// Executes a single deferred cleanup work item against the storage subsystems.
///
/// Implementations are responsible for:
/// - Routing work items by [`WorkItemKind`]
/// - Calling subsystem methods to reclaim resources
/// - Returning a [`JobOutcome`] indicating success, transient error, or fatal error
pub trait JobExecutor {
    /// Execute a cleanup work item.
    fn execute(&mut self, item: &mut CleanupWorkItemV1, ctx: &CleanupContext) -> JobOutcome;

    /// The cleanup phase this executor handles.
    fn phase(&self) -> CleanupPhase;

    /// Human-readable executor identifier for logging.
    fn name(&self) -> &str;
}

// Allow CleanupEngine to be type-erased via Box<dyn JobExecutor> so it
// can be stored as an optional field in pool/mount context structs.
impl JobExecutor for Box<dyn JobExecutor> {
    fn execute(&mut self, item: &mut CleanupWorkItemV1, ctx: &CleanupContext) -> JobOutcome {
        self.as_mut().execute(item, ctx)
    }
    fn phase(&self) -> CleanupPhase {
        self.as_ref().phase()
    }
    fn name(&self) -> &str {
        self.as_ref().name()
    }
}
// Allow CleanupEngine to be type-erased via Box<dyn JobExecutor + Send> so it
// can be stored in thread-safe pool/mount context structs that require Send.
impl JobExecutor for Box<dyn JobExecutor + Send> {
    fn execute(&mut self, item: &mut CleanupWorkItemV1, ctx: &CleanupContext) -> JobOutcome {
        self.as_mut().execute(item, ctx)
    }
    fn phase(&self) -> CleanupPhase {
        self.as_ref().phase()
    }
    fn name(&self) -> &str {
        self.as_ref().name()
    }
}

// ---------------------------------------------------------------------------
// DeferredUnlinkExecutor
// ---------------------------------------------------------------------------

/// Executes deferred unlink cleanup: frees all extents, decrements link count,
/// and registers the inode as orphan if nlink reaches zero.
pub struct DeferredUnlinkExecutor<E, L, O> {
    extent_map: E,
    link_count: L,
    orphan_index: O,
}

impl<E, L, O> DeferredUnlinkExecutor<E, L, O>
where
    E: ExtentMapAccess,
    L: LinkCountAccess,
    O: OrphanIndexAccess,
{
    /// Create a new unlink executor.
    pub fn new(extent_map: E, link_count: L, orphan_index: O) -> Self {
        Self {
            extent_map,
            link_count,
            orphan_index,
        }
    }
}

impl<E, L, O> JobExecutor for DeferredUnlinkExecutor<E, L, O>
where
    E: ExtentMapAccess,
    L: LinkCountAccess,
    O: OrphanIndexAccess,
{
    fn execute(&mut self, item: &mut CleanupWorkItemV1, _ctx: &CleanupContext) -> JobOutcome {
        if item.is_complete() {
            return JobOutcome::Completed;
        }

        let inode_id = item.inode_id;

        // Step 1: Free all extents belonging to this inode
        match self.extent_map.free_all_extents(inode_id) {
            Ok(freed) => {
                item.extents_processed += freed;
            }
            Err(e) => {
                return JobOutcome::Retryable(CleanupError::retryable(
                    format!("unlink extent free failed for inode {inode_id}: {e}"),
                    CleanupPhase::ExtentFree,
                ));
            }
        }

        // Step 2: Decrement link count
        match self.link_count.decrement_link_count(inode_id) {
            Ok(new_count) => {
                // Step 3: If nlink reached 0, register as orphan
                if new_count == 0 {
                    if let Err(e) = self.orphan_index.add_orphan(inode_id) {
                        return JobOutcome::Retryable(CleanupError::retryable(
                            format!("orphan registration failed for inode {inode_id}: {e}"),
                            CleanupPhase::OrphanReap,
                        ));
                    }
                }
            }
            Err(e) => {
                return JobOutcome::Retryable(CleanupError::retryable(
                    format!("link count decrement failed for inode {inode_id}: {e}"),
                    CleanupPhase::ExtentFree,
                ));
            }
        }

        item.mark_complete();
        JobOutcome::Completed
    }

    fn phase(&self) -> CleanupPhase {
        CleanupPhase::ExtentFree
    }

    fn name(&self) -> &str {
        "DeferredUnlinkExecutor"
    }
}

// ---------------------------------------------------------------------------
// DeferredRmdirExecutor
// ---------------------------------------------------------------------------

/// Executes deferred rmdir cleanup: verifies directory is empty and removes
/// the directory entry from the parent.
pub struct DeferredRmdirExecutor<D> {
    dir: D,
}

impl<D> DeferredRmdirExecutor<D>
where
    D: DirAccess,
{
    /// Create a new rmdir executor.
    pub fn new(dir: D) -> Self {
        Self { dir }
    }
}

impl<D> JobExecutor for DeferredRmdirExecutor<D>
where
    D: DirAccess,
{
    fn execute(&mut self, item: &mut CleanupWorkItemV1, _ctx: &CleanupContext) -> JobOutcome {
        if item.is_complete() {
            return JobOutcome::Completed;
        }

        let inode_id = item.inode_id;

        // Step 1: Verify directory is empty
        match self.dir.is_empty(inode_id) {
            Ok(true) => {}
            Ok(false) => {
                return JobOutcome::Retryable(CleanupError::retryable(
                    format!("rmdir: directory {inode_id} is not empty"),
                    CleanupPhase::OrphanReap,
                ));
            }
            Err(e) => {
                return JobOutcome::Retryable(CleanupError::retryable(
                    format!("rmdir: failed to check if directory {inode_id} is empty: {e}"),
                    CleanupPhase::OrphanReap,
                ));
            }
        }

        // Step 2: Remove directory entry from parent
        // The work item's cursor may carry the parent inode and entry name.
        // For simplicity, extract parent from cursor bytes: [parent_inode:8 LE][name_len:1][name:N]
        let cursor = &item.cursor;
        if cursor[0..8] == [0u8; 8] {
            // No cursor data; treat as fatal — can't determine parent
            return JobOutcome::Fatal(CleanupError::fatal(
                format!("rmdir: no parent info in cursor for inode {inode_id}"),
                CleanupPhase::OrphanReap,
            ));
        }

        let parent_inode = u64::from_le_bytes(cursor[0..8].try_into().unwrap());
        let name_len = cursor[8] as usize;
        let name_end = 9usize.saturating_add(name_len).min(64);
        let name_bytes = &cursor[9..name_end];
        let entry_name = match core::str::from_utf8(name_bytes) {
            Ok(s) => s.trim_end_matches('\0'),
            Err(_) => {
                return JobOutcome::Fatal(CleanupError::fatal(
                    format!("rmdir: invalid UTF-8 in cursor name for inode {inode_id}"),
                    CleanupPhase::OrphanReap,
                ));
            }
        };

        match self.dir.remove_entry(parent_inode, entry_name) {
            Ok(()) => {
                item.mark_complete();
                JobOutcome::Completed
            }
            Err(e) => JobOutcome::Retryable(CleanupError::retryable(
                format!(
                    "rmdir: failed to remove entry '{entry_name}' from parent {parent_inode}: {e}"
                ),
                CleanupPhase::OrphanReap,
            )),
        }
    }

    fn phase(&self) -> CleanupPhase {
        CleanupPhase::OrphanReap
    }

    fn name(&self) -> &str {
        "DeferredRmdirExecutor"
    }
}

// ---------------------------------------------------------------------------
// DeferredFreeExtentExecutor
// ---------------------------------------------------------------------------

/// Executes deferred extent-free: returns freed blocks to the space accounting
/// allocator.
pub struct DeferredFreeExtentExecutor<S> {
    space: S,
}

impl<S> DeferredFreeExtentExecutor<S>
where
    S: SpaceAccess,
{
    /// Create a new extent-free executor.
    pub fn new(space: S) -> Self {
        Self { space }
    }
}

impl<S> JobExecutor for DeferredFreeExtentExecutor<S>
where
    S: SpaceAccess,
{
    fn execute(&mut self, item: &mut CleanupWorkItemV1, _ctx: &CleanupContext) -> JobOutcome {
        if item.is_complete() {
            return JobOutcome::Completed;
        }

        let bytes = item.bytes_to_free_estimate;

        match self.space.free_space(bytes) {
            Ok(()) => {
                item.extents_processed += 1;
                item.mark_complete();
                JobOutcome::Completed
            }
            Err(e) => JobOutcome::Retryable(CleanupError::retryable(
                format!("extent free: space accounting returned error: {e}"),
                CleanupPhase::SpacemapUpdate,
            )),
        }
    }

    fn phase(&self) -> CleanupPhase {
        CleanupPhase::SpacemapUpdate
    }

    fn name(&self) -> &str {
        "DeferredFreeExtentExecutor"
    }
}

// ---------------------------------------------------------------------------
// CompositeJobExecutor — dispatches to per-kind executors
// ---------------------------------------------------------------------------

/// Routes work items to the correct executor based on [`WorkItemKind`].
///
/// Holds a separate executor for each work item kind, dispatching
/// `execute()` calls by matching the item kind.
pub struct CompositeJobExecutor<U, R, F> {
    unlink: U,
    rmdir: R,
    free_extent: F,
}

impl<U, R, F> CompositeJobExecutor<U, R, F>
where
    U: JobExecutor,
    R: JobExecutor,
    F: JobExecutor,
{
    /// Create a composite executor from per-kind executors.
    pub fn new(unlink: U, rmdir: R, free_extent: F) -> Self {
        Self {
            unlink,
            rmdir,
            free_extent,
        }
    }
}

impl<U, R, F> JobExecutor for CompositeJobExecutor<U, R, F>
where
    U: JobExecutor,
    R: JobExecutor,
    F: JobExecutor,
{
    fn execute(&mut self, item: &mut CleanupWorkItemV1, ctx: &CleanupContext) -> JobOutcome {
        match item.kind {
            WorkItemKind::UnlinkFree => self.unlink.execute(item, ctx),
            WorkItemKind::RmdirFree => self.rmdir.execute(item, ctx),
            WorkItemKind::TruncateFree
            | WorkItemKind::RenameOverwrite
            | WorkItemKind::SnapDelete
            | WorkItemKind::PunchHoleFree => self.free_extent.execute(item, ctx),
        }
    }

    fn phase(&self) -> CleanupPhase {
        // Composite: lowest (most encompassing) phase
        CleanupPhase::ExtentFree
    }

    fn name(&self) -> &str {
        "CompositeJobExecutor"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tidefs_types_deferred_cleanup_core::BtreeRootPointer;

    // ── Mock implementations ─────────────────────────────────────────

    struct MockExtentMap {
        extents: HashMap<u64, u64>, // inode_id -> extent count
    }
    impl MockExtentMap {
        fn new() -> Self {
            Self {
                extents: HashMap::new(),
            }
        }
        fn set_extents(&mut self, inode_id: u64, count: u64) {
            self.extents.insert(inode_id, count);
        }
    }
    impl ExtentMapAccess for MockExtentMap {
        fn free_all_extents(&mut self, inode_id: u64) -> Result<u64, String> {
            let count = self.extents.remove(&inode_id).unwrap_or(0);
            if count == 0 && !self.extents.contains_key(&inode_id) {
                return Err(format!("inode {inode_id} not found"));
            }
            Ok(count)
        }
    }

    struct MockLinkCount {
        counts: HashMap<u64, u64>,
    }
    impl MockLinkCount {
        fn new() -> Self {
            Self {
                counts: HashMap::new(),
            }
        }
        fn set(&mut self, inode: u64, count: u64) {
            self.counts.insert(inode, count);
        }
    }
    impl LinkCountAccess for MockLinkCount {
        fn get_link_count(&self, inode_id: u64) -> Result<u64, String> {
            self.counts
                .get(&inode_id)
                .copied()
                .ok_or_else(|| format!("inode {inode_id} not found"))
        }
        fn decrement_link_count(&mut self, inode_id: u64) -> Result<u64, String> {
            let count = self
                .counts
                .get_mut(&inode_id)
                .ok_or_else(|| format!("inode {inode_id} not found"))?;
            *count = count.saturating_sub(1);
            Ok(*count)
        }
    }

    struct MockOrphanIndex {
        orphans: Vec<u64>,
    }
    impl MockOrphanIndex {
        fn new() -> Self {
            Self {
                orphans: Vec::new(),
            }
        }
    }
    impl OrphanIndexAccess for MockOrphanIndex {
        fn add_orphan(&mut self, inode_id: u64) -> Result<(), String> {
            self.orphans.push(inode_id);
            Ok(())
        }
    }

    struct MockDir {
        entries: HashMap<u64, Vec<String>>,
    }
    impl MockDir {
        fn new() -> Self {
            Self {
                entries: HashMap::new(),
            }
        }
        fn add_entry(&mut self, dir_inode: u64, name: &str) {
            self.entries
                .entry(dir_inode)
                .or_default()
                .push(name.to_string());
        }
    }
    impl DirAccess for MockDir {
        fn is_empty(&self, inode_id: u64) -> Result<bool, String> {
            let entries = self.entries.get(&inode_id);
            Ok(entries.is_none_or(|e| e.is_empty()))
        }
        fn remove_entry(&mut self, parent_inode: u64, name: &str) -> Result<(), String> {
            let entries = self
                .entries
                .get_mut(&parent_inode)
                .ok_or_else(|| format!("parent dir {parent_inode} not found"))?;
            let pos = entries
                .iter()
                .position(|e| e == name)
                .ok_or_else(|| format!("entry '{name}' not found in dir {parent_inode}"))?;
            entries.remove(pos);
            Ok(())
        }
    }

    struct MockSpace {
        freed_bytes: u64,
    }
    impl MockSpace {
        fn new() -> Self {
            Self { freed_bytes: 0 }
        }
    }
    impl SpaceAccess for MockSpace {
        fn free_space(&mut self, bytes: u64) -> Result<(), String> {
            self.freed_bytes += bytes;
            Ok(())
        }
    }

    fn make_item(inode: u64, kind: WorkItemKind, bytes: u64) -> CleanupWorkItemV1 {
        CleanupWorkItemV1::new(inode, kind, 1, BtreeRootPointer::EMPTY, bytes)
    }

    fn make_item_with_cursor(
        inode: u64,
        kind: WorkItemKind,
        bytes: u64,
        parent_inode: u64,
        name: &str,
    ) -> CleanupWorkItemV1 {
        let mut item = CleanupWorkItemV1::new(inode, kind, 1, BtreeRootPointer::EMPTY, bytes);
        let mut cursor = [0u8; 64];
        cursor[0..8].copy_from_slice(&parent_inode.to_le_bytes());
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(55);
        cursor[8] = name_len as u8;
        cursor[9..9 + name_len].copy_from_slice(&name_bytes[..name_len]);
        item.cursor = cursor;
        item
    }

    // ── DeferredUnlinkExecutor tests ─────────────────────────────────

    #[test]
    fn unlink_executor_frees_extents_and_decrements_link_count() {
        let mut extents = MockExtentMap::new();
        extents.set_extents(100, 5);

        let mut link = MockLinkCount::new();
        link.set(100, 2);

        let orphan = MockOrphanIndex::new();

        let mut executor = DeferredUnlinkExecutor::new(extents, link, orphan);
        let mut item = make_item(100, WorkItemKind::UnlinkFree, 4096);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
        assert_eq!(item.extents_processed, 5);
        // nlink went from 2 to 1, not orphaned
        assert!(executor.orphan_index.orphans.is_empty());
    }

    #[test]
    fn unlink_executor_orphans_when_nlink_reaches_zero() {
        let mut extents = MockExtentMap::new();
        extents.set_extents(200, 3);

        let mut link = MockLinkCount::new();
        link.set(200, 1);

        let orphan = MockOrphanIndex::new();

        let mut executor = DeferredUnlinkExecutor::new(extents, link, orphan);
        let mut item = make_item(200, WorkItemKind::UnlinkFree, 8192);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
        assert_eq!(item.extents_processed, 3);
        // nlink went from 1 to 0 → orphaned
        assert_eq!(executor.orphan_index.orphans, vec![200]);
    }

    #[test]
    fn unlink_executor_completed_item_skipped() {
        let mut extents = MockExtentMap::new();
        extents.set_extents(300, 5);
        let mut link = MockLinkCount::new();
        link.set(300, 1);
        let orphan = MockOrphanIndex::new();

        let mut executor = DeferredUnlinkExecutor::new(extents, link, orphan);
        let mut item = make_item(300, WorkItemKind::UnlinkFree, 4096);
        item.mark_complete();
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        // extents NOT re-freed
        assert_eq!(item.extents_processed, 0);
    }

    #[test]
    fn unlink_executor_extent_free_failure_is_retryable() {
        // Don't register the inode in the extent map → free_all_extents fails
        let extents = MockExtentMap::new();
        let mut link = MockLinkCount::new();
        link.set(400, 1);
        let orphan = MockOrphanIndex::new();

        let mut executor = DeferredUnlinkExecutor::new(extents, link, orphan);
        let mut item = make_item(400, WorkItemKind::UnlinkFree, 4096);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert!(matches!(outcome, JobOutcome::Retryable(_)));
        assert!(!item.is_complete());
    }

    // ── DeferredRmdirExecutor tests ──────────────────────────────────

    #[test]
    fn rmdir_executor_removes_empty_directory() {
        let mut dir = MockDir::new();
        dir.add_entry(10, "child"); // parent dir 10 has entry "child"
        let parent_inode = 10u64;
        let entry_name = "child";

        let executor = dir;
        let mut executor = DeferredRmdirExecutor::new(executor);
        // target inode 20 is empty (no entries in MockDir for 20)
        let mut item =
            make_item_with_cursor(20, WorkItemKind::RmdirFree, 0, parent_inode, entry_name);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
        // entry removed from parent
        assert!(executor.dir.entries.get(&10).unwrap().is_empty());
    }

    #[test]
    fn rmdir_executor_nonempty_directory_is_retryable() {
        let mut dir = MockDir::new();
        dir.add_entry(30, "still_here"); // target dir 30 is not empty
        dir.add_entry(10, "child");

        let mut executor = DeferredRmdirExecutor::new(dir);
        let mut item = make_item_with_cursor(30, WorkItemKind::RmdirFree, 0, 10, "child");
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert!(matches!(outcome, JobOutcome::Retryable(_)));
        assert!(!item.is_complete());
    }

    #[test]
    fn rmdir_executor_no_cursor_is_fatal() {
        let dir = MockDir::new();
        let mut executor = DeferredRmdirExecutor::new(dir);
        let mut item = make_item(40, WorkItemKind::RmdirFree, 0); // no cursor
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert!(matches!(outcome, JobOutcome::Fatal(_)));
        assert!(!item.is_complete());
    }

    #[test]
    fn rmdir_executor_completed_item_skipped() {
        let mut dir = MockDir::new();
        dir.add_entry(10, "child");
        let mut executor = DeferredRmdirExecutor::new(dir);
        let mut item = make_item_with_cursor(50, WorkItemKind::RmdirFree, 0, 10, "child");
        item.mark_complete();
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
    }

    // ── DeferredFreeExtentExecutor tests ─────────────────────────────

    #[test]
    fn free_extent_executor_frees_space() {
        let space = MockSpace::new();
        let mut executor = DeferredFreeExtentExecutor::new(space);
        let mut item = make_item(60, WorkItemKind::TruncateFree, 4096);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
        assert_eq!(executor.space.freed_bytes, 4096);
    }

    #[test]
    fn free_extent_executor_zero_bytes() {
        let space = MockSpace::new();
        let mut executor = DeferredFreeExtentExecutor::new(space);
        let mut item = make_item(70, WorkItemKind::SnapDelete, 0);
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
        assert_eq!(executor.space.freed_bytes, 0);
    }

    #[test]
    fn free_extent_executor_completed_item_skipped() {
        let space = MockSpace::new();
        let mut executor = DeferredFreeExtentExecutor::new(space);
        let mut item = make_item(80, WorkItemKind::PunchHoleFree, 1024);
        item.mark_complete();
        let ctx = CleanupContext::new(1, 1);

        let outcome = executor.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert_eq!(executor.space.freed_bytes, 0);
    }

    // ── CompositeJobExecutor tests ───────────────────────────────────

    #[test]
    fn composite_dispatches_unlink() {
        let mut extents = MockExtentMap::new();
        extents.set_extents(90, 2);
        let mut link = MockLinkCount::new();
        link.set(90, 2);
        let orphan = MockOrphanIndex::new();
        let dir = MockDir::new();
        let space = MockSpace::new();

        let unlink_exec = DeferredUnlinkExecutor::new(extents, link, orphan);
        let rmdir_exec = DeferredRmdirExecutor::new(dir);
        let free_exec = DeferredFreeExtentExecutor::new(space);

        let mut composite = CompositeJobExecutor::new(unlink_exec, rmdir_exec, free_exec);
        let mut item = make_item(90, WorkItemKind::UnlinkFree, 4096);
        let ctx = CleanupContext::new(1, 1);

        let outcome = composite.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
    }

    #[test]
    fn composite_dispatches_free_extent_for_truncate() {
        let extents = MockExtentMap::new();
        let link = MockLinkCount::new();
        let orphan = MockOrphanIndex::new();
        let dir = MockDir::new();
        let space = MockSpace::new();

        let unlink_exec = DeferredUnlinkExecutor::new(extents, link, orphan);
        let rmdir_exec = DeferredRmdirExecutor::new(dir);
        let free_exec = DeferredFreeExtentExecutor::new(space);

        let mut composite = CompositeJobExecutor::new(unlink_exec, rmdir_exec, free_exec);
        let mut item = make_item(91, WorkItemKind::TruncateFree, 2048);
        let ctx = CleanupContext::new(1, 1);

        let outcome = composite.execute(&mut item, &ctx);
        assert_eq!(outcome, JobOutcome::Completed);
        assert!(item.is_complete());
    }

    // ── Executor name and phase ──────────────────────────────────────

    #[test]
    fn executor_names() {
        let extents = MockExtentMap::new();
        let link = MockLinkCount::new();
        let orphan = MockOrphanIndex::new();
        let dir = MockDir::new();
        let space = MockSpace::new();

        let u = DeferredUnlinkExecutor::new(extents, link, orphan);
        assert_eq!(u.name(), "DeferredUnlinkExecutor");
        assert_eq!(u.phase(), CleanupPhase::ExtentFree);

        let r = DeferredRmdirExecutor::new(dir);
        assert_eq!(r.name(), "DeferredRmdirExecutor");
        assert_eq!(r.phase(), CleanupPhase::OrphanReap);

        let f = DeferredFreeExtentExecutor::new(space);
        assert_eq!(f.name(), "DeferredFreeExtentExecutor");
        assert_eq!(f.phase(), CleanupPhase::SpacemapUpdate);
    }
}
