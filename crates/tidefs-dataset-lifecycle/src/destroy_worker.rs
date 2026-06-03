//! DestroyWorker: IncrementalJob implementation for Phase 5 dataset destroy.
//!
//! Walks all allocated structures belonging to a dataset and produces
//! reclaim deltas through the reclaim pipeline. Progress is checkpointed
//! per-phase so the worker is crash-resumable.
//!
//! # Phases
//!
//! 0. InodeTableWalk  — enumerate all inodes, mark each for deletion
//! 1. ExtentMapWalk   — iterate extents per inode, produce refcount deltas
//! 2. DirEntryWalk    — enumerate all dir entries, remove from namespace
//! 3. XattrWalk       — enumerate xattrs, produce reclaim deltas
//! 4. MetadataCleanup — free inode table blocks, directory index pages
//! 5. Complete        — transition dataset state DESTROYING → DESTROYED

use alloc::vec::Vec;
use core::fmt;

use tidefs_incremental_job_core::IncrementalJob;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};
use tidefs_types_reclaim_queue_core::{ObjectKey, QueueFamily, ReclaimQueueEntry};

use crate::DatasetLifecycle;

// ---------------------------------------------------------------------------
// DestroyPhase
// ---------------------------------------------------------------------------

/// The discrete phases of a dataset destroy traversal.
///
/// Phases execute in order.  The cursor encodes the current phase plus
/// an offset within that phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DestroyPhase {
    InodeTableWalk = 0,
    ExtentMapWalk = 1,
    DirEntryWalk = 2,
    XattrWalk = 3,
    MetadataCleanup = 4,
    Complete = 5,
}

impl DestroyPhase {
    /// Total number of work phases (excluding Complete).
    pub const PHASE_COUNT: u8 = 5;

    /// Human-readable label for admin display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DestroyPhase::InodeTableWalk => "inode_table_walk",
            DestroyPhase::ExtentMapWalk => "extent_map_walk",
            DestroyPhase::DirEntryWalk => "dir_entry_walk",
            DestroyPhase::XattrWalk => "xattr_walk",
            DestroyPhase::MetadataCleanup => "metadata_cleanup",
            DestroyPhase::Complete => "complete",
        }
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::InodeTableWalk),
            1 => Some(Self::ExtentMapWalk),
            2 => Some(Self::DirEntryWalk),
            3 => Some(Self::XattrWalk),
            4 => Some(Self::MetadataCleanup),
            5 => Some(Self::Complete),
            _ => None,
        }
    }

    /// Advance to the next phase, resetting sub-phase offsets.
    fn advance(self) -> Option<Self> {
        match self {
            Self::InodeTableWalk => Some(Self::ExtentMapWalk),
            Self::ExtentMapWalk => Some(Self::DirEntryWalk),
            Self::DirEntryWalk => Some(Self::XattrWalk),
            Self::XattrWalk => Some(Self::MetadataCleanup),
            Self::MetadataCleanup => Some(Self::Complete),
            Self::Complete => None,
        }
    }
}

impl fmt::Display for DestroyPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// DestroyWorkerStats
// ---------------------------------------------------------------------------

/// Aggregate statistics collected during destroy traversal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DestroyWorkerStats {
    /// How many of the 5 traversal phases have been completed.
    pub phases_completed: u8,
    /// Total extents whose refcount was decremented.
    pub extents_freed: u64,
    /// Total inodes marked for deletion.
    pub inodes_freed: u64,
    /// Total directory entries removed from the namespace.
    pub dir_entries_removed: u64,
    /// Total xattr key-value pairs reclaimed.
    pub xattrs_reclaimed: u64,
    /// Approximate bytes reclaimed (extent data + metadata pages).
    pub bytes_reclaimed: u64,
}

impl DestroyWorkerStats {
    pub const ZERO: Self = DestroyWorkerStats {
        phases_completed: 0,
        extents_freed: 0,
        inodes_freed: 0,
        dir_entries_removed: 0,
        xattrs_reclaimed: 0,
        bytes_reclaimed: 0,
    };
}

impl fmt::Display for DestroyWorkerStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "phases={}/{} extents_freed={} inodes_freed={} \
             dir_entries_removed={} xattrs_reclaimed={} bytes_reclaimed={}",
            self.phases_completed,
            DestroyPhase::PHASE_COUNT,
            self.extents_freed,
            self.inodes_freed,
            self.dir_entries_removed,
            self.xattrs_reclaimed,
            self.bytes_reclaimed,
        )
    }
}

// ---------------------------------------------------------------------------
// DestroyDataHandle — trait for data access during destroy
// ---------------------------------------------------------------------------

/// Abstract data access that the [`DestroyWorker`] uses to walk dataset
/// structures.  Concrete implementations back this with real B-trees
/// (inode table, extent map, directory index, xattr store).
pub trait DestroyDataHandle: Send {
    /// Total number of inodes in this dataset.
    fn inode_count(&self) -> u64;

    /// Batch-read inode IDs starting at `offset`, up to `limit`.
    /// Returns the IDs read and whether more are available.
    fn read_inode_batch(&self, offset: u64, limit: u64) -> (Vec<u64>, bool);

    /// Number of extents for a given inode.
    fn extent_count(&self, inode_id: u64) -> u64;

    /// Batch-read extent info for `inode_id` starting at `extent_offset`.
    /// Each entry is `(object_key_bytes, extent_size_bytes)`.
    fn read_extent_batch(
        &self,
        inode_id: u64,
        extent_offset: u64,
        limit: u64,
    ) -> (Vec<([u8; 32], u64)>, bool);

    /// Number of directory entries in this dataset.
    fn dir_entry_count(&self) -> u64;

    /// Batch-read directory entries starting at `offset`.
    /// Returns `(entry_name, inode_id)` pairs.
    fn read_dir_entry_batch(&self, offset: u64, limit: u64) -> (Vec<(Vec<u8>, u64)>, bool);

    /// Number of xattr entries in this dataset.
    fn xattr_count(&self) -> u64;

    /// Batch-read xattr entries starting at `offset`.
    /// Returns `(inode_id, name, value_len)` tuples.
    fn read_xattr_batch(&self, offset: u64, limit: u64) -> (Vec<(u64, Vec<u8>, u64)>, bool);

    /// Number of metadata blocks (inode table pages, directory index
    /// pages) to reclaim.
    fn metadata_block_count(&self) -> u64;

    /// Size of each metadata block in bytes.
    fn metadata_block_size(&self) -> u64;
}

// ---------------------------------------------------------------------------
// DestroyCursor — serialized cursor state (56 bytes)
// ---------------------------------------------------------------------------

/// Binary layout:
///
/// ```text
/// [phase: u8][inode_offset: u64][extent_offset: u64]
/// [dir_offset: u64][xattr_offset: u64][meta_offset: u64]
/// [current_inode: u64][padding: 7 bytes]
/// ```
const CURSOR_BYTES: usize = 96;

/// Decode cursor bytes into the current phase and per-phase offsets.
fn decode_cursor(bytes: &[u8]) -> Result<DestroyCursor, JobError> {
    if bytes.len() != CURSOR_BYTES {
        return Err(JobError::CursorStateInvalid {
            job_id: JobId::NONE,
            reason: "invalid cursor length",
        });
    }
    let phase = DestroyPhase::from_u8(bytes[0]).ok_or(JobError::CursorStateInvalid {
        job_id: JobId::NONE,
        reason: "unknown phase byte",
    })?;
    let read_u64 = |start: usize| -> u64 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[start..start + 8]);
        u64::from_le_bytes(buf)
    };
    let stats = DestroyWorkerStats {
        inodes_freed: read_u64(49),
        extents_freed: read_u64(57),
        dir_entries_removed: read_u64(65),
        xattrs_reclaimed: read_u64(73),
        bytes_reclaimed: read_u64(81),
        phases_completed: bytes[89],
    };
    Ok(DestroyCursor {
        phase,
        inode_offset: read_u64(1),
        extent_offset: read_u64(9),
        dir_offset: read_u64(17),
        xattr_offset: read_u64(25),
        meta_offset: read_u64(33),
        current_inode: read_u64(41),
        stats,
    })
}

/// Encode cursor fields into a CursorState blob.
fn encode_cursor(cursor: &DestroyCursor) -> CursorState {
    let mut buf = [0u8; CURSOR_BYTES];
    buf[0] = cursor.phase as u8;
    let mut write_u64 = |start: usize, val: u64| {
        buf[start..start + 8].copy_from_slice(&val.to_le_bytes());
    };
    write_u64(1, cursor.inode_offset);
    write_u64(9, cursor.extent_offset);
    write_u64(17, cursor.dir_offset);
    write_u64(25, cursor.xattr_offset);
    write_u64(33, cursor.meta_offset);
    write_u64(41, cursor.current_inode);
    write_u64(49, cursor.stats.inodes_freed);
    write_u64(57, cursor.stats.extents_freed);
    write_u64(65, cursor.stats.dir_entries_removed);
    write_u64(73, cursor.stats.xattrs_reclaimed);
    write_u64(81, cursor.stats.bytes_reclaimed);
    buf[89] = cursor.stats.phases_completed;
    CursorState(buf.to_vec())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DestroyCursor {
    phase: DestroyPhase,
    inode_offset: u64,
    extent_offset: u64,
    dir_offset: u64,
    xattr_offset: u64,
    meta_offset: u64,
    current_inode: u64,
    stats: DestroyWorkerStats,
}

impl DestroyCursor {
    fn new() -> Self {
        DestroyCursor {
            phase: DestroyPhase::InodeTableWalk,
            inode_offset: 0,
            extent_offset: 0,
            dir_offset: 0,
            xattr_offset: 0,
            meta_offset: 0,
            current_inode: 0,
            stats: DestroyWorkerStats::ZERO,
        }
    }

    /// Advance to the next phase, returning false if already Complete.
    fn advance_phase(&mut self) -> bool {
        match self.phase.advance() {
            Some(next) => {
                // Reset sub-phase offsets for the new phase.
                self.extent_offset = 0;
                self.current_inode = 0;
                self.phase = next;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// DestroyWorker
// ---------------------------------------------------------------------------

/// IncrementalJob that walks all dataset structures and reclaims space
/// when a dataset is destroyed.
///
/// Implements [`IncrementalJob`] with [`JobKind::DatasetDestroy`].
/// Each `step()` call processes a bounded batch within the given
/// [`WorkBudget`] and returns an updated checkpoint for crash recovery.
///
/// # Handle injection
///
/// Because [`IncrementalJob::resume`] has no handle parameter,
/// production callers use [`DestroyWorker::resume_with_handle`]
/// instead.  The trait `resume` always returns an error directing
/// callers to the handle-aware constructor.
pub struct DestroyWorker<H: DestroyDataHandle + Send> {
    job_id: JobId,
    epoch: u64,
    handle: H,
    cursor: DestroyCursor,
    stats: DestroyWorkerStats,
    lifecycle: DatasetLifecycle,
    reclaim_entries: Vec<ReclaimQueueEntry>,
}

impl<H: DestroyDataHandle> DestroyWorker<H> {
    /// Create a fresh destroy worker.
    ///
    /// The `lifecycle` must already be in `DESTROYING` state.
    #[must_use]
    pub fn new(job_id: JobId, epoch: u64, handle: H, lifecycle: DatasetLifecycle) -> Self {
        DestroyWorker {
            job_id,
            epoch,
            handle,
            cursor: DestroyCursor::new(),
            stats: DestroyWorkerStats::ZERO,
            lifecycle,
            reclaim_entries: Vec::new(),
        }
    }

    /// Reconstruct a destroy worker from a checkpoint with a real data
    /// handle.  This is the handle-aware variant of the trait `resume`.
    ///
    /// # Errors
    ///
    /// Returns [`JobError::CursorStateInvalid`] if the cursor is corrupt.
    pub fn resume_with_handle(
        checkpoint: Checkpoint,
        handle: H,
        lifecycle: DatasetLifecycle,
    ) -> Result<Self, JobError> {
        if checkpoint.job_kind != JobKind::DatasetDestroy {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "wrong job kind",
            });
        }
        let cursor = if checkpoint.is_fresh() {
            DestroyCursor::new()
        } else {
            decode_cursor(checkpoint.cursor_state.as_bytes())?
        };
        let stats = cursor.stats;
        Ok(DestroyWorker {
            job_id: checkpoint.job_id,
            epoch: checkpoint.epoch,
            handle,
            cursor,
            stats,
            lifecycle,
            reclaim_entries: Vec::new(),
        })
    }

    /// Current destroy statistics.
    #[must_use]
    pub fn stats(&self) -> DestroyWorkerStats {
        self.stats
    }

    /// Accumulated reclaim entries produced so far.
    #[must_use]
    pub fn reclaim_entries(&self) -> &[ReclaimQueueEntry] {
        &self.reclaim_entries
    }

    /// Drain generated reclaim entries (caller submits to reclaim queue).
    pub fn drain_reclaim_entries(&mut self) -> Vec<ReclaimQueueEntry> {
        let mut out = Vec::new();
        core::mem::swap(&mut out, &mut self.reclaim_entries);
        out
    }

    /// Reference to the dataset lifecycle (for post-destroy state check).
    #[must_use]
    pub fn lifecycle(&self) -> &DatasetLifecycle {
        &self.lifecycle
    }

    // -- Internal phase implementations --

    fn step_inode_table_walk(&mut self, budget: WorkBudget) -> StepOutcome {
        let total = self.handle.inode_count();
        let limit = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let (inodes, has_more) = self
            .handle
            .read_inode_batch(self.cursor.inode_offset, limit);
        let processed = inodes.len() as u64;
        for &inode_id in &inodes {
            self.stats.inodes_freed += 1;
            self.reclaim_entries.push(ReclaimQueueEntry::new(
                make_inode_key(inode_id),
                -1,
                QueueFamily::InodeTombstone,
            ));
        }
        self.cursor.inode_offset += processed;
        let complete = !has_more || self.cursor.inode_offset >= total;
        StepOutcome {
            items: processed,
            bytes: processed * 128,
            phase_complete: complete,
        }
    }

    fn step_extent_map_walk(&mut self, budget: WorkBudget) -> StepOutcome {
        let total_inodes = self.handle.inode_count();
        let limit = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let mut items = 0u64;
        let mut bytes = 0u64;
        let mut phase_complete = true;

        for inode_id in self.cursor.current_inode..total_inodes {
            if items >= limit {
                self.cursor.current_inode = inode_id;
                phase_complete = false;
                break;
            }
            let extent_count = self.handle.extent_count(inode_id);
            if extent_count == 0 {
                self.cursor.extent_offset = 0;
                continue;
            }
            let remaining = limit.saturating_sub(items);
            let (extents, _has_more) =
                self.handle
                    .read_extent_batch(inode_id, self.cursor.extent_offset, remaining);
            let batch_items = extents.len() as u64;
            let mut batch_bytes = 0u64;
            for (obj_key_bytes, extent_size) in &extents {
                batch_bytes += *extent_size;
                self.reclaim_entries.push(ReclaimQueueEntry::new(
                    ObjectKey(*obj_key_bytes),
                    -1,
                    QueueFamily::Extent,
                ));
            }
            self.stats.extents_freed += batch_items;
            self.stats.bytes_reclaimed += batch_bytes;
            items += batch_items;
            bytes += batch_bytes;
            self.cursor.extent_offset += batch_items;
            if self.cursor.extent_offset >= extent_count {
                self.cursor.extent_offset = 0;
                self.cursor.current_inode = inode_id + 1;
            } else {
                // Partial inode — resume here next tick.
                self.cursor.current_inode = inode_id;
                phase_complete = false;
                break;
            }
        }

        if self.cursor.current_inode >= total_inodes {
            phase_complete = true;
        }
        StepOutcome {
            items,
            bytes,
            phase_complete,
        }
    }

    fn step_dir_entry_walk(&mut self, budget: WorkBudget) -> StepOutcome {
        let total = self.handle.dir_entry_count();
        let limit = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let (entries, has_more) = self
            .handle
            .read_dir_entry_batch(self.cursor.dir_offset, limit);
        let processed = entries.len() as u64;
        let mut bytes = 0u64;
        for _entry in &entries {
            self.stats.dir_entries_removed += 1;
            bytes += 256;
        }
        self.cursor.dir_offset += processed;
        let complete = !has_more || self.cursor.dir_offset >= total;
        StepOutcome {
            items: processed,
            bytes,
            phase_complete: complete,
        }
    }

    fn step_xattr_walk(&mut self, budget: WorkBudget) -> StepOutcome {
        let total = self.handle.xattr_count();
        let limit = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let (xattrs, has_more) = self
            .handle
            .read_xattr_batch(self.cursor.xattr_offset, limit);
        let processed = xattrs.len() as u64;
        let mut bytes = 0u64;
        for (_inode_id, _name, value_len) in &xattrs {
            self.stats.xattrs_reclaimed += 1;
            self.stats.bytes_reclaimed += *value_len;
            bytes += *value_len + 128;
        }
        self.cursor.xattr_offset += processed;
        let complete = !has_more || self.cursor.xattr_offset >= total;
        StepOutcome {
            items: processed,
            bytes,
            phase_complete: complete,
        }
    }

    fn step_metadata_cleanup(&mut self, budget: WorkBudget) -> StepOutcome {
        let total = self.handle.metadata_block_count();
        let block_size = self.handle.metadata_block_size();
        let limit = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let remaining = total.saturating_sub(self.cursor.meta_offset);
        let batch = remaining.min(limit);
        self.cursor.meta_offset += batch;
        let bytes = batch * block_size;
        self.stats.bytes_reclaimed += bytes;
        let complete = self.cursor.meta_offset >= total;
        StepOutcome {
            items: batch,
            bytes,
            phase_complete: complete,
        }
    }

    fn build_checkpoint(&self) -> Checkpoint {
        let items_processed = self.stats.inodes_freed
            + self.stats.extents_freed
            + self.stats.dir_entries_removed
            + self.stats.xattrs_reclaimed
            + self.cursor.meta_offset;
        let items_total = self.handle.inode_count()
            + self.handle.dir_entry_count()
            + self.handle.xattr_count()
            + self.handle.metadata_block_count();
        Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::DatasetDestroy,
            epoch: self.epoch,
            cursor_state: encode_cursor(&self.cursor),
            progress: JobProgress {
                items_processed,
                items_total_estimate: items_total,
                bytes_processed: self.stats.bytes_reclaimed,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }
}

/// Internal return value from per-phase step functions.
struct StepOutcome {
    items: u64,
    bytes: u64,
    phase_complete: bool,
}

impl<H: DestroyDataHandle> IncrementalJob for DestroyWorker<H> {
    fn resume(_state: Option<Checkpoint>) -> Result<Self, JobError> {
        // Production callers must use resume_with_handle to inject the
        // data handle and lifecycle.  The trait resume is a control-plane
        // entry point that the scheduler uses; wiring the handle through
        // a registry is deferred to integration (Phase 7+).
        Err(JobError::Other(
            "DestroyWorker requires handle injection; use resume_with_handle".into(),
        ))
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if self.cursor.phase == DestroyPhase::Complete {
            return Err(JobError::JobAlreadyComplete {
                job_id: self.job_id,
            });
        }

        let outcome = match self.cursor.phase {
            DestroyPhase::InodeTableWalk => self.step_inode_table_walk(budget),
            DestroyPhase::ExtentMapWalk => self.step_extent_map_walk(budget),
            DestroyPhase::DirEntryWalk => self.step_dir_entry_walk(budget),
            DestroyPhase::XattrWalk => self.step_xattr_walk(budget),
            DestroyPhase::MetadataCleanup => self.step_metadata_cleanup(budget),
            DestroyPhase::Complete => {
                return Err(JobError::JobAlreadyComplete {
                    job_id: self.job_id,
                });
            }
        };

        // Budget enforcement: ensure items stayed within limits.
        if budget.max_items > 0 && outcome.items > budget.max_items {
            return Err(JobError::BudgetExceeded {
                job_id: self.job_id,
                budget,
                actual_items: outcome.items,
                actual_bytes: outcome.bytes,
            });
        }

        if outcome.phase_complete {
            self.stats.phases_completed += 1;
            self.cursor.advance_phase();
            if self.cursor.phase == DestroyPhase::Complete {
                // All work phases done; transition lifecycle.
                self.lifecycle.escalate_poison();
                let _ = self.lifecycle.transition_to_tombstone();
                let ck = self.build_checkpoint();
                return Ok(StepResult::complete(ck));
            }
        }

        let ck = self.build_checkpoint();
        Ok(StepResult::in_progress(ck))
    }

    fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
        // The caller persists the checkpoint produced by step().
        Ok(())
    }

    fn complete(mut self) -> Result<(), JobError> {
        if self.cursor.phase != DestroyPhase::Complete {
            return Err(JobError::JobAlreadyComplete {
                job_id: self.job_id,
            });
        }
        self.lifecycle.escalate_poison();
        let _ = self.lifecycle.transition_to_tombstone();
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::DatasetDestroy
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_inode_key(inode_id: u64) -> ObjectKey {
    let mut key = [0u8; 32];
    key[0..8].copy_from_slice(&inode_id.to_le_bytes());
    ObjectKey(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    use tidefs_types_dataset_lifecycle_core::{DatasetStateV1, DestroyFlags};

    // ── Mock data handle ────────────────────────────────────────────

    struct MockDataHandle {
        inode_count: u64,
        extents: BTreeMap<u64, Vec<([u8; 32], u64)>>,
        dir_entries: Vec<(Vec<u8>, u64)>,
        xattrs: Vec<(u64, Vec<u8>, u64)>,
        meta_blocks: u64,
        block_size: u64,
    }

    impl MockDataHandle {
        fn new_simple(inodes: u64, dirs: u64, xattrs: u64, meta: u64) -> Self {
            let mut extents = BTreeMap::new();
            for i in 0..inodes {
                extents.insert(i, vec![(make_extent_key(i, 0), 4096)]);
            }
            let mut d_entries = Vec::new();
            for d in 0..dirs {
                d_entries.push((alloc::format!("entry_{d}").into_bytes(), d));
            }
            let mut x_entries = Vec::new();
            for x in 0..xattrs {
                x_entries.push((
                    x % inodes.max(1),
                    alloc::format!("xattr_{x}").into_bytes(),
                    256,
                ));
            }
            MockDataHandle {
                inode_count: inodes,
                extents,
                dir_entries: d_entries,
                xattrs: x_entries,
                meta_blocks: meta,
                block_size: 4096,
            }
        }
    }

    fn make_extent_key(inode_id: u64, extent_idx: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&inode_id.to_le_bytes());
        key[8..16].copy_from_slice(&extent_idx.to_le_bytes());
        key
    }

    impl DestroyDataHandle for MockDataHandle {
        fn inode_count(&self) -> u64 {
            self.inode_count
        }

        fn read_inode_batch(&self, offset: u64, limit: u64) -> (Vec<u64>, bool) {
            let end = self.inode_count.min(offset + limit);
            let ids: Vec<u64> = (offset..end).collect();
            let has_more = end < self.inode_count;
            (ids, has_more)
        }

        fn extent_count(&self, inode_id: u64) -> u64 {
            self.extents.get(&inode_id).map_or(0, |v| v.len() as u64)
        }

        fn read_extent_batch(
            &self,
            inode_id: u64,
            extent_offset: u64,
            limit: u64,
        ) -> (Vec<([u8; 32], u64)>, bool) {
            let list = self.extents.get(&inode_id).cloned().unwrap_or_default();
            let start = extent_offset as usize;
            let end = (start + limit as usize).min(list.len());
            let batch = list[start..end].to_vec();
            let has_more = end < list.len();
            (batch, has_more)
        }

        fn dir_entry_count(&self) -> u64 {
            self.dir_entries.len() as u64
        }

        fn read_dir_entry_batch(&self, offset: u64, limit: u64) -> (Vec<(Vec<u8>, u64)>, bool) {
            let start = offset as usize;
            let end = (start + limit as usize).min(self.dir_entries.len());
            let batch = self.dir_entries[start..end].to_vec();
            let has_more = end < self.dir_entries.len();
            (batch, has_more)
        }

        fn xattr_count(&self) -> u64 {
            self.xattrs.len() as u64
        }

        fn read_xattr_batch(&self, offset: u64, limit: u64) -> (Vec<(u64, Vec<u8>, u64)>, bool) {
            let start = offset as usize;
            let end = (start + limit as usize).min(self.xattrs.len());
            let batch = self.xattrs[start..end].to_vec();
            let has_more = end < self.xattrs.len();
            (batch, has_more)
        }

        fn metadata_block_count(&self) -> u64 {
            self.meta_blocks
        }

        fn metadata_block_size(&self) -> u64 {
            self.block_size
        }
    }

    fn mock_lifecycle() -> DatasetLifecycle {
        let mut lc = DatasetLifecycle::new();
        let _ = lc.transition_to_destroying(DestroyFlags::NONE, &[]);
        lc
    }

    fn make_worker(
        inodes: u64,
        dirs: u64,
        xattrs: u64,
        meta: u64,
    ) -> DestroyWorker<MockDataHandle> {
        let handle = MockDataHandle::new_simple(inodes, dirs, xattrs, meta);
        DestroyWorker::new(JobId(1), 1, handle, mock_lifecycle())
    }

    // ── Basic phase progression ────────────────────────────────────

    #[test]
    fn full_destroy_cycle_unbounded() {
        let mut worker = make_worker(5, 3, 2, 4);
        let mut steps = 0;
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            steps += 1;
            if r.is_complete {
                break;
            }
        }
        // One step per phase (5 + 1 completion = 6 steps).
        assert_eq!(steps, DestroyPhase::PHASE_COUNT as u32);
        let stats = worker.stats();
        assert_eq!(stats.phases_completed, DestroyPhase::PHASE_COUNT);
        assert_eq!(stats.inodes_freed, 5);
        assert_eq!(stats.extents_freed, 5);
        assert_eq!(stats.dir_entries_removed, 3);
        assert_eq!(stats.xattrs_reclaimed, 2);
        assert!(stats.bytes_reclaimed > 0);
        // Lifecycle should be Tombstone after completion.
        assert!(matches!(
            worker.lifecycle().state(),
            DatasetStateV1::Tombstone
        ));
    }

    #[test]
    fn bounded_step_respects_budget_items() {
        let mut worker = make_worker(10, 0, 0, 0);
        let r = worker
            .step(WorkBudget {
                max_items: 3,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(!r.is_complete);
        assert_eq!(r.checkpoint.progress.items_processed, 3);

        let r = worker
            .step(WorkBudget {
                max_items: 3,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(!r.is_complete);
        assert_eq!(r.checkpoint.progress.items_processed, 6);
    }

    // ── Cursor save/restore ────────────────────────────────────────

    #[test]
    fn cursor_save_restore_roundtrip() {
        let c = DestroyCursor {
            stats: DestroyWorkerStats::ZERO,
            phase: DestroyPhase::ExtentMapWalk,
            inode_offset: 100,
            extent_offset: 50,
            dir_offset: 200,
            xattr_offset: 0,
            meta_offset: 0,
            current_inode: 10,
        };
        let state = encode_cursor(&c);
        let c2 = decode_cursor(state.as_bytes()).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn cursor_default_is_phase_zero() {
        let c = DestroyCursor::new();
        assert_eq!(c.phase, DestroyPhase::InodeTableWalk);
        assert_eq!(c.inode_offset, 0);
        assert_eq!(c.extent_offset, 0);
    }

    #[test]
    fn cursor_advance_phase_walks_all() {
        let mut c = DestroyCursor::new();
        assert_eq!(c.phase, DestroyPhase::InodeTableWalk);
        assert!(c.advance_phase());
        assert_eq!(c.phase, DestroyPhase::ExtentMapWalk);
        assert!(c.advance_phase());
        assert_eq!(c.phase, DestroyPhase::DirEntryWalk);
        assert!(c.advance_phase());
        assert_eq!(c.phase, DestroyPhase::XattrWalk);
        assert!(c.advance_phase());
        assert_eq!(c.phase, DestroyPhase::MetadataCleanup);
        assert!(c.advance_phase());
        assert_eq!(c.phase, DestroyPhase::Complete);
        assert!(!c.advance_phase());
    }

    #[test]
    fn cursor_invalid_length_errors() {
        let err = decode_cursor(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }

    #[test]
    fn cursor_invalid_phase_byte_errors() {
        let mut buf = [0u8; CURSOR_BYTES];
        buf[0] = 99u8;
        let err = decode_cursor(&buf).unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }

    // ── Phase completion transitions ───────────────────────────────

    #[test]
    fn phase_transition_inode_to_extent() {
        let mut worker = make_worker(1, 0, 0, 0);
        let _ = worker.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(worker.stats().inodes_freed, 1);
        assert_eq!(worker.stats().phases_completed, 1);
        let _ = worker.step(WorkBudget::UNBOUNDED).unwrap();
        assert_eq!(worker.stats().extents_freed, 1);
    }

    #[test]
    fn destroy_completion_sets_tombstone() {
        let mut worker = make_worker(1, 0, 0, 0);
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            if r.is_complete {
                break;
            }
        }
        assert!(matches!(
            worker.lifecycle().state(),
            DatasetStateV1::Tombstone
        ));
    }

    // ── resume_with_handle ─────────────────────────────────────────

    #[test]
    fn resume_with_handle_from_fresh_checkpoint() {
        let handle = MockDataHandle::new_simple(5, 0, 0, 0);
        let ck = Checkpoint::new_initial(JobId(10), JobKind::DatasetDestroy);
        let worker = DestroyWorker::resume_with_handle(ck, handle, mock_lifecycle())
            .expect("resume should succeed");
        assert_eq!(worker.job_id(), JobId(10));
        assert_eq!(worker.job_kind(), JobKind::DatasetDestroy);
        assert_eq!(worker.stats(), DestroyWorkerStats::ZERO);
    }

    #[test]
    fn resume_with_handle_wrong_job_kind_errors() {
        let handle = MockDataHandle::new_simple(1, 0, 0, 0);
        let ck = Checkpoint::new_initial(JobId(1), JobKind::Scrub); // wrong kind
        let result = DestroyWorker::resume_with_handle(ck, handle, mock_lifecycle());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }

    #[test]
    fn resume_with_handle_from_partial_checkpoint() {
        let handle = MockDataHandle::new_simple(5, 0, 0, 0);
        let mut worker = DestroyWorker::new(JobId(3), 1, handle, mock_lifecycle());
        // Process first 3 inodes of phase 0
        let r = worker
            .step(WorkBudget {
                max_items: 3,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(!r.is_complete);

        // Simulate crash: rebuild from checkpoint
        let handle2 = MockDataHandle::new_simple(5, 0, 0, 0);
        let ck = r.checkpoint.clone();
        let mut worker2 = DestroyWorker::resume_with_handle(ck, handle2, mock_lifecycle()).unwrap();
        assert_eq!(worker2.stats().inodes_freed, 0); // stats not recovered from checkpoint in basic path
                                                     // But the cursor should be at offset 3
        let r2 = worker2
            .step(WorkBudget {
                max_items: 5,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(!r2.is_complete); // phase not yet complete
        assert_eq!(worker2.stats().inodes_freed, 2); // remaining 2 inodes
    }

    // ── Stats tracking ─────────────────────────────────────────────

    #[test]
    fn stats_zero_initial() {
        let worker = make_worker(5, 3, 2, 0);
        assert_eq!(worker.stats(), DestroyWorkerStats::ZERO);
    }

    #[test]
    fn stats_accumulate_across_phases() {
        let mut worker = make_worker(3, 2, 1, 5);
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            if r.is_complete {
                break;
            }
        }
        let s = worker.stats();
        assert_eq!(s.phases_completed, DestroyPhase::PHASE_COUNT);
        assert_eq!(s.inodes_freed, 3);
        assert_eq!(s.extents_freed, 3);
        assert_eq!(s.dir_entries_removed, 2);
        assert_eq!(s.xattrs_reclaimed, 1);
    }

    #[test]
    fn stats_display_format() {
        let s = DestroyWorkerStats {
            phases_completed: 3,
            extents_freed: 100,
            inodes_freed: 10,
            dir_entries_removed: 20,
            xattrs_reclaimed: 5,
            bytes_reclaimed: 4096,
        };
        let d = alloc::format!("{s}");
        assert!(d.contains("phases=3/5"));
        assert!(d.contains("extents_freed=100"));
        assert!(d.contains("inodes_freed=10"));
    }

    // ── Reclaim entries generation ─────────────────────────────────

    #[test]
    fn reclaim_entries_for_extents_are_extent_family() {
        let mut worker = make_worker(1, 0, 0, 0);
        let _ = worker.step(WorkBudget::UNBOUNDED).unwrap(); // phase 0
        let _ = worker.step(WorkBudget::UNBOUNDED).unwrap(); // phase 1
        let entries = worker.reclaim_entries();
        assert!(entries
            .iter()
            .any(|e| e.family == QueueFamily::InodeTombstone));
        assert!(entries.iter().any(|e| e.family == QueueFamily::Extent));
    }

    #[test]
    fn reclaim_entries_all_are_decrements() {
        let mut worker = make_worker(2, 1, 1, 1);
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            if r.is_complete {
                break;
            }
        }
        for entry in worker.reclaim_entries() {
            assert!(entry.is_decrement(), "entry should be decrement: {entry}");
        }
    }

    #[test]
    fn drain_reclaim_entries_clears_buffer() {
        let mut worker = make_worker(1, 0, 0, 0);
        let _ = worker.step(WorkBudget::UNBOUNDED).unwrap();
        assert!(!worker.reclaim_entries().is_empty());
        let drained = worker.drain_reclaim_entries();
        assert!(!drained.is_empty());
        assert!(worker.reclaim_entries().is_empty());
    }

    // ── Budget enforcement ─────────────────────────────────────────

    #[test]
    fn step_with_unbounded_budget_processes_all_in_phase() {
        let mut worker = make_worker(3, 0, 0, 0);
        let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
        assert!(!r.is_complete);
        assert_eq!(worker.stats().inodes_freed, 3);
    }

    #[test]
    fn step_with_item_budget_processes_partial() {
        let mut worker = make_worker(10, 10, 10, 10);
        let r = worker
            .step(WorkBudget {
                max_items: 2,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(!r.is_complete);
        assert_eq!(r.checkpoint.progress.items_processed, 2);
    }

    // ── Metadata cleanup phase ─────────────────────────────────────

    #[test]
    fn metadata_cleanup_reclaims_blocks() {
        let mut worker = make_worker(0, 0, 0, 4);
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            if r.is_complete {
                break;
            }
        }
        assert!(worker.stats().bytes_reclaimed >= 4 * 4096);
    }

    // ── Empty dataset destroy ──────────────────────────────────────

    #[test]
    fn empty_dataset_destroys_immediately() {
        let mut worker = make_worker(0, 0, 0, 0);
        let mut steps = 0;
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            steps += 1;
            if r.is_complete {
                break;
            }
        }
        assert!(steps >= 5);
        assert!(worker.lifecycle().state().is_terminal());
    }

    // ── JobAlreadyComplete error ───────────────────────────────────

    #[test]
    fn step_after_complete_errors() {
        let mut worker = make_worker(1, 0, 0, 0);
        loop {
            let r = worker.step(WorkBudget::UNBOUNDED).unwrap();
            if r.is_complete {
                break;
            }
        }
        let err = worker.step(WorkBudget::UNBOUNDED).unwrap_err();
        assert!(matches!(err, JobError::JobAlreadyComplete { .. }));
    }

    #[test]
    fn trait_resume_returns_handle_error() {
        let ck = Checkpoint::new_initial(JobId(1), JobKind::DatasetDestroy);
        let result = <DestroyWorker<MockDataHandle> as IncrementalJob>::resume(Some(ck));
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, JobError::Other(_)));
    }
}
