// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Device evacuation engine: safely drains all object data from a target
//! device onto remaining pool members.
//!
//! Implements the evacuate path for safe device removal:
//! plan → copy each extent → update locator entries → track progress.
//!
//! # Traits
//!
//! - [`EvacuationAllocator`] – allocate space on remaining devices.
//! - [`EvacuationIo`] – read old extent data and write to new locations.
//! - [`EvacuationLocator`] – atomically update locator-table entries.
//!
//! # Flow
//!
//! ```text
//! EvacuationPlan
//!   → evacuate_device() per-entry loop
//!     → allocator.allocate_on_remaining()
//!     → io.read_extent() from old location
//!     → io.write_extent() to new location
//!     → locator.update_entry() atomically
//!     → stats.record_success() / record_failure()
//! ```

// ── Local types (no external deps to avoid cyclic imports) ────────

/// A single extent entry in an evacuation plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvacuationEntry {
    /// Pool-wide unique extent identifier.
    pub extent_id: u64,
    /// Inode that owns this extent.
    pub inode: u64,
    /// Logical byte offset within the file.
    pub logical_offset: u64,
    /// Device the extent currently resides on.
    pub device_id: u64,
    /// Physical byte offset on the current device.
    pub physical_offset: u64,
    /// Length of this extent in bytes.
    pub length: u32,
    /// Entry flags (compressed, encrypted, checksum type, etc.).
    pub flags: u8,
}

impl EvacuationEntry {
    #[must_use]
    pub const fn new(
        extent_id: u64,
        inode: u64,
        logical_offset: u64,
        device_id: u64,
        physical_offset: u64,
        length: u32,
        flags: u8,
    ) -> Self {
        Self {
            extent_id,
            inode,
            logical_offset,
            device_id,
            physical_offset,
            length,
            flags,
        }
    }
}

/// A plan for evacuating all data from a target device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvacuationPlan {
    /// The device to evacuate.
    pub device_id: u64,
    /// All extent entries resident on the target device.
    pub entries: alloc::vec::Vec<EvacuationEntry>,
    /// Total bytes to relocate across all entries.
    pub total_bytes: u64,
    /// Number of distinct inodes referenced by the entries.
    pub distinct_inodes: usize,
}

impl EvacuationPlan {
    #[must_use]
    pub fn from_entries(device_id: u64, entries: alloc::vec::Vec<EvacuationEntry>) -> Self {
        let total_bytes = entries.iter().map(|e| u64::from(e.length)).sum();
        let inode_set: std::collections::BTreeSet<u64> = entries.iter().map(|e| e.inode).collect();
        Self {
            device_id,
            total_bytes,
            distinct_inodes: inode_set.len(),
            entries,
        }
    }

    #[must_use]
    pub const fn empty(device_id: u64) -> Self {
        Self {
            device_id,
            entries: alloc::vec::Vec::new(),
            total_bytes: 0,
            distinct_inodes: 0,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn take_chunk(&mut self, chunk_size: usize) -> alloc::vec::Vec<EvacuationEntry> {
        let take = chunk_size.min(self.entries.len());
        let chunk: alloc::vec::Vec<EvacuationEntry> = self.entries.drain(..take).collect();
        let chunk_bytes: u64 = chunk.iter().map(|e| u64::from(e.length)).sum();
        self.total_bytes = self.total_bytes.saturating_sub(chunk_bytes);
        let remaining_inodes: std::collections::BTreeSet<u64> =
            self.entries.iter().map(|e| e.inode).collect();
        self.distinct_inodes = remaining_inodes.len();
        chunk
    }
}

/// Progress statistics for an in-flight device evacuation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EvacuationStats {
    /// Number of extents successfully evacuated so far.
    pub entries_evacuated: u64,
    /// Number of extents that could not be evacuated.
    pub entries_failed: u64,
    /// Total bytes successfully relocated.
    pub bytes_evacuated: u64,
    /// Total bytes that could not be relocated.
    pub bytes_failed: u64,
    /// Number of distinct inodes whose extents have been fully evacuated.
    pub distinct_inodes_completed: u64,
    /// Time when evacuation started (ns since epoch).
    pub started_at_ns: u64,
    /// Time of last progress (ns since epoch).
    pub last_progress_at_ns: u64,
}

impl EvacuationStats {
    #[must_use]
    pub const fn new(started_at_ns: u64) -> Self {
        Self {
            entries_evacuated: 0,
            entries_failed: 0,
            bytes_evacuated: 0,
            bytes_failed: 0,
            distinct_inodes_completed: 0,
            started_at_ns,
            last_progress_at_ns: started_at_ns,
        }
    }

    pub fn record_success(&mut self, length: u32, now_ns: u64) {
        self.entries_evacuated = self.entries_evacuated.saturating_add(1);
        self.bytes_evacuated = self.bytes_evacuated.saturating_add(u64::from(length));
        self.last_progress_at_ns = now_ns;
    }

    pub fn record_failure(&mut self, length: u32, now_ns: u64) {
        self.entries_failed = self.entries_failed.saturating_add(1);
        self.bytes_failed = self.bytes_failed.saturating_add(u64::from(length));
        self.last_progress_at_ns = now_ns;
    }

    pub fn record_inode_completed(&mut self) {
        self.distinct_inodes_completed = self.distinct_inodes_completed.saturating_add(1);
    }

    #[must_use]
    pub fn total_entries_processed(&self) -> u64 {
        self.entries_evacuated.saturating_add(self.entries_failed)
    }
}

// ── Error type ───────────────────────────────────────────────────────

/// Errors that can occur during device evacuation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvacuationError {
    /// No remaining devices to evacuate to.
    NoRemainingDevices,
    /// Allocation failed on all remaining devices.
    AllocationFailed { size: u32 },
    /// Read from old location failed.
    ReadFailed {
        device_id: u64,
        physical_offset: u64,
        length: u32,
    },
    /// Write to new location failed.
    WriteFailed {
        device_id: u64,
        physical_offset: u64,
    },
    /// Locator-table update failed.
    LocatorUpdateFailed { inode: u64, extent_id: u64 },
    /// The extent is pinned and cannot be relocated right now.
    ExtentPinned { inode: u64, extent_id: u64 },
}

impl core::fmt::Display for EvacuationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoRemainingDevices => f.write_str("no remaining devices for evacuation"),
            Self::AllocationFailed { size } => {
                write!(
                    f,
                    "allocation of {size} bytes failed on all remaining devices"
                )
            }
            Self::ReadFailed {
                device_id,
                physical_offset,
                length,
            } => write!(
                f,
                "read failed: device {device_id} offset {physical_offset} length {length}"
            ),
            Self::WriteFailed {
                device_id,
                physical_offset,
            } => write!(
                f,
                "write failed: device {device_id} offset {physical_offset}"
            ),
            Self::LocatorUpdateFailed { inode, extent_id } => {
                write!(
                    f,
                    "locator update failed for inode {inode} extent {extent_id}"
                )
            }
            Self::ExtentPinned { inode, extent_id } => {
                write!(f, "extent {extent_id} in inode {inode} is pinned")
            }
        }
    }
}

// ── Traits ───────────────────────────────────────────────────────────

/// Allocates space on remaining pool devices during evacuation.
pub trait EvacuationAllocator {
    /// Allocate `length` bytes on any remaining device (not
    /// `exclude_device_id`). Returns the new `(device_id,
    /// physical_offset)` pair.
    fn allocate_on_remaining(
        &mut self,
        exclude_device_id: u64,
        length: u32,
    ) -> Result<(u64, u64), EvacuationError>;

    /// List of all remaining device IDs (excluding the one being evacuated).
    fn remaining_device_ids(&self) -> &[u64];
}

/// Reads and writes extent payloads during evacuation.
pub trait EvacuationIo {
    /// Read `length` bytes from device `device_id` at `physical_offset`.
    fn read_extent(
        &self,
        device_id: u64,
        physical_offset: u64,
        length: u32,
    ) -> Result<alloc::vec::Vec<u8>, EvacuationError>;

    /// Write `data` to device `device_id` at `physical_offset`.
    fn write_extent(
        &self,
        device_id: u64,
        physical_offset: u64,
        data: &[u8],
    ) -> Result<(), EvacuationError>;
}

/// Updates locator-table entries after evacuation data copy.
pub trait EvacuationLocator {
    /// Update the locator entry for `extent_id` in `inode` to point
    /// to `new_device_id` at `new_physical_offset`.
    fn update_entry(
        &mut self,
        inode: u64,
        extent_id: u64,
        new_device_id: u64,
        new_physical_offset: u64,
    ) -> Result<(), EvacuationError>;
}

// ── Evacuation engine ────────────────────────────────────────────────

/// Evacuate extents from the target device, consuming the plan in
/// byte-budgeted chunks and tracking progress in `stats`.
///
/// Returns `Ok(true)` when the plan is fully evacuated. Returns
/// `Ok(false)` when `budget_bytes` is exhausted before completion;
/// re-invoke with the remaining plan on the next tick.
///
/// # Errors
///
/// Returns [`EvacuationError`] on the first unrecoverable failure.
/// Partial progress up to the failure is captured in `stats` and the
/// plan is left with the remaining unprocessed entries.
pub fn evacuate_device<A, I, L>(
    plan: &mut EvacuationPlan,
    allocator: &mut A,
    io: &I,
    locator: &mut L,
    stats: &mut EvacuationStats,
    budget_bytes: u64,
    now_ns: u64,
) -> Result<bool, EvacuationError>
where
    A: EvacuationAllocator,
    I: EvacuationIo,
    L: EvacuationLocator,
{
    if plan.is_empty() {
        return Ok(true);
    }

    if allocator.remaining_device_ids().is_empty() {
        return Err(EvacuationError::NoRemainingDevices);
    }

    *stats = EvacuationStats::new(now_ns);

    let mut bytes_processed: u64 = 0;

    while !plan.is_empty() && bytes_processed < budget_bytes {
        // Peek at next entry to check budget before draining
        if plan.entries.is_empty() {
            break;
        }
        let next_len = u64::from(plan.entries[0].length);
        if bytes_processed.saturating_add(next_len) > budget_bytes {
            break;
        }

        let chunk = plan.take_chunk(1);
        if chunk.is_empty() {
            break;
        }
        let entry = &chunk[0];

        // 1. Allocate on a remaining device
        let (new_device_id, new_offset) =
            allocator.allocate_on_remaining(plan.device_id, entry.length)?;

        // 2. Read old extent data
        let data = io.read_extent(entry.device_id, entry.physical_offset, entry.length)?;

        // 3. Write to new location
        io.write_extent(new_device_id, new_offset, &data)?;

        // 4. Update locator entry atomically
        locator.update_entry(entry.inode, entry.extent_id, new_device_id, new_offset)?;

        // 5. Record progress
        stats.record_success(entry.length, now_ns);
        bytes_processed = bytes_processed.saturating_add(u64::from(entry.length));
    }

    Ok(plan.is_empty())
}

// ── End-to-end device removal ─────────────────────────────────────

/// Errors that can occur during end-to-end device removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceRemovalError {
    /// Evacuation did not complete within the byte budget.
    EvacuationIncomplete,
    /// Locator table still has entries referencing the removed device.
    DanglingReferences,
    /// Pool label update failed (e.g., last device).
    LabelUpdateFailed,
    /// An I/O or allocation error occurred during evacuation.
    EvacuationError(EvacuationError),
}

impl core::fmt::Display for DeviceRemovalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EvacuationIncomplete => f.write_str("evacuation incomplete within budget"),
            Self::DanglingReferences => f.write_str("dangling locator-table references remain"),
            Self::LabelUpdateFailed => f.write_str("pool label update failed"),
            Self::EvacuationError(e) => write!(f, "evacuation error: {e}"),
        }
    }
}

impl From<EvacuationError> for DeviceRemovalError {
    fn from(e: EvacuationError) -> Self {
        DeviceRemovalError::EvacuationError(e)
    }
}

pub struct DeviceRemovalRequest<'a, F>
where
    F: FnOnce(u64) -> bool,
{
    pub label: &'a tidefs_types_pool_label_core::PoolLabelV1,
    pub verify_no_refs: F,
    pub budget_bytes: u64,
    pub now_ns: u64,
}

/// End-to-end safe device removal: evacuate → verify → update label.
///
/// # Flow
///
/// 1. Evacuates all extents from `plan` via [`evacuate_device`].
/// 2. Verifies no remaining locator-table references to the removed
///    device via `verify_no_refs`.
/// 3. Updates the pool label on a remaining device via
///    [`tidefs_types_pool_label_core::remove_device_from_label`].
///
/// Returns the updated pool label and evacuation statistics on success.
///
/// # Errors
///
/// Returns [`DeviceRemovalError::EvacuationIncomplete`] when the byte
/// budget is exhausted before all extents are evacuated.
/// Returns [`DeviceRemovalError::DanglingReferences`] when the
/// verification callback returns `false`.
/// Returns [`DeviceRemovalError::LabelUpdateFailed`] when the label
/// cannot be updated (e.g., last device in pool).
pub fn remove_device_from_pool<A, I, L, F>(
    plan: &mut EvacuationPlan,
    allocator: &mut A,
    io: &I,
    locator: &mut L,
    request: DeviceRemovalRequest<'_, F>,
) -> Result<(tidefs_types_pool_label_core::PoolLabelV1, EvacuationStats), DeviceRemovalError>
where
    A: EvacuationAllocator,
    I: EvacuationIo,
    L: EvacuationLocator,
    F: FnOnce(u64) -> bool,
{
    let mut stats = EvacuationStats::new(request.now_ns);

    // 1. Evacuate all extents from the target device
    let done = evacuate_device(
        plan,
        allocator,
        io,
        locator,
        &mut stats,
        request.budget_bytes,
        request.now_ns,
    )
    .map_err(DeviceRemovalError::from)?;
    if !done {
        return Err(DeviceRemovalError::EvacuationIncomplete);
    }

    // 2. Verify no remaining locator-table references
    if !(request.verify_no_refs)(plan.device_id) {
        return Err(DeviceRemovalError::DanglingReferences);
    }

    // 3. Update pool label on remaining device
    let updated_label = tidefs_types_pool_label_core::remove_device_from_label(request.label)
        .map_err(|_| DeviceRemovalError::LabelUpdateFailed)?;

    Ok((updated_label, stats))
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // ── Mock allocator ──────────────────────────────────────────────

    struct MockAllocator {
        remaining: Vec<u64>,
        next_alloc: RefCell<u64>,
        allocations: RefCell<Vec<(u32, u64, u64)>>,
        fail_after: RefCell<Option<usize>>,
    }

    impl MockAllocator {
        fn new(remaining: Vec<u64>) -> Self {
            Self {
                remaining,
                next_alloc: RefCell::new(0),
                allocations: RefCell::new(Vec::new()),
                fail_after: RefCell::new(None),
            }
        }
    }

    impl EvacuationAllocator for MockAllocator {
        fn allocate_on_remaining(
            &mut self,
            exclude_device_id: u64,
            length: u32,
        ) -> Result<(u64, u64), EvacuationError> {
            if let Some(max) = *self.fail_after.borrow() {
                if self.allocations.borrow().len() >= max {
                    return Err(EvacuationError::AllocationFailed { size: length });
                }
            }
            for &dev in &self.remaining {
                if dev != exclude_device_id {
                    let offset = *self.next_alloc.borrow();
                    *self.next_alloc.borrow_mut() = offset + u64::from(length);
                    self.allocations.borrow_mut().push((length, dev, offset));
                    return Ok((dev, offset));
                }
            }
            Err(EvacuationError::NoRemainingDevices)
        }

        fn remaining_device_ids(&self) -> &[u64] {
            &self.remaining
        }
    }

    // ── Mock I/O ────────────────────────────────────────────────────

    struct MockIo {
        data: RefCell<HashMap<(u64, u64), Vec<u8>>>,
        writes: RefCell<Vec<(u64, u64, Vec<u8>)>>,
    }

    impl MockIo {
        fn new() -> Self {
            Self {
                data: RefCell::new(HashMap::new()),
                writes: RefCell::new(Vec::new()),
            }
        }

        fn seed(&self, device_id: u64, offset: u64, payload: Vec<u8>) {
            self.data.borrow_mut().insert((device_id, offset), payload);
        }
    }

    impl EvacuationIo for MockIo {
        fn read_extent(
            &self,
            device_id: u64,
            physical_offset: u64,
            _length: u32,
        ) -> Result<Vec<u8>, EvacuationError> {
            self.data
                .borrow()
                .get(&(device_id, physical_offset))
                .cloned()
                .ok_or(EvacuationError::ReadFailed {
                    device_id,
                    physical_offset,
                    length: _length,
                })
        }

        fn write_extent(
            &self,
            device_id: u64,
            physical_offset: u64,
            data: &[u8],
        ) -> Result<(), EvacuationError> {
            self.writes
                .borrow_mut()
                .push((device_id, physical_offset, data.to_vec()));
            Ok(())
        }
    }

    // ── Mock locator ────────────────────────────────────────────────

    struct MockLocator {
        updates: RefCell<Vec<(u64, u64, u64, u64)>>,
    }

    impl MockLocator {
        fn new() -> Self {
            Self {
                updates: RefCell::new(Vec::new()),
            }
        }
    }

    impl EvacuationLocator for MockLocator {
        fn update_entry(
            &mut self,
            inode: u64,
            extent_id: u64,
            new_device_id: u64,
            new_physical_offset: u64,
        ) -> Result<(), EvacuationError> {
            self.updates
                .borrow_mut()
                .push((inode, extent_id, new_device_id, new_physical_offset));
            Ok(())
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────

    fn entry(id: u64, ino: u64, off: u64, dev: u64, phy: u64, len: u32) -> EvacuationEntry {
        EvacuationEntry::new(id, ino, off, dev, phy, len, 0)
    }

    // ── Tests ───────────────────────────────────────────────────────

    #[test]
    fn evacuate_empty_plan_returns_true() {
        let mut plan = EvacuationPlan::empty(7);
        let mut alloc = MockAllocator::new(vec![1, 2]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        let mut stats = EvacuationStats::default();

        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 1024, 100);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn evacuate_single_entry_succeeds() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1, 2]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0xAB; 4096]);

        let mut stats = EvacuationStats::default();
        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 8192, 200);
        assert_eq!(result, Ok(true));

        assert_eq!(alloc.allocations.borrow().len(), 1);
        assert_eq!(alloc.allocations.borrow()[0].0, 4096);
        assert_eq!(io.writes.borrow().len(), 1);
        assert_eq!(io.writes.borrow()[0].2, vec![0xAB; 4096]);
        assert_eq!(loc.updates.borrow().len(), 1);
        assert_eq!(stats.entries_evacuated, 1);
        assert_eq!(stats.bytes_evacuated, 4096);
    }

    #[test]
    fn evacuate_multiple_entries_respects_budget() {
        let entries = vec![
            entry(1, 100, 0, 7, 0, 4096),
            entry(2, 200, 0, 7, 4096, 8192),
            entry(3, 300, 0, 7, 12288, 16384),
        ];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0x11; 4096]);
        io.seed(7, 4096, vec![0x22; 8192]);
        io.seed(7, 12288, vec![0x33; 16384]);

        let mut stats = EvacuationStats::default();

        // Budget only enough for first entry (4096 bytes)
        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 5000, 300);
        assert_eq!(result, Ok(false));
        assert_eq!(stats.entries_evacuated, 1);
        assert!(!plan.is_empty());
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn evacuate_no_remaining_devices_is_error() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        let mut stats = EvacuationStats::default();

        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 8192, 100);
        assert_eq!(result, Err(EvacuationError::NoRemainingDevices));
    }

    #[test]
    fn evacuate_allocation_failure_is_error() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        *alloc.fail_after.borrow_mut() = Some(0);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        let mut stats = EvacuationStats::default();

        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 65536, 500);
        assert!(matches!(
            result,
            Err(EvacuationError::AllocationFailed { .. })
        ));
    }

    #[test]
    fn evacuate_moves_to_different_device() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1, 2]);
        let io = MockIo::new();
        io.seed(7, 0, vec![0xDE; 4096]);
        let mut loc = MockLocator::new();
        let mut stats = EvacuationStats::default();

        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 8192, 100);
        assert_eq!(result, Ok(true));
        assert_eq!(alloc.allocations.borrow()[0].1, 1);
        assert_eq!(loc.updates.borrow()[0].2, 1);
    }

    #[test]
    fn evacuate_all_extents_in_budget() {
        let entries: Vec<EvacuationEntry> = (0..5u64)
            .map(|i| entry(i, i, i * 4096, 7, i * 4096, 1024))
            .collect();
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1, 2]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();

        for i in 0..5u64 {
            io.seed(7, i * 4096, vec![i as u8; 1024]);
        }

        let mut stats = EvacuationStats::default();
        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 65536, 100);
        assert_eq!(result, Ok(true));
        assert!(plan.is_empty());
        assert_eq!(stats.entries_evacuated, 5);
        assert_eq!(io.writes.borrow().len(), 5);
        assert_eq!(loc.updates.borrow().len(), 5);
    }

    #[test]
    fn evacuate_preserves_data_identity() {
        let data = vec![0x42u8; 8192];
        let entries = vec![entry(7, 42, 0, 7, 0, 8192)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        io.seed(7, 0, data.clone());
        let mut loc = MockLocator::new();
        let mut stats = EvacuationStats::default();

        let result = evacuate_device(&mut plan, &mut alloc, &io, &mut loc, &mut stats, 16384, 100);
        assert_eq!(result, Ok(true));
        assert_eq!(io.writes.borrow()[0].2, data);
    }

    #[test]
    fn evacuation_error_display() {
        let errs = [
            EvacuationError::NoRemainingDevices,
            EvacuationError::AllocationFailed { size: 4096 },
            EvacuationError::ReadFailed {
                device_id: 7,
                physical_offset: 0,
                length: 1024,
            },
            EvacuationError::WriteFailed {
                device_id: 1,
                physical_offset: 8192,
            },
            EvacuationError::LocatorUpdateFailed {
                inode: 100,
                extent_id: 5,
            },
            EvacuationError::ExtentPinned {
                inode: 200,
                extent_id: 99,
            },
        ];
        for err in &errs {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }

    #[test]
    fn mock_allocator_skips_excluded_device() {
        let mut alloc = MockAllocator::new(vec![7, 1, 2]);
        let result = alloc.allocate_on_remaining(7, 4096);
        assert!(result.is_ok());
        let (dev, _) = result.unwrap();
        assert_eq!(dev, 1);
    }

    #[test]
    fn mock_io_read_missing_returns_error() {
        let io = MockIo::new();
        let result = io.read_extent(7, 0, 4096);
        assert!(result.is_err());
        assert!(matches!(result, Err(EvacuationError::ReadFailed { .. })));
    }

    #[test]
    fn plan_from_entries_computes_stats() {
        let entries = vec![
            entry(1, 100, 0, 7, 0, 1000),
            entry(2, 100, 1000, 7, 1000, 2000),
            entry(3, 200, 0, 7, 3000, 3000),
        ];
        let plan = EvacuationPlan::from_entries(7, entries);
        assert_eq!(plan.device_id, 7);
        assert_eq!(plan.len(), 3);
        assert_eq!(plan.total_bytes, 6000);
        assert_eq!(plan.distinct_inodes, 2);
    }

    #[test]
    fn plan_take_chunk_reduces_stats() {
        let entries = vec![
            entry(1, 100, 0, 7, 0, 1000),
            entry(2, 200, 0, 7, 1000, 2000),
            entry(3, 300, 0, 7, 3000, 3000),
        ];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let chunk = plan.take_chunk(2);
        assert_eq!(chunk.len(), 2);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan.total_bytes, 3000);
    }

    #[test]
    fn stats_record_tracking() {
        let mut stats = EvacuationStats::new(100);
        stats.record_success(4096, 200);
        stats.record_failure(1024, 300);
        stats.record_inode_completed();
        assert_eq!(stats.entries_evacuated, 1);
        assert_eq!(stats.entries_failed, 1);
        assert_eq!(stats.bytes_evacuated, 4096);
        assert_eq!(stats.bytes_failed, 1024);
        assert_eq!(stats.distinct_inodes_completed, 1);
        assert_eq!(stats.total_entries_processed(), 2);
        assert_eq!(stats.started_at_ns, 100);
        assert_eq!(stats.last_progress_at_ns, 300);
    }

    // ── End-to-end device removal tests ──────────────────────────────

    use tidefs_types_pool_label_core::PoolLabelV1;

    fn make_pool_label(device_count: u32) -> PoolLabelV1 {
        let pool_guid = [0xAAu8; 16];
        let device_guid = [0xBBu8; 16];
        let mut label = PoolLabelV1::new(pool_guid, device_guid, "testpool");
        label.device_count = device_count;
        label.topology_generation = 1;
        tidefs_types_pool_label_core::seal_label(label).unwrap()
    }

    #[test]
    fn end_to_end_remove_device_succeeds() {
        let entries = vec![
            entry(1, 100, 0, 7, 0, 4096),
            entry(2, 200, 0, 7, 4096, 8192),
        ];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1, 2]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0x11; 4096]);
        io.seed(7, 4096, vec![0x22; 8192]);

        let label = make_pool_label(3);

        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| true, // verification passes
                budget_bytes: 65536,
                now_ns: 100,
            },
        );
        assert!(result.is_ok());

        let (updated_label, stats) = result.unwrap();
        assert_eq!(updated_label.device_count, 2);
        assert_eq!(updated_label.topology_generation, 2);
        assert_eq!(stats.entries_evacuated, 2);
        assert_eq!(stats.bytes_evacuated, 4096 + 8192);
        assert!(plan.is_empty());
    }

    #[test]
    fn end_to_end_fails_on_incomplete_evacuation() {
        let entries = vec![
            entry(1, 100, 0, 7, 0, 4096),
            entry(2, 200, 0, 7, 4096, 8192),
        ];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0x11; 4096]);
        io.seed(7, 4096, vec![0x22; 8192]);

        let label = make_pool_label(3);

        // Budget only for first entry
        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| true,
                budget_bytes: 5000,
                now_ns: 100,
            },
        );
        assert_eq!(result, Err(DeviceRemovalError::EvacuationIncomplete));
        // Label should NOT have been updated
        assert_eq!(label.device_count, 3);
    }

    #[test]
    fn end_to_end_fails_on_dangling_references() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0xAA; 4096]);

        let label = make_pool_label(3);

        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| false, // verification FAILS
                budget_bytes: 65536,
                now_ns: 100,
            },
        );
        assert_eq!(result, Err(DeviceRemovalError::DanglingReferences));
    }

    #[test]
    fn end_to_end_fails_on_last_device_label() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();
        io.seed(7, 0, vec![0xBB; 4096]);

        let label = make_pool_label(1); // last device

        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| true,
                budget_bytes: 65536,
                now_ns: 100,
            },
        );
        assert_eq!(result, Err(DeviceRemovalError::LabelUpdateFailed));
    }

    #[test]
    fn end_to_end_evacuation_error_propagates() {
        let entries = vec![entry(1, 100, 0, 7, 0, 4096)];
        let mut plan = EvacuationPlan::from_entries(7, entries);
        let mut alloc = MockAllocator::new(vec![]); // no remaining devices
        let io = MockIo::new();
        let mut loc = MockLocator::new();

        let label = make_pool_label(3);

        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| true,
                budget_bytes: 65536,
                now_ns: 100,
            },
        );
        assert!(matches!(
            result,
            Err(DeviceRemovalError::EvacuationError(_))
        ));
    }

    #[test]
    fn end_to_end_empty_plan_succeeds() {
        let mut plan = EvacuationPlan::empty(7);
        let mut alloc = MockAllocator::new(vec![1]);
        let io = MockIo::new();
        let mut loc = MockLocator::new();

        let label = make_pool_label(4);

        let result = remove_device_from_pool(
            &mut plan,
            &mut alloc,
            &io,
            &mut loc,
            DeviceRemovalRequest {
                label: &label,
                verify_no_refs: |_dev| true,
                budget_bytes: 65536,
                now_ns: 100,
            },
        );
        assert!(result.is_ok());
        let (updated_label, _stats) = result.unwrap();
        assert_eq!(updated_label.device_count, 3);
    }

    #[test]
    fn device_removal_error_display() {
        let errs = [
            DeviceRemovalError::EvacuationIncomplete,
            DeviceRemovalError::DanglingReferences,
            DeviceRemovalError::LabelUpdateFailed,
            DeviceRemovalError::EvacuationError(EvacuationError::NoRemainingDevices),
        ];
        for err in &errs {
            let s = format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }
}
