// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool-level segment allocator: the single authority on free-segment tracking,
//! segment_group selection, and space-pressure signalling for the entire storage
//! pool.
//!
//! Answers "where can I put this data?" at the segment granularity — one level
//! above the block allocator's byte-range decisions and one level below the
//! dataset lifecycle's capacity-planning layer. Every object-store write,
//! reclaim cycle, and pool checkpoint flows through the allocation decisions
//! made here.
//!
//! # Position in the stack
//!
//! ```text
//! dataset lifecycle / capacity planning
//!         |
//!   pool-import / pool-scan   -- "what devices and free segments exist?"
//!         |
//!   PoolAllocator             -- "here is the next free segment" or ENOSPC
//!         |
//!   object store / reclaim    -- commit segments, drain dead objects, checkpoint
//!         |
//!   BlockAllocator            -- "here are N free blocks within this segment"
//! ```
//!
//! # Architecture
//!
//! Two allocator levels, one crate:
//!
//! - [`PoolAllocator`] — single-device allocator wrapping a
//!   [`SegmentFreeMap`] with
//!   per-segment_group cursors, least-free-first segment_group selection,
//!   round-robin tiebreaking, and pressure-transition detection.
//! - [`MultiDevicePoolAllocator`] — coordinates multiple per-device
//!   `PoolAllocator` instances behind a unified allocate/free surface with
//!   device-class routing and cross-device checkpoint coordination.
//!
//! Both levels are `Clone`-safe and hold no I/O handles; persistence is the
//! caller's responsibility via [`PoolAllocator::to_checkpoint`] /
//! [`PoolAllocator::from_checkpoint`].
//!
//! # Allocation strategy
//!
//! The single-device [`PoolAllocator::allocate`] uses a two-phase algorithm:
//!
//! 1. **Segment_group selection** — compute per-segment_group free counts from
//!    the free runs, then pick the non-empty segment_group with the fewest free
//!    segments (least-free-first packing for spatial locality). Ties are broken
//!    with a round-robin counter that advances past the selected segment_group.
//! 2. **Cursor-based allocation** — use the selected segment_group's monotonic
//!    cursor ([`PoolAllocator::cursors`]) to find a free segment via
//!    `alloc_after()`. The cursor wraps within the segment_group boundary, never
//!    crossing into another segment_group.
//!
//! Callers that need a specific segment (e.g., store open with an existing
//! cursor) can bypass the selection policy via [`PoolAllocator::alloc_after`].
//!
//! The multi-device [`MultiDevicePoolAllocator::allocate`] adds a third phase:
//!
//! 3. **Device selection** — iterate per-device allocators in registration
//!    order; the first device that successfully allocates a segment wins. No
//!    cross-device balancing policy is applied (least-free-first operates within
//!    each device independently).
//!
//! # Design invariants
//!
//! 1. Per-segment_group cursors advance monotonically within each segment_group,
//!    wrapping within the segment_group boundary — they never cross
//!    segment_groups.
//! 2. Segment_group selection is deterministic given the same free-map state:
//!    pick the non-empty segment_group with the fewest free segments; break ties
//!    with a round-robin counter.
//! 3. Pressure events fire on threshold crossing (rising edge: >= 95% used;
//!    falling edge: < 95% used), never on repeated queries while already under
//!    pressure.
//! 4. All errors forward the underlying `FreeMapError` faithfully — no
//!    information is swallowed.
//! 5. Multi-device allocators maintain per-device `PoolAllocator` instances;
//!    the aggregate `any_device_under_pressure` flag is true when at least one
//!    device crosses the pressure threshold.
//!
//! # Public API surface
//!
//! ## Core types
//!
//! | Type | Role |
//! |---|---|
//! | [`PoolAllocator`] | Single-device segment allocator |
//! | [`MultiDevicePoolAllocator`] | Multi-device coordinator |
//! | [`PoolAllocatorError`] | Error enum (wraps `FreeMapError`) |
//! | [`SpacePressureEvent`] | Pressure transition (enter/exit) |
//! | [`PoolAllocatorStats`] | Snapshot of pool-wide state |
//! | [`SegmentGroupAllocStats`] | Per-segment_group allocation counters |
//! | [`AllocDeviceClass`] | Device class for multi-device routing |
//! | [`MultiDeviceAllocError`] | Multi-device error enum |
//!
//! ## Allocation lifecycle
//!
//! ```text
//! allocate() ---> use segment ---> add_free(segment) ---> back in free pool
//!                   |
//!                   v
//!             check_pressure_transition()
//!                   |
//!                   v
//!             to_checkpoint() ---> persist free-map state
//! ```
//!
//! ## Delegation methods
//!
//! [`PoolAllocator`] exposes passthrough methods to the underlying
//! [`SegmentFreeMap`] for callers
//! that need direct free-map access:
//! [`add_free`](PoolAllocator::add_free),
//! [`remove_free`](PoolAllocator::remove_free),
//! [`is_free`](PoolAllocator::is_free),
//! [`runs`](PoolAllocator::runs),
//! [`free_count`](PoolAllocator::free_count),
//! [`dirty_segment_groups`](PoolAllocator::dirty_segment_groups),
//! [`clear_dirty_segment_groups`](PoolAllocator::clear_dirty_segment_groups).
//!
//! ## Checkpoint coordination
//!
//! [`PoolAllocator::to_checkpoint`] serialises the current free-map state into
//! a [`SpaceMapCheckpointV1`].
//! When `dirty_only` is true, only segment_groups modified since the last
//! checkpoint are included (incremental checkpoint).
//! [`PoolAllocator::from_checkpoint`] reconstructs a `PoolAllocator` from a
//! persistent checkpoint, decoding per-segment_group bitmaps back into free
//! runs.
//!
//! # Error surface
//!
//! [`PoolAllocatorError`] has five variants:
//!
//! | Variant | Condition |
//! |---|---|
//! | `NoFreeSegments` | Pool exhausted (ENOSPC) |
//! | `SegmentOutOfRange(seg)` | Segment index exceeds `segment_count` |
//! | `AlreadyUsed(seg)` | Segment is already in the target state |
//! | `InvalidRun(start, end)` | Run bounds are invalid |
//! | `CorruptCheckpoint` | Spacemap checkpoint is unreadable |
//!
//! [`MultiDeviceAllocError`] adds two device-level variants:
//!
//! | Variant | Condition |
//! |---|---|
//! | `NoFreeSegments` | No free segments across any device |
//! | `NoDeviceForClass(class)` | No device registered for the requested class |
//!
//! # Integration points
//!
//! | Consumer crate | Interface bridge | Role |
//! |---|---|---|
//! | `tidefs-local-object-store` | `PoolAllocator` (direct dep) | Free-segment
//!   tracking for object-store writes; checkpoint serialization via
//!   `to_checkpoint`/`from_checkpoint`; pressure-signal monitoring |
//! | `tidefs-reclaim` | `SegmentFreer` impl for `PoolAllocator` | Drains dead
//!   object segments back to the free pool via `add_free` |
//! | `tidefs-pool-import` | `PoolAllocator::from_checkpoint` | Bootstrap
//!   pool allocator state from on-disk checkpoint during mount |
//! | `tidefs-pool-scan` | `PoolAllocator::stats` | Pool health and capacity
//!   reporting via allocation statistics |
//! | `tidefs-dataset-lifecycle` | `SpacePressureEvent` | Capacity planning
//!   triggers background reclamation or dataset resize when pressure
//!   transitions fire |
//! | `tidefs-block-allocator` | Segments allocated here | BlockAllocator
//!   operates within segments; pool allocator decides *which* segment,
//!   block allocator decides *which blocks* within it |
//!
//! # Testing
//!
//! All tests live inline in this file under `#[cfg(test)] mod tests` and a
//! second `#[cfg(test)]` block for [`MultiDevicePoolAllocator`]. They cover:
//! basic allocation/exhaustion, add_free/remove_free idempotency, pressure
//! transitions (enter/exit/stable), per-segment_group cursor tracking,
//! round-robin tiebreaking, selection policy (least-free-first), alloc_after
//! bypass, error conversion, full lifecycle round-trips, checkpoint
//! serialization, dirty segment_group tracking, multi-device coordination,
//! and integration-chain propagation.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Gate markers (for xtask validation)
// ---------------------------------------------------------------------------
// POOL_ALLOCATOR_SPEC
// tidefs-xtask check-pool-allocator
// MULTI_DEVICE_ALLOCATOR_COORDINATION_IMPLEMENTED
//   (multi-device allocation with device-class routing, cross-device
//   checkpoint coordination, and pressure aggregation is live)

/// Pool allocator version marker for xtask validation.
///
/// Indicates this crate is a live production allocator.
/// Bump when the allocation strategy, checkpoint format, or public API
/// materially changes.
pub const POOL_ALLOCATOR_VERSION: u32 = 1;

use std::fmt;
use tidefs_spacemap_allocator::{FreeMapError, SegmentFreeMap, SpaceMapCheckpointV1};

// =========================================================================
// Error types
// =========================================================================

/// Pool-level allocator error — transparently wraps `FreeMapError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolAllocatorError {
    /// No free segments remain in the pool.
    NoFreeSegments,
    /// A segment index exceeds the pool's segment_count.
    SegmentOutOfRange(u64),
    /// Attempted to use or free a segment that is already in the target state.
    AlreadyUsed(u64),
    /// A run has invalid bounds (start >= end or end > segment_count).
    InvalidRun(u64, u64),
    /// The spacemap checkpoint is corrupt or unreadable.
    CorruptCheckpoint,
}

impl From<FreeMapError> for PoolAllocatorError {
    fn from(e: FreeMapError) -> Self {
        match e {
            FreeMapError::NoFreeSegments => Self::NoFreeSegments,
            FreeMapError::SegmentOutOfRange(seg) => Self::SegmentOutOfRange(seg),
            FreeMapError::AlreadyUsed(seg) => Self::AlreadyUsed(seg),
            FreeMapError::InvalidRun(start, end) => Self::InvalidRun(start, end),
            FreeMapError::CorruptCheckpoint => Self::CorruptCheckpoint,
        }
    }
}

impl fmt::Display for PoolAllocatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoFreeSegments => write!(f, "no free segments available in pool"),
            Self::SegmentOutOfRange(seg) => write!(f, "segment {seg} out of range"),
            Self::AlreadyUsed(seg) => write!(f, "segment {seg} is already in the target state"),
            Self::InvalidRun(start, end) => write!(f, "invalid free run [{start}, {end})"),
            Self::CorruptCheckpoint => write!(f, "spacemap checkpoint is corrupt"),
        }
    }
}

impl std::error::Error for PoolAllocatorError {}

// =========================================================================
// Space pressure events
// =========================================================================

/// A space pressure state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpacePressureEvent {
    /// The pool crossed above the pressure threshold (>= 95% used).
    EnterPressure,
    /// The pool dropped below the pressure threshold.
    ExitPressure,
}

impl SpacePressureEvent {
    /// Human-readable label for observability / tracing.
    pub fn label(&self) -> &'static str {
        match self {
            Self::EnterPressure => "space_pressure_enter",
            Self::ExitPressure => "space_pressure_exit",
        }
    }
}

// =========================================================================

/// State for round-robin tiebreaking across segment_group selection rounds.
#[derive(Debug, Clone)]
struct RoundRobinState {
    /// Index of the last segment_group selected.
    last_selected: u32,
}

impl RoundRobinState {
    fn new() -> Self {
        Self { last_selected: 0 }
    }
}

// =========================================================================
// PoolAllocator
// =========================================================================

/// Per-segment_group allocation statistics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SegmentGroupAllocStats {
    pub segment_group_index: u32,
    pub free_segments: u64,
    pub total_segments: u64,
    pub cursor: u64,
}

/// Snapshot of pool-wide allocation state.
#[derive(Debug, Clone)]
pub struct PoolAllocatorStats {
    pub segment_count: u64,
    pub free_segments: u64,
    pub used_segments: u64,
    pub free_runs: u64,
    pub fragmentation_pct: f64,
    pub segment_group_count: u32,
    pub dirty_segment_group_count: u32,
    pub under_pressure: bool,
    pub per_segment_group: Vec<SegmentGroupAllocStats>,
}

/// Pool-level allocator that wraps a `SegmentFreeMap` with per-segment_group
/// allocation cursors, a deterministic segment_group selection policy, and
/// pressure-transition detection.
#[derive(Debug, Clone)]
pub struct PoolAllocator {
    /// The underlying segment free map.
    free_map: SegmentFreeMap,
    /// Per-segment_group allocation cursors.  Each cursor is advanced past the
    /// last allocated segment within that segment_group.
    cursors: Vec<u64>,
    /// Round-robin tiebreaker state.
    round_robin: RoundRobinState,
    /// Whether we were already under pressure on the last check (hysteresis).
    was_under_pressure: bool,
}

impl PoolAllocator {
    /// Create a `PoolAllocator` from an already-constructed `SegmentFreeMap`.
    pub fn new(free_map: SegmentFreeMap) -> Self {
        let segment_group_count = free_map.segment_group_count() as usize;
        // Initialize per-segment_group cursors to the start of each segment_group range.
        let cursors = (0..segment_group_count)
            .map(|i| i as u64 * free_map.segment_group_segments)
            .collect();
        Self {
            was_under_pressure: free_map.is_under_pressure(),
            free_map,
            cursors,
            round_robin: RoundRobinState::new(),
        }
    }

    // -- delegation methods (passthrough) --

    /// Return a segment to the free set. Idempotent.
    #[inline]
    pub fn add_free(&mut self, seg: u64) -> Result<(), PoolAllocatorError> {
        Ok(self.free_map.add_free(seg)?)
    }

    /// Mark a segment as used. Errors if not currently free.
    #[inline]
    pub fn remove_free(&mut self, seg: u64) -> Result<(), PoolAllocatorError> {
        Ok(self.free_map.remove_free(seg)?)
    }

    /// Test whether a segment is in the free set.
    #[inline]
    #[must_use]
    pub fn is_free(&self, seg: u64) -> bool {
        self.free_map.is_free(seg)
    }

    /// Snapshot of current free runs.
    #[inline]
    #[must_use]
    pub fn runs(&self) -> Vec<(u64, u64)> {
        self.free_map.runs()
    }

    /// Number of free segments.
    #[inline]
    #[must_use]
    pub fn free_count(&self) -> u64 {
        self.free_map.free_count()
    }

    /// Check if the pool is under space pressure (>= 95% used).
    #[inline]
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        self.free_map.is_under_pressure()
    }

    /// Return sorted vector of dirty segment_group indices.
    #[inline]
    #[must_use]
    pub fn dirty_segment_groups(&self) -> Vec<u32> {
        self.free_map.dirty_segment_groups()
    }

    /// Clear the dirty segment_group set after a successful checkpoint flush.
    pub fn clear_dirty_segment_groups(&mut self) {
        self.free_map.clear_dirty_segment_groups();
    }

    /// Number of segment_groups in the pool.
    #[inline]
    #[must_use]
    pub fn segment_group_count(&self) -> u64 {
        self.free_map.segment_group_count()
    }

    /// Access the inner `SegmentFreeMap` (for checkpoint serialization).
    #[must_use]
    pub fn free_map(&self) -> &SegmentFreeMap {
        &self.free_map
    }

    /// Mutable access to the inner `SegmentFreeMap` (for checkpoint loading).
    pub fn free_map_mut(&mut self) -> &mut SegmentFreeMap {
        &mut self.free_map
    }

    /// Total segments in the pool.
    #[inline]
    #[must_use]
    pub fn segment_count(&self) -> u64 {
        self.free_map.segment_count
    }

    /// Segments per segment_group.
    #[inline]
    #[must_use]
    pub fn segment_group_segments(&self) -> u64 {
        self.free_map.segment_group_segments
    }

    /// Monotonic generation counter from the underlying SegmentFreeMap.
    #[inline]
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.free_map.generation
    }

    // -- checkpoint coordination --

    /// Create a `SpaceMapCheckpointV1` from the current pool state.
    ///
    /// When `dirty_only` is true, only segment_groups that have been modified
    /// since the last checkpoint are included (incremental checkpoint).
    /// When false, all segment_groups are included (full checkpoint).
    #[must_use]
    pub fn to_checkpoint(&self, dirty_only: bool) -> SpaceMapCheckpointV1 {
        SpaceMapCheckpointV1::from_free_map(&self.free_map, dirty_only)
    }

    /// Reconstruct a `PoolAllocator` from a persistent spacemap checkpoint.
    ///
    /// Decodes the per-segment_group bitmaps back into free runs and constructs
    /// the in-memory free map with per-segment_group cursors initialised to
    /// the start of each segment_group range.
    ///
    /// # Errors
    ///
    /// Returns `CorruptCheckpoint` if any bitmap cannot be decoded.
    pub fn from_checkpoint(checkpoint: &SpaceMapCheckpointV1) -> Result<Self, FreeMapError> {
        let fm = SegmentFreeMap::from_checkpoint(checkpoint)?;
        Ok(Self::new(fm))
    }

    // -- per-segment_group allocation --

    /// Allocate a free segment using the per-segment_group selection policy.
    ///
    /// Algorithm:
    /// 1. Compute free counts per segment_group from the free runs.
    /// 2. Select the non-empty segment_group with the fewest free segments
    ///    (least-free-first packing). Break ties with round-robin.
    /// 3. Use that segment_group's cursor to find a free segment via
    ///    `alloc_after()`.
    /// 4. Update the segment_group's cursor past the allocated segment.
    /// 5. Check for pressure transitions.
    pub fn allocate(&mut self) -> Result<u64, PoolAllocatorError> {
        let mc = self.segment_group_count() as u32;
        if mc == 0 {
            return Err(PoolAllocatorError::NoFreeSegments);
        }

        // Step 1: compute per-segment_group free counts.
        let free_counts = self.compute_per_segment_group_free_counts();
        debug_assert_eq!(free_counts.len(), mc as usize);

        // Step 2: select the best segment_group.
        let selected = self.select_segment_group(&free_counts, mc)?;

        // Step 3: try to allocate from the selected segment_group's cursor.
        let cursor = self.cursors[selected as usize];
        let seg = self.free_map.alloc_after(cursor)?;

        // Step 4: advance cursor past the allocated segment, wrapping within
        // the segment_group boundary.
        let ms_start = selected as u64 * self.free_map.segment_group_segments;
        let ms_end = ms_start + self.free_map.segment_group_segments;
        let next_cursor = if seg + 1 < ms_end { seg + 1 } else { ms_start };
        self.cursors[selected as usize] = next_cursor;

        Ok(seg)
    }

    /// Allocate a free segment at or after a specific cursor hint, bypassing
    /// the segment_group selection policy.  Used when the caller needs a specific
    /// segment (e.g., store open with an existing cursor).
    ///
    /// Also updates the per-segment_group cursor for the segment_group containing the
    /// allocated segment so internal coordination state stays consistent
    /// with the underlying free map.
    pub fn alloc_after(&mut self, cursor: u64) -> Result<u64, PoolAllocatorError> {
        let seg = self.free_map.alloc_after(cursor)?;
        let ms_index = (seg / self.free_map.segment_group_segments) as usize;
        if ms_index < self.cursors.len() {
            let ms_start = ms_index as u64 * self.free_map.segment_group_segments;
            let ms_end =
                (ms_start + self.free_map.segment_group_segments).min(self.free_map.segment_count);
            let next = if seg + 1 < ms_end { seg + 1 } else { ms_start };
            self.cursors[ms_index] = next;
        }
        Ok(seg)
    }

    /// Detect and return any space pressure transition since the last call.
    ///
    /// Call this after allocation/free operations to check whether the pool
    /// crossed the pressure threshold. Returns `Some(event)` only on the
    /// first call that detects a crossing; subsequent calls while the
    /// pressure state is stable return `None`.
    pub fn check_pressure_transition(&mut self) -> Option<SpacePressureEvent> {
        let under_now = self.free_map.is_under_pressure();
        let event = if under_now && !self.was_under_pressure {
            Some(SpacePressureEvent::EnterPressure)
        } else if !under_now && self.was_under_pressure {
            Some(SpacePressureEvent::ExitPressure)
        } else {
            None
        };
        self.was_under_pressure = under_now;
        event
    }

    /// Force-reset the pressure tracking state (e.g., after pool import).
    pub fn reset_pressure_tracking(&mut self) {
        self.was_under_pressure = self.free_map.is_under_pressure();
    }

    /// Snapshot of pool-wide allocation statistics.
    #[must_use]
    pub fn stats(&self) -> PoolAllocatorStats {
        let base = self.free_map.stats();
        let free_counts = self.compute_per_segment_group_free_counts();
        let mc = self.segment_group_count() as u32;
        let per_segment_group: Vec<SegmentGroupAllocStats> = (0..mc)
            .map(|i| {
                let ms_start = i as u64 * self.free_map.segment_group_segments;
                let ms_end = (ms_start + self.free_map.segment_group_segments)
                    .min(self.free_map.segment_count);
                SegmentGroupAllocStats {
                    segment_group_index: i,
                    free_segments: free_counts[i as usize],
                    total_segments: ms_end - ms_start,
                    cursor: self.cursors[i as usize],
                }
            })
            .collect();

        let dirty_count = self.free_map.dirty_segment_groups().len() as u32;

        PoolAllocatorStats {
            segment_count: base.segment_count,
            free_segments: base.free_segments,
            used_segments: base.used_segments,
            free_runs: base.free_runs,
            fragmentation_pct: base.fragmentation_pct,
            segment_group_count: mc,
            dirty_segment_group_count: dirty_count,
            under_pressure: self.free_map.is_under_pressure(),
            per_segment_group,
        }
    }

    // -- private helpers --

    /// Compute the number of free segments in each segment_group by walking the
    /// free runs. Runs may span segment_group boundaries.
    fn compute_per_segment_group_free_counts(&self) -> Vec<u64> {
        let mc = self.segment_group_count() as usize;
        let mut counts = vec![0u64; mc];
        let ms_segs = self.free_map.segment_group_segments;

        for &(start, end) in self.free_map.runs().iter() {
            let mut pos = start;
            while pos < end {
                let ms = (pos / ms_segs) as usize;
                if ms >= mc {
                    break;
                }
                let ms_end = ((ms as u64 + 1) * ms_segs).min(end);
                counts[ms] += ms_end - pos;
                pos = ms_end;
            }
        }
        counts
    }

    /// Select the best segment_group for allocation.
    ///
    /// Policy: pick the non-empty segment_group with the fewest free segments
    /// (least-free-first packing for spatial locality). Break ties with
    /// round-robin.
    fn select_segment_group(
        &mut self,
        free_counts: &[u64],
        total: u32,
    ) -> Result<u32, PoolAllocatorError> {
        let mut best_idx: Option<u32> = None;
        let mut best_count: u64 = u64::MAX;

        // First pass: find segment_groups with the minimum non-zero free count.
        for i in 0..total {
            let count = free_counts[i as usize];
            if count > 0 && count < best_count {
                best_count = count;
                best_idx = Some(i);
            }
        }

        let Some(min_count) = best_idx.map(|i| free_counts[i as usize]) else {
            return Err(PoolAllocatorError::NoFreeSegments);
        };

        // Collect all segment_groups tied at the minimum count.
        let tied: Vec<u32> = (0..total)
            .filter(|&i| free_counts[i as usize] == min_count && free_counts[i as usize] > 0)
            .collect();

        // Tiebreak: pick the first tied segment_group at or after the round-robin
        // last_selected index.
        let start = self.round_robin.last_selected;
        let best = tied
            .iter()
            .find(|&&i| i >= start)
            .copied()
            .unwrap_or(tied[0]);

        // Advance round-robin past the selected segment_group so the next tie
        // picks a different segment_group.
        self.round_robin.last_selected = (best + 1) % total;

        Ok(best)
    }

    /// Return the per-segment_group cursors (for testing/observability).
    #[must_use]
    pub fn cursors(&self) -> &[u64] {
        &self.cursors
    }
}

// =========================================================================
// Tests
// =========================================================================

// -------------------------------------------------------------------------
// MultiDevicePoolAllocator — coordinates allocation across multiple devices
// -------------------------------------------------------------------------

/// Device class for multi-device allocation routing.
///
/// Mirrors the `DeviceClass` enum in `tidefs-local-object-store` to avoid a
/// circular dependency; the pool layer maps from the device-level `DeviceClass`
/// to this type when routing allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AllocDeviceClass {
    /// General-purpose data storage.
    Data,
    /// Metadata and small-block special allocations.
    Metadata,
    /// Separate fast intent-log device (LOG_DEVICE).
    IntentLog,
    /// Read cache device (FlashTier).
    ReadCache,
    /// Special allocation class (small files, dedup tables).
    Special,
}

impl AllocDeviceClass {
    /// Human-readable label for logging/observability.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Metadata => "metadata",
            Self::IntentLog => "intent_log",
            Self::ReadCache => "read_cache",
            Self::Special => "special",
        }
    }
}

/// Errors that can occur during multi-device allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiDeviceAllocError {
    /// No free segments across any device in the requested class.
    NoFreeSegments,
    /// No device is configured for the requested device class.
    NoDeviceForClass(AllocDeviceClass),
    /// A segment index exceeds the maximum for its device.
    SegmentOutOfRange { device_index: usize, segment: u64 },
    /// Segment is already in the target state.
    AlreadyUsed { device_index: usize, segment: u64 },
    /// A run has invalid bounds.
    InvalidRun {
        device_index: usize,
        start: u64,
        end: u64,
    },
    /// Spacemap checkpoint is corrupt for a device.
    CorruptCheckpoint { device_index: usize },
}

impl std::fmt::Display for MultiDeviceAllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFreeSegments => write!(f, "no free segments across any device"),
            Self::NoDeviceForClass(cls) => {
                write!(f, "no device configured for device class {}", cls.label())
            }
            Self::SegmentOutOfRange {
                device_index,
                segment,
            } => {
                write!(
                    f,
                    "segment {segment} out of range for device {device_index}"
                )
            }
            Self::AlreadyUsed {
                device_index,
                segment,
            } => {
                write!(
                    f,
                    "segment {segment} already in target state for device {device_index}"
                )
            }
            Self::InvalidRun {
                device_index,
                start,
                end,
            } => {
                write!(f, "invalid run [{start}, {end}) for device {device_index}")
            }
            Self::CorruptCheckpoint { device_index } => {
                write!(f, "corrupt spacemap checkpoint for device {device_index}")
            }
        }
    }
}

impl std::error::Error for MultiDeviceAllocError {}

/// Per-device configuration entry for the multi-device allocator.
#[derive(Debug)]
pub struct DeviceAllocEntry {
    /// Device class for allocation routing.
    pub class: AllocDeviceClass,
    /// The per-device pool allocator.
    pub allocator: PoolAllocator,
}

/// Aggregate multi-device allocator statistics.
#[derive(Debug)]
pub struct MultiDeviceAllocStats {
    /// Number of devices.
    pub device_count: usize,
    /// Aggregate free segments across all devices.
    pub total_free_segments: u64,
    /// Aggregate total segments across all devices.
    pub total_segments: u64,
    /// Whether the pool as a whole is under pressure.
    pub under_pressure: bool,
    /// Whether any individual device is under pressure.
    pub any_device_under_pressure: bool,
    /// Per-device statistics.
    pub per_device: Vec<PoolAllocatorStats>,
}

/// A multi-device pool allocator that coordinates segment allocation across
/// a collection of devices, each with its own `PoolAllocator`.
///
/// # Allocation routing
///
/// - `Data` class: prefers devices explicitly labeled `Data`; falls back to
///   any device (least-free-first) when no `Data` device has free space.
/// - `Metadata` class: prefers `Metadata` then `Special`, falling back to
///   `Data`.
/// - `IntentLog` and `ReadCache`: prefer their dedicated class, falling
///   back to `Data`.
///
/// # Design invariants
///
/// 1. Each device maintains its own `PoolAllocator` with independent per-segment_group
///    cursors and segment_group selection policies.
/// 2. Cross-device allocation uses a least-free-first selection across all
///    eligible devices, with round-robin tiebreaking.
/// 3. `add_free` / `remove_free` are routed to the specific device by index;
///
/// # Deferred (G2+)
///
/// Integration of this multi-device allocator into `LocalObjectStore` is
/// deferred pending multi-device pool support (#1694). The G1 single-device
/// `PoolAllocator` remains the active wire-up path.
#[derive(Debug)]
pub struct MultiDevicePoolAllocator {
    devices: Vec<PoolAllocator>,
    classes: Vec<AllocDeviceClass>,
    /// Round-robin tiebreaker for cross-device allocation.
    round_robin: u32,
    /// Aggregate pressure tracking.
    any_was_under_pressure: bool,
}

impl MultiDevicePoolAllocator {
    /// Create a new multi-device allocator from per-device entries.
    ///
    /// # Panics
    ///
    /// Panics if `entries` is empty.
    #[must_use]
    pub fn new(entries: Vec<DeviceAllocEntry>) -> Self {
        assert!(
            !entries.is_empty(),
            "MultiDevicePoolAllocator requires at least one device"
        );
        let any_under = entries.iter().any(|e| e.allocator.is_under_pressure());
        let (classes, devices): (Vec<_>, Vec<_>) =
            entries.into_iter().map(|e| (e.class, e.allocator)).unzip();
        Self {
            devices,
            classes,
            round_robin: 0,
            any_was_under_pressure: any_under,
        }
    }

    // -- accessors --

    /// Number of devices.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Reference to a specific device's allocator.
    #[must_use]
    pub fn device(&self, index: usize) -> &PoolAllocator {
        &self.devices[index]
    }

    /// Mutable reference to a specific device's allocator.
    pub fn device_mut(&mut self, index: usize) -> &mut PoolAllocator {
        &mut self.devices[index]
    }

    /// Device class for a given device index.
    #[must_use]
    pub fn device_class(&self, index: usize) -> AllocDeviceClass {
        self.classes[index]
    }

    /// Total free segments across all devices.
    #[must_use]
    pub fn total_free_count(&self) -> u64 {
        self.devices.iter().map(|v| v.free_count()).sum()
    }

    /// Total segments across all devices.
    #[must_use]
    pub fn total_segment_count(&self) -> u64 {
        self.devices.iter().map(|v| v.segment_count()).sum()
    }

    /// Whether the pool as a whole is under space pressure.
    #[must_use]
    pub fn is_under_pressure(&self) -> bool {
        if self.devices.is_empty() {
            return false;
        }
        let total_free = self.total_free_count();
        let total_seg = self.total_segment_count();
        if total_seg == 0 {
            return false;
        }
        let used = total_seg.saturating_sub(total_free);
        (used as f64 / total_seg as f64) >= 0.95
    }

    // -- per-device operations --

    /// Return a segment to the free set on a specific device. Idempotent.
    pub fn add_free(&mut self, device_index: usize, seg: u64) -> Result<(), MultiDeviceAllocError> {
        let v = self.device_mut(device_index);
        v.add_free(seg).map_err(|e| map_pool_err(device_index, e))
    }

    /// Mark a segment as used on a specific device.
    pub fn remove_free(
        &mut self,
        device_index: usize,
        seg: u64,
    ) -> Result<(), MultiDeviceAllocError> {
        let v = self.device_mut(device_index);
        v.remove_free(seg)
            .map_err(|e| map_pool_err(device_index, e))
    }

    /// Check whether a segment is free on a specific device.
    #[must_use]
    pub fn is_free(&self, device_index: usize, seg: u64) -> bool {
        self.devices
            .get(device_index)
            .is_some_and(|v| v.is_free(seg))
    }

    /// Free runs for a specific device.
    #[must_use]
    pub fn runs(&self, device_index: usize) -> Vec<(u64, u64)> {
        self.devices
            .get(device_index)
            .map_or(Vec::new(), |v| v.runs())
    }

    /// Segment count for a specific device.
    #[must_use]
    pub fn segment_count(&self, device_index: usize) -> u64 {
        self.devices
            .get(device_index)
            .map_or(0, |v| v.segment_count())
    }

    // -- cross-device allocation --

    /// Allocate a free segment, preferring the given device class.
    ///
    /// If no free segment is available in a device of the preferred class,
    /// falls back to `Data`-class devices, then to any device with free space.
    pub fn allocate_class(
        &mut self,
        preferred_class: AllocDeviceClass,
    ) -> Result<(usize, u64), MultiDeviceAllocError> {
        // Build ordered candidate list: preferred class first, then fallbacks.
        let mut candidates = Vec::new();

        // Preferred class devices first.
        for (i, cls) in self.classes.iter().enumerate() {
            if *cls == preferred_class {
                candidates.push(i);
            }
        }

        // Metadata also considers Special.
        if preferred_class == AllocDeviceClass::Metadata {
            for (i, cls) in self.classes.iter().enumerate() {
                if *cls == AllocDeviceClass::Special && !candidates.contains(&i) {
                    candidates.push(i);
                }
            }
        }

        // Fallback: Data class (unless preferred was already Data).
        if preferred_class != AllocDeviceClass::Data {
            for (i, cls) in self.classes.iter().enumerate() {
                if *cls == AllocDeviceClass::Data && !candidates.contains(&i) {
                    candidates.push(i);
                }
            }
        }

        // Final fallback: any device with free space not yet included.
        for i in 0..self.devices.len() {
            if !candidates.contains(&i) && self.devices[i].free_count() > 0 {
                candidates.push(i);
            }
        }

        // Try each candidate in order, using least-free-first across
        // eligible devices.
        let mut best: Option<usize> = None;
        let mut best_free_count: u64 = u64::MAX;

        for &vi in &candidates {
            let free = self.devices[vi].free_count();
            if free > 0 && free < best_free_count {
                best_free_count = free;
                best = Some(vi);
            }
        }

        if best.is_none() {
            return Err(MultiDeviceAllocError::NoFreeSegments);
        }

        // Tiebreak: collect all devices tied at the minimum free count.
        let tied: Vec<usize> = candidates
            .into_iter()
            .filter(|&vi| {
                let fc = self.devices[vi].free_count();
                fc > 0 && fc == best_free_count
            })
            .collect();

        if tied.is_empty() {
            return Err(MultiDeviceAllocError::NoFreeSegments);
        }

        // Round-robin tiebreak.
        let selected = tied[self.round_robin as usize % tied.len()];
        self.round_robin = self.round_robin.wrapping_add(1);

        let seg = self.devices[selected]
            .allocate()
            .map_err(|e| map_pool_err(selected, e))?;
        Ok((selected, seg))
    }

    /// Allocate a free segment without class preference (uses Data by default).
    pub fn allocate(&mut self) -> Result<(usize, u64), MultiDeviceAllocError> {
        self.allocate_class(AllocDeviceClass::Data)
    }

    /// Allocate at or after a cursor on a specific device.
    pub fn alloc_after(
        &mut self,
        device_index: usize,
        cursor: u64,
    ) -> Result<u64, MultiDeviceAllocError> {
        let v = self.device_mut(device_index);
        v.alloc_after(cursor)
            .map_err(|e| map_pool_err(device_index, e))
    }

    // -- aggregate stats & checkpointing --

    /// Aggregate statistics across all devices.
    #[must_use]
    pub fn stats(&self) -> MultiDeviceAllocStats {
        let mut total_free: u64 = 0;
        let mut total_seg: u64 = 0;
        let mut any_under = false;
        let mut per_device = Vec::with_capacity(self.devices.len());

        for v in &self.devices {
            let s = v.stats();
            total_free += s.free_segments;
            total_seg += s.segment_count;
            if s.under_pressure {
                any_under = true;
            }
            per_device.push(s);
        }

        let pool_under = if total_seg == 0 {
            false
        } else {
            let used = total_seg.saturating_sub(total_free);
            (used as f64 / total_seg as f64) >= 0.95
        };

        MultiDeviceAllocStats {
            device_count: self.devices.len(),
            total_free_segments: total_free,
            total_segments: total_seg,
            under_pressure: pool_under,
            any_device_under_pressure: any_under,
            per_device,
        }
    }

    /// Detect aggregate pressure transitions across all devices.
    pub fn check_pressure_transition(&mut self) -> Option<SpacePressureEvent> {
        let under_now = self.is_under_pressure();
        let event = if under_now && !self.any_was_under_pressure {
            Some(SpacePressureEvent::EnterPressure)
        } else if !under_now && self.any_was_under_pressure {
            Some(SpacePressureEvent::ExitPressure)
        } else {
            None
        };
        self.any_was_under_pressure = under_now;
        event
    }

    /// Reset pressure tracking across all devices.
    pub fn reset_pressure_tracking(&mut self) {
        self.any_was_under_pressure = self.is_under_pressure();
        for v in &mut self.devices {
            v.reset_pressure_tracking();
        }
    }

    /// Dirty segment_groups across all devices, keyed by device index.
    #[must_use]
    pub fn all_dirty_segment_groups(&self) -> Vec<(usize, Vec<u32>)> {
        self.devices
            .iter()
            .enumerate()
            .map(|(i, v)| (i, v.dirty_segment_groups()))
            .collect()
    }

    /// Clear dirty segment_groups across all devices.
    pub fn clear_all_dirty_segment_groups(&mut self) {
        for v in &mut self.devices {
            v.clear_dirty_segment_groups();
        }
    }

    /// Generate checkpoints for all devices that have dirty segment_groups.
    #[must_use]
    pub fn all_checkpoints(&self, dirty_only: bool) -> Vec<(usize, SpaceMapCheckpointV1)> {
        self.devices
            .iter()
            .enumerate()
            .filter(|(_, v)| !dirty_only || !v.dirty_segment_groups().is_empty())
            .map(|(i, v)| (i, v.to_checkpoint(dirty_only)))
            .collect()
    }
}

// -- helper --

fn map_pool_err(device_index: usize, e: PoolAllocatorError) -> MultiDeviceAllocError {
    match e {
        PoolAllocatorError::NoFreeSegments => MultiDeviceAllocError::NoFreeSegments,
        PoolAllocatorError::SegmentOutOfRange(seg) => MultiDeviceAllocError::SegmentOutOfRange {
            device_index,
            segment: seg,
        },
        PoolAllocatorError::AlreadyUsed(seg) => MultiDeviceAllocError::AlreadyUsed {
            device_index,
            segment: seg,
        },
        PoolAllocatorError::InvalidRun(start, end) => MultiDeviceAllocError::InvalidRun {
            device_index,
            start,
            end,
        },
        PoolAllocatorError::CorruptCheckpoint => {
            MultiDeviceAllocError::CorruptCheckpoint { device_index }
        }
    }
}

#[cfg(test)]
mod multi_device_tests {
    use super::*;

    fn make_pa(segment_count: u64, free_runs: Vec<(u64, u64)>) -> PoolAllocator {
        let fm = SegmentFreeMap::new(segment_count, free_runs).unwrap();
        PoolAllocator::new(fm)
    }

    // -- construction and accessors --

    #[test]
    fn build_single_device() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(1000, vec![(0, 1000)]),
        }];
        let mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.device_count(), 1);
        assert_eq!(mva.total_free_count(), 1000);
        assert_eq!(mva.total_segment_count(), 1000);
        assert!(!mva.is_under_pressure());
    }

    #[test]
    fn build_multi_device() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(500, vec![(0, 500)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(500, vec![(0, 500)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.device_count(), 2);
        assert_eq!(mva.total_free_count(), 1000);
    }

    #[test]
    fn device_class_accessor() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(100, vec![(0, 100)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Metadata,
                allocator: make_pa(100, vec![(0, 100)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.device_class(0), AllocDeviceClass::Data);
        assert_eq!(mva.device_class(1), AllocDeviceClass::Metadata);
    }

    // -- allocation routing --

    #[test]
    fn allocate_routes_to_preferred_class() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(100, vec![(0, 100)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Metadata,
                allocator: make_pa(100, vec![(0, 100)]),
            },
        ];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        // Metadata class should route to device 1
        let (vi, seg) = mva.allocate_class(AllocDeviceClass::Metadata).unwrap();
        assert_eq!(vi, 1);
        assert!(seg < 100);
    }

    #[test]
    fn allocate_falls_back_to_data() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(100, vec![(0, 100)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::IntentLog,
                allocator: make_pa(100, vec![(0, 100)]),
            },
        ];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        // Exhaust IntentLog device
        for _ in 0..100 {
            let (vi, _) = mva.allocate_class(AllocDeviceClass::IntentLog).unwrap();
            assert_eq!(vi, 1);
        }
        // Should fall back to Data device
        let (vi, _) = mva.allocate_class(AllocDeviceClass::IntentLog).unwrap();
        assert_eq!(vi, 0);
    }

    #[test]
    fn allocate_enospc_when_all_exhausted() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(10, vec![(0, 10)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        for _ in 0..10 {
            mva.allocate().unwrap();
        }
        assert_eq!(mva.allocate(), Err(MultiDeviceAllocError::NoFreeSegments));
    }

    #[test]
    fn allocate_least_free_first() {
        // device 0 has 500 free, device 1 has 100 free — should pick device 1 first
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(500, vec![(0, 500)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(500, vec![(0, 100)]),
            },
        ];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        let (vi, _) = mva.allocate_class(AllocDeviceClass::Data).unwrap();
        assert_eq!(vi, 1, "should pick device with fewest free segments");
    }

    // -- add_free / remove_free --

    #[test]
    fn add_free_on_specific_device() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 50)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        mva.add_free(0, 50).unwrap();
        assert!(mva.is_free(0, 50));
        assert_eq!(mva.device(0).free_count(), 51);
    }

    #[test]
    fn remove_free_on_specific_device() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 100)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        mva.remove_free(0, 10).unwrap();
        assert!(!mva.is_free(0, 10));
        assert_eq!(mva.device(0).free_count(), 99);
    }

    // -- pressure transitions --

    #[test]
    fn pressure_transition_enter_and_exit() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 100)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        assert!(!mva.is_under_pressure());
        assert_eq!(mva.check_pressure_transition(), None);

        // Allocate 96 segments — crosses 95% (96 used / 100 = 96%)
        for _ in 0..96 {
            mva.allocate().unwrap();
        }
        assert!(mva.is_under_pressure());
        assert_eq!(
            mva.check_pressure_transition(),
            Some(SpacePressureEvent::EnterPressure)
        );
        // Second call stable
        assert_eq!(mva.check_pressure_transition(), None);

        // Free 10 — drops to 86% (86 used)
        for i in 0..10 {
            mva.add_free(0, i).unwrap();
        }
        assert!(!mva.is_under_pressure());
        assert_eq!(
            mva.check_pressure_transition(),
            Some(SpacePressureEvent::ExitPressure)
        );
    }

    #[test]
    fn pressure_aggregated_across_devices() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(50, vec![(0, 50)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(50, vec![(0, 50)]),
            },
        ];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        // 100 total, need 96 used for 95% pressure
        // Each device has 50 free; exhaust device 0 (50 used) and 46 from device 1 = 96 used
        for _ in 0..50 {
            let (vi, _) = mva.allocate_class(AllocDeviceClass::Data).unwrap();
            // both devices in play
            let _ = vi;
        }
        for _ in 0..46 {
            mva.allocate_class(AllocDeviceClass::Data).unwrap();
        }
        assert!(mva.is_under_pressure());
    }

    // -- stats --

    #[test]
    fn stats_aggregates() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(200, vec![(0, 200)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(300, vec![(0, 300)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        let s = mva.stats();
        assert_eq!(s.device_count, 2);
        assert_eq!(s.total_free_segments, 500);
        assert_eq!(s.total_segments, 500);
        assert_eq!(s.per_device.len(), 2);
        assert!(!s.under_pressure);
    }

    #[test]
    fn any_device_under_pressure_flag() {
        let mut pa = make_pa(100, vec![(0, 100)]);
        // Exhaust this device to trigger pressure
        for _ in 0..96 {
            pa.allocate().unwrap();
        }
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: pa,
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(1000, vec![(0, 1000)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        let s = mva.stats();
        assert!(s.any_device_under_pressure);
    }

    // -- cross-device checkpoint coordination --

    #[test]
    fn checkpoint_all_full() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(100, vec![(0, 100)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(200, vec![(0, 200)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        let ckpts = mva.all_checkpoints(false);
        assert_eq!(ckpts.len(), 2);
        assert_eq!(ckpts[0].0, 0);
        assert_eq!(ckpts[1].0, 1);
        assert_eq!(ckpts[0].1.segment_group_count, 1);
        assert_eq!(ckpts[1].1.segment_group_count, 1);
    }

    #[test]
    fn checkpoint_dirty_only_empty() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 100)]),
        }];
        let mva = MultiDevicePoolAllocator::new(entries);
        // No allocations, so no dirty segment_groups
        let ckpts = mva.all_checkpoints(true);
        assert!(ckpts.is_empty());
    }

    #[test]
    fn dirty_segment_groups_after_alloc() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 100)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        mva.allocate().unwrap();
        let dirty = mva.all_dirty_segment_groups();
        assert!(!dirty.is_empty());
        let ckpts = mva.all_checkpoints(true);
        assert_eq!(ckpts.len(), 1);
    }

    #[test]
    fn clear_all_dirty_segment_groups() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(0, 100)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        mva.allocate().unwrap();
        assert!(!mva.all_dirty_segment_groups()[0].1.is_empty());
        mva.clear_all_dirty_segment_groups();
        assert!(mva.all_dirty_segment_groups()[0].1.is_empty());
    }

    // -- full lifecycle roundtrip --

    #[test]
    fn full_alloc_free_cycle_across_devices() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(50, vec![(0, 50)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(50, vec![(0, 50)]),
            },
        ];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.total_free_count(), 100);

        // Allocate 80 segments across devices
        let mut allocs = Vec::new();
        for _ in 0..80 {
            allocs.push(mva.allocate().unwrap());
        }
        assert_eq!(mva.total_free_count(), 20);

        // Free them all
        for (vi, seg) in &allocs {
            mva.add_free(*vi, *seg).unwrap();
        }
        assert_eq!(mva.total_free_count(), 100);

        // Can re-allocate
        let (vi, _) = mva.allocate().unwrap();
        assert_eq!(mva.total_free_count(), 99);
        let _ = vi;
    }

    #[test]
    fn alloc_after_on_specific_device() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(50, 100)]),
        }];
        let mut mva = MultiDevicePoolAllocator::new(entries);
        // alloc_after(0) should find free at 50
        let seg = mva.alloc_after(0, 0).unwrap();
        assert_eq!(seg, 50);
    }

    #[test]
    fn label_methods_do_not_panic() {
        assert_eq!(AllocDeviceClass::Data.label(), "data");
        assert_eq!(AllocDeviceClass::Metadata.label(), "metadata");
        assert_eq!(AllocDeviceClass::IntentLog.label(), "intent_log");
        assert_eq!(AllocDeviceClass::ReadCache.label(), "read_cache");
        assert_eq!(AllocDeviceClass::Special.label(), "special");
    }

    #[test]
    fn segment_count_per_device() {
        let entries = vec![
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(100, vec![(0, 100)]),
            },
            DeviceAllocEntry {
                class: AllocDeviceClass::Data,
                allocator: make_pa(200, vec![(0, 200)]),
            },
        ];
        let mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.segment_count(0), 100);
        assert_eq!(mva.segment_count(1), 200);
        assert_eq!(mva.segment_count(999), 0);
    }

    #[test]
    fn runs_per_device() {
        let entries = vec![DeviceAllocEntry {
            class: AllocDeviceClass::Data,
            allocator: make_pa(100, vec![(10, 20)]),
        }];
        let mva = MultiDevicePoolAllocator::new(entries);
        assert_eq!(mva.runs(0), vec![(10, 20)]);
        assert!(mva.runs(999).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allocator(segment_count: u64, free_runs: Vec<(u64, u64)>) -> PoolAllocator {
        let fm = SegmentFreeMap::new(segment_count, free_runs).unwrap();
        PoolAllocator::new(fm)
    }

    // -- basic allocation --

    #[test]
    fn allocate_from_empty_pool_fails() {
        let mut pa = make_allocator(0, vec![]);
        assert_eq!(pa.allocate(), Err(PoolAllocatorError::NoFreeSegments));
    }

    #[test]
    fn allocate_from_full_free_pool() {
        let mut pa = make_allocator(10, vec![(0, 10)]);
        // Default segment_group size is 4096, so all 10 segments are in segment_group 0.
        let seg = pa.allocate().unwrap();
        assert!(seg < 10);
        assert!(!pa.is_free(seg));
        assert_eq!(pa.free_count(), 9);
    }

    #[test]
    fn allocate_exhausts_pool() {
        let mut pa = make_allocator(5, vec![(0, 5)]);
        for _ in 0..5 {
            assert!(pa.allocate().is_ok());
        }
        assert_eq!(pa.allocate(), Err(PoolAllocatorError::NoFreeSegments));
        assert_eq!(pa.free_count(), 0);
    }

    // -- add_free / remove_free --

    #[test]
    fn add_free_returns_segment() {
        let mut pa = make_allocator(10, vec![(0, 10)]);
        let seg = pa.allocate().unwrap();
        assert_eq!(pa.free_count(), 9);
        pa.add_free(seg).unwrap();
        assert_eq!(pa.free_count(), 10);
        assert!(pa.is_free(seg));
    }

    #[test]
    fn add_free_idempotent() {
        let mut pa = make_allocator(10, vec![(0, 10)]);
        let seg = pa.allocate().unwrap();
        pa.add_free(seg).unwrap();
        // Double-free should be a no-op, not an error.
        assert!(pa.add_free(seg).is_ok());
        assert_eq!(pa.free_count(), 10);
    }

    #[test]
    fn remove_free_on_used_segment_errors() {
        let mut pa = make_allocator(10, vec![(0, 10)]);
        let seg = pa.allocate().unwrap();
        assert_eq!(
            pa.remove_free(seg),
            Err(PoolAllocatorError::AlreadyUsed(seg))
        );
    }

    #[test]
    fn segment_out_of_range() {
        let mut pa = make_allocator(10, vec![(0, 10)]);
        assert_eq!(
            pa.add_free(100),
            Err(PoolAllocatorError::SegmentOutOfRange(100))
        );
        assert_eq!(
            pa.remove_free(100),
            Err(PoolAllocatorError::SegmentOutOfRange(100))
        );
    }

    // -- pressure transitions --

    #[test]
    fn pressure_transition_enter_and_exit() {
        let mut pa = make_allocator(100, vec![(0, 100)]);
        assert!(!pa.is_under_pressure());

        // Allocate 95 segments — 95% used = at pressure threshold.
        let mut allocated = Vec::new();
        for _ in 0..95 {
            let seg = pa.allocate().unwrap();
            allocated.push(seg);
        }
        assert!(pa.is_under_pressure());
        assert_eq!(
            pa.check_pressure_transition(),
            Some(SpacePressureEvent::EnterPressure)
        );
        assert_eq!(pa.check_pressure_transition(), None);

        // Free 10 segments: 85 used = 85% — exits pressure.
        for &seg in &allocated[0..10] {
            pa.add_free(seg).unwrap();
        }
        assert!(!pa.is_under_pressure());
        match pa.check_pressure_transition() {
            Some(SpacePressureEvent::ExitPressure) => {}
            other => panic!("expected ExitPressure, got {other:?}"),
        }
        assert_eq!(pa.check_pressure_transition(), None);
    }

    #[test]
    fn pressure_no_transition_when_stable() {
        let mut pa = make_allocator(100, vec![(0, 100)]);
        assert!(!pa.is_under_pressure());
        assert_eq!(pa.check_pressure_transition(), None);

        // Allocate a few — still well below threshold.
        for _ in 0..50 {
            pa.allocate().unwrap();
        }
        assert!(!pa.is_under_pressure());
        // State changed from false to false — no transition.
        assert_eq!(pa.check_pressure_transition(), None);
    }

    #[test]
    fn reset_pressure_tracking() {
        let mut pa = make_allocator(100, vec![(0, 5)]); // 95 used, 5 free
        assert!(pa.is_under_pressure());
        // Force reset.
        pa.reset_pressure_tracking();
        // The state is still under pressure, so no transition.
        assert_eq!(pa.check_pressure_transition(), None);
    }

    // -- per-segment_group cursor tracking --

    #[test]
    fn cursors_advance_after_allocation() {
        // 10000 segments, 4096 segments per segment_group -> 3 segment_groups.
        let mut pa = make_allocator(10000, vec![(0, 10000)]);
        let initial_cursors = pa.cursors().to_vec();

        let _seg = pa.allocate().unwrap();
        let after_cursors = pa.cursors().to_vec();

        // At least one cursor should have advanced.
        let changed = initial_cursors
            .iter()
            .zip(after_cursors.iter())
            .any(|(a, b)| a != b);
        assert!(
            changed,
            "at least one segment_group cursor should advance after allocation"
        );
    }

    #[test]
    fn cursor_wraps_within_segment_group() {
        // Small pool: 2 segment_groups of 5 segments each (use custom size).
        let fm = SegmentFreeMap::new(10, vec![(0, 10)]).unwrap();
        let mut pa = PoolAllocator::new(fm);
        // Default segment_group size is 4096, so we have 1 segment_group for 10 segments.
        // Test cursor wrapping by allocating all segments.
        for _ in 0..10 {
            pa.allocate().unwrap();
        }
        // After exhausting, cursor wraps — next allocation after add_free
        // should succeed again.
        pa.add_free(5).unwrap();
        let seg = pa.allocate().unwrap();
        assert_eq!(seg, 5);
    }

    // -- stats --

    #[test]
    fn stats_reflect_allocation() {
        let mut pa = make_allocator(100, vec![(0, 100)]);
        let s = pa.stats();
        assert_eq!(s.free_segments, 100);
        assert_eq!(s.used_segments, 0);

        pa.allocate().unwrap();
        let s = pa.stats();
        assert_eq!(s.free_segments, 99);
        assert_eq!(s.used_segments, 1);
    }

    #[test]
    fn stats_per_segment_group() {
        let pa = make_allocator(10000, vec![(0, 10000)]);
        let s = pa.stats();
        assert!(
            s.segment_group_count >= 2,
            "should have multiple segment_groups"
        );
        assert_eq!(s.per_segment_group.len(), s.segment_group_count as usize);
        for m in &s.per_segment_group {
            assert!(m.total_segments > 0);
            assert!(m.free_segments <= m.total_segments);
        }
    }

    // -- dirty segment_groups --

    #[test]
    fn dirty_segment_groups_tracked() {
        let mut pa = make_allocator(10000, vec![(0, 10000)]);
        pa.allocate().unwrap();
        let dirty = pa.dirty_segment_groups();
        assert!(
            !dirty.is_empty(),
            "allocating should mark a segment_group dirty"
        );
        pa.clear_dirty_segment_groups();
        assert!(pa.dirty_segment_groups().is_empty());
    }

    // -- selection policy: least-free-first --

    #[test]
    fn selection_picks_least_free_segment_group() {
        // Create a pool where segment_group 0 has fewer free segments than segment_group 1.
        // 4096 segments/segment_group. Free only 50 in ms0, 100 in ms1.
        // ms0: segments 50..4096 free (4046 free)
        let runs = vec![(50, 4096)];
        // ms1: segments 4096..8192 ALL free (4096 free)
        let fm = SegmentFreeMap::new(8192, runs).unwrap();
        let mut pa = PoolAllocator::new(fm);

        // ms0 has 4046 free, ms1 has 4096 free.
        // Least-free-first should pick ms0 (fewer free segments).
        let seg = pa.allocate().unwrap();
        assert!(
            seg < 4096,
            "expected allocation from segment_group 0 (least free), got seg {seg}"
        );
    }

    #[test]
    fn selection_respects_round_robin_tiebreak() {
        // Three segment_groups with equal free counts: round-robin rotates.
        let fm = SegmentFreeMap::new(12288, vec![(0, 12288)]).unwrap();
        let mut pa = PoolAllocator::new(fm);

        let first = pa.allocate().unwrap();
        let first_ms = first / 4096;

        // Return it to restore equal free counts across all segment_groups.
        pa.add_free(first).unwrap();

        // Round-robin should pick (first_ms + 1) % 3.
        let second = pa.allocate().unwrap();
        let second_ms = second / 4096;
        let expected = (first_ms + 1) % 3;
        assert_eq!(
            second_ms, expected,
            "round-robin should rotate from {first_ms} to {expected}, got {second_ms}"
        );

        // Return and rotate once more.
        pa.add_free(second).unwrap();
        let third = pa.allocate().unwrap();
        let third_ms = third / 4096;
        let expected3 = (expected + 1) % 3;
        assert_eq!(
            third_ms, expected3,
            "round-robin should rotate to {expected3}, got {third_ms}"
        );
    }

    // -- alloc_after bypass --

    #[test]
    fn alloc_after_bypasses_selection() {
        let mut pa = make_allocator(100, vec![(50, 100)]); // only segs 50-99 free.
        let seg = pa.alloc_after(0).unwrap();
        assert!(
            seg >= 50,
            "alloc_after should find free segment at or after cursor"
        );
    }

    // -- error conversion --

    #[test]
    fn error_conversion_from_free_map() {
        let e = PoolAllocatorError::from(FreeMapError::NoFreeSegments);
        assert_eq!(e, PoolAllocatorError::NoFreeSegments);

        let e = PoolAllocatorError::from(FreeMapError::SegmentOutOfRange(42));
        assert_eq!(e, PoolAllocatorError::SegmentOutOfRange(42));

        let e = PoolAllocatorError::from(FreeMapError::AlreadyUsed(7));
        assert_eq!(e, PoolAllocatorError::AlreadyUsed(7));

        let e = PoolAllocatorError::from(FreeMapError::InvalidRun(1, 5));
        assert_eq!(e, PoolAllocatorError::InvalidRun(1, 5));
    }
    // =====================================================================
    // Integration tests: full propagation chain (issue #1347)
    // =====================================================================
    // These tests exercise the complete chain from the PoolAllocator up
    // through the store-facing API surface: allocation → pressure →
    // exhaustion (NoFreeSegments mapped to StoreError::NoSpace) → free →
    // exit pressure → allocation succeeds again.

    #[test]
    fn full_chain_allocate_exhaust_free_reallocate() {
        // Create a pool with exactly 10 segments.
        let mut pa = make_allocator(10, vec![(0, 10)]);

        // Phase 1: allocate all 10 segments.
        let mut allocated = Vec::new();
        for _ in 0..10 {
            let seg = pa.allocate().unwrap();
            assert!(seg < 10);
            allocated.push(seg);
        }

        // Phase 2: pool is exhausted — NoFreeSegments.
        assert_eq!(pa.allocate(), Err(PoolAllocatorError::NoFreeSegments));
        assert_eq!(pa.free_count(), 0);

        // Phase 3: free half the segments.
        for &seg in &allocated[0..5] {
            pa.add_free(seg).unwrap();
        }
        assert_eq!(pa.free_count(), 5);

        // Phase 4: allocation succeeds again.
        let seg = pa.allocate().unwrap();
        assert!(!pa.is_free(seg)); // segment is now used
        assert_eq!(pa.free_count(), 4);
    }

    #[test]
    fn full_chain_pressure_enter_exit_reenter() {
        // 100 segments, 95% threshold at 95 used.
        let mut pa = make_allocator(100, vec![(0, 100)]);
        assert!(!pa.is_under_pressure());
        assert_eq!(pa.check_pressure_transition(), None);

        // Allocate 95 segments — crosses into pressure.
        let mut allocated = Vec::new();
        for _ in 0..95 {
            let seg = pa.allocate().unwrap();
            allocated.push(seg);
        }
        assert!(pa.is_under_pressure());
        assert_eq!(
            pa.check_pressure_transition(),
            Some(SpacePressureEvent::EnterPressure)
        );
        // Second call is stable — no transition.
        assert_eq!(pa.check_pressure_transition(), None);

        // Free 10 segments back to the pool — 85 used = 85% < 95%, exit pressure.
        for &seg in &allocated[0..10] {
            pa.add_free(seg).unwrap();
        }
        assert!(!pa.is_under_pressure());
        assert_eq!(
            pa.check_pressure_transition(),
            Some(SpacePressureEvent::ExitPressure)
        );

        // Re-enter pressure: allocate 10 more (back to 95 used).
        for _ in 0..10 {
            pa.allocate().unwrap();
        }
        assert!(pa.is_under_pressure());
        assert_eq!(
            pa.check_pressure_transition(),
            Some(SpacePressureEvent::EnterPressure)
        );
    }

    #[test]
    fn full_chain_no_double_pressure_event_on_repeated_check() {
        // Start well below threshold, then drive above.
        let mut pa = make_allocator(100, vec![(0, 100)]);
        assert!(!pa.is_under_pressure());

        // Allocate 95 segments — crosses into pressure.
        for _ in 0..95 {
            pa.allocate().unwrap();
        }
        assert!(pa.is_under_pressure());
        // First check must fire EnterPressure.
        assert_eq!(
            pa.check_pressure_transition(),
            Some(SpacePressureEvent::EnterPressure)
        );
        // Repeated checks must not fire again.
        for _ in 0..10 {
            assert_eq!(pa.check_pressure_transition(), None);
        }
    }

    #[test]
    fn full_chain_segment_group_cursors_maintained_through_exhaustion() {
        // 8192 segments = 2 segment_groups (4096 each).
        let mut pa = make_allocator(8192, vec![(0, 8192)]);

        // Exhaust the entire pool.
        let mut count = 0u64;
        while let Ok(_seg) = pa.allocate() {
            count += 1;
        }
        assert_eq!(count, 8192);
        assert_eq!(pa.free_count(), 0);
        assert!(pa.is_under_pressure());

        // Free one segment in each segment_group.
        // ms0: seg 100, ms1: seg 5000
        pa.add_free(100).unwrap();
        pa.add_free(5000).unwrap();
        assert_eq!(pa.free_count(), 2);

        // Allocate both back — should work.
        let s1 = pa.allocate().unwrap();
        let s2 = pa.allocate().unwrap();
        // Both segment_groups should have been served.
        let ms1 = s1 / 4096;
        let ms2 = s2 / 4096;
        assert!(
            ms1 != ms2 || s1 == s2 + 4096 || s2 == s1 + 4096,
            "expected allocations from different segment_groups, got seg {s1} (ms{ms1}) and seg {s2} (ms{ms2})"
        );
        assert_eq!(pa.free_count(), 0);
    }
}
