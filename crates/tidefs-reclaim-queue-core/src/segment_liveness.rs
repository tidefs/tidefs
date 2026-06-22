// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Segment liveness tracking for dead-segment reclamation.
//!
//! Tracks each segment's live-byte and dead-byte counts, updated by
//! overwrite and delete operations. It exposes deterministic liveness reports
//! so the segment cleaner can own fully-dead freeing and the compaction
//! authority can own partial-live rewrite policy.
//!
//! The queue is serializable so it can be persisted as a reclaim-queue
//! segment in the local object store.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// SegmentLivenessEntry
// ---------------------------------------------------------------------------

/// Per-segment liveness counters.
///
/// `live_bytes` tracks bytes still referenced by live objects.
/// `dead_bytes` tracks bytes eligible for reclamation (freed by
/// overwrite or delete). The dead ratio (`dead_bytes / total_bytes`)
/// drives candidate selection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SegmentLivenessEntry {
    /// Stable segment identifier.
    pub segment_id: u64,
    /// Bytes still referenced by live objects in this segment.
    pub live_bytes: u64,
    /// Bytes eligible for reclamation in this segment.
    pub dead_bytes: u64,
    /// Transaction group when this segment was first written (0 if unknown).
    pub creation_commit_group: u64,
}

impl SegmentLivenessEntry {
    /// Create a new liveness entry for a segment.
    #[must_use]
    pub const fn new(segment_id: u64, live_bytes: u64, dead_bytes: u64) -> Self {
        Self {
            segment_id,
            live_bytes,
            dead_bytes,
            creation_commit_group: 0,
        }
    }

    /// Create a new liveness entry with a known creation transaction group.
    #[must_use]
    pub const fn with_txg(
        segment_id: u64,
        live_bytes: u64,
        dead_bytes: u64,
        creation_commit_group: u64,
    ) -> Self {
        Self {
            segment_id,
            live_bytes,
            dead_bytes,
            creation_commit_group,
        }
    }

    /// Total accounted bytes in the segment.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.live_bytes.saturating_add(self.dead_bytes)
    }

    /// Fraction of the segment that is dead, in [0.0, 1.0].
    ///
    /// Returns 0.0 when there are no accounted bytes.
    #[must_use]
    pub fn dead_ratio(self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            return 0.0;
        }
        self.dead_bytes as f64 / total as f64
    }

    /// Returns `true` if this segment has no accounted bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.live_bytes == 0 && self.dead_bytes == 0
    }

    /// Returns `true` if this segment is fully dead (no live bytes).
    #[must_use]
    pub const fn is_fully_dead(self) -> bool {
        self.live_bytes == 0 && self.dead_bytes > 0
    }

    /// Returns true if the segment is old enough relative to `current_commit_group`
    /// given a minimum age threshold in transaction groups.
    ///
    /// A segment with `creation_commit_group == 0` (unknown creation time, e.g.
    /// deserialised from format version 1) is always considered old enough.
    #[must_use]
    pub const fn is_old_enough(
        self,
        current_commit_group: u64,
        min_age_commit_groups: u64,
    ) -> bool {
        if self.creation_commit_group == 0 {
            return true;
        }
        current_commit_group.saturating_sub(self.creation_commit_group) >= min_age_commit_groups
    }
}

impl fmt::Display for SegmentLivenessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "segment={} live={} dead={} ratio={:.4} commit_group={}",
            self.segment_id,
            self.live_bytes,
            self.dead_bytes,
            self.dead_ratio(),
            self.creation_commit_group
        )
    }
}

/// Downstream path indicated by a liveness report entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentLivenessHandoffTarget {
    /// Segment has no live bytes and may proceed through cleaner-owned free work.
    CleanerFullyDead,
    /// Segment has both live and dead bytes; it is input for compaction authority.
    CompactionPartialLive,
}

/// Deterministic liveness handoff record for downstream consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SegmentLivenessHandoff {
    /// Stable segment identifier.
    pub segment_id: u64,
    /// Bytes still live in the segment.
    pub live_bytes: u64,
    /// Bytes known dead in the segment.
    pub dead_bytes: u64,
    /// Transaction group when this segment was first written.
    pub creation_commit_group: u64,
    /// Downstream owner for this liveness path.
    pub target: SegmentLivenessHandoffTarget,
}

impl SegmentLivenessHandoff {
    #[must_use]
    pub const fn new(
        segment_id: u64,
        live_bytes: u64,
        dead_bytes: u64,
        creation_commit_group: u64,
        target: SegmentLivenessHandoffTarget,
    ) -> Self {
        Self {
            segment_id,
            live_bytes,
            dead_bytes,
            creation_commit_group,
            target,
        }
    }

    #[must_use]
    pub const fn is_fully_dead(self) -> bool {
        matches!(self.target, SegmentLivenessHandoffTarget::CleanerFullyDead)
    }

    #[must_use]
    pub const fn is_partially_live(self) -> bool {
        matches!(
            self.target,
            SegmentLivenessHandoffTarget::CompactionPartialLive
        )
    }
}

/// Fully-dead and partial-live liveness paths in stable segment-id order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SegmentLivenessReport {
    /// Fully-dead segments for cleaner/free authority.
    pub fully_dead: Vec<SegmentLivenessHandoff>,
    /// Partial-live segments for compaction authority input.
    pub partially_live: Vec<SegmentLivenessHandoff>,
}

impl SegmentLivenessReport {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fully_dead.is_empty() && self.partially_live.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SegmentLivenessQueue
// ---------------------------------------------------------------------------

/// Persistent queue tracking segment liveness for dead-segment reclamation.
///
/// Each segment known to the queue has live-byte and dead-byte counts.
/// Overwrites transfer bytes from live to dead; deletes add dead bytes. The
/// authoritative cross-crate boundary is [`handoff_report`](Self::handoff_report):
/// fully-dead entries feed cleaner/free authority, while partial-live entries
/// feed compaction authority policy.
///
/// # Persistence
///
/// The queue serializes to a compact byte representation via
/// [`to_bytes`](Self::to_bytes) and [`from_bytes`](Self::from_bytes).
/// The caller (typically the local object store integration layer) is
/// responsible for writing/reading these bytes to/from a reclaim-queue
/// segment with appropriate integrity framing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SegmentLivenessQueue {
    segments: BTreeMap<u64, SegmentLivenessEntry>,
}

impl SegmentLivenessQueue {
    /// Create an empty segment liveness queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
        }
    }

    /// Number of tracked segments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns `true` if no segments are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// Get the liveness entry for a segment, if tracked.
    #[must_use]
    pub fn get(&self, segment_id: u64) -> Option<&SegmentLivenessEntry> {
        self.segments.get(&segment_id)
    }

    /// Returns `true` if the segment is tracked.
    #[must_use]
    pub fn contains(&self, segment_id: u64) -> bool {
        self.segments.contains_key(&segment_id)
    }

    /// Sum of live bytes across all tracked segments.
    #[must_use]
    pub fn total_live_bytes(&self) -> u64 {
        self.segments
            .values()
            .fold(0u64, |acc, e| acc.saturating_add(e.live_bytes))
    }

    /// Sum of dead bytes across all tracked segments.
    #[must_use]
    pub fn total_dead_bytes(&self) -> u64 {
        self.segments
            .values()
            .fold(0u64, |acc, e| acc.saturating_add(e.dead_bytes))
    }

    /// Iterate over all tracked entries in segment-id order.
    pub fn entries(&self) -> impl Iterator<Item = &SegmentLivenessEntry> {
        self.segments.values()
    }

    /// Return fully-dead and partial-live liveness paths in segment-id order.
    ///
    /// This method performs no threshold admission and no merge scoring. It is
    /// a deterministic handoff surface for cleaner and compaction consumers.
    #[must_use]
    pub fn handoff_report(&self) -> SegmentLivenessReport {
        let mut report = SegmentLivenessReport::default();
        for entry in self.segments.values() {
            if entry.is_fully_dead() {
                report.fully_dead.push(SegmentLivenessHandoff::new(
                    entry.segment_id,
                    entry.live_bytes,
                    entry.dead_bytes,
                    entry.creation_commit_group,
                    SegmentLivenessHandoffTarget::CleanerFullyDead,
                ));
            } else if entry.live_bytes > 0 && entry.dead_bytes > 0 {
                report.partially_live.push(SegmentLivenessHandoff::new(
                    entry.segment_id,
                    entry.live_bytes,
                    entry.dead_bytes,
                    entry.creation_commit_group,
                    SegmentLivenessHandoffTarget::CompactionPartialLive,
                ));
            }
        }
        report
    }

    // ------------------------------------------------------------------
    // Mutation
    // ------------------------------------------------------------------

    /// Record that `old_extent_bytes` in a segment were overwritten.
    ///
    /// Transfers bytes from live to dead: decrements live_bytes and
    /// increments dead_bytes by `old_extent_bytes`. If the segment is
    /// not already tracked, it is inserted with zero live bytes and
    /// `old_extent_bytes` dead bytes.
    ///
    /// Live bytes are clamped at zero on underflow (the caller should
    /// never over-report, but the queue is defensive).
    pub fn record_overwrite(&mut self, segment_id: u64, old_extent_bytes: u64) {
        if old_extent_bytes == 0 {
            return;
        }
        let entry = self.segments.entry(segment_id).or_default();
        entry.segment_id = segment_id;
        // Decrement live, clamp at zero.
        entry.live_bytes = entry.live_bytes.saturating_sub(old_extent_bytes);
        entry.dead_bytes = entry.dead_bytes.saturating_add(old_extent_bytes);
    }

    /// Record that `extent_bytes` in a segment were deleted.
    ///
    /// Decrements live_bytes and increments dead_bytes by
    /// `extent_bytes`. If the segment is not already tracked, it is
    /// inserted with zero live bytes and `extent_bytes` dead bytes.
    pub fn record_delete(&mut self, segment_id: u64, extent_bytes: u64) {
        if extent_bytes == 0 {
            return;
        }
        let entry = self.segments.entry(segment_id).or_default();
        entry.segment_id = segment_id;
        entry.live_bytes = entry.live_bytes.saturating_sub(extent_bytes);
        entry.dead_bytes = entry.dead_bytes.saturating_add(extent_bytes);
    }

    /// Register live bytes for a segment (e.g. after a write allocates
    /// new space in the segment). Increments live_bytes.
    ///
    /// This is the inverse of `record_overwrite`/`record_delete`: it
    /// adds live bytes for newly-written data tracked in this segment.
    pub fn record_write(&mut self, segment_id: u64, new_extent_bytes: u64) {
        if new_extent_bytes == 0 {
            return;
        }
        let entry = self.segments.entry(segment_id).or_default();
        entry.segment_id = segment_id;
        entry.live_bytes = entry.live_bytes.saturating_add(new_extent_bytes);
    }

    /// Record a write at a known transaction group.
    ///
    /// Like [`record_write`] but also captures `creation_commit_group` for new
    /// segments (preserves the original creation_commit_group for existing segments).
    pub fn record_write_at_commit_group(
        &mut self,
        segment_id: u64,
        new_extent_bytes: u64,
        creation_commit_group: u64,
    ) {
        if new_extent_bytes == 0 {
            return;
        }
        let existed = self.segments.contains_key(&segment_id);
        self.record_write(segment_id, new_extent_bytes);
        if !existed {
            if let Some(entry) = self.segments.get_mut(&segment_id) {
                entry.creation_commit_group = creation_commit_group;
            }
        }
    }

    // ------------------------------------------------------------------
    // Candidate selection
    // ------------------------------------------------------------------

    /// Return the segment identifier with the highest dead-byte fraction
    /// that meets or exceeds `min_dead_ratio`.
    ///
    /// Ties are broken by higher dead bytes, then lower segment id
    /// for deterministic selection. Returns `None` if no segment meets
    /// the threshold.
    #[must_use]
    pub fn next_candidate(&self, min_dead_ratio: f64) -> Option<u64> {
        self.next_candidate_filtered(min_dead_ratio, |_| true)
    }

    /// Return the best candidate segment identifier, respecting a minimum
    /// segment age. Only segments created at least `min_age_commit_groups` transaction
    /// groups before `current_commit_group` are considered.
    #[must_use]
    pub fn next_candidate_with_age(
        &self,
        min_dead_ratio: f64,
        current_commit_group: u64,
        min_age_commit_groups: u64,
    ) -> Option<u64> {
        self.next_candidate_filtered(min_dead_ratio, |e| {
            e.is_old_enough(current_commit_group, min_age_commit_groups)
        })
    }

    /// Internal helper for filtered candidate selection.
    fn next_candidate_filtered<F: FnMut(&SegmentLivenessEntry) -> bool>(
        &self,
        min_dead_ratio: f64,
        mut filter: F,
    ) -> Option<u64> {
        self.segments
            .values()
            .filter(|e| e.dead_ratio() >= min_dead_ratio && e.dead_bytes > 0 && filter(e))
            .max_by(|a, b| {
                a.dead_ratio()
                    .partial_cmp(&b.dead_ratio())
                    .unwrap_or(core::cmp::Ordering::Equal)
                    .then_with(|| a.dead_bytes.cmp(&b.dead_bytes))
                    .then_with(|| b.segment_id.cmp(&a.segment_id)) // lower id wins
            })
            .map(|e| e.segment_id)
    }

    /// Return up to `limit` candidate segment identifiers sorted by
    /// highest dead ratio (above `min_dead_ratio`), then by highest
    /// dead bytes, then by lowest segment id.
    #[must_use]
    pub fn candidate_batch(&self, min_dead_ratio: f64, limit: usize) -> Vec<u64> {
        self.candidate_batch_filtered(min_dead_ratio, limit, |_| true)
    }

    /// Return up to `limit` candidates respecting a minimum segment age.
    #[must_use]
    pub fn candidate_batch_with_age(
        &self,
        min_dead_ratio: f64,
        limit: usize,
        current_commit_group: u64,
        min_age_commit_groups: u64,
    ) -> Vec<u64> {
        self.candidate_batch_filtered(min_dead_ratio, limit, |e| {
            e.is_old_enough(current_commit_group, min_age_commit_groups)
        })
    }

    /// Internal batch helper with filter.
    fn candidate_batch_filtered<F: FnMut(&SegmentLivenessEntry) -> bool>(
        &self,
        min_dead_ratio: f64,
        limit: usize,
        mut filter: F,
    ) -> Vec<u64> {
        if limit == 0 {
            return Vec::new();
        }
        let mut candidates: Vec<&SegmentLivenessEntry> = self
            .segments
            .values()
            .filter(|e| e.dead_ratio() >= min_dead_ratio && e.dead_bytes > 0 && filter(e))
            .collect();
        candidates.sort_by(|a, b| {
            b.dead_ratio()
                .partial_cmp(&a.dead_ratio())
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| b.dead_bytes.cmp(&a.dead_bytes))
                .then_with(|| a.segment_id.cmp(&b.segment_id))
        });
        candidates
            .into_iter()
            .take(limit)
            .map(|e| e.segment_id)
            .collect()
    }

    // ------------------------------------------------------------------
    // Reclamation completion
    // ------------------------------------------------------------------

    /// Mark a segment as fully reclaimed, removing it from the queue.
    ///
    /// Returns `true` if the segment was present and removed, `false`
    /// if it was not tracked.
    pub fn commit_dead(&mut self, segment_id: u64) -> bool {
        self.segments.remove(&segment_id).is_some()
    }

    /// Clear all entries from the queue.
    pub fn clear(&mut self) {
        self.segments.clear();
    }

    // ------------------------------------------------------------------
    // Serialization (for persistence to local object store)
    // ------------------------------------------------------------------

    /// Serialization format version marker. Bumped to 2 for creation_commit_group.
    const FORMAT_VERSION: u32 = 2;

    /// Magic bytes identifying a reclaim-queue segment payload.
    const MAGIC: &'static [u8; 4] = b"RCLQ";

    /// Serialize the queue to a compact byte representation.
    ///
    /// Format (little-endian):
    /// - 4 bytes: magic `RCLQ`
    /// - 4 bytes: format version (u32)
    /// - 4 bytes: entry count (u32)
    /// - For each entry:
    ///   - 8 bytes: creation_commit_group (u64)  [added in version 2]
    ///   - 8 bytes: segment_id (u64)
    ///   - 8 bytes: live_bytes (u64)
    ///   - 8 bytes: dead_bytes (u64)
    ///
    /// Total size: 12 + N * 32 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let count = self.segments.len() as u32;
        let mut buf = Vec::with_capacity(12 + self.segments.len() * 32);

        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());

        for entry in self.segments.values() {
            buf.extend_from_slice(&entry.creation_commit_group.to_le_bytes());
            buf.extend_from_slice(&entry.segment_id.to_le_bytes());
            buf.extend_from_slice(&entry.live_bytes.to_le_bytes());
            buf.extend_from_slice(&entry.dead_bytes.to_le_bytes());
        }

        buf
    }

    /// Deserialize a queue from bytes previously produced by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// Returns `SegmentLivenessDeserializeError` if the data is
    /// truncated, has an invalid magic, or has an unsupported version.
    pub fn from_bytes(data: &[u8]) -> Result<Self, SegmentLivenessDeserializeError> {
        if data.len() < 12 {
            return Err(SegmentLivenessDeserializeError::Truncated);
        }

        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(SegmentLivenessDeserializeError::InvalidMagic);
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        // Accept version 1 (legacy) and version 2 (current).
        let is_v1 = version == 1;
        if version != Self::FORMAT_VERSION && !is_v1 {
            return Err(SegmentLivenessDeserializeError::UnsupportedVersion {
                found: version,
                expected: Self::FORMAT_VERSION,
            });
        }

        let entry_size: usize = if is_v1 { 24 } else { 32 };
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let expected_len = 12usize
            .checked_add(
                count
                    .checked_mul(entry_size)
                    .ok_or(SegmentLivenessDeserializeError::Truncated)?,
            )
            .ok_or(SegmentLivenessDeserializeError::Truncated)?;

        if data.len() < expected_len {
            return Err(SegmentLivenessDeserializeError::Truncated);
        }

        let mut queue = Self::new();
        if is_v1 {
            // Backward-compatible decode: v1 has 24-byte entries without creation_commit_group.
            for i in 0..count {
                let offset = 12 + i * 24;
                let segment_id = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                let live_bytes =
                    u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
                let dead_bytes =
                    u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
                queue.segments.insert(
                    segment_id,
                    SegmentLivenessEntry {
                        segment_id,
                        live_bytes,
                        dead_bytes,
                        creation_commit_group: 0,
                    },
                );
            }
        } else {
            // Version 2: 32-byte entries with creation_commit_group.
            for i in 0..count {
                let offset = 12 + i * 32;
                let creation_commit_group =
                    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                let segment_id =
                    u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
                let live_bytes =
                    u64::from_le_bytes(data[offset + 16..offset + 24].try_into().unwrap());
                let dead_bytes =
                    u64::from_le_bytes(data[offset + 24..offset + 32].try_into().unwrap());
                queue.segments.insert(
                    segment_id,
                    SegmentLivenessEntry {
                        segment_id,
                        live_bytes,
                        dead_bytes,
                        creation_commit_group,
                    },
                );
            }
        }

        Ok(queue)
    }

    /// Estimate the serialized byte size without allocating.
    #[must_use]
    pub fn serialized_len(&self) -> usize {
        12 + self.segments.len() * 32
    }
}

// ---------------------------------------------------------------------------
// Deserialization error
// ---------------------------------------------------------------------------

/// Errors that can occur when deserializing a [`SegmentLivenessQueue`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegmentLivenessDeserializeError {
    /// Data is shorter than the minimum header.
    Truncated,
    /// Magic bytes do not match the expected `RCLQ`.
    InvalidMagic,
    /// Format version is not supported.
    UnsupportedVersion { found: u32, expected: u32 },
}

impl fmt::Display for SegmentLivenessDeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated reclaim-queue data"),
            Self::InvalidMagic => f.write_str("invalid reclaim-queue magic bytes"),
            Self::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported reclaim-queue version: found {found}, expected {expected}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ReclaimQueueStorage -- persistence abstraction
// ---------------------------------------------------------------------------

/// Storage backend for persisting the reclaim queue.
///
/// Implementations write/read the serialized queue bytes to/from durable
/// storage. The default implementation in `tidefs-reclaim` uses the
/// local object store's `put_named`/`get_named` with a well-known name,
/// which internally wraps every write with `IntegrityTrailerV2` for
/// integrity verification.
pub trait ReclaimQueueStorage {
    /// Error type returned by storage operations.
    type Error: fmt::Debug + fmt::Display;

    /// Load the serialized reclaim queue bytes, if present.
    ///
    /// Returns `Ok(None)` when no queue has been persisted yet (first
    /// startup or after a clean format).
    fn load_reclaim_queue(&self) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Store the serialized reclaim queue bytes.
    ///
    /// Replaces any previously-persisted queue state.
    fn store_reclaim_queue(&mut self, data: &[u8]) -> Result<(), Self::Error>;
}

impl SegmentLivenessQueue {
    /// Load the queue from a storage backend.
    ///
    /// If no persisted state exists, returns an empty queue.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage read fails or if the persisted
    /// bytes are corrupt.
    pub fn load_from(
        storage: &impl ReclaimQueueStorage,
    ) -> Result<Self, SegmentLivenessPersistError> {
        match storage
            .load_reclaim_queue()
            .map_err(|e| SegmentLivenessPersistError::Storage(alloc::format!("{e}")))?
        {
            Some(bytes) => Self::from_bytes(&bytes)
                .map_err(|e| SegmentLivenessPersistError::Deserialize(alloc::format!("{e}"))),
            None => Ok(Self::new()),
        }
    }

    /// Flush the current queue state to a storage backend.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage write fails.
    pub fn flush_to(
        &self,
        storage: &mut impl ReclaimQueueStorage,
    ) -> Result<(), SegmentLivenessPersistError> {
        let bytes = self.to_bytes();
        storage
            .store_reclaim_queue(&bytes)
            .map_err(|e| SegmentLivenessPersistError::Storage(alloc::format!("{e}")))
    }
}

// ---------------------------------------------------------------------------
// SegmentLivenessPersistError
// ---------------------------------------------------------------------------

/// Errors that can occur during persistence operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentLivenessPersistError {
    /// The underlying storage operation failed.
    Storage(String),
    /// The persisted bytes could not be deserialized.
    Deserialize(String),
}

impl fmt::Display for SegmentLivenessPersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(msg) => write!(f, "reclaim queue storage error: {msg}"),
            Self::Deserialize(msg) => write!(f, "reclaim queue deserialize error: {msg}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Construction and accessors --

    #[test]
    fn new_queue_is_empty() {
        let q = SegmentLivenessQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.total_live_bytes(), 0);
        assert_eq!(q.total_dead_bytes(), 0);
        assert_eq!(q.next_candidate(0.0), None);
    }

    #[test]
    fn get_and_contains() {
        let mut q = SegmentLivenessQueue::new();
        assert!(!q.contains(1));
        assert_eq!(q.get(1), None);

        q.record_write(1, 4096);
        assert!(q.contains(1));
        assert_eq!(q.get(1).map(|e| e.live_bytes), Some(4096));
    }

    // -- record_write --

    #[test]
    fn record_write_adds_live_bytes() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 4096);
        q.record_write(1, 4096);
        assert_eq!(q.len(), 1);
        assert_eq!(q.get(1).unwrap().live_bytes, 8192);
        assert_eq!(q.get(1).unwrap().dead_bytes, 0);
    }

    #[test]
    fn record_write_zero_is_noop() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 0);
        assert!(q.is_empty());
    }

    #[test]
    fn record_write_multiple_segments() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 1000);
        q.record_write(2, 2000);
        q.record_write(3, 3000);
        assert_eq!(q.len(), 3);
        assert_eq!(q.total_live_bytes(), 6000);
    }

    // -- record_overwrite --

    #[test]
    fn record_overwrite_transfers_live_to_dead() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 4096);
        q.record_overwrite(1, 1024);
        assert_eq!(q.get(1).unwrap().live_bytes, 3072);
        assert_eq!(q.get(1).unwrap().dead_bytes, 1024);
    }

    #[test]
    fn record_overwrite_clamps_live_at_zero() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 100);
        q.record_overwrite(1, 500); // over-report
        assert_eq!(q.get(1).unwrap().live_bytes, 0);
        assert_eq!(q.get(1).unwrap().dead_bytes, 500);
    }

    #[test]
    fn record_overwrite_unknown_segment_inserts_with_zero_live() {
        let mut q = SegmentLivenessQueue::new();
        q.record_overwrite(42, 2048);
        assert_eq!(q.get(42).unwrap().live_bytes, 0);
        assert_eq!(q.get(42).unwrap().dead_bytes, 2048);
    }

    #[test]
    fn record_overwrite_zero_is_noop() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 100);
        q.record_overwrite(1, 0);
        assert_eq!(q.get(1).unwrap().live_bytes, 100);
        assert_eq!(q.get(1).unwrap().dead_bytes, 0);
    }

    // -- record_delete --

    #[test]
    fn record_delete_transfers_live_to_dead() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 4096);
        q.record_delete(1, 4096);
        assert_eq!(q.get(1).unwrap().live_bytes, 0);
        assert_eq!(q.get(1).unwrap().dead_bytes, 4096);
        assert!(q.get(1).unwrap().is_fully_dead());
    }

    #[test]
    fn record_delete_unknown_segment_inserts_with_zero_live() {
        let mut q = SegmentLivenessQueue::new();
        q.record_delete(7, 1024);
        assert_eq!(q.get(7).unwrap().live_bytes, 0);
        assert_eq!(q.get(7).unwrap().dead_bytes, 1024);
    }

    #[test]
    fn record_delete_zero_is_noop() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 100);
        q.record_delete(1, 0);
        assert_eq!(q.get(1).unwrap().live_bytes, 100);
        assert_eq!(q.get(1).unwrap().dead_bytes, 0);
    }

    // -- Interleaved operations --

    #[test]
    fn interleaved_write_overwrite_delete() {
        let mut q = SegmentLivenessQueue::new();
        // Segment 1: write 10K, overwrite 4K, delete 2K
        q.record_write(1, 10240);
        q.record_overwrite(1, 4096);
        q.record_delete(1, 2048);
        assert_eq!(q.get(1).unwrap().live_bytes, 4096);
        assert_eq!(q.get(1).unwrap().dead_bytes, 6144);

        // Segment 2: just deletes
        q.record_delete(2, 8192);
        assert_eq!(q.get(2).unwrap().live_bytes, 0);
        assert_eq!(q.get(2).unwrap().dead_bytes, 8192);
    }

    #[test]
    fn multi_segment_churn() {
        let mut q = SegmentLivenessQueue::new();
        for seg in 1..=5u64 {
            q.record_write(seg, seg * 1000);
        }
        // Overwrite half of segment 3
        q.record_overwrite(3, 1500);
        // Delete all of segment 5
        q.record_delete(5, 5000);

        assert_eq!(q.len(), 5);
        assert_eq!(q.get(3).unwrap().live_bytes, 1500);
        assert_eq!(q.get(3).unwrap().dead_bytes, 1500);
        assert_eq!(q.get(5).unwrap().live_bytes, 0);
        assert_eq!(q.get(5).unwrap().dead_bytes, 5000);
    }

    #[test]
    fn handoff_report_distinguishes_fully_dead_and_partial_live() {
        let mut q = SegmentLivenessQueue::new();
        q.segments
            .insert(1, SegmentLivenessEntry::with_txg(1, 0, 4096, 10));
        q.segments
            .insert(2, SegmentLivenessEntry::with_txg(2, 2048, 2048, 11));
        q.segments
            .insert(3, SegmentLivenessEntry::with_txg(3, 4096, 0, 12));
        q.segments
            .insert(4, SegmentLivenessEntry::with_txg(4, 0, 0, 13));

        let report = q.handoff_report();

        assert_eq!(
            report.fully_dead,
            vec![SegmentLivenessHandoff::new(
                1,
                0,
                4096,
                10,
                SegmentLivenessHandoffTarget::CleanerFullyDead,
            )]
        );
        assert_eq!(
            report.partially_live,
            vec![SegmentLivenessHandoff::new(
                2,
                2048,
                2048,
                11,
                SegmentLivenessHandoffTarget::CompactionPartialLive,
            )]
        );
    }

    #[test]
    fn handoff_report_is_stable_by_segment_id() {
        let mut q = SegmentLivenessQueue::new();
        q.segments
            .insert(30, SegmentLivenessEntry::new(30, 100, 900));
        q.segments
            .insert(10, SegmentLivenessEntry::new(10, 0, 1024));
        q.segments.insert(20, SegmentLivenessEntry::new(20, 50, 50));

        let report = q.handoff_report();

        assert_eq!(
            report
                .fully_dead
                .iter()
                .map(|entry| entry.segment_id)
                .collect::<Vec<_>>(),
            vec![10]
        );
        assert_eq!(
            report
                .partially_live
                .iter()
                .map(|entry| entry.segment_id)
                .collect::<Vec<_>>(),
            vec![20, 30]
        );
    }

    // -- next_candidate --

    #[test]
    fn next_candidate_empty_queue() {
        let q = SegmentLivenessQueue::new();
        assert_eq!(q.next_candidate(0.0), None);
        assert_eq!(q.next_candidate(0.5), None);
    }

    #[test]
    fn next_candidate_selects_highest_dead_ratio() {
        let mut q = SegmentLivenessQueue::new();
        // seg 10: 900 live, 100 dead (ratio 0.10)
        q.segments
            .insert(10, SegmentLivenessEntry::new(10, 900, 100));
        // seg 20: 500 live, 500 dead (ratio 0.50)
        q.segments
            .insert(20, SegmentLivenessEntry::new(20, 500, 500));
        // seg 30: 100 live, 900 dead (ratio 0.90)
        q.segments
            .insert(30, SegmentLivenessEntry::new(30, 100, 900));

        assert_eq!(q.next_candidate(0.0), Some(30));
        assert_eq!(q.next_candidate(0.5), Some(30));
        assert_eq!(q.next_candidate(0.85), Some(30));
        assert_eq!(q.next_candidate(0.91), None); // above highest ratio
    }

    #[test]
    fn next_candidate_below_threshold_returns_none() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(
            1,
            SegmentLivenessEntry::new(1, 800, 200), // ratio 0.20
        );
        q.segments.insert(
            2,
            SegmentLivenessEntry::new(2, 900, 100), // ratio 0.10
        );
        assert_eq!(q.next_candidate(0.30), None);
        assert_eq!(q.next_candidate(0.10), Some(1));
    }

    #[test]
    fn next_candidate_skips_zero_dead_bytes() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(1, SegmentLivenessEntry::new(1, 0, 0));
        q.segments.insert(
            2,
            SegmentLivenessEntry::new(2, 100, 0), // ratio 0.0, dead=0
        );
        assert_eq!(q.next_candidate(0.0), None);
    }

    #[test]
    fn next_candidate_tiebreak_by_dead_then_lower_id() {
        let mut q = SegmentLivenessQueue::new();
        // Two segments with same dead ratio (0.50)
        q.segments
            .insert(50, SegmentLivenessEntry::new(50, 500, 500));
        q.segments
            .insert(10, SegmentLivenessEntry::new(10, 500, 500));
        // Same ratio, same dead bytes, lower id wins
        assert_eq!(q.next_candidate(0.0), Some(10));

        // Now make seg 50 have more dead bytes
        q.segments.insert(
            50,
            SegmentLivenessEntry::new(50, 500, 1000), // ratio 0.666, dead 1000
        );
        assert_eq!(q.next_candidate(0.0), Some(50));
    }

    // -- candidate_batch --

    #[test]
    fn candidate_batch_empty() {
        let q = SegmentLivenessQueue::new();
        assert!(q.candidate_batch(0.0, 5).is_empty());
    }

    #[test]
    fn candidate_batch_returns_sorted_candidates() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(1, SegmentLivenessEntry::new(1, 100, 900)); // ratio 0.90
        q.segments.insert(2, SegmentLivenessEntry::new(2, 800, 200)); // ratio 0.20
        q.segments.insert(3, SegmentLivenessEntry::new(3, 500, 500)); // ratio 0.50
        q.segments.insert(4, SegmentLivenessEntry::new(4, 200, 800)); // ratio 0.80
        q.segments.insert(5, SegmentLivenessEntry::new(5, 900, 100)); // ratio 0.10

        let batch = q.candidate_batch(0.0, 3);
        assert_eq!(batch, vec![1, 4, 3]); // sorted by ratio desc
    }

    #[test]
    fn candidate_batch_respects_threshold() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(1, SegmentLivenessEntry::new(1, 100, 900)); // 0.90
        q.segments.insert(2, SegmentLivenessEntry::new(2, 800, 200)); // 0.20
        q.segments.insert(3, SegmentLivenessEntry::new(3, 500, 500)); // 0.50

        let batch = q.candidate_batch(0.40, 5);
        assert_eq!(batch, vec![1, 3]);
    }

    #[test]
    fn candidate_batch_zero_limit() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(1, SegmentLivenessEntry::new(1, 100, 900));
        assert!(q.candidate_batch(0.0, 0).is_empty());
    }

    // -- commit_dead --

    #[test]
    fn commit_dead_removes_tracked_segment() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 4096);
        q.record_delete(1, 4096);
        assert_eq!(q.len(), 1);

        assert!(q.commit_dead(1));
        assert!(q.is_empty());
        assert!(!q.contains(1));
    }

    #[test]
    fn commit_dead_unknown_segment_returns_false() {
        let mut q = SegmentLivenessQueue::new();
        assert!(!q.commit_dead(99));
    }

    #[test]
    fn commit_dead_idempotent() {
        let mut q = SegmentLivenessQueue::new();
        q.record_delete(1, 100);
        assert!(q.commit_dead(1));
        assert!(!q.commit_dead(1));
        assert!(q.is_empty());
    }

    // -- clear --

    #[test]
    fn clear_empties_queue() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 100);
        q.record_write(2, 200);
        q.clear();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.total_live_bytes(), 0);
        assert_eq!(q.total_dead_bytes(), 0);
    }

    // -- Serialization round-trip --

    #[test]
    fn roundtrip_empty_queue() {
        let q = SegmentLivenessQueue::new();
        let bytes = q.to_bytes();
        let q2 = SegmentLivenessQueue::from_bytes(&bytes).unwrap();
        assert_eq!(q, q2);
        assert!(q2.is_empty());
    }

    #[test]
    fn roundtrip_single_entry() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(42, 4096);
        q.record_overwrite(42, 1024);

        let bytes = q.to_bytes();
        assert_eq!(bytes.len(), q.serialized_len());

        let q2 = SegmentLivenessQueue::from_bytes(&bytes).unwrap();
        assert_eq!(q, q2);
        assert_eq!(q2.get(42).unwrap().live_bytes, 3072);
        assert_eq!(q2.get(42).unwrap().dead_bytes, 1024);
    }

    #[test]
    fn roundtrip_many_entries() {
        let mut q = SegmentLivenessQueue::new();
        for seg in 1..129u64 {
            q.record_write(seg, seg * 100);
            if seg % 3 == 0 {
                q.record_overwrite(seg, seg * 30);
            }
            if seg % 5 == 0 {
                q.record_delete(seg, seg * 20);
            }
        }

        let bytes = q.to_bytes();
        let q2 = SegmentLivenessQueue::from_bytes(&bytes).unwrap();
        assert_eq!(q, q2);
        assert_eq!(q2.len(), 128);
    }

    #[test]
    fn roundtrip_max_value_entry() {
        let mut q = SegmentLivenessQueue::new();
        q.segments.insert(
            u64::MAX,
            SegmentLivenessEntry::new(u64::MAX, u64::MAX, u64::MAX),
        );

        let bytes = q.to_bytes();
        let q2 = SegmentLivenessQueue::from_bytes(&bytes).unwrap();
        assert_eq!(q, q2);
    }

    #[test]
    fn from_bytes_rejects_truncated_header() {
        let result = SegmentLivenessQueue::from_bytes(&[0; 8]);
        assert_eq!(result, Err(SegmentLivenessDeserializeError::Truncated));
    }

    #[test]
    fn from_bytes_rejects_invalid_magic() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(b"XXXX");
        let result = SegmentLivenessQueue::from_bytes(&data);
        assert_eq!(result, Err(SegmentLivenessDeserializeError::InvalidMagic));
    }

    #[test]
    fn from_bytes_rejects_unsupported_version() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(b"RCLQ");
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        let result = SegmentLivenessQueue::from_bytes(&data);
        assert_eq!(
            result,
            Err(SegmentLivenessDeserializeError::UnsupportedVersion {
                found: 99,
                expected: 2,
            })
        );
    }

    #[test]
    fn from_bytes_rejects_truncated_entries() {
        let mut data = vec![0u8; 12];
        data[0..4].copy_from_slice(b"RCLQ");
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // version 1
        data[8..12].copy_from_slice(&5u32.to_le_bytes()); // claims 5 entries, no data
        let result = SegmentLivenessQueue::from_bytes(&data);
        assert_eq!(result, Err(SegmentLivenessDeserializeError::Truncated));
    }

    // -- SegmentLivenessEntry helpers --

    #[test]
    fn entry_total_bytes() {
        let e = SegmentLivenessEntry::new(1, 3000, 1000);
        assert_eq!(e.total_bytes(), 4000);
    }

    #[test]
    fn entry_total_bytes_saturates() {
        let e = SegmentLivenessEntry::new(1, u64::MAX, 1);
        assert_eq!(e.total_bytes(), u64::MAX);
    }

    #[test]
    fn entry_dead_ratio() {
        let e = SegmentLivenessEntry::new(1, 300, 700);
        assert!((e.dead_ratio() - 0.70).abs() < 0.001);
    }

    #[test]
    fn entry_dead_ratio_when_empty() {
        let e = SegmentLivenessEntry::new(1, 0, 0);
        assert_eq!(e.dead_ratio(), 0.0);
    }

    #[test]
    fn entry_is_empty() {
        assert!(SegmentLivenessEntry::new(1, 0, 0).is_empty());
        assert!(!SegmentLivenessEntry::new(1, 1, 0).is_empty());
        assert!(!SegmentLivenessEntry::new(1, 0, 1).is_empty());
    }

    #[test]
    fn entry_is_fully_dead() {
        assert!(SegmentLivenessEntry::new(1, 0, 100).is_fully_dead());
        assert!(!SegmentLivenessEntry::new(1, 0, 0).is_fully_dead());
        assert!(!SegmentLivenessEntry::new(1, 1, 100).is_fully_dead());
    }

    #[test]
    fn entry_display() {
        let e = SegmentLivenessEntry::new(42, 500, 500);
        let s = alloc::format!("{e}");
        assert!(s.contains("segment=42"));
        assert!(s.contains("live=500"));
        assert!(s.contains("dead=500"));
        assert!(s.contains("0.5000"));
    }

    // -- Integration scenario: segment cleaner candidate pipeline --

    #[test]
    fn cleaner_pipeline_scenario() {
        let mut q = SegmentLivenessQueue::new();

        // Simulate writes allocating space across 10 segments
        for seg in 0..10u64 {
            q.record_write(seg, 100_000);
        }

        // Simulate overwrites and deletes creating dead space
        q.record_overwrite(0, 90_000); // seg 0: 90% dead
        q.record_overwrite(1, 70_000); // seg 1: 70% dead
        q.record_delete(2, 50_000); // seg 2: 50% dead
        q.record_overwrite(3, 30_000); // seg 3: 30% dead
        q.record_delete(4, 10_000); // seg 4: 10% dead
                                    // segs 5-9: no dead space

        // Candidate at 60% threshold
        let candidate = q.next_candidate(0.60);
        assert_eq!(candidate, Some(0)); // seg 0 has highest ratio

        // Batch at 25% threshold
        let batch = q.candidate_batch(0.25, 4);
        assert_eq!(batch, vec![0, 1, 2, 3]);

        // Reclaim seg 0
        assert!(q.commit_dead(0));
        assert!(!q.contains(0));
        assert_eq!(q.len(), 9);

        // Next candidate after reclamation
        let next = q.next_candidate(0.60);
        assert_eq!(next, Some(1)); // seg 1 now leads
    }

    #[test]
    fn fully_dead_segment_immediate_candidate() {
        let mut q = SegmentLivenessQueue::new();
        q.record_write(1, 4096);
        q.record_delete(1, 4096);
        assert!(q.get(1).unwrap().is_fully_dead());
        assert_eq!(q.next_candidate(0.99), Some(1));
    }

    // -- Serialized len consistency --

    #[test]
    fn serialized_len_matches_actual() {
        let mut q = SegmentLivenessQueue::new();
        assert_eq!(q.to_bytes().len(), q.serialized_len());

        q.record_write(1, 100);
        assert_eq!(q.to_bytes().len(), q.serialized_len());

        for seg in 0..50u64 {
            q.record_write(seg, seg * 100);
        }
        assert_eq!(q.to_bytes().len(), q.serialized_len());
    }
}
