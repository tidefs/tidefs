//! Segment builder for batching object writes into checksum-anchored segments.
//!
//! The [`SegmentBuilder`] accumulates pending writes until a configurable byte
//! threshold or an explicit flush signal, then finalizes the segment with a
//! BLAKE3-256 checksum tree over segment contents. The resulting
//! [`WriteSegment`] can be persisted atomically via the object store's
//! [`flush_segment`](crate::LocalObjectStore::flush_segment) method.
//!
//! # Design
//!
//! Writes are accumulated in insertion order. When the threshold is reached
//! or `finish()` is called, the builder computes a BLAKE3-256 digest over
//! all pending write records (key, offset, length, data) to form a checksum
//! anchor. The resulting [`WriteSegment`] is self-describing: it carries all
//! metadata needed for replay without external index state.
//!
//! Empty segments (zero writes) are rejected at finalization time to prevent
//! storing segments with no data.

use crate::constants::RECORD_OVERHEAD_BYTES;
use crate::{ObjectKey, ProductionIntegrityDigest, RecordKind, Result, StoreError};

// ---------------------------------------------------------------------------
// PendingWrite
// ---------------------------------------------------------------------------

/// A single pending object write accumulated by the [`SegmentBuilder`].
///
/// Each entry captures the object identity, the kind of record (Put or
/// Delete), and the write payload. The offset field allows partial-object
/// writes to carry byte-range information when the caller writes a
/// sub-range of an object; full-object writes set offset to 0 and length
/// to the payload length.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWrite {
    /// The object key this write targets.
    pub key: ObjectKey,

    /// Byte offset within the object (0 for full-object writes).
    pub offset: u64,

    /// Length of the data payload in bytes.
    pub length: u64,

    /// The write payload data.
    pub data: Vec<u8>,

    /// Whether this is a Put or Delete record.
    pub kind: RecordKind,
}

impl PendingWrite {
    /// Create a full-object put write at offset 0.
    pub fn put(key: ObjectKey, data: Vec<u8>) -> Self {
        let length = data.len() as u64;
        Self {
            key,
            offset: 0,
            length,
            data,
            kind: RecordKind::Put,
        }
    }

    /// Create a sub-range write at a specific offset.
    pub fn put_at(key: ObjectKey, offset: u64, data: Vec<u8>) -> Self {
        let length = data.len() as u64;
        Self {
            key,
            offset,
            length,
            data,
            kind: RecordKind::Put,
        }
    }

    /// Create a delete tombstone.
    pub fn delete(key: ObjectKey) -> Self {
        Self {
            key,
            offset: 0,
            length: 0,
            data: Vec::new(),
            kind: RecordKind::Delete,
        }
    }

    /// Total on-media bytes this write will consume including record overhead.
    pub fn record_bytes(&self) -> u64 {
        RECORD_OVERHEAD_BYTES + self.data.len() as u64
    }

    /// Computes a BLAKE3-256 digest of the write's identity and data.
    ///
    /// The hasher input is: key || kind || offset || length || data.
    /// This serves as the per-write component digest for the segment-level
    /// checksum anchor.
    pub fn write_digest(&self) -> ProductionIntegrityDigest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.key.as_bytes32());
        hasher.update(&self.kind.as_u16().to_le_bytes());
        hasher.update(&self.offset.to_le_bytes());
        hasher.update(&self.length.to_le_bytes());
        hasher.update(&self.data);
        ProductionIntegrityDigest::from_bytes32(*hasher.finalize().as_bytes())
    }
}

// ---------------------------------------------------------------------------
// WriteSegment
// ---------------------------------------------------------------------------

/// A finalized batch of pending writes with a BLAKE3-256 checksum anchor.
///
/// Once built by [`SegmentBuilder::finish`], a `WriteSegment` is ready to be
/// flushed to durable storage via the object store's flush path. The
/// `checksum` field covers all writes in order and can be verified on read
/// to detect storage-level corruption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteSegment {
    /// The ordered list of writes in this segment.
    pub writes: Vec<PendingWrite>,

    /// Total data bytes across all writes (excluding overhead).
    pub total_data_bytes: u64,

    /// Total on-media bytes including record overhead.
    pub total_media_bytes: u64,

    /// BLAKE3-256 checksum anchor over all writes in insertion order.
    ///
    /// Computed as `BLAKE3(write0_digest || write1_digest || ... || writeN_digest)`
    /// where each `write_digest` covers the write's identity and data.
    pub checksum: ProductionIntegrityDigest,

    /// Number of writes in this segment.
    pub write_count: usize,
}

impl WriteSegment {
    /// Returns true if the segment contains no writes.
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SegmentBuilder
// ---------------------------------------------------------------------------

/// Builds a [`WriteSegment`] by accumulating pending writes.
///
/// Writes are accumulated in insertion order. The builder tracks total
/// byte usage (including per-record overhead) and signals fullness when
/// the configurable threshold is reached. Callers can check `is_full()`
/// to drain intermediate segments, or call `finish()` to finalize the
/// current batch.
///
/// # Examples
///
/// ```rust
/// use tidefs_local_object_store::segment_builder::{PendingWrite, SegmentBuilder};
/// use tidefs_local_object_store::ObjectKey;
///
/// let mut builder = SegmentBuilder::new(1024);
/// let key = ObjectKey::from_name(b"example");
/// builder.push(PendingWrite::put(key, b"hello".to_vec())).unwrap();
/// let segment = builder.finish().unwrap();
/// assert_eq!(segment.write_count, 1);
/// ```
#[derive(Clone, Debug)]
pub struct SegmentBuilder {
    /// Maximum total on-media bytes before the segment is considered full.
    max_bytes: u64,

    /// Accumulated pending writes.
    pending: Vec<PendingWrite>,

    /// Running total of on-media bytes (data + overhead).
    total_media_bytes: u64,
}

impl SegmentBuilder {
    /// Create a new builder with the given maximum segment byte threshold.
    ///
    /// `max_bytes` must be at least `RECORD_OVERHEAD_BYTES`, otherwise no
    /// writes can ever be pushed.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            max_bytes,
            pending: Vec::new(),
            total_media_bytes: 0,
        }
    }

    /// Try to push a pending write into the builder.
    ///
    /// Returns `Ok(())` if the write fits within the remaining capacity.
    /// Returns `Err(StoreError::PayloadTooLarge)` if the write would exceed
    /// the segment's maximum byte size.
    ///
    /// When this returns `Err`, the write is not added, and the builder
    /// remains unchanged.
    pub fn push(&mut self, write: PendingWrite) -> Result<()> {
        let record_bytes = write.record_bytes();
        if self.total_media_bytes + record_bytes > self.max_bytes {
            return Err(StoreError::PayloadTooLarge {
                len: record_bytes,
                max: self.max_bytes - self.total_media_bytes,
            });
        }
        self.total_media_bytes += record_bytes;
        self.pending.push(write);
        Ok(())
    }

    /// Number of pending writes currently in the builder.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Returns true if no writes are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Current total on-media bytes across all pending writes.
    pub fn total_media_bytes(&self) -> u64 {
        self.total_media_bytes
    }

    /// Remaining capacity in on-media bytes before the threshold is reached.
    pub fn remaining_capacity(&self) -> u64 {
        self.max_bytes.saturating_sub(self.total_media_bytes)
    }

    /// Returns true when the next write is unlikely to fit (remaining
    /// capacity is below the minimum record overhead).
    pub fn is_full(&self) -> bool {
        self.remaining_capacity() < RECORD_OVERHEAD_BYTES
    }

    /// Drain all pending writes into a new `Vec`, resetting the builder.
    ///
    /// Use this when you want to flush intermediate segments without
    /// finalizing (checksum computation happens later via `finish`).
    pub fn drain(&mut self) -> Vec<PendingWrite> {
        self.total_media_bytes = 0;
        std::mem::take(&mut self.pending)
    }

    /// Clear all pending writes without returning them.
    pub fn clear(&mut self) {
        self.pending.clear();
        self.total_media_bytes = 0;
    }

    /// Finalize the current batch into a [`WriteSegment`].
    ///
    /// Computes the BLAKE3-256 checksum anchor over all pending writes
    /// and returns the sealed segment. Returns `Err(StoreError::InvalidOptions)`
    /// when the builder has no pending writes (empty segments are rejected).
    pub fn finish(&mut self) -> Result<WriteSegment> {
        if self.pending.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "cannot finish an empty segment; at least one write is required",
            });
        }

        let writes = std::mem::take(&mut self.pending);
        let total_data_bytes: u64 = writes.iter().map(|w| w.data.len() as u64).sum();
        let total_media_bytes = self.total_media_bytes;
        let write_count = writes.len();
        self.total_media_bytes = 0;

        let checksum = compute_segment_checksum(&writes);

        Ok(WriteSegment {
            writes,
            total_data_bytes,
            total_media_bytes,
            checksum,
            write_count,
        })
    }

    /// Build and return a [`WriteSegment`] without consuming the builder.
    ///
    /// This clones the pending writes and computes the checksum. The builder
    /// state is unchanged, so further writes can be added or `finish()` can
    /// be called later to consume.
    pub fn snapshot(&self) -> Result<WriteSegment> {
        if self.pending.is_empty() {
            return Err(StoreError::InvalidOptions {
                reason: "cannot snapshot an empty segment; at least one write is required",
            });
        }

        let total_data_bytes: u64 = self.pending.iter().map(|w| w.data.len() as u64).sum();
        let write_count = self.pending.len();
        let checksum = compute_segment_checksum(&self.pending);

        Ok(WriteSegment {
            writes: self.pending.clone(),
            total_data_bytes,
            total_media_bytes: self.total_media_bytes,
            checksum,
            write_count,
        })
    }
}

// ---------------------------------------------------------------------------
// FlushResult
// ---------------------------------------------------------------------------

/// Result of flushing a segment or object to durable storage.
///
/// Carries the stable locator information needed for crash recovery: which
/// segment the data landed in, the object keys flushed, and the checksum
/// anchor for integrity verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlushResult {
    /// The segment ID where the flushed data was persisted.
    pub segment_id: u64,

    /// Byte offset within the segment where the first record starts.
    pub record_offset: u64,

    /// Total on-media bytes written for this flush.
    pub bytes_written: u64,

    /// Number of individual object writes flushed.
    pub objects_flushed: usize,

    /// Object keys that were flushed in this operation.
    pub flushed_keys: Vec<ObjectKey>,

    /// BLAKE3-256 checksum anchor over all flushed writes.
    pub checksum: ProductionIntegrityDigest,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the BLAKE3-256 segment checksum over a sequence of pending writes.
///
/// Each write digest is concatenated into a single buffer, then hashed with a
/// domain-separated key derived from `DomainTag::WriteSegment` via
/// `ChecksumTreeBuilder` to produce the segment-level integrity anchor.
fn compute_segment_checksum(writes: &[PendingWrite]) -> ProductionIntegrityDigest {
    use tidefs_checksum_tree::{ChecksumTreeBuilder, DomainTag};
    let dk = DomainTag::WriteSegment.derive_key();
    let mut all_bytes = Vec::with_capacity(writes.len() * 32);
    for write in writes {
        all_bytes.extend_from_slice(&write.write_digest().as_bytes32());
    }
    let block_size = all_bytes.len().max(1);
    let mut builder = ChecksumTreeBuilder::new_with_domain(block_size, dk);
    builder.ingest(&all_bytes);
    let tree = builder.finish();
    ProductionIntegrityDigest::from_bytes32(tree.root_hash)
}

// ---------------------------------------------------------------------------
// Record overhead constant — imported from constants module at top
// ---------------------------------------------------------------------------

// RECORD_OVERHEAD_BYTES imported from constants.rs (computed from
// RECORD_HEADER_LEN + RECORD_FOOTER_LEN + INTEGRITY_TRAILER_V2_LEN).
// If this constant doesn't exist yet, we define it here.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordKind;

    // ------------------------------------------------------------------
    // PendingWrite tests
    // ------------------------------------------------------------------

    #[test]
    fn pending_write_put_sets_offset_zero() {
        let key = ObjectKey::from_name(b"test-obj");
        let pw = PendingWrite::put(key, b"data".to_vec());
        assert_eq!(pw.key, key);
        assert_eq!(pw.offset, 0);
        assert_eq!(pw.length, 4);
        assert_eq!(pw.data, b"data");
        assert_eq!(pw.kind, RecordKind::Put);
    }

    #[test]
    fn pending_write_put_at_respects_offset() {
        let key = ObjectKey::from_name(b"test-obj");
        let pw = PendingWrite::put_at(key, 4096, b"chunk".to_vec());
        assert_eq!(pw.offset, 4096);
        assert_eq!(pw.length, 5);
        assert_eq!(pw.data, b"chunk");
    }

    #[test]
    fn pending_write_delete_has_empty_data() {
        let key = ObjectKey::from_name(b"del-obj");
        let pw = PendingWrite::delete(key);
        assert_eq!(pw.kind, RecordKind::Delete);
        assert_eq!(pw.length, 0);
        assert!(pw.data.is_empty());
    }

    #[test]
    fn pending_write_record_bytes_includes_overhead() {
        let key = ObjectKey::from_name(b"obj");
        let pw = PendingWrite::put(key, vec![0u8; 100]);
        // RECORD_OVERHEAD_BYTES is defined in crate::constants
        assert_eq!(
            pw.record_bytes(),
            crate::constants::RECORD_OVERHEAD_BYTES + 100
        );
    }

    #[test]
    fn pending_write_digest_is_deterministic() {
        let key = ObjectKey::from_name(b"obj");
        let pw1 = PendingWrite::put(key, b"hello".to_vec());
        let pw2 = PendingWrite::put(key, b"hello".to_vec());
        assert_eq!(pw1.write_digest(), pw2.write_digest());
    }

    #[test]
    fn pending_write_digest_differs_on_different_data() {
        let key = ObjectKey::from_name(b"obj");
        let pw1 = PendingWrite::put(key, b"hello".to_vec());
        let pw2 = PendingWrite::put(key, b"world".to_vec());
        assert_ne!(pw1.write_digest(), pw2.write_digest());
    }

    #[test]
    fn pending_write_digest_differs_on_different_key() {
        let key1 = ObjectKey::from_name(b"obj-a");
        let key2 = ObjectKey::from_name(b"obj-b");
        let pw1 = PendingWrite::put(key1, b"data".to_vec());
        let pw2 = PendingWrite::put(key2, b"data".to_vec());
        assert_ne!(pw1.write_digest(), pw2.write_digest());
    }

    #[test]
    fn pending_write_digest_differs_on_different_kind() {
        let key = ObjectKey::from_name(b"obj");
        let pw1 = PendingWrite::put(key, b"data".to_vec());
        let pw2 = PendingWrite::delete(key);
        assert_ne!(pw1.write_digest(), pw2.write_digest());
    }

    #[test]
    fn pending_write_digest_differs_on_different_offset() {
        let key = ObjectKey::from_name(b"obj");
        let pw1 = PendingWrite::put_at(key, 0, b"data".to_vec());
        let pw2 = PendingWrite::put_at(key, 8, b"data".to_vec());
        assert_ne!(pw1.write_digest(), pw2.write_digest());
    }

    // ------------------------------------------------------------------
    // SegmentBuilder tests
    // ------------------------------------------------------------------

    #[test]
    fn builder_new_is_empty() {
        let builder = SegmentBuilder::new(1024);
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
        assert_eq!(builder.total_media_bytes(), 0);
        assert!(!builder.is_full());
    }

    #[test]
    fn builder_push_increases_count() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, b"hello".to_vec()))
            .unwrap();
        assert_eq!(builder.len(), 1);
        assert!(!builder.is_empty());
    }

    #[test]
    fn builder_push_tracks_media_bytes() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        let pw = PendingWrite::put(key, vec![0u8; 100]);
        let expected_bytes = pw.record_bytes();
        builder.push(pw).unwrap();
        assert_eq!(builder.total_media_bytes(), expected_bytes);
    }

    #[test]
    fn builder_rejects_write_exceeding_max_bytes() {
        let overhead = crate::constants::RECORD_OVERHEAD_BYTES;
        // Set max just enough for exactly one empty write to barely not fit
        let mut builder = SegmentBuilder::new(overhead - 1);
        let key = ObjectKey::from_name(b"obj");
        let result = builder.push(PendingWrite::put(key, vec![0u8; 1]));
        assert!(result.is_err());
        assert!(builder.is_empty());
    }

    #[test]
    fn builder_is_full_when_remaining_below_overhead() {
        let overhead = crate::constants::RECORD_OVERHEAD_BYTES;
        let mut builder = SegmentBuilder::new(overhead + 10);
        let key = ObjectKey::from_name(b"obj");
        // Push a write that fills up to leave less than overhead remaining
        builder.push(PendingWrite::put(key, vec![0u8; 10])).unwrap();
        assert!(builder.is_full());
    }

    #[test]
    fn builder_remaining_capacity_decreases() {
        let mut builder = SegmentBuilder::new(1024);
        let cap_before = builder.remaining_capacity();
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, b"data".to_vec()))
            .unwrap();
        assert!(builder.remaining_capacity() < cap_before);
    }

    #[test]
    fn builder_drain_empties_and_returns_writes() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        builder.push(PendingWrite::put(key, b"a".to_vec())).unwrap();
        let drained = builder.drain();
        assert_eq!(drained.len(), 1);
        assert!(builder.is_empty());
        assert_eq!(builder.total_media_bytes(), 0);
    }

    #[test]
    fn builder_clear_empties_without_return() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, b"data".to_vec()))
            .unwrap();
        builder.clear();
        assert!(builder.is_empty());
        assert_eq!(builder.len(), 0);
    }

    #[test]
    fn builder_finish_produces_write_segment() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, b"hello".to_vec()))
            .unwrap();
        let segment = builder.finish().unwrap();
        assert_eq!(segment.write_count, 1);
        assert_eq!(segment.writes.len(), 1);
        assert_eq!(segment.total_data_bytes, 5);
        assert!(!segment.is_empty());
    }

    #[test]
    fn builder_finish_rejects_empty() {
        let mut builder = SegmentBuilder::new(1024);
        let result = builder.finish();
        assert!(result.is_err());
    }

    #[test]
    fn builder_snapshot_preserves_state() {
        let mut builder = SegmentBuilder::new(1024);
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, b"hello".to_vec()))
            .unwrap();
        let snap = builder.snapshot().unwrap();
        assert_eq!(snap.write_count, 1);
        // Builder still has the write
        assert_eq!(builder.len(), 1);
    }

    #[test]
    fn builder_snapshot_rejects_empty() {
        let builder = SegmentBuilder::new(1024);
        let result = builder.snapshot();
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // WriteSegment tests
    // ------------------------------------------------------------------

    #[test]
    fn write_segment_is_empty_returns_true_for_no_writes() {
        let segment = WriteSegment {
            writes: vec![],
            total_data_bytes: 0,
            total_media_bytes: 0,
            checksum: ProductionIntegrityDigest::ZERO,
            write_count: 0,
        };
        assert!(segment.is_empty());
    }

    #[test]
    fn write_segment_checksum_is_deterministic() {
        let key = ObjectKey::from_name(b"obj");
        let mut b1 = SegmentBuilder::new(1024);
        b1.push(PendingWrite::put(key, b"data".to_vec())).unwrap();
        let s1 = b1.finish().unwrap();

        let mut b2 = SegmentBuilder::new(1024);
        b2.push(PendingWrite::put(key, b"data".to_vec())).unwrap();
        let s2 = b2.finish().unwrap();

        assert_eq!(s1.checksum, s2.checksum);
    }

    #[test]
    fn write_segment_checksum_differs_on_order_change() {
        let key1 = ObjectKey::from_name(b"a");
        let key2 = ObjectKey::from_name(b"b");

        let mut b1 = SegmentBuilder::new(1024);
        b1.push(PendingWrite::put(key1, b"1".to_vec())).unwrap();
        b1.push(PendingWrite::put(key2, b"2".to_vec())).unwrap();
        let s1 = b1.finish().unwrap();

        let mut b2 = SegmentBuilder::new(1024);
        b2.push(PendingWrite::put(key2, b"2".to_vec())).unwrap();
        b2.push(PendingWrite::put(key1, b"1".to_vec())).unwrap();
        let s2 = b2.finish().unwrap();

        assert_ne!(s1.checksum, s2.checksum);
    }

    // ------------------------------------------------------------------
    // Multi-write accumulation tests
    // ------------------------------------------------------------------

    #[test]
    fn builder_accumulates_multiple_writes() {
        let mut builder = SegmentBuilder::new(4096);
        for i in 0..10u8 {
            let key = ObjectKey::from_name([i; 1]);
            builder.push(PendingWrite::put(key, vec![i; 10])).unwrap();
        }
        assert_eq!(builder.len(), 10);
        let segment = builder.finish().unwrap();
        assert_eq!(segment.write_count, 10);
    }

    #[test]
    fn builder_total_media_bytes_exceeds_data_bytes() {
        let mut builder = SegmentBuilder::new(4096);
        let key = ObjectKey::from_name(b"obj");
        builder
            .push(PendingWrite::put(key, vec![0u8; 100]))
            .unwrap();
        let segment = builder.finish().unwrap();
        // total_media_bytes includes overhead, total_data_bytes does not
        assert!(segment.total_media_bytes > segment.total_data_bytes);
    }

    // ------------------------------------------------------------------
    // FlushResult tests
    // ------------------------------------------------------------------

    #[test]
    fn flush_result_construction() {
        let key = ObjectKey::from_name(b"obj");
        let result = FlushResult {
            segment_id: 7,
            record_offset: 0,
            bytes_written: 150,
            objects_flushed: 1,
            flushed_keys: vec![key],
            checksum: ProductionIntegrityDigest::ZERO,
        };
        assert_eq!(result.segment_id, 7);
        assert_eq!(result.objects_flushed, 1);
        assert_eq!(result.flushed_keys.len(), 1);
    }
}
