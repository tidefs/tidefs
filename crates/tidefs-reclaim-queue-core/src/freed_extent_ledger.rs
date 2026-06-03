//! Persistent freed-extent reclaim-queue ledger.
//!
//! Tracks extents freed during object deletion and truncation so the space
//! allocator can reuse them.  Each [`FreedExtent`] records the device,
//! physical offset, length, a BLAKE3 content hash, and the transaction group
//! at which the free became durable.
//!
//! [`ReclaimQueueLedger`] provides FIFO enqueue/dequeue with binary
//! encode/decode and crash-safe replay via BLAKE3 domain-separated integrity.
//!
//! # Integration
//!
//! - **Object store** enqueues freed extents after commit_group commit.
//! - **Space allocator** dequeues batches for reuse before allocating from
//!   the spacemap.
//! - **Pool import** calls [`ReclaimQueueLedger::replay`] to reconstruct the
//!   ledger from persistent storage.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};

// ---------------------------------------------------------------------------
// FreedExtent
// ---------------------------------------------------------------------------

/// A device-relative freed extent recorded in the reclaim-queue ledger.
///
/// When an object is deleted or truncated, each freed physical extent is
/// enqueued so the space allocator can later reclaim it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreedExtent {
    /// Device identifier for the freed extent.
    pub device_id: u64,
    /// Physical byte offset on the device.
    pub physical_offset: u64,
    /// Length of the freed extent in bytes.
    pub length: u64,
    /// BLAKE3 hash of the data that was stored in this extent (for
    /// verification before reuse).
    pub blake3_hash: [u8; 32],
    /// Transaction group at which this free became durable.
    pub freed_at_txg: u64,
}

impl FreedExtent {
    /// Serialized size in bytes: 8 (device_id) + 8 (physical_offset)
    /// + 8 (length) + 32 (blake3_hash) + 8 (freed_at_txg).
    pub const ENCODED_SIZE: usize = 64;

    /// Create a new freed extent.
    #[must_use]
    pub const fn new(
        device_id: u64,
        physical_offset: u64,
        length: u64,
        blake3_hash: [u8; 32],
        freed_at_txg: u64,
    ) -> Self {
        Self {
            device_id,
            physical_offset,
            length,
            blake3_hash,
            freed_at_txg,
        }
    }

    /// Encode this freed extent into a fixed-size byte array.
    ///
    /// Format (little-endian):
    /// -  8 bytes: device_id (u64)
    /// -  8 bytes: physical_offset (u64)
    /// -  8 bytes: length (u64)
    /// - 32 bytes: blake3_hash
    /// -  8 bytes: freed_at_txg (u64)
    #[must_use]
    pub fn encode(self) -> [u8; Self::ENCODED_SIZE] {
        let mut buf = [0u8; Self::ENCODED_SIZE];
        buf[0..8].copy_from_slice(&self.device_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.physical_offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.length.to_le_bytes());
        buf[24..56].copy_from_slice(&self.blake3_hash);
        buf[56..64].copy_from_slice(&self.freed_at_txg.to_le_bytes());
        buf
    }

    /// Decode a freed extent from a fixed-size byte slice.
    #[must_use]
    pub fn decode(buf: &[u8; Self::ENCODED_SIZE]) -> Self {
        let device_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let physical_offset = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let length = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let mut blake3_hash = [0u8; 32];
        blake3_hash.copy_from_slice(&buf[24..56]);
        let freed_at_txg = u64::from_le_bytes(buf[56..64].try_into().unwrap());
        Self {
            device_id,
            physical_offset,
            length,
            blake3_hash,
            freed_at_txg,
        }
    }

    /// Total bytes represented by this freed extent.
    #[must_use]
    pub const fn total_bytes(self) -> u64 {
        self.length
    }
}

impl fmt::Display for FreedExtent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FreedExtent(dev={} off={} len={} txg={})",
            self.device_id, self.physical_offset, self.length, self.freed_at_txg
        )
    }
}

// ---------------------------------------------------------------------------
// PersistenceMode
// ---------------------------------------------------------------------------

/// Controls when the reclaim-queue ledger is persisted to storage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PersistenceMode {
    /// Persist after every enqueue (most durable, highest I/O overhead).
    EveryEnqueue,
    /// Persist after every batch dequeue (balanced).
    #[default]
    Batch,
    /// Caller is responsible for calling `encode` and persisting manually.
    Manual,
}

// ---------------------------------------------------------------------------
// ReclaimQueueLedgerConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`ReclaimQueueLedger`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimQueueLedgerConfig {
    /// Maximum number of extents returned by a single `dequeue_batch` call.
    pub batch_size: usize,
    /// When the ledger is persisted to storage.
    pub persistence_mode: PersistenceMode,
}

impl Default for ReclaimQueueLedgerConfig {
    fn default() -> Self {
        Self {
            batch_size: 64,
            persistence_mode: PersistenceMode::default(),
        }
    }
}

impl ReclaimQueueLedgerConfig {
    /// Create a new config with defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            batch_size: 64,
            persistence_mode: PersistenceMode::Batch,
        }
    }

    /// Builder: set `batch_size`.
    #[must_use]
    pub const fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Builder: set `persistence_mode`.
    #[must_use]
    pub const fn with_persistence_mode(mut self, mode: PersistenceMode) -> Self {
        self.persistence_mode = mode;
        self
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueLedger
// ---------------------------------------------------------------------------

/// Persistent FIFO queue of freed extents for the space allocator.
///
/// Extents are enqueued when freed by object deletion or truncation and
/// dequeued by the space allocator for reuse.  The ledger supports
/// binary encode/decode with BLAKE3 domain-separated integrity so it
/// survives crashes and pool imports.
///
/// # Crash safety
///
/// On pool import, call [`ReclaimQueueLedger::replay`] with the bytes
/// previously produced by [`ReclaimQueueLedger::encode`].  Enqueue is
/// always safe to call after replay -- it just appends.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReclaimQueueLedger {
    entries: VecDeque<FreedExtent>,
    config: ReclaimQueueLedgerConfig,
}

impl ReclaimQueueLedger {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create an empty reclaim-queue ledger with the given config.
    #[must_use]
    pub fn new(config: ReclaimQueueLedgerConfig) -> Self {
        Self {
            entries: VecDeque::new(),
            config,
        }
    }

    /// Create a ledger with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ReclaimQueueLedgerConfig::default())
    }

    // ------------------------------------------------------------------
    // Queue operations
    // ------------------------------------------------------------------

    /// Push a freed extent onto the back of the queue.
    ///
    /// Returns the new queue length.
    pub fn enqueue(&mut self, extent: FreedExtent) -> usize {
        self.entries.push_back(extent);
        self.entries.len()
    }

    /// Pop up to `max_count` freed extents from the front of the queue
    /// in FIFO order.
    ///
    /// If `max_count` is larger than `self.len()`, all entries are
    /// returned.
    pub fn dequeue_batch(&mut self, max_count: usize) -> Vec<FreedExtent> {
        if max_count == 0 || self.is_empty() {
            return Vec::new();
        }
        let count = max_count.min(self.entries.len());
        self.entries.drain(..count).collect()
    }

    /// Peek at up to `max_count` extents from the front without removing
    /// them.  Useful for planning before committing a dequeue.
    #[must_use]
    pub fn peek_batch(&self, max_count: usize) -> Vec<FreedExtent> {
        if max_count == 0 || self.is_empty() {
            return Vec::new();
        }
        let count = max_count.min(self.entries.len());
        self.entries.iter().take(count).copied().collect()
    }

    /// Number of freed extents currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sum of `length` across all queued extents -- the total bytes
    /// available for reclamation.
    #[must_use]
    pub fn total_freed_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.length).sum()
    }

    /// Remove all entries from the queue.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return a reference to the config.
    #[must_use]
    pub const fn config(&self) -> &ReclaimQueueLedgerConfig {
        &self.config
    }

    /// Iterate over all entries in FIFO order.
    pub fn iter(&self) -> impl Iterator<Item = &FreedExtent> {
        self.entries.iter()
    }

    // ------------------------------------------------------------------
    // Binary encoding / decoding
    // ------------------------------------------------------------------

    /// Magic bytes identifying a freed-extent reclaim-queue ledger payload.
    const MAGIC: &'static [u8; 4] = b"FRLG";

    /// Current binary format version.
    const FORMAT_VERSION: u32 = 1;

    /// Schema family identifier for reclaim-queue-ledger BLAKE3 domain context.
    const FAMILY_ID: SchemaFamilyId = SchemaFamilyId(0x4652_4C47_0000_0001);

    /// Schema type identifier for reclaim-queue-ledger format v1.
    const TYPE_ID: SchemaTypeId = SchemaTypeId(1);

    /// Schema version for reclaim-queue-ledger format v1.0.
    const VERSION: SchemaVersion = SchemaVersion::new(1, 0);

    /// Domain tag for reclaim-queue-ledger payload integrity.
    const DOMAIN_TAG: DomainTag = DomainTag::SectionBody;

    /// Encode the entire ledger to a byte vector with a BLAKE3 integrity
    /// footer.
    ///
    /// Format (little-endian):
    /// - 4 bytes: magic `FRLG`
    /// - 4 bytes: format version (u32)
    /// - 4 bytes: entry count (u32)
    /// - N * 64 bytes: per-entry encoded records
    /// - 32 bytes: BLAKE3 domain-separated digest over all preceding bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = self.entries.len() as u32;

        let body_len = 12usize
            .checked_add(count as usize * FreedExtent::ENCODED_SIZE)
            .expect("reclaim-queue ledger too large to encode");
        let mut buf = Vec::with_capacity(body_len + 32);

        // Header
        buf.extend_from_slice(Self::MAGIC);
        buf.extend_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&count.to_le_bytes());

        // Entries
        for entry in &self.entries {
            buf.extend_from_slice(&entry.encode());
        }

        // BLAKE3 integrity footer over all preceding bytes
        let digest = blake3_domain_digest(
            &buf,
            Self::FAMILY_ID,
            Self::TYPE_ID,
            Self::VERSION,
            Self::DOMAIN_TAG,
        );
        buf.extend_from_slice(&digest);

        buf
    }

    /// Decode a ledger from bytes previously produced by [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimQueueLedgerDecodeError`] if the buffer is
    /// truncated, has an invalid magic, an unsupported version, a
    /// corrupt entry, or a BLAKE3 integrity footer mismatch.
    pub fn decode(
        data: &[u8],
        config: ReclaimQueueLedgerConfig,
    ) -> Result<Self, ReclaimQueueLedgerDecodeError> {
        // Minimum size: header (12) + footer (32) = 44 bytes
        if data.len() < 44 {
            return Err(ReclaimQueueLedgerDecodeError::Truncated);
        }

        // Verify magic
        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(ReclaimQueueLedgerDecodeError::InvalidMagic);
        }

        // Verify version
        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if version != Self::FORMAT_VERSION {
            return Err(ReclaimQueueLedgerDecodeError::UnsupportedVersion {
                found: version,
                expected: Self::FORMAT_VERSION,
            });
        }

        // Verify BLAKE3 integrity footer
        let body_len = data.len() - 32;
        let expected_digest = blake3_domain_digest(
            &data[..body_len],
            Self::FAMILY_ID,
            Self::TYPE_ID,
            Self::VERSION,
            Self::DOMAIN_TAG,
        );
        let actual_digest: [u8; 32] = data[body_len..].try_into().unwrap();
        if expected_digest != actual_digest {
            return Err(ReclaimQueueLedgerDecodeError::IntegrityFooterMismatch);
        }

        // Parse entry count
        let count = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let expected_body_len = 12usize
            .checked_add(
                count
                    .checked_mul(FreedExtent::ENCODED_SIZE)
                    .ok_or(ReclaimQueueLedgerDecodeError::Truncated)?,
            )
            .ok_or(ReclaimQueueLedgerDecodeError::Truncated)?;

        if body_len < expected_body_len {
            return Err(ReclaimQueueLedgerDecodeError::Truncated);
        }

        // Parse entries
        let mut entries = VecDeque::with_capacity(count);
        for i in 0..count {
            let offset = 12 + i * FreedExtent::ENCODED_SIZE;
            let entry_bytes: &[u8; FreedExtent::ENCODED_SIZE] = data
                [offset..offset + FreedExtent::ENCODED_SIZE]
                .try_into()
                .map_err(|_| ReclaimQueueLedgerDecodeError::Truncated)?;
            let entry = FreedExtent::decode(entry_bytes);
            entries.push_back(entry);
        }

        Ok(Self { entries, config })
    }

    /// Reconstruct the ledger from persisted bytes (crash-safe replay).
    ///
    /// This is the primary recovery entrypoint.  On pool import, read
    /// the ledger segment, pass the bytes to `replay`, and the returned
    /// ledger is ready for enqueue/dequeue.  Uses default config.
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimQueueLedgerDecodeError`] on any decode failure.
    pub fn replay(data: &[u8]) -> Result<Self, ReclaimQueueLedgerDecodeError> {
        Self::decode(data, ReclaimQueueLedgerConfig::default())
    }

    /// Estimate the serialized byte size without allocating.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        12 + self.entries.len() * FreedExtent::ENCODED_SIZE + 32
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueueLedgerDecodeError
// ---------------------------------------------------------------------------

/// Errors that can occur when decoding a [`ReclaimQueueLedger`] from
/// its wire-format encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReclaimQueueLedgerDecodeError {
    /// Data is shorter than the minimum header + footer.
    Truncated,
    /// Magic bytes do not match the expected `FRLG`.
    InvalidMagic,
    /// Format version is not supported.
    UnsupportedVersion { found: u32, expected: u32 },
    /// The BLAKE3 integrity footer did not verify.
    IntegrityFooterMismatch,
}

impl fmt::Display for ReclaimQueueLedgerDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated reclaim-queue ledger data"),
            Self::InvalidMagic => f.write_str("invalid reclaim-queue ledger magic bytes"),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported reclaim-queue ledger version: found {found}, expected {expected}"
            ),
            Self::IntegrityFooterMismatch => {
                f.write_str("reclaim-queue ledger BLAKE3 integrity footer mismatch")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test FreedExtent with sequential fields for easy debugging.
    fn fe(seed: u8) -> FreedExtent {
        let mut hash = [0u8; 32];
        hash[0] = seed;
        FreedExtent::new(
            seed as u64,
            (seed as u64) * 4096,
            (seed as u64) * 1024,
            hash,
            (seed as u64) * 100,
        )
    }

    // -- FreedExtent encode/decode --

    #[test]
    fn freed_extent_encode_decode_roundtrip() {
        let e = fe(42);
        let encoded = e.encode();
        let decoded = FreedExtent::decode(&encoded);
        assert_eq!(decoded, e);
    }

    #[test]
    fn freed_extent_encode_decode_zero_values() {
        let e = FreedExtent::new(0, 0, 0, [0u8; 32], 0);
        let encoded = e.encode();
        let decoded = FreedExtent::decode(&encoded);
        assert_eq!(decoded, e);
    }

    #[test]
    fn freed_extent_encode_decode_max_values() {
        let e = FreedExtent::new(u64::MAX, u64::MAX, u64::MAX, [0xFFu8; 32], u64::MAX);
        let encoded = e.encode();
        let decoded = FreedExtent::decode(&encoded);
        assert_eq!(decoded, e);
    }

    #[test]
    fn freed_extent_encoded_size() {
        assert_eq!(FreedExtent::ENCODED_SIZE, 64);
        let e = fe(1);
        assert_eq!(e.encode().len(), 64);
    }

    #[test]
    fn freed_extent_total_bytes() {
        let e = fe(5);
        assert_eq!(e.total_bytes(), 5 * 1024);
    }

    #[test]
    fn freed_extent_display() {
        let e = fe(7);
        let s = format!("{e}");
        assert!(s.contains("FreedExtent"));
        assert!(s.contains("dev=7"));
        assert!(s.contains("len=7168"));
    }

    // -- ReclaimQueueLedgerConfig --

    #[test]
    fn config_defaults() {
        let cfg = ReclaimQueueLedgerConfig::default();
        assert_eq!(cfg.batch_size, 64);
        assert_eq!(cfg.persistence_mode, PersistenceMode::Batch);
    }

    #[test]
    fn config_builder() {
        let cfg = ReclaimQueueLedgerConfig::new()
            .with_batch_size(128)
            .with_persistence_mode(PersistenceMode::EveryEnqueue);
        assert_eq!(cfg.batch_size, 128);
        assert_eq!(cfg.persistence_mode, PersistenceMode::EveryEnqueue);
    }

    #[test]
    fn persistence_mode_default_is_batch() {
        assert_eq!(PersistenceMode::default(), PersistenceMode::Batch);
    }

    // -- ReclaimQueueLedger basic operations --

    #[test]
    fn ledger_new_is_empty() {
        let l = ReclaimQueueLedger::with_defaults();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert_eq!(l.total_freed_bytes(), 0);
    }

    #[test]
    fn enqueue_single() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        assert_eq!(l.len(), 1);
        assert!(!l.is_empty());
        assert_eq!(l.total_freed_bytes(), 1024);
    }

    #[test]
    fn enqueue_multiple() {
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 1..=10u8 {
            l.enqueue(fe(i));
        }
        assert_eq!(l.len(), 10);
        assert_eq!(
            l.total_freed_bytes(),
            (1..=10u64).map(|i| i * 1024).sum::<u64>()
        );
    }

    #[test]
    fn dequeue_batch_fifo_order() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        l.enqueue(fe(3));

        let batch = l.dequeue_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].device_id, 1);
        assert_eq!(batch[1].device_id, 2);

        assert_eq!(l.len(), 1);
        let batch2 = l.dequeue_batch(10);
        assert_eq!(batch2.len(), 1);
        assert_eq!(batch2[0].device_id, 3);
        assert!(l.is_empty());
    }

    #[test]
    fn dequeue_batch_more_than_available() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        let batch = l.dequeue_batch(100);
        assert_eq!(batch.len(), 2);
        assert!(l.is_empty());
    }

    #[test]
    fn dequeue_batch_empty_queue() {
        let mut l = ReclaimQueueLedger::with_defaults();
        assert!(l.dequeue_batch(10).is_empty());
    }

    #[test]
    fn dequeue_batch_zero_max() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        assert!(l.dequeue_batch(0).is_empty());
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn peek_batch_does_not_remove() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        l.enqueue(fe(3));

        let peeked = l.peek_batch(2);
        assert_eq!(peeked.len(), 2);
        assert_eq!(peeked[0].device_id, 1);
        assert_eq!(l.len(), 3);

        let batch = l.dequeue_batch(3);
        assert_eq!(batch.len(), 3);
    }

    #[test]
    fn peek_batch_empty() {
        let l = ReclaimQueueLedger::with_defaults();
        assert!(l.peek_batch(10).is_empty());
    }

    #[test]
    fn clear_empties() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        l.clear();
        assert!(l.is_empty());
        assert_eq!(l.total_freed_bytes(), 0);
    }

    #[test]
    fn iter_yields_fifo_order() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(3));
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        let ids: Vec<u64> = l.iter().map(|e| e.device_id).collect();
        assert_eq!(ids, [3, 1, 2]);
    }

    #[test]
    fn config_accessor() {
        let cfg = ReclaimQueueLedgerConfig::new().with_batch_size(32);
        let l = ReclaimQueueLedger::new(cfg);
        assert_eq!(l.config().batch_size, 32);
    }

    // -- Binary encode/decode round-trip --

    #[test]
    fn encode_decode_empty_ledger() {
        let l = ReclaimQueueLedger::with_defaults();
        let bytes = l.encode();
        assert_eq!(bytes.len(), 44);
        let decoded =
            ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default()).unwrap();
        assert_eq!(decoded, l);
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_single_entry() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(42));
        let bytes = l.encode();
        let decoded =
            ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default()).unwrap();
        assert_eq!(decoded, l);
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn encode_decode_many_entries() {
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 0..100u8 {
            l.enqueue(fe(i));
        }
        let bytes = l.encode();
        let decoded =
            ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default()).unwrap();
        assert_eq!(decoded, l);
        assert_eq!(decoded.len(), 100);
    }

    #[test]
    fn encode_decode_preserves_fifo_order() {
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in [77, 3, 42, 100, 1] {
            l.enqueue(fe(i));
        }
        let bytes = l.encode();
        let decoded =
            ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default()).unwrap();
        let original_ids: Vec<u64> = l.iter().map(|e| e.device_id).collect();
        let decoded_ids: Vec<u64> = decoded.iter().map(|e| e.device_id).collect();
        assert_eq!(original_ids, decoded_ids);
    }

    #[test]
    fn encode_decode_preserves_config() {
        let cfg = ReclaimQueueLedgerConfig::new().with_batch_size(128);
        let mut l = ReclaimQueueLedger::new(cfg);
        l.enqueue(fe(1));
        let bytes = l.encode();
        let decoded = ReclaimQueueLedger::decode(&bytes, cfg).unwrap();
        assert_eq!(decoded.config().batch_size, 128);
    }

    #[test]
    fn encoded_len_matches_actual() {
        let l = ReclaimQueueLedger::with_defaults();
        assert_eq!(l.encode().len(), l.encoded_len());

        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        assert_eq!(l.encode().len(), l.encoded_len());

        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 0..50u8 {
            l.enqueue(fe(i));
        }
        assert_eq!(l.encode().len(), l.encoded_len());
    }

    #[test]
    fn encoded_len_formula() {
        let n = 10;
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 0..n {
            l.enqueue(fe(i as u8));
        }
        assert_eq!(l.encoded_len(), 12 + n * 64 + 32);
    }

    // -- Replay (crash recovery) --

    #[test]
    fn replay_restores_full_queue() {
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 0..200u8 {
            l.enqueue(fe(i));
        }
        let bytes = l.encode();
        let recovered = ReclaimQueueLedger::replay(&bytes).unwrap();
        assert_eq!(recovered, l);
        assert_eq!(recovered.len(), 200);
    }

    #[test]
    fn replay_then_enqueue_is_safe() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        let bytes = l.encode();

        let mut recovered = ReclaimQueueLedger::replay(&bytes).unwrap();
        recovered.enqueue(fe(3));
        assert_eq!(recovered.len(), 3);

        let batch = recovered.dequeue_batch(3);
        let ids: Vec<u64> = batch.iter().map(|e| e.device_id).collect();
        assert_eq!(ids, [1, 2, 3]);
    }

    #[test]
    fn replay_empty_ledger() {
        let l = ReclaimQueueLedger::with_defaults();
        let bytes = l.encode();
        let recovered = ReclaimQueueLedger::replay(&bytes).unwrap();
        assert!(recovered.is_empty());
    }

    // -- Decode error conditions --

    #[test]
    fn decode_rejects_truncated() {
        let result = ReclaimQueueLedger::decode(&[0u8; 8], ReclaimQueueLedgerConfig::default());
        assert_eq!(result, Err(ReclaimQueueLedgerDecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_truncated_at_43_bytes() {
        let result = ReclaimQueueLedger::decode(&[0u8; 43], ReclaimQueueLedgerConfig::default());
        assert_eq!(result, Err(ReclaimQueueLedgerDecodeError::Truncated));
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let mut data = vec![0u8; 44];
        data[0..4].copy_from_slice(b"XXXX");
        let body = &data[..12];
        let digest = blake3_domain_digest(
            body,
            ReclaimQueueLedger::FAMILY_ID,
            ReclaimQueueLedger::TYPE_ID,
            ReclaimQueueLedger::VERSION,
            ReclaimQueueLedger::DOMAIN_TAG,
        );
        data[12..44].copy_from_slice(&digest);
        let result = ReclaimQueueLedger::decode(&data, ReclaimQueueLedgerConfig::default());
        assert_eq!(result, Err(ReclaimQueueLedgerDecodeError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"FRLG");
        header[4..8].copy_from_slice(&99u32.to_le_bytes());
        header[8..12].copy_from_slice(&0u32.to_le_bytes());
        let digest = blake3_domain_digest(
            &header,
            ReclaimQueueLedger::FAMILY_ID,
            ReclaimQueueLedger::TYPE_ID,
            ReclaimQueueLedger::VERSION,
            ReclaimQueueLedger::DOMAIN_TAG,
        );
        let mut data = header;
        data.extend_from_slice(&digest);
        let result = ReclaimQueueLedger::decode(&data, ReclaimQueueLedgerConfig::default());
        assert_eq!(
            result,
            Err(ReclaimQueueLedgerDecodeError::UnsupportedVersion {
                found: 99,
                expected: 1,
            })
        );
    }

    #[test]
    fn decode_rejects_corrupted_footer() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(1));
        let mut bytes = l.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let result = ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default());
        assert_eq!(
            result,
            Err(ReclaimQueueLedgerDecodeError::IntegrityFooterMismatch)
        );
    }

    #[test]
    fn decode_rejects_truncated_entries() {
        let mut header = vec![0u8; 12];
        header[0..4].copy_from_slice(b"FRLG");
        header[4..8].copy_from_slice(&1u32.to_le_bytes());
        header[8..12].copy_from_slice(&5u32.to_le_bytes());
        let mut data = header;
        data.extend_from_slice(&[0u8; 10]);
        let digest = blake3_domain_digest(
            &data,
            ReclaimQueueLedger::FAMILY_ID,
            ReclaimQueueLedger::TYPE_ID,
            ReclaimQueueLedger::VERSION,
            ReclaimQueueLedger::DOMAIN_TAG,
        );
        data.extend_from_slice(&digest);
        let result = ReclaimQueueLedger::decode(&data, ReclaimQueueLedgerConfig::default());
        assert_eq!(result, Err(ReclaimQueueLedgerDecodeError::Truncated));
    }

    #[test]
    fn decode_errors_display_non_empty() {
        let variants = [
            ReclaimQueueLedgerDecodeError::Truncated,
            ReclaimQueueLedgerDecodeError::InvalidMagic,
            ReclaimQueueLedgerDecodeError::UnsupportedVersion {
                found: 2,
                expected: 1,
            },
            ReclaimQueueLedgerDecodeError::IntegrityFooterMismatch,
        ];
        for err in &variants {
            let s = alloc::format!("{err}");
            assert!(!s.is_empty(), "Display output empty for {err:?}");
        }
    }

    // -- Large-scale tests --

    #[test]
    fn large_ledger_roundtrip() {
        let mut l = ReclaimQueueLedger::with_defaults();
        for i in 0..1000u16 {
            let seed = (i % 256) as u8;
            l.enqueue(fe(seed));
        }
        let bytes = l.encode();
        let decoded =
            ReclaimQueueLedger::decode(&bytes, ReclaimQueueLedgerConfig::default()).unwrap();
        assert_eq!(decoded.len(), l.len());
        assert_eq!(decoded.total_freed_bytes(), l.total_freed_bytes());
    }

    #[test]
    fn encode_is_deterministic() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(10));
        l.enqueue(fe(20));
        l.enqueue(fe(30));
        let bytes1 = l.encode();
        let bytes2 = l.encode();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn dequeue_batch_total_freed_bytes_updated() {
        let mut l = ReclaimQueueLedger::with_defaults();
        l.enqueue(fe(10));
        l.enqueue(fe(20));
        assert_eq!(l.total_freed_bytes(), 10240 + 20480);
        let batch = l.dequeue_batch(1);
        assert_eq!(batch.len(), 1);
        assert_eq!(l.total_freed_bytes(), 20480);
    }

    #[test]
    fn enqueue_returns_new_length() {
        let mut l = ReclaimQueueLedger::with_defaults();
        assert_eq!(l.enqueue(fe(1)), 1);
        assert_eq!(l.enqueue(fe(2)), 2);
        assert_eq!(l.enqueue(fe(3)), 3);
    }

    // -- Config persistence across encode/decode --

    #[test]
    fn decode_preserves_custom_config() {
        let cfg = ReclaimQueueLedgerConfig::new()
            .with_batch_size(200)
            .with_persistence_mode(PersistenceMode::EveryEnqueue);
        let mut l = ReclaimQueueLedger::new(cfg);
        l.enqueue(fe(1));
        l.enqueue(fe(2));
        let bytes = l.encode();
        let decoded = ReclaimQueueLedger::decode(&bytes, cfg).unwrap();
        assert_eq!(decoded.config().batch_size, 200);
        assert_eq!(
            decoded.config().persistence_mode,
            PersistenceMode::EveryEnqueue
        );
    }

    // -- Default construction --

    #[test]
    fn with_defaults_uses_default_config() {
        let l = ReclaimQueueLedger::with_defaults();
        assert_eq!(l.config(), &ReclaimQueueLedgerConfig::default());
    }
}
