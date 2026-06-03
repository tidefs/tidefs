//! Block reclamation: bulk-free batching for efficient block-allocator
//! interaction across a TXG window.
//!
//! The [`Reclaimer`] accumulates block IDs from multiple cleanup
//! operations and flushes them in a single bulk `free()` call at TXG
//! commit time, avoiding the per-call overhead of the allocator's
//! locking and bitmap updates.
//!
//! ## Crash safety
//!
//! Progress is recorded via a BLAKE3-verified receipt. After a crash,
//! `resume()` from the last receipt skips already-freed blocks and
//! continues accumulating new ones.

use blake3;
use std::collections::HashSet;

const RECLAIM_DOMAIN: &str = "TideFS Reclaimer receipt v1";
const RECEIPT_HASH_LEN: usize = 32;
const RECEIPT_COUNT_LEN: usize = 8;
const RECEIPT_HEADER_LEN: usize = RECEIPT_HASH_LEN + RECEIPT_COUNT_LEN;

/// Accumulated statistics for block reclamation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReclaimStats {
    /// Total blocks staged across all batches.
    pub blocks_staged: u64,
    /// Total blocks successfully freed.
    pub blocks_freed: u64,
    /// Approximate bytes freed (blocks * block_size).
    pub bytes_freed: u64,
    /// Number of flush batches committed.
    pub batches_committed: u64,
}

/// Errors returned by reclamation operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReclaimError {
    /// Receipt blob too short.
    BlobTooShort { expected: usize, got: usize },
    /// BLAKE3 hash mismatch on receipt verification.
    HashMismatch,
    /// The underlying block allocator returned an error.
    AllocatorError(String),
}

impl std::fmt::Display for ReclaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlobTooShort { expected, got } => write!(
                f,
                "reclaim receipt too short: expected {expected}B, got {got}B"
            ),
            Self::HashMismatch => f.write_str("reclaim receipt hash mismatch"),
            Self::AllocatorError(msg) => write!(f, "allocator error: {msg}"),
        }
    }
}

impl std::error::Error for ReclaimError {}

/// Trait abstracting the block allocator's free operation for testability.
pub trait BlockFreeBackend {
    /// Free a batch of blocks. Returns the count successfully freed.
    fn free_blocks(&mut self, block_ids: &[u64]) -> Result<u64, String>;
}

/// Batched block reclamation engine.
///
/// Accumulates block IDs from cleanup operations and flushes them in
/// a single bulk call at TXG commit time. Supports crash-safe resume
/// from a BLAKE3-verified receipt.
pub struct Reclaimer<B: BlockFreeBackend> {
    backend: B,
    /// Block size in bytes for statistics calculation.
    block_size: u64,
    /// Blocks staged for the current batch (not yet flushed).
    staged: HashSet<u64>,
    /// Blocks already freed (across all batches, for crash-safe resume).
    freed: HashSet<u64>,
    /// Accumulated statistics.
    stats: ReclaimStats,
}

impl<B: BlockFreeBackend> Reclaimer<B> {
    /// Create a new reclaimer with the given backend and block size.
    #[must_use]
    pub fn new(backend: B, block_size: u64) -> Self {
        Self {
            backend,
            block_size,
            staged: HashSet::new(),
            freed: HashSet::new(),
            stats: ReclaimStats::default(),
        }
    }

    /// Resume from a prior receipt, skipping already-freed blocks.
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimError`] if the receipt is corrupt or too short.
    pub fn resume(backend: B, block_size: u64, receipt: &[u8]) -> Result<Self, ReclaimError> {
        let freed = Self::decode_receipt(receipt)?;
        let mut stats = ReclaimStats::default();
        stats.blocks_freed = freed.len() as u64;
        stats.bytes_freed = stats.blocks_freed.saturating_mul(block_size);
        Ok(Self {
            backend,
            block_size,
            staged: HashSet::new(),
            freed,
            stats,
        })
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> ReclaimStats {
        self.stats
    }

    /// Number of blocks currently staged (not yet flushed).
    #[must_use]
    pub fn staged_count(&self) -> usize {
        self.staged.len()
    }

    /// Number of blocks freed across all batches.
    #[must_use]
    pub fn freed_count(&self) -> usize {
        self.freed.len()
    }

    /// Returns `true` if the staged set is empty.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.staged.is_empty()
    }

    /// Stage a block for reclamation in the next flush.
    ///
    /// Blocks already freed or already staged are silently skipped.
    /// Returns `true` if the block was newly staged.
    pub fn stage(&mut self, block_id: u64) -> bool {
        if self.freed.contains(&block_id) {
            return false;
        }
        let inserted = self.staged.insert(block_id);
        if inserted {
            self.stats.blocks_staged = self.stats.blocks_staged.saturating_add(1);
        }
        inserted
    }

    /// Stage multiple blocks at once.
    ///
    /// Returns the number of blocks newly staged (excluding already-freed
    /// and already-staged blocks).
    pub fn stage_batch(&mut self, block_ids: &[u64]) -> usize {
        let mut count = 0;
        for &id in block_ids {
            if self.stage(id) {
                count += 1;
            }
        }
        count
    }

    /// Flush all staged blocks to the allocator in a single bulk call.
    ///
    /// Returns the number of blocks successfully freed.
    ///
    /// # Errors
    ///
    /// Returns [`ReclaimError::AllocatorError`] if the backend fails.
    pub fn flush(&mut self) -> Result<usize, ReclaimError> {
        if self.staged.is_empty() {
            return Ok(0);
        }

        let batch: Vec<u64> = self.staged.iter().copied().collect();
        let freed_count = self
            .backend
            .free_blocks(&batch)
            .map_err(ReclaimError::AllocatorError)?;

        let freed = freed_count as usize;
        self.freed.extend(&batch);
        self.staged.clear();

        self.stats.blocks_freed = self.stats.blocks_freed.saturating_add(freed_count);
        self.stats.bytes_freed = self
            .stats
            .bytes_freed
            .saturating_add(freed_count.saturating_mul(self.block_size));
        self.stats.batches_committed = self.stats.batches_committed.saturating_add(1);

        Ok(freed)
    }

    /// Seal the current freed-set into a BLAKE3-verified receipt blob.
    ///
    /// The receipt can be persisted alongside a TXG commit for crash-safe
    /// resume. Format: `[hash:32][count:8 LE][block_ids: N*8 LE]`.
    #[must_use]
    pub fn seal_receipt(&self) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new_derive_key(RECLAIM_DOMAIN);
        let count = self.freed.len() as u64;
        let mut body = Vec::with_capacity(RECEIPT_COUNT_LEN + self.freed.len() * 8);
        body.extend_from_slice(&count.to_le_bytes());
        let mut sorted: Vec<u64> = self.freed.iter().copied().collect();
        sorted.sort_unstable();
        for id in &sorted {
            body.extend_from_slice(&id.to_le_bytes());
        }
        hasher.update(&body);
        let hash = hasher.finalize();
        let mut receipt = Vec::with_capacity(RECEIPT_HASH_LEN + body.len());
        receipt.extend_from_slice(hash.as_bytes());
        receipt.extend_from_slice(&body);
        receipt
    }

    /// Decode and verify a receipt, returning the set of already-freed blocks.
    fn decode_receipt(blob: &[u8]) -> Result<HashSet<u64>, ReclaimError> {
        if blob.len() < RECEIPT_HEADER_LEN {
            return Err(ReclaimError::BlobTooShort {
                expected: RECEIPT_HEADER_LEN,
                got: blob.len(),
            });
        }
        let (stored_hash, body) = (&blob[..RECEIPT_HASH_LEN], &blob[RECEIPT_HASH_LEN..]);
        let mut hasher = blake3::Hasher::new_derive_key(RECLAIM_DOMAIN);
        hasher.update(body);
        if stored_hash != hasher.finalize().as_bytes() {
            return Err(ReclaimError::HashMismatch);
        }
        if body.len() < RECEIPT_COUNT_LEN {
            return Err(ReclaimError::BlobTooShort {
                expected: RECEIPT_HEADER_LEN,
                got: blob.len(),
            });
        }
        let count = u64::from_le_bytes(body[..RECEIPT_COUNT_LEN].try_into().unwrap()) as usize;
        let expected_body = RECEIPT_COUNT_LEN + count * 8;
        if body.len() < expected_body {
            return Err(ReclaimError::BlobTooShort {
                expected: RECEIPT_HASH_LEN + expected_body,
                got: blob.len(),
            });
        }
        let mut freed = HashSet::with_capacity(count);
        for i in 0..count {
            let start = RECEIPT_COUNT_LEN + i * 8;
            freed.insert(u64::from_le_bytes(
                body[start..start + 8].try_into().unwrap(),
            ));
        }
        Ok(freed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockBackend {
        freed: RefCell<Vec<Vec<u64>>>,
        fail: RefCell<bool>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                freed: RefCell::new(Vec::new()),
                fail: RefCell::new(false),
            }
        }

        fn set_fail(&self, fail: bool) {
            *self.fail.borrow_mut() = fail;
        }

        #[allow(dead_code)]
        fn freed_batches(&self) -> Vec<Vec<u64>> {
            self.freed.borrow().clone()
        }
    }

    impl BlockFreeBackend for MockBackend {
        fn free_blocks(&mut self, block_ids: &[u64]) -> Result<u64, String> {
            if *self.fail.borrow() {
                return Err("mock backend failure".to_string());
            }
            self.freed.borrow_mut().push(block_ids.to_vec());
            Ok(block_ids.len() as u64)
        }
    }

    // ── Basic operations ─────────────────────────────────────────────

    #[test]
    fn new_reclaimer_is_idle() {
        let backend = MockBackend::new();
        let r = Reclaimer::new(backend, 4096);
        assert!(r.is_idle());
        assert_eq!(r.staged_count(), 0);
        assert_eq!(r.freed_count(), 0);
        assert_eq!(r.stats(), ReclaimStats::default());
    }

    #[test]
    fn stage_single_block() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        assert!(r.stage(42));
        assert!(!r.is_idle());
        assert_eq!(r.staged_count(), 1);
        assert_eq!(r.stats().blocks_staged, 1);
    }

    #[test]
    fn stage_duplicate_skipped() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        assert!(r.stage(10));
        assert!(!r.stage(10));
        assert_eq!(r.staged_count(), 1);
        assert_eq!(r.stats().blocks_staged, 1);
    }

    #[test]
    fn stage_batch_counts_new() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        let count = r.stage_batch(&[1, 2, 3, 1, 2]);
        assert_eq!(count, 3); // duplicates skipped
        assert_eq!(r.staged_count(), 3);
    }

    // ── Flush ────────────────────────────────────────────────────────

    #[test]
    fn flush_staged_blocks() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);

        r.stage_batch(&[100, 200, 300]);
        let freed = r.flush().unwrap();
        assert_eq!(freed, 3);
        assert!(r.is_idle());
        assert_eq!(r.stats().blocks_freed, 3);
        assert_eq!(r.stats().bytes_freed, 12288);
        assert_eq!(r.stats().batches_committed, 1);
    }

    #[test]
    fn flush_empty_is_noop() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        let freed = r.flush().unwrap();
        assert_eq!(freed, 0);
        assert_eq!(r.stats().batches_committed, 0);
    }

    #[test]
    fn flush_multiple_batches() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);

        r.stage_batch(&[1, 2]);
        r.flush().unwrap();
        assert_eq!(r.stats().blocks_freed, 2);

        r.stage_batch(&[3, 4, 5]);
        r.flush().unwrap();
        assert_eq!(r.stats().blocks_freed, 5);
        assert_eq!(r.stats().batches_committed, 2);
    }

    #[test]
    fn flush_frees_each_block_once() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);

        r.stage(1);
        r.flush().unwrap();

        // Same block staged again after flush should be skipped
        assert!(!r.stage(1));
        let freed = r.flush().unwrap();
        assert_eq!(freed, 0);
    }

    #[test]
    fn flush_backend_error() {
        let backend = MockBackend::new();
        backend.set_fail(true);
        let mut r = Reclaimer::new(backend, 4096);

        r.stage(42);
        let result = r.flush();
        assert!(matches!(result, Err(ReclaimError::AllocatorError(_))));
        // Blocks remain staged after failed flush
        assert_eq!(r.staged_count(), 1);
    }

    // ── Receipt roundtrip ────────────────────────────────────────────

    #[test]
    fn receipt_roundtrip_single_block() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        r.stage(99);
        r.flush().unwrap();

        let receipt = r.seal_receipt();
        let freed = Reclaimer::<MockBackend>::decode_receipt(&receipt).unwrap();
        assert!(freed.contains(&99));
        assert_eq!(freed.len(), 1);
    }

    #[test]
    fn receipt_roundtrip_multiple_blocks() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        r.stage_batch(&[10, 20, 30, 40, 50]);
        r.flush().unwrap();

        let freed = Reclaimer::<MockBackend>::decode_receipt(&r.seal_receipt()).unwrap();
        assert_eq!(freed.len(), 5);
        for id in [10, 20, 30, 40, 50] {
            assert!(freed.contains(&id));
        }
    }

    #[test]
    fn receipt_empty_reclaimer() {
        let backend = MockBackend::new();
        let r = Reclaimer::new(backend, 4096);
        let freed = Reclaimer::<MockBackend>::decode_receipt(&r.seal_receipt()).unwrap();
        assert!(freed.is_empty());
    }

    #[test]
    fn receipt_hash_mismatch() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);
        r.stage(77);
        r.flush().unwrap();

        let mut receipt = r.seal_receipt();
        receipt[10] ^= 0xFF;
        let result = Reclaimer::<MockBackend>::decode_receipt(&receipt);
        assert!(matches!(result, Err(ReclaimError::HashMismatch)));
    }

    #[test]
    fn receipt_too_short() {
        let result = Reclaimer::<MockBackend>::decode_receipt(&[0u8; 10]);
        assert!(matches!(result, Err(ReclaimError::BlobTooShort { .. })));
    }

    #[test]
    fn receipt_count_mismatch() {
        // Header says 5 blocks but only 3 follow
        let mut receipt = Vec::new();
        let mut hasher = blake3::Hasher::new_derive_key(RECLAIM_DOMAIN);
        let mut body = 5u64.to_le_bytes().to_vec();
        body.extend_from_slice(&1u64.to_le_bytes());
        body.extend_from_slice(&2u64.to_le_bytes());
        body.extend_from_slice(&3u64.to_le_bytes());
        hasher.update(&body);
        let hash = hasher.finalize();
        receipt.extend_from_slice(hash.as_bytes());
        receipt.extend_from_slice(&body);

        let result = Reclaimer::<MockBackend>::decode_receipt(&receipt);
        assert!(matches!(result, Err(ReclaimError::BlobTooShort { .. })));
    }

    // ── Resume ───────────────────────────────────────────────────────

    #[test]
    fn resume_skips_already_freed() {
        let backend1 = MockBackend::new();
        let mut r1 = Reclaimer::new(backend1, 4096);
        r1.stage_batch(&[1, 2, 3]);
        r1.flush().unwrap();
        let receipt = r1.seal_receipt();

        let backend2 = MockBackend::new();
        let mut r2 = Reclaimer::resume(backend2, 4096, &receipt).unwrap();
        // Stage blocks 1-5; 1,2,3 should be skipped
        let staged = r2.stage_batch(&[1, 2, 3, 4, 5]);
        assert_eq!(staged, 2); // only 4 and 5 are new
        assert_eq!(r2.freed_count(), 3); // from resume
    }

    #[test]
    fn resume_with_corrupt_receipt_fails() {
        let backend = MockBackend::new();
        let mut corrupt = vec![0u8; 40];
        corrupt[0] = 0xFF;
        let result = Reclaimer::resume(backend, 4096, &corrupt);
        assert!(result.is_err());
    }

    // ── Statistics ───────────────────────────────────────────────────

    #[test]
    fn stats_accumulate_across_batches() {
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 4096);

        r.stage_batch(&[1, 2]);
        r.flush().unwrap();
        assert_eq!(r.stats().blocks_freed, 2);
        assert_eq!(r.stats().batches_committed, 1);

        r.stage_batch(&[3, 4, 5]);
        r.flush().unwrap();
        assert_eq!(r.stats().blocks_freed, 5);
        assert_eq!(r.stats().batches_committed, 2);
        assert_eq!(r.stats().bytes_freed, 5 * 4096);
    }

    #[test]
    fn stats_block_size_variants() {
        // 512-byte blocks
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 512);
        r.stage_batch(&[1, 2, 3]);
        r.flush().unwrap();
        assert_eq!(r.stats().bytes_freed, 3 * 512);

        // 64 KiB blocks
        let backend = MockBackend::new();
        let mut r = Reclaimer::new(backend, 65536);
        r.stage_batch(&[10, 20]);
        r.flush().unwrap();
        assert_eq!(r.stats().bytes_freed, 2 * 65536);
    }

    // ── Error display ────────────────────────────────────────────────

    #[test]
    fn error_display_blob_too_short() {
        let err = ReclaimError::BlobTooShort {
            expected: 40,
            got: 10,
        };
        let s = format!("{err}");
        assert!(s.contains("40"));
        assert!(s.contains("10"));
    }

    #[test]
    fn error_display_hash_mismatch() {
        let s = format!("{}", ReclaimError::HashMismatch);
        assert!(s.contains("hash mismatch"));
    }

    #[test]
    fn error_display_allocator_error() {
        let s = format!("{}", ReclaimError::AllocatorError("out of space".into()));
        assert!(s.contains("out of space"));
    }
}
