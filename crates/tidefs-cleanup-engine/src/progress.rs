// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified cleanup engine progress checkpointing.
//!
//! [`CleanupProgress`] provides crash-safe resume through a sealed-blob
//! format `[BLAKE3-256 hash: 32 bytes][last_processed_entry_id: 8 bytes LE]`.
//! On reload the hash is recomputed; a mismatch indicates corruption.

use blake3;

/// Domain separation context for `CleanupProgress` BLAKE3 key derivation.
const PROGRESS_DOMAIN: &str = "TideFS CleanupEngine progress v1";

/// Size of the sealed blob: 32-byte BLAKE3-256 hash + 8-byte entry_id (u64 LE).
pub const SEALED_BLOB_SIZE: usize = 40;

/// Errors returned by progress persistence operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgressError {
    /// Blob is too short to contain the hash and entry_id.
    BlobTooShort { expected: usize, got: usize },
    /// The BLAKE3 hash does not match the payload; data may be corrupt.
    HashMismatch,
}

impl core::fmt::Display for ProgressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProgressError::BlobTooShort { expected, got } => {
                write!(
                    f,
                    "sealed blob too short: expected {expected} bytes, got {got}"
                )
            }
            ProgressError::HashMismatch => {
                f.write_str("sealed blob hash mismatch: data may be corrupt")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CleanupProgress
// ---------------------------------------------------------------------------

/// Crash-safe progress checkpoint for the cleanup engine.
///
/// # Format
///
/// ```text
/// [0..32)   BLAKE3-256 hash(key=PROGRESS_DOMAIN, data=last_processed_entry_id LE)
/// [32..40)  last_processed_entry_id: u64 LE
/// ```
///
/// # Crash safety
///
/// On reload, the hash is verified. If it mismatches the sealed entry_id,
/// the checkpoint is considered corrupt and the engine starts from the
/// beginning of the queue. This prevents skipping work items after a
/// torn write.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CleanupProgress {
    /// Last fully processed entry ID. Zero means "start from beginning".
    pub last_processed_entry_id: u64,
}

impl CleanupProgress {
    /// Create a new progress tracker starting from the beginning.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_processed_entry_id: 0,
        }
    }

    /// Record that an entry has been processed.
    pub fn record(&mut self, entry_id: u64) {
        self.last_processed_entry_id = entry_id;
    }

    /// Seal the current progress into a BLAKE3-verified blob.
    ///
    /// The returned 40-byte blob can be persisted to disk and later
    /// passed to [`load`](Self::load) for verified resume.
    #[must_use]
    pub fn seal(&self) -> [u8; SEALED_BLOB_SIZE] {
        let mut hasher = blake3::Hasher::new_derive_key(PROGRESS_DOMAIN);
        hasher.update(&self.last_processed_entry_id.to_le_bytes());
        let hash = hasher.finalize();

        let mut blob = [0u8; SEALED_BLOB_SIZE];
        blob[0..32].copy_from_slice(hash.as_bytes());
        blob[32..40].copy_from_slice(&self.last_processed_entry_id.to_le_bytes());
        blob
    }

    /// Load and verify a sealed progress blob.
    ///
    /// Returns the last processed entry ID on success, or a
    /// [`ProgressError`] if the blob is too short or the hash mismatches.
    pub fn load(blob: &[u8]) -> Result<u64, ProgressError> {
        if blob.len() < SEALED_BLOB_SIZE {
            return Err(ProgressError::BlobTooShort {
                expected: SEALED_BLOB_SIZE,
                got: blob.len(),
            });
        }

        let stored_hash = &blob[0..32];
        let entry_id_bytes: [u8; 8] = blob[32..40].try_into().unwrap();

        let mut hasher = blake3::Hasher::new_derive_key(PROGRESS_DOMAIN);
        hasher.update(&entry_id_bytes);
        let computed_hash = hasher.finalize();

        if stored_hash != computed_hash.as_bytes() {
            return Err(ProgressError::HashMismatch);
        }

        Ok(u64::from_le_bytes(entry_id_bytes))
    }

    /// Load a sealed progress blob and return a `CleanupProgress` instance.
    ///
    /// Convenience wrapper around [`load`](Self::load).
    pub fn from_sealed_blob(blob: &[u8]) -> Result<Self, ProgressError> {
        let entry_id = Self::load(blob)?;
        Ok(Self {
            last_processed_entry_id: entry_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // seal / load round-trip

    #[test]
    fn seal_load_roundtrip_zero() {
        let progress = CleanupProgress::new();
        let blob = progress.seal();
        let loaded = CleanupProgress::load(&blob).unwrap();
        assert_eq!(loaded, 0);
    }

    #[test]
    fn seal_load_roundtrip_nonzero() {
        let mut progress = CleanupProgress::new();
        progress.record(42);
        let blob = progress.seal();
        let loaded = CleanupProgress::load(&blob).unwrap();
        assert_eq!(loaded, 42);
    }

    #[test]
    fn seal_load_roundtrip_max() {
        let mut progress = CleanupProgress::new();
        progress.record(u64::MAX);
        let blob = progress.seal();
        let loaded = CleanupProgress::load(&blob).unwrap();
        assert_eq!(loaded, u64::MAX);
    }

    // from_sealed_blob

    #[test]
    fn from_sealed_blob_roundtrip() {
        let mut progress = CleanupProgress::new();
        progress.record(100);
        let blob = progress.seal();
        let restored = CleanupProgress::from_sealed_blob(&blob).unwrap();
        assert_eq!(restored.last_processed_entry_id, 100);
    }

    // corruption detection

    #[test]
    fn load_blob_too_short() {
        let short_blob = [0u8; 10];
        let result = CleanupProgress::load(&short_blob);
        assert!(matches!(result, Err(ProgressError::BlobTooShort { .. })));
    }

    #[test]
    fn load_blob_empty() {
        let result = CleanupProgress::load(&[]);
        assert!(matches!(result, Err(ProgressError::BlobTooShort { .. })));
    }

    #[test]
    fn load_blob_one_byte_short() {
        let short = [0u8; 39];
        let result = CleanupProgress::load(&short);
        assert!(matches!(result, Err(ProgressError::BlobTooShort { .. })));
    }

    #[test]
    fn load_hash_mismatch_corrupted_entry_id() {
        let mut progress = CleanupProgress::new();
        progress.record(77);
        let mut blob = progress.seal();
        // Corrupt the entry_id bytes
        blob[35] ^= 0xFF;
        let result = CleanupProgress::load(&blob);
        assert!(matches!(result, Err(ProgressError::HashMismatch)));
    }

    #[test]
    fn load_hash_mismatch_corrupted_hash() {
        let mut progress = CleanupProgress::new();
        progress.record(99);
        let mut blob = progress.seal();
        // Corrupt the hash bytes, entry_id unchanged
        blob[10] ^= 0xFF;
        let result = CleanupProgress::load(&blob);
        assert!(matches!(result, Err(ProgressError::HashMismatch)));
    }

    #[test]
    fn load_hash_mismatch_tampered_both() {
        let mut progress = CleanupProgress::new();
        progress.record(55);
        let mut blob = progress.seal();
        // Tamper with both hash and entry_id
        blob[0] ^= 0x01;
        blob[39] ^= 0x01;
        let result = CleanupProgress::load(&blob);
        assert!(matches!(result, Err(ProgressError::HashMismatch)));
    }

    // seal determinism

    #[test]
    fn seal_is_deterministic() {
        let mut progress = CleanupProgress::new();
        progress.record(12345);
        let blob1 = progress.seal();
        let blob2 = progress.seal();
        assert_eq!(blob1, blob2);
    }

    // domain separation

    #[test]
    fn different_domain_produces_different_hash() {
        let mut progress = CleanupProgress::new();
        progress.record(1);
        let blob = progress.seal();

        let alt_domain = "TideFS CleanupEngine progress v2";
        let mut hasher = blake3::Hasher::new_derive_key(alt_domain);
        hasher.update(&1u64.to_le_bytes());
        let alt_hash = hasher.finalize();

        assert_ne!(&blob[0..32], alt_hash.as_bytes());
    }

    #[test]
    fn domain_separation_preserves_roundtrip() {
        let mut progress = CleanupProgress::new();
        progress.record(999);
        let blob = progress.seal();
        let loaded = CleanupProgress::load(&blob).unwrap();
        assert_eq!(loaded, 999);
    }

    // progress display

    #[test]
    fn progress_error_display_blob_too_short() {
        let err = ProgressError::BlobTooShort {
            expected: 40,
            got: 10,
        };
        let s = format!("{err}");
        assert!(s.contains("too short"));
        assert!(s.contains("40"));
        assert!(s.contains("10"));
    }

    #[test]
    fn progress_error_display_hash_mismatch() {
        let err = ProgressError::HashMismatch;
        let s = format!("{err}");
        assert!(s.contains("hash mismatch"));
        assert!(s.contains("corrupt"));
    }

    // record updates

    #[test]
    fn record_updates_field() {
        let mut progress = CleanupProgress::new();
        assert_eq!(progress.last_processed_entry_id, 0);
        progress.record(5);
        assert_eq!(progress.last_processed_entry_id, 5);
        progress.record(10);
        assert_eq!(progress.last_processed_entry_id, 10);
    }

    // default is zero

    #[test]
    fn default_is_zero() {
        let progress = CleanupProgress::default();
        assert_eq!(progress.last_processed_entry_id, 0);
    }
}
