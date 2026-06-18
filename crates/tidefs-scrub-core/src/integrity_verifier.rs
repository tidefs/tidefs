// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-object BLAKE3 integrity verification.
//!
//! [`IntegrityVerifier`] reads object data, recomputes the BLAKE3-256
//! content hash, and compares it against the stored hash from allocation
//! time.  Mismatches indicate silent data corruption.

use std::sync::Arc;
use std::time::{Duration, Instant};

/// Trait abstracting object data reads.
pub trait ObjectReader: Send + Sync {
    /// Read the full payload for the given object ID.
    ///
    /// Returns `Ok(data)` on success, or `Err(description)` on I/O failure.
    fn read_object(&self, object_id: u64) -> Result<Vec<u8>, String>;
}

/// Outcome of verifying a single object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityOutcome {
    /// Object content matches its stored BLAKE3 hash.
    Clean {
        /// Object identifier.
        object_id: u64,
    },
    /// Object content does not match the stored hash (silent corruption).
    CorruptionDetected {
        /// Object identifier.
        object_id: u64,
        /// The hash stored at allocation time.
        stored_hash: [u8; 32],
        /// The hash computed from the data on disk.
        computed_hash: [u8; 32],
    },
    /// I/O error prevented reading the object.
    IoError {
        /// Object identifier.
        object_id: u64,
        /// Human-readable error.
        error: String,
    },
}

/// Aggregate statistics collected during a verification run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntegrityStats {
    /// Total number of objects verified.
    pub objects_scanned: u64,
    /// Total bytes verified across all objects.
    pub bytes_verified: u64,
    /// Number of corruption events detected.
    pub corruptions_detected: u64,
    /// Number of I/O errors encountered.
    pub io_errors: u64,
}

/// Verifies object data against stored BLAKE3-256 content hashes.
pub struct IntegrityVerifier<R: ObjectReader> {
    reader: Arc<R>,
    stats: IntegrityStats,
    /// Wall-clock time spent verifying.
    elapsed: Duration,
}

impl<R: ObjectReader> IntegrityVerifier<R> {
    /// Create a new verifier wrapping the given object reader.
    #[must_use]
    pub fn new(reader: Arc<R>) -> Self {
        Self {
            reader,
            stats: IntegrityStats::default(),
            elapsed: Duration::default(),
        }
    }

    /// Verify a single object.
    ///
    /// Reads the object data, computes its BLAKE3 content hash, and
    /// compares against `stored_hash`.  Updates aggregate statistics.
    pub fn verify_one(&mut self, object_id: u64, stored_hash: &[u8; 32]) -> IntegrityOutcome {
        let start = Instant::now();

        let outcome = match self.reader.read_object(object_id) {
            Ok(data) => {
                let size = data.len() as u64;
                let computed: [u8; 32] = blake3::hash(&data).into();
                self.stats.objects_scanned += 1;
                self.stats.bytes_verified += size;

                if &computed == stored_hash {
                    IntegrityOutcome::Clean { object_id }
                } else {
                    self.stats.corruptions_detected += 1;
                    IntegrityOutcome::CorruptionDetected {
                        object_id,
                        stored_hash: *stored_hash,
                        computed_hash: computed,
                    }
                }
            }
            Err(e) => {
                self.stats.io_errors += 1;
                IntegrityOutcome::IoError {
                    object_id,
                    error: e,
                }
            }
        };

        self.elapsed += start.elapsed();
        outcome
    }

    /// Verify a batch of scanned objects, returning one outcome per object.
    pub fn verify_batch(
        &mut self,
        objects: &[crate::object_scanner::ScannedObject],
    ) -> Vec<IntegrityOutcome> {
        objects
            .iter()
            .map(|obj| self.verify_one(obj.object_id, &obj.stored_hash))
            .collect()
    }

    /// Return a snapshot of aggregate statistics.
    #[must_use]
    pub fn stats(&self) -> &IntegrityStats {
        &self.stats
    }

    /// Return the total wall-clock time spent verifying.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Reset statistics for a new scan cycle.
    pub fn reset_stats(&mut self) {
        self.stats = IntegrityStats::default();
        self.elapsed = Duration::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock ObjectReader backed by an in-memory store.
    struct MockObjectReader {
        data: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl MockObjectReader {
        fn new() -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
            }
        }

        fn put(&self, id: u64, data: Vec<u8>) {
            self.data.lock().unwrap().insert(id, data);
        }
    }

    impl ObjectReader for MockObjectReader {
        fn read_object(&self, object_id: u64) -> Result<Vec<u8>, String> {
            self.data
                .lock()
                .unwrap()
                .get(&object_id)
                .cloned()
                .ok_or_else(|| format!("object {object_id} not found"))
        }
    }

    #[test]
    fn checksum_match_returns_clean() {
        let data = b"hello world".to_vec();
        let stored_hash: [u8; 32] = blake3::hash(&data).into();

        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, data);

        let mut verifier = IntegrityVerifier::new(reader);
        let outcome = verifier.verify_one(1, &stored_hash);

        assert!(matches!(outcome, IntegrityOutcome::Clean { object_id: 1 }));
        assert_eq!(verifier.stats().objects_scanned, 1);
        assert_eq!(verifier.stats().bytes_verified, 11);
        assert_eq!(verifier.stats().corruptions_detected, 0);
        assert_eq!(verifier.stats().io_errors, 0);
    }

    #[test]
    fn checksum_mismatch_detected() {
        let data = b"original".to_vec();
        let corrupted = b"corrupt!".to_vec();
        let stored_hash: [u8; 32] = blake3::hash(&corrupted).into();

        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, data);

        let mut verifier = IntegrityVerifier::new(reader);
        let outcome = verifier.verify_one(1, &stored_hash);

        match outcome {
            IntegrityOutcome::CorruptionDetected {
                object_id,
                stored_hash: _,
                computed_hash: _,
            } => assert_eq!(object_id, 1),
            other => panic!("expected CorruptionDetected, got {other:?}"),
        }
        assert_eq!(verifier.stats().corruptions_detected, 1);
        assert!(!verifier.elapsed().is_zero());
    }

    #[test]
    fn zero_length_object_handled() {
        let data = vec![];
        let stored_hash: [u8; 32] = blake3::hash(&data).into();

        let reader = Arc::new(MockObjectReader::new());
        reader.put(42, data);

        let mut verifier = IntegrityVerifier::new(reader);
        let outcome = verifier.verify_one(42, &stored_hash);

        assert!(matches!(outcome, IntegrityOutcome::Clean { object_id: 42 }));
        assert_eq!(verifier.stats().objects_scanned, 1);
        assert_eq!(verifier.stats().bytes_verified, 0);
    }

    #[test]
    fn io_error_handled_gracefully() {
        let reader = Arc::new(MockObjectReader::new());
        // object 99 does not exist
        let mut verifier = IntegrityVerifier::new(reader);
        let outcome = verifier.verify_one(99, &[0u8; 32]);

        match outcome {
            IntegrityOutcome::IoError {
                object_id,
                error: _,
            } => assert_eq!(object_id, 99),
            other => panic!("expected IoError, got {other:?}"),
        }
        assert_eq!(verifier.stats().io_errors, 1);
    }

    #[test]
    fn reset_stats_clears_accumulators() {
        let data = b"test".to_vec();
        let stored_hash: [u8; 32] = blake3::hash(&data).into();

        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, data);

        let mut verifier = IntegrityVerifier::new(reader);
        verifier.verify_one(1, &stored_hash);
        assert_eq!(verifier.stats().objects_scanned, 1);

        verifier.reset_stats();
        assert_eq!(verifier.stats().objects_scanned, 0);
        assert_eq!(verifier.stats().bytes_verified, 0);
        assert_eq!(verifier.stats().corruptions_detected, 0);
        assert_eq!(verifier.stats().io_errors, 0);
        assert_eq!(verifier.elapsed(), Duration::default());
    }

    #[test]
    fn verify_batch_processes_all() {
        let data_a = b"aaa".to_vec();
        let data_b = b"bbbb".to_vec();
        let stored_hash_a: [u8; 32] = blake3::hash(&data_a).into();
        let stored_hash_b: [u8; 32] = blake3::hash(&data_b).into();

        let reader = Arc::new(MockObjectReader::new());
        reader.put(1, data_a);
        reader.put(2, data_b);

        let mut verifier = IntegrityVerifier::new(reader);

        let objects = vec![
            crate::object_scanner::ScannedObject {
                object_id: 1,
                size: 3,
                stored_hash: stored_hash_a,
            },
            crate::object_scanner::ScannedObject {
                object_id: 2,
                size: 4,
                stored_hash: stored_hash_b,
            },
        ];

        let outcomes = verifier.verify_batch(&objects);
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(
            outcomes[0],
            IntegrityOutcome::Clean { object_id: 1 }
        ));
        assert!(matches!(
            outcomes[1],
            IntegrityOutcome::Clean { object_id: 2 }
        ));
        assert_eq!(verifier.stats().objects_scanned, 2);
        assert_eq!(verifier.stats().bytes_verified, 7);
    }
}
