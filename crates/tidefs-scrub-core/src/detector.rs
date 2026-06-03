//! Corruption event collector with per-object deduplication.
//!
//! [`CorruptionDetector`] ingests [`IntegrityOutcome`] entries from the
//! checksum verifier and collects unique corruption events, deduplicating
//! by object ID.  It records corruption metadata (expected hash, actual
//! hash, physical location) and provides aggregate statistics for the
//! repair scheduler.
//!
//! # Example
//!
//! ```
//! use tidefs_scrub::integrity_verifier::{IntegrityOutcome, IntegrityStats};
//! use tidefs_scrub::detector::CorruptionDetector;
//!
//! let mut detector = CorruptionDetector::new();
//! detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 1 });
//! assert_eq!(detector.total_scanned(), 1);
//! assert_eq!(detector.corruption_count(), 0);
//! ```

use std::collections::HashMap;

use crate::integrity_verifier::IntegrityOutcome;

// ---------------------------------------------------------------------------
// CorruptionRecord — metadata for one corrupt object
// ---------------------------------------------------------------------------

/// Metadata recorded for a single corrupt object.
///
/// Keyed by object ID, deduplicated so only the first detection is stored.
/// Subsequent detections of the same object increment a repeat counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorruptionRecord {
    /// Object identifier (hex-encoded or raw, depending on source).
    pub object_id: u64,
    /// Expected BLAKE3-256 digest from the stored checksum tree root.
    pub expected_hash: [u8; 32],
    /// Actual BLAKE3-256 digest computed from the data on disk.
    pub actual_hash: [u8; 32],
    /// Approximate byte offset in the object store (segment × offset).
    pub physical_location: u64,
    /// How many times this object was re-detected as corrupt.
    pub repeat_detections: u64,
}

impl CorruptionRecord {
    /// Hex-encode the expected hash for display.
    #[must_use]
    pub fn expected_hex(&self) -> String {
        hex_encode(&self.expected_hash)
    }

    /// Hex-encode the actual hash for display.
    #[must_use]
    pub fn actual_hex(&self) -> String {
        hex_encode(&self.actual_hash)
    }
}

// ---------------------------------------------------------------------------
// CorruptionDetector
// ---------------------------------------------------------------------------

/// Collects corruption events from the scrub pipeline, deduplicates by
/// object ID, and provides aggregate statistics.
///
/// # Deduplication
///
/// Only the first detection of a corrupt object is recorded as a
/// [`CorruptionRecord`].  Subsequent detections (e.g. from re-scans)
/// increment `repeat_detections` on the existing record.  This prevents
/// the repair scheduler from being flooded with duplicate entries.
///
/// # Lifecycle
///
/// 1. Feed [`IntegrityOutcome`] entries from the verifier via
///    [`ingest_outcome`](CorruptionDetector::ingest_outcome) or
///    [`ingest_batch`](CorruptionDetector::ingest_batch).
/// 2. Read aggregate statistics via [`corruption_count`](CorruptionDetector::corruption_count)
///    and [`total_scanned`](CorruptionDetector::total_scanned).
/// 3. Drain corrupt records into the repair pipeline via
///    [`drain_corrupt_records`](CorruptionDetector::drain_corrupt_records).
pub struct CorruptionDetector {
    /// Per-object corruption records, keyed by object ID.
    records: HashMap<u64, CorruptionRecord>,
    /// Total number of objects scanned (all outcomes, clean + corrupt + error).
    total_scanned: u64,
    /// Total bytes scanned across all objects.
    total_bytes: u64,
    /// Number of I/O errors encountered.
    io_errors: u64,
}

impl CorruptionDetector {
    /// Create an empty corruption detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            total_scanned: 0,
            total_bytes: 0,
            io_errors: 0,
        }
    }

    // ── Ingestion ─────────────────────────────────────────────

    /// Ingest a single integrity outcome from the verifier.
    ///
    /// - `Clean` objects increment the scan count.
    /// - `CorruptionDetected` objects are recorded and deduplicated.
    /// - `IoError` objects increment the error count.
    pub fn ingest_outcome(&mut self, outcome: IntegrityOutcome) {
        self.total_scanned += 1;

        match outcome {
            IntegrityOutcome::Clean { object_id: _ } => {
                // Nothing to record for clean objects.
            }
            IntegrityOutcome::CorruptionDetected {
                object_id,
                stored_hash,
                computed_hash,
            } => {
                self.record_corruption(object_id, stored_hash, computed_hash, 0);
            }
            IntegrityOutcome::IoError {
                object_id: _,
                error: _,
            } => {
                self.io_errors += 1;
            }
        }
    }

    /// Ingest a batch of outcomes.
    pub fn ingest_batch(&mut self, outcomes: &[IntegrityOutcome]) {
        for outcome in outcomes {
            self.ingest_outcome(outcome.clone());
        }
    }

    /// Ingest an outcome with explicit byte count for cumulative statistics.
    ///
    /// Use this when the verifier reports per-object byte counts.
    pub fn ingest_outcome_with_bytes(&mut self, outcome: IntegrityOutcome, bytes: u64) {
        self.total_bytes += bytes;
        self.ingest_outcome(outcome);
    }

    // ── Recording ─────────────────────────────────────────────

    /// Record a corruption event, deduplicating by object ID.
    fn record_corruption(
        &mut self,
        object_id: u64,
        expected_hash: [u8; 32],
        actual_hash: [u8; 32],
        physical_location: u64,
    ) {
        if let Some(existing) = self.records.get_mut(&object_id) {
            existing.repeat_detections = existing.repeat_detections.saturating_add(1);
        } else {
            self.records.insert(
                object_id,
                CorruptionRecord {
                    object_id,
                    expected_hash,
                    actual_hash,
                    physical_location,
                    repeat_detections: 0,
                },
            );
        }
    }

    // ── Statistics ────────────────────────────────────────────

    /// Total number of objects scanned.
    #[must_use]
    pub fn total_scanned(&self) -> u64 {
        self.total_scanned
    }

    /// Total bytes scanned.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of unique corrupt objects (deduplicated).
    #[must_use]
    pub fn corruption_count(&self) -> usize {
        self.records.len()
    }

    /// Number of I/O errors encountered.
    #[must_use]
    pub fn io_error_count(&self) -> u64 {
        self.io_errors
    }

    /// Total corruption events including repeat detections.
    #[must_use]
    pub fn total_corruption_events(&self) -> u64 {
        self.records.values().map(|r| 1 + r.repeat_detections).sum()
    }

    /// Whether any corruptions were detected.
    #[must_use]
    pub fn has_corruptions(&self) -> bool {
        !self.records.is_empty()
    }

    /// Percentage of objects that are clean.
    #[must_use]
    pub fn clean_percentage(&self) -> f64 {
        if self.total_scanned == 0 {
            return 100.0;
        }
        let corrupt = self.corruption_count() as u64;
        if corrupt >= self.total_scanned {
            return 0.0;
        }
        ((self.total_scanned - corrupt) as f64 / self.total_scanned as f64) * 100.0
    }

    // ── Drain ────────────────────────────────────────────────

    /// Drain all corruption records, resetting the detector.
    ///
    /// After draining, the detector is empty and ready for a new scan cycle.
    /// Scanned counts and error counts are also reset.
    #[must_use]
    pub fn drain_corrupt_records(&mut self) -> Vec<CorruptionRecord> {
        let records: Vec<CorruptionRecord> = self.records.drain().map(|(_, v)| v).collect();
        self.total_scanned = 0;
        self.total_bytes = 0;
        self.io_errors = 0;
        records
    }

    /// Return corruption records sorted by object ID.
    #[must_use]
    pub fn corrupt_records_sorted(&self) -> Vec<&CorruptionRecord> {
        let mut ids: Vec<u64> = self.records.keys().copied().collect();
        ids.sort_unstable();
        ids.iter().filter_map(|id| self.records.get(id)).collect()
    }

    /// Return a reference to all corruption records.
    #[must_use]
    pub fn records(&self) -> &HashMap<u64, CorruptionRecord> {
        &self.records
    }

    /// Reset statistics and clear corruption records.
    pub fn reset(&mut self) {
        self.records.clear();
        self.total_scanned = 0;
        self.total_bytes = 0;
        self.io_errors = 0;
    }
}

impl Default for CorruptionDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hex-encode a byte slice as a lowercase string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Construction ─────────────────────────────────────────

    #[test]
    fn new_detector_is_empty() {
        let detector = CorruptionDetector::new();
        assert_eq!(detector.total_scanned(), 0);
        assert_eq!(detector.corruption_count(), 0);
        assert_eq!(detector.io_error_count(), 0);
        assert!(!detector.has_corruptions());
    }

    #[test]
    fn default_is_empty() {
        let detector = CorruptionDetector::default();
        assert_eq!(detector.total_scanned(), 0);
    }

    // ── Clean objects ────────────────────────────────────────

    #[test]
    fn clean_object_increments_scanned_count() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 42 });
        assert_eq!(detector.total_scanned(), 1);
        assert_eq!(detector.corruption_count(), 0);
        assert!(!detector.has_corruptions());
    }

    #[test]
    fn multiple_clean_objects_accumulate() {
        let mut detector = CorruptionDetector::new();
        for i in 1..=10 {
            detector.ingest_outcome(IntegrityOutcome::Clean { object_id: i });
        }
        assert_eq!(detector.total_scanned(), 10);
        assert_eq!(detector.corruption_count(), 0);
    }

    // ── Corruption detection ─────────────────────────────────

    #[test]
    fn corruption_event_recorded() {
        let mut detector = CorruptionDetector::new();
        let expected = [0xAAu8; 32];
        let actual = [0xBBu8; 32];
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 7,
            stored_hash: expected,
            computed_hash: actual,
        });
        assert_eq!(detector.total_scanned(), 1);
        assert_eq!(detector.corruption_count(), 1);
        assert!(detector.has_corruptions());
        assert_eq!(detector.io_error_count(), 0);
    }

    #[test]
    fn corruption_record_has_correct_hashes() {
        let mut detector = CorruptionDetector::new();
        let expected = [0x11u8; 32];
        let actual = [0x22u8; 32];
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 99,
            stored_hash: expected,
            computed_hash: actual,
        });
        let records = detector.records();
        let record = records.get(&99).unwrap();
        assert_eq!(record.expected_hash, expected);
        assert_eq!(record.actual_hash, actual);
        assert_eq!(record.object_id, 99);
        assert_eq!(record.repeat_detections, 0);
    }

    // ── Deduplication ────────────────────────────────────────

    #[test]
    fn deduplicates_same_object_id() {
        let mut detector = CorruptionDetector::new();
        let expected = [0xAAu8; 32];
        let actual = [0xBBu8; 32];

        // First detection.
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 5,
            stored_hash: expected,
            computed_hash: actual,
        });
        // Second detection of same object.
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 5,
            stored_hash: expected,
            computed_hash: actual,
        });

        assert_eq!(detector.corruption_count(), 1); // deduplicated
        assert_eq!(detector.total_corruption_events(), 2); // both events counted
        assert_eq!(detector.total_scanned(), 2);

        let record = detector.records().get(&5).unwrap();
        assert_eq!(record.repeat_detections, 1);
    }

    #[test]
    fn distinct_objects_not_deduplicated() {
        let mut detector = CorruptionDetector::new();
        let h = [0xAAu8; 32];
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 1,
            stored_hash: h,
            computed_hash: h,
        });
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 2,
            stored_hash: h,
            computed_hash: h,
        });
        assert_eq!(detector.corruption_count(), 2);
    }

    // ── I/O errors ──────────────────────────────────────────

    #[test]
    fn io_error_incremented() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome(IntegrityOutcome::IoError {
            object_id: 3,
            error: "disk failure".into(),
        });
        assert_eq!(detector.total_scanned(), 1);
        assert_eq!(detector.io_error_count(), 1);
        assert_eq!(detector.corruption_count(), 0);
    }

    // ── Mixed outcomes ──────────────────────────────────────

    #[test]
    fn mixed_clean_corrupt_and_error() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 1 });
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 2,
            stored_hash: [0xAAu8; 32],
            computed_hash: [0xBBu8; 32],
        });
        detector.ingest_outcome(IntegrityOutcome::IoError {
            object_id: 3,
            error: "EIO".into(),
        });
        detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 4 });

        assert_eq!(detector.total_scanned(), 4);
        assert_eq!(detector.corruption_count(), 1);
        assert_eq!(detector.io_error_count(), 1);
    }

    // ── Clean percentage ────────────────────────────────────

    #[test]
    fn clean_percentage_all_clean() {
        let mut detector = CorruptionDetector::new();
        for i in 0..10 {
            detector.ingest_outcome(IntegrityOutcome::Clean { object_id: i });
        }
        assert!((detector.clean_percentage() - 100.0).abs() < 0.001);
    }

    #[test]
    fn clean_percentage_half_corrupt() {
        let mut detector = CorruptionDetector::new();
        let h = [0xAAu8; 32];
        for i in 0..5 {
            detector.ingest_outcome(IntegrityOutcome::Clean { object_id: i });
        }
        for i in 5..10 {
            detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
                object_id: i,
                stored_hash: h,
                computed_hash: h,
            });
        }
        assert!((detector.clean_percentage() - 50.0).abs() < 0.001);
    }

    #[test]
    fn clean_percentage_zero_scanned() {
        let detector = CorruptionDetector::new();
        assert_eq!(detector.clean_percentage(), 100.0);
    }

    // ── Drain ───────────────────────────────────────────────

    #[test]
    fn drain_returns_all_records_and_resets() {
        let mut detector = CorruptionDetector::new();
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 10,
            stored_hash: h1,
            computed_hash: h2,
        });
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 20,
            stored_hash: h1,
            computed_hash: h2,
        });
        detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 30 });

        let records = detector.drain_corrupt_records();
        assert_eq!(records.len(), 2);
        assert_eq!(detector.corruption_count(), 0);
        assert_eq!(detector.total_scanned(), 0);
        assert_eq!(detector.total_bytes(), 0);
    }

    #[test]
    fn drain_empty_returns_empty() {
        let mut detector = CorruptionDetector::new();
        let records = detector.drain_corrupt_records();
        assert!(records.is_empty());
    }

    // ── Sorted records ──────────────────────────────────────

    #[test]
    fn corrupt_records_sorted_returns_by_id() {
        let mut detector = CorruptionDetector::new();
        let h = [0xAAu8; 32];
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 30,
            stored_hash: h,
            computed_hash: h,
        });
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 10,
            stored_hash: h,
            computed_hash: h,
        });
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 20,
            stored_hash: h,
            computed_hash: h,
        });

        let sorted = detector.corrupt_records_sorted();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].object_id, 10);
        assert_eq!(sorted[1].object_id, 20);
        assert_eq!(sorted[2].object_id, 30);
    }

    // ── Ingest batch ────────────────────────────────────────

    #[test]
    fn ingest_batch_processes_all() {
        let mut detector = CorruptionDetector::new();
        let outcomes = vec![
            IntegrityOutcome::Clean { object_id: 1 },
            IntegrityOutcome::Clean { object_id: 2 },
            IntegrityOutcome::CorruptionDetected {
                object_id: 3,
                stored_hash: [0xAAu8; 32],
                computed_hash: [0xBBu8; 32],
            },
        ];
        detector.ingest_batch(&outcomes);
        assert_eq!(detector.total_scanned(), 3);
        assert_eq!(detector.corruption_count(), 1);
    }

    // ── Ingest with bytes ───────────────────────────────────

    #[test]
    fn ingest_outcome_with_bytes_tracks_bytes() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome_with_bytes(IntegrityOutcome::Clean { object_id: 1 }, 1024);
        detector.ingest_outcome_with_bytes(IntegrityOutcome::Clean { object_id: 2 }, 2048);
        assert_eq!(detector.total_bytes(), 3072);
        assert_eq!(detector.total_scanned(), 2);
    }

    // ── Hexadecimal encoding ─────────────────────────────────

    #[test]
    fn corruption_record_hex_encoding() {
        let expected = [0xABu8; 32];
        let actual = [0xCDu8; 32];
        let record = CorruptionRecord {
            object_id: 1,
            expected_hash: expected,
            actual_hash: actual,
            physical_location: 0,
            repeat_detections: 0,
        };
        // All bytes equal, so hex string is "ab" repeated 32 times
        let expected_hex = "ab".repeat(32);
        let actual_hex = "cd".repeat(32);
        assert_eq!(record.expected_hex(), expected_hex);
        assert_eq!(record.actual_hex(), actual_hex);
    }

    // ── has_corruptions ─────────────────────────────────────

    #[test]
    fn has_corruptions_false_initially() {
        let detector = CorruptionDetector::new();
        assert!(!detector.has_corruptions());
    }

    #[test]
    fn has_corruptions_true_after_detection() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 1,
            stored_hash: [0u8; 32],
            computed_hash: [0u8; 32],
        });
        assert!(detector.has_corruptions());
    }

    // ── total_corruption_events ──────────────────────────────

    #[test]
    fn total_corruption_events_counts_duplicates() {
        let mut detector = CorruptionDetector::new();
        let h = [0xAAu8; 32];
        for _ in 0..5 {
            detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
                object_id: 1,
                stored_hash: h,
                computed_hash: h,
            });
        }
        assert_eq!(detector.corruption_count(), 1); // dedup
        assert_eq!(detector.total_corruption_events(), 5); // raw
    }

    // ── Reset ───────────────────────────────────────────────

    #[test]
    fn reset_clears_all_state() {
        let mut detector = CorruptionDetector::new();
        detector.ingest_outcome(IntegrityOutcome::CorruptionDetected {
            object_id: 1,
            stored_hash: [0u8; 32],
            computed_hash: [0u8; 32],
        });
        detector.ingest_outcome(IntegrityOutcome::Clean { object_id: 2 });
        detector.ingest_outcome(IntegrityOutcome::IoError {
            object_id: 3,
            error: "err".into(),
        });

        detector.reset();
        assert_eq!(detector.total_scanned(), 0);
        assert_eq!(detector.corruption_count(), 0);
        assert_eq!(detector.io_error_count(), 0);
        assert_eq!(detector.total_bytes(), 0);
        assert!(!detector.has_corruptions());
    }
}
