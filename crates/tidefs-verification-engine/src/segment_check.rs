//! Single-device segment integrity check.
//!
//! Wraps [`tidefs_local_object_store::SegmentIntegrityScrubber`] to verify
//! BLAKE3 integrity trail V2 digests for all segments in a device-local
//! segments directory, producing per-segment [`VerificationOutcome`] results.

use crate::health_report::VerificationOutcome;
use std::path::{Path, PathBuf};
use tidefs_local_object_store::{ScrubCursor, ScrubReport, SegmentIntegrityScrubber, SuspectLog};

/// Configuration for a single segment integrity check run.
#[derive(Clone, Debug)]
pub struct SegmentCheckConfig {
    /// Path to the segments directory (e.g. `<store_root>/segments`).
    pub segments_dir: PathBuf,
    /// Maximum records to verify per tick (0 = unlimited).
    pub max_records: u64,
    /// Maximum bytes to scan per tick (0 = unlimited).
    pub max_bytes: u64,
    /// Optional device path for reporting.
    pub device_path: Option<PathBuf>,
}

impl SegmentCheckConfig {
    #[must_use]
    pub fn new(segments_dir: impl AsRef<Path>) -> Self {
        Self {
            segments_dir: segments_dir.as_ref().to_path_buf(),
            max_records: 0,
            max_bytes: 0,
            device_path: None,
        }
    }

    #[must_use]
    pub fn with_limits(mut self, max_records: u64, max_bytes: u64) -> Self {
        self.max_records = max_records;
        self.max_bytes = max_bytes;
        self
    }

    #[must_use]
    pub fn with_device_path(mut self, path: impl AsRef<Path>) -> Self {
        self.device_path = Some(path.as_ref().to_path_buf());
        self
    }
}

/// Result of a single segment integrity check run.
#[derive(Clone, Debug)]
pub struct SegmentCheckResult {
    /// Per-segment outcomes.
    pub outcomes: Vec<VerificationOutcome>,
    /// Total records verified.
    pub records_verified: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Whether the scan completed all segments.
    pub completed: bool,
    /// Persisted cursor for incremental progress.
    pub cursor: ScrubCursor,
    /// Raw scrub report from the underlying scrubber.
    pub scrub_report: ScrubReport,
}

/// Runs an integrity check on a single device's segments directory.
///
/// Wraps [`SegmentIntegrityScrubber`] to produce [`VerificationOutcome`]
/// results suitable for aggregation into a pool-level [`HealthReport`].
pub fn run_segment_check(
    config: &SegmentCheckConfig,
    cursor: &mut ScrubCursor,
) -> SegmentCheckResult {
    let scrubber = SegmentIntegrityScrubber::new(&config.segments_dir);
    let mut suspect_log = SuspectLog::new();

    let scrub_report = match scrubber.scrub_incremental(
        cursor,
        config.max_records,
        config.max_bytes,
        &mut suspect_log,
    ) {
        Ok(report) => report,
        Err(e) => {
            // If the scrubber itself failed, produce a single unreadable
            // outcome covering whatever we tried to scan.
            let outcomes = vec![VerificationOutcome::Unreadable {
                segment_id: cursor.segment_id,
                reason: format!("scrub error: {e}"),
            }];
            return SegmentCheckResult {
                outcomes,
                records_verified: 0,
                bytes_scanned: 0,
                completed: false,
                cursor: *cursor,
                scrub_report: ScrubReport::default(),
            };
        }
    };

    let mut outcomes = Vec::new();

    // Map ScrubOutcome -> VerificationOutcome.
    for out in &scrub_report.outcomes {
        let vo = match out {
            tidefs_local_object_store::ScrubOutcome::Clean { segment_id } => {
                VerificationOutcome::Pass {
                    segment_id: *segment_id,
                    records_verified: 0, // per-segment record count not tracked individually
                    bytes_scanned: 0,
                }
            }
            tidefs_local_object_store::ScrubOutcome::PayloadMismatch {
                segment_id,
                record_offset: _,
                expected: _,
                actual: _,
            }
            | tidefs_local_object_store::ScrubOutcome::RecordDigestMismatch {
                segment_id,
                record_offset: _,
                expected: _,
                actual: _,
            } => VerificationOutcome::Mismatch {
                segment_id: *segment_id,
                mismatched_records: 1,
                records_verified: 0,
            },
            tidefs_local_object_store::ScrubOutcome::ChainBroken { segment_id, .. }
            | tidefs_local_object_store::ScrubOutcome::TruncatedSegment { segment_id } => {
                VerificationOutcome::Truncated {
                    segment_id: *segment_id,
                }
            }
        };
        outcomes.push(vo);
    }

    // No per-segment outcome means the caller can keep aggregate scan counters,
    // but it must not infer a per-segment PASS.

    SegmentCheckResult {
        outcomes,
        records_verified: scrub_report.records_verified,
        bytes_scanned: scrub_report.bytes_scanned,
        completed: scrub_report.completed,
        cursor: scrub_report.cursor,
        scrub_report,
    }
}

/// Run a full (non-incremental) check on a segments directory.
pub fn run_full_segment_check(config: &SegmentCheckConfig) -> SegmentCheckResult {
    let mut cursor = ScrubCursor::default();
    run_segment_check(config, &mut cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tidefs_local_object_store::{LocalObjectStore, StoreOptions};

    fn make_store(dir: &Path) {
        let opts = StoreOptions {
            max_segment_bytes: 4096,
            segment_count: 8,
            sync_on_write: true,
            ..StoreOptions::test_fast()
        };
        let mut store = LocalObjectStore::open_with_options(dir, opts).unwrap();
        for i in 0u8..3 {
            store.put_named(format!("obj-{i}"), &[i; 100]).unwrap();
        }
        store.flush_segment().unwrap();
        store.sync_all().unwrap();
        drop(store);
    }

    #[test]
    fn clean_store_produces_no_mismatches() {
        let tmp = tempfile::TempDir::with_prefix("segchk-clean").unwrap();
        make_store(tmp.path());
        let seg_dir = tmp.path().join("segments");

        let config = SegmentCheckConfig::new(&seg_dir);
        let result = run_full_segment_check(&config);

        // Clean store: no payload/record mismatches or chain breaks.
        assert!(result.outcomes.iter().all(|o| {
            matches!(
                o,
                VerificationOutcome::Pass { .. } | VerificationOutcome::Truncated { .. }
            )
            // Truncated may appear for segments without footer (active segment).
        }));
        assert!(result.records_verified > 0);
    }

    #[test]
    fn corrupted_store_detects_mismatch() {
        let tmp = tempfile::TempDir::with_prefix("segchk-corr").unwrap();
        make_store(tmp.path());
        let seg_dir = tmp.path().join("segments");

        // Corrupt a byte in the first segment's payload area.
        let mut entries: Vec<_> = fs::read_dir(&seg_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        if let Some(entry) = entries.first() {
            let path = entry.path();
            let len = fs::metadata(&path).unwrap().len();
            if len > 64 {
                let mut data = fs::read(&path).unwrap();
                data[32] ^= 0xFF; // corrupt payload byte
                fs::write(&path, &data).unwrap();
            }
        }

        let config = SegmentCheckConfig::new(&seg_dir);
        let result = run_full_segment_check(&config);

        // Should find at least one mismatch or chain issue.
        let has_issue = result.outcomes.iter().any(|o| !o.is_healthy());
        assert!(
            has_issue || result.scrub_report.chain_breaks_detected > 0,
            "corrupted data must produce an unhealthy outcome"
        );
    }

    #[test]
    fn config_builder_methods() {
        let cfg = SegmentCheckConfig::new("/tmp/segs")
            .with_limits(100, 4096)
            .with_device_path("/dev/sda");
        assert_eq!(cfg.max_records, 100);
        assert_eq!(cfg.max_bytes, 4096);
        assert!(cfg
            .device_path
            .as_ref()
            .unwrap()
            .to_str()
            .unwrap()
            .contains("sda"));
    }

    #[test]
    fn nonexistent_dir_produces_unreadable() {
        let config = SegmentCheckConfig::new("/nonexistent/segments/path");
        let result = run_full_segment_check(&config);
        assert!(!result.outcomes.is_empty());
    }
}
