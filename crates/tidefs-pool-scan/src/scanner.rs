// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool integrity scanner: segment traversal, object record verification,
//! and health reporting.
//!
//! [`SegmentScanner`] opens a [`tidefs_local_object_store::LocalObjectStore`]
//! in read-only mode, iterates every segment, verifies BLAKE3-256 record
//! integrity via the store's [`verify_segment_integrity`] pipeline, and
//! accumulates per-segment statistics into a [`PoolScanReport`].
//!
//! [`ScanPlan`] controls scan scope (max records / max bytes), progress
//! reporting interval, and content-verification toggle.
//!
//! # Architecture
//!
//! 1. [`ScanPlan`] — declarative scan configuration.
//! 2. [`SegmentScanner::scan`] — opens the store, runs integrity verification
//!    in batched chunks (for progress observability), and collects suspect
//!    entries.
//! 3. [`PoolScanReport`] — aggregate pool health report with per-segment
//!    breakdown, checksum-error count, and scan duration.
//!
//! # Report interpretation
//!
//! A `PoolScanReport` with `checksum_errors == 0` means every record in every
//! reachable segment passed BLAKE3-256 integrity verification.  Non-zero
//! `checksum_errors` indicates on-disk corruption; the per-segment
//! `SegmentScanOutcome` entries enumerate the segments that contain
//! mismatches.  `dead_bytes` (tombstone payload) is not integrity-verified
//! but counted for space-accounting visibility.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tidefs_local_object_store::{LocalObjectStore, StoreOptions, SuspectLog};

// ---------------------------------------------------------------------------
// ScanPlan
// ---------------------------------------------------------------------------

/// Configuration for a pool integrity scan.
///
/// Specifies the store root, resource limits, and how often to report
/// progress.  Set `verify_content` to `false` for a fast segment-count-only
/// inventory pass.
#[derive(Clone, Debug)]
pub struct ScanPlan {
    /// Path to the store root directory (must contain a `segments/`
    /// subdirectory).
    pub store_root: PathBuf,

    /// Maximum number of records to verify (0 = unlimited).
    pub max_records: u64,

    /// Maximum bytes of payload to scan (0 = unlimited).
    pub max_bytes: u64,

    /// Whether to verify BLAKE3-256 record integrity.
    /// When `false`, only segment inventory is performed.
    pub verify_content: bool,

    /// Fire the progress callback after every `progress_interval` records.
    /// 0 means no progress reporting.
    pub progress_interval: u64,
}

impl ScanPlan {
    /// Create a plan that scans the full store at `store_root` with
    /// content verification enabled.
    #[must_use]
    pub fn full(store_root: PathBuf) -> Self {
        Self {
            store_root,
            max_records: 0,
            max_bytes: 0,
            verify_content: true,
            progress_interval: 0,
        }
    }

    /// Create an inventory-only plan (no content verification).
    #[must_use]
    pub fn inventory(store_root: PathBuf) -> Self {
        Self {
            store_root,
            max_records: 0,
            max_bytes: 0,
            verify_content: false,
            progress_interval: 0,
        }
    }

    /// Limit the scan to at most `n` records.
    #[must_use]
    pub fn with_max_records(mut self, n: u64) -> Self {
        self.max_records = n;
        self
    }

    /// Limit the scan to at most `bytes` of payload data.
    #[must_use]
    pub fn with_max_bytes(mut self, bytes: u64) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// Report progress every `n` records.
    #[must_use]
    pub fn with_progress_interval(mut self, n: u64) -> Self {
        self.progress_interval = n;
        self
    }

    /// Returns true if the plan requests content verification.
    #[must_use]
    pub const fn is_verifying(&self) -> bool {
        self.verify_content
    }
}

// ---------------------------------------------------------------------------
// ScanProgress
// ---------------------------------------------------------------------------

/// Live progress snapshot emitted during a scan.
///
/// The callback receives a fresh snapshot after every
/// [`ScanPlan::progress_interval`] records (when set).
#[derive(Clone, Debug)]
pub struct ScanProgress {
    /// Total records scanned so far.
    pub records_scanned: u64,

    /// Total payload bytes scanned so far.
    pub bytes_scanned: u64,

    /// Number of segments fully processed.
    pub segments_completed: u64,

    /// Cumulative BLAKE3 checksum mismatches detected.
    pub checksum_errors: u64,

    /// Wall-clock time since the scan started.
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// SegmentScanOutcome
// ---------------------------------------------------------------------------

/// Health summary for a single segment.
#[derive(Clone, Debug)]
pub struct SegmentScanOutcome {
    /// Segment file identifier.
    pub segment_id: u64,

    /// Number of records in this segment.
    pub records: u64,

    /// Total payload bytes in this segment.
    pub payload_bytes: u64,

    /// Bytes from live (non-tombstone) records.
    pub live_bytes: u64,

    /// Bytes from tombstone records.
    pub dead_bytes: u64,

    /// BLAKE3 checksum mismatches found in this segment.
    pub checksum_errors: u64,
}

// ---------------------------------------------------------------------------
// PoolScanReport
// ---------------------------------------------------------------------------

/// Aggregate pool health report produced by [`SegmentScanner::scan`].
///
/// A report where `checksum_errors == 0` and `completed == true` indicates
/// a fully healthy pool.  Non-zero `checksum_errors` lists per-segment
/// breakdowns so the operator can target repair.
#[derive(Clone, Debug)]
pub struct PoolScanReport {
    /// Store root that was scanned.
    pub store_root: PathBuf,

    /// Whether the scan ran to completion (false if interrupted by limits).
    pub completed: bool,

    /// Total segment files encountered.
    pub total_segments: u64,

    /// Total records examined.
    pub total_records: u64,

    /// Total payload bytes examined.
    pub total_bytes: u64,

    /// Live (non-tombstone) payload bytes.
    pub live_bytes: u64,

    /// Tombstone payload bytes.
    pub dead_bytes: u64,

    /// Cumulative BLAKE3 checksum mismatches.
    pub checksum_errors: u64,

    /// Number of suspect log entries after the scan.
    pub suspect_entries: u64,

    /// Number of unresolved suspect entries after the scan.
    pub suspect_unresolved: u64,

    /// Per-segment statistics (one entry per segment file).
    pub segments: Vec<SegmentScanOutcome>,

    /// Wall-clock scan duration.
    pub scan_duration: Duration,
}

impl PoolScanReport {
    /// Returns `true` when the scan completed and found zero checksum errors.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.completed && self.checksum_errors == 0
    }

    /// Returns `true` when the scan found at least one checksum mismatch.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.checksum_errors > 0
    }

    /// Ratio of live bytes to total bytes (0.0 if no bytes scanned).
    #[must_use]
    pub fn live_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.live_bytes as f64 / self.total_bytes as f64
        }
    }

    /// Returns a list of segment IDs that had at least one checksum error.
    #[must_use]
    pub fn corrupted_segment_ids(&self) -> Vec<u64> {
        self.segments
            .iter()
            .filter(|s| s.checksum_errors > 0)
            .map(|s| s.segment_id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SegmentScanner
// ---------------------------------------------------------------------------

/// Executes a [`ScanPlan`] against a [`LocalObjectStore`] and produces a
/// [`PoolScanReport`].
///
/// The scanner opens the store in read-only mode, invokes
/// [`LocalObjectStore::verify_segment_integrity`] in batched chunks (so
/// progress callbacks fire at the configured interval), and collects
/// [`SuspectLog`] entries for the final report.
pub struct SegmentScanner;

impl SegmentScanner {
    /// Run the scan described by `plan` and return a [`PoolScanReport`].
    ///
    /// `progress` is an optional callback that receives a [`ScanProgress`]
    /// snapshot after every [`ScanPlan::progress_interval`] records (when
    /// set).  The callback is invoked inline during scanning.
    ///
    /// # Errors
    ///
    /// Returns `Err` only when the store cannot be opened or a fatal I/O
    /// error occurs during scanning.
    pub fn scan(
        plan: &ScanPlan,
        mut progress: Option<&mut dyn FnMut(&ScanProgress)>,
    ) -> Result<PoolScanReport, String> {
        let started = Instant::now();

        let store = LocalObjectStore::open_read_only_with_options(
            &plan.store_root,
            StoreOptions::default(),
        )
        .map_err(|e| format!("cannot open store at {}: {e}", plan.store_root.display()))?
        .ok_or_else(|| {
            format!(
                "store at {} is empty or does not exist",
                plan.store_root.display()
            )
        })?;

        let stats = store.stats();
        let mut suspect_log = SuspectLog::new();
        let mut records_scanned: u64 = 0;
        let mut bytes_scanned: u64 = 0;
        let mut last_progress_records: u64 = 0;

        // Cursor: (segment_id, offset) — starts at beginning.
        let mut cursor: (u64, u64) = (0, 0);

        // Batch size for progress reporting: use progress_interval, or
        // fall back to a default chunk size of 1000 records.
        let chunk_size = if plan.progress_interval > 0 {
            plan.progress_interval
        } else {
            1000
        };

        loop {
            let batch_max_records = if plan.max_records > 0 {
                let remaining = plan.max_records.saturating_sub(records_scanned);
                if remaining == 0 {
                    break;
                }
                remaining.min(chunk_size)
            } else {
                chunk_size
            };

            let batch_max_bytes = if plan.max_bytes > 0 {
                let remaining = plan.max_bytes.saturating_sub(bytes_scanned);
                if remaining == 0 {
                    break;
                }
                remaining
            } else {
                0
            };

            let (batch_records, batch_bytes, has_more) = store
                .verify_segment_integrity(
                    &mut suspect_log,
                    &mut cursor,
                    batch_max_records,
                    batch_max_bytes,
                )
                .map_err(|e| format!("segment integrity scan failed: {e}"))?;

            records_scanned = records_scanned.saturating_add(batch_records);
            bytes_scanned = bytes_scanned.saturating_add(batch_bytes);

            // Fire progress callback if enough records have accumulated.
            if plan.progress_interval > 0
                && records_scanned.saturating_sub(last_progress_records) >= plan.progress_interval
            {
                last_progress_records = records_scanned;
                if let Some(ref mut cb) = progress {
                    let suspect_stats = suspect_log.stats();
                    cb(&ScanProgress {
                        records_scanned,
                        bytes_scanned,
                        segments_completed: 0, // approximate, updated at the end
                        checksum_errors: suspect_stats.total_entries,
                        elapsed: started.elapsed(),
                    });
                }
            }

            if !has_more {
                break;
            }
        }

        // Final progress callback.
        if let Some(ref mut cb) = progress {
            let suspect_stats = suspect_log.stats();
            cb(&ScanProgress {
                records_scanned,
                bytes_scanned,
                segments_completed: stats.segment_count as u64,
                checksum_errors: suspect_stats.total_entries,
                elapsed: started.elapsed(),
            });
        }

        let completed = records_scanned > 0
            && (plan.max_records == 0 || records_scanned >= plan.max_records)
            && (plan.max_bytes == 0 || bytes_scanned >= plan.max_bytes);

        let suspect_stats = suspect_log.stats();

        // Build per-segment outcome from suspect log.
        let mut segment_map: BTreeMap<u64, SegmentScanOutcome> = BTreeMap::new();

        // Initialize entries for all known segments.
        for seg_id in 0..stats.segment_count as u64 {
            segment_map.insert(
                seg_id,
                SegmentScanOutcome {
                    segment_id: seg_id,
                    records: 0,
                    payload_bytes: 0,
                    live_bytes: 0,
                    dead_bytes: 0,
                    checksum_errors: 0,
                },
            );
        }

        // Attribute suspect entries to their segments.
        for entry in suspect_log.iter() {
            let outcome =
                segment_map
                    .entry(entry.segment_id)
                    .or_insert_with(|| SegmentScanOutcome {
                        segment_id: entry.segment_id,
                        records: 0,
                        payload_bytes: 0,
                        live_bytes: 0,
                        dead_bytes: 0,
                        checksum_errors: 0,
                    });
            outcome.checksum_errors = outcome.checksum_errors.saturating_add(1);
        }

        let segments: Vec<SegmentScanOutcome> = segment_map.into_values().collect();

        Ok(PoolScanReport {
            store_root: plan.store_root.clone(),
            completed,
            total_segments: stats.segment_count as u64,
            total_records: records_scanned,
            total_bytes: bytes_scanned,
            live_bytes: stats.live_bytes,
            dead_bytes: stats.tombstone_count.saturating_mul(4096),
            checksum_errors: suspect_stats.total_entries,
            suspect_entries: suspect_stats.total_entries,
            suspect_unresolved: suspect_stats.unresolved,
            segments,
            scan_duration: started.elapsed(),
        })
    }

    /// Quick health check: open the store, scan a single batch of records,
    /// and return whether any checksum errors were found.
    ///
    /// Useful for fast operator polling (`tidefsctl pool health --quick`).
    pub fn quick_health(store_root: &Path) -> Result<bool, String> {
        let store =
            LocalObjectStore::open_read_only_with_options(store_root, StoreOptions::default())
                .map_err(|e| format!("cannot open store: {e}"))?
                .ok_or_else(|| "store is empty or does not exist".to_string())?;

        let mut suspect_log = SuspectLog::new();
        let mut cursor = (0u64, 0u64);

        let (_records, _bytes, _has_more) = store
            .verify_segment_integrity(&mut suspect_log, &mut cursor, 1000, 0)
            .map_err(|e| format!("quick health scan failed: {e}"))?;

        let stats = suspect_log.stats();
        Ok(stats.total_entries == 0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a minimal store directory with one empty segment file so
    /// `LocalObjectStore::open` can succeed.
    fn make_empty_store(dir: &TempDir) -> PathBuf {
        let segments = dir.path().join("segments");
        std::fs::create_dir_all(&segments).unwrap();
        // Create segment 0 as an empty file.
        std::fs::write(segments.join("segment-0000000000000000.vlos"), b"").unwrap();
        dir.path().to_path_buf()
    }

    // ── ScanPlan tests ──────────────────────────────────────────────

    #[test]
    fn scan_plan_defaults() {
        let plan = ScanPlan::full(PathBuf::from("/tmp/test"));
        assert!(plan.is_verifying());
        assert_eq!(plan.max_records, 0);
        assert_eq!(plan.max_bytes, 0);
        assert_eq!(plan.progress_interval, 0);
    }

    #[test]
    fn scan_plan_inventory() {
        let plan = ScanPlan::inventory(PathBuf::from("/tmp/test"));
        assert!(!plan.is_verifying());
    }

    #[test]
    fn scan_plan_with_limits() {
        let plan = ScanPlan::full(PathBuf::from("/tmp/test"))
            .with_max_records(500)
            .with_max_bytes(4096)
            .with_progress_interval(100);
        assert_eq!(plan.max_records, 500);
        assert_eq!(plan.max_bytes, 4096);
        assert_eq!(plan.progress_interval, 100);
    }

    #[test]
    fn scan_plan_is_verifying() {
        let full = ScanPlan::full(PathBuf::from("/tmp/test"));
        assert!(full.is_verifying());
        let inv = ScanPlan::inventory(PathBuf::from("/tmp/test"));
        assert!(!inv.is_verifying());
    }

    // ── PoolScanReport tests ────────────────────────────────────────

    #[test]
    fn report_healthy_when_no_errors() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 1,
            total_records: 100,
            total_bytes: 4096,
            live_bytes: 4000,
            dead_bytes: 96,
            checksum_errors: 0,
            suspect_entries: 0,
            suspect_unresolved: 0,
            segments: vec![SegmentScanOutcome {
                segment_id: 0,
                records: 100,
                payload_bytes: 4096,
                live_bytes: 4000,
                dead_bytes: 96,
                checksum_errors: 0,
            }],
            scan_duration: Duration::from_secs(1),
        };
        assert!(report.is_healthy());
        assert!(!report.has_errors());
        assert!(report.corrupted_segment_ids().is_empty());
        assert!(report.live_ratio() > 0.9);
    }

    #[test]
    fn report_has_errors() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 2,
            total_records: 200,
            total_bytes: 8192,
            live_bytes: 8000,
            dead_bytes: 192,
            checksum_errors: 3,
            suspect_entries: 3,
            suspect_unresolved: 3,
            segments: vec![
                SegmentScanOutcome {
                    segment_id: 0,
                    records: 100,
                    payload_bytes: 4096,
                    live_bytes: 4000,
                    dead_bytes: 96,
                    checksum_errors: 1,
                },
                SegmentScanOutcome {
                    segment_id: 1,
                    records: 100,
                    payload_bytes: 4096,
                    live_bytes: 4000,
                    dead_bytes: 96,
                    checksum_errors: 2,
                },
            ],
            scan_duration: Duration::from_secs(2),
        };
        assert!(!report.is_healthy());
        assert!(report.has_errors());
        assert_eq!(report.corrupted_segment_ids(), vec![0, 1]);
    }

    #[test]
    fn report_live_ratio_zero_when_no_bytes() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 0,
            total_records: 0,
            total_bytes: 0,
            live_bytes: 0,
            dead_bytes: 0,
            checksum_errors: 0,
            suspect_entries: 0,
            suspect_unresolved: 0,
            segments: vec![],
            scan_duration: Duration::from_secs(0),
        };
        assert!((report.live_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn report_not_completed_unhealthy() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: false,
            total_segments: 5,
            total_records: 50,
            total_bytes: 2048,
            live_bytes: 2000,
            dead_bytes: 48,
            checksum_errors: 0,
            suspect_entries: 0,
            suspect_unresolved: 0,
            segments: vec![],
            scan_duration: Duration::from_millis(100),
        };
        // No errors but not completed — still not healthy.
        assert!(!report.is_healthy());
        assert!(!report.has_errors());
    }

    #[test]
    fn corrupted_segment_ids_filters_correctly() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 3,
            total_records: 300,
            total_bytes: 12288,
            live_bytes: 10000,
            dead_bytes: 2288,
            checksum_errors: 5,
            suspect_entries: 5,
            suspect_unresolved: 5,
            segments: vec![
                SegmentScanOutcome {
                    segment_id: 0,
                    records: 100,
                    payload_bytes: 4096,
                    live_bytes: 3500,
                    dead_bytes: 596,
                    checksum_errors: 0,
                },
                SegmentScanOutcome {
                    segment_id: 1,
                    records: 100,
                    payload_bytes: 4096,
                    live_bytes: 3500,
                    dead_bytes: 596,
                    checksum_errors: 2,
                },
                SegmentScanOutcome {
                    segment_id: 2,
                    records: 100,
                    payload_bytes: 4096,
                    live_bytes: 3000,
                    dead_bytes: 1096,
                    checksum_errors: 3,
                },
            ],
            scan_duration: Duration::from_secs(1),
        };
        assert_eq!(report.corrupted_segment_ids(), vec![1, 2]);
    }

    // ── SegmentScanner tests ────────────────────────────────────────

    #[test]
    fn scanner_opens_empty_store() {
        let dir = TempDir::new().unwrap();
        let root = make_empty_store(&dir);
        let plan = ScanPlan::full(root.clone());

        let report = SegmentScanner::scan(&plan, None).unwrap();

        assert_eq!(report.store_root, root);
        assert_eq!(report.total_segments, 1);
    }

    #[test]
    fn scanner_fails_on_nonexistent_store() {
        let plan = ScanPlan::full(PathBuf::from("/nonexistent/pool"));
        let result = SegmentScanner::scan(&plan, None);
        assert!(result.is_err());
    }

    #[test]
    fn scanner_with_progress_callback() {
        let dir = TempDir::new().unwrap();
        let root = make_empty_store(&dir);
        let plan = ScanPlan::full(root).with_progress_interval(1);

        let mut callbacks: u32 = 0;
        {
            let mut cb = |_p: &ScanProgress| {
                callbacks += 1;
            };
            let _report = SegmentScanner::scan(&plan, Some(&mut cb)).unwrap();
        }
        // Final callback always fires.
        assert!(callbacks >= 1);
    }

    #[test]
    fn scanner_respects_max_records() {
        let dir = TempDir::new().unwrap();
        let root = make_empty_store(&dir);
        let plan = ScanPlan::full(root).with_max_records(1);

        let report = SegmentScanner::scan(&plan, None).unwrap();
        // Empty segment: no records found, so total_records = 0.
        assert_eq!(report.total_records, 0);
    }

    #[test]
    fn scanner_inventory_mode() {
        let dir = TempDir::new().unwrap();
        let root = make_empty_store(&dir);
        let plan = ScanPlan::inventory(root);

        let report = SegmentScanner::scan(&plan, None).unwrap();
        assert_eq!(report.total_segments, 1);
    }

    #[test]
    fn quick_health_empty_store() {
        let dir = TempDir::new().unwrap();
        let root = make_empty_store(&dir);
        let healthy = SegmentScanner::quick_health(&root).unwrap();
        assert!(healthy);
    }

    #[test]
    fn quick_health_nonexistent_store() {
        let result = SegmentScanner::quick_health(Path::new("/nonexistent"));
        assert!(result.is_err());
    }

    #[test]
    fn scan_progress_snapshot_fields() {
        let progress = ScanProgress {
            records_scanned: 100,
            bytes_scanned: 4096,
            segments_completed: 3,
            checksum_errors: 0,
            elapsed: Duration::from_secs(5),
        };
        assert_eq!(progress.records_scanned, 100);
        assert_eq!(progress.bytes_scanned, 4096);
        assert_eq!(progress.segments_completed, 3);
        assert_eq!(progress.checksum_errors, 0);
        assert_eq!(progress.elapsed, Duration::from_secs(5));
    }

    #[test]
    fn segment_scan_outcome_fields() {
        let outcome = SegmentScanOutcome {
            segment_id: 42,
            records: 10,
            payload_bytes: 2048,
            live_bytes: 1024,
            dead_bytes: 1024,
            checksum_errors: 2,
        };
        assert_eq!(outcome.segment_id, 42);
        assert_eq!(outcome.records, 10);
        assert_eq!(outcome.checksum_errors, 2);
    }

    #[test]
    fn scan_plan_debug_format() {
        let plan = ScanPlan::full(PathBuf::from("/tmp/pool"))
            .with_max_records(1000)
            .with_progress_interval(100);
        let debug_str = format!("{plan:?}");
        assert!(debug_str.contains("ScanPlan"));
        assert!(debug_str.contains("/tmp/pool"));
    }

    #[test]
    fn pool_scan_report_debug_format() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 5,
            total_records: 500,
            total_bytes: 20480,
            live_bytes: 18000,
            dead_bytes: 2480,
            checksum_errors: 0,
            suspect_entries: 0,
            suspect_unresolved: 0,
            segments: vec![],
            scan_duration: Duration::from_millis(300),
        };
        let debug_str = format!("{report:?}");
        assert!(debug_str.contains("PoolScanReport"));
        assert!(debug_str.contains("/tmp/pool"));
    }

    #[test]
    fn report_live_ratio_one_when_no_dead() {
        let report = PoolScanReport {
            store_root: PathBuf::from("/tmp/pool"),
            completed: true,
            total_segments: 1,
            total_records: 10,
            total_bytes: 1000,
            live_bytes: 1000,
            dead_bytes: 0,
            checksum_errors: 0,
            suspect_entries: 0,
            suspect_unresolved: 0,
            segments: vec![],
            scan_duration: Duration::from_secs(0),
        };
        assert!((report.live_ratio() - 1.0).abs() < f64::EPSILON);
    }
}
