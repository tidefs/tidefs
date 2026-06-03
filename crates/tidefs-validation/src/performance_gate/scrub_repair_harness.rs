//! Scrub, repair, and rebuild performance benchmark harness.
//!
//! Provides throughput and latency measurement for:
//!
//! - Segment-level integrity scrub (`SegmentIntegrityScrubber`)
//! - Checksum-tree payload verification (`scrub_checksum_tree`)
//! - Torn-tail repair during `LocalObjectStore` reopen
//!
//! All measurements are cargo/unit tier (Tier 1) — they exercise the
//! production scrub/repair code paths against a temp directory store
//! and produce `BenchmarkResult` objects with throughput KPIs suitable
//! for the performance gate matrix.

use super::benchmark_harness::BenchmarkResult;
use super::validation_tier::ValidationTier;
use super::gate_entry::MeasuredKpi;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Harness that measures scrub, repair, and rebuild performance against
/// a local object store.
pub struct ScrubRepairHarness {
    /// Temp directory root for store creation.
    pub store_root: PathBuf,
    /// Whether to enable verify_read_checksums (adds cpu cost).
    pub verify_checksums: bool,
}

impl ScrubRepairHarness {
    pub fn new(store_root: impl AsRef<Path>) -> Self {
        Self {
            store_root: store_root.as_ref().to_path_buf(),
            verify_checksums: false,
        }
    }

    /// Enable read-side checksum verification during measurement.
    pub fn with_verify_checksums(mut self, v: bool) -> Self {
        self.verify_checksums = v;
        self
    }

    // ------------------------------------------------------------------
    // Scrub throughput: segment-level integrity verification
    // ------------------------------------------------------------------

    /// Create a store with `object_count` objects of `object_size` bytes,
    /// sync, close, then run `SegmentIntegrityScrubber::scrub_incremental`
    /// and measure records/sec and bytes/sec throughput.
    pub fn measure_segment_scrub(&self, object_count: u64, object_size: usize) -> BenchmarkResult {
        let subject = "scrub-segment-integrity";
        let desc = format!(
            "segment scrub: {} objects x {} bytes",
            object_count, object_size
        );

        let _ = std::fs::remove_dir_all(&self.store_root);
        if std::fs::create_dir_all(&self.store_root).is_err() {
            return BenchmarkResult::refused(
                subject,
                format!("cannot create store root {:?}", self.store_root),
                ValidationTier::Kbuild,
            );
        }

        let opts = tidefs_local_object_store::StoreOptions {
            max_segment_bytes: 64 * 1024 * 1024,
            sync_on_write: false,
            repair_torn_tail: false,
            segment_rotation_interval_secs: 3600,
            segment_rotation_write_limit: u64::MAX,
            background_scrub_interval_secs: 0,
            segment_count: 16,
            mirror_path: None,
            replica_paths: Vec::new(),
            durability_layout: None,
            fault_injection_config: None,
            reclaim_enabled: false,
            write_throttle_enabled: false,
            verify_read_checksums: self.verify_checksums,
        };

        let mut store = match tidefs_local_object_store::LocalObjectStore::open_with_options(
            &self.store_root,
            opts.clone(),
        ) {
            Ok(s) => s,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("store open failed: {e:?}"),
                    ValidationTier::Kbuild,
                );
            }
        };

        let payload: Vec<u8> = (0..object_size).map(|i| (i % 251) as u8).collect();
        for i in 0..object_count {
            let key = tidefs_local_object_store::ObjectKey::from_name(&format!("obj-{i:06}"));
            if let Err(e) = store.put(key, &payload) {
                return BenchmarkResult::refused(
                    subject,
                    format!("put obj {i}: {e:?}"),
                    ValidationTier::Kbuild,
                );
            }
        }
        if let Err(e) = store.sync_all() {
            return BenchmarkResult::refused(
                subject,
                format!("sync_all: {e:?}"),
                ValidationTier::Kbuild,
            );
        }
        drop(store);

        let segments_dir = self.store_root.join("segments");
        let scrubber = tidefs_local_object_store::SegmentIntegrityScrubber::new(&segments_dir);
        let mut cursor = tidefs_local_object_store::ScrubCursor::default();
        let mut suspect_log = tidefs_local_object_store::SuspectLog::new();

        let t0 = Instant::now();
        let report = match scrubber.scrub_incremental(&mut cursor, 0, 0, &mut suspect_log) {
            Ok(r) => r,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("scrub_incremental failed: {e:?}"),
                    ValidationTier::Kbuild,
                );
            }
        };
        let elapsed = t0.elapsed().as_secs_f64();

        let recs_per_sec = if elapsed > 0.0 {
            report.records_verified as f64 / elapsed
        } else {
            0.0
        };
        let bytes_per_sec = if elapsed > 0.0 {
            report.bytes_scanned as f64 / elapsed
        } else {
            0.0
        };

        let _ = std::fs::remove_dir_all(&self.store_root);

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: elapsed,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "scrub.records-per-sec".into(),
                    name: "scrub_records_per_sec".into(),
                    value: recs_per_sec,
                    unit: "records/s".into(),
                    passed: Some(report.records_verified > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "scrub.bytes-per-sec".into(),
                    name: "scrub_bytes_per_sec".into(),
                    value: bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(report.bytes_scanned > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "scrub.segments".into(),
                    name: "segments_scanned".into(),
                    value: report.segments_scanned as f64,
                    unit: "segments".into(),
                    passed: Some(report.segments_scanned > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "scrub.records".into(),
                    name: "records_verified".into(),
                    value: report.records_verified as f64,
                    unit: "records".into(),
                    passed: Some(report.records_verified > 0),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::Kbuild,
            stdout_tail: format!(
                "scrub complete: {} records, {} bytes in {:.3}s",
                report.records_verified, report.bytes_scanned, elapsed
            ),
            stderr_tail: String::new(),
        }
    }

    // ------------------------------------------------------------------
    // Checksum-tree scrub throughput
    // ------------------------------------------------------------------

    /// Measure checksum-tree payload verification throughput against
    /// in-memory data with a checksum tree.
    pub fn measure_checksum_scrub(&self, data_size: usize, block_size: usize) -> BenchmarkResult {
        let subject = "scrub-checksum-tree";
        let desc = format!(
            "checksum scrub: {} bytes, block size {}",
            data_size, block_size
        );

        let data: Vec<u8> = (0..data_size).map(|i| (i % 251) as u8).collect();

        // Build checksum tree: compute leaf digests, then construct tree.
        let effective_block = if block_size > 0 && block_size <= data_size {
            block_size
        } else {
            4096
        };
        let tree = {
            let leaves: Vec<[u8; 32]> = data
                .chunks(effective_block)
                .map(|chunk| *blake3::hash(chunk).as_bytes())
                .collect();
            tidefs_checksum_tree::ChecksumTree::from_leaves(&leaves, effective_block)
        };

        let t0 = Instant::now();
        let report = tidefs_local_object_store::scrub_checksum_tree(&tree, &data);
        let elapsed = t0.elapsed().as_secs_f64();

        let bytes_per_sec = if elapsed > 0.0 {
            data_size as f64 / elapsed
        } else {
            0.0
        };
        let clean_ratio = if report.leaves_examined > 0 {
            report.leaves_clean as f64 / report.leaves_examined as f64
        } else {
            0.0
        };

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: elapsed,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "csum-scrub.bytes-per-sec".into(),
                    name: "checksum_scrub_bytes_per_sec".into(),
                    value: bytes_per_sec,
                    unit: "bytes/s".into(),
                    passed: Some(report.is_clean()),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "csum-scrub.leaves".into(),
                    name: "leaves_verified".into(),
                    value: report.leaves_examined as f64,
                    unit: "leaves".into(),
                    passed: Some(report.leaves_examined > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "csum-scrub.clean-ratio".into(),
                    name: "clean_ratio".into(),
                    value: clean_ratio,
                    unit: "ratio".into(),
                    passed: Some(report.is_clean()),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::Kbuild,
            stdout_tail: format!(
                "checksum scrub: {} leaves, clean={}, {:.3}s",
                report.leaves_examined,
                report.is_clean(),
                elapsed
            ),
            stderr_tail: String::new(),
        }
    }

    // ------------------------------------------------------------------
    // Torn-tail repair performance
    // ------------------------------------------------------------------

    /// Measure repair/recovery throughput.
    ///
    /// Creates a store, writes objects across multiple segments, corrupts
    /// the tail of the last segment, then reopens with `repair_torn_tail:
    /// true` and measures recovery time and surviving object count.
    pub fn measure_torn_tail_repair(
        &self,
        object_count: u64,
        object_size: usize,
    ) -> BenchmarkResult {
        let subject = "repair-torn-tail";
        let desc = format!(
            "torn-tail repair: {} objects x {} bytes",
            object_count, object_size
        );

        let _ = std::fs::remove_dir_all(&self.store_root);
        if std::fs::create_dir_all(&self.store_root).is_err() {
            return BenchmarkResult::refused(
                subject,
                format!("cannot create store root {:?}", self.store_root),
                ValidationTier::Kbuild,
            );
        }

        let mut opts = tidefs_local_object_store::StoreOptions {
            max_segment_bytes: 64 * 1024,
            sync_on_write: false,
            repair_torn_tail: false,
            segment_rotation_interval_secs: 3600,
            segment_rotation_write_limit: u64::MAX,
            background_scrub_interval_secs: 0,
            segment_count: 16,
            mirror_path: None,
            replica_paths: Vec::new(),
            durability_layout: None,
            fault_injection_config: None,
            reclaim_enabled: false,
            write_throttle_enabled: false,
            verify_read_checksums: self.verify_checksums,
        };

        let payload: Vec<u8> = (0..object_size).map(|i| (i % 251) as u8).collect();
        let segment_path_b: PathBuf;

        {
            let mut store = match tidefs_local_object_store::LocalObjectStore::open_with_options(
                &self.store_root,
                opts.clone(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    return BenchmarkResult::refused(
                        subject,
                        format!("store open failed: {e:?}"),
                        ValidationTier::Kbuild,
                    );
                }
            };

            for i in 0..object_count {
                let key = tidefs_local_object_store::ObjectKey::from_name(&format!("obj-{i:06}"));
                if let Err(e) = store.put(key, &payload) {
                    return BenchmarkResult::refused(
                        subject,
                        format!("put obj {i}: {e:?}"),
                        ValidationTier::Kbuild,
                    );
                }
                if i % 10 == 0 {
                    let _ = store.flush_segment();
                }
            }
            if let Err(e) = store.sync_all() {
                return BenchmarkResult::refused(
                    subject,
                    format!("sync_all: {e:?}"),
                    ValidationTier::Kbuild,
                );
            }

            let segments_dir = store.segments_dir().to_path_buf();
            // Discover segment IDs from filesystem directory listing
            let mut ids: Vec<u64> = match std::fs::read_dir(&segments_dir) {
                Ok(entries) => entries
                    .filter_map(|e| {
                        let e = e.ok()?;
                        let name = e.file_name().into_string().ok()?;
                        let id: u64 = name.parse().ok()?;
                        Some(id)
                    })
                    .collect(),
                Err(_) => Vec::new(),
            };
            ids.sort_unstable();
            if let Some(&last_id) = ids.last() {
                segment_path_b =
                    segments_dir.join(tidefs_local_object_store::segment_file_name(last_id));
            } else {
                return BenchmarkResult::refused(
                    subject,
                    "no segments created",
                    ValidationTier::Kbuild,
                );
            }
        }

        // Corrupt the tail of the last segment.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = match std::fs::OpenOptions::new()
                .write(true)
                .open(&segment_path_b)
            {
                Ok(f) => f,
                Err(e) => {
                    return BenchmarkResult::refused(
                        subject,
                        format!("open segment for corruption: {e}"),
                        ValidationTier::Kbuild,
                    );
                }
            };
            let len = f.seek(SeekFrom::End(0)).unwrap_or(0);
            if len > 512 {
                f.set_len(len / 2).ok();
            } else {
                f.seek(SeekFrom::Start(len.saturating_sub(32))).ok();
                let _ = f.write_all(&[0u8; 32]);
            }
            let _ = f.sync_all();
        }

        // Reopen with repair enabled; measure wall time.
        opts.repair_torn_tail = true;
        let t0 = Instant::now();
        let store = match tidefs_local_object_store::LocalObjectStore::open_with_options(
            &self.store_root,
            opts,
        ) {
            Ok(s) => s,
            Err(e) => {
                return BenchmarkResult::refused(
                    subject,
                    format!("reopen with repair failed: {e:?}"),
                    ValidationTier::Kbuild,
                );
            }
        };
        let elapsed = t0.elapsed().as_secs_f64();

        // Count surviving objects.
        let mut surviving: u64 = 0;
        for i in 0..object_count {
            let key = tidefs_local_object_store::ObjectKey::from_name(&format!("obj-{i:06}"));
            if let Ok(Some(_)) = store.get(key) {
                surviving += 1;
            }
        }

        let _ = std::fs::remove_dir_all(&self.store_root);

        BenchmarkResult {
            subject: subject.to_string(),
            description: desc,
            executed: true,
            exit_code: Some(0),
            duration_secs: elapsed,
            kpis: vec![
                MeasuredKpi {
                    ref_id: "repair.reopen-secs".into(),
                    name: "repair_reopen_secs".into(),
                    value: elapsed,
                    unit: "s".into(),
                    passed: Some(elapsed < 60.0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "repair.objects-surviving".into(),
                    name: "objects_surviving".into(),
                    value: surviving as f64,
                    unit: "objects".into(),
                    passed: Some(surviving > 0),
                    percentile: None,
                },
                MeasuredKpi {
                    ref_id: "repair.objects-expected".into(),
                    name: "objects_expected".into(),
                    value: object_count as f64,
                    unit: "objects".into(),
                    passed: Some(object_count > 0),
                    percentile: None,
                },
            ],
            validation_tier: ValidationTier::Kbuild,
            stdout_tail: format!(
                "torn-tail repair: {}/{} objects survived, {:.3}s reopen",
                surviving, object_count, elapsed
            ),
            stderr_tail: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        let d = std::env::temp_dir()
            .join("tidefs-scrub-repair-harness-test")
            .join(name);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::create_dir_all(&d);
        d
    }

    #[test]
    fn segment_scrub_small_store() {
        let root = temp_root("seg-scrub-small");
        let harness = ScrubRepairHarness::new(&root);
        let result = harness.measure_segment_scrub(50, 1024);
        assert!(result.executed, "segment scrub should execute");
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.kpis.is_empty(), "should produce KPIs");
        let rec_kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "records_verified")
            .unwrap();
        assert_eq!(rec_kpi.passed, Some(true), "records_verified should pass");
    }

    #[test]
    fn checksum_scrub_basic() {
        let root = temp_root("csum-scrub-basic");
        let harness = ScrubRepairHarness::new(&root);
        let result = harness.measure_checksum_scrub(64 * 1024, 4096);
        assert!(result.executed, "checksum scrub should execute");
        assert_eq!(result.exit_code, Some(0));
        let bps_kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "checksum_scrub_bytes_per_sec")
            .unwrap();
        assert!(bps_kpi.value > 0.0, "bytes/sec should be positive");
        assert_eq!(
            bps_kpi.passed,
            Some(true),
            "clean data should pass checksum"
        );
    }

    #[test]
    fn checksum_scrub_bad_data_detected() {
        let data: Vec<u8> = vec![0xAA; 8192];
        let leaves: Vec<[u8; 32]> = data
            .chunks(4096)
            .map(|chunk| *blake3::hash(chunk).as_bytes())
            .collect();
        let tree = tidefs_checksum_tree::ChecksumTree::from_leaves(&leaves, 4096);
        let mut bad_data = data.clone();
        bad_data[100] ^= 0xFF;
        let report = tidefs_local_object_store::scrub_checksum_tree(&tree, &bad_data);
        assert!(!report.is_clean(), "corrupted data should fail scrub");
        assert!(report.leaves_examined > 0, "should examine leaves");
    }

    #[test]
    fn torn_tail_repair_survives() {
        let root = temp_root("torn-repair-survive");
        let harness = ScrubRepairHarness::new(&root);
        let result = harness.measure_torn_tail_repair(100, 2048);
        assert!(result.executed, "torn-tail repair should execute");
        assert_eq!(result.exit_code, Some(0));
        let surv_kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "objects_surviving")
            .unwrap();
        assert!(surv_kpi.value > 0.0, "some objects should survive repair");
        let reopen_kpi = result
            .kpis
            .iter()
            .find(|k| k.name == "repair_reopen_secs")
            .unwrap();
        assert!(reopen_kpi.value < 60.0, "reopen should complete within 60s");
    }

    #[test]
    fn harness_refuses_invalid_path() {
        let harness = ScrubRepairHarness::new("/proc/invalid/scrub-test-path");
        let result = harness.measure_segment_scrub(10, 512);
        assert!(!result.executed, "should refuse on invalid path");
    }
}
