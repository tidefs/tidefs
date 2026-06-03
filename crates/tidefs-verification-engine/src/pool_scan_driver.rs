//! Pool-scan segment iteration driver.
//!
//! Uses [`tidefs_pool_scan`] to discover pool devices and their segment
//! tables, then dispatches integrity checks to the segment verifier.

use crate::health_report::{HealthReport, VerificationOutcome};
use crate::segment_check::{run_full_segment_check, SegmentCheckConfig};
use std::path::PathBuf;
use std::time::SystemTime;
use tidefs_pool_scan::{LabelReader, PoolScanConfig, SegmentTableReader};

/// Driver configuration for pool-level segment scanning.
#[derive(Clone, Debug)]
pub struct PoolScanDriverConfig {
    /// Device paths to scan.
    pub device_paths: Vec<PathBuf>,
    /// Maximum records per check (0 = unlimited).
    pub max_records_per_check: u64,
    /// Maximum bytes per check (0 = unlimited).
    pub max_bytes_per_check: u64,
    /// Segment states to include (default: live only).
    pub include_obsolete: bool,
}

impl PoolScanDriverConfig {
    #[must_use]
    pub fn new(device_paths: Vec<PathBuf>) -> Self {
        Self {
            device_paths,
            max_records_per_check: 0,
            max_bytes_per_check: 0,
            include_obsolete: false,
        }
    }
}

/// Drives segment integrity verification across all pool devices.
///
/// Enumerates devices via [`tidefs_pool_scan`], discovers their segment
/// tables, and runs segment integrity checks on each device's local
/// segments directory.
pub struct PoolScanDriver {
    config: PoolScanDriverConfig,
}

impl PoolScanDriver {
    #[must_use]
    pub fn new(config: PoolScanDriverConfig) -> Self {
        Self { config }
    }

    /// Scan all configured devices and return aggregated results.
    ///
    /// Steps:
    /// 1. Read pool labels from each device via [`LabelReader`].
    /// 2. Enumerate segment tables from labelled devices.
    /// 3. For each device, run a segment integrity check on its segments dir.
    /// 4. Accumulate outcomes into a [`HealthReport`].
    pub fn scan(&self) -> (HealthReport, Vec<String>) {
        let started_at = SystemTime::now();
        let mut report = HealthReport::new(started_at);
        let mut errors = Vec::new();

        let scan_cfg = PoolScanConfig::new(self.config.device_paths.clone());
        let reader = LabelReader::new(scan_cfg);
        let (segment_table, scan_errors) = SegmentTableReader::enumerate_from_reader(&reader);

        for err in &scan_errors {
            errors.push(format!("pool-scan error: {err}"));
        }

        // For each device path, locate its segments directory.
        // In the TideFS architecture, the segments dir sits at:
        //   <device_path>/segments/   (for raw device mounts)
        //   or  <store_root>/segments/ (for dir-backed stores)
        //
        // For pool devices, the segments directory is typically found
        // alongside the pool label. We attempt both conventions.
        for device_path in &self.config.device_paths {
            let seg_dir = device_path.join("segments");

            // Also try the device's parent directory for block devices.
            let candidates = vec![seg_dir.clone()];

            for seg_dir in &candidates {
                if !seg_dir.exists() || !seg_dir.is_dir() {
                    continue;
                }

                let cfg = SegmentCheckConfig::new(seg_dir)
                    .with_limits(
                        self.config.max_records_per_check,
                        self.config.max_bytes_per_check,
                    )
                    .with_device_path(device_path);

                let result = run_full_segment_check(&cfg);

                for outcome in &result.outcomes {
                    report.record(outcome.clone(), Some(device_path.clone()));
                }

                // A clean aggregate scrub without per-segment outcomes is
                // incomplete validation. Do not fabricate PASS rows.
                if result.outcomes.is_empty() && result.records_verified > 0 {
                    for desc in segment_table.live_segments() {
                        report.record(
                            VerificationOutcome::Unreadable {
                                segment_id: desc.segment_id,
                                reason: "segment scrub emitted no per-segment outcome".into(),
                            },
                            Some(device_path.clone()),
                        );
                    }
                }

                break; // only process the first valid segments dir per device
            }
        }

        // If no device-specific segments dir was found, use the segment table
        // to generate Unreadable outcomes for segments on devices we couldn't read.
        if report.is_empty() && !segment_table.is_empty() {
            for desc in segment_table.iter() {
                if !self.config.include_obsolete && !desc.is_live() {
                    continue;
                }
                report.record(
                    VerificationOutcome::Unreadable {
                        segment_id: desc.segment_id,
                        reason: "no segments directory found for device".into(),
                    },
                    None,
                );
            }
        }

        report.finalize();
        (report, errors)
    }
}

/// Convenience: scan a single device path.
pub fn scan_device(device_path: impl Into<PathBuf>) -> (HealthReport, Vec<String>) {
    let driver = PoolScanDriver::new(PoolScanDriverConfig::new(vec![device_path.into()]));
    driver.scan()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_device_list_produces_empty_report() {
        let driver = PoolScanDriver::new(PoolScanDriverConfig::new(vec![]));
        let (report, errors) = driver.scan();
        assert!(report.is_empty());
        assert!(report.pool_healthy);
        assert!(errors.is_empty());
    }

    #[test]
    fn nonexistent_device_path_graceful() {
        let driver = PoolScanDriver::new(PoolScanDriverConfig::new(vec![
            "/nonexistent/device/path".into(),
        ]));
        let (report, _errors) = driver.scan();
        // No segments found, should be empty but still healthy.
        assert!(report.is_empty());
        assert!(report.pool_healthy);
    }

    #[test]
    fn config_defaults() {
        let cfg = PoolScanDriverConfig::new(vec!["/dev/sda".into()]);
        assert_eq!(cfg.max_records_per_check, 0);
        assert_eq!(cfg.max_bytes_per_check, 0);
        assert!(!cfg.include_obsolete);
    }
}
