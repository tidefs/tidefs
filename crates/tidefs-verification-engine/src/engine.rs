// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Verification engine: top-level orchestrator for pool segment integrity.
//!
//! The [`VerificationEngine`] ties together pool-scan device discovery,
//! segment-level BLAKE3 integrity verification, and health report
//! accumulation.  It is designed to run as an optional background task
//! inside [`tidefs-storage-node`] or any other pool-aware runtime.

use crate::health_report::HealthReport;
use crate::pool_scan_driver::{PoolScanDriver, PoolScanDriverConfig};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

// ---------------------------------------------------------------------------
// VerificationEngineConfig
// ---------------------------------------------------------------------------

/// Configuration for the verification engine.
#[derive(Clone, Debug)]
pub struct VerificationEngineConfig {
    /// Device paths forming the pool to verify.
    pub device_paths: Vec<PathBuf>,
    /// Maximum concurrent segment checks (reserved for future worker-pool).
    pub scan_concurrency: usize,
    /// Maximum I/O operations per second (0 = no throttle).
    pub throttle_iops: u64,
    /// Minimum interval between successive background scans.
    pub report_interval: Duration,
    /// Maximum records to verify per segment check tick (0 = unlimited).
    pub max_records_per_check: u64,
    /// Maximum bytes to scan per segment check tick (0 = unlimited).
    pub max_bytes_per_check: u64,
    /// Include obsolete (reclaimed) segments in the scan.
    pub include_obsolete: bool,
}

impl Default for VerificationEngineConfig {
    fn default() -> Self {
        Self {
            device_paths: vec![],
            scan_concurrency: 1,
            throttle_iops: 0,
            report_interval: Duration::from_secs(3600),
            max_records_per_check: 0,
            max_bytes_per_check: 0,
            include_obsolete: false,
        }
    }
}

impl VerificationEngineConfig {
    #[must_use]
    pub fn new(device_paths: Vec<PathBuf>) -> Self {
        Self {
            device_paths,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.scan_concurrency = n;
        self
    }

    #[must_use]
    pub fn with_throttle(mut self, iops: u64) -> Self {
        self.throttle_iops = iops;
        self
    }

    #[must_use]
    pub fn with_interval(mut self, d: Duration) -> Self {
        self.report_interval = d;
        self
    }

    #[must_use]
    pub fn with_max_records(mut self, n: u64) -> Self {
        self.max_records_per_check = n;
        self
    }

    #[must_use]
    pub fn with_max_bytes(mut self, n: u64) -> Self {
        self.max_bytes_per_check = n;
        self
    }
}

// ---------------------------------------------------------------------------
// VerificationEngine
// ---------------------------------------------------------------------------

/// Top-level verification engine for pool segment integrity.
///
/// Owns a [`PoolScanDriver`] and produces [`HealthReport`] results on
/// demand.  The engine is stateless between scans; persistent cursor
/// tracking is handled by the underlying [`SegmentIntegrityScrubber`].
#[derive(Clone, Debug)]
pub struct VerificationEngine {
    config: VerificationEngineConfig,
    /// Timestamp of the last completed scan (None = never scanned).
    last_scan: Option<SystemTime>,
}

impl VerificationEngine {
    /// Create a new verification engine.
    #[must_use]
    pub fn new(config: VerificationEngineConfig) -> Self {
        Self {
            config,
            last_scan: None,
        }
    }

    /// Run a full integrity scan across all configured devices.
    ///
    /// Returns the aggregated [`HealthReport`] and any errors encountered
    /// during device enumeration.  The engine is stateless; each call runs
    /// a fresh scan.
    pub fn run_scan(&mut self) -> (HealthReport, Vec<String>) {
        let driver_config = PoolScanDriverConfig {
            device_paths: self.config.device_paths.clone(),
            max_records_per_check: self.config.max_records_per_check,
            max_bytes_per_check: self.config.max_bytes_per_check,
            include_obsolete: self.config.include_obsolete,
        };

        let driver = PoolScanDriver::new(driver_config);
        let (report, errors) = driver.scan();

        self.last_scan = Some(SystemTime::now());
        (report, errors)
    }

    /// Return the timestamp of the last completed scan, if any.
    #[must_use]
    pub fn last_scan_time(&self) -> Option<SystemTime> {
        self.last_scan
    }

    /// Return the configured report interval.
    #[must_use]
    pub fn report_interval(&self) -> Duration {
        self.config.report_interval
    }

    /// Return true if enough time has elapsed since the last scan to
    /// justify running another.
    #[must_use]
    pub fn ready_for_next_scan(&self) -> bool {
        match self.last_scan {
            None => true,
            Some(t) => match SystemTime::now().duration_since(t) {
                Ok(elapsed) => elapsed >= self.config.report_interval,
                Err(_) => true, // clock went backwards — scan anyway
            },
        }
    }

    /// Return a reference to the engine configuration.
    #[must_use]
    pub fn config(&self) -> &VerificationEngineConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn engine_scan_empty_devices() {
        let config = VerificationEngineConfig::new(vec![]);
        let mut engine = VerificationEngine::new(config);
        let (report, errors) = engine.run_scan();
        assert!(report.is_empty());
        assert!(report.pool_healthy);
        assert!(errors.is_empty());
        assert!(engine.last_scan_time().is_some());
    }

    #[test]
    fn engine_scan_nonexistent_device() {
        let config = VerificationEngineConfig::new(vec!["/nonexistent/pool/dev".into()]);
        let mut engine = VerificationEngine::new(config);
        let (report, _errors) = engine.run_scan();
        // Empty report is still healthy — the device just has no segments to verify.
        assert!(report.pool_healthy);
    }

    #[test]
    fn ready_for_next_scan_initially_true() {
        let engine = VerificationEngine::new(VerificationEngineConfig::default());
        assert!(engine.ready_for_next_scan());
    }

    #[test]
    fn ready_for_next_scan_false_immediately_after_scan() {
        let mut engine = VerificationEngine::new(VerificationEngineConfig {
            report_interval: Duration::from_secs(3600),
            ..Default::default()
        });
        engine.run_scan();
        assert!(!engine.ready_for_next_scan());
    }

    #[test]
    fn ready_for_next_scan_true_after_short_interval() {
        let mut engine = VerificationEngine::new(VerificationEngineConfig {
            report_interval: Duration::from_millis(1),
            ..Default::default()
        });
        engine.run_scan();
        thread::sleep(Duration::from_millis(10));
        assert!(engine.ready_for_next_scan());
    }

    #[test]
    fn config_builders() {
        let cfg = VerificationEngineConfig::new(vec!["/dev/sda".into()])
            .with_concurrency(4)
            .with_throttle(100)
            .with_interval(Duration::from_secs(7200))
            .with_max_records(1000)
            .with_max_bytes(1_000_000);

        assert_eq!(cfg.scan_concurrency, 4);
        assert_eq!(cfg.throttle_iops, 100);
        assert_eq!(cfg.report_interval, Duration::from_secs(7200));
        assert_eq!(cfg.max_records_per_check, 1000);
        assert_eq!(cfg.max_bytes_per_check, 1_000_000);
    }

    #[test]
    fn default_config_has_sensible_values() {
        let cfg = VerificationEngineConfig::default();
        assert_eq!(cfg.scan_concurrency, 1);
        assert_eq!(cfg.throttle_iops, 0);
        assert_eq!(cfg.report_interval, Duration::from_secs(3600));
    }
}
