// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// space_pressure.rs — Multi-level space pressure tracking and threshold configuration
//
// Provides SpacePressureLevel, SpacePressureConfig, and SpacePressure
// for filesystem-level space usage monitoring. Tracks capacity, used
// bytes, and derives a four-level pressure state from configurable
// thresholds. Integrates with pool-level capacity statistics.

/// Space pressure level, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpacePressureLevel {
    /// Space usage is below the warning threshold. Normal operation.
    Healthy,
    /// Space usage has crossed the warning threshold.
    /// Background cleaning should be triggered.
    Warning,
    /// Space usage has crossed the sync threshold.
    /// Synchronous cleaning must run on the write path.
    Sync,
    /// Space usage has crossed the critical threshold.
    /// Only metadata operations (unlink, rmdir) are permitted;
    /// data writes return ENOSPC.
    Critical,
}

impl SpacePressureLevel {
    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Human-readable label for observability / tracing.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Sync => "sync",
            Self::Critical => "critical",
        }
    }
}

/// Configuration for space pressure thresholds.
#[derive(Clone, Debug)]
pub struct SpacePressureConfig {
    /// Fraction of total capacity at which the warning level is triggered
    /// (range 0.0–1.0). Default: 0.70 (70%).
    pub warning_threshold: f64,
    /// Fraction of total capacity at which sync cleaning is triggered
    /// (range 0.0–1.0). Default: 0.85 (85%).
    pub sync_threshold: f64,
    /// Fraction of total capacity at which critical pressure is declared
    /// (range 0.0–1.0). Default: 0.95 (95%).
    pub critical_threshold: f64,
    /// Fraction of total capacity reserved for metadata operations
    /// (range 0.0–0.5). Default: 0.05 (5%).
    pub emergency_reserve: f64,
}

impl Default for SpacePressureConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 0.70,
            sync_threshold: 0.85,
            critical_threshold: 0.95,
            emergency_reserve: 0.05,
        }
    }
}

impl SpacePressureConfig {
    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Validate thresholds are monotonic and within valid ranges.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(0.0..=1.0).contains(&self.warning_threshold) {
            return Err("warning_threshold must be in [0, 1]");
        }
        if !(0.0..=1.0).contains(&self.sync_threshold) {
            return Err("sync_threshold must be in [0, 1]");
        }
        if !(0.0..=1.0).contains(&self.critical_threshold) {
            return Err("critical_threshold must be in [0, 1]");
        }
        if !(0.0..=0.5).contains(&self.emergency_reserve) {
            return Err("emergency_reserve must be in [0, 0.5]");
        }
        if self.warning_threshold > self.sync_threshold {
            return Err("warning_threshold must be <= sync_threshold");
        }
        if self.sync_threshold > self.critical_threshold {
            return Err("sync_threshold must be <= critical_threshold");
        }
        Ok(())
    }
}

/// Tracks space usage and derives the current pressure level.
///
/// Updated from pool capacity statistics after every commit.
/// Thresholds are configurable; the emergency reserve carves
/// out metadata-only space for unlink/rmdir recovery.
#[derive(Clone, Debug)]
pub struct SpacePressure {
    config: SpacePressureConfig,
    /// Total raw capacity in bytes (pool-level).
    total_capacity_bytes: u64,
    /// Currently used bytes across all objects.
    used_bytes: u64,
    /// Bytes reserved exclusively for metadata operations.
    reserved_bytes: u64,
    /// Currently computed pressure level.
    current_level: SpacePressureLevel,
}

impl SpacePressure {
    /// Create a new space pressure tracker with the given config.
    pub fn new(config: SpacePressureConfig) -> Self {
        Self {
            config,
            total_capacity_bytes: 0,
            used_bytes: 0,
            reserved_bytes: 0,
            current_level: SpacePressureLevel::Healthy,
        }
    }

    /// Update space accounting from current pool capacity statistics.
    ///
    /// Recomputes the pressure level and the emergency reserve.
    /// Call after each commit or after cleaning completes.
    pub fn update(&mut self, total_capacity_bytes: u64, used_bytes: u64) {
        self.total_capacity_bytes = total_capacity_bytes;
        self.used_bytes = used_bytes;
        self.reserved_bytes = (total_capacity_bytes as f64 * self.config.emergency_reserve) as u64;
        self.current_level = self.compute_level();
    }

    /// Derive the pressure level from current usage ratio.
    fn compute_level(&self) -> SpacePressureLevel {
        if self.total_capacity_bytes == 0 {
            return SpacePressureLevel::Healthy;
        }
        let used_fraction = self.used_bytes as f64 / self.total_capacity_bytes as f64;
        if used_fraction >= self.config.critical_threshold {
            SpacePressureLevel::Critical
        } else if used_fraction >= self.config.sync_threshold {
            SpacePressureLevel::Sync
        } else if used_fraction >= self.config.warning_threshold {
            SpacePressureLevel::Warning
        } else {
            SpacePressureLevel::Healthy
        }
    }

    /// Current pressure level.
    pub fn current_level(&self) -> SpacePressureLevel {
        self.current_level
    }

    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Free bytes (capacity minus used), saturating at zero.
    pub fn free_bytes(&self) -> u64 {
        self.total_capacity_bytes.saturating_sub(self.used_bytes)
    }

    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Bytes reserved for metadata-only operations.
    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Whether data writes should be rejected (critical level reached).
    pub fn should_reject_writes(&self) -> bool {
        self.current_level >= SpacePressureLevel::Critical
    }

    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Whether background cleaning is indicated (warning level or higher).
    pub fn should_background_clean(&self) -> bool {
        self.current_level >= SpacePressureLevel::Warning
    }

    /// Whether synchronous cleaning is required (sync level or higher).
    pub fn should_sync_clean(&self) -> bool {
        self.current_level >= SpacePressureLevel::Sync
    }

    #[allow(dead_code)] // INTENT: space pressure types for planned admission control and background cleaning
    /// Effective available bytes for data writes: free bytes minus the
    /// emergency reserve. Saturates at zero.
    pub fn data_available_bytes(&self) -> u64 {
        self.free_bytes().saturating_sub(self.reserved_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = SpacePressureConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_rejects_inverted_thresholds() {
        let cfg = SpacePressureConfig {
            warning_threshold: 0.90,
            sync_threshold: 0.80,
            critical_threshold: 0.95,
            emergency_reserve: 0.05,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_out_of_range_threshold() {
        let cfg = SpacePressureConfig {
            warning_threshold: -0.1,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        let cfg = SpacePressureConfig {
            critical_threshold: 1.5,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_large_emergency_reserve() {
        let cfg = SpacePressureConfig {
            emergency_reserve: 0.6,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn healthy_when_below_warning() {
        let mut sp = SpacePressure::new(SpacePressureConfig::default());
        sp.update(1_000_000, 500_000); // 50% used
        assert_eq!(sp.current_level(), SpacePressureLevel::Healthy);
        assert!(!sp.should_reject_writes());
        assert!(!sp.should_background_clean());
        assert!(!sp.should_sync_clean());
    }

    #[test]
    fn warning_at_70_percent() {
        let mut sp = SpacePressure::new(SpacePressureConfig::default());
        sp.update(1_000_000, 710_000); // 71% used
        assert_eq!(sp.current_level(), SpacePressureLevel::Warning);
        assert!(!sp.should_reject_writes());
        assert!(sp.should_background_clean());
        assert!(!sp.should_sync_clean());
    }

    #[test]
    fn sync_at_85_percent() {
        let mut sp = SpacePressure::new(SpacePressureConfig::default());
        sp.update(1_000_000, 860_000); // 86% used
        assert_eq!(sp.current_level(), SpacePressureLevel::Sync);
        assert!(!sp.should_reject_writes());
        assert!(sp.should_background_clean());
        assert!(sp.should_sync_clean());
    }

    #[test]
    fn critical_at_95_percent() {
        let mut sp = SpacePressure::new(SpacePressureConfig::default());
        sp.update(1_000_000, 960_000); // 96% used
        assert_eq!(sp.current_level(), SpacePressureLevel::Critical);
        assert!(sp.should_reject_writes());
        assert!(sp.should_background_clean());
        assert!(sp.should_sync_clean());
    }

    #[test]
    fn zero_capacity_is_healthy() {
        let mut sp = SpacePressure::new(SpacePressureConfig::default());
        sp.update(0, 0);
        assert_eq!(sp.current_level(), SpacePressureLevel::Healthy);
    }

    #[test]
    fn exact_threshold_boundaries() {
        let cfg = SpacePressureConfig {
            warning_threshold: 0.5,
            sync_threshold: 0.8,
            critical_threshold: 0.9,
            emergency_reserve: 0.05,
        };
        let mut sp = SpacePressure::new(cfg);

        sp.update(1000, 500);
        assert_eq!(sp.current_level(), SpacePressureLevel::Warning); // 50% = warning threshold

        sp.update(1000, 800);
        assert_eq!(sp.current_level(), SpacePressureLevel::Sync); // 80% = sync threshold

        sp.update(1000, 900);
        assert_eq!(sp.current_level(), SpacePressureLevel::Critical); // 90% = critical threshold
    }

    #[test]
    fn free_bytes_and_reserved() {
        let mut sp = SpacePressure::new(SpacePressureConfig {
            emergency_reserve: 0.10,
            ..Default::default()
        });
        sp.update(1_000_000, 800_000);
        assert_eq!(sp.free_bytes(), 200_000);
        assert_eq!(sp.reserved_bytes(), 100_000);
        assert_eq!(sp.data_available_bytes(), 100_000);
    }

    #[test]
    fn data_available_saturates_at_zero() {
        let mut sp = SpacePressure::new(SpacePressureConfig {
            emergency_reserve: 0.10,
            ..Default::default()
        });
        sp.update(1_000_000, 960_000); // 40k free, 100k reserved
        assert_eq!(sp.free_bytes(), 40_000);
        assert_eq!(sp.data_available_bytes(), 0); // saturates
    }

    #[test]
    fn level_ordering_is_correct() {
        assert!(SpacePressureLevel::Healthy < SpacePressureLevel::Warning);
        assert!(SpacePressureLevel::Warning < SpacePressureLevel::Sync);
        assert!(SpacePressureLevel::Sync < SpacePressureLevel::Critical);
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(SpacePressureLevel::Healthy.label(), "healthy");
        assert_eq!(SpacePressureLevel::Warning.label(), "warning");
        assert_eq!(SpacePressureLevel::Sync.label(), "sync");
        assert_eq!(SpacePressureLevel::Critical.label(), "critical");
    }

    #[test]
    fn custom_thresholds_work() {
        let cfg = SpacePressureConfig {
            warning_threshold: 0.60,
            sync_threshold: 0.75,
            critical_threshold: 0.90,
            emergency_reserve: 0.02,
        };
        assert!(cfg.validate().is_ok());
        let mut sp = SpacePressure::new(cfg);
        sp.update(1000, 650); // 65% — above warning, below sync
        assert_eq!(sp.current_level(), SpacePressureLevel::Warning);
        sp.update(1000, 800); // 80% — above sync, below critical
        assert_eq!(sp.current_level(), SpacePressureLevel::Sync);
    }

    #[test]
    fn config_validate_edge_cases() {
        // All zeros is valid
        let cfg = SpacePressureConfig {
            warning_threshold: 0.0,
            sync_threshold: 0.0,
            critical_threshold: 0.0,
            emergency_reserve: 0.0,
        };
        assert!(cfg.validate().is_ok());

        // All ones up to 0.95 is valid
        let cfg = SpacePressureConfig {
            warning_threshold: 0.90,
            sync_threshold: 0.93,
            critical_threshold: 0.95,
            emergency_reserve: 0.05,
        };
        assert!(cfg.validate().is_ok());
    }
}
