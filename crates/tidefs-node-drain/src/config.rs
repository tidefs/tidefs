// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Validated drain protocol configuration.
//!
//! [`DrainConfig`] bundles all tunables for the node drain protocol with
//! bounds checking on construction, preventing invalid configurations
//! from reaching the runtime.

use std::fmt;

// ---------------------------------------------------------------------------
// DrainConfig
// ---------------------------------------------------------------------------

/// Configuration for the drain protocol runtime.
///
/// All fields are validated on construction via [`DrainConfig::new`] or
/// on mutation via the setter methods. Defaults are sensible for
/// production use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainConfig {
    /// Maximum wall-clock time for the entire drain operation, in
    /// milliseconds. Default: 30_000 (30 seconds).
    pub drain_timeout_ms: u64,

    /// Maximum number of state objects to include in a single transfer
    /// batch. Default: 64.
    pub state_transfer_batch_size: u64,

    /// Maximum number of concurrent state transfers to different target
    /// peers. Default: 4.
    pub max_concurrent_transfers: u64,
}

impl DrainConfig {
    /// Hard lower bound for `drain_timeout_ms`. Zero disables the timeout;
    /// anything below this is rejected.
    pub const MIN_DRAIN_TIMEOUT_MS: u64 = 1_000; // 1 second floor

    /// Hard upper bound for `drain_timeout_ms`.
    pub const MAX_DRAIN_TIMEOUT_MS: u64 = 3_600_000; // 1 hour

    /// Hard lower bound for `state_transfer_batch_size`.
    pub const MIN_BATCH_SIZE: u64 = 1;

    /// Hard upper bound for `state_transfer_batch_size`.
    pub const MAX_BATCH_SIZE: u64 = 4096;

    /// Hard lower bound for `max_concurrent_transfers`.
    pub const MIN_CONCURRENT_TRANSFERS: u64 = 1;

    /// Hard upper bound for `max_concurrent_transfers`.
    pub const MAX_CONCURRENT_TRANSFERS: u64 = 32;

    /// Create a new `DrainConfig` with the given values, validated against
    /// hard bounds.
    ///
    /// # Errors
    /// Returns [`DrainConfigError`] if any value falls outside its valid
    /// range.
    pub fn new(
        drain_timeout_ms: u64,
        state_transfer_batch_size: u64,
        max_concurrent_transfers: u64,
    ) -> Result<Self, DrainConfigError> {
        if drain_timeout_ms != 0 && drain_timeout_ms < Self::MIN_DRAIN_TIMEOUT_MS {
            return Err(DrainConfigError::InvalidDrainTimeout {
                value: drain_timeout_ms,
                min: Self::MIN_DRAIN_TIMEOUT_MS,
                max: Self::MAX_DRAIN_TIMEOUT_MS,
            });
        }
        if drain_timeout_ms > Self::MAX_DRAIN_TIMEOUT_MS {
            return Err(DrainConfigError::InvalidDrainTimeout {
                value: drain_timeout_ms,
                min: Self::MIN_DRAIN_TIMEOUT_MS,
                max: Self::MAX_DRAIN_TIMEOUT_MS,
            });
        }
        if state_transfer_batch_size < Self::MIN_BATCH_SIZE {
            return Err(DrainConfigError::InvalidBatchSize {
                value: state_transfer_batch_size,
                min: Self::MIN_BATCH_SIZE,
                max: Self::MAX_BATCH_SIZE,
            });
        }
        if state_transfer_batch_size > Self::MAX_BATCH_SIZE {
            return Err(DrainConfigError::InvalidBatchSize {
                value: state_transfer_batch_size,
                min: Self::MIN_BATCH_SIZE,
                max: Self::MAX_BATCH_SIZE,
            });
        }
        if max_concurrent_transfers < Self::MIN_CONCURRENT_TRANSFERS {
            return Err(DrainConfigError::InvalidConcurrentTransfers {
                value: max_concurrent_transfers,
                min: Self::MIN_CONCURRENT_TRANSFERS,
                max: Self::MAX_CONCURRENT_TRANSFERS,
            });
        }
        if max_concurrent_transfers > Self::MAX_CONCURRENT_TRANSFERS {
            return Err(DrainConfigError::InvalidConcurrentTransfers {
                value: max_concurrent_transfers,
                min: Self::MIN_CONCURRENT_TRANSFERS,
                max: Self::MAX_CONCURRENT_TRANSFERS,
            });
        }

        Ok(Self {
            drain_timeout_ms,
            state_transfer_batch_size,
            max_concurrent_transfers,
        })
    }

    // ---- setters with validation ----

    /// Set `drain_timeout_ms`. Zero disables the timeout.
    ///
    /// # Errors
    /// Returns [`DrainConfigError`] if the value is out of range.
    pub fn set_drain_timeout(&mut self, ms: u64) -> Result<(), DrainConfigError> {
        if ms != 0 && ms < Self::MIN_DRAIN_TIMEOUT_MS {
            return Err(DrainConfigError::InvalidDrainTimeout {
                value: ms,
                min: Self::MIN_DRAIN_TIMEOUT_MS,
                max: Self::MAX_DRAIN_TIMEOUT_MS,
            });
        }
        if ms > Self::MAX_DRAIN_TIMEOUT_MS {
            return Err(DrainConfigError::InvalidDrainTimeout {
                value: ms,
                min: Self::MIN_DRAIN_TIMEOUT_MS,
                max: Self::MAX_DRAIN_TIMEOUT_MS,
            });
        }
        self.drain_timeout_ms = ms;
        Ok(())
    }

    /// Set `state_transfer_batch_size`.
    ///
    /// # Errors
    /// Returns [`DrainConfigError`] if the value is out of range.
    pub fn set_batch_size(&mut self, size: u64) -> Result<(), DrainConfigError> {
        if !(Self::MIN_BATCH_SIZE..=Self::MAX_BATCH_SIZE).contains(&size) {
            return Err(DrainConfigError::InvalidBatchSize {
                value: size,
                min: Self::MIN_BATCH_SIZE,
                max: Self::MAX_BATCH_SIZE,
            });
        }
        self.state_transfer_batch_size = size;
        Ok(())
    }

    /// Set `max_concurrent_transfers`.
    ///
    /// # Errors
    /// Returns [`DrainConfigError`] if the value is out of range.
    pub fn set_max_concurrent_transfers(&mut self, n: u64) -> Result<(), DrainConfigError> {
        if !(Self::MIN_CONCURRENT_TRANSFERS..=Self::MAX_CONCURRENT_TRANSFERS).contains(&n) {
            return Err(DrainConfigError::InvalidConcurrentTransfers {
                value: n,
                min: Self::MIN_CONCURRENT_TRANSFERS,
                max: Self::MAX_CONCURRENT_TRANSFERS,
            });
        }
        self.max_concurrent_transfers = n;
        Ok(())
    }

    /// Returns true if the drain timeout is disabled (zero).
    #[must_use]
    pub fn timeout_disabled(&self) -> bool {
        self.drain_timeout_ms == 0
    }
}

impl Default for DrainConfig {
    fn default() -> Self {
        // Safety: defaults are within bounds by construction.
        Self {
            drain_timeout_ms: 30_000,
            state_transfer_batch_size: 64,
            max_concurrent_transfers: 4,
        }
    }
}

// ---------------------------------------------------------------------------
// DrainConfigError
// ---------------------------------------------------------------------------

/// Errors returned when drain configuration values are out of bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainConfigError {
    /// `drain_timeout_ms` is outside [MIN, MAX].
    InvalidDrainTimeout { value: u64, min: u64, max: u64 },
    /// `state_transfer_batch_size` is outside [MIN, MAX].
    InvalidBatchSize { value: u64, min: u64, max: u64 },
    /// `max_concurrent_transfers` is outside [MIN, MAX].
    InvalidConcurrentTransfers { value: u64, min: u64, max: u64 },
}

impl fmt::Display for DrainConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDrainTimeout { value, min, max } => {
                write!(f, "drain_timeout_ms {value} out of range [{min}, {max}]")
            }
            Self::InvalidBatchSize { value, min, max } => {
                write!(
                    f,
                    "state_transfer_batch_size {value} out of range [{min}, {max}]"
                )
            }
            Self::InvalidConcurrentTransfers { value, min, max } => {
                write!(
                    f,
                    "max_concurrent_transfers {value} out of range [{min}, {max}]"
                )
            }
        }
    }
}

impl std::error::Error for DrainConfigError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Construction ---

    #[test]
    fn defaults_are_valid() {
        let c = DrainConfig::default();
        assert_eq!(c.drain_timeout_ms, 30_000);
        assert_eq!(c.state_transfer_batch_size, 64);
        assert_eq!(c.max_concurrent_transfers, 4);
    }

    #[test]
    fn new_accepts_valid_values() {
        let c = DrainConfig::new(60_000, 128, 8).unwrap();
        assert_eq!(c.drain_timeout_ms, 60_000);
        assert_eq!(c.state_transfer_batch_size, 128);
        assert_eq!(c.max_concurrent_transfers, 8);
    }

    #[test]
    fn new_accepts_zero_timeout() {
        // Zero timeout disables the timeout — allowed.
        let c = DrainConfig::new(0, 64, 4).unwrap();
        assert_eq!(c.drain_timeout_ms, 0);
        assert!(c.timeout_disabled());
    }

    #[test]
    fn new_accepts_min_boundary_values() {
        let c = DrainConfig::new(
            DrainConfig::MIN_DRAIN_TIMEOUT_MS,
            DrainConfig::MIN_BATCH_SIZE,
            DrainConfig::MIN_CONCURRENT_TRANSFERS,
        )
        .unwrap();
        assert_eq!(c.drain_timeout_ms, 1_000);
        assert_eq!(c.state_transfer_batch_size, 1);
        assert_eq!(c.max_concurrent_transfers, 1);
    }

    #[test]
    fn new_accepts_max_boundary_values() {
        let c = DrainConfig::new(
            DrainConfig::MAX_DRAIN_TIMEOUT_MS,
            DrainConfig::MAX_BATCH_SIZE,
            DrainConfig::MAX_CONCURRENT_TRANSFERS,
        )
        .unwrap();
        assert_eq!(c.drain_timeout_ms, 3_600_000);
        assert_eq!(c.state_transfer_batch_size, 4096);
        assert_eq!(c.max_concurrent_transfers, 32);
    }

    // --- Rejection ---

    #[test]
    fn new_rejects_below_min_timeout() {
        let err = DrainConfig::new(500, 64, 4).unwrap_err(); // below 1000
        assert!(matches!(err, DrainConfigError::InvalidDrainTimeout { .. }));
    }

    #[test]
    fn new_rejects_above_max_timeout() {
        let err = DrainConfig::new(4_000_000, 64, 4).unwrap_err(); // above 3_600_000
        assert!(matches!(err, DrainConfigError::InvalidDrainTimeout { .. }));
    }

    #[test]
    fn new_rejects_zero_batch_size() {
        let err = DrainConfig::new(30_000, 0, 4).unwrap_err();
        assert!(matches!(err, DrainConfigError::InvalidBatchSize { .. }));
    }

    #[test]
    fn new_rejects_above_max_batch_size() {
        let err = DrainConfig::new(30_000, 5000, 4).unwrap_err();
        assert!(matches!(err, DrainConfigError::InvalidBatchSize { .. }));
    }

    #[test]
    fn new_rejects_zero_concurrent_transfers() {
        let err = DrainConfig::new(30_000, 64, 0).unwrap_err();
        assert!(matches!(
            err,
            DrainConfigError::InvalidConcurrentTransfers { .. }
        ));
    }

    #[test]
    fn new_rejects_above_max_concurrent_transfers() {
        let err = DrainConfig::new(30_000, 64, 64).unwrap_err();
        assert!(matches!(
            err,
            DrainConfigError::InvalidConcurrentTransfers { .. }
        ));
    }

    // --- Setters ---

    #[test]
    fn setter_accepts_valid_timeout() {
        let mut c = DrainConfig::default();
        c.set_drain_timeout(120_000).unwrap();
        assert_eq!(c.drain_timeout_ms, 120_000);
    }

    #[test]
    fn setter_rejects_below_min_timeout() {
        let mut c = DrainConfig::default();
        let err = c.set_drain_timeout(500).unwrap_err();
        assert!(matches!(err, DrainConfigError::InvalidDrainTimeout { .. }));
        // Original value preserved
        assert_eq!(c.drain_timeout_ms, 30_000);
    }

    #[test]
    fn setter_accepts_zero_timeout() {
        let mut c = DrainConfig::default();
        c.set_drain_timeout(0).unwrap();
        assert_eq!(c.drain_timeout_ms, 0);
        assert!(c.timeout_disabled());
    }

    #[test]
    fn setter_accepts_valid_batch_size() {
        let mut c = DrainConfig::default();
        c.set_batch_size(256).unwrap();
        assert_eq!(c.state_transfer_batch_size, 256);
    }

    #[test]
    fn setter_rejects_invalid_batch_size() {
        let mut c = DrainConfig::default();
        let err = c.set_batch_size(10000).unwrap_err();
        assert!(matches!(err, DrainConfigError::InvalidBatchSize { .. }));
        assert_eq!(c.state_transfer_batch_size, 64);
    }

    #[test]
    fn setter_accepts_valid_concurrent_transfers() {
        let mut c = DrainConfig::default();
        c.set_max_concurrent_transfers(16).unwrap();
        assert_eq!(c.max_concurrent_transfers, 16);
    }

    #[test]
    fn setter_rejects_invalid_concurrent_transfers() {
        let mut c = DrainConfig::default();
        let err = c.set_max_concurrent_transfers(0).unwrap_err();
        assert!(matches!(
            err,
            DrainConfigError::InvalidConcurrentTransfers { .. }
        ));
        assert_eq!(c.max_concurrent_transfers, 4);
    }

    // --- Timeout disabled ---

    #[test]
    fn timeout_disabled_when_zero() {
        let c = DrainConfig::new(0, 64, 4).unwrap();
        assert!(c.timeout_disabled());
    }

    #[test]
    fn timeout_not_disabled_when_nonzero() {
        let c = DrainConfig::default();
        assert!(!c.timeout_disabled());
    }

    // --- Error display ---

    #[test]
    fn error_display_timeout() {
        let err = DrainConfigError::InvalidDrainTimeout {
            value: 500,
            min: 1000,
            max: 3600000,
        };
        let s = format!("{err}");
        assert!(s.contains("500"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn error_display_batch_size() {
        let err = DrainConfigError::InvalidBatchSize {
            value: 0,
            min: 1,
            max: 4096,
        };
        let s = format!("{err}");
        assert!(s.contains("state_transfer_batch_size"));
        assert!(s.contains("0"));
    }

    #[test]
    fn error_display_concurrent_transfers() {
        let err = DrainConfigError::InvalidConcurrentTransfers {
            value: 100,
            min: 1,
            max: 32,
        };
        let s = format!("{err}");
        assert!(s.contains("max_concurrent_transfers"));
        assert!(s.contains("100"));
    }

    // --- Clone / Eq ---

    #[test]
    fn config_clone_eq() {
        let c1 = DrainConfig::default();
        let c2 = c1.clone();
        assert_eq!(c1, c2);

        let c3 = DrainConfig::new(60_000, 128, 8).unwrap();
        assert_ne!(c1, c3);
    }
}
