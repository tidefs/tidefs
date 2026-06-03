//! TDMA bandwidth-scheduler configuration.

use serde::{Deserialize, Serialize};

/// Configuration for the credit-based TDMA transmit scheduler.
///
/// Defines epoch timing, slot granularity, default node weight, and total
/// per-epoch bandwidth such that the scheduler produces deterministic
/// per-peer slot tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TdmaConfig {
    /// Duration of a scheduling epoch in microseconds.
    pub epoch_duration_us: u64,
    /// Minimum slot granularity in nanoseconds (the slot quantum).
    pub slot_granularity_ns: u64,
    /// Default weight assigned to nodes without an explicit weight entry.
    pub default_weight: u32,
    /// Total bytes available for all nodes across one full epoch.
    pub total_bandwidth_bytes_per_epoch: u64,
}

/// Validation errors returned by [`TdmaConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TdmaConfigError {
    #[error("epoch_duration_us must be positive (got {0})")]
    EpochDurationZero(u64),
    #[error("slot_granularity_ns must be positive (got {0})")]
    SlotGranularityZero(u64),
    #[error(
        "epoch duration ({epoch_us} us = {epoch_ns} ns) shorter than slot granularity ({slot_ns} ns)"
    )]
    EpochShorterThanSlot {
        epoch_us: u64,
        epoch_ns: u64,
        slot_ns: u64,
    },
    #[error("default_weight must be positive (got {0})")]
    DefaultWeightZero(u32),
    #[error("total_bandwidth_bytes_per_epoch must be positive (got {0})")]
    BandwidthZero(u64),
}

impl Default for TdmaConfig {
    fn default() -> Self {
        Self {
            epoch_duration_us: 1000,
            slot_granularity_ns: 1000,
            default_weight: 100,
            total_bandwidth_bytes_per_epoch: 1024 * 1024 * 1024, // 1 GiB
        }
    }
}

impl TdmaConfig {
    /// Validate every field, returning the first error encountered.
    pub fn validate(&self) -> Result<(), TdmaConfigError> {
        if self.epoch_duration_us == 0 {
            return Err(TdmaConfigError::EpochDurationZero(self.epoch_duration_us));
        }
        if self.slot_granularity_ns == 0 {
            return Err(TdmaConfigError::SlotGranularityZero(
                self.slot_granularity_ns,
            ));
        }
        let epoch_ns = self.epoch_duration_ns();
        if epoch_ns < self.slot_granularity_ns {
            return Err(TdmaConfigError::EpochShorterThanSlot {
                epoch_us: self.epoch_duration_us,
                epoch_ns,
                slot_ns: self.slot_granularity_ns,
            });
        }
        if self.default_weight == 0 {
            return Err(TdmaConfigError::DefaultWeightZero(self.default_weight));
        }
        if self.total_bandwidth_bytes_per_epoch == 0 {
            return Err(TdmaConfigError::BandwidthZero(
                self.total_bandwidth_bytes_per_epoch,
            ));
        }
        Ok(())
    }

    /// Epoch duration expressed in nanoseconds.
    pub fn epoch_duration_ns(&self) -> u64 {
        self.epoch_duration_us.saturating_mul(1000)
    }

    /// Number of slot quanta that fit in one epoch.
    pub fn slots_per_epoch(&self) -> u64 {
        self.epoch_duration_ns() / self.slot_granularity_ns
    }

    /// Bytes available per slot quantum (even division of total bandwidth).
    pub fn bytes_per_slot(&self) -> u64 {
        let slots = self.slots_per_epoch();
        if slots == 0 {
            return 0;
        }
        self.total_bandwidth_bytes_per_epoch / slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        TdmaConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_zero_epoch() {
        let c = TdmaConfig {
            epoch_duration_us: 0,
            ..Default::default()
        };
        assert_eq!(
            c.validate().unwrap_err(),
            TdmaConfigError::EpochDurationZero(0)
        );
    }

    #[test]
    fn rejects_zero_slot() {
        let c = TdmaConfig {
            slot_granularity_ns: 0,
            ..Default::default()
        };
        assert_eq!(
            c.validate().unwrap_err(),
            TdmaConfigError::SlotGranularityZero(0)
        );
    }

    #[test]
    fn rejects_epoch_shorter_than_slot() {
        let c = TdmaConfig {
            epoch_duration_us: 1,
            slot_granularity_ns: 2000,
            ..Default::default()
        };
        assert!(matches!(
            c.validate().unwrap_err(),
            TdmaConfigError::EpochShorterThanSlot { .. }
        ));
    }

    #[test]
    fn rejects_zero_weight() {
        let c = TdmaConfig {
            default_weight: 0,
            ..Default::default()
        };
        assert_eq!(
            c.validate().unwrap_err(),
            TdmaConfigError::DefaultWeightZero(0)
        );
    }

    #[test]
    fn rejects_zero_bandwidth() {
        let c = TdmaConfig {
            total_bandwidth_bytes_per_epoch: 0,
            ..Default::default()
        };
        assert_eq!(c.validate().unwrap_err(), TdmaConfigError::BandwidthZero(0));
    }

    #[test]
    fn derived_epoch_ns() {
        let c = TdmaConfig {
            epoch_duration_us: 500,
            ..Default::default()
        };
        assert_eq!(c.epoch_duration_ns(), 500_000);
    }

    #[test]
    fn derived_slots_per_epoch() {
        let c = TdmaConfig {
            epoch_duration_us: 1000,
            slot_granularity_ns: 5000,
            ..Default::default()
        };
        assert_eq!(c.slots_per_epoch(), 200); // 1_000_000 / 5000
    }

    #[test]
    fn derived_bytes_per_slot() {
        let c = TdmaConfig {
            epoch_duration_us: 1000,
            slot_granularity_ns: 1000,
            total_bandwidth_bytes_per_epoch: 1_000_000,
            ..Default::default()
        };
        assert_eq!(c.bytes_per_slot(), 1000);
    }

    #[test]
    fn serde_roundtrip() {
        let c = TdmaConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let c2: TdmaConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c.epoch_duration_us, c2.epoch_duration_us);
        assert_eq!(c.slot_granularity_ns, c2.slot_granularity_ns);
        assert_eq!(c.default_weight, c2.default_weight);
        assert_eq!(
            c.total_bandwidth_bytes_per_epoch,
            c2.total_bandwidth_bytes_per_epoch
        );
    }
}
