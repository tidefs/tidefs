//! Replication intent encoding.
//!
//! A [`ReplicationIntent`] defines the durability contract that a dataset,
//! pool, or placement group requires. It encodes copy count or erasure-coding
//! parameters together with the failure domain across which data must be
//! spread. The [`super::LayoutValidator`] uses this intent to verify that a
//! concrete placement plan satisfies the contract.

use serde::{Deserialize, Serialize};

use crate::failure_domain::FailureDomain;

// ---------------------------------------------------------------------------
// ReplicationIntent
// ---------------------------------------------------------------------------

/// Durability intent for replicated or erasure-coded data.
///
/// This is the single source of truth consumed by the placement planner,
/// rebuild runtime, and scrub/repair pipeline to determine whether a
/// candidate layout provides the required redundancy guarantees.
///
/// # Examples
///
/// ```
/// use tidefs_replication_model::{ReplicationIntent, FailureDomain};
///
/// // 3-way mirror across distinct nodes
/// let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
/// assert_eq!(intent.total_targets(), 3);
/// assert_eq!(intent.min_surviving_targets(), 1);
///
/// // 4+2 erasure coding across distinct racks
/// let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
/// assert_eq!(intent.total_targets(), 6);
/// assert_eq!(intent.min_surviving_targets(), 4);
/// ```
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplicationIntent {
    /// N-way mirroring: full replicas spread across distinct failure domains.
    Mirror {
        /// Number of full replicas. Must be >= 1.
        copies: u8,
        /// Failure domain at which replicas must be separated.
        failure_domain: FailureDomain,
    },
    /// Erasure-coded layout with k data + m parity shards.
    ErasureCoded {
        /// Number of data shards (k). Must be >= 1.
        data_shards: u8,
        /// Number of parity shards (m). Must be >= 1.
        parity_shards: u8,
        /// Failure domain at which shards must be separated.
        failure_domain: FailureDomain,
    },
    /// Distributed placement: shards spread across failure domains with no
    /// redundancy. All shards must survive for data to be available.
    Distributed {
        /// Number of shards to distribute. Must be >= 1.
        shards: u8,
        /// Failure domain across which shards must be spread.
        failure_domain: FailureDomain,
    },
}

/// Errors returned when constructing a [`ReplicationIntent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplicationIntentError {
    /// Copy count must be at least 1.
    #[error("copy count must be at least 1, got {got}")]
    CopiesTooLow { got: u8 },
    /// Data shard count must be at least 1.
    #[error("data shard count must be at least 1, got {got}")]
    DataShardsTooLow { got: u8 },
    /// Parity shard count must be at least 1.
    #[error("parity shard count must be at least 1, got {got}")]
    ParityShardsTooLow { got: u8 },
    /// Shard count must be at least 1 for distributed placement.
    #[error("shard count must be at least 1, got {got}")]
    ShardsTooLow { got: u8 },
}

impl ReplicationIntent {
    /// Construct a mirror intent, validating that `copies >= 1`.
    pub fn new_mirror(
        copies: u8,
        failure_domain: FailureDomain,
    ) -> Result<Self, ReplicationIntentError> {
        if copies < 1 {
            return Err(ReplicationIntentError::CopiesTooLow { got: copies });
        }
        Ok(Self::Mirror {
            copies,
            failure_domain,
        })
    }

    /// Construct an erasure-coded intent, validating that k >= 1 and m >= 1.
    pub fn new_erasure_coded(
        data_shards: u8,
        parity_shards: u8,
        failure_domain: FailureDomain,
    ) -> Result<Self, ReplicationIntentError> {
        if data_shards < 1 {
            return Err(ReplicationIntentError::DataShardsTooLow { got: data_shards });
        }
        if parity_shards < 1 {
            return Err(ReplicationIntentError::ParityShardsTooLow { got: parity_shards });
        }
        Ok(Self::ErasureCoded {
            data_shards,
            parity_shards,
            failure_domain,
        })
    }

    /// Construct a distributed intent, validating that `shards >= 1`.
    pub fn new_distributed(
        shards: u8,
        failure_domain: FailureDomain,
    ) -> Result<Self, ReplicationIntentError> {
        if shards < 1 {
            return Err(ReplicationIntentError::ShardsTooLow { got: shards });
        }
        Ok(Self::Distributed {
            shards,
            failure_domain,
        })
    }

    /// Total number of distinct failure-domain targets required.
    ///
    /// Mirror: `copies`. ErasureCoded: `data_shards + parity_shards`.
    /// Distributed: `shards`.
    #[must_use]
    pub const fn total_targets(&self) -> u8 {
        match self {
            ReplicationIntent::Mirror { copies, .. } => *copies,
            ReplicationIntent::ErasureCoded {
                data_shards,
                parity_shards,
                ..
            } => data_shards.saturating_add(*parity_shards),
            ReplicationIntent::Distributed { shards, .. } => *shards,
        }
    }

    /// Minimum number of targets that must survive for data to be available.
    ///
    /// Mirror: 1 (any single replica suffices).
    /// ErasureCoded: `data_shards` (need k shards to reconstruct).
    /// Distributed: `shards` (all shards needed; no redundancy).
    #[must_use]
    pub const fn min_surviving_targets(&self) -> u8 {
        match self {
            ReplicationIntent::Mirror { .. } => 1,
            ReplicationIntent::ErasureCoded { data_shards, .. } => *data_shards,
            ReplicationIntent::Distributed { shards, .. } => *shards,
        }
    }

    /// Maximum number of failure-domain failures this intent can tolerate.
    ///
    /// Mirror: `copies - 1`. ErasureCoded: `parity_shards`.
    /// Distributed: 0 (no redundancy).
    #[must_use]
    pub const fn max_tolerable_failures(&self) -> u8 {
        match self {
            ReplicationIntent::Mirror { copies, .. } => copies.saturating_sub(1),
            ReplicationIntent::ErasureCoded { parity_shards, .. } => *parity_shards,
            ReplicationIntent::Distributed { .. } => 0,
        }
    }

    /// The failure domain at which separation is enforced.
    #[must_use]
    pub const fn failure_domain(&self) -> FailureDomain {
        match self {
            ReplicationIntent::Mirror { failure_domain, .. }
            | ReplicationIntent::ErasureCoded { failure_domain, .. }
            | ReplicationIntent::Distributed { failure_domain, .. } => *failure_domain,
        }
    }

    /// Returns `true` if this is a mirror (replication) intent.
    #[must_use]
    pub const fn is_mirror(&self) -> bool {
        matches!(self, ReplicationIntent::Mirror { .. })
    }

    /// Returns `true` if this is an erasure-coded intent.
    #[must_use]
    pub const fn is_erasure_coded(&self) -> bool {
        matches!(self, ReplicationIntent::ErasureCoded { .. })
    }

    /// Returns `true` if this is a distributed (no-redundancy) intent.
    #[must_use]
    pub const fn is_distributed(&self) -> bool {
        matches!(self, ReplicationIntent::Distributed { .. })
    }
    /// Validate that enough failure domains are available to satisfy this intent.
    ///
    /// Returns `Ok(())` when `available_domains >= self.total_targets()`,
    /// otherwise `Err(ReplicationModelError::InsufficientDomains)`.
    pub fn validate(
        &self,
        available_domains: usize,
    ) -> Result<(), crate::class::ReplicationModelError> {
        let required = self.total_targets() as usize;
        if available_domains < required {
            return Err(crate::class::ReplicationModelError::InsufficientDomains {
                required: self.total_targets(),
                available: available_domains,
            });
        }
        Ok(())
    }
}

impl core::fmt::Display for ReplicationIntent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReplicationIntent::Mirror {
                copies,
                failure_domain,
            } => write!(f, "mirror(copies={copies}, domain={failure_domain})"),
            ReplicationIntent::ErasureCoded {
                data_shards,
                parity_shards,
                failure_domain,
            } => write!(
                f,
                "ec(k={data_shards},m={parity_shards}, domain={failure_domain})"
            ),
            ReplicationIntent::Distributed {
                shards,
                failure_domain,
            } => write!(f, "distributed(shards={shards}, domain={failure_domain})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Construction ----------

    #[test]
    fn mirror_construction() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        assert_eq!(intent.total_targets(), 3);
        assert!(intent.is_mirror());
        assert!(!intent.is_distributed());
    }

    #[test]
    fn mirror_rejects_zero_copies() {
        let err = ReplicationIntent::new_mirror(0, FailureDomain::Device).unwrap_err();
        assert!(matches!(
            err,
            ReplicationIntentError::CopiesTooLow { got: 0 }
        ));
    }

    #[test]
    fn erasure_coded_construction() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        assert_eq!(intent.total_targets(), 6);
        assert!(intent.is_erasure_coded());
        assert!(!intent.is_mirror());
        assert!(!intent.is_distributed());
    }

    #[test]
    fn ec_rejects_zero_data_shards() {
        let err = ReplicationIntent::new_erasure_coded(0, 2, FailureDomain::Rack).unwrap_err();
        assert!(matches!(
            err,
            ReplicationIntentError::DataShardsTooLow { got: 0 }
        ));
    }

    #[test]
    fn ec_rejects_zero_parity_shards() {
        let err = ReplicationIntent::new_erasure_coded(4, 0, FailureDomain::Rack).unwrap_err();
        assert!(matches!(
            err,
            ReplicationIntentError::ParityShardsTooLow { got: 0 }
        ));
    }

    // ---------- Distributed construction ----------

    #[test]
    fn distributed_construction() {
        let intent = ReplicationIntent::new_distributed(4, FailureDomain::Rack).unwrap();
        assert_eq!(intent.total_targets(), 4);
        assert!(intent.is_distributed());
        assert!(!intent.is_mirror());
        assert!(!intent.is_erasure_coded());
    }

    #[test]
    fn reject_distributed_zero_shards() {
        assert!(ReplicationIntent::new_distributed(0, FailureDomain::Device).is_err());
    }

    // ---------- Derived properties ----------

    #[test]
    fn mirror_total_targets() {
        assert_eq!(
            ReplicationIntent::new_mirror(1, FailureDomain::Device)
                .unwrap()
                .total_targets(),
            1
        );
        assert_eq!(
            ReplicationIntent::new_mirror(3, FailureDomain::Node)
                .unwrap()
                .total_targets(),
            3
        );
    }

    #[test]
    fn ec_total_targets() {
        assert_eq!(
            ReplicationIntent::new_erasure_coded(2, 1, FailureDomain::Device)
                .unwrap()
                .total_targets(),
            3
        );
        assert_eq!(
            ReplicationIntent::new_erasure_coded(8, 3, FailureDomain::Rack)
                .unwrap()
                .total_targets(),
            11
        );
    }

    #[test]
    fn distributed_total_targets() {
        assert_eq!(
            ReplicationIntent::new_distributed(1, FailureDomain::Device)
                .unwrap()
                .total_targets(),
            1
        );
        assert_eq!(
            ReplicationIntent::new_distributed(8, FailureDomain::Rack)
                .unwrap()
                .total_targets(),
            8
        );
    }

    #[test]
    fn min_surviving_targets() {
        let mirror = ReplicationIntent::new_mirror(5, FailureDomain::Node).unwrap();
        assert_eq!(mirror.min_surviving_targets(), 1);

        let ec = ReplicationIntent::new_erasure_coded(6, 3, FailureDomain::Rack).unwrap();
        assert_eq!(ec.min_surviving_targets(), 6);

        // Distributed: all shards must survive
        let dist = ReplicationIntent::new_distributed(4, FailureDomain::Rack).unwrap();
        assert_eq!(dist.min_surviving_targets(), 4);
    }

    #[test]
    fn max_tolerable_failures() {
        assert_eq!(
            ReplicationIntent::new_mirror(3, FailureDomain::Node)
                .unwrap()
                .max_tolerable_failures(),
            2
        );
        assert_eq!(
            ReplicationIntent::new_mirror(1, FailureDomain::Device)
                .unwrap()
                .max_tolerable_failures(),
            0
        );
        assert_eq!(
            ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack)
                .unwrap()
                .max_tolerable_failures(),
            2
        );
        assert_eq!(
            ReplicationIntent::new_erasure_coded(10, 4, FailureDomain::Datacenter)
                .unwrap()
                .max_tolerable_failures(),
            4
        );
        // Distributed tolerates no failures
        assert_eq!(
            ReplicationIntent::new_distributed(4, FailureDomain::Rack)
                .unwrap()
                .max_tolerable_failures(),
            0
        );
    }

    #[test]
    fn failure_domain_accessor() {
        let intent = ReplicationIntent::new_mirror(2, FailureDomain::Rack).unwrap();
        assert_eq!(intent.failure_domain(), FailureDomain::Rack);

        let intent = ReplicationIntent::new_distributed(3, FailureDomain::Datacenter).unwrap();
        assert_eq!(intent.failure_domain(), FailureDomain::Datacenter);
    }

    // ---------- Serde ----------

    #[test]
    fn serde_mirror_roundtrip() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let json = serde_json::to_string(&intent).expect("serialize");
        let round: ReplicationIntent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(intent, round);
    }

    #[test]
    fn serde_ec_roundtrip() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        let json = serde_json::to_string(&intent).expect("serialize");
        let round: ReplicationIntent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(intent, round);
    }

    #[test]
    fn serde_distributed_roundtrip() {
        let intent = ReplicationIntent::new_distributed(5, FailureDomain::Rack).unwrap();
        let json = serde_json::to_string(&intent).expect("serialize");
        let round: ReplicationIntent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(intent, round);
    }

    // ---------- Display ----------

    #[test]
    fn display_mirror() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        assert_eq!(format!("{intent}"), "mirror(copies=3, domain=node)");
    }

    #[test]
    fn display_ec() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        assert_eq!(format!("{intent}"), "ec(k=4,m=2, domain=rack)");
    }

    #[test]
    fn display_distributed() {
        let intent = ReplicationIntent::new_distributed(3, FailureDomain::Node).unwrap();
        assert_eq!(format!("{intent}"), "distributed(shards=3, domain=node)");
    }

    // ---------- Invalid intent rejection ----------

    #[test]
    fn reject_mirror_zero_copies() {
        assert!(ReplicationIntent::new_mirror(0, FailureDomain::Device).is_err());
    }

    #[test]
    fn reject_ec_zero_data() {
        assert!(ReplicationIntent::new_erasure_coded(0, 2, FailureDomain::Device).is_err());
    }

    #[test]
    fn reject_ec_zero_parity() {
        assert!(ReplicationIntent::new_erasure_coded(4, 0, FailureDomain::Device).is_err());
    }

    // ---------- validate() tests ----------

    #[test]
    fn validate_mirror3_accepts_3_nodes() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        assert!(intent.validate(3).is_ok());
        assert!(intent.validate(5).is_ok());
    }

    #[test]
    fn validate_mirror3_rejects_2_nodes() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let err = intent.validate(2).unwrap_err();
        assert!(matches!(
            err,
            crate::class::ReplicationModelError::InsufficientDomains {
                required: 3,
                available: 2,
            }
        ));
    }

    #[test]
    fn validate_mirror3_rejects_0_nodes() {
        let intent = ReplicationIntent::new_mirror(3, FailureDomain::Node).unwrap();
        let err = intent.validate(0).unwrap_err();
        assert!(matches!(
            err,
            crate::class::ReplicationModelError::InsufficientDomains {
                required: 3,
                available: 0,
            }
        ));
    }

    #[test]
    fn validate_mirror1_accepts_1_node() {
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        assert!(intent.validate(1).is_ok());
    }

    #[test]
    fn validate_mirror1_rejects_0_nodes() {
        let intent = ReplicationIntent::new_mirror(1, FailureDomain::Device).unwrap();
        let err = intent.validate(0).unwrap_err();
        assert!(matches!(
            err,
            crate::class::ReplicationModelError::InsufficientDomains {
                required: 1,
                available: 0,
            }
        ));
    }

    #[test]
    fn validate_ec_4_2_accepts_6_domains() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        assert!(intent.validate(6).is_ok());
        assert!(intent.validate(10).is_ok());
    }

    #[test]
    fn validate_ec_4_2_rejects_5_domains() {
        let intent = ReplicationIntent::new_erasure_coded(4, 2, FailureDomain::Rack).unwrap();
        let err = intent.validate(5).unwrap_err();
        assert!(matches!(
            err,
            crate::class::ReplicationModelError::InsufficientDomains {
                required: 6,
                available: 5,
            }
        ));
    }

    #[test]
    fn validate_ec_8_3_accepts_11_domains() {
        let intent = ReplicationIntent::new_erasure_coded(8, 3, FailureDomain::Datacenter).unwrap();
        assert!(intent.validate(11).is_ok());
    }

    #[test]
    fn validate_error_display() {
        let err = crate::class::ReplicationModelError::InsufficientDomains {
            required: 3,
            available: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("insufficient"));
        assert!(msg.contains("3"));
        assert!(msg.contains("1"));
    }
}
