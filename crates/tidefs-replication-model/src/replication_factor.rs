// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Replication factor for mirrored data.
//!
//! A [`ReplicationFactor`] is a validated value object that constrains the
//! number of full replicas (1-16) and the failure domain across which they
//! must be spread. It is consumed by replication dispatch and layout
//! planning to ensure placement satisfies fault-tolerance requirements.

use serde::{Deserialize, Serialize};

use crate::failure_domain::FailureDomain;

/// Validated replication factor for mirror-style data placement.
///
/// Bounds: 1 <= copies <= 16. Values outside this range are rejected at
/// construction time.
///
/// # Examples
///
/// ```
/// use tidefs_replication_model::{ReplicationFactor, FailureDomain};
///
/// let rf = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
/// assert_eq!(rf.copies(), 3);
/// assert_eq!(rf.max_tolerable_failures(), 2);
/// assert!(rf.is_available_after(2));
/// ```
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReplicationFactor {
    copies: u8,
    failure_domain: FailureDomain,
}

/// Maximum allowed copy count for a [`ReplicationFactor`].
pub const MAX_REPLICATION_COPIES: u8 = 16;

/// Errors returned when constructing a [`ReplicationFactor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplicationFactorError {
    /// Copy count must be at least 1.
    #[error("copy count must be at least 1, got {got}")]
    CopiesTooLow { got: u8 },
    /// Copy count must not exceed [`MAX_REPLICATION_COPIES`].
    #[error("copy count must be at most {max}, got {got}")]
    CopiesTooHigh { got: u8, max: u8 },
}

impl ReplicationFactor {
    /// Construct a validated replication factor.
    ///
    /// Returns an error if `copies` is outside the range 1..=16.
    pub fn new(copies: u8, failure_domain: FailureDomain) -> Result<Self, ReplicationFactorError> {
        if copies < 1 {
            return Err(ReplicationFactorError::CopiesTooLow { got: copies });
        }
        if copies > MAX_REPLICATION_COPIES {
            return Err(ReplicationFactorError::CopiesTooHigh {
                got: copies,
                max: MAX_REPLICATION_COPIES,
            });
        }
        Ok(Self {
            copies,
            failure_domain,
        })
    }

    /// Number of full replicas required.
    #[must_use]
    pub const fn copies(&self) -> u8 {
        self.copies
    }

    /// The failure domain across which replicas must be placed.
    #[must_use]
    pub const fn failure_domain(&self) -> FailureDomain {
        self.failure_domain
    }

    /// Maximum number of failure-domain failures this factor can tolerate
    /// while retaining at least one healthy replica.
    #[must_use]
    pub const fn max_tolerable_failures(&self) -> u8 {
        self.copies.saturating_sub(1)
    }

    /// Returns `true` if the data remains available after `failed` failure
    /// domains become unavailable.
    #[must_use]
    pub const fn is_available_after(&self, failed: u8) -> bool {
        failed < self.copies
    }

    /// Minimum number of distinct failure domains needed to satisfy this
    /// factor after tolerating `failed` domain losses.
    #[must_use]
    pub const fn min_spread_after_failures(&self, failed: u8) -> u8 {
        failed.saturating_add(1)
    }
}

impl core::fmt::Display for ReplicationFactor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.copies, self.failure_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Construction ----------

    #[test]
    fn valid_construction_min() {
        let rf = ReplicationFactor::new(1, FailureDomain::Device).unwrap();
        assert_eq!(rf.copies(), 1);
    }

    #[test]
    fn valid_construction_max() {
        let rf = ReplicationFactor::new(16, FailureDomain::Datacenter).unwrap();
        assert_eq!(rf.copies(), 16);
    }

    #[test]
    fn valid_construction_mid() {
        let rf = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        assert_eq!(rf.copies(), 3);
        assert_eq!(rf.failure_domain(), FailureDomain::Node);
    }

    #[test]
    fn reject_zero_copies() {
        let err = ReplicationFactor::new(0, FailureDomain::Device).unwrap_err();
        assert!(matches!(
            err,
            ReplicationFactorError::CopiesTooLow { got: 0 }
        ));
    }

    #[test]
    fn reject_17_copies() {
        let err = ReplicationFactor::new(17, FailureDomain::Device).unwrap_err();
        assert!(matches!(
            err,
            ReplicationFactorError::CopiesTooHigh { got: 17, max: 16 }
        ));
    }

    #[test]
    fn reject_255_copies() {
        let err = ReplicationFactor::new(255, FailureDomain::Device).unwrap_err();
        assert!(matches!(
            err,
            ReplicationFactorError::CopiesTooHigh { got: 255, max: 16 }
        ));
    }

    // ---------- Derived properties ----------

    #[test]
    fn max_tolerable_failures_1() {
        assert_eq!(
            ReplicationFactor::new(1, FailureDomain::Device)
                .unwrap()
                .max_tolerable_failures(),
            0
        );
    }

    #[test]
    fn max_tolerable_failures_3() {
        assert_eq!(
            ReplicationFactor::new(3, FailureDomain::Node)
                .unwrap()
                .max_tolerable_failures(),
            2
        );
    }

    #[test]
    fn max_tolerable_failures_16() {
        assert_eq!(
            ReplicationFactor::new(16, FailureDomain::Datacenter)
                .unwrap()
                .max_tolerable_failures(),
            15
        );
    }

    // ---------- Availability ----------

    #[test]
    fn is_available_after_3() {
        let rf = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        assert!(rf.is_available_after(0));
        assert!(rf.is_available_after(1));
        assert!(rf.is_available_after(2));
        assert!(!rf.is_available_after(3));
        assert!(!rf.is_available_after(5));
    }

    #[test]
    fn is_available_after_1() {
        let rf = ReplicationFactor::new(1, FailureDomain::Device).unwrap();
        assert!(rf.is_available_after(0));
        assert!(!rf.is_available_after(1));
    }

    // ---------- Min spread ----------

    #[test]
    fn min_spread_after_failures() {
        let rf = ReplicationFactor::new(5, FailureDomain::Rack).unwrap();
        assert_eq!(rf.min_spread_after_failures(0), 1);
        assert_eq!(rf.min_spread_after_failures(2), 3);
        assert_eq!(rf.min_spread_after_failures(4), 5);
    }

    // ---------- Serde ----------

    #[test]
    fn serde_roundtrip() {
        let rf = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        let json = serde_json::to_string(&rf).expect("serialize");
        let round: ReplicationFactor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rf, round);
    }

    #[test]
    fn serde_roundtrip_max() {
        let rf = ReplicationFactor::new(16, FailureDomain::Datacenter).unwrap();
        let json = serde_json::to_string(&rf).expect("serialize");
        let round: ReplicationFactor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rf, round);
    }

    #[test]
    fn serde_roundtrip_min() {
        let rf = ReplicationFactor::new(1, FailureDomain::Device).unwrap();
        let json = serde_json::to_string(&rf).expect("serialize");
        let round: ReplicationFactor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rf, round);
    }

    // ---------- Display ----------

    #[test]
    fn display_node() {
        let rf = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        assert_eq!(format!("{rf}"), "3/node");
    }

    #[test]
    fn display_rack() {
        let rf = ReplicationFactor::new(5, FailureDomain::Rack).unwrap();
        assert_eq!(format!("{rf}"), "5/rack");
    }

    // ---------- Eq / Hash ----------

    #[test]
    fn equality_same() {
        let a = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        let b = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_copies() {
        let a = ReplicationFactor::new(2, FailureDomain::Node).unwrap();
        let b = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_domain() {
        let a = ReplicationFactor::new(3, FailureDomain::Node).unwrap();
        let b = ReplicationFactor::new(3, FailureDomain::Rack).unwrap();
        assert_ne!(a, b);
    }
}
