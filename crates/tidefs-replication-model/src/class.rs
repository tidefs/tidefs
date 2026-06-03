//! Replication class classification.
//!
//! A [`ReplicationClass`] classifies the replication strategy independently
//! of failure-domain placement. It is a simpler classification than the
//! full [`super::ReplicationIntent`], useful for quick capability checks and
//! configuration validation.

use serde::{Deserialize, Serialize};

/// Classification of replication strategy.
///
/// Encodes the data resilience approach: no redundancy, mirroring at fixed
/// copy counts, or erasure coding with configurable data/parity shards.
/// Unlike [`super::ReplicationIntent`], this type does not carry a failure
/// domain — it only describes the replication arithmetic.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplicationClass {
    /// No replication: single copy only. Data is lost if the sole device fails.
    None,
    /// 2-way mirror: two full copies on distinct targets.
    Mirror2,
    /// 3-way mirror: three full copies on distinct targets.
    Mirror3,
    /// Erasure-coded with `data` data shards and `parity` parity shards.
    ErasureCoded {
        /// Number of data shards (k). Must be >= 1.
        data: u8,
        /// Number of parity shards (m). Must be >= 1.
        parity: u8,
    },
}

impl ReplicationClass {
    /// Minimum number of distinct failure domains required by this class.
    ///
    /// Returns the number of distinct failure-domain targets needed:
    /// 1 for `None`, 2 for `Mirror2`, 3 for `Mirror3`,
    /// `data + parity` for `ErasureCoded`.
    #[must_use]
    pub const fn min_domains_required(&self) -> u8 {
        match self {
            ReplicationClass::None => 1,
            ReplicationClass::Mirror2 => 2,
            ReplicationClass::Mirror3 => 3,
            ReplicationClass::ErasureCoded { data, parity } => data.saturating_add(*parity),
        }
    }

    /// Returns `true` if this class provides any redundancy beyond a single
    /// copy.
    #[must_use]
    pub const fn has_redundancy(&self) -> bool {
        !matches!(self, ReplicationClass::None)
    }

    /// Returns `true` if this class uses erasure coding.
    #[must_use]
    pub const fn is_erasure_coded(&self) -> bool {
        matches!(self, ReplicationClass::ErasureCoded { .. })
    }

    /// Returns `true` if this class uses mirror replication.
    #[must_use]
    pub const fn is_mirror(&self) -> bool {
        matches!(self, ReplicationClass::Mirror2 | ReplicationClass::Mirror3)
    }
}

impl core::fmt::Display for ReplicationClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReplicationClass::None => write!(f, "none"),
            ReplicationClass::Mirror2 => write!(f, "mirror2"),
            ReplicationClass::Mirror3 => write!(f, "mirror3"),
            ReplicationClass::ErasureCoded { data, parity } => {
                write!(f, "ec(k={data},m={parity})")
            }
        }
    }
}

/// Errors returned by replication model validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReplicationModelError {
    /// Not enough failure domains available to satisfy the replication intent.
    #[error("insufficient failure domains: need {required}, have {available}")]
    InsufficientDomains {
        /// Minimum number of distinct domains required.
        required: u8,
        /// Number of domains actually available.
        available: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- min_domains_required tests --

    #[test]
    fn min_domains_none() {
        assert_eq!(ReplicationClass::None.min_domains_required(), 1);
    }

    #[test]
    fn min_domains_mirror2() {
        assert_eq!(ReplicationClass::Mirror2.min_domains_required(), 2);
    }

    #[test]
    fn min_domains_mirror3() {
        assert_eq!(ReplicationClass::Mirror3.min_domains_required(), 3);
    }

    #[test]
    fn min_domains_ec_4_2() {
        let ec = ReplicationClass::ErasureCoded { data: 4, parity: 2 };
        assert_eq!(ec.min_domains_required(), 6);
    }

    #[test]
    fn min_domains_ec_8_3() {
        let ec = ReplicationClass::ErasureCoded { data: 8, parity: 3 };
        assert_eq!(ec.min_domains_required(), 11);
    }

    // -- has_redundancy tests --

    #[test]
    fn none_has_no_redundancy() {
        assert!(!ReplicationClass::None.has_redundancy());
    }

    #[test]
    fn mirror2_has_redundancy() {
        assert!(ReplicationClass::Mirror2.has_redundancy());
    }

    #[test]
    fn ec_has_redundancy() {
        let ec = ReplicationClass::ErasureCoded { data: 4, parity: 2 };
        assert!(ec.has_redundancy());
    }

    // -- classification tests --

    #[test]
    fn classification_none() {
        assert!(!ReplicationClass::None.is_erasure_coded());
        assert!(!ReplicationClass::None.is_mirror());
    }

    #[test]
    fn classification_mirror() {
        assert!(!ReplicationClass::Mirror2.is_erasure_coded());
        assert!(ReplicationClass::Mirror2.is_mirror());
        assert!(ReplicationClass::Mirror3.is_mirror());
    }

    #[test]
    fn classification_ec() {
        let ec = ReplicationClass::ErasureCoded { data: 4, parity: 2 };
        assert!(ec.is_erasure_coded());
        assert!(!ec.is_mirror());
    }

    // -- serde roundtrip --

    #[test]
    fn serde_roundtrip() {
        for class in &[
            ReplicationClass::None,
            ReplicationClass::Mirror2,
            ReplicationClass::Mirror3,
            ReplicationClass::ErasureCoded { data: 4, parity: 2 },
        ] {
            let json = serde_json::to_string(class).expect("serialize");
            let round: ReplicationClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*class, round, "roundtrip failed for {class:?}");
        }
    }

    // -- Display --

    #[test]
    fn display_formatting() {
        assert_eq!(format!("{}", ReplicationClass::None), "none");
        assert_eq!(format!("{}", ReplicationClass::Mirror2), "mirror2");
        assert_eq!(format!("{}", ReplicationClass::Mirror3), "mirror3");
        let ec = ReplicationClass::ErasureCoded { data: 4, parity: 2 };
        assert_eq!(format!("{ec}"), "ec(k=4,m=2)");
    }
}
