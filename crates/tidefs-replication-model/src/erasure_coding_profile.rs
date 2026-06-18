// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Erasure coding profile definition.
//!
//! An [`ErasureCodingProfile`] defines the encoding parameters — data shard
//! count `k`, parity shard count `m`, and the algorithm — that the erasure
//! coding layer uses for encode and decode operations.

use serde::{Deserialize, Serialize};

/// Erasure coding algorithm selector.
///
/// The algorithm determines how data and parity shards are computed during
/// encode and how lost shards are recovered during decode.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErasureCodingAlgorithm {
    /// Reed-Solomon erasure coding over GF(2^8) or GF(2^16).
    ReedSolomon,
    /// Simple single-parity XOR (RAID-5 style, m=1 only).
    SingleParityXor,
}

impl core::fmt::Display for ErasureCodingAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErasureCodingAlgorithm::ReedSolomon => write!(f, "reed-solomon"),
            ErasureCodingAlgorithm::SingleParityXor => write!(f, "xor"),
        }
    }
}

/// Validated erasure coding profile.
///
/// Holds `k` data shards + `m` parity shards and the encoding algorithm.
/// Construction validates that k >= 1, m >= 1, and rejects degenerate
/// configurations.
///
/// # Examples
///
/// ```
/// use tidefs_replication_model::{
///     ErasureCodingProfile, ErasureCodingAlgorithm,
/// };
///
/// let profile = ErasureCodingProfile::new(
///     4, 2, ErasureCodingAlgorithm::ReedSolomon,
/// ).unwrap();
/// assert_eq!(profile.data_shards(), 4);
/// assert_eq!(profile.parity_shards(), 2);
/// assert_eq!(profile.total_shards(), 6);
/// ```
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErasureCodingProfile {
    /// Number of data shards (k).
    data_shards: u8,
    /// Number of parity shards (m).
    parity_shards: u8,
    /// The algorithm used for encoding and decoding.
    algorithm: ErasureCodingAlgorithm,
}

/// Errors returned when constructing an [`ErasureCodingProfile`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ErasureCodingProfileError {
    /// Data shard count k must be at least 1.
    #[error("data shard count k must be at least 1, got {got}")]
    DataShardsTooLow { got: u8 },
    /// Parity shard count m must be at least 1.
    #[error("parity shard count m must be at least 1, got {got}")]
    ParityShardsTooLow { got: u8 },
    /// XOR algorithm requires m = 1.
    #[error("SingleParityXor requires m = 1, got m = {got}")]
    XorRequiresSingleParity { got: u8 },
}

impl ErasureCodingProfile {
    /// Construct a validated erasure coding profile.
    ///
    /// Validates that k >= 1, m >= 1, and that the algorithm parameters are
    /// consistent (e.g. XOR requires m = 1).
    pub fn new(
        data_shards: u8,
        parity_shards: u8,
        algorithm: ErasureCodingAlgorithm,
    ) -> Result<Self, ErasureCodingProfileError> {
        if data_shards < 1 {
            return Err(ErasureCodingProfileError::DataShardsTooLow { got: data_shards });
        }
        if parity_shards < 1 {
            return Err(ErasureCodingProfileError::ParityShardsTooLow { got: parity_shards });
        }
        if algorithm == ErasureCodingAlgorithm::SingleParityXor && parity_shards != 1 {
            return Err(ErasureCodingProfileError::XorRequiresSingleParity { got: parity_shards });
        }
        Ok(Self {
            data_shards,
            parity_shards,
            algorithm,
        })
    }

    /// Number of data shards (k).
    #[must_use]
    pub const fn data_shards(&self) -> u8 {
        self.data_shards
    }

    /// Number of parity shards (m).
    #[must_use]
    pub const fn parity_shards(&self) -> u8 {
        self.parity_shards
    }

    /// Total number of shards: k + m.
    #[must_use]
    pub const fn total_shards(&self) -> u8 {
        self.data_shards.saturating_add(self.parity_shards)
    }

    /// The encoding algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> ErasureCodingAlgorithm {
        self.algorithm
    }

    /// Maximum number of shard failures this profile can tolerate.
    ///
    /// For Reed-Solomon, this is `m` (any m shards can be lost).
    /// For XOR, this is 1 (m is always 1).
    #[must_use]
    pub const fn max_tolerable_failures(&self) -> u8 {
        self.parity_shards
    }

    /// Returns `true` if the data can be reconstructed after `lost` shard
    /// failures.
    #[must_use]
    pub const fn is_recoverable_after(&self, lost: u8) -> bool {
        lost <= self.parity_shards
    }

    /// Storage overhead ratio: total / data.
    ///
    /// Returns `None` when data_shards is 0 (impossible after validation).
    #[must_use]
    pub const fn overhead_ratio_numer_denom(&self) -> (u8, u8) {
        (self.total_shards(), self.data_shards)
    }

    /// Minimum number of shards required for reconstruction (k).
    #[must_use]
    pub const fn min_shards_for_reconstruction(&self) -> u8 {
        self.data_shards
    }
}

impl core::fmt::Display for ErasureCodingProfile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ec-{}(k={},m={})",
            self.algorithm, self.data_shards, self.parity_shards
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- Construction ----------

    #[test]
    fn valid_rs_4_2() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.data_shards(), 4);
        assert_eq!(p.parity_shards(), 2);
        assert_eq!(p.algorithm(), ErasureCodingAlgorithm::ReedSolomon);
    }

    #[test]
    fn valid_rs_10_4() {
        let p = ErasureCodingProfile::new(10, 4, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.total_shards(), 14);
    }

    #[test]
    fn valid_xor_1_1() {
        let p = ErasureCodingProfile::new(1, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert_eq!(p.total_shards(), 2);
    }

    #[test]
    fn valid_xor_8_1() {
        let p = ErasureCodingProfile::new(8, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert_eq!(p.data_shards(), 8);
        assert_eq!(p.parity_shards(), 1);
    }

    #[test]
    fn reject_k_zero() {
        let err = ErasureCodingProfile::new(0, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap_err();
        assert!(matches!(
            err,
            ErasureCodingProfileError::DataShardsTooLow { got: 0 }
        ));
    }

    #[test]
    fn reject_m_zero() {
        let err = ErasureCodingProfile::new(4, 0, ErasureCodingAlgorithm::ReedSolomon).unwrap_err();
        assert!(matches!(
            err,
            ErasureCodingProfileError::ParityShardsTooLow { got: 0 }
        ));
    }

    #[test]
    fn reject_xor_m_not_1() {
        let err =
            ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::SingleParityXor).unwrap_err();
        assert!(matches!(
            err,
            ErasureCodingProfileError::XorRequiresSingleParity { got: 2 }
        ));
    }

    #[test]
    fn reject_k_and_m_zero() {
        let err = ErasureCodingProfile::new(0, 0, ErasureCodingAlgorithm::ReedSolomon).unwrap_err();
        assert!(matches!(
            err,
            ErasureCodingProfileError::DataShardsTooLow { got: 0 }
        ));
    }

    // ---------- Derived properties ----------

    #[test]
    fn total_shards_4_2() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.total_shards(), 6);
    }

    #[test]
    fn total_shards_1_1() {
        let p = ErasureCodingProfile::new(1, 1, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.total_shards(), 2);
    }

    #[test]
    fn max_tolerable_failures_rs() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.max_tolerable_failures(), 2);
    }

    #[test]
    fn max_tolerable_failures_rs_10_4() {
        let p = ErasureCodingProfile::new(10, 4, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.max_tolerable_failures(), 4);
    }

    #[test]
    fn max_tolerable_failures_xor() {
        let p = ErasureCodingProfile::new(5, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert_eq!(p.max_tolerable_failures(), 1);
    }

    // ---------- Recoverability ----------

    #[test]
    fn is_recoverable_after_rs() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert!(p.is_recoverable_after(0));
        assert!(p.is_recoverable_after(1));
        assert!(p.is_recoverable_after(2));
        assert!(!p.is_recoverable_after(3));
    }

    #[test]
    fn is_recoverable_after_xor() {
        let p = ErasureCodingProfile::new(8, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert!(p.is_recoverable_after(0));
        assert!(p.is_recoverable_after(1));
        assert!(!p.is_recoverable_after(2));
    }

    // ---------- Overhead ----------

    #[test]
    fn overhead_ratio_4_2() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.overhead_ratio_numer_denom(), (6, 4));
    }

    #[test]
    fn overhead_ratio_10_4() {
        let p = ErasureCodingProfile::new(10, 4, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.overhead_ratio_numer_denom(), (14, 10));
    }

    // ---------- Min shards for reconstruction ----------

    #[test]
    fn min_shards_for_reconstruction_rs() {
        let p = ErasureCodingProfile::new(6, 3, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(p.min_shards_for_reconstruction(), 6);
    }

    // ---------- Serde ----------

    #[test]
    fn serde_roundtrip_rs() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        let json = serde_json::to_string(&p).expect("serialize");
        let round: ErasureCodingProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, round);
    }

    #[test]
    fn serde_roundtrip_xor() {
        let p = ErasureCodingProfile::new(3, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        let json = serde_json::to_string(&p).expect("serialize");
        let round: ErasureCodingProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, round);
    }

    #[test]
    fn serde_roundtrip_edge_min() {
        let p = ErasureCodingProfile::new(1, 1, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        let json = serde_json::to_string(&p).expect("serialize");
        let round: ErasureCodingProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, round);
    }

    // ---------- Display ----------

    #[test]
    fn display_rs() {
        let p = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(format!("{p}"), "ec-reed-solomon(k=4,m=2)");
    }

    #[test]
    fn display_xor() {
        let p = ErasureCodingProfile::new(8, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert_eq!(format!("{p}"), "ec-xor(k=8,m=1)");
    }

    // ---------- Eq / Hash ----------

    #[test]
    fn equality_same() {
        let a = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        let b = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn inequality_different_k() {
        let a = ErasureCodingProfile::new(4, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        let b = ErasureCodingProfile::new(6, 2, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn inequality_different_algorithm() {
        let a = ErasureCodingProfile::new(4, 1, ErasureCodingAlgorithm::ReedSolomon).unwrap();
        let b = ErasureCodingProfile::new(4, 1, ErasureCodingAlgorithm::SingleParityXor).unwrap();
        assert_ne!(a, b);
    }
}
