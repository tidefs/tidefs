// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! TideFS-native durability layout descriptor.
//!
//! A [`DurabilityPolicy`] encodes the data placement policy — mirror or
//! erasure-style (k+m) — and is embedded in [`DurabilityLayoutV1`] alongside
//! failure-domain constraints. Each layout carries a BLAKE3 domain-separated
//! self-verification checksum that detects on-disk corruption of the layout
//! descriptor itself.
//!
//! ## Key Types
//!
//! - [`DurabilityPolicy`]: the policy enum (Mirror, ErasureStyle, or Hybrid).
//! - [`DurabilityLayoutV1`]: struct wrapping a policy with self-checksum.
//! - [`FailureDomainV1`]: hierarchy level with target count.

use tidefs_binary_schema_core::BinarySchemaError;

// ---------------------------------------------------------------------------
// Domain context for BLAKE3 self-verification
// ---------------------------------------------------------------------------

/// Domain-separation context string for BLAKE3 `derive_key` mode.
///
/// Every `DurabilityLayoutV1` self-checksum uses this context to prevent
/// cross-type digest collision attacks.
const DURABILITY_LAYOUT_V1_CONTEXT: &str = "TideFS DurabilityLayoutV1 v1";

/// BLAKE3-256 digest size in bytes.
pub const DIGEST_SIZE: usize = 32;

/// A 32-byte BLAKE3 digest.
pub type Digest = [u8; DIGEST_SIZE];

// ---------------------------------------------------------------------------
// Maximum constants
// ---------------------------------------------------------------------------

/// Maximum mirror copy count (32 replicas across failure-domain targets).
pub const MAX_MIRROR_COUNT: u8 = 32;

/// Maximum data shard count in an erasure layout.
pub const MAX_DATA_SHARDS: u8 = 32;

/// Maximum parity shard count in an erasure layout.
pub const MAX_PARITY_SHARDS: u8 = 32;

/// Maximum mirror copy count in a hybrid layout.
pub const MAX_HYBRID_MIRROR_COUNT: u8 = 8;

/// Maximum target count in a failure domain descriptor.
pub const MAX_FAILURE_DOMAIN_TARGETS: u8 = 64;

// ---------------------------------------------------------------------------
// DurabilityPolicy
// ---------------------------------------------------------------------------

/// TideFS-native durability policy.
///
/// Encodes the data placement policy — mirror (replication) or erasure-style
/// (Reed-Solomon / Cauchy) k+m encoding. This is the single mechanism for
/// durability policy described in v0.262, consumed by
/// [`DurabilityLayoutV1`] and the placement planner.
///
/// Binary encoding (little-endian):
///
/// ```text
/// offset  size  field
/// 0       1     discriminant (0 = Mirror, 1 = ErasureStyle)
/// 1       N     variant payload (see variant docs)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DurabilityPolicy {
    /// N-way mirroring (replication).
    ///
    /// Binary payload: 1 byte `copies` (u8).
    Mirror {
        /// Number of replicas. Must be in `1..=MAX_MIRROR_COUNT`.
        copies: u8,
    },
    /// Erasure-style encoding with k data + m parity shards.
    ///
    /// Binary payload: 1 byte `data_shards`, 1 byte `parity_shards`.
    ErasureStyle {
        /// Number of data shards (k). Must be in `1..=MAX_DATA_SHARDS`.
        data_shards: u8,
        /// Number of parity shards (m). Must be in `1..=MAX_PARITY_SHARDS`.
        parity_shards: u8,
    },
    /// Hybrid policy: mirror across failure domains, erasure-code within each.
    Hybrid {
        mirror_copies: u8,
        data_shards: u8,
        parity_shards: u8,
    },
}

/// Discriminant byte for a [`DurabilityPolicy`] variant.
#[repr(u8)]
enum PolicyDiscriminant {
    Mirror = 0,
    ErasureStyle = 1,
    Hybrid = 2,
}

impl PolicyDiscriminant {
    fn from_u8(d: u8) -> Option<Self> {
        match d {
            0 => Some(Self::Mirror),
            1 => Some(Self::ErasureStyle),
            2 => Some(Self::Hybrid),
            _ => None,
        }
    }
}

impl DurabilityPolicy {
    /// Construct a `Mirror` policy, validating copies.
    ///
    /// Returns `Err` if `copies` is 0 or exceeds `MAX_MIRROR_COUNT`.
    pub fn mirror(copies: u8) -> Result<Self, DurabilityLayoutError> {
        if copies == 0 {
            return Err(DurabilityLayoutError::MirrorCountZero);
        }
        if copies > MAX_MIRROR_COUNT {
            return Err(DurabilityLayoutError::MirrorCountTooLarge {
                count: copies,
                max: MAX_MIRROR_COUNT,
            });
        }
        Ok(Self::Mirror { copies })
    }

    /// Construct an `ErasureStyle` policy, validating k and m.
    ///
    /// Both `data_shards` and `parity_shards` must be non-zero and within
    /// `MAX_DATA_SHARDS` / `MAX_PARITY_SHARDS`.
    pub fn erasure_style(
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Self, DurabilityLayoutError> {
        if data_shards == 0 {
            return Err(DurabilityLayoutError::DataShardsZero);
        }
        if data_shards > MAX_DATA_SHARDS {
            return Err(DurabilityLayoutError::DataShardsTooLarge {
                count: data_shards,
                max: MAX_DATA_SHARDS,
            });
        }
        if parity_shards == 0 {
            return Err(DurabilityLayoutError::ParityShardsZero);
        }
        if parity_shards > MAX_PARITY_SHARDS {
            return Err(DurabilityLayoutError::ParityShardsTooLarge {
                count: parity_shards,
                max: MAX_PARITY_SHARDS,
            });
        }
        Ok(Self::ErasureStyle {
            data_shards,
            parity_shards,
        })
    }

    /// Construct a `Hybrid` policy, validating all counts.
    pub fn hybrid(
        mirror_copies: u8,
        data_shards: u8,
        parity_shards: u8,
    ) -> Result<Self, DurabilityLayoutError> {
        if mirror_copies == 0 {
            return Err(DurabilityLayoutError::MirrorCountZero);
        }
        if mirror_copies > MAX_HYBRID_MIRROR_COUNT {
            return Err(DurabilityLayoutError::MirrorCountTooLarge {
                count: mirror_copies,
                max: MAX_HYBRID_MIRROR_COUNT,
            });
        }
        if data_shards == 0 {
            return Err(DurabilityLayoutError::DataShardsZero);
        }
        if data_shards > MAX_DATA_SHARDS {
            return Err(DurabilityLayoutError::DataShardsTooLarge {
                count: data_shards,
                max: MAX_DATA_SHARDS,
            });
        }
        if parity_shards == 0 {
            return Err(DurabilityLayoutError::ParityShardsZero);
        }
        if parity_shards > MAX_PARITY_SHARDS {
            return Err(DurabilityLayoutError::ParityShardsTooLarge {
                count: parity_shards,
                max: MAX_PARITY_SHARDS,
            });
        }
        Ok(Self::Hybrid {
            mirror_copies,
            data_shards,
            parity_shards,
        })
    }

    /// Return the discriminant byte for this variant.
    pub fn discriminant(&self) -> u8 {
        match self {
            Self::Mirror { .. } => PolicyDiscriminant::Mirror as u8,
            Self::ErasureStyle { .. } => PolicyDiscriminant::ErasureStyle as u8,
            Self::Hybrid { .. } => PolicyDiscriminant::Hybrid as u8,
        }
    }

    /// Return the total shard count required by this policy.
    ///
    /// Mirror: `copies`. ErasureStyle: `data_shards + parity_shards`.
    /// Hybrid: `mirror_copies * (data_shards + parity_shards)`.
    pub fn total_shards(&self) -> usize {
        match self {
            Self::Mirror { copies } => *copies as usize,
            Self::ErasureStyle {
                data_shards,
                parity_shards,
            } => (*data_shards + *parity_shards) as usize,
            Self::Hybrid {
                mirror_copies,
                data_shards,
                parity_shards,
            } => {
                let copies = *mirror_copies as usize;
                let shards_per_copy = (*data_shards + *parity_shards) as usize;
                copies * shards_per_copy
            }
        }
    }

    /// Validate this policy against available device and failure-domain
    /// resources.
    ///
    /// Checks that the policy is internally consistent (no zero counts)
    /// and satisfiable by the given `device_count` and `failure_domains`.
    ///
    /// For each failure domain in the list, the policy's shard count must
    /// not exceed that domain's `target_count`. Returns
    /// [`PolicyValidationError`] on the first violation found.
    pub fn validate(
        &self,
        device_count: usize,
        failure_domains: &[FailureDomainV1],
    ) -> Result<(), PolicyValidationError> {
        let required = self.total_shards();

        // Check against total device count.
        if required > device_count {
            return Err(PolicyValidationError::InsufficientDevices {
                required,
                available: device_count,
            });
        }

        // Check against each failure domain's target count.
        for fd in failure_domains {
            if required > fd.target_count as usize {
                return Err(PolicyValidationError::InsufficientFailureDomainTargets {
                    domain_level: fd.level,
                    required,
                    available: fd.target_count as usize,
                });
            }
        }

        // For Hybrid, also verify mirror_copies <= device_count
        if let Self::Hybrid { mirror_copies, .. } = self {
            if *mirror_copies as usize > device_count {
                return Err(PolicyValidationError::InsufficientDevices {
                    required: *mirror_copies as usize,
                    available: device_count,
                });
            }
        }

        Ok(())
    }

    /// Encode this policy into a byte vector.
    ///
    /// Returns the binary encoding: 1 byte discriminant + payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        match self {
            Self::Mirror { copies } => {
                buf.push(PolicyDiscriminant::Mirror as u8);
                buf.push(*copies);
            }
            Self::ErasureStyle {
                data_shards,
                parity_shards,
            } => {
                buf.push(PolicyDiscriminant::ErasureStyle as u8);
                buf.push(*data_shards);
                buf.push(*parity_shards);
            }
            Self::Hybrid {
                mirror_copies,
                data_shards,
                parity_shards,
            } => {
                buf.push(PolicyDiscriminant::Hybrid as u8);
                buf.push(*mirror_copies);
                buf.push(*data_shards);
                buf.push(*parity_shards);
            }
        }
        buf
    }

    /// Return the length of the encoded representation in bytes.
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Mirror { .. } => 2,
            Self::ErasureStyle { .. } => 3,
            Self::Hybrid { .. } => 4,
        }
    }

    /// Decode a `DurabilityPolicy` from raw bytes.
    ///
    /// Validates the discriminant and enforces that each variant's payload
    /// satisfies its construction constraints.
    pub fn decode(buf: &[u8]) -> Result<Self, BinarySchemaError> {
        if buf.is_empty() {
            return Err(BinarySchemaError::BoundsViolation);
        }
        let disc = PolicyDiscriminant::from_u8(buf[0])
            .ok_or_else(|| BinarySchemaError::BadMagic { got: buf[0] as u32 })?;
        match disc {
            PolicyDiscriminant::Mirror => {
                if buf.len() < 2 {
                    return Err(BinarySchemaError::BoundsViolation);
                }
                let copies = buf[1];
                Self::mirror(copies).map_err(|_| BinarySchemaError::EncodeError)
            }
            PolicyDiscriminant::ErasureStyle => {
                if buf.len() < 3 {
                    return Err(BinarySchemaError::BoundsViolation);
                }
                let data_shards = buf[1];
                let parity_shards = buf[2];
                Self::erasure_style(data_shards, parity_shards)
                    .map_err(|_| BinarySchemaError::EncodeError)
            }
            PolicyDiscriminant::Hybrid => {
                if buf.len() < 4 {
                    return Err(BinarySchemaError::BoundsViolation);
                }
                let mirror_copies = buf[1];
                let data_shards = buf[2];
                let parity_shards = buf[3];
                Self::hybrid(mirror_copies, data_shards, parity_shards)
                    .map_err(|_| BinarySchemaError::EncodeError)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DurabilityLayoutV1
// ---------------------------------------------------------------------------

/// TideFS-native durability layout descriptor.
///
/// Wraps a [`DurabilityPolicy`] with a BLAKE3 self-verification checksum.
/// Future versions may add per-policy metadata (e.g. target domains, shard
/// size hints).
///
/// Binary encoding delegates directly to the embedded [`DurabilityPolicy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DurabilityLayoutV1 {
    /// The durability policy (mirror or erasure-style).
    pub policy: DurabilityPolicy,
}

impl DurabilityLayoutV1 {
    /// Construct a `Mirror` layout, validating copies.
    ///
    /// Returns `Err` if `copies` is 0 or exceeds `MAX_MIRROR_COUNT`.
    pub fn mirror(copies: u8) -> Result<Self, DurabilityLayoutError> {
        Ok(Self {
            policy: DurabilityPolicy::mirror(copies)?,
        })
    }

    /// Construct an `Erasure` layout, validating k and m.
    ///
    /// Both `data_shards` and `parity_shards` must be non-zero and within
    /// `MAX_DATA_SHARDS` / `MAX_PARITY_SHARDS`.
    pub fn erasure(data_shards: u8, parity_shards: u8) -> Result<Self, DurabilityLayoutError> {
        Ok(Self {
            policy: DurabilityPolicy::erasure_style(data_shards, parity_shards)?,
        })
    }

    /// Encode this layout into a byte vector.
    ///
    /// Delegates to the embedded [`DurabilityPolicy`] encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.policy.encode()
    }

    /// Return the length of the encoded representation in bytes.
    pub fn encoded_len(&self) -> usize {
        self.policy.encoded_len()
    }

    /// Decode a `DurabilityLayoutV1` from raw bytes.
    ///
    /// Delegates to [`DurabilityPolicy::decode`].
    pub fn decode(buf: &[u8]) -> Result<Self, BinarySchemaError> {
        Ok(Self {
            policy: DurabilityPolicy::decode(buf)?,
        })
    }

    /// Compute the BLAKE3 domain-separated self-checksum of this layout.
    ///
    /// Uses `derive_key` mode with the context string `b"TideFS DurabilityLayoutV1 v1"`
    /// to prevent cross-type digest collisions.
    pub fn checksum(&self) -> Digest {
        let encoded = self.encode();
        let mut hasher = blake3::Hasher::new_derive_key(DURABILITY_LAYOUT_V1_CONTEXT);
        hasher.update(&encoded);
        hasher.finalize().into()
    }

    /// Verify the self-checksum of this layout against an expected digest.
    ///
    /// Returns `Ok(())` if the digest matches, `Err(BinarySchemaError::DigestMismatch)`
    /// otherwise.
    pub fn verify_checksum(&self, expected: &Digest) -> Result<(), BinarySchemaError> {
        let actual = self.checksum();
        if actual == *expected {
            Ok(())
        } else {
            Err(BinarySchemaError::DigestMismatch)
        }
    }

    /// Determine whether this layout can survive the given number of
    /// concurrent device and node failures without data loss.
    ///
    /// For a `Mirror{N}` layout, up to N-1 total failures are tolerated
    /// (at least one replica survives). For an `ErasureStyle{k,m}` layout,
    /// up to m failures are tolerated (at least k data shards survive).
    ///
    /// The check is conservative: each failure domain (device, node) is
    /// independently compared against the redundancy limit.
    #[must_use]
    pub fn survives_failure(&self, failed_devices: u32, failed_nodes: u32) -> bool {
        let max_tolerable = match &self.policy {
            DurabilityPolicy::Mirror { copies } => (*copies as u32).saturating_sub(1),
            DurabilityPolicy::ErasureStyle { parity_shards, .. } => *parity_shards as u32,
            DurabilityPolicy::Hybrid {
                mirror_copies,
                parity_shards,
                ..
            } => ((*mirror_copies as u32).saturating_sub(1)) + (*parity_shards as u32),
        };
        if failed_devices > max_tolerable {
            return false;
        }
        failed_nodes <= max_tolerable
    }
}

// ---------------------------------------------------------------------------
// FailureDomainV1
// ---------------------------------------------------------------------------

/// Failure domain descriptor for placement policy.
///
/// Encodes the hierarchy level (device, node, rack) at which data is spread,
/// along with the target count. Placement strategies use this to decide
/// whether two targets share a failure domain.
///
/// Binary encoding (little-endian):
///
/// ```text
/// offset  size  field
/// 0       1     discriminant (0 = Device, 1 = Node, 2 = Rack)
/// 1       1     target_count (u8)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FailureDomainV1 {
    /// The hierarchy level.
    pub level: FailureDomainLevel,
    /// Number of distinct targets at this level. Must be in `1..=MAX_FAILURE_DOMAIN_TARGETS`.
    pub target_count: u8,
}

/// Hierarchy levels for failure domains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureDomainLevel {
    /// Device-level (individual drives/NVMe).
    Device = 0,
    /// Node-level (individual hosts/servers).
    Node = 1,
    /// Rack-level (physical rack / power domain).
    Rack = 2,
    /// Datacenter-level (availability zone).
    Datacenter = 3,
}

impl FailureDomainLevel {
    /// Decode from a discriminant byte.
    pub fn from_u8(d: u8) -> Option<Self> {
        match d {
            0 => Some(Self::Device),
            1 => Some(Self::Node),
            2 => Some(Self::Rack),
            3 => Some(Self::Datacenter),
            _ => None,
        }
    }

    /// Return the discriminant byte.
    pub fn discriminant(self) -> u8 {
        self as u8
    }

    /// Return the numeric hierarchy depth (0 = Device, 3 = Datacenter).
    pub fn depth(self) -> u8 {
        self as u8
    }

    /// Compute the hierarchy distance between two domain levels.
    ///
    /// Distance 0 means same level. Distance 1 means adjacent levels
    /// (e.g. Device↔Node). Maximum distance is 3 (Device↔Datacenter).
    pub fn distance(self, other: Self) -> u8 {
        let a = self as u8;
        let b = other as u8;
        a.abs_diff(b)
    }

    /// Returns `true` if `self` contains `other` in the failure-domain hierarchy.
    ///
    /// A higher level contains all lower levels. A level is contained in itself.
    pub fn contains(self, other: Self) -> bool {
        self as u8 >= other as u8
    }

    /// Returns `true` if `self` is contained within `other`.
    pub fn is_contained_in(self, other: Self) -> bool {
        other.contains(self)
    }

    /// Returns `true` if two targets at this level can be co-located in
    /// the same failure domain at the given `constraint` level.
    ///
    /// Two devices can be co-located in the same node (constraint=Node)
    /// but not in the same device (constraint=Device).
    pub fn can_co_locate_in(self, constraint: Self) -> bool {
        (self as u8) < (constraint as u8)
    }

    /// Returns the next broader failure domain level.
    pub fn next_broader(self) -> Option<Self> {
        Self::from_u8((self as u8).saturating_add(1))
    }
}

impl FailureDomainV1 {
    /// Construct a new failure domain descriptor.
    ///
    /// Returns `Err` if `target_count` is 0 or exceeds `MAX_FAILURE_DOMAIN_TARGETS`.
    pub fn new(level: FailureDomainLevel, target_count: u8) -> Result<Self, DurabilityLayoutError> {
        if target_count == 0 {
            return Err(DurabilityLayoutError::FailureDomainTargetsZero);
        }
        if target_count > MAX_FAILURE_DOMAIN_TARGETS {
            return Err(DurabilityLayoutError::FailureDomainTargetsTooLarge {
                count: target_count,
                max: MAX_FAILURE_DOMAIN_TARGETS,
            });
        }
        Ok(Self {
            level,
            target_count,
        })
    }

    /// Encode this failure domain descriptor to bytes.
    pub fn encode(&self) -> [u8; 2] {
        [self.level.discriminant(), self.target_count]
    }

    /// Decode a `FailureDomainV1` from 2 bytes.
    pub fn decode(buf: &[u8; 2]) -> Result<Self, BinarySchemaError> {
        let level = FailureDomainLevel::from_u8(buf[0])
            .ok_or_else(|| BinarySchemaError::BadMagic { got: buf[0] as u32 })?;
        let target_count = buf[1];
        Self::new(level, target_count).map_err(|_| BinarySchemaError::EncodeError)
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors specific to durability layout construction and validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurabilityLayoutError {
    /// Mirror count must be at least 1.
    MirrorCountZero,
    /// Mirror count exceeds the maximum.
    MirrorCountTooLarge { count: u8, max: u8 },
    /// Data shard count (k) must be at least 1.
    DataShardsZero,
    /// Data shard count exceeds the maximum.
    DataShardsTooLarge { count: u8, max: u8 },
    /// Parity shard count (m) must be at least 1.
    ParityShardsZero,
    /// Parity shard count exceeds the maximum.
    ParityShardsTooLarge { count: u8, max: u8 },
    /// Failure domain target count must be at least 1.
    FailureDomainTargetsZero,
    /// Failure domain target count exceeds the maximum.
    FailureDomainTargetsTooLarge { count: u8, max: u8 },
}

/// Errors produced by [`DurabilityPolicy::validate`] when the policy cannot be
/// satisfied by the available resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyValidationError {
    /// Not enough total devices for the required shard count.
    InsufficientDevices { required: usize, available: usize },
    /// A failure domain has insufficient targets for the required shard count.
    InsufficientFailureDomainTargets {
        domain_level: FailureDomainLevel,
        required: usize,
        available: usize,
    },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DurabilityPolicy: Mirror round-trip --------------------------------

    #[test]
    fn policy_mirror_round_trip_min() {
        let policy = DurabilityPolicy::mirror(1).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn policy_mirror_round_trip_max() {
        let policy = DurabilityPolicy::mirror(MAX_MIRROR_COUNT).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn policy_mirror_round_trip_mid() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    // -- DurabilityPolicy: ErasureStyle round-trip --------------------------

    #[test]
    fn policy_erasure_style_round_trip_min() {
        let policy = DurabilityPolicy::erasure_style(1, 1).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn policy_erasure_style_round_trip_max() {
        let policy = DurabilityPolicy::erasure_style(MAX_DATA_SHARDS, MAX_PARITY_SHARDS).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    #[test]
    fn policy_erasure_style_round_trip_8_4() {
        let policy = DurabilityPolicy::erasure_style(8, 4).unwrap();
        let encoded = policy.encode();
        let decoded = DurabilityPolicy::decode(&encoded).unwrap();
        assert_eq!(decoded, policy);
    }

    // -- DurabilityPolicy: construction rejection ---------------------------

    #[test]
    fn policy_mirror_copies_zero_rejected() {
        assert!(DurabilityPolicy::mirror(0).is_err());
    }

    #[test]
    fn policy_mirror_copies_too_large_rejected() {
        assert!(DurabilityPolicy::mirror(MAX_MIRROR_COUNT + 1).is_err());
    }

    #[test]
    fn policy_erasure_data_zero_rejected() {
        assert!(DurabilityPolicy::erasure_style(0, 1).is_err());
    }

    #[test]
    fn policy_erasure_parity_zero_rejected() {
        assert!(DurabilityPolicy::erasure_style(1, 0).is_err());
    }

    #[test]
    fn policy_erasure_data_too_large_rejected() {
        assert!(DurabilityPolicy::erasure_style(MAX_DATA_SHARDS + 1, 1).is_err());
    }

    #[test]
    fn policy_erasure_parity_too_large_rejected() {
        assert!(DurabilityPolicy::erasure_style(1, MAX_PARITY_SHARDS + 1).is_err());
    }

    // -- DurabilityPolicy: total_shards -------------------------------------

    #[test]
    fn policy_total_shards_mirror() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        assert_eq!(policy.total_shards(), 3);
    }

    #[test]
    fn policy_total_shards_erasure() {
        let policy = DurabilityPolicy::erasure_style(8, 3).unwrap();
        assert_eq!(policy.total_shards(), 11);
    }

    #[test]
    fn policy_total_shards_erasure_min() {
        let policy = DurabilityPolicy::erasure_style(1, 1).unwrap();
        assert_eq!(policy.total_shards(), 2);
    }

    // -- DurabilityPolicy: validate -----------------------------------------

    #[test]
    fn validate_mirror_sufficient_devices() {
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 4).unwrap();
        assert!(policy.validate(4, &[fd]).is_ok());
    }

    #[test]
    fn validate_mirror_insufficient_devices() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap();
        let err = policy.validate(2, &[fd]).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientDevices { .. }
        ));
    }

    #[test]
    fn validate_erasure_sufficient_devices() {
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 6).unwrap();
        assert!(policy.validate(6, &[fd]).is_ok());
    }

    #[test]
    fn validate_erasure_insufficient_devices() {
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 6).unwrap();
        let err = policy.validate(5, &[fd]).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientDevices { .. }
        ));
    }

    #[test]
    fn validate_mirror_insufficient_failure_domain_targets() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap();
        let err = policy.validate(10, &[fd]).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientFailureDomainTargets {
                domain_level: FailureDomainLevel::Node,
                required: 3,
                available: 2,
            }
        ));
    }

    #[test]
    fn validate_erasure_insufficient_failure_domain_targets() {
        let policy = DurabilityPolicy::erasure_style(4, 2).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Rack, 5).unwrap();
        let err = policy.validate(100, &[fd]).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientFailureDomainTargets { .. }
        ));
    }

    #[test]
    fn validate_mirror_exact_devices() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 3).unwrap();
        assert!(policy.validate(3, &[fd]).is_ok());
    }

    #[test]
    fn validate_erasure_exact_devices() {
        let policy = DurabilityPolicy::erasure_style(8, 3).unwrap();
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 11).unwrap();
        assert!(policy.validate(11, &[fd]).is_ok());
    }

    #[test]
    fn validate_multiple_failure_domains_all_pass() {
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let fds = vec![
            FailureDomainV1::new(FailureDomainLevel::Device, 5).unwrap(),
            FailureDomainV1::new(FailureDomainLevel::Node, 3).unwrap(),
            FailureDomainV1::new(FailureDomainLevel::Rack, 2).unwrap(),
        ];
        assert!(policy.validate(5, &fds).is_ok());
    }

    #[test]
    fn validate_multiple_failure_domains_one_fails() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        let fds = vec![
            FailureDomainV1::new(FailureDomainLevel::Device, 10).unwrap(),
            FailureDomainV1::new(FailureDomainLevel::Node, 2).unwrap(), // too few
            FailureDomainV1::new(FailureDomainLevel::Rack, 5).unwrap(),
        ];
        let err = policy.validate(10, &fds).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientFailureDomainTargets {
                domain_level: FailureDomainLevel::Node,
                ..
            }
        ));
    }

    #[test]
    fn validate_empty_failure_domains_still_device_check() {
        // No failure domains — only device_count matters.
        let policy = DurabilityPolicy::mirror(2).unwrap();
        assert!(policy.validate(2, &[]).is_ok());
        let err = policy.validate(1, &[]).unwrap_err();
        assert!(matches!(
            err,
            PolicyValidationError::InsufficientDevices { .. }
        ));
    }

    // -- DurabilityPolicy: encode/decode edge cases -------------------------

    #[test]
    fn policy_decode_empty_buf_rejected() {
        assert!(DurabilityPolicy::decode(&[]).is_err());
    }

    #[test]
    fn policy_decode_bad_discriminant_rejected() {
        assert!(DurabilityPolicy::decode(&[0xFF]).is_err());
    }

    #[test]
    fn policy_decode_mirror_truncated_rejected() {
        assert!(DurabilityPolicy::decode(&[0x00]).is_err());
    }

    #[test]
    fn policy_decode_erasure_truncated_rejected() {
        assert!(DurabilityPolicy::decode(&[0x01, 0x08]).is_err());
    }

    #[test]
    fn policy_decode_mirror_zero_copies_in_wire_rejected() {
        // Wire format carries copies=0; decode must reject it.
        assert!(DurabilityPolicy::decode(&[0x00, 0x00]).is_err());
    }

    #[test]
    fn policy_decode_erasure_zero_data_in_wire_rejected() {
        assert!(DurabilityPolicy::decode(&[0x01, 0x00, 0x01]).is_err());
    }

    #[test]
    fn policy_decode_erasure_zero_parity_in_wire_rejected() {
        assert!(DurabilityPolicy::decode(&[0x01, 0x01, 0x00]).is_err());
    }

    // -- DurabilityPolicy: discriminant consistency -------------------------

    #[test]
    fn policy_mirror_discriminant() {
        let policy = DurabilityPolicy::mirror(3).unwrap();
        assert_eq!(policy.discriminant(), 0);
        assert_eq!(policy.encode()[0], 0);
    }

    #[test]
    fn policy_erasure_style_discriminant() {
        let policy = DurabilityPolicy::erasure_style(8, 3).unwrap();
        assert_eq!(policy.discriminant(), 1);
        assert_eq!(policy.encode()[0], 1);
    }

    // -- DurabilityPolicy: encoded_len --------------------------------------

    #[test]
    fn policy_mirror_encoded_len() {
        let policy = DurabilityPolicy::mirror(5).unwrap();
        assert_eq!(policy.encoded_len(), 2);
        assert_eq!(policy.encode().len(), 2);
    }

    #[test]
    fn policy_erasure_encoded_len() {
        let policy = DurabilityPolicy::erasure_style(8, 4).unwrap();
        assert_eq!(policy.encoded_len(), 3);
        assert_eq!(policy.encode().len(), 3);
    }

    // -- DurabilityLayoutV1: construction via DurabilityPolicy --------------

    #[test]
    fn layout_mirror_construction() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        assert_eq!(layout.policy, DurabilityPolicy::Mirror { copies: 3 });
    }

    #[test]
    fn layout_erasure_construction() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        assert_eq!(
            layout.policy,
            DurabilityPolicy::ErasureStyle {
                data_shards: 4,
                parity_shards: 2
            }
        );
    }

    #[test]
    fn layout_mirror_from_policy() {
        let policy = DurabilityPolicy::mirror(2).unwrap();
        let layout = DurabilityLayoutV1 { policy };
        assert_eq!(layout.policy, policy);
    }

    // -- DurabilityLayoutV1: encode/decode round-trip -----------------------

    #[test]
    fn layout_mirror_round_trip_min() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let encoded = layout.encode();
        let decoded = DurabilityLayoutV1::decode(&encoded).unwrap();
        assert_eq!(decoded, layout);
    }

    #[test]
    fn layout_erasure_round_trip_8_3() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let encoded = layout.encode();
        let decoded = DurabilityLayoutV1::decode(&encoded).unwrap();
        assert_eq!(decoded, layout);
    }

    // -- DurabilityLayoutV1: BLAKE3 self-verification -----------------------

    #[test]
    fn layout_mirror_checksum_verifies() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let digest = layout.checksum();
        assert!(layout.verify_checksum(&digest).is_ok());
    }

    #[test]
    fn layout_erasure_checksum_verifies() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let digest = layout.checksum();
        assert!(layout.verify_checksum(&digest).is_ok());
    }

    #[test]
    fn layout_mirror_tampered_checksum_fails() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let digest = layout.checksum();
        let other = DurabilityLayoutV1::mirror(4).unwrap();
        let other_digest = other.checksum();
        assert!(layout.verify_checksum(&other_digest).is_err());
        assert!(layout.verify_checksum(&digest).is_ok());
    }

    #[test]
    fn layout_erasure_tampered_checksum_fails() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let digest = layout.checksum();
        let other = DurabilityLayoutV1::erasure(8, 4).unwrap();
        let other_digest = other.checksum();
        assert!(layout.verify_checksum(&other_digest).is_err());
        assert!(layout.verify_checksum(&digest).is_ok());
    }

    #[test]
    fn layout_single_byte_tamper_detected() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let digest = layout.checksum();
        let mut encoded = layout.encode();
        encoded[2] ^= 0x01;
        let tampered_digest = blake3::Hasher::new_derive_key(DURABILITY_LAYOUT_V1_CONTEXT)
            .update(&encoded)
            .finalize();
        assert_ne!(tampered_digest.as_bytes(), &digest);
    }

    #[test]
    fn layout_checksum_domain_separation() {
        let mirror = DurabilityLayoutV1::mirror(3).unwrap();
        let erasure = DurabilityLayoutV1::erasure(3, 1).unwrap();
        assert_ne!(mirror.checksum(), erasure.checksum());
    }

    #[test]
    fn layout_checksum_deterministic() {
        let a = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let b = DurabilityLayoutV1::erasure(8, 3).unwrap();
        assert_eq!(a.checksum(), b.checksum());
    }

    #[test]
    fn layout_checksum_digest_size() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        let digest = layout.checksum();
        assert_eq!(digest.len(), DIGEST_SIZE);
    }

    // -- FailureDomainV1 ----------------------------------------------------

    #[test]
    fn failure_domain_round_trip_device() {
        let fd = FailureDomainV1::new(FailureDomainLevel::Device, 4).unwrap();
        let encoded = fd.encode();
        let decoded = FailureDomainV1::decode(&encoded).unwrap();
        assert_eq!(decoded.level.discriminant(), fd.level.discriminant());
        assert_eq!(decoded.target_count, fd.target_count);
    }

    #[test]
    fn failure_domain_round_trip_node() {
        let fd = FailureDomainV1::new(FailureDomainLevel::Node, 8).unwrap();
        let encoded = fd.encode();
        let decoded = FailureDomainV1::decode(&encoded).unwrap();
        assert_eq!(decoded.level.discriminant(), fd.level.discriminant());
        assert_eq!(decoded.target_count, fd.target_count);
    }

    #[test]
    fn failure_domain_round_trip_rack() {
        let fd = FailureDomainV1::new(FailureDomainLevel::Rack, 3).unwrap();
        let encoded = fd.encode();
        let decoded = FailureDomainV1::decode(&encoded).unwrap();
        assert_eq!(decoded.level.discriminant(), fd.level.discriminant());
        assert_eq!(decoded.target_count, fd.target_count);
    }

    #[test]
    fn failure_domain_zero_targets_rejected() {
        assert!(FailureDomainV1::new(FailureDomainLevel::Device, 0).is_err());
    }

    #[test]
    fn failure_domain_too_many_targets_rejected() {
        assert!(
            FailureDomainV1::new(FailureDomainLevel::Device, MAX_FAILURE_DOMAIN_TARGETS + 1)
                .is_err()
        );
    }

    #[test]
    fn failure_domain_max_targets_accepted() {
        assert!(FailureDomainV1::new(FailureDomainLevel::Rack, MAX_FAILURE_DOMAIN_TARGETS).is_ok());
    }

    // -- DurabilityLayoutV1::survives_failure ------------------------------

    #[test]
    fn survives_failure_mirror_2_copies_survives_1_device() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        assert!(layout.survives_failure(1, 0));
        assert!(layout.survives_failure(0, 1));
        assert!(layout.survives_failure(1, 1));
    }

    #[test]
    fn survives_failure_mirror_2_copies_fails_2_devices() {
        let layout = DurabilityLayoutV1::mirror(2).unwrap();
        assert!(!layout.survives_failure(2, 0));
        assert!(!layout.survives_failure(0, 2));
        assert!(!layout.survives_failure(2, 2));
    }

    #[test]
    fn survives_failure_mirror_1_copy_survives_nothing() {
        let layout = DurabilityLayoutV1::mirror(1).unwrap();
        assert!(!layout.survives_failure(1, 0));
        assert!(!layout.survives_failure(0, 1));
        assert!(layout.survives_failure(0, 0));
    }

    #[test]
    fn survives_failure_mirror_3_copies_survives_2_device() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        assert!(layout.survives_failure(2, 0));
        assert!(layout.survives_failure(0, 2));
        assert!(!layout.survives_failure(3, 0));
    }

    #[test]
    fn survives_failure_erasure_8_3_survives_3_device() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        assert!(layout.survives_failure(3, 0));
        assert!(layout.survives_failure(0, 3));
        assert!(layout.survives_failure(3, 3));
    }

    #[test]
    fn survives_failure_erasure_8_3_fails_4_device() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        assert!(!layout.survives_failure(4, 0));
        assert!(!layout.survives_failure(0, 4));
    }

    #[test]
    fn survives_failure_erasure_8_3_survives_mixed() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        // 2 device failures + 1 node failure: each within 3-parity limit
        assert!(layout.survives_failure(2, 1));
        // 3 device failures + 0 nodes: at limit
        assert!(layout.survives_failure(3, 0));
        // 4 device failures: exceeds parity limit
        assert!(!layout.survives_failure(4, 0));
        // 4 node failures: exceeds parity limit
        assert!(!layout.survives_failure(0, 4));
    }

    #[test]
    fn survives_failure_erasure_4_2_survives_2() {
        let layout = DurabilityLayoutV1::erasure(4, 2).unwrap();
        assert!(layout.survives_failure(2, 0));
        assert!(!layout.survives_failure(3, 0));
    }

    #[test]
    fn survives_failure_mirror_max_copies() {
        let layout = DurabilityLayoutV1::mirror(MAX_MIRROR_COUNT).unwrap();
        assert!(layout.survives_failure(MAX_MIRROR_COUNT as u32 - 1, 0));
        assert!(!layout.survives_failure(MAX_MIRROR_COUNT as u32, 0));
    }

    #[test]
    fn survives_failure_erasure_max_parity() {
        let layout = DurabilityLayoutV1::erasure(1, MAX_PARITY_SHARDS).unwrap();
        assert!(layout.survives_failure(MAX_PARITY_SHARDS as u32, 0));
        assert!(!layout.survives_failure(MAX_PARITY_SHARDS as u32 + 1, 0));
    }
}

pub mod device_group;
pub mod failure_domain;
pub mod failure_domain_tree;
pub mod layout;
pub mod layout_validator;
pub mod policy;
pub mod verify;

// ---------------------------------------------------------------------------
// BLAKE3-verified layout persistence
// ---------------------------------------------------------------------------

/// Domain-separation context for sealed layout persistence.
const SEALED_LAYOUT_CONTEXT: &str = "TideFS SealedDurabilityLayout v1";

/// Sealed layout wire format magic: b"VSL1".
const SEALED_LAYOUT_MAGIC: &[u8; 4] = b"VSL1";
const SEALED_LAYOUT_HEADER_SIZE: usize = 4 + DIGEST_SIZE;
const SEALED_LAYOUT_TRAILER_SIZE: usize = DIGEST_SIZE;

/// Serialize and seal a durability layout with BLAKE3 verification.
///
/// Produces a canonical byte sequence: magic, content hash, encoded layout,
/// and a seal hash covering the entire payload for integrity verification.
pub fn seal_layout(layout: &DurabilityLayoutV1) -> Vec<u8> {
    let encoded = layout.encode();
    let content_hash: Digest = layout.checksum();

    let header_size = SEALED_LAYOUT_HEADER_SIZE;
    let payload_size = header_size + encoded.len() + SEALED_LAYOUT_TRAILER_SIZE;
    let mut buf = Vec::with_capacity(payload_size);

    buf.extend_from_slice(SEALED_LAYOUT_MAGIC);
    buf.extend_from_slice(&content_hash);
    buf.extend_from_slice(&encoded);

    let seal_hash = {
        let mut hasher = blake3::Hasher::new_derive_key(SEALED_LAYOUT_CONTEXT);
        hasher.update(&buf);
        hasher.finalize()
    };
    buf.extend_from_slice(seal_hash.as_bytes());

    buf
}

/// Verify and decode a sealed durability layout.
///
/// Checks magic, seal hash, and content hash before returning the decoded
/// layout. Returns a `BinarySchemaError` on any verification failure.
pub fn verify_layout(data: &[u8]) -> Result<DurabilityLayoutV1, BinarySchemaError> {
    let min_len = SEALED_LAYOUT_HEADER_SIZE + SEALED_LAYOUT_TRAILER_SIZE;
    if data.len() < min_len {
        return Err(BinarySchemaError::BoundsViolation);
    }

    if &data[0..4] != SEALED_LAYOUT_MAGIC {
        return Err(BinarySchemaError::BadMagic {
            got: u32::from_le_bytes(data[0..4].try_into().unwrap()),
        });
    }

    let content_hash = &data[4..4 + DIGEST_SIZE];
    let layout_start = 4 + DIGEST_SIZE;
    let layout_end = data.len() - DIGEST_SIZE;

    let expected_seal = &data[layout_end..];
    let seal_hash = {
        let mut hasher = blake3::Hasher::new_derive_key(SEALED_LAYOUT_CONTEXT);
        hasher.update(&data[..layout_end]);
        hasher.finalize()
    };
    if seal_hash.as_bytes() != expected_seal {
        return Err(BinarySchemaError::DigestMismatch);
    }

    let layout_bytes = &data[layout_start..layout_end];
    let layout = DurabilityLayoutV1::decode(layout_bytes)?;
    layout.verify_checksum(content_hash.try_into().unwrap())?;

    Ok(layout)
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    #[test]
    fn seal_and_verify_mirror_round_trip() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let sealed = seal_layout(&layout);
        let verified = verify_layout(&sealed).unwrap();
        assert_eq!(verified, layout);
    }

    #[test]
    fn seal_and_verify_erasure_round_trip() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let sealed = seal_layout(&layout);
        let verified = verify_layout(&sealed).unwrap();
        assert_eq!(verified, layout);
    }

    #[test]
    fn seal_and_verify_hybrid_round_trip() {
        let policy = DurabilityPolicy::hybrid(2, 4, 2).unwrap();
        let layout = DurabilityLayoutV1 { policy };
        let sealed = seal_layout(&layout);
        let verified = verify_layout(&sealed).unwrap();
        assert_eq!(verified, layout);
    }

    #[test]
    fn verify_rejects_bad_magic() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let mut sealed = seal_layout(&layout);
        sealed[0] = 0xFF;
        let result = verify_layout(&sealed);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_truncated() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let sealed = seal_layout(&layout);
        let result = verify_layout(&sealed[..10]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_tampered_layout() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let mut sealed = seal_layout(&layout);
        // Tamper with the layout bytes (after header)
        let layout_start = SEALED_LAYOUT_HEADER_SIZE;
        sealed[layout_start] ^= 0x01;
        let result = verify_layout(&sealed);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_tampered_seal() {
        let layout = DurabilityLayoutV1::mirror(3).unwrap();
        let mut sealed = seal_layout(&layout);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let result = verify_layout(&sealed);
        assert!(result.is_err());
    }

    #[test]
    fn seal_deterministic() {
        let layout = DurabilityLayoutV1::erasure(8, 3).unwrap();
        let s1 = seal_layout(&layout);
        let s2 = seal_layout(&layout);
        assert_eq!(s1, s2);
    }

    #[test]
    fn seal_different_layouts_different_output() {
        let a = DurabilityLayoutV1::mirror(2).unwrap();
        let b = DurabilityLayoutV1::mirror(3).unwrap();
        assert_ne!(seal_layout(&a), seal_layout(&b));
    }
}
