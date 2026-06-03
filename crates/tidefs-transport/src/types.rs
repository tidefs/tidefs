use serde::{Deserialize, Serialize};
use std::fmt;
pub use tidefs_auth::NodeIdentity;
pub use tidefs_auth::NodeIdentity as NodeIdentityPublic;
use tidefs_clock_timing::types::HlcValue;

// ---------------------------------------------------------------------------
// Core identifiers
// ---------------------------------------------------------------------------

/// Unique session identifier between two nodes.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct SessionId(pub u64);

impl SessionId {
    #[must_use]
    /// Create a new SessionId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s{}", self.0)
    }
}

/// Locally-unique transfer identifier for chunk shipping.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ChunkTransferId(pub u64);

impl ChunkTransferId {
    #[must_use]
    /// Create a new ChunkTransferId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ChunkTransferId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ct{}", self.0)
    }
}

/// Content-addressable chunk identifier.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ChunkId(pub u64);

impl ChunkId {
    #[must_use]
    /// Create a new ChunkId from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "chunk:{}", self.0)
    }
}

/// SHA-256 hash digest.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    #[must_use]
    /// Create a new Hash from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

mod hex {
    /// Hex-encode raw bytes into a string.
    pub fn encode(bytes: &[u8]) -> String {
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            })
    }
}

// ---------------------------------------------------------------------------
// HLC timestamp (P8-04 Section 7.1, backed by tidefs-clock-timing)
// ---------------------------------------------------------------------------

/// Hybrid Logical Clock timestamp backed by a real HlcValue.
///
/// Wraps HlcValue from tidefs-clock-timing. The outer wrapper keeps the
/// transport crate's API stable while the inner value carries the full HLC
/// physical time (nanoseconds) and logical counter.
///
/// Historical new(wall_millis, logical) constructor remains available as a
/// convenience (interprets wall_millis as milliseconds and converts to ns).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct HlcTimestamp(HlcValue);

impl HlcTimestamp {
    /// Create an HlcTimestamp from wall-clock milliseconds + logical.
    ///
    /// The millisecond value is converted to nanoseconds for storage.
    #[must_use]
    pub fn new(wall_millis: u64, logical: u32) -> Self {
        Self(HlcValue::new(
            wall_millis.saturating_mul(1_000_000),
            logical as u64,
        ))
    }

    /// Create directly from an HlcValue.
    #[must_use]
    pub fn from_hlc_value(value: HlcValue) -> Self {
        Self(value)
    }

    /// Return the inner HlcValue.
    #[must_use]
    pub fn as_hlc_value(&self) -> &HlcValue {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Protocol versioning
// ---------------------------------------------------------------------------

/// A (message family, version) pair for protocol negotiation during handshake.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct FamilyVersion {
    pub family_id: u16,
    pub version_major: u16,
    pub version_minor: u16,
}

impl FamilyVersion {
    #[must_use]
    /// Create a new FamilyVersion with the given family and version numbers.
    pub const fn new(family_id: u16, version_major: u16, version_minor: u16) -> Self {
        Self {
            family_id,
            version_major,
            version_minor,
        }
    }
}

/// Monotonic version for freshness fencing on chunk transfers.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FenceVersion(pub u64);

impl FenceVersion {
    #[must_use]
    /// Create a new FenceVersion from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------

/// Cohort membership info exchanged during session handshake.
#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct CohortMembership {
    pub domain_ids: Vec<u64>,
    pub epoch: u64,
}

impl CohortMembership {
    #[must_use]
    /// Create a new CohortMembership with the given domain IDs and epoch.
    pub fn new(domain_ids: Vec<u64>, epoch: u64) -> Self {
        Self { domain_ids, epoch }
    }
}
