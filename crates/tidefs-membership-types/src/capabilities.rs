// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Peer capability advertisement types for placement and transport carrier selection.
//!
//! Defines [`PeerCapabilities`], the per-peer operational capability record,
//! and [`TransportCarrier`], a bitmask enum for transport protocol carriers.
//! These types flow through the membership join and epoch-advancement protocol
//! so placement planners and transport carrier selection can make informed
//! decisions without out-of-band discovery.
//!
use core::fmt;

use crate::{MembershipCodec, MembershipCodecError};

// ---------------------------------------------------------------------------
// TransportCarrier -- bitmask of supported transport carriers
// ---------------------------------------------------------------------------

/// Bitmask of supported transport protocol carriers.
///
/// Each variant is a power-of-two bit so carriers can be combined via
/// bitwise OR. Placement and transport selection query this mask to
/// decide RDMA vs TCP and to discover future carrier support.
///
/// # Wire format
///
/// Encoded as a single u64 in little-endian byte order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransportCarrier(pub u64);

impl TransportCarrier {
    /// No carriers advertised (genesis / pre-join).
    pub const NONE: Self = Self(0);

    /// Standard TCP transport.
    pub const TCP: Self = Self(1 << 0);

    /// RDMA-capable transport (e.g., RoCE, InfiniBand, iWARP).
    pub const RDMA: Self = Self(1 << 1);

    /// Returns `true` when all bits in `other` are also set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns `true` when no carrier bits are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Combine two carrier masks (bitwise OR).
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl fmt::Display for TransportCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "none");
        }
        let mut first = true;
        if self.contains(Self::TCP) {
            write!(f, "tcp")?;
            first = false;
        }
        if self.contains(Self::RDMA) {
            if !first {
                write!(f, "+")?;
            }
            write!(f, "rdma")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TransportCarrier -- MembershipCodec impl
// ---------------------------------------------------------------------------

impl MembershipCodec for TransportCarrier {
    #[cfg(feature = "alloc")]
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        crate::push_u64(buf, self.0);
        crate::push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        crate::verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;
        let value = crate::read_u64(payload, &mut pos)?;
        Ok(Self(value))
    }
}

// ---------------------------------------------------------------------------
// PeerCapabilities -- per-peer operational capability record
// ---------------------------------------------------------------------------

/// Operational capabilities advertised by a peer on join and refreshable
/// during epoch advancement.
///
/// Fields cover storage capacity, transport carrier support, failure-domain
/// topology, coordinator eligibility, and an extensible key-value attribute
/// list for forward-compatible capability discovery.
///
/// Requires the `alloc` feature (the whole crate requires it for any
/// owned-string wire types).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg(feature = "alloc")]
pub struct PeerCapabilities {
    /// Total storage capacity in bytes.
    pub storage_capacity_bytes: u64,
    /// Currently available (free) bytes.
    pub available_bytes: u64,
    /// Bitmask of supported transport carriers.
    pub transport_carriers: TransportCarrier,
    /// Datacenter-level failure domain tag (e.g., "dc-east").
    pub failure_domain_datacenter: alloc::string::String,
    /// Rack-level failure domain tag (e.g., "rack-42").
    pub failure_domain_rack: alloc::string::String,
    /// Whether this peer is eligible to become coordinator.
    pub coordinator_eligible: bool,
    /// Extensible key-value attribute list for forward-compatible discovery.
    pub attributes: alloc::vec::Vec<(alloc::string::String, alloc::string::String)>,
}

#[cfg(feature = "alloc")]
impl PeerCapabilities {
    /// Create a minimal capabilities record with no carriers and empty attributes.
    #[must_use]
    pub fn new(storage_capacity_bytes: u64, available_bytes: u64) -> Self {
        Self {
            storage_capacity_bytes,
            available_bytes,
            transport_carriers: TransportCarrier::NONE,
            failure_domain_datacenter: alloc::string::String::new(),
            failure_domain_rack: alloc::string::String::new(),
            coordinator_eligible: false,
            attributes: alloc::vec::Vec::new(),
        }
    }
}

// ── Internal helpers (alloc only) ───────────────────────────────────

/// Encode a length-prefixed UTF-8 string.
#[cfg(feature = "alloc")]
fn push_str(buf: &mut alloc::vec::Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    crate::push_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

/// Decode a length-prefixed UTF-8 string.
#[cfg(feature = "alloc")]
fn read_str(data: &[u8], pos: &mut usize) -> Result<alloc::string::String, MembershipCodecError> {
    let len = crate::read_u32(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(MembershipCodecError::Underflow);
    }
    let s = core::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| MembershipCodecError::Underflow)?;
    *pos += len;
    Ok(alloc::string::String::from(s))
}

// ---------------------------------------------------------------------------
// PeerCapabilities -- MembershipCodec impl
// ---------------------------------------------------------------------------

#[cfg(feature = "alloc")]
impl MembershipCodec for PeerCapabilities {
    fn encode(&self, buf: &mut alloc::vec::Vec<u8>) {
        crate::push_u64(buf, self.storage_capacity_bytes);
        crate::push_u64(buf, self.available_bytes);
        crate::push_u64(buf, self.transport_carriers.0);
        buf.push(if self.coordinator_eligible { 1u8 } else { 0u8 });
        push_str(buf, &self.failure_domain_datacenter);
        push_str(buf, &self.failure_domain_rack);
        // attributes: count-prefixed repeated (key, value) pairs
        crate::push_u32(buf, self.attributes.len() as u32);
        for (k, v) in &self.attributes {
            push_str(buf, k);
            push_str(buf, v);
        }
        crate::push_checksum(buf);
    }

    fn decode(data: &[u8]) -> Result<Self, MembershipCodecError> {
        crate::verify_checksum(data)?;
        let payload = &data[..data.len() - 4];
        let mut pos = 0usize;

        let storage_capacity_bytes = crate::read_u64(payload, &mut pos)?;
        let available_bytes = crate::read_u64(payload, &mut pos)?;
        let transport_carriers = TransportCarrier(crate::read_u64(payload, &mut pos)?);
        let coordinator_eligible_byte = crate::read_u8(payload, &mut pos)?;
        let coordinator_eligible = coordinator_eligible_byte != 0;
        let failure_domain_datacenter = read_str(payload, &mut pos)?;
        let failure_domain_rack = read_str(payload, &mut pos)?;

        let attr_count = crate::read_u32(payload, &mut pos)? as usize;
        if attr_count > 1024 {
            return Err(MembershipCodecError::Underflow);
        }
        let mut attributes: alloc::vec::Vec<(alloc::string::String, alloc::string::String)> =
            alloc::vec::Vec::with_capacity(attr_count);
        for _ in 0..attr_count {
            let k = read_str(payload, &mut pos)?;
            let v = read_str(payload, &mut pos)?;
            attributes.push((k, v));
        }

        Ok(Self {
            storage_capacity_bytes,
            available_bytes,
            transport_carriers,
            failure_domain_datacenter,
            failure_domain_rack,
            coordinator_eligible,
            attributes,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec;
    use alloc::vec::Vec;

    // ── TransportCarrier ───────────────────────────────────────────

    #[test]
    fn transport_carrier_default_is_none() {
        let tc = TransportCarrier::default();
        assert!(tc.is_empty());
        assert_eq!(tc.0, 0);
    }

    #[test]
    fn transport_carrier_contains() {
        let tc = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        assert!(tc.contains(TransportCarrier::TCP));
        assert!(tc.contains(TransportCarrier::RDMA));
        assert!(!tc.contains(TransportCarrier(1 << 2)));
    }

    #[test]
    fn transport_carrier_union() {
        let tc = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        assert_eq!(tc.0, (1 << 0) | (1 << 1));
    }

    #[test]
    fn transport_carrier_display_none() {
        assert_eq!(format!("{}", TransportCarrier::NONE), "none");
    }

    #[test]
    fn transport_carrier_display_tcp() {
        assert_eq!(format!("{}", TransportCarrier::TCP), "tcp");
    }

    #[test]
    fn transport_carrier_display_combined() {
        let tc = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        assert_eq!(format!("{tc}"), "tcp+rdma");
    }

    // ── TransportCarrier codec ─────────────────────────────────────

    fn roundtrip_tc(tc: TransportCarrier) {
        let mut buf = Vec::new();
        tc.encode(&mut buf);
        let decoded = TransportCarrier::decode(&buf).expect("decode failed");
        assert_eq!(decoded, tc);
    }

    #[test]
    fn transport_carrier_codec_none() {
        roundtrip_tc(TransportCarrier::NONE);
    }

    #[test]
    fn transport_carrier_codec_tcp() {
        roundtrip_tc(TransportCarrier::TCP);
    }

    #[test]
    fn transport_carrier_codec_combined() {
        roundtrip_tc(TransportCarrier::TCP.union(TransportCarrier::RDMA));
    }

    #[test]
    fn transport_carrier_codec_max() {
        roundtrip_tc(TransportCarrier(u64::MAX));
    }

    #[test]
    fn transport_carrier_checksum_corruption() {
        let mut buf = Vec::new();
        TransportCarrier::TCP.encode(&mut buf);
        let last = buf.len() - 1;
        buf[last] ^= 0xFF;
        assert!(TransportCarrier::decode(&buf).is_err());
    }

    // ── PeerCapabilities ───────────────────────────────────────────

    #[test]
    fn peer_capabilities_new_minimal() {
        let caps = PeerCapabilities::new(1024 * 1024 * 1024, 512 * 1024 * 1024);
        assert_eq!(caps.storage_capacity_bytes, 1_073_741_824);
        assert_eq!(caps.available_bytes, 536_870_912);
        assert!(caps.transport_carriers.is_empty());
        assert!(!caps.coordinator_eligible);
        assert!(caps.failure_domain_datacenter.is_empty());
        assert!(caps.failure_domain_rack.is_empty());
        assert!(caps.attributes.is_empty());
    }

    #[test]
    fn peer_capabilities_full_codec_roundtrip() {
        let caps = PeerCapabilities {
            storage_capacity_bytes: 10_000_000_000,
            available_bytes: 5_000_000_000,
            transport_carriers: TransportCarrier::TCP.union(TransportCarrier::RDMA),
            failure_domain_datacenter: "dc-east".to_string(),
            failure_domain_rack: "rack-42".to_string(),
            coordinator_eligible: true,
            attributes: vec![
                ("zone".to_string(), "us-east-1a".to_string()),
                ("tier".to_string(), "hot".to_string()),
            ],
        };

        let mut buf = Vec::new();
        caps.encode(&mut buf);
        let decoded = PeerCapabilities::decode(&buf).expect("decode failed");
        assert_eq!(decoded.storage_capacity_bytes, caps.storage_capacity_bytes);
        assert_eq!(decoded.available_bytes, caps.available_bytes);
        assert_eq!(decoded.transport_carriers, caps.transport_carriers);
        assert_eq!(decoded.failure_domain_datacenter, "dc-east");
        assert_eq!(decoded.failure_domain_rack, "rack-42");
        assert!(decoded.coordinator_eligible);
        assert_eq!(decoded.attributes.len(), 2);
        assert_eq!(
            decoded.attributes[0],
            ("zone".to_string(), "us-east-1a".to_string())
        );
        assert_eq!(
            decoded.attributes[1],
            ("tier".to_string(), "hot".to_string())
        );
    }

    #[test]
    fn peer_capabilities_empty_attributes_roundtrip() {
        let caps = PeerCapabilities {
            storage_capacity_bytes: 100,
            available_bytes: 50,
            transport_carriers: TransportCarrier::TCP,
            failure_domain_datacenter: String::new(),
            failure_domain_rack: String::new(),
            coordinator_eligible: false,
            attributes: vec![],
        };

        let mut buf = Vec::new();
        caps.encode(&mut buf);
        let decoded = PeerCapabilities::decode(&buf).expect("decode failed");
        assert_eq!(decoded.attributes.len(), 0);
        assert!(decoded.failure_domain_datacenter.is_empty());
    }

    #[test]
    fn peer_capabilities_max_values_roundtrip() {
        let caps = PeerCapabilities {
            storage_capacity_bytes: u64::MAX,
            available_bytes: u64::MAX,
            transport_carriers: TransportCarrier(u64::MAX),
            failure_domain_datacenter: "x".repeat(256),
            failure_domain_rack: "y".repeat(256),
            coordinator_eligible: true,
            attributes: vec![("k".to_string(), "v".to_string())],
        };

        let mut buf = Vec::new();
        caps.encode(&mut buf);
        let decoded = PeerCapabilities::decode(&buf).expect("decode failed");
        assert_eq!(decoded.storage_capacity_bytes, u64::MAX);
        assert_eq!(decoded.failure_domain_datacenter, "x".repeat(256));
    }

    #[test]
    fn peer_capabilities_checksum_corruption() {
        let caps = PeerCapabilities::new(100, 50);
        let mut buf = Vec::new();
        caps.encode(&mut buf);
        let mid = buf.len() / 2;
        buf[mid] ^= 0xFF;
        assert!(PeerCapabilities::decode(&buf).is_err());
    }

    #[test]
    fn peer_capabilities_underflow() {
        let data = [0u8; 3];
        assert!(PeerCapabilities::decode(&data).is_err());
    }

    // ── serde roundtrip (when feature enabled) ─────────────────────

    #[cfg(feature = "serde")]
    #[test]
    fn transport_carrier_serde_roundtrip() {
        let tc = TransportCarrier::TCP.union(TransportCarrier::RDMA);
        let json = serde_json::to_string(&tc).unwrap();
        let restored: TransportCarrier = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, tc);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn peer_capabilities_serde_roundtrip() {
        let caps = PeerCapabilities {
            storage_capacity_bytes: 1000,
            available_bytes: 500,
            transport_carriers: TransportCarrier::TCP,
            failure_domain_datacenter: "dc-west".to_string(),
            failure_domain_rack: "rack-7".to_string(),
            coordinator_eligible: true,
            attributes: vec![("role".to_string(), "storage".to_string())],
        };
        let json = serde_json::to_string(&caps).unwrap();
        let restored: PeerCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.storage_capacity_bytes, 1000);
        assert_eq!(restored.transport_carriers, TransportCarrier::TCP);
        assert_eq!(restored.failure_domain_datacenter, "dc-west");
        assert_eq!(restored.attributes.len(), 1);
    }
}
