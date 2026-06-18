// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Rolling upgrade compatibility gate for multi-node protocol negotiation.
//!
//! ## Purpose
//!
//! During session handshake, TideFS nodes exchange `feature_flags` bitmasks
//! and negotiate the intersection. This module defines the flag namespace and
//! provides a gate that prevents a newer node from publishing unsupported
//! protocol features to an older peer.
//!
//! ## Feature flag life cycle
//!
//! 1. A new protocol feature is assigned a flag bit in [`NodeFeatureFlags`].
//! 2. Nodes that support the feature set the bit in their Hello.
//! 3. The responder computes the intersection and returns it in Accept.
//! 4. Before using a feature, the sender consults the negotiated set.
//!    If the flag is not set, the sender MUST NOT use the feature.
//!
//! ## Integration point
//!
//! The negotiated flags are stored per-session after handshake completion.
//! Callers query [`RollingUpgradeGate::allows`] before any gated protocol
//! operation.
//!
//! ## Bit allocation governance
//!
//! Flag bits are permanently frozen once assigned. No bit ever changes
//! meaning. New features receive new bits. Deprecated features keep their
//! bits but are no longer advertised by current releases.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Feature flag constants
// ---------------------------------------------------------------------------

/// Feature flags for protocol capability negotiation during multi-node
/// session handshake.
///
/// Advertised in `Hello.feature_flags` and negotiated to the intersection
/// in `Accept.negotiated_features`. A node MUST NOT use a feature unless
/// the negotiated set includes its flag bit.
///
/// ## Allocation table
///
/// | Bits  | Scope                              |
/// |-------|------------------------------------|
/// | 0-7   | Transport-level features           |
/// | 8-15  | Session-level features             |
/// | 16-31 | Reserved (transport/session)       |
/// | 32-47 | Application/dataset features       |
/// | 48-63 | Reserved (application)             |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeFeatureFlags(u64);

impl NodeFeatureFlags {
    // ── Transport-level flags (bits 0-7) ─────────────────────────────

    /// Frame-level compression (lz4, zstd). Both peers must agree before
    /// compressed frames are sent.
    pub const COMPRESSION: Self = Self(1 << 0);

    /// Priority queuing: Control-plane messages bypass bulk data on the
    /// outbound send path. When not negotiated, all messages are FIFO.
    pub const PRIORITY_QUEUING: Self = Self(1 << 1);

    /// Message batching: multiple small outbound messages are coalesced
    /// into a single wire send for throughput.
    pub const MESSAGE_BATCHING: Self = Self(1 << 2);

    /// TLS transport encryption at the connection level.
    pub const TLS: Self = Self(1 << 3);

    /// RDMA carrier for data-path transfer. Advertised by nodes that
    /// have an RDMA-capable interface; the connection proceeds over
    /// TCP when this flag is absent from the negotiated set.
    pub const RDMA: Self = Self(1 << 4);

    // ── Session-level flags (bits 8-15) ──────────────────────────────

    /// Per-session encryption (ChaCha20-Poly1305 via HKDF-SHA256).
    /// Both peers must agree to enable session encryption.
    pub const SESSION_ENCRYPTION: Self = Self(1 << 8);

    /// Session rekey: periodic rotation of session encryption keys
    /// without connection teardown.
    pub const SESSION_REKEY: Self = Self(1 << 9);

    /// Flow control: per-lane backpressure and credit-based admission.
    pub const FLOW_CONTROL: Self = Self(1 << 10);

    /// Replication protocol: object-level replication between storage
    /// nodes. Both peers must agree before replication messages flow.
    pub const REPLICATION: Self = Self(1 << 11);

    // ── Convenience masks ────────────────────────────────────────────

    /// All transport-level flags supported by the current release.
    pub const CURRENT_TRANSPORT: Self = Self(
        Self::COMPRESSION.0 | Self::PRIORITY_QUEUING.0 | Self::MESSAGE_BATCHING.0 | Self::TLS.0,
    );

    /// All flags supported by the current release (transport + session).
    pub const CURRENT: Self = Self(
        Self::CURRENT_TRANSPORT.0
            | Self::SESSION_ENCRYPTION.0
            | Self::SESSION_REKEY.0
            | Self::FLOW_CONTROL.0
            | Self::REPLICATION.0,
    );

    // ── Constructors and accessors ───────────────────────────────────

    /// Build from a raw `u64` bitmask received from the wire.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw `u64` bitmask for wire encoding.
    #[must_use]
    pub const fn to_raw(self) -> u64 {
        self.0
    }

    /// Whether all bits in `other` are set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Compute the intersection (bitwise AND) of two feature flag sets.
    #[must_use]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Whether no feature flags are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether any feature flags are set.
    #[must_use]
    pub const fn any(self) -> bool {
        self.0 != 0
    }
}

// ---------------------------------------------------------------------------
// Rolling upgrade gate
// ---------------------------------------------------------------------------

/// Per-session rolling upgrade compatibility gate.
///
/// Created after session handshake completes with the negotiated feature
/// flags. Consumed before gated protocol operations to check whether the
/// peer supports a specific feature.
///
/// # Example
///
/// ```ignore
/// let gate = RollingUpgradeGate::new(negotiated_features);
/// if gate.allows(NodeFeatureFlags::COMPRESSION) {
///     session.set_compression(CompressionConfig::default());
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollingUpgradeGate {
    negotiated: NodeFeatureFlags,
}

impl RollingUpgradeGate {
    /// Create a gate wrapping the given negotiated feature flags.
    #[must_use]
    pub const fn new(negotiated: NodeFeatureFlags) -> Self {
        Self { negotiated }
    }

    /// Create a gate from a raw `u64` negotiated features bitmask.
    #[must_use]
    pub fn from_raw(raw: u64) -> Self {
        Self {
            negotiated: NodeFeatureFlags::from_raw(raw),
        }
    }

    /// Whether the peer supports the given feature(s).
    ///
    /// Returns `true` only when all bits in `feature` are present in the
    /// negotiated set.
    #[must_use]
    pub fn allows(&self, feature: NodeFeatureFlags) -> bool {
        self.negotiated.contains(feature)
    }

    /// Whether the peer does NOT support the given feature(s).
    #[must_use]
    pub fn forbids(&self, feature: NodeFeatureFlags) -> bool {
        !self.allows(feature)
    }

    /// Return the raw negotiated feature bitmask.
    #[must_use]
    pub fn negotiated_raw(&self) -> u64 {
        self.negotiated.to_raw()
    }

    /// Return the negotiated feature flags.
    #[must_use]
    pub fn negotiated(&self) -> NodeFeatureFlags {
        self.negotiated
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── NodeFeatureFlags ─────────────────────────────────────────────

    #[test]
    fn empty_intersection() {
        let a = NodeFeatureFlags::COMPRESSION;
        let b = NodeFeatureFlags::PRIORITY_QUEUING;
        assert!(a.intersect(b).is_empty());
    }

    #[test]
    fn self_intersection_is_identity() {
        let f = NodeFeatureFlags::CURRENT;
        assert_eq!(f.intersect(f), f);
    }

    #[test]
    fn contains_self() {
        assert!(NodeFeatureFlags::COMPRESSION.contains(NodeFeatureFlags::COMPRESSION));
    }

    #[test]
    fn contains_subset() {
        assert!(NodeFeatureFlags::CURRENT_TRANSPORT.contains(NodeFeatureFlags::COMPRESSION));
    }

    #[test]
    fn current_contains_all_transport_flags() {
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::COMPRESSION));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::PRIORITY_QUEUING));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::MESSAGE_BATCHING));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::TLS));
    }

    #[test]
    fn current_contains_session_flags() {
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::SESSION_ENCRYPTION));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::SESSION_REKEY));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::FLOW_CONTROL));
        assert!(NodeFeatureFlags::CURRENT.contains(NodeFeatureFlags::REPLICATION));
    }

    #[test]
    fn current_does_not_contain_unused_bits() {
        let unused = NodeFeatureFlags::from_raw(1 << 20);
        assert!(!NodeFeatureFlags::CURRENT.contains(unused));
    }

    #[test]
    fn transport_mask_excludes_session_flags() {
        assert!(!NodeFeatureFlags::CURRENT_TRANSPORT.contains(NodeFeatureFlags::SESSION_ENCRYPTION));
        assert!(!NodeFeatureFlags::CURRENT_TRANSPORT.contains(NodeFeatureFlags::REPLICATION));
    }

    #[test]
    fn bit_independence() {
        let flags = [
            NodeFeatureFlags::COMPRESSION,
            NodeFeatureFlags::PRIORITY_QUEUING,
            NodeFeatureFlags::MESSAGE_BATCHING,
            NodeFeatureFlags::TLS,
            NodeFeatureFlags::RDMA,
            NodeFeatureFlags::SESSION_ENCRYPTION,
            NodeFeatureFlags::SESSION_REKEY,
            NodeFeatureFlags::FLOW_CONTROL,
            NodeFeatureFlags::REPLICATION,
        ];
        for i in 0..flags.len() {
            for j in 0..flags.len() {
                if i == j {
                    continue;
                }
                assert!(
                    flags[i].intersect(flags[j]).is_empty(),
                    "flag {} ({:#018x}) should not overlap flag {} ({:#018x})",
                    i,
                    flags[i].to_raw(),
                    j,
                    flags[j].to_raw(),
                );
            }
        }
    }

    #[test]
    fn session_flags_are_in_upper_bits() {
        assert_eq!(NodeFeatureFlags::SESSION_ENCRYPTION.to_raw() >> 8, 1);
        assert_eq!(NodeFeatureFlags::SESSION_REKEY.to_raw() >> 9, 1);
        assert_eq!(NodeFeatureFlags::FLOW_CONTROL.to_raw() >> 10, 1);
        assert_eq!(NodeFeatureFlags::REPLICATION.to_raw() >> 11, 1);
    }

    #[test]
    fn round_trip_via_raw() {
        let original = NodeFeatureFlags::CURRENT;
        let raw = original.to_raw();
        let restored = NodeFeatureFlags::from_raw(raw);
        assert_eq!(original, restored);
    }

    #[test]
    fn default_is_empty() {
        assert!(NodeFeatureFlags::default().is_empty());
    }

    #[test]
    fn any_returns_false_for_default() {
        assert!(!NodeFeatureFlags::default().any());
    }

    #[test]
    fn any_returns_true_when_set() {
        assert!(NodeFeatureFlags::COMPRESSION.any());
    }

    // ── RollingUpgradeGate ───────────────────────────────────────────

    #[test]
    fn gate_allows_negotiated_features() {
        let gate = RollingUpgradeGate::new(NodeFeatureFlags::COMPRESSION);
        assert!(gate.allows(NodeFeatureFlags::COMPRESSION));
        assert!(gate.forbids(NodeFeatureFlags::PRIORITY_QUEUING));
    }

    #[test]
    fn gate_allows_multiple_when_present() {
        let combined = NodeFeatureFlags::from_raw(
            NodeFeatureFlags::COMPRESSION.to_raw() | NodeFeatureFlags::PRIORITY_QUEUING.to_raw(),
        );
        let gate = RollingUpgradeGate::new(combined);
        assert!(gate.allows(NodeFeatureFlags::COMPRESSION));
        assert!(gate.allows(NodeFeatureFlags::PRIORITY_QUEUING));
    }

    #[test]
    fn gate_forbids_single_from_multi() {
        let combined = NodeFeatureFlags::from_raw(
            NodeFeatureFlags::COMPRESSION.to_raw() | NodeFeatureFlags::PRIORITY_QUEUING.to_raw(),
        );
        let gate = RollingUpgradeGate::new(combined);
        assert!(gate.forbids(NodeFeatureFlags::MESSAGE_BATCHING));
    }

    #[test]
    fn gate_forbids_missing_features() {
        let gate = RollingUpgradeGate::new(NodeFeatureFlags::CURRENT_TRANSPORT);
        assert!(gate.forbids(NodeFeatureFlags::RDMA));
        assert!(gate.forbids(NodeFeatureFlags::SESSION_REKEY));
        assert!(gate.forbids(NodeFeatureFlags::REPLICATION));
    }

    #[test]
    fn gate_from_raw() {
        let gate = RollingUpgradeGate::from_raw(0x0003);
        assert!(gate.allows(NodeFeatureFlags::COMPRESSION));
        assert!(gate.allows(NodeFeatureFlags::PRIORITY_QUEUING));
        assert!(!gate.allows(NodeFeatureFlags::MESSAGE_BATCHING));
        assert_eq!(gate.negotiated_raw(), 3);
    }

    #[test]
    fn gate_negotiated_accessor() {
        let f = NodeFeatureFlags::COMPRESSION;
        let gate = RollingUpgradeGate::new(f);
        assert_eq!(gate.negotiated(), f);
    }

    #[test]
    fn gate_from_empty_is_permissive_for_none() {
        let gate = RollingUpgradeGate::new(NodeFeatureFlags::default());
        assert!(!gate.allows(NodeFeatureFlags::COMPRESSION));
        assert!(gate.negotiated().is_empty());
    }

    #[test]
    fn gate_allows_empty_feature_trivially() {
        let gate = RollingUpgradeGate::new(NodeFeatureFlags::CURRENT);
        // Querying with NONE (zero bits) is always allowed.
        assert!(gate.allows(NodeFeatureFlags::default()));
    }
}
