//! Membership send gating trait for outbound transport messages.
//!
//! [`SendGate`] provides a roster-query interface that the transport
//! send pipeline calls before enqueueing outbound messages. This lets
//! the membership layer block sends to peers that are not in the current
//! committed roster without requiring a concrete membership dependency
//! in the transport crate.
//!
//! ## Role
//!
//! The gate short-circuits outbound sends at message-queue time for
//! peers evicted from the committed roster, closing the race window
//! between roster eviction and asynchronous session teardown handled
//! by the `MembershipTransportBridge`.
//!
//! ## Trait object
//!
//! The transport holds an `Option<Arc<dyn SendGate>>`. When `None`
//! (the default), no roster gating is performed and all sends proceed
//! subject to connection-state checks. When `Some`, every send consults
//! `can_send_to` before enqueueing.

use crate::circuit_breaker::PeerId;

// ---------------------------------------------------------------------------
// SendGate
// ---------------------------------------------------------------------------

/// Query interface for roster-gated outbound sends.
///
/// Implementations check whether a given peer is in the current
/// committed member set. The transport layer calls `can_send_to`
/// on every outbound send and returns
/// `SendPipelineError::PeerNotInRoster` when the gate returns `false`.
pub trait SendGate: Send + Sync + std::fmt::Debug {
    /// Return whether the given peer is permitted to receive outbound
    /// messages.
    ///
    /// Returns `true` when the peer is in the current committed roster.
    /// Returns `false` when the peer has been evicted or was never
    /// a member, and the caller should reject the send.
    fn can_send_to(&self, peer_id: PeerId) -> bool;
}
