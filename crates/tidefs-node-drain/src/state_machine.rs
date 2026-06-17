// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BLAKE3-verified protocol-level node-drain state machine.
//!
//! [`DrainProtocolMachine`] tracks the lifecycle of a graceful node drain at the
//! protocol level: announce, drain (state transfer), complete, and terminal.
//! Each state transition produces a BLAKE3-256 domain-separated digest
//! (domain: `tidefs-membership-drain-state-v1`) for cryptographic validation.
//!
//! ## State model
//!
//! ```text
//! Idle --> DrainAnnounced --> Draining --> DrainComplete --> Drained
//!   |                            |               |
//!   +----------------------------+---------------+--> (any -> Idle on reset)
//! ```
//!
//! Transitions are validated: only the edges shown above are legal.
//! `Drained` is idempotent (`Drained -> Drained` is permitted for retry
//! safety).

use serde::Serialize;
use std::fmt;
use crate::evacuation_receipt::{EvacuationReceipt, EvacuationReceiptId};
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// DrainProtocolState -- five protocol-level states
// ---------------------------------------------------------------------------

/// Protocol-level state of a node drain operation.
///
/// These states track the drain at the cluster-coordination layer, above the
/// fine-grained stage model in [`crate::drain::DrainStage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum DrainProtocolState {
    /// No drain in progress.
    Idle,
    /// Drain intent has been announced to peers; awaiting acknowledgements.
    DrainAnnounced,
    /// State transfer is in progress: data, leases, and cache being offloaded.
    Draining,
    /// State transfer complete; epoch transition and roster removal pending.
    DrainComplete,
    /// Drain finished; node excluded from membership roster.
    Drained,
}

impl DrainProtocolState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::DrainAnnounced => "drain_announced",
            Self::Draining => "draining",
            Self::DrainComplete => "drain_complete",
            Self::Drained => "drained",
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Drained)
    }

    /// Returns true if the transition to `next` is valid.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Idle, Self::DrainAnnounced)
                | (Self::DrainAnnounced, Self::Draining)
                | (Self::DrainAnnounced, Self::Idle) // cancel before transfer
                | (Self::Draining, Self::DrainComplete)
                | (Self::Draining, Self::Idle) // cancel mid-transfer
                | (Self::DrainComplete, Self::Drained)
                | (Self::DrainComplete, Self::Idle) // cancel before epoch
                | (Self::Drained, Self::Drained) // idempotent
        )
    }

    /// Validate a transition, returning the new state or an error.
    pub fn transition_to(self, next: Self) -> Result<Self, DrainProtocolError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(DrainProtocolError::InvalidTransition {
                from: self,
                to: next,
            })
        }
    }
}

impl Default for DrainProtocolState {
    fn default() -> Self {
        Self::Idle
    }
}

impl fmt::Display for DrainProtocolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DrainProtocolError
// ---------------------------------------------------------------------------

/// Errors returned by the protocol-level drain state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DrainProtocolError {
    /// The requested state transition is not allowed.
    InvalidTransition {
        from: DrainProtocolState,
        to: DrainProtocolState,
    },
    /// A drain is already in progress for this node.
    AlreadyDraining { node_id: MemberId },
    /// The state machine is not in the expected state for the operation.
    WrongState {
        expected: DrainProtocolState,
        actual: DrainProtocolState,
    },
}

impl fmt::Display for DrainProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid drain protocol transition from {from} to {to}")
            }
            Self::AlreadyDraining { node_id } => {
                write!(f, "node {} is already draining", node_id.0)
            }
            Self::WrongState { expected, actual } => {
                write!(
                    f,
                    "expected drain protocol state {expected}, but was {actual}"
                )
            }
        }
    }
}

impl std::error::Error for DrainProtocolError {}

// ---------------------------------------------------------------------------
// DrainProtocolDigest -- BLAKE3 state digest
// ---------------------------------------------------------------------------

/// Domain separation for drain protocol state digests.
const DRAIN_PROTOCOL_DOMAIN: &str = "tidefs-membership-drain-state-v1";

/// Compute a BLAKE3-256 domain-separated digest of the drain protocol state
/// for a given node at a given epoch.
///
/// The digest covers: `(state, node_id, epoch_id)` serialized via bincode.
/// This provides cryptographic validation of the state transition for audit
/// and crash-recovery idempotency.
#[must_use]
pub fn drain_protocol_digest(
    state: DrainProtocolState,
    node_id: MemberId,
    epoch_id: EpochId,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DRAIN_PROTOCOL_DOMAIN);
    // Use a canonical representation: state ordinal, then the tuple.
    let state_ordinal = state as u8;
    let payload: (u8, MemberId, EpochId) = (state_ordinal, node_id, epoch_id);
    if let Ok(encoded) = bincode::serialize(&payload) {
        hasher.update(&encoded);
    }
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// DrainProtocolSnapshot -- attested state snapshot
// ---------------------------------------------------------------------------

/// A BLAKE3-attested snapshot of the drain protocol state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DrainProtocolSnapshot {
    /// Current protocol state.
    pub state: DrainProtocolState,
    /// The node being drained.
    pub node_id: MemberId,
    /// Membership epoch at the time of this snapshot.
    pub epoch_id: EpochId,
    /// Number of peers that have acknowledged the drain announce.
    pub acks_received: u64,
    /// Total peers expected to acknowledge.
    pub acks_expected: u64,
    /// BLAKE3-256 digest covering (`state`, `node_id`, `epoch_id`).
    pub blake3_digest: [u8; 32],
    /// Evacuation receipt id, if set.
    pub evacuation_receipt_id: Option<EvacuationReceiptId>,
    /// Whether the evacuation receipt is committed.
    pub evacuation_receipt_committed: bool,
}

impl DrainProtocolSnapshot {
    /// Create a new snapshot with a computed BLAKE3 digest.
    #[must_use]
    pub fn new(
        state: DrainProtocolState,
        node_id: MemberId,
        epoch_id: EpochId,
        acks_received: u64,
        acks_expected: u64,
    ) -> Self {
        let digest = drain_protocol_digest(state, node_id, epoch_id);
        Self {
            state,
            node_id,
            epoch_id,
            acks_received,
            acks_expected,
            blake3_digest: digest,
            evacuation_receipt_id: None,
            evacuation_receipt_committed: false,
        }
    }

    /// Verify that the stored digest matches the computed digest.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        drain_protocol_digest(self.state, self.node_id, self.epoch_id) == self.blake3_digest
    }

    /// Returns true if all expected acks have been received.
    #[must_use]
    /// Returns true if the evacuation receipt is attached.

    pub fn has_evacuation_receipt(&self) -> bool {
        self.evacuation_receipt_id.is_some()
    }

    pub fn all_acks_received(&self) -> bool {
        self.acks_received >= self.acks_expected
    }
}

// ---------------------------------------------------------------------------
// DrainProtocolMachine -- the protocol-level state machine
// ---------------------------------------------------------------------------

/// Tracks the protocol-level lifecycle of a node drain.
///
/// This is the coordination-layer state machine that sequences:
/// announce, drain, complete, and terminal states. It is separate from
/// the request-level state machine ([`crate::drain_state::DrainStateMachine`])
/// which handles request validation, transfer, and completion for a single
/// drain request.
#[derive(Clone, Debug)]
pub struct DrainProtocolMachine {
    state: DrainProtocolState,
    draining_node_id: MemberId,
    epoch_id: EpochId,
    acks_received: u64,
    acks_expected: u64,
    /// Human-readable reason for the last error or cancellation.
    failure_reason: Option<String>,
    /// Committed evacuation receipt proving data relocation off the
    /// draining node. Set during drain completion.
    evacuation_receipt: Option<EvacuationReceipt>,
}

impl DrainProtocolMachine {
    /// Create a new idle protocol machine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DrainProtocolState::Idle,
            draining_node_id: MemberId::ZERO,
            epoch_id: EpochId(0),
            acks_received: 0,
            acks_expected: 0,
            failure_reason: None,
            evacuation_receipt: None,
        }
    }

    // ---- accessors ----

    #[must_use]
    pub fn state(&self) -> DrainProtocolState {
        self.state
    }

    #[must_use]
    pub fn draining_node_id(&self) -> MemberId {
        self.draining_node_id
    }

    #[must_use]
    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    #[must_use]
    pub fn acks_received(&self) -> u64 {
        self.acks_received
    }

    #[must_use]
    pub fn acks_expected(&self) -> u64 {
        self.acks_expected
    }

    #[must_use]
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    /// Produce a BLAKE3-attested snapshot of the current state.
    #[must_use]
    pub fn snapshot(&self) -> DrainProtocolSnapshot {
        DrainProtocolSnapshot::new(
            self.state,
            self.draining_node_id,
            self.epoch_id,
            self.acks_received,
            self.acks_expected,
        )
    }

    // ---- transitions ----

    /// Announce a drain for the given node.
    ///
    /// Transitions from `Idle` to `DrainAnnounced`. Records the expected
    /// number of peer acknowledgements.
    ///
    /// # Errors
    /// - `AlreadyDraining` if the machine is not idle.
    pub fn announce_drain(
        &mut self,
        node_id: MemberId,
        epoch_id: EpochId,
        expected_peers: u64,
    ) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        if self.state != DrainProtocolState::Idle {
            return Err(DrainProtocolError::AlreadyDraining {
                node_id: self.draining_node_id,
            });
        }

        self.draining_node_id = node_id;
        self.epoch_id = epoch_id;
        self.acks_received = 0;
        self.acks_expected = expected_peers;
        self.failure_reason = None;
        self.evacuation_receipt = None;
        self.state = self
            .state
            .transition_to(DrainProtocolState::DrainAnnounced)?;

        Ok(self.snapshot())
    }

    /// Record a peer acknowledgement of the drain announce.
    ///
    /// Increments the ack counter. Does not change the protocol state
    /// (remains `DrainAnnounced`); the caller checks `all_acks_received()`
    /// to decide when to advance.
    ///
    /// # Errors
    /// - `WrongState` if not in `DrainAnnounced`.
    pub fn record_ack(&mut self) -> Result<(), DrainProtocolError> {
        if self.state != DrainProtocolState::DrainAnnounced {
            return Err(DrainProtocolError::WrongState {
                expected: DrainProtocolState::DrainAnnounced,
                actual: self.state,
            });
        }
        self.acks_received = self.acks_received.saturating_add(1);
        Ok(())
    }

    /// Advance from `DrainAnnounced` to `Draining` when all acks are received.
    ///
    /// # Errors
    /// - `WrongState` if not in `DrainAnnounced`.
    ///
    /// Note: this method does not check that all acks have been received;
    /// the caller is responsible for gating on `all_acks_received()`.
    pub fn start_draining(&mut self) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        if self.state != DrainProtocolState::DrainAnnounced {
            return Err(DrainProtocolError::WrongState {
                expected: DrainProtocolState::DrainAnnounced,
                actual: self.state,
            });
        }
        self.state = self.state.transition_to(DrainProtocolState::Draining)?;
        Ok(self.snapshot())
    }

    /// Complete the drain, transitioning from `Draining` to `DrainComplete`.
    ///
    /// Called after state transfer finishes successfully.
    ///
    /// # Errors
    /// - `WrongState` if not in `Draining`.
    /// Complete draining and attach an evacuation receipt.
    pub fn complete_draining_with_evacuation(
        &mut self,
        receipt: EvacuationReceipt,
    ) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        self.state = self.state.transition_to(DrainProtocolState::DrainComplete)?;
        self.evacuation_receipt = Some(receipt);
        Ok(self.snapshot())
    }

    pub fn complete_draining(&mut self) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        if self.state != DrainProtocolState::Draining {
            return Err(DrainProtocolError::WrongState {
                expected: DrainProtocolState::Draining,
                actual: self.state,
            });
        }
        self.state = self
            .state
            .transition_to(DrainProtocolState::DrainComplete)?;
        Ok(self.snapshot())
    }

    /// Finalize the drain, transitioning from `DrainComplete` to `Drained`.
    ///
    /// Called after the epoch gate commits the membership transition and
    /// the roster removes the node.
    ///
    /// # Errors
    /// - `WrongState` if not in `DrainComplete`.
    pub fn finalize_drain(&mut self) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        self.state = self.state.transition_to(DrainProtocolState::Drained)?;
        Ok(self.snapshot())
    }

    /// Mark the drain as `Drained` regardless of current state (forced path).
    ///
    /// Used for timeout-forced completion. This is a terminal operation.
    pub fn force_drained(&mut self) -> DrainProtocolSnapshot {
        self.state = DrainProtocolState::Drained;
        self.snapshot()
    }

    /// Cancel the drain, returning to `Idle`.
    ///
    /// Can be called from any non-terminal state.
    ///
    /// # Errors
    /// - `InvalidTransition` if already `Drained` and the idempotent
    ///   transition is not supported (but `Drained` is terminal anyway).
    pub fn cancel_drain(
        &mut self,
        reason: String,
    ) -> Result<DrainProtocolSnapshot, DrainProtocolError> {
        if self.state == DrainProtocolState::Drained {
            return Err(DrainProtocolError::InvalidTransition {
                from: self.state,
                to: DrainProtocolState::Idle,
            });
        }
        self.failure_reason = Some(reason);
        let target = DrainProtocolState::Idle;
        self.state = self.state.transition_to(target)?;
        Ok(self.snapshot())
    }

    /// Reset the machine back to idle, clearing all fields.
    pub fn reset(&mut self) {
        self.state = DrainProtocolState::Idle;
        self.draining_node_id = MemberId::ZERO;
        self.epoch_id = EpochId(0);
        self.acks_received = 0;
        self.acks_expected = 0;
        self.failure_reason = None;
        self.evacuation_receipt = None;
    }
}

impl Default for DrainProtocolMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // --- DrainProtocolState tests ---

    #[test]
    fn state_as_str() {
        assert_eq!(DrainProtocolState::Idle.as_str(), "idle");
        assert_eq!(
            DrainProtocolState::DrainAnnounced.as_str(),
            "drain_announced"
        );
        assert_eq!(DrainProtocolState::Draining.as_str(), "draining");
        assert_eq!(DrainProtocolState::DrainComplete.as_str(), "drain_complete");
        assert_eq!(DrainProtocolState::Drained.as_str(), "drained");
    }

    #[test]
    fn state_terminal() {
        assert!(!DrainProtocolState::Idle.is_terminal());
        assert!(!DrainProtocolState::DrainAnnounced.is_terminal());
        assert!(!DrainProtocolState::Draining.is_terminal());
        assert!(!DrainProtocolState::DrainComplete.is_terminal());
        assert!(DrainProtocolState::Drained.is_terminal());
    }

    #[test]
    fn state_transitions_valid() {
        // Happy path
        assert!(DrainProtocolState::Idle.can_transition_to(DrainProtocolState::DrainAnnounced));
        assert!(DrainProtocolState::DrainAnnounced.can_transition_to(DrainProtocolState::Draining));
        assert!(DrainProtocolState::Draining.can_transition_to(DrainProtocolState::DrainComplete));
        assert!(DrainProtocolState::DrainComplete.can_transition_to(DrainProtocolState::Drained));

        // Cancel paths
        assert!(DrainProtocolState::DrainAnnounced.can_transition_to(DrainProtocolState::Idle));
        assert!(DrainProtocolState::Draining.can_transition_to(DrainProtocolState::Idle));
        assert!(DrainProtocolState::DrainComplete.can_transition_to(DrainProtocolState::Idle));

        // Idempotent
        assert!(DrainProtocolState::Drained.can_transition_to(DrainProtocolState::Drained));
    }

    #[test]
    fn state_transitions_invalid() {
        // Skipping states
        assert!(!DrainProtocolState::Idle.can_transition_to(DrainProtocolState::Draining));
        assert!(!DrainProtocolState::Idle.can_transition_to(DrainProtocolState::DrainComplete));
        assert!(!DrainProtocolState::Idle.can_transition_to(DrainProtocolState::Drained));

        // Backwards
        assert!(!DrainProtocolState::Draining.can_transition_to(DrainProtocolState::DrainAnnounced));
        assert!(!DrainProtocolState::DrainComplete.can_transition_to(DrainProtocolState::Draining));
        assert!(!DrainProtocolState::Drained.can_transition_to(DrainProtocolState::DrainComplete));

        // From terminal (except idempotent)
        assert!(!DrainProtocolState::Drained.can_transition_to(DrainProtocolState::Idle));
        assert!(!DrainProtocolState::Drained.can_transition_to(DrainProtocolState::DrainAnnounced));
    }

    #[test]
    fn transition_to_ok() {
        let result = DrainProtocolState::Idle.transition_to(DrainProtocolState::DrainAnnounced);
        assert_eq!(result, Ok(DrainProtocolState::DrainAnnounced));
    }

    #[test]
    fn transition_to_err() {
        let result = DrainProtocolState::Idle.transition_to(DrainProtocolState::Drained);
        assert!(matches!(
            result,
            Err(DrainProtocolError::InvalidTransition { .. })
        ));
    }

    // --- BLAKE3 digest tests ---

    #[test]
    fn digest_is_nonzero() {
        let d = drain_protocol_digest(DrainProtocolState::DrainAnnounced, mid(1), EpochId(5));
        assert_ne!(d, [0u8; 32]);
    }

    #[test]
    fn digest_deterministic() {
        let d1 = drain_protocol_digest(DrainProtocolState::Draining, mid(42), EpochId(7));
        let d2 = drain_protocol_digest(DrainProtocolState::Draining, mid(42), EpochId(7));
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_differs_by_state() {
        let d1 = drain_protocol_digest(DrainProtocolState::DrainAnnounced, mid(1), EpochId(5));
        let d2 = drain_protocol_digest(DrainProtocolState::Draining, mid(1), EpochId(5));
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_differs_by_node() {
        let d1 = drain_protocol_digest(DrainProtocolState::Draining, mid(1), EpochId(5));
        let d2 = drain_protocol_digest(DrainProtocolState::Draining, mid(2), EpochId(5));
        assert_ne!(d1, d2);
    }

    #[test]
    fn digest_differs_by_epoch() {
        let d1 = drain_protocol_digest(DrainProtocolState::Draining, mid(1), EpochId(5));
        let d2 = drain_protocol_digest(DrainProtocolState::Draining, mid(1), EpochId(6));
        assert_ne!(d1, d2);
    }

    // --- DrainProtocolSnapshot tests ---

    #[test]
    fn snapshot_verify_roundtrip() {
        let snap = DrainProtocolSnapshot::new(
            DrainProtocolState::DrainAnnounced,
            mid(7),
            EpochId(3),
            2,
            5,
        );
        assert!(snap.verify_digest());
    }

    #[test]
    fn snapshot_tampered_digest_fails() {
        let mut snap = DrainProtocolSnapshot::new(
            DrainProtocolState::DrainAnnounced,
            mid(7),
            EpochId(3),
            2,
            5,
        );
        snap.blake3_digest[0] ^= 0xFF;
        assert!(!snap.verify_digest());
    }

    #[test]
    fn snapshot_all_acks_received() {
        let snap = DrainProtocolSnapshot::new(
            DrainProtocolState::DrainAnnounced,
            mid(1),
            EpochId(1),
            5,
            5,
        );
        assert!(snap.all_acks_received());

        let snap2 = DrainProtocolSnapshot::new(
            DrainProtocolState::DrainAnnounced,
            mid(1),
            EpochId(1),
            4,
            5,
        );
        assert!(!snap2.all_acks_received());
    }

    // --- DrainProtocolMachine tests ---

    #[test]
    fn machine_starts_idle() {
        let m = DrainProtocolMachine::new();
        assert_eq!(m.state(), DrainProtocolState::Idle);
    }

    #[test]
    fn announce_drain() {
        let mut m = DrainProtocolMachine::new();
        let snap = m.announce_drain(mid(10), EpochId(3), 5).unwrap();
        assert_eq!(m.state(), DrainProtocolState::DrainAnnounced);
        assert_eq!(m.draining_node_id(), mid(10));
        assert_eq!(m.epoch_id(), EpochId(3));
        assert_eq!(m.acks_expected(), 5);
        assert_eq!(m.acks_received(), 0);
        assert!(snap.verify_digest());
    }

    #[test]
    fn announce_rejects_when_not_idle() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        let err = m.announce_drain(mid(2), EpochId(1), 3).unwrap_err();
        assert!(matches!(err, DrainProtocolError::AlreadyDraining { .. }));
    }

    #[test]
    fn record_ack() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.record_ack().unwrap();
        assert_eq!(m.acks_received(), 1);
        m.record_ack().unwrap();
        m.record_ack().unwrap();
        assert_eq!(m.acks_received(), 3);
        // Overflow safe: saturating, will not panic
        m.record_ack().unwrap();
        assert_eq!(m.acks_received(), 4);
    }

    #[test]
    fn record_ack_rejects_wrong_state() {
        let mut m = DrainProtocolMachine::new();
        let err = m.record_ack().unwrap_err();
        assert!(matches!(err, DrainProtocolError::WrongState { .. }));
    }

    #[test]
    fn start_draining() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        let snap = m.start_draining().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Draining);
        assert!(snap.verify_digest());
    }

    #[test]
    fn start_draining_rejects_wrong_state() {
        let mut m = DrainProtocolMachine::new();
        let err = m.start_draining().unwrap_err();
        assert!(matches!(err, DrainProtocolError::WrongState { .. }));
    }

    #[test]
    fn complete_draining() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        let snap = m.complete_draining().unwrap();
        assert_eq!(m.state(), DrainProtocolState::DrainComplete);
        assert!(snap.verify_digest());
    }

    #[test]
    fn complete_draining_rejects_wrong_state() {
        let mut m = DrainProtocolMachine::new();
        let err = m.complete_draining().unwrap_err();
        assert!(matches!(err, DrainProtocolError::WrongState { .. }));
    }

    #[test]
    fn finalize_drain_from_complete() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.complete_draining().unwrap();
        let snap = m.finalize_drain().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());
    }

    #[test]
    fn finalize_drain_from_drained_idempotent() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.complete_draining().unwrap();
        m.finalize_drain().unwrap();
        // Idempotent: Drained -> Drained
        let snap = m.finalize_drain().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());
    }

    #[test]
    fn force_drained() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        // Force to Drained from DrainAnnounced
        let snap = m.force_drained();
        assert_eq!(m.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());
    }

    #[test]
    fn cancel_from_announced() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        let snap = m.cancel_drain("operator requested".into()).unwrap();
        assert_eq!(m.state(), DrainProtocolState::Idle);
        assert!(snap.verify_digest());
        assert_eq!(m.failure_reason(), Some("operator requested"));
    }

    #[test]
    fn cancel_from_draining() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.cancel_drain("transfer failed".into()).unwrap();
        assert_eq!(m.state(), DrainProtocolState::Idle);
        assert_eq!(m.failure_reason(), Some("transfer failed"));
    }

    #[test]
    fn cancel_from_complete() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.complete_draining().unwrap();
        m.cancel_drain("epoch gate rejected".into()).unwrap();
        assert_eq!(m.state(), DrainProtocolState::Idle);
    }

    #[test]
    fn cancel_rejects_from_drained() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.complete_draining().unwrap();
        m.finalize_drain().unwrap();
        let err = m.cancel_drain("too late".into()).unwrap_err();
        assert!(matches!(err, DrainProtocolError::InvalidTransition { .. }));
    }

    #[test]
    fn reset_after_full_lifecycle() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 3).unwrap();
        m.start_draining().unwrap();
        m.complete_draining().unwrap();
        m.finalize_drain().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Drained);

        m.reset();
        assert_eq!(m.state(), DrainProtocolState::Idle);
        assert_eq!(m.draining_node_id(), MemberId::ZERO);
        assert_eq!(m.acks_received(), 0);
        assert_eq!(m.acks_expected(), 0);
    }

    #[test]
    fn snapshot_reflects_ack_count() {
        let mut m = DrainProtocolMachine::new();
        m.announce_drain(mid(1), EpochId(1), 5).unwrap();
        m.record_ack().unwrap();
        m.record_ack().unwrap();
        let snap = m.snapshot();
        assert_eq!(snap.acks_received, 2);
        assert_eq!(snap.acks_expected, 5);
        assert!(!snap.all_acks_received());
        assert!(snap.verify_digest());
    }

    #[test]
    fn full_happy_path() {
        let mut m = DrainProtocolMachine::new();

        // Announce
        let snap = m.announce_drain(mid(42), EpochId(7), 3).unwrap();
        assert_eq!(m.state(), DrainProtocolState::DrainAnnounced);
        assert!(snap.verify_digest());

        // Collect acks
        m.record_ack().unwrap();
        m.record_ack().unwrap();
        m.record_ack().unwrap();
        assert!(m.snapshot().all_acks_received());

        // Start draining
        m.start_draining().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Draining);

        // Complete draining
        m.complete_draining().unwrap();
        assert_eq!(m.state(), DrainProtocolState::DrainComplete);

        // Finalize
        let snap = m.finalize_drain().unwrap();
        assert_eq!(m.state(), DrainProtocolState::Drained);
        assert!(snap.verify_digest());
    }

    #[test]
    fn drain_protocol_error_display() {
        let e = DrainProtocolError::InvalidTransition {
            from: DrainProtocolState::Idle,
            to: DrainProtocolState::Drained,
        };
        let s = format!("{e}");
        assert!(s.contains("idle"));
        assert!(s.contains("drained"));

        let e = DrainProtocolError::AlreadyDraining { node_id: mid(99) };
        assert!(format!("{e}").contains("99"));

        let e = DrainProtocolError::WrongState {
            expected: DrainProtocolState::DrainAnnounced,
            actual: DrainProtocolState::Idle,
        };
        let s = format!("{e}");
        assert!(s.contains("drain_announced"));
        assert!(s.contains("idle"));
    }
}
