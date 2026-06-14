//! Connection admission controller: validates inbound transport connections
//! against the membership roster before allowing message exchange.
//!
//! [`AdmissionController`] sits at the ingress edge of the transport accept
//! loop. Before a new connection reaches the peer manager or any
//! message-processing subsystem, the admission controller queries the
//! current membership roster and decides whether the connecting peer is
//! authorized to exchange frames.
//!
//! # Architecture
//!
//! - [`RosterEntry`]: Simplified roster entry carrying peer identity, health
//!   state, and epoch number. The transport crate owns this type so the
//!   admission controller stays independent of `tidefs-membership-live`.
//! - [`RosterPeerState`]: Four-state peer health model: `Alive`, `Suspected`,
//!   `Failed`, `Drained`.
//! - [`AdmissionController`]: Queries the roster on each admission check.
//! - [`admit`](AdmissionController::admit): Single entry point that checks a
//!   connecting peer's identity and claimed epoch against the roster.
//!
//! # Rejection
//!
//! Admission rejection carries the rejection reason through the authenticated
//! session context established during handshake. The [`ConnectionAdmission`]
//! wrapper emits rejection events to registered subscribers for audit
//! and operator visibility.
//!
//! # Rejection Frame Wire Format
//!
//! When the admission controller rejects a connection, the rejecting side
//! sends a [`RejectionFrame`]:
//!
//! ```text
//! [ 0.. 4)  magic        "VADM" (4 bytes, ASCII)
//! [ 4..12)  peer_id      u64 LE
//! [12..13)  reason       u8 discriminant
//! ```

use tidefs_types_transport_session::{
    ClosureClass, DrainResultClass, TransportClosureReceipt, TransportClosureReceiptId,
    TransportSessionId,
};

// ---------------------------------------------------------------------------
// BLAKE3 domain constant
// ---------------------------------------------------------------------------

/// Magic bytes for rejection frame wire format.
const REJECTION_FRAME_MAGIC: &[u8; 4] = b"VADM";

// ---------------------------------------------------------------------------
// RosterPeerState
// ---------------------------------------------------------------------------

/// Peer health state as seen by the admission controller.
///
/// Mirrors the membership roster's state model but is owned by transport
/// so the admission controller stays independent of `tidefs-membership-live`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterPeerState {
    /// Peer is healthy and participating in the cluster.
    Alive,
    /// Peer is under suspicion (unreachable, ping timeout).
    Suspected,
    /// Peer has been confirmed failed.
    Failed,
    /// Peer has been drained or gracefully left the cluster.
    Drained,
}

// ---------------------------------------------------------------------------
// RosterEntry
// ---------------------------------------------------------------------------

/// Simplified roster entry carrying the fields the admission controller
/// needs to make an accept/reject decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    /// The peer's node identifier.
    pub peer_id: u64,
    /// Current health state in the roster.
    pub state: RosterPeerState,
    /// Roster epoch this entry belongs to.
    pub epoch: u64,
}

impl RosterEntry {
    #[must_use]
    pub const fn new(peer_id: u64, state: RosterPeerState, epoch: u64) -> Self {
        Self {
            peer_id,
            state,
            epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionRejection
// ---------------------------------------------------------------------------

/// Why a peer was rejected at the admission gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionRejection {
    /// Peer is not present in the roster.
    NotInRoster,
    /// Peer is under suspicion and not allowed to connect.
    PeerSuspected,
    /// Peer has been drained/failed and is no longer a cluster member.
    PeerDrained,
    /// Peer's claimed epoch is ahead of the roster epoch (stale peer).
    EpochMismatch,
}

impl AdmissionRejection {
    #[must_use]
    /// Static trigger label used by admission refusal close receipts.
    pub const fn trigger_ref(self) -> &'static str {
        match self {
            Self::NotInRoster => "admission.transport_session_0.not_in_roster.a0",
            Self::PeerSuspected => "admission.transport_session_0.peer_suspected.a1",
            Self::PeerDrained => "admission.transport_session_0.peer_drained.a2",
            Self::EpochMismatch => "admission.transport_session_0.epoch_mismatch.a3",
        }
    }

    #[must_use]
    /// Admission refusals are policy refusals, not clean drains.
    pub const fn closure_class(self) -> ClosureClass {
        ClosureClass::RefusedPolicy
    }

    #[must_use]
    /// No session exists at admission refusal, so there is no clean drain.
    pub const fn drain_result_class(self) -> DrainResultClass {
        DrainResultClass::Force
    }

    /// Discriminant for wire format encoding.
    pub fn discriminant(self) -> u8 {
        match self {
            AdmissionRejection::NotInRoster => 0,
            AdmissionRejection::PeerSuspected => 1,
            AdmissionRejection::PeerDrained => 2,
            AdmissionRejection::EpochMismatch => 3,
        }
    }

    /// Decode a discriminant byte back to an AdmissionRejection.
    pub fn from_discriminant(v: u8) -> Option<Self> {
        match v {
            0 => Some(AdmissionRejection::NotInRoster),
            1 => Some(AdmissionRejection::PeerSuspected),
            2 => Some(AdmissionRejection::PeerDrained),
            3 => Some(AdmissionRejection::EpochMismatch),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionDecision
// ---------------------------------------------------------------------------

/// The result of an admission check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Peer is authorized to connect.
    Accepted,
    /// Peer is rejected. The rejection reason is carried through the
    /// authenticated session context established during handshake.
    Rejected {
        /// Why the peer was rejected.
        reason: AdmissionRejection,
    },
}

impl AdmissionDecision {
    /// Returns `true` if the decision is [`Accepted`](AdmissionDecision::Accepted).
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        matches!(self, AdmissionDecision::Accepted)
    }

    /// Returns `true` if the decision is [`Rejected`](AdmissionDecision::Rejected).
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, AdmissionDecision::Rejected { .. })
    }
}

// ---------------------------------------------------------------------------
// RejectionFrame
// ---------------------------------------------------------------------------

/// Wire-format rejection frame sent to a rejected peer.
///
/// Carries the peer's identity and rejection reason through the
/// authenticated session context established during handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectionFrame {
    /// The rejected peer's node identifier.
    pub peer_id: u64,
    /// Reason for rejection.
    pub reason: AdmissionRejection,
}

impl RejectionFrame {
    /// Wire format size in bytes: 4 (magic) + 8 (peer_id) + 1 (reason).
    pub const WIRE_SIZE: usize = 13;

    /// Create a rejection frame from an admission decision.
    ///
    /// Returns `None` if the decision is `Accepted`.
    #[must_use]
    pub fn from_decision(peer_id: u64, decision: &AdmissionDecision) -> Option<Self> {
        match decision {
            AdmissionDecision::Accepted => None,
            AdmissionDecision::Rejected { reason } => Some(Self {
                peer_id,
                reason: *reason,
            }),
        }
    }

    /// Encode this rejection frame to its wire format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::WIRE_SIZE);
        buf.extend_from_slice(REJECTION_FRAME_MAGIC);
        buf.extend_from_slice(&self.peer_id.to_le_bytes());
        buf.push(self.reason.discriminant());
        buf
    }

    /// Decode a rejection frame from its wire format.
    ///
    /// Returns `None` if the magic bytes don't match or the frame is too
    /// short.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::WIRE_SIZE {
            return None;
        }
        if &data[0..4] != REJECTION_FRAME_MAGIC {
            return None;
        }
        let mut peer_id_bytes = [0u8; 8];
        peer_id_bytes.copy_from_slice(&data[4..12]);
        let peer_id = u64::from_le_bytes(peer_id_bytes);
        let reason = AdmissionRejection::from_discriminant(data[12])?;
        Some(Self { peer_id, reason })
    }
}

// ---------------------------------------------------------------------------
// AdmissionController
// ---------------------------------------------------------------------------

/// Connection admission controller.
///
/// Queries the membership roster to authorize inbound transport connections.
/// Rejection decisions carry an [`AdmissionRejection`] reason through the
/// authenticated session context established during handshake.
///
/// # Integration point
///
/// In the transport accept loop, after accepting a TCP connection but before
/// spawning per-connection handlers or feeding frames to the peer manager:
///
/// ```text
/// let (conn, peer_addr) = backend.accept()?;
/// let (peer_id, peer_epoch) = extract_handshake_info(&mut conn)?;
/// let decision = admission_controller.admit(peer_id, peer_epoch, &roster);
/// match decision {
///     AdmissionDecision::Accepted => { /* proceed to session setup */ }
///     AdmissionDecision::Rejected { .. } => {
///         if let Some(frame) = RejectionFrame::from_decision(peer_id, &decision) {
///             conn.write_frame(&frame.encode())?;
///         }
///         conn.close();
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AdmissionController {
    /// Whether the controller has been initialized with a roster.
    initialized: bool,
}

impl AdmissionController {
    /// Create a new admission controller.
    #[must_use]
    pub fn new() -> Self {
        Self { initialized: false }
    }

    /// Mark the controller as initialized with a roster snapshot.
    ///
    /// Call this whenever the roster changes (member added/removed, state
    /// transition, epoch advance) so that subsequent [`admit`](Self::admit)
    /// calls use the updated roster view.
    pub fn update_roster(&mut self, _roster: &[RosterEntry]) {
        self.initialized = true;
    }

    /// Admit or reject a connecting peer.
    ///
    /// # Arguments
    ///
    /// * `peer_id` — The connecting peer's node identifier.
    /// * `peer_epoch` — The epoch the peer claims to belong to.
    /// * `roster` — Current roster entries to check against.
    ///
    /// # Returns
    ///
    /// [`Accepted`](AdmissionDecision::Accepted) if the peer is in the roster
    /// with state [`Alive`](RosterPeerState::Alive) and its epoch matches.
    /// Otherwise a [`Rejected`](AdmissionDecision::Rejected) decision with
    /// the rejection reason.
    pub fn admit(
        &self,
        peer_id: u64,
        peer_epoch: u64,
        roster: &[RosterEntry],
    ) -> AdmissionDecision {
        let entry = roster.iter().find(|e| e.peer_id == peer_id);

        match entry {
            None => self.reject(peer_id, AdmissionRejection::NotInRoster),
            Some(e) => {
                // A peer claiming an epoch ahead of the roster is stale/wrong.
                if peer_epoch > e.epoch {
                    return self.reject(peer_id, AdmissionRejection::EpochMismatch);
                }
                match e.state {
                    RosterPeerState::Alive => AdmissionDecision::Accepted,
                    RosterPeerState::Suspected => {
                        self.reject(peer_id, AdmissionRejection::PeerSuspected)
                    }
                    RosterPeerState::Failed | RosterPeerState::Drained => {
                        self.reject(peer_id, AdmissionRejection::PeerDrained)
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Build a rejection decision with the given reason.
    fn reject(&self, _peer_id: u64, reason: AdmissionRejection) -> AdmissionDecision {
        AdmissionDecision::Rejected { reason }
    }
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ConnectionAdmissionEvent
// ---------------------------------------------------------------------------

/// Event emitted when a connection is rejected at the admission gate.
///
/// Carries the rejected peer's identity and the rejection reason so
/// operators can audit unauthorized connection attempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionAdmissionEvent {
    /// The rejected peer's node identifier.
    pub peer_id: u64,
    /// The epoch the peer claimed to belong to.
    pub claimed_epoch: u64,
    /// Why the peer was rejected.
    pub reason: AdmissionRejection,
    /// Typed no-session closure evidence for this admission refusal.
    pub closure_receipt: TransportClosureReceipt,
}

impl ConnectionAdmissionEvent {
    /// Create a new admission rejection event.
    #[must_use]
    pub fn new(peer_id: u64, claimed_epoch: u64, reason: AdmissionRejection) -> Self {
        Self {
            peer_id,
            claimed_epoch,
            reason,
            closure_receipt: admission_closure_receipt(peer_id, claimed_epoch, reason),
        }
    }

    #[must_use]
    /// Closure class carried by this admission refusal receipt.
    pub fn closure_class(&self) -> ClosureClass {
        self.closure_receipt.closure_class
    }

    #[must_use]
    /// Drain class carried by this admission refusal receipt.
    pub fn drain_result_class(&self) -> DrainResultClass {
        self.closure_receipt.drain_result_class
    }
}

fn admission_closure_receipt(
    peer_id: u64,
    claimed_epoch: u64,
    reason: AdmissionRejection,
) -> TransportClosureReceipt {
    let digest = admission_receipt_digest(peer_id, claimed_epoch, reason);
    TransportClosureReceipt {
        receipt_id: TransportClosureReceiptId::new(digest),
        session_ref: TransportSessionId::ZERO,
        closure_class: reason.closure_class(),
        trigger_ref: reason.trigger_ref(),
        last_seq_acked: 0,
        drain_result_class: reason.drain_result_class(),
        successor_session_ref: None,
        preserved_artifact_refs: Vec::new(),
        digest,
    }
}

fn admission_receipt_digest(peer_id: u64, claimed_epoch: u64, reason: AdmissionRejection) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tidefs.transport.admission.close_receipt.v1");
    hasher.update(&peer_id.to_le_bytes());
    hasher.update(&claimed_epoch.to_le_bytes());
    hasher.update(&[reason.discriminant()]);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

// ---------------------------------------------------------------------------
// ConnectionAdmissionSubscriber
// ---------------------------------------------------------------------------

/// A subscriber that receives [`ConnectionAdmissionEvent`]s emitted by
/// [`ConnectionAdmission`] when a peer is rejected at the admission gate.
///
/// Implementations must be non-blocking and fast; spawn asynchronous work
/// for long-running audit or alert actions.
pub trait ConnectionAdmissionSubscriber: Send + Sync {
    /// Called synchronously when a connection admission is rejected.
    fn on_admission_rejected(&self, event: &ConnectionAdmissionEvent);
}

// ---------------------------------------------------------------------------
// ConnectionAdmission
// ---------------------------------------------------------------------------

/// Membership-driven connection admission gate.
///
/// Wraps an [`AdmissionController`] and a cached roster snapshot so the
/// transport accept loop can check inbound peers against the current
/// committed membership roster without reaching into the membership layer
/// on every accept.
///
/// The membership layer updates the roster via
/// [`update_roster`](ConnectionAdmission::update_roster) when the committed
/// peer set changes (member joined, left, failed, drained).  The transport
/// accept loop calls [`admit`](ConnectionAdmission::admit) after the
/// handshake completes and before message dispatch begins.
///
/// # Integration
///
/// ```text
/// // In the membership event subscriber (membership-live):
/// admission.update_roster(&new_roster);
///
/// // In the transport accept loop:
/// let (peer_id, peer_epoch) = handshake_result;
/// match admission.admit(peer_id, peer_epoch) {
///     Ok(()) => { /* proceed to session setup */ }
///     Err(rejection) => {
///         tracing::warn!(
///             peer_id = peer_id,
///             reason = %rejection,
///             "admission rejected"
///         );
///         conn.close();
///     }
/// }
/// ```
pub struct ConnectionAdmission {
    /// The underlying admission controller.
    controller: AdmissionController,
    /// Cached roster snapshot for admission lookups.
    roster: Vec<RosterEntry>,
    /// Subscribers notified on admission rejection for audit/logging.
    subscribers: Vec<Box<dyn ConnectionAdmissionSubscriber>>,
}

impl ConnectionAdmission {
    /// Create a new connection admission gate with an empty roster.
    ///
    /// All peers are rejected until [`update_roster`](Self::update_roster)
    /// is called with a non-empty roster.
    #[must_use]
    pub fn new() -> Self {
        Self {
            controller: AdmissionController::new(),
            roster: Vec::new(),
            subscribers: Vec::new(),
        }
    }

    /// Create a new admission gate pre-loaded with a roster.
    #[must_use]
    pub fn with_roster(roster: Vec<RosterEntry>) -> Self {
        let mut controller = AdmissionController::new();
        controller.update_roster(&roster);
        Self {
            controller,
            roster,
            subscribers: Vec::new(),
        }
    }

    /// Return a reference to the current cached roster.
    #[must_use]
    pub fn roster(&self) -> &[RosterEntry] {
        &self.roster
    }

    /// Update the roster from the membership layer.
    ///
    /// Replaces the cached roster and notifies the underlying controller.
    /// Call this on every committed-roster change.
    pub fn update_roster(&mut self, roster: &[RosterEntry]) {
        self.controller.update_roster(roster);
        self.roster = roster.to_vec();
    }

    /// Replace the entire roster (convenience wrapper for bulk updates).
    pub fn set_roster(&mut self, roster: Vec<RosterEntry>) {
        self.controller.update_roster(&roster);
        self.roster = roster;
    }

    /// Admit or reject a connecting peer.
    ///
    /// Returns `Ok(())` if the peer is in the roster with state
    /// [`Alive`](RosterPeerState::Alive) and an acceptable epoch.
    /// Returns `Err(`[`AdmissionRejection`]`)` detailing why the peer was rejected.
    pub fn admit(&self, peer_id: u64, peer_epoch: u64) -> Result<(), AdmissionRejection> {
        match self.controller.admit(peer_id, peer_epoch, &self.roster) {
            AdmissionDecision::Accepted => Ok(()),
            AdmissionDecision::Rejected { reason, .. } => {
                self.emit_rejection(peer_id, peer_epoch, reason);
                Err(reason)
            }
        }
    }

    /// Admit or reject and optionally produce a [`RejectionFrame`] for wire
    /// transmission to the rejected peer.
    ///
    /// Returns `Ok(())` on acceptance, or `Err(RejectionFrame)` on rejection.
    pub fn admit_with_frame(&self, peer_id: u64, peer_epoch: u64) -> Result<(), RejectionFrame> {
        let decision = self.controller.admit(peer_id, peer_epoch, &self.roster);
        match &decision {
            AdmissionDecision::Accepted => Ok(()),
            AdmissionDecision::Rejected { reason, .. } => {
                self.emit_rejection(peer_id, peer_epoch, *reason);
                match RejectionFrame::from_decision(peer_id, &decision) {
                    Some(frame) => Err(frame),
                    None => Err(RejectionFrame {
                        peer_id,
                        reason: AdmissionRejection::NotInRoster,
                    }),
                }
            }
        }
    }

    /// Returns `true` if the roster is empty (all peers will be rejected).
    #[must_use]
    pub fn is_roster_empty(&self) -> bool {
        self.roster.is_empty()
    }

    /// Returns the number of entries in the cached roster.
    #[must_use]
    pub fn roster_len(&self) -> usize {
        self.roster.len()
    }

    /// Register a subscriber for admission rejection events.
    ///
    /// The subscriber's
    /// [`on_admission_rejected`](ConnectionAdmissionSubscriber::on_admission_rejected)
    /// method is called synchronously on every rejected admission.
    /// Subscribers should be non-blocking.
    pub fn subscribe(&mut self, subscriber: Box<dyn ConnectionAdmissionSubscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Emit an admission rejection event to all registered subscribers.
    fn emit_rejection(&self, peer_id: u64, claimed_epoch: u64, reason: AdmissionRejection) {
        if self.subscribers.is_empty() {
            return;
        }
        let event = ConnectionAdmissionEvent::new(peer_id, claimed_epoch, reason);
        for sub in &self.subscribers {
            sub.on_admission_rejected(&event);
        }
    }
}

impl Clone for ConnectionAdmission {
    fn clone(&self) -> Self {
        Self {
            controller: self.controller.clone(),
            roster: self.roster.clone(),
            subscribers: Vec::new(),
        }
    }
}

impl std::fmt::Debug for ConnectionAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionAdmission")
            .field("controller", &self.controller)
            .field("roster", &self.roster)
            .field("subscriber_count", &self.subscribers.len())
            .finish()
    }
}

impl Default for ConnectionAdmission {
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

    // -- helpers --

    fn make_roster(entries: &[(u64, RosterPeerState, u64)]) -> Vec<RosterEntry> {
        entries
            .iter()
            .map(|&(peer_id, state, epoch)| RosterEntry::new(peer_id, state, epoch))
            .collect()
    }

    fn make_controller(roster: &[RosterEntry]) -> AdmissionController {
        let mut c = AdmissionController::new();
        c.update_roster(roster);
        c
    }

    // -------------------------------------------------------------------
    // Accept alive roster member
    // -------------------------------------------------------------------

    #[test]
    fn accept_alive_roster_member() {
        let roster = make_roster(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Alive, 5),
        ]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        assert_eq!(decision, AdmissionDecision::Accepted);
    }

    // -------------------------------------------------------------------
    // Reject: NotInRoster
    // -------------------------------------------------------------------

    #[test]
    fn reject_peer_not_in_roster() {
        let roster = make_roster(&[(1, RosterPeerState::Alive, 5)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(99, 5, &roster);
        match decision {
            AdmissionDecision::Rejected { reason } => {
                assert_eq!(reason, AdmissionRejection::NotInRoster);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Reject: PeerSuspected
    // -------------------------------------------------------------------

    #[test]
    fn reject_suspected_peer() {
        let roster = make_roster(&[(1, RosterPeerState::Suspected, 5)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        match decision {
            AdmissionDecision::Rejected { reason } => {
                assert_eq!(reason, AdmissionRejection::PeerSuspected);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Reject: PeerDrained (Failed + Drained both map to PeerDrained)
    // -------------------------------------------------------------------

    #[test]
    fn reject_drained_peer() {
        let roster = make_roster(&[(1, RosterPeerState::Drained, 5)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        match decision {
            AdmissionDecision::Rejected { reason } => {
                assert_eq!(reason, AdmissionRejection::PeerDrained);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn reject_failed_peer_as_drained() {
        let roster = make_roster(&[(1, RosterPeerState::Failed, 5)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        match decision {
            AdmissionDecision::Rejected { reason } => {
                assert_eq!(reason, AdmissionRejection::PeerDrained);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Reject: EpochMismatch
    // -------------------------------------------------------------------

    #[test]
    fn reject_epoch_mismatch_peer_claims_ahead() {
        let roster = make_roster(&[(1, RosterPeerState::Alive, 5)]);
        let ctrl = make_controller(&roster);

        // Peer claims epoch 7, roster is at epoch 5
        let decision = ctrl.admit(1, 7, &roster);
        match decision {
            AdmissionDecision::Rejected { reason } => {
                assert_eq!(reason, AdmissionRejection::EpochMismatch);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn accept_peer_with_older_epoch() {
        // A peer claiming an older epoch is allowed (it just hasn't caught up).
        let roster = make_roster(&[(1, RosterPeerState::Alive, 10)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        assert_eq!(decision, AdmissionDecision::Accepted);
    }

    // -------------------------------------------------------------------
    // Idempotent admission
    // -------------------------------------------------------------------

    #[test]
    fn idempotent_admission_same_peer_roster_yields_same_decision() {
        let roster = make_roster(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Alive, 5),
        ]);
        let ctrl = make_controller(&roster);

        let d1 = ctrl.admit(1, 5, &roster);
        let d2 = ctrl.admit(1, 5, &roster);
        assert_eq!(d1, d2);
    }

    // -------------------------------------------------------------------
    // Rejection frame round-trip
    // -------------------------------------------------------------------

    #[test]
    fn rejection_frame_encode_decode_roundtrip() {
        let roster = make_roster(&[(1, RosterPeerState::Suspected, 5)]);
        let ctrl = make_controller(&roster);

        let decision = ctrl.admit(1, 5, &roster);
        let frame = RejectionFrame::from_decision(1, &decision)
            .expect("rejection decision must produce a frame");

        let encoded = frame.encode();
        assert_eq!(encoded.len(), RejectionFrame::WIRE_SIZE);
        assert_eq!(&encoded[0..4], b"VADM");

        let decoded = RejectionFrame::decode(&encoded).expect("decode must succeed");
        assert_eq!(decoded.peer_id, 1);
        assert_eq!(decoded.reason, AdmissionRejection::PeerSuspected);
    }

    #[test]
    fn rejection_frame_from_accepted_decision_is_none() {
        let decision = AdmissionDecision::Accepted;
        assert!(RejectionFrame::from_decision(1, &decision).is_none());
    }

    #[test]
    fn rejection_frame_decode_rejects_wrong_magic() {
        let mut data = vec![0u8; RejectionFrame::WIRE_SIZE];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(RejectionFrame::decode(&data).is_none());
    }

    #[test]
    fn rejection_frame_decode_rejects_short_data() {
        assert!(RejectionFrame::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn rejection_frame_decode_rejects_invalid_reason_discriminant() {
        let mut data = vec![0u8; RejectionFrame::WIRE_SIZE];
        data[0..4].copy_from_slice(b"VADM");
        data[12] = 255; // Invalid discriminant
        assert!(RejectionFrame::decode(&data).is_none());
    }

    // -------------------------------------------------------------------
    // Multi-peer roster: accept/reject isolation
    // -------------------------------------------------------------------

    #[test]
    fn multi_peer_roster_accept_alive_reject_others() {
        let roster = make_roster(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Suspected, 5),
            (3, RosterPeerState::Drained, 5),
            (4, RosterPeerState::Failed, 5),
        ]);
        let ctrl = make_controller(&roster);

        assert!(ctrl.admit(1, 5, &roster).is_accepted());
        assert!(ctrl.admit(2, 5, &roster).is_rejected());
        assert!(ctrl.admit(3, 5, &roster).is_rejected());
        assert!(ctrl.admit(4, 5, &roster).is_rejected());
    }

    // -------------------------------------------------------------------
    // AdmissionDecision helpers
    // -------------------------------------------------------------------

    #[test]
    fn admission_decision_is_accepted() {
        assert!(AdmissionDecision::Accepted.is_accepted());
        assert!(!AdmissionDecision::Accepted.is_rejected());
    }

    #[test]
    fn admission_decision_is_rejected() {
        let rej = AdmissionDecision::Rejected {
            reason: AdmissionRejection::NotInRoster,
        };
        assert!(!rej.is_accepted());
        assert!(rej.is_rejected());
    }

    // -------------------------------------------------------------------
    // AdmissionRejection discriminant round-trip
    // -------------------------------------------------------------------

    #[test]
    fn admission_rejection_discriminant_roundtrip() {
        for reason in &[
            AdmissionRejection::NotInRoster,
            AdmissionRejection::PeerSuspected,
            AdmissionRejection::PeerDrained,
            AdmissionRejection::EpochMismatch,
        ] {
            let d = reason.discriminant();
            let decoded = AdmissionRejection::from_discriminant(d);
            assert_eq!(decoded, Some(*reason));
        }
    }

    // -------------------------------------------------------------------
    // AdmissionController defaults
    // -------------------------------------------------------------------

    #[test]
    fn admission_controller_default_is_not_initialized() {
        let ctrl = AdmissionController::default();
        assert!(!ctrl.initialized);
    }

    // ===================================================================
    // ConnectionAdmission tests
    // ===================================================================

    fn make_roster_entries(entries: &[(u64, RosterPeerState, u64)]) -> Vec<RosterEntry> {
        entries
            .iter()
            .map(|&(peer_id, state, epoch)| RosterEntry::new(peer_id, state, epoch))
            .collect()
    }

    // -------------------------------------------------------------------
    // Construction and defaults
    // -------------------------------------------------------------------

    #[test]
    fn connection_admission_new_empty_roster() {
        let adm = ConnectionAdmission::new();
        assert!(adm.is_roster_empty());
        assert_eq!(adm.roster_len(), 0);
    }

    #[test]
    fn connection_admission_with_roster() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster.clone());
        assert!(!adm.is_roster_empty());
        assert_eq!(adm.roster_len(), 1);
        assert_eq!(adm.roster()[0].peer_id, 1);
    }

    #[test]
    fn connection_admission_default_is_empty() {
        let adm = ConnectionAdmission::default();
        assert!(adm.is_roster_empty());
    }

    // -------------------------------------------------------------------
    // Admit: roster lookup hit (allowed)
    // -------------------------------------------------------------------

    #[test]
    fn admit_alive_peer_accepted() {
        let roster = make_roster_entries(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Alive, 5),
        ]);
        let adm = ConnectionAdmission::with_roster(roster);
        assert!(adm.admit(1, 5).is_ok());
        assert!(adm.admit(2, 5).is_ok());
    }

    // -------------------------------------------------------------------
    // Admit: roster lookup miss (rejected)
    // -------------------------------------------------------------------

    #[test]
    fn admit_unknown_peer_rejected() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        let err = adm.admit(42, 5).unwrap_err();
        assert_eq!(err, AdmissionRejection::NotInRoster);
    }

    #[test]
    fn admit_suspected_peer_rejected() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Suspected, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        let err = adm.admit(1, 5).unwrap_err();
        assert_eq!(err, AdmissionRejection::PeerSuspected);
    }

    #[test]
    fn admit_drained_peer_rejected() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Drained, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        let err = adm.admit(1, 5).unwrap_err();
        assert_eq!(err, AdmissionRejection::PeerDrained);
    }

    #[test]
    fn admit_epoch_mismatch_rejected() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        let err = adm.admit(1, 7).unwrap_err(); // peer claims epoch 7, roster has 5
        assert_eq!(err, AdmissionRejection::EpochMismatch);
    }

    // -------------------------------------------------------------------
    // Empty roster: all rejected
    // -------------------------------------------------------------------

    #[test]
    fn empty_roster_rejects_all() {
        let adm = ConnectionAdmission::new();
        assert!(adm.is_roster_empty());
        assert_eq!(
            adm.admit(1, 0).unwrap_err(),
            AdmissionRejection::NotInRoster
        );
        assert_eq!(
            adm.admit(42, 5).unwrap_err(),
            AdmissionRejection::NotInRoster
        );
    }

    // -------------------------------------------------------------------
    // Roster update interleaving
    // -------------------------------------------------------------------

    #[test]
    fn roster_update_peer_added_mid_session() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);

        // Peer 2 not yet in roster — rejected
        assert!(adm.admit(2, 5).is_err());

        // Peer 2 joins the roster
        let new_roster = make_roster_entries(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Alive, 5),
        ]);
        adm.update_roster(&new_roster);

        // Now peer 2 is accepted
        assert!(adm.admit(2, 5).is_ok());
        assert_eq!(adm.roster_len(), 2);
    }

    #[test]
    fn roster_update_peer_removed_mid_session() {
        let roster = make_roster_entries(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Alive, 5),
        ]);
        let mut adm = ConnectionAdmission::with_roster(roster);

        // Both peers accepted initially
        assert!(adm.admit(1, 5).is_ok());
        assert!(adm.admit(2, 5).is_ok());

        // Peer 2 leaves the roster
        let new_roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        adm.update_roster(&new_roster);

        // Peer 1 still accepted, peer 2 now rejected
        assert!(adm.admit(1, 5).is_ok());
        assert_eq!(
            adm.admit(2, 5).unwrap_err(),
            AdmissionRejection::NotInRoster
        );
        assert_eq!(adm.roster_len(), 1);
    }

    #[test]
    fn roster_update_state_change_draining() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        assert!(adm.admit(1, 5).is_ok());

        // Peer transitions to Drained
        let new_roster = make_roster_entries(&[(1, RosterPeerState::Drained, 5)]);
        adm.update_roster(&new_roster);
        assert_eq!(
            adm.admit(1, 5).unwrap_err(),
            AdmissionRejection::PeerDrained
        );
    }

    // -------------------------------------------------------------------
    // set_roster convenience method
    // -------------------------------------------------------------------

    #[test]
    fn set_roster_replaces_completely() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        assert_eq!(adm.roster_len(), 1);

        let new_roster = make_roster_entries(&[
            (10, RosterPeerState::Alive, 6),
            (20, RosterPeerState::Alive, 6),
        ]);
        adm.set_roster(new_roster);
        assert_eq!(adm.roster_len(), 2);
        assert!(adm.admit(1, 5).is_err()); // old peer gone
        assert!(adm.admit(10, 6).is_ok());
        assert!(adm.admit(20, 6).is_ok());
    }

    // -------------------------------------------------------------------
    // admit_with_frame
    // -------------------------------------------------------------------

    #[test]
    fn admit_with_frame_accepted() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        assert!(adm.admit_with_frame(1, 5).is_ok());
    }

    #[test]
    fn admit_with_frame_rejected_produces_frame() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        let frame = adm.admit_with_frame(42, 5).unwrap_err();
        assert_eq!(frame.peer_id, 42);
        assert_eq!(frame.reason, AdmissionRejection::NotInRoster);
    }

    // -------------------------------------------------------------------
    // Multi-peer roster: accept/reject isolation
    // -------------------------------------------------------------------

    #[test]
    fn multi_peer_accept_alive_reject_others_connection_admission() {
        let roster = make_roster_entries(&[
            (1, RosterPeerState::Alive, 5),
            (2, RosterPeerState::Suspected, 5),
            (3, RosterPeerState::Drained, 5),
            (4, RosterPeerState::Failed, 5),
        ]);
        let adm = ConnectionAdmission::with_roster(roster);

        assert!(adm.admit(1, 5).is_ok());
        assert_eq!(
            adm.admit(2, 5).unwrap_err(),
            AdmissionRejection::PeerSuspected
        );
        assert_eq!(
            adm.admit(3, 5).unwrap_err(),
            AdmissionRejection::PeerDrained
        );
        assert_eq!(
            adm.admit(4, 5).unwrap_err(),
            AdmissionRejection::PeerDrained
        );
    }
    // ===================================================================
    // ConnectionAdmissionSubscriber tests
    // ===================================================================

    use std::sync::{Arc, Mutex};

    /// A test subscriber that records rejection events into a shared buffer.
    struct TestSubscriber {
        events: Arc<Mutex<Vec<ConnectionAdmissionEvent>>>,
    }

    impl TestSubscriber {
        fn new() -> (Self, Arc<Mutex<Vec<ConnectionAdmissionEvent>>>) {
            let events = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    events: events.clone(),
                },
                events,
            )
        }
    }

    impl ConnectionAdmissionSubscriber for TestSubscriber {
        fn on_admission_rejected(&self, event: &ConnectionAdmissionEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    #[test]
    fn subscriber_notified_on_rejection() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub, events) = TestSubscriber::new();
        adm.subscribe(Box::new(sub));

        let result = adm.admit(42, 5);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AdmissionRejection::NotInRoster);

        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].peer_id, 42);
        assert_eq!(recorded[0].claimed_epoch, 5);
        assert_eq!(recorded[0].reason, AdmissionRejection::NotInRoster);
        assert_eq!(recorded[0].closure_class(), ClosureClass::RefusedPolicy);
        assert_eq!(recorded[0].drain_result_class(), DrainResultClass::Force);
        assert_eq!(
            recorded[0].closure_receipt.session_ref,
            TransportSessionId::ZERO
        );
        assert_eq!(recorded[0].closure_receipt.last_seq_acked, 0);
        assert_eq!(
            recorded[0].closure_receipt.trigger_ref,
            AdmissionRejection::NotInRoster.trigger_ref()
        );
    }

    #[test]
    fn subscriber_not_notified_on_accept() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub, events) = TestSubscriber::new();
        adm.subscribe(Box::new(sub));

        let result = adm.admit(1, 5);
        assert!(result.is_ok());
        assert!(events.lock().unwrap().is_empty());
    }

    #[test]
    fn multiple_subscribers_all_notified() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub1, events1) = TestSubscriber::new();
        let (sub2, events2) = TestSubscriber::new();
        adm.subscribe(Box::new(sub1));
        adm.subscribe(Box::new(sub2));

        let _ = adm.admit(99, 5);
        assert_eq!(events1.lock().unwrap().len(), 1);
        assert_eq!(events2.lock().unwrap().len(), 1);
    }

    #[test]
    fn subscriber_notified_on_admit_with_frame_rejection() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub, events) = TestSubscriber::new();
        adm.subscribe(Box::new(sub));

        let result = adm.admit_with_frame(42, 5);
        assert!(result.is_err());
        let recorded = events.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].peer_id, 42);
        assert_eq!(recorded[0].reason, AdmissionRejection::NotInRoster);
        assert_eq!(
            recorded[0].closure_receipt.closure_class,
            ClosureClass::RefusedPolicy
        );
    }

    #[test]
    fn subscriber_sees_rejection_reason() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Suspected, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub, events) = TestSubscriber::new();
        adm.subscribe(Box::new(sub));

        let err = adm.admit(1, 5).unwrap_err();
        assert_eq!(err, AdmissionRejection::PeerSuspected);
        let recorded = events.lock().unwrap();
        assert_eq!(recorded[0].reason, AdmissionRejection::PeerSuspected);
    }

    #[test]
    fn empty_subscribers_no_panic() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let adm = ConnectionAdmission::with_roster(roster);
        // No subscribers registered — should not panic
        let result = adm.admit(42, 5);
        assert!(result.is_err());
    }

    #[test]
    fn clone_drops_subscribers() {
        let roster = make_roster_entries(&[(1, RosterPeerState::Alive, 5)]);
        let mut adm = ConnectionAdmission::with_roster(roster);
        let (sub, events) = TestSubscriber::new();
        adm.subscribe(Box::new(sub));

        let cloned = adm.clone();
        // Original still has subscribers
        let _ = adm.admit(42, 5);
        assert_eq!(events.lock().unwrap().len(), 1);

        // Clone has no subscribers — should not panic
        let result = cloned.admit(42, 5);
        assert!(result.is_err());
        // Subscriber not notified via clone (events still = 1)
        assert_eq!(events.lock().unwrap().len(), 1);
    }
}
