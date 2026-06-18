// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport peer manager: membership-driven connection lifecycle and per-peer
//! session routing.
//!
//! [`PeerManager`] subscribes to membership events (node join/leave/fail, epoch
//! transitions) and drives the transport session lifecycle for each known peer:
//! establishing sessions to newly-joined nodes, tearing down sessions to
//! departed/failed nodes, marking sessions stale on epoch transitions, and
//! routing outbound messages to the correct peer session by node identity.
//!
//! # Architecture
//!
//! - [`MembershipEvent`]: Five event variants the upstream membership runtime
//!   feeds into the peer manager.
//! - [`MembershipEventSink`]: Trait defining the contract for membership event
//!   consumers. Transport defines it; `tidefs-membership-live` implements the
//!   bridge.
//! - [`PeerState`]: Five-state machine per peer: `Disconnected` →
//!   `Connecting` → `Connected` → `Stale` → `Draining` → `Disconnected`.
//! - [`PeerManager`]: Owns the peer table and enforces state transitions.
//! - [`PeerManagerHandle`]: Cloneable, `Send + Sync` handle for subsystem use.
//!
//! # Data Integrity
//!
//! Every state mutation updates a BLAKE3-256 peer-set digest with domain
//! separation `"tidefs-transport-peer-manager-v1"`. The digest covers all
//! `(node_id, state)` pairs in canonical node-id order, providing
//! tamper-proof state verification. Replayed or out-of-order membership
//! events are detected through state-machine transition validation — invalid
//! transitions are rejected with [`PeerManagerError::InvalidTransition`].

use blake3::Hasher;
use std::collections::BTreeMap;

use crate::types::SessionId;

// ---------------------------------------------------------------------------
// Membership event types (defined in transport so membership-live can feed
// events without transport depending on membership-live)
// ---------------------------------------------------------------------------

/// Events from the membership runtime that drive peer-manager state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipEvent {
    /// A new node has joined the cluster. `node_id` is the joining node.
    NodeJoined { node_id: u64 },
    /// A node has started graceful draining. The peer manager transitions
    /// the peer to Draining state so existing sessions can flush and
    /// complete state transfer before final teardown.
    NodeDraining { node_id: u64 },
    /// A node has gracefully left the cluster.
    NodeLeft { node_id: u64 },
    /// A node has been detected as failed (SWIM suspicion confirmed).
    NodeFailed { node_id: u64 },
    /// The membership epoch has advanced. All connected peers must be
    /// marked stale until re-verified.
    EpochTransition { new_epoch: u64 },
}

/// Trait for consumers of membership events.
///
/// Transport defines this trait so that `tidefs-membership-live` can push
/// events into the peer manager without creating a circular dependency.
pub trait MembershipEventSink: Send + Sync {
    /// Process a membership event. Returns an error if the event would cause
    /// an invalid state transition.
    fn on_membership_event(&mut self, event: MembershipEvent) -> Result<(), PeerManagerError>;
}

// ---------------------------------------------------------------------------
// Peer state machine
// ---------------------------------------------------------------------------

/// Per-peer connection lifecycle state.
///
/// ```text
/// Disconnected ──[join]──▶ Connecting ──[establish]──▶ Connected ──[epoch]──▶ Stale
///      ▲                      │                          │                        │
///      │                      ▼                          ▼                        ▼
///      ◀─────[teardown]── Draining ◀──[fail/leave]──    ...              [reverify]──▶ Connected
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerState {
    /// No session exists for this peer. Initial state.
    Disconnected,
    /// Session establishment is in progress.
    Connecting,
    /// Session is established and healthy.
    Connected,
    /// Epoch transition occurred; session needs reverification before reuse.
    Stale,
    /// Session is gracefully draining; no new messages accepted.
    Draining,
}

impl PeerState {
    /// Returns `true` if the peer can accept outbound messages.
    pub fn is_ready(&self) -> bool {
        matches!(self, PeerState::Connected)
    }

    /// Returns `true` if outbound messages should be rejected.
    pub fn is_blocked(&self) -> bool {
        matches!(self, PeerState::Disconnected | PeerState::Draining)
    }
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Disconnected => write!(f, "Disconnected"),
            PeerState::Connecting => write!(f, "Connecting"),
            PeerState::Connected => write!(f, "Connected"),
            PeerState::Stale => write!(f, "Stale"),
            PeerState::Draining => write!(f, "Draining"),
        }
    }
}

// ---------------------------------------------------------------------------
// Peer entry
// ---------------------------------------------------------------------------

/// Tracks state and session binding for a single peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEntry {
    /// Node identifier for this peer.
    pub node_id: u64,
    /// Current connection lifecycle state.
    pub state: PeerState,
    /// Session bound to this peer, if any.
    pub session_id: Option<SessionId>,
    /// Epoch at which this peer was last verified.
    pub last_epoch: u64,
}

impl PeerEntry {
    /// Create a new peer entry in Disconnected state.
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            state: PeerState::Disconnected,
            session_id: None,
            last_epoch: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer manager
// ---------------------------------------------------------------------------

/// BLAKE3 domain separation string for peer-set digest.
const PEER_MANAGER_DOMAIN: &str = "tidefs-transport-peer-manager-v1";

/// Errors returned by peer manager operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerManagerError {
    /// The requested peer is not known to the manager.
    UnknownPeer { node_id: u64 },
    /// The requested state transition is invalid given the current state.
    InvalidTransition {
        node_id: u64,
        from: PeerState,
        event: MembershipEvent,
    },
    /// The peer is not in a state that accepts messages.
    NotReady { node_id: u64, state: PeerState },
    /// Attempted to establish a session for an already-connected peer.
    AlreadyConnected { node_id: u64 },
}

impl std::fmt::Display for PeerManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerManagerError::UnknownPeer { node_id } => {
                write!(f, "unknown peer: node_id={node_id}")
            }
            PeerManagerError::InvalidTransition {
                node_id,
                from,
                event,
            } => {
                write!(
                    f,
                    "invalid transition for node_id={node_id}: state={from}, event={event:?}"
                )
            }
            PeerManagerError::NotReady { node_id, state } => {
                write!(f, "peer node_id={node_id} not ready: state={state}")
            }
            PeerManagerError::AlreadyConnected { node_id } => {
                write!(f, "peer node_id={node_id} is already connected")
            }
        }
    }
}

impl std::error::Error for PeerManagerError {}

/// Manages per-peer transport session lifecycle driven by membership events.
///
/// # Example
///
/// ```ignore
/// use tidefs_transport::peer_manager::{PeerManager, MembershipEvent, MembershipEventSink};
///
/// let mut pm = PeerManager::new();
/// pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 7 }).unwrap();
/// assert_eq!(pm.peer_state(7), Some(PeerState::Connecting));
/// ```
#[derive(Debug, Clone)]
pub struct PeerManager {
    /// Peer table keyed by node ID, in canonical order for deterministic digest.
    peers: BTreeMap<u64, PeerEntry>,
    /// Current membership epoch.
    current_epoch: u64,
}

impl PeerManager {
    /// Create an empty peer manager.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            current_epoch: 0,
        }
    }

    /// Return the peer table (for testing and inspection).
    pub fn peers(&self) -> &BTreeMap<u64, PeerEntry> {
        &self.peers
    }

    /// Return the state of a specific peer, or `None` if unknown.
    pub fn peer_state(&self, node_id: u64) -> Option<PeerState> {
        self.peers.get(&node_id).map(|e| e.state)
    }

    /// Return the session ID bound to a peer, or `None`.
    pub fn peer_session(&self, node_id: u64) -> Option<SessionId> {
        self.peers.get(&node_id).and_then(|e| e.session_id)
    }

    /// Current membership epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    // -----------------------------------------------------------------------
    // State transitions (public for testing; normally driven by events)
    // -----------------------------------------------------------------------

    /// Start session establishment for a peer.
    ///
    /// Valid from: `Connecting` or `Stale`.
    /// Transitions to: `Connected`.
    pub fn establish_session(
        &mut self,
        node_id: u64,
        session_id: SessionId,
    ) -> Result<(), PeerManagerError> {
        let entry = self
            .peers
            .get_mut(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;

        match entry.state {
            PeerState::Connecting | PeerState::Stale => {
                entry.state = PeerState::Connected;
                entry.session_id = Some(session_id);
                entry.last_epoch = self.current_epoch;
                Ok(())
            }
            PeerState::Connected => Err(PeerManagerError::AlreadyConnected { node_id }),
            other => Err(PeerManagerError::InvalidTransition {
                node_id,
                from: other,
                event: MembershipEvent::NodeJoined { node_id },
            }),
        }
    }

    /// Begin graceful teardown of a peer session.
    ///
    /// Valid from: `Connected` or `Stale`.
    /// Transitions to: `Draining`.
    pub fn begin_teardown(&mut self, node_id: u64) -> Result<(), PeerManagerError> {
        let entry = self
            .peers
            .get_mut(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;

        match entry.state {
            PeerState::Connected | PeerState::Stale => {
                entry.state = PeerState::Draining;
                Ok(())
            }
            other => Err(PeerManagerError::InvalidTransition {
                node_id,
                from: other,
                event: MembershipEvent::NodeLeft { node_id },
            }),
        }
    }

    /// Complete teardown: transition from Draining to Disconnected.
    pub fn complete_teardown(&mut self, node_id: u64) -> Result<(), PeerManagerError> {
        let entry = self
            .peers
            .get_mut(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;

        if entry.state != PeerState::Draining {
            return Err(PeerManagerError::InvalidTransition {
                node_id,
                from: entry.state,
                event: MembershipEvent::NodeLeft { node_id },
            });
        }

        entry.state = PeerState::Disconnected;
        entry.session_id = None;
        Ok(())
    }

    /// Mark a session as stale (epoch transition).
    ///
    /// Valid from: `Connected`.
    /// Transitions to: `Stale`.
    pub fn mark_stale(&mut self, node_id: u64) -> Result<(), PeerManagerError> {
        let entry = self
            .peers
            .get_mut(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;

        if entry.state != PeerState::Connected {
            return Err(PeerManagerError::InvalidTransition {
                node_id,
                from: entry.state,
                event: MembershipEvent::EpochTransition {
                    new_epoch: self.current_epoch,
                },
            });
        }

        entry.state = PeerState::Stale;
        Ok(())
    }

    /// Reverify a stale session, moving it back to Connected.
    pub fn reverify(&mut self, node_id: u64) -> Result<(), PeerManagerError> {
        let entry = self
            .peers
            .get_mut(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;

        if entry.state != PeerState::Stale {
            return Err(PeerManagerError::InvalidTransition {
                node_id,
                from: entry.state,
                event: MembershipEvent::NodeJoined { node_id },
            });
        }

        entry.state = PeerState::Connected;
        entry.last_epoch = self.current_epoch;
        Ok(())
    }

    /// Check if a peer is ready to accept outbound messages.
    pub fn is_ready(&self, node_id: u64) -> bool {
        self.peers
            .get(&node_id)
            .map(|e| e.state.is_ready())
            .unwrap_or(false)
    }

    /// Route an outbound message to a peer: resolve the peer's session ID.
    ///
    /// Returns  if the peer is known and in  state.
    /// Returns  if the peer is unknown.
    /// Returns  if the peer exists but is
    /// not in a state that accepts outbound messages (e.g. Disconnected,
    /// Connecting, Stale, or Draining).
    pub fn route_message(&self, node_id: u64) -> Result<SessionId, PeerManagerError> {
        let entry = self
            .peers
            .get(&node_id)
            .ok_or(PeerManagerError::UnknownPeer { node_id })?;
        if entry.state.is_ready() {
            entry.session_id.ok_or(PeerManagerError::NotReady {
                node_id,
                state: entry.state,
            })
        } else {
            Err(PeerManagerError::NotReady {
                node_id,
                state: entry.state,
            })
        }
    }

    /// Compute the BLAKE3-256 peer-set digest over all (node_id, state) pairs
    /// in canonical order. Used for tamper-proof state verification.
    pub fn compute_peer_set_digest(&self) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(PEER_MANAGER_DOMAIN);
        // Canonical ordering via BTreeMap iteration
        for (node_id, entry) in &self.peers {
            hasher.update(&node_id.to_le_bytes());
            hasher.update(&[entry.state as u8]);
            hasher.update(&entry.last_epoch.to_le_bytes());
        }
        // Also include current_epoch in the digest
        hasher.update(&self.current_epoch.to_le_bytes());
        hasher.finalize().into()
    }

    /// Return the number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Return the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|e| e.state == PeerState::Connected)
            .count()
    }

    // -----------------------------------------------------------------------
    // Member / event helpers
    // -----------------------------------------------------------------------

    fn ensure_peer(&mut self, node_id: u64) {
        self.peers
            .entry(node_id)
            .or_insert_with(|| PeerEntry::new(node_id));
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MembershipEventSink for PeerManager {
    fn on_membership_event(&mut self, event: MembershipEvent) -> Result<(), PeerManagerError> {
        match event {
            MembershipEvent::NodeJoined { node_id } => {
                self.ensure_peer(node_id);
                let entry = self.peers.get_mut(&node_id).unwrap();
                match entry.state {
                    PeerState::Disconnected => {
                        entry.state = PeerState::Connecting;
                        Ok(())
                    }
                    PeerState::Draining => {
                        // Node re-joined while draining; restart connection
                        entry.state = PeerState::Connecting;
                        Ok(())
                    }
                    PeerState::Connecting | PeerState::Connected | PeerState::Stale => {
                        Err(PeerManagerError::InvalidTransition {
                            node_id,
                            from: entry.state,
                            event,
                        })
                    }
                }
            }
            MembershipEvent::NodeDraining { node_id } => {
                let entry = self
                    .peers
                    .get_mut(&node_id)
                    .ok_or(PeerManagerError::UnknownPeer { node_id })?;
                match entry.state {
                    PeerState::Connected | PeerState::Stale | PeerState::Connecting => {
                        // Transition to Draining to begin graceful teardown.
                        // The session is kept alive so in-flight messages and
                        // state transfer chunks can complete.
                        entry.state = PeerState::Draining;
                        Ok(())
                    }
                    PeerState::Disconnected | PeerState::Draining => {
                        // Already gone or already draining — idempotent.
                        Ok(())
                    }
                }
            }
            MembershipEvent::NodeLeft { node_id } => {
                let entry = self
                    .peers
                    .get_mut(&node_id)
                    .ok_or(PeerManagerError::UnknownPeer { node_id })?;
                match entry.state {
                    PeerState::Connected | PeerState::Stale => {
                        entry.state = PeerState::Draining;
                        Ok(())
                    }
                    PeerState::Connecting => {
                        // Was still connecting; abort to disconnected
                        entry.state = PeerState::Disconnected;
                        entry.session_id = None;
                        Ok(())
                    }
                    PeerState::Disconnected | PeerState::Draining => {
                        Err(PeerManagerError::InvalidTransition {
                            node_id,
                            from: entry.state,
                            event,
                        })
                    }
                }
            }
            MembershipEvent::NodeFailed { node_id } => {
                let entry = self
                    .peers
                    .get_mut(&node_id)
                    .ok_or(PeerManagerError::UnknownPeer { node_id })?;
                match entry.state {
                    PeerState::Connected | PeerState::Stale | PeerState::Connecting => {
                        // Fast path: no drain for failed nodes
                        entry.state = PeerState::Disconnected;
                        entry.session_id = None;
                        Ok(())
                    }
                    PeerState::Disconnected | PeerState::Draining => {
                        // Already gone
                        Ok(())
                    }
                }
            }
            MembershipEvent::EpochTransition { new_epoch } => {
                self.current_epoch = new_epoch;
                // Mark all Connected peers as Stale
                for (_, entry) in self.peers.iter_mut() {
                    if entry.state == PeerState::Connected {
                        entry.state = PeerState::Stale;
                    }
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cloneable handle for subsystem use
// ---------------------------------------------------------------------------

/// Cloneable, `Send + Sync` handle to the peer manager.
///
/// Wraps the peer manager in an `Arc<Mutex<...>>` so multiple subsystems
/// (message dispatch, keepalive, session management) can share access.
pub type PeerManagerHandle = std::sync::Arc<std::sync::Mutex<PeerManager>>;

/// Create a new `PeerManagerHandle`.
pub fn new_peer_manager_handle() -> PeerManagerHandle {
    std::sync::Arc::new(std::sync::Mutex::new(PeerManager::new()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- PeerState display ---

    #[test]
    fn peer_state_display() {
        assert_eq!(format!("{}", PeerState::Disconnected), "Disconnected");
        assert_eq!(format!("{}", PeerState::Connecting), "Connecting");
        assert_eq!(format!("{}", PeerState::Connected), "Connected");
        assert_eq!(format!("{}", PeerState::Stale), "Stale");
        assert_eq!(format!("{}", PeerState::Draining), "Draining");
    }

    // --- PeerState helpers ---

    #[test]
    fn peer_state_is_ready() {
        assert!(!PeerState::Disconnected.is_ready());
        assert!(!PeerState::Connecting.is_ready());
        assert!(PeerState::Connected.is_ready());
        assert!(!PeerState::Stale.is_ready());
        assert!(!PeerState::Draining.is_ready());
    }

    #[test]
    fn peer_state_is_blocked() {
        assert!(PeerState::Disconnected.is_blocked());
        assert!(!PeerState::Connecting.is_blocked());
        assert!(!PeerState::Connected.is_blocked());
        assert!(!PeerState::Stale.is_blocked());
        assert!(PeerState::Draining.is_blocked());
    }

    // --- PeerManager basic lifecycle ---

    #[test]
    fn new_peer_manager_is_empty() {
        let pm = PeerManager::new();
        assert_eq!(pm.peer_count(), 0);
        assert_eq!(pm.connected_count(), 0);
        assert_eq!(pm.current_epoch(), 0);
    }

    #[test]
    fn node_joined_transitions_to_connecting() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Connecting));
        assert_eq!(pm.peer_count(), 1);
        assert_eq!(pm.connected_count(), 0);
    }

    #[test]
    fn duplicate_join_rejected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        let err = pm
            .on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap_err();
        assert!(matches!(err, PeerManagerError::InvalidTransition { .. }));
    }

    #[test]
    fn establish_session_connects_peer() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Connected));
        assert_eq!(pm.peer_session(1), Some(SessionId(42)));
        assert_eq!(pm.connected_count(), 1);
    }

    #[test]
    fn establish_session_unknown_peer_rejected() {
        let mut pm = PeerManager::new();
        let err = pm.establish_session(99, SessionId(1)).unwrap_err();
        assert!(matches!(err, PeerManagerError::UnknownPeer { node_id: 99 }));
    }

    #[test]
    fn establish_session_on_already_connected_rejected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        let err = pm.establish_session(1, SessionId(99)).unwrap_err();
        assert!(matches!(
            err,
            PeerManagerError::AlreadyConnected { node_id: 1 }
        ));
    }

    #[test]
    fn node_left_drains_connected_peer() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.on_membership_event(MembershipEvent::NodeLeft { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Draining));
    }

    #[test]
    fn node_left_aborts_connecting_peer() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.on_membership_event(MembershipEvent::NodeLeft { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Disconnected));
        assert_eq!(pm.peer_session(1), None);
    }

    #[test]
    fn node_failed_disconnects_immediately() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Disconnected));
        assert_eq!(pm.peer_session(1), None);
    }

    #[test]
    fn node_failed_on_connecting_cleans_up() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Disconnected));
    }

    #[test]
    fn node_failed_on_already_disconnected_is_noop() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 1 })
            .unwrap();
        // Second fail on disconnected peer should succeed (noop)
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Disconnected));
    }

    #[test]
    fn complete_teardown_from_draining() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.begin_teardown(1).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Draining));
        pm.complete_teardown(1).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Disconnected));
        assert_eq!(pm.peer_session(1), None);
    }

    #[test]
    fn complete_teardown_not_draining_rejected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        // Peer is Connected, not Draining
        let err = pm.complete_teardown(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::InvalidTransition { .. }));
    }

    // --- Epoch transitions ---

    #[test]
    fn epoch_transition_marks_all_connected_as_stale() {
        let mut pm = PeerManager::new();
        for id in 1..=3 {
            pm.on_membership_event(MembershipEvent::NodeJoined { node_id: id })
                .unwrap();
            pm.establish_session(id, SessionId(id * 10)).unwrap();
        }
        pm.on_membership_event(MembershipEvent::EpochTransition { new_epoch: 5 })
            .unwrap();
        assert_eq!(pm.current_epoch(), 5);
        for id in 1..=3 {
            assert_eq!(pm.peer_state(id), Some(PeerState::Stale));
        }
    }

    #[test]
    fn stale_peer_can_be_reverified() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.mark_stale(1).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Stale));
        pm.reverify(1).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Connected));
        assert_eq!(pm.peer_session(1), Some(SessionId(42)));
    }

    #[test]
    fn stale_peer_can_establish() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.mark_stale(1).unwrap();
        // establish_session also works from Stale
        pm.establish_session(1, SessionId(99)).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Connected));
        assert_eq!(pm.peer_session(1), Some(SessionId(99)));
    }

    // --- BLAKE3 digest ---

    #[test]
    fn peer_set_digest_changes_on_state_transition() {
        let mut pm = PeerManager::new();
        let d0 = pm.compute_peer_set_digest();

        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        let d1 = pm.compute_peer_set_digest();
        assert_ne!(d0, d1, "digest must change when peer added");

        pm.establish_session(1, SessionId(42)).unwrap();
        let d2 = pm.compute_peer_set_digest();
        assert_ne!(d1, d2, "digest must change on state transition");
    }

    #[test]
    fn peer_set_digest_is_deterministic() {
        let mut pm1 = PeerManager::new();
        let mut pm2 = PeerManager::new();

        // Different insertion order, same final state
        pm1.on_membership_event(MembershipEvent::NodeJoined { node_id: 3 })
            .unwrap();
        pm1.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm1.on_membership_event(MembershipEvent::NodeJoined { node_id: 2 })
            .unwrap();
        pm1.establish_session(1, SessionId(10)).unwrap();
        pm1.establish_session(2, SessionId(20)).unwrap();
        pm1.establish_session(3, SessionId(30)).unwrap();

        pm2.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm2.on_membership_event(MembershipEvent::NodeJoined { node_id: 2 })
            .unwrap();
        pm2.on_membership_event(MembershipEvent::NodeJoined { node_id: 3 })
            .unwrap();
        pm2.establish_session(1, SessionId(10)).unwrap();
        pm2.establish_session(2, SessionId(20)).unwrap();
        pm2.establish_session(3, SessionId(30)).unwrap();

        // Insertion order shouldn't matter because BTreeMap sorts by key
        assert_eq!(pm1.compute_peer_set_digest(), pm2.compute_peer_set_digest());
    }

    #[test]
    fn peer_set_digest_includes_epoch() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();

        let d1 = pm.compute_peer_set_digest();
        pm.on_membership_event(MembershipEvent::EpochTransition { new_epoch: 7 })
            .unwrap();
        let d2 = pm.compute_peer_set_digest();
        assert_ne!(d1, d2, "digest must change on epoch transition");
    }

    // --- is_ready / routing helpers ---

    #[test]
    fn is_ready_true_only_for_connected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        assert!(!pm.is_ready(1));

        pm.establish_session(1, SessionId(42)).unwrap();
        assert!(pm.is_ready(1));

        pm.mark_stale(1).unwrap();
        assert!(!pm.is_ready(1));

        pm.on_membership_event(MembershipEvent::NodeLeft { node_id: 1 })
            .unwrap();
        assert!(!pm.is_ready(1));
    }

    #[test]
    fn is_ready_unknown_peer_returns_false() {
        let pm = PeerManager::new();
        assert!(!pm.is_ready(99));
    }

    // --- PeerManagerHandle ---

    #[test]
    fn handle_clone_and_share() {
        let h1 = new_peer_manager_handle();
        let h2 = h1.clone();

        {
            let mut pm = h1.lock().unwrap();
            pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 5 })
                .unwrap();
        }

        {
            let pm = h2.lock().unwrap();
            assert_eq!(pm.peer_state(5), Some(PeerState::Connecting));
        }
    }

    // --- Node re-join while draining ---

    #[test]
    fn rejoin_while_draining_restarts_connection() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.on_membership_event(MembershipEvent::NodeLeft { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Draining));

        // Node comes back
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Connecting));
    }

    // --- Error display ---

    #[test]
    fn error_display() {
        let e = PeerManagerError::UnknownPeer { node_id: 42 };
        assert!(format!("{e}").contains("42"));

        let e = PeerManagerError::NotReady {
            node_id: 7,
            state: PeerState::Draining,
        };
        assert!(format!("{e}").contains("7"));
        assert!(format!("{e}").contains("Draining"));

        let e = PeerManagerError::AlreadyConnected { node_id: 99 };
        assert!(format!("{e}").contains("99"));

        let e = PeerManagerError::InvalidTransition {
            node_id: 1,
            from: PeerState::Connected,
            event: MembershipEvent::NodeJoined { node_id: 1 },
        };
        let s = format!("{e}");
        assert!(s.contains("1"));
        assert!(s.contains("Connected"));
    }

    // --- Default impl ---

    #[test]
    fn default_creates_empty() {
        let pm = PeerManager::default();
        assert_eq!(pm.peer_count(), 0);
        assert_eq!(pm.current_epoch(), 0);
    }

    // --- begin_teardown on stale ---

    #[test]
    fn begin_teardown_from_stale() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.mark_stale(1).unwrap();
        pm.begin_teardown(1).unwrap();
        assert_eq!(pm.peer_state(1), Some(PeerState::Draining));
    }

    // --- begin_teardown on disconnected rejected ---

    #[test]
    fn begin_teardown_from_disconnected_rejected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.on_membership_event(MembershipEvent::NodeLeft { node_id: 1 })
            .unwrap();
        // Now disconnected
        let err = pm.begin_teardown(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::InvalidTransition { .. }));
    }

    // --- NodeFailed on unknown peer ---

    #[test]
    fn node_failed_unknown_peer_error() {
        let mut pm = PeerManager::new();
        let err = pm
            .on_membership_event(MembershipEvent::NodeFailed { node_id: 99 })
            .unwrap_err();
        assert!(matches!(err, PeerManagerError::UnknownPeer { node_id: 99 }));
    }

    // --- NodeLeft on unknown peer ---

    #[test]
    fn node_left_unknown_peer_error() {
        let mut pm = PeerManager::new();
        let err = pm
            .on_membership_event(MembershipEvent::NodeLeft { node_id: 99 })
            .unwrap_err();
        assert!(matches!(err, PeerManagerError::UnknownPeer { node_id: 99 }));
    }

    // --- Epoch transition preserves non-connected peers ---

    #[test]
    fn epoch_transition_preserves_non_connected() {
        let mut pm = PeerManager::new();
        // Peer 1: connected
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(10)).unwrap();
        // Peer 2: just joined (connecting)
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 2 })
            .unwrap();
        // Peer 3: disconnected after teardown
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 3 })
            .unwrap();
        pm.establish_session(3, SessionId(30)).unwrap();
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 3 })
            .unwrap();

        pm.on_membership_event(MembershipEvent::EpochTransition { new_epoch: 3 })
            .unwrap();

        // Connected -> Stale
        assert_eq!(pm.peer_state(1), Some(PeerState::Stale));
        // Connecting stays Connecting
        assert_eq!(pm.peer_state(2), Some(PeerState::Connecting));
        // Disconnected stays Disconnected
        assert_eq!(pm.peer_state(3), Some(PeerState::Disconnected));
    }

    // --- route_message ---

    #[test]
    fn route_message_returns_session_id_when_connected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        let sid = pm.route_message(1).unwrap();
        assert_eq!(sid, SessionId(42));
    }

    #[test]
    fn route_message_unknown_peer_error() {
        let pm = PeerManager::new();
        let err = pm.route_message(99).unwrap_err();
        assert!(matches!(err, PeerManagerError::UnknownPeer { node_id: 99 }));
    }

    #[test]
    fn route_message_not_ready_when_connecting() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        // Still Connecting, not Connected
        let err = pm.route_message(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::NotReady { .. }));
    }

    #[test]
    fn route_message_not_ready_when_disconnected() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.on_membership_event(MembershipEvent::NodeFailed { node_id: 1 })
            .unwrap();
        // Now Disconnected
        let err = pm.route_message(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::NotReady { .. }));
    }

    #[test]
    fn route_message_not_ready_when_stale() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.mark_stale(1).unwrap();
        let err = pm.route_message(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::NotReady { .. }));
    }

    #[test]
    fn route_message_not_ready_when_draining() {
        let mut pm = PeerManager::new();
        pm.on_membership_event(MembershipEvent::NodeJoined { node_id: 1 })
            .unwrap();
        pm.establish_session(1, SessionId(42)).unwrap();
        pm.begin_teardown(1).unwrap();
        let err = pm.route_message(1).unwrap_err();
        assert!(matches!(err, PeerManagerError::NotReady { .. }));
    }

    #[test]
    fn route_message_with_multiple_peers_routes_correctly() {
        let mut pm = PeerManager::new();
        for id in 1..=3 {
            pm.on_membership_event(MembershipEvent::NodeJoined { node_id: id })
                .unwrap();
            pm.establish_session(id, SessionId(id * 10)).unwrap();
        }
        // Peer 2 is Connected
        assert_eq!(pm.route_message(2).unwrap(), SessionId(20));

        // Drain peer 2
        pm.begin_teardown(2).unwrap();
        let err = pm.route_message(2).unwrap_err();
        assert!(matches!(err, PeerManagerError::NotReady { .. }));

        // Peer 3 still routes correctly
        assert_eq!(pm.route_message(3).unwrap(), SessionId(30));
    }
}
