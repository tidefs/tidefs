// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Transport wiring for the P8-02 live membership runtime.
//!
//! Connects `MembershipRuntime` (SWIM failure detection + 3-phase epoch
//! transitions) to the `tidefs-transport` layer so that membership protocol
//! messages flow over TCP sessions between cluster nodes.
//!
//! ## Architecture
//!
//! - `MembershipWireMessage`: bincode-wire enum for all protocol messages
//!   (SWIM ping/ack/indirect + epoch transition propose/accept/commit).
//! - `send_membership_msg` / `recv_membership_msg`: typed send/recv over
//!   an established Transport session.
//! - `MembershipTransport`: session manager that maps `MemberId` → `SessionId`
//!   and provides convenience methods for each protocol message kind.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use bincode;
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::MemberId;
use tidefs_transport::epoch_fence::{
    CommittedEpochEvidence, CommittedEpochSnapshot, EpochTransition, ReconnectAdmission,
    ReconnectEvidenceFailure,
};
use tidefs_transport::{NodeInfo, SessionCloseReason, SessionId, Transport, TransportError};

use crate::gossip::GossipMessage;
use crate::runtime::{MembershipRuntime, RuntimeTickResult};
use crate::types::{
    EpochTransitionAccept, EpochTransitionCommit, EpochTransitionProposal, MembershipView, SwimAck,
    SwimIndirectPingRequest, SwimIndirectPingResponse, SwimPing,
};

// ---------------------------------------------------------------------------
// MembershipWireMessage — the on-wire protocol envelope
// ---------------------------------------------------------------------------

/// A single wire-level message in the membership protocol.
///
/// Serialized with `bincode` and sent as opaque frames over the Transport
/// layer (`send_message` / `recv_message`). Every variant maps 1:1 to a
/// P8-02 membership protocol message type.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum MembershipWireMessage {
    /// SWIM direct ping.
    Ping(SwimPing),
    /// SWIM ack (response to direct ping).
    Ack(SwimAck),
    /// SWIM indirect ping request (forwarded to k random peers).
    IndirectPingRequest(SwimIndirectPingRequest),
    /// SWIM indirect ping response.
    IndirectPingResponse(SwimIndirectPingResponse),
    /// Epoch transition proposal (Phase 1).
    Proposal(EpochTransitionProposal),
    /// Epoch transition accept (Phase 2).
    Accept(EpochTransitionAccept),
    /// Epoch transition commit (Phase 3).
    Commit(EpochTransitionCommit),
    /// Epoch-sequenced membership view snapshot.
    View(MembershipView),
    /// Epidemic gossip broadcast message for cross-node dissemination.
    GossipBroadcast(GossipMessage),
}

/// Result of ticking a runtime and dispatching generated wire messages.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MembershipTransportTickResult {
    pub pings_sent: usize,
    pub ping_send_failures: usize,
    pub runtime_pings_generated: usize,
}

// ---------------------------------------------------------------------------
// Typed send / recv helpers
// ---------------------------------------------------------------------------

/// Send a structured membership message over an established transport session.
///
/// # Errors
///
/// Returns `TransportError` if serialization or frame I/O fails.
pub fn send_membership_msg(
    transport: &mut Transport,
    session_id: SessionId,
    msg: &MembershipWireMessage,
) -> Result<(), TransportError> {
    let payload = bincode::serialize(msg)
        .map_err(|e| TransportError::Generic(format!("membership serialize: {e}")))?;
    transport.send_message(session_id, &payload)
}

/// Receive a structured membership message over an established transport session.
///
/// # Errors
///
/// Returns `TransportError` if frame I/O or deserialization fails.
pub fn recv_membership_msg(
    transport: &mut Transport,
    session_id: SessionId,
) -> Result<MembershipWireMessage, TransportError> {
    let payload = transport.recv_message(session_id)?;
    bincode::deserialize(&payload)
        .map_err(|e| TransportError::Generic(format!("membership deserialize: {e}")))
}

// ---------------------------------------------------------------------------
// MembershipTransport — session manager for membership protocol I/O
// ---------------------------------------------------------------------------

/// Manages transport sessions for the membership protocol layer.
///
/// Owns a `Transport` and maintains a `MemberId → SessionId` mapping so
/// that the membership runtime can send protocol messages to specific
/// peers without tracking session IDs directly.
pub struct MembershipTransport {
    /// The underlying transport.
    pub transport: Transport,
    /// Peer sessions: `member_id → session_id`.
    pub peer_sessions: BTreeMap<MemberId, SessionId>,
    /// Shared committed membership epoch evidence used by reconnect and
    /// session-recovery admission.
    pub committed_epoch_evidence: Option<CommittedEpochEvidence>,
}

impl MembershipTransport {
    /// Attach an outbound membership roster send gate to the underlying
    /// Transport.
    ///
    /// After this call, every Transport::send_message on this transport
    /// checks the gate and rejects sends targeting peers not in the current
    /// committed roster with TransportError::PeerNotInRoster.
    ///
    /// Call this after constructing the transport and before accepting
    /// connections or dialing peers. Pass the gate obtained from
    /// MembershipRuntime::send_gate().
    pub fn set_send_gate(&mut self, gate: Option<std::sync::Arc<dyn tidefs_transport::SendGate>>) {
        self.transport.set_send_gate(gate);
    }

    /// Attach committed epoch evidence shared with reconnect admission.
    pub fn set_committed_epoch_evidence(&mut self, evidence: CommittedEpochEvidence) {
        self.committed_epoch_evidence = Some(evidence);
    }

    /// Attach an epoch-fence sender to the committed evidence publisher.
    ///
    /// If no evidence cell exists yet, one is created so future committed
    /// publications reach both reconnect admission and [`EpochFence`].
    pub fn set_epoch_fence_sender(
        &mut self,
        sender: tokio::sync::broadcast::Sender<EpochTransition>,
    ) {
        let evidence = self
            .committed_epoch_evidence
            .get_or_insert_with(CommittedEpochEvidence::new);
        evidence.set_fence_sender(sender);
    }

    /// Return a clone of the committed epoch evidence cell, if configured.
    #[must_use]
    pub fn committed_epoch_evidence(&self) -> Option<CommittedEpochEvidence> {
        self.committed_epoch_evidence.clone()
    }

    /// Publish a committed membership epoch into reconnect admission and the
    /// optional transport epoch fence sender.
    ///
    /// The underlying transport's advertised handshake epoch is moved to the
    /// committed epoch before new sessions are accepted or dialed.
    pub fn publish_committed_epoch_view<I>(
        &mut self,
        epoch: u64,
        members: I,
    ) -> Result<CommittedEpochSnapshot, TransportError>
    where
        I: IntoIterator<Item = MemberId>,
    {
        let evidence = self.committed_epoch_evidence.as_ref().ok_or_else(|| {
            Self::admission_error(
                0,
                ReconnectAdmission::EvidenceUnavailable {
                    reason: ReconnectEvidenceFailure::Missing,
                },
            )
        })?;
        let snapshot = evidence.publish(epoch, members.into_iter().map(|member| member.0));
        self.transport.epoch = snapshot.epoch;
        Ok(snapshot)
    }

    /// Create a new membership transport for a node.
    #[must_use]
    pub fn new(local_node_id: u64) -> Self {
        Self {
            transport: Transport::new(local_node_id),
            peer_sessions: BTreeMap::new(),
            committed_epoch_evidence: None,
        }
    }

    /// Bind the transport listener to `addr`.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on bind failure.
    pub fn bind(&mut self, addr: SocketAddr) -> Result<(), TransportError> {
        self.transport
            .bind(tidefs_transport::TransportAddr::Tcp(addr))
    }

    /// Return the locally bound address, if any.
    #[must_use]
    pub fn local_addr(&self) -> Option<tidefs_transport::TransportAddr> {
        self.transport.bind_addr.clone()
    }

    /// Connect to a peer and establish a session for membership protocol I/O.
    ///
    /// Registers the peer node, dials out via TCP, performs the handshake,
    /// and records the session for subsequent typed sends.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on connect or handshake failure.
    pub fn connect_to_peer(
        &mut self,
        peer_node_id: u64,
        addr: SocketAddr,
    ) -> Result<SessionId, TransportError> {
        self.transport.add_node(NodeInfo::new(
            peer_node_id,
            vec![tidefs_transport::TransportAddr::Tcp(addr)],
            0,
        ));

        let session_id = self.transport.connect(peer_node_id)?;
        self.transport.perform_handshake(session_id)?;

        self.peer_sessions
            .insert(MemberId::new(peer_node_id), session_id);

        Ok(session_id)
    }

    /// Connect to a peer admitted by the current committed epoch evidence.
    ///
    /// Missing, lagged, stale, or departed evidence rejects before the
    /// session is exposed as a usable membership transport session.
    pub fn connect_to_peer_at_committed_epoch(
        &mut self,
        peer_node_id: u64,
        addr: SocketAddr,
    ) -> Result<SessionId, TransportError> {
        let snapshot = self.require_peer_admitted_for_new_session(peer_node_id)?;
        self.transport.epoch = snapshot.epoch;

        let session_id = self.connect_to_peer(peer_node_id, addr)?;
        if let Err(err) = self.bind_peer_session_to_committed_epoch(peer_node_id, session_id) {
            self.peer_sessions.remove(&MemberId::new(peer_node_id));
            let _ = self
                .transport
                .close_session(session_id, SessionCloseReason::LocalShutdown);
            return Err(err);
        }

        Ok(session_id)
    }

    /// Accept an incoming connection, handshake, and return the peer's node ID.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on accept or handshake failure.
    pub fn accept_peer(&mut self) -> Result<(u64, SessionId), TransportError> {
        let session_id = self.transport.accept_incoming()?;
        self.transport.perform_handshake(session_id)?;

        let peer_node_id = {
            let s = self.transport.sessions.get(&session_id).ok_or_else(|| {
                TransportError::Generic(format!("session {session_id} not found after accept"))
            })?;
            let s = s
                .lock()
                .map_err(|e| TransportError::Generic(format!("lock poisoned: {e}")))?;
            s.peer_node
        };

        self.peer_sessions
            .insert(MemberId::new(peer_node_id), session_id);

        Ok((peer_node_id, session_id))
    }

    /// Accept an incoming peer only if committed epoch evidence admits it.
    pub fn accept_peer_at_committed_epoch(&mut self) -> Result<(u64, SessionId), TransportError> {
        let snapshot = self.current_committed_snapshot()?;
        self.transport.epoch = snapshot.epoch;

        let (peer_node_id, session_id) = self.accept_peer()?;
        if let Err(err) = self.bind_peer_session_to_committed_epoch(peer_node_id, session_id) {
            self.peer_sessions.remove(&MemberId::new(peer_node_id));
            let _ = self
                .transport
                .close_session(session_id, SessionCloseReason::LocalShutdown);
            return Err(err);
        }

        Ok((peer_node_id, session_id))
    }

    /// Poll for an incoming connection, returning the peer info if one is ready.
    ///
    /// This is a convenience wrapper around `accept_peer` that returns
    /// `Ok(None)` when no connection is pending (non-blocking).
    ///
    /// # Errors
    ///
    /// Returns `TransportError` only on handshake or protocol failures,
    /// never on WouldBlock.
    pub fn try_accept_peer(&mut self) -> Result<Option<(u64, SessionId)>, TransportError> {
        match self.transport.accept_incoming() {
            Ok(session_id) => {
                self.transport.perform_handshake(session_id)?;
                let peer_node_id = {
                    let s = self.transport.sessions.get(&session_id).ok_or_else(|| {
                        TransportError::Generic(format!(
                            "session {session_id} not found after accept"
                        ))
                    })?;
                    let s = s
                        .lock()
                        .map_err(|e| TransportError::Generic(format!("lock poisoned: {e}")))?;
                    s.peer_node
                };
                self.peer_sessions
                    .insert(MemberId::new(peer_node_id), session_id);
                Ok(Some((peer_node_id, session_id)))
            }
            Err(TransportError::Generic(msg)) if msg.contains("no pending") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Poll for an incoming connection and admit it against committed epoch
    /// evidence if one is ready.
    pub fn try_accept_peer_at_committed_epoch(
        &mut self,
    ) -> Result<Option<(u64, SessionId)>, TransportError> {
        let snapshot = self.current_committed_snapshot()?;
        self.transport.epoch = snapshot.epoch;

        match self.try_accept_peer()? {
            Some((peer_node_id, session_id)) => {
                if let Err(err) =
                    self.bind_peer_session_to_committed_epoch(peer_node_id, session_id)
                {
                    self.peer_sessions.remove(&MemberId::new(peer_node_id));
                    let _ = self
                        .transport
                        .close_session(session_id, SessionCloseReason::LocalShutdown);
                    return Err(err);
                }
                Ok(Some((peer_node_id, session_id)))
            }
            None => Ok(None),
        }
    }

    /// Bind an existing transport session to the current committed epoch.
    pub fn bind_peer_session_to_committed_epoch(
        &mut self,
        peer_node_id: u64,
        session_id: SessionId,
    ) -> Result<(), TransportError> {
        let evidence = self.committed_epoch_evidence.as_ref().ok_or_else(|| {
            Self::admission_error(
                peer_node_id,
                ReconnectAdmission::EvidenceUnavailable {
                    reason: ReconnectEvidenceFailure::Missing,
                },
            )
        })?;
        let snapshot = evidence.snapshot().ok_or_else(|| {
            Self::admission_error(
                peer_node_id,
                ReconnectAdmission::EvidenceUnavailable {
                    reason: ReconnectEvidenceFailure::Missing,
                },
            )
        })?;
        let session_epoch = self.session_epoch(session_id)?;
        let claimed_epoch = if session_epoch == 0 {
            snapshot.epoch
        } else {
            session_epoch
        };
        let admission = evidence.check_reconnect_admission(peer_node_id, claimed_epoch);
        if !admission.is_admitted() {
            return Err(Self::admission_error(peer_node_id, admission));
        }

        self.bind_session_epoch(session_id, snapshot.epoch)?;
        self.peer_sessions
            .insert(MemberId::new(peer_node_id), session_id);
        Ok(())
    }

    /// Send a SWIM ping to a peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if no session exists for the peer or I/O fails.
    pub fn send_ping(&mut self, ping: &SwimPing) -> Result<(), TransportError> {
        let sid = self.session_for(ping.ping_target)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::Ping(ping.clone()),
        )
    }

    /// Tick a runtime and dispatch generated outbound messages over active sessions.
    pub fn tick_runtime(
        &mut self,
        runtime: &mut MembershipRuntime,
    ) -> (RuntimeTickResult, MembershipTransportTickResult) {
        let tick = runtime.tick();
        let mut transport_tick = MembershipTransportTickResult {
            runtime_pings_generated: tick.pings_sent,
            ..MembershipTransportTickResult::default()
        };

        for (_, ping) in &tick.outbound_pings {
            match self.send_ping(ping) {
                Ok(()) => transport_tick.pings_sent += 1,
                Err(_) => transport_tick.ping_send_failures += 1,
            }
        }

        (tick, transport_tick)
    }

    /// Send a SWIM ack to a peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if no session exists for the peer or I/O fails.
    pub fn send_ack(&mut self, target: MemberId, ack: &SwimAck) -> Result<(), TransportError> {
        let sid = self.session_for(target)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::Ack(ack.clone()),
        )
    }

    /// Send an indirect ping request to a relay peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O failure.
    pub fn send_indirect_ping_req(
        &mut self,
        relay_peer: MemberId,
        req: &SwimIndirectPingRequest,
    ) -> Result<(), TransportError> {
        let sid = self.session_for(relay_peer)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::IndirectPingRequest(req.clone()),
        )
    }

    /// Send an indirect ping response to the original requester.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O failure.
    pub fn send_indirect_ping_resp(
        &mut self,
        requester: MemberId,
        resp: &SwimIndirectPingResponse,
    ) -> Result<(), TransportError> {
        let sid = self.session_for(requester)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::IndirectPingResponse(resp.clone()),
        )
    }

    /// Broadcast an epoch transition proposal to all connected peers.
    ///
    /// Best-effort: individual send failures are logged and skipped.
    pub fn broadcast_proposal(&mut self, proposal: &EpochTransitionProposal) {
        let msg = MembershipWireMessage::Proposal(proposal.clone());
        for &sid in self.peer_sessions.values() {
            let _ = send_membership_msg(&mut self.transport, sid, &msg);
        }
    }

    /// Send an epoch transition accept to the proposal's proposer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O failure.
    pub fn send_accept(
        &mut self,
        proposer: MemberId,
        accept: &EpochTransitionAccept,
    ) -> Result<(), TransportError> {
        let sid = self.session_for(proposer)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::Accept(accept.clone()),
        )
    }

    /// Send an epoch transition commit to a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O failure.
    pub fn send_commit(
        &mut self,
        target: MemberId,
        commit: &EpochTransitionCommit,
    ) -> Result<(), TransportError> {
        let sid = self.session_for(target)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::Commit(commit.clone()),
        )
    }

    /// Send a membership view snapshot to a specific peer.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if no session exists for the peer or I/O fails.
    pub fn send_view(
        &mut self,
        target: MemberId,
        view: &MembershipView,
    ) -> Result<(), TransportError> {
        let sid = self.session_for(target)?;
        send_membership_msg(
            &mut self.transport,
            sid,
            &MembershipWireMessage::View(view.clone()),
        )
    }

    /// Broadcast a membership view snapshot to all connected peers.
    pub fn broadcast_view(&mut self, view: &MembershipView) {
        let msg = MembershipWireMessage::View(view.clone());
        for &sid in self.peer_sessions.values() {
            let _ = send_membership_msg(&mut self.transport, sid, &msg);
        }
    }

    /// Receive the next membership message from a specific peer (blocking).
    ///
    /// # Errors
    ///
    /// Returns `TransportError` on I/O or deserialization failure.
    pub fn recv_from(
        &mut self,
        member_id: MemberId,
    ) -> Result<MembershipWireMessage, TransportError> {
        let sid = self.session_for(member_id)?;
        recv_membership_msg(&mut self.transport, sid)
    }

    /// Close all peer sessions and shut down.
    pub fn close(&mut self) {
        for &sid in self.peer_sessions.values() {
            let _ = self
                .transport
                .close_session(sid, SessionCloseReason::LocalShutdown);
        }
        self.peer_sessions.clear();
    }

    /// Return the session for a given member.
    fn session_for(&self, member_id: MemberId) -> Result<SessionId, TransportError> {
        self.peer_sessions
            .get(&member_id)
            .copied()
            .ok_or(TransportError::PeerNotFound { peer: member_id.0 })
    }

    fn current_committed_snapshot(&self) -> Result<CommittedEpochSnapshot, TransportError> {
        let evidence = self.committed_epoch_evidence.as_ref().ok_or_else(|| {
            Self::admission_error(
                0,
                ReconnectAdmission::EvidenceUnavailable {
                    reason: ReconnectEvidenceFailure::Missing,
                },
            )
        })?;
        evidence.snapshot().ok_or_else(|| {
            Self::admission_error(
                0,
                ReconnectAdmission::EvidenceUnavailable {
                    reason: ReconnectEvidenceFailure::Missing,
                },
            )
        })
    }

    fn require_peer_admitted_for_new_session(
        &self,
        peer_node_id: u64,
    ) -> Result<CommittedEpochSnapshot, TransportError> {
        let snapshot = self.current_committed_snapshot()?;
        let evidence = self.committed_epoch_evidence.as_ref().unwrap();
        let admission = evidence.check_reconnect_admission(peer_node_id, snapshot.epoch);
        if admission.is_admitted() {
            Ok(snapshot)
        } else {
            Err(Self::admission_error(peer_node_id, admission))
        }
    }

    fn session_epoch(&self, session_id: SessionId) -> Result<u64, TransportError> {
        let session = self
            .transport
            .sessions
            .get(&session_id)
            .ok_or(TransportError::SessionNotFound { session_id })?;
        let session = session
            .lock()
            .map_err(|err| TransportError::Generic(format!("session lock poisoned: {err}")))?;
        Ok(session.current_epoch)
    }

    fn bind_session_epoch(&self, session_id: SessionId, epoch: u64) -> Result<(), TransportError> {
        let session = self
            .transport
            .sessions
            .get(&session_id)
            .ok_or(TransportError::SessionNotFound { session_id })?;
        let mut session = session
            .lock()
            .map_err(|err| TransportError::Generic(format!("session lock poisoned: {err}")))?;
        session
            .bind_epoch(epoch)
            .map_err(|err| TransportError::Generic(err.to_string()))
    }

    fn admission_error(peer_node_id: u64, admission: ReconnectAdmission) -> TransportError {
        TransportError::AdmissionRejected {
            peer_id: peer_node_id,
            reason: admission.to_string(),
        }
    }
}

impl Drop for MembershipTransport {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tidefs_transport::backend::TransportBackendKind;
    use tidefs_transport::{EndpointFamily, Session, TransportAddr};

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn wire_message_serde_roundtrip() {
        let ping = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: 42,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(3),
            pinger_epoch_receipt: 7,
            sent_at_millis: 1000,
            indirect_via: vec![MemberId::new(4), MemberId::new(5)],
            signature: vec![9, 8, 7],
        };

        let msg = MembershipWireMessage::Ping(ping);
        let encoded = bincode::serialize(&msg).expect("serialize");
        let decoded: MembershipWireMessage = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn all_wire_message_variants_serde() {
        use crate::types::TransitionReason;

        let variants: Vec<MembershipWireMessage> = vec![
            MembershipWireMessage::Ping(SwimPing {
                pinger: MemberId::new(1),
                ping_target: MemberId::new(2),
                seq_no: 1,
                pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
                pinger_epoch_receipt: 0,
                sent_at_millis: 1000,
                indirect_via: vec![],
                signature: vec![],
            }),
            MembershipWireMessage::Ack(SwimAck {
                ping_seq_no: 1,
                acker: MemberId::new(2),
                acker_epoch: tidefs_membership_epoch::EpochId::new(1),
                acker_epoch_receipt: 0,
                suspicion_list: vec![],
                membership_delta: vec![],
                acked_at_millis: 1001,
                signature: vec![],
            }),
            MembershipWireMessage::IndirectPingRequest(SwimIndirectPingRequest {
                requester: MemberId::new(1),
                target: MemberId::new(3),
                original_seq_no: 5,
                relay_seq_no: 1,
                sent_at_millis: 2000,
                signature: vec![],
            }),
            MembershipWireMessage::IndirectPingResponse(SwimIndirectPingResponse {
                responder: MemberId::new(2),
                target: MemberId::new(3),
                target_reachable: true,
                relay_seq_no: 1,
                responded_at_millis: 2001,
                signature: vec![],
            }),
            MembershipWireMessage::Proposal(EpochTransitionProposal {
                proposal_id: 1,
                proposer: MemberId::new(1),
                from_epoch: tidefs_membership_epoch::EpochId::new(1),
                to_epoch: tidefs_membership_epoch::EpochId::new(2),
                members_added: vec![],
                members_removed: vec![MemberId::new(3)],
                reason: TransitionReason::FailureDetected,
                validation: vec![],
                proposed_at_millis: 3000,
                fence_token: None,
                proposer_signature: vec![],
            }),
            MembershipWireMessage::Accept(EpochTransitionAccept {
                proposal_id: 1,
                acceptor: MemberId::new(2),
                accepted_at_millis: 3001,
                resulting_voter_set: vec![MemberId::new(1), MemberId::new(2)],
                signature: vec![],
            }),
            MembershipWireMessage::Commit(EpochTransitionCommit {
                proposal_id: 1,
                new_epoch: tidefs_membership_epoch::EpochId::new(2),
                accept_receipts: vec![100, 200],
                committed_at_millis: 3002,
                proposer_signature: vec![],
            }),
            MembershipWireMessage::View(MembershipView {
                epoch: tidefs_membership_epoch::EpochId::new(2),
                config_class: tidefs_membership_epoch::ConfigClass::Normal,
                local_member: MemberId::new(1),
                placement_version: 0,
                nodes: vec![crate::types::MembershipViewNode {
                    member_id: MemberId::new(1),
                    member_class: tidefs_membership_epoch::MemberClass::Voter,
                    health: tidefs_membership_epoch::HealthClass::Healthy,
                    epoch: tidefs_membership_epoch::EpochId::new(2),
                    failure_domain: 1,
                    joining: false,
                    draining: false,
                }],
            }),
            MembershipWireMessage::GossipBroadcast(GossipMessage::new(
                tidefs_membership_epoch::MemberId::new(1),
                1,
                crate::gossip::MemberState::Alive,
                10,
                tidefs_membership_epoch::MemberId::new(2),
                tidefs_membership_epoch::EpochId::new(3),
                5000,
            )),
        ];

        for msg in &variants {
            let encoded = bincode::serialize(msg).expect("serialize");
            let decoded: MembershipWireMessage =
                bincode::deserialize(&encoded).expect("deserialize");
            assert_eq!(*msg, decoded);
        }
    }

    fn insert_test_session(transport: &mut MembershipTransport, sid: SessionId, peer_node: u64) {
        let peer_addr = TransportAddr::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9001,
        ));
        let session = Session::new(
            sid,
            transport.transport.local_node_id,
            peer_node,
            peer_addr,
            EndpointFamily::Data,
            TransportBackendKind::Tcp,
        );
        transport
            .transport
            .sessions
            .insert(sid, Arc::new(Mutex::new(session)));
    }

    #[test]
    fn publish_committed_epoch_view_updates_evidence_and_fence_sender() {
        let mut membership_transport = MembershipTransport::new(1);
        let evidence = CommittedEpochEvidence::new();
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        membership_transport.set_committed_epoch_evidence(evidence.clone());
        membership_transport.set_epoch_fence_sender(tx);

        let snapshot = membership_transport
            .publish_committed_epoch_view(7, [MemberId::new(1), MemberId::new(2)])
            .expect("publish committed epoch");

        assert_eq!(snapshot.epoch, 7);
        assert_eq!(snapshot.member_ids(), vec![1, 2]);
        assert_eq!(membership_transport.transport.epoch, 7);
        assert_eq!(evidence.snapshot(), Some(snapshot));

        let transition = rx.try_recv().expect("epoch transition");
        assert_eq!(transition.epoch, 7);
    }

    #[test]
    fn bind_peer_session_to_committed_epoch_binds_session_epoch() {
        let mut membership_transport = MembershipTransport::new(1);
        let evidence = CommittedEpochEvidence::new();
        evidence.publish(6, [1, 2]);
        membership_transport.set_committed_epoch_evidence(evidence);
        let sid = SessionId::new(55);
        insert_test_session(&mut membership_transport, sid, 2);

        membership_transport
            .bind_peer_session_to_committed_epoch(2, sid)
            .expect("bind committed epoch");

        assert_eq!(
            membership_transport.peer_sessions.get(&MemberId::new(2)),
            Some(&sid)
        );
        let epoch = membership_transport
            .transport
            .sessions
            .get(&sid)
            .unwrap()
            .lock()
            .unwrap()
            .current_epoch;
        assert_eq!(epoch, 6);
    }

    #[test]
    fn bind_peer_session_to_committed_epoch_rejects_missing_evidence() {
        let mut membership_transport = MembershipTransport::new(1);
        let sid = SessionId::new(56);

        let err = membership_transport
            .bind_peer_session_to_committed_epoch(2, sid)
            .expect_err("missing evidence rejects");

        match err {
            TransportError::AdmissionRejected { peer_id, reason } => {
                assert_eq!(peer_id, 2);
                assert!(reason.contains("missing committed"));
            }
            other => panic!("expected AdmissionRejected, got {other:?}"),
        }
    }

    #[test]
    fn bind_peer_session_to_committed_epoch_rejects_lagged_evidence() {
        let mut membership_transport = MembershipTransport::new(1);
        let evidence = CommittedEpochEvidence::new();
        evidence.publish(4, [1, 2]);
        membership_transport.set_committed_epoch_evidence(evidence);
        let sid = SessionId::new(57);
        insert_test_session(&mut membership_transport, sid, 2);
        {
            let mut session = membership_transport
                .transport
                .sessions
                .get(&sid)
                .unwrap()
                .lock()
                .unwrap();
            session.bind_epoch(5).unwrap();
        }

        let err = membership_transport
            .bind_peer_session_to_committed_epoch(2, sid)
            .expect_err("lagged evidence rejects");

        match err {
            TransportError::AdmissionRejected { peer_id, reason } => {
                assert_eq!(peer_id, 2);
                assert!(reason.contains("lagged"));
            }
            other => panic!("expected AdmissionRejected, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // TCP loopback integration tests
    // -----------------------------------------------------------------------

    /// Bind a server, report its address, accept a client, receive ping, and send ack.
    fn server_accept_recv_ping_send_ack(
        addr_tx: std::sync::mpsc::Sender<SocketAddr>,
        result_tx: std::sync::mpsc::Sender<SwimPing>,
    ) {
        let mut server = MembershipTransport::new(2);
        let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        server.bind(bind_addr).expect("server bind");
        let bound = server.local_addr().expect("bound addr");
        let bound: SocketAddr = match bound {
            tidefs_transport::TransportAddr::Tcp(addr) => addr,
            _ => panic!("expected Tcp addr"),
        };
        addr_tx.send(bound).expect("send addr");

        // Poll until client connects
        let peer_sid;
        loop {
            match server.try_accept_peer() {
                Ok(Some((peer_id, sid))) => {
                    peer_sid = sid;
                    // peer_id should match whatever the client declared
                    let _ = peer_id;
                    break;
                }
                Ok(None) => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        }

        // Receive the ping
        let msg = recv_membership_msg(&mut server.transport, peer_sid).expect("recv ping");
        let ping = match msg {
            MembershipWireMessage::Ping(p) => p,
            other => panic!("expected Ping, got {other:?}"),
        };

        // Send ack back
        let ack = MembershipWireMessage::Ack(SwimAck {
            ping_seq_no: ping.seq_no,
            acker: MemberId::new(2),
            acker_epoch: tidefs_membership_epoch::EpochId::new(1),
            acker_epoch_receipt: 0,
            suspicion_list: vec![],
            membership_delta: vec![],
            acked_at_millis: 6000,
            signature: vec![],
        });
        send_membership_msg(&mut server.transport, peer_sid, &ack).expect("send ack");

        result_tx.send(ping).expect("send result");
        server.close();
    }

    #[test]
    fn ping_ack_roundtrip_over_tcp_loopback() {
        use std::sync::mpsc;

        let (addr_tx, addr_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();

        let _server = thread::spawn(move || {
            server_accept_recv_ping_send_ack(addr_tx, result_tx);
        });

        let server_addr = addr_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("server addr");

        // Allow server time to bind and enter poll loop
        thread::sleep(Duration::from_millis(20));

        let mut client = MembershipTransport::new(1);
        client
            .connect_to_peer(2, server_addr)
            .expect("client connect");

        let ping = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: 7,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: 5000,
            indirect_via: vec![],
            signature: vec![],
        };

        client.send_ping(&ping).expect("send ping");

        // Receive ack
        let ack = client.recv_from(MemberId::new(2)).expect("recv ack");
        match ack {
            MembershipWireMessage::Ack(ref a) => {
                assert_eq!(a.acker, MemberId::new(2));
                assert_eq!(a.ping_seq_no, 7);
                assert_eq!(a.acked_at_millis, 6000);
            }
            other => panic!("expected Ack, got {other:?}"),
        }

        // Verify server received the correct ping
        let server_ping = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("server ping result");
        assert_eq!(server_ping.pinger, MemberId::new(1));
        assert_eq!(server_ping.ping_target, MemberId::new(2));
        assert_eq!(server_ping.seq_no, 7);

        client.close();
    }

    /// Server that sends an epoch transition proposal to the client.
    fn server_send_proposal(
        addr_tx: std::sync::mpsc::Sender<SocketAddr>,
    ) -> EpochTransitionProposal {
        let mut server = MembershipTransport::new(2);
        server
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
            .expect("bind");
        let bound = server.local_addr().expect("bound addr");
        let bound: SocketAddr = match bound {
            tidefs_transport::TransportAddr::Tcp(addr) => addr,
            _ => panic!("expected Tcp addr"),
        };
        addr_tx.send(bound).expect("send addr");

        // Poll accept
        let peer_sid;
        loop {
            match server.try_accept_peer() {
                Ok(Some((_peer_id, sid))) => {
                    peer_sid = sid;
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(e) => panic!("accept failed: {e}"),
            }
        }

        // Send a proposal
        let proposal = EpochTransitionProposal {
            proposal_id: 42,
            proposer: MemberId::new(2),
            from_epoch: tidefs_membership_epoch::EpochId::new(3),
            to_epoch: tidefs_membership_epoch::EpochId::new(4),
            members_added: vec![MemberId::new(5)],
            members_removed: vec![],
            reason: crate::types::TransitionReason::JoinRequested,
            validation: vec![],
            proposed_at_millis: 7000,
            fence_token: None,
            proposer_signature: vec![],
        };

        let msg = MembershipWireMessage::Proposal(proposal.clone());
        send_membership_msg(&mut server.transport, peer_sid, &msg).expect("send proposal");

        server.close();
        proposal
    }

    #[test]
    fn receive_epoch_proposal_over_tcp_loopback() {
        use std::sync::mpsc;

        let (addr_tx, addr_rx) = mpsc::channel();

        let server_handle = thread::spawn(move || server_send_proposal(addr_tx));

        let server_addr = addr_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("server addr");

        thread::sleep(Duration::from_millis(20));

        let mut client = MembershipTransport::new(1);
        client
            .connect_to_peer(2, server_addr)
            .expect("client connect");

        // Receive the proposal
        let msg = client.recv_from(MemberId::new(2)).expect("recv proposal");
        match msg {
            MembershipWireMessage::Proposal(ref p) => {
                assert_eq!(p.proposal_id, 42);
                assert_eq!(p.proposer, MemberId::new(2));
                assert_eq!(p.from_epoch, tidefs_membership_epoch::EpochId::new(3));
                assert_eq!(p.to_epoch, tidefs_membership_epoch::EpochId::new(4));
                assert_eq!(p.members_added, vec![MemberId::new(5)]);
                assert_eq!(p.reason, crate::types::TransitionReason::JoinRequested);
            }
            other => panic!("expected Proposal, got {other:?}"),
        }

        let expected = server_handle.join().expect("server thread");
        assert_eq!(expected.proposal_id, 42);

        client.close();
    }

    /// Three-node cluster bootstrap: node 1 connects to node 2 and node 3.
    /// Each connection is verified via ping/ack.
    #[test]
    fn three_node_cluster_bootstrap_ping_ack() {
        use std::sync::mpsc;

        // Node 2 server
        let (addr2_tx, addr2_rx) = mpsc::channel();
        let (ping2_tx, ping2_rx) = mpsc::channel();
        let s2 = thread::spawn(move || {
            server_accept_recv_ping_send_ack(addr2_tx, ping2_tx);
        });

        // Node 3 server
        let (addr3_tx, addr3_rx) = mpsc::channel();
        let (ping3_tx, ping3_rx) = mpsc::channel();
        let s3 = thread::spawn(move || {
            server_accept_recv_ping_send_ack(addr3_tx, ping3_tx);
        });

        let addr2 = addr2_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("addr2");
        let addr3 = addr3_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("addr3");

        thread::sleep(Duration::from_millis(50));

        let mut client = MembershipTransport::new(1);

        // Connect to node 2
        client.connect_to_peer(2, addr2).expect("connect to 2");

        let ping2 = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(2),
            seq_no: 1,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: 1000,
            indirect_via: vec![],
            signature: vec![],
        };
        client.send_ping(&ping2).expect("ping 2");
        let ack2 = client.recv_from(MemberId::new(2)).expect("ack 2");
        assert!(matches!(ack2, MembershipWireMessage::Ack(..)));

        // Connect to node 3
        client.connect_to_peer(3, addr3).expect("connect to 3");

        let ping3 = SwimPing {
            pinger: MemberId::new(1),
            ping_target: MemberId::new(3),
            seq_no: 2,
            pinger_epoch: tidefs_membership_epoch::EpochId::new(1),
            pinger_epoch_receipt: 0,
            sent_at_millis: 2000,
            indirect_via: vec![],
            signature: vec![],
        };
        client.send_ping(&ping3).expect("ping 3");
        let ack3 = client.recv_from(MemberId::new(3)).expect("ack 3");
        assert!(matches!(ack3, MembershipWireMessage::Ack(..)));

        // Verify server results
        let p2 = ping2_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("ping2 result");
        let p3 = ping3_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("ping3 result");
        assert_eq!(p2.ping_target, MemberId::new(2));
        assert_eq!(p3.ping_target, MemberId::new(3));

        client.close();
        s2.join().expect("s2");
        s3.join().expect("s3");
    }
}
