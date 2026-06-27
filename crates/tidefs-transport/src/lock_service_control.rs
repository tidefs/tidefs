// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! LOCK service CONTROL-lane transport sink.
//!
//! LOCK frames already carry the stable LOCK service id (`0x0A`) in their
//! fixed frame header. This module binds those encoded service frames to the
//! existing transport CONTROL surface: `EndpointFamily::Control` with the
//! `MessageFamily::LeaseFenceDeadline` family, whose preferred lane is
//! `LaneClass::Control`.

use std::collections::BTreeMap;

use crate::envelope::MessageFamily;
use crate::lane_demux::LaneClass;
use crate::peer_send_queue::{PeerQueueSender, SendError};
use crate::transport_session_set::{SessionHealth, TransportSessionSet};
use crate::types::SessionId;
use crate::EndpointFamily;
use tidefs_lock_service::{LockFrameSink, LockServiceError, MemberId};

/// Endpoint family used for clustered LOCK service frames.
pub const LOCK_CONTROL_ENDPOINT_FAMILY: EndpointFamily = EndpointFamily::Control;
/// Transport message family used for service-id-anchored LOCK payloads.
pub const LOCK_CONTROL_MESSAGE_FAMILY: MessageFamily = MessageFamily::LeaseFenceDeadline;
/// Lane selected by `LOCK_CONTROL_MESSAGE_FAMILY`.
pub const LOCK_CONTROL_LANE: LaneClass = LaneClass::Control;

/// Transport-backed [`LockFrameSink`] for clustered LOCK service frames.
///
/// The sink validates the target [`MemberId`] against the active
/// [`TransportSessionSet`], requires the session to be healthy, and then
/// enqueues the already-encoded LOCK frame into the peer's bounded CONTROL
/// send queue. The I/O runtime should frame queued bytes with
/// [`LOCK_CONTROL_MESSAGE_FAMILY`], which routes to the CONTROL lane.
#[derive(Clone)]
pub struct ControlLockFrameSink {
    sessions: TransportSessionSet,
    senders: BTreeMap<MemberId, PeerQueueSender<Vec<u8>>>,
}

impl ControlLockFrameSink {
    /// Build a sink from a transport session roster.
    #[must_use]
    pub fn new(sessions: TransportSessionSet) -> Self {
        Self {
            sessions,
            senders: BTreeMap::new(),
        }
    }

    /// Build a sink with an initial peer sender map.
    #[must_use]
    pub fn from_senders<I>(sessions: TransportSessionSet, senders: I) -> Self
    where
        I: IntoIterator<Item = (MemberId, PeerQueueSender<Vec<u8>>)>,
    {
        let mut sink = Self::new(sessions);
        for (peer, sender) in senders {
            sink.insert_sender(peer, sender);
        }
        sink
    }

    /// Insert or replace the bounded CONTROL send queue for a peer.
    pub fn insert_sender(&mut self, peer: MemberId, sender: PeerQueueSender<Vec<u8>>) {
        self.senders.insert(peer, sender);
    }

    /// Return the session roster used to validate peer targets.
    #[must_use]
    pub fn sessions(&self) -> &TransportSessionSet {
        &self.sessions
    }

    /// Return a mutable session roster for membership/health updates.
    #[must_use]
    pub fn sessions_mut(&mut self) -> &mut TransportSessionSet {
        &mut self.sessions
    }

    fn healthy_session_for(&self, peer: MemberId) -> Result<SessionId, LockServiceError> {
        match self.sessions.get_binding(peer.0) {
            Some(binding) if binding.health == SessionHealth::Healthy => Ok(binding.session_id),
            Some(binding) => Err(LockServiceError::TransportPeerUnavailable {
                peer,
                reason: format!(
                    "session {} is not healthy (health {:?})",
                    binding.session_id, binding.health
                ),
            }),
            None => Err(LockServiceError::TransportPeerUnavailable {
                peer,
                reason: "peer is not present in the transport session roster".into(),
            }),
        }
    }
}

impl LockFrameSink for ControlLockFrameSink {
    fn send_lock_frame(&mut self, peer: MemberId, frame: Vec<u8>) -> Result<(), LockServiceError> {
        let session_id = self.healthy_session_for(peer)?;
        let sender =
            self.senders
                .get(&peer)
                .ok_or_else(|| LockServiceError::TransportPeerUnavailable {
                    peer,
                    reason: format!("session {session_id} has no CONTROL send queue"),
                })?;

        sender
            .try_send(frame)
            .map(|_| ())
            .map_err(|err| map_send_error(peer, session_id, err))
    }
}

fn map_send_error(peer: MemberId, session_id: SessionId, err: SendError) -> LockServiceError {
    match err {
        SendError::Full { evidence } => LockServiceError::TransportQueueFull {
            peer,
            reason: format!("session {session_id}: {evidence:?}"),
        },
        SendError::Closed { evidence } => LockServiceError::TransportClosed {
            peer,
            reason: format!("session {session_id}: {evidence:?}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io_runtime::{decode_frame, encode_frame};
    use crate::peer_send_queue::{BackpressurePolicy, PeerSendQueue};
    use tidefs_lock_service::{
        AcquireRequest, DatasetMountId, EpochId, LeaseTarget, LockFrame, LockMode, LockPayload,
        ServiceLockOwner,
    };

    fn healthy_roster(peer: MemberId, session_id: SessionId) -> TransportSessionSet {
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding(peer.0, session_id);
        sessions.mark_healthy(session_id);
        sessions
    }

    fn sample_lock_frame() -> LockFrame {
        let owner = ServiceLockOwner::new(MemberId::new(10), 1234, 55);
        let request = AcquireRequest::new(
            LeaseTarget::ByteRange {
                dataset_id: 7,
                ino: 9,
                start: 11,
                len: 13,
            },
            LockMode::Exclusive,
            owner,
            DatasetMountId::new(99),
            3,
            EpochId::new(5),
        );
        LockFrame::new(42, LockPayload::Acquire(request))
    }

    #[tokio::test]
    async fn control_sink_roundtrips_lock_frame_through_peer_queue() {
        let peer = MemberId::new(2);
        let session_id = SessionId::new(77);
        let sessions = healthy_roster(peer, session_id);
        let mut queues = PeerSendQueue::new(4, BackpressurePolicy::Error);
        let sender = queues.sender(peer.0).expect("sender");
        let mut receiver = queues.take_receiver(peer.0).expect("receiver");
        let mut sink = ControlLockFrameSink::from_senders(sessions, [(peer, sender)]);
        let frame = sample_lock_frame();
        let encoded = frame.encode().expect("encode lock frame");

        sink.send_lock_frame(peer, encoded)
            .expect("enqueue lock frame");

        assert_eq!(LOCK_CONTROL_ENDPOINT_FAMILY, EndpointFamily::Control);
        assert_eq!(LOCK_CONTROL_LANE, LaneClass::Control);
        assert_eq!(
            LOCK_CONTROL_MESSAGE_FAMILY.preferred_lane(),
            LOCK_CONTROL_LANE
        );

        let queued = receiver.recv().await.expect("peer-side queued frame");
        let io_frame = encode_frame(LOCK_CONTROL_MESSAGE_FAMILY, &queued);
        let (family, payload) = decode_frame(&io_frame).expect("decode transport frame");

        assert_eq!(family, LOCK_CONTROL_MESSAGE_FAMILY);
        assert_eq!(
            LockFrame::decode(&payload).expect("decode lock frame"),
            frame
        );
    }

    #[test]
    fn control_sink_rejects_peer_missing_from_roster() {
        let peer = MemberId::new(2);
        let mut sink = ControlLockFrameSink::new(TransportSessionSet::new());

        let err = sink
            .send_lock_frame(peer, vec![1, 2, 3])
            .expect_err("missing peer rejected");

        match err {
            LockServiceError::TransportPeerUnavailable { peer: rejected, .. } => {
                assert_eq!(rejected, peer)
            }
            other => panic!("expected unavailable peer, got {other:?}"),
        }
    }

    #[test]
    fn control_sink_rejects_unhealthy_peer() {
        let peer = MemberId::new(2);
        let session_id = SessionId::new(77);
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding(peer.0, session_id);
        sessions.mark_unhealthy(session_id);
        let mut queues = PeerSendQueue::new(4, BackpressurePolicy::Error);
        let sender = queues.sender(peer.0).expect("sender");
        let mut sink = ControlLockFrameSink::from_senders(sessions, [(peer, sender)]);

        let err = sink
            .send_lock_frame(peer, vec![1, 2, 3])
            .expect_err("unhealthy peer rejected");

        match err {
            LockServiceError::TransportPeerUnavailable { peer: rejected, .. } => {
                assert_eq!(rejected, peer)
            }
            other => panic!("expected unavailable peer, got {other:?}"),
        }
    }

    #[test]
    fn control_sink_reports_full_send_queue() {
        let peer = MemberId::new(2);
        let session_id = SessionId::new(77);
        let sessions = healthy_roster(peer, session_id);
        let mut queues = PeerSendQueue::new(1, BackpressurePolicy::Error);
        let sender = queues.sender(peer.0).expect("sender");
        let _receiver = queues.take_receiver(peer.0).expect("receiver");
        sender.try_send(vec![0]).expect("fill queue");
        let mut sink = ControlLockFrameSink::from_senders(sessions, [(peer, sender)]);

        let err = sink
            .send_lock_frame(peer, vec![1, 2, 3])
            .expect_err("full queue rejected");

        match err {
            LockServiceError::TransportQueueFull { peer: rejected, .. } => {
                assert_eq!(rejected, peer)
            }
            other => panic!("expected full queue, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn control_sink_reports_closed_send_queue() {
        let peer = MemberId::new(2);
        let session_id = SessionId::new(77);
        let sessions = healthy_roster(peer, session_id);
        let mut queues = PeerSendQueue::new(1, BackpressurePolicy::Error);
        let sender = queues.sender(peer.0).expect("sender");
        let mut receiver = queues.take_receiver(peer.0).expect("receiver");
        receiver.close().await;
        let mut sink = ControlLockFrameSink::from_senders(sessions, [(peer, sender)]);

        let err = sink
            .send_lock_frame(peer, vec![1, 2, 3])
            .expect_err("closed queue rejected");

        match err {
            LockServiceError::TransportClosed { peer: rejected, .. } => {
                assert_eq!(rejected, peer)
            }
            other => panic!("expected closed queue, got {other:?}"),
        }
    }
}
