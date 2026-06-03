//! Deterministic in-memory transport for the two-node membership harness.
//!
//! Replaces `std::sync::mpsc` channels with framed message passing using
//! the same 4-byte big-endian length-prefix framing as `tidefs-transport`.
//! All I/O is in-memory and under deterministic clock control, preserving
//! byte-for-byte reproducibility across runs.
//!
//! ## Architecture
//!
//! - `DeterministicTransport`: shared backend holding bidirectional queues
//!   of framed messages plus a partition flag.
//! - `DeterministicEndpoint`: per-node handle that bincode-serializes
//!   outbound `HarnessMessage` values, frames them, and pushes them into
//!   the peer's inbound queue. Inbound messages are de-framed and
//!   deserialized on receive.
//! - `DeterministicSession`: wraps a `DeterministicEndpoint` with explicit
//!   open/close lifecycle and an active-state guard on send/recv.
//! - Framing: 4-byte big-endian u32 length prefix + bincode payload,
//!   matching the `TcpTransport` framing used by `Transport::send_message`
//!   and `Transport::recv_message`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use crate::harness::HarnessMessage;

/// Which direction a message is travelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageDirection {
    Node1To2,
    Node2To1,
}

pub type MessageFilter = dyn Fn(&[u8], MessageDirection) -> bool + 'static;

// ---------------------------------------------------------------------------
// DeterministicTransport — shared backend
// ---------------------------------------------------------------------------

/// Shared deterministic transport backend for a two-node harness.
///
/// Maintains two independent message queues (one per direction) and a
/// per-direction partition flag. When a direction is blocked, outbound
/// messages are buffered in per-direction hold queues and released when
/// that direction heals.
// Manual Debug impl because Box<dyn Fn> does not implement Debug.
pub struct DeterministicTransport {
    q_1_to_2: VecDeque<Vec<u8>>,
    q_2_to_1: VecDeque<Vec<u8>>,
    hold_1_to_2: VecDeque<Vec<u8>>,
    hold_2_to_1: VecDeque<Vec<u8>>,
    /// Per-direction blocking: when true for a given direction, messages
    /// are held instead of delivered.
    pub blocked_1_to_2: bool,
    pub blocked_2_to_1: bool,
    /// Optional message filter predicate. When set, messages matching the
    /// predicate are dropped (not held, not delivered). None = no filter.
    pub filter: Option<Box<MessageFilter>>,
}

impl std::fmt::Debug for DeterministicTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeterministicTransport")
            .field("q_1_to_2", &self.q_1_to_2)
            .field("q_2_to_1", &self.q_2_to_1)
            .field("hold_1_to_2", &self.hold_1_to_2)
            .field("hold_2_to_1", &self.hold_2_to_1)
            .field("blocked_1_to_2", &self.blocked_1_to_2)
            .field("blocked_2_to_1", &self.blocked_2_to_1)
            .field("filter", &self.filter.as_ref().map(|_| "<filter>"))
            .finish()
    }
}

impl Default for DeterministicTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DeterministicTransport {
    pub fn new() -> Self {
        Self {
            q_1_to_2: VecDeque::new(),
            q_2_to_1: VecDeque::new(),
            hold_1_to_2: VecDeque::new(),
            hold_2_to_1: VecDeque::new(),
            blocked_1_to_2: false,
            blocked_2_to_1: false,
            filter: None,
        }
    }

    pub fn shared() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }

    /// Release held messages for direction 1->2 into the delivery queue.
    fn heal_1_to_2(&mut self) {
        while let Some(msg) = self.hold_1_to_2.pop_front() {
            self.q_1_to_2.push_back(msg);
        }
    }

    /// Release held messages for direction 2->1 into the delivery queue.
    fn heal_2_to_1(&mut self) {
        while let Some(msg) = self.hold_2_to_1.pop_front() {
            self.q_2_to_1.push_back(msg);
        }
    }

    /// Set directional partition state. When healing a direction, releases
    /// held messages for that direction.
    pub fn set_direction_blocked(&mut self, dir: MessageDirection, blocked: bool) {
        match dir {
            MessageDirection::Node1To2 => self.blocked_1_to_2 = blocked,
            MessageDirection::Node2To1 => self.blocked_2_to_1 = blocked,
        }
        if !blocked {
            match dir {
                MessageDirection::Node1To2 => self.heal_1_to_2(),
                MessageDirection::Node2To1 => self.heal_2_to_1(),
            }
        }
    }

    /// Legacy symmetric partition setter. When healing, releases all held messages.
    pub fn set_partitioned(&mut self, partitioned: bool) {
        self.blocked_1_to_2 = partitioned;
        self.blocked_2_to_1 = partitioned;
        if !partitioned {
            self.heal_1_to_2();
            self.heal_2_to_1();
        }
    }

    /// Return the number of held messages for the given direction.
    pub fn held_count(&self, dir: MessageDirection) -> usize {
        match dir {
            MessageDirection::Node1To2 => self.hold_1_to_2.len(),
            MessageDirection::Node2To1 => self.hold_2_to_1.len(),
        }
    }

    /// Return the number of in-flight (delivered but not yet drained) messages.
    pub fn in_flight_count(&self, dir: MessageDirection) -> usize {
        match dir {
            MessageDirection::Node1To2 => self.q_1_to_2.len(),
            MessageDirection::Node2To1 => self.q_2_to_1.len(),
        }
    }

    pub fn clear_queues_for(&mut self, node_id: u64) {
        if node_id == 1 {
            self.q_2_to_1.clear();
            self.hold_2_to_1.clear();
        } else {
            self.q_1_to_2.clear();
            self.hold_1_to_2.clear();
        }
    }

    /// Apply the filter predicate (if any) to a framed message.
    /// Returns `true` if the message should be dropped.
    fn should_drop(&self, framed: &[u8], dir: MessageDirection) -> bool {
        if let Some(ref filter) = self.filter {
            filter(framed, dir)
        } else {
            false
        }
    }

    /// Push a framed message into the appropriate queue, respecting
    /// directional blocking and filter.
    fn enqueue(&mut self, framed: Vec<u8>, dir: MessageDirection) {
        if self.should_drop(&framed, dir) {
            return;
        }
        match dir {
            MessageDirection::Node1To2 if self.blocked_1_to_2 => self.hold_1_to_2.push_back(framed),
            MessageDirection::Node1To2 => self.q_1_to_2.push_back(framed),
            MessageDirection::Node2To1 if self.blocked_2_to_1 => self.hold_2_to_1.push_back(framed),
            MessageDirection::Node2To1 => self.q_2_to_1.push_back(framed),
        }
    }
}

// ---------------------------------------------------------------------------
// DeterministicEndpoint — per-node send/recv handle
// ---------------------------------------------------------------------------

/// A per-node handle to the deterministic transport.
///
/// Each harness node holds one endpoint. Outbound messages are bincode-
/// serialized, framed (4-byte BE length prefix), and pushed into the peer's
/// inbound queue. Inbound messages are de-framed, bincode-deserialized,
/// and returned as `HarnessMessage` values.
#[derive(Clone)]
pub struct DeterministicEndpoint {
    /// This endpoint's node id (1 or 2).
    node_id: u64,
    /// Shared transport backend.
    transport: Rc<RefCell<DeterministicTransport>>,
}

impl DeterministicEndpoint {
    /// Create a new endpoint for `node_id` using the shared transport.
    pub fn new(node_id: u64, transport: Rc<RefCell<DeterministicTransport>>) -> Self {
        Self { node_id, transport }
    }

    // ------------------------------------------------------------------
    // Send
    // ------------------------------------------------------------------

    /// Serialize `msg` via bincode, frame it, and queue for delivery to the peer.
    ///
    /// When the transport is partitioned, the framed message is held until
    /// the partition heals rather than being delivered immediately.
    pub fn send(&self, msg: &HarnessMessage) {
        let payload = bincode::serialize(msg).expect("bincode serialize HarnessMessage");

        // Frame: 4-byte big-endian length prefix + payload
        let len = payload.len() as u32;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&payload);

        let dir = if self.node_id == 1 {
            MessageDirection::Node1To2
        } else {
            MessageDirection::Node2To1
        };

        self.transport.borrow_mut().enqueue(framed, dir);
    }

    // ------------------------------------------------------------------
    // Receive
    // ------------------------------------------------------------------

    /// Try to receive one framed message, de-frame and deserialize it.
    ///
    /// Returns `None` when the inbound queue is empty.
    pub fn try_recv(&self) -> Option<HarnessMessage> {
        let framed = {
            let mut t = self.transport.borrow_mut();
            if self.node_id == 1 {
                t.q_2_to_1.pop_front()
            } else {
                t.q_1_to_2.pop_front()
            }
        }?;

        // De-frame: expect 4-byte BE length prefix
        if framed.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        let payload = &framed[4..];
        if payload.len() != len {
            // Truncated frame - skip
            return None;
        }

        bincode::deserialize(payload).ok()
    }

    /// Drain all pending inbound messages into a `Vec`.
    pub fn drain(&self) -> Vec<HarnessMessage> {
        let mut msgs = Vec::new();
        while let Some(msg) = self.try_recv() {
            msgs.push(msg);
        }
        msgs
    }
}

// ---------------------------------------------------------------------------
// DeterministicSession — session lifecycle over a DeterministicEndpoint
// ---------------------------------------------------------------------------

/// State of a deterministic session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterministicSessionState {
    /// Session not yet opened.
    Unconnected,
    /// Session is open and can send/receive.
    Connected,
    /// Session has been closed and rejects further I/O.
    Closed,
}

/// A framed session wrapping a [`DeterministicEndpoint`] with explicit
/// open/close lifecycle.
///
/// Provides a session-id, state tracking, and active-state guard on
/// send/recv: messages sent or received on an inactive session are
/// silently dropped / return empty.
#[derive(Clone)]
pub struct DeterministicSession {
    pub session_id: u64,
    pub state: DeterministicSessionState,
    endpoint: DeterministicEndpoint,
}

impl DeterministicSession {
    /// Create a new unconnected session.
    pub fn new(session_id: u64, endpoint: DeterministicEndpoint) -> Self {
        Self {
            session_id,
            state: DeterministicSessionState::Unconnected,
            endpoint,
        }
    }

    /// Open the session (Unconnected -> Connected).
    pub fn open(&mut self) {
        self.state = DeterministicSessionState::Connected;
    }

    /// Close the session (Connected -> Closed).
    pub fn close(&mut self) {
        self.state = DeterministicSessionState::Closed;
    }

    /// Whether the session is active (can send/receive).
    pub fn is_active(&self) -> bool {
        self.state == DeterministicSessionState::Connected
    }

    /// Whether the session has been closed.
    pub fn is_closed(&self) -> bool {
        self.state == DeterministicSessionState::Closed
    }

    /// Send a message through the session.
    ///
    /// Silently drops messages when the session is not active.
    pub fn send(&self, msg: &HarnessMessage) {
        if self.is_active() {
            self.endpoint.send(msg);
        }
    }

    /// Try to receive one message.
    ///
    /// Returns `None` when the session is not active or the queue is empty.
    pub fn try_recv(&self) -> Option<HarnessMessage> {
        if self.is_active() {
            self.endpoint.try_recv()
        } else {
            None
        }
    }

    /// Drain all pending messages into a `Vec`.
    ///
    /// Returns an empty vec when the session is not active.
    pub fn drain(&self) -> Vec<HarnessMessage> {
        if self.is_active() {
            self.endpoint.drain()
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::LeaseType;

    // ----------------------------------------------------------------
    // DeterministicEndpoint tests
    // ----------------------------------------------------------------

    #[test]
    fn endpoint_send_recv_roundtrip() {
        let t = DeterministicTransport::shared();
        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep2 = DeterministicEndpoint::new(2, Rc::clone(&t));

        let msg = HarnessMessage::JoinRequest {
            node_id: 1,
            at_ms: 1000,
        };
        ep1.send(&msg);
        let received = ep2.try_recv().expect("should receive");
        assert_eq!(received, msg);
    }

    #[test]
    fn all_message_variants_roundtrip() {
        let t = DeterministicTransport::shared();
        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep2 = DeterministicEndpoint::new(2, Rc::clone(&t));

        let messages = vec![
            HarnessMessage::JoinRequest {
                node_id: 1,
                at_ms: 100,
            },
            HarnessMessage::JoinResponse {
                to_node_id: 2,
                epoch_id: 1,
                members: vec![1, 2],
                at_ms: 200,
            },
            HarnessMessage::EpochUpdate {
                from_epoch: 0,
                to_epoch: 1,
                added: vec![2],
                removed: vec![],
                at_ms: 300,
            },
            HarnessMessage::LeaveRequest {
                node_id: 2,
                at_ms: 400,
            },
            HarnessMessage::LeaseAcquire {
                node_id: 1,
                object_id: 42,
                lease_type: LeaseType::Writer,
                at_ms: 500,
            },
            HarnessMessage::LeaseAck {
                object_id: 42,
                granted: true,
                holder: 1,
                at_ms: 600,
            },
            HarnessMessage::LeaseRevoke {
                object_id: 42,
                revoked_from: 1,
                at_ms: 700,
            },
            HarnessMessage::Heartbeat {
                node_id: 1,
                epoch_id: 3,
                at_ms: 800,
            },
        ];

        for msg in &messages {
            ep1.send(msg);
            let received = ep2.try_recv().expect("should receive");
            assert_eq!(&received, msg, "roundtrip failed for {msg:?}");
        }
    }

    #[test]
    fn bidirectional() {
        let t = DeterministicTransport::shared();
        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep2 = DeterministicEndpoint::new(2, Rc::clone(&t));

        ep1.send(&HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 0,
            at_ms: 10,
        });
        ep2.send(&HarnessMessage::Heartbeat {
            node_id: 2,
            epoch_id: 0,
            at_ms: 20,
        });

        assert_eq!(
            ep2.try_recv(),
            Some(HarnessMessage::Heartbeat {
                node_id: 1,
                epoch_id: 0,
                at_ms: 10
            })
        );
        assert_eq!(
            ep1.try_recv(),
            Some(HarnessMessage::Heartbeat {
                node_id: 2,
                epoch_id: 0,
                at_ms: 20
            })
        );
    }

    #[test]
    fn partition_holds_and_releases_on_heal() {
        let t = DeterministicTransport::shared();
        t.borrow_mut().set_partitioned(true);

        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep2 = DeterministicEndpoint::new(2, Rc::clone(&t));

        let msg = HarnessMessage::LeaseAcquire {
            node_id: 1,
            object_id: 77,
            lease_type: LeaseType::Writer,
            at_ms: 100,
        };
        ep1.send(&msg);
        assert!(ep2.try_recv().is_none());

        t.borrow_mut().set_partitioned(false);
        let received = ep2.try_recv().expect("should receive after heal");
        assert_eq!(received, msg);
    }

    #[test]
    fn multiple_messages_queued_and_drained() {
        let t = DeterministicTransport::shared();
        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep2 = DeterministicEndpoint::new(2, Rc::clone(&t));

        for i in 0..5 {
            ep1.send(&HarnessMessage::Heartbeat {
                node_id: 1,
                epoch_id: i,
                at_ms: i * 100,
            });
        }

        let drained = ep2.drain();
        assert_eq!(drained.len(), 5);
        for (i, msg) in drained.iter().enumerate() {
            assert_eq!(
                msg,
                &HarnessMessage::Heartbeat {
                    node_id: 1,
                    epoch_id: i as u64,
                    at_ms: i as u64 * 100
                }
            );
        }
    }

    #[test]
    fn frame_format_matches_transport_framing() {
        let t = DeterministicTransport::shared();
        let ep1 = DeterministicEndpoint::new(1, Rc::clone(&t));

        let msg = HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 5,
            at_ms: 42,
        };
        let payload = bincode::serialize(&msg).unwrap();
        ep1.send(&msg);

        let mut t = t.borrow_mut();
        let framed = t.q_1_to_2.pop_front().expect("should have frame");
        let frame_len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(frame_len, payload.len());
        assert_eq!(&framed[4..], &payload[..]);

        let decoded: HarnessMessage = bincode::deserialize(&framed[4..]).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn empty_queue_returns_none() {
        let t = DeterministicTransport::shared();
        let ep = DeterministicEndpoint::new(1, t);
        assert!(ep.try_recv().is_none());
    }

    #[test]
    fn drain_empty_is_empty_vec() {
        let t = DeterministicTransport::shared();
        let ep = DeterministicEndpoint::new(1, t);
        assert!(ep.drain().is_empty());
    }

    // ----------------------------------------------------------------
    // DeterministicSession tests
    // ----------------------------------------------------------------

    #[test]
    fn session_open_close_lifecycle() {
        let t = DeterministicTransport::shared();
        let ep = DeterministicEndpoint::new(1, Rc::clone(&t));
        let mut s = DeterministicSession::new(1, ep);

        assert!(!s.is_active());
        assert!(!s.is_closed());
        s.open();
        assert!(s.is_active());
        assert!(!s.is_closed());
        s.close();
        assert!(!s.is_active());
        assert!(s.is_closed());
    }

    #[test]
    fn session_send_blocked_until_open() {
        let t = DeterministicTransport::shared();
        let ep_sender = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep_recv = DeterministicEndpoint::new(2, Rc::clone(&t));
        let mut sender = DeterministicSession::new(1, ep_sender);
        let mut recv = DeterministicSession::new(2, ep_recv);

        // Send before open — dropped
        sender.send(&HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 0,
            at_ms: 10,
        });
        sender.open();
        recv.open();
        sender.send(&HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 0,
            at_ms: 20,
        });
        assert!(recv.try_recv().is_some());
    }

    #[test]
    fn session_recv_blocked_after_close() {
        let t = DeterministicTransport::shared();
        let ep_sender = DeterministicEndpoint::new(1, Rc::clone(&t));
        let ep_recv = DeterministicEndpoint::new(2, Rc::clone(&t));
        let mut sender = DeterministicSession::new(1, ep_sender);
        let mut recv = DeterministicSession::new(2, ep_recv);

        sender.open();
        recv.open();
        sender.send(&HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 0,
            at_ms: 10,
        });
        assert!(recv.try_recv().is_some());
        recv.close();
        sender.send(&HarnessMessage::Heartbeat {
            node_id: 1,
            epoch_id: 1,
            at_ms: 20,
        });
        assert!(recv.try_recv().is_none());
        assert!(recv.drain().is_empty());
    }

    #[test]
    fn session_roundtrip_through_open_session() {
        let t = DeterministicTransport::shared();
        let mut a = DeterministicSession::new(1, DeterministicEndpoint::new(1, Rc::clone(&t)));
        let mut b = DeterministicSession::new(2, DeterministicEndpoint::new(2, Rc::clone(&t)));
        a.open();
        b.open();

        let msg = HarnessMessage::LeaseAcquire {
            node_id: 1,
            object_id: 99,
            lease_type: LeaseType::Writer,
            at_ms: 42,
        };
        a.send(&msg);
        assert_eq!(b.try_recv(), Some(msg));
    }

    #[test]
    fn session_drain_inactive_returns_empty() {
        let t = DeterministicTransport::shared();
        let s = DeterministicSession::new(1, DeterministicEndpoint::new(1, t));
        assert!(s.drain().is_empty());
    }

    #[test]
    fn session_forced_fencing_through_sessions() {
        let t = DeterministicTransport::shared();
        let mut node_a = DeterministicSession::new(1, DeterministicEndpoint::new(1, Rc::clone(&t)));
        let mut node_b = DeterministicSession::new(2, DeterministicEndpoint::new(2, Rc::clone(&t)));
        node_a.open();
        node_b.open();

        node_a.send(&HarnessMessage::LeaseAcquire {
            node_id: 1,
            object_id: 77,
            lease_type: LeaseType::Writer,
            at_ms: 100,
        });
        let req = node_b.try_recv().unwrap();
        assert_eq!(
            req,
            HarnessMessage::LeaseAcquire {
                node_id: 1,
                object_id: 77,
                lease_type: LeaseType::Writer,
                at_ms: 100
            }
        );

        t.borrow_mut().set_partitioned(true);
        node_a.send(&HarnessMessage::LeaseRevoke {
            object_id: 77,
            revoked_from: 2,
            at_ms: 200,
        });
        assert!(node_b.try_recv().is_none());

        t.borrow_mut().set_partitioned(false);
        let revoke = node_b.try_recv().unwrap();
        assert_eq!(
            revoke,
            HarnessMessage::LeaseRevoke {
                object_id: 77,
                revoked_from: 2,
                at_ms: 200
            }
        );
    }
}
