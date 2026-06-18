// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Lease message dispatch for the transport session handler.
//!
//! Routes encoded [`tidefs_lease::wire::LeaseWireMessage`] values through
//! the transport envelope layer using `MessageFamily::LeaseFenceDeadline` (m3)
//! so that incoming lease messages can be decoded and routed to the lease
//! manager, and responses sent back on the same session.
//!
//! ## Integration with transport envelopes
//!
//! Lease wire messages produced by [`tidefs_lease::wire::LeaseWireCodec`]
//! are already framed with a binary-schema envelope and BLAKE3-256 digest.
//! The transport layer treats these framed bytes as opaque payloads carried
//! inside transport envelopes tagged with `MessageFamily::LeaseFenceDeadline`.
//!
//! ## Dispatch flow
//!
//! ```text
//! LeaseWireMessage
//!   → LeaseWireCodec::encode()  → framed payload bytes
//!   → Transport envelope (m3)   → on-wire frame
//!   → Transport envelope decode → framed payload bytes
//!   → LeaseWireCodec::decode()  → LeaseWireMessage
//! ```

use std::cell::RefCell;
use std::rc::Rc;

use crate::harness::{DeterministicMessageScheduler, LoopbackTransport, SimNode};
#[cfg(test)]
use tidefs_membership_epoch::DatasetMountIdentity;
use tidefs_membership_epoch::{EpochMemberSet, NodeIdentity};

use crate::envelope::MessageFamily;
use crate::session::Session;
use tidefs_binary_schema_core::BinarySchemaError;
use tidefs_lease::wire::{LeaseWireCodec, LeaseWireMessage};

// ---------------------------------------------------------------------------
// Encode/decode lease messages for transport
// ---------------------------------------------------------------------------

/// Encode a [`LeaseWireMessage`] into transport-ready payload bytes.
///
/// The returned bytes are the framed lease wire message (binary-schema
/// envelope + bincode payload + BLAKE3 digest) suitable for wrapping in
/// a transport envelope with `MessageFamily::LeaseFenceDeadline`.
///
/// # Errors
///
/// Returns [`BinarySchemaError`] if encoding fails.
pub fn encode_lease_message(msg: &LeaseWireMessage) -> Result<Vec<u8>, BinarySchemaError> {
    LeaseWireCodec::encode(msg)
}

/// Decode a transport payload into a [`LeaseWireMessage`].
///
/// The payload must be a framed lease wire message as produced by
/// [`encode_lease_message`].
///
/// # Errors
///
/// Returns [`BinarySchemaError`] if the payload is invalid: bad framing,
/// digest mismatch, or deserialization failure.
pub fn decode_lease_message(payload: &[u8]) -> Result<LeaseWireMessage, BinarySchemaError> {
    LeaseWireCodec::decode(payload)
}

/// The [`MessageFamily`] for lease wire messages.
pub const LEASE_MESSAGE_FAMILY: MessageFamily = MessageFamily::LeaseFenceDeadline;

// ---------------------------------------------------------------------------
// Session dispatch helpers
// ---------------------------------------------------------------------------

/// Trait for handling decoded lease messages within a transport session
/// context. Implementors (typically the lease manager) receive decoded
/// messages along with the session they arrived on, enabling responses
/// to be sent back on the same session.
pub trait LeaseMessageHandler: Send + Sync {
    /// Handle an incoming lease message received on the given session.
    ///
    /// The handler should process the message and may use `session` to
    /// send a response. Implementations must be non-blocking; long-running
    /// work should be spawned onto a task.
    fn handle_lease_message(
        &self,
        session: &mut Session,
        msg: LeaseWireMessage,
    ) -> Result<(), BinarySchemaError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TransportBackendKind;
    use crate::types::SessionId;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tidefs_lease::types::{LeaseClass, LeaseDomain};
    use tidefs_lease::wire::{
        LeaseErrorPayload, LeaseReleasePayload, LeaseRenewPayload, LeaseRequestPayload,
        LeaseWireErrorCode,
    };
    use tidefs_membership_epoch::{EpochId, MemberId};
    use tidefs_types_transport_session::EndpointFamily;

    fn make_session() -> Session {
        Session::new(
            SessionId::new(1),
            10,
            20,
            crate::TransportAddr::Tcp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                8000,
            )),
            EndpointFamily::LocalEmbed,
            TransportBackendKind::Tcp,
        )
    }

    // ── encode/decode round-trip ──────────────────────────────────────

    #[test]
    fn roundtrip_request_via_dispatch() {
        let msg = LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 7,
            lease_class: LeaseClass::Exclusive,
            domain: LeaseDomain::Inode {
                dataset_id: 1,
                ino: 42,
            },
            holder_id: MemberId(3),
            term_millis: 15_000,
            epoch: EpochId(2),
            mount_identity: DatasetMountIdentity::ZERO,
        });
        let encoded = encode_lease_message(&msg).unwrap();
        let decoded = decode_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_renew_via_dispatch() {
        let msg = LeaseWireMessage::Renew(LeaseRenewPayload {
            lease_id: 55,
            holder_id: MemberId(9),
            epoch: EpochId(4),
        });
        let encoded = encode_lease_message(&msg).unwrap();
        let decoded = decode_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_release_via_dispatch() {
        let msg = LeaseWireMessage::Release(LeaseReleasePayload {
            lease_id: 77,
            holder_id: MemberId(2),
            epoch: EpochId(6),
        });
        let encoded = encode_lease_message(&msg).unwrap();
        let decoded = decode_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_error_via_dispatch() {
        let msg = LeaseWireMessage::Error(LeaseErrorPayload {
            request_id: 99,
            code: LeaseWireErrorCode::StaleEpoch,
            detail: "epoch mismatch".into(),
        });
        let encoded = encode_lease_message(&msg).unwrap();
        let decoded = decode_lease_message(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    // ── decode rejects garbage ─────────────────────────────────────────

    #[test]
    fn decode_rejects_garbage() {
        let garbage = vec![0xFFu8; 100];
        assert!(decode_lease_message(&garbage).is_err());
    }

    #[test]
    fn decode_rejects_empty() {
        assert!(decode_lease_message(&[]).is_err());
    }

    // ── message family is correct ─────────────────────────────────────

    #[test]
    fn lease_message_family_is_m3() {
        assert_eq!(LEASE_MESSAGE_FAMILY, MessageFamily::LeaseFenceDeadline);
    }

    // ── handler dispatch integration test ─────────────────────────────

    /// A test handler that records received messages.
    struct TestHandler {
        pub received: std::sync::Mutex<Vec<LeaseWireMessage>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                received: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl LeaseMessageHandler for TestHandler {
        fn handle_lease_message(
            &self,
            _session: &mut Session,
            msg: LeaseWireMessage,
        ) -> Result<(), BinarySchemaError> {
            self.received.lock().unwrap().push(msg);
            Ok(())
        }
    }

    #[test]
    fn handler_receives_decoded_message() {
        let handler = TestHandler::new();
        let mut session = make_session();

        let msg = LeaseWireMessage::Renew(LeaseRenewPayload {
            lease_id: 100,
            holder_id: MemberId(5),
            epoch: EpochId(3),
        });

        handler
            .handle_lease_message(&mut session, msg.clone())
            .unwrap();

        let received = handler.received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], msg);
    }

    #[test]
    fn handler_roundtrip_encode_dispatch_decode() {
        let handler = TestHandler::new();
        let mut session = make_session();

        let original = LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 42,
            lease_class: LeaseClass::Shared,
            domain: LeaseDomain::Subtree {
                dataset_id: 10,
                prefix: "/data/".into(),
            },
            holder_id: MemberId(7),
            term_millis: 60_000,
            epoch: EpochId(1),
            mount_identity: DatasetMountIdentity::ZERO,
        });

        // Simulate send: encode → transport would wrap in envelope → decode
        let encoded = encode_lease_message(&original).unwrap();
        let decoded = decode_lease_message(&encoded).unwrap();

        // Dispatch to handler
        handler.handle_lease_message(&mut session, decoded).unwrap();

        let received = handler.received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0], original);
    }
}

// ---------------------------------------------------------------------------
// Lease-aware harness node
// ---------------------------------------------------------------------------

/// A [`SimNode`](crate::harness::SimNode) wrapper that sends and receives
/// [`LeaseWireMessage`] values through the deterministic harness scheduler.
///
/// Each send encodes the message via [`encode_lease_message`] and each recv
/// decodes via [`decode_lease_message`].  Error paths (encode failure, decode
/// failure, no message available) are surfaced through the result variants.
///
/// # Example
///
/// ```ignore
/// let sched = make_scheduler(42);
/// let mut a = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
/// let mut b = LeaseSimNode::bootstrap(2, Rc::clone(&sched));
///
/// let req = LeaseWireMessage::Request(LeaseRequestPayload { … });
/// a.send(&mut b.identity(), &req).unwrap();
/// sched.borrow_mut().tick();
///
/// if let LeaseWireMessage::Grant(g) = b.recv().unwrap().unwrap() {
///     // …
/// }
/// ```
pub struct LeaseSimNode {
    /// Inner harness node.
    pub inner: SimNode,
}

impl LeaseSimNode {
    /// Bootstrap a new lease-aware node registered in the scheduler.
    ///
    /// This is a convenience constructor that creates a [`SimNode`] with a
    /// single-member epoch containing only `node_id`.
    #[must_use]
    pub fn bootstrap(node_id: u64, scheduler: Rc<RefCell<DeterministicMessageScheduler>>) -> Self {
        let identity = NodeIdentity::new(node_id);
        scheduler.borrow_mut().register_node(identity);
        let transport = LoopbackTransport::new(identity, Rc::clone(&scheduler));
        let members = EpochMemberSet::new(vec![identity]);
        Self {
            inner: SimNode::new(identity, transport, members),
        }
    }

    /// Encode and send a lease message to `peer`.
    ///
    /// Returns the assigned transport sequence number on success, or the
    /// encode error if serialization fails.
    ///
    /// # Errors
    ///
    /// Returns [`BinarySchemaError`] if [`encode_lease_message`] fails.
    pub fn send(
        &mut self,
        peer: &NodeIdentity,
        msg: &LeaseWireMessage,
    ) -> Result<Option<u64>, BinarySchemaError> {
        let payload = encode_lease_message(msg)?;
        Ok(self.inner.send_to(*peer, payload))
    }

    /// Try to receive and decode the next lease message for this node.
    ///
    /// Returns `Ok(None)` when no message is available, `Ok(Some(msg))` on
    /// success, and `Err(BinarySchemaError)` when a message is received but
    /// fails to decode.
    ///
    /// # Errors
    ///
    /// Returns [`BinarySchemaError`] if [`decode_lease_message`] fails on the
    /// received payload.
    pub fn recv(&mut self) -> Result<Option<LeaseWireMessage>, BinarySchemaError> {
        match self.inner.recv() {
            None => Ok(None),
            Some((msg, _stale)) => {
                let decoded = decode_lease_message(&msg.payload)?;
                Ok(Some(decoded))
            }
        }
    }

    /// Receive all currently available lease messages for this node.
    ///
    /// Invalid payloads skip gracefully — they return the error for each
    /// undecodable message rather than aborting the batch.
    ///
    /// # Errors
    ///
    /// Returns the first decoding error, or empty [`Ok`] if all messages
    /// were successfully drained (including the no-messages case).
    pub fn recv_all(&mut self) -> Result<Vec<LeaseWireMessage>, BinarySchemaError> {
        let mut results = Vec::new();
        while let Some((msg, _stale)) = self.inner.recv() {
            let decoded = decode_lease_message(&msg.payload)?;
            results.push(decoded);
        }
        Ok(results)
    }

    /// Access the underlying node identity.
    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        self.inner.identity
    }

    /// Delegate to the inner [`SimNode`] for direct access.
    #[must_use]
    pub fn as_inner(&self) -> &SimNode {
        &self.inner
    }

    /// Mutable access to the inner [`SimNode`].
    pub fn as_inner_mut(&mut self) -> &mut SimNode {
        &mut self.inner
    }
}

// ---------------------------------------------------------------------------
// Harness-integration tests for lease dispatch
// ---------------------------------------------------------------------------

#[cfg(test)]
mod harness_tests {
    use super::*;
    use crate::harness::{DeterministicMessageScheduler, SchedulerConfig, SimMessage};
    use std::cell::RefCell;
    use std::rc::Rc;
    use tidefs_lease::types::{LeaseClass, LeaseDomain};
    use tidefs_lease::wire::{
        LeaseGrantPayload, LeaseReleasePayload, LeaseRenewPayload, LeaseRequestPayload,
        LeaseRevokePayload, RevokeReason,
    };
    use tidefs_membership_epoch::{EpochId, MemberId};

    fn make_scheduler(seed: u64) -> Rc<RefCell<DeterministicMessageScheduler>> {
        Rc::new(RefCell::new(DeterministicMessageScheduler::new(
            SchedulerConfig::deterministic(seed),
        )))
    }

    fn sample_request() -> LeaseWireMessage {
        LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 1,
            lease_class: LeaseClass::Exclusive,
            domain: LeaseDomain::Inode {
                dataset_id: 42,
                ino: 100,
            },
            holder_id: MemberId(3),
            term_millis: 30_000,
            epoch: EpochId(7),
            mount_identity: DatasetMountIdentity::ZERO,
        })
    }

    fn sample_grant() -> LeaseWireMessage {
        use tidefs_lease::types::LeaseGrant;
        let grant = LeaseGrant::request(
            99,
            LeaseClass::Exclusive,
            LeaseDomain::Inode {
                dataset_id: 42,
                ino: 100,
            },
            MemberId(3),
            0u64,
            30_000,
            1_000,
            EpochId(7),
            DatasetMountIdentity::ZERO,
            1,
            3,
            5,
        );
        LeaseWireMessage::Grant(LeaseGrantPayload {
            request_id: 1,
            grant,
        })
    }

    // ------------------------------------------------------------------
    // Two-node lease roundtrip through harness
    // ------------------------------------------------------------------

    #[test]
    fn two_node_lease_request_grant_via_harness() {
        let sched = make_scheduler(42);

        let mut alice = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
        let mut bob = LeaseSimNode::bootstrap(2, Rc::clone(&sched));

        let req = sample_request();
        let expected_grant = sample_grant();

        // Alice sends a lease request to Bob
        alice
            .send(&bob.identity(), &req)
            .expect("alice send")
            .expect("alice send should not drop");

        sched.borrow_mut().tick();

        // Bob receives the request
        let bob_msg = bob
            .recv()
            .expect("bob recv")
            .expect("bob should have a message");
        assert_eq!(bob_msg, req, "bob received wrong request");

        // Bob sends a grant back to Alice
        bob.send(&alice.identity(), &expected_grant)
            .expect("bob send")
            .expect("bob send should not drop");

        sched.borrow_mut().tick();

        // Alice receives the grant
        let alice_msg = alice
            .recv()
            .expect("alice recv")
            .expect("alice should have a message");
        assert_eq!(alice_msg, expected_grant, "alice received wrong grant");
    }

    // ------------------------------------------------------------------
    // Multi-message exchange through harness
    // ------------------------------------------------------------------

    #[test]
    fn three_way_lease_exchange_via_harness() {
        let sched = make_scheduler(99);

        let mut n1 = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
        let mut n2 = LeaseSimNode::bootstrap(2, Rc::clone(&sched));
        let mut n3 = LeaseSimNode::bootstrap(3, Rc::clone(&sched));

        let req12 = sample_request();
        let req13 = LeaseWireMessage::Request(LeaseRequestPayload {
            request_id: 2,
            lease_class: LeaseClass::Shared,
            domain: LeaseDomain::Subtree {
                dataset_id: 42,
                prefix: "/shared/".into(),
            },
            holder_id: MemberId(1),
            term_millis: 60_000,
            epoch: EpochId(7),
            mount_identity: DatasetMountIdentity::ZERO,
        });
        let renew2 = LeaseWireMessage::Renew(LeaseRenewPayload {
            lease_id: 99,
            holder_id: MemberId(3),
            epoch: EpochId(7),
        });

        // N1 sends request to N2 and N3
        n1.send(&n2.identity(), &req12).expect("n1->n2");
        n1.send(&n3.identity(), &req13).expect("n1->n3");
        // N2 sends renewal to N1
        n2.send(&n1.identity(), &renew2).expect("n2->n1");

        sched.borrow_mut().tick();

        // Verify each recipient got the right message
        let n1_msgs = n1.recv_all().expect("n1 recv_all");
        assert_eq!(n1_msgs.len(), 1, "n1 should receive 1 message");
        assert_eq!(n1_msgs[0], renew2);

        let n2_msgs = n2.recv_all().expect("n2 recv_all");
        assert_eq!(n2_msgs.len(), 1, "n2 should receive 1 message");
        assert_eq!(n2_msgs[0], req12);

        let n3_msgs = n3.recv_all().expect("n3 recv_all");
        assert_eq!(n3_msgs.len(), 1, "n3 should receive 1 message");
        assert_eq!(n3_msgs[0], req13);
    }

    // ------------------------------------------------------------------
    // Request → Grant → Renew → Release lifecycle through harness
    // ------------------------------------------------------------------

    #[test]
    fn lease_lifecycle_via_harness() {
        let sched = make_scheduler(77);

        let mut alice = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
        let mut bob = LeaseSimNode::bootstrap(2, Rc::clone(&sched));

        let req = sample_request();
        let grant = sample_grant();
        let renew = LeaseWireMessage::Renew(LeaseRenewPayload {
            lease_id: 99,
            holder_id: MemberId(3),
            epoch: EpochId(8),
        });
        let release = LeaseWireMessage::Release(LeaseReleasePayload {
            lease_id: 99,
            holder_id: MemberId(3),
            epoch: EpochId(8),
        });

        // Step 1: Request → Grant
        alice.send(&bob.identity(), &req).expect("send req");
        sched.borrow_mut().tick();
        assert_eq!(bob.recv().expect("bob recv").expect("bob has req"), req);

        bob.send(&alice.identity(), &grant).expect("send grant");
        sched.borrow_mut().tick();
        assert_eq!(
            alice.recv().expect("alice recv").expect("alice has grant"),
            grant
        );

        // Step 2: Renew
        alice.send(&bob.identity(), &renew).expect("send renew");
        sched.borrow_mut().tick();
        assert_eq!(bob.recv().expect("bob recv").expect("bob has renew"), renew);

        // Step 3: Release
        alice.send(&bob.identity(), &release).expect("send release");
        sched.borrow_mut().tick();
        assert_eq!(
            bob.recv().expect("bob recv").expect("bob has release"),
            release
        );
    }

    // ------------------------------------------------------------------
    // Revoke message through harness
    // ------------------------------------------------------------------

    #[test]
    fn lease_revoke_via_harness() {
        let sched = make_scheduler(55);

        let mut alice = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
        let mut bob = LeaseSimNode::bootstrap(2, Rc::clone(&sched));

        let revoke = LeaseWireMessage::Revoke(LeaseRevokePayload {
            lease_id: 55,
            epoch: EpochId(3),
            reason: RevokeReason::Fencing,
        });

        alice.send(&bob.identity(), &revoke).expect("send revoke");
        sched.borrow_mut().tick();

        let bob_msg = bob
            .recv()
            .expect("bob recv")
            .expect("bob should have revoke");
        assert_eq!(bob_msg, revoke);
    }

    // ------------------------------------------------------------------
    // Garbage payload is rejected at decode
    // ------------------------------------------------------------------

    #[test]
    fn lease_harness_rejects_garbage() {
        let sched = make_scheduler(11);

        let mut alice = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
        let mut bob = LeaseSimNode::bootstrap(2, Rc::clone(&sched));

        // Send raw garbage (not a valid lease frame) directly through
        // the inner SimNode's transport to bypass LeaseSimNode::send.
        bob.inner.send_to(alice.identity(), vec![0xFFu8; 64]);

        sched.borrow_mut().tick();

        // Alice should fail to decode the garbage
        let result = alice.recv();
        assert!(
            result.is_err(),
            "garbage payload should produce decode error"
        );
    }

    // ------------------------------------------------------------------
    // Deterministic replay identical traces
    // ------------------------------------------------------------------

    #[test]
    fn lease_harness_deterministic_replay() {
        fn run_lifecycle(seed: u64) -> Vec<(u64, SimMessage)> {
            let sched = make_scheduler(seed);

            let mut a = LeaseSimNode::bootstrap(1, Rc::clone(&sched));
            let mut b = LeaseSimNode::bootstrap(2, Rc::clone(&sched));

            let req = sample_request();
            a.send(&b.identity(), &req).expect("a send");

            sched.borrow_mut().tick();
            let _ = b.recv();

            let grant = sample_grant();
            b.send(&a.identity(), &grant).expect("b send");

            sched.borrow_mut().tick();
            let _ = a.recv();

            let trace = sched.borrow().trace.clone();
            trace
        }

        let t1 = run_lifecycle(42);
        let t2 = run_lifecycle(42);
        assert_eq!(t1, t2, "identical seed must produce identical traces");

        // Different seed should still produce the same number of messages
        let t3 = run_lifecycle(99);
        assert_eq!(t1.len(), t3.len(), "different seeds same message count");
    }
}
