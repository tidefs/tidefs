//! Transport connection drain protocol: graceful in-flight completion and
//! peer acknowledgement handshake bridging the ConnectionState
//! `Draining -> Closed` transition.
//!
//! ## Purpose
//!
//! The connection state machine ([`crate::connection_state`]) defines a
//! `Draining` state but has no protocol-level handshake to coordinate
//! graceful shutdown between peers. Without a drain protocol, connection
//! teardown is abrupt: in-flight messages may be lost, and the remote peer
//! cannot distinguish intentional shutdown from a network fault.
//!
//! This module provides:
//!
//! - **DrainInitiator**: the side that decides to drain a connection.
//! - **DrainResponder**: the side that receives a drain request.
//! - **DrainRequest / DrainAck**: wire messages with bincode serialization.
//! - **PendingSendCounter**: in-flight message tracking.
//!
//! ## Protocol sequence
//!
//! ```text
//! Initiator                                Responder
//!     |                                        |
//!     |  stop new sends, wait pending -> 0     |
//!     |~~~~ DrainRequest(generation=N) ~~~~~~> |
//!     |                                        |  stop new sends, drain pending
//!     | <~~~~ DrainAck(generation=N) ~~~~~~~~~ |
//!     |                                        |
//!     v                                        v
//!   Closed                                  Closed
//! ```
//!
//! ## Wire format
//!
//! Messages are serialized with bincode. The framing layer (codec, channel
//! multiplexing) is handled by the existing transport pipeline; this module
//! only defines the bincode payload types.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::connection_state::ConnectionState;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default deadline for waiting for a `DrainAck` after sending `DrainRequest`.
pub const DEFAULT_DRAIN_DEADLINE_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// DrainRequest / DrainAck
// ---------------------------------------------------------------------------

/// A drain request sent by the initiating peer to request graceful shutdown.
///
/// The generation field ties this request to a specific connection lifecycle
/// generation, ensuring the responder does not act on a stale request from a
/// previous connection incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainRequest {
    /// Connection lifecycle generation at which the drain was initiated.
    pub generation: u64,
}

impl DrainRequest {
    /// Create a new drain request for the given generation.
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self { generation }
    }

    /// Serialize this request to bincode bytes.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize a drain request from bincode bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

/// A drain acknowledgement sent by the responding peer after it has
/// drained its own pending sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainAck {
    /// Echoed generation number from the corresponding `DrainRequest`.
    pub generation: u64,
}

impl DrainAck {
    /// Create a new drain ack for the given generation.
    #[must_use]
    pub fn new(generation: u64) -> Self {
        Self { generation }
    }

    /// Serialize this ack to bincode bytes.
    pub fn encode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize a drain ack from bincode bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// DrainProtocolError
// ---------------------------------------------------------------------------

/// Errors that can occur during the drain protocol handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainProtocolError {
    /// The drain was attempted but the connection is not in `Active` state.
    ConnectionNotActive {
        /// The state the connection was in when drain was attempted.
        current: ConnectionState,
    },
    /// Drain was already initiated on this connection.
    AlreadyDraining,
    /// The drain ack did not arrive within the configured deadline.
    DeadlineExceeded {
        /// Configured deadline duration.
        deadline: Duration,
    },
    /// The peer's drain ack generation does not match the request generation.
    GenerationMismatch {
        /// Expected generation from the drain request.
        expected: u64,
        /// Received generation in the drain ack.
        received: u64,
    },
    /// The peer rejected the drain request (sent an ack with a different
    /// generation indicating it is not in the right state).
    PeerNotReady,
    /// Bincode serialization or deserialization failure.
    Serialization(String),
}

impl fmt::Display for DrainProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionNotActive { current } => {
                write!(f, "connection not Active (current={current})")
            }
            Self::AlreadyDraining => f.write_str("drain already in progress"),
            Self::DeadlineExceeded { deadline } => {
                write!(f, "drain deadline exceeded ({deadline:?})")
            }
            Self::GenerationMismatch { expected, received } => {
                write!(
                    f,
                    "drain ack generation mismatch: expected {expected}, received {received}"
                )
            }
            Self::PeerNotReady => f.write_str("peer not ready for drain"),
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for DrainProtocolError {}

// ---------------------------------------------------------------------------
// PendingSendCounter
// ---------------------------------------------------------------------------

/// Thread-safe counter tracking in-flight sends on a connection.
///
/// The drain protocol uses this to wait until all pending sends have
/// completed before sending the `DrainRequest` or `DrainAck`.
#[derive(Clone, Debug, Default)]
pub struct PendingSendCounter {
    inner: Arc<AtomicU64>,
}

impl PendingSendCounter {
    /// Create a new counter initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increment the pending send count.
    pub fn increment(&self) {
        self.inner.fetch_add(1, Ordering::SeqCst);
    }

    /// Decrement the pending send count, returning the new value.
    ///
    /// Saturates at zero: decrementing when the counter is already zero
    /// returns 0 and leaves the counter at 0.
    pub fn decrement(&self) -> u64 {
        let prev = self.inner.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            self.inner.store(0, Ordering::SeqCst);
            return 0;
        }
        prev - 1
    }

    /// The current number of pending sends.
    pub fn pending(&self) -> u64 {
        self.inner.load(Ordering::SeqCst)
    }

    /// Returns `true` when no pending sends remain.
    pub fn is_zero(&self) -> bool {
        self.pending() == 0
    }
}

// ---------------------------------------------------------------------------
// DrainState
// ---------------------------------------------------------------------------

/// Per-side state of the drain protocol handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainState {
    /// Not draining; the connection is in some other lifecycle state.
    Idle,
    /// Drain initiated locally; new sends blocked, waiting for pending
    /// sends to complete.
    Draining,
    /// Drain request sent; waiting for DrainAck from the peer.
    DrainSent,
    /// Drain request received from peer; draining own pending sends.
    DrainReceived,
    /// Drain completed; the connection should be `Closed`.
    Closed,
}

impl fmt::Display for DrainState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Draining => write!(f, "Draining"),
            Self::DrainSent => write!(f, "DrainSent"),
            Self::DrainReceived => write!(f, "DrainReceived"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// DrainInitiator
// ---------------------------------------------------------------------------

/// State machine for the side that initiates a graceful connection drain.
///
/// After the membership or error-recovery layer decides to tear down a
/// connection, the initiator stops accepting new sends, waits for pending
/// sends to drain to zero, sends a `DrainRequest`, waits for a `DrainAck`
/// (with deadline), and then transitions the connection to `Closed`.
#[derive(Debug)]
pub struct DrainInitiator {
    state: DrainState,
    /// Generation at which the drain request was issued.
    drain_generation: u64,
    /// Deadline for receiving the DrainAck; `None` before the request is
    /// sent.
    deadline: Option<Instant>,
    /// The configured drain deadline duration.
    deadline_duration: Duration,
}

impl DrainInitiator {
    /// Create a new initiator with the given deadline duration.
    #[must_use]
    pub fn new(deadline_duration: Duration) -> Self {
        Self {
            state: DrainState::Idle,
            drain_generation: 0,
            deadline: None,
            deadline_duration,
        }
    }

    /// Create a new initiator with the default 5-second deadline.
    #[must_use]
    pub fn with_default_deadline() -> Self {
        Self::new(Duration::from_millis(DEFAULT_DRAIN_DEADLINE_MS))
    }

    /// Current drain state.
    #[must_use]
    pub fn state(&self) -> DrainState {
        self.state
    }

    /// The generation associated with the current drain operation.
    #[must_use]
    pub fn drain_generation(&self) -> u64 {
        self.drain_generation
    }

    /// Initiate the drain process.
    ///
    /// Records the drain generation and transitions from `Idle` to
    /// `Draining`.  The caller should stop accepting new sends and monitor
    /// the pending send counter.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyDraining` if the initiator is not `Idle`.
    pub fn initiate(&mut self, generation: u64) -> Result<(), DrainProtocolError> {
        if self.state != DrainState::Idle {
            return Err(DrainProtocolError::AlreadyDraining);
        }
        self.drain_generation = generation;
        self.state = DrainState::Draining;
        Ok(())
    }

    /// Build the `DrainRequest` to send to the peer.
    ///
    /// Call this once the pending send counter reaches zero.  Transitions
    /// from `Draining` to `DrainSent` and arms the deadline.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyDraining` if the initiator is not in the `Draining`
    /// state.
    pub fn build_drain_request(&mut self) -> Result<DrainRequest, DrainProtocolError> {
        if self.state != DrainState::Draining {
            return Err(DrainProtocolError::AlreadyDraining);
        }
        self.state = DrainState::DrainSent;
        self.deadline = Some(Instant::now() + self.deadline_duration);
        Ok(DrainRequest::new(self.drain_generation))
    }

    /// Process a `DrainAck` received from the peer.
    ///
    /// Validates the generation match and transitions to `Closed` on
    /// success.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyDraining` if not in `DrainSent` state.
    /// Returns `GenerationMismatch` if the ack generation does not match.
    pub fn handle_drain_ack(&mut self, ack: &DrainAck) -> Result<(), DrainProtocolError> {
        if self.state != DrainState::DrainSent {
            return Err(DrainProtocolError::AlreadyDraining);
        }
        if ack.generation != self.drain_generation {
            return Err(DrainProtocolError::GenerationMismatch {
                expected: self.drain_generation,
                received: ack.generation,
            });
        }
        self.state = DrainState::Closed;
        self.deadline = None;
        Ok(())
    }

    /// Check whether the drain deadline has been exceeded.
    ///
    /// Returns `true` if the initiator is in `DrainSent` state and the
    /// deadline has elapsed.  When the deadline fires, the caller should
    /// force-close the connection.
    #[must_use]
    pub fn is_deadline_exceeded(&self) -> bool {
        match self.deadline {
            Some(deadline) => Instant::now() >= deadline,
            None => false,
        }
    }

    /// Force the initiator to `Closed` (e.g., on deadline expiry or
    /// connection failure).  Returns the drain generation for lifecycle
    /// event emission.
    pub fn force_close(&mut self) -> u64 {
        self.state = DrainState::Closed;
        self.deadline = None;
        self.drain_generation
    }

    /// Returns `true` if the drain is complete (the connection should be
    /// `Closed`).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == DrainState::Closed
    }
}

// ---------------------------------------------------------------------------
// DrainResponder
// ---------------------------------------------------------------------------

/// State machine for the side that receives a drain request from the peer.
///
/// On receiving a `DrainRequest`, the responder stops accepting new sends,
/// waits for its own pending sends to drain to zero, sends a `DrainAck`,
/// and transitions to `Closed`.
#[derive(Debug)]
pub struct DrainResponder {
    state: DrainState,
    /// Generation from the peer's drain request, echoed back in the ack.
    peer_generation: u64,
}

impl DrainResponder {
    /// Create a new responder in `Idle` state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DrainState::Idle,
            peer_generation: 0,
        }
    }

    /// Current drain state.
    #[must_use]
    pub fn state(&self) -> DrainState {
        self.state
    }

    /// The peer's drain generation, if a request has been received.
    #[must_use]
    pub fn peer_generation(&self) -> u64 {
        self.peer_generation
    }

    /// Handle an incoming `DrainRequest`.
    ///
    /// Transitions from `Idle` to `DrainReceived` and records the peer's
    /// generation.  The caller should stop accepting new sends and wait
    /// for the pending send counter to reach zero before calling
    /// `build_drain_ack`.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyDraining` if the responder is not `Idle`.
    pub fn handle_drain_request(
        &mut self,
        request: &DrainRequest,
    ) -> Result<(), DrainProtocolError> {
        if self.state != DrainState::Idle {
            return Err(DrainProtocolError::AlreadyDraining);
        }
        self.peer_generation = request.generation;
        self.state = DrainState::DrainReceived;
        Ok(())
    }

    /// Build the `DrainAck` to send back to the initiator.
    ///
    /// Call this once the pending send counter reaches zero.  Transitions
    /// from `DrainReceived` to `Closed`.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyDraining` if the responder is not in
    /// `DrainReceived` state.
    pub fn build_drain_ack(&mut self) -> Result<DrainAck, DrainProtocolError> {
        if self.state != DrainState::DrainReceived {
            return Err(DrainProtocolError::AlreadyDraining);
        }
        let ack = DrainAck::new(self.peer_generation);
        self.state = DrainState::Closed;
        Ok(ack)
    }

    /// Force the responder to `Closed` (e.g., on connection failure).
    pub fn force_close(&mut self) {
        self.state = DrainState::Closed;
    }

    /// Returns `true` if the drain is complete (the connection should be
    /// `Closed`).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.state == DrainState::Closed
    }
}

impl Default for DrainResponder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DrainEvent
// ---------------------------------------------------------------------------

/// Additional lifecycle events emitted by the drain protocol.
///
/// These extend the base [`crate::connection_state::LifecycleEvent`] variants
/// with drain-specific events that the initiator or responder may emit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DrainEvent {
    /// A drain timeout occurred; forced close with the given generation.
    DrainTimeout { generation: u64 },
    /// The drain completed gracefully with ack from the peer.
    DrainAcknowledged { generation: u64 },
}

impl fmt::Display for DrainEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DrainTimeout { generation } => {
                write!(f, "DrainTimeout(gen={generation})")
            }
            Self::DrainAcknowledged { generation } => {
                write!(f, "DrainAcknowledged(gen={generation})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Convenience: complete the drain protocol for an initiator
// ---------------------------------------------------------------------------

/// Run the full initiator-side drain protocol given a pending send counter
/// and send/recv closures.
///
/// This is a synchronous convenience that encapsulates the common pattern:
///
/// 1. Initiate drain.
/// 2. Build and send `DrainRequest`.
/// 3. Wait with deadline for `DrainAck`.
/// 4. On ack: return `DrainEvent::DrainAcknowledged`.
/// 5. On timeout: force-close and return `DrainEvent::DrainTimeout`.
///
/// `try_recv_drain_ack` should return `None` when no ack is available
/// yet; the function will poll it while checking the deadline.
pub fn run_initiator_drain(
    initiator: &mut DrainInitiator,
    _pending: &PendingSendCounter,
    generation: u64,
    send_drain_request: impl FnOnce(&DrainRequest) -> Result<(), DrainProtocolError>,
    mut try_recv_drain_ack: impl FnMut() -> Option<DrainAck>,
) -> Result<DrainEvent, DrainProtocolError> {
    // Step 1: initiate.
    initiator.initiate(generation)?;

    // Step 2: build and send DrainRequest once pending sends reach zero.
    // The caller is responsible for ensuring pending is zero; we trust
    // the counter passed in.
    let request = initiator.build_drain_request()?;
    send_drain_request(&request)?;

    // Step 3: wait for DrainAck with deadline.
    loop {
        if let Some(ack) = try_recv_drain_ack() {
            initiator.handle_drain_ack(&ack)?;
            return Ok(DrainEvent::DrainAcknowledged {
                generation: initiator.drain_generation(),
            });
        }
        if initiator.is_deadline_exceeded() {
            let gen = initiator.force_close();
            return Ok(DrainEvent::DrainTimeout { generation: gen });
        }
        // Yield -- in real code this would be an async sleep or poll yield.
        std::thread::yield_now();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection_state::LifecycleEvent;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // ---- DrainRequest/DrainAck encode/decode round-trip ----

    #[test]
    fn drain_request_encode_decode_roundtrip() {
        let req = DrainRequest::new(42);
        let bytes = req.encode().unwrap();
        let decoded = DrainRequest::decode(&bytes).unwrap();
        assert_eq!(decoded, req);
        assert_eq!(decoded.generation, 42);
    }

    #[test]
    fn drain_ack_encode_decode_roundtrip() {
        let ack = DrainAck::new(99);
        let bytes = ack.encode().unwrap();
        let decoded = DrainAck::decode(&bytes).unwrap();
        assert_eq!(decoded, ack);
        assert_eq!(decoded.generation, 99);
    }

    #[test]
    fn drain_request_decode_empty_slice() {
        let result = DrainRequest::decode(b"");
        assert!(result.is_err());
    }

    // ---- PendingSendCounter ----

    #[test]
    fn pending_send_counter_inc_dec() {
        let counter = PendingSendCounter::new();
        assert_eq!(counter.pending(), 0);
        assert!(counter.is_zero());

        counter.increment();
        assert_eq!(counter.pending(), 1);
        assert!(!counter.is_zero());

        counter.increment();
        assert_eq!(counter.pending(), 2);

        let v = counter.decrement();
        assert_eq!(v, 1);
        assert_eq!(counter.pending(), 1);

        let v = counter.decrement();
        assert_eq!(v, 0);
        assert_eq!(counter.pending(), 0);
        assert!(counter.is_zero());
    }

    #[test]
    fn pending_send_counter_decrement_below_zero_saturates() {
        let counter = PendingSendCounter::new();
        let v = counter.decrement();
        assert_eq!(v, 0);
        assert_eq!(counter.pending(), 0);
    }

    #[test]
    fn pending_send_counter_clone_shares_state() {
        let a = PendingSendCounter::new();
        let b = a.clone();
        a.increment();
        assert_eq!(b.pending(), 1);
        b.decrement();
        assert_eq!(a.pending(), 0);
    }

    // ---- DrainState display ----

    #[test]
    fn drain_state_display() {
        assert_eq!(format!("{}", DrainState::Idle), "Idle");
        assert_eq!(format!("{}", DrainState::Draining), "Draining");
        assert_eq!(format!("{}", DrainState::DrainSent), "DrainSent");
        assert_eq!(format!("{}", DrainState::DrainReceived), "DrainReceived");
        assert_eq!(format!("{}", DrainState::Closed), "Closed");
    }

    // ---- DrainInitiator happy path ----

    #[test]
    fn initiator_happy_path_drain() {
        let mut init = DrainInitiator::with_default_deadline();
        assert_eq!(init.state(), DrainState::Idle);

        // Initiate.
        init.initiate(3).unwrap();
        assert_eq!(init.state(), DrainState::Draining);
        assert_eq!(init.drain_generation(), 3);

        // Build drain request.
        let req = init.build_drain_request().unwrap();
        assert_eq!(req.generation, 3);
        assert_eq!(init.state(), DrainState::DrainSent);

        // Handle ack.
        let ack = DrainAck::new(3);
        init.handle_drain_ack(&ack).unwrap();
        assert_eq!(init.state(), DrainState::Closed);
        assert!(init.is_complete());
    }

    // ---- DrainInitiator: rejection paths ----

    #[test]
    fn initiator_rejects_double_initiate() {
        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(1).unwrap();
        let err = init.initiate(2).unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn initiator_rejects_build_request_before_initiate() {
        let mut init = DrainInitiator::with_default_deadline();
        let err = init.build_drain_request().unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn initiator_rejects_double_build_request() {
        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(1).unwrap();
        init.build_drain_request().unwrap();
        let err = init.build_drain_request().unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn initiator_rejects_ack_when_not_drain_sent() {
        let mut init = DrainInitiator::with_default_deadline();
        let ack = DrainAck::new(1);
        let err = init.handle_drain_ack(&ack).unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);

        // Even after initiate but before build_drain_request, ack should fail.
        init.initiate(1).unwrap();
        let err = init.handle_drain_ack(&ack).unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn initiator_rejects_generation_mismatch() {
        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(7).unwrap();
        init.build_drain_request().unwrap();
        let ack = DrainAck::new(999); // wrong generation
        let err = init.handle_drain_ack(&ack).unwrap_err();
        assert_eq!(
            err,
            DrainProtocolError::GenerationMismatch {
                expected: 7,
                received: 999
            }
        );
        // State unchanged on error.
        assert_eq!(init.state(), DrainState::DrainSent);
    }

    // ---- DrainInitiator: deadline ----

    #[test]
    fn initiator_deadline_not_exceeded_immediately() {
        let mut init = DrainInitiator::new(Duration::from_secs(60));
        init.initiate(1).unwrap();
        init.build_drain_request().unwrap();
        assert!(!init.is_deadline_exceeded());
    }

    #[test]
    fn initiator_deadline_exceeded_after_zero_duration() {
        let mut init = DrainInitiator::new(Duration::from_secs(0));
        init.initiate(1).unwrap();
        init.build_drain_request().unwrap();
        // With 0 duration, the deadline should be exceeded immediately.
        thread::sleep(Duration::from_millis(1));
        assert!(init.is_deadline_exceeded());
    }

    #[test]
    fn initiator_force_close() {
        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(5).unwrap();
        init.build_drain_request().unwrap();
        let gen = init.force_close();
        assert_eq!(gen, 5);
        assert_eq!(init.state(), DrainState::Closed);
        assert!(init.is_complete());
    }

    // ---- DrainInitiator: idempotency ----

    #[test]
    fn initiator_second_initiate_is_noop() {
        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(1).unwrap();
        let err = init.initiate(2).unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
        assert_eq!(init.drain_generation(), 1); // original generation preserved
    }

    // ---- DrainResponder happy path ----

    #[test]
    fn responder_happy_path() {
        let mut resp = DrainResponder::new();
        assert_eq!(resp.state(), DrainState::Idle);

        // Receive drain request.
        let req = DrainRequest::new(10);
        resp.handle_drain_request(&req).unwrap();
        assert_eq!(resp.state(), DrainState::DrainReceived);
        assert_eq!(resp.peer_generation(), 10);

        // Build drain ack.
        let ack = resp.build_drain_ack().unwrap();
        assert_eq!(ack.generation, 10);
        assert_eq!(resp.state(), DrainState::Closed);
        assert!(resp.is_complete());
    }

    // ---- DrainResponder: rejection paths ----

    #[test]
    fn responder_rejects_double_request() {
        let mut resp = DrainResponder::new();
        let req1 = DrainRequest::new(1);
        resp.handle_drain_request(&req1).unwrap();
        let req2 = DrainRequest::new(2);
        let err = resp.handle_drain_request(&req2).unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn responder_rejects_build_ack_before_request() {
        let mut resp = DrainResponder::new();
        let err = resp.build_drain_ack().unwrap_err();
        assert_eq!(err, DrainProtocolError::AlreadyDraining);
    }

    #[test]
    fn responder_force_close() {
        let mut resp = DrainResponder::new();
        let req = DrainRequest::new(3);
        resp.handle_drain_request(&req).unwrap();
        resp.force_close();
        assert_eq!(resp.state(), DrainState::Closed);
        assert!(resp.is_complete());
    }

    // ---- Bidirectional drain (concurrent init) ----

    #[test]
    fn bidirectional_concurrent_drain() {
        let mut init_a = DrainInitiator::with_default_deadline();
        let mut resp_b = DrainResponder::new();

        // Side A initiates drain.
        init_a.initiate(100).unwrap();
        let req_a = init_a.build_drain_request().unwrap();
        assert_eq!(req_a.generation, 100);

        // Side B handles Side A's request.
        resp_b.handle_drain_request(&req_a).unwrap();
        assert_eq!(resp_b.state(), DrainState::DrainReceived);
        let ack_b = resp_b.build_drain_ack().unwrap();
        assert_eq!(ack_b.generation, 100);

        // Side A processes the ack.
        init_a.handle_drain_ack(&ack_b).unwrap();
        assert!(init_a.is_complete());
        assert!(resp_b.is_complete());
    }

    // ---- Drain with in-flight messages ----

    #[test]
    fn drain_with_in_flight_messages() {
        let counter = PendingSendCounter::new();
        counter.increment();
        counter.increment();
        counter.increment();
        assert_eq!(counter.pending(), 3);

        let mut init = DrainInitiator::with_default_deadline();
        init.initiate(42).unwrap();

        // Pending sends still in flight; drain them.
        assert!(!counter.is_zero());
        counter.decrement();
        counter.decrement();
        counter.decrement();
        assert!(counter.is_zero());

        // Now build the drain request.
        let req = init.build_drain_request().unwrap();
        assert_eq!(req.generation, 42);
    }

    // ---- Drain timeout simulation ----

    #[test]
    fn drain_timeout_simulation() {
        let mut init = DrainInitiator::new(Duration::from_millis(10));
        init.initiate(1).unwrap();
        init.build_drain_request().unwrap();
        assert!(!init.is_deadline_exceeded());

        // Sleep past the deadline.
        thread::sleep(Duration::from_millis(20));
        assert!(init.is_deadline_exceeded());

        let gen = init.force_close();
        assert_eq!(gen, 1);
        assert_eq!(init.state(), DrainState::Closed);
    }

    // ---- run_initiator_drain convenience ----

    #[test]
    fn run_initiator_drain_success() {
        let mut init = DrainInitiator::new(Duration::from_secs(60));
        let pending = PendingSendCounter::new();
        let generation = 7u64;

        let ack = DrainAck::new(generation);
        let mut ack_provided = false;
        let result = run_initiator_drain(
            &mut init,
            &pending,
            generation,
            |req| {
                assert_eq!(req.generation, generation);
                Ok(())
            },
            || {
                if !ack_provided {
                    ack_provided = true;
                    Some(ack.clone())
                } else {
                    None
                }
            },
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            DrainEvent::DrainAcknowledged { generation: 7 }
        );
        assert!(init.is_complete());
    }

    #[test]
    fn run_initiator_drain_timeout() {
        let mut init = DrainInitiator::new(Duration::from_millis(10));
        let pending = PendingSendCounter::new();
        let generation = 1u64;

        let result = run_initiator_drain(
            &mut init,
            &pending,
            generation,
            |_req| Ok(()),
            || None, // never returns an ack
        );
        assert!(result.is_ok());
        match result.unwrap() {
            DrainEvent::DrainTimeout { generation } => {
                assert_eq!(generation, 1);
            }
            other => panic!("expected DrainTimeout, got {other:?}"),
        }
        assert!(init.is_complete());
    }

    // ---- DrainProtocolError display ----

    #[test]
    fn drain_protocol_error_display() {
        let err = DrainProtocolError::ConnectionNotActive {
            current: ConnectionState::Disconnected,
        };
        assert!(format!("{err}").contains("Disconnected"));

        let err = DrainProtocolError::DeadlineExceeded {
            deadline: Duration::from_secs(5),
        };
        assert!(format!("{err}").contains("5s"));

        let err = DrainProtocolError::GenerationMismatch {
            expected: 1,
            received: 2,
        };
        assert!(format!("{err}").contains("expected 1"));
        assert!(format!("{err}").contains("received 2"));
    }

    // ---- DrainEvent display ----

    #[test]
    fn drain_event_display() {
        assert_eq!(
            format!("{}", DrainEvent::DrainTimeout { generation: 5 }),
            "DrainTimeout(gen=5)"
        );
        assert_eq!(
            format!("{}", DrainEvent::DrainAcknowledged { generation: 7 }),
            "DrainAcknowledged(gen=7)"
        );
    }

    // ---- Drain with LifecycleBus integration ----

    #[test]
    fn drain_complete_broadcasts_event() {
        use crate::connection_state::{ConnectionLifecycle, LifecycleBus, LifecycleSubscriber};
        use std::sync::atomic::{AtomicU64, Ordering};

        struct RecordingSub {
            last_gen: AtomicU64,
        }
        impl LifecycleSubscriber for RecordingSub {
            fn on_lifecycle_event(&self, event: &LifecycleEvent) {
                self.last_gen.store(event.generation(), Ordering::SeqCst);
            }
        }

        let sub = Arc::new(RecordingSub {
            last_gen: AtomicU64::new(0),
        });

        struct ArcSub {
            inner: Arc<RecordingSub>,
        }
        impl LifecycleSubscriber for ArcSub {
            fn on_lifecycle_event(&self, event: &LifecycleEvent) {
                self.inner.on_lifecycle_event(event);
            }
        }

        let mut bus = LifecycleBus::new();
        bus.subscribe(Box::new(ArcSub { inner: sub.clone() }));

        // Simulate the full lifecycle: Active -> Draining -> Closed.
        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle
            .transition_to(ConnectionState::Connecting)
            .unwrap();
        lifecycle
            .transition_to(ConnectionState::Handshaking)
            .unwrap();
        lifecycle.transition_to(ConnectionState::Active).unwrap();

        let drain_event = lifecycle.transition_to(ConnectionState::Draining).unwrap();
        assert!(matches!(drain_event, LifecycleEvent::DrainStarted { .. }));

        let closed_event = lifecycle.transition_to(ConnectionState::Closed).unwrap();
        assert!(matches!(closed_event, LifecycleEvent::DrainComplete { .. }));

        bus.broadcast(&closed_event);
        assert_eq!(
            sub.last_gen.load(Ordering::SeqCst),
            closed_event.generation()
        );
    }

    // ---- Integration test: full Active->Draining->Closed lifecycle ----

    #[test]
    fn full_lifecycle_integration_with_drain_protocol() {
        use crate::connection_state::ConnectionLifecycle;

        let mut lifecycle = ConnectionLifecycle::new();
        assert_eq!(lifecycle.state(), ConnectionState::Disconnected);

        // Progress to Active.
        lifecycle
            .transition_to(ConnectionState::Connecting)
            .unwrap();
        lifecycle
            .transition_to(ConnectionState::Handshaking)
            .unwrap();
        lifecycle.transition_to(ConnectionState::Active).unwrap();
        assert!(lifecycle.is_active());

        // Initiate drain via protocol.
        let mut init = DrainInitiator::with_default_deadline();
        let gen_at_initiate = lifecycle.generation();
        init.initiate(gen_at_initiate).unwrap();

        // Transition ConnectionState to Draining.
        let ev = lifecycle.transition_to(ConnectionState::Draining).unwrap();
        assert!(matches!(ev, LifecycleEvent::DrainStarted { .. }));

        // Build and send DrainRequest.
        let req = init.build_drain_request().unwrap();
        // The request's generation is the one captured at initiate time.
        assert_eq!(req.generation, init.drain_generation());

        // Simulate receiving DrainAck.
        let ack = DrainAck::new(req.generation);
        init.handle_drain_ack(&ack).unwrap();
        assert!(init.is_complete());

        // Transition ConnectionState to Closed.
        let ev = lifecycle.transition_to(ConnectionState::Closed).unwrap();
        assert!(matches!(ev, LifecycleEvent::DrainComplete { .. }));
        assert_eq!(lifecycle.state(), ConnectionState::Closed);
    }
}
