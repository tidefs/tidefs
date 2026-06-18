// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport outbound send pipeline: from message submission through
//! length-delimited framing to async TCP socket write, complementing
//! the inbound receive loop ([`crate::receive_loop`]).
//!
//! ## Architecture
//!
//! ```text
//! MessageFamily + payload
//!        |
//!        v
//! SendPipelineHandle::send(family, payload)
//!        |
//!        +-- check roster send-gate (if configured, PeerNotInRoster otherwise)
//!        +-- check connection state gate (Accepted/Connected/Draining ok)
//!        +-- frame via SendFramer (binary-schema envelope + payload)
//!        +-- push framed bytes into mpsc channel
//!              |
//!              v
//!         SendPipeline::run()
//!              |
//!              +-- drain mpsc receiver, batch frames
//!              +-- writev gather-output to TcpStream (write half)
//!              +-- loop until channel closed or state -> Closed
//! ```
//!
//! ## Frame format
//!
//! Frames use the canonical binary-schema envelope header (64 bytes) followed
//! by the payload body, matching the format decoded by the receive loop's
//! [`FramingDecoder`]. The header carries `total_body_bytes` (u64 LE at offset
//! 32) which the decoder uses to delimit frames.
//!
//! ## Roster send-gating
//!
//! When a [`SendGate`](crate::SendGate) is attached via
//! [`SendPipelineHandle::with_send_gate`], every send consults
//! [`SendGate::can_send_to`] before enqueueing. Messages targeting
//! peers not in the current committed membership roster are rejected
//! with [`SendPipelineError::PeerNotInRoster`]. This closes the race
//! window between roster eviction and asynchronous session teardown
//! (handled by the `MembershipTransportBridge` in `tidefs-membership-live`).
//! Without a gate (the default), all sends proceed subject only to
//! connection-state checks.
//!
//! ## Connection state gating
//!
//! Sends are gated by the connection lifecycle state:
//!
//! | State        | Send allowed? |
//! |--------------|---------------|
//! | Connecting   | No            |
//! | Accepted     | Yes           |
//! | Connected    | Yes           |
//! | Draining     | Yes           |
//! | Drained      | No            |
//! | Closed       | No            |
//!
//! ## writev batching
//!
//! ## Session-class-aware priority dispatch
//!
//! When [`SendPipelineHandle::with_session_class`] is called, the default
//! [`send`](SendPipelineHandle::send) and [`try_send`](SendPipelineHandle::try_send)
//! methods derive [`SendPriority`] from the bound [`SessionClass`] via
//! [`session_class_to_send_priority`]:
//!
//! | SessionClass              | SendPriority  |
//! |---------------------------|---------------|
//! | `Bootstrap`, `Control`    | `Control`     |
//! | `ReplicationMeta`, `TransitionOrchestration` | `Membership` |
//! | `TransferBulk`, `ShadowValidation` | `Bulk`  |
//!
//! This prevents data-plane head-of-line blocking: control-plane messages
//! (membership, epoch, leases) are dequeued ahead of bulk data transfer
//! messages when both share the same TCP connection. The existing weighted
//! round-robin scheduler in [`SendScheduler`] handles starvation prevention
//! and burst fairness across priority classes.
//!
//! When multiple frames are queued in the mpsc channel, the pipeline drains
//! up to `max_batch_frames` in one pass and writes them via vectored I/O
//! ([`tokio::io::AsyncWriteExt::write_all_vectored`]), reducing syscall
//! overhead under load.
//!
//! ## Send-path backpressure (water-mark model)
//!
//! When [`SendPipelineHandle::with_backpressure`] is called, the outbound
//! send path enforces a byte-level water-mark model to prevent unbounded
//! memory growth under receiver slowdown:
//!
//! - **High-water mark**: When the pipeline byte depth reaches
//!   [`SendBackpressureConfig::high_water_mark`], new sends are rejected
//!   with [`SendPipelineError::SendBackpressure`], carrying the session
//!   identifier and current queue depth in bytes.
//! - **Low-water mark**: After backpressure has been signalled, the
//!   pipeline drain loop monitors depth. When it drops below
//!   [`SendBackpressureConfig::low_water_mark`], the
//!   [`backpressure_ready`](SendPipelineHandle::backpressure_ready) watch
//!   channel fires `true`, notifying callers that the pipeline can
//!   accept new sends again.
//!
//! The depth counter is stored in a shared [`SendBackpressureState`] behind
//! an `Arc`, with atomic increment on send and atomic decrement on drain.
//! This enables concurrent producers (multiple `SendPipelineHandle` clones)
//! to share a single backpressure signal per TCP connection.
//!
//! ```text
//! send() / try_send()
//!        |
//!        +-- check_backpressure_before_enqueue(wire_size)
//!        |     |
//!        |     +-- depth + wire_size >= high_water_mark?
//!        |            YES -> Err(SendBackpressure { session_id, queue_depth })
//!        |            NO  -> record_enqueue(wire_size), proceed to mpsc
//!        |
//!        v
//!   SendPipeline::run()
//!        |
//!        +-- write batch to TCP socket
//!        +-- record_drain(total_bytes)
//!        +-- check_drain_and_notify()
//!              |
//!              +-- depth < low_water_mark && was under pressure?
//!                   YES -> ready_tx.send(true)  // fires backpressure_ready
//! ```
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::{mpsc, oneshot, watch, RwLock};

use tidefs_binary_schema_core::SchemaVersion;
use tidefs_binary_schema_framing::EnvelopeBuilder;

use crate::barrier::{OutboundItemCounter, SendBarrier};
use crate::channel::ChannelId;
use crate::circuit_breaker::PeerId;
use crate::connection_registry::ConnectionState;
use crate::envelope::MessageFamily;
use crate::frame_governance::{FrameSizeError, FrameSizeGovernor};
use crate::idle_timeout::IdleTracker;
use crate::receive_flow::SenderCreditTracker;
use crate::receive_loop::message_family_to_family_id;
use crate::send_admission::{
    SendAdmission, SendAdmissionEvidence, SendAdmissionOutcome, SendAdmissionPolicy,
    SendCapacityClass, SendCapacityEvidence, SendWakeEvidence,
};
use crate::send_backpressure::{SendCapacity, SendCapacitySet, SendWatermarkConfig};
use crate::send_coalesce::{CoalesceKey, SendCoalescer};
use crate::send_concurrency::{SendConcurrencyError, SendConcurrencyLimiter};
use crate::send_deadline::{
    deadline_channel, resolve_deadline, DeadlineOutcome, DeadlineToken, MessageDeadline,
    SendDeadlineConfig,
};
use crate::send_gate::SendGate;
use crate::send_scheduler::{SendPriority, SendScheduler, SendSchedulerConfig};
use crate::types::SessionId;
use tidefs_types_transport_session::SessionClass;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default capacity of the mpsc channel between handle and pipeline.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// Maximum frames to batch in one writev call.
pub const DEFAULT_MAX_BATCH_FRAMES: usize = 64;

/// Header size of a binary-schema envelope frame (64 bytes).
pub const ENVELOPE_HEADER_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// OutboundFrame
// ---------------------------------------------------------------------------

/// A framed message queued in the outbound send pipeline, with an
/// optional send deadline and a oneshot channel for cancellation
/// signalling.
pub struct OutboundFrame {
    /// The framed message bytes (binary-schema envelope + payload).
    pub data: Vec<u8>,
    /// Optional deadline instant. The pipeline checks this before
    /// transmission and drops the frame if expired.
    pub deadline: Option<tokio::time::Instant>,
    /// Optional oneshot sender to signal the caller about the outcome
    /// (delivered or cancelled).
    pub outcome_tx: Option<tokio::sync::oneshot::Sender<DeadlineOutcome>>,
    /// Optional send-barrier completion marker.
    pub barrier_tx: Option<oneshot::Sender<()>>,
}

impl OutboundFrame {
    /// Create a frame with no deadline and no outcome signalling.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            deadline: None,
            outcome_tx: None,
            barrier_tx: None,
        }
    }

    /// Create a barrier marker frame. The pipeline completes it without
    /// writing bytes once all earlier scheduled frames have been dequeued.
    fn barrier(completion: oneshot::Sender<()>) -> Self {
        Self {
            data: Vec::new(),
            deadline: None,
            outcome_tx: None,
            barrier_tx: Some(completion),
        }
    }
}

impl From<Vec<u8>> for OutboundFrame {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

// ---------------------------------------------------------------------------
// SendBackpressureConfig
// ---------------------------------------------------------------------------

/// Configuration for per-session send-path backpressure water marks.
///
/// The high-water mark gates new sends: when queue depth (in bytes) reaches
/// `high_water_mark`, [`SendPipelineHandle::send`] and
/// [`SendPipelineHandle::try_send`] return
/// [`SendPipelineError::SendBackpressure`].
///
/// The low-water mark resumes sends: after backpressure has been signalled
/// (`high_water_mark` exceeded), the [`backpressure_ready`] watch channel
/// fires `true` when depth drains below `low_water_mark`.
///
/// Sensible defaults: high-water at 1 MiB, low-water at 256 KiB.
/// Set `high_water_mark` to 0 to disable backpressure checks entirely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendBackpressureConfig {
    /// Queue depth (bytes) at which new sends are rejected with
    /// [`SendPipelineError::SendBackpressure`].
    pub high_water_mark: usize,
    /// Queue depth (bytes) below which backpressure is cleared and
    /// [`backpressure_ready`](SendPipelineHandle::backpressure_ready)
    /// fires.
    pub low_water_mark: usize,
}

impl Default for SendBackpressureConfig {
    fn default() -> Self {
        Self {
            high_water_mark: 1_048_576, // 1 MiB
            low_water_mark: 262_144,    // 256 KiB
        }
    }
}

// ---------------------------------------------------------------------------
// SendBackpressureState
// ---------------------------------------------------------------------------

/// Per-pipeline shared backpressure tracking: atomic byte-depth counter
/// and a [`watch`] channel for drain-notification.
///
/// The pipeline drain loop decrements the counter as frames are written;
/// senders (`SendPipelineHandle`) atomically increment before enqueue
/// and check against the configured water marks.
#[derive(Debug)]
pub struct SendBackpressureState {
    /// Current byte depth of queued-but-unsent frames.
    depth: AtomicUsize,
    /// True when depth has exceeded high-water and not yet drained below
    /// low-water.
    under_pressure: AtomicBool,
    /// Watch sender: fires `true` when pressure clears.
    ready_tx: watch::Sender<bool>,
    /// Low-water mark: depth below which backpressure is cleared.
    low_water_mark: AtomicUsize,
}

impl SendBackpressureState {
    /// Create a new backpressure state. The initial value on the watch
    /// channel is `true` (i.e. ready to send).
    #[must_use]
    pub fn new() -> Self {
        let (ready_tx, _) = watch::channel(true);
        Self {
            depth: AtomicUsize::new(0),
            under_pressure: AtomicBool::new(false),
            ready_tx,
            low_water_mark: AtomicUsize::new(0),
        }
    }

    /// Increment the byte-depth counter by `n` bytes.
    /// Called by senders before enqueuing a frame.
    pub fn record_enqueue(&self, n: usize) {
        self.depth.fetch_add(n, Ordering::Release);
    }

    /// Decrement the byte-depth counter by `n` bytes.
    /// Called by the drain loop after writing frames.
    pub fn record_drain(&self, n: usize) {
        self.depth.fetch_sub(n, Ordering::Release);
    }

    /// Return the current byte depth.
    pub fn depth(&self) -> usize {
        self.depth.load(Ordering::Acquire)
    }

    /// Check whether enqueuing `n` more bytes would exceed `high_water_mark`.
    /// Does NOT modify the counter. Returns `Ok(())` if under the mark.
    pub fn check_high_water(&self, high_water_mark: usize, n: usize) -> Result<(), usize> {
        if high_water_mark == 0 {
            return Ok(());
        }
        let current = self.depth.load(Ordering::Acquire);
        let projected = current.saturating_add(n);
        if projected >= high_water_mark {
            self.under_pressure.store(true, Ordering::Release);
            return Err(current);
        }
        Ok(())
    }

    /// Check whether depth has drained below `low_water_mark` after
    /// being under pressure. If so, clear the flag and notify waiters.
    pub fn check_drain_and_notify(&self) {
        if self.under_pressure.load(Ordering::Acquire) {
            let current = self.depth.load(Ordering::Acquire);
            let lwm = self.low_water_mark.load(Ordering::Acquire);
            if lwm > 0 && current < lwm {
                self.under_pressure.store(false, Ordering::Release);
                // Best-effort notify: ignore error if no receivers.
                let _ = self.ready_tx.send(true);
            }
        }
    }

    /// Subscribe to backpressure-ready notifications.
    /// Returns a receiver that fires `true` when the pipeline
    /// drains below the low-water mark after backpressure.
    pub fn subscribe_ready(&self) -> watch::Receiver<bool> {
        self.ready_tx.subscribe()
    }

    /// Set the low-water mark for drain-notification.
    pub fn set_low_water_mark(&self, lwm: usize) {
        self.low_water_mark.store(lwm, Ordering::Release);
    }
}

impl Default for SendBackpressureState {
    fn default() -> Self {
        Self::new()
    }
}
// ---------------------------------------------------------------------------
// SessionClass → SendPriority mapping
// ---------------------------------------------------------------------------

/// Map a [`SessionClass`] to a [`SendPriority`] for outbound dispatch ordering.
///
/// Session classes are coalesced into priority tiers that prevent data-plane
/// head-of-line blocking of control-plane messages:
///
/// | SessionClass                | SendPriority  | Rationale                              |
/// |-----------------------------|---------------|----------------------------------------|
/// | `Bootstrap`                 | `Control`     | Join/bootstrap must complete quickly.  |
/// | `Control`                   | `Control`     | Membership, leases, epoch transitions. |
/// | `ReplicationMeta`           | `Membership`  | Publication/progress metadata.         |
/// | `TransitionOrchestration`   | `Membership`  | Failover/upgrade cutover coordination. |
/// | `TransferBulk`              | `Bulk`        | Bulk data-plane transfer.              |
/// | `ShadowValidation`            | `Bulk`        | Shadow compare / validation transport.   |
///
/// Callers that need explicit priority per individual message can use
/// [`SendPipelineHandle::send_with_priority`] directly.
#[must_use]
pub fn session_class_to_send_priority(sc: SessionClass) -> SendPriority {
    match sc {
        SessionClass::Bootstrap => SendPriority::Control,
        SessionClass::Control => SendPriority::Control,
        SessionClass::ReplicationMeta => SendPriority::Membership,
        SessionClass::TransitionOrchestration => SendPriority::Membership,
        SessionClass::TransferBulk => SendPriority::Bulk,
        SessionClass::ShadowValidation => SendPriority::Bulk,
    }
}
// ---------------------------------------------------------------------------
// SendFramer
// ---------------------------------------------------------------------------

/// Encodes a message into a binary-schema length-delimited frame compatible
/// with the receive loop's [`FramingDecoder`].
///
/// The frame consists of a 64-byte envelope header followed by the payload
/// bytes. The header carries `total_body_bytes` (u64 LE) which the decoder
/// uses for frame delimiting.
///
/// # Format
///
/// ```text
/// [0..64)   envelope header (binary-schema, "VBFS" magic)
/// [64..)    payload bytes
/// ```
#[derive(Clone, Debug)]
pub struct SendFramer;

impl SendFramer {
    /// Frame a message for transmission.
    ///
    /// - `family`: The transport message family.
    /// - `channel_id`: Channel stream-ID for demux (0 = untagged).
    /// - `payload`: The serialized message payload bytes.
    ///
    /// Returns the complete framed bytes ready for socket write.
    #[must_use]
    pub fn frame(family: MessageFamily, channel_id: ChannelId, payload: &[u8]) -> Vec<u8> {
        let family_id = message_family_to_family_id(family);
        let type_id = tidefs_binary_schema_core::SchemaTypeId(channel_id.as_u16() as u64);

        let header = EnvelopeBuilder::new(family_id, type_id, SchemaVersion { major: 1, minor: 0 })
            .build(0, payload.len() as u64);

        let header_bytes = header.encode();
        let mut frame = Vec::with_capacity(header_bytes.len() + payload.len());
        frame.extend_from_slice(&header_bytes);
        frame.extend_from_slice(payload);
        frame
    }

    /// Return the total wire size for a given payload length.
    #[must_use]
    pub const fn wire_size(payload_len: usize) -> usize {
        ENVELOPE_HEADER_SIZE + payload_len
    }
}

// ---------------------------------------------------------------------------
// SendPipelineError
// ---------------------------------------------------------------------------

/// Errors from the outbound send pipeline.
#[derive(Debug, thiserror::Error)]
pub enum SendPipelineError {
    /// The connection is not in a sendable state.
    #[error("connection state {0} does not permit sends")]
    ConnectionStateClosed(ConnectionState),

    /// The pipeline channel is full (backpressure).
    #[error("send pipeline channel full, capacity {0}")]
    ChannelFull(usize),

    /// The pipeline has been shut down.
    #[error("send pipeline shut down")]
    Shutdown,

    /// An I/O error occurred writing to the socket.
    #[error("socket write error: {0}")]
    Io(#[from] std::io::Error),

    /// The send-concurrency limit has been reached.
    #[error("send concurrency limit exceeded: {0}")]
    ConcurrencyLimitExceeded(#[from] SendConcurrencyError),

    /// The target peer is not in the current committed membership roster.
    #[error("peer {0} not in roster")]
    PeerNotInRoster(PeerId),

    /// The per-session send queue is above the high-water mark.
    /// Carries the session identifier and the current byte depth so
    /// callers can inspect congestion level and await drain.
    #[error("send backpressure on session {session_id}: queue depth {queue_depth} bytes >= high-water mark")]
    SendBackpressure {
        /// Session whose send queue is congested.
        session_id: SessionId,
        queue_depth: usize,
    },

    /// The outbound payload exceeds the configured per-session frame-size cap.
    #[error("frame too large: {0}")]
    FrameTooLarge(#[from] FrameSizeError),
}

// ---------------------------------------------------------------------------
// SendPipelineHandle
// ---------------------------------------------------------------------------

/// Cloneable handle for submitting messages to the outbound send pipeline.
///
/// Each handle shares a reference to the connection state (for gating) and
/// an mpsc sender to the pipeline's drain loop. Handles are cheap to clone
/// and can be distributed to subsystem dispatchers.
#[derive(Clone, Debug)]
pub struct SendPipelineHandle {
    /// Shared connection lifecycle state for gating sends.
    state: Arc<RwLock<ConnectionState>>,
    /// Sender half of the framed-bytes channel to the pipeline.
    tx: mpsc::Sender<(SendPriority, OutboundFrame)>,
    /// Channel capacity for backpressure diagnostics.
    capacity: usize,
    /// Monotonic enqueue counter used for barrier ahead-count snapshots.
    counter: Arc<OutboundItemCounter>,
    /// Optional per-connection send-concurrency limiter.
    send_concurrency: Option<Arc<SendConcurrencyLimiter>>,
    /// Session class for this connection, used to derive the default
    /// [`SendPriority`] for [`send`](Self::send) and related methods.
    /// When `None`, falls back to [`SendPriority::Data`].
    session_class: Option<SessionClass>,
    /// Optional roster-gated send check. When set, every send consults
    /// `can_send_to(peer_id)` before enqueueing and returns
    /// [`SendPipelineError::PeerNotInRoster`] when the gate returns `false`.
    send_gate: Option<Arc<dyn SendGate>>,
    /// Peer id of this connection, used for the send-gate check.
    peer_id: Option<PeerId>,
    /// Shared backpressure water-mark state, if configured.
    backpressure_state: Option<Arc<SendBackpressureState>>,
    /// Backpressure config for this pipeline.
    backpressure_config: Option<SendBackpressureConfig>,
    capacity_set: Option<SendCapacitySet>,
    /// Session identifier for backpressure error context.
    /// Optional per-session drain handle for membership-eviction completion tracking.
    drain_handle: Option<Arc<crate::session_drain::SessionDrainHandle>>,
    session_id: Option<SessionId>,
    /// Per-session send-deadline configuration.
    deadline_config: Option<SendDeadlineConfig>,
    /// Per-session frame-size governor for send and receive byte caps.
    /// When set, every send is checked against the governor before framing.
    frame_size_governor: Option<FrameSizeGovernor>,
    /// Optional per-session send coalescer for batching framed messages.
    send_coalescer: Option<Arc<std::sync::Mutex<SendCoalescer>>>,
}

impl SendPipelineHandle {
    /// Create a new handle.
    #[must_use]
    pub fn new(
        state: Arc<RwLock<ConnectionState>>,
        tx: mpsc::Sender<(SendPriority, OutboundFrame)>,
        capacity: usize,
    ) -> Self {
        Self {
            state,
            tx,
            capacity,
            counter: Arc::new(OutboundItemCounter::default()),
            drain_handle: None,
            send_concurrency: None,
            session_class: None,
            send_gate: None,
            deadline_config: None,
            backpressure_state: None,
            backpressure_config: None,
            capacity_set: None,
            session_id: None,
            peer_id: None,
            frame_size_governor: None,
            send_coalescer: None,
        }
    }

    /// Attach a session drain handle for membership-eviction completion
    /// tracking.
    ///
    /// When set, [`send_with_drain_token`](Self::send_with_drain_token)
    /// creates a [`DrainToken`](crate::session_drain::DrainToken) for
    /// each send so callers can await completion or eviction.
    #[must_use]
    pub fn with_drain(mut self, handle: Arc<crate::session_drain::SessionDrainHandle>) -> Self {
        self.drain_handle = Some(handle);
        self
    }

    /// Return a reference to the drain handle, if configured.
    pub fn drain_handle(&self) -> Option<&Arc<crate::session_drain::SessionDrainHandle>> {
        self.drain_handle.as_ref()
    }

    /// Attach a send-concurrency limiter to this handle.
    ///
    /// When set, every send acquires a permit before enqueueing.
    /// The permit is released when the send completes (message accepted
    /// into the pipeline) or fails.
    #[must_use]
    pub fn with_send_concurrency(mut self, limiter: Arc<SendConcurrencyLimiter>) -> Self {
        self.send_concurrency = Some(limiter);
        self
    }

    /// Bind a session class to this handle.
    ///
    /// Once set, the default [`send`](Self::send), [`try_send`](Self::try_send),
    /// [`send_tagged`](Self::send_tagged), and [`try_send_tagged`](Self::try_send_tagged)
    /// methods derive [`SendPriority`] from this class via
    /// [`session_class_to_send_priority`] instead of using
    /// [`SendPriority::Data`].
    ///
    /// Explicit-priority methods ([`send_with_priority`](Self::send_with_priority),
    /// [`try_send_with_priority`](Self::try_send_with_priority)) are unaffected.
    #[must_use]
    pub fn with_session_class(mut self, sc: SessionClass) -> Self {
        self.session_class = Some(sc);
        self
    }

    /// Return the session class bound to this handle, if any.
    pub fn session_class(&self) -> Option<SessionClass> {
        self.session_class
    }

    /// Attach a roster send-gate to this handle.
    ///
    /// When set, every send checks that `peer_id` is in the current
    /// committed roster via [`SendGate::can_send_to`] before enqueueing.
    /// Sends to evicted or unknown peers return
    /// [`SendPipelineError::PeerNotInRoster`].
    #[must_use]
    pub fn with_send_gate(mut self, gate: Arc<dyn SendGate>, peer_id: PeerId) -> Self {
        self.send_gate = Some(gate);
        self.peer_id = Some(peer_id);
        self
    }

    /// Return the peer id bound to this handle, if any.
    pub fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
    }

    /// Attach per-session send-path backpressure water marks.
    ///
    /// When set, [`send`](Self::send) and [`try_send`](Self::try_send)
    /// atomically check the pipeline byte depth against
    /// `config.high_water_mark` before enqueueing. If exceeded,
    /// [`SendPipelineError::SendBackpressure`] is returned.
    ///
    /// [`backpressure_ready`](Self::backpressure_ready) returns a watch
    /// receiver that fires `true` when depth drains below
    /// `config.low_water_mark` after having exceeded the high-water mark.
    ///
    /// Requires `with_session_id` to be called so the error carries
    /// a meaningful session identifier.
    #[must_use]
    pub fn with_backpressure(
        mut self,
        state: Arc<SendBackpressureState>,
        config: SendBackpressureConfig,
    ) -> Self {
        self.backpressure_state = Some(state);
        self.backpressure_config = Some(config);
        if let Some(s) = self.backpressure_state.as_ref() {
            s.set_low_water_mark(config.low_water_mark)
        }
        self
    }

    /// Set the session ID for this handle (used in backpressure error
    /// messages).
    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Attach a per-priority capacity set for send-side backpressure.
    ///
    /// When set, callers can obtain per-priority [`SendCapacity`] handles
    /// via [`send_capacity`](Self::send_capacity) and await async capacity
    /// notification instead of spinning or dropping messages.
    #[must_use]
    pub fn with_capacity_set(mut self, capacity_set: SendCapacitySet) -> Self {
        self.capacity_set = Some(capacity_set);
        self
    }

    /// Return a per-priority capacity handle for async backpressure.
    ///
    /// Returns `None` if no capacity set is configured on this handle.
    pub fn send_capacity(&self, pri: SendPriority) -> Option<SendCapacity> {
        self.capacity_set.as_ref().map(|cs| cs.capacity(pri))
    }

    /// Replace the capacity set on this handle in-place.
    ///
    /// Allows tests and dynamic reconfiguration to swap watermarks
    /// without recreating the entire pipeline.
    pub fn set_capacity_set(&mut self, cs: SendCapacitySet) {
        self.capacity_set = Some(cs);
    }

    /// Send with backpressure-aware capacity check.
    ///
    /// Enqueues immediately if the priority queue has capacity.
    /// Otherwise awaits [`SendCapacity::wait_for_capacity`] before
    /// enqueuing, subject to the message's send deadline.
    ///
    /// Returns admission evidence for accepted, waited, expired-before-enqueue,
    /// capacity, roster, and closed outcomes.
    pub async fn try_send_with_backpressure(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<SendAdmission<DeadlineToken>, SendPipelineError> {
        let mut waited = false;
        let mut wake = SendWakeEvidence::NotApplicable;

        // If a capacity set is configured and this priority is under
        // backpressure, wait until capacity is available.
        if let Some(ref cs) = self.capacity_set {
            let cap = cs.capacity(priority);
            if !cap.is_available() {
                let dl = self.resolve_backpressure_wait_deadline(deadline);
                if dl.is_expired() {
                    return Ok(self.expired_before_enqueue_admission(family, priority, payload));
                }

                waited = true;
                if let Some(remaining) = dl.remaining() {
                    tokio::select! {
                        observed = cap.wait_for_capacity_evidence() => {
                            wake = observed;
                        }
                        () = tokio::time::sleep(remaining) => {
                            return Ok(self.expired_before_enqueue_admission(family, priority, payload));
                        }
                    }
                } else {
                    wake = cap.wait_for_capacity_evidence().await;
                }
            }
        }

        match self.try_send_with_priority_and_deadline(family, priority, payload, deadline) {
            Ok(token) => {
                let outcome = if waited {
                    SendAdmissionOutcome::Blocked
                } else {
                    SendAdmissionOutcome::Accepted
                };
                Ok(SendAdmission::with_value(
                    self.admission_base(outcome, family, priority, payload.len())
                        .with_wake(wake),
                    token,
                ))
            }
            Err(err) => {
                if let Some(evidence) =
                    self.pipeline_error_evidence(&err, family, priority, payload.len(), wake)
                {
                    Ok(SendAdmission::without_value(evidence))
                } else {
                    Err(err)
                }
            }
        }
    }

    fn resolve_backpressure_wait_deadline(
        &self,
        caller_deadline: Option<std::time::Duration>,
    ) -> MessageDeadline {
        match caller_deadline {
            Some(deadline) => MessageDeadline::from_duration(deadline),
            None => resolve_deadline(
                self.deadline_config
                    .as_ref()
                    .unwrap_or(&SendDeadlineConfig::default()),
                None,
            ),
        }
    }

    fn expired_before_enqueue_admission(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
    ) -> SendAdmission<DeadlineToken> {
        let (token, tx) = deadline_channel();
        let _ = tx.send(DeadlineOutcome::Cancelled);
        SendAdmission::with_value(
            self.admission_base(
                SendAdmissionOutcome::ExpiredBeforeEnqueue,
                family,
                priority,
                payload.len(),
            )
            .with_policy(SendAdmissionPolicy::Watermark)
            .with_wake(SendWakeEvidence::Waiting),
            token,
        )
    }

    fn admission_base(
        &self,
        outcome: SendAdmissionOutcome,
        family: MessageFamily,
        priority: SendPriority,
        payload_len: usize,
    ) -> SendAdmissionEvidence {
        let byte_depth = self.backpressure_depth().unwrap_or(0);
        let mut evidence = SendAdmissionEvidence::new(outcome)
            .with_priority(priority)
            .with_family(family)
            .with_byte_depth(byte_depth)
            .with_capacity(SendCapacityEvidence::new(
                SendCapacityClass::Byte,
                byte_depth,
                Some(SendFramer::wire_size(payload_len)),
                self.backpressure_config
                    .map(|config| config.high_water_mark),
            ));
        if let Some(ref capacity_set) = self.capacity_set {
            let snapshot = capacity_set.snapshot(priority);
            evidence =
                evidence
                    .with_queue_depth(snapshot.depth)
                    .with_capacity(SendCapacityEvidence::new(
                        SendCapacityClass::PriorityWatermark,
                        snapshot.depth,
                        Some(1),
                        Some(snapshot.high_watermark),
                    ));
        }
        if let Some(session_id) = self.session_id {
            evidence = evidence.with_session_id(session_id);
        }
        if let Some(peer_id) = self.peer_id {
            evidence = evidence.with_peer_id(peer_id);
        }
        evidence
    }

    fn pipeline_error_evidence(
        &self,
        err: &SendPipelineError,
        family: MessageFamily,
        priority: SendPriority,
        payload_len: usize,
        wake: SendWakeEvidence,
    ) -> Option<SendAdmissionEvidence> {
        let base = |outcome| self.admission_base(outcome, family, priority, payload_len);
        Some(match err {
            SendPipelineError::ConnectionStateClosed(_) => base(SendAdmissionOutcome::Closed)
                .with_policy(SendAdmissionPolicy::ConnectionState)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::ConnectionState,
                    0,
                    Some(1),
                    Some(1),
                ))
                .with_wake(wake),
            SendPipelineError::ChannelFull(capacity) => base(SendAdmissionOutcome::Backpressured)
                .with_policy(SendAdmissionPolicy::BoundedChannel)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::PipelineChannel,
                    *capacity,
                    Some(1),
                    Some(*capacity),
                ))
                .with_wake(wake),
            SendPipelineError::Shutdown => base(SendAdmissionOutcome::Closed)
                .with_policy(SendAdmissionPolicy::Shutdown)
                .with_wake(wake),
            SendPipelineError::ConcurrencyLimitExceeded(SendConcurrencyError::LimitExceeded {
                max,
            }) => base(SendAdmissionOutcome::Backpressured)
                .with_policy(SendAdmissionPolicy::Concurrency)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::Concurrency,
                    *max,
                    Some(1),
                    Some(*max),
                ))
                .with_wake(wake),
            SendPipelineError::ConcurrencyLimitExceeded(_) => base(SendAdmissionOutcome::Closed)
                .with_policy(SendAdmissionPolicy::Shutdown)
                .with_wake(wake),
            SendPipelineError::PeerNotInRoster(peer_id) => base(SendAdmissionOutcome::NoConnection)
                .with_peer_id(*peer_id)
                .with_policy(SendAdmissionPolicy::Roster)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::Roster,
                    0,
                    Some(1),
                    Some(1),
                ))
                .with_wake(wake),
            SendPipelineError::SendBackpressure {
                session_id,
                queue_depth,
            } => base(SendAdmissionOutcome::Backpressured)
                .with_session_id(*session_id)
                .with_policy(SendAdmissionPolicy::Watermark)
                .with_byte_depth(*queue_depth)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::Byte,
                    *queue_depth,
                    Some(SendFramer::wire_size(payload_len)),
                    self.backpressure_config
                        .map(|config| config.high_water_mark),
                ))
                .with_wake(wake),
            SendPipelineError::FrameTooLarge(FrameSizeError::SendPayloadTooLarge {
                limit,
                actual,
            }) => base(SendAdmissionOutcome::Backpressured)
                .with_policy(SendAdmissionPolicy::Error)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::Byte,
                    *actual,
                    Some(*actual),
                    Some(*limit),
                ))
                .with_wake(wake),
            SendPipelineError::FrameTooLarge(_) | SendPipelineError::Io(_) => return None,
        })
    }

    /// Attach a frame-size governor to this handle.
    ///
    /// When set, every send is checked against the governor before framing.
    /// Sends exceeding the per-class send payload cap are rejected with
    /// [`SendPipelineError::FrameTooLarge`].
    #[must_use]
    pub fn with_frame_size_governor(mut self, governor: FrameSizeGovernor) -> Self {
        self.frame_size_governor = Some(governor);
        self
    }

    /// Attach a send coalescer for batching framed messages.
    ///
    /// When set, every send routes through the coalescer: framed messages
    /// are accumulated per (session, priority) key and flushed as a single
    /// concatenated byte buffer when byte, count, or deadline thresholds
    /// are reached. When not set (the default), messages are sent
    /// individually with no batching.
    ///
    /// Requires `with_session_id` to have been called so the coalescer
    /// can key batches by session.
    #[must_use]
    pub fn with_send_coalescer(mut self, coalescer: SendCoalescer) -> Self {
        self.send_coalescer = Some(Arc::new(std::sync::Mutex::new(coalescer)));
        self
    }

    /// Return a clone of the send coalescer Arc, if configured.
    pub fn send_coalescer(&self) -> Option<Arc<std::sync::Mutex<SendCoalescer>>> {
        self.send_coalescer.clone()
    }

    /// Attach a send-deadline configuration to this handle.
    ///
    /// When set, the deadline parameter on send methods is
    /// resolved against this config: if the caller passes `None`, the
    /// config's `default_deadline` is used; if `enabled` is `false`,
    /// all deadline checks are skipped.
    #[must_use]
    pub fn with_send_deadline(mut self, config: SendDeadlineConfig) -> Self {
        self.deadline_config = Some(config);
        self
    }

    /// Return the send-deadline configuration, if attached.
    pub fn deadline_config(&self) -> Option<&SendDeadlineConfig> {
        self.deadline_config.as_ref()
    }

    /// Return a watch receiver that fires `true` when backpressure clears.
    ///
    /// On subscription the receiver gets the current value: `true` means
    /// the pipeline is ready for sends (below high-water or unconfigured),
    /// `false` means the pipeline is under backpressure.
    ///
    /// Returns `None` if backpressure is not configured on this handle.
    pub fn backpressure_ready(&self) -> Option<watch::Receiver<bool>> {
        self.backpressure_state
            .as_ref()
            .map(|state| state.subscribe_ready())
    }

    /// Return the current backpressure queue depth in bytes, if configured.
    #[must_use]
    pub fn backpressure_depth(&self) -> Option<usize> {
        self.backpressure_state.as_ref().map(|state| state.depth())
    }

    fn default_priority(&self) -> SendPriority {
        self.session_class
            .map_or(SendPriority::Data, session_class_to_send_priority)
    }

    /// Send a framed message to the pipeline.
    ///
    /// The message is first framed via [`SendFramer::frame`] using the
    /// untagged channel (channel_id = 0). For channel-tagged sends, use
    /// [`send_tagged`](Self::send_tagged).
    ///
    /// # Errors
    ///
    /// Returns [`SendPipelineError::ConnectionStateClosed`] if the connection
    /// is not in a sendable state [`SendPipelineError::ChannelFull`] if the
    /// pipeline channel is at capacity, or [`SendPipelineError::Shutdown`]
    /// if the pipeline has been torn down.
    ///
    /// Uses [`SendPriority::Data`] as the default priority. For explicit
    /// priority control, use [`send_with_priority`](Self::send_with_priority).
    pub async fn send(
        &self,
        family: MessageFamily,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        self.send_with_priority(family, self.default_priority(), payload)
            .await
    }

    /// Send a framed message with an explicit priority class.
    ///
    /// The priority influences scheduling order in the send pipeline:
    /// Control and Membership messages are dequeued before Data and Bulk
    /// under backpressure.
    pub async fn send_with_priority(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        self.send_tagged_with_priority(family, ChannelId::new(0), priority, payload)
            .await
    }

    /// Send a framed message to the pipeline with an explicit channel ID.
    ///
    /// Uses [`SendPriority::Data`] as the default priority.
    ///
    /// # Errors
    ///
    /// Same as [`send`](Self::send).
    pub async fn send_tagged(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        self.send_tagged_with_priority(family, channel_id, self.default_priority(), payload)
            .await
    }

    /// Send a framed message with an explicit channel ID and priority class.
    ///
    /// # Errors
    ///
    /// Same as [`send`](Self::send).
    pub async fn send_tagged_with_priority(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        priority: SendPriority,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        // Acquire a send-concurrency permit before enqueueing.
        let _permit = if let Some(ref limiter) = self.send_concurrency {
            Some(limiter.acquire().await?)
        } else {
            None
        };

        // Gate: check membership roster send-gate.
        if let Some(ref gate) = self.send_gate {
            let pid = self.peer_id.unwrap_or(0);
            if !gate.can_send_to(pid) {
                return Err(SendPipelineError::PeerNotInRoster(pid));
            }
        }

        // Gate: check connection state.
        {
            let state = *self.state.read().await;
            if !state_gates_send(state) {
                return Err(SendPipelineError::ConnectionStateClosed(state));
            }
        }

        // Check backpressure water marks before enqueue (uses wire_size).
        let wire_size = SendFramer::wire_size(payload.len());
        self.check_backpressure_before_enqueue(wire_size)?;
        let frame = SendFramer::frame(family, channel_id, payload);

        // Route through send coalescer if configured.
        if let Some(ref coalescer) = self.send_coalescer {
            let session_id = self
                .session_id
                .expect("send_coalescer requires with_session_id");
            let key = CoalesceKey::new(session_id, priority);
            let maybe_flush = {
                let mut c = coalescer.lock().expect("SendCoalescer mutex poisoned");
                c.enqueue(key, frame)
            }; // MutexGuard dropped here — safe to await below.
            self.counter.increment();
            if let Some(flush) = maybe_flush {
                // Flush triggered — send batched bytes.
                self.tx
                    .send((flush.key.priority, OutboundFrame::new(flush.data)))
                    .await
                    .map_err(|_| SendPipelineError::Shutdown)?;
                self.record_backpressure_enqueue(wire_size);
                Ok(())
            } else {
                // Message queued in coalescer, no flush triggered.
                self.record_backpressure_enqueue(wire_size);
                Ok(())
            }
        } else {
            self.counter.increment();
            self.tx
                .send((priority, OutboundFrame::new(frame)))
                .await
                .map_err(|_| SendPipelineError::Shutdown)?;
            self.record_backpressure_enqueue(wire_size);
            Ok(())
        }
    }

    /// Send a framed message with an optional send deadline.
    ///
    /// If `deadline` is `Some(d)`, the message must be transmitted within
    /// `d` from now or it will be cancelled. If `None`, the configured
    /// `default_deadline` is used when the config is enabled; otherwise
    /// no deadline is applied.
    ///
    /// Returns a [`DeadlineToken`] that resolves to
    /// [`DeadlineOutcome::Delivered`] or [`DeadlineOutcome::Cancelled`]
    /// when the outcome is known.
    pub async fn send_with_deadline(
        &self,
        family: MessageFamily,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        self.send_with_priority_and_deadline(family, self.default_priority(), payload, deadline)
            .await
    }

    /// Send with an explicit priority and an optional send deadline.
    pub async fn send_with_priority_and_deadline(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        self.send_tagged_with_priority_and_deadline(
            family,
            ChannelId::new(0),
            priority,
            payload,
            deadline,
        )
        .await
    }

    /// Send with a channel ID, priority, and optional send deadline.
    ///
    /// Returns a [`DeadlineToken`] that the caller can await to learn
    /// whether the message was delivered or cancelled due to deadline
    /// expiry.
    pub async fn send_tagged_with_priority_and_deadline(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        priority: SendPriority,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        // Acquire a send-concurrency permit before enqueueing.
        let _permit = if let Some(ref limiter) = self.send_concurrency {
            Some(limiter.acquire().await?)
        } else {
            None
        };

        // Gate: check membership roster send-gate.
        if let Some(ref gate) = self.send_gate {
            let pid = self.peer_id.unwrap_or(0);
            if !gate.can_send_to(pid) {
                return Err(SendPipelineError::PeerNotInRoster(pid));
            }
        }

        // Gate: check connection state.
        {
            let state = *self.state.read().await;
            if !state_gates_send(state) {
                return Err(SendPipelineError::ConnectionStateClosed(state));
            }
        }

        // Check backpressure water marks before enqueue.
        let wire_size = SendFramer::wire_size(payload.len());
        self.check_backpressure_before_enqueue(wire_size)?;

        // Resolve deadline: create the oneshot pair and build OutboundFrame.
        let (dl, token, outcome_tx) = self.prepare_deadline_send(deadline);

        let frame = SendFramer::frame(family, channel_id, payload);
        let outbound = OutboundFrame {
            data: frame,
            deadline: dl.as_instant(),
            outcome_tx,
            barrier_tx: None,
        };

        self.counter.increment();
        self.tx
            .send((priority, outbound))
            .await
            .map_err(|_| SendPipelineError::Shutdown)?;
        self.record_backpressure_enqueue(wire_size);

        Ok(token)
    }

    /// Try to send with a deadline, without waiting for channel capacity.
    pub fn try_send_with_deadline(
        &self,
        family: MessageFamily,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        self.try_send_with_priority_and_deadline(family, self.default_priority(), payload, deadline)
    }

    /// Try to send with an explicit priority and deadline.
    pub fn try_send_with_priority_and_deadline(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        self.try_send_tagged_with_priority_and_deadline(
            family,
            ChannelId::new(0),
            priority,
            payload,
            deadline,
        )
    }

    /// Try to send with channel ID, priority, and deadline.
    pub fn try_send_tagged_with_priority_and_deadline(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        priority: SendPriority,
        payload: &[u8],
        deadline: Option<std::time::Duration>,
    ) -> Result<DeadlineToken, SendPipelineError> {
        // Acquire a send-concurrency permit before enqueueing.
        let _permit = if let Some(ref limiter) = self.send_concurrency {
            Some(limiter.try_acquire()?)
        } else {
            None
        };

        // Gate: check membership roster send-gate.
        if let Some(ref gate) = self.send_gate {
            let pid = self.peer_id.unwrap_or(0);
            if !gate.can_send_to(pid) {
                return Err(SendPipelineError::PeerNotInRoster(pid));
            }
        }

        // Gate: check connection state (non-blocking read).
        {
            let state = *self
                .state
                .try_read()
                .map_err(|_| SendPipelineError::Shutdown)?;
            if !state_gates_send(state) {
                return Err(SendPipelineError::ConnectionStateClosed(state));
            }
        }

        // Frame-size governance: check payload size before framing.
        if let Some(ref governor) = self.frame_size_governor {
            governor.check_send(self.session_class, payload.len())?;
        }

        // Check backpressure water marks before enqueue.
        let wire_size = SendFramer::wire_size(payload.len());
        self.check_backpressure_before_enqueue(wire_size)?;

        // Resolve deadline: create the oneshot pair and build OutboundFrame.
        let (dl, token, outcome_tx) = self.prepare_deadline_send(deadline);

        let frame = SendFramer::frame(family, channel_id, payload);
        let outbound = OutboundFrame {
            data: frame,
            deadline: dl.as_instant(),
            outcome_tx,
            barrier_tx: None,
        };

        self.counter.increment();
        self.tx
            .try_send((priority, outbound))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SendPipelineError::ChannelFull(self.capacity),
                mpsc::error::TrySendError::Closed(_) => SendPipelineError::Shutdown,
            })?;
        self.record_backpressure_enqueue(wire_size);

        Ok(token)
    }

    /// Prepare a deadline send: resolve config, create oneshot channel,
    /// return the deadline, token, and sender for the OutboundFrame.
    fn prepare_deadline_send(
        &self,
        caller_deadline: Option<std::time::Duration>,
    ) -> (
        MessageDeadline,
        DeadlineToken,
        Option<tokio::sync::oneshot::Sender<DeadlineOutcome>>,
    ) {
        let cfg = match self.deadline_config.as_ref() {
            Some(c) => c,
            None => {
                // No deadline config: create a throwaway token that
                // resolves immediately to Delivered.
                let (token, tx) = deadline_channel();
                let _ = tx.send(DeadlineOutcome::Delivered);
                return (MessageDeadline::none(), token, None);
            }
        };
        let dl = resolve_deadline(cfg, caller_deadline);
        if dl.as_instant().is_some() {
            let (token, tx) = deadline_channel();
            (dl, token, Some(tx))
        } else {
            // No deadline (config disabled or no default): create a
            // throwaway token.
            let (token, tx) = deadline_channel();
            let _ = tx.send(DeadlineOutcome::Delivered);
            (dl, token, None)
        }
    }

    /// Try to send without waiting for channel capacity.
    ///
    /// Returns immediately with [`SendPipelineError::ChannelFull`] if the
    /// channel is full instead of waiting.
    ///
    /// Uses [`SendPriority::Data`] as the default priority.
    pub fn try_send(&self, family: MessageFamily, payload: &[u8]) -> Result<(), SendPipelineError> {
        self.try_send_with_priority(family, self.default_priority(), payload)
    }

    /// Try to send with an explicit priority without waiting for capacity.
    pub fn try_send_with_priority(
        &self,
        family: MessageFamily,
        priority: SendPriority,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        self.try_send_tagged_with_priority(family, ChannelId::new(0), priority, payload)
    }

    /// Try to send with a channel ID without waiting for capacity.
    ///
    /// Uses [`SendPriority::Data`] as the default priority.
    pub fn try_send_tagged(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        self.try_send_tagged_with_priority(family, channel_id, self.default_priority(), payload)
    }

    /// Try to send with a channel ID and priority without waiting for capacity.
    pub fn try_send_tagged_with_priority(
        &self,
        family: MessageFamily,
        channel_id: ChannelId,
        priority: SendPriority,
        payload: &[u8],
    ) -> Result<(), SendPipelineError> {
        // Acquire a send-concurrency permit before enqueueing.
        let _permit = if let Some(ref limiter) = self.send_concurrency {
            Some(limiter.try_acquire()?)
        } else {
            None
        };

        // Gate: check membership roster send-gate.
        if let Some(ref gate) = self.send_gate {
            let pid = self.peer_id.unwrap_or(0);
            if !gate.can_send_to(pid) {
                return Err(SendPipelineError::PeerNotInRoster(pid));
            }
        }

        // Gate: check connection state (non-blocking read).
        {
            let state = *self
                .state
                .try_read()
                .map_err(|_| SendPipelineError::Shutdown)?;
            if !state_gates_send(state) {
                return Err(SendPipelineError::ConnectionStateClosed(state));
            }
        }

        // Check backpressure water marks before enqueue (uses wire_size).

        // Frame-size governance: check payload size before framing.
        if let Some(ref governor) = self.frame_size_governor {
            governor.check_send(self.session_class, payload.len())?;
        }
        let wire_size = SendFramer::wire_size(payload.len());
        self.check_backpressure_before_enqueue(wire_size)?;
        let frame = SendFramer::frame(family, channel_id, payload);

        // Route through send coalescer if configured.
        if let Some(ref coalescer) = self.send_coalescer {
            let session_id = self
                .session_id
                .expect("send_coalescer requires with_session_id");
            let key = CoalesceKey::new(session_id, priority);
            let mut c = coalescer.lock().expect("SendCoalescer mutex poisoned");
            if let Some(flush) = c.enqueue(key, frame) {
                // Flush triggered — send batched bytes through mpsc.
                self.counter.increment();
                self.tx
                    .try_send((flush.key.priority, OutboundFrame::new(flush.data)))
                    .map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => {
                            SendPipelineError::ChannelFull(self.capacity)
                        }
                        mpsc::error::TrySendError::Closed(_) => SendPipelineError::Shutdown,
                    })?;
                self.record_backpressure_enqueue(wire_size);
                Ok(())
            } else {
                // Message queued in coalescer, no flush triggered.
                self.counter.increment();
                self.record_backpressure_enqueue(wire_size);
                Ok(())
            }
        } else {
            // No coalescer — send directly as before.
            self.counter.increment();
            self.tx
                .try_send((priority, OutboundFrame::new(frame)))
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => {
                        SendPipelineError::ChannelFull(self.capacity)
                    }
                    mpsc::error::TrySendError::Closed(_) => SendPipelineError::Shutdown,
                })?;
            self.record_backpressure_enqueue(wire_size);
            Ok(())
        }
    }

    /// Request a send barrier for the selected priority lane.
    ///
    /// The returned handle completes when all messages enqueued before this
    /// call have been dequeued by the send pipeline and handed to the I/O
    /// path. The `priority` should match the lane being guarded so the
    /// scheduler does not reorder the barrier ahead of that lane's messages.
    pub fn request_barrier(
        &self,
        priority: SendPriority,
    ) -> Result<SendBarrier, SendPipelineError> {
        {
            let state = *self
                .state
                .try_read()
                .map_err(|_| SendPipelineError::Shutdown)?;
            if !state_gates_send(state) {
                return Err(SendPipelineError::ConnectionStateClosed(state));
            }
        }

        if let Some(ref coalescer) = self.send_coalescer {
            let session_id = self
                .session_id
                .expect("send_coalescer requires with_session_id");
            let key = CoalesceKey::new(session_id, priority);
            let flush = coalescer
                .lock()
                .expect("SendCoalescer mutex poisoned")
                .flush_key(key);
            if let Some(flush) = flush {
                self.tx
                    .try_send((flush.key.priority, OutboundFrame::new(flush.data)))
                    .map_err(|e| match e {
                        mpsc::error::TrySendError::Full(_) => {
                            SendPipelineError::ChannelFull(self.capacity)
                        }
                        mpsc::error::TrySendError::Closed(_) => SendPipelineError::Shutdown,
                    })?;
            }
        }

        let ahead_count = self.counter.snapshot();
        let (tx, rx) = oneshot::channel();
        self.counter.increment();
        self.tx
            .try_send((priority, OutboundFrame::barrier(tx)))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => SendPipelineError::ChannelFull(self.capacity),
                mpsc::error::TrySendError::Closed(_) => SendPipelineError::Shutdown,
            })?;

        Ok(SendBarrier::new(rx, ahead_count))
    }

    /// Return whether the connection is in a sendable state (non-blocking).
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.state
            .try_read()
            .map(|s| state_gates_send(*s))
            .unwrap_or(false)
    }

    /// Check backpressure water marks before enqueuing a frame.
    /// Returns `Err(SendBackpressure)` if depth would exceed high-water mark.
    /// This does not mutate byte-depth accounting; callers commit with
    /// `record_backpressure_enqueue` only after the frame is actually queued.
    fn check_backpressure_before_enqueue(&self, wire_size: usize) -> Result<(), SendPipelineError> {
        if let (Some(ref state), Some(ref config)) =
            (&self.backpressure_state, &self.backpressure_config)
        {
            if let Err(current_depth) = state.check_high_water(config.high_water_mark, wire_size) {
                return Err(SendPipelineError::SendBackpressure {
                    session_id: self.session_id.unwrap_or(SessionId(0)),
                    queue_depth: current_depth,
                });
            }
        }
        Ok(())
    }

    fn record_backpressure_enqueue(&self, wire_size: usize) {
        if let (Some(ref state), Some(_)) = (&self.backpressure_state, &self.backpressure_config) {
            state.record_enqueue(wire_size);
        }
    }

    /// Send a framed message with drain-token completion tracking.
    ///
    /// Creates a [`DrainToken`](crate::session_drain::DrainToken) via the
    /// attached [`SessionDrainHandle`](crate::session_drain::SessionDrainHandle)
    /// and sends the message through the pipeline. On success, the token
    /// is returned so the caller can await send-completion or eviction
    /// notification. On send failure, the token is resolved immediately
    /// with [`DrainError::SessionClosed`](crate::session_drain::DrainError::SessionClosed).
    ///
    /// Requires [`with_drain`](Self::with_drain) to have been called.
    ///
    /// # Errors
    ///
    /// Returns [`SendPipelineError`] if the send fails. Returns
    /// [`SessionDrainError`](crate::session_drain::SessionDrainError) if the
    /// drain handle rejects the token (draining or at capacity).
    pub async fn send_with_drain_token(
        &self,
        family: MessageFamily,
        payload: &[u8],
    ) -> Result<crate::session_drain::DrainToken, SendPipelineError> {
        use crate::session_drain::DrainError;
        let dh = self
            .drain_handle
            .as_ref()
            .ok_or(SendPipelineError::Shutdown)?;
        match dh.send_with_token() {
            Ok(token) => {
                match self
                    .send_with_priority(family, self.default_priority(), payload)
                    .await
                {
                    Ok(()) => Ok(token),
                    Err(e) => {
                        // Send failed; resolve token as session-closed-equivalent.
                        dh.complete(Err(DrainError::SessionClosed));
                        Err(e)
                    }
                }
            }
            Err(_drain_err) => {
                // Drain handle is draining or at capacity.
                Err(SendPipelineError::Shutdown)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SendPipeline
// ---------------------------------------------------------------------------

/// The outbound send pipeline: owns the TCP socket write half, drains the
/// mpsc channel of framed bytes, and writes them to the socket with
/// writev-style gather-output batching.
///
/// Spawned after connection establishment and runs until the channel is
/// `Closed`.
pub struct SendPipeline {
    /// The TCP socket write half.
    stream: OwnedWriteHalf,
    /// Receiver for framed byte buffers from handles.
    rx: mpsc::Receiver<(SendPriority, OutboundFrame)>,
    /// Maximum frames to coalesce per writev batch.
    max_batch_frames: usize,
    /// Shared backpressure state for water-mark tracking.
    backpressure_state: Option<Arc<SendBackpressureState>>,
    idle_tracker: Option<IdleTracker>,
    credit_tracker: Option<Arc<SenderCreditTracker>>,
    /// Priority scheduler configuration passed to SendScheduler at run().
    scheduler_config: SendSchedulerConfig,
    capacity_set: Option<SendCapacitySet>,
}

impl SendPipeline {
    /// Create a new pipeline and a cloneable handle for submitting messages.
    ///
    /// Returns the pipeline (ready to [`run`](Self::run)) and a handle
    /// that can be cloned and distributed to callers.
    #[must_use]
    pub fn new(
        stream: OwnedWriteHalf,
        state: Arc<RwLock<ConnectionState>>,
        channel_capacity: usize,
        max_batch_frames: usize,
    ) -> (Self, SendPipelineHandle) {
        Self::with_scheduler_config(
            stream,
            state,
            channel_capacity,
            max_batch_frames,
            SendSchedulerConfig::default(),
        )
    }

    /// Create a new pipeline with a custom scheduler configuration.
    #[must_use]
    pub fn with_scheduler_config(
        stream: OwnedWriteHalf,
        state: Arc<RwLock<ConnectionState>>,
        channel_capacity: usize,
        max_batch_frames: usize,
        scheduler_config: SendSchedulerConfig,
    ) -> (Self, SendPipelineHandle) {
        let (tx, rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(channel_capacity);

        let backpressure_state = Arc::new(SendBackpressureState::new());
        let bp_clone = Arc::clone(&backpressure_state);

        let mut handle = SendPipelineHandle::new(state, tx, channel_capacity);
        handle.backpressure_state = Some(bp_clone);

        let capacity_set = SendCapacitySet::new(&SendWatermarkConfig::default());
        handle.capacity_set = Some(capacity_set.clone());

        let pipeline = Self {
            stream,
            rx,
            backpressure_state: Some(backpressure_state),
            max_batch_frames,
            idle_tracker: None,
            credit_tracker: None,
            capacity_set: Some(capacity_set.clone()),
            scheduler_config,
        };

        (pipeline, handle)
    }

    /// Create a new pipeline and handle, attaching a send-concurrency
    /// limiter for flow control.
    #[must_use]
    pub fn with_send_concurrency(
        stream: OwnedWriteHalf,
        state: Arc<RwLock<ConnectionState>>,
        channel_capacity: usize,
        max_batch_frames: usize,
        limiter: Arc<SendConcurrencyLimiter>,
    ) -> (Self, SendPipelineHandle) {
        Self::with_send_concurrency_and_scheduler(
            stream,
            state,
            channel_capacity,
            max_batch_frames,
            limiter,
            SendSchedulerConfig::default(),
        )
    }

    /// Create a new pipeline with send-concurrency limiter and custom scheduler config.
    #[must_use]
    pub fn with_send_concurrency_and_scheduler(
        stream: OwnedWriteHalf,
        state: Arc<RwLock<ConnectionState>>,
        channel_capacity: usize,
        max_batch_frames: usize,
        limiter: Arc<SendConcurrencyLimiter>,
        scheduler_config: SendSchedulerConfig,
    ) -> (Self, SendPipelineHandle) {
        let (tx, rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(channel_capacity);

        let backpressure_state = Arc::new(SendBackpressureState::new());
        let bp_clone = Arc::clone(&backpressure_state);

        let mut handle =
            SendPipelineHandle::new(state, tx, channel_capacity).with_send_concurrency(limiter);
        handle.backpressure_state = Some(bp_clone);

        let capacity_set = SendCapacitySet::new(&SendWatermarkConfig::default());
        handle.capacity_set = Some(capacity_set.clone());

        let pipeline = Self {
            stream,
            rx,
            backpressure_state: Some(backpressure_state),
            max_batch_frames,
            idle_tracker: None,
            credit_tracker: None,
            capacity_set: Some(capacity_set.clone()),
            scheduler_config,
        };

        (pipeline, handle)
    }

    /// Attach an idle tracker for recording outbound send-completion activity.
    /// The tracker is called after every successful write.
    #[must_use]
    pub fn with_idle_tracker(mut self, tracker: IdleTracker) -> Self {
        self.idle_tracker = Some(tracker);
        self
    }

    /// Replace the capacity set on this pipeline in-place.
    ///
    /// The caller is responsible for also updating the handle via
    /// [`SendPipelineHandle::set_capacity_set`] if the handle should
    /// see the same watermarks.
    pub fn set_capacity_set(&mut self, cs: SendCapacitySet) {
        self.capacity_set = Some(cs);
    }

    /// Attach a sender-side credit tracker for receive-flow gating.
    ///
    /// When set, the pipeline checks available credits before each frame
    /// transmission. If credits are exhausted, the pipeline stalls until
    /// the inbound path delivers a credit refresh from the peer.
    #[must_use]
    pub fn with_credit_tracker(mut self, tracker: Arc<SenderCreditTracker>) -> Self {
        self.credit_tracker = Some(tracker);
        self
    }

    /// Run the send pipeline loop until the channel is closed.
    ///
    /// Messages are first drained from the mpsc channel into a
    /// [`SendScheduler`] which reorders them by priority class. Under
    /// backpressure, higher-priority Control and Membership messages
    /// are transmitted before Data and Bulk, with starvation prevention
    /// ensuring eventual forward progress for all classes.
    ///
    /// Returns `Ok(())` on clean shutdown (all handles dropped) or
    /// `Err(SendPipelineError::Io)` on socket write failure.
    pub async fn run(&mut self) -> Result<(), SendPipelineError> {
        let mut scheduler = SendScheduler::<OutboundFrame>::new(self.scheduler_config.clone());

        loop {
            // Drain available messages from the mpsc into the scheduler.
            while let Ok((pri, frame)) = self.rx.try_recv() {
                scheduler.enqueue(frame, pri);
            }

            // Dequeue the highest-priority message from the scheduler.
            if let Some(msg) = scheduler.dequeue() {
                let oframe = msg.message;

                if let Some(tx) = oframe.barrier_tx {
                    let _ = tx.send(());
                    if let Some(ref cs) = self.capacity_set {
                        cs.check_after_dequeue(msg.priority, scheduler.class_len(msg.priority));
                    }
                    continue;
                }

                // Check send deadline before transmission.
                if let Some(deadline) = oframe.deadline {
                    if tokio::time::Instant::now() >= deadline {
                        // Deadline expired: signal cancellation and drop.
                        if let Some(tx) = oframe.outcome_tx {
                            let _ = tx.send(DeadlineOutcome::Cancelled);
                        }
                        continue;
                    }
                }

                let mut batch: Vec<Vec<u8>> = Vec::with_capacity(self.max_batch_frames);
                batch.push(oframe.data);

                // Signal delivery for the first dequeued frame.
                if let Some(tx) = oframe.outcome_tx {
                    let _ = tx.send(DeadlineOutcome::Delivered);
                }

                // Batch additional dequeues for writev efficiency.
                for _ in 1..self.max_batch_frames {
                    if let Some(m) = scheduler.dequeue() {
                        let f = m.message;

                        if let Some(tx) = f.barrier_tx {
                            let _ = tx.send(());
                            if let Some(ref cs) = self.capacity_set {
                                cs.check_after_dequeue(m.priority, scheduler.class_len(m.priority));
                            }
                            break;
                        }

                        // Check deadline for each batched frame.
                        if let Some(deadline) = f.deadline {
                            if tokio::time::Instant::now() >= deadline {
                                if let Some(tx) = f.outcome_tx {
                                    let _ = tx.send(DeadlineOutcome::Cancelled);
                                }
                                continue;
                            }
                        }

                        if let Some(tx) = f.outcome_tx {
                            let _ = tx.send(DeadlineOutcome::Delivered);
                        }

                        batch.push(f.data);

                        // Check per-priority watermark after batch dequeue.
                        if let Some(ref cs) = self.capacity_set {
                            cs.check_after_dequeue(m.priority, scheduler.class_len(m.priority));
                        }
                    } else {
                        break;
                    }
                }

                // Receive-flow credit check: verify sender has enough credits
                // from the peer before transmitting. Stalls if credits exhausted.
                if let Some(ref tracker) = self.credit_tracker {
                    let total_bytes: usize = batch.iter().map(|b| b.len()).sum();
                    if !tracker.try_acquire(total_bytes as u64) {
                        // Not enough credits: wait asynchronously and retry.
                        tracker.acquire_or_wait(total_bytes as u64).await;
                    }
                }

                // Compute total bytes before moving batch into write calls.
                let total_bytes: usize = batch.iter().map(|b| b.len()).sum();

                // Write every frame completely. A single vectored write may
                // report a short write, so use write_all for correctness.
                if batch.len() == 1 {
                    self.stream.write_all(&batch[0]).await?;
                    if let Some(ref tracker) = self.idle_tracker {
                        tracker.record_activity();
                    }
                } else {
                    for frame in &batch {
                        self.stream.write_all(frame).await?;
                    }
                    if let Some(ref tracker) = self.idle_tracker {
                        tracker.record_activity();
                    }
                }

                // Record drained bytes for backpressure tracking.
                if let Some(ref bp) = self.backpressure_state {
                    bp.record_drain(total_bytes);
                    bp.check_drain_and_notify();
                }
            } else {
                // Scheduler is empty; block for the next message.
                match self.rx.recv().await {
                    Some((pri, frame)) => {
                        scheduler.enqueue(frame, pri);
                    }
                    None => {
                        // All handles dropped; clean shutdown.
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Consume the pipeline and return the underlying write half.
    #[must_use]
    pub fn into_stream(self) -> OwnedWriteHalf {
        self.stream
    }
}

// ---------------------------------------------------------------------------
// State gating helper
// ---------------------------------------------------------------------------

/// Returns `true` if the given connection state permits outbound sends.
const fn state_gates_send(state: ConnectionState) -> bool {
    matches!(
        state,
        ConnectionState::Accepted | ConnectionState::Connected | ConnectionState::Draining
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::ChannelId;

    use crate::connection_registry::ConnectionState;
    use crate::envelope::MessageFamily;
    use std::sync::Arc;
    use tidefs_types_transport_session::SessionClass;
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    // -------------------------------------------------------------------
    // SendFramer tests
    // -------------------------------------------------------------------

    #[test]
    fn framer_produces_64_byte_header() {
        let frame = SendFramer::frame(MessageFamily::StateTransfer, ChannelId::new(0), b"hello");

        assert_eq!(frame.len(), 64 + 5);
        // First 4 bytes should be "VBFS" magic.
        assert_eq!(&frame[0..4], b"VBFS");
    }

    #[test]
    fn framer_total_body_bytes_correct() {
        let payload = vec![0xABu8; 512];
        let frame = SendFramer::frame(MessageFamily::HeartbeatAck, ChannelId::new(3), &payload);

        // total_body_bytes is at offset 32..40 (u64 LE).
        let mut tbb_buf = [0u8; 8];
        tbb_buf.copy_from_slice(&frame[32..40]);
        let total_body_bytes = u64::from_le_bytes(tbb_buf);
        assert_eq!(total_body_bytes, 512);
    }

    #[test]
    fn framer_family_id_correct() {
        for (family, expected_id) in [
            (MessageFamily::HelloClose, 100u64),
            (MessageFamily::HeartbeatAck, 101),
            (MessageFamily::ElectionControl, 102),
            (MessageFamily::LeaseFenceDeadline, 103),
            (MessageFamily::PublicationProgress, 104),
            (MessageFamily::LogSyncMetadata, 105),
            (MessageFamily::StateTransfer, 106),
            (MessageFamily::ReplicaTransferVerify, 107),
            (MessageFamily::ShadowValidation, 108),
            (MessageFamily::TransitionHoldResume, 109),
        ] {
            let frame = SendFramer::frame(family, ChannelId::new(0), b"x");
            let mut fid_buf = [0u8; 8];
            fid_buf.copy_from_slice(&frame[4..12]);
            let family_id = u64::from_le_bytes(fid_buf);
            assert_eq!(
                family_id, expected_id,
                "family {family} should have family_id {expected_id}"
            );
        }
    }

    #[test]
    fn framer_channel_id_in_type_id() {
        for ch in [0u16, 1, 7, 255, 65535] {
            let frame = SendFramer::frame(MessageFamily::StateTransfer, ChannelId::new(ch), b"x");
            let mut tid_buf = [0u8; 8];
            tid_buf.copy_from_slice(&frame[12..20]);
            let type_id = u64::from_le_bytes(tid_buf);
            assert_eq!(type_id, ch as u64, "channel {ch}: type_id mismatch");
        }
    }

    #[test]
    fn framer_empty_payload() {
        let frame = SendFramer::frame(MessageFamily::HelloClose, ChannelId::new(0), b"");
        assert_eq!(frame.len(), 64);

        let mut tbb_buf = [0u8; 8];
        tbb_buf.copy_from_slice(&frame[32..40]);
        assert_eq!(u64::from_le_bytes(tbb_buf), 0);
    }

    #[test]
    fn framer_large_payload() {
        let payload = vec![0xCCu8; 65536];
        let frame = SendFramer::frame(MessageFamily::StateTransfer, ChannelId::new(0), &payload);
        assert_eq!(frame.len(), 64 + 65536);
        assert_eq!(&frame[64..], &payload[..]);
    }

    #[test]
    fn framer_round_trips_through_framing_decoder() {
        use tidefs_binary_schema_framing::FramingDecoder;

        let payload = b"round-trip test payload for framing";
        let frame = SendFramer::frame(
            MessageFamily::ReplicaTransferVerify,
            ChannelId::new(42),
            payload,
        );

        let mut decoder = FramingDecoder::new();
        let decoded = decoder.feed(&frame);
        assert_eq!(decoded.len(), 1, "should emit exactly one frame");

        let msg = &decoded[0];
        assert_eq!(msg.body, payload);
        assert_eq!(
            msg.header.family_id,
            message_family_to_family_id(MessageFamily::ReplicaTransferVerify)
        );
        assert_eq!(msg.header.type_id.0, 42);
    }

    #[test]
    fn framer_wire_size_formula() {
        assert_eq!(SendFramer::wire_size(0), 64);
        assert_eq!(SendFramer::wire_size(100), 164);
        assert_eq!(SendFramer::wire_size(65536), 65600);
    }

    #[test]
    fn framer_clone() {
        let f1 = SendFramer;
        let _f2 = f1.clone();
        let frame1 = SendFramer::frame(MessageFamily::HelloClose, ChannelId::new(0), b"a");
        let frame2 = SendFramer::frame(MessageFamily::HelloClose, ChannelId::new(0), b"a");
        assert_eq!(frame1, frame2);
    }

    // -------------------------------------------------------------------
    // State gating tests
    // -------------------------------------------------------------------

    #[test]
    fn state_gating_accepted_connected_draining_permit() {
        assert!(state_gates_send(ConnectionState::Accepted));
        assert!(state_gates_send(ConnectionState::Connected));
        assert!(state_gates_send(ConnectionState::Draining));
    }

    #[test]
    fn state_gating_connecting_drained_closed_deny() {
        assert!(!state_gates_send(ConnectionState::Connecting));
        assert!(!state_gates_send(ConnectionState::Drained));
        assert!(!state_gates_send(ConnectionState::Closed));
    }

    // -------------------------------------------------------------------
    // SendPipelineHandle tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn handle_send_frames_and_delivers_to_receiver() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        handle
            .send(MessageFamily::StateTransfer, b"hello-world")
            .await
            .unwrap();

        let (_pri, frame) = rx.recv().await.unwrap();
        assert!(frame.data.len() >= 64);
        assert_eq!(&frame.data[64..], b"hello-world");
    }

    #[tokio::test]
    async fn handle_send_tagged_preserves_channel_id() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        handle
            .send_tagged(MessageFamily::StateTransfer, ChannelId::new(7), b"tagged")
            .await
            .unwrap();

        let (_pri, frame) = rx.recv().await.unwrap();
        let mut tid_buf = [0u8; 8];
        tid_buf.copy_from_slice(&frame.data[12..20]);
        assert_eq!(u64::from_le_bytes(tid_buf), 7);
    }

    #[tokio::test]
    async fn handle_rejects_when_state_closed() {
        let state = Arc::new(RwLock::new(ConnectionState::Closed));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        let result = handle.send(MessageFamily::StateTransfer, b"nope").await;
        assert!(matches!(
            result,
            Err(SendPipelineError::ConnectionStateClosed(
                ConnectionState::Closed
            ))
        ));
    }

    #[tokio::test]
    async fn handle_rejects_when_state_connecting() {
        let state = Arc::new(RwLock::new(ConnectionState::Connecting));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        let result = handle.send(MessageFamily::StateTransfer, b"nope").await;
        assert!(matches!(
            result,
            Err(SendPipelineError::ConnectionStateClosed(
                ConnectionState::Connecting
            ))
        ));
    }

    #[tokio::test]
    async fn handle_rejects_when_state_drained() {
        let state = Arc::new(RwLock::new(ConnectionState::Drained));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        let result = handle.send(MessageFamily::StateTransfer, b"nope").await;
        assert!(matches!(
            result,
            Err(SendPipelineError::ConnectionStateClosed(
                ConnectionState::Drained
            ))
        ));
    }

    #[tokio::test]
    async fn handle_send_returns_shutdown_when_rx_dropped() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        drop(rx); // Drop receiver to close the channel.

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        let result = handle.send(MessageFamily::StateTransfer, b"doomed").await;
        assert!(matches!(result, Err(SendPipelineError::Shutdown)));
    }

    #[tokio::test]
    async fn handle_try_send_full_channel() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(1); // capacity 1

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 1);

        // Fill the channel (no receiver draining).
        handle
            .try_send(MessageFamily::StateTransfer, b"first")
            .unwrap();

        // Second should fail with ChannelFull.
        let result = handle.try_send(MessageFamily::StateTransfer, b"second");
        assert!(matches!(result, Err(SendPipelineError::ChannelFull(1))));
    }

    #[tokio::test]
    async fn handle_can_send_reflects_state() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        assert!(handle.can_send());

        *state.write().await = ConnectionState::Closed;
        assert!(!handle.can_send());

        *state.write().await = ConnectionState::Draining;
        assert!(handle.can_send());
    }

    #[tokio::test]
    async fn handle_clone_works() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let h1 = SendPipelineHandle::new(Arc::clone(&state), tx, 16);
        let h2 = h1.clone();

        h1.send(MessageFamily::StateTransfer, b"from-h1")
            .await
            .unwrap();
        h2.send(MessageFamily::HeartbeatAck, b"from-h2")
            .await
            .unwrap();

        let (_pri1, f1) = rx.recv().await.unwrap();
        let (_pri2, f2) = rx.recv().await.unwrap();

        assert_eq!(&f1.data[64..], b"from-h1");
        assert_eq!(&f2.data[64..], b"from-h2");
    }

    #[tokio::test]
    async fn handle_accepts_in_draining_state() {
        let state = Arc::new(RwLock::new(ConnectionState::Draining));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        handle
            .send(MessageFamily::StateTransfer, b"draining-ok")
            .await
            .unwrap();

        let (_pri, frame) = rx.recv().await.unwrap();
        assert_eq!(&frame.data[64..], b"draining-ok");
    }

    // -------------------------------------------------------------------
    // SendPipeline integration tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn pipeline_writes_to_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server: reads frames from the accepted connection.
        let server_handle = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let (mut stream, _) = listener.accept().await.unwrap();

            // Read first frame: 64-byte header + 5-byte "first" payload.
            let mut header = [0u8; 64];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[0..4], b"VBFS");
            let mut payload1 = vec![0u8; 5];
            stream.read_exact(&mut payload1).await.unwrap();
            assert_eq!(&payload1, b"first");

            // Read second frame: 64-byte header + 6-byte "second" payload.
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[0..4], b"VBFS");
            let mut payload2 = vec![0u8; 6];
            stream.read_exact(&mut payload2).await.unwrap();
            assert_eq!(&payload2, b"second");
        });

        // Client: create pipeline and send frames.
        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        // Spawn pipeline run loop.
        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await.unwrap();
        });

        // Send frames through the handle.
        handle
            .send(MessageFamily::StateTransfer, b"first")
            .await
            .unwrap();
        handle
            .send(MessageFamily::StateTransfer, b"second")
            .await
            .unwrap();

        // Drop the handle so pipeline exits.
        drop(handle);

        // Wait for pipeline to finish.
        pipeline_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipeline_writev_batching() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server: reads all bytes and verifies frame count.
        let server_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut total = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut total)
                .await
                .unwrap();

            // Each frame is 64 + 5 bytes = 69 bytes. We sent 5 frames.
            assert_eq!(total.len(), 5 * (64 + 5));
            // Verify magic on each frame boundary.
            for i in 0..5 {
                let offset = i * (64 + 5);
                assert_eq!(&total[offset..offset + 4], b"VBFS", "frame {i} magic");
            }
        });

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await.unwrap();
        });

        // Send 5 frames rapidly.
        for i in 0..5u8 {
            let payload = [i; 5];
            handle
                .send(MessageFamily::StateTransfer, &payload)
                .await
                .unwrap();
        }

        drop(handle);
        pipeline_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    #[tokio::test]
    async fn pipeline_exits_on_channel_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        // Spawn a task that drops the handle after a short delay,
        // causing the channel to close and the pipeline to exit.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(handle);
        });

        let result = pipeline.run().await;
        assert!(
            result.is_ok(),
            "pipeline should exit cleanly when channel closes"
        );
    }

    #[tokio::test]
    async fn pipeline_exits_when_all_handles_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        // Drop the handle immediately.
        drop(handle);

        let result = pipeline.run().await;
        assert!(
            result.is_ok(),
            "pipeline should exit cleanly when channel closed"
        );
    }

    #[tokio::test]
    async fn pipeline_into_stream_returns_write_half() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (pipeline, _handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        let _wh = pipeline.into_stream();
    }

    // -------------------------------------------------------------------
    // Full round-trip: SendPipeline -> receive_loop
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn full_round_trip_send_pipeline_to_receive_loop() {
        use crate::dispatch::MessageDispatch;
        use crate::receive_loop::{ConnectionReceiver, ReceiveLoopConfig};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server: accept, spawn receive loop.
        let server_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let dispatch = Arc::new(MessageDispatch::new());
            let mut receiver =
                ConnectionReceiver::new(stream, dispatch, ReceiveLoopConfig::default());

            // Run receive loop until EOF.
            let result = receiver.recv_loop().await;
            assert!(result.is_ok(), "receive loop should finish cleanly");
        });

        // Client: connect, create pipeline, send frames, then close.
        let stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (_read_half, write_half) = stream.into_split();

        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (mut pipeline, handle) = SendPipeline::new(write_half, Arc::clone(&state), 16, 64);

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await.unwrap();
        });

        // Send several messages of different families.
        handle
            .send(MessageFamily::HelloClose, b"hello")
            .await
            .unwrap();
        handle
            .send(MessageFamily::HeartbeatAck, b"ping")
            .await
            .unwrap();
        handle
            .send(MessageFamily::StateTransfer, &[0u8; 256])
            .await
            .unwrap();
        handle
            .send(MessageFamily::LeaseFenceDeadline, b"lease")
            .await
            .unwrap();

        // Drop handle to close the channel.
        drop(handle);

        pipeline_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    #[test]
    fn send_pipeline_error_display() {
        let e = SendPipelineError::ConnectionStateClosed(ConnectionState::Closed);
        assert!(format!("{e}").contains("Closed"));

        let e = SendPipelineError::ChannelFull(8);
        assert!(format!("{e}").contains("8"));

        let e = SendPipelineError::Shutdown;
        assert!(format!("{e}").contains("shut down"));
    }

    #[test]
    fn send_pipeline_error_debug() {
        let e = SendPipelineError::ConnectionStateClosed(ConnectionState::Connecting);
        let s = format!("{e:?}");
        assert!(s.contains("ConnectionStateClosed"));
    }

    #[test]
    fn send_framer_debug() {
        let f = SendFramer;
        let s = format!("{f:?}");
        assert!(s.contains("SendFramer"));
    }

    // -------------------------------------------------------------------
    // Send-concurrency bypass prevention tests (#5998)
    // -------------------------------------------------------------------

    #[test]
    fn send_pipeline_handle_with_limiter_try_send_acquires_permit() {
        // Permits are acquired and released within each send call.
        // Serial calls always succeed because the permit is released on return.
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));

        let handle =
            SendPipelineHandle::new(state, tx, 16).with_send_concurrency(Arc::clone(&limiter));

        // First send acquires and releases the permit.
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg1");
        assert!(result.is_ok(), "first send should succeed");
        // Permit released on return.
        assert_eq!(limiter.in_flight_current(), 0);

        // Second send also succeeds (permit was released).
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg2");
        assert!(result.is_ok(), "second send also succeeds (serial)");
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[test]
    fn send_pipeline_handle_without_limiter_bypasses() {
        // When no limiter is configured, sends succeed without gating.
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(state, tx, 16);

        // Both sends should succeed (no limiter configured).
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg1");
        assert!(result.is_ok());
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg2");
        assert!(result.is_ok());
    }

    #[test]
    fn send_pipeline_handle_with_limiter_permit_released_on_return() {
        // Permits are dropped when send returns, making them available immediately.
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        let limiter = Arc::new(SendConcurrencyLimiter::new(2));

        let handle =
            SendPipelineHandle::new(state, tx, 16).with_send_concurrency(Arc::clone(&limiter));

        // try_send acquires and releases the permit on return.
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg1");
        assert!(result.is_ok());
        // Permit released on return, so in-flight is 0.
        assert_eq!(limiter.in_flight_current(), 0);

        // We can acquire again externally (no interference from the handle).
        let _p = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_current(), 1);
        drop(_p);
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[tokio::test]
    async fn send_pipeline_handle_with_limiter_async_send_waits_for_permit() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_send_concurrency(Arc::clone(&limiter));

        // Hold the only permit externally.
        let _held = limiter.try_acquire().unwrap();

        // Spawn an async send that will wait for the permit.
        let send_handle = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.send(MessageFamily::HeartbeatAck, b"waited").await })
        };

        // Give the spawned task time to start waiting.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            limiter.permit_wait_count(),
            1,
            "async send should have waited for permit"
        );

        // Release the held permit; the send should proceed.
        drop(_held);

        let result = send_handle.await.unwrap();
        assert!(result.is_ok());

        // Drain the message from the channel to prevent assertion on drop.
        let _ = rx.try_recv();
    }

    #[test]
    fn send_pipeline_handle_closed_state_releases_permit() {
        let state = Arc::new(RwLock::new(ConnectionState::Closed));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);
        let limiter = Arc::new(SendConcurrencyLimiter::new(2));

        let handle =
            SendPipelineHandle::new(state, tx, 16).with_send_concurrency(Arc::clone(&limiter));

        // try_send should acquire then release the permit (state closed error).
        let result = handle.try_send(MessageFamily::HeartbeatAck, b"msg");
        assert!(matches!(
            result,
            Err(SendPipelineError::ConnectionStateClosed(_))
        ));

        // Permit should have been released (dropped on error path).
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[test]
    fn send_pipeline_error_concurrency_display() {
        let e = SendPipelineError::ConcurrencyLimitExceeded(SendConcurrencyError::LimitExceeded {
            max: 42,
        });
        let s = format!("{e}");
        assert!(s.contains("42"), "error should mention max: {s}");
    }

    // -------------------------------------------------------------------
    // SessionClass → SendPriority mapping tests
    // -------------------------------------------------------------------

    #[test]
    fn session_class_to_send_priority_maps_control_classes() {
        assert_eq!(
            session_class_to_send_priority(SessionClass::Bootstrap),
            SendPriority::Control
        );
        assert_eq!(
            session_class_to_send_priority(SessionClass::Control),
            SendPriority::Control
        );
    }

    #[test]
    fn session_class_to_send_priority_maps_metadata_classes() {
        assert_eq!(
            session_class_to_send_priority(SessionClass::ReplicationMeta),
            SendPriority::Membership
        );
        assert_eq!(
            session_class_to_send_priority(SessionClass::TransitionOrchestration),
            SendPriority::Membership
        );
    }

    #[test]
    fn session_class_to_send_priority_maps_bulk_classes() {
        assert_eq!(
            session_class_to_send_priority(SessionClass::TransferBulk),
            SendPriority::Bulk
        );
        assert_eq!(
            session_class_to_send_priority(SessionClass::ShadowValidation),
            SendPriority::Bulk
        );
    }

    // -------------------------------------------------------------------
    // SendPipelineHandle session class integration tests
    // -------------------------------------------------------------------

    #[test]
    fn handle_with_session_class_derives_correct_priority() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, _rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        // Control session class → SendPriority::Control
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx.clone(), 16)
            .with_session_class(SessionClass::Control);
        assert_eq!(handle.session_class(), Some(SessionClass::Control));
        assert_eq!(handle.default_priority(), SendPriority::Control);

        // TransferBulk session class → SendPriority::Bulk
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx.clone(), 16)
            .with_session_class(SessionClass::TransferBulk);
        assert_eq!(handle.session_class(), Some(SessionClass::TransferBulk));
        assert_eq!(handle.default_priority(), SendPriority::Bulk);

        // No session class → falls back to SendPriority::Data
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);
        assert_eq!(handle.session_class(), None);
        assert_eq!(handle.default_priority(), SendPriority::Data);
    }

    #[tokio::test]
    async fn handle_send_uses_session_class_priority() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        // Control session class → message tagged with Control priority.
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_session_class(SessionClass::Control);

        handle
            .send(MessageFamily::StateTransfer, b"control-msg")
            .await
            .unwrap();

        let (pri, _frame) = rx.recv().await.unwrap();
        assert_eq!(pri, SendPriority::Control);
    }

    #[tokio::test]
    async fn handle_try_send_uses_session_class_priority() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_session_class(SessionClass::TransferBulk);

        handle
            .try_send(MessageFamily::StateTransfer, b"bulk-msg")
            .unwrap();

        let (pri, _frame) = rx.try_recv().unwrap();
        assert_eq!(pri, SendPriority::Bulk);
    }

    #[tokio::test]
    async fn handle_without_session_class_defaults_to_data_priority() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        // No session class set → falls back to SendPriority::Data.
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16);

        handle
            .send(MessageFamily::StateTransfer, b"default-pri")
            .await
            .unwrap();

        let (pri, _frame) = rx.recv().await.unwrap();
        assert_eq!(pri, SendPriority::Data);
    }

    #[tokio::test]
    async fn handle_send_tagged_uses_session_class_priority() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_session_class(SessionClass::Control);

        handle
            .send_tagged(MessageFamily::StateTransfer, ChannelId::new(3), b"tagged")
            .await
            .unwrap();

        let (pri, _frame) = rx.recv().await.unwrap();
        assert_eq!(pri, SendPriority::Control);
    }

    #[tokio::test]
    async fn handle_send_with_priority_bypasses_session_class() {
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        // Session class is Control, but explicit priority overrides to Data.
        let handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_session_class(SessionClass::Control);

        handle
            .send_with_priority(
                MessageFamily::StateTransfer,
                SendPriority::Data,
                b"explicit",
            )
            .await
            .unwrap();

        let (pri, _frame) = rx.recv().await.unwrap();
        assert_eq!(pri, SendPriority::Data);
    }

    #[tokio::test]
    async fn control_session_class_dequeued_before_bulk() {
        // Verify that when both Control and Bulk messages are queued via
        // session-class-aware handles, Control messages are dispatched first.
        let state = Arc::new(RwLock::new(ConnectionState::Connected));
        let (tx, mut rx) = mpsc::channel::<(SendPriority, OutboundFrame)>(16);

        let control_handle = SendPipelineHandle::new(Arc::clone(&state), tx.clone(), 16)
            .with_session_class(SessionClass::Control);
        let bulk_handle = SendPipelineHandle::new(Arc::clone(&state), tx, 16)
            .with_session_class(SessionClass::TransferBulk);

        // Enqueue bulk first, then control.
        bulk_handle
            .send(MessageFamily::StateTransfer, b"bulk")
            .await
            .unwrap();
        control_handle
            .send(MessageFamily::HeartbeatAck, b"control")
            .await
            .unwrap();

        // Feed into the scheduler and verify dequeue order.
        let mut scheduler = SendScheduler::<OutboundFrame>::new(SendSchedulerConfig::default());
        while let Ok((pri, frame)) = rx.try_recv() {
            scheduler.enqueue(frame, pri);
        }

        let first = scheduler.dequeue().unwrap();
        assert_eq!(first.priority, SendPriority::Control);
        let second = scheduler.dequeue().unwrap();
        assert_eq!(second.priority, SendPriority::Bulk);
    }
}
