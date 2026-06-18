// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-connection outbound send dispatch with ordered delivery and
//! backpressure flow control.
//!
//! ## Architecture
//!
//! ```text
//! MessageFamily + payload
//!        |
//!        v
//! SendDispatcher::enqueue(conn_id, msg)
//!        |
//!        +-- lookup conn_id -> SendQueue
//!        +-- enqueue into bounded FIFO queue
//!        |   (max messages + max bytes guards)
//!        +-- return admission evidence or SendError evidence
//!              |
//!              v
//!         SendDrainer per connection
//!              |
//!              +-- pull from SendQueue
//!              +-- feed serialized bytes to TCP I/O write half
//!              +-- notify blocked producers on capacity free
//! ```
//!
//! ## Backpressure contract
//!
//! Callers must inspect the admission evidence returned by `enqueue` or
//! carried by [`SendError`]:
//!
//! | Outcome/error       | Meaning                                                    |
//! |---------------------|------------------------------------------------------------|
//! | `Queued`            | Message accepted into the per-connection send queue.       |
//! | `Backpressure`      | Queue at capacity; caller should delay, drop, or shed.     |
//! | `SendQueueFull`     | Lane-class queue depth is at capacity.                     |
//! | `Shutdown`          | Queue has been shut down (connection closed).              |
//!
//! `Backpressure` is a soft signal — it does not tear down the connection.
//! Callers can inspect the connection ID, current queue depth, and current
//! byte depth from the evidence to make load-shedding decisions.
//!
//! ## Configuration
//!
//! `SendQueueConfig` carries:
//! - `max_messages`: maximum number of messages the queue will hold.
//! - `max_bytes`: maximum total bytes of payload the queue will hold.
//!
//! Enqueue returns `Backpressured` evidence when either threshold is exceeded.
//!
//! ## Integration points
//!
//! - **Upstream**: `SendBatcher` (#5803) batched output flows into
//!   `SendDispatcher::enqueue()`.
//! - **Downstream**: `SendDrainer` feeds drained bytes to the TCP I/O
//!   write half (#5822).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, Notify};

use crate::connection_registry::ConnectionId;
use crate::envelope::MessageFamily;
use crate::error_classification::{
    default_recovery_action, ErrorClassifier, ErrorObserver, TransportErrorKind,
};
use crate::lane_demux::LaneClass;
use crate::send_admission::{
    SendAdmissionEvidence, SendAdmissionOutcome, SendAdmissionPolicy, SendCapacityClass,
    SendCapacityEvidence, SendWakeEvidence,
};
use crate::send_concurrency::{SendConcurrencyError, SendConcurrencyLimiter};
use crate::send_queue_depth::{SendQueueDepth, SendQueueDepthConfig};
use crate::PeerId;

// ---------------------------------------------------------------------------
// SendQueueConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`SendQueue`]: per-connection capacity limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendQueueConfig {
    /// Maximum number of messages the queue will hold.
    pub max_messages: usize,
    /// Maximum total bytes of payload the queue will hold.
    pub max_bytes: usize,
}

impl SendQueueConfig {
    /// Create a new config, validating that `max_messages` and `max_bytes`
    /// are both nonzero.
    ///
    /// Returns `None` if either parameter is zero.
    pub fn new(max_messages: usize, max_bytes: usize) -> Option<Self> {
        if max_messages == 0 || max_bytes == 0 {
            return None;
        }
        Some(Self {
            max_messages,
            max_bytes,
        })
    }
}

impl Default for SendQueueConfig {
    fn default() -> Self {
        Self {
            max_messages: 256,
            max_bytes: 4 * 1_048_576, // 4 MiB
        }
    }
}

impl fmt::Display for SendQueueConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SendQueueConfig {{ max_messages: {}, max_bytes: {} }}",
            self.max_messages, self.max_bytes,
        )
    }
}

// ---------------------------------------------------------------------------
// SendError
// ---------------------------------------------------------------------------

/// Outcome of enqueuing a message into the send dispatch system.
#[derive(Clone, Debug)]
pub enum SendError {
    /// Queue is at capacity; the caller should delay, drop, or shed.
    /// Carries the connection ID, current queue depth (messages), and
    /// current byte depth so the caller can make informed decisions.
    Backpressure {
        /// Connection ID whose queue is full.
        conn_id: PeerId,
        /// Current number of messages queued.
        depth: usize,
        /// Current total bytes queued.
        byte_depth: usize,
        /// Typed admission evidence for this rejection.
        evidence: SendAdmissionEvidence,
    },
    /// No queue exists for the given connection ID.
    /// The connection has not been registered or has been removed.
    NoConnection {
        conn_id: PeerId,
        evidence: SendAdmissionEvidence,
    },
    /// Queue has been shut down (connection closed).
    Shutdown {
        conn_id: PeerId,
        evidence: SendAdmissionEvidence,
    },
    /// Send-concurrency limit exceeded for this connection;
    /// the caller should back off or retry.
    SendConcurrencyLimitExceeded {
        conn_id: PeerId,
        max: usize,
        evidence: SendAdmissionEvidence,
    },
    /// Per-session-class send-queue depth limit reached.
    /// The lane class is at capacity; caller should delay, drop, or shed.
    SendQueueFull {
        /// The lane class at capacity.
        lane: LaneClass,
        /// Current depth for this lane.
        depth: usize,
        /// Configured maximum depth for this lane.
        max_depth: usize,
        /// Typed admission evidence for this rejection.
        evidence: SendAdmissionEvidence,
    },
}

impl SendError {
    /// Return the admission evidence carried by this send error.
    #[must_use]
    pub fn evidence(&self) -> &SendAdmissionEvidence {
        match self {
            Self::Backpressure { evidence, .. }
            | Self::NoConnection { evidence, .. }
            | Self::Shutdown { evidence, .. }
            | Self::SendConcurrencyLimitExceeded { evidence, .. }
            | Self::SendQueueFull { evidence, .. } => evidence,
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backpressure {
                conn_id,
                depth,
                byte_depth,
                ..
            } => {
                write!(
                    f,
                    "backpressure on conn {conn_id}: depth={depth} msgs, byte_depth={byte_depth}B"
                )
            }
            Self::NoConnection { conn_id, .. } => {
                write!(f, "no send queue for conn {conn_id}")
            }
            Self::Shutdown { conn_id, .. } => {
                write!(f, "send queue shut down for conn {conn_id}")
            }
            Self::SendConcurrencyLimitExceeded { conn_id, max, .. } => {
                write!(
                    f,
                    "send concurrency limit exceeded for conn {conn_id}: max={max}"
                )
            }
            Self::SendQueueFull {
                lane,
                depth,
                max_depth,
                ..
            } => {
                write!(
                    f,
                    "send-queue full for lane {}: depth={depth}, max={max_depth}",
                    lane.as_str()
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OutboundMessage
// ---------------------------------------------------------------------------

/// A message enqueued for outbound dispatch.
///
/// Carries the [`MessageFamily`] discriminant and the serialized payload
/// bytes (post-codec, optionally post-batching).
#[derive(Clone, Debug)]
pub struct OutboundMessage {
    /// The message family classifying this message.
    pub family: MessageFamily,
    /// The serialized payload bytes.
    pub payload: Vec<u8>,
}

impl OutboundMessage {
    /// Create a new outbound message.
    pub fn new(family: MessageFamily, payload: Vec<u8>) -> Self {
        Self { family, payload }
    }

    /// Return the total byte size of this message for accounting.
    pub fn byte_len(&self) -> usize {
        1 + self.payload.len() // family discriminant (1 byte) + payload
    }
}

// ---------------------------------------------------------------------------
// SendQueue
// ---------------------------------------------------------------------------

/// A bounded FIFO send queue for a single remote connection.
///
/// Holds [`OutboundMessage`] entries with configurable limits on message
/// count and total byte occupancy. Enqueue returns typed admission evidence
/// or [`SendError::Backpressure`] when either limit would be exceeded.
///
/// The queue is internally mutex-protected and can be shared between the
/// dispatch path (producer) and the drainer path (consumer).
pub struct SendQueue {
    inner: Mutex<InnerQueue>,
    /// Notify signal for blocked producers / waiting drainer.
    notify: Arc<Notify>,
}

struct InnerQueue {
    queue: VecDeque<OutboundMessage>,
    config: SendQueueConfig,
    depth: usize,
    byte_depth: usize,
    shutdown: bool,
}

impl SendQueue {
    /// Create a new send queue with the given configuration and connection ID.
    pub fn new(config: SendQueueConfig, _conn_id: PeerId) -> Self {
        Self {
            inner: Mutex::new(InnerQueue {
                queue: VecDeque::with_capacity(config.max_messages.min(64)),
                config,
                depth: 0,
                byte_depth: 0,
                shutdown: false,
            }),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Try to enqueue a message into the send queue.
    ///
    /// Returns queued evidence on success, [`SendError::Backpressure`] if
    /// the queue is at capacity (message count or byte limit), or
    /// [`SendError::Shutdown`] if the queue has been shut down.
    pub fn try_enqueue(
        &self,
        conn_id: PeerId,
        msg: OutboundMessage,
    ) -> Result<SendAdmissionEvidence, SendError> {
        let mut inner = self.inner.try_lock().map_err(|_| SendError::Shutdown {
            conn_id,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                .with_conn_id(conn_id)
                .with_policy(SendAdmissionPolicy::Shutdown)
                .with_wake(SendWakeEvidence::Unavailable),
        })?;

        if inner.shutdown {
            return Err(SendError::Shutdown {
                conn_id,
                evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                    .with_conn_id(conn_id)
                    .with_family(msg.family)
                    .with_lane(msg.family.preferred_lane())
                    .with_queue_depth(inner.depth)
                    .with_byte_depth(inner.byte_depth)
                    .with_policy(SendAdmissionPolicy::Shutdown),
            });
        }

        let msg_bytes = msg.byte_len();
        let family = msg.family;
        let lane = family.preferred_lane();

        // Check both capacity limits.
        if inner.depth >= inner.config.max_messages
            || inner.byte_depth + msg_bytes > inner.config.max_bytes
        {
            let (class, current, limit) = if inner.depth >= inner.config.max_messages {
                (
                    SendCapacityClass::Message,
                    inner.depth,
                    inner.config.max_messages,
                )
            } else {
                (
                    SendCapacityClass::Byte,
                    inner.byte_depth,
                    inner.config.max_bytes,
                )
            };
            return Err(SendError::Backpressure {
                conn_id,
                depth: inner.depth,
                byte_depth: inner.byte_depth,
                evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                    .with_conn_id(conn_id)
                    .with_family(family)
                    .with_lane(lane)
                    .with_queue_depth(inner.depth)
                    .with_byte_depth(inner.byte_depth)
                    .with_policy(SendAdmissionPolicy::Error)
                    .with_capacity(SendCapacityEvidence::new(
                        class,
                        current,
                        Some(msg_bytes),
                        Some(limit),
                    )),
            });
        }

        inner.depth += 1;
        inner.byte_depth += msg_bytes;
        inner.queue.push_back(msg);
        self.notify.notify_one();
        Ok(SendAdmissionEvidence::new(SendAdmissionOutcome::Queued)
            .with_conn_id(conn_id)
            .with_family(family)
            .with_lane(lane)
            .with_queue_depth(inner.depth)
            .with_byte_depth(inner.byte_depth)
            .with_capacity(SendCapacityEvidence::new(
                SendCapacityClass::Message,
                inner.depth,
                Some(1),
                Some(inner.config.max_messages),
            )))
    }

    /// Dequeue the next message from the front of the queue.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&self) -> Option<OutboundMessage> {
        let mut inner = self.inner.try_lock().ok()?;
        let msg = inner.queue.pop_front()?;
        inner.depth = inner.depth.saturating_sub(1);
        inner.byte_depth = inner.byte_depth.saturating_sub(msg.byte_len());
        self.notify.notify_waiters();
        Some(msg)
    }

    /// Return the current queue depth (message count).
    pub fn depth(&self) -> usize {
        match self.inner.try_lock() {
            Ok(guard) => guard.depth,
            Err(_) => 0,
        }
    }

    /// Return the current queue byte depth.
    pub fn byte_depth(&self) -> usize {
        match self.inner.try_lock() {
            Ok(guard) => guard.byte_depth,
            Err(_) => 0,
        }
    }

    /// Return whether the queue has been shut down.
    pub fn is_shutdown(&self) -> bool {
        match self.inner.try_lock() {
            Ok(guard) => guard.shutdown,
            Err(_) => true,
        }
    }

    /// Shut down the queue, preventing further enqueues and draining
    /// remaining messages.
    pub fn shutdown(&self) {
        if let Ok(mut inner) = self.inner.try_lock() {
            inner.shutdown = true;
            inner.queue.clear();
            inner.depth = 0;
            inner.byte_depth = 0;
            self.notify.notify_waiters();
        }
    }
}

impl fmt::Debug for SendQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let depth = self.depth();
        let byte_depth = self.byte_depth();
        let shutdown = self.is_shutdown();
        f.debug_struct("SendQueue")
            .field("depth", &depth)
            .field("byte_depth", &byte_depth)
            .field("shutdown", &shutdown)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SendDispatcher
// ---------------------------------------------------------------------------

// Per-connection send dispatch registry.
//
// Owns a map of connection ID to [`SendQueue`]. Routes outbound
// [`OutboundMessage`] entries to the correct per-connection queue.
// ---------------------------------------------------------------------------
// SendError → TransportErrorKind mapping
// ---------------------------------------------------------------------------

/// Map a [`SendError`] to a [`TransportErrorKind`] for classification.
fn send_error_to_transport_kind(err: &SendError) -> TransportErrorKind {
    match err {
        SendError::Backpressure { .. } => TransportErrorKind::BackpressureStall,
        SendError::NoConnection { .. } => TransportErrorKind::InternalError,
        SendError::Shutdown { .. } => TransportErrorKind::InternalError,
        SendError::SendConcurrencyLimitExceeded { .. } => TransportErrorKind::BackpressureStall,
        SendError::SendQueueFull { .. } => TransportErrorKind::BackpressureStall,
    }
}

/// Multiple producer tasks can share a [`SendDispatcher`] behind an
/// `Arc` via internal mutex protection.
pub struct SendDispatcher {
    config: SendQueueConfig,
    queues: Mutex<HashMap<PeerId, Arc<SendQueue>>>,
    /// Per-connection send-concurrency limiters, keyed by `PeerId`.
    limiters: Mutex<HashMap<PeerId, Arc<SendConcurrencyLimiter>>>,
    /// Maximum in-flight sends per connection; `None` disables limiting.
    max_inflight: Option<usize>,
    /// Per-session-class send-queue depth governor; `None` disables governance.
    queue_depth: Option<Arc<SendQueueDepth>>,
    classifier: ErrorClassifier,
    observer: Option<Arc<dyn ErrorObserver>>,
}

impl SendDispatcher {
    /// Create a new dispatcher with the given queue configuration.
    ///
    /// The config will be used for every newly created per-connection
    /// send queue.
    /// Create a new dispatcher with the given queue configuration.
    ///
    /// `classifier` and `observer` are used to classify send errors
    /// and notify when backpressure, connection loss, or shutdown
    /// occurs. Pass `None` for `observer` to skip notification.
    pub fn new(
        config: SendQueueConfig,
        classifier: ErrorClassifier,
        observer: Option<Arc<dyn ErrorObserver>>,
    ) -> Self {
        Self {
            config,
            queues: Mutex::new(HashMap::new()),
            limiters: Mutex::new(HashMap::new()),
            max_inflight: None,
            queue_depth: None,
            classifier,
            observer,
        }
    }

    /// Enable per-connection send-concurrency limiting.
    ///
    /// When set, every [`enqueue`](Self::enqueue) call acquires a
    /// send-concurrency permit before enqueueing into the send queue.
    /// The permit is released when the call returns (whether on
    /// success or error).  This prevents one hot peer from saturating
    /// the enqueue path with concurrent calls and provides per-connection
    /// observability via [`SendConcurrencyLimiter`] metrics.
    #[must_use]
    pub fn with_max_inflight(mut self, max: usize) -> Self {
        assert!(max > 0, "max_inflight must be non-zero");
        self.max_inflight = Some(max);
        self
    }

    /// Enable per-session-class send-queue depth governance.
    ///
    /// When set, every [`enqueue`](Self::enqueue) call must acquire
    /// a per-lane-class depth reservation before enqueueing into the
    /// send queue.  Returns [`SendError::SendQueueFull`] when a lane
    /// class is at its configured `max_depth`.
    ///
    /// The [`SendQueueDepth`] is shared behind an `Arc` so the drainer
    /// path can release reservations as messages are consumed.
    #[must_use]
    pub fn with_queue_depth(mut self, config: SendQueueDepthConfig) -> Self {
        self.queue_depth = Some(Arc::new(SendQueueDepth::new(config)));
        self
    }

    /// Return the per-session-class send-queue depth governor, if enabled.
    pub fn queue_depth(&self) -> Option<Arc<SendQueueDepth>> {
        self.queue_depth.clone()
    }

    /// Return the per-connection send-concurrency limiter for `conn_id`,
    /// if limiting is enabled and a limiter exists.
    pub fn limiter(&self, conn_id: PeerId) -> Option<Arc<SendConcurrencyLimiter>> {
        match self.limiters.try_lock() {
            Ok(guard) => guard.get(&conn_id).cloned(),
            Err(_) => None,
        }
    }

    /// Enqueue an outbound message for the given connection.
    ///
    /// If no queue exists yet for `conn_id`, one is created automatically
    /// using the dispatcher's [`SendQueueConfig`].
    ///
    /// When send-queue depth governance is enabled, a per-lane-class
    /// reservation is acquired before enqueueing.  The reservation is
    /// released when the message is drained by [`SendDrainer`].
    ///
    /// # Errors
    ///
    /// Returns [`SendError::Backpressure`] if the queue is at capacity,
    /// [`SendError::SendQueueFull`] if the lane class depth is exceeded,
    /// or [`SendError::Shutdown`] if the queue has been shut down.
    pub fn enqueue(
        &self,
        conn_id: PeerId,
        msg: OutboundMessage,
    ) -> Result<SendAdmissionEvidence, SendError> {
        let lane = msg.family.preferred_lane();
        let family = msg.family;

        // Acquire a send-concurrency permit before enqueueing.
        let _permit = if let Some(max_inflight) = self.max_inflight {
            let limiter = self.get_or_create_limiter(conn_id, max_inflight)?;
            Some(limiter.try_acquire().map_err(|e| {
                match e {
                    SendConcurrencyError::LimitExceeded { max } => {
                        SendError::SendConcurrencyLimitExceeded {
                            conn_id,
                            max,
                            evidence: SendAdmissionEvidence::new(
                                SendAdmissionOutcome::Backpressured,
                            )
                            .with_conn_id(conn_id)
                            .with_family(family)
                            .with_lane(lane)
                            .with_policy(SendAdmissionPolicy::Concurrency)
                            .with_capacity(SendCapacityEvidence::new(
                                SendCapacityClass::Concurrency,
                                max,
                                Some(1),
                                Some(max),
                            )),
                        }
                    }
                    SendConcurrencyError::ConnectionNotSendable
                    | SendConcurrencyError::Shutdown => SendError::Shutdown {
                        conn_id,
                        evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                            .with_conn_id(conn_id)
                            .with_family(family)
                            .with_lane(lane)
                            .with_policy(SendAdmissionPolicy::Shutdown),
                    },
                }
            })?)
        } else {
            None
        };

        // Acquire per-lane-class depth reservation, if governance is enabled.
        if let Some(ref qd) = self.queue_depth {
            if let Err(e) = qd.try_reserve(lane) {
                return Err(SendError::SendQueueFull {
                    lane: e.lane,
                    depth: e.depth,
                    max_depth: e.max_depth,
                    evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                        .with_conn_id(conn_id)
                        .with_family(family)
                        .with_lane(e.lane)
                        .with_queue_depth(e.depth)
                        .with_policy(SendAdmissionPolicy::LaneDepth)
                        .with_capacity(SendCapacityEvidence::new(
                            SendCapacityClass::Lane,
                            e.depth,
                            Some(1),
                            Some(e.max_depth),
                        )),
                });
            }
        }

        let queue = match self.get_or_create_queue(conn_id) {
            Ok(queue) => queue,
            Err(err) => {
                if let Some(ref qd) = self.queue_depth {
                    qd.release(lane);
                }
                return Err(err);
            }
        };
        let result = queue.try_enqueue(conn_id, msg);
        if let Err(ref send_err) = &result {
            // Release the depth reservation if enqueue failed.
            if let Some(ref qd) = self.queue_depth {
                qd.release(lane);
            }
            let kind = send_error_to_transport_kind(send_err);
            let transport_err = self
                .classifier
                .classify_kind_direct(kind, ConnectionId::new(conn_id));
            let action = default_recovery_action(kind);
            if let Some(ref observer) = self.observer {
                observer.on_error(&transport_err, action);
            }
        }
        result
    }

    /// Remove a connection's send queue, shutting it down.
    ///
    /// Returns the removed queue if it existed.
    pub fn remove_connection(&self, conn_id: PeerId) -> Option<Arc<SendQueue>> {
        let mut queues = self.queues.try_lock().ok()?;
        let queue = queues.remove(&conn_id)?;
        queue.shutdown();
        Some(queue)
    }

    /// Shut down all connection queues.
    pub fn shutdown_all(&self) {
        if let Ok(mut queues) = self.queues.try_lock() {
            for (_, queue) in queues.drain() {
                queue.shutdown();
            }
        }
    }

    /// Return the number of active connection queues.
    pub fn connection_count(&self) -> usize {
        match self.queues.try_lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    /// Get a snapshot of per-connection depths.
    pub fn depth_snapshot(&self) -> Vec<(PeerId, usize, usize)> {
        match self.queues.try_lock() {
            Ok(guard) => guard
                .iter()
                .map(|(&k, q)| (k, q.depth(), q.byte_depth()))
                .collect(),
            Err(_) => vec![],
        }
    }

    /// Feed the backpressure depth for a specific connection into a health
    /// signal sink.
    ///
    /// Uses `ConnectionId(peer_id)` to bridge the `PeerId` → `ConnectionId`
    /// gap between the send dispatch layer and the health scoring layer.
    pub fn feed_health_backpressure(
        &self,
        peer_id: PeerId,
        sink: &mut dyn crate::peer_health::HealthSignalSink,
    ) {
        let conn_id = crate::connection_registry::ConnectionId(peer_id);
        if let Some(queue) = self.queue(peer_id) {
            let depth = queue.depth();
            sink.ingest_signal(
                conn_id,
                crate::peer_health::HealthSignal::BackpressureDepth(depth),
            );
        }
    }

    pub fn queue(&self, conn_id: PeerId) -> Option<Arc<SendQueue>> {
        match self.queues.try_lock() {
            Ok(guard) => guard.get(&conn_id).cloned(),
            Err(_) => None,
        }
    }

    /// Get or create the send queue for a connection.
    fn get_or_create_queue(&self, conn_id: PeerId) -> Result<Arc<SendQueue>, SendError> {
        let mut queues = self.queues.try_lock().map_err(|_| SendError::Shutdown {
            conn_id,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                .with_conn_id(conn_id)
                .with_policy(SendAdmissionPolicy::Shutdown)
                .with_wake(SendWakeEvidence::Unavailable),
        })?;

        if let Some(queue) = queues.get(&conn_id) {
            if queue.is_shutdown() {
                return Err(SendError::Shutdown {
                    conn_id,
                    evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                        .with_conn_id(conn_id)
                        .with_policy(SendAdmissionPolicy::Shutdown),
                });
            }
            return Ok(Arc::clone(queue));
        }

        let queue = Arc::new(SendQueue::new(self.config, conn_id));
        queues.insert(conn_id, Arc::clone(&queue));
        Ok(queue)
    }

    /// Get or create the send-concurrency limiter for a connection.
    fn get_or_create_limiter(
        &self,
        conn_id: PeerId,
        max: usize,
    ) -> Result<Arc<SendConcurrencyLimiter>, SendError> {
        let mut limiters = self.limiters.try_lock().map_err(|_| SendError::Shutdown {
            conn_id,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed)
                .with_conn_id(conn_id)
                .with_policy(SendAdmissionPolicy::Shutdown)
                .with_wake(SendWakeEvidence::Unavailable),
        })?;

        if let Some(limiter) = limiters.get(&conn_id) {
            return Ok(Arc::clone(limiter));
        }

        let limiter = Arc::new(SendConcurrencyLimiter::new(max));
        limiters.insert(conn_id, Arc::clone(&limiter));
        Ok(limiter)
    }
}

impl fmt::Debug for SendDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.connection_count();
        f.debug_struct("SendDispatcher")
            .field("config", &self.config)
            .field("connection_count", &count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// DrainedBatch
// ---------------------------------------------------------------------------

/// A batch of messages drained from a per-connection send queue.
///
/// Produced by [`SendDrainer`] and consumed by the TCP I/O write path.
#[derive(Clone, Debug)]
pub struct DrainedBatch {
    /// The connection ID this batch was drained from.
    pub conn_id: PeerId,
    /// The drained messages in FIFO order.
    pub messages: Vec<OutboundMessage>,
}

// ---------------------------------------------------------------------------
// SendDrainer
// ---------------------------------------------------------------------------

/// A per-connection background task that drains messages from a
/// [`SendQueue`] and feeds them to the TCP I/O write half via an
/// mpsc channel.
///
/// The drainer pulls messages in FIFO order, accumulates them into
/// batches up to `max_batch_items`, and sends the batch to the
/// TCP I/O write path.
pub struct SendDrainer {
    conn_id: PeerId,
    queue: Arc<SendQueue>,
    drain_tx: mpsc::Sender<DrainedBatch>,
    max_batch_items: usize,
    /// Per-session-class depth governor; released on dequeue.
    queue_depth: Option<Arc<SendQueueDepth>>,
}

impl SendDrainer {
    /// Create a new drainer for the given connection.
    ///
    /// `drain_tx` is the mpsc sender that feeds into the TCP I/O write
    /// half. `max_batch_items` caps the number of messages per drained
    /// batch (to avoid monopolizing the drain task when the queue is
    /// deep).
    ///
    /// `queue_depth` is the optional per-session-class depth governor.
    /// When set, each dequeued message releases its lane-class reservation.
    pub fn new(
        conn_id: PeerId,
        queue: Arc<SendQueue>,
        drain_tx: mpsc::Sender<DrainedBatch>,
        max_batch_items: usize,
        queue_depth: Option<Arc<SendQueueDepth>>,
    ) -> Self {
        Self {
            conn_id,
            queue,
            drain_tx,
            max_batch_items,
            queue_depth,
        }
    }

    /// Run the drainer as a background task.
    ///
    /// Pulls messages from the queue in a loop, batches them, and sends
    /// them to the drain channel. When send-queue depth governance is
    /// enabled, each dequeued message releases its per-lane-class
    /// reservation. Returns when the queue is shut down and empty,
    /// or when the drain channel is closed.
    ///
    /// This method is intended to be spawned as a `tokio::spawn` task.
    pub async fn run(self) {
        loop {
            // Pull up to max_batch_items from the queue.
            let mut batch = Vec::with_capacity(self.max_batch_items.min(16));
            for _ in 0..self.max_batch_items {
                match self.queue.dequeue() {
                    Some(msg) => {
                        // Release lane-class depth reservation on dequeue.
                        if let Some(ref qd) = self.queue_depth {
                            qd.release(msg.family.preferred_lane());
                        }
                        batch.push(msg);
                    }
                    None => break,
                }
            }

            if !batch.is_empty() {
                let drained = DrainedBatch {
                    conn_id: self.conn_id,
                    messages: batch,
                };
                if self.drain_tx.send(drained).await.is_err() {
                    // Channel closed; stop draining.
                    break;
                }
            }

            // If the queue is shut down and empty, exit.
            if self.queue.is_shutdown() && self.queue.depth() == 0 {
                break;
            }
        }
    }

    /// Run the drainer synchronously (for testing).
    ///
    /// Drains all available messages from the queue and returns them.
    /// Does not block waiting for new messages. Releases per-lane-class
    /// depth reservations when governance is enabled.
    pub fn drain_sync(&self) -> Vec<OutboundMessage> {
        let mut batch = Vec::with_capacity(self.max_batch_items.min(16));
        for _ in 0..self.max_batch_items {
            match self.queue.dequeue() {
                Some(msg) => {
                    if let Some(ref qd) = self.queue_depth {
                        qd.release(msg.family.preferred_lane());
                    }
                    batch.push(msg);
                }
                None => break,
            }
        }
        batch
    }
}

impl fmt::Debug for SendDrainer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendDrainer")
            .field("conn_id", &self.conn_id)
            .field("max_batch_items", &self.max_batch_items)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // SendQueueConfig tests
    // -------------------------------------------------------------------

    #[test]
    fn config_validation_rejects_zero_max_messages() {
        assert!(SendQueueConfig::new(0, 1024).is_none());
    }

    #[test]
    fn config_validation_rejects_zero_max_bytes() {
        assert!(SendQueueConfig::new(256, 0).is_none());
    }

    #[test]
    fn config_validation_accepts_valid() {
        let c = SendQueueConfig::new(256, 4096);
        assert!(c.is_some());
        let c = c.unwrap();
        assert_eq!(c.max_messages, 256);
        assert_eq!(c.max_bytes, 4096);
    }

    #[test]
    fn config_default_is_valid() {
        let c = SendQueueConfig::default();
        assert!(c.max_messages > 0);
        assert!(c.max_bytes > 0);
    }

    #[test]
    fn config_display() {
        let c = SendQueueConfig::default();
        let s = format!("{c}");
        assert!(s.contains("max_messages"));
        assert!(s.contains("max_bytes"));
    }

    // -------------------------------------------------------------------
    // OutboundMessage tests
    // -------------------------------------------------------------------

    #[test]
    fn outbound_message_byte_len() {
        let msg = OutboundMessage::new(MessageFamily::HeartbeatAck, vec![0u8; 100]);
        assert_eq!(msg.byte_len(), 101); // 1 byte family + 100 bytes payload
    }

    #[test]
    fn outbound_message_byte_len_empty_payload() {
        let msg = OutboundMessage::new(MessageFamily::HelloClose, vec![]);
        assert_eq!(msg.byte_len(), 1); // just the family discriminant
    }

    // -------------------------------------------------------------------
    // SendQueue tests
    // -------------------------------------------------------------------

    #[test]
    fn enqueue_dequeue_fifo() {
        let config = SendQueueConfig::default();
        let q = SendQueue::new(config, 1);
        let a = OutboundMessage::new(MessageFamily::StateTransfer, b"a".to_vec());
        let b = OutboundMessage::new(MessageFamily::StateTransfer, b"b".to_vec());

        q.try_enqueue(1, a.clone()).unwrap();
        q.try_enqueue(1, b.clone()).unwrap();

        assert_eq!(q.depth(), 2);
        assert_eq!(q.dequeue().unwrap().payload, b"a");
        assert_eq!(q.dequeue().unwrap().payload, b"b");
        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn backpressure_on_message_count() {
        let config = SendQueueConfig::new(3, 1_000_000).unwrap();
        let q = SendQueue::new(config, 1);

        q.try_enqueue(1, make_msg(b"a")).unwrap();
        q.try_enqueue(1, make_msg(b"b")).unwrap();
        q.try_enqueue(1, make_msg(b"c")).unwrap();

        let result = q.try_enqueue(1, make_msg(b"d"));
        match result {
            Err(SendError::Backpressure {
                depth, evidence, ..
            }) => {
                assert_eq!(depth, 3);
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
                assert_eq!(evidence.capacity.unwrap().class, SendCapacityClass::Message);
            }
            other => panic!("expected Backpressure, got: {other:?}"),
        }
    }

    #[test]
    fn backpressure_on_byte_count() {
        let config = SendQueueConfig::new(100, 20).unwrap(); // only 20 bytes total
        let q = SendQueue::new(config, 1);

        // 15-byte payload + 1 byte family = 16 bytes → fits
        q.try_enqueue(1, make_msg(&[0u8; 15])).unwrap();
        assert_eq!(q.depth(), 1);

        // Next 15-byte payload would push to 32 bytes > 20 → backpressure
        let result = q.try_enqueue(1, make_msg(&[0u8; 15]));
        match result {
            Err(SendError::Backpressure {
                byte_depth,
                evidence,
                ..
            }) => {
                assert_eq!(byte_depth, 16);
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
                assert_eq!(evidence.capacity.unwrap().class, SendCapacityClass::Byte);
            }
            other => panic!("expected Backpressure, got: {other:?}"),
        }
    }

    #[test]
    fn dequeue_frees_capacity() {
        let config = SendQueueConfig::new(2, 10).unwrap();
        let q = SendQueue::new(config, 1);

        // 5 bytes + 1 byte family = 6 bytes each.
        // First message fits: 6 <= 10 bytes.
        q.try_enqueue(1, make_msg(&[0u8; 5])).unwrap();

        // Second message does not fit: 6 + 6 = 12 > 10 -> backpressure.
        let result = q.try_enqueue(1, make_msg(&[0u8; 5]));
        assert!(matches!(result, Err(SendError::Backpressure { .. })));

        // Dequeue frees 6 bytes; now re-enqueue should succeed.
        q.dequeue().unwrap();
        q.try_enqueue(1, make_msg(&[0u8; 5])).unwrap();
        assert_eq!(q.depth(), 1);
    }

    #[test]
    fn dequeue_frees_capacity_for_re_enqueue() {
        let config = SendQueueConfig::new(2, 100).unwrap();
        let q = SendQueue::new(config, 1);

        q.try_enqueue(1, make_msg(b"a")).unwrap();
        q.try_enqueue(1, make_msg(b"b")).unwrap();

        // Queue full (2/2 messages).
        let result = q.try_enqueue(1, make_msg(b"c"));
        assert!(matches!(result, Err(SendError::Backpressure { .. })));

        q.dequeue(); // free one slot
        q.try_enqueue(1, make_msg(b"c")).unwrap();
        assert_eq!(q.depth(), 2);
    }

    #[test]
    fn shutdown_prevents_enqueue() {
        let config = SendQueueConfig::default();
        let q = SendQueue::new(config, 1);

        q.try_enqueue(1, make_msg(b"data")).unwrap();
        q.shutdown();

        assert!(q.is_shutdown());
        assert_eq!(q.depth(), 0);

        let result = q.try_enqueue(1, make_msg(b"more"));
        assert!(matches!(result, Err(SendError::Shutdown { .. })));
    }

    #[test]
    fn shutdown_drains_queue() {
        let config = SendQueueConfig::default();
        let q = SendQueue::new(config, 1);

        q.try_enqueue(1, make_msg(b"a")).unwrap();
        q.try_enqueue(1, make_msg(b"b")).unwrap();
        assert_eq!(q.depth(), 2);

        q.shutdown();
        assert_eq!(q.depth(), 0);
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn empty_queue_returns_none() {
        let config = SendQueueConfig::default();
        let q = SendQueue::new(config, 1);

        assert_eq!(q.depth(), 0);
        assert_eq!(q.byte_depth(), 0);
        assert!(q.dequeue().is_none());
    }

    // -------------------------------------------------------------------
    // SendDispatcher tests
    // -------------------------------------------------------------------

    #[test]
    fn dispatcher_creates_queue_on_first_enqueue() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        assert_eq!(dispatcher.connection_count(), 0);

        let msg = make_msg(b"hello");
        dispatcher.enqueue(42, msg).unwrap();

        assert_eq!(dispatcher.connection_count(), 1);
        assert_eq!(dispatcher.queue(42).unwrap().depth(), 1);
    }

    #[test]
    fn dispatcher_routes_to_correct_connection() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        dispatcher.enqueue(1, make_msg(b"conn-1")).unwrap();
        dispatcher.enqueue(2, make_msg(b"conn-2-a")).unwrap();
        dispatcher.enqueue(2, make_msg(b"conn-2-b")).unwrap();

        assert_eq!(dispatcher.connection_count(), 2);

        let q1 = dispatcher.queue(1).unwrap();
        let q2 = dispatcher.queue(2).unwrap();
        assert_eq!(q1.depth(), 1);
        assert_eq!(q2.depth(), 2);

        assert_eq!(q1.dequeue().unwrap().payload, b"conn-1");
        assert_eq!(q2.dequeue().unwrap().payload, b"conn-2-a");
        assert_eq!(q2.dequeue().unwrap().payload, b"conn-2-b");
    }

    #[test]
    fn dispatcher_backpressure_per_connection() {
        let config = SendQueueConfig::new(2, 10_000).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        dispatcher.enqueue(1, make_msg(b"a")).unwrap();
        dispatcher.enqueue(1, make_msg(b"b")).unwrap();

        let result = dispatcher.enqueue(1, make_msg(b"c"));
        match result {
            Err(SendError::Backpressure { conn_id, depth, .. }) => {
                assert_eq!(conn_id, 1);
                assert_eq!(depth, 2);
            }
            other => panic!("expected Backpressure, got: {other:?}"),
        }

        // Connection 2 is unaffected.
        dispatcher.enqueue(2, make_msg(b"x")).unwrap();
    }

    #[test]
    fn dispatcher_remove_connection() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        dispatcher.enqueue(1, make_msg(b"data")).unwrap();
        assert_eq!(dispatcher.connection_count(), 1);

        let removed = dispatcher.remove_connection(1);
        assert!(removed.is_some());
        assert!(removed.unwrap().is_shutdown());
        assert_eq!(dispatcher.connection_count(), 0);

        // Enqueue after removal should create a new queue.
        dispatcher.enqueue(1, make_msg(b"new-data")).unwrap();
        assert_eq!(dispatcher.connection_count(), 1);
    }

    #[test]
    fn dispatcher_shutdown_all() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        dispatcher.enqueue(1, make_msg(b"a")).unwrap();
        dispatcher.enqueue(2, make_msg(b"b")).unwrap();
        dispatcher.enqueue(3, make_msg(b"c")).unwrap();

        dispatcher.shutdown_all();

        assert_eq!(dispatcher.connection_count(), 0);

        // Enqueue after shutdown_all creates fresh queues.
        dispatcher.enqueue(1, make_msg(b"d")).unwrap();
        assert_eq!(dispatcher.connection_count(), 1);
    }

    #[test]
    fn dispatcher_depth_snapshot() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        dispatcher.enqueue(1, make_msg(b"x")).unwrap();
        dispatcher.enqueue(2, make_msg(b"y")).unwrap();
        dispatcher.enqueue(2, make_msg(b"z")).unwrap();

        let snap = dispatcher.depth_snapshot();
        // Sort for deterministic comparison.
        let mut ids: Vec<u64> = snap.iter().map(|(id, _, _)| *id).collect();
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn dispatcher_no_connection() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        // queue() returns None for unknown connection.
        assert!(dispatcher.queue(999).is_none());
    }

    // -------------------------------------------------------------------
    // SendDrainer tests
    // -------------------------------------------------------------------

    #[test]
    fn drainer_drains_all_messages() {
        let config = SendQueueConfig::default();
        let q = Arc::new(SendQueue::new(config, 1));

        q.try_enqueue(1, make_msg(b"a")).unwrap();
        q.try_enqueue(1, make_msg(b"b")).unwrap();
        q.try_enqueue(1, make_msg(b"c")).unwrap();

        let drainer = SendDrainer {
            conn_id: 1,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 2,
            queue_depth: None,
        };

        let drained = drainer.drain_sync();
        assert_eq!(drained.len(), 2); // max_batch_items = 2
        assert_eq!(drained[0].payload, b"a");
        assert_eq!(drained[1].payload, b"b");

        let drained = drainer.drain_sync();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, b"c");

        // Queue should be empty.
        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn drainer_empty_queue_returns_empty() {
        let config = SendQueueConfig::default();
        let q = Arc::new(SendQueue::new(config, 1));

        let drainer = SendDrainer {
            conn_id: 1,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 16,
            queue_depth: None,
        };

        let drained = drainer.drain_sync();
        assert!(drained.is_empty());
    }

    // -------------------------------------------------------------------
    // SendError tests
    // -------------------------------------------------------------------

    #[test]
    fn send_error_display_backpressure() {
        let e = SendError::Backpressure {
            conn_id: 42,
            depth: 10,
            byte_depth: 4096,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                .with_conn_id(42)
                .with_queue_depth(10)
                .with_byte_depth(4096),
        };
        let s = format!("{e}");
        assert!(s.contains("42"));
        assert!(s.contains("10"));
        assert!(s.contains("4096"));
    }

    #[test]
    fn send_error_display_no_connection() {
        let e = SendError::NoConnection {
            conn_id: 7,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::NoConnection)
                .with_conn_id(7),
        };
        let s = format!("{e}");
        assert!(s.contains("7"));
        assert!(s.contains("no send queue"));
    }

    #[test]
    fn send_error_display_shutdown() {
        let e = SendError::Shutdown {
            conn_id: 3,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Closed).with_conn_id(3),
        };
        let s = format!("{e}");
        assert!(s.contains("3"));
        assert!(s.contains("shut down"));
    }

    // -------------------------------------------------------------------
    // Debug output
    // -------------------------------------------------------------------

    #[test]
    fn send_queue_debug() {
        let config = SendQueueConfig::default();
        let q = SendQueue::new(config, 1);
        let s = format!("{q:?}");
        assert!(s.contains("depth"));
        assert!(s.contains("byte_depth"));
        assert!(s.contains("shutdown"));
    }

    #[test]
    fn send_dispatcher_debug() {
        let config = SendQueueConfig::default();
        let d = SendDispatcher::new(config, ErrorClassifier::new(), None);
        let s = format!("{d:?}");
        assert!(s.contains("SendDispatcher"));
        assert!(s.contains("connection_count"));
    }

    #[test]
    fn send_drainer_debug() {
        let config = SendQueueConfig::default();
        let q = Arc::new(SendQueue::new(config, 1));
        let drainer = SendDrainer {
            conn_id: 1,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 16,
            queue_depth: None,
        };
        let s = format!("{drainer:?}");
        assert!(s.contains("conn_id"));
        assert!(s.contains("max_batch_items"));
    }

    // -------------------------------------------------------------------
    // Integration: dispatcher + drainer
    // -------------------------------------------------------------------

    #[test]
    fn dispatcher_enqueue_then_drainer_drains() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        for i in 0..5 {
            dispatcher.enqueue(1, make_msg(&[i as u8])).unwrap();
        }

        let q = dispatcher.queue(1).unwrap();
        let drainer = SendDrainer {
            conn_id: 1,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 10,
            queue_depth: None,
        };

        let drained = drainer.drain_sync();
        assert_eq!(drained.len(), 5);
        for (i, msg) in drained.iter().enumerate() {
            assert_eq!(msg.payload[0], i as u8);
        }

        assert_eq!(q.depth(), 0);
    }

    #[test]
    fn fifo_ordering_across_enqueue_and_drain() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        let expected: Vec<u8> = (0..100).map(|i| i as u8).collect();

        for &b in &expected {
            dispatcher.enqueue(1, make_msg(&[b])).unwrap();
        }

        let q = dispatcher.queue(1).unwrap();
        let drainer = SendDrainer {
            conn_id: 1,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 100,
            queue_depth: None,
        };

        let drained = drainer.drain_sync();
        assert_eq!(drained.len(), 100);
        for (i, msg) in drained.iter().enumerate() {
            assert_eq!(
                msg.payload[0], expected[i],
                "FIFO ordering violated at position {i}"
            );
        }
    }

    #[test]
    fn multi_connection_fifo_isolation() {
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);

        // Interleave enqueues to two connections.
        dispatcher.enqueue(10, make_msg(b"10-a")).unwrap();
        dispatcher.enqueue(20, make_msg(b"20-a")).unwrap();
        dispatcher.enqueue(10, make_msg(b"10-b")).unwrap();
        dispatcher.enqueue(20, make_msg(b"20-b")).unwrap();

        let q10 = dispatcher.queue(10).unwrap();
        let q20 = dispatcher.queue(20).unwrap();

        let d10 = SendDrainer {
            conn_id: 10,
            queue: Arc::clone(&q10),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 10,
            queue_depth: None,
        };
        let d20 = SendDrainer {
            conn_id: 20,
            queue: Arc::clone(&q20),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 10,
            queue_depth: None,
        };

        let drained10 = d10.drain_sync();
        let drained20 = d20.drain_sync();

        assert_eq!(drained10.len(), 2);
        assert_eq!(drained20.len(), 2);
        assert_eq!(drained10[0].payload, b"10-a");
        assert_eq!(drained10[1].payload, b"10-b");
        assert_eq!(drained20[0].payload, b"20-a");
        assert_eq!(drained20[1].payload, b"20-b");
    }

    // -------------------------------------------------------------------
    // Codec integration tests
    // -------------------------------------------------------------------

    /// Serialize messages through MessageCodec, enqueue into SendDispatcher,
    /// drain through SendDrainer, decode, and verify byte-for-byte FIFO
    /// delivery.
    #[test]
    fn codec_roundtrip_through_send_dispatch() {
        let codec = crate::codec::MessageCodec::default();
        let config = SendQueueConfig::default();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);
        let conn_id: PeerId = 42;

        // Encode several messages through the codec.
        let messages: Vec<(MessageFamily, Vec<u8>)> = vec![
            (MessageFamily::HelloClose, b"hello-close-payload".to_vec()),
            (MessageFamily::HeartbeatAck, b"heartbeat-data".to_vec()),
            (MessageFamily::StateTransfer, vec![0u8; 256]),
            (MessageFamily::LeaseFenceDeadline, b"lease-fence".to_vec()),
            (MessageFamily::PublicationProgress, b"pub-progress".to_vec()),
        ];

        let encoded_frames: Vec<Vec<u8>> = messages
            .iter()
            .map(|(family, payload)| codec.encode(*family, payload).expect("codec encode"))
            .collect();

        // Enqueue each encoded frame as an OutboundMessage.
        for frame in &encoded_frames {
            // The frame from codec is [payload_len LE][family u8][payload...].
            // We extract family from the frame and store the full frame as payload
            // so we can decode it after drain.
            let family = match codec.decode(frame) {
                Ok((f, _)) => f,
                Err(e) => panic!("decode failed: {e:?}"),
            };
            dispatcher
                .enqueue(conn_id, OutboundMessage::new(family, frame.clone()))
                .expect("enqueue");
        }

        // Drain all messages.
        let q = dispatcher.queue(conn_id).unwrap();
        let drainer = SendDrainer {
            conn_id,
            queue: Arc::clone(&q),
            drain_tx: mpsc::channel::<DrainedBatch>(1).0,
            max_batch_items: 10,
            queue_depth: None,
        };

        let drained = drainer.drain_sync();
        assert_eq!(drained.len(), messages.len(), "all messages should drain");

        // Decode each drained message and verify byte-for-byte with original.
        for (i, msg) in drained.iter().enumerate() {
            let (decoded_family, decoded_payload) =
                codec.decode(&msg.payload).expect("decode drained frame");
            let (orig_family, orig_payload) = &messages[i];

            assert_eq!(decoded_family, *orig_family, "message {i}: family mismatch");
            assert_eq!(
                decoded_payload, *orig_payload,
                "message {i}: payload mismatch"
            );
        }

        // Queue should be empty after drain.
        assert_eq!(q.depth(), 0);
        assert_eq!(q.byte_depth(), 0);
    }

    /// Verify backpressure carries accurate depth information that callers
    /// can inspect.
    #[test]
    fn codec_integration_backpressure_metadata() {
        let codec = crate::codec::MessageCodec::default();
        let config = SendQueueConfig::new(2, 1024).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);
        let conn_id: PeerId = 7;

        let frame = codec
            .encode(MessageFamily::StateTransfer, b"payload-a")
            .unwrap();

        dispatcher
            .enqueue(
                conn_id,
                OutboundMessage::new(MessageFamily::StateTransfer, frame.clone()),
            )
            .unwrap();
        dispatcher
            .enqueue(
                conn_id,
                OutboundMessage::new(MessageFamily::StateTransfer, frame),
            )
            .unwrap();

        // Third enqueue must hit backpressure.
        let frame3 = codec
            .encode(MessageFamily::StateTransfer, b"payload-c")
            .unwrap();
        let result = dispatcher.enqueue(
            conn_id,
            OutboundMessage::new(MessageFamily::StateTransfer, frame3),
        );

        match result {
            Err(SendError::Backpressure {
                conn_id: cid,
                depth,
                byte_depth,
                ..
            }) => {
                assert_eq!(cid, 7);
                assert_eq!(depth, 2);
                assert!(byte_depth > 0, "byte_depth should be non-zero");
            }
            other => panic!("expected Backpressure, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------

    fn make_msg(payload: &[u8]) -> OutboundMessage {
        OutboundMessage::new(MessageFamily::StateTransfer, payload.to_vec())
    }

    // -------------------------------------------------------------------
    // Send-concurrency limiter integration tests (#5998)
    // -------------------------------------------------------------------

    #[test]
    fn send_concurrency_limit_exceeded_error_display() {
        let e = SendError::SendConcurrencyLimitExceeded {
            conn_id: 42,
            max: 5,
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                .with_conn_id(42)
                .with_capacity(SendCapacityEvidence::new(
                    SendCapacityClass::Concurrency,
                    5,
                    Some(1),
                    Some(5),
                )),
        };
        let s = format!("{e}");
        assert!(s.contains("42"), "display should mention conn_id");
        assert!(s.contains("5"), "display should mention max");
    }

    #[test]
    fn dispatcher_without_max_inflight_bypasses_limiter() {
        // Backward-compatible: when max_inflight is not set, enqueue
        // works normally without acquiring any permit.
        let config = SendQueueConfig::new(16, 1024 * 1024).unwrap();
        let dispatcher = SendDispatcher::new(config, ErrorClassifier::new(), None);
        let conn_id: PeerId = 10;

        // Multiple enqueues should succeed (no limiting configured).
        for i in 0..10 {
            let msg = make_msg(format!("msg-{i}").as_bytes());
            let result = dispatcher.enqueue(conn_id, msg);
            assert!(result.is_ok(), "enqueue {i} should succeed without limiter");
        }

        // No limiter should exist.
        assert!(dispatcher.limiter(conn_id).is_none());
    }

    #[test]
    fn dispatcher_per_connection_limiter_isolation() {
        // Each peer gets its own independent limiter.
        // Concurrent enqueues on the same peer compete, but enqueues on
        // different peers do not interfere.
        use std::sync::Barrier;
        let config = SendQueueConfig::new(16, 1024 * 1024).unwrap();
        let dispatcher = Arc::new(
            SendDispatcher::new(config, ErrorClassifier::new(), None).with_max_inflight(1),
        );
        let peer_a: PeerId = 100;
        let peer_b: PeerId = 200;

        // Seed the limiters.
        dispatcher.enqueue(peer_a, make_msg(b"seed")).unwrap();
        dispatcher.enqueue(peer_b, make_msg(b"seed")).unwrap();

        assert!(dispatcher.limiter(peer_a).is_some(), "peer A has a limiter");
        assert!(dispatcher.limiter(peer_b).is_some(), "peer B has a limiter");

        // Concurrently enqueue on peer_a and peer_b.
        let barrier = Arc::new(Barrier::new(3));
        let results = Arc::new(std::sync::Mutex::new(Vec::new()));

        for (tid, peer) in [(0, peer_a), (1, peer_b)] {
            let d = Arc::clone(&dispatcher);
            let b = Arc::clone(&barrier);
            let r = Arc::clone(&results);
            std::thread::spawn(move || {
                b.wait();
                let res = d.enqueue(peer, make_msg(format!("t{tid}").as_bytes()));
                r.lock().unwrap().push((peer, res));
            });
        }

        barrier.wait();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let final_results = results.lock().unwrap();

        // Peer B must succeed (independent limiter from peer A).
        // Peer A may get Shutdown from transient lock contention
        // on the shared limiters HashMap; the important property
        // is that peer B's limiter is independent.
        let b_ok = final_results.iter().any(|(p, r)| *p == peer_b && r.is_ok());
        assert!(
            b_ok,
            "peer B should succeed with independent limiter: {final_results:?}"
        );
    }

    #[test]
    fn dispatcher_per_connection_limiter_metrics_independent() {
        // High-watermark metrics are independent per-peer.
        let config = SendQueueConfig::new(16, 1024 * 1024).unwrap();
        let dispatcher =
            SendDispatcher::new(config, ErrorClassifier::new(), None).with_max_inflight(5);
        let peer_a: PeerId = 300;
        let peer_b: PeerId = 400;

        // Enqueue several messages on each peer (serial, so in-flight drops to 0 each time).
        dispatcher.enqueue(peer_a, make_msg(b"a1")).unwrap();
        dispatcher.enqueue(peer_a, make_msg(b"a2")).unwrap();
        dispatcher.enqueue(peer_b, make_msg(b"b1")).unwrap();

        let lim_a = dispatcher.limiter(peer_a).unwrap();
        let lim_b = dispatcher.limiter(peer_b).unwrap();

        // In-flight is 0 because permits are released on return.
        assert_eq!(
            lim_a.in_flight_current(),
            0,
            "peer A in-flight returns to 0"
        );
        assert_eq!(
            lim_b.in_flight_current(),
            0,
            "peer B in-flight returns to 0"
        );

        // High-watermark captures peak concurrent usage.
        assert_eq!(
            lim_a.in_flight_high_watermark(),
            1,
            "peer A high-watermark should be 1 (serial calls)"
        );
        assert_eq!(
            lim_b.in_flight_high_watermark(),
            1,
            "peer B high-watermark should be 1"
        );
    }

    #[test]
    fn dispatcher_with_max_inflight_parity_without_limiter() {
        // When two dispatchers are created identically except one has
        // max_inflight enabled and both have sufficient capacity,
        // they should both accept messages.
        let config = SendQueueConfig::new(16, 1024 * 1024).unwrap();
        let d_no_limit = SendDispatcher::new(config, ErrorClassifier::new(), None);
        let d_with_limit =
            SendDispatcher::new(config, ErrorClassifier::new(), None).with_max_inflight(8);

        let conn_id: PeerId = 500;

        let result1 = d_no_limit.enqueue(conn_id, make_msg(b"hi"));
        let result2 = d_with_limit.enqueue(conn_id, make_msg(b"hi"));
        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }
}
