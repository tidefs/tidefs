//! Per-session message prioritization with Control/Data head-of-line bypass
//! for the outbound send path.
//!
//! ## Design
//!
//! Two priority classes (`Control`, `Data`) each have an independent FIFO
//! sub-queue. Dequeue drains the Control queue before the Data queue,
//! preventing bulk data transfers from delaying control-plane traffic
//! (membership, leases, epoch transitions, keepalive).
//!
//! The Control queue has a bounded depth (default 16 messages) to prevent
//! abuse by misbehaving callers. The Data queue is unbounded.
//!
//! Starvation prevention (opt-in via []):
//! after N consecutive Control dequeues, the scheduler yields one Data message
//! to prevent indefinite Data starvation under sustained control traffic.
//!
//! ## Message classes
//!
//! | Class   | Priority | Use cases                                             |
//! |---------|----------|-------------------------------------------------------|
//! | Control | high     | membership state, leases, epoch transitions, keepalive|
//! | Data    | normal   | object replication, chunk transfer, background scrub  |
//!
//! No wire-format changes: prioritization is a send-side ordering decision.
//! Receivers process messages in arrival order as before.

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// MessagePriority
// ---------------------------------------------------------------------------

/// Message priority class for session send scheduling.
///
/// Control-plane messages always bypass queued Data-plane messages within
/// a session, preventing head-of-line blocking of time-sensitive control
/// traffic during bulk data transfers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MessagePriority {
    /// Membership state, leases, epoch transitions, keepalive.
    /// Starvation of this class causes false peer-failure detection.
    Control = 0,
    /// Object replication, chunk transfer, background scrub.
    /// Starvation is acceptable for moderate intervals.
    Data = 1,
}

impl MessagePriority {
    /// Number of distinct priority classes.
    pub const fn count() -> usize {
        2
    }

    /// All classes in priority order (highest first).
    pub fn all() -> [MessagePriority; 2] {
        [MessagePriority::Control, MessagePriority::Data]
    }
}

// ---------------------------------------------------------------------------
// MessagePriorityConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`MessagePriorityQueue`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessagePriorityConfig {
    /// Maximum number of Control-class messages allowed in the queue.
    /// Enqueue beyond this limit returns [`MessagePriorityError::ControlQueueFull`].
    pub control_max_depth: usize,
    /// After this many consecutive Control dequeues, yield one Data message
    /// to prevent indefinite Data starvation. When set to 0 (default), no
    /// starvation prevention is applied and Control is drained strictly-first.
    pub starvation_prevention_threshold: usize,
}

impl Default for MessagePriorityConfig {
    fn default() -> Self {
        Self {
            control_max_depth: 16,
            starvation_prevention_threshold: 0,
        }
    }
}

impl MessagePriorityConfig {
    /// Validate the configuration. Returns `Err` on invalid values.
    pub fn validate(&self) -> Result<(), String> {
        if self.control_max_depth == 0 {
            return Err("control_max_depth must be > 0".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MessagePriorityError
// ---------------------------------------------------------------------------

/// Error returned when enqueuing into a [`MessagePriorityQueue`] fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessagePriorityError {
    /// The Control queue has reached its configured maximum depth.
    ControlQueueFull {
        /// Current depth of the Control queue.
        depth: usize,
        /// Configured maximum depth.
        max_depth: usize,
    },
}

impl std::fmt::Display for MessagePriorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ControlQueueFull { depth, max_depth } => {
                write!(
                    f,
                    "control queue full: depth={depth}, max_depth={max_depth}"
                )
            }
        }
    }
}

impl std::error::Error for MessagePriorityError {}

// ---------------------------------------------------------------------------
// MessagePriorityQueue
// ---------------------------------------------------------------------------

/// A per-session priority queue with Control/Data sub-queues.
///
/// Dequeue always drains Control messages before Data messages, providing
/// head-of-line bypass for time-sensitive control-plane traffic.
///
/// # Type parameters
///
/// * `M` - The message type held in queues.
pub struct MessagePriorityQueue<M> {
    control: VecDeque<M>,
    data: VecDeque<M>,
    config: MessagePriorityConfig,
    total_enqueued: u64,
    total_dequeued: u64,
    /// Number of consecutive Control messages dequeued since the last Data yield.
    consecutive_control_dequeues: usize,
}

impl<M> MessagePriorityQueue<M> {
    /// Create a new priority queue with the given configuration.
    pub fn new(config: MessagePriorityConfig) -> Self {
        config
            .validate()
            .expect("MessagePriorityConfig validation failed");
        Self {
            control: VecDeque::new(),
            data: VecDeque::new(),
            config,
            total_enqueued: 0,
            total_dequeued: 0,
            consecutive_control_dequeues: 0,
        }
    }

    /// Create a new priority queue with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MessagePriorityConfig::default())
    }

    // ------------------------------------------------------------------
    // Enqueue
    // ------------------------------------------------------------------

    /// Enqueue a message with the given priority class.
    ///
    /// Returns `Ok(())` on success, or [`MessagePriorityError::ControlQueueFull`]
    /// if the Control queue has reached its maximum depth.
    pub fn enqueue(
        &mut self,
        message: M,
        priority: MessagePriority,
    ) -> Result<(), MessagePriorityError> {
        match priority {
            MessagePriority::Control => {
                if self.control.len() >= self.config.control_max_depth {
                    return Err(MessagePriorityError::ControlQueueFull {
                        depth: self.control.len(),
                        max_depth: self.config.control_max_depth,
                    });
                }
                self.control.push_back(message);
            }
            MessagePriority::Data => {
                self.data.push_back(message);
            }
        }
        self.total_enqueued += 1;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Dequeue
    // ------------------------------------------------------------------

    /// Dequeue the next message, draining Control before Data with optional
    /// starvation prevention.
    ///
    /// When [](MessagePriorityConfig::starvation_prevention_threshold)
    /// is > 0 and N consecutive Control messages have been dequeued, the next
    /// dequeue yields one Data message (if available) to prevent indefinite
    /// Data starvation under sustained control traffic.
    ///
    /// Returns `None` when both queues are empty.
    pub fn dequeue(&mut self) -> Option<M> {
        // Starvation prevention: yield Data after N consecutive Control dequeues.
        let threshold = self.config.starvation_prevention_threshold;
        if threshold > 0 && self.consecutive_control_dequeues >= threshold && !self.data.is_empty()
        {
            if let Some(msg) = self.data.pop_front() {
                self.total_dequeued += 1;
                self.consecutive_control_dequeues = 0;
                return Some(msg);
            }
        }

        if let Some(msg) = self.control.pop_front() {
            self.total_dequeued += 1;
            if threshold > 0 {
                self.consecutive_control_dequeues =
                    self.consecutive_control_dequeues.saturating_add(1);
            }
            return Some(msg);
        }

        if let Some(msg) = self.data.pop_front() {
            self.total_dequeued += 1;
            self.consecutive_control_dequeues = 0;
            return Some(msg);
        }

        None
    }

    /// Dequeue the next message with its priority class, draining Control
    /// before Data. Returns `None` when both queues are empty.
    ///
    /// Use this when the caller needs to know which priority class the
    /// dequeued message came from (e.g. for per-priority statistics).
    ///
    /// Starvation prevention works the same way as [`dequeue`].
    pub fn dequeue_with_priority(&mut self) -> Option<(M, MessagePriority)> {
        // Starvation prevention: yield Data after N consecutive Control dequeues.
        let threshold = self.config.starvation_prevention_threshold;
        if threshold > 0 && self.consecutive_control_dequeues >= threshold && !self.data.is_empty()
        {
            if let Some(msg) = self.data.pop_front() {
                self.total_dequeued += 1;
                self.consecutive_control_dequeues = 0;
                return Some((msg, MessagePriority::Data));
            }
        }

        if let Some(msg) = self.control.pop_front() {
            self.total_dequeued += 1;
            if threshold > 0 {
                self.consecutive_control_dequeues =
                    self.consecutive_control_dequeues.saturating_add(1);
            }
            return Some((msg, MessagePriority::Control));
        }

        if let Some(msg) = self.data.pop_front() {
            self.total_dequeued += 1;
            self.consecutive_control_dequeues = 0;
            return Some((msg, MessagePriority::Data));
        }
        None
    }

    /// Dequeue up to `limit` messages, draining Control before Data.
    pub fn dequeue_batch(&mut self, limit: usize) -> Vec<M> {
        let mut batch = Vec::with_capacity(limit.min(self.len()));
        for _ in 0..limit {
            match self.dequeue() {
                Some(msg) => batch.push(msg),
                None => break,
            }
        }
        batch
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /// Total number of messages across both queues.
    pub fn len(&self) -> usize {
        self.control.len() + self.data.len()
    }

    /// Whether both queues are empty.
    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.data.is_empty()
    }

    /// Number of messages in the Control queue.
    pub fn control_len(&self) -> usize {
        self.control.len()
    }

    /// Number of messages in the Data queue.
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// Pop the oldest Data-priority message from the Data sub-queue,
    /// skipping any Control messages that may be ahead.
    ///
    /// Returns `None` if the Data sub-queue is empty. Control messages
    /// are never evicted by backpressure.
    pub fn pop_oldest_data(&mut self) -> Option<M> {
        self.data.pop_front()
    }

    /// Total messages ever enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Total messages ever dequeued.
    pub fn total_dequeued(&self) -> u64 {
        self.total_dequeued
    }

    /// The queue configuration (read-only).
    pub fn config(&self) -> &MessagePriorityConfig {
        &self.config
    }
}

impl<M> Default for MessagePriorityQueue<M> {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl<M: Clone> Clone for MessagePriorityQueue<M> {
    fn clone(&self) -> Self {
        Self {
            control: self.control.clone(),
            data: self.data.clone(),
            config: self.config,
            total_enqueued: self.total_enqueued,
            total_dequeued: self.total_dequeued,
            consecutive_control_dequeues: self.consecutive_control_dequeues,
        }
    }
}

impl<M: std::fmt::Debug> std::fmt::Debug for MessagePriorityQueue<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagePriorityQueue")
            .field("control_len", &self.control.len())
            .field("data_len", &self.data.len())
            .field("config", &self.config)
            .field("total_enqueued", &self.total_enqueued)
            .field("total_dequeued", &self.total_dequeued)
            .field(
                "consecutive_control_dequeues",
                &self.consecutive_control_dequeues,
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Outbound send cancellation — caller-visible handles for stale-message discard
//
// When a coordinator is deposed (election, #6222), an epoch advances, or
// a peer is evicted (#6221), messages already accepted into the priority
// queues become stale. These types provide a local queue-management primitive
// that lets upper layers proactively discard queued messages before they
// reach the wire.
//
// ## Security boundary
//
// This extension adds no cryptography, authentication, integrity verification,
// or authorization. Cancellation is purely local queue-management: it removes
// stale messages before they reach the wire. The existing transport/session
// security boundary (session ciphers, epoch fencing, membership roster gating,
// HELLO attestation) remains the sole authority for node-to-node authenticity
// and integrity.
// ---------------------------------------------------------------------------

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// SendCancelState — shared atomic state machine for one queued message
// ---------------------------------------------------------------------------

const STATE_QUEUED: u8 = 0;
const STATE_SENT: u8 = 1;
const STATE_CANCELLED: u8 = 2;

#[derive(Debug)]
struct SendCancelState {
    state: AtomicU8,
}

impl SendCancelState {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_QUEUED),
        }
    }

    /// QUEUED → CANCELLED. Returns `true` when the message was successfully
    /// cancelled before being sent.
    fn cancel(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_QUEUED,
                STATE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// QUEUED → SENT, called by the drain path. Returns `true` when the
    /// message should be sent, `false` when already cancelled.
    fn mark_sent(&self) -> bool {
        self.state
            .compare_exchange(
                STATE_QUEUED,
                STATE_SENT,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    fn current_state(&self) -> u8 {
        self.state.load(Ordering::Relaxed)
    }

    fn is_cancelled(&self) -> bool {
        self.current_state() == STATE_CANCELLED
    }
}

// ---------------------------------------------------------------------------
// SendCancelHandle — caller-visible handle, Clone + Send + Sync
// ---------------------------------------------------------------------------

/// Opaque handle that can cancel a single queued outbound message.
///
/// `SendCancelHandle` is cheap to clone — every clone targets the same
/// underlying message.  Any clone (or the original) can call [`cancel`]
/// to discard the message before it is sent.
///
/// Once a message has been dequeued and sent, further `cancel` calls
/// return `false` (the message is no longer in the queue).
#[derive(Clone, Debug)]
pub struct SendCancelHandle {
    inner: Arc<SendCancelState>,
}

impl SendCancelHandle {
    /// Cancel the associated outbound message if it is still queued.
    ///
    /// Returns `true` if the message was successfully cancelled before
    /// being sent.  Returns `false` if the message was already sent or
    /// already cancelled (idempotent).
    pub fn cancel(&self) -> bool {
        self.inner.cancel()
    }

    /// Returns `true` if this handle's message has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

// ---------------------------------------------------------------------------
// QueuedMessage — priority-queue entry with optional cancellation marker
// ---------------------------------------------------------------------------

/// An entry in the session's outbound priority queue.
///
/// Wraps the raw payload plus an optional cancellation marker so the drain
/// path can atomically check cancellation state before sending.
#[derive(Clone, Debug)]
pub(crate) struct QueuedMessage {
    pub payload: Vec<u8>,
    cancel: Option<Arc<SendCancelState>>,
}

impl QueuedMessage {
    /// Create a queue entry without a cancellation handle.
    pub(crate) fn new(payload: Vec<u8>) -> Self {
        Self {
            payload,
            cancel: None,
        }
    }

    /// Create a queue entry with a cancellation handle, returning both the
    /// entry and the caller-visible `SendCancelHandle`.
    pub(crate) fn new_cancelable(payload: Vec<u8>) -> (Self, SendCancelHandle) {
        let state = Arc::new(SendCancelState::new());
        let handle = SendCancelHandle {
            inner: Arc::clone(&state),
        };
        (
            Self {
                payload,
                cancel: Some(state),
            },
            handle,
        )
    }

    /// Called by the drain path before sending.  Returns `true` when the
    /// message should be sent, `false` when it has been cancelled.
    pub(crate) fn mark_sent(&self) -> bool {
        match &self.cancel {
            Some(state) => state.mark_sent(),
            None => true, // non-cancelable messages are always sent
        }
    }
}
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Discriminant values --

    #[test]
    fn priority_discriminants() {
        assert_eq!(MessagePriority::Control as u8, 0);
        assert_eq!(MessagePriority::Data as u8, 1);
    }

    #[test]
    fn priority_all_order() {
        let all = MessagePriority::all();
        assert_eq!(all[0], MessagePriority::Control);
        assert_eq!(all[1], MessagePriority::Data);
    }

    #[test]
    fn priority_ord_reflects_priority() {
        assert!(MessagePriority::Control < MessagePriority::Data);
    }

    // -- Config validation --

    #[test]
    fn config_default_is_valid() {
        let cfg = MessagePriorityConfig::default();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.control_max_depth, 16);
    }

    #[test]
    fn config_zero_depth_rejected() {
        let cfg = MessagePriorityConfig {
            control_max_depth: 0,
            starvation_prevention_threshold: 0,
        };
        assert!(cfg.validate().is_err());
    }

    // -- Empty queue --

    #[test]
    fn empty_queue_dequeue_returns_none() {
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::with_defaults();
        assert!(q.dequeue().is_none());
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
    }

    // -- Control bypasses Data --

    #[test]
    fn control_bypasses_queued_data() {
        let mut q = MessagePriorityQueue::with_defaults();
        // Enqueue Data then Control.
        q.enqueue("data-1", MessagePriority::Data).unwrap();
        q.enqueue("data-2", MessagePriority::Data).unwrap();
        q.enqueue("urgent-control", MessagePriority::Control)
            .unwrap();

        // First dequeue should be Control.
        let first = q.dequeue().unwrap();
        assert_eq!(first, "urgent-control");

        // Then Data in FIFO order.
        let second = q.dequeue().unwrap();
        assert_eq!(second, "data-1");
        let third = q.dequeue().unwrap();
        assert_eq!(third, "data-2");

        assert!(q.dequeue().is_none());
    }

    #[test]
    fn control_enqueued_first_still_dequeues_first() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("control", MessagePriority::Control).unwrap();
        q.enqueue("data", MessagePriority::Data).unwrap();

        assert_eq!(q.dequeue().unwrap(), "control");
        assert_eq!(q.dequeue().unwrap(), "data");
        assert!(q.dequeue().is_none());
    }

    // -- FIFO within priority class --

    #[test]
    fn data_messages_fifo_within_class() {
        let mut q = MessagePriorityQueue::with_defaults();
        for i in 0..10 {
            q.enqueue(i, MessagePriority::Data).unwrap();
        }
        for i in 0..10 {
            q.enqueue(i + 100, MessagePriority::Control).unwrap();
        }

        // All Control first (in FIFO order).
        for i in 0..10 {
            let msg = q.dequeue().unwrap();
            assert_eq!(msg, i + 100, "Control FIFO broken at index {i}");
        }

        // Then all Data (in FIFO order).
        for i in 0..10 {
            let msg = q.dequeue().unwrap();
            assert_eq!(msg, i, "Data FIFO broken at index {i}");
        }

        assert!(q.dequeue().is_none());
    }

    // -- Bounded Control queue depth --

    #[test]
    fn control_queue_bounded_depth_enforcement() {
        let cfg = MessagePriorityConfig {
            control_max_depth: 3,
            starvation_prevention_threshold: 0,
        };
        let mut q = MessagePriorityQueue::new(cfg);

        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();
        q.enqueue("c3", MessagePriority::Control).unwrap();

        let err = q.enqueue("c4", MessagePriority::Control).unwrap_err();
        assert_eq!(
            err,
            MessagePriorityError::ControlQueueFull {
                depth: 3,
                max_depth: 3,
            }
        );
        assert_eq!(q.control_len(), 3);
    }

    #[test]
    fn control_queue_accepts_after_dequeue() {
        let cfg = MessagePriorityConfig {
            control_max_depth: 2,
            starvation_prevention_threshold: 0,
        };
        let mut q = MessagePriorityQueue::new(cfg);

        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();
        assert!(q.enqueue("c3", MessagePriority::Control).is_err());

        q.dequeue(); // free one slot
        q.enqueue("c3", MessagePriority::Control).unwrap();
        assert_eq!(q.control_len(), 2);
    }

    #[test]
    fn data_queue_is_unbounded() {
        let cfg = MessagePriorityConfig {
            control_max_depth: 2,
            starvation_prevention_threshold: 0,
        };
        let mut q = MessagePriorityQueue::new(cfg);

        for i in 0..1000 {
            q.enqueue(i, MessagePriority::Data).unwrap();
        }
        assert_eq!(q.data_len(), 1000);
    }

    // -- Interleaved enqueue/dequeue --

    #[test]
    fn interleaved_enqueue_dequeue_maintains_ordering() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("a", MessagePriority::Data).unwrap();
        q.enqueue("ctrl", MessagePriority::Control).unwrap();
        assert_eq!(q.dequeue().unwrap(), "ctrl"); // Control jumps ahead
        q.enqueue("b", MessagePriority::Data).unwrap();
        q.enqueue("ctrl2", MessagePriority::Control).unwrap();
        assert_eq!(q.dequeue().unwrap(), "ctrl2");
        assert_eq!(q.dequeue().unwrap(), "a");
        assert_eq!(q.dequeue().unwrap(), "b");
        assert!(q.dequeue().is_none());
    }

    // -- Total counters --

    #[test]
    fn total_enqueued_and_dequeued_counters() {
        let mut q = MessagePriorityQueue::with_defaults();
        assert_eq!(q.total_enqueued(), 0);
        assert_eq!(q.total_dequeued(), 0);

        q.enqueue(1, MessagePriority::Control).unwrap();
        q.enqueue(2, MessagePriority::Data).unwrap();
        q.enqueue(3, MessagePriority::Data).unwrap();
        assert_eq!(q.total_enqueued(), 3);

        q.dequeue();
        q.dequeue();
        assert_eq!(q.total_dequeued(), 2);
        assert_eq!(q.total_enqueued(), 3);
    }

    // -- Dequeue batch --

    #[test]
    fn dequeue_batch_respects_limit() {
        let mut q = MessagePriorityQueue::with_defaults();
        for i in 0..5 {
            q.enqueue(i, MessagePriority::Data).unwrap();
        }

        let batch = q.dequeue_batch(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch, vec![0, 1, 2]);
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn dequeue_batch_control_first() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("d1", MessagePriority::Data).unwrap();
        q.enqueue("d2", MessagePriority::Data).unwrap();
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();

        let batch = q.dequeue_batch(4);
        assert_eq!(batch, vec!["c1", "c2", "d1", "d2"]);
        assert!(q.is_empty());
    }

    // -- Empty-queue edge cases --

    #[test]
    fn only_control_queued_dequeues_control() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("only-ctrl", MessagePriority::Control).unwrap();
        assert_eq!(q.dequeue().unwrap(), "only-ctrl");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn only_data_queued_dequeues_data() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("only-data", MessagePriority::Data).unwrap();
        assert_eq!(q.dequeue().unwrap(), "only-data");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn both_empty_repeated_dequeue_returns_none() {
        let mut q: MessagePriorityQueue<u32> = MessagePriorityQueue::with_defaults();
        assert!(q.dequeue().is_none());
        assert!(q.dequeue().is_none());
        assert!(q.dequeue().is_none());
    }

    // -- Default via trait --

    #[test]
    fn default_queue_is_empty() {
        let q = MessagePriorityQueue::<u32>::default();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.config().control_max_depth, 16);
    }

    // -- Error display --

    #[test]
    fn control_queue_full_error_display() {
        let err = MessagePriorityError::ControlQueueFull {
            depth: 16,
            max_depth: 16,
        };
        let s = format!("{err}");
        assert!(s.contains("control queue full"));
        assert!(s.contains("depth=16"));
        assert!(s.contains("max_depth=16"));
    }

    // -- Debug output --

    #[test]
    fn queue_debug() {
        let mut q = MessagePriorityQueue::with_defaults();
        q.enqueue("a", MessagePriority::Control).unwrap();
        q.enqueue("b", MessagePriority::Data).unwrap();
        let s = format!("{q:?}");
        assert!(s.contains("control_len"));
        assert!(s.contains("data_len"));
        assert!(s.contains("total_enqueued"));
        assert!(s.contains("total_dequeued"));
    }

    // -- Clone --

    #[test]
    fn queue_clone_is_independent() {
        let mut q1 = MessagePriorityQueue::with_defaults();
        q1.enqueue("x", MessagePriority::Control).unwrap();
        q1.enqueue("y", MessagePriority::Data).unwrap();

        let q2 = q1.clone();
        assert_eq!(q1.len(), q2.len());

        // q2 dequeues independently.
        let mut q2 = q2;
        assert_eq!(q2.dequeue().unwrap(), "x");
        assert_eq!(q2.dequeue().unwrap(), "y");
        assert!(q2.is_empty());

        // q1 is unaffected.
        assert_eq!(q1.len(), 2);
    }

    // ------------------------------------------------------------------
    // SendCancelHandle + QueuedMessage lifecycle
    // ------------------------------------------------------------------

    #[test]
    fn cancel_queued_message_returns_true() {
        let (entry, handle) = QueuedMessage::new_cancelable(b"hello".to_vec());
        assert!(handle.cancel()); // cancel before drain
        assert!(!entry.mark_sent()); // drain sees cancelled state
    }

    #[test]
    fn cancel_already_sent_message_returns_false() {
        let (entry, handle) = QueuedMessage::new_cancelable(b"world".to_vec());
        assert!(entry.mark_sent()); // drain marks sent first
        assert!(!handle.cancel()); // cancel after send returns false
    }

    #[test]
    fn double_cancel_is_idempotent() {
        let (_entry, handle) = QueuedMessage::new_cancelable(b"double".to_vec());
        assert!(handle.cancel());
        assert!(!handle.cancel());
        assert!(handle.is_cancelled());
    }

    #[test]
    fn clone_cancel_behavior() {
        let (_entry, handle) = QueuedMessage::new_cancelable(b"clone".to_vec());
        let clone = handle.clone();
        assert!(clone.cancel());
        assert!(handle.is_cancelled());
        assert!(!handle.cancel());
    }

    #[test]
    fn uncancelled_message_is_sent_normally() {
        let (entry, _handle) = QueuedMessage::new_cancelable(b"normal".to_vec());
        assert!(entry.mark_sent());
    }

    #[test]
    fn message_without_handle_always_sent() {
        let entry = QueuedMessage::new(b"no-handle".to_vec());
        assert!(entry.mark_sent());
    }

    #[test]
    fn is_cancelled_after_cancel() {
        let (_entry, handle) = QueuedMessage::new_cancelable(b"x".to_vec());
        assert!(!handle.is_cancelled());
        handle.cancel();
        assert!(handle.is_cancelled());
    }

    #[test]
    fn is_cancelled_after_send() {
        let (entry, handle) = QueuedMessage::new_cancelable(b"y".to_vec());
        entry.mark_sent();
        assert!(!handle.is_cancelled());
    }

    #[test]
    fn cancel_one_message_in_batch() {
        let (c_entry, c_handle) = QueuedMessage::new_cancelable(b"cancel-me".to_vec());
        let e1 = QueuedMessage::new(b"keep-1".to_vec());
        let e2 = QueuedMessage::new(b"keep-2".to_vec());

        assert!(c_handle.cancel());
        assert!(!c_entry.mark_sent());
        assert_eq!(e1.payload, b"keep-1");
        assert_eq!(e2.payload, b"keep-2");
    }

    #[test]
    fn handle_debug_output() {
        let (_entry, handle) = QueuedMessage::new_cancelable(b"debug".to_vec());
        let s = format!("{handle:?}");
        assert!(s.contains("SendCancelHandle"));
    }

    // -- Starvation prevention -----------------------------------------

    #[test]
    fn starvation_prevention_disabled_by_default() {
        let cfg = MessagePriorityConfig::default();
        assert_eq!(cfg.starvation_prevention_threshold, 0);
    }

    #[test]
    fn starvation_prevention_zero_threshold_no_yield() {
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::new(MessagePriorityConfig {
            control_max_depth: 8,
            starvation_prevention_threshold: 0,
        });
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();
        q.enqueue("d1", MessagePriority::Data).unwrap();

        // Without starvation prevention, Control drains first entirely.
        assert_eq!(q.dequeue().unwrap(), "c1");
        assert_eq!(q.dequeue().unwrap(), "c2");
        assert_eq!(q.dequeue().unwrap(), "d1");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn starvation_prevention_yields_data_after_threshold() {
        let mut q: MessagePriorityQueue<String> =
            MessagePriorityQueue::new(MessagePriorityConfig {
                control_max_depth: 8,
                starvation_prevention_threshold: 2,
            });
        for i in 0..6 {
            q.enqueue(format!("c{i}"), MessagePriority::Control)
                .unwrap();
        }
        q.enqueue("d1".to_string(), MessagePriority::Data).unwrap();
        q.enqueue("d2".to_string(), MessagePriority::Data).unwrap();

        assert_eq!(q.dequeue().unwrap(), "c0");
        assert_eq!(q.dequeue().unwrap(), "c1");
        // threshold reached, d1 comes next
        assert_eq!(q.dequeue().unwrap(), "d1");
        assert_eq!(q.dequeue().unwrap(), "c2");
        assert_eq!(q.dequeue().unwrap(), "c3");
        // threshold reached again, d2 comes next
        assert_eq!(q.dequeue().unwrap(), "d2");
        assert_eq!(q.dequeue().unwrap(), "c4");
        assert_eq!(q.dequeue().unwrap(), "c5");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn starvation_prevention_skips_when_data_empty() {
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::new(MessagePriorityConfig {
            control_max_depth: 8,
            starvation_prevention_threshold: 2,
        });
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();
        q.enqueue("c3", MessagePriority::Control).unwrap();

        assert_eq!(q.dequeue().unwrap(), "c1");
        assert_eq!(q.dequeue().unwrap(), "c2");
        assert_eq!(q.dequeue().unwrap(), "c3");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn starvation_prevention_resets_on_data_dequeue() {
        // Control counter only resets when a Data message is actually dequeued
        // (either by starvation yield or by natural fall-through after Control empties).
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::new(MessagePriorityConfig {
            control_max_depth: 8,
            starvation_prevention_threshold: 1,
        });
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("d1", MessagePriority::Data).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();

        // threshold=1 means yield Data after every Control
        assert_eq!(q.dequeue().unwrap(), "c1");
        // threshold reached, yield d1
        assert_eq!(q.dequeue().unwrap(), "d1");
        // counter reset, next Control proceeds normally
        assert_eq!(q.dequeue().unwrap(), "c2");
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn starvation_prevention_with_priority_tracks_yield_class() {
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::new(MessagePriorityConfig {
            control_max_depth: 8,
            starvation_prevention_threshold: 2,
        });
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("c2", MessagePriority::Control).unwrap();
        q.enqueue("d1", MessagePriority::Data).unwrap();

        let (msg, pri) = q.dequeue_with_priority().unwrap();
        assert_eq!(msg, "c1");
        assert_eq!(pri, MessagePriority::Control);

        let (msg, pri) = q.dequeue_with_priority().unwrap();
        assert_eq!(msg, "c2");
        assert_eq!(pri, MessagePriority::Control);

        // threshold reached, yield Data
        let (msg, pri) = q.dequeue_with_priority().unwrap();
        assert_eq!(msg, "d1");
        assert_eq!(pri, MessagePriority::Data);

        assert!(q.dequeue_with_priority().is_none());
    }

    #[test]
    fn starvation_prevention_interleaved_batch_drain() {
        let mut q: MessagePriorityQueue<String> =
            MessagePriorityQueue::new(MessagePriorityConfig {
                control_max_depth: 16,
                starvation_prevention_threshold: 3,
            });
        for i in 0..10 {
            q.enqueue(format!("c{i}"), MessagePriority::Control)
                .unwrap();
        }
        for i in 0..4 {
            q.enqueue(format!("d{i}"), MessagePriority::Data).unwrap();
        }

        let batch = q.dequeue_batch(20);
        assert_eq!(batch[0], "c0");
        assert_eq!(batch[1], "c1");
        assert_eq!(batch[2], "c2");
        assert_eq!(batch[3], "d0"); // yield
        assert_eq!(batch[4], "c3");
        assert_eq!(batch[5], "c4");
        assert_eq!(batch[6], "c5");
        assert_eq!(batch[7], "d1"); // yield
        assert_eq!(batch[8], "c6");
        assert_eq!(batch[9], "c7");
        assert_eq!(batch[10], "c8");
        assert_eq!(batch[11], "d2"); // yield
        assert_eq!(batch[12], "c9");
        assert_eq!(batch[13], "d3"); // remaining data
        assert_eq!(batch.len(), 14);
    }

    #[test]
    fn starvation_prevention_queue_depth_stats_accurate() {
        let mut q: MessagePriorityQueue<&str> = MessagePriorityQueue::new(MessagePriorityConfig {
            control_max_depth: 8,
            starvation_prevention_threshold: 2,
        });
        q.enqueue("c1", MessagePriority::Control).unwrap();
        q.enqueue("d1", MessagePriority::Data).unwrap();
        q.enqueue("d2", MessagePriority::Data).unwrap();

        assert_eq!(q.control_len(), 1);
        assert_eq!(q.data_len(), 2);
        assert_eq!(q.len(), 3);

        q.dequeue().unwrap(); // c1
        assert_eq!(q.control_len(), 0);
        assert_eq!(q.data_len(), 2);
    }
}
