//! Typed send-pressure and admission evidence for outbound producers.
//!
//! This is the TFR-017 send-pressure boundary: it records what the local
//! transport send path knew when it accepted, queued, waited, rejected, or
//! cancelled an outbound attempt. It is intentionally separate from
//! session-close receipt authority and from storage placement or rebuild
//! authority.

use crate::envelope::MessageFamily;
use crate::lane_demux::LaneClass;
use crate::send_scheduler::SendPriority;
use crate::types::SessionId;
use crate::PeerId;

/// High-level outcome of a send admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendAdmissionOutcome {
    /// The send was accepted without observing pressure.
    Accepted,
    /// The send was queued in an intermediate transport FIFO.
    Queued,
    /// Capacity was unavailable and the send was not enqueued.
    Backpressured,
    /// The producer waited for a drain transition before the send was accepted.
    Blocked,
    /// The send was accepted only after dropping older queued work.
    DroppedOldest,
    /// The send deadline expired before anything was enqueued.
    ExpiredBeforeEnqueue,
    /// The peer, connection, session, or queue was closed or shut down.
    Closed,
    /// No usable connection, peer queue, or roster admission was available.
    NoConnection,
}

/// Capacity surface that made the admission decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendCapacityClass {
    /// Bounded number of queued messages.
    Message,
    /// Bounded number of queued bytes.
    Byte,
    /// Bounded per-lane depth.
    Lane,
    /// Bounded per-pipeline channel slots.
    PipelineChannel,
    /// Per-priority high/low watermark pressure.
    PriorityWatermark,
    /// Per-connection send-concurrency limit.
    Concurrency,
    /// Membership roster send gate.
    Roster,
    /// Connection lifecycle state gate.
    ConnectionState,
    /// Peer frame-buffer memory cap.
    BufferMemory,
}

/// Configured policy or gate that produced the decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendAdmissionPolicy {
    /// Return pressure to the caller without mutating the queue.
    Error,
    /// Wait for a drain wake before retrying admission.
    Block,
    /// Drop oldest queued work before admitting the new work.
    DropOldest,
    /// High/low watermark pressure.
    Watermark,
    /// Bounded channel admission.
    BoundedChannel,
    /// Per-lane queue-depth governor.
    LaneDepth,
    /// Per-connection concurrency governor.
    Concurrency,
    /// Membership roster send gate.
    Roster,
    /// Connection lifecycle state gate.
    ConnectionState,
    /// Queue or session shutdown.
    Shutdown,
}

/// Whether a drain or close wake was observed for a waiting producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendWakeEvidence {
    /// The decision did not wait for a wake.
    NotApplicable,
    /// A wait was required but no specific wake source was available.
    Unavailable,
    /// The caller is waiting or observed that wait admission would be needed.
    Waiting,
    /// A drain transition woke the producer.
    DrainObserved,
    /// A close or shutdown transition woke the producer.
    ClosedObserved,
    /// The notifying side disappeared while the producer was waiting.
    SenderDropped,
}

/// Capacity values observed at the decision point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendCapacityEvidence {
    /// Capacity surface that was checked.
    pub class: SendCapacityClass,
    /// Current depth or occupancy at the checked surface.
    pub current: usize,
    /// Requested increment for this admission attempt, when known.
    pub requested: Option<usize>,
    /// Configured bound, when known.
    pub limit: Option<usize>,
}

impl SendCapacityEvidence {
    /// Build a capacity evidence record.
    #[must_use]
    pub const fn new(
        class: SendCapacityClass,
        current: usize,
        requested: Option<usize>,
        limit: Option<usize>,
    ) -> Self {
        Self {
            class,
            current,
            requested,
            limit,
        }
    }
}

/// Evidence for older queued work dropped to admit a new send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DroppedSendEvidence {
    /// Dropped frame/message size in bytes, when known.
    pub bytes: Option<usize>,
    /// Queue depth before the drop, when known.
    pub queue_depth_before: Option<usize>,
    /// Byte depth before the drop, when known.
    pub byte_depth_before: Option<usize>,
    /// Dropped message family, when known.
    pub family: Option<MessageFamily>,
    /// Dropped priority class, when known.
    pub priority: Option<SendPriority>,
    /// Dropped lane class, when known.
    pub lane: Option<LaneClass>,
}

impl DroppedSendEvidence {
    /// Build dropped-frame evidence when only byte accounting is known.
    #[must_use]
    pub const fn frame(bytes: usize, queue_depth_before: usize, byte_depth_before: usize) -> Self {
        Self {
            bytes: Some(bytes),
            queue_depth_before: Some(queue_depth_before),
            byte_depth_before: Some(byte_depth_before),
            family: None,
            priority: None,
            lane: None,
        }
    }

    /// Build dropped-message evidence when payload details are not available.
    #[must_use]
    pub const fn message(queue_depth_before: usize) -> Self {
        Self {
            bytes: None,
            queue_depth_before: Some(queue_depth_before),
            byte_depth_before: None,
            family: None,
            priority: None,
            lane: None,
        }
    }
}

/// One typed evidence record for a send admission decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendAdmissionEvidence {
    /// Admission outcome.
    pub outcome: SendAdmissionOutcome,
    /// Peer identifier, when available.
    pub peer_id: Option<PeerId>,
    /// Connection identifier, when available.
    pub conn_id: Option<PeerId>,
    /// Session identifier, when available.
    pub session_id: Option<SessionId>,
    /// Priority class, when available.
    pub priority: Option<SendPriority>,
    /// Lane class, when available.
    pub lane: Option<LaneClass>,
    /// Message family, when available.
    pub family: Option<MessageFamily>,
    /// Queue depth after accepted admission or at rejection, when known.
    pub queue_depth: Option<usize>,
    /// Byte depth after accepted admission or at rejection, when known.
    pub byte_depth: Option<usize>,
    /// Checked capacity surface, when known.
    pub capacity: Option<SendCapacityEvidence>,
    /// Configured policy or gate that made the decision.
    pub policy: Option<SendAdmissionPolicy>,
    /// Drain or close wake evidence.
    pub wake: SendWakeEvidence,
    /// Dropped older work, if admission used a drop-oldest policy.
    pub dropped: Vec<DroppedSendEvidence>,
}

impl SendAdmissionEvidence {
    /// Start an evidence record with the given outcome.
    #[must_use]
    pub fn new(outcome: SendAdmissionOutcome) -> Self {
        Self {
            outcome,
            peer_id: None,
            conn_id: None,
            session_id: None,
            priority: None,
            lane: None,
            family: None,
            queue_depth: None,
            byte_depth: None,
            capacity: None,
            policy: None,
            wake: SendWakeEvidence::NotApplicable,
            dropped: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    #[must_use]
    pub fn with_conn_id(mut self, conn_id: PeerId) -> Self {
        self.conn_id = Some(conn_id);
        self
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    #[must_use]
    pub fn with_priority(mut self, priority: SendPriority) -> Self {
        self.priority = Some(priority);
        self
    }

    #[must_use]
    pub fn with_lane(mut self, lane: LaneClass) -> Self {
        self.lane = Some(lane);
        self
    }

    #[must_use]
    pub fn with_family(mut self, family: MessageFamily) -> Self {
        self.family = Some(family);
        self
    }

    #[must_use]
    pub fn with_queue_depth(mut self, depth: usize) -> Self {
        self.queue_depth = Some(depth);
        self
    }

    #[must_use]
    pub fn with_byte_depth(mut self, depth: usize) -> Self {
        self.byte_depth = Some(depth);
        self
    }

    #[must_use]
    pub fn with_capacity(mut self, capacity: SendCapacityEvidence) -> Self {
        self.capacity = Some(capacity);
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: SendAdmissionPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_wake(mut self, wake: SendWakeEvidence) -> Self {
        self.wake = wake;
        self
    }

    #[must_use]
    pub fn with_dropped(mut self, dropped: Vec<DroppedSendEvidence>) -> Self {
        self.dropped = dropped;
        self
    }
}

/// Admission evidence plus an optional accepted/cancelled return value.
#[derive(Debug)]
pub struct SendAdmission<T = ()> {
    /// Admission evidence.
    pub evidence: SendAdmissionEvidence,
    /// Value associated with the decision, such as a deadline token.
    pub value: Option<T>,
}

impl<T> SendAdmission<T> {
    /// Build admission evidence with an associated value.
    #[must_use]
    pub fn with_value(evidence: SendAdmissionEvidence, value: T) -> Self {
        Self {
            evidence,
            value: Some(value),
        }
    }

    /// Build admission evidence with no associated value.
    #[must_use]
    pub fn without_value(evidence: SendAdmissionEvidence) -> Self {
        Self {
            evidence,
            value: None,
        }
    }

    /// Return true when the outcome accepted or queued work.
    #[must_use]
    pub fn admitted(&self) -> bool {
        matches!(
            self.evidence.outcome,
            SendAdmissionOutcome::Accepted
                | SendAdmissionOutcome::Queued
                | SendAdmissionOutcome::Blocked
                | SendAdmissionOutcome::DroppedOldest
        )
    }
}
