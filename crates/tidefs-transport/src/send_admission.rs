// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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
use tidefs_cache_core::{
    AdmissionTicket, BackpressureSignal as GovernorBackpressureSignal, BudgetCategory, BudgetError,
    Governor,
};

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
    /// Unified governor `cluster_queues` memory budget.
    GovernorClusterQueues,
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
    /// Unified governor budget admission.
    GovernorBudget,
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

/// Governor pressure observed for the transport `cluster_queues` budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterQueuePressure {
    /// No cluster-queue memory pressure was observed.
    None,
    /// Cluster queues are above the governor soft watermark.
    SoftPressure,
    /// Cluster queues are at or above the governor hard-pressure watermark.
    HardPressure,
}

impl ClusterQueuePressure {
    /// Return true when the pressure should reduce non-critical admission.
    #[must_use]
    pub const fn is_pressure(self) -> bool {
        !matches!(self, Self::None)
    }

    /// Return true when non-critical cluster work should be refused.
    #[must_use]
    pub const fn refuses_non_critical(self) -> bool {
        matches!(self, Self::HardPressure)
    }
}

impl From<GovernorBackpressureSignal> for ClusterQueuePressure {
    fn from(value: GovernorBackpressureSignal) -> Self {
        match value {
            GovernorBackpressureSignal::None => Self::None,
            GovernorBackpressureSignal::SoftPressure => Self::SoftPressure,
            GovernorBackpressureSignal::HardPressure => Self::HardPressure,
        }
    }
}

/// Transport allocation class charged to `BudgetCategory::ClusterQueues`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterQueueAllocationKind {
    /// Serialized RPC or control frame held by transport.
    RpcFrame,
    /// Bytes queued in a per-peer send buffer.
    SendBuffer,
    /// Memory held by the transport duplicate-response window.
    DedupWindow,
    /// BULK transfer token or token-associated admission state.
    BulkTransferToken,
}

/// Priority class for cluster-queue governor admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterQueueAdmissionClass {
    /// Required correctness work such as drain, fence, receipt, and closure
    /// semantics. Still bounded by the governor hard budget cap.
    Critical,
    /// Ordinary foreground cluster work.
    Normal,
    /// Speculative transport work that can be conservatively refused under
    /// soft pressure.
    Speculative,
    /// BULK transfer admission token or transfer-window work.
    Bulk,
}

impl ClusterQueueAdmissionClass {
    /// Return true when this work may still be admitted under hard pressure.
    #[must_use]
    pub const fn is_critical(self) -> bool {
        matches!(self, Self::Critical)
    }

    /// Return true when this work may be admitted at the sampled pressure.
    #[must_use]
    pub const fn admits_under_pressure(self, pressure: ClusterQueuePressure) -> bool {
        match pressure {
            ClusterQueuePressure::None => true,
            ClusterQueuePressure::SoftPressure => !matches!(self, Self::Speculative | Self::Bulk),
            ClusterQueuePressure::HardPressure => self.is_critical(),
        }
    }
}

/// Observable transport pressure reason attached to admission evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendPressureReason {
    /// The unified governor constrained `BudgetCategory::ClusterQueues`.
    ClusterQueues {
        /// Pressure sampled from the governor.
        pressure: ClusterQueuePressure,
        /// Allocation kind being admitted or refused.
        kind: ClusterQueueAllocationKind,
        /// Admission class supplied by the caller.
        admission_class: ClusterQueueAdmissionClass,
        /// Cluster-queue bytes used at the decision point.
        used: usize,
        /// Cluster-queue hard cap at the decision point.
        limit: usize,
    },
}

impl SendPressureReason {
    /// Build a cluster-queue pressure reason from governor state.
    #[must_use]
    pub fn cluster_queues(
        governor: &Governor,
        pressure: ClusterQueuePressure,
        kind: ClusterQueueAllocationKind,
        admission_class: ClusterQueueAdmissionClass,
    ) -> Self {
        Self::ClusterQueues {
            pressure,
            kind,
            admission_class,
            used: saturating_usize(governor.category_used(BudgetCategory::ClusterQueues)),
            limit: saturating_usize(governor.category_cap(BudgetCategory::ClusterQueues)),
        }
    }
}

/// RAII guard for bytes admitted against `BudgetCategory::ClusterQueues`.
///
/// Dropping the guard releases the governor budget, so completion,
/// cancellation, timeout, and peer drain paths only need to drop their owned
/// guard to return cluster-queue memory.
#[derive(Debug)]
pub struct ClusterQueueBudgetGuard {
    governor: Governor,
    ticket: Option<AdmissionTicket>,
    kind: ClusterQueueAllocationKind,
    admission_class: ClusterQueueAdmissionClass,
}

impl ClusterQueueBudgetGuard {
    fn new(
        governor: &Governor,
        ticket: AdmissionTicket,
        kind: ClusterQueueAllocationKind,
        admission_class: ClusterQueueAdmissionClass,
    ) -> Self {
        debug_assert_eq!(ticket.category, BudgetCategory::ClusterQueues);
        Self {
            governor: governor.clone(),
            ticket: Some(ticket),
            kind,
            admission_class,
        }
    }

    /// Return the allocation kind charged by this guard.
    #[must_use]
    pub const fn kind(&self) -> ClusterQueueAllocationKind {
        self.kind
    }

    /// Return the admission class used to acquire this guard.
    #[must_use]
    pub const fn admission_class(&self) -> ClusterQueueAdmissionClass {
        self.admission_class
    }

    /// Return the number of admitted bytes still held by this guard.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.ticket.as_ref().map_or(0, |ticket| ticket.size)
    }

    /// Release the governor budget before dropping the guard.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if let Some(ticket) = self.ticket.take() {
            self.governor.release(ticket.category, ticket.size);
        }
    }
}

impl Drop for ClusterQueueBudgetGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
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
    /// Observable pressure/refusal reason, when admission was affected by a
    /// cross-transport resource authority.
    pub pressure_reason: Option<SendPressureReason>,
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
            pressure_reason: None,
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

    #[must_use]
    pub fn with_pressure_reason(mut self, reason: SendPressureReason) -> Self {
        self.pressure_reason = Some(reason);
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

/// Admit a transport allocation against the governor `cluster_queues` budget.
///
/// Non-critical work is refused while hard pressure is already active.
/// Speculative and BULK work are also refused under soft pressure so callers
/// can shrink speculative windows before consuming more cluster memory.
#[must_use]
pub fn admit_cluster_queue_budget(
    governor: &Governor,
    bytes: u64,
    kind: ClusterQueueAllocationKind,
    admission_class: ClusterQueueAdmissionClass,
) -> SendAdmission<ClusterQueueBudgetGuard> {
    let pressure = ClusterQueuePressure::from(governor.backpressure(BudgetCategory::ClusterQueues));
    if !admission_class.admits_under_pressure(pressure) {
        let reason = SendPressureReason::cluster_queues(governor, pressure, kind, admission_class);
        let evidence = cluster_queue_evidence(
            SendAdmissionOutcome::Backpressured,
            governor,
            bytes,
            Some(reason),
        )
        .with_policy(SendAdmissionPolicy::GovernorBudget)
        .with_wake(SendWakeEvidence::Unavailable);
        return SendAdmission::without_value(evidence);
    }

    match governor.admit(BudgetCategory::ClusterQueues, bytes) {
        Ok(ticket) => {
            let pressure =
                ClusterQueuePressure::from(governor.backpressure(BudgetCategory::ClusterQueues));
            let reason = pressure.is_pressure().then(|| {
                SendPressureReason::cluster_queues(governor, pressure, kind, admission_class)
            });
            let evidence =
                cluster_queue_evidence(SendAdmissionOutcome::Accepted, governor, bytes, reason)
                    .with_policy(SendAdmissionPolicy::GovernorBudget);
            SendAdmission::with_value(
                evidence,
                ClusterQueueBudgetGuard::new(governor, ticket, kind, admission_class),
            )
        }
        Err(err) => {
            let pressure =
                ClusterQueuePressure::from(governor.backpressure(BudgetCategory::ClusterQueues));
            let reason = Some(SendPressureReason::cluster_queues(
                governor,
                pressure,
                kind,
                admission_class,
            ));
            let evidence = cluster_queue_budget_error_evidence(err, governor, bytes, reason)
                .with_policy(SendAdmissionPolicy::GovernorBudget)
                .with_wake(SendWakeEvidence::Unavailable);
            SendAdmission::without_value(evidence)
        }
    }
}

fn cluster_queue_budget_error_evidence(
    err: BudgetError,
    governor: &Governor,
    requested: u64,
    reason: Option<SendPressureReason>,
) -> SendAdmissionEvidence {
    let available = match err {
        BudgetError::OverBudget { available, .. }
        | BudgetError::GlobalOverBudget { available, .. } => Some(saturating_usize(available)),
        BudgetError::UnknownCategory => None,
    };
    let mut evidence = SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
        .with_capacity(SendCapacityEvidence::new(
            SendCapacityClass::GovernorClusterQueues,
            saturating_usize(governor.category_used(BudgetCategory::ClusterQueues)),
            Some(saturating_usize(requested)),
            Some(saturating_usize(
                governor.category_cap(BudgetCategory::ClusterQueues),
            )),
        ));
    if let Some(reason) = reason {
        evidence = evidence.with_pressure_reason(reason);
    }
    if let Some(available) = available {
        evidence.byte_depth = Some(available);
    }
    evidence
}

fn cluster_queue_evidence(
    outcome: SendAdmissionOutcome,
    governor: &Governor,
    requested: u64,
    reason: Option<SendPressureReason>,
) -> SendAdmissionEvidence {
    let mut evidence =
        SendAdmissionEvidence::new(outcome).with_capacity(SendCapacityEvidence::new(
            SendCapacityClass::GovernorClusterQueues,
            saturating_usize(governor.category_used(BudgetCategory::ClusterQueues)),
            Some(saturating_usize(requested)),
            Some(saturating_usize(
                governor.category_cap(BudgetCategory::ClusterQueues),
            )),
        ));
    if let Some(reason) = reason {
        evidence = evidence.with_pressure_reason(reason);
    }
    evidence
}

fn saturating_usize(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_cache_core::GovernorConfig;

    fn cluster_only_governor() -> Governor {
        Governor::new(GovernorConfig {
            total_budget_bytes: 1_000,
            data_cache_fraction: 0.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 1.0,
            misc_fraction: 0.0,
            auto_tune: false,
        })
        .unwrap()
    }

    #[test]
    fn cluster_queue_guard_releases_budget_on_drop() {
        let governor = cluster_only_governor();

        let admission = admit_cluster_queue_budget(
            &governor,
            128,
            ClusterQueueAllocationKind::DedupWindow,
            ClusterQueueAdmissionClass::Normal,
        );

        assert!(admission.admitted());
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 128);
        drop(admission.value);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 0);
    }

    #[test]
    fn soft_pressure_refuses_bulk_and_reports_reason() {
        let governor = cluster_only_governor();
        let _held = governor
            .admit(BudgetCategory::ClusterQueues, 701)
            .expect("seed soft pressure");

        let admission = admit_cluster_queue_budget(
            &governor,
            1,
            ClusterQueueAllocationKind::BulkTransferToken,
            ClusterQueueAdmissionClass::Bulk,
        );

        assert!(!admission.admitted());
        assert_eq!(
            admission.evidence.outcome,
            SendAdmissionOutcome::Backpressured
        );
        assert_eq!(
            admission.evidence.policy,
            Some(SendAdmissionPolicy::GovernorBudget)
        );
        assert!(matches!(
            admission.evidence.pressure_reason,
            Some(SendPressureReason::ClusterQueues {
                pressure: ClusterQueuePressure::SoftPressure,
                kind: ClusterQueueAllocationKind::BulkTransferToken,
                admission_class: ClusterQueueAdmissionClass::Bulk,
                ..
            })
        ));
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 701);
    }

    #[test]
    fn hard_pressure_refuses_non_critical_but_preserves_critical_admission() {
        let governor = cluster_only_governor();
        let _held = governor
            .admit(BudgetCategory::ClusterQueues, 950)
            .expect("seed hard pressure");

        let refused = admit_cluster_queue_budget(
            &governor,
            1,
            ClusterQueueAllocationKind::RpcFrame,
            ClusterQueueAdmissionClass::Normal,
        );
        assert!(!refused.admitted());
        assert!(matches!(
            refused.evidence.pressure_reason,
            Some(SendPressureReason::ClusterQueues {
                pressure: ClusterQueuePressure::HardPressure,
                admission_class: ClusterQueueAdmissionClass::Normal,
                ..
            })
        ));
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 950);

        let critical = admit_cluster_queue_budget(
            &governor,
            1,
            ClusterQueueAllocationKind::RpcFrame,
            ClusterQueueAdmissionClass::Critical,
        );
        assert!(critical.admitted());
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 951);
        drop(critical.value);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 950);
    }
}
