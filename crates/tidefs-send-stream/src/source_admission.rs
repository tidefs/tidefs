// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Source-side VFSSEND2 shipment admission, retry, and operator-visible state.

use std::collections::BTreeMap;

use crate::{Id128, SendCursor};

/// Stable source-side key for one outbound snapshot shipment attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ShipmentKey {
    pub source_pool_id: Id128,
    pub source_dataset_id: Id128,
    pub peer_node_id: u64,
    pub target_snapshot_id: Id128,
    pub stream_id: Id128,
}

impl ShipmentKey {
    #[must_use]
    pub const fn new(
        source_pool_id: Id128,
        source_dataset_id: Id128,
        peer_node_id: u64,
        target_snapshot_id: Id128,
        stream_id: Id128,
    ) -> Self {
        Self {
            source_pool_id,
            source_dataset_id,
            peer_node_id,
            target_snapshot_id,
            stream_id,
        }
    }
}

/// Shipment mode selected by the source admission controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShipmentMode {
    Resume { cursor: SendCursor },
    Incremental { base_snapshot_id: Id128 },
    Full,
}

impl ShipmentMode {
    #[must_use]
    pub const fn priority_rank(self) -> u8 {
        match self {
            Self::Resume { .. } => 0,
            Self::Incremental { .. } => 1,
            Self::Full => 2,
        }
    }
}

/// Whether the source snapshot is safe to ship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSnapshotState {
    Committed,
    PendingBarrier,
    Uncommitted,
    PartialReceive,
}

/// Receiver base-root evidence for incremental sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverBaseRootStatus {
    NotRequired,
    Verified,
    Missing,
    Unknown,
}

/// Resume checkpoint evidence supplied by the receiver or persisted locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResumeCheckpointStatus {
    NotRequired,
    Valid,
    Invalid,
    Unknown,
}

/// Evidence from adjacent source layers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceStatus {
    /// The adjacent evidence surface is not implemented or not wired yet.
    NotProvided,
    /// The adjacent evidence surface exists, but cannot currently answer.
    Unknown,
    Allows,
    Refuses,
}

impl Default for EvidenceStatus {
    fn default() -> Self {
        Self::NotProvided
    }
}

/// Shipment scope for adjacent source-admission evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShipmentAdmissionScope {
    /// Production or distributed VFSSEND2 send; all adjacent evidence is mandatory.
    DistributedRuntime,
    /// Local/offline model path that deliberately does not claim distributed admission.
    LocalOfflineModel,
}

impl Default for ShipmentAdmissionScope {
    fn default() -> Self {
        Self::DistributedRuntime
    }
}

/// Transport-path evidence consumed when #846-style path state is available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportPathEvidence {
    pub peer_available: EvidenceStatus,
    pub transfer_bulk_ready: EvidenceStatus,
}

/// All source-side evidence considered for one admission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceAdmissionEvidence {
    pub scope: ShipmentAdmissionScope,
    pub required_work_clear: bool,
    pub transport_path: TransportPathEvidence,
    pub storage_intent_allows_bulk: EvidenceStatus,
    pub governor_allows_bulk: EvidenceStatus,
}

impl Default for SourceAdmissionEvidence {
    fn default() -> Self {
        Self {
            scope: ShipmentAdmissionScope::DistributedRuntime,
            required_work_clear: true,
            transport_path: TransportPathEvidence::default(),
            storage_intent_allows_bulk: EvidenceStatus::NotProvided,
            governor_allows_bulk: EvidenceStatus::NotProvided,
        }
    }
}

impl SourceAdmissionEvidence {
    /// Explicit model-only evidence for local/offline send paths.
    ///
    /// This preserves the early local snapshot-send model without making
    /// missing distributed transport, storage-intent, or governor evidence look
    /// like production admission.
    #[must_use]
    pub fn local_offline_model() -> Self {
        Self {
            scope: ShipmentAdmissionScope::LocalOfflineModel,
            ..Self::default()
        }
    }

    /// Positive adjacent evidence required before distributed runtime admission.
    #[must_use]
    pub fn distributed_runtime_allows() -> Self {
        Self {
            scope: ShipmentAdmissionScope::DistributedRuntime,
            transport_path: TransportPathEvidence {
                peer_available: EvidenceStatus::Allows,
                transfer_bulk_ready: EvidenceStatus::Allows,
            },
            storage_intent_allows_bulk: EvidenceStatus::Allows,
            governor_allows_bulk: EvidenceStatus::Allows,
            ..Self::default()
        }
    }
}

/// Candidate state tracked before admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShipmentCandidate {
    pub key: ShipmentKey,
    pub mode: ShipmentMode,
    pub source_state: SourceSnapshotState,
    pub receiver_base_root: ReceiverBaseRootStatus,
    pub resume_checkpoint: ResumeCheckpointStatus,
    pub operator_reseed_allowed: bool,
}

impl ShipmentCandidate {
    #[must_use]
    pub const fn full(key: ShipmentKey) -> Self {
        Self {
            key,
            mode: ShipmentMode::Full,
            source_state: SourceSnapshotState::Committed,
            receiver_base_root: ReceiverBaseRootStatus::NotRequired,
            resume_checkpoint: ResumeCheckpointStatus::NotRequired,
            operator_reseed_allowed: false,
        }
    }

    #[must_use]
    pub const fn incremental(
        key: ShipmentKey,
        base_snapshot_id: Id128,
        receiver_base_root: ReceiverBaseRootStatus,
    ) -> Self {
        Self {
            key,
            mode: ShipmentMode::Incremental { base_snapshot_id },
            source_state: SourceSnapshotState::Committed,
            receiver_base_root,
            resume_checkpoint: ResumeCheckpointStatus::NotRequired,
            operator_reseed_allowed: false,
        }
    }

    #[must_use]
    pub const fn resume(key: ShipmentKey, cursor: SendCursor) -> Self {
        Self {
            key,
            mode: ShipmentMode::Resume { cursor },
            source_state: SourceSnapshotState::Committed,
            receiver_base_root: ReceiverBaseRootStatus::NotRequired,
            resume_checkpoint: ResumeCheckpointStatus::Valid,
            operator_reseed_allowed: false,
        }
    }

    #[must_use]
    pub const fn with_source_state(mut self, source_state: SourceSnapshotState) -> Self {
        self.source_state = source_state;
        self
    }

    #[must_use]
    pub const fn with_operator_reseed_allowed(mut self, allowed: bool) -> Self {
        self.operator_reseed_allowed = allowed;
        self
    }
}

/// Static hard limits from distributed snapshot shipping section 7.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceAdmissionLimits {
    pub dataset_outbound: usize,
    pub pool_outbound: usize,
    pub peer_pair_outbound: usize,
    pub node_total: usize,
}

impl Default for SourceAdmissionLimits {
    fn default() -> Self {
        Self {
            dataset_outbound: 1,
            pool_outbound: 2,
            peer_pair_outbound: 1,
            node_total: 4,
        }
    }
}

/// Scope that exhausted admission capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionLimitScope {
    Dataset,
    Pool,
    PeerPair,
    Node,
}

/// Operator-visible defer/refusal reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendDeferReason {
    PendingSourceSnapshot(SourceSnapshotState),
    RequiredWorkPressure,
    TransportFailure,
    PeerUnavailable,
    TransportPathUnknown,
    TransferBulkBackpressured,
    StorageIntentUnavailable,
    StorageIntentRefused,
    GovernorUnavailable,
    GovernorBackpressure,
    ReceiverRejected,
    MissingIncrementalBase,
    InvalidResumeCheckpoint,
    RetryBackoffActive { retry_after_ms: u64 },
    AdmissionLimitPressure { scope: AdmissionLimitScope },
}

/// Failure class recorded for retry/backoff state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendFailureClass {
    TransportFailure,
    PeerUnavailable,
    ReceiverRejected,
    MissingIncrementalBase,
    InvalidResumeCheckpoint,
    AdmissionLimitPressure,
}

impl SendFailureClass {
    #[must_use]
    pub fn operator_reason(self) -> SendDeferReason {
        match self {
            Self::TransportFailure => SendDeferReason::TransportFailure,
            Self::PeerUnavailable => SendDeferReason::PeerUnavailable,
            Self::ReceiverRejected => SendDeferReason::ReceiverRejected,
            Self::MissingIncrementalBase => SendDeferReason::MissingIncrementalBase,
            Self::InvalidResumeCheckpoint => SendDeferReason::InvalidResumeCheckpoint,
            Self::AdmissionLimitPressure => SendDeferReason::AdmissionLimitPressure {
                scope: AdmissionLimitScope::Node,
            },
        }
    }
}

/// Exponential retry/backoff policy with deterministic per-stream jitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBackoffPolicy {
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter_ms: u64,
}

impl Default for RetryBackoffPolicy {
    fn default() -> Self {
        Self {
            base_delay_ms: 1_000,
            max_delay_ms: 60_000,
            jitter_ms: 250,
        }
    }
}

impl RetryBackoffPolicy {
    #[must_use]
    pub fn delay_for(self, key: ShipmentKey, attempts: u32) -> u64 {
        let exponent = attempts.saturating_sub(1).min(16);
        let base = self
            .base_delay_ms
            .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX));
        let capped = base.min(self.max_delay_ms);
        capped.saturating_add(jitter_for_key(key, attempts, self.jitter_ms))
    }
}

/// Retry state retained after a failed shipment attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRetryState {
    pub attempts: u32,
    pub last_failure: SendFailureClass,
    pub operator_reason: SendDeferReason,
    pub next_retry_after_ms: u64,
}

/// Active shipment admitted by the source controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActiveShipment {
    pub key: ShipmentKey,
    pub mode: ShipmentMode,
    pub admitted_at_ms: u64,
}

/// Admission token returned for an accepted shipment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionToken {
    pub shipment: ActiveShipment,
}

/// Admission result for one candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendAdmissionDecision {
    Admitted(AdmissionToken),
    Deferred(SendDeferReason),
}

/// Source-side admission controller for outbound VFSSEND2 sessions.
#[derive(Clone, Debug)]
pub struct SourceAdmissionController {
    limits: SourceAdmissionLimits,
    backoff: RetryBackoffPolicy,
    active: BTreeMap<ShipmentKey, ActiveShipment>,
    retries: BTreeMap<ShipmentKey, SendRetryState>,
}

impl SourceAdmissionController {
    #[must_use]
    pub fn new(limits: SourceAdmissionLimits) -> Self {
        Self {
            limits,
            backoff: RetryBackoffPolicy::default(),
            active: BTreeMap::new(),
            retries: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_backoff(mut self, backoff: RetryBackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    #[must_use]
    pub const fn limits(&self) -> SourceAdmissionLimits {
        self.limits
    }

    #[must_use]
    pub fn active_shipments(&self) -> &BTreeMap<ShipmentKey, ActiveShipment> {
        &self.active
    }

    #[must_use]
    pub fn retry_state(&self, key: ShipmentKey) -> Option<&SendRetryState> {
        self.retries.get(&key)
    }

    pub fn admit(
        &mut self,
        candidate: ShipmentCandidate,
        evidence: SourceAdmissionEvidence,
        now_ms: u64,
    ) -> SendAdmissionDecision {
        if let Some(reason) = self.source_state_reason(candidate.source_state) {
            return SendAdmissionDecision::Deferred(reason);
        }
        if !evidence.required_work_clear {
            return SendAdmissionDecision::Deferred(SendDeferReason::RequiredWorkPressure);
        }
        if let Some(retry) = self.retries.get(&candidate.key) {
            if now_ms < retry.next_retry_after_ms {
                return SendAdmissionDecision::Deferred(SendDeferReason::RetryBackoffActive {
                    retry_after_ms: retry.next_retry_after_ms.saturating_sub(now_ms),
                });
            }
        }
        if let Some(reason) = transport_reason(evidence.scope, evidence.transport_path) {
            return SendAdmissionDecision::Deferred(reason);
        }
        if let Some(reason) = policy_reason(
            evidence.scope,
            evidence.storage_intent_allows_bulk,
            SendDeferReason::StorageIntentUnavailable,
            SendDeferReason::StorageIntentRefused,
        ) {
            return SendAdmissionDecision::Deferred(reason);
        }
        if let Some(reason) = policy_reason(
            evidence.scope,
            evidence.governor_allows_bulk,
            SendDeferReason::GovernorUnavailable,
            SendDeferReason::GovernorBackpressure,
        ) {
            return SendAdmissionDecision::Deferred(reason);
        }
        if let Some(reason) = self.mode_reason(candidate) {
            return SendAdmissionDecision::Deferred(reason);
        }
        if let Some(scope) = self.limit_pressure(candidate.key) {
            return SendAdmissionDecision::Deferred(SendDeferReason::AdmissionLimitPressure {
                scope,
            });
        }

        let shipment = ActiveShipment {
            key: candidate.key,
            mode: candidate.mode,
            admitted_at_ms: now_ms,
        };
        self.active.insert(candidate.key, shipment);
        SendAdmissionDecision::Admitted(AdmissionToken { shipment })
    }

    pub fn complete(&mut self, key: ShipmentKey) -> Option<ActiveShipment> {
        self.active.remove(&key)
    }

    pub fn record_failure(
        &mut self,
        key: ShipmentKey,
        failure: SendFailureClass,
        now_ms: u64,
    ) -> &SendRetryState {
        let attempts = self
            .retries
            .get(&key)
            .map(|state| state.attempts.saturating_add(1))
            .unwrap_or(1);
        let delay = self.backoff.delay_for(key, attempts);
        self.active.remove(&key);
        self.retries.insert(
            key,
            SendRetryState {
                attempts,
                last_failure: failure,
                operator_reason: failure.operator_reason(),
                next_retry_after_ms: now_ms.saturating_add(delay),
            },
        );
        self.retries.get(&key).expect("retry state was inserted")
    }

    pub fn clear_retry(&mut self, key: ShipmentKey) -> Option<SendRetryState> {
        self.retries.remove(&key)
    }

    fn source_state_reason(&self, state: SourceSnapshotState) -> Option<SendDeferReason> {
        match state {
            SourceSnapshotState::Committed => None,
            other => Some(SendDeferReason::PendingSourceSnapshot(other)),
        }
    }

    fn mode_reason(&self, candidate: ShipmentCandidate) -> Option<SendDeferReason> {
        match candidate.mode {
            ShipmentMode::Resume { .. } => match candidate.resume_checkpoint {
                ResumeCheckpointStatus::Valid => None,
                ResumeCheckpointStatus::Invalid => Some(SendDeferReason::InvalidResumeCheckpoint),
                ResumeCheckpointStatus::Unknown => Some(SendDeferReason::InvalidResumeCheckpoint),
                ResumeCheckpointStatus::NotRequired => {
                    Some(SendDeferReason::InvalidResumeCheckpoint)
                }
            },
            ShipmentMode::Incremental { .. } => match candidate.receiver_base_root {
                ReceiverBaseRootStatus::Verified => None,
                ReceiverBaseRootStatus::Missing | ReceiverBaseRootStatus::Unknown => {
                    Some(SendDeferReason::MissingIncrementalBase)
                }
                ReceiverBaseRootStatus::NotRequired => {
                    Some(SendDeferReason::MissingIncrementalBase)
                }
            },
            ShipmentMode::Full => None,
        }
    }

    fn limit_pressure(&self, key: ShipmentKey) -> Option<AdmissionLimitScope> {
        if self
            .active
            .values()
            .filter(|shipment| shipment.key.source_dataset_id == key.source_dataset_id)
            .count()
            >= self.limits.dataset_outbound
        {
            return Some(AdmissionLimitScope::Dataset);
        }
        if self
            .active
            .values()
            .filter(|shipment| shipment.key.source_pool_id == key.source_pool_id)
            .count()
            >= self.limits.pool_outbound
        {
            return Some(AdmissionLimitScope::Pool);
        }
        if self
            .active
            .values()
            .filter(|shipment| {
                shipment.key.source_pool_id == key.source_pool_id
                    && shipment.key.peer_node_id == key.peer_node_id
            })
            .count()
            >= self.limits.peer_pair_outbound
        {
            return Some(AdmissionLimitScope::PeerPair);
        }
        if self.active.len() >= self.limits.node_total {
            return Some(AdmissionLimitScope::Node);
        }
        None
    }
}

impl Default for SourceAdmissionController {
    fn default() -> Self {
        Self::new(SourceAdmissionLimits::default())
    }
}

fn transport_reason(
    scope: ShipmentAdmissionScope,
    evidence: TransportPathEvidence,
) -> Option<SendDeferReason> {
    match evidence.peer_available {
        EvidenceStatus::Refuses => return Some(SendDeferReason::PeerUnavailable),
        EvidenceStatus::Unknown => return Some(SendDeferReason::TransportPathUnknown),
        EvidenceStatus::NotProvided if scope == ShipmentAdmissionScope::DistributedRuntime => {
            return Some(SendDeferReason::TransportPathUnknown);
        }
        EvidenceStatus::NotProvided | EvidenceStatus::Allows => {}
    }
    match evidence.transfer_bulk_ready {
        EvidenceStatus::Refuses => Some(SendDeferReason::TransferBulkBackpressured),
        EvidenceStatus::Unknown => Some(SendDeferReason::TransportPathUnknown),
        EvidenceStatus::NotProvided if scope == ShipmentAdmissionScope::DistributedRuntime => {
            Some(SendDeferReason::TransportPathUnknown)
        }
        EvidenceStatus::NotProvided | EvidenceStatus::Allows => None,
    }
}

fn policy_reason(
    scope: ShipmentAdmissionScope,
    status: EvidenceStatus,
    unknown: SendDeferReason,
    refused: SendDeferReason,
) -> Option<SendDeferReason> {
    match status {
        EvidenceStatus::Unknown => Some(unknown),
        EvidenceStatus::Refuses => Some(refused),
        EvidenceStatus::NotProvided if scope == ShipmentAdmissionScope::DistributedRuntime => {
            Some(unknown)
        }
        EvidenceStatus::NotProvided | EvidenceStatus::Allows => None,
    }
}

fn jitter_for_key(key: ShipmentKey, attempts: u32, jitter_ms: u64) -> u64 {
    if jitter_ms == 0 {
        return 0;
    }
    let mut acc = attempts as u64 ^ key.peer_node_id;
    for byte in key
        .source_pool_id
        .iter()
        .chain(key.source_dataset_id.iter())
        .chain(key.target_snapshot_id.iter())
        .chain(key.stream_id.iter())
    {
        acc = acc.rotate_left(5) ^ u64::from(*byte);
    }
    acc % jitter_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id128 {
        [byte; 16]
    }

    fn key(dataset: u8, peer: u64, target: u8) -> ShipmentKey {
        ShipmentKey::new(id(1), id(dataset), peer, id(target), id(target + 10))
    }

    #[test]
    fn incremental_requires_verified_receiver_base() {
        let mut controller = SourceAdmissionController::default();
        let candidate =
            ShipmentCandidate::incremental(key(2, 10, 3), id(9), ReceiverBaseRootStatus::Missing);

        assert_eq!(
            controller.admit(
                candidate,
                SourceAdmissionEvidence::distributed_runtime_allows(),
                0,
            ),
            SendAdmissionDecision::Deferred(SendDeferReason::MissingIncrementalBase)
        );
    }

    #[test]
    fn static_limits_refuse_second_dataset_peer_shipment() {
        let mut controller = SourceAdmissionController::default();
        let first = ShipmentCandidate::full(key(2, 10, 3));
        assert!(matches!(
            controller.admit(
                first,
                SourceAdmissionEvidence::distributed_runtime_allows(),
                0,
            ),
            SendAdmissionDecision::Admitted(_)
        ));

        let second = ShipmentCandidate::full(key(2, 10, 4));
        assert_eq!(
            controller.admit(
                second,
                SourceAdmissionEvidence::distributed_runtime_allows(),
                1,
            ),
            SendAdmissionDecision::Deferred(SendDeferReason::AdmissionLimitPressure {
                scope: AdmissionLimitScope::Dataset
            })
        );
    }

    #[test]
    fn resume_priority_wins_over_incremental_and_full() {
        let cursor = SendCursor::initial();
        assert!(
            ShipmentMode::Resume { cursor }.priority_rank()
                < ShipmentMode::Incremental {
                    base_snapshot_id: id(9)
                }
                .priority_rank()
        );
        assert!(
            ShipmentMode::Incremental {
                base_snapshot_id: id(9)
            }
            .priority_rank()
                < ShipmentMode::Full.priority_rank()
        );
    }

    #[test]
    fn retry_state_records_visible_backoff_reason() {
        let mut controller =
            SourceAdmissionController::default().with_backoff(RetryBackoffPolicy {
                base_delay_ms: 100,
                max_delay_ms: 1_000,
                jitter_ms: 0,
            });
        let key = key(2, 10, 3);

        let retry = controller.record_failure(key, SendFailureClass::PeerUnavailable, 500);
        assert_eq!(retry.attempts, 1);
        assert_eq!(retry.operator_reason, SendDeferReason::PeerUnavailable);
        assert_eq!(retry.next_retry_after_ms, 600);

        assert_eq!(
            controller.admit(
                ShipmentCandidate::full(key),
                SourceAdmissionEvidence::default(),
                550,
            ),
            SendAdmissionDecision::Deferred(SendDeferReason::RetryBackoffActive {
                retry_after_ms: 50
            })
        );
    }

    #[test]
    fn distributed_runtime_requires_transport_path_evidence() {
        let mut controller = SourceAdmissionController::default();

        assert_eq!(
            controller.admit(
                ShipmentCandidate::full(key(2, 10, 3)),
                SourceAdmissionEvidence::default(),
                0,
            ),
            SendAdmissionDecision::Deferred(SendDeferReason::TransportPathUnknown)
        );
    }

    #[test]
    fn distributed_runtime_requires_storage_intent_evidence() {
        let mut controller = SourceAdmissionController::default();
        let evidence = SourceAdmissionEvidence {
            storage_intent_allows_bulk: EvidenceStatus::NotProvided,
            ..SourceAdmissionEvidence::distributed_runtime_allows()
        };

        assert_eq!(
            controller.admit(ShipmentCandidate::full(key(2, 10, 3)), evidence, 0,),
            SendAdmissionDecision::Deferred(SendDeferReason::StorageIntentUnavailable)
        );
    }

    #[test]
    fn distributed_runtime_requires_governor_evidence() {
        let mut controller = SourceAdmissionController::default();
        let evidence = SourceAdmissionEvidence {
            governor_allows_bulk: EvidenceStatus::NotProvided,
            ..SourceAdmissionEvidence::distributed_runtime_allows()
        };

        assert_eq!(
            controller.admit(ShipmentCandidate::full(key(2, 10, 3)), evidence, 0,),
            SendAdmissionDecision::Deferred(SendDeferReason::GovernorUnavailable)
        );
    }

    #[test]
    fn local_offline_model_keeps_unwired_evidence_boundary_explicit() {
        let mut controller = SourceAdmissionController::default();

        assert!(matches!(
            controller.admit(
                ShipmentCandidate::full(key(2, 10, 3)),
                SourceAdmissionEvidence::local_offline_model(),
                0,
            ),
            SendAdmissionDecision::Admitted(_)
        ));
    }

    #[test]
    fn adjacent_refusal_evidence_is_consumed_when_present() {
        let mut controller = SourceAdmissionController::default();
        let evidence = SourceAdmissionEvidence {
            transport_path: TransportPathEvidence {
                peer_available: EvidenceStatus::Refuses,
                transfer_bulk_ready: EvidenceStatus::NotProvided,
            },
            ..SourceAdmissionEvidence::default()
        };

        assert_eq!(
            controller.admit(ShipmentCandidate::full(key(2, 10, 3)), evidence, 0,),
            SendAdmissionDecision::Deferred(SendDeferReason::PeerUnavailable)
        );
    }
}
