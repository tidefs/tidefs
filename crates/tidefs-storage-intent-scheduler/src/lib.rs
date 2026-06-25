// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Storage-intent demand-side admission and scheduling.
//!
//! This crate is the first #862 source slice. It consumes compiled
//! storage-intent policy from #855 and storage-intent records from #841,
//! maps work into the unified LaneClass lane model from
//! `docs/design/unified-scheduling-classes-lane-priority-model.md`, and
//! enforces intent-aware admission, QoS budget caps, backpressure,
//! speculative-drop behaviour, and read-only scheduling evidence.
//!
//! It does not implement placement planning, ack receipt emission, media/cost
//! ledgers, relocation execution, operator rendering, or performance gate
//! definitions. FUSE, block, and transport admission adapters are wired by
//! their owning issues, not by this crate.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use tidefs_storage_intent_core::{
    EvidenceFamilyFreshnessState, PrefetchResidencyActionMask, PrefetchResidencyCandidateClass,
    PrefetchResidencyPolicyEnvelope, PrefetchResidencyPolicyFlags, PrefetchResidencyPolicyScope,
    StorageIntentActionClass, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef, StorageIntentGuaranteeClass,
    StorageIntentPolicyId, StorageIntentPolicyRevision, StorageIntentRefusalReason,
};
use tidefs_types_transport_session::{LaneClass, LaneConfig};

// ---------------------------------------------------------------------------
// Spec anchor
// ---------------------------------------------------------------------------

/// Canonical identifier for this scheduler/admission surface.
pub const STORAGE_INTENT_SCHEDULER_SPEC: &str = "tidefs-storage-intent-scheduler-v1-issue-862";

/// Maximum evidence refs carried directly on one admission request.
pub const MAX_ADMISSION_EVIDENCE_REFS: usize = 8;

/// Maximum distinct evidence families tracked for one admission decision.
///
/// Compiled prefetch/residency policies can require more evidence families
/// than request-local evidence refs carry, because the active policy envelope
/// also supplies refs. Keep this large enough for the policy flag surface plus
/// request-local requirements, and fail closed if a caller still overflows it.
pub const MAX_REQUIRED_EVIDENCE_KINDS: usize = 24;

// ---------------------------------------------------------------------------
// Lane mapping: storage-intent action → LaneClass
// ---------------------------------------------------------------------------

/// Maps a storage-intent action class to its canonical scheduling lane.
///
/// The mapping follows the priority order defined in
/// `docs/design/unified-scheduling-classes-lane-priority-model.md`.
/// CONTROL > METADATA > DEMAND > SPECULATIVE > BACKGROUND.
///
/// Unknown or unmapped action classes map to the most conservative lane
/// (Background) and carry `EvidenceNotUsable` refusal state so callers
/// cannot silently promote unknown work.
#[must_use]
pub const fn action_class_to_lane(action: StorageIntentActionClass) -> LaneClass {
    match action {
        // Metadata storms, fsyncdir-heavy work, directory operations
        // map to Metadata (priority=1).
        StorageIntentActionClass::ReadTriggeredRepair
        | StorageIntentActionClass::DegradedReadReconstruction => LaneClass::Metadata,

        // Ordinary foreground reads/writes, sync barriers, and
        // authority-demand placement movement map to Demand (priority=2).
        StorageIntentActionClass::NewWriteShaping
        | StorageIntentActionClass::AuthorityPromotion
        | StorageIntentActionClass::DurablePlacementMovement
        | StorageIntentActionClass::ReadSourceRefresh => LaneClass::Demand,

        // Speculative prefetch, cache-only hot-read serving trials,
        // and flash-serving promotion map to Speculative (priority=3).
        StorageIntentActionClass::QueuePrefetchTuning
        | StorageIntentActionClass::CacheOnlyServingTrial
        | StorageIntentActionClass::FlashServingPromotion => LaneClass::Speculative,

        // Defrag, reclaim relocation, geo catch-up, and archive migration
        // map to Background (priority=4).
        StorageIntentActionClass::DefragRepack
        | StorageIntentActionClass::ReclaimRelocation
        | StorageIntentActionClass::GeoCatchup
        | StorageIntentActionClass::ArchiveMigration => LaneClass::Background,
    }
}

/// Returns true when an action class can be preempted and dropped.
#[must_use]
pub const fn action_class_can_be_dropped(action: StorageIntentActionClass) -> bool {
    matches!(
        action,
        StorageIntentActionClass::QueuePrefetchTuning
            | StorageIntentActionClass::CacheOnlyServingTrial
            | StorageIntentActionClass::FlashServingPromotion
            | StorageIntentActionClass::DefragRepack
            | StorageIntentActionClass::ReclaimRelocation
            | StorageIntentActionClass::GeoCatchup
            | StorageIntentActionClass::ArchiveMigration
    )
}

/// Returns true when an action class is recovery/repair work that may
/// escalate under durability pressure.
#[must_use]
pub const fn action_class_is_repair_escalation(action: StorageIntentActionClass) -> bool {
    matches!(
        action,
        StorageIntentActionClass::ReadTriggeredRepair
            | StorageIntentActionClass::DegradedReadReconstruction
    )
}

/// Return the stricter lane when two classifiers disagree.
///
/// `LaneClass` uses lower discriminants for higher priority. Resolving to the
/// stricter lane lets an externally classified authority or durability action
/// prevent a broad work-class label from accidentally demoting it to a
/// droppable lane.
#[must_use]
pub const fn stricter_lane(left: LaneClass, right: LaneClass) -> LaneClass {
    if lane_priority(left) <= lane_priority(right) {
        left
    } else {
        right
    }
}

/// Resolve the effective dispatch lane from both scheduler work class and
/// storage-intent action class.
#[must_use]
pub const fn resolve_admission_lane(
    work_class: AdmissionWorkClass,
    action_class: StorageIntentActionClass,
) -> LaneClass {
    stricter_lane(work_class.lane_class(), action_class_to_lane(action_class))
}

const fn lane_priority(lane: LaneClass) -> u8 {
    match lane {
        LaneClass::Control => 0,
        LaneClass::Metadata => 1,
        LaneClass::Demand => 2,
        LaneClass::Speculative => 3,
        LaneClass::Background => 4,
    }
}

const LANE_CLASSES_BY_PRIORITY: [LaneClass; LaneClass::COUNT] = [
    LaneClass::Control,
    LaneClass::Metadata,
    LaneClass::Demand,
    LaneClass::Speculative,
    LaneClass::Background,
];

// ---------------------------------------------------------------------------
// Budget cap types — hard enforcement dimensions
// ---------------------------------------------------------------------------

/// Budget dimensions that the scheduler enforces as hard caps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageIntentBudgetCaps {
    /// Hard cap on dirty (unflushed) bytes for write-combining buffers.
    /// When exceeded, all write-shaping actions are backpressured.
    pub max_dirty_bytes: u64,

    /// Current dirty bytes in-flight.
    pub dirty_bytes: u64,

    /// Hard cap on inflight bytes across all lanes.
    /// When exceeded, admission backpressures lowest-priority lanes first.
    pub max_inflight_bytes: u64,

    /// Current inflight bytes across all lanes.
    pub inflight_bytes: u64,

    /// Hard cap on transport window bytes per edge/session.
    /// When exceeded, transport sends are backpressured.
    pub max_transport_window_bytes: u64,

    /// Current transport window bytes in use across all sessions.
    /// When exceeded, demand-class transport sends are backpressured
    /// and speculative/background work is dropped first.
    pub transport_window_bytes: u64,

    /// Hard cap on device queue depth (outstanding I/O ops).
    pub max_device_queue_depth: u64,

    /// Current device queue depth.
    pub device_queue_depth: u64,

    /// Allocator free-space pressure: 0=none, 100=full.
    /// Scheduler refuses relocation/defrag work above 90.
    pub allocator_pressure_pct: u8,

    /// Foreground latency budget in microseconds.
    /// Scheduler throttles Demand, Speculative, and Background lanes
    /// when inflight pressure (>70% of cap) indicates the budget
    /// is at risk. Control and Metadata are exempt.
    pub foreground_latency_budget_us: u64,

    /// Background optimizer budget bytes remaining in this window.
    /// Background work is refused when this reaches zero.
    pub background_optimizer_budget_bytes: u64,
}

impl StorageIntentBudgetCaps {
    /// Returns true when any hard cap is exceeded.
    #[must_use]
    pub fn any_cap_exceeded(&self) -> bool {
        self.dirty_bytes > self.max_dirty_bytes
            || self.inflight_bytes > self.max_inflight_bytes
            || (self.max_transport_window_bytes > 0
                && self.transport_window_bytes > self.max_transport_window_bytes)
            || self.device_queue_depth > self.max_device_queue_depth
            || self.allocator_pressure_pct > 90
            || self.background_optimizer_budget_bytes == 0
    }

    /// Returns the primary backpressure reason, or None.
    #[must_use]
    pub fn backpressure_reason(&self) -> Option<StorageIntentRefusalReason> {
        if self.dirty_bytes > self.max_dirty_bytes
            || self.inflight_bytes > self.max_inflight_bytes
            || (self.max_transport_window_bytes > 0
                && self.transport_window_bytes > self.max_transport_window_bytes)
        {
            Some(StorageIntentRefusalReason::GuaranteeFloorNotMet)
        } else if self.device_queue_depth > self.max_device_queue_depth
            || self.allocator_pressure_pct > 90
        {
            Some(StorageIntentRefusalReason::EvidenceNotUsable)
        } else if self.background_optimizer_budget_bytes == 0 {
            Some(StorageIntentRefusalReason::MovementDebtNotPaidBack)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Tenant/workload isolation hook
// ---------------------------------------------------------------------------

/// Budget-owner identity for tenant/workload isolation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct StorageIntentBudgetOwnerId(pub [u8; 16]);

impl StorageIntentBudgetOwnerId {
    /// All-zero sentinel for "no budget owner" (global/shared).
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut i = 0;
        while i < self.0.len() {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// Per-budget-owner isolation state so one workload cannot starve another.
#[derive(Clone, Debug, Default)]
pub struct BudgetOwnerIsolationState {
    /// Per-lane inflight bytes owned by this budget owner.
    pub per_lane_inflight: BTreeMap<LaneClass, u64>,

    /// Soft dirty-byte bound for this owner.
    pub max_dirty_bytes: u64,

    /// Current dirty bytes for this owner.
    pub dirty_bytes: u64,

    /// Whether this owner is exceeding its fair share and should be throttled.
    pub throttle: bool,

    /// Reason for throttle.
    pub throttle_reason: StorageIntentRefusalReason,
}

// ---------------------------------------------------------------------------
// Admission request
// ---------------------------------------------------------------------------

/// Classification of the work being admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionWorkClass {
    /// POSIX sync barrier or block FUA/flush request.
    SyncBarrier,
    /// Ordinary foreground read or write.
    ForegroundIo,
    /// Read-serving refresh or degraded-read reconstruction.
    ReadServing,
    /// Metadata-heavy operation (readdir, fsyncdir, bulk unlink).
    MetadataStorm,
    /// VM/random I/O with tail-latency budget.
    VmRandomIo,
    /// Bulk streaming ingest.
    BulkIngest,
    /// Speculative prefetch.
    SpeculativePrefetch,
    /// Cache-only hot-read serving trial.
    CacheOnlyTrial,
    /// Authority promotion work admitted by #848.
    AuthorityPromotion,
    /// Durable relocation/defrag/rebake/rebuild/geo catch-up background.
    BackgroundOptimizer,
    /// Repair/evacuation escalated by durability risk.
    RepairEscalation,
}

impl AdmissionWorkClass {
    /// Map to the canonical scheduling lane.
    #[must_use]
    pub const fn lane_class(self) -> LaneClass {
        match self {
            Self::SyncBarrier | Self::MetadataStorm => LaneClass::Metadata,
            Self::ForegroundIo
            | Self::ReadServing
            | Self::VmRandomIo
            | Self::BulkIngest
            | Self::AuthorityPromotion => LaneClass::Demand,
            Self::SpeculativePrefetch | Self::CacheOnlyTrial => LaneClass::Speculative,
            Self::BackgroundOptimizer => LaneClass::Background,
            Self::RepairEscalation => LaneClass::Control,
        }
    }

    /// Returns true when work can be dropped under pressure.
    #[must_use]
    pub const fn can_be_dropped(self) -> bool {
        matches!(
            self,
            Self::SpeculativePrefetch | Self::CacheOnlyTrial | Self::BackgroundOptimizer
        )
    }

    /// Returns true when dropped work can be resumed.
    #[must_use]
    pub const fn can_be_resumed(self) -> bool {
        matches!(self, Self::BackgroundOptimizer)
    }
}

/// An admission request from a producer (FUSE, block, transport, background).
#[derive(Clone, Debug)]
pub struct AdmissionRequest {
    /// What kind of work.
    pub work_class: AdmissionWorkClass,

    /// Storage-intent action class for lane mapping.
    pub action_class: StorageIntentActionClass,

    /// Budget owner for tenant isolation.
    pub budget_owner: StorageIntentBudgetOwnerId,

    /// Requested byte count (may be zero for metadata ops).
    pub requested_bytes: u64,

    /// Requested op count.
    pub requested_ops: u64,

    /// Compiled policy identity, or ZERO when unknown.
    pub policy_id: StorageIntentPolicyId,

    /// Compiled policy revision, or 0.
    pub policy_revision: StorageIntentPolicyRevision,

    /// Requested durability guarantee.
    pub guarantee: StorageIntentGuaranteeClass,

    /// Evidence refs carried by the request.
    pub evidence_refs: [StorageIntentEvidenceRef; MAX_ADMISSION_EVIDENCE_REFS],

    /// Evidence families that must be present and fresh enough for this
    /// request. The scheduler also augments this list from compiled policy
    /// flags when a policy snapshot is active.
    pub required_evidence_kinds: [StorageIntentEvidenceKind; MAX_REQUIRED_EVIDENCE_KINDS],

    /// Number of populated entries in `required_evidence_kinds`.
    pub required_evidence_count: u8,

    /// True when required evidence did not fit in `required_evidence_kinds`.
    pub required_evidence_overflow: bool,
}

/// An empty evidence ref sentinel for array initialization.
pub const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

fn push_required_evidence_kind(
    kinds: &mut [StorageIntentEvidenceKind],
    count: &mut u8,
    kind: StorageIntentEvidenceKind,
) -> bool {
    if kind as u16 == StorageIntentEvidenceKind::Unknown as u16 {
        return true;
    }

    let mut index = 0;
    while index < *count as usize {
        if kinds[index] as u16 == kind as u16 {
            return true;
        }
        index += 1;
    }

    if (*count as usize) < kinds.len() {
        kinds[*count as usize] = kind;
        *count = (*count).saturating_add(1);
        true
    } else {
        false
    }
}

fn evidence_ref_matches_kind(
    evidence: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence.is_bound() && evidence.kind as u16 == kind as u16
}

fn action_mask_contains_any_prefetch_candidate(mask: PrefetchResidencyActionMask) -> bool {
    mask.contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::StridedVectorPrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::MetadataNamespacePrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::SmallRandomHotsetTrial)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::ManifestIndexPrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::SnapshotClonePrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::DegradedReadPrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
        || mask.contains_candidate(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage)
}

impl AdmissionRequest {
    /// Construct a request with no evidence.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        work_class: AdmissionWorkClass,
        action_class: StorageIntentActionClass,
        budget_owner: StorageIntentBudgetOwnerId,
        requested_bytes: u64,
        requested_ops: u64,
        policy_id: StorageIntentPolicyId,
        policy_revision: StorageIntentPolicyRevision,
        guarantee: StorageIntentGuaranteeClass,
    ) -> Self {
        Self {
            work_class,
            action_class,
            budget_owner,
            requested_bytes,
            requested_ops,
            policy_id,
            policy_revision,
            guarantee,
            evidence_refs: [EMPTY_EVIDENCE_REF; MAX_ADMISSION_EVIDENCE_REFS],
            required_evidence_kinds: [StorageIntentEvidenceKind::Unknown;
                MAX_REQUIRED_EVIDENCE_KINDS],
            required_evidence_count: 0,
            required_evidence_overflow: false,
        }
    }

    /// Add an evidence ref at the next free slot.
    #[must_use]
    pub fn with_evidence(mut self, evidence: StorageIntentEvidenceRef) -> Self {
        for slot in self.evidence_refs.iter_mut() {
            if !slot.is_bound() {
                *slot = evidence;
                break;
            }
        }
        self
    }

    /// Require one evidence family for this request.
    #[must_use]
    pub fn with_required_evidence_kind(mut self, kind: StorageIntentEvidenceKind) -> Self {
        if !push_required_evidence_kind(
            &mut self.required_evidence_kinds,
            &mut self.required_evidence_count,
            kind,
        ) {
            self.required_evidence_overflow = true;
        }
        self
    }

    /// Resolve the effective dispatch lane from work and action class.
    #[must_use]
    pub const fn resolved_lane(&self) -> LaneClass {
        resolve_admission_lane(self.work_class, self.action_class)
    }

    /// Returns true only when both the work and action class are droppable.
    #[must_use]
    pub const fn can_be_dropped(&self) -> bool {
        self.work_class.can_be_dropped() && action_class_can_be_dropped(self.action_class)
    }
}

// ---------------------------------------------------------------------------
// Admission decision
// ---------------------------------------------------------------------------

/// Outcome of an admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOutcome {
    /// Admitted for immediate dispatch.
    Admitted,
    /// Admitted but backpressured (producer should slow down).
    Backpressured,
    /// Throttled — admitted but rate-limited.
    Throttled,
    /// Dropped — speculative/prefetch work discarded.
    Dropped,
    /// Expired — cache-only trial timed out.
    Expired,
    /// Refused — cannot be admitted under current policy/caps.
    Refused,
}

/// A scheduler admission decision.
#[derive(Clone, Debug)]
pub struct AdmissionDecision {
    /// The outcome.
    pub outcome: AdmissionOutcome,

    /// Assigned lane for dispatch.
    pub lane: LaneClass,

    /// Reason for non-admitted outcomes.
    pub refusal: StorageIntentRefusalReason,

    /// Budget dimension that constrained this decision.
    pub budget_class: BudgetConstraintClass,

    /// Queue time before this decision, in microseconds.
    pub queue_time_us: u64,

    /// Whether a starvation override was applied to this decision.
    pub starvation_override: bool,

    /// Whether reserve protection was applied (protected from drop/throttle).
    pub reserve_protected: bool,

    /// Budget owner that was checked.
    pub budget_owner: StorageIntentBudgetOwnerId,
}

impl AdmissionDecision {
    /// Create an admitted decision.
    #[must_use]
    pub const fn admitted(lane: LaneClass, budget_owner: StorageIntentBudgetOwnerId) -> Self {
        Self {
            outcome: AdmissionOutcome::Admitted,
            lane,
            refusal: StorageIntentRefusalReason::None,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Create a backpressured decision.
    #[must_use]
    pub const fn backpressured(
        lane: LaneClass,
        reason: StorageIntentRefusalReason,
        budget_owner: StorageIntentBudgetOwnerId,
    ) -> Self {
        Self {
            outcome: AdmissionOutcome::Backpressured,
            lane,
            refusal: reason,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Create a refused decision.
    #[must_use]
    pub const fn refused(
        lane: LaneClass,
        reason: StorageIntentRefusalReason,
        budget_owner: StorageIntentBudgetOwnerId,
    ) -> Self {
        Self {
            outcome: AdmissionOutcome::Refused,
            lane,
            refusal: reason,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Create a dropped decision (speculative/prefetch only).
    #[must_use]
    pub const fn dropped(
        lane: LaneClass,
        reason: StorageIntentRefusalReason,
        budget_owner: StorageIntentBudgetOwnerId,
    ) -> Self {
        Self {
            outcome: AdmissionOutcome::Dropped,
            lane,
            refusal: reason,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Create a throttled decision (admitted but rate-limited).
    #[must_use]
    pub const fn throttled(
        lane: LaneClass,
        reason: StorageIntentRefusalReason,
        budget_owner: StorageIntentBudgetOwnerId,
    ) -> Self {
        Self {
            outcome: AdmissionOutcome::Throttled,
            lane,
            refusal: reason,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Create an expired decision for cache-only serving trials.
    #[must_use]
    pub const fn expired(
        lane: LaneClass,
        reason: StorageIntentRefusalReason,
        budget_owner: StorageIntentBudgetOwnerId,
    ) -> Self {
        Self {
            outcome: AdmissionOutcome::Expired,
            lane,
            refusal: reason,
            budget_class: BudgetConstraintClass::None,
            queue_time_us: 0,
            starvation_override: false,
            reserve_protected: false,
            budget_owner,
        }
    }

    /// Record the budget dimension that constrained this decision.
    #[must_use]
    pub const fn with_budget_class(mut self, budget_class: BudgetConstraintClass) -> Self {
        self.budget_class = budget_class;
        self
    }

    /// Record queue time.
    #[must_use]
    pub const fn with_queue_time(mut self, queue_time_us: u64) -> Self {
        self.queue_time_us = queue_time_us;
        self
    }

    /// Mark as starvation-overridden.
    #[must_use]
    pub const fn with_starvation_override(mut self) -> Self {
        self.starvation_override = true;
        self
    }

    /// Mark as reserve-protected.
    #[must_use]
    pub const fn with_reserve_protection(mut self) -> Self {
        self.reserve_protected = true;
        self
    }
}

// ---------------------------------------------------------------------------
// Scheduler evidence (read-only, for #849, #850, #877 consumers)
// ---------------------------------------------------------------------------

/// Confidence in an admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulingConfidenceClass {
    /// All required evidence is present and fresh.
    High,
    /// Evidence is present but may be stale.
    Stale,
    /// Evidence is partially missing; conservative defaults used.
    DegradedVisible,
    /// Evidence is absent; decision is based on conservative refusal.
    Unknown,
    /// Evidence is contradicted; decision may be unsafe.
    Contradicted,
}

/// Read-only scheduling evidence emitted for downstream consumers.
#[derive(Clone, Debug)]
pub struct SchedulingEvidence {
    /// When the evidence was recorded (monotonic tick).
    pub observed_tick: u64,

    /// The admission decision this evidence describes.
    pub decision: AdmissionDecision,

    /// Storage-intent action class.
    pub action_class: StorageIntentActionClass,

    /// Work class that was classified.
    pub work_class: AdmissionWorkClass,

    /// Confidence in the decision.
    pub confidence: SchedulingConfidenceClass,

    /// Throttling or refusal reason (same as decision.refusal for
    /// non-admitted outcomes).
    pub throttle_or_refusal_reason: StorageIntentRefusalReason,

    /// Allocator/layout pressure reason from #880 evidence, when available.
    pub allocator_pressure_reason: Option<StorageIntentRefusalReason>,

    /// Speculative drop or expiration reason.
    pub speculative_drop_reason: Option<StorageIntentRefusalReason>,

    /// Whether a starvation override was applied.
    pub starvation_override: bool,

    /// Whether reserve protection was applied.
    pub reserve_protected: bool,

    /// Budget class: which budget cap(s) constrained this decision.
    pub budget_class: BudgetConstraintClass,

    /// Policy identity that governed this decision.
    pub policy_id: StorageIntentPolicyId,

    /// Policy revision.
    pub policy_revision: StorageIntentPolicyRevision,

    /// Evidence refs that were available for this decision.
    pub available_evidence: [StorageIntentEvidenceRef; MAX_ADMISSION_EVIDENCE_REFS],

    /// Evidence refs that were missing or stale.
    pub missing_evidence_kinds: [StorageIntentEvidenceKind; MAX_REQUIRED_EVIDENCE_KINDS],
    pub missing_evidence_count: u8,

    /// True when required evidence overflowed the scheduler evidence buffer.
    pub missing_evidence_overflow: bool,
}

/// Which budget cap constrained the decision (or None).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetConstraintClass {
    /// No budget constraint was applied.
    None,
    /// Dirty-byte cap constrained this decision.
    DirtyBytes,
    /// Inflight-byte cap constrained this decision.
    InflightBytes,
    /// Transport window cap constrained this decision.
    TransportWindow,
    /// Device queue depth constrained this decision.
    DeviceQueueDepth,
    /// Allocator/free-space pressure constrained this decision.
    AllocatorPressure,
    /// Foreground latency budget constrained this decision.
    ForegroundLatency,
    /// Background optimizer budget constrained this decision.
    BackgroundOptimizer,
    /// Tenant isolation budget constrained this decision.
    TenantIsolation,
}

// ---------------------------------------------------------------------------
// Dispatch queue: admitted work -> lane-ordered dispatch
// ---------------------------------------------------------------------------

/// Work admitted to a lane and waiting for dispatch.
#[derive(Clone, Debug)]
pub struct QueuedStorageIntentWork<T> {
    /// Caller-owned work item.
    pub item: T,

    /// Admission request used to produce the decision.
    pub request: AdmissionRequest,

    /// Admission decision that made this work dispatchable.
    pub admission: AdmissionDecision,

    /// Monotonic enqueue time in microseconds, supplied by the caller.
    pub enqueued_at_us: u64,

    /// Evidence confidence carried from admission.
    pub confidence: SchedulingConfidenceClass,
}

/// Work selected for dispatch from one lane.
#[derive(Clone, Debug)]
pub struct StorageIntentDispatch<T> {
    /// Caller-owned work item.
    pub item: T,

    /// Original request.
    pub request: AdmissionRequest,

    /// Dispatch decision with queue time and starvation state applied.
    pub decision: AdmissionDecision,

    /// Lane selected for dispatch.
    pub lane: LaneClass,

    /// Time spent queued, in microseconds.
    pub queue_time_us: u64,

    /// True when this dispatch bypassed higher-priority queued work because
    /// the selected lane exceeded its starvation timeout.
    pub starvation_override: bool,
}

/// Reason an admission decision could not be queued for dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchQueueAdmissionError {
    /// The decision was not dispatchable.
    NotDispatchable {
        /// Outcome that blocked dispatch.
        outcome: AdmissionOutcome,
        /// Refusal/drop/throttle reason carried by the decision.
        refusal: StorageIntentRefusalReason,
    },
}

/// Lane-ordered dispatch queue for already-admitted storage-intent work.
///
/// This queue is intentionally adapter-agnostic. FUSE, block, transport,
/// device-IO, and background-service producers can enqueue their own work item
/// type after `StorageIntentScheduler::admit` returns a dispatchable decision.
/// The queue then selects the next lane using the unified `LaneClass` ordering
/// and starvation timeouts without inventing a second scheduler vocabulary.
#[derive(Clone, Debug)]
pub struct StorageIntentDispatchQueue<T> {
    queues: BTreeMap<LaneClass, VecDeque<QueuedStorageIntentWork<T>>>,
    pending: usize,
}

impl<T> StorageIntentDispatchQueue<T> {
    /// Create an empty dispatch queue with one FIFO per lane.
    #[must_use]
    pub fn new() -> Self {
        let mut queues = BTreeMap::new();
        for lane in LANE_CLASSES_BY_PRIORITY {
            queues.insert(lane, VecDeque::new());
        }

        Self { queues, pending: 0 }
    }

    /// Total queued work items.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.pending
    }

    /// Return true when no work is queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pending == 0
    }

    /// Queued work items for one lane.
    #[must_use]
    pub fn lane_len(&self, lane: LaneClass) -> usize {
        self.queues.get(&lane).map_or(0, VecDeque::len)
    }

    /// Queue work that has a dispatchable admission decision.
    ///
    /// `Admitted` and `Throttled` decisions may enter the dispatch queue.
    /// `Backpressured`, `Dropped`, `Expired`, and `Refused` outcomes are
    /// visible stop states and are not silently converted into runnable work.
    pub fn enqueue_dispatchable(
        &mut self,
        request: AdmissionRequest,
        admission: AdmissionDecision,
        item: T,
        enqueued_at_us: u64,
        confidence: SchedulingConfidenceClass,
    ) -> Result<(), DispatchQueueAdmissionError> {
        if !matches!(
            admission.outcome,
            AdmissionOutcome::Admitted | AdmissionOutcome::Throttled
        ) {
            return Err(DispatchQueueAdmissionError::NotDispatchable {
                outcome: admission.outcome,
                refusal: admission.refusal,
            });
        }

        let lane = admission.lane;
        let queued = QueuedStorageIntentWork {
            item,
            request,
            admission,
            enqueued_at_us,
            confidence,
        };

        self.queues.entry(lane).or_default().push_back(queued);
        self.pending = self.pending.saturating_add(1);
        Ok(())
    }

    /// Dispatch the next work item using `scheduler.current_tick + 1` as the
    /// synthetic queue-time clock.
    pub fn dispatch_next(
        &mut self,
        scheduler: &mut StorageIntentScheduler,
    ) -> Option<StorageIntentDispatch<T>> {
        let now_us = scheduler.current_tick.saturating_add(1);
        self.dispatch_next_at(scheduler, now_us)
    }

    /// Dispatch the next work item at the caller-supplied monotonic time.
    ///
    /// Selection honors strict lane priority unless a lower-priority lane has
    /// waited past its configured starvation timeout. Dispatch records
    /// queue-time evidence and accounts the item as inflight.
    pub fn dispatch_next_at(
        &mut self,
        scheduler: &mut StorageIntentScheduler,
        now_us: u64,
    ) -> Option<StorageIntentDispatch<T>> {
        scheduler.advance_tick();

        let (lane, starvation_override) = match self.select_starved_lane(scheduler, now_us) {
            Some(lane) => (lane, true),
            None => (self.select_priority_lane()?, false),
        };

        let queued = self.queues.get_mut(&lane)?.pop_front()?;
        self.pending = self.pending.saturating_sub(1);

        let queue_time_us = now_us.saturating_sub(queued.enqueued_at_us);
        let mut decision = queued.admission.with_queue_time(queue_time_us);
        if starvation_override {
            decision = decision.with_starvation_override();
        }

        scheduler.account_inflight(
            lane,
            queued.request.requested_bytes,
            queued.request.requested_ops,
            queued.request.budget_owner,
        );
        if let Some(counter) = scheduler.counters.get_mut(&lane) {
            counter.last_service_tick = scheduler.current_tick;
        }
        scheduler.emit_evidence(&queued.request, &decision, queued.confidence, None);

        Some(StorageIntentDispatch {
            item: queued.item,
            request: queued.request,
            decision,
            lane,
            queue_time_us,
            starvation_override,
        })
    }

    fn select_priority_lane(&self) -> Option<LaneClass> {
        LANE_CLASSES_BY_PRIORITY
            .into_iter()
            .find(|&lane| self.lane_len(lane) > 0)
    }

    fn select_starved_lane(
        &self,
        scheduler: &StorageIntentScheduler,
        now_us: u64,
    ) -> Option<LaneClass> {
        let mut selected: Option<(LaneClass, u64)> = None;

        for lane in LANE_CLASSES_BY_PRIORITY {
            let Some(wait_us) = self.starved_wait_us(lane, scheduler, now_us) else {
                continue;
            };

            selected = match selected {
                Some((best_lane, best_wait))
                    if best_wait > wait_us
                        || (best_wait == wait_us
                            && lane_priority(best_lane) >= lane_priority(lane)) =>
                {
                    Some((best_lane, best_wait))
                }
                _ => Some((lane, wait_us)),
            };
        }

        selected.map(|(lane, _)| lane)
    }

    fn starved_wait_us(
        &self,
        lane: LaneClass,
        scheduler: &StorageIntentScheduler,
        now_us: u64,
    ) -> Option<u64> {
        let config = scheduler.lane_configs.get(&lane)?;
        if config.starvation_timeout_ms == 0 {
            return None;
        }

        let queued = self.queues.get(&lane)?.front()?;
        let wait_us = now_us.saturating_sub(queued.enqueued_at_us);
        let timeout_us = config.starvation_timeout_ms.saturating_mul(1_000);
        if wait_us > timeout_us {
            Some(wait_us)
        } else {
            None
        }
    }
}

impl<T> Default for StorageIntentDispatchQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Scheduler state
// ---------------------------------------------------------------------------

/// Per-lane admission counters.
#[derive(Clone, Debug, Default)]
pub struct LaneAdmissionCounters {
    pub admitted: u64,
    pub backpressured: u64,
    pub throttled: u64,
    pub dropped: u64,
    pub expired: u64,
    pub refused: u64,
    pub inflight_bytes: u64,
    pub inflight_ops: u64,
    pub last_service_tick: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvidenceAssessment {
    confidence: SchedulingConfidenceClass,
    refusal: StorageIntentRefusalReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RequiredEvidenceKinds {
    kinds: [StorageIntentEvidenceKind; MAX_REQUIRED_EVIDENCE_KINDS],
    count: u8,
    overflow: bool,
}

impl RequiredEvidenceKinds {
    const fn empty() -> Self {
        Self {
            kinds: [StorageIntentEvidenceKind::Unknown; MAX_REQUIRED_EVIDENCE_KINDS],
            count: 0,
            overflow: false,
        }
    }

    fn push(&mut self, kind: StorageIntentEvidenceKind) {
        if !push_required_evidence_kind(&mut self.kinds, &mut self.count, kind) {
            self.overflow = true;
        }
    }
}

impl EvidenceAssessment {
    const HIGH: Self = Self {
        confidence: SchedulingConfidenceClass::High,
        refusal: StorageIntentRefusalReason::None,
    };

    const fn refused(
        confidence: SchedulingConfidenceClass,
        refusal: StorageIntentRefusalReason,
    ) -> Self {
        Self {
            confidence,
            refusal,
        }
    }
}

/// The storage-intent scheduler.
///
/// One instance governs admission for a single resource domain (e.g., one
/// dataset, one mount, or one transport edge). The scheduler consumes
/// policy snapshots, budget caps, and evidence state to produce admission
/// decisions and read-only scheduling evidence.
#[derive(Clone, Debug)]
pub struct StorageIntentScheduler {
    /// Per-lane configurations (derived from policy and transport records).
    pub lane_configs: BTreeMap<LaneClass, LaneConfig>,

    /// Current budget caps.
    pub caps: StorageIntentBudgetCaps,

    /// Per-lane admission counters.
    pub counters: BTreeMap<LaneClass, LaneAdmissionCounters>,

    /// Per-budget-owner isolation state.
    pub owner_isolation: BTreeMap<StorageIntentBudgetOwnerId, BudgetOwnerIsolationState>,

    /// Monotonic tick counter for evidence timestamps.
    pub current_tick: u64,

    /// Current policy identity.
    pub active_policy_id: StorageIntentPolicyId,

    /// Current policy revision.
    pub active_policy_revision: StorageIntentPolicyRevision,

    /// Active compiled prefetch/residency policy snapshot from #855.
    pub active_prefetch_policy: PrefetchResidencyPolicyEnvelope,

    /// Evidence-query cut that supports the active compiled policy.
    pub active_evidence_snapshot: StorageIntentEvidenceQuerySnapshot,

    /// Recently emitted evidence (bounded ring).
    pub evidence_log: Vec<SchedulingEvidence>,
}

impl StorageIntentScheduler {
    /// Max evidence entries to retain.
    const MAX_EVIDENCE_LOG: usize = 256;

    /// Create a new scheduler with default lane configs.
    #[must_use]
    pub fn new() -> Self {
        let mut lane_configs = BTreeMap::new();
        lane_configs.insert(LaneClass::Control, LaneConfig::control(u64::MAX, u64::MAX));
        lane_configs.insert(
            LaneClass::Metadata,
            LaneConfig::metadata(16 * 1024 * 1024, 1024),
        );
        lane_configs.insert(
            LaneClass::Demand,
            LaneConfig::demand(256 * 1024 * 1024, 4096),
        );
        lane_configs.insert(
            LaneClass::Speculative,
            LaneConfig::speculative(64 * 1024 * 1024, 2048),
        );
        lane_configs.insert(
            LaneClass::Background,
            LaneConfig::background(128 * 1024 * 1024, 512),
        );

        let mut counters = BTreeMap::new();
        for lane in &[
            LaneClass::Control,
            LaneClass::Metadata,
            LaneClass::Demand,
            LaneClass::Speculative,
            LaneClass::Background,
        ] {
            counters.insert(*lane, LaneAdmissionCounters::default());
        }

        Self {
            lane_configs,
            caps: StorageIntentBudgetCaps::default(),
            counters,
            owner_isolation: BTreeMap::new(),
            current_tick: 0,
            active_policy_id: StorageIntentPolicyId::ZERO,
            active_policy_revision: StorageIntentPolicyRevision(0),
            active_prefetch_policy: PrefetchResidencyPolicyEnvelope::default(),
            active_evidence_snapshot: StorageIntentEvidenceQuerySnapshot::default(),
            evidence_log: Vec::with_capacity(Self::MAX_EVIDENCE_LOG),
        }
    }

    /// Update policy identity and revision from a compiled snapshot.
    pub fn set_active_policy(
        &mut self,
        policy_id: StorageIntentPolicyId,
        revision: StorageIntentPolicyRevision,
    ) {
        self.active_policy_id = policy_id;
        self.active_policy_revision = revision;
    }

    /// Consume a compiled prefetch/residency policy envelope from #855.
    ///
    /// The scheduler records the policy identity, stores the policy envelope
    /// for later action-mask and evidence checks, and only tightens lane caps
    /// from compiled policy limits. A zero compiled limit means "no compiled
    /// limit", not "zero-byte lane".
    pub fn apply_prefetch_residency_policy(
        &mut self,
        policy: &PrefetchResidencyPolicyEnvelope,
        evidence_snapshot: Option<&StorageIntentEvidenceQuerySnapshot>,
    ) {
        self.active_prefetch_policy = *policy;
        self.active_evidence_snapshot = match evidence_snapshot {
            Some(snapshot) => *snapshot,
            None => StorageIntentEvidenceQuerySnapshot::default(),
        };
        self.set_active_policy(policy.policy_id, policy.policy_revision);

        self.tighten_lane_inflight_bytes(LaneClass::Speculative, policy.max_prefetch_window_bytes);
        self.tighten_lane_inflight_bytes(LaneClass::Background, policy.max_staging_bytes);
    }

    /// Advance the monotonic tick.
    pub fn advance_tick(&mut self) {
        self.current_tick = self.current_tick.wrapping_add(1);
    }

    // ------------------------------------------------------------------
    // Admission
    // ------------------------------------------------------------------

    /// Admit or refuse work.
    ///
    /// Returns an admission decision that respects priority ordering,
    /// budget caps, tenant isolation, and speculative-drop policy.
    /// This is the primary entry point for producers.
    pub fn admit(&mut self, request: &AdmissionRequest) -> AdmissionDecision {
        self.advance_tick();

        let lane = request.resolved_lane();
        let config = self
            .lane_configs
            .get(&lane)
            .cloned()
            .unwrap_or_else(|| LaneConfig::background(u64::MAX, u64::MAX));
        let evidence_assessment = self.assess_evidence(request);

        if evidence_assessment.refusal as u16 != StorageIntentRefusalReason::None as u16 {
            let decision =
                self.conservative_refusal_decision(lane, request, evidence_assessment.refusal);
            self.record_decision(lane, &decision);
            self.emit_evidence(
                request,
                &decision,
                evidence_assessment.confidence,
                if decision.outcome == AdmissionOutcome::Dropped {
                    Some(evidence_assessment.refusal)
                } else {
                    None
                },
            );
            return decision;
        }

        // ── 1. Check budget caps in priority order ──
        if let Some((reason, budget_class)) = self.check_hard_caps(request, lane) {
            let mut decision = if request.can_be_dropped() {
                AdmissionDecision::dropped(lane, reason, request.budget_owner)
            } else if lane == LaneClass::Background {
                AdmissionDecision::refused(lane, reason, request.budget_owner)
            } else if lane == LaneClass::Control || lane == LaneClass::Metadata {
                AdmissionDecision::admitted(lane, request.budget_owner).with_reserve_protection()
            } else {
                AdmissionDecision::throttled(lane, reason, request.budget_owner)
            };
            decision = decision.with_budget_class(budget_class);
            self.record_decision(lane, &decision);
            self.emit_evidence(request, &decision, evidence_assessment.confidence, None);
            return decision;
        }

        // ── 2. Check tenant isolation ──
        if !request.budget_owner.is_zero() {
            if let Some((reason, budget_class)) = self.check_tenant_isolation(request) {
                let decision = if request.can_be_dropped() {
                    AdmissionDecision::dropped(lane, reason, request.budget_owner)
                } else {
                    AdmissionDecision::backpressured(lane, reason, request.budget_owner)
                }
                .with_budget_class(budget_class);
                self.record_decision(lane, &decision);
                self.emit_evidence(request, &decision, evidence_assessment.confidence, None);
                return decision;
            }
        }

        // ── 3. Check per-lane inflight caps ──
        if let Some((reason, budget_class)) = self.check_lane_inflight(lane, request, &config) {
            let mut decision = if request.can_be_dropped() {
                AdmissionDecision::dropped(lane, reason, request.budget_owner)
            } else if lane == LaneClass::Background {
                AdmissionDecision::refused(lane, reason, request.budget_owner)
            } else if lane == LaneClass::Control || lane == LaneClass::Metadata {
                AdmissionDecision::admitted(lane, request.budget_owner).with_reserve_protection()
            } else {
                AdmissionDecision::throttled(lane, reason, request.budget_owner)
            };
            decision = decision.with_budget_class(budget_class);
            self.record_decision(lane, &decision);
            self.emit_evidence(request, &decision, evidence_assessment.confidence, None);
            return decision;
        }

        // ── 4. Check speculative drop/expiry ──
        if request.can_be_dropped() {
            if let Some((reason, budget_class)) = self.check_speculative_pressure() {
                let decision = AdmissionDecision::dropped(lane, reason, request.budget_owner)
                    .with_budget_class(budget_class);
                self.record_decision(lane, &decision);
                self.emit_evidence(
                    request,
                    &decision,
                    evidence_assessment.confidence,
                    Some(reason),
                );
                return decision;
            }
        }

        // ── 5. Check serving-trial expiry ──
        if request.work_class == AdmissionWorkClass::CacheOnlyTrial
            && self.caps.foreground_latency_budget_us > 0
            && self.caps.inflight_bytes > self.caps.max_inflight_bytes / 2
        {
            let decision = AdmissionDecision::expired(
                lane,
                StorageIntentRefusalReason::MovementDebtNotPaidBack,
                request.budget_owner,
            )
            .with_budget_class(BudgetConstraintClass::ForegroundLatency);
            self.record_decision(lane, &decision);
            self.emit_evidence(
                request,
                &decision,
                evidence_assessment.confidence,
                Some(StorageIntentRefusalReason::MovementDebtNotPaidBack),
            );
            return decision;
        }

        // ── 6. Admitted ──
        let mut decision = AdmissionDecision::admitted(lane, request.budget_owner);

        // Apply starvation override: lower-priority lane not serviced
        // within its starvation timeout gets at least one op.
        if let Some(counter) = self.counters.get(&lane) {
            if config.starvation_timeout_ms > 0
                && counter.last_service_tick > 0
                && self.current_tick.saturating_sub(counter.last_service_tick)
                    > config.starvation_timeout_ms
            {
                decision = decision.with_starvation_override();
            }
        }

        self.record_decision(lane, &decision);
        self.emit_evidence(request, &decision, evidence_assessment.confidence, None);
        decision
    }

    // ------------------------------------------------------------------
    // Internal checks
    // ------------------------------------------------------------------

    fn tighten_lane_inflight_bytes(&mut self, lane: LaneClass, compiled_limit: u64) {
        if compiled_limit == 0 {
            return;
        }

        let fallback = match lane {
            LaneClass::Control => LaneConfig::control(compiled_limit, u64::MAX),
            LaneClass::Metadata => LaneConfig::metadata(compiled_limit, u64::MAX),
            LaneClass::Demand => LaneConfig::demand(compiled_limit, u64::MAX),
            LaneClass::Speculative => LaneConfig::speculative(compiled_limit, u64::MAX),
            LaneClass::Background => LaneConfig::background(compiled_limit, u64::MAX),
        };

        let config = self.lane_configs.entry(lane).or_insert(fallback);
        if config.max_inflight_bytes == 0 {
            config.max_inflight_bytes = compiled_limit;
        } else {
            config.max_inflight_bytes = config.max_inflight_bytes.min(compiled_limit);
        }
    }

    fn conservative_refusal_decision(
        &self,
        lane: LaneClass,
        request: &AdmissionRequest,
        reason: StorageIntentRefusalReason,
    ) -> AdmissionDecision {
        if request.can_be_dropped()
            && reason as u16 != StorageIntentRefusalReason::NoLegalReceiptSet as u16
        {
            AdmissionDecision::dropped(lane, reason, request.budget_owner)
        } else {
            AdmissionDecision::refused(lane, reason, request.budget_owner)
        }
    }

    fn assess_evidence(&self, request: &AdmissionRequest) -> EvidenceAssessment {
        if let Some(refusal) = self.check_policy_identity(request) {
            return EvidenceAssessment::refused(SchedulingConfidenceClass::Contradicted, refusal);
        }

        if self.active_policy_loaded()
            && self.action_is_prefetch_residency_scoped(request.action_class)
        {
            if !self.policy_scope_usable() {
                return EvidenceAssessment::refused(
                    SchedulingConfidenceClass::Unknown,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                );
            }

            if !self.policy_allows_action(request.action_class) {
                return EvidenceAssessment::refused(
                    SchedulingConfidenceClass::DegradedVisible,
                    StorageIntentRefusalReason::NoLegalReceiptSet,
                );
            }
        }

        let required_evidence = self.collect_required_evidence_kinds(request);
        if required_evidence.overflow {
            return EvidenceAssessment::refused(
                SchedulingConfidenceClass::Unknown,
                StorageIntentRefusalReason::EvidenceNotUsable,
            );
        }

        let mut confidence = EvidenceAssessment::HIGH.confidence;
        let mut index = 0;
        while index < required_evidence.count as usize {
            let kind = required_evidence.kinds[index];
            if !self.has_bound_evidence_kind(request, kind) {
                return EvidenceAssessment::refused(
                    SchedulingConfidenceClass::Unknown,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                );
            }

            match self.blocking_freshness_for_kind(kind) {
                Some(blocking_confidence) => {
                    return EvidenceAssessment::refused(
                        blocking_confidence,
                        StorageIntentRefusalReason::EvidenceNotUsable,
                    );
                }
                None => {
                    if required_evidence.count > 0
                        && !self.active_evidence_snapshot.has_query_identity()
                    {
                        confidence = SchedulingConfidenceClass::DegradedVisible;
                    }
                }
            }
            index += 1;
        }

        EvidenceAssessment {
            confidence,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn check_policy_identity(
        &self,
        request: &AdmissionRequest,
    ) -> Option<StorageIntentRefusalReason> {
        if request.policy_id.is_zero() {
            return None;
        }

        if !self.active_policy_loaded() {
            return Some(StorageIntentRefusalReason::EvidenceNotUsable);
        }

        if request.policy_id != self.active_policy_id
            || request.policy_revision != self.active_policy_revision
        {
            return Some(StorageIntentRefusalReason::EvidenceNotUsable);
        }

        None
    }

    fn active_policy_loaded(&self) -> bool {
        !self.active_policy_id.is_zero() && self.active_policy_revision.0 > 0
    }

    fn policy_scope_usable(&self) -> bool {
        if self
            .active_prefetch_policy
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_DATASET_SCOPE)
        {
            matches!(
                self.active_prefetch_policy.policy_scope,
                PrefetchResidencyPolicyScope::Dataset | PrefetchResidencyPolicyScope::SubjectRange
            )
        } else {
            true
        }
    }

    fn action_is_prefetch_residency_scoped(&self, action: StorageIntentActionClass) -> bool {
        matches!(
            action,
            StorageIntentActionClass::QueuePrefetchTuning
                | StorageIntentActionClass::CacheOnlyServingTrial
                | StorageIntentActionClass::FlashServingPromotion
                | StorageIntentActionClass::AuthorityPromotion
        )
    }

    fn policy_allows_action(&self, action: StorageIntentActionClass) -> bool {
        let mask = self.active_prefetch_policy.allowed_actions;
        match action {
            StorageIntentActionClass::QueuePrefetchTuning => {
                action_mask_contains_any_prefetch_candidate(mask)
            }
            StorageIntentActionClass::CacheOnlyServingTrial => {
                mask.contains_candidate(PrefetchResidencyCandidateClass::CacheOnlyTrial)
                    || mask.contains_candidate(PrefetchResidencyCandidateClass::VolatileRamTrial)
            }
            StorageIntentActionClass::FlashServingPromotion => {
                mask.contains_candidate(PrefetchResidencyCandidateClass::FlashHotServing)
                    || mask.contains_candidate(PrefetchResidencyCandidateClass::IntentBackedRam)
                    || mask.contains_candidate(PrefetchResidencyCandidateClass::PmemDurable)
            }
            StorageIntentActionClass::AuthorityPromotion => {
                mask.contains_candidate(
                    PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
                ) || mask.contains_candidate(PrefetchResidencyCandidateClass::IntentBackedRam)
                    || mask.contains_candidate(PrefetchResidencyCandidateClass::PmemDurable)
            }
            _ => true,
        }
    }

    fn collect_required_evidence_kinds(&self, request: &AdmissionRequest) -> RequiredEvidenceKinds {
        let mut required = RequiredEvidenceKinds::empty();
        if request.required_evidence_overflow
            || request.required_evidence_count as usize > request.required_evidence_kinds.len()
        {
            required.overflow = true;
        }

        let mut index = 0;
        let request_required_count =
            (request.required_evidence_count as usize).min(request.required_evidence_kinds.len());
        while index < request_required_count {
            required.push(request.required_evidence_kinds[index]);
            index += 1;
        }

        if self.active_policy_loaded()
            && self.action_is_prefetch_residency_scoped(request.action_class)
        {
            self.push_policy_required_evidence(&mut required);
        }

        required
    }

    fn push_policy_required_evidence(&self, required: &mut RequiredEvidenceKinds) {
        let flags = self.active_prefetch_policy.flags;

        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE) {
            required.push(StorageIntentEvidenceKind::ServiceObjectiveEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY) {
            required.push(StorageIntentEvidenceKind::EvidenceQuerySnapshot);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY) {
            required.push(StorageIntentEvidenceKind::MediaCapabilityEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
            || flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
        {
            required.push(StorageIntentEvidenceKind::MediaCostWearLedger);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT) {
            required.push(StorageIntentEvidenceKind::DecisionFrontierEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE) {
            required.push(StorageIntentEvidenceKind::CapacityAdmissionEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION) {
            required.push(StorageIntentEvidenceKind::TenantIsolationEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY) {
            required.push(StorageIntentEvidenceKind::ReadFreshnessEvidence);
        }
        if flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
        {
            required.push(StorageIntentEvidenceKind::RelocationReceipt);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN) {
            required.push(StorageIntentEvidenceKind::TrustDomainEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET) {
            required.push(StorageIntentEvidenceKind::TransportPathEvidence);
        }
        if flags.contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION) {
            required.push(StorageIntentEvidenceKind::SchedulerAdmissionRecord);
        }
    }

    fn has_bound_evidence_kind(
        &self,
        request: &AdmissionRequest,
        kind: StorageIntentEvidenceKind,
    ) -> bool {
        request
            .evidence_refs
            .iter()
            .any(|evidence| evidence_ref_matches_kind(*evidence, kind))
            || self.active_policy_has_bound_evidence_kind(kind)
    }

    fn active_policy_has_bound_evidence_kind(&self, kind: StorageIntentEvidenceKind) -> bool {
        let refs = self.active_prefetch_policy.evidence_refs;
        match kind {
            StorageIntentEvidenceKind::ServiceObjectiveEvidence => {
                evidence_ref_matches_kind(refs.service_objective_ref, kind)
            }
            StorageIntentEvidenceKind::EvidenceQuerySnapshot => {
                evidence_ref_matches_kind(refs.evidence_query_ref, kind)
            }
            StorageIntentEvidenceKind::DecisionFrontierEvidence => {
                evidence_ref_matches_kind(refs.decision_frontier_ref, kind)
            }
            StorageIntentEvidenceKind::MediaCapabilityEvidence => {
                evidence_ref_matches_kind(refs.media_capability_ref, kind)
            }
            StorageIntentEvidenceKind::SchedulerAdmissionRecord => {
                evidence_ref_matches_kind(refs.scheduler_admission_ref, kind)
            }
            StorageIntentEvidenceKind::CapacityAdmissionEvidence => {
                evidence_ref_matches_kind(refs.capacity_reserve_ref, kind)
            }
            StorageIntentEvidenceKind::TenantIsolationEvidence => {
                evidence_ref_matches_kind(refs.tenant_isolation_ref, kind)
            }
            StorageIntentEvidenceKind::MediaCostWearLedger => {
                evidence_ref_matches_kind(refs.cost_wear_ref, kind)
                    || evidence_ref_matches_kind(refs.egress_restore_cost_ref, kind)
            }
            StorageIntentEvidenceKind::TransportPathEvidence => {
                evidence_ref_matches_kind(refs.transport_budget_ref, kind)
            }
            StorageIntentEvidenceKind::TrustDomainEvidence => {
                evidence_ref_matches_kind(refs.trust_domain_ref, kind)
            }
            StorageIntentEvidenceKind::ReadFreshnessEvidence => {
                evidence_ref_matches_kind(refs.read_serving_boundary_ref, kind)
            }
            StorageIntentEvidenceKind::RelocationReceipt => {
                evidence_ref_matches_kind(refs.relocation_boundary_ref, kind)
            }
            StorageIntentEvidenceKind::ResultRefusalEvidence => {
                evidence_ref_matches_kind(refs.result_refusal_ref, kind)
            }
            _ => false,
        }
    }

    fn blocking_freshness_for_kind(
        &self,
        kind: StorageIntentEvidenceKind,
    ) -> Option<SchedulingConfidenceClass> {
        if !self.active_evidence_snapshot.has_query_identity() {
            return None;
        }

        match self
            .active_evidence_snapshot
            .family_freshness
            .state_for_kind(kind)
        {
            EvidenceFamilyFreshnessState::Fresh => None,
            EvidenceFamilyFreshnessState::Contradictory => {
                Some(SchedulingConfidenceClass::Contradicted)
            }
            EvidenceFamilyFreshnessState::Stale
            | EvidenceFamilyFreshnessState::Superseded
            | EvidenceFamilyFreshnessState::Redacted
            | EvidenceFamilyFreshnessState::Compacted => Some(SchedulingConfidenceClass::Stale),
            EvidenceFamilyFreshnessState::Unknown
            | EvidenceFamilyFreshnessState::Missing
            | EvidenceFamilyFreshnessState::Unavailable
            | EvidenceFamilyFreshnessState::Refused => Some(SchedulingConfidenceClass::Unknown),
        }
    }

    fn check_hard_caps(
        &self,
        request: &AdmissionRequest,
        lane: LaneClass,
    ) -> Option<(StorageIntentRefusalReason, BudgetConstraintClass)> {
        let caps = &self.caps;

        // Repair escalation bypasses dirty/inflight caps.
        if request.work_class == AdmissionWorkClass::RepairEscalation {
            return None;
        }

        // Sync barriers bypass allocator/background budget caps.
        let is_barrier = request.work_class == AdmissionWorkClass::SyncBarrier;

        if !is_barrier {
            if caps.allocator_pressure_pct > 90 {
                return Some((
                    StorageIntentRefusalReason::EvidenceNotUsable,
                    BudgetConstraintClass::AllocatorPressure,
                ));
            }
            if caps.background_optimizer_budget_bytes == 0 && lane == LaneClass::Background {
                return Some((
                    StorageIntentRefusalReason::MovementDebtNotPaidBack,
                    BudgetConstraintClass::BackgroundOptimizer,
                ));
            }
        }

        if caps.dirty_bytes > caps.max_dirty_bytes && caps.max_dirty_bytes > 0 {
            return Some((
                StorageIntentRefusalReason::GuaranteeFloorNotMet,
                BudgetConstraintClass::DirtyBytes,
            ));
        }

        if caps.inflight_bytes > caps.max_inflight_bytes && caps.max_inflight_bytes > 0 {
            // Still admit Metadata and Control; throttle everything else.
            if lane != LaneClass::Metadata && lane != LaneClass::Control {
                return Some((
                    StorageIntentRefusalReason::GuaranteeFloorNotMet,
                    BudgetConstraintClass::InflightBytes,
                ));
            }
        }

        if caps.device_queue_depth > caps.max_device_queue_depth
            && caps.max_device_queue_depth > 0
            && lane != LaneClass::Control
        {
            return Some((
                StorageIntentRefusalReason::EvidenceNotUsable,
                BudgetConstraintClass::DeviceQueueDepth,
            ));
        }

        // Transport window cap: backpressure demand-class and drop
        // speculative/background work when the window is exceeded.
        // Metadata and Control bypass this cap.
        if caps.max_transport_window_bytes > 0
            && caps.transport_window_bytes > caps.max_transport_window_bytes
            && lane != LaneClass::Metadata
            && lane != LaneClass::Control
        {
            return Some((
                StorageIntentRefusalReason::GuaranteeFloorNotMet,
                BudgetConstraintClass::TransportWindow,
            ));
        }

        // Foreground latency budget: throttle demand-class work and
        // drop speculative/background when budget would be exceeded.
        // Control and Metadata bypass; repair escalation already
        // returned None above.
        if caps.foreground_latency_budget_us > 0
            && caps.inflight_bytes > caps.max_inflight_bytes.saturating_mul(7) / 10
            && lane != LaneClass::Control
            && lane != LaneClass::Metadata
        {
            return Some((
                StorageIntentRefusalReason::MovementDebtNotPaidBack,
                BudgetConstraintClass::ForegroundLatency,
            ));
        }

        None
    }

    fn check_tenant_isolation(
        &self,
        request: &AdmissionRequest,
    ) -> Option<(StorageIntentRefusalReason, BudgetConstraintClass)> {
        let owner = self.owner_isolation.get(&request.budget_owner)?;
        if owner.throttle {
            return Some((
                owner.throttle_reason,
                BudgetConstraintClass::TenantIsolation,
            ));
        }
        if owner.max_dirty_bytes > 0 && owner.dirty_bytes > owner.max_dirty_bytes {
            return Some((
                StorageIntentRefusalReason::GuaranteeFloorNotMet,
                BudgetConstraintClass::TenantIsolation,
            ));
        }
        None
    }

    fn check_lane_inflight(
        &self,
        lane: LaneClass,
        request: &AdmissionRequest,
        config: &LaneConfig,
    ) -> Option<(StorageIntentRefusalReason, BudgetConstraintClass)> {
        let counter = self.counters.get(&lane)?;

        if config.max_inflight_bytes > 0
            && counter.inflight_bytes + request.requested_bytes > config.max_inflight_bytes
        {
            return Some((
                StorageIntentRefusalReason::GuaranteeFloorNotMet,
                BudgetConstraintClass::InflightBytes,
            ));
        }

        if config.max_inflight_ops > 0
            && counter.inflight_ops + request.requested_ops > config.max_inflight_ops
        {
            return Some((
                StorageIntentRefusalReason::GuaranteeFloorNotMet,
                BudgetConstraintClass::InflightBytes,
            ));
        }

        None
    }

    fn check_speculative_pressure(
        &self,
    ) -> Option<(StorageIntentRefusalReason, BudgetConstraintClass)> {
        // Drop speculative work when foreground latency budget is at risk.
        if self.caps.foreground_latency_budget_us > 0
            && self.caps.inflight_bytes > self.caps.max_inflight_bytes.saturating_mul(7) / 10
        {
            return Some((
                StorageIntentRefusalReason::MovementDebtNotPaidBack,
                BudgetConstraintClass::ForegroundLatency,
            ));
        }

        // Drop speculative work when allocator pressure is high.
        if self.caps.allocator_pressure_pct > 70 {
            return Some((
                StorageIntentRefusalReason::EvidenceNotUsable,
                BudgetConstraintClass::AllocatorPressure,
            ));
        }

        None
    }

    // ------------------------------------------------------------------
    // Accounting
    // ------------------------------------------------------------------

    fn record_decision(&mut self, lane: LaneClass, decision: &AdmissionDecision) {
        let counter = self.counters.entry(lane).or_default();
        counter.last_service_tick = self.current_tick;

        match decision.outcome {
            AdmissionOutcome::Admitted => {
                counter.admitted = counter.admitted.saturating_add(1);
            }
            AdmissionOutcome::Backpressured => {
                counter.backpressured = counter.backpressured.saturating_add(1);
            }
            AdmissionOutcome::Throttled => {
                counter.throttled = counter.throttled.saturating_add(1);
            }
            AdmissionOutcome::Dropped => {
                counter.dropped = counter.dropped.saturating_add(1);
            }
            AdmissionOutcome::Expired => {
                counter.expired = counter.expired.saturating_add(1);
            }
            AdmissionOutcome::Refused => {
                counter.refused = counter.refused.saturating_add(1);
            }
        }
    }

    /// Account for inflight bytes/ops after admission.
    pub fn account_inflight(
        &mut self,
        lane: LaneClass,
        bytes: u64,
        ops: u64,
        budget_owner: StorageIntentBudgetOwnerId,
    ) {
        let counter = self.counters.entry(lane).or_default();
        counter.inflight_bytes = counter.inflight_bytes.saturating_add(bytes);
        counter.inflight_ops = counter.inflight_ops.saturating_add(ops);

        if !budget_owner.is_zero() {
            let owner = self.owner_isolation.entry(budget_owner).or_default();
            *owner.per_lane_inflight.entry(lane).or_default() = owner
                .per_lane_inflight
                .get(&lane)
                .unwrap_or(&0)
                .saturating_add(bytes);
        }

        self.caps.inflight_bytes = self.caps.inflight_bytes.saturating_add(bytes);
    }

    /// Release inflight bytes/ops after completion.
    pub fn release_inflight(
        &mut self,
        lane: LaneClass,
        bytes: u64,
        ops: u64,
        budget_owner: StorageIntentBudgetOwnerId,
    ) {
        let counter = self.counters.entry(lane).or_default();
        counter.inflight_bytes = counter.inflight_bytes.saturating_sub(bytes);
        counter.inflight_ops = counter.inflight_ops.saturating_sub(ops);

        if !budget_owner.is_zero() {
            if let Some(owner) = self.owner_isolation.get_mut(&budget_owner) {
                if let Some(per_lane) = owner.per_lane_inflight.get_mut(&lane) {
                    *per_lane = per_lane.saturating_sub(bytes);
                }
            }
        }

        self.caps.inflight_bytes = self.caps.inflight_bytes.saturating_sub(bytes);
    }

    /// Update the budget caps snapshot.
    pub fn update_caps(&mut self, caps: StorageIntentBudgetCaps) {
        self.caps = caps;
    }

    /// Update a single lane config.
    pub fn set_lane_config(&mut self, config: LaneConfig) {
        self.lane_configs.insert(config.lane_class, config);
    }

    /// Set tenant isolation throttle.
    pub fn throttle_budget_owner(
        &mut self,
        owner: StorageIntentBudgetOwnerId,
        reason: StorageIntentRefusalReason,
    ) {
        let state = self.owner_isolation.entry(owner).or_default();
        state.throttle = true;
        state.throttle_reason = reason;
    }

    /// Clear tenant isolation throttle.
    pub fn unthrottle_budget_owner(&mut self, owner: StorageIntentBudgetOwnerId) {
        if let Some(state) = self.owner_isolation.get_mut(&owner) {
            state.throttle = false;
            state.throttle_reason = StorageIntentRefusalReason::None;
        }
    }

    // ------------------------------------------------------------------
    // Evidence emission
    // ------------------------------------------------------------------

    fn emit_evidence(
        &mut self,
        request: &AdmissionRequest,
        decision: &AdmissionDecision,
        confidence: SchedulingConfidenceClass,
        speculative_drop_reason: Option<StorageIntentRefusalReason>,
    ) {
        if self.evidence_log.len() >= Self::MAX_EVIDENCE_LOG {
            self.evidence_log.remove(0);
        }

        let required_evidence = self.collect_required_evidence_kinds(request);
        let mut missing_kinds = [StorageIntentEvidenceKind::Unknown; MAX_REQUIRED_EVIDENCE_KINDS];
        let mut missing_count: u8 = 0;
        let mut missing_evidence_overflow = required_evidence.overflow;
        let mut index = 0;
        while index < required_evidence.count as usize {
            let kind = required_evidence.kinds[index];
            if (!self.has_bound_evidence_kind(request, kind)
                || self.blocking_freshness_for_kind(kind).is_some())
                && !push_required_evidence_kind(&mut missing_kinds, &mut missing_count, kind)
            {
                missing_evidence_overflow = true;
            }
            index += 1;
        }

        let evidence = SchedulingEvidence {
            observed_tick: self.current_tick,
            decision: decision.clone(),
            action_class: request.action_class,
            work_class: request.work_class,
            confidence,
            throttle_or_refusal_reason: decision.refusal,
            allocator_pressure_reason: if self.caps.allocator_pressure_pct > 70 {
                Some(StorageIntentRefusalReason::EvidenceNotUsable)
            } else {
                None
            },
            speculative_drop_reason,
            starvation_override: decision.starvation_override,
            reserve_protected: decision.reserve_protected,
            budget_class: decision.budget_class,
            policy_id: self.active_policy_id,
            policy_revision: self.active_policy_revision,
            available_evidence: request.evidence_refs,
            missing_evidence_kinds: missing_kinds,
            missing_evidence_count: missing_count,
            missing_evidence_overflow,
        };

        self.evidence_log.push(evidence);
    }

    /// Drain and return all pending evidence, clearing the log.
    pub fn drain_evidence(&mut self) -> Vec<SchedulingEvidence> {
        let drained: Vec<SchedulingEvidence> = self.evidence_log.drain(..).collect();
        drained
    }

    /// Return a snapshot of evidence without draining.
    #[must_use]
    pub fn evidence_snapshot(&self) -> &[SchedulingEvidence] {
        &self.evidence_log
    }
}

impl Default for StorageIntentScheduler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scheduler() -> StorageIntentScheduler {
        StorageIntentScheduler::new()
    }

    fn enable_background_budget(scheduler: &mut StorageIntentScheduler) {
        scheduler.caps.background_optimizer_budget_bytes = 1024 * 1024;
    }

    fn foreground_read_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::ForegroundIo,
            StorageIntentActionClass::ReadSourceRefresh,
            StorageIntentBudgetOwnerId::ZERO,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        )
    }

    fn speculative_prefetch_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::SpeculativePrefetch,
            StorageIntentActionClass::QueuePrefetchTuning,
            StorageIntentBudgetOwnerId::ZERO,
            65536,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        )
    }

    fn background_defrag_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::BackgroundOptimizer,
            StorageIntentActionClass::DefragRepack,
            StorageIntentBudgetOwnerId::ZERO,
            1048576,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::FullPlacement,
        )
    }

    fn repair_escalation_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::RepairEscalation,
            StorageIntentActionClass::ReadTriggeredRepair,
            StorageIntentBudgetOwnerId::ZERO,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::QuorumIntent,
        )
    }

    fn metadata_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::MetadataStorm,
            StorageIntentActionClass::DegradedReadReconstruction,
            StorageIntentBudgetOwnerId::ZERO,
            0,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        )
    }

    fn sync_barrier_request() -> AdmissionRequest {
        AdmissionRequest::new(
            AdmissionWorkClass::SyncBarrier,
            StorageIntentActionClass::NewWriteShaping,
            StorageIntentBudgetOwnerId::ZERO,
            0,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::QuorumIntent,
        )
    }

    fn policy_id(byte: u8) -> StorageIntentPolicyId {
        StorageIntentPolicyId([byte; 16])
    }

    fn evidence_id(byte: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([byte; 32])
    }

    fn evidence_ref(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, evidence_id(byte), 1, 1)
    }

    fn compiled_prefetch_policy() -> PrefetchResidencyPolicyEnvelope {
        PrefetchResidencyPolicyEnvelope {
            policy_id: policy_id(7),
            policy_revision: StorageIntentPolicyRevision(3),
            policy_scope: PrefetchResidencyPolicyScope::Dataset,
            allowed_actions: PrefetchResidencyActionMask::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead,
            )
            .with(PrefetchResidencyCandidateClass::CacheOnlyTrial),
            max_prefetch_window_bytes: 4096,
            max_staging_bytes: 8192,
            ..PrefetchResidencyPolicyEnvelope::default()
        }
    }

    // ── Lane mapping tests ──

    #[test]
    fn foreground_io_maps_to_demand_lane() {
        let req = foreground_read_request();
        assert_eq!(req.work_class.lane_class(), LaneClass::Demand);
    }

    #[test]
    fn speculative_prefetch_maps_to_speculative_lane() {
        let req = speculative_prefetch_request();
        assert_eq!(req.work_class.lane_class(), LaneClass::Speculative);
    }

    #[test]
    fn background_defrag_maps_to_background_lane() {
        let req = background_defrag_request();
        assert_eq!(req.work_class.lane_class(), LaneClass::Background);
    }

    #[test]
    fn repair_escalation_maps_to_control_lane() {
        let req = repair_escalation_request();
        assert_eq!(req.work_class.lane_class(), LaneClass::Control);
    }

    #[test]
    fn sync_barrier_maps_to_metadata_lane() {
        let req = sync_barrier_request();
        assert_eq!(req.work_class.lane_class(), LaneClass::Metadata);
    }

    #[test]
    fn authority_promotion_maps_to_demand_lane() {
        let req = AdmissionRequest::new(
            AdmissionWorkClass::AuthorityPromotion,
            StorageIntentActionClass::AuthorityPromotion,
            StorageIntentBudgetOwnerId::ZERO,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::FullPlacement,
        );
        assert_eq!(req.work_class.lane_class(), LaneClass::Demand);
        assert_eq!(req.resolved_lane(), LaneClass::Demand);
    }

    #[test]
    fn action_lane_prevents_authority_demoting_to_speculative() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 100;
        s.caps.inflight_bytes = 90;
        s.caps.foreground_latency_budget_us = 1;

        let req = AdmissionRequest::new(
            AdmissionWorkClass::SpeculativePrefetch,
            StorageIntentActionClass::AuthorityPromotion,
            StorageIntentBudgetOwnerId::ZERO,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::FullPlacement,
        );

        let decision = s.admit(&req);
        assert_eq!(decision.lane, LaneClass::Demand);
        assert_ne!(decision.outcome, AdmissionOutcome::Dropped);
    }

    #[test]
    fn lane_mapping_covers_all_action_classes() {
        let all_actions = [
            StorageIntentActionClass::QueuePrefetchTuning,
            StorageIntentActionClass::CacheOnlyServingTrial,
            StorageIntentActionClass::NewWriteShaping,
            StorageIntentActionClass::FlashServingPromotion,
            StorageIntentActionClass::AuthorityPromotion,
            StorageIntentActionClass::DurablePlacementMovement,
            StorageIntentActionClass::ReadSourceRefresh,
            StorageIntentActionClass::DegradedReadReconstruction,
            StorageIntentActionClass::ReadTriggeredRepair,
            StorageIntentActionClass::DefragRepack,
            StorageIntentActionClass::ReclaimRelocation,
            StorageIntentActionClass::GeoCatchup,
            StorageIntentActionClass::ArchiveMigration,
        ];
        for action in &all_actions {
            let lane = action_class_to_lane(*action);
            // Every action must map to a valid lane.
            assert!(
                lane == LaneClass::Control
                    || lane == LaneClass::Metadata
                    || lane == LaneClass::Demand
                    || lane == LaneClass::Speculative
                    || lane == LaneClass::Background
            );
        }
    }

    // ── Compiled policy tests ──

    #[test]
    fn compiled_prefetch_policy_updates_identity_and_caps() {
        let mut s = test_scheduler();
        let policy = compiled_prefetch_policy();

        s.apply_prefetch_residency_policy(&policy, None);

        assert_eq!(s.active_policy_id, policy.policy_id);
        assert_eq!(s.active_policy_revision, policy.policy_revision);
        assert_eq!(
            s.lane_configs
                .get(&LaneClass::Speculative)
                .unwrap()
                .max_inflight_bytes,
            policy.max_prefetch_window_bytes
        );
        assert_eq!(
            s.lane_configs
                .get(&LaneClass::Background)
                .unwrap()
                .max_inflight_bytes,
            policy.max_staging_bytes
        );
    }

    #[test]
    fn compiled_policy_refuses_disallowed_prefetch_actions() {
        let mut s = test_scheduler();
        let mut policy = compiled_prefetch_policy();
        policy.allowed_actions = PrefetchResidencyActionMask::from_candidate(
            PrefetchResidencyCandidateClass::NoPrefetch,
        );
        s.apply_prefetch_residency_policy(&policy, None);

        let decision = s.admit(&speculative_prefetch_request());

        assert_eq!(decision.outcome, AdmissionOutcome::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::NoLegalReceiptSet
        );
    }

    #[test]
    fn compiled_policy_flags_add_named_required_evidence() {
        let mut s = test_scheduler();
        let mut policy = compiled_prefetch_policy();
        policy.flags = PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE
            .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE);
        s.apply_prefetch_residency_policy(&policy, None);

        let decision = s.admit(&speculative_prefetch_request());
        let evidence = s.drain_evidence();

        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_eq!(evidence[0].missing_evidence_count, 2);
        assert_eq!(
            evidence[0].missing_evidence_kinds[0],
            StorageIntentEvidenceKind::ServiceObjectiveEvidence
        );
        assert_eq!(
            evidence[0].missing_evidence_kinds[1],
            StorageIntentEvidenceKind::CapacityAdmissionEvidence
        );
    }

    #[test]
    fn compiled_policy_late_required_evidence_is_not_truncated() {
        let mut s = test_scheduler();
        let mut policy = compiled_prefetch_policy();
        policy.max_prefetch_window_bytes = 1024 * 1024;
        policy.flags = PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE
            .union(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
            .union(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION);
        policy.evidence_refs = tidefs_storage_intent_core::PrefetchResidencyDecisionEvidenceRefs {
            service_objective_ref: evidence_ref(
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                21,
            ),
            evidence_query_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 22),
            decision_frontier_ref: evidence_ref(
                StorageIntentEvidenceKind::DecisionFrontierEvidence,
                23,
            ),
            media_capability_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                24,
            ),
            capacity_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                25,
            ),
            tenant_isolation_ref: evidence_ref(
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                26,
            ),
            cost_wear_ref: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 27),
            transport_budget_ref: evidence_ref(
                StorageIntentEvidenceKind::TransportPathEvidence,
                28,
            ),
            trust_domain_ref: evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 29),
            read_serving_boundary_ref: evidence_ref(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                30,
            ),
            relocation_boundary_ref: evidence_ref(StorageIntentEvidenceKind::RelocationReceipt, 31),
            ..Default::default()
        };
        s.apply_prefetch_residency_policy(&policy, None);

        let decision = s.admit(&speculative_prefetch_request());
        let evidence = s.drain_evidence();
        let missing =
            &evidence[0].missing_evidence_kinds[..evidence[0].missing_evidence_count as usize];

        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!evidence[0].missing_evidence_overflow);
        assert!(missing.contains(&StorageIntentEvidenceKind::SchedulerAdmissionRecord));
    }

    #[test]
    fn required_evidence_overflow_refuses_closed() {
        let mut s = test_scheduler();
        let mut req = foreground_read_request();
        req.required_evidence_count = MAX_REQUIRED_EVIDENCE_KINDS as u8 + 1;

        let decision = s.admit(&req);
        let evidence = s.drain_evidence();

        assert_eq!(decision.outcome, AdmissionOutcome::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(evidence[0].missing_evidence_overflow);
    }

    #[test]
    fn bound_required_evidence_degrades_without_query_snapshot() {
        let mut s = test_scheduler();
        let req = foreground_read_request()
            .with_required_evidence_kind(StorageIntentEvidenceKind::OrderingEvidence)
            .with_evidence(evidence_ref(
                StorageIntentEvidenceKind::OrderingEvidence,
                11,
            ));

        let decision = s.admit(&req);
        let evidence = s.drain_evidence();

        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
        assert_eq!(evidence[0].missing_evidence_count, 0);
        assert_eq!(
            evidence[0].confidence,
            SchedulingConfidenceClass::DegradedVisible
        );
    }

    // ── Admission priority tests ──

    #[test]
    fn foreground_read_is_admitted_under_normal_conditions() {
        let mut s = test_scheduler();
        let req = foreground_read_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
        assert_eq!(decision.lane, LaneClass::Demand);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
    }

    #[test]
    fn repair_escalation_is_admitted_under_pressure() {
        let mut s = test_scheduler();
        s.caps.max_dirty_bytes = 1024;
        s.caps.dirty_bytes = 2048; // exceeded
        s.caps.max_inflight_bytes = 0;
        s.caps.inflight_bytes = 1;
        s.caps.max_device_queue_depth = 0;
        s.caps.device_queue_depth = 1;
        s.caps.allocator_pressure_pct = 95;

        let req = repair_escalation_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
        assert_eq!(decision.lane, LaneClass::Control);
    }

    #[test]
    fn sync_barrier_is_admitted_when_allocator_pressure_is_high() {
        let mut s = test_scheduler();
        s.caps.allocator_pressure_pct = 95;
        s.caps.background_optimizer_budget_bytes = 0;

        let req = sync_barrier_request();
        let decision = s.admit(&req);
        // Sync barriers bypass allocator and background caps.
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
        assert_eq!(decision.lane, LaneClass::Metadata);
    }

    #[test]
    fn speculative_prefetch_is_dropped_under_inflight_pressure() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 1024;
        s.caps.inflight_bytes = 2048; // over cap

        let req = speculative_prefetch_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
    }

    #[test]
    fn speculative_prefetch_is_dropped_under_allocator_pressure() {
        let mut s = test_scheduler();
        s.caps.allocator_pressure_pct = 75; // >70 threshold

        let req = speculative_prefetch_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn speculative_prefetch_is_dropped_under_latency_pressure() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 8000; // >70% of max_inflight_bytes
        s.caps.foreground_latency_budget_us = 100;

        let req = speculative_prefetch_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
    }

    #[test]
    fn background_defrag_is_dropped_when_budget_exhausted() {
        let mut s = test_scheduler();
        s.caps.background_optimizer_budget_bytes = 0;

        let req = background_defrag_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::MovementDebtNotPaidBack
        );
    }

    #[test]
    fn background_defrag_is_dropped_under_allocator_pressure() {
        let mut s = test_scheduler();
        s.caps.allocator_pressure_pct = 95;
        s.caps.background_optimizer_budget_bytes = 1024 * 1024;

        let req = background_defrag_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn metadata_is_admitted_when_inflight_is_exceeded() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 1024;
        s.caps.inflight_bytes = 2048;

        let req = metadata_request();
        let decision = s.admit(&req);
        // Metadata is still admitted even when inflight cap is exceeded.
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
        assert_eq!(decision.lane, LaneClass::Metadata);
    }

    #[test]
    fn foreground_read_is_throttled_when_inflight_cap_exceeded() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 1024;
        s.caps.inflight_bytes = 2048;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Throttled);
        assert_eq!(decision.budget_class, BudgetConstraintClass::InflightBytes);
    }

    // ── Tenant isolation tests ──

    #[test]
    fn tenant_isolation_throttles_exceeding_owner() {
        let mut s = test_scheduler();
        let owner = StorageIntentBudgetOwnerId([1; 16]);
        s.throttle_budget_owner(owner, StorageIntentRefusalReason::GuaranteeFloorNotMet);

        let req = AdmissionRequest::new(
            AdmissionWorkClass::ForegroundIo,
            StorageIntentActionClass::ReadSourceRefresh,
            owner,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        );

        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Backpressured);
        assert_eq!(
            decision.budget_class,
            BudgetConstraintClass::TenantIsolation
        );
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::GuaranteeFloorNotMet
        );
    }

    #[test]
    fn zero_budget_owner_bypasses_tenant_isolation() {
        let mut s = test_scheduler();
        let owner = StorageIntentBudgetOwnerId([1; 16]);
        s.throttle_budget_owner(owner, StorageIntentRefusalReason::GuaranteeFloorNotMet);

        // Request with ZERO owner should not be throttled.
        let req = foreground_read_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    // ── Serving-trial expiry tests ──

    #[test]
    fn cache_only_trial_is_expired_under_latency_pressure() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 6000; // >50% of cap
        s.caps.foreground_latency_budget_us = 100;

        let req = AdmissionRequest::new(
            AdmissionWorkClass::CacheOnlyTrial,
            StorageIntentActionClass::CacheOnlyServingTrial,
            StorageIntentBudgetOwnerId::ZERO,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        );

        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Expired);
        assert_eq!(
            decision.budget_class,
            BudgetConstraintClass::ForegroundLatency
        );
    }

    // ── Per-lane inflight cap tests ──

    #[test]
    fn demand_lane_throttles_when_inflight_ops_exceed_cap() {
        let mut s = test_scheduler();
        s.set_lane_config(LaneConfig::demand(256 * 1024 * 1024, 1));
        // Pre-fill inflight ops to 1 so the next request hits the cap.
        s.counters.get_mut(&LaneClass::Demand).unwrap().inflight_ops = 1;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        // Requested 1 op, cap is 1, current 1 → throttled.
        assert_eq!(decision.outcome, AdmissionOutcome::Throttled);
    }

    #[test]
    fn background_lane_is_dropped_when_inflight_bytes_exceed_cap() {
        let mut s = test_scheduler();
        s.set_lane_config(LaneConfig::background(1, u64::MAX));

        let req = background_defrag_request();
        let decision = s.admit(&req);
        // Requested 1 MiB, cap is 1 byte → inflight exceeded → dropped (bg work is droppable).
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
    }

    // ── Accounting tests ──

    #[test]
    fn inflight_accounting_updates_counters() {
        let mut s = test_scheduler();
        s.account_inflight(LaneClass::Demand, 4096, 1, StorageIntentBudgetOwnerId::ZERO);

        let counter = s.counters.get(&LaneClass::Demand).unwrap();
        assert_eq!(counter.inflight_bytes, 4096);
        assert_eq!(counter.inflight_ops, 1);
        assert_eq!(s.caps.inflight_bytes, 4096);
    }

    #[test]
    fn release_inflight_reduces_counters() {
        let mut s = test_scheduler();
        s.account_inflight(LaneClass::Demand, 4096, 1, StorageIntentBudgetOwnerId::ZERO);
        s.release_inflight(LaneClass::Demand, 4096, 1, StorageIntentBudgetOwnerId::ZERO);

        let counter = s.counters.get(&LaneClass::Demand).unwrap();
        assert_eq!(counter.inflight_bytes, 0);
        assert_eq!(counter.inflight_ops, 0);
        assert_eq!(s.caps.inflight_bytes, 0);
    }

    #[test]
    fn per_owner_inflight_is_tracked() {
        let mut s = test_scheduler();
        let owner = StorageIntentBudgetOwnerId([1; 16]);

        s.account_inflight(LaneClass::Demand, 4096, 1, owner);

        let owner_state = s.owner_isolation.get(&owner).unwrap();
        let per_lane = owner_state
            .per_lane_inflight
            .get(&LaneClass::Demand)
            .unwrap();
        assert_eq!(*per_lane, 4096);

        s.release_inflight(LaneClass::Demand, 4096, 1, owner);

        let owner_state = s.owner_isolation.get(&owner).unwrap();
        let per_lane = owner_state
            .per_lane_inflight
            .get(&LaneClass::Demand)
            .unwrap();
        assert_eq!(*per_lane, 0);
    }

    // ── Evidence tests ──

    #[test]
    fn evidence_is_emitted_for_each_decision() {
        let mut s = test_scheduler();
        let req = foreground_read_request();
        s.admit(&req);
        s.admit(&req);

        let evidence = s.drain_evidence();
        assert_eq!(evidence.len(), 2);
        assert_eq!(evidence[0].work_class, AdmissionWorkClass::ForegroundIo);
        assert_eq!(evidence[1].work_class, AdmissionWorkClass::ForegroundIo);
    }

    #[test]
    fn evidence_log_is_bounded() {
        let mut s = test_scheduler();
        for _ in 0..300 {
            let req = foreground_read_request();
            s.admit(&req);
        }
        assert!(s.evidence_log.len() <= StorageIntentScheduler::MAX_EVIDENCE_LOG);
    }

    #[test]
    fn evidence_captures_missing_evidence_kinds() {
        let mut s = test_scheduler();
        let req = foreground_read_request()
            .with_required_evidence_kind(StorageIntentEvidenceKind::OrderingEvidence);
        let decision = s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(decision.outcome, AdmissionOutcome::Refused);
        assert_eq!(evidence[0].confidence, SchedulingConfidenceClass::Unknown);
        assert_eq!(evidence[0].missing_evidence_count, 1);
        assert_eq!(
            evidence[0].missing_evidence_kinds[0],
            StorageIntentEvidenceKind::OrderingEvidence
        );
    }

    #[test]
    fn evidence_does_not_report_unused_slots_as_missing() {
        let mut s = test_scheduler();
        let req = foreground_read_request();
        s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(evidence[0].missing_evidence_count, 0);
    }

    #[test]
    fn evidence_captures_budget_class() {
        let mut s = test_scheduler();
        s.caps.background_optimizer_budget_bytes = 0;

        let req = background_defrag_request();
        s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(
            evidence[0].budget_class,
            BudgetConstraintClass::BackgroundOptimizer
        );
    }

    #[test]
    fn evidence_distinguishes_allocator_and_inflight_pressure() {
        let mut s = test_scheduler();
        s.caps.allocator_pressure_pct = 95;

        let req = background_defrag_request();
        s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(
            evidence[0].budget_class,
            BudgetConstraintClass::AllocatorPressure
        );

        s.caps.allocator_pressure_pct = 0;
        s.caps.max_inflight_bytes = 1024;
        s.caps.inflight_bytes = 2048;

        let req = foreground_read_request();
        s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(
            evidence[0].budget_class,
            BudgetConstraintClass::InflightBytes
        );
    }

    // ── Starvation override tests ──

    #[test]
    fn starvation_timeout_triggers_override() {
        let mut s = test_scheduler();
        // Give enough background budget so hard caps don't block admission.
        enable_background_budget(&mut s);
        // Set background lane config with 1-tick starvation timeout.
        s.set_lane_config(LaneConfig {
            lane_class: LaneClass::Background,
            max_inflight_bytes: u64::MAX,
            max_inflight_ops: u64::MAX,
            starvation_timeout_ms: 1,
            preemptible: true,
            droppable: true,
            resumable: true,
            pressure_throttle_order: 0,
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        });

        // Set last_service_tick far in the past (must be > 0 for starvation check).
        s.counters
            .get_mut(&LaneClass::Background)
            .unwrap()
            .last_service_tick = 1;
        s.current_tick = 10;

        let req = background_defrag_request();
        let decision = s.admit(&req);
        assert!(decision.starvation_override);
    }

    // -- Dispatch queue tests --

    #[test]
    fn dispatch_queue_orders_by_unified_lane_priority() {
        let mut s = test_scheduler();
        enable_background_budget(&mut s);
        let mut queue = StorageIntentDispatchQueue::new();

        let background = background_defrag_request();
        let background_decision = s.admit(&background);
        assert_eq!(background_decision.outcome, AdmissionOutcome::Admitted);
        queue
            .enqueue_dispatchable(
                background,
                background_decision,
                "background",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap();

        let demand = foreground_read_request();
        let demand_decision = s.admit(&demand);
        assert_eq!(demand_decision.outcome, AdmissionOutcome::Admitted);
        queue
            .enqueue_dispatchable(
                demand,
                demand_decision,
                "demand",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap();

        let metadata = metadata_request();
        let metadata_decision = s.admit(&metadata);
        assert_eq!(metadata_decision.outcome, AdmissionOutcome::Admitted);
        queue
            .enqueue_dispatchable(
                metadata,
                metadata_decision,
                "metadata",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap();

        let control = repair_escalation_request();
        let control_decision = s.admit(&control);
        assert_eq!(control_decision.outcome, AdmissionOutcome::Admitted);
        queue
            .enqueue_dispatchable(
                control,
                control_decision,
                "control",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap();

        assert_eq!(queue.len(), 4);
        let _ = s.drain_evidence();

        let first = queue.dispatch_next_at(&mut s, 100).unwrap();
        assert_eq!(first.item, "control");
        assert_eq!(first.lane, LaneClass::Control);

        let second = queue.dispatch_next_at(&mut s, 101).unwrap();
        assert_eq!(second.item, "metadata");
        assert_eq!(second.lane, LaneClass::Metadata);

        let third = queue.dispatch_next_at(&mut s, 102).unwrap();
        assert_eq!(third.item, "demand");
        assert_eq!(third.lane, LaneClass::Demand);

        let fourth = queue.dispatch_next_at(&mut s, 103).unwrap();
        assert_eq!(fourth.item, "background");
        assert_eq!(fourth.lane, LaneClass::Background);
        assert!(queue.is_empty());
    }

    #[test]
    fn dispatch_queue_starvation_override_runs_starved_background_first() {
        let mut s = test_scheduler();
        enable_background_budget(&mut s);
        s.set_lane_config(LaneConfig {
            lane_class: LaneClass::Background,
            max_inflight_bytes: u64::MAX,
            max_inflight_ops: u64::MAX,
            starvation_timeout_ms: 1,
            preemptible: true,
            droppable: true,
            resumable: true,
            pressure_throttle_order: 0,
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        });

        let mut queue = StorageIntentDispatchQueue::new();
        let background = background_defrag_request();
        let background_decision = s.admit(&background);
        queue
            .enqueue_dispatchable(
                background,
                background_decision,
                "background",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap();

        let demand = foreground_read_request();
        let demand_decision = s.admit(&demand);
        queue
            .enqueue_dispatchable(
                demand,
                demand_decision,
                "demand",
                2_000,
                SchedulingConfidenceClass::High,
            )
            .unwrap();
        let _ = s.drain_evidence();

        let dispatch = queue.dispatch_next_at(&mut s, 2_500).unwrap();
        assert_eq!(dispatch.item, "background");
        assert_eq!(dispatch.lane, LaneClass::Background);
        assert_eq!(dispatch.queue_time_us, 2_500);
        assert!(dispatch.starvation_override);
        assert!(dispatch.decision.starvation_override);

        let evidence = s.drain_evidence();
        assert_eq!(evidence[0].decision.queue_time_us, 2_500);
        assert!(evidence[0].starvation_override);
        assert_eq!(evidence[0].decision.lane, LaneClass::Background);
    }

    #[test]
    fn dispatch_queue_rejects_visible_drop_state() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 1024;
        s.caps.inflight_bytes = 2048;
        let mut queue = StorageIntentDispatchQueue::new();

        let request = speculative_prefetch_request();
        let decision = s.admit(&request);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);

        let error = queue
            .enqueue_dispatchable(
                request,
                decision,
                "prefetch",
                0,
                SchedulingConfidenceClass::High,
            )
            .unwrap_err();
        assert_eq!(
            error,
            DispatchQueueAdmissionError::NotDispatchable {
                outcome: AdmissionOutcome::Dropped,
                refusal: StorageIntentRefusalReason::GuaranteeFloorNotMet,
            }
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn dispatch_queue_accounts_inflight_by_budget_owner() {
        let mut s = test_scheduler();
        let owner = StorageIntentBudgetOwnerId([3; 16]);
        let request = AdmissionRequest::new(
            AdmissionWorkClass::ForegroundIo,
            StorageIntentActionClass::ReadSourceRefresh,
            owner,
            4096,
            2,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        );
        let decision = s.admit(&request);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);

        let mut queue = StorageIntentDispatchQueue::new();
        queue
            .enqueue_dispatchable(
                request,
                decision,
                "foreground",
                10,
                SchedulingConfidenceClass::High,
            )
            .unwrap();
        let _ = s.drain_evidence();

        let dispatch = queue.dispatch_next_at(&mut s, 15).unwrap();
        assert_eq!(dispatch.item, "foreground");
        assert_eq!(dispatch.queue_time_us, 5);

        let counter = s.counters.get(&LaneClass::Demand).unwrap();
        assert_eq!(counter.inflight_bytes, 4096);
        assert_eq!(counter.inflight_ops, 2);
        assert_eq!(s.caps.inflight_bytes, 4096);

        let owner_state = s.owner_isolation.get(&owner).unwrap();
        assert_eq!(
            *owner_state
                .per_lane_inflight
                .get(&LaneClass::Demand)
                .unwrap(),
            4096
        );
    }

    // ── Drop/resume semantics tests ──

    #[test]
    fn speculative_prefetch_can_be_dropped_not_resumed() {
        assert!(AdmissionWorkClass::SpeculativePrefetch.can_be_dropped());
        assert!(!AdmissionWorkClass::SpeculativePrefetch.can_be_resumed());
    }

    #[test]
    fn background_optimizer_can_be_dropped_and_resumed() {
        assert!(AdmissionWorkClass::BackgroundOptimizer.can_be_dropped());
        assert!(AdmissionWorkClass::BackgroundOptimizer.can_be_resumed());
    }

    #[test]
    fn foreground_io_cannot_be_dropped() {
        assert!(!AdmissionWorkClass::ForegroundIo.can_be_dropped());
    }

    #[test]
    fn repair_escalation_cannot_be_dropped() {
        assert!(!AdmissionWorkClass::RepairEscalation.can_be_dropped());
    }

    // ── Policy identity tracking ──

    #[test]
    fn set_active_policy_updates_identity() {
        let mut s = test_scheduler();
        let pid = StorageIntentPolicyId([0xAB; 16]);
        let rev = StorageIntentPolicyRevision(42);
        s.set_active_policy(pid, rev);

        let req = foreground_read_request();
        s.admit(&req);
        let evidence = s.drain_evidence();
        assert_eq!(evidence[0].policy_id, pid);
        assert_eq!(evidence[0].policy_revision, rev);
    }

    // ── Budget cap helper tests ──

    #[test]
    fn budget_caps_detect_dirty_bytes_exceeded() {
        let caps = StorageIntentBudgetCaps {
            max_dirty_bytes: 100,
            dirty_bytes: 200,
            ..Default::default()
        };
        assert!(caps.any_cap_exceeded());
        assert_eq!(
            caps.backpressure_reason(),
            Some(StorageIntentRefusalReason::GuaranteeFloorNotMet)
        );
    }

    #[test]
    fn budget_caps_detect_inflight_exceeded() {
        let caps = StorageIntentBudgetCaps {
            max_inflight_bytes: 100,
            inflight_bytes: 200,
            ..Default::default()
        };
        assert!(caps.any_cap_exceeded());
    }

    #[test]
    fn budget_caps_detect_allocator_pressure() {
        let caps = StorageIntentBudgetCaps {
            allocator_pressure_pct: 95,
            ..Default::default()
        };
        assert!(caps.any_cap_exceeded());
    }

    #[test]
    fn budget_caps_detect_background_budget_exhausted() {
        let caps = StorageIntentBudgetCaps {
            background_optimizer_budget_bytes: 0,
            ..Default::default()
        };
        assert!(caps.any_cap_exceeded());
    }

    #[test]
    fn budget_caps_normal_state_is_ok() {
        let caps = StorageIntentBudgetCaps {
            max_dirty_bytes: 1024 * 1024,
            dirty_bytes: 0,
            max_inflight_bytes: 1024 * 1024,
            inflight_bytes: 0,
            max_transport_window_bytes: 1024 * 1024,
            transport_window_bytes: 0,
            max_device_queue_depth: 32,
            device_queue_depth: 0,
            allocator_pressure_pct: 10,
            foreground_latency_budget_us: 1000,
            background_optimizer_budget_bytes: 1024 * 1024,
        };
        assert!(!caps.any_cap_exceeded());
        assert_eq!(caps.backpressure_reason(), None);
    }

    // ── Mixed workload simulation ──

    #[test]
    fn foreground_p99_protected_under_mixed_workload() {
        let mut s = test_scheduler();
        // Set up moderate pressure.
        s.caps.max_inflight_bytes = 1024 * 1024;
        s.caps.inflight_bytes = 800 * 1024; // ~78% full
        s.caps.foreground_latency_budget_us = 500;

        // Background work should be dropped (it is droppable under pressure).
        let bg = background_defrag_request();
        let bg_decision = s.admit(&bg);
        assert_eq!(bg_decision.outcome, AdmissionOutcome::Dropped);

        // Speculative prefetch should be dropped.
        let sp = speculative_prefetch_request();
        let sp_decision = s.admit(&sp);
        assert_eq!(sp_decision.outcome, AdmissionOutcome::Dropped);

        // Foreground read should still be admitted (or throttled, not dropped).
        let fg = foreground_read_request();
        let fg_decision = s.admit(&fg);
        assert!(fg_decision.outcome != AdmissionOutcome::Dropped);
        assert!(fg_decision.outcome != AdmissionOutcome::Refused);
    }

    #[test]
    fn repair_escalation_always_admitted_under_mixed_pressure() {
        let mut s = test_scheduler();
        s.caps.max_dirty_bytes = 100;
        s.caps.dirty_bytes = 200;
        s.caps.max_inflight_bytes = 100;
        s.caps.inflight_bytes = 200;
        s.caps.max_device_queue_depth = 0;
        s.caps.device_queue_depth = 1;
        s.caps.allocator_pressure_pct = 99;

        let repair = repair_escalation_request();
        let decision = s.admit(&repair);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    // ── Throughput-heavy workload cannot destroy another's p99 ──

    #[test]
    fn tenant_isolation_protects_one_workloads_p99_from_another() {
        let mut s = test_scheduler();
        let heavy_owner = StorageIntentBudgetOwnerId([1; 16]);
        let lat_owner = StorageIntentBudgetOwnerId([2; 16]);

        // Throttle the heavy owner.
        s.throttle_budget_owner(
            heavy_owner,
            StorageIntentRefusalReason::GuaranteeFloorNotMet,
        );

        // Heavy owner gets backpressured.
        let heavy_req = AdmissionRequest::new(
            AdmissionWorkClass::BulkIngest,
            StorageIntentActionClass::NewWriteShaping,
            heavy_owner,
            1048576,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        );
        let heavy_decision = s.admit(&heavy_req);
        assert_eq!(heavy_decision.outcome, AdmissionOutcome::Backpressured);

        // Latency-sensitive owner is admitted normally.
        let lat_req = AdmissionRequest::new(
            AdmissionWorkClass::VmRandomIo,
            StorageIntentActionClass::ReadSourceRefresh,
            lat_owner,
            4096,
            1,
            StorageIntentPolicyId::ZERO,
            StorageIntentPolicyRevision(0),
            StorageIntentGuaranteeClass::VolatileLocal,
        );
        let lat_decision = s.admit(&lat_req);
        assert_eq!(lat_decision.outcome, AdmissionOutcome::Admitted);
    }

    // ── Transport window enforcement tests ──

    #[test]
    fn transport_window_exceeded_throttles_demand() {
        let mut s = test_scheduler();
        s.caps.max_transport_window_bytes = 1024;
        s.caps.transport_window_bytes = 2048;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        // Demand lane is not droppable, not Background, not Control/Metadata
        // → throttled under hard-cap pressure.
        assert_eq!(decision.outcome, AdmissionOutcome::Throttled);
        assert_eq!(
            decision.budget_class,
            BudgetConstraintClass::TransportWindow
        );
    }

    #[test]
    fn transport_window_exceeded_drops_speculative() {
        let mut s = test_scheduler();
        s.caps.max_transport_window_bytes = 1024;
        s.caps.transport_window_bytes = 2048;

        let req = speculative_prefetch_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
        assert_eq!(
            decision.budget_class,
            BudgetConstraintClass::TransportWindow
        );
    }

    #[test]
    fn transport_window_exceeded_metadata_still_admitted() {
        let mut s = test_scheduler();
        s.caps.max_transport_window_bytes = 1024;
        s.caps.transport_window_bytes = 2048;

        let req = metadata_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    #[test]
    fn transport_window_zero_means_unlimited() {
        let mut s = test_scheduler();
        s.caps.max_transport_window_bytes = 0;
        s.caps.transport_window_bytes = 999_999_999;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        // Cap is zero → unlimited, so no backpressure.
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    // ── Foreground latency budget enforcement tests ──

    #[test]
    fn foreground_latency_budget_throttles_demand_under_inflight_pressure() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 8000; // >70% of cap
        s.caps.foreground_latency_budget_us = 100;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        // Demand lane throttled (not dropped, not backpressured) under
        // hard-cap pressure.
        assert_eq!(decision.outcome, AdmissionOutcome::Throttled);
        assert_eq!(
            decision.budget_class,
            BudgetConstraintClass::ForegroundLatency
        );
    }

    #[test]
    fn foreground_latency_budget_drops_background_under_pressure() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 8000;
        s.caps.foreground_latency_budget_us = 100;
        s.caps.background_optimizer_budget_bytes = 1024 * 1024;

        let req = background_defrag_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Dropped);
    }

    #[test]
    fn foreground_latency_budget_not_enforced_below_threshold() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 5000; // 50% of cap, below 70% threshold
        s.caps.foreground_latency_budget_us = 100;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        // Below threshold, should be admitted normally.
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    #[test]
    fn foreground_latency_zero_means_not_enforced() {
        let mut s = test_scheduler();
        s.caps.max_inflight_bytes = 10000;
        s.caps.inflight_bytes = 9000;
        s.caps.foreground_latency_budget_us = 0;

        let req = foreground_read_request();
        let decision = s.admit(&req);
        assert_eq!(decision.outcome, AdmissionOutcome::Admitted);
    }

    // ── Updated budget caps tests ──

    #[test]
    fn budget_caps_normal_state_includes_transport_window() {
        let caps = StorageIntentBudgetCaps {
            max_dirty_bytes: 1024 * 1024,
            dirty_bytes: 0,
            max_inflight_bytes: 1024 * 1024,
            inflight_bytes: 0,
            max_transport_window_bytes: 1024 * 1024,
            transport_window_bytes: 0,
            max_device_queue_depth: 32,
            device_queue_depth: 0,
            allocator_pressure_pct: 10,
            foreground_latency_budget_us: 1000,
            background_optimizer_budget_bytes: 1024 * 1024,
        };
        assert!(!caps.any_cap_exceeded());
        assert_eq!(caps.backpressure_reason(), None);
    }

    #[test]
    fn budget_caps_detect_transport_window_exceeded() {
        let caps = StorageIntentBudgetCaps {
            max_transport_window_bytes: 100,
            transport_window_bytes: 200,
            ..Default::default()
        };
        assert!(caps.any_cap_exceeded());
        assert_eq!(
            caps.backpressure_reason(),
            Some(StorageIntentRefusalReason::GuaranteeFloorNotMet)
        );
    }
}
