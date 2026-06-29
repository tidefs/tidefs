// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Closed-loop prefetch and residency feedback records (#975).
//!
//! This crate consumes #972 prefetch executor outcome records and #912
//! measurement-attribution evidence to produce conservative, per-dataset
//! learning summaries. It can lower confidence, shorten windows, cool down,
//! refuse, or emit demotion/payback candidates. It does not execute prefetch,
//! move bytes, spend flash lifetime, publish replacement receipts, retire
//! sources, change authority, render operator UAPI, or support public
//! comparator claims by itself.

use core::fmt;

use tidefs_storage_intent_core::{
    AccessPatternClass, EvidenceQuerySubjectScopeClass, PredictionConfidence,
    PrefetchResidencyCandidateClass, PrefetchResidencyStateClass, StorageIntentActionClass,
    StorageIntentDomainId, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceRef, StorageIntentMeasurementAttributionEvidence,
    StorageIntentMeasurementAttributionUseMask, StorageIntentMeasurementAttributionVerdict,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
    StorageIntentRefusalReason, StorageMediaClass,
};
use tidefs_storage_intent_prefetch_executor::{
    PrefetchExecutorActionFamily, PrefetchExecutorAdmissionOutcome, PrefetchExecutorAntiWasteMask,
    PrefetchExecutorByteState, PrefetchExecutorOutcome, PrefetchExecutorPressureMask,
    PrefetchExecutorRecord, PrefetchExecutorResultDetail,
};

macro_rules! impl_u8_canonical {
    ($ty:ident, { $($variant:ident = $value:literal => $name:literal),+ $(,)? }) => {
        impl $ty {
            /// Stable diagnostic spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            /// Encode to a stable discriminant.
            #[must_use]
            pub const fn to_discriminant(self) -> u8 {
                self as u8
            }

            /// Decode from a stable discriminant. Unknown values fail closed.
            #[must_use]
            pub const fn from_discriminant(raw: u8) -> Option<Self> {
                match raw {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

/// Version of the feedback model surface.
pub const STORAGE_INTENT_PREFETCH_FEEDBACK_VERSION: u16 = 1;

/// Stable identifier for feedback records and tests.
pub const STORAGE_INTENT_PREFETCH_FEEDBACK_SPEC: &str =
    "tidefs-storage-intent-prefetch-feedback-v1-issue-975";

/// Maximum number of records reduced into one model-only learning checkpoint.
pub const PREFETCH_FEEDBACK_LEARNING_WINDOW_MAX_RECORDS: usize = 16;

/// Minimum repeated positive records before a window can stay confidence-positive.
pub const PREFETCH_FEEDBACK_SUSTAINED_MIN_POSITIVE_RECORDS: u16 = 2;

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

/// Concrete or forward executor outcome state consumed by feedback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackExecutorOutcomeState {
    /// No executor outcome has been supplied.
    #[default]
    Unavailable = 0,
    /// A concrete #972 outcome record is present.
    Present = 1,
    /// The executor outcome is older than the policy, scope, or decision cut.
    Stale = 2,
    /// Scheduler, pressure, or evidence blocked execution.
    Blocked = 3,
    /// Policy, cost, wear, or evidence refused execution.
    Refused = 4,
}

impl_u8_canonical!(PrefetchFeedbackExecutorOutcomeState, {
    Unavailable = 0 => "unavailable",
    Present = 1 => "present",
    Stale = 2 => "stale",
    Blocked = 3 => "blocked",
    Refused = 4 => "refused",
});

/// Conservative attribution state used by feedback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackAttributionState {
    /// No attribution verdict is available.
    #[default]
    Unavailable = 0,
    /// The measurement is attributable for the exact envelope.
    Attributable = 1,
    /// Attribution is bounded but still authority-eligible when the core mask permits it.
    PartiallyAttributableWithBounds = 2,
    /// The measurement is confounded by another producer, comparator, or baseline.
    Confounded = 3,
    /// The sample mass or retained metric set is too small.
    InsufficientSample = 4,
    /// The attribution verdict is stale.
    Stale = 5,
    /// The measurement contradicts the decision or workload envelope.
    Contradicted = 6,
    /// The result is shadow-only and diagnostic.
    ShadowOnly = 7,
    /// The attribution authority refused the record.
    Refused = 8,
}

impl_u8_canonical!(PrefetchFeedbackAttributionState, {
    Unavailable = 0 => "unavailable",
    Attributable = 1 => "attributable",
    PartiallyAttributableWithBounds = 2 => "partially-attributable-with-bounds",
    Confounded = 3 => "confounded",
    InsufficientSample = 4 => "insufficient-sample",
    Stale = 5 => "stale",
    Contradicted = 6 => "contradicted",
    ShadowOnly = 7 => "shadow-only",
    Refused = 8 => "refused",
});

impl PrefetchFeedbackAttributionState {
    /// Convert the core #912 verdict into feedback state.
    #[must_use]
    pub const fn from_verdict(verdict: StorageIntentMeasurementAttributionVerdict) -> Self {
        match verdict {
            StorageIntentMeasurementAttributionVerdict::Unknown => Self::Unavailable,
            StorageIntentMeasurementAttributionVerdict::Attributable => Self::Attributable,
            StorageIntentMeasurementAttributionVerdict::PartiallyAttributableWithBounds => {
                Self::PartiallyAttributableWithBounds
            }
            StorageIntentMeasurementAttributionVerdict::Confounded => Self::Confounded,
            StorageIntentMeasurementAttributionVerdict::InsufficientSample => {
                Self::InsufficientSample
            }
            StorageIntentMeasurementAttributionVerdict::Stale => Self::Stale,
            StorageIntentMeasurementAttributionVerdict::Contradicted => Self::Contradicted,
            StorageIntentMeasurementAttributionVerdict::ShadowOnly => Self::ShadowOnly,
            StorageIntentMeasurementAttributionVerdict::Refused => Self::Refused,
        }
    }

    /// Returns true when the state may diagnose or lower but not train authority up.
    #[must_use]
    pub const fn blocks_upward_learning(self) -> bool {
        matches!(
            self,
            Self::Unavailable
                | Self::Confounded
                | Self::InsufficientSample
                | Self::Stale
                | Self::Contradicted
                | Self::ShadowOnly
                | Self::Refused
        )
    }
}

/// Retention/proof-root state for feedback materialization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackRetentionState {
    /// No #910 proof root is available.
    #[default]
    Unavailable = 0,
    /// Exact proof root is retained for the feedback envelope.
    ProofRoot = 1,
    /// Evidence was summarized past authority use.
    Compacted = 2,
    /// Evidence was redacted past authority use.
    Redacted = 3,
    /// Evidence may be purged and cannot support durable claims.
    Purgeable = 4,
    /// Retention authority refused the evidence.
    Refused = 5,
}

impl_u8_canonical!(PrefetchFeedbackRetentionState, {
    Unavailable = 0 => "unavailable",
    ProofRoot = 1 => "proof-root",
    Compacted = 2 => "compacted",
    Redacted = 3 => "redacted",
    Purgeable = 4 => "purgeable",
    Refused = 5 => "refused",
});

impl PrefetchFeedbackRetentionState {
    /// Returns true when this retention state can support payback and claim gates.
    #[must_use]
    pub const fn has_authority_proof_root(self) -> bool {
        matches!(self, Self::ProofRoot)
    }
}

/// Scheduler/admission state consumed by feedback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackSchedulerState {
    /// No scheduler lane is known.
    #[default]
    UnknownLane = 0,
    /// Scheduler/admission evidence is present.
    Present = 1,
    /// Scheduler evidence is unavailable.
    Unavailable = 2,
    /// Scheduler blocked the action.
    Blocked = 3,
    /// Scheduler refused the action.
    Refused = 4,
}

impl_u8_canonical!(PrefetchFeedbackSchedulerState, {
    UnknownLane = 0 => "unknown-lane",
    Present = 1 => "present",
    Unavailable = 2 => "unavailable",
    Blocked = 3 => "blocked",
    Refused = 4 => "refused",
});

/// Materialization-cost state for feedback summaries, checkpoints, and telemetry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackMaterializationCostState {
    /// Feedback collection cost is unknown and must be treated conservatively.
    #[default]
    UnknownConservative = 0,
    /// Feedback collection/materialization was charged to the policy cost basis.
    KnownCharged = 1,
    /// Materialization was over budget.
    OverBudget = 2,
    /// Cost or wear authority refused materialization.
    Refused = 3,
}

impl_u8_canonical!(PrefetchFeedbackMaterializationCostState, {
    UnknownConservative = 0 => "unknown-conservative",
    KnownCharged = 1 => "known-charged",
    OverBudget = 2 => "over-budget",
    Refused = 3 => "refused",
});

/// Feedback verdict emitted for the measured action family.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackVerdict {
    /// Evidence is not yet usable.
    #[default]
    InsufficientSample = 0,
    Beneficial = 1,
    Neutral = 2,
    Wasteful = 3,
    OverBudget = 4,
    HarmfulToForeground = 5,
    Contradicted = 6,
    PhaseChanged = 7,
    OnePassScan = 8,
    WrongDatasetPolicy = 9,
    WrongMediaTopology = 10,
    StaleEvidence = 11,
    MissingCostWear = 12,
    ComparatorConfounded = 13,
    ShadowOnly = 14,
    Refused = 15,
}

impl_u8_canonical!(PrefetchFeedbackVerdict, {
    InsufficientSample = 0 => "insufficient-sample",
    Beneficial = 1 => "beneficial",
    Neutral = 2 => "neutral",
    Wasteful = 3 => "wasteful",
    OverBudget = 4 => "over-budget",
    HarmfulToForeground = 5 => "harmful-to-foreground",
    Contradicted = 6 => "contradicted",
    PhaseChanged = 7 => "phase-changed",
    OnePassScan = 8 => "one-pass-scan",
    WrongDatasetPolicy = 9 => "wrong-dataset-policy",
    WrongMediaTopology = 10 => "wrong-media-topology",
    StaleEvidence = 11 => "stale-evidence",
    MissingCostWear = 12 => "missing-cost-wear",
    ComparatorConfounded = 13 => "comparator-confounded",
    ShadowOnly = 14 => "shadow-only",
    Refused = 15 => "refused",
});

impl PrefetchFeedbackVerdict {
    /// Returns true when the verdict is weak or negative for future action classes.
    #[must_use]
    pub const fn is_weak_or_negative(self) -> bool {
        !matches!(self, Self::Beneficial | Self::Neutral)
    }
}

/// Bounded confidence update emitted by feedback.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackConfidenceUpdate {
    /// Confidence is unchanged.
    #[default]
    None = 0,
    /// Confidence may be lowered one bounded step.
    LowerOneStep = 1,
    /// Confidence must not rise above the previous value.
    CapAtCurrent = 2,
    /// Confidence may rise one bounded step.
    RaiseOneStep = 3,
    /// Confidence update is refused.
    Refused = 4,
}

impl_u8_canonical!(PrefetchFeedbackConfidenceUpdate, {
    None = 0 => "none",
    LowerOneStep = 1 => "lower-one-step",
    CapAtCurrent = 2 => "cap-at-current",
    RaiseOneStep = 3 => "raise-one-step",
    Refused = 4 => "refused",
});

/// Action adjustments that feedback may suggest to future decision authorities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackAdjustmentMask(pub u64);

impl PrefetchFeedbackAdjustmentMask {
    pub const EMPTY: Self = Self(0);
    pub const LOWER_ACTION_CLASS: Self = Self(1_u64 << 0);
    pub const SHORTEN_WINDOW: Self = Self(1_u64 << 1);
    pub const DEMOTION_CANDIDATE: Self = Self(1_u64 << 2);
    pub const EXTEND_DWELL: Self = Self(1_u64 << 3);
    pub const COOLDOWN: Self = Self(1_u64 << 4);
    pub const EXPLICIT_NO_PREFETCH: Self = Self(1_u64 << 5);
    pub const TYPED_REFUSAL: Self = Self(1_u64 << 6);
    pub const PAYBACK_CANDIDATE: Self = Self(1_u64 << 7);
    pub const PROMOTION_CANDIDATE: Self = Self(1_u64 << 8);
    pub const MOVEMENT_DEBT_CANDIDATE: Self = Self(1_u64 << 9);
    pub const NEED_MORE_EVIDENCE: Self = Self(1_u64 << 10);

    /// Add another adjustment bitset.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all bits from `other` are present.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true when any bit from `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Dataset and envelope key for one learned feedback cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackScopeKey {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub budget_owner: StorageIntentDomainId,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub subject: StorageIntentObjectScope,
    pub access_pattern: AccessPatternClass,
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_path_ref: StorageIntentEvidenceRef,
    pub target_destination_ref: StorageIntentEvidenceRef,
    pub action_class: StorageIntentActionClass,
    pub action_family: PrefetchExecutorActionFamily,
    pub observation_window_ms: u64,
}

impl Default for PrefetchFeedbackScopeKey {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            budget_owner: StorageIntentDomainId::ZERO,
            service_objective_ref: EMPTY_EVIDENCE_REF,
            subject: StorageIntentObjectScope::default(),
            access_pattern: AccessPatternClass::Unknown,
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_path_ref: EMPTY_EVIDENCE_REF,
            target_destination_ref: EMPTY_EVIDENCE_REF,
            action_class: StorageIntentActionClass::QueuePrefetchTuning,
            action_family: PrefetchExecutorActionFamily::Unknown,
            observation_window_ms: 0,
        }
    }
}

impl PrefetchFeedbackScopeKey {
    /// Build a feedback key from one executor outcome and an explicit objective/window.
    #[must_use]
    pub const fn from_executor(
        executor: PrefetchExecutorRecord,
        service_objective_ref: StorageIntentEvidenceRef,
        observation_window_ms: u64,
    ) -> Self {
        Self {
            policy_id: executor.policy_id,
            policy_revision: executor.policy_revision,
            budget_owner: executor.budget_owner,
            service_objective_ref,
            subject: executor.subject,
            access_pattern: executor.access_pattern,
            source_media: executor.source_media,
            target_media: executor.target_media,
            source_path_ref: executor.source_path_ref,
            target_destination_ref: executor.target_destination_ref,
            action_class: executor.action_class,
            action_family: executor.action_family,
            observation_window_ms,
        }
    }

    /// Returns true when all minimum dataset-scope dimensions are bound.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        !self.policy_id.is_zero()
            && self.policy_revision.0 > 0
            && !self.budget_owner.is_zero()
            && !self.subject.dataset_id.is_zero()
            && self.subject.range_len > 0
            && self.service_objective_ref.is_bound()
            && self.observation_window_ms > 0
    }

    /// Returns true when this key still matches an executor record.
    #[must_use]
    pub fn matches_executor(self, executor: PrefetchExecutorRecord) -> bool {
        self.policy_id.0 == executor.policy_id.0
            && self.policy_revision.0 == executor.policy_revision.0
            && self.budget_owner.0 == executor.budget_owner.0
            && self.subject.dataset_id.0 == executor.subject.dataset_id.0
            && self.subject.object_id.0 == executor.subject.object_id.0
            && self.subject.range_start == executor.subject.range_start
            && self.subject.range_len == executor.subject.range_len
            && self.subject.generation == executor.subject.generation
            && self.access_pattern as u8 == executor.access_pattern as u8
            && self.source_media as u8 == executor.source_media as u8
            && self.target_media as u8 == executor.target_media as u8
            && evidence_ref_equal(self.source_path_ref, executor.source_path_ref)
            && evidence_ref_equal(self.target_destination_ref, executor.target_destination_ref)
            && self.action_class as u8 == executor.action_class as u8
            && self.action_family as u8 == executor.action_family as u8
    }

    /// Returns true when attribution names the same dataset policy and range cohort.
    #[must_use]
    pub fn matches_attribution_scope(
        self,
        attribution: StorageIntentMeasurementAttributionEvidence,
    ) -> bool {
        self.policy_id.0 == attribution.policy_id.0
            && self.policy_revision.0 == attribution.policy_revision.0
            && self.budget_owner.0 == attribution.budget_owner_id.0
            && attribution.subject.scope_class as u8
                == EvidenceQuerySubjectScopeClass::ObjectRange as u8
            && self.subject.dataset_id.0 == attribution.subject.object_scope.dataset_id.0
            && self.subject.object_id.0 == attribution.subject.object_scope.object_id.0
            && self.subject.range_start == attribution.subject.object_scope.range_start
            && self.subject.range_len == attribution.subject.object_scope.range_len
            && self.subject.generation == attribution.subject.object_scope.generation
            && self.service_objective_ref.is_bound()
            && evidence_ref_equal(
                self.service_objective_ref,
                attribution.service_objective_ref,
            )
            && attribution.sample_window.sample_window_ms == self.observation_window_ms
    }
}

/// Payback, cost, pressure, and retained measurement counters for one action.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackPaybackEvidence {
    pub bytes_prefetched: u64,
    pub bytes_used: u64,
    pub bytes_unused: u64,
    pub bytes_expired: u64,
    pub latency_avoided_us: u64,
    pub latency_harm_us: u64,
    pub foreground_p50_disruption_us: u64,
    pub foreground_p95_disruption_us: u64,
    pub foreground_p99_disruption_us: u64,
    pub queue_delay_us: u64,
    pub flash_write_bytes: u64,
    pub pmem_write_bytes: u64,
    pub waf_micros: u64,
    pub ram_pressure_bytes: u64,
    pub cache_index_write_bytes: u64,
    pub predictor_metadata_write_bytes: u64,
    pub wan_bytes: u64,
    pub egress_cost_microunits: u64,
    pub restore_cost_microunits: u64,
    pub staging_capacity_bytes: u64,
    pub cpu_us: u64,
    pub memory_bytes: u64,
    pub protected_reserve_pressure: bool,
}

impl PrefetchFeedbackPaybackEvidence {
    /// Copy counters from the executor result detail.
    #[must_use]
    pub const fn from_result_detail(detail: PrefetchExecutorResultDetail) -> Self {
        Self {
            bytes_prefetched: detail.prefetched_bytes,
            bytes_used: detail.used_bytes,
            bytes_unused: detail.unused_bytes,
            bytes_expired: detail.expired_bytes,
            latency_avoided_us: detail.latency_benefit_us,
            latency_harm_us: detail.latency_harm_us,
            foreground_p50_disruption_us: detail.foreground_p50_disruption_us,
            foreground_p95_disruption_us: detail.foreground_p95_disruption_us,
            foreground_p99_disruption_us: detail.foreground_p99_disruption_us,
            queue_delay_us: detail.queue_delay_us,
            flash_write_bytes: detail.flash_write_bytes,
            pmem_write_bytes: detail.pmem_write_bytes,
            waf_micros: detail.waf_micros,
            ram_pressure_bytes: detail.ram_pressure_bytes,
            cache_index_write_bytes: detail.cache_index_write_bytes,
            predictor_metadata_write_bytes: detail.predictor_metadata_write_bytes,
            wan_bytes: detail.wan_bytes,
            egress_cost_microunits: detail.egress_cost_microunits,
            restore_cost_microunits: detail.restore_cost_microunits,
            staging_capacity_bytes: detail.staging_capacity_bytes,
            cpu_us: detail.cpu_us,
            memory_bytes: detail.memory_bytes,
            protected_reserve_pressure: detail.protected_reserve_pressure,
        }
    }

    /// Returns true when usage counters are present.
    #[must_use]
    pub const fn has_usage(self) -> bool {
        self.bytes_prefetched != 0
            || self.bytes_used != 0
            || self.bytes_unused != 0
            || self.bytes_expired != 0
    }

    /// Returns true when latency/tail counters are present.
    #[must_use]
    pub const fn has_latency(self) -> bool {
        self.latency_avoided_us != 0
            || self.latency_harm_us != 0
            || self.foreground_p50_disruption_us != 0
            || self.foreground_p95_disruption_us != 0
            || self.foreground_p99_disruption_us != 0
            || self.queue_delay_us != 0
    }

    /// Returns true when cost, wear, memory, network, or reserve counters are present.
    #[must_use]
    pub const fn has_cost_or_pressure(self) -> bool {
        self.flash_write_bytes != 0
            || self.pmem_write_bytes != 0
            || self.waf_micros != 0
            || self.ram_pressure_bytes != 0
            || self.cache_index_write_bytes != 0
            || self.predictor_metadata_write_bytes != 0
            || self.wan_bytes != 0
            || self.egress_cost_microunits != 0
            || self.restore_cost_microunits != 0
            || self.staging_capacity_bytes != 0
            || self.cpu_us != 0
            || self.memory_bytes != 0
            || self.protected_reserve_pressure
    }

    /// Returns true when the counters show plausible payback.
    #[must_use]
    pub const fn looks_beneficial(self) -> bool {
        self.bytes_used > 0
            && self.bytes_used >= self.bytes_unused.saturating_add(self.bytes_expired)
            && self.latency_avoided_us > self.latency_harm_us
            && self.latency_avoided_us > self.foreground_p99_disruption_us
    }

    /// Returns true when bytes were mostly unused or expired.
    #[must_use]
    pub const fn looks_wasteful(self) -> bool {
        (self.bytes_prefetched > 0 && self.bytes_used == 0)
            || self.bytes_unused.saturating_add(self.bytes_expired) > self.bytes_used
    }

    /// Returns true when foreground harm exceeds the claimed benefit.
    #[must_use]
    pub const fn harms_foreground(self) -> bool {
        self.latency_harm_us > self.latency_avoided_us
            || self.foreground_p99_disruption_us > self.latency_avoided_us
    }

    /// Saturating counter addition for bounded learning-window summaries.
    #[must_use]
    pub const fn saturating_add(self, other: Self) -> Self {
        Self {
            bytes_prefetched: self.bytes_prefetched.saturating_add(other.bytes_prefetched),
            bytes_used: self.bytes_used.saturating_add(other.bytes_used),
            bytes_unused: self.bytes_unused.saturating_add(other.bytes_unused),
            bytes_expired: self.bytes_expired.saturating_add(other.bytes_expired),
            latency_avoided_us: self
                .latency_avoided_us
                .saturating_add(other.latency_avoided_us),
            latency_harm_us: self.latency_harm_us.saturating_add(other.latency_harm_us),
            foreground_p50_disruption_us: self
                .foreground_p50_disruption_us
                .saturating_add(other.foreground_p50_disruption_us),
            foreground_p95_disruption_us: self
                .foreground_p95_disruption_us
                .saturating_add(other.foreground_p95_disruption_us),
            foreground_p99_disruption_us: self
                .foreground_p99_disruption_us
                .saturating_add(other.foreground_p99_disruption_us),
            queue_delay_us: self.queue_delay_us.saturating_add(other.queue_delay_us),
            flash_write_bytes: self
                .flash_write_bytes
                .saturating_add(other.flash_write_bytes),
            pmem_write_bytes: self.pmem_write_bytes.saturating_add(other.pmem_write_bytes),
            waf_micros: self.waf_micros.saturating_add(other.waf_micros),
            ram_pressure_bytes: self
                .ram_pressure_bytes
                .saturating_add(other.ram_pressure_bytes),
            cache_index_write_bytes: self
                .cache_index_write_bytes
                .saturating_add(other.cache_index_write_bytes),
            predictor_metadata_write_bytes: self
                .predictor_metadata_write_bytes
                .saturating_add(other.predictor_metadata_write_bytes),
            wan_bytes: self.wan_bytes.saturating_add(other.wan_bytes),
            egress_cost_microunits: self
                .egress_cost_microunits
                .saturating_add(other.egress_cost_microunits),
            restore_cost_microunits: self
                .restore_cost_microunits
                .saturating_add(other.restore_cost_microunits),
            staging_capacity_bytes: self
                .staging_capacity_bytes
                .saturating_add(other.staging_capacity_bytes),
            cpu_us: self.cpu_us.saturating_add(other.cpu_us),
            memory_bytes: self.memory_bytes.saturating_add(other.memory_bytes),
            protected_reserve_pressure: self.protected_reserve_pressure
                || other.protected_reserve_pressure,
        }
    }
}

/// Evidence references retained by the feedback record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackEvidenceRefs {
    pub executor_outcome_ref: StorageIntentEvidenceRef,
    pub attribution_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub cost_wear_ref: StorageIntentEvidenceRef,
    pub egress_restore_cost_ref: StorageIntentEvidenceRef,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub source_path_ref: StorageIntentEvidenceRef,
    pub target_destination_ref: StorageIntentEvidenceRef,
    pub transport_path_ref: StorageIntentEvidenceRef,
    pub comparator_ref: StorageIntentEvidenceRef,
    pub allowed_use_ref: StorageIntentEvidenceRef,
}

/// Input consumed by the feedback reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackInput {
    pub executor: PrefetchExecutorRecord,
    pub executor_outcome_ref: StorageIntentEvidenceRef,
    pub attribution: StorageIntentMeasurementAttributionEvidence,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub observation_window_ms: u64,
    pub executor_state: PrefetchFeedbackExecutorOutcomeState,
    pub attribution_state: PrefetchFeedbackAttributionState,
    pub retention_state: PrefetchFeedbackRetentionState,
    pub scheduler_state: PrefetchFeedbackSchedulerState,
    pub materialization_cost_state: PrefetchFeedbackMaterializationCostState,
}

impl Default for PrefetchFeedbackInput {
    fn default() -> Self {
        Self {
            executor: PrefetchExecutorRecord::default(),
            executor_outcome_ref: EMPTY_EVIDENCE_REF,
            attribution: StorageIntentMeasurementAttributionEvidence::default(),
            service_objective_ref: EMPTY_EVIDENCE_REF,
            observation_window_ms: 0,
            executor_state: PrefetchFeedbackExecutorOutcomeState::Unavailable,
            attribution_state: PrefetchFeedbackAttributionState::Unavailable,
            retention_state: PrefetchFeedbackRetentionState::Unavailable,
            scheduler_state: PrefetchFeedbackSchedulerState::UnknownLane,
            materialization_cost_state:
                PrefetchFeedbackMaterializationCostState::UnknownConservative,
        }
    }
}

/// Conservative feedback record emitted for #845/#967/#848 consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackRecord {
    pub version: u16,
    pub scope: PrefetchFeedbackScopeKey,
    pub executor_outcome: PrefetchExecutorOutcome,
    pub executor_byte_state: PrefetchExecutorByteState,
    pub verdict: PrefetchFeedbackVerdict,
    pub executor_state: PrefetchFeedbackExecutorOutcomeState,
    pub attribution_state: PrefetchFeedbackAttributionState,
    pub retention_state: PrefetchFeedbackRetentionState,
    pub scheduler_state: PrefetchFeedbackSchedulerState,
    pub materialization_cost_state: PrefetchFeedbackMaterializationCostState,
    pub payback: PrefetchFeedbackPaybackEvidence,
    pub previous_confidence: PredictionConfidence,
    pub next_confidence: PredictionConfidence,
    pub confidence_update: PrefetchFeedbackConfidenceUpdate,
    pub next_action_class: StorageIntentActionClass,
    pub next_candidate: PrefetchResidencyCandidateClass,
    pub next_residency: PrefetchResidencyStateClass,
    pub next_prefetch_window_bytes: u64,
    pub next_staging_bytes: u64,
    pub dwell_extension_ms: u64,
    pub cooldown_ms: u64,
    pub adjustments: PrefetchFeedbackAdjustmentMask,
    pub allowed_uses: StorageIntentMeasurementAttributionUseMask,
    pub refusal: StorageIntentRefusalReason,
    pub evidence_refs: PrefetchFeedbackEvidenceRefs,
}

impl Default for PrefetchFeedbackRecord {
    fn default() -> Self {
        Self {
            version: STORAGE_INTENT_PREFETCH_FEEDBACK_VERSION,
            scope: PrefetchFeedbackScopeKey::default(),
            executor_outcome: PrefetchExecutorOutcome::Unknown,
            executor_byte_state: PrefetchExecutorByteState::Unknown,
            verdict: PrefetchFeedbackVerdict::InsufficientSample,
            executor_state: PrefetchFeedbackExecutorOutcomeState::Unavailable,
            attribution_state: PrefetchFeedbackAttributionState::Unavailable,
            retention_state: PrefetchFeedbackRetentionState::Unavailable,
            scheduler_state: PrefetchFeedbackSchedulerState::UnknownLane,
            materialization_cost_state:
                PrefetchFeedbackMaterializationCostState::UnknownConservative,
            payback: PrefetchFeedbackPaybackEvidence::default(),
            previous_confidence: PredictionConfidence::Unknown,
            next_confidence: PredictionConfidence::Unknown,
            confidence_update: PrefetchFeedbackConfidenceUpdate::None,
            next_action_class: StorageIntentActionClass::QueuePrefetchTuning,
            next_candidate: PrefetchResidencyCandidateClass::NeedMoreEvidence,
            next_residency: PrefetchResidencyStateClass::Unknown,
            next_prefetch_window_bytes: 0,
            next_staging_bytes: 0,
            dwell_extension_ms: 0,
            cooldown_ms: 0,
            adjustments: PrefetchFeedbackAdjustmentMask::EMPTY,
            allowed_uses: StorageIntentMeasurementAttributionUseMask::EMPTY,
            refusal: StorageIntentRefusalReason::None,
            evidence_refs: PrefetchFeedbackEvidenceRefs::default(),
        }
    }
}

impl PrefetchFeedbackRecord {
    /// Returns true when #845 may raise confidence one bounded step.
    #[must_use]
    pub const fn may_train_confidence_upward(self) -> bool {
        matches!(
            self.confidence_update,
            PrefetchFeedbackConfidenceUpdate::RaiseOneStep
        ) && self
            .allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD)
    }

    /// Returns true when feedback may close payback for the exact envelope.
    #[must_use]
    pub const fn may_close_payback(self) -> bool {
        self.allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK)
    }

    /// Returns true when a movement-debt or promotion candidate may be handed to #848.
    #[must_use]
    pub const fn may_emit_movement_candidate(self) -> bool {
        self.adjustments.intersects(
            PrefetchFeedbackAdjustmentMask::PROMOTION_CANDIDATE
                .union(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE)
                .union(PrefetchFeedbackAdjustmentMask::MOVEMENT_DEBT_CANDIDATE),
        )
    }

    /// Feedback records never publish replacement receipts.
    #[must_use]
    pub const fn can_publish_replacement_receipt(self) -> bool {
        false
    }

    /// Feedback records never retire source receipts.
    #[must_use]
    pub const fn can_retire_source_receipt(self) -> bool {
        false
    }

    /// Feedback records do not spend budget by themselves.
    #[must_use]
    pub const fn can_spend_extra_flash_movement_budget(self) -> bool {
        false
    }

    /// Returns true when a later budget authority may inspect a flash-budget candidate.
    #[must_use]
    pub const fn may_request_flash_budget_candidate(self) -> bool {
        self.allowed_uses.contains_all(
            StorageIntentMeasurementAttributionUseMask::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET,
        )
    }

    /// Returns true only when comparator/claim use was authorized by #912 and #910 proof exists.
    #[must_use]
    pub const fn may_support_public_or_comparator_claim(self) -> bool {
        self.allowed_uses.contains_all(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM,
        ) && self.retention_state.has_authority_proof_root()
    }
}

/// Sustained learning-window state for a checkpoint summary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackLearningWindowState {
    /// No records were reduced.
    #[default]
    Empty = 0,
    /// The window is scoped but does not have enough repeated evidence.
    NeedMoreEvidence = 1,
    /// Repeated positive records in one exact envelope can keep confidence raised.
    SustainedPositiveBounded = 2,
    /// The window must cool down before future authority-positive use.
    Cooldown = 3,
    /// The window should prefer demotion or no-prefetch candidates.
    Demotion = 4,
    /// The window was reset by stale, mismatched, or unusable evidence.
    Reset = 5,
    /// The window is refused as authority-positive evidence.
    Refused = 6,
}

impl_u8_canonical!(PrefetchFeedbackLearningWindowState, {
    Empty = 0 => "empty",
    NeedMoreEvidence = 1 => "need-more-evidence",
    SustainedPositiveBounded = 2 => "sustained-positive-bounded",
    Cooldown = 3 => "cooldown",
    Demotion = 4 => "demotion",
    Reset = 5 => "reset",
    Refused = 6 => "refused",
});

/// Typed reason a learning window cannot stay authority-positive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchFeedbackLearningRefusal {
    /// The window is not refused.
    #[default]
    None = 0,
    UnboundScope = 1,
    SinglePositiveRecord = 2,
    LowSample = 3,
    NeutralRecord = 4,
    MismatchedScope = 5,
    MismatchedEvidenceEnvelope = 6,
    StaleEvidence = 7,
    WrongDatasetPolicy = 8,
    WrongMediaTopology = 9,
    MissingRetentionEvidence = 10,
    MissingCostWear = 11,
    UnknownMaterializationCost = 12,
    ComparatorConfounded = 13,
    ShadowOnly = 14,
    RefusedRecord = 15,
    OnePassScan = 16,
    PhaseChanged = 17,
    Wasteful = 18,
    OverBudget = 19,
    ForegroundHarm = 20,
    Contradicted = 21,
    NonAuthorityRecord = 22,
    SchedulerNotPresent = 23,
    ExecutorNotPresent = 24,
}

impl_u8_canonical!(PrefetchFeedbackLearningRefusal, {
    None = 0 => "none",
    UnboundScope = 1 => "unbound-scope",
    SinglePositiveRecord = 2 => "single-positive-record",
    LowSample = 3 => "low-sample",
    NeutralRecord = 4 => "neutral-record",
    MismatchedScope = 5 => "mismatched-scope",
    MismatchedEvidenceEnvelope = 6 => "mismatched-evidence-envelope",
    StaleEvidence = 7 => "stale-evidence",
    WrongDatasetPolicy = 8 => "wrong-dataset-policy",
    WrongMediaTopology = 9 => "wrong-media-topology",
    MissingRetentionEvidence = 10 => "missing-retention-evidence",
    MissingCostWear = 11 => "missing-cost-wear",
    UnknownMaterializationCost = 12 => "unknown-materialization-cost",
    ComparatorConfounded = 13 => "comparator-confounded",
    ShadowOnly = 14 => "shadow-only",
    RefusedRecord = 15 => "refused-record",
    OnePassScan = 16 => "one-pass-scan",
    PhaseChanged = 17 => "phase-changed",
    Wasteful = 18 => "wasteful",
    OverBudget = 19 => "over-budget",
    ForegroundHarm = 20 => "foreground-harm",
    Contradicted = 21 => "contradicted",
    NonAuthorityRecord = 22 => "non-authority-record",
    SchedulerNotPresent = 23 => "scheduler-not-present",
    ExecutorNotPresent = 24 => "executor-not-present",
});

/// Evidence envelope that must stay identical across a sustained-positive window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackLearningEnvelope {
    pub scope: PrefetchFeedbackScopeKey,
    pub executor_state: PrefetchFeedbackExecutorOutcomeState,
    pub attribution_state: PrefetchFeedbackAttributionState,
    pub retention_state: PrefetchFeedbackRetentionState,
    pub scheduler_state: PrefetchFeedbackSchedulerState,
    pub materialization_cost_state: PrefetchFeedbackMaterializationCostState,
    pub evidence_refs: PrefetchFeedbackEvidenceRefs,
}

impl PrefetchFeedbackLearningEnvelope {
    /// Build the comparable evidence envelope from a feedback record.
    #[must_use]
    pub const fn from_record(record: PrefetchFeedbackRecord) -> Self {
        Self {
            scope: record.scope,
            executor_state: record.executor_state,
            attribution_state: record.attribution_state,
            retention_state: record.retention_state,
            scheduler_state: record.scheduler_state,
            materialization_cost_state: record.materialization_cost_state,
            evidence_refs: record.evidence_refs,
        }
    }

    /// Returns true when this record has the required positive authority refs bound.
    #[must_use]
    pub const fn has_authority_positive_refs(self) -> bool {
        self.evidence_refs.executor_outcome_ref.is_bound()
            && self.evidence_refs.attribution_ref.is_bound()
            && self.evidence_refs.retention_ref.is_bound()
            && self.evidence_refs.service_objective_ref.is_bound()
            && self.evidence_refs.evidence_query_snapshot_ref.is_bound()
            && self.evidence_refs.decision_frontier_ref.is_bound()
            && self.evidence_refs.scheduler_admission_ref.is_bound()
            && self.evidence_refs.cost_wear_ref.is_bound()
            && self.evidence_refs.source_media_ref.is_bound()
            && self.evidence_refs.target_media_ref.is_bound()
            && self.evidence_refs.source_path_ref.is_bound()
            && self.evidence_refs.target_destination_ref.is_bound()
            && self.evidence_refs.transport_path_ref.is_bound()
            && self.evidence_refs.allowed_use_ref.is_bound()
    }

    /// Returns true when a record is in the same sustained-feedback envelope.
    #[must_use]
    pub fn matches_record(self, record: PrefetchFeedbackRecord) -> bool {
        let other = Self::from_record(record);
        self.scope == other.scope
            && self.executor_state == other.executor_state
            && self.attribution_state == other.attribution_state
            && self.retention_state == other.retention_state
            && self.scheduler_state == other.scheduler_state
            && self.materialization_cost_state == other.materialization_cost_state
            && learning_evidence_refs_match(self.evidence_refs, other.evidence_refs)
    }
}

/// Bounded checkpoint emitted by the learning-window reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchFeedbackLearningCheckpoint {
    pub version: u16,
    pub state: PrefetchFeedbackLearningWindowState,
    pub refusal_state: PrefetchFeedbackLearningRefusal,
    pub refusal: StorageIntentRefusalReason,
    pub scope: PrefetchFeedbackScopeKey,
    pub envelope: PrefetchFeedbackLearningEnvelope,
    pub records_seen: u16,
    pub matched_records: u16,
    pub beneficial_records: u16,
    pub conservative_records: u16,
    pub payback: PrefetchFeedbackPaybackEvidence,
    pub previous_confidence: PredictionConfidence,
    pub next_confidence: PredictionConfidence,
    pub confidence_update: PrefetchFeedbackConfidenceUpdate,
    pub adjustments: PrefetchFeedbackAdjustmentMask,
    pub allowed_uses: StorageIntentMeasurementAttributionUseMask,
    pub cooldown_ms: u64,
    pub dwell_extension_ms: u64,
}

impl Default for PrefetchFeedbackLearningCheckpoint {
    fn default() -> Self {
        Self {
            version: STORAGE_INTENT_PREFETCH_FEEDBACK_VERSION,
            state: PrefetchFeedbackLearningWindowState::Empty,
            refusal_state: PrefetchFeedbackLearningRefusal::None,
            refusal: StorageIntentRefusalReason::None,
            scope: PrefetchFeedbackScopeKey::default(),
            envelope: PrefetchFeedbackLearningEnvelope::default(),
            records_seen: 0,
            matched_records: 0,
            beneficial_records: 0,
            conservative_records: 0,
            payback: PrefetchFeedbackPaybackEvidence::default(),
            previous_confidence: PredictionConfidence::Unknown,
            next_confidence: PredictionConfidence::Unknown,
            confidence_update: PrefetchFeedbackConfidenceUpdate::None,
            adjustments: PrefetchFeedbackAdjustmentMask::EMPTY,
            allowed_uses: StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE,
            cooldown_ms: 0,
            dwell_extension_ms: 0,
        }
    }
}

impl PrefetchFeedbackLearningCheckpoint {
    /// Returns true when repeated evidence can keep confidence raised.
    #[must_use]
    pub const fn may_keep_confidence_raised(self) -> bool {
        matches!(
            self.state,
            PrefetchFeedbackLearningWindowState::SustainedPositiveBounded
        ) && self
            .allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD)
    }

    /// Returns true when repeated evidence can close payback for this exact envelope.
    #[must_use]
    pub const fn may_close_payback(self) -> bool {
        matches!(
            self.state,
            PrefetchFeedbackLearningWindowState::SustainedPositiveBounded
        ) && self
            .allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK)
    }

    /// Learning checkpoints never publish replacement receipts.
    #[must_use]
    pub const fn can_publish_replacement_receipt(self) -> bool {
        false
    }

    /// Learning checkpoints never retire source receipts.
    #[must_use]
    pub const fn can_retire_source_receipt(self) -> bool {
        false
    }

    /// Learning checkpoints do not spend flash movement budget by themselves.
    #[must_use]
    pub const fn can_spend_extra_flash_movement_budget(self) -> bool {
        false
    }

    /// Learning checkpoints cannot support public or comparator claims by themselves.
    #[must_use]
    pub const fn may_support_public_or_comparator_claim(self) -> bool {
        false
    }
}

/// Reduce feedback records into a bounded model-only learning checkpoint.
#[must_use]
pub fn reduce_prefetch_feedback_learning_window(
    records: &[PrefetchFeedbackRecord],
) -> PrefetchFeedbackLearningCheckpoint {
    let mut checkpoint = PrefetchFeedbackLearningCheckpoint::default();
    if records.is_empty() {
        return checkpoint;
    }

    for (index, record) in records
        .iter()
        .take(PREFETCH_FEEDBACK_LEARNING_WINDOW_MAX_RECORDS)
        .copied()
        .enumerate()
    {
        checkpoint.records_seen = saturating_inc_u16(checkpoint.records_seen);
        checkpoint.payback = checkpoint.payback.saturating_add(record.payback);
        checkpoint.previous_confidence =
            max_confidence(checkpoint.previous_confidence, record.previous_confidence);
        checkpoint.next_confidence =
            max_confidence(checkpoint.next_confidence, record.next_confidence);

        if index == 0 {
            checkpoint.scope = record.scope;
            checkpoint.envelope = PrefetchFeedbackLearningEnvelope::from_record(record);
        } else if record.scope != checkpoint.scope {
            return finish_conservative_learning_window(
                checkpoint,
                record,
                PrefetchFeedbackLearningRefusal::MismatchedScope,
            );
        }

        checkpoint.matched_records = saturating_inc_u16(checkpoint.matched_records);
        let refusal = learning_refusal_for_record(record);
        if !matches!(refusal, PrefetchFeedbackLearningRefusal::None) {
            return finish_conservative_learning_window(checkpoint, record, refusal);
        }

        if index > 0 && !checkpoint.envelope.matches_record(record) {
            return finish_conservative_learning_window(
                checkpoint,
                record,
                PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope,
            );
        }

        checkpoint.beneficial_records = saturating_inc_u16(checkpoint.beneficial_records);
    }

    if checkpoint.beneficial_records >= PREFETCH_FEEDBACK_SUSTAINED_MIN_POSITIVE_RECORDS {
        return finish_sustained_positive_learning_window(checkpoint);
    }

    finish_need_more_learning_evidence(
        checkpoint,
        PrefetchFeedbackLearningRefusal::SinglePositiveRecord,
    )
}

fn finish_sustained_positive_learning_window(
    mut checkpoint: PrefetchFeedbackLearningCheckpoint,
) -> PrefetchFeedbackLearningCheckpoint {
    checkpoint.state = PrefetchFeedbackLearningWindowState::SustainedPositiveBounded;
    checkpoint.refusal_state = PrefetchFeedbackLearningRefusal::None;
    checkpoint.refusal = StorageIntentRefusalReason::None;
    checkpoint.confidence_update = PrefetchFeedbackConfidenceUpdate::CapAtCurrent;
    checkpoint.adjustments = PrefetchFeedbackAdjustmentMask::PAYBACK_CANDIDATE;
    checkpoint.allowed_uses = sustained_learning_allowed_uses();
    checkpoint.cooldown_ms = 0;
    checkpoint.dwell_extension_ms = 0;
    checkpoint
}

fn finish_need_more_learning_evidence(
    mut checkpoint: PrefetchFeedbackLearningCheckpoint,
    refusal: PrefetchFeedbackLearningRefusal,
) -> PrefetchFeedbackLearningCheckpoint {
    checkpoint.state = PrefetchFeedbackLearningWindowState::NeedMoreEvidence;
    checkpoint.refusal_state = refusal;
    checkpoint.refusal = StorageIntentRefusalReason::None;
    checkpoint.confidence_update = PrefetchFeedbackConfidenceUpdate::None;
    checkpoint.next_confidence = checkpoint.previous_confidence;
    checkpoint.adjustments = PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE;
    checkpoint.allowed_uses = StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE;
    checkpoint
}

fn finish_conservative_learning_window(
    mut checkpoint: PrefetchFeedbackLearningCheckpoint,
    record: PrefetchFeedbackRecord,
    refusal: PrefetchFeedbackLearningRefusal,
) -> PrefetchFeedbackLearningCheckpoint {
    checkpoint.conservative_records = saturating_inc_u16(checkpoint.conservative_records);
    checkpoint.state = state_for_learning_refusal(refusal);
    checkpoint.refusal_state = refusal;
    checkpoint.refusal = if record.refusal != StorageIntentRefusalReason::None {
        record.refusal
    } else {
        refusal_reason_for_learning(refusal)
    };
    checkpoint.allowed_uses = StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE;
    checkpoint.confidence_update = confidence_update_for_learning_refusal(refusal);
    checkpoint.next_confidence =
        apply_confidence_update(checkpoint.previous_confidence, checkpoint.confidence_update);
    checkpoint.adjustments = record
        .adjustments
        .union(adjustments_for_learning_refusal(refusal));
    checkpoint.cooldown_ms = record.cooldown_ms;
    if checkpoint
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::COOLDOWN)
        && checkpoint.cooldown_ms == 0
    {
        checkpoint.cooldown_ms = 1;
    }
    checkpoint.dwell_extension_ms = record.dwell_extension_ms;
    checkpoint
}

fn learning_refusal_for_record(record: PrefetchFeedbackRecord) -> PrefetchFeedbackLearningRefusal {
    if !record.scope.is_bound() {
        return PrefetchFeedbackLearningRefusal::UnboundScope;
    }
    if !matches!(
        record.executor_state,
        PrefetchFeedbackExecutorOutcomeState::Present
    ) {
        return match record.executor_state {
            PrefetchFeedbackExecutorOutcomeState::Stale => {
                PrefetchFeedbackLearningRefusal::StaleEvidence
            }
            PrefetchFeedbackExecutorOutcomeState::Unavailable => {
                PrefetchFeedbackLearningRefusal::ExecutorNotPresent
            }
            PrefetchFeedbackExecutorOutcomeState::Blocked
            | PrefetchFeedbackExecutorOutcomeState::Refused => {
                PrefetchFeedbackLearningRefusal::RefusedRecord
            }
            PrefetchFeedbackExecutorOutcomeState::Present => PrefetchFeedbackLearningRefusal::None,
        };
    }
    if !matches!(
        record.scheduler_state,
        PrefetchFeedbackSchedulerState::Present
    ) {
        return PrefetchFeedbackLearningRefusal::SchedulerNotPresent;
    }
    if !record.retention_state.has_authority_proof_root() {
        return PrefetchFeedbackLearningRefusal::MissingRetentionEvidence;
    }
    match record.materialization_cost_state {
        PrefetchFeedbackMaterializationCostState::UnknownConservative => {
            return PrefetchFeedbackLearningRefusal::UnknownMaterializationCost;
        }
        PrefetchFeedbackMaterializationCostState::OverBudget => {
            return PrefetchFeedbackLearningRefusal::OverBudget;
        }
        PrefetchFeedbackMaterializationCostState::Refused => {
            return PrefetchFeedbackLearningRefusal::MissingCostWear;
        }
        PrefetchFeedbackMaterializationCostState::KnownCharged => {}
    }
    match record.attribution_state {
        PrefetchFeedbackAttributionState::Unavailable
        | PrefetchFeedbackAttributionState::InsufficientSample => {
            return PrefetchFeedbackLearningRefusal::LowSample;
        }
        PrefetchFeedbackAttributionState::Confounded => {
            return PrefetchFeedbackLearningRefusal::ComparatorConfounded;
        }
        PrefetchFeedbackAttributionState::Stale => {
            return PrefetchFeedbackLearningRefusal::StaleEvidence;
        }
        PrefetchFeedbackAttributionState::Contradicted => {
            return PrefetchFeedbackLearningRefusal::Contradicted;
        }
        PrefetchFeedbackAttributionState::ShadowOnly => {
            return PrefetchFeedbackLearningRefusal::ShadowOnly;
        }
        PrefetchFeedbackAttributionState::Refused => {
            return PrefetchFeedbackLearningRefusal::RefusedRecord;
        }
        PrefetchFeedbackAttributionState::Attributable
        | PrefetchFeedbackAttributionState::PartiallyAttributableWithBounds => {}
    }
    match record.verdict {
        PrefetchFeedbackVerdict::Beneficial => {}
        PrefetchFeedbackVerdict::Neutral => {
            return PrefetchFeedbackLearningRefusal::NeutralRecord;
        }
        PrefetchFeedbackVerdict::InsufficientSample => {
            return PrefetchFeedbackLearningRefusal::LowSample;
        }
        PrefetchFeedbackVerdict::Wasteful => {
            return PrefetchFeedbackLearningRefusal::Wasteful;
        }
        PrefetchFeedbackVerdict::OverBudget => {
            return PrefetchFeedbackLearningRefusal::OverBudget;
        }
        PrefetchFeedbackVerdict::HarmfulToForeground => {
            return PrefetchFeedbackLearningRefusal::ForegroundHarm;
        }
        PrefetchFeedbackVerdict::Contradicted => {
            return PrefetchFeedbackLearningRefusal::Contradicted;
        }
        PrefetchFeedbackVerdict::PhaseChanged => {
            return PrefetchFeedbackLearningRefusal::PhaseChanged;
        }
        PrefetchFeedbackVerdict::OnePassScan => {
            return PrefetchFeedbackLearningRefusal::OnePassScan;
        }
        PrefetchFeedbackVerdict::WrongDatasetPolicy => {
            return PrefetchFeedbackLearningRefusal::WrongDatasetPolicy;
        }
        PrefetchFeedbackVerdict::WrongMediaTopology => {
            return PrefetchFeedbackLearningRefusal::WrongMediaTopology;
        }
        PrefetchFeedbackVerdict::StaleEvidence => {
            return PrefetchFeedbackLearningRefusal::StaleEvidence;
        }
        PrefetchFeedbackVerdict::MissingCostWear => {
            return PrefetchFeedbackLearningRefusal::MissingCostWear;
        }
        PrefetchFeedbackVerdict::ComparatorConfounded => {
            return PrefetchFeedbackLearningRefusal::ComparatorConfounded;
        }
        PrefetchFeedbackVerdict::ShadowOnly => {
            return PrefetchFeedbackLearningRefusal::ShadowOnly;
        }
        PrefetchFeedbackVerdict::Refused => {
            return PrefetchFeedbackLearningRefusal::RefusedRecord;
        }
    }
    if !PrefetchFeedbackLearningEnvelope::from_record(record).has_authority_positive_refs() {
        return PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope;
    }
    if !record.payback.has_cost_or_pressure() {
        return PrefetchFeedbackLearningRefusal::MissingCostWear;
    }
    if !record.payback.looks_beneficial() {
        return PrefetchFeedbackLearningRefusal::LowSample;
    }
    if !record.may_train_confidence_upward() || !record.may_close_payback() {
        return PrefetchFeedbackLearningRefusal::NonAuthorityRecord;
    }
    PrefetchFeedbackLearningRefusal::None
}

const fn state_for_learning_refusal(
    refusal: PrefetchFeedbackLearningRefusal,
) -> PrefetchFeedbackLearningWindowState {
    match refusal {
        PrefetchFeedbackLearningRefusal::None => {
            PrefetchFeedbackLearningWindowState::SustainedPositiveBounded
        }
        PrefetchFeedbackLearningRefusal::SinglePositiveRecord
        | PrefetchFeedbackLearningRefusal::LowSample
        | PrefetchFeedbackLearningRefusal::NeutralRecord
        | PrefetchFeedbackLearningRefusal::NonAuthorityRecord => {
            PrefetchFeedbackLearningWindowState::NeedMoreEvidence
        }
        PrefetchFeedbackLearningRefusal::Wasteful
        | PrefetchFeedbackLearningRefusal::OverBudget
        | PrefetchFeedbackLearningRefusal::ForegroundHarm
        | PrefetchFeedbackLearningRefusal::MissingCostWear
        | PrefetchFeedbackLearningRefusal::UnknownMaterializationCost => {
            PrefetchFeedbackLearningWindowState::Cooldown
        }
        PrefetchFeedbackLearningRefusal::OnePassScan
        | PrefetchFeedbackLearningRefusal::PhaseChanged
        | PrefetchFeedbackLearningRefusal::Contradicted => {
            PrefetchFeedbackLearningWindowState::Demotion
        }
        PrefetchFeedbackLearningRefusal::UnboundScope
        | PrefetchFeedbackLearningRefusal::MismatchedScope
        | PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope
        | PrefetchFeedbackLearningRefusal::StaleEvidence
        | PrefetchFeedbackLearningRefusal::WrongDatasetPolicy
        | PrefetchFeedbackLearningRefusal::WrongMediaTopology => {
            PrefetchFeedbackLearningWindowState::Reset
        }
        PrefetchFeedbackLearningRefusal::MissingRetentionEvidence
        | PrefetchFeedbackLearningRefusal::ComparatorConfounded
        | PrefetchFeedbackLearningRefusal::ShadowOnly
        | PrefetchFeedbackLearningRefusal::RefusedRecord
        | PrefetchFeedbackLearningRefusal::SchedulerNotPresent
        | PrefetchFeedbackLearningRefusal::ExecutorNotPresent => {
            PrefetchFeedbackLearningWindowState::Refused
        }
    }
}

const fn confidence_update_for_learning_refusal(
    refusal: PrefetchFeedbackLearningRefusal,
) -> PrefetchFeedbackConfidenceUpdate {
    match refusal {
        PrefetchFeedbackLearningRefusal::None
        | PrefetchFeedbackLearningRefusal::SinglePositiveRecord
        | PrefetchFeedbackLearningRefusal::NeutralRecord => PrefetchFeedbackConfidenceUpdate::None,
        PrefetchFeedbackLearningRefusal::UnboundScope
        | PrefetchFeedbackLearningRefusal::MismatchedScope
        | PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope
        | PrefetchFeedbackLearningRefusal::WrongDatasetPolicy
        | PrefetchFeedbackLearningRefusal::WrongMediaTopology
        | PrefetchFeedbackLearningRefusal::MissingRetentionEvidence
        | PrefetchFeedbackLearningRefusal::RefusedRecord
        | PrefetchFeedbackLearningRefusal::SchedulerNotPresent
        | PrefetchFeedbackLearningRefusal::ExecutorNotPresent => {
            PrefetchFeedbackConfidenceUpdate::Refused
        }
        PrefetchFeedbackLearningRefusal::LowSample
        | PrefetchFeedbackLearningRefusal::StaleEvidence
        | PrefetchFeedbackLearningRefusal::MissingCostWear
        | PrefetchFeedbackLearningRefusal::UnknownMaterializationCost
        | PrefetchFeedbackLearningRefusal::ComparatorConfounded
        | PrefetchFeedbackLearningRefusal::ShadowOnly
        | PrefetchFeedbackLearningRefusal::OnePassScan
        | PrefetchFeedbackLearningRefusal::PhaseChanged
        | PrefetchFeedbackLearningRefusal::Wasteful
        | PrefetchFeedbackLearningRefusal::OverBudget
        | PrefetchFeedbackLearningRefusal::ForegroundHarm
        | PrefetchFeedbackLearningRefusal::Contradicted
        | PrefetchFeedbackLearningRefusal::NonAuthorityRecord => {
            PrefetchFeedbackConfidenceUpdate::LowerOneStep
        }
    }
}

const fn refusal_reason_for_learning(
    refusal: PrefetchFeedbackLearningRefusal,
) -> StorageIntentRefusalReason {
    match refusal {
        PrefetchFeedbackLearningRefusal::None
        | PrefetchFeedbackLearningRefusal::SinglePositiveRecord
        | PrefetchFeedbackLearningRefusal::LowSample
        | PrefetchFeedbackLearningRefusal::NeutralRecord
        | PrefetchFeedbackLearningRefusal::ComparatorConfounded
        | PrefetchFeedbackLearningRefusal::ShadowOnly
        | PrefetchFeedbackLearningRefusal::OnePassScan
        | PrefetchFeedbackLearningRefusal::PhaseChanged
        | PrefetchFeedbackLearningRefusal::Wasteful
        | PrefetchFeedbackLearningRefusal::ForegroundHarm
        | PrefetchFeedbackLearningRefusal::Contradicted
        | PrefetchFeedbackLearningRefusal::NonAuthorityRecord => StorageIntentRefusalReason::None,
        PrefetchFeedbackLearningRefusal::OverBudget => StorageIntentRefusalReason::OverBudget,
        PrefetchFeedbackLearningRefusal::UnboundScope
        | PrefetchFeedbackLearningRefusal::MismatchedScope
        | PrefetchFeedbackLearningRefusal::WrongDatasetPolicy => {
            StorageIntentRefusalReason::WrongDomain
        }
        PrefetchFeedbackLearningRefusal::WrongMediaTopology
        | PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope => {
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        }
        PrefetchFeedbackLearningRefusal::StaleEvidence
        | PrefetchFeedbackLearningRefusal::MissingRetentionEvidence
        | PrefetchFeedbackLearningRefusal::MissingCostWear
        | PrefetchFeedbackLearningRefusal::UnknownMaterializationCost
        | PrefetchFeedbackLearningRefusal::RefusedRecord
        | PrefetchFeedbackLearningRefusal::SchedulerNotPresent
        | PrefetchFeedbackLearningRefusal::ExecutorNotPresent => {
            StorageIntentRefusalReason::EvidenceNotUsable
        }
    }
}

const fn adjustments_for_learning_refusal(
    refusal: PrefetchFeedbackLearningRefusal,
) -> PrefetchFeedbackAdjustmentMask {
    match state_for_learning_refusal(refusal) {
        PrefetchFeedbackLearningWindowState::Empty
        | PrefetchFeedbackLearningWindowState::SustainedPositiveBounded => {
            PrefetchFeedbackAdjustmentMask::EMPTY
        }
        PrefetchFeedbackLearningWindowState::NeedMoreEvidence => {
            PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE
        }
        PrefetchFeedbackLearningWindowState::Cooldown => PrefetchFeedbackAdjustmentMask::COOLDOWN
            .union(PrefetchFeedbackAdjustmentMask::SHORTEN_WINDOW)
            .union(PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL),
        PrefetchFeedbackLearningWindowState::Demotion => {
            PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS
                .union(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE)
                .union(PrefetchFeedbackAdjustmentMask::COOLDOWN)
                .union(PrefetchFeedbackAdjustmentMask::EXPLICIT_NO_PREFETCH)
        }
        PrefetchFeedbackLearningWindowState::Reset
        | PrefetchFeedbackLearningWindowState::Refused => {
            PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL
                .union(PrefetchFeedbackAdjustmentMask::COOLDOWN)
        }
    }
}

const fn sustained_learning_allowed_uses() -> StorageIntentMeasurementAttributionUseMask {
    StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE
        .union(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD)
        .union(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK)
}

fn learning_evidence_refs_match(
    left: PrefetchFeedbackEvidenceRefs,
    right: PrefetchFeedbackEvidenceRefs,
) -> bool {
    same_learning_ref(left.retention_ref, right.retention_ref)
        && same_learning_ref(left.service_objective_ref, right.service_objective_ref)
        && same_learning_ref(
            left.evidence_query_snapshot_ref,
            right.evidence_query_snapshot_ref,
        )
        && same_learning_ref(left.decision_frontier_ref, right.decision_frontier_ref)
        && same_learning_ref(left.scheduler_admission_ref, right.scheduler_admission_ref)
        && same_learning_ref(left.cost_wear_ref, right.cost_wear_ref)
        && same_optional_learning_ref(left.egress_restore_cost_ref, right.egress_restore_cost_ref)
        && same_learning_ref(left.source_media_ref, right.source_media_ref)
        && same_learning_ref(left.target_media_ref, right.target_media_ref)
        && same_learning_ref(left.source_path_ref, right.source_path_ref)
        && same_learning_ref(left.target_destination_ref, right.target_destination_ref)
        && same_learning_ref(left.transport_path_ref, right.transport_path_ref)
        && same_optional_learning_ref(left.comparator_ref, right.comparator_ref)
        && same_learning_ref(left.allowed_use_ref, right.allowed_use_ref)
}

const fn same_learning_ref(
    left: StorageIntentEvidenceRef,
    right: StorageIntentEvidenceRef,
) -> bool {
    evidence_ref_equal(left, right)
}

const fn same_optional_learning_ref(
    left: StorageIntentEvidenceRef,
    right: StorageIntentEvidenceRef,
) -> bool {
    (!left.is_bound() && !right.is_bound())
        || (left.is_bound() && right.is_bound() && evidence_ref_equal(left, right))
}

const fn saturating_inc_u16(value: u16) -> u16 {
    value.saturating_add(1)
}

fn max_confidence(left: PredictionConfidence, right: PredictionConfidence) -> PredictionConfidence {
    left.max(right)
}

/// Reduce executor and attribution records into a conservative feedback summary.
#[must_use]
pub fn evaluate_prefetch_feedback(input: PrefetchFeedbackInput) -> PrefetchFeedbackRecord {
    let scope = PrefetchFeedbackScopeKey::from_executor(
        input.executor,
        input.service_objective_ref,
        input.observation_window_ms,
    );
    let payback = PrefetchFeedbackPaybackEvidence::from_result_detail(input.executor.result_detail);
    let executor_state = normalize_executor_state(input.executor_state, input.executor);
    let attribution_state = normalize_attribution_state(input.attribution_state, input.attribution);
    let retention_state = normalize_retention_state(
        input.retention_state,
        input.executor.evidence_refs.retention_ref,
        input.attribution.retention_ref,
    );
    let scheduler_state = normalize_scheduler_state(input.scheduler_state, input.executor);
    let materialization_cost_state = input.materialization_cost_state;
    let evidence_refs = evidence_refs_from_input(input);

    let mut record = PrefetchFeedbackRecord {
        scope,
        executor_outcome: input.executor.outcome,
        executor_byte_state: input.executor.executor_byte_state,
        executor_state,
        attribution_state,
        retention_state,
        scheduler_state,
        materialization_cost_state,
        payback,
        previous_confidence: input.executor.confidence,
        next_confidence: input.executor.confidence,
        next_action_class: input.executor.action_class,
        next_candidate: input.executor.selected_candidate,
        next_residency: input.executor.selected_residency,
        next_prefetch_window_bytes: input.executor.max_prefetch_window_bytes,
        next_staging_bytes: input.executor.max_staging_bytes,
        evidence_refs,
        ..PrefetchFeedbackRecord::default()
    };

    let verdict = classify_feedback(input, record);
    record.verdict = verdict;
    record.refusal = refusal_for_verdict(verdict, input.executor.refusal);
    record.allowed_uses = allowed_uses_for_feedback(input, record, verdict);
    record.confidence_update = confidence_update_for(record, verdict);
    record.next_confidence =
        apply_confidence_update(record.previous_confidence, record.confidence_update);
    record.adjustments = adjustments_for_verdict(input.executor, verdict, record);
    apply_action_adjustments(&mut record, input.executor);
    record
}

fn classify_feedback(
    input: PrefetchFeedbackInput,
    record: PrefetchFeedbackRecord,
) -> PrefetchFeedbackVerdict {
    if !record.scope.is_bound() || !record.scope.matches_executor(input.executor) {
        return PrefetchFeedbackVerdict::WrongDatasetPolicy;
    }
    if !matches!(
        record.executor_state,
        PrefetchFeedbackExecutorOutcomeState::Present
    ) {
        return match record.executor_state {
            PrefetchFeedbackExecutorOutcomeState::Stale => PrefetchFeedbackVerdict::StaleEvidence,
            PrefetchFeedbackExecutorOutcomeState::Unavailable => {
                PrefetchFeedbackVerdict::InsufficientSample
            }
            PrefetchFeedbackExecutorOutcomeState::Blocked
            | PrefetchFeedbackExecutorOutcomeState::Refused => PrefetchFeedbackVerdict::Refused,
            PrefetchFeedbackExecutorOutcomeState::Present => PrefetchFeedbackVerdict::Neutral,
        };
    }
    if matches!(
        record.scheduler_state,
        PrefetchFeedbackSchedulerState::Blocked
            | PrefetchFeedbackSchedulerState::Refused
            | PrefetchFeedbackSchedulerState::Unavailable
            | PrefetchFeedbackSchedulerState::UnknownLane
    ) {
        return PrefetchFeedbackVerdict::Refused;
    }
    if !record.scope.matches_attribution_scope(input.attribution) {
        return PrefetchFeedbackVerdict::WrongDatasetPolicy;
    }
    if attribution_media_or_topology_mismatch(input) {
        return PrefetchFeedbackVerdict::WrongMediaTopology;
    }
    match record.attribution_state {
        PrefetchFeedbackAttributionState::Unavailable => {
            return PrefetchFeedbackVerdict::InsufficientSample;
        }
        PrefetchFeedbackAttributionState::Confounded => {
            return PrefetchFeedbackVerdict::ComparatorConfounded;
        }
        PrefetchFeedbackAttributionState::InsufficientSample => {
            return PrefetchFeedbackVerdict::InsufficientSample;
        }
        PrefetchFeedbackAttributionState::Stale => return PrefetchFeedbackVerdict::StaleEvidence,
        PrefetchFeedbackAttributionState::Contradicted => {
            return PrefetchFeedbackVerdict::Contradicted;
        }
        PrefetchFeedbackAttributionState::ShadowOnly => return PrefetchFeedbackVerdict::ShadowOnly,
        PrefetchFeedbackAttributionState::Refused => return PrefetchFeedbackVerdict::Refused,
        PrefetchFeedbackAttributionState::Attributable
        | PrefetchFeedbackAttributionState::PartiallyAttributableWithBounds => {}
    }
    if input
        .executor
        .anti_waste
        .intersects(PrefetchExecutorAntiWasteMask::ONE_PASS_SCAN)
        || matches!(
            input.executor.access_pattern,
            AccessPatternClass::OnePassScan
        )
    {
        return PrefetchFeedbackVerdict::OnePassScan;
    }
    if input
        .executor
        .anti_waste
        .intersects(PrefetchExecutorAntiWasteMask::PHASE_CHANGE)
        || matches!(
            input.executor.access_pattern,
            AccessPatternClass::PhaseChangingSparse
        )
    {
        return PrefetchFeedbackVerdict::PhaseChanged;
    }
    if feedback_missing_cost_or_wear(input, record) {
        return PrefetchFeedbackVerdict::MissingCostWear;
    }
    if feedback_over_budget(input, record) {
        return PrefetchFeedbackVerdict::OverBudget;
    }
    if record.payback.harms_foreground()
        || input
            .executor
            .admission
            .pressure
            .intersects(PrefetchExecutorPressureMask::P99_LATENCY)
    {
        return PrefetchFeedbackVerdict::HarmfulToForeground;
    }
    if record.payback.looks_wasteful()
        || matches!(
            input.executor.outcome,
            PrefetchExecutorOutcome::Dropped
                | PrefetchExecutorOutcome::TimedOut
                | PrefetchExecutorOutcome::VerificationFailed
        )
    {
        return PrefetchFeedbackVerdict::Wasteful;
    }
    if exact_authority_feedback_ready(input, record)
        && record.payback.looks_beneficial()
        && !input.executor.is_non_authority_population()
    {
        return PrefetchFeedbackVerdict::Beneficial;
    }
    PrefetchFeedbackVerdict::Neutral
}

fn allowed_uses_for_feedback(
    input: PrefetchFeedbackInput,
    record: PrefetchFeedbackRecord,
    verdict: PrefetchFeedbackVerdict,
) -> StorageIntentMeasurementAttributionUseMask {
    let diagnostic = StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE;
    if !matches!(verdict, PrefetchFeedbackVerdict::Beneficial)
        || !exact_authority_feedback_ready(input, record)
    {
        return diagnostic;
    }

    let mut allowed = diagnostic;
    for requested in [
        StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD,
        StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK,
        StorageIntentMeasurementAttributionUseMask::ADMIT_AUTHORITY_MOVEMENT,
        StorageIntentMeasurementAttributionUseMask::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET,
        StorageIntentMeasurementAttributionUseMask::SUPPORT_PERFORMANCE_EVIDENCE,
        StorageIntentMeasurementAttributionUseMask::SUPPORT_FAULT_EVIDENCE,
        StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM,
    ] {
        if input.attribution.authorizes_use(requested) {
            allowed = allowed.union(requested);
        }
    }

    allowed.without(StorageIntentMeasurementAttributionUseMask::RETIRE_SOURCE_RECEIPTS)
}

fn confidence_update_for(
    record: PrefetchFeedbackRecord,
    verdict: PrefetchFeedbackVerdict,
) -> PrefetchFeedbackConfidenceUpdate {
    if matches!(verdict, PrefetchFeedbackVerdict::Beneficial) {
        if record
            .allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD)
        {
            return PrefetchFeedbackConfidenceUpdate::RaiseOneStep;
        }
        return PrefetchFeedbackConfidenceUpdate::CapAtCurrent;
    }
    if verdict.is_weak_or_negative() {
        return match verdict {
            PrefetchFeedbackVerdict::WrongDatasetPolicy
            | PrefetchFeedbackVerdict::WrongMediaTopology
            | PrefetchFeedbackVerdict::Refused => PrefetchFeedbackConfidenceUpdate::Refused,
            _ => PrefetchFeedbackConfidenceUpdate::LowerOneStep,
        };
    }
    PrefetchFeedbackConfidenceUpdate::None
}

fn apply_confidence_update(
    previous: PredictionConfidence,
    update: PrefetchFeedbackConfidenceUpdate,
) -> PredictionConfidence {
    match update {
        PrefetchFeedbackConfidenceUpdate::RaiseOneStep => raise_confidence_one_step(previous),
        PrefetchFeedbackConfidenceUpdate::LowerOneStep => lower_confidence_one_step(previous),
        PrefetchFeedbackConfidenceUpdate::Refused => PredictionConfidence::Low,
        PrefetchFeedbackConfidenceUpdate::CapAtCurrent | PrefetchFeedbackConfidenceUpdate::None => {
            previous
        }
    }
}

fn adjustments_for_verdict(
    executor: PrefetchExecutorRecord,
    verdict: PrefetchFeedbackVerdict,
    record: PrefetchFeedbackRecord,
) -> PrefetchFeedbackAdjustmentMask {
    match verdict {
        PrefetchFeedbackVerdict::Beneficial => {
            let mut mask = PrefetchFeedbackAdjustmentMask::PAYBACK_CANDIDATE;
            if record
                .allowed_uses
                .contains_all(StorageIntentMeasurementAttributionUseMask::ADMIT_AUTHORITY_MOVEMENT)
            {
                mask = mask.union(PrefetchFeedbackAdjustmentMask::MOVEMENT_DEBT_CANDIDATE);
                if matches!(
                    executor.selected_candidate,
                    PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
                        | PrefetchResidencyCandidateClass::IntentBackedRam
                        | PrefetchResidencyCandidateClass::PmemDurable
                ) {
                    mask = mask.union(PrefetchFeedbackAdjustmentMask::PROMOTION_CANDIDATE);
                }
            }
            mask
        }
        PrefetchFeedbackVerdict::Neutral => PrefetchFeedbackAdjustmentMask::EMPTY,
        PrefetchFeedbackVerdict::InsufficientSample => {
            PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE
                .union(PrefetchFeedbackAdjustmentMask::SHORTEN_WINDOW)
        }
        PrefetchFeedbackVerdict::Wasteful
        | PrefetchFeedbackVerdict::PhaseChanged
        | PrefetchFeedbackVerdict::OnePassScan
        | PrefetchFeedbackVerdict::Contradicted => {
            PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS
                .union(PrefetchFeedbackAdjustmentMask::SHORTEN_WINDOW)
                .union(PrefetchFeedbackAdjustmentMask::EXTEND_DWELL)
                .union(PrefetchFeedbackAdjustmentMask::COOLDOWN)
                .union(PrefetchFeedbackAdjustmentMask::EXPLICIT_NO_PREFETCH)
                .union(demotion_if_persistent(executor))
        }
        PrefetchFeedbackVerdict::OverBudget
        | PrefetchFeedbackVerdict::HarmfulToForeground
        | PrefetchFeedbackVerdict::MissingCostWear => {
            PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS
                .union(PrefetchFeedbackAdjustmentMask::SHORTEN_WINDOW)
                .union(PrefetchFeedbackAdjustmentMask::COOLDOWN)
                .union(PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL)
                .union(demotion_if_persistent(executor))
        }
        PrefetchFeedbackVerdict::WrongDatasetPolicy
        | PrefetchFeedbackVerdict::WrongMediaTopology
        | PrefetchFeedbackVerdict::StaleEvidence
        | PrefetchFeedbackVerdict::ComparatorConfounded
        | PrefetchFeedbackVerdict::ShadowOnly
        | PrefetchFeedbackVerdict::Refused => PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL
            .union(PrefetchFeedbackAdjustmentMask::COOLDOWN),
    }
}

fn apply_action_adjustments(record: &mut PrefetchFeedbackRecord, executor: PrefetchExecutorRecord) {
    if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::SHORTEN_WINDOW)
    {
        record.next_prefetch_window_bytes /= 2;
        record.next_staging_bytes /= 2;
    }
    if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::EXPLICIT_NO_PREFETCH)
    {
        record.next_candidate = PrefetchResidencyCandidateClass::NoPrefetch;
        record.next_residency = PrefetchResidencyStateClass::CacheOnlyRam;
        record.next_action_class = StorageIntentActionClass::QueuePrefetchTuning;
        record.next_prefetch_window_bytes = 0;
        record.next_staging_bytes = 0;
    } else if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE)
    {
        record.next_candidate = PrefetchResidencyCandidateClass::NeedMoreEvidence;
        record.next_residency = PrefetchResidencyStateClass::Unknown;
    } else if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS)
    {
        record.next_action_class = StorageIntentActionClass::CacheOnlyServingTrial;
        record.next_candidate = PrefetchResidencyCandidateClass::CacheOnlyTrial;
        record.next_residency = PrefetchResidencyStateClass::CacheOnlyRam;
    }
    if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE)
    {
        record.next_candidate = PrefetchResidencyCandidateClass::DemotionCandidate;
    }
    if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::EXTEND_DWELL)
    {
        record.dwell_extension_ms = executor.freshness_rpo_floor_ms.max(1);
    }
    if record
        .adjustments
        .intersects(PrefetchFeedbackAdjustmentMask::COOLDOWN)
    {
        record.cooldown_ms = executor.freshness_rpo_floor_ms.max(1);
    }
}

fn normalize_executor_state(
    state: PrefetchFeedbackExecutorOutcomeState,
    executor: PrefetchExecutorRecord,
) -> PrefetchFeedbackExecutorOutcomeState {
    if !matches!(state, PrefetchFeedbackExecutorOutcomeState::Unavailable) {
        return state;
    }
    match executor.outcome {
        PrefetchExecutorOutcome::Unknown | PrefetchExecutorOutcome::Unavailable => {
            PrefetchFeedbackExecutorOutcomeState::Unavailable
        }
        PrefetchExecutorOutcome::Stale => PrefetchFeedbackExecutorOutcomeState::Stale,
        PrefetchExecutorOutcome::Blocked => PrefetchFeedbackExecutorOutcomeState::Blocked,
        PrefetchExecutorOutcome::Refused => PrefetchFeedbackExecutorOutcomeState::Refused,
        PrefetchExecutorOutcome::Started
        | PrefetchExecutorOutcome::Dropped
        | PrefetchExecutorOutcome::Throttled
        | PrefetchExecutorOutcome::Completed
        | PrefetchExecutorOutcome::TimedOut
        | PrefetchExecutorOutcome::DegradedVisible
        | PrefetchExecutorOutcome::OverBudget
        | PrefetchExecutorOutcome::VerificationFailed
        | PrefetchExecutorOutcome::HandoffRequired => PrefetchFeedbackExecutorOutcomeState::Present,
    }
}

fn normalize_attribution_state(
    state: PrefetchFeedbackAttributionState,
    attribution: StorageIntentMeasurementAttributionEvidence,
) -> PrefetchFeedbackAttributionState {
    if !matches!(state, PrefetchFeedbackAttributionState::Unavailable) {
        return state;
    }
    PrefetchFeedbackAttributionState::from_verdict(attribution.verdict)
}

fn normalize_retention_state(
    state: PrefetchFeedbackRetentionState,
    executor_ref: StorageIntentEvidenceRef,
    attribution_ref: StorageIntentEvidenceRef,
) -> PrefetchFeedbackRetentionState {
    if !matches!(state, PrefetchFeedbackRetentionState::Unavailable) {
        return state;
    }
    if executor_ref.is_bound()
        && attribution_ref.is_bound()
        && evidence_ref_equal(executor_ref, attribution_ref)
    {
        PrefetchFeedbackRetentionState::ProofRoot
    } else {
        PrefetchFeedbackRetentionState::Unavailable
    }
}

fn normalize_scheduler_state(
    state: PrefetchFeedbackSchedulerState,
    executor: PrefetchExecutorRecord,
) -> PrefetchFeedbackSchedulerState {
    if !matches!(state, PrefetchFeedbackSchedulerState::UnknownLane) {
        return state;
    }
    match executor.admission.outcome {
        PrefetchExecutorAdmissionOutcome::Admitted
        | PrefetchExecutorAdmissionOutcome::Dropped
        | PrefetchExecutorAdmissionOutcome::Throttled
        | PrefetchExecutorAdmissionOutcome::Expired => PrefetchFeedbackSchedulerState::Present,
        PrefetchExecutorAdmissionOutcome::Refused => PrefetchFeedbackSchedulerState::Refused,
        PrefetchExecutorAdmissionOutcome::Blocked => PrefetchFeedbackSchedulerState::Blocked,
        PrefetchExecutorAdmissionOutcome::Unavailable => {
            PrefetchFeedbackSchedulerState::Unavailable
        }
        PrefetchExecutorAdmissionOutcome::Unknown => PrefetchFeedbackSchedulerState::UnknownLane,
    }
}

fn exact_authority_feedback_ready(
    input: PrefetchFeedbackInput,
    record: PrefetchFeedbackRecord,
) -> bool {
    matches!(
        record.attribution_state,
        PrefetchFeedbackAttributionState::Attributable
            | PrefetchFeedbackAttributionState::PartiallyAttributableWithBounds
    ) && record.retention_state.has_authority_proof_root()
        && matches!(
            record.materialization_cost_state,
            PrefetchFeedbackMaterializationCostState::KnownCharged
        )
        && record.scope.matches_attribution_scope(input.attribution)
        && !attribution_media_or_topology_mismatch(input)
        && input.executor.has_feedback_payback_inputs()
        && input.executor_outcome_ref.kind as u16
            == StorageIntentEvidenceKind::ActionExecutionEvidence as u16
        && input.executor_outcome_ref.is_bound()
        && evidence_ref_equal(
            input.attribution.action_execution_ref,
            input.executor_outcome_ref,
        )
        && evidence_ref_equal(
            input.attribution.evidence_query_snapshot_ref,
            input.executor.evidence_refs.evidence_query_snapshot_ref,
        )
        && evidence_ref_equal(
            input.attribution.scheduler_ref,
            input.executor.evidence_refs.scheduler_admission_ref,
        )
        && evidence_ref_equal(
            input.attribution.retention_ref,
            input.executor.evidence_refs.retention_ref,
        )
        && input
            .attribution
            .measurement_source_refs
            .contains_ref(input.executor.evidence_refs.cost_wear_ref)
}

fn attribution_media_or_topology_mismatch(input: PrefetchFeedbackInput) -> bool {
    bound_mismatch(
        input.executor.evidence_refs.source_media_ref,
        input.attribution.source_media_ref,
    ) || bound_mismatch(
        input.executor.evidence_refs.target_media_ref,
        input.attribution.target_media_ref,
    ) || bound_mismatch(
        input.executor.evidence_refs.transport_budget_ref,
        input.attribution.transport_path_ref,
    )
}

fn feedback_missing_cost_or_wear(
    input: PrefetchFeedbackInput,
    record: PrefetchFeedbackRecord,
) -> bool {
    matches!(
        record.materialization_cost_state,
        PrefetchFeedbackMaterializationCostState::UnknownConservative
            | PrefetchFeedbackMaterializationCostState::Refused
    ) || input.executor.cost_state.unknown_waf
        || input.executor.cost_state.unknown_egress_or_restore_cost
        || input.executor.cost_state.missing_required_cost()
        || (input.executor.target_media.charges_rewrite_wear() && record.payback.waf_micros == 0)
}

fn feedback_over_budget(input: PrefetchFeedbackInput, record: PrefetchFeedbackRecord) -> bool {
    matches!(
        record.materialization_cost_state,
        PrefetchFeedbackMaterializationCostState::OverBudget
    ) || input.executor.cost_state.over_budget
        || record.payback.protected_reserve_pressure
        || input.executor.admission.reserve_protected
        || input
            .executor
            .admission
            .pressure
            .intersects(PrefetchExecutorPressureMask::PROTECTED_RESERVE)
        || matches!(input.executor.outcome, PrefetchExecutorOutcome::OverBudget)
}

const fn demotion_if_persistent(
    executor: PrefetchExecutorRecord,
) -> PrefetchFeedbackAdjustmentMask {
    if executor.target_media.is_persistent() {
        PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE
    } else {
        PrefetchFeedbackAdjustmentMask::EMPTY
    }
}

const fn refusal_for_verdict(
    verdict: PrefetchFeedbackVerdict,
    executor_refusal: StorageIntentRefusalReason,
) -> StorageIntentRefusalReason {
    if executor_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return executor_refusal;
    }
    match verdict {
        PrefetchFeedbackVerdict::Beneficial
        | PrefetchFeedbackVerdict::Neutral
        | PrefetchFeedbackVerdict::Wasteful
        | PrefetchFeedbackVerdict::HarmfulToForeground
        | PrefetchFeedbackVerdict::InsufficientSample
        | PrefetchFeedbackVerdict::Contradicted
        | PrefetchFeedbackVerdict::PhaseChanged
        | PrefetchFeedbackVerdict::OnePassScan
        | PrefetchFeedbackVerdict::ComparatorConfounded
        | PrefetchFeedbackVerdict::ShadowOnly => StorageIntentRefusalReason::None,
        PrefetchFeedbackVerdict::OverBudget => StorageIntentRefusalReason::OverBudget,
        PrefetchFeedbackVerdict::WrongDatasetPolicy => StorageIntentRefusalReason::WrongDomain,
        PrefetchFeedbackVerdict::WrongMediaTopology => {
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        }
        PrefetchFeedbackVerdict::StaleEvidence
        | PrefetchFeedbackVerdict::MissingCostWear
        | PrefetchFeedbackVerdict::Refused => StorageIntentRefusalReason::EvidenceNotUsable,
    }
}

const fn raise_confidence_one_step(confidence: PredictionConfidence) -> PredictionConfidence {
    match confidence {
        PredictionConfidence::Unknown => PredictionConfidence::Low,
        PredictionConfidence::Low => PredictionConfidence::Medium,
        PredictionConfidence::Medium | PredictionConfidence::High => PredictionConfidence::High,
    }
}

const fn lower_confidence_one_step(confidence: PredictionConfidence) -> PredictionConfidence {
    match confidence {
        PredictionConfidence::High => PredictionConfidence::Medium,
        PredictionConfidence::Medium => PredictionConfidence::Low,
        PredictionConfidence::Low | PredictionConfidence::Unknown => PredictionConfidence::Low,
    }
}

const fn bound_mismatch(left: StorageIntentEvidenceRef, right: StorageIntentEvidenceRef) -> bool {
    left.is_bound() && right.is_bound() && !evidence_ref_equal(left, right)
}

const fn evidence_ref_equal(
    left: StorageIntentEvidenceRef,
    right: StorageIntentEvidenceRef,
) -> bool {
    left.kind as u16 == right.kind as u16
        && bytes32_equal(left.id.0, right.id.0)
        && left.generation == right.generation
        && left.version == right.version
}

const fn bytes32_equal(left: [u8; 32], right: [u8; 32]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

fn evidence_refs_from_input(input: PrefetchFeedbackInput) -> PrefetchFeedbackEvidenceRefs {
    PrefetchFeedbackEvidenceRefs {
        executor_outcome_ref: input.executor_outcome_ref,
        attribution_ref: input.attribution.evidence_ref,
        retention_ref: first_bound(
            input.executor.evidence_refs.retention_ref,
            input.attribution.retention_ref,
        ),
        service_objective_ref: input.service_objective_ref,
        evidence_query_snapshot_ref: input.executor.evidence_refs.evidence_query_snapshot_ref,
        decision_frontier_ref: input.executor.evidence_refs.prefetch_decision_ref,
        scheduler_admission_ref: input.executor.evidence_refs.scheduler_admission_ref,
        cost_wear_ref: input.executor.evidence_refs.cost_wear_ref,
        egress_restore_cost_ref: input.executor.evidence_refs.egress_restore_cost_ref,
        source_media_ref: input.executor.evidence_refs.source_media_ref,
        target_media_ref: input.executor.evidence_refs.target_media_ref,
        source_path_ref: input.executor.evidence_refs.source_path_ref,
        target_destination_ref: input.executor.evidence_refs.target_destination_ref,
        transport_path_ref: input.executor.evidence_refs.transport_budget_ref,
        comparator_ref: input.attribution.comparator.comparator_ref,
        allowed_use_ref: input.attribution.allowed_use_ref,
    }
}

const fn first_bound(
    first: StorageIntentEvidenceRef,
    second: StorageIntentEvidenceRef,
) -> StorageIntentEvidenceRef {
    if first.is_bound() {
        first
    } else {
        second
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        EvidenceQuerySubjectScope, EvidenceQuerySubjectScopeClass, StorageIntentEvidenceRefs,
        StorageIntentMeasurementBaselineClass, StorageIntentMeasurementComparatorLineage,
        StorageIntentMeasurementMetricDimension, StorageIntentMeasurementMetricEntry,
        StorageIntentMeasurementMetricSet, StorageIntentMeasurementMetricState,
        StorageIntentMeasurementMetricUnit, StorageIntentMeasurementSampleWindow,
        StorageIntentMeasurementTransferScopeMask,
    };
    use tidefs_storage_intent_prefetch_executor::{
        PrefetchExecutorAdmissionRecord, PrefetchExecutorEvidenceRefs,
    };

    fn policy(byte: u8) -> StorageIntentPolicyId {
        StorageIntentPolicyId([byte; 16])
    }

    fn domain(byte: u8) -> StorageIntentDomainId {
        StorageIntentDomainId([byte; 16])
    }

    fn evidence_id(byte: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([byte; 32])
    }

    fn evidence(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, evidence_id(byte), 1, 1)
    }

    fn subject() -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: domain(3),
            object_id: evidence_id(4),
            range_start: 4096,
            range_len: 131_072,
            generation: 7,
        }
    }

    fn metric(
        dimension: StorageIntentMeasurementMetricDimension,
        unit: StorageIntentMeasurementMetricUnit,
        byte: u8,
    ) -> StorageIntentMeasurementMetricEntry {
        StorageIntentMeasurementMetricEntry {
            dimension,
            state: StorageIntentMeasurementMetricState::Known,
            unit,
            value: i64::from(byte) * 100,
            variance_ppm: u32::from(byte),
            evidence_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, byte),
        }
    }

    fn payback_metrics() -> StorageIntentMeasurementMetricSet {
        let mut metrics = StorageIntentMeasurementMetricSet::EMPTY;
        metrics
            .push(metric(
                StorageIntentMeasurementMetricDimension::Latency,
                StorageIntentMeasurementMetricUnit::Microseconds,
                91,
            ))
            .unwrap();
        metrics
            .push(metric(
                StorageIntentMeasurementMetricDimension::PaybackWindow,
                StorageIntentMeasurementMetricUnit::Milliseconds,
                92,
            ))
            .unwrap();
        metrics
            .push(metric(
                StorageIntentMeasurementMetricDimension::MediaWriteBytes,
                StorageIntentMeasurementMetricUnit::Bytes,
                93,
            ))
            .unwrap();
        metrics
            .push(metric(
                StorageIntentMeasurementMetricDimension::ForegroundHarm,
                StorageIntentMeasurementMetricUnit::Microseconds,
                94,
            ))
            .unwrap();
        metrics
    }

    fn all_authority_uses() -> StorageIntentMeasurementAttributionUseMask {
        StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE
            .union(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD)
            .union(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK)
            .union(StorageIntentMeasurementAttributionUseMask::ADMIT_AUTHORITY_MOVEMENT)
            .union(StorageIntentMeasurementAttributionUseMask::RETIRE_SOURCE_RECEIPTS)
            .union(StorageIntentMeasurementAttributionUseMask::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET)
            .union(StorageIntentMeasurementAttributionUseMask::SUPPORT_PERFORMANCE_EVIDENCE)
            .union(StorageIntentMeasurementAttributionUseMask::SUPPORT_FAULT_EVIDENCE)
            .union(StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM)
    }

    fn source_refs(cost_ref: StorageIntentEvidenceRef) -> StorageIntentEvidenceRefs {
        let mut refs = StorageIntentEvidenceRefs::EMPTY;
        refs.push(cost_ref).unwrap();
        refs.push(evidence(StorageIntentEvidenceKind::TemporalEvidence, 95))
            .unwrap();
        refs
    }

    fn executor_record() -> PrefetchExecutorRecord {
        let query_ref = evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 21);
        let scheduler_ref = evidence(StorageIntentEvidenceKind::SchedulerAdmissionRecord, 22);
        let retention_ref = evidence(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 23);
        let attribution_ref = evidence(
            StorageIntentEvidenceKind::MeasurementAttributionEvidence,
            24,
        );
        let cost_ref = evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 25);
        let source_media_ref = evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, 26);
        let target_media_ref = evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, 27);
        let source_path_ref = evidence(StorageIntentEvidenceKind::TransportPathEvidence, 28);
        let target_destination_ref =
            evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, 29);
        let transport_ref = evidence(StorageIntentEvidenceKind::TransportPathEvidence, 30);

        PrefetchExecutorRecord {
            policy_id: policy(1),
            policy_revision: StorageIntentPolicyRevision(3),
            budget_owner: domain(2),
            action_class: StorageIntentActionClass::FlashServingPromotion,
            action_family: PrefetchExecutorActionFamily::BoundedSequentialReadahead,
            subject: subject(),
            access_pattern: AccessPatternClass::SequentialRead,
            confidence: PredictionConfidence::Medium,
            requested_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            selected_candidate: PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            selected_residency: PrefetchResidencyStateClass::FlashHotServing,
            executor_byte_state: PrefetchExecutorByteState::HandoffRequired,
            source_media: StorageMediaClass::HddRotational,
            target_media: StorageMediaClass::NvmeFlash,
            source_path_ref,
            target_destination_ref,
            freshness_rpo_floor_ms: 60_000,
            max_prefetch_window_bytes: 131_072,
            max_staging_bytes: 262_144,
            admission: PrefetchExecutorAdmissionRecord {
                outcome: PrefetchExecutorAdmissionOutcome::Admitted,
                budget_owner: domain(2),
                requested_bytes: 131_072,
                admitted_bytes: 131_072,
                queue_time_us: 20,
                scheduler_admission_ref: scheduler_ref,
                ..PrefetchExecutorAdmissionRecord::default()
            },
            result_detail: PrefetchExecutorResultDetail {
                prefetched_bytes: 131_072,
                used_bytes: 131_072,
                unused_bytes: 0,
                expired_bytes: 0,
                latency_benefit_us: 10_000,
                latency_harm_us: 100,
                foreground_p50_disruption_us: 10,
                foreground_p95_disruption_us: 20,
                foreground_p99_disruption_us: 30,
                queue_delay_us: 20,
                flash_write_bytes: 131_072,
                waf_micros: 1_100_000,
                cache_index_write_bytes: 512,
                predictor_metadata_write_bytes: 256,
                staging_capacity_bytes: 262_144,
                cpu_us: 200,
                memory_bytes: 4096,
                attribution_ref,
                retention_ref,
                ..PrefetchExecutorResultDetail::default()
            },
            outcome: PrefetchExecutorOutcome::Completed,
            evidence_refs: PrefetchExecutorEvidenceRefs {
                prefetch_decision_ref: evidence(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    31,
                ),
                evidence_query_snapshot_ref: query_ref,
                scheduler_admission_ref: scheduler_ref,
                cost_wear_ref: cost_ref,
                egress_restore_cost_ref: evidence(
                    StorageIntentEvidenceKind::MediaCostWearLedger,
                    32,
                ),
                source_media_ref,
                target_media_ref,
                source_path_ref,
                target_destination_ref,
                transport_budget_ref: transport_ref,
                retention_ref,
                attribution_ref,
                ..PrefetchExecutorEvidenceRefs::default()
            },
            ..PrefetchExecutorRecord::default()
        }
    }

    fn attribution_for(
        executor: PrefetchExecutorRecord,
    ) -> StorageIntentMeasurementAttributionEvidence {
        let service_ref = evidence(StorageIntentEvidenceKind::ServiceObjectiveEvidence, 40);
        let cost_ref = executor.evidence_refs.cost_wear_ref;

        StorageIntentMeasurementAttributionEvidence {
            evidence_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                41,
            ),
            measurement_id: evidence_id(42),
            tenant_id: domain(9),
            budget_owner_id: executor.budget_owner,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::ObjectRange,
                object_scope: executor.subject,
                pool_id: domain(10),
                domain_id: domain(9),
                request_ref: evidence(StorageIntentEvidenceKind::LocalIntentRecord, 43),
                action_ref: executor.evidence_refs.prefetch_decision_ref,
                validation_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, 44),
            },
            policy_id: executor.policy_id,
            policy_revision: executor.policy_revision,
            observation_generation: 11,
            producer_component_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, 45),
            producer_version: 1,
            workload_envelope_ref: evidence(StorageIntentEvidenceKind::WorkloadEvidence, 46),
            workload_scope_ref: evidence(StorageIntentEvidenceKind::WorkloadEvidence, 47),
            environment_profile_ref: evidence(StorageIntentEvidenceKind::TransportPathEvidence, 48),
            noise_policy_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, 49),
            service_objective_ref: service_ref,
            sample_window: StorageIntentMeasurementSampleWindow {
                temporal_window_ref: evidence(StorageIntentEvidenceKind::TemporalEvidence, 50),
                warmup_ms: 1000,
                sample_window_ms: 60_000,
                sample_mass: 512,
                censored_sample_count: 0,
                dropped_sample_count: 0,
                variance_ppm: 1000,
                confidence_bound_ppm: 10_000,
                censor_drop_policy_ref: evidence(
                    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                    51,
                ),
            },
            measurement_source_refs: source_refs(cost_ref),
            evidence_query_snapshot_ref: executor.evidence_refs.evidence_query_snapshot_ref,
            decision_frontier_ref: executor.evidence_refs.prefetch_decision_ref,
            action_execution_ref: evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, 20),
            admission_ref: executor.evidence_refs.scheduler_admission_ref,
            scheduler_ref: executor.evidence_refs.scheduler_admission_ref,
            isolation_ref: evidence(StorageIntentEvidenceKind::TenantIsolationEvidence, 52),
            capacity_ref: evidence(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 53),
            source_media_ref: executor.evidence_refs.source_media_ref,
            target_media_ref: executor.evidence_refs.target_media_ref,
            trust_domain_ref: evidence(StorageIntentEvidenceKind::TrustDomainEvidence, 54),
            transport_path_ref: executor.evidence_refs.transport_budget_ref,
            recovery_ref: evidence(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 55),
            rollout_ref: evidence(StorageIntentEvidenceKind::PolicyRolloutEvidence, 56),
            layout_ref: evidence(StorageIntentEvidenceKind::LayoutAllocatorEvidence, 57),
            lifecycle_ref: evidence(StorageIntentEvidenceKind::LifecycleGenerationEvidence, 58),
            comparator: StorageIntentMeasurementComparatorLineage {
                baseline_class: StorageIntentMeasurementBaselineClass::IncumbentPeerComparator,
                baseline_ref: evidence(StorageIntentEvidenceKind::ComparatorEvidence, 59),
                comparator_ref: evidence(StorageIntentEvidenceKind::ComparatorEvidence, 60),
                counterfactual_ref: evidence(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    61,
                ),
                prior_admitted_variant_ref: evidence(
                    StorageIntentEvidenceKind::PlacementReceipt,
                    62,
                ),
                shadow_target_ref: evidence(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    63,
                ),
                baseline_generation: 2,
                no_valid_baseline_refusal: StorageIntentRefusalReason::None,
            },
            metrics: payback_metrics(),
            verdict: StorageIntentMeasurementAttributionVerdict::Attributable,
            allowed_uses: all_authority_uses(),
            allowed_use_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                64,
            ),
            transfer_scope: StorageIntentMeasurementTransferScopeMask::EXACT_AUTHORITY_SCOPE,
            transfer_scope_ref: evidence(StorageIntentEvidenceKind::TenantIsolationEvidence, 65),
            attribution_verdict_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                66,
            ),
            retention_ref: executor.evidence_refs.retention_ref,
            refusal: StorageIntentRefusalReason::None,
            ..StorageIntentMeasurementAttributionEvidence::default()
        }
    }

    fn admissible_input() -> PrefetchFeedbackInput {
        let executor = executor_record();
        let attribution = attribution_for(executor);
        PrefetchFeedbackInput {
            executor,
            executor_outcome_ref: attribution.action_execution_ref,
            attribution,
            service_objective_ref: attribution.service_objective_ref,
            observation_window_ms: attribution.sample_window.sample_window_ms,
            executor_state: PrefetchFeedbackExecutorOutcomeState::Present,
            attribution_state: PrefetchFeedbackAttributionState::Attributable,
            retention_state: PrefetchFeedbackRetentionState::ProofRoot,
            scheduler_state: PrefetchFeedbackSchedulerState::Present,
            materialization_cost_state: PrefetchFeedbackMaterializationCostState::KnownCharged,
        }
    }

    #[test]
    fn exact_attributed_payback_raises_only_one_bounded_step() {
        let record = evaluate_prefetch_feedback(admissible_input());

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::Beneficial);
        assert!(record.may_train_confidence_upward());
        assert_eq!(record.previous_confidence, PredictionConfidence::Medium);
        assert_eq!(record.next_confidence, PredictionConfidence::High);
        assert!(record.may_close_payback());
        assert!(record.may_request_flash_budget_candidate());
        assert!(record.may_support_public_or_comparator_claim());
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::PAYBACK_CANDIDATE));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::MOVEMENT_DEBT_CANDIDATE));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::PROMOTION_CANDIDATE));
        assert!(!record
            .allowed_uses
            .contains_all(StorageIntentMeasurementAttributionUseMask::RETIRE_SOURCE_RECEIPTS));
        assert!(!record.can_publish_replacement_receipt());
        assert!(!record.can_retire_source_receipt());
        assert!(!record.can_spend_extra_flash_movement_budget());
    }

    #[test]
    fn budget_owner_mismatch_blocks_cross_dataset_learning() {
        let mut input = admissible_input();
        input.attribution.budget_owner_id = domain(88);

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::WrongDatasetPolicy);
        assert_eq!(
            record.confidence_update,
            PrefetchFeedbackConfidenceUpdate::Refused
        );
        assert!(!record.may_train_confidence_upward());
        assert!(!record.may_close_payback());
        assert_eq!(record.next_confidence, PredictionConfidence::Low);
        assert_eq!(record.refusal, StorageIntentRefusalReason::WrongDomain);
    }

    #[test]
    fn wrong_dataset_subject_blocks_transfer() {
        let mut input = admissible_input();
        input.attribution.subject.object_scope.dataset_id = domain(89);

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::WrongDatasetPolicy);
        assert!(!record.may_train_confidence_upward());
        assert!(!record.may_emit_movement_candidate());
        assert_eq!(record.next_confidence, PredictionConfidence::Low);
    }

    #[test]
    fn confounded_and_low_sample_evidence_cannot_train_upward() {
        let mut confounded = admissible_input();
        confounded.attribution_state = PrefetchFeedbackAttributionState::Confounded;
        confounded.attribution.verdict = StorageIntentMeasurementAttributionVerdict::Confounded;

        let confounded_record = evaluate_prefetch_feedback(confounded);
        assert_eq!(
            confounded_record.verdict,
            PrefetchFeedbackVerdict::ComparatorConfounded
        );
        assert!(!confounded_record.may_train_confidence_upward());
        assert!(!confounded_record.may_close_payback());
        assert_eq!(confounded_record.next_confidence, PredictionConfidence::Low);

        let mut low_sample = admissible_input();
        low_sample.attribution_state = PrefetchFeedbackAttributionState::InsufficientSample;
        low_sample.attribution.verdict =
            StorageIntentMeasurementAttributionVerdict::InsufficientSample;

        let low_sample_record = evaluate_prefetch_feedback(low_sample);
        assert_eq!(
            low_sample_record.verdict,
            PrefetchFeedbackVerdict::InsufficientSample
        );
        assert!(!low_sample_record.may_train_confidence_upward());
        assert!(low_sample_record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE));
    }

    #[test]
    fn cache_only_success_stays_non_authority() {
        let mut input = admissible_input();
        input.executor.executor_byte_state = PrefetchExecutorByteState::CacheOnly;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::Neutral);
        assert_eq!(
            record.confidence_update,
            PrefetchFeedbackConfidenceUpdate::None
        );
        assert!(!record.may_train_confidence_upward());
        assert!(!record.may_close_payback());
        assert!(!record.may_emit_movement_candidate());
        assert!(!record.may_support_public_or_comparator_claim());
    }

    #[test]
    fn failed_payback_lowers_confidence_and_emits_demotion_candidate() {
        let mut input = admissible_input();
        input.executor.result_detail.used_bytes = 0;
        input.executor.result_detail.unused_bytes = input.executor.result_detail.prefetched_bytes;
        input.executor.result_detail.latency_benefit_us = 1000;
        input.executor.anti_waste = PrefetchExecutorAntiWasteMask::FAILED_PAYBACK;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::Wasteful);
        assert_eq!(
            record.confidence_update,
            PrefetchFeedbackConfidenceUpdate::LowerOneStep
        );
        assert_eq!(record.next_confidence, PredictionConfidence::Low);
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::COOLDOWN));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE));
        assert_eq!(
            record.next_candidate,
            PrefetchResidencyCandidateClass::DemotionCandidate
        );
        assert_eq!(
            record.next_residency,
            PrefetchResidencyStateClass::CacheOnlyRam
        );
        assert_eq!(record.next_prefetch_window_bytes, 0);
        assert!(record.cooldown_ms > 0);
        assert!(!record.can_retire_source_receipt());
    }

    #[test]
    fn missing_cost_wear_and_egress_refuse_persistent_promotion() {
        let mut input = admissible_input();
        input.executor.cost_state.unknown_waf = true;
        input.executor.cost_state.unknown_egress_or_restore_cost = true;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::MissingCostWear);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!record.may_train_confidence_upward());
        assert!(!record.may_request_flash_budget_candidate());
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE));
    }

    #[test]
    fn protected_reserve_pressure_refuses_over_budget_feedback() {
        let mut input = admissible_input();
        input.executor.admission.reserve_protected = true;
        input.executor.result_detail.protected_reserve_pressure = true;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::OverBudget);
        assert_eq!(record.refusal, StorageIntentRefusalReason::OverBudget);
        assert!(!record.may_train_confidence_upward());
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::COOLDOWN));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::TYPED_REFUSAL));
    }

    #[test]
    fn comparator_claims_require_explicit_attribution_permission() {
        let mut input = admissible_input();
        input.attribution.allowed_uses = all_authority_uses().without(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM,
        );

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::Beneficial);
        assert!(record.may_train_confidence_upward());
        assert!(record.may_close_payback());
        assert!(!record.may_support_public_or_comparator_claim());
    }

    #[test]
    fn one_pass_scan_demotes_and_blocks_persistent_promotion() {
        let mut input = admissible_input();
        input.executor.anti_waste = PrefetchExecutorAntiWasteMask::ONE_PASS_SCAN;
        input.executor.access_pattern = AccessPatternClass::OnePassScan;
        input.executor.target_media = StorageMediaClass::NvmeFlash;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::OnePassScan);
        assert_eq!(
            record.confidence_update,
            PrefetchFeedbackConfidenceUpdate::LowerOneStep
        );
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::EXPLICIT_NO_PREFETCH));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::COOLDOWN));
        assert_eq!(
            record.next_candidate,
            PrefetchResidencyCandidateClass::DemotionCandidate
        );
        assert_eq!(record.next_prefetch_window_bytes, 0);
        assert!(record.cooldown_ms > 0);
        assert!(!record.can_retire_source_receipt());
    }

    #[test]
    fn phase_changed_workload_cools_down_and_demotes() {
        let mut input = admissible_input();
        input.executor.anti_waste = PrefetchExecutorAntiWasteMask::PHASE_CHANGE;
        input.executor.access_pattern = AccessPatternClass::PhaseChangingSparse;
        input.executor.target_media = StorageMediaClass::NvmeFlash;

        let record = evaluate_prefetch_feedback(input);

        assert_eq!(record.verdict, PrefetchFeedbackVerdict::PhaseChanged);
        assert_eq!(
            record.confidence_update,
            PrefetchFeedbackConfidenceUpdate::LowerOneStep
        );
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::LOWER_ACTION_CLASS));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::DEMOTION_CANDIDATE));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::COOLDOWN));
        assert!(record
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::EXTEND_DWELL));
        assert_eq!(
            record.next_candidate,
            PrefetchResidencyCandidateClass::DemotionCandidate
        );
        assert!(record.cooldown_ms > 0);
        assert!(!record.can_retire_source_receipt());
    }

    #[test]
    fn repeated_beneficial_records_keep_only_bounded_sustained_positive_state() {
        let record = evaluate_prefetch_feedback(admissible_input());

        let checkpoint = reduce_prefetch_feedback_learning_window(&[record, record]);

        assert_eq!(
            checkpoint.state,
            PrefetchFeedbackLearningWindowState::SustainedPositiveBounded
        );
        assert_eq!(checkpoint.records_seen, 2);
        assert_eq!(checkpoint.matched_records, 2);
        assert_eq!(checkpoint.beneficial_records, 2);
        assert_eq!(checkpoint.conservative_records, 0);
        assert_eq!(
            checkpoint.confidence_update,
            PrefetchFeedbackConfidenceUpdate::CapAtCurrent
        );
        assert_eq!(checkpoint.next_confidence, PredictionConfidence::High);
        assert!(checkpoint.may_keep_confidence_raised());
        assert!(checkpoint.may_close_payback());
        assert!(checkpoint
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::PAYBACK_CANDIDATE));
        assert!(!checkpoint.adjustments.intersects(
            PrefetchFeedbackAdjustmentMask::PROMOTION_CANDIDATE
                .union(PrefetchFeedbackAdjustmentMask::MOVEMENT_DEBT_CANDIDATE),
        ));
        assert!(!checkpoint.allowed_uses.contains_all(
            StorageIntentMeasurementAttributionUseMask::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET,
        ));
        assert!(!checkpoint.allowed_uses.contains_all(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM,
        ));
        assert!(!checkpoint.can_publish_replacement_receipt());
        assert!(!checkpoint.can_retire_source_receipt());
        assert!(!checkpoint.can_spend_extra_flash_movement_budget());
        assert!(!checkpoint.may_support_public_or_comparator_claim());
    }

    #[test]
    fn single_beneficial_record_needs_more_window_evidence() {
        let record = evaluate_prefetch_feedback(admissible_input());

        let checkpoint = reduce_prefetch_feedback_learning_window(&[record]);

        assert_eq!(
            checkpoint.state,
            PrefetchFeedbackLearningWindowState::NeedMoreEvidence
        );
        assert_eq!(
            checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::SinglePositiveRecord
        );
        assert_eq!(
            checkpoint.confidence_update,
            PrefetchFeedbackConfidenceUpdate::None
        );
        assert_eq!(checkpoint.next_confidence, PredictionConfidence::Medium);
        assert!(!checkpoint.may_keep_confidence_raised());
        assert!(!checkpoint.may_close_payback());
        assert!(checkpoint
            .adjustments
            .contains_all(PrefetchFeedbackAdjustmentMask::NEED_MORE_EVIDENCE));
    }

    #[test]
    fn mismatched_scope_and_evidence_envelopes_do_not_aggregate() {
        let record = evaluate_prefetch_feedback(admissible_input());
        let mut wrong_scope = record;
        wrong_scope.scope.budget_owner = domain(77);

        let scope_checkpoint = reduce_prefetch_feedback_learning_window(&[record, wrong_scope]);

        assert_eq!(
            scope_checkpoint.state,
            PrefetchFeedbackLearningWindowState::Reset
        );
        assert_eq!(
            scope_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::MismatchedScope
        );
        assert!(!scope_checkpoint.may_keep_confidence_raised());
        assert!(!scope_checkpoint.may_close_payback());

        let mut wrong_envelope = record;
        wrong_envelope.evidence_refs.target_media_ref =
            evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, 99);

        let envelope_checkpoint =
            reduce_prefetch_feedback_learning_window(&[record, wrong_envelope]);

        assert_eq!(
            envelope_checkpoint.state,
            PrefetchFeedbackLearningWindowState::Reset
        );
        assert_eq!(
            envelope_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::MismatchedEvidenceEnvelope
        );
        assert!(!envelope_checkpoint.may_keep_confidence_raised());
        assert!(!envelope_checkpoint.may_close_payback());
    }

    #[test]
    fn low_sample_and_confounded_records_break_positive_window() {
        let record = evaluate_prefetch_feedback(admissible_input());

        let mut low_sample = admissible_input();
        low_sample.attribution_state = PrefetchFeedbackAttributionState::InsufficientSample;
        low_sample.attribution.verdict =
            StorageIntentMeasurementAttributionVerdict::InsufficientSample;
        let low_sample_record = evaluate_prefetch_feedback(low_sample);

        let low_sample_checkpoint =
            reduce_prefetch_feedback_learning_window(&[record, low_sample_record]);

        assert_eq!(
            low_sample_checkpoint.state,
            PrefetchFeedbackLearningWindowState::NeedMoreEvidence
        );
        assert_eq!(
            low_sample_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::LowSample
        );
        assert!(!low_sample_checkpoint.may_keep_confidence_raised());
        assert!(!low_sample_checkpoint.may_close_payback());

        let mut confounded = admissible_input();
        confounded.attribution_state = PrefetchFeedbackAttributionState::Confounded;
        confounded.attribution.verdict = StorageIntentMeasurementAttributionVerdict::Confounded;
        let confounded_record = evaluate_prefetch_feedback(confounded);

        let confounded_checkpoint =
            reduce_prefetch_feedback_learning_window(&[record, confounded_record]);

        assert_eq!(
            confounded_checkpoint.state,
            PrefetchFeedbackLearningWindowState::Refused
        );
        assert_eq!(
            confounded_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::ComparatorConfounded
        );
        assert!(!confounded_checkpoint.may_keep_confidence_raised());
        assert!(!confounded_checkpoint.may_close_payback());
    }

    #[test]
    fn wasteful_records_cool_down_learning_window() {
        let record = evaluate_prefetch_feedback(admissible_input());
        let mut wasteful = admissible_input();
        wasteful.executor.result_detail.used_bytes = 0;
        wasteful.executor.result_detail.unused_bytes =
            wasteful.executor.result_detail.prefetched_bytes;
        wasteful.executor.result_detail.latency_benefit_us = 1000;
        wasteful.executor.anti_waste = PrefetchExecutorAntiWasteMask::FAILED_PAYBACK;
        let wasteful_record = evaluate_prefetch_feedback(wasteful);

        let checkpoint = reduce_prefetch_feedback_learning_window(&[record, wasteful_record]);

        assert_eq!(
            checkpoint.state,
            PrefetchFeedbackLearningWindowState::Cooldown
        );
        assert_eq!(
            checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::Wasteful
        );
        assert_eq!(
            checkpoint.confidence_update,
            PrefetchFeedbackConfidenceUpdate::LowerOneStep
        );
        assert!(checkpoint.cooldown_ms > 0);
        assert!(!checkpoint.may_keep_confidence_raised());
        assert!(!checkpoint.may_close_payback());
    }

    #[test]
    fn missing_retention_or_cost_blocks_checkpoint_authority_positive_state() {
        let record = evaluate_prefetch_feedback(admissible_input());
        let mut missing_retention = record;
        missing_retention.retention_state = PrefetchFeedbackRetentionState::Unavailable;

        let retention_checkpoint = reduce_prefetch_feedback_learning_window(&[missing_retention]);

        assert_eq!(
            retention_checkpoint.state,
            PrefetchFeedbackLearningWindowState::Refused
        );
        assert_eq!(
            retention_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::MissingRetentionEvidence
        );
        assert!(!retention_checkpoint.may_keep_confidence_raised());
        assert!(!retention_checkpoint.may_close_payback());

        let mut unknown_cost = record;
        unknown_cost.materialization_cost_state =
            PrefetchFeedbackMaterializationCostState::UnknownConservative;

        let cost_checkpoint = reduce_prefetch_feedback_learning_window(&[unknown_cost]);

        assert_eq!(
            cost_checkpoint.state,
            PrefetchFeedbackLearningWindowState::Cooldown
        );
        assert_eq!(
            cost_checkpoint.refusal_state,
            PrefetchFeedbackLearningRefusal::UnknownMaterializationCost
        );
        assert!(!cost_checkpoint.may_keep_confidence_raised());
        assert!(!cost_checkpoint.may_close_payback());
    }

    #[test]
    fn feedback_record_never_retires_or_spends_by_itself() {
        let record = PrefetchFeedbackRecord::default();

        assert!(!record.can_retire_source_receipt());
        assert!(!record.can_publish_replacement_receipt());
        assert!(!record.can_spend_extra_flash_movement_budget());
    }
}
