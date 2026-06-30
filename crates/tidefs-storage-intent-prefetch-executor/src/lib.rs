// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Storage-intent prefetch and staging executor boundary (#972).
//!
//! This crate records what a prefetch executor may attempt after #967 has
//! already selected a legal prefetch/residency decision and #913 has supplied a
//! lawful evidence cut. It does not move bytes, wire FUSE/block/transport
//! adapters, publish replacement receipts, retire sources, satisfy durable sync,
//! decide placement, or make performance/product claims.

use core::fmt;

use tidefs_storage_intent_core::{
    AccessPatternClass, EvidenceCompletenessVerdict, EvidenceQuerySubjectScopeClass,
    PredictionConfidence, PrefetchResidencyCandidateClass, PrefetchResidencyDecisionOutcome,
    PrefetchResidencyDecisionRecord, PrefetchResidencyStateClass, StorageIntentActionClass,
    StorageIntentDomainId, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef, StorageIntentEvidenceRefs,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
    StorageIntentRefusalReason, StorageMediaClass,
};
use tidefs_storage_intent_cost::{
    StorageIntentCostClass, StorageIntentCostEvidenceState, StorageIntentCostSnapshot,
};

macro_rules! impl_u8_canonical {
    ($ty:ident, { $($variant:ident = $value:literal => $name:literal),+ $(,)? }) => {
        impl $ty {
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }

            #[must_use]
            pub const fn to_discriminant(self) -> u8 {
                self as u8
            }

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

pub const STORAGE_INTENT_PREFETCH_EXECUTOR_VERSION: u16 = 1;
pub const STORAGE_INTENT_PREFETCH_EXECUTOR_SPEC: &str =
    "tidefs-storage-intent-prefetch-executor-v1-issue-972";

const EMPTY_EVIDENCE_REF: StorageIntentEvidenceRef = StorageIntentEvidenceRef {
    kind: StorageIntentEvidenceKind::Unknown,
    id: StorageIntentEvidenceId::ZERO,
    generation: 0,
    version: 0,
};

const EMPTY_SCOPE: StorageIntentObjectScope = StorageIntentObjectScope {
    dataset_id: StorageIntentDomainId::ZERO,
    object_id: StorageIntentEvidenceId::ZERO,
    range_start: 0,
    range_len: 0,
    generation: 0,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorActionFamily {
    #[default]
    Unknown = 0,
    BoundedSequentialReadahead = 1,
    StridedVectorRangePrefetch = 2,
    MetadataNamespaceWalkPrefetch = 3,
    SmallRandomHotsetCacheTrial = 4,
    ManifestIndexFanout = 5,
    SnapshotCloneRepeatedRead = 6,
    DegradedReadReconstruction = 7,
    WanGeoDeltaPrefetch = 8,
    ObjectArchiveRestoreStaging = 9,
    ExplicitNoPrefetch = 10,
    AuthorityChangingHandoff = 11,
    Unsupported = 12,
}

impl_u8_canonical!(PrefetchExecutorActionFamily, {
    Unknown = 0 => "unknown",
    BoundedSequentialReadahead = 1 => "bounded-sequential-readahead",
    StridedVectorRangePrefetch = 2 => "strided-vector-range-prefetch",
    MetadataNamespaceWalkPrefetch = 3 => "metadata-namespace-walk-prefetch",
    SmallRandomHotsetCacheTrial = 4 => "small-random-hotset-cache-trial",
    ManifestIndexFanout = 5 => "manifest-index-fanout",
    SnapshotCloneRepeatedRead = 6 => "snapshot-clone-repeated-read",
    DegradedReadReconstruction = 7 => "degraded-read-reconstruction",
    WanGeoDeltaPrefetch = 8 => "wan-geo-delta-prefetch",
    ObjectArchiveRestoreStaging = 9 => "object-archive-restore-staging",
    ExplicitNoPrefetch = 10 => "explicit-no-prefetch",
    AuthorityChangingHandoff = 11 => "authority-changing-handoff",
    Unsupported = 12 => "unsupported",
});

impl PrefetchExecutorActionFamily {
    #[must_use]
    pub const fn from_candidate(candidate: PrefetchResidencyCandidateClass) -> Self {
        match candidate {
            PrefetchResidencyCandidateClass::NoPrefetch => Self::ExplicitNoPrefetch,
            PrefetchResidencyCandidateClass::BoundedReadahead => Self::BoundedSequentialReadahead,
            PrefetchResidencyCandidateClass::StridedVectorPrefetch => {
                Self::StridedVectorRangePrefetch
            }
            PrefetchResidencyCandidateClass::MetadataNamespacePrefetch => {
                Self::MetadataNamespaceWalkPrefetch
            }
            PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
            | PrefetchResidencyCandidateClass::CacheOnlyTrial
            | PrefetchResidencyCandidateClass::VolatileRamTrial => {
                Self::SmallRandomHotsetCacheTrial
            }
            PrefetchResidencyCandidateClass::ManifestIndexPrefetch => Self::ManifestIndexFanout,
            PrefetchResidencyCandidateClass::SnapshotClonePrefetch => {
                Self::SnapshotCloneRepeatedRead
            }
            PrefetchResidencyCandidateClass::DegradedReadPrefetch => {
                Self::DegradedReadReconstruction
            }
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch => Self::WanGeoDeltaPrefetch,
            PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage => {
                Self::ObjectArchiveRestoreStaging
            }
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            | PrefetchResidencyCandidateClass::DemotionCandidate
            | PrefetchResidencyCandidateClass::IntentBackedRam
            | PrefetchResidencyCandidateClass::PmemDurable => Self::AuthorityChangingHandoff,
            PrefetchResidencyCandidateClass::FlashHotServing
            | PrefetchResidencyCandidateClass::HddLocalityOptimized => {
                Self::BoundedSequentialReadahead
            }
            PrefetchResidencyCandidateClass::Cooldown
            | PrefetchResidencyCandidateClass::NeedMoreEvidence
            | PrefetchResidencyCandidateClass::Refused => Self::Unsupported,
        }
    }

    #[must_use]
    pub const fn action_class(self) -> StorageIntentActionClass {
        match self {
            Self::ExplicitNoPrefetch
            | Self::BoundedSequentialReadahead
            | Self::StridedVectorRangePrefetch
            | Self::ManifestIndexFanout
            | Self::SnapshotCloneRepeatedRead => StorageIntentActionClass::QueuePrefetchTuning,
            Self::MetadataNamespaceWalkPrefetch => StorageIntentActionClass::ReadSourceRefresh,
            Self::SmallRandomHotsetCacheTrial => StorageIntentActionClass::CacheOnlyServingTrial,
            Self::DegradedReadReconstruction => {
                StorageIntentActionClass::DegradedReadReconstruction
            }
            Self::WanGeoDeltaPrefetch => StorageIntentActionClass::GeoCatchup,
            Self::ObjectArchiveRestoreStaging => StorageIntentActionClass::ArchiveMigration,
            Self::AuthorityChangingHandoff => StorageIntentActionClass::AuthorityPromotion,
            Self::Unknown | Self::Unsupported => StorageIntentActionClass::QueuePrefetchTuning,
        }
    }

    #[must_use]
    pub const fn needs_remote_path_evidence(self) -> bool {
        matches!(
            self,
            Self::WanGeoDeltaPrefetch | Self::ObjectArchiveRestoreStaging
        )
    }

    #[must_use]
    pub const fn needs_metadata_namespace_evidence(self) -> bool {
        matches!(
            self,
            Self::MetadataNamespaceWalkPrefetch
                | Self::ManifestIndexFanout
                | Self::SnapshotCloneRepeatedRead
        )
    }

    #[must_use]
    pub const fn is_negative_enforcement(self) -> bool {
        matches!(self, Self::ExplicitNoPrefetch)
    }

    #[must_use]
    pub const fn can_start_runtime_dispatch(self) -> bool {
        matches!(
            self,
            Self::BoundedSequentialReadahead
                | Self::StridedVectorRangePrefetch
                | Self::MetadataNamespaceWalkPrefetch
                | Self::SmallRandomHotsetCacheTrial
                | Self::ManifestIndexFanout
                | Self::SnapshotCloneRepeatedRead
                | Self::DegradedReadReconstruction
                | Self::WanGeoDeltaPrefetch
                | Self::ObjectArchiveRestoreStaging
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorByteState {
    #[default]
    Unknown = 0,
    CacheOnly = 1,
    CacheOnlyTrial = 2,
    Staged = 3,
    DegradedVisible = 4,
    NoPrefetchEnforced = 5,
    HandoffRequired = 6,
    Blocked = 7,
    Refused = 8,
    Unavailable = 9,
}

impl_u8_canonical!(PrefetchExecutorByteState, {
    Unknown = 0 => "unknown",
    CacheOnly = 1 => "cache-only",
    CacheOnlyTrial = 2 => "cache-only-trial",
    Staged = 3 => "staged",
    DegradedVisible = 4 => "degraded-visible",
    NoPrefetchEnforced = 5 => "no-prefetch-enforced",
    HandoffRequired = 6 => "handoff-required",
    Blocked = 7 => "blocked",
    Refused = 8 => "refused",
    Unavailable = 9 => "unavailable",
});

impl PrefetchExecutorByteState {
    #[must_use]
    pub const fn is_non_authority(self) -> bool {
        matches!(
            self,
            Self::CacheOnly
                | Self::CacheOnlyTrial
                | Self::Staged
                | Self::DegradedVisible
                | Self::NoPrefetchEnforced
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorOutcome {
    #[default]
    Unknown = 0,
    Started = 1,
    Dropped = 2,
    Throttled = 3,
    Completed = 4,
    Stale = 5,
    TimedOut = 6,
    Refused = 7,
    DegradedVisible = 8,
    OverBudget = 9,
    VerificationFailed = 10,
    HandoffRequired = 11,
    Blocked = 12,
    Unavailable = 13,
}

impl_u8_canonical!(PrefetchExecutorOutcome, {
    Unknown = 0 => "unknown",
    Started = 1 => "started",
    Dropped = 2 => "dropped",
    Throttled = 3 => "throttled",
    Completed = 4 => "completed",
    Stale = 5 => "stale",
    TimedOut = 6 => "timed-out",
    Refused = 7 => "refused",
    DegradedVisible = 8 => "degraded-visible",
    OverBudget = 9 => "over-budget",
    VerificationFailed = 10 => "verification-failed",
    HandoffRequired = 11 => "handoff-required",
    Blocked = 12 => "blocked",
    Unavailable = 13 => "unavailable",
});

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorSchedulerLane {
    #[default]
    Unknown = 0,
    Control = 1,
    Metadata = 2,
    Demand = 3,
    Speculative = 4,
    Background = 5,
}

impl_u8_canonical!(PrefetchExecutorSchedulerLane, {
    Unknown = 0 => "unknown",
    Control = 1 => "control",
    Metadata = 2 => "metadata",
    Demand = 3 => "demand",
    Speculative = 4 => "speculative",
    Background = 5 => "background",
});

impl PrefetchExecutorSchedulerLane {
    #[must_use]
    pub const fn for_action_family(family: PrefetchExecutorActionFamily) -> Self {
        match family.action_class() {
            StorageIntentActionClass::ReadTriggeredRepair
            | StorageIntentActionClass::DegradedReadReconstruction => Self::Metadata,
            StorageIntentActionClass::NewWriteShaping
            | StorageIntentActionClass::AuthorityPromotion
            | StorageIntentActionClass::DurablePlacementMovement
            | StorageIntentActionClass::ReadSourceRefresh => Self::Demand,
            StorageIntentActionClass::QueuePrefetchTuning
            | StorageIntentActionClass::CacheOnlyServingTrial
            | StorageIntentActionClass::FlashServingPromotion => Self::Speculative,
            StorageIntentActionClass::DefragRepack
            | StorageIntentActionClass::ReclaimRelocation
            | StorageIntentActionClass::GeoCatchup
            | StorageIntentActionClass::ArchiveMigration => Self::Background,
        }
    }

    #[must_use]
    pub const fn priority_rank(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Metadata => 1,
            Self::Demand => 2,
            Self::Speculative => 3,
            Self::Background => 4,
            Self::Unknown => 5,
        }
    }

    #[must_use]
    pub const fn is_stricter_than(self, other: Self) -> bool {
        self.priority_rank() < other.priority_rank()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorAdmissionOutcome {
    #[default]
    Unknown = 0,
    Admitted = 1,
    Dropped = 2,
    Throttled = 3,
    Expired = 4,
    Refused = 5,
    Blocked = 6,
    Unavailable = 7,
}

impl_u8_canonical!(PrefetchExecutorAdmissionOutcome, {
    Unknown = 0 => "unknown",
    Admitted = 1 => "admitted",
    Dropped = 2 => "dropped",
    Throttled = 3 => "throttled",
    Expired = 4 => "expired",
    Refused = 5 => "refused",
    Blocked = 6 => "blocked",
    Unavailable = 7 => "unavailable",
});

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorRecoveryEscalationClass {
    #[default]
    None = 0,
    DegradedRiskReduction = 1,
    RepairEscalation = 2,
    EvacuationEscalation = 3,
    GeoCatchupEscalation = 4,
    ReplacementReceiptRisk = 5,
}

impl_u8_canonical!(PrefetchExecutorRecoveryEscalationClass, {
    None = 0 => "none",
    DegradedRiskReduction = 1 => "degraded-risk-reduction",
    RepairEscalation = 2 => "repair-escalation",
    EvacuationEscalation = 3 => "evacuation-escalation",
    GeoCatchupEscalation = 4 => "geo-catchup-escalation",
    ReplacementReceiptRisk = 5 => "replacement-receipt-risk",
});

impl PrefetchExecutorRecoveryEscalationClass {
    #[must_use]
    pub const fn requires_recovery_degradation_evidence(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorPressureMask(pub u64);

impl PrefetchExecutorPressureMask {
    pub const EMPTY: Self = Self(0);
    pub const FOREGROUND_POSIX_SYNC: Self = Self(1_u64 << 0);
    pub const REPAIR: Self = Self(1_u64 << 1);
    pub const EVACUATION: Self = Self(1_u64 << 2);
    pub const RECEIPT_RETIREMENT: Self = Self(1_u64 << 3);
    pub const MEMORY: Self = Self(1_u64 << 4);
    pub const WEAR: Self = Self(1_u64 << 5);
    pub const EGRESS: Self = Self(1_u64 << 6);
    pub const RESTORE_COST: Self = Self(1_u64 << 7);
    pub const P99_LATENCY: Self = Self(1_u64 << 8);
    pub const PROTECTED_RESERVE: Self = Self(1_u64 << 9);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorAntiWasteMask(pub u64);

impl PrefetchExecutorAntiWasteMask {
    pub const EMPTY: Self = Self(0);
    pub const ONE_PASS_SCAN: Self = Self(1_u64 << 0);
    pub const PHASE_CHANGE: Self = Self(1_u64 << 1);
    pub const LOW_SAMPLE_MASS: Self = Self(1_u64 << 2);
    pub const CONTRADICTED_HINTS: Self = Self(1_u64 << 3);
    pub const MEMORY_ONLY_EVIDENCE: Self = Self(1_u64 << 4);
    pub const SAMPLED_AWAY: Self = Self(1_u64 << 5);
    pub const NOISY_NEIGHBOR_PRESSURE: Self = Self(1_u64 << 6);
    pub const FAILED_PAYBACK: Self = Self(1_u64 << 7);
    pub const LOW_DWELL: Self = Self(1_u64 << 8);
    pub const COOLDOWN: Self = Self(1_u64 << 9);
    pub const UNKNOWN_WAF: Self = Self(1_u64 << 10);
    pub const UNKNOWN_EGRESS_OR_RESTORE_COST: Self = Self(1_u64 << 11);
    pub const PROTECTED_RESERVE_PRESSURE: Self = Self(1_u64 << 12);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    #[must_use]
    pub const fn cancellation_mask() -> Self {
        Self(
            Self::ONE_PASS_SCAN.0
                | Self::PHASE_CHANGE.0
                | Self::LOW_SAMPLE_MASS.0
                | Self::CONTRADICTED_HINTS.0
                | Self::MEMORY_ONLY_EVIDENCE.0
                | Self::SAMPLED_AWAY.0
                | Self::NOISY_NEIGHBOR_PRESSURE.0
                | Self::FAILED_PAYBACK.0
                | Self::LOW_DWELL.0
                | Self::COOLDOWN.0
                | Self::UNKNOWN_WAF.0
                | Self::UNKNOWN_EGRESS_OR_RESTORE_COST.0
                | Self::PROTECTED_RESERVE_PRESSURE.0,
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorCostRequirementMask(pub u64);

impl PrefetchExecutorCostRequirementMask {
    pub const EMPTY: Self = Self(0);
    pub const FLASH_WRITES: Self = Self(1_u64 << 0);
    pub const CACHE_DEVICE_INDEXES: Self = Self(1_u64 << 1);
    pub const PREDICTOR_CHECKPOINTS: Self = Self(1_u64 << 2);
    pub const RETAINED_EVIDENCE: Self = Self(1_u64 << 3);
    pub const RAM_PMEM_CAPACITY: Self = Self(1_u64 << 4);
    pub const CPU: Self = Self(1_u64 << 5);
    pub const MEMORY: Self = Self(1_u64 << 6);
    pub const WAN_BANDWIDTH: Self = Self(1_u64 << 7);
    pub const EGRESS: Self = Self(1_u64 << 8);
    pub const OBJECT_ARCHIVE_RESTORE_CALLS: Self = Self(1_u64 << 9);
    pub const STAGING_CAPACITY: Self = Self(1_u64 << 10);
    pub const FOREGROUND_DISRUPTION: Self = Self(1_u64 << 11);

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorRuntimeSupportMask(pub u64);

impl PrefetchExecutorRuntimeSupportMask {
    pub const EMPTY: Self = Self(0);
    pub const BOUNDED_SEQUENTIAL_READAHEAD: Self = Self(1_u64 << 0);
    pub const STRIDED_VECTOR_RANGE_PREFETCH: Self = Self(1_u64 << 1);
    pub const METADATA_NAMESPACE_WALK_PREFETCH: Self = Self(1_u64 << 2);
    pub const SMALL_RANDOM_HOTSET_CACHE_TRIAL: Self = Self(1_u64 << 3);
    pub const MANIFEST_INDEX_FANOUT: Self = Self(1_u64 << 4);
    pub const SNAPSHOT_CLONE_REPEATED_READ: Self = Self(1_u64 << 5);
    pub const DEGRADED_READ_RECONSTRUCTION: Self = Self(1_u64 << 6);
    pub const WAN_GEO_DELTA_PREFETCH: Self = Self(1_u64 << 7);
    pub const OBJECT_ARCHIVE_RESTORE_STAGING: Self = Self(1_u64 << 8);
    pub const ALL_MODELLED_DISPATCH: Self = Self(
        Self::BOUNDED_SEQUENTIAL_READAHEAD.0
            | Self::STRIDED_VECTOR_RANGE_PREFETCH.0
            | Self::METADATA_NAMESPACE_WALK_PREFETCH.0
            | Self::SMALL_RANDOM_HOTSET_CACHE_TRIAL.0
            | Self::MANIFEST_INDEX_FANOUT.0
            | Self::SNAPSHOT_CLONE_REPEATED_READ.0
            | Self::DEGRADED_READ_RECONSTRUCTION.0
            | Self::WAN_GEO_DELTA_PREFETCH.0
            | Self::OBJECT_ARCHIVE_RESTORE_STAGING.0,
    );

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn for_action_family(family: PrefetchExecutorActionFamily) -> Self {
        match family {
            PrefetchExecutorActionFamily::BoundedSequentialReadahead => {
                Self::BOUNDED_SEQUENTIAL_READAHEAD
            }
            PrefetchExecutorActionFamily::StridedVectorRangePrefetch => {
                Self::STRIDED_VECTOR_RANGE_PREFETCH
            }
            PrefetchExecutorActionFamily::MetadataNamespaceWalkPrefetch => {
                Self::METADATA_NAMESPACE_WALK_PREFETCH
            }
            PrefetchExecutorActionFamily::SmallRandomHotsetCacheTrial => {
                Self::SMALL_RANDOM_HOTSET_CACHE_TRIAL
            }
            PrefetchExecutorActionFamily::ManifestIndexFanout => Self::MANIFEST_INDEX_FANOUT,
            PrefetchExecutorActionFamily::SnapshotCloneRepeatedRead => {
                Self::SNAPSHOT_CLONE_REPEATED_READ
            }
            PrefetchExecutorActionFamily::DegradedReadReconstruction => {
                Self::DEGRADED_READ_RECONSTRUCTION
            }
            PrefetchExecutorActionFamily::WanGeoDeltaPrefetch => Self::WAN_GEO_DELTA_PREFETCH,
            PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging => {
                Self::OBJECT_ARCHIVE_RESTORE_STAGING
            }
            PrefetchExecutorActionFamily::Unknown
            | PrefetchExecutorActionFamily::ExplicitNoPrefetch
            | PrefetchExecutorActionFamily::AuthorityChangingHandoff
            | PrefetchExecutorActionFamily::Unsupported => Self::EMPTY,
        }
    }

    #[must_use]
    pub const fn supports_family(self, family: PrefetchExecutorActionFamily) -> bool {
        family.can_start_runtime_dispatch() && self.contains(Self::for_action_family(family))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorRuntimeSupport {
    pub supported: PrefetchExecutorRuntimeSupportMask,
    pub support_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for PrefetchExecutorRuntimeSupport {
    fn default() -> Self {
        Self {
            supported: PrefetchExecutorRuntimeSupportMask::EMPTY,
            support_ref: EMPTY_EVIDENCE_REF,
            refusal: StorageIntentRefusalReason::EvidenceNotUsable,
        }
    }
}

impl PrefetchExecutorRuntimeSupport {
    #[must_use]
    pub const fn supported(
        supported: PrefetchExecutorRuntimeSupportMask,
        support_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            supported,
            support_ref,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    #[must_use]
    pub const fn supports_family(self, family: PrefetchExecutorActionFamily) -> bool {
        self.support_ref.kind as u16 == StorageIntentEvidenceKind::ActionExecutionEvidence as u16
            && self.support_ref.is_bound()
            && self.supported.supports_family(family)
    }

    #[must_use]
    pub const fn refusal_reason(self) -> StorageIntentRefusalReason {
        if matches!(self.refusal, StorageIntentRefusalReason::None) {
            StorageIntentRefusalReason::EvidenceNotUsable
        } else {
            self.refusal
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorDispatchShape {
    #[default]
    Unknown = 0,
    BoundedRange = 1,
    StridedVectorRanges = 2,
    MetadataNamespaceWalk = 3,
    HotsetCacheTrial = 4,
    ManifestIndexFanout = 5,
    SnapshotCloneRanges = 6,
    DegradedReconstructionRange = 7,
    WanGeoDeltaRange = 8,
    ObjectArchiveRestoreRange = 9,
}

impl_u8_canonical!(PrefetchExecutorDispatchShape, {
    Unknown = 0 => "unknown",
    BoundedRange = 1 => "bounded-range",
    StridedVectorRanges = 2 => "strided-vector-ranges",
    MetadataNamespaceWalk = 3 => "metadata-namespace-walk",
    HotsetCacheTrial = 4 => "hotset-cache-trial",
    ManifestIndexFanout = 5 => "manifest-index-fanout",
    SnapshotCloneRanges = 6 => "snapshot-clone-ranges",
    DegradedReconstructionRange = 7 => "degraded-reconstruction-range",
    WanGeoDeltaRange = 8 => "wan-geo-delta-range",
    ObjectArchiveRestoreRange = 9 => "object-archive-restore-range",
});

impl PrefetchExecutorDispatchShape {
    #[must_use]
    pub const fn for_action_family(family: PrefetchExecutorActionFamily) -> Self {
        match family {
            PrefetchExecutorActionFamily::BoundedSequentialReadahead => Self::BoundedRange,
            PrefetchExecutorActionFamily::StridedVectorRangePrefetch => Self::StridedVectorRanges,
            PrefetchExecutorActionFamily::MetadataNamespaceWalkPrefetch => {
                Self::MetadataNamespaceWalk
            }
            PrefetchExecutorActionFamily::SmallRandomHotsetCacheTrial => Self::HotsetCacheTrial,
            PrefetchExecutorActionFamily::ManifestIndexFanout => Self::ManifestIndexFanout,
            PrefetchExecutorActionFamily::SnapshotCloneRepeatedRead => Self::SnapshotCloneRanges,
            PrefetchExecutorActionFamily::DegradedReadReconstruction => {
                Self::DegradedReconstructionRange
            }
            PrefetchExecutorActionFamily::WanGeoDeltaPrefetch => Self::WanGeoDeltaRange,
            PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging => {
                Self::ObjectArchiveRestoreRange
            }
            PrefetchExecutorActionFamily::Unknown
            | PrefetchExecutorActionFamily::ExplicitNoPrefetch
            | PrefetchExecutorActionFamily::AuthorityChangingHandoff
            | PrefetchExecutorActionFamily::Unsupported => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn matches_action_family(self, family: PrefetchExecutorActionFamily) -> bool {
        self as u8 == Self::for_action_family(family) as u8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorDispatchPlan {
    pub shape: PrefetchExecutorDispatchShape,
    pub range_start: u64,
    pub range_bytes: u64,
    pub stride_bytes: u64,
    pub range_count: u32,
    pub fanout_limit: u32,
    pub namespace_depth_limit: u16,
    pub expires_after_ms: u64,
    pub plan_ref: StorageIntentEvidenceRef,
}

impl Default for PrefetchExecutorDispatchPlan {
    fn default() -> Self {
        Self {
            shape: PrefetchExecutorDispatchShape::Unknown,
            range_start: 0,
            range_bytes: 0,
            stride_bytes: 0,
            range_count: 0,
            fanout_limit: 0,
            namespace_depth_limit: 0,
            expires_after_ms: 0,
            plan_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl PrefetchExecutorDispatchPlan {
    #[must_use]
    pub const fn bounded_range(
        range_start: u64,
        range_bytes: u64,
        plan_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            shape: PrefetchExecutorDispatchShape::BoundedRange,
            range_start,
            range_bytes,
            stride_bytes: 0,
            range_count: 1,
            fanout_limit: 0,
            namespace_depth_limit: 0,
            expires_after_ms: 0,
            plan_ref,
        }
    }

    #[must_use]
    pub const fn with_shape(mut self, shape: PrefetchExecutorDispatchShape) -> Self {
        self.shape = shape;
        self
    }

    #[must_use]
    pub const fn with_stride(mut self, stride_bytes: u64, range_count: u32) -> Self {
        self.stride_bytes = stride_bytes;
        self.range_count = range_count;
        self
    }

    #[must_use]
    pub const fn with_fanout_limit(mut self, fanout_limit: u32) -> Self {
        self.fanout_limit = fanout_limit;
        self
    }

    #[must_use]
    pub const fn with_namespace_depth_limit(mut self, namespace_depth_limit: u16) -> Self {
        self.namespace_depth_limit = namespace_depth_limit;
        self
    }

    #[must_use]
    pub const fn with_expires_after_ms(mut self, expires_after_ms: u64) -> Self {
        self.expires_after_ms = expires_after_ms;
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorCostState {
    pub snapshot: StorageIntentCostSnapshot,
    pub required: PrefetchExecutorCostRequirementMask,
    pub unknown_waf: bool,
    pub unknown_egress_or_restore_cost: bool,
    pub missing_isolation_evidence: bool,
    pub over_budget: bool,
    pub cost_ref: StorageIntentEvidenceRef,
    pub isolation_ref: StorageIntentEvidenceRef,
}

impl Default for PrefetchExecutorCostState {
    fn default() -> Self {
        Self {
            snapshot: StorageIntentCostSnapshot::default(),
            required: PrefetchExecutorCostRequirementMask::EMPTY,
            unknown_waf: false,
            unknown_egress_or_restore_cost: false,
            missing_isolation_evidence: false,
            over_budget: false,
            cost_ref: EMPTY_EVIDENCE_REF,
            isolation_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl PrefetchExecutorCostState {
    #[must_use]
    pub fn missing_required_cost(self) -> bool {
        self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::FLASH_WRITES,
            StorageIntentCostClass::CapacityMediaClass,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::CACHE_DEVICE_INDEXES,
            StorageIntentCostClass::CapacityMediaClass,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::PREDICTOR_CHECKPOINTS,
            StorageIntentCostClass::TransformProcessing,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::RETAINED_EVIDENCE,
            StorageIntentCostClass::ColdRetention,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::RAM_PMEM_CAPACITY,
            StorageIntentCostClass::CapacityMediaClass,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::CPU,
            StorageIntentCostClass::CpuProcessing,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::MEMORY,
            StorageIntentCostClass::MemoryUsage,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::WAN_BANDWIDTH,
            StorageIntentCostClass::NetworkIngress,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::EGRESS,
            StorageIntentCostClass::NetworkEgress,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS,
            StorageIntentCostClass::RestoreTime,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::STAGING_CAPACITY,
            StorageIntentCostClass::CapacityMediaClass,
        ) || self.missing_required_cost_class(
            PrefetchExecutorCostRequirementMask::FOREGROUND_DISRUPTION,
            StorageIntentCostClass::ForegroundDisruption,
        )
    }

    fn missing_required_cost_class(
        self,
        requirement: PrefetchExecutorCostRequirementMask,
        cost_class: StorageIntentCostClass,
    ) -> bool {
        self.required.contains(requirement)
            && class_missing_or_unknown(self.snapshot.evidence_state, cost_class)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorAdmissionRecord {
    pub lane: PrefetchExecutorSchedulerLane,
    pub outcome: PrefetchExecutorAdmissionOutcome,
    pub pressure: PrefetchExecutorPressureMask,
    pub droppable: bool,
    pub throttleable: bool,
    pub expirable: bool,
    pub recovery_escalation: PrefetchExecutorRecoveryEscalationClass,
    pub reserve_protected: bool,
    pub budget_owner: StorageIntentDomainId,
    pub requested_bytes: u64,
    pub admitted_bytes: u64,
    pub queue_time_us: u64,
    pub refusal: StorageIntentRefusalReason,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub recovery_degradation_ref: StorageIntentEvidenceRef,
}

impl Default for PrefetchExecutorAdmissionRecord {
    fn default() -> Self {
        Self {
            lane: PrefetchExecutorSchedulerLane::Unknown,
            outcome: PrefetchExecutorAdmissionOutcome::Unknown,
            pressure: PrefetchExecutorPressureMask::EMPTY,
            droppable: false,
            throttleable: false,
            expirable: false,
            recovery_escalation: PrefetchExecutorRecoveryEscalationClass::None,
            reserve_protected: false,
            budget_owner: StorageIntentDomainId::ZERO,
            requested_bytes: 0,
            admitted_bytes: 0,
            queue_time_us: 0,
            refusal: StorageIntentRefusalReason::None,
            scheduler_admission_ref: EMPTY_EVIDENCE_REF,
            recovery_degradation_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl PrefetchExecutorAdmissionRecord {
    #[must_use]
    pub const fn admitted(
        lane: PrefetchExecutorSchedulerLane,
        budget_owner: StorageIntentDomainId,
        evidence_ref: StorageIntentEvidenceRef,
    ) -> Self {
        Self {
            lane,
            outcome: PrefetchExecutorAdmissionOutcome::Admitted,
            pressure: PrefetchExecutorPressureMask::EMPTY,
            droppable: false,
            throttleable: true,
            expirable: false,
            recovery_escalation: PrefetchExecutorRecoveryEscalationClass::None,
            reserve_protected: false,
            budget_owner,
            requested_bytes: 0,
            admitted_bytes: 0,
            queue_time_us: 0,
            refusal: StorageIntentRefusalReason::None,
            scheduler_admission_ref: evidence_ref,
            recovery_degradation_ref: EMPTY_EVIDENCE_REF,
        }
    }

    #[must_use]
    pub const fn with_outcome(
        mut self,
        outcome: PrefetchExecutorAdmissionOutcome,
        refusal: StorageIntentRefusalReason,
    ) -> Self {
        self.outcome = outcome;
        self.refusal = refusal;
        self
    }

    #[must_use]
    pub const fn with_speculative_controls(
        mut self,
        droppable: bool,
        throttleable: bool,
        expirable: bool,
    ) -> Self {
        self.droppable = droppable;
        self.throttleable = throttleable;
        self.expirable = expirable;
        self
    }

    #[must_use]
    pub const fn with_recovery_escalation(
        mut self,
        escalation: PrefetchExecutorRecoveryEscalationClass,
        recovery_degradation_ref: StorageIntentEvidenceRef,
    ) -> Self {
        self.recovery_escalation = escalation;
        self.recovery_degradation_ref = recovery_degradation_ref;
        self
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorHandoffTarget {
    #[default]
    None = 0,
    Promotion = 1,
    Demotion = 2,
    SourceRetirement = 3,
    DurableResidencyChange = 4,
    ReceiptPublication = 5,
}

impl_u8_canonical!(PrefetchExecutorHandoffTarget, {
    None = 0 => "none",
    Promotion = 1 => "promotion",
    Demotion = 2 => "demotion",
    SourceRetirement = 3 => "source-retirement",
    DurableResidencyChange = 4 => "durable-residency-change",
    ReceiptPublication = 5 => "receipt-publication",
});

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchExecutorInterruptionClass {
    #[default]
    None = 0,
    InterruptedStaging = 1,
    WanStall = 2,
    CacheEviction = 3,
    CrashRestartReplay = 4,
    RuntimeAbort = 5,
}

impl_u8_canonical!(PrefetchExecutorInterruptionClass, {
    None = 0 => "none",
    InterruptedStaging = 1 => "interrupted-staging",
    WanStall = 2 => "wan-stall",
    CacheEviction = 3 => "cache-eviction",
    CrashRestartReplay = 4 => "crash-restart-replay",
    RuntimeAbort = 5 => "runtime-abort",
});

impl PrefetchExecutorInterruptionClass {
    #[must_use]
    pub const fn requires_terminal_evidence(self) -> bool {
        !matches!(self, Self::None)
    }

    #[must_use]
    pub const fn terminal_evidence_kind(self) -> StorageIntentEvidenceKind {
        StorageIntentEvidenceKind::ActionExecutionEvidence
    }

    #[must_use]
    pub const fn is_compatible_with_outcome(self, outcome: PrefetchExecutorOutcome) -> bool {
        match self {
            Self::None => true,
            Self::InterruptedStaging => matches!(
                outcome,
                PrefetchExecutorOutcome::Stale
                    | PrefetchExecutorOutcome::TimedOut
                    | PrefetchExecutorOutcome::VerificationFailed
                    | PrefetchExecutorOutcome::Blocked
                    | PrefetchExecutorOutcome::Unavailable
            ),
            Self::WanStall => matches!(
                outcome,
                PrefetchExecutorOutcome::Throttled
                    | PrefetchExecutorOutcome::TimedOut
                    | PrefetchExecutorOutcome::Blocked
                    | PrefetchExecutorOutcome::Unavailable
            ),
            Self::CacheEviction => matches!(
                outcome,
                PrefetchExecutorOutcome::Dropped
                    | PrefetchExecutorOutcome::Stale
                    | PrefetchExecutorOutcome::VerificationFailed
                    | PrefetchExecutorOutcome::Unavailable
            ),
            Self::CrashRestartReplay => matches!(
                outcome,
                PrefetchExecutorOutcome::Completed
                    | PrefetchExecutorOutcome::Stale
                    | PrefetchExecutorOutcome::TimedOut
                    | PrefetchExecutorOutcome::VerificationFailed
                    | PrefetchExecutorOutcome::Blocked
                    | PrefetchExecutorOutcome::Unavailable
            ),
            Self::RuntimeAbort => matches!(
                outcome,
                PrefetchExecutorOutcome::Dropped
                    | PrefetchExecutorOutcome::Refused
                    | PrefetchExecutorOutcome::VerificationFailed
                    | PrefetchExecutorOutcome::Blocked
                    | PrefetchExecutorOutcome::Unavailable
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorMediaPath {
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_path_ref: StorageIntentEvidenceRef,
    pub target_destination_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub transport_path_ref: StorageIntentEvidenceRef,
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub rdma_available: bool,
}

impl Default for PrefetchExecutorMediaPath {
    fn default() -> Self {
        Self {
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_path_ref: EMPTY_EVIDENCE_REF,
            target_destination_ref: EMPTY_EVIDENCE_REF,
            media_capability_ref: EMPTY_EVIDENCE_REF,
            transport_path_ref: EMPTY_EVIDENCE_REF,
            trust_domain_ref: EMPTY_EVIDENCE_REF,
            rdma_available: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorEvidenceRefs {
    pub compiled_policy_ref: StorageIntentEvidenceRef,
    pub prefetch_decision_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub cost_wear_ref: StorageIntentEvidenceRef,
    pub egress_restore_cost_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub source_path_ref: StorageIntentEvidenceRef,
    pub target_destination_ref: StorageIntentEvidenceRef,
    pub dispatch_plan_ref: StorageIntentEvidenceRef,
    pub runtime_support_ref: StorageIntentEvidenceRef,
    pub read_serving_boundary_ref: StorageIntentEvidenceRef,
    pub relocation_boundary_ref: StorageIntentEvidenceRef,
    pub result_refusal_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub transport_budget_ref: StorageIntentEvidenceRef,
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub recovery_degradation_ref: StorageIntentEvidenceRef,
    pub degraded_visibility_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub attribution_ref: StorageIntentEvidenceRef,
    pub validation_ref: StorageIntentEvidenceRef,
    pub interruption_ref: StorageIntentEvidenceRef,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorResultDetail {
    pub prefetched_bytes: u64,
    pub used_bytes: u64,
    pub unused_bytes: u64,
    pub expired_bytes: u64,
    pub latency_benefit_us: u64,
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
    pub attribution_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub validation_ref: StorageIntentEvidenceRef,
}

impl Default for PrefetchExecutorResultDetail {
    fn default() -> Self {
        Self {
            prefetched_bytes: 0,
            used_bytes: 0,
            unused_bytes: 0,
            expired_bytes: 0,
            latency_benefit_us: 0,
            latency_harm_us: 0,
            foreground_p50_disruption_us: 0,
            foreground_p95_disruption_us: 0,
            foreground_p99_disruption_us: 0,
            queue_delay_us: 0,
            flash_write_bytes: 0,
            pmem_write_bytes: 0,
            waf_micros: 0,
            ram_pressure_bytes: 0,
            cache_index_write_bytes: 0,
            predictor_metadata_write_bytes: 0,
            wan_bytes: 0,
            egress_cost_microunits: 0,
            restore_cost_microunits: 0,
            staging_capacity_bytes: 0,
            cpu_us: 0,
            memory_bytes: 0,
            protected_reserve_pressure: false,
            attribution_ref: EMPTY_EVIDENCE_REF,
            retention_ref: EMPTY_EVIDENCE_REF,
            validation_ref: EMPTY_EVIDENCE_REF,
        }
    }
}

impl PrefetchExecutorResultDetail {
    #[must_use]
    pub const fn has_usage_measurement(self) -> bool {
        self.prefetched_bytes != 0
            || self.used_bytes != 0
            || self.unused_bytes != 0
            || self.expired_bytes != 0
    }

    #[must_use]
    pub const fn has_latency_measurement(self) -> bool {
        self.latency_benefit_us != 0
            || self.latency_harm_us != 0
            || self.foreground_p50_disruption_us != 0
            || self.foreground_p95_disruption_us != 0
            || self.foreground_p99_disruption_us != 0
            || self.queue_delay_us != 0
    }

    #[must_use]
    pub const fn has_cost_or_pressure_measurement(self) -> bool {
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

    #[must_use]
    pub const fn has_feedback_payback_inputs(self) -> bool {
        self.has_usage_measurement()
            || self.has_latency_measurement()
            || self.has_cost_or_pressure_measurement()
    }

    #[must_use]
    pub fn charge_requirements(self) -> PrefetchExecutorCostRequirementMask {
        let mut required = PrefetchExecutorCostRequirementMask::EMPTY;

        if self.flash_write_bytes != 0 || self.waf_micros != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::FLASH_WRITES);
        }
        if self.pmem_write_bytes != 0 || self.ram_pressure_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::RAM_PMEM_CAPACITY);
        }
        if self.cache_index_write_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::CACHE_DEVICE_INDEXES);
        }
        if self.predictor_metadata_write_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::PREDICTOR_CHECKPOINTS);
        }
        if self.wan_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::WAN_BANDWIDTH);
        }
        if self.egress_cost_microunits != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::EGRESS);
        }
        if self.restore_cost_microunits != 0 {
            required =
                required.union(PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS);
        }
        if self.staging_capacity_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::STAGING_CAPACITY);
        }
        if self.cpu_us != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::CPU);
        }
        if self.memory_bytes != 0 {
            required = required.union(PrefetchExecutorCostRequirementMask::MEMORY);
        }
        if self.foreground_p50_disruption_us != 0
            || self.foreground_p95_disruption_us != 0
            || self.foreground_p99_disruption_us != 0
            || self.protected_reserve_pressure
        {
            required = required.union(PrefetchExecutorCostRequirementMask::FOREGROUND_DISRUPTION);
        }

        required
    }

    #[must_use]
    pub const fn has_feedback_evidence_roots(self) -> bool {
        self.attribution_ref.is_bound()
            && self.attribution_ref.kind as u16
                == StorageIntentEvidenceKind::MeasurementAttributionEvidence as u16
            && self.retention_ref.is_bound()
            && self.retention_ref.kind as u16
                == StorageIntentEvidenceKind::EvidenceRetentionEvidence as u16
            && self.validation_ref.is_bound()
            && self.validation_ref.kind as u16
                == StorageIntentEvidenceKind::ValidationArtifact as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorTerminalEvidenceCut {
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub included_refs: StorageIntentEvidenceRefs,
}

impl Default for PrefetchExecutorTerminalEvidenceCut {
    fn default() -> Self {
        Self {
            evidence_query_snapshot_ref: EMPTY_EVIDENCE_REF,
            included_refs: StorageIntentEvidenceRefs::EMPTY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorTerminalUpdate {
    pub outcome: PrefetchExecutorOutcome,
    pub result_detail: PrefetchExecutorResultDetail,
    pub refusal: StorageIntentRefusalReason,
    pub handoff_target: PrefetchExecutorHandoffTarget,
    pub interruption: PrefetchExecutorInterruptionClass,
    pub interruption_ref: StorageIntentEvidenceRef,
    pub result_refusal_ref: StorageIntentEvidenceRef,
    pub degraded_visibility_ref: StorageIntentEvidenceRef,
    pub evidence_cut: PrefetchExecutorTerminalEvidenceCut,
}

impl Default for PrefetchExecutorTerminalUpdate {
    fn default() -> Self {
        Self {
            outcome: PrefetchExecutorOutcome::Unknown,
            result_detail: PrefetchExecutorResultDetail::default(),
            refusal: StorageIntentRefusalReason::None,
            handoff_target: PrefetchExecutorHandoffTarget::None,
            interruption: PrefetchExecutorInterruptionClass::None,
            interruption_ref: EMPTY_EVIDENCE_REF,
            result_refusal_ref: EMPTY_EVIDENCE_REF,
            degraded_visibility_ref: EMPTY_EVIDENCE_REF,
            evidence_cut: PrefetchExecutorTerminalEvidenceCut::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorInput {
    pub decision: PrefetchResidencyDecisionRecord,
    pub evidence_query_snapshot: StorageIntentEvidenceQuerySnapshot,
    pub admission: PrefetchExecutorAdmissionRecord,
    pub media_path: PrefetchExecutorMediaPath,
    pub dispatch_plan: PrefetchExecutorDispatchPlan,
    pub cost_state: PrefetchExecutorCostState,
    pub result_detail: PrefetchExecutorResultDetail,
    pub runtime_support: PrefetchExecutorRuntimeSupport,
    pub action_family: PrefetchExecutorActionFamily,
    pub freshness_rpo_floor_ms: u64,
    pub anti_waste: PrefetchExecutorAntiWasteMask,
    pub require_known_waf: bool,
    pub require_known_egress_restore_cost: bool,
    pub require_budget_owner: bool,
    pub require_isolation_evidence: bool,
}

impl Default for PrefetchExecutorInput {
    fn default() -> Self {
        Self {
            decision: PrefetchResidencyDecisionRecord::default(),
            evidence_query_snapshot: StorageIntentEvidenceQuerySnapshot::default(),
            admission: PrefetchExecutorAdmissionRecord::default(),
            media_path: PrefetchExecutorMediaPath::default(),
            dispatch_plan: PrefetchExecutorDispatchPlan::default(),
            cost_state: PrefetchExecutorCostState::default(),
            result_detail: PrefetchExecutorResultDetail::default(),
            runtime_support: PrefetchExecutorRuntimeSupport::default(),
            action_family: PrefetchExecutorActionFamily::Unknown,
            freshness_rpo_floor_ms: 0,
            anti_waste: PrefetchExecutorAntiWasteMask::EMPTY,
            require_known_waf: false,
            require_known_egress_restore_cost: false,
            require_budget_owner: false,
            require_isolation_evidence: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchExecutorRecord {
    pub version: u16,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub budget_owner: StorageIntentDomainId,
    pub action_class: StorageIntentActionClass,
    pub action_family: PrefetchExecutorActionFamily,
    pub subject: StorageIntentObjectScope,
    pub access_pattern: AccessPatternClass,
    pub confidence: PredictionConfidence,
    pub requested_candidate: PrefetchResidencyCandidateClass,
    pub selected_candidate: PrefetchResidencyCandidateClass,
    pub selected_residency: PrefetchResidencyStateClass,
    pub decision_outcome: PrefetchResidencyDecisionOutcome,
    pub executor_byte_state: PrefetchExecutorByteState,
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_path_ref: StorageIntentEvidenceRef,
    pub target_destination_ref: StorageIntentEvidenceRef,
    pub dispatch_plan: PrefetchExecutorDispatchPlan,
    pub freshness_rpo_floor_ms: u64,
    pub max_prefetch_window_bytes: u64,
    pub max_staging_bytes: u64,
    pub admission: PrefetchExecutorAdmissionRecord,
    pub cost_state: PrefetchExecutorCostState,
    pub result_detail: PrefetchExecutorResultDetail,
    pub anti_waste: PrefetchExecutorAntiWasteMask,
    pub outcome: PrefetchExecutorOutcome,
    pub refusal: StorageIntentRefusalReason,
    pub handoff_target: PrefetchExecutorHandoffTarget,
    pub interruption: PrefetchExecutorInterruptionClass,
    pub evidence_refs: PrefetchExecutorEvidenceRefs,
}

impl Default for PrefetchExecutorRecord {
    fn default() -> Self {
        Self {
            version: STORAGE_INTENT_PREFETCH_EXECUTOR_VERSION,
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            budget_owner: StorageIntentDomainId::ZERO,
            action_class: StorageIntentActionClass::QueuePrefetchTuning,
            action_family: PrefetchExecutorActionFamily::Unknown,
            subject: EMPTY_SCOPE,
            access_pattern: AccessPatternClass::Unknown,
            confidence: PredictionConfidence::Unknown,
            requested_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            selected_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            selected_residency: PrefetchResidencyStateClass::Unknown,
            decision_outcome: PrefetchResidencyDecisionOutcome::NoAction,
            executor_byte_state: PrefetchExecutorByteState::Unknown,
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_path_ref: EMPTY_EVIDENCE_REF,
            target_destination_ref: EMPTY_EVIDENCE_REF,
            dispatch_plan: PrefetchExecutorDispatchPlan::default(),
            freshness_rpo_floor_ms: 0,
            max_prefetch_window_bytes: 0,
            max_staging_bytes: 0,
            admission: PrefetchExecutorAdmissionRecord::default(),
            cost_state: PrefetchExecutorCostState::default(),
            result_detail: PrefetchExecutorResultDetail::default(),
            anti_waste: PrefetchExecutorAntiWasteMask::EMPTY,
            outcome: PrefetchExecutorOutcome::Unknown,
            refusal: StorageIntentRefusalReason::None,
            handoff_target: PrefetchExecutorHandoffTarget::None,
            interruption: PrefetchExecutorInterruptionClass::None,
            evidence_refs: PrefetchExecutorEvidenceRefs::default(),
        }
    }
}

impl PrefetchExecutorRecord {
    #[must_use]
    pub const fn can_publish_replacement_receipt(self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_retire_source_receipt(self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_satisfy_durable_sync(self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_satisfy_durable_placement(self) -> bool {
        false
    }

    #[must_use]
    pub const fn implies_latest_read_authority(self) -> bool {
        false
    }

    #[must_use]
    pub const fn implies_ram_authority(self) -> bool {
        false
    }

    #[must_use]
    pub const fn implies_geo_freshness_authority(self) -> bool {
        false
    }

    #[must_use]
    pub const fn can_make_successor_comparator_claim(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_non_authority_population(self) -> bool {
        self.executor_byte_state.is_non_authority()
    }

    #[must_use]
    pub const fn has_feedback_payback_inputs(self) -> bool {
        self.result_detail.has_feedback_payback_inputs()
    }

    #[must_use]
    pub const fn completed(mut self) -> Self {
        self.outcome = PrefetchExecutorOutcome::Completed;
        self
    }

    #[must_use]
    pub const fn verification_failed(mut self) -> Self {
        self.outcome = PrefetchExecutorOutcome::VerificationFailed;
        self.refusal = StorageIntentRefusalReason::ValidationGateFailed;
        self
    }

    #[must_use]
    pub const fn timed_out(mut self) -> Self {
        self.outcome = PrefetchExecutorOutcome::TimedOut;
        self.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        self
    }
}

#[must_use]
pub fn evaluate_prefetch_execution(input: PrefetchExecutorInput) -> PrefetchExecutorRecord {
    let mut record = base_record(input);
    let family = record.action_family;

    if decision_identity_missing(input.decision) {
        return terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    if !snapshot_matches_decision(input.evidence_query_snapshot, input.decision) {
        return terminal(
            record,
            PrefetchExecutorOutcome::Stale,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    if !evidence_ref_matches_snapshot(
        input.decision.evidence_refs.evidence_query_ref,
        input.evidence_query_snapshot,
    ) {
        return terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    match input.evidence_query_snapshot.completeness {
        EvidenceCompletenessVerdict::CompleteForPurpose => {}
        EvidenceCompletenessVerdict::DegradedVisible => {
            return terminal(
                record,
                PrefetchExecutorOutcome::DegradedVisible,
                PrefetchExecutorByteState::DegradedVisible,
                StorageIntentRefusalReason::None,
            );
        }
        EvidenceCompletenessVerdict::Refused => {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                snapshot_refusal(input.evidence_query_snapshot),
            );
        }
        EvidenceCompletenessVerdict::Blocked
        | EvidenceCompletenessVerdict::UnknownEvidence
        | EvidenceCompletenessVerdict::PartialAdmissible
        | EvidenceCompletenessVerdict::UnsafeVisible => {
            return terminal(
                record,
                PrefetchExecutorOutcome::Blocked,
                PrefetchExecutorByteState::Blocked,
                snapshot_refusal(input.evidence_query_snapshot),
            );
        }
    }

    if !required_families_fresh(input.evidence_query_snapshot, family) {
        return terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    if initial_result_detail_lacks_feedback_evidence(input) {
        return terminal(
            record,
            PrefetchExecutorOutcome::VerificationFailed,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::ValidationGateFailed,
        );
    }

    if decision_refused_or_needs_more_evidence(input.decision) {
        return terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            decision_refusal(input.decision),
        );
    }

    if family.is_negative_enforcement() || no_prefetch_decision(input.decision) {
        record.executor_byte_state = PrefetchExecutorByteState::NoPrefetchEnforced;
        record.outcome = PrefetchExecutorOutcome::Completed;
        return record;
    }

    let freshness_rpo_refusal =
        freshness_rpo_floor_refusal(input.evidence_query_snapshot, input.freshness_rpo_floor_ms);
    if freshness_rpo_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            freshness_rpo_refusal,
        );
    }

    if authority_handoff_required(input.decision, family) {
        record.handoff_target = handoff_target(input.decision);
        return terminal(
            record,
            PrefetchExecutorOutcome::HandoffRequired,
            PrefetchExecutorByteState::HandoffRequired,
            StorageIntentRefusalReason::None,
        );
    }

    if input.require_budget_owner && input.decision.budget_owner.is_zero() {
        return terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::UnownedWork,
        );
    }

    if input.require_budget_owner {
        if input.admission.budget_owner.is_zero() {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                StorageIntentRefusalReason::MissingBudgetOwnerEvidence,
            );
        }
        if input.admission.budget_owner != input.decision.budget_owner {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                StorageIntentRefusalReason::PolicyConflict,
            );
        }
    }

    let isolation_ref = first_bound(
        input.cost_state.isolation_ref,
        input.decision.evidence_refs.tenant_isolation_ref,
    );
    if input.require_isolation_evidence {
        if input.cost_state.missing_isolation_evidence || !isolation_ref.is_bound() {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                StorageIntentRefusalReason::MissingTenantDomainEvidence,
            );
        }
        if !snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            isolation_ref,
        ) {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                StorageIntentRefusalReason::StaleIsolationEvidence,
            );
        }
    }

    if input.cost_state.required != PrefetchExecutorCostRequirementMask::EMPTY {
        let cost_ref = first_bound(
            input.cost_state.cost_ref,
            input.decision.evidence_refs.cost_wear_ref,
        );
        if !snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::MediaCostWearLedger,
            cost_ref,
        ) {
            return terminal(
                record,
                PrefetchExecutorOutcome::Refused,
                PrefetchExecutorByteState::Refused,
                StorageIntentRefusalReason::EvidenceNotUsable,
            );
        }
    }

    if (input.require_known_waf
        || input
            .cost_state
            .required
            .contains(PrefetchExecutorCostRequirementMask::FLASH_WRITES))
        && input.cost_state.unknown_waf
    {
        return terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::FlashWearBudgetExceeded,
        );
    }

    if (input.require_known_egress_restore_cost
        || input
            .cost_state
            .required
            .contains(PrefetchExecutorCostRequirementMask::EGRESS)
        || input
            .cost_state
            .required
            .contains(PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS))
        && input.cost_state.unknown_egress_or_restore_cost
    {
        return terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    if input.cost_state.missing_required_cost() {
        return terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    if input.cost_state.over_budget {
        return terminal(
            record,
            PrefetchExecutorOutcome::OverBudget,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::GuaranteeFloorNotMet,
        );
    }

    if input
        .anti_waste
        .intersects(PrefetchExecutorAntiWasteMask::cancellation_mask())
    {
        return terminal(
            record,
            PrefetchExecutorOutcome::Dropped,
            PrefetchExecutorByteState::CacheOnly,
            anti_waste_refusal(input.anti_waste),
        );
    }

    match input.admission.outcome {
        PrefetchExecutorAdmissionOutcome::Admitted => {
            if !input.admission.scheduler_admission_ref.is_bound()
                || !snapshot_contains_ref(input, input.admission.scheduler_admission_ref)
            {
                terminal(
                    record,
                    PrefetchExecutorOutcome::Blocked,
                    PrefetchExecutorByteState::Blocked,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                )
            } else if admitted_scheduler_lane_refusal(input, family) as u16
                != StorageIntentRefusalReason::None as u16
            {
                let refusal = admitted_scheduler_lane_refusal(input, family);
                let (outcome, byte_state) =
                    if refusal as u16 == StorageIntentRefusalReason::EvidenceNotUsable as u16 {
                        (
                            PrefetchExecutorOutcome::Blocked,
                            PrefetchExecutorByteState::Blocked,
                        )
                    } else {
                        (
                            PrefetchExecutorOutcome::Refused,
                            PrefetchExecutorByteState::Refused,
                        )
                    };
                terminal(record, outcome, byte_state, refusal)
            } else if runtime_dispatch_evidence_refusal(input, family) as u16
                != StorageIntentRefusalReason::None as u16
            {
                terminal(
                    record,
                    PrefetchExecutorOutcome::Blocked,
                    PrefetchExecutorByteState::Blocked,
                    runtime_dispatch_evidence_refusal(input, family),
                )
            } else if admitted_speculative_pressure_refusal(input) as u16
                != StorageIntentRefusalReason::None as u16
            {
                terminal(
                    record,
                    PrefetchExecutorOutcome::Refused,
                    PrefetchExecutorByteState::Refused,
                    admitted_speculative_pressure_refusal(input),
                )
            } else {
                let dispatch_plan_refusal = dispatch_plan_refusal(input, family);
                if dispatch_plan_refusal as u16 != StorageIntentRefusalReason::None as u16 {
                    let outcome = if dispatch_plan_refusal as u16
                        == StorageIntentRefusalReason::OverBudget as u16
                    {
                        PrefetchExecutorOutcome::OverBudget
                    } else {
                        PrefetchExecutorOutcome::Blocked
                    };
                    terminal(
                        record,
                        outcome,
                        PrefetchExecutorByteState::Blocked,
                        dispatch_plan_refusal,
                    )
                } else if !input.runtime_support.supports_family(family) {
                    terminal(
                        record,
                        PrefetchExecutorOutcome::Unavailable,
                        PrefetchExecutorByteState::Unavailable,
                        input.runtime_support.refusal_reason(),
                    )
                } else if !snapshot_contains_ref(input, input.runtime_support.support_ref) {
                    terminal(
                        record,
                        PrefetchExecutorOutcome::Blocked,
                        PrefetchExecutorByteState::Blocked,
                        StorageIntentRefusalReason::EvidenceNotUsable,
                    )
                } else {
                    record.executor_byte_state = byte_state_for_decision(input.decision, family);
                    record.outcome = PrefetchExecutorOutcome::Started;
                    record
                }
            }
        }
        PrefetchExecutorAdmissionOutcome::Dropped => terminal(
            record,
            PrefetchExecutorOutcome::Dropped,
            PrefetchExecutorByteState::CacheOnly,
            admission_refusal(input.admission),
        ),
        PrefetchExecutorAdmissionOutcome::Throttled => terminal(
            record,
            PrefetchExecutorOutcome::Throttled,
            PrefetchExecutorByteState::CacheOnly,
            admission_refusal(input.admission),
        ),
        PrefetchExecutorAdmissionOutcome::Expired => terminal(
            record,
            PrefetchExecutorOutcome::TimedOut,
            PrefetchExecutorByteState::Unavailable,
            admission_refusal(input.admission),
        ),
        PrefetchExecutorAdmissionOutcome::Refused => terminal(
            record,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorByteState::Refused,
            admission_refusal(input.admission),
        ),
        PrefetchExecutorAdmissionOutcome::Blocked => terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            admission_refusal(input.admission),
        ),
        PrefetchExecutorAdmissionOutcome::Unavailable
        | PrefetchExecutorAdmissionOutcome::Unknown => terminal(
            record,
            PrefetchExecutorOutcome::Unavailable,
            PrefetchExecutorByteState::Unavailable,
            StorageIntentRefusalReason::EvidenceNotUsable,
        ),
    }
}

#[must_use]
pub fn finalize_prefetch_execution(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> PrefetchExecutorRecord {
    if record.outcome != PrefetchExecutorOutcome::Started
        || !terminal_update_outcome_allowed(update.outcome)
    {
        return terminal(
            record,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    let mut record = record;
    record.result_detail = update.result_detail;
    record.evidence_refs.attribution_ref = update.result_detail.attribution_ref;
    record.evidence_refs.retention_ref = update.result_detail.retention_ref;
    record.evidence_refs.validation_ref = update.result_detail.validation_ref;
    if update.result_refusal_ref.is_bound() {
        record.evidence_refs.result_refusal_ref = update.result_refusal_ref;
    }
    if update.degraded_visibility_ref.is_bound() {
        record.evidence_refs.degraded_visibility_ref = update.degraded_visibility_ref;
    }
    record.interruption = update.interruption;
    if update.interruption_ref.is_bound() {
        record.evidence_refs.interruption_ref = update.interruption_ref;
    }

    if terminal_result_detail_is_inconsistent(update.result_detail) {
        return terminal(
            record,
            PrefetchExecutorOutcome::VerificationFailed,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::ValidationGateFailed,
        );
    }

    if terminal_result_detail_exceeds_executor_limit(record, update.result_detail) {
        return terminal(
            record,
            PrefetchExecutorOutcome::OverBudget,
            PrefetchExecutorByteState::Blocked,
            StorageIntentRefusalReason::OverBudget,
        );
    }

    if terminal_update_refs_outside_evidence_cut(record, update)
        || terminal_result_detail_lacks_feedback_evidence(record, update)
        || terminal_update_lacks_result_refusal_evidence(record, update)
        || terminal_update_lacks_verification_evidence(record, update)
        || terminal_update_lacks_degraded_visibility_evidence(record, update)
        || terminal_update_lacks_interruption_evidence(record, update)
        || terminal_update_has_inconsistent_interruption(update)
        || terminal_update_lacks_handoff_boundary_evidence(record, update)
        || terminal_update_lacks_started_dispatch_evidence(record, update)
        || terminal_result_detail_lacks_charge_evidence(record, update)
    {
        return terminal(
            record,
            PrefetchExecutorOutcome::VerificationFailed,
            PrefetchExecutorByteState::Refused,
            StorageIntentRefusalReason::ValidationGateFailed,
        );
    }

    if update.outcome == PrefetchExecutorOutcome::HandoffRequired {
        if update.handoff_target == PrefetchExecutorHandoffTarget::None {
            return terminal(
                record,
                PrefetchExecutorOutcome::Blocked,
                PrefetchExecutorByteState::Blocked,
                StorageIntentRefusalReason::EvidenceNotUsable,
            );
        }
        record.handoff_target = update.handoff_target;
    }

    record.executor_byte_state = terminal_update_byte_state(record.executor_byte_state, update);
    record.outcome = update.outcome;
    record.refusal = terminal_update_refusal(update);
    record
}

fn base_record(input: PrefetchExecutorInput) -> PrefetchExecutorRecord {
    let family = if matches!(input.action_family, PrefetchExecutorActionFamily::Unknown) {
        PrefetchExecutorActionFamily::from_candidate(input.decision.selected_candidate)
    } else {
        input.action_family
    };

    PrefetchExecutorRecord {
        policy_id: input.decision.policy_id,
        policy_revision: input.decision.policy_revision,
        budget_owner: input.decision.budget_owner,
        action_class: family.action_class(),
        action_family: family,
        subject: input.decision.scope,
        access_pattern: input.decision.access_pattern,
        confidence: input.decision.confidence,
        requested_candidate: input.decision.requested_candidate,
        selected_candidate: input.decision.selected_candidate,
        selected_residency: input.decision.selected_residency,
        decision_outcome: input.decision.outcome,
        source_media: input.decision.source_media,
        target_media: input.decision.target_media,
        source_path_ref: input.media_path.source_path_ref,
        target_destination_ref: input.media_path.target_destination_ref,
        dispatch_plan: input.dispatch_plan,
        freshness_rpo_floor_ms: input.freshness_rpo_floor_ms,
        max_prefetch_window_bytes: input.decision.max_prefetch_window_bytes,
        max_staging_bytes: input.decision.max_staging_bytes,
        admission: input.admission,
        cost_state: input.cost_state,
        result_detail: input.result_detail,
        anti_waste: input.anti_waste,
        evidence_refs: PrefetchExecutorEvidenceRefs {
            compiled_policy_ref: input.decision.evidence_refs.compiled_policy_ref,
            prefetch_decision_ref: input.decision.evidence_refs.decision_frontier_ref,
            evidence_query_snapshot_ref: input.decision.evidence_refs.evidence_query_ref,
            scheduler_admission_ref: input.admission.scheduler_admission_ref,
            cost_wear_ref: input.decision.evidence_refs.cost_wear_ref,
            egress_restore_cost_ref: input.decision.evidence_refs.egress_restore_cost_ref,
            media_capability_ref: first_bound(
                input.media_path.media_capability_ref,
                input.decision.evidence_refs.media_capability_ref,
            ),
            source_media_ref: input.decision.source_media_ref,
            target_media_ref: input.decision.target_media_ref,
            source_path_ref: input.media_path.source_path_ref,
            target_destination_ref: input.media_path.target_destination_ref,
            dispatch_plan_ref: input.dispatch_plan.plan_ref,
            runtime_support_ref: input.runtime_support.support_ref,
            read_serving_boundary_ref: input.decision.evidence_refs.read_serving_boundary_ref,
            relocation_boundary_ref: input.decision.evidence_refs.relocation_boundary_ref,
            result_refusal_ref: input.decision.evidence_refs.result_refusal_ref,
            tenant_isolation_ref: first_bound(
                input.cost_state.isolation_ref,
                input.decision.evidence_refs.tenant_isolation_ref,
            ),
            transport_budget_ref: first_bound(
                input.media_path.transport_path_ref,
                input.decision.evidence_refs.transport_budget_ref,
            ),
            trust_domain_ref: first_bound(
                input.media_path.trust_domain_ref,
                input.decision.evidence_refs.trust_domain_ref,
            ),
            recovery_degradation_ref: input.admission.recovery_degradation_ref,
            degraded_visibility_ref: EMPTY_EVIDENCE_REF,
            retention_ref: input.result_detail.retention_ref,
            attribution_ref: input.result_detail.attribution_ref,
            validation_ref: input.result_detail.validation_ref,
            interruption_ref: EMPTY_EVIDENCE_REF,
        },
        ..PrefetchExecutorRecord::default()
    }
}

fn terminal_update_outcome_allowed(outcome: PrefetchExecutorOutcome) -> bool {
    matches!(
        outcome,
        PrefetchExecutorOutcome::Dropped
            | PrefetchExecutorOutcome::Throttled
            | PrefetchExecutorOutcome::Completed
            | PrefetchExecutorOutcome::Stale
            | PrefetchExecutorOutcome::TimedOut
            | PrefetchExecutorOutcome::Refused
            | PrefetchExecutorOutcome::DegradedVisible
            | PrefetchExecutorOutcome::OverBudget
            | PrefetchExecutorOutcome::VerificationFailed
            | PrefetchExecutorOutcome::HandoffRequired
            | PrefetchExecutorOutcome::Blocked
            | PrefetchExecutorOutcome::Unavailable
    )
}

fn terminal_update_byte_state(
    prior: PrefetchExecutorByteState,
    update: PrefetchExecutorTerminalUpdate,
) -> PrefetchExecutorByteState {
    match update.outcome {
        PrefetchExecutorOutcome::Completed
        | PrefetchExecutorOutcome::Dropped
        | PrefetchExecutorOutcome::Throttled => prior,
        PrefetchExecutorOutcome::DegradedVisible => PrefetchExecutorByteState::DegradedVisible,
        PrefetchExecutorOutcome::Stale
        | PrefetchExecutorOutcome::OverBudget
        | PrefetchExecutorOutcome::Blocked => PrefetchExecutorByteState::Blocked,
        PrefetchExecutorOutcome::TimedOut | PrefetchExecutorOutcome::Unavailable => {
            PrefetchExecutorByteState::Unavailable
        }
        PrefetchExecutorOutcome::Refused | PrefetchExecutorOutcome::VerificationFailed => {
            PrefetchExecutorByteState::Refused
        }
        PrefetchExecutorOutcome::HandoffRequired => PrefetchExecutorByteState::HandoffRequired,
        PrefetchExecutorOutcome::Unknown | PrefetchExecutorOutcome::Started => {
            PrefetchExecutorByteState::Blocked
        }
    }
}

fn terminal_update_refusal(update: PrefetchExecutorTerminalUpdate) -> StorageIntentRefusalReason {
    if update.refusal != StorageIntentRefusalReason::None {
        return update.refusal;
    }

    match update.outcome {
        PrefetchExecutorOutcome::Completed
        | PrefetchExecutorOutcome::DegradedVisible
        | PrefetchExecutorOutcome::HandoffRequired => StorageIntentRefusalReason::None,
        PrefetchExecutorOutcome::OverBudget => StorageIntentRefusalReason::OverBudget,
        PrefetchExecutorOutcome::VerificationFailed => {
            StorageIntentRefusalReason::ValidationGateFailed
        }
        PrefetchExecutorOutcome::Dropped
        | PrefetchExecutorOutcome::Throttled
        | PrefetchExecutorOutcome::Stale
        | PrefetchExecutorOutcome::TimedOut
        | PrefetchExecutorOutcome::Refused
        | PrefetchExecutorOutcome::Blocked
        | PrefetchExecutorOutcome::Unavailable
        | PrefetchExecutorOutcome::Unknown
        | PrefetchExecutorOutcome::Started => StorageIntentRefusalReason::EvidenceNotUsable,
    }
}

fn terminal_result_detail_is_inconsistent(detail: PrefetchExecutorResultDetail) -> bool {
    match detail
        .used_bytes
        .checked_add(detail.unused_bytes)
        .and_then(|accounted_bytes| accounted_bytes.checked_add(detail.expired_bytes))
    {
        Some(accounted_bytes) => accounted_bytes > detail.prefetched_bytes,
        None => true,
    }
}

fn terminal_result_detail_lacks_feedback_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    update.result_detail.has_feedback_payback_inputs()
        && !terminal_result_detail_has_cut_feedback_roots(record, update)
}

fn terminal_update_lacks_result_refusal_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    terminal_update_refusal(update) != StorageIntentRefusalReason::None
        && !terminal_ref_in_cut(
            record,
            update.evidence_cut,
            update.result_refusal_ref,
            StorageIntentEvidenceKind::ResultRefusalEvidence,
        )
}

fn terminal_update_lacks_verification_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    update.outcome == PrefetchExecutorOutcome::VerificationFailed
        && !terminal_ref_in_cut(
            record,
            update.evidence_cut,
            update.result_detail.validation_ref,
            StorageIntentEvidenceKind::ValidationArtifact,
        )
}

fn terminal_update_lacks_degraded_visibility_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    if update.outcome != PrefetchExecutorOutcome::DegradedVisible {
        return update.degraded_visibility_ref.is_bound();
    }

    !terminal_ref_in_cut(
        record,
        update.evidence_cut,
        update.degraded_visibility_ref,
        StorageIntentEvidenceKind::RecoveryDegradationEvidence,
    )
}

fn terminal_update_lacks_interruption_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    if !update.interruption.requires_terminal_evidence() {
        return update.interruption_ref.is_bound();
    }

    !terminal_ref_in_cut(
        record,
        update.evidence_cut,
        update.interruption_ref,
        update.interruption.terminal_evidence_kind(),
    )
}

fn terminal_update_has_inconsistent_interruption(update: PrefetchExecutorTerminalUpdate) -> bool {
    !update
        .interruption
        .is_compatible_with_outcome(update.outcome)
}

fn terminal_update_lacks_handoff_boundary_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    update.outcome == PrefetchExecutorOutcome::HandoffRequired
        && update.handoff_target != PrefetchExecutorHandoffTarget::None
        && !terminal_ref_in_cut(
            record,
            update.evidence_cut,
            record.evidence_refs.relocation_boundary_ref,
            StorageIntentEvidenceKind::RelocationReceipt,
        )
}

fn terminal_update_lacks_started_dispatch_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    if !record.action_family.can_start_runtime_dispatch() {
        return false;
    }

    let cut = update.evidence_cut;
    if !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.prefetch_decision_ref,
        StorageIntentEvidenceKind::DecisionFrontierEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.scheduler_admission_ref,
        StorageIntentEvidenceKind::SchedulerAdmissionRecord,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.dispatch_plan_ref,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.runtime_support_ref,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.read_serving_boundary_ref,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.source_media_ref,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.target_media_ref,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.media_capability_ref,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.source_path_ref,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
    ) || !terminal_ref_in_cut(
        record,
        cut,
        record.evidence_refs.target_destination_ref,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
    ) {
        return true;
    }

    let required = record.cost_state.required;
    if !required.is_empty() {
        if !terminal_ref_in_cut(
            record,
            cut,
            record.evidence_refs.cost_wear_ref,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        ) || !terminal_ref_in_cut(
            record,
            cut,
            record.evidence_refs.tenant_isolation_ref,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
        ) {
            return true;
        }

        if terminal_charge_requires_egress_restore(required)
            && !terminal_ref_in_cut(
                record,
                cut,
                record.evidence_refs.egress_restore_cost_ref,
                StorageIntentEvidenceKind::MediaCostWearLedger,
            )
        {
            return true;
        }

        if terminal_charge_requires_transport(required)
            && !terminal_ref_in_cut(
                record,
                cut,
                record.evidence_refs.transport_budget_ref,
                StorageIntentEvidenceKind::TransportPathEvidence,
            )
        {
            return true;
        }
    }

    if record_runtime_dispatch_needs_transport_or_trust(record)
        && (!terminal_ref_in_cut(
            record,
            cut,
            record.evidence_refs.transport_budget_ref,
            StorageIntentEvidenceKind::TransportPathEvidence,
        ) || !terminal_ref_in_cut(
            record,
            cut,
            record.evidence_refs.trust_domain_ref,
            StorageIntentEvidenceKind::TrustDomainEvidence,
        ))
    {
        return true;
    }

    if record_uses_recovery_escalation(record)
        && !terminal_ref_in_cut(
            record,
            cut,
            record.evidence_refs.recovery_degradation_ref,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        )
    {
        return true;
    }

    false
}

fn record_runtime_dispatch_needs_transport_or_trust(record: PrefetchExecutorRecord) -> bool {
    record.action_family.needs_remote_path_evidence()
        || media_needs_transport_or_trust(record.source_media)
        || media_needs_transport_or_trust(record.target_media)
}

fn record_uses_recovery_escalation(record: PrefetchExecutorRecord) -> bool {
    record
        .admission
        .recovery_escalation
        .requires_recovery_degradation_evidence()
}

fn terminal_result_detail_lacks_charge_evidence(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    let required = update.result_detail.charge_requirements();
    if required.is_empty() {
        return false;
    }

    if record.budget_owner.is_zero()
        || !record.cost_state.required.contains(required)
        || record.cost_state.missing_isolation_evidence
    {
        return true;
    }

    let terminal_cost_state = PrefetchExecutorCostState {
        required,
        ..record.cost_state
    };
    if terminal_cost_state.missing_required_cost() {
        return true;
    }

    if terminal_charge_requires_flash_waf(required) && record.cost_state.unknown_waf {
        return true;
    }
    if terminal_charge_requires_egress_restore(required)
        && record.cost_state.unknown_egress_or_restore_cost
    {
        return true;
    }

    if !terminal_ref_in_cut(
        record,
        update.evidence_cut,
        record.evidence_refs.cost_wear_ref,
        StorageIntentEvidenceKind::MediaCostWearLedger,
    ) || !terminal_ref_in_cut(
        record,
        update.evidence_cut,
        record.evidence_refs.tenant_isolation_ref,
        StorageIntentEvidenceKind::TenantIsolationEvidence,
    ) {
        return true;
    }

    if terminal_charge_requires_egress_restore(required)
        && !terminal_ref_in_cut(
            record,
            update.evidence_cut,
            record.evidence_refs.egress_restore_cost_ref,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        )
    {
        return true;
    }

    if terminal_charge_requires_transport(required)
        && !terminal_ref_in_cut(
            record,
            update.evidence_cut,
            record.evidence_refs.transport_budget_ref,
            StorageIntentEvidenceKind::TransportPathEvidence,
        )
    {
        return true;
    }

    false
}

fn terminal_charge_requires_flash_waf(required: PrefetchExecutorCostRequirementMask) -> bool {
    required.contains(PrefetchExecutorCostRequirementMask::FLASH_WRITES)
}

fn terminal_charge_requires_egress_restore(required: PrefetchExecutorCostRequirementMask) -> bool {
    required.contains(PrefetchExecutorCostRequirementMask::EGRESS)
        || required.contains(PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS)
}

fn terminal_charge_requires_transport(required: PrefetchExecutorCostRequirementMask) -> bool {
    required.contains(PrefetchExecutorCostRequirementMask::WAN_BANDWIDTH)
        || terminal_charge_requires_egress_restore(required)
}

fn initial_result_detail_lacks_feedback_evidence(input: PrefetchExecutorInput) -> bool {
    input.result_detail.has_feedback_payback_inputs()
        && !initial_result_detail_has_snapshot_feedback_roots(input)
}

fn initial_result_detail_has_snapshot_feedback_roots(input: PrefetchExecutorInput) -> bool {
    snapshot_contains_typed_ref(
        input,
        input.result_detail.attribution_ref,
        StorageIntentEvidenceKind::MeasurementAttributionEvidence,
    ) && snapshot_contains_typed_ref(
        input,
        input.result_detail.retention_ref,
        StorageIntentEvidenceKind::EvidenceRetentionEvidence,
    ) && snapshot_contains_typed_ref(
        input,
        input.result_detail.validation_ref,
        StorageIntentEvidenceKind::ValidationArtifact,
    )
}

fn terminal_result_detail_has_cut_feedback_roots(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    terminal_ref_in_cut(
        record,
        update.evidence_cut,
        update.result_detail.attribution_ref,
        StorageIntentEvidenceKind::MeasurementAttributionEvidence,
    ) && terminal_ref_in_cut(
        record,
        update.evidence_cut,
        update.result_detail.retention_ref,
        StorageIntentEvidenceKind::EvidenceRetentionEvidence,
    ) && terminal_ref_in_cut(
        record,
        update.evidence_cut,
        update.result_detail.validation_ref,
        StorageIntentEvidenceKind::ValidationArtifact,
    )
}

fn terminal_update_refs_outside_evidence_cut(
    record: PrefetchExecutorRecord,
    update: PrefetchExecutorTerminalUpdate,
) -> bool {
    terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.result_detail.attribution_ref,
        StorageIntentEvidenceKind::MeasurementAttributionEvidence,
    ) || terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.result_detail.retention_ref,
        StorageIntentEvidenceKind::EvidenceRetentionEvidence,
    ) || terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.result_detail.validation_ref,
        StorageIntentEvidenceKind::ValidationArtifact,
    ) || terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.result_refusal_ref,
        StorageIntentEvidenceKind::ResultRefusalEvidence,
    ) || terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.degraded_visibility_ref,
        StorageIntentEvidenceKind::RecoveryDegradationEvidence,
    ) || terminal_bound_ref_outside_cut(
        record,
        update.evidence_cut,
        update.interruption_ref,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
    )
}

fn terminal_bound_ref_outside_cut(
    record: PrefetchExecutorRecord,
    cut: PrefetchExecutorTerminalEvidenceCut,
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.is_bound() && !terminal_ref_in_cut(record, cut, evidence_ref, kind)
}

fn terminal_ref_in_cut(
    record: PrefetchExecutorRecord,
    cut: PrefetchExecutorTerminalEvidenceCut,
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.is_bound()
        && evidence_ref.kind == kind
        && cut.evidence_query_snapshot_ref == record.evidence_refs.evidence_query_snapshot_ref
        && cut.included_refs.contains_ref(evidence_ref)
}

fn terminal_result_detail_exceeds_executor_limit(
    record: PrefetchExecutorRecord,
    detail: PrefetchExecutorResultDetail,
) -> bool {
    let byte_limit = match record.action_family {
        PrefetchExecutorActionFamily::WanGeoDeltaPrefetch
        | PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging => record.max_staging_bytes,
        _ => record.max_prefetch_window_bytes,
    };

    (byte_limit != 0 && detail.prefetched_bytes > byte_limit)
        || (record.max_staging_bytes != 0
            && detail.staging_capacity_bytes > record.max_staging_bytes)
}

fn terminal(
    mut record: PrefetchExecutorRecord,
    outcome: PrefetchExecutorOutcome,
    byte_state: PrefetchExecutorByteState,
    refusal: StorageIntentRefusalReason,
) -> PrefetchExecutorRecord {
    record.outcome = outcome;
    record.executor_byte_state = byte_state;
    record.refusal = refusal;
    record
}

fn decision_identity_missing(decision: PrefetchResidencyDecisionRecord) -> bool {
    decision.policy_id.is_zero()
        || decision.policy_revision.0 == 0
        || decision.scope.dataset_id.is_zero()
        || !decision.evidence_refs.decision_frontier_ref.is_bound()
}

fn snapshot_matches_decision(
    snapshot: StorageIntentEvidenceQuerySnapshot,
    decision: PrefetchResidencyDecisionRecord,
) -> bool {
    snapshot.has_query_identity()
        && snapshot.has_policy_identity()
        && snapshot.has_subject_scope()
        && snapshot.subject.scope_class == EvidenceQuerySubjectScopeClass::ObjectRange
        && snapshot.subject.object_scope == decision.scope
        && snapshot.policy_id == decision.policy_id
        && snapshot.policy_revision.0 >= decision.policy_revision.0
}

fn evidence_ref_matches_snapshot(
    evidence_ref: StorageIntentEvidenceRef,
    snapshot: StorageIntentEvidenceQuerySnapshot,
) -> bool {
    evidence_ref.kind == StorageIntentEvidenceKind::EvidenceQuerySnapshot
        && evidence_ref.is_bound()
        && evidence_ref.id == snapshot.snapshot_id
        && evidence_ref.generation > 0
        && evidence_ref.version > 0
}

fn required_families_fresh(
    snapshot: StorageIntentEvidenceQuerySnapshot,
    family: PrefetchExecutorActionFamily,
) -> bool {
    snapshot.contains_fresh_authority_family(StorageIntentEvidenceKind::EvidenceQuerySnapshot)
        && snapshot
            .contains_fresh_authority_family(StorageIntentEvidenceKind::DecisionFrontierEvidence)
        && (family.is_negative_enforcement()
            || snapshot.contains_fresh_authority_family(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            ))
        && (!family.can_start_runtime_dispatch()
            || snapshot.contains_fresh_authority_family(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
            ))
        && (!family.needs_metadata_namespace_evidence()
            || snapshot.contains_fresh_authority_family(
                StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            ))
        && (!family.needs_remote_path_evidence()
            || (snapshot
                .contains_fresh_authority_family(StorageIntentEvidenceKind::TransportPathEvidence)
                && snapshot.contains_fresh_authority_family(
                    StorageIntentEvidenceKind::TrustDomainEvidence,
                )))
        && (!family.can_start_runtime_dispatch()
            || snapshot.contains_fresh_authority_family(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
            ))
        && snapshot
            .contains_fresh_authority_family(StorageIntentEvidenceKind::ReadFreshnessEvidence)
}

fn runtime_dispatch_evidence_refusal(
    input: PrefetchExecutorInput,
    family: PrefetchExecutorActionFamily,
) -> StorageIntentRefusalReason {
    if !family.can_start_runtime_dispatch() {
        return StorageIntentRefusalReason::None;
    }

    let media_capability_ref = first_bound(
        input.media_path.media_capability_ref,
        input.decision.evidence_refs.media_capability_ref,
    );
    if !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
        input.decision.source_media_ref,
    ) || !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
        input.decision.target_media_ref,
    ) || !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
        media_capability_ref,
    ) {
        return StorageIntentRefusalReason::MissingMediaCapabilityEvidence;
    }

    if input.media_path.source_media != input.decision.source_media
        || input.media_path.target_media != input.decision.target_media
    {
        return StorageIntentRefusalReason::PolicyConflict;
    }

    if !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
        input.decision.evidence_refs.read_serving_boundary_ref,
    ) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if !input.media_path.source_path_ref.is_bound()
        || !input.media_path.target_destination_ref.is_bound()
    {
        return StorageIntentRefusalReason::UnstableNamespaceIdentity;
    }
    if !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
        input.media_path.source_path_ref,
    ) || !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
        input.media_path.target_destination_ref,
    ) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if runtime_dispatch_needs_transport_or_trust(input, family) {
        let transport_path_ref = first_bound(
            input.media_path.transport_path_ref,
            input.decision.evidence_refs.transport_budget_ref,
        );
        if !snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::TransportPathEvidence,
            transport_path_ref,
        ) {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
        let trust_domain_ref = first_bound(
            input.media_path.trust_domain_ref,
            input.decision.evidence_refs.trust_domain_ref,
        );
        if !snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            trust_domain_ref,
        ) {
            return StorageIntentRefusalReason::StaleTrustEvidence;
        }
    }

    StorageIntentRefusalReason::None
}

fn dispatch_plan_refusal(
    input: PrefetchExecutorInput,
    family: PrefetchExecutorActionFamily,
) -> StorageIntentRefusalReason {
    if !family.can_start_runtime_dispatch() {
        return StorageIntentRefusalReason::None;
    }

    let plan = input.dispatch_plan;
    if !plan.shape.matches_action_family(family) || !dispatch_plan_has_shape_bounds(plan) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if !snapshot_contains_fresh_ref(
        input,
        StorageIntentEvidenceKind::ActionExecutionEvidence,
        plan.plan_ref,
    ) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }

    if !dispatch_plan_within_subject(plan, input.decision.scope) {
        return StorageIntentRefusalReason::UnstableNamespaceIdentity;
    }

    if !dispatch_plan_within_executor_limits(plan, input.decision, family) {
        return StorageIntentRefusalReason::OverBudget;
    }

    StorageIntentRefusalReason::None
}

fn dispatch_plan_has_shape_bounds(plan: PrefetchExecutorDispatchPlan) -> bool {
    match plan.shape {
        PrefetchExecutorDispatchShape::BoundedRange
        | PrefetchExecutorDispatchShape::HotsetCacheTrial
        | PrefetchExecutorDispatchShape::SnapshotCloneRanges
        | PrefetchExecutorDispatchShape::DegradedReconstructionRange
        | PrefetchExecutorDispatchShape::WanGeoDeltaRange
        | PrefetchExecutorDispatchShape::ObjectArchiveRestoreRange => {
            plan.range_bytes != 0
                && plan.range_count == 1
                && plan.stride_bytes == 0
                && plan.fanout_limit == 0
                && plan.namespace_depth_limit == 0
        }
        PrefetchExecutorDispatchShape::StridedVectorRanges => {
            plan.range_bytes != 0
                && plan.stride_bytes != 0
                && plan.range_count > 1
                && plan.fanout_limit == 0
                && plan.namespace_depth_limit == 0
        }
        PrefetchExecutorDispatchShape::MetadataNamespaceWalk => {
            plan.range_count <= 1
                && plan.stride_bytes == 0
                && (plan.range_bytes != 0
                    || plan.fanout_limit != 0
                    || plan.namespace_depth_limit != 0)
        }
        PrefetchExecutorDispatchShape::ManifestIndexFanout => {
            plan.range_count <= 1
                && plan.stride_bytes == 0
                && plan.fanout_limit != 0
                && (plan.range_bytes != 0 || plan.namespace_depth_limit != 0)
        }
        PrefetchExecutorDispatchShape::Unknown => false,
    }
}

fn dispatch_plan_within_subject(
    plan: PrefetchExecutorDispatchPlan,
    subject: StorageIntentObjectScope,
) -> bool {
    if plan.range_bytes == 0 {
        return true;
    }

    let Some(plan_end) = dispatch_plan_extent_end(plan) else {
        return false;
    };
    let Some(subject_end) = subject.range_start.checked_add(subject.range_len) else {
        return false;
    };

    plan.range_start >= subject.range_start && plan_end <= subject_end
}

fn dispatch_plan_within_executor_limits(
    plan: PrefetchExecutorDispatchPlan,
    decision: PrefetchResidencyDecisionRecord,
    family: PrefetchExecutorActionFamily,
) -> bool {
    let Some(planned_bytes) = dispatch_plan_planned_bytes(plan) else {
        return false;
    };
    if planned_bytes == 0 {
        return true;
    }

    let byte_limit = match family {
        PrefetchExecutorActionFamily::WanGeoDeltaPrefetch
        | PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging => decision.max_staging_bytes,
        _ => decision.max_prefetch_window_bytes,
    };

    byte_limit == 0 || planned_bytes <= byte_limit
}

fn dispatch_plan_planned_bytes(plan: PrefetchExecutorDispatchPlan) -> Option<u64> {
    let count = dispatch_plan_range_count(plan);
    plan.range_bytes.checked_mul(count)
}

fn dispatch_plan_extent_end(plan: PrefetchExecutorDispatchPlan) -> Option<u64> {
    let count = dispatch_plan_range_count(plan);
    let last_start = if count <= 1 {
        plan.range_start
    } else {
        let stride_span = plan.stride_bytes.checked_mul(count - 1)?;
        plan.range_start.checked_add(stride_span)?
    };

    last_start.checked_add(plan.range_bytes)
}

fn dispatch_plan_range_count(plan: PrefetchExecutorDispatchPlan) -> u64 {
    if plan.range_count == 0 {
        1
    } else {
        u64::from(plan.range_count)
    }
}

fn freshness_rpo_floor_refusal(
    snapshot: StorageIntentEvidenceQuerySnapshot,
    floor_ms: u64,
) -> StorageIntentRefusalReason {
    if floor_ms == 0 {
        return StorageIntentRefusalReason::None;
    }
    if !snapshot.has_frontiers() || snapshot.allowed_staleness_ms == 0 {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if snapshot.freshness_frontier_ms > snapshot.temporal_frontier_ms {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if snapshot
        .temporal_frontier_ms
        .saturating_sub(snapshot.freshness_frontier_ms)
        > floor_ms
        || snapshot.allowed_staleness_ms > floor_ms
    {
        return StorageIntentRefusalReason::DurabilityOrRpoNotMet;
    }

    let (families, len) = snapshot.family_freshness.as_parts();
    let mut index = 0;
    let mut found = false;
    while index < len as usize {
        let family = families[index];
        if family.kind as u16 == StorageIntentEvidenceKind::ReadFreshnessEvidence as u16 {
            if found
                || !family.state.is_fresh_for_authority()
                || !family.evidence_ref.is_bound()
                || family.freshness_frontier_ms == 0
                || family.allowed_staleness_ms == 0
                || family.freshness_frontier_ms > snapshot.temporal_frontier_ms
            {
                return StorageIntentRefusalReason::EvidenceNotUsable;
            }
            if snapshot
                .temporal_frontier_ms
                .saturating_sub(family.freshness_frontier_ms)
                > floor_ms
                || family.allowed_staleness_ms > floor_ms
            {
                return StorageIntentRefusalReason::DurabilityOrRpoNotMet;
            }
            found = true;
        }
        index += 1;
    }

    if found {
        StorageIntentRefusalReason::None
    } else {
        StorageIntentRefusalReason::EvidenceNotUsable
    }
}

fn snapshot_contains_ref(
    input: PrefetchExecutorInput,
    evidence_ref: StorageIntentEvidenceRef,
) -> bool {
    input
        .evidence_query_snapshot
        .included_refs
        .contains_ref(evidence_ref)
}

fn snapshot_contains_typed_ref(
    input: PrefetchExecutorInput,
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.is_bound()
        && evidence_ref.kind == kind
        && snapshot_contains_ref(input, evidence_ref)
}

fn snapshot_contains_fresh_ref(
    input: PrefetchExecutorInput,
    kind: StorageIntentEvidenceKind,
    evidence_ref: StorageIntentEvidenceRef,
) -> bool {
    evidence_ref.kind == kind
        && input
            .evidence_query_snapshot
            .contains_fresh_authority_family(kind)
        && snapshot_contains_ref(input, evidence_ref)
}

fn runtime_dispatch_needs_transport_or_trust(
    input: PrefetchExecutorInput,
    family: PrefetchExecutorActionFamily,
) -> bool {
    family.needs_remote_path_evidence()
        || media_needs_transport_or_trust(input.decision.source_media)
        || media_needs_transport_or_trust(input.decision.target_media)
        || media_needs_transport_or_trust(input.media_path.source_media)
        || media_needs_transport_or_trust(input.media_path.target_media)
}

const fn media_needs_transport_or_trust(media: StorageMediaClass) -> bool {
    matches!(
        media,
        StorageMediaClass::RemoteRam
            | StorageMediaClass::ObjectAppliance
            | StorageMediaClass::CloudObject
            | StorageMediaClass::OpticalArchive
            | StorageMediaClass::TapeArchive
    )
}

fn admitted_scheduler_lane_refusal(
    input: PrefetchExecutorInput,
    family: PrefetchExecutorActionFamily,
) -> StorageIntentRefusalReason {
    if !family.can_start_runtime_dispatch() {
        return StorageIntentRefusalReason::None;
    }

    let admission = input.admission;
    let expected = PrefetchExecutorSchedulerLane::for_action_family(family);
    if admission.lane == expected {
        return StorageIntentRefusalReason::None;
    }
    if matches!(admission.lane, PrefetchExecutorSchedulerLane::Unknown) {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if admission.lane.is_stricter_than(expected)
        && admission
            .recovery_escalation
            .requires_recovery_degradation_evidence()
    {
        if snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            admission.recovery_degradation_ref,
        ) {
            return StorageIntentRefusalReason::None;
        }
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }

    StorageIntentRefusalReason::PolicyConflict
}

fn admitted_speculative_pressure_refusal(
    input: PrefetchExecutorInput,
) -> StorageIntentRefusalReason {
    let admission = input.admission;
    if !matches!(
        admission.lane,
        PrefetchExecutorSchedulerLane::Speculative | PrefetchExecutorSchedulerLane::Background
    ) || admission.pressure.is_empty()
    {
        return StorageIntentRefusalReason::None;
    }

    if admission.droppable || admission.throttleable || admission.expirable {
        return StorageIntentRefusalReason::None;
    }

    if admission
        .recovery_escalation
        .requires_recovery_degradation_evidence()
    {
        if snapshot_contains_fresh_ref(
            input,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            admission.recovery_degradation_ref,
        ) {
            return StorageIntentRefusalReason::None;
        }
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }

    pressure_refusal(admission.pressure)
}

fn no_prefetch_decision(decision: PrefetchResidencyDecisionRecord) -> bool {
    matches!(
        decision.selected_candidate,
        PrefetchResidencyCandidateClass::NoPrefetch
    ) || matches!(decision.outcome, PrefetchResidencyDecisionOutcome::NoAction)
}

fn decision_refused_or_needs_more_evidence(decision: PrefetchResidencyDecisionRecord) -> bool {
    matches!(
        decision.outcome,
        PrefetchResidencyDecisionOutcome::Refused
            | PrefetchResidencyDecisionOutcome::NeedMoreEvidence
    ) || matches!(
        decision.selected_candidate,
        PrefetchResidencyCandidateClass::NeedMoreEvidence
            | PrefetchResidencyCandidateClass::Refused
    ) || matches!(
        decision.selected_residency,
        PrefetchResidencyStateClass::Refused
    )
}

fn authority_handoff_required(
    decision: PrefetchResidencyDecisionRecord,
    family: PrefetchExecutorActionFamily,
) -> bool {
    matches!(
        family,
        PrefetchExecutorActionFamily::AuthorityChangingHandoff
    ) || matches!(
        decision.selected_candidate,
        PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            | PrefetchResidencyCandidateClass::DemotionCandidate
    ) || matches!(
        decision.selected_residency,
        PrefetchResidencyStateClass::IntentBackedRam
            | PrefetchResidencyStateClass::PmemDurable
            | PrefetchResidencyStateClass::RemoteDurable
    ) || matches!(
        decision.outcome,
        PrefetchResidencyDecisionOutcome::PromotionCandidate
            | PrefetchResidencyDecisionOutcome::DemotionCandidate
    )
}

fn handoff_target(decision: PrefetchResidencyDecisionRecord) -> PrefetchExecutorHandoffTarget {
    if matches!(
        decision.selected_candidate,
        PrefetchResidencyCandidateClass::DemotionCandidate
    ) || matches!(
        decision.outcome,
        PrefetchResidencyDecisionOutcome::DemotionCandidate
    ) {
        PrefetchExecutorHandoffTarget::Demotion
    } else if matches!(
        decision.selected_residency,
        PrefetchResidencyStateClass::IntentBackedRam
            | PrefetchResidencyStateClass::PmemDurable
            | PrefetchResidencyStateClass::RemoteDurable
    ) {
        PrefetchExecutorHandoffTarget::DurableResidencyChange
    } else {
        PrefetchExecutorHandoffTarget::Promotion
    }
}

fn byte_state_for_decision(
    decision: PrefetchResidencyDecisionRecord,
    family: PrefetchExecutorActionFamily,
) -> PrefetchExecutorByteState {
    match family {
        PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging
        | PrefetchExecutorActionFamily::WanGeoDeltaPrefetch => PrefetchExecutorByteState::Staged,
        PrefetchExecutorActionFamily::DegradedReadReconstruction => {
            PrefetchExecutorByteState::DegradedVisible
        }
        PrefetchExecutorActionFamily::SmallRandomHotsetCacheTrial => {
            PrefetchExecutorByteState::CacheOnlyTrial
        }
        PrefetchExecutorActionFamily::ExplicitNoPrefetch => {
            PrefetchExecutorByteState::NoPrefetchEnforced
        }
        _ if matches!(
            decision.outcome,
            PrefetchResidencyDecisionOutcome::ServingTrial
                | PrefetchResidencyDecisionOutcome::CacheOnly
        ) =>
        {
            PrefetchExecutorByteState::CacheOnlyTrial
        }
        _ => PrefetchExecutorByteState::CacheOnly,
    }
}

fn decision_refusal(decision: PrefetchResidencyDecisionRecord) -> StorageIntentRefusalReason {
    if matches!(decision.refusal, StorageIntentRefusalReason::None) {
        StorageIntentRefusalReason::EvidenceNotUsable
    } else {
        decision.refusal
    }
}

fn snapshot_refusal(snapshot: StorageIntentEvidenceQuerySnapshot) -> StorageIntentRefusalReason {
    if matches!(snapshot.refusal, StorageIntentRefusalReason::None) {
        StorageIntentRefusalReason::EvidenceNotUsable
    } else {
        snapshot.refusal
    }
}

fn admission_refusal(admission: PrefetchExecutorAdmissionRecord) -> StorageIntentRefusalReason {
    if matches!(admission.refusal, StorageIntentRefusalReason::None) {
        StorageIntentRefusalReason::EvidenceNotUsable
    } else {
        admission.refusal
    }
}

fn anti_waste_refusal(mask: PrefetchExecutorAntiWasteMask) -> StorageIntentRefusalReason {
    if mask.intersects(PrefetchExecutorAntiWasteMask::UNKNOWN_WAF) {
        StorageIntentRefusalReason::FlashWearBudgetExceeded
    } else if mask.intersects(PrefetchExecutorAntiWasteMask::NOISY_NEIGHBOR_PRESSURE) {
        StorageIntentRefusalReason::NoisyNeighborPressure
    } else if mask.intersects(PrefetchExecutorAntiWasteMask::FAILED_PAYBACK)
        || mask.intersects(PrefetchExecutorAntiWasteMask::LOW_DWELL)
        || mask.intersects(PrefetchExecutorAntiWasteMask::COOLDOWN)
    {
        StorageIntentRefusalReason::MovementDebtNotPaidBack
    } else if mask.intersects(PrefetchExecutorAntiWasteMask::PROTECTED_RESERVE_PRESSURE) {
        StorageIntentRefusalReason::ProtectedReserveWouldBeBreached
    } else {
        StorageIntentRefusalReason::EvidenceNotUsable
    }
}

fn pressure_refusal(pressure: PrefetchExecutorPressureMask) -> StorageIntentRefusalReason {
    if pressure.intersects(PrefetchExecutorPressureMask::PROTECTED_RESERVE) {
        StorageIntentRefusalReason::ProtectedReserveWouldBeBreached
    } else if pressure.intersects(
        PrefetchExecutorPressureMask::REPAIR
            .union(PrefetchExecutorPressureMask::EVACUATION)
            .union(PrefetchExecutorPressureMask::RECEIPT_RETIREMENT),
    ) {
        StorageIntentRefusalReason::RecoveryReserveExhausted
    } else if pressure.intersects(PrefetchExecutorPressureMask::WEAR) {
        StorageIntentRefusalReason::FlashWearBudgetExceeded
    } else if pressure.intersects(
        PrefetchExecutorPressureMask::EGRESS.union(PrefetchExecutorPressureMask::RESTORE_COST),
    ) {
        StorageIntentRefusalReason::OverBudget
    } else if pressure.intersects(
        PrefetchExecutorPressureMask::FOREGROUND_POSIX_SYNC
            .union(PrefetchExecutorPressureMask::MEMORY)
            .union(PrefetchExecutorPressureMask::P99_LATENCY),
    ) {
        StorageIntentRefusalReason::NoisyNeighborPressure
    } else {
        StorageIntentRefusalReason::EvidenceNotUsable
    }
}

fn first_bound(
    preferred: StorageIntentEvidenceRef,
    fallback: StorageIntentEvidenceRef,
) -> StorageIntentEvidenceRef {
    if preferred.is_bound() {
        preferred
    } else {
        fallback
    }
}

fn class_missing_or_unknown(
    state: StorageIntentCostEvidenceState,
    class: StorageIntentCostClass,
) -> bool {
    state.class_is_missing(class) || state.class_is_stale(class) || state.class_is_refused(class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        EvidenceFamilyFreshness, EvidenceFamilyFreshnessSet, EvidenceQuerySubjectScope,
        EvidenceQuerySubjectScopeClass, StorageIntentEvidenceRefs,
    };

    const POLICY: StorageIntentPolicyId = StorageIntentPolicyId([1; 16]);
    const DATASET: StorageIntentDomainId = StorageIntentDomainId([2; 16]);
    const BUDGET: StorageIntentDomainId = StorageIntentDomainId([3; 16]);
    const OBJECT: StorageIntentEvidenceId = StorageIntentEvidenceId([4; 32]);
    const SNAPSHOT: StorageIntentEvidenceId = StorageIntentEvidenceId([5; 32]);
    const QUERY: StorageIntentEvidenceId = StorageIntentEvidenceId([6; 32]);
    const DECISION: StorageIntentEvidenceId = StorageIntentEvidenceId([7; 32]);
    const SCHED: StorageIntentEvidenceId = StorageIntentEvidenceId([8; 32]);
    const MEDIA: StorageIntentEvidenceId = StorageIntentEvidenceId([9; 32]);
    const READ: StorageIntentEvidenceId = StorageIntentEvidenceId([10; 32]);
    const COST: StorageIntentEvidenceId = StorageIntentEvidenceId([11; 32]);
    const ISO: StorageIntentEvidenceId = StorageIntentEvidenceId([12; 32]);
    const TRANSPORT: StorageIntentEvidenceId = StorageIntentEvidenceId([13; 32]);
    const TRUST: StorageIntentEvidenceId = StorageIntentEvidenceId([14; 32]);
    const ATTRIBUTION: StorageIntentEvidenceId = StorageIntentEvidenceId([15; 32]);
    const RETENTION: StorageIntentEvidenceId = StorageIntentEvidenceId([16; 32]);
    const VALIDATION: StorageIntentEvidenceId = StorageIntentEvidenceId([17; 32]);
    const ACTION: StorageIntentEvidenceId = StorageIntentEvidenceId([18; 32]);
    const SOURCE_PATH: StorageIntentEvidenceId = StorageIntentEvidenceId([19; 32]);
    const TARGET_DESTINATION: StorageIntentEvidenceId = StorageIntentEvidenceId([20; 32]);
    const OUTSIDE_CUT: StorageIntentEvidenceId = StorageIntentEvidenceId([21; 32]);
    const RESULT_REFUSAL: StorageIntentEvidenceId = StorageIntentEvidenceId([22; 32]);
    const INTERRUPTION: StorageIntentEvidenceId = StorageIntentEvidenceId([23; 32]);
    const RUNTIME_SUPPORT: StorageIntentEvidenceId = StorageIntentEvidenceId([24; 32]);
    const RELOCATION: StorageIntentEvidenceId = StorageIntentEvidenceId([25; 32]);
    const RECOVERY: StorageIntentEvidenceId = StorageIntentEvidenceId([26; 32]);

    fn evidence(
        kind: StorageIntentEvidenceKind,
        id: StorageIntentEvidenceId,
    ) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, id, 1, 1)
    }

    fn scope() -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: DATASET,
            object_id: OBJECT,
            range_start: 4096,
            range_len: 8192,
            generation: 9,
        }
    }

    fn fresh(
        kind: StorageIntentEvidenceKind,
        id: StorageIntentEvidenceId,
    ) -> EvidenceFamilyFreshness {
        EvidenceFamilyFreshness {
            kind,
            state: tidefs_storage_intent_core::EvidenceFamilyFreshnessState::Fresh,
            source_index_generation: 1,
            producer_generation: 1,
            freshness_frontier_ms: 10,
            allowed_staleness_ms: 1,
            evidence_ref: evidence(kind, id),
        }
    }

    fn add_fresh(
        snapshot: &mut StorageIntentEvidenceQuerySnapshot,
        kind: StorageIntentEvidenceKind,
        id: StorageIntentEvidenceId,
    ) {
        let family = fresh(kind, id);
        snapshot.included_refs.push(family.evidence_ref).unwrap();
        snapshot.family_freshness.push(family).unwrap();
    }

    fn rewrite_family_freshness(
        snapshot: &mut StorageIntentEvidenceQuerySnapshot,
        kind: StorageIntentEvidenceKind,
        freshness_frontier_ms: u64,
        allowed_staleness_ms: u64,
    ) {
        let (families, len) = snapshot.family_freshness.as_parts();
        let mut rewritten = EvidenceFamilyFreshnessSet::EMPTY;
        let mut index = 0;
        while index < len as usize {
            let mut family = families[index];
            if family.kind == kind {
                family.freshness_frontier_ms = freshness_frontier_ms;
                family.allowed_staleness_ms = allowed_staleness_ms;
            }
            rewritten.push(family).unwrap();
            index += 1;
        }
        snapshot.family_freshness = rewritten;
    }

    fn snapshot(
        extra_kind: Option<StorageIntentEvidenceKind>,
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot = StorageIntentEvidenceQuerySnapshot {
            snapshot_id: SNAPSHOT,
            query_id: QUERY,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::ObjectRange,
                object_scope: scope(),
                ..EvidenceQuerySubjectScope::default()
            },
            policy_id: POLICY,
            policy_revision: StorageIntentPolicyRevision(7),
            temporal_frontier_ms: 10,
            freshness_frontier_ms: 10,
            source_index_generation: 1,
            producer_generation: 1,
            producer_watermark_ms: 10,
            included_refs: StorageIntentEvidenceRefs::EMPTY,
            family_freshness: EvidenceFamilyFreshnessSet::EMPTY,
            completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
            ..StorageIntentEvidenceQuerySnapshot::default()
        };

        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::EvidenceQuerySnapshot,
            SNAPSHOT,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
            DECISION,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            SCHED,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
            MEDIA,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::MediaCostWearLedger,
            COST,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            ISO,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            READ,
        );
        add_fresh(
            &mut snapshot,
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            ACTION,
        );
        snapshot
            .included_refs
            .push(evidence(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                SOURCE_PATH,
            ))
            .unwrap();
        snapshot
            .included_refs
            .push(evidence(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                TARGET_DESTINATION,
            ))
            .unwrap();
        if let Some(kind) = extra_kind {
            add_fresh(&mut snapshot, kind, TRANSPORT);
        }
        snapshot
    }

    fn decision(candidate: PrefetchResidencyCandidateClass) -> PrefetchResidencyDecisionRecord {
        PrefetchResidencyDecisionRecord {
            policy_id: POLICY,
            policy_revision: StorageIntentPolicyRevision(7),
            scope: scope(),
            budget_owner: BUDGET,
            requested_candidate: candidate,
            selected_candidate: candidate,
            selected_residency: PrefetchResidencyStateClass::CacheOnlyRam,
            outcome: PrefetchResidencyDecisionOutcome::Admitted,
            source_media: StorageMediaClass::HddRotational,
            target_media: StorageMediaClass::SystemRam,
            source_media_ref: evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, MEDIA),
            target_media_ref: evidence(StorageIntentEvidenceKind::MediaCapabilityEvidence, MEDIA),
            max_prefetch_window_bytes: 1 << 20,
            max_staging_bytes: 1 << 21,
            evidence_refs: tidefs_storage_intent_core::PrefetchResidencyDecisionEvidenceRefs {
                evidence_query_ref: evidence(
                    StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                    SNAPSHOT,
                ),
                decision_frontier_ref: evidence(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    DECISION,
                ),
                scheduler_admission_ref: evidence(
                    StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                    SCHED,
                ),
                media_capability_ref: evidence(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    MEDIA,
                ),
                read_serving_boundary_ref: evidence(
                    StorageIntentEvidenceKind::ReadFreshnessEvidence,
                    READ,
                ),
                cost_wear_ref: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, COST),
                egress_restore_cost_ref: evidence(
                    StorageIntentEvidenceKind::MediaCostWearLedger,
                    COST,
                ),
                tenant_isolation_ref: evidence(
                    StorageIntentEvidenceKind::TenantIsolationEvidence,
                    ISO,
                ),
                transport_budget_ref: evidence(
                    StorageIntentEvidenceKind::TransportPathEvidence,
                    TRANSPORT,
                ),
                trust_domain_ref: evidence(StorageIntentEvidenceKind::TrustDomainEvidence, TRUST),
                ..tidefs_storage_intent_core::PrefetchResidencyDecisionEvidenceRefs::default()
            },
            ..PrefetchResidencyDecisionRecord::default()
        }
    }

    fn dispatch_plan(candidate: PrefetchResidencyCandidateClass) -> PrefetchExecutorDispatchPlan {
        let family = PrefetchExecutorActionFamily::from_candidate(candidate);
        let shape = PrefetchExecutorDispatchShape::for_action_family(family);
        let plan_ref = evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, ACTION);

        match shape {
            PrefetchExecutorDispatchShape::Unknown => PrefetchExecutorDispatchPlan::default(),
            PrefetchExecutorDispatchShape::StridedVectorRanges => {
                PrefetchExecutorDispatchPlan::bounded_range(4096, 4096, plan_ref)
                    .with_shape(shape)
                    .with_stride(4096, 2)
            }
            PrefetchExecutorDispatchShape::MetadataNamespaceWalk => {
                PrefetchExecutorDispatchPlan::bounded_range(4096, 4096, plan_ref)
                    .with_shape(shape)
                    .with_fanout_limit(16)
                    .with_namespace_depth_limit(2)
            }
            PrefetchExecutorDispatchShape::ManifestIndexFanout => {
                PrefetchExecutorDispatchPlan::bounded_range(4096, 4096, plan_ref)
                    .with_shape(shape)
                    .with_fanout_limit(16)
            }
            PrefetchExecutorDispatchShape::BoundedRange
            | PrefetchExecutorDispatchShape::HotsetCacheTrial
            | PrefetchExecutorDispatchShape::SnapshotCloneRanges
            | PrefetchExecutorDispatchShape::DegradedReconstructionRange
            | PrefetchExecutorDispatchShape::WanGeoDeltaRange
            | PrefetchExecutorDispatchShape::ObjectArchiveRestoreRange => {
                PrefetchExecutorDispatchPlan::bounded_range(4096, 4096, plan_ref).with_shape(shape)
            }
        }
    }

    fn admitted_input(candidate: PrefetchResidencyCandidateClass) -> PrefetchExecutorInput {
        let decision = decision(candidate);
        let family = PrefetchExecutorActionFamily::from_candidate(candidate);
        PrefetchExecutorInput {
            evidence_query_snapshot: snapshot(None),
            admission: PrefetchExecutorAdmissionRecord::admitted(
                PrefetchExecutorSchedulerLane::for_action_family(family),
                BUDGET,
                evidence(StorageIntentEvidenceKind::SchedulerAdmissionRecord, SCHED),
            )
            .with_speculative_controls(true, true, true),
            media_path: PrefetchExecutorMediaPath {
                source_media: decision.source_media,
                target_media: decision.target_media,
                source_path_ref: evidence(
                    StorageIntentEvidenceKind::ReadFreshnessEvidence,
                    SOURCE_PATH,
                ),
                target_destination_ref: evidence(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    TARGET_DESTINATION,
                ),
                media_capability_ref: evidence(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    MEDIA,
                ),
                ..PrefetchExecutorMediaPath::default()
            },
            dispatch_plan: dispatch_plan(candidate),
            cost_state: PrefetchExecutorCostState {
                snapshot: StorageIntentCostSnapshot {
                    evidence_id: COST,
                    policy_id: POLICY,
                    policy_revision: StorageIntentPolicyRevision(7),
                    budget_owner: BUDGET,
                    evidence_state: StorageIntentCostEvidenceState::FRESH,
                    ..StorageIntentCostSnapshot::default()
                },
                cost_ref: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, COST),
                isolation_ref: evidence(StorageIntentEvidenceKind::TenantIsolationEvidence, ISO),
                ..PrefetchExecutorCostState::default()
            },
            runtime_support: PrefetchExecutorRuntimeSupport::supported(
                PrefetchExecutorRuntimeSupportMask::ALL_MODELLED_DISPATCH,
                evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, ACTION),
            ),
            decision,
            require_budget_owner: true,
            require_isolation_evidence: true,
            ..PrefetchExecutorInput::default()
        }
    }

    fn assert_record_has_no_authority_claims(record: PrefetchExecutorRecord) {
        assert!(!record.can_publish_replacement_receipt());
        assert!(!record.can_retire_source_receipt());
        assert!(!record.can_satisfy_durable_sync());
        assert!(!record.can_satisfy_durable_placement());
        assert!(!record.implies_latest_read_authority());
        assert!(!record.implies_ram_authority());
        assert!(!record.implies_geo_freshness_authority());
        assert!(!record.can_make_successor_comparator_claim());
    }

    fn terminal_detail() -> PrefetchExecutorResultDetail {
        PrefetchExecutorResultDetail {
            prefetched_bytes: 128 * 1024,
            used_bytes: 96 * 1024,
            unused_bytes: 16 * 1024,
            expired_bytes: 16 * 1024,
            latency_benefit_us: 900,
            latency_harm_us: 7,
            foreground_p99_disruption_us: 13,
            queue_delay_us: 5,
            flash_write_bytes: 512,
            waf_micros: 1_050_000,
            cpu_us: 33,
            memory_bytes: 16 * 1024,
            attribution_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                ATTRIBUTION,
            ),
            retention_ref: evidence(
                StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                RETENTION,
            ),
            validation_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, VALIDATION),
            ..PrefetchExecutorResultDetail::default()
        }
    }

    fn push_terminal_ref(
        refs: &mut StorageIntentEvidenceRefs,
        evidence_ref: StorageIntentEvidenceRef,
    ) {
        if evidence_ref.is_bound() && !refs.contains_ref(evidence_ref) {
            refs.push(evidence_ref).unwrap();
        }
    }

    fn push_terminal_start_refs(
        refs: &mut StorageIntentEvidenceRefs,
        record: PrefetchExecutorRecord,
    ) {
        push_terminal_ref(refs, record.evidence_refs.prefetch_decision_ref);
        push_terminal_ref(refs, record.evidence_refs.scheduler_admission_ref);
        push_terminal_ref(refs, record.evidence_refs.dispatch_plan_ref);
        push_terminal_ref(refs, record.evidence_refs.runtime_support_ref);
        push_terminal_ref(refs, record.evidence_refs.read_serving_boundary_ref);
        push_terminal_ref(refs, record.evidence_refs.source_media_ref);
        push_terminal_ref(refs, record.evidence_refs.target_media_ref);
        push_terminal_ref(refs, record.evidence_refs.media_capability_ref);
        push_terminal_ref(refs, record.evidence_refs.source_path_ref);
        push_terminal_ref(refs, record.evidence_refs.target_destination_ref);
        push_terminal_start_charge_refs(refs, record, record.cost_state.required);
        if record_runtime_dispatch_needs_transport_or_trust(record) {
            push_terminal_ref(refs, record.evidence_refs.transport_budget_ref);
            push_terminal_ref(refs, record.evidence_refs.trust_domain_ref);
        }
        if record_uses_recovery_escalation(record) {
            push_terminal_ref(refs, record.evidence_refs.recovery_degradation_ref);
        }
    }

    fn push_terminal_start_refs_except(
        refs: &mut StorageIntentEvidenceRefs,
        record: PrefetchExecutorRecord,
        omitted: StorageIntentEvidenceRef,
    ) {
        push_terminal_start_ref_unless(refs, record.evidence_refs.prefetch_decision_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.scheduler_admission_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.dispatch_plan_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.runtime_support_ref, omitted);
        push_terminal_start_ref_unless(
            refs,
            record.evidence_refs.read_serving_boundary_ref,
            omitted,
        );
        push_terminal_start_ref_unless(refs, record.evidence_refs.source_media_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.target_media_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.media_capability_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.source_path_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.target_destination_ref, omitted);
        push_terminal_start_charge_refs_except(refs, record, record.cost_state.required, omitted);
        if record_runtime_dispatch_needs_transport_or_trust(record) {
            push_terminal_start_ref_unless(
                refs,
                record.evidence_refs.transport_budget_ref,
                omitted,
            );
            push_terminal_start_ref_unless(refs, record.evidence_refs.trust_domain_ref, omitted);
        }
        if record_uses_recovery_escalation(record) {
            push_terminal_start_ref_unless(
                refs,
                record.evidence_refs.recovery_degradation_ref,
                omitted,
            );
        }
    }

    fn push_terminal_start_ref_unless(
        refs: &mut StorageIntentEvidenceRefs,
        evidence_ref: StorageIntentEvidenceRef,
        omitted: StorageIntentEvidenceRef,
    ) {
        if evidence_ref != omitted {
            push_terminal_ref(refs, evidence_ref);
        }
    }

    fn push_terminal_start_charge_refs(
        refs: &mut StorageIntentEvidenceRefs,
        record: PrefetchExecutorRecord,
        required: PrefetchExecutorCostRequirementMask,
    ) {
        if required.is_empty() {
            return;
        }

        push_terminal_ref(refs, record.evidence_refs.cost_wear_ref);
        push_terminal_ref(refs, record.evidence_refs.tenant_isolation_ref);
        if terminal_charge_requires_egress_restore(required) {
            push_terminal_ref(refs, record.evidence_refs.egress_restore_cost_ref);
        }
        if terminal_charge_requires_transport(required) {
            push_terminal_ref(refs, record.evidence_refs.transport_budget_ref);
        }
    }

    fn push_terminal_start_charge_refs_except(
        refs: &mut StorageIntentEvidenceRefs,
        record: PrefetchExecutorRecord,
        required: PrefetchExecutorCostRequirementMask,
        omitted: StorageIntentEvidenceRef,
    ) {
        if required.is_empty() {
            return;
        }

        push_terminal_start_ref_unless(refs, record.evidence_refs.cost_wear_ref, omitted);
        push_terminal_start_ref_unless(refs, record.evidence_refs.tenant_isolation_ref, omitted);
        if terminal_charge_requires_egress_restore(required) {
            push_terminal_start_ref_unless(
                refs,
                record.evidence_refs.egress_restore_cost_ref,
                omitted,
            );
        }
        if terminal_charge_requires_transport(required) {
            push_terminal_start_ref_unless(
                refs,
                record.evidence_refs.transport_budget_ref,
                omitted,
            );
        }
    }

    fn admitted_charged_input(
        candidate: PrefetchResidencyCandidateClass,
        detail: PrefetchExecutorResultDetail,
    ) -> PrefetchExecutorInput {
        let mut input = admitted_input(candidate);
        input.cost_state.required = detail.charge_requirements();
        input
    }

    fn terminal_evidence_cut(
        record: PrefetchExecutorRecord,
        detail: PrefetchExecutorResultDetail,
        result_refusal_ref: StorageIntentEvidenceRef,
    ) -> PrefetchExecutorTerminalEvidenceCut {
        terminal_evidence_cut_with_interruption(
            record,
            detail,
            result_refusal_ref,
            EMPTY_EVIDENCE_REF,
        )
    }

    fn terminal_evidence_cut_with_interruption(
        record: PrefetchExecutorRecord,
        detail: PrefetchExecutorResultDetail,
        result_refusal_ref: StorageIntentEvidenceRef,
        interruption_ref: StorageIntentEvidenceRef,
    ) -> PrefetchExecutorTerminalEvidenceCut {
        let mut included_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_start_refs(&mut included_refs, record);
        push_terminal_ref(&mut included_refs, detail.attribution_ref);
        push_terminal_ref(&mut included_refs, detail.retention_ref);
        push_terminal_ref(&mut included_refs, detail.validation_ref);
        push_terminal_ref(&mut included_refs, result_refusal_ref);
        push_terminal_ref(&mut included_refs, interruption_ref);
        let required = record
            .cost_state
            .required
            .union(detail.charge_requirements());
        if !required.is_empty() {
            push_terminal_start_charge_refs(&mut included_refs, record, required);
        }

        PrefetchExecutorTerminalEvidenceCut {
            evidence_query_snapshot_ref: record.evidence_refs.evidence_query_snapshot_ref,
            included_refs,
        }
    }

    fn terminal_evidence_cut_with_degraded_visibility(
        record: PrefetchExecutorRecord,
        detail: PrefetchExecutorResultDetail,
        result_refusal_ref: StorageIntentEvidenceRef,
        degraded_visibility_ref: StorageIntentEvidenceRef,
    ) -> PrefetchExecutorTerminalEvidenceCut {
        let mut cut = terminal_evidence_cut(record, detail, result_refusal_ref);
        push_terminal_ref(&mut cut.included_refs, degraded_visibility_ref);
        cut
    }

    fn add_initial_feedback_roots(
        snapshot: &mut StorageIntentEvidenceQuerySnapshot,
        detail: PrefetchExecutorResultDetail,
    ) {
        push_terminal_ref(&mut snapshot.included_refs, detail.attribution_ref);
        push_terminal_ref(&mut snapshot.included_refs, detail.retention_ref);
        push_terminal_ref(&mut snapshot.included_refs, detail.validation_ref);
    }

    #[test]
    fn action_families_cover_required_candidates() {
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::BoundedReadahead
            ),
            PrefetchExecutorActionFamily::BoundedSequentialReadahead
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::StridedVectorPrefetch
            ),
            PrefetchExecutorActionFamily::StridedVectorRangePrefetch
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
            ),
            PrefetchExecutorActionFamily::MetadataNamespaceWalkPrefetch
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
            ),
            PrefetchExecutorActionFamily::SmallRandomHotsetCacheTrial
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::ManifestIndexPrefetch
            ),
            PrefetchExecutorActionFamily::ManifestIndexFanout
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::SnapshotClonePrefetch
            ),
            PrefetchExecutorActionFamily::SnapshotCloneRepeatedRead
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::DegradedReadPrefetch
            ),
            PrefetchExecutorActionFamily::DegradedReadReconstruction
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
            ),
            PrefetchExecutorActionFamily::WanGeoDeltaPrefetch
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
            ),
            PrefetchExecutorActionFamily::ObjectArchiveRestoreStaging
        );
        assert_eq!(
            PrefetchExecutorActionFamily::from_candidate(
                PrefetchResidencyCandidateClass::NoPrefetch
            ),
            PrefetchExecutorActionFamily::ExplicitNoPrefetch
        );
    }

    #[test]
    fn missing_decision_or_evidence_query_blocks_execution() {
        let record = evaluate_prefetch_execution(PrefetchExecutorInput::default());
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn stale_snapshot_blocks_execution() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.evidence_query_snapshot.policy_revision = StorageIntentPolicyRevision(6);
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Stale);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn mismatched_snapshot_subject_blocks_execution() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input
            .evidence_query_snapshot
            .subject
            .object_scope
            .range_start += 1;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Stale);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn freshness_rpo_floor_is_preserved_when_proven() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.freshness_rpo_floor_ms = 5;
        input.evidence_query_snapshot.allowed_staleness_ms = 1;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(record.freshness_rpo_floor_ms, 5);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::CacheOnly
        );
    }

    #[test]
    fn freshness_rpo_floor_requires_known_snapshot_staleness() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.freshness_rpo_floor_ms = 5;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn no_prefetch_enforcement_preserves_floor_without_positive_dispatch() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::NoPrefetch);
        input.freshness_rpo_floor_ms = 5;
        input.decision.outcome = PrefetchResidencyDecisionOutcome::NoAction;
        input.admission = PrefetchExecutorAdmissionRecord::default();
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Completed);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::NoPrefetchEnforced
        );
        assert_eq!(record.freshness_rpo_floor_ms, 5);
        assert!(!record.can_satisfy_durable_sync());
    }

    #[test]
    fn stale_snapshot_frontier_misses_freshness_rpo_floor() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.freshness_rpo_floor_ms = 1;
        input.evidence_query_snapshot.allowed_staleness_ms = 1;
        input.evidence_query_snapshot.freshness_frontier_ms = 8;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
    }

    #[test]
    fn read_freshness_family_must_satisfy_rpo_floor() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.freshness_rpo_floor_ms = 1;
        input.evidence_query_snapshot.allowed_staleness_ms = 1;
        rewrite_family_freshness(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            10,
            3,
        );
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
    }

    #[test]
    fn cache_trial_record_is_cache_only_and_not_durable_authority() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::SmallRandomHotsetTrial);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::ServingTrial;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::CacheOnlyTrial
        );
        assert!(record.is_non_authority_population());
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn staged_and_degraded_bytes_stay_read_source_candidates_only() {
        let mut staged = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        staged.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut staged.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        let staged_record = evaluate_prefetch_execution(staged);
        assert_eq!(staged_record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            staged_record.executor_byte_state,
            PrefetchExecutorByteState::Staged
        );
        assert!(staged_record.is_non_authority_population());
        assert_record_has_no_authority_claims(staged_record);

        let degraded = admitted_input(PrefetchResidencyCandidateClass::DegradedReadPrefetch);
        let degraded_record = evaluate_prefetch_execution(degraded);
        assert_eq!(degraded_record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            degraded_record.executor_byte_state,
            PrefetchExecutorByteState::DegradedVisible
        );
        assert!(degraded_record.is_non_authority_population());
        assert_record_has_no_authority_claims(degraded_record);
    }

    #[test]
    fn pressured_speculative_dispatch_requires_controls_or_recovery_escalation() {
        let mut unprotected = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        unprotected.admission.pressure = PrefetchExecutorPressureMask::P99_LATENCY;
        unprotected.admission = unprotected
            .admission
            .with_speculative_controls(false, false, false);
        let unprotected_record = evaluate_prefetch_execution(unprotected);
        assert_eq!(unprotected_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            unprotected_record.refusal,
            StorageIntentRefusalReason::NoisyNeighborPressure
        );
        assert_record_has_no_authority_claims(unprotected_record);

        let mut missing_ref = unprotected;
        missing_ref.admission = missing_ref.admission.with_recovery_escalation(
            PrefetchExecutorRecoveryEscalationClass::DegradedRiskReduction,
            EMPTY_EVIDENCE_REF,
        );
        let missing_ref_record = evaluate_prefetch_execution(missing_ref);
        assert_eq!(missing_ref_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            missing_ref_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(missing_ref_record);

        let wrong_kind_ref = evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, RECOVERY);
        let mut wrong_kind = unprotected;
        wrong_kind.admission = wrong_kind.admission.with_recovery_escalation(
            PrefetchExecutorRecoveryEscalationClass::RepairEscalation,
            wrong_kind_ref,
        );
        wrong_kind
            .evidence_query_snapshot
            .included_refs
            .push(wrong_kind_ref)
            .unwrap();
        let wrong_kind_record = evaluate_prefetch_execution(wrong_kind);
        assert_eq!(wrong_kind_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            wrong_kind_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(wrong_kind_record);

        let recovery_ref = evidence(
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );
        let mut escalated = unprotected;
        add_fresh(
            &mut escalated.evidence_query_snapshot,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );
        escalated.admission = escalated.admission.with_recovery_escalation(
            PrefetchExecutorRecoveryEscalationClass::DegradedRiskReduction,
            recovery_ref,
        );
        let escalated_record = evaluate_prefetch_execution(escalated);
        assert_eq!(escalated_record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            escalated_record.evidence_refs.recovery_degradation_ref,
            recovery_ref
        );
        assert_record_has_no_authority_claims(escalated_record);
    }

    #[test]
    fn feedback_result_detail_is_preserved_for_975() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission.requested_bytes = 16 * 1024;
        input.admission.admitted_bytes = 12 * 1024;
        input.admission.queue_time_us = 17;
        input.admission.reserve_protected = true;
        input.admission.pressure = PrefetchExecutorPressureMask::P99_LATENCY
            .union(PrefetchExecutorPressureMask::PROTECTED_RESERVE);
        input.result_detail = PrefetchExecutorResultDetail {
            prefetched_bytes: 12 * 1024,
            used_bytes: 8 * 1024,
            unused_bytes: 3 * 1024,
            expired_bytes: 1024,
            latency_benefit_us: 1_500,
            latency_harm_us: 25,
            foreground_p50_disruption_us: 4,
            foreground_p95_disruption_us: 12,
            foreground_p99_disruption_us: 31,
            queue_delay_us: 17,
            flash_write_bytes: 512,
            pmem_write_bytes: 256,
            waf_micros: 1_250_000,
            ram_pressure_bytes: 64 * 1024,
            cache_index_write_bytes: 128,
            predictor_metadata_write_bytes: 64,
            wan_bytes: 32,
            egress_cost_microunits: 7,
            restore_cost_microunits: 11,
            staging_capacity_bytes: 12 * 1024,
            cpu_us: 42,
            memory_bytes: 64 * 1024,
            protected_reserve_pressure: true,
            attribution_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                ATTRIBUTION,
            ),
            retention_ref: evidence(
                StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                RETENTION,
            ),
            validation_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, VALIDATION),
        };
        add_initial_feedback_roots(&mut input.evidence_query_snapshot, input.result_detail);

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(record.subject.dataset_id, DATASET);
        assert_eq!(record.result_detail, input.result_detail);
        assert!(record.has_feedback_payback_inputs());
        assert!(record.result_detail.has_feedback_evidence_roots());
        assert_eq!(
            record.evidence_refs.attribution_ref,
            input.result_detail.attribution_ref
        );
        assert_eq!(
            record.evidence_refs.retention_ref,
            input.result_detail.retention_ref
        );
        assert_eq!(
            record.evidence_refs.validation_ref,
            input.result_detail.validation_ref
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn initial_feedback_detail_requires_evidence_roots() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.result_detail = PrefetchExecutorResultDetail {
            prefetched_bytes: 4 * 1024,
            used_bytes: 3 * 1024,
            unused_bytes: 1024,
            ..PrefetchExecutorResultDetail::default()
        };

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::VerificationFailed);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn initial_feedback_roots_must_be_inside_evidence_snapshot() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.result_detail = terminal_detail();

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::VerificationFailed);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn completion_alone_is_not_feedback_payback_evidence() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::NoPrefetch);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::NoAction;
        input.admission = PrefetchExecutorAdmissionRecord::default();
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Completed);
        assert!(!record.has_feedback_payback_inputs());
        assert!(!record.result_detail.has_feedback_evidence_roots());
    }

    #[test]
    fn scheduler_drop_is_preserved() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission = input.admission.with_outcome(
            PrefetchExecutorAdmissionOutcome::Dropped,
            StorageIntentRefusalReason::NoisyNeighborPressure,
        );
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Dropped);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::NoisyNeighborPressure
        );
    }

    #[test]
    fn pressured_speculative_admission_requires_cancellation_controls() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission = input
            .admission
            .with_speculative_controls(false, false, false);
        input.admission.pressure = PrefetchExecutorPressureMask::P99_LATENCY;

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::NoisyNeighborPressure
        );
        assert!(!record.can_publish_replacement_receipt());
        assert!(!record.can_satisfy_durable_sync());
    }

    #[test]
    fn scheduler_lane_mismatch_refuses_speculative_priority_bypass() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission.lane = PrefetchExecutorSchedulerLane::Demand;
        input.admission = input
            .admission
            .with_speculative_controls(false, false, false);
        input.admission.pressure = PrefetchExecutorPressureMask::P99_LATENCY;

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(record.refusal, StorageIntentRefusalReason::PolicyConflict);
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn scheduler_lane_recovery_escalation_allows_stricter_lane_with_evidence() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );
        input.admission.lane = PrefetchExecutorSchedulerLane::Demand;
        input.admission = input
            .admission
            .with_speculative_controls(false, false, false)
            .with_recovery_escalation(
                PrefetchExecutorRecoveryEscalationClass::DegradedRiskReduction,
                evidence(
                    StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                    RECOVERY,
                ),
            );
        input.admission.pressure = PrefetchExecutorPressureMask::P99_LATENCY;

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::CacheOnly
        );
        assert_eq!(
            record.evidence_refs.recovery_degradation_ref,
            input.admission.recovery_degradation_ref
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn admitted_scheduler_ref_must_be_inside_evidence_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission.scheduler_admission_ref = evidence(
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            OUTSIDE_CUT,
        );

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn admitted_budget_owner_must_match_decision_owner() {
        let mut missing_owner = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_owner.admission.budget_owner = StorageIntentDomainId::ZERO;

        let missing_owner_record = evaluate_prefetch_execution(missing_owner);
        assert_eq!(
            missing_owner_record.outcome,
            PrefetchExecutorOutcome::Refused
        );
        assert_eq!(
            missing_owner_record.refusal,
            StorageIntentRefusalReason::MissingBudgetOwnerEvidence
        );

        let mut mismatched_owner =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        mismatched_owner.admission.budget_owner = StorageIntentDomainId([9; 16]);

        let mismatched_owner_record = evaluate_prefetch_execution(mismatched_owner);
        assert_eq!(
            mismatched_owner_record.outcome,
            PrefetchExecutorOutcome::Refused
        );
        assert_eq!(
            mismatched_owner_record.refusal,
            StorageIntentRefusalReason::PolicyConflict
        );
    }

    #[test]
    fn required_isolation_ref_must_be_inside_evidence_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.cost_state.isolation_ref = evidence(
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            OUTSIDE_CUT,
        );

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::StaleIsolationEvidence
        );
    }

    #[test]
    fn missing_runtime_support_keeps_admitted_action_unavailable() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.runtime_support = PrefetchExecutorRuntimeSupport::default();
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Unavailable);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Unavailable
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!record.can_satisfy_durable_sync());
    }

    #[test]
    fn runtime_support_mask_must_cover_selected_family() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.runtime_support = PrefetchExecutorRuntimeSupport::supported(
            PrefetchExecutorRuntimeSupportMask::STRIDED_VECTOR_RANGE_PREFETCH,
            evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, ACTION),
        );
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Unavailable);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Unavailable
        );
    }

    #[test]
    fn runtime_support_ref_must_be_inside_evidence_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.runtime_support = PrefetchExecutorRuntimeSupport::supported(
            PrefetchExecutorRuntimeSupportMask::BOUNDED_SEQUENTIAL_READAHEAD,
            evidence(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                OUTSIDE_CUT,
            ),
        );

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn missing_runtime_support_does_not_mask_missing_dispatch_plan() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.runtime_support = PrefetchExecutorRuntimeSupport::default();
        input.dispatch_plan = PrefetchExecutorDispatchPlan::default();

        let record = evaluate_prefetch_execution(input);

        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn wrong_runtime_support_does_not_mask_out_of_cut_dispatch_plan() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.runtime_support = PrefetchExecutorRuntimeSupport::supported(
            PrefetchExecutorRuntimeSupportMask::STRIDED_VECTOR_RANGE_PREFETCH,
            evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, ACTION),
        );
        input.dispatch_plan.plan_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            OUTSIDE_CUT,
        );

        let record = evaluate_prefetch_execution(input);

        assert_eq!(record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn started_record_preserves_typed_dispatch_plan() {
        let input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        let dispatch_plan = input.dispatch_plan;
        let record = evaluate_prefetch_execution(input);

        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(record.dispatch_plan, dispatch_plan);
        assert_eq!(
            record.dispatch_plan.shape,
            PrefetchExecutorDispatchShape::BoundedRange
        );
        assert_eq!(
            record.evidence_refs.dispatch_plan_ref,
            evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, ACTION)
        );
    }

    #[test]
    fn runtime_dispatch_requires_typed_dispatch_plan() {
        let mut missing_plan = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_plan.dispatch_plan = PrefetchExecutorDispatchPlan::default();
        let missing_plan_record = evaluate_prefetch_execution(missing_plan);
        assert_eq!(
            missing_plan_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_plan_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut wrong_shape = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_shape.dispatch_plan = wrong_shape
            .dispatch_plan
            .with_shape(PrefetchExecutorDispatchShape::StridedVectorRanges)
            .with_stride(4096, 2);
        let wrong_shape_record = evaluate_prefetch_execution(wrong_shape);
        assert_eq!(wrong_shape_record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            wrong_shape_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut missing_ref = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_ref.dispatch_plan.plan_ref = EMPTY_EVIDENCE_REF;
        let missing_ref_record = evaluate_prefetch_execution(missing_ref);
        assert_eq!(missing_ref_record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            missing_ref_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut outside_cut = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        outside_cut.dispatch_plan.plan_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            OUTSIDE_CUT,
        );
        let outside_cut_record = evaluate_prefetch_execution(outside_cut);
        assert_eq!(outside_cut_record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            outside_cut_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn dispatch_plan_bounds_subject_and_executor_limit() {
        let mut outside_subject = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        outside_subject.dispatch_plan.range_start =
            outside_subject.decision.scope.range_start + outside_subject.decision.scope.range_len;
        outside_subject.dispatch_plan.range_bytes = 1;
        let outside_subject_record = evaluate_prefetch_execution(outside_subject);
        assert_eq!(
            outside_subject_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            outside_subject_record.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );

        let mut over_limit = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        over_limit.decision.max_prefetch_window_bytes = 1024;
        let over_limit_record = evaluate_prefetch_execution(over_limit);
        assert_eq!(
            over_limit_record.outcome,
            PrefetchExecutorOutcome::OverBudget
        );
        assert_eq!(
            over_limit_record.refusal,
            StorageIntentRefusalReason::OverBudget
        );
    }

    #[test]
    fn strided_vector_dispatch_requires_stride_and_count() {
        let input = admitted_input(PrefetchResidencyCandidateClass::StridedVectorPrefetch);
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            record.dispatch_plan.shape,
            PrefetchExecutorDispatchShape::StridedVectorRanges
        );
        assert_eq!(record.dispatch_plan.stride_bytes, 4096);
        assert_eq!(record.dispatch_plan.range_count, 2);

        let mut missing_stride =
            admitted_input(PrefetchResidencyCandidateClass::StridedVectorPrefetch);
        missing_stride.dispatch_plan.stride_bytes = 0;
        let missing_stride_record = evaluate_prefetch_execution(missing_stride);
        assert_eq!(
            missing_stride_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_stride_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn metadata_namespace_dispatch_requires_bounded_walk_plan() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::MetadataNamespacePrefetch);
        input.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::MetadataNamespaceEvidence));
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            record.dispatch_plan.shape,
            PrefetchExecutorDispatchShape::MetadataNamespaceWalk
        );
        assert_eq!(record.dispatch_plan.fanout_limit, 16);
        assert_eq!(record.dispatch_plan.namespace_depth_limit, 2);

        let mut unbounded = input;
        unbounded.dispatch_plan.range_bytes = 0;
        unbounded.dispatch_plan.fanout_limit = 0;
        unbounded.dispatch_plan.namespace_depth_limit = 0;
        let unbounded_record = evaluate_prefetch_execution(unbounded);
        assert_eq!(unbounded_record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            unbounded_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn admitted_runtime_dispatch_requires_source_and_destination_refs() {
        let mut missing_source = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_source.media_path.source_path_ref = EMPTY_EVIDENCE_REF;
        let missing_source_record = evaluate_prefetch_execution(missing_source);
        assert_eq!(
            missing_source_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_source_record.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );

        let mut missing_target = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_target.media_path.target_destination_ref = EMPTY_EVIDENCE_REF;
        let missing_target_record = evaluate_prefetch_execution(missing_target);
        assert_eq!(
            missing_target_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_target_record.refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );

        let mut outside_cut = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        outside_cut.media_path.target_destination_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            OUTSIDE_CUT,
        );
        let outside_cut_record = evaluate_prefetch_execution(outside_cut);
        assert_eq!(outside_cut_record.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            outside_cut_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut wrong_source_kind =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_source_kind.media_path.source_path_ref =
            wrong_source_kind.media_path.target_destination_ref;
        let wrong_source_kind_record = evaluate_prefetch_execution(wrong_source_kind);
        assert_eq!(
            wrong_source_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_source_kind_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut wrong_target_kind =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_target_kind.media_path.target_destination_ref =
            wrong_target_kind.media_path.source_path_ref;
        let wrong_target_kind_record = evaluate_prefetch_execution(wrong_target_kind);
        assert_eq!(
            wrong_target_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_target_kind_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn admitted_runtime_dispatch_requires_read_serving_boundary_ref() {
        let mut missing_boundary =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_boundary
            .decision
            .evidence_refs
            .read_serving_boundary_ref = EMPTY_EVIDENCE_REF;
        let missing_boundary_record = evaluate_prefetch_execution(missing_boundary);
        assert_eq!(
            missing_boundary_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_boundary_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut wrong_boundary_kind =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_boundary_kind
            .decision
            .evidence_refs
            .read_serving_boundary_ref = wrong_boundary_kind.media_path.target_destination_ref;
        let wrong_boundary_kind_record = evaluate_prefetch_execution(wrong_boundary_kind);
        assert_eq!(
            wrong_boundary_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_boundary_kind_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn admitted_runtime_dispatch_requires_media_capability_refs() {
        let mut missing_source_media =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_source_media.decision.source_media_ref = EMPTY_EVIDENCE_REF;
        let missing_source_media_record = evaluate_prefetch_execution(missing_source_media);
        assert_eq!(
            missing_source_media_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_source_media_record.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );

        let mut missing_target_media =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_target_media.decision.target_media_ref = EMPTY_EVIDENCE_REF;
        let missing_target_media_record = evaluate_prefetch_execution(missing_target_media);
        assert_eq!(
            missing_target_media_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_target_media_record.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );

        let mut missing_role_media =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        missing_role_media.media_path.media_capability_ref = EMPTY_EVIDENCE_REF;
        missing_role_media
            .decision
            .evidence_refs
            .media_capability_ref = EMPTY_EVIDENCE_REF;
        let missing_role_media_record = evaluate_prefetch_execution(missing_role_media);
        assert_eq!(
            missing_role_media_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_role_media_record.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );

        let mut wrong_source_kind =
            admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_source_kind.decision.source_media_ref = wrong_source_kind.media_path.source_path_ref;
        let wrong_source_kind_record = evaluate_prefetch_execution(wrong_source_kind);
        assert_eq!(
            wrong_source_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_source_kind_record.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );

        let mut wrong_role_kind = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        wrong_role_kind.media_path.media_capability_ref =
            wrong_role_kind.media_path.source_path_ref;
        wrong_role_kind.decision.evidence_refs.media_capability_ref =
            wrong_role_kind.media_path.source_path_ref;
        let wrong_role_kind_record = evaluate_prefetch_execution(wrong_role_kind);
        assert_eq!(
            wrong_role_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_role_kind_record.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );
    }

    #[test]
    fn runtime_dispatch_refuses_media_path_class_conflicts() {
        let mut source_conflict = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        let expected_source = source_conflict.decision.source_media;
        source_conflict.media_path.source_media = StorageMediaClass::NvmeFlash;
        let source_conflict_record = evaluate_prefetch_execution(source_conflict);
        assert_eq!(
            source_conflict_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            source_conflict_record.refusal,
            StorageIntentRefusalReason::PolicyConflict
        );
        assert_eq!(source_conflict_record.source_media, expected_source);
        assert_record_has_no_authority_claims(source_conflict_record);

        let mut target_conflict = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        let expected_target = target_conflict.decision.target_media;
        target_conflict.media_path.target_media = StorageMediaClass::PersistentMemory;
        let target_conflict_record = evaluate_prefetch_execution(target_conflict);
        assert_eq!(
            target_conflict_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            target_conflict_record.refusal,
            StorageIntentRefusalReason::PolicyConflict
        );
        assert_eq!(target_conflict_record.target_media, expected_target);
        assert_record_has_no_authority_claims(target_conflict_record);
    }

    #[test]
    fn remote_runtime_dispatch_requires_transport_and_trust_refs() {
        let mut missing_transport =
            admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        missing_transport.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut missing_transport.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        missing_transport
            .decision
            .evidence_refs
            .transport_budget_ref = EMPTY_EVIDENCE_REF;
        missing_transport.media_path.transport_path_ref = EMPTY_EVIDENCE_REF;
        let missing_transport_record = evaluate_prefetch_execution(missing_transport);
        assert_eq!(
            missing_transport_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_transport_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut missing_trust =
            admitted_input(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);
        missing_trust.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut missing_trust.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        missing_trust.decision.evidence_refs.trust_domain_ref = EMPTY_EVIDENCE_REF;
        missing_trust.media_path.trust_domain_ref = EMPTY_EVIDENCE_REF;
        let missing_trust_record = evaluate_prefetch_execution(missing_trust);
        assert_eq!(
            missing_trust_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            missing_trust_record.refusal,
            StorageIntentRefusalReason::StaleTrustEvidence
        );

        let mut wrong_transport_kind =
            admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        wrong_transport_kind.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut wrong_transport_kind.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        wrong_transport_kind.media_path.transport_path_ref =
            wrong_transport_kind.media_path.source_path_ref;
        wrong_transport_kind
            .decision
            .evidence_refs
            .transport_budget_ref = wrong_transport_kind.media_path.source_path_ref;
        let wrong_transport_kind_record = evaluate_prefetch_execution(wrong_transport_kind);
        assert_eq!(
            wrong_transport_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_transport_kind_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut wrong_trust_kind =
            admitted_input(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);
        wrong_trust_kind.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut wrong_trust_kind.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        wrong_trust_kind.media_path.trust_domain_ref = wrong_trust_kind.media_path.source_path_ref;
        wrong_trust_kind.decision.evidence_refs.trust_domain_ref =
            wrong_trust_kind.media_path.source_path_ref;
        let wrong_trust_kind_record = evaluate_prefetch_execution(wrong_trust_kind);
        assert_eq!(
            wrong_trust_kind_record.outcome,
            PrefetchExecutorOutcome::Blocked
        );
        assert_eq!(
            wrong_trust_kind_record.refusal,
            StorageIntentRefusalReason::StaleTrustEvidence
        );
    }

    #[test]
    fn unknown_waf_and_egress_refuse_when_policy_requires_proof() {
        let mut waf = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        waf.require_known_waf = true;
        waf.cost_state.unknown_waf = true;
        let waf_record = evaluate_prefetch_execution(waf);
        assert_eq!(waf_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            waf_record.refusal,
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        );

        let mut egress = admitted_input(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);
        egress.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut egress.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        egress.require_known_egress_restore_cost = true;
        egress.cost_state.unknown_egress_or_restore_cost = true;
        let egress_record = evaluate_prefetch_execution(egress);
        assert_eq!(egress_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            egress_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn unknown_cost_anti_waste_drops_without_zero_cost_dispatch() {
        let mut waf = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        waf.anti_waste = PrefetchExecutorAntiWasteMask::UNKNOWN_WAF;
        let waf_record = evaluate_prefetch_execution(waf);
        assert_eq!(waf_record.outcome, PrefetchExecutorOutcome::Dropped);
        assert_eq!(
            waf_record.refusal,
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        );
        assert!(!waf_record.can_satisfy_durable_sync());

        let mut egress = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        egress.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut egress.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        egress.anti_waste = PrefetchExecutorAntiWasteMask::UNKNOWN_EGRESS_OR_RESTORE_COST;
        let egress_record = evaluate_prefetch_execution(egress);
        assert_eq!(egress_record.outcome, PrefetchExecutorOutcome::Dropped);
        assert_eq!(
            egress_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!egress_record.can_publish_replacement_receipt());
    }

    #[test]
    fn missing_required_cost_class_is_not_zero_cost() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);
        input.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        input.cost_state.required = PrefetchExecutorCostRequirementMask::EGRESS;
        input.cost_state.snapshot.evidence_state = StorageIntentCostEvidenceState::FRESH
            .with_missing(StorageIntentCostClass::NetworkEgress);
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn required_cost_ref_must_be_inside_evidence_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.cost_state.required = PrefetchExecutorCostRequirementMask::FLASH_WRITES;
        input.cost_state.cost_ref =
            evidence(StorageIntentEvidenceKind::MediaCostWearLedger, OUTSIDE_CUT);

        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn every_required_executor_cost_class_refuses_missing_evidence() {
        let cases = [
            (
                PrefetchExecutorCostRequirementMask::FLASH_WRITES,
                StorageIntentCostClass::CapacityMediaClass,
            ),
            (
                PrefetchExecutorCostRequirementMask::CACHE_DEVICE_INDEXES,
                StorageIntentCostClass::CapacityMediaClass,
            ),
            (
                PrefetchExecutorCostRequirementMask::PREDICTOR_CHECKPOINTS,
                StorageIntentCostClass::TransformProcessing,
            ),
            (
                PrefetchExecutorCostRequirementMask::RETAINED_EVIDENCE,
                StorageIntentCostClass::ColdRetention,
            ),
            (
                PrefetchExecutorCostRequirementMask::RAM_PMEM_CAPACITY,
                StorageIntentCostClass::CapacityMediaClass,
            ),
            (
                PrefetchExecutorCostRequirementMask::CPU,
                StorageIntentCostClass::CpuProcessing,
            ),
            (
                PrefetchExecutorCostRequirementMask::MEMORY,
                StorageIntentCostClass::MemoryUsage,
            ),
            (
                PrefetchExecutorCostRequirementMask::WAN_BANDWIDTH,
                StorageIntentCostClass::NetworkIngress,
            ),
            (
                PrefetchExecutorCostRequirementMask::EGRESS,
                StorageIntentCostClass::NetworkEgress,
            ),
            (
                PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS,
                StorageIntentCostClass::RestoreTime,
            ),
            (
                PrefetchExecutorCostRequirementMask::STAGING_CAPACITY,
                StorageIntentCostClass::CapacityMediaClass,
            ),
            (
                PrefetchExecutorCostRequirementMask::FOREGROUND_DISRUPTION,
                StorageIntentCostClass::ForegroundDisruption,
            ),
        ];

        for (requirement, cost_class) in cases {
            let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
            input.cost_state.required = requirement;
            input.cost_state.snapshot.evidence_state =
                StorageIntentCostEvidenceState::FRESH.with_missing(cost_class);

            let record = evaluate_prefetch_execution(input);
            assert_eq!(
                record.outcome,
                PrefetchExecutorOutcome::Refused,
                "requirement {requirement:?} did not refuse missing {cost_class:?}"
            );
            assert_eq!(
                record.refusal,
                StorageIntentRefusalReason::EvidenceNotUsable,
                "requirement {requirement:?} reported the wrong refusal"
            );
        }
    }

    #[test]
    fn required_flash_and_remote_costs_reject_unknown_cost_state() {
        let mut flash = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        flash.cost_state.required = PrefetchExecutorCostRequirementMask::FLASH_WRITES;
        flash.cost_state.unknown_waf = true;
        let flash_record = evaluate_prefetch_execution(flash);
        assert_eq!(flash_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            flash_record.refusal,
            StorageIntentRefusalReason::FlashWearBudgetExceeded
        );

        let mut egress = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        egress.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut egress.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        egress.cost_state.required = PrefetchExecutorCostRequirementMask::EGRESS;
        egress.cost_state.unknown_egress_or_restore_cost = true;
        let egress_record = evaluate_prefetch_execution(egress);
        assert_eq!(egress_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            egress_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut restore =
            admitted_input(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage);
        restore.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut restore.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        restore.cost_state.required =
            PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS;
        restore.cost_state.unknown_egress_or_restore_cost = true;
        let restore_record = evaluate_prefetch_execution(restore);
        assert_eq!(restore_record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            restore_record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn rdma_absence_is_not_a_correctness_failure() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        input.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        input.media_path.rdma_available = false;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Started);
        assert_ne!(
            record.refusal,
            StorageIntentRefusalReason::RdmaRequiredForCorrectness
        );
    }

    #[test]
    fn authority_changing_decision_hands_off_without_receipt_power() {
        let mut input =
            admitted_input(PrefetchResidencyCandidateClass::AuthorityPromotionCandidate);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::PromotionCandidate;
        input.decision.selected_residency = PrefetchResidencyStateClass::PmemDurable;
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::HandoffRequired);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::HandoffRequired
        );
        assert_eq!(
            record.handoff_target,
            PrefetchExecutorHandoffTarget::DurableResidencyChange
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn explicit_no_prefetch_completes_without_dispatch_authority() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::NoPrefetch);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::NoAction;
        input.admission = PrefetchExecutorAdmissionRecord::default();
        let record = evaluate_prefetch_execution(input);
        assert_eq!(record.outcome, PrefetchExecutorOutcome::Completed);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::NoPrefetchEnforced
        );
        assert!(record.is_non_authority_population());
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn refused_no_prefetch_decision_does_not_complete_negative_enforcement() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::NoPrefetch);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::NeedMoreEvidence;
        input.decision.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        input.admission = PrefetchExecutorAdmissionRecord::default();

        let record = evaluate_prefetch_execution(input);

        assert_eq!(record.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(
            record.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_eq!(
            record.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(record);
    }

    #[test]
    fn terminal_update_completes_started_record_without_authority() {
        let detail = terminal_detail();
        let started = evaluate_prefetch_execution(admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            detail,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let result_ref = evidence(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            RESULT_REFUSAL,
        );
        let completed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut(started, detail, result_ref),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(completed.outcome, PrefetchExecutorOutcome::Completed);
        assert_eq!(completed.refusal, StorageIntentRefusalReason::None);
        assert_eq!(completed.executor_byte_state, started.executor_byte_state);
        assert_eq!(completed.result_detail, detail);
        assert_eq!(
            completed.evidence_refs.attribution_ref,
            detail.attribution_ref
        );
        assert_eq!(completed.evidence_refs.retention_ref, detail.retention_ref);
        assert_eq!(
            completed.evidence_refs.validation_ref,
            detail.validation_ref
        );
        assert_eq!(completed.evidence_refs.result_refusal_ref, result_ref);
        assert!(completed.has_feedback_payback_inputs());
        assert!(completed.result_detail.has_feedback_evidence_roots());
        assert!(completed.is_non_authority_population());
        assert_record_has_no_authority_claims(completed);
    }

    #[test]
    fn terminal_update_requires_started_dispatch_refs_inside_terminal_cut() {
        let detail = terminal_detail();
        let started = evaluate_prefetch_execution(admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            detail,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let mut feedback_and_charge_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_ref(&mut feedback_and_charge_refs, detail.attribution_ref);
        push_terminal_ref(&mut feedback_and_charge_refs, detail.retention_ref);
        push_terminal_ref(&mut feedback_and_charge_refs, detail.validation_ref);
        push_terminal_start_charge_refs(
            &mut feedback_and_charge_refs,
            started,
            detail.charge_requirements(),
        );

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: feedback_and_charge_refs,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_requires_runtime_support_ref_inside_terminal_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        let runtime_support_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            RUNTIME_SUPPORT,
        );
        input
            .evidence_query_snapshot
            .included_refs
            .push(runtime_support_ref)
            .unwrap();
        input.runtime_support = PrefetchExecutorRuntimeSupport::supported(
            PrefetchExecutorRuntimeSupportMask::BOUNDED_SEQUENTIAL_READAHEAD,
            runtime_support_ref,
        );
        let started = evaluate_prefetch_execution(input);
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);
        assert_eq!(
            started.evidence_refs.runtime_support_ref,
            runtime_support_ref
        );
        assert_ne!(
            started.evidence_refs.runtime_support_ref,
            started.evidence_refs.dispatch_plan_ref
        );

        let mut missing_runtime_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_start_refs_except(
            &mut missing_runtime_refs,
            started,
            started.evidence_refs.runtime_support_ref,
        );
        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: missing_runtime_refs,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(rejected);

        let completed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(completed.outcome, PrefetchExecutorOutcome::Completed);
        assert_record_has_no_authority_claims(completed);
    }

    #[test]
    fn terminal_update_requires_remote_transport_and_trust_start_refs() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        input.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        let started = evaluate_prefetch_execution(input);
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);
        assert!(record_runtime_dispatch_needs_transport_or_trust(started));

        let mut missing_trust_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_start_refs_except(
            &mut missing_trust_refs,
            started,
            started.evidence_refs.trust_domain_ref,
        );
        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: missing_trust_refs,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(rejected);

        let completed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(completed.outcome, PrefetchExecutorOutcome::Completed);
        assert_record_has_no_authority_claims(completed);
    }

    #[test]
    fn terminal_update_requires_recovery_escalation_ref_inside_terminal_cut() {
        let recovery_ref = evidence(
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );
        let mut input = admitted_input(PrefetchResidencyCandidateClass::BoundedReadahead);
        input.admission.pressure = PrefetchExecutorPressureMask::REPAIR;
        input.admission = input
            .admission
            .with_speculative_controls(false, false, false)
            .with_recovery_escalation(
                PrefetchExecutorRecoveryEscalationClass::RepairEscalation,
                recovery_ref,
            );
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );
        let started = evaluate_prefetch_execution(input);
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);
        assert!(record_uses_recovery_escalation(started));

        let mut missing_recovery_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_start_refs_except(
            &mut missing_recovery_refs,
            started,
            started.evidence_refs.recovery_degradation_ref,
        );
        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: missing_recovery_refs,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(rejected);

        let completed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(completed.outcome, PrefetchExecutorOutcome::Completed);
        assert_record_has_no_authority_claims(completed);
    }

    #[test]
    fn terminal_detail_derives_charge_requirements_from_measurements() {
        let detail = PrefetchExecutorResultDetail {
            flash_write_bytes: 1,
            waf_micros: 1,
            pmem_write_bytes: 1,
            ram_pressure_bytes: 1,
            cache_index_write_bytes: 1,
            predictor_metadata_write_bytes: 1,
            wan_bytes: 1,
            egress_cost_microunits: 1,
            restore_cost_microunits: 1,
            staging_capacity_bytes: 1,
            cpu_us: 1,
            memory_bytes: 1,
            foreground_p95_disruption_us: 1,
            protected_reserve_pressure: true,
            ..PrefetchExecutorResultDetail::default()
        };

        let required = detail.charge_requirements();

        assert!(required.contains(PrefetchExecutorCostRequirementMask::FLASH_WRITES));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::RAM_PMEM_CAPACITY));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::CACHE_DEVICE_INDEXES));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::PREDICTOR_CHECKPOINTS));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::WAN_BANDWIDTH));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::EGRESS));
        assert!(
            required.contains(PrefetchExecutorCostRequirementMask::OBJECT_ARCHIVE_RESTORE_CALLS)
        );
        assert!(required.contains(PrefetchExecutorCostRequirementMask::STAGING_CAPACITY));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::CPU));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::MEMORY));
        assert!(required.contains(PrefetchExecutorCostRequirementMask::FOREGROUND_DISRUPTION));
    }

    #[test]
    fn terminal_update_rejects_uncharged_result_measurements() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let detail = terminal_detail();
        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                evidence_cut: terminal_evidence_cut(started, detail, EMPTY_EVIDENCE_REF),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_requires_charge_refs_inside_terminal_cut() {
        let detail = terminal_detail();
        let started = evaluate_prefetch_execution(admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            detail,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let mut feedback_only_refs = StorageIntentEvidenceRefs::EMPTY;
        push_terminal_ref(&mut feedback_only_refs, detail.attribution_ref);
        push_terminal_ref(&mut feedback_only_refs, detail.retention_ref);
        push_terminal_ref(&mut feedback_only_refs, detail.validation_ref);

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: feedback_only_refs,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_rejects_measured_result_without_feedback_root() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let measured_without_root = PrefetchExecutorResultDetail {
            prefetched_bytes: 128 * 1024,
            used_bytes: 96 * 1024,
            unused_bytes: 16 * 1024,
            expired_bytes: 16 * 1024,
            latency_benefit_us: 900,
            flash_write_bytes: 512,
            waf_micros: 1_050_000,
            ..PrefetchExecutorResultDetail::default()
        };
        assert!(measured_without_root.has_feedback_payback_inputs());
        assert!(!measured_without_root.has_feedback_evidence_roots());

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: measured_without_root,
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_rejects_partial_or_wrong_kind_feedback_roots() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));

        let partial_detail = PrefetchExecutorResultDetail {
            attribution_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                ATTRIBUTION,
            ),
            prefetched_bytes: 128 * 1024,
            used_bytes: 96 * 1024,
            ..PrefetchExecutorResultDetail::default()
        };
        assert!(partial_detail.has_feedback_payback_inputs());
        assert!(!partial_detail.has_feedback_evidence_roots());

        let rejected_partial = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: partial_detail,
                evidence_cut: terminal_evidence_cut(started, partial_detail, EMPTY_EVIDENCE_REF),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected_partial.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected_partial.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected_partial.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected_partial);

        let wrong_kind_detail = PrefetchExecutorResultDetail {
            validation_ref: evidence(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                VALIDATION,
            ),
            ..terminal_detail()
        };
        assert!(!wrong_kind_detail.has_feedback_evidence_roots());

        let rejected_wrong_kind = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: wrong_kind_detail,
                evidence_cut: terminal_evidence_cut(started, wrong_kind_detail, EMPTY_EVIDENCE_REF),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected_wrong_kind.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected_wrong_kind.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected_wrong_kind.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected_wrong_kind);
    }

    #[test]
    fn terminal_update_rejects_feedback_root_outside_evidence_cut() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        let detail = terminal_detail();

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: StorageIntentEvidenceRefs::EMPTY,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_validates_result_refusal_ref_cut() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        let result_ref = evidence(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            RESULT_REFUSAL,
        );

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Refused,
                result_refusal_ref: result_ref,
                evidence_cut: PrefetchExecutorTerminalEvidenceCut {
                    evidence_query_snapshot_ref: started.evidence_refs.evidence_query_snapshot_ref,
                    included_refs: StorageIntentEvidenceRefs::EMPTY,
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );

        let refused = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Refused,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    result_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(refused.outcome, PrefetchExecutorOutcome::Refused);
        assert_eq!(refused.evidence_refs.result_refusal_ref, result_ref);
        assert_record_has_no_authority_claims(refused);
    }

    #[test]
    fn terminal_update_requires_validation_artifact_for_verification_failed() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        let result_ref = evidence(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            RESULT_REFUSAL,
        );

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::VerificationFailed,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    result_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            rejected.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(rejected);

        let detail = PrefetchExecutorResultDetail {
            validation_ref: evidence(StorageIntentEvidenceKind::ValidationArtifact, VALIDATION),
            ..PrefetchExecutorResultDetail::default()
        };
        let failed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::VerificationFailed,
                result_detail: detail,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut(started, detail, result_ref),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(failed.outcome, PrefetchExecutorOutcome::VerificationFailed);
        assert_eq!(
            failed.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(failed.evidence_refs.validation_ref, detail.validation_ref);
        assert_eq!(failed.evidence_refs.result_refusal_ref, result_ref);
        assert_record_has_no_authority_claims(failed);
    }

    #[test]
    fn terminal_update_records_interruption_evidence_without_authority() {
        let detail = terminal_detail();
        let started = evaluate_prefetch_execution(admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            detail,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let interruption_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            INTERRUPTION,
        );
        let completed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: detail,
                interruption: PrefetchExecutorInterruptionClass::CrashRestartReplay,
                interruption_ref,
                evidence_cut: terminal_evidence_cut_with_interruption(
                    started,
                    detail,
                    EMPTY_EVIDENCE_REF,
                    interruption_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(completed.outcome, PrefetchExecutorOutcome::Completed);
        assert_eq!(completed.refusal, StorageIntentRefusalReason::None);
        assert_eq!(
            completed.interruption,
            PrefetchExecutorInterruptionClass::CrashRestartReplay
        );
        assert_eq!(completed.evidence_refs.interruption_ref, interruption_ref);
        assert_eq!(completed.executor_byte_state, started.executor_byte_state);
        assert_record_has_no_authority_claims(completed);
    }

    #[test]
    fn terminal_update_requires_interruption_ref_inside_terminal_cut() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch);
        input.evidence_query_snapshot =
            snapshot(Some(StorageIntentEvidenceKind::TransportPathEvidence));
        add_fresh(
            &mut input.evidence_query_snapshot,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            TRUST,
        );
        let started = evaluate_prefetch_execution(input);
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let result_ref = evidence(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            RESULT_REFUSAL,
        );
        let interruption_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            INTERRUPTION,
        );

        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::TimedOut,
                interruption: PrefetchExecutorInterruptionClass::WanStall,
                interruption_ref,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    result_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(rejected);

        let accepted = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::TimedOut,
                interruption: PrefetchExecutorInterruptionClass::WanStall,
                interruption_ref,
                result_refusal_ref: result_ref,
                evidence_cut: terminal_evidence_cut_with_interruption(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    result_ref,
                    interruption_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(accepted.outcome, PrefetchExecutorOutcome::TimedOut);
        assert_eq!(
            accepted.interruption,
            PrefetchExecutorInterruptionClass::WanStall
        );
        assert_eq!(accepted.evidence_refs.interruption_ref, interruption_ref);
        assert_record_has_no_authority_claims(accepted);
    }

    #[test]
    fn terminal_update_rejects_incompatible_interruption_outcome() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let interruption_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            INTERRUPTION,
        );
        let rejected = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                interruption: PrefetchExecutorInterruptionClass::WanStall,
                interruption_ref,
                evidence_cut: terminal_evidence_cut_with_interruption(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                    interruption_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(
            rejected.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            rejected.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(rejected);
    }

    #[test]
    fn terminal_update_requires_result_refusal_root_for_refusal_outcomes() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));

        for outcome in [
            PrefetchExecutorOutcome::Dropped,
            PrefetchExecutorOutcome::Throttled,
            PrefetchExecutorOutcome::Stale,
            PrefetchExecutorOutcome::TimedOut,
            PrefetchExecutorOutcome::Refused,
            PrefetchExecutorOutcome::OverBudget,
            PrefetchExecutorOutcome::VerificationFailed,
            PrefetchExecutorOutcome::Blocked,
            PrefetchExecutorOutcome::Unavailable,
        ] {
            let rejected = finalize_prefetch_execution(
                started,
                PrefetchExecutorTerminalUpdate {
                    outcome,
                    evidence_cut: terminal_evidence_cut(
                        started,
                        PrefetchExecutorResultDetail::default(),
                        EMPTY_EVIDENCE_REF,
                    ),
                    ..PrefetchExecutorTerminalUpdate::default()
                },
            );

            assert_eq!(
                rejected.outcome,
                PrefetchExecutorOutcome::VerificationFailed,
                "outcome {outcome:?} did not require result/refusal evidence"
            );
            assert_eq!(
                rejected.refusal,
                StorageIntentRefusalReason::ValidationGateFailed
            );
            assert_record_has_no_authority_claims(rejected);
        }
    }

    #[test]
    fn terminal_update_requires_degraded_visibility_root_for_degraded_outcome() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);
        let degraded_ref = evidence(
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            RECOVERY,
        );

        let missing = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::DegradedVisible,
                evidence_cut: terminal_evidence_cut(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(missing.outcome, PrefetchExecutorOutcome::VerificationFailed);
        assert_eq!(
            missing.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(missing);

        let wrong_kind_ref = evidence(StorageIntentEvidenceKind::ActionExecutionEvidence, RECOVERY);
        let wrong_kind = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::DegradedVisible,
                degraded_visibility_ref: wrong_kind_ref,
                evidence_cut: terminal_evidence_cut_with_degraded_visibility(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                    wrong_kind_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            wrong_kind.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            wrong_kind.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(wrong_kind);

        let completed_with_degraded_ref = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                degraded_visibility_ref: degraded_ref,
                evidence_cut: terminal_evidence_cut_with_degraded_visibility(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                    degraded_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            completed_with_degraded_ref.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            completed_with_degraded_ref.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_record_has_no_authority_claims(completed_with_degraded_ref);

        let degraded = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::DegradedVisible,
                degraded_visibility_ref: degraded_ref,
                evidence_cut: terminal_evidence_cut_with_degraded_visibility(
                    started,
                    PrefetchExecutorResultDetail::default(),
                    EMPTY_EVIDENCE_REF,
                    degraded_ref,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(degraded.outcome, PrefetchExecutorOutcome::DegradedVisible);
        assert_eq!(
            degraded.executor_byte_state,
            PrefetchExecutorByteState::DegradedVisible
        );
        assert_eq!(degraded.refusal, StorageIntentRefusalReason::None);
        assert_eq!(degraded.evidence_refs.degraded_visibility_ref, degraded_ref);
        assert_record_has_no_authority_claims(degraded);
    }

    #[test]
    fn terminal_update_requires_started_record() {
        let mut input = admitted_input(PrefetchResidencyCandidateClass::NoPrefetch);
        input.decision.outcome = PrefetchResidencyDecisionOutcome::NoAction;
        input.admission = PrefetchExecutorAdmissionRecord::default();
        let no_prefetch = evaluate_prefetch_execution(input);
        assert_eq!(no_prefetch.outcome, PrefetchExecutorOutcome::Completed);

        let blocked = finalize_prefetch_execution(
            no_prefetch,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: terminal_detail(),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );

        assert_eq!(blocked.outcome, PrefetchExecutorOutcome::Blocked);
        assert_eq!(
            blocked.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_eq!(
            blocked.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_record_has_no_authority_claims(blocked);
    }

    #[test]
    fn terminal_update_rejects_impossible_or_over_limit_byte_accounting() {
        let started = evaluate_prefetch_execution(admitted_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
        ));

        let impossible = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: PrefetchExecutorResultDetail {
                    prefetched_bytes: 4 * 1024,
                    used_bytes: 4 * 1024,
                    unused_bytes: 1024,
                    validation_ref: evidence(
                        StorageIntentEvidenceKind::ValidationArtifact,
                        VALIDATION,
                    ),
                    ..PrefetchExecutorResultDetail::default()
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            impossible.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            impossible.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            impossible.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(impossible);

        let mut unlimited = started;
        unlimited.max_prefetch_window_bytes = u64::MAX;
        let overflow = finalize_prefetch_execution(
            unlimited,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: PrefetchExecutorResultDetail {
                    prefetched_bytes: u64::MAX,
                    used_bytes: u64::MAX,
                    unused_bytes: 1,
                    ..PrefetchExecutorResultDetail::default()
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            overflow.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            overflow.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            overflow.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(overflow);

        let over_limit = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::Completed,
                result_detail: PrefetchExecutorResultDetail {
                    prefetched_bytes: started.max_prefetch_window_bytes + 1,
                    ..PrefetchExecutorResultDetail::default()
                },
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(over_limit.outcome, PrefetchExecutorOutcome::OverBudget);
        assert_eq!(over_limit.refusal, StorageIntentRefusalReason::OverBudget);
        assert_eq!(
            over_limit.executor_byte_state,
            PrefetchExecutorByteState::Blocked
        );
        assert_record_has_no_authority_claims(over_limit);
    }

    #[test]
    fn terminal_update_projects_failure_and_handoff_without_receipt_power() {
        let failed_detail = terminal_detail();
        let started = evaluate_prefetch_execution(admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            failed_detail,
        ));
        assert_eq!(started.outcome, PrefetchExecutorOutcome::Started);

        let failed_result_ref = evidence(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            RESULT_REFUSAL,
        );
        let failed = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::VerificationFailed,
                result_detail: failed_detail,
                result_refusal_ref: failed_result_ref,
                evidence_cut: terminal_evidence_cut(started, failed_detail, failed_result_ref),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(failed.outcome, PrefetchExecutorOutcome::VerificationFailed);
        assert_eq!(
            failed.refusal,
            StorageIntentRefusalReason::ValidationGateFailed
        );
        assert_eq!(
            failed.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(failed);

        let handoff_without_target_detail = terminal_detail();
        let handoff_without_target = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::HandoffRequired,
                result_detail: handoff_without_target_detail,
                evidence_cut: terminal_evidence_cut(
                    started,
                    handoff_without_target_detail,
                    EMPTY_EVIDENCE_REF,
                ),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            handoff_without_target.outcome,
            PrefetchExecutorOutcome::Blocked
        );

        let handoff_detail = terminal_detail();
        let handoff_without_boundary = finalize_prefetch_execution(
            started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::HandoffRequired,
                result_detail: handoff_detail,
                handoff_target: PrefetchExecutorHandoffTarget::Promotion,
                evidence_cut: terminal_evidence_cut(started, handoff_detail, EMPTY_EVIDENCE_REF),
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            handoff_without_boundary.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            handoff_without_boundary.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(handoff_without_boundary);

        let mut wrong_kind_input = admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            handoff_detail,
        );
        let wrong_kind_relocation_ref = evidence(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            RELOCATION,
        );
        wrong_kind_input
            .decision
            .evidence_refs
            .relocation_boundary_ref = wrong_kind_relocation_ref;
        wrong_kind_input
            .evidence_query_snapshot
            .included_refs
            .push(wrong_kind_relocation_ref)
            .unwrap();
        let wrong_kind_started = evaluate_prefetch_execution(wrong_kind_input);
        assert_eq!(wrong_kind_started.outcome, PrefetchExecutorOutcome::Started);

        let mut wrong_kind_cut =
            terminal_evidence_cut(wrong_kind_started, handoff_detail, EMPTY_EVIDENCE_REF);
        wrong_kind_cut
            .included_refs
            .push(wrong_kind_started.evidence_refs.relocation_boundary_ref)
            .unwrap();
        let handoff_wrong_kind = finalize_prefetch_execution(
            wrong_kind_started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::HandoffRequired,
                result_detail: handoff_detail,
                handoff_target: PrefetchExecutorHandoffTarget::Promotion,
                evidence_cut: wrong_kind_cut,
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(
            handoff_wrong_kind.outcome,
            PrefetchExecutorOutcome::VerificationFailed
        );
        assert_eq!(
            handoff_wrong_kind.executor_byte_state,
            PrefetchExecutorByteState::Refused
        );
        assert_record_has_no_authority_claims(handoff_wrong_kind);

        let mut handoff_input = admitted_charged_input(
            PrefetchResidencyCandidateClass::BoundedReadahead,
            handoff_detail,
        );
        let relocation_ref = evidence(StorageIntentEvidenceKind::RelocationReceipt, RELOCATION);
        handoff_input.decision.evidence_refs.relocation_boundary_ref = relocation_ref;
        handoff_input
            .evidence_query_snapshot
            .included_refs
            .push(relocation_ref)
            .unwrap();
        let handoff_started = evaluate_prefetch_execution(handoff_input);
        assert_eq!(handoff_started.outcome, PrefetchExecutorOutcome::Started);

        let mut handoff_cut =
            terminal_evidence_cut(handoff_started, handoff_detail, EMPTY_EVIDENCE_REF);
        handoff_cut
            .included_refs
            .push(handoff_started.evidence_refs.relocation_boundary_ref)
            .unwrap();
        let handoff = finalize_prefetch_execution(
            handoff_started,
            PrefetchExecutorTerminalUpdate {
                outcome: PrefetchExecutorOutcome::HandoffRequired,
                result_detail: handoff_detail,
                handoff_target: PrefetchExecutorHandoffTarget::Promotion,
                evidence_cut: handoff_cut,
                ..PrefetchExecutorTerminalUpdate::default()
            },
        );
        assert_eq!(handoff.outcome, PrefetchExecutorOutcome::HandoffRequired);
        assert_eq!(
            handoff.executor_byte_state,
            PrefetchExecutorByteState::HandoffRequired
        );
        assert_eq!(
            handoff.handoff_target,
            PrefetchExecutorHandoffTarget::Promotion
        );
        assert_record_has_no_authority_claims(handoff);
    }
}
