// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Receipt-aware read-serving model for storage intent (#877).
//!
//! This crate defines the read-source policy/model boundary. It consumes the
//! #841 core evidence vocabulary and #967 prefetch/residency decision classes,
//! but it does not implement local filesystem reads, transport fetches, scrub
//! dispatch, repair execution, receipt retirement, operator rendering, or
//! performance claims.

use core::fmt;

use tidefs_storage_intent_core::{
    EvidenceCompletenessVerdict, EvidenceQueryContextClass, PrefetchResidencyCandidateClass,
    PrefetchResidencyDecisionOutcome, PrefetchResidencyDecisionRecord, PrefetchResidencyStateClass,
    ReadServingSourceClass as CoreReadServingSourceClass, ReadSourceFreshnessRecord,
    StorageIntentActionClass, StorageIntentDomainId, StorageIntentEvidenceId,
    StorageIntentEvidenceKind, StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef,
    StorageIntentObjectScope, StorageIntentPolicyId, StorageIntentPolicyRevision,
    StorageIntentReceiptId, StorageIntentRefusalReason,
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

/// Current read-serving model version.
pub const STORAGE_INTENT_READ_SERVING_VERSION: u16 = 1;

/// Stable diagnostic identifier for evidence, PR descriptions, and tests.
pub const STORAGE_INTENT_READ_SERVING_SPEC: &str =
    "tidefs-storage-intent-read-serving-v1-issue-877";

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

const fn bytes16_are_zero(bytes: [u8; 16]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

const fn bytes16_equal(left: [u8; 16], right: [u8; 16]) -> bool {
    let mut index = 0;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn evidence_ref_has_id(evidence: StorageIntentEvidenceRef) -> bool {
    evidence.kind as u16 != StorageIntentEvidenceKind::Unknown as u16 && evidence.is_bound()
}

const fn evidence_ref_has_kind(
    evidence: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence.kind as u16 == kind as u16 && evidence.is_bound()
}

const fn receipt_id_is_zero(receipt_id: StorageIntentReceiptId) -> bool {
    bytes16_are_zero(receipt_id.0)
}

const fn policy_identity_matches(
    policy_id: StorageIntentPolicyId,
    policy_revision: StorageIntentPolicyRevision,
    candidate_id: StorageIntentPolicyId,
    candidate_revision: StorageIntentPolicyRevision,
) -> bool {
    bytes16_equal(policy_id.0, candidate_id.0) && policy_revision.0 == candidate_revision.0
}

/// Read source classes known to the #877 authority boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentReadSourceClass {
    /// No source was selected.
    #[default]
    Unknown = 0,
    /// Dirty bytes visible through page-cache/writeback law.
    DirtyPageCacheVisible = 1,
    /// Clean cache hit under a valid anchor and fence.
    CleanCache = 2,
    /// Cache-only serving trial admitted by #967-style policy.
    CacheOnlyServingTrial = 3,
    /// RAM authority backed by explicit RAM-authority evidence.
    AuthoritativeRam = 4,
    /// Persistent-memory authority with media-capability evidence.
    AuthoritativePmem = 5,
    /// Local placement receipt source.
    LocalPlacementReceipt = 6,
    /// Remote placement receipt source.
    RemotePlacementReceipt = 7,
    /// Reconstruction from surviving receipt targets.
    DegradedReconstruction = 8,
    /// Read-only snapshot or generation source.
    SnapshotGeneration = 9,
    /// Geo-async remote source under explicit lag/RPO evidence.
    GeoAsyncRemote = 10,
    /// Archive or restore-stage source.
    ArchiveRestore = 11,
    /// Metadata or namespace hot lookup source.
    MetadataHotLookup = 12,
    /// Directory index source backed by namespace evidence.
    DirectoryIndex = 13,
}

/// Freshness profile requested by the caller or compiled policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ReadFreshnessProfile {
    /// Latest local/POSIX read; stale or lagged sources do not satisfy it.
    #[default]
    LatestLocal = 0,
    /// Read a named read-only generation.
    SnapshotGeneration = 1,
    /// Explicit stale read within the recorded lag envelope.
    ExplicitStaleRead = 2,
    /// Disaster-recovery/RPO profile within a lag envelope.
    DisasterRecoveryRpo = 3,
    /// Cache-only acceleration; never durable or successor authority.
    CacheOnlyAcceleration = 4,
    /// Archive or restore profile with explicit restore evidence.
    ArchiveRestore = 5,
}

/// Policy for verified degraded reconstruction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DegradedReadPolicy {
    /// Verified reconstruction may satisfy a normal read.
    #[default]
    ServeWhenVerified = 0,
    /// Verified reconstruction is visible as degraded state.
    ExposeDegradedVisible = 1,
    /// Degraded reconstruction is refused by policy.
    Refuse = 2,
}

/// Evidence-query snapshot state used by this decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ReadServingEvidenceCutState {
    /// Caller did not classify the evidence cut.
    #[default]
    Unknown = 0,
    /// Complete enough for read-serving authority.
    Bound = 1,
    /// Snapshot is missing.
    Missing = 2,
    /// Snapshot is partial and may only support non-authority visibility.
    Partial = 3,
    /// Snapshot is stale.
    Stale = 4,
    /// Snapshot is redacted.
    Redacted = 5,
    /// Snapshot was compacted beyond this decision's authority needs.
    Compacted = 6,
    /// Snapshot permits degraded-visible output only.
    DegradedVisible = 7,
    /// Snapshot blocks the decision.
    Blocked = 8,
    /// Snapshot explicitly refused the decision.
    Refused = 9,
}

/// Outcome state emitted by a read-serving decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ReadServingDecisionState {
    /// No source can be selected from the supplied model input.
    #[default]
    Unknown = 0,
    /// Source may serve the requested read.
    Available = 1,
    /// Source may only accelerate a cache-only read.
    CacheOnly = 2,
    /// Source may serve a trial but is not authority.
    ServingTrial = 3,
    /// Source may serve only with degraded visibility.
    DegradedVisible = 4,
    /// Evidence is unavailable, stale, redacted, or compacted.
    Unavailable = 5,
    /// Policy or evidence blocks the decision.
    Blocked = 6,
    /// Policy or evidence refused the decision.
    Refused = 7,
}

/// Read-triggered repair disposition. This never executes repair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ReadRepairDisposition {
    /// No repair was requested by this read decision.
    #[default]
    None = 0,
    /// Repair was requested, but scheduler/reserve evidence is missing.
    ReserveRequired = 1,
    /// Repair may be planned, but no replacement receipt exists yet.
    ReplacementReceiptPending = 2,
    /// Replacement receipt was published and can be cited by retirement logic.
    ReplacementReceiptPublished = 3,
    /// Repair is refused by policy or evidence.
    Refused = 4,
}

/// Machine-readable rejection reasons for explanation, performance, and faults.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingRejectionMask(pub u64);

impl ReadServingRejectionMask {
    pub const EMPTY: Self = Self(0);
    pub const MISSING_EVIDENCE_CUT: Self = Self(1_u64 << 0);
    pub const MISSING_EVIDENCE_REF: Self = Self(1_u64 << 1);
    pub const STALE_GENERATION: Self = Self(1_u64 << 2);
    pub const CACHE_ANCHOR_INVALID: Self = Self(1_u64 << 3);
    pub const CACHE_CANNOT_BE_AUTHORITY: Self = Self(1_u64 << 4);
    pub const RECEIPT_MISSING: Self = Self(1_u64 << 5);
    pub const DIGEST_OR_SHAPE_MISMATCH: Self = Self(1_u64 << 6);
    pub const DEGRADED_POLICY_REFUSED: Self = Self(1_u64 << 7);
    pub const GEO_PROFILE_MISMATCH: Self = Self(1_u64 << 8);
    pub const GEO_LAG_OUTSIDE_RPO: Self = Self(1_u64 << 9);
    pub const SNAPSHOT_GENERATION_MISMATCH: Self = Self(1_u64 << 10);
    pub const REMOTE_TRUST_OR_TRANSPORT_MISSING: Self = Self(1_u64 << 11);
    pub const REPAIR_REPLACEMENT_RECEIPT_MISSING: Self = Self(1_u64 << 12);
    pub const MISSING_FRESH_EVIDENCE_FAMILY: Self = Self(1_u64 << 13);
    pub const MISSING_ORDERING_EVIDENCE: Self = Self(1_u64 << 14);
    pub const MISSING_POLICY_ROLLOUT_EVIDENCE: Self = Self(1_u64 << 15);
    pub const MISSING_TENANT_ISOLATION_EVIDENCE: Self = Self(1_u64 << 16);
    pub const MISSING_SERVICE_OBJECTIVE_EVIDENCE: Self = Self(1_u64 << 17);
    pub const MISSING_CAPACITY_ADMISSION_EVIDENCE: Self = Self(1_u64 << 18);
    pub const TRUST_DOMAIN_MISMATCH: Self = Self(1_u64 << 19);
    pub const MISSING_TEMPORAL_EVIDENCE: Self = Self(1_u64 << 20);
    pub const PMEM_MISSING_MEDIA_CAPABILITY: Self = Self(1_u64 << 21);
    pub const MISSING_METADATA_NAMESPACE_EVIDENCE: Self = Self(1_u64 << 22);

    /// Merge two masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when any bit in `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Returns true when no rejection bit is present.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Compiled read-serving policy envelope consumed by this model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingPolicy {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub freshness_profile: ReadFreshnessProfile,
    pub required_object_generation: u64,
    pub required_namespace_generation: u64,
    pub required_layout_generation: u64,
    pub required_snapshot_generation: u64,
    pub max_remote_lag_ms: u64,
    pub degraded_read_policy: DegradedReadPolicy,
    pub allow_cache_only: bool,
    pub allow_serving_trial: bool,
    pub allow_read_repair: bool,
    pub repair_requires_reserve: bool,
    pub require_digest_verification: bool,
}

impl Default for ReadServingPolicy {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            freshness_profile: ReadFreshnessProfile::LatestLocal,
            required_object_generation: 0,
            required_namespace_generation: 0,
            required_layout_generation: 0,
            required_snapshot_generation: 0,
            max_remote_lag_ms: 0,
            degraded_read_policy: DegradedReadPolicy::ServeWhenVerified,
            allow_cache_only: false,
            allow_serving_trial: false,
            allow_read_repair: false,
            repair_requires_reserve: true,
            require_digest_verification: true,
        }
    }
}

/// Evidence references that bind one read-serving decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingEvidenceRefs {
    pub compiled_policy_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub freshness_ref: StorageIntentEvidenceRef,
    pub namespace_generation_ref: StorageIntentEvidenceRef,
    pub placement_receipt_ref: StorageIntentEvidenceRef,
    pub cache_anchor_ref: StorageIntentEvidenceRef,
    pub cache_fence_ref: StorageIntentEvidenceRef,
    pub membership_epoch_ref: StorageIntentEvidenceRef,
    pub lease_epoch_ref: StorageIntentEvidenceRef,
    pub transport_path_ref: StorageIntentEvidenceRef,
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub data_shape_ref: StorageIntentEvidenceRef,
    pub layout_allocator_ref: StorageIntentEvidenceRef,
    pub digest_checksum_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub ram_authority_ref: StorageIntentEvidenceRef,
    pub recovery_degradation_ref: StorageIntentEvidenceRef,
    pub redundancy_ref: StorageIntentEvidenceRef,
    pub temporal_ref: StorageIntentEvidenceRef,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub repair_budget_ref: StorageIntentEvidenceRef,
    pub replacement_receipt_ref: StorageIntentEvidenceRef,
    pub prefetch_decision_ref: StorageIntentEvidenceRef,
    pub result_refusal_ref: StorageIntentEvidenceRef,
    pub ordering_evidence_ref: StorageIntentEvidenceRef,
    pub policy_rollout_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub capacity_admission_ref: StorageIntentEvidenceRef,
}

impl ReadServingEvidenceRefs {
    /// Empty evidence refs.
    pub const EMPTY: Self = Self {
        compiled_policy_ref: EMPTY_EVIDENCE_REF,
        evidence_query_snapshot_ref: EMPTY_EVIDENCE_REF,
        freshness_ref: EMPTY_EVIDENCE_REF,
        namespace_generation_ref: EMPTY_EVIDENCE_REF,
        placement_receipt_ref: EMPTY_EVIDENCE_REF,
        cache_anchor_ref: EMPTY_EVIDENCE_REF,
        cache_fence_ref: EMPTY_EVIDENCE_REF,
        membership_epoch_ref: EMPTY_EVIDENCE_REF,
        lease_epoch_ref: EMPTY_EVIDENCE_REF,
        transport_path_ref: EMPTY_EVIDENCE_REF,
        trust_domain_ref: EMPTY_EVIDENCE_REF,
        data_shape_ref: EMPTY_EVIDENCE_REF,
        layout_allocator_ref: EMPTY_EVIDENCE_REF,
        digest_checksum_ref: EMPTY_EVIDENCE_REF,
        media_capability_ref: EMPTY_EVIDENCE_REF,
        ram_authority_ref: EMPTY_EVIDENCE_REF,
        recovery_degradation_ref: EMPTY_EVIDENCE_REF,
        redundancy_ref: EMPTY_EVIDENCE_REF,
        temporal_ref: EMPTY_EVIDENCE_REF,
        scheduler_admission_ref: EMPTY_EVIDENCE_REF,
        repair_budget_ref: EMPTY_EVIDENCE_REF,
        replacement_receipt_ref: EMPTY_EVIDENCE_REF,
        prefetch_decision_ref: EMPTY_EVIDENCE_REF,
        result_refusal_ref: EMPTY_EVIDENCE_REF,
        ordering_evidence_ref: EMPTY_EVIDENCE_REF,
        policy_rollout_ref: EMPTY_EVIDENCE_REF,
        tenant_isolation_ref: EMPTY_EVIDENCE_REF,
        service_objective_ref: EMPTY_EVIDENCE_REF,
        capacity_admission_ref: EMPTY_EVIDENCE_REF,
    };

    /// Returns true when the decision cites a #913-compatible evidence cut.
    #[must_use]
    pub const fn has_evidence_query_snapshot(self) -> bool {
        evidence_ref_has_kind(
            self.evidence_query_snapshot_ref,
            StorageIntentEvidenceKind::EvidenceQuerySnapshot,
        )
    }
}

impl Default for ReadServingEvidenceRefs {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Candidate read source supplied to the #877 model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingCandidateRecord {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub source_class: StorageIntentReadSourceClass,
    pub source_receipt: StorageIntentReceiptId,
    pub object_generation: u64,
    pub namespace_generation: u64,
    pub layout_generation: u64,
    pub snapshot_generation: u64,
    pub geo_lag_ms: u64,
    pub lag_known: bool,
    pub freshness_frontier_ms: u64,
    pub cache_anchor_generation: u64,
    pub cache_fence_generation: u64,
    pub digest_verified: bool,
    pub reconstruction_verified: bool,
    pub redundancy_width: u8,
    pub missing_targets: u8,
    pub read_repair_requested: bool,
    pub replacement_receipt: StorageIntentReceiptId,
    pub prefetch_candidate: PrefetchResidencyCandidateClass,
    pub prefetch_outcome: PrefetchResidencyDecisionOutcome,
    pub prefetch_residency: PrefetchResidencyStateClass,
    pub action_class: StorageIntentActionClass,
    pub evidence_refs: ReadServingEvidenceRefs,
}

impl Default for ReadServingCandidateRecord {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: EMPTY_SCOPE,
            source_class: StorageIntentReadSourceClass::Unknown,
            source_receipt: StorageIntentReceiptId::ZERO,
            object_generation: 0,
            namespace_generation: 0,
            layout_generation: 0,
            snapshot_generation: 0,
            geo_lag_ms: 0,
            lag_known: false,
            freshness_frontier_ms: 0,
            cache_anchor_generation: 0,
            cache_fence_generation: 0,
            digest_verified: false,
            reconstruction_verified: false,
            redundancy_width: 0,
            missing_targets: 0,
            read_repair_requested: false,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            prefetch_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            prefetch_outcome: PrefetchResidencyDecisionOutcome::NoAction,
            prefetch_residency: PrefetchResidencyStateClass::Unknown,
            action_class: StorageIntentActionClass::ReadSourceRefresh,
            evidence_refs: ReadServingEvidenceRefs::EMPTY,
        }
    }
}

impl ReadServingCandidateRecord {
    /// Consume the stable #967 decision classes without executing prefetch.
    #[must_use]
    pub const fn with_prefetch_decision(
        mut self,
        decision: PrefetchResidencyDecisionRecord,
    ) -> Self {
        self.prefetch_candidate = decision.selected_candidate;
        self.prefetch_outcome = decision.outcome;
        self.prefetch_residency = decision.selected_residency;
        self.evidence_refs.prefetch_decision_ref = decision.evidence_refs.decision_frontier_ref;
        self
    }
}

/// Full input envelope for a read-serving decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingDecisionInput {
    pub policy: ReadServingPolicy,
    pub candidate: ReadServingCandidateRecord,
    pub evidence_cut_state: ReadServingEvidenceCutState,
    pub evidence_query_snapshot: StorageIntentEvidenceQuerySnapshot,
}

impl Default for ReadServingDecisionInput {
    fn default() -> Self {
        Self {
            policy: ReadServingPolicy::default(),
            candidate: ReadServingCandidateRecord::default(),
            evidence_cut_state: ReadServingEvidenceCutState::Missing,
            evidence_query_snapshot: StorageIntentEvidenceQuerySnapshot::default(),
        }
    }
}

/// Decision record emitted by the read-serving authority model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingDecisionRecord {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub freshness_profile: ReadFreshnessProfile,
    pub requested_source: StorageIntentReadSourceClass,
    pub chosen_source: StorageIntentReadSourceClass,
    pub core_source: CoreReadServingSourceClass,
    pub decision_state: ReadServingDecisionState,
    pub refusal: StorageIntentRefusalReason,
    pub source_receipt: StorageIntentReceiptId,
    pub replacement_receipt: StorageIntentReceiptId,
    pub freshness: ReadSourceFreshnessRecord,
    pub object_generation: u64,
    pub namespace_generation: u64,
    pub layout_generation: u64,
    pub cache_only: bool,
    pub serving_trial: bool,
    pub degraded_visible: bool,
    pub read_repair: ReadRepairDisposition,
    pub rejected_reasons: ReadServingRejectionMask,
    pub prefetch_candidate: PrefetchResidencyCandidateClass,
    pub prefetch_outcome: PrefetchResidencyDecisionOutcome,
    pub prefetch_residency: PrefetchResidencyStateClass,
    pub action_class: StorageIntentActionClass,
    pub evidence_cut_state: ReadServingEvidenceCutState,
    pub evidence_refs: ReadServingEvidenceRefs,
}

impl Default for ReadServingDecisionRecord {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: EMPTY_SCOPE,
            freshness_profile: ReadFreshnessProfile::LatestLocal,
            requested_source: StorageIntentReadSourceClass::Unknown,
            chosen_source: StorageIntentReadSourceClass::Unknown,
            core_source: CoreReadServingSourceClass::Cache,
            decision_state: ReadServingDecisionState::Unknown,
            refusal: StorageIntentRefusalReason::None,
            source_receipt: StorageIntentReceiptId::ZERO,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            freshness: ReadSourceFreshnessRecord {
                source: CoreReadServingSourceClass::Cache,
                source_receipt: StorageIntentReceiptId::ZERO,
                snapshot_generation: 0,
                geo_lag_ms: 0,
                lag_known: false,
                freshness_frontier_ms: 0,
                evidence: EMPTY_EVIDENCE_REF,
            },
            object_generation: 0,
            namespace_generation: 0,
            layout_generation: 0,
            cache_only: false,
            serving_trial: false,
            degraded_visible: false,
            read_repair: ReadRepairDisposition::None,
            rejected_reasons: ReadServingRejectionMask::EMPTY,
            prefetch_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            prefetch_outcome: PrefetchResidencyDecisionOutcome::NoAction,
            prefetch_residency: PrefetchResidencyStateClass::Unknown,
            action_class: StorageIntentActionClass::ReadSourceRefresh,
            evidence_cut_state: ReadServingEvidenceCutState::Missing,
            evidence_refs: ReadServingEvidenceRefs::EMPTY,
        }
    }
}

/// Map this crate's detailed source class to the #841 core projection.
#[must_use]
pub const fn read_source_core_class(
    source: StorageIntentReadSourceClass,
) -> CoreReadServingSourceClass {
    match source {
        StorageIntentReadSourceClass::DirtyPageCacheVisible
        | StorageIntentReadSourceClass::CleanCache => CoreReadServingSourceClass::Cache,
        StorageIntentReadSourceClass::CacheOnlyServingTrial => {
            CoreReadServingSourceClass::ServingTrial
        }
        StorageIntentReadSourceClass::AuthoritativeRam => CoreReadServingSourceClass::RamAuthority,
        StorageIntentReadSourceClass::AuthoritativePmem => {
            CoreReadServingSourceClass::PmemAuthority
        }
        StorageIntentReadSourceClass::LocalPlacementReceipt => {
            CoreReadServingSourceClass::PlacementReceipt
        }
        StorageIntentReadSourceClass::RemotePlacementReceipt => {
            CoreReadServingSourceClass::RemoteReceipt
        }
        StorageIntentReadSourceClass::DegradedReconstruction => {
            CoreReadServingSourceClass::DegradedReconstruction
        }
        StorageIntentReadSourceClass::SnapshotGeneration => {
            CoreReadServingSourceClass::SnapshotGeneration
        }
        StorageIntentReadSourceClass::GeoAsyncRemote => CoreReadServingSourceClass::GeoAsyncLag,
        StorageIntentReadSourceClass::ArchiveRestore => CoreReadServingSourceClass::ArchiveRestore,
        StorageIntentReadSourceClass::MetadataHotLookup
        | StorageIntentReadSourceClass::DirectoryIndex => CoreReadServingSourceClass::Cache,
        StorageIntentReadSourceClass::Unknown => CoreReadServingSourceClass::Cache,
    }
}

/// Returns true when the source may only be cache/trial acceleration.
#[must_use]
pub const fn read_source_is_cache_or_trial(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::DirtyPageCacheVisible
            | StorageIntentReadSourceClass::CleanCache
            | StorageIntentReadSourceClass::CacheOnlyServingTrial
    )
}

/// Returns true when the source needs a placement or source receipt.
#[must_use]
pub const fn read_source_requires_receipt(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::LocalPlacementReceipt
            | StorageIntentReadSourceClass::RemotePlacementReceipt
            | StorageIntentReadSourceClass::DegradedReconstruction
            | StorageIntentReadSourceClass::GeoAsyncRemote
            | StorageIntentReadSourceClass::ArchiveRestore
    )
}

/// Returns true when a source needs metadata/namespace evidence even if the
/// caller did not request an explicit namespace generation floor.
#[must_use]
pub const fn read_source_requires_metadata_namespace(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::MetadataHotLookup
            | StorageIntentReadSourceClass::DirectoryIndex
            | StorageIntentReadSourceClass::SnapshotGeneration
    )
}

const fn read_source_requires_ordering_fence(source: StorageIntentReadSourceClass) -> bool {
    read_source_is_cache_or_trial(source)
        || matches!(
            source,
            StorageIntentReadSourceClass::MetadataHotLookup
                | StorageIntentReadSourceClass::DirectoryIndex
        )
}

const fn evidence_cut_has_fresh_family(
    input: ReadServingDecisionInput,
    kind: StorageIntentEvidenceKind,
) -> bool {
    input
        .evidence_query_snapshot
        .contains_fresh_authority_family(kind)
}

const fn source_uses_remote_path(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::RemotePlacementReceipt
            | StorageIntentReadSourceClass::GeoAsyncRemote
            | StorageIntentReadSourceClass::ArchiveRestore
    )
}

const fn source_uses_volatile_or_pmem_authority(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::AuthoritativeRam
            | StorageIntentReadSourceClass::AuthoritativePmem
    )
}

const fn source_uses_degradation_or_recovery(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::DegradedReconstruction
            | StorageIntentReadSourceClass::GeoAsyncRemote
            | StorageIntentReadSourceClass::ArchiveRestore
    )
}

const fn read_serving_evidence_cut_missing_required_family(
    input: ReadServingDecisionInput,
) -> bool {
    let source = input.candidate.source_class;
    if !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::LocalIntentRecord)
        || !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::ReadFreshnessEvidence)
        || !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::TemporalEvidence)
    {
        return true;
    }
    if (input.policy.required_namespace_generation > 0
        || read_source_requires_metadata_namespace(source))
        && !evidence_cut_has_fresh_family(
            input,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
        )
    {
        return true;
    }
    if input.policy.required_layout_generation > 0
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::LayoutAllocatorEvidence)
    {
        return true;
    }
    if read_source_requires_receipt(source)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::PlacementReceipt)
    {
        return true;
    }
    if read_source_requires_ordering_fence(source)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::OrderingEvidence)
    {
        return true;
    }
    if input.policy.require_digest_verification
        && !matches!(source, StorageIntentReadSourceClass::DirtyPageCacheVisible)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::DataShapeEvidence)
    {
        return true;
    }
    if source_uses_volatile_or_pmem_authority(source)
        && (!evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::RamAuthorityEvidence)
            || !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::MembershipEvidence))
    {
        return true;
    }
    if matches!(
        source,
        StorageIntentReadSourceClass::AuthoritativePmem
            | StorageIntentReadSourceClass::ArchiveRestore
    ) && !evidence_cut_has_fresh_family(
        input,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) {
        return true;
    }
    if source_uses_remote_path(source)
        && (!evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::MembershipEvidence)
            || !evidence_cut_has_fresh_family(
                input,
                StorageIntentEvidenceKind::TransportPathEvidence,
            )
            || !evidence_cut_has_fresh_family(
                input,
                StorageIntentEvidenceKind::TrustDomainEvidence,
            ))
    {
        return true;
    }
    if source_uses_degradation_or_recovery(source)
        && !evidence_cut_has_fresh_family(
            input,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        )
    {
        return true;
    }
    if matches!(source, StorageIntentReadSourceClass::DegradedReconstruction)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::TrustDomainEvidence)
    {
        return true;
    }
    if matches!(source, StorageIntentReadSourceClass::CacheOnlyServingTrial)
        && !evidence_cut_has_fresh_family(
            input,
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
        )
    {
        return true;
    }
    if read_serving_requires_policy_rollout(source)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::PolicyRolloutEvidence)
    {
        return true;
    }
    if read_serving_requires_tenant_isolation(source)
        && !evidence_cut_has_fresh_family(input, StorageIntentEvidenceKind::TenantIsolationEvidence)
    {
        return true;
    }
    if read_serving_requires_service_objective(source)
        && !evidence_cut_has_fresh_family(
            input,
            StorageIntentEvidenceKind::ServiceObjectiveEvidence,
        )
    {
        return true;
    }
    if read_serving_requires_capacity_admission(
        input.candidate.read_repair_requested,
        input.policy.allow_read_repair,
    ) && (!evidence_cut_has_fresh_family(
        input,
        StorageIntentEvidenceKind::SchedulerAdmissionRecord,
    ) || !evidence_cut_has_fresh_family(
        input,
        StorageIntentEvidenceKind::CapacityAdmissionEvidence,
    )) {
        return true;
    }
    false
}

/// Returns true when the #913-compatible cut carries every fresh family this
/// policy/source combination needs for read-serving authority.
#[must_use]
pub const fn read_serving_evidence_cut_has_required_families(
    input: ReadServingDecisionInput,
) -> bool {
    !read_serving_evidence_cut_missing_required_family(input)
}

/// Return candidate-local evidence ref gaps for the policy/source combination.
///
/// A #913-compatible cut can only authorize a decision when the candidate also
/// cites the typed refs for the families it consumes. This predicate does not
/// execute or infer those producers; it only preserves their authority boundary.
#[must_use]
pub const fn read_serving_candidate_missing_required_ref_reasons(
    input: ReadServingDecisionInput,
) -> ReadServingRejectionMask {
    let source = input.candidate.source_class;
    let refs = input.candidate.evidence_refs;
    let mut missing = ReadServingRejectionMask::EMPTY;

    if !evidence_ref_has_kind(
        refs.compiled_policy_ref,
        StorageIntentEvidenceKind::LocalIntentRecord,
    ) || !evidence_ref_has_kind(
        refs.freshness_ref,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
    ) {
        missing = missing.union(ReadServingRejectionMask::MISSING_EVIDENCE_REF);
    }
    if !evidence_ref_has_kind(
        refs.temporal_ref,
        StorageIntentEvidenceKind::TemporalEvidence,
    ) {
        missing = missing.union(ReadServingRejectionMask::MISSING_TEMPORAL_EVIDENCE);
    }
    if (input.policy.required_namespace_generation > 0
        || read_source_requires_metadata_namespace(source))
        && !evidence_ref_has_kind(
            refs.namespace_generation_ref,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_METADATA_NAMESPACE_EVIDENCE);
    }
    if input.policy.required_layout_generation > 0
        && !evidence_ref_has_kind(
            refs.layout_allocator_ref,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_EVIDENCE_REF);
    }
    if read_source_requires_receipt(source)
        && !evidence_ref_has_kind(
            refs.placement_receipt_ref,
            StorageIntentEvidenceKind::PlacementReceipt,
        )
    {
        missing = missing.union(ReadServingRejectionMask::RECEIPT_MISSING);
    }
    if read_source_is_cache_or_trial(source) {
        if !evidence_ref_has_kind(
            refs.cache_anchor_ref,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
        ) {
            missing = missing.union(ReadServingRejectionMask::CACHE_ANCHOR_INVALID);
        }
        if !evidence_ref_has_kind(
            refs.cache_fence_ref,
            StorageIntentEvidenceKind::OrderingEvidence,
        ) {
            missing = missing.union(ReadServingRejectionMask::MISSING_ORDERING_EVIDENCE);
        }
    }
    if matches!(
        source,
        StorageIntentReadSourceClass::MetadataHotLookup
            | StorageIntentReadSourceClass::DirectoryIndex
    ) && !evidence_ref_has_kind(
        refs.ordering_evidence_ref,
        StorageIntentEvidenceKind::OrderingEvidence,
    ) {
        missing = missing.union(ReadServingRejectionMask::MISSING_ORDERING_EVIDENCE);
    }
    if input.policy.require_digest_verification
        && !matches!(source, StorageIntentReadSourceClass::DirtyPageCacheVisible)
        && (!evidence_ref_has_kind(
            refs.data_shape_ref,
            StorageIntentEvidenceKind::DataShapeEvidence,
        ) || !evidence_ref_has_kind(
            refs.digest_checksum_ref,
            StorageIntentEvidenceKind::DataShapeEvidence,
        ))
    {
        missing = missing.union(ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH);
    }
    if source_uses_volatile_or_pmem_authority(source)
        && (!evidence_ref_has_kind(
            refs.ram_authority_ref,
            StorageIntentEvidenceKind::RamAuthorityEvidence,
        ) || !evidence_ref_has_kind(
            refs.membership_epoch_ref,
            StorageIntentEvidenceKind::MembershipEvidence,
        ) || !evidence_ref_has_kind(
            refs.lease_epoch_ref,
            StorageIntentEvidenceKind::MembershipEvidence,
        ))
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_EVIDENCE_REF);
    }
    if matches!(source, StorageIntentReadSourceClass::AuthoritativePmem)
        && !evidence_ref_has_kind(
            refs.media_capability_ref,
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::PMEM_MISSING_MEDIA_CAPABILITY);
    }
    if source_uses_remote_path(source)
        && (!evidence_ref_has_kind(
            refs.membership_epoch_ref,
            StorageIntentEvidenceKind::MembershipEvidence,
        ) || !evidence_ref_has_kind(
            refs.lease_epoch_ref,
            StorageIntentEvidenceKind::MembershipEvidence,
        ) || !evidence_ref_has_kind(
            refs.transport_path_ref,
            StorageIntentEvidenceKind::TransportPathEvidence,
        ) || !evidence_ref_has_kind(
            refs.trust_domain_ref,
            StorageIntentEvidenceKind::TrustDomainEvidence,
        ))
    {
        missing = missing.union(ReadServingRejectionMask::REMOTE_TRUST_OR_TRANSPORT_MISSING);
    }
    if source_uses_degradation_or_recovery(source)
        && !evidence_ref_has_kind(
            refs.recovery_degradation_ref,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH);
    }
    if matches!(source, StorageIntentReadSourceClass::DegradedReconstruction)
        && (!evidence_ref_has_kind(
            refs.trust_domain_ref,
            StorageIntentEvidenceKind::TrustDomainEvidence,
        ) || !evidence_ref_has_kind(
            refs.redundancy_ref,
            StorageIntentEvidenceKind::DataShapeEvidence,
        ))
    {
        missing = missing.union(ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH);
    }
    if matches!(source, StorageIntentReadSourceClass::CacheOnlyServingTrial)
        && !evidence_ref_has_kind(
            refs.prefetch_decision_ref,
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::CACHE_CANNOT_BE_AUTHORITY);
    }
    if read_serving_requires_policy_rollout(source)
        && !evidence_ref_has_kind(
            refs.policy_rollout_ref,
            StorageIntentEvidenceKind::PolicyRolloutEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_POLICY_ROLLOUT_EVIDENCE);
    }
    if read_serving_requires_tenant_isolation(source)
        && !evidence_ref_has_kind(
            refs.tenant_isolation_ref,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_TENANT_ISOLATION_EVIDENCE);
    }
    if read_serving_requires_service_objective(source)
        && !evidence_ref_has_kind(
            refs.service_objective_ref,
            StorageIntentEvidenceKind::ServiceObjectiveEvidence,
        )
    {
        missing = missing.union(ReadServingRejectionMask::MISSING_SERVICE_OBJECTIVE_EVIDENCE);
    }

    missing
}

/// Returns true when candidate-local refs match the required evidence families.
#[must_use]
pub const fn read_serving_candidate_refs_have_required_families(
    input: ReadServingDecisionInput,
) -> bool {
    read_serving_candidate_missing_required_ref_reasons(input).is_empty()
}

/// Classify an evidence-query snapshot for #877 callers.
#[must_use]
pub const fn read_serving_evidence_cut_state(
    snapshot: StorageIntentEvidenceQuerySnapshot,
) -> ReadServingEvidenceCutState {
    if snapshot.refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return ReadServingEvidenceCutState::Refused;
    }
    if !matches!(
        snapshot.context,
        EvidenceQueryContextClass::ReadServing | EvidenceQueryContextClass::CacheOnlyRead
    ) {
        return ReadServingEvidenceCutState::Refused;
    }
    if !snapshot.has_query_identity()
        || !snapshot.has_policy_identity()
        || !snapshot.has_subject_scope()
        || !snapshot.has_frontiers()
        || !snapshot.has_source_replay_anchor()
    {
        return ReadServingEvidenceCutState::Missing;
    }
    match snapshot.completeness {
        EvidenceCompletenessVerdict::CompleteForPurpose => ReadServingEvidenceCutState::Bound,
        EvidenceCompletenessVerdict::PartialAdmissible => ReadServingEvidenceCutState::Partial,
        EvidenceCompletenessVerdict::DegradedVisible => {
            ReadServingEvidenceCutState::DegradedVisible
        }
        EvidenceCompletenessVerdict::Blocked => ReadServingEvidenceCutState::Blocked,
        EvidenceCompletenessVerdict::Refused | EvidenceCompletenessVerdict::UnsafeVisible => {
            ReadServingEvidenceCutState::Refused
        }
        EvidenceCompletenessVerdict::UnknownEvidence => ReadServingEvidenceCutState::Missing,
    }
}

const fn evidence_cut_refusal_state(
    input: ReadServingDecisionInput,
) -> Option<(
    ReadServingDecisionState,
    StorageIntentRefusalReason,
    ReadServingRejectionMask,
)> {
    let source = input.candidate.source_class;
    let cache_or_trial = read_source_is_cache_or_trial(source);
    match input.evidence_cut_state {
        ReadServingEvidenceCutState::Bound => {
            if input.candidate.evidence_refs.has_evidence_query_snapshot() {
                None
            } else {
                Some((
                    ReadServingDecisionState::Unavailable,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                    ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
                ))
            }
        }
        ReadServingEvidenceCutState::Partial => {
            if cache_or_trial
                && input.candidate.evidence_refs.has_evidence_query_snapshot()
                && matches!(
                    input.policy.freshness_profile,
                    ReadFreshnessProfile::CacheOnlyAcceleration
                )
            {
                None
            } else {
                Some((
                    ReadServingDecisionState::Unknown,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                    ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
                ))
            }
        }
        ReadServingEvidenceCutState::DegradedVisible => {
            if matches!(source, StorageIntentReadSourceClass::DegradedReconstruction)
                && input.candidate.evidence_refs.has_evidence_query_snapshot()
            {
                None
            } else {
                Some((
                    ReadServingDecisionState::DegradedVisible,
                    StorageIntentRefusalReason::EvidenceNotUsable,
                    ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
                ))
            }
        }
        ReadServingEvidenceCutState::Blocked => Some((
            ReadServingDecisionState::Blocked,
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
        )),
        ReadServingEvidenceCutState::Refused => Some((
            ReadServingDecisionState::Refused,
            if input.evidence_query_snapshot.refusal as u16
                != StorageIntentRefusalReason::None as u16
            {
                input.evidence_query_snapshot.refusal
            } else {
                StorageIntentRefusalReason::EvidenceNotUsable
            },
            ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
        )),
        ReadServingEvidenceCutState::Missing
        | ReadServingEvidenceCutState::Stale
        | ReadServingEvidenceCutState::Redacted
        | ReadServingEvidenceCutState::Compacted => Some((
            ReadServingDecisionState::Unavailable,
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
        )),
        ReadServingEvidenceCutState::Unknown => Some((
            ReadServingDecisionState::Unknown,
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_EVIDENCE_CUT,
        )),
    }
}

const fn read_repair_disposition(input: ReadServingDecisionInput) -> ReadRepairDisposition {
    if !input.candidate.read_repair_requested {
        return ReadRepairDisposition::None;
    }
    if !input.policy.allow_read_repair {
        return ReadRepairDisposition::Refused;
    }
    if input.policy.repair_requires_reserve
        && (!evidence_ref_has_id(input.candidate.evidence_refs.scheduler_admission_ref)
            || !evidence_ref_has_id(input.candidate.evidence_refs.repair_budget_ref)
            || !evidence_ref_has_kind(
                input.candidate.evidence_refs.capacity_admission_ref,
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            ))
    {
        return ReadRepairDisposition::ReserveRequired;
    }
    if !receipt_id_is_zero(input.candidate.replacement_receipt)
        && evidence_ref_has_id(input.candidate.evidence_refs.replacement_receipt_ref)
    {
        return ReadRepairDisposition::ReplacementReceiptPublished;
    }
    ReadRepairDisposition::ReplacementReceiptPending
}

const fn decision_from_parts(
    input: ReadServingDecisionInput,
    state: ReadServingDecisionState,
    refusal: StorageIntentRefusalReason,
    rejected: ReadServingRejectionMask,
) -> ReadServingDecisionRecord {
    let source = if refusal as u16 == StorageIntentRefusalReason::None as u16 {
        input.candidate.source_class
    } else {
        StorageIntentReadSourceClass::Unknown
    };
    let core_source = read_source_core_class(input.candidate.source_class);
    let cache_only = refusal as u16 == StorageIntentRefusalReason::None as u16
        && (matches!(state, ReadServingDecisionState::CacheOnly)
            || matches!(
                input.candidate.source_class,
                StorageIntentReadSourceClass::CleanCache
            ));
    let serving_trial = refusal as u16 == StorageIntentRefusalReason::None as u16
        && (matches!(state, ReadServingDecisionState::ServingTrial)
            || matches!(
                input.candidate.source_class,
                StorageIntentReadSourceClass::CacheOnlyServingTrial
            ));
    let degraded_visible = matches!(state, ReadServingDecisionState::DegradedVisible);
    ReadServingDecisionRecord {
        policy_id: input.policy.policy_id,
        policy_revision: input.policy.policy_revision,
        scope: input.candidate.scope,
        freshness_profile: input.policy.freshness_profile,
        requested_source: input.candidate.source_class,
        chosen_source: source,
        core_source,
        decision_state: state,
        refusal,
        source_receipt: input.candidate.source_receipt,
        replacement_receipt: input.candidate.replacement_receipt,
        freshness: ReadSourceFreshnessRecord {
            source: core_source,
            source_receipt: input.candidate.source_receipt,
            snapshot_generation: input.candidate.snapshot_generation,
            geo_lag_ms: input.candidate.geo_lag_ms,
            lag_known: input.candidate.lag_known,
            freshness_frontier_ms: input.candidate.freshness_frontier_ms,
            evidence: input.candidate.evidence_refs.freshness_ref,
        },
        object_generation: input.candidate.object_generation,
        namespace_generation: input.candidate.namespace_generation,
        layout_generation: input.candidate.layout_generation,
        cache_only,
        serving_trial,
        degraded_visible,
        read_repair: read_repair_disposition(input),
        rejected_reasons: rejected,
        prefetch_candidate: input.candidate.prefetch_candidate,
        prefetch_outcome: input.candidate.prefetch_outcome,
        prefetch_residency: input.candidate.prefetch_residency,
        action_class: input.candidate.action_class,
        evidence_cut_state: input.evidence_cut_state,
        evidence_refs: input.candidate.evidence_refs,
    }
}

const fn common_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !policy_identity_matches(
        input.policy.policy_id,
        input.policy.policy_revision,
        input.candidate.policy_id,
        input.candidate.policy_revision,
    ) {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        ));
    }
    if matches!(
        input.candidate.source_class,
        StorageIntentReadSourceClass::Unknown
    ) {
        return Some((
            StorageIntentRefusalReason::NoLegalReceiptSet,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        ));
    }
    if !evidence_ref_has_id(input.candidate.evidence_refs.freshness_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.compiled_policy_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.temporal_ref)
    {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        ));
    }
    if input.candidate.object_generation < input.policy.required_object_generation
        || input.candidate.namespace_generation < input.policy.required_namespace_generation
        || (input.policy.required_layout_generation > 0
            && input.candidate.layout_generation < input.policy.required_layout_generation)
    {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::STALE_GENERATION,
        ));
    }
    if read_source_requires_receipt(input.candidate.source_class)
        && (receipt_id_is_zero(input.candidate.source_receipt)
            || !evidence_ref_has_id(input.candidate.evidence_refs.placement_receipt_ref))
    {
        return Some((
            StorageIntentRefusalReason::NoLegalReceiptSet,
            ReadServingRejectionMask::RECEIPT_MISSING,
        ));
    }
    if input.policy.require_digest_verification
        && !matches!(
            input.candidate.source_class,
            StorageIntentReadSourceClass::DirtyPageCacheVisible
        )
        && (!input.candidate.digest_verified
            || !evidence_ref_has_id(input.candidate.evidence_refs.data_shape_ref)
            || !evidence_ref_has_id(input.candidate.evidence_refs.digest_checksum_ref))
    {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH,
        ));
    }
    None
}

const fn cache_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !matches!(
        input.candidate.source_class,
        StorageIntentReadSourceClass::DirtyPageCacheVisible
    ) && !input.policy.allow_cache_only
        && !matches!(
            input.policy.freshness_profile,
            ReadFreshnessProfile::CacheOnlyAcceleration
        )
    {
        return Some((
            StorageIntentRefusalReason::CacheCannotBeAuthority,
            ReadServingRejectionMask::CACHE_CANNOT_BE_AUTHORITY,
        ));
    }
    if !evidence_ref_has_id(input.candidate.evidence_refs.cache_anchor_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.cache_fence_ref)
        || input.candidate.cache_anchor_generation < input.policy.required_object_generation
        || input.candidate.cache_fence_generation < input.policy.required_object_generation
    {
        return Some((
            StorageIntentRefusalReason::CacheCannotBeAuthority,
            ReadServingRejectionMask::CACHE_ANCHOR_INVALID,
        ));
    }
    if matches!(
        input.candidate.source_class,
        StorageIntentReadSourceClass::CacheOnlyServingTrial
    ) && (!input.policy.allow_serving_trial
        || !evidence_ref_has_id(input.candidate.evidence_refs.prefetch_decision_ref)
        || !matches!(
            input.candidate.prefetch_outcome,
            PrefetchResidencyDecisionOutcome::CacheOnly
                | PrefetchResidencyDecisionOutcome::ServingTrial
        ))
    {
        return Some((
            StorageIntentRefusalReason::CacheCannotBeAuthority,
            ReadServingRejectionMask::CACHE_CANNOT_BE_AUTHORITY,
        ));
    }
    None
}

const fn ram_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !evidence_ref_has_kind(
        input.candidate.evidence_refs.ram_authority_ref,
        StorageIntentEvidenceKind::RamAuthorityEvidence,
    ) || !evidence_ref_has_id(input.candidate.evidence_refs.membership_epoch_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.lease_epoch_ref)
    {
        return Some((
            StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        ));
    }
    if matches!(
        input.candidate.source_class,
        StorageIntentReadSourceClass::AuthoritativePmem
    ) && !evidence_ref_has_kind(
        input.candidate.evidence_refs.media_capability_ref,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) {
        return Some((
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
            ReadServingRejectionMask::PMEM_MISSING_MEDIA_CAPABILITY,
        ));
    }
    None
}

const fn remote_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !evidence_ref_has_id(input.candidate.evidence_refs.membership_epoch_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.lease_epoch_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.transport_path_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.trust_domain_ref)
    {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::REMOTE_TRUST_OR_TRANSPORT_MISSING,
        ));
    }
    None
}

const fn degraded_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if matches!(
        input.policy.degraded_read_policy,
        DegradedReadPolicy::Refuse
    ) {
        return Some((
            StorageIntentRefusalReason::NoLegalReceiptSet,
            ReadServingRejectionMask::DEGRADED_POLICY_REFUSED,
        ));
    }
    if !input.candidate.reconstruction_verified
        || input.candidate.redundancy_width == 0
        || input.candidate.missing_targets >= input.candidate.redundancy_width
        || !evidence_ref_has_id(input.candidate.evidence_refs.recovery_degradation_ref)
        || !evidence_ref_has_id(input.candidate.evidence_refs.redundancy_ref)
    {
        return Some((
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH,
        ));
    }
    None
}

const fn snapshot_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !matches!(
        input.policy.freshness_profile,
        ReadFreshnessProfile::SnapshotGeneration
    ) || input.policy.required_snapshot_generation == 0
        || input.candidate.snapshot_generation != input.policy.required_snapshot_generation
    {
        return Some((
            StorageIntentRefusalReason::DurabilityOrRpoNotMet,
            ReadServingRejectionMask::SNAPSHOT_GENERATION_MISMATCH,
        ));
    }
    None
}

const fn geo_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !matches!(
        input.policy.freshness_profile,
        ReadFreshnessProfile::ExplicitStaleRead | ReadFreshnessProfile::DisasterRecoveryRpo
    ) {
        return Some((
            StorageIntentRefusalReason::DurabilityOrRpoNotMet,
            ReadServingRejectionMask::GEO_PROFILE_MISMATCH,
        ));
    }
    if !input.candidate.lag_known || input.candidate.geo_lag_ms > input.policy.max_remote_lag_ms {
        return Some((
            StorageIntentRefusalReason::DurabilityOrRpoNotMet,
            ReadServingRejectionMask::GEO_LAG_OUTSIDE_RPO,
        ));
    }
    remote_refusal(input)
}

const fn archive_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    if !matches!(
        input.policy.freshness_profile,
        ReadFreshnessProfile::ArchiveRestore | ReadFreshnessProfile::DisasterRecoveryRpo
    ) {
        return Some((
            StorageIntentRefusalReason::DurabilityOrRpoNotMet,
            ReadServingRejectionMask::GEO_PROFILE_MISMATCH,
        ));
    }
    if !evidence_ref_has_kind(
        input.candidate.evidence_refs.media_capability_ref,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
    ) {
        return Some((
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        ));
    }
    None
}

const fn source_refusal(
    input: ReadServingDecisionInput,
) -> Option<(StorageIntentRefusalReason, ReadServingRejectionMask)> {
    match input.candidate.source_class {
        StorageIntentReadSourceClass::DirtyPageCacheVisible
        | StorageIntentReadSourceClass::CleanCache
        | StorageIntentReadSourceClass::CacheOnlyServingTrial => cache_refusal(input),
        StorageIntentReadSourceClass::AuthoritativeRam
        | StorageIntentReadSourceClass::AuthoritativePmem => ram_refusal(input),
        StorageIntentReadSourceClass::RemotePlacementReceipt => remote_refusal(input),
        StorageIntentReadSourceClass::DegradedReconstruction => degraded_refusal(input),
        StorageIntentReadSourceClass::SnapshotGeneration => snapshot_refusal(input),
        StorageIntentReadSourceClass::GeoAsyncRemote => geo_refusal(input),
        StorageIntentReadSourceClass::ArchiveRestore => archive_refusal(input),
        StorageIntentReadSourceClass::LocalPlacementReceipt
        | StorageIntentReadSourceClass::MetadataHotLookup
        | StorageIntentReadSourceClass::DirectoryIndex => None,
        StorageIntentReadSourceClass::Unknown => Some((
            StorageIntentRefusalReason::NoLegalReceiptSet,
            ReadServingRejectionMask::MISSING_EVIDENCE_REF,
        )),
    }
}

const fn success_state(input: ReadServingDecisionInput) -> ReadServingDecisionState {
    match input.candidate.source_class {
        StorageIntentReadSourceClass::DirtyPageCacheVisible
        | StorageIntentReadSourceClass::AuthoritativeRam
        | StorageIntentReadSourceClass::AuthoritativePmem
        | StorageIntentReadSourceClass::LocalPlacementReceipt
        | StorageIntentReadSourceClass::RemotePlacementReceipt
        | StorageIntentReadSourceClass::SnapshotGeneration
        | StorageIntentReadSourceClass::GeoAsyncRemote
        | StorageIntentReadSourceClass::ArchiveRestore
        | StorageIntentReadSourceClass::MetadataHotLookup
        | StorageIntentReadSourceClass::DirectoryIndex => ReadServingDecisionState::Available,
        StorageIntentReadSourceClass::CleanCache => ReadServingDecisionState::CacheOnly,
        StorageIntentReadSourceClass::CacheOnlyServingTrial => {
            ReadServingDecisionState::ServingTrial
        }
        StorageIntentReadSourceClass::DegradedReconstruction => {
            if matches!(
                input.policy.degraded_read_policy,
                DegradedReadPolicy::ExposeDegradedVisible
            ) || matches!(
                input.evidence_cut_state,
                ReadServingEvidenceCutState::DegradedVisible
            ) {
                ReadServingDecisionState::DegradedVisible
            } else {
                ReadServingDecisionState::Available
            }
        }
        StorageIntentReadSourceClass::Unknown => ReadServingDecisionState::Unknown,
    }
}

/// Decide whether one candidate is a legal read-serving source.
#[must_use]
pub const fn read_serving_decide(input: ReadServingDecisionInput) -> ReadServingDecisionRecord {
    if let Some((state, refusal, rejected)) = evidence_cut_refusal_state(input) {
        return decision_from_parts(input, state, refusal, rejected);
    }
    if !read_serving_evidence_cut_has_required_families(input) {
        return decision_from_parts(
            input,
            ReadServingDecisionState::Unavailable,
            StorageIntentRefusalReason::EvidenceNotUsable,
            ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY,
        );
    }
    if let Some((refusal, rejected)) = common_refusal(input) {
        return decision_from_parts(input, ReadServingDecisionState::Refused, refusal, rejected);
    }
    if let Some((refusal, rejected)) = source_refusal(input) {
        return decision_from_parts(input, ReadServingDecisionState::Refused, refusal, rejected);
    }
    let missing_candidate_refs = read_serving_candidate_missing_required_ref_reasons(input);
    if !missing_candidate_refs.is_empty() {
        return decision_from_parts(
            input,
            ReadServingDecisionState::Unavailable,
            StorageIntentRefusalReason::EvidenceNotUsable,
            missing_candidate_refs,
        );
    }

    decision_from_parts(
        input,
        success_state(input),
        StorageIntentRefusalReason::None,
        if matches!(
            read_repair_disposition(input),
            ReadRepairDisposition::ReserveRequired
        ) {
            ReadServingRejectionMask::MISSING_CAPACITY_ADMISSION_EVIDENCE
        } else if matches!(
            read_repair_disposition(input),
            ReadRepairDisposition::ReplacementReceiptPending
        ) {
            ReadServingRejectionMask::REPAIR_REPLACEMENT_RECEIPT_MISSING
        } else {
            ReadServingRejectionMask::EMPTY
        },
    )
}

/// Returns true only when a read-triggered repair has replacement evidence.
#[must_use]
pub const fn read_repair_may_retire_old_receipt(decision: ReadServingDecisionRecord) -> bool {
    decision.refusal as u16 == StorageIntentRefusalReason::None as u16
        && matches!(
            decision.read_repair,
            ReadRepairDisposition::ReplacementReceiptPublished
        )
        && !receipt_id_is_zero(decision.source_receipt)
        && !receipt_id_is_zero(decision.replacement_receipt)
        && evidence_ref_has_id(decision.evidence_refs.replacement_receipt_ref)
}

/// Returns true when the selected source is not authority for durable claims.
#[must_use]
pub const fn read_serving_decision_is_cache_only(decision: ReadServingDecisionRecord) -> bool {
    decision.refusal as u16 == StorageIntentRefusalReason::None as u16
        && (decision.cache_only || decision.serving_trial)
}

/// Summary of how one read was served, for explanation, performance, fault,
/// and satisfaction consumers (#849, #850, #863, #874).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadServingExplanation {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub freshness_profile: ReadFreshnessProfile,
    pub requested_source: StorageIntentReadSourceClass,
    pub chosen_source: StorageIntentReadSourceClass,
    pub core_source: CoreReadServingSourceClass,
    pub decision_state: ReadServingDecisionState,
    pub refusal: StorageIntentRefusalReason,
    pub source_receipt: StorageIntentReceiptId,
    pub freshness: ReadSourceFreshnessRecord,
    pub object_generation: u64,
    pub namespace_generation: u64,
    pub layout_generation: u64,
    pub cache_only: bool,
    pub serving_trial: bool,
    pub degraded_visible: bool,
    pub read_repair: ReadRepairDisposition,
    pub rejected_reasons: ReadServingRejectionMask,
    pub prefetch_candidate: PrefetchResidencyCandidateClass,
    pub prefetch_outcome: PrefetchResidencyDecisionOutcome,
    pub prefetch_residency: PrefetchResidencyStateClass,
    pub action_class: StorageIntentActionClass,
    pub evidence_cut_state: ReadServingEvidenceCutState,
}

impl From<ReadServingDecisionRecord> for ReadServingExplanation {
    fn from(decision: ReadServingDecisionRecord) -> Self {
        Self {
            policy_id: decision.policy_id,
            policy_revision: decision.policy_revision,
            scope: decision.scope,
            freshness_profile: decision.freshness_profile,
            requested_source: decision.requested_source,
            chosen_source: decision.chosen_source,
            core_source: decision.core_source,
            decision_state: decision.decision_state,
            refusal: decision.refusal,
            source_receipt: decision.source_receipt,
            freshness: decision.freshness,
            object_generation: decision.object_generation,
            namespace_generation: decision.namespace_generation,
            layout_generation: decision.layout_generation,
            cache_only: decision.cache_only,
            serving_trial: decision.serving_trial,
            degraded_visible: decision.degraded_visible,
            read_repair: decision.read_repair,
            rejected_reasons: decision.rejected_reasons,
            prefetch_candidate: decision.prefetch_candidate,
            prefetch_outcome: decision.prefetch_outcome,
            prefetch_residency: decision.prefetch_residency,
            action_class: decision.action_class,
            evidence_cut_state: decision.evidence_cut_state,
        }
    }
}

impl Default for ReadServingExplanation {
    fn default() -> Self {
        Self::from(ReadServingDecisionRecord::default())
    }
}

/// Returns true when policy rollout evidence is required for this source.
#[must_use]
pub const fn read_serving_requires_policy_rollout(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::RemotePlacementReceipt
            | StorageIntentReadSourceClass::DegradedReconstruction
            | StorageIntentReadSourceClass::GeoAsyncRemote
            | StorageIntentReadSourceClass::ArchiveRestore
    )
}

/// Returns true when tenant isolation evidence is required for this source.
#[must_use]
pub const fn read_serving_requires_tenant_isolation(source: StorageIntentReadSourceClass) -> bool {
    read_source_requires_receipt(source)
}

/// Returns true when service objective evidence is required for this source.
#[must_use]
pub const fn read_serving_requires_service_objective(source: StorageIntentReadSourceClass) -> bool {
    matches!(
        source,
        StorageIntentReadSourceClass::AuthoritativeRam
            | StorageIntentReadSourceClass::AuthoritativePmem
            | StorageIntentReadSourceClass::MetadataHotLookup
            | StorageIntentReadSourceClass::DirectoryIndex
    )
}

/// Returns true when capacity admission evidence is required for read repair.
#[must_use]
pub const fn read_serving_requires_capacity_admission(
    read_repair_requested: bool,
    allow_read_repair: bool,
) -> bool {
    read_repair_requested && allow_read_repair
}

impl_u8_canonical!(StorageIntentReadSourceClass, {
    Unknown = 0 => "unknown",
    DirtyPageCacheVisible = 1 => "dirty-page-cache-visible",
    CleanCache = 2 => "clean-cache",
    CacheOnlyServingTrial = 3 => "cache-only-serving-trial",
    AuthoritativeRam = 4 => "authoritative-ram",
    AuthoritativePmem = 5 => "authoritative-pmem",
    LocalPlacementReceipt = 6 => "local-placement-receipt",
    RemotePlacementReceipt = 7 => "remote-placement-receipt",
    DegradedReconstruction = 8 => "degraded-reconstruction",
    SnapshotGeneration = 9 => "snapshot-generation",
    GeoAsyncRemote = 10 => "geo-async-remote",
    ArchiveRestore = 11 => "archive-restore",
    MetadataHotLookup = 12 => "metadata-hot-lookup",
    DirectoryIndex = 13 => "directory-index",
});

impl_u8_canonical!(ReadFreshnessProfile, {
    LatestLocal = 0 => "latest-local",
    SnapshotGeneration = 1 => "snapshot-generation",
    ExplicitStaleRead = 2 => "explicit-stale-read",
    DisasterRecoveryRpo = 3 => "disaster-recovery-rpo",
    CacheOnlyAcceleration = 4 => "cache-only-acceleration",
    ArchiveRestore = 5 => "archive-restore",
});

impl_u8_canonical!(DegradedReadPolicy, {
    ServeWhenVerified = 0 => "serve-when-verified",
    ExposeDegradedVisible = 1 => "expose-degraded-visible",
    Refuse = 2 => "refuse",
});

impl_u8_canonical!(ReadServingEvidenceCutState, {
    Unknown = 0 => "unknown",
    Bound = 1 => "bound",
    Missing = 2 => "missing",
    Partial = 3 => "partial",
    Stale = 4 => "stale",
    Redacted = 5 => "redacted",
    Compacted = 6 => "compacted",
    DegradedVisible = 7 => "degraded-visible",
    Blocked = 8 => "blocked",
    Refused = 9 => "refused",
});

impl_u8_canonical!(ReadServingDecisionState, {
    Unknown = 0 => "unknown",
    Available = 1 => "available",
    CacheOnly = 2 => "cache-only",
    ServingTrial = 3 => "serving-trial",
    DegradedVisible = 4 => "degraded-visible",
    Unavailable = 5 => "unavailable",
    Blocked = 6 => "blocked",
    Refused = 7 => "refused",
});

impl_u8_canonical!(ReadRepairDisposition, {
    None = 0 => "none",
    ReserveRequired = 1 => "reserve-required",
    ReplacementReceiptPending = 2 => "replacement-receipt-pending",
    ReplacementReceiptPublished = 3 => "replacement-receipt-published",
    Refused = 4 => "refused",
});

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        EvidenceConsumerClass, EvidenceFamilyFreshness, EvidenceFamilyFreshnessState,
        EvidenceQuerySubjectScope, EvidenceQuerySubjectScopeClass, EvidenceRetentionClass,
        StorageIntentEvidenceRefs,
    };

    const POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId([7_u8; 16]);
    const POLICY_REVISION: StorageIntentPolicyRevision = StorageIntentPolicyRevision(3);
    const DATASET_ID: StorageIntentDomainId = StorageIntentDomainId([9_u8; 16]);
    const OBJECT_ID: StorageIntentEvidenceId = StorageIntentEvidenceId([11_u8; 32]);

    fn evidence_ref(kind: StorageIntentEvidenceKind, seed: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, StorageIntentEvidenceId([seed; 32]), 1, 1)
    }

    fn receipt(seed: u8) -> StorageIntentReceiptId {
        StorageIntentReceiptId([seed; 16])
    }

    fn scope(generation: u64) -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: DATASET_ID,
            object_id: OBJECT_ID,
            range_start: 4096,
            range_len: 8192,
            generation,
        }
    }

    fn policy(profile: ReadFreshnessProfile) -> ReadServingPolicy {
        ReadServingPolicy {
            policy_id: POLICY_ID,
            policy_revision: POLICY_REVISION,
            freshness_profile: profile,
            required_object_generation: 10,
            required_namespace_generation: 5,
            required_layout_generation: 2,
            required_snapshot_generation: 0,
            max_remote_lag_ms: 0,
            degraded_read_policy: DegradedReadPolicy::ServeWhenVerified,
            allow_cache_only: matches!(profile, ReadFreshnessProfile::CacheOnlyAcceleration),
            allow_serving_trial: matches!(profile, ReadFreshnessProfile::CacheOnlyAcceleration),
            allow_read_repair: true,
            repair_requires_reserve: true,
            require_digest_verification: true,
        }
    }

    fn refs() -> ReadServingEvidenceRefs {
        ReadServingEvidenceRefs {
            compiled_policy_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 1),
            evidence_query_snapshot_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                2,
            ),
            freshness_ref: evidence_ref(StorageIntentEvidenceKind::ReadFreshnessEvidence, 3),
            namespace_generation_ref: evidence_ref(
                StorageIntentEvidenceKind::MetadataNamespaceEvidence,
                4,
            ),
            placement_receipt_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 5),
            cache_anchor_ref: evidence_ref(StorageIntentEvidenceKind::ReadFreshnessEvidence, 6),
            cache_fence_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 7),
            membership_epoch_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 8),
            lease_epoch_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 9),
            transport_path_ref: evidence_ref(StorageIntentEvidenceKind::TransportPathEvidence, 10),
            trust_domain_ref: evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 11),
            data_shape_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 12),
            layout_allocator_ref: evidence_ref(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                13,
            ),
            digest_checksum_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 14),
            media_capability_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                15,
            ),
            ram_authority_ref: evidence_ref(StorageIntentEvidenceKind::RamAuthorityEvidence, 16),
            recovery_degradation_ref: evidence_ref(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                17,
            ),
            redundancy_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 18),
            temporal_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 19),
            scheduler_admission_ref: evidence_ref(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                20,
            ),
            repair_budget_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                21,
            ),
            replacement_receipt_ref: EMPTY_EVIDENCE_REF,
            prefetch_decision_ref: evidence_ref(
                StorageIntentEvidenceKind::DecisionFrontierEvidence,
                22,
            ),
            result_refusal_ref: evidence_ref(StorageIntentEvidenceKind::ResultRefusalEvidence, 23),
            ordering_evidence_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 24),
            policy_rollout_ref: evidence_ref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 25),
            tenant_isolation_ref: evidence_ref(
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                26,
            ),
            service_objective_ref: evidence_ref(
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                27,
            ),
            capacity_admission_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                28,
            ),
        }
    }

    fn family_ref(kind: StorageIntentEvidenceKind) -> StorageIntentEvidenceRef {
        let refs = refs();
        match kind {
            StorageIntentEvidenceKind::LocalIntentRecord => refs.compiled_policy_ref,
            StorageIntentEvidenceKind::ReadFreshnessEvidence => refs.freshness_ref,
            StorageIntentEvidenceKind::TemporalEvidence => refs.temporal_ref,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence => refs.namespace_generation_ref,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence => refs.layout_allocator_ref,
            StorageIntentEvidenceKind::DataShapeEvidence => refs.data_shape_ref,
            StorageIntentEvidenceKind::PlacementReceipt => refs.placement_receipt_ref,
            StorageIntentEvidenceKind::OrderingEvidence => refs.cache_fence_ref,
            StorageIntentEvidenceKind::MembershipEvidence => refs.membership_epoch_ref,
            StorageIntentEvidenceKind::TransportPathEvidence => refs.transport_path_ref,
            StorageIntentEvidenceKind::TrustDomainEvidence => refs.trust_domain_ref,
            StorageIntentEvidenceKind::MediaCapabilityEvidence => refs.media_capability_ref,
            StorageIntentEvidenceKind::RamAuthorityEvidence => refs.ram_authority_ref,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence => refs.recovery_degradation_ref,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord => refs.scheduler_admission_ref,
            StorageIntentEvidenceKind::CapacityAdmissionEvidence => refs.capacity_admission_ref,
            StorageIntentEvidenceKind::DecisionFrontierEvidence => refs.prefetch_decision_ref,
            StorageIntentEvidenceKind::PolicyRolloutEvidence => refs.policy_rollout_ref,
            StorageIntentEvidenceKind::TenantIsolationEvidence => refs.tenant_isolation_ref,
            StorageIntentEvidenceKind::ServiceObjectiveEvidence => refs.service_objective_ref,
            _ => evidence_ref(kind, 90),
        }
    }

    fn push_family(
        snapshot: &mut StorageIntentEvidenceQuerySnapshot,
        kind: StorageIntentEvidenceKind,
        state: EvidenceFamilyFreshnessState,
    ) {
        let evidence_ref = family_ref(kind);
        snapshot.included_refs.push(evidence_ref).unwrap();
        snapshot
            .family_freshness
            .push(EvidenceFamilyFreshness {
                kind,
                state,
                source_index_generation: 1,
                producer_generation: 1,
                freshness_frontier_ms: 1000,
                allowed_staleness_ms: 0,
                evidence_ref,
            })
            .unwrap();
    }

    fn snapshot_base() -> StorageIntentEvidenceQuerySnapshot {
        StorageIntentEvidenceQuerySnapshot {
            snapshot_id: StorageIntentEvidenceId([31_u8; 32]),
            query_id: StorageIntentEvidenceId([32_u8; 32]),
            consumer: EvidenceConsumerClass::ReadPath,
            context: EvidenceQueryContextClass::ReadServing,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::ObjectRange,
                object_scope: scope(10),
                pool_id: StorageIntentDomainId::ZERO,
                domain_id: StorageIntentDomainId::ZERO,
                request_ref: EMPTY_EVIDENCE_REF,
                action_ref: EMPTY_EVIDENCE_REF,
                validation_ref: EMPTY_EVIDENCE_REF,
            },
            policy_id: POLICY_ID,
            policy_revision: POLICY_REVISION,
            temporal_frontier_ms: 1000,
            freshness_frontier_ms: 1000,
            allowed_staleness_ms: 0,
            source_catalog_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 33),
            source_index_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 34),
            source_index_generation: 1,
            producer_generation: 1,
            producer_watermark_ms: 1000,
            compaction_generation: 0,
            redaction_generation: 0,
            included_refs: StorageIntentEvidenceRefs::EMPTY,
            family_freshness: Default::default(),
            completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
            retention: EvidenceRetentionClass::ExactRequired,
            retention_ref: EMPTY_EVIDENCE_REF,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    const DEFAULT_FRESH_FAMILIES: [StorageIntentEvidenceKind; 20] = [
        StorageIntentEvidenceKind::LocalIntentRecord,
        StorageIntentEvidenceKind::ReadFreshnessEvidence,
        StorageIntentEvidenceKind::TemporalEvidence,
        StorageIntentEvidenceKind::MetadataNamespaceEvidence,
        StorageIntentEvidenceKind::LayoutAllocatorEvidence,
        StorageIntentEvidenceKind::DataShapeEvidence,
        StorageIntentEvidenceKind::PlacementReceipt,
        StorageIntentEvidenceKind::OrderingEvidence,
        StorageIntentEvidenceKind::MembershipEvidence,
        StorageIntentEvidenceKind::TransportPathEvidence,
        StorageIntentEvidenceKind::TrustDomainEvidence,
        StorageIntentEvidenceKind::MediaCapabilityEvidence,
        StorageIntentEvidenceKind::RamAuthorityEvidence,
        StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        StorageIntentEvidenceKind::SchedulerAdmissionRecord,
        StorageIntentEvidenceKind::CapacityAdmissionEvidence,
        StorageIntentEvidenceKind::DecisionFrontierEvidence,
        StorageIntentEvidenceKind::PolicyRolloutEvidence,
        StorageIntentEvidenceKind::TenantIsolationEvidence,
        StorageIntentEvidenceKind::ServiceObjectiveEvidence,
    ];

    fn snapshot_with_families(
        families: &[StorageIntentEvidenceKind],
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot = snapshot_base();
        let mut index = 0;
        while index < families.len() {
            push_family(
                &mut snapshot,
                families[index],
                EvidenceFamilyFreshnessState::Fresh,
            );
            index += 1;
        }
        snapshot
    }

    fn snapshot_with_family_override(
        override_kind: StorageIntentEvidenceKind,
        override_state: EvidenceFamilyFreshnessState,
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot = snapshot_base();
        let mut index = 0;
        while index < DEFAULT_FRESH_FAMILIES.len() {
            let kind = DEFAULT_FRESH_FAMILIES[index];
            let state = if kind as u16 == override_kind as u16 {
                override_state
            } else {
                EvidenceFamilyFreshnessState::Fresh
            };
            push_family(&mut snapshot, kind, state);
            index += 1;
        }
        snapshot
    }

    fn snapshot() -> StorageIntentEvidenceQuerySnapshot {
        snapshot_with_families(&DEFAULT_FRESH_FAMILIES)
    }

    fn candidate(source_class: StorageIntentReadSourceClass) -> ReadServingCandidateRecord {
        ReadServingCandidateRecord {
            policy_id: POLICY_ID,
            policy_revision: POLICY_REVISION,
            scope: scope(10),
            source_class,
            source_receipt: receipt(44),
            object_generation: 10,
            namespace_generation: 5,
            layout_generation: 2,
            snapshot_generation: 0,
            geo_lag_ms: 0,
            lag_known: true,
            freshness_frontier_ms: 1000,
            cache_anchor_generation: 10,
            cache_fence_generation: 10,
            digest_verified: true,
            reconstruction_verified: false,
            redundancy_width: 0,
            missing_targets: 0,
            read_repair_requested: false,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            prefetch_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            prefetch_outcome: PrefetchResidencyDecisionOutcome::NoAction,
            prefetch_residency: PrefetchResidencyStateClass::Unknown,
            action_class: StorageIntentActionClass::ReadSourceRefresh,
            evidence_refs: refs(),
        }
    }

    fn decide(
        policy: ReadServingPolicy,
        candidate: ReadServingCandidateRecord,
    ) -> ReadServingDecisionRecord {
        decide_with_snapshot(policy, candidate, snapshot())
    }

    fn decide_with_snapshot(
        policy: ReadServingPolicy,
        candidate: ReadServingCandidateRecord,
        evidence_query_snapshot: StorageIntentEvidenceQuerySnapshot,
    ) -> ReadServingDecisionRecord {
        read_serving_decide(ReadServingDecisionInput {
            policy,
            candidate,
            evidence_cut_state: ReadServingEvidenceCutState::Bound,
            evidence_query_snapshot,
        })
    }

    #[test]
    fn evidence_cut_requires_fresh_families_for_receipt_authority() {
        let families = [
            StorageIntentEvidenceKind::LocalIntentRecord,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            StorageIntentEvidenceKind::TemporalEvidence,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
            StorageIntentEvidenceKind::PlacementReceipt,
        ];
        let input = ReadServingDecisionInput {
            policy: policy(ReadFreshnessProfile::LatestLocal),
            candidate: candidate(StorageIntentReadSourceClass::LocalPlacementReceipt),
            evidence_cut_state: ReadServingEvidenceCutState::Bound,
            evidence_query_snapshot: snapshot_with_families(&families),
        };

        assert!(!read_serving_evidence_cut_has_required_families(input));
        let decision = read_serving_decide(input);
        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn stale_family_row_cannot_authorize_digest_backed_source() {
        let input = ReadServingDecisionInput {
            policy: policy(ReadFreshnessProfile::LatestLocal),
            candidate: candidate(StorageIntentReadSourceClass::LocalPlacementReceipt),
            evidence_cut_state: ReadServingEvidenceCutState::Bound,
            evidence_query_snapshot: snapshot_with_family_override(
                StorageIntentEvidenceKind::DataShapeEvidence,
                EvidenceFamilyFreshnessState::Stale,
            ),
        };

        assert!(!read_serving_evidence_cut_has_required_families(input));
        let decision = read_serving_decide(input);
        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn remote_receipt_requires_transport_and_trust_families_in_cut() {
        let families = [
            StorageIntentEvidenceKind::LocalIntentRecord,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            StorageIntentEvidenceKind::TemporalEvidence,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
            StorageIntentEvidenceKind::DataShapeEvidence,
            StorageIntentEvidenceKind::PlacementReceipt,
            StorageIntentEvidenceKind::MembershipEvidence,
        ];
        let decision = decide_with_snapshot(
            policy(ReadFreshnessProfile::LatestLocal),
            candidate(StorageIntentReadSourceClass::RemotePlacementReceipt),
            snapshot_with_families(&families),
        );

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn serving_trial_requires_decision_frontier_family_in_cut() {
        let families = [
            StorageIntentEvidenceKind::LocalIntentRecord,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            StorageIntentEvidenceKind::TemporalEvidence,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
            StorageIntentEvidenceKind::DataShapeEvidence,
            StorageIntentEvidenceKind::OrderingEvidence,
        ];
        let mut candidate = candidate(StorageIntentReadSourceClass::CacheOnlyServingTrial);
        candidate.prefetch_candidate = PrefetchResidencyCandidateClass::CacheOnlyTrial;
        candidate.prefetch_outcome = PrefetchResidencyDecisionOutcome::ServingTrial;
        candidate.prefetch_residency = PrefetchResidencyStateClass::VolatileRamServingTrial;

        let decision = decide_with_snapshot(
            policy(ReadFreshnessProfile::CacheOnlyAcceleration),
            candidate,
            snapshot_with_families(&families),
        );

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn cache_trial_invalidates_when_anchor_or_fence_is_stale() {
        let mut candidate = candidate(StorageIntentReadSourceClass::CacheOnlyServingTrial);
        candidate.cache_anchor_generation = 9;
        candidate.prefetch_candidate = PrefetchResidencyCandidateClass::CacheOnlyTrial;
        candidate.prefetch_outcome = PrefetchResidencyDecisionOutcome::ServingTrial;
        candidate.prefetch_residency = PrefetchResidencyStateClass::CacheOnlyRam;

        let decision = decide(
            policy(ReadFreshnessProfile::CacheOnlyAcceleration),
            candidate,
        );

        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::CacheCannotBeAuthority
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::CACHE_ANCHOR_INVALID));
    }

    #[test]
    fn stale_generation_refuses_receipt_source() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.object_generation = 9;

        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::STALE_GENERATION));
    }

    #[test]
    fn receipt_backed_degraded_read_can_serve_when_verified() {
        let mut candidate = candidate(StorageIntentReadSourceClass::DegradedReconstruction);
        candidate.reconstruction_verified = true;
        candidate.redundancy_width = 6;
        candidate.missing_targets = 1;
        candidate.action_class = StorageIntentActionClass::DegradedReadReconstruction;

        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
        assert_eq!(
            decision.core_source,
            CoreReadServingSourceClass::DegradedReconstruction
        );
    }

    #[test]
    fn digest_mismatch_refuses_instead_of_serving_stale_bytes() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.digest_verified = false;

        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH));
    }

    #[test]
    fn geo_async_read_requires_stale_or_dr_profile() {
        let mut candidate = candidate(StorageIntentReadSourceClass::GeoAsyncRemote);
        candidate.geo_lag_ms = 1200;
        candidate.lag_known = true;

        let latest = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(latest.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            latest.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert!(latest
            .rejected_reasons
            .intersects(ReadServingRejectionMask::GEO_PROFILE_MISMATCH));

        let mut dr_policy = policy(ReadFreshnessProfile::DisasterRecoveryRpo);
        dr_policy.max_remote_lag_ms = 2000;
        let dr = decide(dr_policy, candidate);
        assert_eq!(dr.decision_state, ReadServingDecisionState::Available);
        assert_eq!(dr.refusal, StorageIntentRefusalReason::None);
        assert_eq!(dr.freshness.geo_lag_ms, 1200);
    }

    #[test]
    fn snapshot_generation_reads_are_bound_to_requested_generation() {
        let mut snapshot_policy = policy(ReadFreshnessProfile::SnapshotGeneration);
        snapshot_policy.required_snapshot_generation = 88;
        let mut candidate = candidate(StorageIntentReadSourceClass::SnapshotGeneration);
        candidate.snapshot_generation = 88;

        let decision = decide(snapshot_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);

        candidate.snapshot_generation = 87;
        let refused = decide(snapshot_policy, candidate);
        assert_eq!(refused.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            refused.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert!(refused
            .rejected_reasons
            .intersects(ReadServingRejectionMask::SNAPSHOT_GENERATION_MISMATCH));
    }

    #[test]
    fn ram_authority_reads_require_ram_authority_evidence() {
        let candidate = candidate(StorageIntentReadSourceClass::AuthoritativeRam);
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);

        let mut missing = candidate;
        missing.evidence_refs.ram_authority_ref = EMPTY_EVIDENCE_REF;
        let refused = decide(policy(ReadFreshnessProfile::LatestLocal), missing);
        assert_eq!(refused.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            refused.refusal,
            StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent
        );
    }

    #[test]
    fn read_repair_cannot_retire_old_receipt_before_replacement_evidence() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.read_repair_requested = true;
        candidate.action_class = StorageIntentActionClass::ReadTriggeredRepair;

        let pending = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(
            pending.read_repair,
            ReadRepairDisposition::ReplacementReceiptPending
        );
        assert!(!read_repair_may_retire_old_receipt(pending));

        candidate.replacement_receipt = receipt(99);
        candidate.evidence_refs.replacement_receipt_ref =
            evidence_ref(StorageIntentEvidenceKind::RelocationReceipt, 99);
        let published = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(
            published.read_repair,
            ReadRepairDisposition::ReplacementReceiptPublished
        );
        assert!(read_repair_may_retire_old_receipt(published));
    }

    #[test]
    fn read_serving_explanation_round_trips_from_decision() {
        let candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        let explanation = ReadServingExplanation::from(decision);
        assert_eq!(explanation.decision_state, decision.decision_state);
        assert_eq!(explanation.chosen_source, decision.chosen_source);
        assert_eq!(explanation.rejected_reasons, decision.rejected_reasons);
    }

    #[test]
    fn metadata_hot_lookup_requires_namespace_ref_without_policy_floor() {
        let mut metadata_policy = policy(ReadFreshnessProfile::LatestLocal);
        metadata_policy.required_namespace_generation = 0;
        let mut candidate = candidate(StorageIntentReadSourceClass::MetadataHotLookup);
        candidate.evidence_refs.namespace_generation_ref = EMPTY_EVIDENCE_REF;
        let input = ReadServingDecisionInput {
            policy: metadata_policy,
            candidate,
            evidence_cut_state: ReadServingEvidenceCutState::Bound,
            evidence_query_snapshot: snapshot(),
        };

        assert!(read_source_requires_metadata_namespace(
            StorageIntentReadSourceClass::MetadataHotLookup
        ));
        assert!(!read_serving_candidate_refs_have_required_families(input));
        assert!(read_serving_candidate_missing_required_ref_reasons(input)
            .intersects(ReadServingRejectionMask::MISSING_METADATA_NAMESPACE_EVIDENCE));
        let decision = read_serving_decide(input);
        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_METADATA_NAMESPACE_EVIDENCE));
    }

    #[test]
    fn metadata_hot_lookup_requires_fresh_namespace_family_in_cut() {
        let mut metadata_policy = policy(ReadFreshnessProfile::LatestLocal);
        metadata_policy.required_namespace_generation = 0;
        let candidate = candidate(StorageIntentReadSourceClass::MetadataHotLookup);
        let decision = decide_with_snapshot(
            metadata_policy,
            candidate,
            snapshot_with_family_override(
                StorageIntentEvidenceKind::MetadataNamespaceEvidence,
                EvidenceFamilyFreshnessState::Stale,
            ),
        );

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn directory_index_is_metadata_source_not_receipt_or_cache_authority() {
        let mut candidate = candidate(StorageIntentReadSourceClass::DirectoryIndex);
        candidate.source_receipt = StorageIntentReceiptId::ZERO;
        candidate.evidence_refs.placement_receipt_ref = EMPTY_EVIDENCE_REF;

        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert!(!read_source_requires_receipt(
            StorageIntentReadSourceClass::DirectoryIndex
        ));
        assert!(!read_source_is_cache_or_trial(
            StorageIntentReadSourceClass::DirectoryIndex
        ));
        assert!(read_source_requires_metadata_namespace(
            StorageIntentReadSourceClass::DirectoryIndex
        ));
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.source_receipt, StorageIntentReceiptId::ZERO);
        assert!(!decision.cache_only);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
    }

    #[test]
    fn directory_index_requires_ordering_evidence_ref() {
        let mut candidate = candidate(StorageIntentReadSourceClass::DirectoryIndex);
        candidate.evidence_refs.ordering_evidence_ref = EMPTY_EVIDENCE_REF;

        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_ORDERING_EVIDENCE));
    }

    #[test]
    fn local_receipt_requires_tenant_isolation_candidate_ref() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.evidence_refs.tenant_isolation_ref = EMPTY_EVIDENCE_REF;
        let input = ReadServingDecisionInput {
            policy: policy(ReadFreshnessProfile::LatestLocal),
            candidate,
            evidence_cut_state: ReadServingEvidenceCutState::Bound,
            evidence_query_snapshot: snapshot(),
        };

        assert!(!read_serving_candidate_refs_have_required_families(input));
        assert!(read_serving_candidate_missing_required_ref_reasons(input)
            .intersects(ReadServingRejectionMask::MISSING_TENANT_ISOLATION_EVIDENCE));
        let decision = read_serving_decide(input);
        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_TENANT_ISOLATION_EVIDENCE));
    }

    #[test]
    fn remote_receipt_requires_policy_rollout_candidate_ref() {
        let mut candidate = candidate(StorageIntentReadSourceClass::RemotePlacementReceipt);
        candidate.evidence_refs.policy_rollout_ref = EMPTY_EVIDENCE_REF;
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_POLICY_ROLLOUT_EVIDENCE));
    }

    #[test]
    fn ram_authority_requires_service_objective_candidate_ref() {
        let mut candidate = candidate(StorageIntentReadSourceClass::AuthoritativeRam);
        candidate.evidence_refs.service_objective_ref = EMPTY_EVIDENCE_REF;
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_SERVICE_OBJECTIVE_EVIDENCE));
    }

    #[test]
    fn read_repair_requires_capacity_family_in_evidence_cut() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.read_repair_requested = true;
        candidate.action_class = StorageIntentActionClass::ReadTriggeredRepair;
        let families = [
            StorageIntentEvidenceKind::LocalIntentRecord,
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
            StorageIntentEvidenceKind::TemporalEvidence,
            StorageIntentEvidenceKind::MetadataNamespaceEvidence,
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
            StorageIntentEvidenceKind::DataShapeEvidence,
            StorageIntentEvidenceKind::PlacementReceipt,
            StorageIntentEvidenceKind::OrderingEvidence,
            StorageIntentEvidenceKind::MembershipEvidence,
            StorageIntentEvidenceKind::TransportPathEvidence,
            StorageIntentEvidenceKind::TrustDomainEvidence,
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
            StorageIntentEvidenceKind::RamAuthorityEvidence,
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
            StorageIntentEvidenceKind::PolicyRolloutEvidence,
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            StorageIntentEvidenceKind::ServiceObjectiveEvidence,
        ];
        let decision = decide_with_snapshot(
            policy(ReadFreshnessProfile::LatestLocal),
            candidate,
            snapshot_with_families(&families),
        );

        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::Unavailable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_FRESH_EVIDENCE_FAMILY));
    }

    #[test]
    fn read_repair_without_capacity_ref_is_reserve_required() {
        let mut candidate = candidate(StorageIntentReadSourceClass::LocalPlacementReceipt);
        candidate.read_repair_requested = true;
        candidate.action_class = StorageIntentActionClass::ReadTriggeredRepair;
        candidate.evidence_refs.capacity_admission_ref = EMPTY_EVIDENCE_REF;
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);

        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.read_repair, ReadRepairDisposition::ReserveRequired);
        assert!(!read_repair_may_retire_old_receipt(decision));
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::MISSING_CAPACITY_ADMISSION_EVIDENCE));
    }

    #[test]
    fn policy_rollout_required_for_remote_and_degraded_sources() {
        assert!(read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::RemotePlacementReceipt
        ));
        assert!(read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::DegradedReconstruction
        ));
        assert!(read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::GeoAsyncRemote
        ));
        assert!(read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::ArchiveRestore
        ));
        assert!(!read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::LocalPlacementReceipt
        ));
        assert!(!read_serving_requires_policy_rollout(
            StorageIntentReadSourceClass::AuthoritativeRam
        ));
    }

    #[test]
    fn tenant_isolation_required_for_receipt_backed_sources() {
        assert!(read_serving_requires_tenant_isolation(
            StorageIntentReadSourceClass::LocalPlacementReceipt
        ));
        assert!(read_serving_requires_tenant_isolation(
            StorageIntentReadSourceClass::RemotePlacementReceipt
        ));
        assert!(!read_serving_requires_tenant_isolation(
            StorageIntentReadSourceClass::AuthoritativeRam
        ));
    }

    #[test]
    fn service_objective_required_for_ram_and_pmem_authority() {
        assert!(read_serving_requires_service_objective(
            StorageIntentReadSourceClass::AuthoritativeRam
        ));
        assert!(read_serving_requires_service_objective(
            StorageIntentReadSourceClass::AuthoritativePmem
        ));
        assert!(read_serving_requires_service_objective(
            StorageIntentReadSourceClass::MetadataHotLookup
        ));
        assert!(read_serving_requires_service_objective(
            StorageIntentReadSourceClass::DirectoryIndex
        ));
        assert!(!read_serving_requires_service_objective(
            StorageIntentReadSourceClass::LocalPlacementReceipt
        ));
    }

    #[test]
    fn capacity_admission_required_when_read_repair_requested_and_allowed() {
        assert!(read_serving_requires_capacity_admission(true, true));
        assert!(!read_serving_requires_capacity_admission(false, true));
        assert!(!read_serving_requires_capacity_admission(true, false));
        assert!(!read_serving_requires_capacity_admission(false, false));
    }

    #[test]
    fn pmem_requires_media_capability_evidence() {
        let candidate = candidate(StorageIntentReadSourceClass::AuthoritativePmem);
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);

        let mut missing = candidate;
        missing.evidence_refs.media_capability_ref = EMPTY_EVIDENCE_REF;
        let refused = decide(policy(ReadFreshnessProfile::LatestLocal), missing);
        assert_eq!(refused.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            refused.refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );
        assert!(refused
            .rejected_reasons
            .intersects(ReadServingRejectionMask::PMEM_MISSING_MEDIA_CAPABILITY));
    }

    #[test]
    fn ram_and_pmem_keep_distinct_core_source_projection() {
        let ram = decide(
            policy(ReadFreshnessProfile::LatestLocal),
            candidate(StorageIntentReadSourceClass::AuthoritativeRam),
        );
        let pmem = decide(
            policy(ReadFreshnessProfile::LatestLocal),
            candidate(StorageIntentReadSourceClass::AuthoritativePmem),
        );

        assert_eq!(ram.core_source, CoreReadServingSourceClass::RamAuthority);
        assert_eq!(
            ram.freshness.source,
            CoreReadServingSourceClass::RamAuthority
        );
        assert_eq!(pmem.core_source, CoreReadServingSourceClass::PmemAuthority);
        assert_eq!(
            pmem.freshness.source,
            CoreReadServingSourceClass::PmemAuthority
        );
        assert_eq!(pmem.core_source.as_str(), "pmem-authority");
    }

    #[test]
    fn remote_read_refuses_without_trust_domain_evidence() {
        let mut candidate = candidate(StorageIntentReadSourceClass::RemotePlacementReceipt);
        candidate.evidence_refs.trust_domain_ref = EMPTY_EVIDENCE_REF;
        let decision = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::REMOTE_TRUST_OR_TRANSPORT_MISSING));
    }

    #[test]
    fn archive_restore_requires_archive_or_dr_profile() {
        let candidate = candidate(StorageIntentReadSourceClass::ArchiveRestore);
        let latest = decide(policy(ReadFreshnessProfile::LatestLocal), candidate);
        assert_eq!(latest.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            latest.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert!(latest
            .rejected_reasons
            .intersects(ReadServingRejectionMask::GEO_PROFILE_MISMATCH));

        let archive_policy = policy(ReadFreshnessProfile::ArchiveRestore);
        let archive = decide(archive_policy, candidate);
        assert_eq!(archive.decision_state, ReadServingDecisionState::Available);
        assert_eq!(archive.refusal, StorageIntentRefusalReason::None);
    }

    #[test]
    fn explicit_stale_read_permits_geo_within_lag_envelope() {
        let mut stale_policy = policy(ReadFreshnessProfile::ExplicitStaleRead);
        stale_policy.max_remote_lag_ms = 5000;
        let mut candidate = candidate(StorageIntentReadSourceClass::GeoAsyncRemote);
        candidate.geo_lag_ms = 3000;
        candidate.lag_known = true;

        let decision = decide(stale_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
        assert_eq!(decision.freshness.geo_lag_ms, 3000);
        assert!(decision.freshness.lag_known);
    }

    #[test]
    fn explicit_stale_read_refuses_geo_outside_lag_envelope() {
        let mut stale_policy = policy(ReadFreshnessProfile::ExplicitStaleRead);
        stale_policy.max_remote_lag_ms = 1000;
        let mut candidate = candidate(StorageIntentReadSourceClass::GeoAsyncRemote);
        candidate.geo_lag_ms = 3000;
        candidate.lag_known = true;

        let decision = decide(stale_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::GEO_LAG_OUTSIDE_RPO));
    }

    #[test]
    fn explicit_stale_read_refuses_geo_without_lag_known() {
        let mut stale_policy = policy(ReadFreshnessProfile::ExplicitStaleRead);
        stale_policy.max_remote_lag_ms = 5000;
        let mut candidate = candidate(StorageIntentReadSourceClass::GeoAsyncRemote);
        candidate.geo_lag_ms = 0;
        candidate.lag_known = false;

        let decision = decide(stale_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::GEO_LAG_OUTSIDE_RPO));
    }

    #[test]
    fn receipt_backed_degraded_reconstruction_requires_verified_evidence() {
        let mut degraded_policy = policy(ReadFreshnessProfile::LatestLocal);
        degraded_policy.degraded_read_policy = DegradedReadPolicy::ServeWhenVerified;
        let mut candidate = candidate(StorageIntentReadSourceClass::DegradedReconstruction);
        candidate.reconstruction_verified = true;
        candidate.redundancy_width = 3;
        candidate.missing_targets = 1;
        candidate.digest_verified = true;
        candidate.evidence_refs.recovery_degradation_ref =
            evidence_ref(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 17);
        candidate.evidence_refs.redundancy_ref =
            evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 18);

        let decision = decide(degraded_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Available);
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
        assert!(!decision.degraded_visible);
    }

    #[test]
    fn receipt_backed_degraded_reconstruction_refuses_without_recovery_evidence() {
        let mut degraded_policy = policy(ReadFreshnessProfile::LatestLocal);
        degraded_policy.degraded_read_policy = DegradedReadPolicy::ServeWhenVerified;
        let mut candidate = candidate(StorageIntentReadSourceClass::DegradedReconstruction);
        candidate.reconstruction_verified = true;
        candidate.redundancy_width = 3;
        candidate.missing_targets = 1;
        candidate.digest_verified = true;
        candidate.evidence_refs.recovery_degradation_ref = EMPTY_EVIDENCE_REF;
        candidate.evidence_refs.redundancy_ref =
            evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 18);

        let decision = decide(degraded_policy, candidate);
        assert_eq!(decision.decision_state, ReadServingDecisionState::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(decision
            .rejected_reasons
            .intersects(ReadServingRejectionMask::DIGEST_OR_SHAPE_MISMATCH));
    }

    #[test]
    fn degraded_reconstruction_exposes_visible_flag_when_policy_allows() {
        let mut expose_policy = policy(ReadFreshnessProfile::LatestLocal);
        expose_policy.degraded_read_policy = DegradedReadPolicy::ExposeDegradedVisible;
        let mut candidate = candidate(StorageIntentReadSourceClass::DegradedReconstruction);
        candidate.reconstruction_verified = true;
        candidate.redundancy_width = 3;
        candidate.missing_targets = 1;
        candidate.digest_verified = true;
        candidate.evidence_refs.recovery_degradation_ref =
            evidence_ref(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 17);
        candidate.evidence_refs.redundancy_ref =
            evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 18);

        let decision = decide(expose_policy, candidate);
        assert_eq!(
            decision.decision_state,
            ReadServingDecisionState::DegradedVisible
        );
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
        assert!(decision.degraded_visible);
    }
}
