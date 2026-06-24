// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Core storage-intent records and predicates.
//!
//! This crate is the narrow #841 type surface for
//! `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`. It gives write admission,
//! placement, transport, relocation, validation, and explanation code one
//! shared vocabulary for requested policy, earned receipts, evidence refs,
//! media roles, trust state, durability/RPO, capacity/admission, cost/wear,
//! and refusal shape.
//!
//! It does not activate runtime placement behavior or define a durable wire or
//! on-disk format. Callers that persist these records must define their own
//! versioned encoding and fail closed on unknown discriminants, non-zero
//! reserved fields, malformed widths, and unsupported versions.

use core::fmt;

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

/// Canonical identifier for this authority surface.
pub const STORAGE_INTENT_CORE_SPEC: &str = "tidefs-storage-intent-core-v1-issue-841";

/// Current syntactic record version for versioned authority envelopes.
pub const STORAGE_INTENT_RECORD_VERSION: u16 = 1;

/// Bounded evidence fan-in carried inline by a policy or receipt.
pub const STORAGE_INTENT_INLINE_EVIDENCE_REFS: usize = 20;

/// Bounded per-family freshness fan-in carried by an evidence query snapshot.
pub const STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES: usize = StorageIntentEvidenceKind::COUNT;

/// A compiled policy identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPolicyId(pub [u8; 16]);

impl StorageIntentPolicyId {
    /// All-zero sentinel for "no compiled policy".
    pub const ZERO: Self = Self([0_u8; 16]);

    /// Returns true when this is the sentinel value.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        bytes16_are_zero(self.0)
    }
}

/// Monotonic compiled-policy revision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPolicyRevision(pub u64);

/// Identity of one earned receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentReceiptId(pub [u8; 16]);

impl StorageIntentReceiptId {
    /// All-zero sentinel for "no receipt".
    pub const ZERO: Self = Self([0_u8; 16]);
}

/// Identity of an evidence artifact owned by another authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentEvidenceId(pub [u8; 32]);

impl StorageIntentEvidenceId {
    /// All-zero sentinel for "no evidence".
    pub const ZERO: Self = Self([0_u8; 32]);
}

/// Fixed-width policy, tenant, admin, security, and sharing-domain identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDomainId(pub [u8; 16]);

impl StorageIntentDomainId {
    /// All-zero sentinel for "domain not constrained".
    pub const ZERO: Self = Self([0_u8; 16]);

    /// Returns true when this is the sentinel value.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        bytes16_are_zero(self.0)
    }
}

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

const fn bytes32_are_zero(bytes: [u8; 32]) -> bool {
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

/// Versioned record envelope state used by persistence or transport codecs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentRecordHeader {
    /// Version of the containing record shape.
    pub version: u16,
    /// Reserved bytes; authority decoders must reject non-zero values.
    pub reserved: [u8; 6],
}

impl StorageIntentRecordHeader {
    /// Header for the current syntactic record family.
    pub const CURRENT: Self = Self {
        version: STORAGE_INTENT_RECORD_VERSION,
        reserved: [0_u8; 6],
    };

    /// Validate fail-closed authority envelope rules.
    pub const fn validate(self) -> Result<(), StorageIntentRecordError> {
        if self.version != STORAGE_INTENT_RECORD_VERSION {
            return Err(StorageIntentRecordError::UnsupportedVersion);
        }
        let mut index = 0;
        while index < self.reserved.len() {
            if self.reserved[index] != 0 {
                return Err(StorageIntentRecordError::NonZeroReserved);
            }
            index += 1;
        }
        Ok(())
    }
}

impl Default for StorageIntentRecordHeader {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Fail-closed syntactic validation errors for authority records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum StorageIntentRecordError {
    /// The record version is not supported by this decoder.
    UnsupportedVersion,
    /// Reserved fields were non-zero.
    NonZeroReserved,
    /// A discriminant was unknown for an authority path.
    UnknownDiscriminant,
    /// A fixed-width record was malformed.
    MalformedWidth,
}

impl fmt::Display for StorageIntentRecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "unsupported storage-intent record version",
            Self::NonZeroReserved => "non-zero storage-intent reserved field",
            Self::UnknownDiscriminant => "unknown storage-intent discriminant",
            Self::MalformedWidth => "malformed storage-intent fixed-width record",
        })
    }
}

/// Evidence source families referenced by storage-intent records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u16)]
pub enum StorageIntentEvidenceKind {
    /// Sentinel for absent evidence.
    #[default]
    Unknown = 0,
    /// Local intent-log or committed-root publication record.
    LocalIntentRecord = 1,
    /// Placement receipt for final or provisional object/shard locations.
    PlacementReceipt = 2,
    /// Transport path, session, route, or latency evidence.
    TransportPathEvidence = 3,
    /// Media capability, cost, or wear ledger.
    MediaCostWearLedger = 4,
    /// Scheduler admission, reserve, or budget record.
    SchedulerAdmissionRecord = 5,
    /// Relocation, defrag, rebake, repair, or source-retirement receipt.
    RelocationReceipt = 6,
    /// Validation or benchmark artifact.
    ValidationArtifact = 7,
    /// Operator-facing explanation projection.
    OperatorExplanationProjection = 8,
    /// Membership epoch, quorum, roster, fence, or split-brain evidence.
    MembershipEvidence = 9,
    /// Ordering, barrier, replay, dirty-epoch, or publication evidence.
    OrderingEvidence = 10,
    /// Security, tenant, admin-domain, key, authorization, or audit evidence.
    TrustDomainEvidence = 11,
    /// Capacity, reserve, pending-free, recovery-headroom, or admission evidence.
    CapacityAdmissionEvidence = 12,
    /// Degraded service, repair, rebuild, geo catch-up, or replacement evidence.
    RecoveryDegradationEvidence = 13,
    /// Policy rollout, downgrade, rollback, and convergence-frontier evidence.
    PolicyRolloutEvidence = 14,
    /// Tenant isolation, budget-owner, noisy-neighbor, or throttling evidence.
    TenantIsolationEvidence = 15,
    /// Prediction, contradiction, decay, hint, or observation evidence.
    PredictionEvidence = 16,
    /// Workload classification evidence.
    WorkloadEvidence = 17,
    /// Data shape, compression, checksum, dedup, encryption, or EC evidence.
    DataShapeEvidence = 18,
    /// Layout, allocator, free-run, zone, or fragmentation evidence.
    LayoutAllocatorEvidence = 19,
    /// Measurement attribution or comparator evidence.
    MeasurementAttributionEvidence = 20,
    /// Evidence query snapshot.
    EvidenceQuerySnapshot = 21,
    /// Retention, compaction, redaction, or proof-lifetime evidence.
    EvidenceRetentionEvidence = 22,
    /// Metadata, namespace, fsyncdir, inode, xattr, ACL, or small-object evidence.
    MetadataNamespaceEvidence = 23,
    /// Read freshness or source-selection evidence.
    ReadFreshnessEvidence = 24,
    /// Service objective, latency, throughput, tail, isolation, and cost evidence.
    ServiceObjectiveEvidence = 25,
    /// Non-authoritative what-if simulation evidence.
    PreflightSimulationEvidence = 26,
    /// Planner candidate, gate, score, and selected-frontier evidence.
    DecisionFrontierEvidence = 27,
    /// Action execution, idempotency, cutover, abort, and outcome evidence.
    ActionExecutionEvidence = 28,
    /// Caller-visible result/refusal projection evidence.
    ResultRefusalEvidence = 29,
    /// Timebase, freshness, expiry, skew, and lag evidence.
    TemporalEvidence = 30,
    /// Media capability, persistence-domain, flush/FUA, and role evidence.
    MediaCapabilityEvidence = 31,
    /// Comparator-equivalence and allowed-claim-scope evidence.
    ComparatorEvidence = 32,
    /// Claim-gate evidence bounding successor, performance, and durability claims.
    ClaimGateEvidence = 33,
    /// RAM authority class, loss, survival, and admission evidence.
    RamAuthorityEvidence = 34,
    /// Lifecycle, generation, retained-root, and reclaim-frontier evidence.
    LifecycleGenerationEvidence = 35,
}

impl StorageIntentEvidenceKind {
    /// Number of defined evidence kinds.
    pub const COUNT: usize = 36;

    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::LocalIntentRecord => "local-intent-record",
            Self::PlacementReceipt => "placement-receipt",
            Self::TransportPathEvidence => "transport-path-evidence",
            Self::MediaCostWearLedger => "media-cost-wear-ledger",
            Self::SchedulerAdmissionRecord => "scheduler-admission-record",
            Self::RelocationReceipt => "relocation-receipt",
            Self::ValidationArtifact => "validation-artifact",
            Self::OperatorExplanationProjection => "operator-explanation-projection",
            Self::MembershipEvidence => "membership-evidence",
            Self::OrderingEvidence => "ordering-evidence",
            Self::TrustDomainEvidence => "trust-domain-evidence",
            Self::CapacityAdmissionEvidence => "capacity-admission-evidence",
            Self::RecoveryDegradationEvidence => "recovery-degradation-evidence",
            Self::PolicyRolloutEvidence => "policy-rollout-evidence",
            Self::TenantIsolationEvidence => "tenant-isolation-evidence",
            Self::PredictionEvidence => "prediction-evidence",
            Self::WorkloadEvidence => "workload-evidence",
            Self::DataShapeEvidence => "data-shape-evidence",
            Self::LayoutAllocatorEvidence => "layout-allocator-evidence",
            Self::MeasurementAttributionEvidence => "measurement-attribution-evidence",
            Self::EvidenceQuerySnapshot => "evidence-query-snapshot",
            Self::EvidenceRetentionEvidence => "evidence-retention-evidence",
            Self::MetadataNamespaceEvidence => "metadata-namespace-evidence",
            Self::ReadFreshnessEvidence => "read-freshness-evidence",
            Self::ServiceObjectiveEvidence => "service-objective-evidence",
            Self::PreflightSimulationEvidence => "preflight-simulation-evidence",
            Self::DecisionFrontierEvidence => "decision-frontier-evidence",
            Self::ActionExecutionEvidence => "action-execution-evidence",
            Self::ResultRefusalEvidence => "result-refusal-evidence",
            Self::TemporalEvidence => "temporal-evidence",
            Self::MediaCapabilityEvidence => "media-capability-evidence",
            Self::ComparatorEvidence => "comparator-evidence",
            Self::ClaimGateEvidence => "claim-gate-evidence",
            Self::RamAuthorityEvidence => "ram-authority-evidence",
            Self::LifecycleGenerationEvidence => "lifecycle-generation-evidence",
        }
    }

    /// Encode to a stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u16 {
        self as u16
    }

    /// Decode from a stable discriminant. Unknown values fail closed.
    #[must_use]
    pub const fn from_discriminant(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::LocalIntentRecord),
            2 => Some(Self::PlacementReceipt),
            3 => Some(Self::TransportPathEvidence),
            4 => Some(Self::MediaCostWearLedger),
            5 => Some(Self::SchedulerAdmissionRecord),
            6 => Some(Self::RelocationReceipt),
            7 => Some(Self::ValidationArtifact),
            8 => Some(Self::OperatorExplanationProjection),
            9 => Some(Self::MembershipEvidence),
            10 => Some(Self::OrderingEvidence),
            11 => Some(Self::TrustDomainEvidence),
            12 => Some(Self::CapacityAdmissionEvidence),
            13 => Some(Self::RecoveryDegradationEvidence),
            14 => Some(Self::PolicyRolloutEvidence),
            15 => Some(Self::TenantIsolationEvidence),
            16 => Some(Self::PredictionEvidence),
            17 => Some(Self::WorkloadEvidence),
            18 => Some(Self::DataShapeEvidence),
            19 => Some(Self::LayoutAllocatorEvidence),
            20 => Some(Self::MeasurementAttributionEvidence),
            21 => Some(Self::EvidenceQuerySnapshot),
            22 => Some(Self::EvidenceRetentionEvidence),
            23 => Some(Self::MetadataNamespaceEvidence),
            24 => Some(Self::ReadFreshnessEvidence),
            25 => Some(Self::ServiceObjectiveEvidence),
            26 => Some(Self::PreflightSimulationEvidence),
            27 => Some(Self::DecisionFrontierEvidence),
            28 => Some(Self::ActionExecutionEvidence),
            29 => Some(Self::ResultRefusalEvidence),
            30 => Some(Self::TemporalEvidence),
            31 => Some(Self::MediaCapabilityEvidence),
            32 => Some(Self::ComparatorEvidence),
            33 => Some(Self::ClaimGateEvidence),
            34 => Some(Self::RamAuthorityEvidence),
            35 => Some(Self::LifecycleGenerationEvidence),
            _ => None,
        }
    }
}

impl fmt::Display for StorageIntentEvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reference to an authority-owned evidence artifact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentEvidenceRef {
    /// Evidence family.
    pub kind: StorageIntentEvidenceKind,
    /// Stable artifact identity in the owning evidence namespace.
    pub id: StorageIntentEvidenceId,
    /// Owning-source generation, epoch, sequence, or artifact revision.
    pub generation: u64,
    /// Version of the referenced artifact family.
    pub version: u16,
}

impl StorageIntentEvidenceRef {
    /// Construct a new evidence reference.
    #[must_use]
    pub const fn new(
        kind: StorageIntentEvidenceKind,
        id: StorageIntentEvidenceId,
        generation: u64,
        version: u16,
    ) -> Self {
        Self {
            kind,
            id,
            generation,
            version,
        }
    }

    /// Returns true when this ref names a concrete non-empty artifact.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        self.kind as u16 != StorageIntentEvidenceKind::Unknown as u16
            && !bytes32_are_zero(self.id.0)
    }
}

/// Bounded inline evidence reference set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentEvidenceRefs {
    len: u8,
    refs: [StorageIntentEvidenceRef; STORAGE_INTENT_INLINE_EVIDENCE_REFS],
}

impl StorageIntentEvidenceRefs {
    /// Empty evidence set.
    pub const EMPTY: Self = Self {
        len: 0,
        refs: [StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        }; STORAGE_INTENT_INLINE_EVIDENCE_REFS],
    };

    /// Number of inline evidence refs.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns true when the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Return the backing array and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[StorageIntentEvidenceRef; STORAGE_INTENT_INLINE_EVIDENCE_REFS],
        u8,
    ) {
        (&self.refs, self.len)
    }

    /// Append an evidence ref if capacity remains.
    pub fn push(
        &mut self,
        evidence_ref: StorageIntentEvidenceRef,
    ) -> Result<(), EvidenceRefsError> {
        if self.len as usize >= STORAGE_INTENT_INLINE_EVIDENCE_REFS {
            return Err(EvidenceRefsError::Full);
        }
        self.refs[self.len as usize] = evidence_ref;
        self.len += 1;
        Ok(())
    }

    /// Returns true if a ref of the given kind is present.
    #[must_use]
    pub const fn contains_kind(&self, kind: StorageIntentEvidenceKind) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if self.refs[index].kind as u16 == kind as u16 {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Returns true if this exact bound evidence ref is present in the cut.
    #[must_use]
    pub const fn contains_ref(&self, evidence_ref: StorageIntentEvidenceRef) -> bool {
        if !evidence_ref.is_bound() {
            return false;
        }

        let mut index = 0;
        while index < self.len as usize {
            if evidence_ref_equal(self.refs[index], evidence_ref) {
                return true;
            }
            index += 1;
        }
        false
    }
}

impl Default for StorageIntentEvidenceRefs {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Consumer of a bounded evidence query snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceConsumerClass {
    #[default]
    Planner = 0,
    Reconciler = 1,
    ReadPath = 2,
    ActionExecutor = 3,
    MeasurementAttribution = 4,
    OperatorExplanation = 5,
    PerformanceGate = 6,
    FaultGate = 7,
    ClaimGate = 8,
}

impl EvidenceConsumerClass {
    /// Returns true when this consumer may change authority, claims, or proof state.
    #[must_use]
    pub const fn requires_complete_authority_cut(self) -> bool {
        matches!(
            self,
            Self::Planner
                | Self::Reconciler
                | Self::ActionExecutor
                | Self::MeasurementAttribution
                | Self::PerformanceGate
                | Self::FaultGate
                | Self::ClaimGate
        )
    }
}

/// Request context that one evidence query snapshot answers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceQueryContextClass {
    #[default]
    Unknown = 0,
    RequestAdmission = 1,
    ActionAdmission = 2,
    ReadServing = 3,
    CacheOnlyRead = 4,
    Validation = 5,
    OperatorExplanation = 6,
    PerformanceRow = 7,
    FaultRow = 8,
    Claim = 9,
    PrefetchResidency = 10,
    MeasurementAttribution = 11,
}

/// Subject scope described by one evidence query snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceQuerySubjectScopeClass {
    #[default]
    Unknown = 0,
    Request = 1,
    Action = 2,
    ObjectRange = 3,
    Dataset = 4,
    Pool = 5,
    Domain = 6,
    Cluster = 7,
    ValidationArtifact = 8,
    Claim = 9,
}

/// Subject identity for one evidence query snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct EvidenceQuerySubjectScope {
    pub scope_class: EvidenceQuerySubjectScopeClass,
    pub object_scope: StorageIntentObjectScope,
    pub pool_id: StorageIntentDomainId,
    pub domain_id: StorageIntentDomainId,
    pub request_ref: StorageIntentEvidenceRef,
    pub action_ref: StorageIntentEvidenceRef,
    pub validation_ref: StorageIntentEvidenceRef,
}

/// Completeness verdict for one lawful evidence cut.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceCompletenessVerdict {
    #[default]
    UnknownEvidence = 0,
    CompleteForPurpose = 1,
    PartialAdmissible = 2,
    DegradedVisible = 3,
    Blocked = 4,
    Refused = 5,
    UnsafeVisible = 6,
}

impl EvidenceCompletenessVerdict {
    /// Returns true when the cut is exact enough to change authority or claims.
    #[must_use]
    pub const fn is_complete_for_authority(self) -> bool {
        matches!(self, Self::CompleteForPurpose)
    }

    /// Returns true when the cut may be shown but must not change authority.
    #[must_use]
    pub const fn is_visible_non_authority(self) -> bool {
        matches!(self, Self::PartialAdmissible | Self::DegradedVisible)
    }

    /// Returns true when the verdict must block all authority-changing use.
    #[must_use]
    pub const fn blocks_authority(self) -> bool {
        matches!(
            self,
            Self::UnknownEvidence | Self::Blocked | Self::Refused | Self::UnsafeVisible
        )
    }
}

/// Freshness state for one evidence family inside a query snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceFamilyFreshnessState {
    #[default]
    Unknown = 0,
    Fresh = 1,
    Missing = 2,
    Stale = 3,
    Contradictory = 4,
    Superseded = 5,
    Redacted = 6,
    Compacted = 7,
    Unavailable = 8,
    Refused = 9,
}

impl EvidenceFamilyFreshnessState {
    /// Returns true when this family can support authority-changing decisions.
    #[must_use]
    pub const fn is_fresh_for_authority(self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Returns true when this family cannot be silently consumed as authority.
    #[must_use]
    pub const fn blocks_authority(self) -> bool {
        matches!(
            self,
            Self::Unknown
                | Self::Missing
                | Self::Stale
                | Self::Contradictory
                | Self::Superseded
                | Self::Redacted
                | Self::Compacted
                | Self::Unavailable
                | Self::Refused
        )
    }
}

/// Retention class for exact or summarized evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceRetentionClass {
    /// Exact evidence is still needed for receipts, claims, audit, or cooldown.
    #[default]
    ExactRequired = 0,
    /// Evidence may be summarized after dependent receipts retire.
    Summarizable = 1,
    /// Evidence may be redacted after audit and claim windows close.
    Redactable = 2,
    /// Evidence may be purged after no proof dependency remains.
    Purgeable = 3,
}

/// Freshness and replay metadata for one evidence family in a query snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct EvidenceFamilyFreshness {
    pub kind: StorageIntentEvidenceKind,
    pub state: EvidenceFamilyFreshnessState,
    pub source_index_generation: u64,
    pub producer_generation: u64,
    pub freshness_frontier_ms: u64,
    pub allowed_staleness_ms: u64,
    pub evidence_ref: StorageIntentEvidenceRef,
}

impl EvidenceFamilyFreshness {
    pub const EMPTY: Self = Self {
        kind: StorageIntentEvidenceKind::Unknown,
        state: EvidenceFamilyFreshnessState::Unknown,
        source_index_generation: 0,
        producer_generation: 0,
        freshness_frontier_ms: 0,
        allowed_staleness_ms: 0,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };
}

impl Default for EvidenceFamilyFreshness {
    fn default() -> Self {
        Self::EMPTY
    }
}

#[cfg(feature = "serde")]
mod serde_families {
    use super::{EvidenceFamilyFreshness, STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES};

    pub fn serialize<S: serde::Serializer>(
        families: &[EvidenceFamilyFreshness; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::Serialize;
        families[..].serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[EvidenceFamilyFreshness; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES], D::Error>
    {
        struct ArrayVisitor;

        impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
            type Value = [EvidenceFamilyFreshness; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES];

            fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                f.write_str("a sequence of EvidenceFamilyFreshness")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr =
                    [EvidenceFamilyFreshness::EMPTY; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES];
                let mut idx: usize = 0;
                while let Some(elem) = seq.next_element::<EvidenceFamilyFreshness>()? {
                    if idx >= STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES {
                        return Err(serde::de::Error::invalid_length(
                            idx + 1,
                            &"at most 36 EvidenceFamilyFreshness elements",
                        ));
                    }
                    arr[idx] = elem;
                    idx += 1;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_seq(ArrayVisitor)
    }
}

/// Bounded freshness table for families used by one evidence query snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct EvidenceFamilyFreshnessSet {
    len: u8,
    #[cfg_attr(feature = "serde", serde(with = "serde_families"))]
    families: [EvidenceFamilyFreshness; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES],
}

impl EvidenceFamilyFreshnessSet {
    pub const EMPTY: Self = Self {
        len: 0,
        families: [EvidenceFamilyFreshness::EMPTY; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES],
    };

    /// Return the backing array and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[EvidenceFamilyFreshness; STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES],
        u8,
    ) {
        (&self.families, self.len)
    }

    /// Append a family freshness row if capacity remains.
    pub fn push(&mut self, family: EvidenceFamilyFreshness) -> Result<(), EvidenceRefsError> {
        if self.len as usize >= STORAGE_INTENT_EVIDENCE_QUERY_FAMILY_STATES {
            return Err(EvidenceRefsError::Full);
        }
        self.families[self.len as usize] = family;
        self.len += 1;
        Ok(())
    }

    /// Returns true when a family row exists for the given kind.
    #[must_use]
    pub const fn contains_kind(&self, kind: StorageIntentEvidenceKind) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if self.families[index].kind as u16 == kind as u16 {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Return the recorded state for one family, or `Unknown` when absent.
    #[must_use]
    pub const fn state_for_kind(
        &self,
        kind: StorageIntentEvidenceKind,
    ) -> EvidenceFamilyFreshnessState {
        let mut index = 0;
        while index < self.len as usize {
            if self.families[index].kind as u16 == kind as u16 {
                return self.families[index].state;
            }
            index += 1;
        }
        EvidenceFamilyFreshnessState::Unknown
    }

    /// Returns true when the family is explicitly fresh for authority use.
    #[must_use]
    pub const fn family_is_fresh_for_authority(&self, kind: StorageIntentEvidenceKind) -> bool {
        self.fresh_ref_for_kind(kind).is_some()
    }

    /// Return the single fresh replay anchor for one family, if it is unambiguous.
    #[must_use]
    pub const fn fresh_ref_for_kind(
        &self,
        kind: StorageIntentEvidenceKind,
    ) -> Option<StorageIntentEvidenceRef> {
        let mut index = 0;
        let mut found = false;
        let mut evidence_ref = StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        };

        while index < self.len as usize {
            let family = self.families[index];
            if family.kind as u16 == kind as u16 {
                if found {
                    return None;
                }
                if !family.state.is_fresh_for_authority()
                    || family.source_index_generation == 0
                    || family.producer_generation == 0
                    || family.freshness_frontier_ms == 0
                    || family.evidence_ref.kind as u16 != kind as u16
                    || !family.evidence_ref.is_bound()
                {
                    return None;
                }
                found = true;
                evidence_ref = family.evidence_ref;
            }
            index += 1;
        }

        if found {
            Some(evidence_ref)
        } else {
            None
        }
    }
}

impl Default for EvidenceFamilyFreshnessSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// One bounded, lawful evidence cut for a consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentEvidenceQuerySnapshot {
    pub snapshot_id: StorageIntentEvidenceId,
    pub query_id: StorageIntentEvidenceId,
    pub consumer: EvidenceConsumerClass,
    pub context: EvidenceQueryContextClass,
    pub subject: EvidenceQuerySubjectScope,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub temporal_frontier_ms: u64,
    pub freshness_frontier_ms: u64,
    pub allowed_staleness_ms: u64,
    pub source_catalog_ref: StorageIntentEvidenceRef,
    pub source_index_ref: StorageIntentEvidenceRef,
    pub source_index_generation: u64,
    pub producer_generation: u64,
    pub producer_watermark_ms: u64,
    pub compaction_generation: u64,
    pub redaction_generation: u64,
    pub included_refs: StorageIntentEvidenceRefs,
    pub family_freshness: EvidenceFamilyFreshnessSet,
    pub completeness: EvidenceCompletenessVerdict,
    pub retention: EvidenceRetentionClass,
    pub retention_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for StorageIntentEvidenceQuerySnapshot {
    fn default() -> Self {
        Self {
            snapshot_id: StorageIntentEvidenceId::ZERO,
            query_id: StorageIntentEvidenceId::ZERO,
            consumer: EvidenceConsumerClass::Planner,
            context: EvidenceQueryContextClass::Unknown,
            subject: EvidenceQuerySubjectScope::default(),
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            temporal_frontier_ms: 0,
            freshness_frontier_ms: 0,
            allowed_staleness_ms: 0,
            source_catalog_ref: StorageIntentEvidenceRef::default(),
            source_index_ref: StorageIntentEvidenceRef::default(),
            source_index_generation: 0,
            producer_generation: 0,
            producer_watermark_ms: 0,
            compaction_generation: 0,
            redaction_generation: 0,
            included_refs: StorageIntentEvidenceRefs::EMPTY,
            family_freshness: EvidenceFamilyFreshnessSet::EMPTY,
            completeness: EvidenceCompletenessVerdict::UnknownEvidence,
            retention: EvidenceRetentionClass::ExactRequired,
            retention_ref: StorageIntentEvidenceRef::default(),
            refusal: StorageIntentRefusalReason::None,
        }
    }
}

impl StorageIntentEvidenceQuerySnapshot {
    /// Returns true when the snapshot and query identities are explicit.
    #[must_use]
    pub const fn has_query_identity(self) -> bool {
        !bytes32_are_zero(self.snapshot_id.0) && !bytes32_are_zero(self.query_id.0)
    }

    /// Returns true when the snapshot is bound to one compiled policy revision.
    #[must_use]
    pub const fn has_policy_identity(self) -> bool {
        !self.policy_id.is_zero() && self.policy_revision.0 > 0
    }

    /// Returns true when the snapshot names the subject it answers for.
    #[must_use]
    pub const fn has_subject_scope(self) -> bool {
        match self.subject.scope_class {
            EvidenceQuerySubjectScopeClass::Unknown => false,
            EvidenceQuerySubjectScopeClass::Request => self.subject.request_ref.is_bound(),
            EvidenceQuerySubjectScopeClass::Action => self.subject.action_ref.is_bound(),
            EvidenceQuerySubjectScopeClass::ObjectRange => {
                !self.subject.object_scope.dataset_id.is_zero()
                    && !bytes32_are_zero(self.subject.object_scope.object_id.0)
            }
            EvidenceQuerySubjectScopeClass::Dataset => {
                !self.subject.object_scope.dataset_id.is_zero()
            }
            EvidenceQuerySubjectScopeClass::Pool => !self.subject.pool_id.is_zero(),
            EvidenceQuerySubjectScopeClass::Domain => !self.subject.domain_id.is_zero(),
            EvidenceQuerySubjectScopeClass::Cluster => self.source_catalog_ref.is_bound(),
            EvidenceQuerySubjectScopeClass::ValidationArtifact => {
                self.subject.validation_ref.is_bound()
            }
            EvidenceQuerySubjectScopeClass::Claim => {
                self.subject.request_ref.is_bound() || self.subject.validation_ref.is_bound()
            }
        }
    }

    /// Returns true when temporal and freshness frontiers are explicit.
    #[must_use]
    pub const fn has_frontiers(self) -> bool {
        self.temporal_frontier_ms > 0 && self.freshness_frontier_ms > 0
    }

    /// Returns true when source index replay metadata is explicit.
    #[must_use]
    pub const fn has_source_replay_anchor(self) -> bool {
        self.source_index_generation > 0
            && self.producer_generation > 0
            && self.source_catalog_ref.is_bound()
            && self.source_index_ref.is_bound()
    }

    /// Returns true when the snapshot cites an included evidence kind.
    #[must_use]
    pub const fn contains_evidence_kind(self, kind: StorageIntentEvidenceKind) -> bool {
        self.included_refs.contains_kind(kind)
    }

    /// Returns true when one included family is fresh enough for authority use.
    #[must_use]
    pub const fn contains_fresh_authority_family(self, kind: StorageIntentEvidenceKind) -> bool {
        match self.family_freshness.fresh_ref_for_kind(kind) {
            Some(evidence_ref) => self.included_refs.contains_ref(evidence_ref),
            None => false,
        }
    }

    /// Returns true when media capability evidence is present and fresh.
    #[must_use]
    pub const fn has_fresh_media_capability(self) -> bool {
        self.contains_fresh_authority_family(StorageIntentEvidenceKind::MediaCapabilityEvidence)
    }

    /// Returns true when service-objective evidence is present and fresh.
    #[must_use]
    pub const fn has_fresh_service_objective(self) -> bool {
        self.contains_fresh_authority_family(StorageIntentEvidenceKind::ServiceObjectiveEvidence)
    }

    /// Returns true when the cut carries the fresh families #967 needs.
    #[must_use]
    pub const fn has_fresh_prefetch_residency_basis(self) -> bool {
        matches!(self.context, EvidenceQueryContextClass::PrefetchResidency)
            && self.has_fresh_service_objective()
            && self.contains_fresh_authority_family(StorageIntentEvidenceKind::WorkloadEvidence)
            && self.has_fresh_media_capability()
            && self
                .contains_fresh_authority_family(StorageIntentEvidenceKind::ReadFreshnessEvidence)
            && self.contains_fresh_authority_family(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            )
            && self.contains_fresh_authority_family(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            )
            && self
                .contains_fresh_authority_family(StorageIntentEvidenceKind::TenantIsolationEvidence)
            && self.contains_fresh_authority_family(StorageIntentEvidenceKind::TrustDomainEvidence)
            && self
                .contains_fresh_authority_family(StorageIntentEvidenceKind::TransportPathEvidence)
            && self.contains_fresh_authority_family(StorageIntentEvidenceKind::TemporalEvidence)
            && self.contains_fresh_authority_family(StorageIntentEvidenceKind::MediaCostWearLedger)
    }

    /// Returns true when a prefetch/residency result can train or claim upward.
    #[must_use]
    pub const fn authorizes_prefetch_residency_feedback(self) -> bool {
        matches!(
            self.consumer,
            EvidenceConsumerClass::MeasurementAttribution
                | EvidenceConsumerClass::PerformanceGate
                | EvidenceConsumerClass::ClaimGate
        ) && self.is_authority_admissible()
            && self.has_fresh_prefetch_residency_basis()
            && self
                .contains_fresh_authority_family(StorageIntentEvidenceKind::ActionExecutionEvidence)
            && self.contains_fresh_authority_family(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
            )
            && self.contains_fresh_authority_family(
                StorageIntentEvidenceKind::EvidenceRetentionEvidence,
            )
    }

    /// Returns true when the snapshot may be shown for cache-only or diagnostics use.
    #[must_use]
    pub const fn allows_non_authority_visibility(self) -> bool {
        self.has_query_identity()
            && self.has_policy_identity()
            && self.has_subject_scope()
            && self.has_frontiers()
            && self.has_source_replay_anchor()
            && self.refusal as u16 == StorageIntentRefusalReason::None as u16
            && self.completeness.is_visible_non_authority()
            && matches!(
                self.consumer,
                EvidenceConsumerClass::ReadPath
                    | EvidenceConsumerClass::OperatorExplanation
                    | EvidenceConsumerClass::PerformanceGate
                    | EvidenceConsumerClass::FaultGate
            )
            && matches!(
                self.context,
                EvidenceQueryContextClass::CacheOnlyRead
                    | EvidenceQueryContextClass::ReadServing
                    | EvidenceQueryContextClass::OperatorExplanation
                    | EvidenceQueryContextClass::Validation
                    | EvidenceQueryContextClass::PrefetchResidency
            )
    }

    /// Typed fail-closed admission result for authority-changing consumers.
    #[must_use]
    pub const fn authority_refusal(self) -> StorageIntentRefusalReason {
        if self.refusal as u16 != StorageIntentRefusalReason::None as u16 {
            return self.refusal;
        }
        if !self.has_query_identity()
            || !self.has_policy_identity()
            || !self.has_subject_scope()
            || !self.has_frontiers()
            || !self.has_source_replay_anchor()
        {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
        if self.consumer.requires_complete_authority_cut()
            && !self.completeness.is_complete_for_authority()
        {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
        if self.completeness.blocks_authority() {
            return StorageIntentRefusalReason::EvidenceNotUsable;
        }
        StorageIntentRefusalReason::None
    }

    /// Returns true when the snapshot may authorize authority-changing work.
    #[must_use]
    pub const fn is_authority_admissible(self) -> bool {
        self.authority_refusal() as u16 == StorageIntentRefusalReason::None as u16
    }

    /// Returns true when the snapshot can authorize authority use of one family.
    #[must_use]
    pub const fn authorizes_fresh_evidence_kind(self, kind: StorageIntentEvidenceKind) -> bool {
        self.is_authority_admissible() && self.contains_fresh_authority_family(kind)
    }
}

/// Bounded measurement metric entries carried inline by attribution evidence.
pub const STORAGE_INTENT_MEASUREMENT_METRIC_ENTRIES: usize = 16;

/// Causal verdict for a measured outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentMeasurementAttributionVerdict {
    #[default]
    Unknown = 0,
    Attributable = 1,
    PartiallyAttributableWithBounds = 2,
    Confounded = 3,
    InsufficientSample = 4,
    Stale = 5,
    Contradicted = 6,
    ShadowOnly = 7,
    Refused = 8,
}

impl StorageIntentMeasurementAttributionVerdict {
    /// Returns true when this verdict may support authority-changing uses.
    #[must_use]
    pub const fn may_support_authority(self) -> bool {
        matches!(
            self,
            Self::Attributable | Self::PartiallyAttributableWithBounds
        )
    }

    /// Returns true when this verdict is diagnostic only.
    #[must_use]
    pub const fn blocks_authority(self) -> bool {
        matches!(
            self,
            Self::Unknown
                | Self::Confounded
                | Self::InsufficientSample
                | Self::Stale
                | Self::Contradicted
                | Self::ShadowOnly
                | Self::Refused
        )
    }
}

/// Baseline or counterfactual family for a measured outcome.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentMeasurementBaselineClass {
    #[default]
    Unknown = 0,
    PriorAdmittedVariant = 1,
    ShadowTarget = 2,
    IncumbentPeerComparator = 3,
    NoopCounterfactual = 4,
    SamePolicyCohort = 5,
    NoValidBaselineRefused = 6,
}

/// Measurement dimension retained by attribution evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentMeasurementMetricDimension {
    #[default]
    Latency = 0,
    TailLatency = 1,
    Throughput = 2,
    Iops = 3,
    CacheHitRatio = 4,
    ReadAmplification = 5,
    WriteAmplification = 6,
    MediaWriteBytes = 7,
    WearCost = 8,
    NetworkEgressBytes = 9,
    RestoreBytes = 10,
    CostMicrounits = 11,
    RpoLag = 12,
    CpuTime = 13,
    ForegroundHarm = 14,
    PaybackWindow = 15,
}

/// Unit attached to a measured metric.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentMeasurementMetricUnit {
    #[default]
    UnitlessPpm = 0,
    Microseconds = 1,
    Milliseconds = 2,
    Bytes = 3,
    BytesPerSecond = 4,
    Iops = 5,
    CostMicrounits = 6,
    Count = 7,
}

/// State of a measured metric entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentMeasurementMetricState {
    #[default]
    Unknown = 0,
    Known = 1,
    Bounded = 2,
    Censored = 3,
    Dropped = 4,
    Refused = 5,
}

impl StorageIntentMeasurementMetricState {
    /// Returns true when this metric may support an attribution verdict.
    #[must_use]
    pub const fn is_usable_for_attribution(self) -> bool {
        matches!(self, Self::Known | Self::Bounded)
    }
}

/// One measured metric entry with unit, uncertainty, and source evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementMetricEntry {
    pub dimension: StorageIntentMeasurementMetricDimension,
    pub state: StorageIntentMeasurementMetricState,
    pub unit: StorageIntentMeasurementMetricUnit,
    pub value: i64,
    pub variance_ppm: u32,
    pub evidence_ref: StorageIntentEvidenceRef,
}

impl StorageIntentMeasurementMetricEntry {
    pub const EMPTY: Self = Self {
        dimension: StorageIntentMeasurementMetricDimension::Latency,
        state: StorageIntentMeasurementMetricState::Unknown,
        unit: StorageIntentMeasurementMetricUnit::UnitlessPpm,
        value: 0,
        variance_ppm: 0,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };

    /// Returns true when this metric is source-backed and usable.
    #[must_use]
    pub const fn is_usable_for_attribution(self) -> bool {
        self.state.is_usable_for_attribution() && evidence_ref_has_id(self.evidence_ref)
    }
}

/// Bounded vector of raw metrics, normalized KPIs, and deltas.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementMetricSet {
    len: u8,
    entries: [StorageIntentMeasurementMetricEntry; STORAGE_INTENT_MEASUREMENT_METRIC_ENTRIES],
}

impl StorageIntentMeasurementMetricSet {
    pub const EMPTY: Self = Self {
        len: 0,
        entries: [StorageIntentMeasurementMetricEntry::EMPTY;
            STORAGE_INTENT_MEASUREMENT_METRIC_ENTRIES],
    };

    /// Number of retained metric entries.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Append a metric entry if capacity remains.
    pub fn push(
        &mut self,
        entry: StorageIntentMeasurementMetricEntry,
    ) -> Result<(), EvidenceRefsError> {
        if self.len as usize >= STORAGE_INTENT_MEASUREMENT_METRIC_ENTRIES {
            return Err(EvidenceRefsError::Full);
        }
        self.entries[self.len as usize] = entry;
        self.len += 1;
        Ok(())
    }

    /// Returns true when any usable metric is retained.
    #[must_use]
    pub const fn has_usable_metric(self) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if self.entries[index].is_usable_for_attribution() {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Returns true when a usable metric dimension is retained.
    #[must_use]
    pub const fn has_usable_dimension(
        self,
        dimension: StorageIntentMeasurementMetricDimension,
    ) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            let entry = self.entries[index];
            if entry.dimension as u8 == dimension as u8 && entry.is_usable_for_attribution() {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Returns true when cost, wear, or network deltas are represented.
    #[must_use]
    pub const fn has_cost_wear_or_network_delta(self) -> bool {
        self.has_usable_dimension(StorageIntentMeasurementMetricDimension::MediaWriteBytes)
            || self.has_usable_dimension(StorageIntentMeasurementMetricDimension::WearCost)
            || self
                .has_usable_dimension(StorageIntentMeasurementMetricDimension::NetworkEgressBytes)
            || self.has_usable_dimension(StorageIntentMeasurementMetricDimension::RestoreBytes)
            || self.has_usable_dimension(StorageIntentMeasurementMetricDimension::CostMicrounits)
    }

    /// Returns true when foreground harm is explicitly bounded.
    #[must_use]
    pub const fn has_foreground_harm_delta(self) -> bool {
        self.has_usable_dimension(StorageIntentMeasurementMetricDimension::ForegroundHarm)
    }

    /// Returns true when payback window evidence is explicitly represented.
    #[must_use]
    pub const fn has_payback_window(self) -> bool {
        self.has_usable_dimension(StorageIntentMeasurementMetricDimension::PaybackWindow)
    }
}

/// Allowed use mask for a measurement-attribution verdict.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementAttributionUseMask(pub u64);

impl StorageIntentMeasurementAttributionUseMask {
    pub const EMPTY: Self = Self(0);
    pub const DIAGNOSE: Self = Self(1 << 0);
    pub const OPEN_INVESTIGATION: Self = Self(1 << 1);
    pub const FORCE_CONSERVATIVE_COOLDOWN: Self = Self(1 << 2);
    pub const LOWER_CONFIDENCE: Self = Self(1 << 3);
    pub const TRAIN_CONFIDENCE_UPWARD: Self = Self(1 << 4);
    pub const CLOSE_PAYBACK: Self = Self(1 << 5);
    pub const ADMIT_AUTHORITY_MOVEMENT: Self = Self(1 << 6);
    pub const RETIRE_SOURCE_RECEIPTS: Self = Self(1 << 7);
    pub const SPEND_EXTRA_FLASH_MOVEMENT_BUDGET: Self = Self(1 << 8);
    pub const SUPPORT_PERFORMANCE_EVIDENCE: Self = Self(1 << 9);
    pub const SUPPORT_FAULT_EVIDENCE: Self = Self(1 << 10);
    pub const SUPPORT_OPERATOR_EXPLANATION: Self = Self(1 << 11);
    pub const SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM: Self = Self(1 << 12);

    pub const NON_AUTHORITY_SAFE: Self = Self(
        Self::DIAGNOSE.0
            | Self::OPEN_INVESTIGATION.0
            | Self::FORCE_CONSERVATIVE_COOLDOWN.0
            | Self::LOWER_CONFIDENCE.0
            | Self::SUPPORT_OPERATOR_EXPLANATION.0,
    );

    pub const AUTHORITY_CHANGING: Self = Self(
        Self::TRAIN_CONFIDENCE_UPWARD.0
            | Self::CLOSE_PAYBACK.0
            | Self::ADMIT_AUTHORITY_MOVEMENT.0
            | Self::RETIRE_SOURCE_RECEIPTS.0
            | Self::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET.0
            | Self::SUPPORT_PERFORMANCE_EVIDENCE.0
            | Self::SUPPORT_FAULT_EVIDENCE.0
            | Self::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM.0,
    );

    pub const PAYBACK_OR_MOVEMENT: Self = Self(
        Self::CLOSE_PAYBACK.0
            | Self::ADMIT_AUTHORITY_MOVEMENT.0
            | Self::RETIRE_SOURCE_RECEIPTS.0
            | Self::SPEND_EXTRA_FLASH_MOVEMENT_BUDGET.0,
    );

    /// Returns true when the mask is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Add another allowed-use mask.
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

    /// Strip all bits from `other`.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// Scope-transfer mask for attribution reuse beyond the exact measured scope.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementTransferScopeMask(pub u64);

impl StorageIntentMeasurementTransferScopeMask {
    pub const EMPTY: Self = Self(0);
    pub const SAME_POLICY_REVISION: Self = Self(1 << 0);
    pub const SAME_TENANT: Self = Self(1 << 1);
    pub const SAME_DATASET: Self = Self(1 << 2);
    pub const SAME_WORKLOAD_ENVELOPE: Self = Self(1 << 3);
    pub const SAME_ENVIRONMENT_PROFILE: Self = Self(1 << 4);
    pub const SAME_MEDIA_CLASS: Self = Self(1 << 5);
    pub const SAME_TRANSPORT_PATH: Self = Self(1 << 6);
    pub const SAME_SERVICE_OBJECTIVE: Self = Self(1 << 7);
    pub const SAME_COST_WEAR_BASIS: Self = Self(1 << 8);
    pub const EXPLICIT_TRANSFER_RULE: Self = Self(1 << 9);
    pub const ISOLATION_ELIGIBLE: Self = Self(1 << 10);
    pub const TRUST_DOMAIN_ELIGIBLE: Self = Self(1 << 11);
    pub const DOMAIN_ELIGIBLE: Self = Self(1 << 12);

    pub const EXACT_AUTHORITY_SCOPE: Self = Self(
        Self::SAME_POLICY_REVISION.0
            | Self::SAME_TENANT.0
            | Self::SAME_DATASET.0
            | Self::SAME_WORKLOAD_ENVELOPE.0
            | Self::SAME_ENVIRONMENT_PROFILE.0
            | Self::SAME_MEDIA_CLASS.0
            | Self::SAME_TRANSPORT_PATH.0
            | Self::SAME_SERVICE_OBJECTIVE.0
            | Self::SAME_COST_WEAR_BASIS.0,
    );

    pub const CROSS_SCOPE_ELIGIBILITY: Self = Self(
        Self::EXPLICIT_TRANSFER_RULE.0
            | Self::ISOLATION_ELIGIBLE.0
            | Self::TRUST_DOMAIN_ELIGIBLE.0
            | Self::DOMAIN_ELIGIBLE.0,
    );

    /// Add another scope mask.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all bits from `other` are present.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Sample window, warmup, censor/drop, variance, and source-window evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementSampleWindow {
    pub temporal_window_ref: StorageIntentEvidenceRef,
    pub warmup_ms: u64,
    pub sample_window_ms: u64,
    pub sample_mass: u64,
    pub censored_sample_count: u64,
    pub dropped_sample_count: u64,
    pub variance_ppm: u32,
    pub confidence_bound_ppm: u32,
    pub censor_drop_policy_ref: StorageIntentEvidenceRef,
}

impl StorageIntentMeasurementSampleWindow {
    /// Returns true when warmup, sample mass, duration, and censor policy are explicit.
    #[must_use]
    pub const fn has_sample_boundary(self) -> bool {
        evidence_ref_has_id(self.temporal_window_ref)
            && self.sample_window_ms > 0
            && self.sample_mass > 0
            && self.confidence_bound_ppm > 0
            && evidence_ref_has_id(self.censor_drop_policy_ref)
    }
}

/// Baseline, comparator, and counterfactual lineage for attribution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementComparatorLineage {
    pub baseline_class: StorageIntentMeasurementBaselineClass,
    pub baseline_ref: StorageIntentEvidenceRef,
    pub comparator_ref: StorageIntentEvidenceRef,
    pub counterfactual_ref: StorageIntentEvidenceRef,
    pub prior_admitted_variant_ref: StorageIntentEvidenceRef,
    pub shadow_target_ref: StorageIntentEvidenceRef,
    pub baseline_generation: u64,
    pub no_valid_baseline_refusal: StorageIntentRefusalReason,
}

impl StorageIntentMeasurementComparatorLineage {
    /// Returns true when the record explicitly refuses a usable baseline.
    #[must_use]
    pub const fn has_no_valid_baseline_refusal(self) -> bool {
        matches!(
            self.baseline_class,
            StorageIntentMeasurementBaselineClass::NoValidBaselineRefused
        ) && self.no_valid_baseline_refusal as u16 != StorageIntentRefusalReason::None as u16
    }

    /// Returns true when authority use has an inspectable baseline.
    #[must_use]
    pub const fn has_authority_baseline(self) -> bool {
        if self.has_no_valid_baseline_refusal()
            || matches!(
                self.baseline_class,
                StorageIntentMeasurementBaselineClass::Unknown
            )
            || self.no_valid_baseline_refusal as u16 != StorageIntentRefusalReason::None as u16
            || self.baseline_generation == 0
            || !evidence_ref_has_id(self.baseline_ref)
        {
            return false;
        }
        if matches!(
            self.baseline_class,
            StorageIntentMeasurementBaselineClass::IncumbentPeerComparator
        ) && (self.comparator_ref.kind as u16
            != StorageIntentEvidenceKind::ComparatorEvidence as u16
            || !evidence_ref_has_id(self.comparator_ref))
        {
            return false;
        }
        true
    }
}

/// Storage-intent measurement-attribution evidence projection owned by #912.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMeasurementAttributionEvidence {
    pub evidence_ref: StorageIntentEvidenceRef,
    pub measurement_id: StorageIntentEvidenceId,
    pub tenant_id: StorageIntentDomainId,
    pub budget_owner_id: StorageIntentDomainId,
    pub subject: EvidenceQuerySubjectScope,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub observation_generation: u64,
    pub producer_component_ref: StorageIntentEvidenceRef,
    pub producer_version: u64,
    pub workload_envelope_ref: StorageIntentEvidenceRef,
    pub workload_scope_ref: StorageIntentEvidenceRef,
    pub environment_profile_ref: StorageIntentEvidenceRef,
    pub noise_policy_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub sample_window: StorageIntentMeasurementSampleWindow,
    pub measurement_source_refs: StorageIntentEvidenceRefs,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    pub action_execution_ref: StorageIntentEvidenceRef,
    pub admission_ref: StorageIntentEvidenceRef,
    pub scheduler_ref: StorageIntentEvidenceRef,
    pub isolation_ref: StorageIntentEvidenceRef,
    pub capacity_ref: StorageIntentEvidenceRef,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub transport_path_ref: StorageIntentEvidenceRef,
    pub recovery_ref: StorageIntentEvidenceRef,
    pub rollout_ref: StorageIntentEvidenceRef,
    pub layout_ref: StorageIntentEvidenceRef,
    pub lifecycle_ref: StorageIntentEvidenceRef,
    pub shaping_refs: StorageIntentEvidenceRefs,
    pub comparator: StorageIntentMeasurementComparatorLineage,
    pub metrics: StorageIntentMeasurementMetricSet,
    pub verdict: StorageIntentMeasurementAttributionVerdict,
    pub bounded_uncertainty_ppm: u32,
    pub allowed_uses: StorageIntentMeasurementAttributionUseMask,
    pub allowed_use_ref: StorageIntentEvidenceRef,
    pub transfer_scope: StorageIntentMeasurementTransferScopeMask,
    pub transfer_scope_ref: StorageIntentEvidenceRef,
    pub attribution_verdict_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl StorageIntentMeasurementAttributionEvidence {
    /// Returns true when identity, policy, subject, and producer are bound.
    #[must_use]
    pub const fn has_measurement_identity(self) -> bool {
        self.evidence_ref.kind as u16
            == StorageIntentEvidenceKind::MeasurementAttributionEvidence as u16
            && evidence_ref_has_id(self.evidence_ref)
            && !bytes32_are_zero(self.measurement_id.0)
            && !self.policy_id.is_zero()
            && self.policy_revision.0 > 0
            && self.observation_generation > 0
            && !self.tenant_id.is_zero()
            && !self.budget_owner_id.is_zero()
            && self.producer_version > 0
            && evidence_ref_has_id(self.producer_component_ref)
            && measurement_subject_scope_is_bound(self.subject)
    }

    /// Returns true when workload, environment, noise, sample, and sources are bound.
    #[must_use]
    pub const fn has_measurement_basis(self) -> bool {
        evidence_ref_has_id(self.workload_envelope_ref)
            && evidence_ref_has_id(self.workload_scope_ref)
            && evidence_ref_has_id(self.environment_profile_ref)
            && evidence_ref_has_id(self.noise_policy_ref)
            && evidence_ref_has_id(self.service_objective_ref)
            && self.sample_window.has_sample_boundary()
            && !self.measurement_source_refs.is_empty()
            && self.metrics.has_usable_metric()
    }

    /// Returns true when the decision, executed action, query cut, and retention are bound.
    #[must_use]
    pub const fn has_authority_lineage(self) -> bool {
        self.evidence_query_snapshot_ref.kind as u16
            == StorageIntentEvidenceKind::EvidenceQuerySnapshot as u16
            && evidence_ref_has_id(self.evidence_query_snapshot_ref)
            && self.decision_frontier_ref.kind as u16
                == StorageIntentEvidenceKind::DecisionFrontierEvidence as u16
            && evidence_ref_has_id(self.decision_frontier_ref)
            && self.action_execution_ref.kind as u16
                == StorageIntentEvidenceKind::ActionExecutionEvidence as u16
            && evidence_ref_has_id(self.action_execution_ref)
            && self.retention_ref.kind as u16
                == StorageIntentEvidenceKind::EvidenceRetentionEvidence as u16
            && evidence_ref_has_id(self.retention_ref)
    }

    /// Returns true when non-decision shaping evidence is explicit.
    #[must_use]
    pub const fn has_shaping_evidence(self) -> bool {
        evidence_ref_has_id(self.admission_ref)
            && evidence_ref_has_id(self.scheduler_ref)
            && evidence_ref_has_id(self.isolation_ref)
            && evidence_ref_has_id(self.capacity_ref)
            && evidence_ref_has_id(self.source_media_ref)
            && evidence_ref_has_id(self.target_media_ref)
            && evidence_ref_has_id(self.trust_domain_ref)
            && evidence_ref_has_id(self.transport_path_ref)
            && evidence_ref_has_id(self.recovery_ref)
            && evidence_ref_has_id(self.rollout_ref)
            && evidence_ref_has_id(self.layout_ref)
            && evidence_ref_has_id(self.lifecycle_ref)
    }

    /// Returns true when the verdict and allowed-use artifact are explicit.
    #[must_use]
    pub const fn has_verdict_boundary(self) -> bool {
        evidence_ref_has_id(self.allowed_use_ref)
            && evidence_ref_has_id(self.attribution_verdict_ref)
            && self.refusal as u16 == StorageIntentRefusalReason::None as u16
            && (!matches!(
                self.verdict,
                StorageIntentMeasurementAttributionVerdict::PartiallyAttributableWithBounds
            ) || self.bounded_uncertainty_ppm > 0)
    }

    /// Returns true when any authority-changing use is requested or allowed.
    #[must_use]
    pub const fn carries_authority_changing_use(self) -> bool {
        self.allowed_uses
            .intersects(StorageIntentMeasurementAttributionUseMask::AUTHORITY_CHANGING)
    }

    /// Returns true when diagnostic-only verdicts do not carry authority permissions.
    #[must_use]
    pub const fn hard_law_is_respected(self) -> bool {
        !self.verdict.blocks_authority() || !self.carries_authority_changing_use()
    }

    /// Returns true when the attribution can transfer to the requested authority scope.
    #[must_use]
    pub const fn authority_transfer_is_allowed(self) -> bool {
        self.transfer_scope
            .contains_all(StorageIntentMeasurementTransferScopeMask::EXACT_AUTHORITY_SCOPE)
            || (self
                .transfer_scope
                .contains_all(StorageIntentMeasurementTransferScopeMask::CROSS_SCOPE_ELIGIBILITY)
                && evidence_ref_has_id(self.transfer_scope_ref))
    }

    /// Returns true when metrics include the deltas needed for payback and movement.
    #[must_use]
    pub const fn metrics_support_payback_or_movement(self) -> bool {
        self.metrics.has_payback_window()
            && self.metrics.has_cost_wear_or_network_delta()
            && self.metrics.has_foreground_harm_delta()
    }

    /// Returns true when this record can support the requested use mask.
    #[must_use]
    pub const fn authorizes_use(
        self,
        requested: StorageIntentMeasurementAttributionUseMask,
    ) -> bool {
        if requested.is_empty()
            || !self.allowed_uses.contains_all(requested)
            || !self.has_measurement_identity()
            || !self.has_measurement_basis()
            || !self.has_verdict_boundary()
            || !self.hard_law_is_respected()
        {
            return false;
        }
        if !requested.intersects(StorageIntentMeasurementAttributionUseMask::AUTHORITY_CHANGING) {
            return true;
        }
        if !self.verdict.may_support_authority()
            || !self.has_authority_lineage()
            || !self.has_shaping_evidence()
            || !self.comparator.has_authority_baseline()
            || !self.authority_transfer_is_allowed()
        {
            return false;
        }
        if requested.intersects(StorageIntentMeasurementAttributionUseMask::PAYBACK_OR_MOVEMENT)
            && !self.metrics_support_payback_or_movement()
        {
            return false;
        }
        true
    }
}

/// Predicate wrapper for callers that want a typed refusal result.
#[must_use]
pub const fn measurement_attribution_authorizes_use(
    evidence: StorageIntentMeasurementAttributionEvidence,
    requested: StorageIntentMeasurementAttributionUseMask,
) -> ReceiptPredicateResult {
    if evidence.authorizes_use(requested) {
        ReceiptPredicateResult::SATISFIED
    } else if evidence.refusal as u16 != StorageIntentRefusalReason::None as u16 {
        ReceiptPredicateResult::refused(evidence.refusal)
    } else {
        ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable)
    }
}

const fn measurement_subject_scope_is_bound(subject: EvidenceQuerySubjectScope) -> bool {
    match subject.scope_class {
        EvidenceQuerySubjectScopeClass::Unknown => false,
        EvidenceQuerySubjectScopeClass::Request => evidence_ref_has_id(subject.request_ref),
        EvidenceQuerySubjectScopeClass::Action => evidence_ref_has_id(subject.action_ref),
        EvidenceQuerySubjectScopeClass::ObjectRange => {
            !subject.object_scope.dataset_id.is_zero()
                && !bytes32_are_zero(subject.object_scope.object_id.0)
                && subject.object_scope.range_len > 0
        }
        EvidenceQuerySubjectScopeClass::Dataset => !subject.object_scope.dataset_id.is_zero(),
        EvidenceQuerySubjectScopeClass::Pool => !subject.pool_id.is_zero(),
        EvidenceQuerySubjectScopeClass::Domain => !subject.domain_id.is_zero(),
        EvidenceQuerySubjectScopeClass::Cluster => false,
        EvidenceQuerySubjectScopeClass::ValidationArtifact => {
            evidence_ref_has_id(subject.validation_ref)
        }
        EvidenceQuerySubjectScopeClass::Claim => {
            evidence_ref_has_id(subject.request_ref) || evidence_ref_has_id(subject.validation_ref)
        }
    }
}

/// Bounded candidate records retained by one decision frontier.
pub const STORAGE_INTENT_DECISION_FRONTIER_CANDIDATES: usize = 16;

/// Bounded hard-gate records retained by one decision frontier.
pub const STORAGE_INTENT_DECISION_HARD_GATES: usize = 20;

/// Bounded score entries retained by one decision frontier.
pub const STORAGE_INTENT_DECISION_SCORE_ENTRIES: usize = StorageIntentDecisionScoreDimension::COUNT;

#[allow(clippy::cast_lossless)]
const fn decision_frontier_len(len: u8) -> usize {
    len as usize
}

/// Authority mode for one decision frontier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionAuthorityMode {
    #[default]
    Unknown = 0,
    Live = 1,
    Shadow = 2,
    Trial = 3,
    Preflight = 4,
    Simulated = 5,
    Replay = 6,
    Refused = 7,
}

impl StorageIntentDecisionAuthorityMode {
    /// Returns true when this frontier may admit authority-changing work.
    #[must_use]
    pub const fn may_admit_authority_change(self) -> bool {
        matches!(self, Self::Live)
    }
}

/// Candidate class captured before scoring.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionCandidateClass {
    #[default]
    Unknown = 0,
    AcknowledgmentPlan = 1,
    PlacementPlan = 2,
    ReadServingPlan = 3,
    SchedulingPlan = 4,
    RebakePlan = 5,
    RelocationPlan = 6,
    RepairPlan = 7,
    GeoPlan = 8,
    ReceiptRetirementPlan = 9,
    PrefetchResidencyPlan = 10,
    NoActionPlan = 11,
}

/// Candidate status after hard gates and before score ranking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionCandidateStatus {
    #[default]
    Unknown = 0,
    Legal = 1,
    Illegal = 2,
    DegradedVisible = 3,
    Deferred = 4,
    Blocked = 5,
    Refused = 6,
}

impl StorageIntentDecisionCandidateStatus {
    /// Returns true when hard gates allow this candidate to reach scoring.
    #[must_use]
    pub const fn may_reach_scoring(self) -> bool {
        matches!(self, Self::Legal)
    }
}

/// Hard-gate dimension evaluated before score ranking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionHardGateKind {
    #[default]
    Unknown = 0,
    Guarantee = 1,
    ServiceObjective = 2,
    OrderingReplay = 3,
    MembershipFence = 4,
    TrustDomain = 5,
    Temporal = 6,
    MediaCapability = 7,
    DataShape = 8,
    Layout = 9,
    Lifecycle = 10,
    CapacityReserve = 11,
    RecoveryDegradation = 12,
    PolicyRollout = 13,
    TenantIsolation = 14,
    PredictionActionClass = 15,
    Transport = 16,
    Wear = 17,
    OperatorPolicy = 18,
}

/// Hard-gate verdict retained for operator explanation and validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionHardGateVerdict {
    #[default]
    Unknown = 0,
    Passed = 1,
    Failed = 2,
    DegradedVisible = 3,
    Blocked = 4,
    Deferred = 5,
    Refused = 6,
}

impl StorageIntentDecisionHardGateVerdict {
    /// Returns true when this hard gate admits scoring.
    #[must_use]
    pub const fn admits_scoring(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// One retained hard-gate result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionHardGateResult {
    pub candidate_id: StorageIntentEvidenceId,
    pub gate: StorageIntentDecisionHardGateKind,
    pub verdict: StorageIntentDecisionHardGateVerdict,
    pub refusal: StorageIntentRefusalReason,
    pub evidence_ref: StorageIntentEvidenceRef,
}

impl StorageIntentDecisionHardGateResult {
    pub const EMPTY: Self = Self {
        candidate_id: StorageIntentEvidenceId::ZERO,
        gate: StorageIntentDecisionHardGateKind::Unknown,
        verdict: StorageIntentDecisionHardGateVerdict::Unknown,
        refusal: StorageIntentRefusalReason::None,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };
}

/// Bounded hard-gate result set for a decision frontier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionHardGateResultSet {
    len: u8,
    gates: [StorageIntentDecisionHardGateResult; STORAGE_INTENT_DECISION_HARD_GATES],
}

impl StorageIntentDecisionHardGateResultSet {
    pub const EMPTY: Self = Self {
        len: 0,
        gates: [StorageIntentDecisionHardGateResult::EMPTY; STORAGE_INTENT_DECISION_HARD_GATES],
    };

    /// Number of retained hard-gate records.
    #[must_use]
    pub const fn len(self) -> usize {
        decision_frontier_len(self.len)
    }

    /// Returns true when no hard-gate records are retained.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Append a hard-gate record if capacity remains.
    pub fn push(
        &mut self,
        gate: StorageIntentDecisionHardGateResult,
    ) -> Result<(), EvidenceRefsError> {
        if decision_frontier_len(self.len) >= STORAGE_INTENT_DECISION_HARD_GATES {
            return Err(EvidenceRefsError::Full);
        }
        self.gates[decision_frontier_len(self.len)] = gate;
        self.len += 1;
        Ok(())
    }

    /// Returns true when any retained hard gate did not pass.
    #[must_use]
    pub const fn has_non_passing_gate(self) -> bool {
        let mut index = 0;
        while index < decision_frontier_len(self.len) {
            if !self.gates[index].verdict.admits_scoring() {
                return true;
            }
            index += 1;
        }
        false
    }
}

/// Score-vector dimension retained for one auditable decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionScoreDimension {
    #[default]
    Latency = 0,
    Tail = 1,
    Throughput = 2,
    ServiceObjectiveHeadroom = 3,
    OrderingReplayCost = 4,
    MediaWriteCost = 5,
    CpuReadAmplification = 6,
    LayoutReclaimCost = 7,
    LifecycleChurnRisk = 8,
    MembershipDrainRisk = 9,
    CapacityCost = 10,
    EgressCongestionCost = 11,
    RecoveryRpoRisk = 12,
    ForegroundDisruption = 13,
    ConfidenceMispredictionRisk = 14,
    MovementDebt = 15,
    PaybackRisk = 16,
    OperationalComplexity = 17,
}

impl StorageIntentDecisionScoreDimension {
    pub const COUNT: usize = 18;
    pub const COUNT_U8: u8 = 18;

    /// Return this score dimension's requirement-mask bit.
    #[must_use]
    pub const fn bit(self) -> u64 {
        1_u64 << self.to_discriminant()
    }
}

/// Unit attached to a known score dimension.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionScoreUnit {
    #[default]
    UnitlessPpm = 0,
    Microseconds = 1,
    Bytes = 2,
    BytesPerSecond = 3,
    Iops = 4,
    CostMicrounits = 5,
    RiskPpm = 6,
    Count = 7,
}

/// Typed score state. Unknowns are explicit and never score as zero.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionScoreState {
    #[default]
    UnknownCost = 0,
    UnknownBenefit = 1,
    Known = 2,
    Blocked = 3,
    DegradedVisible = 4,
    Refused = 5,
    NotApplicable = 6,
}

impl StorageIntentDecisionScoreState {
    /// Returns true only for score states that can be ranked.
    #[must_use]
    pub const fn is_known_for_ranking(self) -> bool {
        matches!(self, Self::Known | Self::NotApplicable)
    }
}

/// One score-vector entry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionScoreEntry {
    pub dimension: StorageIntentDecisionScoreDimension,
    pub state: StorageIntentDecisionScoreState,
    pub unit: StorageIntentDecisionScoreUnit,
    pub value: i64,
    pub evidence_ref: StorageIntentEvidenceRef,
}

impl StorageIntentDecisionScoreEntry {
    pub const EMPTY: Self = Self {
        dimension: StorageIntentDecisionScoreDimension::Latency,
        state: StorageIntentDecisionScoreState::UnknownCost,
        unit: StorageIntentDecisionScoreUnit::UnitlessPpm,
        value: 0,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    };
}

/// Bounded score vector for one selected or scored candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionScoreVector {
    len: u8,
    entries: [StorageIntentDecisionScoreEntry; STORAGE_INTENT_DECISION_SCORE_ENTRIES],
}

impl StorageIntentDecisionScoreVector {
    pub const EMPTY: Self = Self {
        len: 0,
        entries: [StorageIntentDecisionScoreEntry::EMPTY; STORAGE_INTENT_DECISION_SCORE_ENTRIES],
    };

    /// Number of retained score entries.
    #[must_use]
    pub const fn len(self) -> usize {
        decision_frontier_len(self.len)
    }

    /// Returns true when no score entries are retained.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Append a score entry if capacity remains.
    pub fn push(
        &mut self,
        entry: StorageIntentDecisionScoreEntry,
    ) -> Result<(), EvidenceRefsError> {
        if decision_frontier_len(self.len) >= STORAGE_INTENT_DECISION_SCORE_ENTRIES {
            return Err(EvidenceRefsError::Full);
        }
        self.entries[decision_frontier_len(self.len)] = entry;
        self.len += 1;
        Ok(())
    }

    /// Return the recorded state for a dimension, or unknown-cost when absent.
    #[must_use]
    pub const fn state_for_dimension(
        self,
        dimension: StorageIntentDecisionScoreDimension,
    ) -> StorageIntentDecisionScoreState {
        let mut index = 0;
        while index < decision_frontier_len(self.len) {
            if self.entries[index].dimension.to_discriminant() == dimension.to_discriminant() {
                return self.entries[index].state;
            }
            index += 1;
        }
        StorageIntentDecisionScoreState::UnknownCost
    }

    /// Returns true when all required score dimensions are known for ranking.
    #[must_use]
    pub const fn satisfies_required_dimensions(
        self,
        required: StorageIntentDecisionScoreRequirementMask,
    ) -> bool {
        let mut raw = 0_u8;
        while raw < StorageIntentDecisionScoreDimension::COUNT_U8 {
            let bit = 1_u64 << raw;
            if (required.0 & bit) != 0 {
                let dimension = match StorageIntentDecisionScoreDimension::from_discriminant(raw) {
                    Some(dimension) => dimension,
                    None => return false,
                };
                if !self.state_for_dimension(dimension).is_known_for_ranking() {
                    return false;
                }
            }
            raw += 1;
        }
        true
    }
}

/// Required score dimensions for a policy or audit gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionScoreRequirementMask(pub u64);

impl StorageIntentDecisionScoreRequirementMask {
    pub const EMPTY: Self = Self(0);
    pub const AUTHORITY_MINIMUM: Self = Self(
        StorageIntentDecisionScoreDimension::Latency.bit()
            | StorageIntentDecisionScoreDimension::Tail.bit()
            | StorageIntentDecisionScoreDimension::Throughput.bit()
            | StorageIntentDecisionScoreDimension::MediaWriteCost.bit()
            | StorageIntentDecisionScoreDimension::CapacityCost.bit()
            | StorageIntentDecisionScoreDimension::RecoveryRpoRisk.bit()
            | StorageIntentDecisionScoreDimension::PaybackRisk.bit(),
    );

    /// Construct a one-dimension requirement.
    #[must_use]
    pub const fn from_dimension(dimension: StorageIntentDecisionScoreDimension) -> Self {
        Self(dimension.bit())
    }

    /// Add one required dimension.
    #[must_use]
    pub const fn with(self, dimension: StorageIntentDecisionScoreDimension) -> Self {
        Self(self.0 | dimension.bit())
    }
}

/// One candidate retained by a decision frontier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionCandidateRecord {
    pub candidate_id: StorageIntentEvidenceId,
    pub candidate_class: StorageIntentDecisionCandidateClass,
    pub action_class: StorageIntentActionClass,
    pub status: StorageIntentDecisionCandidateStatus,
    pub deterministic_order_key: u64,
    pub tie_breaker_input: u64,
    pub input_evidence_refs: StorageIntentEvidenceRefs,
    pub hard_gate_ref: StorageIntentEvidenceRef,
    pub score_vector_ref: StorageIntentEvidenceRef,
    pub rejection_refusal: StorageIntentRefusalReason,
}

impl StorageIntentDecisionCandidateRecord {
    pub const EMPTY: Self = Self {
        candidate_id: StorageIntentEvidenceId::ZERO,
        candidate_class: StorageIntentDecisionCandidateClass::Unknown,
        action_class: StorageIntentActionClass::QueuePrefetchTuning,
        status: StorageIntentDecisionCandidateStatus::Unknown,
        deterministic_order_key: 0,
        tie_breaker_input: 0,
        input_evidence_refs: StorageIntentEvidenceRefs::EMPTY,
        hard_gate_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
        score_vector_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
        rejection_refusal: StorageIntentRefusalReason::None,
    };

    /// Returns true when this candidate carries score evidence.
    #[must_use]
    pub const fn has_score(self) -> bool {
        evidence_ref_has_id(self.score_vector_ref)
    }
}

/// Bounded candidate frontier with stable digest and deterministic ordering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionCandidateSet {
    len: u8,
    pub candidate_set_digest: StorageIntentEvidenceId,
    candidates: [StorageIntentDecisionCandidateRecord; STORAGE_INTENT_DECISION_FRONTIER_CANDIDATES],
}

impl StorageIntentDecisionCandidateSet {
    pub const EMPTY: Self = Self {
        len: 0,
        candidate_set_digest: StorageIntentEvidenceId::ZERO,
        candidates: [StorageIntentDecisionCandidateRecord::EMPTY;
            STORAGE_INTENT_DECISION_FRONTIER_CANDIDATES],
    };

    /// Number of retained candidates.
    #[must_use]
    pub const fn len(self) -> usize {
        decision_frontier_len(self.len)
    }

    /// Returns true when no candidates are retained.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Append a candidate if capacity remains.
    pub fn push(
        &mut self,
        candidate: StorageIntentDecisionCandidateRecord,
    ) -> Result<(), EvidenceRefsError> {
        if decision_frontier_len(self.len) >= STORAGE_INTENT_DECISION_FRONTIER_CANDIDATES {
            return Err(EvidenceRefsError::Full);
        }
        self.candidates[decision_frontier_len(self.len)] = candidate;
        self.len += 1;
        Ok(())
    }

    /// Returns true when any retained candidate is not legal.
    #[must_use]
    pub const fn has_non_legal_candidate(self) -> bool {
        let mut index = 0;
        while index < decision_frontier_len(self.len) {
            if !matches!(
                self.candidates[index].status,
                StorageIntentDecisionCandidateStatus::Legal
            ) {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Returns true when every scored candidate first passed hard gates.
    #[must_use]
    pub const fn illegal_candidates_are_unscored(self) -> bool {
        let mut index = 0;
        while index < decision_frontier_len(self.len) {
            let candidate = self.candidates[index];
            if !candidate.status.may_reach_scoring() && candidate.has_score() {
                return false;
            }
            index += 1;
        }
        true
    }

    /// Returns true when a candidate id appears in the frontier.
    #[must_use]
    pub const fn contains_candidate_id(self, candidate_id: StorageIntentEvidenceId) -> bool {
        if bytes32_are_zero(candidate_id.0) {
            return false;
        }
        let mut index = 0;
        while index < decision_frontier_len(self.len) {
            if bytes32_equal(self.candidates[index].candidate_id.0, candidate_id.0) {
                return true;
            }
            index += 1;
        }
        false
    }
}

/// Reason the selected candidate won or no candidate may run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionSelectionReason {
    #[default]
    Unknown = 0,
    OnlyLegalCandidate = 1,
    HighestScore = 2,
    RequiredRepair = 3,
    RequiredPolicy = 4,
    TieBreak = 5,
    NoCandidateLegal = 6,
    Deferred = 7,
    Refused = 8,
}

/// Deterministic tie-breaker used after score equality.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionTieBreakerClass {
    #[default]
    None = 0,
    DeterministicOrderKey = 1,
    PolicyPriority = 2,
    StableExistingPlacement = 3,
    LowerMovementDebt = 4,
    LowerCapacityCost = 5,
    HigherConfidence = 6,
    LexicographicCandidateId = 7,
}

impl StorageIntentDecisionTieBreakerClass {
    /// Returns true when the tie-breaker has deterministic inputs.
    #[must_use]
    pub const fn is_deterministic(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// State of the selected candidate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDecisionSelectedState {
    #[default]
    Unknown = 0,
    Shadow = 1,
    Trial = 2,
    Admitted = 3,
    RollbackOnly = 4,
    Deferred = 5,
    Refused = 6,
}

/// Selected candidate, admission refs, tie-breaker, and refusal/defer state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionSelectionRecord {
    pub selected_plan_id: StorageIntentEvidenceId,
    pub reason: StorageIntentDecisionSelectionReason,
    pub tie_breaker: StorageIntentDecisionTieBreakerClass,
    pub tie_breaker_input: u64,
    pub state: StorageIntentDecisionSelectedState,
    pub reserve_ref: StorageIntentEvidenceRef,
    pub admission_ref: StorageIntentEvidenceRef,
    pub rollback_proof_ref: StorageIntentEvidenceRef,
    pub no_cutover_proof_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl StorageIntentDecisionSelectionRecord {
    /// Returns true when a tie-break selection is deterministic and evidence-backed.
    #[must_use]
    pub const fn tie_breaker_is_deterministic(self) -> bool {
        if !matches!(self.reason, StorageIntentDecisionSelectionReason::TieBreak) {
            return true;
        }
        self.tie_breaker.is_deterministic()
            && self.tie_breaker_input != 0
            && evidence_ref_has_id(self.no_cutover_proof_ref)
    }

    /// Returns true when the selected state admits authority-changing work.
    #[must_use]
    pub const fn is_admitted(self) -> bool {
        matches!(self.state, StorageIntentDecisionSelectedState::Admitted)
            && matches!(self.refusal, StorageIntentRefusalReason::None)
            && !bytes32_are_zero(self.selected_plan_id.0)
    }
}

/// Counterfactual baseline, payback, harm, outcome, and retention anchors.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionCounterfactualPaybackRecord {
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    pub baseline_candidate_id: StorageIntentEvidenceId,
    pub expected_payback_window_ms: u64,
    pub expected_harm_ceiling_ppm: u32,
    pub outcome_attachment_ref: StorageIntentEvidenceRef,
    pub failed_payback_ref: StorageIntentEvidenceRef,
    pub harm_attachment_ref: StorageIntentEvidenceRef,
    pub cooldown_ref: StorageIntentEvidenceRef,
    pub retention_ref: StorageIntentEvidenceRef,
}

impl StorageIntentDecisionCounterfactualPaybackRecord {
    /// Returns true when failed payback or harm can attach to this frontier.
    #[must_use]
    pub const fn attaches_outcome_to_frontier(
        self,
        decision_frontier_ref: StorageIntentEvidenceRef,
    ) -> bool {
        evidence_ref_equal(self.decision_frontier_ref, decision_frontier_ref)
            && !bytes32_are_zero(self.baseline_candidate_id.0)
            && self.expected_payback_window_ms > 0
            && self.expected_harm_ceiling_ppm > 0
            && evidence_ref_has_id(self.outcome_attachment_ref)
            && (evidence_ref_has_id(self.failed_payback_ref)
                || evidence_ref_has_id(self.harm_attachment_ref))
            && evidence_ref_has_id(self.retention_ref)
    }
}

/// Complete #905 decision-frontier evidence record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDecisionEvidence {
    pub evidence_ref: StorageIntentEvidenceRef,
    pub decision_id: StorageIntentEvidenceId,
    pub action_class: StorageIntentActionClass,
    pub subject_scope: StorageIntentObjectScope,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub actor_component_ref: StorageIntentEvidenceRef,
    pub actor_version: u64,
    pub decision_epoch: u64,
    pub temporal_evidence_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub authority_mode: StorageIntentDecisionAuthorityMode,
    pub candidates: StorageIntentDecisionCandidateSet,
    pub hard_gates: StorageIntentDecisionHardGateResultSet,
    pub score_vector: StorageIntentDecisionScoreVector,
    pub selected_candidate: StorageIntentDecisionSelectionRecord,
    pub counterfactual_payback: StorageIntentDecisionCounterfactualPaybackRecord,
    pub retention_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl StorageIntentDecisionEvidence {
    /// Returns true when the decision identity and shared evidence cut are bound.
    #[must_use]
    pub const fn has_decision_identity(self) -> bool {
        matches!(
            self.evidence_ref.kind,
            StorageIntentEvidenceKind::DecisionFrontierEvidence
        ) && evidence_ref_has_id(self.evidence_ref)
            && !bytes32_are_zero(self.decision_id.0)
            && !self.policy_id.is_zero()
            && self.policy_revision.0 > 0
            && self.actor_version > 0
            && self.decision_epoch > 0
            && evidence_ref_has_id(self.actor_component_ref)
            && matches!(
                self.temporal_evidence_ref.kind,
                StorageIntentEvidenceKind::TemporalEvidence
            )
            && evidence_ref_has_id(self.temporal_evidence_ref)
            && matches!(
                self.evidence_query_snapshot_ref.kind,
                StorageIntentEvidenceKind::EvidenceQuerySnapshot
            )
            && evidence_ref_has_id(self.evidence_query_snapshot_ref)
    }

    /// Returns true when this record is not only the winning candidate.
    #[must_use]
    pub const fn retains_decision_frontier(self) -> bool {
        self.candidates.len() > 1
            && !bytes32_are_zero(self.candidates.candidate_set_digest.0)
            && !self.hard_gates.is_empty()
            && (!self.candidates.has_non_legal_candidate()
                || self.hard_gates.has_non_passing_gate())
    }

    /// Returns true when no illegal, unknown, blocked, or refused candidate was scored.
    #[must_use]
    pub const fn illegal_candidates_are_unscored(self) -> bool {
        self.candidates.illegal_candidates_are_unscored()
    }

    /// Returns true when required score dimensions are known for ranking.
    #[must_use]
    pub const fn required_scores_are_known(
        self,
        required: StorageIntentDecisionScoreRequirementMask,
    ) -> bool {
        self.score_vector.satisfies_required_dimensions(required)
    }

    /// Returns true when the selected candidate and any tie-breaker are deterministic.
    #[must_use]
    pub const fn selection_is_deterministic(self) -> bool {
        self.candidates
            .contains_candidate_id(self.selected_candidate.selected_plan_id)
            && self.selected_candidate.tie_breaker_is_deterministic()
    }

    /// Returns true when failed payback or harm can attach to this exact frontier.
    #[must_use]
    pub const fn has_outcome_payback_anchor(self) -> bool {
        self.counterfactual_payback
            .attaches_outcome_to_frontier(self.evidence_ref)
    }
}

/// Evaluate the #905 audit policy for an authority-capable frontier.
#[must_use]
pub const fn decision_frontier_satisfies_audit_policy(
    evidence: StorageIntentDecisionEvidence,
    required_scores: StorageIntentDecisionScoreRequirementMask,
) -> ReceiptPredicateResult {
    if !matches!(evidence.refusal, StorageIntentRefusalReason::None) {
        return ReceiptPredicateResult::refused(evidence.refusal);
    }
    if !evidence.has_decision_identity()
        || !evidence.retains_decision_frontier()
        || !evidence.illegal_candidates_are_unscored()
        || !evidence.required_scores_are_known(required_scores)
        || !evidence.selection_is_deterministic()
        || !evidence.has_outcome_payback_anchor()
        || !evidence.selected_candidate.is_admitted()
        || !evidence.authority_mode.may_admit_authority_change()
        || !evidence_ref_has_id(evidence.retention_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Bounded evidence set mutation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum EvidenceRefsError {
    /// No inline slot remains.
    Full,
}

/// Acknowledgment guarantee class earned by a receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentGuaranteeClass {
    /// Only local volatile state has accepted the operation.
    #[default]
    VolatileLocal = 0,
    /// Volatile state exists on more than one eligible participant.
    VolatileReplicated = 1,
    /// Local durable intent or committed-root publication exists.
    LocalIntent = 2,
    /// Local durable intent plus a remote volatile copy exists.
    RemoteVolatilePlusLocal = 3,
    /// A quorum has durable intent evidence.
    QuorumIntent = 4,
    /// The full required placement set has been durably materialized.
    FullPlacement = 5,
    /// Geo replica progress exists under explicit lag/RPO evidence.
    GeoAsync = 6,
    /// Geo-side durable intent exists under explicit geo policy evidence.
    GeoIntent = 7,
    /// Full geo placement has been durably materialized.
    GeoFullPlacement = 8,
    /// Archive erasure-coded placement has been materialized.
    ArchiveEc = 9,
}

impl StorageIntentGuaranteeClass {
    /// Number of defined guarantee classes.
    pub const COUNT: usize = 10;

    /// Stable policy spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VolatileLocal => "volatile-local",
            Self::VolatileReplicated => "volatile-replicated",
            Self::LocalIntent => "local-intent",
            Self::RemoteVolatilePlusLocal => "remote-volatile-plus-local",
            Self::QuorumIntent => "quorum-intent",
            Self::FullPlacement => "full-placement",
            Self::GeoAsync => "geo-async",
            Self::GeoIntent => "geo-intent",
            Self::GeoFullPlacement => "geo-full-placement",
            Self::ArchiveEc => "archive-ec",
        }
    }

    /// Decode from stable discriminant. Unknown values fail closed.
    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::VolatileLocal),
            1 => Some(Self::VolatileReplicated),
            2 => Some(Self::LocalIntent),
            3 => Some(Self::RemoteVolatilePlusLocal),
            4 => Some(Self::QuorumIntent),
            5 => Some(Self::FullPlacement),
            6 => Some(Self::GeoAsync),
            7 => Some(Self::GeoIntent),
            8 => Some(Self::GeoFullPlacement),
            9 => Some(Self::ArchiveEc),
            _ => None,
        }
    }

    /// Encode to stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for StorageIntentGuaranteeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Explicit guarantee capabilities; this avoids enum-ordinal comparisons.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct GuaranteeCapabilities {
    pub volatile_local: bool,
    pub volatile_replicated: bool,
    pub local_intent: bool,
    pub remote_volatile_plus_local: bool,
    pub quorum_intent: bool,
    pub full_placement: bool,
    pub geo_async: bool,
    pub geo_intent: bool,
    pub geo_full_placement: bool,
    pub archive_ec: bool,
}

impl GuaranteeCapabilities {
    /// Required capability vector for a requested class.
    #[must_use]
    pub const fn required_by(class: StorageIntentGuaranteeClass) -> Self {
        match class {
            StorageIntentGuaranteeClass::VolatileLocal => Self {
                volatile_local: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::VolatileReplicated => Self {
                volatile_replicated: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::LocalIntent => Self {
                local_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::RemoteVolatilePlusLocal => Self {
                local_intent: true,
                remote_volatile_plus_local: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::QuorumIntent => Self {
                quorum_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::FullPlacement => Self {
                full_placement: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoAsync => Self {
                geo_async: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoIntent => Self {
                geo_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoFullPlacement => Self {
                geo_full_placement: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::ArchiveEc => Self {
                archive_ec: true,
                ..Self::empty()
            },
        }
    }

    /// Capability vector provided by an earned receipt class.
    #[must_use]
    pub const fn provided_by(class: StorageIntentGuaranteeClass) -> Self {
        match class {
            StorageIntentGuaranteeClass::VolatileLocal => Self {
                volatile_local: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::VolatileReplicated => Self {
                volatile_local: true,
                volatile_replicated: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::LocalIntent => Self {
                volatile_local: true,
                local_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::RemoteVolatilePlusLocal => Self {
                volatile_local: true,
                volatile_replicated: true,
                local_intent: true,
                remote_volatile_plus_local: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::QuorumIntent => Self {
                volatile_local: true,
                volatile_replicated: true,
                local_intent: true,
                quorum_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::FullPlacement => Self {
                volatile_local: true,
                local_intent: true,
                full_placement: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoAsync => Self {
                volatile_local: true,
                local_intent: true,
                full_placement: true,
                geo_async: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoIntent => Self {
                volatile_local: true,
                local_intent: true,
                quorum_intent: true,
                geo_intent: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::GeoFullPlacement => Self {
                volatile_local: true,
                local_intent: true,
                quorum_intent: true,
                full_placement: true,
                geo_async: true,
                geo_intent: true,
                geo_full_placement: true,
                ..Self::empty()
            },
            StorageIntentGuaranteeClass::ArchiveEc => Self {
                local_intent: true,
                full_placement: true,
                archive_ec: true,
                ..Self::empty()
            },
        }
    }

    /// Empty capability vector.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            volatile_local: false,
            volatile_replicated: false,
            local_intent: false,
            remote_volatile_plus_local: false,
            quorum_intent: false,
            full_placement: false,
            geo_async: false,
            geo_intent: false,
            geo_full_placement: false,
            archive_ec: false,
        }
    }

    /// Returns true when `self` provides every capability in `required`.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        (!required.volatile_local || self.volatile_local)
            && (!required.volatile_replicated || self.volatile_replicated)
            && (!required.local_intent || self.local_intent)
            && (!required.remote_volatile_plus_local || self.remote_volatile_plus_local)
            && (!required.quorum_intent || self.quorum_intent)
            && (!required.full_placement || self.full_placement)
            && (!required.geo_async || self.geo_async)
            && (!required.geo_intent || self.geo_intent)
            && (!required.geo_full_placement || self.geo_full_placement)
            && (!required.archive_ec || self.archive_ec)
    }
}

/// Predicate: does an earned receipt class satisfy the requested guarantee floor?
#[must_use]
pub const fn ack_receipt_satisfies_requested_floor(
    requested: StorageIntentGuaranteeClass,
    earned: StorageIntentGuaranteeClass,
) -> bool {
    GuaranteeCapabilities::provided_by(earned)
        .satisfies(GuaranteeCapabilities::required_by(requested))
}

/// Failure-domain dimensions that receipts may prove.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum FailureDomainDimension {
    Local = 0,
    Node = 1,
    Rack = 2,
    Datacenter = 3,
    Wan = 4,
    Internet = 5,
    Geo = 6,
}

impl FailureDomainDimension {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Node => "node",
            Self::Rack => "rack",
            Self::Datacenter => "datacenter",
            Self::Wan => "wan",
            Self::Internet => "internet",
            Self::Geo => "geo",
        }
    }

    /// Decode from stable discriminant.
    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Local),
            1 => Some(Self::Node),
            2 => Some(Self::Rack),
            3 => Some(Self::Datacenter),
            4 => Some(Self::Wan),
            5 => Some(Self::Internet),
            6 => Some(Self::Geo),
            _ => None,
        }
    }

    /// Encode to a stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for FailureDomainDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Set of proved failure-domain dimensions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct FailureDomainMask(pub u32);

impl FailureDomainMask {
    pub const EMPTY: Self = Self(0);
    pub const LOCAL: Self = Self(1 << FailureDomainDimension::Local as u32);
    pub const NODE: Self = Self(1 << FailureDomainDimension::Node as u32);
    pub const RACK: Self = Self(1 << FailureDomainDimension::Rack as u32);
    pub const DATACENTER: Self = Self(1 << FailureDomainDimension::Datacenter as u32);
    pub const WAN: Self = Self(1 << FailureDomainDimension::Wan as u32);
    pub const INTERNET: Self = Self(1 << FailureDomainDimension::Internet as u32);
    pub const GEO: Self = Self(1 << FailureDomainDimension::Geo as u32);

    /// Construct a one-domain mask.
    #[must_use]
    pub const fn from_domain(domain: FailureDomainDimension) -> Self {
        Self(1 << domain as u32)
    }

    /// Add one domain dimension.
    #[must_use]
    pub const fn with(self, domain: FailureDomainDimension) -> Self {
        Self(self.0 | (1 << domain as u32))
    }

    /// Returns true if all `required` dimensions are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Predicate: are all requested failure-domain dimensions proved?
#[must_use]
pub const fn failure_domains_satisfied(
    required: FailureDomainMask,
    achieved: FailureDomainMask,
) -> bool {
    achieved.contains_all(required)
}

/// Maximum response-distance/proximity class for a receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ProximityClass {
    /// Same address space or kernel instance.
    #[default]
    InProcess = 0,
    /// Local system RAM or memory-pool participant.
    LocalRam = 1,
    /// Local persistent memory, flash, or disk.
    LocalMedia = 2,
    /// Same node through a local service boundary.
    Node = 3,
    /// Same rack or equivalent low-latency fabric.
    Rack = 4,
    /// Same datacenter.
    Datacenter = 5,
    /// Wide-area network.
    Wan = 6,
    /// Internet path with no RDMA assumption.
    Internet = 7,
    /// Geo-distributed path.
    Geo = 8,
    /// Offline, restore, or archive path.
    ArchiveOffline = 9,
}

impl ProximityClass {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProcess => "in-process",
            Self::LocalRam => "local-ram",
            Self::LocalMedia => "local-media",
            Self::Node => "node",
            Self::Rack => "rack",
            Self::Datacenter => "datacenter",
            Self::Wan => "wan",
            Self::Internet => "internet",
            Self::Geo => "geo",
            Self::ArchiveOffline => "archive-offline",
        }
    }

    /// Decode from stable discriminant. Unknown values fail closed.
    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::InProcess),
            1 => Some(Self::LocalRam),
            2 => Some(Self::LocalMedia),
            3 => Some(Self::Node),
            4 => Some(Self::Rack),
            5 => Some(Self::Datacenter),
            6 => Some(Self::Wan),
            7 => Some(Self::Internet),
            8 => Some(Self::Geo),
            9 => Some(Self::ArchiveOffline),
            _ => None,
        }
    }

    /// Encode to a stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for ProximityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Predicate: is the observed response path no farther than the requested max?
#[must_use]
pub const fn proximity_satisfies_max(
    max_allowed: ProximityClass,
    observed: ProximityClass,
) -> bool {
    match max_allowed {
        ProximityClass::InProcess => matches!(observed, ProximityClass::InProcess),
        ProximityClass::LocalRam => matches!(
            observed,
            ProximityClass::InProcess | ProximityClass::LocalRam
        ),
        ProximityClass::LocalMedia => matches!(
            observed,
            ProximityClass::InProcess | ProximityClass::LocalRam | ProximityClass::LocalMedia
        ),
        ProximityClass::Node => matches!(
            observed,
            ProximityClass::InProcess
                | ProximityClass::LocalRam
                | ProximityClass::LocalMedia
                | ProximityClass::Node
        ),
        ProximityClass::Rack => matches!(
            observed,
            ProximityClass::InProcess
                | ProximityClass::LocalRam
                | ProximityClass::LocalMedia
                | ProximityClass::Node
                | ProximityClass::Rack
        ),
        ProximityClass::Datacenter => matches!(
            observed,
            ProximityClass::InProcess
                | ProximityClass::LocalRam
                | ProximityClass::LocalMedia
                | ProximityClass::Node
                | ProximityClass::Rack
                | ProximityClass::Datacenter
        ),
        ProximityClass::Wan => matches!(
            observed,
            ProximityClass::InProcess
                | ProximityClass::LocalRam
                | ProximityClass::LocalMedia
                | ProximityClass::Node
                | ProximityClass::Rack
                | ProximityClass::Datacenter
                | ProximityClass::Wan
        ),
        ProximityClass::Internet => !matches!(
            observed,
            ProximityClass::Geo | ProximityClass::ArchiveOffline
        ),
        ProximityClass::Geo => !matches!(observed, ProximityClass::ArchiveOffline),
        ProximityClass::ArchiveOffline => true,
    }
}

/// Durability state proved by a receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DurabilityState {
    /// Only volatile state is known.
    #[default]
    Volatile = 0,
    /// Replayable durable intent or committed-root publication is known.
    DurableIntent = 1,
    /// Full requested placement has been materialized.
    FullPlacement = 2,
}

/// Required durability and RPO/lag bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DurabilityRequirement {
    /// Minimum durability state.
    pub min_state: DurabilityState,
    /// Maximum acceptable lag in milliseconds. `u64::MAX` means no bound.
    pub max_lag_ms: u64,
    /// Whether unknown lag may satisfy this requirement.
    pub allow_unknown_lag: bool,
}

impl DurabilityRequirement {
    /// Volatile, no explicit RPO bound.
    pub const VOLATILE: Self = Self {
        min_state: DurabilityState::Volatile,
        max_lag_ms: u64::MAX,
        allow_unknown_lag: true,
    };

    /// Durable intent with known zero-lag local publication.
    pub const DURABLE_INTENT_ZERO_LAG: Self = Self {
        min_state: DurabilityState::DurableIntent,
        max_lag_ms: 0,
        allow_unknown_lag: false,
    };
}

impl Default for DurabilityRequirement {
    fn default() -> Self {
        Self::VOLATILE
    }
}

/// Durability/RPO state carried by a receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DurabilityReceiptState {
    /// Achieved durability state.
    pub state: DurabilityState,
    /// Observed lag in milliseconds when known.
    pub observed_lag_ms: u64,
    /// Whether `observed_lag_ms` is known and fresh enough for this receipt.
    pub lag_known: bool,
}

/// Predicate: does receipt durability and lag satisfy the requested bound?
#[must_use]
pub const fn durability_satisfies(
    requested: DurabilityRequirement,
    earned: DurabilityReceiptState,
) -> bool {
    durability_state_satisfies(requested.min_state, earned.state)
        && ((earned.lag_known && earned.observed_lag_ms <= requested.max_lag_ms)
            || (requested.allow_unknown_lag && !earned.lag_known))
}

/// Predicate: explicit durability-state implication, without enum ordinals.
#[must_use]
pub const fn durability_state_satisfies(
    requested: DurabilityState,
    earned: DurabilityState,
) -> bool {
    match requested {
        DurabilityState::Volatile => true,
        DurabilityState::DurableIntent => matches!(
            earned,
            DurabilityState::DurableIntent | DurabilityState::FullPlacement
        ),
        DurabilityState::FullPlacement => matches!(earned, DurabilityState::FullPlacement),
    }
}

/// Required transport/session security.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum SessionSecurityClass {
    /// No session evidence required.
    #[default]
    None = 0,
    /// Peer identity authenticated.
    Authenticated = 1,
    /// Encrypted channel.
    Encrypted = 2,
    /// Mutual authentication and encryption.
    MutualAuthenticated = 3,
    /// Mutual authentication, encryption, and attestation evidence.
    Attested = 4,
}

/// Predicate: explicit session-security implication.
#[must_use]
pub const fn session_security_satisfies(
    required: SessionSecurityClass,
    observed: SessionSecurityClass,
) -> bool {
    match required {
        SessionSecurityClass::None => true,
        SessionSecurityClass::Authenticated => matches!(
            observed,
            SessionSecurityClass::Authenticated
                | SessionSecurityClass::MutualAuthenticated
                | SessionSecurityClass::Attested
        ),
        SessionSecurityClass::Encrypted => matches!(
            observed,
            SessionSecurityClass::Encrypted
                | SessionSecurityClass::MutualAuthenticated
                | SessionSecurityClass::Attested
        ),
        SessionSecurityClass::MutualAuthenticated => matches!(
            observed,
            SessionSecurityClass::MutualAuthenticated | SessionSecurityClass::Attested
        ),
        SessionSecurityClass::Attested => matches!(observed, SessionSecurityClass::Attested),
    }
}

/// Residency boundary for remote, WAN, internet, geo, and archive decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ResidencyScope {
    /// No residency constraint in this policy.
    #[default]
    Unspecified = 0,
    /// Same node.
    LocalNode = 1,
    /// Same datacenter.
    Datacenter = 2,
    /// Same region.
    Region = 3,
    /// Same legal or operator jurisdiction.
    Jurisdiction = 4,
    /// Geo replicas are allowed by policy.
    GeoReplicaAllowed = 5,
    /// Internet placement/transport is allowed by policy.
    InternetAllowed = 6,
}

/// Sharing boundary for peer, tenant, dedup, repair, and cache state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum SharingDomainClass {
    /// Private to this dataset or authority domain.
    #[default]
    PrivateDataset = 0,
    /// Shared only within the same tenant.
    SameTenant = 1,
    /// Cross-tenant sharing is explicitly allowed.
    CrossTenantAllowed = 2,
    /// Public or internet-facing sharing is explicitly allowed.
    PublicInternet = 3,
}

/// Compromise state of a source, peer, or repair participant.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum CompromiseState {
    /// No compromise evidence is present.
    #[default]
    Clear = 0,
    /// Suspicious but not yet barred by policy.
    Suspect = 1,
    /// Compromised source; must not satisfy authority paths.
    Compromised = 2,
}

/// Quarantine state of a source, peer, or media target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum QuarantineState {
    /// Not quarantined.
    #[default]
    Clear = 0,
    /// Quarantine pending, policy may refuse.
    Pending = 1,
    /// Quarantined; must not satisfy authority paths.
    Quarantined = 2,
}

/// Storage-intent role whose trust/domain evidence is being evaluated.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentTrustRole {
    #[default]
    SyncIntent = 0,
    QuorumIntent = 1,
    GeoIntent = 2,
    DurablePlacement = 3,
    ReadServing = 4,
    DegradedReconstruction = 5,
    AuthoritativeRam = 6,
    RepairSource = 7,
    RelocationTarget = 8,
    DedupRebakeSharing = 9,
    ArchiveRestore = 10,
}

/// Freshness/refusal state of the trust-domain evidence cut.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum TrustEvidenceFreshnessState {
    #[default]
    Unknown = 0,
    Fresh = 1,
    Missing = 2,
    Stale = 3,
    Contradictory = 4,
    Refused = 5,
}

/// Encryption/key lifecycle state projected from the key authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum TrustKeyLifecycleState {
    #[default]
    Unknown = 0,
    Active = 1,
    RotatingDualValid = 2,
    Revoked = 3,
    Quarantined = 4,
    Retired = 5,
}

/// Revocation state of the peer, domain, principal, or trust epoch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum TrustRevocationState {
    #[default]
    Clear = 0,
    Revoked = 1,
}

/// Dedup/reflink/rebake sharing compatibility projected from shape evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DedupSharingCompatibilityState {
    #[default]
    Unknown = 0,
    Compatible = 1,
    SameTenantOnly = 2,
    CrossTenantForbidden = 3,
    Refused = 4,
}

/// Allowed-domain classes proven by regulatory or operator policy evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustAllowedDomainMask(pub u32);

impl TrustAllowedDomainMask {
    pub const EMPTY: Self = Self(0);
    pub const SAME_ADMIN: Self = Self(1 << 0);
    pub const SAME_SECURITY: Self = Self(1 << 1);
    pub const SAME_TENANT: Self = Self(1 << 2);
    pub const SAME_POLICY: Self = Self(1 << 3);
    pub const SAME_JURISDICTION: Self = Self(1 << 4);
    pub const GEO_ALLOWED: Self = Self(1 << 5);
    pub const INTERNET_ALLOWED: Self = Self(1 << 6);
    pub const OPERATOR_DEFINED: Self = Self(1 << 7);

    /// Add classes.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when no class is required or proved.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when all required classes are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Trust evidence dimensions required or proved by a receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustEvidenceFlags(pub u32);

impl TrustEvidenceFlags {
    pub const EMPTY: Self = Self(0);
    pub const AUTHENTICATED_PRINCIPAL: Self = Self(1 << 0);
    pub const ADMIN_DOMAIN: Self = Self(1 << 1);
    pub const SECURITY_DOMAIN: Self = Self(1 << 2);
    pub const TENANT_DOMAIN: Self = Self(1 << 3);
    pub const SESSION_SECURITY: Self = Self(1 << 4);
    pub const KEY_EPOCH: Self = Self(1 << 5);
    pub const AUTHORIZATION: Self = Self(1 << 6);
    pub const AUDIT: Self = Self(1 << 7);
    pub const RESIDENCY: Self = Self(1 << 8);
    pub const SHARING_DOMAIN: Self = Self(1 << 9);
    pub const NOT_COMPROMISED: Self = Self(1 << 10);
    pub const NOT_QUARANTINED: Self = Self(1 << 11);
    pub const PEER_IDENTITY: Self = Self(1 << 12);
    pub const DATASET_DOMAIN: Self = Self(1 << 13);
    pub const POLICY_DOMAIN: Self = Self(1 << 14);
    pub const BUDGET_OWNER_DOMAIN: Self = Self(1 << 15);
    pub const ENCRYPTION_DOMAIN: Self = Self(1 << 16);
    pub const KEY_LIFECYCLE: Self = Self(1 << 17);
    pub const KEY_LEASE: Self = Self(1 << 18);
    pub const DEDUP_SHARING_COMPATIBLE: Self = Self(1 << 19);
    pub const REGULATORY_DOMAIN: Self = Self(1 << 20);
    pub const OPERATOR_ALLOWED_DOMAIN: Self = Self(1 << 21);
    pub const TRUST_EPOCH: Self = Self(1 << 22);
    pub const FRESH_TRUST_EVIDENCE: Self = Self(1 << 23);
    pub const NOT_REVOKED: Self = Self(1 << 24);

    /// Add flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all flags are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Trust/security requirement compiled into a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustRequirement {
    pub required_flags: TrustEvidenceFlags,
    pub min_session_security: SessionSecurityClass,
    pub min_key_epoch: u64,
    pub admin_domain: StorageIntentDomainId,
    pub security_domain: StorageIntentDomainId,
    pub tenant_domain: StorageIntentDomainId,
    pub residency: ResidencyScope,
    pub sharing_domain: SharingDomainClass,
}

impl TrustRequirement {
    /// No trust/domain floor.
    pub const NONE: Self = Self {
        required_flags: TrustEvidenceFlags::EMPTY,
        min_session_security: SessionSecurityClass::None,
        min_key_epoch: 0,
        admin_domain: StorageIntentDomainId::ZERO,
        security_domain: StorageIntentDomainId::ZERO,
        tenant_domain: StorageIntentDomainId::ZERO,
        residency: ResidencyScope::Unspecified,
        sharing_domain: SharingDomainClass::PrivateDataset,
    };
}

impl Default for TrustRequirement {
    fn default() -> Self {
        Self::NONE
    }
}

/// Extended trust/domain requirement used by role-specific #897 predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustDomainRequirement {
    pub base: TrustRequirement,
    pub dataset_domain: StorageIntentDomainId,
    pub policy_domain: StorageIntentDomainId,
    pub budget_owner_domain: StorageIntentDomainId,
    pub encryption_domain: StorageIntentDomainId,
    pub allowed_domain_classes: TrustAllowedDomainMask,
    pub min_trust_epoch: u64,
    pub max_evidence_age_ms: u64,
}

impl TrustDomainRequirement {
    /// No extended trust/domain floor.
    pub const NONE: Self = Self {
        base: TrustRequirement::NONE,
        dataset_domain: StorageIntentDomainId::ZERO,
        policy_domain: StorageIntentDomainId::ZERO,
        budget_owner_domain: StorageIntentDomainId::ZERO,
        encryption_domain: StorageIntentDomainId::ZERO,
        allowed_domain_classes: TrustAllowedDomainMask::EMPTY,
        min_trust_epoch: 0,
        max_evidence_age_ms: 0,
    };
}

impl Default for TrustDomainRequirement {
    fn default() -> Self {
        Self::NONE
    }
}

/// Trust/security evidence carried by a receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustEvidenceState {
    pub flags: TrustEvidenceFlags,
    pub session_security: SessionSecurityClass,
    pub key_epoch: u64,
    pub admin_domain: StorageIntentDomainId,
    pub security_domain: StorageIntentDomainId,
    pub tenant_domain: StorageIntentDomainId,
    pub residency: ResidencyScope,
    pub sharing_domain: SharingDomainClass,
    pub compromise_state: CompromiseState,
    pub quarantine_state: QuarantineState,
}

impl TrustEvidenceState {
    /// Empty trust evidence.
    pub const EMPTY: Self = Self {
        flags: TrustEvidenceFlags::EMPTY,
        session_security: SessionSecurityClass::None,
        key_epoch: 0,
        admin_domain: StorageIntentDomainId::ZERO,
        security_domain: StorageIntentDomainId::ZERO,
        tenant_domain: StorageIntentDomainId::ZERO,
        residency: ResidencyScope::Unspecified,
        sharing_domain: SharingDomainClass::PrivateDataset,
        compromise_state: CompromiseState::Clear,
        quarantine_state: QuarantineState::Clear,
    };
}

impl Default for TrustEvidenceState {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Trust/domain evidence plus refs to the authority artifacts that proved it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TrustEvidenceRecord {
    pub state: TrustEvidenceState,
    pub principal_ref: StorageIntentEvidenceRef,
    pub peer_identity_ref: StorageIntentEvidenceRef,
    pub admin_domain_ref: StorageIntentEvidenceRef,
    pub security_domain_ref: StorageIntentEvidenceRef,
    pub tenant_domain_ref: StorageIntentEvidenceRef,
    pub dataset_domain: StorageIntentDomainId,
    pub dataset_domain_ref: StorageIntentEvidenceRef,
    pub policy_domain: StorageIntentDomainId,
    pub policy_domain_ref: StorageIntentEvidenceRef,
    pub budget_owner_domain: StorageIntentDomainId,
    pub budget_owner_domain_ref: StorageIntentEvidenceRef,
    pub encryption_domain: StorageIntentDomainId,
    pub encryption_domain_ref: StorageIntentEvidenceRef,
    pub session_security_ref: StorageIntentEvidenceRef,
    pub key_epoch_ref: StorageIntentEvidenceRef,
    pub key_lifecycle: TrustKeyLifecycleState,
    pub key_lifecycle_ref: StorageIntentEvidenceRef,
    pub key_lease_ref: StorageIntentEvidenceRef,
    pub authorization_ref: StorageIntentEvidenceRef,
    pub audit_ref: StorageIntentEvidenceRef,
    pub residency_ref: StorageIntentEvidenceRef,
    pub sharing_domain_ref: StorageIntentEvidenceRef,
    pub sharing_compatibility: DedupSharingCompatibilityState,
    pub sharing_compatibility_ref: StorageIntentEvidenceRef,
    pub allowed_domain_classes: TrustAllowedDomainMask,
    pub regulatory_domain_ref: StorageIntentEvidenceRef,
    pub operator_allowed_domain_ref: StorageIntentEvidenceRef,
    pub trust_epoch: u64,
    pub trust_epoch_ref: StorageIntentEvidenceRef,
    pub evidence_age_ms: u64,
    pub freshness_state: TrustEvidenceFreshnessState,
    pub freshness_ref: StorageIntentEvidenceRef,
    pub revocation_state: TrustRevocationState,
    pub revocation_ref: StorageIntentEvidenceRef,
    pub compromise_ref: StorageIntentEvidenceRef,
    pub quarantine_ref: StorageIntentEvidenceRef,
    pub refusal_ref: StorageIntentEvidenceRef,
}

/// Storage media classes known to the policy layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageMediaClass {
    /// System RAM.
    #[default]
    SystemRam = 0,
    /// Remote RAM reachable over a transport path.
    RemoteRam = 1,
    /// Byte-addressable persistent memory.
    PersistentMemory = 2,
    /// NVMe flash.
    NvmeFlash = 3,
    /// SSD flash.
    SsdFlash = 4,
    /// Rotational HDD.
    HddRotational = 5,
    /// Zoned rotational HDD.
    ZonedHdd = 6,
    /// Zoned flash.
    ZonedFlash = 7,
    /// Local object or appliance-backed storage.
    ObjectAppliance = 8,
    /// Cloud/object storage over a remote path.
    CloudObject = 9,
    /// Optical archive media.
    OpticalArchive = 10,
    /// Tape archive media.
    TapeArchive = 11,
}

impl StorageMediaClass {
    /// Returns true if the media can hold state across power loss by itself.
    #[must_use]
    pub const fn is_persistent(self) -> bool {
        !matches!(self, Self::SystemRam | Self::RemoteRam)
    }

    /// Returns true if extent locality/defrag is likely a primary read benefit.
    #[must_use]
    pub const fn favors_extent_locality_defrag(self) -> bool {
        matches!(
            self,
            Self::HddRotational | Self::ZonedHdd | Self::OpticalArchive | Self::TapeArchive
        )
    }

    /// Returns true when extra rewrites must be charged against flash/PMem wear.
    #[must_use]
    pub const fn charges_rewrite_wear(self) -> bool {
        matches!(
            self,
            Self::PersistentMemory | Self::NvmeFlash | Self::SsdFlash | Self::ZonedFlash
        )
    }

    /// Returns true when low-latency write intent is plausible.
    #[must_use]
    pub const fn can_host_low_latency_intent(self) -> bool {
        matches!(
            self,
            Self::SystemRam
                | Self::RemoteRam
                | Self::PersistentMemory
                | Self::NvmeFlash
                | Self::SsdFlash
        )
    }

    /// Returns true for media whose geometry is write-pointer constrained.
    #[must_use]
    pub const fn is_zoned(self) -> bool {
        matches!(self, Self::ZonedHdd | Self::ZonedFlash)
    }

    /// Returns true for object-like media that need explicit commit semantics.
    #[must_use]
    pub const fn is_object_like(self) -> bool {
        matches!(self, Self::ObjectAppliance | Self::CloudObject)
    }

    /// Returns true for offline or nearline archive media.
    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::OpticalArchive | Self::TapeArchive)
    }
}

/// Media role in a policy or receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageMediaRole {
    /// Durable sync intent or ordering authority.
    #[default]
    SyncIntent = 0,
    /// Hot metadata and small-object placement.
    MetadataHot = 1,
    /// Hot serving data.
    ServingDataHot = 2,
    /// Cold bulk data.
    BulkDataCold = 3,
    /// Volatile scratch, never durable authority.
    ScratchVolatile = 4,
    /// Repair/rebuild temporary storage.
    RepairTemp = 5,
    /// Read cache, not authority.
    ReadCache = 6,
    /// RAM cache, not authority.
    RamCache = 7,
    /// RAM is intentionally the visible volatile authority.
    RamVolatileAuthority = 8,
    /// RAM is backed by durable intent and may serve as fast authority.
    RamIntentBackedAuthority = 9,
    /// Durable placement authority.
    PlacementAuthority = 10,
    /// Geo async replica under explicit lag/RPO evidence.
    GeoAsyncReplica = 11,
    /// Archive erasure-coded authority.
    ArchiveEc = 12,
    /// Defrag, compaction, or rebake temporary destination.
    OptimizerTemp = 13,
}

impl StorageMediaRole {
    /// Number of defined roles.
    pub const COUNT: usize = 14;

    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyncIntent => "sync-intent",
            Self::MetadataHot => "metadata-hot",
            Self::ServingDataHot => "serving-data-hot",
            Self::BulkDataCold => "bulk-data-cold",
            Self::ScratchVolatile => "scratch-volatile",
            Self::RepairTemp => "repair-temp",
            Self::ReadCache => "read-cache",
            Self::RamCache => "ram-cache",
            Self::RamVolatileAuthority => "ram-volatile-authority",
            Self::RamIntentBackedAuthority => "ram-intent-backed-authority",
            Self::PlacementAuthority => "placement-authority",
            Self::GeoAsyncReplica => "geo-async-replica",
            Self::ArchiveEc => "archive-ec",
            Self::OptimizerTemp => "optimizer-temp",
        }
    }

    /// Decode from stable discriminant.
    #[must_use]
    pub const fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::SyncIntent),
            1 => Some(Self::MetadataHot),
            2 => Some(Self::ServingDataHot),
            3 => Some(Self::BulkDataCold),
            4 => Some(Self::ScratchVolatile),
            5 => Some(Self::RepairTemp),
            6 => Some(Self::ReadCache),
            7 => Some(Self::RamCache),
            8 => Some(Self::RamVolatileAuthority),
            9 => Some(Self::RamIntentBackedAuthority),
            10 => Some(Self::PlacementAuthority),
            11 => Some(Self::GeoAsyncReplica),
            12 => Some(Self::ArchiveEc),
            13 => Some(Self::OptimizerTemp),
            _ => None,
        }
    }

    /// Encode to a stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }

    /// Returns true when this role is cache-only and cannot be authority.
    #[must_use]
    pub const fn is_cache_only(self) -> bool {
        matches!(self, Self::ReadCache | Self::RamCache)
    }

    /// Returns true when the role is temporary optimizer or repair state.
    #[must_use]
    pub const fn is_temporary(self) -> bool {
        matches!(
            self,
            Self::RepairTemp | Self::OptimizerTemp | Self::ScratchVolatile
        )
    }
}

impl fmt::Display for StorageMediaRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Allowed media role set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MediaRoleMask(pub u64);

impl MediaRoleMask {
    pub const EMPTY: Self = Self(0);
    pub const ALL_DEFINED: Self = Self((1_u64 << StorageMediaRole::COUNT) - 1);

    /// Construct a one-role mask.
    #[must_use]
    pub const fn from_role(role: StorageMediaRole) -> Self {
        Self(1_u64 << role as u8)
    }

    /// Add one role.
    #[must_use]
    pub const fn with(self, role: StorageMediaRole) -> Self {
        Self(self.0 | (1_u64 << role as u8))
    }

    /// Returns true if this mask is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true if `role` is allowed.
    #[must_use]
    pub const fn contains_role(self, role: StorageMediaRole) -> bool {
        (self.0 & (1_u64 << role as u8)) != 0
    }
}

/// Media-role constraints compiled into a policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MediaRoleRequirement {
    /// Empty means "no role allow-list"; non-empty is an allow-list.
    pub allowed_roles: MediaRoleMask,
    /// If true, cache-only and temporary roles must not satisfy the receipt.
    pub require_authority_role: bool,
}

impl MediaRoleRequirement {
    /// No role allow-list, but authority receipts still cannot be cache-only.
    pub const AUTHORITY: Self = Self {
        allowed_roles: MediaRoleMask::EMPTY,
        require_authority_role: true,
    };
}

impl Default for MediaRoleRequirement {
    fn default() -> Self {
        Self::AUTHORITY
    }
}

/// Facts proven by media-capability evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MediaCapabilityFlags(pub u64);

impl MediaCapabilityFlags {
    pub const EMPTY: Self = Self(0);
    pub const STABLE_DEVICE_IDENTITY: Self = Self(1_u64 << 0);
    pub const STABLE_NAMESPACE_IDENTITY: Self = Self(1_u64 << 1);
    pub const POOL_MEMBER_BINDING: Self = Self(1_u64 << 2);
    pub const FIRMWARE_CAPABILITY_GENERATION: Self = Self(1_u64 << 3);
    pub const PERSISTENCE_DOMAIN: Self = Self(1_u64 << 4);
    pub const FLUSH_FUA_ORDERING: Self = Self(1_u64 << 5);
    pub const WRITE_CACHE_SAFE: Self = Self(1_u64 << 6);
    pub const ATOMICITY_GRANULARITY: Self = Self(1_u64 << 7);
    pub const PROTOCOL_GEOMETRY: Self = Self(1_u64 << 8);
    pub const HEALTH: Self = Self(1_u64 << 9);
    pub const FRESHNESS: Self = Self(1_u64 << 10);
    pub const PMEM_FLUSH_FENCE: Self = Self(1_u64 << 11);
    pub const REMOTE_COMMIT: Self = Self(1_u64 << 12);
    pub const ARCHIVE_RESTORE_RETENTION: Self = Self(1_u64 << 13);
    pub const TRANSPORT_RDMA_ABSENT_LEGAL: Self = Self(1_u64 << 14);
    pub const DISCARD_ZEROES_SHAPE: Self = Self(1_u64 << 15);

    /// Merge two capability flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove one capability flag set from another.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Returns true when all required facts are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Persistence domain proven for a media target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaPersistenceDomain {
    #[default]
    Unknown = 0,
    VolatileRam = 1,
    CacheOnlyVolatile = 2,
    PlpBackedVolatileCache = 3,
    OrdinaryPersistent = 4,
    PersistentMemory = 5,
    RotationalPersistent = 6,
    RemoteDurable = 7,
    ObjectDurable = 8,
    ArchiveDurable = 9,
}

impl MediaPersistenceDomain {
    /// Returns true when this domain can be durable authority for data.
    #[must_use]
    pub const fn can_be_durable_authority(self, flags: MediaCapabilityFlags) -> bool {
        match self {
            Self::PlpBackedVolatileCache => {
                flags.contains_all(MediaCapabilityFlags::WRITE_CACHE_SAFE)
            }
            Self::OrdinaryPersistent
            | Self::PersistentMemory
            | Self::RotationalPersistent
            | Self::RemoteDurable
            | Self::ObjectDurable
            | Self::ArchiveDurable => true,
            Self::Unknown | Self::VolatileRam | Self::CacheOnlyVolatile => false,
        }
    }
}

/// Flush, FUA, ordering, and commit semantics proven for a media target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaFlushOrderingClass {
    #[default]
    Unknown = 0,
    None = 1,
    FlushOnly = 2,
    FuaOnly = 3,
    FlushAndFua = 4,
    PmemFlushFence = 5,
    OrderedRemoteCommit = 6,
    ObjectCommit = 7,
    ArchiveCommit = 8,
}

impl MediaFlushOrderingClass {
    /// Returns true when ordinary block durable writes have flush and FUA proof.
    #[must_use]
    pub const fn supports_block_durable(self) -> bool {
        matches!(self, Self::FlushAndFua)
    }

    /// Returns true when persistent memory has explicit flush/fence proof.
    #[must_use]
    pub const fn supports_pmem_flush_fence(self) -> bool {
        matches!(self, Self::PmemFlushFence)
    }

    /// Returns true when remote or object commit is explicitly durable.
    #[must_use]
    pub const fn supports_remote_or_object_commit(self) -> bool {
        matches!(self, Self::OrderedRemoteCommit | Self::ObjectCommit)
    }

    /// Returns true when archive commit semantics are explicitly retained.
    #[must_use]
    pub const fn supports_archive_commit(self) -> bool {
        matches!(self, Self::ArchiveCommit)
    }
}

/// Atomicity and replay granularity proven for a media target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaAtomicityClass {
    #[default]
    Unknown = 0,
    TornWritesPossible = 1,
    LogicalBlockAtomic = 2,
    PhysicalBlockAtomic = 3,
    AtomicWriteUnit = 4,
    IdempotentObjectPut = 5,
    AppendRecordAtomic = 6,
}

impl MediaAtomicityClass {
    /// Returns true when block writes have a usable atomic replay granularity.
    #[must_use]
    pub const fn supports_block_durable(self) -> bool {
        matches!(
            self,
            Self::LogicalBlockAtomic | Self::PhysicalBlockAtomic | Self::AtomicWriteUnit
        )
    }

    /// Returns true when object/archive writes have idempotent commit semantics.
    #[must_use]
    pub const fn supports_object_or_archive(self) -> bool {
        matches!(self, Self::IdempotentObjectPut | Self::AppendRecordAtomic)
    }
}

/// Protocol geometry or access constraint proven for a media target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaProtocolGeometryClass {
    #[default]
    Unknown = 0,
    RamByteAddressable = 1,
    PmemByteAddressable = 2,
    RandomBlock = 3,
    RotationalSeek = 4,
    ZonedSequential = 5,
    ZonedAppend = 6,
    ObjectKeyValue = 7,
    RemoteObject = 8,
    ArchiveSequential = 9,
}

/// Health verdict proven by media-capability evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaHealthState {
    #[default]
    Unknown = 0,
    Healthy = 1,
    Warning = 2,
    Degraded = 3,
    Failed = 4,
    Quarantined = 5,
}

/// Freshness verdict for the capability snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaCapabilityFreshnessState {
    #[default]
    Missing = 0,
    Fresh = 1,
    Stale = 2,
    Contradictory = 3,
    Refused = 4,
}

/// Remote commit semantics proven for a target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaRemoteCommitSemantics {
    #[default]
    Unknown = 0,
    NotRemote = 1,
    VolatileAckOnly = 2,
    DurableAck = 3,
    QuorumDurableAck = 4,
    ObjectConditionalDurable = 5,
    ArchiveRetained = 6,
    RdmaRequiredOnly = 7,
}

impl MediaRemoteCommitSemantics {
    /// Returns true when a remote target can acknowledge durable commit.
    #[must_use]
    pub const fn supports_durable_commit(self) -> bool {
        matches!(
            self,
            Self::DurableAck
                | Self::QuorumDurableAck
                | Self::ObjectConditionalDurable
                | Self::ArchiveRetained
        )
    }
}

/// Archive restore and retention semantics proven for a target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum MediaArchiveRestoreSemantics {
    #[default]
    Unknown = 0,
    NotArchive = 1,
    RestoreUnbounded = 2,
    RestoreRetained = 3,
    RestoreAudited = 4,
}

impl MediaArchiveRestoreSemantics {
    /// Returns true when archive retention and restore semantics are bounded.
    #[must_use]
    pub const fn supports_retained_restore(self) -> bool {
        matches!(self, Self::RestoreRetained | Self::RestoreAudited)
    }
}

/// Evidence-bound media capability projection consumed by role predicates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentMediaCapabilityRecord {
    pub media_class: StorageMediaClass,
    pub flags: MediaCapabilityFlags,
    pub identity_generation: u64,
    pub namespace_generation: u64,
    pub firmware_generation: u64,
    pub settings_generation: u64,
    pub pool_member_generation: u64,
    pub persistence: MediaPersistenceDomain,
    pub flush_ordering: MediaFlushOrderingClass,
    pub atomicity: MediaAtomicityClass,
    pub geometry: MediaProtocolGeometryClass,
    pub health: MediaHealthState,
    pub freshness: MediaCapabilityFreshnessState,
    pub remote_commit: MediaRemoteCommitSemantics,
    pub archive_restore: MediaArchiveRestoreSemantics,
    pub logical_block_bytes: u32,
    pub physical_block_bytes: u32,
    pub atomic_write_unit_bytes: u32,
    pub optimal_io_bytes: u32,
    pub max_queue_depth: u32,
    pub latency_class_us: u32,
    pub evidence: StorageIntentEvidenceRef,
    pub stable_identity_ref: StorageIntentEvidenceRef,
    pub namespace_identity_ref: StorageIntentEvidenceRef,
    pub persistence_ref: StorageIntentEvidenceRef,
    pub flush_ref: StorageIntentEvidenceRef,
    pub atomicity_ref: StorageIntentEvidenceRef,
    pub geometry_ref: StorageIntentEvidenceRef,
    pub health_ref: StorageIntentEvidenceRef,
    pub freshness_ref: StorageIntentEvidenceRef,
    pub remote_commit_ref: StorageIntentEvidenceRef,
    pub archive_restore_ref: StorageIntentEvidenceRef,
}

impl StorageIntentMediaCapabilityRecord {
    /// Returns true when the record cites a non-empty media-capability artifact.
    #[must_use]
    pub const fn has_media_capability_evidence(self) -> bool {
        self.evidence.kind as u16 == StorageIntentEvidenceKind::MediaCapabilityEvidence as u16
            && !bytes32_are_zero(self.evidence.id.0)
    }
}

impl Default for StorageIntentMediaCapabilityRecord {
    fn default() -> Self {
        Self {
            media_class: StorageMediaClass::SystemRam,
            flags: MediaCapabilityFlags::EMPTY,
            identity_generation: 0,
            namespace_generation: 0,
            firmware_generation: 0,
            settings_generation: 0,
            pool_member_generation: 0,
            persistence: MediaPersistenceDomain::Unknown,
            flush_ordering: MediaFlushOrderingClass::Unknown,
            atomicity: MediaAtomicityClass::Unknown,
            geometry: MediaProtocolGeometryClass::Unknown,
            health: MediaHealthState::Unknown,
            freshness: MediaCapabilityFreshnessState::Missing,
            remote_commit: MediaRemoteCommitSemantics::Unknown,
            archive_restore: MediaArchiveRestoreSemantics::Unknown,
            logical_block_bytes: 0,
            physical_block_bytes: 0,
            atomic_write_unit_bytes: 0,
            optimal_io_bytes: 0,
            max_queue_depth: 0,
            latency_class_us: 0,
            evidence: StorageIntentEvidenceRef::default(),
            stable_identity_ref: StorageIntentEvidenceRef::default(),
            namespace_identity_ref: StorageIntentEvidenceRef::default(),
            persistence_ref: StorageIntentEvidenceRef::default(),
            flush_ref: StorageIntentEvidenceRef::default(),
            atomicity_ref: StorageIntentEvidenceRef::default(),
            geometry_ref: StorageIntentEvidenceRef::default(),
            health_ref: StorageIntentEvidenceRef::default(),
            freshness_ref: StorageIntentEvidenceRef::default(),
            remote_commit_ref: StorageIntentEvidenceRef::default(),
            archive_restore_ref: StorageIntentEvidenceRef::default(),
        }
    }
}

/// RAM or PMem authority class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum RamAuthorityClass {
    /// Evictable RAM cache, not authority.
    #[default]
    NonAuthoritativeCache = 0,
    /// Bytes are authoritative only in one live local RAM authority instance.
    RamVolatileLocal = 1,
    /// Volatile RAM authority replicated across fenced peers.
    RamVolatileReplicated = 2,
    /// RAM serving copy covered by durable intent evidence.
    RamIntentBacked = 3,
    /// Durable PMem authority with persistence-domain and flush/fence evidence.
    PmemDurable = 4,
}

/// Failure or recovery event used for RAM authority explanation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum AuthorityEvent {
    #[default]
    ProcessCrash = 0,
    DaemonRestart = 1,
    HostCrash = 2,
    PowerLoss = 3,
    PeerLoss = 4,
    NetworkPartition = 5,
    FencingAmbiguity = 6,
    ReplayAfterDurableIntent = 7,
}

/// Set of failure/recovery events for authority explanation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct AuthorityEventMask(pub u32);

impl AuthorityEventMask {
    pub const EMPTY: Self = Self(0);

    /// Construct a one-event mask.
    #[must_use]
    pub const fn from_event(event: AuthorityEvent) -> Self {
        Self(1_u32 << event as u8)
    }

    /// Add one event.
    #[must_use]
    pub const fn with(self, event: AuthorityEvent) -> Self {
        Self(self.0 | (1_u32 << event as u8))
    }

    /// Returns true if this mask contains `event`.
    #[must_use]
    pub const fn contains(self, event: AuthorityEvent) -> bool {
        (self.0 & (1_u32 << event as u8)) != 0
    }
}

/// Object, range, generation, and dataset scope for authority records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentObjectScope {
    pub dataset_id: StorageIntentDomainId,
    pub object_id: StorageIntentEvidenceId,
    pub range_start: u64,
    pub range_len: u64,
    pub generation: u64,
}

/// Stable idempotency key for crash replay and duplicate suppression.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentReplayIdempotencyKey(pub [u8; 16]);

impl StorageIntentReplayIdempotencyKey {
    /// All-zero sentinel for "no replay key".
    pub const ZERO: Self = Self([0_u8; 16]);

    /// Returns true when this is the sentinel value.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        bytes16_are_zero(self.0)
    }
}

/// Caller-visible operation scope proven by ordering evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentOrderingOperationScope {
    /// No caller-visible operation scope was recorded.
    #[default]
    Unknown = 0,
    /// Range write intent or dirty writeback range.
    RangeWrite = 1,
    /// File `fsync` data and required metadata barrier.
    FileFsync = 2,
    /// File `fdatasync` data and retrieval metadata barrier.
    FileFdatasync = 3,
    /// Directory `fsync` namespace barrier.
    DirectoryFsync = 4,
    /// `O_DSYNC` range write barrier.
    ODsyncDataWrite = 5,
    /// Block-volume or media FUA write barrier.
    FuaBlockWrite = 6,
    /// Shared writable mmap `msync(MS_SYNC)` barrier.
    MsyncSync = 7,
    /// Filesystem or dataset `syncfs` barrier.
    SyncfsDatasetBarrier = 8,
    /// Local intent replay after recovery.
    LocalIntentReplay = 9,
    /// Durable quorum intent fanout.
    QuorumIntentFanout = 10,
    /// Relocation replacement-publication cutover.
    RelocationCutover = 11,
    /// Data-shape rebake publication boundary.
    Rebake = 12,
    /// Repair or rebuild replacement publication.
    Repair = 13,
    /// Old receipt retirement after replacement proof.
    ReceiptRetirement = 14,
}

/// Evidence aggregation shape used by fast sync paths.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentOrderingAggregationClass {
    /// Single operation, no aggregation.
    #[default]
    Single = 0,
    /// Multiple barriers were batched behind a shared boundary.
    Batched = 1,
    /// Work was sharded while preserving caller-visible barriers.
    Sharded = 2,
    /// Adjacent or compatible ranges were coalesced.
    Coalesced = 3,
    /// Work was pipelined with explicit replay or convergence obligations.
    Pipelined = 4,
    /// Quorum fanout was grouped behind one replay frontier.
    QuorumFanout = 5,
}

/// Completion state for the ordering/replay contract, not byte placement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentOrderingCompletionState {
    /// Completion is unknown.
    #[default]
    Unknown = 0,
    /// Replay is still owed before the contract can satisfy authority.
    PendingReplay = 1,
    /// Placement, quorum, or publication convergence is still owed.
    PendingConvergence = 2,
    /// The caller-visible ordering/replay contract is satisfied.
    Satisfied = 3,
    /// A weaker/degraded state is visible but cannot satisfy authority.
    DegradedVisible = 4,
    /// Evidence producer refused the contract.
    Refused = 5,
    /// Receipt retirement has completed under replacement proof.
    Retired = 6,
}

impl StorageIntentOrderingCompletionState {
    /// Returns true when the state can satisfy an authority-changing predicate.
    #[must_use]
    pub const fn is_authority_satisfied(self) -> bool {
        matches!(self, Self::Satisfied | Self::Retired)
    }

    /// Returns true when completion is pending and must name an obligation.
    #[must_use]
    pub const fn requires_pending_obligation_ref(self) -> bool {
        matches!(self, Self::PendingReplay | Self::PendingConvergence)
    }
}

/// Bit-set of facts an ordering-evidence producer has proved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentOrderingFlags(pub u64);

impl StorageIntentOrderingFlags {
    pub const EMPTY: Self = Self(0);
    /// A bound `OrderingEvidence` artifact exists.
    pub const EVIDENCE_PRESENT: Self = Self(1 << 0);
    /// The evidence is fresh for the consumer's authority cut.
    pub const FRESH: Self = Self(1 << 1);
    /// Dirty epoch is sealed for the barrier being acknowledged.
    pub const DIRTY_EPOCH_SEALED: Self = Self(1 << 2);
    /// Committed root or publication boundary matches the requested root.
    pub const ROOT_MATCHES: Self = Self(1 << 3);
    /// Range/dataset scope covers the caller-visible barrier.
    pub const RANGE_MATCHES: Self = Self(1 << 4);
    /// Replay idempotency key and duplicate-suppression law are present.
    pub const REPLAY_IDEMPOTENT: Self = Self(1 << 5);
    /// Namespace dependencies are complete for directory or metadata barriers.
    pub const NAMESPACE_COMPLETE: Self = Self(1 << 6);
    /// Metadata deltas needed for replay are complete.
    pub const METADATA_DELTA_COMPLETE: Self = Self(1 << 7);
    /// Prior writeback errors are recorded and cannot be hidden by the receipt.
    pub const WRITEBACK_ERRORS_RECORDED: Self = Self(1 << 8);
    /// Required quorum count and membership/fence evidence are satisfied.
    pub const QUORUM_SATISFIED: Self = Self(1 << 9);
    /// Evidence is not contradicted by another fresh authority artifact.
    pub const NOT_CONTRADICTORY: Self = Self(1 << 10);
    /// Required dependency refs are complete in the same evidence cut.
    pub const DEPENDENCIES_COMPLETE: Self = Self(1 << 11);
    /// Aggregation preserves the caller-visible barrier order.
    pub const BARRIER_PRESERVED: Self = Self(1 << 12);
    /// Ordering evidence is not being substituted by placement evidence.
    pub const PLACEMENT_INDEPENDENT: Self = Self(1 << 13);
    /// Workload prediction did not weaken or reorder required barriers.
    pub const PREDICTION_INDEPENDENT: Self = Self(1 << 14);

    /// Minimum facts for an authority-changing ordering predicate.
    pub const AUTHORITY_MINIMUM: Self = Self(
        Self::EVIDENCE_PRESENT.0
            | Self::FRESH.0
            | Self::DIRTY_EPOCH_SEALED.0
            | Self::ROOT_MATCHES.0
            | Self::RANGE_MATCHES.0
            | Self::REPLAY_IDEMPOTENT.0
            | Self::WRITEBACK_ERRORS_RECORDED.0
            | Self::NOT_CONTRADICTORY.0
            | Self::DEPENDENCIES_COMPLETE.0
            | Self::BARRIER_PRESERVED.0
            | Self::PLACEMENT_INDEPENDENT.0
            | Self::PREDICTION_INDEPENDENT.0,
    );

    /// Return the union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true if all `required` facts are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Returns true if any fact in `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Predicate input describing the ordering contract a caller-visible receipt needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentOrderingRequirement {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub operation_scope: StorageIntentOrderingOperationScope,
    pub object_scope: StorageIntentObjectScope,
    pub committed_root_id: StorageIntentEvidenceId,
    pub min_dirty_epoch: u64,
    pub min_barrier_sequence: u64,
    pub min_intent_log_sequence: u64,
    pub required_quorum: u16,
    pub required_flags: StorageIntentOrderingFlags,
    pub dependency_refs: StorageIntentEvidenceRefs,
}

impl Default for StorageIntentOrderingRequirement {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            operation_scope: StorageIntentOrderingOperationScope::Unknown,
            object_scope: StorageIntentObjectScope::default(),
            committed_root_id: StorageIntentEvidenceId::ZERO,
            min_dirty_epoch: 0,
            min_barrier_sequence: 0,
            min_intent_log_sequence: 0,
            required_quorum: 0,
            required_flags: StorageIntentOrderingFlags::AUTHORITY_MINIMUM,
            dependency_refs: StorageIntentEvidenceRefs::EMPTY,
        }
    }
}

/// Ordering/replay evidence projection for #894.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentOrderingEvidence {
    pub evidence_ref: StorageIntentEvidenceRef,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub operation_scope: StorageIntentOrderingOperationScope,
    pub object_scope: StorageIntentObjectScope,
    pub dirty_epoch: u64,
    pub barrier_sequence: u64,
    pub intent_log_sequence: u64,
    pub replay_idempotency_key: StorageIntentReplayIdempotencyKey,
    pub committed_root_id: StorageIntentEvidenceId,
    pub committed_root_generation: u64,
    pub publication_sequence: u64,
    pub proved_quorum: u16,
    pub required_quorum: u16,
    pub aggregation: StorageIntentOrderingAggregationClass,
    pub completion: StorageIntentOrderingCompletionState,
    pub flags: StorageIntentOrderingFlags,
    pub dependency_refs: StorageIntentEvidenceRefs,
    pub local_intent_ref: StorageIntentEvidenceRef,
    pub committed_root_ref: StorageIntentEvidenceRef,
    pub publication_ref: StorageIntentEvidenceRef,
    pub namespace_ref: StorageIntentEvidenceRef,
    pub metadata_delta_ref: StorageIntentEvidenceRef,
    pub writeback_error_ref: StorageIntentEvidenceRef,
    pub quorum_ref: StorageIntentEvidenceRef,
    pub placement_ref: StorageIntentEvidenceRef,
    pub prediction_ref: StorageIntentEvidenceRef,
    pub replay_obligation_ref: StorageIntentEvidenceRef,
    pub convergence_ref: StorageIntentEvidenceRef,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for StorageIntentOrderingEvidence {
    fn default() -> Self {
        Self {
            evidence_ref: StorageIntentEvidenceRef::default(),
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            operation_scope: StorageIntentOrderingOperationScope::Unknown,
            object_scope: StorageIntentObjectScope::default(),
            dirty_epoch: 0,
            barrier_sequence: 0,
            intent_log_sequence: 0,
            replay_idempotency_key: StorageIntentReplayIdempotencyKey::ZERO,
            committed_root_id: StorageIntentEvidenceId::ZERO,
            committed_root_generation: 0,
            publication_sequence: 0,
            proved_quorum: 0,
            required_quorum: 0,
            aggregation: StorageIntentOrderingAggregationClass::Single,
            completion: StorageIntentOrderingCompletionState::Unknown,
            flags: StorageIntentOrderingFlags::EMPTY,
            dependency_refs: StorageIntentEvidenceRefs::EMPTY,
            local_intent_ref: StorageIntentEvidenceRef::default(),
            committed_root_ref: StorageIntentEvidenceRef::default(),
            publication_ref: StorageIntentEvidenceRef::default(),
            namespace_ref: StorageIntentEvidenceRef::default(),
            metadata_delta_ref: StorageIntentEvidenceRef::default(),
            writeback_error_ref: StorageIntentEvidenceRef::default(),
            quorum_ref: StorageIntentEvidenceRef::default(),
            placement_ref: StorageIntentEvidenceRef::default(),
            prediction_ref: StorageIntentEvidenceRef::default(),
            replay_obligation_ref: StorageIntentEvidenceRef::default(),
            convergence_ref: StorageIntentEvidenceRef::default(),
            refusal: StorageIntentRefusalReason::None,
        }
    }
}

/// Returns true when the ref is a bound ordering-evidence artifact.
#[must_use]
pub const fn ordering_evidence_ref_is_bound(evidence_ref: StorageIntentEvidenceRef) -> bool {
    evidence_ref.kind as u16 == StorageIntentEvidenceKind::OrderingEvidence as u16
        && !bytes32_are_zero(evidence_ref.id.0)
}

const fn ordering_range_end(start: u64, len: u64) -> u64 {
    if len == 0 {
        return u64::MAX;
    }
    if start > u64::MAX - len {
        return u64::MAX;
    }
    start + len
}

/// Returns true when `evidence_scope` covers the requested object/range scope.
#[must_use]
pub const fn ordering_object_scope_covers(
    evidence_scope: StorageIntentObjectScope,
    required_scope: StorageIntentObjectScope,
) -> bool {
    if !bytes16_equal(evidence_scope.dataset_id.0, required_scope.dataset_id.0) {
        return false;
    }
    if !bytes32_are_zero(required_scope.object_id.0)
        && !bytes32_equal(evidence_scope.object_id.0, required_scope.object_id.0)
    {
        return false;
    }
    if required_scope.range_len == 0 {
        return true;
    }
    if evidence_scope.range_len == 0 {
        return true;
    }
    let evidence_end = ordering_range_end(evidence_scope.range_start, evidence_scope.range_len);
    let required_end = ordering_range_end(required_scope.range_start, required_scope.range_len);
    evidence_scope.range_start <= required_scope.range_start && evidence_end >= required_end
}

const fn ordering_dependencies_satisfied(
    required: StorageIntentEvidenceRefs,
    observed: StorageIntentEvidenceRefs,
) -> bool {
    let mut index = 0;
    while index < required.len as usize {
        let dependency = required.refs[index];
        if dependency.is_bound() && !observed.contains_ref(dependency) {
            return false;
        }
        index += 1;
    }
    true
}

/// Returns true when non-single aggregation preserves barriers or records the debt.
#[must_use]
pub const fn ordering_evidence_records_pending_obligation(
    evidence: StorageIntentOrderingEvidence,
) -> bool {
    match evidence.completion {
        StorageIntentOrderingCompletionState::PendingReplay => {
            evidence_ref_has_id(evidence.replay_obligation_ref)
        }
        StorageIntentOrderingCompletionState::PendingConvergence => {
            evidence_ref_has_id(evidence.convergence_ref)
        }
        _ => false,
    }
}

/// Returns true when batching/sharding/coalescing/pipelining did not weaken barriers.
#[must_use]
pub const fn ordering_evidence_aggregation_is_legal(
    evidence: StorageIntentOrderingEvidence,
) -> bool {
    if matches!(
        evidence.aggregation,
        StorageIntentOrderingAggregationClass::Single
    ) {
        return true;
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::BARRIER_PRESERVED)
        || !evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::REPLAY_IDEMPOTENT)
        || !evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::NOT_CONTRADICTORY)
    {
        return false;
    }
    evidence.completion.is_authority_satisfied()
        || ordering_evidence_records_pending_obligation(evidence)
}

/// Evaluate one ordering evidence record against a caller-visible requirement.
#[must_use]
pub const fn ordering_evidence_satisfies_requirement(
    requirement: StorageIntentOrderingRequirement,
    evidence: StorageIntentOrderingEvidence,
) -> ReceiptPredicateResult {
    if !ordering_evidence_ref_is_bound(evidence.evidence_ref)
        || !evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::EVIDENCE_PRESENT)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingOrderingEvidence,
        );
    }
    if evidence.refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return ReceiptPredicateResult::refused(evidence.refusal);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::FRESH)
        || evidence.dirty_epoch < requirement.min_dirty_epoch
        || evidence.barrier_sequence < requirement.min_barrier_sequence
        || evidence.intent_log_sequence < requirement.min_intent_log_sequence
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleOrderingEvidence);
    }
    if requirement.operation_scope as u8 != StorageIntentOrderingOperationScope::Unknown as u8
        && evidence.operation_scope as u8 != requirement.operation_scope as u8
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongOrderingScope);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::DIRTY_EPOCH_SEALED)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::UnsealedDirtyEpoch);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::ROOT_MATCHES)
        || (!bytes32_are_zero(requirement.committed_root_id.0)
            && !bytes32_equal(
                requirement.committed_root_id.0,
                evidence.committed_root_id.0,
            ))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongCommittedRoot);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::RANGE_MATCHES)
        || !ordering_object_scope_covers(evidence.object_scope, requirement.object_scope)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongOrderingRange);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::REPLAY_IDEMPOTENT)
        || evidence.replay_idempotency_key.is_zero()
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NonIdempotentReplay);
    }
    if requirement
        .required_flags
        .contains_all(StorageIntentOrderingFlags::NAMESPACE_COMPLETE)
        && !evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::NAMESPACE_COMPLETE)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::PartialNamespaceEvidence,
        );
    }
    if requirement
        .required_flags
        .contains_all(StorageIntentOrderingFlags::METADATA_DELTA_COMPLETE)
        && !evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::METADATA_DELTA_COMPLETE)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::IncompleteMetadataDelta,
        );
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::WRITEBACK_ERRORS_RECORDED)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::LostWritebackError);
    }
    let quorum_required = if requirement.required_quorum > 0 {
        requirement.required_quorum
    } else {
        evidence.required_quorum
    };
    if quorum_required > 0
        && (!evidence
            .flags
            .contains_all(StorageIntentOrderingFlags::QUORUM_SATISFIED)
            || evidence.proved_quorum < quorum_required)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::UnderQuorum);
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::NOT_CONTRADICTORY)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::ContradictoryOrderingEvidence,
        );
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::DEPENDENCIES_COMPLETE)
        || !ordering_dependencies_satisfied(requirement.dependency_refs, evidence.dependency_refs)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingOrderingDependency,
        );
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::PLACEMENT_INDEPENDENT)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingOrderingEvidence,
        );
    }
    if !evidence
        .flags
        .contains_all(StorageIntentOrderingFlags::PREDICTION_INDEPENDENT)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::OrderingAggregationWouldWeaken,
        );
    }
    if !ordering_evidence_aggregation_is_legal(evidence) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::OrderingAggregationWouldWeaken,
        );
    }
    if !evidence.completion.is_authority_satisfied() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::PendingOrderingConvergence,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// RAM/PMem authority record carried by #841 without runtime-local policy dialects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct RamAuthorityRecord {
    pub authority_class: RamAuthorityClass,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub requested_guarantee: StorageIntentGuaranteeClass,
    pub earned_receipt: StorageIntentReceiptId,
    pub earned_ack_class: StorageIntentGuaranteeClass,
    pub lost_if: AuthorityEventMask,
    pub survives: AuthorityEventMask,
    pub resource_budget_ref: StorageIntentEvidenceRef,
    pub admission_ref: StorageIntentEvidenceRef,
    pub local_intent_ref: StorageIntentEvidenceRef,
    pub quorum_intent_ref: StorageIntentEvidenceRef,
    pub ordering_ref: StorageIntentEvidenceRef,
    pub placement_ref: StorageIntentEvidenceRef,
    pub pmem_ref: StorageIntentEvidenceRef,
    pub transport_ref: StorageIntentEvidenceRef,
    pub membership_epoch_ref: StorageIntentEvidenceRef,
    pub fencing_ref: StorageIntentEvidenceRef,
    pub capacity_admission_ref: StorageIntentEvidenceRef,
    pub policy_rollout_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub temporal_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub downgrade_refusal: StorageIntentRefusalReason,
}

impl Default for RamAuthorityRecord {
    fn default() -> Self {
        Self {
            authority_class: RamAuthorityClass::NonAuthoritativeCache,
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: StorageIntentObjectScope::default(),
            requested_guarantee: StorageIntentGuaranteeClass::VolatileLocal,
            earned_receipt: StorageIntentReceiptId::ZERO,
            earned_ack_class: StorageIntentGuaranteeClass::VolatileLocal,
            lost_if: AuthorityEventMask::EMPTY,
            survives: AuthorityEventMask::EMPTY,
            resource_budget_ref: StorageIntentEvidenceRef::default(),
            admission_ref: StorageIntentEvidenceRef::default(),
            local_intent_ref: StorageIntentEvidenceRef::default(),
            quorum_intent_ref: StorageIntentEvidenceRef::default(),
            ordering_ref: StorageIntentEvidenceRef::default(),
            placement_ref: StorageIntentEvidenceRef::default(),
            pmem_ref: StorageIntentEvidenceRef::default(),
            transport_ref: StorageIntentEvidenceRef::default(),
            membership_epoch_ref: StorageIntentEvidenceRef::default(),
            fencing_ref: StorageIntentEvidenceRef::default(),
            capacity_admission_ref: StorageIntentEvidenceRef::default(),
            policy_rollout_ref: StorageIntentEvidenceRef::default(),
            tenant_isolation_ref: StorageIntentEvidenceRef::default(),
            temporal_ref: StorageIntentEvidenceRef::default(),
            media_capability_ref: StorageIntentEvidenceRef::default(),
            downgrade_refusal: StorageIntentRefusalReason::None,
        }
    }
}

/// Workload shape used by predictors and policy explanation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum WorkloadShape {
    #[default]
    Unknown = 0,
    SyncSmallWrite = 1,
    AsyncBulkWrite = 2,
    RandomReadHot = 3,
    SequentialReadScan = 4,
    MetadataHotset = 5,
    AppendLog = 6,
    MixedTailSensitive = 7,
    RepairRebuild = 8,
    GeoCatchup = 9,
    ArchiveIngest = 10,
    Scratch = 11,
}

/// Prediction confidence for placement and relocation hints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PredictionConfidence {
    #[default]
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

/// Prediction contradiction state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ContradictionState {
    #[default]
    None = 0,
    WeakContradiction = 1,
    StrongContradiction = 2,
    Refused = 3,
}

/// Hint provenance for workload and lifetime predictions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum HintProvenance {
    #[default]
    None = 0,
    Caller = 1,
    OperatorPolicy = 2,
    RuntimeObserved = 3,
    ImportedMetadata = 4,
    BenchmarkProfile = 5,
    LearningModel = 6,
}

/// Bounded observation metadata for a workload prediction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct WorkloadPrediction {
    pub shape: WorkloadShape,
    pub confidence: PredictionConfidence,
    pub observation_window_ms: u64,
    pub decay_age_ms: u64,
    pub contradiction: ContradictionState,
    pub provenance: HintProvenance,
    pub evidence: StorageIntentEvidenceRef,
}

/// Scope at which a bounded workload signal was collected or summarized.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum WorkloadSignalScopeClass {
    /// Scope is not known.
    #[default]
    Unknown = 0,
    /// One foreground request or small request cohort.
    Request = 1,
    /// One object/range/generation cohort.
    SubjectRange = 2,
    /// One dataset policy envelope.
    Dataset = 3,
    /// Pool-wide default or fallback signal. Never enough to relax a dataset.
    Pool = 4,
    /// One local or remote media device.
    Device = 5,
    /// One transport, path, route, or endpoint.
    Path = 6,
    /// One tenant or workload-budget owner.
    TenantBudget = 7,
}

/// Bounded storage mode for a workload signal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum SignalMaterializationMode {
    /// Signal was not materialized.
    #[default]
    Unknown = 0,
    /// Memory-only sketch; advisory and not durable proof.
    MemoryOnlySketch = 1,
    /// Sampled counter with explicit sampling/drop policy.
    SampledCounter = 2,
    /// Decayed histogram with bounded retention.
    DecayedHistogram = 3,
    /// Top-K set with bounded cardinality.
    TopKSet = 4,
    /// Durable summary charged to the cost/wear ledger.
    DurableSummary = 5,
    /// Derived view rebuilt from other authority records.
    DerivedView = 6,
    /// Retained evidence root kept for audit, validation, or claims.
    RetainedEvidence = 7,
}

/// Access-pattern class projected by bounded workload signals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum AccessPatternClass {
    #[default]
    Unknown = 0,
    SequentialRead = 1,
    StridedRead = 2,
    VectorRead = 3,
    SmallRandomHotset = 4,
    MetadataNamespace = 5,
    ManifestIndexFanout = 6,
    SnapshotCloneRepeat = 7,
    DegradedReconstruction = 8,
    WanGeoDelta = 9,
    ObjectArchiveRestore = 10,
    OnePassScan = 11,
    PhaseChangingSparse = 12,
    NoisyAdversarial = 13,
    SyncSmallWrite = 14,
    AsyncBulkWrite = 15,
    OverwriteChurn = 16,
    AppendLog = 17,
    DatabaseWalFsync = 18,
    VmImageMixedRead = 19,
    MmapPageCacheReuse = 20,
    BackupRestoreScan = 21,
}

/// Prefetch/residency candidate emitted by workload signals for #967.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchResidencyCandidateClass {
    /// No prefetch or residency action is justified.
    #[default]
    NoPrefetch = 0,
    /// Bounded sequential readahead only.
    BoundedReadahead = 1,
    /// Strided or vector range prefetch.
    StridedVectorPrefetch = 2,
    /// Metadata, namespace, or directory/index prefetch.
    MetadataNamespacePrefetch = 3,
    /// Cache-only hotset serving trial.
    SmallRandomHotsetTrial = 4,
    /// Manifest or index fanout prefetch.
    ManifestIndexPrefetch = 5,
    /// Snapshot/clone repeated-read prefetch.
    SnapshotClonePrefetch = 6,
    /// Degraded-read reconstruction prefetch.
    DegradedReadPrefetch = 7,
    /// WAN or geo delta prefetch.
    WanGeoDeltaPrefetch = 8,
    /// Object/archive restore staging.
    ObjectArchiveRestoreStage = 9,
    /// Generic cache-only trial.
    CacheOnlyTrial = 10,
    /// Volatile RAM serving trial, not authority.
    VolatileRamTrial = 11,
    /// RAM serving backed by durable intent evidence.
    IntentBackedRam = 12,
    /// PMem durable residency candidate.
    PmemDurable = 13,
    /// Flash/NVMe/SSD hot serving candidate.
    FlashHotServing = 14,
    /// HDD locality or layout-optimized serving candidate.
    HddLocalityOptimized = 15,
    /// Authority-changing promotion candidate.
    AuthorityPromotionCandidate = 16,
    /// Demotion candidate.
    DemotionCandidate = 17,
    /// Cooldown candidate after failed payback or anti-thrash evidence.
    Cooldown = 18,
    /// More evidence is required before action selection.
    NeedMoreEvidence = 19,
    /// Policy or evidence refused the candidate.
    Refused = 20,
}

/// Flags carried by a bounded workload signal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct WorkloadSignalFlags(pub u64);

impl WorkloadSignalFlags {
    pub const EMPTY: Self = Self(0);
    pub const HINT_ONLY: Self = Self(1_u64 << 0);
    pub const MEMORY_ONLY: Self = Self(1_u64 << 1);
    pub const SAMPLED_AWAY: Self = Self(1_u64 << 2);
    pub const DROPPED_OBSERVATIONS: Self = Self(1_u64 << 3);
    pub const COMPACTED_BEYOND_AUTHORITY: Self = Self(1_u64 << 4);
    pub const LOW_SAMPLE_MASS: Self = Self(1_u64 << 5);
    pub const ONE_PASS_SCAN: Self = Self(1_u64 << 6);
    pub const PHASE_CHANGE: Self = Self(1_u64 << 7);
    pub const NOISY_NEIGHBOR: Self = Self(1_u64 << 8);
    pub const CONTRADICTED: Self = Self(1_u64 << 9);
    pub const UNKNOWN_COLLECTION_COST: Self = Self(1_u64 << 10);
    pub const UNKNOWN_WAF: Self = Self(1_u64 << 11);
    pub const UNKNOWN_EGRESS_OR_RESTORE_COST: Self = Self(1_u64 << 12);
    pub const FOREGROUND_TAIL_PRESSURE: Self = Self(1_u64 << 13);
    pub const SNAPSHOT_PINNED: Self = Self(1_u64 << 14);
    pub const DURABLE_METADATA_WRITES: Self = Self(1_u64 << 15);

    /// Merge two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all requested flags are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    /// Returns true when any requested flag is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Bounded workload signal projected for policy, prefetch, and residency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct WorkloadSignalRecord {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub pool_id: StorageIntentDomainId,
    pub signal_scope: WorkloadSignalScopeClass,
    pub access_pattern: AccessPatternClass,
    pub confidence: PredictionConfidence,
    pub observation_window_ms: u64,
    pub sample_mass: u32,
    pub decay_age_ms: u64,
    pub contradiction: ContradictionState,
    pub provenance: HintProvenance,
    pub materialization_mode: SignalMaterializationMode,
    pub flags: WorkloadSignalFlags,
    pub budget_owner: StorageIntentDomainId,
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub topology_ref: StorageIntentEvidenceRef,
    pub signal_materialization_ref: StorageIntentEvidenceRef,
    pub signal_collection_cost_ref: StorageIntentEvidenceRef,
    pub candidate: PrefetchResidencyCandidateClass,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for WorkloadSignalRecord {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: StorageIntentObjectScope::default(),
            pool_id: StorageIntentDomainId::ZERO,
            signal_scope: WorkloadSignalScopeClass::Unknown,
            access_pattern: AccessPatternClass::Unknown,
            confidence: PredictionConfidence::Unknown,
            observation_window_ms: 0,
            sample_mass: 0,
            decay_age_ms: 0,
            contradiction: ContradictionState::None,
            provenance: HintProvenance::None,
            materialization_mode: SignalMaterializationMode::Unknown,
            flags: WorkloadSignalFlags::EMPTY,
            budget_owner: StorageIntentDomainId::ZERO,
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_media_ref: StorageIntentEvidenceRef::default(),
            target_media_ref: StorageIntentEvidenceRef::default(),
            service_objective_ref: StorageIntentEvidenceRef::default(),
            topology_ref: StorageIntentEvidenceRef::default(),
            signal_materialization_ref: StorageIntentEvidenceRef::default(),
            signal_collection_cost_ref: StorageIntentEvidenceRef::default(),
            candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            refusal: StorageIntentRefusalReason::None,
        }
    }
}

/// Scope that made a prefetch/residency policy actionable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchResidencyPolicyScope {
    /// No compiled policy scope is known.
    #[default]
    Unknown = 0,
    /// Pool default or inherited template only; not sufficient by itself.
    PoolDefault = 1,
    /// Compiled dataset policy revision.
    Dataset = 2,
    /// Dataset-admitted per-object or per-range override.
    SubjectRange = 3,
}

/// Set of prefetch/residency action classes admitted by a dataset policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchResidencyActionMask(pub u64);

impl PrefetchResidencyActionMask {
    pub const EMPTY: Self = Self(0);
    pub const ALL_DEFINED: Self = Self((1_u64 << 21) - 1);
    pub const LOW_RISK_PREFETCH: Self = Self::EMPTY
        .with(PrefetchResidencyCandidateClass::NoPrefetch)
        .with(PrefetchResidencyCandidateClass::BoundedReadahead)
        .with(PrefetchResidencyCandidateClass::StridedVectorPrefetch)
        .with(PrefetchResidencyCandidateClass::MetadataNamespacePrefetch)
        .with(PrefetchResidencyCandidateClass::ManifestIndexPrefetch)
        .with(PrefetchResidencyCandidateClass::SnapshotClonePrefetch)
        .with(PrefetchResidencyCandidateClass::DegradedReadPrefetch)
        .with(PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch)
        .with(PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage)
        .with(PrefetchResidencyCandidateClass::CacheOnlyTrial)
        .with(PrefetchResidencyCandidateClass::Cooldown)
        .with(PrefetchResidencyCandidateClass::NeedMoreEvidence)
        .with(PrefetchResidencyCandidateClass::Refused);

    /// Construct a one-action mask.
    #[must_use]
    pub const fn from_candidate(candidate: PrefetchResidencyCandidateClass) -> Self {
        Self(1_u64 << candidate as u8)
    }

    /// Add one candidate.
    #[must_use]
    pub const fn with(self, candidate: PrefetchResidencyCandidateClass) -> Self {
        Self(self.0 | (1_u64 << candidate as u8))
    }

    /// Remove one candidate.
    #[must_use]
    pub const fn without(self, candidate: PrefetchResidencyCandidateClass) -> Self {
        Self(self.0 & !(1_u64 << candidate as u8))
    }

    /// Returns true when no actions are admitted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true when `candidate` is admitted.
    #[must_use]
    pub const fn contains_candidate(self, candidate: PrefetchResidencyCandidateClass) -> bool {
        (self.0 & (1_u64 << candidate as u8)) != 0
    }
}

/// Requirements a compiled dataset policy imposes on #967 decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchResidencyPolicyFlags(pub u64);

impl PrefetchResidencyPolicyFlags {
    pub const EMPTY: Self = Self(0);
    pub const REQUIRE_DATASET_SCOPE: Self = Self(1_u64 << 0);
    pub const REQUIRE_SERVICE_OBJECTIVE: Self = Self(1_u64 << 1);
    pub const REQUIRE_EVIDENCE_QUERY: Self = Self(1_u64 << 2);
    pub const REQUIRE_FRESH_MEDIA_CAPABILITY: Self = Self(1_u64 << 3);
    pub const REQUIRE_COST_WEAR_EVIDENCE: Self = Self(1_u64 << 4);
    pub const REQUIRE_EGRESS_RESTORE_EVIDENCE: Self = Self(1_u64 << 5);
    pub const REQUIRE_PAYBACK_FOR_MOVEMENT: Self = Self(1_u64 << 6);
    pub const REQUIRE_CAPACITY_RESERVE: Self = Self(1_u64 << 7);
    pub const REQUIRE_TENANT_ISOLATION: Self = Self(1_u64 << 8);
    pub const REQUIRE_READ_SERVING_BOUNDARY: Self = Self(1_u64 << 9);
    pub const REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY: Self = Self(1_u64 << 10);
    pub const PROTECT_FOREGROUND_TAIL: Self = Self(1_u64 << 11);
    pub const PROTECT_FLASH_LIFETIME: Self = Self(1_u64 << 12);
    pub const REQUIRE_TRUST_DOMAIN: Self = Self(1_u64 << 13);
    pub const REQUIRE_TRANSPORT_BUDGET: Self = Self(1_u64 << 14);
    pub const REQUIRE_SCHEDULER_ADMISSION: Self = Self(1_u64 << 15);

    /// Merge two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all requested flags are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Evidence references required to explain a prefetch/residency decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchResidencyDecisionEvidenceRefs {
    pub compiled_policy_ref: StorageIntentEvidenceRef,
    pub service_objective_ref: StorageIntentEvidenceRef,
    pub evidence_query_ref: StorageIntentEvidenceRef,
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub capacity_reserve_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub cost_wear_ref: StorageIntentEvidenceRef,
    pub egress_restore_cost_ref: StorageIntentEvidenceRef,
    pub transport_budget_ref: StorageIntentEvidenceRef,
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub read_serving_boundary_ref: StorageIntentEvidenceRef,
    pub relocation_boundary_ref: StorageIntentEvidenceRef,
    pub result_refusal_ref: StorageIntentEvidenceRef,
}

/// Compiled dataset policy envelope for prefetch and media residency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchResidencyPolicyEnvelope {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub policy_scope: PrefetchResidencyPolicyScope,
    pub pool_id: StorageIntentDomainId,
    pub dataset_id: StorageIntentDomainId,
    pub budget_owner: StorageIntentDomainId,
    pub allowed_actions: PrefetchResidencyActionMask,
    pub flags: PrefetchResidencyPolicyFlags,
    pub max_prefetch_window_bytes: u64,
    pub max_staging_bytes: u64,
    pub min_sample_mass: u32,
    pub min_observation_window_ms: u64,
    pub max_decay_age_ms: u64,
    pub dwell_min_ms: u64,
    pub cooldown_ms: u64,
    pub evidence_refs: PrefetchResidencyDecisionEvidenceRefs,
}

impl Default for PrefetchResidencyPolicyEnvelope {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            policy_scope: PrefetchResidencyPolicyScope::Unknown,
            pool_id: StorageIntentDomainId::ZERO,
            dataset_id: StorageIntentDomainId::ZERO,
            budget_owner: StorageIntentDomainId::ZERO,
            allowed_actions: PrefetchResidencyActionMask::EMPTY,
            flags: PrefetchResidencyPolicyFlags::EMPTY,
            max_prefetch_window_bytes: 0,
            max_staging_bytes: 0,
            min_sample_mass: 0,
            min_observation_window_ms: 0,
            max_decay_age_ms: 0,
            dwell_min_ms: 0,
            cooldown_ms: 0,
            evidence_refs: PrefetchResidencyDecisionEvidenceRefs::default(),
        }
    }
}

/// Decision outcome class emitted by #967 before any executor runs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchResidencyDecisionOutcome {
    /// No action is selected.
    #[default]
    NoAction = 0,
    /// Requested action is admitted as-is.
    Admitted = 1,
    /// Requested action was lowered to a safer class.
    Lowered = 2,
    /// Cache-only or bounded speculative work is the maximum admitted class.
    CacheOnly = 3,
    /// Serving trial may run but is not authority.
    ServingTrial = 4,
    /// Authority-changing promotion may be proposed to relocation/action law.
    PromotionCandidate = 5,
    /// Demotion or source-cooling candidate.
    DemotionCandidate = 6,
    /// Anti-thrash or failed-payback cooldown.
    Cooldown = 7,
    /// More evidence is required before work is legal.
    NeedMoreEvidence = 8,
    /// Policy or evidence refused the action.
    Refused = 9,
}

/// Media residency state selected by the #967 model before execution.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum PrefetchResidencyStateClass {
    /// No residency state is proven or selected.
    #[default]
    Unknown = 0,
    /// Cache-only RAM; never durable authority.
    CacheOnlyRam = 1,
    /// Volatile RAM serving trial; still not durable authority.
    VolatileRamServingTrial = 2,
    /// RAM serving backed by durable intent evidence.
    IntentBackedRam = 3,
    /// Persistent-memory durable residency.
    PmemDurable = 4,
    /// Flash/NVMe/SSD hot serving residency.
    FlashHotServing = 5,
    /// Rotational or zoned HDD cold/locality-optimized residency.
    HddColdLocalityOptimized = 6,
    /// Remote durable residency.
    RemoteDurable = 7,
    /// WAN/geo async residency under explicit RPO evidence.
    WanGeoAsync = 8,
    /// Object/archive restore or staged residency.
    ObjectArchiveStaged = 9,
    /// Policy or evidence explicitly refused residency.
    Refused = 10,
}

/// Input snapshot for a prefetch/residency decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Default)]
pub struct PrefetchResidencyDecisionContext {
    pub policy: PrefetchResidencyPolicyEnvelope,
    pub signal: WorkloadSignalRecord,
    pub source_media: StorageIntentMediaCapabilityRecord,
    pub target_media: StorageIntentMediaCapabilityRecord,
    pub cost_wear: CostWearRecord,
}

/// Result record emitted by the prefetch/residency decision authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct PrefetchResidencyDecisionRecord {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub pool_id: StorageIntentDomainId,
    pub budget_owner: StorageIntentDomainId,
    pub access_pattern: AccessPatternClass,
    pub confidence: PredictionConfidence,
    pub requested_candidate: PrefetchResidencyCandidateClass,
    pub selected_candidate: PrefetchResidencyCandidateClass,
    pub selected_residency: PrefetchResidencyStateClass,
    pub outcome: PrefetchResidencyDecisionOutcome,
    pub refusal: StorageIntentRefusalReason,
    pub source_media: StorageMediaClass,
    pub target_media: StorageMediaClass,
    pub source_media_ref: StorageIntentEvidenceRef,
    pub target_media_ref: StorageIntentEvidenceRef,
    pub topology_ref: StorageIntentEvidenceRef,
    pub max_prefetch_window_bytes: u64,
    pub max_staging_bytes: u64,
    pub evidence_refs: PrefetchResidencyDecisionEvidenceRefs,
}

impl Default for PrefetchResidencyDecisionRecord {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: StorageIntentObjectScope::default(),
            pool_id: StorageIntentDomainId::ZERO,
            budget_owner: StorageIntentDomainId::ZERO,
            access_pattern: AccessPatternClass::Unknown,
            confidence: PredictionConfidence::Unknown,
            requested_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            selected_candidate: PrefetchResidencyCandidateClass::NoPrefetch,
            selected_residency: PrefetchResidencyStateClass::Unknown,
            outcome: PrefetchResidencyDecisionOutcome::NoAction,
            refusal: StorageIntentRefusalReason::None,
            source_media: StorageMediaClass::SystemRam,
            target_media: StorageMediaClass::SystemRam,
            source_media_ref: StorageIntentEvidenceRef::default(),
            target_media_ref: StorageIntentEvidenceRef::default(),
            topology_ref: StorageIntentEvidenceRef::default(),
            max_prefetch_window_bytes: 0,
            max_staging_bytes: 0,
            evidence_refs: PrefetchResidencyDecisionEvidenceRefs::default(),
        }
    }
}

const fn prefetch_candidate_requires_wear_or_cost(
    candidate: PrefetchResidencyCandidateClass,
    target_media: StorageMediaClass,
) -> bool {
    matches!(
        candidate,
        PrefetchResidencyCandidateClass::IntentBackedRam
            | PrefetchResidencyCandidateClass::PmemDurable
            | PrefetchResidencyCandidateClass::FlashHotServing
            | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            | PrefetchResidencyCandidateClass::DemotionCandidate
    ) || (target_media.charges_rewrite_wear()
        && !matches!(
            candidate,
            PrefetchResidencyCandidateClass::NoPrefetch
                | PrefetchResidencyCandidateClass::BoundedReadahead
                | PrefetchResidencyCandidateClass::StridedVectorPrefetch
                | PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
                | PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
                | PrefetchResidencyCandidateClass::ManifestIndexPrefetch
                | PrefetchResidencyCandidateClass::SnapshotClonePrefetch
                | PrefetchResidencyCandidateClass::DegradedReadPrefetch
                | PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
                | PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
                | PrefetchResidencyCandidateClass::CacheOnlyTrial
                | PrefetchResidencyCandidateClass::VolatileRamTrial
                | PrefetchResidencyCandidateClass::Cooldown
                | PrefetchResidencyCandidateClass::NeedMoreEvidence
                | PrefetchResidencyCandidateClass::Refused
        ))
}

const fn prefetch_candidate_requires_egress_or_restore_cost(
    candidate: PrefetchResidencyCandidateClass,
    target_media: StorageMediaClass,
) -> bool {
    target_media.is_object_like()
        || target_media.is_archive()
        || matches!(
            target_media,
            StorageMediaClass::RemoteRam | StorageMediaClass::ObjectAppliance
        )
        || matches!(
            candidate,
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
                | PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
        )
}

/// Returns true when a candidate can change durable authority or receipt state.
#[must_use]
pub const fn prefetch_candidate_changes_authority(
    candidate: PrefetchResidencyCandidateClass,
) -> bool {
    matches!(
        candidate,
        PrefetchResidencyCandidateClass::IntentBackedRam
            | PrefetchResidencyCandidateClass::PmemDurable
            | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            | PrefetchResidencyCandidateClass::DemotionCandidate
    )
}

const fn evidence_ref_has_id(evidence: StorageIntentEvidenceRef) -> bool {
    evidence.kind as u16 != StorageIntentEvidenceKind::Unknown as u16
        && !bytes32_are_zero(evidence.id.0)
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

/// Returns true when a signal carries an evidence root for materialization.
#[must_use]
pub const fn workload_signal_has_materialization_evidence(signal: WorkloadSignalRecord) -> bool {
    evidence_ref_has_id(signal.signal_materialization_ref)
}

/// Returns true when a signal carries an evidence root for materialization cost.
#[must_use]
pub const fn workload_signal_has_collection_cost(signal: WorkloadSignalRecord) -> bool {
    evidence_ref_has_id(signal.signal_collection_cost_ref)
        && !signal
            .flags
            .contains_all(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST)
}

/// Returns true when a signal can raise confidence for promotion or movement.
#[must_use]
pub const fn workload_signal_can_train_upward(signal: WorkloadSignalRecord) -> bool {
    if matches!(
        signal.confidence,
        PredictionConfidence::Unknown | PredictionConfidence::Low
    ) || matches!(
        signal.signal_scope,
        WorkloadSignalScopeClass::Unknown | WorkloadSignalScopeClass::Pool
    ) || signal.sample_mass == 0
        || !matches!(signal.contradiction, ContradictionState::None)
        || matches!(
            signal.materialization_mode,
            SignalMaterializationMode::Unknown | SignalMaterializationMode::MemoryOnlySketch
        )
        || signal.flags.intersects(
            WorkloadSignalFlags::HINT_ONLY
                .union(WorkloadSignalFlags::MEMORY_ONLY)
                .union(WorkloadSignalFlags::SAMPLED_AWAY)
                .union(WorkloadSignalFlags::DROPPED_OBSERVATIONS)
                .union(WorkloadSignalFlags::COMPACTED_BEYOND_AUTHORITY)
                .union(WorkloadSignalFlags::LOW_SAMPLE_MASS)
                .union(WorkloadSignalFlags::ONE_PASS_SCAN)
                .union(WorkloadSignalFlags::PHASE_CHANGE)
                .union(WorkloadSignalFlags::NOISY_NEIGHBOR)
                .union(WorkloadSignalFlags::CONTRADICTED)
                .union(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST)
                .union(WorkloadSignalFlags::UNKNOWN_WAF)
                .union(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE),
        )
    {
        return false;
    }

    if prefetch_candidate_requires_wear_or_cost(signal.candidate, signal.target_media)
        && signal.flags.contains_all(WorkloadSignalFlags::UNKNOWN_WAF)
    {
        return false;
    }

    if prefetch_candidate_requires_egress_or_restore_cost(signal.candidate, signal.target_media)
        && signal
            .flags
            .contains_all(WorkloadSignalFlags::UNKNOWN_EGRESS_OR_RESTORE_COST)
    {
        return false;
    }

    workload_signal_has_materialization_evidence(signal)
        && workload_signal_has_collection_cost(signal)
}

/// Returns true when a learned result may transfer between two signal records.
#[must_use]
pub const fn workload_signal_same_learning_envelope(
    left: WorkloadSignalRecord,
    right: WorkloadSignalRecord,
) -> bool {
    bytes16_equal(left.policy_id.0, right.policy_id.0)
        && left.policy_revision.0 == right.policy_revision.0
        && bytes16_equal(left.pool_id.0, right.pool_id.0)
        && bytes16_equal(left.scope.dataset_id.0, right.scope.dataset_id.0)
        && bytes16_equal(left.budget_owner.0, right.budget_owner.0)
        && left.access_pattern as u8 == right.access_pattern as u8
        && left.source_media as u8 == right.source_media as u8
        && left.target_media as u8 == right.target_media as u8
        && evidence_ref_equal(left.service_objective_ref, right.service_objective_ref)
        && evidence_ref_equal(left.topology_ref, right.topology_ref)
        && evidence_ref_equal(left.source_media_ref, right.source_media_ref)
        && evidence_ref_equal(left.target_media_ref, right.target_media_ref)
}

/// Lower a requested prefetch/residency candidate according to signal quality.
#[must_use]
pub const fn workload_signal_lowered_candidate(
    signal: WorkloadSignalRecord,
) -> PrefetchResidencyCandidateClass {
    if signal.refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return PrefetchResidencyCandidateClass::Refused;
    }

    match signal.access_pattern {
        AccessPatternClass::DatabaseWalFsync
        | AccessPatternClass::SyncSmallWrite
        | AccessPatternClass::AsyncBulkWrite
        | AccessPatternClass::OverwriteChurn
        | AccessPatternClass::AppendLog => {
            if !matches!(
                signal.candidate,
                PrefetchResidencyCandidateClass::NoPrefetch
                    | PrefetchResidencyCandidateClass::NeedMoreEvidence
                    | PrefetchResidencyCandidateClass::Refused
            ) {
                return PrefetchResidencyCandidateClass::NoPrefetch;
            }
        }
        AccessPatternClass::BackupRestoreScan | AccessPatternClass::OnePassScan => {
            if !matches!(
                signal.candidate,
                PrefetchResidencyCandidateClass::NoPrefetch
                    | PrefetchResidencyCandidateClass::NeedMoreEvidence
                    | PrefetchResidencyCandidateClass::Refused
            ) {
                return PrefetchResidencyCandidateClass::BoundedReadahead;
            }
        }
        AccessPatternClass::VmImageMixedRead | AccessPatternClass::MmapPageCacheReuse => {
            if !matches!(
                signal.candidate,
                PrefetchResidencyCandidateClass::NoPrefetch
                    | PrefetchResidencyCandidateClass::NeedMoreEvidence
                    | PrefetchResidencyCandidateClass::Refused
            ) {
                return PrefetchResidencyCandidateClass::CacheOnlyTrial;
            }
        }
        AccessPatternClass::PhaseChangingSparse | AccessPatternClass::NoisyAdversarial => {
            if !matches!(
                signal.candidate,
                PrefetchResidencyCandidateClass::NoPrefetch
                    | PrefetchResidencyCandidateClass::NeedMoreEvidence
                    | PrefetchResidencyCandidateClass::Refused
            ) {
                return PrefetchResidencyCandidateClass::Cooldown;
            }
        }
        _ => {}
    }

    if matches!(
        signal.contradiction,
        ContradictionState::StrongContradiction | ContradictionState::Refused
    ) || signal.flags.intersects(
        WorkloadSignalFlags::CONTRADICTED.union(WorkloadSignalFlags::COMPACTED_BEYOND_AUTHORITY),
    ) {
        return PrefetchResidencyCandidateClass::Refused;
    }

    if signal.flags.intersects(
        WorkloadSignalFlags::PHASE_CHANGE
            .union(WorkloadSignalFlags::NOISY_NEIGHBOR)
            .union(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE),
    ) {
        return PrefetchResidencyCandidateClass::Cooldown;
    }

    if signal
        .flags
        .contains_all(WorkloadSignalFlags::UNKNOWN_COLLECTION_COST)
        || signal
            .flags
            .contains_all(WorkloadSignalFlags::UNKNOWN_EGRESS_OR_RESTORE_COST)
    {
        return match signal.access_pattern {
            AccessPatternClass::SequentialRead
            | AccessPatternClass::OnePassScan
            | AccessPatternClass::BackupRestoreScan => {
                PrefetchResidencyCandidateClass::BoundedReadahead
            }
            AccessPatternClass::StridedRead | AccessPatternClass::VectorRead => {
                PrefetchResidencyCandidateClass::StridedVectorPrefetch
            }
            AccessPatternClass::SmallRandomHotset
            | AccessPatternClass::VmImageMixedRead
            | AccessPatternClass::MmapPageCacheReuse => {
                PrefetchResidencyCandidateClass::CacheOnlyTrial
            }
            _ => PrefetchResidencyCandidateClass::NoPrefetch,
        };
    }

    if !workload_signal_can_train_upward(signal) {
        return match signal.access_pattern {
            AccessPatternClass::SequentialRead
            | AccessPatternClass::OnePassScan
            | AccessPatternClass::BackupRestoreScan => {
                PrefetchResidencyCandidateClass::BoundedReadahead
            }
            AccessPatternClass::StridedRead | AccessPatternClass::VectorRead => {
                PrefetchResidencyCandidateClass::StridedVectorPrefetch
            }
            AccessPatternClass::MetadataNamespace => {
                PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
            }
            AccessPatternClass::ManifestIndexFanout => {
                PrefetchResidencyCandidateClass::ManifestIndexPrefetch
            }
            AccessPatternClass::SnapshotCloneRepeat => {
                PrefetchResidencyCandidateClass::SnapshotClonePrefetch
            }
            AccessPatternClass::DegradedReconstruction => {
                PrefetchResidencyCandidateClass::DegradedReadPrefetch
            }
            AccessPatternClass::WanGeoDelta => PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            AccessPatternClass::ObjectArchiveRestore => {
                PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
            }
            AccessPatternClass::SmallRandomHotset
            | AccessPatternClass::VmImageMixedRead
            | AccessPatternClass::MmapPageCacheReuse => {
                PrefetchResidencyCandidateClass::CacheOnlyTrial
            }
            AccessPatternClass::DatabaseWalFsync
            | AccessPatternClass::SyncSmallWrite
            | AccessPatternClass::AsyncBulkWrite
            | AccessPatternClass::OverwriteChurn
            | AccessPatternClass::AppendLog => PrefetchResidencyCandidateClass::NoPrefetch,
            AccessPatternClass::PhaseChangingSparse | AccessPatternClass::NoisyAdversarial => {
                PrefetchResidencyCandidateClass::Cooldown
            }
            _ => PrefetchResidencyCandidateClass::NoPrefetch,
        };
    }

    signal.candidate
}

/// Map a concrete media class to the residency state it can represent.
#[must_use]
pub const fn prefetch_residency_state_for_media(
    media: StorageMediaClass,
) -> PrefetchResidencyStateClass {
    match media {
        StorageMediaClass::SystemRam | StorageMediaClass::RemoteRam => {
            PrefetchResidencyStateClass::CacheOnlyRam
        }
        StorageMediaClass::PersistentMemory => PrefetchResidencyStateClass::PmemDurable,
        StorageMediaClass::NvmeFlash
        | StorageMediaClass::SsdFlash
        | StorageMediaClass::ZonedFlash => PrefetchResidencyStateClass::FlashHotServing,
        StorageMediaClass::HddRotational | StorageMediaClass::ZonedHdd => {
            PrefetchResidencyStateClass::HddColdLocalityOptimized
        }
        StorageMediaClass::ObjectAppliance | StorageMediaClass::CloudObject => {
            PrefetchResidencyStateClass::RemoteDurable
        }
        StorageMediaClass::OpticalArchive | StorageMediaClass::TapeArchive => {
            PrefetchResidencyStateClass::ObjectArchiveStaged
        }
    }
}

/// Map a selected candidate and target media to its non-executed residency class.
#[must_use]
pub const fn prefetch_residency_candidate_state(
    candidate: PrefetchResidencyCandidateClass,
    target_media: StorageMediaClass,
) -> PrefetchResidencyStateClass {
    match candidate {
        PrefetchResidencyCandidateClass::NoPrefetch
        | PrefetchResidencyCandidateClass::NeedMoreEvidence
        | PrefetchResidencyCandidateClass::Cooldown => PrefetchResidencyStateClass::Unknown,
        PrefetchResidencyCandidateClass::Refused => PrefetchResidencyStateClass::Refused,
        PrefetchResidencyCandidateClass::BoundedReadahead
        | PrefetchResidencyCandidateClass::StridedVectorPrefetch
        | PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
        | PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
        | PrefetchResidencyCandidateClass::ManifestIndexPrefetch
        | PrefetchResidencyCandidateClass::SnapshotClonePrefetch
        | PrefetchResidencyCandidateClass::DegradedReadPrefetch
        | PrefetchResidencyCandidateClass::CacheOnlyTrial => {
            PrefetchResidencyStateClass::CacheOnlyRam
        }
        PrefetchResidencyCandidateClass::VolatileRamTrial => {
            PrefetchResidencyStateClass::VolatileRamServingTrial
        }
        PrefetchResidencyCandidateClass::IntentBackedRam => {
            PrefetchResidencyStateClass::IntentBackedRam
        }
        PrefetchResidencyCandidateClass::PmemDurable => PrefetchResidencyStateClass::PmemDurable,
        PrefetchResidencyCandidateClass::FlashHotServing => {
            PrefetchResidencyStateClass::FlashHotServing
        }
        PrefetchResidencyCandidateClass::HddLocalityOptimized => {
            PrefetchResidencyStateClass::HddColdLocalityOptimized
        }
        PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch => {
            PrefetchResidencyStateClass::WanGeoAsync
        }
        PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage => {
            PrefetchResidencyStateClass::ObjectArchiveStaged
        }
        PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
        | PrefetchResidencyCandidateClass::DemotionCandidate => {
            prefetch_residency_state_for_media(target_media)
        }
    }
}

const fn prefetch_residency_record(
    context: PrefetchResidencyDecisionContext,
    selected_candidate: PrefetchResidencyCandidateClass,
    outcome: PrefetchResidencyDecisionOutcome,
    refusal: StorageIntentRefusalReason,
) -> PrefetchResidencyDecisionRecord {
    PrefetchResidencyDecisionRecord {
        policy_id: context.policy.policy_id,
        policy_revision: context.policy.policy_revision,
        scope: context.signal.scope,
        pool_id: context.policy.pool_id,
        budget_owner: context.policy.budget_owner,
        access_pattern: context.signal.access_pattern,
        confidence: context.signal.confidence,
        requested_candidate: context.signal.candidate,
        selected_candidate,
        selected_residency: prefetch_residency_candidate_state(
            selected_candidate,
            context.signal.target_media,
        ),
        outcome,
        refusal,
        source_media: context.signal.source_media,
        target_media: context.signal.target_media,
        source_media_ref: context.signal.source_media_ref,
        target_media_ref: context.signal.target_media_ref,
        topology_ref: context.signal.topology_ref,
        max_prefetch_window_bytes: context.policy.max_prefetch_window_bytes,
        max_staging_bytes: context.policy.max_staging_bytes,
        evidence_refs: context.policy.evidence_refs,
    }
}

const fn prefetch_residency_policy_is_dataset_scoped(
    context: PrefetchResidencyDecisionContext,
) -> bool {
    matches!(
        context.policy.policy_scope,
        PrefetchResidencyPolicyScope::Dataset | PrefetchResidencyPolicyScope::SubjectRange
    ) && !context.policy.dataset_id.is_zero()
        && bytes16_equal(context.policy.policy_id.0, context.signal.policy_id.0)
        && context.policy.policy_revision.0 == context.signal.policy_revision.0
        && bytes16_equal(context.policy.pool_id.0, context.signal.pool_id.0)
        && bytes16_equal(
            context.policy.dataset_id.0,
            context.signal.scope.dataset_id.0,
        )
        && bytes16_equal(context.policy.budget_owner.0, context.signal.budget_owner.0)
}

const fn prefetch_residency_fallback_candidate(
    policy: PrefetchResidencyPolicyEnvelope,
    signal: WorkloadSignalRecord,
) -> PrefetchResidencyCandidateClass {
    let pattern_candidate = match signal.access_pattern {
        AccessPatternClass::SequentialRead
        | AccessPatternClass::OnePassScan
        | AccessPatternClass::BackupRestoreScan => {
            PrefetchResidencyCandidateClass::BoundedReadahead
        }
        AccessPatternClass::StridedRead | AccessPatternClass::VectorRead => {
            PrefetchResidencyCandidateClass::StridedVectorPrefetch
        }
        AccessPatternClass::MetadataNamespace => {
            PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
        }
        AccessPatternClass::ManifestIndexFanout => {
            PrefetchResidencyCandidateClass::ManifestIndexPrefetch
        }
        AccessPatternClass::SnapshotCloneRepeat => {
            PrefetchResidencyCandidateClass::SnapshotClonePrefetch
        }
        AccessPatternClass::DegradedReconstruction => {
            PrefetchResidencyCandidateClass::DegradedReadPrefetch
        }
        AccessPatternClass::WanGeoDelta => PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
        AccessPatternClass::ObjectArchiveRestore => {
            PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
        }
        AccessPatternClass::SmallRandomHotset
        | AccessPatternClass::VmImageMixedRead
        | AccessPatternClass::MmapPageCacheReuse => PrefetchResidencyCandidateClass::CacheOnlyTrial,
        AccessPatternClass::DatabaseWalFsync
        | AccessPatternClass::SyncSmallWrite
        | AccessPatternClass::AsyncBulkWrite
        | AccessPatternClass::OverwriteChurn
        | AccessPatternClass::AppendLog => PrefetchResidencyCandidateClass::NoPrefetch,
        AccessPatternClass::PhaseChangingSparse | AccessPatternClass::NoisyAdversarial => {
            PrefetchResidencyCandidateClass::Cooldown
        }
        _ => PrefetchResidencyCandidateClass::NoPrefetch,
    };

    if policy.allowed_actions.contains_candidate(pattern_candidate) {
        return pattern_candidate;
    }
    if policy
        .allowed_actions
        .contains_candidate(PrefetchResidencyCandidateClass::CacheOnlyTrial)
    {
        return PrefetchResidencyCandidateClass::CacheOnlyTrial;
    }
    if policy
        .allowed_actions
        .contains_candidate(PrefetchResidencyCandidateClass::BoundedReadahead)
    {
        return PrefetchResidencyCandidateClass::BoundedReadahead;
    }
    if policy
        .allowed_actions
        .contains_candidate(PrefetchResidencyCandidateClass::NoPrefetch)
    {
        return PrefetchResidencyCandidateClass::NoPrefetch;
    }
    PrefetchResidencyCandidateClass::Refused
}

/// Apply dataset policy to a signal-derived prefetch/residency candidate.
#[must_use]
pub const fn prefetch_residency_policy_candidate(
    policy: PrefetchResidencyPolicyEnvelope,
    signal: WorkloadSignalRecord,
) -> PrefetchResidencyCandidateClass {
    let lowered = workload_signal_lowered_candidate(signal);
    if policy.allowed_actions.contains_candidate(lowered) {
        return lowered;
    }
    if matches!(
        lowered,
        PrefetchResidencyCandidateClass::Refused
            | PrefetchResidencyCandidateClass::NeedMoreEvidence
            | PrefetchResidencyCandidateClass::Cooldown
            | PrefetchResidencyCandidateClass::NoPrefetch
    ) {
        return lowered;
    }
    prefetch_residency_fallback_candidate(policy, signal)
}

const fn prefetch_residency_candidate_target_role(
    candidate: PrefetchResidencyCandidateClass,
) -> StorageMediaRole {
    match candidate {
        PrefetchResidencyCandidateClass::VolatileRamTrial => StorageMediaRole::RamCache,
        PrefetchResidencyCandidateClass::IntentBackedRam => {
            StorageMediaRole::RamIntentBackedAuthority
        }
        PrefetchResidencyCandidateClass::PmemDurable
        | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate => {
            StorageMediaRole::PlacementAuthority
        }
        PrefetchResidencyCandidateClass::FlashHotServing
        | PrefetchResidencyCandidateClass::HddLocalityOptimized => StorageMediaRole::ServingDataHot,
        PrefetchResidencyCandidateClass::DemotionCandidate => StorageMediaRole::BulkDataCold,
        PrefetchResidencyCandidateClass::DegradedReadPrefetch => StorageMediaRole::RepairTemp,
        PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage => StorageMediaRole::ArchiveEc,
        PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch => StorageMediaRole::GeoAsyncReplica,
        _ => StorageMediaRole::ReadCache,
    }
}

const fn prefetch_residency_candidate_ack_floor(
    candidate: PrefetchResidencyCandidateClass,
) -> StorageIntentGuaranteeClass {
    match candidate {
        PrefetchResidencyCandidateClass::IntentBackedRam => {
            StorageIntentGuaranteeClass::LocalIntent
        }
        PrefetchResidencyCandidateClass::PmemDurable
        | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
        | PrefetchResidencyCandidateClass::DemotionCandidate => {
            StorageIntentGuaranteeClass::FullPlacement
        }
        PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch => {
            StorageIntentGuaranteeClass::GeoAsync
        }
        PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage => {
            StorageIntentGuaranteeClass::ArchiveEc
        }
        _ => StorageIntentGuaranteeClass::VolatileLocal,
    }
}

const fn prefetch_residency_decision_outcome(
    requested: PrefetchResidencyCandidateClass,
    selected: PrefetchResidencyCandidateClass,
) -> PrefetchResidencyDecisionOutcome {
    if selected as u8 != requested as u8 {
        return match selected {
            PrefetchResidencyCandidateClass::NoPrefetch => {
                PrefetchResidencyDecisionOutcome::NoAction
            }
            PrefetchResidencyCandidateClass::Cooldown => PrefetchResidencyDecisionOutcome::Cooldown,
            PrefetchResidencyCandidateClass::NeedMoreEvidence => {
                PrefetchResidencyDecisionOutcome::NeedMoreEvidence
            }
            PrefetchResidencyCandidateClass::Refused => PrefetchResidencyDecisionOutcome::Refused,
            _ => PrefetchResidencyDecisionOutcome::Lowered,
        };
    }

    match selected {
        PrefetchResidencyCandidateClass::NoPrefetch => PrefetchResidencyDecisionOutcome::NoAction,
        PrefetchResidencyCandidateClass::BoundedReadahead
        | PrefetchResidencyCandidateClass::StridedVectorPrefetch
        | PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
        | PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
        | PrefetchResidencyCandidateClass::ManifestIndexPrefetch
        | PrefetchResidencyCandidateClass::SnapshotClonePrefetch
        | PrefetchResidencyCandidateClass::DegradedReadPrefetch
        | PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
        | PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
        | PrefetchResidencyCandidateClass::CacheOnlyTrial => {
            PrefetchResidencyDecisionOutcome::CacheOnly
        }
        PrefetchResidencyCandidateClass::VolatileRamTrial
        | PrefetchResidencyCandidateClass::FlashHotServing
        | PrefetchResidencyCandidateClass::HddLocalityOptimized => {
            PrefetchResidencyDecisionOutcome::ServingTrial
        }
        PrefetchResidencyCandidateClass::IntentBackedRam
        | PrefetchResidencyCandidateClass::PmemDurable
        | PrefetchResidencyCandidateClass::AuthorityPromotionCandidate => {
            PrefetchResidencyDecisionOutcome::PromotionCandidate
        }
        PrefetchResidencyCandidateClass::DemotionCandidate => {
            PrefetchResidencyDecisionOutcome::DemotionCandidate
        }
        PrefetchResidencyCandidateClass::Cooldown => PrefetchResidencyDecisionOutcome::Cooldown,
        PrefetchResidencyCandidateClass::NeedMoreEvidence => {
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence
        }
        PrefetchResidencyCandidateClass::Refused => PrefetchResidencyDecisionOutcome::Refused,
    }
}

const fn prefetch_residency_required_refusal(
    context: PrefetchResidencyDecisionContext,
    candidate: PrefetchResidencyCandidateClass,
) -> StorageIntentRefusalReason {
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE)
        && !evidence_ref_has_id(context.policy.evidence_refs.service_objective_ref)
        && !evidence_ref_has_id(context.signal.service_objective_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY)
        && (!evidence_ref_has_id(context.policy.evidence_refs.evidence_query_ref)
            || !evidence_ref_has_id(context.policy.evidence_refs.decision_frontier_ref))
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION)
        && !evidence_ref_has_id(context.policy.evidence_refs.scheduler_admission_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
        && !evidence_ref_has_id(context.policy.evidence_refs.transport_budget_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN)
        && !evidence_ref_has_id(context.policy.evidence_refs.trust_domain_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE)
        && !evidence_ref_has_id(context.policy.evidence_refs.capacity_reserve_ref)
    {
        return StorageIntentRefusalReason::NoLegalReceiptSet;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION)
        && !evidence_ref_has_id(context.policy.evidence_refs.tenant_isolation_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
        && !matches!(
            candidate,
            PrefetchResidencyCandidateClass::NoPrefetch
                | PrefetchResidencyCandidateClass::NeedMoreEvidence
                | PrefetchResidencyCandidateClass::Refused
        )
        && !evidence_ref_has_id(context.policy.evidence_refs.read_serving_boundary_ref)
    {
        return StorageIntentRefusalReason::CacheCannotBeAuthority;
    }
    if prefetch_candidate_changes_authority(candidate)
        && context
            .policy
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
        && !evidence_ref_has_id(context.policy.evidence_refs.relocation_boundary_ref)
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if (context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
        || prefetch_candidate_requires_wear_or_cost(candidate, context.signal.target_media))
        && (!evidence_ref_has_id(context.policy.evidence_refs.cost_wear_ref)
            || !evidence_ref_has_id(context.cost_wear.evidence))
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if (context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
        || prefetch_candidate_requires_egress_or_restore_cost(
            candidate,
            context.signal.target_media,
        ))
        && (!evidence_ref_has_id(context.policy.evidence_refs.egress_restore_cost_ref)
            || context
                .signal
                .flags
                .contains_all(WorkloadSignalFlags::UNKNOWN_EGRESS_OR_RESTORE_COST))
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    StorageIntentRefusalReason::None
}

const fn prefetch_residency_cost_refusal(
    context: PrefetchResidencyDecisionContext,
    candidate: PrefetchResidencyCandidateClass,
) -> StorageIntentRefusalReason {
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::PROTECT_FOREGROUND_TAIL)
        && context
            .signal
            .flags
            .contains_all(WorkloadSignalFlags::FOREGROUND_TAIL_PRESSURE)
    {
        return StorageIntentRefusalReason::MovementDebtNotPaidBack;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::PROTECT_FLASH_LIFETIME)
        && prefetch_candidate_requires_wear_or_cost(candidate, context.signal.target_media)
        && (context
            .signal
            .flags
            .contains_all(WorkloadSignalFlags::UNKNOWN_WAF)
            || (context.cost_wear.expected_write_bytes > 0
                && context.cost_wear.write_amplification_ppm == 0))
    {
        return StorageIntentRefusalReason::EvidenceNotUsable;
    }
    if prefetch_candidate_requires_wear_or_cost(candidate, context.signal.target_media)
        && context.cost_wear.flash_wear_cost_ppm == u32::MAX
    {
        return StorageIntentRefusalReason::FlashWearBudgetExceeded;
    }
    if (prefetch_candidate_changes_authority(candidate)
        || matches!(
            candidate,
            PrefetchResidencyCandidateClass::FlashHotServing
                | PrefetchResidencyCandidateClass::PmemDurable
        ))
        && context
            .policy
            .flags
            .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT)
        && (!evidence_ref_has_id(context.cost_wear.payback_evidence)
            || context.cost_wear.payback_window_ms == 0
            || !matches!(context.cost_wear.skipped_reason, SkippedMoveReason::None))
    {
        return match context.cost_wear.skipped_reason {
            SkippedMoveReason::FlashWearBudgetExceeded => {
                StorageIntentRefusalReason::FlashWearBudgetExceeded
            }
            SkippedMoveReason::ReceiptWouldWeaken => StorageIntentRefusalReason::ReceiptWouldWeaken,
            _ => StorageIntentRefusalReason::MovementDebtNotPaidBack,
        };
    }
    StorageIntentRefusalReason::None
}

const fn prefetch_residency_media_refusal(
    context: PrefetchResidencyDecisionContext,
    candidate: PrefetchResidencyCandidateClass,
) -> StorageIntentRefusalReason {
    if matches!(
        candidate,
        PrefetchResidencyCandidateClass::NoPrefetch
            | PrefetchResidencyCandidateClass::NeedMoreEvidence
            | PrefetchResidencyCandidateClass::Refused
            | PrefetchResidencyCandidateClass::Cooldown
    ) {
        return StorageIntentRefusalReason::None;
    }
    if context.source_media.media_class as u8 != context.signal.source_media as u8
        || context.target_media.media_class as u8 != context.signal.target_media as u8
    {
        return StorageIntentRefusalReason::MissingMediaCapabilityEvidence;
    }
    if context
        .policy
        .flags
        .contains_all(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
    {
        let source_freshness = media_capability_freshness_satisfies(context.source_media);
        if !source_freshness.satisfied {
            return source_freshness.refusal;
        }
    }

    let role = prefetch_residency_candidate_target_role(candidate);
    let role_requirement = MediaRoleRequirement {
        allowed_roles: MediaRoleMask::from_role(role),
        require_authority_role: prefetch_candidate_changes_authority(candidate),
    };
    let target = media_capability_satisfies_role(
        role_requirement,
        prefetch_residency_candidate_ack_floor(candidate),
        role,
        context.target_media,
    );
    if !target.satisfied {
        return target.refusal;
    }
    StorageIntentRefusalReason::None
}

/// Decide the #967 prefetch/residency action for one dataset/range envelope.
#[must_use]
pub const fn prefetch_residency_decide(
    context: PrefetchResidencyDecisionContext,
) -> PrefetchResidencyDecisionRecord {
    if !prefetch_residency_policy_is_dataset_scoped(context) {
        return prefetch_residency_record(
            context,
            PrefetchResidencyCandidateClass::Refused,
            PrefetchResidencyDecisionOutcome::Refused,
            StorageIntentRefusalReason::EvidenceNotUsable,
        );
    }

    let selected = prefetch_residency_policy_candidate(context.policy, context.signal);
    if matches!(selected, PrefetchResidencyCandidateClass::Refused) {
        let refusal = if context.signal.refusal as u16 != StorageIntentRefusalReason::None as u16 {
            context.signal.refusal
        } else {
            StorageIntentRefusalReason::NoLegalReceiptSet
        };
        return prefetch_residency_record(
            context,
            selected,
            PrefetchResidencyDecisionOutcome::Refused,
            refusal,
        );
    }
    if matches!(selected, PrefetchResidencyCandidateClass::NoPrefetch) {
        return prefetch_residency_record(
            context,
            selected,
            PrefetchResidencyDecisionOutcome::NoAction,
            StorageIntentRefusalReason::None,
        );
    }

    let ref_refusal = prefetch_residency_required_refusal(context, selected);
    if ref_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return prefetch_residency_record(
            context,
            PrefetchResidencyCandidateClass::NeedMoreEvidence,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence,
            ref_refusal,
        );
    }
    let cost_refusal = prefetch_residency_cost_refusal(context, selected);
    if cost_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return prefetch_residency_record(
            context,
            PrefetchResidencyCandidateClass::Cooldown,
            PrefetchResidencyDecisionOutcome::Cooldown,
            cost_refusal,
        );
    }
    let media_refusal = prefetch_residency_media_refusal(context, selected);
    if media_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return prefetch_residency_record(
            context,
            PrefetchResidencyCandidateClass::NeedMoreEvidence,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence,
            media_refusal,
        );
    }

    prefetch_residency_record(
        context,
        selected,
        prefetch_residency_decision_outcome(context.signal.candidate, selected),
        StorageIntentRefusalReason::None,
    )
}

/// Returns true when the decision remains speculative/cache-only.
#[must_use]
pub const fn prefetch_residency_decision_is_cache_only(
    decision: PrefetchResidencyDecisionRecord,
) -> bool {
    matches!(
        decision.selected_candidate,
        PrefetchResidencyCandidateClass::BoundedReadahead
            | PrefetchResidencyCandidateClass::StridedVectorPrefetch
            | PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
            | PrefetchResidencyCandidateClass::SmallRandomHotsetTrial
            | PrefetchResidencyCandidateClass::ManifestIndexPrefetch
            | PrefetchResidencyCandidateClass::SnapshotClonePrefetch
            | PrefetchResidencyCandidateClass::DegradedReadPrefetch
            | PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
            | PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
            | PrefetchResidencyCandidateClass::CacheOnlyTrial
    )
}

/// Returns true only for decisions that may be handed to relocation authority.
#[must_use]
pub const fn prefetch_residency_decision_may_request_authority_change(
    decision: PrefetchResidencyDecisionRecord,
) -> bool {
    decision.refusal as u16 == StorageIntentRefusalReason::None as u16
        && matches!(
            decision.outcome,
            PrefetchResidencyDecisionOutcome::PromotionCandidate
                | PrefetchResidencyDecisionOutcome::DemotionCandidate
        )
        && prefetch_candidate_changes_authority(decision.selected_candidate)
}

/// Planner/action class. These are optimizer intents, not proof of success.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionClass {
    #[default]
    QueuePrefetchTuning = 0,
    CacheOnlyServingTrial = 1,
    NewWriteShaping = 2,
    FlashServingPromotion = 3,
    AuthorityPromotion = 4,
    DurablePlacementMovement = 5,
    ReadSourceRefresh = 6,
    DegradedReadReconstruction = 7,
    ReadTriggeredRepair = 8,
    DefragRepack = 9,
    ReclaimRelocation = 10,
    GeoCatchup = 11,
    ArchiveMigration = 12,
}

/// Execution step for an authority-changing storage-intent action.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionExecutionStepState {
    #[default]
    Unknown = 0,
    Planned = 1,
    Admitted = 2,
    Prepared = 3,
    Copying = 4,
    Verifying = 5,
    Publishing = 6,
    Cutover = 7,
    RetiringSource = 8,
    Complete = 9,
    Aborted = 10,
    RolledBack = 11,
    Refused = 12,
}

impl StorageIntentActionExecutionStepState {
    /// Returns true when the step can still be retried after a crash.
    #[must_use]
    pub const fn requires_idempotent_replay(self) -> bool {
        !matches!(self, Self::Unknown)
    }

    /// Returns true after target bytes may have been written.
    #[must_use]
    pub const fn requires_source_protection(self) -> bool {
        matches!(
            self,
            Self::Admitted
                | Self::Prepared
                | Self::Copying
                | Self::Verifying
                | Self::Publishing
                | Self::Cutover
                | Self::RetiringSource
                | Self::Complete
                | Self::Aborted
                | Self::RolledBack
        )
    }

    /// Returns true when target-write evidence must be verified.
    #[must_use]
    pub const fn requires_target_verification(self) -> bool {
        matches!(
            self,
            Self::Verifying
                | Self::Publishing
                | Self::Cutover
                | Self::RetiringSource
                | Self::Complete
        )
    }

    /// Returns true when publication/cutover evidence must exist.
    #[must_use]
    pub const fn requires_publication_boundary(self) -> bool {
        matches!(
            self,
            Self::Publishing | Self::Cutover | Self::RetiringSource | Self::Complete
        )
    }

    /// Returns true when abort or rollback proof must remain visible.
    #[must_use]
    pub const fn requires_abort_or_rollback_proof(self) -> bool {
        matches!(self, Self::Aborted | Self::RolledBack | Self::Refused)
    }

    /// Returns true when this step can be final action-completion evidence.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Replay state recorded for crash recovery and duplicate delivery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionReplayState {
    #[default]
    Unknown = 0,
    FirstAttempt = 1,
    RetryInProgress = 2,
    CrashRecovery = 3,
    DuplicateSuppressed = 4,
    ReplayRefused = 5,
}

/// Staleness or invalidation class for execution evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionEvidenceState {
    #[default]
    Unknown = 0,
    Fresh = 1,
    DecisionFrontierStale = 2,
    PolicyRevisionChanged = 3,
    MediaCapabilityChanged = 4,
    CapacityReserveChanged = 5,
    MembershipChanged = 6,
    TrustChanged = 7,
    TemporalExpired = 8,
    EvidenceRetentionCompacted = 9,
}

impl StorageIntentActionEvidenceState {
    /// Returns true when the action may continue without revalidation.
    #[must_use]
    pub const fn is_fresh_for_execution(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// Source-retirement state guarded by action-execution evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentSourceRetirementState {
    #[default]
    Unknown = 0,
    Forbidden = 1,
    RetainedForRollback = 2,
    PendingCompletion = 3,
    Ready = 4,
    Retired = 5,
}

impl StorageIntentSourceRetirementState {
    /// Returns true when source receipts are still protected from retirement.
    #[must_use]
    pub const fn forbids_retirement(self) -> bool {
        matches!(
            self,
            Self::Unknown | Self::Forbidden | Self::RetainedForRollback | Self::PendingCompletion
        )
    }
}

/// Target-copy verification state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionTargetVerificationState {
    #[default]
    Unknown = 0,
    NotStarted = 1,
    PartialWrite = 2,
    DigestMismatch = 3,
    DegradedPartial = 4,
    Verified = 5,
    Refused = 6,
}

impl StorageIntentActionTargetVerificationState {
    /// Returns true when target bytes are verified as complete authority input.
    #[must_use]
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }
}

/// Publication and cutover state for replacement receipts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionPublicationState {
    #[default]
    Unknown = 0,
    NotPublished = 1,
    ReplacementPublished = 2,
    CutoverVisible = 3,
    SourceRetirementPublished = 4,
    NoCutover = 5,
}

impl StorageIntentActionPublicationState {
    /// Returns true when a replacement publication boundary exists.
    #[must_use]
    pub const fn has_replacement_publication(self) -> bool {
        matches!(
            self,
            Self::ReplacementPublished | Self::CutoverVisible | Self::SourceRetirementPublished
        )
    }
}

/// Action-execution refusal detail.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentActionExecutionRefusalReason {
    #[default]
    None = 0,
    MissingActionIdentity = 1,
    PlannerDecisionIsNotExecution = 2,
    MissingDecisionAdmissionEvidence = 3,
    StaleExecutionEvidence = 4,
    NonIdempotentReplay = 5,
    DuplicateActionDelivery = 6,
    MissingSourceProtection = 7,
    TargetWriteIsNotCompletion = 8,
    MissingTargetVerification = 9,
    PartialTargetWrite = 10,
    MissingMediaFlushOrBarrierProof = 11,
    MissingPublicationEvidence = 12,
    MissingOrderingEvidence = 13,
    MissingRecoveryDegradationEvidence = 14,
    MissingRetentionEvidence = 15,
    MissingActionCompletionEvidence = 16,
    SourceRetirementForbidden = 17,
    ReserveExhausted = 18,
    ReserveDoubleSpent = 19,
    AbortRollbackIncomplete = 20,
    NoCutoverProofMissing = 21,
    ContradictoryReceiptPublication = 22,
    RefusedByActionEvidence = 23,
}

impl StorageIntentActionExecutionRefusalReason {
    /// Map action-specific refusal to the shared policy/refusal vocabulary.
    #[must_use]
    pub const fn to_storage_intent_refusal(self) -> StorageIntentRefusalReason {
        match self {
            Self::None => StorageIntentRefusalReason::None,
            Self::NonIdempotentReplay => StorageIntentRefusalReason::NonIdempotentReplay,
            Self::MissingOrderingEvidence => StorageIntentRefusalReason::MissingOrderingEvidence,
            Self::MissingMediaFlushOrBarrierProof => {
                StorageIntentRefusalReason::UnsupportedFlushFuaSemantics
            }
            Self::ReserveExhausted | Self::ReserveDoubleSpent => {
                StorageIntentRefusalReason::MovementDebtNotPaidBack
            }
            Self::SourceRetirementForbidden | Self::ContradictoryReceiptPublication => {
                StorageIntentRefusalReason::ReceiptWouldWeaken
            }
            _ => StorageIntentRefusalReason::EvidenceNotUsable,
        }
    }
}

/// Action-execution proof dimensions present in one evidence record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionExecutionFlags(pub u64);

impl StorageIntentActionExecutionFlags {
    pub const EMPTY: Self = Self(0);
    pub const ACTION_IDENTITY: Self = Self(1_u64 << 0);
    pub const DECISION_FRONTIER_REF: Self = Self(1_u64 << 1);
    pub const HARD_GATE_REF: Self = Self(1_u64 << 2);
    pub const SELECTED_CANDIDATE_REF: Self = Self(1_u64 << 3);
    pub const COUNTERFACTUAL_PAYBACK_REF: Self = Self(1_u64 << 4);
    pub const RESERVE_ADMISSION_REF: Self = Self(1_u64 << 5);
    pub const ISOLATION_REF: Self = Self(1_u64 << 6);
    pub const MEDIA_CAPABILITY_REF: Self = Self(1_u64 << 7);
    pub const RETENTION_REF: Self = Self(1_u64 << 8);
    pub const IDEMPOTENCY_KEY: Self = Self(1_u64 << 9);
    pub const STEP_SEQUENCE: Self = Self(1_u64 << 10);
    pub const CRASH_RECOVERY_MARKER: Self = Self(1_u64 << 11);
    pub const DUPLICATE_SUPPRESSION: Self = Self(1_u64 << 12);
    pub const SOURCE_RECEIPTS: Self = Self(1_u64 << 13);
    pub const ROLLBACK_SOURCES_RETAINED: Self = Self(1_u64 << 14);
    pub const READ_SERVING_ELIGIBILITY: Self = Self(1_u64 << 15);
    pub const FORBID_SOURCE_RETIREMENT_UNTIL_COMPLETE: Self = Self(1_u64 << 16);
    pub const TARGET_RECEIPT_CANDIDATE: Self = Self(1_u64 << 17);
    pub const TARGET_DIGEST_INTEGRITY: Self = Self(1_u64 << 18);
    pub const MEDIA_FLUSH_BARRIER: Self = Self(1_u64 << 19);
    pub const RECONSTRUCTION_WIDTH: Self = Self(1_u64 << 20);
    pub const REPLACEMENT_PUBLICATION: Self = Self(1_u64 << 21);
    pub const PUBLICATION_ORDERING: Self = Self(1_u64 << 22);
    pub const RECOVERY_DEGRADATION_REF: Self = Self(1_u64 << 23);
    pub const POLICY_ROLLOUT_REF: Self = Self(1_u64 << 24);
    pub const VISIBLE_CONVERGING_STATE: Self = Self(1_u64 << 25);
    pub const OPERATOR_EXPLANATION_REF: Self = Self(1_u64 << 26);
    pub const ABORT_REASON: Self = Self(1_u64 << 27);
    pub const PARTIAL_TARGET_CLEANUP: Self = Self(1_u64 << 28);
    pub const ROLLBACK_COMPLETION: Self = Self(1_u64 << 29);
    pub const NO_CUTOVER_PROOF: Self = Self(1_u64 << 30);
    pub const BUDGET_ACCOUNTING: Self = Self(1_u64 << 31);
    pub const PAYBACK_ATTACHMENT: Self = Self(1_u64 << 32);
    pub const COOLDOWN_DEPENDENCY: Self = Self(1_u64 << 33);
    pub const ACTION_COMPLETION_PROOF: Self = Self(1_u64 << 34);

    /// Add flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all required flags are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Decision, admission, and peer-authority refs consumed by an action executor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionExecutionAdmissionRefs {
    pub decision_frontier_ref: StorageIntentEvidenceRef,
    pub hard_gate_result_ref: StorageIntentEvidenceRef,
    pub selected_candidate_ref: StorageIntentEvidenceRef,
    pub counterfactual_payback_ref: StorageIntentEvidenceRef,
    pub reserve_admission_ref: StorageIntentEvidenceRef,
    pub scheduler_admission_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub evidence_retention_ref: StorageIntentEvidenceRef,
}

impl StorageIntentActionExecutionAdmissionRefs {
    /// Returns true when the selected decision/admission basis is evidence-backed.
    #[must_use]
    pub const fn has_required_refs(self) -> bool {
        evidence_ref_is_kind(
            self.decision_frontier_ref,
            StorageIntentEvidenceKind::DecisionFrontierEvidence,
        ) && evidence_ref_has_id(self.hard_gate_result_ref)
            && evidence_ref_has_id(self.selected_candidate_ref)
            && evidence_ref_has_id(self.counterfactual_payback_ref)
            && evidence_ref_has_id(self.reserve_admission_ref)
            && evidence_ref_has_id(self.scheduler_admission_ref)
            && evidence_ref_is_kind(
                self.tenant_isolation_ref,
                StorageIntentEvidenceKind::TenantIsolationEvidence,
            )
            && evidence_ref_is_kind(
                self.media_capability_ref,
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
            )
            && evidence_ref_is_kind(
                self.evidence_retention_ref,
                StorageIntentEvidenceKind::EvidenceRetentionEvidence,
            )
    }
}

/// Idempotency, step sequence, crash-recovery, and duplicate-suppression proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionExecutionReplayRecord {
    pub idempotency_key: StorageIntentReplayIdempotencyKey,
    pub step_sequence: u64,
    pub retry_generation: u32,
    pub state: StorageIntentActionReplayState,
    pub crash_recovery_marker_ref: StorageIntentEvidenceRef,
    pub duplicate_suppression_ref: StorageIntentEvidenceRef,
    pub replay_refusal_ref: StorageIntentEvidenceRef,
}

impl StorageIntentActionExecutionReplayRecord {
    /// Returns true when replay cannot duplicate reserves, receipts, or retirements.
    #[must_use]
    pub const fn is_idempotent_for_step(self, step: StorageIntentActionExecutionStepState) -> bool {
        if !step.requires_idempotent_replay() {
            return false;
        }
        if self.idempotency_key.is_zero() || self.step_sequence == 0 {
            return false;
        }
        if !evidence_ref_has_id(self.crash_recovery_marker_ref)
            || !evidence_ref_has_id(self.duplicate_suppression_ref)
        {
            return false;
        }
        !matches!(self.state, StorageIntentActionReplayState::Unknown)
    }

    /// Returns true when a duplicate delivery has been suppressed visibly.
    #[must_use]
    pub const fn duplicate_delivery_is_suppressed(self) -> bool {
        matches!(
            self.state,
            StorageIntentActionReplayState::DuplicateSuppressed
        ) && evidence_ref_has_id(self.duplicate_suppression_ref)
            && evidence_ref_has_id(self.replay_refusal_ref)
    }
}

/// Source receipts, rollback protection, and read-serving legality.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionSourceProtectionRecord {
    pub source_receipts_ref: StorageIntentEvidenceRef,
    pub old_placement_ref: StorageIntentEvidenceRef,
    pub old_placement_generation: u64,
    pub retained_rollback_sources_ref: StorageIntentEvidenceRef,
    pub retained_rollback_source_count: u8,
    pub read_serving_eligibility_ref: StorageIntentEvidenceRef,
    pub read_serving_eligible: bool,
    pub retirement_state: StorageIntentSourceRetirementState,
}

impl StorageIntentActionSourceProtectionRecord {
    /// Returns true while source receipts remain safe for reads or rollback.
    #[must_use]
    pub const fn protects_source_before_retirement(self) -> bool {
        evidence_ref_has_id(self.source_receipts_ref)
            && evidence_ref_has_id(self.old_placement_ref)
            && self.old_placement_generation > 0
            && evidence_ref_has_id(self.retained_rollback_sources_ref)
            && self.retained_rollback_source_count > 0
            && evidence_ref_has_id(self.read_serving_eligibility_ref)
            && self.read_serving_eligible
            && !matches!(
                self.retirement_state,
                StorageIntentSourceRetirementState::Retired
            )
    }
}

/// Target receipt candidate, integrity, flush/barrier, and width proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionTargetVerificationRecord {
    pub state: StorageIntentActionTargetVerificationState,
    pub target_receipt_candidate_ref: StorageIntentEvidenceRef,
    pub digest_integrity_ref: StorageIntentEvidenceRef,
    pub media_flush_barrier_ref: StorageIntentEvidenceRef,
    pub reconstruction_width: u8,
    pub required_reconstruction_width: u8,
    pub target_bytes: u64,
    pub verified_bytes: u64,
}

impl StorageIntentActionTargetVerificationRecord {
    /// Returns true when a target write has become verified target evidence.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.state.is_verified()
            && evidence_ref_has_id(self.target_receipt_candidate_ref)
            && evidence_ref_has_id(self.digest_integrity_ref)
            && evidence_ref_has_id(self.media_flush_barrier_ref)
            && self.required_reconstruction_width > 0
            && self.reconstruction_width >= self.required_reconstruction_width
            && self.target_bytes > 0
            && self.target_bytes == self.verified_bytes
    }
}

/// Replacement publication, ordering, recovery, rollout, and explanation proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionPublicationBoundaryRecord {
    pub state: StorageIntentActionPublicationState,
    pub replacement_receipt_ref: StorageIntentEvidenceRef,
    pub ordering_evidence_ref: StorageIntentEvidenceRef,
    pub recovery_degradation_ref: StorageIntentEvidenceRef,
    pub policy_rollout_ref: StorageIntentEvidenceRef,
    pub visible_state_ref: StorageIntentEvidenceRef,
    pub operator_explanation_ref: StorageIntentEvidenceRef,
    pub publication_sequence: u64,
}

impl StorageIntentActionPublicationBoundaryRecord {
    /// Returns true when cutover has durable, ordered, visible publication proof.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.state.has_replacement_publication()
            && evidence_ref_has_id(self.replacement_receipt_ref)
            && evidence_ref_is_kind(
                self.ordering_evidence_ref,
                StorageIntentEvidenceKind::OrderingEvidence,
            )
            && evidence_ref_is_kind(
                self.recovery_degradation_ref,
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            )
            && evidence_ref_is_kind(
                self.policy_rollout_ref,
                StorageIntentEvidenceKind::PolicyRolloutEvidence,
            )
            && evidence_ref_has_id(self.visible_state_ref)
            && evidence_ref_has_id(self.operator_explanation_ref)
            && self.publication_sequence > 0
    }
}

/// Abort, rollback, partial-target cleanup, and no-cutover proof.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionAbortRollbackRecord {
    pub abort_reason: StorageIntentActionExecutionRefusalReason,
    pub partial_target_cleanup_ref: StorageIntentEvidenceRef,
    pub retained_proof_ref: StorageIntentEvidenceRef,
    pub rollback_completion_ref: StorageIntentEvidenceRef,
    pub no_cutover_proof_ref: StorageIntentEvidenceRef,
    pub cutover_published: bool,
}

impl StorageIntentActionAbortRollbackRecord {
    /// Returns true when aborted or rolled-back work remains auditable.
    #[must_use]
    pub const fn is_visible_no_cutover(self) -> bool {
        !self.cutover_published
            && !matches!(
                self.abort_reason,
                StorageIntentActionExecutionRefusalReason::None
            )
            && evidence_ref_has_id(self.partial_target_cleanup_ref)
            && evidence_ref_has_id(self.retained_proof_ref)
            && evidence_ref_has_id(self.rollback_completion_ref)
            && evidence_ref_has_id(self.no_cutover_proof_ref)
    }
}

/// Work, disruption, reserve, egress, write, outcome, and cooldown accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionBudgetOutcomeRecord {
    pub work_bytes: u64,
    pub foreground_disruption_us: u64,
    pub media_write_bytes: u64,
    pub network_egress_bytes: u64,
    pub reserve_consumed_bytes: u64,
    pub reserve_budget_bytes: u64,
    pub reserve_generation: u64,
    pub outcome_attachment_ref: StorageIntentEvidenceRef,
    pub payback_ref: StorageIntentEvidenceRef,
    pub cooldown_dependency_ref: StorageIntentEvidenceRef,
}

impl StorageIntentActionBudgetOutcomeRecord {
    /// Returns true when accounting is present and cannot spend outside admission.
    #[must_use]
    pub const fn is_within_admitted_budget(self) -> bool {
        self.work_bytes > 0
            && self.reserve_budget_bytes > 0
            && self.reserve_consumed_bytes <= self.reserve_budget_bytes
            && self.reserve_generation > 0
            && evidence_ref_has_id(self.outcome_attachment_ref)
            && evidence_ref_has_id(self.payback_ref)
            && evidence_ref_has_id(self.cooldown_dependency_ref)
    }
}

/// Complete #911 action-execution evidence record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentActionExecutionEvidence {
    pub evidence_ref: StorageIntentEvidenceRef,
    pub action_id: StorageIntentEvidenceId,
    pub subject_scope: StorageIntentObjectScope,
    pub action_class: StorageIntentActionClass,
    pub producer_component_ref: StorageIntentEvidenceRef,
    pub producer_version: u64,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub execution_epoch: u64,
    pub temporal_ref: StorageIntentEvidenceRef,
    pub integrity_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    pub admission_refs: StorageIntentActionExecutionAdmissionRefs,
    pub step_state: StorageIntentActionExecutionStepState,
    pub replay: StorageIntentActionExecutionReplayRecord,
    pub source_protection: StorageIntentActionSourceProtectionRecord,
    pub target_verification: StorageIntentActionTargetVerificationRecord,
    pub publication: StorageIntentActionPublicationBoundaryRecord,
    pub abort_rollback: StorageIntentActionAbortRollbackRecord,
    pub budget: StorageIntentActionBudgetOutcomeRecord,
    pub action_completion_ref: StorageIntentEvidenceRef,
    pub evidence_state: StorageIntentActionEvidenceState,
    pub flags: StorageIntentActionExecutionFlags,
    pub refusal: StorageIntentActionExecutionRefusalReason,
}

impl StorageIntentActionExecutionEvidence {
    /// Returns true when this record is bound as action-execution evidence.
    #[must_use]
    pub const fn has_action_identity(self) -> bool {
        evidence_ref_is_kind(
            self.evidence_ref,
            StorageIntentEvidenceKind::ActionExecutionEvidence,
        ) && !bytes32_are_zero(self.action_id.0)
            && !bytes16_are_zero(self.subject_scope.dataset_id.0)
            && self.execution_epoch > 0
            && self.producer_version > 0
            && self.policy_revision.0 > 0
            && evidence_ref_has_id(self.producer_component_ref)
            && evidence_ref_is_kind(
                self.temporal_ref,
                StorageIntentEvidenceKind::TemporalEvidence,
            )
            && evidence_ref_has_id(self.integrity_ref)
            && evidence_ref_is_kind(
                self.evidence_query_snapshot_ref,
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
            )
    }

    /// Returns true when a planner decision is paired with actual admission refs.
    #[must_use]
    pub const fn has_execution_admission(self) -> bool {
        self.admission_refs.has_required_refs()
            && self.flags.contains_all(
                StorageIntentActionExecutionFlags::DECISION_FRONTIER_REF
                    .union(StorageIntentActionExecutionFlags::HARD_GATE_REF)
                    .union(StorageIntentActionExecutionFlags::SELECTED_CANDIDATE_REF)
                    .union(StorageIntentActionExecutionFlags::COUNTERFACTUAL_PAYBACK_REF)
                    .union(StorageIntentActionExecutionFlags::RESERVE_ADMISSION_REF)
                    .union(StorageIntentActionExecutionFlags::ISOLATION_REF)
                    .union(StorageIntentActionExecutionFlags::MEDIA_CAPABILITY_REF)
                    .union(StorageIntentActionExecutionFlags::RETENTION_REF),
            )
    }

    /// Returns true when every retry of this step has a stable replay key.
    #[must_use]
    pub const fn has_idempotent_replay(self) -> bool {
        self.replay.is_idempotent_for_step(self.step_state)
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::IDEMPOTENCY_KEY)
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::STEP_SEQUENCE)
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::CRASH_RECOVERY_MARKER)
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::DUPLICATE_SUPPRESSION)
    }

    /// Returns true when source receipts are retained until authority is safe.
    #[must_use]
    pub const fn has_source_protection(self) -> bool {
        if !self.step_state.requires_source_protection() {
            return true;
        }
        self.source_protection.protects_source_before_retirement()
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::SOURCE_RECEIPTS)
            && self.flags.contains_all(
                StorageIntentActionExecutionFlags::FORBID_SOURCE_RETIREMENT_UNTIL_COMPLETE,
            )
    }

    /// Returns true when target evidence is more than a target write.
    #[must_use]
    pub const fn has_target_verification(self) -> bool {
        if !self.step_state.requires_target_verification() {
            return true;
        }
        self.target_verification.is_complete()
            && self.flags.contains_all(
                StorageIntentActionExecutionFlags::TARGET_RECEIPT_CANDIDATE
                    .union(StorageIntentActionExecutionFlags::TARGET_DIGEST_INTEGRITY)
                    .union(StorageIntentActionExecutionFlags::MEDIA_FLUSH_BARRIER)
                    .union(StorageIntentActionExecutionFlags::RECONSTRUCTION_WIDTH),
            )
    }

    /// Returns true when publication/cutover is ordered and visible.
    #[must_use]
    pub const fn has_publication_boundary(self) -> bool {
        if !self.step_state.requires_publication_boundary() {
            return true;
        }
        self.publication.is_complete()
            && self.flags.contains_all(
                StorageIntentActionExecutionFlags::REPLACEMENT_PUBLICATION
                    .union(StorageIntentActionExecutionFlags::PUBLICATION_ORDERING)
                    .union(StorageIntentActionExecutionFlags::RECOVERY_DEGRADATION_REF)
                    .union(StorageIntentActionExecutionFlags::POLICY_ROLLOUT_REF)
                    .union(StorageIntentActionExecutionFlags::VISIBLE_CONVERGING_STATE),
            )
    }

    /// Returns true when abort or rollback remains visible until retention permits compaction.
    #[must_use]
    pub const fn has_visible_abort_or_rollback(self) -> bool {
        if !self.step_state.requires_abort_or_rollback_proof() {
            return true;
        }
        self.abort_rollback.is_visible_no_cutover()
            && self.flags.contains_all(
                StorageIntentActionExecutionFlags::ABORT_REASON
                    .union(StorageIntentActionExecutionFlags::PARTIAL_TARGET_CLEANUP)
                    .union(StorageIntentActionExecutionFlags::ROLLBACK_COMPLETION)
                    .union(StorageIntentActionExecutionFlags::NO_CUTOVER_PROOF),
            )
    }

    /// Returns true when completion proof exists.
    #[must_use]
    pub const fn has_action_completion_proof(self) -> bool {
        self.step_state.is_complete()
            && evidence_ref_is_kind(
                self.action_completion_ref,
                StorageIntentEvidenceKind::ActionExecutionEvidence,
            )
            && self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::ACTION_COMPLETION_PROOF)
    }

    /// Return the first fail-closed action-execution refusal.
    #[must_use]
    pub const fn action_refusal(self) -> StorageIntentActionExecutionRefusalReason {
        if !matches!(
            self.refusal,
            StorageIntentActionExecutionRefusalReason::None
        ) {
            return self.refusal;
        }
        if !self.has_action_identity()
            || !self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::ACTION_IDENTITY)
        {
            return StorageIntentActionExecutionRefusalReason::MissingActionIdentity;
        }
        if !self.evidence_state.is_fresh_for_execution() {
            return StorageIntentActionExecutionRefusalReason::StaleExecutionEvidence;
        }
        if !self.has_execution_admission() {
            return StorageIntentActionExecutionRefusalReason::MissingDecisionAdmissionEvidence;
        }
        if !self.has_idempotent_replay() {
            return StorageIntentActionExecutionRefusalReason::NonIdempotentReplay;
        }
        if self.replay.duplicate_delivery_is_suppressed() {
            return StorageIntentActionExecutionRefusalReason::DuplicateActionDelivery;
        }
        if !self.budget.is_within_admitted_budget()
            || !self
                .flags
                .contains_all(StorageIntentActionExecutionFlags::BUDGET_ACCOUNTING)
        {
            return StorageIntentActionExecutionRefusalReason::ReserveExhausted;
        }
        if !self.has_source_protection() {
            return StorageIntentActionExecutionRefusalReason::MissingSourceProtection;
        }
        if self.step_state.requires_target_verification()
            && !self.target_verification.state.is_verified()
        {
            return if matches!(
                self.target_verification.state,
                StorageIntentActionTargetVerificationState::PartialWrite
                    | StorageIntentActionTargetVerificationState::DegradedPartial
            ) || self.target_verification.verified_bytes
                < self.target_verification.target_bytes
            {
                StorageIntentActionExecutionRefusalReason::PartialTargetWrite
            } else {
                StorageIntentActionExecutionRefusalReason::MissingTargetVerification
            };
        }
        if !self.has_target_verification() {
            return StorageIntentActionExecutionRefusalReason::TargetWriteIsNotCompletion;
        }
        if !self.has_publication_boundary() {
            if !evidence_ref_is_kind(
                self.publication.ordering_evidence_ref,
                StorageIntentEvidenceKind::OrderingEvidence,
            ) {
                return StorageIntentActionExecutionRefusalReason::MissingOrderingEvidence;
            }
            if !evidence_ref_is_kind(
                self.publication.recovery_degradation_ref,
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
            ) {
                return StorageIntentActionExecutionRefusalReason::MissingRecoveryDegradationEvidence;
            }
            return StorageIntentActionExecutionRefusalReason::MissingPublicationEvidence;
        }
        if !self.has_visible_abort_or_rollback() {
            return StorageIntentActionExecutionRefusalReason::AbortRollbackIncomplete;
        }
        if self.step_state.is_complete() && !self.has_action_completion_proof() {
            return StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence;
        }
        StorageIntentActionExecutionRefusalReason::None
    }

    /// Return the fail-closed reason that blocks source receipt retirement.
    #[must_use]
    pub const fn source_retirement_refusal(self) -> StorageIntentActionExecutionRefusalReason {
        let action_refusal = self.action_refusal();
        if !matches!(
            action_refusal,
            StorageIntentActionExecutionRefusalReason::None
                | StorageIntentActionExecutionRefusalReason::DuplicateActionDelivery
        ) {
            return action_refusal;
        }
        if !self.has_action_completion_proof() {
            return StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence;
        }
        if self.source_protection.retirement_state.forbids_retirement() {
            return StorageIntentActionExecutionRefusalReason::SourceRetirementForbidden;
        }
        if !evidence_ref_is_kind(
            self.admission_refs.evidence_retention_ref,
            StorageIntentEvidenceKind::EvidenceRetentionEvidence,
        ) {
            return StorageIntentActionExecutionRefusalReason::MissingRetentionEvidence;
        }
        StorageIntentActionExecutionRefusalReason::None
    }
}

/// Returns true when `evidence_ref` is a bound artifact of `kind`.
#[must_use]
pub const fn evidence_ref_is_kind(
    evidence_ref: StorageIntentEvidenceRef,
    kind: StorageIntentEvidenceKind,
) -> bool {
    evidence_ref.kind as u16 == kind as u16 && !bytes32_are_zero(evidence_ref.id.0)
}

/// Evaluate whether action execution can count as completed authority.
#[must_use]
pub const fn action_execution_satisfies_completion(
    evidence: StorageIntentActionExecutionEvidence,
) -> ReceiptPredicateResult {
    let refusal = evidence.action_refusal();
    if matches!(refusal, StorageIntentActionExecutionRefusalReason::None)
        && evidence.has_action_completion_proof()
    {
        return ReceiptPredicateResult::SATISFIED;
    }
    let completion_refusal = if matches!(refusal, StorageIntentActionExecutionRefusalReason::None) {
        StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence
    } else {
        refusal
    };
    ReceiptPredicateResult::refused(completion_refusal.to_storage_intent_refusal())
}

/// Evaluate whether old source receipts may be retired.
#[must_use]
pub const fn action_execution_allows_source_retirement(
    evidence: StorageIntentActionExecutionEvidence,
) -> ReceiptPredicateResult {
    let refusal = evidence.source_retirement_refusal();
    if matches!(refusal, StorageIntentActionExecutionRefusalReason::None) {
        return ReceiptPredicateResult::SATISFIED;
    }
    ReceiptPredicateResult::refused(refusal.to_storage_intent_refusal())
}

/// Source used to serve a read, with freshness evidence elsewhere.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum ReadServingSourceClass {
    #[default]
    Cache = 0,
    ServingTrial = 1,
    RamAuthority = 2,
    PlacementReceipt = 3,
    RemoteReceipt = 4,
    DegradedReconstruction = 5,
    SnapshotGeneration = 6,
    GeoAsyncLag = 7,
    ArchiveRestore = 8,
}

/// Freshness evidence for a selected read source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReadSourceFreshnessRecord {
    pub source: ReadServingSourceClass,
    pub source_receipt: StorageIntentReceiptId,
    pub snapshot_generation: u64,
    pub geo_lag_ms: u64,
    pub lag_known: bool,
    pub freshness_frontier_ms: u64,
    pub evidence: StorageIntentEvidenceRef,
}

// ---------------------------------------------------------------------------
// Data-shape types: record sizing, compression, checksum/digest, dedup,
// encryption, EC/archive, coalescing, and rebake (issue #878).
// ---------------------------------------------------------------------------

/// Allowed extent/chunk/stripe size class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum RecordSizeClass {
    #[default]
    Unknown = 0,
    /// 512 B - 4 KiB: inode, xattr, small file, directory block.
    Tiny = 1,
    /// 4 KiB - 64 KiB: small file payload, metadata block.
    Small = 2,
    /// 64 KiB - 1 MiB: default extent.
    Medium = 3,
    /// 1 MiB - 16 MiB: streaming ingest, archive.
    Large = 4,
    /// 16 MiB - 256 MiB: EC stripe, backup.
    Huge = 5,
    /// Caller-specified split/coalesce rules override.
    RangeOverride = 6,
}

/// Compression algorithm and level/class.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum CompressionAlgorithmClass {
    #[default]
    None = 0,
    Lz4Fast = 1,
    Lz4High = 2,
    ZstdFast = 3,
    ZstdHigh = 4,
    ZstdAdaptive = 5,
    DictionaryBacked = 6,
    Custom = 7,
}

/// Compression ordering relative to encryption.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum CompressionOrderingClass {
    #[default]
    Unknown = 0,
    /// Compression before encryption (standard safe construction).
    CompressThenEncrypt = 1,
    /// Encryption before compression (compression ineffective).
    EncryptThenCompress = 2,
    /// Compression only, no encryption layer.
    CompressOnly = 3,
    /// No compression, encryption may be present.
    NoCompression = 4,
}

/// Checksum/digest suite and layer identity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DigestSuiteClass {
    #[default]
    Unknown = 0,
    /// CRC32C for framing sanity only.
    Crc32cFraming = 1,
    /// BLAKE3-256 for durable content identity.
    Blake3Content = 2,
    /// BLAKE3-256 keyed for committed-root authentication.
    Blake3KeyedRoot = 3,
    /// CRC32C framing + BLAKE3-256 payload.
    Crc32cPlusBlake3 = 4,
    /// CRC32C framing + BLAKE3-256 payload + BLAKE3-256 keyed root.
    FullIntegrityTrailerV2 = 5,
}

/// Dedup fingerprint scope and collision/security posture.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DedupFingerprintScopeClass {
    #[default]
    Unknown = 0,
    /// No dedup fingerprinting.
    NoDedup = 1,
    /// Fingerprints within one dataset only.
    DatasetLocal = 2,
    /// Fingerprints within one tenant domain.
    TenantLocal = 3,
    /// Fingerprints within a security domain.
    SecurityDomain = 4,
    /// Cross-domain sharing allowed by explicit policy.
    CrossDomainAuthorized = 5,
    /// Dedup refused: domain or policy mismatch.
    DedupRefused = 6,
}

/// Erasure-coding or archive shape parameters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ECArchiveShape {
    /// Data shards (k).
    pub ec_data_shards: u8,
    /// Parity shards (m).
    pub ec_parity_shards: u8,
    /// Stripe unit size in bytes.
    pub stripe_unit_bytes: u32,
    /// Locality group size (0 = none).
    pub locality_group_size: u8,
    /// Rebuild width (how many shards are read for rebuild).
    pub rebuild_width: u8,
    /// Restore-time class: how many shards must be retrieved for a full read.
    pub restore_read_width: u8,
}

impl ECArchiveShape {
    /// Sentinel for replication (k=1, m=0).
    pub const REPLICATION: Self = Self {
        ec_data_shards: 1,
        ec_parity_shards: 0,
        stripe_unit_bytes: 0,
        locality_group_size: 0,
        rebuild_width: 1,
        restore_read_width: 1,
    };

    /// Returns true when this is a replication shape (no EC).
    #[must_use]
    pub const fn is_replication(self) -> bool {
        self.ec_parity_shards == 0
    }

    /// Returns true when this is an erasure-coded shape.
    #[must_use]
    pub const fn is_erasure_coded(self) -> bool {
        self.ec_parity_shards > 0 && self.ec_data_shards > 0
    }

    /// Returns true when this is a valid shape (k > 0, k+m <= 255).
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.ec_data_shards > 0
            && self.ec_data_shards as u16 + self.ec_parity_shards as u16 <= 255
    }

    /// Total shards (k+m).
    #[must_use]
    pub const fn total_shards(self) -> u8 {
        self.ec_data_shards.saturating_add(self.ec_parity_shards)
    }
}

/// Small-object coalescing mode.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum CoalescingModeClass {
    #[default]
    Unknown = 0,
    /// No coalescing; each record stands alone.
    NoCoalescing = 1,
    /// Inline payload packed into extent header.
    InlinePayload = 2,
    /// Packed small files share one extent.
    PackedSmallFiles = 3,
    /// Directory block inlining.
    DirBlockInline = 4,
    /// Xattr payload inlining.
    XattrPayloadInline = 5,
    /// Externalized to a shared small-object extent.
    ExternalizedSmallObject = 6,
}

/// Rebake eligibility and payback window.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum RebakeEligibilityClass {
    #[default]
    Unknown = 0,
    /// Rebake is not permitted by policy.
    RebakeForbidden = 1,
    /// Shadow evaluation only; no live rebake.
    ShadowEvaluation = 2,
    /// Eligible after cooldown window.
    EligibleAfterCooldown = 3,
    /// Eligible immediately (payback window satisfied).
    EligibleImmediate = 4,
    /// Refused: replacement receipts not yet published.
    ReplacementReceiptPending = 5,
    /// Refused: payback window not met.
    PaybackWindowNotMet = 6,
}

/// Data-shape cost budget limits.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DataShapeCostBudget {
    /// Max CPU budget for compression (ppm of CPU capacity).
    pub cpu_budget_ppm: u32,
    /// Max memory budget for compression/dedup tables (bytes).
    pub memory_budget_bytes: u64,
    /// Max read amplification factor (multiplied by 1000, e.g. 1500 = 1.5x).
    pub read_amplification_ppm: u32,
    /// Max decompression latency budget (microseconds).
    pub decompression_latency_us: u64,
    /// Max WAN egress budget (bytes per period).
    pub wan_egress_budget_bytes: u64,
    /// Max flash wear budget (estimated physical bytes written).
    pub wear_budget_bytes: u64,
    /// Max rebuild bandwidth budget (bytes/s).
    pub rebuild_budget_bytes_per_sec: u64,
    /// Max movement debt budget (bytes of relocation not yet paid back).
    pub movement_debt_budget_bytes: u64,
}

/// Requested data-shape policy for a range or generation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DataShapePolicy {
    /// Compiled policy identity.
    pub policy_id: StorageIntentPolicyId,
    /// Monotonic policy revision.
    pub policy_revision: StorageIntentPolicyRevision,
    /// Allowed record size class (floor).
    pub record_size_class: RecordSizeClass,
    /// Allowed compression algorithm and level (None = compression forbidden).
    pub compression_algorithm: CompressionAlgorithmClass,
    /// Compression ordering relative to encryption.
    pub compression_ordering: CompressionOrderingClass,
    /// Required checksum/digest suite (floor).
    pub digest_suite: DigestSuiteClass,
    /// Allowed dedup fingerprint scope (floor/domain constraint).
    pub dedup_scope: DedupFingerprintScopeClass,
    /// Encryption domain for transform boundary.
    pub encryption_domain: StorageIntentDomainId,
    /// Minimum encryption key epoch.
    pub encryption_key_epoch_min: u64,
    /// EC/archive shape (replication if ec_parity_shards=0).
    pub ec_archive_shape: ECArchiveShape,
    /// Coalescing mode for small objects.
    pub coalescing_mode: CoalescingModeClass,
    /// Rebake eligibility.
    pub rebake_eligibility: RebakeEligibilityClass,
    /// Cost budget limits.
    pub cost_budget: DataShapeCostBudget,
    /// Domain constraint for dedup/encryption sharing.
    pub sharing_domain: StorageIntentDomainId,
    /// Evidence refs for policy compilation provenance.
    pub evidence_refs: StorageIntentEvidenceRefs,
}

/// Transform refusal reason for data-shape decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum TransformRefusalClass {
    #[default]
    None = 0,
    UnsupportedCompression = 1,
    UnsupportedChecksum = 2,
    DedupDomainMismatch = 3,
    EncryptionKeyEpochStale = 4,
    ErasureShapeIllegal = 5,
    RebakeWouldWeakenReceipt = 6,
    ReplacementReceiptMissing = 7,
}


/// Data-shape specific refusal reasons.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum DataShapeRefusalReason {
    #[default]
    None = 0,
    UnknownDataShapeEvidence = 1,
    StaleDataShapeEvidence = 2,
    WrongDomainForDedup = 3,
    DedupCrossesTenantDomain = 4,
    EncryptionBypassedForDedup = 5,
    CompressedBeforeEncryptionOrderViolation = 6,
    ECShapeBlocksReadServing = 7,
    ECShapeExceedsRebuildBudget = 8,
    ECShapeExceedsRestoreTime = 9,
    RecordSizeTooSmallForEC = 10,
    RecordSizeTooLargeForOverwriteLatency = 11,
    DigestSuiteTooWeakForPolicy = 12,
    CompressionExceedsCpuBudget = 13,
    CompressionExceedsMemoryBudget = 14,
    RebakePaybackWindowNotMet = 15,
    RebakeReplacementReceiptMissing = 16,
    CostBudgetExceeded = 17,
}

impl DataShapeRefusalReason {
    /// Project data-shape specific refusals into the shared storage-intent
    /// refusal namespace.
    #[must_use]
    pub const fn to_storage_intent_refusal(self) -> StorageIntentRefusalReason {
        match self {
            Self::None => StorageIntentRefusalReason::None,
            Self::UnknownDataShapeEvidence => {
                StorageIntentRefusalReason::UnknownDataShapeEvidence
            }
            Self::StaleDataShapeEvidence => StorageIntentRefusalReason::StaleDataShapeEvidence,
            Self::WrongDomainForDedup | Self::DedupCrossesTenantDomain => {
                StorageIntentRefusalReason::DedupCrossesTenantDomain
            }
            Self::EncryptionBypassedForDedup => {
                StorageIntentRefusalReason::EncryptionBypassedForDedup
            }
            Self::CompressedBeforeEncryptionOrderViolation => {
                StorageIntentRefusalReason::IllegalCompressionOrdering
            }
            Self::ECShapeBlocksReadServing
            | Self::ECShapeExceedsRebuildBudget
            | Self::ECShapeExceedsRestoreTime
            | Self::RecordSizeTooSmallForEC => StorageIntentRefusalReason::ECShapeBlocksReadServing,
            Self::RecordSizeTooLargeForOverwriteLatency
            | Self::CompressionExceedsCpuBudget
            | Self::CompressionExceedsMemoryBudget
            | Self::CostBudgetExceeded => StorageIntentRefusalReason::DataShapeCostBudgetExceeded,
            Self::DigestSuiteTooWeakForPolicy => {
                StorageIntentRefusalReason::DataShapeTransformRefused
            }
            Self::RebakePaybackWindowNotMet => {
                StorageIntentRefusalReason::RebakePaybackWindowNotMet
            }
            Self::RebakeReplacementReceiptMissing => {
                StorageIntentRefusalReason::RebakeReplacementReceiptMissing
            }
        }
    }
}


/// Data-shape evidence: proven encoded shape for a range or generation.
///
/// Carries the actual record size class, compression algorithm and ordering,
/// digest suite, dedup fingerprint scope, encryption domain and key epoch,
/// EC/archive shape parameters, coalescing mode, rebake eligibility, cost
/// accounting refs, typed refusal state, and evidence provenance so consumers
/// can verify the encoded shape against policy and prove integrity,
/// domain compatibility, and receipt-retirement law.
///
/// The numeric fields (`record_size_bytes`, `compression_algorithm`,
/// `checksum_algorithm`, `digest`, `ec_data_shards`, `ec_parity_shards`,
/// `coalescing_generation`, `rebake_generation`) are the stable on-media
/// projections. The typed fields (`record_size_class`, `compression_class`,
/// `digest_suite`, `dedup_scope`, `ec_archive_shape`, `coalescing_mode`,
/// `rebake_eligibility`, `data_shape_refusal`) are the storage-intent
/// authority view and may carry richer policy/evidence semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DataShapeRecord {
    // -- Stable on-media projection fields (backward compat) --
    pub record_size_bytes: u32,
    pub compression_algorithm: u16,
    pub checksum_algorithm: u16,
    pub digest: [u8; 32],
    pub dedup_domain: StorageIntentDomainId,
    pub encryption_key_epoch: u64,
    pub ec_data_shards: u8,
    pub ec_parity_shards: u8,
    pub coalescing_generation: u64,
    pub rebake_generation: u64,
    pub transform_refusal: TransformRefusalClass,
    pub replacement_receipt: StorageIntentReceiptId,
    // -- Storage-intent authority typed fields --
    /// Typed record size class.
    pub record_size_class: RecordSizeClass,
    /// Typed compression algorithm class.
    pub compression_class: CompressionAlgorithmClass,
    /// Compression ordering relative to encryption.
    pub compression_ordering: CompressionOrderingClass,
    /// Typed digest suite.
    pub digest_suite: DigestSuiteClass,
    /// Dedup fingerprint scope evidence.
    pub dedup_scope: DedupFingerprintScopeClass,
    /// Encryption domain for transform boundary.
    pub encryption_domain: StorageIntentDomainId,
    /// EC/archive shape parameters.
    pub ec_archive_shape: ECArchiveShape,
    /// Coalescing mode for small objects.
    pub coalescing_mode: CoalescingModeClass,
    /// Rebake eligibility state.
    pub rebake_eligibility: RebakeEligibilityClass,
    /// Data-shape specific refusal reason (if any).
    pub data_shape_refusal: DataShapeRefusalReason,
    /// Policy that authorized this shape.
    pub policy_id: StorageIntentPolicyId,
    /// Policy revision at write time.
    pub policy_revision: StorageIntentPolicyRevision,
    /// Cost accounting evidence ref.
    pub cost_accounting_ref: StorageIntentEvidenceRef,
    /// Evidence provenance ref.
    pub evidence: StorageIntentEvidenceRef,
}

impl DataShapeRecord {
    /// Returns the shared refusal implied by the data-shape record.
    #[must_use]
    pub const fn shape_refusal(self) -> StorageIntentRefusalReason {
        if !matches!(self.data_shape_refusal, DataShapeRefusalReason::None) {
            return self.data_shape_refusal.to_storage_intent_refusal();
        }
        match self.transform_refusal {
            TransformRefusalClass::None => StorageIntentRefusalReason::None,
            TransformRefusalClass::UnsupportedCompression
            | TransformRefusalClass::UnsupportedChecksum
            | TransformRefusalClass::ErasureShapeIllegal => {
                StorageIntentRefusalReason::DataShapeTransformRefused
            }
            TransformRefusalClass::DedupDomainMismatch => {
                StorageIntentRefusalReason::DedupCrossesTenantDomain
            }
            TransformRefusalClass::EncryptionKeyEpochStale => {
                StorageIntentRefusalReason::StaleKeyEpoch
            }
            TransformRefusalClass::RebakeWouldWeakenReceipt
            | TransformRefusalClass::ReplacementReceiptMissing => {
                StorageIntentRefusalReason::RebakeReplacementReceiptMissing
            }
        }
    }

    /// Returns true when no transform has been refused.
    #[must_use]
    pub const fn is_transform_legal(self) -> bool {
        matches!(self.shape_refusal(), StorageIntentRefusalReason::None)
    }

    /// Returns true when encryption domain is present.
    #[must_use]
    pub const fn has_encryption_domain(self) -> bool {
        !self.encryption_domain.is_zero()
    }

    /// Returns true when dedup domain is present.
    #[must_use]
    pub const fn has_dedup_domain(self) -> bool {
        !self.dedup_domain.is_zero()
    }

    /// Returns true when the shape uses compression.
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        !matches!(self.compression_class, CompressionAlgorithmClass::None)
    }
}

// ---------------------------------------------------------------------------
// Data-shape hard-gate validation predicates.
// ---------------------------------------------------------------------------


/// Const-compatible domain-id equality.
const fn domain_ids_equal(a: StorageIntentDomainId, b: StorageIntentDomainId) -> bool {
    let mut i = 0;
    while i < 16 {
        if a.0[i] != b.0[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Const-compatible receipt-id equality.
const fn receipt_ids_equal(a: StorageIntentReceiptId, b: StorageIntentReceiptId) -> bool {
    let mut i = 0;
    while i < 16 {
        if a.0[i] != b.0[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Const-compatible policy-id equality.
const fn policy_ids_equal(a: StorageIntentPolicyId, b: StorageIntentPolicyId) -> bool {
    bytes16_equal(a.0, b.0)
}

/// Returns SATISFIED when the data-shape evidence record has usable evidence.
///
/// Unknown, missing, or stale data-shape evidence blocks authority.
#[must_use]
pub const fn data_shape_evidence_is_usable(
    record: DataShapeRecord,
) -> ReceiptPredicateResult {
    if !evidence_ref_is_kind(record.evidence, StorageIntentEvidenceKind::DataShapeEvidence) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnknownDataShapeEvidence,
        );
    }
    if record.evidence.generation == 0 || record.evidence.version == 0 {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::StaleDataShapeEvidence,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Returns SATISFIED when the evidence record reports a legal transform.
///
/// Any transform or data-shape refusal blocks authority.
#[must_use]
pub const fn data_shape_transform_is_legal(
    record: DataShapeRecord,
) -> ReceiptPredicateResult {
    let refusal = record.shape_refusal();
    if matches!(refusal, StorageIntentRefusalReason::None) {
        return ReceiptPredicateResult::SATISFIED;
    }
    ReceiptPredicateResult::refused(refusal)
}

/// Returns SATISFIED when the shape record was proven under the policy
/// identity and revision being checked.
#[must_use]
pub const fn data_shape_policy_identity_is_current(
    record: DataShapeRecord,
    policy: DataShapePolicy,
) -> ReceiptPredicateResult {
    if !policy.policy_id.is_zero()
        && (record.policy_id.is_zero() || !policy_ids_equal(record.policy_id, policy.policy_id))
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::StaleDataShapeEvidence,
        );
    }
    if policy.policy_revision.0 > 0 && record.policy_revision.0 < policy.policy_revision.0 {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::StaleDataShapeEvidence,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Returns SATISFIED when dedup does not cross encryption or tenant domains
/// without explicit policy permission.
///
/// Identity law: dedup fingerprints are over the policy-approved identity
/// and domain; they cannot cross encryption, tenant, security, or retention
/// domains by accident.
#[must_use]
pub const fn data_shape_dedup_domain_is_compatible(
    record: DataShapeRecord,
    policy_domain: StorageIntentDomainId,
) -> ReceiptPredicateResult {
    // No dedup active: trivially satisfied.
    if matches!(record.dedup_scope, DedupFingerprintScopeClass::NoDedup) {
        return ReceiptPredicateResult::SATISFIED;
    }
    if matches!(record.dedup_scope, DedupFingerprintScopeClass::Unknown) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnknownDataShapeEvidence,
        );
    }
    // Dedup refused: unsatisfied.
    if matches!(record.dedup_scope, DedupFingerprintScopeClass::DedupRefused) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::DedupCrossesTenantDomain,
        );
    }
    // If a sharing domain is specified, it must match policy.
    if !record.dedup_domain.is_zero() && !domain_ids_equal(record.dedup_domain, policy_domain) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::DedupCrossesTenantDomain,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Returns SATISFIED when encryption is not bypassed for dedup,
/// compression, or recovery convenience.
///
/// Identity law: encryption cannot be bypassed to make compression,
/// dedup, repair, recovery, or operator inspection convenient.
#[must_use]
pub const fn data_shape_encryption_is_not_bypassed(
    record: DataShapeRecord,
    policy_requires_encryption: bool,
) -> ReceiptPredicateResult {
    if !policy_requires_encryption {
        return ReceiptPredicateResult::SATISFIED;
    }
    // Encryption domain must be present when policy requires encryption.
    if record.encryption_domain.is_zero() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::EncryptionBypassedForDedup,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Returns SATISFIED when compression ordering respects the
/// compress-then-encrypt identity law.
///
/// Compression must happen before encryption for useful compression.
/// Encrypt-then-compress is a legal but wasteful choice that must be
/// an explicit policy decision, not a silent default.
#[must_use]
pub const fn data_shape_compression_ordering_is_legal(
    record: DataShapeRecord,
) -> ReceiptPredicateResult {
    match record.compression_ordering {
        CompressionOrderingClass::CompressThenEncrypt
        | CompressionOrderingClass::CompressOnly
        | CompressionOrderingClass::NoCompression => ReceiptPredicateResult::SATISFIED,
        CompressionOrderingClass::EncryptThenCompress => {
            // Legal but uneconomical; not a hard gate failure.
            ReceiptPredicateResult::SATISFIED
        }
        CompressionOrderingClass::Unknown => {
            ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::IllegalCompressionOrdering,
            )
        }
    }
}

/// Returns SATISFIED when the EC/archive shape is valid and can satisfy
/// read-serving latency floors.
///
/// EC shapes with high rebuild width or restore-time width may block
/// read-serving unless the policy explicitly permits degraded reads.
#[must_use]
pub const fn data_shape_ec_shape_is_legal(
    shape: ECArchiveShape,
) -> ReceiptPredicateResult {
    if shape.is_replication() {
        return ReceiptPredicateResult::SATISFIED;
    }
    if !shape.is_valid() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::ECShapeBlocksReadServing,
        );
    }
    // Rebuild width must not exceed total shards.
    if shape.rebuild_width > shape.total_shards() || shape.restore_read_width > shape.total_shards()
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::ECShapeBlocksReadServing,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Returns SATISFIED when rebake replacement receipts exist before
/// old shape retirement.
///
/// Identity law: rebake must publish replacement placement and data-shape
/// receipts that satisfy the target policy before old shape receipts
/// or locators are retired.
#[must_use]
pub const fn data_shape_rebake_replacement_receipt_is_present(
    record: DataShapeRecord,
) -> ReceiptPredicateResult {
    match record.rebake_eligibility {
        RebakeEligibilityClass::Unknown
        | RebakeEligibilityClass::RebakeForbidden
        | RebakeEligibilityClass::ShadowEvaluation => ReceiptPredicateResult::SATISFIED,
        RebakeEligibilityClass::EligibleAfterCooldown
        | RebakeEligibilityClass::EligibleImmediate => {
            if !receipt_ids_equal(record.replacement_receipt, StorageIntentReceiptId::ZERO) {
                ReceiptPredicateResult::SATISFIED
            } else {
                ReceiptPredicateResult::refused(
                    StorageIntentRefusalReason::RebakeReplacementReceiptMissing,
                )
            }
        }
        RebakeEligibilityClass::ReplacementReceiptPending => {
            ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::RebakeReplacementReceiptMissing,
            )
        }
        RebakeEligibilityClass::PaybackWindowNotMet => {
            ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::RebakePaybackWindowNotMet,
            )
        }
    }
}

/// Returns SATISFIED when the digest suite meets or exceeds the policy floor.
#[must_use]
pub const fn data_shape_digest_suite_is_adequate(
    record: DataShapeRecord,
    policy_min_suite: DigestSuiteClass,
) -> ReceiptPredicateResult {
    if record.digest_suite as u8 >= policy_min_suite as u8
        && !matches!(record.digest_suite, DigestSuiteClass::Unknown)
    {
        return ReceiptPredicateResult::SATISFIED;
    }
    ReceiptPredicateResult::refused(StorageIntentRefusalReason::DataShapeTransformRefused)
}

/// Full data-shape hard-gate check: combine all predicates.
///
/// Returns SATISFIED only when all identity-law, domain, integrity,
/// and receipt-retirement predicates pass. Any single refusal blocks
/// authority.
#[must_use]
pub const fn data_shape_hard_gate_check(
    record: DataShapeRecord,
    policy: DataShapePolicy,
) -> ReceiptPredicateResult {
    // Evidence must be usable.
    let r = data_shape_evidence_is_usable(record);
    if !r.satisfied {
        return r;
    }
    // Transform must be legal.
    let r = data_shape_transform_is_legal(record);
    if !r.satisfied {
        return r;
    }
    // Policy identity and revision must match the evaluated policy.
    let r = data_shape_policy_identity_is_current(record, policy);
    if !r.satisfied {
        return r;
    }
    // Dedup domain must be compatible with policy.
    let r = data_shape_dedup_domain_is_compatible(record, policy.sharing_domain);
    if !r.satisfied {
        return r;
    }
    // Encryption must not be bypassed if policy requires it.
    let r = data_shape_encryption_is_not_bypassed(
        record,
        !policy.encryption_domain.is_zero(),
    );
    if !r.satisfied {
        return r;
    }
    // Compression ordering must be legal.
    let r = data_shape_compression_ordering_is_legal(record);
    if !r.satisfied {
        return r;
    }
    // EC shape must be valid.
    let r = data_shape_ec_shape_is_legal(record.ec_archive_shape);
    if !r.satisfied {
        return r;
    }
    // Rebake replacement receipt must be present when eligible.
    let r = data_shape_rebake_replacement_receipt_is_present(record);
    if !r.satisfied {
        return r;
    }
    // Digest suite must meet policy floor.
    let r = data_shape_digest_suite_is_adequate(record, policy.digest_suite);
    if !r.satisfied {
        return r;
    }
    ReceiptPredicateResult::SATISFIED
}

/// Allocation class used by allocator evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum AllocationClass {
    #[default]
    Unknown = 0,
    IntentLog = 1,
    Metadata = 2,
    SmallData = 3,
    LargeSequential = 4,
    ErasureShard = 5,
    ArchiveStripe = 6,
    RepairScratch = 7,
}

/// Segment/region class used by allocator evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum SegmentRegionClass {
    #[default]
    Unknown = 0,
    Hot = 1,
    Warm = 2,
    Cold = 3,
    ZoneAppend = 4,
    EraseBlockAligned = 5,
    Fragmented = 6,
}

/// Layout/allocator evidence ref projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct LayoutAllocatorRecord {
    pub allocation_class: AllocationClass,
    pub region_class: SegmentRegionClass,
    pub free_run_pressure_ppm: u32,
    pub fragmentation_ppm: u32,
    pub locality_score_ppm: u32,
    pub alignment_bytes: u32,
    pub zone_write_pointer: u64,
    pub pending_free_bytes: u64,
    pub pending_free_safe: bool,
    pub reclaim_debt_bytes: u64,
    pub stale_mirror_refusal: bool,
    pub evidence: StorageIntentEvidenceRef,
}

/// Relocation or optimizer reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum RelocationReasonClass {
    #[default]
    Unknown = 0,
    DefragRotationalLocality = 1,
    ReclaimPressure = 2,
    FlashServingPromotion = 3,
    AuthorityConvergence = 4,
    Evacuation = 5,
    Repair = 6,
    GeoCatchup = 7,
    ArchiveMigration = 8,
    DataShapeRebake = 9,
}

/// Relocation lifecycle state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum RelocationLifecycleState {
    #[default]
    Proposed = 0,
    Admitted = 1,
    Copying = 2,
    Verifying = 3,
    PublishingReceipt = 4,
    RetiringSource = 5,
    Complete = 6,
    Cooldown = 7,
    Refused = 8,
    Aborted = 9,
}

/// Skipped move or cooldown reason.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum SkippedMoveReason {
    #[default]
    None = 0,
    MovementDebtTooHigh = 1,
    FlashWearBudgetExceeded = 2,
    PaybackWindowTooLong = 3,
    NoLegalTarget = 4,
    ReceiptWouldWeaken = 5,
    SourceQuarantined = 6,
    ReclaimReserveUnavailable = 7,
    CooldownActive = 8,
    CostBudgetExceeded = 9,
    StaleEvidence = 10,
}

impl_u8_canonical!(EvidenceConsumerClass, {
    Planner = 0 => "planner",
    Reconciler = 1 => "reconciler",
    ReadPath = 2 => "read-path",
    ActionExecutor = 3 => "action-executor",
    MeasurementAttribution = 4 => "measurement-attribution",
    OperatorExplanation = 5 => "operator-explanation",
    PerformanceGate = 6 => "performance-gate",
    FaultGate = 7 => "fault-gate",
    ClaimGate = 8 => "claim-gate",
});

impl_u8_canonical!(EvidenceQueryContextClass, {
    Unknown = 0 => "unknown",
    RequestAdmission = 1 => "request-admission",
    ActionAdmission = 2 => "action-admission",
    ReadServing = 3 => "read-serving",
    CacheOnlyRead = 4 => "cache-only-read",
    Validation = 5 => "validation",
    OperatorExplanation = 6 => "operator-explanation",
    PerformanceRow = 7 => "performance-row",
    FaultRow = 8 => "fault-row",
    Claim = 9 => "claim",
    PrefetchResidency = 10 => "prefetch-residency",
    MeasurementAttribution = 11 => "measurement-attribution",
});

impl_u8_canonical!(EvidenceQuerySubjectScopeClass, {
    Unknown = 0 => "unknown",
    Request = 1 => "request",
    Action = 2 => "action",
    ObjectRange = 3 => "object-range",
    Dataset = 4 => "dataset",
    Pool = 5 => "pool",
    Domain = 6 => "domain",
    Cluster = 7 => "cluster",
    ValidationArtifact = 8 => "validation-artifact",
    Claim = 9 => "claim",
});

impl_u8_canonical!(EvidenceCompletenessVerdict, {
    UnknownEvidence = 0 => "unknown-evidence",
    CompleteForPurpose = 1 => "complete-for-purpose",
    PartialAdmissible = 2 => "partial-admissible",
    DegradedVisible = 3 => "degraded-visible",
    Blocked = 4 => "blocked",
    Refused = 5 => "refused",
    UnsafeVisible = 6 => "unsafe-visible",
});

impl_u8_canonical!(EvidenceFamilyFreshnessState, {
    Unknown = 0 => "unknown",
    Fresh = 1 => "fresh",
    Missing = 2 => "missing",
    Stale = 3 => "stale",
    Contradictory = 4 => "contradictory",
    Superseded = 5 => "superseded",
    Redacted = 6 => "redacted",
    Compacted = 7 => "compacted",
    Unavailable = 8 => "unavailable",
    Refused = 9 => "refused",
});

impl_u8_canonical!(EvidenceRetentionClass, {
    ExactRequired = 0 => "exact-required",
    Summarizable = 1 => "summarizable",
    Redactable = 2 => "redactable",
    Purgeable = 3 => "purgeable",
});

impl_u8_canonical!(StorageIntentMeasurementAttributionVerdict, {
    Unknown = 0 => "unknown",
    Attributable = 1 => "attributable",
    PartiallyAttributableWithBounds = 2 => "partially-attributable-with-bounds",
    Confounded = 3 => "confounded",
    InsufficientSample = 4 => "insufficient-sample",
    Stale = 5 => "stale",
    Contradicted = 6 => "contradicted",
    ShadowOnly = 7 => "shadow-only",
    Refused = 8 => "refused",
});

impl_u8_canonical!(StorageIntentMeasurementBaselineClass, {
    Unknown = 0 => "unknown",
    PriorAdmittedVariant = 1 => "prior-admitted-variant",
    ShadowTarget = 2 => "shadow-target",
    IncumbentPeerComparator = 3 => "incumbent-peer-comparator",
    NoopCounterfactual = 4 => "noop-counterfactual",
    SamePolicyCohort = 5 => "same-policy-cohort",
    NoValidBaselineRefused = 6 => "no-valid-baseline-refused",
});

impl_u8_canonical!(StorageIntentMeasurementMetricDimension, {
    Latency = 0 => "latency",
    TailLatency = 1 => "tail-latency",
    Throughput = 2 => "throughput",
    Iops = 3 => "iops",
    CacheHitRatio = 4 => "cache-hit-ratio",
    ReadAmplification = 5 => "read-amplification",
    WriteAmplification = 6 => "write-amplification",
    MediaWriteBytes = 7 => "media-write-bytes",
    WearCost = 8 => "wear-cost",
    NetworkEgressBytes = 9 => "network-egress-bytes",
    RestoreBytes = 10 => "restore-bytes",
    CostMicrounits = 11 => "cost-microunits",
    RpoLag = 12 => "rpo-lag",
    CpuTime = 13 => "cpu-time",
    ForegroundHarm = 14 => "foreground-harm",
    PaybackWindow = 15 => "payback-window",
});

impl_u8_canonical!(StorageIntentMeasurementMetricUnit, {
    UnitlessPpm = 0 => "unitless-ppm",
    Microseconds = 1 => "microseconds",
    Milliseconds = 2 => "milliseconds",
    Bytes = 3 => "bytes",
    BytesPerSecond = 4 => "bytes-per-second",
    Iops = 5 => "iops",
    CostMicrounits = 6 => "cost-microunits",
    Count = 7 => "count",
});

impl_u8_canonical!(StorageIntentMeasurementMetricState, {
    Unknown = 0 => "unknown",
    Known = 1 => "known",
    Bounded = 2 => "bounded",
    Censored = 3 => "censored",
    Dropped = 4 => "dropped",
    Refused = 5 => "refused",
});

impl_u8_canonical!(StorageIntentOrderingOperationScope, {
    Unknown = 0 => "unknown",
    RangeWrite = 1 => "range-write",
    FileFsync = 2 => "file-fsync",
    FileFdatasync = 3 => "file-fdatasync",
    DirectoryFsync = 4 => "directory-fsync",
    ODsyncDataWrite = 5 => "odsync-data-write",
    FuaBlockWrite = 6 => "fua-block-write",
    MsyncSync = 7 => "msync-sync",
    SyncfsDatasetBarrier = 8 => "syncfs-dataset-barrier",
    LocalIntentReplay = 9 => "local-intent-replay",
    QuorumIntentFanout = 10 => "quorum-intent-fanout",
    RelocationCutover = 11 => "relocation-cutover",
    Rebake = 12 => "rebake",
    Repair = 13 => "repair",
    ReceiptRetirement = 14 => "receipt-retirement",
});

impl_u8_canonical!(StorageIntentOrderingAggregationClass, {
    Single = 0 => "single",
    Batched = 1 => "batched",
    Sharded = 2 => "sharded",
    Coalesced = 3 => "coalesced",
    Pipelined = 4 => "pipelined",
    QuorumFanout = 5 => "quorum-fanout",
});

impl_u8_canonical!(StorageIntentOrderingCompletionState, {
    Unknown = 0 => "unknown",
    PendingReplay = 1 => "pending-replay",
    PendingConvergence = 2 => "pending-convergence",
    Satisfied = 3 => "satisfied",
    DegradedVisible = 4 => "degraded-visible",
    Refused = 5 => "refused",
    Retired = 6 => "retired",
});

impl_u8_canonical!(DurabilityState, {
    Volatile = 0 => "volatile",
    DurableIntent = 1 => "durable-intent",
    FullPlacement = 2 => "full-placement",
});

impl_u8_canonical!(SessionSecurityClass, {
    None = 0 => "none",
    Authenticated = 1 => "authenticated",
    Encrypted = 2 => "encrypted",
    MutualAuthenticated = 3 => "mutual-authenticated",
    Attested = 4 => "attested",
});

impl_u8_canonical!(ResidencyScope, {
    Unspecified = 0 => "unspecified",
    LocalNode = 1 => "local-node",
    Datacenter = 2 => "datacenter",
    Region = 3 => "region",
    Jurisdiction = 4 => "jurisdiction",
    GeoReplicaAllowed = 5 => "geo-replica-allowed",
    InternetAllowed = 6 => "internet-allowed",
});

impl_u8_canonical!(SharingDomainClass, {
    PrivateDataset = 0 => "private-dataset",
    SameTenant = 1 => "same-tenant",
    CrossTenantAllowed = 2 => "cross-tenant-allowed",
    PublicInternet = 3 => "public-internet",
});

impl_u8_canonical!(CompromiseState, {
    Clear = 0 => "clear",
    Suspect = 1 => "suspect",
    Compromised = 2 => "compromised",
});

impl_u8_canonical!(QuarantineState, {
    Clear = 0 => "clear",
    Pending = 1 => "pending",
    Quarantined = 2 => "quarantined",
});

impl_u8_canonical!(StorageIntentTrustRole, {
    SyncIntent = 0 => "sync-intent",
    QuorumIntent = 1 => "quorum-intent",
    GeoIntent = 2 => "geo-intent",
    DurablePlacement = 3 => "durable-placement",
    ReadServing = 4 => "read-serving",
    DegradedReconstruction = 5 => "degraded-reconstruction",
    AuthoritativeRam = 6 => "authoritative-ram",
    RepairSource = 7 => "repair-source",
    RelocationTarget = 8 => "relocation-target",
    DedupRebakeSharing = 9 => "dedup-rebake-sharing",
    ArchiveRestore = 10 => "archive-restore",
});

impl_u8_canonical!(TrustEvidenceFreshnessState, {
    Unknown = 0 => "unknown",
    Fresh = 1 => "fresh",
    Missing = 2 => "missing",
    Stale = 3 => "stale",
    Contradictory = 4 => "contradictory",
    Refused = 5 => "refused",
});

impl_u8_canonical!(TrustKeyLifecycleState, {
    Unknown = 0 => "unknown",
    Active = 1 => "active",
    RotatingDualValid = 2 => "rotating-dual-valid",
    Revoked = 3 => "revoked",
    Quarantined = 4 => "quarantined",
    Retired = 5 => "retired",
});

impl_u8_canonical!(TrustRevocationState, {
    Clear = 0 => "clear",
    Revoked = 1 => "revoked",
});

impl_u8_canonical!(DedupSharingCompatibilityState, {
    Unknown = 0 => "unknown",
    Compatible = 1 => "compatible",
    SameTenantOnly = 2 => "same-tenant-only",
    CrossTenantForbidden = 3 => "cross-tenant-forbidden",
    Refused = 4 => "refused",
});

impl_u8_canonical!(StorageMediaClass, {
    SystemRam = 0 => "system-ram",
    RemoteRam = 1 => "remote-ram",
    PersistentMemory = 2 => "persistent-memory",
    NvmeFlash = 3 => "nvme-flash",
    SsdFlash = 4 => "ssd-flash",
    HddRotational = 5 => "hdd-rotational",
    ZonedHdd = 6 => "zoned-hdd",
    ZonedFlash = 7 => "zoned-flash",
    ObjectAppliance = 8 => "object-appliance",
    CloudObject = 9 => "cloud-object",
    OpticalArchive = 10 => "optical-archive",
    TapeArchive = 11 => "tape-archive",
});

impl_u8_canonical!(MediaPersistenceDomain, {
    Unknown = 0 => "unknown",
    VolatileRam = 1 => "volatile-ram",
    CacheOnlyVolatile = 2 => "cache-only-volatile",
    PlpBackedVolatileCache = 3 => "plp-backed-volatile-cache",
    OrdinaryPersistent = 4 => "ordinary-persistent",
    PersistentMemory = 5 => "persistent-memory",
    RotationalPersistent = 6 => "rotational-persistent",
    RemoteDurable = 7 => "remote-durable",
    ObjectDurable = 8 => "object-durable",
    ArchiveDurable = 9 => "archive-durable",
});

impl_u8_canonical!(MediaFlushOrderingClass, {
    Unknown = 0 => "unknown",
    None = 1 => "none",
    FlushOnly = 2 => "flush-only",
    FuaOnly = 3 => "fua-only",
    FlushAndFua = 4 => "flush-and-fua",
    PmemFlushFence = 5 => "pmem-flush-fence",
    OrderedRemoteCommit = 6 => "ordered-remote-commit",
    ObjectCommit = 7 => "object-commit",
    ArchiveCommit = 8 => "archive-commit",
});

impl_u8_canonical!(MediaAtomicityClass, {
    Unknown = 0 => "unknown",
    TornWritesPossible = 1 => "torn-writes-possible",
    LogicalBlockAtomic = 2 => "logical-block-atomic",
    PhysicalBlockAtomic = 3 => "physical-block-atomic",
    AtomicWriteUnit = 4 => "atomic-write-unit",
    IdempotentObjectPut = 5 => "idempotent-object-put",
    AppendRecordAtomic = 6 => "append-record-atomic",
});

impl_u8_canonical!(MediaProtocolGeometryClass, {
    Unknown = 0 => "unknown",
    RamByteAddressable = 1 => "ram-byte-addressable",
    PmemByteAddressable = 2 => "pmem-byte-addressable",
    RandomBlock = 3 => "random-block",
    RotationalSeek = 4 => "rotational-seek",
    ZonedSequential = 5 => "zoned-sequential",
    ZonedAppend = 6 => "zoned-append",
    ObjectKeyValue = 7 => "object-key-value",
    RemoteObject = 8 => "remote-object",
    ArchiveSequential = 9 => "archive-sequential",
});

impl_u8_canonical!(MediaHealthState, {
    Unknown = 0 => "unknown",
    Healthy = 1 => "healthy",
    Warning = 2 => "warning",
    Degraded = 3 => "degraded",
    Failed = 4 => "failed",
    Quarantined = 5 => "quarantined",
});

impl_u8_canonical!(MediaCapabilityFreshnessState, {
    Missing = 0 => "missing",
    Fresh = 1 => "fresh",
    Stale = 2 => "stale",
    Contradictory = 3 => "contradictory",
    Refused = 4 => "refused",
});

impl_u8_canonical!(MediaRemoteCommitSemantics, {
    Unknown = 0 => "unknown",
    NotRemote = 1 => "not-remote",
    VolatileAckOnly = 2 => "volatile-ack-only",
    DurableAck = 3 => "durable-ack",
    QuorumDurableAck = 4 => "quorum-durable-ack",
    ObjectConditionalDurable = 5 => "object-conditional-durable",
    ArchiveRetained = 6 => "archive-retained",
    RdmaRequiredOnly = 7 => "rdma-required-only",
});

impl_u8_canonical!(MediaArchiveRestoreSemantics, {
    Unknown = 0 => "unknown",
    NotArchive = 1 => "not-archive",
    RestoreUnbounded = 2 => "restore-unbounded",
    RestoreRetained = 3 => "restore-retained",
    RestoreAudited = 4 => "restore-audited",
});

impl_u8_canonical!(RamAuthorityClass, {
    NonAuthoritativeCache = 0 => "non-authoritative-cache",
    RamVolatileLocal = 1 => "ram-volatile-local",
    RamVolatileReplicated = 2 => "ram-volatile-replicated",
    RamIntentBacked = 3 => "ram-intent-backed",
    PmemDurable = 4 => "pmem-durable",
});

impl_u8_canonical!(AuthorityEvent, {
    ProcessCrash = 0 => "process-crash",
    DaemonRestart = 1 => "daemon-restart",
    HostCrash = 2 => "host-crash",
    PowerLoss = 3 => "power-loss",
    PeerLoss = 4 => "peer-loss",
    NetworkPartition = 5 => "network-partition",
    FencingAmbiguity = 6 => "fencing-ambiguity",
    ReplayAfterDurableIntent = 7 => "replay-after-durable-intent",
});

impl_u8_canonical!(WorkloadShape, {
    Unknown = 0 => "unknown",
    SyncSmallWrite = 1 => "sync-small-write",
    AsyncBulkWrite = 2 => "async-bulk-write",
    RandomReadHot = 3 => "random-read-hot",
    SequentialReadScan = 4 => "sequential-read-scan",
    MetadataHotset = 5 => "metadata-hotset",
    AppendLog = 6 => "append-log",
    MixedTailSensitive = 7 => "mixed-tail-sensitive",
    RepairRebuild = 8 => "repair-rebuild",
    GeoCatchup = 9 => "geo-catchup",
    ArchiveIngest = 10 => "archive-ingest",
    Scratch = 11 => "scratch",
});

impl_u8_canonical!(PredictionConfidence, {
    Unknown = 0 => "unknown",
    Low = 1 => "low",
    Medium = 2 => "medium",
    High = 3 => "high",
});

impl_u8_canonical!(ContradictionState, {
    None = 0 => "none",
    WeakContradiction = 1 => "weak-contradiction",
    StrongContradiction = 2 => "strong-contradiction",
    Refused = 3 => "refused",
});

impl_u8_canonical!(HintProvenance, {
    None = 0 => "none",
    Caller = 1 => "caller",
    OperatorPolicy = 2 => "operator-policy",
    RuntimeObserved = 3 => "runtime-observed",
    ImportedMetadata = 4 => "imported-metadata",
    BenchmarkProfile = 5 => "benchmark-profile",
    LearningModel = 6 => "learning-model",
});

impl_u8_canonical!(WorkloadSignalScopeClass, {
    Unknown = 0 => "unknown",
    Request = 1 => "request",
    SubjectRange = 2 => "subject-range",
    Dataset = 3 => "dataset",
    Pool = 4 => "pool",
    Device = 5 => "device",
    Path = 6 => "path",
    TenantBudget = 7 => "tenant-budget",
});

impl_u8_canonical!(SignalMaterializationMode, {
    Unknown = 0 => "unknown",
    MemoryOnlySketch = 1 => "memory-only-sketch",
    SampledCounter = 2 => "sampled-counter",
    DecayedHistogram = 3 => "decayed-histogram",
    TopKSet = 4 => "top-k-set",
    DurableSummary = 5 => "durable-summary",
    DerivedView = 6 => "derived-view",
    RetainedEvidence = 7 => "retained-evidence",
});

impl_u8_canonical!(AccessPatternClass, {
    Unknown = 0 => "unknown",
    SequentialRead = 1 => "sequential-read",
    StridedRead = 2 => "strided-read",
    VectorRead = 3 => "vector-read",
    SmallRandomHotset = 4 => "small-random-hotset",
    MetadataNamespace = 5 => "metadata-namespace",
    ManifestIndexFanout = 6 => "manifest-index-fanout",
    SnapshotCloneRepeat = 7 => "snapshot-clone-repeat",
    DegradedReconstruction = 8 => "degraded-reconstruction",
    WanGeoDelta = 9 => "wan-geo-delta",
    ObjectArchiveRestore = 10 => "object-archive-restore",
    OnePassScan = 11 => "one-pass-scan",
    PhaseChangingSparse = 12 => "phase-changing-sparse",
    NoisyAdversarial = 13 => "noisy-adversarial",
    SyncSmallWrite = 14 => "sync-small-write",
    AsyncBulkWrite = 15 => "async-bulk-write",
    OverwriteChurn = 16 => "overwrite-churn",
    AppendLog = 17 => "append-log",
    DatabaseWalFsync = 18 => "database-wal-fsync",
    VmImageMixedRead = 19 => "vm-image-mixed-read",
    MmapPageCacheReuse = 20 => "mmap-page-cache-reuse",
    BackupRestoreScan = 21 => "backup-restore-scan",
});

impl_u8_canonical!(PrefetchResidencyCandidateClass, {
    NoPrefetch = 0 => "no-prefetch",
    BoundedReadahead = 1 => "bounded-readahead",
    StridedVectorPrefetch = 2 => "strided-vector-prefetch",
    MetadataNamespacePrefetch = 3 => "metadata-namespace-prefetch",
    SmallRandomHotsetTrial = 4 => "small-random-hotset-trial",
    ManifestIndexPrefetch = 5 => "manifest-index-prefetch",
    SnapshotClonePrefetch = 6 => "snapshot-clone-prefetch",
    DegradedReadPrefetch = 7 => "degraded-read-prefetch",
    WanGeoDeltaPrefetch = 8 => "wan-geo-delta-prefetch",
    ObjectArchiveRestoreStage = 9 => "object-archive-restore-stage",
    CacheOnlyTrial = 10 => "cache-only-trial",
    VolatileRamTrial = 11 => "volatile-ram-trial",
    IntentBackedRam = 12 => "intent-backed-ram",
    PmemDurable = 13 => "pmem-durable",
    FlashHotServing = 14 => "flash-hot-serving",
    HddLocalityOptimized = 15 => "hdd-locality-optimized",
    AuthorityPromotionCandidate = 16 => "authority-promotion-candidate",
    DemotionCandidate = 17 => "demotion-candidate",
    Cooldown = 18 => "cooldown",
    NeedMoreEvidence = 19 => "need-more-evidence",
    Refused = 20 => "refused",
});

impl_u8_canonical!(PrefetchResidencyPolicyScope, {
    Unknown = 0 => "unknown",
    PoolDefault = 1 => "pool-default",
    Dataset = 2 => "dataset",
    SubjectRange = 3 => "subject-range",
});

impl_u8_canonical!(PrefetchResidencyStateClass, {
    Unknown = 0 => "unknown",
    CacheOnlyRam = 1 => "cache-only-ram",
    VolatileRamServingTrial = 2 => "volatile-ram-serving-trial",
    IntentBackedRam = 3 => "intent-backed-ram",
    PmemDurable = 4 => "pmem-durable",
    FlashHotServing = 5 => "flash-hot-serving",
    HddColdLocalityOptimized = 6 => "hdd-cold-locality-optimized",
    RemoteDurable = 7 => "remote-durable",
    WanGeoAsync = 8 => "wan-geo-async",
    ObjectArchiveStaged = 9 => "object-archive-staged",
    Refused = 10 => "refused",
});

impl_u8_canonical!(PrefetchResidencyDecisionOutcome, {
    NoAction = 0 => "no-action",
    Admitted = 1 => "admitted",
    Lowered = 2 => "lowered",
    CacheOnly = 3 => "cache-only",
    ServingTrial = 4 => "serving-trial",
    PromotionCandidate = 5 => "promotion-candidate",
    DemotionCandidate = 6 => "demotion-candidate",
    Cooldown = 7 => "cooldown",
    NeedMoreEvidence = 8 => "need-more-evidence",
    Refused = 9 => "refused",
});

impl_u8_canonical!(StorageIntentActionClass, {
    QueuePrefetchTuning = 0 => "queue-prefetch-tuning",
    CacheOnlyServingTrial = 1 => "cache-only-serving-trial",
    NewWriteShaping = 2 => "new-write-shaping",
    FlashServingPromotion = 3 => "flash-serving-promotion",
    AuthorityPromotion = 4 => "authority-promotion",
    DurablePlacementMovement = 5 => "durable-placement-movement",
    ReadSourceRefresh = 6 => "read-source-refresh",
    DegradedReadReconstruction = 7 => "degraded-read-reconstruction",
    ReadTriggeredRepair = 8 => "read-triggered-repair",
    DefragRepack = 9 => "defrag-repack",
    ReclaimRelocation = 10 => "reclaim-relocation",
    GeoCatchup = 11 => "geo-catchup",
    ArchiveMigration = 12 => "archive-migration",
});

impl_u8_canonical!(StorageIntentActionExecutionStepState, {
    Unknown = 0 => "unknown",
    Planned = 1 => "planned",
    Admitted = 2 => "admitted",
    Prepared = 3 => "prepared",
    Copying = 4 => "copying",
    Verifying = 5 => "verifying",
    Publishing = 6 => "publishing",
    Cutover = 7 => "cutover",
    RetiringSource = 8 => "retiring-source",
    Complete = 9 => "complete",
    Aborted = 10 => "aborted",
    RolledBack = 11 => "rolled-back",
    Refused = 12 => "refused",
});

impl_u8_canonical!(StorageIntentActionReplayState, {
    Unknown = 0 => "unknown",
    FirstAttempt = 1 => "first-attempt",
    RetryInProgress = 2 => "retry-in-progress",
    CrashRecovery = 3 => "crash-recovery",
    DuplicateSuppressed = 4 => "duplicate-suppressed",
    ReplayRefused = 5 => "replay-refused",
});

impl_u8_canonical!(StorageIntentActionEvidenceState, {
    Unknown = 0 => "unknown",
    Fresh = 1 => "fresh",
    DecisionFrontierStale = 2 => "decision-frontier-stale",
    PolicyRevisionChanged = 3 => "policy-revision-changed",
    MediaCapabilityChanged = 4 => "media-capability-changed",
    CapacityReserveChanged = 5 => "capacity-reserve-changed",
    MembershipChanged = 6 => "membership-changed",
    TrustChanged = 7 => "trust-changed",
    TemporalExpired = 8 => "temporal-expired",
    EvidenceRetentionCompacted = 9 => "evidence-retention-compacted",
});

impl_u8_canonical!(StorageIntentSourceRetirementState, {
    Unknown = 0 => "unknown",
    Forbidden = 1 => "forbidden",
    RetainedForRollback = 2 => "retained-for-rollback",
    PendingCompletion = 3 => "pending-completion",
    Ready = 4 => "ready",
    Retired = 5 => "retired",
});

impl_u8_canonical!(StorageIntentActionTargetVerificationState, {
    Unknown = 0 => "unknown",
    NotStarted = 1 => "not-started",
    PartialWrite = 2 => "partial-write",
    DigestMismatch = 3 => "digest-mismatch",
    DegradedPartial = 4 => "degraded-partial",
    Verified = 5 => "verified",
    Refused = 6 => "refused",
});

impl_u8_canonical!(StorageIntentActionPublicationState, {
    Unknown = 0 => "unknown",
    NotPublished = 1 => "not-published",
    ReplacementPublished = 2 => "replacement-published",
    CutoverVisible = 3 => "cutover-visible",
    SourceRetirementPublished = 4 => "source-retirement-published",
    NoCutover = 5 => "no-cutover",
});

impl_u8_canonical!(StorageIntentActionExecutionRefusalReason, {
    None = 0 => "none",
    MissingActionIdentity = 1 => "missing-action-identity",
    PlannerDecisionIsNotExecution = 2 => "planner-decision-is-not-execution",
    MissingDecisionAdmissionEvidence = 3 => "missing-decision-admission-evidence",
    StaleExecutionEvidence = 4 => "stale-execution-evidence",
    NonIdempotentReplay = 5 => "non-idempotent-replay",
    DuplicateActionDelivery = 6 => "duplicate-action-delivery",
    MissingSourceProtection = 7 => "missing-source-protection",
    TargetWriteIsNotCompletion = 8 => "target-write-is-not-completion",
    MissingTargetVerification = 9 => "missing-target-verification",
    PartialTargetWrite = 10 => "partial-target-write",
    MissingMediaFlushOrBarrierProof = 11 => "missing-media-flush-or-barrier-proof",
    MissingPublicationEvidence = 12 => "missing-publication-evidence",
    MissingOrderingEvidence = 13 => "missing-ordering-evidence",
    MissingRecoveryDegradationEvidence = 14 => "missing-recovery-degradation-evidence",
    MissingRetentionEvidence = 15 => "missing-retention-evidence",
    MissingActionCompletionEvidence = 16 => "missing-action-completion-evidence",
    SourceRetirementForbidden = 17 => "source-retirement-forbidden",
    ReserveExhausted = 18 => "reserve-exhausted",
    ReserveDoubleSpent = 19 => "reserve-double-spent",
    AbortRollbackIncomplete = 20 => "abort-rollback-incomplete",
    NoCutoverProofMissing = 21 => "no-cutover-proof-missing",
    ContradictoryReceiptPublication = 22 => "contradictory-receipt-publication",
    RefusedByActionEvidence = 23 => "refused-by-action-evidence",
});

impl_u8_canonical!(StorageIntentDecisionAuthorityMode, {
    Unknown = 0 => "unknown",
    Live = 1 => "live",
    Shadow = 2 => "shadow",
    Trial = 3 => "trial",
    Preflight = 4 => "preflight",
    Simulated = 5 => "simulated",
    Replay = 6 => "replay",
    Refused = 7 => "refused",
});

impl_u8_canonical!(StorageIntentDecisionCandidateClass, {
    Unknown = 0 => "unknown",
    AcknowledgmentPlan = 1 => "acknowledgment-plan",
    PlacementPlan = 2 => "placement-plan",
    ReadServingPlan = 3 => "read-serving-plan",
    SchedulingPlan = 4 => "scheduling-plan",
    RebakePlan = 5 => "rebake-plan",
    RelocationPlan = 6 => "relocation-plan",
    RepairPlan = 7 => "repair-plan",
    GeoPlan = 8 => "geo-plan",
    ReceiptRetirementPlan = 9 => "receipt-retirement-plan",
    PrefetchResidencyPlan = 10 => "prefetch-residency-plan",
    NoActionPlan = 11 => "no-action-plan",
});

impl_u8_canonical!(StorageIntentDecisionCandidateStatus, {
    Unknown = 0 => "unknown",
    Legal = 1 => "legal",
    Illegal = 2 => "illegal",
    DegradedVisible = 3 => "degraded-visible",
    Deferred = 4 => "deferred",
    Blocked = 5 => "blocked",
    Refused = 6 => "refused",
});

impl_u8_canonical!(StorageIntentDecisionHardGateKind, {
    Unknown = 0 => "unknown",
    Guarantee = 1 => "guarantee",
    ServiceObjective = 2 => "service-objective",
    OrderingReplay = 3 => "ordering-replay",
    MembershipFence = 4 => "membership-fence",
    TrustDomain = 5 => "trust-domain",
    Temporal = 6 => "temporal",
    MediaCapability = 7 => "media-capability",
    DataShape = 8 => "data-shape",
    Layout = 9 => "layout",
    Lifecycle = 10 => "lifecycle",
    CapacityReserve = 11 => "capacity-reserve",
    RecoveryDegradation = 12 => "recovery-degradation",
    PolicyRollout = 13 => "policy-rollout",
    TenantIsolation = 14 => "tenant-isolation",
    PredictionActionClass = 15 => "prediction-action-class",
    Transport = 16 => "transport",
    Wear = 17 => "wear",
    OperatorPolicy = 18 => "operator-policy",
});

impl_u8_canonical!(StorageIntentDecisionHardGateVerdict, {
    Unknown = 0 => "unknown",
    Passed = 1 => "passed",
    Failed = 2 => "failed",
    DegradedVisible = 3 => "degraded-visible",
    Blocked = 4 => "blocked",
    Deferred = 5 => "deferred",
    Refused = 6 => "refused",
});

impl_u8_canonical!(StorageIntentDecisionScoreDimension, {
    Latency = 0 => "latency",
    Tail = 1 => "tail",
    Throughput = 2 => "throughput",
    ServiceObjectiveHeadroom = 3 => "service-objective-headroom",
    OrderingReplayCost = 4 => "ordering-replay-cost",
    MediaWriteCost = 5 => "media-write-cost",
    CpuReadAmplification = 6 => "cpu-read-amplification",
    LayoutReclaimCost = 7 => "layout-reclaim-cost",
    LifecycleChurnRisk = 8 => "lifecycle-churn-risk",
    MembershipDrainRisk = 9 => "membership-drain-risk",
    CapacityCost = 10 => "capacity-cost",
    EgressCongestionCost = 11 => "egress-congestion-cost",
    RecoveryRpoRisk = 12 => "recovery-rpo-risk",
    ForegroundDisruption = 13 => "foreground-disruption",
    ConfidenceMispredictionRisk = 14 => "confidence-misprediction-risk",
    MovementDebt = 15 => "movement-debt",
    PaybackRisk = 16 => "payback-risk",
    OperationalComplexity = 17 => "operational-complexity",
});

impl_u8_canonical!(StorageIntentDecisionScoreUnit, {
    UnitlessPpm = 0 => "unitless-ppm",
    Microseconds = 1 => "microseconds",
    Bytes = 2 => "bytes",
    BytesPerSecond = 3 => "bytes-per-second",
    Iops = 4 => "iops",
    CostMicrounits = 5 => "cost-microunits",
    RiskPpm = 6 => "risk-ppm",
    Count = 7 => "count",
});

impl_u8_canonical!(StorageIntentDecisionScoreState, {
    UnknownCost = 0 => "unknown-cost",
    UnknownBenefit = 1 => "unknown-benefit",
    Known = 2 => "known",
    Blocked = 3 => "blocked",
    DegradedVisible = 4 => "degraded-visible",
    Refused = 5 => "refused",
    NotApplicable = 6 => "not-applicable",
});

impl_u8_canonical!(StorageIntentDecisionSelectionReason, {
    Unknown = 0 => "unknown",
    OnlyLegalCandidate = 1 => "only-legal-candidate",
    HighestScore = 2 => "highest-score",
    RequiredRepair = 3 => "required-repair",
    RequiredPolicy = 4 => "required-policy",
    TieBreak = 5 => "tie-break",
    NoCandidateLegal = 6 => "no-candidate-legal",
    Deferred = 7 => "deferred",
    Refused = 8 => "refused",
});

impl_u8_canonical!(StorageIntentDecisionTieBreakerClass, {
    None = 0 => "none",
    DeterministicOrderKey = 1 => "deterministic-order-key",
    PolicyPriority = 2 => "policy-priority",
    StableExistingPlacement = 3 => "stable-existing-placement",
    LowerMovementDebt = 4 => "lower-movement-debt",
    LowerCapacityCost = 5 => "lower-capacity-cost",
    HigherConfidence = 6 => "higher-confidence",
    LexicographicCandidateId = 7 => "lexicographic-candidate-id",
});

impl_u8_canonical!(StorageIntentDecisionSelectedState, {
    Unknown = 0 => "unknown",
    Shadow = 1 => "shadow",
    Trial = 2 => "trial",
    Admitted = 3 => "admitted",
    RollbackOnly = 4 => "rollback-only",
    Deferred = 5 => "deferred",
    Refused = 6 => "refused",
});

impl_u8_canonical!(ReadServingSourceClass, {
    Cache = 0 => "cache",
    ServingTrial = 1 => "serving-trial",
    RamAuthority = 2 => "ram-authority",
    PlacementReceipt = 3 => "placement-receipt",
    RemoteReceipt = 4 => "remote-receipt",
    DegradedReconstruction = 5 => "degraded-reconstruction",
    SnapshotGeneration = 6 => "snapshot-generation",
    GeoAsyncLag = 7 => "geo-async-lag",
    ArchiveRestore = 8 => "archive-restore",
});

impl_u8_canonical!(TransformRefusalClass, {
    None = 0 => "none",
    UnsupportedCompression = 1 => "unsupported-compression",
    UnsupportedChecksum = 2 => "unsupported-checksum",
    DedupDomainMismatch = 3 => "dedup-domain-mismatch",
    EncryptionKeyEpochStale = 4 => "encryption-key-epoch-stale",
    ErasureShapeIllegal = 5 => "erasure-shape-illegal",
    RebakeWouldWeakenReceipt = 6 => "rebake-would-weaken-receipt",
    ReplacementReceiptMissing = 7 => "replacement-receipt-missing",
});

impl_u8_canonical!(RecordSizeClass, {
    Unknown = 0 => "unknown",
    Tiny = 1 => "tiny",
    Small = 2 => "small",
    Medium = 3 => "medium",
    Large = 4 => "large",
    Huge = 5 => "huge",
    RangeOverride = 6 => "range-override",
});

impl_u8_canonical!(CompressionAlgorithmClass, {
    None = 0 => "none",
    Lz4Fast = 1 => "lz4-fast",
    Lz4High = 2 => "lz4-high",
    ZstdFast = 3 => "zstd-fast",
    ZstdHigh = 4 => "zstd-high",
    ZstdAdaptive = 5 => "zstd-adaptive",
    DictionaryBacked = 6 => "dictionary-backed",
    Custom = 7 => "custom",
});

impl_u8_canonical!(CompressionOrderingClass, {
    Unknown = 0 => "unknown",
    CompressThenEncrypt = 1 => "compress-then-encrypt",
    EncryptThenCompress = 2 => "encrypt-then-compress",
    CompressOnly = 3 => "compress-only",
    NoCompression = 4 => "no-compression",
});

impl_u8_canonical!(DigestSuiteClass, {
    Unknown = 0 => "unknown",
    Crc32cFraming = 1 => "crc32c-framing",
    Blake3Content = 2 => "blake3-content",
    Blake3KeyedRoot = 3 => "blake3-keyed-root",
    Crc32cPlusBlake3 = 4 => "crc32c-plus-blake3",
    FullIntegrityTrailerV2 = 5 => "full-integrity-trailer-v2",
});

impl_u8_canonical!(DedupFingerprintScopeClass, {
    Unknown = 0 => "unknown",
    NoDedup = 1 => "no-dedup",
    DatasetLocal = 2 => "dataset-local",
    TenantLocal = 3 => "tenant-local",
    SecurityDomain = 4 => "security-domain",
    CrossDomainAuthorized = 5 => "cross-domain-authorized",
    DedupRefused = 6 => "dedup-refused",
});

impl_u8_canonical!(CoalescingModeClass, {
    Unknown = 0 => "unknown",
    NoCoalescing = 1 => "no-coalescing",
    InlinePayload = 2 => "inline-payload",
    PackedSmallFiles = 3 => "packed-small-files",
    DirBlockInline = 4 => "dir-block-inline",
    XattrPayloadInline = 5 => "xattr-payload-inline",
    ExternalizedSmallObject = 6 => "externalized-small-object",
});

impl_u8_canonical!(RebakeEligibilityClass, {
    Unknown = 0 => "unknown",
    RebakeForbidden = 1 => "rebake-forbidden",
    ShadowEvaluation = 2 => "shadow-evaluation",
    EligibleAfterCooldown = 3 => "eligible-after-cooldown",
    EligibleImmediate = 4 => "eligible-immediate",
    ReplacementReceiptPending = 5 => "replacement-receipt-pending",
    PaybackWindowNotMet = 6 => "payback-window-not-met",
});

impl_u8_canonical!(DataShapeRefusalReason, {
    None = 0 => "none",
    UnknownDataShapeEvidence = 1 => "unknown-data-shape-evidence",
    StaleDataShapeEvidence = 2 => "stale-data-shape-evidence",
    WrongDomainForDedup = 3 => "wrong-domain-for-dedup",
    DedupCrossesTenantDomain = 4 => "dedup-crosses-tenant-domain",
    EncryptionBypassedForDedup = 5 => "encryption-bypassed-for-dedup",
    CompressedBeforeEncryptionOrderViolation = 6 => "compressed-before-encryption-order-violation",
    ECShapeBlocksReadServing = 7 => "ec-shape-blocks-read-serving",
    ECShapeExceedsRebuildBudget = 8 => "ec-shape-exceeds-rebuild-budget",
    ECShapeExceedsRestoreTime = 9 => "ec-shape-exceeds-restore-time",
    RecordSizeTooSmallForEC = 10 => "record-size-too-small-for-ec",
    RecordSizeTooLargeForOverwriteLatency = 11 => "record-size-too-large-for-overwrite-latency",
    DigestSuiteTooWeakForPolicy = 12 => "digest-suite-too-weak-for-policy",
    CompressionExceedsCpuBudget = 13 => "compression-exceeds-cpu-budget",
    CompressionExceedsMemoryBudget = 14 => "compression-exceeds-memory-budget",
    RebakePaybackWindowNotMet = 15 => "rebake-payback-window-not-met",
    RebakeReplacementReceiptMissing = 16 => "rebake-replacement-receipt-missing",
    CostBudgetExceeded = 17 => "cost-budget-exceeded",
});

impl_u8_canonical!(AllocationClass, {
    Unknown = 0 => "unknown",
    IntentLog = 1 => "intent-log",
    Metadata = 2 => "metadata",
    SmallData = 3 => "small-data",
    LargeSequential = 4 => "large-sequential",
    ErasureShard = 5 => "erasure-shard",
    ArchiveStripe = 6 => "archive-stripe",
    RepairScratch = 7 => "repair-scratch",
});

impl_u8_canonical!(SegmentRegionClass, {
    Unknown = 0 => "unknown",
    Hot = 1 => "hot",
    Warm = 2 => "warm",
    Cold = 3 => "cold",
    ZoneAppend = 4 => "zone-append",
    EraseBlockAligned = 5 => "erase-block-aligned",
    Fragmented = 6 => "fragmented",
});

impl_u8_canonical!(RelocationReasonClass, {
    Unknown = 0 => "unknown",
    DefragRotationalLocality = 1 => "defrag-rotational-locality",
    ReclaimPressure = 2 => "reclaim-pressure",
    FlashServingPromotion = 3 => "flash-serving-promotion",
    AuthorityConvergence = 4 => "authority-convergence",
    Evacuation = 5 => "evacuation",
    Repair = 6 => "repair",
    GeoCatchup = 7 => "geo-catchup",
    ArchiveMigration = 8 => "archive-migration",
    DataShapeRebake = 9 => "data-shape-rebake",
});

impl_u8_canonical!(RelocationLifecycleState, {
    Proposed = 0 => "proposed",
    Admitted = 1 => "admitted",
    Copying = 2 => "copying",
    Verifying = 3 => "verifying",
    PublishingReceipt = 4 => "publishing-receipt",
    RetiringSource = 5 => "retiring-source",
    Complete = 6 => "complete",
    Cooldown = 7 => "cooldown",
    Refused = 8 => "refused",
    Aborted = 9 => "aborted",
});

impl_u8_canonical!(SkippedMoveReason, {
    None = 0 => "none",
    MovementDebtTooHigh = 1 => "movement-debt-too-high",
    FlashWearBudgetExceeded = 2 => "flash-wear-budget-exceeded",
    PaybackWindowTooLong = 3 => "payback-window-too-long",
    NoLegalTarget = 4 => "no-legal-target",
    ReceiptWouldWeaken = 5 => "receipt-would-weaken",
    SourceQuarantined = 6 => "source-quarantined",
    ReclaimReserveUnavailable = 7 => "reclaim-reserve-unavailable",
    CooldownActive = 8 => "cooldown-active",
    CostBudgetExceeded = 9 => "cost-budget-exceeded",
    StaleEvidence = 10 => "stale-evidence",
});

/// Cost/wear and movement-debt evidence projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct CostWearRecord {
    pub movement_debt_bytes: u64,
    pub expected_write_bytes: u64,
    pub flash_wear_cost_ppm: u32,
    pub write_amplification_ppm: u32,
    pub egress_cost_microunits: u64,
    pub capacity_cost_microunits: u64,
    pub payback_window_ms: u64,
    pub payback_evidence: StorageIntentEvidenceRef,
    pub cooldown_until_ms: u64,
    pub skipped_reason: SkippedMoveReason,
    pub evidence: StorageIntentEvidenceRef,
}

/// Relocation lifecycle record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct RelocationLifecycleRecord {
    pub reason: RelocationReasonClass,
    pub state: RelocationLifecycleState,
    pub source_receipt: StorageIntentReceiptId,
    pub replacement_receipt: StorageIntentReceiptId,
    pub cost_wear: CostWearRecord,
    pub evidence: StorageIntentEvidenceRef,
}

/// Compiled storage-intent policy snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPolicy {
    pub policy_id: StorageIntentPolicyId,
    pub revision: StorageIntentPolicyRevision,
    pub requested_guarantee: StorageIntentGuaranteeClass,
    pub required_failure_domains: FailureDomainMask,
    pub max_proximity: ProximityClass,
    pub durability: DurabilityRequirement,
    pub trust: TrustRequirement,
    pub media: MediaRoleRequirement,
    pub workload: WorkloadPrediction,
    pub evidence_refs: StorageIntentEvidenceRefs,
}

impl Default for StorageIntentPolicy {
    fn default() -> Self {
        Self {
            policy_id: StorageIntentPolicyId::ZERO,
            revision: StorageIntentPolicyRevision(0),
            requested_guarantee: StorageIntentGuaranteeClass::VolatileLocal,
            required_failure_domains: FailureDomainMask::EMPTY,
            max_proximity: ProximityClass::ArchiveOffline,
            durability: DurabilityRequirement::VOLATILE,
            trust: TrustRequirement::NONE,
            media: MediaRoleRequirement::AUTHORITY,
            workload: WorkloadPrediction::default(),
            evidence_refs: StorageIntentEvidenceRefs::EMPTY,
        }
    }
}

/// Earned storage-intent receipt for one operation, range, or convergence step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentReceipt {
    pub receipt_id: StorageIntentReceiptId,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub ack_class: StorageIntentGuaranteeClass,
    pub failure_domains: FailureDomainMask,
    pub proximity: ProximityClass,
    pub durability: DurabilityReceiptState,
    pub trust: TrustEvidenceState,
    pub media_role: StorageMediaRole,
    pub media_class: StorageMediaClass,
    pub read_source: ReadServingSourceClass,
    pub action_class: StorageIntentActionClass,
    pub evidence_refs: StorageIntentEvidenceRefs,
}

impl Default for StorageIntentReceipt {
    fn default() -> Self {
        Self {
            receipt_id: StorageIntentReceiptId::ZERO,
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            ack_class: StorageIntentGuaranteeClass::VolatileLocal,
            failure_domains: FailureDomainMask::EMPTY,
            proximity: ProximityClass::ArchiveOffline,
            durability: DurabilityReceiptState::default(),
            trust: TrustEvidenceState::EMPTY,
            media_role: StorageMediaRole::SyncIntent,
            media_class: StorageMediaClass::SystemRam,
            read_source: ReadServingSourceClass::Cache,
            action_class: StorageIntentActionClass::QueuePrefetchTuning,
            evidence_refs: StorageIntentEvidenceRefs::EMPTY,
        }
    }
}

/// Typed refusal reason emitted by predicates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u16)]
pub enum StorageIntentRefusalReason {
    /// No refusal.
    #[default]
    None = 0,
    /// No receipt in the candidate set can satisfy the policy.
    NoLegalReceiptSet = 1,
    /// Ack class does not satisfy the requested guarantee floor.
    GuaranteeFloorNotMet = 2,
    /// Required failure-domain evidence is absent.
    FailureDomainNotMet = 3,
    /// Receipt path is farther than the allowed proximity.
    ProximityTooFar = 4,
    /// Durability state or lag/RPO bound is not met.
    DurabilityOrRpoNotMet = 5,
    /// Authenticated principal/peer evidence is missing.
    MissingAuthenticatedPrincipal = 6,
    /// Admin/security/tenant domain does not match policy.
    WrongDomain = 7,
    /// Key epoch evidence is absent or older than policy.
    StaleKeyEpoch = 8,
    /// Authorization evidence is missing.
    MissingAuthorization = 9,
    /// Audit evidence is missing.
    MissingAudit = 10,
    /// Required session security is missing or too weak.
    MissingRequiredSessionSecurity = 11,
    /// Sharing domain is not compatible with policy.
    IllegalSharingDomain = 12,
    /// Residency constraint is violated.
    ResidencyViolation = 13,
    /// Repair/source evidence marks the source compromised.
    CompromisedRepairSource = 14,
    /// Source, peer, or target is quarantined.
    QuarantinedSource = 15,
    /// Media role is not allowed by policy.
    MediaRoleNotAllowed = 16,
    /// Cache-only state attempted to satisfy authority.
    CacheCannotBeAuthority = 17,
    /// Volatile RAM attempted to satisfy durable intent or full placement.
    VolatileRamCannotSatisfyDurableIntent = 18,
    /// Temporary repair/scratch/optimizer state attempted to satisfy authority.
    TemporaryMediaCannotBeAuthority = 19,
    /// Persistent media was required but not present.
    PersistentMediaRequired = 20,
    /// Movement would weaken an existing receipt.
    ReceiptWouldWeaken = 21,
    /// Movement debt or payback window blocks optimizer action.
    MovementDebtNotPaidBack = 22,
    /// Flash wear budget blocks optimizer action.
    FlashWearBudgetExceeded = 23,
    /// Required evidence is missing, stale, contradictory, or refused.
    EvidenceNotUsable = 24,
    /// Media-capability evidence is absent or not a media-capability artifact.
    MissingMediaCapabilityEvidence = 25,
    /// Persistence domain is unknown or unproved.
    UnknownPersistenceDomain = 26,
    /// Flush, FUA, barrier, or ordering semantics are missing or too weak.
    UnsupportedFlushFuaSemantics = 27,
    /// Volatile write cache is not proven safe for a durable role.
    UnsafeVolatileWriteCache = 28,
    /// Device, namespace, path, or pool-member identity is unstable or stale.
    UnstableNamespaceIdentity = 29,
    /// Atomicity, block size, or write granularity is not legal for the role.
    WrongAtomicityGranularity = 30,
    /// Zoned or write-pointer constraints are not legal for the role.
    UnsupportedZoneWritePointer = 31,
    /// Media-capability evidence is older than the legal freshness frontier.
    StaleMediaCapabilityEvidence = 32,
    /// Health evidence reports a degraded, failed, or quarantined target.
    DegradedMediaHealth = 33,
    /// Remote/object commit semantics cannot prove the requested durability.
    UnsupportedRemoteCommitSemantics = 34,
    /// Persistent-memory durable authority lacks flush/fence proof.
    PmemFlushFenceMissing = 35,
    /// Archive restore or retention semantics are unknown or unbounded.
    UnknownArchiveRestoreRetention = 36,
    /// Correctness depends on RDMA being present for a remote target.
    RdmaRequiredForCorrectness = 37,
    /// Peer, principal, domain, trust epoch, or key lifecycle was revoked.
    RevokedTrustDomain = 38,
    /// Trust-domain evidence is missing, stale, contradictory, or refused.
    StaleTrustEvidence = 39,
    /// Required key-lease evidence is absent.
    MissingKeyLeaseEvidence = 40,
    /// Ordering evidence names a different caller-visible operation scope.
    WrongOrderingScope = 41,
    /// Required ordering evidence is absent or not an ordering artifact.
    MissingOrderingEvidence = 42,
    /// Ordering evidence is stale for the requested barrier or replay frontier.
    StaleOrderingEvidence = 43,
    /// Dirty epoch was not sealed for the acknowledged barrier.
    UnsealedDirtyEpoch = 44,
    /// Committed-root or publication boundary does not match the requirement.
    WrongCommittedRoot = 45,
    /// Ordering evidence does not cover the requested dataset/object/range.
    WrongOrderingRange = 46,
    /// Replay idempotency key or duplicate-suppression law is missing.
    NonIdempotentReplay = 47,
    /// Namespace dependency set is partial for a namespace barrier.
    PartialNamespaceEvidence = 48,
    /// Metadata delta set is incomplete for exact replay.
    IncompleteMetadataDelta = 49,
    /// Prior writeback error state was not preserved for the barrier.
    LostWritebackError = 50,
    /// Quorum fanout did not prove the required quorum count.
    UnderQuorum = 51,
    /// Ordering evidence contradicts another fresh authority artifact.
    ContradictoryOrderingEvidence = 52,
    /// Aggregation, batching, sharding, coalescing, or prediction would weaken order.
    OrderingAggregationWouldWeaken = 53,
    /// Ordering evidence records pending replay or convergence but not completion.
    PendingOrderingConvergence = 54,
    /// Required ordering dependency refs are absent from the same evidence cut.
    MissingOrderingDependency = 55,
    /// Temporal evidence is missing or not a temporal-evidence artifact.
    MissingTemporalEvidence = 56,
    /// Clock skew is unknown; wall-time claims cannot be proved.
    UnknownClockSkew = 57,
    /// Clock-health sample is stale and cannot support freshness claims.
    StaleClockHealthSample = 58,
    /// Clock has stepped backwards; wall-time comparisons are unreliable.
    BackwardsClockStep = 59,
    /// Temporal lease or expiry deadline has passed.
    ExpiredTemporalLease = 60,
    /// Policy rollout stage deadline has been crossed.
    CrossedPolicyStageDeadline = 61,
    /// Remote apply frontier evidence is missing; RPO cannot be proved.
    MissingRemoteApplyFrontier = 62,
    /// Evidence is sequence-only; wall-clock RPO or freshness cannot be proved.
    SequenceOnlyCannotSatisfyWallClockRpo = 63,
    /// Capacity/admission evidence is missing or not a capacity artifact.
    MissingCapacityAdmissionEvidence = 64,
    /// Capacity evidence is older than the legal admission frontier.
    StaleCapacityEvidence = 65,
    /// Capacity admission was not active when the role needed it.
    CapacityAdmissionNotActive = 66,
    /// Logical or requested headroom is exhausted.
    CapacityHeadroomExhausted = 67,
    /// Physical, allocation-class, or segment-class headroom is exhausted.
    PhysicalHeadroomExhausted = 68,
    /// Dataset quota, slop, or protected logical floor would be violated.
    QuotaOrSlopFloorExceeded = 69,
    /// Allocation ticket evidence is missing, stale, or expired.
    StaleAllocationTicket = 70,
    /// Reserve escrow or reserve receipt evidence has expired.
    ExpiredReserveEscrow = 71,
    /// Pending-free bytes were counted before publication and fences were safe.
    PendingFreeNotSafe = 72,
    /// Reclaimable bytes or reclaim debt were counted before retirement was safe.
    ReclaimDebtNotSafe = 73,
    /// Amplification estimate omitted required old-plus-new or transform overlap.
    CapacityAmplificationUnderestimated = 74,
    /// Claim or reserve ledgers report overcommitment.
    ReserveOvercommitted = 75,
    /// Admission would breach a protected sync, repair, evacuation, or retirement floor.
    ProtectedReserveWouldBeBreached = 76,
    /// Repair, rebuild, evacuation, or receipt-retirement reserve is exhausted.
    RecoveryReserveExhausted = 77,
    /// Relocation scratch reserve is exhausted.
    RelocationScratchReserveExhausted = 78,
    /// Geo catch-up backlog exceeds admitted reserve.
    GeoCatchUpReserveExceeded = 79,
    /// Background optimizer would borrow protected reserves without override.
    OptimizerProtectedReserveBorrow = 80,
    /// Data-shape evidence is unknown, missing, or not a data-shape artifact.
    UnknownDataShapeEvidence = 81,
    /// Data-shape evidence is stale or superseded.
    StaleDataShapeEvidence = 82,
    /// Transform refused for data-shape reasons (see DataShapeRefusalReason).
    DataShapeTransformRefused = 83,
    /// Compression ordering violates policy (e.g. compressed before encryption order).
    IllegalCompressionOrdering = 84,
    /// Dedup domain crosses encryption or tenant boundary without authorization.
    DedupCrossesTenantDomain = 85,
    /// Encryption was bypassed for dedup or compression convenience.
    EncryptionBypassedForDedup = 86,
    /// EC/archive shape blocks read-serving latency floors.
    ECShapeBlocksReadServing = 87,
    /// Rebake replacement receipt is missing; old shape cannot be retired.
    RebakeReplacementReceiptMissing = 88,
    /// Rebake payback window has not elapsed; cooldown required.
    RebakePaybackWindowNotMet = 89,
    /// Data-shape cost budget (CPU, memory, wear, WAN) would be exceeded.
    DataShapeCostBudgetExceeded = 90,
}

impl StorageIntentRefusalReason {
    /// Stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::NoLegalReceiptSet => "no-legal-receipt-set",
            Self::GuaranteeFloorNotMet => "guarantee-floor-not-met",
            Self::FailureDomainNotMet => "failure-domain-not-met",
            Self::ProximityTooFar => "proximity-too-far",
            Self::DurabilityOrRpoNotMet => "durability-or-rpo-not-met",
            Self::MissingAuthenticatedPrincipal => "missing-authenticated-principal",
            Self::WrongDomain => "wrong-domain",
            Self::StaleKeyEpoch => "stale-key-epoch",
            Self::MissingAuthorization => "missing-authorization",
            Self::MissingAudit => "missing-audit",
            Self::MissingRequiredSessionSecurity => "missing-required-session-security",
            Self::IllegalSharingDomain => "illegal-sharing-domain",
            Self::ResidencyViolation => "residency-violation",
            Self::CompromisedRepairSource => "compromised-repair-source",
            Self::QuarantinedSource => "quarantined-source",
            Self::MediaRoleNotAllowed => "media-role-not-allowed",
            Self::CacheCannotBeAuthority => "cache-cannot-be-authority",
            Self::VolatileRamCannotSatisfyDurableIntent => {
                "volatile-ram-cannot-satisfy-durable-intent"
            }
            Self::TemporaryMediaCannotBeAuthority => "temporary-media-cannot-be-authority",
            Self::PersistentMediaRequired => "persistent-media-required",
            Self::ReceiptWouldWeaken => "receipt-would-weaken",
            Self::MovementDebtNotPaidBack => "movement-debt-not-paid-back",
            Self::FlashWearBudgetExceeded => "flash-wear-budget-exceeded",
            Self::EvidenceNotUsable => "evidence-not-usable",
            Self::MissingMediaCapabilityEvidence => "missing-media-capability-evidence",
            Self::UnknownPersistenceDomain => "unknown-persistence-domain",
            Self::UnsupportedFlushFuaSemantics => "unsupported-flush-fua-semantics",
            Self::UnsafeVolatileWriteCache => "unsafe-volatile-write-cache",
            Self::UnstableNamespaceIdentity => "unstable-namespace-identity",
            Self::WrongAtomicityGranularity => "wrong-atomicity-granularity",
            Self::UnsupportedZoneWritePointer => "unsupported-zone-write-pointer",
            Self::StaleMediaCapabilityEvidence => "stale-media-capability-evidence",
            Self::DegradedMediaHealth => "degraded-media-health",
            Self::UnsupportedRemoteCommitSemantics => "unsupported-remote-commit-semantics",
            Self::PmemFlushFenceMissing => "pmem-flush-fence-missing",
            Self::UnknownArchiveRestoreRetention => "unknown-archive-restore-retention",
            Self::RdmaRequiredForCorrectness => "rdma-required-for-correctness",
            Self::RevokedTrustDomain => "revoked-trust-domain",
            Self::StaleTrustEvidence => "stale-trust-evidence",
            Self::MissingKeyLeaseEvidence => "missing-key-lease-evidence",
            Self::WrongOrderingScope => "wrong-ordering-scope",
            Self::MissingOrderingEvidence => "missing-ordering-evidence",
            Self::StaleOrderingEvidence => "stale-ordering-evidence",
            Self::UnsealedDirtyEpoch => "unsealed-dirty-epoch",
            Self::WrongCommittedRoot => "wrong-root",
            Self::WrongOrderingRange => "wrong-range",
            Self::NonIdempotentReplay => "non-idempotent-replay",
            Self::PartialNamespaceEvidence => "partial-namespace-evidence",
            Self::IncompleteMetadataDelta => "incomplete-metadata-delta",
            Self::LostWritebackError => "lost-writeback-error",
            Self::UnderQuorum => "under-quorum",
            Self::ContradictoryOrderingEvidence => "contradictory-ordering-evidence",
            Self::OrderingAggregationWouldWeaken => "ordering-aggregation-would-weaken",
            Self::PendingOrderingConvergence => "pending-ordering-convergence",
            Self::MissingOrderingDependency => "missing-ordering-dependency",
            Self::MissingTemporalEvidence => "missing-temporal-evidence",
            Self::UnknownClockSkew => "unknown-clock-skew",
            Self::StaleClockHealthSample => "stale-clock-health-sample",
            Self::BackwardsClockStep => "backwards-clock-step",
            Self::ExpiredTemporalLease => "expired-temporal-lease",
            Self::CrossedPolicyStageDeadline => "crossed-policy-stage-deadline",
            Self::MissingRemoteApplyFrontier => "missing-remote-apply-frontier",
            Self::SequenceOnlyCannotSatisfyWallClockRpo => {
                "sequence-only-cannot-satisfy-wall-clock-rpo"
            }
            Self::MissingCapacityAdmissionEvidence => "missing-capacity-admission-evidence",
            Self::StaleCapacityEvidence => "stale-capacity-evidence",
            Self::CapacityAdmissionNotActive => "capacity-admission-not-active",
            Self::CapacityHeadroomExhausted => "capacity-headroom-exhausted",
            Self::PhysicalHeadroomExhausted => "physical-headroom-exhausted",
            Self::QuotaOrSlopFloorExceeded => "quota-or-slop-floor-exceeded",
            Self::StaleAllocationTicket => "stale-allocation-ticket",
            Self::ExpiredReserveEscrow => "expired-reserve-escrow",
            Self::PendingFreeNotSafe => "pending-free-not-safe",
            Self::ReclaimDebtNotSafe => "reclaim-debt-not-safe",
            Self::CapacityAmplificationUnderestimated => "capacity-amplification-underestimated",
            Self::ReserveOvercommitted => "reserve-overcommitted",
            Self::ProtectedReserveWouldBeBreached => "protected-reserve-would-be-breached",
            Self::RecoveryReserveExhausted => "recovery-reserve-exhausted",
            Self::RelocationScratchReserveExhausted => "relocation-scratch-reserve-exhausted",
            Self::GeoCatchUpReserveExceeded => "geo-catch-up-reserve-exceeded",
            Self::OptimizerProtectedReserveBorrow => "optimizer-protected-reserve-borrow",
            Self::UnknownDataShapeEvidence => "unknown-data-shape-evidence",
            Self::StaleDataShapeEvidence => "stale-data-shape-evidence",
            Self::DataShapeTransformRefused => "data-shape-transform-refused",
            Self::IllegalCompressionOrdering => "illegal-compression-ordering",
            Self::DedupCrossesTenantDomain => "dedup-crosses-tenant-domain",
            Self::EncryptionBypassedForDedup => "encryption-bypassed-for-dedup",
            Self::ECShapeBlocksReadServing => "ec-shape-blocks-read-serving",
            Self::RebakeReplacementReceiptMissing => "rebake-replacement-receipt-missing",
            Self::RebakePaybackWindowNotMet => "rebake-payback-window-not-met",
            Self::DataShapeCostBudgetExceeded => "data-shape-cost-budget-exceeded",
        }
    }

    /// Decode from stable discriminant. Unknown values fail closed.
    #[must_use]
    pub const fn from_discriminant(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::NoLegalReceiptSet),
            2 => Some(Self::GuaranteeFloorNotMet),
            3 => Some(Self::FailureDomainNotMet),
            4 => Some(Self::ProximityTooFar),
            5 => Some(Self::DurabilityOrRpoNotMet),
            6 => Some(Self::MissingAuthenticatedPrincipal),
            7 => Some(Self::WrongDomain),
            8 => Some(Self::StaleKeyEpoch),
            9 => Some(Self::MissingAuthorization),
            10 => Some(Self::MissingAudit),
            11 => Some(Self::MissingRequiredSessionSecurity),
            12 => Some(Self::IllegalSharingDomain),
            13 => Some(Self::ResidencyViolation),
            14 => Some(Self::CompromisedRepairSource),
            15 => Some(Self::QuarantinedSource),
            16 => Some(Self::MediaRoleNotAllowed),
            17 => Some(Self::CacheCannotBeAuthority),
            18 => Some(Self::VolatileRamCannotSatisfyDurableIntent),
            19 => Some(Self::TemporaryMediaCannotBeAuthority),
            20 => Some(Self::PersistentMediaRequired),
            21 => Some(Self::ReceiptWouldWeaken),
            22 => Some(Self::MovementDebtNotPaidBack),
            23 => Some(Self::FlashWearBudgetExceeded),
            24 => Some(Self::EvidenceNotUsable),
            25 => Some(Self::MissingMediaCapabilityEvidence),
            26 => Some(Self::UnknownPersistenceDomain),
            27 => Some(Self::UnsupportedFlushFuaSemantics),
            28 => Some(Self::UnsafeVolatileWriteCache),
            29 => Some(Self::UnstableNamespaceIdentity),
            30 => Some(Self::WrongAtomicityGranularity),
            31 => Some(Self::UnsupportedZoneWritePointer),
            32 => Some(Self::StaleMediaCapabilityEvidence),
            33 => Some(Self::DegradedMediaHealth),
            34 => Some(Self::UnsupportedRemoteCommitSemantics),
            35 => Some(Self::PmemFlushFenceMissing),
            36 => Some(Self::UnknownArchiveRestoreRetention),
            37 => Some(Self::RdmaRequiredForCorrectness),
            38 => Some(Self::RevokedTrustDomain),
            39 => Some(Self::StaleTrustEvidence),
            40 => Some(Self::MissingKeyLeaseEvidence),
            41 => Some(Self::WrongOrderingScope),
            42 => Some(Self::MissingOrderingEvidence),
            43 => Some(Self::StaleOrderingEvidence),
            44 => Some(Self::UnsealedDirtyEpoch),
            45 => Some(Self::WrongCommittedRoot),
            46 => Some(Self::WrongOrderingRange),
            47 => Some(Self::NonIdempotentReplay),
            48 => Some(Self::PartialNamespaceEvidence),
            49 => Some(Self::IncompleteMetadataDelta),
            50 => Some(Self::LostWritebackError),
            51 => Some(Self::UnderQuorum),
            52 => Some(Self::ContradictoryOrderingEvidence),
            53 => Some(Self::OrderingAggregationWouldWeaken),
            54 => Some(Self::PendingOrderingConvergence),
            55 => Some(Self::MissingOrderingDependency),
            56 => Some(Self::MissingTemporalEvidence),
            57 => Some(Self::UnknownClockSkew),
            58 => Some(Self::StaleClockHealthSample),
            59 => Some(Self::BackwardsClockStep),
            60 => Some(Self::ExpiredTemporalLease),
            61 => Some(Self::CrossedPolicyStageDeadline),
            62 => Some(Self::MissingRemoteApplyFrontier),
            63 => Some(Self::SequenceOnlyCannotSatisfyWallClockRpo),
            64 => Some(Self::MissingCapacityAdmissionEvidence),
            65 => Some(Self::StaleCapacityEvidence),
            66 => Some(Self::CapacityAdmissionNotActive),
            67 => Some(Self::CapacityHeadroomExhausted),
            68 => Some(Self::PhysicalHeadroomExhausted),
            69 => Some(Self::QuotaOrSlopFloorExceeded),
            70 => Some(Self::StaleAllocationTicket),
            71 => Some(Self::ExpiredReserveEscrow),
            72 => Some(Self::PendingFreeNotSafe),
            73 => Some(Self::ReclaimDebtNotSafe),
            74 => Some(Self::CapacityAmplificationUnderestimated),
            75 => Some(Self::ReserveOvercommitted),
            76 => Some(Self::ProtectedReserveWouldBeBreached),
            77 => Some(Self::RecoveryReserveExhausted),
            78 => Some(Self::RelocationScratchReserveExhausted),
            79 => Some(Self::GeoCatchUpReserveExceeded),
            80 => Some(Self::OptimizerProtectedReserveBorrow),
            81 => Some(Self::UnknownDataShapeEvidence),
            82 => Some(Self::StaleDataShapeEvidence),
            83 => Some(Self::DataShapeTransformRefused),
            84 => Some(Self::IllegalCompressionOrdering),
            85 => Some(Self::DedupCrossesTenantDomain),
            86 => Some(Self::EncryptionBypassedForDedup),
            87 => Some(Self::ECShapeBlocksReadServing),
            88 => Some(Self::RebakeReplacementReceiptMissing),
            89 => Some(Self::RebakePaybackWindowNotMet),
            90 => Some(Self::DataShapeCostBudgetExceeded),
            _ => None,
        }
    }

    /// Encode to stable discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u16 {
        self as u16
    }
}

impl fmt::Display for StorageIntentRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Predicate result for one receipt candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReceiptPredicateResult {
    pub satisfied: bool,
    pub refusal: StorageIntentRefusalReason,
}

impl ReceiptPredicateResult {
    /// Satisfied result.
    pub const SATISFIED: Self = Self {
        satisfied: true,
        refusal: StorageIntentRefusalReason::None,
    };

    /// Refused result.
    #[must_use]
    pub const fn refused(reason: StorageIntentRefusalReason) -> Self {
        Self {
            satisfied: false,
            refusal: reason,
        }
    }
}

/// Refusal record that can be surfaced to operators or validation artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentRefusal {
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub attempted_receipt: StorageIntentReceiptId,
    pub reason: StorageIntentRefusalReason,
    pub evidence: StorageIntentEvidenceRef,
}

/// Build a typed refusal when no legal receipt set satisfies a policy.
#[must_use]
pub const fn refusal_for_no_legal_receipt_set(
    policy: StorageIntentPolicy,
    reason: StorageIntentRefusalReason,
) -> StorageIntentRefusal {
    StorageIntentRefusal {
        policy_id: policy.policy_id,
        policy_revision: policy.revision,
        attempted_receipt: StorageIntentReceiptId::ZERO,
        reason,
        evidence: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
    }
}

/// Predicate: do trust/security dimensions satisfy policy?
#[must_use]
pub const fn trust_security_satisfies(
    required: TrustRequirement,
    observed: TrustEvidenceState,
) -> ReceiptPredicateResult {
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL)
        && !observed
            .flags
            .contains_all(TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingAuthenticatedPrincipal,
        );
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::ADMIN_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::ADMIN_DOMAIN)
            || (!required.admin_domain.is_zero()
                && !bytes16_equal(observed.admin_domain.0, required.admin_domain.0)))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::SECURITY_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::SECURITY_DOMAIN)
            || (!required.security_domain.is_zero()
                && !bytes16_equal(observed.security_domain.0, required.security_domain.0)))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::TENANT_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::TENANT_DOMAIN)
            || (!required.tenant_domain.is_zero()
                && !bytes16_equal(observed.tenant_domain.0, required.tenant_domain.0)))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::KEY_EPOCH)
        && (!observed.flags.contains_all(TrustEvidenceFlags::KEY_EPOCH)
            || observed.key_epoch < required.min_key_epoch)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleKeyEpoch);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::AUTHORIZATION)
        && !observed
            .flags
            .contains_all(TrustEvidenceFlags::AUTHORIZATION)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MissingAuthorization);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::AUDIT)
        && !observed.flags.contains_all(TrustEvidenceFlags::AUDIT)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MissingAudit);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::SESSION_SECURITY)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::SESSION_SECURITY)
            || !session_security_satisfies(
                required.min_session_security,
                observed.session_security,
            ))
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingRequiredSessionSecurity,
        );
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::RESIDENCY)
        && (!observed.flags.contains_all(TrustEvidenceFlags::RESIDENCY)
            || !residency_satisfies(required.residency, observed.residency))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ResidencyViolation);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::SHARING_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::SHARING_DOMAIN)
            || !sharing_domain_satisfies(required.sharing_domain, observed.sharing_domain))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::IllegalSharingDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::NOT_COMPROMISED)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::NOT_COMPROMISED)
            || matches!(observed.compromise_state, CompromiseState::Compromised))
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CompromisedRepairSource,
        );
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::NOT_QUARANTINED)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::NOT_QUARANTINED)
            || matches!(observed.quarantine_state, QuarantineState::Quarantined))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Role-specific default trust/domain requirement.
#[must_use]
pub const fn trust_domain_role_requirement(role: StorageIntentTrustRole) -> TrustDomainRequirement {
    TrustDomainRequirement {
        base: TrustRequirement {
            required_flags: trust_domain_role_required_flags(role),
            min_session_security: trust_domain_role_min_session_security(role),
            min_key_epoch: 0,
            admin_domain: StorageIntentDomainId::ZERO,
            security_domain: StorageIntentDomainId::ZERO,
            tenant_domain: StorageIntentDomainId::ZERO,
            residency: ResidencyScope::Unspecified,
            sharing_domain: SharingDomainClass::PrivateDataset,
        },
        dataset_domain: StorageIntentDomainId::ZERO,
        policy_domain: StorageIntentDomainId::ZERO,
        budget_owner_domain: StorageIntentDomainId::ZERO,
        encryption_domain: StorageIntentDomainId::ZERO,
        allowed_domain_classes: trust_domain_role_allowed_domain_floor(role),
        min_trust_epoch: 0,
        max_evidence_age_ms: 0,
    }
}

/// Predicate: can trust/domain evidence satisfy one storage-intent role?
#[must_use]
pub const fn trust_domain_role_satisfies(
    role: StorageIntentTrustRole,
    required: TrustDomainRequirement,
    observed: TrustEvidenceRecord,
) -> ReceiptPredicateResult {
    let role_flags = trust_domain_role_required_flags(role);
    let effective_flags = required.base.required_flags.union(role_flags);
    let effective = TrustRequirement {
        required_flags: effective_flags,
        min_session_security: trust_domain_session_floor(
            required.base.min_session_security,
            trust_domain_role_min_session_security(role),
        ),
        min_key_epoch: required.base.min_key_epoch,
        admin_domain: required.base.admin_domain,
        security_domain: required.base.security_domain,
        tenant_domain: required.base.tenant_domain,
        residency: required.base.residency,
        sharing_domain: required.base.sharing_domain,
    };

    let base = trust_security_satisfies(effective, observed.state);
    if !base.satisfied {
        return base;
    }

    trust_domain_record_refs_satisfy(role, required, effective_flags, observed)
}

#[must_use]
pub const fn trust_domain_role_required_flags(role: StorageIntentTrustRole) -> TrustEvidenceFlags {
    let common = TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL
        .union(TrustEvidenceFlags::PEER_IDENTITY)
        .union(TrustEvidenceFlags::ADMIN_DOMAIN)
        .union(TrustEvidenceFlags::SECURITY_DOMAIN)
        .union(TrustEvidenceFlags::SESSION_SECURITY)
        .union(TrustEvidenceFlags::TRUST_EPOCH)
        .union(TrustEvidenceFlags::FRESH_TRUST_EVIDENCE)
        .union(TrustEvidenceFlags::NOT_REVOKED)
        .union(TrustEvidenceFlags::NOT_QUARANTINED);

    match role {
        StorageIntentTrustRole::SyncIntent => common,
        StorageIntentTrustRole::QuorumIntent => common
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT),
        StorageIntentTrustRole::GeoIntent => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::RESIDENCY)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::REGULATORY_DOMAIN)
            .union(TrustEvidenceFlags::OPERATOR_ALLOWED_DOMAIN),
        StorageIntentTrustRole::DurablePlacement => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::POLICY_DOMAIN)
            .union(TrustEvidenceFlags::BUDGET_OWNER_DOMAIN)
            .union(TrustEvidenceFlags::ENCRYPTION_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::KEY_LEASE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::RESIDENCY),
        StorageIntentTrustRole::ReadServing => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT),
        StorageIntentTrustRole::DegradedReconstruction => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::RESIDENCY)
            .union(TrustEvidenceFlags::NOT_COMPROMISED),
        StorageIntentTrustRole::AuthoritativeRam => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::KEY_LEASE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT),
        StorageIntentTrustRole::RepairSource => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::RESIDENCY)
            .union(TrustEvidenceFlags::NOT_COMPROMISED),
        StorageIntentTrustRole::RelocationTarget => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::POLICY_DOMAIN)
            .union(TrustEvidenceFlags::BUDGET_OWNER_DOMAIN)
            .union(TrustEvidenceFlags::ENCRYPTION_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::KEY_LEASE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::RESIDENCY)
            .union(TrustEvidenceFlags::OPERATOR_ALLOWED_DOMAIN),
        StorageIntentTrustRole::DedupRebakeSharing => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::POLICY_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::SHARING_DOMAIN)
            .union(TrustEvidenceFlags::DEDUP_SHARING_COMPATIBLE),
        StorageIntentTrustRole::ArchiveRestore => common
            .union(TrustEvidenceFlags::TENANT_DOMAIN)
            .union(TrustEvidenceFlags::DATASET_DOMAIN)
            .union(TrustEvidenceFlags::POLICY_DOMAIN)
            .union(TrustEvidenceFlags::ENCRYPTION_DOMAIN)
            .union(TrustEvidenceFlags::KEY_EPOCH)
            .union(TrustEvidenceFlags::KEY_LIFECYCLE)
            .union(TrustEvidenceFlags::KEY_LEASE)
            .union(TrustEvidenceFlags::AUTHORIZATION)
            .union(TrustEvidenceFlags::AUDIT)
            .union(TrustEvidenceFlags::RESIDENCY)
            .union(TrustEvidenceFlags::REGULATORY_DOMAIN)
            .union(TrustEvidenceFlags::OPERATOR_ALLOWED_DOMAIN),
    }
}

#[must_use]
pub const fn trust_domain_role_min_session_security(
    role: StorageIntentTrustRole,
) -> SessionSecurityClass {
    match role {
        StorageIntentTrustRole::SyncIntent
        | StorageIntentTrustRole::DurablePlacement
        | StorageIntentTrustRole::ReadServing => SessionSecurityClass::Authenticated,
        StorageIntentTrustRole::QuorumIntent | StorageIntentTrustRole::AuthoritativeRam => {
            SessionSecurityClass::MutualAuthenticated
        }
        StorageIntentTrustRole::GeoIntent
        | StorageIntentTrustRole::DegradedReconstruction
        | StorageIntentTrustRole::RepairSource
        | StorageIntentTrustRole::RelocationTarget
        | StorageIntentTrustRole::DedupRebakeSharing
        | StorageIntentTrustRole::ArchiveRestore => SessionSecurityClass::Encrypted,
    }
}

#[must_use]
pub const fn trust_domain_role_allowed_domain_floor(
    role: StorageIntentTrustRole,
) -> TrustAllowedDomainMask {
    match role {
        StorageIntentTrustRole::GeoIntent => TrustAllowedDomainMask::GEO_ALLOWED,
        StorageIntentTrustRole::ArchiveRestore => TrustAllowedDomainMask::SAME_JURISDICTION
            .union(TrustAllowedDomainMask::OPERATOR_DEFINED),
        StorageIntentTrustRole::DedupRebakeSharing => TrustAllowedDomainMask::SAME_TENANT,
        StorageIntentTrustRole::RelocationTarget => TrustAllowedDomainMask::OPERATOR_DEFINED,
        _ => TrustAllowedDomainMask::EMPTY,
    }
}

const fn trust_domain_session_floor(
    requested: SessionSecurityClass,
    role_floor: SessionSecurityClass,
) -> SessionSecurityClass {
    match (requested, role_floor) {
        (SessionSecurityClass::Attested, _) | (_, SessionSecurityClass::Attested) => {
            SessionSecurityClass::Attested
        }
        (SessionSecurityClass::MutualAuthenticated, _)
        | (_, SessionSecurityClass::MutualAuthenticated) => {
            SessionSecurityClass::MutualAuthenticated
        }
        (SessionSecurityClass::Encrypted, _) | (_, SessionSecurityClass::Encrypted) => {
            SessionSecurityClass::Encrypted
        }
        (SessionSecurityClass::Authenticated, _) | (_, SessionSecurityClass::Authenticated) => {
            SessionSecurityClass::Authenticated
        }
        _ => SessionSecurityClass::None,
    }
}

const fn trust_domain_effective_allowed_mask(
    role: StorageIntentTrustRole,
    required: TrustAllowedDomainMask,
) -> TrustAllowedDomainMask {
    if required.is_empty() {
        trust_domain_role_allowed_domain_floor(role)
    } else {
        required
    }
}

const fn trust_domain_id_satisfies(
    required: StorageIntentDomainId,
    observed: StorageIntentDomainId,
) -> bool {
    !observed.is_zero() && (required.is_zero() || bytes16_equal(required.0, observed.0))
}

const fn trust_key_lifecycle_is_active(lifecycle: TrustKeyLifecycleState) -> bool {
    matches!(
        lifecycle,
        TrustKeyLifecycleState::Active | TrustKeyLifecycleState::RotatingDualValid
    )
}

const fn trust_domain_record_refs_satisfy(
    role: StorageIntentTrustRole,
    required: TrustDomainRequirement,
    flags: TrustEvidenceFlags,
    observed: TrustEvidenceRecord,
) -> ReceiptPredicateResult {
    if flags.contains_all(TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL)
        && !evidence_ref_has_id(observed.principal_ref)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingAuthenticatedPrincipal,
        );
    }
    if flags.contains_all(TrustEvidenceFlags::PEER_IDENTITY)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::PEER_IDENTITY)
            || !evidence_ref_has_id(observed.peer_identity_ref))
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingAuthenticatedPrincipal,
        );
    }
    if flags.contains_all(TrustEvidenceFlags::ADMIN_DOMAIN)
        && (!trust_domain_id_satisfies(required.base.admin_domain, observed.state.admin_domain)
            || !evidence_ref_has_id(observed.admin_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::SECURITY_DOMAIN)
        && (!trust_domain_id_satisfies(
            required.base.security_domain,
            observed.state.security_domain,
        ) || !evidence_ref_has_id(observed.security_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::TENANT_DOMAIN)
        && (!trust_domain_id_satisfies(required.base.tenant_domain, observed.state.tenant_domain)
            || !evidence_ref_has_id(observed.tenant_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::DATASET_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::DATASET_DOMAIN)
            || !trust_domain_id_satisfies(required.dataset_domain, observed.dataset_domain)
            || !evidence_ref_has_id(observed.dataset_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::POLICY_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::POLICY_DOMAIN)
            || !trust_domain_id_satisfies(required.policy_domain, observed.policy_domain)
            || !evidence_ref_has_id(observed.policy_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::BUDGET_OWNER_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::BUDGET_OWNER_DOMAIN)
            || !trust_domain_id_satisfies(
                required.budget_owner_domain,
                observed.budget_owner_domain,
            )
            || !evidence_ref_has_id(observed.budget_owner_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::ENCRYPTION_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::ENCRYPTION_DOMAIN)
            || !trust_domain_id_satisfies(required.encryption_domain, observed.encryption_domain)
            || !evidence_ref_has_id(observed.encryption_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::SESSION_SECURITY)
        && !evidence_ref_has_id(observed.session_security_ref)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingRequiredSessionSecurity,
        );
    }
    if flags.contains_all(TrustEvidenceFlags::KEY_EPOCH)
        && !evidence_ref_has_id(observed.key_epoch_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleKeyEpoch);
    }
    if flags.contains_all(TrustEvidenceFlags::KEY_LIFECYCLE) {
        if !observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::KEY_LIFECYCLE)
            || !evidence_ref_has_id(observed.key_lifecycle_ref)
        {
            return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleKeyEpoch);
        }
        if matches!(
            observed.key_lifecycle,
            TrustKeyLifecycleState::Revoked | TrustKeyLifecycleState::Retired
        ) {
            return ReceiptPredicateResult::refused(StorageIntentRefusalReason::RevokedTrustDomain);
        }
        if matches!(observed.key_lifecycle, TrustKeyLifecycleState::Quarantined) {
            return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
        }
        if !trust_key_lifecycle_is_active(observed.key_lifecycle) {
            return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleKeyEpoch);
        }
    }
    if flags.contains_all(TrustEvidenceFlags::KEY_LEASE)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::KEY_LEASE)
            || !evidence_ref_has_id(observed.key_lease_ref))
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingKeyLeaseEvidence,
        );
    }
    if flags.contains_all(TrustEvidenceFlags::AUTHORIZATION)
        && !evidence_ref_has_id(observed.authorization_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MissingAuthorization);
    }
    if flags.contains_all(TrustEvidenceFlags::AUDIT) && !evidence_ref_has_id(observed.audit_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MissingAudit);
    }
    if flags.contains_all(TrustEvidenceFlags::RESIDENCY)
        && !evidence_ref_has_id(observed.residency_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ResidencyViolation);
    }
    if flags.contains_all(TrustEvidenceFlags::SHARING_DOMAIN)
        && !evidence_ref_has_id(observed.sharing_domain_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::IllegalSharingDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::DEDUP_SHARING_COMPATIBLE)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::DEDUP_SHARING_COMPATIBLE)
            || !evidence_ref_has_id(observed.sharing_compatibility_ref)
            || !matches!(
                observed.sharing_compatibility,
                DedupSharingCompatibilityState::Compatible
            ))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::IllegalSharingDomain);
    }

    let required_allowed_domain =
        trust_domain_effective_allowed_mask(role, required.allowed_domain_classes);
    if flags.contains_all(TrustEvidenceFlags::REGULATORY_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::REGULATORY_DOMAIN)
            || required_allowed_domain.is_empty()
            || !observed
                .allowed_domain_classes
                .contains_all(required_allowed_domain)
            || !evidence_ref_has_id(observed.regulatory_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ResidencyViolation);
    }
    if flags.contains_all(TrustEvidenceFlags::OPERATOR_ALLOWED_DOMAIN)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::OPERATOR_ALLOWED_DOMAIN)
            || required_allowed_domain.is_empty()
            || !observed
                .allowed_domain_classes
                .contains_all(required_allowed_domain)
            || !evidence_ref_has_id(observed.operator_allowed_domain_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ResidencyViolation);
    }
    if flags.contains_all(TrustEvidenceFlags::TRUST_EPOCH)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::TRUST_EPOCH)
            || observed.trust_epoch < required.min_trust_epoch
            || !evidence_ref_has_id(observed.trust_epoch_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleTrustEvidence);
    }
    if flags.contains_all(TrustEvidenceFlags::FRESH_TRUST_EVIDENCE)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::FRESH_TRUST_EVIDENCE)
            || !matches!(observed.freshness_state, TrustEvidenceFreshnessState::Fresh)
            || (required.max_evidence_age_ms != 0
                && observed.evidence_age_ms > required.max_evidence_age_ms)
            || !evidence_ref_has_id(observed.freshness_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleTrustEvidence);
    }
    if flags.contains_all(TrustEvidenceFlags::NOT_REVOKED)
        && (!observed
            .state
            .flags
            .contains_all(TrustEvidenceFlags::NOT_REVOKED)
            || matches!(observed.revocation_state, TrustRevocationState::Revoked)
            || !evidence_ref_has_id(observed.revocation_ref))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::RevokedTrustDomain);
    }
    if flags.contains_all(TrustEvidenceFlags::NOT_COMPROMISED)
        && !evidence_ref_has_id(observed.compromise_ref)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CompromisedRepairSource,
        );
    }
    if flags.contains_all(TrustEvidenceFlags::NOT_QUARANTINED)
        && !evidence_ref_has_id(observed.quarantine_ref)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }

    ReceiptPredicateResult::SATISFIED
}

/// Predicate: is observed residency no broader than the required policy?
#[must_use]
pub const fn residency_satisfies(required: ResidencyScope, observed: ResidencyScope) -> bool {
    match required {
        ResidencyScope::Unspecified => true,
        ResidencyScope::LocalNode => matches!(observed, ResidencyScope::LocalNode),
        ResidencyScope::Datacenter => matches!(
            observed,
            ResidencyScope::LocalNode | ResidencyScope::Datacenter
        ),
        ResidencyScope::Region => matches!(
            observed,
            ResidencyScope::LocalNode | ResidencyScope::Datacenter | ResidencyScope::Region
        ),
        ResidencyScope::Jurisdiction => matches!(
            observed,
            ResidencyScope::LocalNode
                | ResidencyScope::Datacenter
                | ResidencyScope::Region
                | ResidencyScope::Jurisdiction
        ),
        ResidencyScope::GeoReplicaAllowed => !matches!(observed, ResidencyScope::InternetAllowed),
        ResidencyScope::InternetAllowed => true,
    }
}

/// Predicate: is observed sharing no broader than the policy allows?
#[must_use]
pub const fn sharing_domain_satisfies(
    allowed: SharingDomainClass,
    observed: SharingDomainClass,
) -> bool {
    match allowed {
        SharingDomainClass::PrivateDataset => {
            matches!(observed, SharingDomainClass::PrivateDataset)
        }
        SharingDomainClass::SameTenant => matches!(
            observed,
            SharingDomainClass::PrivateDataset | SharingDomainClass::SameTenant
        ),
        SharingDomainClass::CrossTenantAllowed => {
            !matches!(observed, SharingDomainClass::PublicInternet)
        }
        SharingDomainClass::PublicInternet => true,
    }
}

const fn media_capability_identity_flags_required() -> MediaCapabilityFlags {
    MediaCapabilityFlags::STABLE_DEVICE_IDENTITY
        .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
        .union(MediaCapabilityFlags::POOL_MEMBER_BINDING)
        .union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION)
}

const fn media_capability_requires_stable_identity(
    role: StorageMediaRole,
    ack_class: StorageIntentGuaranteeClass,
) -> bool {
    durable_media_required(ack_class)
        || !matches!(
            role,
            StorageMediaRole::ReadCache
                | StorageMediaRole::RamCache
                | StorageMediaRole::ScratchVolatile
                | StorageMediaRole::RepairTemp
                | StorageMediaRole::OptimizerTemp
                | StorageMediaRole::RamVolatileAuthority
        )
}

const fn media_capability_requires_durable_media(
    role: StorageMediaRole,
    ack_class: StorageIntentGuaranteeClass,
) -> bool {
    durable_media_required(ack_class)
        || matches!(
            role,
            StorageMediaRole::SyncIntent
                | StorageMediaRole::MetadataHot
                | StorageMediaRole::ServingDataHot
                | StorageMediaRole::BulkDataCold
                | StorageMediaRole::RamIntentBackedAuthority
                | StorageMediaRole::PlacementAuthority
                | StorageMediaRole::GeoAsyncReplica
                | StorageMediaRole::ArchiveEc
        )
}

const fn media_capability_requires_remote_commit(
    role: StorageMediaRole,
    capability: StorageIntentMediaCapabilityRecord,
    durable_required: bool,
) -> bool {
    durable_required
        && (capability.media_class.is_object_like()
            || matches!(
                capability.persistence,
                MediaPersistenceDomain::RemoteDurable | MediaPersistenceDomain::ObjectDurable
            )
            || matches!(role, StorageMediaRole::GeoAsyncReplica))
}

const fn media_capability_requires_archive_restore(
    role: StorageMediaRole,
    capability: StorageIntentMediaCapabilityRecord,
) -> bool {
    capability.media_class.is_archive()
        || matches!(
            capability.persistence,
            MediaPersistenceDomain::ArchiveDurable
        )
        || matches!(role, StorageMediaRole::ArchiveEc)
}

const fn media_capability_freshness_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
) -> ReceiptPredicateResult {
    if !capability.has_media_capability_evidence()
        || !capability
            .flags
            .contains_all(MediaCapabilityFlags::FRESHNESS)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
        );
    }
    match capability.freshness {
        MediaCapabilityFreshnessState::Fresh => ReceiptPredicateResult::SATISFIED,
        MediaCapabilityFreshnessState::Missing => ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
        ),
        MediaCapabilityFreshnessState::Stale => ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence,
        ),
        MediaCapabilityFreshnessState::Contradictory | MediaCapabilityFreshnessState::Refused => {
            ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable)
        }
    }
}

const fn media_capability_health_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
    durable_required: bool,
) -> ReceiptPredicateResult {
    if !durable_required && !capability.flags.contains_all(MediaCapabilityFlags::HEALTH) {
        return ReceiptPredicateResult::SATISFIED;
    }
    if !capability.flags.contains_all(MediaCapabilityFlags::HEALTH)
        || matches!(capability.health, MediaHealthState::Unknown)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if matches!(
        capability.health,
        MediaHealthState::Degraded | MediaHealthState::Failed | MediaHealthState::Quarantined
    ) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::DegradedMediaHealth);
    }
    ReceiptPredicateResult::SATISFIED
}

const fn media_capability_geometry_satisfies(
    role: StorageMediaRole,
    capability: StorageIntentMediaCapabilityRecord,
    durable_required: bool,
) -> ReceiptPredicateResult {
    if capability.media_class.is_zoned() {
        if !capability
            .flags
            .contains_all(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
            || !matches!(
                capability.geometry,
                MediaProtocolGeometryClass::ZonedSequential
                    | MediaProtocolGeometryClass::ZonedAppend
            )
        {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::UnsupportedZoneWritePointer,
            );
        }
        if matches!(
            role,
            StorageMediaRole::SyncIntent
                | StorageMediaRole::MetadataHot
                | StorageMediaRole::ServingDataHot
                | StorageMediaRole::PlacementAuthority
                | StorageMediaRole::RamIntentBackedAuthority
        ) && !matches!(capability.geometry, MediaProtocolGeometryClass::ZonedAppend)
        {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::UnsupportedZoneWritePointer,
            );
        }
    } else if durable_required
        && !capability
            .flags
            .contains_all(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

const fn media_capability_atomicity_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
    durable_required: bool,
) -> ReceiptPredicateResult {
    if !durable_required {
        return ReceiptPredicateResult::SATISFIED;
    }
    if !capability
        .flags
        .contains_all(MediaCapabilityFlags::ATOMICITY_GRANULARITY)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::WrongAtomicityGranularity,
        );
    }
    if capability.media_class.is_object_like() || capability.media_class.is_archive() {
        if !capability.atomicity.supports_object_or_archive() {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::WrongAtomicityGranularity,
            );
        }
        return ReceiptPredicateResult::SATISFIED;
    }
    if !capability.atomicity.supports_block_durable()
        || capability.logical_block_bytes == 0
        || capability.physical_block_bytes == 0
        || capability.atomic_write_unit_bytes == 0
        || capability.physical_block_bytes % capability.logical_block_bytes != 0
        || capability.atomic_write_unit_bytes % capability.logical_block_bytes != 0
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::WrongAtomicityGranularity,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

const fn media_capability_flush_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
    durable_required: bool,
) -> ReceiptPredicateResult {
    if !durable_required {
        return ReceiptPredicateResult::SATISFIED;
    }
    if matches!(
        capability.persistence,
        MediaPersistenceDomain::PersistentMemory
    ) || matches!(capability.media_class, StorageMediaClass::PersistentMemory)
    {
        if !capability
            .flags
            .contains_all(MediaCapabilityFlags::PMEM_FLUSH_FENCE)
            || !capability.flush_ordering.supports_pmem_flush_fence()
        {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::PmemFlushFenceMissing,
            );
        }
        return ReceiptPredicateResult::SATISFIED;
    }
    if capability.media_class.is_object_like()
        || capability.media_class.is_archive()
        || matches!(
            capability.persistence,
            MediaPersistenceDomain::RemoteDurable
                | MediaPersistenceDomain::ObjectDurable
                | MediaPersistenceDomain::ArchiveDurable
        )
    {
        return ReceiptPredicateResult::SATISFIED;
    }
    if !capability
        .flags
        .contains_all(MediaCapabilityFlags::FLUSH_FUA_ORDERING)
        || !capability.flush_ordering.supports_block_durable()
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnsupportedFlushFuaSemantics,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

const fn media_capability_remote_commit_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
) -> ReceiptPredicateResult {
    if matches!(
        capability.remote_commit,
        MediaRemoteCommitSemantics::RdmaRequiredOnly
    ) {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::RdmaRequiredForCorrectness,
        );
    }
    if !capability
        .flags
        .contains_all(MediaCapabilityFlags::REMOTE_COMMIT)
        || !capability.remote_commit.supports_durable_commit()
        || !(capability.flush_ordering.supports_remote_or_object_commit()
            || capability.flush_ordering.supports_archive_commit())
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnsupportedRemoteCommitSemantics,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

const fn media_capability_archive_restore_satisfies(
    capability: StorageIntentMediaCapabilityRecord,
) -> ReceiptPredicateResult {
    if !capability
        .flags
        .contains_all(MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION)
        || !capability.archive_restore.supports_retained_restore()
        || !capability.flush_ordering.supports_archive_commit()
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can capability evidence legally support a media role.
#[must_use]
pub const fn media_capability_satisfies_role(
    requirement: MediaRoleRequirement,
    ack_class: StorageIntentGuaranteeClass,
    role: StorageMediaRole,
    capability: StorageIntentMediaCapabilityRecord,
) -> ReceiptPredicateResult {
    let role_result =
        media_role_satisfies_receipt(requirement, ack_class, role, capability.media_class);
    if !role_result.satisfied {
        return role_result;
    }

    let freshness = media_capability_freshness_satisfies(capability);
    if !freshness.satisfied {
        return freshness;
    }

    let durable_required = media_capability_requires_durable_media(role, ack_class);
    let health = media_capability_health_satisfies(capability, durable_required);
    if !health.satisfied {
        return health;
    }

    if media_capability_requires_stable_identity(role, ack_class)
        && !capability
            .flags
            .contains_all(media_capability_identity_flags_required())
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnstableNamespaceIdentity,
        );
    }

    if !capability
        .flags
        .contains_all(MediaCapabilityFlags::PERSISTENCE_DOMAIN)
        || matches!(capability.persistence, MediaPersistenceDomain::Unknown)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::UnknownPersistenceDomain,
        );
    }

    if durable_required {
        if matches!(
            capability.persistence,
            MediaPersistenceDomain::CacheOnlyVolatile
        ) {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::UnsafeVolatileWriteCache,
            );
        }
        if !capability
            .persistence
            .can_be_durable_authority(capability.flags)
        {
            return ReceiptPredicateResult::refused(
                StorageIntentRefusalReason::PersistentMediaRequired,
            );
        }
    }

    let geometry = media_capability_geometry_satisfies(role, capability, durable_required);
    if !geometry.satisfied {
        return geometry;
    }
    let atomicity = media_capability_atomicity_satisfies(capability, durable_required);
    if !atomicity.satisfied {
        return atomicity;
    }
    let flush = media_capability_flush_satisfies(capability, durable_required);
    if !flush.satisfied {
        return flush;
    }
    if media_capability_requires_remote_commit(role, capability, durable_required) {
        let remote_commit = media_capability_remote_commit_satisfies(capability);
        if !remote_commit.satisfied {
            return remote_commit;
        }
    }
    if media_capability_requires_archive_restore(role, capability) {
        let archive_restore = media_capability_archive_restore_satisfies(capability);
        if !archive_restore.satisfied {
            return archive_restore;
        }
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a media role/class legally support this receipt?
#[must_use]
pub const fn media_role_satisfies_receipt(
    requirement: MediaRoleRequirement,
    ack_class: StorageIntentGuaranteeClass,
    role: StorageMediaRole,
    media_class: StorageMediaClass,
) -> ReceiptPredicateResult {
    if !requirement.allowed_roles.is_empty() && !requirement.allowed_roles.contains_role(role) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MediaRoleNotAllowed);
    }
    if requirement.require_authority_role && role.is_cache_only() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::CacheCannotBeAuthority);
    }
    if requirement.require_authority_role && role.is_temporary() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::TemporaryMediaCannotBeAuthority,
        );
    }
    if matches!(role, StorageMediaRole::RamVolatileAuthority)
        && GuaranteeCapabilities::provided_by(ack_class).satisfies(
            GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::LocalIntent),
        )
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent,
        );
    }
    if durable_media_required(ack_class)
        && !media_class.is_persistent()
        && !matches!(role, StorageMediaRole::RamIntentBackedAuthority)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::PersistentMediaRequired,
        );
    }
    ReceiptPredicateResult::SATISFIED
}

const fn durable_media_required(ack_class: StorageIntentGuaranteeClass) -> bool {
    GuaranteeCapabilities::provided_by(ack_class).satisfies(GuaranteeCapabilities::required_by(
        StorageIntentGuaranteeClass::LocalIntent,
    )) || GuaranteeCapabilities::provided_by(ack_class).satisfies(
        GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::FullPlacement),
    ) || GuaranteeCapabilities::provided_by(ack_class).satisfies(
        GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::ArchiveEc),
    )
}

/// Evaluate one receipt candidate against one compiled policy.
#[must_use]
pub const fn evaluate_receipt_against_policy(
    policy: StorageIntentPolicy,
    receipt: StorageIntentReceipt,
) -> ReceiptPredicateResult {
    if !ack_receipt_satisfies_requested_floor(policy.requested_guarantee, receipt.ack_class) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::GuaranteeFloorNotMet);
    }
    if !failure_domains_satisfied(policy.required_failure_domains, receipt.failure_domains) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::FailureDomainNotMet);
    }
    if !proximity_satisfies_max(policy.max_proximity, receipt.proximity) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ProximityTooFar);
    }
    if !durability_satisfies(policy.durability, receipt.durability) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::DurabilityOrRpoNotMet);
    }
    let trust = trust_security_satisfies(policy.trust, receipt.trust);
    if !trust.satisfied {
        return trust;
    }
    media_role_satisfies_receipt(
        policy.media,
        receipt.ack_class,
        receipt.media_role,
        receipt.media_class,
    )
}

/// Predicate result for a receipt set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ReceiptSetPredicateResult {
    /// Whether at least one receipt in the set satisfies the policy.
    pub satisfied: bool,
    /// Number of satisfying receipts in the candidate set.
    pub satisfying_receipts: usize,
    /// First refusal observed while scanning candidates.
    pub first_refusal: StorageIntentRefusalReason,
    /// Typed refusal to surface when the set is not legal.
    pub refusal: StorageIntentRefusal,
}

/// Evaluate a bounded candidate set against one compiled policy.
#[must_use]
pub fn evaluate_receipt_set_against_policy(
    policy: StorageIntentPolicy,
    receipts: &[StorageIntentReceipt],
) -> ReceiptSetPredicateResult {
    let mut satisfying_receipts = 0_usize;
    let mut first_refusal = StorageIntentRefusalReason::None;

    for receipt in receipts {
        let result = evaluate_receipt_against_policy(policy, *receipt);
        if result.satisfied {
            satisfying_receipts += 1;
        } else if first_refusal == StorageIntentRefusalReason::None {
            first_refusal = result.refusal;
        }
    }

    if satisfying_receipts > 0 {
        ReceiptSetPredicateResult {
            satisfied: true,
            satisfying_receipts,
            first_refusal,
            refusal: refusal_for_no_legal_receipt_set(policy, StorageIntentRefusalReason::None),
        }
    } else {
        let reason = if first_refusal == StorageIntentRefusalReason::None {
            StorageIntentRefusalReason::NoLegalReceiptSet
        } else {
            first_refusal
        };
        ReceiptSetPredicateResult {
            satisfied: false,
            satisfying_receipts: 0,
            first_refusal: reason,
            refusal: refusal_for_no_legal_receipt_set(policy, reason),
        }
    }
}

// ── Temporal evidence types (issue #903) ── //

/// Timebase identity for storage-intent temporal evidence.
///
/// Distinguishes local monotonic, local wall-clock, cluster consensus,
/// remote wall-clock, and sequence/log-frontier timebases so consumers
/// know whether age, lag, expiry, and deadline facts are comparable
/// and fresh enough for the requested role.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentTimebaseClass {
    /// No timebase evidence available.
    #[default]
    Unknown = 0,
    /// Local monotonic clock (e.g. CLOCK_MONOTONIC).
    LocalMonotonic = 1,
    /// Local wall clock (e.g. CLOCK_REALTIME).
    LocalWallClock = 2,
    /// Cluster or consensus time agreed across members.
    ClusterConsensusTime = 3,
    /// Remote peer-reported wall clock.
    RemoteWallClock = 4,
    /// Sequence or log frontier (LSN, raft index, etc.).
    SequenceLogFrontier = 5,
    /// Sequence-only evidence without time conversion.
    SequenceOnly = 6,
}

impl_u8_canonical!(StorageIntentTimebaseClass, {
    Unknown = 0 => "unknown",
    LocalMonotonic = 1 => "local-monotonic",
    LocalWallClock = 2 => "local-wall-clock",
    ClusterConsensusTime = 3 => "cluster-consensus-time",
    RemoteWallClock = 4 => "remote-wall-clock",
    SequenceLogFrontier = 5 => "sequence-log-frontier",
    SequenceOnly = 6 => "sequence-only",
});

/// Returns true when the timebase can support wall-clock age, lag, or expiry comparisons.
#[must_use]
pub const fn timebase_supports_wall_clock(timebase: StorageIntentTimebaseClass) -> bool {
    matches!(
        timebase,
        StorageIntentTimebaseClass::LocalWallClock
            | StorageIntentTimebaseClass::ClusterConsensusTime
            | StorageIntentTimebaseClass::RemoteWallClock
    )
}

/// Returns true when the timebase can only provide sequence or monotonic ordering.
#[must_use]
pub const fn timebase_is_sequence_only(timebase: StorageIntentTimebaseClass) -> bool {
    matches!(
        timebase,
        StorageIntentTimebaseClass::SequenceLogFrontier | StorageIntentTimebaseClass::SequenceOnly
    )
}

/// Clock source identity for temporal evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentClockSourceClass {
    /// Clock source is unknown.
    #[default]
    Unknown = 0,
    /// Local CMOS / RTC hardware clock.
    LocalCmos = 1,
    /// Local TSC or platform timer.
    LocalTsc = 2,
    /// NTP-synchronized clock.
    NtpSynchronized = 3,
    /// PTP / IEEE 1588 synchronized clock.
    PtpSynchronized = 4,
    /// Derived from cluster consensus protocol.
    ClusterConsensusDerived = 5,
    /// Reported by a remote peer.
    RemotePeerReported = 6,
    /// Derived from sequence or log frontier rate.
    SequenceDerived = 7,
}

impl_u8_canonical!(StorageIntentClockSourceClass, {
    Unknown = 0 => "unknown",
    LocalCmos = 1 => "local-cmos",
    LocalTsc = 2 => "local-tsc",
    NtpSynchronized = 3 => "ntp-synchronized",
    PtpSynchronized = 4 => "ptp-synchronized",
    ClusterConsensusDerived = 5 => "cluster-consensus-derived",
    RemotePeerReported = 6 => "remote-peer-reported",
    SequenceDerived = 7 => "sequence-derived",
});

/// Bitmask of clock health properties.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct ClockHealthFlags(pub u8);

impl ClockHealthFlags {
    /// No health properties asserted.
    pub const EMPTY: Self = Self(0);

    /// Clock is known to be monotonic (no backwards steps observed).
    pub const MONOTONIC: u8 = 1 << 0;

    /// Skew bound is known and current.
    pub const KNOWN_SKEW: u8 = 1 << 1;

    /// No backwards clock step has been observed since the last health sample.
    pub const NO_BACKWARDS_STEP: u8 = 1 << 2;

    /// No leap second is pending or in progress.
    pub const NO_LEAP_SECOND_PENDING: u8 = 1 << 3;

    /// Clock has not been stepped (only slewed) since last health sample.
    pub const NO_STEP_ADJUSTMENT: u8 = 1 << 4;

    /// All defined health flags.
    pub const ALL_DEFINED: u8 = Self::MONOTONIC
        | Self::KNOWN_SKEW
        | Self::NO_BACKWARDS_STEP
        | Self::NO_LEAP_SECOND_PENDING
        | Self::NO_STEP_ADJUSTMENT;

    /// Construct a mask with a single flag.
    #[must_use]
    pub const fn from_flag(flag: u8) -> Self {
        Self(flag)
    }

    /// Combine with another flag set.
    #[must_use]
    pub const fn with(self, flag: u8) -> Self {
        Self(self.0 | flag)
    }

    /// Returns true when all bits in `required` are set.
    #[must_use]
    pub const fn contains_all(self, required: u8) -> bool {
        (self.0 & required) == required
    }

    /// Returns true when any bit in `mask` is set.
    #[must_use]
    pub const fn intersects(self, mask: u8) -> bool {
        (self.0 & mask) != 0
    }
}

/// Clock health evidence carried by temporal evidence records.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentClockHealth {
    /// Clock source identity.
    pub source: StorageIntentClockSourceClass,
    /// Synchronization domain (zero when unknown or local-only).
    pub sync_domain: StorageIntentDomainId,
    /// Conservative skew bound in microseconds (0 = unknown skew).
    pub skew_bound_us: u64,
    /// Health flags.
    pub flags: ClockHealthFlags,
    /// Age of the clock-health sample in milliseconds.
    pub sample_age_ms: u64,
    /// Evidence ref for the clock-health sample artifact.
    pub sample_ref: StorageIntentEvidenceRef,
    /// Evidence ref for the clock-health authority source.
    pub health_ref: StorageIntentEvidenceRef,
}

impl StorageIntentClockHealth {
    /// Returns true when clock health cites a non-empty artifact.
    #[must_use]
    pub const fn has_evidence(self) -> bool {
        self.sample_ref.is_bound() || self.health_ref.is_bound()
    }

    /// Returns true when skew is bounded and the bound is known.
    #[must_use]
    pub const fn has_known_skew(self) -> bool {
        self.skew_bound_us > 0 && self.flags.contains_all(ClockHealthFlags::KNOWN_SKEW)
    }

    /// Returns true when the clock has not stepped backwards.
    #[must_use]
    pub const fn no_backwards_step(self) -> bool {
        self.flags.contains_all(ClockHealthFlags::NO_BACKWARDS_STEP)
    }
}

/// Event frontier class for temporal evidence.
///
/// Binds a specific event type to a comparable time or sequence frontier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentEventFrontierClass {
    /// No event frontier bound.
    #[default]
    Unknown = 0,
    /// Write receipt publication frontier.
    WriteReceipt = 1,
    /// Committed root frontier.
    CommittedRoot = 2,
    /// Policy publication frontier.
    PolicyPublication = 3,
    /// Membership epoch frontier.
    MembershipEpoch = 4,
    /// Trust or key epoch frontier.
    TrustKeyEpoch = 5,
    /// Receive source frontier.
    ReceiveSource = 6,
    /// Geo source frontier.
    GeoSource = 7,
    /// Remote apply frontier.
    RemoteApply = 8,
    /// Read source frontier.
    ReadSource = 9,
    /// Prediction decision frontier.
    PredictionDecision = 10,
    /// Relocation outcome frontier.
    RelocationOutcome = 11,
}

impl_u8_canonical!(StorageIntentEventFrontierClass, {
    Unknown = 0 => "unknown",
    WriteReceipt = 1 => "write-receipt",
    CommittedRoot = 2 => "committed-root",
    PolicyPublication = 3 => "policy-publication",
    MembershipEpoch = 4 => "membership-epoch",
    TrustKeyEpoch = 5 => "trust-key-epoch",
    ReceiveSource = 6 => "receive-source",
    GeoSource = 7 => "geo-source",
    RemoteApply = 8 => "remote-apply",
    ReadSource = 9 => "read-source",
    PredictionDecision = 10 => "prediction-decision",
    RelocationOutcome = 11 => "relocation-outcome",
});

/// Lag or staleness class for temporal evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentStalenessClass {
    /// No staleness class assigned.
    #[default]
    Unknown = 0,
    /// Geo replica RPO lag.
    GeoRpoLag = 1,
    /// Stale-read age.
    StaleReadAge = 2,
    /// Read-serving freshness.
    ReadServingFreshness = 3,
    /// Archive or restore age.
    ArchiveRestoreAge = 4,
    /// Repair or rebuild lag.
    RepairRebuildLag = 5,
    /// Receive backlog age.
    ReceiveBacklogAge = 6,
    /// Remote catch-up age.
    RemoteCatchUpAge = 7,
}

impl_u8_canonical!(StorageIntentStalenessClass, {
    Unknown = 0 => "unknown",
    GeoRpoLag = 1 => "geo-rpo-lag",
    StaleReadAge = 2 => "stale-read-age",
    ReadServingFreshness = 3 => "read-serving-freshness",
    ArchiveRestoreAge = 4 => "archive-restore-age",
    RepairRebuildLag = 5 => "repair-rebuild-lag",
    ReceiveBacklogAge = 6 => "receive-backlog-age",
    RemoteCatchUpAge = 7 => "remote-catch-up-age",
});

/// Expiry or deadline class for temporal evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentExpiryDeadlineClass {
    /// No expiry or deadline class assigned.
    #[default]
    Unknown = 0,
    /// Key lease expiry.
    KeyLeaseExpiry = 1,
    /// Authorization window deadline.
    AuthorizationWindow = 2,
    /// Policy rollout stage deadline.
    PolicyRolloutStageDeadline = 3,
    /// In-flight fence deadline.
    InFlightFenceDeadline = 4,
    /// Cooldown window.
    CooldownWindow = 5,
    /// Payback window.
    PaybackWindow = 6,
    /// TTL or lifecycle window.
    TtlLifecycleWindow = 7,
    /// Retry window.
    RetryWindow = 8,
    /// Refusal deadline.
    RefusalDeadline = 9,
}

impl_u8_canonical!(StorageIntentExpiryDeadlineClass, {
    Unknown = 0 => "unknown",
    KeyLeaseExpiry = 1 => "key-lease-expiry",
    AuthorizationWindow = 2 => "authorization-window",
    PolicyRolloutStageDeadline = 3 => "policy-rollout-stage-deadline",
    InFlightFenceDeadline = 4 => "in-flight-fence-deadline",
    CooldownWindow = 5 => "cooldown-window",
    PaybackWindow = 6 => "payback-window",
    TtlLifecycleWindow = 7 => "ttl-lifecycle-window",
    RetryWindow = 8 => "retry-window",
    RefusalDeadline = 9 => "refusal-deadline",
});

/// Sequence-to-time conversion evidence.
///
/// Converts sequence/log/byte lag to wall-time only when the source rate,
/// observation window, and uncertainty bound make the conversion conservative.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSequenceTimeConversion {
    /// Conservative source rate in bytes per second.
    pub rate_bytes_per_sec: u64,
    /// Observation window over which the rate was measured in milliseconds.
    pub observation_window_ms: u64,
    /// Uncertainty bound for the conversion in milliseconds.
    pub uncertainty_bound_ms: u64,
    /// Conservative wall-clock bound derived from the conversion.
    pub conservative_bound_ms: u64,
    /// Evidence ref for the conversion artifact.
    pub conversion_ref: StorageIntentEvidenceRef,
}

impl StorageIntentSequenceTimeConversion {
    /// Returns true when the conversion cites a non-empty artifact.
    #[must_use]
    pub const fn has_evidence(self) -> bool {
        self.conversion_ref.is_bound()
    }

    /// Returns true when rate and uncertainty are explicit enough for conversion.
    #[must_use]
    pub const fn has_conservative_rate(self) -> bool {
        self.rate_bytes_per_sec > 0
            && self.observation_window_ms > 0
            && self.conservative_bound_ms > 0
    }
}

/// Temporal refusal reason at the evidence level.
///
/// These are typed refusal states that temporal evidence producers record
/// when timebase, clock-health, or frontier evidence is not usable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentTemporalRefusalReason {
    /// No refusal.
    #[default]
    None = 0,
    /// Timebase evidence is missing.
    MissingTimebase = 1,
    /// Clock skew is unknown; wall-time claims cannot be proved.
    UnknownSkew = 2,
    /// Clock-health sample is stale.
    StaleSample = 3,
    /// Expiry or deadline has been crossed.
    CrossedExpiry = 4,
    /// Frontiers from different timebases are contradictory.
    ContradictoryFrontier = 5,
    /// Clock has stepped backwards.
    BackwardsTime = 6,
    /// Sequence frontier is insufficient for the requested conversion.
    InsufficientSequenceFrontier = 7,
    /// Cross-domain time comparison is not supported.
    UnsupportedCrossDomainComparison = 8,
}

impl_u8_canonical!(StorageIntentTemporalRefusalReason, {
    None = 0 => "none",
    MissingTimebase = 1 => "missing-timebase",
    UnknownSkew = 2 => "unknown-skew",
    StaleSample = 3 => "stale-sample",
    CrossedExpiry = 4 => "crossed-expiry",
    ContradictoryFrontier = 5 => "contradictory-frontier",
    BackwardsTime = 6 => "backwards-time",
    InsufficientSequenceFrontier = 7 => "insufficient-sequence-frontier",
    UnsupportedCrossDomainComparison = 8 => "unsupported-cross-domain-comparison",
});

/// Storage-intent temporal evidence record.
///
/// Carries timebase identity, clock health, event/frontier stamps,
/// lag/staleness, expiry/deadline, sequence-to-time conversion, and
/// typed refusal evidence so that consumers can make honest claims
/// about age, lag, staleness, RPO/RTO, TTL, cooldown, payback,
/// policy-stage deadlines, and evidence freshness.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentTemporalEvidence {
    /// Self-referential evidence identity.
    pub evidence: StorageIntentEvidenceRef,
    /// Timebase identity.
    pub timebase: StorageIntentTimebaseClass,
    /// Evidence ref for the timebase artifact.
    pub timebase_ref: StorageIntentEvidenceRef,
    /// Clock health record.
    pub clock_health: StorageIntentClockHealth,
    /// Evidence ref for the clock-health artifact.
    pub clock_health_ref: StorageIntentEvidenceRef,
    /// Event frontier class.
    pub event_frontier: StorageIntentEventFrontierClass,
    /// Evidence ref for the event-frontier artifact.
    pub event_frontier_ref: StorageIntentEvidenceRef,
    /// Lag or staleness class.
    pub staleness_class: StorageIntentStalenessClass,
    /// Evidence ref for the lag/staleness artifact.
    pub staleness_ref: StorageIntentEvidenceRef,
    /// Expiry or deadline class.
    pub expiry_deadline_class: StorageIntentExpiryDeadlineClass,
    /// Evidence ref for the expiry/deadline artifact.
    pub expiry_deadline_ref: StorageIntentEvidenceRef,
    /// Sequence-to-time conversion evidence.
    pub sequence_time_conversion: StorageIntentSequenceTimeConversion,
    /// Temporal refusal reason at the evidence level.
    pub refusal: StorageIntentTemporalRefusalReason,
    /// Evidence ref for the refusal artifact.
    pub refusal_ref: StorageIntentEvidenceRef,
}

impl StorageIntentTemporalEvidence {
    /// Returns true when the record cites a non-empty temporal-evidence artifact.
    #[must_use]
    pub const fn has_temporal_evidence(self) -> bool {
        self.evidence.kind as u16 == StorageIntentEvidenceKind::TemporalEvidence as u16
            && !bytes32_are_zero(self.evidence.id.0)
    }

    /// Returns true when the timebase is explicit.
    #[must_use]
    pub const fn has_timebase(self) -> bool {
        self.timebase as u8 != StorageIntentTimebaseClass::Unknown as u8
            && self.timebase_ref.is_bound()
    }

    /// Returns true when clock health evidence is present.
    #[must_use]
    pub const fn has_clock_health(self) -> bool {
        self.clock_health.has_evidence() && self.clock_health_ref.is_bound()
    }

    /// Returns true when an event frontier is bound.
    #[must_use]
    pub const fn has_event_frontier(self) -> bool {
        self.event_frontier as u8 != StorageIntentEventFrontierClass::Unknown as u8
            && self.event_frontier_ref.is_bound()
    }

    /// Returns true when lag/staleness evidence is present.
    #[must_use]
    pub const fn has_lag_staleness(self) -> bool {
        self.staleness_class as u8 != StorageIntentStalenessClass::Unknown as u8
            && self.staleness_ref.is_bound()
    }

    /// Returns true when expiry/deadline evidence is present.
    #[must_use]
    pub const fn has_expiry_deadline(self) -> bool {
        self.expiry_deadline_class as u8 != StorageIntentExpiryDeadlineClass::Unknown as u8
            && self.expiry_deadline_ref.is_bound()
    }

    /// Returns true when sequence-to-time conversion evidence is present.
    #[must_use]
    pub const fn has_sequence_conversion(self) -> bool {
        self.sequence_time_conversion.has_evidence()
    }

    /// Returns true when the evidence has an active refusal.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        self.refusal as u8 != StorageIntentTemporalRefusalReason::None as u8
    }
}

// ── Temporal evidence predicates ── //

/// Returns true when the clock health sample is fresh enough for authority decisions.
///
/// A stale clock-health sample cannot support freshness, RPO, or expiry claims.
#[must_use]
pub const fn clock_health_is_fresh_for_authority(
    health: StorageIntentClockHealth,
    max_sample_age_ms: u64,
) -> bool {
    health.has_evidence() && health.sample_age_ms <= max_sample_age_ms
}

/// Returns true when wall-clock temporal evidence can prove the requested RPO bound.
///
/// Requires: wall-clock timebase, known clock skew, no backwards steps,
/// fresh clock-health sample, remote-apply frontier evidence, and the
/// observed lag does not exceed the RPO bound.
#[must_use]
pub const fn temporal_evidence_supports_wall_clock_rpo(
    evidence: StorageIntentTemporalEvidence,
    required_rpo_ms: u64,
    observed_lag_ms: u64,
    max_sample_age_ms: u64,
) -> bool {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return false;
    }
    if !timebase_supports_wall_clock(evidence.timebase) {
        return false;
    }
    if !clock_health_is_fresh_for_authority(evidence.clock_health, max_sample_age_ms) {
        return false;
    }
    if !evidence.clock_health.has_known_skew() {
        return false;
    }
    if !evidence.clock_health.no_backwards_step() {
        return false;
    }
    if evidence.event_frontier as u8 != StorageIntentEventFrontierClass::RemoteApply as u8 {
        return false;
    }
    // Observed lag plus skew bound must not exceed required RPO.
    // When skew is known, add it to the conservative bound.
    let conservative_lag_ms =
        observed_lag_ms.saturating_add(evidence.clock_health.skew_bound_us / 1000);
    conservative_lag_ms <= required_rpo_ms
}

/// Returns true when temporal evidence can support a wall-clock freshness claim.
///
/// Requires: wall-clock timebase, known skew, no backwards steps,
/// fresh clock-health sample, and a bound staleness ref.
#[must_use]
pub const fn temporal_evidence_supports_freshness_claim(
    evidence: StorageIntentTemporalEvidence,
    max_age_ms: u64,
    max_sample_age_ms: u64,
) -> bool {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return false;
    }
    if !timebase_supports_wall_clock(evidence.timebase) {
        return false;
    }
    if !clock_health_is_fresh_for_authority(evidence.clock_health, max_sample_age_ms) {
        return false;
    }
    if !evidence.clock_health.has_known_skew() {
        return false;
    }
    if !evidence.clock_health.no_backwards_step() {
        return false;
    }
    if !evidence.has_lag_staleness() {
        return false;
    }
    // Freshness claim is valid when the evidence staleness ref is bound
    // and the max age is within acceptable bounds.
    max_age_ms > 0
}

/// Returns true when temporal evidence can support an expiry or deadline claim.
///
/// Requires: explicit expiry/deadline class, wall-clock timebase,
/// known skew, no backwards steps, and fresh clock-health sample.
#[must_use]
pub const fn temporal_evidence_supports_expiry_claim(
    evidence: StorageIntentTemporalEvidence,
    deadline_ms: u64,
    now_ms: u64,
    max_sample_age_ms: u64,
) -> bool {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return false;
    }
    if !timebase_supports_wall_clock(evidence.timebase) {
        return false;
    }
    if !clock_health_is_fresh_for_authority(evidence.clock_health, max_sample_age_ms) {
        return false;
    }
    if !evidence.clock_health.has_known_skew() {
        return false;
    }
    if !evidence.clock_health.no_backwards_step() {
        return false;
    }
    if !evidence.has_expiry_deadline() {
        return false;
    }
    // Deadline has not passed, accounting for skew.
    let conservative_now = now_ms.saturating_add(evidence.clock_health.skew_bound_us / 1000);
    conservative_now < deadline_ms
}

/// Returns true when temporal evidence can support a cooldown or payback window claim.
///
/// Cooldown/payback windows can use local monotonic time when no cross-node
/// comparison is required, but wall-clock claims need wall-clock timebase.
#[must_use]
pub const fn temporal_evidence_supports_cooldown_claim(
    evidence: StorageIntentTemporalEvidence,
    window_ms: u64,
    elapsed_ms: u64,
    requires_cross_node: bool,
) -> bool {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return false;
    }
    if requires_cross_node && !timebase_supports_wall_clock(evidence.timebase) {
        return false;
    }
    if !evidence.has_expiry_deadline() {
        return false;
    }
    // Cooldown satisfied when elapsed time exceeds the window.
    elapsed_ms >= window_ms
}

/// Map a temporal evidence refusal reason to the policy-level refusal reason.
#[must_use]
pub const fn temporal_refusal_to_policy_refusal(
    reason: StorageIntentTemporalRefusalReason,
) -> StorageIntentRefusalReason {
    match reason {
        StorageIntentTemporalRefusalReason::None => StorageIntentRefusalReason::None,
        StorageIntentTemporalRefusalReason::MissingTimebase => {
            StorageIntentRefusalReason::MissingTemporalEvidence
        }
        StorageIntentTemporalRefusalReason::UnknownSkew => {
            StorageIntentRefusalReason::UnknownClockSkew
        }
        StorageIntentTemporalRefusalReason::StaleSample => {
            StorageIntentRefusalReason::StaleClockHealthSample
        }
        StorageIntentTemporalRefusalReason::CrossedExpiry => {
            StorageIntentRefusalReason::ExpiredTemporalLease
        }
        StorageIntentTemporalRefusalReason::ContradictoryFrontier => {
            StorageIntentRefusalReason::EvidenceNotUsable
        }
        StorageIntentTemporalRefusalReason::BackwardsTime => {
            StorageIntentRefusalReason::BackwardsClockStep
        }
        StorageIntentTemporalRefusalReason::InsufficientSequenceFrontier => {
            StorageIntentRefusalReason::SequenceOnlyCannotSatisfyWallClockRpo
        }
        StorageIntentTemporalRefusalReason::UnsupportedCrossDomainComparison => {
            StorageIntentRefusalReason::EvidenceNotUsable
        }
    }
}

/// Returns true when temporal evidence can satisfy a TTL/lifecycle window claim.
///
/// TTL claims need wall-clock timebase with known skew; sequence-only evidence
/// is not sufficient to prove an absolute time window has elapsed.
#[must_use]
pub const fn temporal_evidence_supports_ttl_claim(
    evidence: StorageIntentTemporalEvidence,
    ttl_ms: u64,
    age_ms: u64,
    max_sample_age_ms: u64,
) -> bool {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return false;
    }
    if !timebase_supports_wall_clock(evidence.timebase) {
        return false;
    }
    if !clock_health_is_fresh_for_authority(evidence.clock_health, max_sample_age_ms) {
        return false;
    }
    if !evidence.clock_health.has_known_skew() {
        return false;
    }
    if !evidence.clock_health.no_backwards_step() {
        return false;
    }
    age_ms >= ttl_ms
}

/// Returns the temporal evidence age in milliseconds, or None if not computable.
///
/// Evidence age is computable only when a wall-clock timebase with known skew
/// and no backwards step is available.
#[must_use]
pub const fn temporal_evidence_age_ms(
    evidence: StorageIntentTemporalEvidence,
    now_ms: u64,
    event_timestamp_ms: u64,
) -> Option<u64> {
    if !evidence.has_temporal_evidence() || evidence.is_refused() {
        return None;
    }
    if !timebase_supports_wall_clock(evidence.timebase) {
        return None;
    }
    if !evidence.clock_health.has_known_skew() || !evidence.clock_health.no_backwards_step() {
        return None;
    }
    if now_ms < event_timestamp_ms {
        return None;
    }
    Some(now_ms - event_timestamp_ms)
}

/// Storage-intent capacity role being admitted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentCapacityAdmissionRole {
    #[default]
    Unknown = 0,
    LocalIntent = 1,
    QuorumIntent = 2,
    FullPlacement = 3,
    GeoCatchUp = 4,
    ArchiveEc = 5,
    ReadRepair = 6,
    Relocation = 7,
    Rebake = 8,
    AuthorityPromotion = 9,
    RamIntentBacking = 10,
    BlockFlushFua = 11,
    FallocateReservation = 12,
    ReceiptRetirement = 13,
    BackgroundOptimizer = 14,
}

impl_u8_canonical!(StorageIntentCapacityAdmissionRole, {
    Unknown = 0 => "unknown",
    LocalIntent = 1 => "local-intent",
    QuorumIntent = 2 => "quorum-intent",
    FullPlacement = 3 => "full-placement",
    GeoCatchUp = 4 => "geo-catch-up",
    ArchiveEc = 5 => "archive-ec",
    ReadRepair = 6 => "read-repair",
    Relocation = 7 => "relocation",
    Rebake = 8 => "rebake",
    AuthorityPromotion = 9 => "authority-promotion",
    RamIntentBacking = 10 => "ram-intent-backing",
    BlockFlushFua = 11 => "block-flush-fua",
    FallocateReservation = 12 => "fallocate-reservation",
    ReceiptRetirement = 13 => "receipt-retirement",
    BackgroundOptimizer = 14 => "background-optimizer",
});

impl StorageIntentCapacityAdmissionRole {
    /// Returns true when the role is background optimizer work.
    #[must_use]
    pub const fn is_background_optimizer(self) -> bool {
        matches!(
            self,
            Self::Relocation | Self::Rebake | Self::BackgroundOptimizer
        )
    }
}

/// Lifecycle state of one admission or reserve escrow.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentCapacityAdmissionState {
    #[default]
    Unknown = 0,
    Admitted = 1,
    DegradedVisible = 2,
    Blocked = 3,
    Refused = 4,
    Expired = 5,
    Released = 6,
    Aborted = 7,
    Committed = 8,
}

impl_u8_canonical!(StorageIntentCapacityAdmissionState, {
    Unknown = 0 => "unknown",
    Admitted = 1 => "admitted",
    DegradedVisible = 2 => "degraded-visible",
    Blocked = 3 => "blocked",
    Refused = 4 => "refused",
    Expired = 5 => "expired",
    Released = 6 => "released",
    Aborted = 7 => "aborted",
    Committed = 8 => "committed",
});

impl StorageIntentCapacityAdmissionState {
    /// Returns true when the admission can still satisfy capacity authority.
    #[must_use]
    pub const fn is_active_for_authority(self) -> bool {
        matches!(self, Self::Admitted | Self::Committed)
    }
}

/// Pressure state reported by reserve and claim ledgers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentReservePressureState {
    #[default]
    Unknown = 0,
    Normal = 1,
    Elevated = 2,
    Critical = 3,
    Overcommitted = 4,
    ProtectedFloorWouldBeBreached = 5,
}

impl_u8_canonical!(StorageIntentReservePressureState, {
    Unknown = 0 => "unknown",
    Normal = 1 => "normal",
    Elevated = 2 => "elevated",
    Critical = 3 => "critical",
    Overcommitted = 4 => "overcommitted",
    ProtectedFloorWouldBeBreached = 5 => "protected-floor-would-be-breached",
});

/// Protected reserve floors that capacity admission may not trespass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentProtectedReserveMask(pub u32);

impl StorageIntentProtectedReserveMask {
    pub const EMPTY: Self = Self(0);
    pub const SYNC: Self = Self(1_u32 << 0);
    pub const REPAIR: Self = Self(1_u32 << 1);
    pub const EVACUATION: Self = Self(1_u32 << 2);
    pub const RECEIPT_RETIREMENT: Self = Self(1_u32 << 3);

    /// Add protected floors.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when no protected floor is named.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Capacity/admission facts proven by a record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCapacityAdmissionFlags(pub u64);

impl StorageIntentCapacityAdmissionFlags {
    pub const EMPTY: Self = Self(0);
    pub const LOGICAL_HEADROOM_PROVED: Self = Self(1_u64 << 0);
    pub const QUOTA_HEADROOM_PROVED: Self = Self(1_u64 << 1);
    pub const PHYSICAL_HEADROOM_PROVED: Self = Self(1_u64 << 2);
    pub const ALLOCATION_CLASS_HEADROOM_PROVED: Self = Self(1_u64 << 3);
    pub const SEGMENT_CLASS_HEADROOM_PROVED: Self = Self(1_u64 << 4);
    pub const ALLOCATION_TICKET_FRESH: Self = Self(1_u64 << 5);
    pub const CLAIM_LEDGER_FRESH: Self = Self(1_u64 << 6);
    pub const RESERVE_LEDGER_FRESH: Self = Self(1_u64 << 7);
    pub const RESERVE_RECEIPT_FRESH: Self = Self(1_u64 << 8);
    pub const RESERVE_ESCROW_ACTIVE: Self = Self(1_u64 << 9);
    pub const DIRTY_WINDOW_RESERVED: Self = Self(1_u64 << 10);
    pub const WRITEBACK_BUDGET_RESERVED: Self = Self(1_u64 << 11);
    pub const SYNC_INTENT_RESERVED: Self = Self(1_u64 << 12);
    pub const REPAIR_RESERVE_AVAILABLE: Self = Self(1_u64 << 13);
    pub const EVACUATION_RESERVE_AVAILABLE: Self = Self(1_u64 << 14);
    pub const REBUILD_RESERVE_AVAILABLE: Self = Self(1_u64 << 15);
    pub const GEO_CATCHUP_RESERVE_AVAILABLE: Self = Self(1_u64 << 16);
    pub const RELOCATION_RESERVE_AVAILABLE: Self = Self(1_u64 << 17);
    pub const PENDING_FREE_PUBLISHED: Self = Self(1_u64 << 18);
    pub const PENDING_FREE_FENCED: Self = Self(1_u64 << 19);
    pub const PENDING_FREE_SNAPSHOT_SAFE: Self = Self(1_u64 << 20);
    pub const PENDING_FREE_GENERATION_SAFE: Self = Self(1_u64 << 21);
    pub const RECEIPT_RETIREMENT_SAFE: Self = Self(1_u64 << 22);
    pub const RECLAIM_DEBT_ACCOUNTED: Self = Self(1_u64 << 23);
    pub const AMPLIFICATION_ESTIMATE_PROVED: Self = Self(1_u64 << 24);
    pub const SLOP_FLOOR_PRESERVED: Self = Self(1_u64 << 25);
    pub const PROTECTED_FLOORS_PRESERVED: Self = Self(1_u64 << 26);
    pub const EVIDENCE_FRESH: Self = Self(1_u64 << 27);
    pub const QUERY_SNAPSHOT_FRESH: Self = Self(1_u64 << 28);
    pub const TENANT_BUDGET_PROVED: Self = Self(1_u64 << 29);
    pub const TEMPORAL_DEADLINES_VALID: Self = Self(1_u64 << 30);
    pub const POLICY_ROLLOUT_SAFE: Self = Self(1_u64 << 31);
    pub const AUTHORITY_PROMOTION_SAFE: Self = Self(1_u64 << 32);
    pub const EXPLICIT_OPTIMIZER_OVERRIDE: Self = Self(1_u64 << 33);

    /// Combine capacity facts.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when every required fact is present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Evidence references consumed by capacity/admission predicates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCapacityAdmissionRefs {
    pub dataset_ref: StorageIntentEvidenceRef,
    pub space_domain_ref: StorageIntentEvidenceRef,
    pub quota_ref: StorageIntentEvidenceRef,
    pub logical_headroom_ref: StorageIntentEvidenceRef,
    pub physical_headroom_ref: StorageIntentEvidenceRef,
    pub allocation_class_ref: StorageIntentEvidenceRef,
    pub segment_class_ref: StorageIntentEvidenceRef,
    pub allocation_ticket_ref: StorageIntentEvidenceRef,
    pub claim_ledger_ref: StorageIntentEvidenceRef,
    pub reserve_ledger_ref: StorageIntentEvidenceRef,
    pub reserve_receipt_ref: StorageIntentEvidenceRef,
    pub dirty_window_ref: StorageIntentEvidenceRef,
    pub writeback_budget_ref: StorageIntentEvidenceRef,
    pub sync_intent_reserve_ref: StorageIntentEvidenceRef,
    pub repair_reserve_ref: StorageIntentEvidenceRef,
    pub evacuation_reserve_ref: StorageIntentEvidenceRef,
    pub rebuild_reserve_ref: StorageIntentEvidenceRef,
    pub geo_catchup_reserve_ref: StorageIntentEvidenceRef,
    pub relocation_scratch_ref: StorageIntentEvidenceRef,
    pub pending_free_frontier_ref: StorageIntentEvidenceRef,
    pub reclaim_debt_ref: StorageIntentEvidenceRef,
    pub amplification_estimate_ref: StorageIntentEvidenceRef,
    pub capacity_authority_ref: StorageIntentEvidenceRef,
    pub policy_rollout_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub temporal_ref: StorageIntentEvidenceRef,
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
}

impl StorageIntentCapacityAdmissionRefs {
    /// Returns true when core dataset, quota, logical, physical, and cut refs exist.
    #[must_use]
    pub const fn has_core_refs(self) -> bool {
        self.dataset_ref.is_bound()
            && self.space_domain_ref.is_bound()
            && self.quota_ref.is_bound()
            && self.logical_headroom_ref.is_bound()
            && self.physical_headroom_ref.is_bound()
            && self.amplification_estimate_ref.is_bound()
            && self.capacity_authority_ref.is_bound()
            && self.policy_rollout_ref.is_bound()
            && self.tenant_isolation_ref.is_bound()
            && self.temporal_ref.is_bound()
            && self.evidence_query_snapshot_ref.is_bound()
    }
}

/// Capacity amplification estimate for one admission decision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCapacityAmplificationEstimate {
    pub logical_bytes: u64,
    pub replica_count: u16,
    pub ec_data_shards: u16,
    pub ec_parity_shards: u16,
    pub cow_old_plus_new_bytes: u64,
    pub snapshot_pinned_bytes: u64,
    pub clone_pinned_bytes: u64,
    pub receive_base_pinned_bytes: u64,
    pub compression_expansion_bytes: u64,
    pub rebake_overlap_bytes: u64,
    pub receipt_overlap_bytes: u64,
    pub projected_required_bytes: u64,
    pub estimate_ref: StorageIntentEvidenceRef,
}

impl StorageIntentCapacityAmplificationEstimate {
    /// Returns the minimum byte floor implied by every explicit amplification term.
    #[must_use]
    pub const fn component_floor_bytes(self) -> u64 {
        let replicated = if self.replica_count > 1 {
            saturating_mul_u64(self.logical_bytes, self.replica_count as u64)
        } else {
            self.logical_bytes
        };
        let ec_total_shards = self.ec_data_shards as u64 + self.ec_parity_shards as u64;
        let ec_floor = if self.ec_data_shards > 0 && self.ec_parity_shards > 0 {
            div_ceil_u64(
                saturating_mul_u64(self.logical_bytes, ec_total_shards),
                self.ec_data_shards as u64,
            )
        } else {
            replicated
        };
        let mut total = max_u64(replicated, ec_floor);
        total = saturating_add_u64(total, self.cow_old_plus_new_bytes);
        total = saturating_add_u64(total, self.snapshot_pinned_bytes);
        total = saturating_add_u64(total, self.clone_pinned_bytes);
        total = saturating_add_u64(total, self.receive_base_pinned_bytes);
        total = saturating_add_u64(total, self.compression_expansion_bytes);
        total = saturating_add_u64(total, self.rebake_overlap_bytes);
        saturating_add_u64(total, self.receipt_overlap_bytes)
    }

    /// Returns true when the projection cites evidence and covers every term.
    #[must_use]
    pub const fn proves_required_overlap(self) -> bool {
        self.estimate_ref.is_bound()
            && self.projected_required_bytes >= self.component_floor_bytes()
            && self.projected_required_bytes > 0
    }
}

/// Capacity/admission evidence projected into storage-intent authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCapacityAdmissionEvidence {
    pub evidence_ref: StorageIntentEvidenceRef,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub dataset_id: StorageIntentDomainId,
    pub space_domain_id: StorageIntentDomainId,
    pub quota_domain_id: StorageIntentDomainId,
    pub budget_owner_id: StorageIntentDomainId,
    pub state: StorageIntentCapacityAdmissionState,
    pub reserve_pressure: StorageIntentReservePressureState,
    pub protected_floor_breaches: StorageIntentProtectedReserveMask,
    pub flags: StorageIntentCapacityAdmissionFlags,
    pub refs: StorageIntentCapacityAdmissionRefs,
    pub amplification: StorageIntentCapacityAmplificationEstimate,
    pub logical_required_bytes: u64,
    pub logical_available_bytes: u64,
    pub quota_available_bytes: u64,
    pub physical_required_bytes: u64,
    pub physical_available_bytes: u64,
    pub dirty_window_required_bytes: u64,
    pub dirty_window_available_bytes: u64,
    pub writeback_required_bytes: u64,
    pub writeback_available_bytes: u64,
    pub sync_intent_required_bytes: u64,
    pub sync_intent_available_bytes: u64,
    pub recovery_required_bytes: u64,
    pub repair_scratch_available_bytes: u64,
    pub evacuation_scratch_available_bytes: u64,
    pub rebuild_scratch_available_bytes: u64,
    pub geo_catchup_required_bytes: u64,
    pub geo_catchup_available_bytes: u64,
    pub relocation_scratch_required_bytes: u64,
    pub relocation_scratch_available_bytes: u64,
    pub pending_free_counted_bytes: u64,
    pub reclaimable_counted_bytes: u64,
    pub reclaim_debt_bytes: u64,
    pub slop_floor_required_bytes: u64,
    pub protected_floor_required_bytes: u64,
    pub protected_floor_available_bytes: u64,
    pub evidence_observed_at_ms: u64,
    pub evidence_valid_until_ms: u64,
    pub allocation_ticket_expires_at_ms: u64,
    pub reserve_escrow_expires_at_ms: u64,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for StorageIntentCapacityAdmissionEvidence {
    fn default() -> Self {
        Self {
            evidence_ref: StorageIntentEvidenceRef::default(),
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            scope: StorageIntentObjectScope::default(),
            dataset_id: StorageIntentDomainId::ZERO,
            space_domain_id: StorageIntentDomainId::ZERO,
            quota_domain_id: StorageIntentDomainId::ZERO,
            budget_owner_id: StorageIntentDomainId::ZERO,
            state: StorageIntentCapacityAdmissionState::Unknown,
            reserve_pressure: StorageIntentReservePressureState::Unknown,
            protected_floor_breaches: StorageIntentProtectedReserveMask::EMPTY,
            flags: StorageIntentCapacityAdmissionFlags::EMPTY,
            refs: StorageIntentCapacityAdmissionRefs::default(),
            amplification: StorageIntentCapacityAmplificationEstimate::default(),
            logical_required_bytes: 0,
            logical_available_bytes: 0,
            quota_available_bytes: 0,
            physical_required_bytes: 0,
            physical_available_bytes: 0,
            dirty_window_required_bytes: 0,
            dirty_window_available_bytes: 0,
            writeback_required_bytes: 0,
            writeback_available_bytes: 0,
            sync_intent_required_bytes: 0,
            sync_intent_available_bytes: 0,
            recovery_required_bytes: 0,
            repair_scratch_available_bytes: 0,
            evacuation_scratch_available_bytes: 0,
            rebuild_scratch_available_bytes: 0,
            geo_catchup_required_bytes: 0,
            geo_catchup_available_bytes: 0,
            relocation_scratch_required_bytes: 0,
            relocation_scratch_available_bytes: 0,
            pending_free_counted_bytes: 0,
            reclaimable_counted_bytes: 0,
            reclaim_debt_bytes: 0,
            slop_floor_required_bytes: 0,
            protected_floor_required_bytes: 0,
            protected_floor_available_bytes: 0,
            evidence_observed_at_ms: 0,
            evidence_valid_until_ms: 0,
            allocation_ticket_expires_at_ms: 0,
            reserve_escrow_expires_at_ms: 0,
            refusal: StorageIntentRefusalReason::None,
        }
    }
}

impl StorageIntentCapacityAdmissionEvidence {
    /// Returns true when the record is a bound capacity/admission artifact.
    #[must_use]
    pub const fn has_capacity_identity(self) -> bool {
        self.evidence_ref.is_bound()
            && self.evidence_ref.kind as u16
                == StorageIntentEvidenceKind::CapacityAdmissionEvidence as u16
    }

    /// Returns true when the evidence timestamp is usable for authority.
    #[must_use]
    pub const fn is_fresh_for_authority(self, now_ms: u64, max_age_ms: u64) -> bool {
        if self.evidence_observed_at_ms == 0 || now_ms < self.evidence_observed_at_ms {
            return false;
        }
        if self.evidence_valid_until_ms == 0 || now_ms > self.evidence_valid_until_ms {
            return false;
        }
        if max_age_ms > 0 && now_ms - self.evidence_observed_at_ms > max_age_ms {
            return false;
        }
        self.flags
            .contains_all(StorageIntentCapacityAdmissionFlags::EVIDENCE_FRESH)
    }

    /// Returns true when a counted pending-free byte contribution is safe.
    #[must_use]
    pub const fn pending_free_is_admissible(self) -> bool {
        self.pending_free_counted_bytes == 0
            || (self.refs.pending_free_frontier_ref.is_bound()
                && self
                    .flags
                    .contains_all(capacity_pending_free_safety_flags()))
    }

    /// Returns true when counted reclaimable bytes are fenced by retirement law.
    #[must_use]
    pub const fn reclaim_debt_is_admissible(self) -> bool {
        self.reclaimable_counted_bytes == 0
            || (self.refs.reclaim_debt_ref.is_bound()
                && self.flags.contains_all(
                    StorageIntentCapacityAdmissionFlags::RECLAIM_DEBT_ACCOUNTED
                        .union(StorageIntentCapacityAdmissionFlags::RECEIPT_RETIREMENT_SAFE),
                ))
    }
}

/// Capacity/admission requirement for one storage-intent role.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentCapacityAdmissionRequirement {
    pub role: StorageIntentCapacityAdmissionRole,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub scope: StorageIntentObjectScope,
    pub min_logical_bytes: u64,
    pub min_physical_bytes: u64,
    pub max_evidence_age_ms: u64,
    pub now_ms: u64,
}

/// Predicate: can capacity/admission evidence satisfy the requested role?
#[must_use]
pub const fn capacity_evidence_satisfies_role(
    requirement: StorageIntentCapacityAdmissionRequirement,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> ReceiptPredicateResult {
    if !evidence.has_capacity_identity() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::MissingCapacityAdmissionEvidence,
        );
    }
    if evidence.refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return ReceiptPredicateResult::refused(evidence.refusal);
    }
    if !evidence.refs.has_core_refs() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !capacity_requirement_scope_matches(requirement, evidence) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.state.is_active_for_authority() {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CapacityAdmissionNotActive,
        );
    }
    if !evidence.is_fresh_for_authority(requirement.now_ms, requirement.max_evidence_age_ms) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleCapacityEvidence);
    }
    if !evidence
        .flags
        .contains_all(capacity_role_required_flags(requirement.role))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !capacity_allocation_ticket_is_usable(requirement, evidence) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleAllocationTicket);
    }
    if !capacity_reserve_escrow_is_usable(requirement, evidence) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ExpiredReserveEscrow);
    }
    if !evidence.pending_free_is_admissible() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::PendingFreeNotSafe);
    }
    if !evidence.reclaim_debt_is_admissible() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::ReclaimDebtNotSafe);
    }
    let protected_refusal = capacity_protected_floor_refusal(requirement.role, evidence);
    if protected_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return ReceiptPredicateResult::refused(protected_refusal);
    }
    if !evidence.amplification.proves_required_overlap()
        || evidence.amplification.component_floor_bytes()
            < max_u64(
                requirement.min_physical_bytes,
                evidence.physical_required_bytes,
            )
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CapacityAmplificationUnderestimated,
        );
    }
    let logical_required = max_u64(
        requirement.min_logical_bytes,
        evidence.logical_required_bytes,
    );
    if evidence.logical_available_bytes < logical_required {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CapacityHeadroomExhausted,
        );
    }
    let quota_required = saturating_add_u64(logical_required, evidence.slop_floor_required_bytes);
    if evidence.quota_available_bytes < quota_required
        || !evidence
            .flags
            .contains_all(StorageIntentCapacityAdmissionFlags::SLOP_FLOOR_PRESERVED)
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::QuotaOrSlopFloorExceeded,
        );
    }
    let physical_required = max_u64(
        max_u64(
            requirement.min_physical_bytes,
            evidence.physical_required_bytes,
        ),
        evidence.amplification.projected_required_bytes,
    );
    if evidence.physical_available_bytes < physical_required {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::PhysicalHeadroomExhausted,
        );
    }
    if evidence.dirty_window_available_bytes < evidence.dirty_window_required_bytes
        || evidence.writeback_available_bytes < evidence.writeback_required_bytes
        || evidence.sync_intent_available_bytes < evidence.sync_intent_required_bytes
    {
        return ReceiptPredicateResult::refused(
            StorageIntentRefusalReason::CapacityHeadroomExhausted,
        );
    }
    let scratch_refusal = capacity_role_scratch_refusal(requirement.role, evidence);
    if scratch_refusal as u16 != StorageIntentRefusalReason::None as u16 {
        return ReceiptPredicateResult::refused(scratch_refusal);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: are pending-free publication/fence/snapshot/generation frontiers safe?
#[must_use]
pub const fn capacity_pending_free_is_safe(
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> bool {
    evidence.pending_free_is_admissible()
}

const fn capacity_pending_free_safety_flags() -> StorageIntentCapacityAdmissionFlags {
    StorageIntentCapacityAdmissionFlags::PENDING_FREE_PUBLISHED
        .union(StorageIntentCapacityAdmissionFlags::PENDING_FREE_FENCED)
        .union(StorageIntentCapacityAdmissionFlags::PENDING_FREE_SNAPSHOT_SAFE)
        .union(StorageIntentCapacityAdmissionFlags::PENDING_FREE_GENERATION_SAFE)
        .union(StorageIntentCapacityAdmissionFlags::RECEIPT_RETIREMENT_SAFE)
}

const fn capacity_base_required_flags() -> StorageIntentCapacityAdmissionFlags {
    StorageIntentCapacityAdmissionFlags::LOGICAL_HEADROOM_PROVED
        .union(StorageIntentCapacityAdmissionFlags::QUOTA_HEADROOM_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::PHYSICAL_HEADROOM_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::ALLOCATION_CLASS_HEADROOM_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::SEGMENT_CLASS_HEADROOM_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::ALLOCATION_TICKET_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::CLAIM_LEDGER_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::RESERVE_LEDGER_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::RESERVE_RECEIPT_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::RESERVE_ESCROW_ACTIVE)
        .union(StorageIntentCapacityAdmissionFlags::AMPLIFICATION_ESTIMATE_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::SLOP_FLOOR_PRESERVED)
        .union(StorageIntentCapacityAdmissionFlags::PROTECTED_FLOORS_PRESERVED)
        .union(StorageIntentCapacityAdmissionFlags::EVIDENCE_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::QUERY_SNAPSHOT_FRESH)
        .union(StorageIntentCapacityAdmissionFlags::TENANT_BUDGET_PROVED)
        .union(StorageIntentCapacityAdmissionFlags::TEMPORAL_DEADLINES_VALID)
        .union(StorageIntentCapacityAdmissionFlags::POLICY_ROLLOUT_SAFE)
}

const fn capacity_role_required_flags(
    role: StorageIntentCapacityAdmissionRole,
) -> StorageIntentCapacityAdmissionFlags {
    let base = capacity_base_required_flags();
    match role {
        StorageIntentCapacityAdmissionRole::Unknown => StorageIntentCapacityAdmissionFlags::EMPTY,
        StorageIntentCapacityAdmissionRole::LocalIntent
        | StorageIntentCapacityAdmissionRole::QuorumIntent
        | StorageIntentCapacityAdmissionRole::BlockFlushFua => base
            .union(StorageIntentCapacityAdmissionFlags::DIRTY_WINDOW_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::WRITEBACK_BUDGET_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::SYNC_INTENT_RESERVED),
        StorageIntentCapacityAdmissionRole::FullPlacement
        | StorageIntentCapacityAdmissionRole::ArchiveEc
        | StorageIntentCapacityAdmissionRole::FallocateReservation => base,
        StorageIntentCapacityAdmissionRole::GeoCatchUp => {
            base.union(StorageIntentCapacityAdmissionFlags::GEO_CATCHUP_RESERVE_AVAILABLE)
        }
        StorageIntentCapacityAdmissionRole::ReadRepair => base
            .union(StorageIntentCapacityAdmissionFlags::REPAIR_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::REBUILD_RESERVE_AVAILABLE),
        StorageIntentCapacityAdmissionRole::Relocation => {
            base.union(StorageIntentCapacityAdmissionFlags::RELOCATION_RESERVE_AVAILABLE)
        }
        StorageIntentCapacityAdmissionRole::Rebake
        | StorageIntentCapacityAdmissionRole::BackgroundOptimizer => base,
        StorageIntentCapacityAdmissionRole::AuthorityPromotion => {
            base.union(StorageIntentCapacityAdmissionFlags::AUTHORITY_PROMOTION_SAFE)
        }
        StorageIntentCapacityAdmissionRole::RamIntentBacking => base
            .union(StorageIntentCapacityAdmissionFlags::DIRTY_WINDOW_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::WRITEBACK_BUDGET_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::SYNC_INTENT_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::TENANT_BUDGET_PROVED),
        StorageIntentCapacityAdmissionRole::ReceiptRetirement => {
            base.union(StorageIntentCapacityAdmissionFlags::RECEIPT_RETIREMENT_SAFE)
        }
    }
}

const fn capacity_requirement_scope_matches(
    requirement: StorageIntentCapacityAdmissionRequirement,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> bool {
    if !requirement.policy_id.is_zero()
        && !bytes16_equal(requirement.policy_id.0, evidence.policy_id.0)
    {
        return false;
    }
    if requirement.policy_revision.0 > 0
        && requirement.policy_revision.0 != evidence.policy_revision.0
    {
        return false;
    }
    if !requirement.scope.dataset_id.is_zero()
        && !bytes16_equal(requirement.scope.dataset_id.0, evidence.dataset_id.0)
    {
        return false;
    }
    if !bytes32_are_zero(requirement.scope.object_id.0)
        && !bytes32_equal(requirement.scope.object_id.0, evidence.scope.object_id.0)
    {
        return false;
    }
    true
}

const fn capacity_allocation_ticket_is_usable(
    requirement: StorageIntentCapacityAdmissionRequirement,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> bool {
    if !capacity_role_required_flags(requirement.role)
        .contains_all(StorageIntentCapacityAdmissionFlags::ALLOCATION_TICKET_FRESH)
    {
        return true;
    }
    evidence.refs.allocation_ticket_ref.is_bound()
        && evidence.allocation_ticket_expires_at_ms > 0
        && requirement.now_ms <= evidence.allocation_ticket_expires_at_ms
}

const fn capacity_reserve_escrow_is_usable(
    requirement: StorageIntentCapacityAdmissionRequirement,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> bool {
    if !capacity_role_required_flags(requirement.role)
        .contains_all(StorageIntentCapacityAdmissionFlags::RESERVE_ESCROW_ACTIVE)
    {
        return true;
    }
    evidence.refs.reserve_receipt_ref.is_bound()
        && evidence.reserve_escrow_expires_at_ms > 0
        && requirement.now_ms <= evidence.reserve_escrow_expires_at_ms
}

const fn capacity_protected_floor_refusal(
    role: StorageIntentCapacityAdmissionRole,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> StorageIntentRefusalReason {
    if matches!(
        evidence.reserve_pressure,
        StorageIntentReservePressureState::Overcommitted
    ) {
        return StorageIntentRefusalReason::ReserveOvercommitted;
    }
    if evidence.protected_floor_available_bytes < evidence.protected_floor_required_bytes {
        return StorageIntentRefusalReason::ProtectedReserveWouldBeBreached;
    }
    if matches!(
        evidence.reserve_pressure,
        StorageIntentReservePressureState::ProtectedFloorWouldBeBreached
    ) || !evidence.protected_floor_breaches.is_empty()
    {
        if role.is_background_optimizer()
            && !evidence
                .flags
                .contains_all(StorageIntentCapacityAdmissionFlags::EXPLICIT_OPTIMIZER_OVERRIDE)
        {
            return StorageIntentRefusalReason::OptimizerProtectedReserveBorrow;
        }
        return StorageIntentRefusalReason::ProtectedReserveWouldBeBreached;
    }
    StorageIntentRefusalReason::None
}

const fn capacity_role_scratch_refusal(
    role: StorageIntentCapacityAdmissionRole,
    evidence: StorageIntentCapacityAdmissionEvidence,
) -> StorageIntentRefusalReason {
    match role {
        StorageIntentCapacityAdmissionRole::ReadRepair => {
            if evidence.repair_scratch_available_bytes < evidence.recovery_required_bytes
                || evidence.rebuild_scratch_available_bytes < evidence.recovery_required_bytes
            {
                StorageIntentRefusalReason::RecoveryReserveExhausted
            } else {
                StorageIntentRefusalReason::None
            }
        }
        StorageIntentCapacityAdmissionRole::GeoCatchUp => {
            if evidence.geo_catchup_available_bytes < evidence.geo_catchup_required_bytes {
                StorageIntentRefusalReason::GeoCatchUpReserveExceeded
            } else {
                StorageIntentRefusalReason::None
            }
        }
        StorageIntentCapacityAdmissionRole::Relocation => {
            if evidence.relocation_scratch_available_bytes
                < evidence.relocation_scratch_required_bytes
            {
                StorageIntentRefusalReason::RelocationScratchReserveExhausted
            } else {
                StorageIntentRefusalReason::None
            }
        }
        StorageIntentCapacityAdmissionRole::ReceiptRetirement => {
            if evidence.evacuation_scratch_available_bytes < evidence.recovery_required_bytes {
                StorageIntentRefusalReason::RecoveryReserveExhausted
            } else {
                StorageIntentRefusalReason::None
            }
        }
        _ => StorageIntentRefusalReason::None,
    }
}

const fn max_u64(left: u64, right: u64) -> u64 {
    if left >= right {
        left
    } else {
        right
    }
}

const fn saturating_add_u64(left: u64, right: u64) -> u64 {
    if u64::MAX - left < right {
        u64::MAX
    } else {
        left + right
    }
}

const fn saturating_mul_u64(left: u64, right: u64) -> u64 {
    if right != 0 && left > u64::MAX / right {
        u64::MAX
    } else {
        left * right
    }
}

const fn div_ceil_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        let quotient = numerator / denominator;
        if numerator % denominator == 0 {
            quotient
        } else {
            saturating_add_u64(quotient, 1)
        }
    }
}

// ===== Policy Rollout Evidence (Issue #901) =====

/// Classification of a policy revision change.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentPolicyChangeClass {
    /// No change class assigned.
    #[default]
    Unknown = 0,
    /// Strengthens durability, RPO, trust, recovery, capacity, or visibility floors.
    Strengthen = 1,
    /// Weakens durability, RPO, trust, recovery, capacity, or visibility floors.
    Weaken = 2,
    /// Lateral change: different shape, same floor level.
    Lateral = 3,
    /// The old and new policy languages are not compatible.
    Incompatible = 4,
    /// Privileged emergency override that bypasses normal stage gates.
    EmergencyOverride = 5,
    /// Restoring a previous or superseding revision.
    Rollback = 6,
    /// Re-entering a previously rolled-back or superseded revision.
    ReEntry = 7,
    /// The old revision is being fully retired.
    Retirement = 8,
}

impl StorageIntentPolicyChangeClass {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Strengthen => "strengthen",
            Self::Weaken => "weaken",
            Self::Lateral => "lateral",
            Self::Incompatible => "incompatible",
            Self::EmergencyOverride => "emergency-override",
            Self::Rollback => "rollback",
            Self::ReEntry => "re-entry",
            Self::Retirement => "retirement",
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
            0 => Some(Self::Unknown),
            1 => Some(Self::Strengthen),
            2 => Some(Self::Weaken),
            3 => Some(Self::Lateral),
            4 => Some(Self::Incompatible),
            5 => Some(Self::EmergencyOverride),
            6 => Some(Self::Rollback),
            7 => Some(Self::ReEntry),
            8 => Some(Self::Retirement),
            _ => None,
        }
    }

    /// Returns true when the change class weakens any policy floor.
    #[must_use]
    pub const fn is_weakening(self) -> bool {
        matches!(
            self,
            Self::Weaken | Self::Incompatible | Self::EmergencyOverride
        )
    }

    /// Returns true when the change class requires downgrade authorization.
    #[must_use]
    pub const fn requires_downgrade_authorization(self) -> bool {
        matches!(
            self,
            Self::Weaken | Self::Incompatible | Self::EmergencyOverride
        )
    }
}

impl fmt::Display for StorageIntentPolicyChangeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Policy rollout stage state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentPolicyStageState {
    /// No stage recorded.
    #[default]
    Unknown = 0,
    /// Source policy exists but is not a storage-intent language for admission.
    Draft = 1,
    /// Compiler/planner can explain effects, but no receipt may cite this revision.
    DryRun = 2,
    /// Capacity, trust, membership, recovery, validation, and runbook refs permit staging.
    PreflightAdmitted = 3,
    /// Published for a bounded scope or cohort with in-flight fence and rollback anchor.
    Staged = 4,
    /// New operations in scope cite the new revision; old receipts keep historical revision.
    ActiveForNewWrites = 5,
    /// Existing ranges/generations owe replacement receipts or convergence.
    ConvergingExisting = 6,
    /// Missing prerequisites; revision is not yet active but not rolled back.
    Blocked = 7,
    /// Stage cannot safely continue; must fence new work or re-enter restored revision.
    RollbackRequired = 8,
    /// Future admission uses restored revision; rollback receipts and obligations visible.
    RolledBack = 9,
    /// A later revision replaced this one; new work cannot cite it except for cleanup/re-entry.
    Superseded = 10,
    /// No live receipt, convergence, rollback, or explanation dependency remains.
    Retired = 11,
    /// The change cannot become active for the selected scope.
    Refused = 12,
}

impl StorageIntentPolicyStageState {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Draft => "draft",
            Self::DryRun => "dry-run",
            Self::PreflightAdmitted => "preflight-admitted",
            Self::Staged => "staged",
            Self::ActiveForNewWrites => "active-for-new-writes",
            Self::ConvergingExisting => "converging-existing",
            Self::Blocked => "blocked",
            Self::RollbackRequired => "rollback-required",
            Self::RolledBack => "rolled-back",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
            Self::Refused => "refused",
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
            0 => Some(Self::Unknown),
            1 => Some(Self::Draft),
            2 => Some(Self::DryRun),
            3 => Some(Self::PreflightAdmitted),
            4 => Some(Self::Staged),
            5 => Some(Self::ActiveForNewWrites),
            6 => Some(Self::ConvergingExisting),
            7 => Some(Self::Blocked),
            8 => Some(Self::RollbackRequired),
            9 => Some(Self::RolledBack),
            10 => Some(Self::Superseded),
            11 => Some(Self::Retired),
            12 => Some(Self::Refused),
            _ => None,
        }
    }

    /// Returns true when the stage represents an active or transitioning state.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::ActiveForNewWrites | Self::ConvergingExisting
        )
    }

    /// Returns true when the stage is a terminal state.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Superseded | Self::Retired | Self::Refused
        )
    }

    /// Returns true when the stage permits new writes.
    #[must_use]
    pub const fn admits_new_writes(self) -> bool {
        matches!(
            self,
            Self::ActiveForNewWrites | Self::ConvergingExisting
        )
    }

    /// Returns true when the rollout is blocked but not yet rolled back.
    #[must_use]
    pub const fn requires_intervention(self) -> bool {
        matches!(
            self,
            Self::Blocked | Self::RollbackRequired
        )
    }
}

impl fmt::Display for StorageIntentPolicyStageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Old-receipt treatment under a new policy revision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentOldReceiptTreatment {
    /// No treatment recorded.
    #[default]
    Unknown = 0,
    /// Old receipts remain valid under the original revision.
    Grandfathered = 1,
    /// Old receipts must be replaced or re-proved before satisfying the new revision.
    RequireConvergence = 2,
    /// Old receipts are valid for their original claim but not for new claims.
    UnusableForNewClaims = 3,
    /// Receipts from the old revision must be refused for any purpose.
    Refuse = 4,
}

impl StorageIntentOldReceiptTreatment {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Grandfathered => "grandfathered",
            Self::RequireConvergence => "require-convergence",
            Self::UnusableForNewClaims => "unusable-for-new-claims",
            Self::Refuse => "refuse",
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
            0 => Some(Self::Unknown),
            1 => Some(Self::Grandfathered),
            2 => Some(Self::RequireConvergence),
            3 => Some(Self::UnusableForNewClaims),
            4 => Some(Self::Refuse),
            _ => None,
        }
    }

    /// Returns true when old receipts remain valid without convergence.
    #[must_use]
    pub const fn preserves_old_receipts(self) -> bool {
        matches!(
            self,
            Self::Grandfathered | Self::UnusableForNewClaims
        )
    }

    /// Returns true when old receipts must be replaced before satisfying the new revision.
    #[must_use]
    pub const fn requires_convergence(self) -> bool {
        matches!(self, Self::RequireConvergence)
    }
}

impl fmt::Display for StorageIntentOldReceiptTreatment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// In-flight operation types that must be fenced during rollout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentInFlightOperationFlags(pub u32);

impl StorageIntentInFlightOperationFlags {
    pub const EMPTY: Self = Self(0);

    pub const WRITES: Self = Self(1 << 0);
    pub const FSYNC_FUA: Self = Self(1 << 1);
    pub const READ_REPAIR: Self = Self(1 << 2);
    pub const REBUILD: Self = Self(1 << 3);
    pub const RELOCATION: Self = Self(1 << 4);
    pub const REBAKE: Self = Self(1 << 5);
    pub const GEO_CATCHUP: Self = Self(1 << 6);
    pub const ARCHIVE_RESTORE: Self = Self(1 << 7);
    pub const RECEIPT_RETIREMENT: Self = Self(1 << 8);

    pub const ALL_NEW_WRITE: Self = Self(
        Self::WRITES.0
            | Self::FSYNC_FUA.0,
    );

    pub const ALL_BACKGROUND: Self = Self(
        Self::READ_REPAIR.0
            | Self::REBUILD.0
            | Self::RELOCATION.0
            | Self::REBAKE.0
            | Self::GEO_CATCHUP.0
            | Self::ARCHIVE_RESTORE.0
            | Self::RECEIPT_RETIREMENT.0,
    );

    pub const ALL: Self = Self(Self::ALL_NEW_WRITE.0 | Self::ALL_BACKGROUND.0);

    /// Returns true when a flag is set.
    #[must_use]
    pub const fn has(self, flags: Self) -> bool {
        (self.0 & flags.0) == flags.0
    }

    /// Set additional flags.
    #[must_use]
    pub const fn with(self, flags: Self) -> Self {
        Self(self.0 | flags.0)
    }

    /// Returns true when new-write operations are fenced.
    #[must_use]
    pub const fn fenced_new_writes(self) -> bool {
        (self.0 & Self::WRITES.0) != 0
            && (self.0 & Self::FSYNC_FUA.0) != 0
    }

    /// Returns true when at least one background operation is fenced.
    #[must_use]
    pub const fn has_any_background_fence(self) -> bool {
        (self.0 & Self::ALL_BACKGROUND.0) != 0
    }
}

/// Typed refusal reason for policy rollout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentRolloutRefusalReason {
    /// No refusal.
    #[default]
    None = 0,
    /// Stale policy source: last-known source generation is newer than compiled.
    StalePolicySource = 1,
    /// Conflicting overrides cannot be merged.
    ConflictingOverrides = 2,
    /// Downgrade authorization is missing.
    MissingDowngradeAuthorization = 3,
    /// Unsafe downgrade detected (durability, RPO, trust, recovery, capacity, or visibility floor).
    UnsafeDowngrade = 4,
    /// In-flight fence operation failed.
    InFlightFenceFailure = 5,
    /// Convergence debt exceeds policy tolerance.
    ConvergenceDebt = 6,
    /// Validation gate failure.
    ValidationGateFailure = 7,
    /// Unsupported combination of policy sources or revision classes.
    UnsupportedCombination = 8,
    /// Missing preflight simulation evidence.
    MissingPreflightEvidence = 9,
    /// Stale preflight simulation evidence.
    StalePreflightEvidence = 10,
    /// Missing evidence query snapshot.
    MissingEvidenceQuerySnapshot = 11,
    /// Missing temporal evidence for stage deadlines.
    MissingTemporalEvidence = 12,
    /// Stage deadline has been crossed.
    StageDeadlineCrossed = 13,
    /// Missing runbook step or operator acknowledgment.
    MissingRunbookStep = 14,
}

impl StorageIntentRolloutRefusalReason {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StalePolicySource => "stale-policy-source",
            Self::ConflictingOverrides => "conflicting-overrides",
            Self::MissingDowngradeAuthorization => "missing-downgrade-authorization",
            Self::UnsafeDowngrade => "unsafe-downgrade",
            Self::InFlightFenceFailure => "in-flight-fence-failure",
            Self::ConvergenceDebt => "convergence-debt",
            Self::ValidationGateFailure => "validation-gate-failure",
            Self::UnsupportedCombination => "unsupported-combination",
            Self::MissingPreflightEvidence => "missing-preflight-evidence",
            Self::StalePreflightEvidence => "stale-preflight-evidence",
            Self::MissingEvidenceQuerySnapshot => "missing-evidence-query-snapshot",
            Self::MissingTemporalEvidence => "missing-temporal-evidence",
            Self::StageDeadlineCrossed => "stage-deadline-crossed",
            Self::MissingRunbookStep => "missing-runbook-step",
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
            0 => Some(Self::None),
            1 => Some(Self::StalePolicySource),
            2 => Some(Self::ConflictingOverrides),
            3 => Some(Self::MissingDowngradeAuthorization),
            4 => Some(Self::UnsafeDowngrade),
            5 => Some(Self::InFlightFenceFailure),
            6 => Some(Self::ConvergenceDebt),
            7 => Some(Self::ValidationGateFailure),
            8 => Some(Self::UnsupportedCombination),
            9 => Some(Self::MissingPreflightEvidence),
            10 => Some(Self::StalePreflightEvidence),
            11 => Some(Self::MissingEvidenceQuerySnapshot),
            12 => Some(Self::MissingTemporalEvidence),
            13 => Some(Self::StageDeadlineCrossed),
            14 => Some(Self::MissingRunbookStep),
            _ => None,
        }
    }

    /// Returns true when a refusal reason is present.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl fmt::Display for StorageIntentRolloutRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Policy rollout, downgrade, rollback, and convergence-frontier evidence.
///
/// This record is the concrete projection for evidence kind
/// `PolicyRolloutEvidence = 14` as prescribed by the
/// `docs/STORAGE_INTENT_POLICY_AUTHORITY.md` field inventory.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPolicyRolloutEvidence {
    /// Self-referencing identity for this evidence artifact.
    pub evidence_ref: StorageIntentEvidenceRef,
    /// Compiled policy identity targeted by this rollout.
    pub compiled_policy_id: StorageIntentPolicyId,
    /// Compiled policy revision targeted by this rollout.
    pub compiled_policy_revision: StorageIntentPolicyRevision,
    /// Previously active revision, if any.
    pub previous_policy_id: StorageIntentPolicyId,
    /// Previously active revision number.
    pub previous_policy_revision: StorageIntentPolicyRevision,
    /// Revision being restored (set during rollback or re-entry).
    pub target_policy_id: StorageIntentPolicyId,
    /// Target revision number for rollback or supersession.
    pub target_policy_revision: StorageIntentPolicyRevision,
    /// Monotonic policy publication epoch.
    pub policy_epoch: u64,
    /// Names the pool, dataset, mount, caller, inherited-default, override,
    /// or internal-maintenance source set from #855.
    pub source_policy_ref: StorageIntentEvidenceRef,
    /// Records which policy sources participated and which conflicts or
    /// inheritance rules were applied.
    pub source_provenance_mask: u32,
    /// Full provenance trace including per-source stamps.
    pub source_provenance_refs: StorageIntentEvidenceRefs,
    /// Proves the compiled revision was durably published.
    pub publication_transaction_ref: StorageIntentEvidenceRef,
    /// Classifies the nature of the change.
    pub change_class: StorageIntentPolicyChangeClass,
    /// Authz/audit evidence required when a change lowers durability, RPO,
    /// trust, recovery, capacity, or visibility floors.
    pub downgrade_authorization_ref: StorageIntentEvidenceRef,
    /// Current stage state.
    pub stage_state: StorageIntentPolicyStageState,
    /// Names the pool, dataset, mount, file, range, generation, cohort,
    /// or internal-maintenance scope affected by the revision.
    pub scope_selector: StorageIntentObjectScope,
    /// Says whether old receipts are grandfathered, require convergence,
    /// are unusable for new claims, or must be refused.
    pub old_receipt_treatment: StorageIntentOldReceiptTreatment,
    /// Which operations continue under old or new revision.
    pub in_flight_fence_flags: StorageIntentInFlightOperationFlags,
    /// Evidence ref for the in-flight fence record.
    pub in_flight_fence_ref: StorageIntentEvidenceRef,
    /// Per-range, per-generation, per-receipt, or per-cohort convergence frontier.
    pub convergence_frontier_ref: StorageIntentEvidenceRef,
    /// Proves stronger placement, shape, trust, recovery, or capacity
    /// requirements were earned before old-revision satisfaction is claimed.
    pub replacement_receipt_set_ref: StorageIntentEvidenceRef,
    /// Remaining convergence, rollback repair, receipt-retirement,
    /// validation, or operator-review work.
    pub outstanding_obligation_ref: StorageIntentEvidenceRef,
    /// Old-revision proof-retention evidence for safe explanation and purge.
    pub old_revision_retention_ref: StorageIntentEvidenceRef,
    /// Evidence that no live receipt, generation, repair, receive-base, or
    /// operator claim still depends on this revision before retirement.
    pub safe_retirement_evidence_ref: StorageIntentEvidenceRef,
    /// Rollback anchor snapshot, dry-run/preflight result, failed-stage reason,
    /// restored revision, rollback receipt, and post-rollback verification.
    pub rollback_reentry_ref: StorageIntentEvidenceRef,
    /// Later revision that replaced this one.
    pub supersession_ref: StorageIntentEvidenceRef,
    /// Typed refusal reason when the rollout cannot proceed.
    pub refusal_reason: StorageIntentRolloutRefusalReason,
    /// Preflight simulation evidence ref for dry-run/preflight-admitted states.
    pub preflight_evidence_ref: StorageIntentEvidenceRef,
    /// Temporal evidence ref for stage deadlines and convergence age.
    pub temporal_evidence_ref: StorageIntentEvidenceRef,
    /// Evidence query snapshot ref for the decision basis.
    pub evidence_query_snapshot_ref: StorageIntentEvidenceRef,
    /// Action-execution evidence ref for rollout cutover, rollback, or
    /// source-retirement work.
    pub action_execution_evidence_ref: StorageIntentEvidenceRef,
    /// Caller-visible result/refusal evidence ref for rollout outcomes.
    pub result_refusal_evidence_ref: StorageIntentEvidenceRef,
    /// Measurement-attribution evidence ref when measured deltas shaped the
    /// rollout, feedback, or validation decision.
    pub measurement_attribution_evidence_ref: StorageIntentEvidenceRef,
    /// Policy-revision-scoped feedback window or predictor state ref.
    pub feedback_window_ref: StorageIntentEvidenceRef,
    /// Tenant isolation evidence ref for budget/tenant-aware rollout.
    pub tenant_isolation_evidence_ref: StorageIntentEvidenceRef,
    /// Capacity admission evidence ref for reserve-aware rollout.
    pub capacity_admission_evidence_ref: StorageIntentEvidenceRef,
    /// Decision frontier evidence ref for the selection basis.
    pub decision_frontier_evidence_ref: StorageIntentEvidenceRef,
    /// Membership evidence ref for epoch/quorum-aware rollout.
    pub membership_evidence_ref: StorageIntentEvidenceRef,
    /// Trust domain evidence ref for security/domain-aware rollout.
    pub trust_domain_evidence_ref: StorageIntentEvidenceRef,
    /// Recovery/degradation evidence ref for repair-aware rollout.
    pub recovery_evidence_ref: StorageIntentEvidenceRef,
    /// Media capability evidence ref for role-aware rollout.
    pub media_capability_evidence_ref: StorageIntentEvidenceRef,
    /// Metadata/namespace evidence ref for namespace-aware rollout.
    pub metadata_namespace_evidence_ref: StorageIntentEvidenceRef,
}

impl StorageIntentPolicyRolloutEvidence {
    /// Returns true when the rollout has a compiled policy identity.
    #[must_use]
    pub const fn has_compiled_policy(self) -> bool {
        matches!(
            self.evidence_ref.kind,
            StorageIntentEvidenceKind::PolicyRolloutEvidence
        )
            && evidence_ref_has_id(self.evidence_ref)
            && !self.compiled_policy_id.is_zero()
            && self.compiled_policy_revision.0 > 0
    }

    /// Returns true when the rollout has a previous revision to compare against.
    #[must_use]
    pub const fn has_previous_revision(self) -> bool {
        !self.previous_policy_id.is_zero()
            && self.previous_policy_revision.0 > 0
    }

    /// Returns true when the rollout has a target revision (rollback or supersession).
    #[must_use]
    pub const fn has_target_revision(self) -> bool {
        !self.target_policy_id.is_zero()
            && self.target_policy_revision.0 > 0
    }

    /// Returns true when the change class is set to a known value.
    #[must_use]
    pub const fn has_change_class(self) -> bool {
        !matches!(self.change_class, StorageIntentPolicyChangeClass::Unknown)
    }

    /// Returns true when the scope selector is bound.
    #[must_use]
    pub const fn has_scope(self) -> bool {
        !self.scope_selector.dataset_id.is_zero()
            || !bytes32_are_zero(self.scope_selector.object_id.0)
            || self.scope_selector.range_len > 0
    }

    /// Returns true when the stage state is known.
    #[must_use]
    pub const fn has_stage_state(self) -> bool {
        !matches!(self.stage_state, StorageIntentPolicyStageState::Unknown)
    }

    /// Returns true when the rollout is refused.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self.stage_state, StorageIntentPolicyStageState::Refused)
            || self.refusal_reason.is_refused()
    }

    /// Returns true when a publication transaction ref is present.
    #[must_use]
    pub const fn has_publication_transaction(self) -> bool {
        evidence_ref_has_id(self.publication_transaction_ref)
    }

    /// Returns true when the change class requires downgrade authorization
    /// and the authorization ref is present.
    #[must_use]
    pub const fn has_downgrade_authorization_if_required(self) -> bool {
        if !self.change_class.requires_downgrade_authorization() {
            return true;
        }
        evidence_ref_has_id(self.downgrade_authorization_ref)
    }

    /// Returns true when the old-receipt treatment is defined.
    #[must_use]
    pub const fn has_old_receipt_treatment(self) -> bool {
        !matches!(
            self.old_receipt_treatment,
            StorageIntentOldReceiptTreatment::Unknown
        )
    }

    /// Returns true when the in-flight fence is defined for the current stage.
    #[must_use]
    pub const fn has_in_flight_fence(self) -> bool {
        evidence_ref_has_id(self.in_flight_fence_ref)
            && self.in_flight_fence_flags.0 != 0
    }

    /// Returns true when retirement is backed by retention and cleanup proof.
    #[must_use]
    pub const fn has_safe_retirement_evidence(self) -> bool {
        evidence_ref_has_id(self.old_revision_retention_ref)
            && evidence_ref_has_id(self.safe_retirement_evidence_ref)
    }
}

// ===== Rollout hard law predicates =====

/// Hard rollout law: publication is not activation.
///
/// A compiled revision can exist for dry-run, comparison, and operator
/// explanation without admitting new writes.
#[must_use]
pub const fn rollout_publication_is_not_activation(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    // A rollout can have a compiled policy without being active.
    evidence.has_compiled_policy()
}

/// Hard rollout law: activation for new writes requires publication transaction,
/// scope selector, stage state, and in-flight fence.
///
/// Missing one of those is `unknown-evidence`, `blocked`, or `refused`.
#[must_use]
pub const fn rollout_activation_requires_publication_scope_stage_fence(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    evidence.has_compiled_policy()
        && evidence.has_publication_transaction()
        && evidence.has_scope()
        && evidence.has_stage_state()
        && evidence.has_in_flight_fence()
        && !evidence.is_refused()
}

/// Hard rollout law: strengthening may gate new operations immediately,
/// but old generations reach stronger satisfaction only after replacement
/// receipts, convergence frontiers, and old-receipt retirement law say so.
#[must_use]
pub const fn rollout_strengthen_new_writes_only(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    if matches!(
        evidence.change_class,
        StorageIntentPolicyChangeClass::Strengthen
    ) {
        // Strengthening: old receipts must be grandfathered or require convergence.
        matches!(
            evidence.old_receipt_treatment,
            StorageIntentOldReceiptTreatment::Grandfathered
                | StorageIntentOldReceiptTreatment::RequireConvergence
        )
    } else {
        true
    }
}

/// Hard rollout law: weakening requires downgrade authorization and audit refs,
/// and it must not turn prior durable, geo, recovery, trust, or capacity
/// promises into weaker product claims.
#[must_use]
pub const fn rollout_weaken_requires_authorization_and_audit(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    if !evidence.change_class.is_weakening() {
        return true;
    }
    evidence.has_downgrade_authorization_if_required()
        && evidence_ref_has_id(evidence.downgrade_authorization_ref)
}

/// Hard rollout law: reads, repair, rebuild, relocation, rebake, geo catch-up,
/// RAM authority, block-volume flush/FUA, and receipt retirement must choose
/// the policy revision by receipt identity and rollout fence, not by a
/// mutable global property lookup.
#[must_use]
pub const fn rollout_operation_chooses_revision_by_receipt_and_fence(
    evidence: StorageIntentPolicyRolloutEvidence,
    receipt_policy_revision: StorageIntentPolicyRevision,
    in_flight_operation: StorageIntentInFlightOperationFlags,
) -> bool {
    if in_flight_operation.0 == 0 {
        return false;
    }
    if evidence.in_flight_fence_flags.has(in_flight_operation) {
        return evidence.has_in_flight_fence();
    }
    // Unfenced operations must carry a concrete historical receipt revision.
    receipt_policy_revision.0 > 0
}

/// Hard rollout law: relocation across a revision boundary must publish
/// target receipts for the target revision before claiming convergence,
/// and it must preserve source receipts until rollback and old-receipt
/// retirement law allow retirement.
#[must_use]
pub const fn rollout_relocation_crosses_revision_boundary(
    evidence: StorageIntentPolicyRolloutEvidence,
    source_receipt_revision: StorageIntentPolicyRevision,
) -> bool {
    // Relocation crosses revision boundary when source receipt revision
    // differs from compiled revision.
    if source_receipt_revision.0 == evidence.compiled_policy_revision.0 {
        return false;
    }
    // Must have replacement receipt set and outstanding obligation refs.
    evidence_ref_has_id(evidence.replacement_receipt_set_ref)
        && evidence_ref_has_id(evidence.outstanding_obligation_ref)
}

/// Hard rollout law: rollback is a receipt-producing operation.
/// It restores future admission to a previous or superseding revision,
/// but it does not erase receipts earned while the failed revision was staged.
#[must_use]
pub const fn rollout_rollback_is_receipt_producing(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::RolledBack
    )
        && evidence.has_target_revision()
        && evidence_ref_has_id(evidence.rollback_reentry_ref)
}

/// Hard rollout law: superseded revisions remain visible until no live
/// receipt, retained generation, receive base, geo backlog, repair
/// obligation, or operator claim still depends on their explanation.
#[must_use]
pub const fn rollout_superseded_remains_visible_until_clean(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::Superseded
    )
        && evidence_ref_has_id(evidence.supersession_ref)
}

// ===== Stage transition predicates =====

/// Stage transition: draft → dry-run.
///
/// A draft can become a dry-run when the compiled policy has an identity
/// and a publication transaction is bound.
#[must_use]
pub const fn rollout_can_transition_draft_to_dry_run(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(evidence.stage_state, StorageIntentPolicyStageState::Draft)
        && evidence.has_compiled_policy()
        && evidence_ref_has_id(evidence.publication_transaction_ref)
}

/// Stage transition: dry-run → preflight-admitted.
///
/// A dry-run can be preflight-admitted when preflight simulation evidence
/// is present and not stale, and the evidence query snapshot is bound.
#[must_use]
pub const fn rollout_can_transition_dry_run_to_preflight_admitted(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(evidence.stage_state, StorageIntentPolicyStageState::DryRun)
        && evidence_ref_has_id(evidence.preflight_evidence_ref)
        && evidence_ref_has_id(evidence.evidence_query_snapshot_ref)
}

/// Stage transition: preflight-admitted → staged.
///
/// Preflight-admitted can be staged when scope is bound, downgrade
/// authorization is present if required, and in-flight fence is recorded.
#[must_use]
pub const fn rollout_can_transition_preflight_admitted_to_staged(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::PreflightAdmitted
    )
        && evidence.has_scope()
        && evidence.has_downgrade_authorization_if_required()
        && evidence.has_in_flight_fence()
}

/// Stage transition: staged → active-for-new-writes.
///
/// Staged becomes active when publication transaction is bound, scope
/// is set, old-receipt treatment is defined, and the change class is known.
#[must_use]
pub const fn rollout_can_transition_staged_to_active(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(evidence.stage_state, StorageIntentPolicyStageState::Staged)
        && evidence.has_compiled_policy()
        && evidence.has_publication_transaction()
        && evidence.has_scope()
        && evidence.has_old_receipt_treatment()
        && evidence.has_change_class()
}

/// Stage transition: active-for-new-writes → converging-existing.
///
/// Active becomes converging when new writes are being admitted and
/// convergence frontier and replacement receipt set are bound.
#[must_use]
pub const fn rollout_can_transition_active_to_converging(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::ActiveForNewWrites
    )
        && evidence_ref_has_id(evidence.convergence_frontier_ref)
        && evidence_ref_has_id(evidence.replacement_receipt_set_ref)
}

/// Stage transition: converging-existing → superseded.
///
/// Converging becomes superseded when a later revision has replaced it.
#[must_use]
pub const fn rollout_can_transition_converging_to_superseded(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::ConvergingExisting
    )
        && evidence_ref_has_id(evidence.supersession_ref)
}

/// Stage transition: any active state → rollback-required.
///
/// Rollback is required when the stage cannot safely continue.
#[must_use]
pub const fn rollout_can_transition_to_rollback_required(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    evidence.stage_state.admits_new_writes()
        || matches!(
            evidence.stage_state,
            StorageIntentPolicyStageState::Staged
                | StorageIntentPolicyStageState::Blocked
        )
}

/// Stage transition: rollback-required → rolled-back.
///
/// Rollback is complete when the rollback/re-entry ref is present.
#[must_use]
pub const fn rollout_can_transition_rollback_required_to_rolled_back(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::RollbackRequired
    )
        && evidence_ref_has_id(evidence.rollback_reentry_ref)
}

/// Stage transition: any active or staged state → blocked.
///
/// The rollout becomes blocked when prerequisites are missing.
#[must_use]
pub const fn rollout_can_become_blocked(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::Staged
            | StorageIntentPolicyStageState::ActiveForNewWrites
            | StorageIntentPolicyStageState::ConvergingExisting
    )
}

/// Stage transition: blocked → rollback-required.
///
/// Blocked can move to rollback-required when intervention is needed.
#[must_use]
pub const fn rollout_can_transition_blocked_to_rollback_required(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(evidence.stage_state, StorageIntentPolicyStageState::Blocked)
}

/// Stage transition: superseded → retired.
///
/// Superseded becomes retired when no obligations remain and retention/safe
/// retirement evidence says the old revision is no longer needed.
#[must_use]
pub const fn rollout_can_transition_superseded_to_retired(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.stage_state,
        StorageIntentPolicyStageState::Superseded
    )
        && !evidence_ref_has_id(evidence.outstanding_obligation_ref)
        && evidence.has_safe_retirement_evidence()
}

/// Returns true when the in-flight fence requires new writes to use the
/// new revision.
#[must_use]
pub const fn rollout_fence_splits_new_and_old_writes(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    evidence.stage_state.admits_new_writes()
        && evidence.in_flight_fence_flags.fenced_new_writes()
}

/// Returns true when old-receipt treatment permits reading old receipts.
#[must_use]
pub const fn rollout_permits_reading_old_receipts(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    !matches!(
        evidence.old_receipt_treatment,
        StorageIntentOldReceiptTreatment::Refuse
            | StorageIntentOldReceiptTreatment::Unknown
    )
}

/// Returns true when replacement receipt evidence is required before
/// claiming convergence for old-revision receipts.
#[must_use]
pub const fn rollout_requires_replacement_receipts_for_old_generations(
    evidence: StorageIntentPolicyRolloutEvidence,
) -> bool {
    matches!(
        evidence.old_receipt_treatment,
        StorageIntentOldReceiptTreatment::RequireConvergence
    )
        && evidence_ref_has_id(evidence.replacement_receipt_set_ref)
}

// ── Recovery/degradation evidence types (#900) ── //

/// Current degraded state for a receipt set, read path, or repair obligation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDegradationClass {
    /// No degradation; receipt set is exact and authority-capable.
    #[default]
    Exact = 0,
    /// A weaker or healing state is visible but must not be hidden as exact.
    DegradedVisible = 1,
    /// Active reconstruction in progress; receipts are not yet authority.
    Reconstructing = 2,
    /// A read repair or scrub-triggered repair is required before next authority use.
    RepairRequired = 3,
    /// A full rebuild or resilver must complete before authority can be restored.
    RebuildRequired = 4,
    /// Quorum is not reachable for the receipt set.
    NoQuorum = 5,
    /// Network partition prevents authority-capable operation.
    Partitioned = 6,
    /// Geo-replication lag exceeds the policy RPO bound.
    GeoLagged = 7,
    /// Operation is temporarily blocked by a recovery cooldown, fence, or gate.
    Blocked = 8,
    /// Operation is permanently refused by evidence or policy.
    Refused = 9,
    /// Evidence is missing and the degradation class cannot be determined.
    UnknownEvidence = 10,
}

impl StorageIntentDegradationClass {
    /// Returns true when the state may legally satisfy authority.
    #[must_use]
    pub const fn is_authority_capable(self) -> bool {
        matches!(self, Self::Exact)
    }

    /// Returns true when the state is visible but must not change authority.
    #[must_use]
    pub const fn is_visible_non_authority(self) -> bool {
        matches!(
            self,
            Self::DegradedVisible
                | Self::Reconstructing
                | Self::RepairRequired
                | Self::RebuildRequired
                | Self::NoQuorum
                | Self::Partitioned
                | Self::GeoLagged
        )
    }

    /// Returns true when the state blocks all authority-changing use.
    #[must_use]
    pub const fn blocks_authority(self) -> bool {
        matches!(
            self,
            Self::Blocked
                | Self::Refused
                | Self::UnknownEvidence
                | Self::NoQuorum
                | Self::Partitioned
        )
    }
}

/// Visibility law for degraded state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDegradationVisibility {
    /// No explicit degradation visibility law.
    #[default]
    Unknown = 0,
    /// Degraded state must be surfaced to callers or operators.
    Visible = 1,
    /// Degraded state may be hidden only when the guarantee class permits it.
    ConditionalHide = 2,
    /// Degraded state must not be hidden under any circumstances.
    ForbidHide = 3,
}

/// Refusal law for degraded reads, writes, or repairs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentDegradationRefusalLaw {
    /// No explicit refusal law.
    #[default]
    Unknown = 0,
    /// Refuse when any target is missing or under-width.
    RefuseWhenUnderWidth = 1,
    /// Refuse when quorum is not reachable.
    RefuseWhenNoQuorum = 2,
    /// Refuse when partition or split-brain hazard exists.
    RefuseWhenPartitioned = 3,
    /// Refuse when geo lag exceeds policy.
    RefuseWhenGeoLagged = 4,
    /// Refuse when trust, key, or domain evidence is stale.
    RefuseWhenTrustEvidenceStale = 5,
    /// Refuse when capacity reserve cannot cover the repair.
    RefuseWhenNoRepairReserve = 6,
    /// Serve degraded-visible reads but refuse authority-changing operations.
    ServeDegradedReadsOnly = 7,
    /// Refuse all operations while degraded.
    RefuseAllDegraded = 8,
}

/// Requested degradation policy bound to a compiled storage-intent policy revision.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentDegradationPolicy {
    /// Visibility law for degraded state.
    pub visibility: StorageIntentDegradationVisibility,
    /// Refusal law for degraded operations.
    pub refusal_law: StorageIntentDegradationRefusalLaw,
    /// The compiled policy that set this degradation law.
    pub policy_ref: StorageIntentEvidenceRef,
    /// Policy revision that defined these bounds.
    pub policy_revision: StorageIntentPolicyRevision,
}

impl StorageIntentDegradationPolicy {
    /// Returns true when the policy explicitly forbids hiding degradation.
    #[must_use]
    pub const fn forbids_hiding_degradation(self) -> bool {
        matches!(self.visibility, StorageIntentDegradationVisibility::ForbidHide)
    }

    /// Returns true when the policy permits degraded-visible reads.
    #[must_use]
    pub const fn permits_degraded_reads(self) -> bool {
        matches!(
            self.refusal_law,
            StorageIntentDegradationRefusalLaw::ServeDegradedReadsOnly
        )
    }

    /// Returns true when the policy refuses all operations while degraded.
    #[must_use]
    pub const fn refuses_all_degraded(self) -> bool {
        matches!(
            self.refusal_law,
            StorageIntentDegradationRefusalLaw::RefuseAllDegraded
        )
    }

    /// Returns true when the policy has a bound policy reference.
    #[must_use]
    pub const fn has_policy_ref(self) -> bool {
        evidence_ref_has_id(self.policy_ref) && self.policy_revision.0 > 0
    }
}

/// Recovery priority class for repair, rebuild, and catch-up scheduling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentRecoveryPriorityClass {
    /// Priority is unknown or not yet determined.
    #[default]
    Unknown = 0,
    /// Immediate critical: data loss or corruption risk is active.
    ImmediateCritical = 1,
    /// High foreground: read path is blocked or will degrade without repair.
    HighForeground = 2,
    /// Normal priority: scheduled recovery within the RTO window.
    Normal = 3,
    /// Background opportunistic: recovery may use idle resources.
    BackgroundOpportunistic = 4,
    /// Deferred or hibernating: recovery is held behind a cooldown or gate.
    DeferredHibernating = 5,
    /// Archived: recovery is not needed for live authority.
    Archived = 6,
}

/// Individual target degradation class within a receipt set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentTargetDegradationClass {
    /// Target is present and accounted for.
    #[default]
    Present = 0,
    /// Target is missing entirely (device lost, unplugged, or decommissioned).
    Missing = 1,
    /// Target data is corrupt or digest-mismatched.
    Corrupt = 2,
    /// Target data is stale (outdated generation or epoch).
    Stale = 3,
    /// Target is quarantined by trust or health evidence.
    Quarantined = 4,
    /// Target has been fenced out of the membership.
    Fenced = 5,
    /// Target is draining and must not satisfy fresh reads.
    Drained = 6,
    /// Target belongs to a wrong administrative or trust domain.
    WrongDomain = 7,
    /// Target count is below the redundancy width.
    UnderWidth = 8,
    /// Target is unreachable due to transport or network failure.
    Unreachable = 9,
}

/// Split-brain hazard state from membership evidence (#750).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentSplitBrainHazard {
    /// No split-brain hazard is detected.
    #[default]
    None = 0,
    /// Partition is possible; hazard assessment is incomplete.
    Possible = 1,
    /// A confirmed split-brain hazard exists.
    Confirmed = 2,
    /// Hazard was detected and the minority side is fenced.
    FencedMinority = 3,
    /// Hazard was detected and is being healed.
    Healing = 4,
    /// Evidence is missing and the hazard cannot be determined.
    UnknownEvidence = 5,
}

/// Typed refusal reason for recovery/degradation evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentRecoveryRefusalReason {
    /// No refusal.
    #[default]
    None = 0,
    /// No legal receipt set exists for this recovery role.
    NoLegalReceiptSet = 1,
    /// Source receipt is stale or missing.
    StaleSourceReceipt = 2,
    /// Reconstruction width is below policy minimum.
    UnderWidthReconstruction = 3,
    /// A corrupt repair source was included in the reconstruction set.
    CorruptRepairSource = 4,
    /// Partition healing attempted with an old membership epoch.
    OldEpochPartitionHealing = 5,
    /// A fenced or draining peer was counted as a data source.
    FencedPeerCountedAsData = 6,
    /// A quarantined source was used for repair or reconstruction.
    QuarantinedRepairSource = 7,
    /// A wrong-domain source was included in the reconstruction set.
    WrongDomainRepairSource = 8,
    /// Read repair was attempted without capacity reserve evidence.
    ReadRepairWithoutReserve = 9,
    /// Replacement receipt is missing at old-receipt retirement time.
    MissingReplacementReceipt = 10,
    /// Geo lag exceeds the policy RPO bound.
    GeoLagExceedsPolicy = 11,
    /// Trust evidence is stale for repair or geo participants.
    StaleTrustEvidenceForRecovery = 12,
    /// Ordering evidence is missing for repair publication.
    MissingOrderingForRepairPublication = 13,
    /// Capacity reserve cannot cover the rebuild scratch space.
    InsufficientRebuildScratchCapacity = 14,
    /// Recovery is blocked by a retry cooldown.
    RecoveryCooldownBlocked = 15,
    /// Evidence is missing for the recovery obligation.
    MissingRecoveryObligationEvidence = 16,
    /// Split-brain hazard prevents safe recovery.
    SplitBrainHazardUnsafe = 17,
    /// Key epoch is stale for cross-domain repair sources.
    StaleKeyEpochForRecovery = 18,
    /// Residency constraint is violated by a repair participant.
    ResidencyViolationInRecovery = 19,
    /// Recovery RPO/RTO deadline has been crossed.
    RecoveryDeadlineCrossed = 20,
}

/// Full recovery/degradation evidence record (#900).
///
/// This record is the storage-intent authority projection for degraded reads,
/// read repair, scrub-triggered repair, rebuild/resilver, evacuation,
/// relocation overlap, geo catch-up, archive restore, degraded write admission,
/// receipt retirement, and satisfaction reconciliation.
///
/// It cites placement receipt sets, membership evidence, trust evidence,
/// ordering evidence, capacity evidence, and media-capability evidence
/// without implementing their producer or consumer runtime behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentRecoveryDegradationEvidence {
    /// Self-referential evidence identity.
    pub evidence_ref: StorageIntentEvidenceRef,
    /// Requested degradation policy from the compiled storage-intent policy.
    pub degradation_policy: StorageIntentDegradationPolicy,
    /// Current degraded state.
    pub degradation: StorageIntentDegradationClass,
    /// Evidence ref for the source placement receipt set.
    pub source_receipt_set_ref: StorageIntentEvidenceRef,
    /// Receipt generation for the source set.
    pub receipt_generation: u64,
    /// Redundancy width (total targets including parity) for the receipt set.
    pub redundancy_width: u8,
    /// Reconstruction width (minimum targets needed to reconstruct).
    pub reconstruction_width: u8,
    /// Evidence ref for the payload digest or shard-digest set.
    pub payload_digest_ref: StorageIntentEvidenceRef,
    /// Wall-clock freshness of the source evidence in milliseconds (0 if unknown).
    pub source_freshness_ms: u64,
    /// True when source freshness is backed by temporal evidence.
    pub source_freshness_known: bool,
    /// Population counts for each target degradation class.
    pub target_present: u8,
    pub target_missing: u8,
    pub target_corrupt: u8,
    pub target_stale: u8,
    pub target_quarantined: u8,
    pub target_fenced: u8,
    pub target_drained: u8,
    pub target_wrong_domain: u8,
    pub target_under_width: u8,
    pub target_unreachable: u8,
    /// Repair and rebuild evidence refs.
    pub read_repair_ref: StorageIntentEvidenceRef,
    pub scrub_finding_ref: StorageIntentEvidenceRef,
    pub repair_ticket_ref: StorageIntentEvidenceRef,
    pub rebuild_ticket_ref: StorageIntentEvidenceRef,
    pub relocation_overlap_ref: StorageIntentEvidenceRef,
    pub replacement_receipt_ref: StorageIntentEvidenceRef,
    pub flow_commit_ref: StorageIntentEvidenceRef,
    pub old_receipt_retirement_ref: StorageIntentEvidenceRef,
    /// Partition and healing evidence refs (#750).
    pub partition_evidence_ref: StorageIntentEvidenceRef,
    pub membership_epoch_ref: StorageIntentEvidenceRef,
    pub fence_ref: StorageIntentEvidenceRef,
    pub quorum_set_ref: StorageIntentEvidenceRef,
    pub witness_role_ref: StorageIntentEvidenceRef,
    pub data_role_ref: StorageIntentEvidenceRef,
    pub split_brain_hazard: StorageIntentSplitBrainHazard,
    /// Trust and domain evidence refs (#897).
    pub trust_domain_ref: StorageIntentEvidenceRef,
    pub key_epoch_ref: StorageIntentEvidenceRef,
    pub authorization_ref: StorageIntentEvidenceRef,
    pub audit_ref: StorageIntentEvidenceRef,
    pub residency_ref: StorageIntentEvidenceRef,
    pub quarantine_ref: StorageIntentEvidenceRef,
    /// Ordering and replay evidence refs (#894).
    pub repair_publication_ref: StorageIntentEvidenceRef,
    pub rebuild_completion_ref: StorageIntentEvidenceRef,
    pub replacement_publication_ref: StorageIntentEvidenceRef,
    pub receipt_retirement_ordering_ref: StorageIntentEvidenceRef,
    /// Capacity and admission evidence refs (#898).
    pub read_repair_capacity_ref: StorageIntentEvidenceRef,
    pub rebuild_scratch_capacity_ref: StorageIntentEvidenceRef,
    pub evacuation_capacity_ref: StorageIntentEvidenceRef,
    pub geo_backlog_capacity_ref: StorageIntentEvidenceRef,
    pub receipt_retirement_capacity_ref: StorageIntentEvidenceRef,
    /// Recovery scheduling and debt state.
    pub recovery_priority: StorageIntentRecoveryPriorityClass,
    pub rpo_lag_ms: u64,
    pub rto_lag_ms: u64,
    pub repair_debt_bytes: u64,
    pub degraded_read_foreground_cost_us: u32,
    pub retry_cooldown_ms: u64,
    /// Recovery-level typed refusal.
    pub refusal: StorageIntentRecoveryRefusalReason,
    pub refusal_ref: StorageIntentEvidenceRef,
}

impl StorageIntentRecoveryDegradationEvidence {
    /// Returns true when the record cites a non-empty recovery/degradation artifact.
    #[must_use]
    pub const fn has_recovery_evidence(self) -> bool {
        self.evidence_ref.kind as u16
            == StorageIntentEvidenceKind::RecoveryDegradationEvidence as u16
            && !bytes32_are_zero(self.evidence_ref.id.0)
    }

    /// Returns true when the degradation policy is bound.
    #[must_use]
    pub const fn has_degradation_policy(self) -> bool {
        self.degradation_policy.has_policy_ref()
    }

    /// Returns true when the source receipt set is bound.
    #[must_use]
    pub const fn has_source_receipt_set(self) -> bool {
        evidence_ref_has_id(self.source_receipt_set_ref) && self.receipt_generation > 0
    }

    /// Returns true when the receipt set has enough targets present for authority.
    #[must_use]
    pub const fn has_authority_width(self) -> bool {
        self.redundancy_width > 0
            && self.target_present >= self.redundancy_width
            && self.target_missing == 0
            && self.target_corrupt == 0
            && self.target_unreachable == 0
    }

    /// Returns true when enough targets are reachable for degraded reconstruction.
    #[must_use]
    pub const fn has_reconstruction_width(self) -> bool {
        self.reconstruction_width > 0
            && self.target_present >= self.reconstruction_width
    }

    /// Returns true when no target is quarantined, fenced, or wrong-domain.
    #[must_use]
    pub const fn targets_are_clean(self) -> bool {
        self.target_corrupt == 0
            && self.target_stale == 0
            && self.target_quarantined == 0
            && self.target_fenced == 0
            && self.target_wrong_domain == 0
            && self.target_drained == 0
    }

    /// Returns true when the recovery evidence has an active refusal.
    #[must_use]
    pub const fn is_refused(self) -> bool {
        self.refusal as u8 != StorageIntentRecoveryRefusalReason::None as u8
    }

    /// Returns true when the degradation class is authority-capable (exact).
    #[must_use]
    pub const fn is_exact(self) -> bool {
        self.degradation.is_authority_capable()
    }

    /// Returns true when the degradation is visible but non-authority.
    #[must_use]
    pub const fn is_degraded_visible(self) -> bool {
        self.degradation.is_visible_non_authority()
    }

    /// Returns true when source freshness is known and within a bound.
    #[must_use]
    pub const fn source_freshness_within(self, max_age_ms: u64) -> bool {
        self.source_freshness_known && self.source_freshness_ms <= max_age_ms
    }
}

// ── Recovery/degradation evidence predicates (#900) ── //

/// Predicate: can this receipt set serve a degraded read?
///
/// A degraded read is legal only when the policy permits degraded-visible reads,
/// the receipt set has reconstruction width, no quarantined or fenced target
/// is counted as a data source, trust and domain evidence is present, and
/// the source freshness is within the tolerable bound.
#[must_use]
pub const fn recovery_evidence_supports_degraded_read(
    evidence: StorageIntentRecoveryDegradationEvidence,
    max_source_age_ms: u64,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.degradation_policy.permits_degraded_reads() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_reconstruction_width() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.targets_are_clean() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }
    if !evidence.source_freshness_within(max_source_age_ms) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::StaleOrderingEvidence);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a read repair proceed?
///
/// A read repair is legal only when a source receipt set is present,
/// the repair target is identified, the read repair capacity ref is bound,
/// and the source data is not from a fenced, quarantined, or wrong-domain peer.
#[must_use]
pub const fn recovery_evidence_supports_read_repair(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    if evidence.target_corrupt == 0 && evidence.target_stale == 0 && evidence.target_missing == 0 {
        // Nothing to repair; this is not a predicate failure but a no-op.
        // Still satisfiable: repair is not needed.
    }
    if evidence.target_quarantined > 0 {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }
    if evidence.target_fenced > 0 {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if evidence.target_wrong_domain > 0 {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if !evidence_ref_has_id(evidence.read_repair_capacity_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a scrub-triggered repair proceed?
///
/// A scrub-triggered repair is legal only when a scrub finding ref is bound,
/// the repair ticket ref is bound, and the targets are clean of quarantined,
/// fenced, or wrong-domain peers.
#[must_use]
pub const fn recovery_evidence_supports_scrub_repair(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.scrub_finding_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.repair_ticket_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.targets_are_clean() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }
    if !evidence.has_reconstruction_width() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a rebuild or resilver proceed?
///
/// A rebuild is legal only when the rebuild ticket ref is bound,
/// the rebuild completion ordering ref is bound, the capacity reserve
/// for rebuild scratch is bound, and the source receipt set has reconstruction width.
#[must_use]
pub const fn recovery_evidence_supports_rebuild(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.rebuild_ticket_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.rebuild_completion_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.rebuild_scratch_capacity_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() || !evidence.has_reconstruction_width() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    if !evidence.targets_are_clean() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::QuarantinedSource);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can an evacuation proceed?
///
/// Evacuation is legal only when the evacuation capacity ref is bound,
/// a source receipt set exists, and no target is fenced or drained
/// in a way that would hide data loss.
#[must_use]
pub const fn recovery_evidence_supports_evacuation(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.evacuation_capacity_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    // Drained targets are expected during evacuation, but fenced targets
    // must not be counted as safe to drain.
    if evidence.target_fenced > 0 {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a relocation overlap proceed?
///
/// Relocation overlap (source and destination both holding authority temporarily)
/// is legal only when the relocation overlap ref is bound, the replacement
/// receipt ref is bound, and the source receipt set is present.
#[must_use]
pub const fn recovery_evidence_supports_relocation_overlap(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.relocation_overlap_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.replacement_receipt_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a geo catch-up proceed?
///
/// Geo catch-up is legal only when the geo backlog capacity ref is bound,
/// the trust domain ref is bound, the partition evidence ref is present,
/// and the split-brain hazard is not confirmed or healing.
#[must_use]
pub const fn recovery_evidence_supports_geo_catchup(
    evidence: StorageIntentRecoveryDegradationEvidence,
    max_geo_lag_ms: u64,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.geo_backlog_capacity_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.trust_domain_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if evidence.split_brain_hazard as u8 == StorageIntentSplitBrainHazard::Confirmed as u8
        || evidence.split_brain_hazard as u8 == StorageIntentSplitBrainHazard::Healing as u8
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if evidence.rpo_lag_ms > max_geo_lag_ms {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::DurabilityOrRpoNotMet);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can an archive restore proceed?
///
/// Archive restore is legal only when the archive restore evidence refs
/// are present, the residency ref is bound (if required), and the
/// receipt set has at least reconstruction width.
#[must_use]
pub const fn recovery_evidence_supports_archive_restore(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    if !evidence.has_reconstruction_width() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can a degraded write be admitted when policy permits it?
///
/// A degraded write is legal only when the policy does not refuse all degraded
/// operations, the receipt set has reconstruction width, and the source
/// receipt evidence is present. Hidden downgrade (claiming durable success
/// from under-width or stale evidence) is forbidden.
#[must_use]
pub const fn recovery_evidence_supports_degraded_write(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if evidence.degradation_policy.refuses_all_degraded() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    if !evidence.has_reconstruction_width() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if evidence.degradation.blocks_authority() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    // Hidden downgrade gate: if degradation is not exact, the write must
    // not be claimed as durable success.
    if evidence.is_exact() {
        return ReceiptPredicateResult::SATISFIED;
    }
    // Degraded-visible write: policy must permit degraded reads at minimum.
    if !evidence.degradation_policy.permits_degraded_reads() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can an old receipt be retired?
///
/// Receipt retirement is legal only when the replacement receipt ref is bound,
/// the old receipt retirement ref is bound (ordering evidence for retirement),
/// the receipt retirement ordering ref is bound, and the receipt retirement
/// capacity ref is bound.
#[must_use]
pub const fn recovery_evidence_supports_receipt_retirement(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.replacement_receipt_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.old_receipt_retirement_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence_ref_has_id(evidence.receipt_retirement_ordering_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::MissingOrderingEvidence);
    }
    if !evidence_ref_has_id(evidence.receipt_retirement_capacity_ref) {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: can satisfaction reconciliation proceed?
///
/// Satisfaction reconciliation (#874) is legal only when the receipt set
/// is present, the degradation class is not blocked or refused, and
/// the recovery obligation evidence is present.
#[must_use]
pub const fn recovery_evidence_supports_satisfaction_reconciliation(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> ReceiptPredicateResult {
    if evidence.is_refused() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_recovery_evidence() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if evidence.degradation.blocks_authority() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::EvidenceNotUsable);
    }
    if !evidence.has_source_receipt_set() {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::NoLegalReceiptSet);
    }
    ReceiptPredicateResult::SATISFIED
}

/// Predicate: does the degradation policy forbid hiding the degraded state?
///
/// When true, callers and operators must surface the degradation class and
/// refusal reason; an "OK" or "success" result is illegal.
#[must_use]
pub const fn degradation_forbids_hiding(
    policy: StorageIntentDegradationPolicy,
    degradation: StorageIntentDegradationClass,
) -> bool {
    if policy.forbids_hiding_degradation() {
        return true;
    }
    // Even without explicit forbid-hide, a non-exact degradation must not be hidden
    // when the policy has conditional-hide but the degradation is not exact.
    if policy.visibility as u8 == StorageIntentDegradationVisibility::ConditionalHide as u8
        && !degradation.is_authority_capable()
    {
        return true;
    }
    false
}

/// Predicate: verify that a recovery/degradation record does not commit any
/// of the hidden-downgrade violations enumerated in #900.
///
/// Returns true when the record would be illegal to surface as authority.
/// Durable success, fresh read, geo intent, full placement, or receipt
/// retirement must not be claimed from stale, under-width, partition-ambiguous,
/// wrong-domain, under-reserved, or unverified reconstruction evidence.
#[must_use]
pub const fn recovery_evidence_commits_hidden_downgrade(
    evidence: StorageIntentRecoveryDegradationEvidence,
) -> bool {
    // If the record itself is refused, a hidden-downgrade claim would be outright fraud.
    if evidence.is_refused() {
        return true;
    }
    if !evidence.has_recovery_evidence() {
        return true;
    }
    // Claiming exact/authority from under-width targets.
    if evidence.is_exact() && !evidence.has_authority_width() {
        return true;
    }
    // Claiming fresh read from stale source.
    if evidence.is_exact() && !evidence.source_freshness_known {
        return true;
    }
    // Claiming geo intent while geo-lagged.
    if evidence.degradation as u8 == StorageIntentDegradationClass::Exact as u8
        && evidence.rpo_lag_ms > 0
        && !evidence.source_freshness_known
    {
        return true;
    }
    // Claiming full placement from under-width reconstruction.
    if evidence.is_exact() && evidence.target_under_width > 0 {
        return true;
    }
    // Claiming exact authority during partition ambiguity.
    if evidence.is_exact()
        && evidence.split_brain_hazard as u8 != StorageIntentSplitBrainHazard::None as u8
    {
        return true;
    }
    // Claiming receipt retirement without replacement receipt.
    if evidence.replacement_receipt_ref.is_bound()
        && !evidence_ref_has_id(evidence.replacement_receipt_ref)
    {
        return true;
    }
    // Claiming authority with wrong-domain targets mixed in.
    if evidence.is_exact() && evidence.target_wrong_domain > 0 {
        return true;
    }
    false
}

// ── Canonical encodings for new enums ── //

impl_u8_canonical!(StorageIntentDegradationClass, {
    Exact = 0 => "exact",
    DegradedVisible = 1 => "degraded-visible",
    Reconstructing = 2 => "reconstructing",
    RepairRequired = 3 => "repair-required",
    RebuildRequired = 4 => "rebuild-required",
    NoQuorum = 5 => "no-quorum",
    Partitioned = 6 => "partitioned",
    GeoLagged = 7 => "geo-lagged",
    Blocked = 8 => "blocked",
    Refused = 9 => "refused",
    UnknownEvidence = 10 => "unknown-evidence",
});

impl_u8_canonical!(StorageIntentDegradationVisibility, {
    Unknown = 0 => "unknown",
    Visible = 1 => "visible",
    ConditionalHide = 2 => "conditional-hide",
    ForbidHide = 3 => "forbid-hide",
});

impl_u8_canonical!(StorageIntentDegradationRefusalLaw, {
    Unknown = 0 => "unknown",
    RefuseWhenUnderWidth = 1 => "refuse-when-under-width",
    RefuseWhenNoQuorum = 2 => "refuse-when-no-quorum",
    RefuseWhenPartitioned = 3 => "refuse-when-partitioned",
    RefuseWhenGeoLagged = 4 => "refuse-when-geo-lagged",
    RefuseWhenTrustEvidenceStale = 5 => "refuse-when-trust-evidence-stale",
    RefuseWhenNoRepairReserve = 6 => "refuse-when-no-repair-reserve",
    ServeDegradedReadsOnly = 7 => "serve-degraded-reads-only",
    RefuseAllDegraded = 8 => "refuse-all-degraded",
});

impl_u8_canonical!(StorageIntentRecoveryPriorityClass, {
    Unknown = 0 => "unknown",
    ImmediateCritical = 1 => "immediate-critical",
    HighForeground = 2 => "high-foreground",
    Normal = 3 => "normal",
    BackgroundOpportunistic = 4 => "background-opportunistic",
    DeferredHibernating = 5 => "deferred-hibernating",
    Archived = 6 => "archived",
});

impl_u8_canonical!(StorageIntentTargetDegradationClass, {
    Present = 0 => "present",
    Missing = 1 => "missing",
    Corrupt = 2 => "corrupt",
    Stale = 3 => "stale",
    Quarantined = 4 => "quarantined",
    Fenced = 5 => "fenced",
    Drained = 6 => "drained",
    WrongDomain = 7 => "wrong-domain",
    UnderWidth = 8 => "under-width",
    Unreachable = 9 => "unreachable",
});

impl_u8_canonical!(StorageIntentSplitBrainHazard, {
    None = 0 => "none",
    Possible = 1 => "possible",
    Confirmed = 2 => "confirmed",
    FencedMinority = 3 => "fenced-minority",
    Healing = 4 => "healing",
    UnknownEvidence = 5 => "unknown-evidence",
});

impl_u8_canonical!(StorageIntentRecoveryRefusalReason, {
    None = 0 => "none",
    NoLegalReceiptSet = 1 => "no-legal-receipt-set",
    StaleSourceReceipt = 2 => "stale-source-receipt",
    UnderWidthReconstruction = 3 => "under-width-reconstruction",
    CorruptRepairSource = 4 => "corrupt-repair-source",
    OldEpochPartitionHealing = 5 => "old-epoch-partition-healing",
    FencedPeerCountedAsData = 6 => "fenced-peer-counted-as-data",
    QuarantinedRepairSource = 7 => "quarantined-repair-source",
    WrongDomainRepairSource = 8 => "wrong-domain-repair-source",
    ReadRepairWithoutReserve = 9 => "read-repair-without-reserve",
    MissingReplacementReceipt = 10 => "missing-replacement-receipt",
    GeoLagExceedsPolicy = 11 => "geo-lag-exceeds-policy",
    StaleTrustEvidenceForRecovery = 12 => "stale-trust-evidence-for-recovery",
    MissingOrderingForRepairPublication = 13 => "missing-ordering-for-repair-publication",
    InsufficientRebuildScratchCapacity = 14 => "insufficient-rebuild-scratch-capacity",
    RecoveryCooldownBlocked = 15 => "recovery-cooldown-blocked",
    MissingRecoveryObligationEvidence = 16 => "missing-recovery-obligation-evidence",
    SplitBrainHazardUnsafe = 17 => "split-brain-hazard-unsafe",
    StaleKeyEpochForRecovery = 18 => "stale-key-epoch-for-recovery",
    ResidencyViolationInRecovery = 19 => "residency-violation-in-recovery",
    RecoveryDeadlineCrossed = 20 => "recovery-deadline-crossed",
});

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_A: StorageIntentDomainId = StorageIntentDomainId([1_u8; 16]);
    const DOMAIN_B: StorageIntentDomainId = StorageIntentDomainId([2_u8; 16]);

    fn evidence_ref(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            StorageIntentEvidenceId([byte; 32]),
            u64::from(byte),
            1,
        )
    }

    fn trust_ref(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, byte)
    }

    fn capacity_scope() -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: DOMAIN_A,
            object_id: StorageIntentEvidenceId([201_u8; 32]),
            range_start: 0,
            range_len: 4096,
            generation: 11,
        }
    }

    fn capacity_refs() -> StorageIntentCapacityAdmissionRefs {
        StorageIntentCapacityAdmissionRefs {
            dataset_ref: evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 130),
            space_domain_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                131,
            ),
            quota_ref: evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 132),
            logical_headroom_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                133,
            ),
            physical_headroom_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                134,
            ),
            allocation_class_ref: evidence_ref(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                135,
            ),
            segment_class_ref: evidence_ref(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                136,
            ),
            allocation_ticket_ref: evidence_ref(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                137,
            ),
            claim_ledger_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                138,
            ),
            reserve_ledger_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                139,
            ),
            reserve_receipt_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                140,
            ),
            dirty_window_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 141),
            writeback_budget_ref: evidence_ref(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                142,
            ),
            sync_intent_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                143,
            ),
            repair_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                144,
            ),
            evacuation_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                145,
            ),
            rebuild_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                146,
            ),
            geo_catchup_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                147,
            ),
            relocation_scratch_ref: evidence_ref(StorageIntentEvidenceKind::RelocationReceipt, 148),
            pending_free_frontier_ref: evidence_ref(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                149,
            ),
            reclaim_debt_ref: evidence_ref(StorageIntentEvidenceKind::LayoutAllocatorEvidence, 150),
            amplification_estimate_ref: evidence_ref(
                StorageIntentEvidenceKind::DataShapeEvidence,
                151,
            ),
            capacity_authority_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                152,
            ),
            policy_rollout_ref: evidence_ref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 153),
            tenant_isolation_ref: evidence_ref(
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                154,
            ),
            temporal_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 155),
            evidence_query_snapshot_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                156,
            ),
        }
    }

    fn full_capacity_flags() -> StorageIntentCapacityAdmissionFlags {
        capacity_base_required_flags()
            .union(StorageIntentCapacityAdmissionFlags::DIRTY_WINDOW_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::WRITEBACK_BUDGET_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::SYNC_INTENT_RESERVED)
            .union(StorageIntentCapacityAdmissionFlags::REPAIR_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::EVACUATION_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::REBUILD_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::GEO_CATCHUP_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::RELOCATION_RESERVE_AVAILABLE)
            .union(StorageIntentCapacityAdmissionFlags::RECEIPT_RETIREMENT_SAFE)
            .union(StorageIntentCapacityAdmissionFlags::AUTHORITY_PROMOTION_SAFE)
    }

    fn capacity_requirement(
        role: StorageIntentCapacityAdmissionRole,
    ) -> StorageIntentCapacityAdmissionRequirement {
        StorageIntentCapacityAdmissionRequirement {
            role,
            policy_id: StorageIntentPolicyId([157_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(12),
            scope: capacity_scope(),
            min_logical_bytes: 100,
            min_physical_bytes: 300,
            max_evidence_age_ms: 2000,
            now_ms: 2000,
        }
    }

    fn capacity_evidence() -> StorageIntentCapacityAdmissionEvidence {
        let scope = capacity_scope();
        StorageIntentCapacityAdmissionEvidence {
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 158),
            policy_id: StorageIntentPolicyId([157_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(12),
            scope,
            dataset_id: scope.dataset_id,
            space_domain_id: DOMAIN_A,
            quota_domain_id: DOMAIN_A,
            budget_owner_id: DOMAIN_A,
            state: StorageIntentCapacityAdmissionState::Admitted,
            reserve_pressure: StorageIntentReservePressureState::Normal,
            protected_floor_breaches: StorageIntentProtectedReserveMask::EMPTY,
            flags: full_capacity_flags(),
            refs: capacity_refs(),
            amplification: StorageIntentCapacityAmplificationEstimate {
                logical_bytes: 100,
                replica_count: 3,
                ec_data_shards: 0,
                ec_parity_shards: 0,
                cow_old_plus_new_bytes: 0,
                snapshot_pinned_bytes: 0,
                clone_pinned_bytes: 0,
                receive_base_pinned_bytes: 0,
                compression_expansion_bytes: 0,
                rebake_overlap_bytes: 0,
                receipt_overlap_bytes: 0,
                projected_required_bytes: 400,
                estimate_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 159),
            },
            logical_required_bytes: 100,
            logical_available_bytes: 10_000,
            quota_available_bytes: 10_000,
            physical_required_bytes: 300,
            physical_available_bytes: 10_000,
            dirty_window_required_bytes: 100,
            dirty_window_available_bytes: 1000,
            writeback_required_bytes: 100,
            writeback_available_bytes: 1000,
            sync_intent_required_bytes: 100,
            sync_intent_available_bytes: 1000,
            recovery_required_bytes: 100,
            repair_scratch_available_bytes: 1000,
            evacuation_scratch_available_bytes: 1000,
            rebuild_scratch_available_bytes: 1000,
            geo_catchup_required_bytes: 100,
            geo_catchup_available_bytes: 1000,
            relocation_scratch_required_bytes: 100,
            relocation_scratch_available_bytes: 1000,
            pending_free_counted_bytes: 0,
            reclaimable_counted_bytes: 0,
            reclaim_debt_bytes: 0,
            slop_floor_required_bytes: 50,
            protected_floor_required_bytes: 100,
            protected_floor_available_bytes: 1000,
            evidence_observed_at_ms: 1000,
            evidence_valid_until_ms: 5000,
            allocation_ticket_expires_at_ms: 5000,
            reserve_escrow_expires_at_ms: 5000,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    #[test]
    fn capacity_evidence_satisfies_all_named_roles() {
        let roles = [
            StorageIntentCapacityAdmissionRole::LocalIntent,
            StorageIntentCapacityAdmissionRole::QuorumIntent,
            StorageIntentCapacityAdmissionRole::FullPlacement,
            StorageIntentCapacityAdmissionRole::GeoCatchUp,
            StorageIntentCapacityAdmissionRole::ArchiveEc,
            StorageIntentCapacityAdmissionRole::ReadRepair,
            StorageIntentCapacityAdmissionRole::Relocation,
            StorageIntentCapacityAdmissionRole::Rebake,
            StorageIntentCapacityAdmissionRole::AuthorityPromotion,
            StorageIntentCapacityAdmissionRole::RamIntentBacking,
            StorageIntentCapacityAdmissionRole::BlockFlushFua,
            StorageIntentCapacityAdmissionRole::FallocateReservation,
            StorageIntentCapacityAdmissionRole::ReceiptRetirement,
            StorageIntentCapacityAdmissionRole::BackgroundOptimizer,
        ];

        for role in roles {
            assert_eq!(
                capacity_evidence_satisfies_role(capacity_requirement(role), capacity_evidence()),
                ReceiptPredicateResult::SATISFIED,
                "{role:?}"
            );
        }
    }

    #[test]
    fn capacity_enospc_refuses_without_logical_headroom() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            logical_available_bytes: 99,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::LocalIntent),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::CapacityHeadroomExhausted
        );
    }

    #[test]
    fn capacity_quota_and_slop_floor_refuse() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            quota_available_bytes: 149,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::FallocateReservation),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::QuotaOrSlopFloorExceeded
        );
    }

    #[test]
    fn capacity_stale_allocation_ticket_refuses() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            allocation_ticket_expires_at_ms: 1999,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::FullPlacement),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::StaleAllocationTicket
        );
    }

    #[test]
    fn capacity_expired_reserve_escrow_refuses() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            reserve_escrow_expires_at_ms: 1999,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::QuorumIntent),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::ExpiredReserveEscrow
        );
    }

    #[test]
    fn capacity_pending_free_counted_too_early_refuses() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            pending_free_counted_bytes: 4096,
            ..capacity_evidence()
        };

        assert!(!capacity_pending_free_is_safe(evidence));
        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::FullPlacement),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::PendingFreeNotSafe
        );
    }

    #[test]
    fn capacity_cow_old_plus_new_under_snapshot_pressure_refuses() {
        let mut evidence = capacity_evidence();
        evidence.amplification.cow_old_plus_new_bytes = 1000;
        evidence.amplification.snapshot_pinned_bytes = 500;
        evidence.amplification.projected_required_bytes = 300;

        assert!(!evidence.amplification.proves_required_overlap());
        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::FullPlacement),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::CapacityAmplificationUnderestimated
        );
    }

    #[test]
    fn capacity_relocation_scratch_reserve_exhaustion_refuses() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            relocation_scratch_available_bytes: 99,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::Relocation),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::RelocationScratchReserveExhausted
        );
    }

    #[test]
    fn capacity_geo_catch_up_backlog_exceeding_reserve_refuses() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            geo_catchup_available_bytes: 99,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::GeoCatchUp),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::GeoCatchUpReserveExceeded
        );
    }

    #[test]
    fn capacity_optimizer_refuses_protected_reserve_borrow() {
        let evidence = StorageIntentCapacityAdmissionEvidence {
            protected_floor_breaches: StorageIntentProtectedReserveMask::SYNC,
            reserve_pressure: StorageIntentReservePressureState::ProtectedFloorWouldBeBreached,
            ..capacity_evidence()
        };

        assert_eq!(
            capacity_evidence_satisfies_role(
                capacity_requirement(StorageIntentCapacityAdmissionRole::BackgroundOptimizer),
                evidence,
            )
            .refusal,
            StorageIntentRefusalReason::OptimizerProtectedReserveBorrow
        );
    }

    fn trust_role_residency(role: StorageIntentTrustRole) -> ResidencyScope {
        match role {
            StorageIntentTrustRole::GeoIntent => ResidencyScope::GeoReplicaAllowed,
            StorageIntentTrustRole::ArchiveRestore => ResidencyScope::Jurisdiction,
            StorageIntentTrustRole::DurablePlacement
            | StorageIntentTrustRole::DegradedReconstruction
            | StorageIntentTrustRole::RepairSource
            | StorageIntentTrustRole::RelocationTarget => ResidencyScope::Region,
            _ => ResidencyScope::Unspecified,
        }
    }

    fn trust_role_requirement_for_test(role: StorageIntentTrustRole) -> TrustDomainRequirement {
        TrustDomainRequirement {
            base: TrustRequirement {
                required_flags: trust_domain_role_required_flags(role),
                min_session_security: trust_domain_role_min_session_security(role),
                min_key_epoch: 9,
                admin_domain: DOMAIN_A,
                security_domain: DOMAIN_A,
                tenant_domain: DOMAIN_A,
                residency: trust_role_residency(role),
                sharing_domain: SharingDomainClass::SameTenant,
            },
            dataset_domain: DOMAIN_A,
            policy_domain: DOMAIN_A,
            budget_owner_domain: DOMAIN_A,
            encryption_domain: DOMAIN_A,
            allowed_domain_classes: trust_domain_role_allowed_domain_floor(role),
            min_trust_epoch: 7,
            max_evidence_age_ms: 100,
        }
    }

    fn all_allowed_domain_classes() -> TrustAllowedDomainMask {
        TrustAllowedDomainMask::SAME_ADMIN
            .union(TrustAllowedDomainMask::SAME_SECURITY)
            .union(TrustAllowedDomainMask::SAME_TENANT)
            .union(TrustAllowedDomainMask::SAME_POLICY)
            .union(TrustAllowedDomainMask::SAME_JURISDICTION)
            .union(TrustAllowedDomainMask::GEO_ALLOWED)
            .union(TrustAllowedDomainMask::INTERNET_ALLOWED)
            .union(TrustAllowedDomainMask::OPERATOR_DEFINED)
    }

    fn full_trust_record_for_role(role: StorageIntentTrustRole) -> TrustEvidenceRecord {
        let reference = trust_ref(170_u8 + role.to_discriminant());
        TrustEvidenceRecord {
            state: TrustEvidenceState {
                flags: trust_domain_role_required_flags(role),
                session_security: trust_domain_role_min_session_security(role),
                key_epoch: 9,
                admin_domain: DOMAIN_A,
                security_domain: DOMAIN_A,
                tenant_domain: DOMAIN_A,
                residency: trust_role_residency(role),
                sharing_domain: SharingDomainClass::PrivateDataset,
                compromise_state: CompromiseState::Clear,
                quarantine_state: QuarantineState::Clear,
            },
            principal_ref: reference,
            peer_identity_ref: reference,
            admin_domain_ref: reference,
            security_domain_ref: reference,
            tenant_domain_ref: reference,
            dataset_domain: DOMAIN_A,
            dataset_domain_ref: reference,
            policy_domain: DOMAIN_A,
            policy_domain_ref: reference,
            budget_owner_domain: DOMAIN_A,
            budget_owner_domain_ref: reference,
            encryption_domain: DOMAIN_A,
            encryption_domain_ref: reference,
            session_security_ref: reference,
            key_epoch_ref: reference,
            key_lifecycle: TrustKeyLifecycleState::Active,
            key_lifecycle_ref: reference,
            key_lease_ref: reference,
            authorization_ref: reference,
            audit_ref: reference,
            residency_ref: reference,
            sharing_domain_ref: reference,
            sharing_compatibility: DedupSharingCompatibilityState::Compatible,
            sharing_compatibility_ref: reference,
            allowed_domain_classes: all_allowed_domain_classes(),
            regulatory_domain_ref: reference,
            operator_allowed_domain_ref: reference,
            trust_epoch: 7,
            trust_epoch_ref: reference,
            evidence_age_ms: 10,
            freshness_state: TrustEvidenceFreshnessState::Fresh,
            freshness_ref: reference,
            revocation_state: TrustRevocationState::Clear,
            revocation_ref: reference,
            compromise_ref: reference,
            quarantine_ref: reference,
            refusal_ref: reference,
        }
    }

    fn freshness_row(
        kind: StorageIntentEvidenceKind,
        state: EvidenceFamilyFreshnessState,
        byte: u8,
    ) -> EvidenceFamilyFreshness {
        EvidenceFamilyFreshness {
            kind,
            state,
            source_index_generation: u64::from(byte),
            producer_generation: u64::from(byte),
            freshness_frontier_ms: 10_000 + u64::from(byte),
            allowed_staleness_ms: 100,
            evidence_ref: evidence_ref(kind, byte),
        }
    }

    fn base_query_snapshot(
        consumer: EvidenceConsumerClass,
        context: EvidenceQueryContextClass,
    ) -> StorageIntentEvidenceQuerySnapshot {
        StorageIntentEvidenceQuerySnapshot {
            snapshot_id: StorageIntentEvidenceId([40_u8; 32]),
            query_id: StorageIntentEvidenceId([41_u8; 32]),
            consumer,
            context,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::Dataset,
                object_scope: StorageIntentObjectScope {
                    dataset_id: DOMAIN_A,
                    object_id: StorageIntentEvidenceId([42_u8; 32]),
                    range_start: 0,
                    range_len: 4096,
                    generation: 7,
                },
                pool_id: StorageIntentDomainId([43_u8; 16]),
                domain_id: DOMAIN_A,
                request_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 44),
                action_ref: evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 45),
                validation_ref: evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, 46),
            },
            policy_id: StorageIntentPolicyId([47_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(8),
            temporal_frontier_ms: 20_000,
            freshness_frontier_ms: 20_000,
            allowed_staleness_ms: 100,
            source_catalog_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                48,
            ),
            source_index_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 49),
            source_index_generation: 10,
            producer_generation: 11,
            producer_watermark_ms: 19_999,
            compaction_generation: 12,
            redaction_generation: 13,
            completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
            retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 50),
            ..StorageIntentEvidenceQuerySnapshot::default()
        }
    }

    fn snapshot_with_fresh_media(
        consumer: EvidenceConsumerClass,
        context: EvidenceQueryContextClass,
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot = base_query_snapshot(consumer, context);
        push_family_freshness(
            &mut snapshot,
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            51,
        );
        snapshot
    }

    fn push_family_freshness(
        snapshot: &mut StorageIntentEvidenceQuerySnapshot,
        kind: StorageIntentEvidenceKind,
        state: EvidenceFamilyFreshnessState,
        byte: u8,
    ) {
        snapshot
            .included_refs
            .push(evidence_ref(kind, byte))
            .unwrap();
        snapshot
            .family_freshness
            .push(freshness_row(kind, state, byte))
            .unwrap();
    }

    fn snapshot_with_prefetch_basis(
        consumer: EvidenceConsumerClass,
        service_objective_state: EvidenceFamilyFreshnessState,
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot =
            base_query_snapshot(consumer, EvidenceQueryContextClass::PrefetchResidency);
        let families = [
            (
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                service_objective_state,
            ),
            (
                StorageIntentEvidenceKind::WorkloadEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::TrustDomainEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::TransportPathEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::TemporalEvidence,
                EvidenceFamilyFreshnessState::Fresh,
            ),
            (
                StorageIntentEvidenceKind::MediaCostWearLedger,
                EvidenceFamilyFreshnessState::Fresh,
            ),
        ];

        for (offset, (kind, state)) in families.into_iter().enumerate() {
            push_family_freshness(&mut snapshot, kind, state, 70 + offset as u8);
        }
        snapshot
    }

    fn measurement_metric(
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
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, byte),
        }
    }

    fn measurement_metrics(include_payback_deltas: bool) -> StorageIntentMeasurementMetricSet {
        let mut metrics = StorageIntentMeasurementMetricSet::EMPTY;
        metrics
            .push(measurement_metric(
                StorageIntentMeasurementMetricDimension::Latency,
                StorageIntentMeasurementMetricUnit::Microseconds,
                101,
            ))
            .unwrap();
        metrics
            .push(measurement_metric(
                StorageIntentMeasurementMetricDimension::Throughput,
                StorageIntentMeasurementMetricUnit::BytesPerSecond,
                102,
            ))
            .unwrap();

        if include_payback_deltas {
            metrics
                .push(measurement_metric(
                    StorageIntentMeasurementMetricDimension::PaybackWindow,
                    StorageIntentMeasurementMetricUnit::Milliseconds,
                    103,
                ))
                .unwrap();
            metrics
                .push(measurement_metric(
                    StorageIntentMeasurementMetricDimension::MediaWriteBytes,
                    StorageIntentMeasurementMetricUnit::Bytes,
                    104,
                ))
                .unwrap();
            metrics
                .push(measurement_metric(
                    StorageIntentMeasurementMetricDimension::ForegroundHarm,
                    StorageIntentMeasurementMetricUnit::UnitlessPpm,
                    105,
                ))
                .unwrap();
        }
        metrics
    }

    fn all_authority_measurement_uses() -> StorageIntentMeasurementAttributionUseMask {
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

    fn measurement_source_refs() -> StorageIntentEvidenceRefs {
        let mut refs = StorageIntentEvidenceRefs::EMPTY;
        refs.push(evidence_ref(
            StorageIntentEvidenceKind::ValidationArtifact,
            106,
        ))
        .unwrap();
        refs.push(evidence_ref(
            StorageIntentEvidenceKind::TemporalEvidence,
            107,
        ))
        .unwrap();
        refs
    }

    fn shaping_refs() -> StorageIntentEvidenceRefs {
        let mut refs = StorageIntentEvidenceRefs::EMPTY;
        refs.push(evidence_ref(
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
            108,
        ))
        .unwrap();
        refs.push(evidence_ref(
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            109,
        ))
        .unwrap();
        refs
    }

    fn measurement_attribution() -> StorageIntentMeasurementAttributionEvidence {
        StorageIntentMeasurementAttributionEvidence {
            evidence_ref: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                110,
            ),
            measurement_id: StorageIntentEvidenceId([111_u8; 32]),
            tenant_id: DOMAIN_A,
            budget_owner_id: DOMAIN_A,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::ObjectRange,
                object_scope: StorageIntentObjectScope {
                    dataset_id: DOMAIN_A,
                    object_id: StorageIntentEvidenceId([112_u8; 32]),
                    range_start: 4096,
                    range_len: 131_072,
                    generation: 3,
                },
                pool_id: StorageIntentDomainId([113_u8; 16]),
                domain_id: DOMAIN_A,
                request_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 114),
                action_ref: evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 115),
                validation_ref: evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, 116),
            },
            policy_id: StorageIntentPolicyId([117_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(12),
            observation_generation: 13,
            producer_component_ref: evidence_ref(
                StorageIntentEvidenceKind::ValidationArtifact,
                118,
            ),
            producer_version: 14,
            workload_envelope_ref: evidence_ref(StorageIntentEvidenceKind::WorkloadEvidence, 119),
            workload_scope_ref: evidence_ref(StorageIntentEvidenceKind::WorkloadEvidence, 120),
            environment_profile_ref: evidence_ref(
                StorageIntentEvidenceKind::TransportPathEvidence,
                121,
            ),
            noise_policy_ref: evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, 122),
            service_objective_ref: evidence_ref(
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                123,
            ),
            sample_window: StorageIntentMeasurementSampleWindow {
                temporal_window_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 124),
                warmup_ms: 5_000,
                sample_window_ms: 60_000,
                sample_mass: 512,
                censored_sample_count: 2,
                dropped_sample_count: 1,
                variance_ppm: 5_000,
                confidence_bound_ppm: 20_000,
                censor_drop_policy_ref: evidence_ref(
                    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                    125,
                ),
            },
            measurement_source_refs: measurement_source_refs(),
            evidence_query_snapshot_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                126,
            ),
            decision_frontier_ref: evidence_ref(
                StorageIntentEvidenceKind::DecisionFrontierEvidence,
                127,
            ),
            action_execution_ref: evidence_ref(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                128,
            ),
            admission_ref: evidence_ref(StorageIntentEvidenceKind::SchedulerAdmissionRecord, 129),
            scheduler_ref: evidence_ref(StorageIntentEvidenceKind::SchedulerAdmissionRecord, 130),
            isolation_ref: evidence_ref(StorageIntentEvidenceKind::TenantIsolationEvidence, 131),
            capacity_ref: evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, 132),
            source_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 133),
            target_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 134),
            trust_domain_ref: evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 135),
            transport_path_ref: evidence_ref(StorageIntentEvidenceKind::TransportPathEvidence, 136),
            recovery_ref: evidence_ref(StorageIntentEvidenceKind::RecoveryDegradationEvidence, 137),
            rollout_ref: evidence_ref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 138),
            layout_ref: evidence_ref(StorageIntentEvidenceKind::LayoutAllocatorEvidence, 139),
            lifecycle_ref: evidence_ref(
                StorageIntentEvidenceKind::LifecycleGenerationEvidence,
                140,
            ),
            shaping_refs: shaping_refs(),
            comparator: StorageIntentMeasurementComparatorLineage {
                baseline_class: StorageIntentMeasurementBaselineClass::PriorAdmittedVariant,
                baseline_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 141),
                comparator_ref: evidence_ref(StorageIntentEvidenceKind::ComparatorEvidence, 142),
                counterfactual_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    143,
                ),
                prior_admitted_variant_ref: evidence_ref(
                    StorageIntentEvidenceKind::PlacementReceipt,
                    144,
                ),
                shadow_target_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    145,
                ),
                baseline_generation: 15,
                no_valid_baseline_refusal: StorageIntentRefusalReason::None,
            },
            metrics: measurement_metrics(true),
            verdict: StorageIntentMeasurementAttributionVerdict::Attributable,
            bounded_uncertainty_ppm: 0,
            allowed_uses: all_authority_measurement_uses(),
            allowed_use_ref: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                146,
            ),
            transfer_scope: StorageIntentMeasurementTransferScopeMask::EXACT_AUTHORITY_SCOPE,
            transfer_scope_ref: evidence_ref(
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                147,
            ),
            attribution_verdict_ref: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                148,
            ),
            retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 149),
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn decision_candidate_id(byte: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([byte; 32])
    }

    fn known_decision_score(
        dimension: StorageIntentDecisionScoreDimension,
        byte: u8,
    ) -> StorageIntentDecisionScoreEntry {
        StorageIntentDecisionScoreEntry {
            dimension,
            state: StorageIntentDecisionScoreState::Known,
            unit: StorageIntentDecisionScoreUnit::UnitlessPpm,
            value: i64::from(byte) * 100,
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::DecisionFrontierEvidence, byte),
        }
    }

    fn decision_score_vector(unknown_media_cost: bool) -> StorageIntentDecisionScoreVector {
        let mut vector = StorageIntentDecisionScoreVector::EMPTY;
        let dimensions = [
            (StorageIntentDecisionScoreDimension::Latency, 180),
            (StorageIntentDecisionScoreDimension::Tail, 181),
            (StorageIntentDecisionScoreDimension::Throughput, 182),
            (StorageIntentDecisionScoreDimension::MediaWriteCost, 183),
            (StorageIntentDecisionScoreDimension::CapacityCost, 184),
            (StorageIntentDecisionScoreDimension::RecoveryRpoRisk, 185),
            (StorageIntentDecisionScoreDimension::PaybackRisk, 186),
        ];

        for (dimension, byte) in dimensions {
            let mut entry = known_decision_score(dimension, byte);
            if unknown_media_cost
                && matches!(
                    dimension,
                    StorageIntentDecisionScoreDimension::MediaWriteCost
                )
            {
                entry.state = StorageIntentDecisionScoreState::UnknownCost;
            }
            vector.push(entry).unwrap();
        }
        vector
    }

    fn decision_candidate(
        byte: u8,
        status: StorageIntentDecisionCandidateStatus,
        scored: bool,
    ) -> StorageIntentDecisionCandidateRecord {
        StorageIntentDecisionCandidateRecord {
            candidate_id: decision_candidate_id(byte),
            candidate_class: StorageIntentDecisionCandidateClass::PlacementPlan,
            action_class: StorageIntentActionClass::DurablePlacementMovement,
            status,
            deterministic_order_key: u64::from(byte),
            tie_breaker_input: u64::from(byte) * 10,
            input_evidence_refs: {
                let mut refs = StorageIntentEvidenceRefs::EMPTY;
                refs.push(evidence_ref(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    byte,
                ))
                .unwrap();
                refs
            },
            hard_gate_ref: evidence_ref(StorageIntentEvidenceKind::DecisionFrontierEvidence, byte),
            score_vector_ref: if scored {
                evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    120 + byte,
                )
            } else {
                StorageIntentEvidenceRef::default()
            },
            rejection_refusal: if status.may_reach_scoring() {
                StorageIntentRefusalReason::None
            } else {
                StorageIntentRefusalReason::EvidenceNotUsable
            },
        }
    }

    fn decision_candidate_set() -> StorageIntentDecisionCandidateSet {
        let mut candidates = StorageIntentDecisionCandidateSet {
            candidate_set_digest: decision_candidate_id(199),
            ..StorageIntentDecisionCandidateSet::EMPTY
        };
        candidates
            .push(decision_candidate(
                1,
                StorageIntentDecisionCandidateStatus::Legal,
                true,
            ))
            .unwrap();
        candidates
            .push(decision_candidate(
                2,
                StorageIntentDecisionCandidateStatus::Illegal,
                false,
            ))
            .unwrap();
        candidates
    }

    fn decision_hard_gates() -> StorageIntentDecisionHardGateResultSet {
        let mut gates = StorageIntentDecisionHardGateResultSet::EMPTY;
        gates
            .push(StorageIntentDecisionHardGateResult {
                candidate_id: decision_candidate_id(1),
                gate: StorageIntentDecisionHardGateKind::Guarantee,
                verdict: StorageIntentDecisionHardGateVerdict::Passed,
                refusal: StorageIntentRefusalReason::None,
                evidence_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    131,
                ),
            })
            .unwrap();
        gates
            .push(StorageIntentDecisionHardGateResult {
                candidate_id: decision_candidate_id(2),
                gate: StorageIntentDecisionHardGateKind::MediaCapability,
                verdict: StorageIntentDecisionHardGateVerdict::Failed,
                refusal: StorageIntentRefusalReason::MissingMediaCapabilityEvidence,
                evidence_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    132,
                ),
            })
            .unwrap();
        gates
    }

    fn decision_payback_anchor(
        frontier_ref: StorageIntentEvidenceRef,
    ) -> StorageIntentDecisionCounterfactualPaybackRecord {
        StorageIntentDecisionCounterfactualPaybackRecord {
            decision_frontier_ref: frontier_ref,
            baseline_candidate_id: decision_candidate_id(2),
            expected_payback_window_ms: 60_000,
            expected_harm_ceiling_ppm: 10_000,
            outcome_attachment_ref: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                140,
            ),
            failed_payback_ref: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                141,
            ),
            harm_attachment_ref: StorageIntentEvidenceRef::default(),
            cooldown_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 142),
            retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 143),
        }
    }

    fn decision_frontier() -> StorageIntentDecisionEvidence {
        let frontier_ref = evidence_ref(StorageIntentEvidenceKind::DecisionFrontierEvidence, 200);
        StorageIntentDecisionEvidence {
            evidence_ref: frontier_ref,
            decision_id: decision_candidate_id(201),
            action_class: StorageIntentActionClass::DurablePlacementMovement,
            subject_scope: StorageIntentObjectScope {
                dataset_id: DOMAIN_A,
                object_id: decision_candidate_id(202),
                range_start: 0,
                range_len: 4096,
                generation: 1,
            },
            policy_id: StorageIntentPolicyId([203_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(9),
            actor_component_ref: evidence_ref(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                204,
            ),
            actor_version: 1,
            decision_epoch: 44,
            temporal_evidence_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 205),
            evidence_query_snapshot_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                206,
            ),
            authority_mode: StorageIntentDecisionAuthorityMode::Live,
            candidates: decision_candidate_set(),
            hard_gates: decision_hard_gates(),
            score_vector: decision_score_vector(false),
            selected_candidate: StorageIntentDecisionSelectionRecord {
                selected_plan_id: decision_candidate_id(1),
                reason: StorageIntentDecisionSelectionReason::HighestScore,
                tie_breaker: StorageIntentDecisionTieBreakerClass::None,
                tie_breaker_input: 0,
                state: StorageIntentDecisionSelectedState::Admitted,
                reserve_ref: evidence_ref(
                    StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                    207,
                ),
                admission_ref: evidence_ref(
                    StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                    208,
                ),
                rollback_proof_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    209,
                ),
                no_cutover_proof_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    210,
                ),
                refusal: StorageIntentRefusalReason::None,
            },
            counterfactual_payback: decision_payback_anchor(frontier_ref),
            retention_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 211),
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn durable_policy() -> StorageIntentPolicy {
        StorageIntentPolicy {
            requested_guarantee: StorageIntentGuaranteeClass::LocalIntent,
            required_failure_domains: FailureDomainMask::LOCAL,
            max_proximity: ProximityClass::LocalMedia,
            durability: DurabilityRequirement::DURABLE_INTENT_ZERO_LAG,
            ..StorageIntentPolicy::default()
        }
    }

    fn durable_receipt() -> StorageIntentReceipt {
        StorageIntentReceipt {
            ack_class: StorageIntentGuaranteeClass::LocalIntent,
            failure_domains: FailureDomainMask::LOCAL,
            proximity: ProximityClass::LocalMedia,
            durability: DurabilityReceiptState {
                state: DurabilityState::DurableIntent,
                observed_lag_ms: 0,
                lag_known: true,
            },
            media_role: StorageMediaRole::SyncIntent,
            media_class: StorageMediaClass::NvmeFlash,
            ..StorageIntentReceipt::default()
        }
    }

    fn ordering_flags() -> StorageIntentOrderingFlags {
        StorageIntentOrderingFlags::AUTHORITY_MINIMUM
            .union(StorageIntentOrderingFlags::NAMESPACE_COMPLETE)
            .union(StorageIntentOrderingFlags::METADATA_DELTA_COMPLETE)
            .union(StorageIntentOrderingFlags::QUORUM_SATISFIED)
    }

    fn ordering_flags_without(flag: StorageIntentOrderingFlags) -> StorageIntentOrderingFlags {
        StorageIntentOrderingFlags(ordering_flags().0 & !flag.0)
    }

    fn ordering_scope() -> StorageIntentObjectScope {
        StorageIntentObjectScope {
            dataset_id: DOMAIN_A,
            object_id: StorageIntentEvidenceId([31_u8; 32]),
            range_start: 4096,
            range_len: 8192,
            generation: 4,
        }
    }

    fn ordering_dependency() -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::MetadataNamespaceEvidence, 116)
    }

    fn ordering_requirement() -> StorageIntentOrderingRequirement {
        let mut dependency_refs = StorageIntentEvidenceRefs::EMPTY;
        dependency_refs.push(ordering_dependency()).unwrap();

        StorageIntentOrderingRequirement {
            policy_id: StorageIntentPolicyId([111_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(12),
            operation_scope: StorageIntentOrderingOperationScope::FileFsync,
            object_scope: ordering_scope(),
            committed_root_id: StorageIntentEvidenceId([112_u8; 32]),
            min_dirty_epoch: 10,
            min_barrier_sequence: 20,
            min_intent_log_sequence: 30,
            required_quorum: 2,
            required_flags: ordering_flags(),
            dependency_refs,
        }
    }

    fn ordering_evidence() -> StorageIntentOrderingEvidence {
        let mut dependency_refs = StorageIntentEvidenceRefs::EMPTY;
        dependency_refs.push(ordering_dependency()).unwrap();

        StorageIntentOrderingEvidence {
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, 110),
            policy_id: StorageIntentPolicyId([111_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(12),
            operation_scope: StorageIntentOrderingOperationScope::FileFsync,
            object_scope: ordering_scope(),
            dirty_epoch: 10,
            barrier_sequence: 20,
            intent_log_sequence: 30,
            replay_idempotency_key: StorageIntentReplayIdempotencyKey([117_u8; 16]),
            committed_root_id: StorageIntentEvidenceId([112_u8; 32]),
            committed_root_generation: 2,
            publication_sequence: 40,
            proved_quorum: 2,
            required_quorum: 2,
            aggregation: StorageIntentOrderingAggregationClass::Single,
            completion: StorageIntentOrderingCompletionState::Satisfied,
            flags: ordering_flags(),
            dependency_refs,
            local_intent_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 113),
            committed_root_ref: evidence_ref(StorageIntentEvidenceKind::LocalIntentRecord, 114),
            publication_ref: evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 115),
            namespace_ref: ordering_dependency(),
            metadata_delta_ref: evidence_ref(
                StorageIntentEvidenceKind::MetadataNamespaceEvidence,
                118,
            ),
            writeback_error_ref: evidence_ref(
                StorageIntentEvidenceKind::ResultRefusalEvidence,
                119,
            ),
            quorum_ref: evidence_ref(StorageIntentEvidenceKind::MembershipEvidence, 120),
            placement_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 121),
            prediction_ref: evidence_ref(StorageIntentEvidenceKind::PredictionEvidence, 122),
            replay_obligation_ref: StorageIntentEvidenceRef::default(),
            convergence_ref: StorageIntentEvidenceRef::default(),
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn action_execution_flags() -> StorageIntentActionExecutionFlags {
        StorageIntentActionExecutionFlags::ACTION_IDENTITY
            .union(StorageIntentActionExecutionFlags::DECISION_FRONTIER_REF)
            .union(StorageIntentActionExecutionFlags::HARD_GATE_REF)
            .union(StorageIntentActionExecutionFlags::SELECTED_CANDIDATE_REF)
            .union(StorageIntentActionExecutionFlags::COUNTERFACTUAL_PAYBACK_REF)
            .union(StorageIntentActionExecutionFlags::RESERVE_ADMISSION_REF)
            .union(StorageIntentActionExecutionFlags::ISOLATION_REF)
            .union(StorageIntentActionExecutionFlags::MEDIA_CAPABILITY_REF)
            .union(StorageIntentActionExecutionFlags::RETENTION_REF)
            .union(StorageIntentActionExecutionFlags::IDEMPOTENCY_KEY)
            .union(StorageIntentActionExecutionFlags::STEP_SEQUENCE)
            .union(StorageIntentActionExecutionFlags::CRASH_RECOVERY_MARKER)
            .union(StorageIntentActionExecutionFlags::DUPLICATE_SUPPRESSION)
            .union(StorageIntentActionExecutionFlags::SOURCE_RECEIPTS)
            .union(StorageIntentActionExecutionFlags::ROLLBACK_SOURCES_RETAINED)
            .union(StorageIntentActionExecutionFlags::READ_SERVING_ELIGIBILITY)
            .union(StorageIntentActionExecutionFlags::FORBID_SOURCE_RETIREMENT_UNTIL_COMPLETE)
            .union(StorageIntentActionExecutionFlags::TARGET_RECEIPT_CANDIDATE)
            .union(StorageIntentActionExecutionFlags::TARGET_DIGEST_INTEGRITY)
            .union(StorageIntentActionExecutionFlags::MEDIA_FLUSH_BARRIER)
            .union(StorageIntentActionExecutionFlags::RECONSTRUCTION_WIDTH)
            .union(StorageIntentActionExecutionFlags::REPLACEMENT_PUBLICATION)
            .union(StorageIntentActionExecutionFlags::PUBLICATION_ORDERING)
            .union(StorageIntentActionExecutionFlags::RECOVERY_DEGRADATION_REF)
            .union(StorageIntentActionExecutionFlags::POLICY_ROLLOUT_REF)
            .union(StorageIntentActionExecutionFlags::VISIBLE_CONVERGING_STATE)
            .union(StorageIntentActionExecutionFlags::OPERATOR_EXPLANATION_REF)
            .union(StorageIntentActionExecutionFlags::ABORT_REASON)
            .union(StorageIntentActionExecutionFlags::PARTIAL_TARGET_CLEANUP)
            .union(StorageIntentActionExecutionFlags::ROLLBACK_COMPLETION)
            .union(StorageIntentActionExecutionFlags::NO_CUTOVER_PROOF)
            .union(StorageIntentActionExecutionFlags::BUDGET_ACCOUNTING)
            .union(StorageIntentActionExecutionFlags::PAYBACK_ATTACHMENT)
            .union(StorageIntentActionExecutionFlags::COOLDOWN_DEPENDENCY)
            .union(StorageIntentActionExecutionFlags::ACTION_COMPLETION_PROOF)
    }

    fn action_execution_evidence(
        step_state: StorageIntentActionExecutionStepState,
    ) -> StorageIntentActionExecutionEvidence {
        let decision = decision_frontier();

        StorageIntentActionExecutionEvidence {
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 220),
            action_id: StorageIntentEvidenceId([221_u8; 32]),
            subject_scope: decision.subject_scope,
            action_class: decision.action_class,
            producer_component_ref: evidence_ref(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                222,
            ),
            producer_version: 1,
            policy_id: decision.policy_id,
            policy_revision: decision.policy_revision,
            execution_epoch: 44,
            temporal_ref: evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 223),
            integrity_ref: evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, 224),
            evidence_query_snapshot_ref: evidence_ref(
                StorageIntentEvidenceKind::EvidenceQuerySnapshot,
                225,
            ),
            admission_refs: StorageIntentActionExecutionAdmissionRefs {
                decision_frontier_ref: decision.evidence_ref,
                hard_gate_result_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    226,
                ),
                selected_candidate_ref: evidence_ref(
                    StorageIntentEvidenceKind::DecisionFrontierEvidence,
                    227,
                ),
                counterfactual_payback_ref: evidence_ref(
                    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                    228,
                ),
                reserve_admission_ref: evidence_ref(
                    StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                    229,
                ),
                scheduler_admission_ref: evidence_ref(
                    StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                    230,
                ),
                tenant_isolation_ref: evidence_ref(
                    StorageIntentEvidenceKind::TenantIsolationEvidence,
                    231,
                ),
                media_capability_ref: evidence_ref(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    232,
                ),
                evidence_retention_ref: evidence_ref(
                    StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                    233,
                ),
            },
            step_state,
            replay: StorageIntentActionExecutionReplayRecord {
                idempotency_key: StorageIntentReplayIdempotencyKey([234_u8; 16]),
                step_sequence: 1,
                retry_generation: 0,
                state: StorageIntentActionReplayState::FirstAttempt,
                crash_recovery_marker_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    235,
                ),
                duplicate_suppression_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    236,
                ),
                replay_refusal_ref: StorageIntentEvidenceRef::default(),
            },
            source_protection: StorageIntentActionSourceProtectionRecord {
                source_receipts_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 237),
                old_placement_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 238),
                old_placement_generation: 7,
                retained_rollback_sources_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    239,
                ),
                retained_rollback_source_count: 1,
                read_serving_eligibility_ref: evidence_ref(
                    StorageIntentEvidenceKind::ReadFreshnessEvidence,
                    240,
                ),
                read_serving_eligible: true,
                retirement_state: StorageIntentSourceRetirementState::Ready,
            },
            target_verification: StorageIntentActionTargetVerificationRecord {
                state: StorageIntentActionTargetVerificationState::Verified,
                target_receipt_candidate_ref: evidence_ref(
                    StorageIntentEvidenceKind::PlacementReceipt,
                    241,
                ),
                digest_integrity_ref: evidence_ref(
                    StorageIntentEvidenceKind::DataShapeEvidence,
                    242,
                ),
                media_flush_barrier_ref: evidence_ref(
                    StorageIntentEvidenceKind::OrderingEvidence,
                    243,
                ),
                reconstruction_width: 3,
                required_reconstruction_width: 2,
                target_bytes: 4096,
                verified_bytes: 4096,
            },
            publication: StorageIntentActionPublicationBoundaryRecord {
                state: StorageIntentActionPublicationState::ReplacementPublished,
                replacement_receipt_ref: evidence_ref(
                    StorageIntentEvidenceKind::PlacementReceipt,
                    244,
                ),
                ordering_evidence_ref: evidence_ref(
                    StorageIntentEvidenceKind::OrderingEvidence,
                    245,
                ),
                recovery_degradation_ref: evidence_ref(
                    StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                    246,
                ),
                policy_rollout_ref: evidence_ref(
                    StorageIntentEvidenceKind::PolicyRolloutEvidence,
                    247,
                ),
                visible_state_ref: evidence_ref(
                    StorageIntentEvidenceKind::ResultRefusalEvidence,
                    248,
                ),
                operator_explanation_ref: evidence_ref(
                    StorageIntentEvidenceKind::OperatorExplanationProjection,
                    249,
                ),
                publication_sequence: 1,
            },
            abort_rollback: StorageIntentActionAbortRollbackRecord {
                abort_reason: StorageIntentActionExecutionRefusalReason::RefusedByActionEvidence,
                partial_target_cleanup_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    250,
                ),
                retained_proof_ref: evidence_ref(
                    StorageIntentEvidenceKind::EvidenceRetentionEvidence,
                    251,
                ),
                rollback_completion_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    252,
                ),
                no_cutover_proof_ref: evidence_ref(
                    StorageIntentEvidenceKind::ActionExecutionEvidence,
                    253,
                ),
                cutover_published: false,
            },
            budget: StorageIntentActionBudgetOutcomeRecord {
                work_bytes: 4096,
                foreground_disruption_us: 10,
                media_write_bytes: 8192,
                network_egress_bytes: 0,
                reserve_consumed_bytes: 4096,
                reserve_budget_bytes: 8192,
                reserve_generation: 1,
                outcome_attachment_ref: evidence_ref(
                    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                    254,
                ),
                payback_ref: evidence_ref(
                    StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                    255,
                ),
                cooldown_dependency_ref: evidence_ref(
                    StorageIntentEvidenceKind::TemporalEvidence,
                    219,
                ),
            },
            action_completion_ref: evidence_ref(
                StorageIntentEvidenceKind::ActionExecutionEvidence,
                218,
            ),
            evidence_state: StorageIntentActionEvidenceState::Fresh,
            flags: action_execution_flags(),
            refusal: StorageIntentActionExecutionRefusalReason::None,
        }
    }

    fn media_evidence(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, byte)
    }

    fn durable_media_flags() -> MediaCapabilityFlags {
        MediaCapabilityFlags::STABLE_DEVICE_IDENTITY
            .union(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY)
            .union(MediaCapabilityFlags::POOL_MEMBER_BINDING)
            .union(MediaCapabilityFlags::FIRMWARE_CAPABILITY_GENERATION)
            .union(MediaCapabilityFlags::PERSISTENCE_DOMAIN)
            .union(MediaCapabilityFlags::FLUSH_FUA_ORDERING)
            .union(MediaCapabilityFlags::ATOMICITY_GRANULARITY)
            .union(MediaCapabilityFlags::PROTOCOL_GEOMETRY)
            .union(MediaCapabilityFlags::HEALTH)
            .union(MediaCapabilityFlags::FRESHNESS)
    }

    fn proven_nvme_capability() -> StorageIntentMediaCapabilityRecord {
        let evidence = media_evidence(9);
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::NvmeFlash,
            flags: durable_media_flags(),
            identity_generation: 1,
            namespace_generation: 2,
            firmware_generation: 3,
            settings_generation: 4,
            pool_member_generation: 5,
            persistence: MediaPersistenceDomain::OrdinaryPersistent,
            flush_ordering: MediaFlushOrderingClass::FlushAndFua,
            atomicity: MediaAtomicityClass::AtomicWriteUnit,
            geometry: MediaProtocolGeometryClass::RandomBlock,
            health: MediaHealthState::Healthy,
            freshness: MediaCapabilityFreshnessState::Fresh,
            remote_commit: MediaRemoteCommitSemantics::NotRemote,
            archive_restore: MediaArchiveRestoreSemantics::NotArchive,
            logical_block_bytes: 512,
            physical_block_bytes: 4096,
            atomic_write_unit_bytes: 4096,
            optimal_io_bytes: 131_072,
            max_queue_depth: 64,
            latency_class_us: 100,
            evidence,
            stable_identity_ref: evidence,
            namespace_identity_ref: evidence,
            persistence_ref: evidence,
            flush_ref: evidence,
            atomicity_ref: evidence,
            geometry_ref: evidence,
            health_ref: evidence,
            freshness_ref: evidence,
            remote_commit_ref: evidence,
            archive_restore_ref: evidence,
        }
    }

    #[test]
    fn ordering_evidence_satisfies_exact_barrier_requirement() {
        let result =
            ordering_evidence_satisfies_requirement(ordering_requirement(), ordering_evidence());

        assert!(result.satisfied);
        assert_eq!(result.refusal, StorageIntentRefusalReason::None);
        assert!(ordering_object_scope_covers(
            StorageIntentObjectScope {
                range_start: 0,
                range_len: 32 * 1024,
                ..ordering_scope()
            },
            ordering_scope(),
        ));
        assert_eq!(
            StorageIntentOrderingOperationScope::FileFsync.as_str(),
            "file-fsync"
        );
        assert_eq!(
            StorageIntentOrderingCompletionState::Retired.as_str(),
            "retired"
        );
    }

    #[test]
    fn ordering_evidence_covers_all_caller_visible_scopes() {
        let scopes = [
            (
                1,
                StorageIntentOrderingOperationScope::RangeWrite,
                "range-write",
            ),
            (
                2,
                StorageIntentOrderingOperationScope::FileFsync,
                "file-fsync",
            ),
            (
                3,
                StorageIntentOrderingOperationScope::FileFdatasync,
                "file-fdatasync",
            ),
            (
                4,
                StorageIntentOrderingOperationScope::DirectoryFsync,
                "directory-fsync",
            ),
            (
                5,
                StorageIntentOrderingOperationScope::ODsyncDataWrite,
                "odsync-data-write",
            ),
            (
                6,
                StorageIntentOrderingOperationScope::FuaBlockWrite,
                "fua-block-write",
            ),
            (
                7,
                StorageIntentOrderingOperationScope::MsyncSync,
                "msync-sync",
            ),
            (
                8,
                StorageIntentOrderingOperationScope::SyncfsDatasetBarrier,
                "syncfs-dataset-barrier",
            ),
            (
                9,
                StorageIntentOrderingOperationScope::LocalIntentReplay,
                "local-intent-replay",
            ),
            (
                10,
                StorageIntentOrderingOperationScope::QuorumIntentFanout,
                "quorum-intent-fanout",
            ),
            (
                11,
                StorageIntentOrderingOperationScope::RelocationCutover,
                "relocation-cutover",
            ),
            (12, StorageIntentOrderingOperationScope::Rebake, "rebake"),
            (13, StorageIntentOrderingOperationScope::Repair, "repair"),
            (
                14,
                StorageIntentOrderingOperationScope::ReceiptRetirement,
                "receipt-retirement",
            ),
        ];

        for (discriminant, scope, spelling) in scopes {
            assert_eq!(
                StorageIntentOrderingOperationScope::from_discriminant(discriminant),
                Some(scope)
            );
            assert_eq!(scope.as_str(), spelling);
        }
        assert_eq!(
            StorageIntentOrderingOperationScope::from_discriminant(99),
            None
        );
    }

    #[test]
    fn ordering_evidence_hard_gates_refuse_unsatisfied_contracts() {
        let requirement = ordering_requirement();

        assert_eq!(
            ordering_evidence_satisfies_requirement(
                requirement,
                StorageIntentOrderingEvidence::default(),
            )
            .refusal,
            StorageIntentRefusalReason::MissingOrderingEvidence
        );

        let cases = [
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(StorageIntentOrderingFlags::FRESH),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::StaleOrderingEvidence,
            ),
            (
                StorageIntentOrderingEvidence {
                    dirty_epoch: 9,
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::StaleOrderingEvidence,
            ),
            (
                StorageIntentOrderingEvidence {
                    operation_scope: StorageIntentOrderingOperationScope::DirectoryFsync,
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::WrongOrderingScope,
            ),
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(StorageIntentOrderingFlags::DIRTY_EPOCH_SEALED),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::UnsealedDirtyEpoch,
            ),
            (
                StorageIntentOrderingEvidence {
                    committed_root_id: StorageIntentEvidenceId([99_u8; 32]),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::WrongCommittedRoot,
            ),
            (
                StorageIntentOrderingEvidence {
                    object_scope: StorageIntentObjectScope {
                        range_start: 0,
                        range_len: 4096,
                        ..ordering_scope()
                    },
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::WrongOrderingRange,
            ),
            (
                StorageIntentOrderingEvidence {
                    replay_idempotency_key: StorageIntentReplayIdempotencyKey::ZERO,
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::NonIdempotentReplay,
            ),
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(StorageIntentOrderingFlags::NAMESPACE_COMPLETE),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::PartialNamespaceEvidence,
            ),
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(
                        StorageIntentOrderingFlags::METADATA_DELTA_COMPLETE,
                    ),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::IncompleteMetadataDelta,
            ),
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(
                        StorageIntentOrderingFlags::WRITEBACK_ERRORS_RECORDED,
                    ),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::LostWritebackError,
            ),
            (
                StorageIntentOrderingEvidence {
                    proved_quorum: 1,
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::UnderQuorum,
            ),
            (
                StorageIntentOrderingEvidence {
                    flags: ordering_flags_without(StorageIntentOrderingFlags::NOT_CONTRADICTORY),
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::ContradictoryOrderingEvidence,
            ),
            (
                StorageIntentOrderingEvidence {
                    dependency_refs: StorageIntentEvidenceRefs::EMPTY,
                    ..ordering_evidence()
                },
                StorageIntentRefusalReason::MissingOrderingDependency,
            ),
        ];

        for (evidence, refusal) in cases {
            assert_eq!(
                ordering_evidence_satisfies_requirement(requirement, evidence).refusal,
                refusal
            );
        }
    }

    #[test]
    fn ordering_aggregation_requires_preserved_barriers_or_obligation() {
        let pending = StorageIntentOrderingEvidence {
            aggregation: StorageIntentOrderingAggregationClass::Coalesced,
            completion: StorageIntentOrderingCompletionState::PendingConvergence,
            convergence_ref: evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 123),
            ..ordering_evidence()
        };

        assert!(ordering_evidence_aggregation_is_legal(pending));
        assert!(ordering_evidence_records_pending_obligation(pending));
        assert_eq!(
            ordering_evidence_satisfies_requirement(ordering_requirement(), pending).refusal,
            StorageIntentRefusalReason::PendingOrderingConvergence
        );

        let missing_obligation = StorageIntentOrderingEvidence {
            convergence_ref: StorageIntentEvidenceRef::default(),
            ..pending
        };
        assert!(!ordering_evidence_aggregation_is_legal(missing_obligation));

        let weakened_barrier = StorageIntentOrderingEvidence {
            aggregation: StorageIntentOrderingAggregationClass::Pipelined,
            flags: ordering_flags_without(StorageIntentOrderingFlags::BARRIER_PRESERVED),
            ..ordering_evidence()
        };
        assert_eq!(
            ordering_evidence_satisfies_requirement(ordering_requirement(), weakened_barrier)
                .refusal,
            StorageIntentRefusalReason::OrderingAggregationWouldWeaken
        );
    }

    #[test]
    fn placement_and_prediction_refs_do_not_substitute_for_ordering() {
        let placement_only = StorageIntentOrderingEvidence {
            evidence_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 124),
            placement_ref: evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, 125),
            ..ordering_evidence()
        };
        assert_eq!(
            ordering_evidence_satisfies_requirement(ordering_requirement(), placement_only).refusal,
            StorageIntentRefusalReason::MissingOrderingEvidence
        );

        let prediction_reordered = StorageIntentOrderingEvidence {
            flags: ordering_flags_without(StorageIntentOrderingFlags::PREDICTION_INDEPENDENT),
            prediction_ref: evidence_ref(StorageIntentEvidenceKind::PredictionEvidence, 126),
            ..ordering_evidence()
        };
        assert_eq!(
            ordering_evidence_satisfies_requirement(ordering_requirement(), prediction_reordered)
                .refusal,
            StorageIntentRefusalReason::OrderingAggregationWouldWeaken
        );
    }

    #[test]
    fn action_execution_requires_idempotent_replay_for_each_crash_step() {
        let steps = [
            StorageIntentActionExecutionStepState::Planned,
            StorageIntentActionExecutionStepState::Admitted,
            StorageIntentActionExecutionStepState::Prepared,
            StorageIntentActionExecutionStepState::Copying,
            StorageIntentActionExecutionStepState::Verifying,
            StorageIntentActionExecutionStepState::Publishing,
            StorageIntentActionExecutionStepState::Cutover,
            StorageIntentActionExecutionStepState::RetiringSource,
            StorageIntentActionExecutionStepState::Complete,
            StorageIntentActionExecutionStepState::Aborted,
            StorageIntentActionExecutionStepState::RolledBack,
            StorageIntentActionExecutionStepState::Refused,
        ];

        for step in steps {
            let mut evidence = action_execution_evidence(step);
            evidence.replay.crash_recovery_marker_ref = StorageIntentEvidenceRef::default();

            assert_eq!(
                evidence.action_refusal(),
                StorageIntentActionExecutionRefusalReason::NonIdempotentReplay,
                "step {} did not fail closed on missing crash marker",
                step.as_str()
            );
        }
    }

    #[test]
    fn action_execution_admission_flags_must_match_admission_refs() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::Admitted);
        evidence.flags = StorageIntentActionExecutionFlags(
            evidence.flags.0 & !StorageIntentActionExecutionFlags::HARD_GATE_REF.0,
        );

        assert!(evidence.admission_refs.has_required_refs());
        assert_eq!(
            evidence.action_refusal(),
            StorageIntentActionExecutionRefusalReason::MissingDecisionAdmissionEvidence
        );
    }

    #[test]
    fn duplicate_action_delivery_is_suppressed_not_reexecuted() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::Copying);
        evidence.replay.state = StorageIntentActionReplayState::DuplicateSuppressed;
        evidence.replay.replay_refusal_ref =
            evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 217);

        assert!(evidence.replay.duplicate_delivery_is_suppressed());
        assert_eq!(
            evidence.action_refusal(),
            StorageIntentActionExecutionRefusalReason::DuplicateActionDelivery
        );
        assert_eq!(
            action_execution_satisfies_completion(evidence).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn target_write_is_not_completion_without_verification_and_barrier() {
        let mut partial =
            action_execution_evidence(StorageIntentActionExecutionStepState::Verifying);
        partial.target_verification.state =
            StorageIntentActionTargetVerificationState::PartialWrite;
        partial.target_verification.verified_bytes = 2048;

        assert_eq!(
            partial.action_refusal(),
            StorageIntentActionExecutionRefusalReason::PartialTargetWrite
        );

        let mut missing_barrier =
            action_execution_evidence(StorageIntentActionExecutionStepState::Complete);
        missing_barrier.target_verification.media_flush_barrier_ref =
            StorageIntentEvidenceRef::default();

        assert_eq!(
            missing_barrier.action_refusal(),
            StorageIntentActionExecutionRefusalReason::TargetWriteIsNotCompletion
        );
        assert_eq!(
            action_execution_satisfies_completion(missing_barrier).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn stale_action_evidence_blocks_or_requires_revalidation() {
        let stale_states = [
            StorageIntentActionEvidenceState::DecisionFrontierStale,
            StorageIntentActionEvidenceState::PolicyRevisionChanged,
            StorageIntentActionEvidenceState::MediaCapabilityChanged,
            StorageIntentActionEvidenceState::CapacityReserveChanged,
            StorageIntentActionEvidenceState::MembershipChanged,
            StorageIntentActionEvidenceState::TrustChanged,
            StorageIntentActionEvidenceState::TemporalExpired,
            StorageIntentActionEvidenceState::EvidenceRetentionCompacted,
        ];

        for state in stale_states {
            let mut evidence =
                action_execution_evidence(StorageIntentActionExecutionStepState::Copying);
            evidence.evidence_state = state;

            assert_eq!(
                evidence.action_refusal(),
                StorageIntentActionExecutionRefusalReason::StaleExecutionEvidence,
                "state {} did not block stale execution",
                state.as_str()
            );
        }
    }

    #[test]
    fn reserve_exhaustion_mid_action_refuses_progress() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::Copying);
        evidence.budget.reserve_consumed_bytes = evidence.budget.reserve_budget_bytes + 1;

        assert_eq!(
            evidence.action_refusal(),
            StorageIntentActionExecutionRefusalReason::ReserveExhausted
        );
        assert_eq!(
            action_execution_satisfies_completion(evidence).refusal,
            StorageIntentRefusalReason::MovementDebtNotPaidBack
        );
    }

    #[test]
    fn rollback_before_publication_stays_visible_but_is_not_completion() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::RolledBack);
        evidence.source_protection.retirement_state =
            StorageIntentSourceRetirementState::RetainedForRollback;
        evidence.publication = StorageIntentActionPublicationBoundaryRecord::default();

        assert!(evidence.abort_rollback.is_visible_no_cutover());
        assert_eq!(
            evidence.action_refusal(),
            StorageIntentActionExecutionRefusalReason::None
        );
        assert_eq!(
            action_execution_satisfies_completion(evidence).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_eq!(
            evidence.source_retirement_refusal(),
            StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence
        );
    }

    #[test]
    fn crash_after_publication_can_resume_before_source_retirement() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::Complete);
        evidence.replay.state = StorageIntentActionReplayState::CrashRecovery;
        evidence.replay.retry_generation = 1;
        evidence.publication.state = StorageIntentActionPublicationState::ReplacementPublished;
        evidence.source_protection.retirement_state = StorageIntentSourceRetirementState::Ready;

        assert_eq!(
            evidence.action_refusal(),
            StorageIntentActionExecutionRefusalReason::None
        );
        assert!(action_execution_satisfies_completion(evidence).satisfied);
        assert!(action_execution_allows_source_retirement(evidence).satisfied);
    }

    #[test]
    fn source_retirement_refuses_without_action_completion_proof() {
        let mut evidence =
            action_execution_evidence(StorageIntentActionExecutionStepState::Complete);
        evidence.action_completion_ref = StorageIntentEvidenceRef::default();
        evidence.flags = StorageIntentActionExecutionFlags(
            evidence.flags.0 & !StorageIntentActionExecutionFlags::ACTION_COMPLETION_PROOF.0,
        );

        assert_eq!(
            evidence.source_retirement_refusal(),
            StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence
        );
        assert_eq!(
            action_execution_allows_source_retirement(evidence).refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn default_evidence_query_snapshot_fails_closed() {
        let snapshot = StorageIntentEvidenceQuerySnapshot::default();

        assert!(!snapshot.has_query_identity());
        assert!(!snapshot.has_policy_identity());
        assert_eq!(
            snapshot.completeness,
            EvidenceCompletenessVerdict::UnknownEvidence
        );
        assert_eq!(
            snapshot.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert!(!snapshot.is_authority_admissible());
        assert!(!snapshot.allows_non_authority_visibility());
    }

    #[test]
    fn authority_snapshot_requires_replay_anchor_and_complete_cut() {
        let snapshot = snapshot_with_fresh_media(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );

        assert!(snapshot.has_query_identity());
        assert!(snapshot.has_policy_identity());
        assert!(snapshot.has_subject_scope());
        assert!(snapshot.has_frontiers());
        assert!(snapshot.has_source_replay_anchor());
        assert!(snapshot.is_authority_admissible());
        assert!(snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));

        let mut missing_source = snapshot;
        missing_source.source_index_ref = StorageIntentEvidenceRef::default();
        assert_eq!(
            missing_source.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut missing_catalog = snapshot;
        missing_catalog.source_catalog_ref = StorageIntentEvidenceRef::default();
        assert_eq!(
            missing_catalog.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut missing_subject = snapshot;
        missing_subject.subject.scope_class = EvidenceQuerySubjectScopeClass::Unknown;
        assert_eq!(
            missing_subject.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut partial = snapshot;
        partial.completeness = EvidenceCompletenessVerdict::PartialAdmissible;
        assert_eq!(
            partial.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn cache_only_visibility_requires_explicit_partial_context() {
        let mut snapshot = base_query_snapshot(
            EvidenceConsumerClass::ReadPath,
            EvidenceQueryContextClass::CacheOnlyRead,
        );
        snapshot.completeness = EvidenceCompletenessVerdict::PartialAdmissible;

        assert!(snapshot.allows_non_authority_visibility());
        assert_eq!(
            snapshot.authority_refusal(),
            StorageIntentRefusalReason::None
        );

        let mut planner = snapshot;
        planner.consumer = EvidenceConsumerClass::Planner;
        planner.context = EvidenceQueryContextClass::PrefetchResidency;
        assert!(!planner.allows_non_authority_visibility());
        assert_eq!(
            planner.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn claim_gate_blocks_refused_unknown_and_unsafe_cuts() {
        let mut snapshot = snapshot_with_fresh_media(
            EvidenceConsumerClass::ClaimGate,
            EvidenceQueryContextClass::Claim,
        );

        assert!(snapshot.is_authority_admissible());

        snapshot.completeness = EvidenceCompletenessVerdict::Refused;
        assert_eq!(
            snapshot.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        snapshot.completeness = EvidenceCompletenessVerdict::UnsafeVisible;
        assert_eq!(
            snapshot.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        snapshot.completeness = EvidenceCompletenessVerdict::CompleteForPurpose;
        snapshot.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
        assert_eq!(
            snapshot.authority_refusal(),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn media_capability_must_be_fresh_inside_the_snapshot_cut() {
        let states = [
            EvidenceFamilyFreshnessState::Missing,
            EvidenceFamilyFreshnessState::Stale,
            EvidenceFamilyFreshnessState::Contradictory,
            EvidenceFamilyFreshnessState::Superseded,
            EvidenceFamilyFreshnessState::Redacted,
            EvidenceFamilyFreshnessState::Compacted,
            EvidenceFamilyFreshnessState::Unavailable,
            EvidenceFamilyFreshnessState::Refused,
        ];

        for (offset, state) in states.into_iter().enumerate() {
            let mut snapshot = base_query_snapshot(
                EvidenceConsumerClass::Planner,
                EvidenceQueryContextClass::PrefetchResidency,
            );
            let byte = 60 + offset as u8;
            snapshot
                .included_refs
                .push(evidence_ref(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    byte,
                ))
                .unwrap();
            snapshot
                .family_freshness
                .push(freshness_row(
                    StorageIntentEvidenceKind::MediaCapabilityEvidence,
                    state,
                    byte,
                ))
                .unwrap();

            assert!(snapshot.is_authority_admissible());
            assert!(!snapshot.has_fresh_media_capability());
            assert!(!snapshot.authorizes_fresh_evidence_kind(
                StorageIntentEvidenceKind::MediaCapabilityEvidence
            ));
        }
    }

    #[test]
    fn fresh_family_requires_bound_ref_inside_snapshot_cut() {
        let mut unbound = base_query_snapshot(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );
        let unbound_media_ref = StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::MediaCapabilityEvidence,
            id: StorageIntentEvidenceId::ZERO,
            generation: 61,
            version: 1,
        };
        unbound.included_refs.push(unbound_media_ref).unwrap();
        unbound
            .family_freshness
            .push(EvidenceFamilyFreshness {
                kind: StorageIntentEvidenceKind::MediaCapabilityEvidence,
                state: EvidenceFamilyFreshnessState::Fresh,
                source_index_generation: 61,
                producer_generation: 61,
                freshness_frontier_ms: 10_061,
                allowed_staleness_ms: 100,
                evidence_ref: unbound_media_ref,
            })
            .unwrap();

        assert!(unbound.contains_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
        assert!(!unbound
            .family_freshness
            .family_is_fresh_for_authority(StorageIntentEvidenceKind::MediaCapabilityEvidence));
        assert!(!unbound.has_fresh_media_capability());
        assert!(!unbound
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));

        let mut missing_included = base_query_snapshot(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );
        missing_included
            .family_freshness
            .push(freshness_row(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                EvidenceFamilyFreshnessState::Fresh,
                62,
            ))
            .unwrap();

        assert!(!missing_included.has_fresh_media_capability());
        assert!(!missing_included
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
    }

    #[test]
    fn fresh_family_ref_must_match_included_snapshot_ref() {
        let mut snapshot = base_query_snapshot(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );
        snapshot
            .included_refs
            .push(evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                63,
            ))
            .unwrap();
        snapshot
            .family_freshness
            .push(freshness_row(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                EvidenceFamilyFreshnessState::Fresh,
                64,
            ))
            .unwrap();

        assert!(snapshot.contains_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
        assert!(snapshot
            .family_freshness
            .family_is_fresh_for_authority(StorageIntentEvidenceKind::MediaCapabilityEvidence));
        assert!(!snapshot.has_fresh_media_capability());
        assert!(!snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));

        snapshot
            .included_refs
            .push(evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                64,
            ))
            .unwrap();

        assert!(snapshot.has_fresh_media_capability());
        assert!(snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
    }

    #[test]
    fn duplicate_family_freshness_rows_fail_closed() {
        let mut snapshot = snapshot_with_fresh_media(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );
        assert!(snapshot.has_fresh_media_capability());

        snapshot
            .family_freshness
            .push(freshness_row(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                EvidenceFamilyFreshnessState::Fresh,
                65,
            ))
            .unwrap();

        assert!(!snapshot
            .family_freshness
            .family_is_fresh_for_authority(StorageIntentEvidenceKind::MediaCapabilityEvidence));
        assert!(!snapshot.has_fresh_media_capability());
        assert!(!snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
    }

    #[test]
    fn service_objective_must_be_fresh_inside_the_snapshot_cut() {
        let mut snapshot = snapshot_with_prefetch_basis(
            EvidenceConsumerClass::Planner,
            EvidenceFamilyFreshnessState::Fresh,
        );

        assert!(snapshot.is_authority_admissible());
        assert!(snapshot.has_fresh_service_objective());
        assert!(snapshot.has_fresh_prefetch_residency_basis());
        assert!(snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::ServiceObjectiveEvidence));

        snapshot = snapshot_with_prefetch_basis(
            EvidenceConsumerClass::Planner,
            EvidenceFamilyFreshnessState::Stale,
        );
        assert!(snapshot.is_authority_admissible());
        assert!(!snapshot.has_fresh_service_objective());
        assert!(!snapshot.has_fresh_prefetch_residency_basis());
        assert!(!snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::ServiceObjectiveEvidence));
    }

    #[test]
    fn prefetch_feedback_requires_same_fresh_replayable_cut() {
        let mut snapshot = snapshot_with_prefetch_basis(
            EvidenceConsumerClass::MeasurementAttribution,
            EvidenceFamilyFreshnessState::Fresh,
        );

        assert!(snapshot.has_fresh_prefetch_residency_basis());
        assert!(!snapshot.authorizes_prefetch_residency_feedback());

        push_family_freshness(
            &mut snapshot,
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            90,
        );
        push_family_freshness(
            &mut snapshot,
            StorageIntentEvidenceKind::MeasurementAttributionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            91,
        );
        push_family_freshness(
            &mut snapshot,
            StorageIntentEvidenceKind::EvidenceRetentionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            92,
        );

        assert!(snapshot.authorizes_prefetch_residency_feedback());

        let mut stale_objective = snapshot_with_prefetch_basis(
            EvidenceConsumerClass::MeasurementAttribution,
            EvidenceFamilyFreshnessState::Stale,
        );
        push_family_freshness(
            &mut stale_objective,
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            93,
        );
        push_family_freshness(
            &mut stale_objective,
            StorageIntentEvidenceKind::MeasurementAttributionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            94,
        );
        push_family_freshness(
            &mut stale_objective,
            StorageIntentEvidenceKind::EvidenceRetentionEvidence,
            EvidenceFamilyFreshnessState::Fresh,
            95,
        );
        assert!(!stale_objective.has_fresh_prefetch_residency_basis());
        assert!(!stale_objective.authorizes_prefetch_residency_feedback());
    }

    #[test]
    fn measurement_attribution_with_full_lineage_can_close_payback() {
        let evidence = measurement_attribution();
        let requested = StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD
            .union(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK)
            .union(StorageIntentMeasurementAttributionUseMask::ADMIT_AUTHORITY_MOVEMENT);

        assert!(evidence.has_measurement_identity());
        assert!(evidence.has_measurement_basis());
        assert!(evidence.has_authority_lineage());
        assert!(evidence.has_shaping_evidence());
        assert!(evidence.metrics_support_payback_or_movement());
        assert!(evidence.authorizes_use(requested));
        assert_eq!(
            measurement_attribution_authorizes_use(evidence, requested),
            ReceiptPredicateResult::SATISFIED
        );
    }

    #[test]
    fn confounded_measurements_are_diagnostic_only() {
        let mut evidence = measurement_attribution();
        evidence.verdict = StorageIntentMeasurementAttributionVerdict::Confounded;
        evidence.allowed_uses = StorageIntentMeasurementAttributionUseMask::NON_AUTHORITY_SAFE;

        assert!(evidence.verdict.blocks_authority());
        assert!(evidence.hard_law_is_respected());
        assert!(evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::DIAGNOSE));
        assert!(evidence.authorizes_use(
            StorageIntentMeasurementAttributionUseMask::FORCE_CONSERVATIVE_COOLDOWN
        ));
        assert!(!evidence
            .authorizes_use(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD));
        assert!(!evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK));

        evidence.allowed_uses = evidence
            .allowed_uses
            .union(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK);
        assert!(!evidence.hard_law_is_respected());
        assert!(!evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::DIAGNOSE));
    }

    #[test]
    fn missing_or_refused_baseline_blocks_payback_and_claims() {
        let mut evidence = measurement_attribution();
        evidence.comparator = StorageIntentMeasurementComparatorLineage {
            baseline_class: StorageIntentMeasurementBaselineClass::NoValidBaselineRefused,
            no_valid_baseline_refusal: StorageIntentRefusalReason::EvidenceNotUsable,
            ..evidence.comparator
        };

        assert!(evidence.comparator.has_no_valid_baseline_refusal());
        assert!(!evidence.comparator.has_authority_baseline());
        assert!(evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::DIAGNOSE));
        assert!(!evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK));
        assert!(!evidence.authorizes_use(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PUBLIC_OR_COMPARATOR_CLAIM
        ));
    }

    #[test]
    fn cross_scope_training_requires_explicit_transfer_evidence() {
        let mut evidence = measurement_attribution();

        evidence.transfer_scope = StorageIntentMeasurementTransferScopeMask::EXPLICIT_TRANSFER_RULE
            .union(StorageIntentMeasurementTransferScopeMask::ISOLATION_ELIGIBLE)
            .union(StorageIntentMeasurementTransferScopeMask::TRUST_DOMAIN_ELIGIBLE);
        evidence.transfer_scope_ref = StorageIntentEvidenceRef::default();
        assert!(!evidence.authority_transfer_is_allowed());
        assert!(!evidence
            .authorizes_use(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD));

        evidence.transfer_scope = evidence
            .transfer_scope
            .union(StorageIntentMeasurementTransferScopeMask::DOMAIN_ELIGIBLE);
        assert!(!evidence.authority_transfer_is_allowed());

        evidence.transfer_scope_ref =
            evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 150);
        assert!(evidence.authority_transfer_is_allowed());
        assert!(evidence
            .authorizes_use(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD));
    }

    #[test]
    fn partial_attribution_requires_bounds_before_authority_use() {
        let mut evidence = measurement_attribution();
        evidence.verdict =
            StorageIntentMeasurementAttributionVerdict::PartiallyAttributableWithBounds;
        evidence.bounded_uncertainty_ppm = 0;

        assert!(!evidence.has_verdict_boundary());
        assert!(!evidence.authorizes_use(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PERFORMANCE_EVIDENCE
        ));

        evidence.bounded_uncertainty_ppm = 25_000;
        assert!(evidence.has_verdict_boundary());
        assert!(evidence.authorizes_use(
            StorageIntentMeasurementAttributionUseMask::SUPPORT_PERFORMANCE_EVIDENCE
        ));
    }

    #[test]
    fn payback_uses_require_payback_cost_and_harm_metrics() {
        let mut evidence = measurement_attribution();
        evidence.metrics = measurement_metrics(false);

        assert!(evidence.metrics.has_usable_metric());
        assert!(!evidence.metrics_support_payback_or_movement());
        assert!(evidence
            .authorizes_use(StorageIntentMeasurementAttributionUseMask::TRAIN_CONFIDENCE_UPWARD));
        assert!(!evidence.authorizes_use(StorageIntentMeasurementAttributionUseMask::CLOSE_PAYBACK));
    }

    #[test]
    fn free_floating_evidence_ref_does_not_satisfy_query_snapshot() {
        let snapshot = base_query_snapshot(
            EvidenceConsumerClass::Planner,
            EvidenceQueryContextClass::PrefetchResidency,
        );
        let cache_guess = media_evidence(99);

        assert_eq!(
            cache_guess.kind,
            StorageIntentEvidenceKind::MediaCapabilityEvidence
        );
        assert!(snapshot.is_authority_admissible());
        assert!(
            !snapshot.contains_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence)
        );
        assert!(!snapshot
            .authorizes_fresh_evidence_kind(StorageIntentEvidenceKind::MediaCapabilityEvidence));
    }

    fn workload_signal(
        dataset_id: StorageIntentDomainId,
        access_pattern: AccessPatternClass,
        candidate: PrefetchResidencyCandidateClass,
        flags: WorkloadSignalFlags,
    ) -> WorkloadSignalRecord {
        WorkloadSignalRecord {
            policy_id: StorageIntentPolicyId([7_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(11),
            scope: StorageIntentObjectScope {
                dataset_id,
                object_id: StorageIntentEvidenceId([8_u8; 32]),
                range_start: 4096,
                range_len: 131_072,
                generation: 19,
            },
            pool_id: StorageIntentDomainId([9_u8; 16]),
            signal_scope: WorkloadSignalScopeClass::Dataset,
            access_pattern,
            confidence: PredictionConfidence::High,
            observation_window_ms: 60_000,
            sample_mass: 512,
            decay_age_ms: 1_000,
            contradiction: ContradictionState::None,
            provenance: HintProvenance::RuntimeObserved,
            materialization_mode: SignalMaterializationMode::RetainedEvidence,
            flags,
            budget_owner: dataset_id,
            source_media: StorageMediaClass::HddRotational,
            target_media: StorageMediaClass::NvmeFlash,
            source_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 20),
            target_media_ref: evidence_ref(StorageIntentEvidenceKind::MediaCapabilityEvidence, 21),
            service_objective_ref: evidence_ref(
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                22,
            ),
            topology_ref: evidence_ref(StorageIntentEvidenceKind::TransportPathEvidence, 23),
            signal_materialization_ref: evidence_ref(
                StorageIntentEvidenceKind::PredictionEvidence,
                24,
            ),
            signal_collection_cost_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCostWearLedger,
                25,
            ),
            candidate,
            refusal: StorageIntentRefusalReason::None,
        }
    }

    fn proven_media_capability(
        media_class: StorageMediaClass,
        byte: u8,
    ) -> StorageIntentMediaCapabilityRecord {
        let evidence = media_evidence(byte);
        StorageIntentMediaCapabilityRecord {
            media_class,
            evidence,
            stable_identity_ref: evidence,
            namespace_identity_ref: evidence,
            persistence_ref: evidence,
            flush_ref: evidence,
            atomicity_ref: evidence,
            geometry_ref: evidence,
            health_ref: evidence,
            freshness_ref: evidence,
            remote_commit_ref: evidence,
            archive_restore_ref: evidence,
            ..proven_nvme_capability()
        }
    }

    fn proven_cloud_object_capability(byte: u8) -> StorageIntentMediaCapabilityRecord {
        let evidence = media_evidence(byte);
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::CloudObject,
            flags: durable_media_flags().union(MediaCapabilityFlags::REMOTE_COMMIT),
            persistence: MediaPersistenceDomain::ObjectDurable,
            flush_ordering: MediaFlushOrderingClass::ObjectCommit,
            atomicity: MediaAtomicityClass::IdempotentObjectPut,
            geometry: MediaProtocolGeometryClass::RemoteObject,
            remote_commit: MediaRemoteCommitSemantics::ObjectConditionalDurable,
            archive_restore: MediaArchiveRestoreSemantics::NotArchive,
            evidence,
            stable_identity_ref: evidence,
            namespace_identity_ref: evidence,
            persistence_ref: evidence,
            flush_ref: evidence,
            atomicity_ref: evidence,
            geometry_ref: evidence,
            health_ref: evidence,
            freshness_ref: evidence,
            remote_commit_ref: evidence,
            archive_restore_ref: evidence,
            ..proven_nvme_capability()
        }
    }

    fn proven_archive_capability(byte: u8) -> StorageIntentMediaCapabilityRecord {
        let evidence = media_evidence(byte);
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::TapeArchive,
            flags: durable_media_flags()
                .union(MediaCapabilityFlags::REMOTE_COMMIT)
                .union(MediaCapabilityFlags::ARCHIVE_RESTORE_RETENTION),
            persistence: MediaPersistenceDomain::ArchiveDurable,
            flush_ordering: MediaFlushOrderingClass::ArchiveCommit,
            atomicity: MediaAtomicityClass::AppendRecordAtomic,
            geometry: MediaProtocolGeometryClass::ArchiveSequential,
            remote_commit: MediaRemoteCommitSemantics::ArchiveRetained,
            archive_restore: MediaArchiveRestoreSemantics::RestoreAudited,
            evidence,
            stable_identity_ref: evidence,
            namespace_identity_ref: evidence,
            persistence_ref: evidence,
            flush_ref: evidence,
            atomicity_ref: evidence,
            geometry_ref: evidence,
            health_ref: evidence,
            freshness_ref: evidence,
            remote_commit_ref: evidence,
            archive_restore_ref: evidence,
            ..proven_nvme_capability()
        }
    }

    fn proven_hdd_capability(byte: u8) -> StorageIntentMediaCapabilityRecord {
        let evidence = media_evidence(byte);
        StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::HddRotational,
            persistence: MediaPersistenceDomain::RotationalPersistent,
            geometry: MediaProtocolGeometryClass::RotationalSeek,
            optimal_io_bytes: 1_048_576,
            latency_class_us: 8_000,
            evidence,
            stable_identity_ref: evidence,
            namespace_identity_ref: evidence,
            persistence_ref: evidence,
            flush_ref: evidence,
            atomicity_ref: evidence,
            geometry_ref: evidence,
            health_ref: evidence,
            freshness_ref: evidence,
            remote_commit_ref: evidence,
            archive_restore_ref: evidence,
            ..proven_nvme_capability()
        }
    }

    fn decision_refs() -> PrefetchResidencyDecisionEvidenceRefs {
        PrefetchResidencyDecisionEvidenceRefs {
            compiled_policy_ref: evidence_ref(StorageIntentEvidenceKind::PolicyRolloutEvidence, 40),
            service_objective_ref: evidence_ref(
                StorageIntentEvidenceKind::ServiceObjectiveEvidence,
                41,
            ),
            evidence_query_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 42),
            decision_frontier_ref: evidence_ref(
                StorageIntentEvidenceKind::DecisionFrontierEvidence,
                43,
            ),
            media_capability_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                54,
            ),
            scheduler_admission_ref: evidence_ref(
                StorageIntentEvidenceKind::SchedulerAdmissionRecord,
                44,
            ),
            capacity_reserve_ref: evidence_ref(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                45,
            ),
            tenant_isolation_ref: evidence_ref(
                StorageIntentEvidenceKind::TenantIsolationEvidence,
                46,
            ),
            cost_wear_ref: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 47),
            egress_restore_cost_ref: evidence_ref(
                StorageIntentEvidenceKind::MediaCostWearLedger,
                48,
            ),
            transport_budget_ref: evidence_ref(
                StorageIntentEvidenceKind::TransportPathEvidence,
                49,
            ),
            trust_domain_ref: evidence_ref(StorageIntentEvidenceKind::TrustDomainEvidence, 50),
            read_serving_boundary_ref: evidence_ref(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                51,
            ),
            relocation_boundary_ref: evidence_ref(StorageIntentEvidenceKind::RelocationReceipt, 52),
            result_refusal_ref: evidence_ref(StorageIntentEvidenceKind::ResultRefusalEvidence, 53),
        }
    }

    fn prefetch_policy(
        dataset_id: StorageIntentDomainId,
        allowed_actions: PrefetchResidencyActionMask,
    ) -> PrefetchResidencyPolicyEnvelope {
        PrefetchResidencyPolicyEnvelope {
            policy_id: StorageIntentPolicyId([7_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(11),
            policy_scope: PrefetchResidencyPolicyScope::Dataset,
            pool_id: StorageIntentDomainId([9_u8; 16]),
            dataset_id,
            budget_owner: dataset_id,
            allowed_actions,
            flags: PrefetchResidencyPolicyFlags::REQUIRE_DATASET_SCOPE
                .union(PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY)
                .union(PrefetchResidencyPolicyFlags::PROTECT_FOREGROUND_TAIL)
                .union(PrefetchResidencyPolicyFlags::PROTECT_FLASH_LIFETIME)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET)
                .union(PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION),
            max_prefetch_window_bytes: 131_072,
            max_staging_bytes: 8 * 1024 * 1024,
            min_sample_mass: 128,
            min_observation_window_ms: 10_000,
            max_decay_age_ms: 30_000,
            dwell_min_ms: 60_000,
            cooldown_ms: 300_000,
            evidence_refs: decision_refs(),
        }
    }

    fn cost_wear_record() -> CostWearRecord {
        CostWearRecord {
            movement_debt_bytes: 0,
            expected_write_bytes: 131_072,
            flash_wear_cost_ppm: 10,
            write_amplification_ppm: 1_100_000,
            egress_cost_microunits: 0,
            capacity_cost_microunits: 1,
            payback_window_ms: 60_000,
            payback_evidence: evidence_ref(
                StorageIntentEvidenceKind::MeasurementAttributionEvidence,
                51,
            ),
            cooldown_until_ms: 0,
            skipped_reason: SkippedMoveReason::None,
            evidence: evidence_ref(StorageIntentEvidenceKind::MediaCostWearLedger, 52),
        }
    }

    fn decision_context(
        dataset_id: StorageIntentDomainId,
        access_pattern: AccessPatternClass,
        candidate: PrefetchResidencyCandidateClass,
        flags: WorkloadSignalFlags,
        allowed_actions: PrefetchResidencyActionMask,
    ) -> PrefetchResidencyDecisionContext {
        PrefetchResidencyDecisionContext {
            policy: prefetch_policy(dataset_id, allowed_actions),
            signal: workload_signal(dataset_id, access_pattern, candidate, flags),
            source_media: proven_media_capability(StorageMediaClass::HddRotational, 53),
            target_media: proven_media_capability(StorageMediaClass::NvmeFlash, 54),
            cost_wear: cost_wear_record(),
        }
    }

    fn decision_context_with_media(
        dataset_id: StorageIntentDomainId,
        access_pattern: AccessPatternClass,
        candidate: PrefetchResidencyCandidateClass,
        flags: WorkloadSignalFlags,
        allowed_actions: PrefetchResidencyActionMask,
        source_media: StorageIntentMediaCapabilityRecord,
        target_media: StorageIntentMediaCapabilityRecord,
    ) -> PrefetchResidencyDecisionContext {
        let mut context = decision_context(
            dataset_id,
            access_pattern,
            candidate,
            flags,
            allowed_actions,
        );
        context.signal.source_media = source_media.media_class;
        context.signal.target_media = target_media.media_class;
        context.signal.source_media_ref = source_media.evidence;
        context.signal.target_media_ref = target_media.evidence;
        context.source_media = source_media;
        context.target_media = target_media;
        context
    }

    #[test]
    fn guarantee_floor_uses_capability_predicates() {
        assert!(ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::VolatileLocal,
            StorageIntentGuaranteeClass::LocalIntent
        ));
        assert!(!ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::VolatileReplicated,
            StorageIntentGuaranteeClass::LocalIntent
        ));
        assert!(ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::GeoAsync,
            StorageIntentGuaranteeClass::GeoFullPlacement
        ));
        assert!(!ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::GeoFullPlacement,
            StorageIntentGuaranteeClass::GeoIntent
        ));
    }

    #[test]
    fn failure_domains_are_set_based() {
        let required = FailureDomainMask::LOCAL.with(FailureDomainDimension::Rack);
        let achieved = FailureDomainMask::LOCAL
            .with(FailureDomainDimension::Node)
            .with(FailureDomainDimension::Rack);
        assert!(failure_domains_satisfied(required, achieved));
        assert!(!failure_domains_satisfied(
            required.with(FailureDomainDimension::Geo),
            achieved
        ));
    }

    #[test]
    fn trust_predicate_returns_typed_refusals() {
        let required = TrustRequirement {
            required_flags: TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL
                .union(TrustEvidenceFlags::ADMIN_DOMAIN)
                .union(TrustEvidenceFlags::KEY_EPOCH)
                .union(TrustEvidenceFlags::AUTHORIZATION)
                .union(TrustEvidenceFlags::AUDIT)
                .union(TrustEvidenceFlags::SESSION_SECURITY)
                .union(TrustEvidenceFlags::SHARING_DOMAIN)
                .union(TrustEvidenceFlags::NOT_QUARANTINED),
            min_session_security: SessionSecurityClass::MutualAuthenticated,
            min_key_epoch: 9,
            admin_domain: DOMAIN_A,
            security_domain: StorageIntentDomainId::ZERO,
            tenant_domain: StorageIntentDomainId::ZERO,
            residency: ResidencyScope::Unspecified,
            sharing_domain: SharingDomainClass::SameTenant,
        };
        let observed = TrustEvidenceState {
            flags: TrustEvidenceFlags::AUTHENTICATED_PRINCIPAL
                .union(TrustEvidenceFlags::ADMIN_DOMAIN)
                .union(TrustEvidenceFlags::KEY_EPOCH)
                .union(TrustEvidenceFlags::AUDIT)
                .union(TrustEvidenceFlags::SESSION_SECURITY)
                .union(TrustEvidenceFlags::SHARING_DOMAIN)
                .union(TrustEvidenceFlags::NOT_QUARANTINED),
            session_security: SessionSecurityClass::Encrypted,
            key_epoch: 8,
            admin_domain: DOMAIN_B,
            sharing_domain: SharingDomainClass::CrossTenantAllowed,
            quarantine_state: QuarantineState::Clear,
            ..TrustEvidenceState::EMPTY
        };

        assert_eq!(
            trust_security_satisfies(required, observed).refusal,
            StorageIntentRefusalReason::WrongDomain
        );

        let observed = TrustEvidenceState {
            admin_domain: DOMAIN_A,
            ..observed
        };
        assert_eq!(
            trust_security_satisfies(required, observed).refusal,
            StorageIntentRefusalReason::StaleKeyEpoch
        );

        let observed = TrustEvidenceState {
            key_epoch: 9,
            ..observed
        };
        assert_eq!(
            trust_security_satisfies(required, observed).refusal,
            StorageIntentRefusalReason::MissingAuthorization
        );
    }

    #[test]
    fn trust_role_predicates_cover_named_roles() {
        let roles = [
            StorageIntentTrustRole::SyncIntent,
            StorageIntentTrustRole::QuorumIntent,
            StorageIntentTrustRole::GeoIntent,
            StorageIntentTrustRole::DurablePlacement,
            StorageIntentTrustRole::ReadServing,
            StorageIntentTrustRole::DegradedReconstruction,
            StorageIntentTrustRole::AuthoritativeRam,
            StorageIntentTrustRole::RepairSource,
            StorageIntentTrustRole::RelocationTarget,
            StorageIntentTrustRole::DedupRebakeSharing,
            StorageIntentTrustRole::ArchiveRestore,
        ];

        for role in roles {
            assert_eq!(
                trust_domain_role_satisfies(
                    role,
                    trust_role_requirement_for_test(role),
                    full_trust_record_for_role(role),
                ),
                ReceiptPredicateResult::SATISFIED,
                "role {role} should have a satisfiable trust/domain evidence envelope"
            );
        }
    }

    #[test]
    fn stale_key_epoch_blocks_durable_placement() {
        let role = StorageIntentTrustRole::DurablePlacement;
        let mut observed = full_trust_record_for_role(role);
        observed.state.key_epoch = 8;

        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::StaleKeyEpoch
        );
    }

    #[test]
    fn revoked_or_quarantined_trust_domain_is_refused() {
        let role = StorageIntentTrustRole::ReadServing;
        let mut observed = full_trust_record_for_role(role);
        observed.revocation_state = TrustRevocationState::Revoked;

        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::RevokedTrustDomain
        );

        let mut observed = full_trust_record_for_role(role);
        observed.state.quarantine_state = QuarantineState::Quarantined;
        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::QuarantinedSource
        );
    }

    #[test]
    fn internet_path_needs_session_security_not_rdma() {
        let role = StorageIntentTrustRole::GeoIntent;
        let required = TrustDomainRequirement {
            base: TrustRequirement {
                residency: ResidencyScope::InternetAllowed,
                ..trust_role_requirement_for_test(role).base
            },
            allowed_domain_classes: TrustAllowedDomainMask::INTERNET_ALLOWED,
            ..trust_role_requirement_for_test(role)
        };
        let mut observed = full_trust_record_for_role(role);
        observed.state.residency = ResidencyScope::InternetAllowed;
        observed.allowed_domain_classes = TrustAllowedDomainMask::INTERNET_ALLOWED;
        observed.state.session_security = SessionSecurityClass::Authenticated;

        assert_eq!(
            trust_domain_role_satisfies(role, required, observed).refusal,
            StorageIntentRefusalReason::MissingRequiredSessionSecurity
        );
    }

    #[test]
    fn cross_tenant_dedup_rebake_is_illegal_without_sharing_authority() {
        let role = StorageIntentTrustRole::DedupRebakeSharing;
        let mut observed = full_trust_record_for_role(role);
        observed.state.sharing_domain = SharingDomainClass::CrossTenantAllowed;
        observed.sharing_compatibility = DedupSharingCompatibilityState::CrossTenantForbidden;

        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::IllegalSharingDomain
        );
    }

    #[test]
    fn cross_admin_geo_placement_requires_authorization_ref() {
        let role = StorageIntentTrustRole::GeoIntent;
        let required = TrustDomainRequirement {
            base: TrustRequirement {
                admin_domain: StorageIntentDomainId::ZERO,
                security_domain: StorageIntentDomainId::ZERO,
                ..trust_role_requirement_for_test(role).base
            },
            ..trust_role_requirement_for_test(role)
        };
        let mut observed = full_trust_record_for_role(role);
        observed.state.admin_domain = DOMAIN_B;
        observed.state.security_domain = DOMAIN_B;
        observed.authorization_ref = StorageIntentEvidenceRef::default();

        assert_eq!(
            trust_domain_role_satisfies(role, required, observed).refusal,
            StorageIntentRefusalReason::MissingAuthorization
        );
    }

    #[test]
    fn regulatory_residency_refusal_is_visible() {
        let role = StorageIntentTrustRole::ArchiveRestore;
        let mut observed = full_trust_record_for_role(role);
        observed.state.residency = ResidencyScope::InternetAllowed;

        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::ResidencyViolation
        );
    }

    #[test]
    fn compromised_repair_source_is_rejected() {
        let role = StorageIntentTrustRole::RepairSource;
        let mut observed = full_trust_record_for_role(role);
        observed.state.compromise_state = CompromiseState::Compromised;

        assert_eq!(
            trust_domain_role_satisfies(role, trust_role_requirement_for_test(role), observed)
                .refusal,
            StorageIntentRefusalReason::CompromisedRepairSource
        );
    }

    #[test]
    fn media_role_blocks_cache_and_volatile_ram_authority() {
        assert_eq!(
            media_role_satisfies_receipt(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::ReadCache,
                StorageMediaClass::NvmeFlash,
            )
            .refusal,
            StorageIntentRefusalReason::CacheCannotBeAuthority
        );
        assert_eq!(
            media_role_satisfies_receipt(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::RamVolatileAuthority,
                StorageMediaClass::SystemRam,
            )
            .refusal,
            StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent
        );
        assert!(
            media_role_satisfies_receipt(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::RamIntentBackedAuthority,
                StorageMediaClass::SystemRam,
            )
            .satisfied
        );
    }

    #[test]
    fn media_capability_requires_fresh_evidence_not_class_labels() {
        assert!(
            media_role_satisfies_receipt(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                StorageMediaClass::NvmeFlash,
            )
            .satisfied
        );

        let class_label_only = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::NvmeFlash,
            ..StorageIntentMediaCapabilityRecord::default()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                class_label_only,
            )
            .refusal,
            StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        );

        let stale = StorageIntentMediaCapabilityRecord {
            freshness: MediaCapabilityFreshnessState::Stale,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                stale,
            )
            .refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn media_capability_blocks_unsafe_flush_and_cache_durable() {
        assert!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                proven_nvme_capability(),
            )
            .satisfied
        );

        let unsupported_fua = StorageIntentMediaCapabilityRecord {
            flush_ordering: MediaFlushOrderingClass::FlushOnly,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                unsupported_fua,
            )
            .refusal,
            StorageIntentRefusalReason::UnsupportedFlushFuaSemantics
        );

        let unsafe_cache = StorageIntentMediaCapabilityRecord {
            persistence: MediaPersistenceDomain::CacheOnlyVolatile,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                unsafe_cache,
            )
            .refusal,
            StorageIntentRefusalReason::UnsafeVolatileWriteCache
        );
    }

    #[test]
    fn media_capability_blocks_pmem_without_flush_fence() {
        let pmem_without_fence = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::PersistentMemory,
            persistence: MediaPersistenceDomain::PersistentMemory,
            flush_ordering: MediaFlushOrderingClass::FlushAndFua,
            geometry: MediaProtocolGeometryClass::PmemByteAddressable,
            ..proven_nvme_capability()
        };

        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                pmem_without_fence,
            )
            .refusal,
            StorageIntentRefusalReason::PmemFlushFenceMissing
        );
    }

    #[test]
    fn media_capability_blocks_stale_identity_and_bad_atomicity() {
        let stale_namespace = StorageIntentMediaCapabilityRecord {
            flags: durable_media_flags().without(MediaCapabilityFlags::STABLE_NAMESPACE_IDENTITY),
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                stale_namespace,
            )
            .refusal,
            StorageIntentRefusalReason::UnstableNamespaceIdentity
        );

        let torn_writes = StorageIntentMediaCapabilityRecord {
            atomicity: MediaAtomicityClass::TornWritesPossible,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                torn_writes,
            )
            .refusal,
            StorageIntentRefusalReason::WrongAtomicityGranularity
        );
    }

    #[test]
    fn media_capability_blocks_zoned_remote_and_archive_gaps() {
        let random_zoned_flash = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::ZonedFlash,
            geometry: MediaProtocolGeometryClass::RandomBlock,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::SyncIntent,
                random_zoned_flash,
            )
            .refusal,
            StorageIntentRefusalReason::UnsupportedZoneWritePointer
        );

        let rdma_only_object = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::CloudObject,
            flags: durable_media_flags().union(MediaCapabilityFlags::REMOTE_COMMIT),
            persistence: MediaPersistenceDomain::ObjectDurable,
            flush_ordering: MediaFlushOrderingClass::ObjectCommit,
            atomicity: MediaAtomicityClass::IdempotentObjectPut,
            geometry: MediaProtocolGeometryClass::RemoteObject,
            remote_commit: MediaRemoteCommitSemantics::RdmaRequiredOnly,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::PlacementAuthority,
                rdma_only_object,
            )
            .refusal,
            StorageIntentRefusalReason::RdmaRequiredForCorrectness
        );

        let unknown_archive_restore = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::TapeArchive,
            persistence: MediaPersistenceDomain::ArchiveDurable,
            flush_ordering: MediaFlushOrderingClass::ArchiveCommit,
            atomicity: MediaAtomicityClass::AppendRecordAtomic,
            geometry: MediaProtocolGeometryClass::ArchiveSequential,
            remote_commit: MediaRemoteCommitSemantics::ArchiveRetained,
            archive_restore: MediaArchiveRestoreSemantics::Unknown,
            ..proven_nvme_capability()
        };
        assert_eq!(
            media_capability_satisfies_role(
                MediaRoleRequirement::AUTHORITY,
                StorageIntentGuaranteeClass::ArchiveEc,
                StorageMediaRole::ArchiveEc,
                unknown_archive_restore,
            )
            .refusal,
            StorageIntentRefusalReason::UnknownArchiveRestoreRetention
        );
    }

    #[test]
    fn media_capability_allows_cache_only_prefetch_when_policy_allows() {
        let evidence = media_evidence(10);
        let cache_requirement = MediaRoleRequirement {
            allowed_roles: MediaRoleMask::from_role(StorageMediaRole::ReadCache),
            require_authority_role: false,
        };
        let ram_cache = StorageIntentMediaCapabilityRecord {
            media_class: StorageMediaClass::SystemRam,
            flags: MediaCapabilityFlags::PERSISTENCE_DOMAIN.union(MediaCapabilityFlags::FRESHNESS),
            persistence: MediaPersistenceDomain::VolatileRam,
            freshness: MediaCapabilityFreshnessState::Fresh,
            geometry: MediaProtocolGeometryClass::RamByteAddressable,
            evidence,
            persistence_ref: evidence,
            freshness_ref: evidence,
            ..StorageIntentMediaCapabilityRecord::default()
        };

        assert!(
            media_capability_satisfies_role(
                cache_requirement,
                StorageIntentGuaranteeClass::VolatileLocal,
                StorageMediaRole::ReadCache,
                ram_cache,
            )
            .satisfied
        );
    }

    #[test]
    fn receipt_evaluation_returns_first_refusal() {
        let policy = durable_policy();
        let mut receipt = durable_receipt();
        assert!(evaluate_receipt_against_policy(policy, receipt).satisfied);

        receipt.media_role = StorageMediaRole::RamCache;
        let result = evaluate_receipt_against_policy(policy, receipt);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::CacheCannotBeAuthority
        );

        receipt = durable_receipt();
        receipt.durability.observed_lag_ms = 10;
        let result = evaluate_receipt_against_policy(policy, receipt);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
    }

    #[test]
    fn receipt_set_surfaces_no_legal_set_refusal() {
        let policy = durable_policy();
        let mut receipt = durable_receipt();
        receipt.media_role = StorageMediaRole::RamCache;

        let result = evaluate_receipt_set_against_policy(policy, &[receipt]);
        assert!(!result.satisfied);
        assert_eq!(result.satisfying_receipts, 0);
        assert_eq!(
            result.refusal.reason,
            StorageIntentRefusalReason::CacheCannotBeAuthority
        );

        let result = evaluate_receipt_set_against_policy(policy, &[]);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal.reason,
            StorageIntentRefusalReason::NoLegalReceiptSet
        );
    }

    #[test]
    fn canonical_spellings_and_decoders_are_stable() {
        assert_eq!(
            StorageIntentEvidenceKind::from_discriminant(31),
            Some(StorageIntentEvidenceKind::MediaCapabilityEvidence)
        );
        assert_eq!(
            StorageIntentEvidenceKind::MediaCapabilityEvidence.as_str(),
            "media-capability-evidence"
        );
        assert_eq!(
            EvidenceQueryContextClass::PrefetchResidency.as_str(),
            "prefetch-residency"
        );
        assert_eq!(EvidenceQuerySubjectScopeClass::Dataset.to_discriminant(), 4);
        assert_eq!(
            EvidenceCompletenessVerdict::CompleteForPurpose.as_str(),
            "complete-for-purpose"
        );
        assert_eq!(
            EvidenceFamilyFreshnessState::Compacted.as_str(),
            "compacted"
        );
        assert_eq!(
            StorageIntentActionClass::from_discriminant(5),
            Some(StorageIntentActionClass::DurablePlacementMovement)
        );
        assert_eq!(
            StorageIntentActionClass::DurablePlacementMovement.as_str(),
            "durable-placement-movement"
        );
        assert_eq!(
            StorageIntentActionExecutionStepState::from_discriminant(8),
            Some(StorageIntentActionExecutionStepState::RetiringSource)
        );
        assert_eq!(
            StorageIntentActionExecutionStepState::RolledBack.as_str(),
            "rolled-back"
        );
        assert_eq!(
            StorageIntentActionReplayState::CrashRecovery.as_str(),
            "crash-recovery"
        );
        assert_eq!(
            StorageIntentActionEvidenceState::PolicyRevisionChanged.as_str(),
            "policy-revision-changed"
        );
        assert_eq!(
            StorageIntentSourceRetirementState::from_discriminant(4),
            Some(StorageIntentSourceRetirementState::Ready)
        );
        assert_eq!(
            StorageIntentActionTargetVerificationState::PartialWrite.as_str(),
            "partial-write"
        );
        assert_eq!(
            StorageIntentActionPublicationState::ReplacementPublished.as_str(),
            "replacement-published"
        );
        assert_eq!(
            StorageIntentActionExecutionRefusalReason::from_discriminant(16),
            Some(StorageIntentActionExecutionRefusalReason::MissingActionCompletionEvidence)
        );
        assert_eq!(StorageMediaClass::NvmeFlash.to_discriminant(), 3);
        assert_eq!(
            StorageIntentRefusalReason::from_discriminant(18),
            Some(StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent)
        );
        assert_eq!(
            StorageIntentRefusalReason::from_discriminant(37),
            Some(StorageIntentRefusalReason::RdmaRequiredForCorrectness)
        );
        assert_eq!(
            MediaFlushOrderingClass::PmemFlushFence.as_str(),
            "pmem-flush-fence"
        );
        assert_eq!(
            MediaRemoteCommitSemantics::from_discriminant(7),
            Some(MediaRemoteCommitSemantics::RdmaRequiredOnly)
        );
        assert_eq!(
            AccessPatternClass::from_discriminant(11),
            Some(AccessPatternClass::OnePassScan)
        );
        assert_eq!(
            AccessPatternClass::from_discriminant(21),
            Some(AccessPatternClass::BackupRestoreScan)
        );
        assert_eq!(
            AccessPatternClass::DatabaseWalFsync.as_str(),
            "database-wal-fsync"
        );
        assert_eq!(
            PrefetchResidencyCandidateClass::FlashHotServing.as_str(),
            "flash-hot-serving"
        );
        assert_eq!(PrefetchResidencyPolicyScope::Dataset.as_str(), "dataset");
        assert_eq!(
            PrefetchResidencyStateClass::WanGeoAsync.as_str(),
            "wan-geo-async"
        );
        assert_eq!(
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence.as_str(),
            "need-more-evidence"
        );
        assert_eq!(
            SignalMaterializationMode::from_discriminant(5),
            Some(SignalMaterializationMode::DurableSummary)
        );
        assert_eq!(SkippedMoveReason::from_discriminant(99), None);
    }

    #[test]
    fn ram_authority_record_carries_loss_and_evidence_refs() {
        let ram_record = RamAuthorityRecord {
            authority_class: RamAuthorityClass::RamIntentBacked,
            requested_guarantee: StorageIntentGuaranteeClass::LocalIntent,
            earned_ack_class: StorageIntentGuaranteeClass::LocalIntent,
            lost_if: AuthorityEventMask::from_event(AuthorityEvent::ProcessCrash)
                .with(AuthorityEvent::PowerLoss),
            survives: AuthorityEventMask::from_event(AuthorityEvent::ReplayAfterDurableIntent),
            ordering_ref: StorageIntentEvidenceRef::new(
                StorageIntentEvidenceKind::OrderingEvidence,
                StorageIntentEvidenceId([3_u8; 32]),
                7,
                1,
            ),
            media_capability_ref: StorageIntentEvidenceRef::new(
                StorageIntentEvidenceKind::MediaCapabilityEvidence,
                StorageIntentEvidenceId([4_u8; 32]),
                8,
                1,
            ),
            ..RamAuthorityRecord::default()
        };

        assert_eq!(ram_record.authority_class.as_str(), "ram-intent-backed");
        assert!(ram_record.lost_if.contains(AuthorityEvent::PowerLoss));
        assert!(ram_record
            .survives
            .contains(AuthorityEvent::ReplayAfterDurableIntent));
        assert_eq!(
            ram_record.ordering_ref.kind,
            StorageIntentEvidenceKind::OrderingEvidence
        );
        assert_eq!(
            ram_record.media_capability_ref.kind,
            StorageIntentEvidenceKind::MediaCapabilityEvidence
        );
    }

    #[test]
    fn media_traits_separate_rotational_defrag_from_flash_wear() {
        assert!(StorageMediaClass::HddRotational.favors_extent_locality_defrag());
        assert!(!StorageMediaClass::NvmeFlash.favors_extent_locality_defrag());
        assert!(StorageMediaClass::NvmeFlash.charges_rewrite_wear());
        assert!(!StorageMediaClass::HddRotational.charges_rewrite_wear());
    }

    #[test]
    fn workload_signal_learning_stays_dataset_scoped() {
        let dataset_a = workload_signal(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
        );
        let dataset_b = workload_signal(
            DOMAIN_B,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::NoPrefetch,
            WorkloadSignalFlags::UNKNOWN_WAF,
        );

        assert!(workload_signal_can_train_upward(dataset_a));
        assert!(!workload_signal_can_train_upward(dataset_b));
        assert!(!workload_signal_same_learning_envelope(
            dataset_a, dataset_b
        ));
        assert_eq!(dataset_a.pool_id, dataset_b.pool_id);
        let pool_scope = WorkloadSignalRecord {
            signal_scope: WorkloadSignalScopeClass::Pool,
            ..dataset_a
        };
        assert!(!workload_signal_can_train_upward(pool_scope));
        assert_eq!(
            workload_signal_lowered_candidate(dataset_b),
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
    }

    #[test]
    fn weak_or_confounded_signals_do_not_promote_flash() {
        let one_pass = workload_signal(
            DOMAIN_A,
            AccessPatternClass::OnePassScan,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::ONE_PASS_SCAN,
        );
        let hint_only = workload_signal(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            WorkloadSignalFlags::HINT_ONLY,
        );
        let memory_only = workload_signal(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::PmemDurable,
            WorkloadSignalFlags::MEMORY_ONLY,
        );
        let sketch_only = WorkloadSignalRecord {
            materialization_mode: SignalMaterializationMode::MemoryOnlySketch,
            ..workload_signal(
                DOMAIN_A,
                AccessPatternClass::SmallRandomHotset,
                PrefetchResidencyCandidateClass::PmemDurable,
                WorkloadSignalFlags::EMPTY,
            )
        };

        assert!(!workload_signal_can_train_upward(one_pass));
        assert_eq!(
            workload_signal_lowered_candidate(one_pass),
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert!(!workload_signal_can_train_upward(hint_only));
        assert_eq!(
            workload_signal_lowered_candidate(hint_only),
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert!(!workload_signal_can_train_upward(memory_only));
        assert_eq!(
            workload_signal_lowered_candidate(memory_only),
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert!(!workload_signal_can_train_upward(sketch_only));
        assert_eq!(
            workload_signal_lowered_candidate(sketch_only),
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
    }

    #[test]
    fn unknown_waf_and_collection_cost_lower_action_class() {
        let unknown_waf = workload_signal(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::UNKNOWN_WAF,
        );
        let unknown_collection_cost = workload_signal(
            DOMAIN_A,
            AccessPatternClass::WanGeoDelta,
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            WorkloadSignalFlags::UNKNOWN_COLLECTION_COST,
        );

        assert!(!workload_signal_can_train_upward(unknown_waf));
        assert_eq!(
            workload_signal_lowered_candidate(unknown_waf),
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert!(!workload_signal_has_collection_cost(
            unknown_collection_cost
        ));
        assert_eq!(
            workload_signal_lowered_candidate(unknown_collection_cost),
            PrefetchResidencyCandidateClass::NoPrefetch
        );
    }

    #[test]
    fn prefetch_residency_decision_respects_dataset_policy() {
        let aggressive = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        let conservative = decision_context(
            DOMAIN_B,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
        );

        let aggressive_decision = prefetch_residency_decide(aggressive);
        let conservative_decision = prefetch_residency_decide(conservative);

        assert_eq!(aggressive.signal.pool_id, conservative.signal.pool_id);
        assert_eq!(
            aggressive_decision.selected_candidate,
            PrefetchResidencyCandidateClass::FlashHotServing
        );
        assert_eq!(
            aggressive_decision.outcome,
            PrefetchResidencyDecisionOutcome::ServingTrial
        );
        assert_eq!(
            conservative_decision.selected_candidate,
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert_eq!(
            conservative_decision.outcome,
            PrefetchResidencyDecisionOutcome::Lowered
        );
        assert!(prefetch_residency_decision_is_cache_only(
            conservative_decision
        ));
        assert!(!prefetch_residency_decision_may_request_authority_change(
            aggressive_decision
        ));
    }

    #[test]
    fn pool_default_policy_cannot_authorize_prefetch() {
        let mut context = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        context.policy.policy_scope = PrefetchResidencyPolicyScope::PoolDefault;

        let decision = prefetch_residency_decide(context);

        assert_eq!(decision.outcome, PrefetchResidencyDecisionOutcome::Refused);
        assert_eq!(
            decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn prefetch_residency_decision_requires_evidence_cuts_and_fresh_media() {
        let mut missing_evidence = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        missing_evidence.policy.evidence_refs.evidence_query_ref =
            StorageIntentEvidenceRef::default();

        let missing_decision = prefetch_residency_decide(missing_evidence);
        assert_eq!(
            missing_decision.outcome,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence
        );
        assert_eq!(
            missing_decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut missing_trust_domain = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        missing_trust_domain.policy.evidence_refs.trust_domain_ref =
            StorageIntentEvidenceRef::default();

        let trust_decision = prefetch_residency_decide(missing_trust_domain);
        assert_eq!(
            trust_decision.outcome,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence
        );
        assert_eq!(
            trust_decision.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut stale_media = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        stale_media.target_media.freshness = MediaCapabilityFreshnessState::Stale;

        let stale_decision = prefetch_residency_decide(stale_media);
        assert_eq!(
            stale_decision.outcome,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence
        );
        assert_eq!(
            stale_decision.refusal,
            StorageIntentRefusalReason::StaleMediaCapabilityEvidence
        );
    }

    #[test]
    fn promotion_requires_relocation_and_payback_evidence() {
        let mut no_relocation = decision_context(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        no_relocation.policy.evidence_refs.relocation_boundary_ref =
            StorageIntentEvidenceRef::default();

        let blocked = prefetch_residency_decide(no_relocation);
        assert_eq!(
            blocked.outcome,
            PrefetchResidencyDecisionOutcome::NeedMoreEvidence
        );
        assert_eq!(
            blocked.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        let mut no_payback = decision_context(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        no_payback.cost_wear.payback_evidence = StorageIntentEvidenceRef::default();
        no_payback.cost_wear.payback_window_ms = 0;

        let cooled = prefetch_residency_decide(no_payback);
        assert_eq!(cooled.outcome, PrefetchResidencyDecisionOutcome::Cooldown);
        assert_eq!(
            cooled.refusal,
            StorageIntentRefusalReason::MovementDebtNotPaidBack
        );

        let admitted = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            admitted.outcome,
            PrefetchResidencyDecisionOutcome::PromotionCandidate
        );
        assert!(prefetch_residency_decision_may_request_authority_change(
            admitted
        ));
    }

    #[test]
    fn access_pattern_refinements_lower_to_safe_actions() {
        let wal = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::DatabaseWalFsync,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            wal.selected_candidate,
            PrefetchResidencyCandidateClass::NoPrefetch
        );
        assert_eq!(wal.outcome, PrefetchResidencyDecisionOutcome::NoAction);

        let vm = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::VmImageMixedRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            vm.selected_candidate,
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert_eq!(vm.outcome, PrefetchResidencyDecisionOutcome::Lowered);
        assert!(prefetch_residency_decision_is_cache_only(vm));

        let mmap = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::MmapPageCacheReuse,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            mmap.selected_candidate,
            PrefetchResidencyCandidateClass::CacheOnlyTrial
        );
        assert_eq!(mmap.outcome, PrefetchResidencyDecisionOutcome::Lowered);
        assert!(prefetch_residency_decision_is_cache_only(mmap));

        let backup = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::BackupRestoreScan,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            backup.selected_candidate,
            PrefetchResidencyCandidateClass::BoundedReadahead
        );
        assert_eq!(backup.outcome, PrefetchResidencyDecisionOutcome::Lowered);
        assert!(prefetch_residency_decision_is_cache_only(backup));
    }

    #[test]
    fn prefetch_residency_states_cover_remote_archive_and_demotion() {
        let wan = prefetch_residency_decide(decision_context_with_media(
            DOMAIN_A,
            AccessPatternClass::WanGeoDelta,
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
            proven_hdd_capability(61),
            proven_cloud_object_capability(62),
        ));
        assert_eq!(
            wan.selected_candidate,
            PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch
        );
        assert_eq!(wan.outcome, PrefetchResidencyDecisionOutcome::CacheOnly);
        assert_eq!(
            wan.selected_residency,
            PrefetchResidencyStateClass::WanGeoAsync
        );
        assert!(prefetch_residency_decision_is_cache_only(wan));

        let archive = prefetch_residency_decide(decision_context_with_media(
            DOMAIN_A,
            AccessPatternClass::ObjectArchiveRestore,
            PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
            proven_hdd_capability(63),
            proven_archive_capability(64),
        ));
        assert_eq!(
            archive.selected_candidate,
            PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
        );
        assert_eq!(
            archive.selected_residency,
            PrefetchResidencyStateClass::ObjectArchiveStaged
        );
        assert!(prefetch_residency_decision_is_cache_only(archive));

        let demotion = prefetch_residency_decide(decision_context_with_media(
            DOMAIN_A,
            AccessPatternClass::SmallRandomHotset,
            PrefetchResidencyCandidateClass::DemotionCandidate,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
            proven_nvme_capability(),
            proven_hdd_capability(65),
        ));
        assert_eq!(
            demotion.outcome,
            PrefetchResidencyDecisionOutcome::DemotionCandidate
        );
        assert_eq!(
            demotion.selected_residency,
            PrefetchResidencyStateClass::HddColdLocalityOptimized
        );
        assert!(prefetch_residency_decision_may_request_authority_change(
            demotion
        ));
    }

    #[test]
    fn flash_lifetime_unknowns_lower_or_cool_down() {
        let unknown_signal_waf = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::UNKNOWN_WAF,
            PrefetchResidencyActionMask::ALL_DEFINED,
        ));
        assert_eq!(
            unknown_signal_waf.selected_candidate,
            PrefetchResidencyCandidateClass::BoundedReadahead
        );

        let mut unknown_context_waf = decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::FlashHotServing,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::ALL_DEFINED,
        );
        unknown_context_waf.cost_wear.write_amplification_ppm = 0;

        let cooled = prefetch_residency_decide(unknown_context_waf);
        assert_eq!(cooled.outcome, PrefetchResidencyDecisionOutcome::Cooldown);
        assert_eq!(
            cooled.refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn cache_only_decision_never_changes_authority() {
        let decision = prefetch_residency_decide(decision_context(
            DOMAIN_A,
            AccessPatternClass::SequentialRead,
            PrefetchResidencyCandidateClass::BoundedReadahead,
            WorkloadSignalFlags::EMPTY,
            PrefetchResidencyActionMask::LOW_RISK_PREFETCH,
        ));

        assert_eq!(
            decision.outcome,
            PrefetchResidencyDecisionOutcome::CacheOnly
        );
        assert!(prefetch_residency_decision_is_cache_only(decision));
        assert!(!prefetch_residency_decision_may_request_authority_change(
            decision
        ));
        assert_eq!(decision.refusal, StorageIntentRefusalReason::None);
    }

    #[test]
    fn decision_frontier_discriminants_fail_closed() {
        assert_eq!(
            StorageIntentDecisionAuthorityMode::from_discriminant(4),
            Some(StorageIntentDecisionAuthorityMode::Preflight)
        );
        assert!(!StorageIntentDecisionAuthorityMode::Preflight.may_admit_authority_change());
        assert!(StorageIntentDecisionAuthorityMode::Live.may_admit_authority_change());
        assert_eq!(
            StorageIntentDecisionScoreState::UnknownCost.as_str(),
            "unknown-cost"
        );
        assert_eq!(
            StorageIntentDecisionScoreDimension::from_discriminant(17),
            Some(StorageIntentDecisionScoreDimension::OperationalComplexity)
        );
        assert_eq!(
            StorageIntentDecisionScoreDimension::from_discriminant(99),
            None
        );
    }

    #[test]
    fn complete_decision_frontier_satisfies_audit_policy() {
        let frontier = decision_frontier();

        assert!(frontier.has_decision_identity());
        assert!(frontier.retains_decision_frontier());
        assert!(frontier.illegal_candidates_are_unscored());
        assert!(frontier.required_scores_are_known(
            StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM
        ));
        assert!(frontier.selection_is_deterministic());
        assert!(frontier.has_outcome_payback_anchor());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            ),
            ReceiptPredicateResult::SATISFIED
        );
    }

    #[test]
    fn illegal_decision_candidates_never_reach_scoring() {
        let mut frontier = decision_frontier();
        let mut candidates = StorageIntentDecisionCandidateSet {
            candidate_set_digest: decision_candidate_id(199),
            ..StorageIntentDecisionCandidateSet::EMPTY
        };
        candidates
            .push(decision_candidate(
                1,
                StorageIntentDecisionCandidateStatus::Legal,
                true,
            ))
            .unwrap();
        candidates
            .push(decision_candidate(
                2,
                StorageIntentDecisionCandidateStatus::Illegal,
                true,
            ))
            .unwrap();
        frontier.candidates = candidates;

        assert!(!frontier.illegal_candidates_are_unscored());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            )
            .refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn all_legal_decision_frontiers_remain_auditable() {
        let mut frontier = decision_frontier();
        let mut candidates = StorageIntentDecisionCandidateSet {
            candidate_set_digest: decision_candidate_id(199),
            ..StorageIntentDecisionCandidateSet::EMPTY
        };
        candidates
            .push(decision_candidate(
                1,
                StorageIntentDecisionCandidateStatus::Legal,
                true,
            ))
            .unwrap();
        candidates
            .push(decision_candidate(
                2,
                StorageIntentDecisionCandidateStatus::Legal,
                true,
            ))
            .unwrap();
        frontier.candidates = candidates;

        let mut hard_gates = StorageIntentDecisionHardGateResultSet::EMPTY;
        for byte in [1_u8, 2_u8] {
            hard_gates
                .push(StorageIntentDecisionHardGateResult {
                    candidate_id: decision_candidate_id(byte),
                    gate: StorageIntentDecisionHardGateKind::Guarantee,
                    verdict: StorageIntentDecisionHardGateVerdict::Passed,
                    refusal: StorageIntentRefusalReason::None,
                    evidence_ref: evidence_ref(
                        StorageIntentEvidenceKind::DecisionFrontierEvidence,
                        140 + byte,
                    ),
                })
                .unwrap();
        }
        frontier.hard_gates = hard_gates;

        assert!(frontier.retains_decision_frontier());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            ),
            ReceiptPredicateResult::SATISFIED
        );
    }

    #[test]
    fn winner_only_decision_records_are_not_auditable() {
        let mut frontier = decision_frontier();
        let mut candidates = StorageIntentDecisionCandidateSet {
            candidate_set_digest: decision_candidate_id(199),
            ..StorageIntentDecisionCandidateSet::EMPTY
        };
        candidates
            .push(decision_candidate(
                1,
                StorageIntentDecisionCandidateStatus::Legal,
                true,
            ))
            .unwrap();
        frontier.candidates = candidates;
        frontier.hard_gates = StorageIntentDecisionHardGateResultSet::EMPTY;

        assert!(!frontier.retains_decision_frontier());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            )
            .refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn unknown_required_score_dimensions_fail_closed() {
        let mut frontier = decision_frontier();
        frontier.score_vector = decision_score_vector(true);

        assert_eq!(
            frontier
                .score_vector
                .state_for_dimension(StorageIntentDecisionScoreDimension::MediaWriteCost),
            StorageIntentDecisionScoreState::UnknownCost
        );
        assert!(!frontier.required_scores_are_known(
            StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM
        ));
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            )
            .refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn tie_breakers_are_deterministic_and_evidence_backed() {
        let mut frontier = decision_frontier();
        frontier.selected_candidate.reason = StorageIntentDecisionSelectionReason::TieBreak;
        frontier.selected_candidate.tie_breaker = StorageIntentDecisionTieBreakerClass::None;
        frontier.selected_candidate.tie_breaker_input = 0;
        frontier.selected_candidate.no_cutover_proof_ref = StorageIntentEvidenceRef::default();

        assert!(!frontier.selection_is_deterministic());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            )
            .refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );

        frontier.selected_candidate.tie_breaker =
            StorageIntentDecisionTieBreakerClass::DeterministicOrderKey;
        frontier.selected_candidate.tie_breaker_input = 99;
        frontier.selected_candidate.no_cutover_proof_ref =
            evidence_ref(StorageIntentEvidenceKind::ActionExecutionEvidence, 212);

        assert!(frontier.selection_is_deterministic());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            ),
            ReceiptPredicateResult::SATISFIED
        );
    }

    #[test]
    fn failed_payback_and_harm_attach_to_original_frontier() {
        let mut frontier = decision_frontier();
        assert!(frontier.has_outcome_payback_anchor());

        frontier.counterfactual_payback.decision_frontier_ref =
            evidence_ref(StorageIntentEvidenceKind::DecisionFrontierEvidence, 213);
        assert!(!frontier.has_outcome_payback_anchor());
        assert_eq!(
            decision_frontier_satisfies_audit_policy(
                frontier,
                StorageIntentDecisionScoreRequirementMask::AUTHORITY_MINIMUM,
            )
            .refusal,
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn record_header_fails_closed() {
        assert_eq!(StorageIntentRecordHeader::CURRENT.validate(), Ok(()));
        assert_eq!(
            StorageIntentRecordHeader {
                version: STORAGE_INTENT_RECORD_VERSION + 1,
                reserved: [0_u8; 6],
            }
            .validate(),
            Err(StorageIntentRecordError::UnsupportedVersion)
        );
        assert_eq!(
            StorageIntentRecordHeader {
                version: STORAGE_INTENT_RECORD_VERSION,
                reserved: [0, 0, 1, 0, 0, 0],
            }
            .validate(),
            Err(StorageIntentRecordError::NonZeroReserved)
        );
    }
    // ── Temporal evidence tests (issue #903) ── //

    fn temporal_evidence_ref(
        kind: StorageIntentEvidenceKind,
        byte: u8,
    ) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            StorageIntentEvidenceId([byte; 32]),
            u64::from(byte),
            1,
        )
    }

    fn healthy_wall_clock_timebase() -> StorageIntentTemporalEvidence {
        StorageIntentTemporalEvidence {
            evidence: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 1),
            timebase: StorageIntentTimebaseClass::LocalWallClock,
            timebase_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 2),
            clock_health: StorageIntentClockHealth {
                source: StorageIntentClockSourceClass::NtpSynchronized,
                sync_domain: StorageIntentDomainId::ZERO,
                skew_bound_us: 100, // 100 us skew
                flags: ClockHealthFlags::from_flag(
                    ClockHealthFlags::MONOTONIC
                        | ClockHealthFlags::KNOWN_SKEW
                        | ClockHealthFlags::NO_BACKWARDS_STEP,
                ),
                sample_age_ms: 1000,
                sample_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 3),
                health_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 4),
            },
            clock_health_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 5),
            event_frontier: StorageIntentEventFrontierClass::RemoteApply,
            event_frontier_ref: temporal_evidence_ref(
                StorageIntentEvidenceKind::TemporalEvidence,
                6,
            ),
            staleness_class: StorageIntentStalenessClass::GeoRpoLag,
            staleness_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 7),
            expiry_deadline_class: StorageIntentExpiryDeadlineClass::Unknown,
            expiry_deadline_ref: StorageIntentEvidenceRef::default(),
            sequence_time_conversion: StorageIntentSequenceTimeConversion::default(),
            refusal: StorageIntentTemporalRefusalReason::None,
            refusal_ref: StorageIntentEvidenceRef::default(),
        }
    }

    #[test]
    fn unknown_clock_skew_cannot_satisfy_wall_clock_rpo() {
        let mut evidence = healthy_wall_clock_timebase();
        // Set unknown skew: zero bound and missing KNOWN_SKEW flag.
        evidence.clock_health.skew_bound_us = 0;
        evidence.clock_health.flags = ClockHealthFlags::from_flag(
            ClockHealthFlags::MONOTONIC | ClockHealthFlags::NO_BACKWARDS_STEP,
        );

        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        // But the evidence still has a wall-clock timebase.
        assert!(timebase_supports_wall_clock(evidence.timebase));
        // The refusal should map correctly.
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::UnknownSkew),
            StorageIntentRefusalReason::UnknownClockSkew
        );
    }

    #[test]
    fn unknown_clock_skew_cannot_satisfy_freshness() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.clock_health.skew_bound_us = 0;
        evidence.clock_health.flags = ClockHealthFlags::EMPTY;

        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
    }

    #[test]
    fn backwards_clock_step_cannot_satisfy_wall_clock_claims() {
        let mut evidence = healthy_wall_clock_timebase();
        // Remove NO_BACKWARDS_STEP flag — simulates a backwards clock step.
        evidence.clock_health.flags =
            ClockHealthFlags::from_flag(ClockHealthFlags::MONOTONIC | ClockHealthFlags::KNOWN_SKEW);

        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        assert!(!temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 7_200_000, 5000
        ));

        // Map backwards time to the policy refusal.
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::BackwardsTime),
            StorageIntentRefusalReason::BackwardsClockStep
        );
    }

    #[test]
    fn stale_clock_health_sample_cannot_satisfy_freshness() {
        let evidence = healthy_wall_clock_timebase();
        // Sample age is 1000 ms, max is 500 ms -> stale.
        assert!(!clock_health_is_fresh_for_authority(
            evidence.clock_health,
            500
        ));
        // But with generous max sample age, it's fresh.
        assert!(clock_health_is_fresh_for_authority(
            evidence.clock_health,
            2000
        ));

        // Stale sample makes all wall-clock claims fail.
        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 500
        ));
    }

    #[test]
    fn expired_temporal_lease_cannot_satisfy_expiry_claim() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.expiry_deadline_class = StorageIntentExpiryDeadlineClass::KeyLeaseExpiry;
        evidence.expiry_deadline_ref =
            temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 10);

        // Deadline is 10000 ms, now is 15000 ms — expired.
        assert!(!temporal_evidence_supports_expiry_claim(
            evidence, 10000, 15000, 5000
        ));

        // Map crossed expiry to policy refusal.
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::CrossedExpiry),
            StorageIntentRefusalReason::ExpiredTemporalLease
        );
    }

    #[test]
    fn crossed_policy_stage_deadline_cannot_satisfy_freshness() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.expiry_deadline_class =
            StorageIntentExpiryDeadlineClass::PolicyRolloutStageDeadline;
        evidence.expiry_deadline_ref =
            temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 11);

        // Deadline has passed.
        assert!(!temporal_evidence_supports_expiry_claim(
            evidence, 10000, 15000, 5000
        ));
    }

    #[test]
    fn missing_remote_apply_frontier_cannot_satisfy_rpo() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.event_frontier = StorageIntentEventFrontierClass::CommittedRoot;

        // RPO requires RemoteApply frontier.
        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
    }

    #[test]
    fn sequence_only_lag_cannot_satisfy_wall_clock_rpo() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.timebase = StorageIntentTimebaseClass::SequenceOnly;

        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        assert!(!temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 7_200_000, 5000
        ));

        assert!(timebase_is_sequence_only(evidence.timebase));
        assert!(!timebase_supports_wall_clock(evidence.timebase));

        // Map insufficient sequence to policy refusal.
        assert_eq!(
            temporal_refusal_to_policy_refusal(
                StorageIntentTemporalRefusalReason::InsufficientSequenceFrontier
            ),
            StorageIntentRefusalReason::SequenceOnlyCannotSatisfyWallClockRpo
        );
    }

    #[test]
    fn sequence_only_lag_cannot_satisfy_wall_clock_freshness() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.timebase = StorageIntentTimebaseClass::SequenceLogFrontier;

        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        // But cooldown claims can work with local monotonic time.
        assert!(timebase_is_sequence_only(evidence.timebase));
    }

    #[test]
    fn local_monotonic_supports_cooldown_but_not_cross_node() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.timebase = StorageIntentTimebaseClass::LocalMonotonic;
        evidence.expiry_deadline_class = StorageIntentExpiryDeadlineClass::CooldownWindow;
        evidence.expiry_deadline_ref =
            temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 12);

        // Local cooldown with local monotonic time is valid.
        assert!(temporal_evidence_supports_cooldown_claim(
            evidence, 5000, 10000, false
        ));
        // Cross-node cooldown needs wall-clock.
        assert!(!temporal_evidence_supports_cooldown_claim(
            evidence, 5000, 10000, true
        ));
    }

    #[test]
    fn unbound_temporal_evidence_rejected() {
        let evidence = StorageIntentTemporalEvidence::default();
        assert!(!evidence.has_temporal_evidence());
        assert!(!evidence.has_timebase());
        assert!(!evidence.has_clock_health());
        assert!(!evidence.has_event_frontier());
        assert!(!evidence.has_lag_staleness());
        assert!(!evidence.has_expiry_deadline());
        assert!(!evidence.has_sequence_conversion());
        assert!(!evidence.is_refused());

        // All predicates must return false for unbound evidence.
        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        assert!(!temporal_evidence_supports_expiry_claim(
            evidence, 10000, 5000, 5000
        ));
        assert!(!temporal_evidence_supports_cooldown_claim(
            evidence, 5000, 10000, false
        ));
        assert!(!temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 3_600_000, 5000
        ));
    }

    #[test]
    fn refused_temporal_evidence_blocks_all_claims() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.refusal = StorageIntentTemporalRefusalReason::MissingTimebase;

        assert!(evidence.is_refused());
        assert!(!temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        assert!(!temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        assert!(!temporal_evidence_supports_expiry_claim(
            evidence, 10000, 5000, 5000
        ));
    }

    #[test]
    fn temporal_evidence_age_requires_wall_clock_and_known_skew() {
        let evidence = healthy_wall_clock_timebase();
        assert_eq!(
            temporal_evidence_age_ms(evidence, 20000, 10000),
            Some(10000)
        );

        // Backwards time returns None.
        assert_eq!(temporal_evidence_age_ms(evidence, 5000, 10000), None);

        // Missing skew returns None.
        let mut no_skew = evidence;
        no_skew.clock_health.skew_bound_us = 0;
        assert_eq!(temporal_evidence_age_ms(no_skew, 20000, 10000), None);

        // Sequence-only returns None.
        let mut seq = evidence;
        seq.timebase = StorageIntentTimebaseClass::SequenceOnly;
        assert_eq!(temporal_evidence_age_ms(seq, 20000, 10000), None);
    }

    #[test]
    fn temporal_refusal_reasons_map_to_policy_refusals() {
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::None),
            StorageIntentRefusalReason::None
        );
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::MissingTimebase),
            StorageIntentRefusalReason::MissingTemporalEvidence
        );
        assert_eq!(
            temporal_refusal_to_policy_refusal(StorageIntentTemporalRefusalReason::StaleSample),
            StorageIntentRefusalReason::StaleClockHealthSample
        );
        assert_eq!(
            temporal_refusal_to_policy_refusal(
                StorageIntentTemporalRefusalReason::ContradictoryFrontier
            ),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
        assert_eq!(
            temporal_refusal_to_policy_refusal(
                StorageIntentTemporalRefusalReason::UnsupportedCrossDomainComparison
            ),
            StorageIntentRefusalReason::EvidenceNotUsable
        );
    }

    #[test]
    fn timebase_enums_encode_decode_roundtrip() {
        let timebases = [
            StorageIntentTimebaseClass::Unknown,
            StorageIntentTimebaseClass::LocalMonotonic,
            StorageIntentTimebaseClass::LocalWallClock,
            StorageIntentTimebaseClass::ClusterConsensusTime,
            StorageIntentTimebaseClass::RemoteWallClock,
            StorageIntentTimebaseClass::SequenceLogFrontier,
            StorageIntentTimebaseClass::SequenceOnly,
        ];
        for tb in &timebases {
            let disc = tb.to_discriminant();
            let decoded = StorageIntentTimebaseClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*tb), "roundtrip failed for {:?}", tb.as_str());
        }
        assert_eq!(StorageIntentTimebaseClass::from_discriminant(255), None);
    }

    #[test]
    fn temporal_refusal_enums_encode_decode_roundtrip() {
        let refusals = [
            StorageIntentTemporalRefusalReason::None,
            StorageIntentTemporalRefusalReason::MissingTimebase,
            StorageIntentTemporalRefusalReason::UnknownSkew,
            StorageIntentTemporalRefusalReason::StaleSample,
            StorageIntentTemporalRefusalReason::CrossedExpiry,
            StorageIntentTemporalRefusalReason::ContradictoryFrontier,
            StorageIntentTemporalRefusalReason::BackwardsTime,
            StorageIntentTemporalRefusalReason::InsufficientSequenceFrontier,
            StorageIntentTemporalRefusalReason::UnsupportedCrossDomainComparison,
        ];
        for r in &refusals {
            let disc = r.to_discriminant();
            let decoded = StorageIntentTemporalRefusalReason::from_discriminant(disc);
            assert_eq!(decoded, Some(*r), "roundtrip failed for {:?}", r.as_str());
        }
        assert_eq!(
            StorageIntentTemporalRefusalReason::from_discriminant(255),
            None
        );
    }

    #[test]
    fn clock_health_flags_combine_and_test() {
        let flags =
            ClockHealthFlags::from_flag(ClockHealthFlags::MONOTONIC | ClockHealthFlags::KNOWN_SKEW);
        assert!(flags.contains_all(ClockHealthFlags::MONOTONIC));
        assert!(flags.contains_all(ClockHealthFlags::KNOWN_SKEW));
        assert!(!flags.contains_all(ClockHealthFlags::NO_BACKWARDS_STEP));
        assert!(flags.intersects(ClockHealthFlags::MONOTONIC));
        assert!(!flags.intersects(ClockHealthFlags::NO_LEAP_SECOND_PENDING));

        let all = ClockHealthFlags::from_flag(ClockHealthFlags::ALL_DEFINED);
        assert!(all.contains_all(ClockHealthFlags::MONOTONIC));
        assert!(all.contains_all(ClockHealthFlags::NO_STEP_ADJUSTMENT));
    }

    #[test]
    fn sequence_time_conversion_validates_rate_and_bounds() {
        let conv = StorageIntentSequenceTimeConversion {
            rate_bytes_per_sec: 100_000_000,
            observation_window_ms: 60_000,
            uncertainty_bound_ms: 500,
            conservative_bound_ms: 5000,
            conversion_ref: temporal_evidence_ref(StorageIntentEvidenceKind::TemporalEvidence, 20),
        };
        assert!(conv.has_evidence());
        assert!(conv.has_conservative_rate());

        let empty = StorageIntentSequenceTimeConversion::default();
        assert!(!empty.has_evidence());
        assert!(!empty.has_conservative_rate());
    }

    #[test]
    fn ttl_claim_fails_on_sequence_only_timebase() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.timebase = StorageIntentTimebaseClass::SequenceOnly;
        assert!(!temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 7_200_000, 5000
        ));
    }

    #[test]
    fn ttl_claim_fails_on_backwards_clock_step() {
        let mut evidence = healthy_wall_clock_timebase();
        evidence.clock_health.flags = ClockHealthFlags::from_flag(ClockHealthFlags::KNOWN_SKEW);
        // Missing NO_BACKWARDS_STEP.
        assert!(!temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 7_200_000, 5000
        ));
    }

    #[test]
    fn healthy_temporal_evidence_satisfies_all_wall_clock_claims() {
        let evidence = healthy_wall_clock_timebase();
        assert!(evidence.has_temporal_evidence());
        assert!(evidence.has_timebase());
        assert!(evidence.has_clock_health());
        assert!(evidence.has_event_frontier());
        assert!(evidence.has_lag_staleness());

        // Known skew, no backwards step, wall-clock timebase, fresh sample.
        assert!(temporal_evidence_supports_wall_clock_rpo(
            evidence, 5000, 1000, 5000
        ));
        assert!(temporal_evidence_supports_freshness_claim(
            evidence, 30000, 5000
        ));
        assert!(temporal_evidence_supports_ttl_claim(
            evidence, 3_600_000, 7_200_000, 5000
        ));
        assert_eq!(
            temporal_evidence_age_ms(evidence, 20000, 10000),
            Some(10000)
        );
    }

    // ===== Policy Rollout Evidence tests (Issue #901) =====

    fn rollout_evidence_ref(byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = byte;
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::PolicyRolloutEvidence,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn publication_ref(byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = byte;
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::LocalIntentRecord,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn preflight_ref(byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = byte;
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::PreflightSimulationEvidence,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn query_snapshot_ref(byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = byte;
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::EvidenceQuerySnapshot,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn authz_ref(byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = byte;
        StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::TrustDomainEvidence,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn build_rollout_base() -> StorageIntentPolicyRolloutEvidence {
        let mut compiled_id = [0_u8; 16];
        compiled_id[0] = 1;
        StorageIntentPolicyRolloutEvidence {
            evidence_ref: rollout_evidence_ref(1),
            compiled_policy_id: StorageIntentPolicyId(compiled_id),
            compiled_policy_revision: StorageIntentPolicyRevision(1),
            previous_policy_id: StorageIntentPolicyId::ZERO,
            previous_policy_revision: StorageIntentPolicyRevision(0),
            target_policy_id: StorageIntentPolicyId::ZERO,
            target_policy_revision: StorageIntentPolicyRevision(0),
            policy_epoch: 1,
            source_policy_ref: StorageIntentEvidenceRef::default(),
            source_provenance_mask: 0,
            source_provenance_refs: StorageIntentEvidenceRefs::default(),
            publication_transaction_ref: publication_ref(1),
            change_class: StorageIntentPolicyChangeClass::Strengthen,
            downgrade_authorization_ref: StorageIntentEvidenceRef::default(),
            stage_state: StorageIntentPolicyStageState::Draft,
            scope_selector: StorageIntentObjectScope::default(),
            old_receipt_treatment: StorageIntentOldReceiptTreatment::Grandfathered,
            in_flight_fence_flags: StorageIntentInFlightOperationFlags::EMPTY,
            in_flight_fence_ref: StorageIntentEvidenceRef::default(),
            convergence_frontier_ref: StorageIntentEvidenceRef::default(),
            replacement_receipt_set_ref: StorageIntentEvidenceRef::default(),
            outstanding_obligation_ref: StorageIntentEvidenceRef::default(),
            old_revision_retention_ref: StorageIntentEvidenceRef::default(),
            safe_retirement_evidence_ref: StorageIntentEvidenceRef::default(),
            rollback_reentry_ref: StorageIntentEvidenceRef::default(),
            supersession_ref: StorageIntentEvidenceRef::default(),
            refusal_reason: StorageIntentRolloutRefusalReason::None,
            preflight_evidence_ref: StorageIntentEvidenceRef::default(),
            temporal_evidence_ref: StorageIntentEvidenceRef::default(),
            evidence_query_snapshot_ref: StorageIntentEvidenceRef::default(),
            action_execution_evidence_ref: StorageIntentEvidenceRef::default(),
            result_refusal_evidence_ref: StorageIntentEvidenceRef::default(),
            measurement_attribution_evidence_ref: StorageIntentEvidenceRef::default(),
            feedback_window_ref: StorageIntentEvidenceRef::default(),
            tenant_isolation_evidence_ref: StorageIntentEvidenceRef::default(),
            capacity_admission_evidence_ref: StorageIntentEvidenceRef::default(),
            decision_frontier_evidence_ref: StorageIntentEvidenceRef::default(),
            membership_evidence_ref: StorageIntentEvidenceRef::default(),
            trust_domain_evidence_ref: StorageIntentEvidenceRef::default(),
            recovery_evidence_ref: StorageIntentEvidenceRef::default(),
            media_capability_evidence_ref: StorageIntentEvidenceRef::default(),
            metadata_namespace_evidence_ref: StorageIntentEvidenceRef::default(),
        }
    }

    // ── Recovery/degradation evidence model tests (#900) ── //

    fn recovery_evidence_ref(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::RecoveryDegradationEvidence, byte)
    }

    fn placement_receipt_ref(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::PlacementReceipt, byte)
    }

    fn capacity_ref(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::CapacityAdmissionEvidence, byte)
    }

    fn ordering_ref(byte: u8) -> StorageIntentEvidenceRef {
        evidence_ref(StorageIntentEvidenceKind::OrderingEvidence, byte)
    }

    fn healthy_recovery_evidence() -> StorageIntentRecoveryDegradationEvidence {
        StorageIntentRecoveryDegradationEvidence {
            evidence_ref: recovery_evidence_ref(1),
            degradation_policy: StorageIntentDegradationPolicy {
                visibility: StorageIntentDegradationVisibility::Visible,
                refusal_law: StorageIntentDegradationRefusalLaw::ServeDegradedReadsOnly,
                policy_ref: placement_receipt_ref(10),
                policy_revision: StorageIntentPolicyRevision(1),
            },
            degradation: StorageIntentDegradationClass::Exact,
            source_receipt_set_ref: placement_receipt_ref(20),
            receipt_generation: 3,
            redundancy_width: 3,
            reconstruction_width: 2,
            payload_digest_ref: evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 30),
            source_freshness_ms: 5000,
            source_freshness_known: true,
            target_present: 3,
            target_missing: 0,
            target_corrupt: 0,
            target_stale: 0,
            target_quarantined: 0,
            target_fenced: 0,
            target_drained: 0,
            target_wrong_domain: 0,
            target_under_width: 0,
            target_unreachable: 0,
            read_repair_ref: StorageIntentEvidenceRef::default(),
            scrub_finding_ref: StorageIntentEvidenceRef::default(),
            repair_ticket_ref: StorageIntentEvidenceRef::default(),
            rebuild_ticket_ref: StorageIntentEvidenceRef::default(),
            relocation_overlap_ref: StorageIntentEvidenceRef::default(),
            replacement_receipt_ref: StorageIntentEvidenceRef::default(),
            flow_commit_ref: StorageIntentEvidenceRef::default(),
            old_receipt_retirement_ref: StorageIntentEvidenceRef::default(),
            partition_evidence_ref: StorageIntentEvidenceRef::default(),
            membership_epoch_ref: StorageIntentEvidenceRef::default(),
            fence_ref: StorageIntentEvidenceRef::default(),
            quorum_set_ref: StorageIntentEvidenceRef::default(),
            witness_role_ref: StorageIntentEvidenceRef::default(),
            data_role_ref: StorageIntentEvidenceRef::default(),
            split_brain_hazard: StorageIntentSplitBrainHazard::None,
            trust_domain_ref: StorageIntentEvidenceRef::default(),
            key_epoch_ref: StorageIntentEvidenceRef::default(),
            authorization_ref: StorageIntentEvidenceRef::default(),
            audit_ref: StorageIntentEvidenceRef::default(),
            residency_ref: StorageIntentEvidenceRef::default(),
            quarantine_ref: StorageIntentEvidenceRef::default(),
            repair_publication_ref: StorageIntentEvidenceRef::default(),
            rebuild_completion_ref: StorageIntentEvidenceRef::default(),
            replacement_publication_ref: StorageIntentEvidenceRef::default(),
            receipt_retirement_ordering_ref: StorageIntentEvidenceRef::default(),
            read_repair_capacity_ref: capacity_ref(40),
            rebuild_scratch_capacity_ref: StorageIntentEvidenceRef::default(),
            evacuation_capacity_ref: StorageIntentEvidenceRef::default(),
            geo_backlog_capacity_ref: StorageIntentEvidenceRef::default(),
            receipt_retirement_capacity_ref: StorageIntentEvidenceRef::default(),
            recovery_priority: StorageIntentRecoveryPriorityClass::Normal,
            rpo_lag_ms: 0,
            rto_lag_ms: 10000,
            repair_debt_bytes: 0,
            degraded_read_foreground_cost_us: 0,
            retry_cooldown_ms: 0,
            refusal: StorageIntentRecoveryRefusalReason::None,
            refusal_ref: StorageIntentEvidenceRef::default(),
        }
    }

    #[test]
    fn rollout_change_class_enums_encode_decode_roundtrip() {
        let classes = [
            StorageIntentPolicyChangeClass::Unknown,
            StorageIntentPolicyChangeClass::Strengthen,
            StorageIntentPolicyChangeClass::Weaken,
            StorageIntentPolicyChangeClass::Lateral,
            StorageIntentPolicyChangeClass::Incompatible,
            StorageIntentPolicyChangeClass::EmergencyOverride,
            StorageIntentPolicyChangeClass::Rollback,
            StorageIntentPolicyChangeClass::ReEntry,
            StorageIntentPolicyChangeClass::Retirement,
        ];
        for c in &classes {
            let disc = c.to_discriminant();
            let decoded = StorageIntentPolicyChangeClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*c), "roundtrip failed for {:?}", c.as_str());
        }
        assert_eq!(StorageIntentPolicyChangeClass::from_discriminant(255), None);
    }

    #[test]
    fn rollout_weakening_classes_require_authorization() {
        assert!(StorageIntentPolicyChangeClass::Weaken.is_weakening());
        assert!(StorageIntentPolicyChangeClass::Incompatible.is_weakening());
        assert!(StorageIntentPolicyChangeClass::EmergencyOverride.is_weakening());
        assert!(!StorageIntentPolicyChangeClass::Strengthen.is_weakening());
        assert!(!StorageIntentPolicyChangeClass::Lateral.is_weakening());
        assert!(!StorageIntentPolicyChangeClass::Rollback.is_weakening());
    }

    #[test]
    fn rollout_weakening_classes_require_downgrade_authz() {
        assert!(StorageIntentPolicyChangeClass::Weaken.requires_downgrade_authorization());
        assert!(StorageIntentPolicyChangeClass::Incompatible.requires_downgrade_authorization());
        assert!(StorageIntentPolicyChangeClass::EmergencyOverride.requires_downgrade_authorization());
        assert!(!StorageIntentPolicyChangeClass::Strengthen.requires_downgrade_authorization());
    }

    #[test]
    fn rollout_stage_state_enums_encode_decode_roundtrip() {
        let states = [
            StorageIntentPolicyStageState::Unknown,
            StorageIntentPolicyStageState::Draft,
            StorageIntentPolicyStageState::DryRun,
            StorageIntentPolicyStageState::PreflightAdmitted,
            StorageIntentPolicyStageState::Staged,
            StorageIntentPolicyStageState::ActiveForNewWrites,
            StorageIntentPolicyStageState::ConvergingExisting,
            StorageIntentPolicyStageState::Blocked,
            StorageIntentPolicyStageState::RollbackRequired,
            StorageIntentPolicyStageState::RolledBack,
            StorageIntentPolicyStageState::Superseded,
            StorageIntentPolicyStageState::Retired,
            StorageIntentPolicyStageState::Refused,
        ];
        for s in &states {
            let disc = s.to_discriminant();
            let decoded = StorageIntentPolicyStageState::from_discriminant(disc);
            assert_eq!(decoded, Some(*s), "roundtrip failed for {:?}", s.as_str());
        }
        assert_eq!(StorageIntentPolicyStageState::from_discriminant(255), None);
    }

    #[test]
    fn rollout_active_states_admit_new_writes() {
        assert!(StorageIntentPolicyStageState::ActiveForNewWrites.admits_new_writes());
        assert!(StorageIntentPolicyStageState::ConvergingExisting.admits_new_writes());
        assert!(!StorageIntentPolicyStageState::Draft.admits_new_writes());
        assert!(!StorageIntentPolicyStageState::DryRun.admits_new_writes());
        assert!(!StorageIntentPolicyStageState::Staged.admits_new_writes());
        assert!(!StorageIntentPolicyStageState::Refused.admits_new_writes());
    }

    #[test]
    fn rollout_terminal_states_are_terminal() {
        assert!(StorageIntentPolicyStageState::Superseded.is_terminal());
        assert!(StorageIntentPolicyStageState::Retired.is_terminal());
        assert!(StorageIntentPolicyStageState::Refused.is_terminal());
        assert!(!StorageIntentPolicyStageState::ActiveForNewWrites.is_terminal());
    }

    #[test]
    fn old_receipt_treatment_enums_encode_decode_roundtrip() {
        let treatments = [
            StorageIntentOldReceiptTreatment::Unknown,
            StorageIntentOldReceiptTreatment::Grandfathered,
            StorageIntentOldReceiptTreatment::RequireConvergence,
            StorageIntentOldReceiptTreatment::UnusableForNewClaims,
            StorageIntentOldReceiptTreatment::Refuse,
        ];
        for t in &treatments {
            let disc = t.to_discriminant();
            let decoded = StorageIntentOldReceiptTreatment::from_discriminant(disc);
            assert_eq!(decoded, Some(*t), "roundtrip failed for {:?}", t.as_str());
        }
        assert_eq!(StorageIntentOldReceiptTreatment::from_discriminant(255), None);
    }

    #[test]
    fn rollout_refusal_reason_enums_encode_decode_roundtrip() {
        let reasons = [
            StorageIntentRolloutRefusalReason::None,
            StorageIntentRolloutRefusalReason::StalePolicySource,
            StorageIntentRolloutRefusalReason::ConflictingOverrides,
            StorageIntentRolloutRefusalReason::MissingDowngradeAuthorization,
            StorageIntentRolloutRefusalReason::UnsafeDowngrade,
            StorageIntentRolloutRefusalReason::InFlightFenceFailure,
            StorageIntentRolloutRefusalReason::ConvergenceDebt,
            StorageIntentRolloutRefusalReason::ValidationGateFailure,
            StorageIntentRolloutRefusalReason::UnsupportedCombination,
            StorageIntentRolloutRefusalReason::MissingPreflightEvidence,
            StorageIntentRolloutRefusalReason::StalePreflightEvidence,
            StorageIntentRolloutRefusalReason::MissingEvidenceQuerySnapshot,
            StorageIntentRolloutRefusalReason::MissingTemporalEvidence,
            StorageIntentRolloutRefusalReason::StageDeadlineCrossed,
            StorageIntentRolloutRefusalReason::MissingRunbookStep,
        ];
        for r in &reasons {
            let disc = r.to_discriminant();
            let decoded = StorageIntentRolloutRefusalReason::from_discriminant(disc);
            assert_eq!(decoded, Some(*r), "roundtrip failed for {:?}", r.as_str());
        }
        assert_eq!(StorageIntentRolloutRefusalReason::from_discriminant(255), None);
    }

    #[test]
    fn in_flight_flags_combine_and_test() {
        let fenced = StorageIntentInFlightOperationFlags::WRITES
            .with(StorageIntentInFlightOperationFlags::FSYNC_FUA);
        assert!(fenced.has(StorageIntentInFlightOperationFlags::WRITES));
        assert!(fenced.has(StorageIntentInFlightOperationFlags::FSYNC_FUA));
        assert!(!fenced.has(StorageIntentInFlightOperationFlags::RELOCATION));
        assert!(fenced.fenced_new_writes());
        assert!(!fenced.has_any_background_fence());
    }

    #[test]
    fn rollout_has_compiled_policy_when_bound() {
        let evidence = build_rollout_base();
        assert!(evidence.has_compiled_policy());
        assert!(evidence.has_publication_transaction());
    }

    #[test]
    fn rollout_default_is_not_compiled() {
        let evidence = StorageIntentPolicyRolloutEvidence::default();
        assert!(!evidence.has_compiled_policy());
        assert!(!evidence.has_publication_transaction());
    }

    #[test]
    fn rollout_publication_is_not_activation_law() {
        let evidence = build_rollout_base();
        // Published but not yet active.
        assert!(rollout_publication_is_not_activation(evidence));
        assert!(!evidence.stage_state.admits_new_writes());
    }

    #[test]
    fn test_activation_requires_publication_scope_stage_fence() {
        let mut evidence = build_rollout_base();
        // Missing scope, stage, fence.
        assert!(!rollout_activation_requires_publication_scope_stage_fence(evidence));

        // Add publication, scope, stage, and mark not refused.
        evidence.publication_transaction_ref = publication_ref(2);
        evidence.scope_selector.dataset_id = StorageIntentDomainId([1_u8; 16]);
        evidence.stage_state = StorageIntentPolicyStageState::ActiveForNewWrites;
        assert!(!rollout_activation_requires_publication_scope_stage_fence(evidence));

        evidence.in_flight_fence_flags = StorageIntentInFlightOperationFlags::ALL_NEW_WRITE;
        evidence.in_flight_fence_ref = rollout_evidence_ref(3);
        assert!(rollout_activation_requires_publication_scope_stage_fence(evidence));
    }

    #[test]
    fn rollout_strengthen_new_writes_only_law() {
        let mut evidence = build_rollout_base();
        evidence.change_class = StorageIntentPolicyChangeClass::Strengthen;
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::Grandfathered;
        assert!(rollout_strengthen_new_writes_only(evidence));

        // Grandfathered is valid for strengthen.
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::RequireConvergence;
        assert!(rollout_strengthen_new_writes_only(evidence));

        // Refuse is not valid for strengthen.
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::Refuse;
        assert!(!rollout_strengthen_new_writes_only(evidence));
    }

    #[test]
    fn rollout_weaken_requires_authorization_law() {
        let mut evidence = build_rollout_base();
        evidence.change_class = StorageIntentPolicyChangeClass::Strengthen;
        // Strengthen does not require downgrade authorization.
        assert!(rollout_weaken_requires_authorization_and_audit(evidence));

        evidence.change_class = StorageIntentPolicyChangeClass::Weaken;
        // Weaken with missing authorization ref should fail.
        assert!(!rollout_weaken_requires_authorization_and_audit(evidence));

        evidence.downgrade_authorization_ref = authz_ref(1);
        assert!(rollout_weaken_requires_authorization_and_audit(evidence));
    }

    #[test]
    fn test_operation_chooses_revision_by_receipt_and_fence() {
        let mut evidence = build_rollout_base();
        evidence.in_flight_fence_flags = StorageIntentInFlightOperationFlags::WRITES;
        let old_revision = StorageIntentPolicyRevision(0);

        // Fenced write without a fence record cannot select the new revision.
        assert!(!rollout_operation_chooses_revision_by_receipt_and_fence(
            evidence,
            old_revision,
            StorageIntentInFlightOperationFlags::WRITES,
        ));

        evidence.in_flight_fence_ref = rollout_evidence_ref(11);
        // Fenced write under new revision — operation is fenced, so true.
        assert!(rollout_operation_chooses_revision_by_receipt_and_fence(
            evidence,
            old_revision,
            StorageIntentInFlightOperationFlags::WRITES,
        ));

        // Non-fenced operation with old receipt revision — uses receipt identity.
        assert!(rollout_operation_chooses_revision_by_receipt_and_fence(
            evidence,
            StorageIntentPolicyRevision(7),
            StorageIntentInFlightOperationFlags::RELOCATION,
        ));
        assert!(!rollout_operation_chooses_revision_by_receipt_and_fence(
            evidence,
            StorageIntentPolicyRevision(0),
            StorageIntentInFlightOperationFlags::RELOCATION,
        ));
        assert!(!rollout_operation_chooses_revision_by_receipt_and_fence(
            evidence,
            StorageIntentPolicyRevision(7),
            StorageIntentInFlightOperationFlags::EMPTY,
        ));
    }

    #[test]
    fn test_relocation_crosses_revision_boundary() {
        let mut evidence = build_rollout_base();
        let old_revision = StorageIntentPolicyRevision(0);

        // Same revision — no boundary crossing.
        assert!(!rollout_relocation_crosses_revision_boundary(evidence, StorageIntentPolicyRevision(1)));

        // Different revision without replacement receipt set — fails.
        assert!(!rollout_relocation_crosses_revision_boundary(evidence, old_revision));

        // Add replacement receipt set and outstanding obligation refs.
        evidence.replacement_receipt_set_ref = rollout_evidence_ref(2);
        evidence.outstanding_obligation_ref = rollout_evidence_ref(3);
        assert!(rollout_relocation_crosses_revision_boundary(evidence, old_revision));
    }

    #[test]
    fn test_rollback_is_receipt_producing() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::RolledBack;
        let mut target_id = [0_u8; 16];
        target_id[0] = 2;
        evidence.target_policy_id = StorageIntentPolicyId(target_id);
        evidence.target_policy_revision = StorageIntentPolicyRevision(2);
        evidence.rollback_reentry_ref = rollout_evidence_ref(10);
        assert!(rollout_rollback_is_receipt_producing(evidence));
    }

    #[test]
    fn test_superseded_remains_visible() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Superseded;
        evidence.supersession_ref = rollout_evidence_ref(11);
        assert!(rollout_superseded_remains_visible_until_clean(evidence));
    }

    #[test]
    fn rollout_stage_transition_draft_to_dry_run() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Draft;
        assert!(rollout_can_transition_draft_to_dry_run(evidence));

        // Missing publication ref blocks transition.
        evidence.publication_transaction_ref = StorageIntentEvidenceRef::default();
        assert!(!rollout_can_transition_draft_to_dry_run(evidence));
    }

    #[test]
    fn rollout_stage_transition_dry_run_to_preflight_admitted() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::DryRun;
        evidence.preflight_evidence_ref = preflight_ref(1);
        evidence.evidence_query_snapshot_ref = query_snapshot_ref(1);
        assert!(rollout_can_transition_dry_run_to_preflight_admitted(evidence));
    }

    #[test]
    fn rollout_stage_transition_preflight_admitted_to_staged() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::PreflightAdmitted;
        evidence.scope_selector.dataset_id = StorageIntentDomainId([1_u8; 16]);
        evidence.change_class = StorageIntentPolicyChangeClass::Strengthen;
        evidence.in_flight_fence_ref = rollout_evidence_ref(1);
        evidence.in_flight_fence_flags = StorageIntentInFlightOperationFlags::WRITES;
        assert!(rollout_can_transition_preflight_admitted_to_staged(evidence));

        // Weaken without authorization blocks.
        evidence.change_class = StorageIntentPolicyChangeClass::Weaken;
        assert!(!rollout_can_transition_preflight_admitted_to_staged(evidence));

        // Weaken with authorization passes.
        evidence.downgrade_authorization_ref = authz_ref(1);
        assert!(rollout_can_transition_preflight_admitted_to_staged(evidence));
    }

    #[test]
    fn rollout_stage_transition_staged_to_active() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Staged;
        evidence.scope_selector.dataset_id = StorageIntentDomainId([1_u8; 16]);
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::Grandfathered;
        assert!(rollout_can_transition_staged_to_active(evidence));
    }

    #[test]
    fn rollout_can_become_blocked_from_staged_or_active() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Staged;
        assert!(rollout_can_become_blocked(evidence));

        evidence.stage_state = StorageIntentPolicyStageState::ActiveForNewWrites;
        assert!(rollout_can_become_blocked(evidence));

        evidence.stage_state = StorageIntentPolicyStageState::ConvergingExisting;
        assert!(rollout_can_become_blocked(evidence));

        evidence.stage_state = StorageIntentPolicyStageState::Draft;
        assert!(!rollout_can_become_blocked(evidence));
    }

    #[test]
    fn rollout_blocked_to_rollback_required() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Blocked;
        assert!(rollout_can_transition_blocked_to_rollback_required(evidence));
    }

    #[test]
    fn rollout_rollback_required_to_rolled_back() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::RollbackRequired;
        // Missing rollback reentry ref — cannot complete rollback.
        assert!(!rollout_can_transition_rollback_required_to_rolled_back(evidence));

        evidence.rollback_reentry_ref = rollout_evidence_ref(20);
        assert!(rollout_can_transition_rollback_required_to_rolled_back(evidence));
    }

    #[test]
    fn rollout_superseded_to_retired() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Superseded;
        // Missing retention/retirement proof — cannot retire.
        assert!(!rollout_can_transition_superseded_to_retired(evidence));

        evidence.old_revision_retention_ref =
            evidence_ref(StorageIntentEvidenceKind::EvidenceRetentionEvidence, 31);
        evidence.safe_retirement_evidence_ref =
            evidence_ref(StorageIntentEvidenceKind::LifecycleGenerationEvidence, 32);
        // No outstanding obligations and retention/retirement proof — can retire.
        assert!(rollout_can_transition_superseded_to_retired(evidence));

        // With outstanding obligations — cannot retire.
        evidence.outstanding_obligation_ref = rollout_evidence_ref(30);
        assert!(!rollout_can_transition_superseded_to_retired(evidence));
    }

    #[test]
    fn test_fence_splits_new_and_old_writes() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::ActiveForNewWrites;
        evidence.in_flight_fence_flags = StorageIntentInFlightOperationFlags::WRITES
            .with(StorageIntentInFlightOperationFlags::FSYNC_FUA);
        assert!(rollout_fence_splits_new_and_old_writes(evidence));
    }

    #[test]
    fn test_permits_reading_old_receipts() {
        let mut evidence = build_rollout_base();
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::Grandfathered;
        assert!(rollout_permits_reading_old_receipts(evidence));

        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::Refuse;
        assert!(!rollout_permits_reading_old_receipts(evidence));
    }

    #[test]
    fn test_requires_replacement_receipts_for_old_generations() {
        let mut evidence = build_rollout_base();
        evidence.old_receipt_treatment = StorageIntentOldReceiptTreatment::RequireConvergence;
        evidence.replacement_receipt_set_ref = rollout_evidence_ref(40);
        assert!(rollout_requires_replacement_receipts_for_old_generations(evidence));

        evidence.replacement_receipt_set_ref = StorageIntentEvidenceRef::default();
        assert!(!rollout_requires_replacement_receipts_for_old_generations(evidence));
    }

    #[test]
    fn rollout_is_refused_when_stage_state_is_refused() {
        let mut evidence = build_rollout_base();
        evidence.stage_state = StorageIntentPolicyStageState::Refused;
        assert!(evidence.is_refused());
    }

    #[test]
    fn rollout_is_refused_when_refusal_reason_is_present() {
        let mut evidence = build_rollout_base();
        evidence.refusal_reason = StorageIntentRolloutRefusalReason::UnsafeDowngrade;
        assert!(evidence.is_refused());
    }

    #[test]
    fn rollout_has_downgrade_authorization_if_required() {
        let mut evidence = build_rollout_base();
        // Strengthen does not require authorization.
        evidence.change_class = StorageIntentPolicyChangeClass::Strengthen;
        assert!(evidence.has_downgrade_authorization_if_required());

        // Weaken without authorization fails.
        evidence.change_class = StorageIntentPolicyChangeClass::Weaken;
        assert!(!evidence.has_downgrade_authorization_if_required());

        // Weaken with authorization passes.
        evidence.downgrade_authorization_ref = authz_ref(1);
        assert!(evidence.has_downgrade_authorization_if_required());
    }

    #[test]
    fn rollout_change_class_display_outputs_stable_spelling() {
        assert_eq!(
            StorageIntentPolicyChangeClass::Strengthen.as_str(),
            "strengthen"
        );
        assert_eq!(
            StorageIntentPolicyChangeClass::Weaken.as_str(),
            "weaken"
        );
    }

    #[test]
    fn rollout_stage_display_outputs_stable_spelling() {
        assert_eq!(
            StorageIntentPolicyStageState::ActiveForNewWrites.as_str(),
            "active-for-new-writes"
        );
        assert_eq!(
            StorageIntentPolicyStageState::RolledBack.as_str(),
            "rolled-back"
        );
    }

    // -----------------------------------------------------------------------
    // Data-shape type tests (issue #878)
    // -----------------------------------------------------------------------

    #[test]
    fn record_size_class_enums_encode_decode_roundtrip() {
        let classes = [
            RecordSizeClass::Unknown,
            RecordSizeClass::Tiny,
            RecordSizeClass::Small,
            RecordSizeClass::Medium,
            RecordSizeClass::Large,
            RecordSizeClass::Huge,
            RecordSizeClass::RangeOverride,
        ];
        for c in &classes {
            let disc = c.to_discriminant();
            let decoded = RecordSizeClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*c), "roundtrip failed for {:?}", c.as_str());
        }
        assert_eq!(RecordSizeClass::from_discriminant(255), None);
    }

    #[test]
    fn compression_algorithm_enums_encode_decode_roundtrip() {
        let algs = [
            CompressionAlgorithmClass::None,
            CompressionAlgorithmClass::Lz4Fast,
            CompressionAlgorithmClass::Lz4High,
            CompressionAlgorithmClass::ZstdFast,
            CompressionAlgorithmClass::ZstdHigh,
            CompressionAlgorithmClass::ZstdAdaptive,
            CompressionAlgorithmClass::DictionaryBacked,
            CompressionAlgorithmClass::Custom,
        ];
        for a in &algs {
            let disc = a.to_discriminant();
            let decoded = CompressionAlgorithmClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*a), "roundtrip failed for {:?}", a.as_str());
        }
        assert_eq!(CompressionAlgorithmClass::from_discriminant(255), None);
    }

    #[test]
    fn compression_ordering_enums_encode_decode_roundtrip() {
        let orders = [
            CompressionOrderingClass::Unknown,
            CompressionOrderingClass::CompressThenEncrypt,
            CompressionOrderingClass::EncryptThenCompress,
            CompressionOrderingClass::CompressOnly,
            CompressionOrderingClass::NoCompression,
        ];
        for o in &orders {
            let disc = o.to_discriminant();
            let decoded = CompressionOrderingClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*o), "roundtrip failed for {:?}", o.as_str());
        }
        assert_eq!(CompressionOrderingClass::from_discriminant(255), None);
    }

    #[test]
    fn digest_suite_enums_encode_decode_roundtrip() {
        let suites = [
            DigestSuiteClass::Unknown,
            DigestSuiteClass::Crc32cFraming,
            DigestSuiteClass::Blake3Content,
            DigestSuiteClass::Blake3KeyedRoot,
            DigestSuiteClass::Crc32cPlusBlake3,
            DigestSuiteClass::FullIntegrityTrailerV2,
        ];
        for s in &suites {
            let disc = s.to_discriminant();
            let decoded = DigestSuiteClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*s), "roundtrip failed for {:?}", s.as_str());
        }
        assert_eq!(DigestSuiteClass::from_discriminant(255), None);
    }

    #[test]
    fn dedup_fingerprint_scope_enums_encode_decode_roundtrip() {
        let scopes = [
            DedupFingerprintScopeClass::Unknown,
            DedupFingerprintScopeClass::NoDedup,
            DedupFingerprintScopeClass::DatasetLocal,
            DedupFingerprintScopeClass::TenantLocal,
            DedupFingerprintScopeClass::SecurityDomain,
            DedupFingerprintScopeClass::CrossDomainAuthorized,
            DedupFingerprintScopeClass::DedupRefused,
        ];
        for s in &scopes {
            let disc = s.to_discriminant();
            let decoded = DedupFingerprintScopeClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*s), "roundtrip failed for {:?}", s.as_str());
        }
        assert_eq!(DedupFingerprintScopeClass::from_discriminant(255), None);
    }

    #[test]
    fn ec_archive_shape_replication_is_detected() {
        let repl = ECArchiveShape::REPLICATION;
        assert!(repl.is_replication());
        assert!(!repl.is_erasure_coded());
        assert!(repl.is_valid());
        assert_eq!(repl.total_shards(), 1);
    }

    #[test]
    fn ec_archive_shape_erasure_coding_is_detected() {
        let ec = ECArchiveShape {
            ec_data_shards: 6,
            ec_parity_shards: 2,
            stripe_unit_bytes: 65536,
            locality_group_size: 3,
            rebuild_width: 8,
            restore_read_width: 6,
        };
        assert!(!ec.is_replication());
        assert!(ec.is_erasure_coded());
        assert!(ec.is_valid());
        assert_eq!(ec.total_shards(), 8);
    }

    #[test]
    fn ec_archive_shape_invalid_zero_k_is_rejected() {
        let bad = ECArchiveShape {
            ec_data_shards: 0,
            ec_parity_shards: 2,
            ..ECArchiveShape::default()
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn coalescing_mode_enums_encode_decode_roundtrip() {
        let modes = [
            CoalescingModeClass::Unknown,
            CoalescingModeClass::NoCoalescing,
            CoalescingModeClass::InlinePayload,
            CoalescingModeClass::PackedSmallFiles,
            CoalescingModeClass::DirBlockInline,
            CoalescingModeClass::XattrPayloadInline,
            CoalescingModeClass::ExternalizedSmallObject,
        ];
        for m in &modes {
            let disc = m.to_discriminant();
            let decoded = CoalescingModeClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*m), "roundtrip failed for {:?}", m.as_str());
        }
        assert_eq!(CoalescingModeClass::from_discriminant(255), None);
    }

    #[test]
    fn rebake_eligibility_enums_encode_decode_roundtrip() {
        let eligs = [
            RebakeEligibilityClass::Unknown,
            RebakeEligibilityClass::RebakeForbidden,
            RebakeEligibilityClass::ShadowEvaluation,
            RebakeEligibilityClass::EligibleAfterCooldown,
            RebakeEligibilityClass::EligibleImmediate,
            RebakeEligibilityClass::ReplacementReceiptPending,
            RebakeEligibilityClass::PaybackWindowNotMet,
        ];
        for e in &eligs {
            let disc = e.to_discriminant();
            let decoded = RebakeEligibilityClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*e), "roundtrip failed for {:?}", e.as_str());
        }
        assert_eq!(RebakeEligibilityClass::from_discriminant(255), None);
    }

    #[test]
    fn data_shape_refusal_enums_encode_decode_roundtrip() {
        let refusals = [
            DataShapeRefusalReason::None,
            DataShapeRefusalReason::UnknownDataShapeEvidence,
            DataShapeRefusalReason::StaleDataShapeEvidence,
            DataShapeRefusalReason::WrongDomainForDedup,
            DataShapeRefusalReason::DedupCrossesTenantDomain,
            DataShapeRefusalReason::CompressedBeforeEncryptionOrderViolation,
            DataShapeRefusalReason::ECShapeBlocksReadServing,
            DataShapeRefusalReason::RecordSizeTooSmallForEC,
            DataShapeRefusalReason::DigestSuiteTooWeakForPolicy,
            DataShapeRefusalReason::CompressionExceedsCpuBudget,
            DataShapeRefusalReason::RebakePaybackWindowNotMet,
            DataShapeRefusalReason::RebakeReplacementReceiptMissing,
            DataShapeRefusalReason::CostBudgetExceeded,
        ];
        for r in &refusals {
            let disc = r.to_discriminant();
            let decoded = DataShapeRefusalReason::from_discriminant(disc);
            assert_eq!(decoded, Some(*r), "roundtrip failed for {:?}", r.as_str());
        }
        assert_eq!(DataShapeRefusalReason::from_discriminant(255), None);
    }

    fn data_shape_evidence_ref(kind: StorageIntentEvidenceKind, id_byte: u8) -> StorageIntentEvidenceRef {
        let mut id = [0_u8; 32];
        id[0] = id_byte;
        StorageIntentEvidenceRef {
            kind,
            id: StorageIntentEvidenceId(id),
            generation: 1,
            version: 1,
        }
    }

    fn healthy_data_shape_record() -> DataShapeRecord {
        DataShapeRecord {
            record_size_class: RecordSizeClass::Medium,
            compression_class: CompressionAlgorithmClass::ZstdFast,
            compression_ordering: CompressionOrderingClass::CompressThenEncrypt,
            digest_suite: DigestSuiteClass::Crc32cPlusBlake3,
            dedup_scope: DedupFingerprintScopeClass::DatasetLocal,
            encryption_domain: StorageIntentDomainId([1_u8; 16]),
            encryption_key_epoch: 5,
            ec_archive_shape: ECArchiveShape::REPLICATION,
            coalescing_mode: CoalescingModeClass::NoCoalescing,
            rebake_eligibility: RebakeEligibilityClass::RebakeForbidden,
            transform_refusal: TransformRefusalClass::None,
            data_shape_refusal: DataShapeRefusalReason::None,
            policy_id: StorageIntentPolicyId([1_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(1),
            evidence: data_shape_evidence_ref(StorageIntentEvidenceKind::DataShapeEvidence, 1),
            ..DataShapeRecord::default()
        }
    }

    fn restrictive_data_shape_policy() -> DataShapePolicy {
        DataShapePolicy {
            policy_id: StorageIntentPolicyId([1_u8; 16]),
            policy_revision: StorageIntentPolicyRevision(1),
            record_size_class: RecordSizeClass::Medium,
            compression_algorithm: CompressionAlgorithmClass::ZstdFast,
            compression_ordering: CompressionOrderingClass::CompressThenEncrypt,
            digest_suite: DigestSuiteClass::Crc32cPlusBlake3,
            dedup_scope: DedupFingerprintScopeClass::DatasetLocal,
            encryption_domain: StorageIntentDomainId([1_u8; 16]),
            encryption_key_epoch_min: 1,
            ec_archive_shape: ECArchiveShape::REPLICATION,
            coalescing_mode: CoalescingModeClass::NoCoalescing,
            rebake_eligibility: RebakeEligibilityClass::RebakeForbidden,
            sharing_domain: StorageIntentDomainId::ZERO,
            ..DataShapePolicy::default()
        }
    }

    #[test]
    fn healthy_data_shape_record_passes_hard_gate_check() {
        let record = healthy_data_shape_record();
        let policy = restrictive_data_shape_policy();
        assert!(data_shape_evidence_is_usable(record).satisfied);
        assert!(data_shape_transform_is_legal(record).satisfied);
        assert!(data_shape_hard_gate_check(record, policy).satisfied);
    }

    #[test]
    fn missing_evidence_blocks_hard_gate() {
        let mut record = healthy_data_shape_record();
        record.evidence = StorageIntentEvidenceRef::default(); // no evidence bound
        let result = data_shape_evidence_is_usable(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::UnknownDataShapeEvidence
        );
    }

    #[test]
    fn no_quorum_refuses_authority() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::NoQuorum;
        // No-quorum must refuse authority-changing operations.
        let result = recovery_evidence_supports_degraded_write(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn stale_receipt_source_refuses_degraded_read() {
        let mut evidence = healthy_recovery_evidence();
        evidence.source_freshness_ms = 120_000;
        // Request max freshness of 60_000ms; the 120_000ms source is stale.
        let result = recovery_evidence_supports_degraded_read(evidence, 60_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn under_width_ec_reconstruction_blocks_authority() {
        let mut evidence = healthy_recovery_evidence();
        evidence.target_present = 1;
        evidence.redundancy_width = 6;
        evidence.reconstruction_width = 3;
        assert!(!evidence.has_authority_width());
        assert!(!evidence.has_reconstruction_width());
        let result = recovery_evidence_supports_degraded_read(evidence, 30_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn corrupt_repair_source_blocks_rebuild() {
        let mut evidence = healthy_recovery_evidence();
        evidence.target_corrupt = 1;
        evidence.target_present = 2;
        evidence.redundancy_width = 3;
        evidence.reconstruction_width = 2;
        evidence.rebuild_ticket_ref = ordering_ref(50);
        evidence.rebuild_completion_ref = ordering_ref(51);
        evidence.rebuild_scratch_capacity_ref = capacity_ref(52);
        // Has reconstruction width but source is corrupt.
        assert!(evidence.has_reconstruction_width());
        // Rebuild predicate: targets must be clean.
        let result = recovery_evidence_supports_rebuild(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn partition_healing_with_old_epoch_refuses_geo_catchup() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Partitioned;
        evidence.split_brain_hazard = StorageIntentSplitBrainHazard::Confirmed;
        evidence.geo_backlog_capacity_ref = capacity_ref(60);
        evidence.trust_domain_ref = trust_ref(61);
        let result = recovery_evidence_supports_geo_catchup(evidence, 30_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn fenced_peer_counted_as_data_blocks_degraded_read() {
        let mut evidence = healthy_recovery_evidence();
        evidence.target_fenced = 1;
        evidence.target_present = 2;
        evidence.redundancy_width = 3;
        evidence.reconstruction_width = 2;
        // Has reconstruction width but a fenced peer is in the set.
        assert!(evidence.has_reconstruction_width());
        let result = recovery_evidence_supports_degraded_read(evidence, 30_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn quarantined_repair_source_blocks_read_repair() {
        let mut evidence = healthy_recovery_evidence();
        evidence.target_quarantined = 1;
        evidence.target_present = 2;
        evidence.redundancy_width = 3;
        evidence.reconstruction_width = 2;
        let result = recovery_evidence_supports_read_repair(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn wrong_domain_repair_source_blocks_read_repair() {
        let mut evidence = healthy_recovery_evidence();
        evidence.target_wrong_domain = 1;
        evidence.target_present = 2;
        evidence.redundancy_width = 3;
        evidence.reconstruction_width = 2;
        let result = recovery_evidence_supports_read_repair(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn read_repair_without_capacity_reserve_is_refused() {
        let mut evidence = healthy_recovery_evidence();
        evidence.read_repair_capacity_ref = StorageIntentEvidenceRef::default();
        evidence.target_stale = 1;
        evidence.target_present = 2;
        evidence.redundancy_width = 3;
        evidence.reconstruction_width = 2;
        let result = recovery_evidence_supports_read_repair(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn replacement_receipt_missing_at_receipt_retirement() {
        let mut evidence = healthy_recovery_evidence();
        evidence.replacement_receipt_ref = StorageIntentEvidenceRef::default();
        evidence.old_receipt_retirement_ref = ordering_ref(70);
        evidence.receipt_retirement_ordering_ref = ordering_ref(71);
        evidence.receipt_retirement_capacity_ref = capacity_ref(72);
        let result = recovery_evidence_supports_receipt_retirement(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn geo_lag_exceeding_policy_refuses_catchup() {
        let mut evidence = healthy_recovery_evidence();
        evidence.geo_backlog_capacity_ref = capacity_ref(80);
        evidence.trust_domain_ref = trust_ref(81);
        evidence.rpo_lag_ms = 60_000;
        // Policy max lag is 30_000ms.
        let result = recovery_evidence_supports_geo_catchup(evidence, 30_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn policy_permitted_degraded_visible_reads_succeed() {
        let evidence = healthy_recovery_evidence();
        // Exact + ServeDegradedReadsOnly policy = degraded read allowed.
        let result = recovery_evidence_supports_degraded_read(evidence, 30_000);
        assert!(result.satisfied);
    }

    #[test]
    fn hidden_downgrade_detected_when_exact_claimed_under_width() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Exact;
        evidence.target_under_width = 1;
        assert!(recovery_evidence_commits_hidden_downgrade(evidence));
    }

    #[test]
    fn hidden_downgrade_detected_when_exact_claimed_with_partition_ambiguity() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Exact;
        evidence.split_brain_hazard = StorageIntentSplitBrainHazard::Possible;
        assert!(recovery_evidence_commits_hidden_downgrade(evidence));
    }

    #[test]
    fn hidden_downgrade_detected_when_exact_claimed_with_wrong_domain_targets() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Exact;
        evidence.target_wrong_domain = 1;
        assert!(recovery_evidence_commits_hidden_downgrade(evidence));
    }

    #[test]
    fn degradation_forbids_hiding_when_policy_says_forbid() {
        let policy = StorageIntentDegradationPolicy {
            visibility: StorageIntentDegradationVisibility::ForbidHide,
            refusal_law: StorageIntentDegradationRefusalLaw::ServeDegradedReadsOnly,
            policy_ref: placement_receipt_ref(90),
            policy_revision: StorageIntentPolicyRevision(2),
        };
        assert!(degradation_forbids_hiding(
            policy,
            StorageIntentDegradationClass::DegradedVisible
        ));
    }

    #[test]
    fn degradation_allows_hiding_when_exact_and_conditional() {
        let policy = StorageIntentDegradationPolicy {
            visibility: StorageIntentDegradationVisibility::ConditionalHide,
            refusal_law: StorageIntentDegradationRefusalLaw::ServeDegradedReadsOnly,
            policy_ref: placement_receipt_ref(91),
            policy_revision: StorageIntentPolicyRevision(2),
        };
        assert!(!degradation_forbids_hiding(
            policy,
            StorageIntentDegradationClass::Exact
        ));
    }

    #[test]
    fn degradation_enums_encode_decode_roundtrip() {
        let classes = [
            StorageIntentDegradationClass::Exact,
            StorageIntentDegradationClass::DegradedVisible,
            StorageIntentDegradationClass::Reconstructing,
            StorageIntentDegradationClass::RepairRequired,
            StorageIntentDegradationClass::RebuildRequired,
            StorageIntentDegradationClass::NoQuorum,
            StorageIntentDegradationClass::Partitioned,
            StorageIntentDegradationClass::GeoLagged,
            StorageIntentDegradationClass::Blocked,
            StorageIntentDegradationClass::Refused,
            StorageIntentDegradationClass::UnknownEvidence,
        ];
        for c in &classes {
            let disc = c.to_discriminant();
            let decoded = StorageIntentDegradationClass::from_discriminant(disc);
            assert_eq!(decoded, Some(*c), "roundtrip failed for {:?}", c.as_str());
        }
        assert_eq!(StorageIntentDegradationClass::from_discriminant(255), None);
    }

    #[test]
    fn recovery_refusal_enums_encode_decode_roundtrip() {
        let refusals = [
            StorageIntentRecoveryRefusalReason::None,
            StorageIntentRecoveryRefusalReason::NoLegalReceiptSet,
            StorageIntentRecoveryRefusalReason::StaleSourceReceipt,
            StorageIntentRecoveryRefusalReason::UnderWidthReconstruction,
            StorageIntentRecoveryRefusalReason::CorruptRepairSource,
            StorageIntentRecoveryRefusalReason::OldEpochPartitionHealing,
            StorageIntentRecoveryRefusalReason::FencedPeerCountedAsData,
            StorageIntentRecoveryRefusalReason::QuarantinedRepairSource,
            StorageIntentRecoveryRefusalReason::WrongDomainRepairSource,
            StorageIntentRecoveryRefusalReason::ReadRepairWithoutReserve,
            StorageIntentRecoveryRefusalReason::MissingReplacementReceipt,
            StorageIntentRecoveryRefusalReason::GeoLagExceedsPolicy,
            StorageIntentRecoveryRefusalReason::StaleTrustEvidenceForRecovery,
            StorageIntentRecoveryRefusalReason::MissingOrderingForRepairPublication,
            StorageIntentRecoveryRefusalReason::InsufficientRebuildScratchCapacity,
            StorageIntentRecoveryRefusalReason::RecoveryCooldownBlocked,
            StorageIntentRecoveryRefusalReason::MissingRecoveryObligationEvidence,
            StorageIntentRecoveryRefusalReason::SplitBrainHazardUnsafe,
            StorageIntentRecoveryRefusalReason::StaleKeyEpochForRecovery,
            StorageIntentRecoveryRefusalReason::ResidencyViolationInRecovery,
            StorageIntentRecoveryRefusalReason::RecoveryDeadlineCrossed,
        ];
        for r in &refusals {
            let disc = r.to_discriminant();
            let decoded = StorageIntentRecoveryRefusalReason::from_discriminant(disc);
            assert_eq!(decoded, Some(*r), "roundtrip failed for {:?}", r.as_str());
        }
        assert_eq!(
            StorageIntentRecoveryRefusalReason::from_discriminant(255),
            None
        );
    }

    #[test]
    fn stale_evidence_blocks_hard_gate() {
        let mut record = healthy_data_shape_record();
        record.evidence.generation = 0;
        let result = data_shape_evidence_is_usable(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleDataShapeEvidence
        );
    }

    #[test]
    fn transform_refusal_blocks_hard_gate() {
        let mut record = healthy_data_shape_record();
        record.transform_refusal = TransformRefusalClass::UnsupportedCompression;
        let result = data_shape_transform_is_legal(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DataShapeTransformRefused
        );
    }

    #[test]
    fn data_shape_refusal_blocks_hard_gate() {
        let mut record = healthy_data_shape_record();
        record.data_shape_refusal = DataShapeRefusalReason::DigestSuiteTooWeakForPolicy;
        let result = data_shape_transform_is_legal(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DataShapeTransformRefused
        );
    }

    #[test]
    fn stale_policy_revision_blocks_hard_gate() {
        let mut record = healthy_data_shape_record();
        let policy = DataShapePolicy {
            policy_revision: StorageIntentPolicyRevision(2),
            ..restrictive_data_shape_policy()
        };
        record.policy_revision = StorageIntentPolicyRevision(1);
        let result = data_shape_policy_identity_is_current(record, policy);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::StaleDataShapeEvidence
        );
    }

    #[test]
    fn dedup_domain_mismatch_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.dedup_scope = DedupFingerprintScopeClass::TenantLocal;
        record.dedup_domain = StorageIntentDomainId([2_u8; 16]);
        // Policy has a non-zero domain that doesn't match the record domain
        let policy_domain = StorageIntentDomainId([1_u8; 16]);
        let result = data_shape_dedup_domain_is_compatible(record, policy_domain);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DedupCrossesTenantDomain
        );
    }

    #[test]
    fn dedup_refused_state_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.dedup_scope = DedupFingerprintScopeClass::DedupRefused;
        let policy = restrictive_data_shape_policy();
        let result = data_shape_dedup_domain_is_compatible(record, policy.sharing_domain);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DedupCrossesTenantDomain
        );
    }

    #[test]
    fn no_dedup_is_always_compatible() {
        let mut record = healthy_data_shape_record();
        record.dedup_scope = DedupFingerprintScopeClass::NoDedup;
        let policy = restrictive_data_shape_policy();
        let result = data_shape_dedup_domain_is_compatible(record, policy.sharing_domain);
        assert!(result.satisfied);
    }

    #[test]
    fn healthy_recovery_evidence_passes_all_basic_predicates() {
        let evidence = healthy_recovery_evidence();
        assert!(evidence.has_recovery_evidence());
        assert!(evidence.has_degradation_policy());
        assert!(evidence.has_source_receipt_set());
        assert!(evidence.has_authority_width());
        assert!(evidence.has_reconstruction_width());
        assert!(evidence.targets_are_clean());
        assert!(evidence.is_exact());
        assert!(!evidence.is_refused());
        assert!(evidence.source_freshness_within(30_000));
        assert!(!recovery_evidence_commits_hidden_downgrade(evidence));
    }

    #[test]
    fn refused_recovery_evidence_blocks_all_predicates() {
        let mut evidence = healthy_recovery_evidence();
        evidence.refusal = StorageIntentRecoveryRefusalReason::RecoveryCooldownBlocked;
        assert!(evidence.is_refused());

        assert!(!recovery_evidence_supports_degraded_read(evidence, 30_000).satisfied);
        assert!(!recovery_evidence_supports_read_repair(evidence).satisfied);
        assert!(!recovery_evidence_supports_rebuild(evidence).satisfied);
        assert!(!recovery_evidence_supports_geo_catchup(evidence, 30_000).satisfied);
        assert!(!recovery_evidence_supports_receipt_retirement(evidence).satisfied);
        assert!(recovery_evidence_commits_hidden_downgrade(evidence));
    }

    #[test]
    fn unrecognized_evidence_ref_does_not_satisfy() {
        let mut evidence = healthy_recovery_evidence();
        // Corrupt the evidence_ref so it no longer points to RecoveryDegradation.
        evidence.evidence_ref = placement_receipt_ref(99);
        assert!(!evidence.has_recovery_evidence());
        let result = recovery_evidence_supports_degraded_read(evidence, 30_000);
        assert!(!result.satisfied);
    }

    #[test]
    fn exact_write_admission_when_not_degraded() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Exact;
        let result = recovery_evidence_supports_degraded_write(evidence);
        assert!(result.satisfied);
    }

    #[test]
    fn encryption_not_bypassed_when_policy_requires_it() {
        let record = healthy_data_shape_record();
        let result = data_shape_encryption_is_not_bypassed(record, true);
        assert!(result.satisfied); // record has encryption domain
    }

    #[test]
    fn encryption_bypass_is_blocked_when_policy_requires_it() {
        let mut record = healthy_data_shape_record();
        record.encryption_domain = StorageIntentDomainId::ZERO;
        let result = data_shape_encryption_is_not_bypassed(record, true);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::EncryptionBypassedForDedup
        );
    }

    #[test]
    fn compression_ordering_unknown_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.compression_ordering = CompressionOrderingClass::Unknown;
        let result = data_shape_compression_ordering_is_legal(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::IllegalCompressionOrdering
        );
    }

    #[test]
    fn ec_replication_always_legal() {
        let shape = ECArchiveShape::REPLICATION;
        let result = data_shape_ec_shape_is_legal(shape);
        assert!(result.satisfied);
    }

    #[test]
    fn ec_invalid_shape_is_blocked() {
        let shape = ECArchiveShape {
            ec_data_shards: 0,
            ec_parity_shards: 2,
            ..ECArchiveShape::default()
        };
        let result = data_shape_ec_shape_is_legal(shape);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::ECShapeBlocksReadServing
        );
    }

    #[test]
    fn rebake_replacement_receipt_missing_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.rebake_eligibility = RebakeEligibilityClass::EligibleImmediate;
        record.replacement_receipt = StorageIntentReceiptId::ZERO;
        let result = data_shape_rebake_replacement_receipt_is_present(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::RebakeReplacementReceiptMissing
        );
    }

    #[test]
    fn rebake_payback_window_not_met_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.rebake_eligibility = RebakeEligibilityClass::PaybackWindowNotMet;
        let result = data_shape_rebake_replacement_receipt_is_present(record);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::RebakePaybackWindowNotMet
        );
    }

    #[test]
    fn digest_suite_below_policy_floor_is_blocked() {
        let mut record = healthy_data_shape_record();
        record.digest_suite = DigestSuiteClass::Crc32cFraming;
        let policy = restrictive_data_shape_policy(); // requires Crc32cPlusBlake3
        let result = data_shape_digest_suite_is_adequate(record, policy.digest_suite);
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::DataShapeTransformRefused
        );
    }

    #[test]
    fn digest_suite_at_or_above_floor_passes() {
        let record = healthy_data_shape_record(); // Crc32cPlusBlake3
        let policy = restrictive_data_shape_policy(); // requires Crc32cPlusBlake3
        let result = data_shape_digest_suite_is_adequate(record, policy.digest_suite);
        assert!(result.satisfied);
    }

    #[test]
    fn data_shape_record_is_compressed_detection() {
        let mut record = DataShapeRecord::default();
        assert!(!record.is_compressed());
        record.compression_class = CompressionAlgorithmClass::ZstdFast;
        assert!(record.is_compressed());
    }

    #[test]
    fn storage_intent_refusal_reason_enums_encode_decode_data_shape() {
        let refusals = [
            StorageIntentRefusalReason::UnknownDataShapeEvidence,
            StorageIntentRefusalReason::StaleDataShapeEvidence,
            StorageIntentRefusalReason::DataShapeTransformRefused,
            StorageIntentRefusalReason::IllegalCompressionOrdering,
            StorageIntentRefusalReason::DedupCrossesTenantDomain,
            StorageIntentRefusalReason::EncryptionBypassedForDedup,
            StorageIntentRefusalReason::ECShapeBlocksReadServing,
            StorageIntentRefusalReason::RebakeReplacementReceiptMissing,
            StorageIntentRefusalReason::RebakePaybackWindowNotMet,
            StorageIntentRefusalReason::DataShapeCostBudgetExceeded,
        ];
        for r in &refusals {
            let disc = r.to_discriminant();
            let decoded = StorageIntentRefusalReason::from_discriminant(disc);
            assert_eq!(decoded, Some(*r), "roundtrip failed for {:?}", r.as_str());
        }
    }

    #[test]
    fn data_shape_policy_default_has_zero_policy_id() {
        let policy = DataShapePolicy::default();
        assert!(policy.policy_id.is_zero());
    }

    #[test]
    fn degraded_write_refused_when_policy_refuses_all_degraded() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::DegradedVisible;
        evidence.degradation_policy.refusal_law =
            StorageIntentDegradationRefusalLaw::RefuseAllDegraded;
        let result = recovery_evidence_supports_degraded_write(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn satisfaction_reconciliation_blocked_when_degradation_blocks_authority() {
        let mut evidence = healthy_recovery_evidence();
        evidence.degradation = StorageIntentDegradationClass::Blocked;
        let result = recovery_evidence_supports_satisfaction_reconciliation(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn evacuation_refused_when_fenced_targets_present() {
        let mut evidence = healthy_recovery_evidence();
        evidence.evacuation_capacity_ref = capacity_ref(100);
        evidence.target_fenced = 1;
        let result = recovery_evidence_supports_evacuation(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn relocation_overlap_requires_replacement_receipt() {
        let mut evidence = healthy_recovery_evidence();
        evidence.relocation_overlap_ref = ordering_ref(110);
        evidence.replacement_receipt_ref = StorageIntentEvidenceRef::default();
        let result = recovery_evidence_supports_relocation_overlap(evidence);
        assert!(!result.satisfied);
    }

    #[test]
    fn scrub_repair_requires_scrub_finding_and_repair_ticket() {
        let mut evidence = healthy_recovery_evidence();
        evidence.scrub_finding_ref = evidence_ref(StorageIntentEvidenceKind::ValidationArtifact, 120);
        evidence.repair_ticket_ref = ordering_ref(121);
        let result = recovery_evidence_supports_scrub_repair(evidence);
        assert!(result.satisfied);
    }

}
