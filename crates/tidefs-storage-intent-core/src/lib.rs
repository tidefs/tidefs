// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Core storage-intent records and predicates.
//!
//! This crate is the narrow #841 type surface for
//! `docs/STORAGE_INTENT_POLICY_AUTHORITY.md`. It gives write admission,
//! placement, transport, relocation, validation, and explanation code one
//! shared vocabulary for requested policy, earned receipts, evidence refs,
//! media roles, trust state, durability/RPO, cost/wear, and refusal shape.
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
pub struct PrefetchResidencyDecisionContext {
    pub policy: PrefetchResidencyPolicyEnvelope,
    pub signal: WorkloadSignalRecord,
    pub source_media: StorageIntentMediaCapabilityRecord,
    pub target_media: StorageIntentMediaCapabilityRecord,
    pub cost_wear: CostWearRecord,
}

impl Default for PrefetchResidencyDecisionContext {
    fn default() -> Self {
        Self {
            policy: PrefetchResidencyPolicyEnvelope::default(),
            signal: WorkloadSignalRecord::default(),
            source_media: StorageIntentMediaCapabilityRecord::default(),
            target_media: StorageIntentMediaCapabilityRecord::default(),
            cost_wear: CostWearRecord::default(),
        }
    }
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

/// Data-shape evidence ref projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct DataShapeRecord {
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
    pub evidence: StorageIntentEvidenceRef,
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
                "role {} should have a satisfiable trust/domain evidence envelope",
                role
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
}
