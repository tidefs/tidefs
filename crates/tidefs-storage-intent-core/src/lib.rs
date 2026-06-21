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

/// Canonical identifier for this authority surface.
pub const STORAGE_INTENT_CORE_SPEC: &str = "tidefs-storage-intent-core-v1-issue-841";

/// Current syntactic record version for versioned authority envelopes.
pub const STORAGE_INTENT_RECORD_VERSION: u16 = 1;

/// Bounded evidence fan-in carried inline by a policy or receipt.
pub const STORAGE_INTENT_INLINE_EVIDENCE_REFS: usize = 16;

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
}

impl StorageIntentEvidenceKind {
    /// Number of defined evidence kinds.
    pub const COUNT: usize = 25;

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

/// Completeness verdict for one lawful evidence cut.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum EvidenceCompletenessVerdict {
    #[default]
    Complete = 0,
    Partial = 1,
    Stale = 2,
    Contradictory = 3,
    Refused = 4,
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

/// One bounded, lawful evidence cut for a consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentEvidenceQuerySnapshot {
    pub query_id: StorageIntentEvidenceId,
    pub consumer: EvidenceConsumerClass,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub freshness_frontier_ms: u64,
    pub source_index_generation: u64,
    pub included_refs: StorageIntentEvidenceRefs,
    pub completeness: EvidenceCompletenessVerdict,
    pub retention: EvidenceRetentionClass,
    pub refusal: StorageIntentRefusalReason,
}

impl Default for StorageIntentEvidenceQuerySnapshot {
    fn default() -> Self {
        Self {
            query_id: StorageIntentEvidenceId::ZERO,
            consumer: EvidenceConsumerClass::Planner,
            policy_id: StorageIntentPolicyId::ZERO,
            policy_revision: StorageIntentPolicyRevision(0),
            freshness_frontier_ms: 0,
            source_index_generation: 0,
            included_refs: StorageIntentEvidenceRefs::EMPTY,
            completeness: EvidenceCompletenessVerdict::Complete,
            retention: EvidenceRetentionClass::ExactRequired,
            refusal: StorageIntentRefusalReason::None,
        }
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
    pub session_security_ref: StorageIntentEvidenceRef,
    pub key_epoch_ref: StorageIntentEvidenceRef,
    pub authorization_ref: StorageIntentEvidenceRef,
    pub audit_ref: StorageIntentEvidenceRef,
    pub residency_ref: StorageIntentEvidenceRef,
    pub sharing_domain_ref: StorageIntentEvidenceRef,
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
        }
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
            || !bytes16_equal(observed.admin_domain.0, required.admin_domain.0))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::SECURITY_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::SECURITY_DOMAIN)
            || !bytes16_equal(observed.security_domain.0, required.security_domain.0))
    {
        return ReceiptPredicateResult::refused(StorageIntentRefusalReason::WrongDomain);
    }
    if required
        .required_flags
        .contains_all(TrustEvidenceFlags::TENANT_DOMAIN)
        && (!observed
            .flags
            .contains_all(TrustEvidenceFlags::TENANT_DOMAIN)
            || !bytes16_equal(observed.tenant_domain.0, required.tenant_domain.0))
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

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_A: StorageIntentDomainId = StorageIntentDomainId([1_u8; 16]);
    const DOMAIN_B: StorageIntentDomainId = StorageIntentDomainId([2_u8; 16]);

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
    fn media_traits_separate_rotational_defrag_from_flash_wear() {
        assert!(StorageMediaClass::HddRotational.favors_extent_locality_defrag());
        assert!(!StorageMediaClass::NvmeFlash.favors_extent_locality_defrag());
        assert!(StorageMediaClass::NvmeFlash.charges_rewrite_wear());
        assert!(!StorageMediaClass::HddRotational.charges_rewrite_wear());
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
