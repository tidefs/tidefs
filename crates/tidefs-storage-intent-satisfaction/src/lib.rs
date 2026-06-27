// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![no_std]
#![forbid(unsafe_code)]

//! Read-only storage-intent satisfaction reconciliation.
//!
//! This crate is the first #874 source-model slice. It consumes supplied
//! `tidefs-storage-intent-core` policy, receipt, and evidence-query records
//! and emits a typed satisfaction record. It does not select placements,
//! execute relocation or repair, emit local acknowledgments, measure transport,
//! retire receipts, or render operator UAPI.

use core::fmt;

use tidefs_storage_intent_core::{
    evaluate_receipt_against_policy, DurabilityState, EvidenceCompletenessVerdict,
    EvidenceFamilyFreshnessState, EvidenceQuerySubjectScopeClass, FailureDomainMask,
    GuaranteeCapabilities, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef, StorageIntentGuaranteeClass,
    StorageIntentPolicy, StorageIntentPolicyId, StorageIntentPolicyRevision, StorageIntentReceipt,
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

macro_rules! impl_u16_canonical {
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
            pub const fn to_discriminant(self) -> u16 {
                self as u16
            }

            /// Decode from a stable discriminant. Unknown values fail closed.
            #[must_use]
            pub const fn from_discriminant(raw: u16) -> Option<Self> {
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

/// Version of the satisfaction reconciler model surface.
pub const STORAGE_INTENT_SATISFACTION_VERSION: u16 = 1;

/// Stable identifier for the #874 satisfaction reconciler surface.
pub const STORAGE_INTENT_SATISFACTION_SPEC: &str =
    "tidefs-storage-intent-satisfaction-v1-issue-874";

/// Error returned when a bounded satisfaction buffer is full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageIntentSatisfactionError {
    /// The inline buffer has reached its capacity limit.
    BufferFull,
}

impl fmt::Display for StorageIntentSatisfactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("satisfaction inline buffer full")
    }
}

/// Bounded number of reason/output rows carried inline by one satisfaction record.
pub const STORAGE_INTENT_SATISFACTION_INLINE_REASONS: usize = 24;

/// Bounded number of satisfying receipt ids carried inline by one record.
pub const STORAGE_INTENT_SATISFACTION_INLINE_RECEIPTS: usize = 16;

/// Bounded number of evidence refs carried inline by one record.
pub const STORAGE_INTENT_SATISFACTION_INLINE_EVIDENCE_REFS: usize = 24;

/// Top-level satisfaction state emitted by the reconciler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentSatisfactionClass {
    /// Required evidence was absent, stale, malformed, contradictory, or not authoritative.
    #[default]
    UnknownEvidence = 0,
    /// Supplied current receipts satisfy the compiled policy under the evidence cut.
    Satisfied = 1,
    /// Success is pending durable intent publication, policy-strengthening convergence, or catch-up.
    Converging = 2,
    /// Weaker or under-width state is explicitly visible and policy-admissible.
    DegradedVisible = 3,
    /// Reconciliation is waiting on repair, relocation, geo catch-up, consent, or refresh.
    Blocked = 4,
    /// No legal supplied receipt set can satisfy the compiled policy.
    Refused = 5,
    /// The policy explicitly requested weaker volatile behavior; this is not durable success.
    UnsafeVolatile = 6,
}

impl_u8_canonical!(StorageIntentSatisfactionClass, {
    UnknownEvidence = 0 => "unknown-evidence",
    Satisfied = 1 => "satisfied",
    Converging = 2 => "converging",
    DegradedVisible = 3 => "degraded-visible",
    Blocked = 4 => "blocked",
    Refused = 5 => "refused",
    UnsafeVolatile = 6 => "unsafe-volatile",
});

impl StorageIntentSatisfactionClass {
    /// Returns true when this state must not be treated as durable authority success.
    #[must_use]
    pub const fn blocks_durable_authority(self) -> bool {
        matches!(
            self,
            Self::UnknownEvidence | Self::Blocked | Self::Refused | Self::UnsafeVolatile
        )
    }

    /// Returns true when receipt predicates were successfully satisfied.
    #[must_use]
    pub const fn has_positive_receipt(self) -> bool {
        matches!(
            self,
            Self::Satisfied | Self::DegradedVisible | Self::UnsafeVolatile
        )
    }
}

/// Evidence/receipt/policy axis associated with a satisfaction row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentSatisfactionAxis {
    /// Axis was not identified.
    #[default]
    Unknown = 0,
    Policy = 1,
    EvidenceQuery = 2,
    ReceiptSet = 3,
    LocalAckReceipt = 4,
    PlacementReceipt = 5,
    ReadServing = 6,
    DataShape = 7,
    LayoutAllocator = 8,
    MediaWear = 9,
    WorkloadConfidence = 10,
    TransportPath = 11,
    RamAuthority = 12,
    Relocation = 13,
    NonWearCost = 14,
    SchedulerAdmission = 15,
    CapacityAdmission = 16,
    RecoveryDegradation = 17,
    PolicyRollout = 18,
    TenantIsolation = 19,
    Temporal = 20,
    MediaCapability = 21,
    DecisionFrontier = 22,
    ServiceObjective = 23,
    PrefetchResidency = 24,
    OrderingReplay = 25,
    MembershipEpoch = 26,
    LifecycleGeneration = 27,
    OperatorExplanation = 28,
    PerformanceRow = 29,
    FaultValidation = 30,
    ActionExecution = 31,
    ResultRefusal = 32,
    EvidenceRetention = 33,
    MetadataNamespace = 34,
    PreflightSimulation = 35,
    Comparator = 36,
    ClaimGate = 37,
}

impl_u8_canonical!(StorageIntentSatisfactionAxis, {
    Unknown = 0 => "unknown",
    Policy = 1 => "policy",
    EvidenceQuery = 2 => "evidence-query",
    ReceiptSet = 3 => "receipt-set",
    LocalAckReceipt = 4 => "local-ack-receipt",
    PlacementReceipt = 5 => "placement-receipt",
    ReadServing = 6 => "read-serving",
    DataShape = 7 => "data-shape",
    LayoutAllocator = 8 => "layout-allocator",
    MediaWear = 9 => "media-wear",
    WorkloadConfidence = 10 => "workload-confidence",
    TransportPath = 11 => "transport-path",
    RamAuthority = 12 => "ram-authority",
    Relocation = 13 => "relocation",
    NonWearCost = 14 => "non-wear-cost",
    SchedulerAdmission = 15 => "scheduler-admission",
    CapacityAdmission = 16 => "capacity-admission",
    RecoveryDegradation = 17 => "recovery-degradation",
    PolicyRollout = 18 => "policy-rollout",
    TenantIsolation = 19 => "tenant-isolation",
    Temporal = 20 => "temporal",
    MediaCapability = 21 => "media-capability",
    DecisionFrontier = 22 => "decision-frontier",
    ServiceObjective = 23 => "service-objective",
    PrefetchResidency = 24 => "prefetch-residency",
    OrderingReplay = 25 => "ordering-replay",
    MembershipEpoch = 26 => "membership-epoch",
    LifecycleGeneration = 27 => "lifecycle-generation",
    OperatorExplanation = 28 => "operator-explanation",
    PerformanceRow = 29 => "performance-row",
    FaultValidation = 30 => "fault-validation",
    ActionExecution = 31 => "action-execution",
    ResultRefusal = 32 => "result-refusal",
    EvidenceRetention = 33 => "evidence-retention",
    MetadataNamespace = 34 => "metadata-namespace",
    PreflightSimulation = 35 => "preflight-simulation",
    Comparator = 36 => "comparator",
    ClaimGate = 37 => "claim-gate",
});

/// Machine-readable reason emitted for a satisfaction row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u16)]
pub enum StorageIntentSatisfactionReason {
    /// No reason.
    #[default]
    None = 0,
    MissingCompiledPolicy = 1,
    MalformedCompiledPolicy = 2,
    MissingEvidenceQuerySnapshot = 3,
    EvidenceQueryRefused = 4,
    EvidenceQueryNotAuthoritative = 5,
    EvidenceQueryPolicyMismatch = 6,
    EvidenceFamilyMissing = 7,
    EvidenceFamilyStale = 8,
    EvidenceFamilyContradictory = 9,
    EvidenceFamilyCompacted = 10,
    EvidenceFamilyRefused = 11,
    EvidenceFamilyUnavailable = 12,
    EvidenceRefOutOfCut = 13,
    ReceiptEvidenceMissing = 14,
    ReceiptPolicyMismatch = 15,
    ReceiptRevisionBehindPolicy = 16,
    ReceiptRevisionAheadOfPolicyCut = 17,
    ReceiptPredicateRefused = 18,
    NoCandidateReceipts = 19,
    NoLegalReceiptSet = 20,
    PendingDurableIntentConvergence = 21,
    PendingPolicyStrengtheningConvergence = 22,
    RepairRelocationWaiting = 23,
    GeoCatchupWaiting = 24,
    EvidenceRefreshWaiting = 25,
    PolicyWeakeningNeedsOperatorConsent = 26,
    PolicyUnsafeVolatileRequiresOptIn = 27,
    UnsafeVolatilePolicySatisfied = 28,
    VolatilePolicyDoesNotSatisfyPosixDurableFloor = 29,
    DegradedVisibleByPolicy = 30,
    UnderWidthFailureDomainPlacement = 31,
    GeoLagCrossedPolicy = 32,
    CapacityReserveExhausted = 33,
    StaleReadServingEvidence = 34,
    WrongDomainDataShapeEvidence = 35,
    StaleMirrorOnlyLayoutEvidence = 36,
    DegradedReadRefused = 37,
    CacheOnlyCannotSatisfyDurable = 38,
    UnknownCostEvidence = 39,
    UnknownWafEvidence = 40,
    PendingFreeUnsafe = 41,
    WrongEpochEvidence = 42,
    WrongKeyEpoch = 43,
    WrongDedupOrEncryptionDomain = 44,
    MalformedEvidence = 45,
    ContradictoryEvidence = 46,
    NotAuthoritativeEnough = 47,
    ProducerFinding = 48,
    ReasonBufferFull = 49,
    StaleTransportPathEvidence = 50,
    RecoveryDegradationRefused = 51,
}

impl_u16_canonical!(StorageIntentSatisfactionReason, {
    None = 0 => "none",
    MissingCompiledPolicy = 1 => "missing-compiled-policy",
    MalformedCompiledPolicy = 2 => "malformed-compiled-policy",
    MissingEvidenceQuerySnapshot = 3 => "missing-evidence-query-snapshot",
    EvidenceQueryRefused = 4 => "evidence-query-refused",
    EvidenceQueryNotAuthoritative = 5 => "evidence-query-not-authoritative",
    EvidenceQueryPolicyMismatch = 6 => "evidence-query-policy-mismatch",
    EvidenceFamilyMissing = 7 => "evidence-family-missing",
    EvidenceFamilyStale = 8 => "evidence-family-stale",
    EvidenceFamilyContradictory = 9 => "evidence-family-contradictory",
    EvidenceFamilyCompacted = 10 => "evidence-family-compacted",
    EvidenceFamilyRefused = 11 => "evidence-family-refused",
    EvidenceFamilyUnavailable = 12 => "evidence-family-unavailable",
    EvidenceRefOutOfCut = 13 => "evidence-ref-out-of-cut",
    ReceiptEvidenceMissing = 14 => "receipt-evidence-missing",
    ReceiptPolicyMismatch = 15 => "receipt-policy-mismatch",
    ReceiptRevisionBehindPolicy = 16 => "receipt-revision-behind-policy",
    ReceiptRevisionAheadOfPolicyCut = 17 => "receipt-revision-ahead-of-policy-cut",
    ReceiptPredicateRefused = 18 => "receipt-predicate-refused",
    NoCandidateReceipts = 19 => "no-candidate-receipts",
    NoLegalReceiptSet = 20 => "no-legal-receipt-set",
    PendingDurableIntentConvergence = 21 => "pending-durable-intent-convergence",
    PendingPolicyStrengtheningConvergence = 22 => "pending-policy-strengthening-convergence",
    RepairRelocationWaiting = 23 => "repair-relocation-waiting",
    GeoCatchupWaiting = 24 => "geo-catchup-waiting",
    EvidenceRefreshWaiting = 25 => "evidence-refresh-waiting",
    PolicyWeakeningNeedsOperatorConsent = 26 => "policy-weakening-needs-operator-consent",
    PolicyUnsafeVolatileRequiresOptIn = 27 => "policy-unsafe-volatile-requires-opt-in",
    UnsafeVolatilePolicySatisfied = 28 => "unsafe-volatile-policy-satisfied",
    VolatilePolicyDoesNotSatisfyPosixDurableFloor = 29 => "volatile-policy-does-not-satisfy-posix-durable-floor",
    DegradedVisibleByPolicy = 30 => "degraded-visible-by-policy",
    UnderWidthFailureDomainPlacement = 31 => "under-width-failure-domain-placement",
    GeoLagCrossedPolicy = 32 => "geo-lag-crossed-policy",
    CapacityReserveExhausted = 33 => "capacity-reserve-exhausted",
    StaleReadServingEvidence = 34 => "stale-read-serving-evidence",
    WrongDomainDataShapeEvidence = 35 => "wrong-domain-data-shape-evidence",
    StaleMirrorOnlyLayoutEvidence = 36 => "stale-mirror-only-layout-evidence",
    DegradedReadRefused = 37 => "degraded-read-refused",
    CacheOnlyCannotSatisfyDurable = 38 => "cache-only-cannot-satisfy-durable",
    UnknownCostEvidence = 39 => "unknown-cost-evidence",
    UnknownWafEvidence = 40 => "unknown-waf-evidence",
    PendingFreeUnsafe = 41 => "pending-free-unsafe",
    WrongEpochEvidence = 42 => "wrong-epoch-evidence",
    WrongKeyEpoch = 43 => "wrong-key-epoch",
    WrongDedupOrEncryptionDomain = 44 => "wrong-dedup-or-encryption-domain",
    MalformedEvidence = 45 => "malformed-evidence",
    ContradictoryEvidence = 46 => "contradictory-evidence",
    NotAuthoritativeEnough = 47 => "not-authoritative-enough",
    ProducerFinding = 48 => "producer-finding",
    ReasonBufferFull = 49 => "reason-buffer-full",
    StaleTransportPathEvidence = 50 => "stale-transport-path-evidence",
    RecoveryDegradationRefused = 51 => "recovery-degradation-refused",
});

/// Output consumers represented by a satisfaction row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionOutputRoleMask(pub u16);

impl StorageIntentSatisfactionOutputRoleMask {
    pub const NONE: Self = Self(0);
    pub const MACHINE_REASON: Self = Self(1 << 0);
    pub const OPERATOR_EXPLANATION: Self = Self(1 << 1);
    pub const PERFORMANCE_ROW: Self = Self(1 << 2);
    pub const FAULT_VALIDATION: Self = Self(1 << 3);
    pub const ALL_CONSUMERS: Self = Self(
        Self::MACHINE_REASON.0
            | Self::OPERATOR_EXPLANATION.0
            | Self::PERFORMANCE_ROW.0
            | Self::FAULT_VALIDATION.0,
    );

    /// Merge two output-role masks.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all roles in `required` are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// A machine-readable reason row and consumer projection fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionReasonRecord {
    pub axis: StorageIntentSatisfactionAxis,
    pub state: StorageIntentSatisfactionClass,
    pub reason: StorageIntentSatisfactionReason,
    pub evidence_kind: StorageIntentEvidenceKind,
    pub evidence_state: EvidenceFamilyFreshnessState,
    pub refusal: StorageIntentRefusalReason,
    pub receipt_id: StorageIntentReceiptId,
    pub evidence_ref: StorageIntentEvidenceRef,
    pub output_roles: StorageIntentSatisfactionOutputRoleMask,
}

impl StorageIntentSatisfactionReasonRecord {
    pub const EMPTY: Self = Self {
        axis: StorageIntentSatisfactionAxis::Unknown,
        state: StorageIntentSatisfactionClass::UnknownEvidence,
        reason: StorageIntentSatisfactionReason::None,
        evidence_kind: StorageIntentEvidenceKind::Unknown,
        evidence_state: EvidenceFamilyFreshnessState::Unknown,
        refusal: StorageIntentRefusalReason::None,
        receipt_id: StorageIntentReceiptId::ZERO,
        evidence_ref: StorageIntentEvidenceRef {
            kind: StorageIntentEvidenceKind::Unknown,
            id: StorageIntentEvidenceId::ZERO,
            generation: 0,
            version: 0,
        },
        output_roles: StorageIntentSatisfactionOutputRoleMask::NONE,
    };

    /// Build a row that can be consumed by explanation, performance, and fault consumers.
    #[must_use]
    pub const fn new(
        axis: StorageIntentSatisfactionAxis,
        state: StorageIntentSatisfactionClass,
        reason: StorageIntentSatisfactionReason,
    ) -> Self {
        Self {
            axis,
            state,
            reason,
            evidence_kind: StorageIntentEvidenceKind::Unknown,
            evidence_state: EvidenceFamilyFreshnessState::Unknown,
            refusal: StorageIntentRefusalReason::None,
            receipt_id: StorageIntentReceiptId::ZERO,
            evidence_ref: StorageIntentEvidenceRef {
                kind: StorageIntentEvidenceKind::Unknown,
                id: StorageIntentEvidenceId::ZERO,
                generation: 0,
                version: 0,
            },
            output_roles: StorageIntentSatisfactionOutputRoleMask::ALL_CONSUMERS,
        }
    }
}

impl Default for StorageIntentSatisfactionReasonRecord {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Bounded reason rows carried by one satisfaction record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionReasonSet {
    len: u8,
    rows: [StorageIntentSatisfactionReasonRecord; STORAGE_INTENT_SATISFACTION_INLINE_REASONS],
}

impl StorageIntentSatisfactionReasonSet {
    pub const EMPTY: Self = Self {
        len: 0,
        rows: [StorageIntentSatisfactionReasonRecord::EMPTY;
            STORAGE_INTENT_SATISFACTION_INLINE_REASONS],
    };

    /// Return the backing rows and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[StorageIntentSatisfactionReasonRecord; STORAGE_INTENT_SATISFACTION_INLINE_REASONS],
        u8,
    ) {
        (&self.rows, self.len)
    }

    /// Append one row.
    pub fn push(
        &mut self,
        row: StorageIntentSatisfactionReasonRecord,
    ) -> Result<(), StorageIntentSatisfactionError> {
        if self.len as usize >= STORAGE_INTENT_SATISFACTION_INLINE_REASONS {
            return Err(StorageIntentSatisfactionError::BufferFull);
        }
        self.rows[self.len as usize] = row;
        self.len += 1;
        Ok(())
    }

    /// Returns true when the set contains a row with this reason.
    #[must_use]
    pub const fn contains_reason(self, reason: StorageIntentSatisfactionReason) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if self.rows[index].reason as u16 == reason as u16 {
                return true;
            }
            index += 1;
        }
        false
    }
}

impl Default for StorageIntentSatisfactionReasonSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Bounded receipt ids that satisfied the policy predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionReceiptSet {
    len: u8,
    receipts: [StorageIntentReceiptId; STORAGE_INTENT_SATISFACTION_INLINE_RECEIPTS],
}

impl StorageIntentSatisfactionReceiptSet {
    pub const EMPTY: Self = Self {
        len: 0,
        receipts: [StorageIntentReceiptId::ZERO; STORAGE_INTENT_SATISFACTION_INLINE_RECEIPTS],
    };

    /// Number of satisfying receipts.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len as usize
    }

    /// Returns true when no satisfying receipt was recorded.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Return the backing rows and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[StorageIntentReceiptId; STORAGE_INTENT_SATISFACTION_INLINE_RECEIPTS],
        u8,
    ) {
        (&self.receipts, self.len)
    }

    /// Append one receipt id.
    pub fn push(
        &mut self,
        receipt: StorageIntentReceiptId,
    ) -> Result<(), StorageIntentSatisfactionError> {
        if self.len as usize >= STORAGE_INTENT_SATISFACTION_INLINE_RECEIPTS {
            return Err(StorageIntentSatisfactionError::BufferFull);
        }
        self.receipts[self.len as usize] = receipt;
        self.len += 1;
        Ok(())
    }

    /// Returns true when the set contains this receipt id.
    #[must_use]
    pub const fn contains(self, receipt: StorageIntentReceiptId) -> bool {
        let mut index = 0;
        while index < self.len as usize {
            if bytes16_equal(self.receipts[index].0, receipt.0) {
                return true;
            }
            index += 1;
        }
        false
    }
}

impl Default for StorageIntentSatisfactionReceiptSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Bounded evidence refs preserved by the satisfaction record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionEvidenceSet {
    len: u8,
    refs: [StorageIntentEvidenceRef; STORAGE_INTENT_SATISFACTION_INLINE_EVIDENCE_REFS],
}

impl StorageIntentSatisfactionEvidenceSet {
    pub const EMPTY: Self = Self {
        len: 0,
        refs: [StorageIntentSatisfactionReasonRecord::EMPTY.evidence_ref;
            STORAGE_INTENT_SATISFACTION_INLINE_EVIDENCE_REFS],
    };

    /// Return the backing rows and valid length.
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        &[StorageIntentEvidenceRef; STORAGE_INTENT_SATISFACTION_INLINE_EVIDENCE_REFS],
        u8,
    ) {
        (&self.refs, self.len)
    }

    /// Append one evidence ref if bound and not already present.
    pub fn push_unique(
        &mut self,
        evidence_ref: StorageIntentEvidenceRef,
    ) -> Result<(), StorageIntentSatisfactionError> {
        if !evidence_ref.is_bound() || self.contains(evidence_ref) {
            return Ok(());
        }
        if self.len as usize >= STORAGE_INTENT_SATISFACTION_INLINE_EVIDENCE_REFS {
            return Err(StorageIntentSatisfactionError::BufferFull);
        }
        self.refs[self.len as usize] = evidence_ref;
        self.len += 1;
        Ok(())
    }

    /// Returns true when this exact ref is present.
    #[must_use]
    pub const fn contains(self, evidence_ref: StorageIntentEvidenceRef) -> bool {
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

impl Default for StorageIntentSatisfactionEvidenceSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Record flags set by reconciliation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionFlags(pub u32);

impl StorageIntentSatisfactionFlags {
    pub const EMPTY: Self = Self(0);
    pub const REASON_ROWS_TRUNCATED: Self = Self(1 << 0);
    pub const RECEIPT_ROWS_TRUNCATED: Self = Self(1 << 1);
    pub const EVIDENCE_REFS_TRUNCATED: Self = Self(1 << 2);
    pub const RECEIPT_SET_EVALUATED: Self = Self(1 << 3);
    pub const SNAPSHOT_GATED_BEFORE_RECEIPTS: Self = Self(1 << 4);
    pub const PRODUCER_FINDINGS_INCLUDED: Self = Self(1 << 5);

    /// Add flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when all flags in `required` are present.
    #[must_use]
    pub const fn contains_all(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }
}

/// Top-level satisfaction output record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionRecord {
    pub version: u16,
    pub state: StorageIntentSatisfactionClass,
    pub top_reason: StorageIntentSatisfactionReason,
    pub refusal: StorageIntentRefusalReason,
    pub policy_id: StorageIntentPolicyId,
    pub policy_revision: StorageIntentPolicyRevision,
    pub evidence_query_ref: StorageIntentEvidenceRef,
    pub satisfying_receipts: StorageIntentSatisfactionReceiptSet,
    pub evidence_refs: StorageIntentSatisfactionEvidenceSet,
    pub reasons: StorageIntentSatisfactionReasonSet,
    pub flags: StorageIntentSatisfactionFlags,
}

impl StorageIntentSatisfactionRecord {
    /// Empty unknown record.
    pub const EMPTY: Self = Self {
        version: STORAGE_INTENT_SATISFACTION_VERSION,
        state: StorageIntentSatisfactionClass::UnknownEvidence,
        top_reason: StorageIntentSatisfactionReason::None,
        refusal: StorageIntentRefusalReason::None,
        policy_id: StorageIntentPolicyId::ZERO,
        policy_revision: StorageIntentPolicyRevision(0),
        evidence_query_ref: StorageIntentSatisfactionReasonRecord::EMPTY.evidence_ref,
        satisfying_receipts: StorageIntentSatisfactionReceiptSet::EMPTY,
        evidence_refs: StorageIntentSatisfactionEvidenceSet::EMPTY,
        reasons: StorageIntentSatisfactionReasonSet::EMPTY,
        flags: StorageIntentSatisfactionFlags::EMPTY,
    };

    /// Build an initial satisfied record for a policy identity.
    #[must_use]
    pub const fn for_policy(policy: StorageIntentPolicy) -> Self {
        Self {
            version: STORAGE_INTENT_SATISFACTION_VERSION,
            state: StorageIntentSatisfactionClass::Satisfied,
            top_reason: StorageIntentSatisfactionReason::None,
            refusal: StorageIntentRefusalReason::None,
            policy_id: policy.policy_id,
            policy_revision: policy.revision,
            evidence_query_ref: StorageIntentSatisfactionReasonRecord::EMPTY.evidence_ref,
            satisfying_receipts: StorageIntentSatisfactionReceiptSet::EMPTY,
            evidence_refs: StorageIntentSatisfactionEvidenceSet::EMPTY,
            reasons: StorageIntentSatisfactionReasonSet::EMPTY,
            flags: StorageIntentSatisfactionFlags::EMPTY,
        }
    }

    fn add_flag(&mut self, flag: StorageIntentSatisfactionFlags) {
        self.flags = self.flags.union(flag);
    }

    fn add_reason(&mut self, row: StorageIntentSatisfactionReasonRecord) {
        if class_rank(row.state) > class_rank(self.state) {
            self.state = row.state;
            self.top_reason = row.reason;
            if row.refusal != StorageIntentRefusalReason::None {
                self.refusal = row.refusal;
            }
        } else if self.top_reason == StorageIntentSatisfactionReason::None
            && row.reason != StorageIntentSatisfactionReason::None
        {
            self.top_reason = row.reason;
            if row.refusal != StorageIntentRefusalReason::None {
                self.refusal = row.refusal;
            }
        }
        if row.evidence_ref.is_bound() && self.evidence_refs.push_unique(row.evidence_ref).is_err()
        {
            self.add_flag(StorageIntentSatisfactionFlags::EVIDENCE_REFS_TRUNCATED);
        }
        if self.reasons.push(row).is_err() {
            self.add_flag(StorageIntentSatisfactionFlags::REASON_ROWS_TRUNCATED);
            self.top_reason = StorageIntentSatisfactionReason::ReasonBufferFull;
        }
    }

    fn add_satisfying_receipt(&mut self, receipt_id: StorageIntentReceiptId) {
        if self.satisfying_receipts.push(receipt_id).is_err() {
            self.add_flag(StorageIntentSatisfactionFlags::RECEIPT_ROWS_TRUNCATED);
        }
    }
}

impl Default for StorageIntentSatisfactionRecord {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Policy transition context supplied by rollout or policy evidence.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[repr(u8)]
pub enum StorageIntentPolicyChangeClass {
    /// No policy change is relevant to this cut.
    #[default]
    None = 0,
    /// Current policy is stronger than receipts that may still exist.
    Strengthened = 1,
    /// Current policy is weaker and requires explicit operator consent.
    WeakenedRequiresConsent = 2,
    /// Current weaker policy carried explicit consent.
    WeakenedConsented = 3,
    /// The evidence cut spans mixed policy revisions.
    MixedRevision = 4,
}

impl_u8_canonical!(StorageIntentPolicyChangeClass, {
    None = 0 => "none",
    Strengthened = 1 => "strengthened",
    WeakenedRequiresConsent = 2 => "weakened-requires-consent",
    WeakenedConsented = 3 => "weakened-consented",
    MixedRevision = 4 => "mixed-revision",
});

/// Policy transition evidence supplied by rollout authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPolicyTransition {
    pub change: StorageIntentPolicyChangeClass,
    pub operator_consent_ref: StorageIntentEvidenceRef,
    pub rollout_ref: StorageIntentEvidenceRef,
}

/// Pending work that prevents final success.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentPendingWorkMask(pub u32);

impl StorageIntentPendingWorkMask {
    pub const EMPTY: Self = Self(0);
    pub const DURABLE_INTENT: Self = Self(1 << 0);
    pub const POLICY_STRENGTHENING: Self = Self(1 << 1);
    pub const REPAIR: Self = Self(1 << 2);
    pub const RELOCATION: Self = Self(1 << 3);
    pub const GEO_CATCHUP: Self = Self(1 << 4);
    pub const EVIDENCE_REFRESH: Self = Self(1 << 5);

    /// Add pending-work flags.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns true when any flag in `other` is present.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }
}

/// Reconciler options that must be supplied by policy/rollout callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentSatisfactionOptions {
    pub policy_transition: StorageIntentPolicyTransition,
    pub pending_work: StorageIntentPendingWorkMask,
    pub explicit_unsafe_volatile_policy: bool,
    pub posix_durable_floor: bool,
    pub known_no_legal_receipt_set: bool,
}

impl StorageIntentSatisfactionOptions {
    /// Strict authority reconciliation: no unsafe volatile opt-in or POSIX floor override.
    pub const STRICT_AUTHORITY: Self = Self {
        policy_transition: StorageIntentPolicyTransition {
            change: StorageIntentPolicyChangeClass::None,
            operator_consent_ref: StorageIntentSatisfactionReasonRecord::EMPTY.evidence_ref,
            rollout_ref: StorageIntentSatisfactionReasonRecord::EMPTY.evidence_ref,
        },
        pending_work: StorageIntentPendingWorkMask::EMPTY,
        explicit_unsafe_volatile_policy: false,
        posix_durable_floor: false,
        known_no_legal_receipt_set: false,
    };
}

impl Default for StorageIntentSatisfactionOptions {
    fn default() -> Self {
        Self::STRICT_AUTHORITY
    }
}

/// Required evidence family and policy-selected outcome when unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct StorageIntentRequiredEvidence {
    pub axis: StorageIntentSatisfactionAxis,
    pub kind: StorageIntentEvidenceKind,
    pub when_unusable: StorageIntentSatisfactionClass,
}

impl StorageIntentRequiredEvidence {
    /// Build a required family that becomes unknown evidence when unusable.
    #[must_use]
    pub const fn required(kind: StorageIntentEvidenceKind) -> Self {
        Self {
            axis: axis_for_evidence_kind(kind),
            kind,
            when_unusable: StorageIntentSatisfactionClass::UnknownEvidence,
        }
    }

    /// Build a family with an explicit policy-selected unusable outcome.
    #[must_use]
    pub const fn with_outcome(
        kind: StorageIntentEvidenceKind,
        when_unusable: StorageIntentSatisfactionClass,
    ) -> Self {
        Self {
            axis: axis_for_evidence_kind(kind),
            kind,
            when_unusable,
        }
    }
}

/// Common durable-authority evidence families. Callers may pass narrower or
/// broader policy-specific slices when the compiled policy selects different axes.
pub const STORAGE_INTENT_DURABLE_AUTHORITY_EVIDENCE: [StorageIntentRequiredEvidence; 10] = [
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::LocalIntentRecord),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::PlacementReceipt),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::MediaCapabilityEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::MembershipEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::OrderingEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::TrustDomainEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::CapacityAdmissionEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::RecoveryDegradationEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::TemporalEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::PolicyRolloutEvidence),
];

/// Full issue #874 evidence vocabulary. This is not automatically required for
/// every policy because `StorageIntentEvidenceQuerySnapshot` is a bounded cut
/// and policy #855 decides which axes are relevant.
pub const STORAGE_INTENT_FULL_SATISFACTION_EVIDENCE: [StorageIntentRequiredEvidence; 22] = [
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::LocalIntentRecord),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::PlacementReceipt),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::ReadFreshnessEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::DataShapeEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::LayoutAllocatorEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::MediaCostWearLedger),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::WorkloadEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::TransportPathEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::RamAuthorityEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::RelocationReceipt),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::SchedulerAdmissionRecord),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::CapacityAdmissionEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::RecoveryDegradationEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::PolicyRolloutEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::TenantIsolationEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::TemporalEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::MediaCapabilityEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::DecisionFrontierEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::ServiceObjectiveEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::OrderingEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::MembershipEvidence),
    StorageIntentRequiredEvidence::required(StorageIntentEvidenceKind::LifecycleGenerationEvidence),
];

/// Input to the read-only satisfaction reconciler.
#[derive(Clone, Copy, Debug)]
pub struct StorageIntentSatisfactionInput<'a> {
    pub policy: Option<StorageIntentPolicy>,
    pub evidence_query: Option<StorageIntentEvidenceQuerySnapshot>,
    pub receipts: &'a [StorageIntentReceipt],
    pub required_evidence: &'a [StorageIntentRequiredEvidence],
    pub producer_findings: &'a [StorageIntentSatisfactionReasonRecord],
    pub options: StorageIntentSatisfactionOptions,
}

/// Reconcile supplied policy, evidence query, receipts, and producer findings.
#[must_use]
pub fn reconcile_storage_intent_satisfaction(
    input: StorageIntentSatisfactionInput<'_>,
) -> StorageIntentSatisfactionRecord {
    let Some(policy) = input.policy else {
        let mut record = StorageIntentSatisfactionRecord::EMPTY;
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::Policy,
            StorageIntentSatisfactionClass::UnknownEvidence,
            StorageIntentSatisfactionReason::MissingCompiledPolicy,
        ));
        return record;
    };

    let mut record = StorageIntentSatisfactionRecord::for_policy(policy);
    if !policy_has_identity(policy) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::Policy,
            StorageIntentSatisfactionClass::UnknownEvidence,
            StorageIntentSatisfactionReason::MalformedCompiledPolicy,
        ));
        return record;
    }

    reconcile_policy_transition(&mut record, input.options);
    reconcile_volatile_policy(&mut record, policy, input.options);

    let Some(snapshot) = input.evidence_query else {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::EvidenceQuery,
            StorageIntentSatisfactionClass::UnknownEvidence,
            StorageIntentSatisfactionReason::MissingEvidenceQuerySnapshot,
        ));
        record.add_flag(StorageIntentSatisfactionFlags::SNAPSHOT_GATED_BEFORE_RECEIPTS);
        return record;
    };

    record.evidence_query_ref = snapshot_ref(snapshot);
    let snapshot_gate = reconcile_snapshot(&mut record, policy, snapshot);
    for requirement in input.required_evidence {
        reconcile_required_evidence(&mut record, snapshot, *requirement);
    }
    for finding in input.producer_findings {
        record.add_flag(StorageIntentSatisfactionFlags::PRODUCER_FINDINGS_INCLUDED);
        record.add_reason(*finding);
    }
    reconcile_pending_work(&mut record, input.options.pending_work);

    if snapshot_gate.blocks_durable_authority()
        && !matches!(
            snapshot_gate,
            StorageIntentSatisfactionClass::DegradedVisible
                | StorageIntentSatisfactionClass::UnsafeVolatile
        )
    {
        record.add_flag(StorageIntentSatisfactionFlags::SNAPSHOT_GATED_BEFORE_RECEIPTS);
        return record;
    }

    if record.state.blocks_durable_authority()
        && !matches!(
            record.state,
            StorageIntentSatisfactionClass::Converging
                | StorageIntentSatisfactionClass::DegradedVisible
                | StorageIntentSatisfactionClass::UnsafeVolatile
        )
    {
        return record;
    }

    reconcile_receipts(&mut record, policy, snapshot, input.receipts, input.options);
    record
}

/// Map an evidence family to the satisfaction axis that owns its interpretation.
#[must_use]
pub const fn axis_for_evidence_kind(
    kind: StorageIntentEvidenceKind,
) -> StorageIntentSatisfactionAxis {
    match kind {
        StorageIntentEvidenceKind::LocalIntentRecord => {
            StorageIntentSatisfactionAxis::LocalAckReceipt
        }
        StorageIntentEvidenceKind::PlacementReceipt => {
            StorageIntentSatisfactionAxis::PlacementReceipt
        }
        StorageIntentEvidenceKind::TransportPathEvidence => {
            StorageIntentSatisfactionAxis::TransportPath
        }
        StorageIntentEvidenceKind::MediaCostWearLedger => StorageIntentSatisfactionAxis::MediaWear,
        StorageIntentEvidenceKind::SchedulerAdmissionRecord => {
            StorageIntentSatisfactionAxis::SchedulerAdmission
        }
        StorageIntentEvidenceKind::RelocationReceipt => StorageIntentSatisfactionAxis::Relocation,
        StorageIntentEvidenceKind::OperatorExplanationProjection => {
            StorageIntentSatisfactionAxis::OperatorExplanation
        }
        StorageIntentEvidenceKind::MembershipEvidence => {
            StorageIntentSatisfactionAxis::MembershipEpoch
        }
        StorageIntentEvidenceKind::OrderingEvidence => {
            StorageIntentSatisfactionAxis::OrderingReplay
        }
        StorageIntentEvidenceKind::TrustDomainEvidence => StorageIntentSatisfactionAxis::Policy,
        StorageIntentEvidenceKind::CapacityAdmissionEvidence => {
            StorageIntentSatisfactionAxis::CapacityAdmission
        }
        StorageIntentEvidenceKind::RecoveryDegradationEvidence => {
            StorageIntentSatisfactionAxis::RecoveryDegradation
        }
        StorageIntentEvidenceKind::PolicyRolloutEvidence => {
            StorageIntentSatisfactionAxis::PolicyRollout
        }
        StorageIntentEvidenceKind::TenantIsolationEvidence => {
            StorageIntentSatisfactionAxis::TenantIsolation
        }
        StorageIntentEvidenceKind::PredictionEvidence
        | StorageIntentEvidenceKind::WorkloadEvidence => {
            StorageIntentSatisfactionAxis::WorkloadConfidence
        }
        StorageIntentEvidenceKind::DataShapeEvidence => StorageIntentSatisfactionAxis::DataShape,
        StorageIntentEvidenceKind::LayoutAllocatorEvidence => {
            StorageIntentSatisfactionAxis::LayoutAllocator
        }
        StorageIntentEvidenceKind::MeasurementAttributionEvidence => {
            StorageIntentSatisfactionAxis::PerformanceRow
        }
        StorageIntentEvidenceKind::EvidenceQuerySnapshot => {
            StorageIntentSatisfactionAxis::EvidenceQuery
        }
        StorageIntentEvidenceKind::ReadFreshnessEvidence => {
            StorageIntentSatisfactionAxis::ReadServing
        }
        StorageIntentEvidenceKind::ServiceObjectiveEvidence => {
            StorageIntentSatisfactionAxis::ServiceObjective
        }
        StorageIntentEvidenceKind::DecisionFrontierEvidence => {
            StorageIntentSatisfactionAxis::DecisionFrontier
        }
        StorageIntentEvidenceKind::TemporalEvidence => StorageIntentSatisfactionAxis::Temporal,
        StorageIntentEvidenceKind::MediaCapabilityEvidence => {
            StorageIntentSatisfactionAxis::MediaCapability
        }
        StorageIntentEvidenceKind::RamAuthorityEvidence => {
            StorageIntentSatisfactionAxis::RamAuthority
        }
        StorageIntentEvidenceKind::LifecycleGenerationEvidence => {
            StorageIntentSatisfactionAxis::LifecycleGeneration
        }
        StorageIntentEvidenceKind::ValidationArtifact => {
            StorageIntentSatisfactionAxis::FaultValidation
        }
        StorageIntentEvidenceKind::PreflightSimulationEvidence => {
            StorageIntentSatisfactionAxis::PreflightSimulation
        }
        StorageIntentEvidenceKind::ActionExecutionEvidence => {
            StorageIntentSatisfactionAxis::ActionExecution
        }
        StorageIntentEvidenceKind::ResultRefusalEvidence => {
            StorageIntentSatisfactionAxis::ResultRefusal
        }
        StorageIntentEvidenceKind::EvidenceRetentionEvidence => {
            StorageIntentSatisfactionAxis::EvidenceRetention
        }
        StorageIntentEvidenceKind::MetadataNamespaceEvidence => {
            StorageIntentSatisfactionAxis::MetadataNamespace
        }
        StorageIntentEvidenceKind::ComparatorEvidence => StorageIntentSatisfactionAxis::Comparator,
        StorageIntentEvidenceKind::ClaimGateEvidence => StorageIntentSatisfactionAxis::ClaimGate,
        StorageIntentEvidenceKind::Unknown => StorageIntentSatisfactionAxis::Unknown,
    }
}

const fn class_rank(class: StorageIntentSatisfactionClass) -> u8 {
    match class {
        StorageIntentSatisfactionClass::Satisfied => 0,
        StorageIntentSatisfactionClass::UnsafeVolatile => 1,
        StorageIntentSatisfactionClass::DegradedVisible => 2,
        StorageIntentSatisfactionClass::Converging => 3,
        StorageIntentSatisfactionClass::UnknownEvidence => 4,
        StorageIntentSatisfactionClass::Blocked => 5,
        StorageIntentSatisfactionClass::Refused => 6,
    }
}

const fn policy_has_identity(policy: StorageIntentPolicy) -> bool {
    !policy.policy_id.is_zero() && policy.revision.0 > 0
}

const fn policy_requests_volatile(policy: StorageIntentPolicy) -> bool {
    matches!(
        policy.requested_guarantee,
        StorageIntentGuaranteeClass::VolatileLocal
            | StorageIntentGuaranteeClass::VolatileReplicated
    ) && matches!(policy.durability.min_state, DurabilityState::Volatile)
}

fn reconcile_policy_transition(
    record: &mut StorageIntentSatisfactionRecord,
    options: StorageIntentSatisfactionOptions,
) {
    match options.policy_transition.change {
        StorageIntentPolicyChangeClass::WeakenedRequiresConsent
            if !options.policy_transition.operator_consent_ref.is_bound() =>
        {
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::PolicyRollout,
                StorageIntentSatisfactionClass::Blocked,
                StorageIntentSatisfactionReason::PolicyWeakeningNeedsOperatorConsent,
            );
            row.evidence_kind = StorageIntentEvidenceKind::PolicyRolloutEvidence;
            row.evidence_ref = options.policy_transition.rollout_ref;
            record.add_reason(row);
        }
        StorageIntentPolicyChangeClass::Strengthened => {
            record.add_reason(StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::PolicyRollout,
                StorageIntentSatisfactionClass::Converging,
                StorageIntentSatisfactionReason::PendingPolicyStrengtheningConvergence,
            ));
        }
        StorageIntentPolicyChangeClass::MixedRevision => {
            record.add_reason(StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::PolicyRollout,
                StorageIntentSatisfactionClass::UnknownEvidence,
                StorageIntentSatisfactionReason::WrongEpochEvidence,
            ));
        }
        _ => {}
    }
}

fn reconcile_volatile_policy(
    record: &mut StorageIntentSatisfactionRecord,
    policy: StorageIntentPolicy,
    options: StorageIntentSatisfactionOptions,
) {
    if !policy_requests_volatile(policy) {
        return;
    }
    if options.posix_durable_floor {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::Policy,
            StorageIntentSatisfactionClass::Refused,
            StorageIntentSatisfactionReason::VolatilePolicyDoesNotSatisfyPosixDurableFloor,
        ));
        return;
    }
    if !options.explicit_unsafe_volatile_policy {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::Policy,
            StorageIntentSatisfactionClass::Refused,
            StorageIntentSatisfactionReason::PolicyUnsafeVolatileRequiresOptIn,
        ));
    }
}

fn reconcile_snapshot(
    record: &mut StorageIntentSatisfactionRecord,
    policy: StorageIntentPolicy,
    snapshot: StorageIntentEvidenceQuerySnapshot,
) -> StorageIntentSatisfactionClass {
    let row = if !snapshot_has_basic_identity(snapshot) {
        Some(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::EvidenceQuery,
            StorageIntentSatisfactionClass::UnknownEvidence,
            StorageIntentSatisfactionReason::EvidenceQueryNotAuthoritative,
        ))
    } else if snapshot.policy_id != policy.policy_id || snapshot.policy_revision != policy.revision
    {
        Some(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::EvidenceQuery,
            StorageIntentSatisfactionClass::UnknownEvidence,
            StorageIntentSatisfactionReason::EvidenceQueryPolicyMismatch,
        ))
    } else if snapshot.refusal != StorageIntentRefusalReason::None {
        let mut row = StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::EvidenceQuery,
            StorageIntentSatisfactionClass::Refused,
            StorageIntentSatisfactionReason::EvidenceQueryRefused,
        );
        row.refusal = snapshot.refusal;
        Some(row)
    } else {
        match snapshot.completeness {
            EvidenceCompletenessVerdict::CompleteForPurpose => None,
            EvidenceCompletenessVerdict::PartialAdmissible
            | EvidenceCompletenessVerdict::DegradedVisible => {
                Some(StorageIntentSatisfactionReasonRecord::new(
                    StorageIntentSatisfactionAxis::EvidenceQuery,
                    StorageIntentSatisfactionClass::DegradedVisible,
                    StorageIntentSatisfactionReason::EvidenceQueryNotAuthoritative,
                ))
            }
            EvidenceCompletenessVerdict::Blocked => {
                Some(StorageIntentSatisfactionReasonRecord::new(
                    StorageIntentSatisfactionAxis::EvidenceQuery,
                    StorageIntentSatisfactionClass::Blocked,
                    StorageIntentSatisfactionReason::EvidenceQueryNotAuthoritative,
                ))
            }
            EvidenceCompletenessVerdict::Refused => {
                Some(StorageIntentSatisfactionReasonRecord::new(
                    StorageIntentSatisfactionAxis::EvidenceQuery,
                    StorageIntentSatisfactionClass::Refused,
                    StorageIntentSatisfactionReason::EvidenceQueryRefused,
                ))
            }
            EvidenceCompletenessVerdict::UnsafeVisible => {
                Some(StorageIntentSatisfactionReasonRecord::new(
                    StorageIntentSatisfactionAxis::EvidenceQuery,
                    StorageIntentSatisfactionClass::UnsafeVolatile,
                    StorageIntentSatisfactionReason::UnsafeVolatilePolicySatisfied,
                ))
            }
            EvidenceCompletenessVerdict::UnknownEvidence => {
                Some(StorageIntentSatisfactionReasonRecord::new(
                    StorageIntentSatisfactionAxis::EvidenceQuery,
                    StorageIntentSatisfactionClass::UnknownEvidence,
                    StorageIntentSatisfactionReason::EvidenceQueryNotAuthoritative,
                ))
            }
        }
    };

    match row {
        Some(mut row) => {
            row.evidence_kind = StorageIntentEvidenceKind::EvidenceQuerySnapshot;
            row.evidence_ref = snapshot_ref(snapshot);
            let state = row.state;
            record.add_reason(row);
            state
        }
        None => StorageIntentSatisfactionClass::Satisfied,
    }
}

fn reconcile_required_evidence(
    record: &mut StorageIntentSatisfactionRecord,
    snapshot: StorageIntentEvidenceQuerySnapshot,
    requirement: StorageIntentRequiredEvidence,
) {
    if snapshot.contains_fresh_authority_family(requirement.kind) {
        if let Some(evidence_ref) = family_ref(snapshot, requirement.kind) {
            if record.evidence_refs.push_unique(evidence_ref).is_err() {
                record.add_flag(StorageIntentSatisfactionFlags::EVIDENCE_REFS_TRUNCATED);
            }
        }
        return;
    }

    let state = snapshot.family_freshness.state_for_kind(requirement.kind);
    let mut reason = reason_for_family_state_kind(requirement.kind, state);
    if matches!(state, EvidenceFamilyFreshnessState::Fresh) {
        reason = StorageIntentSatisfactionReason::EvidenceRefOutOfCut;
    }
    let mut row = StorageIntentSatisfactionReasonRecord::new(
        requirement.axis,
        requirement.when_unusable,
        reason,
    );
    row.evidence_kind = requirement.kind;
    row.evidence_state = state;
    row.evidence_ref = family_ref(snapshot, requirement.kind).unwrap_or_default();
    if matches!(state, EvidenceFamilyFreshnessState::Refused) {
        row.refusal = StorageIntentRefusalReason::EvidenceNotUsable;
    }
    record.add_reason(row);
}

fn reconcile_pending_work(
    record: &mut StorageIntentSatisfactionRecord,
    pending: StorageIntentPendingWorkMask,
) {
    if pending.intersects(StorageIntentPendingWorkMask::DURABLE_INTENT) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::LocalAckReceipt,
            StorageIntentSatisfactionClass::Converging,
            StorageIntentSatisfactionReason::PendingDurableIntentConvergence,
        ));
    }
    if pending.intersects(StorageIntentPendingWorkMask::POLICY_STRENGTHENING) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::PolicyRollout,
            StorageIntentSatisfactionClass::Converging,
            StorageIntentSatisfactionReason::PendingPolicyStrengtheningConvergence,
        ));
    }
    if pending.intersects(
        StorageIntentPendingWorkMask::REPAIR.union(StorageIntentPendingWorkMask::RELOCATION),
    ) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::Relocation,
            StorageIntentSatisfactionClass::Blocked,
            StorageIntentSatisfactionReason::RepairRelocationWaiting,
        ));
    }
    if pending.intersects(StorageIntentPendingWorkMask::GEO_CATCHUP) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::RecoveryDegradation,
            StorageIntentSatisfactionClass::Blocked,
            StorageIntentSatisfactionReason::GeoCatchupWaiting,
        ));
    }
    if pending.intersects(StorageIntentPendingWorkMask::EVIDENCE_REFRESH) {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::EvidenceQuery,
            StorageIntentSatisfactionClass::Blocked,
            StorageIntentSatisfactionReason::EvidenceRefreshWaiting,
        ));
    }
}

fn reconcile_receipts(
    record: &mut StorageIntentSatisfactionRecord,
    policy: StorageIntentPolicy,
    snapshot: StorageIntentEvidenceQuerySnapshot,
    receipts: &[StorageIntentReceipt],
    options: StorageIntentSatisfactionOptions,
) {
    record.add_flag(StorageIntentSatisfactionFlags::RECEIPT_SET_EVALUATED);
    if receipts.is_empty() {
        let class = if options.known_no_legal_receipt_set {
            StorageIntentSatisfactionClass::Refused
        } else {
            StorageIntentSatisfactionClass::UnknownEvidence
        };
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::ReceiptSet,
            class,
            if options.known_no_legal_receipt_set {
                StorageIntentSatisfactionReason::NoLegalReceiptSet
            } else {
                StorageIntentSatisfactionReason::NoCandidateReceipts
            },
        ));
        return;
    }

    let mut first_refusal = StorageIntentRefusalReason::None;
    let mut old_revision_seen = false;

    for receipt in receipts {
        if receipt.policy_id != policy.policy_id {
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::UnknownEvidence,
                StorageIntentSatisfactionReason::ReceiptPolicyMismatch,
            );
            row.receipt_id = receipt.receipt_id;
            record.add_reason(row);
            continue;
        }
        if receipt.policy_revision.0 < policy.revision.0 {
            old_revision_seen = true;
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::Converging,
                StorageIntentSatisfactionReason::ReceiptRevisionBehindPolicy,
            );
            row.receipt_id = receipt.receipt_id;
            record.add_reason(row);
            continue;
        }
        if receipt.policy_revision.0 > snapshot.policy_revision.0 {
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::UnknownEvidence,
                StorageIntentSatisfactionReason::ReceiptRevisionAheadOfPolicyCut,
            );
            row.receipt_id = receipt.receipt_id;
            record.add_reason(row);
            continue;
        }
        if let Some(missing_ref) = receipt_ref_not_in_cut(snapshot, *receipt) {
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::UnknownEvidence,
                StorageIntentSatisfactionReason::EvidenceRefOutOfCut,
            );
            row.receipt_id = receipt.receipt_id;
            row.evidence_kind = missing_ref.kind;
            row.evidence_ref = missing_ref;
            record.add_reason(row);
            continue;
        }
        if receipt.evidence_refs.is_empty() {
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::UnknownEvidence,
                StorageIntentSatisfactionReason::ReceiptEvidenceMissing,
            );
            row.receipt_id = receipt.receipt_id;
            record.add_reason(row);
            continue;
        }

        let result = evaluate_receipt_against_policy(policy, *receipt);
        if result.satisfied {
            record.add_satisfying_receipt(receipt.receipt_id);
        } else {
            if first_refusal == StorageIntentRefusalReason::None {
                first_refusal = result.refusal;
            }
            let mut row = StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::ReceiptSet,
                StorageIntentSatisfactionClass::Refused,
                reason_for_receipt_refusal(result.refusal),
            );
            row.refusal = result.refusal;
            row.receipt_id = receipt.receipt_id;
            record.add_reason(row);
        }
    }

    if !record.satisfying_receipts.is_empty() {
        if policy_requests_volatile(policy) && options.explicit_unsafe_volatile_policy {
            record.add_reason(StorageIntentSatisfactionReasonRecord::new(
                StorageIntentSatisfactionAxis::Policy,
                StorageIntentSatisfactionClass::UnsafeVolatile,
                StorageIntentSatisfactionReason::UnsafeVolatilePolicySatisfied,
            ));
        }
        return;
    }

    if old_revision_seen
        || options
            .pending_work
            .intersects(StorageIntentPendingWorkMask::POLICY_STRENGTHENING)
        || matches!(
            options.policy_transition.change,
            StorageIntentPolicyChangeClass::Strengthened
        )
    {
        record.add_reason(StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::PolicyRollout,
            StorageIntentSatisfactionClass::Converging,
            StorageIntentSatisfactionReason::PendingPolicyStrengtheningConvergence,
        ));
    } else if first_refusal == StorageIntentRefusalReason::None
        && matches!(
            record.state,
            StorageIntentSatisfactionClass::UnknownEvidence
                | StorageIntentSatisfactionClass::Blocked
        )
    {
        return;
    } else {
        let reason = if first_refusal == StorageIntentRefusalReason::None {
            StorageIntentRefusalReason::NoLegalReceiptSet
        } else {
            first_refusal
        };
        let mut row = StorageIntentSatisfactionReasonRecord::new(
            StorageIntentSatisfactionAxis::ReceiptSet,
            StorageIntentSatisfactionClass::Refused,
            if reason == StorageIntentRefusalReason::NoLegalReceiptSet {
                StorageIntentSatisfactionReason::NoLegalReceiptSet
            } else {
                reason_for_receipt_refusal(reason)
            },
        );
        row.refusal = reason;
        record.add_reason(row);
    }
}

const fn reason_for_family_state(
    state: EvidenceFamilyFreshnessState,
) -> StorageIntentSatisfactionReason {
    match state {
        EvidenceFamilyFreshnessState::Missing => {
            StorageIntentSatisfactionReason::EvidenceFamilyMissing
        }
        EvidenceFamilyFreshnessState::Stale => StorageIntentSatisfactionReason::EvidenceFamilyStale,
        EvidenceFamilyFreshnessState::Contradictory => {
            StorageIntentSatisfactionReason::EvidenceFamilyContradictory
        }
        EvidenceFamilyFreshnessState::Compacted | EvidenceFamilyFreshnessState::Redacted => {
            StorageIntentSatisfactionReason::EvidenceFamilyCompacted
        }
        EvidenceFamilyFreshnessState::Refused => {
            StorageIntentSatisfactionReason::EvidenceFamilyRefused
        }
        EvidenceFamilyFreshnessState::Fresh => StorageIntentSatisfactionReason::None,
        EvidenceFamilyFreshnessState::Unknown
        | EvidenceFamilyFreshnessState::Superseded
        | EvidenceFamilyFreshnessState::Unavailable => {
            StorageIntentSatisfactionReason::EvidenceFamilyUnavailable
        }
    }
}

/// Map evidence-kind and family-state to a specific satisfaction reason.
/// Evidence-kind-specific staleness, wrong-domain, and degraded conditions
/// produce precise reasons so that consumers can distinguish
/// transport-path, read-serving, data-shape, layout, read-refusal, and
/// recovery-degradation evidence problems without decoding generic
/// family-state reasons.
const fn reason_for_family_state_kind(
    kind: StorageIntentEvidenceKind,
    state: EvidenceFamilyFreshnessState,
) -> StorageIntentSatisfactionReason {
    match kind {
        StorageIntentEvidenceKind::TransportPathEvidence => match state {
            EvidenceFamilyFreshnessState::Stale | EvidenceFamilyFreshnessState::Missing => {
                StorageIntentSatisfactionReason::StaleTransportPathEvidence
            }
            _ => reason_for_family_state(state),
        },
        StorageIntentEvidenceKind::ReadFreshnessEvidence => match state {
            EvidenceFamilyFreshnessState::Stale | EvidenceFamilyFreshnessState::Missing => {
                StorageIntentSatisfactionReason::StaleReadServingEvidence
            }
            EvidenceFamilyFreshnessState::Refused => {
                StorageIntentSatisfactionReason::DegradedReadRefused
            }
            _ => reason_for_family_state(state),
        },
        StorageIntentEvidenceKind::DataShapeEvidence => match state {
            EvidenceFamilyFreshnessState::Missing
            | EvidenceFamilyFreshnessState::Stale
            | EvidenceFamilyFreshnessState::Contradictory => {
                StorageIntentSatisfactionReason::WrongDomainDataShapeEvidence
            }
            _ => reason_for_family_state(state),
        },
        StorageIntentEvidenceKind::LayoutAllocatorEvidence => match state {
            EvidenceFamilyFreshnessState::Missing | EvidenceFamilyFreshnessState::Stale => {
                StorageIntentSatisfactionReason::StaleMirrorOnlyLayoutEvidence
            }
            _ => reason_for_family_state(state),
        },
        StorageIntentEvidenceKind::CapacityAdmissionEvidence => match state {
            EvidenceFamilyFreshnessState::Stale
            | EvidenceFamilyFreshnessState::Missing
            | EvidenceFamilyFreshnessState::Contradictory => {
                StorageIntentSatisfactionReason::CapacityReserveExhausted
            }
            _ => reason_for_family_state(state),
        },
        StorageIntentEvidenceKind::RecoveryDegradationEvidence => match state {
            EvidenceFamilyFreshnessState::Refused => {
                StorageIntentSatisfactionReason::RecoveryDegradationRefused
            }
            _ => reason_for_family_state(state),
        },
        _ => reason_for_family_state(state),
    }
}

const fn reason_for_receipt_refusal(
    refusal: StorageIntentRefusalReason,
) -> StorageIntentSatisfactionReason {
    match refusal {
        StorageIntentRefusalReason::None => StorageIntentSatisfactionReason::None,
        StorageIntentRefusalReason::NoLegalReceiptSet => {
            StorageIntentSatisfactionReason::NoLegalReceiptSet
        }
        StorageIntentRefusalReason::FailureDomainNotMet => {
            StorageIntentSatisfactionReason::UnderWidthFailureDomainPlacement
        }
        StorageIntentRefusalReason::DurabilityOrRpoNotMet => {
            StorageIntentSatisfactionReason::GeoLagCrossedPolicy
        }
        StorageIntentRefusalReason::CacheCannotBeAuthority
        | StorageIntentRefusalReason::VolatileRamCannotSatisfyDurableIntent => {
            StorageIntentSatisfactionReason::CacheOnlyCannotSatisfyDurable
        }
        StorageIntentRefusalReason::StaleKeyEpoch => StorageIntentSatisfactionReason::WrongKeyEpoch,
        StorageIntentRefusalReason::WrongDomain => {
            StorageIntentSatisfactionReason::WrongDomainDataShapeEvidence
        }
        StorageIntentRefusalReason::EvidenceNotUsable
        | StorageIntentRefusalReason::MissingMediaCapabilityEvidence
        | StorageIntentRefusalReason::StaleMediaCapabilityEvidence => {
            StorageIntentSatisfactionReason::NotAuthoritativeEnough
        }
        _ => StorageIntentSatisfactionReason::ReceiptPredicateRefused,
    }
}

const fn snapshot_ref(snapshot: StorageIntentEvidenceQuerySnapshot) -> StorageIntentEvidenceRef {
    StorageIntentEvidenceRef {
        kind: StorageIntentEvidenceKind::EvidenceQuerySnapshot,
        id: snapshot.snapshot_id,
        generation: snapshot.producer_generation,
        version: STORAGE_INTENT_SATISFACTION_VERSION,
    }
}

fn snapshot_has_basic_identity(snapshot: StorageIntentEvidenceQuerySnapshot) -> bool {
    snapshot.has_query_identity()
        && snapshot.has_policy_identity()
        && snapshot.has_subject_scope()
        && snapshot.has_frontiers()
        && snapshot.has_source_replay_anchor()
        && !matches!(
            snapshot.subject.scope_class,
            EvidenceQuerySubjectScopeClass::Unknown
        )
}

fn family_ref(
    snapshot: StorageIntentEvidenceQuerySnapshot,
    kind: StorageIntentEvidenceKind,
) -> Option<StorageIntentEvidenceRef> {
    let (families, len) = snapshot.family_freshness.as_parts();
    let mut index = 0;
    while index < len as usize {
        let family = families[index];
        if family.kind == kind && family.evidence_ref.is_bound() {
            return Some(family.evidence_ref);
        }
        index += 1;
    }
    None
}

fn receipt_ref_not_in_cut(
    snapshot: StorageIntentEvidenceQuerySnapshot,
    receipt: StorageIntentReceipt,
) -> Option<StorageIntentEvidenceRef> {
    let (refs, len) = receipt.evidence_refs.as_parts();
    let mut index = 0;
    while index < len as usize {
        let evidence_ref = refs[index];
        if evidence_ref.is_bound() && !snapshot.included_refs.contains_ref(evidence_ref) {
            return Some(evidence_ref);
        }
        index += 1;
    }
    None
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

/// Returns true when an earned receipt class satisfies the policy floor.
#[must_use]
pub const fn receipt_class_satisfies_policy_floor(
    policy: StorageIntentPolicy,
    earned: StorageIntentGuaranteeClass,
) -> bool {
    GuaranteeCapabilities::provided_by(earned).satisfies(GuaranteeCapabilities::required_by(
        policy.requested_guarantee,
    ))
}

/// Returns true when a receipt has all failure-domain dimensions requested by policy.
#[must_use]
pub const fn receipt_domains_satisfy_policy(
    policy: StorageIntentPolicy,
    achieved: FailureDomainMask,
) -> bool {
    achieved.contains_all(policy.required_failure_domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        DurabilityReceiptState, DurabilityRequirement, EvidenceConsumerClass,
        EvidenceFamilyFreshness, EvidenceQueryContextClass, EvidenceQuerySubjectScope,
        FailureDomainDimension, MediaRoleRequirement, ProximityClass, StorageIntentActionClass,
        StorageIntentDomainId, StorageIntentEvidenceRefs, StorageIntentObjectScope,
        StorageMediaClass, StorageMediaRole,
    };

    const POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId([7_u8; 16]);
    const DATASET_ID: StorageIntentDomainId = StorageIntentDomainId([8_u8; 16]);

    fn evidence_ref(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(
            kind,
            StorageIntentEvidenceId([byte; 32]),
            u64::from(byte),
            1,
        )
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

    fn policy(revision: u64, guarantee: StorageIntentGuaranteeClass) -> StorageIntentPolicy {
        let durability = if GuaranteeCapabilities::provided_by(guarantee).satisfies(
            GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::LocalIntent),
        ) {
            DurabilityRequirement::DURABLE_INTENT_ZERO_LAG
        } else {
            DurabilityRequirement::VOLATILE
        };
        StorageIntentPolicy {
            policy_id: POLICY_ID,
            revision: StorageIntentPolicyRevision(revision),
            requested_guarantee: guarantee,
            required_failure_domains: FailureDomainMask::LOCAL,
            max_proximity: ProximityClass::LocalMedia,
            durability,
            media: MediaRoleRequirement::AUTHORITY,
            ..StorageIntentPolicy::default()
        }
    }

    fn receipt(
        id: u8,
        revision: u64,
        guarantee: StorageIntentGuaranteeClass,
    ) -> StorageIntentReceipt {
        let mut refs = StorageIntentEvidenceRefs::EMPTY;
        refs.push(evidence_ref(
            StorageIntentEvidenceKind::LocalIntentRecord,
            1,
        ))
        .unwrap();
        StorageIntentReceipt {
            receipt_id: StorageIntentReceiptId([id; 16]),
            policy_id: POLICY_ID,
            policy_revision: StorageIntentPolicyRevision(revision),
            ack_class: guarantee,
            failure_domains: FailureDomainMask::LOCAL,
            proximity: ProximityClass::LocalMedia,
            durability: DurabilityReceiptState {
                state: if GuaranteeCapabilities::provided_by(guarantee).satisfies(
                    GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::FullPlacement),
                ) {
                    DurabilityState::FullPlacement
                } else if GuaranteeCapabilities::provided_by(guarantee).satisfies(
                    GuaranteeCapabilities::required_by(StorageIntentGuaranteeClass::LocalIntent),
                ) {
                    DurabilityState::DurableIntent
                } else {
                    DurabilityState::Volatile
                },
                observed_lag_ms: 0,
                lag_known: true,
            },
            media_role: StorageMediaRole::SyncIntent,
            media_class: StorageMediaClass::NvmeFlash,
            action_class: StorageIntentActionClass::NewWriteShaping,
            evidence_refs: refs,
            ..StorageIntentReceipt::default()
        }
    }

    fn snapshot_with_families(
        revision: u64,
        families: &[(StorageIntentEvidenceKind, EvidenceFamilyFreshnessState, u8)],
    ) -> StorageIntentEvidenceQuerySnapshot {
        let mut snapshot = StorageIntentEvidenceQuerySnapshot {
            snapshot_id: StorageIntentEvidenceId([40_u8; 32]),
            query_id: StorageIntentEvidenceId([41_u8; 32]),
            consumer: EvidenceConsumerClass::Reconciler,
            context: EvidenceQueryContextClass::RequestAdmission,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::Dataset,
                object_scope: StorageIntentObjectScope {
                    dataset_id: DATASET_ID,
                    object_id: StorageIntentEvidenceId([9_u8; 32]),
                    range_start: 0,
                    range_len: 4096,
                    generation: 1,
                },
                ..EvidenceQuerySubjectScope::default()
            },
            policy_id: POLICY_ID,
            policy_revision: StorageIntentPolicyRevision(revision),
            temporal_frontier_ms: 20_000,
            freshness_frontier_ms: 20_000,
            source_catalog_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 42),
            source_index_ref: evidence_ref(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 43),
            source_index_generation: 1,
            producer_generation: 1,
            producer_watermark_ms: 20_000,
            completeness: EvidenceCompletenessVerdict::CompleteForPurpose,
            ..StorageIntentEvidenceQuerySnapshot::default()
        };

        for (kind, state, byte) in families {
            let row = freshness_row(*kind, *state, *byte);
            snapshot.family_freshness.push(row).unwrap();
            snapshot.included_refs.push(row.evidence_ref).unwrap();
        }
        snapshot
    }

    fn basic_input<'a>(
        policy: StorageIntentPolicy,
        snapshot: StorageIntentEvidenceQuerySnapshot,
        receipts: &'a [StorageIntentReceipt],
        required_evidence: &'a [StorageIntentRequiredEvidence],
    ) -> StorageIntentSatisfactionInput<'a> {
        StorageIntentSatisfactionInput {
            policy: Some(policy),
            evidence_query: Some(snapshot),
            receipts,
            required_evidence,
            producer_findings: &[],
            options: StorageIntentSatisfactionOptions::default(),
        }
    }

    #[test]
    fn satisfied_current_receipt_records_receipt_id() {
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::LocalIntentRecord,
        )];
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let receipts = [receipt(3, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &required,
        ));

        assert_eq!(record.state, StorageIntentSatisfactionClass::Satisfied);
        assert!(record
            .satisfying_receipts
            .contains(StorageIntentReceiptId([3; 16])));
    }

    #[test]
    fn policy_strengthening_with_old_bytes_converges() {
        let snapshot = snapshot_with_families(
            2,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let receipts = [receipt(4, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut input = basic_input(
            policy(2, StorageIntentGuaranteeClass::FullPlacement),
            snapshot,
            &receipts,
            &[],
        );
        input.options.policy_transition.change = StorageIntentPolicyChangeClass::Strengthened;

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(record.state, StorageIntentSatisfactionClass::Converging);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::ReceiptRevisionBehindPolicy));
    }

    #[test]
    fn policy_weakening_requires_operator_consent() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let receipts = [receipt(5, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut input = basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &[],
        );
        input.options.policy_transition.change =
            StorageIntentPolicyChangeClass::WeakenedRequiresConsent;

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(record.state, StorageIntentSatisfactionClass::Blocked);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::PolicyWeakeningNeedsOperatorConsent));
    }

    #[test]
    fn stale_transport_path_becomes_unknown_evidence() {
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::TransportPathEvidence,
        )];
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::TransportPathEvidence,
                EvidenceFamilyFreshnessState::Stale,
                2,
            )],
        );
        let receipts = [receipt(6, 1, StorageIntentGuaranteeClass::LocalIntent)];

        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &required,
        ));

        assert_eq!(
            record.state,
            StorageIntentSatisfactionClass::UnknownEvidence
        );
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleTransportPathEvidence));
    }

    #[test]
    fn degraded_visible_policy_can_report_missing_layout_as_degraded() {
        let required = [StorageIntentRequiredEvidence::with_outcome(
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
            StorageIntentSatisfactionClass::DegradedVisible,
        )];
        let snapshot = snapshot_with_families(
            1,
            &[
                (
                    StorageIntentEvidenceKind::LocalIntentRecord,
                    EvidenceFamilyFreshnessState::Fresh,
                    1,
                ),
                (
                    StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                    EvidenceFamilyFreshnessState::Missing,
                    3,
                ),
            ],
        );
        let receipts = [receipt(7, 1, StorageIntentGuaranteeClass::LocalIntent)];

        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &required,
        ));

        assert_eq!(
            record.state,
            StorageIntentSatisfactionClass::DegradedVisible
        );
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleMirrorOnlyLayoutEvidence));
    }

    #[test]
    fn under_width_failure_domain_placement_is_refused() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let receipts = [receipt(8, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut durable = policy(1, StorageIntentGuaranteeClass::LocalIntent);
        durable.required_failure_domains =
            FailureDomainMask::LOCAL.with(FailureDomainDimension::Rack);

        let record =
            reconcile_storage_intent_satisfaction(basic_input(durable, snapshot, &receipts, &[]));

        assert_eq!(record.state, StorageIntentSatisfactionClass::Refused);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::UnderWidthFailureDomainPlacement));
    }

    #[test]
    fn geo_async_lag_crossing_policy_is_refused() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let mut receipt = receipt(9, 1, StorageIntentGuaranteeClass::GeoAsync);
        receipt.durability.observed_lag_ms = 500;
        let mut geo_policy = policy(1, StorageIntentGuaranteeClass::GeoAsync);
        geo_policy.durability.max_lag_ms = 100;

        let record = reconcile_storage_intent_satisfaction(basic_input(
            geo_policy,
            snapshot,
            &[receipt],
            &[],
        ));

        assert_eq!(record.state, StorageIntentSatisfactionClass::Refused);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::GeoLagCrossedPolicy));
    }

    #[test]
    fn capacity_reserve_exhaustion_blocks() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let finding = StorageIntentSatisfactionReasonRecord {
            axis: StorageIntentSatisfactionAxis::CapacityAdmission,
            state: StorageIntentSatisfactionClass::Blocked,
            reason: StorageIntentSatisfactionReason::CapacityReserveExhausted,
            evidence_kind: StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            ..StorageIntentSatisfactionReasonRecord::EMPTY
        };
        let receipts = [receipt(10, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut input = basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &[],
        );
        let findings = [finding];
        input.producer_findings = &findings;

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(record.state, StorageIntentSatisfactionClass::Blocked);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::CapacityReserveExhausted));
    }

    #[test]
    fn stale_read_serving_and_wrong_domain_data_shape_are_typed() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let findings = [
            StorageIntentSatisfactionReasonRecord {
                axis: StorageIntentSatisfactionAxis::ReadServing,
                state: StorageIntentSatisfactionClass::UnknownEvidence,
                reason: StorageIntentSatisfactionReason::StaleReadServingEvidence,
                evidence_kind: StorageIntentEvidenceKind::ReadFreshnessEvidence,
                ..StorageIntentSatisfactionReasonRecord::EMPTY
            },
            StorageIntentSatisfactionReasonRecord {
                axis: StorageIntentSatisfactionAxis::DataShape,
                state: StorageIntentSatisfactionClass::Refused,
                reason: StorageIntentSatisfactionReason::WrongDedupOrEncryptionDomain,
                evidence_kind: StorageIntentEvidenceKind::DataShapeEvidence,
                ..StorageIntentSatisfactionReasonRecord::EMPTY
            },
        ];
        let receipts = [receipt(11, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut input = basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &[],
        );
        input.producer_findings = &findings;

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(record.state, StorageIntentSatisfactionClass::Refused);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleReadServingEvidence));
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::WrongDedupOrEncryptionDomain));
    }

    #[test]
    fn stale_mirror_layout_and_degraded_read_refusal_are_preserved() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let findings = [
            StorageIntentSatisfactionReasonRecord {
                axis: StorageIntentSatisfactionAxis::LayoutAllocator,
                state: StorageIntentSatisfactionClass::DegradedVisible,
                reason: StorageIntentSatisfactionReason::StaleMirrorOnlyLayoutEvidence,
                evidence_kind: StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                ..StorageIntentSatisfactionReasonRecord::EMPTY
            },
            StorageIntentSatisfactionReasonRecord {
                axis: StorageIntentSatisfactionAxis::RecoveryDegradation,
                state: StorageIntentSatisfactionClass::Refused,
                reason: StorageIntentSatisfactionReason::RecoveryDegradationRefused,
                evidence_kind: StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                ..StorageIntentSatisfactionReasonRecord::EMPTY
            },
        ];
        let receipts = [receipt(12, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let mut input = basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &[],
        );
        input.producer_findings = &findings;

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(record.state, StorageIntentSatisfactionClass::Refused);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleMirrorOnlyLayoutEvidence));
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::RecoveryDegradationRefused));
    }

    #[test]
    fn cache_only_receipt_cannot_satisfy_durable_policy() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let mut cache_receipt = receipt(13, 1, StorageIntentGuaranteeClass::FullPlacement);
        cache_receipt.media_role = StorageMediaRole::ReadCache;

        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::FullPlacement),
            snapshot,
            &[cache_receipt],
            &[],
        ));

        assert_eq!(record.state, StorageIntentSatisfactionClass::Refused);
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::CacheOnlyCannotSatisfyDurable));
    }

    #[test]
    fn volatile_policy_can_be_explicitly_unsafe_but_not_posix_durable() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let receipts = [receipt(14, 1, StorageIntentGuaranteeClass::VolatileLocal)];
        let mut input = basic_input(
            policy(1, StorageIntentGuaranteeClass::VolatileLocal),
            snapshot,
            &receipts,
            &[],
        );
        input.options.explicit_unsafe_volatile_policy = true;

        let record = reconcile_storage_intent_satisfaction(input);
        assert_eq!(record.state, StorageIntentSatisfactionClass::UnsafeVolatile);

        let mut posix_input = input;
        posix_input.options.posix_durable_floor = true;
        let posix_record = reconcile_storage_intent_satisfaction(posix_input);
        assert_eq!(posix_record.state, StorageIntentSatisfactionClass::Refused);
        assert!(posix_record.reasons.contains_reason(
            StorageIntentSatisfactionReason::VolatilePolicyDoesNotSatisfyPosixDurableFloor
        ));
    }

    #[test]
    fn missing_evidence_snapshot_stops_before_receipts() {
        let receipts = [receipt(15, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let input = StorageIntentSatisfactionInput {
            policy: Some(policy(1, StorageIntentGuaranteeClass::LocalIntent)),
            evidence_query: None,
            receipts: &receipts,
            required_evidence: &[],
            producer_findings: &[],
            options: StorageIntentSatisfactionOptions::default(),
        };

        let record = reconcile_storage_intent_satisfaction(input);

        assert_eq!(
            record.state,
            StorageIntentSatisfactionClass::UnknownEvidence
        );
        assert!(record
            .flags
            .contains_all(StorageIntentSatisfactionFlags::SNAPSHOT_GATED_BEFORE_RECEIPTS));
        assert!(record.satisfying_receipts.is_empty());
    }

    #[test]
    fn new_evidence_kinds_map_to_correct_axes() {
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::PreflightSimulationEvidence),
            StorageIntentSatisfactionAxis::PreflightSimulation
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::ActionExecutionEvidence),
            StorageIntentSatisfactionAxis::ActionExecution
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::ResultRefusalEvidence),
            StorageIntentSatisfactionAxis::ResultRefusal
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::EvidenceRetentionEvidence),
            StorageIntentSatisfactionAxis::EvidenceRetention
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::MetadataNamespaceEvidence),
            StorageIntentSatisfactionAxis::MetadataNamespace
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::ComparatorEvidence),
            StorageIntentSatisfactionAxis::Comparator
        );
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::ClaimGateEvidence),
            StorageIntentSatisfactionAxis::ClaimGate
        );

        // Unknown must still map to Unknown.
        assert_eq!(
            axis_for_evidence_kind(StorageIntentEvidenceKind::Unknown),
            StorageIntentSatisfactionAxis::Unknown
        );

        // Each new axis round-trips through discriminant encode/decode.
        for (axis, discriminant) in [
            (StorageIntentSatisfactionAxis::ActionExecution, 31u8),
            (StorageIntentSatisfactionAxis::ResultRefusal, 32),
            (StorageIntentSatisfactionAxis::EvidenceRetention, 33),
            (StorageIntentSatisfactionAxis::MetadataNamespace, 34),
            (StorageIntentSatisfactionAxis::PreflightSimulation, 35),
            (StorageIntentSatisfactionAxis::Comparator, 36),
            (StorageIntentSatisfactionAxis::ClaimGate, 37),
        ] {
            assert_eq!(axis.to_discriminant(), discriminant);
            assert_eq!(
                StorageIntentSatisfactionAxis::from_discriminant(discriminant),
                Some(axis)
            );
        }

        // Out-of-range discriminants fail closed.
        assert_eq!(StorageIntentSatisfactionAxis::from_discriminant(38), None);
        assert_eq!(StorageIntentSatisfactionAxis::from_discriminant(255), None);
    }

    #[test]
    fn topology_path_evidence_staleness_becomes_degraded_unknown() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::TransportPathEvidence,
                EvidenceFamilyFreshnessState::Stale,
                1,
            )],
        );
        let receipts = [receipt(20, 1, StorageIntentGuaranteeClass::LocalIntent)];
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::TransportPathEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &receipts,
            &required,
        ));

        assert_eq!(
            record.state,
            StorageIntentSatisfactionClass::UnknownEvidence
        );
        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleTransportPathEvidence));
    }

    #[test]
    fn under_width_failure_domain_placement_is_refused_by_receipt() {
        // A receipt that fails evaluate_receipt_against_policy on
        // failure-domain width should be refused. Use a LocalIntent
        // receipt against a FullPlacement policy with required domains that
        // the receipt cannot cover because of empty failure domains.
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::PlacementReceipt,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::PlacementReceipt,
        )];
        // receipt with ack=LocalIntent cannot satisfy policy=FullPlacement
        let mut receipt = receipt(21, 1, StorageIntentGuaranteeClass::LocalIntent);
        receipt.failure_domains = FailureDomainMask::EMPTY;
        let receipts = [receipt];
        let mut pol = policy(1, StorageIntentGuaranteeClass::FullPlacement);
        pol.required_failure_domains = FailureDomainMask::LOCAL;
        let input = basic_input(pol, snapshot, &receipts, &required);

        let record = reconcile_storage_intent_satisfaction(input);
        assert_ne!(record.state, StorageIntentSatisfactionClass::Satisfied);
    }

    #[test]
    fn geo_async_lag_crossing_policy_rejects_receipt() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LocalIntentRecord,
                EvidenceFamilyFreshnessState::Fresh,
                1,
            )],
        );
        let mut receipt = receipt(22, 1, StorageIntentGuaranteeClass::LocalIntent);
        receipt.durability.observed_lag_ms = 60_000;
        receipt.durability.lag_known = true;
        let receipts = [receipt];
        // Use a strong policy that demands low-lag placement.
        let mut pol = policy(1, StorageIntentGuaranteeClass::FullPlacement);
        pol.durability.max_lag_ms = 100;
        let input = basic_input(pol, snapshot, &receipts, &[]);

        let record = reconcile_storage_intent_satisfaction(input);
        assert!(record.state != StorageIntentSatisfactionClass::Satisfied);
    }

    #[test]
    fn exhausted_critical_reserves_becomes_degraded_or_blocked() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::CapacityAdmissionEvidence,
                EvidenceFamilyFreshnessState::Stale,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(23, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::CapacityReserveExhausted));
    }

    #[test]
    fn stale_read_serving_evidence_is_typed() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                EvidenceFamilyFreshnessState::Stale,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(24, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleReadServingEvidence));
    }

    #[test]
    fn wrong_domain_data_shape_evidence_is_typed() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::DataShapeEvidence,
                EvidenceFamilyFreshnessState::Contradictory,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::DataShapeEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(25, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::WrongDomainDataShapeEvidence));
    }

    #[test]
    fn stale_layout_allocator_evidence_is_typed() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::LayoutAllocatorEvidence,
                EvidenceFamilyFreshnessState::Missing,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::LayoutAllocatorEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(26, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::StaleMirrorOnlyLayoutEvidence));
    }

    #[test]
    fn degraded_read_refusal_is_typed_for_read_serving_evidence_refusal() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::ReadFreshnessEvidence,
                EvidenceFamilyFreshnessState::Refused,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::ReadFreshnessEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(27, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::DegradedReadRefused));
    }

    #[test]
    fn recovery_degradation_refusal_is_typed() {
        let snapshot = snapshot_with_families(
            1,
            &[(
                StorageIntentEvidenceKind::RecoveryDegradationEvidence,
                EvidenceFamilyFreshnessState::Refused,
                1,
            )],
        );
        let required = [StorageIntentRequiredEvidence::required(
            StorageIntentEvidenceKind::RecoveryDegradationEvidence,
        )];
        let record = reconcile_storage_intent_satisfaction(basic_input(
            policy(1, StorageIntentGuaranteeClass::LocalIntent),
            snapshot,
            &[receipt(28, 1, StorageIntentGuaranteeClass::LocalIntent)],
            &required,
        ));

        assert!(record
            .reasons
            .contains_reason(StorageIntentSatisfactionReason::RecoveryDegradationRefused));
    }
}
