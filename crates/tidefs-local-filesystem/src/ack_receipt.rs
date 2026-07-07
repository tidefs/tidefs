// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

//! Local storage-intent acknowledgment receipts.
//!
//! This module is deliberately a shape and evidence surface. It binds local
//! write and durability-barrier replies to the shared storage-intent core
//! records without claiming transport, distributed quorum, operator UAPI, or
//! broad crash-validation closure.

use tidefs_local_object_store::pool::PlacementReceipt;
use tidefs_storage_intent_core::{
    evaluate_receipt_against_policy, DurabilityReceiptState, DurabilityRequirement,
    DurabilityState, FailureDomainMask, ProximityClass, ReadServingSourceClass,
    StorageIntentActionClass, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceRef, StorageIntentEvidenceRefs, StorageIntentGuaranteeClass,
    StorageIntentPolicy, StorageIntentPolicyId, StorageIntentPolicyRevision, StorageIntentReceipt,
    StorageIntentReceiptId, StorageIntentRefusal, StorageIntentRefusalReason, StorageMediaClass,
    StorageMediaRole, TrustEvidenceState,
};

/// Local filesystem receipt surface version for issue #842.
pub const LOCAL_ACK_RECEIPT_SPEC: &str = "tidefs-local-ack-receipt-v1-issue-842";

/// Record version carried by local evidence refs.
pub const LOCAL_ACK_RECEIPT_RECORD_VERSION: u16 = 1;

/// Synthetic policy id for the current source-local receipt-shape slice.
pub const LOCAL_ACK_POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId(*b"tidefs-ack-842v1");

/// Revision of the local source-shape policy used by this crate.
pub const LOCAL_ACK_POLICY_REVISION: StorageIntentPolicyRevision = StorageIntentPolicyRevision(1);

const LOCAL_ACK_RECEIPT_LEDGER_LIMIT: usize = 256;

/// Local operation that emitted an earned-ack receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LocalAckOperation {
    /// A sync-style write was acknowledged through a durable local intent.
    SyncWrite = 0,
    /// A POSIX fsync-style barrier completed.
    Fsync = 1,
    /// A POSIX fdatasync-style barrier completed.
    Fdatasync = 2,
    /// O_DSYNC data-range intent completed.
    Odsync = 3,
    /// Shared writable mmap MS_SYNC intent completed.
    SharedMmapMsync = 4,
    /// Filesystem-wide sync/syncfs completed.
    Syncfs = 5,
    /// Directory fsync completed.
    FsyncDirectory = 6,
}

impl LocalAckOperation {
    /// Stable diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SyncWrite => "sync-write",
            Self::Fsync => "fsync",
            Self::Fdatasync => "fdatasync",
            Self::Odsync => "odsync",
            Self::SharedMmapMsync => "shared-mmap-msync",
            Self::Syncfs => "syncfs",
            Self::FsyncDirectory => "fsync-directory",
        }
    }

    /// Stable local discriminant.
    #[must_use]
    pub const fn to_discriminant(self) -> u8 {
        self as u8
    }
}

/// Object and range that one local receipt covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LocalAckReceiptTarget {
    pub inode_id: Option<u64>,
    pub offset: u64,
    pub length: u64,
    pub has_range: bool,
}

impl LocalAckReceiptTarget {
    /// Filesystem-wide target.
    pub const FILESYSTEM: Self = Self {
        inode_id: None,
        offset: 0,
        length: 0,
        has_range: false,
    };

    /// Inode-wide target.
    #[must_use]
    pub const fn inode(inode_id: u64) -> Self {
        Self {
            inode_id: Some(inode_id),
            offset: 0,
            length: 0,
            has_range: false,
        }
    }

    /// Byte-range target.
    #[must_use]
    pub const fn range(inode_id: u64, offset: u64, length: u64) -> Self {
        Self {
            inode_id: Some(inode_id),
            offset,
            length,
            has_range: true,
        }
    }
}

/// Synchronous receipt result, separate from asynchronous convergence debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LocalAckReceiptDisposition {
    /// Durable POSIX receipt: local intent or placement evidence backs success.
    DurablePosix = 0,
    /// Explicitly weaker non-POSIX/unsafe receipt class.
    WeakerUnsafeVolatile = 1,
    /// Typed refusal returned instead of hidden weakening.
    Refused = 2,
    /// Missing or stale evidence leaves the receipt unknown.
    Unknown = 3,
    /// Policy/evidence gate blocked emission.
    Blocked = 4,
}

/// Asynchronous convergence state carried alongside the synchronous ack.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum LocalAckConvergenceState {
    /// The synchronous ack also satisfied the modeled local convergence target.
    Satisfied = 0,
    /// Local durable intent was earned, but full local placement still has debt.
    PendingFullPlacement = 1,
    /// Later placement/convergence is actively expected.
    Converging = 2,
    /// Degraded state is caller-visible and not normalized into success.
    DegradedVisible = 3,
    /// Required evidence is missing, stale, or outside the current cut.
    Unknown = 4,
    /// A hard policy/evidence gate blocks the requested floor.
    Blocked = 5,
    /// The requested floor was refused.
    Refused = 6,
}

impl LocalAckConvergenceState {
    /// True when later full-placement work remains.
    #[must_use]
    pub const fn has_pending_full_placement(self) -> bool {
        matches!(self, Self::PendingFullPlacement | Self::Converging)
    }

    /// True when this convergence state can satisfy the synchronous ack floor.
    #[must_use]
    pub const fn satisfies_ack_floor(self) -> bool {
        matches!(
            self,
            Self::Satisfied | Self::PendingFullPlacement | Self::Converging
        )
    }
}

/// Local receipt envelope that preserves issue #842 evidence refs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAckReceipt {
    pub receipt: StorageIntentReceipt,
    pub operation: LocalAckOperation,
    pub target: LocalAckReceiptTarget,
    pub requested_ack_floor: StorageIntentGuaranteeClass,
    pub payload_or_replay_digest: Option<u64>,
    pub local_intent_record_ref: StorageIntentEvidenceRef,
    pub ordering_ref: StorageIntentEvidenceRef,
    pub flush_fence_ref: StorageIntentEvidenceRef,
    pub media_capability_ref: StorageIntentEvidenceRef,
    pub placement_ref: StorageIntentEvidenceRef,
    pub reserve_ref: StorageIntentEvidenceRef,
    pub dirty_window_ref: StorageIntentEvidenceRef,
    pub rollout_ref: StorageIntentEvidenceRef,
    pub tenant_isolation_ref: StorageIntentEvidenceRef,
    pub convergence: LocalAckConvergenceState,
    pub replacement_receipt: StorageIntentReceiptId,
    pub retires_receipt: StorageIntentReceiptId,
    pub old_receipt_retired: bool,
    pub refusal: StorageIntentRefusal,
    pub disposition: LocalAckReceiptDisposition,
}

impl LocalAckReceipt {
    /// Build a local durable-intent success receipt with pending placement debt.
    #[must_use]
    pub fn durable_intent(
        sequence: u64,
        operation: LocalAckOperation,
        target: LocalAckReceiptTarget,
        payload_or_replay_digest: Option<u64>,
    ) -> Self {
        let local_intent_record_ref = evidence_ref(
            StorageIntentEvidenceKind::LocalIntentRecord,
            "local-intent",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let ordering_ref = evidence_ref(
            StorageIntentEvidenceKind::OrderingEvidence,
            "ordering",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let flush_fence_ref = evidence_ref(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            "flush-fence",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let media_capability_ref = evidence_ref(
            StorageIntentEvidenceKind::MediaCapabilityEvidence,
            "media-capability",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let reserve_ref = evidence_ref(
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            "reserve",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let dirty_window_ref = evidence_ref(
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
            "dirty-window",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let rollout_ref = evidence_ref(
            StorageIntentEvidenceKind::PolicyRolloutEvidence,
            "rollout",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let tenant_isolation_ref = evidence_ref(
            StorageIntentEvidenceKind::TenantIsolationEvidence,
            "tenant-isolation",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let evidence_refs = evidence_refs(&[
            local_intent_record_ref,
            ordering_ref,
            flush_fence_ref,
            media_capability_ref,
            reserve_ref,
            dirty_window_ref,
            rollout_ref,
            tenant_isolation_ref,
        ]);
        let receipt = StorageIntentReceipt {
            receipt_id: receipt_id(sequence, operation, target, payload_or_replay_digest),
            policy_id: LOCAL_ACK_POLICY_ID,
            policy_revision: LOCAL_ACK_POLICY_REVISION,
            ack_class: StorageIntentGuaranteeClass::LocalIntent,
            failure_domains: FailureDomainMask::LOCAL,
            proximity: ProximityClass::LocalMedia,
            durability: DurabilityReceiptState {
                state: DurabilityState::DurableIntent,
                observed_lag_ms: 0,
                lag_known: true,
            },
            trust: TrustEvidenceState::EMPTY,
            media_role: StorageMediaRole::SyncIntent,
            media_class: StorageMediaClass::ObjectAppliance,
            read_source: ReadServingSourceClass::PlacementReceipt,
            action_class: StorageIntentActionClass::NewWriteShaping,
            evidence_refs,
        };
        Self {
            receipt,
            operation,
            target,
            requested_ack_floor: StorageIntentGuaranteeClass::LocalIntent,
            payload_or_replay_digest,
            local_intent_record_ref,
            ordering_ref,
            flush_fence_ref,
            media_capability_ref,
            placement_ref: StorageIntentEvidenceRef::default(),
            reserve_ref,
            dirty_window_ref,
            rollout_ref,
            tenant_isolation_ref,
            convergence: LocalAckConvergenceState::PendingFullPlacement,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            retires_receipt: StorageIntentReceiptId::ZERO,
            old_receipt_retired: false,
            refusal: refusal(
                sequence,
                receipt.receipt_id,
                StorageIntentRefusalReason::None,
            ),
            disposition: LocalAckReceiptDisposition::DurablePosix,
        }
    }

    /// Build a full local commit/placement-shaped success receipt.
    #[must_use]
    pub fn full_local_placement(
        sequence: u64,
        operation: LocalAckOperation,
        target: LocalAckReceiptTarget,
        payload_or_replay_digest: Option<u64>,
    ) -> Self {
        let mut receipt =
            Self::durable_intent(sequence, operation, target, payload_or_replay_digest);
        let placement_ref = evidence_ref(
            StorageIntentEvidenceKind::PlacementReceipt,
            "placement",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let local_intent_record_ref = receipt.local_intent_record_ref;
        let ordering_ref = receipt.ordering_ref;
        let flush_fence_ref = receipt.flush_fence_ref;
        let media_capability_ref = receipt.media_capability_ref;
        let reserve_ref = receipt.reserve_ref;
        let dirty_window_ref = receipt.dirty_window_ref;
        let rollout_ref = receipt.rollout_ref;
        let tenant_isolation_ref = receipt.tenant_isolation_ref;
        receipt.receipt.ack_class = StorageIntentGuaranteeClass::FullPlacement;
        receipt.receipt.durability = DurabilityReceiptState {
            state: DurabilityState::FullPlacement,
            observed_lag_ms: 0,
            lag_known: true,
        };
        receipt.receipt.media_role = StorageMediaRole::PlacementAuthority;
        receipt.receipt.action_class = StorageIntentActionClass::DurablePlacementMovement;
        receipt.receipt.evidence_refs = evidence_refs(&[
            local_intent_record_ref,
            ordering_ref,
            flush_fence_ref,
            media_capability_ref,
            placement_ref,
            reserve_ref,
            dirty_window_ref,
            rollout_ref,
            tenant_isolation_ref,
        ]);
        receipt.requested_ack_floor = StorageIntentGuaranteeClass::LocalIntent;
        receipt.placement_ref = placement_ref;
        receipt.convergence = LocalAckConvergenceState::Satisfied;
        receipt
    }

    /// Build an explicit weaker/unsafe volatile receipt shape.
    #[must_use]
    pub fn unsafe_volatile(
        sequence: u64,
        operation: LocalAckOperation,
        target: LocalAckReceiptTarget,
        payload_or_replay_digest: Option<u64>,
        reason: StorageIntentRefusalReason,
    ) -> Self {
        let flush_fence_ref = evidence_ref(
            StorageIntentEvidenceKind::ActionExecutionEvidence,
            "unsafe-volatile",
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        );
        let mut evidence_refs = StorageIntentEvidenceRefs::EMPTY;
        let _ = evidence_refs.push(flush_fence_ref);
        let receipt_id = receipt_id(sequence, operation, target, payload_or_replay_digest);
        let receipt = StorageIntentReceipt {
            receipt_id,
            policy_id: LOCAL_ACK_POLICY_ID,
            policy_revision: LOCAL_ACK_POLICY_REVISION,
            ack_class: StorageIntentGuaranteeClass::VolatileLocal,
            failure_domains: FailureDomainMask::LOCAL,
            proximity: ProximityClass::LocalRam,
            durability: DurabilityReceiptState {
                state: DurabilityState::Volatile,
                observed_lag_ms: u64::MAX,
                lag_known: false,
            },
            trust: TrustEvidenceState::EMPTY,
            media_role: StorageMediaRole::RamVolatileAuthority,
            media_class: StorageMediaClass::SystemRam,
            read_source: ReadServingSourceClass::Cache,
            action_class: StorageIntentActionClass::NewWriteShaping,
            evidence_refs,
        };
        Self {
            receipt,
            operation,
            target,
            requested_ack_floor: StorageIntentGuaranteeClass::VolatileLocal,
            payload_or_replay_digest,
            local_intent_record_ref: StorageIntentEvidenceRef::default(),
            ordering_ref: StorageIntentEvidenceRef::default(),
            flush_fence_ref,
            media_capability_ref: StorageIntentEvidenceRef::default(),
            placement_ref: StorageIntentEvidenceRef::default(),
            reserve_ref: StorageIntentEvidenceRef::default(),
            dirty_window_ref: StorageIntentEvidenceRef::default(),
            rollout_ref: StorageIntentEvidenceRef::default(),
            tenant_isolation_ref: StorageIntentEvidenceRef::default(),
            convergence: LocalAckConvergenceState::DegradedVisible,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            retires_receipt: StorageIntentReceiptId::ZERO,
            old_receipt_retired: false,
            refusal: refusal(sequence, receipt_id, reason),
            disposition: LocalAckReceiptDisposition::WeakerUnsafeVolatile,
        }
    }

    /// Build a typed refusal for an unmet requested floor.
    #[must_use]
    pub fn refused_unmet_floor(
        sequence: u64,
        operation: LocalAckOperation,
        target: LocalAckReceiptTarget,
        requested_ack_floor: StorageIntentGuaranteeClass,
        earned_ack_class: StorageIntentGuaranteeClass,
        reason: StorageIntentRefusalReason,
    ) -> Self {
        let attempted = Self::durable_intent(sequence, operation, target, None);
        let mut receipt = attempted.receipt;
        receipt.ack_class = earned_ack_class;
        if !matches!(
            earned_ack_class,
            StorageIntentGuaranteeClass::LocalIntent
                | StorageIntentGuaranteeClass::FullPlacement
                | StorageIntentGuaranteeClass::QuorumIntent
                | StorageIntentGuaranteeClass::GeoIntent
                | StorageIntentGuaranteeClass::GeoFullPlacement
                | StorageIntentGuaranteeClass::ArchiveEc
        ) {
            receipt.durability = DurabilityReceiptState {
                state: DurabilityState::Volatile,
                observed_lag_ms: u64::MAX,
                lag_known: false,
            };
        }
        Self {
            receipt,
            operation,
            target,
            requested_ack_floor,
            payload_or_replay_digest: None,
            local_intent_record_ref: attempted.local_intent_record_ref,
            ordering_ref: attempted.ordering_ref,
            flush_fence_ref: attempted.flush_fence_ref,
            media_capability_ref: attempted.media_capability_ref,
            placement_ref: attempted.placement_ref,
            reserve_ref: attempted.reserve_ref,
            dirty_window_ref: attempted.dirty_window_ref,
            rollout_ref: attempted.rollout_ref,
            tenant_isolation_ref: attempted.tenant_isolation_ref,
            convergence: LocalAckConvergenceState::Refused,
            replacement_receipt: StorageIntentReceiptId::ZERO,
            retires_receipt: StorageIntentReceiptId::ZERO,
            old_receipt_retired: false,
            refusal: refusal(sequence, receipt.receipt_id, reason),
            disposition: LocalAckReceiptDisposition::Refused,
        }
    }

    /// Returns true for durable POSIX success receipts.
    #[must_use]
    pub const fn is_posix_durable_success(self) -> bool {
        matches!(self.disposition, LocalAckReceiptDisposition::DurablePosix)
            && matches!(
                self.receipt.durability.state,
                DurabilityState::DurableIntent | DurabilityState::FullPlacement
            )
    }

    /// Returns true only when this receipt earned its requested ack floor.
    #[must_use]
    pub fn satisfies_requested_ack_floor(self) -> bool {
        self.is_posix_durable_success()
            && self.has_local_ack_policy_identity()
            && self.refusal_reason() == StorageIntentRefusalReason::None
            && self.has_requested_ack_floor_evidence()
            && self.convergence.satisfies_ack_floor()
            && evaluate_receipt_against_policy(
                local_ack_policy(self.requested_ack_floor),
                self.receipt,
            )
            .satisfied
    }

    fn has_local_ack_policy_identity(self) -> bool {
        self.receipt.policy_id == LOCAL_ACK_POLICY_ID
            && self.receipt.policy_revision == LOCAL_ACK_POLICY_REVISION
            && self.refusal.policy_id == LOCAL_ACK_POLICY_ID
            && self.refusal.policy_revision == LOCAL_ACK_POLICY_REVISION
    }

    fn required_local_evidence_refs(self) -> [StorageIntentEvidenceRef; 8] {
        [
            self.local_intent_record_ref,
            self.ordering_ref,
            self.flush_fence_ref,
            self.media_capability_ref,
            self.reserve_ref,
            self.dirty_window_ref,
            self.rollout_ref,
            self.tenant_isolation_ref,
        ]
    }

    fn has_requested_ack_floor_evidence(self) -> bool {
        if !local_ack_floor_has_evidence_surface(self.requested_ack_floor) {
            return false;
        }

        let has_local_evidence = self
            .required_local_evidence_refs()
            .iter()
            .all(|evidence_ref| {
                evidence_ref.is_bound() && self.receipt.evidence_refs.contains_ref(*evidence_ref)
            });
        let needs_full_placement = matches!(
            self.requested_ack_floor,
            StorageIntentGuaranteeClass::FullPlacement
        );

        has_local_evidence
            && (!needs_full_placement
                || (self.placement_ref.is_bound()
                    && self.receipt.evidence_refs.contains_ref(self.placement_ref)))
    }

    /// Refusal reason carried by this envelope.
    #[must_use]
    pub const fn refusal_reason(self) -> StorageIntentRefusalReason {
        self.refusal.reason
    }
}

const fn local_ack_floor_has_evidence_surface(
    requested_ack_floor: StorageIntentGuaranteeClass,
) -> bool {
    matches!(
        requested_ack_floor,
        StorageIntentGuaranteeClass::VolatileLocal
            | StorageIntentGuaranteeClass::LocalIntent
            | StorageIntentGuaranteeClass::FullPlacement
    )
}

// ---------------------------------------------------------------------
// Readback receipt authority evidence
// ---------------------------------------------------------------------

/// Evidence classification for a pool placement receipt queried during
/// local readback or degraded-read source selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadReceiptEvidence {
    /// Receipt generation matches the chunk ref; receipt is committed authority.
    Valid { generation: u64 },
    /// Pool lookup failed (I/O error, device unavailable).
    Unavailable { expected_generation: u64 },
    /// No receipt exists in the pool for this object key.
    Missing { expected_generation: u64 },
    /// Pool receipt generation differs from the chunk ref's recorded generation.
    Stale {
        expected_generation: u64,
        observed_generation: u64,
    },
    /// Receipt exists but generation is zero (synthetic/uncommitted).
    Synthetic {
        expected_generation: u64,
        observed_generation: u64,
    },
    /// Receipt's redundancy policy is not well-formed.
    MalformedPolicy { generation: u64 },
    /// Receipt target_count is less than the policy's required width.
    UnderWidth {
        generation: u64,
        target_count: u16,
        required_width: u16,
    },
    /// Receipt target_count exceeds the policy's required width.
    OverWidth {
        generation: u64,
        target_count: u16,
        required_width: u16,
    },
}

impl ReadReceiptEvidence {
    /// True when the receipt is committed placement authority suitable for
    /// receipt-verified device selection.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }

    /// Human-readable classification label for diagnostics.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Valid { .. } => "valid",
            Self::Unavailable { .. } => "unavailable",
            Self::Missing { .. } => "missing",
            Self::Stale { .. } => "stale",
            Self::Synthetic { .. } => "synthetic",
            Self::MalformedPolicy { .. } => "malformed-policy",
            Self::UnderWidth { .. } => "under-width",
            Self::OverWidth { .. } => "over-width",
        }
    }
}

/// Bounded latest-receipt side-channel owned by `LocalFileSystem`.
#[derive(Clone, Debug)]
pub struct LocalAckReceiptLedger {
    receipts: Vec<LocalAckReceipt>,
    next_sequence: u64,
}

impl LocalAckReceiptLedger {
    /// Create an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            receipts: Vec::new(),
            next_sequence: 1,
        }
    }

    /// Reserve the next monotonic local sequence.
    pub fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1).max(1);
        sequence
    }

    /// Append a receipt, keeping only the bounded latest window.
    pub fn record(&mut self, receipt: LocalAckReceipt) {
        self.receipts.push(receipt);
        if self.receipts.len() > LOCAL_ACK_RECEIPT_LEDGER_LIMIT {
            self.receipts.remove(0);
        }
    }

    /// Latest recorded receipt.
    #[must_use]
    pub fn latest(&self) -> Option<LocalAckReceipt> {
        self.receipts.last().copied()
    }

    /// Snapshot of the bounded receipt window.
    #[must_use]
    pub fn snapshot(&self) -> Vec<LocalAckReceipt> {
        self.receipts.clone()
    }

    /// Number of receipts in the bounded window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Whether no receipts are recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }
}

impl Default for LocalAckReceiptLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the local policy shape used to evaluate a requested floor.
#[must_use]
pub fn local_ack_policy(requested_guarantee: StorageIntentGuaranteeClass) -> StorageIntentPolicy {
    let durability = match requested_guarantee {
        StorageIntentGuaranteeClass::VolatileLocal
        | StorageIntentGuaranteeClass::VolatileReplicated
        | StorageIntentGuaranteeClass::RemoteVolatilePlusLocal => DurabilityRequirement::VOLATILE,
        StorageIntentGuaranteeClass::FullPlacement
        | StorageIntentGuaranteeClass::GeoAsync
        | StorageIntentGuaranteeClass::GeoFullPlacement
        | StorageIntentGuaranteeClass::ArchiveEc => DurabilityRequirement {
            min_state: DurabilityState::FullPlacement,
            max_lag_ms: 0,
            allow_unknown_lag: false,
        },
        StorageIntentGuaranteeClass::LocalIntent
        | StorageIntentGuaranteeClass::QuorumIntent
        | StorageIntentGuaranteeClass::GeoIntent => DurabilityRequirement::DURABLE_INTENT_ZERO_LAG,
    };

    StorageIntentPolicy {
        policy_id: LOCAL_ACK_POLICY_ID,
        revision: LOCAL_ACK_POLICY_REVISION,
        requested_guarantee,
        required_failure_domains: FailureDomainMask::LOCAL,
        max_proximity: ProximityClass::LocalMedia,
        durability,
        ..StorageIntentPolicy::default()
    }
}

fn evidence_refs(refs: &[StorageIntentEvidenceRef]) -> StorageIntentEvidenceRefs {
    let mut evidence_refs = StorageIntentEvidenceRefs::EMPTY;
    for evidence_ref in refs {
        if evidence_ref.is_bound() {
            let _ = evidence_refs.push(*evidence_ref);
        }
    }
    evidence_refs
}

fn receipt_id(
    sequence: u64,
    operation: LocalAckOperation,
    target: LocalAckReceiptTarget,
    payload_or_replay_digest: Option<u64>,
) -> StorageIntentReceiptId {
    let mut out = [0_u8; 16];
    let hash = hash_context(
        "receipt",
        sequence,
        operation,
        target,
        payload_or_replay_digest,
    );
    out.copy_from_slice(&hash[..16]);
    StorageIntentReceiptId(out)
}

fn evidence_ref(
    kind: StorageIntentEvidenceKind,
    label: &'static str,
    sequence: u64,
    operation: LocalAckOperation,
    target: LocalAckReceiptTarget,
    payload_or_replay_digest: Option<u64>,
) -> StorageIntentEvidenceRef {
    StorageIntentEvidenceRef::new(
        kind,
        StorageIntentEvidenceId(hash_context(
            label,
            sequence,
            operation,
            target,
            payload_or_replay_digest,
        )),
        sequence,
        LOCAL_ACK_RECEIPT_RECORD_VERSION,
    )
}

fn refusal(
    sequence: u64,
    attempted_receipt: StorageIntentReceiptId,
    reason: StorageIntentRefusalReason,
) -> StorageIntentRefusal {
    StorageIntentRefusal {
        policy_id: LOCAL_ACK_POLICY_ID,
        policy_revision: LOCAL_ACK_POLICY_REVISION,
        attempted_receipt,
        reason,
        evidence: StorageIntentEvidenceRef::new(
            StorageIntentEvidenceKind::ResultRefusalEvidence,
            StorageIntentEvidenceId(hash_refusal_context(sequence, attempted_receipt, reason)),
            sequence,
            LOCAL_ACK_RECEIPT_RECORD_VERSION,
        ),
    }
}

fn hash_context(
    label: &str,
    sequence: u64,
    operation: LocalAckOperation,
    target: LocalAckReceiptTarget,
    payload_or_replay_digest: Option<u64>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOCAL_ACK_RECEIPT_SPEC.as_bytes());
    hasher.update(label.as_bytes());
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&[operation.to_discriminant()]);
    match target.inode_id {
        Some(inode_id) => {
            hasher.update(&[1]);
            hasher.update(&inode_id.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&0_u64.to_le_bytes());
        }
    }
    hasher.update(&target.offset.to_le_bytes());
    hasher.update(&target.length.to_le_bytes());
    hasher.update(&[u8::from(target.has_range)]);
    match payload_or_replay_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&0_u64.to_le_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

fn hash_refusal_context(
    sequence: u64,
    attempted_receipt: StorageIntentReceiptId,
    reason: StorageIntentRefusalReason,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOCAL_ACK_RECEIPT_SPEC.as_bytes());
    hasher.update(b"refusal");
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&attempted_receipt.0);
    hasher.update(&reason.to_discriminant().to_le_bytes());
    *hasher.finalize().as_bytes()
}
// ---------------------------------------------------------------------
// Readback receipt authority classification
// ---------------------------------------------------------------------

/// Classify a pool placement receipt against an expected generation for
/// local readback source selection.
///
/// Returns [`ReadReceiptEvidence`] describing whether the receipt can serve
/// as committed placement authority or what typed deficiency it exhibits.
pub fn classify_read_receipt(
    receipt: &PlacementReceipt,
    expected_generation: u64,
) -> ReadReceiptEvidence {
    // Synthetic / zero-generation receipt: not committed authority.
    if receipt.generation == 0 {
        return ReadReceiptEvidence::Synthetic {
            expected_generation,
            observed_generation: 0,
        };
    }

    // Check generation match.
    if receipt.generation != expected_generation {
        return ReadReceiptEvidence::Stale {
            expected_generation,
            observed_generation: receipt.generation,
        };
    }

    // Check policy well-formedness via projection to the shared receipt model.
    let rp = receipt.policy.to_receipt_redundancy_policy();
    if !rp.is_well_formed() {
        return ReadReceiptEvidence::MalformedPolicy {
            generation: receipt.generation,
        };
    }

    // Check target width.
    let required_width = rp.target_width();
    let target_count = u16::try_from(receipt.targets.len()).unwrap_or(u16::MAX);
    if target_count < required_width {
        return ReadReceiptEvidence::UnderWidth {
            generation: receipt.generation,
            target_count,
            required_width,
        };
    }
    if target_count > required_width {
        return ReadReceiptEvidence::OverWidth {
            generation: receipt.generation,
            target_count,
            required_width,
        };
    }

    ReadReceiptEvidence::Valid {
        generation: receipt.generation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        ack_receipt_satisfies_requested_floor, evaluate_receipt_against_policy,
    };

    #[test]
    fn durable_intent_receipt_records_pending_full_placement() {
        let receipt = LocalAckReceipt::durable_intent(
            1,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::range(42, 64, 4096),
            Some(0xfeed_beef),
        );

        assert_eq!(
            receipt.receipt.ack_class,
            StorageIntentGuaranteeClass::LocalIntent
        );
        assert!(receipt.is_posix_durable_success());
        assert!(receipt.satisfies_requested_ack_floor());
        assert!(receipt.local_intent_record_ref.is_bound());
        assert!(receipt.flush_fence_ref.is_bound());
        assert_eq!(
            receipt.convergence,
            LocalAckConvergenceState::PendingFullPlacement
        );
        assert!(receipt.convergence.has_pending_full_placement());
        assert_eq!(receipt.refusal_reason(), StorageIntentRefusalReason::None);
        assert!(ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::LocalIntent,
            receipt.receipt.ack_class
        ));
    }

    #[test]
    fn full_local_placement_receipt_satisfies_full_floor_when_evidence_is_bound() {
        let receipt = LocalAckReceipt::full_local_placement(
            2,
            LocalAckOperation::Fsync,
            LocalAckReceiptTarget::inode(7),
            None,
        );

        assert_eq!(
            receipt.receipt.ack_class,
            StorageIntentGuaranteeClass::FullPlacement
        );
        assert_eq!(receipt.convergence, LocalAckConvergenceState::Satisfied);
        assert!(receipt.placement_ref.is_bound());
        let result = evaluate_receipt_against_policy(
            local_ack_policy(StorageIntentGuaranteeClass::FullPlacement),
            receipt.receipt,
        );
        assert!(result.satisfied, "refusal was {:?}", result.refusal);
        assert!(receipt.satisfies_requested_ack_floor());
    }

    #[test]
    fn pending_convergence_does_not_imply_full_placement() {
        let mut receipt = LocalAckReceipt::durable_intent(
            3,
            LocalAckOperation::Fdatasync,
            LocalAckReceiptTarget::inode(9),
            None,
        );

        assert!(
            evaluate_receipt_against_policy(
                local_ack_policy(StorageIntentGuaranteeClass::LocalIntent),
                receipt.receipt,
            )
            .satisfied
        );
        let result = evaluate_receipt_against_policy(
            local_ack_policy(StorageIntentGuaranteeClass::FullPlacement),
            receipt.receipt,
        );
        assert!(!result.satisfied);
        assert_eq!(
            result.refusal,
            StorageIntentRefusalReason::GuaranteeFloorNotMet
        );

        receipt.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;
        assert!(!receipt.satisfies_requested_ack_floor());
    }

    #[test]
    fn unsafe_volatile_receipt_is_distinct_from_posix_durable_success() {
        let receipt = LocalAckReceipt::unsafe_volatile(
            4,
            LocalAckOperation::Odsync,
            LocalAckReceiptTarget::range(11, 0, 512),
            Some(0x1234),
            StorageIntentRefusalReason::UnsafeVolatileWriteCache,
        );

        assert_eq!(
            receipt.disposition,
            LocalAckReceiptDisposition::WeakerUnsafeVolatile
        );
        assert!(!receipt.is_posix_durable_success());
        assert_eq!(
            receipt.refusal_reason(),
            StorageIntentRefusalReason::UnsafeVolatileWriteCache
        );
        assert_eq!(
            receipt.receipt.ack_class,
            StorageIntentGuaranteeClass::VolatileLocal
        );
        let result = evaluate_receipt_against_policy(
            local_ack_policy(StorageIntentGuaranteeClass::LocalIntent),
            receipt.receipt,
        );
        assert!(!result.satisfied);
        assert!(!receipt.satisfies_requested_ack_floor());
    }

    #[test]
    fn refusal_shape_preserves_requested_floor_and_reason() {
        let receipt = LocalAckReceipt::refused_unmet_floor(
            5,
            LocalAckOperation::SharedMmapMsync,
            LocalAckReceiptTarget::range(13, 4096, 4096),
            StorageIntentGuaranteeClass::FullPlacement,
            StorageIntentGuaranteeClass::LocalIntent,
            StorageIntentRefusalReason::DurabilityOrRpoNotMet,
        );

        assert_eq!(receipt.disposition, LocalAckReceiptDisposition::Refused);
        assert_eq!(receipt.convergence, LocalAckConvergenceState::Refused);
        assert_eq!(
            receipt.requested_ack_floor,
            StorageIntentGuaranteeClass::FullPlacement
        );
        assert_eq!(
            receipt.refusal_reason(),
            StorageIntentRefusalReason::DurabilityOrRpoNotMet
        );
        assert_eq!(
            receipt.refusal.attempted_receipt,
            receipt.receipt.receipt_id
        );
        assert!(!receipt.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_full_placement_floor_requires_full_placement_receipt() {
        let mut local_receipt = LocalAckReceipt::durable_intent(
            6,
            LocalAckOperation::FsyncDirectory,
            LocalAckReceiptTarget::inode(17),
            None,
        );
        local_receipt.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;

        let mut full_receipt = LocalAckReceipt::full_local_placement(
            7,
            LocalAckOperation::Syncfs,
            LocalAckReceiptTarget::inode(17),
            None,
        );
        full_receipt.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;

        assert!(local_receipt.is_posix_durable_success());
        assert!(!local_receipt.satisfies_requested_ack_floor());
        assert!(full_receipt.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_floor_receipt_fails_closed_without_bound_evidence() {
        let mut missing_local_intent = LocalAckReceipt::durable_intent(
            8,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(19),
            None,
        );
        missing_local_intent.local_intent_record_ref = StorageIntentEvidenceRef::default();

        let mut missing_placement = LocalAckReceipt::full_local_placement(
            9,
            LocalAckOperation::Fsync,
            LocalAckReceiptTarget::inode(19),
            None,
        );
        missing_placement.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;
        missing_placement.placement_ref = StorageIntentEvidenceRef::default();

        assert!(missing_local_intent.is_posix_durable_success());
        assert!(!missing_local_intent.satisfies_requested_ack_floor());
        assert!(missing_placement.is_posix_durable_success());
        assert!(!missing_placement.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_floor_receipt_fails_closed_without_shared_evidence_refs() {
        let mut missing_shared_refs = LocalAckReceipt::durable_intent(
            10,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(21),
            None,
        );
        assert!(missing_shared_refs.satisfies_requested_ack_floor());
        assert!(missing_shared_refs.local_intent_record_ref.is_bound());
        missing_shared_refs.receipt.evidence_refs = StorageIntentEvidenceRefs::EMPTY;

        assert!(missing_shared_refs.is_posix_durable_success());
        assert!(!missing_shared_refs.satisfies_requested_ack_floor());

        let mut missing_full_shared_refs = LocalAckReceipt::full_local_placement(
            11,
            LocalAckOperation::Fsync,
            LocalAckReceiptTarget::inode(21),
            None,
        );
        missing_full_shared_refs.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;
        assert!(missing_full_shared_refs.satisfies_requested_ack_floor());
        assert!(missing_full_shared_refs.placement_ref.is_bound());
        missing_full_shared_refs.receipt.evidence_refs = StorageIntentEvidenceRefs::EMPTY;

        assert!(missing_full_shared_refs.is_posix_durable_success());
        assert!(!missing_full_shared_refs.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_floor_receipt_fails_closed_for_stale_shared_evidence_refs() {
        let target = LocalAckReceiptTarget::inode(21);
        let mut stale_local_ref =
            LocalAckReceipt::durable_intent(12, LocalAckOperation::SyncWrite, target, None);
        let other_local_intent_ref = evidence_ref(
            StorageIntentEvidenceKind::LocalIntentRecord,
            "local-intent",
            112,
            LocalAckOperation::SyncWrite,
            target,
            None,
        );
        stale_local_ref.receipt.evidence_refs = evidence_refs(&[
            other_local_intent_ref,
            stale_local_ref.ordering_ref,
            stale_local_ref.flush_fence_ref,
            stale_local_ref.media_capability_ref,
            stale_local_ref.reserve_ref,
            stale_local_ref.dirty_window_ref,
            stale_local_ref.rollout_ref,
            stale_local_ref.tenant_isolation_ref,
        ]);

        assert!(stale_local_ref.is_posix_durable_success());
        assert!(other_local_intent_ref.is_bound());
        assert!(!stale_local_ref.satisfies_requested_ack_floor());

        let mut stale_placement_ref =
            LocalAckReceipt::full_local_placement(13, LocalAckOperation::Fsync, target, None);
        stale_placement_ref.requested_ack_floor = StorageIntentGuaranteeClass::FullPlacement;
        let other_placement_ref = evidence_ref(
            StorageIntentEvidenceKind::PlacementReceipt,
            "placement",
            113,
            LocalAckOperation::Fsync,
            target,
            None,
        );
        stale_placement_ref.receipt.evidence_refs = evidence_refs(&[
            stale_placement_ref.local_intent_record_ref,
            stale_placement_ref.ordering_ref,
            stale_placement_ref.flush_fence_ref,
            stale_placement_ref.media_capability_ref,
            other_placement_ref,
            stale_placement_ref.reserve_ref,
            stale_placement_ref.dirty_window_ref,
            stale_placement_ref.rollout_ref,
            stale_placement_ref.tenant_isolation_ref,
        ]);

        assert!(stale_placement_ref.is_posix_durable_success());
        assert!(other_placement_ref.is_bound());
        assert!(!stale_placement_ref.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_floor_receipt_fails_closed_for_mismatched_policy_identity() {
        const OTHER_POLICY_ID: StorageIntentPolicyId = StorageIntentPolicyId([0x42; 16]);
        const OTHER_POLICY_REVISION: StorageIntentPolicyRevision =
            StorageIntentPolicyRevision(LOCAL_ACK_POLICY_REVISION.0 + 1);

        let mut receipt_policy_id = LocalAckReceipt::durable_intent(
            12,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(22),
            None,
        );
        assert!(receipt_policy_id.satisfies_requested_ack_floor());
        receipt_policy_id.receipt.policy_id = OTHER_POLICY_ID;
        assert!(receipt_policy_id.is_posix_durable_success());
        assert_eq!(
            receipt_policy_id.refusal_reason(),
            StorageIntentRefusalReason::None
        );
        assert!(!receipt_policy_id.satisfies_requested_ack_floor());

        let mut receipt_policy_revision = LocalAckReceipt::durable_intent(
            13,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(22),
            None,
        );
        assert!(receipt_policy_revision.satisfies_requested_ack_floor());
        receipt_policy_revision.receipt.policy_revision = OTHER_POLICY_REVISION;
        assert!(receipt_policy_revision.is_posix_durable_success());
        assert_eq!(
            receipt_policy_revision.refusal_reason(),
            StorageIntentRefusalReason::None
        );
        assert!(!receipt_policy_revision.satisfies_requested_ack_floor());

        let mut refusal_policy_id = LocalAckReceipt::durable_intent(
            14,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(22),
            None,
        );
        assert!(refusal_policy_id.satisfies_requested_ack_floor());
        refusal_policy_id.refusal.policy_id = OTHER_POLICY_ID;
        assert!(refusal_policy_id.is_posix_durable_success());
        assert_eq!(
            refusal_policy_id.refusal_reason(),
            StorageIntentRefusalReason::None
        );
        assert!(!refusal_policy_id.satisfies_requested_ack_floor());

        let mut refusal_policy_revision = LocalAckReceipt::durable_intent(
            15,
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(22),
            None,
        );
        assert!(refusal_policy_revision.satisfies_requested_ack_floor());
        refusal_policy_revision.refusal.policy_revision = OTHER_POLICY_REVISION;
        assert!(refusal_policy_revision.is_posix_durable_success());
        assert_eq!(
            refusal_policy_revision.refusal_reason(),
            StorageIntentRefusalReason::None
        );
        assert!(!refusal_policy_revision.satisfies_requested_ack_floor());
    }

    #[test]
    fn requested_floor_receipt_fails_closed_for_blocked_convergence() {
        let blocked_states = [
            LocalAckConvergenceState::DegradedVisible,
            LocalAckConvergenceState::Unknown,
            LocalAckConvergenceState::Blocked,
            LocalAckConvergenceState::Refused,
        ];

        for (offset, state) in blocked_states.into_iter().enumerate() {
            let mut receipt = LocalAckReceipt::durable_intent(
                10 + u64::try_from(offset).expect("small state index"),
                LocalAckOperation::Fsync,
                LocalAckReceiptTarget::inode(23),
                None,
            );

            assert!(receipt.satisfies_requested_ack_floor());
            assert!(!state.satisfies_ack_floor());

            receipt.convergence = state;
            assert!(receipt.is_posix_durable_success());
            assert_eq!(receipt.refusal_reason(), StorageIntentRefusalReason::None);
            assert!(!receipt.satisfies_requested_ack_floor());
        }
    }

    #[test]
    fn unsupported_requested_floors_fail_closed_without_external_evidence_surface() {
        let unsupported_floors = [
            StorageIntentGuaranteeClass::VolatileReplicated,
            StorageIntentGuaranteeClass::RemoteVolatilePlusLocal,
            StorageIntentGuaranteeClass::QuorumIntent,
            StorageIntentGuaranteeClass::GeoAsync,
            StorageIntentGuaranteeClass::GeoIntent,
            StorageIntentGuaranteeClass::GeoFullPlacement,
            StorageIntentGuaranteeClass::ArchiveEc,
        ];

        for (offset, floor) in unsupported_floors.into_iter().enumerate() {
            let mut receipt = LocalAckReceipt::full_local_placement(
                20 + u64::try_from(offset).expect("small floor index"),
                LocalAckOperation::Syncfs,
                LocalAckReceiptTarget::FILESYSTEM,
                None,
            );
            receipt.requested_ack_floor = floor;
            receipt.receipt.ack_class = floor;

            assert!(receipt.is_posix_durable_success());
            assert!(!local_ack_floor_has_evidence_surface(floor));
            assert!(!receipt.satisfies_requested_ack_floor());
        }
    }

    #[test]
    fn ack_operation_spelling_and_discriminants_cover_receipt_surface() {
        let operations = [
            (LocalAckOperation::SyncWrite, "sync-write", 0),
            (LocalAckOperation::Fsync, "fsync", 1),
            (LocalAckOperation::Fdatasync, "fdatasync", 2),
            (LocalAckOperation::Odsync, "odsync", 3),
            (LocalAckOperation::SharedMmapMsync, "shared-mmap-msync", 4),
            (LocalAckOperation::Syncfs, "syncfs", 5),
            (LocalAckOperation::FsyncDirectory, "fsync-directory", 6),
        ];

        for (operation, spelling, discriminant) in operations {
            assert_eq!(operation.as_str(), spelling);
            assert_eq!(operation.to_discriminant(), discriminant);
        }
    }

    #[test]
    fn ledger_keeps_latest_receipts_bounded() {
        let mut ledger = LocalAckReceiptLedger::new();
        let first = LocalAckReceipt::durable_intent(
            ledger.next_sequence(),
            LocalAckOperation::SyncWrite,
            LocalAckReceiptTarget::inode(1),
            None,
        );
        ledger.record(first);
        let second = LocalAckReceipt::full_local_placement(
            ledger.next_sequence(),
            LocalAckOperation::Fsync,
            LocalAckReceiptTarget::inode(1),
            None,
        );
        ledger.record(second);

        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.latest(), Some(second));
        assert_eq!(ledger.snapshot(), vec![first, second]);
    }
}
