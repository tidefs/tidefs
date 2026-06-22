// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use tidefs_membership_epoch::{
    ClusterMemberRecord, EpochId, FailureDomainVector, MemberClass, MemberId,
};

/// Quorum class for witness verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessQuorumClass {
    /// Strict majority: floor(N/2) + 1 witnesses required.
    StrictMajority,
    /// Flexible: configurable threshold (e.g., 3 of 5).
    Flexible { required: usize, total: usize },
}

impl WitnessQuorumClass {
    /// Compute the number of witnesses required for a given voter count.
    pub fn required_count(self, voter_count: usize) -> usize {
        match self {
            Self::StrictMajority => (voter_count / 2) + 1,
            Self::Flexible { required, .. } => required.min(voter_count),
        }
    }

    /// Check whether `collected` meets the quorum threshold.
    pub fn is_satisfied(self, collected: usize, voter_count: usize) -> bool {
        collected >= self.required_count(voter_count)
    }
}

// ---------------------------------------------------------------------------
// Witness lifecycle
// ---------------------------------------------------------------------------

/// Lifecycle of a witness set from proposal to expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessLifecycle {
    /// Proposed: witness assignment requested, awaiting responses.
    Proposed,
    /// Collecting: some witnesses have responded, still below quorum.
    Collecting,
    /// QuorumReached: enough witnesses confirmed to satisfy quorum.
    QuorumReached,
    /// Verified: all witness signatures verified and payload validated.
    Verified,
    /// Refuted: witnesses disagreed with the claim.
    Refuted { reason: String },
    /// TimedOut: collection deadline expired before quorum reached.
    TimedOut,
    /// Expired: witness set is no longer valid (exceeded TTL).
    Expired,
}

// ---------------------------------------------------------------------------
// Subject anchor
// ---------------------------------------------------------------------------

/// What a witness set attests to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessAnchor {
    /// Attesting a chunk's content digest.
    Chunk {
        chunk_key: Vec<u8>,
        expected_digest: Vec<u8>,
    },
    /// Attesting the validity of an epoch transition.
    Epoch { epoch_id: EpochId },
    /// Attesting a placement receipt.
    Receipt { receipt_id: u64 },
}

// ---------------------------------------------------------------------------
// Witness record
// ---------------------------------------------------------------------------

/// A signed witness attestation from a single witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRecord {
    /// Which member is providing the witness.
    pub witness_id: MemberId,
    /// What is being attested.
    pub anchor: WitnessAnchor,
    /// The witness's claim — typically a digest or acknowledgment.
    pub claim_digest: Vec<u8>,
    /// When the witness made the observation (millis since epoch).
    pub witnessed_at_millis: u64,
    /// Quorum class this witness was selected under.
    pub quorum_class: WitnessQuorumClass,
    /// Ed25519 signature over the witness payload.
    pub signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Witness set
// ---------------------------------------------------------------------------

/// A collection of witness attestations for a subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessSet {
    /// Unique identifier for this witness set.
    pub set_id: u64,
    /// What is being witnessed.
    pub anchor: WitnessAnchor,
    /// Quorum class for verification.
    pub quorum_class: WitnessQuorumClass,
    /// Voters selected as witnesses.
    pub selected_witnesses: Vec<MemberId>,
    /// Collectd witness records.
    pub collected: Vec<WitnessRecord>,
    /// Current lifecycle state.
    pub lifecycle: WitnessLifecycle,
    /// When the witness set was created (millis since epoch).
    pub created_at_millis: u64,
    /// Collection deadline (millis since epoch).
    pub deadline_millis: u64,
    /// Current epoch at time of creation.
    pub epoch: EpochId,
    /// Verification receipt (produced after quorum verification).
    pub verification_receipt: Option<WitnessVerificationReceipt>,
}

// ---------------------------------------------------------------------------
// Witness verification receipt
// ---------------------------------------------------------------------------

/// Emitted after witness quorum is reached and verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessVerificationReceipt {
    /// The witness set this receipt verifies.
    pub witness_set_id: u64,
    /// Whether the verification passed.
    pub verified: bool,
    /// Number of witnesses that confirmed.
    pub confirming_count: usize,
    /// Number of witnesses that refuted.
    pub refuting_count: usize,
    /// When verification completed (millis since epoch).
    pub verified_at_millis: u64,
    /// Digest of all witness signatures for audit trail.
    pub aggregate_digest: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Witness set errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("not enough voters to form witness set: have {have}, need at least {need}")]
    InsufficientVoters { have: usize, need: usize },
    #[error("witness {0} is quarantined and cannot serve")]
    RefuseQuarantinedWitness(u64),
    #[error("witness {0} is not in the current epoch {1}")]
    WitnessNotInEpoch(u64, u64),
    #[error("witness {witness} is unknown in membership epoch {epoch}")]
    UnknownWitness { witness: u64, epoch: u64 },
    #[error(
        "witness {witness} belongs to membership epoch {member_epoch}, current epoch is {current_epoch}"
    )]
    StaleWitnessEpoch {
        witness: u64,
        member_epoch: u64,
        current_epoch: u64,
    },
    #[error("witness {witness} has member class {member_class:?}, not voter")]
    WitnessNotVoter {
        witness: u64,
        member_class: MemberClass,
    },
    #[error("witness {0} has invalid signature")]
    InvalidSignature(u64),
    #[error("collection timed out: collected {collected} of {required}")]
    Timeout { collected: usize, required: usize },
    #[error("witness set already in terminal state {0:?}")]
    AlreadyTerminal(WitnessLifecycle),
    #[error("witness set not found: {0}")]
    NotFound(u64),
    #[error("witness set already exists: {0}")]
    Duplicate(u64),
}

// ---------------------------------------------------------------------------
// Witness selection context
// ---------------------------------------------------------------------------

/// Context for selecting witnesses.
#[derive(Clone, Debug)]
pub struct WitnessSelectionContext {
    /// All voters in the current epoch.
    pub voters: Vec<ClusterMemberRecord>,
    /// Members to exclude from selection (e.g., quarantined, drained).
    pub excluded: Vec<MemberId>,
    /// The subject's authority homes (for failure-domain separation).
    pub authority_homes: Vec<FailureDomainVector>,
    /// The subject's replica locations (for failure-domain separation).
    pub replica_locations: Vec<FailureDomainVector>,
    /// Maximum witnesses to select.
    pub max_witnesses: usize,
    /// Minimum witnesses required.
    pub min_witnesses: usize,
    /// Current epoch.
    pub current_epoch: EpochId,
}

// ---------------------------------------------------------------------------
// Witness membership classification
// ---------------------------------------------------------------------------

/// Membership-epoch classification snapshot consumed by the ack tracker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessMemberClassification {
    /// Member identity from `tidefs-membership-epoch`.
    pub member_id: MemberId,
    /// Committed membership epoch that produced this classification.
    pub epoch: EpochId,
    /// Member class in that epoch.
    pub member_class: MemberClass,
}

impl WitnessMemberClassification {
    #[must_use]
    pub const fn from_record(record: &ClusterMemberRecord) -> Self {
        Self {
            member_id: record.member_id,
            epoch: record.current_membership_epoch_ref,
            member_class: record.member_class,
        }
    }

    #[must_use]
    pub const fn is_voter_in_epoch(self, epoch: EpochId) -> bool {
        self.epoch.0 == epoch.0 && self.member_class.can_vote()
    }
}

// ---------------------------------------------------------------------------
// Canonical typed IDs for witness-set tracking (issue #5203)
// ---------------------------------------------------------------------------

/// Node identifier within the cluster (maps to membership NodeIdentity).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

/// Object identifier within the local object store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub u64);

/// Transaction group identifier for ordering and epoch scoping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxgId(pub u64);

/// Classification of a witness acknowledgment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckKind {
    /// The replica completed the write and flushed to stable storage.
    WriteComplete,
    /// The replica acknowledged the intent-log record but may not have flushed.
    IntentLogged,
    /// The replica received the write but has not yet processed it.
    Received,
    /// An explicit refutation: the replica rejected the operation.
    Refuted,
}

// ---------------------------------------------------------------------------
// WitnessEntry — typed acknowledgment record
// ---------------------------------------------------------------------------

/// A single witness acknowledgment, carrying typed identifiers for the node,
/// object, and transaction group that produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessEntry {
    /// Which node provided this acknowledgment.
    pub node_id: NodeId,
    /// Which object the acknowledgment pertains to.
    pub object_id: ObjectId,
    /// Which transaction group this ack belongs to.
    pub txg_id: TxgId,
    /// The kind of acknowledgment (write-complete, intent-logged, etc.).
    pub ack_kind: AckKind,
    /// Wall-clock timestamp in nanoseconds since an arbitrary epoch.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Quorum outcome
// ---------------------------------------------------------------------------

/// Result of evaluating a witness set against a quorum threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumOutcome {
    /// The configured quorum threshold has been reached.
    Reached,
    /// Quorum not satisfied; the number of additional acks needed.
    Shortfall(u32),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};

    // -- WitnessQuorumClass --------------------------------------------------

    #[test]
    fn test_strict_majority_required_count() {
        let qc = WitnessQuorumClass::StrictMajority;
        assert_eq!(qc.required_count(0), 1);
        assert_eq!(qc.required_count(1), 1);
        assert_eq!(qc.required_count(2), 2);
        assert_eq!(qc.required_count(3), 2);
        assert_eq!(qc.required_count(4), 3);
        assert_eq!(qc.required_count(5), 3);
        assert_eq!(qc.required_count(10), 6);
    }

    #[test]
    fn test_flexible_required_count() {
        let qc = WitnessQuorumClass::Flexible {
            required: 3,
            total: 5,
        };
        assert_eq!(qc.required_count(5), 3);
        assert_eq!(qc.required_count(2), 2);
        assert_eq!(qc.required_count(0), 0);
    }

    #[test]
    fn test_strict_majority_is_satisfied() {
        let qc = WitnessQuorumClass::StrictMajority;
        assert!(qc.is_satisfied(2, 3));
        assert!(!qc.is_satisfied(1, 3));
        assert!(qc.is_satisfied(3, 3));
        assert!(qc.is_satisfied(1, 1));
        assert!(!qc.is_satisfied(0, 1));
    }

    #[test]
    fn test_flexible_is_satisfied() {
        let qc = WitnessQuorumClass::Flexible {
            required: 2,
            total: 5,
        };
        assert!(qc.is_satisfied(2, 5));
        assert!(!qc.is_satisfied(1, 5));
        assert!(qc.is_satisfied(3, 5));
    }

    #[test]
    fn test_witness_quorum_class_serialization() {
        let qc = WitnessQuorumClass::StrictMajority;
        let json = serde_json::to_string(&qc).unwrap();
        let qc2: WitnessQuorumClass = serde_json::from_str(&json).unwrap();
        assert_eq!(qc, qc2);

        let qc = WitnessQuorumClass::Flexible {
            required: 3,
            total: 7,
        };
        let json = serde_json::to_string(&qc).unwrap();
        let qc2: WitnessQuorumClass = serde_json::from_str(&json).unwrap();
        assert_eq!(qc, qc2);
    }

    // -- WitnessLifecycle ----------------------------------------------------

    #[test]
    fn test_witness_lifecycle_serialization() {
        let states = vec![
            WitnessLifecycle::Proposed,
            WitnessLifecycle::Collecting,
            WitnessLifecycle::QuorumReached,
            WitnessLifecycle::Verified,
            WitnessLifecycle::Refuted {
                reason: "claim mismatch".into(),
            },
            WitnessLifecycle::TimedOut,
            WitnessLifecycle::Expired,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let s2: WitnessLifecycle = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, s2);
        }
    }

    // -- WitnessAnchor -------------------------------------------------------

    #[test]
    fn test_witness_anchor_serialization() {
        let anchors = vec![
            WitnessAnchor::Chunk {
                chunk_key: b"key1".to_vec(),
                expected_digest: b"digest1".to_vec(),
            },
            WitnessAnchor::Epoch {
                epoch_id: EpochId::new(42),
            },
            WitnessAnchor::Receipt { receipt_id: 999 },
        ];
        for anchor in &anchors {
            let json = serde_json::to_string(anchor).unwrap();
            let a2: WitnessAnchor = serde_json::from_str(&json).unwrap();
            assert_eq!(*anchor, a2);
        }
    }

    // -- WitnessRecord -------------------------------------------------------

    #[test]
    fn test_witness_record_serialization() {
        let record = WitnessRecord {
            witness_id: MemberId::new(7),
            anchor: WitnessAnchor::Chunk {
                chunk_key: b"ck".to_vec(),
                expected_digest: b"ed".to_vec(),
            },
            claim_digest: b"claim".to_vec(),
            witnessed_at_millis: 123456789,
            quorum_class: WitnessQuorumClass::StrictMajority,
            signature: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&record).unwrap();
        let r2: WitnessRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, r2);
    }

    // -- WitnessSet (types) --------------------------------------------------

    #[test]
    fn test_types_witness_set_serialization() {
        let ws = WitnessSet {
            set_id: 1,
            anchor: WitnessAnchor::Epoch {
                epoch_id: EpochId::new(5),
            },
            quorum_class: WitnessQuorumClass::StrictMajority,
            selected_witnesses: vec![MemberId::new(1), MemberId::new(2)],
            collected: vec![],
            lifecycle: WitnessLifecycle::Proposed,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(5),
            verification_receipt: None,
        };
        let json = serde_json::to_string(&ws).unwrap();
        let ws2: WitnessSet = serde_json::from_str(&json).unwrap();
        assert_eq!(ws, ws2);
    }

    #[test]
    fn test_types_witness_set_with_receipt() {
        let receipt = WitnessVerificationReceipt {
            witness_set_id: 1,
            verified: true,
            confirming_count: 3,
            refuting_count: 0,
            verified_at_millis: 2000,
            aggregate_digest: vec![9, 8, 7],
        };
        let ws = WitnessSet {
            set_id: 1,
            anchor: WitnessAnchor::Receipt { receipt_id: 100 },
            quorum_class: WitnessQuorumClass::Flexible {
                required: 2,
                total: 3,
            },
            selected_witnesses: vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            collected: vec![],
            lifecycle: WitnessLifecycle::Verified,
            created_at_millis: 1000,
            deadline_millis: 5000,
            epoch: EpochId::new(10),
            verification_receipt: Some(receipt.clone()),
        };
        let json = serde_json::to_string(&ws).unwrap();
        let ws2: WitnessSet = serde_json::from_str(&json).unwrap();
        assert_eq!(ws, ws2);
        assert!(ws2.verification_receipt.is_some());
        assert_eq!(ws2.verification_receipt.unwrap().confirming_count, 3);
    }

    // -- WitnessVerificationReceipt ------------------------------------------

    #[test]
    fn test_verification_receipt_serialization() {
        let receipt = WitnessVerificationReceipt {
            witness_set_id: 42,
            verified: false,
            confirming_count: 1,
            refuting_count: 2,
            verified_at_millis: 9999,
            aggregate_digest: vec![0xAA, 0xBB],
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let r2: WitnessVerificationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, r2);
    }

    // -- WitnessError --------------------------------------------------------

    #[test]
    fn test_witness_error_display_insufficient_voters() {
        let err = WitnessError::InsufficientVoters { have: 2, need: 5 };
        assert!(format!("{err}").contains("not enough voters"));
    }

    #[test]
    fn test_witness_error_display_quarantined() {
        let err = WitnessError::RefuseQuarantinedWitness(42);
        assert!(format!("{err}").contains("42"));
    }

    #[test]
    fn test_witness_error_display_not_in_epoch() {
        let err = WitnessError::WitnessNotInEpoch(7, 3);
        assert!(format!("{err}").contains("7"));
        assert!(format!("{err}").contains("3"));
    }

    #[test]
    fn test_witness_error_display_invalid_signature() {
        let err = WitnessError::InvalidSignature(99);
        assert!(format!("{err}").contains("99"));
    }

    #[test]
    fn test_witness_error_display_timeout() {
        let err = WitnessError::Timeout {
            collected: 1,
            required: 3,
        };
        assert!(format!("{err}").contains("timed out"));
    }

    #[test]
    fn test_witness_error_display_already_terminal() {
        let err = WitnessError::AlreadyTerminal(WitnessLifecycle::Expired);
        assert!(format!("{err}").contains("terminal"));
    }

    #[test]
    fn test_witness_error_display_not_found() {
        let err = WitnessError::NotFound(555);
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn test_witness_error_display_duplicate() {
        let err = WitnessError::Duplicate(777);
        assert!(format!("{err}").contains("already exists"));
    }

    #[test]
    fn test_witness_error_debug() {
        let err = WitnessError::NotFound(10);
        let debug = format!("{err:?}");
        assert!(debug.contains("NotFound"));
    }

    // -- Typed IDs -----------------------------------------------------------

    #[test]
    fn test_node_id_ordering() {
        assert!(NodeId(1) < NodeId(2));
        assert!(NodeId(10) > NodeId(5));
        assert_eq!(NodeId(42), NodeId(42));
    }

    #[test]
    fn test_object_id_ordering() {
        let mut ids = vec![ObjectId(3), ObjectId(1), ObjectId(2)];
        ids.sort();
        assert_eq!(ids, vec![ObjectId(1), ObjectId(2), ObjectId(3)]);
    }

    #[test]
    fn test_txg_id_serialization() {
        let txg = TxgId(12345);
        let json = serde_json::to_string(&txg).unwrap();
        let txg2: TxgId = serde_json::from_str(&json).unwrap();
        assert_eq!(txg, txg2);
    }

    // -- AckKind -------------------------------------------------------------

    #[test]
    fn test_ack_kind_serialization() {
        let kinds = [
            AckKind::WriteComplete,
            AckKind::IntentLogged,
            AckKind::Received,
            AckKind::Refuted,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let k2: AckKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, k2);
        }
    }

    // -- WitnessEntry --------------------------------------------------------

    #[test]
    fn test_witness_entry_construction() {
        let entry = WitnessEntry {
            node_id: NodeId(1),
            object_id: ObjectId(100),
            txg_id: TxgId(5),
            ack_kind: AckKind::WriteComplete,
            timestamp_ns: 1000,
        };
        assert_eq!(entry.node_id.0, 1);
        assert_eq!(entry.object_id.0, 100);
        assert_eq!(entry.txg_id.0, 5);
        assert_eq!(entry.ack_kind, AckKind::WriteComplete);
        assert_eq!(entry.timestamp_ns, 1000);
    }

    #[test]
    fn test_witness_entry_serialization() {
        let entry = WitnessEntry {
            node_id: NodeId(42),
            object_id: ObjectId(777),
            txg_id: TxgId(999),
            ack_kind: AckKind::IntentLogged,
            timestamp_ns: 1234567890123,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let e2: WitnessEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, e2);
    }

    // -- QuorumOutcome -------------------------------------------------------

    #[test]
    fn test_quorum_outcome_reached() {
        let outcome = QuorumOutcome::Reached;
        assert_eq!(outcome, QuorumOutcome::Reached);
    }

    #[test]
    fn test_quorum_outcome_shortfall() {
        let outcome = QuorumOutcome::Shortfall(3);
        assert_eq!(outcome, QuorumOutcome::Shortfall(3));
        assert_ne!(outcome, QuorumOutcome::Shortfall(2));
        assert_ne!(outcome, QuorumOutcome::Reached);
    }

    // -- WitnessSelectionContext ---------------------------------------------

    #[test]
    fn test_witness_selection_context_fields() {
        let ctx = WitnessSelectionContext {
            voters: vec![],
            excluded: vec![],
            authority_homes: vec![],
            replica_locations: vec![],
            max_witnesses: 5,
            min_witnesses: 3,
            current_epoch: EpochId::new(1),
        };
        assert_eq!(ctx.max_witnesses, 5);
        assert_eq!(ctx.min_witnesses, 3);
        assert!(ctx.voters.is_empty());
    }
}
