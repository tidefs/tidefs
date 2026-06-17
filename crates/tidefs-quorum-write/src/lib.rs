#![allow(clippy::too_many_arguments)]
#![forbid(unsafe_code)]

//! Deterministic 4-phase quorum write protocol model.
//!
//! Implements the PREPARE → TRANSFER → COMMIT → WITNESS protocol from
//! the P8-0x quorum write specification. This crate provides the type
//! grammar, message forms, durability modes, and a deterministic state
//! machine for test-driven validation before wiring into LocalFileSystem.
//!
//! # Durability modes
//!
//! - `quorum_full`: write returns only after N placement receipts
//! - `quorum_witness`: write returns after N/2+1 witness attestations
//! - `quorum_chain`: per-chunk receipt chain agreement

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Identifier newtypes
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct QuorumWriteId(pub u64);

impl QuorumWriteId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct TransferTicketId(pub u64);

impl TransferTicketId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct NodeId(pub u64);

impl NodeId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochId(pub u64);

impl EpochId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct WriteReceiptId(pub u64);

impl WriteReceiptId {
    pub const ZERO: Self = Self(0);
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// SHA-256 hash represented as bytes.
pub type DigestBytes = [u8; 32];

// ---------------------------------------------------------------------------
// DurabilityMode
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurabilityMode {
    QuorumFull = 0,
    QuorumWitness = 1,
    QuorumChain = 2,
}

impl DurabilityMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QuorumFull => "quorum_full",
            Self::QuorumWitness => "quorum_witness",
            Self::QuorumChain => "quorum_chain",
        }
    }

    /// Minimum acks required for quorum given N target nodes.
    #[must_use]
    pub const fn min_quorum(self, target_count: usize) -> usize {
        match self {
            Self::QuorumFull => target_count,
            Self::QuorumWitness | Self::QuorumChain => target_count / 2 + 1,
        }
    }
}

// ---------------------------------------------------------------------------
// WriteClass
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteClass {
    Committed = 0,
    DegradedCommitted = 1,
    RefusedNoQuorum = 2,
}

impl WriteClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::DegradedCommitted => "degraded_committed",
            Self::RefusedNoQuorum => "refused_no_quorum",
        }
    }

    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Committed | Self::DegradedCommitted)
    }

    #[must_use]
    pub const fn needs_repair(self) -> bool {
        matches!(self, Self::DegradedCommitted)
    }

    #[must_use]
    pub const fn is_refused(self) -> bool {
        matches!(self, Self::RefusedNoQuorum)
    }
}

// ---------------------------------------------------------------------------
// ReadClass
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadClass {
    Exact = 0,
    DegradedButValid = 1,
    RepairRequired = 2,
    Unavailable = 3,
}

impl ReadClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::DegradedButValid => "degraded_but_valid",
            Self::RepairRequired => "repair_required",
            Self::Unavailable => "unavailable",
        }
    }

    #[must_use]
    pub const fn is_readable(self) -> bool {
        matches!(self, Self::Exact | Self::DegradedButValid)
    }
}

// ---------------------------------------------------------------------------
// PhaseKind
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseKind {
    Prepare = 0,
    Transfer = 1,
    Commit = 2,
    Witness = 3,
}

impl PhaseKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Transfer => "transfer",
            Self::Commit => "commit",
            Self::Witness => "witness",
        }
    }

    #[must_use]
    pub fn next(self) -> Option<Self> {
        match self {
            Self::Prepare => Some(Self::Transfer),
            Self::Transfer => Some(Self::Commit),
            Self::Commit => Some(Self::Witness),
            Self::Witness => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RefusalReason
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalReason {
    NoCapacity = 0,
    WrongEpoch = 1,
    NotAuthorized = 2,
    DigestMismatch = 3,
    Timeout = 4,
}

impl RefusalReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCapacity => "no_capacity",
            Self::WrongEpoch => "wrong_epoch",
            Self::NotAuthorized => "not_authorized",
            Self::DigestMismatch => "digest_mismatch",
            Self::Timeout => "timeout",
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol state
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumWriteProtocol {
    pub write_id: QuorumWriteId,
    pub ticket_id: TransferTicketId,
    pub object_key: String,
    pub durability_mode: DurabilityMode,
    pub writer_id: NodeId,
    pub target_nodes: Vec<NodeId>,
    pub byte_count: u64,
    pub expected_digest: DigestBytes,
    pub placement_epoch: EpochId,
    pub current_phase: PhaseKind,
    pub digest: u64,
}

impl QuorumWriteProtocol {
    #[must_use]
    pub fn new(
        write_id: QuorumWriteId,
        ticket_id: TransferTicketId,
        object_key: String,
        durability_mode: DurabilityMode,
        writer_id: NodeId,
        target_nodes: Vec<NodeId>,
        byte_count: u64,
        expected_digest: DigestBytes,
        placement_epoch: EpochId,
    ) -> Self {
        Self {
            write_id,
            ticket_id,
            object_key,
            durability_mode,
            writer_id,
            target_nodes,
            byte_count,
            expected_digest,
            placement_epoch,
            current_phase: PhaseKind::Prepare,
            digest: 0,
        }
    }

    #[must_use]
    pub fn min_quorum(&self) -> usize {
        self.durability_mode.min_quorum(self.target_nodes.len())
    }
}

// ---------------------------------------------------------------------------
// Message types: Phase 1 — PREPARE
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PrepareRequest {
    pub ticket_id: TransferTicketId,
    pub object_key: String,
    pub byte_count: u64,
    pub expected_digest: DigestBytes,
    pub placement_epoch: EpochId,
    pub writer_id: NodeId,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PrepareResponse {
    pub ticket_id: TransferTicketId,
    pub target: NodeId,
    pub accepted: bool,
    pub reason_if_refused: Option<RefusalReason>,
    pub digest: u64,
}

// ---------------------------------------------------------------------------
// Message types: Phase 2 — TRANSFER
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferChunk {
    pub ticket_id: TransferTicketId,
    pub chunk_index: u64,
    pub data: Vec<u8>,
    pub expected_digest: DigestBytes,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransferAck {
    pub ticket_id: TransferTicketId,
    pub chunk_index: u64,
    pub target: NodeId,
    pub received_digest: DigestBytes,
    pub digest_ok: bool,
}

// ---------------------------------------------------------------------------
// Message types: Phase 3 — COMMIT
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CommitRequest {
    pub ticket_id: TransferTicketId,
    pub object_key: String,
    pub commit_seq: u64,
    pub acks_received: u64,
    pub quorum_size: u64,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CommitAck {
    pub ticket_id: TransferTicketId,
    pub target: NodeId,
    pub placement_receipt_id: WriteReceiptId,
    pub receipt_committed: bool,
    pub digest: u64,
}

// ---------------------------------------------------------------------------
// Message types: Phase 4 — WITNESS
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct WitnessRequest {
    pub ticket_id: TransferTicketId,
    pub object_key: String,
    pub placement_receipts: Vec<WriteReceiptId>,
    pub quorum_size: u64,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct WitnessAck {
    pub ticket_id: TransferTicketId,
    pub target: NodeId,
    pub attested: bool,
    pub digest: u64,
}

// ---------------------------------------------------------------------------
// Aggregate records
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumWriteResult {
    pub write_id: QuorumWriteId,
    pub ticket_id: TransferTicketId,
    pub object_key: String,
    pub write_class: WriteClass,
    pub acks_count: u64,
    pub target_count: u64,
    pub quorum_size: u64,
    pub durability_mode: DurabilityMode,
    pub placement_receipts: Vec<WriteReceiptId>,
    pub witnesses: Vec<NodeId>,
    pub needs_repair: bool,
    pub digests_matched: bool,
    pub digest: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumWriteTargetRecord {
    pub target: NodeId,
    pub prepare_accepted: bool,
    pub prepare_refusal_reason: Option<RefusalReason>,
    pub transfer_acked: bool,
    pub transfer_digest_ok: bool,
    pub commit_acked: bool,
    pub witness_attested: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QuorumWriteSummary {
    pub write_id: QuorumWriteId,
    pub write_class: WriteClass,
    pub target_records: Vec<QuorumWriteTargetRecord>,
    pub acks_at_commit: u64,
    pub acks_at_witness: u64,
    pub min_quorum: u64,
    pub degraded: bool,
    pub refused: bool,
}

// ---------------------------------------------------------------------------
// Algorithm 1: execute PREPARE phase
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_prepare_phase(
    protocol: &QuorumWriteProtocol,
    target_capacities: &[(NodeId, bool)],
    target_epochs: &[(NodeId, EpochId)],
    authorized_writers: &[NodeId],
) -> Vec<PrepareResponse> {
    let mut responses = Vec::with_capacity(protocol.target_nodes.len());
    let epoch = protocol.placement_epoch;

    for &target in &protocol.target_nodes {
        let has_capacity = target_capacities.iter().any(|(n, c)| *n == target && *c);
        let target_epoch = target_epochs
            .iter()
            .find(|(n, _)| *n == target)
            .map(|(_, e)| *e)
            .unwrap_or(EpochId::ZERO);
        let is_authorized = authorized_writers.contains(&protocol.writer_id);

        let (accepted, reason) = if !has_capacity {
            (false, Some(RefusalReason::NoCapacity))
        } else if target_epoch != epoch {
            (false, Some(RefusalReason::WrongEpoch))
        } else if !is_authorized {
            (false, Some(RefusalReason::NotAuthorized))
        } else {
            (true, None)
        };

        let mut digest = protocol.ticket_id.0;
        digest = digest.wrapping_mul(31).wrapping_add(target.0);
        digest = digest
            .wrapping_mul(31)
            .wrapping_add(if accepted { 1 } else { 0 });

        responses.push(PrepareResponse {
            ticket_id: protocol.ticket_id,
            target,
            accepted,
            reason_if_refused: reason,
            digest,
        });
    }

    responses
}

// ---------------------------------------------------------------------------
// Algorithm 2: execute TRANSFER phase
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_transfer_phase(
    protocol: &QuorumWriteProtocol,
    prepare_responses: &[PrepareResponse],
    data: &[u8],
    target_digest_ok: &[(NodeId, bool)],
) -> Vec<TransferAck> {
    let mut acks = Vec::new();
    for (ci, pr) in prepare_responses.iter().enumerate() {
        if !pr.accepted {
            continue;
        }
        let ok = target_digest_ok
            .iter()
            .find(|(n, _)| *n == pr.target)
            .map(|(_, d)| *d)
            .unwrap_or(true);

        let mut rd: DigestBytes = [0u8; 32];
        for (i, b) in data.iter().enumerate().take(32) {
            rd[i] = if ok { *b } else { b.wrapping_add(1) };
        }

        acks.push(TransferAck {
            ticket_id: protocol.ticket_id,
            chunk_index: ci as u64,
            target: pr.target,
            received_digest: rd,
            digest_ok: ok,
        });
    }
    acks
}

// ---------------------------------------------------------------------------
// Algorithm 3: execute COMMIT phase
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_commit_phase(
    protocol: &QuorumWriteProtocol,
    transfer_acks: &[TransferAck],
) -> Vec<CommitAck> {
    let mut acks = Vec::new();
    for ta in transfer_acks.iter().filter(|a| a.digest_ok) {
        let receipt_id = WriteReceiptId::new(
            protocol
                .ticket_id
                .0
                .wrapping_mul(31)
                .wrapping_add(ta.target.0),
        );

        let mut digest = protocol.ticket_id.0;
        digest = digest.wrapping_mul(31).wrapping_add(ta.target.0);

        acks.push(CommitAck {
            ticket_id: protocol.ticket_id,
            target: ta.target,
            placement_receipt_id: receipt_id,
            receipt_committed: true,
            digest,
        });
    }
    acks
}

// ---------------------------------------------------------------------------
// Algorithm 4: execute WITNESS phase
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_witness_phase(
    protocol: &QuorumWriteProtocol,
    commit_acks: &[CommitAck],
    witness_targets: &[(NodeId, bool)],
) -> Vec<WitnessAck> {
    let mut acks = Vec::new();
    for ca in commit_acks {
        let attests = witness_targets
            .iter()
            .find(|(n, _)| *n == ca.target)
            .map(|(_, a)| *a)
            .unwrap_or(true);

        let mut digest = protocol.ticket_id.0;
        digest = digest.wrapping_mul(31).wrapping_add(ca.target.0);
        digest = digest
            .wrapping_mul(31)
            .wrapping_add(if attests { 1 } else { 0 });

        acks.push(WitnessAck {
            ticket_id: protocol.ticket_id,
            target: ca.target,
            attested: attests,
            digest,
        });
    }
    acks
}

// ---------------------------------------------------------------------------
// Algorithm 5: evaluate quorum result
// ---------------------------------------------------------------------------

#[must_use]
pub fn evaluate_quorum_result(
    protocol: &QuorumWriteProtocol,
    transfer_acks: &[TransferAck],
    commit_acks: &[CommitAck],
    witness_acks: &[WitnessAck],
) -> QuorumWriteResult {
    let min_q = protocol.min_quorum() as u64;
    let target_count = protocol.target_nodes.len() as u64;
    let committed_receipt_acks: Vec<&CommitAck> = commit_acks
        .iter()
        .filter(|ack| ack.receipt_committed && ack.placement_receipt_id != WriteReceiptId::ZERO)
        .collect();
    let valid_commit_acks = committed_receipt_acks.len() as u64;
    let _valid_witness = witness_acks.iter().filter(|w| w.attested).count() as u64;

    let write_class = if valid_commit_acks < min_q {
        WriteClass::RefusedNoQuorum
    } else if valid_commit_acks == target_count {
        WriteClass::Committed
    } else {
        WriteClass::DegradedCommitted
    };

    let placement_receipts: Vec<WriteReceiptId> = committed_receipt_acks
        .iter()
        .map(|ca| ca.placement_receipt_id)
        .collect();
    let witnesses: Vec<NodeId> = witness_acks
        .iter()
        .filter(|w| w.attested)
        .map(|w| w.target)
        .collect();
    let all_digests_ok = transfer_acks.iter().all(|a| a.digest_ok);

    let mut digest = protocol.write_id.0;
    digest = digest.wrapping_mul(31).wrapping_add(write_class as u64);
    digest = digest.wrapping_mul(31).wrapping_add(valid_commit_acks);

    QuorumWriteResult {
        write_id: protocol.write_id,
        ticket_id: protocol.ticket_id,
        object_key: protocol.object_key.clone(),
        write_class,
        acks_count: valid_commit_acks,
        target_count,
        quorum_size: min_q,
        durability_mode: protocol.durability_mode,
        placement_receipts,
        witnesses,
        needs_repair: write_class == WriteClass::DegradedCommitted,
        digests_matched: all_digests_ok,
        digest,
    }
}

// ---------------------------------------------------------------------------
// Algorithm 6: full protocol execution (convenience)
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_full_quorum_write(
    write_id: QuorumWriteId,
    ticket_id: TransferTicketId,
    object_key: &str,
    durability_mode: DurabilityMode,
    writer_id: NodeId,
    target_nodes: &[NodeId],
    byte_count: u64,
    expected_digest: DigestBytes,
    placement_epoch: EpochId,
    target_capacities: &[(NodeId, bool)],
    target_epochs: &[(NodeId, EpochId)],
    authorized_writers: &[NodeId],
    data: &[u8],
    target_digest_ok: &[(NodeId, bool)],
    witness_targets: &[(NodeId, bool)],
) -> QuorumWriteResult {
    let protocol = QuorumWriteProtocol::new(
        write_id,
        ticket_id,
        object_key.to_string(),
        durability_mode,
        writer_id,
        target_nodes.to_vec(),
        byte_count,
        expected_digest,
        placement_epoch,
    );

    let prepare = execute_prepare_phase(
        &protocol,
        target_capacities,
        target_epochs,
        authorized_writers,
    );
    let transfer = execute_transfer_phase(&protocol, &prepare, data, target_digest_ok);
    let commit = execute_commit_phase(&protocol, &transfer);
    let witness = execute_witness_phase(&protocol, &commit, witness_targets);

    evaluate_quorum_result(&protocol, &transfer, &commit, &witness)
}

// ---------------------------------------------------------------------------
// Algorithm 7: degraded read assembly
// ---------------------------------------------------------------------------

#[must_use]
pub fn execute_degraded_read(
    target_nodes: &[NodeId],
    replica_data: &[(NodeId, Option<Vec<u8>>)],
) -> (ReadClass, Option<Vec<u8>>, Vec<NodeId>) {
    let mut tried = Vec::new();

    for &target in target_nodes {
        tried.push(target);
        if let Some(data) = replica_data
            .iter()
            .find(|(n, _)| *n == target)
            .and_then(|(_, d)| d.clone())
        {
            if !data.is_empty() {
                if target == target_nodes[0] {
                    return (ReadClass::Exact, Some(data), tried);
                }
                return (ReadClass::DegradedButValid, Some(data), tried);
            }
        }
    }

    (ReadClass::Unavailable, None, tried)
}

// ---------------------------------------------------------------------------
// Algorithm 8: build quorum write summary
// ---------------------------------------------------------------------------

#[must_use]
pub fn build_quorum_write_summary(
    result: &QuorumWriteResult,
    prepare_responses: &[PrepareResponse],
    transfer_acks: &[TransferAck],
    commit_acks: &[CommitAck],
    witness_acks: &[WitnessAck],
) -> QuorumWriteSummary {
    let mut target_records = Vec::new();
    let mut seen = Vec::new();
    for pr in prepare_responses {
        if !seen.contains(&pr.target) {
            seen.push(pr.target);
        }
    }

    for &target in &seen {
        let pr = prepare_responses.iter().find(|r| r.target == target);
        let ta = transfer_acks.iter().find(|a| a.target == target);
        let ca = commit_acks.iter().find(|a| a.target == target);
        let wa = witness_acks.iter().find(|a| a.target == target);

        target_records.push(QuorumWriteTargetRecord {
            target,
            prepare_accepted: pr.map(|r| r.accepted).unwrap_or(false),
            prepare_refusal_reason: pr.and_then(|r| r.reason_if_refused),
            transfer_acked: ta.is_some(),
            transfer_digest_ok: ta.map(|a| a.digest_ok).unwrap_or(false),
            commit_acked: ca.map(|a| a.receipt_committed).unwrap_or(false),
            witness_attested: wa.map(|a| a.attested).unwrap_or(false),
        });
    }

    QuorumWriteSummary {
        write_id: result.write_id,
        write_class: result.write_class,
        target_records,
        acks_at_commit: commit_acks
            .iter()
            .filter(|ack| ack.receipt_committed && ack.placement_receipt_id != WriteReceiptId::ZERO)
            .count() as u64,
        acks_at_witness: witness_acks.iter().filter(|w| w.attested).count() as u64,
        min_quorum: result.quorum_size,
        degraded: result.write_class == WriteClass::DegradedCommitted,
        refused: result.write_class == WriteClass::RefusedNoQuorum,
    }
}

// ---------------------------------------------------------------------------
// Algorithm 9: validate quorum invariants
// ---------------------------------------------------------------------------

#[must_use]
pub fn validate_quorum_invariants(
    result: &QuorumWriteResult,
    summary: &QuorumWriteSummary,
) -> Vec<String> {
    let mut violations = Vec::new();

    if result.write_class == WriteClass::Committed && result.acks_count < result.quorum_size {
        violations.push(format!(
            "Committed but acks ({}) < quorum ({})",
            result.acks_count, result.quorum_size
        ));
    }
    if result.write_class == WriteClass::RefusedNoQuorum
        && result.quorum_size > 0
        && result.acks_count >= result.quorum_size
    {
        violations.push(format!(
            "RefusedNoQuorum but acks ({}) >= quorum ({})",
            result.acks_count, result.quorum_size
        ));
    }
    if result.write_class == WriteClass::DegradedCommitted {
        if result.acks_count < result.quorum_size {
            violations.push(format!(
                "DegradedCommitted but acks ({}) < quorum ({})",
                result.acks_count, result.quorum_size
            ));
        }
        if result.acks_count >= result.target_count {
            violations.push(format!(
                "DegradedCommitted but acks ({}) >= target count ({})",
                result.acks_count, result.target_count
            ));
        }
    }
    if result.needs_repair != (result.write_class == WriteClass::DegradedCommitted) {
        violations.push("needs_repair mismatch".into());
    }
    if result.placement_receipts.len() as u64 != result.acks_count {
        violations.push(format!(
            "Placement receipts ({}) != acks ({})",
            result.placement_receipts.len(),
            result.acks_count
        ));
    }
    if summary.degraded != (result.write_class == WriteClass::DegradedCommitted) {
        violations.push("summary.degraded mismatch".into());
    }
    if summary.refused != (result.write_class == WriteClass::RefusedNoQuorum) {
        violations.push("summary.refused mismatch".into());
    }

    violations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(n: usize) -> Vec<NodeId> {
        (1..=n).map(|i| NodeId::new(i as u64)).collect()
    }

    fn all_capacity(targets: &[NodeId], val: bool) -> Vec<(NodeId, bool)> {
        targets.iter().map(|&n| (n, val)).collect()
    }

    fn all_epoch(targets: &[NodeId], epoch: EpochId) -> Vec<(NodeId, EpochId)> {
        targets.iter().map(|&n| (n, epoch)).collect()
    }

    fn empty_digest() -> DigestBytes {
        [0u8; 32]
    }
    fn full_digest() -> DigestBytes {
        [0xAAu8; 32]
    }

    fn basic_protocol() -> QuorumWriteProtocol {
        QuorumWriteProtocol::new(
            QuorumWriteId::new(1),
            TransferTicketId::new(100),
            "obj/1".into(),
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            nodes(3),
            1024,
            full_digest(),
            EpochId::new(1),
        )
    }

    // ------- ID newtypes ----------------------------------------------

    #[test]
    fn all_ids_have_zero() {
        assert_eq!(QuorumWriteId::ZERO.0, 0);
        assert_eq!(TransferTicketId::ZERO.0, 0);
        assert_eq!(NodeId::ZERO.0, 0);
        assert_eq!(EpochId::ZERO.0, 0);
        assert_eq!(WriteReceiptId::ZERO.0, 0);
    }

    #[test]
    fn ids_are_comparable() {
        let a = NodeId::new(1);
        let b = NodeId::new(2);
        assert!(a < b);
        assert_eq!(NodeId::new(1), NodeId::new(1));
    }

    // ------- DurabilityMode -------------------------------------------

    #[test]
    fn quorum_full_requires_all_targets() {
        assert_eq!(DurabilityMode::QuorumFull.min_quorum(3), 3);
        assert_eq!(DurabilityMode::QuorumFull.min_quorum(5), 5);
        assert_eq!(DurabilityMode::QuorumFull.min_quorum(1), 1);
    }

    #[test]
    fn quorum_witness_requires_majority() {
        assert_eq!(DurabilityMode::QuorumWitness.min_quorum(3), 2);
        assert_eq!(DurabilityMode::QuorumWitness.min_quorum(5), 3);
        assert_eq!(DurabilityMode::QuorumWitness.min_quorum(2), 2);
        assert_eq!(DurabilityMode::QuorumWitness.min_quorum(1), 1);
    }

    #[test]
    fn quorum_chain_requires_majority() {
        assert_eq!(DurabilityMode::QuorumChain.min_quorum(3), 2);
        assert_eq!(DurabilityMode::QuorumChain.min_quorum(7), 4);
    }

    #[test]
    fn durability_mode_as_str_is_correct() {
        assert_eq!(DurabilityMode::QuorumFull.as_str(), "quorum_full");
        assert_eq!(DurabilityMode::QuorumWitness.as_str(), "quorum_witness");
        assert_eq!(DurabilityMode::QuorumChain.as_str(), "quorum_chain");
    }

    // ------- WriteClass -----------------------------------------------

    #[test]
    fn committed_is_success() {
        assert!(WriteClass::Committed.is_success());
        assert!(!WriteClass::Committed.needs_repair());
        assert!(!WriteClass::Committed.is_refused());
    }

    #[test]
    fn degraded_is_success_but_needs_repair() {
        assert!(WriteClass::DegradedCommitted.is_success());
        assert!(WriteClass::DegradedCommitted.needs_repair());
        assert!(!WriteClass::DegradedCommitted.is_refused());
    }

    #[test]
    fn refused_is_not_success() {
        assert!(!WriteClass::RefusedNoQuorum.is_success());
        assert!(!WriteClass::RefusedNoQuorum.needs_repair());
        assert!(WriteClass::RefusedNoQuorum.is_refused());
    }

    // ------- ReadClass ------------------------------------------------

    #[test]
    fn exact_and_degraded_are_readable() {
        assert!(ReadClass::Exact.is_readable());
        assert!(ReadClass::DegradedButValid.is_readable());
    }

    #[test]
    fn repair_and_unavailable_are_not_readable() {
        assert!(!ReadClass::RepairRequired.is_readable());
        assert!(!ReadClass::Unavailable.is_readable());
    }

    // ------- PhaseKind ------------------------------------------------

    #[test]
    fn phase_chain_is_ordered() {
        assert_eq!(PhaseKind::Prepare.next(), Some(PhaseKind::Transfer));
        assert_eq!(PhaseKind::Transfer.next(), Some(PhaseKind::Commit));
        assert_eq!(PhaseKind::Commit.next(), Some(PhaseKind::Witness));
        assert_eq!(PhaseKind::Witness.next(), None);
    }

    // ------- Protocol construction ------------------------------------

    #[test]
    fn protocol_min_quorum_with_3_targets_witness() {
        let p = basic_protocol();
        assert_eq!(p.min_quorum(), 2);
        assert_eq!(p.target_nodes.len(), 3);
    }

    #[test]
    fn protocol_full_mode_min_quorum_is_3() {
        let p = QuorumWriteProtocol::new(
            QuorumWriteId::new(2),
            TransferTicketId::new(200),
            "obj/2".into(),
            DurabilityMode::QuorumFull,
            NodeId::new(0),
            nodes(3),
            512,
            empty_digest(),
            EpochId::new(1),
        );
        assert_eq!(p.min_quorum(), 3);
    }

    // ------- PREPARE phase (Algorithm 1) ------------------------------

    #[test]
    fn prepare_all_targets_accept_when_healthy() {
        let p = basic_protocol();
        let capacities = all_capacity(&nodes(3), true);
        let epochs = all_epoch(&nodes(3), EpochId::new(1));
        let auth = vec![NodeId::new(0)]; // writer is authorized

        let responses = execute_prepare_phase(&p, &capacities, &epochs, &auth);
        assert_eq!(responses.len(), 3);
        assert!(responses.iter().all(|r| r.accepted));
        assert!(responses.iter().all(|r| r.reason_if_refused.is_none()));
    }

    #[test]
    fn prepare_target_refuses_on_no_capacity() {
        let p = basic_protocol();
        let mut capacities = all_capacity(&nodes(3), true);
        capacities[1] = (NodeId::new(2), false); // target 2 has no capacity
        let epochs = all_epoch(&nodes(3), EpochId::new(1));
        let auth = vec![NodeId::new(0)];

        let responses = execute_prepare_phase(&p, &capacities, &epochs, &auth);
        let refused = responses
            .iter()
            .find(|r| r.target == NodeId::new(2))
            .unwrap();
        assert!(!refused.accepted);
        assert_eq!(refused.reason_if_refused, Some(RefusalReason::NoCapacity));
        // Others still accept
        assert!(responses
            .iter()
            .filter(|r| r.target != NodeId::new(2))
            .all(|r| r.accepted));
    }

    #[test]
    fn prepare_target_refuses_on_wrong_epoch() {
        let p = basic_protocol();
        let capacities = all_capacity(&nodes(3), true);
        let mut epochs = all_epoch(&nodes(3), EpochId::new(1));
        epochs[2] = (NodeId::new(3), EpochId::new(2)); // wrong epoch
        let auth = vec![NodeId::new(0)];

        let responses = execute_prepare_phase(&p, &capacities, &epochs, &auth);
        let refused = responses
            .iter()
            .find(|r| r.target == NodeId::new(3))
            .unwrap();
        assert!(!refused.accepted);
        assert_eq!(refused.reason_if_refused, Some(RefusalReason::WrongEpoch));
    }

    #[test]
    fn prepare_target_refuses_on_unauthorized_writer() {
        let p = basic_protocol();
        let capacities = all_capacity(&nodes(3), true);
        let epochs = all_epoch(&nodes(3), EpochId::new(1));
        let auth: Vec<NodeId> = vec![]; // writer NOT authorized

        let responses = execute_prepare_phase(&p, &capacities, &epochs, &auth);
        assert!(responses.iter().all(|r| !r.accepted));
        assert!(responses
            .iter()
            .all(|r| r.reason_if_refused == Some(RefusalReason::NotAuthorized)));
    }

    // ------- TRANSFER phase (Algorithm 2) -----------------------------

    #[test]
    fn transfer_only_sends_to_accepting_targets() {
        let p = basic_protocol();
        let prepare_responses = vec![
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                accepted: false,
                reason_if_refused: Some(RefusalReason::NoCapacity),
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
        ];
        let digests_ok = all_capacity(&nodes(3), true);
        let data = b"test_payload_data";

        let acks = execute_transfer_phase(&p, &prepare_responses, data, &digests_ok);
        assert_eq!(acks.len(), 2); // only targets 1 and 3
    }

    #[test]
    fn transfer_digest_mismatch_is_recorded() {
        let p = basic_protocol();
        let prepare_responses = vec![
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
        ];
        let mut digests_ok = all_capacity(&nodes(2), true);
        digests_ok[1] = (NodeId::new(2), false); // target 2 has digest mismatch
        let data = b"test_data";

        let acks = execute_transfer_phase(&p, &prepare_responses, data, &digests_ok);
        let ack2 = acks.iter().find(|a| a.target == NodeId::new(2)).unwrap();
        assert!(!ack2.digest_ok);
    }

    // ------- COMMIT phase (Algorithm 3) -------------------------------

    #[test]
    fn commit_only_includes_digest_ok_transfers() {
        let p = basic_protocol();
        let transfer_acks = vec![
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 0,
                target: NodeId::new(1),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 1,
                target: NodeId::new(2),
                received_digest: empty_digest(),
                digest_ok: false,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 2,
                target: NodeId::new(3),
                received_digest: empty_digest(),
                digest_ok: true,
            },
        ];
        let acks = execute_commit_phase(&p, &transfer_acks);
        assert_eq!(acks.len(), 2);
        assert!(acks.iter().any(|a| a.target == NodeId::new(1)));
        assert!(acks.iter().any(|a| a.target == NodeId::new(3)));
        assert!(acks
            .iter()
            .all(|a| a.placement_receipt_id != WriteReceiptId::ZERO));
    }

    #[test]
    fn commit_no_valid_transfers_returns_empty() {
        let p = basic_protocol();
        let transfer_acks = vec![TransferAck {
            ticket_id: p.ticket_id,
            chunk_index: 0,
            target: NodeId::new(1),
            received_digest: empty_digest(),
            digest_ok: false,
        }];
        let acks = execute_commit_phase(&p, &transfer_acks);
        assert!(acks.is_empty());
    }

    // ------- WITNESS phase (Algorithm 4) ------------------------------

    #[test]
    fn witness_all_attest() {
        let p = basic_protocol();
        let commit_acks = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witnesses = all_capacity(&[NodeId::new(1), NodeId::new(2)], true);

        let acks = execute_witness_phase(&p, &commit_acks, &witnesses);
        assert_eq!(acks.len(), 2);
        assert!(acks.iter().all(|w| w.attested));
    }

    #[test]
    fn witness_partial_attestation() {
        let p = basic_protocol();
        let commit_acks = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let mut witnesses = all_capacity(&[NodeId::new(1), NodeId::new(2)], true);
        witnesses[1] = (NodeId::new(2), false);

        let acks = execute_witness_phase(&p, &commit_acks, &witnesses);
        assert!(
            acks.iter()
                .find(|w| w.target == NodeId::new(1))
                .unwrap()
                .attested
        );
        assert!(
            !acks
                .iter()
                .find(|w| w.target == NodeId::new(2))
                .unwrap()
                .attested
        );
    }

    // ------- Evaluate result (Algorithm 5) ----------------------------

    #[test]
    fn evaluate_committed_when_3_of_3_ack() {
        let p = basic_protocol();
        let transfer = vec![
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 0,
                target: NodeId::new(1),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 1,
                target: NodeId::new(2),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 2,
                target: NodeId::new(3),
                received_digest: empty_digest(),
                digest_ok: true,
            },
        ];
        let commit = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                placement_receipt_id: WriteReceiptId::new(3),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witness = vec![
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                attested: true,
                digest: 0,
            },
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                attested: true,
                digest: 0,
            },
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                attested: true,
                digest: 0,
            },
        ];

        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        assert_eq!(result.write_class, WriteClass::Committed);
        assert_eq!(result.acks_count, 3);
        assert_eq!(result.quorum_size, 2); // witness mode: 3/2+1=2
        assert!(!result.needs_repair);
        assert_eq!(result.placement_receipts.len(), 3);
        assert_eq!(result.witnesses.len(), 3);
    }

    #[test]
    fn evaluate_rejects_quorum_when_receipt_uncommitted() {
        let p = QuorumWriteProtocol::new(
            QuorumWriteId::new(3),
            TransferTicketId::new(300),
            "obj/full".into(),
            DurabilityMode::QuorumFull,
            NodeId::new(0),
            nodes(3),
            512,
            empty_digest(),
            EpochId::new(1),
        );
        let transfer: Vec<TransferAck> = nodes(3)
            .into_iter()
            .enumerate()
            .map(|(chunk_index, target)| TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: chunk_index as u64,
                target,
                received_digest: empty_digest(),
                digest_ok: true,
            })
            .collect();
        let commit = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: false,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                placement_receipt_id: WriteReceiptId::new(3),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witness: Vec<WitnessAck> = nodes(3)
            .into_iter()
            .map(|target| WitnessAck {
                ticket_id: p.ticket_id,
                target,
                attested: true,
                digest: 0,
            })
            .collect();

        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.acks_count, 2);
        assert_eq!(
            result.placement_receipts,
            vec![WriteReceiptId::new(1), WriteReceiptId::new(3)]
        );
    }

    #[test]
    fn evaluate_refuses_when_1_of_3_ack() {
        let p = basic_protocol();
        let transfer = vec![TransferAck {
            ticket_id: p.ticket_id,
            chunk_index: 0,
            target: NodeId::new(1),
            received_digest: empty_digest(),
            digest_ok: true,
        }];
        let commit = vec![CommitAck {
            ticket_id: p.ticket_id,
            target: NodeId::new(1),
            placement_receipt_id: WriteReceiptId::new(1),
            receipt_committed: true,
            digest: 0,
        }];
        let witness = vec![WitnessAck {
            ticket_id: p.ticket_id,
            target: NodeId::new(1),
            attested: true,
            digest: 0,
        }];

        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.acks_count, 1);
        assert!(!result.needs_repair);
    }

    #[test]
    fn evaluate_degraded_when_committed_quorum_short_of_targets() {
        let p = basic_protocol();
        let transfer: Vec<TransferAck> = nodes(2)
            .into_iter()
            .enumerate()
            .map(|(chunk_index, target)| TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: chunk_index as u64,
                target,
                received_digest: empty_digest(),
                digest_ok: true,
            })
            .collect();
        let commit = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witness: Vec<WitnessAck> = nodes(2)
            .into_iter()
            .map(|target| WitnessAck {
                ticket_id: p.ticket_id,
                target,
                attested: true,
                digest: 0,
            })
            .collect();

        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        assert_eq!(result.write_class, WriteClass::DegradedCommitted);
        assert_eq!(result.acks_count, 2);
        assert!(result.needs_repair);
    }

    #[test]
    fn evaluate_refused_when_0_ack() {
        let p = basic_protocol();
        let transfer: Vec<TransferAck> = vec![];
        let commit: Vec<CommitAck> = vec![];
        let witness: Vec<WitnessAck> = vec![];

        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.acks_count, 0);
        assert!(!result.needs_repair);
    }

    // ------- Full protocol execution (Algorithm 6) --------------------

    #[test]
    fn full_protocol_3_of_3_healthy_committed() {
        let targets = nodes(3);
        let result = execute_full_quorum_write(
            QuorumWriteId::new(1),
            TransferTicketId::new(100),
            "obj/1",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            1024,
            full_digest(),
            EpochId::new(1),
            &all_capacity(&targets, true),
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"payload_data",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        assert_eq!(result.write_class, WriteClass::Committed);
        assert_eq!(result.acks_count, 3);
        assert!(!result.needs_repair);
        assert!(result.digests_matched);
    }

    #[test]
    fn full_protocol_1_target_no_capacity_refused() {
        let targets = nodes(3);
        let mut capacities = all_capacity(&targets, true);
        capacities[1] = (NodeId::new(2), false); // target 2 no capacity
        capacities[2] = (NodeId::new(3), false); // target 3 no capacity

        let result = execute_full_quorum_write(
            QuorumWriteId::new(2),
            TransferTicketId::new(200),
            "obj/2",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            512,
            empty_digest(),
            EpochId::new(1),
            &capacities,
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"payload",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.acks_count, 1); // only target 1
        assert!(!result.needs_repair);
    }

    #[test]
    fn full_protocol_all_refused_on_capacity() {
        let targets = nodes(3);
        let capacities = all_capacity(&targets, false);

        let result = execute_full_quorum_write(
            QuorumWriteId::new(3),
            TransferTicketId::new(300),
            "obj/3",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            256,
            empty_digest(),
            EpochId::new(1),
            &capacities,
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"payload",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.acks_count, 0);
    }

    #[test]
    fn full_protocol_epoch_mismatch_refused() {
        let targets = nodes(3);
        let mut epochs = all_epoch(&targets, EpochId::new(1));
        epochs[0] = (NodeId::new(1), EpochId::new(2));
        epochs[1] = (NodeId::new(2), EpochId::new(3));
        epochs[2] = (NodeId::new(3), EpochId::new(4));

        let result = execute_full_quorum_write(
            QuorumWriteId::new(4),
            TransferTicketId::new(400),
            "obj/4",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            256,
            empty_digest(),
            EpochId::new(1),
            &all_capacity(&targets, true),
            &epochs,
            &[NodeId::new(0)],
            b"payload",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
    }

    #[test]
    fn full_protocol_quorum_full_mode_requires_all_3() {
        let targets = nodes(3);
        let mut capacities = all_capacity(&targets, true);
        capacities[2] = (NodeId::new(3), false); // only 2 of 3 have capacity

        let result = execute_full_quorum_write(
            QuorumWriteId::new(5),
            TransferTicketId::new(500),
            "obj/5",
            DurabilityMode::QuorumFull,
            NodeId::new(0),
            &targets,
            1024,
            full_digest(),
            EpochId::new(1),
            &capacities,
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"payload",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        // QuorumFull requires 3 committed receipts, and only 2 were committed.
        assert_eq!(result.write_class, WriteClass::RefusedNoQuorum);
        assert_eq!(result.quorum_size, 3);
    }

    // ------- Degraded read (Algorithm 7) ------------------------------

    #[test]
    fn degraded_read_exact_from_primary() {
        let targets = nodes(3);
        let replicas = vec![
            (NodeId::new(1), Some(b"primary_data".to_vec())),
            (NodeId::new(2), Some(b"secondary_data".to_vec())),
        ];
        let (class, data, tried) = execute_degraded_read(&targets, &replicas);
        assert_eq!(class, ReadClass::Exact);
        assert_eq!(data, Some(b"primary_data".to_vec()));
        assert_eq!(tried.len(), 1);
    }

    #[test]
    fn degraded_read_degraded_when_primary_missing() {
        let targets = nodes(3);
        let replicas = vec![
            (NodeId::new(1), None),
            (NodeId::new(2), Some(b"fallback_data".to_vec())),
        ];
        let (class, data, tried) = execute_degraded_read(&targets, &replicas);
        assert_eq!(class, ReadClass::DegradedButValid);
        assert_eq!(data, Some(b"fallback_data".to_vec()));
        assert_eq!(tried.len(), 2);
    }

    #[test]
    fn degraded_read_unavailable_when_no_replica_has_data() {
        let targets = nodes(2);
        let replicas = vec![(NodeId::new(1), None), (NodeId::new(2), None)];
        let (class, data, tried) = execute_degraded_read(&targets, &replicas);
        assert_eq!(class, ReadClass::Unavailable);
        assert!(data.is_none());
        assert_eq!(tried.len(), 2);
    }

    // ------- Build summary (Algorithm 8) ------------------------------

    #[test]
    fn build_summary_for_committed_write() {
        let p = basic_protocol();
        let prepare = vec![
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
        ];
        let transfer = vec![
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 0,
                target: NodeId::new(1),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 1,
                target: NodeId::new(2),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 2,
                target: NodeId::new(3),
                received_digest: empty_digest(),
                digest_ok: true,
            },
        ];
        let commit = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                placement_receipt_id: WriteReceiptId::new(3),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witness = vec![
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                attested: true,
                digest: 0,
            },
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                attested: true,
                digest: 0,
            },
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(3),
                attested: true,
                digest: 0,
            },
        ];
        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);

        let summary = build_quorum_write_summary(&result, &prepare, &transfer, &commit, &witness);
        assert_eq!(summary.write_class, WriteClass::Committed);
        assert_eq!(summary.target_records.len(), 3);
        assert_eq!(summary.acks_at_commit, 3);
        assert_eq!(summary.acks_at_witness, 3);
        assert!(!summary.degraded);
        assert!(!summary.refused);
        // All targets: prepare_accepted, transfer_acked, commit_acked, witness_attested
        for rec in &summary.target_records {
            assert!(rec.prepare_accepted);
            assert!(rec.transfer_acked);
            assert!(rec.transfer_digest_ok);
            assert!(rec.commit_acked);
            assert!(rec.witness_attested);
        }
    }

    #[test]
    fn build_summary_for_refused_write_has_refusal_reasons() {
        let p = basic_protocol();
        let prepare = vec![PrepareResponse {
            ticket_id: p.ticket_id,
            target: NodeId::new(1),
            accepted: false,
            reason_if_refused: Some(RefusalReason::NoCapacity),
            digest: 0,
        }];
        let transfer: Vec<TransferAck> = vec![];
        let commit: Vec<CommitAck> = vec![];
        let witness: Vec<WitnessAck> = vec![];
        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);

        let summary = build_quorum_write_summary(&result, &prepare, &transfer, &commit, &witness);
        assert!(summary.refused);
        assert_eq!(summary.target_records.len(), 1);
        assert_eq!(
            summary.target_records[0].prepare_refusal_reason,
            Some(RefusalReason::NoCapacity)
        );
    }

    // ------- Validate invariants (Algorithm 9) ------------------------

    #[test]
    fn validate_passes_for_clean_committed() {
        let p = basic_protocol();
        let transfer = vec![
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 0,
                target: NodeId::new(1),
                received_digest: empty_digest(),
                digest_ok: true,
            },
            TransferAck {
                ticket_id: p.ticket_id,
                chunk_index: 1,
                target: NodeId::new(2),
                received_digest: empty_digest(),
                digest_ok: true,
            },
        ];
        let commit = vec![
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                placement_receipt_id: WriteReceiptId::new(1),
                receipt_committed: true,
                digest: 0,
            },
            CommitAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                placement_receipt_id: WriteReceiptId::new(2),
                receipt_committed: true,
                digest: 0,
            },
        ];
        let witness = vec![
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                attested: true,
                digest: 0,
            },
            WitnessAck {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                attested: true,
                digest: 0,
            },
        ];
        let result = evaluate_quorum_result(&p, &transfer, &commit, &witness);
        let prepare = vec![
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(1),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
            PrepareResponse {
                ticket_id: p.ticket_id,
                target: NodeId::new(2),
                accepted: true,
                reason_if_refused: None,
                digest: 0,
            },
        ];
        let summary = build_quorum_write_summary(&result, &prepare, &transfer, &commit, &witness);

        let violations = validate_quorum_invariants(&result, &summary);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn validate_detects_committed_with_insufficient_acks() {
        // Manually construct an invalid result
        let result = QuorumWriteResult {
            write_id: QuorumWriteId::new(1),
            ticket_id: TransferTicketId::new(100),
            object_key: "obj".into(),
            write_class: WriteClass::Committed,
            acks_count: 1, // Should be >= 2 for quorum
            target_count: 3,
            quorum_size: 2,
            durability_mode: DurabilityMode::QuorumWitness,
            placement_receipts: vec![WriteReceiptId::new(1)],
            witnesses: vec![NodeId::new(1)],
            needs_repair: false,
            digests_matched: true,
            digest: 0,
        };
        let summary = QuorumWriteSummary {
            write_id: QuorumWriteId::new(1),
            write_class: WriteClass::Committed,
            target_records: vec![],
            acks_at_commit: 1,
            acks_at_witness: 1,
            min_quorum: 2,
            degraded: false,
            refused: false,
        };
        let violations = validate_quorum_invariants(&result, &summary);
        assert!(!violations.is_empty());
        assert!(violations.iter().any(|v| v.contains("Committed but acks")));
    }

    // ------- Edge cases -----------------------------------------------

    #[test]
    fn single_target_with_quorum_witness() {
        let targets = vec![NodeId::new(1)];
        let result = execute_full_quorum_write(
            QuorumWriteId::new(10),
            TransferTicketId::new(1000),
            "obj/single",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            64,
            empty_digest(),
            EpochId::new(1),
            &all_capacity(&targets, true),
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"data",
            &all_capacity(&targets, true),
            &all_capacity(&targets, true),
        );
        assert_eq!(result.write_class, WriteClass::Committed); // min_quorum for 1 target is 1
        assert_eq!(result.acks_count, 1);
    }

    #[test]
    fn digest_mismatch_on_one_target_is_degraded_when_quorum_met() {
        let targets = nodes(3);
        let mut digest_ok = all_capacity(&targets, true);
        digest_ok[2] = (NodeId::new(3), false); // target 3 digest mismatch

        let result = execute_full_quorum_write(
            QuorumWriteId::new(11),
            TransferTicketId::new(1100),
            "obj/digest",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            256,
            empty_digest(),
            EpochId::new(1),
            &all_capacity(&targets, true),
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"data",
            &digest_ok,
            &all_capacity(&targets, true),
        );
        // 2 of 3 digest OK → commit acks = 2, quorum_witness min = 2.
        assert_eq!(result.write_class, WriteClass::DegradedCommitted);
        assert_eq!(result.acks_count, 2);
        assert!(result.needs_repair);
        assert!(!result.digests_matched); // one mismatch
    }

    #[test]
    fn witness_disagreement_does_not_affect_write_class() {
        let targets = nodes(3);
        let mut witnesses = all_capacity(&targets, true);
        witnesses[2] = (NodeId::new(3), false); // target 3 does not attest

        let result = execute_full_quorum_write(
            QuorumWriteId::new(12),
            TransferTicketId::new(1200),
            "obj/witness",
            DurabilityMode::QuorumWitness,
            NodeId::new(0),
            &targets,
            256,
            empty_digest(),
            EpochId::new(1),
            &all_capacity(&targets, true),
            &all_epoch(&targets, EpochId::new(1)),
            &[NodeId::new(0)],
            b"data",
            &all_capacity(&targets, true),
            &witnesses,
        );
        // All 3 commit, 2 witness attest → Committed
        assert_eq!(result.write_class, WriteClass::Committed);
        assert_eq!(result.witnesses.len(), 2);
        assert_eq!(result.acks_count, 3);
    }

    #[test]
    fn write_class_as_str_is_correct() {
        assert_eq!(WriteClass::Committed.as_str(), "committed");
        assert_eq!(WriteClass::DegradedCommitted.as_str(), "degraded_committed");
        assert_eq!(WriteClass::RefusedNoQuorum.as_str(), "refused_no_quorum");
    }

    #[test]
    fn refusal_reason_as_str_is_correct() {
        assert_eq!(RefusalReason::NoCapacity.as_str(), "no_capacity");
        assert_eq!(RefusalReason::WrongEpoch.as_str(), "wrong_epoch");
        assert_eq!(RefusalReason::NotAuthorized.as_str(), "not_authorized");
        assert_eq!(RefusalReason::DigestMismatch.as_str(), "digest_mismatch");
        assert_eq!(RefusalReason::Timeout.as_str(), "timeout");
    }
}
