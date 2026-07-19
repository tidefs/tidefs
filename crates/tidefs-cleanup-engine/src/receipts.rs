// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cleanup-engine replay decision receipts.
//!
//! These records describe the cleanup engine's per-entry replay decision:
//! the queue entry observed, the work kind, the authority evidence the engine
//! required for that decision, the decision reason, the validation tier of
//! that evidence, and an optional artifact digest supplied by callers.
//!
//! A receipt is engine decision evidence only. It does not prove that the
//! cleanup queue root replayed end to end or that runtime reclaim was crash
//! safe across a mounted filesystem workload.

use std::fmt;

use tidefs_types_deferred_cleanup_core::{CleanupWorkItemV1, WorkItemKind};

const RECEIPT_MAGIC: [u8; 8] = *b"CLNRPLY1";
const RECEIPT_NO_EVIDENCE: u8 = u8::MAX;
const RECEIPT_ARTIFACT_ABSENT: u8 = 0;
const RECEIPT_ARTIFACT_PRESENT: u8 = 1;

/// Length of the optional artifact digest carried by replay receipts.
pub const CLEANUP_REPLAY_ARTIFACT_DIGEST_LEN: usize = 32;

/// Cleanup replay action selected for one queue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CleanupReplayDecision {
    /// The engine invoked an executor and accepted a completed outcome.
    Executed = 0,
    /// The engine intentionally skipped the entry using queue/cursor evidence.
    Skipped = 1,
    /// The engine deferred the entry for a later cycle.
    Deferred = 2,
    /// The engine rejected the entry after a fatal executor outcome.
    Rejected = 3,
}

impl CleanupReplayDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::Skipped => "skipped",
            Self::Deferred => "deferred",
            Self::Rejected => "rejected",
        }
    }

    /// Returns true when the decision keeps the entry within normal replay
    /// acceptance rather than rejecting it as fatal.
    #[must_use]
    pub const fn is_accepted(self) -> bool {
        !matches!(self, Self::Rejected)
    }

    const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for CleanupReplayDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Machine-readable evidence kind required for a replay decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CleanupReplayRequiredEvidence {
    /// The queue entry was already marked complete.
    QueueCompletionFlag = 0,
    /// The engine progress cursor already covered this entry id.
    ProgressCursor = 1,
    /// The executor returned `Completed`.
    ExecutorCompleted = 2,
    /// The executor returned `Incomplete`.
    ExecutorIncomplete = 3,
    /// The executor returned a retryable error.
    ExecutorRetryable = 4,
    /// The executor returned a fatal error.
    ExecutorFatal = 5,
}

impl CleanupReplayRequiredEvidence {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueCompletionFlag => "queue-completion-flag",
            Self::ProgressCursor => "progress-cursor",
            Self::ExecutorCompleted => "executor-completed",
            Self::ExecutorIncomplete => "executor-incomplete",
            Self::ExecutorRetryable => "executor-retryable",
            Self::ExecutorFatal => "executor-fatal",
        }
    }

    const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for CleanupReplayRequiredEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Tier of evidence represented by a replay receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CleanupReplayValidationTier {
    /// Evidence came from the cleanup queue entry itself.
    QueueEntry = 0,
    /// Evidence came from cleanup-engine cursor/retry state.
    EngineState = 1,
    /// Evidence came from an executor outcome observed by the engine.
    ExecutorOutcome = 2,
}

impl CleanupReplayValidationTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::QueueEntry => "queue-entry",
            Self::EngineState => "engine-state",
            Self::ExecutorOutcome => "executor-outcome",
        }
    }

    const fn code(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for CleanupReplayValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validation errors for cleanup replay decision receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupReplayReceiptError {
    /// A receipt omitted the evidence required to justify the decision.
    MissingRequiredEvidence {
        entry_id: u64,
        decision: CleanupReplayDecision,
    },
    /// The receipt was produced for an older work-item generation.
    StaleEntryGeneration {
        entry_id: u64,
        receipt_generation: u64,
        current_generation: u64,
    },
    /// The decision reason was empty or whitespace only.
    EmptyDecisionReason { entry_id: u64 },
    /// The decision reason was too generic to be useful evidence.
    GenericDecisionReason { entry_id: u64, reason: String },
    /// The decision reason cannot fit in the deterministic receipt format.
    DecisionReasonTooLong { entry_id: u64, len: usize },
}

impl fmt::Display for CleanupReplayReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredEvidence { entry_id, decision } => {
                write!(
                    f,
                    "cleanup replay receipt for entry {entry_id} has no required evidence for {decision}"
                )
            }
            Self::StaleEntryGeneration {
                entry_id,
                receipt_generation,
                current_generation,
            } => {
                write!(
                    f,
                    "cleanup replay receipt for entry {entry_id} has stale generation {receipt_generation}, current generation is {current_generation}"
                )
            }
            Self::EmptyDecisionReason { entry_id } => {
                write!(
                    f,
                    "cleanup replay receipt for entry {entry_id} has an empty reason"
                )
            }
            Self::GenericDecisionReason { entry_id, reason } => {
                write!(
                    f,
                    "cleanup replay receipt for entry {entry_id} has a generic reason: {reason}"
                )
            }
            Self::DecisionReasonTooLong { entry_id, len } => {
                write!(
                    f,
                    "cleanup replay receipt for entry {entry_id} reason is too long: {len} bytes"
                )
            }
        }
    }
}

impl std::error::Error for CleanupReplayReceiptError {}

/// Per-entry cleanup-engine replay decision receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupReplayDecisionReceipt {
    /// Cleanup queue entry id that the engine observed.
    pub entry_id: u64,
    /// Work-item generation bound into the receipt.
    ///
    /// For current cleanup work items this is the enqueue commit group,
    /// `CleanupWorkItemV1::created_commit_group`.
    pub entry_generation: u64,
    /// Deferred cleanup work kind.
    pub work_kind: WorkItemKind,
    /// Engine replay decision.
    pub decision: CleanupReplayDecision,
    /// Authority evidence required for the decision.
    pub required_evidence: Option<CleanupReplayRequiredEvidence>,
    /// Machine-auditable reason for the decision.
    pub decision_reason: String,
    /// Validation tier represented by the required evidence.
    pub validation_tier: CleanupReplayValidationTier,
    /// Optional digest of an external validation artifact.
    pub artifact_digest: Option<[u8; CLEANUP_REPLAY_ARTIFACT_DIGEST_LEN]>,
}

impl CleanupReplayDecisionReceipt {
    /// Build a receipt for a cleanup queue entry.
    #[must_use]
    pub fn new(
        entry_id: u64,
        entry_generation: u64,
        work_kind: WorkItemKind,
        decision: CleanupReplayDecision,
        required_evidence: Option<CleanupReplayRequiredEvidence>,
        decision_reason: impl Into<String>,
        validation_tier: CleanupReplayValidationTier,
    ) -> Self {
        Self {
            entry_id,
            entry_generation,
            work_kind,
            decision,
            required_evidence,
            decision_reason: decision_reason.into(),
            validation_tier,
            artifact_digest: None,
        }
    }

    /// Build a receipt using fields already present on the work item.
    #[must_use]
    pub fn for_item(
        entry_id: u64,
        item: &CleanupWorkItemV1,
        decision: CleanupReplayDecision,
        required_evidence: CleanupReplayRequiredEvidence,
        decision_reason: impl Into<String>,
        validation_tier: CleanupReplayValidationTier,
    ) -> Self {
        Self::new(
            entry_id,
            item.created_commit_group,
            item.kind,
            decision,
            Some(required_evidence),
            decision_reason,
            validation_tier,
        )
    }

    /// Attach a caller-supplied artifact digest.
    #[must_use]
    pub fn with_artifact_digest(
        mut self,
        artifact_digest: [u8; CLEANUP_REPLAY_ARTIFACT_DIGEST_LEN],
    ) -> Self {
        self.artifact_digest = Some(artifact_digest);
        self
    }

    /// Validate this receipt against the current generation for the entry.
    pub fn validate(&self, current_entry_generation: u64) -> Result<(), CleanupReplayReceiptError> {
        if self.entry_generation != current_entry_generation {
            return Err(CleanupReplayReceiptError::StaleEntryGeneration {
                entry_id: self.entry_id,
                receipt_generation: self.entry_generation,
                current_generation: current_entry_generation,
            });
        }

        if self.required_evidence.is_none() {
            return Err(CleanupReplayReceiptError::MissingRequiredEvidence {
                entry_id: self.entry_id,
                decision: self.decision,
            });
        }

        let reason = self.decision_reason.trim();
        if reason.is_empty() {
            return Err(CleanupReplayReceiptError::EmptyDecisionReason {
                entry_id: self.entry_id,
            });
        }
        if is_generic_reason(reason) {
            return Err(CleanupReplayReceiptError::GenericDecisionReason {
                entry_id: self.entry_id,
                reason: self.decision_reason.clone(),
            });
        }

        Ok(())
    }

    /// Deterministically serialize this receipt.
    ///
    /// Format:
    ///
    /// ```text
    /// [0..8)    magic "CLNRPLY1"
    /// [8..16)   entry_id u64 LE
    /// [16..24)  entry_generation u64 LE
    /// [24]      work_kind u8
    /// [25]      decision u8
    /// [26]      required_evidence u8, or 0xff when absent
    /// [27]      validation_tier u8
    /// [28..30)  decision_reason length u16 LE
    /// [30..N)   UTF-8 decision_reason bytes
    /// [N]       artifact flag: 0 absent, 1 present
    /// [N+1..]   optional 32-byte artifact digest
    /// ```
    pub fn to_bytes(&self) -> Result<Vec<u8>, CleanupReplayReceiptError> {
        let reason = self.decision_reason.as_bytes();
        let reason_len = u16::try_from(reason.len()).map_err(|_| {
            CleanupReplayReceiptError::DecisionReasonTooLong {
                entry_id: self.entry_id,
                len: reason.len(),
            }
        })?;

        let artifact_len = if self.artifact_digest.is_some() {
            CLEANUP_REPLAY_ARTIFACT_DIGEST_LEN
        } else {
            0
        };
        let mut bytes = Vec::with_capacity(31 + reason.len() + artifact_len);
        bytes.extend_from_slice(&RECEIPT_MAGIC);
        bytes.extend_from_slice(&self.entry_id.to_le_bytes());
        bytes.extend_from_slice(&self.entry_generation.to_le_bytes());
        bytes.push(self.work_kind as u8);
        bytes.push(self.decision.code());
        bytes.push(
            self.required_evidence
                .map_or(RECEIPT_NO_EVIDENCE, CleanupReplayRequiredEvidence::code),
        );
        bytes.push(self.validation_tier.code());
        bytes.extend_from_slice(&reason_len.to_le_bytes());
        bytes.extend_from_slice(reason);
        match self.artifact_digest {
            Some(digest) => {
                bytes.push(RECEIPT_ARTIFACT_PRESENT);
                bytes.extend_from_slice(&digest);
            }
            None => bytes.push(RECEIPT_ARTIFACT_ABSENT),
        }
        Ok(bytes)
    }
}

fn is_generic_reason(reason: &str) -> bool {
    let normalized = reason.trim().to_ascii_lowercase();
    if normalized.len() < 12 {
        return true;
    }
    matches!(
        normalized.as_str(),
        "ok" | "done"
            | "success"
            | "completed"
            | "skipped"
            | "deferred"
            | "rejected"
            | "failed"
            | "failure"
            | "error"
            | "fatal"
            | "retry"
            | "retryable"
            | "incomplete"
            | "processed"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_deferred_cleanup_core::UnresolvedExtentMapRoot;

    fn item(kind: WorkItemKind, generation: u64) -> CleanupWorkItemV1 {
        CleanupWorkItemV1::new(42, kind, generation, UnresolvedExtentMapRoot::EMPTY, 4096)
    }

    fn receipt(decision: CleanupReplayDecision) -> CleanupReplayDecisionReceipt {
        let evidence = match decision {
            CleanupReplayDecision::Executed => CleanupReplayRequiredEvidence::ExecutorCompleted,
            CleanupReplayDecision::Skipped => CleanupReplayRequiredEvidence::ProgressCursor,
            CleanupReplayDecision::Deferred => CleanupReplayRequiredEvidence::ExecutorRetryable,
            CleanupReplayDecision::Rejected => CleanupReplayRequiredEvidence::ExecutorFatal,
        };
        let tier = match decision {
            CleanupReplayDecision::Skipped => CleanupReplayValidationTier::EngineState,
            CleanupReplayDecision::Executed
            | CleanupReplayDecision::Deferred
            | CleanupReplayDecision::Rejected => CleanupReplayValidationTier::ExecutorOutcome,
        };
        CleanupReplayDecisionReceipt::for_item(
            7,
            &item(WorkItemKind::UnlinkFree, 12),
            decision,
            evidence,
            format!("engine recorded {decision} cleanup replay evidence"),
            tier,
        )
    }

    #[test]
    fn validates_each_decision_class() {
        for decision in [
            CleanupReplayDecision::Executed,
            CleanupReplayDecision::Skipped,
            CleanupReplayDecision::Deferred,
            CleanupReplayDecision::Rejected,
        ] {
            receipt(decision).validate(12).unwrap();
        }
    }

    #[test]
    fn rejects_accepted_decision_without_required_evidence() {
        let mut receipt = receipt(CleanupReplayDecision::Executed);
        receipt.required_evidence = None;

        assert!(matches!(
            receipt.validate(12),
            Err(CleanupReplayReceiptError::MissingRequiredEvidence {
                decision: CleanupReplayDecision::Executed,
                ..
            })
        ));
    }

    #[test]
    fn rejects_stale_entry_generation() {
        let result = receipt(CleanupReplayDecision::Executed).validate(13);

        assert!(matches!(
            result,
            Err(CleanupReplayReceiptError::StaleEntryGeneration {
                entry_id: 7,
                receipt_generation: 12,
                current_generation: 13,
            })
        ));
    }

    #[test]
    fn rejects_empty_decision_reason() {
        let mut receipt = receipt(CleanupReplayDecision::Skipped);
        receipt.decision_reason = "   ".to_string();

        assert!(matches!(
            receipt.validate(12),
            Err(CleanupReplayReceiptError::EmptyDecisionReason { entry_id: 7 })
        ));
    }

    #[test]
    fn rejects_generic_decision_reason() {
        let mut receipt = receipt(CleanupReplayDecision::Deferred);
        receipt.decision_reason = "done".to_string();

        assert!(matches!(
            receipt.validate(12),
            Err(CleanupReplayReceiptError::GenericDecisionReason { entry_id: 7, .. })
        ));
    }

    #[test]
    fn serialization_is_deterministic() {
        let receipt = receipt(CleanupReplayDecision::Executed).with_artifact_digest([0x5a; 32]);

        let first = receipt.to_bytes().unwrap();
        let second = receipt.to_bytes().unwrap();

        assert_eq!(first, second);
        assert_eq!(&first[0..8], b"CLNRPLY1");
        assert_eq!(first.last().copied(), Some(0x5a));
    }

    #[test]
    fn serialization_changes_when_decision_changes() {
        let executed = receipt(CleanupReplayDecision::Executed).to_bytes().unwrap();
        let skipped = receipt(CleanupReplayDecision::Skipped).to_bytes().unwrap();

        assert_ne!(executed, skipped);
    }
}
