// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Receipt-bound reclaim runtime evidence for obsolete-location trim gating.

use serde::{Deserialize, Serialize};
use tidefs_reclaim_queue_core::DeadObjectReclaimQueue;
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReceiptPolicy, DeadObjectReplacementReceipt, ObjectKey,
};

/// The isolated runtime row added for issue #999.
pub const RECEIPT_BOUND_RECLAIM_ROW_ID: &str = "receipt-bound-obsolete-location-trim";

/// The primary evidence artifact filename emitted by the runtime row.
pub const RECEIPT_BOUND_RECLAIM_ARTIFACT: &str = "receipt-bound-reclaim-runtime.json";

/// One receipt-bound reclaim runtime row result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundReclaimRuntimeEvidence {
    pub manifest_version: u8,
    pub row_id: String,
    pub source_issue: String,
    pub parent_tracker: String,
    pub parent_tracker_disposition: String,
    pub validation_tier: String,
    pub scenario: String,
    pub stable_committed_txg: u64,
    pub stable_committed_receipt_generation: u64,
    pub cases: Vec<ReceiptBoundReclaimCaseEvidence>,
    pub passed: bool,
}

impl ReceiptBoundReclaimRuntimeEvidence {
    /// Return an error that names every failed case.
    pub fn assert_passed(&self) -> Result<(), String> {
        let failed = self
            .cases
            .iter()
            .filter(|case| !case.passed)
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>();
        if failed.is_empty() && self.passed {
            Ok(())
        } else {
            Err(format!(
                "receipt-bound reclaim row failed: {}",
                failed.join(", ")
            ))
        }
    }
}

/// Per-case evidence distinguishing receipt-safety refusal from other failure
/// classes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundReclaimCaseEvidence {
    pub name: String,
    pub receipt_evidence: String,
    pub expected_decision: String,
    pub actual_decision: String,
    pub refusal_reason: Option<String>,
    pub receipt_facts: ReceiptBoundReclaimReceiptFacts,
    pub publish_accepted: Option<bool>,
    pub queue_depth_after_replay: usize,
    pub receipt_bound_eligible_after_replay: usize,
    pub dequeue_batch_len: usize,
    pub ack_removed: usize,
    pub queue_depth_after_decision: usize,
    pub failure_domain: String,
    pub allocator_path_invoked: bool,
    pub segment_cleaner_path_invoked: bool,
    pub harness_failure: bool,
    pub passed: bool,
}

/// Receipt facts serialized with each row case so refusal evidence can be
/// separated from allocator, segment-cleaner, or harness failures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundReclaimReceiptFacts {
    pub receipt_present: bool,
    pub receipt_epoch: Option<u64>,
    pub receipt_generation: Option<u64>,
    pub receipt_policy: Option<String>,
    pub receipt_policy_well_formed: Option<bool>,
    pub receipt_policy_target_width: Option<u16>,
    pub receipt_target_count: Option<u16>,
    pub receipt_is_synthetic: Option<bool>,
    pub receipt_generation_stable: Option<bool>,
    pub receipt_authorizes_reclaim: Option<bool>,
    pub receipt_authorizes_reclaim_at_stable_generation: Option<bool>,
}

/// Execute the isolated receipt-bound obsolete-location trim row.
#[must_use]
pub fn run_receipt_bound_obsolete_location_trim_gate() -> ReceiptBoundReclaimRuntimeEvidence {
    const STABLE_TXG: u64 = 6;
    const STABLE_RECEIPT_GENERATION: u64 = 1;

    let mut cases = vec![valid_publication_and_replay_case(
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    )];

    cases.push(refused_publish_case(
        "synthetic-receipt-publish-refused",
        0x22,
        synthetic_generation_receipt,
        "generation-zero synthetic receipt rejected before publication",
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));
    cases.push(refused_publish_case(
        "epoch-zero-receipt-publish-refused",
        0x23,
        epoch_zero_receipt,
        "epoch-zero synthetic receipt rejected before publication",
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));
    cases.push(queued_invalid_receipt_case(
        "stale-generation-remains-queued",
        0x24,
        future_generation_receipt,
        "receipt generation is newer than stable committed generation",
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));
    cases.push(queued_invalid_receipt_case(
        "malformed-policy-remains-queued",
        0x25,
        malformed_policy_receipt,
        "replacement receipt redundancy policy is malformed",
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));
    cases.push(queued_invalid_receipt_case(
        "under-width-erasure-remains-queued",
        0x26,
        under_width_erasure_receipt,
        "replacement receipt target count is below redundancy width",
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));
    cases.push(receiptless_replay_case(
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));

    let passed = cases.iter().all(|case| case.passed);
    ReceiptBoundReclaimRuntimeEvidence {
        manifest_version: 2,
        row_id: RECEIPT_BOUND_RECLAIM_ROW_ID.to_string(),
        source_issue: "https://github.com/tidefs/tidefs/issues/999".to_string(),
        parent_tracker: "https://github.com/tidefs/tidefs/issues/676".to_string(),
        parent_tracker_disposition: "narrow regression guard; not by itself a #676 closure claim"
            .to_string(),
        validation_tier: "github-actions-runtime-harness".to_string(),
        scenario: "dead-object queue replay plus strict receipt-bound stable-generation dequeue"
            .to_string(),
        stable_committed_txg: STABLE_TXG,
        stable_committed_receipt_generation: STABLE_RECEIPT_GENERATION,
        cases,
        passed,
    }
}

fn valid_publication_and_replay_case(
    stable_txg: u64,
    stable_generation: u64,
) -> ReceiptBoundReclaimCaseEvidence {
    let key = object_key(0x21);
    let mut queue = DeadObjectReclaimQueue::new();
    assert!(queue.enqueue(entry_without_receipt(key)));
    let receipt = valid_receipt(key);
    let receipt_facts = receipt_facts(key, Some(receipt), stable_generation);
    let publish_accepted = queue.publish_replacement_receipt(&key, receipt);
    let mut queue = replay_queue(queue);

    let queue_depth_after_replay = queue.len();
    let eligible =
        queue.receipt_bound_eligible_count_with_stable_generation(stable_txg, stable_generation);
    let batch =
        queue.dequeue_receipt_bound_batch_with_stable_generation(16, stable_txg, stable_generation);
    let ack_removed = queue.ack_reclaimed(&[key]);
    let queue_depth_after_decision = queue.len();
    let passed = publish_accepted
        && queue_depth_after_replay == 1
        && eligible == 1
        && batch.len() == 1
        && batch[0].object_id == key
        && ack_removed == 1
        && queue_depth_after_decision == 0;

    ReceiptBoundReclaimCaseEvidence {
        name: "durable-valid-replacement-reclaims-after-replay".to_string(),
        receipt_evidence:
            "non-synthetic replicated receipt published before replay and stable generation"
                .to_string(),
        expected_decision: "reclaimed".to_string(),
        actual_decision: if ack_removed == 1 {
            "reclaimed".to_string()
        } else {
            "queued".to_string()
        },
        refusal_reason: None,
        receipt_facts,
        publish_accepted: Some(publish_accepted),
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len: batch.len(),
        ack_removed,
        queue_depth_after_decision,
        failure_domain: "none".to_string(),
        allocator_path_invoked: false,
        segment_cleaner_path_invoked: false,
        harness_failure: false,
        passed,
    }
}

fn refused_publish_case(
    name: &str,
    key_byte: u8,
    receipt_builder: fn(ObjectKey) -> DeadObjectReplacementReceipt,
    reason: &str,
    stable_txg: u64,
    stable_generation: u64,
) -> ReceiptBoundReclaimCaseEvidence {
    let key = object_key(key_byte);
    let mut queue = DeadObjectReclaimQueue::new();
    assert!(queue.enqueue(entry_without_receipt(key)));
    let receipt = receipt_builder(key);
    let receipt_facts = receipt_facts(key, Some(receipt), stable_generation);
    let publish_accepted = queue.publish_replacement_receipt(&key, receipt);
    let mut queue = replay_queue(queue);

    let queue_depth_after_replay = queue.len();
    let eligible =
        queue.receipt_bound_eligible_count_with_stable_generation(stable_txg, stable_generation);
    let batch =
        queue.dequeue_receipt_bound_batch_with_stable_generation(16, stable_txg, stable_generation);
    let ack_removed = if batch.is_empty() {
        0
    } else {
        queue.ack_reclaimed(&[key])
    };
    let queue_depth_after_decision = queue.len();
    let passed = !publish_accepted
        && queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1;

    ReceiptBoundReclaimCaseEvidence {
        name: name.to_string(),
        receipt_evidence: "rejected replacement receipt publication".to_string(),
        expected_decision: "refused".to_string(),
        actual_decision: if ack_removed > 0 {
            "reclaimed".to_string()
        } else if publish_accepted {
            "queued".to_string()
        } else {
            "refused".to_string()
        },
        refusal_reason: Some(reason.to_string()),
        receipt_facts,
        publish_accepted: Some(publish_accepted),
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len: batch.len(),
        ack_removed,
        queue_depth_after_decision,
        failure_domain: "receipt-safety".to_string(),
        allocator_path_invoked: false,
        segment_cleaner_path_invoked: false,
        harness_failure: false,
        passed,
    }
}

fn queued_invalid_receipt_case(
    name: &str,
    key_byte: u8,
    receipt_builder: fn(ObjectKey) -> DeadObjectReplacementReceipt,
    reason: &str,
    stable_txg: u64,
    stable_generation: u64,
) -> ReceiptBoundReclaimCaseEvidence {
    let key = object_key(key_byte);
    let mut queue = DeadObjectReclaimQueue::new();
    let receipt = receipt_builder(key);
    let receipt_facts = receipt_facts(key, Some(receipt), stable_generation);
    assert!(queue.enqueue(entry_with_receipt(key, receipt)));
    let mut queue = replay_queue(queue);

    let queue_depth_after_replay = queue.len();
    let eligible =
        queue.receipt_bound_eligible_count_with_stable_generation(stable_txg, stable_generation);
    let batch =
        queue.dequeue_receipt_bound_batch_with_stable_generation(16, stable_txg, stable_generation);
    let ack_removed = if batch.is_empty() {
        0
    } else {
        queue.ack_reclaimed(&[key])
    };
    let queue_depth_after_decision = queue.len();
    let passed = queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1;

    ReceiptBoundReclaimCaseEvidence {
        name: name.to_string(),
        receipt_evidence: "replayed queued entry with non-authorizing receipt evidence".to_string(),
        expected_decision: "queued".to_string(),
        actual_decision: if queue_depth_after_decision == 1 {
            "queued".to_string()
        } else {
            "reclaimed".to_string()
        },
        refusal_reason: Some(reason.to_string()),
        receipt_facts,
        publish_accepted: None,
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len: batch.len(),
        ack_removed,
        queue_depth_after_decision,
        failure_domain: "receipt-safety".to_string(),
        allocator_path_invoked: false,
        segment_cleaner_path_invoked: false,
        harness_failure: false,
        passed,
    }
}

fn receiptless_replay_case(
    stable_txg: u64,
    stable_generation: u64,
) -> ReceiptBoundReclaimCaseEvidence {
    let key = object_key(0x27);
    let mut queue = DeadObjectReclaimQueue::new();
    assert!(queue.enqueue(entry_without_receipt(key)));
    let mut queue = replay_queue(queue);

    let queue_depth_after_replay = queue.len();
    let eligible =
        queue.receipt_bound_eligible_count_with_stable_generation(stable_txg, stable_generation);
    let batch =
        queue.dequeue_receipt_bound_batch_with_stable_generation(16, stable_txg, stable_generation);
    let ack_removed = if batch.is_empty() {
        0
    } else {
        queue.ack_reclaimed(&[key])
    };
    let queue_depth_after_decision = queue.len();
    let passed = queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1;

    ReceiptBoundReclaimCaseEvidence {
        name: "receiptless-replay-remains-queued".to_string(),
        receipt_evidence: "replayed queued entry without replacement receipt".to_string(),
        expected_decision: "queued".to_string(),
        actual_decision: if queue_depth_after_decision == 1 {
            "queued".to_string()
        } else {
            "reclaimed".to_string()
        },
        refusal_reason: Some("missing replacement receipt evidence".to_string()),
        receipt_facts: receipt_facts(key, None, stable_generation),
        publish_accepted: None,
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len: batch.len(),
        ack_removed,
        queue_depth_after_decision,
        failure_domain: "receipt-safety".to_string(),
        allocator_path_invoked: false,
        segment_cleaner_path_invoked: false,
        harness_failure: false,
        passed,
    }
}

fn receipt_facts(
    key: ObjectKey,
    receipt: Option<DeadObjectReplacementReceipt>,
    stable_generation: u64,
) -> ReceiptBoundReclaimReceiptFacts {
    match receipt {
        Some(receipt) => ReceiptBoundReclaimReceiptFacts {
            receipt_present: true,
            receipt_epoch: Some(receipt.receipt_epoch),
            receipt_generation: Some(receipt.receipt_generation),
            receipt_policy: Some(receipt_policy_label(receipt.redundancy_policy)),
            receipt_policy_well_formed: Some(receipt.redundancy_policy.is_well_formed()),
            receipt_policy_target_width: Some(receipt.redundancy_policy.target_width()),
            receipt_target_count: Some(receipt.target_count),
            receipt_is_synthetic: Some(receipt.is_synthetic()),
            receipt_generation_stable: Some(receipt.receipt_generation <= stable_generation),
            receipt_authorizes_reclaim: Some(receipt.authorizes_reclaim_for(key)),
            receipt_authorizes_reclaim_at_stable_generation: Some(
                receipt.authorizes_reclaim_for_with_stable_generation(key, stable_generation),
            ),
        },
        None => ReceiptBoundReclaimReceiptFacts {
            receipt_present: false,
            receipt_epoch: None,
            receipt_generation: None,
            receipt_policy: None,
            receipt_policy_well_formed: None,
            receipt_policy_target_width: None,
            receipt_target_count: None,
            receipt_is_synthetic: None,
            receipt_generation_stable: None,
            receipt_authorizes_reclaim: None,
            receipt_authorizes_reclaim_at_stable_generation: None,
        },
    }
}

fn receipt_policy_label(policy: DeadObjectReceiptPolicy) -> String {
    match policy {
        DeadObjectReceiptPolicy::Replicated { copies } => format!("replicated:{copies}"),
        DeadObjectReceiptPolicy::Erasure {
            data_shards,
            parity_shards,
        } => format!("erasure:{data_shards}+{parity_shards}"),
    }
}

fn replay_queue(queue: DeadObjectReclaimQueue) -> DeadObjectReclaimQueue {
    let encoded = queue.encode();
    DeadObjectReclaimQueue::decode(&encoded).expect("dead-object queue replay must decode")
}

fn entry_without_receipt(key: ObjectKey) -> DeadObjectEntry {
    DeadObjectEntry::new(key, dataset_uuid(key), 5, true, 5)
}

fn entry_with_receipt(key: ObjectKey, receipt: DeadObjectReplacementReceipt) -> DeadObjectEntry {
    entry_without_receipt(key).with_replacement_receipt(receipt)
}

fn valid_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::replicated(key, 7, 1, 2, 4096, digest_for_key(key))
}

fn synthetic_generation_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::replicated(key, 7, 0, 2, 4096, digest_for_key(key))
}

fn epoch_zero_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::new(
        key,
        0,
        1,
        DeadObjectReceiptPolicy::Replicated { copies: 2 },
        4096,
        digest_for_key(key),
        2,
    )
}

fn future_generation_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::replicated(key, 7, 2, 2, 4096, digest_for_key(key))
}

fn malformed_policy_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::new(
        key,
        7,
        1,
        DeadObjectReceiptPolicy::Replicated { copies: 0 },
        4096,
        digest_for_key(key),
        0,
    )
}

fn under_width_erasure_receipt(key: ObjectKey) -> DeadObjectReplacementReceipt {
    DeadObjectReplacementReceipt::new(
        key,
        7,
        1,
        DeadObjectReceiptPolicy::Erasure {
            data_shards: 2,
            parity_shards: 1,
        },
        4096,
        digest_for_key(key),
        2,
    )
}

fn object_key(byte: u8) -> ObjectKey {
    let mut key = [0u8; 32];
    key[0] = byte;
    ObjectKey(key)
}

fn dataset_uuid(key: ObjectKey) -> [u8; 16] {
    [key.0[0]; 16]
}

fn digest_for_key(key: ObjectKey) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[0] = key.0[0];
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_bound_obsolete_location_trim_gate_passes() {
        let evidence = run_receipt_bound_obsolete_location_trim_gate();
        evidence.assert_passed().expect("row should pass");
        assert_eq!(evidence.manifest_version, 2);
        assert_eq!(evidence.cases.len(), 7);
        assert!(evidence.cases.iter().any(|case| {
            case.name == "durable-valid-replacement-reclaims-after-replay"
                && case.actual_decision == "reclaimed"
                && case
                    .receipt_facts
                    .receipt_authorizes_reclaim_at_stable_generation
                    == Some(true)
        }));
        assert!(evidence.cases.iter().any(|case| {
            case.name == "under-width-erasure-remains-queued"
                && case.actual_decision == "queued"
                && case.receipt_facts.receipt_policy_target_width == Some(3)
                && case.receipt_facts.receipt_target_count == Some(2)
                && case
                    .refusal_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("below redundancy width"))
        }));
        assert!(evidence.cases.iter().any(|case| {
            case.name == "stale-generation-remains-queued"
                && case.receipt_facts.receipt_generation == Some(2)
                && case.receipt_facts.receipt_generation_stable == Some(false)
        }));
    }

    #[test]
    fn receipt_bound_obsolete_location_trim_artifact_serializes() {
        let evidence = run_receipt_bound_obsolete_location_trim_gate();
        let encoded = serde_json::to_vec(&evidence).expect("serialize evidence");
        let decoded: ReceiptBoundReclaimRuntimeEvidence =
            serde_json::from_slice(&encoded).expect("decode evidence");
        assert_eq!(decoded, evidence);
    }
}
