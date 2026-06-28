// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Receipt-bound reclaim runtime evidence for obsolete-location trim gating.

use std::{cell::RefCell, collections::BTreeMap, fmt::Write as _};

use serde::{Deserialize, Serialize};
use tidefs_reclaim::{
    ClearanceEvidence, GateDecision, ReclaimConsumerStats, ReclaimGate, SegmentFreer,
    SegmentLiveCounts, SegmentResolver,
};
use tidefs_reclaim_queue_core::DeadObjectReclaimQueue;
use tidefs_segment_cleaner::{drain_receipt_bound_physical_reclaim, PhysicalReclaimConfig};
use tidefs_types_reclaim_queue_core::{
    DeadObjectEntry, DeadObjectReceiptPolicy, DeadObjectReplacementReceipt, ObjectKey,
};

/// The isolated runtime row added for #999 and extended through #1528.
pub const RECEIPT_BOUND_RECLAIM_ROW_ID: &str = "receipt-bound-obsolete-location-trim";

/// The primary evidence artifact filename emitted by the runtime row.
pub const RECEIPT_BOUND_RECLAIM_ARTIFACT: &str = "receipt-bound-reclaim-runtime.json";

const OBSERVED_SEGMENT_ID: u64 = 0x1528;
const CLEARANCE_PIN_EPOCH: u64 = 9;

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
    pub physical_drain: ReceiptBoundPhysicalDrainEvidence,
    pub harness_failure: bool,
    pub passed: bool,
}

/// Physical-drain evidence emitted by the segment-cleaner bridge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundPhysicalDrainEvidence {
    pub physical_drain_invoked: bool,
    pub stats: ReceiptBoundPhysicalDrainStats,
    pub segment_free_invocations: Vec<u64>,
    pub reclaimed_segment_ids: Vec<u64>,
    pub ack_object_ids: Vec<String>,
    pub receipt_present: bool,
    pub receipt_extent_count: usize,
    pub receipt_extents: Vec<ReceiptBoundPhysicalReceiptExtent>,
    pub receipt_deadlist_committed_txg: Option<u64>,
    pub receipt_pin_clearance_epoch: Option<u64>,
    pub gate_checked_object_ids: Vec<String>,
    pub observed_segment_live_count_after_drain: u64,
    pub capacity_debt: ReceiptBoundCapacityDebtEvidence,
}

/// Stable serialization of the reclaim consumer stats available at this
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundPhysicalDrainStats {
    pub entries_processed: usize,
    pub segments_reclaimed: u64,
    pub blocks_freed: u64,
    pub reclaim_queue_depth: usize,
    pub gate_segments_skipped: u64,
    pub gate_extents_denied: u64,
    pub checkpoint_batches: usize,
}

/// Exact segment/object pair recorded in the physical reclaim receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundPhysicalReceiptExtent {
    pub segment_id: u64,
    pub object_key: String,
}

/// Queue/debt counters available before mounted capacity authority wiring.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBoundCapacityDebtEvidence {
    pub dead_object_debt_before_drain: usize,
    pub dead_object_debt_after_drain: usize,
    pub physical_reclaim_objects_freed: u64,
    pub physical_reclaim_segments_freed: usize,
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
    cases.push(replay_lost_receipt_case(
        STABLE_TXG,
        STABLE_RECEIPT_GENERATION,
    ));

    let passed = cases.iter().all(|case| case.passed);
    ReceiptBoundReclaimRuntimeEvidence {
        manifest_version: 3,
        row_id: RECEIPT_BOUND_RECLAIM_ROW_ID.to_string(),
        source_issue: "https://github.com/tidefs/tidefs/issues/1528".to_string(),
        parent_tracker: "https://github.com/tidefs/tidefs/issues/676".to_string(),
        parent_tracker_disposition:
            "narrow physical-drain regression guard; not the next #676 closure boundary"
                .to_string(),
        validation_tier: "github-actions-runtime-harness".to_string(),
        scenario:
            "dead-object queue replay through receipt-bound physical drain and SegmentFreer observer"
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
    let dequeue_batch_len = batch.len();
    let drain = run_observed_physical_drain(&mut queue, key, stable_txg, stable_generation);
    let ack_removed = drain.ack_removed;
    let queue_depth_after_decision = queue.len();
    let harness_failure = drain.harness_failure;
    let physical_drain = drain.physical_drain;
    let allocator_path_invoked = !physical_drain.segment_free_invocations.is_empty();
    let segment_cleaner_path_invoked = !physical_drain.reclaimed_segment_ids.is_empty();
    let passed = publish_accepted
        && queue_depth_after_replay == 1
        && eligible == 1
        && dequeue_batch_len == 1
        && batch[0].object_id == key
        && ack_removed == 1
        && queue_depth_after_decision == 0
        && physical_drain.reclaimed_segment_ids == vec![OBSERVED_SEGMENT_ID]
        && physical_drain.segment_free_invocations == vec![OBSERVED_SEGMENT_ID]
        && physical_drain.receipt_extent_count == 1
        && physical_drain.receipt_present
        && physical_drain.stats.segments_reclaimed == 1
        && physical_drain.stats.blocks_freed == 1
        && physical_drain.capacity_debt.dead_object_debt_before_drain == 1
        && physical_drain.capacity_debt.dead_object_debt_after_drain == 0
        && !harness_failure;

    ReceiptBoundReclaimCaseEvidence {
        name: "durable-valid-replacement-reclaims-after-replay".to_string(),
        receipt_evidence:
            "non-synthetic replicated receipt survived replay and authorized physical drain"
                .to_string(),
        expected_decision: "reclaimed".to_string(),
        actual_decision: if ack_removed == 1 && allocator_path_invoked {
            "reclaimed".to_string()
        } else {
            "queued".to_string()
        },
        refusal_reason: None,
        receipt_facts,
        publish_accepted: Some(publish_accepted),
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len,
        ack_removed,
        queue_depth_after_decision,
        failure_domain: if harness_failure {
            "harness".to_string()
        } else if passed {
            "none".to_string()
        } else {
            "allocator-or-segment-cleaner".to_string()
        },
        allocator_path_invoked,
        segment_cleaner_path_invoked,
        physical_drain,
        harness_failure,
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
    let dequeue_batch_len = batch.len();
    let drain = run_observed_physical_drain(&mut queue, key, stable_txg, stable_generation);
    let ack_removed = drain.ack_removed;
    let queue_depth_after_decision = queue.len();
    let harness_failure = drain.harness_failure;
    let physical_drain = drain.physical_drain;
    let allocator_path_invoked = !physical_drain.segment_free_invocations.is_empty();
    let segment_cleaner_path_invoked = !physical_drain.reclaimed_segment_ids.is_empty();
    let passed = !publish_accepted
        && queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1
        && physical_drain.segment_free_invocations.is_empty()
        && physical_drain.reclaimed_segment_ids.is_empty()
        && !physical_drain.receipt_present
        && physical_drain.stats.entries_processed == 0
        && physical_drain.capacity_debt.dead_object_debt_after_drain == 1
        && !harness_failure;

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
        dequeue_batch_len,
        ack_removed,
        queue_depth_after_decision,
        failure_domain: if harness_failure {
            "harness".to_string()
        } else {
            "receipt-safety".to_string()
        },
        allocator_path_invoked,
        segment_cleaner_path_invoked,
        physical_drain,
        harness_failure,
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
    let dequeue_batch_len = batch.len();
    let drain = run_observed_physical_drain(&mut queue, key, stable_txg, stable_generation);
    let ack_removed = drain.ack_removed;
    let queue_depth_after_decision = queue.len();
    let harness_failure = drain.harness_failure;
    let physical_drain = drain.physical_drain;
    let allocator_path_invoked = !physical_drain.segment_free_invocations.is_empty();
    let segment_cleaner_path_invoked = !physical_drain.reclaimed_segment_ids.is_empty();
    let passed = queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1
        && physical_drain.segment_free_invocations.is_empty()
        && physical_drain.reclaimed_segment_ids.is_empty()
        && !physical_drain.receipt_present
        && physical_drain.stats.entries_processed == 0
        && physical_drain.capacity_debt.dead_object_debt_after_drain == 1
        && !harness_failure;

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
        dequeue_batch_len,
        ack_removed,
        queue_depth_after_decision,
        failure_domain: if harness_failure {
            "harness".to_string()
        } else {
            "receipt-safety".to_string()
        },
        allocator_path_invoked,
        segment_cleaner_path_invoked,
        physical_drain,
        harness_failure,
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
    let dequeue_batch_len = batch.len();
    let drain = run_observed_physical_drain(&mut queue, key, stable_txg, stable_generation);
    let ack_removed = drain.ack_removed;
    let queue_depth_after_decision = queue.len();
    let harness_failure = drain.harness_failure;
    let physical_drain = drain.physical_drain;
    let allocator_path_invoked = !physical_drain.segment_free_invocations.is_empty();
    let segment_cleaner_path_invoked = !physical_drain.reclaimed_segment_ids.is_empty();
    let passed = queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1
        && physical_drain.segment_free_invocations.is_empty()
        && physical_drain.reclaimed_segment_ids.is_empty()
        && !physical_drain.receipt_present
        && physical_drain.stats.entries_processed == 0
        && physical_drain.capacity_debt.dead_object_debt_after_drain == 1
        && !harness_failure;

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
        dequeue_batch_len,
        ack_removed,
        queue_depth_after_decision,
        failure_domain: if harness_failure {
            "harness".to_string()
        } else {
            "receipt-safety".to_string()
        },
        allocator_path_invoked,
        segment_cleaner_path_invoked,
        physical_drain,
        harness_failure,
        passed,
    }
}

fn replay_lost_receipt_case(
    stable_txg: u64,
    stable_generation: u64,
) -> ReceiptBoundReclaimCaseEvidence {
    let key = object_key(0x28);
    let mut pre_replay_queue = DeadObjectReclaimQueue::new();
    assert!(pre_replay_queue.enqueue(entry_without_receipt(key)));
    let receipt = valid_receipt(key);
    let pre_replay_receipt_facts = receipt_facts(key, Some(receipt), stable_generation);
    let publish_accepted = pre_replay_queue.publish_replacement_receipt(&key, receipt);

    let mut queue = DeadObjectReclaimQueue::new();
    assert!(queue.enqueue(entry_without_receipt(key)));
    let mut queue = replay_queue(queue);

    let queue_depth_after_replay = queue.len();
    let eligible =
        queue.receipt_bound_eligible_count_with_stable_generation(stable_txg, stable_generation);
    let batch =
        queue.dequeue_receipt_bound_batch_with_stable_generation(16, stable_txg, stable_generation);
    let dequeue_batch_len = batch.len();
    let drain = run_observed_physical_drain(&mut queue, key, stable_txg, stable_generation);
    let ack_removed = drain.ack_removed;
    let queue_depth_after_decision = queue.len();
    let harness_failure = drain.harness_failure;
    let physical_drain = drain.physical_drain;
    let allocator_path_invoked = !physical_drain.segment_free_invocations.is_empty();
    let segment_cleaner_path_invoked = !physical_drain.reclaimed_segment_ids.is_empty();
    let passed = publish_accepted
        && pre_replay_receipt_facts.receipt_authorizes_reclaim_at_stable_generation == Some(true)
        && queue_depth_after_replay == 1
        && eligible == 0
        && batch.is_empty()
        && ack_removed == 0
        && queue_depth_after_decision == 1
        && physical_drain.segment_free_invocations.is_empty()
        && physical_drain.reclaimed_segment_ids.is_empty()
        && !physical_drain.receipt_present
        && physical_drain.stats.entries_processed == 0
        && physical_drain.capacity_debt.dead_object_debt_after_drain == 1
        && !harness_failure;

    ReceiptBoundReclaimCaseEvidence {
        name: "replay-lost-receipt-remains-queued".to_string(),
        receipt_evidence:
            "valid replacement receipt was published before replay but absent after replay"
                .to_string(),
        expected_decision: "queued".to_string(),
        actual_decision: if queue_depth_after_decision == 1 {
            "queued".to_string()
        } else {
            "reclaimed".to_string()
        },
        refusal_reason: Some("replacement receipt evidence lost across replay".to_string()),
        receipt_facts: receipt_facts(key, None, stable_generation),
        publish_accepted: Some(publish_accepted),
        queue_depth_after_replay,
        receipt_bound_eligible_after_replay: eligible,
        dequeue_batch_len,
        ack_removed,
        queue_depth_after_decision,
        failure_domain: if harness_failure {
            "harness".to_string()
        } else {
            "receipt-safety".to_string()
        },
        allocator_path_invoked,
        segment_cleaner_path_invoked,
        physical_drain,
        harness_failure,
        passed,
    }
}

struct ObservedPhysicalDrain {
    physical_drain: ReceiptBoundPhysicalDrainEvidence,
    ack_removed: usize,
    harness_failure: bool,
}

fn run_observed_physical_drain(
    queue: &mut DeadObjectReclaimQueue,
    key: ObjectKey,
    stable_txg: u64,
    stable_generation: u64,
) -> ObservedPhysicalDrain {
    let debt_before = queue.len();
    let mut resolver = ObservedResolver::default();
    resolver.set(key, OBSERVED_SEGMENT_ID);

    let mut live_counts = SegmentLiveCounts::new();
    live_counts.set_live_count(OBSERVED_SEGMENT_ID, 1);

    let mut freer = ObservedSegmentFreer::default();
    let gate = RecordingAllowGate::new(stable_txg, CLEARANCE_PIN_EPOCH);
    let config = PhysicalReclaimConfig::new(stable_txg, stable_generation, 16);

    match drain_receipt_bound_physical_reclaim(
        queue,
        &resolver,
        &mut freer,
        &mut live_counts,
        &gate,
        &config,
    ) {
        Ok(drain) => {
            let ack_removed = queue.ack_reclaimed(&drain.ack_object_ids);
            let debt_after = queue.len();
            let receipt_present = drain.receipt.is_some();
            let receipt_extent_count = drain.receipt_extent_count();
            let receipt_extents = drain
                .receipt
                .as_ref()
                .map(|receipt| {
                    receipt
                        .freed_segment_extents
                        .iter()
                        .map(|extent| ReceiptBoundPhysicalReceiptExtent {
                            segment_id: extent.segment_id,
                            object_key: object_key_hex(extent.extent_key),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let receipt_deadlist_committed_txg = drain
                .receipt
                .as_ref()
                .map(|receipt| receipt.deadlist_committed_txg);
            let receipt_pin_clearance_epoch = drain
                .receipt
                .as_ref()
                .map(|receipt| receipt.pin_clearance_epoch);
            let gate_checked_object_ids = gate.checked_object_ids();
            let reclaimed_segment_ids = drain.reclaimed_segment_ids;
            let ack_object_ids = drain
                .ack_object_ids
                .iter()
                .copied()
                .map(object_key_hex)
                .collect();
            let stats = drain_stats(drain.stats);
            let physical_reclaim_segments_freed = reclaimed_segment_ids.len();
            let physical_reclaim_objects_freed = stats.blocks_freed;

            ObservedPhysicalDrain {
                physical_drain: ReceiptBoundPhysicalDrainEvidence {
                    physical_drain_invoked: true,
                    stats,
                    segment_free_invocations: freer.freed_segments,
                    reclaimed_segment_ids,
                    ack_object_ids,
                    receipt_present,
                    receipt_extent_count,
                    receipt_extents,
                    receipt_deadlist_committed_txg,
                    receipt_pin_clearance_epoch,
                    gate_checked_object_ids,
                    observed_segment_live_count_after_drain: live_counts
                        .live_count(OBSERVED_SEGMENT_ID),
                    capacity_debt: ReceiptBoundCapacityDebtEvidence {
                        dead_object_debt_before_drain: debt_before,
                        dead_object_debt_after_drain: debt_after,
                        physical_reclaim_objects_freed,
                        physical_reclaim_segments_freed,
                    },
                },
                ack_removed,
                harness_failure: false,
            }
        }
        Err(error) => ObservedPhysicalDrain {
            physical_drain: ReceiptBoundPhysicalDrainEvidence {
                physical_drain_invoked: true,
                stats: ReceiptBoundPhysicalDrainStats::zero(),
                segment_free_invocations: freer.freed_segments,
                reclaimed_segment_ids: Vec::new(),
                ack_object_ids: Vec::new(),
                receipt_present: false,
                receipt_extent_count: 0,
                receipt_extents: Vec::new(),
                receipt_deadlist_committed_txg: None,
                receipt_pin_clearance_epoch: None,
                gate_checked_object_ids: gate.checked_object_ids(),
                observed_segment_live_count_after_drain: live_counts
                    .live_count(OBSERVED_SEGMENT_ID),
                capacity_debt: ReceiptBoundCapacityDebtEvidence {
                    dead_object_debt_before_drain: debt_before,
                    dead_object_debt_after_drain: queue.len(),
                    physical_reclaim_objects_freed: 0,
                    physical_reclaim_segments_freed: 0,
                },
            },
            ack_removed: 0,
            harness_failure: {
                let _ = error.to_string();
                true
            },
        },
    }
}

#[derive(Default)]
struct ObservedResolver {
    by_key: BTreeMap<ObjectKey, u64>,
}

impl ObservedResolver {
    fn set(&mut self, key: ObjectKey, segment_id: u64) {
        self.by_key.insert(key, segment_id);
    }
}

impl SegmentResolver for ObservedResolver {
    type Error = String;

    fn resolve(&self, key: &ObjectKey) -> Result<Option<u64>, Self::Error> {
        Ok(self.by_key.get(key).copied())
    }
}

#[derive(Default)]
struct ObservedSegmentFreer {
    freed_segments: Vec<u64>,
}

impl SegmentFreer for ObservedSegmentFreer {
    type Error = String;

    fn free_segment(&mut self, segment_id: u64) -> Result<(), Self::Error> {
        self.freed_segments.push(segment_id);
        Ok(())
    }
}

struct RecordingAllowGate {
    deadlist_txg: u64,
    pin_epoch: u64,
    checked: RefCell<Vec<ObjectKey>>,
}

impl RecordingAllowGate {
    fn new(deadlist_txg: u64, pin_epoch: u64) -> Self {
        Self {
            deadlist_txg,
            pin_epoch,
            checked: RefCell::new(Vec::new()),
        }
    }

    fn checked_object_ids(&self) -> Vec<String> {
        self.checked
            .borrow()
            .iter()
            .copied()
            .map(object_key_hex)
            .collect()
    }
}

impl ReclaimGate for RecordingAllowGate {
    fn check_extent(&self, extent_key: &ObjectKey) -> GateDecision {
        self.checked.borrow_mut().push(*extent_key);
        GateDecision::Allow(ClearanceEvidence::Verified {
            deadlist_committed_txg: self.deadlist_txg,
            pin_clearance_epoch: self.pin_epoch,
        })
    }
}

impl ReceiptBoundPhysicalDrainStats {
    const fn zero() -> Self {
        Self {
            entries_processed: 0,
            segments_reclaimed: 0,
            blocks_freed: 0,
            reclaim_queue_depth: 0,
            gate_segments_skipped: 0,
            gate_extents_denied: 0,
            checkpoint_batches: 0,
        }
    }
}

fn drain_stats(stats: ReclaimConsumerStats) -> ReceiptBoundPhysicalDrainStats {
    ReceiptBoundPhysicalDrainStats {
        entries_processed: stats.entries_processed,
        segments_reclaimed: stats.segments_reclaimed,
        blocks_freed: stats.blocks_freed,
        reclaim_queue_depth: stats.reclaim_queue_depth,
        gate_segments_skipped: stats.gate_segments_skipped,
        gate_extents_denied: stats.gate_extents_denied,
        checkpoint_batches: stats.checkpoint_batches,
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

fn object_key_hex(key: ObjectKey) -> String {
    let mut out = String::with_capacity(key.0.len() * 2);
    for byte in key.0 {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
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
        assert_eq!(evidence.manifest_version, 3);
        assert_eq!(
            evidence.source_issue,
            "https://github.com/tidefs/tidefs/issues/1528"
        );
        assert_eq!(evidence.cases.len(), 8);
        assert!(evidence.cases.iter().any(|case| {
            case.name == "durable-valid-replacement-reclaims-after-replay"
                && case.actual_decision == "reclaimed"
                && case.allocator_path_invoked
                && case.segment_cleaner_path_invoked
                && case.physical_drain.physical_drain_invoked
                && case.physical_drain.segment_free_invocations == vec![OBSERVED_SEGMENT_ID]
                && case.physical_drain.reclaimed_segment_ids == vec![OBSERVED_SEGMENT_ID]
                && case.physical_drain.receipt_extent_count == 1
                && case.physical_drain.receipt_deadlist_committed_txg == Some(6)
                && case.physical_drain.receipt_pin_clearance_epoch == Some(CLEARANCE_PIN_EPOCH)
                && case.physical_drain.stats.blocks_freed == 1
                && case
                    .physical_drain
                    .capacity_debt
                    .dead_object_debt_after_drain
                    == 0
                && case
                    .receipt_facts
                    .receipt_authorizes_reclaim_at_stable_generation
                    == Some(true)
        }));
        assert!(evidence
            .cases
            .iter()
            .filter(|case| case.name != "durable-valid-replacement-reclaims-after-replay")
            .all(|case| {
                case.physical_drain.physical_drain_invoked
                    && !case.allocator_path_invoked
                    && !case.segment_cleaner_path_invoked
                    && case.physical_drain.segment_free_invocations.is_empty()
                    && case.physical_drain.reclaimed_segment_ids.is_empty()
                    && case
                        .physical_drain
                        .capacity_debt
                        .dead_object_debt_after_drain
                        == 1
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
        assert!(evidence.cases.iter().any(|case| {
            case.name == "replay-lost-receipt-remains-queued"
                && case.publish_accepted == Some(true)
                && case.receipt_facts.receipt_present == false
                && case.actual_decision == "queued"
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
