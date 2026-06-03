//! Integration bridge between local-filesystem scrub and scrub-core
//! automatic repair engine.
//!
//! The [`run_scrub_repair_pass`] function runs the detect→record pipeline:
//! it scrubs all inode content via the existing block-level checksum
//! verifier and records each corruption event in a BLAKE3-verified
//! [`ScrubRepairLedger`] with domain-separated validation hashing.
//!
//! In single-copy configurations (current local-filesystem), corrupt
//! blocks are recorded as failures (`repair_failure_count`). When
//! redundant storage becomes available, a [`BlockReconstructor`]
//! implementation can be wired in to attempt automatic reconstruction
//! and writeback, turning failures into successful repairs
//! (`repair_count`).

use tidefs_scrub::scrub_repair::ScrubRepairLedger;

use std::collections::BTreeMap;

use tidefs_local_object_store::SuspectEntry;
use tidefs_scrub::repair_scheduling::{RebakeSchedulingBridge, ScrubToRepairBridge};

use crate::scrub::{ScrubBlockOutcome, ScrubReport, ScrubViolation};

// ---------------------------------------------------------------------------
// run_scrub_repair_pass
// ---------------------------------------------------------------------------

/// Record scrub findings into a BLAKE3-verified validation ledger.
///
/// Each corrupt block found in the scrub report is recorded as a
/// [`ScrubRepairEvent`] with before/after hash information and the
/// block identity. In single-copy mode, all corruptions are recorded
/// as failures since no healthy replica is available for reconstruction.
///
/// When a [`BlockReconstructor`] is available (multi-replica or
/// erasure-coded redundancy), callers should use [`ScrubRepairEngine`]
/// directly to attempt automatic repair and writeback.
#[must_use]
pub fn run_scrub_repair_pass(report: &ScrubReport) -> ScrubRepairLedger {
    let mut ledger = ScrubRepairLedger::new();

    if report.is_clean() {
        return ledger;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for violation in &report.violations {
        let block_address = violation.block_id.inode_id;

        let expected_hash = match &violation.outcome {
            ScrubBlockOutcome::Corrupt { expected, .. } => {
                let mut hash = [0u8; 32];
                let bytes = expected.0.to_le_bytes();
                hash[..8].copy_from_slice(&bytes);
                hash
            }
            ScrubBlockOutcome::Unreadable(_) | ScrubBlockOutcome::NoChecksum => {
                // Record as failure with zero hashes — block cannot be
                // verified or repaired.
                ledger.record_failure(tidefs_scrub::scrub_repair::ScrubRepairEvent {
                    block_address,
                    expected_hash: [0u8; 32],
                    corrupted_hash: [0u8; 32],
                    rebuilt_hash: [0u8; 32],
                    shard_sources: vec![],
                    timestamp_secs: timestamp,
                    success: false,
                    integrity_outcome: None,
                });
                continue;
            }
            ScrubBlockOutcome::Clean => continue,
        };

        // In single-copy mode, all corruption is unrepairable —
        // no healthy replica exists. Record as failure.
        ledger.record_failure(tidefs_scrub::scrub_repair::ScrubRepairEvent {
            block_address,
            expected_hash,
            corrupted_hash: [0u8; 32], // actual corrupt hash not recoverable here
            rebuilt_hash: [0u8; 32],
            shard_sources: vec![],
            timestamp_secs: timestamp,
            success: false,
            integrity_outcome: None,
        });
    }

    ledger
}

// ---------------------------------------------------------------------------
// ScrubRepairSchedule — prioritized repair + rebake scheduling
// ---------------------------------------------------------------------------

/// Result of the scrub-to-repair scheduling pipeline.
///
/// Contains the populated [`ScrubToRepairBridge`] with prioritized repair
/// jobs, the [`RebakeSchedulingBridge`] with EC parity recomputation
/// entries, and the raw suspect entries for audit/replay.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScrubRepairSchedule {
    pub bridge: ScrubToRepairBridge,
    pub rebake: RebakeSchedulingBridge,
    pub suspect_entries: Vec<SuspectEntry>,
}

// ---------------------------------------------------------------------------
// run_scrub_repair_scheduling
// ---------------------------------------------------------------------------

/// Wire scrub findings through the repair scheduling bridge and rebake
/// scheduling bridge.
///
/// Converts every [`ScrubViolation`] in the report into a [`SuspectEntry`],
/// ingests them into a [`ScrubToRepairBridge`] with priority/escalation
/// classification, and generates reclaim-queue rebake entries for payload-
/// corruption findings that require EC parity recomputation.
///
/// In single-copy local-filesystem mode (`replicas_remaining == 0`), all
/// payload corruption is immediately escalated to
/// [`RepairEscalation::Immediate`] since no healthy replica exists.
#[must_use]
#[allow(dead_code)]
pub fn run_scrub_repair_scheduling(report: &ScrubReport) -> ScrubRepairSchedule {
    let mut bridge = ScrubToRepairBridge::new();
    let mut rebake = RebakeSchedulingBridge::new();

    let suspect_entries = convert_violations_to_suspect_entries(report);

    // Single-copy local filesystem: 0 replicas remaining.
    bridge.ingest(&suspect_entries, 0);

    // Generate rebake entries for payload corruption needing EC parity
    // recomputation. In single-copy mode this produces no entries.
    let _rebake_entries = rebake.generate_rebake_entries(&suspect_entries);

    ScrubRepairSchedule {
        bridge,
        rebake,
        suspect_entries,
    }
}

// ---------------------------------------------------------------------------
// convert_violations_to_suspect_entries
// ---------------------------------------------------------------------------

/// Convert [`ScrubReport`] violations into [`SuspectEntry`] format for
/// ingestion by the scheduling bridges.
///
/// Mapping rules:
/// - `locator_id` ← `inode_id`
/// - `segment_id` ← `data_version`
/// - `offset` ← `chunk_index` for chunk corruption, 0 otherwise
/// - `record_type` = 1 for payload corruption, 3 for unreadable
fn convert_violations_to_suspect_entries(report: &ScrubReport) -> Vec<SuspectEntry> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    report
        .violations
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let (record_type, expected_hash, actual_hash) = match &v.outcome {
                ScrubBlockOutcome::Corrupt { expected, actual } => {
                    let mut exp = [0u8; 32];
                    let mut act = [0u8; 32];
                    exp[..8].copy_from_slice(&expected.0.to_le_bytes());
                    act[..8].copy_from_slice(&actual.0.to_le_bytes());
                    (1u8, exp, act)
                }
                ScrubBlockOutcome::Unreadable(_) | ScrubBlockOutcome::NoChecksum => {
                    (3u8, [0u8; 32], [0u8; 32])
                }
                ScrubBlockOutcome::Clean => (0u8, [0u8; 32], [0u8; 32]),
            };

            let offset = match &v.block_id.kind {
                crate::scrub::ScrubBlockKind::ContentChunk { chunk_index } => *chunk_index,
                _ => 0,
            };

            SuspectEntry {
                entry_id: i as u64,
                locator_id: v.block_id.inode_id,
                segment_id: v.block_id.data_version,
                offset,
                record_type,
                expected_hash,
                actual_hash,
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 0,
                timestamp_secs: timestamp,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// dispatch_repair_from_bridge
// ---------------------------------------------------------------------------

/// Dispatch prioritized repair jobs from the [`ScrubToRepairBridge`] through
/// the filesystem repair pipeline.
///
/// Iterates jobs in priority order (Immediate → Urgent → Normal →
/// Background), resolves each into a repair strategy via
/// [`crate::repair::resolve_violation`], and applies the repair through
/// [`crate::repair::apply_one_repair`].
///
/// Repaired jobs are marked resolved in the bridge; failed jobs are
/// escalated and may be marked exhausted after max attempts.
#[allow(dead_code)]
pub fn dispatch_repair_from_bridge(
    bridge: &mut ScrubToRepairBridge,
    state: &mut crate::FileSystemState,
    store: &mut tidefs_local_object_store::LocalObjectStore,
    content_layout_cache: &mut BTreeMap<
        tidefs_types_vfs_core::InodeId,
        crate::records::ContentLayout,
    >,
) -> crate::repair::RepairLog {
    let mut applied_log = crate::repair::RepairLog::new();

    // Snapshot locator IDs to avoid borrow conflicts during mutation.
    let locator_ids: Vec<u64> = bridge
        .prioritized_jobs()
        .iter()
        .map(|j| j.entry.locator_id)
        .collect();

    for locator_id in locator_ids {
        // Look up current job state for this locator.
        let all_jobs: Vec<_> = bridge.prioritized_jobs().into_iter().cloned().collect();
        let job = match all_jobs.iter().find(|j| j.entry.locator_id == locator_id) {
            Some(j) => j.clone(),
            None => continue, // already removed (exhausted)
        };

        let violation = repair_job_to_violation(&job);
        let ctx = crate::repair::ResolverContext {
            redundancy_available: job.replicas_remaining > 0,
        };
        let strategy = crate::repair::resolve_violation(&violation, ctx);

        let entry = crate::repair::RepairEntry {
            block_id: violation.block_id.clone(),
            strategy,
            outcome: crate::repair::RepairOutcome::Skipped,
        };

        let outcome = crate::repair::apply_one_repair(&entry, state, store, content_layout_cache);

        applied_log.record(crate::repair::RepairEntry {
            block_id: entry.block_id,
            strategy: entry.strategy,
            outcome: outcome.clone(),
        });

        // In single-copy mode (replicas_remaining == 0), MarkedCorrupt is
        // data-loss containment, not a repair. Only Truncated and
        // Reconstructed are true repairs. In multi-replica mode the
        // resolver should prefer Reconstruct before MarkCorrupt.
        match &outcome {
            crate::repair::RepairOutcome::Reconstructed { .. }
            | crate::repair::RepairOutcome::Truncated { .. } => {
                bridge.mark_repaired(locator_id);
            }
            crate::repair::RepairOutcome::MarkedCorrupt | crate::repair::RepairOutcome::Skipped => {
                bridge.mark_failed(locator_id);
            }
        }
    }

    applied_log
}

/// Reconstruct a [`ScrubViolation`] from a [`RepairJob`] so the existing
/// repair resolution pipeline can consume it.
fn repair_job_to_violation(job: &tidefs_scrub::repair_scheduling::RepairJob) -> ScrubViolation {
    let entry = &job.entry;
    let kind = if entry.offset > 0 || entry.segment_id > 1 {
        crate::scrub::ScrubBlockKind::ContentChunk {
            chunk_index: entry.offset,
        }
    } else {
        crate::scrub::ScrubBlockKind::InlineContent
    };

    let block_id = crate::scrub::ScrubBlockId {
        inode_id: entry.locator_id,
        data_version: entry.segment_id,
        kind,
    };

    let outcome = if entry.record_type == 1 {
        ScrubBlockOutcome::Corrupt {
            expected: tidefs_local_object_store::IntegrityDigest64(u64::from_le_bytes([
                entry.expected_hash[0],
                entry.expected_hash[1],
                entry.expected_hash[2],
                entry.expected_hash[3],
                entry.expected_hash[4],
                entry.expected_hash[5],
                entry.expected_hash[6],
                entry.expected_hash[7],
            ])),
            actual: tidefs_local_object_store::IntegrityDigest64(u64::from_le_bytes([
                entry.actual_hash[0],
                entry.actual_hash[1],
                entry.actual_hash[2],
                entry.actual_hash[3],
                entry.actual_hash[4],
                entry.actual_hash[5],
                entry.actual_hash[6],
                entry.actual_hash[7],
            ])),
        }
    } else {
        ScrubBlockOutcome::Unreadable("dispatched from suspect log".into())
    };

    ScrubViolation {
        block_id,
        key_hex: format!("{:016x}", entry.locator_id),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::{
        ScrubBlockId, ScrubBlockKind, ScrubBlockOutcome, ScrubReport, ScrubViolation,
    };
    use tidefs_local_object_store::IntegrityDigest64;

    #[test]
    fn clean_report_returns_empty_ledger() {
        let report = ScrubReport::empty();
        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 0);
        assert_eq!(ledger.event_count(), 0);
    }

    #[test]
    fn corrupt_blocks_recorded_as_failures() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 2;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 10,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "000000000000000000000000000000000000000000000000000000000000000a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xCAFE),
                actual: IntegrityDigest64(0xBABE),
            },
        });
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 20,
                data_version: 2,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000014".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xDEAD),
                actual: IntegrityDigest64(0xBEEF),
            },
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 2);
        assert_eq!(ledger.event_count(), 2);
    }

    #[test]
    fn validation_digest_nonzero_for_nonempty() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 1,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(1),
                actual: IntegrityDigest64(2),
            },
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_ne!(ledger.validation_digest(), [0u8; 32]);
    }

    #[test]
    fn unreadable_blocks_recorded_as_failures() {
        let mut report = ScrubReport::empty();
        report.blocks_unreadable = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 99,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000063".into(),
            outcome: ScrubBlockOutcome::Unreadable("disk error".into()),
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_failure_count, 1);
        assert_eq!(ledger.repair_count, 0);
    }

    // ── run_scrub_repair_scheduling tests ──────────────────────────

    #[test]
    fn scheduling_bridge_populated_from_corrupt_report() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 42,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "000000000000000000000000000000000000000000000000000000000000002a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xABCD),
                actual: IntegrityDigest64(0x1234),
            },
        });

        let schedule = run_scrub_repair_scheduling(&report);

        // Bridge has work from the corrupt violation.
        assert!(schedule.bridge.has_work());
        assert_eq!(schedule.bridge.pending_count(), 1);

        // Suspect entries are populated.
        assert_eq!(schedule.suspect_entries.len(), 1);
        let suspect = &schedule.suspect_entries[0];
        assert_eq!(suspect.locator_id, 42);
        assert_eq!(suspect.record_type, 1u8); // payload corruption

        // Single-copy mode: no rebake entries.
        assert_eq!(schedule.rebake.entries_generated(), 0);
    }

    #[test]
    fn scheduling_bridge_empty_for_clean_report() {
        let report = ScrubReport::empty();
        let schedule = run_scrub_repair_scheduling(&report);

        assert!(!schedule.bridge.has_work());
        assert_eq!(schedule.bridge.pending_count(), 0);
        assert!(schedule.suspect_entries.is_empty());
    }

    #[test]
    fn scheduling_bridge_prioritizes_immediate_in_single_copy() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 2;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 10,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(1),
                actual: IntegrityDigest64(2),
            },
        });
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 20,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "14".into(),
            outcome: ScrubBlockOutcome::Unreadable("io error".into()),
        });

        let schedule = run_scrub_repair_scheduling(&report);

        // In single-copy mode (replicas_remaining=0), both are Immediate.
        let jobs = schedule.bridge.prioritized_jobs();
        assert_eq!(jobs.len(), 2);

        use tidefs_scrub::repair_scheduling::RepairEscalation;
        assert!(jobs
            .iter()
            .all(|j| j.escalation == RepairEscalation::Immediate));
    }

    // ── convert_violations_to_suspect_entries tests ─────────────────

    #[test]
    fn convert_corrupt_violation_to_suspect_entry() {
        let mut report = ScrubReport::empty();
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 100,
                data_version: 3,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 5 },
            },
            key_hex: "64".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xDEADBEEF),
                actual: IntegrityDigest64(0xCAFEBABE),
            },
        });

        let entries = convert_violations_to_suspect_entries(&report);
        assert_eq!(entries.len(), 1);

        let e = &entries[0];
        assert_eq!(e.locator_id, 100);
        assert_eq!(e.segment_id, 3);
        assert_eq!(e.offset, 5);
        assert_eq!(e.record_type, 1u8); // payload corruption
        assert!(!e.resolved);
        assert_eq!(e.repair_attempts, 0);
    }

    #[test]
    fn convert_unreadable_violation_to_suspect_entry() {
        let mut report = ScrubReport::empty();
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 200,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "c8".into(),
            outcome: ScrubBlockOutcome::Unreadable("disk sector bad".into()),
        });

        let entries = convert_violations_to_suspect_entries(&report);
        assert_eq!(entries.len(), 1);

        let e = &entries[0];
        assert_eq!(e.locator_id, 200);
        assert_eq!(e.record_type, 3u8); // unreadable
        assert_eq!(e.expected_hash, [0u8; 32]);
        assert_eq!(e.actual_hash, [0u8; 32]);
    }

    #[test]
    fn convert_empty_report_returns_no_entries() {
        let report = ScrubReport::empty();
        let entries = convert_violations_to_suspect_entries(&report);
        assert!(entries.is_empty());
    }

    // ── repair_job_to_violation tests ──────────────────────────────

    #[test]
    fn repair_job_to_violation_maps_fields() {
        use tidefs_local_object_store::SuspectEntry;

        let suspect = SuspectEntry {
            entry_id: 0,
            locator_id: 77,
            segment_id: 2,
            offset: 3,
            record_type: 1, // corrupt
            expected_hash: {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&0xCAFEu64.to_le_bytes());
                h
            },
            actual_hash: {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&0xBABEu64.to_le_bytes());
                h
            },
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 0,
        };

        use tidefs_scrub::repair_scheduling::RepairJob;
        let job = RepairJob::new(suspect, 0);

        let violation = repair_job_to_violation(&job);
        assert_eq!(violation.block_id.inode_id, 77);
        assert_eq!(violation.block_id.data_version, 2);

        // ContentChunk since offset > 0.
        match &violation.block_id.kind {
            ScrubBlockKind::ContentChunk { chunk_index } => assert_eq!(*chunk_index, 3),
            _ => panic!("expected ContentChunk"),
        }

        match &violation.outcome {
            ScrubBlockOutcome::Corrupt { expected, actual } => {
                assert_eq!(expected.0, 0xCAFE);
                assert_eq!(actual.0, 0xBABE);
            }
            _ => panic!("expected Corrupt outcome"),
        }
    }
}
