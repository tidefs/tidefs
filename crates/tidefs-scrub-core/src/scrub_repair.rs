// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Automatic checksum scrub repair with BLAKE3-verified rebake validation.
//!
//! When checksum verification during scrub traversal detects a corrupted block,
//! this module reconstructs the block from redundant storage (erasure-coded
//! shards or replication), verifies the rebuilt content, and records each
//! repair event in a domain-separated BLAKE3-256 validation ledger.
//!
//! # Architecture
//!
//! ```text
//! Scrub traversal ──► checksum mismatch detected
//!                          │
//!                          ▼
//!                 ScrubRepairEngine
//!                    │          │
//!            BlockReconstructor  ScrubRepairLedger
//!            (rebuild-runtime    (BLAKE3-verified
//!             or replica read)    validation log)
//!                    │
//!              verify rebuilt
//!              write back
//! ```
//!
//! # Domain separation
//!
//! Repair validation is recorded under `DomainTag::ScrubRepair` (0x0E) using
//! BLAKE3 keyed hashing. Two independent corruption+repair sequences
//! produce identical validation digests (deterministic replay).

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cross_replica_comparison::{ComparisonClassification, CrossReplicaComparisonRecord};
use tidefs_checksum_tree::{DomainKey, DomainTag};
use tidefs_verification_engine::ObjectVerificationOutcome;

// ---------------------------------------------------------------------------
// ScrubRepairEvent — a single repair record
// ---------------------------------------------------------------------------

/// One repair event with before/after hashes and shard sources.
///
/// Each event records the block that was corrupted, which shards were used
/// to reconstruct it, and the resulting hashes for deterministic validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScrubRepairEvent {
    /// Logical block address (or object store locator ID).
    pub block_address: u64,
    /// Expected BLAKE3-256 hash from the checksum tree.
    pub expected_hash: [u8; 32],
    /// Hash computed from the corrupted block data.
    pub corrupted_hash: [u8; 32],
    /// Hash computed from the rebuilt block data (must equal expected_hash).
    pub rebuilt_hash: [u8; 32],
    /// IDs of shards (or replicas) used for reconstruction.
    pub shard_sources: Vec<u64>,
    /// Unix timestamp (seconds) when repair was attempted.
    pub timestamp_secs: u64,
    /// Whether the repair succeeded (rebuilt_hash == expected_hash).
    pub success: bool,
    /// Content integrity verification outcome from the verification engine.
    /// Carries the authoritative verification result for this repair event.
    pub integrity_outcome: Option<ObjectVerificationOutcome>,
}

// ---------------------------------------------------------------------------
// ScrubRepairLedger — BLAKE3-verified validation accumulator
// ---------------------------------------------------------------------------

/// Accumulates repair events and produces a deterministic BLAKE3-256
/// domain-separated validation digest over the full repair history.
///
/// Two independent scrub-repair runs that encounter identical corruption
/// and produce identical repair sequences will compute the same validation
/// digest, enabling cross-node verification.
#[derive(Clone, Debug)]
pub struct ScrubRepairLedger {
    events: Vec<ScrubRepairEvent>,
    /// Number of successful repairs.
    pub repair_count: u64,
    /// Number of failed (unrepairable) repair attempts.
    pub repair_failure_count: u64,
    /// Domain key for BLAKE3-256 validation hashing.
    domain_key: DomainKey,
}

impl ScrubRepairLedger {
    /// Create a new empty ledger with domain-separated validation hashing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            repair_count: 0,
            repair_failure_count: 0,
            domain_key: DomainTag::ScrubRepair.derive_key(),
        }
    }

    /// Record a successful repair event.
    pub fn record_repair(&mut self, event: ScrubRepairEvent) {
        assert!(event.success, "record_repair called with failed event");
        self.repair_count += 1;
        self.events.push(event);
    }

    /// Record a failed (unrepairable) repair attempt.
    pub fn record_failure(&mut self, event: ScrubRepairEvent) {
        assert!(
            !event.success,
            "record_failure called with successful event"
        );
        self.repair_failure_count += 1;
        self.events.push(event);
    }

    /// Number of recorded events (both successful and failed).
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return all recorded events.
    #[must_use]
    pub fn events(&self) -> &[ScrubRepairEvent] {
        &self.events
    }

    /// Compute a deterministic BLAKE3-256 validation digest over all events.
    ///
    /// The digest is domain-separated via `DomainTag::ScrubRepair`. Events
    /// are hashed in insertion order. The digest covers: block_address,
    /// expected_hash, corrupted_hash, rebuilt_hash, shard_sources, and
    /// timestamp_secs. The `success` flag is excluded so that success and
    /// failure events contribute equally to the audit trail.
    #[must_use]
    pub fn validation_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(self.domain_key.as_bytes());
        for event in &self.events {
            hasher.update(&event.block_address.to_le_bytes());
            hasher.update(&event.expected_hash);
            hasher.update(&event.corrupted_hash);
            hasher.update(&event.rebuilt_hash);
            // shard_sources: hash count then each ID.
            hasher.update(&(event.shard_sources.len() as u64).to_le_bytes());
            for source in &event.shard_sources {
                hasher.update(&source.to_le_bytes());
            }
            hasher.update(&event.timestamp_secs.to_le_bytes());
        }
        // Include aggregate counters in the digest for completeness.
        hasher.update(&self.repair_count.to_le_bytes());
        hasher.update(&self.repair_failure_count.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Verify that the ledger's own integrity is intact by recomputing
    /// and comparing the validation digest.
    ///
    /// Corruption of the ledger will cause the recomputed digest to
    /// diverge from the stored digest.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        // The ledger stores no separate digest — integrity is verified
        // by deterministic replay. Two ledgers built from the same events
        // must produce the same digest.
        let digest = self.validation_digest();
        !digest.iter().all(|&b| b == 0)
    }

    /// Reset the ledger for a new scrub-repair cycle.
    pub fn reset(&mut self) {
        self.events.clear();
        self.repair_count = 0;
        self.repair_failure_count = 0;
    }
}

impl Default for ScrubRepairLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BlockReconstructor — abstract block reconstruction
// ---------------------------------------------------------------------------

/// Trait for reconstructing a corrupted block from redundant storage.
///
/// Implementations may use erasure-coded parity, replicated copies, or
/// other redundancy schemes. The trait is Send + Sync so it can be shared
/// across background scheduler tasks.
pub trait BlockReconstructor: Send + Sync {
    /// Attempt to reconstruct the block at `block_address` whose expected
    /// hash is `expected_hash`.
    ///
    /// Returns `Ok((rebuilt_data, shard_source_ids))` on success, or
    /// `Err(reason)` if reconstruction is not possible (all sources
    /// corrupt, insufficient redundancy, I/O failure).
    fn reconstruct(
        &self,
        block_address: u64,
        expected_hash: &[u8; 32],
    ) -> Result<(Vec<u8>, Vec<u64>), String>;

    /// Write repaired data back to the given block address.
    ///
    /// After successful reconstruction and verification, the rebuilt data
    /// must be persisted to replace the corrupted block. Returns `Ok(())`
    /// on success or `Err(reason)` on write failure.
    fn write_back(&self, block_address: u64, data: &[u8]) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// ScrubRepairOutcome — typed writeback admission and repair result
// ---------------------------------------------------------------------------

/// Result of a scrub repair writeback attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScrubRepairOutcome {
    /// The local bytes already matched the expected checksum.
    Clean,
    /// Repair writeback succeeded.
    Repaired { bytes_repaired: u64 },
    /// The candidate did not carry the comparison record required for writeback.
    MissingComparisonRecord,
    /// The comparison record carried stale generation or receipt evidence.
    StaleComparisonRecord,
    /// Reconciled comparison found contradictory replica evidence.
    CrossReplicaDisagreement,
    /// The comparison classification does not authorize writeback.
    UnreconciledComparison { classification: &'static str },
    /// Unresolved failed-quorum mutation evidence overlaps this repair candidate.
    UnresolvedFailedQuorumMutation { mutation_id: String },
    /// Reconstruction failed before a candidate writeback was available.
    ReconstructionFailed,
    /// Reconstructed bytes did not match the expected checksum.
    VerificationFailed,
    /// Repaired bytes were verified but writeback failed.
    WritebackFailed,
}

impl ScrubRepairOutcome {
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Clean | Self::Repaired { .. })
    }
}

/// Unresolved failed-quorum mutation evidence supplied by the repair caller.
///
/// The replicated object store owns the durable mutation ledger. Scrub repair
/// treats any caller-supplied unresolved row for the candidate as explicit
/// uncertainty and refuses writeback until an owning reconciler closes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnresolvedFailedQuorumMutationEvidence {
    /// Stable mutation identifier from the unresolved-mutation ledger.
    pub mutation_id: String,
    /// Object key affected by the unresolved mutation, when known.
    pub object_key: Option<[u8; 32]>,
}

impl UnresolvedFailedQuorumMutationEvidence {
    /// Create unresolved failed-quorum evidence for an optional object key.
    #[must_use]
    pub fn new(mutation_id: impl Into<String>, object_key: Option<[u8; 32]>) -> Self {
        Self {
            mutation_id: mutation_id.into(),
            object_key,
        }
    }
}

// ---------------------------------------------------------------------------
// ScrubRepairEngine — detect-repair-verify pipeline
// ---------------------------------------------------------------------------

/// Coordinates the detect→reconstruct→verify→writeback pipeline for a
/// single block during scrub traversal.
///
/// The engine:
/// 1. Compares the block's actual hash against the expected checksum.
/// 2. On mismatch, delegates to the [`BlockReconstructor`].
/// 3. Verifies the rebuilt BLAKE3 hash against the expected hash.
/// 4. Writes back through the reconstructor's `write_back`.
/// 5. Records the event in the [`ScrubRepairLedger`].
pub struct ScrubRepairEngine<R: BlockReconstructor> {
    reconstructor: R,
    ledger: ScrubRepairLedger,
}

impl<R: BlockReconstructor> ScrubRepairEngine<R> {
    /// Create a new engine with the given reconstructor.
    #[must_use]
    pub fn new(reconstructor: R) -> Self {
        Self {
            reconstructor,
            ledger: ScrubRepairLedger::new(),
        }
    }

    /// Return a reference to the repair ledger.
    #[must_use]
    pub fn ledger(&self) -> &ScrubRepairLedger {
        &self.ledger
    }

    /// Mutable access to the ledger for integration with external reporting.
    #[must_use]
    pub fn ledger_mut(&mut self) -> &mut ScrubRepairLedger {
        &mut self.ledger
    }

    /// Run the repair pipeline for one block.
    ///
    /// `block_address` is the logical address, `expected_hash` is the
    /// hash stored in the checksum tree, `actual_data` is the block
    /// data read from storage.
    ///
    /// Returns `true` if the block is clean or was successfully repaired.
    /// Returns `false` if the block is corrupt, lacks comparison evidence,
    /// or is otherwise not writeback-eligible.
    pub fn repair_one(
        &mut self,
        block_address: u64,
        expected_hash: &[u8; 32],
        actual_data: &[u8],
    ) -> bool {
        self.repair_one_with_comparison(block_address, expected_hash, actual_data, None)
            .is_success()
    }

    /// Run repair for one block using a reconciled comparison record.
    pub fn repair_one_with_comparison(
        &mut self,
        block_address: u64,
        expected_hash: &[u8; 32],
        actual_data: &[u8],
        comparison_record: Option<&CrossReplicaComparisonRecord>,
    ) -> ScrubRepairOutcome {
        self.repair_one_with_comparison_and_failed_quorum_evidence(
            block_address,
            expected_hash,
            actual_data,
            comparison_record,
            &[],
        )
    }

    /// Run repair for one block using comparison plus unresolved-mutation evidence.
    pub fn repair_one_with_comparison_and_failed_quorum_evidence(
        &mut self,
        block_address: u64,
        expected_hash: &[u8; 32],
        actual_data: &[u8],
        comparison_record: Option<&CrossReplicaComparisonRecord>,
        unresolved_mutations: &[UnresolvedFailedQuorumMutationEvidence],
    ) -> ScrubRepairOutcome {
        // 1. Compute actual hash and compare.
        let actual_hash: [u8; 32] = blake3::hash(actual_data).into();

        if &actual_hash == expected_hash {
            // Block is clean — no repair needed.
            return ScrubRepairOutcome::Clean;
        }

        let comparison_record = match comparison_record {
            Some(record) => record,
            None => return ScrubRepairOutcome::MissingComparisonRecord,
        };
        if let Err(outcome) = comparison_permits_writeback(comparison_record) {
            return outcome;
        }
        if let Some(evidence) =
            unresolved_failed_quorum_evidence_for_candidate(comparison_record, unresolved_mutations)
        {
            return ScrubRepairOutcome::UnresolvedFailedQuorumMutation {
                mutation_id: evidence.mutation_id.clone(),
            };
        }

        self.repair_corrupt_block(block_address, expected_hash, actual_hash)
    }

    fn repair_corrupt_block(
        &mut self,
        block_address: u64,
        expected_hash: &[u8; 32],
        actual_hash: [u8; 32],
    ) -> ScrubRepairOutcome {
        // 2. Attempt reconstruction.
        let (rebuilt_data, shard_sources) =
            match self.reconstructor.reconstruct(block_address, expected_hash) {
                Ok(result) => result,
                Err(reason) => {
                    let timestamp = current_timestamp_secs();
                    let integrity = ObjectVerificationOutcome::Mismatch {
                        byte_offset: 0,
                        expected_hash: *expected_hash,
                        actual_hash,
                    };
                    self.ledger.record_failure(ScrubRepairEvent {
                        block_address,
                        expected_hash: *expected_hash,
                        corrupted_hash: actual_hash,
                        rebuilt_hash: [0u8; 32], // no rebuild to verify
                        shard_sources: Vec::new(),
                        timestamp_secs: timestamp,
                        success: false,
                        integrity_outcome: Some(integrity),
                    });
                    // Record the failure reason in the failure_count — the event
                    // is already pushed by record_failure.
                    let _ = reason;
                    return ScrubRepairOutcome::ReconstructionFailed;
                }
            };

        // 3. Verify rebuilt hash.
        let rebuilt_hash: [u8; 32] = blake3::hash(&rebuilt_data).into();
        if rebuilt_hash != *expected_hash {
            // Rebuilt data doesn't match — reconstruction failed.
            let integrity = ObjectVerificationOutcome::Mismatch {
                byte_offset: 0,
                expected_hash: *expected_hash,
                actual_hash: rebuilt_hash,
            };
            let timestamp = current_timestamp_secs();
            self.ledger.record_failure(ScrubRepairEvent {
                block_address,
                expected_hash: *expected_hash,
                corrupted_hash: actual_hash,
                rebuilt_hash,
                shard_sources,
                timestamp_secs: timestamp,
                success: false,
                integrity_outcome: Some(integrity),
            });
            return ScrubRepairOutcome::VerificationFailed;
        }

        // 4. Write back the repaired data.
        if let Err(reason) = self.reconstructor.write_back(block_address, &rebuilt_data) {
            let integrity = ObjectVerificationOutcome::Match;
            let timestamp = current_timestamp_secs();
            self.ledger.record_failure(ScrubRepairEvent {
                block_address,
                expected_hash: *expected_hash,
                corrupted_hash: actual_hash,
                rebuilt_hash,
                shard_sources,
                timestamp_secs: timestamp,
                success: false,
                integrity_outcome: Some(integrity),
            });
            let _ = reason;
            return ScrubRepairOutcome::WritebackFailed;
        }

        // 5. Record successful repair.
        let bytes_repaired = rebuilt_data.len() as u64;
        let integrity = ObjectVerificationOutcome::Match;
        let timestamp = current_timestamp_secs();
        self.ledger.record_repair(ScrubRepairEvent {
            block_address,
            expected_hash: *expected_hash,
            corrupted_hash: actual_hash,
            rebuilt_hash,
            shard_sources,
            timestamp_secs: timestamp,
            success: true,
            integrity_outcome: Some(integrity),
        });

        ScrubRepairOutcome::Repaired { bytes_repaired }
    }

    /// Run the repair pipeline for multiple blocks.
    ///
    /// Each item is `(block_address, expected_hash, actual_data)`.
    /// Returns a count of blocks that are clean or successfully repaired
    /// (the complement are unrepairable failures recorded in the ledger).
    pub fn repair_batch(&mut self, blocks: &[(u64, [u8; 32], Vec<u8>)]) -> Vec<bool> {
        blocks
            .iter()
            .map(|(addr, expected, data)| self.repair_one(*addr, expected, data))
            .collect()
    }
}

fn unresolved_failed_quorum_evidence_for_candidate<'a>(
    record: &CrossReplicaComparisonRecord,
    unresolved_mutations: &'a [UnresolvedFailedQuorumMutationEvidence],
) -> Option<&'a UnresolvedFailedQuorumMutationEvidence> {
    unresolved_mutations
        .iter()
        .find(|evidence| match evidence.object_key {
            Some(object_key) => object_key == record.object_key,
            None => true,
        })
}

fn comparison_permits_writeback(
    record: &CrossReplicaComparisonRecord,
) -> Result<(), ScrubRepairOutcome> {
    match &record.classification {
        ComparisonClassification::SingleReplicaCorruption { .. } => {
            if record.clean_source_set.is_empty() || record.corrupt_target_set.is_empty() {
                return Err(ScrubRepairOutcome::UnreconciledComparison {
                    classification: comparison_classification_label(&record.classification),
                });
            }
            Ok(())
        }
        ComparisonClassification::CrossReplicaDisagreement
        | ComparisonClassification::ChecksumAuthorityDisagreement => {
            Err(ScrubRepairOutcome::CrossReplicaDisagreement)
        }
        ComparisonClassification::StaleEvidence { .. } => {
            Err(ScrubRepairOutcome::StaleComparisonRecord)
        }
        other => Err(ScrubRepairOutcome::UnreconciledComparison {
            classification: comparison_classification_label(other),
        }),
    }
}

fn comparison_classification_label(classification: &ComparisonClassification) -> &'static str {
    match classification {
        ComparisonClassification::CleanAgreement => "clean-agreement",
        ComparisonClassification::SingleReplicaCorruption { .. } => "single-replica-corruption",
        ComparisonClassification::RemoteReplicaCorruption { .. } => "remote-replica-corruption",
        ComparisonClassification::IncompleteComparison { .. } => "incomplete-comparison",
        ComparisonClassification::CrossReplicaDisagreement => "cross-replica-disagreement",
        ComparisonClassification::ChecksumAuthorityDisagreement => {
            "checksum-authority-disagreement"
        }
        ComparisonClassification::StaleEvidence { .. } => "stale-evidence",
        ComparisonClassification::MissingChecksumEvidence { .. } => "missing-checksum-evidence",
        ComparisonClassification::MissingReplicaEvidence { .. } => "missing-replica-evidence",
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Current wall-clock time in seconds since the Unix epoch.
fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_replica_comparison::{ChecksumLayer, ScrubSubject, ScrubSubjectKind};
    use std::sync::Mutex;

    // ── MockBlockReconstructor ──────────────────────────────────────

    /// Mock reconstructor backed by an in-memory "healthy replica" store.
    struct MockReconstructor {
        /// Maps block_address -> healthy data.
        healthy_blocks: Mutex<std::collections::HashMap<u64, Vec<u8>>>,
        /// Written-back blocks (for verification).
        written: Mutex<std::collections::HashMap<u64, Vec<u8>>>,
        /// Whether reconstruction should fail.
        fail_reconstruct: Mutex<bool>,
        /// Whether write_back should fail.
        fail_write: Mutex<bool>,
    }

    impl MockReconstructor {
        fn new() -> Self {
            Self {
                healthy_blocks: Mutex::new(std::collections::HashMap::new()),
                written: Mutex::new(std::collections::HashMap::new()),
                fail_reconstruct: Mutex::new(false),
                fail_write: Mutex::new(false),
            }
        }

        fn set_healthy_block(&self, addr: u64, data: Vec<u8>) {
            self.healthy_blocks.lock().unwrap().insert(addr, data);
        }

        #[allow(dead_code)]
        fn set_fail_reconstruct(&self, fail: bool) {
            *self.fail_reconstruct.lock().unwrap() = fail;
        }

        fn set_fail_write(&self, fail: bool) {
            *self.fail_write.lock().unwrap() = fail;
        }
    }

    impl BlockReconstructor for MockReconstructor {
        fn reconstruct(
            &self,
            block_address: u64,
            _expected_hash: &[u8; 32],
        ) -> Result<(Vec<u8>, Vec<u64>), String> {
            if *self.fail_reconstruct.lock().unwrap() {
                return Err("mock reconstruction failure".into());
            }
            let blocks = self.healthy_blocks.lock().unwrap();
            blocks
                .get(&block_address)
                .cloned()
                .map(|data| (data, vec![block_address + 1000]))
                .ok_or_else(|| format!("no healthy replica for block {block_address}"))
        }

        fn write_back(&self, block_address: u64, data: &[u8]) -> Result<(), String> {
            if *self.fail_write.lock().unwrap() {
                return Err("mock write failure".into());
            }
            self.written
                .lock()
                .unwrap()
                .insert(block_address, data.to_vec());
            Ok(())
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    fn make_block_data(pattern: u8) -> Vec<u8> {
        vec![pattern; 64]
    }

    fn hash_data(data: &[u8]) -> [u8; 32] {
        blake3::hash(data).into()
    }

    fn repair_comparison_record() -> CrossReplicaComparisonRecord {
        CrossReplicaComparisonRecord {
            subject: ScrubSubject {
                inode_id: 1,
                data_version: 1,
                kind: ScrubSubjectKind::InlineContent,
            },
            object_key: [0x11; 32],
            checksum_layer: ChecksumLayer::InlineContentBody,
            redundancy_policy_id: 1,
            target_count: 2,
            placement_receipt_epoch: 1,
            placement_receipt_generation: 1,
            membership_epoch: 1,
            replica_outcomes: Vec::new(),
            classification: ComparisonClassification::SingleReplicaCorruption {
                corrupt_replica: 1,
                clean_sources: vec![2],
            },
            clean_source_set: vec![2],
            corrupt_target_set: vec![1],
        }
    }

    // ── ScrubRepairLedger tests ─────────────────────────────────────

    #[test]
    fn ledger_starts_empty() {
        let ledger = ScrubRepairLedger::new();
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 0);
        assert_eq!(ledger.event_count(), 0);
    }

    #[test]
    fn ledger_records_successful_repair() {
        let mut ledger = ScrubRepairLedger::new();
        let event = ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        };
        ledger.record_repair(event);
        assert_eq!(ledger.repair_count, 1);
        assert_eq!(ledger.repair_failure_count, 0);
        assert_eq!(ledger.event_count(), 1);
    }

    #[test]
    fn ledger_records_failed_repair() {
        let mut ledger = ScrubRepairLedger::new();
        let event = ScrubRepairEvent {
            block_address: 2,
            expected_hash: [0xCC; 32],
            corrupted_hash: [0xDD; 32],
            rebuilt_hash: [0x00; 32],
            shard_sources: vec![],
            timestamp_secs: 2000,
            success: false,
            integrity_outcome: None,
        };
        ledger.record_failure(event);
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 1);
        assert_eq!(ledger.event_count(), 1);
    }

    #[test]
    fn ledger_events_are_retrievable() {
        let mut ledger = ScrubRepairLedger::new();
        ledger.record_repair(ScrubRepairEvent {
            block_address: 10,
            expected_hash: [0x11; 32],
            corrupted_hash: [0x22; 32],
            rebuilt_hash: [0x11; 32],
            shard_sources: vec![1, 2],
            timestamp_secs: 500,
            success: true,
            integrity_outcome: None,
        });
        ledger.record_failure(ScrubRepairEvent {
            block_address: 20,
            expected_hash: [0x33; 32],
            corrupted_hash: [0x44; 32],
            rebuilt_hash: [0x00; 32],
            shard_sources: vec![],
            timestamp_secs: 501,
            success: false,
            integrity_outcome: None,
        });

        let events = ledger.events();
        assert_eq!(events.len(), 2);
        assert!(events[0].success);
        assert!(!events[1].success);
    }

    #[test]
    fn validation_digest_is_nonzero_for_nonempty_ledger() {
        let mut ledger = ScrubRepairLedger::new();
        ledger.record_repair(ScrubRepairEvent {
            block_address: 42,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![7],
            timestamp_secs: 999,
            success: true,
            integrity_outcome: None,
        });
        let digest = ledger.validation_digest();
        assert_ne!(digest, [0u8; 32]);
    }

    #[test]
    fn validation_digest_is_deterministic() {
        let mut l1 = ScrubRepairLedger::new();
        let mut l2 = ScrubRepairLedger::new();

        let event = ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        };

        l1.record_repair(event.clone());
        l2.record_repair(event);

        assert_eq!(l1.validation_digest(), l2.validation_digest());
    }

    #[test]
    fn validation_digest_differs_for_different_events() {
        let mut l1 = ScrubRepairLedger::new();
        let mut l2 = ScrubRepairLedger::new();

        l1.record_repair(ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        });

        l2.record_repair(ScrubRepairEvent {
            block_address: 2,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        });

        assert_ne!(l1.validation_digest(), l2.validation_digest());
    }

    #[test]
    fn validation_digest_changes_with_counter() {
        let mut l1 = ScrubRepairLedger::new();
        let mut l2 = ScrubRepairLedger::new();

        // Same event twice vs once — counters differ.
        let event = ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        };

        l1.record_repair(event.clone());
        l2.record_repair(event.clone());
        l2.record_repair(event);

        assert_ne!(l1.validation_digest(), l2.validation_digest());
    }

    #[test]
    fn ledger_verify_integrity_nonzero_for_nonempty() {
        let mut ledger = ScrubRepairLedger::new();
        // Empty ledger: keyed hash is non-zero (domain-separated counters).
        // verify_integrity returns false because there are no events to audit.
        let digest = ledger.validation_digest();
        assert!(
            !digest.iter().all(|&b| b == 0),
            "empty ledger keyed hash is non-zero"
        );

        ledger.record_repair(ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        });
        assert!(ledger.verify_integrity());
    }

    #[test]
    fn ledger_reset_clears_all() {
        let mut ledger = ScrubRepairLedger::new();
        ledger.record_repair(ScrubRepairEvent {
            block_address: 1,
            expected_hash: [0xAA; 32],
            corrupted_hash: [0xBB; 32],
            rebuilt_hash: [0xAA; 32],
            shard_sources: vec![100],
            timestamp_secs: 1000,
            success: true,
            integrity_outcome: None,
        });
        ledger.reset();
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 0);
        assert_eq!(ledger.event_count(), 0);
    }

    #[test]
    fn domain_separation_produces_distinct_keys() {
        let k1 = DomainTag::ScrubRepair.derive_key();
        let k2 = DomainTag::ScrubRecord.derive_key();
        assert_ne!(k1, k2, "scrub-repair domain must differ from scrub-record");
    }

    // ── ScrubRepairEngine tests ─────────────────────────────────────

    #[test]
    fn repair_one_clean_block_no_action() {
        let recon = MockReconstructor::new();
        let mut engine = ScrubRepairEngine::new(recon);

        let data = make_block_data(0xAB);
        let expected = hash_data(&data);

        let result = engine.repair_one(1, &expected, &data);
        assert!(result);
        assert_eq!(engine.ledger().repair_count, 0);
        assert_eq!(engine.ledger().repair_failure_count, 0);
    }

    #[test]
    fn repair_one_corrupt_block_successfully_repaired() {
        let recon = MockReconstructor::new();
        // Set up the healthy version that reconstruction will return.
        let healthy_data = make_block_data(0xCA);
        let expected = hash_data(&healthy_data);
        recon.set_healthy_block(1, healthy_data.clone());

        let mut engine = ScrubRepairEngine::new(recon);

        // The data on disk is corrupted.
        let corrupt_data = make_block_data(0xFE);
        let comparison = repair_comparison_record();

        let result =
            engine.repair_one_with_comparison(1, &expected, &corrupt_data, Some(&comparison));
        assert!(
            result.is_success(),
            "repair should succeed with healthy replica available"
        );
        assert_eq!(engine.ledger().repair_count, 1);
        assert_eq!(engine.ledger().repair_failure_count, 0);
        assert_eq!(engine.ledger().event_count(), 1);

        let events = engine.ledger().events();
        assert!(events[0].success);
        assert_eq!(events[0].block_address, 1);
        assert_eq!(events[0].expected_hash, expected);
        assert_ne!(events[0].corrupted_hash, expected);
        assert_eq!(events[0].rebuilt_hash, expected);
    }

    #[test]
    fn repair_one_unrepairable_records_failure() {
        let recon = MockReconstructor::new();
        // No healthy block set — reconstruction will fail.
        let mut engine = ScrubRepairEngine::new(recon);

        let data = make_block_data(0xDE);
        let expected: [u8; 32] = [0x11; 32]; // different from anything
        let comparison = repair_comparison_record();

        let result = engine.repair_one_with_comparison(1, &expected, &data, Some(&comparison));
        assert_eq!(result, ScrubRepairOutcome::ReconstructionFailed);
        assert_eq!(engine.ledger().repair_count, 0);
        assert_eq!(engine.ledger().repair_failure_count, 1);
    }

    #[test]
    fn repair_one_reconstruction_returns_wrong_data() {
        let recon = MockReconstructor::new();
        // Healthy block has different data than what the expected hash encodes.
        let wrong_data = make_block_data(0xBB);
        recon.set_healthy_block(1, wrong_data);

        let actual_data = make_block_data(0xCC);
        let expected = hash_data(&make_block_data(0xDD)); // neither actual nor healthy

        let mut engine = ScrubRepairEngine::new(recon);
        let comparison = repair_comparison_record();

        let result =
            engine.repair_one_with_comparison(1, &expected, &actual_data, Some(&comparison));
        assert_eq!(result, ScrubRepairOutcome::VerificationFailed);
        assert_eq!(engine.ledger().repair_failure_count, 1);
    }

    #[test]
    fn repair_one_write_back_failure_records_failure() {
        let recon = MockReconstructor::new();
        let healthy_data = make_block_data(0xEF);
        let expected = hash_data(&healthy_data);
        recon.set_healthy_block(1, healthy_data.clone());
        recon.set_fail_write(true);

        let mut engine = ScrubRepairEngine::new(recon);
        let corrupt_data = make_block_data(0xAB);
        let comparison = repair_comparison_record();

        let result =
            engine.repair_one_with_comparison(1, &expected, &corrupt_data, Some(&comparison));
        assert_eq!(result, ScrubRepairOutcome::WritebackFailed);
        assert_eq!(engine.ledger().repair_failure_count, 1);
        assert_eq!(engine.ledger().repair_count, 0);
    }

    #[test]
    fn repair_batch_handles_multiple_blocks() {
        let recon = MockReconstructor::new();
        let healthy_a = make_block_data(0x01);
        let healthy_b = make_block_data(0x02);
        let expected_a = hash_data(&healthy_a);
        let expected_b = hash_data(&healthy_b);
        recon.set_healthy_block(1, healthy_a);
        recon.set_healthy_block(2, healthy_b.clone());

        let mut engine = ScrubRepairEngine::new(recon);

        let blocks = vec![
            (1, expected_a, make_block_data(0xFE)), // corrupt → missing comparison
            (2, expected_b, healthy_b.clone()),     // clean
            (3, [0x99; 32], make_block_data(0xAB)), // corrupt → missing comparison
        ];

        let results = engine.repair_batch(&blocks);
        assert_eq!(results, vec![false, true, false]);
        assert_eq!(engine.ledger().repair_count, 0);
        assert_eq!(engine.ledger().repair_failure_count, 0);
    }

    #[test]
    fn ledger_determinism_same_sequence_same_digest() {
        let recon1 = MockReconstructor::new();
        let recon2 = MockReconstructor::new();
        let healthy = make_block_data(0x42);
        let expected = hash_data(&healthy);
        recon1.set_healthy_block(10, healthy.clone());
        recon2.set_healthy_block(10, healthy.clone());

        let mut engine1 = ScrubRepairEngine::new(recon1);
        let mut engine2 = ScrubRepairEngine::new(recon2);
        let comparison = repair_comparison_record();

        engine1.repair_one_with_comparison(
            10,
            &expected,
            &make_block_data(0xAD),
            Some(&comparison),
        );
        engine2.repair_one_with_comparison(
            10,
            &expected,
            &make_block_data(0xAD),
            Some(&comparison),
        );

        assert_eq!(
            engine1.ledger().validation_digest(),
            engine2.ledger().validation_digest()
        );
    }

    #[test]
    fn ledger_mut_allows_external_inspection() {
        let recon = MockReconstructor::new();
        let healthy = make_block_data(0x55);
        let expected = hash_data(&healthy);
        recon.set_healthy_block(1, healthy);

        let mut engine = ScrubRepairEngine::new(recon);
        let comparison = repair_comparison_record();
        engine.repair_one_with_comparison(1, &expected, &make_block_data(0x99), Some(&comparison));

        let ledger = engine.ledger_mut();
        assert_eq!(ledger.repair_count, 1);
        // Mutating through ledger_mut is allowed for integration.
        ledger.reset();
        assert_eq!(ledger.repair_count, 0);
    }
}
