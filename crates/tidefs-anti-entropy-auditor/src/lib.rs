// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Anti-entropy auditor: periodic scan/compare/repair-candidate discovery
//! for P8-03 data_copy_8.
//!
//! The anti-entropy auditor is the bridge between replica health tracking
//! (which detects lag/degradation via `tidefs-replica-health`) and the
//! rebuild/transfer machinery (which fixes divergences via
//! `tidefs-replication-model`). Without it, replica health signals have
//! no automated follow-through.
//!
//! # Design
//!
//! - **State machine**: 6 states (idle → enumerating → compare →
//!   divergence_found → ticketed → resolved)
//! - **Incremental frontier**: high-water mark + degraded-subject list
//!   prevents re-scanning already-verified subjects (unlike ZFS scrub)
//! - **Three-source comparison**: primary digest, replica digest, optional
//!   witness digest for tie-breaking
//! - **Merkle tree exchange**: efficient O(k log N) comparison for large
//!   datasets by exchanging tree hashes level-by-level
//! - **Scrub integration**: divergences found by the auditor trigger
//!   targeted scrub via `ScrubTrigger` trait
//! - **SuspectLog feeding**: divergence records are converted to
//!   `SuspectEntry` records for the repair pipeline
//!
//! # Comparison to existing systems
//!
//! | System    | Scan Type     | Incremental | Backpressure | Witness |
//! |-----------|--------------|-------------|--------------|---------|
//! | ZFS       | Full pool     | No          | No           | No      |
//! | Ceph      | Per-PG deep   | No          | No           | No      |
//! | Cassandra | Merkle tree   | Yes         | No           | No      |
//! | TideFS    | Per-subject   | Yes         | Yes          | Yes     |

pub mod ae_state;
pub mod comparator;
pub mod merkle_exchange;
pub mod scan_scheduler;

use ae_state::{AntiEntropyState, DivergenceClass, DivergenceRecord};
use comparator::{ComparisonInput, ComparisonResult, DigestComparator};
use merkle_exchange::{
    MerkleExchange, MerkleExchangeResult, MerkleExchangeStatus, MerkleLeafRange,
};
use scan_scheduler::{ScanDecision, ScanSchedulePolicy, ScanScheduler};

use tidefs_checksum_tree::{ChecksumTree, Digest, SubtreeProof};
use tidefs_local_object_store::{SuspectEntry, SuspectLog};
use tidefs_replica_health::ReplicaLagStateRecord;

// ── Scrub trigger trait ─────────────────────────────────────────────

/// Trait for triggering targeted scrub operations on objects identified
/// as divergent by the anti-entropy auditor.
///
/// Implementations wire the auditor into the scrub/resilver pipeline:
/// when the auditor finds a digest mismatch, it calls `trigger_scrub`
/// to queue the affected objects for immediate integrity verification.
pub trait ScrubTrigger: Send + Sync {
    /// Trigger a targeted scrub of specific subject objects.
    ///
    /// Called when the auditor detects divergence. Returns the number
    /// of scrub operations that were successfully queued.
    fn trigger_scrub(&self, subject_refs: &[u64], reason: &str) -> usize;

    /// Trigger a scrub on a single node for the given subjects.
    fn trigger_scrub_on_node(&self, node_id: u64, subject_refs: &[u64], reason: &str) -> usize;

    /// Trigger a full cross-node scrub of all subjects that diverged.
    fn trigger_cross_node_scrub(
        &self,
        primary_node: u64,
        replica_node: u64,
        subject_refs: &[u64],
        reason: &str,
    ) -> usize;
}

// ── SuspectLog feeder ───────────────────────────────────────────────

/// Converts a [`DivergenceRecord`] into a [`SuspectEntry`] for the repair
/// pipeline.
///
/// The anti-entropy auditor works at the subject/replica level and produces
/// `DivergenceRecord`s. To feed these into the scrub/repair pipeline, we
/// convert them into `SuspectEntry` records that the `SuspectLog` and
/// repair scheduler understand.
impl From<&DivergenceRecord> for SuspectEntry {
    fn from(rec: &DivergenceRecord) -> Self {
        let record_type: u8 = match rec.class {
            DivergenceClass::LagBehind => 10,           // AE: lag detected
            DivergenceClass::DigestMismatch => 11,      // AE: digest mismatch
            DivergenceClass::MissingReplica => 12,      // AE: missing replica
            DivergenceClass::ReplicaUnhealthy => 13,    // AE: unhealthy replica
            DivergenceClass::WitnessDisagreement => 14, // AE: witness disagreement
        };

        let expected = rec
            .expected_hash
            .unwrap_or_else(|| digest_from_u64(rec.expected_digest));
        let actual = rec
            .actual_hash
            .unwrap_or_else(|| digest_from_u64(rec.actual_digest));

        SuspectEntry {
            entry_id: 0, // auto-assigned by SuspectLog::record
            locator_id: rec.subject_ref,
            segment_id: 0, // not available at AE level
            offset: 0,     // not available at AE level
            record_type,
            expected_hash: expected,
            actual_hash: actual,
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: (rec.detected_at_ns / 1_000_000_000),
        }
    }
}

fn digest_from_u64(digest: u64) -> Digest {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&digest.to_le_bytes());
    hash
}

/// The anti-entropy auditor — orchestrates periodic scan/compare cycles.
///
/// Owns the state machine, scan scheduler, digest comparator, Merkle
/// exchange engine, and divergence registry. Feeds discovered divergences
/// into the SuspectLog and scrub trigger.
#[derive(Debug)]
pub struct AntiEntropyAuditor {
    /// Current state in the anti-entropy lifecycle.
    pub state: AntiEntropyState,
    /// Scan scheduler — controls when and what to scan.
    pub scheduler: ScanScheduler,
    /// Digest comparator — performs the actual comparison.
    pub comparator: DigestComparator,
    /// Merkle exchange engine — efficient tree-based cross-node comparison.
    pub merkle_exchange: Option<MerkleExchange>,
    /// Divergences found in the current scan cycle.
    pub current_divergences: Vec<DivergenceRecord>,
    /// All divergences found (lifetime), for validation/audit trail.
    pub divergence_history: Vec<DivergenceRecord>,
    /// Tickets created in the current cycle.
    pub tickets_created: Vec<u64>,
    /// Epoch context for the current cycle.
    pub epoch: u64,
    /// Total subjects known in the system.
    pub total_subjects: u64,
    /// Monotonic audit sequence number.
    pub audit_sequence: u64,
    /// Last error encountered (if any).
    pub last_error: Option<String>,
}

impl AntiEntropyAuditor {
    /// Create a new anti-entropy auditor.
    #[must_use]
    pub fn new(policy: ScanSchedulePolicy, epoch: u64, now_ns: u64) -> Self {
        AntiEntropyAuditor {
            state: AntiEntropyState::Idle {
                last_scan_completed_ns: 0,
                next_scan_eligible_ns: now_ns,
            },
            scheduler: ScanScheduler::new(policy, now_ns),
            comparator: DigestComparator::default(),
            merkle_exchange: None,
            current_divergences: Vec::new(),
            divergence_history: Vec::new(),
            tickets_created: Vec::new(),
            epoch,
            total_subjects: 0,
            audit_sequence: 0,
            last_error: None,
        }
    }

    /// Advance the epoch context.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Update the total number of known subjects.
    pub fn set_total_subjects(&mut self, total: u64) {
        self.total_subjects = total;
    }

    // ── Merkle exchange ───────────────────────────────────────────────

    /// Initialize a Merkle exchange session with a local Merkle tree.
    ///
    /// Call this before beginning cross-node comparison. The local tree
    /// is built from local data blocks; the remote root is fetched from
    /// the peer node.
    pub fn init_merkle_exchange(&mut self, local_tree: ChecksumTree, remote_root: Digest) {
        self.merkle_exchange = Some(MerkleExchange::new(local_tree, remote_root));
    }

    /// Run the Merkle exchange comparison against the currently configured
    /// remote root. Returns the exchange result with divergent leaf indices.
    ///
    /// If no Merkle exchange has been initialized, returns None.
    pub fn run_merkle_exchange(&mut self) -> Option<MerkleExchangeResult> {
        let exchange = self.merkle_exchange.as_mut()?;
        Some(exchange.compare())
    }

    /// Run Merkle exchange with a fully available remote tree (for testing
    /// or when remote tree data has been fully transferred).
    pub fn run_merkle_exchange_with_remote(
        &mut self,
        remote_tree: &ChecksumTree,
    ) -> Option<MerkleExchangeResult> {
        let exchange = self.merkle_exchange.as_mut()?;
        Some(exchange.compare_with_remote_tree(remote_tree))
    }

    /// Run Merkle exchange with remote leaf proofs for one exact subject range.
    pub fn run_merkle_exchange_with_remote_proofs(
        &mut self,
        range: MerkleLeafRange,
        proofs: &[SubtreeProof],
    ) -> Option<MerkleExchangeResult> {
        let exchange = self.merkle_exchange.as_mut()?;
        Some(exchange.compare_with_remote_leaf_proofs(range, proofs))
    }

    /// Record validated Merkle leaf divergences as repair-eligible evidence.
    ///
    /// Root mismatches without complete leaf proof, corrupt proof data, and
    /// witness disagreements remain audit evidence and do not enter the
    /// divergence registry that feeds scrub and repair scheduling.
    pub fn record_merkle_exchange_result(
        &mut self,
        result: &MerkleExchangeResult,
        target_node: u64,
        now_ns: u64,
    ) -> usize {
        if !result.is_repair_evidence() {
            match result.status {
                MerkleExchangeStatus::ProofNeededRootMismatch => {
                    self.last_error =
                        Some("merkle root mismatch requires complete remote leaf proof".into());
                }
                MerkleExchangeStatus::CorruptProof => {
                    self.last_error = Some(format!(
                        "remote merkle proof failed closed: {:?}",
                        result.proof_failure
                    ));
                }
                MerkleExchangeStatus::WitnessTieBreakDisagreement => {
                    self.last_error =
                        Some("witness digest disagrees with primary and replica".into());
                }
                MerkleExchangeStatus::EqualRoots
                | MerkleExchangeStatus::CompleteDivergentLeafProof => {}
            }
            return 0;
        }

        let mut new_divergences = 0;
        for divergence in &result.leaf_divergences {
            let record = DivergenceRecord::new_with_hashes(
                divergence.subject_ref,
                target_node,
                DivergenceClass::DigestMismatch,
                divergence.expected_digest,
                divergence.actual_digest,
                self.epoch,
                now_ns,
            );

            self.scheduler
                .frontier
                .register_degraded(divergence.subject_ref);
            self.divergence_history.push(record.clone());
            self.current_divergences.push(record);
            new_divergences += 1;
        }

        if let AntiEntropyState::Compare {
            ref mut comparisons_done,
            ref mut divergences_found,
            ..
        } = self.state
        {
            *comparisons_done += result.blocks_compared;
            *divergences_found += new_divergences;
        }

        new_divergences as usize
    }

    /// Clear the current Merkle exchange session.
    pub fn clear_merkle_exchange(&mut self) {
        self.merkle_exchange = None;
    }

    // ── Degraded registration ─────────────────────────────────────────

    /// Register degraded subjects from the replica health tracker.
    ///
    /// Call this when `ReplicaLagStateRecord` entries show degraded or
    /// lagging replicas. These subjects get priority in the next scan.
    pub fn register_degraded_from_health(
        &mut self,
        lag_records: &[ReplicaLagStateRecord],
    ) -> usize {
        let mut count = 0;
        for record in lag_records {
            if record.is_stale() {
                self.scheduler
                    .frontier
                    .register_degraded(record.subject_ref.0);
                count += 1;
            }
        }
        count
    }

    /// Register a specific subject as degraded for priority re-scanning.
    pub fn register_degraded_subject(&mut self, subject_ref: u64) {
        self.scheduler.frontier.register_degraded(subject_ref);
    }

    /// Clear a subject from the degraded set (e.g., after successful repair).
    pub fn clear_degraded_subject(&mut self, subject_ref: u64) {
        self.scheduler.frontier.clear_degraded(subject_ref);
    }

    // ── Scan lifecycle ───────────────────────────────────────────────

    /// Check whether a scan should start.
    ///
    /// `cluster_load_factor` should be in [0.0, 1.0] where 1.0 = fully loaded.
    #[must_use]
    pub fn should_scan(&self, now_ns: u64, cluster_load_factor: f64) -> ScanDecision {
        self.scheduler.should_scan(now_ns, cluster_load_factor)
    }

    /// Begin an anti-entropy scan cycle.
    ///
    /// Transitions from Idle/Resolved to Enumerating. Returns the batch
    /// of subjects to scan, or None if no work is pending.
    pub fn begin_scan(&mut self, now_ns: u64) -> Option<Vec<u64>> {
        let batch = self.scheduler.start_scan(now_ns, self.total_subjects)?;

        self.state = AntiEntropyState::Enumerating {
            started_at_ns: now_ns,
            subjects_in_scope: batch.subjects.len() as u64,
            frontier_mark: self.scheduler.frontier.high_water_mark,
        };

        self.current_divergences.clear();
        self.tickets_created.clear();
        self.audit_sequence += 1;

        Some(batch.subjects)
    }

    /// Transition to the comparison phase.
    ///
    /// Called after the enumeration batch has been fetched and comparison
    /// inputs are ready. Sets the expected comparison count.
    pub fn begin_compare(&mut self, now_ns: u64, total_comparisons: u64) {
        self.state = AntiEntropyState::Compare {
            started_at_ns: now_ns,
            comparisons_done: 0,
            comparisons_total: total_comparisons,
            divergences_found: 0,
        };
    }

    /// Feed comparison results into the auditor.
    ///
    /// Updates the comparison progress in the state machine and collects
    /// divergence records. Returns the new divergence count.
    pub fn record_comparisons(&mut self, results: &[ComparisonResult], _now_ns: u64) -> usize {
        let mut new_divergences = 0;

        for result in results {
            if let Some(class) = result.divergence_class {
                new_divergences += 1;
                let record = DivergenceRecord::new(
                    result.subject_ref,
                    result.target_node,
                    class,
                    result.primary_digest,
                    result.replica_digest,
                    result.epoch,
                    result.compared_at_ns,
                );

                // Update frontier: mark subject as degraded for re-scan
                if record.requires_ticket() {
                    self.scheduler
                        .frontier
                        .register_degraded(result.subject_ref);
                }

                self.current_divergences.push(record);
            }
        }

        // Update comparison progress in state
        if let AntiEntropyState::Compare {
            ref mut comparisons_done,
            ref mut divergences_found,
            ..
        } = self.state
        {
            *comparisons_done += results.len() as u64;
            *divergences_found += new_divergences as u64;
        }

        self.divergence_history
            .extend(self.current_divergences.iter().cloned());

        new_divergences
    }

    // ── SuspectLog integration ────────────────────────────────────────

    /// Feed current divergence records into a [`SuspectLog`].
    ///
    /// Converts each divergence into a [`SuspectEntry`] and records it
    /// in the log. Returns the number of entries added.
    pub fn feed_suspect_log(&self, suspect_log: &mut SuspectLog) -> usize {
        let mut count = 0;
        for div in &self.current_divergences {
            if div.requires_ticket() {
                let entry = SuspectEntry::from(div);
                suspect_log.record(entry);
                count += 1;
            }
        }
        count
    }

    /// Feed all historical divergence records into a [`SuspectLog`].
    ///
    /// Returns the number of entries added.
    pub fn feed_suspect_log_all(&self, suspect_log: &mut SuspectLog) -> usize {
        let mut count = 0;
        for div in &self.divergence_history {
            if div.requires_ticket() {
                let entry = SuspectEntry::from(div);
                suspect_log.record(entry);
                count += 1;
            }
        }
        count
    }

    // ── Scrub trigger integration ─────────────────────────────────────

    /// Trigger scrub for all ticketable divergences found in the current cycle.
    ///
    /// Calls the [`ScrubTrigger`] implementation to queue targeted scrub
    /// operations. Returns the number of scrub operations queued.
    pub fn trigger_scrub_for_divergences(
        &self,
        trigger: &dyn ScrubTrigger,
        primary_node: u64,
        replica_node: u64,
    ) -> usize {
        let subject_refs: Vec<u64> = self
            .current_divergences
            .iter()
            .filter(|d| d.requires_ticket())
            .map(|d| d.subject_ref)
            .collect();

        if subject_refs.is_empty() {
            return 0;
        }

        trigger.trigger_cross_node_scrub(
            primary_node,
            replica_node,
            &subject_refs,
            &format!(
                "anti-entropy audit #{}: {} divergences found",
                self.audit_sequence,
                subject_refs.len()
            ),
        )
    }

    /// Trigger scrub for divergences on a specific node.
    pub fn trigger_scrub_on_node(&self, trigger: &dyn ScrubTrigger, node_id: u64) -> usize {
        let subject_refs: Vec<u64> = self
            .current_divergences
            .iter()
            .filter(|d| d.requires_ticket())
            .map(|d| d.subject_ref)
            .collect();

        if subject_refs.is_empty() {
            return 0;
        }

        trigger.trigger_scrub_on_node(
            node_id,
            &subject_refs,
            &format!(
                "anti-entropy audit #{}: target scrub for node {}",
                self.audit_sequence, node_id
            ),
        )
    }

    // ── Divergence classification ─────────────────────────────────────

    /// Transition to divergence_found state with classification summary.
    pub fn classify_divergences(&mut self, now_ns: u64) {
        let total = self.current_divergences.len() as u64;
        let classified_lag = self
            .current_divergences
            .iter()
            .filter(|d| d.is_lag_only())
            .count() as u64;
        let classified_corruption = self
            .current_divergences
            .iter()
            .filter(|d| matches!(d.class, DivergenceClass::DigestMismatch))
            .count() as u64;
        let classified_missing = self
            .current_divergences
            .iter()
            .filter(|d| {
                matches!(
                    d.class,
                    DivergenceClass::MissingReplica | DivergenceClass::ReplicaUnhealthy
                )
            })
            .count() as u64;
        let classified_witness_disagreement = self
            .current_divergences
            .iter()
            .filter(|d| d.is_witness_disagreement())
            .count() as u64;

        self.state = AntiEntropyState::DivergenceFound {
            detected_at_ns: now_ns,
            total_divergences: total,
            classified_lag,
            classified_corruption,
            classified_missing,
            classified_witness_disagreement,
        };
    }

    /// Transition to ticketed state after creating repair tickets.
    ///
    /// `ticket_ids` is the range of ticket ids created for the divergences.
    pub fn record_tickets(&mut self, now_ns: u64, ticket_ids: &[u64]) {
        self.tickets_created = ticket_ids.to_vec();

        let (first, last) = if ticket_ids.is_empty() {
            (0, 0)
        } else {
            (*ticket_ids.first().unwrap(), *ticket_ids.last().unwrap())
        };

        self.state = AntiEntropyState::Ticketed {
            created_at_ns: now_ns,
            tickets_created: ticket_ids.len() as u64,
            ticket_range_start: first,
            ticket_range_end: last,
        };
    }

    /// Transition to resolved state after all tickets are consumed.
    ///
    /// `receipt_ids` is the range of verification receipts confirming resolution.
    pub fn resolve(&mut self, now_ns: u64, receipt_ids: &[u64]) {
        let (first, last) = if receipt_ids.is_empty() {
            (0, 0)
        } else {
            (*receipt_ids.first().unwrap(), *receipt_ids.last().unwrap())
        };

        self.state = AntiEntropyState::Resolved {
            resolved_at_ns: now_ns,
            divergences_resolved: self.current_divergences.len() as u64,
            receipt_range_start: first,
            receipt_range_end: last,
        };
    }

    /// Complete the scan cycle and schedule the next one.
    ///
    /// Transitions to Idle and updates the scheduler frontier.
    pub fn complete_scan(&mut self, now_ns: u64) {
        let divergences = self.current_divergences.len() as u64;

        self.scheduler
            .complete_scan(self.epoch, now_ns, divergences);
        self.scheduler.frontier.advance(self.total_subjects);

        self.state = AntiEntropyState::Idle {
            last_scan_completed_ns: now_ns,
            next_scan_eligible_ns: now_ns + self.scheduler.policy.min_scan_interval_ns,
        };
    }

    // ── Direct comparison (skips the scheduler for targeted audits) ──

    /// Run a targeted comparison of specific subject-replica pairs.
    ///
    /// Bypasses the scan scheduler — useful for operator-initiated audits
    /// or post-repair verification.
    pub fn targeted_audit(
        &mut self,
        inputs: &[ComparisonInput],
        now_ns: u64,
    ) -> Vec<ComparisonResult> {
        let results = self.comparator.compare_batch(inputs, now_ns);
        self.record_comparisons(&results, now_ns);
        results
    }

    /// Run a comparison of a single subject against all its replicas.
    pub fn audit_subject(
        &mut self,
        subject_ref: u64,
        primary_digest: u64,
        replica_digests: &[(u64, u64)],
        witness_digest: Option<u64>,
        now_ns: u64,
    ) -> (Vec<u64>, Vec<ComparisonResult>) {
        let (healthy, divergences) = self.comparator.compare_subject_against_replicas(
            subject_ref,
            primary_digest,
            replica_digests,
            witness_digest,
            self.epoch,
            now_ns,
        );
        self.record_comparisons(&divergences, now_ns);
        (healthy, divergences)
    }

    // ── Merkle-based cross-node audit ─────────────────────────────────

    /// Run a Merkle tree exchange against a peer node's root hash.
    ///
    /// Returns the exchange result if a Merkle exchange session was active.
    pub fn cross_node_merkle_audit(&mut self, remote_root: Digest) -> Option<MerkleExchangeResult> {
        if let Some(exchange) = self.merkle_exchange.as_mut() {
            exchange.remote_root = remote_root;
            Some(exchange.compare())
        } else {
            None
        }
    }

    // ── Statistics ───────────────────────────────────────────────────

    /// Divergences requiring tickets (not just lag).
    #[must_use]
    pub fn ticketable_divergences(&self) -> Vec<&DivergenceRecord> {
        self.current_divergences
            .iter()
            .filter(|d| d.requires_ticket())
            .collect()
    }

    /// Lag-only divergences (may self-heal).
    #[must_use]
    pub fn lag_divergences(&self) -> Vec<&DivergenceRecord> {
        self.current_divergences
            .iter()
            .filter(|d| d.is_lag_only())
            .collect()
    }

    /// Whether the current cycle found any divergences.
    #[must_use]
    pub fn has_divergences(&self) -> bool {
        !self.current_divergences.is_empty()
    }

    /// Whether tickets have been created for the current divergences.
    #[must_use]
    pub fn is_ticketed(&self) -> bool {
        matches!(self.state, AntiEntropyState::Ticketed { .. })
    }

    /// Whether the current cycle is resolved.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self.state, AntiEntropyState::Resolved { .. })
    }

    /// Total number of divergences across all scan cycles.
    #[must_use]
    pub fn total_historical_divergences(&self) -> usize {
        self.divergence_history.len()
    }

    /// Drain and return divergence records from the current cycle.
    #[must_use]
    pub fn drain_divergences(&mut self) -> Vec<DivergenceRecord> {
        std::mem::take(&mut self.current_divergences)
    }

    /// Drain and return ticket ids.
    #[must_use]
    pub fn drain_tickets(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.tickets_created)
    }
}

// ── Default ScrubTrigger implementation for testing ─────────────────

/// A no-op scrub trigger that counts calls. Useful for testing.
#[derive(Default, Debug)]
pub struct CountingScrubTrigger {
    pub trigger_count: std::sync::atomic::AtomicUsize,
    pub total_subjects: std::sync::atomic::AtomicUsize,
}

impl ScrubTrigger for CountingScrubTrigger {
    fn trigger_scrub(&self, subject_refs: &[u64], _reason: &str) -> usize {
        self.trigger_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_subjects
            .fetch_add(subject_refs.len(), std::sync::atomic::Ordering::Relaxed);
        subject_refs.len()
    }

    fn trigger_scrub_on_node(&self, _node_id: u64, subject_refs: &[u64], _reason: &str) -> usize {
        self.trigger_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_subjects
            .fetch_add(subject_refs.len(), std::sync::atomic::Ordering::Relaxed);
        subject_refs.len()
    }

    fn trigger_cross_node_scrub(
        &self,
        _primary_node: u64,
        _replica_node: u64,
        subject_refs: &[u64],
        _reason: &str,
    ) -> usize {
        self.trigger_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.total_subjects
            .fetch_add(subject_refs.len(), std::sync::atomic::Ordering::Relaxed);
        subject_refs.len()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_checksum_tree::ChecksumTreeBuilder;
    use tidefs_replication_model::ReplicatedSubjectId;

    const NS_PER_SEC: u64 = 1_000_000_000;
    const NS_PER_MIN: u64 = 60 * NS_PER_SEC;

    fn auditor() -> AntiEntropyAuditor {
        let policy = ScanSchedulePolicy::default();
        AntiEntropyAuditor::new(policy, 1, 0)
    }

    // ── Existing scan lifecycle tests ────────────────────────────────

    #[test]
    fn full_scan_lifecycle_no_divergences() {
        let mut aud = auditor();
        aud.set_total_subjects(100);

        // Begin scan
        let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
        assert!(!subjects.is_empty());
        assert!(matches!(aud.state, AntiEntropyState::Enumerating { .. }));

        // Compare (all matched)
        aud.begin_compare(2 * NS_PER_MIN, subjects.len() as u64);
        let inputs: Vec<ComparisonInput> = subjects
            .iter()
            .map(|s| ComparisonInput {
                subject_ref: *s,
                target_node: 1,
                primary_digest: 42,
                replica_digest: 42,
                witness_digest: None,
                epoch: 1,
            })
            .collect();
        let results = aud.comparator.compare_batch(&inputs, 2 * NS_PER_MIN);
        let new_divs = aud.record_comparisons(&results, 2 * NS_PER_MIN);
        assert_eq!(new_divs, 0);
        assert!(!aud.has_divergences());

        // Complete scan → Idle
        aud.complete_scan(3 * NS_PER_MIN);
        assert!(matches!(aud.state, AntiEntropyState::Idle { .. }));
    }

    #[test]
    fn full_scan_lifecycle_with_divergences() {
        let mut aud = auditor();
        aud.set_total_subjects(50);

        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(2 * NS_PER_MIN, 50);

        // Inject divergences
        let inputs: Vec<ComparisonInput> = (1..=50)
            .map(|s| ComparisonInput {
                subject_ref: s,
                target_node: 1,
                primary_digest: if s <= 5 { 99 } else { 42 },
                replica_digest: 42,
                witness_digest: None,
                epoch: 1,
            })
            .collect();
        let results = aud.comparator.compare_batch(&inputs, 2 * NS_PER_MIN);
        aud.record_comparisons(&results, 2 * NS_PER_MIN);

        assert!(aud.has_divergences());
        assert_eq!(aud.ticketable_divergences().len(), 5);

        // Classify divergences
        aud.classify_divergences(3 * NS_PER_MIN);
        assert!(matches!(
            aud.state,
            AntiEntropyState::DivergenceFound { .. }
        ));

        // Create tickets
        aud.record_tickets(4 * NS_PER_MIN, &[100, 101, 102, 103, 104]);
        assert!(aud.is_ticketed());

        // Resolve
        aud.resolve(5 * NS_PER_MIN, &[200, 201, 202, 203, 204]);
        assert!(aud.is_resolved());

        // Complete
        aud.complete_scan(6 * NS_PER_MIN);
        assert!(matches!(aud.state, AntiEntropyState::Idle { .. }));
        assert_eq!(aud.total_historical_divergences(), 5);
    }

    #[test]
    fn degraded_subjects_get_priority() {
        let mut aud = auditor();
        aud.set_total_subjects(1000);
        aud.register_degraded_subject(777);

        let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
        // 777 should be first in the batch
        assert_eq!(subjects[0], 777);
    }

    #[test]
    fn register_degraded_from_health_records() {
        let mut aud = auditor();
        let lag_records = vec![
            ReplicaLagStateRecord::new(
                ReplicatedSubjectId::new(10),
                1,
                100,
                tidefs_replication_model::ReplicaLagClass::Stale,
                5000,
            ),
            ReplicaLagStateRecord::new(
                ReplicatedSubjectId::new(20),
                1,
                100,
                tidefs_replication_model::ReplicaLagClass::SlightlyBehind,
                100,
            ),
        ];

        let count = aud.register_degraded_from_health(&lag_records);
        assert_eq!(count, 1); // Only the Stale one

        aud.set_total_subjects(100);
        let subjects = aud.begin_scan(NS_PER_MIN).unwrap();
        assert_eq!(subjects[0], 10);
    }

    #[test]
    fn targeted_audit_bypasses_scheduler() {
        let mut aud = auditor();
        let inputs = vec![ComparisonInput {
            subject_ref: 99,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: Some(42),
            epoch: 1,
        }];

        let results = aud.targeted_audit(&inputs, 1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].diverged);
        assert!(aud.has_divergences());
    }

    #[test]
    fn witness_disagreement_is_not_lag_or_repair_ticket() {
        let mut aud = auditor();
        aud.begin_compare(NS_PER_MIN, 1);
        let inputs = vec![ComparisonInput {
            subject_ref: 99,
            target_node: 1,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: Some(77),
            epoch: 1,
        }];

        let results = aud.targeted_audit(&inputs, NS_PER_MIN);
        assert_eq!(
            results[0].divergence_class,
            Some(DivergenceClass::WitnessDisagreement)
        );
        assert_eq!(aud.ticketable_divergences().len(), 0);
        assert_eq!(aud.lag_divergences().len(), 0);

        aud.classify_divergences(2 * NS_PER_MIN);
        assert!(matches!(
            aud.state,
            AntiEntropyState::DivergenceFound {
                classified_lag: 0,
                classified_corruption: 0,
                classified_missing: 0,
                classified_witness_disagreement: 1,
                ..
            }
        ));

        let mut suspect_log = SuspectLog::new();
        assert_eq!(aud.feed_suspect_log(&mut suspect_log), 0);

        let trigger = CountingScrubTrigger::default();
        assert_eq!(aud.trigger_scrub_for_divergences(&trigger, 1, 2), 0);
    }

    #[test]
    fn drain_divergences_clears_current_cycle() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        let inputs: Vec<ComparisonInput> = (1..=3)
            .map(|s| ComparisonInput {
                subject_ref: s,
                target_node: 1,
                primary_digest: 42,
                replica_digest: 0,
                witness_digest: None,
                epoch: 1,
            })
            .collect();
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);
        assert!(aud.has_divergences());

        let drained = aud.drain_divergences();
        assert_eq!(drained.len(), 3);
        assert!(!aud.has_divergences());
        // History still retains them
        assert_eq!(aud.total_historical_divergences(), 3);
    }

    // ── SuspectLog integration tests ─────────────────────────────────

    #[test]
    fn feed_suspect_log_converts_divergences() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        // Create divergences
        let inputs: Vec<ComparisonInput> = vec![
            ComparisonInput {
                subject_ref: 1,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 99,
                witness_digest: None,
                epoch: 1,
            },
            ComparisonInput {
                subject_ref: 3,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 0,
                witness_digest: None,
                epoch: 1,
            },
            ComparisonInput {
                subject_ref: 5,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 41,
                witness_digest: Some(42),
                epoch: 1,
            },
        ];
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);

        let mut suspect_log = SuspectLog::new();
        let count = aud.feed_suspect_log(&mut suspect_log);
        assert_eq!(count, 3); // All three are ticketable

        let entries: Vec<SuspectEntry> = suspect_log.iter().copied().collect();
        assert_eq!(entries.len(), 3);
        // First entry: digest mismatch
        assert_eq!(entries[0].locator_id, 1);
        assert_eq!(entries[0].record_type, 11); // DigestMismatch
                                                // Second entry: missing replica
        assert_eq!(entries[1].locator_id, 3);
        assert_eq!(entries[1].record_type, 12); // MissingReplica
                                                // Third entry: digest mismatch
        assert_eq!(entries[2].locator_id, 5);
        assert_eq!(entries[2].record_type, 11);
    }

    #[test]
    fn feed_suspect_log_skips_lag_only() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        // Create a lag-only divergence (primary behind replica with witness confirming replica)
        let inputs: Vec<ComparisonInput> = vec![
            ComparisonInput {
                subject_ref: 1,
                target_node: 2,
                primary_digest: 99,
                replica_digest: 42,
                witness_digest: Some(42),
                epoch: 1,
            },
            ComparisonInput {
                subject_ref: 2,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 99,
                witness_digest: None,
                epoch: 1,
            },
        ];
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);

        let mut suspect_log = SuspectLog::new();
        let count = aud.feed_suspect_log(&mut suspect_log);
        assert_eq!(count, 1); // Only the digest mismatch (subject 2), not lag (subject 1)
    }

    #[test]
    fn feed_suspect_log_all_includes_history() {
        let mut aud = auditor();
        aud.set_total_subjects(10);

        // First cycle
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 1);
        let inputs = vec![ComparisonInput {
            subject_ref: 1,
            target_node: 2,
            primary_digest: 42,
            replica_digest: 99,
            witness_digest: None,
            epoch: 1,
        }];
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);
        aud.complete_scan(NS_PER_MIN);

        // Second cycle
        aud.begin_scan(2 * NS_PER_MIN);
        aud.begin_compare(2 * NS_PER_MIN, 1);
        let inputs = vec![ComparisonInput {
            subject_ref: 2,
            target_node: 3,
            primary_digest: 42,
            replica_digest: 0,
            witness_digest: None,
            epoch: 1,
        }];
        let results = aud.comparator.compare_batch(&inputs, 2 * NS_PER_MIN);
        aud.record_comparisons(&results, 2 * NS_PER_MIN);
        aud.complete_scan(2 * NS_PER_MIN);

        // feed_suspect_log only feeds current cycle
        let mut log_current = SuspectLog::new();
        let count_current = aud.feed_suspect_log(&mut log_current);
        assert_eq!(count_current, 1); // Only subject 2

        // feed_suspect_log_all feeds history (subjects 1 and 2)
        let mut log_all = SuspectLog::new();
        let count_all = aud.feed_suspect_log_all(&mut log_all);
        assert_eq!(count_all, 2);
    }

    // ── Scrub trigger integration tests ──────────────────────────────

    #[test]
    fn trigger_scrub_on_divergence() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        // Create ticketable divergences
        let inputs: Vec<ComparisonInput> = (1..=4)
            .map(|s| ComparisonInput {
                subject_ref: s,
                target_node: 2,
                primary_digest: 42,
                replica_digest: if s == 2 { 42 } else { 99 },
                witness_digest: None,
                epoch: 1,
            })
            .collect();
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);

        let trigger = CountingScrubTrigger::default();
        let count = aud.trigger_scrub_on_node(&trigger, 2);
        assert_eq!(count, 3); // Subjects 1, 3, 4 diverged; subject 2 matched

        let total = trigger
            .total_subjects
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(total, 3);
    }

    #[test]
    fn trigger_cross_node_scrub() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        let inputs: Vec<ComparisonInput> = vec![
            ComparisonInput {
                subject_ref: 10,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 99,
                witness_digest: None,
                epoch: 1,
            },
            ComparisonInput {
                subject_ref: 20,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 0,
                witness_digest: None,
                epoch: 1,
            },
        ];
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);

        let trigger = CountingScrubTrigger::default();
        let count = aud.trigger_scrub_for_divergences(&trigger, 1, 2);
        assert_eq!(count, 2);

        let trigger_count = trigger
            .trigger_count
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(trigger_count, 1); // One cross-node call
    }

    #[test]
    fn trigger_scrub_no_divergences_is_noop() {
        let mut aud = auditor();
        aud.set_total_subjects(10);
        aud.begin_scan(NS_PER_MIN);
        aud.begin_compare(NS_PER_MIN, 10);

        // All matched
        let inputs: Vec<ComparisonInput> = (1..=3)
            .map(|s| ComparisonInput {
                subject_ref: s,
                target_node: 2,
                primary_digest: 42,
                replica_digest: 42,
                witness_digest: None,
                epoch: 1,
            })
            .collect();
        let results = aud.comparator.compare_batch(&inputs, NS_PER_MIN);
        aud.record_comparisons(&results, NS_PER_MIN);

        let trigger = CountingScrubTrigger::default();
        let count = aud.trigger_scrub_on_node(&trigger, 2);
        assert_eq!(count, 0);

        let trigger_count = trigger
            .trigger_count
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(trigger_count, 0);
    }

    // ── Merkle exchange integration tests ────────────────────────────

    fn build_tree(data_blocks: &[&[u8]]) -> ChecksumTree {
        let mut builder = ChecksumTreeBuilder::new(256);
        for block in data_blocks {
            builder.ingest(block);
        }
        builder.finish()
    }

    fn merkle_test_trees() -> (ChecksumTree, ChecksumTree) {
        let data1: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 64]).collect();
        let mut data2 = data1.clone();
        data2[42][0] = 0xFF;

        let slices1: Vec<&[u8]> = data1.iter().map(|d| d.as_slice()).collect();
        let slices2: Vec<&[u8]> = data2.iter().map(|d| d.as_slice()).collect();

        (build_tree(&slices1), build_tree(&slices2))
    }

    #[test]
    fn merkle_exchange_init_and_compare() {
        let data: Vec<Vec<u8>> = (0..50).map(|i| vec![i as u8; 64]).collect();
        let slices: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let tree = build_tree(&slices);
        let root = tree.root_hash;

        let mut aud = auditor();
        aud.init_merkle_exchange(tree.clone(), root);

        let result = aud.run_merkle_exchange().unwrap();
        assert_eq!(result.status, MerkleExchangeStatus::EqualRoots);
        assert!(result.consistent);
        assert_eq!(result.divergent_blocks, 0);
    }

    #[test]
    fn merkle_exchange_detects_divergence() {
        let data1: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 64]).collect();
        let mut data2 = data1.clone();
        data2[42][0] = 0xFF; // Corrupt block 42

        let slices1: Vec<&[u8]> = data1.iter().map(|d| d.as_slice()).collect();
        let slices2: Vec<&[u8]> = data2.iter().map(|d| d.as_slice()).collect();
        let tree1 = build_tree(&slices1);
        let tree2 = build_tree(&slices2);

        let mut aud = auditor();
        aud.init_merkle_exchange(tree1.clone(), tree2.root_hash);

        let result = aud.run_merkle_exchange_with_remote(&tree2).unwrap();
        assert_eq!(
            result.status,
            MerkleExchangeStatus::CompleteDivergentLeafProof
        );
        assert!(!result.consistent);
        assert_eq!(result.divergent_blocks, 1);
        assert_eq!(result.divergent_indices, vec![42]);
    }

    #[test]
    fn cross_node_merkle_audit_updates_remote_root() {
        let data: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 64]).collect();
        let slices: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let tree = build_tree(&slices);
        let root = tree.root_hash;

        let mut aud = auditor();
        aud.init_merkle_exchange(tree.clone(), [0u8; 32]); // Start with zero root

        // Update with real remote root
        let result = aud.cross_node_merkle_audit(root);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.status, MerkleExchangeStatus::EqualRoots);
        assert!(result.consistent);
    }

    #[test]
    fn merkle_root_mismatch_without_leaf_proof_does_not_feed_repair() {
        let (tree1, tree2) = merkle_test_trees();
        let mut aud = auditor();
        aud.init_merkle_exchange(tree1, tree2.root_hash);

        let result = aud.run_merkle_exchange().unwrap();
        assert_eq!(result.status, MerkleExchangeStatus::ProofNeededRootMismatch);
        assert_eq!(aud.record_merkle_exchange_result(&result, 2, NS_PER_MIN), 0);
        assert!(!aud.has_divergences());

        let mut suspect_log = SuspectLog::new();
        assert_eq!(aud.feed_suspect_log(&mut suspect_log), 0);

        let trigger = CountingScrubTrigger::default();
        assert_eq!(aud.trigger_scrub_for_divergences(&trigger, 1, 2), 0);
    }

    #[test]
    fn corrupt_merkle_leaf_proof_does_not_feed_repair() {
        let (tree1, tree2) = merkle_test_trees();
        let mut proof = tree2.generate_proof(42).unwrap();
        proof.leaf_digest[0] ^= 0x80;
        let range = MerkleLeafRange::new(42, 42, 1);

        let mut aud = auditor();
        aud.init_merkle_exchange(tree1, tree2.root_hash);
        let result = aud
            .run_merkle_exchange_with_remote_proofs(range, &[proof])
            .unwrap();

        assert_eq!(result.status, MerkleExchangeStatus::CorruptProof);
        assert_eq!(
            result.proof_failure,
            Some(crate::merkle_exchange::MerkleProofFailure::ChecksumMismatch { leaf_index: 42 })
        );
        assert_eq!(aud.record_merkle_exchange_result(&result, 2, NS_PER_MIN), 0);
        assert!(!aud.has_divergences());

        let mut suspect_log = SuspectLog::new();
        assert_eq!(aud.feed_suspect_log(&mut suspect_log), 0);
    }

    #[test]
    fn valid_merkle_leaf_proof_feeds_exact_suspect_entry() {
        let (tree1, tree2) = merkle_test_trees();
        let proof = tree2.generate_proof(42).unwrap();
        let range = MerkleLeafRange::new(1_042, 42, 1);

        let mut aud = auditor();
        aud.begin_compare(NS_PER_MIN, 1);
        aud.init_merkle_exchange(tree1.clone(), tree2.root_hash);
        let result = aud
            .run_merkle_exchange_with_remote_proofs(range, &[proof])
            .unwrap();

        assert_eq!(
            result.status,
            MerkleExchangeStatus::CompleteDivergentLeafProof
        );
        assert_eq!(aud.record_merkle_exchange_result(&result, 2, NS_PER_MIN), 1);
        assert_eq!(aud.ticketable_divergences().len(), 1);

        let mut suspect_log = SuspectLog::new();
        assert_eq!(aud.feed_suspect_log(&mut suspect_log), 1);
        let entries: Vec<SuspectEntry> = suspect_log.iter().copied().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].locator_id, 1_042);
        assert_eq!(entries[0].record_type, 11);
        assert_eq!(entries[0].expected_hash, tree1.leaf_digest(42).unwrap());
        assert_eq!(entries[0].actual_hash, tree2.leaf_digest(42).unwrap());
    }

    #[test]
    fn merkle_exchange_clear() {
        let data: Vec<Vec<u8>> = (0..10).map(|i| vec![i as u8; 64]).collect();
        let slices: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let tree = build_tree(&slices);

        let mut aud = auditor();
        aud.init_merkle_exchange(tree, [0u8; 32]);
        assert!(aud.merkle_exchange.is_some());

        aud.clear_merkle_exchange();
        assert!(aud.merkle_exchange.is_none());
        assert!(aud.run_merkle_exchange().is_none());
    }
}
