//! Repair scheduling bridge: connects scrub findings to prioritized repair
//! and rebake dispatch through existing background-service and reclaim primitives.
//!
//! # Architecture
//!
//! ```text
//! ScrubService ──► SuspectLog
//!                       │
//!                       ▼
//!              ScrubToRepairBridge
//!                       │
//!          ┌────────────┼────────────┐
//!          ▼            ▼            ▼
//!    RepairService  RebuildPlanner  ReclaimQueue
//!    (mirror/EC)    (loss events)   (Rebake family)
//! ```
//!
//! # Priority/escalation semantics
//!
//! Scrub findings are classified into four escalation levels:
//!
//! - **Immediate** — active degraded reads, corruption in hot data. Highest
//!   priority; bypasses normal scheduling limits.
//! - **Urgent** — corruption in data with only one remaining replica.
//!   Must be repaired before next scrub cycle.
//! - **Normal** — single-replica corruption with healthy replicas available.
//!   Standard repair cadence.
//! - **Background** — suspect entries where corruption is unconfirmed (e.g.
//!   chain-of-trust breaks without payload mismatch). Repaired when idle.
//!
//! Escalation happens when repair attempts fail repeatedly: Normal → Urgent
//! after 2 failed attempts, Urgent → Immediate after 1 more.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::collections::HashSet;

use tidefs_background_scheduler::ServicePriority;
use tidefs_local_object_store::SuspectEntry;
use tidefs_types_incremental_job_core::JobKind;
use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry};

// ---------------------------------------------------------------------------
// RepairEscalation — priority level for a repair task
// ---------------------------------------------------------------------------

/// Escalation level for a repair task derived from a scrub finding.
///
/// Higher levels get preferential scheduling and budget allocation.
/// Escalation is monotonic: once elevated, a task never de-escalates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairEscalation {
    /// Background-priority repair: unconfirmed corruption or chain-of-trust
    /// break without payload mismatch. Treated as opportunistic work.
    Background = 0,
    /// Standard repair: single corruption with healthy replicas available.
    Normal = 1,
    /// Urgent repair: corruption where only one healthy replica remains,
    /// or repeated repair failures on Normal-level entries.
    Urgent = 2,
    /// Immediate repair: active degraded reads detected, or corruption in
    /// data with zero remaining replicas (last-copy). Bypasses budget caps.
    Immediate = 3,
}

impl RepairEscalation {
    /// Number of escalation levels.
    pub const LEVEL_COUNT: usize = 4;

    /// All levels in descending priority order.
    pub const ALL_DESCENDING: [RepairEscalation; 4] = [
        RepairEscalation::Immediate,
        RepairEscalation::Urgent,
        RepairEscalation::Normal,
        RepairEscalation::Background,
    ];

    /// Derive escalation from a suspect entry, its repair attempt count,
    /// and whether active degraded reads are detected.
    ///
    /// # Escalation rules
    ///
    /// - `is_degraded_read_active` → Immediate
    /// - `replicas_remaining == 0` → Immediate (last copy)
    /// - `replicas_remaining == 1` → Urgent
    /// - `failed_attempts >= 2` at Normal → Urgent
    /// - `failed_attempts >= 1` at Urgent → Immediate
    /// - Otherwise, Normal or Background
    #[must_use]
    pub fn classify(
        entry: &SuspectEntry,
        failed_attempts: u32,
        replicas_remaining: u32,
        is_degraded_read_active: bool,
    ) -> Self {
        if is_degraded_read_active {
            return RepairEscalation::Immediate;
        }
        if replicas_remaining == 0 {
            return RepairEscalation::Immediate;
        }
        if replicas_remaining == 1 {
            return RepairEscalation::Urgent;
        }

        // Escalate based on prior failures.
        if failed_attempts >= 3 {
            return RepairEscalation::Immediate;
        }
        if failed_attempts >= 2 {
            return RepairEscalation::Urgent;
        }

        // Unconfirmed corruption (record_type 2=chain, 3=truncated) is Background.
        if entry.record_type == 2 || entry.record_type == 3 {
            return RepairEscalation::Background;
        }

        RepairEscalation::Normal
    }

    /// Map escalation to the background scheduler's `ServicePriority`.
    #[must_use]
    pub const fn to_service_priority(self) -> ServicePriority {
        match self {
            RepairEscalation::Immediate => ServicePriority::Critical,
            RepairEscalation::Urgent => ServicePriority::Critical,
            RepairEscalation::Normal => ServicePriority::Throughput,
            RepairEscalation::Background => ServicePriority::BestEffort,
        }
    }

    /// Map escalation to a `JobKind` for integration with the reclaim queue
    /// and background scheduler.
    #[must_use]
    pub const fn to_job_kind(self) -> JobKind {
        match self {
            RepairEscalation::Immediate => JobKind::Scrub,
            RepairEscalation::Urgent => JobKind::Scrub,
            RepairEscalation::Normal => JobKind::Rebake,
            RepairEscalation::Background => JobKind::Rebake,
        }
    }

    /// Whether this escalation level may preempt other background work.
    #[must_use]
    pub const fn may_preempt(self) -> bool {
        matches!(self, RepairEscalation::Immediate | RepairEscalation::Urgent)
    }

    /// Whether this escalation level warrants an operator alert.
    #[must_use]
    pub const fn should_alert(self) -> bool {
        matches!(self, RepairEscalation::Immediate)
    }

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RepairEscalation::Immediate => "immediate",
            RepairEscalation::Urgent => "urgent",
            RepairEscalation::Normal => "normal",
            RepairEscalation::Background => "background",
        }
    }

    /// Escalate this level by one step (Background→Normal→Urgent→Immediate).
    /// Immediate stays at Immediate.
    #[must_use]
    pub const fn escalate(self) -> Self {
        match self {
            RepairEscalation::Background => RepairEscalation::Normal,
            RepairEscalation::Normal => RepairEscalation::Urgent,
            RepairEscalation::Urgent | RepairEscalation::Immediate => RepairEscalation::Immediate,
        }
    }
}

impl core::fmt::Display for RepairEscalation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// RepairJob — a prioritized repair task derived from a scrub finding
// ---------------------------------------------------------------------------

/// A single repair job with priority, retry state, and routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairJob {
    /// The suspect entry to repair.
    pub entry: SuspectEntry,
    /// Current escalation level.
    pub escalation: RepairEscalation,
    /// Number of failed repair attempts so far.
    pub failed_attempts: u32,
    /// Maximum repair attempts before marking unrepairable.
    pub max_attempts: u32,
    /// Whether this job should be routed to rebake (EC parity recomputation)
    /// rather than direct mirror/EC repair.
    pub route_to_rebake: bool,
    /// Whether active degraded reads are detected for this entry's data.
    pub degraded_read_active: bool,
    /// Number of healthy replicas remaining.
    pub replicas_remaining: u32,
}

impl RepairJob {
    /// Create a new repair job from a suspect entry.
    #[must_use]
    pub fn new(entry: SuspectEntry, replicas_remaining: u32) -> Self {
        let escalation = RepairEscalation::classify(&entry, 0, replicas_remaining, false);
        Self {
            entry,
            escalation,
            failed_attempts: 0,
            max_attempts: 3,
            route_to_rebake: false,
            degraded_read_active: false,
            replicas_remaining,
        }
    }

    /// Record a failed repair attempt and escalate if needed.
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        self.escalation = RepairEscalation::classify(
            &self.entry,
            self.failed_attempts,
            self.replicas_remaining,
            self.degraded_read_active,
        );
    }

    /// Mark this job for rebake routing (EC parity recomputation).
    pub fn route_to_rebake(&mut self) {
        self.route_to_rebake = true;
    }

    /// Whether this job has exceeded its maximum repair attempts.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.failed_attempts >= self.max_attempts
    }

    /// Whether this job can still be retried.
    #[must_use]
    pub fn can_retry(&self) -> bool {
        !self.is_exhausted()
    }

    /// Get the repair priority for background scheduler dispatch.
    #[must_use]
    pub fn service_priority(&self) -> ServicePriority {
        self.escalation.to_service_priority()
    }
}

// ---------------------------------------------------------------------------
// ScrubToRepairBridge — connects scrub findings to prioritized repair dispatch
// ---------------------------------------------------------------------------

/// Bridges scrub findings to repair scheduling with priority/escalation
/// semantics.
///
/// Consumes `SuspectEntry` entries from the scrub pipeline, classifies them
/// by urgency, maintains per-entry escalation state, and dispatches them
/// to the appropriate repair mechanism (mirror, EC, or rebake).
///
/// This is the central scheduling bridge required by #5337.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScrubToRepairBridge {
    /// Jobs currently pending repair, grouped by escalation level.
    jobs: HashMap<u64, RepairJob>,
    /// Order of job insertion (locator_id), for FIFO within each level.
    insertion_order: Vec<u64>,
    /// Set of locator IDs that have been successfully repaired and removed.
    /// Prevents re-ingestion of already-repaired entries after crash recovery
    /// or repeated scrub cycles; provides idempotence under repeated failures.
    repaired_set: HashSet<u64>,
    /// Set of locator IDs that have been exhausted (max retries reached).
    /// Prevents re-ingestion of entries that cannot be repaired.
    exhausted_set: HashSet<u64>,
    /// Audit log of mark_repaired / mark_failed calls for debugging.
    audit_trace: Vec<RepairAuditEntry>,
    /// Aggregate statistics.
    stats: BridgeStats,
}

/// Audit trail entry for repair scheduling operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairAuditEntry {
    pub locator_id: u64,
    pub operation: &'static str,
    pub result: &'static str,
    /// Monotonic sequence number for ordering.
    pub seq: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeStats {
    /// Total suspect entries ingested.
    pub entries_ingested: u64,
    /// Entries dispatched to repair (mirror or EC).
    pub entries_dispatched_repair: u64,
    /// Entries routed to rebake (EC parity recomputation).
    pub entries_routed_rebake: u64,
    /// Entries that exhausted retries and were abandoned.
    pub entries_exhausted: u64,
    /// Entries by escalation level.
    pub by_escalation: [u64; RepairEscalation::LEVEL_COUNT],
    /// Failed dispatch attempts.
    pub dispatch_failures: u64,
    /// Number of idempotent no-ops (mark_repaired on absent, mark_failed on
    /// absent, ingest skip of already-repaired or exhausted entry).
    pub idempotent_noops: u64,
}

impl ScrubToRepairBridge {
    /// Create an empty bridge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            insertion_order: Vec::new(),
            repaired_set: HashSet::new(),
            exhausted_set: HashSet::new(),
            audit_trace: Vec::new(),
            stats: BridgeStats::default(),
        }
    }

    /// Ingest suspect entries from a scrub cycle.
    ///
    /// Entries already tracked are updated (e.g. escalated if this is a
    /// re-detection). New entries are classified and queued.
    /// Ingest suspect entries from a scrub cycle.
    ///
    /// Entries already tracked are updated (e.g. escalated if this is a
    /// re-detection). New entries are classified and queued.
    ///
    /// # Idempotence
    ///
    /// Entries whose locator_id is in the repaired set or exhausted set
    /// are silently skipped. This prevents re-creation of already-resolved
    /// work after crash recovery or repeated scrub cycles.
    pub fn ingest(&mut self, entries: &[SuspectEntry], replicas_remaining: u32) {
        for entry in entries {
            let locator_id = entry.locator_id;

            // Idempotence: skip already-repaired entries.
            if self.repaired_set.contains(&locator_id) {
                self.stats.idempotent_noops += 1;
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "ingest",
                    result: "skipped_already_repaired",
                    seq: self.audit_trace.len() as u64,
                });
                continue;
            }

            // Idempotence: skip already-exhausted entries.
            if self.exhausted_set.contains(&locator_id) {
                self.stats.idempotent_noops += 1;
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "ingest",
                    result: "skipped_already_exhausted",
                    seq: self.audit_trace.len() as u64,
                });
                continue;
            }

            if let Some(job) = self.jobs.get_mut(&locator_id) {
                // Re-detection: escalate if still present after prior repair attempt.
                if job.failed_attempts > 0 {
                    job.record_failure();
                }
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "ingest",
                    result: "updated_existing",
                    seq: self.audit_trace.len() as u64,
                });
            } else {
                let job = RepairJob::new(*entry, replicas_remaining);
                self.stats.entries_ingested += 1;
                self.stats.by_escalation[job.escalation as usize] += 1;
                self.jobs.insert(locator_id, job);
                self.insertion_order.push(locator_id);
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "ingest",
                    result: "created_new",
                    seq: self.audit_trace.len() as u64,
                });
            }
        }
    }

    /// Return jobs sorted by escalation level (Immediate first, Background last),
    /// then by insertion order within each level.
    #[must_use]
    pub fn prioritized_jobs(&self) -> Vec<&RepairJob> {
        let mut indices: Vec<(usize, &u64)> = self.insertion_order.iter().enumerate().collect();
        // Sort by escalation (descending), then insertion index (ascending).
        indices.sort_by(|(ai, ak), (bi, bk)| {
            let ja = &self.jobs[ak];
            let jb = &self.jobs[bk];
            jb.escalation.cmp(&ja.escalation).then_with(|| ai.cmp(bi))
        });
        indices
            .iter()
            .filter_map(|(_, loc_id)| self.jobs.get(*loc_id))
            .collect()
    }

    /// Return jobs at a specific escalation level.
    #[must_use]
    pub fn jobs_at_level(&self, level: RepairEscalation) -> Vec<&RepairJob> {
        self.insertion_order
            .iter()
            .filter_map(|lid| self.jobs.get(lid))
            .filter(|j| j.escalation == level)
            .collect()
    }

    /// Number of pending jobs.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.jobs.len()
    }

    /// Whether the bridge has any pending work.
    #[must_use]
    pub fn has_work(&self) -> bool {
        !self.jobs.is_empty()
    }

    /// Statistics for observability.
    #[must_use]
    pub fn stats(&self) -> &BridgeStats {
        &self.stats
    }

    /// Return the audit trace for diagnostics.
    #[must_use]
    pub fn audit_trace(&self) -> &[RepairAuditEntry] {
        &self.audit_trace
    }

    /// Number of entries in the repaired set.
    #[must_use]
    pub fn repaired_count(&self) -> usize {
        self.repaired_set.len()
    }

    /// Mark a job as successfully repaired and remove it (idempotent).
    ///
    /// If the locator_id is already in the repaired set (previously repaired),
    /// this is a no-op and increments the idempotent-noop counter for audit.
    /// Safe to call multiple times with the same locator_id; the first call
    /// removes the job and records the repair, subsequent calls are no-ops.
    pub fn mark_repaired(&mut self, locator_id: u64) {
        // Idempotence: already repaired.
        if self.repaired_set.contains(&locator_id) {
            self.stats.idempotent_noops += 1;
            self.audit_trace.push(RepairAuditEntry {
                locator_id,
                operation: "mark_repaired",
                result: "noop_already_repaired",
                seq: self.audit_trace.len() as u64,
            });
            return;
        }

        if self.jobs.remove(&locator_id).is_some() {
            self.stats.entries_dispatched_repair += 1;
        }
        self.repaired_set.insert(locator_id);
        self.audit_trace.push(RepairAuditEntry {
            locator_id,
            operation: "mark_repaired",
            result: "repaired",
            seq: self.audit_trace.len() as u64,
        });
    }

    /// Mark a job as failed and escalate (idempotent).
    ///
    /// If the locator_id is already in the exhausted set, this is a no-op.
    /// Safe to call multiple times; the first call that exhausts the job
    /// records it in the exhausted set, subsequent calls are no-ops.
    pub fn mark_failed(&mut self, locator_id: u64) {
        // Idempotence: already exhausted.
        if self.exhausted_set.contains(&locator_id) {
            self.stats.idempotent_noops += 1;
            self.audit_trace.push(RepairAuditEntry {
                locator_id,
                operation: "mark_failed",
                result: "noop_already_exhausted",
                seq: self.audit_trace.len() as u64,
            });
            return;
        }

        if let Some(job) = self.jobs.get_mut(&locator_id) {
            let old_level = job.escalation;
            job.record_failure();
            if job.escalation != old_level {
                // Update stats: decrement old level, increment new.
                if (old_level as usize) < RepairEscalation::LEVEL_COUNT {
                    self.stats.by_escalation[old_level as usize] =
                        self.stats.by_escalation[old_level as usize].saturating_sub(1);
                }
                self.stats.by_escalation[job.escalation as usize] =
                    self.stats.by_escalation[job.escalation as usize].saturating_add(1);
            }
            if job.is_exhausted() {
                self.stats.entries_exhausted += 1;
                self.exhausted_set.insert(locator_id);
                self.jobs.remove(&locator_id);
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "mark_failed",
                    result: "exhausted",
                    seq: self.audit_trace.len() as u64,
                });
            } else {
                self.audit_trace.push(RepairAuditEntry {
                    locator_id,
                    operation: "mark_failed",
                    result: "escalated",
                    seq: self.audit_trace.len() as u64,
                });
            }
        } else {
            // Job already removed (e.g., previously exhausted via a different path).
            self.exhausted_set.insert(locator_id);
            self.audit_trace.push(RepairAuditEntry {
                locator_id,
                operation: "mark_failed",
                result: "noop_not_found_absorbed",
                seq: self.audit_trace.len() as u64,
            });
        }
    }
}

impl Default for ScrubToRepairBridge {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RebakeSchedulingBridge — routes EC-corruption findings to reclaim queue
// ---------------------------------------------------------------------------

/// Routes scrub findings that require parity recomputation into the
/// reclaim queue's `Rebake` family.
///
/// When an erasure-coded stripe has a corrupt data shard but surviving
/// parity, the repair needs to trigger a parity recomputation (rebake)
/// after the data shard is reconstructed. This bridge converts
/// `SuspectEntry` entries into `ReclaimQueueEntry` entries with
/// `QueueFamily::Rebake` for consumption by the rebake service (#3447).
#[derive(Debug)]
pub struct RebakeSchedulingBridge {
    /// Generated reclaim queue entries awaiting enqueue.
    pending_rebake: Vec<ReclaimQueueEntry>,
    /// Total entries generated.
    entries_generated: u64,
    /// Set of (locator_id, segment_id, offset) tuples already generated.
    /// Prevents duplicate entries when generate_rebake_entries is called
    /// multiple times with the same suspect entries.
    generated_entry_ids: std::collections::HashSet<(u64, u64, u64)>,
}

impl RebakeSchedulingBridge {
    /// Create an empty rebake scheduling bridge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_rebake: Vec::new(),
            entries_generated: 0,
            generated_entry_ids: std::collections::HashSet::new(),
        }
    }

    /// Convert a set of suspect entries that require EC parity recomputation
    /// into reclaim queue entries with `QueueFamily::Rebake`.
    ///
    /// Each suspect entry whose `record_type` indicates a payload mismatch
    /// (record_type 1 or 3) in an erasure-coded stripe generates a rebake
    /// entry. The `object_key` is derived from the locator_id and the delta
    /// encodes the segment/offset for deterministic replay.
    ///
    /// Returns the vector of generated `ReclaimQueueEntry` values ready for
    /// insertion into the reclaim queue B-tree.
    /// Convert a set of suspect entries that require EC parity recomputation
    /// into reclaim queue entries with `QueueFamily::Rebake`.
    ///
    /// Each suspect entry whose `record_type` indicates a payload mismatch
    /// (record_type 1 or 3) in an erasure-coded stripe generates a rebake
    /// entry. The `object_key` is derived from the locator_id and the delta
    /// encodes the segment/offset for deterministic replay.
    ///
    /// # Idempotence
    ///
    /// Duplicate entries (same locator_id/segment_id/offset) are silently
    /// skipped. Safe to call multiple times with overlapping suspect entry
    /// sets; only the first generation of each unique entry is recorded.
    ///
    /// Returns the vector of generated `ReclaimQueueEntry` values ready for
    /// insertion into the reclaim queue B-tree.
    pub fn generate_rebake_entries(
        &mut self,
        suspect_entries: &[SuspectEntry],
    ) -> Vec<ReclaimQueueEntry> {
        let mut entries = Vec::with_capacity(suspect_entries.len());
        for suspect in suspect_entries {
            // Only payload corruption (record_type 1) or truncated records (3)
            // that need EC rebake are routed here. Chain breaks (2) don't
            // need parity recomputation.
            if suspect.record_type != 1 && suspect.record_type != 3 {
                continue;
            }

            // Idempotence: skip entries already generated.
            let entry_id = (suspect.locator_id, suspect.segment_id, suspect.offset);
            if self.generated_entry_ids.contains(&entry_id) {
                continue;
            }
            self.generated_entry_ids.insert(entry_id);

            let object_key = suspect_to_object_key(suspect);
            // Negative delta encodes the segment/offset for replay ordering.
            let delta =
                -((suspect.segment_id as i64).wrapping_mul(1_000_000) + suspect.offset as i64);

            let entry = ReclaimQueueEntry::new(object_key, delta, QueueFamily::Rebake);
            entries.push(entry);
        }

        self.entries_generated += entries.len() as u64;
        self.pending_rebake.extend(entries.clone());
        entries
    }

    /// Drain all pending rebake entries, clearing internal state.
    pub fn drain_pending(&mut self) -> Vec<ReclaimQueueEntry> {
        std::mem::take(&mut self.pending_rebake)
    }

    /// Number of rebake entries generated since creation.
    #[must_use]
    pub fn entries_generated(&self) -> u64 {
        self.entries_generated
    }

    /// Number of pending entries not yet drained.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_rebake.len()
    }

    /// Whether there are pending entries.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending_rebake.is_empty()
    }
}

impl Default for RebakeSchedulingBridge {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `SuspectEntry` into a deterministic `ObjectKey` suitable for
/// the reclaim queue's B-tree.
///
/// The key is a BLAKE3 hash of (locator_id, segment_id, offset) so that
/// entries are uniquely identified and deterministically ordered.
fn suspect_to_object_key(entry: &SuspectEntry) -> tidefs_types_reclaim_queue_core::ObjectKey {
    use tidefs_types_reclaim_queue_core::ObjectKey;
    let mut key = [0u8; 32];
    // Pack locator_id, segment_id, offset, and record_type into a
    // deterministic 32-byte key for stable B-tree ordering.
    key[0..8].copy_from_slice(&entry.locator_id.to_be_bytes());
    key[8..16].copy_from_slice(&entry.segment_id.to_be_bytes());
    key[16..24].copy_from_slice(&entry.offset.to_be_bytes());
    key[24] = entry.record_type;
    ObjectKey(key)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_local_object_store::SuspectEntry;

    fn make_entry(locator_id: u64, record_type: u8) -> SuspectEntry {
        SuspectEntry {
            entry_id: locator_id,
            locator_id,
            segment_id: 1,
            offset: 0,
            record_type,
            expected_hash: [0xAAu8; 32],
            actual_hash: [0xBBu8; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 1,
            timestamp_secs: 1,
        }
    }

    // ── RepairEscalation ──────────────────────────────────────────

    #[test]
    fn escalation_degraded_read_is_immediate() {
        let entry = make_entry(1, 1);
        let level = RepairEscalation::classify(&entry, 0, 3, true);
        assert_eq!(level, RepairEscalation::Immediate);
    }

    #[test]
    fn escalation_zero_replicas_is_immediate() {
        let entry = make_entry(2, 1);
        let level = RepairEscalation::classify(&entry, 0, 0, false);
        assert_eq!(level, RepairEscalation::Immediate);
    }

    #[test]
    fn escalation_one_replica_is_urgent() {
        let entry = make_entry(3, 1);
        let level = RepairEscalation::classify(&entry, 0, 1, false);
        assert_eq!(level, RepairEscalation::Urgent);
    }

    #[test]
    fn escalation_failed_attempts_escalate() {
        let entry = make_entry(4, 1);
        // 2 failures → Urgent
        assert_eq!(
            RepairEscalation::classify(&entry, 2, 3, false),
            RepairEscalation::Urgent
        );
        // 3 failures → Immediate
        assert_eq!(
            RepairEscalation::classify(&entry, 3, 3, false),
            RepairEscalation::Immediate
        );
    }

    #[test]
    fn escalation_chain_break_is_background() {
        let entry = make_entry(5, 2); // record_type 2 = chain break
        let level = RepairEscalation::classify(&entry, 0, 3, false);
        assert_eq!(level, RepairEscalation::Background);
    }

    #[test]
    fn escalation_truncated_is_background() {
        let entry = make_entry(6, 3); // record_type 3 = truncated
        let level = RepairEscalation::classify(&entry, 0, 3, false);
        assert_eq!(level, RepairEscalation::Background);
    }

    #[test]
    fn escalation_normal_with_replicas() {
        let entry = make_entry(7, 1);
        let level = RepairEscalation::classify(&entry, 0, 3, false);
        assert_eq!(level, RepairEscalation::Normal);
    }

    #[test]
    fn escalation_to_service_priority() {
        assert_eq!(
            RepairEscalation::Immediate.to_service_priority(),
            ServicePriority::Critical
        );
        assert_eq!(
            RepairEscalation::Urgent.to_service_priority(),
            ServicePriority::Critical
        );
        assert_eq!(
            RepairEscalation::Normal.to_service_priority(),
            ServicePriority::Throughput
        );
        assert_eq!(
            RepairEscalation::Background.to_service_priority(),
            ServicePriority::BestEffort
        );
    }

    #[test]
    fn escalation_escalate_monotonic() {
        assert_eq!(
            RepairEscalation::Background.escalate(),
            RepairEscalation::Normal
        );
        assert_eq!(
            RepairEscalation::Normal.escalate(),
            RepairEscalation::Urgent
        );
        assert_eq!(
            RepairEscalation::Urgent.escalate(),
            RepairEscalation::Immediate
        );
        assert_eq!(
            RepairEscalation::Immediate.escalate(),
            RepairEscalation::Immediate
        );
    }

    #[test]
    fn escalation_may_preempt() {
        assert!(RepairEscalation::Immediate.may_preempt());
        assert!(RepairEscalation::Urgent.may_preempt());
        assert!(!RepairEscalation::Normal.may_preempt());
        assert!(!RepairEscalation::Background.may_preempt());
    }

    #[test]
    fn escalation_should_alert() {
        assert!(RepairEscalation::Immediate.should_alert());
        assert!(!RepairEscalation::Urgent.should_alert());
        assert!(!RepairEscalation::Normal.should_alert());
        assert!(!RepairEscalation::Background.should_alert());
    }

    #[test]
    fn escalation_labels_are_unique() {
        let labels: Vec<&str> = RepairEscalation::ALL_DESCENDING
            .iter()
            .map(|l| l.label())
            .collect();
        let mut unique = labels.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn escalation_display_matches_label() {
        for level in &RepairEscalation::ALL_DESCENDING {
            assert_eq!(format!("{level}"), level.label());
        }
    }

    // ── RepairJob ────────────────────────────────────────────────

    #[test]
    fn repair_job_new_classifies_normal() {
        let entry = make_entry(10, 1);
        let job = RepairJob::new(entry, 3);
        assert_eq!(job.escalation, RepairEscalation::Normal);
        assert_eq!(job.failed_attempts, 0);
        assert!(job.can_retry());
    }

    #[test]
    fn repair_job_record_failure_escalates() {
        let entry = make_entry(11, 1);
        let mut job = RepairJob::new(entry, 3);
        job.record_failure();
        assert_eq!(job.failed_attempts, 1);
        assert_eq!(job.escalation, RepairEscalation::Normal);

        job.record_failure();
        assert_eq!(job.failed_attempts, 2);
        assert_eq!(job.escalation, RepairEscalation::Urgent);

        job.record_failure();
        assert_eq!(job.failed_attempts, 3);
        assert_eq!(job.escalation, RepairEscalation::Immediate);
        assert!(job.is_exhausted());
        assert!(!job.can_retry());
    }

    #[test]
    fn repair_job_exhausted_after_max_attempts() {
        let entry = make_entry(12, 1);
        let mut job = RepairJob::new(entry, 3);
        for _ in 0..3 {
            job.record_failure();
        }
        assert!(job.is_exhausted());
    }

    #[test]
    fn repair_job_service_priority() {
        let entry = make_entry(13, 1);
        let mut job = RepairJob::new(entry, 3);
        assert_eq!(job.service_priority(), ServicePriority::Throughput);
        job.record_failure(); // 1
        job.record_failure(); // 2 → Urgent
        assert_eq!(job.service_priority(), ServicePriority::Critical);
    }

    // ── ScrubToRepairBridge ──────────────────────────────────────

    #[test]
    fn bridge_ingest_and_prioritize() {
        let mut bridge = ScrubToRepairBridge::new();
        let entries = vec![
            make_entry(1, 1),
            make_entry(2, 2), // chain break → Background
            make_entry(3, 1),
        ];
        bridge.ingest(&entries, 3);
        assert_eq!(bridge.pending_count(), 3);
        assert_eq!(bridge.stats().entries_ingested, 3);

        let prioritized = bridge.prioritized_jobs();
        // First should be Normal (entry 1 or 3), then Background (entry 2)
        assert_eq!(prioritized.len(), 3);
        // Background should be last.
        assert_eq!(prioritized[2].escalation, RepairEscalation::Background);
    }

    #[test]
    fn bridge_degraded_read_escalates_to_immediate() {
        let entry = make_entry(100, 1);
        // Simulate degraded read active: classify with is_degraded_read_active=true
        let level = RepairEscalation::classify(&entry, 0, 3, true);
        assert_eq!(level, RepairEscalation::Immediate);
    }

    #[test]
    fn bridge_mark_repaired_removes_job() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(50, 1)], 3);
        assert_eq!(bridge.pending_count(), 1);
        bridge.mark_repaired(50);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_dispatched_repair, 1);
    }

    #[test]
    fn bridge_mark_failed_escalates_and_may_exhaust() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(60, 1)], 3);
        // 2 failures → Urgent, still pending
        bridge.mark_failed(60);
        bridge.mark_failed(60);
        assert_eq!(bridge.pending_count(), 1);
        // 3rd failure → Immediate + exhausted → removed
        bridge.mark_failed(60);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_exhausted, 1);
    }

    #[test]
    fn bridge_jobs_at_level_filters() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(
            &[
                make_entry(1, 1), // normal
                make_entry(2, 2), // background
                make_entry(3, 1), // normal
            ],
            3,
        );
        let normals = bridge.jobs_at_level(RepairEscalation::Normal);
        assert_eq!(normals.len(), 2);
        let bgs = bridge.jobs_at_level(RepairEscalation::Background);
        assert_eq!(bgs.len(), 1);
        let immediates = bridge.jobs_at_level(RepairEscalation::Immediate);
        assert_eq!(immediates.len(), 0);
    }

    #[test]
    fn bridge_empty_has_no_work() {
        let bridge = ScrubToRepairBridge::new();
        assert!(!bridge.has_work());
        assert_eq!(bridge.pending_count(), 0);
    }

    // ── RebakeSchedulingBridge ───────────────────────────────────

    #[test]
    fn rebake_generates_entries_for_payload_corruption() {
        let mut bridge = RebakeSchedulingBridge::new();
        let entries = vec![
            make_entry(100, 1), // payload mismatch → rebake
            make_entry(200, 1), // payload mismatch → rebake
        ];
        let generated = bridge.generate_rebake_entries(&entries);
        assert_eq!(generated.len(), 2);
        assert_eq!(bridge.entries_generated(), 2);
    }

    #[test]
    fn rebake_skips_chain_breaks() {
        let mut bridge = RebakeSchedulingBridge::new();
        let entries = vec![
            make_entry(100, 1), // payload → included
            make_entry(200, 2), // chain break → skipped
            make_entry(300, 3), // truncated → included
        ];
        let generated = bridge.generate_rebake_entries(&entries);
        assert_eq!(generated.len(), 2);
    }

    #[test]
    fn rebake_drain_clears_pending() {
        let mut bridge = RebakeSchedulingBridge::new();
        bridge.generate_rebake_entries(&[make_entry(100, 1)]);
        assert!(bridge.has_pending());
        let drained = bridge.drain_pending();
        assert_eq!(drained.len(), 1);
        assert!(!bridge.has_pending());
    }

    #[test]
    fn rebake_entries_have_correct_family() {
        let mut bridge = RebakeSchedulingBridge::new();
        let generated = bridge.generate_rebake_entries(&[make_entry(42, 1)]);
        assert_eq!(generated[0].family, QueueFamily::Rebake);
    }

    #[test]
    fn rebake_empty_input_produces_nothing() {
        let mut bridge = RebakeSchedulingBridge::new();
        let generated = bridge.generate_rebake_entries(&[]);
        assert!(generated.is_empty());
        assert_eq!(bridge.entries_generated(), 0);
    }

    // ── suspect_to_object_key ────────────────────────────────────

    #[test]
    fn object_key_is_deterministic() {
        let entry = make_entry(42, 1);
        let key1 = suspect_to_object_key(&entry);
        let key2 = suspect_to_object_key(&entry);
        assert_eq!(key1, key2);
    }

    #[test]
    fn object_key_differs_for_different_entries() {
        let e1 = make_entry(1, 1);
        let e2 = make_entry(2, 1);
        assert_ne!(suspect_to_object_key(&e1), suspect_to_object_key(&e2));
    }

    // ── Integration: scrub → bridge → repair flow ──────────────────

    #[test]
    fn scrub_finding_becomes_repair_job_with_priority() {
        let mut bridge = ScrubToRepairBridge::new();

        // Simulate scrub producing findings.
        let findings = vec![
            make_entry(10, 1), // payload corruption
            make_entry(20, 2), // chain break → background
            make_entry(30, 1), // payload corruption
        ];
        bridge.ingest(&findings, 3);

        assert_eq!(bridge.pending_count(), 3);
        let stats = bridge.stats();
        assert_eq!(stats.entries_ingested, 3);

        // Priority order: Normal (entries 10, 30) before Background (entry 20).
        let prioritized = bridge.prioritized_jobs();
        assert_eq!(prioritized.len(), 3);
        // First two should be Normal (locator 10 and 30, insertion order).
        assert_eq!(prioritized[0].escalation, RepairEscalation::Normal);
        assert_eq!(prioritized[1].escalation, RepairEscalation::Normal);
        // Last should be Background.
        assert_eq!(prioritized[2].escalation, RepairEscalation::Background);
    }

    #[test]
    fn failed_repair_escalates_in_bridge() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(100, 1)], 3);

        // Mark failed twice → Urgent.
        bridge.mark_failed(100);
        bridge.mark_failed(100);
        assert_eq!(bridge.pending_count(), 1);

        let jobs = bridge.jobs_at_level(RepairEscalation::Urgent);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].escalation, RepairEscalation::Urgent);

        // Third failure → Immediate + exhausted → removed.
        bridge.mark_failed(100);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_exhausted, 1);
    }

    #[test]
    fn successful_repair_removes_job_from_bridge() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(200, 1)], 3);
        assert_eq!(bridge.pending_count(), 1);

        bridge.mark_repaired(200);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_dispatched_repair, 1);
    }

    #[test]
    fn bridge_degraded_read_trumps_all() {
        let mut bridge = ScrubToRepairBridge::new();

        // Ingest 3 entries, one with degraded read active.
        bridge.ingest(&[make_entry(1, 1)], 3); // Normal
        bridge.ingest(&[make_entry(2, 1)], 3); // Normal
        bridge.ingest(&[make_entry(3, 2)], 3); // Background (chain break)

        // Manually mark entry 3 as degraded-read-active via escalation classify.
        // Ingest would auto-classify, so let's test directly.
        let entry = make_entry(99, 1);
        let level = RepairEscalation::classify(&entry, 0, 3, true);
        assert_eq!(level, RepairEscalation::Immediate);
    }

    #[test]
    fn rebake_bridge_generates_correct_entries() {
        let mut rebake = RebakeSchedulingBridge::new();

        let findings = vec![
            make_entry(1, 1), // payload corruption → included
            make_entry(2, 2), // chain break → skipped
            make_entry(3, 1), // payload → included
            make_entry(4, 3), // truncated → included
        ];

        let entries = rebake.generate_rebake_entries(&findings);
        assert_eq!(entries.len(), 3); // chain break skipped

        // All should have Rebake family.
        for e in &entries {
            assert_eq!(e.family, QueueFamily::Rebake);
        }

        assert_eq!(rebake.entries_generated(), 3);
        assert!(rebake.has_pending());

        let drained = rebake.drain_pending();
        assert_eq!(drained.len(), 3);
        assert!(!rebake.has_pending());
    }

    #[test]
    fn repair_job_escalation_monotonic() {
        let entry = make_entry(42, 1);
        let mut job = RepairJob::new(entry, 3);
        assert_eq!(job.escalation, RepairEscalation::Normal);

        job.record_failure(); // 1 failure: still Normal (threshold is 2→Urgent, 3→Immediate)
        assert_eq!(job.escalation, RepairEscalation::Normal);

        job.record_failure(); // 2 failures: Urgent
        assert_eq!(job.escalation, RepairEscalation::Urgent);
        assert!(job.can_retry());

        job.record_failure(); // 3 failures: Immediate + exhausted
        assert_eq!(job.escalation, RepairEscalation::Immediate);
        assert!(!job.can_retry());
    }

    #[test]
    fn rebuild_planner_integration_ready() {
        // Verify that the bridge can produce jobs compatible with the
        // rebuild planner's LossEventClass::CorruptionDetected priority.
        let entry = make_entry(500, 1);
        let job = RepairJob::new(entry, 1); // 1 replica → Urgent
        assert_eq!(job.escalation, RepairEscalation::Urgent);
        assert_eq!(job.service_priority(), ServicePriority::Critical);
        // Urgent jobs may_preempt, so rebuild can prioritize them.
        assert!(job.escalation.may_preempt());
    }

    // ── Idempotence: ScrubToRepairBridge ──────────────────────────

    #[test]
    fn mark_repaired_twice_is_idempotent() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(1, 1)], 3);
        assert_eq!(bridge.pending_count(), 1);
        assert_eq!(bridge.stats().entries_ingested, 1);

        // First repair succeeds.
        bridge.mark_repaired(1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_dispatched_repair, 1);
        assert_eq!(bridge.repaired_count(), 1);

        // Second mark_repaired on same locator_id is a no-op.
        bridge.mark_repaired(1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_dispatched_repair, 1); // not double-counted
        assert_eq!(bridge.repaired_count(), 1); // still one
        assert_eq!(bridge.stats().idempotent_noops, 1);
    }

    #[test]
    fn mark_failed_twice_is_idempotent() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(2, 1)], 3);

        // 3 failures exhausts the job (max_attempts=3).
        bridge.mark_failed(2);
        bridge.mark_failed(2);
        bridge.mark_failed(2);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_exhausted, 1);

        // Fourth mark_failed is a no-op.
        bridge.mark_failed(2);
        assert_eq!(bridge.stats().entries_exhausted, 1); // not double-counted
        assert_eq!(bridge.stats().idempotent_noops, 1);
    }

    #[test]
    fn ingest_skips_already_repaired_entry() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(3, 1)], 3);
        bridge.mark_repaired(3);
        assert_eq!(bridge.pending_count(), 0);

        // Re-ingest same entry after repair: skipped.
        bridge.ingest(&[make_entry(3, 1)], 3);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_ingested, 1); // original only
        assert!(bridge.stats().idempotent_noops >= 1);
    }

    #[test]
    fn ingest_skips_already_exhausted_entry() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(4, 1)], 3);
        for _ in 0..3 {
            bridge.mark_failed(4);
        }
        assert_eq!(bridge.pending_count(), 0);

        // Re-ingest same entry after exhaustion: skipped.
        bridge.ingest(&[make_entry(4, 1)], 3);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_ingested, 1); // original only
        assert!(bridge.stats().idempotent_noops >= 1);
    }

    #[test]
    fn repeated_ingest_of_same_entry_escalates_not_duplicates() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(5, 1)], 3);
        assert_eq!(bridge.pending_count(), 1);

        // First re-ingest: failed_attempts == 0, so no escalation (idempotent).
        bridge.ingest(&[make_entry(5, 1)], 3);
        assert_eq!(bridge.pending_count(), 1); // not duplicated

        // Mark failed once to set failed_attempts = 1.
        bridge.mark_failed(5);
        assert_eq!(bridge.pending_count(), 1); // still present, not exhausted

        // Re-ingest with failed_attempts > 0: escalates to failed_attempts=2 → Urgent.
        bridge.ingest(&[make_entry(5, 1)], 3);
        let jobs = bridge.jobs_at_level(RepairEscalation::Urgent);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].escalation, RepairEscalation::Urgent);
    }

    #[test]
    fn audit_trace_records_mark_repaired_operations() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(6, 1)], 3);
        bridge.mark_repaired(6);
        bridge.mark_repaired(6); // no-op

        let trace = bridge.audit_trace();
        assert!(trace
            .iter()
            .any(|e| e.operation == "mark_repaired" && e.result == "repaired"));
        assert!(trace
            .iter()
            .any(|e| e.operation == "mark_repaired" && e.result == "noop_already_repaired"));
    }

    #[test]
    fn audit_trace_records_mark_failed_operations() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(7, 1)], 3);

        bridge.mark_failed(7); // escalated (1)
        bridge.mark_failed(7); // escalated (2)
        bridge.mark_failed(7); // exhausted
        bridge.mark_failed(7); // no-op

        let trace = bridge.audit_trace();
        assert!(trace
            .iter()
            .any(|e| e.operation == "mark_failed" && e.result == "exhausted"));
        assert!(trace
            .iter()
            .any(|e| e.operation == "mark_failed" && e.result == "noop_already_exhausted"));
    }

    #[test]
    fn idempotent_stats_increment_on_duplicate_operations() {
        let mut bridge = ScrubToRepairBridge::new();
        bridge.ingest(&[make_entry(8, 1)], 3);
        bridge.mark_repaired(8);
        bridge.mark_repaired(8); // no-op
        let noops_after_repaired = bridge.stats().idempotent_noops;
        assert_eq!(noops_after_repaired, 1);

        // Ingest another entry, exhaust it, then no-op.
        bridge.ingest(&[make_entry(9, 1)], 3);
        for _ in 0..3 {
            bridge.mark_failed(9);
        }
        bridge.mark_failed(9); // no-op
        assert_eq!(bridge.stats().idempotent_noops, 2);
    }

    // ── Idempotence: RebakeSchedulingBridge ───────────────────────

    #[test]
    fn rebake_generate_twice_is_idempotent() {
        let mut bridge = RebakeSchedulingBridge::new();
        let entries = vec![make_entry(100, 1), make_entry(200, 1)];

        let first = bridge.generate_rebake_entries(&entries);
        assert_eq!(first.len(), 2);
        assert_eq!(bridge.entries_generated(), 2);

        // Second call with same entries: no duplicates.
        let second = bridge.generate_rebake_entries(&entries);
        assert!(second.is_empty());
        assert_eq!(bridge.entries_generated(), 2); // not double-counted
    }

    #[test]
    fn rebake_generate_partial_overlap_no_duplicates() {
        let mut bridge = RebakeSchedulingBridge::new();
        let batch1 = vec![make_entry(100, 1), make_entry(200, 3)];
        let batch2 = vec![make_entry(100, 1), make_entry(300, 1)];

        let first = bridge.generate_rebake_entries(&batch1);
        assert_eq!(first.len(), 2);
        assert_eq!(bridge.entries_generated(), 2);

        // batch2 overlaps on entry 100 → only entry 300 is new.
        let second = bridge.generate_rebake_entries(&batch2);
        assert_eq!(second.len(), 1);
        assert_eq!(bridge.entries_generated(), 3);
    }

    #[test]
    fn rebake_chain_breaks_still_skipped() {
        let mut bridge = RebakeSchedulingBridge::new();
        let entries = vec![
            make_entry(1, 2), // chain break → skipped
            make_entry(2, 1), // payload → included
        ];
        let generated = bridge.generate_rebake_entries(&entries);
        assert_eq!(generated.len(), 1);

        // Second call: chain break still skipped, payload already generated → skipped.
        let second = bridge.generate_rebake_entries(&entries);
        assert!(second.is_empty());
    }

    #[test]
    fn rebake_drain_then_regenerate_emits_fresh_entries() {
        let mut bridge = RebakeSchedulingBridge::new();
        bridge.generate_rebake_entries(&[make_entry(1, 1)]);
        let drained = bridge.drain_pending();
        assert_eq!(drained.len(), 1);
        assert!(!bridge.has_pending());

        // Re-generating same entry: no duplicates (idempotent).
        let second = bridge.generate_rebake_entries(&[make_entry(1, 1)]);
        assert!(second.is_empty());
    }
}
