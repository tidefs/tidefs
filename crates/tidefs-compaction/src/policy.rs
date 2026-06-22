// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Authoritative compaction policy facade.
//!
//! The policy owns trigger admission, write-amplification caps, candidate
//! ordering, and testable decision reports for segment merge compaction.

use core::cmp::Ordering;

use tidefs_reclaim_queue_core::{SegmentLivenessEntry, SegmentLivenessQueue};
use tidefs_types_incremental_job_core::WorkBudget;

use crate::CompactionConfig;

/// Exact write-amplification ratio used for admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteAmplification {
    /// Bytes that would be read/rewritten from the source segment.
    pub numerator: u64,
    /// Bytes expected to be reclaimed if the source segment is released.
    pub denominator: u64,
}

impl WriteAmplification {
    /// Normal scheduled compaction cap: 2.0x.
    pub const SCHEDULED_CAP: Self = Self {
        numerator: 2,
        denominator: 1,
    };

    /// Pressure-escalated compaction cap: 4.0x.
    pub const PRESSURE_CAP: Self = Self {
        numerator: 4,
        denominator: 1,
    };

    /// Build a whole-number cap.
    #[must_use]
    pub const fn whole(value: u64) -> Self {
        Self {
            numerator: value,
            denominator: 1,
        }
    }

    /// Estimate `(live_bytes + dead_bytes) / dead_bytes`.
    #[must_use]
    pub fn from_live_dead(live_bytes: u64, dead_bytes: u64) -> Option<Self> {
        if dead_bytes == 0 {
            return None;
        }
        Some(Self {
            numerator: live_bytes.saturating_add(dead_bytes),
            denominator: dead_bytes,
        })
    }

    /// Floating representation for diagnostics.
    #[must_use]
    pub fn as_f64(self) -> f64 {
        self.numerator as f64 / self.denominator as f64
    }
}

impl Ord for WriteAmplification {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = self.numerator as u128 * other.denominator as u128;
        let rhs = other.numerator as u128 * self.denominator as u128;
        lhs.cmp(&rhs)
    }
}

impl PartialOrd for WriteAmplification {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Segment-cleaner pressure vocabulary accepted as compaction input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompactionPressureLevel {
    /// Free space is at or above the deferred watermark; use the scheduled cap.
    #[default]
    Deferred,
    /// Free space is below the automatic pressure watermark.
    Auto,
    /// Free space is below the urgent pressure watermark.
    Urgent,
}

/// Why this compaction tick exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CompactionTrigger {
    /// Ordinary scheduler tick. The scheduler supplies time/budget only.
    #[default]
    Scheduled,
    /// Space pressure escalated a tick, but the policy still owns admission.
    PressureEscalated(CompactionPressureLevel),
}

impl CompactionTrigger {
    /// Write-amplification cap for this trigger.
    #[must_use]
    pub const fn write_amplification_cap(self) -> WriteAmplification {
        match self {
            Self::Scheduled | Self::PressureEscalated(CompactionPressureLevel::Deferred) => {
                WriteAmplification::SCHEDULED_CAP
            }
            Self::PressureEscalated(
                CompactionPressureLevel::Auto | CompactionPressureLevel::Urgent,
            ) => WriteAmplification::PRESSURE_CAP,
        }
    }
}

/// Input supplied by the background scheduler or cleaner pressure path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionTriggerInput {
    /// Admission trigger for this tick.
    pub trigger: CompactionTrigger,
    /// Scheduler-supplied work budget. It bounds work but does not set policy.
    pub work_budget: WorkBudget,
}

impl CompactionTriggerInput {
    /// Scheduled best-effort compaction tick.
    #[must_use]
    pub const fn scheduled(work_budget: WorkBudget) -> Self {
        Self {
            trigger: CompactionTrigger::Scheduled,
            work_budget,
        }
    }

    /// Pressure-escalated compaction tick.
    #[must_use]
    pub const fn pressure_escalated(
        level: CompactionPressureLevel,
        work_budget: WorkBudget,
    ) -> Self {
        Self {
            trigger: CompactionTrigger::PressureEscalated(level),
            work_budget,
        }
    }

    /// Write-amplification cap for this input.
    #[must_use]
    pub const fn write_amplification_cap(self) -> WriteAmplification {
        self.trigger.write_amplification_cap()
    }
}

impl Default for CompactionTriggerInput {
    fn default() -> Self {
        Self::scheduled(WorkBudget::DEFAULT_TICK)
    }
}

/// Candidate admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionAdmissionDecision {
    /// Partial-live candidate admitted for merge compaction.
    Admitted,
    /// Fully dead segment belongs to the cleaner-only free path.
    CleanerOnlyFullyDead,
    /// Empty liveness record.
    RejectedEmpty,
    /// No reclaimable bytes; compaction would make no progress.
    RejectedNoReclaim,
    /// Live bytes are below the configured relocation floor.
    RejectedLiveBytesFloor,
    /// Estimated write amplification exceeds the active cap.
    RejectedWriteAmplificationCap,
    /// Configured batch size has already been filled.
    RejectedBatchLimit,
    /// Scheduler item budget has already been filled.
    RejectedItemBudget,
    /// Relocated-live-byte budget would be exceeded.
    RejectedRelocateBudget,
}

/// Candidate admitted by policy in deterministic merge order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionPolicyCandidate {
    /// Source segment identifier.
    pub segment_id: u64,
    /// Bytes that must be relocated.
    pub live_bytes: u64,
    /// Bytes expected to be reclaimed.
    pub dead_bytes: u64,
    /// Total accounted bytes in the source segment.
    pub total_bytes: u64,
    /// Source creation transaction group; lower means older.
    pub creation_commit_group: u64,
    /// Exact estimated write amplification.
    pub write_amplification: WriteAmplification,
}

impl CompactionPolicyCandidate {
    fn from_entry(entry: SegmentLivenessEntry, write_amplification: WriteAmplification) -> Self {
        Self {
            segment_id: entry.segment_id,
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            total_bytes: entry.total_bytes(),
            creation_commit_group: entry.creation_commit_group,
            write_amplification,
        }
    }

    /// Bytes expected to be reclaimed if this segment is released.
    #[must_use]
    pub const fn reclaimable_bytes(self) -> u64 {
        self.dead_bytes
    }

    /// Bytes that must be relocated for this candidate.
    #[must_use]
    pub const fn relocation_cost_bytes(self) -> u64 {
        self.live_bytes
    }
}

impl Ord for CompactionPolicyCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.write_amplification
            .cmp(&other.write_amplification)
            .then_with(|| other.dead_bytes.cmp(&self.dead_bytes))
            .then_with(|| {
                self.creation_commit_group
                    .cmp(&other.creation_commit_group)
            })
            .then_with(|| self.segment_id.cmp(&other.segment_id))
    }
}

impl PartialOrd for CompactionPolicyCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Per-segment policy decision for report consumers and tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactionCandidateDecision {
    /// Source segment identifier.
    pub segment_id: u64,
    /// Bytes that would need relocation.
    pub live_bytes: u64,
    /// Bytes expected to be reclaimed.
    pub dead_bytes: u64,
    /// Total accounted bytes.
    pub total_bytes: u64,
    /// Source creation transaction group; lower means older.
    pub creation_commit_group: u64,
    /// Exact estimated write amplification when reclaimable bytes exist.
    pub write_amplification: Option<WriteAmplification>,
    /// Admission outcome.
    pub decision: CompactionAdmissionDecision,
}

impl CompactionCandidateDecision {
    fn new(
        entry: SegmentLivenessEntry,
        write_amplification: Option<WriteAmplification>,
        decision: CompactionAdmissionDecision,
    ) -> Self {
        Self {
            segment_id: entry.segment_id,
            live_bytes: entry.live_bytes,
            dead_bytes: entry.dead_bytes,
            total_bytes: entry.total_bytes(),
            creation_commit_group: entry.creation_commit_group,
            write_amplification,
            decision,
        }
    }
}

/// Testable report of policy admission for one tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactionPolicyReport {
    /// Trigger input used for this admission run.
    pub trigger_input: CompactionTriggerInput,
    /// Effective write-amplification cap.
    pub write_amplification_cap: WriteAmplification,
    /// Effective relocated-live-byte budget after scheduler and config caps.
    ///
    /// `0` means unbounded.
    pub effective_relocate_bytes_budget: u64,
    /// Per-segment decisions sorted by segment id for deterministic inspection.
    pub decisions: Vec<CompactionCandidateDecision>,
    /// Admitted partial-live candidates in authoritative merge order.
    pub admitted_candidates: Vec<CompactionPolicyCandidate>,
    /// Number of liveness records considered.
    pub candidates_considered: usize,
    /// Number of admitted partial-live candidates.
    pub candidates_admitted: usize,
    /// Fully dead segments excluded for cleaner-only freeing.
    pub cleaner_only_segments: usize,
    /// Empty records rejected.
    pub rejected_empty: usize,
    /// Records with no reclaimable bytes rejected.
    pub rejected_no_reclaim: usize,
    /// Records below the live-byte floor rejected.
    pub rejected_live_bytes_floor: usize,
    /// Records rejected by write-amplification cap.
    pub rejected_write_amplification: usize,
    /// Records rejected by configured batch size.
    pub rejected_batch_limit: usize,
    /// Records rejected by scheduler item budget.
    pub rejected_item_budget: usize,
    /// Records rejected by relocated-live-byte budget.
    pub rejected_relocate_budget: usize,
    /// Live bytes admitted for relocation.
    pub admitted_live_bytes: u64,
    /// Dead bytes expected to be reclaimed by admitted candidates.
    pub admitted_reclaimable_bytes: u64,
}

impl Default for CompactionPolicyReport {
    fn default() -> Self {
        let trigger_input = CompactionTriggerInput::default();
        Self {
            trigger_input,
            write_amplification_cap: trigger_input.write_amplification_cap(),
            effective_relocate_bytes_budget: 0,
            decisions: Vec::new(),
            admitted_candidates: Vec::new(),
            candidates_considered: 0,
            candidates_admitted: 0,
            cleaner_only_segments: 0,
            rejected_empty: 0,
            rejected_no_reclaim: 0,
            rejected_live_bytes_floor: 0,
            rejected_write_amplification: 0,
            rejected_batch_limit: 0,
            rejected_item_budget: 0,
            rejected_relocate_budget: 0,
            admitted_live_bytes: 0,
            admitted_reclaimable_bytes: 0,
        }
    }
}

/// Authoritative compaction admission and ordering policy.
#[derive(Clone, Debug, PartialEq)]
pub struct CompactionPolicy {
    config: CompactionConfig,
}

impl CompactionPolicy {
    /// Create a new policy facade.
    #[must_use]
    pub fn new(config: CompactionConfig) -> Self {
        Self { config }
    }

    /// Return the policy configuration.
    #[must_use]
    pub fn config(&self) -> &CompactionConfig {
        &self.config
    }

    /// Evaluate all entries in a queue.
    #[must_use]
    pub fn evaluate_queue(
        &self,
        queue: &SegmentLivenessQueue,
        trigger_input: CompactionTriggerInput,
    ) -> CompactionPolicyReport {
        let entries: Vec<_> = queue.entries().copied().collect();
        self.evaluate_entries(&entries, trigger_input)
    }

    /// Evaluate liveness entries for one tick.
    #[must_use]
    pub fn evaluate_entries(
        &self,
        entries: &[SegmentLivenessEntry],
        trigger_input: CompactionTriggerInput,
    ) -> CompactionPolicyReport {
        let cap = trigger_input.write_amplification_cap();
        let effective_budget = min_nonzero(
            self.config.max_relocate_bytes_per_tick,
            trigger_input.work_budget.max_bytes,
        );

        let mut static_decisions: Vec<CompactionCandidateDecision> = Vec::new();
        let mut eligible: Vec<CompactionPolicyCandidate> = Vec::new();

        for entry in entries {
            let entry = *entry;
            let total = entry.total_bytes();
            let write_amplification =
                WriteAmplification::from_live_dead(entry.live_bytes, entry.dead_bytes);

            if total == 0 {
                static_decisions.push(CompactionCandidateDecision::new(
                    entry,
                    write_amplification,
                    CompactionAdmissionDecision::RejectedEmpty,
                ));
                continue;
            }

            if entry.is_fully_dead() {
                static_decisions.push(CompactionCandidateDecision::new(
                    entry,
                    write_amplification,
                    CompactionAdmissionDecision::CleanerOnlyFullyDead,
                ));
                continue;
            }

            let Some(write_amplification) = write_amplification else {
                static_decisions.push(CompactionCandidateDecision::new(
                    entry,
                    None,
                    CompactionAdmissionDecision::RejectedNoReclaim,
                ));
                continue;
            };

            if entry.live_bytes < self.config.min_live_bytes {
                static_decisions.push(CompactionCandidateDecision::new(
                    entry,
                    Some(write_amplification),
                    CompactionAdmissionDecision::RejectedLiveBytesFloor,
                ));
                continue;
            }

            if write_amplification > cap {
                static_decisions.push(CompactionCandidateDecision::new(
                    entry,
                    Some(write_amplification),
                    CompactionAdmissionDecision::RejectedWriteAmplificationCap,
                ));
                continue;
            }

            eligible.push(CompactionPolicyCandidate::from_entry(
                entry,
                write_amplification,
            ));
        }

        eligible.sort();

        let mut admitted_candidates = Vec::new();
        let mut budgeted_decisions = Vec::new();
        let mut admitted_live_bytes = 0u64;

        for candidate in eligible {
            let decision = if admitted_candidates.len() >= self.config.batch_size {
                CompactionAdmissionDecision::RejectedBatchLimit
            } else if trigger_input.work_budget.max_items > 0
                && admitted_candidates.len() as u64 >= trigger_input.work_budget.max_items
            {
                CompactionAdmissionDecision::RejectedItemBudget
            } else {
                let projected = admitted_live_bytes.saturating_add(candidate.live_bytes);
                if effective_budget > 0 && projected > effective_budget {
                    CompactionAdmissionDecision::RejectedRelocateBudget
                } else {
                    admitted_live_bytes = projected;
                    admitted_candidates.push(candidate);
                    CompactionAdmissionDecision::Admitted
                }
            };

            budgeted_decisions.push(CompactionCandidateDecision {
                segment_id: candidate.segment_id,
                live_bytes: candidate.live_bytes,
                dead_bytes: candidate.dead_bytes,
                total_bytes: candidate.total_bytes,
                creation_commit_group: candidate.creation_commit_group,
                write_amplification: Some(candidate.write_amplification),
                decision,
            });
        }

        let mut decisions = static_decisions;
        decisions.extend(budgeted_decisions);
        decisions.sort_by(|a, b| a.segment_id.cmp(&b.segment_id));

        let mut report = CompactionPolicyReport {
            trigger_input,
            write_amplification_cap: cap,
            effective_relocate_bytes_budget: effective_budget,
            decisions,
            admitted_candidates,
            candidates_considered: entries.len(),
            ..CompactionPolicyReport::default()
        };

        report.candidates_admitted = report.admitted_candidates.len();
        report.admitted_live_bytes = report
            .admitted_candidates
            .iter()
            .map(|candidate| candidate.live_bytes)
            .sum();
        report.admitted_reclaimable_bytes = report
            .admitted_candidates
            .iter()
            .map(|candidate| candidate.dead_bytes)
            .sum();

        for decision in &report.decisions {
            match decision.decision {
                CompactionAdmissionDecision::Admitted => {}
                CompactionAdmissionDecision::CleanerOnlyFullyDead => {
                    report.cleaner_only_segments += 1;
                }
                CompactionAdmissionDecision::RejectedEmpty => {
                    report.rejected_empty += 1;
                }
                CompactionAdmissionDecision::RejectedNoReclaim => {
                    report.rejected_no_reclaim += 1;
                }
                CompactionAdmissionDecision::RejectedLiveBytesFloor => {
                    report.rejected_live_bytes_floor += 1;
                }
                CompactionAdmissionDecision::RejectedWriteAmplificationCap => {
                    report.rejected_write_amplification += 1;
                }
                CompactionAdmissionDecision::RejectedBatchLimit => {
                    report.rejected_batch_limit += 1;
                }
                CompactionAdmissionDecision::RejectedItemBudget => {
                    report.rejected_item_budget += 1;
                }
                CompactionAdmissionDecision::RejectedRelocateBudget => {
                    report.rejected_relocate_budget += 1;
                }
            }
        }

        report
    }
}

fn min_nonzero(left: u64, right: u64) -> u64 {
    match (left, right) {
        (0, 0) => 0,
        (0, value) | (value, 0) => value,
        (left, right) => left.min(right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: u64, live: u64, dead: u64) -> SegmentLivenessEntry {
        SegmentLivenessEntry::new(id, live, dead)
    }

    fn entry_with_txg(id: u64, live: u64, dead: u64, txg: u64) -> SegmentLivenessEntry {
        SegmentLivenessEntry::with_txg(id, live, dead, txg)
    }

    #[test]
    fn write_amplification_orders_exact_ratios() {
        let low = WriteAmplification::from_live_dead(10, 90).unwrap();
        let high = WriteAmplification::from_live_dead(60, 40).unwrap();

        assert!(low < high);
        assert!(low <= WriteAmplification::SCHEDULED_CAP);
        assert!(high <= WriteAmplification::PRESSURE_CAP);
        assert!(high > WriteAmplification::SCHEDULED_CAP);
    }

    #[test]
    fn scheduled_tick_uses_normal_write_amplification_cap() {
        let report = CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(
            &[entry(1, 60_000, 40_000), entry(2, 40_000, 60_000)],
            CompactionTriggerInput::scheduled(WorkBudget::DEFAULT_TICK),
        );

        assert_eq!(report.write_amplification_cap, WriteAmplification::SCHEDULED_CAP);
        assert_eq!(report.candidates_admitted, 1);
        assert_eq!(report.rejected_write_amplification, 1);
        assert_eq!(report.admitted_candidates[0].segment_id, 2);
    }

    #[test]
    fn pressure_tick_raises_admission_cap_without_unbounded_work() {
        let budget = WorkBudget {
            max_items: 10,
            max_bytes: 128_000,
            max_ms: 10,
        };
        let report = CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(
            &[entry(1, 60_000, 40_000), entry(2, 80_000, 20_000)],
            CompactionTriggerInput::pressure_escalated(CompactionPressureLevel::Auto, budget),
        );

        assert_eq!(report.write_amplification_cap, WriteAmplification::PRESSURE_CAP);
        assert_eq!(report.effective_relocate_bytes_budget, 128_000);
        assert_eq!(report.candidates_admitted, 1);
        assert_eq!(report.rejected_write_amplification, 1);
        assert_eq!(report.admitted_candidates[0].segment_id, 1);
    }

    #[test]
    fn fully_dead_segments_are_cleaner_only_not_merge_candidates() {
        let report = CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(
            &[entry(1, 0, 100_000), entry(2, 30_000, 70_000)],
            CompactionTriggerInput::default(),
        );

        assert_eq!(report.cleaner_only_segments, 1);
        assert_eq!(report.candidates_admitted, 1);
        assert_eq!(
            report.decisions[0].decision,
            CompactionAdmissionDecision::CleanerOnlyFullyDead
        );
    }

    #[test]
    fn admitted_candidates_are_ordered_by_cost_yield_age_and_id() {
        let report = CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(
            &[
                entry_with_txg(30, 30_000, 70_000, 9),
                entry_with_txg(20, 20_000, 80_000, 7),
                entry_with_txg(40, 20_000, 80_000, 3),
                entry_with_txg(10, 20_000, 80_000, 3),
            ],
            CompactionTriggerInput::default(),
        );

        let ids: Vec<_> = report
            .admitted_candidates
            .iter()
            .map(|candidate| candidate.segment_id)
            .collect();
        assert_eq!(ids, vec![10, 40, 20, 30]);
        assert_eq!(report.admitted_reclaimable_bytes, 310_000);
        assert_eq!(report.admitted_live_bytes, 90_000);
    }

    #[test]
    fn relocate_budget_rejects_candidates_after_positive_progress() {
        let budget = WorkBudget {
            max_items: 10,
            max_bytes: 55_000,
            max_ms: 10,
        };
        let report = CompactionPolicy::new(CompactionConfig::default()).evaluate_entries(
            &[entry(1, 30_000, 70_000), entry(2, 30_000, 80_000)],
            CompactionTriggerInput::scheduled(budget),
        );

        assert_eq!(report.candidates_admitted, 1);
        assert_eq!(report.rejected_relocate_budget, 1);
        assert_eq!(report.admitted_live_bytes, 30_000);
    }
}
