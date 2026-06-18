// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Quorum-level replica health aggregation.
//!
//! Collects `HealthSample` entries from a replica set after BLAKE3
//! verification, gates them on epoch freshness, and derives a
//! quorum-health status: Healthy, Degraded, Critical, or LossImminent.
//!
//! # Quorum semantics
//!
//! - **Healthy**: all epoch-valid replicas reported healthy. Stale
//!   replicas (epoch < current) are excluded entirely since they
//!   represent unknown health, not unhealthy health.
//! - **Degraded**: a majority (>50%) of epoch-valid replicas reported
//!   healthy; some are unhealthy. Writes can proceed, reads may retry.
//! - **Critical**: minority (<50%) of epoch-valid replicas healthy;
//!   below durability floor. Placement/rebuild should be triggered.
//! - **LossImminent**: zero epoch-valid replicas healthy; data loss
//!   is imminent or already occurring.
//!
//! # Epoch gating and repair-source evidence
//!
//! Samples with `epoch < quorum_epoch` are classified as stale for
//! health computation. Separately, each sample is assigned a
//! `ProbeEvidenceClass` based on receipt presence, epoch match, and
//! timestamp freshness. The quorum result exposes separate counters
//! for reachability, fresh repair evidence, stale evidence, and
//! missing evidence so consumers can distinguish reachable peers from
//! peers eligible as repair sources.

use crate::health_probe::{HealthSample, ProbeEvidenceClass};
use tidefs_membership_epoch::EpochId;

// ── Quorum health status ────────────────────────────────────────────

/// Aggregate health status of a replica set.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum QuorumHealthStatus {
    /// All epoch-valid replicas healthy.
    Healthy,
    /// Majority healthy; writes OK, reads may retry.
    Degraded,
    /// Minority healthy; below durability floor.
    Critical,
    /// Zero healthy replicas; data loss imminent.
    LossImminent,
}

impl QuorumHealthStatus {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            QuorumHealthStatus::Healthy => "healthy",
            QuorumHealthStatus::Degraded => "degraded",
            QuorumHealthStatus::Critical => "critical",
            QuorumHealthStatus::LossImminent => "loss_imminent",
        }
    }

    /// Whether this status allows normal write operations.
    pub fn can_write(&self) -> bool {
        matches!(
            self,
            QuorumHealthStatus::Healthy | QuorumHealthStatus::Degraded
        )
    }

    /// Whether this status should trigger placement/rebuild.
    pub fn needs_rebuild(&self) -> bool {
        matches!(
            self,
            QuorumHealthStatus::Critical | QuorumHealthStatus::LossImminent
        )
    }

    /// Whether an operator alert is warranted.
    pub fn is_alertable(&self) -> bool {
        matches!(self, QuorumHealthStatus::LossImminent)
    }
}

impl std::fmt::Display for QuorumHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Quorum aggregation result ───────────────────────────────────────

/// Result of a quorum health aggregation.
///
/// Carries both traditional healthy/unhealthy/stale counters and
/// evidence-class counters so consumers can distinguish reachability
/// from actionable repair-source eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumHealthResult {
    /// Computed quorum status.
    pub status: QuorumHealthStatus,
    /// Number of healthy samples (epoch-valid).
    pub healthy_count: usize,
    /// Number of unhealthy samples (epoch-valid but !healthy).
    pub unhealthy_count: usize,
    /// Number of stale samples rejected (epoch < quorum_epoch).
    pub stale_count: usize,
    /// Total replica set size (including stale).
    pub total_replicas: usize,
    /// Epoch used for gating.
    pub quorum_epoch: EpochId,
    /// Number of reachable replicas (all samples in the quorum).
    pub reachable_count: usize,
    /// Number of replicas with fresh repair-source evidence
    /// (receipt present, epoch >= quorum_epoch, timestamp fresh).
    pub fresh_repair_evidence_count: usize,
    /// Number of replicas with stale evidence (timestamp too old
    /// but receipt present and epoch valid).
    pub stale_evidence_count: usize,
    /// Number of replicas with missing evidence (no receipt, or
    /// epoch older than quorum epoch).
    pub missing_evidence_count: usize,
}

impl QuorumHealthResult {
    /// Fraction of healthy replicas among epoch-valid replicas, in [0.0, 1.0].
    pub fn healthy_fraction(&self) -> f64 {
        let valid = self.healthy_count + self.unhealthy_count;
        if valid == 0 {
            return 0.0;
        }
        self.healthy_count as f64 / valid as f64
    }

    /// Whether the quorum threshold is met for writes.
    pub fn quorum_met(&self) -> bool {
        self.status.can_write()
    }
}

// ── HealthQuorum ────────────────────────────────────────────────────

/// Aggregates health samples from a replica set and derives
/// quorum-level health status.
///
/// # Usage
///
/// ```ignore
/// let mut quorum = HealthQuorum::new();
/// quorum.add_sample(sample1);
/// quorum.add_sample(sample2);
/// let result = quorum.compute(EpochId::new(5), 0, 30_000_000_000);
/// if result.status.needs_rebuild() {
///     // trigger placement/rebuild
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct HealthQuorum {
    samples: Vec<HealthSample>,
}

impl HealthQuorum {
    /// Create an empty quorum tracker.
    pub fn new() -> Self {
        HealthQuorum {
            samples: Vec::new(),
        }
    }

    /// Create a tracker pre-populated with samples.
    pub fn with_samples(samples: Vec<HealthSample>) -> Self {
        HealthQuorum { samples }
    }

    /// Add a health sample to the quorum tracker.
    pub fn add_sample(&mut self, sample: HealthSample) {
        self.samples.push(sample);
    }

    /// Add multiple health samples.
    pub fn add_samples(&mut self, samples: impl IntoIterator<Item = HealthSample>) {
        self.samples.extend(samples);
    }

    /// Number of samples currently held.
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Clear all samples.
    pub fn clear(&mut self) {
        self.samples.clear();
    }

    /// Compute quorum health status for the given membership epoch.
    ///
    /// Samples with `epoch < quorum_epoch` are classified as stale and
    /// excluded from the healthy/unhealthy count. The quorum status is
    /// derived from the proportion of epoch-valid healthy samples to
    /// epoch-valid total.
    ///
    /// Evidence counters use `now_ns` and `staleness_threshold_ns`
    /// to classify each sample's `ProbeEvidenceClass` for repair-source
    /// eligibility tracking.
    pub fn compute(
        &self,
        quorum_epoch: EpochId,
        now_ns: u64,
        staleness_threshold_ns: u64,
    ) -> QuorumHealthResult {
        let total = self.samples.len();

        let mut healthy = 0usize;
        let mut unhealthy = 0usize;
        let mut stale = 0usize;

        let mut fresh_repair = 0usize;
        let mut stale_evidence = 0usize;
        let mut missing_evidence = 0usize;

        for sample in &self.samples {
            if !sample.is_epoch_valid(quorum_epoch) {
                stale += 1;
            } else if sample.healthy {
                healthy += 1;
            } else {
                unhealthy += 1;
            }

            let cls = sample.classify_evidence(quorum_epoch, now_ns, staleness_threshold_ns);
            match cls {
                ProbeEvidenceClass::FreshRepairEvidence => fresh_repair += 1,
                ProbeEvidenceClass::StaleEvidence => stale_evidence += 1,
                ProbeEvidenceClass::MissingReceiptEvidence
                | ProbeEvidenceClass::OlderEpochEvidence => missing_evidence += 1,
            }
        }

        let status = compute_quorum_status(healthy, unhealthy);

        QuorumHealthResult {
            status,
            healthy_count: healthy,
            unhealthy_count: unhealthy,
            stale_count: stale,
            total_replicas: total,
            quorum_epoch,
            reachable_count: total,
            fresh_repair_evidence_count: fresh_repair,
            stale_evidence_count: stale_evidence,
            missing_evidence_count: missing_evidence,
        }
    }

    /// Drain all samples and return them (useful for batch processing).
    pub fn drain_samples(&mut self) -> Vec<HealthSample> {
        std::mem::take(&mut self.samples)
    }
}

// ── Quorum computation logic ────────────────────────────────────────

/// Compute quorum health status from epoch-valid counts.
///
/// Stale replicas are excluded from the valid set entirely; they
/// represent unknown health (could be healthy, could be dead).
/// Only epoch-valid healthy and unhealthy counts factor into
/// the status.
fn compute_quorum_status(healthy: usize, unhealthy: usize) -> QuorumHealthStatus {
    let valid = healthy + unhealthy;

    if valid == 0 {
        // No epoch-valid attestations at all: data loss is imminent.
        return QuorumHealthStatus::LossImminent;
    }

    // All epoch-valid replicas are healthy
    if unhealthy == 0 {
        return QuorumHealthStatus::Healthy;
    }

    // Some unhealthy replicas exist.
    if healthy == 0 {
        return QuorumHealthStatus::LossImminent;
    }

    let majority = valid / 2 + 1;
    if healthy >= majority {
        QuorumHealthStatus::Degraded
    } else {
        QuorumHealthStatus::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health_probe::HealthSample;
    use tidefs_membership_epoch::EpochId;
    use tidefs_replication_model::ReplicatedReceiptId;

    fn healthy_sample(device_id: u64, epoch: u64, ts: u64) -> HealthSample {
        HealthSample {
            device_id,
            epoch: EpochId::new(epoch),
            healthy: true,
            timestamp_ns: ts,
            latency_ns: Some(100_000),
            receipt_id: None,
        }
    }

    fn unhealthy_sample(device_id: u64, epoch: u64, ts: u64) -> HealthSample {
        HealthSample {
            device_id,
            epoch: EpochId::new(epoch),
            healthy: false,
            timestamp_ns: ts,
            latency_ns: None,
            receipt_id: None,
        }
    }

    #[test]
    fn empty_quorum_is_loss_imminent() {
        let q = HealthQuorum::new();
        let result = q.compute(EpochId::new(1), 0, 30_000_000_000);
        assert_eq!(result.status, QuorumHealthStatus::LossImminent);
        assert_eq!(result.healthy_count, 0);
        assert_eq!(result.total_replicas, 0);
        assert_eq!(result.healthy_fraction(), 0.0);
    }

    #[test]
    fn single_healthy_replica_is_healthy() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        assert_eq!(result.status, QuorumHealthStatus::Healthy);
        assert_eq!(result.healthy_count, 1);
        assert_eq!(result.unhealthy_count, 0);
        assert_eq!(result.stale_count, 0);
    }

    #[test]
    fn single_unhealthy_replica_is_loss_imminent() {
        let mut q = HealthQuorum::new();
        q.add_sample(unhealthy_sample(1, 5, 1000));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        assert_eq!(result.status, QuorumHealthStatus::LossImminent);
        assert_eq!(result.healthy_count, 0);
        assert_eq!(result.unhealthy_count, 1);
    }

    #[test]
    fn majority_healthy_is_degraded() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        q.add_sample(unhealthy_sample(3, 5, 1000)); // 1/3 unhealthy
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 2/3 healthy = majority -> Degraded
        assert_eq!(result.status, QuorumHealthStatus::Degraded);
        assert!(result.quorum_met());
    }

    #[test]
    fn even_split_with_majority_is_degraded() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        q.add_sample(healthy_sample(3, 5, 1000));
        q.add_sample(unhealthy_sample(4, 5, 1000));
        q.add_sample(unhealthy_sample(5, 5, 1000)); // 3/5 healthy
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 3/5 = 60% > 50% -> Degraded
        assert_eq!(result.status, QuorumHealthStatus::Degraded);
    }

    #[test]
    fn minority_healthy_is_critical() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(unhealthy_sample(2, 5, 1000));
        q.add_sample(unhealthy_sample(3, 5, 1000)); // 1/3 healthy
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 1/3 < majority(2) -> Critical
        assert_eq!(result.status, QuorumHealthStatus::Critical);
        assert!(result.status.needs_rebuild());
        assert!(!result.quorum_met());
    }

    #[test]
    fn zero_healthy_is_loss_imminent() {
        let mut q = HealthQuorum::new();
        q.add_sample(unhealthy_sample(1, 5, 1000));
        q.add_sample(unhealthy_sample(2, 5, 1000));
        q.add_sample(unhealthy_sample(3, 5, 1000));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        assert_eq!(result.status, QuorumHealthStatus::LossImminent);
        assert!(result.status.is_alertable());
    }

    #[test]
    fn stale_samples_are_excluded_from_health_count() {
        let mut q = HealthQuorum::new();
        // Epoch-valid healthy
        q.add_sample(healthy_sample(1, 5, 1000));
        // Stale (epoch 3 < current 5) — excluded, not counted as unhealthy
        q.add_sample(healthy_sample(2, 3, 500));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        assert_eq!(result.healthy_count, 1);
        assert_eq!(result.unhealthy_count, 0);
        assert_eq!(result.stale_count, 1);
        assert_eq!(result.total_replicas, 2);
        // 1 epoch-valid healthy, 0 unhealthy — all valid are healthy
        assert_eq!(result.status, QuorumHealthStatus::Healthy);
    }

    #[test]
    fn all_stale_with_no_epoch_valid_is_loss_imminent() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 1, 100));
        q.add_sample(healthy_sample(2, 2, 200));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        assert_eq!(result.healthy_count, 0);
        assert_eq!(result.unhealthy_count, 0);
        assert_eq!(result.stale_count, 2);
        // No epoch-valid replicas at all
        assert_eq!(result.status, QuorumHealthStatus::LossImminent);
    }

    #[test]
    fn healthy_fraction_computes_correctly() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        q.add_sample(unhealthy_sample(3, 5, 1000));
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 2 healthy out of 3 valid = 0.666...
        assert!((result.healthy_fraction() - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn healthy_fraction_excludes_stale() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000)); // epoch-valid healthy
        q.add_sample(healthy_sample(2, 3, 500)); // stale
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 1 healthy / 1 valid = 1.0
        assert_eq!(result.healthy_fraction(), 1.0);
    }

    #[test]
    fn drain_samples_clears_and_returns() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        assert_eq!(q.sample_count(), 2);

        let drained = q.drain_samples();
        assert_eq!(drained.len(), 2);
        assert_eq!(q.sample_count(), 0);
    }

    #[test]
    fn add_samples_batch() {
        let mut q = HealthQuorum::new();
        let samples = vec![
            healthy_sample(1, 5, 1000),
            healthy_sample(2, 5, 1000),
            unhealthy_sample(3, 5, 1000),
        ];
        q.add_samples(samples);
        assert_eq!(q.sample_count(), 3);
    }

    #[test]
    fn clear_removes_all_samples() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.clear();
        assert_eq!(q.sample_count(), 0);
    }

    #[test]
    fn quorum_health_status_predicates() {
        assert!(QuorumHealthStatus::Healthy.can_write());
        assert!(QuorumHealthStatus::Degraded.can_write());
        assert!(!QuorumHealthStatus::Critical.can_write());
        assert!(!QuorumHealthStatus::LossImminent.can_write());

        assert!(!QuorumHealthStatus::Healthy.needs_rebuild());
        assert!(!QuorumHealthStatus::Degraded.needs_rebuild());
        assert!(QuorumHealthStatus::Critical.needs_rebuild());
        assert!(QuorumHealthStatus::LossImminent.needs_rebuild());

        assert!(!QuorumHealthStatus::Healthy.is_alertable());
        assert!(!QuorumHealthStatus::Degraded.is_alertable());
        assert!(!QuorumHealthStatus::Critical.is_alertable());
        assert!(QuorumHealthStatus::LossImminent.is_alertable());
    }

    #[test]
    fn quorum_health_status_display() {
        assert_eq!(QuorumHealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(QuorumHealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(QuorumHealthStatus::Critical.to_string(), "critical");
        assert_eq!(
            QuorumHealthStatus::LossImminent.to_string(),
            "loss_imminent"
        );
    }

    #[test]
    fn with_samples_constructor() {
        let samples = vec![healthy_sample(1, 5, 1000), healthy_sample(2, 5, 1000)];
        let q = HealthQuorum::with_samples(samples);
        assert_eq!(q.sample_count(), 2);
    }

    #[test]
    fn quorum_epoch_preserved_in_result() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 7, 1000));
        let result = q.compute(EpochId::new(7), 0, 30_000_000_000);
        assert_eq!(result.quorum_epoch, EpochId::new(7));
    }

    #[test]
    fn stale_unhealthy_does_not_make_healthy_degraded() {
        // Regression: a stale unhealthy sample should not make the
        // quorum appear degraded when all epoch-valid replicas are healthy.
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000)); // epoch-valid healthy
        q.add_sample(healthy_sample(2, 5, 1000)); // epoch-valid healthy
        q.add_sample(unhealthy_sample(3, 3, 500)); // stale (epoch 3 < 5)
        q.add_sample(unhealthy_sample(4, 4, 700)); // stale (epoch 4 < 5)
        let result = q.compute(EpochId::new(5), 0, 30_000_000_000);
        // 2 healthy, 0 unhealthy valid, 2 stale
        assert_eq!(result.healthy_count, 2);
        assert_eq!(result.unhealthy_count, 0);
        assert_eq!(result.stale_count, 2);
        assert_eq!(result.status, QuorumHealthStatus::Healthy);
    }

    // ── Evidence classification counter tests ───────────────────────

    fn sample_with_receipt(device_id: u64, epoch: u64, ts: u64, receipt: u64) -> HealthSample {
        HealthSample {
            device_id,
            epoch: EpochId::new(epoch),
            healthy: true,
            timestamp_ns: ts,
            latency_ns: Some(100_000),
            receipt_id: Some(ReplicatedReceiptId(receipt)),
        }
    }

    #[test]
    fn reachable_count_equals_total_samples() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        q.add_sample(unhealthy_sample(3, 5, 1000));
        let result = q.compute(EpochId::new(5), 2000, 30_000_000_000);
        assert_eq!(result.reachable_count, 3);
        assert_eq!(result.total_replicas, 3);
    }

    #[test]
    fn fresh_repair_evidence_counted() {
        let mut q = HealthQuorum::new();
        q.add_sample(sample_with_receipt(1, 5, 1000, 10));
        q.add_sample(sample_with_receipt(2, 5, 1000, 20));
        q.add_sample(healthy_sample(3, 5, 1000)); // no receipt
        let result = q.compute(EpochId::new(5), 2000, 30_000_000_000);
        assert_eq!(result.fresh_repair_evidence_count, 2);
        assert_eq!(result.missing_evidence_count, 1);
    }

    #[test]
    fn stale_evidence_counted() {
        let mut q = HealthQuorum::new();
        // Sample with receipt but timestamp is very old relative to now
        q.add_sample(sample_with_receipt(1, 5, 1000, 10));
        // now_ns = 20_000_000_000, timestamp = 1000, diff > threshold(5_000_000_000)
        let result = q.compute(EpochId::new(5), 20_000_000_000, 5_000_000_000);
        assert_eq!(result.stale_evidence_count, 1);
        assert_eq!(result.fresh_repair_evidence_count, 0);
        assert_eq!(result.reachable_count, 1);
    }

    #[test]
    fn older_epoch_evidence_counted_as_missing() {
        let mut q = HealthQuorum::new();
        // Only the older-epoch sample — to isolate the counter
        q.add_sample(sample_with_receipt(1, 3, 1000, 10)); // epoch 3 < 5
        let result = q.compute(EpochId::new(5), 2000, 30_000_000_000);
        assert_eq!(result.missing_evidence_count, 1);
        assert_eq!(result.fresh_repair_evidence_count, 0);
        assert_eq!(result.stale_evidence_count, 0);
    }

    #[test]
    fn missing_receipt_evidence_counted() {
        let mut q = HealthQuorum::new();
        q.add_sample(healthy_sample(1, 5, 1000));
        q.add_sample(healthy_sample(2, 5, 1000));
        let result = q.compute(EpochId::new(5), 2000, 30_000_000_000);
        assert_eq!(result.missing_evidence_count, 2);
        assert_eq!(result.fresh_repair_evidence_count, 0);
        assert_eq!(result.reachable_count, 2);
    }

    #[test]
    fn evidence_counters_sum_to_reachable() {
        let mut q = HealthQuorum::new();
        q.add_sample(sample_with_receipt(1, 5, 1000, 10)); // fresh
        q.add_sample(sample_with_receipt(2, 5, 100, 20));  // stale (old timestamp)
        q.add_sample(healthy_sample(3, 5, 1000));           // missing receipt
        q.add_sample(sample_with_receipt(4, 3, 1000, 30)); // older epoch → missing
        let result = q.compute(EpochId::new(5), 100000, 500);
        // 1 fresh, 1 stale, 2 missing = 4 reachable
        assert_eq!(result.reachable_count, 4);
        assert_eq!(
            result.fresh_repair_evidence_count
                + result.stale_evidence_count
                + result.missing_evidence_count,
            result.reachable_count
        );
    }

    #[test]
    fn recovery_from_stale_to_fresh_evidence() {
        let mut q = HealthQuorum::new();
        // First compute: stale evidence (old timestamp)
        q.add_sample(sample_with_receipt(1, 5, 1000, 10));
        let result1 = q.compute(EpochId::new(5), 20_000_000_000, 5_000_000_000);
        assert_eq!(result1.stale_evidence_count, 1);
        assert_eq!(result1.fresh_repair_evidence_count, 0);

        // Now update with fresh sample (recent timestamp)
        q.clear();
        q.add_sample(sample_with_receipt(1, 5, 20_000_000_000, 10));
        let result2 = q.compute(EpochId::new(5), 20_000_000_001, 5_000_000_000);
        assert_eq!(result2.stale_evidence_count, 0);
        assert_eq!(result2.fresh_repair_evidence_count, 1);
    }
}
