// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Runtime write-admission integration for local filesystem dirty paths.
//!
//! Wraps [`tidefs_performance_contract::WriteAdmissionState`] with
//! filesystem-local caps and queue-depth tracking. Every dirty byte/op
//! producer that contributes to the `perf.local.no_unbounded_dirty_debt.v1`
//! claim must acquire an [`AdmissionPermit`] through this module before
//! work enters any tracked queue or buffer.
//!
//! ## Authority Classification (per docs/cache-authority-model.md)
//!
//! This admission state is **Authoritative** for dirty-debt caps and
//! admission gating in the local-filesystem runtime.  It is the single
//! enforcement point for hard dirty byte/op/age/slot caps; every
//! write-path queue or buffer that carries dirty debt must route through
//! its permits.

use std::time::Instant;

use tidefs_performance_contract::{
    AdmissionCharge, AdmissionError, AdmissionPermit, DynamicAdmissionTuning, WriteAdmissionConfig,
    WriteAdmissionState, WriteAdmissionUsage,
};

/// Hard admission caps for a mounted local filesystem.
///
/// These caps are structural: they cannot be raised by runtime tuning,
/// compatibility defaults, or fallback paths.  The contract crate enforces
/// this by clamping every soft limit to the hard cap in
/// [`WriteAdmissionConfig::with_dynamic_tuning`].
#[derive(Clone, Copy, Debug)]
pub struct LocalAdmissionCaps {
    pub hard_max_dirty_bytes: u64,
    pub hard_max_dirty_ops: u32,
    pub hard_max_dirty_age_ticks: u64,
    pub hard_max_permits: u32,
}

impl Default for LocalAdmissionCaps {
    fn default() -> Self {
        Self {
            // 256 MiB dirty ceiling: large enough for typical local-fs
            // workloads but prevents unbounded dirty accumulation.
            hard_max_dirty_bytes: 256 * 1024 * 1024,
            // 4096 outstanding dirty ops before admission blocks.
            hard_max_dirty_ops: 4096,
            // 300 ticks (approx 5 minutes at 1s ticks) dirty-age cap.
            hard_max_dirty_age_ticks: 300,
            // 2048 concurrent permits; each permit conserves dirty debt.
            hard_max_permits: 2048,
        }
    }
}

/// Runtime write-admission state for the local filesystem.
///
/// tidefs-queue-root: local_fs.write_admission
/// admission: AdmissionPermit  service_curve: ServiceCurve
#[derive(Debug)]
pub struct LocalWriteAdmission {
    state: WriteAdmissionState,
    /// Tick counter incremented by the commit-group or writeback daemon.
    current_tick: u64,
    /// Bounded snapshot of the peak dirty-byte usage observed since the
    /// last snapshot was taken.  Used for runtime evidence artifacts.
    peak_dirty_bytes: u64,
    peak_dirty_ops: u32,
    peak_outstanding_permits: u32,
    last_snapshot: Instant,
}

impl LocalWriteAdmission {
    /// Construct a new admission state with the supplied hard caps.
    pub fn new(caps: LocalAdmissionCaps) -> Self {
        let config = WriteAdmissionConfig::new(
            caps.hard_max_dirty_bytes,
            caps.hard_max_dirty_ops,
            caps.hard_max_dirty_age_ticks,
            caps.hard_max_permits,
        );
        Self {
            state: WriteAdmissionState::new(config),
            current_tick: 0,
            peak_dirty_bytes: 0,
            peak_dirty_ops: 0,
            peak_outstanding_permits: 0,
            last_snapshot: Instant::now(),
        }
    }

    /// Advance the logical tick (called by commit-group or writeback timer).
    pub fn advance_tick(&mut self) {
        self.current_tick = self.current_tick.saturating_add(1);
    }

    /// Return the current logical tick.
    pub fn current_tick(&self) -> u64 {
        self.current_tick
    }

    /// Try to admit a dirty write charge at the current tick.
    ///
    /// Returns an [`AdmissionPermit`] that must be released or
    /// enqueued once the dirty work is persisted.  The permit is
    /// `#[must_use]` to prevent silent drops.
    pub fn try_admit_dirty_write(
        &mut self,
        dirty_bytes: u64,
        dirty_ops: u32,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let charge = AdmissionCharge::dirty_write(dirty_bytes, dirty_ops, self.current_tick);
        let permit = self.state.try_admit(charge)?;
        self.update_peaks();
        Ok(permit)
    }

    /// Try to admit a metadata-mutation charge for rename, link, unlink,
    /// or orphan-index operations.
    ///
    /// tidefs-queue-root: local_fs.metadata_mutation_admission
    /// admission: AdmissionPermit  service_curve: ServiceCurve
    ///
    /// Metadata mutations are gated on permit count; they do not consume
    /// dirty-byte or dirty-op caps.  The returned [`AdmissionPermit`]
    /// should be pushed into a [`BudgetedQueue`] or released after the
    /// metadata mutation is durably committed.
    pub fn try_admit_metadata_mutation(
        &mut self,
    ) -> Result<AdmissionPermit, AdmissionError> {
        let permit = self.state.try_admit_metadata(self.current_tick)?;
        self.update_peaks();
        Ok(permit)
    }

    /// Release an admission permit, returning the released charge.
    ///
    /// Call this after the dirty work represented by the permit has
    /// been persisted (e.g., after a successful commit_group SYNC).
    pub fn release(&mut self, permit: AdmissionPermit) -> Result<AdmissionCharge, AdmissionError> {
        self.state.release(permit)
    }

    /// Apply dynamic tuning while preserving hard caps.
    pub fn apply_dynamic_tuning(&mut self, tuning: DynamicAdmissionTuning) {
        self.state.apply_dynamic_tuning(tuning);
    }

    /// Return the current usage snapshot.
    pub fn usage(&self) -> WriteAdmissionUsage {
        self.state.usage()
    }

    /// Return the effective config (soft limits clamped to hard caps).
    pub fn config(&self) -> WriteAdmissionConfig {
        self.state.config()
    }

    /// Return true if the oldest dirty charge exceeds the age cap.
    pub fn dirty_age_exceeded(&self) -> bool {
        self.state.dirty_age_over_cap(self.current_tick)
    }

    // --- peak tracking for runtime evidence ---

    fn update_peaks(&mut self) {
        let u = self.state.usage();
        self.peak_dirty_bytes = self.peak_dirty_bytes.max(u.dirty_bytes);
        self.peak_dirty_ops = self.peak_dirty_ops.max(u.dirty_ops);
        self.peak_outstanding_permits = self.peak_outstanding_permits.max(u.outstanding_permits);
    }

    /// Take a bounded snapshot of peak usage since the last snapshot.
    ///
    /// Resets peaks after the snapshot so callers can poll bounded
    /// queue-depth evidence without unbounded memory growth.
    pub fn take_peak_snapshot(&mut self) -> AdmissionPeakSnapshot {
        let snap = AdmissionPeakSnapshot {
            peak_dirty_bytes: self.peak_dirty_bytes,
            peak_dirty_ops: self.peak_dirty_ops,
            peak_outstanding_permits: self.peak_outstanding_permits,
            current_dirty_bytes: self.state.usage().dirty_bytes,
            current_dirty_ops: self.state.usage().dirty_ops,
            current_outstanding_permits: self.state.usage().outstanding_permits,
            current_tick: self.current_tick,
            since: self.last_snapshot,
        };
        self.peak_dirty_bytes = 0;
        self.peak_dirty_ops = 0;
        self.peak_outstanding_permits = 0;
        self.last_snapshot = Instant::now();
        snap
    }
}

/// Bounded peak-usage snapshot suitable for runtime evidence artifacts.
#[derive(Clone, Copy, Debug)]
pub struct AdmissionPeakSnapshot {
    pub peak_dirty_bytes: u64,
    pub peak_dirty_ops: u32,
    pub peak_outstanding_permits: u32,
    pub current_dirty_bytes: u64,
    pub current_dirty_ops: u32,
    pub current_outstanding_permits: u32,
    pub current_tick: u64,
    pub since: Instant,
}

impl AdmissionPeakSnapshot {
    /// Serialize a minimal evidence record for validation artifacts.
    pub fn as_evidence_record(&self) -> AdmissionEvidenceRecord {
        AdmissionEvidenceRecord {
            peak_dirty_bytes: self.peak_dirty_bytes,
            peak_dirty_ops: self.peak_dirty_ops,
            peak_outstanding_permits: self.peak_outstanding_permits,
            current_dirty_bytes: self.current_dirty_bytes,
            current_dirty_ops: self.current_dirty_ops,
            current_outstanding_permits: self.current_outstanding_permits,
            current_tick: self.current_tick,
        }
    }
}

/// Serializable evidence record for claim artifacts.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct AdmissionEvidenceRecord {
    pub peak_dirty_bytes: u64,
    pub peak_dirty_ops: u32,
    pub peak_outstanding_permits: u32,
    pub current_dirty_bytes: u64,
    pub current_dirty_ops: u32,
    pub current_outstanding_permits: u32,
    pub current_tick: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_caps_are_nonzero() {
        let caps = LocalAdmissionCaps::default();
        assert!(caps.hard_max_dirty_bytes > 0);
        assert!(caps.hard_max_dirty_ops > 0);
        assert!(caps.hard_max_dirty_age_ticks > 0);
        assert!(caps.hard_max_permits > 0);
    }

    #[test]
    fn admit_and_release_single_write() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        let permit = admission
            .try_admit_dirty_write(4096, 1)
            .expect("should admit small write");
        let charge = admission.release(permit).expect("should release");
        assert_eq!(charge.dirty_bytes, 4096);
        assert_eq!(charge.dirty_ops, 1);
        let usage = admission.usage();
        assert_eq!(usage.dirty_bytes, 0);
        assert_eq!(usage.dirty_ops, 0);
    }

    #[test]
    fn hard_cap_blocks_excess_bytes() {
        let caps = LocalAdmissionCaps {
            hard_max_dirty_bytes: 1024,
            ..Default::default()
        };
        let mut admission = LocalWriteAdmission::new(caps);
        // First write fills the cap
        admission
            .try_admit_dirty_write(1024, 1)
            .expect("should admit up to cap");
        // Second write exceeds cap
        let err = admission
            .try_admit_dirty_write(1, 1)
            .expect_err("should reject over cap");
        assert!(matches!(err, AdmissionError::DirtyBytesHardCap { .. }));
    }

    #[test]
    fn dynamic_tuning_cannot_exceed_hard_caps() {
        let caps = LocalAdmissionCaps {
            hard_max_dirty_bytes: 4096,
            ..Default::default()
        };
        let mut admission = LocalWriteAdmission::new(caps);
        // Try to tune above hard cap
        admission.apply_dynamic_tuning(DynamicAdmissionTuning {
            max_dirty_bytes: 8192, // above hard cap
            max_dirty_ops: 100,
            max_dirty_age_ticks: 100,
        });
        let config = admission.config();
        // Effective cap must be clamped to hard cap
        assert_eq!(config.effective_max_dirty_bytes(), 4096);
    }

    #[test]
    fn peak_snapshot_resets_after_take() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        admission
            .try_admit_dirty_write(8192, 2)
            .expect("should admit");
        let snap1 = admission.take_peak_snapshot();
        assert!(snap1.peak_dirty_bytes >= 8192);
        // Peaks should be reset
        let snap2 = admission.take_peak_snapshot();
        assert_eq!(snap2.peak_dirty_bytes, 0);
    }

    #[test]
    fn tick_advances() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        assert_eq!(admission.current_tick(), 0);
        admission.advance_tick();
        assert_eq!(admission.current_tick(), 1);
    }

    #[test]
    fn zero_dirty_ops_is_rejected() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        let err = admission
            .try_admit_dirty_write(4096, 0)
            .expect_err("zero ops should be rejected");
        assert!(matches!(err, AdmissionError::ZeroDirtyOperations));
    }
}
