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

use std::{collections::BTreeMap, time::Instant};

use tidefs_performance_contract::{
    AdmissionCharge, AdmissionError, AdmissionPermit, DynamicAdmissionTuning, WriteAdmissionConfig,
    WriteAdmissionState, WriteAdmissionUsage,
};
use tidefs_storage_intent_core::{
    StorageIntentEvidenceId, StorageIntentEvidenceKind, StorageIntentEvidenceRef,
};

/// Version of the local dirty-write admission evidence family.
pub const LOCAL_DIRTY_WRITE_ADMISSION_EVIDENCE_VERSION: u16 = 1;

const LOCAL_DIRTY_WRITE_ADMISSION_EVIDENCE_SPEC: &str =
    "tidefs.local-dirty-write-admission-evidence.v1";

/// Runtime evidence for one accepted, still-active dirty-write permit.
///
/// The record is created only after the performance-contract admission state
/// accepts the charge. Callers must present an active permit with the recorded
/// id and charge to retrieve it; releasing the permit removes the record from
/// this admission owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalDirtyWriteAdmissionEvidence {
    permit_id: u64,
    charge: AdmissionCharge,
    config_at_admission: WriteAdmissionConfig,
    usage_after_admission: WriteAdmissionUsage,
    resource_budget_ref: StorageIntentEvidenceRef,
    admission_ref: StorageIntentEvidenceRef,
}

impl LocalDirtyWriteAdmissionEvidence {
    fn from_accepted_permit(
        permit: &AdmissionPermit,
        config_at_admission: WriteAdmissionConfig,
        usage_after_admission: WriteAdmissionUsage,
    ) -> Self {
        let permit_id = permit.id();
        let charge = permit.charge();
        Self {
            permit_id,
            charge,
            config_at_admission,
            usage_after_admission,
            resource_budget_ref: local_admission_evidence_ref(
                "resource-budget",
                permit_id,
                charge,
                config_at_admission,
                usage_after_admission,
            ),
            admission_ref: local_admission_evidence_ref(
                "accepted-permit",
                permit_id,
                charge,
                config_at_admission,
                usage_after_admission,
            ),
        }
    }

    /// Return the accepted permit id bound into this record.
    #[must_use]
    pub const fn permit_id(self) -> u64 {
        self.permit_id
    }

    /// Return the accepted charge bound into this record.
    #[must_use]
    pub const fn charge(self) -> AdmissionCharge {
        self.charge
    }

    /// Return the effective hard and soft caps observed at admission.
    #[must_use]
    pub const fn config_at_admission(self) -> WriteAdmissionConfig {
        self.config_at_admission
    }

    /// Return the bounded admission usage observed after accepting the permit.
    #[must_use]
    pub const fn usage_after_admission(self) -> WriteAdmissionUsage {
        self.usage_after_admission
    }

    /// Return the scheduler record naming the admitted resource budget.
    #[must_use]
    pub const fn resource_budget_ref(self) -> StorageIntentEvidenceRef {
        self.resource_budget_ref
    }

    /// Return the scheduler record naming the accepted permit decision.
    #[must_use]
    pub const fn admission_ref(self) -> StorageIntentEvidenceRef {
        self.admission_ref
    }

    /// Return true only when both the active permit id and charge match.
    #[must_use]
    pub fn matches_permit(&self, permit: &AdmissionPermit) -> bool {
        self.permit_id == permit.id() && self.charge == permit.charge()
    }
}

fn local_admission_evidence_ref(
    label: &str,
    permit_id: u64,
    charge: AdmissionCharge,
    config: WriteAdmissionConfig,
    usage: WriteAdmissionUsage,
) -> StorageIntentEvidenceRef {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LOCAL_DIRTY_WRITE_ADMISSION_EVIDENCE_SPEC.as_bytes());
    hasher.update(&[0]);
    hasher.update(label.as_bytes());
    hasher.update(&[0]);
    hasher.update(&permit_id.to_le_bytes());
    hasher.update(charge.work_class.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(charge.primary_domain.as_str().as_bytes());
    hasher.update(&[0]);
    hasher.update(&charge.dirty_bytes.to_le_bytes());
    hasher.update(&charge.dirty_ops.to_le_bytes());
    hasher.update(&charge.admitted_tick.to_le_bytes());
    hasher.update(&config.hard_max_dirty_bytes.to_le_bytes());
    hasher.update(&config.hard_max_dirty_ops.to_le_bytes());
    hasher.update(&config.hard_max_dirty_age_ticks.to_le_bytes());
    hasher.update(&config.hard_max_permits.to_le_bytes());
    hasher.update(&config.soft_max_dirty_bytes.to_le_bytes());
    hasher.update(&config.soft_max_dirty_ops.to_le_bytes());
    hasher.update(&config.soft_max_dirty_age_ticks.to_le_bytes());
    hasher.update(&usage.dirty_bytes.to_le_bytes());
    hasher.update(&usage.dirty_ops.to_le_bytes());
    hasher.update(&usage.outstanding_permits.to_le_bytes());
    match usage.oldest_dirty_tick {
        Some(tick) => {
            hasher.update(&[1]);
            hasher.update(&tick.to_le_bytes());
        }
        None => {
            hasher.update(&[0]);
            hasher.update(&0_u64.to_le_bytes());
        }
    }
    StorageIntentEvidenceRef::new(
        StorageIntentEvidenceKind::SchedulerAdmissionRecord,
        StorageIntentEvidenceId(*hasher.finalize().as_bytes()),
        permit_id,
        LOCAL_DIRTY_WRITE_ADMISSION_EVIDENCE_VERSION,
    )
}

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
/// admission: AdmissionPermit  service_curve: ServiceCurve
#[derive(Debug)]
pub struct LocalWriteAdmission {
    state: WriteAdmissionState,
    /// Evidence for accepted dirty-write permits that have not been released.
    /// This map is bounded by `WriteAdmissionConfig::hard_max_permits`.
    active_dirty_write_evidence: BTreeMap<u64, LocalDirtyWriteAdmissionEvidence>,
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
            active_dirty_write_evidence: BTreeMap::new(),
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
        let evidence = LocalDirtyWriteAdmissionEvidence::from_accepted_permit(
            &permit,
            self.state.config(),
            self.state.usage(),
        );
        let replaced = self
            .active_dirty_write_evidence
            .insert(permit.id(), evidence);
        debug_assert!(replaced.is_none(), "active admission permit ids are unique");
        Ok(permit)
    }

    /// Return admission evidence only for the exact still-active dirty permit.
    #[must_use]
    pub fn active_dirty_write_evidence(
        &self,
        permit: &AdmissionPermit,
    ) -> Option<&LocalDirtyWriteAdmissionEvidence> {
        self.active_dirty_write_evidence
            .get(&permit.id())
            .filter(|evidence| evidence.matches_permit(permit))
    }

    /// Try to admit a metadata-mutation charge for rename, link, unlink,
    /// or orphan-index operations.
    ///
    /// admission: AdmissionPermit  service_curve: ServiceCurve
    ///
    /// Metadata mutations are gated on permit count; they do not consume
    /// dirty-byte or dirty-op caps.  The returned [`AdmissionPermit`]
    /// should be pushed into a [`BudgetedQueue`] or released after the
    /// metadata mutation is durably committed.
    pub fn try_admit_metadata_mutation(&mut self) -> Result<AdmissionPermit, AdmissionError> {
        let permit = self.state.try_admit_metadata(self.current_tick)?;
        self.update_peaks();
        Ok(permit)
    }

    /// Release an admission permit, returning the released charge.
    ///
    /// Call this after the dirty work represented by the permit has
    /// been persisted (e.g., after a successful commit_group SYNC).
    pub fn release(&mut self, permit: AdmissionPermit) -> Result<AdmissionCharge, AdmissionError> {
        let permit_id = permit.id();
        let charge = self.state.release(permit)?;
        self.active_dirty_write_evidence.remove(&permit_id);
        Ok(charge)
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
    fn accepted_dirty_permit_exposes_bound_scheduler_evidence() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        admission.advance_tick();
        let permit = admission
            .try_admit_dirty_write(4096, 2)
            .expect("should admit dirty write");
        let evidence = *admission
            .active_dirty_write_evidence(&permit)
            .expect("accepted permit should expose evidence");

        assert!(evidence.matches_permit(&permit));
        assert_eq!(evidence.permit_id(), permit.id());
        assert_eq!(evidence.charge(), permit.charge());
        assert_eq!(evidence.config_at_admission(), admission.config());
        assert_eq!(evidence.usage_after_admission(), admission.usage());
        assert_eq!(
            evidence.resource_budget_ref().kind,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord
        );
        assert_eq!(
            evidence.admission_ref().kind,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord
        );
        assert!(evidence.resource_budget_ref().is_bound());
        assert!(evidence.admission_ref().is_bound());
        assert_ne!(evidence.resource_budget_ref(), evidence.admission_ref());
        assert_eq!(evidence.resource_budget_ref().generation, permit.id());
        assert_eq!(
            evidence.resource_budget_ref().version,
            LOCAL_DIRTY_WRITE_ADMISSION_EVIDENCE_VERSION
        );

        admission.release(permit).expect("should release permit");
    }

    #[test]
    fn dirty_permits_cannot_reuse_each_others_evidence() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        let first = admission
            .try_admit_dirty_write(4096, 1)
            .expect("should admit first write");
        let second = admission
            .try_admit_dirty_write(8192, 2)
            .expect("should admit second write");
        let first_evidence = *admission
            .active_dirty_write_evidence(&first)
            .expect("first permit should expose evidence");
        let second_evidence = *admission
            .active_dirty_write_evidence(&second)
            .expect("second permit should expose evidence");

        assert!(!first_evidence.matches_permit(&second));
        assert!(!second_evidence.matches_permit(&first));
        assert_ne!(
            first_evidence.resource_budget_ref(),
            second_evidence.resource_budget_ref()
        );
        assert_ne!(
            first_evidence.admission_ref(),
            second_evidence.admission_ref()
        );

        admission
            .release(first)
            .expect("should release first permit");
        admission
            .release(second)
            .expect("should release second permit");
    }

    #[test]
    fn permit_cap_rejection_creates_no_additional_evidence() {
        let caps = LocalAdmissionCaps {
            hard_max_permits: 1,
            ..Default::default()
        };
        let mut admission = LocalWriteAdmission::new(caps);
        let accepted = admission
            .try_admit_dirty_write(4096, 1)
            .expect("should admit first permit");
        assert_eq!(admission.active_dirty_write_evidence.len(), 1);

        let error = admission
            .try_admit_dirty_write(4096, 1)
            .expect_err("should reject second permit");
        assert!(matches!(error, AdmissionError::PermitHardCap { .. }));
        assert_eq!(admission.active_dirty_write_evidence.len(), 1);

        admission
            .release(accepted)
            .expect("should release accepted permit");
    }

    #[test]
    fn released_dirty_permit_no_longer_has_active_evidence() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        let permit = admission
            .try_admit_dirty_write(4096, 1)
            .expect("should admit dirty write");
        let permit_id = permit.id();
        assert!(admission
            .active_dirty_write_evidence
            .contains_key(&permit_id));

        admission.release(permit).expect("should release permit");

        assert!(!admission
            .active_dirty_write_evidence
            .contains_key(&permit_id));
    }

    #[test]
    fn metadata_permit_does_not_expose_dirty_write_evidence() {
        let mut admission = LocalWriteAdmission::new(LocalAdmissionCaps::default());
        let permit = admission
            .try_admit_metadata_mutation()
            .expect("should admit metadata mutation");

        assert!(admission.active_dirty_write_evidence(&permit).is_none());
        assert!(admission.active_dirty_write_evidence.is_empty());

        admission.release(permit).expect("should release permit");
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
