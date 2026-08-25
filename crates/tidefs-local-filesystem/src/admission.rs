// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Filesystem-owned admission for bounded local dirty work.
//!
//! This module is the mounted filesystem's runtime authority for hard dirty
//! byte, operation, age, and permit limits.  It deliberately does not depend
//! on development performance-policy types: the filesystem owns the counters
//! and permit identities that gate its own write and metadata mutation paths.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_LOCAL_ADMISSION_ISSUER_ID: AtomicU64 = AtomicU64::new(1);

const fn min_u64(left: u64, right: u64) -> u64 {
    if left < right {
        left
    } else {
        right
    }
}

const fn min_u32(left: u32, right: u32) -> u32 {
    if left < right {
        left
    } else {
        right
    }
}

/// Hard and tunable admission settings for one mounted local filesystem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAdmissionConfig {
    pub hard_max_dirty_bytes: u64,
    pub hard_max_dirty_ops: u32,
    pub hard_max_dirty_age_ticks: u64,
    pub hard_max_permits: u32,
    pub soft_max_dirty_bytes: u64,
    pub soft_max_dirty_ops: u32,
    pub soft_max_dirty_age_ticks: u64,
}

impl LocalAdmissionConfig {
    /// Construct a configuration whose tunable limits start at the hard caps.
    #[must_use]
    pub const fn new(
        hard_max_dirty_bytes: u64,
        hard_max_dirty_ops: u32,
        hard_max_dirty_age_ticks: u64,
        hard_max_permits: u32,
    ) -> Self {
        Self {
            hard_max_dirty_bytes,
            hard_max_dirty_ops,
            hard_max_dirty_age_ticks,
            hard_max_permits,
            soft_max_dirty_bytes: hard_max_dirty_bytes,
            soft_max_dirty_ops: hard_max_dirty_ops,
            soft_max_dirty_age_ticks: hard_max_dirty_age_ticks,
        }
    }

    /// Apply runtime tuning without allowing any hard cap to be raised.
    #[must_use]
    pub const fn with_dynamic_tuning(self, tuning: LocalAdmissionTuning) -> Self {
        Self {
            soft_max_dirty_bytes: min_u64(tuning.max_dirty_bytes, self.hard_max_dirty_bytes),
            soft_max_dirty_ops: min_u32(tuning.max_dirty_ops, self.hard_max_dirty_ops),
            soft_max_dirty_age_ticks: min_u64(
                tuning.max_dirty_age_ticks,
                self.hard_max_dirty_age_ticks,
            ),
            ..self
        }
    }

    #[must_use]
    pub const fn effective_max_dirty_bytes(self) -> u64 {
        min_u64(self.soft_max_dirty_bytes, self.hard_max_dirty_bytes)
    }

    #[must_use]
    pub const fn effective_max_dirty_ops(self) -> u32 {
        min_u32(self.soft_max_dirty_ops, self.hard_max_dirty_ops)
    }

    #[must_use]
    pub const fn effective_max_dirty_age_ticks(self) -> u64 {
        min_u64(self.soft_max_dirty_age_ticks, self.hard_max_dirty_age_ticks)
    }
}

impl Default for LocalAdmissionConfig {
    fn default() -> Self {
        Self::new(
            // 256 MiB bounds dirty accumulation without constraining ordinary
            // local workloads to individual write sizes.
            256 * 1024 * 1024,
            // Bound both accumulated dirty operations and live token storage.
            4096,
            // Approximately five minutes when the owner advances one tick/s.
            300,
            2048,
        )
    }
}

/// Runtime tuning request; values above hard caps are clamped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAdmissionTuning {
    pub max_dirty_bytes: u64,
    pub max_dirty_ops: u32,
    pub max_dirty_age_ticks: u64,
}

/// Current resource usage owned by one admission issuer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalAdmissionUsage {
    pub dirty_bytes: u64,
    pub dirty_ops: u32,
    pub outstanding_permits: u32,
    pub oldest_dirty_tick: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalAdmissionChargeKind {
    DirtyWrite,
    MetadataMutation,
}

/// Resources conserved by a single local admission permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalAdmissionCharge {
    kind: LocalAdmissionChargeKind,
    pub dirty_bytes: u64,
    pub dirty_ops: u32,
    pub admitted_tick: u64,
}

impl LocalAdmissionCharge {
    #[must_use]
    pub const fn dirty_write(dirty_bytes: u64, dirty_ops: u32, admitted_tick: u64) -> Self {
        Self {
            kind: LocalAdmissionChargeKind::DirtyWrite,
            dirty_bytes,
            dirty_ops,
            admitted_tick,
        }
    }

    #[must_use]
    pub const fn metadata_mutation(admitted_tick: u64) -> Self {
        Self {
            kind: LocalAdmissionChargeKind::MetadataMutation,
            dirty_bytes: 0,
            dirty_ops: 0,
            admitted_tick,
        }
    }

    #[must_use]
    pub const fn is_metadata_mutation(self) -> bool {
        matches!(self.kind, LocalAdmissionChargeKind::MetadataMutation)
    }

    const fn is_dirty_write(self) -> bool {
        matches!(self.kind, LocalAdmissionChargeKind::DirtyWrite)
    }
}

/// Linear identity proving that this issuer admitted one charge.
#[must_use = "local admission permits conserve dirty debt; release or retain the permit explicitly"]
#[derive(Debug, Eq, PartialEq)]
pub struct LocalAdmissionPermit {
    issuer_id: u64,
    id: u64,
    charge: LocalAdmissionCharge,
}

impl LocalAdmissionPermit {
    #[must_use]
    pub const fn issuer_id(&self) -> u64 {
        self.issuer_id
    }

    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub const fn charge(&self) -> LocalAdmissionCharge {
        self.charge
    }
}

/// Admission and permit-release failures.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum LocalAdmissionError {
    #[error("local admission issuer identity space is exhausted")]
    IssuerIdExhausted,
    #[error("local admission permit identity space is exhausted for issuer {issuer_id}")]
    PermitIdExhausted { issuer_id: u64 },
    #[error("dirty admission requires at least one dirty operation")]
    ZeroDirtyOperations,
    #[error("dirty-byte accounting overflow")]
    DirtyBytesOverflow,
    #[error("dirty-operation accounting overflow")]
    DirtyOpsOverflow,
    #[error("outstanding-permit accounting overflow")]
    PermitOverflow,
    #[error("dirty-byte hard cap rejected {requested} bytes with {in_use} in use (hard {cap}, effective {effective_cap})")]
    DirtyBytesHardCap {
        in_use: u64,
        requested: u64,
        cap: u64,
        effective_cap: u64,
    },
    #[error("dirty-operation hard cap rejected {requested} operations with {in_use} in use (hard {cap}, effective {effective_cap})")]
    DirtyOpsHardCap {
        in_use: u32,
        requested: u32,
        cap: u32,
        effective_cap: u32,
    },
    #[error("dirty-age hard cap rejected oldest tick {oldest_tick} at tick {now_tick} (hard {cap}, effective {effective_cap})")]
    DirtyAgeHardCap {
        oldest_tick: u64,
        now_tick: u64,
        cap: u64,
        effective_cap: u64,
    },
    #[error("permit hard cap rejected {requested} permit with {in_use} in use (hard {cap})")]
    PermitHardCap {
        in_use: u32,
        requested: u32,
        cap: u32,
    },
    #[error("permit identity {permit_id} already exists for issuer {issuer_id}")]
    PermitIdentityCollision { issuer_id: u64, permit_id: u64 },
    #[error("permit belongs to issuer {actual_issuer_id}, not issuer {expected_issuer_id}")]
    ForeignPermit {
        expected_issuer_id: u64,
        actual_issuer_id: u64,
        permit: LocalAdmissionPermit,
    },
    #[error("permit {permit_id} is stale or already released for issuer {issuer_id}")]
    StalePermit {
        issuer_id: u64,
        permit_id: u64,
        permit: LocalAdmissionPermit,
    },
    #[error("permit {permit_id} charge does not match issuer {issuer_id}'s active ledger")]
    PermitChargeMismatch {
        issuer_id: u64,
        permit_id: u64,
        permit: LocalAdmissionPermit,
    },
    #[error("permit {permit_id} cannot be released because issuer {issuer_id}'s {counter} counter is inconsistent")]
    ReleaseAccountingInvariant {
        issuer_id: u64,
        permit_id: u64,
        counter: &'static str,
        permit: LocalAdmissionPermit,
    },
}

impl LocalAdmissionError {
    /// Recover the unconsumed permit from a failed release attempt.
    #[must_use]
    pub fn into_permit(self) -> Option<LocalAdmissionPermit> {
        match self {
            Self::ForeignPermit { permit, .. }
            | Self::StalePermit { permit, .. }
            | Self::PermitChargeMismatch { permit, .. }
            | Self::ReleaseAccountingInvariant { permit, .. } => Some(permit),
            _ => None,
        }
    }
}

/// Runtime admission state for one mounted local filesystem.
///
/// admission: LocalAdmissionPermit  service_curve: filesystem-owned bounded work
#[derive(Debug)]
pub struct LocalWriteAdmission {
    issuer_id: u64,
    config: LocalAdmissionConfig,
    usage: LocalAdmissionUsage,
    next_permit_id: u64,
    active_permits: BTreeMap<u64, LocalAdmissionCharge>,
    started_at: Instant,
    current_tick: u64,
    peak_dirty_bytes: u64,
    peak_dirty_ops: u32,
    peak_outstanding_permits: u32,
    last_snapshot: Instant,
}

impl LocalWriteAdmission {
    /// Construct an empty admission authority with a process-unique issuer.
    pub fn new(config: LocalAdmissionConfig) -> Result<Self, LocalAdmissionError> {
        let issuer_id = NEXT_LOCAL_ADMISSION_ISSUER_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| LocalAdmissionError::IssuerIdExhausted)?;
        let now = Instant::now();
        Ok(Self {
            issuer_id,
            config,
            usage: LocalAdmissionUsage::default(),
            next_permit_id: 1,
            active_permits: BTreeMap::new(),
            started_at: now,
            current_tick: 0,
            peak_dirty_bytes: 0,
            peak_dirty_ops: 0,
            peak_outstanding_permits: 0,
            last_snapshot: now,
        })
    }

    #[must_use]
    pub const fn issuer_id(&self) -> u64 {
        self.issuer_id
    }

    /// Advance the logical tick owned by commit/writeback progress.
    pub fn advance_tick(&mut self) {
        self.current_tick = self.current_tick.saturating_add(1);
    }

    #[must_use]
    pub fn current_tick(&self) -> u64 {
        self.current_tick.max(self.started_at.elapsed().as_secs())
    }

    /// Admit dirty bytes and operations at the current logical tick.
    pub fn try_admit_dirty_write(
        &mut self,
        dirty_bytes: u64,
        dirty_ops: u32,
    ) -> Result<LocalAdmissionPermit, LocalAdmissionError> {
        self.refresh_tick();
        let (new_bytes, new_ops, new_permits) =
            self.checked_dirty_write_usage(dirty_bytes, dirty_ops)?;
        let charge = LocalAdmissionCharge::dirty_write(dirty_bytes, dirty_ops, self.current_tick);
        let permit = self.issue_permit(charge)?;
        self.usage.dirty_bytes = new_bytes;
        self.usage.dirty_ops = new_ops;
        self.usage.outstanding_permits = new_permits;
        self.usage.oldest_dirty_tick = Some(match self.usage.oldest_dirty_tick {
            Some(oldest) => min_u64(oldest, charge.admitted_tick),
            None => charge.admitted_tick,
        });
        self.update_peaks();
        Ok(permit)
    }

    /// Check whether one dirty write can be admitted without issuing a permit.
    ///
    /// Mounted writeback uses this to close an existing deferred commit group
    /// before starting a new mutation whose permit would otherwise be refused.
    /// The real admission still issues the linear permit after planning.
    pub fn check_dirty_write(
        &mut self,
        dirty_bytes: u64,
        dirty_ops: u32,
    ) -> Result<(), LocalAdmissionError> {
        self.refresh_tick();
        self.checked_dirty_write_usage(dirty_bytes, dirty_ops)
            .map(|_| ())
    }

    fn checked_dirty_write_usage(
        &self,
        dirty_bytes: u64,
        dirty_ops: u32,
    ) -> Result<(u64, u32, u32), LocalAdmissionError> {
        if dirty_ops == 0 {
            return Err(LocalAdmissionError::ZeroDirtyOperations);
        }
        self.check_dirty_age(self.current_tick)?;

        let max_bytes = self.config.effective_max_dirty_bytes();
        let new_bytes = self
            .usage
            .dirty_bytes
            .checked_add(dirty_bytes)
            .ok_or(LocalAdmissionError::DirtyBytesOverflow)?;
        if new_bytes > max_bytes {
            return Err(LocalAdmissionError::DirtyBytesHardCap {
                in_use: self.usage.dirty_bytes,
                requested: dirty_bytes,
                cap: self.config.hard_max_dirty_bytes,
                effective_cap: max_bytes,
            });
        }

        let max_ops = self.config.effective_max_dirty_ops();
        let new_ops = self
            .usage
            .dirty_ops
            .checked_add(dirty_ops)
            .ok_or(LocalAdmissionError::DirtyOpsOverflow)?;
        if new_ops > max_ops {
            return Err(LocalAdmissionError::DirtyOpsHardCap {
                in_use: self.usage.dirty_ops,
                requested: dirty_ops,
                cap: self.config.hard_max_dirty_ops,
                effective_cap: max_ops,
            });
        }

        let new_permits = self.checked_permit_count()?;
        Ok((new_bytes, new_ops, new_permits))
    }

    /// Admit one metadata mutation against the permit-slot cap only.
    pub fn try_admit_metadata_mutation(
        &mut self,
    ) -> Result<LocalAdmissionPermit, LocalAdmissionError> {
        self.refresh_tick();
        let new_permits = self.checked_permit_count()?;
        let permit =
            self.issue_permit(LocalAdmissionCharge::metadata_mutation(self.current_tick))?;
        self.usage.outstanding_permits = new_permits;
        self.update_peaks();
        Ok(permit)
    }

    /// Release one active permit after validating its issuer, identity, and charge.
    ///
    /// Every failure leaves the active ledger and usage counters unchanged.  A
    /// caller that tried the wrong issuer can recover the permit with
    /// [`LocalAdmissionError::into_permit`] and retry against its owner.
    pub fn release(
        &mut self,
        permit: LocalAdmissionPermit,
    ) -> Result<LocalAdmissionCharge, LocalAdmissionError> {
        let permit_id = permit.id;
        if permit.issuer_id != self.issuer_id {
            return Err(LocalAdmissionError::ForeignPermit {
                expected_issuer_id: self.issuer_id,
                actual_issuer_id: permit.issuer_id,
                permit,
            });
        }

        let Some(active_charge) = self.active_permits.get(&permit_id).copied() else {
            return Err(LocalAdmissionError::StalePermit {
                issuer_id: self.issuer_id,
                permit_id,
                permit,
            });
        };
        if active_charge != permit.charge {
            return Err(LocalAdmissionError::PermitChargeMismatch {
                issuer_id: self.issuer_id,
                permit_id,
                permit,
            });
        }

        let Some(new_bytes) = self
            .usage
            .dirty_bytes
            .checked_sub(active_charge.dirty_bytes)
        else {
            return Err(LocalAdmissionError::ReleaseAccountingInvariant {
                issuer_id: self.issuer_id,
                permit_id,
                counter: "dirty-bytes",
                permit,
            });
        };
        let Some(new_ops) = self.usage.dirty_ops.checked_sub(active_charge.dirty_ops) else {
            return Err(LocalAdmissionError::ReleaseAccountingInvariant {
                issuer_id: self.issuer_id,
                permit_id,
                counter: "dirty-operations",
                permit,
            });
        };
        let Some(new_permits) = self.usage.outstanding_permits.checked_sub(1) else {
            return Err(LocalAdmissionError::ReleaseAccountingInvariant {
                issuer_id: self.issuer_id,
                permit_id,
                counter: "outstanding-permits",
                permit,
            });
        };

        self.active_permits.remove(&permit_id);
        self.usage.dirty_bytes = new_bytes;
        self.usage.dirty_ops = new_ops;
        self.usage.outstanding_permits = new_permits;
        self.usage.oldest_dirty_tick = self
            .active_permits
            .values()
            .filter(|charge| charge.is_dirty_write())
            .map(|charge| charge.admitted_tick)
            .min();
        Ok(active_charge)
    }

    pub fn apply_dynamic_tuning(&mut self, tuning: LocalAdmissionTuning) {
        self.config = self.config.with_dynamic_tuning(tuning);
    }

    #[must_use]
    pub const fn usage(&self) -> LocalAdmissionUsage {
        self.usage
    }

    #[must_use]
    pub const fn config(&self) -> LocalAdmissionConfig {
        self.config
    }

    #[must_use]
    pub fn dirty_age_exceeded(&self) -> bool {
        self.usage.oldest_dirty_tick.is_some_and(|oldest| {
            self.current_tick().saturating_sub(oldest) > self.config.effective_max_dirty_age_ticks()
        })
    }

    fn refresh_tick(&mut self) {
        self.current_tick = self.current_tick();
    }

    fn checked_permit_count(&self) -> Result<u32, LocalAdmissionError> {
        let new_permits = self
            .usage
            .outstanding_permits
            .checked_add(1)
            .ok_or(LocalAdmissionError::PermitOverflow)?;
        if new_permits > self.config.hard_max_permits {
            return Err(LocalAdmissionError::PermitHardCap {
                in_use: self.usage.outstanding_permits,
                requested: 1,
                cap: self.config.hard_max_permits,
            });
        }
        Ok(new_permits)
    }

    fn issue_permit(
        &mut self,
        charge: LocalAdmissionCharge,
    ) -> Result<LocalAdmissionPermit, LocalAdmissionError> {
        let permit_id = self.next_permit_id;
        let next_permit_id =
            permit_id
                .checked_add(1)
                .ok_or(LocalAdmissionError::PermitIdExhausted {
                    issuer_id: self.issuer_id,
                })?;
        if self.active_permits.contains_key(&permit_id) {
            return Err(LocalAdmissionError::PermitIdentityCollision {
                issuer_id: self.issuer_id,
                permit_id,
            });
        }
        self.active_permits.insert(permit_id, charge);
        self.next_permit_id = next_permit_id;
        Ok(LocalAdmissionPermit {
            issuer_id: self.issuer_id,
            id: permit_id,
            charge,
        })
    }

    fn check_dirty_age(&self, now_tick: u64) -> Result<(), LocalAdmissionError> {
        if let Some(oldest_tick) = self.usage.oldest_dirty_tick {
            let effective_cap = self.config.effective_max_dirty_age_ticks();
            if now_tick.saturating_sub(oldest_tick) > effective_cap {
                return Err(LocalAdmissionError::DirtyAgeHardCap {
                    oldest_tick,
                    now_tick,
                    cap: self.config.hard_max_dirty_age_ticks,
                    effective_cap,
                });
            }
        }
        Ok(())
    }

    fn update_peaks(&mut self) {
        self.peak_dirty_bytes = self.peak_dirty_bytes.max(self.usage.dirty_bytes);
        self.peak_dirty_ops = self.peak_dirty_ops.max(self.usage.dirty_ops);
        self.peak_outstanding_permits = self
            .peak_outstanding_permits
            .max(self.usage.outstanding_permits);
    }

    /// Snapshot peak and current usage, then begin a new interval at current usage.
    pub fn take_peak_snapshot(&mut self) -> AdmissionPeakSnapshot {
        self.refresh_tick();
        let snapshot = AdmissionPeakSnapshot {
            peak_dirty_bytes: self.peak_dirty_bytes,
            peak_dirty_ops: self.peak_dirty_ops,
            peak_outstanding_permits: self.peak_outstanding_permits,
            current_dirty_bytes: self.usage.dirty_bytes,
            current_dirty_ops: self.usage.dirty_ops,
            current_outstanding_permits: self.usage.outstanding_permits,
            current_tick: self.current_tick,
            since: self.last_snapshot,
        };
        self.peak_dirty_bytes = self.usage.dirty_bytes;
        self.peak_dirty_ops = self.usage.dirty_ops;
        self.peak_outstanding_permits = self.usage.outstanding_permits;
        self.last_snapshot = Instant::now();
        snapshot
    }
}

/// Bounded peak and current admission usage for one reporting interval.
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
    #[must_use]
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

/// Serializable values used by the existing optional observation surface.
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

    fn test_admission(config: LocalAdmissionConfig) -> LocalWriteAdmission {
        LocalWriteAdmission::new(config).expect("issuer identity available")
    }

    #[test]
    fn default_caps_are_nonzero() {
        let config = LocalAdmissionConfig::default();
        assert!(config.hard_max_dirty_bytes > 0);
        assert!(config.hard_max_dirty_ops > 0);
        assert!(config.hard_max_dirty_age_ticks > 0);
        assert!(config.hard_max_permits > 0);
    }

    #[test]
    fn dirty_permits_conserve_bytes_ops_and_slots() {
        let mut admission = test_admission(LocalAdmissionConfig::default());
        let permit = admission
            .try_admit_dirty_write(4096, 1)
            .expect("small write admitted");
        assert_eq!(admission.usage().dirty_bytes, 4096);
        assert_eq!(admission.usage().dirty_ops, 1);
        assert_eq!(admission.usage().outstanding_permits, 1);

        let charge = admission.release(permit).expect("permit released");
        assert_eq!(charge.dirty_bytes, 4096);
        assert_eq!(charge.dirty_ops, 1);
        assert_eq!(admission.usage(), LocalAdmissionUsage::default());
    }

    #[test]
    fn hard_byte_and_operation_caps_refuse_growth() {
        let config = LocalAdmissionConfig::new(1024, 1, 8, 4);
        let mut admission = test_admission(config);
        let permit = admission
            .try_admit_dirty_write(1024, 1)
            .expect("write at caps admitted");
        let err = admission
            .try_admit_dirty_write(1, 1)
            .expect_err("byte cap enforced");
        assert!(matches!(err, LocalAdmissionError::DirtyBytesHardCap { .. }));
        admission.release(permit).expect("permit released");

        let err = admission
            .try_admit_dirty_write(0, 2)
            .expect_err("operation cap enforced");
        assert!(matches!(err, LocalAdmissionError::DirtyOpsHardCap { .. }));
    }

    #[test]
    fn dirty_age_cap_blocks_new_dirty_debt() {
        let mut admission = test_admission(LocalAdmissionConfig::new(4096, 4, 2, 4));
        let permit = admission
            .try_admit_dirty_write(512, 1)
            .expect("initial write admitted");
        admission.advance_tick();
        admission.advance_tick();
        admission.advance_tick();
        assert!(admission.dirty_age_exceeded());
        let err = admission
            .try_admit_dirty_write(512, 1)
            .expect_err("aged debt blocks new dirty debt");
        assert!(matches!(err, LocalAdmissionError::DirtyAgeHardCap { .. }));
        admission.release(permit).expect("permit released");
    }

    #[test]
    fn metadata_permits_consume_slots_only() {
        let mut admission = test_admission(LocalAdmissionConfig::new(0, 0, 0, 2));
        let first = admission
            .try_admit_metadata_mutation()
            .expect("metadata admitted without dirty budget");
        let second = admission
            .try_admit_metadata_mutation()
            .expect("second metadata permit admitted");
        assert!(first.charge().is_metadata_mutation());
        assert_eq!(admission.usage().dirty_bytes, 0);
        assert_eq!(admission.usage().dirty_ops, 0);
        assert_eq!(admission.usage().oldest_dirty_tick, None);
        assert_eq!(admission.usage().outstanding_permits, 2);
        assert!(matches!(
            admission.try_admit_metadata_mutation(),
            Err(LocalAdmissionError::PermitHardCap { .. })
        ));
        admission.release(first).expect("first permit released");
        admission.release(second).expect("second permit released");
    }

    #[test]
    fn dynamic_tuning_cannot_raise_hard_caps() {
        let mut admission = test_admission(LocalAdmissionConfig::new(4096, 4, 4, 4));
        admission.apply_dynamic_tuning(LocalAdmissionTuning {
            max_dirty_bytes: 8192,
            max_dirty_ops: 8,
            max_dirty_age_ticks: 8,
        });
        let config = admission.config();
        assert_eq!(config.effective_max_dirty_bytes(), 4096);
        assert_eq!(config.effective_max_dirty_ops(), 4);
        assert_eq!(config.effective_max_dirty_age_ticks(), 4);
    }

    #[test]
    fn foreign_release_preserves_both_issuers_and_returns_permit() {
        let mut owner = test_admission(LocalAdmissionConfig::default());
        let mut foreign = test_admission(LocalAdmissionConfig::default());
        assert_ne!(owner.issuer_id(), foreign.issuer_id());
        let permit = owner
            .try_admit_dirty_write(128, 1)
            .expect("owner admitted write");
        let owner_usage = owner.usage();
        let foreign_usage = foreign.usage();

        let err = foreign.release(permit).expect_err("foreign issuer refused");
        assert!(matches!(&err, LocalAdmissionError::ForeignPermit { .. }));
        assert_eq!(owner.usage(), owner_usage);
        assert_eq!(foreign.usage(), foreign_usage);
        let permit = err.into_permit().expect("foreign error returns permit");
        owner
            .release(permit)
            .expect("owner can release recovered permit");
    }

    #[test]
    fn stale_release_is_recoverable_and_does_not_change_counters() {
        let mut admission = test_admission(LocalAdmissionConfig::default());
        let permit = admission
            .try_admit_dirty_write(128, 1)
            .expect("write admitted");
        let duplicate = LocalAdmissionPermit {
            issuer_id: permit.issuer_id,
            id: permit.id,
            charge: permit.charge,
        };
        admission.release(permit).expect("first release succeeds");
        let usage = admission.usage();
        let err = admission
            .release(duplicate)
            .expect_err("duplicate release refused");
        assert!(matches!(&err, LocalAdmissionError::StalePermit { .. }));
        assert_eq!(admission.usage(), usage);
        assert!(err.into_permit().is_some());
    }

    #[test]
    fn snapshot_reports_current_usage_in_each_new_interval() {
        let mut admission = test_admission(LocalAdmissionConfig::default());
        let permit = admission
            .try_admit_dirty_write(8192, 2)
            .expect("write admitted");
        let first = admission.take_peak_snapshot();
        assert_eq!(first.peak_dirty_bytes, 8192);
        let second = admission.take_peak_snapshot();
        assert_eq!(second.peak_dirty_bytes, 8192);
        assert_eq!(second.current_dirty_bytes, 8192);
        admission.release(permit).expect("permit released");
    }

    #[test]
    fn zero_dirty_operations_are_rejected() {
        let mut admission = test_admission(LocalAdmissionConfig::default());
        assert!(matches!(
            admission.try_admit_dirty_write(4096, 0),
            Err(LocalAdmissionError::ZeroDirtyOperations)
        ));
    }
}
