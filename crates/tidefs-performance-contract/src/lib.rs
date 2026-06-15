#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]

//! Typed performance-correctness contracts for local TideFS work.
//!
//! This crate deliberately starts with bounded dirty debt and foreground-read
//! protection models, not throughput claims. Runtime crates can import these
//! types when wiring concrete queues, but this first slice is pure accounting
//! and deterministic oracle signal.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::collections::VecDeque;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Stable labels for work that competes for local service.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum WorkClass {
    ForegroundRead,
    ForegroundWrite,
    MetadataMutation,
    WritebackFlush,
    Scrub,
    Reclaim,
    Compaction,
    ControlPlane,
}

impl WorkClass {
    /// Return the canonical metadata spelling used by queue registries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundRead => "foreground-read",
            Self::ForegroundWrite => "foreground-write",
            Self::MetadataMutation => "metadata-mutation",
            Self::WritebackFlush => "writeback-flush",
            Self::Scrub => "scrub",
            Self::Reclaim => "reclaim",
            Self::Compaction => "compaction",
            Self::ControlPlane => "control-plane",
        }
    }

    /// Foreground work has precedence in the local service oracle.
    #[must_use]
    pub const fn is_foreground(self) -> bool {
        matches!(
            self,
            Self::ForegroundRead | Self::ForegroundWrite | Self::MetadataMutation
        )
    }
}

impl fmt::Display for WorkClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resource domains that admission and scheduling can budget independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ResourceDomain {
    ForegroundIo,
    BackgroundIo,
    DirtyBytes,
    DirtyOperations,
    DirtyAge,
    Metadata,
    QueueSlots,
    Cpu,
}

impl ResourceDomain {
    /// Return the canonical metadata spelling used by queue registries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundIo => "foreground-io",
            Self::BackgroundIo => "background-io",
            Self::DirtyBytes => "dirty-bytes",
            Self::DirtyOperations => "dirty-operations",
            Self::DirtyAge => "dirty-age",
            Self::Metadata => "metadata",
            Self::QueueSlots => "queue-slots",
            Self::Cpu => "cpu",
        }
    }
}

impl fmt::Display for ResourceDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-tick service envelope for one work class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServiceCurve {
    pub work_class: WorkClass,
    pub primary_domain: ResourceDomain,
    pub max_ops_per_tick: u32,
    pub max_bytes_per_tick: u64,
    pub queue_slots: u32,
}

impl ServiceCurve {
    /// Construct a service curve with hard per-tick and queue-depth limits.
    #[must_use]
    pub const fn new(
        work_class: WorkClass,
        primary_domain: ResourceDomain,
        max_ops_per_tick: u32,
        max_bytes_per_tick: u64,
        queue_slots: u32,
    ) -> Self {
        Self {
            work_class,
            primary_domain,
            max_ops_per_tick,
            max_bytes_per_tick,
            queue_slots,
        }
    }

    /// Foreground read curve used by the oracle tests.
    pub const FOREGROUND_READ_DEFAULT: Self = Self::new(
        WorkClass::ForegroundRead,
        ResourceDomain::ForegroundIo,
        1,
        128 * 1024,
        64,
    );

    /// Conservative scrub curve used by the oracle tests.
    pub const SCRUB_BOUNDED_DEFAULT: Self = Self::new(
        WorkClass::Scrub,
        ResourceDomain::BackgroundIo,
        1,
        1024 * 1024,
        4,
    );

    /// Dirty writeback queue curve for contract tests.
    pub const WRITEBACK_DIRTY_DEFAULT: Self = Self::new(
        WorkClass::ForegroundWrite,
        ResourceDomain::DirtyBytes,
        1,
        1024 * 1024,
        64,
    );

    /// Return true when a single work item can fit this curve.
    #[must_use]
    pub fn admits(self, work_class: WorkClass, ops: u32, bytes: u64) -> bool {
        self.work_class == work_class
            && ops <= self.max_ops_per_tick
            && bytes <= self.max_bytes_per_tick
    }
}

/// Hard and tunable local dirty-admission settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WriteAdmissionConfig {
    pub hard_max_dirty_bytes: u64,
    pub hard_max_dirty_ops: u32,
    pub hard_max_dirty_age_ticks: u64,
    pub hard_max_permits: u32,
    pub soft_max_dirty_bytes: u64,
    pub soft_max_dirty_ops: u32,
    pub soft_max_dirty_age_ticks: u64,
}

impl WriteAdmissionConfig {
    /// Construct a config whose soft limits initially equal its hard caps.
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

    /// Apply dynamic tuning while clamping every soft limit to the hard cap.
    #[must_use]
    pub const fn with_dynamic_tuning(self, tuning: DynamicAdmissionTuning) -> Self {
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

    /// Return the effective byte limit after dynamic clamps.
    #[must_use]
    pub const fn effective_max_dirty_bytes(self) -> u64 {
        min_u64(self.soft_max_dirty_bytes, self.hard_max_dirty_bytes)
    }

    /// Return the effective operation limit after dynamic clamps.
    #[must_use]
    pub const fn effective_max_dirty_ops(self) -> u32 {
        min_u32(self.soft_max_dirty_ops, self.hard_max_dirty_ops)
    }

    /// Return the effective dirty-age limit after dynamic clamps.
    #[must_use]
    pub const fn effective_max_dirty_age_ticks(self) -> u64 {
        min_u64(self.soft_max_dirty_age_ticks, self.hard_max_dirty_age_ticks)
    }
}

/// Dynamic tuning request. Values above hard caps are ignored by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DynamicAdmissionTuning {
    pub max_dirty_bytes: u64,
    pub max_dirty_ops: u32,
    pub max_dirty_age_ticks: u64,
}

/// A single admission charge tracked by an [`AdmissionPermit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AdmissionCharge {
    pub work_class: WorkClass,
    pub primary_domain: ResourceDomain,
    pub dirty_bytes: u64,
    pub dirty_ops: u32,
    pub admitted_tick: u64,
}

impl AdmissionCharge {
    /// Construct a dirty write charge.
    #[must_use]
    pub const fn dirty_write(dirty_bytes: u64, dirty_ops: u32, admitted_tick: u64) -> Self {
        Self {
            work_class: WorkClass::ForegroundWrite,
            primary_domain: ResourceDomain::DirtyBytes,
            dirty_bytes,
            dirty_ops,
            admitted_tick,
        }
    }
}

/// A linear admission token. Release it or move it into a [`BudgetedQueue`].
#[must_use = "admission permits conserve dirty debt; release or enqueue the permit explicitly"]
#[derive(Debug, Eq, PartialEq)]
pub struct AdmissionPermit {
    id: u64,
    charge: AdmissionCharge,
}

impl AdmissionPermit {
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub const fn charge(&self) -> AdmissionCharge {
        self.charge
    }

    fn new(id: u64, charge: AdmissionCharge) -> Self {
        Self { id, charge }
    }
}

/// Current write-admission usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WriteAdmissionUsage {
    pub dirty_bytes: u64,
    pub dirty_ops: u32,
    pub outstanding_permits: u32,
    pub oldest_dirty_tick: Option<u64>,
}

/// Write-admission state with hard dirty byte/op/age caps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteAdmissionState {
    config: WriteAdmissionConfig,
    usage: WriteAdmissionUsage,
    next_permit_id: u64,
}

impl WriteAdmissionState {
    /// Create an empty state with the supplied hard/soft config.
    #[must_use]
    pub const fn new(config: WriteAdmissionConfig) -> Self {
        Self {
            config,
            usage: WriteAdmissionUsage {
                dirty_bytes: 0,
                dirty_ops: 0,
                outstanding_permits: 0,
                oldest_dirty_tick: None,
            },
            next_permit_id: 1,
        }
    }

    #[must_use]
    pub const fn config(&self) -> WriteAdmissionConfig {
        self.config
    }

    #[must_use]
    pub const fn usage(&self) -> WriteAdmissionUsage {
        self.usage
    }

    /// Apply dynamic tuning without changing any hard cap.
    pub fn apply_dynamic_tuning(&mut self, tuning: DynamicAdmissionTuning) {
        self.config = self.config.with_dynamic_tuning(tuning);
    }

    /// Try to admit one dirty charge at the charge's recorded tick.
    pub fn try_admit(
        &mut self,
        charge: AdmissionCharge,
    ) -> Result<AdmissionPermit, AdmissionError> {
        self.try_admit_at(charge, charge.admitted_tick)
    }

    /// Try to admit one dirty charge at the current scheduler tick.
    pub fn try_admit_at(
        &mut self,
        charge: AdmissionCharge,
        now_tick: u64,
    ) -> Result<AdmissionPermit, AdmissionError> {
        if charge.dirty_ops == 0 {
            return Err(AdmissionError::ZeroDirtyOperations);
        }
        self.check_dirty_age(now_tick)?;

        let max_bytes = self.config.effective_max_dirty_bytes();
        let max_ops = self.config.effective_max_dirty_ops();
        let new_bytes = self
            .usage
            .dirty_bytes
            .checked_add(charge.dirty_bytes)
            .ok_or(AdmissionError::DirtyBytesOverflow)?;
        if new_bytes > max_bytes {
            return Err(AdmissionError::DirtyBytesHardCap {
                in_use: self.usage.dirty_bytes,
                requested: charge.dirty_bytes,
                cap: self.config.hard_max_dirty_bytes,
                effective_cap: max_bytes,
            });
        }

        let new_ops = self
            .usage
            .dirty_ops
            .checked_add(charge.dirty_ops)
            .ok_or(AdmissionError::DirtyOpsOverflow)?;
        if new_ops > max_ops {
            return Err(AdmissionError::DirtyOpsHardCap {
                in_use: self.usage.dirty_ops,
                requested: charge.dirty_ops,
                cap: self.config.hard_max_dirty_ops,
                effective_cap: max_ops,
            });
        }

        let new_permits = self
            .usage
            .outstanding_permits
            .checked_add(1)
            .ok_or(AdmissionError::PermitOverflow)?;
        if new_permits > self.config.hard_max_permits {
            return Err(AdmissionError::PermitHardCap {
                in_use: self.usage.outstanding_permits,
                requested: 1,
                cap: self.config.hard_max_permits,
            });
        }

        self.usage.dirty_bytes = new_bytes;
        self.usage.dirty_ops = new_ops;
        self.usage.outstanding_permits = new_permits;
        self.usage.oldest_dirty_tick = match self.usage.oldest_dirty_tick {
            Some(oldest) => Some(min_u64(oldest, charge.admitted_tick)),
            None => Some(charge.admitted_tick),
        };
        let permit_id = self.next_permit_id;
        self.next_permit_id = self.next_permit_id.saturating_add(1);
        Ok(AdmissionPermit::new(permit_id, charge))
    }

    /// Release an admission permit and return the released charge.
    pub fn release(&mut self, permit: AdmissionPermit) -> Result<AdmissionCharge, AdmissionError> {
        let charge = permit.charge;
        self.usage.dirty_bytes = self
            .usage
            .dirty_bytes
            .checked_sub(charge.dirty_bytes)
            .ok_or(AdmissionError::ReleaseUnderflow)?;
        self.usage.dirty_ops = self
            .usage
            .dirty_ops
            .checked_sub(charge.dirty_ops)
            .ok_or(AdmissionError::ReleaseUnderflow)?;
        self.usage.outstanding_permits = self
            .usage
            .outstanding_permits
            .checked_sub(1)
            .ok_or(AdmissionError::ReleaseUnderflow)?;
        if self.usage.dirty_ops == 0 {
            self.usage.oldest_dirty_tick = None;
        }
        Ok(charge)
    }

    /// Return true once the oldest outstanding dirty charge exceeds the cap.
    #[must_use]
    pub fn dirty_age_over_cap(&self, now_tick: u64) -> bool {
        match self.usage.oldest_dirty_tick {
            Some(oldest) => {
                now_tick.saturating_sub(oldest) > self.config.effective_max_dirty_age_ticks()
            }
            None => false,
        }
    }

    fn check_dirty_age(&self, now_tick: u64) -> Result<(), AdmissionError> {
        if let Some(oldest) = self.usage.oldest_dirty_tick {
            let age = now_tick.saturating_sub(oldest);
            let effective_cap = self.config.effective_max_dirty_age_ticks();
            if age > effective_cap {
                return Err(AdmissionError::DirtyAgeHardCap {
                    oldest_tick: oldest,
                    now_tick,
                    cap: self.config.hard_max_dirty_age_ticks,
                    effective_cap,
                });
            }
        }
        Ok(())
    }
}

/// Admission failure reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AdmissionError {
    ZeroDirtyOperations,
    DirtyBytesOverflow,
    DirtyOpsOverflow,
    PermitOverflow,
    ReleaseUnderflow,
    DirtyBytesHardCap {
        in_use: u64,
        requested: u64,
        cap: u64,
        effective_cap: u64,
    },
    DirtyOpsHardCap {
        in_use: u32,
        requested: u32,
        cap: u32,
        effective_cap: u32,
    },
    DirtyAgeHardCap {
        oldest_tick: u64,
        now_tick: u64,
        cap: u64,
        effective_cap: u64,
    },
    PermitHardCap {
        in_use: u32,
        requested: u32,
        cap: u32,
    },
}

/// Runtime metadata for a budgeted queue root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QueueMetadata {
    pub id: &'static str,
    pub work_class: WorkClass,
    pub primary_domain: ResourceDomain,
    pub service_curve: ServiceCurve,
}

/// An alloc-backed queue that requires an admission permit for each item.
///
/// tidefs-queue-root: performance_contract.budgeted_queue
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct BudgetedQueue<T> {
    metadata: QueueMetadata,
    items: VecDeque<BudgetedItem<T>>,
    queued_dirty_bytes: u64,
    queued_dirty_ops: u32,
}

#[cfg(feature = "alloc")]
impl<T> BudgetedQueue<T> {
    #[must_use]
    pub fn new(metadata: QueueMetadata) -> Self {
        Self {
            metadata,
            items: VecDeque::new(),
            queued_dirty_bytes: 0,
            queued_dirty_ops: 0,
        }
    }

    #[must_use]
    pub const fn metadata(&self) -> QueueMetadata {
        self.metadata
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub const fn queued_dirty_bytes(&self) -> u64 {
        self.queued_dirty_bytes
    }

    #[must_use]
    pub const fn queued_dirty_ops(&self) -> u32 {
        self.queued_dirty_ops
    }

    pub fn push(&mut self, item: T, permit: AdmissionPermit) -> Result<(), QueueAdmissionError<T>> {
        let charge = permit.charge();
        if charge.work_class != self.metadata.work_class {
            return Err(QueueAdmissionError::WrongWorkClass {
                expected: self.metadata.work_class,
                actual: charge.work_class,
                item,
                permit,
            });
        }
        if charge.primary_domain != self.metadata.primary_domain {
            return Err(QueueAdmissionError::WrongResourceDomain {
                expected: self.metadata.primary_domain,
                actual: charge.primary_domain,
                item,
                permit,
            });
        }
        if self.items.len() >= self.metadata.service_curve.queue_slots as usize {
            return Err(QueueAdmissionError::QueueFull { item, permit });
        }
        let Some(new_dirty_bytes) = self.queued_dirty_bytes.checked_add(charge.dirty_bytes) else {
            return Err(QueueAdmissionError::QueueAccountingOverflow { item, permit });
        };
        let Some(new_dirty_ops) = self.queued_dirty_ops.checked_add(charge.dirty_ops) else {
            return Err(QueueAdmissionError::QueueAccountingOverflow { item, permit });
        };
        self.queued_dirty_bytes = new_dirty_bytes;
        self.queued_dirty_ops = new_dirty_ops;
        self.items.push_back(BudgetedItem { item, permit });
        Ok(())
    }

    pub fn pop(&mut self) -> Option<BudgetedItem<T>> {
        let item = self.items.pop_front()?;
        let charge = item.permit.charge();
        self.queued_dirty_bytes = self.queued_dirty_bytes.saturating_sub(charge.dirty_bytes);
        self.queued_dirty_ops = self.queued_dirty_ops.saturating_sub(charge.dirty_ops);
        Some(item)
    }
}

/// A queue item plus the admission permit that conserves its dirty debt.
#[cfg(feature = "alloc")]
#[must_use = "budgeted queue items carry an admission permit that must be released"]
#[derive(Debug)]
pub struct BudgetedItem<T> {
    item: T,
    permit: AdmissionPermit,
}

#[cfg(feature = "alloc")]
impl<T> BudgetedItem<T> {
    pub fn into_parts(self) -> (T, AdmissionPermit) {
        (self.item, self.permit)
    }
}

/// Queue admission failure. Ownership of the item and permit is returned.
#[cfg(feature = "alloc")]
#[derive(Debug, Eq, PartialEq)]
pub enum QueueAdmissionError<T> {
    WrongWorkClass {
        expected: WorkClass,
        actual: WorkClass,
        item: T,
        permit: AdmissionPermit,
    },
    WrongResourceDomain {
        expected: ResourceDomain,
        actual: ResourceDomain,
        item: T,
        permit: AdmissionPermit,
    },
    QueueFull {
        item: T,
        permit: AdmissionPermit,
    },
    QueueAccountingOverflow {
        item: T,
        permit: AdmissionPermit,
    },
}

/// Deterministic foreground-read/scrub oracle.
#[cfg(feature = "alloc")]
pub mod oracle {
    use super::{ServiceCurve, WorkClass};

    /// Oracle configuration for the local read-vs-scrub counterexample.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct OracleConfig {
        pub scrub_units: u32,
        pub read_arrival_tick: u64,
        pub max_foreground_read_wait_ticks: u64,
    }

    impl Default for OracleConfig {
        fn default() -> Self {
            Self {
                scrub_units: 16,
                read_arrival_tick: 1,
                max_foreground_read_wait_ticks: 1,
            }
        }
    }

    /// Oracle result for both unscheduled and scheduled runs.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct OracleOutcome {
        pub foreground_read_completed_tick: u64,
        pub foreground_read_wait_ticks: u64,
        pub scrub_admitted: u32,
        pub scrub_deferred: u32,
        pub max_scrub_queue_depth: u32,
    }

    impl OracleOutcome {
        #[must_use]
        pub const fn foreground_read_within_bound(self, bound: u64) -> bool {
            self.foreground_read_wait_ticks <= bound
        }
    }

    /// FIFO-only model: scrub work can hide ahead of a foreground read.
    #[must_use]
    pub fn without_scheduling_or_admission(config: OracleConfig) -> OracleOutcome {
        let completed = config.read_arrival_tick + config.scrub_units as u64;
        OracleOutcome {
            foreground_read_completed_tick: completed,
            foreground_read_wait_ticks: completed.saturating_sub(config.read_arrival_tick),
            scrub_admitted: config.scrub_units,
            scrub_deferred: 0,
            max_scrub_queue_depth: config.scrub_units,
        }
    }

    /// Service-curve model: foreground read service wins and scrub queue depth is capped.
    #[must_use]
    pub fn with_scheduling_and_admission(
        config: OracleConfig,
        foreground: ServiceCurve,
        scrub: ServiceCurve,
    ) -> OracleOutcome {
        let scrub_slots = scrub.queue_slots;
        let scrub_admitted = min_u32(config.scrub_units, scrub_slots);
        let scrub_deferred = config.scrub_units.saturating_sub(scrub_admitted);
        let foreground_can_run = foreground.work_class as u8 == WorkClass::ForegroundRead as u8
            && foreground.max_ops_per_tick > 0;
        let completed = if foreground_can_run {
            config.read_arrival_tick
        } else {
            config.read_arrival_tick + scrub_admitted as u64
        };
        OracleOutcome {
            foreground_read_completed_tick: completed,
            foreground_read_wait_ticks: completed.saturating_sub(config.read_arrival_tick),
            scrub_admitted,
            scrub_deferred,
            max_scrub_queue_depth: scrub_admitted,
        }
    }

    const fn min_u32(left: u32, right: u32) -> u32 {
        if left < right {
            left
        } else {
            right
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::oracle::{
        with_scheduling_and_admission, without_scheduling_or_admission, OracleConfig,
    };
    use super::*;

    #[test]
    fn admission_permits_conserve_dirty_debt() {
        let config = WriteAdmissionConfig::new(4096, 4, 8, 4);
        let mut state = WriteAdmissionState::new(config);

        let first = state
            .try_admit(AdmissionCharge::dirty_write(1024, 1, 10))
            .expect("first write admitted");
        let second = state
            .try_admit(AdmissionCharge::dirty_write(2048, 2, 11))
            .expect("second write admitted");
        assert_eq!(state.usage().dirty_bytes, 3072);
        assert_eq!(state.usage().dirty_ops, 3);
        assert_eq!(state.usage().outstanding_permits, 2);

        state.release(first).expect("first release");
        assert_eq!(state.usage().dirty_bytes, 2048);
        assert_eq!(state.usage().dirty_ops, 2);
        assert_eq!(state.usage().outstanding_permits, 1);

        state.release(second).expect("second release");
        assert_eq!(state.usage(), WriteAdmissionUsage::default());
    }

    #[test]
    fn dynamic_tuning_cannot_bypass_hard_dirty_caps() {
        let config =
            WriteAdmissionConfig::new(1024, 1, 4, 2).with_dynamic_tuning(DynamicAdmissionTuning {
                max_dirty_bytes: 4096,
                max_dirty_ops: 8,
                max_dirty_age_ticks: 32,
            });
        let mut state = WriteAdmissionState::new(config);
        let permit = state
            .try_admit(AdmissionCharge::dirty_write(1024, 1, 0))
            .expect("at hard cap");

        let err = state
            .try_admit(AdmissionCharge::dirty_write(1, 1, 1))
            .expect_err("hard byte/op caps still apply");
        assert!(matches!(
            err,
            AdmissionError::DirtyBytesHardCap {
                cap: 1024,
                effective_cap: 1024,
                ..
            }
        ));

        state.release(permit).expect("release");
    }

    #[test]
    fn dirty_age_cap_blocks_new_dirty_admission() {
        let config =
            WriteAdmissionConfig::new(4096, 4, 4, 4).with_dynamic_tuning(DynamicAdmissionTuning {
                max_dirty_bytes: 4096,
                max_dirty_ops: 4,
                max_dirty_age_ticks: 128,
            });
        let mut state = WriteAdmissionState::new(config);
        let permit = state
            .try_admit(AdmissionCharge::dirty_write(512, 1, 10))
            .expect("initial dirty write");

        let err = state
            .try_admit_at(AdmissionCharge::dirty_write(512, 1, 15), 15)
            .expect_err("hard age cap blocks additional dirty debt");
        assert!(matches!(
            err,
            AdmissionError::DirtyAgeHardCap {
                oldest_tick: 10,
                now_tick: 15,
                cap: 4,
                effective_cap: 4,
            }
        ));

        state.release(permit).expect("release");
    }

    #[test]
    fn budgeted_queue_requires_and_returns_permits() {
        let config = WriteAdmissionConfig::new(4096, 4, 8, 4);
        let mut state = WriteAdmissionState::new(config);
        let metadata = QueueMetadata {
            id: "performance_contract.budgeted_queue",
            work_class: WorkClass::ForegroundWrite,
            primary_domain: ResourceDomain::DirtyBytes,
            service_curve: ServiceCurve::WRITEBACK_DIRTY_DEFAULT,
        };
        let mut queue = BudgetedQueue::new(metadata);

        let permit = state
            .try_admit(AdmissionCharge::dirty_write(128, 1, 0))
            .expect("admitted");
        queue.push("dirty extent", permit).expect("queued");
        assert_eq!(queue.queued_dirty_bytes(), 128);
        assert_eq!(queue.queued_dirty_ops(), 1);

        let queued = queue.pop().expect("queued item");
        let (item, permit) = queued.into_parts();
        assert_eq!(item, "dirty extent");
        state.release(permit).expect("release queued permit");
        assert_eq!(state.usage(), WriteAdmissionUsage::default());
        assert!(queue.is_empty());
    }

    #[test]
    fn unscheduled_scrub_blocks_foreground_read_counterexample() {
        let config = OracleConfig::default();
        let outcome = without_scheduling_or_admission(config);

        assert!(!outcome.foreground_read_within_bound(config.max_foreground_read_wait_ticks));
        assert_eq!(outcome.scrub_admitted, config.scrub_units);
        assert_eq!(outcome.scrub_deferred, 0);
    }

    #[test]
    fn service_curve_protects_foreground_read_and_bounds_scrub() {
        let config = OracleConfig::default();
        let outcome = with_scheduling_and_admission(
            config,
            ServiceCurve::FOREGROUND_READ_DEFAULT,
            ServiceCurve::SCRUB_BOUNDED_DEFAULT,
        );

        assert!(outcome.foreground_read_within_bound(config.max_foreground_read_wait_ticks));
        assert_eq!(
            outcome.max_scrub_queue_depth,
            ServiceCurve::SCRUB_BOUNDED_DEFAULT.queue_slots
        );
        assert_eq!(
            outcome.scrub_deferred,
            config.scrub_units - ServiceCurve::SCRUB_BOUNDED_DEFAULT.queue_slots
        );
    }
}
