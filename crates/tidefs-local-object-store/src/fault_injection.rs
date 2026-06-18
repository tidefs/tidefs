// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Fault injection hooks for crash injection testing.
//!
//! This module provides configurable fault injection that enables testing
//! of crash recovery, torn writes, and I/O error handling without requiring
//! real process kills or hardware faults. It is gated behind `StoreOptions`
//! and has zero runtime cost when disabled (the `Option` is `None`).
//!
//! The probability-based parameters are a simplified interface; for typed,
//! reproducible campaigns use [`FaultInjectionConfig::from_schedule`] with a
//! `crate::FaultSchedule` from the typed fault catalog (P10-02).

use rand::Rng;

use crate::fault_catalog::FaultSchedule;

/// Named injection point for deterministic crash testing (#1230).
///
/// Each variant corresponds to a specific point in the commit_group lifecycle,
/// namespace operations, I/O operations, or recovery sequence where
/// a crash can be injected. The harness iterates over all variants
/// to ensure exhaustive crash-boundary coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrashInjectionPoint {
    // COMMIT_GROUP lifecycle hooks
    CommitGroupBeforeQuiesce,
    CommitGroupAfterQuiesce,
    CommitGroupBeforeSync,
    CommitGroupAfterAppendData,
    CommitGroupBeforeCommit,
    CommitGroupAfterCommit,
    CommitGroupBeforeCheckpoint,
    CommitGroupAfterCheckpoint,
    CommitGroupAfterFlush,
    // Namespace operation hooks
    OpRenameAfterResolve,
    OpUnlinkBeforeNlinkDecr,
    OpUnlinkAfterNlinkZero,
    // I/O operation hooks
    OpWriteBeforeExtentUpdate,
    OpFsyncBeforeFlush,
    OpAllocateBeforeSpaceUpdate,
    // Recovery hooks
    RecoveryBeforeReplay,
    RecoveryAfterReplay,
    RecoveryBeforeRootSelect,
    // Repair hooks -- crash during scrub/repair operations
    RepairBeforeApply,
    RepairBeforeWriteback,
    RepairAfterWriteback,
}

impl CrashInjectionPoint {
    pub const ALL: &'static [CrashInjectionPoint] = &[
        Self::CommitGroupBeforeQuiesce,
        Self::CommitGroupAfterQuiesce,
        Self::CommitGroupBeforeSync,
        Self::CommitGroupAfterAppendData,
        Self::CommitGroupBeforeCommit,
        Self::CommitGroupAfterCommit,
        Self::CommitGroupBeforeCheckpoint,
        Self::CommitGroupAfterCheckpoint,
        Self::CommitGroupAfterFlush,
        Self::OpRenameAfterResolve,
        Self::OpUnlinkBeforeNlinkDecr,
        Self::OpUnlinkAfterNlinkZero,
        Self::OpWriteBeforeExtentUpdate,
        Self::OpFsyncBeforeFlush,
        Self::OpAllocateBeforeSpaceUpdate,
        Self::RecoveryBeforeReplay,
        Self::RecoveryAfterReplay,
        Self::RecoveryBeforeRootSelect,
        Self::RepairBeforeApply,
        Self::RepairBeforeWriteback,
        Self::RepairAfterWriteback,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Self::CommitGroupBeforeQuiesce => "COMMIT_GROUP_BEFORE_QUIESCE",
            Self::CommitGroupAfterQuiesce => "COMMIT_GROUP_AFTER_QUIESCE",
            Self::CommitGroupBeforeSync => "COMMIT_GROUP_BEFORE_SYNC",
            Self::CommitGroupAfterAppendData => "COMMIT_GROUP_AFTER_APPEND_DATA",
            Self::CommitGroupBeforeCommit => "COMMIT_GROUP_BEFORE_COMMIT",
            Self::CommitGroupAfterCommit => "COMMIT_GROUP_AFTER_COMMIT",
            Self::CommitGroupBeforeCheckpoint => "COMMIT_GROUP_BEFORE_CHECKPOINT",
            Self::CommitGroupAfterCheckpoint => "COMMIT_GROUP_AFTER_CHECKPOINT",
            Self::CommitGroupAfterFlush => "COMMIT_GROUP_AFTER_FLUSH",
            Self::OpRenameAfterResolve => "OP_RENAME_AFTER_RESOLVE",
            Self::OpUnlinkBeforeNlinkDecr => "OP_UNLINK_BEFORE_NLINK_DECR",
            Self::OpUnlinkAfterNlinkZero => "OP_UNLINK_AFTER_NLINK_ZERO",
            Self::OpWriteBeforeExtentUpdate => "OP_WRITE_BEFORE_EXTENT_UPDATE",
            Self::OpFsyncBeforeFlush => "OP_FSYNC_BEFORE_FLUSH",
            Self::OpAllocateBeforeSpaceUpdate => "OP_ALLOCATE_BEFORE_SPACE_UPDATE",
            Self::RecoveryBeforeReplay => "RECOVERY_BEFORE_REPLAY",
            Self::RecoveryAfterReplay => "RECOVERY_AFTER_REPLAY",
            Self::RecoveryBeforeRootSelect => "RECOVERY_BEFORE_ROOT_SELECT",
            Self::RepairBeforeApply => "REPAIR_BEFORE_APPLY",
            Self::RepairBeforeWriteback => "REPAIR_BEFORE_WRITEBACK",
            Self::RepairAfterWriteback => "REPAIR_AFTER_WRITEBACK",
        }
    }

    pub fn is_commit_group_hook(&self) -> bool {
        matches!(
            self,
            Self::CommitGroupBeforeQuiesce
                | Self::CommitGroupAfterQuiesce
                | Self::CommitGroupBeforeSync
                | Self::CommitGroupAfterAppendData
                | Self::CommitGroupBeforeCommit
                | Self::CommitGroupAfterCommit
                | Self::CommitGroupBeforeCheckpoint
                | Self::CommitGroupAfterCheckpoint
                | Self::CommitGroupAfterFlush
        )
    }

    pub fn is_recovery_hook(&self) -> bool {
        matches!(
            self,
            Self::RecoveryBeforeReplay | Self::RecoveryAfterReplay | Self::RecoveryBeforeRootSelect
        )
    }

    pub fn is_namespace_hook(&self) -> bool {
        matches!(
            self,
            Self::OpRenameAfterResolve
                | Self::OpUnlinkBeforeNlinkDecr
                | Self::OpUnlinkAfterNlinkZero
        )
    }

    pub fn is_repair_hook(&self) -> bool {
        matches!(
            self,
            Self::RepairBeforeApply | Self::RepairBeforeWriteback | Self::RepairAfterWriteback
        )
    }
}

impl std::fmt::Display for CrashInjectionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Configuration for deterministic crash injection at named hooks (#1230).
///
/// Uses interior mutability (Cell) for the hit counter so injection
/// checks work through shared references - essential for the call path
/// from LocalFileSystem through Pool through LocalObjectStore.
#[derive(Debug)]
pub struct CrashInjectionConfig {
    pub crash_at: Option<CrashInjectionPoint>,
    pub crash_on_hit: u64,
    hit_count: std::cell::Cell<u64>,
}

// Manual Clone impl: reset the hit counter on clone for fresh test configs.
impl Clone for CrashInjectionConfig {
    fn clone(&self) -> Self {
        Self {
            crash_at: self.crash_at,
            crash_on_hit: self.crash_on_hit,
            hit_count: std::cell::Cell::new(0),
        }
    }
}

impl CrashInjectionConfig {
    #[must_use]
    pub fn off() -> Self {
        Self {
            crash_at: None,
            crash_on_hit: 1,
            hit_count: std::cell::Cell::new(0),
        }
    }

    #[must_use]
    pub fn crash_at(point: CrashInjectionPoint) -> Self {
        Self {
            crash_at: Some(point),
            crash_on_hit: 1,
            hit_count: std::cell::Cell::new(0),
        }
    }

    #[must_use]
    pub fn crash_at_hit(point: CrashInjectionPoint, hit: u64) -> Self {
        Self {
            crash_at: Some(point),
            crash_on_hit: hit.max(1),
            hit_count: std::cell::Cell::new(0),
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.crash_at.is_some()
    }

    /// Check whether a crash should be triggered at a given point.
    /// Uses interior mutability (Cell) so it works through &self.
    pub fn should_crash(&self, point: CrashInjectionPoint) -> bool {
        let Some(target) = self.crash_at else {
            return false;
        };
        if target != point {
            return false;
        }
        let count = self.hit_count.get() + 1;
        self.hit_count.set(count);
        count == self.crash_on_hit
    }
}

impl Default for CrashInjectionConfig {
    fn default() -> Self {
        Self::off()
    }
}

/// Check the crash injection config and panic if the hook fires.
///
/// This is the main injection-point function. Call it with a reference
/// to an `Option<FaultInjectionConfig>` and the current injection point.
/// When the crash config is armed and the hit count matches, this panics
/// with a structured message that the test harness can detect.
#[track_caller]
pub fn check_crash_inject(fault_config: Option<&FaultInjectionConfig>, point: CrashInjectionPoint) {
    if let Some(cfg) = fault_config {
        if cfg.crash.should_crash(point) {
            panic!("CRASH_INJECT: {}", point.label());
        }
    }
}

/// Inject a crash at a named injection point if the crash injection
/// config is armed for this point.
///
/// Usage:
/// ```ignore
/// crash_inject!(&self.store.primary_store().fault_injection_config(),
///               CrashInjectionPoint::CommitGroupBeforeCommit);
/// ```
#[macro_export]
macro_rules! crash_inject {
    ($fault_config:expr, $point:expr) => {
        $crate::fault_injection::check_crash_inject($fault_config.and_then(|c| Some(c)), $point);
    };
}

/// Fault injection configuration for crash and corruption testing.
#[derive(Clone, Debug)]
pub struct FaultInjectionConfig {
    pub write_failure_probability: f64,
    pub byte_corruption_probability: f64,
    pub enospc_after_bytes: Option<u64>,
    /// Typed fault campaign schedule (P10-02). When set, this drives
    /// fault injection with a seed-reproducible, typed schedule.
    pub schedule: Option<FaultSchedule>,
    /// Crash injection configuration (#1230).
    pub crash: CrashInjectionConfig,
}

impl FaultInjectionConfig {
    #[must_use]
    pub fn off() -> Self {
        Self {
            write_failure_probability: 0.0,
            byte_corruption_probability: 0.0,
            enospc_after_bytes: None,
            schedule: None,
            crash: CrashInjectionConfig::off(),
        }
    }

    #[must_use]
    pub fn chaos(_seed: u64) -> Self {
        Self {
            write_failure_probability: 0.02,
            byte_corruption_probability: 0.001,
            enospc_after_bytes: None,
            schedule: None,
            crash: CrashInjectionConfig::off(),
        }
    }

    /// Create a config from a typed [`FaultSchedule`] (P10-02 campaign).
    #[must_use]
    pub fn from_schedule(schedule: FaultSchedule) -> Self {
        Self {
            write_failure_probability: 0.0,
            byte_corruption_probability: 0.0,
            enospc_after_bytes: None,
            schedule: Some(schedule),
            crash: CrashInjectionConfig::off(),
        }
    }

    #[must_use]
    pub fn is_active(&self) -> bool {
        self.write_failure_probability > 0.0
            || self.byte_corruption_probability > 0.0
            || self.enospc_after_bytes.is_some()
            || self.schedule.is_some()
            || self.crash.is_active()
    }

    #[must_use]
    pub fn should_fail_write(&self, rng: &mut impl Rng) -> bool {
        rng.gen_bool(self.write_failure_probability.clamp(0.0, 1.0))
    }

    pub fn corrupt_payload(&self, rng: &mut impl Rng, payload: &mut [u8]) {
        let prob = self.byte_corruption_probability.clamp(0.0, 1.0);
        if prob <= 0.0 {
            return;
        }
        for byte in payload.iter_mut() {
            if rng.gen_bool(prob) {
                *byte ^= 0xFF;
            }
        }
    }
}

impl Default for FaultInjectionConfig {
    fn default() -> Self {
        Self::off()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn off_config_never_injects() {
        let cfg = FaultInjectionConfig::off();
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..1000 {
            assert!(!cfg.should_fail_write(&mut rng));
        }
        let mut payload = b"hello".to_vec();
        let orig = payload.clone();
        cfg.corrupt_payload(&mut rng, &mut payload);
        assert_eq!(payload, orig);
    }

    #[test]
    fn always_fail() {
        let cfg = FaultInjectionConfig {
            write_failure_probability: 1.0,
            ..FaultInjectionConfig::off()
        };
        let mut rng = StdRng::seed_from_u64(99);
        for _ in 0..100 {
            assert!(cfg.should_fail_write(&mut rng));
        }
    }

    #[test]
    fn corruption_modifies() {
        let cfg = FaultInjectionConfig {
            byte_corruption_probability: 0.5,
            ..FaultInjectionConfig::off()
        };
        let mut rng = StdRng::seed_from_u64(7);
        let mut payload = vec![0u8; 1000];
        cfg.corrupt_payload(&mut rng, &mut payload);
        assert!(payload.iter().any(|&b| b != 0));
    }
}
