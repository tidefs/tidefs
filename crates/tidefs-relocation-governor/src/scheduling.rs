// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Background-scheduler and incremental-job integration for the
//! relocation governor.
//!
//! The governor integrates with the canonical background-service framework
//! and incremental-job model. It does not create an independent unbounded
//! relocation executor.
//!
//! For the first #848 law/model slice, this module provides the integration
//! surface and stubs. Concrete data-mover execution and receipt retirement
//! are out of scope.

use crate::governor::RelocationGovernor;
use crate::reasons::GovernorRelocationReason;

/// Background service adaptor for the relocation governor.
///
/// Wraps the governor so it can be driven by the background scheduler's
/// priority-lane dispatch. The governor service runs at `Maintenance`
/// priority: below critical (repair/sync) and writeback, but above idle.
///
/// For the first slice, this is a stub that demonstrates the integration
/// shape. Full scheduler integration requires implementing the
/// `BackgroundService` or `Schedulable` trait and registering with the
/// scheduler.
pub struct RelocationGovernorService {
    /// The underlying governor.
    pub governor: RelocationGovernor,

    /// Current time source (ms since epoch).
    now_ms: u64,
}

impl RelocationGovernorService {
    /// Create a new relocation governor service.
    #[must_use]
    pub fn new(governor: RelocationGovernor) -> Self {
        RelocationGovernorService {
            governor,
            now_ms: 0,
        }
    }

    /// Advance the service clock.
    pub fn advance_time(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }

    /// Set the current time.
    pub fn set_time(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Current time.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Poll the governor: expire cooldowns and return the number of
    /// active relocations.
    #[must_use]
    pub fn poll(&mut self) -> GovernorPollResult {
        self.governor.expire_cooldowns(self.now_ms);

        GovernorPollResult {
            admitted_count: self.governor.admitted_count(),
            bytes_in_flight: self.governor.bytes_in_flight(),
            can_admit: self.governor.can_admit(),
        }
    }
}

/// Result of polling the governor service.
#[derive(Clone, Copy, Debug)]
pub struct GovernorPollResult {
    /// Number of currently admitted relocations.
    pub admitted_count: usize,

    /// Total bytes in flight.
    pub bytes_in_flight: u64,

    /// Whether the governor can admit more relocations.
    pub can_admit: bool,
}

/// Relocation governor job kind for the incremental-job model.
///
/// Each relocation proposal that passes admission becomes an
/// incremental job. The governor does not execute the job; it hands
/// the admission record to the appropriate data mover or scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationJobKind {
    /// HDD defrag job.
    HddDefrag,

    /// SSD compaction job.
    SsdCompaction,

    /// Wear rebalance job.
    WearRebalance,

    /// Geo catch-up job.
    GeoCatchup,

    /// Rebake (data-shape transform) job.
    Rebake,

    /// Promotion job.
    Promotion,

    /// Demotion job.
    Demotion,

    /// Policy satisfaction job.
    PolicySatisfaction,

    /// Repair/rebuild job.
    Repair,

    /// Evacuation/drain job.
    Evacuation,
}

impl RelocationJobKind {
    /// Map from governor relocation reason.
    #[must_use]
    pub const fn from_reason(reason: GovernorRelocationReason) -> Self {
        match reason {
            GovernorRelocationReason::PolicySatisfaction => RelocationJobKind::PolicySatisfaction,
            GovernorRelocationReason::Repair => RelocationJobKind::Repair,
            GovernorRelocationReason::Evacuation => RelocationJobKind::Evacuation,
            GovernorRelocationReason::HddDefrag => RelocationJobKind::HddDefrag,
            GovernorRelocationReason::SsdCompaction => RelocationJobKind::SsdCompaction,
            GovernorRelocationReason::Rebake => RelocationJobKind::Rebake,
            GovernorRelocationReason::Promotion => RelocationJobKind::Promotion,
            GovernorRelocationReason::Demotion => RelocationJobKind::Demotion,
            GovernorRelocationReason::GeoCatchup => RelocationJobKind::GeoCatchup,
            GovernorRelocationReason::WearRebalance => RelocationJobKind::WearRebalance,
        }
    }

    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RelocationJobKind::HddDefrag => "hdd-defrag",
            RelocationJobKind::SsdCompaction => "ssd-compaction",
            RelocationJobKind::WearRebalance => "wear-rebalance",
            RelocationJobKind::GeoCatchup => "geo-catchup",
            RelocationJobKind::Rebake => "rebake",
            RelocationJobKind::Promotion => "promotion",
            RelocationJobKind::Demotion => "demotion",
            RelocationJobKind::PolicySatisfaction => "policy-satisfaction",
            RelocationJobKind::Repair => "repair",
            RelocationJobKind::Evacuation => "evacuation",
        }
    }
}

impl core::fmt::Display for RelocationJobKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governor::RelocationGovernorConfig;

    #[test]
    fn poll_expires_cooldowns() {
        let mut gov = RelocationGovernor::new(RelocationGovernorConfig {
            default_cooldown_ms: 100_000,
            ..RelocationGovernorConfig::default()
        });
        // Enter cooldown via a refused proposal (stub: directly set cooldown)
        gov.enter_cooldown_for_subject(1, 0, GovernorRelocationReason::Promotion, "test", false);

        let mut service = RelocationGovernorService::new(gov);
        service.set_time(50_000);
        let result = service.poll();
        // Cooldown still active, no admissions
        assert_eq!(result.admitted_count, 0);

        service.set_time(200_000);
        let result = service.poll();
        // Cooldown should have expired by now
        assert_eq!(result.admitted_count, 0);
        assert!(result.can_admit);
    }

    #[test]
    fn job_kind_from_all_reasons() {
        for reason in &GovernorRelocationReason::ALL {
            let kind = RelocationJobKind::from_reason(*reason);
            assert!(!format!("{kind}").is_empty());
        }
    }
}
