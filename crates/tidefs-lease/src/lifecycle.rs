//! Lease lifecycle management: renewal scheduling, expiry tracking,
//! fencing integration, and release coordination (P8-03 core law 5).
//!
//! Tracks active leases through their lifecycle, integrates with
//! tidefs-clock-timing for deadline management.

use crate::types::*;
use std::collections::BTreeMap;
use tidefs_clock_timing::types::{DriftClass, LeaseDeadlineState};
use tidefs_clock_timing::LeaseDeadline;

/// Manages the lifecycle of multiple lease grants.
///
/// Tracks deadlines, handles renewal scheduling, evaluates expiry,
/// and coordinates fencing.
pub struct LeaseLifecycleManager {
    leases: BTreeMap<u64, (LeaseGrant, LeaseDeadline)>,
    default_renew_period_ns: u64,
    default_expiry_period_ns: u64,
    default_grace_period_ns: u64,
}

impl LeaseLifecycleManager {
    /// Create a new lifecycle manager with default periods (in nanoseconds).
    pub fn new(
        default_renew_period_ns: u64,
        default_expiry_period_ns: u64,
        default_grace_period_ns: u64,
    ) -> Self {
        LeaseLifecycleManager {
            leases: BTreeMap::new(),
            default_renew_period_ns,
            default_expiry_period_ns,
            default_grace_period_ns,
        }
    }

    /// Register a newly granted lease for lifecycle tracking.
    pub fn register(&mut self, grant: &LeaseGrant) {
        let lease_id = grant.lease_id;
        let now_ns = now_nanos();
        let deadline = LeaseDeadline::open(
            lease_id,
            now_ns,
            self.default_renew_period_ns,
            self.default_expiry_period_ns,
            self.default_grace_period_ns,
            DriftClass::TrustedLocal,
        );
        self.leases.insert(lease_id, (grant.clone(), deadline));
    }

    /// Evaluate all tracked leases and return statuses.
    pub fn evaluate_all(&mut self) -> Vec<LeaseLifecycleStatus> {
        let now = now_nanos();
        let mut statuses = Vec::new();
        for (lease_id, (grant, deadline)) in &mut self.leases {
            let state = deadline.evaluate(now);
            if grant.lifecycle.is_terminal() {
                continue;
            }
            match state {
                LeaseDeadlineState::Expired => {
                    grant.lifecycle = LeaseLifecycle::Expired;
                }
                LeaseDeadlineState::Grace => {
                    // Grace period: lease is technically expired but not yet terminal.
                }
                _ => {}
            }
            statuses.push(LeaseLifecycleStatus {
                lease_id: *lease_id,
                deadline_state: state,
                lease_lifecycle: grant.lifecycle,
                version: grant.version,
            });
        }
        statuses
    }

    /// Renew a tracked lease, extending its deadline.
    pub fn renew(&mut self, lease_id: u64) -> Result<(), LeaseError> {
        let (grant, deadline) = self
            .leases
            .get_mut(&lease_id)
            .ok_or(LeaseError::NotFound { lease_id })?;

        if grant.lifecycle.is_terminal() {
            return Err(LeaseError::AlreadyTerminal {
                lease_id,
                state: grant.lifecycle,
            });
        }

        let now = now_nanos();
        deadline.renew(
            now,
            self.default_renew_period_ns,
            self.default_expiry_period_ns,
            self.default_grace_period_ns,
        );
        grant.lifecycle = LeaseLifecycle::Granted;
        grant.version = grant.version.saturating_add(1);
        Ok(())
    }

    /// Stage failover for an expired lease.
    pub fn stage_failover(&mut self, lease_id: u64) -> Option<LeaseLifecycleStatus> {
        let (grant, deadline) = self.leases.get_mut(&lease_id)?;
        deadline.stage_failover()?;
        Some(LeaseLifecycleStatus {
            lease_id,
            deadline_state: LeaseDeadlineState::FailoverStaged,
            lease_lifecycle: grant.lifecycle,
            version: grant.version,
        })
    }

    /// Remove a lease from tracking (e.g., after release/fence/release).
    pub fn deregister(&mut self, lease_id: u64) {
        self.leases.remove(&lease_id);
    }

    /// Return the number of tracked leases.
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// Return true if no leases are tracked.
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

/// Status of a lease lifecycle at evaluation time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseLifecycleStatus {
    pub lease_id: u64,
    pub deadline_state: LeaseDeadlineState,
    pub lease_lifecycle: LeaseLifecycle,
    pub version: u64,
}

fn now_nanos() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn make_grant(id: u64) -> LeaseGrant {
        LeaseGrant::request(
            id,
            LeaseClass::Exclusive,
            LeaseDomain::EpochTransition {
                epoch_id: tidefs_membership_epoch::EpochId::new(1),
            },
            tidefs_membership_epoch::MemberId::new(1),
            60_000,
            0,
            tidefs_membership_epoch::EpochId::new(1),
            id,
            3,
            3,
        )
    }

    #[test]
    fn test_register_and_evaluate() {
        let mut mgr = LeaseLifecycleManager::new(
            500_000_000,   // 500ms renew
            2_000_000_000, // 2s expiry
            1_000_000_000, // 1s grace
        );
        let grant = make_grant(1);
        mgr.register(&grant);
        assert_eq!(mgr.len(), 1);

        let statuses = mgr.evaluate_all();
        assert!(!statuses.is_empty());
        // Should be Open initially.
        let s = &statuses[0];
        assert_eq!(s.lease_id, 1);
        assert_eq!(s.deadline_state, LeaseDeadlineState::Open);
    }

    #[test]
    fn test_renewal() {
        let mut mgr = LeaseLifecycleManager::new(500_000_000, 2_000_000_000, 1_000_000_000);
        let grant = make_grant(1);
        mgr.register(&grant);
        mgr.renew(1).expect("renewal should succeed");
        let statuses = mgr.evaluate_all();
        assert_eq!(statuses[0].version, 2);
    }

    #[test]
    fn test_deregister() {
        let mut mgr = LeaseLifecycleManager::new(500_000_000, 2_000_000_000, 1_000_000_000);
        let grant = make_grant(1);
        mgr.register(&grant);
        assert_eq!(mgr.len(), 1);
        mgr.deregister(1);
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_renewal_on_expired_fails() {
        let mut mgr = LeaseLifecycleManager::new(
            500_000_000,
            1,
            1, // very short expiry
        );
        let grant = make_grant(1);
        mgr.register(&grant);
        std::thread::sleep(std::time::Duration::from_millis(5));
        mgr.evaluate_all(); // should transition to Expired

        let result = mgr.renew(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_renewal_not_found() {
        let mut mgr = LeaseLifecycleManager::new(500_000_000, 2_000_000_000, 1_000_000_000);
        let result = mgr.renew(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_stage_failover_not_expired() {
        let mut mgr = LeaseLifecycleManager::new(500_000_000, 60_000_000_000, 10_000_000_000);
        let grant = make_grant(1);
        mgr.register(&grant);
        // Should be Open, not expired - failover should not be possible.
        let result = mgr.stage_failover(1);
        assert!(result.is_none());
    }
}
