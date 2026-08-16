// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Live Pool-lease session contract shared by product carriers.

use std::time::{Duration, Instant};

use crate::PoolLeaseToken;

const MIN_RENEWAL_LEAD_MS: u64 = 250;
const MAX_RENEWAL_LEAD_MS: u64 = 10_000;

/// Authenticated Pool authority plus its conservative process-local deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterLeaseGrant {
    pub token: PoolLeaseToken,
    pub valid_until: Instant,
}

impl ClusterLeaseGrant {
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.valid_until.saturating_duration_since(Instant::now())
    }
}

/// Live authenticated session capable of renewing and releasing one Pool lease.
pub trait ClusterLeaseSession: std::fmt::Debug + Send {
    fn renew(&mut self, token: &PoolLeaseToken) -> Result<ClusterLeaseGrant, String>;

    fn release(&mut self, token: &PoolLeaseToken) -> Result<(), String>;
}

/// Schedule renewal early enough to preserve a bounded local safety margin.
#[must_use]
pub fn cluster_lease_renewal_at(valid_until: Instant) -> Instant {
    let now = Instant::now();
    let valid_for = valid_until.saturating_duration_since(now);
    let remaining_ms = u64::try_from(valid_for.as_millis()).unwrap_or(u64::MAX);
    let lead_ms = (remaining_ms / 3)
        .clamp(MIN_RENEWAL_LEAD_MS, MAX_RENEWAL_LEAD_MS)
        .min((remaining_ms / 2).max(1));
    now.checked_add(Duration::from_millis(remaining_ms.saturating_sub(lead_ms)))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_is_scheduled_before_local_expiration() {
        let now = Instant::now();
        let valid_until = now + Duration::from_secs(30);
        let renewal_at = cluster_lease_renewal_at(valid_until);

        assert!(renewal_at >= now);
        assert!(renewal_at < valid_until);
    }
}
