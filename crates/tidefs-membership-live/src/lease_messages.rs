// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Lease protocol message construction.
//!
//! Provides typed builder functions that construct [`MembershipMessage`]
//! variants for lease lifecycle operations. Each function accepts domain
//! parameters (member identity, lease identity, epoch, term, TTL) and
//! returns the correctly-formed protocol message variant.
//!
//! ## Lease Lifecycle
//!
//! ```text
//!   Grant ──> Renew ──> Revoke
//!     │         │
//!     └──> Expire (if TTL elapses without renewal)
//!     │
//!     └──> Acknowledge (lease-holder confirms grant)
//! ```
//!
//! Builders populate millisecond timestamps from a caller-provided clock
//! value so that the caller controls time sourcing (wall clock, simulated
//! clock, or deterministic monotonic), keeping the message construction
//! layer free of ambient time dependencies.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tidefs_membership_epoch::{EpochId, MemberId};

use crate::dispatch_router::MembershipMessage;

// ---------------------------------------------------------------------------
// Lease domain types
// ---------------------------------------------------------------------------

/// Unique lease identifier scoped within an epoch.
///
/// Lease IDs are assigned by the lease manager on grant and remain
/// stable across renewals within the same epoch. A new epoch receives
/// a fresh lease-id namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseId(pub u64);

impl LeaseId {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

impl From<u64> for LeaseId {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

/// Monotonic lease term counter.
///
/// Incremented on each grant and renewal to detect stale or
/// replayed lease messages. The lease holder must present a
/// term at least as high as the manager's last-issued term
/// for write-authority operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseTerm(pub u64);

impl LeaseTerm {
    #[must_use]
    pub const fn new(term: u64) -> Self {
        Self(term)
    }
}

// ---------------------------------------------------------------------------
// Clock helpers
// ---------------------------------------------------------------------------

/// Return the current wall-clock millisecond timestamp.
///
/// This is suitable for production message construction where
/// the system clock is the authority. For deterministic or
/// simulated environments, callers should use a synthetic clock
/// and pass the value directly to builder alternative functions.
#[must_use]
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Builder functions
// ---------------------------------------------------------------------------

/// Build a `LeaseGrant` message.
///
/// Called by the lease manager when it grants write authority to
/// `member_id` for the given `lease_id` within `epoch`.
/// `term` is the monotonic lease term; `ttl` is the duration
/// before the lease expires (typically a few seconds).
#[must_use]
pub fn build_lease_grant(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    term: LeaseTerm,
    ttl: Duration,
) -> MembershipMessage {
    let now = now_millis();
    MembershipMessage::LeaseGrant {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        lease_term: term.0,
        lease_ttl_millis: ttl.as_millis() as u64,
        lease_expires_at_millis: now.saturating_add(ttl.as_millis() as u64),
        granted_at_millis: now,
    }
}

/// Build a `LeaseGrant` message with an explicit clock value.
///
/// Use this variant for deterministic or simulated clocks.
#[must_use]
pub fn build_lease_grant_at(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    term: LeaseTerm,
    ttl: Duration,
    at_millis: u64,
) -> MembershipMessage {
    MembershipMessage::LeaseGrant {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        lease_term: term.0,
        lease_ttl_millis: ttl.as_millis() as u64,
        lease_expires_at_millis: at_millis.saturating_add(ttl.as_millis() as u64),
        granted_at_millis: at_millis,
    }
}

/// Build a `LeaseRenew` message.
///
/// Called when the lease holder requests an extension of its
/// current lease before the TTL expires. `term` must be >= the
/// last-granted term; the lease manager rejects stale terms.
#[must_use]
pub fn build_lease_renew(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    term: LeaseTerm,
    ttl: Duration,
) -> MembershipMessage {
    let now = now_millis();
    MembershipMessage::LeaseRenew {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        lease_term: term.0,
        lease_ttl_millis: ttl.as_millis() as u64,
        new_expires_at_millis: now.saturating_add(ttl.as_millis() as u64),
        renewed_at_millis: now,
    }
}

/// Build a `LeaseRenew` message with an explicit clock value.
#[must_use]
pub fn build_lease_renew_at(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    term: LeaseTerm,
    ttl: Duration,
    at_millis: u64,
) -> MembershipMessage {
    MembershipMessage::LeaseRenew {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        lease_term: term.0,
        lease_ttl_millis: ttl.as_millis() as u64,
        new_expires_at_millis: at_millis.saturating_add(ttl.as_millis() as u64),
        renewed_at_millis: at_millis,
    }
}

/// Build a `LeaseRevoke` message.
///
/// Called by the lease manager (or epoch transition logic) to
/// strip write authority from `member_id` for the specific lease.
#[must_use]
pub fn build_lease_revoke(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
) -> MembershipMessage {
    MembershipMessage::LeaseRevoke {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        revoked_at_millis: now_millis(),
    }
}

/// Build a `LeaseRevoke` message with an explicit clock value.
#[must_use]
pub fn build_lease_revoke_at(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    at_millis: u64,
) -> MembershipMessage {
    MembershipMessage::LeaseRevoke {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        revoked_at_millis: at_millis,
    }
}

/// Build a `LeaseAcknowledge` message.
///
/// Sent by the lease holder to confirm receipt and acceptance
/// of a lease grant. If `accepted` is false, the lease manager
/// should treat the grant as rejected and may reassign.
#[must_use]
pub fn build_lease_acknowledge(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    accepted: bool,
) -> MembershipMessage {
    MembershipMessage::LeaseAcknowledge {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        accepted,
        acknowledged_at_millis: now_millis(),
    }
}

/// Build a `LeaseAcknowledge` message with an explicit clock value.
#[must_use]
pub fn build_lease_acknowledge_at(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    accepted: bool,
    at_millis: u64,
) -> MembershipMessage {
    MembershipMessage::LeaseAcknowledge {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        accepted,
        acknowledged_at_millis: at_millis,
    }
}

/// Build a `LeaseExpire` message.
///
/// Sent by the lease manager when a lease's TTL elapses
/// without a timely renewal. This message notifies the former
/// lease holder (and any observers) that write authority has
/// been automatically withdrawn.
#[must_use]
pub fn build_lease_expire(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
) -> MembershipMessage {
    MembershipMessage::LeaseExpire {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        expired_at_millis: now_millis(),
    }
}

/// Build a `LeaseExpire` message with an explicit clock value.
#[must_use]
pub fn build_lease_expire_at(
    member_id: MemberId,
    lease_id: LeaseId,
    epoch: EpochId,
    at_millis: u64,
) -> MembershipMessage {
    MembershipMessage::LeaseExpire {
        member_id,
        lease_id: lease_id.0,
        lease_epoch: epoch,
        expired_at_millis: at_millis,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;
    use tidefs_membership_epoch::{EpochId, MemberId};

    // ------------------------------------------------------------------
    // LeaseId / LeaseTerm unit tests
    // ------------------------------------------------------------------

    #[test]
    fn lease_id_new_and_from() {
        let a = LeaseId::new(42);
        let b: LeaseId = 42u64.into();
        assert_eq!(a, b);
        assert_eq!(a.0, 42);
    }

    #[test]
    fn lease_id_ordering() {
        let a = LeaseId::new(1);
        let b = LeaseId::new(2);
        assert!(a < b);
    }

    #[test]
    fn lease_term_new_and_ordering() {
        let a = LeaseTerm::new(0);
        let b = LeaseTerm::new(1);
        assert!(a < b);
        assert_eq!(a.0, 0);
    }

    // ------------------------------------------------------------------
    // build_lease_grant tests
    // ------------------------------------------------------------------

    #[test]
    fn build_lease_grant_produces_correct_variant() {
        let msg = build_lease_grant_at(
            MemberId::new(10),
            LeaseId::new(1),
            EpochId::new(3),
            LeaseTerm::new(0),
            Duration::from_secs(5),
            1000,
        );
        match msg {
            MembershipMessage::LeaseGrant {
                member_id,
                lease_id,
                lease_epoch,
                lease_term,
                lease_ttl_millis,
                lease_expires_at_millis,
                granted_at_millis,
            } => {
                assert_eq!(member_id, MemberId::new(10));
                assert_eq!(lease_id, 1);
                assert_eq!(lease_epoch, EpochId::new(3));
                assert_eq!(lease_term, 0);
                assert_eq!(lease_ttl_millis, 5000);
                assert_eq!(lease_expires_at_millis, 6000);
                assert_eq!(granted_at_millis, 1000);
            }
            _ => panic!("expected LeaseGrant, got {:?}", msg.discriminant()),
        }
    }

    #[test]
    fn build_lease_grant_computes_expiry_from_now() {
        let msg = build_lease_grant(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(1),
            Duration::from_secs(10),
        );
        match msg {
            MembershipMessage::LeaseGrant {
                lease_expires_at_millis,
                granted_at_millis,
                lease_ttl_millis,
                ..
            } => {
                assert!(granted_at_millis > 0);
                assert_eq!(lease_ttl_millis, 10_000);
                assert!(lease_expires_at_millis > granted_at_millis);
            }
            _ => panic!("expected LeaseGrant"),
        }
    }

    #[test]
    fn build_lease_grant_zero_ttl() {
        let msg = build_lease_grant_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(0),
            Duration::ZERO,
            5000,
        );
        match msg {
            MembershipMessage::LeaseGrant {
                lease_ttl_millis,
                lease_expires_at_millis,
                ..
            } => {
                assert_eq!(lease_ttl_millis, 0);
                assert_eq!(lease_expires_at_millis, 5000);
            }
            _ => panic!("expected LeaseGrant"),
        }
    }

    #[test]
    fn build_lease_grant_max_epoch_and_term() {
        let msg = build_lease_grant_at(
            MemberId::new(u64::MAX),
            LeaseId::new(u64::MAX),
            EpochId::new(u64::MAX),
            LeaseTerm::new(u64::MAX),
            Duration::from_secs(60),
            0,
        );
        match msg {
            MembershipMessage::LeaseGrant {
                member_id,
                lease_id,
                lease_epoch,
                lease_term,
                ..
            } => {
                assert_eq!(member_id, MemberId::new(u64::MAX));
                assert_eq!(lease_id, u64::MAX);
                assert_eq!(lease_epoch, EpochId::new(u64::MAX));
                assert_eq!(lease_term, u64::MAX);
            }
            _ => panic!("expected LeaseGrant"),
        }
    }

    // ------------------------------------------------------------------
    // build_lease_renew tests
    // ------------------------------------------------------------------

    #[test]
    fn build_lease_renew_produces_correct_variant() {
        let msg = build_lease_renew_at(
            MemberId::new(20),
            LeaseId::new(5),
            EpochId::new(7),
            LeaseTerm::new(3),
            Duration::from_secs(3),
            2000,
        );
        match msg {
            MembershipMessage::LeaseRenew {
                member_id,
                lease_id,
                lease_epoch,
                lease_term,
                lease_ttl_millis,
                new_expires_at_millis,
                renewed_at_millis,
            } => {
                assert_eq!(member_id, MemberId::new(20));
                assert_eq!(lease_id, 5);
                assert_eq!(lease_epoch, EpochId::new(7));
                assert_eq!(lease_term, 3);
                assert_eq!(lease_ttl_millis, 3000);
                assert_eq!(new_expires_at_millis, 5000);
                assert_eq!(renewed_at_millis, 2000);
            }
            _ => panic!("expected LeaseRenew, got {:?}", msg.discriminant()),
        }
    }

    // ------------------------------------------------------------------
    // build_lease_revoke tests
    // ------------------------------------------------------------------

    #[test]
    fn build_lease_revoke_produces_correct_variant() {
        let msg = build_lease_revoke_at(MemberId::new(30), LeaseId::new(9), EpochId::new(2), 3000);
        match msg {
            MembershipMessage::LeaseRevoke {
                member_id,
                lease_id,
                lease_epoch,
                revoked_at_millis,
            } => {
                assert_eq!(member_id, MemberId::new(30));
                assert_eq!(lease_id, 9);
                assert_eq!(lease_epoch, EpochId::new(2));
                assert_eq!(revoked_at_millis, 3000);
            }
            _ => panic!("expected LeaseRevoke, got {:?}", msg.discriminant()),
        }
    }

    // ------------------------------------------------------------------
    // build_lease_acknowledge tests
    // ------------------------------------------------------------------

    #[test]
    fn build_lease_acknowledge_accepted() {
        let msg = build_lease_acknowledge_at(
            MemberId::new(40),
            LeaseId::new(3),
            EpochId::new(1),
            true,
            4000,
        );
        match msg {
            MembershipMessage::LeaseAcknowledge {
                member_id,
                lease_id,
                lease_epoch,
                accepted,
                acknowledged_at_millis,
            } => {
                assert_eq!(member_id, MemberId::new(40));
                assert_eq!(lease_id, 3);
                assert_eq!(lease_epoch, EpochId::new(1));
                assert!(accepted);
                assert_eq!(acknowledged_at_millis, 4000);
            }
            _ => panic!("expected LeaseAcknowledge, got {:?}", msg.discriminant()),
        }
    }

    #[test]
    fn build_lease_acknowledge_rejected() {
        let msg = build_lease_acknowledge_at(
            MemberId::new(50),
            LeaseId::new(7),
            EpochId::new(4),
            false,
            5000,
        );
        match msg {
            MembershipMessage::LeaseAcknowledge { accepted, .. } => {
                assert!(!accepted);
            }
            _ => panic!("expected LeaseAcknowledge"),
        }
    }

    // ------------------------------------------------------------------
    // build_lease_expire tests
    // ------------------------------------------------------------------

    #[test]
    fn build_lease_expire_produces_correct_variant() {
        let msg = build_lease_expire_at(MemberId::new(60), LeaseId::new(11), EpochId::new(5), 6000);
        match msg {
            MembershipMessage::LeaseExpire {
                member_id,
                lease_id,
                lease_epoch,
                expired_at_millis,
            } => {
                assert_eq!(member_id, MemberId::new(60));
                assert_eq!(lease_id, 11);
                assert_eq!(lease_epoch, EpochId::new(5));
                assert_eq!(expired_at_millis, 6000);
            }
            _ => panic!("expected LeaseExpire, got {:?}", msg.discriminant()),
        }
    }

    // ------------------------------------------------------------------
    // Cross-builder distinctness tests
    // ------------------------------------------------------------------

    #[test]
    fn back_to_back_grant_and_revoke_produce_distinct_messages() {
        let grant = build_lease_grant_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(0),
            Duration::from_secs(10),
            100,
        );
        let revoke = build_lease_revoke_at(MemberId::new(1), LeaseId::new(1), EpochId::new(0), 200);
        assert_ne!(grant, revoke);
    }

    #[test]
    fn grant_renew_revoke_are_distinct_variants() {
        let grant = build_lease_grant_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(0),
            Duration::from_secs(5),
            0,
        );
        let renew = build_lease_renew_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(1),
            Duration::from_secs(5),
            0,
        );
        let revoke = build_lease_revoke_at(MemberId::new(1), LeaseId::new(1), EpochId::new(0), 0);
        assert_ne!(grant.discriminant(), renew.discriminant());
        assert_ne!(renew.discriminant(), revoke.discriminant());
        assert_ne!(revoke.discriminant(), grant.discriminant());
    }

    #[test]
    fn acknowledge_accepted_vs_rejected_are_distinct() {
        let accepted =
            build_lease_acknowledge_at(MemberId::new(1), LeaseId::new(1), EpochId::new(0), true, 0);
        let rejected = build_lease_acknowledge_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            false,
            0,
        );
        assert_ne!(accepted, rejected);
    }

    #[test]
    fn different_lease_ids_produce_different_messages() {
        let a = build_lease_grant_at(
            MemberId::new(1),
            LeaseId::new(1),
            EpochId::new(0),
            LeaseTerm::new(0),
            Duration::from_secs(5),
            0,
        );
        let b = build_lease_grant_at(
            MemberId::new(1),
            LeaseId::new(2),
            EpochId::new(0),
            LeaseTerm::new(0),
            Duration::from_secs(5),
            0,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn lease_id_hash_and_eq() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(LeaseId::new(1));
        set.insert(LeaseId::new(1));
        set.insert(LeaseId::new(2));
        assert_eq!(set.len(), 2);
    }
}
