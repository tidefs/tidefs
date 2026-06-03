//! Integration bridge between membership epoch transitions and the cluster
//! lease runtime.
//!
//! When the membership epoch advances, any held membership lease must be
//! renegotiated for the new epoch. Callers that drive epoch transitions
//! (typically the `MembershipRuntime`) should invoke
//! [`renegotiate_lease_on_epoch`] after each successful epoch advance to
//! keep lease state aligned with membership state.
//!
//! ## Usage pattern
//!
//! ```ignore
//! use tidefs_membership_live::cluster_lease_wiring::renegotiate_lease_on_epoch;
//!
//! // After the EpochTransitionEngine commits a new epoch:
//! if let Some(ref mut lease_rt) = cluster_lease_runtime {
//!     renegotiate_lease_on_epoch(lease_rt, new_epoch);
//! }
//! ```

use tidefs_cluster::ClusterLeaseRuntime;
use tidefs_membership_epoch::EpochId;

/// Notify the cluster lease runtime that the membership epoch has advanced,
/// triggering lease renegotiation if a lease from the old epoch is held.
pub fn renegotiate_lease_on_epoch(runtime: &mut ClusterLeaseRuntime, new_epoch: EpochId) {
    runtime.on_epoch_transition(new_epoch);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tidefs_cluster::{ClusterLeaseConfig, ClusterLeaseRuntime};

    #[test]
    fn renegotiate_updates_epoch() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut rt = ClusterLeaseRuntime::new(1, EpochId(1), ClusterLeaseConfig::default(), tx);

        renegotiate_lease_on_epoch(&mut rt, EpochId(2));

        let status = rt.status();
        assert_eq!(status.current_epoch, EpochId(2));
    }
}
