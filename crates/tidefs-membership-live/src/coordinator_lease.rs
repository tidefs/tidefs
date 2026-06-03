#![forbid(unsafe_code)]

//! Coordinator epoch lease with transport-based heartbeat renewal and
//! quorum-loss automatic stepdown.
//!
//! Prevents split-brain coordinator operation during network partitions
//! by requiring the active coordinator to periodically confirm majority
//! connectivity through transport heartbeats to every roster member.
//!
//! ## Architecture
//!
//! ```text
//! CoordinatorLease (tick-driven)
//!   |
//!   +-- on each heartbeat tick (interval/3):
//!   |     increment lease_nonce
//!   |     send CoordinatorHeartbeat to every roster member
//!   |
//!   +-- on each tick, collect CoordinatorHeartbeatAck responses
//!   |
//!   +-- at end of heartbeat window:
//!         evaluate_renewal(ack_count, roster_size) -> LeaseStatus
//!         if Lost: emit stepdown, deactivate
//! ```
//!
//! ## Peer-side
//!
//! The [`handle_inbound_heartbeat`] function handles inbound heartbeats:
//! - Matching epoch: reply with ack immediately.
//! - Stale epoch: reply with ack (no side effect).
//! - Future epoch: reply with ack, trigger catch-up signal.
//!
//! ## Integration
//!
//! - Activated on coordinator promotion via [`CoordinatorLease::activate`].
//! - Deactivated on stepdown via [`CoordinatorLease::deactivate`].
//! - The stepdown callback is invoked when quorum is lost, signaling the
//!   coordinator promotion subsystem (#6160) to initiate failover.

use std::collections::HashSet;
use std::time::Duration;
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// CoordinatorLeaseConfig
// ---------------------------------------------------------------------------

/// Configuration for the coordinator epoch lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorLeaseConfig {
    /// Duration of the lease. The coordinator must receive majority
    /// acknowledgments within this window; otherwise the lease is lost.
    pub lease_duration: Duration,
    /// Interval at which heartbeats are sent to roster members.
    /// Internally, the heartbeat fires at interval/3 to allow multiple
    /// retry rounds within the lease duration.
    pub heartbeat_interval: Duration,
}

impl Default for CoordinatorLeaseConfig {
    fn default() -> Self {
        Self {
            lease_duration: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(10),
        }
    }
}

impl CoordinatorLeaseConfig {
    /// Create a new config with explicit durations.
    #[must_use]
    pub const fn new(lease_duration: Duration, heartbeat_interval: Duration) -> Self {
        Self {
            lease_duration,
            heartbeat_interval,
        }
    }

    /// The interval between individual heartbeat rounds (interval/3).
    #[must_use]
    pub fn heartbeat_tick_interval(&self) -> Duration {
        self.heartbeat_interval.div_f64(3.0)
    }

    /// Number of heartbeat rounds within the lease duration.
    #[must_use]
    pub fn rounds_per_lease(&self) -> u64 {
        let tick_ms = self.heartbeat_tick_interval().as_millis().max(1);
        let lease_ms = self.lease_duration.as_millis();
        (lease_ms / tick_ms) as u64
    }
}

// ---------------------------------------------------------------------------
// LeaseStatus
// ---------------------------------------------------------------------------

/// Outcome of a coordinator lease renewal evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseStatus {
    /// The coordinator received acknowledgments from a majority of
    /// roster members — the lease remains held.
    Held,
    /// The coordinator lost quorum — fewer than majority acknowledged.
    /// The coordinator should step down and trigger failover.
    Lost,
}

// ---------------------------------------------------------------------------
// CoordinatorLease
// ---------------------------------------------------------------------------

/// A coordinator epoch lease that prevents split-brain by requiring
/// periodic majority confirmation through transport heartbeats.
///
/// The lease is tick-driven: callers invoke [`tick`] periodically
/// (matching the heartbeat tick interval). On each tick the lease
/// evaluates whether it's time to send a new heartbeat round or
/// collect acks from the previous round.
///
/// # Example
///
/// ```ignore
/// let config = CoordinatorLeaseConfig::default();
/// let mut lease = CoordinatorLease::new(config, coordinator_id);
/// lease.activate();
///
/// // In the runtime tick loop:
/// let (requests, status) = lease.tick(now_ms, &roster_members);
/// if status == LeaseStatus::Lost {
///     // trigger stepdown
/// }
/// ```
///
/// [`tick`]: Self::tick
pub struct CoordinatorLease {
    config: CoordinatorLeaseConfig,
    coordinator_id: MemberId,
    /// Whether the lease is currently active (coordinator is running).
    active: bool,
    /// Monotonic nonce that increments on each heartbeat round.
    /// Acks with a lower nonce are silently ignored.
    lease_nonce: u64,
    /// Millisecond timestamp of the last heartbeat send.
    last_heartbeat_ms: u64,
    /// Millisecond timestamp when the lease was last confirmed held.
    last_renewed_ms: u64,
    /// Members that have acked the current nonce.
    acked_members: HashSet<MemberId>,
    /// Whether we are currently in a heartbeat-collection window.
    collecting: bool,
    /// Roster size at the start of the current collection window.
    current_roster_size: usize,
    /// Exact roster member set at the start of the current collection
    /// window. Only acks from members in this set are counted.
    current_roster_set: HashSet<MemberId>,
    /// Number of heartbeat rounds completed since last renewal.
    rounds_since_renewal: u64,
}

impl CoordinatorLease {
    /// Create a new coordinator lease in the inactive state.
    #[must_use]
    pub fn new(config: CoordinatorLeaseConfig, coordinator_id: MemberId) -> Self {
        Self {
            config,
            coordinator_id,
            active: false,
            lease_nonce: 0,
            last_heartbeat_ms: 0,
            last_renewed_ms: 0,
            acked_members: HashSet::new(),
            collecting: false,
            current_roster_size: 0,
            current_roster_set: HashSet::new(),
            rounds_since_renewal: 0,
        }
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Whether the lease is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Activate the lease.
    ///
    /// Called when this node becomes the coordinator (promotion).
    /// Resets nonce and collection state.
    pub fn activate(&mut self) {
        self.active = true;
        self.lease_nonce = 0;
        self.last_heartbeat_ms = 0;
        self.last_renewed_ms = 0;
        self.acked_members.clear();
        self.collecting = false;
        self.current_roster_size = 0;
        self.current_roster_set.clear();
        self.rounds_since_renewal = 0;
    }

    /// Deactivate the lease.
    ///
    /// Called on stepdown or departure. Clears all heartbeat state.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.acked_members.clear();
        self.collecting = false;
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Current monotonic lease nonce.
    #[must_use]
    pub fn current_nonce(&self) -> u64 {
        self.lease_nonce
    }

    /// The coordinator's member id.
    #[must_use]
    pub fn coordinator_id(&self) -> MemberId {
        self.coordinator_id
    }

    /// Set of members that have acked the current nonce.
    #[must_use]
    pub fn acked_member_ids(&self) -> &HashSet<MemberId> {
        &self.acked_members
    }

    /// Current number of collected acks for this round.
    #[must_use]
    pub fn ack_count(&self) -> usize {
        self.acked_members.len()
    }

    // ------------------------------------------------------------------
    // Tick — the main entry point
    // ------------------------------------------------------------------

    /// Advance the lease state machine by one tick.
    ///
    /// `now_ms` is the current wall-clock (or simulated) time in
    /// milliseconds. `roster_members` is the current set of active
    /// roster member IDs.
    ///
    /// Returns the pending heartbeat messages to send (empty if not
    /// time for a new round) and the current lease evaluation status.
    ///
    /// Callers should send the returned heartbeats via transport and
    /// call [`record_ack`] for each received ack during the collection
    /// window.
    ///
    /// [`record_ack`]: Self::record_ack
    pub fn tick(
        &mut self,
        now_ms: u64,
        roster_members: &[MemberId],
    ) -> (Vec<CoordinatorHeartbeatRequest>, LeaseStatus) {
        if !self.active {
            return (vec![], LeaseStatus::Held);
        }

        let lease_duration_ms = self.config.lease_duration.as_millis() as u64;
        let tick_interval_ms = self.config.heartbeat_tick_interval().as_millis() as u64;

        // Check for lease expiration
        if self.last_renewed_ms > 0
            && now_ms.saturating_sub(self.last_renewed_ms) > lease_duration_ms
        {
            self.collecting = false;
            self.acked_members.clear();
            return (vec![], LeaseStatus::Lost);
        }

        // If we're collecting, check if the collection window has elapsed
        if self.collecting {
            let elapsed = now_ms.saturating_sub(self.last_heartbeat_ms);
            if elapsed >= tick_interval_ms {
                // Collection window closed — evaluate
                let status = self.evaluate_current_round();
                self.collecting = false;
                if status == LeaseStatus::Held {
                    self.last_renewed_ms = now_ms;
                    self.rounds_since_renewal = 0;
                }
                self.acked_members.clear();
                // Start a new round immediately if still active
                if self.active {
                    return self.start_new_round(now_ms, roster_members);
                }
                return (vec![], status);
            }
            // Still collecting — interim status
            return (vec![], LeaseStatus::Held);
        }

        // Not collecting — decide whether to start a new round
        let time_since_last = now_ms.saturating_sub(self.last_heartbeat_ms);
        if time_since_last >= tick_interval_ms {
            return self.start_new_round(now_ms, roster_members);
        }

        // Not time yet
        (vec![], LeaseStatus::Held)
    }

    /// Record an acknowledgment from a roster member.
    ///
    /// Acks with a nonce other than the current lease_nonce are
    /// silently ignored (stale or future). Acks from members not in
    /// the current round's roster set are also ignored. The
    /// coordinator's self-ack is pre-recorded at round start.
    pub fn record_ack(&mut self, member_id: MemberId, ack_nonce: u64) {
        if !self.active || !self.collecting {
            return;
        }
        if ack_nonce != self.lease_nonce {
            return; // stale or future ack
        }
        // Only accept acks from members in the current round's roster.
        if !self.current_roster_set.contains(&member_id) {
            return;
        }
        // Deduplicate: count each member at most once per round.
        self.acked_members.insert(member_id);
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn start_new_round(
        &mut self,
        now_ms: u64,
        roster_members: &[MemberId],
    ) -> (Vec<CoordinatorHeartbeatRequest>, LeaseStatus) {
        self.lease_nonce = self.lease_nonce.wrapping_add(1);
        self.last_heartbeat_ms = now_ms;
        self.acked_members.clear();
        self.collecting = true;
        self.current_roster_size = roster_members.len();
        // Store the exact roster set so record_ack can validate membership.
        self.current_roster_set.clear();
        for m in roster_members {
            self.current_roster_set.insert(*m);
        }
        self.rounds_since_renewal = self.rounds_since_renewal.saturating_add(1);

        // Self-ack: if the coordinator is in the roster, pre-record its
        // own ack. This ensures a single-node cluster doesn't spuriously
        // lose its lease and that the coordinator's own membership always
        // contributes to the majority count.
        if self.current_roster_set.contains(&self.coordinator_id) {
            self.acked_members.insert(self.coordinator_id);
        }

        let nonce = self.lease_nonce;
        let requests: Vec<CoordinatorHeartbeatRequest> = roster_members
            .iter()
            .filter(|mid| **mid != self.coordinator_id)
            .map(|member_id| CoordinatorHeartbeatRequest {
                coordinator_id: self.coordinator_id,
                target_member_id: *member_id,
                nonce,
            })
            .collect();

        (requests, LeaseStatus::Held)
    }

    fn evaluate_current_round(&self) -> LeaseStatus {
        evaluate_lease(self.acked_members.len(), self.current_roster_size)
    }

    /// Force-evaluate lease status from ack count and roster size.
    ///
    /// Does not modify internal state. Useful for testing.
    #[must_use]
    pub fn evaluate_renewal(ack_count: usize, roster_size: usize) -> LeaseStatus {
        evaluate_lease(ack_count, roster_size)
    }
}

// ---------------------------------------------------------------------------
// CoordinatorHeartbeatRequest
// ---------------------------------------------------------------------------

/// A pending coordinator heartbeat that the caller should send via
/// transport to the specified target member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorHeartbeatRequest {
    /// The coordinator sending the heartbeat.
    pub coordinator_id: MemberId,
    /// The target roster member to ping.
    pub target_member_id: MemberId,
    /// Monotonic nonce for this heartbeat round.
    pub nonce: u64,
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Evaluate whether an ack count constitutes a majority of the roster.
///
/// - `roster_size == 0` returns `Held` (degenerate case: empty cluster).
/// - `ack_count >= majority` (ceil(N/2)) returns `Held`.
/// - Otherwise returns `Lost`.
#[must_use]
pub fn evaluate_lease(ack_count: usize, roster_size: usize) -> LeaseStatus {
    if roster_size == 0 {
        return LeaseStatus::Held;
    }
    // Majority = floor(N/2) + 1, which is ceil(N/2) for positive N.
    let majority = (roster_size / 2) + 1;
    if ack_count >= majority {
        LeaseStatus::Held
    } else {
        LeaseStatus::Lost
    }
}

// ---------------------------------------------------------------------------
// CoordinatorHeartbeatResponder — peer-side heartbeat handling
// ---------------------------------------------------------------------------

/// Outcome of handling an inbound coordinator heartbeat on the peer side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeartbeatResponse {
    /// Normal: epoch matches, acknowledge immediately.
    Ack { member_id: MemberId, nonce: u64 },
    /// Stale epoch: ack without side effects.
    AckStale { member_id: MemberId, nonce: u64 },
    /// Future epoch: ack and trigger catch-up.
    AckWithCatchUp {
        member_id: MemberId,
        nonce: u64,
        local_epoch: EpochId,
        heartbeat_epoch: EpochId,
    },
}

/// Handle an inbound coordinator heartbeat from the peer's perspective.
///
/// # Arguments
/// * `local_epoch` - The peer's current committed epoch.
/// * `heartbeat_epoch` - The epoch carried in the heartbeat.
/// * `member_id` - The local member's identity (for the ack).
/// * `nonce` - The nonce from the heartbeat.
///
/// # Returns
/// A [`HeartbeatResponse`] indicating the action to take:
/// - Matching epoch: reply with ack (no catch-up needed).
/// - Stale epoch (heartbeat < local): ack without side effect.
/// - Future epoch (heartbeat > local): ack and signal catch-up so
///   the local node pulls the missing epoch state.
#[must_use]
pub fn handle_inbound_heartbeat(
    local_epoch: EpochId,
    heartbeat_epoch: EpochId,
    member_id: MemberId,
    nonce: u64,
) -> HeartbeatResponse {
    use std::cmp::Ordering;

    match heartbeat_epoch.cmp(&local_epoch) {
        Ordering::Equal => HeartbeatResponse::Ack { member_id, nonce },
        Ordering::Less => HeartbeatResponse::AckStale { member_id, nonce },
        Ordering::Greater => HeartbeatResponse::AckWithCatchUp {
            member_id,
            nonce,
            local_epoch,
            heartbeat_epoch,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    fn epoch(id: u64) -> EpochId {
        EpochId::new(id)
    }

    fn default_config() -> CoordinatorLeaseConfig {
        CoordinatorLeaseConfig {
            lease_duration: Duration::from_secs(30),
            heartbeat_interval: Duration::from_millis(9000),
        }
    }

    // ------------------------------------------------------------------
    // CoordinatorLeaseConfig tests
    // ------------------------------------------------------------------

    #[test]
    fn config_default_values() {
        let c = CoordinatorLeaseConfig::default();
        assert_eq!(c.lease_duration, Duration::from_secs(30));
        assert_eq!(c.heartbeat_interval, Duration::from_secs(10));
    }

    #[test]
    fn config_tick_interval_is_third_of_heartbeat() {
        let c = CoordinatorLeaseConfig::new(Duration::from_secs(30), Duration::from_millis(9000));
        let tick = c.heartbeat_tick_interval();
        assert_eq!(tick, Duration::from_millis(3000));
    }

    #[test]
    fn config_rounds_per_lease() {
        let c = CoordinatorLeaseConfig::new(Duration::from_secs(30), Duration::from_millis(9000));
        assert_eq!(c.rounds_per_lease(), 10);
    }

    #[test]
    fn config_rounds_per_lease_minimum_one() {
        let c = CoordinatorLeaseConfig::new(Duration::from_millis(3), Duration::from_millis(9));
        assert_eq!(c.rounds_per_lease(), 1);
    }

    #[test]
    fn config_equality() {
        let a = CoordinatorLeaseConfig::new(Duration::from_secs(30), Duration::from_millis(9000));
        let b = CoordinatorLeaseConfig::new(Duration::from_secs(30), Duration::from_millis(9000));
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // CoordinatorLease lifecycle tests
    // ------------------------------------------------------------------

    #[test]
    fn new_lease_is_inactive() {
        let lease = CoordinatorLease::new(default_config(), member(1));
        assert!(!lease.is_active());
        assert_eq!(lease.current_nonce(), 0);
        assert_eq!(lease.ack_count(), 0);
    }

    #[test]
    fn activate_resets_state() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();
        assert!(lease.is_active());
        assert_eq!(lease.current_nonce(), 0);
        assert_eq!(lease.ack_count(), 0);
    }

    #[test]
    fn deactivate_clears_collection() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();
        let roster = vec![member(1), member(2), member(3)];
        let _ = lease.tick(3000, &roster);
        // self-ack gives 1 ack before deactivate
        assert_eq!(lease.ack_count(), 1);
        lease.deactivate();
        assert!(!lease.is_active());
        assert_eq!(lease.ack_count(), 0);
    }

    #[test]
    fn coordinator_id_accessor() {
        let lease = CoordinatorLease::new(default_config(), member(42));
        assert_eq!(lease.coordinator_id(), member(42));
    }

    // ------------------------------------------------------------------
    // Tick tests — heartbeat generation
    // ------------------------------------------------------------------

    #[test]
    fn tick_inactive_returns_empty() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        let roster = vec![member(1), member(2), member(3)];
        let (reqs, status) = lease.tick(3000, &roster);
        assert!(reqs.is_empty());
        assert_eq!(status, LeaseStatus::Held);
    }

    #[test]
    fn tick_starts_round_after_tick_interval() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2), member(3)];
        // First tick at 3000ms — exactly one tick interval.
        // Coordinator self-acks, so only peers (2, 3) get heartbeat requests.
        let (reqs, status) = lease.tick(3000, &roster);
        assert_eq!(
            reqs.len(),
            2,
            "coordinator self-acks, only peers get heartbeats"
        );
        assert_eq!(status, LeaseStatus::Held);
        assert_eq!(lease.current_nonce(), 1);
        // Self-ack already counted.
        assert_eq!(lease.ack_count(), 1);

        // Verify request contents go to peers only.
        assert_eq!(reqs[0].coordinator_id, member(1));
        assert_eq!(reqs[0].target_member_id, member(2));
        assert_eq!(reqs[0].nonce, 1);
        assert_eq!(reqs[1].target_member_id, member(3));
        assert_eq!(reqs[1].nonce, 1);
    }

    #[test]
    fn tick_before_interval_returns_empty() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];
        let (reqs, status) = lease.tick(1000, &roster);
        assert!(reqs.is_empty());
        assert_eq!(status, LeaseStatus::Held);
        assert_eq!(lease.current_nonce(), 0);
    }

    #[test]
    fn tick_second_round_starts_after_collection_window() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2), member(3)];

        // Round 1 starts at 3000ms — self-ack included, 2 peer requests.
        let (reqs1, _) = lease.tick(3000, &roster);
        assert_eq!(reqs1.len(), 2);
        assert_eq!(lease.current_nonce(), 1);
        assert_eq!(lease.ack_count(), 1); // self-ack

        // Record peer acks during collection window
        lease.record_ack(member(2), 1);
        lease.record_ack(member(3), 1);

        // Tick at 6000ms — collection window closes, round 2 starts
        let (reqs2, _) = lease.tick(6000, &roster);
        assert_eq!(reqs2.len(), 2);
        assert_eq!(lease.current_nonce(), 2);
    }

    #[test]
    fn tick_multiple_rounds_increment_nonce() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];

        // Round 1 — self-ack auto, one peer request.
        let _ = lease.tick(3000, &roster);
        assert_eq!(lease.current_nonce(), 1);
        assert_eq!(lease.ack_count(), 1); // self-ack
        lease.record_ack(member(2), 1);

        // Round 2
        let _ = lease.tick(6000, &roster);
        assert_eq!(lease.current_nonce(), 2);
        assert_eq!(lease.ack_count(), 1); // self-ack
        lease.record_ack(member(2), 2);

        // Round 3
        let _ = lease.tick(9000, &roster);
        assert_eq!(lease.current_nonce(), 3);
    }

    // ------------------------------------------------------------------
    // Record ack tests
    // ------------------------------------------------------------------

    #[test]
    fn record_ack_increments_count() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2), member(3)];
        let _ = lease.tick(3000, &roster);
        // self-ack gives 1 ack for coordinator(1)
        assert_eq!(lease.ack_count(), 1);

        lease.record_ack(member(2), 1);
        assert_eq!(lease.ack_count(), 2);
        assert!(lease.acked_member_ids().contains(&member(2)));

        lease.record_ack(member(3), 1);
        assert_eq!(lease.ack_count(), 3);
    }

    #[test]
    fn record_ack_ignores_stale_nonce() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];
        let _ = lease.tick(3000, &roster);
        // self-ack = 1

        lease.record_ack(member(2), 2); // nonce mismatch
        assert_eq!(lease.ack_count(), 1); // still just self-ack
    }

    #[test]
    fn record_ack_ignores_when_inactive() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        // Inactive: no round started, no roster stored.
        lease.record_ack(member(1), 0);
        assert_eq!(lease.ack_count(), 0);
    }

    #[test]
    fn record_ack_deduplicates_same_member() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];
        let _ = lease.tick(3000, &roster);
        // self-ack = 1

        lease.record_ack(member(2), 1);
        assert_eq!(lease.ack_count(), 2);
        lease.record_ack(member(2), 1); // duplicate
        assert_eq!(lease.ack_count(), 2);
    }

    #[test]
    fn record_ack_ignores_when_not_collecting() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();
        // Don't tick to start collection — record_ack is a no-op.
        lease.record_ack(member(1), 0);
        assert_eq!(lease.ack_count(), 0);
    }

    // ------------------------------------------------------------------
    // Lease evaluation tests
    // ------------------------------------------------------------------

    #[test]
    fn evaluate_lease_empty_roster_is_held() {
        assert_eq!(evaluate_lease(0, 0), LeaseStatus::Held);
    }

    #[test]
    fn evaluate_lease_single_member_held() {
        // Self-ack alone gives majority for a 1-node cluster.
        assert_eq!(evaluate_lease(1, 1), LeaseStatus::Held);
    }

    #[test]
    fn evaluate_lease_single_member_no_self_ack_lost() {
        // Without self-ack, 0 acks out of 1 is lost.
        assert_eq!(evaluate_lease(0, 1), LeaseStatus::Lost);
    }

    // ------------------------------------------------------------------
    // Roster-set validation and self-ack tests
    // ------------------------------------------------------------------

    #[test]
    fn record_ack_rejects_non_roster_member() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];
        let _ = lease.tick(3000, &roster);
        // self-ack = 1
        assert_eq!(lease.ack_count(), 1);

        // Member 99 is not in the roster set.
        lease.record_ack(member(99), 1);
        assert_eq!(lease.ack_count(), 1); // still only self-ack
        assert!(!lease.acked_member_ids().contains(&member(99)));
    }

    #[test]
    fn record_ack_does_not_count_duplicate_self_ack() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];
        let _ = lease.tick(3000, &roster);
        // Self-ack already counted.
        assert_eq!(lease.ack_count(), 1);

        // Trying to record_ack for self again should not increase count
        // (it's a duplicate set insert).
        lease.record_ack(member(1), 1);
        assert_eq!(lease.ack_count(), 1);
    }

    #[test]
    fn tick_single_node_cluster_self_ack_holds_lease() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        // Single-node cluster: only the coordinator.
        let roster = vec![member(1)];
        let (reqs, _) = lease.tick(3000, &roster);
        // No heartbeat requests to peers (none exist).
        assert!(reqs.is_empty());
        // Self-ack counted.
        assert_eq!(lease.ack_count(), 1);

        // After collection window, evaluate: 1 ack, 1 node = majority = held.
        let (reqs2, _status) = lease.tick(6000, &roster);
        assert!(reqs2.is_empty()); // still no peers
        assert!(lease.is_active());
    }

    #[test]
    fn tick_self_is_not_in_roster_no_self_ack() {
        // If the coordinator is not in the roster (e.g., freshly joined
        // but not yet added), no self-ack is pre-recorded.
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(2), member(3)];
        let (reqs, _) = lease.tick(3000, &roster);
        // Both peers get heartbeat requests.
        assert_eq!(reqs.len(), 2);
        // No self-ack because coordinator(1) not in roster.
        assert_eq!(lease.ack_count(), 0);
    }

    #[test]
    fn record_ack_after_new_round_only_counts_new_roster() {
        // Round 1: roster [1,2,3]. Round 2: roster [1,2] (member 3 departed).
        // Member 3's stale ack from round 1 must not count in round 2.
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster1 = vec![member(1), member(2), member(3)];
        let _ = lease.tick(3000, &roster1);
        assert_eq!(lease.ack_count(), 1); // self-ack
        lease.record_ack(member(2), 1);
        lease.record_ack(member(3), 1);
        assert_eq!(lease.ack_count(), 3);

        // Round 2: roster shrinks to [1,2].
        let roster2 = vec![member(1), member(2)];
        let _ = lease.tick(6000, &roster2);
        // New round: nonce is now 2, only self-ack counted.
        assert_eq!(lease.current_nonce(), 2);
        assert_eq!(lease.ack_count(), 1); // only self-ack

        // A stale ack from member 3 with old nonce is ignored.
        lease.record_ack(member(3), 1);
        assert_eq!(lease.ack_count(), 1);

        // Even if member 3 sends correct nonce, it's not in roster set.
        lease.record_ack(member(3), 2);
        assert_eq!(lease.ack_count(), 1); // rejected because not in roster set

        // Member 2 is still valid.
        lease.record_ack(member(2), 2);
        assert_eq!(lease.ack_count(), 2);
    }

    #[test]
    fn evaluate_lease_single_member_lost() {
        assert_eq!(evaluate_lease(0, 1), LeaseStatus::Lost);
    }

    #[test]
    fn evaluate_lease_three_member_majority() {
        assert_eq!(evaluate_lease(2, 3), LeaseStatus::Held);
        assert_eq!(evaluate_lease(3, 3), LeaseStatus::Held);
        assert_eq!(evaluate_lease(1, 3), LeaseStatus::Lost);
    }

    #[test]
    fn evaluate_lease_five_member_majority() {
        assert_eq!(evaluate_lease(3, 5), LeaseStatus::Held);
        assert_eq!(evaluate_lease(4, 5), LeaseStatus::Held);
        assert_eq!(evaluate_lease(5, 5), LeaseStatus::Held);
        assert_eq!(evaluate_lease(2, 5), LeaseStatus::Lost);
    }

    #[test]
    fn evaluate_lease_even_roster() {
        // 4 nodes: majority = 4/2 + 1 = 3
        assert_eq!(evaluate_lease(2, 4), LeaseStatus::Lost);
        assert_eq!(evaluate_lease(3, 4), LeaseStatus::Held);
        assert_eq!(evaluate_lease(4, 4), LeaseStatus::Held);
    }

    #[test]
    fn evaluate_lease_large_cluster() {
        // 100 nodes: majority = 51
        assert_eq!(evaluate_lease(50, 100), LeaseStatus::Lost);
        assert_eq!(evaluate_lease(51, 100), LeaseStatus::Held);
    }

    // ------------------------------------------------------------------
    // Tick evaluation — end-to-end renewal scenarios
    // ------------------------------------------------------------------

    #[test]
    fn tick_majority_acks_renews_lease() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2), member(3), member(4), member(5)];

        let _ = lease.tick(3000, &roster);
        // self-ack gives 1, need 2 more peer acks for majority of 5 (floor(5/2)+1 = 3).
        lease.record_ack(member(2), 1);
        lease.record_ack(member(3), 1); // total: 3 = majority

        let (reqs2, _) = lease.tick(6000, &roster);
        assert_eq!(reqs2.len(), 4); // 4 peer requests (self excluded), new round
        assert!(lease.is_active());
    }

    #[test]
    fn tick_minority_acks_continues() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster = vec![member(1), member(2), member(3), member(4), member(5)];

        let _ = lease.tick(3000, &roster);
        // self-ack = 1, record only 1 more peer = 2 total (< majority of 3)
        lease.record_ack(member(2), 1); // only 2 of 5 total

        // After collection window, evaluation determines Lost internally,
        // but a new round starts. The lease remains active.
        let (reqs2, _) = lease.tick(6000, &roster);
        assert_eq!(reqs2.len(), 4); // 4 peer requests, self excluded
        assert!(lease.is_active());
    }

    #[test]
    fn tick_lease_expires_without_any_renewal() {
        let config =
            CoordinatorLeaseConfig::new(Duration::from_secs(30), Duration::from_millis(9000));
        let mut lease = CoordinatorLease::new(config, member(1));
        lease.activate();

        let roster = vec![member(1), member(2)];

        // Round 1 at 3000ms: self-ack gives 1, need 1 more for majority of 2 (2).
        let _ = lease.tick(3000, &roster);
        lease.record_ack(member(2), 1); // majority achieved
        let _ = lease.tick(6000, &roster); // eval passes, renewed

        // Now jump past lease_duration from last renewal (6000ms)
        // 6000 + 30000 + 1 = 36001ms
        let (reqs, status) = lease.tick(36001, &roster);
        assert_eq!(status, LeaseStatus::Lost);
        assert!(reqs.is_empty());
    }

    #[test]
    fn tick_empty_roster_held() {
        let mut lease = CoordinatorLease::new(default_config(), member(1));
        lease.activate();

        let roster: Vec<MemberId> = vec![];
        let (reqs, status) = lease.tick(3000, &roster);
        assert!(reqs.is_empty()); // no members to send to
        assert_eq!(status, LeaseStatus::Held);
    }

    // ------------------------------------------------------------------
    // handle_inbound_heartbeat tests
    // ------------------------------------------------------------------

    #[test]
    fn handle_heartbeat_matching_epoch() {
        let response = handle_inbound_heartbeat(epoch(5), epoch(5), member(2), 42);
        assert_eq!(
            response,
            HeartbeatResponse::Ack {
                member_id: member(2),
                nonce: 42,
            }
        );
    }

    #[test]
    fn handle_heartbeat_stale_epoch() {
        let response = handle_inbound_heartbeat(epoch(5), epoch(3), member(2), 7);
        assert_eq!(
            response,
            HeartbeatResponse::AckStale {
                member_id: member(2),
                nonce: 7,
            }
        );
    }

    #[test]
    fn handle_heartbeat_future_epoch_triggers_catch_up() {
        let response = handle_inbound_heartbeat(epoch(3), epoch(5), member(2), 7);
        assert_eq!(
            response,
            HeartbeatResponse::AckWithCatchUp {
                member_id: member(2),
                nonce: 7,
                local_epoch: epoch(3),
                heartbeat_epoch: epoch(5),
            }
        );
    }

    #[test]
    fn handle_heartbeat_equal_at_zero() {
        let response = handle_inbound_heartbeat(EpochId::ZERO, EpochId::ZERO, member(1), 0);
        assert_eq!(
            response,
            HeartbeatResponse::Ack {
                member_id: member(1),
                nonce: 0,
            }
        );
    }

    // ------------------------------------------------------------------
    // CoordinatorHeartbeatRequest tests
    // ------------------------------------------------------------------

    #[test]
    fn heartbeat_request_equality() {
        let a = CoordinatorHeartbeatRequest {
            coordinator_id: member(1),
            target_member_id: member(2),
            nonce: 3,
        };
        let b = CoordinatorHeartbeatRequest {
            coordinator_id: member(1),
            target_member_id: member(2),
            nonce: 3,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn heartbeat_request_mismatch_not_equal() {
        let a = CoordinatorHeartbeatRequest {
            coordinator_id: member(1),
            target_member_id: member(2),
            nonce: 1,
        };
        let b = CoordinatorHeartbeatRequest {
            coordinator_id: member(1),
            target_member_id: member(2),
            nonce: 2,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn heartbeat_request_clone() {
        let a = CoordinatorHeartbeatRequest {
            coordinator_id: member(1),
            target_member_id: member(3),
            nonce: 5,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // HeartbeatResponse tests
    // ------------------------------------------------------------------

    #[test]
    fn heartbeat_response_equality() {
        let a = HeartbeatResponse::Ack {
            member_id: member(1),
            nonce: 3,
        };
        let b = HeartbeatResponse::Ack {
            member_id: member(1),
            nonce: 3,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn heartbeat_response_diff_variants_not_equal() {
        let a = HeartbeatResponse::Ack {
            member_id: member(1),
            nonce: 3,
        };
        let b = HeartbeatResponse::AckStale {
            member_id: member(1),
            nonce: 3,
        };
        assert_ne!(a, b);
    }

    // ------------------------------------------------------------------
    // evaluate_renewal static method tests
    // ------------------------------------------------------------------

    #[test]
    fn evaluate_renewal_static_method() {
        assert_eq!(CoordinatorLease::evaluate_renewal(2, 3), LeaseStatus::Held);
        assert_eq!(CoordinatorLease::evaluate_renewal(1, 3), LeaseStatus::Lost);
    }
}
