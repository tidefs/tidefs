// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-advance coordinator bridging peer liveness detection to committed
//! epoch views.
//!
//! The [`EpochAdvanceCoordinator`] sits between the peer liveness state
//! machine (#5958) and the epoch-commit subscriber dispatch (#5900). When a
//! liveness state change warrants a membership view update — peer transition
//! to Dead or Alive — the coordinator produces a new committed [`EpochView`]
//! and notifies registered [`EpochCommitSubscriber`]s.
//!
//! ## Input contract
//!
//! - Liveness changes arrive as [`PeerLivenessChange`] values: a member id,
//!   previous status, new status, and timestamp.
//! - The coordinator tracks the current [`EpochView`] (member set + epoch
//!   number) as a projection of
//!   [`tidefs_membership_epoch::EpochStateMachine`], which owns epoch
//!   identity, monotonic advancement, and member-set transition law.
//!
//! ## Output contract
//!
//! - When a new epoch view is committed, every registered
//!   [`EpochCommitSubscriber`] receives the callback.
//! - The committed view is available via [`current_view`].
//!
//! ## Idempotency
//!
//! Repeated liveness changes with the same `previous_status` and
//! `new_status` for a given member are suppressed: the coordinator records
//! the last change per member and does not produce duplicate epoch advances.
//!
//! ## Quorum guard
//!
//! The coordinator will not produce an epoch view whose member set drops
//! below the configured `min_members`. This prevents single-node clusters
//! from losing their only member through a liveness event.
//!
//! ## Integration points
//!
//! - [`crate::heartbeat::PeerLivenessTracker`]: source of liveness changes
//!   (Alive → Suspected → Failed).
//! - [`crate::event_bridge::MembershipEventPublisher`]: subscriber dispatch
//!   that epoch views flow into for transport notification.
//! - Transport epoch-gate enforcement (#5889): downstream consumer of
//!   committed membership-epoch views for stale-epoch rejection.

use std::collections::BTreeMap;
use tidefs_membership_epoch::{
    EpochId, EpochMemberSet, EpochStateMachine as MembershipEpochStateMachine, MemberId,
    NodeIdentity,
};

// ---------------------------------------------------------------------------
// PeerLivenessStatus
// ---------------------------------------------------------------------------

/// Binary liveness status relevant for epoch coordination.
///
/// The heartbeat protocol tracks three states (Alive, Suspected, Failed),
/// but for epoch membership the coordinator collapses Suspected into the
/// current status: a Suspected peer is still a member until confirmed
/// Failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerLivenessStatus {
    /// Peer is alive and a member of the current epoch.
    Alive,
    /// Peer is confirmed dead and should be removed from the member set.
    Dead,
}

// ---------------------------------------------------------------------------
// PeerLivenessChange
// ---------------------------------------------------------------------------

/// A liveness state change for a tracked peer, emitted by the liveness
/// state machine.
///
/// The coordinator consumes these changes and decides whether to advance
/// the epoch view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerLivenessChange {
    /// The member whose liveness changed.
    pub member_id: MemberId,
    /// Status before this change.
    pub previous_status: PeerLivenessStatus,
    /// Status after this change.
    pub new_status: PeerLivenessStatus,
    /// Timestamp of the change (milliseconds since epoch).
    pub timestamp_millis: u64,
}

impl PeerLivenessChange {
    /// Create a new liveness change event.
    pub fn new(
        member_id: MemberId,
        previous: PeerLivenessStatus,
        new: PeerLivenessStatus,
        timestamp_millis: u64,
    ) -> Self {
        Self {
            member_id,
            previous_status: previous,
            new_status: new,
            timestamp_millis,
        }
    }

    /// Whether this change represents a meaningful transition.
    ///
    /// Returns `true` when `previous_status != new_status`.
    pub fn is_transition(&self) -> bool {
        self.previous_status != self.new_status
    }
}

// ---------------------------------------------------------------------------
// EpochView
// ---------------------------------------------------------------------------

/// A committed epoch view: the member set at a specific epoch number.
///
/// Published to subscribers when the coordinator advances the epoch in
/// response to a liveness change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochView {
    /// Monotonic epoch number for this view.
    pub epoch_number: EpochId,
    /// Members in this epoch (sorted, deduplicated).
    pub member_set: Vec<MemberId>,
    /// When this view was created (milliseconds since epoch).
    pub created_at_millis: u64,
}

impl EpochView {
    /// Create a new epoch view.
    ///
    /// The member set is sorted and deduplicated.
    pub fn new(
        epoch_number: EpochId,
        mut member_set: Vec<MemberId>,
        created_at_millis: u64,
    ) -> Self {
        member_set.sort();
        member_set.dedup();
        Self {
            epoch_number,
            member_set,
            created_at_millis,
        }
    }

    /// Number of members in this view.
    pub fn member_count(&self) -> usize {
        self.member_set.len()
    }

    /// Check whether a specific member is in this view.
    pub fn contains(&self, member_id: MemberId) -> bool {
        self.member_set.contains(&member_id)
    }
}

// ---------------------------------------------------------------------------
// EpochCommitSubscriber
// ---------------------------------------------------------------------------

/// Trait for subscribers that receive committed epoch views.
///
/// Implementors register with [`EpochAdvanceCoordinator::subscribe`] and
/// are notified each time the coordinator commits a new [`EpochView`].
///
/// Implementations must be non-blocking and fast; do not perform
/// long-running I/O or blocking operations in this callback.
pub trait EpochCommitSubscriber: Send + Sync {
    /// Called when a new epoch view is committed.
    fn on_epoch_committed(&self, view: &EpochView);
}

// ---------------------------------------------------------------------------
// EpochAdvanceCoordinator
// ---------------------------------------------------------------------------

/// Coordinates epoch advances in response to peer liveness state changes.
///
/// # Lifecycle
///
/// 1. Construct via [`new`] with a minimum member count.
/// 2. Call [`initialize`] with the initial member set.
/// 3. Register subscribers via [`subscribe`].
/// 4. Feed liveness changes via [`on_liveness_change`].
/// 5. Committed epoch views flow to subscribers automatically.
///
/// [`new`]: EpochAdvanceCoordinator::new
/// [`initialize`]: EpochAdvanceCoordinator::initialize
/// [`subscribe`]: EpochAdvanceCoordinator::subscribe
/// [`on_liveness_change`]: EpochAdvanceCoordinator::on_liveness_change
pub struct EpochAdvanceCoordinator {
    /// The current committed epoch view (None before initialization).
    current_view: Option<EpochView>,
    /// Deterministic membership-epoch authority backing the committed view.
    epoch_state: Option<MembershipEpochStateMachine>,
    /// Known peer liveness statuses.
    peer_status: BTreeMap<MemberId, PeerLivenessStatus>,
    /// Minimum number of members required for a valid epoch view.
    min_members: usize,
    /// Subscribers notified on each epoch commit.
    subscribers: Vec<Box<dyn EpochCommitSubscriber>>,
    /// Last liveness change processed per member (idempotency guard).
    last_change: BTreeMap<MemberId, PeerLivenessChange>,
}

impl EpochAdvanceCoordinator {
    /// Create a new coordinator.
    ///
    /// `min_members` is the minimum member set size for a valid epoch
    /// view.  Must be at least 1.  When a liveness change would drop the
    /// member set below this threshold, no view is produced.
    pub fn new(min_members: usize) -> Self {
        Self {
            current_view: None,
            epoch_state: None,
            peer_status: BTreeMap::new(),
            min_members: min_members.max(1),
            subscribers: Vec::new(),
            last_change: BTreeMap::new(),
        }
    }

    // ----- Initialization -----

    /// Initialize the coordinator with a starting member set at epoch 0.
    ///
    /// All members are initially considered Alive.
    pub fn initialize(&mut self, members: Vec<MemberId>, now_ms: u64) {
        let epoch_state = MembershipEpochStateMachine::bootstrap(Self::epoch_member_set(members));
        let view = Self::view_from_epoch_state(&epoch_state, now_ms);
        self.current_view = Some(view);
        self.epoch_state = Some(epoch_state);
        self.peer_status.clear();
        self.last_change.clear();
        for m in &self.current_view.as_ref().unwrap().member_set {
            self.peer_status.insert(*m, PeerLivenessStatus::Alive);
        }
    }

    // ----- Subscribers -----

    /// Register a subscriber for committed epoch views.
    pub fn subscribe(&mut self, subscriber: Box<dyn EpochCommitSubscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    // ----- Liveness processing -----

    /// Process a liveness state change.
    ///
    /// Evaluates whether the change triggers an epoch view update.
    /// Returns the new [`EpochView`] if one was committed, or `None` if
    /// the change was suppressed, the coordinator is not initialized, or the
    /// deterministic authority rejects the resulting view.
    ///
    /// # Idempotency
    ///
    /// A change with the same `previous_status` and `new_status` for a
    /// given member is suppressed and returns `None`.
    pub fn on_liveness_change(&mut self, change: PeerLivenessChange) -> Option<EpochView> {
        // Idempotency guard: same transition for same member → no-op
        if let Some(prev) = self.last_change.get(&change.member_id) {
            if prev.previous_status == change.previous_status
                && prev.new_status == change.new_status
            {
                return None;
            }
        }

        // No-op for non-transitions (Alive → Alive, Dead → Dead)
        if !change.is_transition() {
            self.last_change.insert(change.member_id, change);
            return None;
        }

        self.last_change.insert(change.member_id, change.clone());

        let (epoch_state, new_view) = self.epoch_state_for_liveness_change(&change)?;

        // Update tracked status only after the deterministic authority accepts
        // the transition.
        self.peer_status.insert(change.member_id, change.new_status);

        Some(self.commit_epoch_state(epoch_state, new_view))
    }

    /// Compute the new epoch view by applying a liveness transition to the
    /// deterministic membership-epoch state machine.
    ///
    /// Returns `None` if:
    /// - The resulting member set would drop below `min_members`.
    /// - The supplied current view is not the committed authority projection.
    pub fn propose_epoch_view(
        &self,
        current: &EpochView,
        change: &PeerLivenessChange,
    ) -> Option<EpochView> {
        if Some(current) != self.current_view.as_ref() {
            return None;
        }
        self.epoch_state_for_liveness_change(change)
            .map(|(_, view)| view)
    }

    /// Commit an epoch state projection, notify subscribers, and return the
    /// committed view.
    fn commit_epoch_state(
        &mut self,
        epoch_state: MembershipEpochStateMachine,
        view: EpochView,
    ) -> EpochView {
        let committed = view;
        self.epoch_state = Some(epoch_state);
        self.sync_peer_status_to_view(&committed);

        for sub in &self.subscribers {
            sub.on_epoch_committed(&committed);
        }

        self.current_view = Some(committed.clone());
        committed
    }

    fn epoch_state_for_liveness_change(
        &self,
        change: &PeerLivenessChange,
    ) -> Option<(MembershipEpochStateMachine, EpochView)> {
        if !change.is_transition() {
            return None;
        }

        let transition = match change.new_status {
            PeerLivenessStatus::Alive => AuthorityTransition::Join(change.member_id),
            PeerLivenessStatus::Dead => AuthorityTransition::Leave(change.member_id),
        };
        self.epoch_state_after_transition(transition, change.timestamp_millis)
    }

    fn epoch_state_after_transition(
        &self,
        transition: AuthorityTransition,
        now_ms: u64,
    ) -> Option<(MembershipEpochStateMachine, EpochView)> {
        let mut candidate = self.epoch_state.as_ref()?.clone();
        Self::apply_authority_transition(&mut candidate, transition);
        let view = Self::view_from_epoch_state(&candidate, now_ms);
        if view.member_count() < self.min_members {
            return None;
        }
        Some((candidate, view))
    }

    fn epoch_member_set(members: Vec<MemberId>) -> EpochMemberSet {
        EpochMemberSet::new(members.into_iter().map(|m| NodeIdentity::new(m.0)))
    }

    fn view_from_epoch_state(
        epoch_state: &MembershipEpochStateMachine,
        created_at_millis: u64,
    ) -> EpochView {
        let epoch = epoch_state.current_epoch();
        let members = epoch
            .members
            .iter()
            .map(|member| MemberId::new(member.node_id))
            .collect();
        EpochView::new(EpochId::new(epoch.epoch_id), members, created_at_millis)
    }

    fn apply_authority_transition(
        epoch_state: &mut MembershipEpochStateMachine,
        transition: AuthorityTransition,
    ) {
        match transition {
            AuthorityTransition::Join(member_id) => {
                epoch_state.join(NodeIdentity::new(member_id.0));
            }
            AuthorityTransition::Leave(member_id) => {
                epoch_state.leave(NodeIdentity::new(member_id.0));
            }
            AuthorityTransition::Increment => {
                epoch_state.increment();
            }
        }
    }

    fn normalized_member_set(member_set: &[MemberId]) -> Vec<MemberId> {
        let mut members = member_set.to_vec();
        members.sort();
        members.dedup();
        members
    }

    fn member_set_delta(
        current_members: &[MemberId],
        target_members: &[MemberId],
    ) -> (Vec<MemberId>, Vec<MemberId>) {
        let added = target_members
            .iter()
            .copied()
            .filter(|member| !current_members.contains(member))
            .collect();
        let removed = current_members
            .iter()
            .copied()
            .filter(|member| !target_members.contains(member))
            .collect();
        (added, removed)
    }

    fn sync_peer_status_to_view(&mut self, view: &EpochView) {
        for status in self.peer_status.values_mut() {
            *status = PeerLivenessStatus::Dead;
        }
        for member in &view.member_set {
            self.peer_status.insert(*member, PeerLivenessStatus::Alive);
        }
    }

    // ----- Accessors -----

    /// The current epoch counter.
    pub fn epoch_counter(&self) -> u64 {
        self.epoch_state
            .as_ref()
            .map_or(0, |epoch_state| epoch_state.current_epoch().epoch_id)
    }

    /// The current epoch view, if initialized.
    pub fn current_view(&self) -> Option<&EpochView> {
        self.current_view.as_ref()
    }

    /// Liveness status of a tracked peer.
    pub fn peer_status(&self, member_id: MemberId) -> Option<PeerLivenessStatus> {
        self.peer_status.get(&member_id).copied()
    }

    /// Number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peer_status.len()
    }

    /// The minimum member set size.
    pub fn min_members(&self) -> usize {
        self.min_members
    }

    /// Advance to the given epoch number with the given member set by applying
    /// the smallest deterministic membership-epoch transition that produces
    /// that committed view.
    ///
    /// This is used by catch-up replay when an epoch transition had no
    /// net membership change (e.g., a no-op administrative epoch). It
    /// stores the new view and notifies subscribers only after
    /// [`tidefs_membership_epoch::EpochStateMachine`] has produced the target
    /// epoch and roster.
    ///
    /// Returns `None` if not initialized or the epoch number doesn't
    /// match the next authority epoch. Returns `None` when the requested
    /// member set would drop below `min_members`, change more than one member,
    /// or diverge from the deterministic authority result.
    pub fn force_advance_epoch(
        &mut self,
        epoch_number: u64,
        member_set: &[MemberId],
        now_ms: u64,
    ) -> Option<EpochView> {
        let current_epoch = self.epoch_counter();
        if epoch_number != current_epoch + 1 {
            return None;
        }

        let current_members = self.current_view.as_ref()?.member_set.clone();
        let target_members = Self::normalized_member_set(member_set);
        if target_members.len() < self.min_members {
            return None;
        }

        let (added, removed) = Self::member_set_delta(&current_members, &target_members);
        let transition = match (added.as_slice(), removed.as_slice()) {
            ([], []) => AuthorityTransition::Increment,
            ([member], []) => AuthorityTransition::Join(*member),
            ([], [member]) => AuthorityTransition::Leave(*member),
            _ => return None,
        };

        let (epoch_state, view) = self.epoch_state_after_transition(transition, now_ms)?;
        if view.epoch_number != EpochId::new(epoch_number) || view.member_set != target_members {
            return None;
        }

        Some(self.commit_epoch_state(epoch_state, view))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityTransition {
    Join(MemberId),
    Leave(MemberId),
    Increment,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Test subscriber that records committed views in a shared Vec.
    struct TestSubscriber {
        views: Arc<Mutex<Vec<EpochView>>>,
    }

    impl TestSubscriber {
        fn new_with_handle() -> (Self, Arc<Mutex<Vec<EpochView>>>) {
            let handle = Arc::new(Mutex::new(Vec::new()));
            let sub = Self {
                views: Arc::clone(&handle),
            };
            (sub, handle)
        }

        fn views(handle: &Arc<Mutex<Vec<EpochView>>>) -> Vec<EpochView> {
            handle.lock().unwrap().clone()
        }
    }

    impl EpochCommitSubscriber for TestSubscriber {
        fn on_epoch_committed(&self, view: &EpochView) {
            self.views.lock().unwrap().push(view.clone());
        }
    }

    fn now_ms() -> u64 {
        1_700_000_000_000
    }

    fn new_coordinator_with_members(members: Vec<MemberId>) -> EpochAdvanceCoordinator {
        let mut c = EpochAdvanceCoordinator::new(2);
        c.initialize(members, now_ms());
        c
    }

    fn authority_members(coord: &EpochAdvanceCoordinator) -> Vec<MemberId> {
        coord
            .epoch_state
            .as_ref()
            .unwrap()
            .current_epoch()
            .members
            .iter()
            .map(|member| MemberId::new(member.node_id))
            .collect()
    }

    fn assert_projection_matches_authority(coord: &EpochAdvanceCoordinator) {
        let epoch_state = coord.epoch_state.as_ref().unwrap();
        let view = coord.current_view().unwrap();
        assert_eq!(
            view.epoch_number,
            EpochId::new(epoch_state.current_epoch().epoch_id)
        );
        assert_eq!(view.member_set, authority_members(coord));
    }

    // ----- Dead peer removal -----

    #[test]
    fn dead_peer_is_removed_from_view() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(result.is_some());

        let view = result.unwrap();
        assert_eq!(view.epoch_number, EpochId::new(1));
        assert_eq!(view.member_set, vec![MemberId::new(1), MemberId::new(2)]);
        assert_eq!(view.member_count(), 2);
        assert!(!view.contains(MemberId::new(3)));

        // Subscriber was notified
        let views = TestSubscriber::views(&handle);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0], view);

        // Coordinator state updated
        assert_eq!(coord.epoch_counter(), 1);
        assert_projection_matches_authority(&coord);
        assert_eq!(
            coord.peer_status(MemberId::new(3)),
            Some(PeerLivenessStatus::Dead)
        );
    }

    // ----- Alive peer addition -----

    #[test]
    fn alive_peer_is_added_to_view() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);

        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(result.is_some());

        let view = result.unwrap();
        assert_eq!(view.member_count(), 3);
        assert!(view.contains(MemberId::new(3)));
        assert_eq!(coord.epoch_counter(), 1);
        assert_projection_matches_authority(&coord);
    }

    // ----- No-op transitions -----

    #[test]
    fn alive_to_alive_is_noop() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Alive,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(result.is_none());
        assert_eq!(coord.epoch_counter(), 0);
    }

    #[test]
    fn dead_to_dead_is_noop() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);

        let change = PeerLivenessChange::new(
            MemberId::new(99),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(result.is_none());
    }

    // ----- Quorum guard -----

    #[test]
    fn removing_last_member_above_min_is_rejected() {
        // 2 members, min_members=2: removing one drops below minimum
        let mut coord = EpochAdvanceCoordinator::new(2);
        coord.initialize(vec![MemberId::new(1), MemberId::new(2)], now_ms());

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(
            result.is_none(),
            "should not produce view below min_members"
        );
        assert_eq!(coord.epoch_counter(), 0);
    }

    #[test]
    fn removing_one_of_three_above_min_succeeds() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let result = coord.on_liveness_change(change);
        assert!(result.is_some());
        let view = result.unwrap();
        assert_eq!(view.member_count(), 2);
        assert!(!view.contains(MemberId::new(1)));
    }

    // ----- Idempotency -----

    #[test]
    fn identical_change_is_suppressed() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);

        let change = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        // First occurrence → produces view
        let r1 = coord.on_liveness_change(change.clone());
        assert!(r1.is_some());

        // Second occurrence → suppressed
        let r2 = coord.on_liveness_change(change);
        assert!(r2.is_none());

        assert_eq!(coord.epoch_counter(), 1);
    }

    #[test]
    fn different_change_for_same_member_is_not_suppressed() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);

        // Peer 2 goes Dead
        let dead = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        let r1 = coord.on_liveness_change(dead);
        assert!(r1.is_some());
        assert_eq!(coord.epoch_counter(), 1);

        // Peer 2 comes back Alive
        let alive = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms() + 1000,
        );
        let r2 = coord.on_liveness_change(alive);
        assert!(r2.is_some());
        assert_eq!(coord.epoch_counter(), 2);

        let view = coord.current_view().unwrap();
        assert!(view.contains(MemberId::new(2)));
        assert_eq!(view.member_count(), 3);
    }

    // ----- propose_epoch_view directly -----

    #[test]
    fn propose_removes_dead_peer() {
        let coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);
        let current = coord.current_view().unwrap();

        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let new_view = coord.propose_epoch_view(current, &change).unwrap();
        assert_eq!(new_view.epoch_number, EpochId::new(1));
        assert_eq!(
            new_view.member_set,
            vec![MemberId::new(1), MemberId::new(2)]
        );
    }

    #[test]
    fn propose_adds_alive_peer() {
        let coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let current = coord.current_view().unwrap();

        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms(),
        );

        let new_view = coord.propose_epoch_view(current, &change).unwrap();
        assert_eq!(new_view.member_count(), 3);
        assert!(new_view.contains(MemberId::new(3)));
    }

    #[test]
    fn propose_already_present_alive_uses_authority_empty_delta_join() {
        let coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let current = coord.current_view().unwrap();

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms(),
        );

        let view = coord.propose_epoch_view(current, &change).unwrap();
        assert_eq!(view.epoch_number, EpochId::new(1));
        assert_eq!(view.member_set, current.member_set);
    }

    #[test]
    fn propose_dead_non_member_uses_authority_empty_delta_leave() {
        let coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let current = coord.current_view().unwrap();

        let change = PeerLivenessChange::new(
            MemberId::new(99),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );

        let view = coord.propose_epoch_view(current, &change).unwrap();
        assert_eq!(view.epoch_number, EpochId::new(1));
        assert_eq!(view.member_set, current.member_set);
    }

    #[test]
    fn stale_current_view_cannot_propose_from_local_copy() {
        let coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let mut stale = coord.current_view().unwrap().clone();
        stale.epoch_number = EpochId::new(7);

        let change = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms(),
        );

        assert!(coord.propose_epoch_view(&stale, &change).is_none());
    }

    // ----- Subscriber lifecycle -----

    #[test]
    fn subscriber_receives_committed_view() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coord.on_liveness_change(change);

        let views = TestSubscriber::views(&handle);
        assert_eq!(views.len(), 1);
        assert!(!views[0].contains(MemberId::new(1)));
    }

    #[test]
    fn multiple_subscribers_all_receive() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);
        let (sub1, handle1) = TestSubscriber::new_with_handle();
        let (sub2, handle2) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub1));
        coord.subscribe(Box::new(sub2));

        let change = PeerLivenessChange::new(
            MemberId::new(2),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coord.on_liveness_change(change);

        assert_eq!(TestSubscriber::views(&handle1).len(), 1);
        assert_eq!(TestSubscriber::views(&handle2).len(), 1);
    }

    #[test]
    fn subscriber_not_notified_on_noop() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        let change = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Alive,
            now_ms(),
        );
        coord.on_liveness_change(change);

        assert!(TestSubscriber::views(&handle).is_empty());
    }

    // ----- Initialization and accessors -----

    #[test]
    fn initialization_sets_epoch_zero() {
        let mut coord = EpochAdvanceCoordinator::new(2);
        coord.initialize(vec![MemberId::new(1), MemberId::new(2)], now_ms());

        let view = coord.current_view().unwrap();
        assert_eq!(view.epoch_number, EpochId::new(0));
        assert_eq!(view.member_set, vec![MemberId::new(1), MemberId::new(2)]);
        assert_eq!(coord.epoch_counter(), 0);
        assert_eq!(coord.peer_count(), 2);
        assert_projection_matches_authority(&coord);
    }

    #[test]
    fn uninitialized_coordinator_has_no_view() {
        let coord = EpochAdvanceCoordinator::new(2);
        assert!(coord.current_view().is_none());
        assert_eq!(coord.peer_count(), 0);
    }

    #[test]
    fn initialize_sorts_and_deduplicates() {
        let mut coord = EpochAdvanceCoordinator::new(1);
        coord.initialize(
            vec![
                MemberId::new(3),
                MemberId::new(1),
                MemberId::new(1),
                MemberId::new(2),
            ],
            now_ms(),
        );

        let view = coord.current_view().unwrap();
        assert_eq!(
            view.member_set,
            vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)]
        );
        assert_eq!(view.member_count(), 3);
    }

    #[test]
    fn min_members_clamped_to_one() {
        let coord = EpochAdvanceCoordinator::new(0);
        assert_eq!(coord.min_members(), 1);
    }

    // ----- EpochView methods -----

    #[test]
    fn epoch_view_member_count() {
        let view = EpochView::new(
            EpochId::new(5),
            vec![MemberId::new(1), MemberId::new(2)],
            now_ms(),
        );
        assert_eq!(view.member_count(), 2);
    }

    #[test]
    fn epoch_view_contains() {
        let view = EpochView::new(
            EpochId::new(1),
            vec![MemberId::new(10), MemberId::new(20)],
            now_ms(),
        );
        assert!(view.contains(MemberId::new(10)));
        assert!(view.contains(MemberId::new(20)));
        assert!(!view.contains(MemberId::new(30)));
    }

    // ----- PeerLivenessChange -----

    #[test]
    fn change_is_transition_detects_difference() {
        let dead = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            100,
        );
        assert!(dead.is_transition());

        let alive = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            200,
        );
        assert!(alive.is_transition());

        let same = PeerLivenessChange::new(
            MemberId::new(1),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Alive,
            300,
        );
        assert!(!same.is_transition());
    }

    // ----- force_advance_epoch -----

    #[test]
    fn force_advance_epoch_advances_without_member_change() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        let (sub, handle) = TestSubscriber::new_with_handle();
        coord.subscribe(Box::new(sub));

        assert_eq!(coord.epoch_counter(), 0);

        // Force advance to epoch 1 with same member set
        let result = coord.force_advance_epoch(1, &[MemberId::new(1), MemberId::new(2)], now_ms());
        assert!(result.is_some());
        let view = result.unwrap();
        assert_eq!(view.epoch_number, EpochId::new(1));
        assert_eq!(view.member_set, vec![MemberId::new(1), MemberId::new(2)]);
        assert_eq!(coord.epoch_counter(), 1);
        assert_projection_matches_authority(&coord);

        // Subscriber was notified
        assert_eq!(TestSubscriber::views(&handle).len(), 1);
    }

    #[test]
    fn force_advance_epoch_rejects_wrong_epoch_number() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1)]);

        // Try to advance to epoch 5 (should be 1)
        let result = coord.force_advance_epoch(5, &[MemberId::new(1)], now_ms());
        assert!(result.is_none());
        assert_eq!(coord.epoch_counter(), 0);
    }

    #[test]
    fn force_advance_epoch_rejects_reused_epoch_id() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);
        assert!(coord
            .force_advance_epoch(1, &[MemberId::new(1), MemberId::new(2)], now_ms())
            .is_some());

        let result = coord.force_advance_epoch(1, &[MemberId::new(1), MemberId::new(2)], now_ms());
        assert!(result.is_none());
        assert_eq!(coord.epoch_counter(), 1);
        assert_projection_matches_authority(&coord);
    }

    #[test]
    fn force_advance_epoch_rejects_when_uninitialized() {
        let mut coord = EpochAdvanceCoordinator::new(2);
        let result = coord.force_advance_epoch(1, &[MemberId::new(1)], now_ms());
        assert!(result.is_none());
    }

    #[test]
    fn force_advance_epoch_advances_new_member_set() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);

        // Force advance to epoch 1 with a new member added
        let result = coord.force_advance_epoch(
            1,
            &[MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            now_ms(),
        );
        assert!(result.is_some());
        let view = coord.current_view().unwrap();
        assert_eq!(view.epoch_number, EpochId::new(1));
        assert!(view.contains(MemberId::new(3)));
        assert_eq!(view.member_count(), 3);
        assert_projection_matches_authority(&coord);
    }

    #[test]
    fn force_advance_epoch_rejects_multi_member_divergence() {
        let mut coord = new_coordinator_with_members(vec![MemberId::new(1), MemberId::new(2)]);

        let result = coord.force_advance_epoch(
            1,
            &[MemberId::new(1), MemberId::new(3), MemberId::new(4)],
            now_ms(),
        );

        assert!(result.is_none());
        assert_eq!(coord.epoch_counter(), 0);
        assert_eq!(
            coord.current_view().unwrap().member_set,
            vec![MemberId::new(1), MemberId::new(2)]
        );
        assert_projection_matches_authority(&coord);
    }

    #[test]
    fn coordinator_sequence_matches_membership_epoch_state_machine() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
        ]);
        let mut expected =
            MembershipEpochStateMachine::bootstrap(EpochAdvanceCoordinator::epoch_member_set(
                vec![MemberId::new(1), MemberId::new(2), MemberId::new(3)],
            ));

        let leave = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        let committed = coord.on_liveness_change(leave).unwrap();
        expected.leave(NodeIdentity::new(3));
        let expected_view = EpochAdvanceCoordinator::view_from_epoch_state(&expected, now_ms());
        assert_eq!(committed, expected_view);

        let join = PeerLivenessChange::new(
            MemberId::new(4),
            PeerLivenessStatus::Dead,
            PeerLivenessStatus::Alive,
            now_ms() + 1,
        );
        let committed = coord.on_liveness_change(join).unwrap();
        expected.join(NodeIdentity::new(4));
        let expected_view = EpochAdvanceCoordinator::view_from_epoch_state(&expected, now_ms() + 1);
        assert_eq!(committed, expected_view);
        assert_projection_matches_authority(&coord);
    }

    // ----- Epoch counter advances monotonically -----

    #[test]
    fn epoch_counter_advances_on_each_commit() {
        let mut coord = new_coordinator_with_members(vec![
            MemberId::new(1),
            MemberId::new(2),
            MemberId::new(3),
            MemberId::new(4),
        ]);

        // Remove member 3
        let c1 = PeerLivenessChange::new(
            MemberId::new(3),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms(),
        );
        coord.on_liveness_change(c1);
        assert_eq!(coord.epoch_counter(), 1);
        assert_eq!(coord.current_view().unwrap().epoch_number, EpochId::new(1));
        assert_projection_matches_authority(&coord);

        // Remove member 4
        let c2 = PeerLivenessChange::new(
            MemberId::new(4),
            PeerLivenessStatus::Alive,
            PeerLivenessStatus::Dead,
            now_ms() + 10,
        );
        coord.on_liveness_change(c2);
        assert_eq!(coord.epoch_counter(), 2);
        assert_eq!(coord.current_view().unwrap().epoch_number, EpochId::new(2));
        assert_projection_matches_authority(&coord);
    }
}
