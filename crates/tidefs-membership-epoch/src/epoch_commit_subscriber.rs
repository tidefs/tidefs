// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Epoch-commit subscriber dispatch registry for transport epoch-gate notification.
//!
//! [`EpochCommitBus`] provides a multi-subscriber dispatch point so transport
//! subsystems (epoch-gate enforcement, admission control) receive structured
//! notification on each roster epoch transition without polling or indirect
//! side-channel signals.
//!
//! # Integration
//!
//! 1. Transport creates an [`EpochCommitBus`] and registers one or more
//!    [`EpochCommitSubscriber`] implementations.
//! 2. The epoch driver (or any commit-path authority) calls
//!    [`EpochCommitBus::dispatch_commit`] when a roster epoch transitions.
//! 3. Subscribers receive a [`EpochCommitNotification`] carrying the epoch
//!    number, BLAKE3 roster hash, member set, and a monotonic commit index
//!    for consumer-side deduplication.
//!
//! Intended transport consumers: #5889 (epoch-gate enforcement), #5892
//! (admission control).

use std::cell::RefCell;

use blake3::Hasher;

use crate::EpochId;

// ── BLAKE3 domain separator ─────────────────────────────────────────

const ROSTER_HASH_DOMAIN: &str = "tidefs-membership-epoch-roster-v1";

// ── CommittedRoster ─────────────────────────────────────────────────

/// A committed membership roster at a specific epoch.
///
/// Carries the deterministic BLAKE3-256 roster hash over the sorted,
/// deduplicated member set so consumers can detect duplicate or
/// replayed commit events.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CommittedRoster {
    /// The epoch at which this roster was committed.
    pub epoch: EpochId,
    /// Sorted, deduplicated member node ids.
    pub member_ids: Vec<u64>,
    /// BLAKE3-256 hash over the domain-separated canonical preimage
    /// (epoch_id || sorted member ids).
    pub roster_hash: [u8; 32],
}

impl CommittedRoster {
    /// Construct a committed roster from an epoch number and member set.
    ///
    /// Member IDs are sorted and deduplicated before hashing to ensure
    /// deterministic inter-node agreement.
    #[must_use]
    pub fn new(epoch: EpochId, member_ids: Vec<u64>) -> Self {
        let mut sorted = member_ids;
        sorted.sort();
        sorted.dedup();

        let mut hasher = Hasher::new_derive_key(ROSTER_HASH_DOMAIN);
        hasher.update(&epoch.0.to_le_bytes());
        for id in &sorted {
            hasher.update(&id.to_le_bytes());
        }
        let roster_hash = hasher.finalize().into();

        Self {
            epoch,
            member_ids: sorted,
            roster_hash,
        }
    }

    /// Verify the embedded roster hash against a fresh canonical
    /// computation. Returns `true` if the hash matches.
    #[must_use]
    pub fn verify(&self) -> bool {
        let recomputed = Self::new(self.epoch, self.member_ids.clone());
        self.roster_hash == recomputed.roster_hash
    }

    /// Number of members in this roster.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_ids.len()
    }

    /// Whether the given node id is a member of this roster.
    #[must_use]
    pub fn contains(&self, node_id: u64) -> bool {
        self.member_ids.binary_search(&node_id).is_ok()
    }
}

// ── EpochCommitNotification ─────────────────────────────────────────

/// Notification payload delivered to subscribers on each epoch commit.
///
/// The notification carries the epoch, BLAKE3 roster hash, member set,
/// and a monotonic commit index. Consumers can use the commit index for
/// idempotent deduplication: if the index hasn't advanced since the
/// last processed notification, the event is a duplicate.
#[derive(Clone, Debug)]
pub struct EpochCommitNotification {
    /// The newly committed epoch.
    pub epoch: EpochId,
    /// BLAKE3-256 roster hash for idempotent consumer deduplication.
    pub roster_hash: [u8; 32],
    /// Sorted member node ids at this epoch.
    pub member_ids: Vec<u64>,
    /// Monotonic commit index, incremented per dispatch call.
    /// Consumers can store the last-seen index to suppress replays.
    pub commit_index: u64,
    /// Optional serialized catalog delta (dataset create/destroy/rename)
    /// carried by the committed epoch proposal.
    /// `None` when this epoch carries no catalog mutation.
    pub catalog_delta_bytes: Option<Vec<u8>>,
}

// ── EpochCommitSubscriber ───────────────────────────────────────────

/// Trait for receiving epoch-commit notifications.
///
/// Implementors register with [`EpochCommitBus`] and receive
/// [`EpochCommitNotification`] on each roster epoch transition.
///
/// Implementations must be non-blocking and fast; do not perform
/// long-running I/O or blocking operations in this callback.
pub trait EpochCommitSubscriber: Send + Sync {
    /// Called by the bus for each committed roster epoch transition.
    ///
    /// The `notification` carries the new epoch, roster hash, member
    /// set, and a monotonic commit index for consumer-side dedup.
    fn on_epoch_committed(&self, notification: &EpochCommitNotification);
}

// ── EpochCommitBus ──────────────────────────────────────────────────

/// Registry of epoch-commit subscribers with multi-subscriber dispatch.
///
/// Uses interior mutability via [`RefCell`] so the bus can be shared
/// across call sites while subscribers are registered during
/// initialization. Designed for single-threaded use within the
/// epoch-commit path; wrap in `Mutex` or `RwLock` for multi-threaded
/// environments.
///
/// # Example
///
/// ```ignore
/// let bus = EpochCommitBus::new();
/// bus.register(Box::new(MySubscriber));
/// bus.dispatch_commit(EpochId::new(1), vec![1, 2, 3]);
/// assert_eq!(bus.subscriber_count(), 1);
/// assert_eq!(bus.current_commit_index(), 1);
/// ```
pub struct EpochCommitBus {
    subscribers: RefCell<Vec<Box<dyn EpochCommitSubscriber>>>,
    commit_index: RefCell<u64>,
}

impl EpochCommitBus {
    /// Create a new, empty bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            subscribers: RefCell::new(Vec::new()),
            commit_index: RefCell::new(0),
        }
    }

    /// Register a subscriber. Returns a [`SubscriberId`] for later
    /// unregistration.
    ///
    /// The subscriber will receive all future commit dispatches.
    pub fn register(&self, subscriber: Box<dyn EpochCommitSubscriber>) -> SubscriberId {
        let mut subs = self.subscribers.borrow_mut();
        let id = SubscriberId(subs.len() as u64);
        subs.push(subscriber);
        id
    }

    /// Unregister a previously registered subscriber.
    ///
    /// Returns `true` if the subscriber was found and removed.
    ///
    /// Note: removal shifts remaining subscribers; previously returned
    /// [`SubscriberId`]s for later elements are invalidated. Register
    /// all subscribers before unregistering any, or re-register after
    /// unregistration.
    pub fn unregister(&self, id: SubscriberId) -> bool {
        let mut subs = self.subscribers.borrow_mut();
        let idx = id.0 as usize;
        if idx < subs.len() {
            subs.remove(idx);
            true
        } else {
            false
        }
    }

    /// Dispatch an epoch commit to all registered subscribers.
    ///
    /// Constructs the [`CommittedRoster`], increments the commit index,
    /// and notifies each subscriber with the resulting
    /// [`EpochCommitNotification`].
    ///
    /// Returns the notification that was dispatched so callers can
    /// store it for dedup or logging.
    pub fn dispatch_commit(&self, epoch: EpochId, member_ids: Vec<u64>) -> EpochCommitNotification {
        let mut idx = self.commit_index.borrow_mut();
        *idx += 1;

        let roster = CommittedRoster::new(epoch, member_ids);
        let notification = EpochCommitNotification {
            epoch,
            roster_hash: roster.roster_hash,
            member_ids: roster.member_ids,
            commit_index: *idx,
            catalog_delta_bytes: None,
        };

        let subs = self.subscribers.borrow();
        for sub in subs.iter() {
            sub.on_epoch_committed(&notification);
        }

        notification
    }

    /// Return the number of registered subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.borrow().len()
    }

    /// Return the current commit index (number of dispatches issued).
    #[must_use]
    pub fn current_commit_index(&self) -> u64 {
        *self.commit_index.borrow()
    }
}

impl Default for EpochCommitBus {
    fn default() -> Self {
        Self::new()
    }
}

// ── SubscriberId ────────────────────────────────────────────────────

/// Opaque identifier for a registered subscriber.
///
/// Returned by [`EpochCommitBus::register`] and consumed by
/// [`EpochCommitBus::unregister`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriberId(u64);

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // ── Test subscriber helpers ──────────────────────────────────

    /// A subscriber that records notifications in a shared Vec.
    struct RecordingSubscriber {
        notifications: Arc<Mutex<Vec<EpochCommitNotification>>>,
    }

    impl RecordingSubscriber {
        fn new_with_handle() -> (Self, Arc<Mutex<Vec<EpochCommitNotification>>>) {
            let handle = Arc::new(Mutex::new(Vec::new()));
            let sub = Self {
                notifications: handle.clone(),
            };
            (sub, handle)
        }

        fn events(
            handle: &Arc<Mutex<Vec<EpochCommitNotification>>>,
        ) -> Vec<EpochCommitNotification> {
            handle.lock().unwrap().clone()
        }
    }

    impl EpochCommitSubscriber for RecordingSubscriber {
        fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
            self.notifications
                .lock()
                .unwrap()
                .push(notification.clone());
        }
    }

    /// A subscriber that records call count and last-seen fields via shared state.
    struct StateTrackingSubscriber {
        call_count: Arc<Mutex<usize>>,
        last_epoch: Arc<Mutex<u64>>,
    }

    struct TrackingHandle {
        call_count: Arc<Mutex<usize>>,
        last_epoch: Arc<Mutex<u64>>,
    }

    impl TrackingHandle {
        fn call_count(&self) -> usize {
            *self.call_count.lock().unwrap()
        }

        fn last_epoch(&self) -> u64 {
            *self.last_epoch.lock().unwrap()
        }
    }

    impl StateTrackingSubscriber {
        fn new_with_handle() -> (Self, TrackingHandle) {
            let call_count = Arc::new(Mutex::new(0usize));
            let last_epoch = Arc::new(Mutex::new(0u64));
            let sub = Self {
                call_count: call_count.clone(),
                last_epoch: last_epoch.clone(),
            };
            let handle = TrackingHandle {
                call_count,
                last_epoch,
            };
            (sub, handle)
        }
    }

    impl EpochCommitSubscriber for StateTrackingSubscriber {
        fn on_epoch_committed(&self, notification: &EpochCommitNotification) {
            *self.call_count.lock().unwrap() += 1;
            *self.last_epoch.lock().unwrap() = notification.epoch.0;
        }
    }

    // ── CommittedRoster tests ────────────────────────────────────

    #[test]
    fn roster_new_sorts_and_deduplicates() {
        let roster = CommittedRoster::new(EpochId::new(0), vec![3, 1, 2, 1]);
        assert_eq!(roster.member_ids, vec![1, 2, 3]);
        assert_eq!(roster.epoch, EpochId::new(0));
    }

    #[test]
    fn roster_hash_is_deterministic() {
        let a = CommittedRoster::new(EpochId::new(1), vec![1, 2, 3]);
        let b = CommittedRoster::new(EpochId::new(1), vec![3, 1, 2]);
        assert_eq!(a.roster_hash, b.roster_hash);
    }

    #[test]
    fn roster_hash_differs_by_epoch() {
        let a = CommittedRoster::new(EpochId::new(1), vec![1, 2]);
        let b = CommittedRoster::new(EpochId::new(2), vec![1, 2]);
        assert_ne!(a.roster_hash, b.roster_hash);
    }

    #[test]
    fn roster_hash_differs_by_members() {
        let a = CommittedRoster::new(EpochId::new(1), vec![1, 2]);
        let b = CommittedRoster::new(EpochId::new(1), vec![1, 2, 3]);
        assert_ne!(a.roster_hash, b.roster_hash);
    }

    #[test]
    fn roster_verify_passes() {
        let roster = CommittedRoster::new(EpochId::new(5), vec![10, 20]);
        assert!(roster.verify());
    }

    #[test]
    fn roster_verify_fails_on_tamper() {
        let mut roster = CommittedRoster::new(EpochId::new(5), vec![10, 20]);
        roster.roster_hash[0] ^= 0xFF;
        assert!(!roster.verify());
    }

    #[test]
    fn roster_member_count() {
        let roster = CommittedRoster::new(EpochId::new(0), vec![1, 2, 3]);
        assert_eq!(roster.member_count(), 3);
    }

    #[test]
    fn roster_contains() {
        let roster = CommittedRoster::new(EpochId::new(0), vec![1, 2, 3]);
        assert!(roster.contains(1));
        assert!(roster.contains(3));
        assert!(!roster.contains(4));
        assert!(!roster.contains(0));
    }

    #[test]
    fn roster_empty_set() {
        let roster = CommittedRoster::new(EpochId::new(0), vec![]);
        assert_eq!(roster.member_count(), 0);
        assert!(roster.verify());
    }

    // ── Empty bus dispatch ───────────────────────────────────────

    #[test]
    fn empty_bus_dispatch_no_panic() {
        let bus = EpochCommitBus::new();
        let notification = bus.dispatch_commit(EpochId::new(1), vec![1, 2]);
        assert_eq!(notification.epoch, EpochId::new(1));
        assert_eq!(notification.commit_index, 1);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn empty_bus_commit_index_increments() {
        let bus = EpochCommitBus::new();
        bus.dispatch_commit(EpochId::new(1), vec![1]);
        assert_eq!(bus.current_commit_index(), 1);
        bus.dispatch_commit(EpochId::new(2), vec![1, 2]);
        assert_eq!(bus.current_commit_index(), 2);
    }

    // ── Single subscriber dispatch ───────────────────────────────

    #[test]
    fn single_subscriber_receives_notification() {
        let bus = EpochCommitBus::new();
        let (sub, handle) = StateTrackingSubscriber::new_with_handle();
        bus.register(Box::new(sub));

        bus.dispatch_commit(EpochId::new(1), vec![1, 2]);
        assert_eq!(handle.call_count(), 1);
    }

    #[test]
    fn single_subscriber_receives_correct_epoch() {
        let bus = EpochCommitBus::new();
        let (sub, handle) = StateTrackingSubscriber::new_with_handle();
        bus.register(Box::new(sub));

        bus.dispatch_commit(EpochId::new(7), vec![1, 2]);
        assert_eq!(handle.last_epoch(), 7);
    }

    // ── Multiple subscriber dispatch ─────────────────────────────

    #[test]
    fn multiple_subscribers_all_receive() {
        let bus = EpochCommitBus::new();
        let (s1, h1) = StateTrackingSubscriber::new_with_handle();
        let (s2, h2) = StateTrackingSubscriber::new_with_handle();
        let (s3, h3) = StateTrackingSubscriber::new_with_handle();

        bus.register(Box::new(s1));
        bus.register(Box::new(s2));
        bus.register(Box::new(s3));

        bus.dispatch_commit(EpochId::new(1), vec![1]);

        assert_eq!(h1.call_count(), 1);
        assert_eq!(h2.call_count(), 1);
        assert_eq!(h3.call_count(), 1);
    }

    #[test]
    fn multiple_subscribers_receive_same_notification() {
        let bus = EpochCommitBus::new();
        let (sub1, handle1) = RecordingSubscriber::new_with_handle();
        let (sub2, handle2) = RecordingSubscriber::new_with_handle();

        bus.register(Box::new(sub1));
        bus.register(Box::new(sub2));

        bus.dispatch_commit(EpochId::new(42), vec![10, 20]);

        let events1 = RecordingSubscriber::events(&handle1);
        let events2 = RecordingSubscriber::events(&handle2);
        assert_eq!(events1.len(), 1);
        assert_eq!(events2.len(), 1);
        assert_eq!(events1[0].epoch, events2[0].epoch);
        assert_eq!(events1[0].roster_hash, events2[0].roster_hash);
    }

    // ── Unregister ───────────────────────────────────────────────

    #[test]
    fn unregister_stops_dispatch() {
        let bus = EpochCommitBus::new();
        let (s1, h1) = StateTrackingSubscriber::new_with_handle();
        let (s2, h2) = StateTrackingSubscriber::new_with_handle();

        let id1 = bus.register(Box::new(s1));
        bus.register(Box::new(s2));

        bus.dispatch_commit(EpochId::new(1), vec![1]);
        assert_eq!(h1.call_count(), 1);
        assert_eq!(h2.call_count(), 1);

        assert!(bus.unregister(id1));

        bus.dispatch_commit(EpochId::new(2), vec![1, 2]);
        assert_eq!(
            h1.call_count(),
            1,
            "unregistered subscriber should not receive"
        );
        assert_eq!(
            h2.call_count(),
            2,
            "remaining subscriber should still receive"
        );
    }

    #[test]
    fn unregister_nonexistent_returns_false() {
        let bus = EpochCommitBus::new();
        assert!(!bus.unregister(SubscriberId(0)));
        assert!(!bus.unregister(SubscriberId(999)));
    }

    #[test]
    fn unregister_then_register_new_subscriber() {
        let bus = EpochCommitBus::new();
        let (s1, h1) = StateTrackingSubscriber::new_with_handle();
        let (s2, h2) = StateTrackingSubscriber::new_with_handle();

        let id1 = bus.register(Box::new(s1));
        bus.dispatch_commit(EpochId::new(1), vec![1]);
        assert_eq!(h1.call_count(), 1);

        bus.unregister(id1);
        bus.register(Box::new(s2));
        bus.dispatch_commit(EpochId::new(2), vec![1, 2]);

        assert_eq!(h1.call_count(), 1, "unregistered subscriber stops");
        assert_eq!(h2.call_count(), 1, "new subscriber receives");
    }

    // ── Subscriber count ─────────────────────────────────────────

    #[test]
    fn subscriber_count_tracks_registered() {
        let bus = EpochCommitBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let (sub, _handle) = StateTrackingSubscriber::new_with_handle();
        let id = bus.register(Box::new(sub));
        assert_eq!(bus.subscriber_count(), 1);

        bus.unregister(id);
        assert_eq!(bus.subscriber_count(), 0);
    }

    // ── Commit index monotonicity ────────────────────────────────

    #[test]
    fn commit_index_starts_at_zero() {
        let bus = EpochCommitBus::new();
        assert_eq!(bus.current_commit_index(), 0);
    }

    #[test]
    fn commit_index_monotonic_across_dispatches() {
        let bus = EpochCommitBus::new();
        bus.dispatch_commit(EpochId::new(1), vec![1]);
        assert_eq!(bus.current_commit_index(), 1);

        bus.dispatch_commit(EpochId::new(2), vec![1, 2]);
        assert_eq!(bus.current_commit_index(), 2);

        bus.dispatch_commit(EpochId::new(3), vec![1, 2, 3]);
        assert_eq!(bus.current_commit_index(), 3);
    }

    #[test]
    fn notification_carries_commit_index() {
        let bus = EpochCommitBus::new();
        let n1 = bus.dispatch_commit(EpochId::new(1), vec![1]);
        assert_eq!(n1.commit_index, 1);

        let n2 = bus.dispatch_commit(EpochId::new(2), vec![1, 2]);
        assert_eq!(n2.commit_index, 2);
    }

    // ── Default impl ─────────────────────────────────────────────

    #[test]
    fn default_bus_has_no_subscribers() {
        let bus = EpochCommitBus::default();
        assert_eq!(bus.subscriber_count(), 0);
        assert_eq!(bus.current_commit_index(), 0);
    }

    // ── Roster hash in notification ──────────────────────────────

    #[test]
    fn notification_roster_hash_matches_committed_roster() {
        let bus = EpochCommitBus::new();
        let notification = bus.dispatch_commit(EpochId::new(3), vec![5, 6, 7]);
        let roster = CommittedRoster::new(EpochId::new(3), vec![5, 6, 7]);
        assert_eq!(notification.roster_hash, roster.roster_hash);
    }

    #[test]
    fn notification_member_ids_are_sorted() {
        let bus = EpochCommitBus::new();
        let notification = bus.dispatch_commit(EpochId::new(1), vec![3, 1, 2, 1]);
        assert_eq!(notification.member_ids, vec![1, 2, 3]);
    }
}
