use blake3::Hasher;
use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// BLAKE3 domain separator for membership event digests
// ---------------------------------------------------------------------------

const EVENT_DOMAIN: &str = "tidefs-membership-event-v1";

// ---------------------------------------------------------------------------
// MembershipEvent: typed membership state changes
// ---------------------------------------------------------------------------

/// Represents a membership state transition discovered by the SWIM failure
/// detector and published to interested subscribers.
///
/// Each variant carries the `member_id`, an incarnation number (monotonic
/// epoch-derived counter), and a BLAKE3-256 domain-separated event digest
/// for tamper detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipEvent {
    /// A new member has joined the cluster.
    MemberJoined {
        member_id: MemberId,
        incarnation: u64,
        /// BLAKE3-256 digest (domain `tidefs-membership-event-v1`) covering
        /// the variant discriminant + member_id + incarnation.
        event_digest: [u8; 32],
    },
    /// A member's health transitioned to Suspect.
    MemberSuspected {
        member_id: MemberId,
        incarnation: u64,
        event_digest: [u8; 32],
    },
    /// A member's health transitioned to Down (failed).
    MemberFailed {
        member_id: MemberId,
        incarnation: u64,
        event_digest: [u8; 32],
    },
    /// A member gracefully left (draining complete) or was removed.
    MemberLeft {
        member_id: MemberId,
        incarnation: u64,
        event_digest: [u8; 32],
    },
    /// A member has started graceful draining (announce sent, acks
    /// being collected). State transfer has not yet begun.
    MemberDraining {
        member_id: MemberId,
        incarnation: u64,
        event_digest: [u8; 32],
    },
    /// A member has completed graceful draining (state transfer done,
    /// roster removed, transport torn down). This is the final event
    /// for the drain lifecycle.
    MemberDrained {
        member_id: MemberId,
        incarnation: u64,
        event_digest: [u8; 32],
    },
}

impl MembershipEvent {
    /// Variant discriminant used in the BLAKE3 preimage so that events of
    /// different kinds produce different digests even for the same member.
    fn discriminant(&self) -> u8 {
        match self {
            MembershipEvent::MemberJoined { .. } => 0,
            MembershipEvent::MemberSuspected { .. } => 1,
            MembershipEvent::MemberFailed { .. } => 2,
            MembershipEvent::MemberLeft { .. } => 3,
            MembershipEvent::MemberDraining { .. } => 4,
            MembershipEvent::MemberDrained { .. } => 5,
        }
    }

    /// Return the member id for this event.
    pub fn member_id(&self) -> MemberId {
        match self {
            MembershipEvent::MemberJoined { member_id, .. }
            | MembershipEvent::MemberSuspected { member_id, .. }
            | MembershipEvent::MemberFailed { member_id, .. }
            | MembershipEvent::MemberLeft { member_id, .. }
            | MembershipEvent::MemberDraining { member_id, .. }
            | MembershipEvent::MemberDrained { member_id, .. } => *member_id,
        }
    }

    /// Return the incarnation number for this event.
    pub fn incarnation(&self) -> u64 {
        match self {
            MembershipEvent::MemberJoined { incarnation, .. }
            | MembershipEvent::MemberSuspected { incarnation, .. }
            | MembershipEvent::MemberFailed { incarnation, .. }
            | MembershipEvent::MemberLeft { incarnation, .. }
            | MembershipEvent::MemberDraining { incarnation, .. }
            | MembershipEvent::MemberDrained { incarnation, .. } => *incarnation,
        }
    }

    /// Return the BLAKE3 event digest.
    pub fn event_digest(&self) -> &[u8; 32] {
        match self {
            MembershipEvent::MemberJoined { event_digest, .. }
            | MembershipEvent::MemberSuspected { event_digest, .. }
            | MembershipEvent::MemberFailed { event_digest, .. }
            | MembershipEvent::MemberLeft { event_digest, .. }
            | MembershipEvent::MemberDraining { event_digest, .. }
            | MembershipEvent::MemberDrained { event_digest, .. } => event_digest,
        }
    }

    // ------------------------------------------------------------------
    // Factory constructors — compute and embed the BLAKE3 digest
    // ------------------------------------------------------------------

    /// Create a `MemberJoined` event with BLAKE3 domain-separated digest.
    pub fn member_joined(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(0, member_id, incarnation);
        MembershipEvent::MemberJoined {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Create a `MemberSuspected` event with BLAKE3 domain-separated digest.
    pub fn member_suspected(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(1, member_id, incarnation);
        MembershipEvent::MemberSuspected {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Create a `MemberFailed` event with BLAKE3 domain-separated digest.
    pub fn member_failed(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(2, member_id, incarnation);
        MembershipEvent::MemberFailed {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Create a `MemberLeft` event with BLAKE3 domain-separated digest.
    pub fn member_left(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(3, member_id, incarnation);
        MembershipEvent::MemberLeft {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Create a `MemberDraining` event with BLAKE3 domain-separated digest.
    ///
    /// Published when a node begins graceful drain: announce broadcast,
    /// ack collection, and state transfer preparation.
    pub fn member_draining(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(4, member_id, incarnation);
        MembershipEvent::MemberDraining {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Create a `MemberDrained` event with BLAKE3 domain-separated digest.
    ///
    /// Published when drain completes: state transfer done, roster
    /// removed, transport torn down. This is the terminal drain event.
    pub fn member_drained(member_id: MemberId, incarnation: u64) -> Self {
        let digest = Self::compute_digest(5, member_id, incarnation);
        MembershipEvent::MemberDrained {
            member_id,
            incarnation,
            event_digest: digest,
        }
    }

    /// Compute the BLAKE3-256 domain-separated digest for the given
    /// discriminant, member_id, and incarnation.
    fn compute_digest(discriminant: u8, member_id: MemberId, incarnation: u64) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key(EVENT_DOMAIN);
        hasher.update(&[discriminant]);
        hasher.update(&member_id.0.to_le_bytes());
        hasher.update(&incarnation.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the embedded BLAKE3 event digest against the canonical
    /// preimage.  Returns `true` when the digest matches, `false` on
    /// tampering or corruption.
    pub fn verify_event_digest(&self) -> bool {
        let expected =
            Self::compute_digest(self.discriminant(), self.member_id(), self.incarnation());
        self.event_digest() == &expected
    }
}

// ---------------------------------------------------------------------------
// MembershipEventSubscriber trait
// ---------------------------------------------------------------------------

/// Trait for receiving membership state-change notifications.
///
/// Implementors register with [`MembershipEventPublisher`] and receive
/// events published by the SWIM failure-detector loop.
///
/// Integration guidance for transport consumers (e.g., #5671):
/// - On `MemberJoined`: establish a transport session to the new peer.
/// - On `MemberSuspected`: begin graceful degradation (quarantine, mark
///   session suspect, do not yet teardown).
/// - On `MemberFailed`: tear down transport sessions, cancel in-flight
///   transfers, initiate state-transfer backfill.
/// - On `MemberDraining`: the node has announced drain intent; begin
///   graceful degradation (quarantine sessions, prepare for state
///   transfer, do not accept new work for this peer).
/// - On `MemberDrained`: drain is complete; tear down transport
///   sessions, remove peer from local state, finalize epoch transition.
/// - On `MemberLeft`: similar to Failed but the node initiated the
///   departure — drain/transfer may already be complete.
pub trait MembershipEventSubscriber: Send + Sync {
    /// Called by the publisher for each published event.
    ///
    /// Implementations must be non-blocking and fast; do not perform
    /// long-running I/O or blocking operations in this callback.  Spawn
    /// asynchronous work if needed.
    fn on_membership_event(&self, event: &MembershipEvent);
}

// ---------------------------------------------------------------------------
// MembershipEventPublisher
// ---------------------------------------------------------------------------

/// Publishes typed [`MembershipEvent`]s to registered subscribers.
///
/// ## Deduplication
///
/// The publisher tracks the last event kind published for each member and
/// suppresses consecutive duplicates — e.g., re-suspicion of an
/// already-suspected member does not produce a second
/// `MemberSuspected` event.
///
/// ## Thread safety
///
/// The publisher uses interior mutability via `RefCell` and is designed
/// for single-threaded use within the `MembershipRuntime::tick()` loop.
/// For multi-threaded use, wrap in `Mutex` or `RwLock`.
pub struct MembershipEventPublisher {
    subscribers: Vec<Box<dyn MembershipEventSubscriber>>,
    /// Last published event discriminant per member_id, used for
    /// deduplication.
    last_event: BTreeMap<MemberId, u8>,
}

impl MembershipEventPublisher {
    /// Create a new, empty publisher.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            last_event: BTreeMap::new(),
        }
    }

    /// Register a subscriber.  The subscriber will receive all future
    /// published events until unregistered.
    ///
    /// Returns a `SubscriberId` that can be used to unregister.
    pub fn subscribe(&mut self, subscriber: Box<dyn MembershipEventSubscriber>) -> SubscriberId {
        let id = SubscriberId(self.subscribers.len() as u64);
        self.subscribers.push(subscriber);
        id
    }

    /// Unregister a previously subscribed subscriber by its id.
    ///
    /// Returns `true` if the subscriber was found and removed.
    pub fn unsubscribe(&mut self, id: SubscriberId) -> bool {
        let idx = id.0 as usize;
        if idx < self.subscribers.len() {
            self.subscribers.remove(idx);
            true
        } else {
            false
        }
    }

    /// Publish an event to all registered subscribers.
    ///
    /// Deduplication: if `event` is the same kind as the last published
    /// event for `event.member_id()`, the event is suppressed and no
    /// subscribers are notified.  Returns `true` if the event was
    /// delivered, `false` if it was suppressed as a duplicate.
    pub fn publish(&mut self, event: &MembershipEvent) -> bool {
        let member_id = event.member_id();
        let disc = event.discriminant();

        if self.last_event.get(&member_id) == Some(&disc) {
            return false;
        }

        self.last_event.insert(member_id, disc);

        for subscriber in &self.subscribers {
            subscriber.on_membership_event(event);
        }

        true
    }

    /// Clear the deduplication state for a member.  Useful after a member
    /// leaves, so a subsequent rejoin event is not suppressed.
    pub fn clear_dedup(&mut self, member_id: MemberId) {
        self.last_event.remove(&member_id);
    }

    /// Return the number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }
}

impl Default for MembershipEventPublisher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SubscriberId
// ---------------------------------------------------------------------------

/// Opaque identifier for a registered subscriber.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SubscriberId(u64);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Test subscriber that records received events in an Arc<Mutex<Vec>>.
    /// The Arc can be cloned before subscribing so tests can inspect
    /// received events without holding a reference to the boxed subscriber.
    struct TestSubscriber {
        events: Arc<Mutex<Vec<MembershipEvent>>>,
    }

    impl TestSubscriber {
        /// Create a new subscriber and return both the subscriber (for
        /// subscribing) and an Arc handle (for inspecting events).
        fn new_with_handle() -> (Self, Arc<Mutex<Vec<MembershipEvent>>>) {
            let handle = Arc::new(Mutex::new(Vec::new()));
            let sub = Self {
                events: Arc::clone(&handle),
            };
            (sub, handle)
        }

        fn events(handle: &Arc<Mutex<Vec<MembershipEvent>>>) -> Vec<MembershipEvent> {
            handle.lock().unwrap().clone()
        }
    }

    impl MembershipEventSubscriber for TestSubscriber {
        fn on_membership_event(&self, event: &MembershipEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    // ----- Digest determinism and domain separation -----

    #[test]
    fn event_digest_is_deterministic() {
        let a = MembershipEvent::member_joined(MemberId::new(1), 5);
        let b = MembershipEvent::member_joined(MemberId::new(1), 5);
        assert_eq!(a.event_digest(), b.event_digest());
    }

    #[test]
    fn event_digest_differs_by_variant() {
        let joined = MembershipEvent::member_joined(MemberId::new(1), 1);
        let suspected = MembershipEvent::member_suspected(MemberId::new(1), 1);
        assert_ne!(joined.event_digest(), suspected.event_digest());
    }

    #[test]
    fn event_digest_differs_by_member() {
        let a = MembershipEvent::member_joined(MemberId::new(1), 1);
        let b = MembershipEvent::member_joined(MemberId::new(2), 1);
        assert_ne!(a.event_digest(), b.event_digest());
    }

    #[test]
    fn event_digest_differs_by_incarnation() {
        let a = MembershipEvent::member_joined(MemberId::new(1), 1);
        let b = MembershipEvent::member_joined(MemberId::new(1), 2);
        assert_ne!(a.event_digest(), b.event_digest());
    }

    #[test]
    fn verify_event_digest_accepts_valid_event() {
        let event = MembershipEvent::member_joined(MemberId::new(42), 7);
        assert!(event.verify_event_digest());
    }

    #[test]
    fn verify_event_digest_rejects_tampered_member() {
        let mut event = MembershipEvent::member_joined(MemberId::new(42), 7);
        if let MembershipEvent::MemberJoined {
            ref mut member_id, ..
        } = &mut event
        {
            *member_id = MemberId::new(99);
        }
        assert!(!event.verify_event_digest());
    }

    #[test]
    fn verify_event_digest_rejects_tampered_incarnation() {
        let mut event = MembershipEvent::member_failed(MemberId::new(10), 3);
        if let MembershipEvent::MemberFailed {
            ref mut incarnation,
            ..
        } = &mut event
        {
            *incarnation = 99;
        }
        assert!(!event.verify_event_digest());
    }

    #[test]
    fn verify_event_digest_rejects_tampered_digest() {
        let mut event = MembershipEvent::member_suspected(MemberId::new(7), 2);
        let fake_digest = [0xAAu8; 32];
        match &mut event {
            MembershipEvent::MemberSuspected {
                ref mut event_digest,
                ..
            } => *event_digest = fake_digest,
            _ => unreachable!(),
        }
        assert!(!event.verify_event_digest());
    }

    #[test]
    fn all_six_variants_produce_valid_digests() {
        let joined = MembershipEvent::member_joined(MemberId::new(1), 1);
        let suspected = MembershipEvent::member_suspected(MemberId::new(2), 1);
        let failed = MembershipEvent::member_failed(MemberId::new(3), 1);
        let left = MembershipEvent::member_left(MemberId::new(4), 1);
        let draining = MembershipEvent::member_draining(MemberId::new(5), 1);
        let drained = MembershipEvent::member_drained(MemberId::new(6), 1);

        assert!(joined.verify_event_digest());
        assert!(suspected.verify_event_digest());
        assert!(failed.verify_event_digest());
        assert!(left.verify_event_digest());
        assert!(draining.verify_event_digest());
        assert!(drained.verify_event_digest());
    }

    #[test]
    fn all_six_variants_have_distinct_discriminants() {
        let joined = MembershipEvent::member_joined(MemberId::new(1), 1);
        let suspected = MembershipEvent::member_suspected(MemberId::new(1), 1);
        let failed = MembershipEvent::member_failed(MemberId::new(1), 1);
        let left = MembershipEvent::member_left(MemberId::new(1), 1);
        let draining = MembershipEvent::member_draining(MemberId::new(1), 1);
        let drained = MembershipEvent::member_drained(MemberId::new(1), 1);

        let mut discs = vec![
            joined.discriminant(),
            suspected.discriminant(),
            failed.discriminant(),
            left.discriminant(),
            draining.discriminant(),
            drained.discriminant(),
        ];
        discs.sort();
        discs.dedup();
        assert_eq!(
            discs.len(),
            6,
            "all six variants must have distinct discriminants"
        );
    }

    // ----- Subscriber lifecycle -----

    #[test]
    fn subscriber_receives_published_event() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub));

        let event = MembershipEvent::member_joined(MemberId::new(10), 1);
        let delivered = pubr.publish(&event);
        assert!(delivered);

        let events = TestSubscriber::events(&handle);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], event);
    }

    #[test]
    fn unsubscribed_subscriber_stops_receiving() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub1, handle1) = TestSubscriber::new_with_handle();
        let (sub2, handle2) = TestSubscriber::new_with_handle();

        let id1 = pubr.subscribe(Box::new(sub1));
        let _id2 = pubr.subscribe(Box::new(sub2));

        let event1 = MembershipEvent::member_joined(MemberId::new(10), 1);
        pubr.publish(&event1);
        assert_eq!(TestSubscriber::events(&handle1).len(), 1);
        assert_eq!(TestSubscriber::events(&handle2).len(), 1);

        // Unsubscribe first subscriber
        assert!(pubr.unsubscribe(id1));

        let event2 = MembershipEvent::member_suspected(MemberId::new(11), 1);
        pubr.publish(&event2);

        // sub1 stopped receiving, sub2 still gets events
        assert_eq!(TestSubscriber::events(&handle1).len(), 1);
        assert_eq!(TestSubscriber::events(&handle2).len(), 2);
    }

    #[test]
    fn multiple_subscribers_all_receive() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub1, handle1) = TestSubscriber::new_with_handle();
        let (sub2, handle2) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub1));
        pubr.subscribe(Box::new(sub2));

        let event = MembershipEvent::member_failed(MemberId::new(20), 3);
        pubr.publish(&event);

        assert_eq!(TestSubscriber::events(&handle1).len(), 1);
        assert_eq!(TestSubscriber::events(&handle2).len(), 1);
    }

    #[test]
    fn subscriber_count_tracks_registered() {
        let mut pubr = MembershipEventPublisher::new();
        assert_eq!(pubr.subscriber_count(), 0);

        let (sub, _handle) = TestSubscriber::new_with_handle();
        let id = pubr.subscribe(Box::new(sub));
        assert_eq!(pubr.subscriber_count(), 1);

        pubr.unsubscribe(id);
        assert_eq!(pubr.subscriber_count(), 0);
    }

    // ----- Deduplication -----

    #[test]
    fn duplicate_event_is_suppressed() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub));

        let event1 = MembershipEvent::member_suspected(MemberId::new(1), 1);
        assert!(pubr.publish(&event1));
        assert_eq!(TestSubscriber::events(&handle).len(), 1);

        let event2 = MembershipEvent::member_suspected(MemberId::new(1), 2);
        assert!(!pubr.publish(&event2), "re-suspicion must be suppressed");
        assert_eq!(TestSubscriber::events(&handle).len(), 1);
    }

    #[test]
    fn different_event_kind_not_suppressed() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub));

        let e1 = MembershipEvent::member_suspected(MemberId::new(1), 1);
        assert!(pubr.publish(&e1));

        let e2 = MembershipEvent::member_failed(MemberId::new(1), 1);
        assert!(pubr.publish(&e2), "different kind, should deliver");

        assert_eq!(TestSubscriber::events(&handle).len(), 2);
    }

    #[test]
    fn different_member_not_suppressed() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub));

        assert!(pubr.publish(&MembershipEvent::member_suspected(MemberId::new(1), 1)));
        assert!(pubr.publish(&MembershipEvent::member_suspected(MemberId::new(2), 1)));

        assert_eq!(TestSubscriber::events(&handle).len(), 2);
    }

    #[test]
    fn clear_dedup_allows_re_publish() {
        let mut pubr = MembershipEventPublisher::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        pubr.subscribe(Box::new(sub));

        pubr.publish(&MembershipEvent::member_joined(MemberId::new(5), 1));
        assert_eq!(TestSubscriber::events(&handle).len(), 1);

        // Same kind again -> suppressed
        assert!(!pubr.publish(&MembershipEvent::member_joined(MemberId::new(5), 2)));

        pubr.clear_dedup(MemberId::new(5));

        // Now allowed again
        assert!(pubr.publish(&MembershipEvent::member_joined(MemberId::new(5), 3)));
        assert_eq!(TestSubscriber::events(&handle).len(), 2);
    }

    // ----- Default impl -----

    #[test]
    fn default_publisher_has_no_subscribers() {
        let pubr = MembershipEventPublisher::default();
        assert_eq!(pubr.subscriber_count(), 0);
    }
}
