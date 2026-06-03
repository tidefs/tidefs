//! Roster change transport session lifecycle bridge.
//!
//! Bridges membership roster changes (peer addition and removal) to transport
//! session establish/teardown. Provides a unified [`RosterSessionHandle`]
//! that membership subsystems use to register interest and receive
//! session-ready / session-lost notifications before sending protocol
//! messages.
//!
//! ## Architecture
//!
//! 1. Watches [`MembershipEvent`] via the [`MembershipEventSubscriber`]
//!    trait — on `MemberJoined` it calls [`TransportSessionOps::establish`],
//!    on `MemberLeft`/`MemberFailed`/`MemberDrained` it calls
//!    [`TransportSessionOps::teardown`].
//! 2. Maintains a bidirectional [`MemberId`]↔[`SessionId`] mapping that is
//!    updated when the transport layer notifies the handle of a completed
//!    session establishment or teardown via
//!    [`notify_session_ready`](RosterSessionHandle::notify_session_ready) /
//!    [`notify_session_lost`](RosterSessionHandle::notify_session_lost).
//! 3. Provides per-peer [`tokio::sync::Notify`] channels so subsystems
//!    can call [`session_ready`](RosterSessionHandle::session_ready) and
//!    await readiness before sending protocol messages over transport.
//!
//! ## Integration
//!
//! ```ignore
//! use tidefs_membership_live::roster_session_bridge::{
//!     RosterSessionHandle, TransportSessionOps,
//! };
//! use tidefs_membership_live::event_bridge::MembershipEventPublisher;
//!
//! let handle = RosterSessionHandle::new(transport_ops);
//! // Register with the event publisher so handle receives membership events.
//! event_publisher.subscribe(Box::new(handle.clone()));
//!
//! // Subsystem usage:
//! let ready = handle.session_ready(peer_id);
//! tokio::spawn(async move {
//!     ready.await;
//!     // Session is now established; safe to send protocol messages.
//! });
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;
use tidefs_membership_epoch::MemberId;
use tidefs_transport::addr::TransportAddr;

use crate::event_bridge::{MembershipEvent, MembershipEventSubscriber};
use crate::session_binding::SessionId;

// ---------------------------------------------------------------------------
// TransportSessionOps — trait abstracting per-peer transport operations
// ---------------------------------------------------------------------------

/// Per-peer transport session lifecycle operations.
///
/// Implementations initiate transport session establishment and teardown.
/// This trait is the membership-side abstraction; `tidefs-transport` provides
/// the production implementation as part of its session manager.
///
/// Both methods are fire-and-forget: they initiate the transport work
/// but do not wait for completion. The transport layer notifies the
/// [`RosterSessionHandle`] of completion via
/// [`RosterSessionHandle::notify_session_ready`] /
/// [`RosterSessionHandle::notify_session_lost`].
pub trait TransportSessionOps: Send + Sync {
    /// Initiate transport session establishment to the peer at the given
    /// addresses.
    ///
    /// The implementation should spawn async connect work and, on success,
    /// call [`RosterSessionHandle::notify_session_ready`] with the resulting
    /// session identifier.
    fn establish(&self, peer_id: MemberId, addresses: Vec<TransportAddr>);

    /// Initiate transport session teardown for the given peer.
    ///
    /// `graceful` — when `true`, drain in-flight messages before closing
    /// (via the existing #6097 session-drain infrastructure); when `false`,
    /// close immediately. On completion, the implementation should call
    /// [`RosterSessionHandle::notify_session_lost`].
    fn teardown(&self, peer_id: MemberId, graceful: bool);
}

// ---------------------------------------------------------------------------
// RosterSessionHandle — public handle for roster↔transport bridging
// ---------------------------------------------------------------------------

/// Public handle that bridges membership roster changes to transport
/// session lifecycle.
///
/// Watches [`MembershipEvent`]s and delegates to [`TransportSessionOps`].
/// Maintains bidirectional [`MemberId`]↔[`SessionId`] mapping and
/// per-peer notification channels so subsystems can await session
/// readiness before sending protocol messages.
///
/// # Thread safety
///
/// All interior state is behind `Mutex`. The handle is `Clone` (the
/// interior `Arc` makes clones share the same mapping and notifiers).
/// The handle is designed for single-threaded use within
/// `MembershipRuntime::tick()` for event delivery, consistent with
/// the other membership event subscribers.
#[derive(Clone)]
pub struct RosterSessionHandle {
    /// Shared interior state.
    inner: Arc<RosterSessionInner>,
}

/// Interior state shared across clones.
struct RosterSessionInner {
    /// Transport session operations implementation.
    transport: Box<dyn TransportSessionOps>,
    /// PeerId → SessionId mapping.
    peer_to_session: Mutex<BTreeMap<MemberId, SessionId>>,
    /// SessionId → PeerId reverse mapping.
    session_to_peer: Mutex<BTreeMap<SessionId, MemberId>>,
    /// Per-peer notification channels for session-readiness.
    ///
    /// A `Notify` is inserted when a subsystem calls `session_ready`
    /// before the session is established. When `notify_session_ready`
    /// is called, the `Notify` is woken and removed.
    session_notifiers: Mutex<BTreeMap<MemberId, Arc<Notify>>>,
}

impl RosterSessionHandle {
    /// Create a new handle backed by the given [`TransportSessionOps`].
    #[must_use]
    pub fn new(transport: Box<dyn TransportSessionOps>) -> Self {
        Self {
            inner: Arc::new(RosterSessionInner {
                transport,
                peer_to_session: Mutex::new(BTreeMap::new()),
                session_to_peer: Mutex::new(BTreeMap::new()),
                session_notifiers: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    // -- Notification channel API for subsystems --

    /// Return a future that resolves when a transport session is established
    /// for `peer_id`.
    ///
    /// If the peer already has an active session in the mapping, the
    /// returned future resolves immediately (already-ready). Otherwise,
    /// a `Notify` is registered and the caller's `.await` will block
    /// until [`notify_session_ready`](Self::notify_session_ready) is called
    /// for this peer.
    ///
    /// Multiple callers can wait on the same peer; all will be woken
    /// when the session is established.
    pub fn session_ready(&self, peer_id: MemberId) -> SessionReady {
        // Fast path: peer already has a session.
        {
            let p2s = self.inner.peer_to_session.lock().unwrap();
            if p2s.contains_key(&peer_id) {
                return SessionReady::immediate();
            }
        }

        // Register a notifier.
        let notify = {
            let mut notifiers = self.inner.session_notifiers.lock().unwrap();
            notifiers
                .entry(peer_id)
                .or_insert_with(|| Arc::new(Notify::new()))
                .clone()
        };

        SessionReady::pending(notify)
    }

    /// Look up the [`SessionId`] for a peer, if a session is established.
    #[must_use]
    pub fn session_of(&self, peer_id: MemberId) -> Option<SessionId> {
        self.inner
            .peer_to_session
            .lock()
            .unwrap()
            .get(&peer_id)
            .copied()
    }

    /// Look up the peer for a [`SessionId`], if known.
    #[must_use]
    pub fn peer_of(&self, session_id: SessionId) -> Option<MemberId> {
        self.inner
            .session_to_peer
            .lock()
            .unwrap()
            .get(&session_id)
            .copied()
    }

    /// Return the number of active session mappings.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.inner.peer_to_session.lock().unwrap().len()
    }

    /// Return whether any session is registered for the given peer.
    #[must_use]
    pub fn has_session(&self, peer_id: MemberId) -> bool {
        self.inner
            .peer_to_session
            .lock()
            .unwrap()
            .contains_key(&peer_id)
    }

    // -- Notification callbacks for transport layer --

    /// Notify the handle that a transport session has been established
    /// for `peer_id` with the given `session_id`.
    ///
    /// Called by the transport layer (or by the [`TransportSessionOps`]
    /// implementation) after a successful outbound connect or inbound
    /// accept for this peer.
    ///
    /// Updates the bidirectional mapping and wakes all waiters registered
    /// via [`session_ready`](Self::session_ready).
    ///
    /// If a session for this peer was already registered, the old mapping
    /// is replaced (e.g., after a reconnect).
    pub fn notify_session_ready(&self, peer_id: MemberId, session_id: SessionId) {
        // Update bidirectional mapping.
        {
            let mut p2s = self.inner.peer_to_session.lock().unwrap();
            // Remove old session if replacing.
            if let Some(old_sid) = p2s.insert(peer_id, session_id) {
                let mut s2p = self.inner.session_to_peer.lock().unwrap();
                s2p.remove(&old_sid);
            }
        }
        {
            let mut s2p = self.inner.session_to_peer.lock().unwrap();
            s2p.insert(session_id, peer_id);
        }

        // Wake any waiters.
        let notifier = {
            let mut notifiers = self.inner.session_notifiers.lock().unwrap();
            notifiers.remove(&peer_id)
        };
        if let Some(notify) = notifier {
            notify.notify_waiters();
        }
    }

    /// Notify the handle that a transport session for `peer_id` has been
    /// torn down or lost.
    ///
    /// Called by the transport layer after session teardown completes.
    /// Removes the peer from the bidirectional mapping.
    pub fn notify_session_lost(&self, peer_id: MemberId) {
        let old_sid = {
            let mut p2s = self.inner.peer_to_session.lock().unwrap();
            p2s.remove(&peer_id)
        };
        if let Some(sid) = old_sid {
            let mut s2p = self.inner.session_to_peer.lock().unwrap();
            s2p.remove(&sid);
        }
        // Clean up any lingering notifier.
        {
            let mut notifiers = self.inner.session_notifiers.lock().unwrap();
            notifiers.remove(&peer_id);
        }
    }

    // -- Private helpers --

    /// Handle a peer-add event: call establish via the transport ops.
    fn on_peer_added(&self, peer_id: MemberId) {
        // Idempotency: if the peer already has a registered session, skip.
        if self.has_session(peer_id) {
            return;
        }
        // Delegate to transport ops. Addresses are resolved by the
        // implementation internally (or via the shared PeerAddressRegistry).
        self.inner.transport.establish(peer_id, Vec::new());
    }

    /// Handle a peer-removed event: call teardown via the transport ops.
    fn on_peer_removed(&self, peer_id: MemberId, graceful: bool) {
        // If the peer has a registered session, tear it down.
        if !self.has_session(peer_id) {
            // No session to tear down — still notify loss to clean up
            // any pending notifiers.
            self.notify_session_lost(peer_id);
            return;
        }
        self.inner.transport.teardown(peer_id, graceful);
        // Note: the transport layer will call notify_session_lost when
        // teardown completes, which cleans up the mapping.
    }
}

// ---------------------------------------------------------------------------
// MembershipEventSubscriber impl
// ---------------------------------------------------------------------------

impl MembershipEventSubscriber for RosterSessionHandle {
    /// Called for each published membership event.
    ///
    /// - `MemberJoined` → establishes transport session.
    /// - `MemberLeft`   → graceful teardown with drain.
    /// - `MemberFailed` → immediate teardown (close).
    /// - `MemberDrained`→ immediate teardown (close).
    /// - `MemberSuspected`, `MemberDraining` → ignored (no session action).
    fn on_membership_event(&self, event: &MembershipEvent) {
        match event {
            MembershipEvent::MemberJoined { member_id, .. } => {
                self.on_peer_added(*member_id);
            }
            MembershipEvent::MemberLeft { member_id, .. } => {
                self.on_peer_removed(*member_id, true);
            }
            MembershipEvent::MemberFailed { member_id, .. } => {
                self.on_peer_removed(*member_id, false);
            }
            MembershipEvent::MemberDrained { member_id, .. } => {
                self.on_peer_removed(*member_id, false);
            }
            MembershipEvent::MemberSuspected { .. } | MembershipEvent::MemberDraining { .. } => {
                // No session lifecycle action for suspect or draining.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SessionReady — future-like handle for session readiness
// ---------------------------------------------------------------------------

/// A handle that resolves when a transport session is established for a peer.
///
/// Created by [`RosterSessionHandle::session_ready`]. Can be `.await`ed
/// directly or polled via [`is_ready`](SessionReady::is_ready).
///
/// Multiple callers awaiting the same peer all receive independent
/// `SessionReady` handles that share the underlying `Notify`; the first
/// notification wakes all waiters.
#[must_use]
pub struct SessionReady {
    /// `None` when already ready (immediate resolution),
    /// `Some(Notify)` when waiting.
    notify: Option<Arc<Notify>>,
}

impl SessionReady {
    /// Construct a `SessionReady` that resolves immediately (peer already
    /// has a session).
    fn immediate() -> Self {
        Self { notify: None }
    }

    /// Construct a `SessionReady` that waits on the given notifier.
    fn pending(notify: Arc<Notify>) -> Self {
        Self {
            notify: Some(notify),
        }
    }

    /// Returns `true` if the session is already ready (immediate).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.notify.is_none()
    }

    /// Await session readiness asynchronously.
    ///
    /// If the peer already has a session, returns immediately. Otherwise,
    /// waits until [`RosterSessionHandle::notify_session_ready`] is called.
    pub async fn wait(&self) {
        if let Some(ref notify) = self.notify {
            notify.notified().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    // ------------------------------------------------------------------
    // Mock TransportSessionOps
    // ------------------------------------------------------------------

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum MockCall {
        Establish { peer_id: u64, address_count: usize },
        Teardown { peer_id: u64, graceful: bool },
    }

    struct MockTransportOps {
        calls: StdMutex<Vec<MockCall>>,
    }

    impl MockTransportOps {
        fn new() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
            }
        }
        fn take_calls(&self) -> Vec<MockCall> {
            self.calls.lock().unwrap().drain(..).collect()
        }
    }

    impl TransportSessionOps for MockTransportOps {
        fn establish(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
            self.calls.lock().unwrap().push(MockCall::Establish {
                peer_id: peer_id.0,
                address_count: addresses.len(),
            });
        }

        fn teardown(&self, peer_id: MemberId, graceful: bool) {
            self.calls.lock().unwrap().push(MockCall::Teardown {
                peer_id: peer_id.0,
                graceful,
            });
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn mid(v: u64) -> MemberId {
        MemberId::new(v)
    }

    fn sid(v: u64) -> SessionId {
        SessionId::new(v)
    }

    /// A TransportSessionOps that delegates to an Arc<MockTransportOps>.
    struct SharedMockOps {
        inner: Arc<MockTransportOps>,
    }

    impl TransportSessionOps for SharedMockOps {
        fn establish(&self, peer_id: MemberId, addresses: Vec<TransportAddr>) {
            self.inner.establish(peer_id, addresses);
        }
        fn teardown(&self, peer_id: MemberId, graceful: bool) {
            self.inner.teardown(peer_id, graceful);
        }
    }

    fn make_handle_shared() -> (RosterSessionHandle, Arc<MockTransportOps>) {
        let mock = Arc::new(MockTransportOps::new());
        let handle = RosterSessionHandle::new(Box::new(SharedMockOps {
            inner: Arc::clone(&mock),
        }));
        (handle, mock)
    }

    // ------------------------------------------------------------------
    // MemberJoined → establish
    // ------------------------------------------------------------------

    #[test]
    fn member_joined_calls_establish() {
        let (handle, mock) = make_handle_shared();

        let event = MembershipEvent::member_joined(mid(42), 1);
        handle.on_membership_event(&event);

        let calls = mock.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            MockCall::Establish {
                peer_id: 42,
                address_count: 0,
            }
        );
    }

    #[test]
    fn member_joined_twice_is_idempotent() {
        let (handle, mock) = make_handle_shared();

        // First join triggers establish.
        let event = MembershipEvent::member_joined(mid(7), 1);
        handle.on_membership_event(&event);
        assert_eq!(mock.take_calls().len(), 1);

        // Notify that the session is ready.
        handle.notify_session_ready(mid(7), sid(700));

        // Second join should be idempotent — already has a session.
        let event2 = MembershipEvent::member_joined(mid(7), 2);
        handle.on_membership_event(&event2);
        assert!(mock.take_calls().is_empty());
    }

    // ------------------------------------------------------------------
    // MemberLeft → graceful teardown
    // ------------------------------------------------------------------

    #[test]
    fn member_left_calls_graceful_teardown() {
        let (handle, mock) = make_handle_shared();

        // Establish a session first.
        handle.notify_session_ready(mid(10), sid(100));

        let event = MembershipEvent::member_left(mid(10), 1);
        handle.on_membership_event(&event);

        let calls = mock.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            MockCall::Teardown {
                peer_id: 10,
                graceful: true,
            }
        );
    }

    // ------------------------------------------------------------------
    // MemberFailed → immediate teardown
    // ------------------------------------------------------------------

    #[test]
    fn member_failed_calls_immediate_teardown() {
        let (handle, mock) = make_handle_shared();

        handle.notify_session_ready(mid(99), sid(999));

        let event = MembershipEvent::member_failed(mid(99), 1);
        handle.on_membership_event(&event);

        let calls = mock.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            MockCall::Teardown {
                peer_id: 99,
                graceful: false,
            }
        );
    }

    // ------------------------------------------------------------------
    // MemberDrained → immediate teardown
    // ------------------------------------------------------------------

    #[test]
    fn member_drained_calls_immediate_teardown() {
        let (handle, mock) = make_handle_shared();

        handle.notify_session_ready(mid(55), sid(555));

        let event = MembershipEvent::member_drained(mid(55), 3);
        handle.on_membership_event(&event);

        let calls = mock.take_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            MockCall::Teardown {
                peer_id: 55,
                graceful: false,
            }
        );
    }

    // ------------------------------------------------------------------
    // Non-session events are ignored
    // ------------------------------------------------------------------

    #[test]
    fn suspected_and_draining_are_ignored() {
        let (handle, mock) = make_handle_shared();

        handle.notify_session_ready(mid(1), sid(100));

        handle.on_membership_event(&MembershipEvent::member_suspected(mid(1), 1));
        handle.on_membership_event(&MembershipEvent::member_draining(mid(1), 1));

        assert!(mock.take_calls().is_empty());
        // Session mapping should still be intact.
        assert!(handle.has_session(mid(1)));
    }

    // ------------------------------------------------------------------
    // Remove-without-add is a no-op
    // ------------------------------------------------------------------

    #[test]
    fn remove_without_add_is_noop() {
        let (handle, mock) = make_handle_shared();

        // No session registered for peer 5.
        let event = MembershipEvent::member_left(mid(5), 1);
        handle.on_membership_event(&event);

        // Should not call teardown (no session to tear down).
        assert!(mock.take_calls().is_empty());
    }

    // ------------------------------------------------------------------
    // Bidirectional mapping
    // ------------------------------------------------------------------

    #[test]
    fn notify_session_ready_creates_bidirectional_mapping() {
        let (handle, _mock) = make_handle_shared();

        handle.notify_session_ready(mid(10), sid(100));
        handle.notify_session_ready(mid(20), sid(200));

        assert_eq!(handle.session_of(mid(10)), Some(sid(100)));
        assert_eq!(handle.session_of(mid(20)), Some(sid(200)));
        assert_eq!(handle.peer_of(sid(100)), Some(mid(10)));
        assert_eq!(handle.peer_of(sid(200)), Some(mid(20)));
        assert_eq!(handle.session_count(), 2);
    }

    #[test]
    fn notify_session_ready_replaces_old_mapping() {
        let (handle, _mock) = make_handle_shared();

        handle.notify_session_ready(mid(10), sid(100));
        // Reconnect: new session for same peer.
        handle.notify_session_ready(mid(10), sid(999));

        assert_eq!(handle.session_of(mid(10)), Some(sid(999)));
        assert_eq!(handle.peer_of(sid(100)), None); // old sid removed
        assert_eq!(handle.peer_of(sid(999)), Some(mid(10)));
        assert_eq!(handle.session_count(), 1);
    }

    #[test]
    fn notify_session_lost_removes_mapping() {
        let (handle, _mock) = make_handle_shared();

        handle.notify_session_ready(mid(10), sid(100));
        handle.notify_session_ready(mid(20), sid(200));

        handle.notify_session_lost(mid(10));

        assert_eq!(handle.session_of(mid(10)), None);
        assert_eq!(handle.peer_of(sid(100)), None);
        assert_eq!(handle.session_of(mid(20)), Some(sid(200))); // unaffected
        assert_eq!(handle.session_count(), 1);
    }

    #[test]
    fn notify_session_lost_unknown_peer_is_noop() {
        let (handle, _mock) = make_handle_shared();

        // Should not panic.
        handle.notify_session_lost(mid(999));
        assert_eq!(handle.session_count(), 0);
    }

    // ------------------------------------------------------------------
    // has_session
    // ------------------------------------------------------------------

    #[test]
    fn has_session_reflects_mapping_state() {
        let (handle, _mock) = make_handle_shared();

        assert!(!handle.has_session(mid(10)));

        handle.notify_session_ready(mid(10), sid(100));
        assert!(handle.has_session(mid(10)));

        handle.notify_session_lost(mid(10));
        assert!(!handle.has_session(mid(10)));
    }

    // ------------------------------------------------------------------
    // session_ready notification channel (synchronous path)
    // ------------------------------------------------------------------

    #[test]
    fn session_ready_immediate_when_already_established() {
        let (handle, _mock) = make_handle_shared();

        handle.notify_session_ready(mid(10), sid(100));

        let ready = handle.session_ready(mid(10));
        assert!(ready.is_ready());
    }

    #[test]
    fn session_ready_pending_when_not_established() {
        let (handle, _mock) = make_handle_shared();

        let ready = handle.session_ready(mid(10));
        assert!(!ready.is_ready());
    }

    // ------------------------------------------------------------------
    // notification after session_ready wakes waiters
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn notification_wakes_waiters() {
        let (handle, _mock) = make_handle_shared();

        // Call session_ready before the session is established.
        let ready = handle.session_ready(mid(10));
        assert!(!ready.is_ready());

        // Establish the session from another task.
        let h = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            h.notify_session_ready(mid(10), sid(100));
        });

        // This should wake when notified.
        ready.wait().await;
        assert!(handle.has_session(mid(10)));
    }

    #[tokio::test]
    async fn multiple_waiters_woken_by_single_notification() {
        let (handle, _mock) = make_handle_shared();

        let r1 = handle.session_ready(mid(10));
        let r2 = handle.session_ready(mid(10));
        let r3 = handle.session_ready(mid(10));

        let h = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            h.notify_session_ready(mid(10), sid(100));
        });

        tokio::join!(r1.wait(), r2.wait(), r3.wait());
        assert!(handle.has_session(mid(10)));
    }

    // ------------------------------------------------------------------
    // Clone shares state
    // ------------------------------------------------------------------

    #[test]
    fn clone_shares_mapping() {
        let (handle, _mock) = make_handle_shared();
        let clone = handle.clone();

        handle.notify_session_ready(mid(10), sid(100));

        assert!(clone.has_session(mid(10)));
        assert_eq!(clone.session_of(mid(10)), Some(sid(100)));
        assert_eq!(clone.session_count(), 1);
    }

    // ------------------------------------------------------------------
    // session_ready immediate for clone after parent establishes
    // ------------------------------------------------------------------

    #[test]
    fn clone_session_ready_immediate_after_parent_notify() {
        let (handle, _mock) = make_handle_shared();
        let clone = handle.clone();

        handle.notify_session_ready(mid(10), sid(100));

        let ready = clone.session_ready(mid(10));
        assert!(ready.is_ready());
    }

    // ------------------------------------------------------------------
    // Idempotency: join already-connected peer
    // ------------------------------------------------------------------

    #[test]
    fn join_already_connected_peer_is_idempotent() {
        let (handle, mock) = make_handle_shared();

        // First join → establish call.
        handle.on_membership_event(&MembershipEvent::member_joined(mid(3), 1));
        assert_eq!(mock.take_calls().len(), 1);

        // Session established.
        handle.notify_session_ready(mid(3), sid(300));

        // Second join → no establish call.
        handle.on_membership_event(&MembershipEvent::member_joined(mid(3), 2));
        assert!(mock.take_calls().is_empty());
    }

    // ------------------------------------------------------------------
    // MemberLeft after notify_session_lost already processed
    // ------------------------------------------------------------------

    #[test]
    fn member_left_after_session_already_lost_is_noop() {
        let (handle, mock) = make_handle_shared();

        handle.notify_session_ready(mid(10), sid(100));
        handle.notify_session_lost(mid(10));

        // Session is already gone — MemberLeft should not call teardown.
        let event = MembershipEvent::member_left(mid(10), 1);
        handle.on_membership_event(&event);

        assert!(mock.take_calls().is_empty());
    }

    // ------------------------------------------------------------------
    // notify_session_lost cleans up pending notifier
    // ------------------------------------------------------------------

    #[test]
    fn notify_session_lost_cleans_up_pending_notifier() {
        let (handle, _mock) = make_handle_shared();

        // Register interest in session readiness.
        let ready = handle.session_ready(mid(10));
        assert!(!ready.is_ready());

        // Lose the session before it was established.
        handle.notify_session_lost(mid(10));

        // The notifier should have been removed; a subsequent
        // session_ready call should get a fresh pending notifier.
        let ready2 = handle.session_ready(mid(10));
        assert!(!ready2.is_ready());
    }
}
