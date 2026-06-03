//! Transport connection state machine with lifecycle transition enforcement
//! and subsystem notification hooks.
//!
//! ## Purpose
//!
//! The transport layer has growing lifecycle machinery spread across multiple
//! modules: connection initialization handshake, active TCP connect, error
//! classification with recovery dispatch, per-connection async receive loop,
//! connection teardown on epoch peer removal, and connection establishment on
//! peer addition. Each module currently manages connection state transitions
//! ad-hoc through boolean flags or local enums.
//!
//! This module provides a centralized state machine that:
//!
//! - Governs the full connection lifecycle with enforced valid transitions.
//! - Prevents invalid transitions (e.g., sending on a closed connection).
//! - Emits structured lifecycle events that recovery, membership bridging,
//!   and the receive loop can consume without re-deriving connection state
//!   from scattered signals.
//!
//! ## State graph
//!
//! ```text
//! Disconnected ──▶ Connecting ──▶ Handshaking ──▶ Active
//!      ▲               │                │              │
//!      │               ▼                ▼              ▼
//!      ◀──────── Disconnected ◀──────────┘          Draining
//!                                                        │
//!                                                        ▼
//!                                                     Closed
//! ```
//!
//! Valid transitions:
//! - `Disconnected → Connecting`
//! - `Connecting → Handshaking | Disconnected`
//! - `Handshaking → Active | Disconnected`
//! - `Active → Draining | Disconnected`
//! - `Draining → Closed`
//! - `Closed` is terminal (no outbound transitions).
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::connection_state::{
//!     ConnectionLifecycle, ConnectionState, LifecycleBus, LifecycleSubscriber,
//! };
//!
//! let mut lifecycle = ConnectionLifecycle::new();
//! lifecycle.transition_to(ConnectionState::Connecting).unwrap();
//! assert!(!lifecycle.can_send());  // not active yet
//!
//! let mut bus = LifecycleBus::new();
//! bus.subscribe(Box::new(my_subscriber));
//! match lifecycle.transition_to(ConnectionState::Active) {
//!     Ok(event) => bus.broadcast(&event),
//!     Err(e) => tracing::warn!("Invalid transition: {}", e),
//! }
//! ```

use std::any::{Any, TypeId};
use std::fmt;

// ---------------------------------------------------------------------------
// ConnectionState
// ---------------------------------------------------------------------------

/// The six canonical states of a transport connection lifecycle.
///
/// States progress forward through the graph; `Closed` is terminal.
/// Each transition increments a monotonic generation counter housed in
/// [`ConnectionLifecycle`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    /// No connection exists; starting state.
    Disconnected,
    /// TCP connect in progress; awaiting completion.
    Connecting,
    /// Connection established; Hello/HelloAck handshake in progress.
    Handshaking,
    /// Fully established; normal message flow permitted.
    Active,
    /// Graceful drain in progress; no new sends, drain pending writes.
    Draining,
    /// Connection closed; terminal state.
    Closed,
}

impl ConnectionState {
    /// Attempt a transition from `self` to `next`.
    ///
    /// Returns `Ok(next)` on a valid transition, `Err(InvalidTransition)`
    /// otherwise.
    pub fn transition(self, next: ConnectionState) -> Result<ConnectionState, InvalidTransition> {
        match (self, next) {
            (ConnectionState::Disconnected, ConnectionState::Connecting) => Ok(next),
            (ConnectionState::Connecting, ConnectionState::Handshaking) => Ok(next),
            (ConnectionState::Connecting, ConnectionState::Disconnected) => Ok(next),
            (ConnectionState::Handshaking, ConnectionState::Active) => Ok(next),
            (ConnectionState::Handshaking, ConnectionState::Disconnected) => Ok(next),
            (ConnectionState::Active, ConnectionState::Draining) => Ok(next),
            (ConnectionState::Active, ConnectionState::Disconnected) => Ok(next),
            (ConnectionState::Draining, ConnectionState::Closed) => Ok(next),
            (from, to) => Err(InvalidTransition { from, to }),
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => write!(f, "Disconnected"),
            Self::Connecting => write!(f, "Connecting"),
            Self::Handshaking => write!(f, "Handshaking"),
            Self::Active => write!(f, "Active"),
            Self::Draining => write!(f, "Draining"),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// InvalidTransition
// ---------------------------------------------------------------------------

/// Error returned when a requested state transition is not legal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition {
    /// The state before the attempted transition.
    pub from: ConnectionState,
    /// The state that was requested but rejected.
    pub to: ConnectionState,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid transition from {} to {}", self.from, self.to)
    }
}

impl std::error::Error for InvalidTransition {}

// ---------------------------------------------------------------------------
// LifecycleEvent
// ---------------------------------------------------------------------------

/// Structured lifecycle events emitted on each valid state transition.
///
/// Each event carries the generation number from [`ConnectionLifecycle`]
/// for ordering guarantees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleEvent {
    /// Transitioned to `Connecting`.
    ConnectStarted { generation: u64 },
    /// Transitioned to `Active` from `Handshaking` (handshake completed).
    HandshakeComplete { generation: u64 },
    /// Transitioned to `Active` (fully established).
    Active { generation: u64 },
    /// Transitioned to `Draining`; drain of pending writes begun.
    DrainStarted { generation: u64 },
    /// Transitioned to `Closed` from `Draining`; drain complete.
    DrainComplete { generation: u64 },
    /// Transitioned to `Closed` or `Disconnected` from a non-drain path
    /// (e.g., connection reset, explicit close).
    Closed { generation: u64 },
}

impl LifecycleEvent {
    /// The monotonic generation number that produced this event.
    pub fn generation(&self) -> u64 {
        match self {
            Self::ConnectStarted { generation } => *generation,
            Self::HandshakeComplete { generation } => *generation,
            Self::Active { generation } => *generation,
            Self::DrainStarted { generation } => *generation,
            Self::DrainComplete { generation } => *generation,
            Self::Closed { generation } => *generation,
        }
    }
}

impl fmt::Display for LifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectStarted { generation } => {
                write!(f, "ConnectStarted(gen={generation})")
            }
            Self::HandshakeComplete { generation } => {
                write!(f, "HandshakeComplete(gen={generation})")
            }
            Self::Active { generation } => write!(f, "Active(gen={generation})"),
            Self::DrainStarted { generation } => {
                write!(f, "DrainStarted(gen={generation})")
            }
            Self::DrainComplete { generation } => {
                write!(f, "DrainComplete(gen={generation})")
            }
            Self::Closed { generation } => write!(f, "Closed(gen={generation})"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionLifecycle
// ---------------------------------------------------------------------------

/// A connection lifecycle container holding the current state and a
/// monotonic generation counter incremented on each transition.
#[derive(Clone, Debug)]
pub struct ConnectionLifecycle {
    state: ConnectionState,
    generation: u64,
}

impl ConnectionLifecycle {
    /// Create a new lifecycle starting at `Disconnected` with generation 0.
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            generation: 0,
        }
    }

    /// The current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// The current generation number.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Attempt a transition to `next`.
    ///
    /// On success: the state is updated, the generation counter is
    /// incremented, and the corresponding [`LifecycleEvent`] is returned.
    ///
    /// On failure: state and generation are unchanged; an
    /// [`InvalidTransition`] error is returned.
    pub fn transition_to(
        &mut self,
        next: ConnectionState,
    ) -> Result<LifecycleEvent, InvalidTransition> {
        let prev = self.state;
        self.state = self.state.transition(next)?;

        self.state = next;
        self.generation += 1;

        let event = self.event_for(prev, next, self.generation);
        Ok(event)
    }

    /// Returns true if the connection is in `Active` state.
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Active
    }

    /// Returns true if outbound sends are permitted.
    ///
    /// Sends are allowed in `Active` and `Draining` (to drain pending
    /// writes).
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Active | ConnectionState::Draining
        )
    }

    /// Returns true if inbound receives are permitted.
    ///
    /// Receives are allowed during handshake and while active/draining.
    pub fn can_receive(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Handshaking | ConnectionState::Active | ConnectionState::Draining
        )
    }

    fn event_for(&self, prev: ConnectionState, state: ConnectionState, gen: u64) -> LifecycleEvent {
        match state {
            ConnectionState::Connecting | ConnectionState::Handshaking => {
                LifecycleEvent::ConnectStarted { generation: gen }
            }
            ConnectionState::Active => LifecycleEvent::Active { generation: gen },
            ConnectionState::Draining => LifecycleEvent::DrainStarted { generation: gen },
            ConnectionState::Closed => {
                if prev == ConnectionState::Draining {
                    LifecycleEvent::DrainComplete { generation: gen }
                } else {
                    LifecycleEvent::Closed { generation: gen }
                }
            }
            ConnectionState::Disconnected => LifecycleEvent::Closed { generation: gen },
        }
    }
}

impl Default for ConnectionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LifecycleSubscriber
// ---------------------------------------------------------------------------

/// A subscriber that receives lifecycle events emitted by
/// [`LifecycleBus`] when [`ConnectionLifecycle`] transitions occur.
pub trait LifecycleSubscriber: Send + Sync + Any {
    /// Called synchronously when a lifecycle event is broadcast.
    fn on_lifecycle_event(&self, event: &LifecycleEvent);
}

// ---------------------------------------------------------------------------
// LifecycleBus
// ---------------------------------------------------------------------------

/// A subscriber registry that fans out lifecycle events to registered
/// subscribers.
///
/// Subscribers are called synchronously in registration order on each
/// [`broadcast`](LifecycleBus::broadcast) call.
pub struct LifecycleBus {
    subscribers: Vec<Box<dyn LifecycleSubscriber>>,
}

impl LifecycleBus {
    /// Create an empty bus with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
        }
    }

    /// Register a subscriber. No duplicate detection is performed.
    pub fn subscribe(&mut self, subscriber: Box<dyn LifecycleSubscriber>) {
        self.subscribers.push(subscriber);
    }

    /// Remove the first subscriber whose concrete type matches the type
    /// parameter `T`. Returns true if a subscriber was removed.
    pub fn unsubscribe_by_type<T: LifecycleSubscriber + 'static>(&mut self) -> bool {
        let target = TypeId::of::<T>();
        if let Some(pos) = self.subscribers.iter().position(|s| {
            let a: &dyn std::any::Any = s.as_ref();
            a.type_id() == target
        }) {
            self.subscribers.remove(pos);
            true
        } else {
            false
        }
    }

    /// Remove the subscriber at the given index. Returns the removed
    /// subscriber if the index is in bounds.
    pub fn unsubscribe_by_index(&mut self, index: usize) -> Option<Box<dyn LifecycleSubscriber>> {
        if index < self.subscribers.len() {
            Some(self.subscribers.remove(index))
        } else {
            None
        }
    }

    /// Broadcast an event to all registered subscribers synchronously.
    pub fn broadcast(&self, event: &LifecycleEvent) {
        for sub in &self.subscribers {
            sub.on_lifecycle_event(event);
        }
    }

    /// Returns the number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }
}

impl Default for LifecycleBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Helper: all 6 states.
    fn all_states() -> [ConnectionState; 6] {
        [
            ConnectionState::Disconnected,
            ConnectionState::Connecting,
            ConnectionState::Handshaking,
            ConnectionState::Active,
            ConnectionState::Draining,
            ConnectionState::Closed,
        ]
    }

    // Valid transitions as (from, to) pairs.
    fn valid_transitions() -> Vec<(ConnectionState, ConnectionState)> {
        vec![
            (ConnectionState::Disconnected, ConnectionState::Connecting),
            (ConnectionState::Connecting, ConnectionState::Handshaking),
            (ConnectionState::Connecting, ConnectionState::Disconnected),
            (ConnectionState::Handshaking, ConnectionState::Active),
            (ConnectionState::Handshaking, ConnectionState::Disconnected),
            (ConnectionState::Active, ConnectionState::Draining),
            (ConnectionState::Active, ConnectionState::Disconnected),
            (ConnectionState::Draining, ConnectionState::Closed),
        ]
    }

    #[test]
    fn all_36_transitions_assert_valid_and_invalid() {
        let states = all_states();
        let valid = valid_transitions();
        for &from in &states {
            for &to in &states {
                let result = from.transition(to);
                let is_valid = valid.contains(&(from, to));
                match result {
                    Ok(_) => assert!(
                        is_valid,
                        "transition {from:?} -> {to:?} succeeded but should be invalid"
                    ),
                    Err(e) => {
                        assert!(
                            !is_valid,
                            "transition {from:?} -> {to:?} failed with {e:?} but should be valid"
                        );
                        assert_eq!(e.from, from);
                        assert_eq!(e.to, to);
                    }
                }
            }
        }
    }

    #[test]
    fn full_happy_path_generation_monotonic() {
        let mut lc = ConnectionLifecycle::new();
        assert_eq!(lc.state(), ConnectionState::Disconnected);
        assert_eq!(lc.generation(), 0);

        // Connecting
        let ev = lc
            .transition_to(ConnectionState::Connecting)
            .expect("to Connecting");
        assert_eq!(lc.generation(), 1);
        assert!(matches!(
            ev,
            LifecycleEvent::ConnectStarted { generation: 1 }
        ));

        // Handshaking
        let ev = lc
            .transition_to(ConnectionState::Handshaking)
            .expect("to Handshaking");
        assert_eq!(lc.generation(), 2);
        assert!(matches!(
            ev,
            LifecycleEvent::ConnectStarted { generation: 2 }
        ));

        // Active
        let ev = lc
            .transition_to(ConnectionState::Active)
            .expect("to Active");
        assert_eq!(lc.generation(), 3);
        assert!(matches!(ev, LifecycleEvent::Active { generation: 3 }));

        // Draining
        let ev = lc
            .transition_to(ConnectionState::Draining)
            .expect("to Draining");
        assert_eq!(lc.generation(), 4);
        assert!(matches!(ev, LifecycleEvent::DrainStarted { generation: 4 }));

        // Closed (from Draining → DrainComplete)
        let ev = lc
            .transition_to(ConnectionState::Closed)
            .expect("to Closed");
        assert_eq!(lc.generation(), 5);
        assert!(matches!(
            ev,
            LifecycleEvent::DrainComplete { generation: 5 }
        ));
    }

    #[test]
    fn closed_is_terminal() {
        let mut lc = ConnectionLifecycle::new();
        lc.transition_to(ConnectionState::Connecting).unwrap();
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        lc.transition_to(ConnectionState::Active).unwrap();
        lc.transition_to(ConnectionState::Draining).unwrap();
        lc.transition_to(ConnectionState::Closed).unwrap();
        assert_eq!(lc.state(), ConnectionState::Closed);

        // Any further transition from Closed must fail.
        for next in all_states() {
            assert!(
                lc.transition_to(next).is_err(),
                "transition from Closed to {next:?} must fail"
            );
        }
    }

    #[test]
    fn can_send_every_state() {
        let mut lc = ConnectionLifecycle::new();
        // Disconnected
        assert!(!lc.can_send());
        // Connecting
        lc.transition_to(ConnectionState::Connecting).unwrap();
        assert!(!lc.can_send());
        // Handshaking
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        assert!(!lc.can_send());
        // Active
        lc.transition_to(ConnectionState::Active).unwrap();
        assert!(lc.can_send());
        // Draining
        lc.transition_to(ConnectionState::Draining).unwrap();
        assert!(lc.can_send());
        // Closed
        lc.transition_to(ConnectionState::Closed).unwrap();
        assert!(!lc.can_send());
    }

    #[test]
    fn can_receive_every_state() {
        let mut lc = ConnectionLifecycle::new();
        // Disconnected
        assert!(!lc.can_receive());
        // Connecting
        lc.transition_to(ConnectionState::Connecting).unwrap();
        assert!(!lc.can_receive());
        // Handshaking
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        assert!(lc.can_receive());
        // Active
        lc.transition_to(ConnectionState::Active).unwrap();
        assert!(lc.can_receive());
        // Draining
        lc.transition_to(ConnectionState::Draining).unwrap();
        assert!(lc.can_receive());
        // Closed
        lc.transition_to(ConnectionState::Closed).unwrap();
        assert!(!lc.can_receive());
    }

    #[test]
    fn active_to_disconnected_emits_closed() {
        let mut lc = ConnectionLifecycle::new();
        lc.transition_to(ConnectionState::Connecting).unwrap();
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        lc.transition_to(ConnectionState::Active).unwrap();
        // Active → Disconnected (e.g., connection reset)
        let ev = lc
            .transition_to(ConnectionState::Disconnected)
            .expect("Active → Disconnected");
        assert_eq!(lc.generation(), 4);
        assert!(matches!(ev, LifecycleEvent::Closed { generation: 4 }));
    }

    #[test]
    fn lifecyle_subscriber_receives_events() {
        struct CountingSub {
            count: AtomicUsize,
        }

        impl LifecycleSubscriber for CountingSub {
            fn on_lifecycle_event(&self, _event: &LifecycleEvent) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let sub = Arc::new(CountingSub {
            count: AtomicUsize::new(0),
        });
        // We cannot move the Arc into the bus directly; use a wrapper that
        // delegates to the inner Arc'd subscriber.
        struct ArcSub {
            inner: Arc<CountingSub>,
        }
        impl LifecycleSubscriber for ArcSub {
            fn on_lifecycle_event(&self, event: &LifecycleEvent) {
                self.inner.on_lifecycle_event(event);
            }
        }

        let mut bus = LifecycleBus::new();
        bus.subscribe(Box::new(ArcSub { inner: sub.clone() }));

        bus.broadcast(&LifecycleEvent::ConnectStarted { generation: 1 });
        bus.broadcast(&LifecycleEvent::Active { generation: 2 });
        bus.broadcast(&LifecycleEvent::Closed { generation: 3 });

        assert_eq!(sub.count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn lifecyle_bus_multiple_subscribers() {
        struct CounterSub {
            count: AtomicUsize,
        }
        impl CounterSub {
            fn new() -> Self {
                Self {
                    count: AtomicUsize::new(0),
                }
            }
        }
        impl LifecycleSubscriber for CounterSub {
            fn on_lifecycle_event(&self, _event: &LifecycleEvent) {
                self.count.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut bus = LifecycleBus::new();
        bus.subscribe(Box::new(CounterSub::new()));
        bus.subscribe(Box::new(CounterSub::new()));
        bus.subscribe(Box::new(CounterSub::new()));

        assert_eq!(bus.subscriber_count(), 3);

        bus.broadcast(&LifecycleEvent::Active { generation: 1 });

        // Verify removal by index.
        let removed = bus.unsubscribe_by_index(0);
        assert!(removed.is_some());
        assert_eq!(bus.subscriber_count(), 2);

        bus.unsubscribe_by_index(0);
        bus.unsubscribe_by_index(0);
        assert_eq!(bus.subscriber_count(), 0);
        assert!(bus.unsubscribe_by_index(0).is_none());
    }

    #[test]
    fn lifecyle_bus_unsubscribe_by_type() {
        struct SubA;
        impl LifecycleSubscriber for SubA {
            fn on_lifecycle_event(&self, _event: &LifecycleEvent) {}
        }

        struct SubB;
        impl LifecycleSubscriber for SubB {
            fn on_lifecycle_event(&self, _event: &LifecycleEvent) {}
        }

        let mut bus = LifecycleBus::new();
        bus.subscribe(Box::new(SubA));
        bus.subscribe(Box::new(SubB));

        assert_eq!(bus.subscriber_count(), 2);
        assert!(bus.unsubscribe_by_type::<SubA>());
        assert_eq!(bus.subscriber_count(), 1);
        assert!(!bus.unsubscribe_by_type::<SubA>()); // already gone

        assert!(bus.unsubscribe_by_type::<SubB>());
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn lifecyle_event_display() {
        let events = [
            LifecycleEvent::ConnectStarted { generation: 1 },
            LifecycleEvent::HandshakeComplete { generation: 2 },
            LifecycleEvent::Active { generation: 3 },
            LifecycleEvent::DrainStarted { generation: 4 },
            LifecycleEvent::DrainComplete { generation: 5 },
            LifecycleEvent::Closed { generation: 6 },
        ];
        let expected = [
            "ConnectStarted(gen=1)",
            "HandshakeComplete(gen=2)",
            "Active(gen=3)",
            "DrainStarted(gen=4)",
            "DrainComplete(gen=5)",
            "Closed(gen=6)",
        ];
        for (ev, exp) in events.iter().zip(expected.iter()) {
            assert_eq!(format!("{ev}"), *exp);
        }
    }

    #[test]
    fn transition_to_returns_error_does_not_mutate() {
        let mut lc = ConnectionLifecycle::new();
        lc.transition_to(ConnectionState::Connecting).unwrap();
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        lc.transition_to(ConnectionState::Active).unwrap();

        let state_before = lc.state();
        let gen_before = lc.generation();

        // Active → Connecting is invalid.
        let result = lc.transition_to(ConnectionState::Connecting);
        assert!(result.is_err());
        assert_eq!(lc.state(), state_before, "state must not change on error");
        assert_eq!(
            lc.generation(),
            gen_before,
            "generation must not change on error"
        );
    }

    #[test]
    fn invalid_transition_display() {
        let err = InvalidTransition {
            from: ConnectionState::Active,
            to: ConnectionState::Connecting,
        };
        assert_eq!(
            format!("{err}"),
            "invalid transition from Active to Connecting"
        );
    }

    #[test]
    fn connecting_to_active_directly_fails() {
        let mut lc = ConnectionLifecycle::new();
        lc.transition_to(ConnectionState::Connecting).unwrap();
        // Connecting → Active is not a valid transition (must go through
        // Handshaking first).
        assert!(lc.transition_to(ConnectionState::Active).is_err());
    }

    #[test]
    fn draining_directly_to_disconnected_fails() {
        let mut lc = ConnectionLifecycle::new();
        lc.transition_to(ConnectionState::Connecting).unwrap();
        lc.transition_to(ConnectionState::Handshaking).unwrap();
        lc.transition_to(ConnectionState::Active).unwrap();
        lc.transition_to(ConnectionState::Draining).unwrap();
        // Draining → Disconnected is not valid; must go through Closed.
        assert!(lc.transition_to(ConnectionState::Disconnected).is_err());
    }
}
