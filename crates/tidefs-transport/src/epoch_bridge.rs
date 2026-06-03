//! Epoch event bridge: dispatches membership epoch transition events
//! to registered transport subsystems, keeping per-peer state across
//! all transport components consistent with the current membership
//! roster after every epoch change.
//!
//! Without this bridge, transport subsystems hold stale peer state
//! after join, drain, or failure transitions -- causing routing to
//! departed nodes, leaked send buffers, and flow-control windows
//! that never close.
//!
//! ## Architecture
//!
//! - [`TransportEpochSubscriber`]: Trait that each transport subsystem
//!   implements to receive typed peer-state deltas and the new roster
//!   on every epoch completion.
//! - [`EpochEventBridge`]: Manages subscriber registration, dispatches
//!   epoch completion events with out-of-order queuing, and maintains
//!   a BLAKE3-256 domain-separated bridge state digest.
//!
//! ## Out-of-order handling
//!
//! If an epoch notification arrives before a prior epoch was fully
//! applied (e.g., epochs N and N+2 arrive while N+1 is pending), the
//! bridge queues it and applies epochs in strict monotonic order.
//! This is critical during rapid epoch churn or when membership
//! transitions overlap with transport subsystem backpressure.
//!
//! ## BLAKE3 domain
//!
//! Domain: `tidefs-transport-epoch-bridge-v1`
//! Covers: last-applied epoch number (u64 LE), roster hash (32 bytes,
//! BLAKE3 of sorted node IDs), and subscriber count (u64 LE).

use blake3::Hasher;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// BLAKE3 domain separator
// ---------------------------------------------------------------------------

const BRIDGE_DOMAIN: &str = "tidefs-transport-epoch-bridge-v1";

// ---------------------------------------------------------------------------
// PeerStateDelta: typed peer state changes
// ---------------------------------------------------------------------------

/// Describes a change to a peer's cluster membership state that
/// transport subsystems must react to when an epoch transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStateDelta {
    /// A new peer has joined the cluster. Subsystems should allocate
    /// per-peer resources (routing entry, send buffer, flow-control
    /// window, delivery tracker).
    Joined { node_id: u64 },
    /// A peer has gracefully drained and departed. Subsystems should
    /// tear down per-peer resources after draining in-flight work.
    Drained { node_id: u64 },
    /// A peer has been detected as failed (SWIM suspicion confirmed).
    /// Subsystems should immediately cancel in-flight transfers,
    /// release resources, and trigger backfill/rebuild if needed.
    Failed { node_id: u64 },
    /// A peer's state changed (e.g., health transitioned healthy↔suspect)
    /// but the peer remains in the roster. Subsystems should re-validate
    /// connections and adjust flow-control windows.
    StateChanged { node_id: u64 },
}

impl PeerStateDelta {
    /// Return the node ID for this delta.
    pub fn node_id(&self) -> u64 {
        match self {
            PeerStateDelta::Joined { node_id }
            | PeerStateDelta::Drained { node_id }
            | PeerStateDelta::Failed { node_id }
            | PeerStateDelta::StateChanged { node_id } => *node_id,
        }
    }
}

// ---------------------------------------------------------------------------
// TransportEpochSubscriber trait
// ---------------------------------------------------------------------------

/// Trait for transport subsystems that need to react to membership
/// epoch transitions.
///
/// Each transport subsystem (send buffer, priority scheduler, delivery
/// confirmation, routing table, connection admission, flow control,
/// etc.) implements this trait and registers with [`EpochEventBridge`]
/// to receive typed peer-state deltas on every epoch completion.
///
/// # Implementation guidance
///
/// - `on_epoch_transition` is called for every epoch change, in order.
/// - `roster` is the complete sorted set of node IDs in the new epoch.
/// - `deltas` lists the per-peer changes from the previous roster to
///   the new one. An empty `deltas` means the roster changed without
///   per-member state changes (e.g., epoch-only transition).
/// - Implementations must be non-blocking and fast; spawn async work
///   if teardown or allocation is needed.
/// - One subscriber's failure must not prevent other subscribers from
///   receiving the notification; implementations should not panic.
pub trait TransportEpochSubscriber: Send + Sync {
    /// Called when an epoch transition completes.
    ///
    /// * `new_epoch` — the epoch number after the transition.
    /// * `roster` — sorted list of all node IDs in the new roster.
    /// * `deltas` — per-peer changes from the previous roster to the
    ///   new one (joined, drained, failed, state-changed).
    fn on_epoch_transition(&self, new_epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]);
}

// ---------------------------------------------------------------------------
// EpochEventBridge
// ---------------------------------------------------------------------------

/// Dispatches epoch completion events to registered transport
/// subsystem subscribers, with out-of-order queuing and
/// bridge state integrity.
///
/// ## Lifecycle
///
/// 1. Transport subsystems register via [`register`](Self::register).
/// 2. The membership layer calls [`on_epoch_completed`](Self::on_epoch_completed)
///    when an epoch transition commits.
/// 3. The bridge dispatches the roster and per-peer deltas to all
///    subscribers in strict epoch order.
///
/// ## Out-of-order delivery
///
/// If epoch N+2 arrives before N+1, N+2 is queued. When N+1 later
/// arrives, both N+1 and N+2 are dispatched in order. Stale epochs
/// (≤ current) are silently ignored.
///
/// ## BLAKE3 state digest
///
/// After each successfully dispatched epoch, the bridge recomputes a
/// BLAKE3-256 domain-separated digest (`tidefs-transport-epoch-bridge-v1`)
/// covering:
///
/// - `last_applied_epoch` (u64, little-endian)
/// - roster hash (32 bytes, BLAKE3 over sorted node IDs)
/// - subscriber count (u64, little-endian)
///
/// This digest provides deterministic validation that the bridge applied
/// a specific epoch to a specific set of subscribers with a specific
/// roster.
pub struct EpochEventBridge {
    /// Registered subscribers.
    subscribers: Vec<Box<dyn TransportEpochSubscriber>>,
    /// Last epoch successfully dispatched to all subscribers.
    last_applied_epoch: u64,
    /// BLAKE3-256 state digest covering the bridge state.
    state_digest: [u8; 32],
    /// Queued future-epoch transitions, sorted by epoch number.
    pending_epochs: VecDeque<PendingEpoch>,
    /// Whether any epoch has been applied yet (distinguishes 0 from
    /// uninitialized).
    initialized: bool,
}

/// A queued epoch transition waiting for prior epochs to complete.
struct PendingEpoch {
    epoch: u64,
    roster: Vec<u64>,
    deltas: Vec<PeerStateDelta>,
}

impl EpochEventBridge {
    /// Create a new, empty bridge in pre-initialization state.
    ///
    /// The first call to [`on_epoch_completed`](Self::on_epoch_completed)
    /// initializes the bridge at that epoch without requiring a transition
    /// from epoch 0.
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            last_applied_epoch: 0,
            state_digest: [0u8; 32],
            pending_epochs: VecDeque::new(),
            initialized: false,
        }
    }

    /// Register a subscriber.
    ///
    /// Returns a registration index that can be used to unregister.
    /// The subscriber will receive all future epoch transitions.
    /// Registration does not retroactively deliver past epochs.
    pub fn register(&mut self, subscriber: Box<dyn TransportEpochSubscriber>) -> usize {
        let id = self.subscribers.len();
        self.subscribers.push(subscriber);
        self.recompute_digest(self.last_applied_epoch, &[]);
        id
    }

    /// Unregister a previously registered subscriber.
    ///
    /// Returns `true` if the subscriber was found and removed,
    /// `false` if the index was out of bounds.
    pub fn unregister(&mut self, id: usize) -> bool {
        if id < self.subscribers.len() {
            self.subscribers.remove(id);
            self.recompute_digest(self.last_applied_epoch, &[]);
            true
        } else {
            false
        }
    }

    /// Notify the bridge that an epoch transition has committed.
    ///
    /// # Arguments
    ///
    /// * `epoch` — the new epoch number (must be > `last_applied_epoch`).
    /// * `roster` — sorted list of node IDs in the new roster.
    /// * `deltas` — per-peer changes from the previous roster to the new one.
    ///
    /// # Behavior
    ///
    /// - If `epoch` is exactly `last_applied_epoch + 1`, dispatches immediately.
    /// - If `epoch` is > `last_applied_epoch + 1`, queues and drains when
    ///   the missing intermediate epochs arrive.
    /// - If `epoch` ≤ `last_applied_epoch`, silently ignored (stale/dup).
    /// - On the very first call, `epoch` is accepted regardless of value.
    pub fn on_epoch_completed(&mut self, epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]) {
        if !self.initialized {
            self.dispatch_to_subscribers(epoch, roster, deltas);
            self.last_applied_epoch = epoch;
            self.initialized = true;
            self.recompute_digest(epoch, roster);
            return;
        }

        if epoch <= self.last_applied_epoch {
            return; // stale or duplicate
        }

        // Insert in sorted order and try to drain
        self.insert_pending(epoch, roster, deltas);
        self.drain_pending();
    }

    /// Return the last successfully applied epoch.
    pub fn last_applied_epoch(&self) -> u64 {
        self.last_applied_epoch
    }

    /// Return the current BLAKE3-256 bridge state digest.
    ///
    /// The digest covers `(last_applied_epoch, roster_hash, subscriber_count)`
    /// under domain `tidefs-transport-epoch-bridge-v1`.
    pub fn state_digest(&self) -> &[u8; 32] {
        &self.state_digest
    }

    /// Return the number of registered subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Number of epochs queued waiting for prior epochs to complete.
    pub fn pending_count(&self) -> usize {
        self.pending_epochs.len()
    }

    /// Whether the bridge has been initialized with at least one epoch.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // ── private helpers ─────────────────────────────────────────

    fn dispatch_to_subscribers(&self, epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]) {
        for sub in &self.subscribers {
            sub.on_epoch_transition(epoch, roster, deltas);
        }
    }

    fn recompute_digest(&mut self, epoch: u64, roster: &[u64]) {
        let roster_hash = Self::compute_roster_hash(roster);
        let mut hasher = Hasher::new_derive_key(BRIDGE_DOMAIN);
        hasher.update(&epoch.to_le_bytes());
        hasher.update(&roster_hash);
        hasher.update(&(self.subscribers.len() as u64).to_le_bytes());
        self.state_digest = hasher.finalize().into();
    }

    fn compute_roster_hash(roster: &[u64]) -> [u8; 32] {
        let mut hasher = Hasher::new();
        for node_id in roster {
            hasher.update(&node_id.to_le_bytes());
        }
        hasher.finalize().into()
    }

    fn insert_pending(&mut self, epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]) {
        let pending = PendingEpoch {
            epoch,
            roster: roster.to_vec(),
            deltas: deltas.to_vec(),
        };
        // Find insertion point to maintain sorted order
        let pos = self.pending_epochs.iter().position(|p| p.epoch > epoch);
        match pos {
            Some(idx) => {
                // Check for duplicate epoch
                if idx > 0 && self.pending_epochs[idx - 1].epoch == epoch {
                    return; // already queued
                }
                self.pending_epochs.insert(idx, pending);
            }
            None => {
                // Check last element for duplicate
                if self.pending_epochs.back().map(|p| p.epoch) == Some(epoch) {
                    return;
                }
                self.pending_epochs.push_back(pending);
            }
        }
    }

    fn drain_pending(&mut self) {
        loop {
            let next_epoch = self.last_applied_epoch + 1;
            match self.pending_epochs.front() {
                Some(pending) if pending.epoch == next_epoch => {
                    let p = self.pending_epochs.pop_front().unwrap();
                    self.dispatch_to_subscribers(p.epoch, &p.roster, &p.deltas);
                    self.last_applied_epoch = p.epoch;
                    self.recompute_digest(p.epoch, &p.roster);
                }
                Some(pending) if pending.epoch < next_epoch => {
                    // Stale queued epoch (shouldn't happen with sorted insert,
                    // but guard against it)
                    self.pending_epochs.pop_front();
                }
                _ => break,
            }
        }
    }
}

impl Default for EpochEventBridge {
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
    use std::sync::{Arc, Mutex};

    type TransitionRecord = (u64, Vec<u64>, Vec<PeerStateDelta>);
    type TransitionLog = Arc<Mutex<Vec<TransitionRecord>>>;

    /// Test subscriber that records received transitions.
    struct TestSubscriber {
        transitions: TransitionLog,
    }

    impl TestSubscriber {
        fn new_with_handle() -> (Self, TransitionLog) {
            let handle = Arc::new(Mutex::new(Vec::new()));
            let sub = Self {
                transitions: Arc::clone(&handle),
            };
            (sub, handle)
        }

        fn transitions(handle: &TransitionLog) -> Vec<TransitionRecord> {
            handle.lock().unwrap().clone()
        }
    }

    impl TransportEpochSubscriber for TestSubscriber {
        fn on_epoch_transition(&self, epoch: u64, roster: &[u64], deltas: &[PeerStateDelta]) {
            self.transitions
                .lock()
                .unwrap()
                .push((epoch, roster.to_vec(), deltas.to_vec()));
        }
    }

    // ----- initial dispatch -----

    #[test]
    fn first_epoch_accepted_regardless_of_value() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        // Start at epoch 7 (non-zero first epoch is valid for initial sync)
        bridge.on_epoch_completed(
            7,
            &[1, 2, 3],
            &[
                PeerStateDelta::Joined { node_id: 1 },
                PeerStateDelta::Joined { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ],
        );

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, 7);
        assert_eq!(t[0].1, vec![1, 2, 3]);
        assert_eq!(bridge.last_applied_epoch(), 7);
        assert!(bridge.is_initialized());
    }

    #[test]
    fn first_epoch_at_zero_is_accepted() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        bridge.on_epoch_completed(0, &[1], &[PeerStateDelta::Joined { node_id: 1 }]);

        assert_eq!(bridge.last_applied_epoch(), 0);
        assert!(bridge.is_initialized());
        assert_eq!(TestSubscriber::transitions(&handle).len(), 1);
    }

    // ----- sequential dispatch -----

    #[test]
    fn sequential_epochs_dispatch_in_order() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        bridge.on_epoch_completed(0, &[1], &[PeerStateDelta::Joined { node_id: 1 }]);
        bridge.on_epoch_completed(1, &[1, 2], &[PeerStateDelta::Joined { node_id: 2 }]);
        bridge.on_epoch_completed(2, &[1, 2, 3], &[PeerStateDelta::Joined { node_id: 3 }]);

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 3);
        assert_eq!(t[0].0, 0);
        assert_eq!(t[1].0, 1);
        assert_eq!(t[2].0, 2);
        assert_eq!(bridge.last_applied_epoch(), 2);
    }

    // ----- stale/duplicate rejection -----

    #[test]
    fn stale_epoch_is_ignored() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        bridge.on_epoch_completed(5, &[1], &[]);
        assert_eq!(bridge.last_applied_epoch(), 5);

        // Stale: epoch 3 < 5
        bridge.on_epoch_completed(3, &[1, 2], &[PeerStateDelta::Joined { node_id: 2 }]);
        assert_eq!(bridge.last_applied_epoch(), 5);

        // Duplicate
        bridge.on_epoch_completed(5, &[1], &[]);
        assert_eq!(bridge.last_applied_epoch(), 5);

        assert_eq!(TestSubscriber::transitions(&handle).len(), 1);
    }

    // ----- out-of-order queuing -----

    #[test]
    fn out_of_order_epochs_queued_and_drained() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        // Epoch 10 first
        bridge.on_epoch_completed(10, &[1], &[PeerStateDelta::Joined { node_id: 1 }]);
        assert_eq!(bridge.last_applied_epoch(), 10);

        // Epoch 13 arrives before 11 and 12
        bridge.on_epoch_completed(
            13,
            &[1, 2, 3, 4],
            &[
                PeerStateDelta::Joined { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
                PeerStateDelta::Joined { node_id: 4 },
            ],
        );
        assert_eq!(bridge.last_applied_epoch(), 10); // not yet applied
        assert_eq!(bridge.pending_count(), 1);

        // Epoch 12 arrives (still missing 11)
        bridge.on_epoch_completed(
            12,
            &[1, 2, 3],
            &[
                PeerStateDelta::Joined { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ],
        );
        assert_eq!(bridge.last_applied_epoch(), 10);
        assert_eq!(bridge.pending_count(), 2);

        // Epoch 11 arrives -- should drain 11, 12, 13
        bridge.on_epoch_completed(11, &[1, 2], &[PeerStateDelta::Joined { node_id: 2 }]);
        assert_eq!(bridge.last_applied_epoch(), 13);
        assert_eq!(bridge.pending_count(), 0);

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 4);
        assert_eq!(t[0].0, 10);
        assert_eq!(t[1].0, 11);
        assert_eq!(t[2].0, 12);
        assert_eq!(t[3].0, 13);
    }

    // ----- empty roster -----

    #[test]
    fn empty_roster_epoch_is_valid() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        bridge.on_epoch_completed(0, &[], &[]);

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, 0);
        assert!(t[0].1.is_empty());
        assert!(t[0].2.is_empty());
    }

    // ----- multiple subscribers -----

    #[test]
    fn multiple_subscribers_all_receive() {
        let mut bridge = EpochEventBridge::new();
        let (sub1, handle1) = TestSubscriber::new_with_handle();
        let (sub2, handle2) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub1));
        bridge.register(Box::new(sub2));

        bridge.on_epoch_completed(
            0,
            &[1, 2],
            &[
                PeerStateDelta::Joined { node_id: 1 },
                PeerStateDelta::Joined { node_id: 2 },
            ],
        );

        let t1 = TestSubscriber::transitions(&handle1);
        let t2 = TestSubscriber::transitions(&handle2);
        assert_eq!(t1.len(), 1);
        assert_eq!(t2.len(), 1);
        assert_eq!(t1[0], t2[0]);
    }

    // ----- subscriber lifecycle -----

    #[test]
    fn unsubscribed_subscriber_stops_receiving() {
        let mut bridge = EpochEventBridge::new();
        let (sub1, handle1) = TestSubscriber::new_with_handle();
        let (sub2, handle2) = TestSubscriber::new_with_handle();
        let id1 = bridge.register(Box::new(sub1));
        bridge.register(Box::new(sub2));

        bridge.on_epoch_completed(0, &[1], &[PeerStateDelta::Joined { node_id: 1 }]);
        assert_eq!(TestSubscriber::transitions(&handle1).len(), 1);
        assert_eq!(TestSubscriber::transitions(&handle2).len(), 1);

        assert!(bridge.unregister(id1));

        bridge.on_epoch_completed(1, &[1, 2], &[PeerStateDelta::Joined { node_id: 2 }]);
        assert_eq!(TestSubscriber::transitions(&handle1).len(), 1); // no new
        assert_eq!(TestSubscriber::transitions(&handle2).len(), 2);
    }

    #[test]
    fn subscriber_count_is_accurate() {
        let mut bridge = EpochEventBridge::new();
        assert_eq!(bridge.subscriber_count(), 0);

        let (sub, _) = TestSubscriber::new_with_handle();
        let id = bridge.register(Box::new(sub));
        assert_eq!(bridge.subscriber_count(), 1);

        bridge.unregister(id);
        assert_eq!(bridge.subscriber_count(), 0);
    }

    #[test]
    fn unregister_invalid_index_returns_false() {
        let mut bridge = EpochEventBridge::new();
        assert!(!bridge.unregister(0));
        assert!(!bridge.unregister(999));
    }

    // ----- BLAKE3 digest determinism -----

    #[test]
    fn state_digest_is_deterministic() {
        let mut b1 = EpochEventBridge::new();
        let (sub1, _) = TestSubscriber::new_with_handle();
        b1.register(Box::new(sub1));
        b1.on_epoch_completed(
            5,
            &[1, 2, 3],
            &[
                PeerStateDelta::Joined { node_id: 1 },
                PeerStateDelta::Joined { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ],
        );

        let mut b2 = EpochEventBridge::new();
        let (sub2, _) = TestSubscriber::new_with_handle();
        b2.register(Box::new(sub2));
        b2.on_epoch_completed(
            5,
            &[1, 2, 3],
            &[
                PeerStateDelta::Joined { node_id: 1 },
                PeerStateDelta::Joined { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ],
        );

        assert_eq!(b1.state_digest(), b2.state_digest());
    }

    #[test]
    fn state_digest_differs_by_epoch() {
        let mut b1 = EpochEventBridge::new();
        let (sub1, _) = TestSubscriber::new_with_handle();
        b1.register(Box::new(sub1));
        b1.on_epoch_completed(1, &[1], &[]);

        let mut b2 = EpochEventBridge::new();
        let (sub2, _) = TestSubscriber::new_with_handle();
        b2.register(Box::new(sub2));
        b2.on_epoch_completed(2, &[1], &[]);

        assert_ne!(b1.state_digest(), b2.state_digest());
    }

    #[test]
    fn state_digest_differs_by_roster() {
        let mut b1 = EpochEventBridge::new();
        let (sub1, _) = TestSubscriber::new_with_handle();
        b1.register(Box::new(sub1));
        b1.on_epoch_completed(1, &[1, 2], &[]);

        let mut b2 = EpochEventBridge::new();
        let (sub2, _) = TestSubscriber::new_with_handle();
        b2.register(Box::new(sub2));
        b2.on_epoch_completed(1, &[1, 3], &[]);

        assert_ne!(b1.state_digest(), b2.state_digest());
    }

    #[test]
    fn state_digest_differs_by_subscriber_count() {
        let mut b1 = EpochEventBridge::new();
        let (sub1, _) = TestSubscriber::new_with_handle();
        b1.register(Box::new(sub1));
        b1.on_epoch_completed(1, &[1], &[]);

        let mut b2 = EpochEventBridge::new();
        let (sub2, _) = TestSubscriber::new_with_handle();
        let (sub3, _) = TestSubscriber::new_with_handle();
        b2.register(Box::new(sub2));
        b2.register(Box::new(sub3));
        b2.on_epoch_completed(1, &[1], &[]);

        assert_ne!(b1.state_digest(), b2.state_digest());
    }

    #[test]
    fn state_digest_updates_after_each_epoch() {
        let mut bridge = EpochEventBridge::new();
        let (sub, _) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        let d0 = *bridge.state_digest(); // pre-init (all zeros)

        bridge.on_epoch_completed(0, &[1], &[]);
        let d1 = *bridge.state_digest();
        assert_ne!(d0, d1);

        bridge.on_epoch_completed(1, &[1, 2], &[]);
        let d2 = *bridge.state_digest();
        assert_ne!(d1, d2);
    }

    // ----- rapid epoch churn -----

    #[test]
    fn rapid_epoch_churn_dispatches_all_in_order() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        // Simulate rapid churn: epochs arrive out of order
        let epochs: Vec<(u64, Vec<u64>, Vec<PeerStateDelta>)> = vec![
            (0, vec![1], vec![PeerStateDelta::Joined { node_id: 1 }]),
            (
                2,
                vec![1, 2, 3],
                vec![
                    PeerStateDelta::Joined { node_id: 2 },
                    PeerStateDelta::Joined { node_id: 3 },
                ],
            ),
            (
                4,
                vec![1, 2, 3, 4],
                vec![PeerStateDelta::Joined { node_id: 4 }],
            ),
            (1, vec![1, 2], vec![PeerStateDelta::Joined { node_id: 2 }]),
            (3, vec![1, 2, 3], vec![]), // no-op delta
            (
                5,
                vec![1, 2, 3, 4, 5],
                vec![PeerStateDelta::Joined { node_id: 5 }],
            ),
        ];

        for (epoch, roster, deltas) in &epochs {
            bridge.on_epoch_completed(*epoch, roster, deltas);
        }

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 6);
        for (i, transition) in t.iter().enumerate().take(6) {
            assert_eq!(transition.0, i as u64);
        }
        assert_eq!(bridge.last_applied_epoch(), 5);
        assert_eq!(bridge.pending_count(), 0);
    }

    // ----- all delta variant types -----

    #[test]
    fn all_delta_variants_dispatched() {
        let mut bridge = EpochEventBridge::new();
        let (sub, handle) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));

        bridge.on_epoch_completed(
            0,
            &[1, 2],
            &[
                PeerStateDelta::Joined { node_id: 1 },
                PeerStateDelta::Joined { node_id: 2 },
            ],
        );

        bridge.on_epoch_completed(
            1,
            &[1, 2, 3],
            &[
                PeerStateDelta::Drained { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ],
        );

        bridge.on_epoch_completed(2, &[1, 3], &[PeerStateDelta::Failed { node_id: 1 }]);

        bridge.on_epoch_completed(3, &[3], &[PeerStateDelta::StateChanged { node_id: 3 }]);

        let t = TestSubscriber::transitions(&handle);
        assert_eq!(t.len(), 4);
        assert_eq!(
            t[1].2,
            vec![
                PeerStateDelta::Drained { node_id: 2 },
                PeerStateDelta::Joined { node_id: 3 },
            ]
        );
        assert_eq!(t[2].2, vec![PeerStateDelta::Failed { node_id: 1 }]);
        assert_eq!(t[3].2, vec![PeerStateDelta::StateChanged { node_id: 3 }]);
    }

    // ----- PeerStateDelta accessors -----

    #[test]
    fn peer_state_delta_node_id() {
        assert_eq!(PeerStateDelta::Joined { node_id: 42 }.node_id(), 42);
        assert_eq!(PeerStateDelta::Drained { node_id: 7 }.node_id(), 7);
        assert_eq!(PeerStateDelta::Failed { node_id: 99 }.node_id(), 99);
        assert_eq!(PeerStateDelta::StateChanged { node_id: 0 }.node_id(), 0);
    }

    // ----- default implementation -----

    #[test]
    fn default_bridge_is_empty() {
        let bridge = EpochEventBridge::default();
        assert_eq!(bridge.subscriber_count(), 0);
        assert_eq!(bridge.pending_count(), 0);
        assert!(!bridge.is_initialized());
    }

    #[test]
    fn initialized_flag_after_first_epoch() {
        let mut bridge = EpochEventBridge::new();
        let (sub, _) = TestSubscriber::new_with_handle();
        bridge.register(Box::new(sub));
        assert!(!bridge.is_initialized());
        bridge.on_epoch_completed(0, &[1], &[]);
        assert!(bridge.is_initialized());
    }
}
