// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-peer bounded FIFO send queue with configurable backpressure.
//!
//! Provides a bounded FIFO send queue per connected peer so upper-layer
//! protocols (membership, leases, filesystem data) can enqueue outbound
//! messages with ordering guarantees and receive backpressure when the
//! peer's queue reaches capacity.

use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::{Mutex, Notify};

use crate::send_admission::{
    DroppedSendEvidence, SendAdmissionEvidence, SendAdmissionOutcome, SendAdmissionPolicy,
    SendCapacityClass, SendCapacityEvidence, SendWakeEvidence,
};
use crate::PeerId;

/// Backpressure policy applied when a peer's send queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Block the sender until capacity frees up (async wait).
    Block,
    /// Drop the oldest message to make room for the new one.
    DropOldest,
    /// Return an error to the sender immediately.
    Error,
}

/// Accumulated statistics for a single peer send queue.
#[derive(Debug, Clone, Default)]
pub struct QueueStats {
    /// Current number of messages waiting in the queue.
    pub depth: usize,
    /// Total messages ever enqueued successfully.
    pub total_enqueued: u64,
    /// Total messages dropped due to backpressure (DropOldest policy).
    pub total_dropped: u64,
}

/// Reason a send operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SendError {
    /// Queue is full and policy is `Error`.
    #[error("peer send queue is full")]
    Full { evidence: SendAdmissionEvidence },
    /// Queue has been closed (peer removed or shutting down).
    #[error("peer send queue is closed")]
    Closed { evidence: SendAdmissionEvidence },
}

impl SendError {
    /// Return the admission evidence carried by this send error.
    #[must_use]
    pub fn evidence(&self) -> &SendAdmissionEvidence {
        match self {
            Self::Full { evidence } | Self::Closed { evidence } => evidence,
        }
    }
}

/// Cloneable sender handle for enqueuing messages into a specific peer's queue.
///
/// Multiple upper-layer protocol handlers can hold clones of this sender
/// and enqueue messages concurrently. Ordering is FIFO per queue but
/// interleaving across concurrent senders is non-deterministic.
pub struct PeerQueueSender<M> {
    peer_id: PeerId,
    inner: Arc<Mutex<InnerQueue<M>>>,
    notify: Arc<Notify>,
}

impl<M> Clone for PeerQueueSender<M> {
    fn clone(&self) -> Self {
        Self {
            peer_id: self.peer_id,
            inner: Arc::clone(&self.inner),
            notify: Arc::clone(&self.notify),
        }
    }
}

/// Single-consumer receiver handle that drains a peer's queue.
///
/// The transport send path holds exactly one receiver per peer and
/// forwards dequeued messages to frame encoding.
pub struct PeerQueueReceiver<M> {
    peer_id: PeerId,
    inner: Arc<Mutex<InnerQueue<M>>>,
    notify: Arc<Notify>,
}

struct InnerQueue<M> {
    queue: VecDeque<M>,
    capacity: usize,
    policy: BackpressurePolicy,
    stats: QueueStats,
    closed: bool,
}

impl<M> InnerQueue<M> {
    fn new(capacity: usize, policy: BackpressurePolicy) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity.min(64)),
            capacity,
            policy,
            stats: QueueStats::default(),
            closed: false,
        }
    }

    fn stats(&self) -> QueueStats {
        let mut s = self.stats.clone();
        s.depth = self.queue.len();
        s
    }
}

/// Manages bounded FIFO send queues for all connected peers.
///
/// Upper-layer protocols obtain a [`PeerQueueSender`] via
/// [`sender`](PeerSendQueue::sender) and enqueue outbound messages.
/// The transport send path obtains a [`PeerQueueReceiver`] via
/// [`take_receiver`](PeerSendQueue::take_receiver) and drains the
/// queue to feed frame encoding.
pub struct PeerSendQueue<M> {
    max_queued_per_peer: usize,
    default_policy: BackpressurePolicy,
    senders: HashMap<PeerId, PeerQueueSender<M>>,
    receivers: HashMap<PeerId, PeerQueueReceiver<M>>,
    removed: HashSet<PeerId>,
}

impl<M> PeerSendQueue<M> {
    /// Create a new peer send queue registry.
    ///
    /// `max_queued_per_peer` sets the per-peer channel capacity (default 256).
    /// `default_policy` is applied to new peer queues.
    pub fn new(max_queued_per_peer: usize, default_policy: BackpressurePolicy) -> Self {
        Self {
            max_queued_per_peer,
            default_policy,
            senders: HashMap::new(),
            receivers: HashMap::new(),
            removed: HashSet::new(),
        }
    }

    /// Get or create a cloneable sender for the given peer.
    ///
    /// Returns `None` if the queue was previously removed via
    /// [`remove_peer`](Self::remove_peer).
    pub fn sender(&mut self, peer_id: PeerId) -> Option<PeerQueueSender<M>> {
        if self.removed.contains(&peer_id) {
            return None;
        }
        if let Some(sender) = self.senders.get(&peer_id) {
            return Some(sender.clone());
        }
        let (sender, receiver) =
            Self::make_pair(peer_id, self.max_queued_per_peer, self.default_policy);
        self.senders.insert(peer_id, sender.clone());
        self.receivers.insert(peer_id, receiver);
        Some(sender)
    }

    /// Take the single-consumer receiver for a peer.
    ///
    /// Returns `None` if the peer has no queue or the receiver was
    /// already taken.
    pub fn take_receiver(&mut self, peer_id: PeerId) -> Option<PeerQueueReceiver<M>> {
        self.receivers.remove(&peer_id)
    }

    /// Remove a peer's queue entirely, draining any pending messages.
    ///
    /// After removal, calls to [`sender`](Self::sender) for this peer
    /// will return `None`, and any in-flight or future sends will
    /// receive [`SendError::Closed`].
    pub fn remove_peer(&mut self, peer_id: PeerId) {
        self.removed.insert(peer_id);
        // Close the inner state before removing entries so any
        // in-flight or future sends see Closed.
        if let Some(sender) = self.senders.get(&peer_id) {
            if let Ok(mut guard) = sender.inner.try_lock() {
                guard.closed = true;
                sender.notify.notify_waiters();
            }
        }
        self.senders.remove(&peer_id);
        // Dropping the receiver (if present) also triggers its Drop
        // which redundantly sets closed — harmless.
        self.receivers.remove(&peer_id);
    }

    /// Snapshot stats for a peer's queue.
    pub fn stats(&self, peer_id: PeerId) -> Option<QueueStats> {
        self.senders
            .get(&peer_id)
            .map(|s| match s.inner.try_lock() {
                Ok(guard) => guard.stats(),
                Err(_) => QueueStats::default(),
            })
    }

    fn make_pair(
        peer_id: PeerId,
        capacity: usize,
        policy: BackpressurePolicy,
    ) -> (PeerQueueSender<M>, PeerQueueReceiver<M>) {
        let inner = Arc::new(Mutex::new(InnerQueue::new(capacity, policy)));
        let notify = Arc::new(Notify::new());
        let sender = PeerQueueSender {
            peer_id,
            inner: Arc::clone(&inner),
            notify: Arc::clone(&notify),
        };
        let receiver = PeerQueueReceiver {
            peer_id,
            inner,
            notify,
        };
        (sender, receiver)
    }
}

impl<M> PeerQueueSender<M> {
    /// Enqueue a message into the peer's FIFO send queue.
    ///
    /// Behaviour depends on the configured [`BackpressurePolicy`]:
    ///
    /// - [`Block`](BackpressurePolicy::Block): waits asynchronously until
    ///   capacity frees up.
    /// - [`DropOldest`](BackpressurePolicy::DropOldest): evicts the oldest
    ///   message to make room if the queue is full.
    /// - [`Error`](BackpressurePolicy::Error): returns full-queue evidence
    ///   immediately if the queue is at capacity.
    ///
    /// Returns closed evidence if the peer's queue has been removed.
    pub async fn send(&self, msg: M) -> Result<SendAdmissionEvidence, SendError> {
        let mut waited = false;
        loop {
            let notified = self.notify.notified();
            {
                let mut guard = self.inner.lock().await;
                if guard.closed {
                    let wake = if waited {
                        SendWakeEvidence::ClosedObserved
                    } else {
                        SendWakeEvidence::NotApplicable
                    };
                    return Err(SendError::Closed {
                        evidence: self
                            .evidence(SendAdmissionOutcome::Closed, &guard)
                            .with_policy(SendAdmissionPolicy::Shutdown)
                            .with_wake(wake),
                    });
                }
                if guard.queue.len() < guard.capacity {
                    guard.queue.push_back(msg);
                    guard.stats.total_enqueued += 1;
                    self.notify.notify_one();
                    let outcome = if waited {
                        SendAdmissionOutcome::Blocked
                    } else {
                        SendAdmissionOutcome::Queued
                    };
                    let wake = if waited {
                        SendWakeEvidence::DrainObserved
                    } else {
                        SendWakeEvidence::NotApplicable
                    };
                    return Ok(self
                        .evidence(outcome, &guard)
                        .with_policy(self.policy_evidence(guard.policy))
                        .with_wake(wake));
                }
                match guard.policy {
                    BackpressurePolicy::Error => {
                        return Err(SendError::Full {
                            evidence: self
                                .evidence(SendAdmissionOutcome::Backpressured, &guard)
                                .with_policy(SendAdmissionPolicy::Error),
                        });
                    }
                    BackpressurePolicy::DropOldest => {
                        let depth_before = guard.queue.len();
                        let _oldest = guard.queue.pop_front();
                        guard.stats.total_dropped += 1;
                        guard.queue.push_back(msg);
                        guard.stats.total_enqueued += 1;
                        self.notify.notify_one();
                        return Ok(self
                            .evidence(SendAdmissionOutcome::DroppedOldest, &guard)
                            .with_policy(SendAdmissionPolicy::DropOldest)
                            .with_dropped(vec![DroppedSendEvidence::message(depth_before)]));
                    }
                    BackpressurePolicy::Block => {
                        // Fall through: drop lock, wait for space.
                    }
                }
            }
            // Queue full under Block policy; wait for receiver to drain.
            notified.await;
            waited = true;
        }
    }

    /// Attempt to enqueue without blocking.
    ///
    /// Returns queued evidence on success, full evidence if the queue
    /// is at capacity under a policy that doesn't resolve synchronously,
    /// or closed evidence if the queue is closed.
    pub fn try_send(&self, msg: M) -> Result<SendAdmissionEvidence, SendError> {
        let mut guard = self.inner.try_lock().map_err(|_| SendError::Full {
            evidence: SendAdmissionEvidence::new(SendAdmissionOutcome::Backpressured)
                .with_peer_id(self.peer_id)
                .with_wake(SendWakeEvidence::Unavailable),
        })?;
        if guard.closed {
            return Err(SendError::Closed {
                evidence: self
                    .evidence(SendAdmissionOutcome::Closed, &guard)
                    .with_policy(SendAdmissionPolicy::Shutdown),
            });
        }
        if guard.queue.len() < guard.capacity {
            guard.queue.push_back(msg);
            guard.stats.total_enqueued += 1;
            self.notify.notify_one();
            return Ok(self
                .evidence(SendAdmissionOutcome::Queued, &guard)
                .with_policy(self.policy_evidence(guard.policy)));
        }
        match guard.policy {
            BackpressurePolicy::Error => Err(SendError::Full {
                evidence: self
                    .evidence(SendAdmissionOutcome::Backpressured, &guard)
                    .with_policy(SendAdmissionPolicy::Error),
            }),
            BackpressurePolicy::DropOldest => {
                let depth_before = guard.queue.len();
                let _oldest = guard.queue.pop_front();
                guard.stats.total_dropped += 1;
                guard.queue.push_back(msg);
                guard.stats.total_enqueued += 1;
                self.notify.notify_one();
                Ok(self
                    .evidence(SendAdmissionOutcome::DroppedOldest, &guard)
                    .with_policy(SendAdmissionPolicy::DropOldest)
                    .with_dropped(vec![DroppedSendEvidence::message(depth_before)]))
            }
            BackpressurePolicy::Block => Err(SendError::Full {
                evidence: self
                    .evidence(SendAdmissionOutcome::Backpressured, &guard)
                    .with_policy(SendAdmissionPolicy::Block)
                    .with_wake(SendWakeEvidence::Unavailable),
            }),
        }
    }

    /// Return statistics for this peer's queue.
    pub fn stats(&self) -> QueueStats {
        match self.inner.try_lock() {
            Ok(guard) => guard.stats(),
            Err(_) => QueueStats::default(),
        }
    }

    fn policy_evidence(&self, policy: BackpressurePolicy) -> SendAdmissionPolicy {
        match policy {
            BackpressurePolicy::Block => SendAdmissionPolicy::Block,
            BackpressurePolicy::DropOldest => SendAdmissionPolicy::DropOldest,
            BackpressurePolicy::Error => SendAdmissionPolicy::Error,
        }
    }

    fn evidence(
        &self,
        outcome: SendAdmissionOutcome,
        guard: &InnerQueue<M>,
    ) -> SendAdmissionEvidence {
        SendAdmissionEvidence::new(outcome)
            .with_peer_id(self.peer_id)
            .with_queue_depth(guard.queue.len())
            .with_capacity(SendCapacityEvidence::new(
                SendCapacityClass::Message,
                guard.queue.len(),
                Some(1),
                Some(guard.capacity),
            ))
    }
}

impl<M> PeerQueueReceiver<M> {
    /// Return the peer identity associated with this receiver.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Receive the next message from the peer's FIFO queue.
    ///
    /// Returns `Some(msg)` when a message is available, or `None` when
    /// the queue is closed and empty.
    pub async fn recv(&mut self) -> Option<M> {
        loop {
            {
                let mut guard = self.inner.lock().await;
                if let Some(msg) = guard.queue.pop_front() {
                    self.notify.notify_one();
                    return Some(msg);
                }
                if guard.closed {
                    return None;
                }
            }
            // Queue empty and not closed; wait for a sender.
            self.notify.notified().await;
        }
    }

    /// Mark the queue as closed so the receiver and any blocked senders
    /// wake up and return `None` / `Closed` respectively.
    pub async fn close(&mut self) {
        let mut guard = self.inner.lock().await;
        guard.closed = true;
        self.notify.notify_waiters();
    }
}

impl<M> Drop for PeerQueueReceiver<M> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.try_lock() {
            guard.closed = true;
            self.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fifo_ordering() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(256, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        for i in 0..10 {
            sender.send(i).await.unwrap();
        }

        for i in 0..10 {
            let msg = receiver.recv().await;
            assert_eq!(msg, Some(i), "FIFO ordering violated at position {i}");
        }
    }

    #[tokio::test]
    async fn block_on_full() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(4, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        for i in 0..4 {
            sender.send(i).await.unwrap();
        }

        let s2 = sender.clone();
        let handle = tokio::spawn(async move { s2.send(100).await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let first = receiver.recv().await;
        assert_eq!(first, Some(0));

        let evidence = handle.await.unwrap();
        assert_eq!(evidence.outcome, SendAdmissionOutcome::Blocked);
        assert_eq!(evidence.wake, SendWakeEvidence::DrainObserved);
    }

    #[tokio::test]
    async fn drop_oldest_policy() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(4, BackpressurePolicy::DropOldest);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        for i in 0..4 {
            sender.send(i).await.unwrap();
        }

        // Should drop 0, push 100: [1, 2, 3, 100]
        sender.send(100).await.unwrap();

        let stats = sender.stats();
        assert_eq!(stats.total_dropped, 1);

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, Some(2));
        assert_eq!(receiver.recv().await, Some(3));
        assert_eq!(receiver.recv().await, Some(100));
    }

    #[tokio::test]
    async fn error_policy_on_full() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(2, BackpressurePolicy::Error);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.send(1).await.unwrap();
        sender.send(2).await.unwrap();

        let result = sender.send(3).await;
        match result {
            Err(SendError::Full { evidence }) => {
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
                assert_eq!(evidence.peer_id, Some(1));
                assert_eq!(evidence.queue_depth, Some(2));
            }
            other => panic!("expected full evidence, got {other:?}"),
        }

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, Some(2));
    }

    #[tokio::test]
    async fn multiple_concurrent_senders() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(256, BackpressurePolicy::Block);
        let s1 = psq.sender(1).unwrap();
        let s2 = s1.clone();
        let s3 = s1.clone();
        let mut receiver = psq.take_receiver(1).unwrap();

        let h1 = tokio::spawn(async move {
            for i in 0..10 {
                s1.send(i).await.unwrap();
            }
        });
        let h2 = tokio::spawn(async move {
            for i in 10..20 {
                s2.send(i).await.unwrap();
            }
        });
        let h3 = tokio::spawn(async move {
            for i in 20..30 {
                s3.send(i).await.unwrap();
            }
        });

        h1.await.unwrap();
        h2.await.unwrap();
        h3.await.unwrap();

        let mut received: Vec<u32> = vec![];
        for _ in 0..30 {
            let msg = receiver.recv().await;
            received.push(msg.unwrap());
        }

        received.sort_unstable();
        assert_eq!(received, (0..30).collect::<Vec<u32>>());
    }

    #[tokio::test]
    async fn stats_tracking() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(10, BackpressurePolicy::DropOldest);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        for i in 0..5 {
            sender.send(i).await.unwrap();
        }

        let stats = sender.stats();
        assert_eq!(stats.depth, 5);
        assert_eq!(stats.total_enqueued, 5);
        assert_eq!(stats.total_dropped, 0);

        assert_eq!(receiver.recv().await, Some(0));
        assert_eq!(receiver.recv().await, Some(1));

        let stats = sender.stats();
        assert_eq!(stats.depth, 3);
        assert_eq!(stats.total_enqueued, 5);
    }

    #[tokio::test]
    async fn remove_peer_closes_queue() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(4, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.send(1).await.unwrap();

        // Remove the peer while the receiver is held externally.
        psq.remove_peer(1);

        // Draining should still work — already-enqueued messages
        // are delivered before the close is observed.
        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, None);

        // Subsequent sends fail.
        let result = sender.send(2).await;
        match result {
            Err(SendError::Closed { evidence }) => {
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Closed);
                assert_eq!(evidence.peer_id, Some(1));
            }
            other => panic!("expected closed evidence, got {other:?}"),
        }

        assert!(psq.sender(1).is_none());
    }

    #[tokio::test]
    async fn receiver_close_wakes_blocked_senders() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(2, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.send(1).await.unwrap();
        sender.send(2).await.unwrap();

        let s2 = sender.clone();
        let handle = tokio::spawn(async move { s2.send(3).await });

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        receiver.close().await;

        let result = handle.await.unwrap();
        match result {
            Err(SendError::Closed { evidence }) => {
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Closed);
                assert_eq!(evidence.wake, SendWakeEvidence::ClosedObserved);
            }
            other => panic!("expected closed wake evidence, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_returns_none_when_closed_and_empty() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(256, BackpressurePolicy::Block);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.send(42).await.unwrap();

        receiver.close().await;

        assert_eq!(receiver.recv().await, Some(42));
        assert_eq!(receiver.recv().await, None);
    }

    #[tokio::test]
    async fn try_send_basic() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(2, BackpressurePolicy::Error);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.try_send(1).unwrap();
        sender.try_send(2).unwrap();
        match sender.try_send(3) {
            Err(SendError::Full { evidence }) => {
                assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
                assert_eq!(evidence.queue_depth, Some(2));
            }
            other => panic!("expected try_send full evidence, got {other:?}"),
        }

        assert_eq!(receiver.recv().await, Some(1));
        assert_eq!(receiver.recv().await, Some(2));
    }

    #[tokio::test]
    async fn try_send_drop_oldest() {
        let mut psq: PeerSendQueue<u32> = PeerSendQueue::new(2, BackpressurePolicy::DropOldest);
        let sender = psq.sender(1).unwrap();
        let mut receiver = psq.take_receiver(1).unwrap();

        sender.try_send(1).unwrap();
        sender.try_send(2).unwrap();
        let evidence = sender.try_send(3).unwrap(); // drops 1
        assert_eq!(evidence.outcome, SendAdmissionOutcome::DroppedOldest);
        assert_eq!(evidence.dropped.len(), 1);

        assert_eq!(receiver.recv().await, Some(2));
        assert_eq!(receiver.recv().await, Some(3));
    }
}
