// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bounded per-peer send buffer with memory accounting and backpressure
//! propagation.
//!
//! ## Design
//!
//! Each remote peer gets a [`PeerSendBuffer`] that holds serialized frames
//! (`Bytes`) awaiting transmission on the wire. The buffer has a configurable
//! `max_memory` cap (default 4 MiB, min 4 KiB, max 64 MiB). When a peer's
//! buffer is full, [`try_enqueue`](PeerSendBuffer::try_enqueue) returns typed
//! [`SendAdmissionEvidence`](crate::send_admission::SendAdmissionEvidence) so
//! the producing subsystem can slow down or drop rather than growing memory
//! without bound.
//!
//! The send buffer sits below the priority scheduler and above the wire,
//! holding frames after scheduling decisions have been made. Flow control
//! (#5701) governs rate; the send buffer governs capacity.
//!
//! ### Backpressure contract
//!
//! Callers must inspect the evidence returned by `try_enqueue`:
//!
//! | Outcome                 | Meaning                                              |
//! |-------------------------|------------------------------------------------------|
//! | `Accepted`              | Frame accepted into the buffer.                      |
//! | `DroppedOldest`         | Frame accepted after older queued frames were dropped. |
//! | `Backpressured`         | Buffer at capacity; caller should slow down or drop. |
//! | `Closed`                | Buffer has been shut down (peer departed/closed).    |
//!
//! `Backpressured` is a soft pressure signal — distinct from circuit-breaker
//! open, which is a hard-failure signal. Flow-control windows and circuit
//! breakers should treat it as an advisory to reduce send rate, not as a
//! reason to open the circuit.
//!
//! ### Memory accounting
//!
//! Memory tracking uses plain atomic counters rather than BLAKE3 hashing,
//! consistent with the transport refactoring trend (#5714, #5713) of
//! removing redundant integrity layers from hot paths. The `allocated`
//! counter tracks the sum of all `Bytes` lengths currently queued.

use bytes::Bytes;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tidefs_cache_core::Governor;

use crate::send_admission::{
    admit_cluster_queue_budget, ClusterQueueAdmissionClass, ClusterQueueAllocationKind,
    ClusterQueueBudgetGuard, DroppedSendEvidence, SendAdmissionEvidence, SendAdmissionOutcome,
    SendAdmissionPolicy, SendCapacityClass, SendCapacityEvidence, SendPressureReason,
    SendWakeEvidence,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Minimum allowed per-peer send buffer memory (4 KiB).
pub const MIN_SEND_BUFFER_MEMORY: u64 = 4_096;

/// Default per-peer send buffer memory (4 MiB).
pub const DEFAULT_SEND_BUFFER_MEMORY: u64 = 4 * 1_048_576;

/// Maximum allowed per-peer send buffer memory (64 MiB).
pub const MAX_SEND_BUFFER_MEMORY: u64 = 64 * 1_048_576;

// ---------------------------------------------------------------------------
// SendBufferConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`PeerSendBuffer`].
///
/// `max_memory` is clamped to [`MIN_SEND_BUFFER_MEMORY`]..=
/// [`MAX_SEND_BUFFER_MEMORY`] during validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendBufferConfig {
    /// Maximum bytes this send buffer may hold across all queued frames.
    pub max_memory: u64,
    /// Policy applied when the buffer cannot accommodate a new frame.
    pub backpressure_policy: BackpressurePolicy,
}

impl Default for SendBufferConfig {
    fn default() -> Self {
        Self {
            max_memory: DEFAULT_SEND_BUFFER_MEMORY,
            backpressure_policy: BackpressurePolicy::Error,
        }
    }
}

impl SendBufferConfig {
    /// Validate the configuration.
    ///
    /// Returns `Err` with a message if `max_memory` is outside the
    /// allowed range.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_memory < MIN_SEND_BUFFER_MEMORY {
            return Err("max_memory below minimum (4 KiB)");
        }
        if self.max_memory > MAX_SEND_BUFFER_MEMORY {
            return Err("max_memory above maximum (64 MiB)");
        }
        Ok(())
    }

    /// Return a validated config, clamping to the allowed range.
    #[must_use]
    pub fn validated(self) -> Self {
        Self {
            max_memory: self
                .max_memory
                .clamp(MIN_SEND_BUFFER_MEMORY, MAX_SEND_BUFFER_MEMORY),
            backpressure_policy: self.backpressure_policy,
        }
    }

    /// Create a config with the minimum allowed memory.
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            max_memory: MIN_SEND_BUFFER_MEMORY,
            backpressure_policy: BackpressurePolicy::Error,
        }
    }
}

// ---------------------------------------------------------------------------
// BackpressurePolicy
// ---------------------------------------------------------------------------

/// Per-session backpressure enforcement policy.
///
/// Determines what happens when the send buffer is at capacity and a new
/// message is submitted for enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// Return an error immediately. The caller must retry or drop the message.
    Error,
    /// Evict the oldest queued Data-plane messages from the buffer until
    /// enough capacity is freed, then enqueue the new message. A warning
    /// is logged for each evicted message.
    DropOldest,
    /// Return an error for now.
    ///
    /// Review debt TFR-017: async-wait for capacity with optional deadline.
    Block,
}

impl Default for BackpressurePolicy {
    fn default() -> Self {
        Self::Error
    }
}

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

/// Outcome of attempting to enqueue a frame into a [`PeerSendBuffer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backpressure {
    /// Frame was accepted into the buffer.
    Ok,
    /// Buffer is at capacity; the caller should slow down or drop the frame.
    PeerFull,
    /// Buffer has been shut down; no further enqueues are accepted.
    Shutdown,
}

impl std::fmt::Display for Backpressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::PeerFull => write!(f, "peer send buffer full"),
            Self::Shutdown => write!(f, "peer send buffer shut down"),
        }
    }
}

impl PartialEq<Backpressure> for SendAdmissionEvidence {
    fn eq(&self, other: &Backpressure) -> bool {
        matches!(
            (self.outcome, other),
            (
                SendAdmissionOutcome::Accepted
                    | SendAdmissionOutcome::Queued
                    | SendAdmissionOutcome::Blocked
                    | SendAdmissionOutcome::DroppedOldest,
                Backpressure::Ok
            ) | (SendAdmissionOutcome::Backpressured, Backpressure::PeerFull)
                | (SendAdmissionOutcome::Closed, Backpressure::Shutdown)
        )
    }
}

// ---------------------------------------------------------------------------
// PeerBufferStats
// ---------------------------------------------------------------------------

/// Monotonic per-peer send buffer statistics.
///
/// All counters are `AtomicU64` for lock-free access from the enqueue path
/// and the stats-reporting path simultaneously.
#[derive(Debug)]
pub struct PeerBufferStats {
    /// Total frames accepted by `try_enqueue`.
    pub enqueued: AtomicU64,
    /// Total frames dropped via `drain()` (peer close / circuit-breaker open).
    pub dropped: AtomicU64,
    /// Total frames rejected due to full buffer (`Backpressure::PeerFull`).
    pub rejected: AtomicU64,
    /// Total frames rejected due to shutdown (`Backpressure::Shutdown`).
    pub rejected_shutdown: AtomicU64,
    /// Total frames that encountered the Block policy (backpressure signal
    /// where the caller should wait rather than drop or error).
    pub blocks: AtomicU64,
}

impl Default for PeerBufferStats {
    fn default() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            rejected_shutdown: AtomicU64::new(0),
            blocks: AtomicU64::new(0),
        }
    }
}

impl PeerBufferStats {
    /// Return a snapshot of all counters at this instant.
    pub fn snapshot(&self) -> BufferStatsSnapshot {
        BufferStatsSnapshot {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            rejected_shutdown: self.rejected_shutdown.load(Ordering::Relaxed),
            blocks: self.blocks.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time snapshot of [`PeerBufferStats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BufferStatsSnapshot {
    pub enqueued: u64,
    pub dropped: u64,
    pub rejected: u64,
    pub rejected_shutdown: u64,
    pub blocks: u64,
}

// ---------------------------------------------------------------------------
// PeerSendBuffer
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct QueuedFrame {
    bytes: Bytes,
    cluster_budget: Option<ClusterQueueBudgetGuard>,
}

impl QueuedFrame {
    fn new(bytes: Bytes) -> Self {
        Self {
            bytes,
            cluster_budget: None,
        }
    }

    fn with_cluster_budget(bytes: Bytes, cluster_budget: ClusterQueueBudgetGuard) -> Self {
        Self {
            bytes,
            cluster_budget: Some(cluster_budget),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn into_bytes(self) -> Bytes {
        self.bytes
    }

    fn cluster_budgeted_bytes(&self) -> u64 {
        self.cluster_budget
            .as_ref()
            .map_or(0, |guard| guard.bytes())
    }
}

/// Bounded per-peer send buffer holding serialized frames awaiting
/// transmission.
///
/// ## Lifecycle
///
/// 1. Created via [`PeerSendBuffer::new`] with a [`SendBufferConfig`].
/// 2. Frames are queued with [`try_enqueue`](Self::try_enqueue); when the
///    buffer is full the caller receives `Backpressured` evidence.
/// 3. The I/O path pulls frames with [`dequeue`](Self::dequeue), which
///    releases capacity for subsequent enqueues.
/// 4. On peer close or circuit-breaker open, [`drain`](Self::drain) drops
///    all queued frames and resets `allocated`.
/// 5. After [`shutdown`](Self::shutdown), all further enqueues return
///    `Closed` evidence.
#[derive(Debug)]
pub struct PeerSendBuffer {
    /// Serialized frames queued for transmission.
    queue: VecDeque<QueuedFrame>,
    /// Current sum of all `Bytes` lengths in `queue`.
    allocated: u64,
    /// Maximum total bytes allowed across all queued frames.
    max_memory: u64,
    /// The full configuration (includes backpressure policy).
    config: SendBufferConfig,
    /// Whether the buffer has been shut down.
    shutdown: AtomicBool,
    /// Monotonic statistics counters.
    pub stats: PeerBufferStats,
}

impl PeerSendBuffer {
    /// Create a new bounded send buffer with the given configuration.
    pub fn new(config: &SendBufferConfig) -> Self {
        let validated = config.validated();
        Self {
            queue: VecDeque::new(),
            allocated: 0,
            max_memory: validated.max_memory,
            config: validated,
            shutdown: AtomicBool::new(false),
            stats: PeerBufferStats::default(),
        }
    }

    /// Try to enqueue a frame for transmission.
    ///
    /// Returns typed evidence for accepted, drop-oldest, backpressured, and
    /// shutdown decisions.
    pub fn try_enqueue(&mut self, frame: Bytes) -> SendAdmissionEvidence {
        self.try_enqueue_frame(QueuedFrame::new(frame), None)
    }

    /// Try to enqueue a frame after admitting its queued bytes against the
    /// unified governor `cluster_queues` budget.
    ///
    /// The buffer owns the budget guard while the frame remains queued.
    /// Dequeue, drop-oldest, drain, shutdown, and buffer drop release the
    /// charged bytes by dropping the queued frame.
    pub fn try_enqueue_with_cluster_budget(
        &mut self,
        frame: Bytes,
        governor: &Governor,
        admission_class: ClusterQueueAdmissionClass,
    ) -> SendAdmissionEvidence {
        let admission = admit_cluster_queue_budget(
            governor,
            frame.len() as u64,
            ClusterQueueAllocationKind::SendBuffer,
            admission_class,
        );
        let budget_pressure = admission.evidence.pressure_reason;
        let Some(guard) = admission.value else {
            return admission.evidence;
        };
        self.try_enqueue_frame(
            QueuedFrame::with_cluster_budget(frame, guard),
            budget_pressure,
        )
    }

    fn try_enqueue_frame(
        &mut self,
        frame: QueuedFrame,
        budget_pressure: Option<SendPressureReason>,
    ) -> SendAdmissionEvidence {
        if self.shutdown.load(Ordering::Acquire) {
            self.stats.rejected_shutdown.fetch_add(1, Ordering::Relaxed);
            return self
                .evidence(SendAdmissionOutcome::Closed, frame.len())
                .with_policy(SendAdmissionPolicy::Shutdown);
        }
        let frame_len = frame.len() as u64;
        if frame_len > self.max_memory {
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return self
                .evidence(SendAdmissionOutcome::Backpressured, frame.len())
                .with_policy(self.admission_policy());
        }
        if self.allocated + frame_len > self.max_memory {
            match self.config.backpressure_policy {
                BackpressurePolicy::Error => {
                    self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                    return self
                        .evidence(SendAdmissionOutcome::Backpressured, frame.len())
                        .with_policy(SendAdmissionPolicy::Error);
                }
                BackpressurePolicy::Block => {
                    self.stats.blocks.fetch_add(1, Ordering::Relaxed);
                    return self
                        .evidence(SendAdmissionOutcome::Backpressured, frame.len())
                        .with_policy(SendAdmissionPolicy::Block)
                        .with_wake(SendWakeEvidence::Unavailable);
                }
                BackpressurePolicy::DropOldest => {
                    let mut dropped = Vec::new();
                    while self.allocated + frame_len > self.max_memory {
                        let Some(front) = self.queue.pop_front() else {
                            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                            return self
                                .evidence(SendAdmissionOutcome::Backpressured, frame.len())
                                .with_policy(SendAdmissionPolicy::DropOldest)
                                .with_dropped(dropped);
                        };
                        let queue_depth_before = self.queue.len() + 1;
                        let byte_depth_before = self.allocated as usize;
                        let len = front.len() as u64;
                        self.allocated = self.allocated.saturating_sub(len);
                        dropped.push(DroppedSendEvidence::frame(
                            len as usize,
                            queue_depth_before,
                            byte_depth_before,
                        ));
                    }
                    let dropped_count = dropped.len() as u64;
                    if dropped_count > 0 {
                        self.stats
                            .dropped
                            .fetch_add(dropped_count, Ordering::Relaxed);
                    }
                    self.allocated += frame_len;
                    self.queue.push_back(frame);
                    self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
                    let evidence = self
                        .evidence(SendAdmissionOutcome::DroppedOldest, frame_len as usize)
                        .with_policy(SendAdmissionPolicy::DropOldest)
                        .with_dropped(dropped);
                    return attach_budget_pressure(evidence, budget_pressure);
                }
            }
        }
        self.allocated += frame_len;
        self.queue.push_back(frame);
        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
        let evidence = self
            .evidence(SendAdmissionOutcome::Accepted, frame_len as usize)
            .with_policy(self.admission_policy());
        attach_budget_pressure(evidence, budget_pressure)
    }

    /// Remove and return the next frame from the front of the buffer.
    ///
    /// Returns `None` if the buffer is empty.
    pub fn dequeue(&mut self) -> Option<Bytes> {
        let frame = self.queue.pop_front()?;
        self.allocated = self.allocated.saturating_sub(frame.len() as u64);
        Some(frame.into_bytes())
    }

    /// Drop all queued frames and reset allocated memory to zero.
    ///
    /// Increments `dropped` by the number of frames discarded.
    /// Does not change the shutdown state — use [`shutdown`](Self::shutdown)
    /// for that.
    pub fn drain(&mut self) {
        let count = self.queue.len() as u64;
        self.queue.clear();
        self.allocated = 0;
        if count > 0 {
            self.stats.dropped.fetch_add(count, Ordering::Relaxed);
        }
    }

    /// Evict the oldest frame from the buffer to free capacity for new
    /// messages under the [`BackpressurePolicy::DropOldest`] policy.
    ///
    /// Returns the number of bytes freed, or `None` if the buffer was empty.
    pub fn drop_oldest(&mut self) -> Option<u64> {
        let frame = self.queue.pop_front()?;
        let len = frame.len() as u64;
        self.allocated = self.allocated.saturating_sub(len);
        Some(len)
    }

    /// Shut down the buffer: mark it as closed and drain all queued frames.
    ///
    /// After this call, all further [`try_enqueue`](Self::try_enqueue) calls
    /// return `Closed` evidence.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.drain();
    }

    /// Return the number of frames currently queued.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Return `true` if the buffer has no queued frames.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Return the current allocated memory in bytes.
    pub fn allocated(&self) -> u64 {
        self.allocated
    }

    /// Return bytes in this buffer that are currently charged to the
    /// governor `cluster_queues` budget.
    pub fn cluster_budgeted_bytes(&self) -> u64 {
        self.queue
            .iter()
            .map(QueuedFrame::cluster_budgeted_bytes)
            .sum()
    }

    /// Return the configured maximum memory in bytes.
    pub fn max_memory(&self) -> u64 {
        self.max_memory
    }

    /// Return `true` if the buffer has been shut down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Return the size of the oldest queued frame in bytes, or `None`
    /// if the buffer is empty.
    pub fn oldest_frame_size(&self) -> Option<u64> {
        self.queue.front().map(|b| b.len() as u64)
    }

    /// Return the remaining capacity in bytes before the buffer is full.
    pub fn remaining_capacity(&self) -> u64 {
        self.max_memory.saturating_sub(self.allocated)
    }

    /// Return the configured backpressure policy.
    pub fn policy(&self) -> BackpressurePolicy {
        self.config.backpressure_policy
    }

    fn admission_policy(&self) -> SendAdmissionPolicy {
        match self.config.backpressure_policy {
            BackpressurePolicy::Error => SendAdmissionPolicy::Error,
            BackpressurePolicy::DropOldest => SendAdmissionPolicy::DropOldest,
            BackpressurePolicy::Block => SendAdmissionPolicy::Block,
        }
    }

    fn evidence(&self, outcome: SendAdmissionOutcome, requested: usize) -> SendAdmissionEvidence {
        SendAdmissionEvidence::new(outcome)
            .with_queue_depth(self.queue.len())
            .with_byte_depth(self.allocated as usize)
            .with_capacity(SendCapacityEvidence::new(
                SendCapacityClass::BufferMemory,
                self.allocated as usize,
                Some(requested),
                Some(self.max_memory as usize),
            ))
    }
}

fn attach_budget_pressure(
    evidence: SendAdmissionEvidence,
    pressure: Option<SendPressureReason>,
) -> SendAdmissionEvidence {
    match pressure {
        Some(reason) => evidence.with_pressure_reason(reason),
        None => evidence,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_cache_core::{BudgetCategory, GovernorConfig};

    const KB: u64 = MIN_SEND_BUFFER_MEMORY;

    fn cluster_only_governor(total_budget_bytes: u64) -> Governor {
        Governor::new(GovernorConfig {
            total_budget_bytes,
            data_cache_fraction: 0.0,
            meta_cache_fraction: 0.0,
            dirty_bytes_fraction: 0.0,
            inode_state_fraction: 0.0,
            cluster_queues_fraction: 1.0,
            misc_fraction: 0.0,
        })
        .unwrap()
    }

    // --- Enqueue / dequeue FIFO ordering ---

    #[test]
    fn enqueue_dequeue_fifo() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        let a = Bytes::from_static(b"hello");
        let b = Bytes::from_static(b"world");
        assert_eq!(buf.try_enqueue(a.clone()), Backpressure::Ok);
        assert_eq!(buf.try_enqueue(b.clone()), Backpressure::Ok);
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.allocated(), 10);
        assert_eq!(buf.dequeue(), Some(a));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), 5);
        assert_eq!(buf.dequeue(), Some(b));
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.allocated(), 0);
        assert_eq!(buf.dequeue(), None);
    }

    // --- Memory limit enforcement ---

    #[test]
    fn rejects_when_full() {
        // Use minimal buffer size (4 KiB) and large frames to test the limit
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        // Fill the buffer with two 2 KiB frames
        let half = Bytes::from(vec![0u8; (KB / 2) as usize]);
        assert_eq!(buf.try_enqueue(half.clone()), Backpressure::Ok);
        assert_eq!(buf.try_enqueue(half), Backpressure::Ok);
        // Buffer is now full (4096 bytes), next enqueue should reject
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"x")),
            Backpressure::PeerFull
        );
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.allocated(), KB);
    }

    #[test]
    fn enqueue_after_dequeue_frees_capacity() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let full = Bytes::from(vec![0u8; KB as usize]);
        assert_eq!(buf.try_enqueue(full), Backpressure::Ok);
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"x")),
            Backpressure::PeerFull
        );
        buf.dequeue(); // free all 4096 bytes
        assert_eq!(buf.allocated(), 0);
        assert_eq!(
            buf.try_enqueue(Bytes::from(vec![0u8; KB as usize])),
            Backpressure::Ok
        );
    }

    #[test]
    fn exact_fit_allows_enqueue() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let full = Bytes::from(vec![0u8; KB as usize]);
        assert_eq!(buf.try_enqueue(full), Backpressure::Ok);
        assert_eq!(buf.allocated(), KB);
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"x")),
            Backpressure::PeerFull
        );
    }

    #[test]
    fn full_buffer_rejection_reports_capacity_evidence_without_mutation() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::Error,
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(
            buf.try_enqueue(Bytes::from(vec![0u8; KB as usize])),
            Backpressure::Ok
        );

        let evidence = buf.try_enqueue(Bytes::from_static(b"x"));
        assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
        assert_eq!(evidence.policy, Some(SendAdmissionPolicy::Error));
        assert_eq!(
            evidence.capacity.unwrap().class,
            SendCapacityClass::BufferMemory
        );
        assert_eq!(evidence.queue_depth, Some(1));
        assert_eq!(evidence.byte_depth, Some(KB as usize));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), KB);
    }

    // --- Backpressure signal on full buffer ---

    #[test]
    fn backpressure_peer_full_does_not_mutate_queue() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let full = Bytes::from(vec![0u8; KB as usize]);
        assert_eq!(buf.try_enqueue(full), Backpressure::Ok);
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"d")),
            Backpressure::PeerFull
        );
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), KB);
        let snap = buf.stats.snapshot();
        assert_eq!(snap.rejected, 1);
        assert_eq!(snap.enqueued, 1);
    }

    // --- Drain clears all frames ---

    #[test]
    fn drain_clears_all_frames_and_resets_allocated() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.try_enqueue(Bytes::from_static(b"a"));
        buf.try_enqueue(Bytes::from_static(b"bb"));
        buf.try_enqueue(Bytes::from_static(b"ccc"));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.allocated(), 6);
        buf.drain();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.allocated(), 0);
        assert!(buf.is_empty());
        assert_eq!(buf.dequeue(), None);
    }

    #[test]
    fn drain_updates_dropped_counter() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.try_enqueue(Bytes::from_static(b"a"));
        buf.try_enqueue(Bytes::from_static(b"b"));
        buf.try_enqueue(Bytes::from_static(b"c"));
        buf.drain();
        assert_eq!(buf.stats.snapshot().dropped, 3);
    }

    #[test]
    fn cluster_budget_released_on_dequeue() {
        let governor = cluster_only_governor(10_000);
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());

        let evidence = buf.try_enqueue_with_cluster_budget(
            Bytes::from_static(b"frame"),
            &governor,
            ClusterQueueAdmissionClass::Normal,
        );

        assert_eq!(evidence.outcome, SendAdmissionOutcome::Accepted);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 5);
        assert_eq!(buf.cluster_budgeted_bytes(), 5);
        assert_eq!(buf.dequeue().unwrap(), Bytes::from_static(b"frame"));
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 0);
    }

    #[test]
    fn cluster_budget_released_on_drain() {
        let governor = cluster_only_governor(10_000);
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());

        assert_eq!(
            buf.try_enqueue_with_cluster_budget(
                Bytes::from_static(b"one"),
                &governor,
                ClusterQueueAdmissionClass::Normal
            )
            .outcome,
            SendAdmissionOutcome::Accepted
        );
        assert_eq!(
            buf.try_enqueue_with_cluster_budget(
                Bytes::from_static(b"two"),
                &governor,
                ClusterQueueAdmissionClass::Normal
            )
            .outcome,
            SendAdmissionOutcome::Accepted
        );
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 6);

        buf.drain();

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.allocated(), 0);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 0);
    }

    #[test]
    fn hard_cluster_pressure_refuses_non_critical_send_buffer() {
        let governor = cluster_only_governor(1_000);
        let _held = governor
            .admit(BudgetCategory::ClusterQueues, 950)
            .expect("seed hard pressure");
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());

        let evidence = buf.try_enqueue_with_cluster_budget(
            Bytes::from_static(b"x"),
            &governor,
            ClusterQueueAdmissionClass::Normal,
        );

        assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
        assert_eq!(buf.len(), 0);
        assert_eq!(governor.category_used(BudgetCategory::ClusterQueues), 950);
        assert!(matches!(
            evidence.pressure_reason,
            Some(SendPressureReason::ClusterQueues {
                pressure: crate::send_admission::ClusterQueuePressure::HardPressure,
                ..
            })
        ));
    }

    #[test]
    fn drain_on_empty_is_noop() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.drain();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.allocated(), 0);
        assert_eq!(buf.stats.snapshot().dropped, 0);
    }

    // --- Shutdown state ---

    #[test]
    fn shutdown_prevents_further_enqueue() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.try_enqueue(Bytes::from_static(b"data"));
        buf.shutdown();
        assert!(buf.is_shutdown());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.allocated(), 0);
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"more")),
            Backpressure::Shutdown
        );
    }

    #[test]
    fn shutdown_drains_and_counts_dropped() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.try_enqueue(Bytes::from_static(b"a"));
        buf.try_enqueue(Bytes::from_static(b"b"));
        buf.shutdown();
        assert_eq!(buf.stats.snapshot().dropped, 2);
    }

    // --- Counter correctness ---

    #[test]
    fn counters_accumulate_across_operations() {
        // Use KB half-slices so we can trigger reject with 3 half-KB frames
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let chunk = Bytes::from(vec![0u8; (KB / 2) as usize]); // 2048 bytes
        let small = Bytes::from(vec![0u8; (KB / 4) as usize]); // 1024 bytes
        buf.try_enqueue(chunk.clone()); // 2048 / 4096
        buf.try_enqueue(small.clone()); // 3072 / 4096
                                        // Next chunk (2048) would exceed: 3072 + 2048 = 5120 > 4096 -> reject
        assert_eq!(buf.try_enqueue(chunk), Backpressure::PeerFull);
        buf.dequeue(); // free 2048, now 1024 / 4096
        buf.try_enqueue(small.clone()); // 2048 / 4096
        buf.drain(); // 2 frames dropped
        let snap = buf.stats.snapshot();
        assert_eq!(snap.enqueued, 3);
        assert_eq!(snap.rejected, 1);
        assert_eq!(snap.dropped, 2);
    }

    // --- Zero / minimal max_memory ---

    #[test]
    fn minimal_memory_clamps_upward() {
        let config = SendBufferConfig {
            max_memory: 0,
            ..Default::default()
        }
        .validated();
        assert_eq!(config.max_memory, MIN_SEND_BUFFER_MEMORY);
        let mut buf = PeerSendBuffer::new(&config);
        let result = buf.try_enqueue(Bytes::from_static(b"x"));
        assert_eq!(result, Backpressure::Ok);
    }

    // --- SendBufferConfig validation ---

    #[test]
    fn config_below_minimum() {
        let config = SendBufferConfig {
            max_memory: 512,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        let config = config.validated();
        assert_eq!(config.max_memory, MIN_SEND_BUFFER_MEMORY);
    }

    #[test]
    fn config_above_maximum() {
        let config = SendBufferConfig {
            max_memory: 128 * 1_048_576,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        let config = config.validated();
        assert_eq!(config.max_memory, MAX_SEND_BUFFER_MEMORY);
    }

    #[test]
    fn config_default_is_valid() {
        let config = SendBufferConfig::default();
        assert!(config.validate().is_ok());
    }

    // --- Concurrent enqueue/dequeue simulation (single-threaded interleaving) ---

    #[test]
    fn interleaved_enqueue_dequeue_maintains_invariants() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let half = Bytes::from(vec![0u8; (KB / 2) as usize]); // 2048 bytes
        assert_eq!(buf.try_enqueue(half.clone()), Backpressure::Ok);
        assert_eq!(buf.try_enqueue(half.clone()), Backpressure::Ok);
        // Full: 4096 bytes
        assert_eq!(buf.dequeue(), Some(half.clone()));
        // Now 2048 bytes remaining
        assert_eq!(buf.try_enqueue(half.clone()), Backpressure::Ok);
        // Now 4096 bytes, full
        assert_eq!(buf.allocated(), KB);
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"X")),
            Backpressure::PeerFull
        );
        buf.drain();
        assert_eq!(buf.allocated(), 0);
        assert_eq!(buf.len(), 0);
    }

    // --- Stats snapshot ---

    #[test]
    fn stats_snapshot_reflects_current_state() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        buf.try_enqueue(Bytes::from_static(b"aaa"));
        buf.try_enqueue(Bytes::from_static(b"bbb"));
        let snap = buf.stats.snapshot();
        assert_eq!(snap.enqueued, 2);
        assert_eq!(snap.dropped, 0);
        assert_eq!(snap.rejected, 0);
        buf.drain();
        let snap = buf.stats.snapshot();
        assert_eq!(snap.dropped, 2);
    }

    // --- Default config provides usable buffer ---

    #[test]
    fn default_buffer_accepts_large_frames() {
        let mut buf = PeerSendBuffer::new(&SendBufferConfig::default());
        let big = Bytes::from(vec![0u8; 1024 * 1024]); // 1 MiB
        assert_eq!(buf.try_enqueue(big), Backpressure::Ok);
        assert_eq!(buf.allocated(), 1_048_576);
    }

    // --- Backpressure Display ---

    #[test]
    fn backpressure_display() {
        assert_eq!(Backpressure::Ok.to_string(), "ok");
        assert_eq!(Backpressure::PeerFull.to_string(), "peer send buffer full");
        assert_eq!(
            Backpressure::Shutdown.to_string(),
            "peer send buffer shut down"
        );
    }

    // --- remaining_capacity ---

    #[test]
    fn remaining_capacity_tracks_allocated() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(buf.remaining_capacity(), KB);
        let chunk = Bytes::from(vec![0u8; (KB / 2) as usize]); // 2048
        buf.try_enqueue(chunk);
        assert_eq!(buf.remaining_capacity(), KB / 2);
        buf.dequeue();
        assert_eq!(buf.remaining_capacity(), KB);
    }

    // --- BackpressurePolicy tests ---

    #[test]
    fn backpressure_policy_default_is_error() {
        assert_eq!(BackpressurePolicy::default(), BackpressurePolicy::Error);
    }

    #[test]
    fn config_with_drop_oldest_policy() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::DropOldest,
        };
        assert_eq!(config.backpressure_policy, BackpressurePolicy::DropOldest);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn config_with_block_policy() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::Block,
        };
        assert_eq!(config.backpressure_policy, BackpressurePolicy::Block);
    }

    // --- drop_oldest tests ---

    #[test]
    fn drop_oldest_evicts_front_frame() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        let a = Bytes::from(vec![0u8; 100]);
        let b = Bytes::from(vec![0u8; 200]);
        buf.try_enqueue(a.clone());
        buf.try_enqueue(b.clone());
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.allocated(), 300);

        let freed = buf.drop_oldest().unwrap();
        assert_eq!(freed, 100);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), 200);
        // The remaining frame should be b (the second enqueued).
        assert_eq!(buf.dequeue().unwrap().len(), 200);
    }

    #[test]
    fn drop_oldest_on_empty_returns_none() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(buf.drop_oldest(), None);
        assert_eq!(buf.allocated(), 0);
    }

    #[test]
    fn drop_oldest_frees_capacity_for_new_enqueue() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        // Fill completely
        buf.try_enqueue(Bytes::from(vec![0u8; KB as usize]));
        assert_eq!(buf.remaining_capacity(), 0);

        // Drop oldest frees 4096 bytes
        buf.drop_oldest();
        assert_eq!(buf.remaining_capacity(), KB);
        assert!(buf.is_empty());

        // Can enqueue again
        assert_eq!(buf.try_enqueue(Bytes::from_static(b"x")), Backpressure::Ok);
    }

    #[test]
    fn drop_oldest_try_enqueue_reports_dropped_frame_evidence() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::DropOldest,
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(
            buf.try_enqueue(Bytes::from(vec![0u8; KB as usize])),
            Backpressure::Ok
        );

        let evidence = buf.try_enqueue(Bytes::from_static(b"x"));
        assert_eq!(evidence.outcome, SendAdmissionOutcome::DroppedOldest);
        assert_eq!(evidence.policy, Some(SendAdmissionPolicy::DropOldest));
        assert_eq!(evidence.dropped.len(), 1);
        assert_eq!(evidence.dropped[0].bytes, Some(KB as usize));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), 1);
        assert_eq!(buf.stats.snapshot().dropped, 1);
        assert_eq!(buf.stats.snapshot().rejected, 0);
    }

    #[test]
    fn block_policy_reports_wait_unavailable_without_mutation() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::Block,
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(
            buf.try_enqueue(Bytes::from(vec![0u8; KB as usize])),
            Backpressure::Ok
        );

        let evidence = buf.try_enqueue(Bytes::from_static(b"x"));
        assert_eq!(evidence.outcome, SendAdmissionOutcome::Backpressured);
        assert_eq!(evidence.policy, Some(SendAdmissionPolicy::Block));
        assert_eq!(evidence.wake, SendWakeEvidence::Unavailable);
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.allocated(), KB);
        let stats = buf.stats.snapshot();
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.rejected, 0);
    }

    #[test]
    fn drop_oldest_maintains_fifo_after_eviction() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        buf.try_enqueue(Bytes::from_static(b"first"));
        buf.try_enqueue(Bytes::from_static(b"second"));
        buf.try_enqueue(Bytes::from_static(b"third"));

        // Evict oldest (first)
        let freed = buf.drop_oldest().unwrap();
        assert_eq!(freed, 5);

        // Remaining should be second, third in order
        assert_eq!(buf.dequeue().unwrap(), Bytes::from_static(b"second"));
        assert_eq!(buf.dequeue().unwrap(), Bytes::from_static(b"third"));
        assert!(buf.is_empty());
    }

    // --- oldest_frame_size tests ---

    #[test]
    fn oldest_frame_size_returns_front_length() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let mut buf = PeerSendBuffer::new(&config);
        assert_eq!(buf.oldest_frame_size(), None);

        buf.try_enqueue(Bytes::from_static(b"hello"));
        assert_eq!(buf.oldest_frame_size(), Some(5));

        buf.try_enqueue(Bytes::from_static(b"world!"));
        assert_eq!(buf.oldest_frame_size(), Some(5)); // still "hello"

        buf.dequeue();
        assert_eq!(buf.oldest_frame_size(), Some(6)); // "world!"
    }

    // --- blocks counter tests ---

    #[test]
    fn blocks_counter_in_snapshot() {
        let config = SendBufferConfig {
            max_memory: KB,
            ..Default::default()
        };
        let buf = PeerSendBuffer::new(&config);

        // Initially zero
        assert_eq!(buf.stats.snapshot().blocks, 0);

        // Increment blocks counter directly to simulate Block policy
        buf.stats.blocks.fetch_add(3, Ordering::Relaxed);
        assert_eq!(buf.stats.snapshot().blocks, 3);

        buf.stats.blocks.fetch_add(1, Ordering::Relaxed);
        assert_eq!(buf.stats.snapshot().blocks, 4);
    }

    #[test]
    fn blocks_counter_independent_of_rejected() {
        let config = SendBufferConfig {
            max_memory: KB,
            backpressure_policy: BackpressurePolicy::Error,
        };
        let mut buf = PeerSendBuffer::new(&config);
        buf.try_enqueue(Bytes::from(vec![0u8; KB as usize]));
        // This gets rejected
        assert_eq!(
            buf.try_enqueue(Bytes::from_static(b"x")),
            Backpressure::PeerFull
        );

        let snap = buf.stats.snapshot();
        assert_eq!(snap.rejected, 1);
        assert_eq!(snap.blocks, 0);

        // Increment blocks separately
        buf.stats.blocks.fetch_add(1, Ordering::Relaxed);
        let snap2 = buf.stats.snapshot();
        assert_eq!(snap2.rejected, 1);
        assert_eq!(snap2.blocks, 1);
    }
}
