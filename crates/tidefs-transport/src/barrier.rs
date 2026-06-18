// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Connection-level send-barrier for flush-completion synchronization.
//!
//! ## Purpose
//!
//! Provides a one-shot flush point that callers insert into the outbound send
//! pipeline. When the barrier marker is processed by the send drainer — after
//! all messages enqueued before the barrier have been dequeued and written to
//! the I/O path — the barrier's completion signal fires. This lets subsystems
//! (epoch-commit notifications, membership state updates, lease grants) know
//! when an entire batch has been delivered before taking the next coordination
//! step, without building ad-hoc completion tracking per subsystem.
//!
//! ## Ordering guarantee
//!
//! The barrier completes after all messages that were enqueued before the
//! barrier are dequeued from the priority scheduler and handed to the I/O
//! path. The barrier uses only oneshot channels for coordination and relies
//! on the existing transport session security boundary for integrity.
//!
//! ## Architecture
//!
//! ```text
//! Caller                           SendPipeline
//!   |                                    |
//!   +-- request_barrier() -> SendBarrier |
//!   |   (enqueues Barrier marker)        |
//!   |                                    +-- dequeue Frame, write
//!   |                                    +-- dequeue Frame, write
//!   |                                    +-- dequeue Barrier, fire oneshot
//!   |                                    |
//!   +-- wait() resolves                  |
//! ```

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::oneshot;

use crate::backpressure::SendSlot;
use crate::send_scheduler::SendPriority;

// ---------------------------------------------------------------------------
// OutboundItem
// ---------------------------------------------------------------------------

/// An item traveling through the outbound send pipeline.
///
/// Either a framed message ready for wire transmission, or a barrier marker
/// that fires a completion signal when the pipeline drains up to it.
#[derive(Debug)]
pub enum OutboundItem {
    /// A framed byte buffer with its send priority.
    Frame {
        /// Optional send-completion handle resolved after socket write.
        completion: Option<crate::send_completion::SendCompletion>,
        /// Priority class for scheduling.
        priority: SendPriority,
        /// Framed bytes (envelope header + payload).
        data: Vec<u8>,
        /// Optional backpressure send slot released after socket write.
        slot: Option<SendSlot>,
    },
    /// A barrier marker: fires `completion` when the pipeline dequeues it,
    /// signalling that all ahead-of-barrier frames have been handed to I/O.
    Barrier {
        /// Priority class for scheduling (typically the same class as the
        /// messages being guarded, so the barrier is not reordered past them).
        priority: SendPriority,
        /// Fired by the send drainer when this barrier is processed.
        completion: oneshot::Sender<()>,
    },
}

// ---------------------------------------------------------------------------
// SendBarrier
// ---------------------------------------------------------------------------

/// A handle to a pending send barrier.
///
/// Created by [`SendPipelineHandle::request_barrier`] (in
/// [`crate::outbound_send`]). The handle resolves when the barrier marker
/// has been processed by the send pipeline and all ahead-of-barrier messages
/// have been handed to the I/O path.
///
/// # Example
///
/// ```ignore
/// let mut barrier = handle.request_barrier(SendPriority::Control)?;
/// // ... enqueue more messages after the barrier if needed ...
/// barrier.wait().await?;
/// // All messages enqueued before `request_barrier` have been sent.
/// ```
#[derive(Debug)]
pub struct SendBarrier {
    /// Receives the completion signal when the barrier is processed.
    rx: oneshot::Receiver<()>,
    /// Number of outbound items known to be ahead of this barrier at creation
    /// time (informational; the barrier's position in the FIFO queue is the
    /// authoritative ordering guarantee).
    ahead_count: usize,
}

impl SendBarrier {
    #[allow(dead_code)]
    /// Create a new barrier handle.
    pub(crate) fn new(rx: oneshot::Receiver<()>, ahead_count: usize) -> Self {
        Self { rx, ahead_count }
    }

    /// Wait for the barrier to complete.
    ///
    /// Returns `Ok(())` when all ahead-of-barrier messages have been handed
    /// to the I/O path. Returns `Err(BarrierError::Cancelled)` if the
    /// pipeline shut down before the barrier was processed (e.g., connection
    /// closed, all handles dropped).
    pub async fn wait(&mut self) -> Result<(), BarrierError> {
        (&mut self.rx).await.map_err(|_| BarrierError::Cancelled)
    }

    /// Number of outbound items that were ahead of this barrier at creation
    /// time. This is a snapshot and may not reflect the exact state at
    /// resolution time (messages may have been enqueued after the barrier).
    pub fn ahead_count(&self) -> usize {
        self.ahead_count
    }

    /// Check whether the barrier has already completed, without blocking.
    pub fn try_wait(&mut self) -> Option<Result<(), BarrierError>> {
        match self.rx.try_recv() {
            Ok(()) => Some(Ok(())),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                Some(Err(BarrierError::Cancelled))
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// BarrierError
// ---------------------------------------------------------------------------

/// Error returned by [`SendBarrier::wait`] when the barrier cannot complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarrierError {
    /// The pipeline was shut down before the barrier marker was processed.
    Cancelled,
}

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "barrier cancelled: pipeline shut down"),
        }
    }
}

impl std::error::Error for BarrierError {}

// ---------------------------------------------------------------------------
// OutboundItemCounter
// ---------------------------------------------------------------------------

/// Atomic counter shared between [`SendPipelineHandle`] and the barrier
/// creation path. Incremented on every enqueue so that `request_barrier`
#[allow(dead_code)]
/// can snapshot the current queue depth.
#[derive(Debug, Default)]
pub(crate) struct OutboundItemCounter {
    count: AtomicUsize,
}

impl OutboundItemCounter {
    /// Increment the counter and return the previous value.
    #[allow(dead_code)]
    pub fn increment(&self) -> usize {
        self.count.fetch_add(1, Ordering::Relaxed)
    }

    /// Snapshot the current count without modifying it.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // SendBarrier tests
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn barrier_wait_resolves_when_sender_fired() {
        let (tx, rx) = oneshot::channel();
        let mut barrier = SendBarrier::new(rx, 0);

        // Not yet resolved
        assert!(barrier.try_wait().is_none());

        // Fire the sender
        tx.send(()).unwrap();

        // Now resolved
        let result = barrier.wait().await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn barrier_wait_returns_cancelled_when_sender_dropped() {
        let (tx, rx) = oneshot::channel::<()>();
        let mut barrier = SendBarrier::new(rx, 0);

        // Drop the sender without firing
        drop(tx);

        let result = barrier.wait().await;
        assert_eq!(result, Err(BarrierError::Cancelled));
    }

    #[tokio::test]
    async fn barrier_try_wait_returns_none_when_pending() {
        let (_tx, rx) = oneshot::channel::<()>();
        let mut barrier = SendBarrier::new(rx, 3);
        assert!(barrier.try_wait().is_none());
        assert_eq!(barrier.ahead_count(), 3);
    }

    #[test]
    fn barrier_error_display() {
        let e = BarrierError::Cancelled;
        assert!(format!("{e}").contains("cancelled"));
    }

    // -------------------------------------------------------------------
    // OutboundItemCounter tests
    // -------------------------------------------------------------------

    #[test]
    fn counter_increment_returns_previous_value() {
        let c = OutboundItemCounter::default();
        assert_eq!(c.increment(), 0);
        assert_eq!(c.increment(), 1);
        assert_eq!(c.snapshot(), 2);
    }

    #[test]
    fn counter_snapshot_is_consistent() {
        let c = OutboundItemCounter::default();
        for _ in 0..5 {
            c.increment();
        }
        assert_eq!(c.snapshot(), 5);
    }
}
