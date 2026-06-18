// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Bounded send queue with backpressure for transport dispatch.
//!
//! [`SendQueue`] buffers framed chunks before they are handed to a
//! transport backend. When the queue reaches its capacity, further
//! enqueue operations block until space is freed via [`drain`](SendQueue::drain).
//!
//! This provides natural backpressure: producers (object framers) are
//! throttled when the transport consumer is slow, preventing unbounded
//! memory growth.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

/// A bounded FIFO queue with blocking enqueue and batched drain.
///
/// # Example
///
/// ```ignore
/// use tidefs_send_stream::send_queue::SendQueue;
///
/// let queue = SendQueue::new(4);
/// queue.enqueue(1u32);
/// queue.enqueue(2u32);
/// assert_eq!(queue.len(), 2);
/// let drained: Vec<u32> = queue.drain();
/// assert_eq!(drained, vec![1, 2]);
/// assert!(queue.is_empty());
/// ```
pub struct SendQueue<T> {
    inner: Mutex<SendQueueInner<T>>,
    condvar: Condvar,
}

struct SendQueueInner<T> {
    queue: VecDeque<T>,
    capacity: usize,
}

impl<T> SendQueue<T> {
    /// Create a new send queue with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "SendQueue capacity must be at least 1");
        Self {
            inner: Mutex::new(SendQueueInner {
                queue: VecDeque::with_capacity(capacity),
                capacity,
            }),
            condvar: Condvar::new(),
        }
    }

    /// Enqueue an item, blocking if the queue is at capacity.
    ///
    /// This call will block until space is freed by a [`drain`](Self::drain)
    /// call on another thread.
    pub fn enqueue(&self, item: T) {
        let mut inner = self.inner.lock().unwrap();
        while inner.queue.len() >= inner.capacity {
            inner = self.condvar.wait(inner).unwrap();
        }
        inner.queue.push_back(item);
    }

    /// Try to enqueue an item without blocking.
    ///
    /// Returns `Ok(())` on success, or `Err(item)` when the queue is full.
    pub fn try_enqueue(&self, item: T) -> Result<(), T> {
        let mut inner = self.inner.lock().unwrap();
        if inner.queue.len() >= inner.capacity {
            return Err(item);
        }
        inner.queue.push_back(item);
        Ok(())
    }

    /// Drain all items from the queue, returning them in FIFO order.
    ///
    /// This frees capacity and notifies blocked [`enqueue`](Self::enqueue)
    /// callers.
    pub fn drain(&self) -> Vec<T> {
        let mut inner = self.inner.lock().unwrap();
        let drained: Vec<T> = inner.queue.drain(..).collect();
        // Notify all waiting enqueuers; we just opened up all capacity slots.
        if drained.len() == inner.capacity {
            self.condvar.notify_all();
        } else {
            self.condvar.notify_one();
        }
        drained
    }

    /// Returns the number of items currently in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    /// Returns `true` when the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.queue.is_empty()
    }

    /// Returns `true` when the queue is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.queue.len() >= inner.capacity
    }

    /// Returns the maximum number of items the queue can hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.lock().unwrap().capacity
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn new_queue_is_empty() {
        let q = SendQueue::<u32>::new(4);
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);
        assert_eq!(q.capacity(), 4);
    }

    #[test]
    fn enqueue_and_drain_preserves_order() {
        let q = SendQueue::new(4);
        q.enqueue(10u32);
        q.enqueue(20u32);
        q.enqueue(30u32);
        assert_eq!(q.len(), 3);
        assert!(!q.is_full());

        let drained = q.drain();
        assert_eq!(drained, vec![10, 20, 30]);
        assert!(q.is_empty());
        assert!(!q.is_full());
    }

    #[test]
    fn try_enqueue_succeeds_and_fails() {
        let q = SendQueue::new(2);
        assert!(q.try_enqueue(1u32).is_ok());
        assert!(q.try_enqueue(2u32).is_ok());
        assert!(q.is_full());
        assert_eq!(q.try_enqueue(3u32), Err(3));
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn drain_notifies_blocked_enqueuers() {
        let q = Arc::new(SendQueue::new(1));
        q.enqueue(100u32);
        assert!(q.is_full());

        let q_clone = Arc::clone(&q);
        let handle = thread::spawn(move || {
            q_clone.enqueue(200u32);
            200u32
        });

        // Give the spawned thread time to block on the full queue
        thread::sleep(std::time::Duration::from_millis(100));

        // Drain to unblock
        let drained = q.drain();
        assert_eq!(drained, vec![100]);

        let result = handle.join().unwrap();
        assert_eq!(result, 200);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn drain_on_empty_queue_returns_empty() {
        let q = SendQueue::<u32>::new(4);
        let drained = q.drain();
        assert!(drained.is_empty());
        assert!(q.is_empty());
    }

    #[test]
    fn multiple_producers_single_consumer() {
        let q = Arc::new(SendQueue::new(3));
        let mut handles = Vec::new();

        for i in 0..3 {
            let q_clone = Arc::clone(&q);
            handles.push(thread::spawn(move || {
                q_clone.enqueue(i);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert!(q.is_full());
        let mut drained = q.drain();
        drained.sort();
        assert_eq!(drained, vec![0, 1, 2]);
    }

    #[test]
    #[should_panic(expected = "capacity must be at least 1")]
    fn zero_capacity_panics() {
        let _q = SendQueue::<u32>::new(0);
    }

    #[test]
    fn len_is_empty_is_full_are_consistent() {
        let q = SendQueue::new(3);
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 0);

        q.enqueue(1u32);
        assert!(!q.is_empty());
        assert!(!q.is_full());
        assert_eq!(q.len(), 1);

        q.enqueue(2u32);
        q.enqueue(3u32);
        assert!(!q.is_empty());
        assert!(q.is_full());
        assert_eq!(q.len(), 3);
    }
}
