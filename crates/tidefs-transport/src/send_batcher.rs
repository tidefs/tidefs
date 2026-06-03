//! Transport send-side message byte batching.
//!
//! ## Purpose
//!
//! `SendBatcher` coalesces small outbound message payloads destined for the
//! same peer into accumulated byte buffers, flushing only when a configurable
//! byte threshold or time deadline is reached. This reduces per-enqueue
//! syscall overhead for chatty protocols (lease renewals, keepalive acks,
//! namespace invalidation notifications, small metadata updates).
//!
//! ## Architecture
//!
//! ```text
//! send(msg, peer) -> SendBatcher::enqueue(msg, peer)
//!                        |
//!                        v
//!                     Per-peer Batch (Vec<u8> + deadline)
//!                        |
//!                        v
//!                     BatchResult::Flushed on trigger
//!                        |
//!                        v
//!                     Per-peer FIFO send queue (#5793)
//! ```
//!
//! ## Flush triggers
//!
//! A batch is flushed when any of:
//! 1. Byte threshold -- the next enqueue would push total bytes past
//!    `max_batch_bytes`.
//! 2. Deadline -- `max_flush_interval` has elapsed since the first message
//!    was enqueued for that peer.
//! 3. Explicit -- caller invokes `flush_peer()` or `flush_all()`.
//!
//! ## Defaults
//!
//! | Parameter | Default | Rationale |
//! |---|---|---|
//! | `max_batch_bytes` | 65536 (64 KiB) | Balances syscall amortization against latency |
//! | `max_flush_interval` | 200 us | Low enough for latency-sensitive control messages |

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use crate::PeerId;

// ---------------------------------------------------------------------------
// SendBatchConfig
// ---------------------------------------------------------------------------

/// Configuration for the send-side byte batcher.
#[derive(Clone, Debug)]
pub struct SendBatchConfig {
    /// Maximum accumulated bytes before forcing a flush.
    pub max_batch_bytes: usize,
    /// Maximum time to hold a batch open since its first enqueue.
    pub max_flush_interval: Duration,
}

impl SendBatchConfig {
    /// Create a new config, validating that `max_batch_bytes` is nonzero.
    ///
    /// Returns `None` if `max_batch_bytes == 0`.
    pub fn new(max_batch_bytes: usize, max_flush_interval: Duration) -> Option<Self> {
        if max_batch_bytes == 0 {
            return None;
        }
        Some(Self {
            max_batch_bytes,
            max_flush_interval,
        })
    }
}

impl Default for SendBatchConfig {
    fn default() -> Self {
        Self {
            max_batch_bytes: 65536, // 64 KiB
            max_flush_interval: Duration::from_micros(200),
        }
    }
}

impl fmt::Display for SendBatchConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SendBatchConfig {{ max_batch_bytes: {}, max_flush_interval: {:?} }}",
            self.max_batch_bytes, self.max_flush_interval
        )
    }
}

// ---------------------------------------------------------------------------
// BatchResult
// ---------------------------------------------------------------------------

/// Outcome of enqueuing a message into the batcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchResult {
    /// The message was queued; no batch was flushed.
    Queued,
    /// The batch for `peer` was flushed, carrying `bytes` of accumulated
    /// payload.
    Flushed { peer: PeerId, bytes: Vec<u8> },
}

// ---------------------------------------------------------------------------
// Batch (internal per-peer state)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Batch {
    /// Accumulated payload bytes.
    buf: Vec<u8>,
    /// Deadline for this batch (first-enqueue time + max_flush_interval).
    deadline: Instant,
    /// Configured byte limit.
    max_bytes: usize,
}

impl Batch {
    fn new(first_payload: Vec<u8>, deadline: Instant, max_bytes: usize) -> Self {
        Self {
            buf: first_payload,
            deadline,
            max_bytes,
        }
    }

    /// Attempt to append `payload`. Returns `true` if it fit; `false` means
    /// the batch is over the byte limit and should be flushed before retry.
    fn try_append(&mut self, payload: &[u8]) -> bool {
        if self.buf.len() + payload.len() > self.max_bytes {
            return false;
        }
        self.buf.extend_from_slice(payload);
        true
    }

    /// Whether the deadline has elapsed.
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }
}

// ---------------------------------------------------------------------------
// SendBatcher
// ---------------------------------------------------------------------------

/// A per-peer byte accumulator that batches small outbound messages.
///
/// # Thread safety
///
/// All methods take `&self` and use an internal `std::sync::Mutex`. The
/// batcher is safe to share across threads -- for example, between the
/// transport send path and a periodic flush timer.
pub struct SendBatcher {
    inner: std::sync::Mutex<Inner>,
}

struct Inner {
    config: SendBatchConfig,
    batches: BTreeMap<PeerId, Batch>,
}

impl SendBatcher {
    /// Create a new batcher with the given configuration.
    pub fn new(config: SendBatchConfig) -> Self {
        Self {
            inner: std::sync::Mutex::new(Inner {
                config,
                batches: BTreeMap::new(),
            }),
        }
    }

    /// Enqueue a message payload for `peer`.
    ///
    /// Returns `BatchResult::Flushed` with the accumulated bytes if the
    /// enqueue caused the batch to exceed `max_batch_bytes` or the deadline
    /// expired. Otherwise returns `BatchResult::Queued`.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn enqueue(&self, peer: PeerId, payload: Vec<u8>) -> BatchResult {
        let mut inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        let now = Instant::now();
        let max_bytes = inner.config.max_batch_bytes;
        let flush_interval = inner.config.max_flush_interval;

        // If the payload alone exceeds the byte limit, flush immediately as
        // a single-message batch.
        if payload.len() > max_bytes {
            return BatchResult::Flushed {
                peer,
                bytes: payload,
            };
        }

        if let Some(batch) = inner.batches.get_mut(&peer) {
            // Check deadline expiry first.
            if batch.expired(now) {
                let drained =
                    std::mem::replace(batch, Batch::new(payload, now + flush_interval, max_bytes));
                return BatchResult::Flushed {
                    peer,
                    bytes: drained.buf,
                };
            }

            // Try to append.
            if batch.try_append(&payload) {
                return BatchResult::Queued;
            }

            // Batch full -- drain and start a new one with the new payload.
            let drained =
                std::mem::replace(batch, Batch::new(payload, now + flush_interval, max_bytes));
            return BatchResult::Flushed {
                peer,
                bytes: drained.buf,
            };
        }

        // No existing batch for this peer -- start one.
        inner
            .batches
            .insert(peer, Batch::new(payload, now + flush_interval, max_bytes));
        BatchResult::Queued
    }

    /// Flush a specific peer's pending batch, returning its accumulated bytes
    /// (if any).
    pub fn flush_peer(&self, peer: PeerId) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        inner.batches.remove(&peer).map(|b| b.buf)
    }

    /// Flush all pending batches and return per-peer accumulated bytes.
    ///
    /// Batches are returned in `BTreeMap` key order (deterministic increasing
    /// by `PeerId`).
    pub fn flush_all(&self) -> Vec<(PeerId, Vec<u8>)> {
        let mut inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        let peers: Vec<PeerId> = inner.batches.keys().copied().collect();
        peers
            .into_iter()
            .filter_map(|peer| inner.batches.remove(&peer).map(|b| (peer, b.buf)))
            .collect()
    }

    /// Flush all batches whose deadlines have expired.
    ///
    /// Returns per-peer accumulated bytes for expired batches. Non-expired
    /// batches are left untouched.
    pub fn flush_expired(&self) -> Vec<(PeerId, Vec<u8>)> {
        let mut inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        let now = Instant::now();
        let expired_peers: Vec<PeerId> = inner
            .batches
            .iter()
            .filter(|(_, b)| b.expired(now))
            .map(|(&k, _)| k)
            .collect();

        expired_peers
            .into_iter()
            .filter_map(|peer| inner.batches.remove(&peer).map(|b| (peer, b.buf)))
            .collect()
    }

    /// Number of peers with pending batches.
    pub fn active_peers(&self) -> usize {
        let inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        inner.batches.len()
    }

    /// Whether no batches are currently pending.
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        inner.batches.is_empty()
    }
}

impl fmt::Debug for SendBatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().expect("SendBatcher mutex poisoned");
        f.debug_struct("SendBatcher")
            .field("config", &inner.config)
            .field("batches", &inner.batches.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_message_exceeds_byte_limit_triggers_immediate_flush() {
        let config = SendBatchConfig::new(10, Duration::from_secs(60)).unwrap();
        let batcher = SendBatcher::new(config);
        // Payload larger than max_batch_bytes (10)
        let result = batcher.enqueue(1, vec![0u8; 20]);
        assert_eq!(
            result,
            BatchResult::Flushed {
                peer: 1,
                bytes: vec![0u8; 20],
            }
        );
    }

    #[test]
    fn multi_message_accumulation_under_byte_limit() {
        let config = SendBatchConfig::new(100, Duration::from_secs(60)).unwrap();
        let batcher = SendBatcher::new(config);

        // Two messages should queue without flushing.
        assert_eq!(batcher.enqueue(1, vec![1u8; 30]), BatchResult::Queued);
        assert_eq!(batcher.enqueue(1, vec![2u8; 30]), BatchResult::Queued);

        // Flush and verify both are accumulated.
        let flushed = batcher.flush_peer(1);
        assert!(flushed.is_some());
        let bytes = flushed.unwrap();
        assert_eq!(bytes.len(), 60);
    }

    #[test]
    fn byte_limit_triggers_flush_on_overflow() {
        let config = SendBatchConfig::new(50, Duration::from_secs(60)).unwrap();
        let batcher = SendBatcher::new(config);

        assert_eq!(batcher.enqueue(1, vec![1u8; 40]), BatchResult::Queued);
        // 40 + 20 = 60 > 50 -> flush the accumulated 40 bytes.
        let result = batcher.enqueue(1, vec![2u8; 20]);
        assert!(matches!(result, BatchResult::Flushed { peer: 1, .. }));
        if let BatchResult::Flushed { bytes, .. } = result {
            assert_eq!(bytes.len(), 40);
        }
        // The new 20-byte payload starts a new batch.
        let flushed = batcher.flush_peer(1);
        assert_eq!(flushed.unwrap().len(), 20);
    }

    #[test]
    fn deadline_driven_flush() {
        let config = SendBatchConfig::new(1000, Duration::from_millis(10)).unwrap();
        let batcher = SendBatcher::new(config);

        assert_eq!(batcher.enqueue(1, vec![1u8; 10]), BatchResult::Queued);

        // Wait past the deadline.
        std::thread::sleep(Duration::from_millis(15));

        // Next enqueue should flush the expired batch.
        let result = batcher.enqueue(1, vec![2u8; 10]);
        assert!(matches!(result, BatchResult::Flushed { peer: 1, .. }));
    }

    #[test]
    fn per_peer_isolation() {
        let config = SendBatchConfig::new(100, Duration::from_secs(60)).unwrap();
        let batcher = SendBatcher::new(config);

        assert_eq!(batcher.enqueue(1, vec![1u8; 30]), BatchResult::Queued);
        assert_eq!(batcher.enqueue(2, vec![2u8; 30]), BatchResult::Queued);

        // Flush peer 1 only.
        let p1 = batcher.flush_peer(1);
        assert!(p1.is_some());
        assert_eq!(p1.unwrap().len(), 30);

        // Peer 2 should still be pending.
        let p2 = batcher.flush_peer(2);
        assert!(p2.is_some());
        assert_eq!(p2.unwrap().len(), 30);

        // Peer 1 is now empty.
        assert!(batcher.flush_peer(1).is_none());
    }

    #[test]
    fn flush_all_drains_all_peers() {
        let config = SendBatchConfig::default();
        let batcher = SendBatcher::new(config);

        assert_eq!(batcher.enqueue(1, vec![1u8; 10]), BatchResult::Queued);
        assert_eq!(batcher.enqueue(2, vec![2u8; 20]), BatchResult::Queued);
        assert_eq!(batcher.enqueue(3, vec![3u8; 30]), BatchResult::Queued);

        let all = batcher.flush_all();
        assert_eq!(all.len(), 3);

        // Deterministic ordering by PeerId (BTreeMap).
        assert_eq!(all[0].0, 1);
        assert_eq!(all[1].0, 2);
        assert_eq!(all[2].0, 3);
        assert_eq!(all[0].1.len(), 10);
        assert_eq!(all[1].1.len(), 20);
        assert_eq!(all[2].1.len(), 30);

        // Batcher should be empty after flush_all.
        assert!(batcher.is_empty());
    }

    #[test]
    fn empty_batch_no_op() {
        let config = SendBatchConfig::default();
        let batcher = SendBatcher::new(config);

        assert!(batcher.flush_peer(42).is_none());
        assert!(batcher.flush_all().is_empty());
        assert!(batcher.flush_expired().is_empty());
        assert!(batcher.is_empty());
        assert_eq!(batcher.active_peers(), 0);
    }

    #[test]
    fn config_validation_rejects_zero_max_batch_bytes() {
        assert!(SendBatchConfig::new(0, Duration::from_millis(100)).is_none());
    }

    #[test]
    fn peer_ordering_determinism() {
        let config = SendBatchConfig::default();
        let batcher = SendBatcher::new(config);

        // Insert in non-sorted order.
        for peer in [5u64, 1, 3, 9, 2] {
            batcher.enqueue(peer, vec![peer as u8; 5]);
        }

        let all = batcher.flush_all();
        let peer_order: Vec<u64> = all.iter().map(|(p, _)| *p).collect();
        // BTreeMap guarantees sorted order.
        assert_eq!(peer_order, vec![1, 2, 3, 5, 9]);
    }

    #[test]
    fn flush_expired_only_drains_expired_batches() {
        let config = SendBatchConfig::new(1000, Duration::from_millis(10)).unwrap();
        let batcher = SendBatcher::new(config);

        // Enqueue to peer 1 -- its deadline starts now.
        assert_eq!(batcher.enqueue(1, vec![1u8; 10]), BatchResult::Queued);

        // Wait long enough for peer 1 to expire.
        std::thread::sleep(Duration::from_millis(15));

        // Enqueue to peer 2 after the sleep -- its deadline is still fresh.
        assert_eq!(batcher.enqueue(2, vec![2u8; 10]), BatchResult::Queued);

        let expired = batcher.flush_expired();
        let peers_flushed: Vec<u64> = expired.iter().map(|(p, _)| *p).collect();
        assert!(peers_flushed.contains(&1), "expected peer 1 to be flushed");
        assert!(
            !peers_flushed.contains(&2),
            "expected peer 2 not to be flushed (still fresh)"
        );

        // Peer 2 should still be queued.
        let p2 = batcher.flush_peer(2);
        assert!(p2.is_some());
    }
}
