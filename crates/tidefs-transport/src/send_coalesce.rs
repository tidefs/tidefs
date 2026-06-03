//! Transport outbound send coalescing: batches multiple outbound framed
//! messages destined for the same session and priority class into fewer
//! mpsc channel submissions, reducing per-frame syscall and scheduler
//! overhead under concurrent multi-node workloads.
//!
//! ## Architecture
//!
//! ```text
//! try_send(family, priority, payload) -> SendCoalescer::enqueue(session, priority, frame)
//!                                              |
//!                                              v
//!                                         Per-(session,priority) Batch
//!                                              |
//!                                              v
//!                                         CoalesceFlush on trigger
//!                                              |
//!                                              v
//!                                         mpsc channel -> SendPipeline -> TCP
//! ```
//!
//! ## Keying
//!
//! Batches are keyed by `(SessionId, SendPriority)`, so messages to
//! different sessions or priorities are never coalesced together.
//! Within a batch, frames are concatenated in enqueue order; the
//! receiver's framing decoder handles back-to-back frames natively
//! since each frame carries its own binary-schema envelope header.
//!
//! ## Flush triggers
//!
//! A batch is emitted when any of these conditions is met:
//!
//! 1. Byte threshold — the next enqueue would push total framed bytes
//!    past `max_batch_bytes`.
//! 2. Count threshold — the batch has accumulated `max_batch_messages`.
//! 3. Deadline — `batch_window` has elapsed since the first message was
//!    enqueued for that key.
//! 4. Explicit — caller invokes `flush_key()` or `flush_all()`.
//!
//! ## Configuration
//!
//! Batching is disabled by default (`CoalesceConfig::enabled = false`),
//! preserving existing individual-frame send behavior. Enable by setting
//! `enabled = true` and configuring the thresholds.
//!
//! ## Integration
//!
//! Inserted in the outbound send path between frame encoding and the
//! mpsc channel. When disabled, every enqueue immediately returns the
//! frame for direct submission (passthrough mode).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use crate::send_scheduler::SendPriority;
use crate::types::SessionId;

// ---------------------------------------------------------------------------
// CoalesceConfig
// ---------------------------------------------------------------------------

/// Configuration for the send coalescer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalesceConfig {
    /// Maximum bytes of concatenated framed payloads allowed in a single
    /// batch flush.
    pub max_batch_bytes: usize,
    /// Maximum number of framed messages allowed in a single batch.
    pub max_batch_messages: usize,
    /// Maximum time to wait after the first enqueue before flushing a batch.
    pub batch_window: Duration,
    /// Whether coalescing is enabled. When `false`, every enqueue immediately
    /// returns the frame for direct submission (passthrough).
    pub enabled: bool,
}

impl CoalesceConfig {
    /// Create a new enabled config.
    #[must_use]
    pub fn new(max_batch_bytes: usize, max_batch_messages: usize, batch_window: Duration) -> Self {
        Self {
            max_batch_bytes,
            max_batch_messages,
            batch_window,
            enabled: true,
        }
    }

    /// Config that disables coalescing (passthrough mode).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_batch_bytes: 0,
            max_batch_messages: 0,
            batch_window: Duration::ZERO,
            enabled: false,
        }
    }
}

impl Default for CoalesceConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl fmt::Display for CoalesceConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoalesceConfig {{ max_batch_bytes: {}, max_batch_messages: {}, batch_window: {:?}, enabled: {} }}",
            self.max_batch_bytes, self.max_batch_messages, self.batch_window, self.enabled
        )
    }
}

// ---------------------------------------------------------------------------
// CoalesceKey
// ---------------------------------------------------------------------------

/// Unique key for a coalescing batch: session identifier plus send priority.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CoalesceKey {
    /// Transport session identifier.
    pub session: SessionId,
    /// Send priority class.
    pub priority: SendPriority,
}

impl CoalesceKey {
    /// Create a new coalesce key.
    #[must_use]
    pub fn new(session: SessionId, priority: SendPriority) -> Self {
        Self { session, priority }
    }
}

impl fmt::Display for CoalesceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session={} prio={:?}", self.session.0, self.priority)
    }
}

// ---------------------------------------------------------------------------
// CoalesceBatch
// ---------------------------------------------------------------------------

/// Accumulated framed messages for a single (session, priority) key.
#[derive(Debug)]
struct CoalesceBatch {
    /// Framed message payloads (already envelope-encoded, ready for wire).
    frames: Vec<Vec<u8>>,
    /// Total bytes across all frames in this batch.
    total_bytes: usize,
    /// Instant of first enqueue (for deadline calculation).
    first_enqueue: Option<Instant>,
}

impl CoalesceBatch {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            total_bytes: 0,
            first_enqueue: None,
        }
    }

    fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    fn len(&self) -> usize {
        self.frames.len()
    }

    /// Drain all frames into a single concatenated byte vector.
    fn drain(&mut self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.total_bytes);
        for frame in self.frames.drain(..) {
            buf.extend_from_slice(&frame);
        }
        self.total_bytes = 0;
        self.first_enqueue = None;
        buf
    }
}

// ---------------------------------------------------------------------------
// CoalesceFlush
// ---------------------------------------------------------------------------

/// A flushed batch of coalesced frames, ready for submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoalesceFlush {
    /// The key that triggered this flush.
    pub key: CoalesceKey,
    /// Concatenated framed message bytes, in enqueue order.
    pub data: Vec<u8>,
    /// Number of messages in this batch.
    pub message_count: usize,
    /// Total bytes in this batch.
    pub total_bytes: usize,
}

// ---------------------------------------------------------------------------
// SendCoalescer
// ---------------------------------------------------------------------------

/// Batches outbound framed messages per (session, priority) key.
///
/// # Concurrency
///
/// Methods take `&mut self`; the caller is responsible for wrapping in
/// an appropriate synchronization primitive (e.g., `Mutex`).
///
/// # Example
///
/// ```ignore
/// let mut coalescer = SendCoalescer::new(CoalesceConfig::new(
///     65536, 64, Duration::from_micros(200),
/// ));
///
/// let key = CoalesceKey::new(session_id, SendPriority::Data);
/// if let Some(flush) = coalescer.enqueue(key, framed_bytes) {
///     tx.try_send((flush.key.priority, OutboundFrame::new(flush.data)))?;
/// }
/// ```
pub struct SendCoalescer {
    config: CoalesceConfig,
    batches: HashMap<CoalesceKey, CoalesceBatch>,
}

impl SendCoalescer {
    /// Create a new coalescer with the given configuration.
    #[must_use]
    pub fn new(config: CoalesceConfig) -> Self {
        Self {
            config,
            batches: HashMap::new(),
        }
    }

    /// Enqueue a framed message for a (session, priority) key.
    ///
    /// Returns `Some(CoalesceFlush)` if enqueuing triggered a flush (due to
    /// byte or count thresholds), so the caller can submit the batch
    /// immediately. Returns `None` if the frame was queued without
    /// triggering a flush.
    ///
    /// When coalescing is disabled (`config.enabled == false`), every
    /// enqueue immediately returns a single-frame `CoalesceFlush`
    /// (passthrough mode).
    #[must_use]
    pub fn enqueue(&mut self, key: CoalesceKey, frame: Vec<u8>) -> Option<CoalesceFlush> {
        if !self.config.enabled {
            let total = frame.len();
            return Some(CoalesceFlush {
                key,
                data: frame,
                message_count: 1,
                total_bytes: total,
            });
        }

        let now = Instant::now();
        let frame_len = frame.len();

        let batch = self.batches.entry(key).or_insert_with(CoalesceBatch::new);

        // Check if adding this frame would overflow the byte limit (and the
        // batch is non-empty — no point flushing an empty batch).
        let would_overflow =
            !batch.is_empty() && batch.total_bytes + frame_len > self.config.max_batch_bytes;

        if would_overflow {
            // Capture state before drain (drain clears the batch).
            let msg_count = batch.len();
            let total = batch.total_bytes;
            let drained = batch.drain();
            let flush = CoalesceFlush {
                key,
                data: drained,
                message_count: msg_count,
                total_bytes: total,
            };
            // Reset and add the new frame.
            *batch = CoalesceBatch::new();
            batch.first_enqueue = Some(now);
            batch.frames.push(frame);
            batch.total_bytes = frame_len;
            return Some(flush);
        }

        // Normal enqueue.
        if batch.first_enqueue.is_none() {
            batch.first_enqueue = Some(now);
        }
        batch.frames.push(frame);
        batch.total_bytes += frame_len;

        // Check count threshold.
        if batch.len() >= self.config.max_batch_messages {
            let msg_count = batch.len();
            let total = batch.total_bytes;
            let drained = batch.drain();
            return Some(CoalesceFlush {
                key,
                data: drained,
                message_count: msg_count,
                total_bytes: total,
            });
        }

        None
    }

    /// Flush the batch for a specific key, returning the concatenated data
    /// if the batch was non-empty.
    #[must_use]
    pub fn flush_key(&mut self, key: CoalesceKey) -> Option<CoalesceFlush> {
        let batch = self.batches.get_mut(&key)?;
        if batch.is_empty() {
            return None;
        }
        let msg_count = batch.len();
        let total = batch.total_bytes;
        let data = batch.drain();
        Some(CoalesceFlush {
            key,
            data,
            message_count: msg_count,
            total_bytes: total,
        })
    }

    /// Flush all batches whose deadlines have expired.
    ///
    /// Returns a list of `CoalesceFlush` events for expired batches.
    /// Non-expired batches are left untouched.
    #[must_use]
    pub fn flush_expired(&mut self) -> Vec<CoalesceFlush> {
        let now = Instant::now();
        let expired_keys: Vec<CoalesceKey> = self
            .batches
            .iter()
            .filter_map(|(&k, b)| {
                if let Some(first) = b.first_enqueue {
                    if now.duration_since(first) >= self.config.batch_window {
                        return Some(k);
                    }
                }
                None
            })
            .collect();

        expired_keys
            .into_iter()
            .filter_map(|key| self.flush_key(key))
            .collect()
    }

    /// Force-flush all batches, draining every key.
    ///
    /// Returns a list of `CoalesceFlush` events for all non-empty batches.
    #[must_use]
    pub fn flush_all(&mut self) -> Vec<CoalesceFlush> {
        let all_keys: Vec<CoalesceKey> = self.batches.keys().copied().collect();

        all_keys
            .into_iter()
            .filter_map(|key| self.flush_key(key))
            .collect()
    }

    /// Number of messages currently queued across all batches.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.batches.values().map(|b| b.len()).sum()
    }

    /// Number of active batches (keys with at least one queued frame).
    #[must_use]
    pub fn active_batches(&self) -> usize {
        self.batches.values().filter(|b| !b.is_empty()).count()
    }

    /// Whether all batches are empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.batches.values().all(|b| b.is_empty())
    }

    /// Return a reference to the current configuration.
    #[must_use]
    pub fn config(&self) -> &CoalesceConfig {
        &self.config
    }
}

impl fmt::Debug for SendCoalescer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendCoalescer")
            .field("config", &self.config)
            .field("batches", &self.batches.len())
            .field("total_queued", &self.total_queued())
            .finish()
    }
}

impl Default for SendCoalescer {
    fn default() -> Self {
        Self::new(CoalesceConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(id: u64) -> CoalesceKey {
        CoalesceKey::new(SessionId(id), SendPriority::Data)
    }

    fn make_config() -> CoalesceConfig {
        CoalesceConfig::new(65536, 64, Duration::from_millis(10))
    }

    // -------------------------------------------------------------------
    // CoalesceConfig
    // -------------------------------------------------------------------

    #[test]
    fn config_default_is_disabled() {
        let cfg = CoalesceConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.max_batch_bytes, 0);
        assert_eq!(cfg.max_batch_messages, 0);
        assert_eq!(cfg.batch_window, Duration::ZERO);
    }

    #[test]
    fn config_new_is_enabled() {
        let cfg = CoalesceConfig::new(1000, 10, Duration::from_millis(5));
        assert!(cfg.enabled);
        assert_eq!(cfg.max_batch_bytes, 1000);
        assert_eq!(cfg.max_batch_messages, 10);
        assert_eq!(cfg.batch_window, Duration::from_millis(5));
    }

    #[test]
    fn config_disabled_method() {
        let cfg = CoalesceConfig::disabled();
        assert!(!cfg.enabled);
    }

    #[test]
    fn config_display() {
        let cfg = CoalesceConfig::new(500, 5, Duration::from_micros(100));
        let s = format!("{cfg}");
        assert!(s.contains("500"));
        assert!(s.contains("5"));
    }

    // -------------------------------------------------------------------
    // CoalesceKey
    // -------------------------------------------------------------------

    #[test]
    fn key_equality() {
        let k1 = CoalesceKey::new(SessionId(1), SendPriority::Control);
        let k2 = CoalesceKey::new(SessionId(1), SendPriority::Control);
        let k3 = CoalesceKey::new(SessionId(2), SendPriority::Control);
        let k4 = CoalesceKey::new(SessionId(1), SendPriority::Bulk);

        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
    }

    #[test]
    fn key_display() {
        let k = CoalesceKey::new(SessionId(42), SendPriority::Data);
        let s = format!("{k}");
        assert!(s.contains("42"));
        assert!(s.contains("Data"));
    }

    // -------------------------------------------------------------------
    // SendCoalescer: disabled (passthrough)
    // -------------------------------------------------------------------

    #[test]
    fn disabled_passthrough_always_emits_single_frame() {
        let mut c = SendCoalescer::new(CoalesceConfig::disabled());
        let key = make_key(1);

        let flush = c.enqueue(key, b"frame1".to_vec()).unwrap();
        assert_eq!(flush.message_count, 1);
        assert_eq!(flush.data, b"frame1");
        assert_eq!(flush.key, key);

        let flush = c.enqueue(key, b"frame2".to_vec()).unwrap();
        assert_eq!(flush.message_count, 1);
        assert_eq!(flush.data, b"frame2");

        assert!(c.is_empty());
    }

    // -------------------------------------------------------------------
    // SendCoalescer: basic accumulation
    // -------------------------------------------------------------------

    #[test]
    fn single_frame_no_flush_below_thresholds() {
        let mut c = SendCoalescer::new(make_config());
        let key = make_key(1);

        let result = c.enqueue(key, b"hello".to_vec());
        assert!(result.is_none());
        assert_eq!(c.total_queued(), 1);
        assert_eq!(c.active_batches(), 1);
    }

    #[test]
    fn two_frames_no_flush_below_thresholds() {
        let mut c = SendCoalescer::new(make_config());
        let key = make_key(1);

        assert!(c.enqueue(key, b"a".to_vec()).is_none());
        assert!(c.enqueue(key, b"b".to_vec()).is_none());
        assert_eq!(c.total_queued(), 2);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: count-threshold flush
    // -------------------------------------------------------------------

    #[test]
    fn count_threshold_flush() {
        let cfg = CoalesceConfig::new(65536, 3, Duration::from_secs(60));
        let mut c = SendCoalescer::new(cfg);
        let key = make_key(1);

        // 2 frames: no flush.
        assert!(c.enqueue(key, b"a".to_vec()).is_none());
        assert!(c.enqueue(key, b"b".to_vec()).is_none());
        assert_eq!(c.total_queued(), 2);

        // 3rd frame triggers count flush.
        let flush = c.enqueue(key, b"c".to_vec()).unwrap();
        assert_eq!(flush.message_count, 3);
        assert_eq!(flush.key, key);
        assert!(c.is_empty());
    }

    // -------------------------------------------------------------------
    // SendCoalescer: byte-threshold flush
    // -------------------------------------------------------------------

    #[test]
    fn byte_threshold_flush() {
        let cfg = CoalesceConfig::new(20, 64, Duration::from_secs(60));
        let mut c = SendCoalescer::new(cfg);
        let key = make_key(1);

        // Frame 1: 10 bytes -> queued.
        assert!(c.enqueue(key, vec![0u8; 10]).is_none());
        // Frame 2: 8 bytes -> queued (total 18, under 20).
        assert!(c.enqueue(key, vec![1u8; 8]).is_none());
        // Frame 3: 5 bytes -> would exceed 20, flush previous 18 bytes.
        let flush = c.enqueue(key, vec![2u8; 5]).unwrap();
        assert_eq!(flush.total_bytes, 18);
        assert_eq!(flush.message_count, 2);
        // The 5-byte frame is now queued alone.
        assert_eq!(c.total_queued(), 1);
    }

    #[test]
    fn oversized_single_frame_queued_normally() {
        let cfg = CoalesceConfig::new(10, 64, Duration::from_secs(60));
        let mut c = SendCoalescer::new(cfg);
        let key = make_key(1);

        // Single frame that exceeds max_batch_bytes — queued normally
        // since we can't split a frame.
        let result = c.enqueue(key, vec![0u8; 100]);
        assert!(result.is_none());
        assert_eq!(c.total_queued(), 1);

        let flush = c.flush_key(key).unwrap();
        assert_eq!(flush.message_count, 1);
        assert_eq!(flush.total_bytes, 100);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: deadline flush
    // -------------------------------------------------------------------

    #[test]
    fn deadline_flush() {
        let cfg = CoalesceConfig::new(65536, 64, Duration::from_millis(10));
        let mut c = SendCoalescer::new(cfg);
        let key = make_key(1);

        assert!(c.enqueue(key, b"deadline".to_vec()).is_none());

        // Not expired yet.
        let expired = c.flush_expired();
        assert!(expired.is_empty());

        std::thread::sleep(Duration::from_millis(15));

        let expired = c.flush_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].message_count, 1);
        assert_eq!(expired[0].data, b"deadline");
        assert!(c.is_empty());
    }

    // -------------------------------------------------------------------
    // SendCoalescer: per-key isolation
    // -------------------------------------------------------------------

    #[test]
    fn per_key_isolation() {
        let cfg = CoalesceConfig::new(65536, 64, Duration::from_millis(10));
        let mut c = SendCoalescer::new(cfg);

        let k1 = make_key(1);
        let k2 = CoalesceKey::new(SessionId(1), SendPriority::Control);

        assert!(c.enqueue(k1, b"a".to_vec()).is_none());
        assert!(c.enqueue(k2, b"b".to_vec()).is_none());
        assert_eq!(c.active_batches(), 2);
        assert_eq!(c.total_queued(), 2);

        // Flush only k1.
        let f1 = c.flush_key(k1).unwrap();
        assert_eq!(f1.message_count, 1);
        assert_eq!(f1.data, b"a");

        // k2 still queued.
        assert_eq!(c.total_queued(), 1);
        let f2 = c.flush_key(k2).unwrap();
        assert_eq!(f2.data, b"b");
        assert!(c.is_empty());
    }

    #[test]
    fn per_key_counting_independent() {
        let cfg = CoalesceConfig::new(65536, 2, Duration::from_secs(60));
        let mut c = SendCoalescer::new(cfg);

        let k1 = make_key(1);
        let k2 = make_key(2);

        // k1: 2 frames triggers count flush; k2 unaffected.
        assert!(c.enqueue(k1, b"x".to_vec()).is_none());
        assert!(c.enqueue(k2, b"y".to_vec()).is_none());
        let flush = c.enqueue(k1, b"z".to_vec()).unwrap();
        assert_eq!(flush.key, k1);
        assert_eq!(flush.message_count, 2);

        // k2 still has 1 frame.
        assert_eq!(c.total_queued(), 1);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: flush_all
    // -------------------------------------------------------------------

    #[test]
    fn flush_all_drains_every_batch() {
        let cfg = CoalesceConfig::new(65536, 64, Duration::from_secs(999));
        let mut c = SendCoalescer::new(cfg);

        let k1 = make_key(1);
        let k2 = make_key(2);
        let k3 = CoalesceKey::new(SessionId(1), SendPriority::Control);

        assert!(c.enqueue(k1, b"a".to_vec()).is_none());
        assert!(c.enqueue(k2, b"b".to_vec()).is_none());
        assert!(c.enqueue(k3, b"c".to_vec()).is_none());

        let flushes = c.flush_all();
        assert_eq!(flushes.len(), 3);
        assert!(c.is_empty());

        // Verify all keys were flushed.
        let mut keys: Vec<CoalesceKey> = flushes.iter().map(|f| f.key).collect();
        keys.sort();
        let mut expected = vec![k1, k3, k2];
        expected.sort();
        assert_eq!(keys, expected);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: empty state
    // -------------------------------------------------------------------

    #[test]
    fn empty_coalescer_returns_none() {
        let mut c = SendCoalescer::new(make_config());
        let key = make_key(1);

        assert!(c.flush_key(key).is_none());
        assert!(c.flush_all().is_empty());
        assert!(c.flush_expired().is_empty());
        assert!(c.is_empty());
        assert_eq!(c.active_batches(), 0);
        assert_eq!(c.total_queued(), 0);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: config accessor
    // -------------------------------------------------------------------

    #[test]
    fn config_accessor() {
        let cfg = CoalesceConfig::new(500, 5, Duration::from_micros(100));
        let c = SendCoalescer::new(cfg.clone());
        assert_eq!(c.config(), &cfg);
    }

    // -------------------------------------------------------------------
    // SendCoalescer: multi-frame concatenation
    // -------------------------------------------------------------------

    #[test]
    fn flushed_data_is_concatenated_in_order() {
        let cfg = CoalesceConfig::new(65536, 4, Duration::from_secs(60));
        let mut c = SendCoalescer::new(cfg);
        let key = make_key(1);

        let frames: Vec<Vec<u8>> = (0..4).map(|i| format!("f{i:02}").into_bytes()).collect();

        for (i, f) in frames.iter().enumerate() {
            if i < 3 {
                assert!(c.enqueue(key, f.clone()).is_none());
            } else {
                // 4th triggers count flush.
                let flush = c.enqueue(key, f.clone()).unwrap();
                let expected: Vec<u8> = frames.iter().flatten().cloned().collect();
                assert_eq!(flush.data, expected);
                assert_eq!(flush.message_count, 4);
            }
        }
    }

    // -------------------------------------------------------------------
    // SendCoalescer: debug output
    // -------------------------------------------------------------------

    #[test]
    fn debug_output() {
        let mut c = SendCoalescer::new(make_config());
        let key = make_key(1);
        let _ = c.enqueue(key, b"x".to_vec());

        let s = format!("{c:?}");
        assert!(s.contains("SendCoalescer"));
        assert!(s.contains("batches"));
    }
}
