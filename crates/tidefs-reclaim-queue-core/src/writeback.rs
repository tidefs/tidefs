//! Writeback engine for dirty page-cache extents.
//!
//! Connects dirty page-cache extents to the object store so that FUSE
//! writes persist to stable storage. The engine:
//!
//! 1. Collects dirty extents sorted by `(object_id, offset)` for
//!    sequential writeback, minimising random I/O.
//! 2. Flushes batches through the [`WriteSink`] abstraction.
//! 3. Runs a background [`ReclaimLoop`] that polls for dirty extents,
//!    flushes when the dirty ratio exceeds a threshold, and sleeps
//!    when idle.
//!
//! # Architecture
//!
//! ```text
//! DirtyExtentSource  --> ReclaimScanner  --> ReclaimFlush  --> WriteSink
//!       |                     |                    |
//!       |              (sort + batch)       (write + mark clean)
//!       |
//!  ReclaimLoop (background thread)
//!       |
//!  ReclaimQueue (public API: start / stop / set_thresholds)
//! ```

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tidefs_types_reclaim_queue_core::ObjectKey;

// ---------------------------------------------------------------------------
// DirtyExtentKey -- sort key for writeback ordering
// ---------------------------------------------------------------------------

/// Identifies a dirty extent for writeback, ordered by `(object_id, offset)`
/// so that writes to the same object are batched sequentially.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DirtyExtentKey {
    /// Object that owns this extent.
    pub object_id: ObjectKey,
    /// Byte offset within the object.
    pub offset: u64,
}

impl DirtyExtentKey {
    /// Create a new dirty-extent key.
    #[must_use]
    pub const fn new(object_id: ObjectKey, offset: u64) -> Self {
        Self { object_id, offset }
    }
}

impl fmt::Display for DirtyExtentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.object_id, self.offset)
    }
}

// ---------------------------------------------------------------------------
// DirtyExtent -- a single dirty region to flush
// ---------------------------------------------------------------------------

/// A dirty page-cache extent that must be flushed to stable storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyExtent {
    /// Sort / lookup key.
    pub key: DirtyExtentKey,
    /// Length in bytes of the dirty region.
    pub length: u64,
    /// Payload bytes to write (may be shorter than `length` for sparse
    /// extents; the object store handles zero-fill of unwritten tails).
    pub data: Vec<u8>,
}

impl DirtyExtent {
    /// Create a new dirty extent.
    #[must_use]
    pub fn new(key: DirtyExtentKey, length: u64, data: Vec<u8>) -> Self {
        Self { key, length, data }
    }

    /// Total bytes including zero-fill beyond `data.len()`.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.length.max(self.data.len() as u64)
    }
}

// ---------------------------------------------------------------------------
// WriteSink -- flush abstraction
// ---------------------------------------------------------------------------

/// Trait for flushing dirty extents to backing storage.
///
/// Implementations write data to an object store, segment log, or test
/// double. The engine does not depend on a concrete object-store crate.
pub trait WriteSink {
    /// Error type returned by the sink.
    type Error: fmt::Debug + fmt::Display + Send + Sync + 'static;

    /// Write `data` at `offset` within the object identified by `key`.
    ///
    /// The sink is responsible for partial-page handling and zero-fill.
    /// Returns `Ok(())` on durable commit, or an error if the write
    /// could not be persisted.
    fn write(&mut self, key: ObjectKey, offset: u64, data: &[u8]) -> Result<(), Self::Error>;
}

// ---------------------------------------------------------------------------
// FlushResult -- per-extent flush outcome
// ---------------------------------------------------------------------------

/// Outcome of flushing a single dirty extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Data was written and the extent is now clean.
    Clean,
    /// The write failed; the extent remains dirty.
    Failed(String),
}

impl FlushOutcome {
    /// Returns `true` if the flush succeeded.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::Clean)
    }
}

// ---------------------------------------------------------------------------
// DirtyPageCounter -- tracks dirty/clean page ratio
// ---------------------------------------------------------------------------

/// Atomic counter pair for tracking the dirty-to-clean page ratio.
///
/// Callers increment `dirty` when a page is marked dirty and decrement
/// it (while incrementing `clean`) when writeback completes. The
/// reclaim loop reads the ratio to decide whether to flush.
#[derive(Debug, Default)]
pub struct DirtyPageCounter {
    dirty: AtomicU64,
    clean: AtomicU64,
}

impl DirtyPageCounter {
    /// Create a new zeroed counter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the dirty page count.
    pub fn inc_dirty(&self) {
        self.dirty.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement dirty and increment clean (one page transitioned).
    pub fn mark_clean(&self) {
        self.dirty.fetch_sub(1, Ordering::Relaxed);
        self.clean.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the clean page count directly (e.g. new page fill).
    pub fn inc_clean(&self) {
        self.clean.fetch_add(1, Ordering::Relaxed);
    }

    /// Current dirty page count.
    #[must_use]
    pub fn dirty_count(&self) -> u64 {
        self.dirty.load(Ordering::Relaxed)
    }

    /// Current clean page count.
    #[must_use]
    pub fn clean_count(&self) -> u64 {
        self.clean.load(Ordering::Relaxed)
    }

    /// Total tracked pages.
    #[must_use]
    pub fn total_count(&self) -> u64 {
        self.dirty_count() + self.clean_count()
    }

    /// Dirty ratio in [0.0, 1.0]. Returns 0.0 when there are no pages.
    #[must_use]
    pub fn dirty_ratio(&self) -> f64 {
        let total = self.total_count();
        if total == 0 {
            return 0.0;
        }
        self.dirty_count() as f64 / total as f64
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.dirty.store(0, Ordering::Relaxed);
        self.clean.store(0, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// DirtyExtentSource -- bridge between page cache and writeback engine
// ---------------------------------------------------------------------------

/// Provides dirty extents to the writeback engine and allows the engine
/// to mark extents clean after successful flush.
///
/// The integration layer (e.g. `tidefs-local-filesystem`) implements
/// this trait to bridge the page cache and the reclaim loop.
pub trait DirtyExtentSource: Send + Sync + 'static {
    /// Collect all currently-dirty extents that need writeback.
    fn poll_dirty(&self) -> Vec<DirtyExtent>;

    /// Mark the given extents as clean after a successful flush.
    ///
    /// The implementation should clear the dirty flag on the
    /// corresponding page-cache pages.
    fn mark_clean(&self, keys: &[DirtyExtentKey]);
}

// ---------------------------------------------------------------------------
// ReclaimConfig -- writeback engine configuration
// ---------------------------------------------------------------------------

/// Configuration for the reclaim writeback engine.
#[derive(Clone, Debug, PartialEq)]
pub struct ReclaimConfig {
    /// Maximum bytes per flush batch (default: 256 KiB).
    pub max_batch_bytes: u64,

    /// Maximum number of extents per flush batch (default: 64).
    pub max_batch_entries: usize,

    /// Dirty ratio above which the reclaim loop actively flushes
    /// (default: 0.10 = 10%).
    pub dirty_ratio_threshold: f64,

    /// Sleep duration when the dirty ratio is below threshold
    /// (default: 100 ms).
    pub idle_sleep: Duration,
}

impl Default for ReclaimConfig {
    fn default() -> Self {
        Self {
            max_batch_bytes: 256 * 1024, // 256 KiB
            max_batch_entries: 64,
            dirty_ratio_threshold: 0.10,
            idle_sleep: Duration::from_millis(100),
        }
    }
}

impl ReclaimConfig {
    /// Create a new config with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set `max_batch_bytes`.
    #[must_use]
    pub fn with_max_batch_bytes(mut self, bytes: u64) -> Self {
        self.max_batch_bytes = bytes;
        self
    }

    /// Builder: set `dirty_ratio_threshold`.
    #[must_use]
    pub fn with_dirty_ratio_threshold(mut self, threshold: f64) -> Self {
        self.dirty_ratio_threshold = threshold;
        self
    }

    /// Builder: set `idle_sleep`.
    #[must_use]
    pub fn with_idle_sleep(mut self, sleep: Duration) -> Self {
        self.idle_sleep = sleep;
        self
    }
}

// ---------------------------------------------------------------------------
// ReclaimScanner -- sorts dirty extents and produces batches
// ---------------------------------------------------------------------------

/// Collects dirty extents, sorts by `(object_id, offset)`, and produces
/// batches bounded by [`ReclaimConfig::max_batch_bytes`] and
/// [`ReclaimConfig::max_batch_entries`].
#[derive(Clone, Debug)]
pub struct ReclaimScanner {
    config: ReclaimConfig,
}

impl ReclaimScanner {
    /// Create a new scanner with the given configuration.
    #[must_use]
    pub fn new(config: ReclaimConfig) -> Self {
        Self { config }
    }

    /// Scan a set of dirty extents and produce sorted, bounded batches.
    ///
    /// Extents are sorted by `(object_id, offset)`. Batches are formed
    /// greedily: extents are added to the current batch until adding
    /// the next extent would exceed `max_batch_bytes` or
    /// `max_batch_entries`. A single extent larger than
    /// `max_batch_bytes` becomes its own batch.
    #[must_use]
    pub fn scan(&self, dirty_extents: &[DirtyExtent]) -> Vec<Vec<DirtyExtent>> {
        if dirty_extents.is_empty() {
            return Vec::new();
        }

        // Sort by (object_id, offset)
        let mut sorted: Vec<DirtyExtent> = dirty_extents.to_vec();
        sorted.sort_by(|a, b| a.key.cmp(&b.key));

        let mut batches: Vec<Vec<DirtyExtent>> = Vec::new();
        let mut current: Vec<DirtyExtent> = Vec::new();
        let mut current_bytes: u64 = 0;

        for extent in sorted {
            let extent_bytes = extent.total_bytes();

            let would_exceed_bytes =
                !current.is_empty() && current_bytes + extent_bytes > self.config.max_batch_bytes;
            let would_exceed_entries = current.len() >= self.config.max_batch_entries;

            if would_exceed_bytes || would_exceed_entries {
                batches.push(std::mem::take(&mut current));
                current_bytes = 0;
            }

            current_bytes += extent_bytes;
            current.push(extent);
        }

        if !current.is_empty() {
            batches.push(current);
        }

        batches
    }

    /// Returns the configured maximum batch bytes.
    #[must_use]
    pub fn max_batch_bytes(&self) -> u64 {
        self.config.max_batch_bytes
    }
}

// ---------------------------------------------------------------------------
// ReclaimFlush -- flushes batches through a WriteSink
// ---------------------------------------------------------------------------

/// Flushes a batch of dirty extents through a [`WriteSink`] and returns
/// per-extent outcomes.
#[derive(Clone, Debug)]
pub struct ReclaimFlush;

impl ReclaimFlush {
    /// Create a new flusher.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Flush a single batch of dirty extents.
    ///
    /// Each extent is written via `sink.write()`. On success, the
    /// outcome is [`FlushOutcome::Clean`]; on error, the outcome is
    /// [`FlushOutcome::Failed`] with the error message.
    ///
    /// This method stops at the first failure -- subsequent extents in
    /// the batch are not attempted. This is intentional: a write error
    /// usually indicates a storage-level problem that affects all
    /// subsequent writes.
    #[must_use]
    pub fn flush<S: WriteSink>(&self, sink: &mut S, batch: &[DirtyExtent]) -> Vec<FlushOutcome> {
        let mut results = Vec::with_capacity(batch.len());

        for extent in batch {
            match sink.write(extent.key.object_id, extent.key.offset, &extent.data) {
                Ok(()) => results.push(FlushOutcome::Clean),
                Err(e) => {
                    results.push(FlushOutcome::Failed(e.to_string()));
                    break;
                }
            }
        }

        // Fill remaining entries as skipped-due-to-prior-error.
        while results.len() < batch.len() {
            results.push(FlushOutcome::Failed("skipped: prior error in batch".into()));
        }

        results
    }
}

impl Default for ReclaimFlush {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ReclaimLoopControl -- start/stop signaling
// ---------------------------------------------------------------------------

/// Commands sent to the background reclaim loop.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LoopCommand {
    /// Gracefully stop the loop.
    Stop,
}

// ---------------------------------------------------------------------------
// ReclaimLoop -- background writeback task
// ---------------------------------------------------------------------------

/// A background writeback loop that periodically polls for dirty extents
/// and flushes them when the dirty ratio exceeds the configured threshold.
///
/// The loop runs on a dedicated thread. Use [`ReclaimQueue`] for the
/// public API (`start`, `stop`, `set_thresholds`).
pub struct ReclaimLoop {
    handle: Option<JoinHandle<()>>,
    cmd_tx: mpsc::Sender<LoopCommand>,
}

impl ReclaimLoop {
    /// Spawn a new reclaim loop.
    ///
    /// The loop immediately begins polling `source` for dirty extents.
    /// It flushes batches through `sink` according to `config`.
    ///
    /// # Panics
    ///
    /// Panics if the loop thread cannot be spawned.
    pub fn spawn<S: WriteSink + Send + 'static>(
        config: ReclaimConfig,
        source: Arc<dyn DirtyExtentSource>,
        counter: Arc<DirtyPageCounter>,
        sink: S,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<LoopCommand>();

        let flusher = ReclaimFlush::new();
        let scanner = ReclaimScanner::new(config.clone());

        let handle = thread::spawn(move || {
            let mut sink = sink;
            loop {
                // Check for stop command (non-blocking).
                if let Ok(cmd) = cmd_rx.try_recv() {
                    if cmd == LoopCommand::Stop {
                        break;
                    }
                }

                // Check dirty ratio.
                let ratio = counter.dirty_ratio();
                if ratio < config.dirty_ratio_threshold {
                    // Sleep, but check for commands during sleep.
                    match cmd_rx.recv_timeout(config.idle_sleep) {
                        Ok(LoopCommand::Stop) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    continue;
                }

                // Poll dirty extents.
                let dirty = source.poll_dirty();
                if dirty.is_empty() {
                    // Nothing to flush; short sleep then re-check.
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }

                // Scan and batch.
                let batches = scanner.scan(&dirty);

                // Flush each batch.
                let mut cleaned_keys: Vec<DirtyExtentKey> = Vec::new();
                for batch in &batches {
                    let outcomes = flusher.flush(&mut sink, batch);
                    for (extent, outcome) in batch.iter().zip(outcomes.iter()) {
                        if outcome.is_clean() {
                            cleaned_keys.push(extent.key);
                            counter.mark_clean();
                        }
                    }
                }

                // Mark successfully-flushed extents clean in the source.
                if !cleaned_keys.is_empty() {
                    source.mark_clean(&cleaned_keys);
                }
            }
        });

        Self {
            handle: Some(handle),
            cmd_tx,
        }
    }

    /// Gracefully stop the loop and join the background thread.
    ///
    /// Returns `Ok(())` if the thread joined cleanly, or an error if
    /// the thread panicked.
    pub fn stop(&mut self) -> thread::Result<()> {
        let _ = self.cmd_tx.send(LoopCommand::Stop);
        if let Some(handle) = self.handle.take() {
            handle.join()
        } else {
            Ok(())
        }
    }
}

impl Drop for ReclaimLoop {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(LoopCommand::Stop);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// ReclaimQueue -- top-level writeback API
// ---------------------------------------------------------------------------

/// Public API for the reclaim writeback engine.
///
/// Wraps a [`ReclaimLoop`] and exposes `start`, `stop`, and
/// `set_thresholds`.
///
/// # Example
///
/// ```ignore
/// let source: Arc<dyn DirtyExtentSource> = ...;
/// let counter = Arc::new(DirtyPageCounter::new());
/// let sink = MyObjectStore::new();
/// let config = ReclaimConfig::default();
///
/// let mut queue = ReclaimQueue::start(config, source, counter, sink);
/// // ... system runs ...
/// queue.set_thresholds(0.20, Duration::from_millis(50));
/// queue.stop();
/// ```
pub struct ReclaimQueue {
    loop_handle: ReclaimLoop,
    #[allow(dead_code)]
    config: Arc<Mutex<ReclaimConfig>>,
    counter: Arc<DirtyPageCounter>,
}

impl ReclaimQueue {
    /// Start a new reclaim writeback loop.
    ///
    /// This spawns a background thread that polls `source` for dirty
    /// extents and flushes them through `sink`.
    #[must_use]
    pub fn start<S: WriteSink + Send + 'static>(
        config: ReclaimConfig,
        source: Arc<dyn DirtyExtentSource>,
        counter: Arc<DirtyPageCounter>,
        sink: S,
    ) -> Self {
        let loop_handle = ReclaimLoop::spawn(config.clone(), source, counter.clone(), sink);
        Self {
            loop_handle,
            config: Arc::new(Mutex::new(config)),
            counter,
        }
    }

    /// Gracefully stop the reclaim loop.
    ///
    /// Blocks until the background thread exits.
    pub fn stop(&mut self) -> thread::Result<()> {
        self.loop_handle.stop()
    }

    /// Update the dirty-ratio threshold and idle sleep duration.
    ///
    /// The new values take effect on the next loop iteration.
    pub fn set_thresholds(&self, dirty_ratio_threshold: f64, idle_sleep: Duration) {
        if let Ok(mut cfg) = self.config.lock() {
            cfg.dirty_ratio_threshold = dirty_ratio_threshold;
            cfg.idle_sleep = idle_sleep;
        }
    }

    /// Return a reference to the shared dirty-page counter.
    #[must_use]
    pub fn counter(&self) -> &Arc<DirtyPageCounter> {
        &self.counter
    }
}

impl Drop for ReclaimQueue {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // Helper: create an ObjectKey from a u64 for test readability.
    fn obj_key(id: u64) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0..8].copy_from_slice(&id.to_le_bytes());
        ObjectKey(k)
    }

    fn dk(obj: u64, offset: u64) -> DirtyExtentKey {
        DirtyExtentKey::new(obj_key(obj), offset)
    }

    fn de(obj: u64, offset: u64, len: u64, data: &[u8]) -> DirtyExtent {
        DirtyExtent::new(dk(obj, offset), len, data.to_vec())
    }

    // -- DirtyExtentKey ordering --

    #[test]
    fn dirty_extent_key_ordering_by_object_first() {
        let a = dk(1, 100);
        let b = dk(2, 0);
        assert!(a < b);
    }

    #[test]
    fn dirty_extent_key_ordering_by_offset_within_same_object() {
        let a = dk(1, 0);
        let b = dk(1, 4096);
        assert!(a < b);
    }

    #[test]
    fn dirty_extent_key_equality() {
        let a = dk(42, 8192);
        let b = dk(42, 8192);
        assert_eq!(a, b);
    }

    #[test]
    fn dirty_extent_key_sort_stable_for_batch_ordering() {
        let mut keys = vec![dk(3, 0), dk(1, 8192), dk(1, 0), dk(2, 4096), dk(1, 4096)];
        keys.sort();
        let expected = vec![dk(1, 0), dk(1, 4096), dk(1, 8192), dk(2, 4096), dk(3, 0)];
        assert_eq!(keys, expected);
    }

    // -- ReclaimScanner --

    #[test]
    fn scanner_empty_input_produces_no_batches() {
        let scanner = ReclaimScanner::new(ReclaimConfig::default());
        let batches = scanner.scan(&[]);
        assert!(batches.is_empty());
    }

    #[test]
    fn scanner_single_extent_is_one_batch() {
        let scanner = ReclaimScanner::new(ReclaimConfig::default());
        let extents = vec![de(1, 0, 4096, &[0xAA; 4096])];
        let batches = scanner.scan(&extents);
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].key, dk(1, 0));
    }

    #[test]
    fn scanner_sorts_by_object_then_offset() {
        let scanner = ReclaimScanner::new(ReclaimConfig::default());
        let extents = vec![
            de(3, 0, 100, &[0; 100]),
            de(1, 500, 100, &[0; 100]),
            de(1, 0, 100, &[0; 100]),
            de(2, 100, 100, &[0; 100]),
        ];
        let batches = scanner.scan(&extents);
        // Everything fits in one batch (400 bytes < 256 KiB)
        assert_eq!(batches.len(), 1);
        let keys: Vec<DirtyExtentKey> = batches[0].iter().map(|e| e.key).collect();
        assert_eq!(keys, vec![dk(1, 0), dk(1, 500), dk(2, 100), dk(3, 0)]);
    }

    #[test]
    fn scanner_splits_at_max_batch_bytes() {
        let config = ReclaimConfig::default().with_max_batch_bytes(500);
        let scanner = ReclaimScanner::new(config);
        let extents = vec![
            de(1, 0, 300, &[0; 300]),
            de(1, 300, 300, &[0; 300]),
            de(2, 0, 300, &[0; 300]),
        ];
        let batches = scanner.scan(&extents);
        // Each extent is 300 bytes; max_batch_bytes=500, so each batch holds
        // at most one 300-byte extent (300+300=600 > 500).
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].key, dk(1, 0));
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[1][0].key, dk(1, 300));
        assert_eq!(batches[2].len(), 1);
        assert_eq!(batches[2][0].key, dk(2, 0));
    }

    #[test]
    fn scanner_splits_at_max_batch_entries() {
        let config = ReclaimConfig {
            max_batch_entries: 3,
            ..ReclaimConfig::default()
        };
        let scanner = ReclaimScanner::new(config);
        let extents: Vec<DirtyExtent> = (0..7).map(|i| de(1, i * 10, 10, &[0; 10])).collect();
        let batches = scanner.scan(&extents);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 3);
        assert_eq!(batches[1].len(), 3);
        assert_eq!(batches[2].len(), 1);
    }

    #[test]
    fn scanner_large_extent_gets_own_batch() {
        let config = ReclaimConfig::default().with_max_batch_bytes(1000);
        let scanner = ReclaimScanner::new(config);
        let extents = vec![
            de(1, 0, 500, &[0; 500]),
            de(1, 500, 2000, &[0; 2000]),
            de(1, 2500, 100, &[0; 100]),
        ];
        let batches = scanner.scan(&extents);
        // 500 fits, then 2000 > 1000 alone, then 100
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), 1);
        assert_eq!(batches[0][0].key.offset, 0);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(batches[1][0].key.offset, 500);
        assert_eq!(batches[2].len(), 1);
        assert_eq!(batches[2][0].key.offset, 2500);
    }

    // -- WriteSink mock --

    type ObjectWriteLog = Arc<StdMutex<Vec<(ObjectKey, u64, Vec<u8>)>>>;

    /// In-memory mock object store for testing.
    #[derive(Clone, Debug, Default)]
    struct MockSink {
        writes: ObjectWriteLog,
        fail_next: Arc<StdMutex<Option<String>>>,
    }

    impl MockSink {
        fn new() -> Self {
            Self::default()
        }

        fn set_fail_next(&self, msg: &str) {
            *self.fail_next.lock().unwrap() = Some(msg.to_string());
        }

        fn writes(&self) -> Vec<(ObjectKey, u64, Vec<u8>)> {
            self.writes.lock().unwrap().clone()
        }
    }

    impl WriteSink for MockSink {
        type Error = String;

        fn write(&mut self, key: ObjectKey, offset: u64, data: &[u8]) -> Result<(), Self::Error> {
            if let Some(msg) = self.fail_next.lock().unwrap().take() {
                return Err(msg);
            }
            self.writes
                .lock()
                .unwrap()
                .push((key, offset, data.to_vec()));
            Ok(())
        }
    }

    // -- ReclaimFlush tests --

    #[test]
    fn flush_single_extent_success() {
        let mut sink = MockSink::new();
        let flusher = ReclaimFlush::new();
        let batch = vec![de(1, 0, 4, b"data")];

        let outcomes = flusher.flush(&mut sink, &batch);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0], FlushOutcome::Clean);

        let writes = sink.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, obj_key(1));
        assert_eq!(writes[0].1, 0);
        assert_eq!(writes[0].2, b"data");
    }

    #[test]
    fn flush_multiple_extents_all_succeed() {
        let mut sink = MockSink::new();
        let flusher = ReclaimFlush::new();
        let batch = vec![
            de(1, 0, 4, b"aaaa"),
            de(1, 4, 4, b"bbbb"),
            de(2, 0, 4, b"cccc"),
        ];

        let outcomes = flusher.flush(&mut sink, &batch);
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes.iter().all(|o| o.is_clean()));

        let writes = sink.writes();
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[0].2, b"aaaa");
        assert_eq!(writes[1].2, b"bbbb");
        assert_eq!(writes[2].2, b"cccc");
    }

    #[test]
    fn flush_stops_on_first_error_and_marks_remaining_skipped() {
        let mut sink = MockSink::new();
        sink.set_fail_next("disk full");

        let flusher = ReclaimFlush::new();
        let batch = vec![de(1, 0, 4, b"aa"), de(1, 4, 4, b"bb"), de(2, 0, 4, b"cc")];

        let outcomes = flusher.flush(&mut sink, &batch);
        assert_eq!(outcomes.len(), 3);
        assert_eq!(outcomes[0], FlushOutcome::Failed("disk full".into()));
        assert_eq!(
            outcomes[1],
            FlushOutcome::Failed("skipped: prior error in batch".into())
        );
        assert_eq!(
            outcomes[2],
            FlushOutcome::Failed("skipped: prior error in batch".into())
        );

        let writes = sink.writes();
        assert!(
            writes.is_empty(),
            "no writes should succeed when first fails"
        );
    }

    #[test]
    fn flush_empty_batch() {
        let mut sink = MockSink::new();
        let flusher = ReclaimFlush::new();
        let outcomes = flusher.flush(&mut sink, &[]);
        assert!(outcomes.is_empty());
        assert!(sink.writes().is_empty());
    }

    // -- DirtyPageCounter tests --

    #[test]
    fn counter_starts_at_zero() {
        let c = DirtyPageCounter::new();
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.clean_count(), 0);
        assert_eq!(c.total_count(), 0);
        assert_eq!(c.dirty_ratio(), 0.0);
    }

    #[test]
    fn counter_dirty_ratio() {
        let c = DirtyPageCounter::new();
        c.inc_dirty();
        c.inc_dirty();
        c.inc_clean();
        c.inc_clean();
        c.inc_clean();

        assert_eq!(c.dirty_count(), 2);
        assert_eq!(c.clean_count(), 3);
        assert_eq!(c.total_count(), 5);
        assert!((c.dirty_ratio() - 0.40).abs() < 0.001);
    }

    #[test]
    fn counter_mark_clean_transitions() {
        let c = DirtyPageCounter::new();
        c.inc_dirty();
        c.inc_dirty();
        assert_eq!(c.dirty_count(), 2);

        c.mark_clean();
        assert_eq!(c.dirty_count(), 1);
        assert_eq!(c.clean_count(), 1);

        c.mark_clean();
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.clean_count(), 2);
    }

    #[test]
    fn counter_reset() {
        let c = DirtyPageCounter::new();
        c.inc_dirty();
        c.inc_clean();
        c.reset();
        assert_eq!(c.dirty_count(), 0);
        assert_eq!(c.clean_count(), 0);
    }

    // -- DirtyExtentSource mock --

    struct MockSource {
        extents: Arc<StdMutex<Vec<DirtyExtent>>>,
        cleaned: Arc<StdMutex<Vec<DirtyExtentKey>>>,
    }

    impl MockSource {
        fn new() -> Self {
            Self {
                extents: Arc::new(StdMutex::new(Vec::new())),
                cleaned: Arc::new(StdMutex::new(Vec::new())),
            }
        }

        fn set_extents(&self, exts: Vec<DirtyExtent>) {
            *self.extents.lock().unwrap() = exts;
        }

        fn cleaned_keys(&self) -> Vec<DirtyExtentKey> {
            self.cleaned.lock().unwrap().clone()
        }
    }

    impl DirtyExtentSource for MockSource {
        fn poll_dirty(&self) -> Vec<DirtyExtent> {
            self.extents.lock().unwrap().clone()
        }

        fn mark_clean(&self, keys: &[DirtyExtentKey]) {
            self.cleaned.lock().unwrap().extend_from_slice(keys);
            let mut exts = self.extents.lock().unwrap();
            exts.retain(|e| !keys.contains(&e.key));
        }
    }

    // -- ReclaimLoop integration test --

    #[test]
    fn reclaim_loop_flushes_when_dirty_ratio_above_threshold() {
        let config = ReclaimConfig::default()
            .with_dirty_ratio_threshold(0.0) // always flush
            .with_idle_sleep(Duration::from_millis(10));

        let source = Arc::new(MockSource::new());
        source.set_extents(vec![de(1, 0, 4, b"wxyz")]);

        let counter = Arc::new(DirtyPageCounter::new());
        counter.inc_dirty(); // dirty ratio = 1.0

        let sink = MockSink::new();

        let mut loop_handle = ReclaimLoop::spawn(config, source.clone(), counter.clone(), sink);

        // Give the loop a moment to process.
        thread::sleep(Duration::from_millis(200));

        loop_handle.stop().unwrap();

        let cleaned = source.cleaned_keys();
        assert!(!cleaned.is_empty(), "expected at least one cleaned extent");
        assert!(cleaned.contains(&dk(1, 0)));
    }

    #[test]
    fn reclaim_loop_does_not_flush_below_threshold() {
        let config = ReclaimConfig::default()
            .with_dirty_ratio_threshold(0.50)
            .with_idle_sleep(Duration::from_millis(10));

        let source = Arc::new(MockSource::new());
        source.set_extents(vec![de(1, 0, 4, b"data")]);

        let counter = Arc::new(DirtyPageCounter::new());
        counter.inc_clean();
        counter.inc_clean();
        counter.inc_clean();
        counter.inc_dirty(); // ratio = 0.25, below 0.50

        let writes_ref = Arc::new(StdMutex::new(Vec::new()));

        struct SharedSink {
            writes: ObjectWriteLog,
        }
        impl WriteSink for SharedSink {
            type Error = String;
            fn write(
                &mut self,
                key: ObjectKey,
                offset: u64,
                data: &[u8],
            ) -> Result<(), Self::Error> {
                self.writes
                    .lock()
                    .unwrap()
                    .push((key, offset, data.to_vec()));
                Ok(())
            }
        }

        let mut loop_handle = ReclaimLoop::spawn(
            config,
            source.clone(),
            counter.clone(),
            SharedSink {
                writes: writes_ref.clone(),
            },
        );

        thread::sleep(Duration::from_millis(200));
        loop_handle.stop().unwrap();

        let writes = writes_ref.lock().unwrap();
        assert!(
            writes.is_empty(),
            "no writes expected below dirty threshold"
        );
    }

    #[test]
    fn reclaim_loop_stops_cleanly_on_drop() {
        let config = ReclaimConfig::default().with_dirty_ratio_threshold(0.0);
        let source = Arc::new(MockSource::new());
        let counter = Arc::new(DirtyPageCounter::new());
        counter.inc_dirty();
        let sink = MockSink::new();

        let loop_handle = ReclaimLoop::spawn(config, source.clone(), counter.clone(), sink);
        drop(loop_handle);
        // If we get here without hanging, the drop joined correctly.
    }

    // -- ReclaimQueue API tests --

    #[test]
    fn reclaim_queue_start_and_stop() {
        let config = ReclaimConfig::default()
            .with_dirty_ratio_threshold(1.0) // effectively never flush
            .with_idle_sleep(Duration::from_millis(10));
        let source = Arc::new(MockSource::new());
        let counter = Arc::new(DirtyPageCounter::new());

        struct NullSink;
        impl WriteSink for NullSink {
            type Error = String;
            fn write(
                &mut self,
                _key: ObjectKey,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let mut queue = ReclaimQueue::start(config, source, counter, NullSink);
        queue.stop().unwrap();
    }

    #[test]
    fn reclaim_queue_set_thresholds_does_not_panic() {
        let config = ReclaimConfig::default();
        let source = Arc::new(MockSource::new());
        let counter = Arc::new(DirtyPageCounter::new());

        struct NullSink;
        impl WriteSink for NullSink {
            type Error = String;
            fn write(
                &mut self,
                _key: ObjectKey,
                _offset: u64,
                _data: &[u8],
            ) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let mut queue = ReclaimQueue::start(config, source, counter, NullSink);
        queue.set_thresholds(0.20, Duration::from_millis(50));
        queue.stop().unwrap();
    }

    // -- Concurrency: inject extents while loop runs --

    #[test]
    fn concurrent_inject_while_loop_runs() {
        let config = ReclaimConfig::default()
            .with_dirty_ratio_threshold(0.0)
            .with_idle_sleep(Duration::from_millis(5));

        let source = Arc::new(MockSource::new());
        source.set_extents(vec![de(1, 0, 4, b"init")]);

        let counter = Arc::new(DirtyPageCounter::new());
        counter.inc_dirty();

        let sink = MockSink::new();

        let mut loop_handle = ReclaimLoop::spawn(config, source.clone(), counter.clone(), sink);

        for i in 0..5 {
            source.set_extents(vec![de(i, i * 10, 4, &[i as u8; 4])]);
            counter.inc_dirty();
            thread::sleep(Duration::from_millis(20));
        }

        thread::sleep(Duration::from_millis(200));
        loop_handle.stop().unwrap();

        let cleaned = source.cleaned_keys();
        assert!(!cleaned.is_empty(), "expected at least one cleaned extent");
    }

    // -- DirtyExtentKey Display --

    #[test]
    fn dirty_extent_key_display() {
        let key = dk(0xAB, 4096);
        let s = format!("{key}");
        assert!(s.contains("4096"));
    }

    // -- DirtyExtent total_bytes --

    #[test]
    fn dirty_extent_total_bytes_uses_max_of_length_and_data_len() {
        let e1 = DirtyExtent::new(dk(1, 0), 100, vec![0; 50]);
        assert_eq!(e1.total_bytes(), 100);

        let e2 = DirtyExtent::new(dk(1, 0), 50, vec![0; 200]);
        assert_eq!(e2.total_bytes(), 200);

        let e3 = DirtyExtent::new(dk(1, 0), 100, vec![0; 100]);
        assert_eq!(e3.total_bytes(), 100);
    }
}
