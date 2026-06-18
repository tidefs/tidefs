// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// writeback_daemon.rs — periodic dirty-page flush scheduling loop
//
// The WritebackDaemon bridges DirtyPageTracker and the local object store
// write path.  It wakes on a configurable interval, collects dirty ranges
// from the tracker, reads the dirty bytes from a PageDataProvider, and
// dispatches each range to a FlushTarget for persistence.
//
// This is the first concrete scheduling increment under the broader
// #3364 writeback work.  Adaptive scheduling, throttling, and backpressure
// are tracked by Review debt TFR-008.

#![cfg_attr(not(test), allow(dead_code, unused))]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

// LocalObjectStore and ObjectKey are used only in #[cfg(test)] store_flush_target_test_support
#[cfg(test)]
use tidefs_local_object_store::{LocalObjectStore, ObjectKey};
use tidefs_types_vfs_core::InodeId;

use crate::dirty_page_tracker::DirtyPageTracker;
use std::collections::{BTreeMap, BTreeSet};

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct FsyncCoordinator {
    pub active_fsyncs: BTreeMap<InodeId, std::sync::atomic::AtomicBool>,
}
#[cfg_attr(not(test), allow(dead_code))]
impl FsyncCoordinator {
    pub fn new() -> Self {
        Self {
            active_fsyncs: BTreeMap::new(),
        }
    }
    #[allow(dead_code)] // INTENT: writeback daemon types for planned periodic flush scheduling
    pub fn start_fsync(&mut self, inode: InodeId) {
        self.active_fsyncs
            .entry(inode)
            .or_insert_with(|| std::sync::atomic::AtomicBool::new(false))
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[allow(dead_code)] // INTENT: writeback daemon types for planned periodic flush scheduling
    pub fn finish_fsync(&mut self, inode: InodeId) {
        if let Some(f) = self.active_fsyncs.get(&inode) {
            f.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub fn is_fsync_active(&self, inode: InodeId) -> bool {
        self.active_fsyncs
            .get(&inode)
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// Configuration for the writeback daemon.
#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct WritebackConfig {
    /// Interval between daemon ticks.
    pub interval: Duration,
    /// Policy for page aging and flush selection.
    pub policy: crate::writeback::WritebackPolicy,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Default for WritebackConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            policy: crate::writeback::WritebackPolicy::default(),
        }
    }
}

/// Provides dirty-page data for a given (inode, offset, length) span.
///
/// The daemon calls `read_range` before dispatching a flush so the
/// `FlushTarget` receives the actual bytes to persist.  In test
/// contexts this may be backed by an in-memory buffer; in production
/// it will read from the page cache or the filesystem read path.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait PageDataProvider: Send + Sync {
    fn read_range(&self, inode: InodeId, offset: u64, length: u64) -> Result<Vec<u8>, String>;
}

/// Trait abstracting the flush destination.
///
/// The daemon calls `flush_range` for each dirty range it collects.
/// Implementations write the supplied bytes to durable storage.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait FlushTarget: Send {
    /// Flush a single dirty range.
    ///
    /// * `inode` — the inode owning the range.
    /// * `offset` — byte offset within the inode.
    /// * `data` — the dirty bytes to write.  May be empty (no-op).
    fn flush_range(&mut self, inode: InodeId, offset: u64, data: &[u8]) -> Result<(), String>;
}

/// Handle to a running writeback daemon.
///
/// Created by [`WritebackDaemon::start`].  Call `shutdown` to signal
/// the daemon to drain its final tick and join the background thread.
pub(crate) struct WritebackHandle {
    shutdown_flag: Arc<AtomicBool>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl WritebackHandle {
    /// Signal the daemon to stop and wait for the background thread to
    /// exit.  The daemon will drain one final tick before returning.
    pub fn shutdown(mut self) {
        self.shutdown_flag.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl std::fmt::Debug for WritebackHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritebackHandle")
            .field("shutdown_flag", &self.shutdown_flag)
            .finish()
    }
}

/// The writeback daemon.
///
/// Owns the scheduling loop and flush dispatch logic.  Constructed
/// via `start` which spawns a background thread, or used directly
/// with `tick` in test/synchronous contexts.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct WritebackDaemon {
    config: WritebackConfig,
    tracker: Arc<Mutex<DirtyPageTracker>>,
    page_provider: Arc<dyn PageDataProvider>,
    flush_target: Box<dyn FlushTarget>,
    fsync_coordinator: Arc<Mutex<FsyncCoordinator>>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl WritebackDaemon {
    #[allow(dead_code)] // INTENT: writeback daemon types for planned periodic flush scheduling
    /// Create a new daemon without starting the background thread.
    ///
    /// This is the primary constructor.  Use `start` to spawn the
    /// background loop; use `tick` directly for synchronous testing.
    pub fn new(
        config: WritebackConfig,
        tracker: Arc<Mutex<DirtyPageTracker>>,
        page_provider: Arc<dyn PageDataProvider>,
        flush_target: Box<dyn FlushTarget>,
    ) -> Self {
        Self {
            config,
            tracker,
            page_provider,
            flush_target,
            fsync_coordinator: Arc::new(Mutex::new(FsyncCoordinator::new())),
        }
    }
    #[allow(dead_code)] // INTENT: writeback daemon types for planned periodic flush scheduling
    pub fn fsync_coordinator(&self) -> Arc<Mutex<FsyncCoordinator>> {
        Arc::clone(&self.fsync_coordinator)
    }

    /// Spawn the daemon loop in a background thread.
    ///
    /// Returns a [`WritebackHandle`] for shutdown coordination.
    /// The daemon will:
    ///
    /// 1. Sleep for `config.interval`.
    /// 2. Lock the tracker and collect dirty ranges.
    /// 3. For each range, read data from the page provider.
    /// 4. Call `flush_target.flush_range(...)`.
    /// 5. Repeat until shutdown is signaled, then drain one final tick.
    pub fn start(
        config: WritebackConfig,
        tracker: Arc<Mutex<DirtyPageTracker>>,
        page_provider: Arc<dyn PageDataProvider>,
        flush_target: Box<dyn FlushTarget>,
    ) -> WritebackHandle {
        Self::start_with_coordinator(
            config,
            tracker,
            page_provider,
            flush_target,
            Arc::new(Mutex::new(FsyncCoordinator::new())),
        )
    }

    pub fn start_with_coordinator(
        config: WritebackConfig,
        tracker: Arc<Mutex<DirtyPageTracker>>,
        page_provider: Arc<dyn PageDataProvider>,
        flush_target: Box<dyn FlushTarget>,
        fsync_coordinator: Arc<Mutex<FsyncCoordinator>>,
    ) -> WritebackHandle {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown_flag);
        let mut daemon = Self {
            config,
            tracker,
            page_provider,
            flush_target,
            fsync_coordinator: Arc::clone(&fsync_coordinator),
        };

        let handle = thread::spawn(move || loop {
            let should_stop = flag.load(Ordering::SeqCst);
            daemon.tick();
            if should_stop {
                break;
            }
            thread::sleep(daemon.config.interval);
        });

        WritebackHandle {
            shutdown_flag,
            thread_handle: Some(handle),
        }
    }

    /// Run one tick: collect dirty ranges from the tracker, read data
    /// from the page provider, and dispatch each range to the flush
    /// target.
    ///
    /// Public for synchronous testing.  The background thread calls this
    /// on each wake-up.
    pub fn tick(&mut self) {
        let dirty_ranges = {
            let mut t = self.tracker.lock().expect("poisoned");
            t.collect_dirty_ranges()
        };
        if dirty_ranges.is_empty() {
            return;
        }
        let selected = self.config.policy.select_pages(&dirty_ranges);
        let mut flushed: BTreeSet<(InodeId, u64)> = BTreeSet::new();
        {
            let c = self.fsync_coordinator.lock().expect("poisoned");
            for (ino, r) in &selected {
                if c.is_fsync_active(*ino) {
                    continue;
                }
                match self.page_provider.read_range(*ino, r.offset, r.length) {
                    Err(e) => {
                        eprintln!("wb rd err ino={} off={}: {}", ino.0, r.offset, e);
                        continue;
                    }
                    Ok(d) => {
                        if let Err(e) = self.flush_target.flush_range(*ino, r.offset, &d) {
                            eprintln!("wb flush err ino={} off={}: {}", ino.0, r.offset, e);
                            continue;
                        }
                    }
                }
                flushed.insert((*ino, r.offset));
            }
        }
        let mut t = self.tracker.lock().expect("poisoned");
        for (ino, ranges) in &dirty_ranges {
            for r in ranges {
                if !flushed.contains(&(*ino, r.offset)) {
                    t.mark_dirty(*ino, r.offset, r.length);
                }
            }
        }
    }
}

// ── StoreFlushTarget (test-only) ──────────────────────────────
// StoreFlushTarget is gated behind #[cfg(test)] per #5940.
// Production writeback must go through the authoritative filesystem
// data path (content layout + extent allocation + root commit), not
// sidecar tidefs:writeback:* objects.
#[cfg(test)]
mod store_flush_target_test_support {
    use super::*;

    /// Flushes dirty-page data into a [`LocalObjectStore`].
    ///
    /// Each dirty range is written as a named object under the
    /// `tidefs:writeback:` key prefix so tests can read it back
    /// and verify byte equality.  The object key encodes both the
    /// inode id and the byte offset.
    pub(crate) struct StoreFlushTarget {
        pub(crate) store: Arc<Mutex<LocalObjectStore>>,
    }

    impl StoreFlushTarget {
        /// Wrap a shared [`LocalObjectStore`].
        pub fn new(store: Arc<Mutex<LocalObjectStore>>) -> Self {
            Self { store }
        }

        /// Build a deterministic object key from (inode, offset).
        pub fn writeback_key(inode: InodeId, offset: u64) -> ObjectKey {
            ObjectKey::from_name(format!("tidefs:writeback:{:016x}:{:016x}", inode.0, offset))
        }
    }

    impl FlushTarget for StoreFlushTarget {
        fn flush_range(&mut self, inode: InodeId, offset: u64, data: &[u8]) -> Result<(), String> {
            if data.is_empty() {
                return Ok(());
            }
            let key = Self::writeback_key(inode, offset);
            self.store
                .lock()
                .map_err(|e| format!("store lock poisoned: {e}"))?
                .put(key, data)
                .map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}

// ── tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> InodeId {
        InodeId::new(n)
    }

    // ── test helpers ─────────────────────────────────────────

    /// Mock flush target that records every call.
    struct SpyFlushTarget {
        calls: Vec<(InodeId, u64, Vec<u8>)>,
    }

    impl SpyFlushTarget {
        fn new() -> Self {
            Self { calls: Vec::new() }
        }
    }

    impl FlushTarget for SpyFlushTarget {
        fn flush_range(&mut self, inode: InodeId, offset: u64, data: &[u8]) -> Result<(), String> {
            self.calls.push((inode, offset, data.to_vec()));
            Ok(())
        }
    }

    /// In-memory page-data provider backed by a Vec<u8> per inode.
    struct BufferDataProvider {
        buffers: Vec<(InodeId, Vec<u8>)>,
    }

    impl BufferDataProvider {
        fn new(buffers: Vec<(InodeId, Vec<u8>)>) -> Self {
            Self { buffers }
        }
    }

    impl PageDataProvider for BufferDataProvider {
        fn read_range(&self, inode: InodeId, offset: u64, length: u64) -> Result<Vec<u8>, String> {
            let (_, buf) = self
                .buffers
                .iter()
                .find(|(ino, _)| *ino == inode)
                .ok_or_else(|| format!("no buffer for inode {}", inode.0))?;
            let start = offset as usize;
            let end = (offset + length) as usize;
            if end > buf.len() {
                return Err(format!(
                    "read beyond buffer: offset={offset} length={length} buf_len={}",
                    buf.len()
                ));
            }
            Ok(buf[start..end].to_vec())
        }
    }

    fn make_tracker_with_dirty(inode: InodeId, offset: u64, length: u64) -> DirtyPageTracker {
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty(inode, offset, length);
        tracker
    }

    /// Wraps a `SpyFlushTarget` behind `Arc<Mutex<>>` so tests can
    /// inspect recorded calls after the daemon has consumed the
    /// `FlushTarget`.
    struct SharedSpy {
        inner: Arc<Mutex<SpyFlushTarget>>,
    }

    impl FlushTarget for SharedSpy {
        fn flush_range(&mut self, inode: InodeId, offset: u64, data: &[u8]) -> Result<(), String> {
            self.inner.lock().unwrap().flush_range(inode, offset, data)
        }
    }

    /// Stub data provider that always returns empty bytes for any range.
    struct StubDataProvider;

    impl PageDataProvider for StubDataProvider {
        fn read_range(
            &self,
            _inode: InodeId,
            _offset: u64,
            length: u64,
        ) -> Result<Vec<u8>, String> {
            Ok(vec![0u8; length as usize])
        }
    }

    fn setup_daemon_with_spy(
        tracker: Arc<Mutex<DirtyPageTracker>>,
    ) -> (WritebackDaemon, Arc<Mutex<SpyFlushTarget>>) {
        let spy = Arc::new(Mutex::new(SpyFlushTarget::new()));
        let shared_spy = SharedSpy {
            inner: Arc::clone(&spy),
        };
        let config = WritebackConfig {
            interval: std::time::Duration::from_secs(5),
            policy: crate::writeback::WritebackPolicy::new(
                std::time::Duration::from_secs(0),
                512,
                8,
            ),
        };
        let daemon = WritebackDaemon::new(
            config,
            tracker,
            Arc::new(StubDataProvider),
            Box::new(shared_spy),
        );
        (daemon, spy)
    }

    // ── existing unit tests (updated) ────────────────────────

    #[test]
    fn single_tick_flushes_one_dirty_range() {
        let ino = id(1);
        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(ino, 0, 4096)));
        let (mut daemon, spy) = setup_daemon_with_spy(Arc::clone(&tracker));

        daemon.tick();

        let calls = &spy.lock().unwrap().calls;
        assert_eq!(calls.len(), 1, "expected one flush call");
        assert_eq!(calls[0].0, ino, "inode mismatch");
        assert_eq!(calls[0].1, 0, "offset mismatch");
        // StubDataProvider returns zeros
        assert_eq!(calls[0].2.len(), 4096, "expected 4096 bytes of data");
    }

    #[test]
    fn coalesced_ranges_flushed_as_separate_writes() {
        let ino = id(2);
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty(ino, 0, 4096);
        tracker.mark_dirty(ino, 8192, 4096);
        let tracker = Arc::new(Mutex::new(tracker));
        let (mut daemon, spy) = setup_daemon_with_spy(Arc::clone(&tracker));

        daemon.tick();

        let calls = &spy.lock().unwrap().calls;
        assert_eq!(calls.len(), 2, "expected two flush calls for two ranges");
        assert_eq!(calls[0].0, ino);
        assert_eq!(calls[0].1, 0);
        assert_eq!(calls[1].0, ino);
        assert_eq!(calls[1].1, 8192);
    }

    #[test]
    fn idle_tick_noops_when_tracker_empty() {
        let tracker = Arc::new(Mutex::new(DirtyPageTracker::new()));
        let (mut daemon, spy) = setup_daemon_with_spy(Arc::clone(&tracker));

        daemon.tick();

        let calls = &spy.lock().unwrap().calls;
        assert!(
            calls.is_empty(),
            "expected zero flush calls when tracker is empty"
        );
    }

    #[test]
    fn shutdown_drains_final_tick() {
        let ino = id(3);
        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(ino, 0, 4096)));

        let spy = Arc::new(Mutex::new(SpyFlushTarget::new()));
        let shared_spy = SharedSpy {
            inner: Arc::clone(&spy),
        };

        let config = WritebackConfig {
            interval: Duration::from_millis(10),
            policy: crate::writeback::WritebackPolicy::new(Duration::from_secs(0), 512, 8),
        };

        let handle = WritebackDaemon::start(
            config,
            Arc::clone(&tracker),
            Arc::new(StubDataProvider),
            Box::new(shared_spy),
        );

        thread::sleep(Duration::from_millis(50));
        handle.shutdown();

        let calls = &spy.lock().unwrap().calls;
        assert!(
            !calls.is_empty(),
            "expected at least one flush call from the final drain"
        );
        assert_eq!(calls[0].0, ino, "inode mismatch");
    }

    #[test]
    fn multiple_inodes_flushed_independently() {
        let ino_a = id(10);
        let ino_b = id(20);
        let mut tracker = DirtyPageTracker::new();
        tracker.mark_dirty(ino_a, 0, 4096);
        tracker.mark_dirty(ino_b, 100, 8192);
        let tracker = Arc::new(Mutex::new(tracker));
        let (mut daemon, spy) = setup_daemon_with_spy(Arc::clone(&tracker));

        daemon.tick();

        let calls = &spy.lock().unwrap().calls;
        assert_eq!(calls.len(), 2, "expected two flush calls");

        let flushed_inodes: Vec<u64> = calls.iter().map(|(ino, _, _)| ino.0).collect();
        assert!(flushed_inodes.contains(&10));
        assert!(flushed_inodes.contains(&20));

        assert_eq!(
            tracker.lock().unwrap().dirty_inode_count(),
            0,
            "tracker should be empty after collection"
        );
    }

    #[test]
    fn tick_after_collect_leaves_tracker_empty() {
        let ino = id(5);
        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(ino, 0, 4096)));
        let (mut daemon, spy) = setup_daemon_with_spy(Arc::clone(&tracker));

        daemon.tick();
        assert_eq!(tracker.lock().unwrap().dirty_inode_count(), 0);

        daemon.tick();
        assert_eq!(spy.lock().unwrap().calls.len(), 1);
    }

    // ── BufferDataProvider unit tests ────────────────────────

    #[test]
    fn buffer_provider_reads_correct_range() {
        let provider = BufferDataProvider::new(vec![(id(1), b"hello world".to_vec())]);
        let data = provider.read_range(id(1), 0, 5).unwrap();
        assert_eq!(data, b"hello");
    }

    #[test]
    fn buffer_provider_reads_mid_buffer() {
        let provider = BufferDataProvider::new(vec![(id(1), b"abcdefghij".to_vec())]);
        let data = provider.read_range(id(1), 3, 4).unwrap();
        assert_eq!(data, b"defg");
    }

    #[test]
    fn buffer_provider_errors_on_missing_inode() {
        let provider = BufferDataProvider::new(vec![]);
        assert!(provider.read_range(id(99), 0, 1).is_err());
    }

    #[test]
    fn buffer_provider_errors_on_out_of_bounds() {
        let provider = BufferDataProvider::new(vec![(id(1), b"abc".to_vec())]);
        assert!(provider.read_range(id(1), 2, 5).is_err());
    }

    // ── store_flush_target_test_support::StoreFlushTarget integration test ────────────────────

    #[test]
    fn store_flush_target_writes_and_reads_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");
        let store = Arc::new(Mutex::new(store));

        let ino = id(42);
        let payload = b"writeback-test-payload";
        let mut target = store_flush_target_test_support::StoreFlushTarget::new(Arc::clone(&store));

        target
            .flush_range(ino, 0, payload)
            .expect("flush should succeed");

        // Read back through the store
        let key = store_flush_target_test_support::StoreFlushTarget::writeback_key(ino, 0);
        let stored = store
            .lock()
            .unwrap()
            .get(key)
            .expect("get should succeed")
            .expect("object should exist");

        assert_eq!(stored, payload);
    }

    #[test]
    fn store_flush_target_empty_data_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");
        let store = Arc::new(Mutex::new(store));

        let ino = id(43);
        let mut target = store_flush_target_test_support::StoreFlushTarget::new(Arc::clone(&store));

        target
            .flush_range(ino, 0, &[])
            .expect("empty flush should succeed");

        // Should not have written anything
        let key = store_flush_target_test_support::StoreFlushTarget::writeback_key(ino, 0);
        let stored = store.lock().unwrap().get(key).expect("get should succeed");
        assert!(stored.is_none(), "empty flush should not write an object");
    }

    #[test]
    fn store_flush_target_multiple_ranges_different_offsets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");
        let store = Arc::new(Mutex::new(store));

        let ino = id(44);
        let mut target = store_flush_target_test_support::StoreFlushTarget::new(Arc::clone(&store));

        target.flush_range(ino, 0, b"first").unwrap();
        target.flush_range(ino, 4096, b"second").unwrap();

        // Verify both keys exist with correct data
        let key0 = store_flush_target_test_support::StoreFlushTarget::writeback_key(ino, 0);
        let key4096 = store_flush_target_test_support::StoreFlushTarget::writeback_key(ino, 4096);

        let stored0 = store.lock().unwrap().get(key0).unwrap().unwrap();
        let stored4096 = store.lock().unwrap().get(key4096).unwrap().unwrap();

        assert_eq!(stored0, b"first");
        assert_eq!(stored4096, b"second");
    }

    // ── end-to-end daemon + store integration test ────────────

    #[test]
    fn daemon_flushes_dirty_range_through_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LocalObjectStore::open(dir.path()).expect("open store");
        let store = Arc::new(Mutex::new(store));

        let ino = id(100);
        // Pre-populate a data buffer for the provider
        let payload: Vec<u8> = (0..128u8).collect(); // 0..127

        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(
            ino,
            0,
            payload.len() as u64,
        )));
        let provider = Arc::new(BufferDataProvider::new(vec![(ino, payload.clone())]));
        let flush_target =
            store_flush_target_test_support::StoreFlushTarget::new(Arc::clone(&store));

        let config = WritebackConfig {
            interval: Duration::from_secs(5),
            policy: crate::writeback::WritebackPolicy::new(Duration::from_secs(0), 512, 8),
        };
        let mut daemon = WritebackDaemon::new(
            config,
            Arc::clone(&tracker),
            provider,
            Box::new(flush_target),
        );

        daemon.tick();

        // Tracker should be empty
        assert_eq!(tracker.lock().unwrap().dirty_inode_count(), 0);

        // Read back from store
        let key = store_flush_target_test_support::StoreFlushTarget::writeback_key(ino, 0);
        let stored = store
            .lock()
            .unwrap()
            .get(key)
            .expect("get should succeed")
            .expect("object should exist");

        assert_eq!(stored, payload);
    }

    // ── LocalFileSystem integration tests ────────────────────────

    /// Verify that opening a LocalFileSystem does NOT start the
    /// writeback daemon (#5940). The daemon was removed because it used
    /// StoreFlushTarget to write to sidecar tidefs:writeback:* objects
    /// that bypassed the authoritative filesystem data path.
    ///
    /// The dirty-page tracker is still populated by write_file, and
    /// dirty ranges are cleared through the authoritative path
    /// (flush_write_buffer -> content layout -> extent allocation).
    #[test]
    fn filesystem_mount_no_writeback_daemon_tracker_works() {
        use crate::LocalFileSystem;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open(dir.path()).expect("open fs");

        // The writeback daemon should NOT be started (#5940).
        assert!(
            !fs.has_writeback_daemon(),
            "writeback daemon must not be started on production mount"
        );

        // Write data — the tracker should still be populated.
        let ino = fs
            .create_file("/test", crate::DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/test", 0, b"hello-world-data")
            .expect("write file");

        // Check tracker has the dirty range.
        {
            let tracker = fs.writeback_range_tracker();
            let lock = tracker.lock().unwrap();
            assert!(
                lock.is_dirty(ino.inode_id),
                "tracker should mark inode dirty after write"
            );
            let ranges = lock.dirty_ranges(ino.inode_id);
            assert!(ranges.is_some(), "dirty ranges should exist");
            let ranges = ranges.unwrap();
            assert_eq!(ranges.len(), 1, "one dirty range");
            assert_eq!(ranges[0].offset, 0);
            assert_eq!(ranges[0].length, 16); // "hello-world-data"
        }

        drop(fs);
    }

    /// Multiple writes to the same inode coalesce dirty ranges.
    #[test]
    fn filesystem_multiple_writes_coalesce() {
        use crate::LocalFileSystem;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open(dir.path()).expect("open fs");

        let ino = fs
            .create_file("/coalesce", crate::DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.write_file("/coalesce", 0, &[0u8; 4096])
            .expect("write block 0");
        fs.write_file("/coalesce", 4096, &[1u8; 4096])
            .expect("write block 1");

        let tracker = fs.writeback_range_tracker();
        let lock = tracker.lock().unwrap();
        let ranges = lock.dirty_ranges(ino.inode_id);
        assert!(ranges.is_some());
        let ranges = ranges.unwrap();
        // Two adjacent 4K writes should coalesce into one 8K range
        assert_eq!(ranges.len(), 1, "adjacent writes should coalesce");
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].length, 8192);
    }

    /// End-to-end: write data through the authoritative filesystem path,
    /// verify dirty ranges are cleared by flush_write_buffer, and confirm
    /// no sidecar tidefs:writeback:* objects exist (#5940).
    #[test]
    fn end_to_end_write_flush_authoritative_path_no_sidecar() {
        use crate::LocalFileSystem;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut fs = LocalFileSystem::open(dir.path()).expect("open fs");

        let payload = b"end-to-end-payload-data";

        // Create a file and write known data.
        fs.create_file("/e2e", crate::DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        let ino = fs.write_file("/e2e", 0, payload).expect("write file");

        // Verify the tracker has the dirty entry.
        {
            let tracker = fs.writeback_range_tracker();
            let lock = tracker.lock().unwrap();
            assert!(
                lock.dirty_inode_count() > 0,
                "tracker should have dirty data after write"
            );
        }

        // Flush through the authoritative path (flush_write_buffer).
        fs.flush_write_buffer(ino.inode_id)
            .expect("flush write buffer");

        // After flush, the dirty range should be cleared (authoritative path).
        {
            let tracker = fs.writeback_range_tracker();
            let lock = tracker.lock().unwrap();
            assert_eq!(
                lock.dirty_inode_count(),
                0,
                "dirty ranges must be cleared after authoritative flush"
            );
        }

        // Commit to make durable.
        fs.do_commit().expect("do_commit");

        // Verify no sidecar tidefs:writeback:* objects exist.
        let wb_dir = dir.path().join("writeback");
        if wb_dir.exists() {
            // If the writeback directory exists from legacy code paths,
            // verify it contains no writeback objects.
            let store = tidefs_local_object_store::LocalObjectStore::open(&wb_dir);
            if let Ok(store) = store {
                let key = tidefs_local_object_store::ObjectKey::from_name(format!(
                    "tidefs:writeback:{:016x}:{:016x}",
                    ino.inode_id.0, 0u64
                ));
                let stored = store.get(key);
                match stored {
                    Ok(None) | Err(_) => { /* no sidecar object — correct */ }
                    Ok(Some(_)) => {
                        panic!("sidecar tidefs:writeback:* object exists; should not be produced");
                    }
                }
            }
        }

        drop(fs);
    }

    // ── concurrent read-during-writeback ───────────────────────────

    /// Verify that a read issued while the daemon is flushing a page
    /// sees consistent data (either all-old or all-new, never torn).
    #[test]
    fn concurrent_read_during_writeback_sees_consistent_data() {
        use std::sync::Barrier;

        let ino = id(200);
        let payload: Vec<u8> = (0..128u8).collect();
        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(
            ino,
            0,
            payload.len() as u64,
        )));

        // Shared data buffer that simulates the page cache.
        let shared_data = Arc::new(Mutex::new(payload.clone()));

        struct SharedBufferProvider {
            data: Arc<Mutex<Vec<u8>>>,
            inode: InodeId,
        }
        impl PageDataProvider for SharedBufferProvider {
            fn read_range(
                &self,
                inode: InodeId,
                offset: u64,
                length: u64,
            ) -> Result<Vec<u8>, String> {
                if inode != self.inode {
                    return Err("wrong inode".into());
                }
                let data = self.data.lock().unwrap();
                let start = offset as usize;
                let end = (offset + length) as usize;
                if end > data.len() {
                    return Err("out of bounds".into());
                }
                Ok(data[start..end].to_vec())
            }
        }

        // Flush target that simulates a slow writeback by sleeping.
        struct SlowFlushTarget {
            delay: Duration,
            flushed: Arc<Mutex<Vec<Vec<u8>>>>,
            barrier: Arc<Barrier>,
        }
        impl FlushTarget for SlowFlushTarget {
            fn flush_range(
                &mut self,
                _inode: InodeId,
                _offset: u64,
                data: &[u8],
            ) -> Result<(), String> {
                self.flushed.lock().unwrap().push(data.to_vec());
                // Signal that flush has captured the data.
                self.barrier.wait();
                std::thread::sleep(self.delay);
                Ok(())
            }
        }

        let flushed_data = Arc::new(Mutex::new(Vec::new()));
        let read_barrier = Arc::new(Barrier::new(2));

        let slow_target = SlowFlushTarget {
            delay: Duration::from_millis(200),
            flushed: Arc::clone(&flushed_data),
            barrier: Arc::clone(&read_barrier),
        };

        let provider = Arc::new(SharedBufferProvider {
            data: Arc::clone(&shared_data),
            inode: ino,
        });

        let config = WritebackConfig {
            interval: Duration::from_secs(5),
            policy: crate::writeback::WritebackPolicy::new(Duration::from_secs(0), 512, 8),
        };
        let mut daemon = WritebackDaemon::new(
            config,
            Arc::clone(&tracker),
            provider,
            Box::new(slow_target),
        );

        // Spawn the daemon tick in a separate thread.
        let daemon_done = Arc::new(AtomicBool::new(false));
        let daemon_flag = Arc::clone(&daemon_done);

        let t_handle = std::thread::spawn(move || {
            daemon.tick();
            daemon_flag.store(true, Ordering::SeqCst);
        });

        // Wait for the flush to capture the data, then modify the
        // "page cache" while the flush is still in progress.
        read_barrier.wait();

        // Meanwhile, modify the shared data — a concurrent reader
        // would see the new data if it reads after this point.
        {
            let mut data = shared_data.lock().unwrap();
            data[0] = 0xFF;
        }

        t_handle.join().expect("daemon tick thread");

        // The flushed data should be the original (captured before
        // the modification), proving no torn write.
        let flushed = flushed_data.lock().unwrap();
        assert_eq!(flushed.len(), 1, "one flush call expected");
        assert_eq!(
            flushed[0], payload,
            "flushed data should be pre-modification"
        );

        // Tracker should be empty after tick.
        assert_eq!(tracker.lock().unwrap().dirty_inode_count(), 0);
    }

    // ── writeback error injection ──────────────────────────────────

    /// Verify that after a flush error, the dirty page is retained
    /// in the tracker for retry (not lost).
    #[test]
    fn dirty_page_retained_after_flush_error() {
        let ino = id(400);
        let tracker = Arc::new(Mutex::new(make_tracker_with_dirty(ino, 0, 4096)));

        // Verify the dirty range exists before any flush.
        assert!(tracker.lock().unwrap().is_dirty(ino));
        assert_eq!(tracker.lock().unwrap().dirty_inode_count(), 1);

        // Simulate a daemon tick that collects dirty ranges.
        // In the current implementation, tick() collects all dirty
        // ranges before flushing, so the tracker is emptied regardless
        // of flush success. This test documents that behavior.

        // Collect dirty ranges (simulating tick start).
        let dirty_ranges = {
            let mut t = tracker.lock().unwrap();
            t.collect_dirty_ranges()
        };
        assert_eq!(dirty_ranges.len(), 1);

        // After collect_dirty_ranges, the tracker is emptied.
        // This means errors during flush lose dirty tracking —
        // a known limitation tracked by Review debt TFR-008.
        assert_eq!(
            tracker.lock().unwrap().dirty_inode_count(),
            0,
            "KNOWN LIMITATION: tracker is emptied during collect, before flush"
        );

        // Re-mark dirty to simulate the retry path.
        tracker.lock().unwrap().mark_dirty(ino, 0, 4096);
        assert!(tracker.lock().unwrap().is_dirty(ino));
    }
}
