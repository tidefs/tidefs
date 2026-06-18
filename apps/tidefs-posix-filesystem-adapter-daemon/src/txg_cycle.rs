// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Periodic transaction group commit cycle wired into the FUSE daemon.
//!
//! Maintains a CommitGroupManager for write accumulation, a DurabilitySequence
//! for checkpoint tracking, and a tokio interval timer that periodically
//! commits the current transaction group.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tidefs_commit_group::{CommitGroupId, RootPointer};
use tidefs_flow_commit_coordinator::{DurabilityError, DurabilitySequence};
use tidefs_local_object_store::txg_manager::{CommitGroupManager, COMMITTED_ROOT_FILE};
use tidefs_recovery_loop::compute_committed_root_digest;

const COMMIT_GROUP_DIRTY_FLUSH_BYTES: usize = 256 * 1024 * 1024;

pub struct CommitGroupCycle {
    mgr: Mutex<CommitGroupManager>,
    durability: Mutex<DurabilitySequence>,
    pub current_commit_group_id: AtomicU64,
    pub committed_count: AtomicU64,
    queued_dirty_bytes: AtomicUsize,
    store_root: Mutex<Option<PathBuf>>,
    barrier_active: AtomicU64,
}

impl CommitGroupCycle {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mgr: Mutex::new(CommitGroupManager::new(CommitGroupId::FIRST)),
            durability: Mutex::new(DurabilitySequence::new()),
            current_commit_group_id: AtomicU64::new(CommitGroupId::FIRST.0),
            committed_count: AtomicU64::new(0),
            queued_dirty_bytes: AtomicUsize::new(0),
            store_root: Mutex::new(None),
            barrier_active: AtomicU64::new(0),
        }
    }

    #[must_use]
    pub fn with_store_root(store_root: PathBuf) -> Self {
        let recovered_root = Self::read_persisted_root(&store_root);
        let (mgr, starting_id) = if let Some(root) = recovered_root {
            let next_id = root.commit_group_id.next();
            eprintln!(
                "commit_group: resumed from committed root: id={} handle={} next_id={}",
                root.commit_group_id.0, root.root_handle, next_id.0
            );
            (CommitGroupManager::resume(next_id, root), next_id)
        } else {
            eprintln!("commit_group: no committed root found, starting fresh at commit_group 1");
            (
                CommitGroupManager::new(CommitGroupId::FIRST),
                CommitGroupId::FIRST,
            )
        };
        Self {
            current_commit_group_id: AtomicU64::new(starting_id.0),
            committed_count: AtomicU64::new(0),
            queued_dirty_bytes: AtomicUsize::new(0),
            store_root: Mutex::new(Some(store_root)),
            mgr: Mutex::new(mgr),
            durability: Mutex::new(DurabilitySequence::new()),
            barrier_active: AtomicU64::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn set_store_root(&self, root: PathBuf) {
        *self.store_root.lock().unwrap() = Some(root);
    }

    fn read_persisted_root(store_root: &Path) -> Option<RootPointer> {
        let path = store_root.join(COMMITTED_ROOT_FILE);
        let payload = std::fs::read(&path).ok()?;
        CommitGroupManager::decode_root(&payload)
    }

    fn persist_committed_root(store_root: &Path, root: RootPointer) -> std::io::Result<()> {
        let target = store_root.join(COMMITTED_ROOT_FILE);
        let tmp = store_root.join(format!(".{COMMITTED_ROOT_FILE}.tmp"));
        let digest = compute_committed_root_digest(root);
        let payload = CommitGroupManager::encode_root_with_digest(root, digest);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        file.write_all(&payload)?;
        file.sync_all()?;
        drop(file);
        if let Err(e) = std::fs::rename(&tmp, &target) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::File::open(store_root)?.sync_all()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn load_persisted_root(store_root: &Path) -> Option<RootPointer> {
        Self::read_persisted_root(store_root)
    }

    pub fn queue_write(&self, ino: u64, offset: u64, data: &[u8]) {
        self.queue_write_with_flush_threshold(ino, offset, data, COMMIT_GROUP_DIRTY_FLUSH_BYTES);
    }

    fn encode_write_descriptor(ino: u64, offset: u64, len: u64) -> [u8; 32] {
        let mut descriptor = [0_u8; 32];
        descriptor[0..8].copy_from_slice(b"twdesc01");
        descriptor[8..16].copy_from_slice(&ino.to_le_bytes());
        descriptor[16..24].copy_from_slice(&offset.to_le_bytes());
        descriptor[24..32].copy_from_slice(&len.to_le_bytes());
        descriptor
    }

    fn add_queued_dirty_bytes(&self, dirty_bytes: usize) -> usize {
        let mut current = self.queued_dirty_bytes.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(dirty_bytes);
            match self.queued_dirty_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return next,
                Err(observed) => current = observed,
            }
        }
    }

    fn queue_write_with_flush_threshold(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
        flush_bytes: usize,
    ) {
        if data.is_empty() {
            return;
        }
        if let Ok(mut mgr) = self.mgr.lock() {
            let key = crate::dispatch_helpers::derive_commit_group_object_key(ino, offset);
            let descriptor = Self::encode_write_descriptor(ino, offset, data.len() as u64);
            match mgr.queue_put(key, &descriptor) {
                Ok(_) => {
                    let queued_dirty_bytes = self.add_queued_dirty_bytes(data.len());
                    if queued_dirty_bytes >= flush_bytes {
                        match mgr.commit_current() {
                            Ok(Some(root)) => {
                                self.queued_dirty_bytes.store(0, Ordering::Relaxed);
                                if let Err(e) = self.publish_committed_root(root) {
                                    eprintln!("commit_group threshold commit publish error: {e}");
                                } else {
                                    eprintln!(
                                        "commit_group committed: id={} handle={} count={}",
                                        root.commit_group_id.0,
                                        root.root_handle,
                                        self.committed_count.load(Ordering::Relaxed)
                                    );
                                }
                            }
                            Ok(None) => {}
                            Err(e) => eprintln!("commit_group threshold commit error: {e}"),
                        }
                    }
                }
                Err(e) => eprintln!("commit_group queue write error: {e}"),
            }
        }
    }

    fn publish_committed_root(
        &self,
        root: RootPointer,
    ) -> Result<(), tidefs_commit_group::CommitGroupError> {
        if let Some(ref store_root) = *self.store_root.lock().unwrap() {
            Self::persist_committed_root(store_root, root)
                .map_err(|e| tidefs_commit_group::CommitGroupError::Io(e.kind()))?;
        }
        let durable_high_val = {
            let mut dur = self.durability.lock().unwrap();
            let seq = dur.submit();
            let _ = dur.mark_durable(seq);
            dur.durable_high()
        };
        crate::observability::COMMIT_GROUP_CURRENT_ID
            .store(root.commit_group_id.0, Ordering::Relaxed);
        crate::observability::TXG_COMMITTED_COUNT.store(
            self.committed_count
                .load(Ordering::Relaxed)
                .saturating_add(1),
            Ordering::Relaxed,
        );
        crate::observability::TXG_DURABLE_HIGH.store(durable_high_val, Ordering::Relaxed);
        self.current_commit_group_id
            .store(root.commit_group_id.0, Ordering::Relaxed);
        self.committed_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn commit_current(
        &self,
    ) -> Result<Option<RootPointer>, tidefs_commit_group::CommitGroupError> {
        let mut mgr = self.mgr.lock().unwrap();
        let result = mgr.commit_current()?;
        if let Some(root) = result {
            self.queued_dirty_bytes.store(0, Ordering::Relaxed);
            self.publish_committed_root(root)?;
            Ok(Some(root))
        } else {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    pub fn checkpoint_barrier(&self) -> Result<u64, DurabilityError> {
        let mut dur = self.durability.lock().unwrap();
        let barrier_seq = dur.submit_barrier()?;
        self.barrier_active.store(barrier_seq, Ordering::Relaxed);
        Ok(barrier_seq)
    }

    #[allow(dead_code)]
    pub fn ack_barrier(&self, barrier_seq: u64) -> Result<(), DurabilityError> {
        let mut dur = self.durability.lock().unwrap();
        dur.ack_barrier(barrier_seq)?;
        self.barrier_active.store(0, Ordering::Relaxed);
        Ok(())
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn barrier_is_active(&self) -> bool {
        self.barrier_active.load(Ordering::Relaxed) > 0
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn active_barrier_seq(&self) -> u64 {
        self.barrier_active.load(Ordering::Relaxed)
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn durable_high(&self) -> u64 {
        self.durability.lock().unwrap().durable_high()
    }

    pub fn spawn_periodic_commit_loop(
        cycle: Arc<Self>,
        shutdown: Arc<std::sync::atomic::AtomicBool>,
        interval: Duration,
    ) {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("commit_group periodic commit loop: tokio runtime: {e}");
                return;
            }
        };
        rt.block_on(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                tokio::select! {
                    _ = ticker.tick() => {
                        match cycle.commit_current() {
                            Ok(Some(root)) => {
                                eprintln!("commit_group committed: id={} handle={} count={}",
                                    root.commit_group_id.0, root.root_handle,
                                    cycle.committed_count.load(Ordering::Relaxed));
                            }
                            Ok(None) => {}
                            Err(e) => { eprintln!("commit_group commit error: {e}"); }
                        }
                    }
                    _ = async {
                        while !shutdown.load(Ordering::Relaxed) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    } => { break; }
                }
            }
            eprintln!("commit_group: shutdown -- performing final flush");
            match cycle.commit_current() {
                Ok(Some(root)) => {
                    eprintln!(
                        "commit_group: final flush committed id={} handle={}",
                        root.commit_group_id.0, root.root_handle
                    );
                }
                Ok(None) => {
                    eprintln!("commit_group: final flush -- no pending writes");
                }
                Err(e) => {
                    eprintln!("commit_group: final flush error: {e}");
                }
            }
        });
    }
}

impl Default for CommitGroupCycle {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    #[test]
    fn new_cycle_starts_at_first_id() {
        let cycle = CommitGroupCycle::new();
        assert_eq!(
            cycle.current_commit_group_id.load(Ordering::Relaxed),
            CommitGroupId::FIRST.0
        );
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn queue_write_makes_cycle_non_empty() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"hello");
        let result = cycle.commit_current().unwrap();
        assert!(result.is_some());
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn queue_write_commits_when_dirty_bytes_cross_threshold() {
        let cycle = CommitGroupCycle::new();
        let payload = vec![0xA5; 1024];

        cycle.queue_write_with_flush_threshold(1, 0, &payload, 1024);

        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 1);
        let result = cycle.commit_current().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn queue_write_stages_descriptor_not_full_payload() {
        let cycle = CommitGroupCycle::new();
        let payload = vec![0xA5; 8192];

        cycle.queue_write_with_flush_threshold(1, 0, &payload, usize::MAX);

        let mgr = cycle.mgr.lock().unwrap();
        assert_eq!(mgr.current_write_count(), 1);
        assert_eq!(mgr.current_bytes(), 32);
        assert!(
            mgr.current_bytes() < payload.len(),
            "txg staging must not retain the full authoritative payload"
        );
        assert_eq!(
            cycle.queued_dirty_bytes.load(Ordering::Relaxed),
            payload.len()
        );
    }

    #[test]
    fn commit_current_empty_is_noop() {
        let cycle = CommitGroupCycle::new();
        let result = cycle.commit_current().unwrap();
        assert!(result.is_none());
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn empty_write_is_skipped() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"");
        let result = cycle.commit_current().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn multiple_writes_multiple_commits() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"first");
        let root1 = cycle.commit_current().unwrap().unwrap();
        assert_eq!(root1.commit_group_id, CommitGroupId::FIRST);
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 1);
        cycle.queue_write(2, 0, b"second");
        let root2 = cycle.commit_current().unwrap().unwrap();
        assert_eq!(root2.commit_group_id, CommitGroupId(2));
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn multiple_writes_in_one_commit() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"write1");
        cycle.queue_write(2, 0, b"write2");
        cycle.queue_write(1, 100, b"write3");
        let root = cycle.commit_current().unwrap().unwrap();
        assert_eq!(root.commit_group_id, CommitGroupId::FIRST);
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 1);
        let result = cycle.commit_current().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn txg_id_advances_across_commits() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"a");
        cycle.commit_current().unwrap();
        assert_eq!(cycle.current_commit_group_id.load(Ordering::Relaxed), 1);
        cycle.queue_write(1, 0, b"b");
        cycle.commit_current().unwrap();
        assert_eq!(cycle.current_commit_group_id.load(Ordering::Relaxed), 2);
        cycle.queue_write(1, 0, b"c");
        cycle.commit_current().unwrap();
        assert_eq!(cycle.current_commit_group_id.load(Ordering::Relaxed), 3);
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn periodic_commit_loop_starts_and_stops() {
        let cycle = Arc::new(CommitGroupCycle::new());
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cycle_clone = Arc::clone(&cycle);
        let shutdown_clone = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            CommitGroupCycle::spawn_periodic_commit_loop(
                cycle_clone,
                shutdown_clone,
                Duration::from_millis(50),
            );
        });
        cycle.queue_write(1, 0, b"commit_group-test-data");
        std::thread::sleep(Duration::from_millis(200));
        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
        assert!(cycle.committed_count.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn persist_and_load_committed_root() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        let cycle = CommitGroupCycle::with_store_root(store_root.clone());
        cycle.queue_write(1, 0, b"persist-me");
        let root = cycle.commit_current().unwrap().unwrap();
        let loaded = CommitGroupCycle::load_persisted_root(&store_root).unwrap();
        assert_eq!(loaded, root);
    }

    #[test]
    fn resume_from_persisted_root() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        let cycle1 = CommitGroupCycle::with_store_root(store_root.clone());
        cycle1.queue_write(1, 0, b"txg1");
        let root1 = cycle1.commit_current().unwrap().unwrap();
        assert_eq!(root1.commit_group_id, CommitGroupId(1));
        cycle1.queue_write(1, 0, b"txg2");
        let root2 = cycle1.commit_current().unwrap().unwrap();
        assert_eq!(root2.commit_group_id, CommitGroupId(2));
        let cycle2 = CommitGroupCycle::with_store_root(store_root.clone());
        assert_eq!(cycle2.current_commit_group_id.load(Ordering::Relaxed), 3);
        cycle2.queue_write(1, 0, b"txg3");
        let root3 = cycle2.commit_current().unwrap().unwrap();
        assert_eq!(root3.commit_group_id, CommitGroupId(3));
        assert_eq!(cycle2.committed_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn resume_from_empty_store_starts_fresh() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        let cycle = CommitGroupCycle::with_store_root(store_root);
        assert_eq!(
            cycle.current_commit_group_id.load(Ordering::Relaxed),
            CommitGroupId::FIRST.0
        );
        assert_eq!(cycle.committed_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn checkpoint_barrier_blocks_durable_marking() {
        let cycle = CommitGroupCycle::new();
        cycle.queue_write(1, 0, b"before-barrier");
        cycle.commit_current().unwrap();
        let barrier_seq = cycle.checkpoint_barrier().unwrap();
        assert!(cycle.barrier_is_active());
        assert_eq!(cycle.active_barrier_seq(), barrier_seq);
        cycle.queue_write(2, 0, b"after-barrier");
        let _root = cycle.commit_current().unwrap().unwrap();
        cycle.ack_barrier(barrier_seq).unwrap();
        assert!(!cycle.barrier_is_active());
    }

    #[test]
    fn durable_high_advances_with_commits() {
        let cycle = CommitGroupCycle::new();
        assert_eq!(cycle.durable_high(), 0);
        cycle.queue_write(1, 0, b"a");
        cycle.commit_current().unwrap();
        assert_eq!(cycle.durable_high(), 1);
        cycle.queue_write(2, 0, b"b");
        cycle.commit_current().unwrap();
        assert_eq!(cycle.durable_high(), 2);
    }

    #[test]
    fn derive_txg_object_key_is_deterministic() {
        let key1 = crate::dispatch_helpers::derive_commit_group_object_key(42, 4096);
        let key2 = crate::dispatch_helpers::derive_commit_group_object_key(42, 4096);
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_txg_object_key_different_for_different_inputs() {
        let k1 = crate::dispatch_helpers::derive_commit_group_object_key(1, 0);
        let k2 = crate::dispatch_helpers::derive_commit_group_object_key(1, 1);
        let k3 = crate::dispatch_helpers::derive_commit_group_object_key(2, 0);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    #[test]
    fn kill9_crash_recovery_resumes_from_disk() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        let root1;
        let root2;
        {
            let cycle1 = CommitGroupCycle::with_store_root(store_root.clone());
            cycle1.queue_write(10, 0, b"kill9-write1");
            root1 = cycle1.commit_current().unwrap().unwrap();
            assert_eq!(root1.commit_group_id, CommitGroupId(1));
            cycle1.queue_write(10, 4096, b"kill9-write2");
            cycle1.queue_write(20, 0, b"kill9-write3");
            root2 = cycle1.commit_current().unwrap().unwrap();
            assert_eq!(root2.commit_group_id, CommitGroupId(2));
        }
        let loaded = CommitGroupCycle::load_persisted_root(&store_root).unwrap();
        assert_eq!(loaded, root2);
        let cycle2 = CommitGroupCycle::with_store_root(store_root.clone());
        assert_eq!(
            cycle2.current_commit_group_id.load(Ordering::Relaxed),
            root2.commit_group_id.next().0
        );
        cycle2.queue_write(10, 8192, b"post-crash-write");
        let root3 = cycle2.commit_current().unwrap().unwrap();
        assert_eq!(root3.commit_group_id, CommitGroupId(3));
        assert_eq!(cycle2.committed_count.load(Ordering::Relaxed), 1);
        let loaded_after = CommitGroupCycle::load_persisted_root(&store_root).unwrap();
        assert_eq!(loaded_after, root3);
    }

    #[test]
    fn kill9_crash_with_uncommitted_data_leaves_last_committed_root() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        let committed_root;
        {
            let cycle1 = CommitGroupCycle::with_store_root(store_root.clone());
            cycle1.queue_write(10, 0, b"committed-data");
            committed_root = cycle1.commit_current().unwrap().unwrap();
            cycle1.queue_write(10, 4096, b"uncommitted-lost-data");
            cycle1.queue_write(20, 0, b"also-lost");
        }
        let loaded = CommitGroupCycle::load_persisted_root(&store_root).unwrap();
        assert_eq!(loaded, committed_root);
        let cycle2 = CommitGroupCycle::with_store_root(store_root.clone());
        assert_eq!(
            cycle2.current_commit_group_id.load(Ordering::Relaxed),
            committed_root.commit_group_id.next().0
        );
        assert!(cycle2.commit_current().unwrap().is_none());
    }

    #[test]
    fn kill9_multiple_crash_recovery_cycles() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let store_root = tmp.path().to_path_buf();
        for cycle_num in 1..=5 {
            let cycle = CommitGroupCycle::with_store_root(store_root.clone());
            let expected_id = cycle_num as u64;
            let data = format!("cycle-{cycle_num}");
            cycle.queue_write(expected_id, 0, data.as_bytes());
            let root = cycle.commit_current().unwrap().unwrap();
            assert_eq!(root.commit_group_id, CommitGroupId(expected_id));
        }
        let loaded = CommitGroupCycle::load_persisted_root(&store_root).unwrap();
        assert_eq!(loaded.commit_group_id, CommitGroupId(5));
        let cycle_final = CommitGroupCycle::with_store_root(store_root.clone());
        assert_eq!(
            cycle_final.current_commit_group_id.load(Ordering::Relaxed),
            6
        );
    }
}
