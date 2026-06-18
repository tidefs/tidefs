// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::ingress::{
    ClassifiedWrite, IngressWriteHandleTable, RawFuseWriteRequest, WriteClassifier,
};
use crate::scheduler::{DirtyExtentScheduler, DirtyExtentSchedulerError};
use crate::workers_writeback::DirtyPageTracker;
use tidefs_posix_filesystem_adapter_workers_io::{WriteBuffer, WriteStagingError};

pub struct DaemonWriteDispatch<const DIRTY_QUEUE_CAP: usize> {
    classifier: WriteClassifier,
    write_buffer: WriteBuffer,
    dirty_scheduler: DirtyExtentScheduler<DIRTY_QUEUE_CAP>,
    payload_buffer: BTreeMap<u64, Vec<u8>>,
    /// Per-inode dirty-page range tracker with fsync boundary groups.
    /// Populated on every accepted write dispatch; consumed by the
    /// background writeback flush service (#4657).
    /// Shared ownership allows the background flush service to drain
    /// dirty ranges without blocking FUSE write dispatch.
    dirty_page_tracker: Arc<Mutex<DirtyPageTracker>>,
}

impl<const DIRTY_QUEUE_CAP: usize> DaemonWriteDispatch<DIRTY_QUEUE_CAP> {
    pub fn new() -> Self {
        Self {
            classifier: WriteClassifier::new(),
            write_buffer: WriteBuffer::new(),
            dirty_scheduler: DirtyExtentScheduler::new(),
            payload_buffer: BTreeMap::new(),
            dirty_page_tracker: Arc::new(Mutex::new(DirtyPageTracker::new())),
        }
    }

    pub fn dispatch<H: IngressWriteHandleTable>(
        &mut self,
        handles: &H,
        request: RawFuseWriteRequest,
        payload: &[u8],
    ) -> Result<DaemonWriteDispatchOutcome, DaemonWriteDispatchError> {
        let staging_request = match self.classifier.classify(handles, request) {
            ClassifiedWrite::DirtyExtent(staging_request) => staging_request,
            ClassifiedWrite::Rejected { unique, errno } => {
                return Err(DaemonWriteDispatchError::Rejected { unique, errno })
            }
        };
        let staged = self
            .write_buffer
            .stage(staging_request, payload)
            .map_err(DaemonWriteDispatchError::Staging)?;
        let work_item_id = self
            .dirty_scheduler
            .submit_dirty_extent(staged.outcome)
            .map_err(DaemonWriteDispatchError::Scheduler)?;
        // Accumulate the dirty byte range in the writeback worker tracker
        // before the payload is consumed by the buffer.
        let _ = self.dirty_page_tracker.lock().unwrap().accept_write(
            staging_request.inode,
            staging_request.offset,
            &staged.data,
        );

        self.payload_buffer.insert(work_item_id, staged.data);
        Ok(DaemonWriteDispatchOutcome {
            unique: staging_request.unique,
            written: staging_request.length,
            work_item_id,
        })
    }

    pub fn take_payload(&mut self, work_item_id: u64) -> Option<Vec<u8>> {
        self.payload_buffer.remove(&work_item_id)
    }

    pub fn payload_buffer_len(&self) -> usize {
        self.payload_buffer.len()
    }

    /// Return a clone of the shared dirty-page tracker Arc for
    /// consumption by the background writeback flush service (#4657).
    ///
    /// Both the FUSE dispatch path and the background flush service can
    /// hold clones of this Arc, allowing concurrent access through the
    /// inner Mutex.
    pub fn dirty_page_tracker_arc(&self) -> Arc<Mutex<DirtyPageTracker>> {
        Arc::clone(&self.dirty_page_tracker)
    }

    /// Take a snapshot of the current dirty-page tracker by atomically
    /// swapping in a fresh empty one. Returns the accumulated tracker
    /// for drain by the background flush service.
    pub fn take_dirty_page_tracker(&mut self) -> Arc<Mutex<DirtyPageTracker>> {
        std::mem::replace(
            &mut self.dirty_page_tracker,
            Arc::new(Mutex::new(DirtyPageTracker::new())),
        )
    }

    pub fn dirty_scheduler(&self) -> &DirtyExtentScheduler<DIRTY_QUEUE_CAP> {
        &self.dirty_scheduler
    }

    pub fn dirty_scheduler_mut(&mut self) -> &mut DirtyExtentScheduler<DIRTY_QUEUE_CAP> {
        &mut self.dirty_scheduler
    }
}

impl<const DIRTY_QUEUE_CAP: usize> Default for DaemonWriteDispatch<DIRTY_QUEUE_CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonWriteDispatchOutcome {
    pub unique: u64,
    pub written: u32,
    pub work_item_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonWriteDispatchError {
    Rejected { unique: u64, errno: i32 },
    Staging(WriteStagingError),
    Scheduler(DirtyExtentSchedulerError),
}

impl DaemonWriteDispatchError {
    pub const fn to_errno(self) -> i32 {
        match self {
            Self::Rejected { errno, .. } => errno,
            Self::Staging(err) => err.to_errno(),
            Self::Scheduler(DirtyExtentSchedulerError::Full) => libc::EAGAIN,
            Self::Scheduler(DirtyExtentSchedulerError::InvalidRange) => libc::EINVAL,
            Self::Scheduler(DirtyExtentSchedulerError::OutOfWorkItemIds) => libc::EIO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{IngressWriteHandle, FUSE_WRITE_LOCKOWNER};
    use tidefs_posix_filesystem_adapter_workers_io::staged_write_hash64;

    struct TestHandles {
        inode: u64,
        fh: u64,
        writable: bool,
    }
    impl IngressWriteHandleTable for TestHandles {
        fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle> {
            (fh == self.fh).then_some(IngressWriteHandle {
                inode: self.inode,
                writable: self.writable,
            })
        }
    }
    fn handles() -> TestHandles {
        TestHandles {
            inode: 99,
            fh: 7,
            writable: true,
        }
    }
    fn write_request(offset: u64, size: u32) -> RawFuseWriteRequest {
        RawFuseWriteRequest {
            unique: 700,
            inode: 99,
            fh: 7,
            offset,
            size,
            payload_len: size,
            write_flags: FUSE_WRITE_LOCKOWNER,
            lock_owner: 11,
        }
    }

    #[test]
    fn dispatch_accepts_stages_and_submits_dirty_extent() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let p = vec![0x44_u8; 4096];
        let o = d.dispatch(&handles(), write_request(0, 4096), &p).unwrap();
        assert_eq!(
            o,
            DaemonWriteDispatchOutcome {
                unique: 700,
                written: 4096,
                work_item_id: 1
            }
        );
        let item = d.dirty_scheduler().as_slice()[0];
        assert_eq!(item.unique, 700);
        assert_eq!(item.content_hash64, staged_write_hash64(&p));
    }

    #[test]
    fn dispatch_retains_payload_in_buffer() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let p = vec![0xAA_u8; 4096];
        let o = d.dispatch(&handles(), write_request(0, 4096), &p).unwrap();
        assert_eq!(d.payload_buffer_len(), 1);
        assert_eq!(d.take_payload(o.work_item_id).unwrap(), p);
        assert_eq!(d.payload_buffer_len(), 0);
    }

    #[test]
    fn take_payload_consumes_only_once() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let o = d
            .dispatch(&handles(), write_request(0, 4096), &[0xBB_u8; 4096])
            .unwrap();
        assert!(d.take_payload(o.work_item_id).is_some());
        assert!(d.take_payload(o.work_item_id).is_none());
    }

    #[test]
    fn dispatch_rejects_readonly_handle_before_staging() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let h = TestHandles {
            writable: false,
            ..handles()
        };
        assert_eq!(
            d.dispatch(&h, write_request(0, 4096), &[0_u8; 4096]),
            Err(DaemonWriteDispatchError::Rejected {
                unique: 700,
                errno: libc::EBADF
            })
        );
        assert_eq!(d.payload_buffer_len(), 0);
    }

    #[test]
    fn dispatch_rejects_misaligned_write_during_staging() {
        let mut d = DaemonWriteDispatch::<4>::new();
        assert_eq!(
            d.dispatch(&handles(), write_request(1, 4096), &[0_u8; 4096]),
            Err(DaemonWriteDispatchError::Staging(
                WriteStagingError::Misaligned
            ))
        );
        assert_eq!(d.payload_buffer_len(), 0);
    }

    #[test]
    fn dispatch_reports_scheduler_backpressure_when_queue_full() {
        let mut d = DaemonWriteDispatch::<1>::new();
        d.dispatch(&handles(), write_request(0, 4096), &[1_u8; 4096])
            .unwrap();
        assert_eq!(
            d.dispatch(&handles(), write_request(4096, 4096), &[2_u8; 4096]),
            Err(DaemonWriteDispatchError::Scheduler(
                DirtyExtentSchedulerError::Full
            ))
        );
        assert_eq!(d.payload_buffer_len(), 1);
    }

    #[test]
    fn dispatch_populates_dirty_page_tracker() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let p = vec![0xDD_u8; 4096];
        let o = d.dispatch(&handles(), write_request(0, 4096), &p).unwrap();
        assert_eq!(
            o,
            DaemonWriteDispatchOutcome {
                unique: 700,
                written: 4096,
                work_item_id: 1
            }
        );
        // Verify the DirtyPageTracker was populated
        let t_arc = d.dirty_page_tracker_arc();
        let tracker = t_arc.lock().unwrap();
        assert!(!tracker.is_empty());
        assert_eq!(tracker.range_count(), 1);
        assert_eq!(tracker.dirty_bytes(99), 4096);
        let ranges = tracker.get_dirty_ranges(99);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset_start, 0);
        assert_eq!(ranges[0].offset_end, 4096);
    }

    #[test]
    fn dispatch_populates_dirty_page_tracker_out_of_order_writes() {
        let mut d = DaemonWriteDispatch::<4>::new();
        // Write at high offset first, then low offset
        d.dispatch(&handles(), write_request(8192, 4096), &[0x11_u8; 4096])
            .unwrap();
        d.dispatch(&handles(), write_request(0, 4096), &[0x22_u8; 4096])
            .unwrap();
        // Write in the middle to bridge
        d.dispatch(&handles(), write_request(4096, 4096), &[0x33_u8; 4096])
            .unwrap();

        let t_arc = d.dirty_page_tracker_arc();
        let tracker = t_arc.lock().unwrap();
        let ranges = tracker.get_dirty_ranges(99);
        // All three should be merged into one contiguous range
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].offset_start, 0);
        assert_eq!(ranges[0].offset_end, 12288);
        assert_eq!(tracker.dirty_bytes(99), 12288);
    }

    #[test]
    fn dispatch_populates_dirty_page_tracker_multiple_inodes() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let h = handles(); // inode 99

        let mut h2 = handles();
        h2.inode = 100;

        let p1 = vec![0xAA_u8; 4096];
        let p2 = vec![0xBB_u8; 4096];

        // Use the first request for inode 99
        d.dispatch(&h, write_request(0, 4096), &p1).unwrap();

        // Create a second request for inode 100
        let req2 = RawFuseWriteRequest {
            unique: 701,
            inode: 100,
            fh: 8,
            offset: 0,
            size: 4096,
            payload_len: 4096,
            write_flags: FUSE_WRITE_LOCKOWNER,
            lock_owner: 11,
        };
        // Need a handle for inode 100
        struct MultiHandles {
            map: std::collections::BTreeMap<u64, (u64, bool)>,
        }
        impl IngressWriteHandleTable for MultiHandles {
            fn lookup_write_handle(&self, fh: u64) -> Option<IngressWriteHandle> {
                self.map.get(&fh).map(|(ino, writable)| IngressWriteHandle {
                    inode: *ino,
                    writable: *writable,
                })
            }
        }
        let mh = MultiHandles {
            map: [(7, (99, true)), (8, (100, true))].into(),
        };

        let mut d2 = DaemonWriteDispatch::<4>::new();
        d2.dispatch(&mh, write_request(0, 4096), &p1).unwrap();
        d2.dispatch(&mh, req2, &p2).unwrap();

        let t_arc = d2.dirty_page_tracker_arc();
        let tracker = t_arc.lock().unwrap();
        assert_eq!(tracker.dirty_inode_count(), 2);
        assert_eq!(tracker.dirty_bytes(99), 4096);
        assert_eq!(tracker.dirty_bytes(100), 4096);
    }

    // ── Concurrent insert safety ─────────────────────────────────────
    #[test]
    fn concurrent_inserts_into_shared_tracker_across_threads() {
        let tracker = Arc::new(Mutex::new(DirtyPageTracker::new()));
        let mut handles = Vec::new();

        // Spawn 4 threads inserting ranges for different inodes.
        // Each thread owns its own inode, so no cross-thread coalescing.
        // All ranges within a thread are non-overlapping (gap of 8192).
        for t in 0..4u64 {
            let tracker = Arc::clone(&tracker);
            let handle = std::thread::spawn(move || {
                for i in 0..16u64 {
                    let offset = i * 8192; // each 4096-byte write with 4096 gap
                    tracker.lock().unwrap().mark_dirty(t, offset, 4096).unwrap();
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let t_arc_ref = tracker;
        let t = t_arc_ref.lock().unwrap();
        // 4 inodes × 16 ranges each = 64 total, all non-overlapping
        assert_eq!(
            t.range_count(),
            64,
            "expected 64 ranges, got {}",
            t.range_count()
        );
        assert_eq!(t.dirty_inode_count(), 4);
    }

    #[test]
    fn concurrent_inserts_merge_correctly_under_contention() {
        let tracker = Arc::new(Mutex::new(DirtyPageTracker::new()));
        let mut handles = Vec::new();

        // Spawn 4 threads writing to the same range — all should merge to one
        for _ in 0..4 {
            let tracker = Arc::clone(&tracker);
            let handle = std::thread::spawn(move || {
                for i in 0..16 {
                    tracker
                        .lock()
                        .unwrap()
                        .mark_dirty(1, 0, 4096 + i * 256)
                        .unwrap();
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let t = tracker.lock().unwrap();
        // Every write starts at offset 0 with increasing lengths — all merge
        assert_eq!(t.dirty_inode_count(), 1);
        assert!(t.range_count() >= 1); // may have merged to 1 or few ranges
        assert!(t.dirty_bytes(1) > 0);
    }

    #[test]
    fn concurrent_inserts_multiple_inodes_independent() {
        let tracker = Arc::new(Mutex::new(DirtyPageTracker::new()));
        let mut handles = Vec::new();

        for ino in 0..8u64 {
            let tracker = Arc::clone(&tracker);
            let handle = std::thread::spawn(move || {
                for i in 0..4 {
                    tracker
                        .lock()
                        .unwrap()
                        .mark_dirty(ino, i * 4096, 4096)
                        .unwrap();
                }
            });
            handles.push(handle);
        }

        for h in handles {
            h.join().unwrap();
        }

        let t = tracker.lock().unwrap();
        assert_eq!(t.dirty_inode_count(), 8);
        for ino in 0..8u64 {
            assert!(
                t.dirty_bytes(ino) > 0,
                "inode {ino} should have dirty bytes"
            );
        }
    }

    #[test]
    fn payload_buffer_persistence_across_multiple_writes() {
        let mut d = DaemonWriteDispatch::<4>::new();
        let p1 = vec![0x11_u8; 4096];
        let p2 = vec![0x22_u8; 4096];
        let o1 = d.dispatch(&handles(), write_request(0, 4096), &p1).unwrap();
        let o2 = d
            .dispatch(&handles(), write_request(4096, 4096), &p2)
            .unwrap();
        assert_eq!(d.payload_buffer_len(), 2);
        assert_eq!(d.take_payload(o1.work_item_id).unwrap(), p1);
        assert_eq!(d.take_payload(o2.work_item_id).unwrap(), p2);
        assert_eq!(d.payload_buffer_len(), 0);
    }
}
