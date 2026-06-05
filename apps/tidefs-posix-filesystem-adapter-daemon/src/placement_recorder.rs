//! Cluster placement recorder: bridges mounted file I/O to the placement map.
//!
//! When the filesystem is mounted in cluster mode (--cluster), every file
//! write records a placement receipt that ties the inode/extent range to
//! the local member/device. This is the first step toward durable placement
//! receipts that survive remount and enable read-path replica selection.
//!
//! ## Design
//!
//! The [`ClusterPlacementRecorder`] wraps a [`PlacementMap`] and provides:
//! - `record_write()`: called after a successful write to record placement
//! - `persist()`: serializes the placement map to the backing store
//! - `load()`: restores the placement map from the backing store on mount
//!
//! ## Object ID derivation
//!
//! Object IDs are derived from (inode_id, logical_block) pairs so that
//! distinct file regions map to distinct placement entries. This mirrors
//! the extent-map granularity: each 4 KiB logical block gets its own
//! placement record.
//!
//! ## VfsEngine wrapper
//!
//! [`ClusterPlacementVfsEngine`] wraps [`VfsLocalFileSystem`] and implements
//! [`VfsEngine`] + [`VfsEngineStatFs`]. It delegates all operations to the
//! inner engine and records placement receipts on write/fallocate, persisting
//! the placement map on fsync/flush/syncfs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tidefs_cluster::placement_heal::{PlacementMap, PlacementObjectReceipt};
use tidefs_local_filesystem::vfs_engine_impl::VfsLocalFileSystem;
use tidefs_types_extent_map_core::FiemapExtent;
use tidefs_types_vfs_core::{
    DirEntry, EngineDirHandle, EngineFileHandle, Errno, InodeAttr, InodeId, LockSpec, NodeKind,
    RequestCtx, SetAttr, StatFs,
};
use tidefs_vfs_engine::LseekDataRange;
use tidefs_vfs_engine::{AllocatedInode, PageOwnershipMode, VfsEngine, VfsEngineStatFs};

/// File name for the persisted placement map inside the backing directory.
const PLACEMENT_MAP_FILENAME: &str = "cluster_placement_map.bincode";

/// Block size used for object-ID derivation (matches typical extent alignment).
const LOGICAL_BLOCK_SIZE: u64 = 4096;

/// Records file-IO placements into the cluster placement map.
pub struct ClusterPlacementRecorder {
    map: PlacementMap,
    member_id: u64,
}

impl ClusterPlacementRecorder {
    pub fn new(member_id: u64, epoch: u64) -> Self {
        Self {
            map: PlacementMap::new(epoch),
            member_id,
        }
    }

    pub fn load_or_new(backing_dir: &Path, member_id: u64, epoch: u64) -> Self {
        let map_path = backing_dir.join(PLACEMENT_MAP_FILENAME);
        if let Ok(data) = std::fs::read(&map_path) {
            if let Ok(map) = bincode::deserialize::<PlacementMap>(&data) {
                return Self { map, member_id };
            }
        }
        Self::new(member_id, epoch)
    }

    /// Record that the given byte range of an inode was written to this member.
    pub fn record_write(&mut self, inode_id: u64, offset: u64, length: u64) {
        let start_block = offset / LOGICAL_BLOCK_SIZE;
        let end_byte = offset.saturating_add(length);
        let end_block = end_byte.saturating_add(LOGICAL_BLOCK_SIZE - 1) / LOGICAL_BLOCK_SIZE;
        let epoch = self.map.epoch();

        for block in start_block..end_block {
            let block_offset = block * LOGICAL_BLOCK_SIZE;
            let block_len = if block_offset + LOGICAL_BLOCK_SIZE > end_byte {
                end_byte - block_offset
            } else {
                LOGICAL_BLOCK_SIZE
            };
            let object_id = (inode_id << 32) | (block & 0xFFFF_FFFF);
            let receipt = PlacementObjectReceipt::new(
                object_id,
                self.member_id,
                inode_id,
                block_offset,
                block_len,
                epoch,
            );
            self.map.record_receipt(receipt);
        }
    }

    pub fn persist(&self, backing_dir: &Path) -> Result<(), String> {
        let map_path = backing_dir.join(PLACEMENT_MAP_FILENAME);
        let data = bincode::serialize(&self.map)
            .map_err(|e| format!("placement map serialize failed: {e}"))?;
        std::fs::write(&map_path, &data).map_err(|e| format!("placement map write failed: {e}"))?;
        Ok(())
    }

    pub fn placement_map(&self) -> &PlacementMap {
        &self.map
    }

    pub fn member_id(&self) -> u64 {
        self.member_id
    }

    pub fn object_count(&self) -> usize {
        self.map.object_count()
    }

    /// Find which members hold data for the given file byte range.
    ///
    /// Used to select a replica for read-path I/O in a clustered filesystem.
    /// Returns the set of member IDs whose placement receipts overlap the
    /// query range. The caller should prefer the local member when available.
    pub fn members_for_range(&self, inode_id: u64, offset: u64, length: u64) -> BTreeSet<u64> {
        self.map.members_for_range(inode_id, offset, length)
    }

    /// True if at least one placement receipt covers any part of the given
    /// (inode, byte_range). Used by the read path to verify that data being
    /// read has been placed — a gap means the data was written before cluster
    /// mode or the placement was lost.
    pub fn has_placement_for_range(&self, inode_id: u64, offset: u64, length: u64) -> bool {
        !self
            .map
            .members_for_range(inode_id, offset, length)
            .is_empty()
    }

    /// Number of receipts stored (covers the full receipt index).
    pub fn receipt_count(&self) -> usize {
        self.map.receipt_count()
    }
}

// ── VfsEngine placement wrapper ─────────────────────────────────────

/// A VfsEngine wrapper that records file-I/O placements into the cluster
/// placement map when the filesystem is mounted in cluster mode.
pub struct ClusterPlacementVfsEngine {
    inner: VfsLocalFileSystem,
    recorder: Mutex<ClusterPlacementRecorder>,
    backing_dir: PathBuf,
}

impl ClusterPlacementVfsEngine {
    pub fn new(
        inner: VfsLocalFileSystem,
        backing_dir: PathBuf,
        member_id: u64,
        epoch: u64,
    ) -> Self {
        let recorder = ClusterPlacementRecorder::load_or_new(&backing_dir, member_id, epoch);
        Self {
            inner,
            recorder: Mutex::new(recorder),
            backing_dir,
        }
    }

    fn record_write_placement(&self, inode_id: InodeId, offset: u64, length: u64) {
        if let Ok(mut rec) = self.recorder.lock() {
            rec.record_write(inode_id.0, offset, length);
        }
    }

    fn persist_placement(&self) {
        if let Ok(rec) = self.recorder.lock() {
            let _ = rec.persist(&self.backing_dir);
        }
    }
}

impl VfsEngine for ClusterPlacementVfsEngine {
    fn get_root_inode(&self, ctx: &RequestCtx) -> Result<InodeId, Errno> {
        self.inner.get_root_inode(ctx)
    }
    fn lookup(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<InodeAttr, Errno> {
        self.inner.lookup(parent, name, ctx)
    }
    fn getattr(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.inner.getattr(inode, handle, ctx)
    }
    fn setattr(
        &self,
        inode: InodeId,
        attr: &SetAttr,
        handle: Option<&EngineFileHandle>,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        let prev = self.inner.getattr(inode, handle, ctx).ok();
        let result = self.inner.setattr(inode, attr, handle, ctx)?;
        // Record placement for truncate-extend (FATTR_SIZE = 1 << 3).
        if attr.valid & (1 << 3) != 0 {
            if let Some(prev_attr) = prev {
                if attr.size > prev_attr.posix.size {
                    self.record_write_placement(
                        inode,
                        prev_attr.posix.size,
                        attr.size - prev_attr.posix.size,
                    );
                }
            }
        }
        Ok(result)
    }
    fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.inner.mkdir(parent, name, mode, ctx)
    }
    fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        self.inner.create(parent, name, mode, flags, ctx)
    }
    fn create_excl(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        self.inner.create_excl(parent, name, mode, flags, ctx)
    }
    fn tmpfile(
        &self,
        parent: InodeId,
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(InodeAttr, EngineFileHandle), Errno> {
        self.inner.tmpfile(parent, mode, flags, ctx)
    }
    fn unlink(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.unlink(parent, name, ctx)
    }
    fn rmdir(&self, parent: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.rmdir(parent, name, ctx)
    }
    fn rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner
            .rename(old_parent, old_name, new_parent, new_name, flags, ctx)
    }
    fn link(
        &self,
        target: InodeId,
        new_parent: InodeId,
        new_name: &[u8],
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.inner.link(target, new_parent, new_name, ctx)
    }
    fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.inner.symlink(parent, name, target, ctx)
    }
    fn readlink(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        self.inner.readlink(inode, ctx)
    }
    fn mknod(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: &RequestCtx,
    ) -> Result<InodeAttr, Errno> {
        self.inner.mknod(parent, name, mode, rdev, ctx)
    }
    fn allocate_inode(
        &self,
        kind: NodeKind,
        parent: InodeId,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<AllocatedInode, Errno> {
        self.inner.allocate_inode(kind, parent, mode, uid, gid)
    }
    fn open(
        &self,
        inode: InodeId,
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<EngineFileHandle, Errno> {
        self.inner.open(inode, flags, ctx)
    }
    fn release(&self, fh: &EngineFileHandle) -> Result<(), Errno> {
        self.inner.release(fh)
    }
    fn read(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> Result<Vec<u8>, Errno> {
        let data = self.inner.read(fh, offset, size, ctx)?;
        // Verify placement: the data being read should have placement receipts.
        // A gap means the data was written before cluster mode or placement
        // state was lost — this is not an I/O error but signals degraded
        // placement tracking.
        let read_len = data.len() as u64;
        if read_len > 0 {
            if let Ok(rec) = self.recorder.lock() {
                if !rec.has_placement_for_range(fh.inode_id.0, offset, read_len) {
                    eprintln!(
                        "cluster placement: read at inode={} offset={} len={} has no placement receipt — degraded",
                        fh.inode_id.0, offset, read_len
                    );
                }
            }
        }
        Ok(data)
    }
    fn write(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let written = self.inner.write(fh, offset, data, ctx)?;
        let written_u64 = u64::from(written);
        if written_u64 > 0 {
            self.record_write_placement(fh.inode_id, offset, written_u64);
        }
        Ok(written)
    }
    fn copy_file_range(
        &self,
        source_fh: &EngineFileHandle,
        offset_in: u64,
        dest_fh: &EngineFileHandle,
        offset_out: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<u32, Errno> {
        let copied = self
            .inner
            .copy_file_range(source_fh, offset_in, dest_fh, offset_out, length, ctx)?;
        let copied_u64 = u64::from(copied);
        if copied_u64 > 0 {
            self.record_write_placement(dest_fh.inode_id, offset_out, copied_u64);
        }
        Ok(copied)
    }
    fn flush(&self, fh: &EngineFileHandle, ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.flush(fh, ctx)?;
        self.persist_placement();
        Ok(())
    }
    fn fsync(&self, fh: &EngineFileHandle, datasync: bool, ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.fsync(fh, datasync, ctx)?;
        self.persist_placement();
        Ok(())
    }
    fn fallocate(
        &self,
        fh: &EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner.fallocate(fh, mode, offset, length, ctx)?;
        // Record placement for allocation modes (mode=0 or FALLOC_FL_KEEP_SIZE).
        if mode == 0 || mode & 1 != 0 {
            self.record_write_placement(fh.inode_id, offset, length);
        }
        Ok(())
    }
    fn readahead(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner.readahead(fh, offset, length, ctx)
    }
    fn data_ranges(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> Result<Vec<LseekDataRange>, Errno> {
        self.inner.data_ranges(fh, offset, length, ctx)
    }
    fn fiemap_file(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u64,
        max_extents: u32,
        ctx: &RequestCtx,
    ) -> Result<Vec<FiemapExtent>, Errno> {
        self.inner.fiemap_file(fh, offset, length, max_extents, ctx)
    }
    fn opendir(&self, inode: InodeId, ctx: &RequestCtx) -> Result<EngineDirHandle, Errno> {
        self.inner.opendir(inode, ctx)
    }
    fn releasedir(&self, dh: &EngineDirHandle) -> Result<(), Errno> {
        self.inner.releasedir(dh)
    }
    fn readdir(
        &self,
        dh: &EngineDirHandle,
        offset_cookie: u64,
        ctx: &RequestCtx,
    ) -> Result<(Vec<DirEntry>, bool), Errno> {
        self.inner.readdir(dh, offset_cookie, ctx)
    }
    fn fsyncdir(
        &self,
        dh: &EngineDirHandle,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner.fsyncdir(dh, datasync, ctx)
    }
    fn fdatasync_inode(
        &self,
        fh: &EngineFileHandle,
        datasync: bool,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner.fdatasync_inode(fh, datasync, ctx)?;
        self.persist_placement();
        Ok(())
    }
    fn syncfs(&self, ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.syncfs(ctx)?;
        self.persist_placement();
        Ok(())
    }
    fn getxattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        self.inner.getxattr(inode, name, ctx)
    }
    fn setxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> Result<(), Errno> {
        self.inner.setxattr(inode, name, value, flags, ctx)
    }
    fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> Result<Vec<u8>, Errno> {
        self.inner.listxattr(inode, ctx)
    }
    fn removexattr(&self, inode: InodeId, name: &[u8], ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.removexattr(inode, name, ctx)
    }
    fn getlk(
        &self,
        inode: InodeId,
        lock: &LockSpec,
        ctx: &RequestCtx,
    ) -> Result<Option<LockSpec>, Errno> {
        self.inner.getlk(inode, lock, ctx)
    }
    fn setlk(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.setlk(inode, lock, ctx)
    }
    fn setlkw(&self, inode: InodeId, lock: &LockSpec, ctx: &RequestCtx) -> Result<(), Errno> {
        self.inner.setlkw(inode, lock, ctx)
    }
    fn check_write_admission(&self, byte_count: u64) -> Result<(), Errno> {
        self.inner.check_write_admission(byte_count)
    }
    fn defrag_file(&self, ino: InodeId, ctx: &RequestCtx) -> Result<(u64, u64), Errno> {
        self.inner.defrag_file(ino, ctx)
    }
    fn invalidate_cache_range(&self, inode: InodeId, start: u64, end: u64) -> Result<(), Errno> {
        self.inner.invalidate_cache_range(inode, start, end)
    }
    fn page_ownership_acquired(&self, inode: InodeId, page_idx: u64, mode: PageOwnershipMode) {
        self.inner.page_ownership_acquired(inode, page_idx, mode)
    }
}

impl VfsEngineStatFs for ClusterPlacementVfsEngine {
    fn statfs(&self, ctx: &RequestCtx) -> Result<StatFs, Errno> {
        self.inner.statfs(ctx)
    }

    fn live_pool_admin_request(&self, request_json: &[u8]) -> Result<Vec<u8>, Errno> {
        self.inner.live_pool_admin_request(request_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_recorder_is_empty() {
        let recorder = ClusterPlacementRecorder::new(1, 5);
        assert_eq!(recorder.object_count(), 0);
        assert_eq!(recorder.member_id(), 1);
        assert_eq!(recorder.placement_map().epoch(), 5);
    }

    #[test]
    fn record_single_block_write() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 0, 4096);
        assert_eq!(recorder.object_count(), 1);
    }

    #[test]
    fn record_multi_block_write() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 0, 12288);
        assert_eq!(recorder.object_count(), 3);
    }

    #[test]
    fn record_unaligned_write() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 5000, 1);
        assert_eq!(recorder.object_count(), 1);
    }

    #[test]
    fn record_write_spanning_block_boundary() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 4000, 100);
        assert_eq!(recorder.object_count(), 2);
    }

    #[test]
    fn distinct_inodes_get_distinct_object_ids() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 0, 4096);
        recorder.record_write(200, 0, 4096);
        assert_eq!(recorder.object_count(), 2);
    }

    #[test]
    fn persist_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path: PathBuf = dir.path().to_path_buf();

        let mut recorder = ClusterPlacementRecorder::new(1, 3);
        recorder.record_write(100, 0, 8192);
        recorder.persist(&dir_path).unwrap();

        let loaded = ClusterPlacementRecorder::load_or_new(&dir_path, 1, 3);
        assert_eq!(loaded.object_count(), 2);
        assert_eq!(loaded.member_id(), 1);
        assert_eq!(loaded.placement_map().epoch(), 3);
        assert!(loaded.placement_map().replicas_of(100u64 << 32).is_some());
        assert!(loaded
            .placement_map()
            .replicas_of((100u64 << 32) | 1)
            .is_some());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::path::PathBuf;

    /// Full placement round-trip: write placement, persist, reload, verify.
    #[test]
    fn placement_survives_persist_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path: PathBuf = dir.path().to_path_buf();

        // Phase 1: write some data and record placements.
        {
            let mut recorder = ClusterPlacementRecorder::new(7, 42);
            // Simulate writing 3 blocks to inode 100.
            recorder.record_write(100, 0, 12288); // 3 blocks (0-12287)
            recorder.record_write(100, 16384, 4096); // 1 block at offset 16384
            recorder.record_write(200, 0, 4096); // 1 block to different inode
            assert_eq!(recorder.object_count(), 5);
            recorder.persist(&dir_path).unwrap();
        }

        // Phase 2: reload (simulates remount).
        {
            let recorder = ClusterPlacementRecorder::load_or_new(&dir_path, 7, 42);
            assert_eq!(recorder.object_count(), 5);

            // Verify read-path lookup works after reload.
            let members = recorder.members_for_range(100, 0, 4096);
            assert!(
                members.contains(&7),
                "member 7 should hold block 0 of inode 100"
            );

            let members = recorder.members_for_range(100, 4096, 4096);
            assert!(
                members.contains(&7),
                "member 7 should hold block 1 of inode 100"
            );

            let members = recorder.members_for_range(100, 16384, 4096);
            assert!(
                members.contains(&7),
                "member 7 should hold block at offset 16384"
            );

            let members = recorder.members_for_range(200, 0, 4096);
            assert!(
                members.contains(&7),
                "member 7 should hold block 0 of inode 200"
            );

            // Verify has_placement_for_range.
            assert!(recorder.has_placement_for_range(100, 0, 4096));
            assert!(recorder.has_placement_for_range(100, 8192, 4096));
            // Gap: bytes 12288-16383 were never written.
            assert!(!recorder.has_placement_for_range(100, 12288, 4096));
        }
    }

    /// Verify that a write to a new inode after reload continues to accumulate.
    #[test]
    fn placement_continues_after_reload() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path: PathBuf = dir.path().to_path_buf();

        {
            let mut recorder = ClusterPlacementRecorder::new(1, 1);
            recorder.record_write(100, 0, 4096);
            recorder.persist(&dir_path).unwrap();
        }

        {
            let mut recorder = ClusterPlacementRecorder::load_or_new(&dir_path, 1, 1);
            assert_eq!(recorder.object_count(), 1);

            // Write more data after reload.
            recorder.record_write(100, 4096, 4096);
            recorder.record_write(300, 0, 8192);
            assert_eq!(recorder.object_count(), 4); // original 1 + 1 + 2

            // Verify both old and new placements are present.
            assert!(recorder.has_placement_for_range(100, 0, 4096));
            assert!(recorder.has_placement_for_range(100, 4096, 4096));
            assert!(recorder.has_placement_for_range(300, 0, 4096));
            assert!(recorder.has_placement_for_range(300, 4096, 4096));

            recorder.persist(&dir_path).unwrap();
        }

        // Final reload: all 4 placements should survive.
        {
            let recorder = ClusterPlacementRecorder::load_or_new(&dir_path, 1, 1);
            assert_eq!(recorder.object_count(), 4);
            assert!(recorder.has_placement_for_range(100, 0, 4096));
            assert!(recorder.has_placement_for_range(300, 0, 8192));
        }
    }

    /// Verify members_for_range returns empty for unwritten ranges.
    #[test]
    fn unwritten_range_returns_empty_members() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);
        recorder.record_write(100, 0, 4096);

        // This range was never written.
        let members = recorder.members_for_range(100, 8192, 4096);
        assert!(members.is_empty());
        assert!(!recorder.has_placement_for_range(100, 8192, 4096));
    }

    /// Verify that overlapping partial writes are handled correctly.
    #[test]
    fn partial_block_write_coverage() {
        let mut recorder = ClusterPlacementRecorder::new(1, 1);

        // Write 100 bytes at offset 100 (within block 0, bytes 0-4095).
        recorder.record_write(100, 100, 100);

        // The receipt covers block 0, which spans bytes 0-4095.
        let members = recorder.members_for_range(100, 0, 100);
        assert!(members.contains(&1));

        let members = recorder.members_for_range(100, 200, 100);
        // offset 200 is exactly at the receipt end (exclusive), so no overlap.
        assert!(members.is_empty());

        // Gap: block 1 was never written.
        let members = recorder.members_for_range(100, 4096, 100);
        assert!(members.is_empty());
    }
}
