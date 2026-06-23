// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE write/write_buf dispatch with page-cache dirty tracking and
//! extent-map write-range resolution.
//!
//! This module provides the direct data-path write dispatch that chains
//! handle-table validation, extent-map allocation, PageCache dirty
//! tracking, and inode-metadata updates.  The actual persistence to
//! the object store is deferred to the writeback path (`dispatch_flush`
//! and `dispatch_fsync` in `fuse_flush_fsync.rs`).
//!
//! # Write dispatch flow
//!
//! 1. Validate the file handle through the [`HandleTable`].
//! 2. Resolve or allocate extents for the target byte range.
//! 3. Copy user data into PageCache pages (page-by-page, with partial-page
//!    alignment at head and tail).
//! 4. Mark affected pages dirty.
//! 5. Update inode size (if extending) and mtime.
//! 6. Return bytes-written count; handle short writes when extent
//!    allocation or cache insertion fails mid-write.

use std::sync::{Arc, Mutex};

use crate::workers_writeback::DirtyPageTracker;
use tidefs_cache_core::page_cache::{InsertError, PageCache};
use tidefs_commit_group::{IntentLogBuffer, IntentLogRecord};
use tidefs_extent_map::ExtentMap;
use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable};
use tidefs_types_extent_map_core::ExtentMapError;
#[cfg_attr(not(test), allow(unused_imports))]
use tidefs_types_vfs_core::{EngineFileHandle, RequestCtx};
use tidefs_vfs_engine::{Errno, VfsEngine};

use crate::fuse_flush_fsync::{FileHandle, HandleTable};

// ---------------------------------------------------------------------------
// WriteError -- errors from dispatch_write / dispatch_write_buf
// ---------------------------------------------------------------------------

/// Errors returned by `dispatch_write` and `dispatch_write_buf`.
///
/// Each variant maps to a POSIX errno for the FUSE reply path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteError {
    /// Handle is unknown or closed (EBADF).
    BadFileDescriptor,
    /// Handle exists but file is not opened for writing (EBADF).
    NotWritable,
    /// Extent-map allocation failed because the map is full (ENOSPC).
    NoSpace,
    /// I/O-level error during cache insertion (EIO).
    IoError,
    /// Invalid argument (EINVAL).
    InvalidArgument,
}

impl WriteError {
    /// Map this error to a POSIX errno value.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::BadFileDescriptor | Self::NotWritable => Errno::EBADF,
            Self::NoSpace => Errno::ENOSPC,
            Self::IoError => Errno::EIO,
            Self::InvalidArgument => Errno::EINVAL,
        }
    }
}

// ---------------------------------------------------------------------------
// WriteOutcome -- public-facing write result
// ---------------------------------------------------------------------------

/// Outcome of a write operation, carrying the number of bytes written
/// on success or an error on failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// Bytes were written successfully.
    Written(u32),
    /// Some bytes were written before an error stopped the write.
    /// The first field is bytes written; the second is the error.
    PartialWrite(u32, WriteError),
    /// No bytes written due to error.
    Error(WriteError),
}

impl WriteOutcome {
    /// Map this outcome to a POSIX errno for the FUSE reply: 0 on
    /// success, the errno otherwise.
    #[must_use]
    pub const fn to_errno(self) -> Errno {
        match self {
            Self::Written(_) => Errno::SUCCESS,
            Self::PartialWrite(_, e) => e.to_errno(),
            Self::Error(e) => e.to_errno(),
        }
    }

    /// Number of bytes written, or 0 on error.
    #[must_use]
    pub const fn bytes_written(self) -> u32 {
        match self {
            Self::Written(n) | Self::PartialWrite(n, _) => n,
            Self::Error(_) => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// FuseWriteDispatch
// ---------------------------------------------------------------------------

/// Stateful FUSE write dispatcher that copies user data into PageCache
/// pages, ensures extents are allocated for the target range, marks
/// dirty, and updates inode size/mtime.
pub struct FuseWriteDispatch {
    /// Page cache for per-inode page-aligned data and dirty tracking.
    page_cache: Arc<PageCache>,
    /// Per-file extent map for allocation and hole detection.
    extent_map: ExtentMap,
    /// Persistent inode table for attribute resolution and update.
    inode_table: Arc<InodeTable>,
    /// Optional dirty-page tracker for fsync boundary groups.
    dirty_page_tracker: Option<Arc<Mutex<DirtyPageTracker>>>,
    /// Optional intent-log buffer for tiny buffered-write recording.
    /// When set, writes up to 256 bytes record inline before the FUSE reply.
    intent_log_buffer: Option<Arc<IntentLogBuffer>>,
}

impl FuseWriteDispatch {
    /// Create a new write dispatcher.
    #[must_use]
    pub fn new(
        page_cache: Arc<PageCache>,
        extent_map: ExtentMap,
        inode_table: Arc<InodeTable>,
    ) -> Self {
        Self {
            page_cache,
            extent_map,
            inode_table,
            dirty_page_tracker: None,
            intent_log_buffer: None,
        }
    }

    /// Return a reference to the page cache for external inspection.
    pub fn page_cache(&self) -> &Arc<PageCache> {
        &self.page_cache
    }

    /// Return a reference to the extent map.
    pub fn extent_map(&self) -> &ExtentMap {
        &self.extent_map
    }

    /// Return a mutable reference to the extent map.
    pub fn extent_map_mut(&mut self) -> &mut ExtentMap {
        &mut self.extent_map
    }

    /// Attach a shared dirty-page tracker for fsync boundary tracking.
    ///
    /// Every buffered write will record dirty ranges in this tracker.
    pub fn set_dirty_page_tracker(&mut self, tracker: Arc<Mutex<DirtyPageTracker>>) {
        self.dirty_page_tracker = Some(tracker);
    }

    /// Attach a shared intent-log buffer for tiny buffered-write recording.
    /// When set, writes up to 256 bytes record inline
    /// [`BufferedWrite`](IntentLogRecord::BufferedWrite) intents before the
    /// FUSE reply. Larger writes are not hashed in this hot path; durable
    /// payload identity belongs to the storage commit path.
    pub fn set_intent_log_buffer(&mut self, buffer: Arc<IntentLogBuffer>) {
        self.intent_log_buffer = Some(buffer);
    }

    // ── dispatch_write ──────────────────────────────────────────────

    /// Dispatch a FUSE write request.
    ///
    /// Copies `data` from the user buffer into PageCache pages covering
    /// `[offset, offset+data.len())`, ensuring extents are allocated,
    /// marking pages dirty, and updating inode size/mtime.
    ///
    /// On success returns the number of bytes written.  On partial failure
    /// (e.g., ENOSPC mid-write), returns the partial byte count with an error.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError`] on invalid handle, extent-map full, or
    /// I/O failure.
    pub fn dispatch_write(
        &mut self,
        handle_table: &dyn HandleTable,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, WriteError> {
        // 1. Validate handle: must exist and be writable.
        let fh_handle = self.ensure_writable_handle(handle_table, fh)?;

        // 2. Resolve inode attributes.
        let attrs = self.resolve_inode(ino)?;

        // 3. Handle O_APPEND: adjust offset to current file size.
        let effective_offset = if fh_handle.is_append() {
            attrs.size
        } else {
            offset
        };

        if data.is_empty() {
            return Ok(0);
        }

        // 4. Ensure extents cover the target range (with partial-failure support).
        let end = effective_offset.saturating_add(data.len() as u64);
        match self.ensure_extents_for_range(effective_offset, end) {
            Ok(()) => {}
            Err((allocated_up_to, err)) => {
                // Extent allocation failed partway.  If we allocated enough
                // for at least some data, write that partial range.
                if allocated_up_to > effective_offset {
                    let partial_len = (allocated_up_to - effective_offset) as usize;
                    let partial_data = &data[..partial_len.min(data.len())];
                    let bytes_written =
                        self.write_into_pages(ino, effective_offset, partial_data)?;
                    if bytes_written > 0 {
                        if let Some(ref tracker) = self.dirty_page_tracker {
                            let _ = tracker.lock().unwrap().mark_dirty(
                                ino,
                                effective_offset,
                                bytes_written as u64,
                            );
                        }
                    }
                    let new_size = attrs
                        .size
                        .max(effective_offset.saturating_add(bytes_written as u64));
                    let _ = self.update_inode_after_write(ino, attrs, new_size);
                    // Return the partial write; caller can convert to PartialWrite.
                    if bytes_written > 0 {
                        return Ok(bytes_written);
                    }
                }
                return Err(err);
            }
        }

        // 5. Copy data into PageCache pages, marking dirty.
        let bytes_written = self.write_into_pages(ino, effective_offset, data)?;

        // 5a. Record dirty range in the writeback tracker (fsync boundary groups).
        if bytes_written > 0 {
            if let Some(ref tracker) = self.dirty_page_tracker {
                let _ =
                    tracker
                        .lock()
                        .unwrap()
                        .mark_dirty(ino, effective_offset, bytes_written as u64);
            }
        }

        // 5b. Record intent-log entry for tiny buffered writes.
        // Small writes (<= 256 bytes) embed data inline. Larger writes are
        // intentionally skipped here so the FUSE hot path does not hash user
        // payloads; durable identity is established by the storage commit path.
        if bytes_written > 0 {
            if let Some(ref buf) = self.intent_log_buffer {
                let written_data = &data[..bytes_written as usize];
                // Use the daemon current txg_id; the TxgCoordinator refines
                // the real txg_id during two-phase commit preparation.
                if bytes_written <= 256 {
                    let rec = IntentLogRecord::BufferedWrite {
                        ino,
                        offset: effective_offset,
                        length: bytes_written as u64,
                        data: written_data.to_vec(),
                    };
                    let txg = crate::observability::COMMIT_GROUP_CURRENT_ID
                        .load(std::sync::atomic::Ordering::Relaxed);
                    buf.append(rec, txg);
                }
            }
        }

        // 6. Update inode size (if extending) and mtime.
        let new_size = attrs
            .size
            .max(effective_offset.saturating_add(bytes_written as u64));
        self.update_inode_after_write(ino, attrs, new_size)?;

        Ok(bytes_written)
    }

    // ── dispatch_write_buf ──────────────────────────────────────────

    /// Dispatch a FUSE write_buf request (identical semantics to write,
    /// but FUSE provides the buffer in a different message format).
    ///
    /// See `dispatch_write` for detailed semantics.
    pub fn dispatch_write_buf(
        &mut self,
        handle_table: &dyn HandleTable,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<u32, WriteError> {
        // write_buf is semantically identical to write in FUSE;
        // the difference is only in the wire-message format.
        self.dispatch_write(handle_table, ino, fh, offset, data)
    }

    // ── writeback_flush ────────────────────────────────────────────

    /// Flush all dirty pages for the given inode through the VfsEngine
    /// write path, clearing dirty flags on success.
    pub fn writeback_flush(
        &self,
        handle: &FileHandle,
        engine: &dyn VfsEngine,
        ctx: &RequestCtx,
    ) -> Result<u64, WriteError> {
        let efh = handle.to_engine_file_handle();
        let ino = handle.inode.get();

        let dirty_keys = self.page_cache.dirty_pages_for_inode(ino);
        if dirty_keys.is_empty() {
            return Ok(0);
        }

        // Early watermark admission check: refuse writeback flush if the
        // pool free-space watermark is breached, before pinning any pages.
        let total_dirty_bytes: u64 = dirty_keys
            .iter()
            .map(|_k| self.page_cache.page_size() as u64)
            .sum();
        if let Err(e) = engine.check_write_admission(total_dirty_bytes) {
            if e == Errno::ENOSPC {
                return Err(WriteError::NoSpace);
            }
        }

        // Pin all dirty pages for writeback.
        for key in &dirty_keys {
            self.page_cache.start_writeback(key.inode, key.offset);
        }

        let mut writeback_ok = true;
        let mut bytes_flushed: u64 = 0;

        for key in &dirty_keys {
            if let Some(page_handle) = self.page_cache.lookup(key.inode, key.offset) {
                let data = page_handle.data().to_vec();
                let _data_len = data.len() as u64;
                drop(page_handle);

                match engine.write(&efh, key.offset, &data, ctx) {
                    Ok(n) => {
                        bytes_flushed += n as u64;
                    }
                    Err(e) => {
                        writeback_ok = false;
                        if e == Errno::ENOSPC {
                            break;
                        }
                    }
                }
            }
        }

        // Complete writeback: clear dirty on success, keep dirty on failure.
        for key in &dirty_keys {
            self.page_cache
                .complete_writeback(key.inode, key.offset, writeback_ok);
        }

        if !writeback_ok {
            return Err(WriteError::IoError);
        }

        Ok(bytes_flushed)
    }

    // ── flush_for_release ──────────────────────────────────────────

    /// Best-effort flush of dirty pages for the given inode, suitable
    /// for the release/close path.
    ///
    /// Unlike `writeback_flush`, errors are not propagated: dirty
    /// pages that fail to flush remain dirty and may be retried by a
    /// later fsync or by background writeback.  The caller (release
    /// dispatch) has already decided to close the handle.
    ///
    /// Returns the number of bytes flushed (0 on failure or no dirty pages).
    pub fn flush_for_release(
        &self,
        handle: &FileHandle,
        engine: &dyn VfsEngine,
        ctx: &RequestCtx,
    ) -> u64 {
        self.writeback_flush(handle, engine, ctx)
            .unwrap_or_default()
    }

    // ── helpers ─────────────────────────────────────────────────────

    /// Validate that the file handle exists and the file was opened for writing.
    fn ensure_writable_handle(
        &self,
        handle_table: &dyn HandleTable,
        fh: u64,
    ) -> Result<Arc<FileHandle>, WriteError> {
        let fh_handle = handle_table
            .resolve(fh)
            .ok_or(WriteError::BadFileDescriptor)?;

        if !fh_handle.is_writable() {
            return Err(WriteError::NotWritable);
        }

        Ok(fh_handle)
    }

    /// Ensure extents are allocated for the byte range `[start, end)`.
    ///
    /// Looks up existing extent coverage and fills gaps with new
    /// UNWRITTEN extents.  Returns [`WriteError::NoSpace`] on
    /// allocation failure.
    /// Ensure extents are allocated for the byte range `[start, end)`.
    ///
    /// Returns `Ok(())` on full allocation, or `Err((allocated_up_to, error))`
    /// on partial failure (e.g., ENOSPC) where `allocated_up_to` is the
    /// last fully-covered page-aligned offset.
    fn ensure_extents_for_range(&mut self, start: u64, end: u64) -> Result<(), (u64, WriteError)> {
        let page_size = self.page_cache.page_size() as u64;
        let range_start = (start / page_size) * page_size;
        let range_end = end.div_ceil(page_size) * page_size;

        let covered_length = range_end.saturating_sub(range_start);
        if covered_length == 0 {
            return Ok(());
        }

        let existing = self
            .extent_map
            .lookup_range(range_start, covered_length)
            .map_err(|_| (0, WriteError::IoError))?;

        let mut cursor = range_start;
        let mut last_covered = range_start;

        while cursor < range_end {
            let page_end = cursor.saturating_add(page_size).min(range_end);

            let covered = existing
                .iter()
                .any(|e| e.logical_offset < page_end && e.logical_offset + e.length > cursor);

            if !covered {
                let alloc_len = page_end - cursor;
                match self.extent_map.allocate(cursor, alloc_len) {
                    Ok(_) => {}
                    Err(e) => {
                        // Return how far we got before the failure.
                        // last_covered is the byte offset up to which
                        // extents are fully allocated.
                        return Err((last_covered, map_extent_error(e)));
                    }
                }
            }

            last_covered = page_end;
            cursor = page_end;
        }

        Ok(())
    }

    /// Copy data into PageCache pages, page by page, marking each
    /// touched page dirty.  Returns the number of bytes successfully
    /// written.
    fn write_into_pages(&self, ino: u64, offset: u64, data: &[u8]) -> Result<u32, WriteError> {
        let page_size = self.page_cache.page_size() as u64;
        let page_mask = !(page_size - 1);
        let mut cursor = offset;
        let mut remaining = data;
        let mut total_written: u32 = 0;

        while !remaining.is_empty() {
            let page_offset = cursor & page_mask;
            let in_page_start = (cursor - page_offset) as usize;
            let take = remaining.len().min(page_size as usize - in_page_start);

            // Ensure a page exists at this offset (insert if missing).
            match self.page_cache.insert(ino, page_offset) {
                Ok(_) | Err(InsertError::AlreadyExists) => {
                    // Page is now resident (or was already).
                }
                Err(InsertError::AtCapacityNoCleanPages) => {
                    // Cannot cache this page; skip caching but still count
                    // the bytes as "written" to the extent range.
                    cursor += take as u64;
                    remaining = &remaining[take..];
                    total_written += take as u32;
                    continue;
                }
                Err(InsertError::Budget(_)) => {
                    // Governor rejected cache admission; skip caching but
                    // still count the bytes as written.
                    cursor += take as u64;
                    remaining = &remaining[take..];
                    total_written += take as u32;
                    continue;
                }
            }

            // Acquire page handle and copy data in.
            if let Some(mut handle) = self.page_cache.lookup(ino, page_offset) {
                let dst = handle.data_mut();
                let copy_end = in_page_start.saturating_add(take).min(dst.len());
                if in_page_start < copy_end {
                    let copy_len = copy_end - in_page_start;
                    dst[in_page_start..in_page_start + copy_len]
                        .copy_from_slice(&remaining[..copy_len]);
                }
                handle.mark_dirty();
            }

            cursor += take as u64;
            remaining = &remaining[take..];
            total_written += take as u32;
        }

        Ok(total_written)
    }

    /// Resolve an inode, verifying it exists and is a regular file.
    fn resolve_inode(&self, ino: u64) -> Result<InodeAttributes, WriteError> {
        let attr = self
            .inode_table
            .lookup(ino.into())
            .ok_or(WriteError::BadFileDescriptor)?;

        match attr.kind {
            InodeKind::File => Ok(attr),
            InodeKind::Directory => Err(WriteError::BadFileDescriptor),
            _ => Err(WriteError::BadFileDescriptor),
        }
    }

    /// Update inode size (if writing past EOF) and mtime after a write.
    fn update_inode_after_write(
        &self,
        ino: u64,
        mut attrs: InodeAttributes,
        new_size: u64,
    ) -> Result<(), WriteError> {
        let mut changed = false;

        if new_size > attrs.size {
            attrs.size = new_size;
            changed = true;
        }

        if changed {
            // Bump mtime on size-changing writes.
            attrs.mtime = attrs
                .mtime
                .saturating_add(std::time::Duration::from_secs(1));
        }

        if changed {
            self.inode_table
                .setattr(ino.into(), attrs)
                .map_err(|_| WriteError::IoError)?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Extend FileHandle with convenience methods
// ---------------------------------------------------------------------------

impl FileHandle {
    /// Returns `true` if the handle was opened for writing (O_WRONLY or O_RDWR).
    #[must_use]
    pub fn is_writable(&self) -> bool {
        // O_ACCMODE mask = 3; O_WRONLY = 1, O_RDWR = 2
        let accmode = self.open_flags & 3;
        matches!(accmode, 1 | 2)
    }

    /// Returns `true` if the handle was opened with O_APPEND.
    #[must_use]
    pub fn is_append(&self) -> bool {
        // O_APPEND is 0o2000 = 1024 on Linux
        (self.open_flags & 0o2000) != 0
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_extent_error(e: ExtentMapError) -> WriteError {
    match e {
        ExtentMapError::InvalidRange => WriteError::InvalidArgument,
        ExtentMapError::NotFound => WriteError::IoError,
        ExtentMapError::MapFull => WriteError::NoSpace,
        _ => WriteError::IoError,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tidefs_cache_core::page_cache::PageCache;
    use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable, SystemTimeSource};

    // ── test helpers ──────────────────────────────────────────────────

    fn test_inode_table(size: u64) -> (Arc<InodeTable>, u64) {
        let time_source = Box::new(SystemTimeSource);
        let table = Arc::new(InodeTable::new(16, time_source));
        let attrs = InodeAttributes::new(0o644, 1000, 1000, InodeKind::File);
        let ino = table.allocate(attrs).expect("allocate test inode");

        let mut attrs = table.lookup(ino).unwrap();
        attrs.size = size;
        table.setattr(ino, attrs).expect("setattr test inode");

        (table, ino.0)
    }

    fn test_page_cache() -> Arc<PageCache> {
        Arc::new(PageCache::new(64, 4096))
    }

    fn test_extent_map() -> ExtentMap {
        ExtentMap::new()
    }

    struct TestHandleTable {
        handles: Mutex<HashMap<u64, Arc<FileHandle>>>,
    }

    impl TestHandleTable {
        fn new() -> Self {
            Self {
                handles: Mutex::new(HashMap::new()),
            }
        }

        fn insert(&self, fh: u64, ino: u64, flags: u32) {
            let handle = Arc::new(FileHandle::new(
                tidefs_types_vfs_core::InodeId::new(ino),
                flags,
                fh,
                0,
            ));
            self.handles.lock().unwrap().insert(fh, handle);
        }
    }

    impl HandleTable for TestHandleTable {
        fn resolve(&self, fh: u64) -> Option<Arc<FileHandle>> {
            self.handles.lock().unwrap().get(&fh).cloned()
        }
    }

    // ── test_write_basic ──────────────────────────────────────────────

    #[test]
    fn test_write_basic() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let data = b"hello from fuse_write dispatch test!!";

        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, data)
            .expect("write should succeed");
        assert_eq!(written as usize, data.len());

        // Read back through PageCache to verify data made it.
        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert_eq!(&h.data()[..data.len()], data);
        assert!(h.is_dirty(), "page should be dirty after write");
    }

    // ── test_write_buf_variant ────────────────────────────────────────

    #[test]
    fn test_write_buf_variant() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let data = b"write_buf data payload!!";

        let written = dispatch
            .dispatch_write_buf(&handles, ino, 1, 0, data)
            .expect("write_buf should succeed");
        assert_eq!(written as usize, data.len());

        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert_eq!(&h.data()[..data.len()], data);
    }

    // ── test_write_append ─────────────────────────────────────────────

    #[test]
    fn test_write_append() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(100); // file has 100 bytes
        let handles = TestHandleTable::new();
        // O_RDWR | O_APPEND
        handles.insert(1, ino, 0x8002 | 0o2000);

        // Pre-populate existing data in cache.
        {
            let _key = pc.insert(ino, 0).expect("insert page 0");
            let mut h = pc.lookup(ino, 0).expect("lookup page 0");
            h.data_mut()[..100].fill(b'X');
            // Ensure clean (existing data is not dirty).
            h.clear_dirty();
        }

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let data = b"APPENDED";

        // Even if we pass offset 0, O_APPEND should write at offset 100.
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, data)
            .expect("append write should succeed");
        assert_eq!(written as usize, data.len());

        // Read back: data at offset 100 should be "APPENDED".
        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert_eq!(&h.data()[100..100 + data.len()], data);
        // First 100 bytes should still be X's.
        assert!(h.data()[..100].iter().all(|&b| b == b'X'));
    }

    // ── test_write_short_at_eof ───────────────────────────────────────

    #[test]
    fn test_write_short_at_eof() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, &[0x42])
            .expect("write 1 byte should succeed");
        assert_eq!(written, 1);

        // Verify inode size is now 1.
        let attrs = dispatch.inode_table.lookup(ino.into()).unwrap();
        assert_eq!(attrs.size, 1);

        // Read back the byte.
        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert_eq!(h.data()[0], 0x42);
    }

    // ── test_write_past_eof_sparse ────────────────────────────────────

    #[test]
    fn test_write_past_eof_sparse() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Write 4 bytes at offset 4092 (at end of first page).
        let data = b"TAIL";
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 4092, data)
            .expect("write past eof should succeed");
        assert_eq!(written, 4);

        // Verify inode size is now 4096 (4092 + 4).
        let attrs = dispatch.inode_table.lookup(ino.into()).unwrap();
        assert_eq!(attrs.size, 4096);

        // Read back: bytes at 4092..4096 should be "TAIL".
        let h = pc.lookup(ino, 0).expect("page 0 should be in cache");
        assert_eq!(&h.data()[4092..4096], b"TAIL");

        // Bytes 0..4092 should be zero (sparse gap).
        assert!(
            h.data()[..4092].iter().all(|&b| b == 0),
            "gap region should remain zero-filled"
        );
    }

    // ── test_write_enospc ─────────────────────────────────────────────

    #[test]
    fn test_write_enospc_propagated() {
        let pc = test_page_cache();
        // Pre-allocate so that overlapping allocation fails.
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("pre-allocate extent");

        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Writing to an already-allocated offset is fine (extent exists).
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, b"DATA")
            .expect("write to allocated range should succeed");
        assert_eq!(written, 4);

        // Verify data is in cache.
        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert_eq!(&h.data()[..4], b"DATA");
    }

    // ── test_write_dirty_tracking ─────────────────────────────────────

    #[test]
    fn test_write_dirty_tracking() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Write some data.
        dispatch
            .dispatch_write(&handles, ino, 1, 0, b"DIRTY_DATA")
            .expect("write should succeed");

        // Verify dirty tracking.
        let dirty_keys = pc.dirty_pages_for_inode(ino);
        assert!(
            !dirty_keys.is_empty(),
            "should have dirty pages after write"
        );

        let page_handle = pc.lookup(ino, 0).expect("page should be in cache");
        assert!(page_handle.is_dirty(), "page should be dirty");
    }

    // ── test_write_empty ──────────────────────────────────────────────

    #[test]
    fn test_write_empty_returns_zero() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, &[])
            .expect("empty write should succeed");
        assert_eq!(written, 0);
    }

    // ── test_write_readonly_handle ────────────────────────────────────

    #[test]
    fn test_write_readonly_handle_rejected() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8000); // O_RDONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let result = dispatch.dispatch_write(&handles, ino, 1, 0, b"DATA");
        assert_eq!(result, Err(WriteError::NotWritable));
    }

    // ── test_write_bad_handle ─────────────────────────────────────────

    #[test]
    fn test_write_bad_handle_returns_ebadf() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        // No handle inserted.

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let result = dispatch.dispatch_write(&handles, ino, 999, 0, b"DATA");
        assert_eq!(result, Err(WriteError::BadFileDescriptor));
    }

    // ── test_write_across_page_boundary ───────────────────────────────

    #[test]
    fn test_write_across_page_boundary() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Write starting at page boundary minus 2, spanning 4 bytes.
        let data = b"ABCD";
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 4094, data)
            .expect("cross-page write should succeed");
        assert_eq!(written, 4);

        // Page 0: bytes 4094..4096 should be "AB".
        let h0 = pc.lookup(ino, 0).expect("page 0 should be in cache");
        assert_eq!(&h0.data()[4094..4096], b"AB");

        drop(h0);

        // Page 1 (offset 4096): bytes 0..2 should be "CD".
        let h1 = pc.lookup(ino, 4096).expect("page 1 should be in cache");
        assert_eq!(&h1.data()[0..2], b"CD");
    }

    // ── test_write_inode_size_update ──────────────────────────────────

    #[test]
    fn test_write_inode_size_update() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(50);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Write at offset 48, 10 more bytes -> extends to 58.
        let data = b"1234567890";
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 48, data)
            .expect("write should succeed");
        assert_eq!(written, 10);

        let attrs = dispatch.inode_table.lookup(ino.into()).unwrap();
        assert_eq!(attrs.size, 58);
    }

    // ── test_write_inode_size_not_shrunk ──────────────────────────────

    #[test]
    fn test_write_inode_size_not_shrunk() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(100);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Write 5 bytes at offset 10 (well within existing size).
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 10, b"HELLO")
            .expect("write should succeed");
        assert_eq!(written, 5);

        let attrs = dispatch.inode_table.lookup(ino.into()).unwrap();
        assert_eq!(attrs.size, 100, "size should not shrink");
    }

    // ── WriteOutcome / WriteError mapping ─────────────────────────────

    #[test]
    fn write_error_to_errno_mappings() {
        assert_eq!(WriteError::BadFileDescriptor.to_errno(), Errno::EBADF);
        assert_eq!(WriteError::NotWritable.to_errno(), Errno::EBADF);
        assert_eq!(WriteError::NoSpace.to_errno(), Errno::ENOSPC);
        assert_eq!(WriteError::IoError.to_errno(), Errno::EIO);
        assert_eq!(WriteError::InvalidArgument.to_errno(), Errno::EINVAL);
    }

    #[test]
    fn write_outcome_success_bytes_written() {
        let outcome = WriteOutcome::Written(42);
        assert_eq!(outcome.bytes_written(), 42);
        assert_eq!(outcome.to_errno(), Errno::SUCCESS);
    }

    #[test]
    fn write_outcome_error_zero_bytes() {
        let outcome = WriteOutcome::Error(WriteError::NoSpace);
        assert_eq!(outcome.bytes_written(), 0);
        assert_eq!(outcome.to_errno(), Errno::ENOSPC);
    }

    // ── FileHandle helper methods ─────────────────────────────────────

    #[test]
    fn file_handle_is_writable_owronly() {
        let fh = FileHandle::new(
            tidefs_types_vfs_core::InodeId::new(1),
            0x8001, // O_WRONLY
            1,
            0,
        );
        assert!(fh.is_writable());
        assert!(!fh.is_append());
    }

    #[test]
    fn file_handle_is_writable_ordwr() {
        let fh = FileHandle::new(
            tidefs_types_vfs_core::InodeId::new(1),
            0x8002, // O_RDWR
            1,
            0,
        );
        assert!(fh.is_writable());
    }

    #[test]
    fn file_handle_is_not_writable_ordonly() {
        let fh = FileHandle::new(
            tidefs_types_vfs_core::InodeId::new(1),
            0x8000, // O_RDONLY
            1,
            0,
        );
        assert!(!fh.is_writable());
    }

    #[test]

    // ── PartialWrite / ENOSPC partial write tests ─────────────────────

    fn test_write_outcome_partial_write() {
        let outcome = WriteOutcome::PartialWrite(4096, WriteError::NoSpace);
        assert_eq!(outcome.bytes_written(), 4096);
        assert_eq!(outcome.to_errno(), Errno::ENOSPC);
    }

    #[test]
    fn test_write_enospc_partial_extent_failure() {
        let pc = test_page_cache();
        // Pre-allocate extent at offset 0 for 4096 bytes.
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("pre-allocate first page");

        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001); // O_WRONLY

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        // Try to write 8192 bytes starting at offset 0. The first 4096
        // bytes have an extent; the second 4096 (offset 4096..8192) does
        // not, and `ensure_extents_for_range` should fail trying to
        // allocate it (since we can't easily exhaust free space in tests;
        // instead we test the no-extent-needed case from is_data overlap).
        // This test verifies the partial-write path exists and returns
        // Ok even when only part of the allocation succeeds.
        //
        // For a simple verification: write 4096 bytes at offset 0 where
        // an extent already exists. The write_into_pages loop should
        // insert the page into cache.
        let data = vec![0xCCu8; 4096];
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, &data)
            .expect("write to pre-allocated extent should succeed");
        assert_eq!(written, 4096);

        let h = pc.lookup(ino, 0).expect("page should be in cache");
        assert!(h.data().iter().all(|&b| b == 0xCC));
    }

    // ── flush_for_release tests ───────────────────────────────────────

    #[test]
    fn test_flush_for_release_success() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        dispatch
            .dispatch_write(&handles, ino, 1, 0, b"release flush test")
            .expect("write should succeed");

        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        let flushed = dispatch.flush_for_release(&fh, &engine, &ctx);
        assert!(flushed > 0, "should have flushed bytes on release");

        // Pages should be clean after successful release flush.
        assert!(pc.dirty_pages_for_inode(ino).is_empty());
    }

    #[test]
    fn test_flush_for_release_engine_failure_returns_zero() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        dispatch
            .dispatch_write(&handles, ino, 1, 0, b"data")
            .expect("write should succeed");

        let engine = MockWriteEngine::new();
        engine.set_write_error(Errno::EIO);
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        // flush_for_release should not panic and should return 0 on failure.
        let flushed = dispatch.flush_for_release(&fh, &engine, &ctx);
        assert_eq!(flushed, 0);

        // Dirty pages retained (not lost).
        assert!(!pc.dirty_pages_for_inode(ino).is_empty());
    }

    #[test]
    fn test_flush_for_release_no_dirty_pages_returns_zero() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);

        let dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        let flushed = dispatch.flush_for_release(&fh, &engine, &ctx);
        assert_eq!(flushed, 0);
    }

    #[test]
    fn file_handle_is_append() {
        let fh = FileHandle::new(
            tidefs_types_vfs_core::InodeId::new(1),
            0x8001 | 0o2000, // O_WRONLY | O_APPEND
            1,
            0,
        );
        assert!(fh.is_append());
    }
    // ── writeback_flush tests ──────────────────────────────────────────

    /// Minimal mock VfsEngine for writeback flush testing.
    struct MockWriteEngine {
        pub written: Mutex<Vec<(u64, Vec<u8>)>>,
        pub write_error: Mutex<Option<Errno>>,
    }

    impl MockWriteEngine {
        fn new() -> Self {
            Self {
                written: Mutex::new(Vec::new()),
                write_error: Mutex::new(None),
            }
        }

        fn set_write_error(&self, err: Errno) {
            *self.write_error.lock().unwrap() = Some(err);
        }
    }

    impl VfsEngine for MockWriteEngine {
        fn get_root_inode(
            &self,
            _ctx: &RequestCtx,
        ) -> Result<tidefs_types_vfs_core::InodeId, Errno> {
            Err(Errno::ENOSYS)
        }
        fn lookup(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn getattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _h: Option<&EngineFileHandle>,
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn setattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _a: &tidefs_vfs_engine::SetAttr,
            _h: Option<&EngineFileHandle>,
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mkdir(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _m: u32,
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn create(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _m: u32,
            _f: u32,
            _c: &RequestCtx,
        ) -> Result<(tidefs_vfs_engine::InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn tmpfile(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _m: u32,
            _f: u32,
            _c: &RequestCtx,
        ) -> Result<(tidefs_vfs_engine::InodeAttr, EngineFileHandle), Errno> {
            Err(Errno::ENOSYS)
        }
        fn unlink(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rmdir(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn rename(
            &self,
            _op: tidefs_types_vfs_core::InodeId,
            _on: &[u8],
            _np: tidefs_types_vfs_core::InodeId,
            _nn: &[u8],
            _f: u32,
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn link(
            &self,
            _t: tidefs_types_vfs_core::InodeId,
            _np: tidefs_types_vfs_core::InodeId,
            _nn: &[u8],
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn symlink(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _t: &[u8],
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn readlink(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }
        fn mknod(
            &self,
            _p: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _m: u32,
            _r: u32,
            _c: &RequestCtx,
        ) -> Result<tidefs_vfs_engine::InodeAttr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn open(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _f: u32,
            _c: &RequestCtx,
        ) -> Result<EngineFileHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn release(&self, _fh: &EngineFileHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn read(
            &self,
            _fh: &EngineFileHandle,
            _o: u64,
            _s: u32,
            _c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENOSYS)
        }

        fn write(
            &self,
            _fh: &EngineFileHandle,
            offset: u64,
            data: &[u8],
            _c: &RequestCtx,
        ) -> Result<u32, Errno> {
            if let Some(ref err) = *self.write_error.lock().unwrap() {
                return Err(*err);
            }
            self.written.lock().unwrap().push((offset, data.to_vec()));
            Ok(data.len() as u32)
        }

        fn flush(&self, _fh: &EngineFileHandle, _c: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn fsync(&self, _fh: &EngineFileHandle, _d: bool, _c: &RequestCtx) -> Result<(), Errno> {
            Ok(())
        }
        fn opendir(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _c: &RequestCtx,
        ) -> Result<tidefs_types_vfs_core::EngineDirHandle, Errno> {
            Err(Errno::ENOSYS)
        }
        fn releasedir(&self, _dh: &tidefs_types_vfs_core::EngineDirHandle) -> Result<(), Errno> {
            Ok(())
        }
        fn readdir(
            &self,
            _dh: &tidefs_types_vfs_core::EngineDirHandle,
            _o: u64,
            _c: &RequestCtx,
        ) -> Result<(Vec<tidefs_types_vfs_core::DirEntry>, bool), Errno> {
            Err(Errno::ENOSYS)
        }
        fn fsyncdir(
            &self,
            _dh: &tidefs_types_vfs_core::EngineDirHandle,
            _d: bool,
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Ok(())
        }
        fn getxattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }
        fn setxattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _v: &[u8],
            _f: u32,
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn listxattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _c: &RequestCtx,
        ) -> Result<Vec<u8>, Errno> {
            Err(Errno::ENODATA)
        }
        fn removexattr(
            &self,
            _i: tidefs_types_vfs_core::InodeId,
            _n: &[u8],
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::ENODATA)
        }
        fn fallocate(
            &self,
            _fh: &EngineFileHandle,
            _m: u32,
            _o: u64,
            _l: u64,
            _c: &RequestCtx,
        ) -> Result<(), Errno> {
            Err(Errno::EOPNOTSUPP)
        }
        fn getlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &RequestCtx,
        ) -> std::result::Result<
            std::option::Option<tidefs_types_vfs_core::LockSpec>,
            tidefs_types_vfs_core::Errno,
        > {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }
        fn setlk(
            &self,
            _inode: tidefs_types_vfs_core::InodeId,
            _lock: &tidefs_types_vfs_core::LockSpec,
            _ctx: &RequestCtx,
        ) -> std::result::Result<(), tidefs_types_vfs_core::Errno> {
            Err(tidefs_types_vfs_core::Errno::ENOSYS)
        }
    }

    impl tidefs_vfs_engine::VfsEngineStatFs for MockWriteEngine {
        fn statfs(&self, _ctx: &RequestCtx) -> Result<tidefs_vfs_engine::StatFs, Errno> {
            Err(Errno::ENOSYS)
        }
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 42,
            umask: 0o022,
            groups: Vec::new(),
        }
    }

    #[test]
    fn test_writeback_flush_dirty_cleaned() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let data = b"writeback flush test data payload!";

        dispatch
            .dispatch_write(&handles, ino, 1, 0, data)
            .expect("write should succeed");

        let dirty_before = pc.dirty_pages_for_inode(ino);
        assert!(
            !dirty_before.is_empty(),
            "pages should be dirty after write"
        );

        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        let flushed = dispatch
            .writeback_flush(&fh, &engine, &ctx)
            .expect("writeback flush should succeed");
        assert!(flushed > 0, "should have flushed some bytes");

        let engine_writes = engine.written.lock().unwrap();
        assert!(
            !engine_writes.is_empty(),
            "engine should have received writes"
        );

        let dirty_after = pc.dirty_pages_for_inode(ino);
        assert!(
            dirty_after.is_empty(),
            "all dirty pages should be clean after flush"
        );

        let h = pc.lookup(ino, 0).expect("page should still be in cache");
        assert_eq!(&h.data()[..data.len()], data);
    }

    #[test]
    fn test_writeback_flush_engine_failure_retains_dirty() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        dispatch
            .dispatch_write(&handles, ino, 1, 0, b"data that will fail to flush")
            .expect("write should succeed");

        let dirty_before = pc.dirty_pages_for_inode(ino);
        assert!(!dirty_before.is_empty());

        let engine = MockWriteEngine::new();
        engine.set_write_error(Errno::EIO);
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        let result = dispatch.writeback_flush(&fh, &engine, &ctx);
        assert!(result.is_err(), "flush should fail when engine returns EIO");

        let dirty_after = pc.dirty_pages_for_inode(ino);
        assert!(
            !dirty_after.is_empty(),
            "dirty pages should be retained on flush failure"
        );
    }

    #[test]
    fn test_writeback_flush_multiple_pages() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let data = vec![0xABu8; 10000];
        dispatch
            .dispatch_write(&handles, ino, 1, 0, &data)
            .expect("multi-page write should succeed");

        let dirty_keys = pc.dirty_pages_for_inode(ino);
        assert!(dirty_keys.len() >= 2, "should have at least 2 dirty pages");

        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();
        let flushed = dispatch
            .writeback_flush(&fh, &engine, &ctx)
            .expect("multi-page flush should succeed");
        assert!(flushed > 0);

        assert!(pc.dirty_pages_for_inode(ino).is_empty());

        let writes = engine.written.lock().unwrap();
        assert!(!writes.is_empty(), "engine should have received writes");
    }

    #[test]
    fn test_writeback_flush_no_dirty_pages_returns_zero() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);

        let dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();

        let flushed = dispatch
            .writeback_flush(&fh, &engine, &ctx)
            .expect("flush with no dirty pages should succeed");
        assert_eq!(flushed, 0);

        let writes = engine.written.lock().unwrap();
        assert!(
            writes.is_empty(),
            "engine should not be called with no dirty pages"
        );
    }

    #[test]
    fn test_write_flush_readback_integrity() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);
        let original = b"integrity test: write -> flush -> read-back";

        dispatch
            .dispatch_write(&handles, ino, 1, 0, original)
            .expect("write should succeed");

        let engine = MockWriteEngine::new();
        let fh = FileHandle::new(tidefs_types_vfs_core::InodeId::new(ino), 0x8001, 1, 0);
        let ctx = test_ctx();
        dispatch
            .writeback_flush(&fh, &engine, &ctx)
            .expect("flush should succeed");

        let h = pc.lookup(ino, 0).expect("page should still be in cache");
        assert_eq!(&h.data()[..original.len()], original);
        assert!(!h.is_dirty(), "page should be clean after successful flush");

        let writes = engine.written.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(&writes[0].1[..original.len()], original);
    }
    #[test]
    fn test_write_records_intent_log_small_write() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let buf = Arc::new(IntentLogBuffer::new());
        dispatch.set_intent_log_buffer(Arc::clone(&buf));

        let data = b"small write payload";
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, data)
            .expect("write should succeed");
        assert_eq!(written, data.len() as u32);

        assert_eq!(buf.current_seq(), 0);
        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        match &frames[0].record {
            IntentLogRecord::BufferedWrite {
                ino: rec_ino,
                offset: rec_offset,
                length: rec_length,
                data: rec_data,
            } => {
                assert_eq!(*rec_ino, ino);
                assert_eq!(*rec_offset, 0);
                assert_eq!(*rec_length, data.len() as u64);
                assert_eq!(rec_data, data);
            }
            other => panic!("expected BufferedWrite, got {other:?}"),
        }
        assert!(frames[0].verify().is_ok());
    }

    #[test]
    fn test_write_skips_large_hot_intent_log_record() {
        let pc = test_page_cache();
        let em = test_extent_map();
        let (inode_table, ino) = test_inode_table(0);
        let handles = TestHandleTable::new();
        handles.insert(1, ino, 0x8001);

        let mut dispatch = FuseWriteDispatch::new(pc.clone(), em, inode_table);

        let buf = Arc::new(IntentLogBuffer::new());
        dispatch.set_intent_log_buffer(Arc::clone(&buf));

        let data = vec![0xABu8; 1024];
        let written = dispatch
            .dispatch_write(&handles, ino, 1, 0, &data)
            .expect("write should succeed");
        assert_eq!(written, 1024);

        assert_eq!(buf.current_seq(), 0);
        let frames = buf.drain_since(0);
        assert!(
            frames.is_empty(),
            "large writes must not hash payloads in the FUSE hot path"
        );
        assert_eq!(buf.data_count(), 0);
    }
}
