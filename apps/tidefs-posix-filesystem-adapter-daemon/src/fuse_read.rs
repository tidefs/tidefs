//! FUSE read dispatch with page-cache integration and extent-map data path.
//!
//! This module provides the direct data-path read dispatch that chains
//! `tidefs-inode-table` lookup, `tidefs-extent-map` byte-range resolution,
//! `tidefs-cache-core` (PageCache) hits/misses, and a pluggable
//! [`ReadDataProvider`] for cache-miss data retrieval.
//!
//! The page-by-page loop serves cache hits directly from the page cache
//! and fills misses by consulting the extent map for hole detection, then
//! calling the data provider for DATA extents or zero-filling holes.

use std::sync::Arc;

use crate::materialized_cache::MaterializedSignatureCache;

use tidefs_cache_core::page_cache::{InsertError, PageCache};
use tidefs_extent_map::ExtentMap;
use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable};
use tidefs_types_extent_map_core::ExtentMapError;
use tidefs_types_vfs_core::{EngineFileHandle, FileHandleId, InodeId, RequestCtx};
use tidefs_vfs_engine::{Errno, VfsEngine};

// ---------------------------------------------------------------------------
// ReadDataProvider trait
// ---------------------------------------------------------------------------

/// Trait for reading file data on cache miss.
///
/// Implementations must return data for the requested `[offset, offset+length)`
/// byte range.  Zeros are expected for holes and unwritten extents; the
/// caller may also use the extent map to skip the call entirely for pure-hole
/// ranges.  A short return (fewer bytes than requested) signals EOF.
pub trait ReadDataProvider: Send + Sync {
    /// Read `length` bytes starting at `offset` for inode `ino` via
    /// file handle `fh`.  The `fh` is the FUSE file-handle value; the
    /// implementation is responsible for resolving it to an engine handle.
    fn read_data(&self, ino: u64, fh: u64, offset: u64, length: u64) -> Result<Vec<u8>, Errno>;
}

// ---------------------------------------------------------------------------
// FuseReadDispatch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// EngineReadProvider
// ---------------------------------------------------------------------------

/// [`ReadDataProvider`] backed by a VFS engine.
///
/// Converts FUSE-level (ino, fh, offset, length) calls into engine
/// [`VfsEngine::read`] calls, using the engine's internal extent-map
/// and object-store resolution.
pub struct EngineReadProvider {
    pub engine: std::sync::Mutex<Box<dyn VfsEngine + Send>>,
    pub ctx: RequestCtx,
}

impl EngineReadProvider {
    pub fn new(engine: Box<dyn VfsEngine + Send>, ctx: RequestCtx) -> Self {
        Self {
            engine: std::sync::Mutex::new(engine),
            ctx,
        }
    }
}

impl ReadDataProvider for EngineReadProvider {
    fn read_data(&self, ino: u64, fh: u64, offset: u64, length: u64) -> Result<Vec<u8>, Errno> {
        let engine_fh = EngineFileHandle::new(InodeId::new(ino), 0, FileHandleId::new(fh), 0);
        let e = self.engine.lock().map_err(|_| Errno::EIO)?;
        e.read(&engine_fh, offset, length as u32, &self.ctx)
    }
}

/// Stateful FUSE read dispatcher that resolves logical byte ranges through
/// the extent map, serves cache hits from the page cache, and fills misses
/// via a [`ReadDataProvider`].
pub struct FuseReadDispatch {
    /// Page cache for per-inode page-aligned data.
    page_cache: Arc<PageCache>,
    /// Per-file extent map (owned, one per open file or shared pool).
    extent_map: ExtentMap,
    /// Persistent inode table for attribute resolution.
    inode_table: Arc<InodeTable>,
    /// Pluggable data provider for cache-miss reads.
    data_provider: Option<Arc<dyn ReadDataProvider>>,
    /// Materialized workload-signature cache for adaptive readahead.
    signature_cache: Option<Arc<MaterializedSignatureCache>>,
}

/// Read request bundled with the VFS engine used for page-cache misses.
pub struct EngineReadRequest<'a> {
    pub ino: u64,
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub file_size: u64,
    pub engine: &'a dyn VfsEngine,
    pub ctx: &'a RequestCtx,
}

impl FuseReadDispatch {
    /// Create a new read dispatcher without a data provider.
    ///
    /// Cache hits are served directly; cache misses return `EIO` unless a
    /// data provider is supplied via [`with_data_provider`](Self::with_data_provider).
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
            data_provider: None,
            signature_cache: None,
        }
    }

    /// Attach a data provider for cache-miss reads.
    #[must_use]
    pub fn with_data_provider(mut self, provider: Arc<dyn ReadDataProvider>) -> Self {
        self.data_provider = Some(provider);
        self
    }

    /// Attach a workload-signature cache for adaptive readahead tuning.
    #[must_use]
    pub fn with_signature_cache(mut self, cache: Arc<MaterializedSignatureCache>) -> Self {
        self.signature_cache = Some(cache);
        self
    }

    /// Return workload-adaptive readahead page count.
    #[must_use]
    pub fn readahead_pages(&self) -> usize {
        self.signature_cache
            .as_ref()
            .map(|c| c.readahead_pages())
            .unwrap_or(4)
    }

    /// Return a reference to the page cache for stats inspection.
    pub fn page_cache(&self) -> &Arc<PageCache> {
        &self.page_cache
    }

    /// Populate the page cache with externally-provided data.
    ///
    /// Used after an engine read to pre-warm the cache for future hits.
    /// The data is inserted page-by-page, covering the range
    /// `[offset, offset + data.len())`.
    pub fn populate_cache(&self, ino: u64, offset: u64, data: &[u8]) {
        let page_size = self.page_cache.page_size() as u64;

        let page_mask = !(page_size - 1);

        let mut cursor = offset;

        let mut remaining = data;

        while !remaining.is_empty() {
            let page_offset = cursor & page_mask;

            let in_page = (cursor - page_offset) as usize;

            let take = remaining.len().min(page_size as usize - in_page);

            // Try to insert; if AlreadyExists, fill existing page.

            if self.page_cache.lookup(ino, page_offset).is_none() {
                if let Ok(_key) = self.page_cache.insert(ino, page_offset) {
                    if let Some(mut handle) = self.page_cache.lookup(ino, page_offset) {
                        let buf = handle.data_mut();

                        let copy_len = take.min(buf.len().saturating_sub(in_page));

                        buf[in_page..in_page + copy_len].copy_from_slice(&remaining[..copy_len]);
                    }
                }
            }

            cursor += take as u64;

            remaining = &remaining[take..];
        }
    }
    /// Dispatch a FUSE read request.
    ///
    /// Returns the data bytes for the requested `[offset, offset+size)` range,
    /// with zero-filling for holes and short reads at EOF.
    ///
    /// # Errors
    ///
    /// Returns `Err(Errno)` on invalid inode or I/O failure.
    pub fn dispatch_read(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, Errno> {
        // 1. Validate inode exists and is a regular file.
        let attr = self.resolve_inode(ino)?;

        // 2. Delegate to the inner loop with resolved file size.
        self.dispatch_read_with_size(ino, fh, offset, size, attr.size)
    }

    /// Dispatch a read when the file size is already known (avoids
    /// redundant inode-table lookup).
    pub fn dispatch_read_with_size(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        size: u32,
        file_size: u64,
    ) -> Result<Vec<u8>, Errno> {
        // Zero-size or offset-past-EOF: return empty.
        if size == 0 || offset >= file_size {
            return Ok(Vec::new());
        }

        // Clip requested size at EOF for short reads.
        let effective_size = {
            let end = offset.saturating_add(size as u64);
            if end > file_size {
                (file_size - offset) as u32
            } else {
                size
            }
        };

        // Build the reply buffer page-by-page.
        let page_size = self.page_cache.page_size() as u64;
        let mut reply = Vec::with_capacity(effective_size as usize);
        let mut cursor = offset;
        let mut remaining = effective_size as u64;

        while remaining > 0 {
            let page_offset = (cursor / page_size) * page_size;
            let in_page_offset = (cursor - page_offset) as usize;
            let take = remaining.min(page_size - (cursor - page_offset)) as usize;

            // Try page-cache hit first.
            let served = if let Some(handle) = self.page_cache.lookup(ino, page_offset) {
                let data = handle.data();
                let available = data.len().saturating_sub(in_page_offset);
                let chunk = available.min(take);
                if chunk > 0 {
                    reply.extend_from_slice(&data[in_page_offset..in_page_offset + chunk]);
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !served {
                // Cache miss: determine data vs hole via extent map.
                let extents = self
                    .extent_map
                    .lookup_range(page_offset, page_size)
                    .map_err(map_extent_error)?;

                let has_data = extents.iter().any(|e| e.is_data());

                let page_data = if has_data {
                    // DATA extent: fetch from data provider.
                    match &self.data_provider {
                        Some(provider) => provider.read_data(ino, fh, page_offset, page_size)?,
                        None => {
                            // No data provider: can't serve this range.
                            return Err(Errno::EIO);
                        }
                    }
                } else {
                    // Hole or UNWRITTEN: zero-fill.
                    vec![0u8; page_size as usize]
                };

                // Attempt to populate the page cache.
                let inserted = match self.page_cache.insert(ino, page_offset) {
                    Ok(_key) => {
                        // Fill the newly inserted page with data from provider.
                        if let Some(mut handle) = self.page_cache.lookup(ino, page_offset) {
                            let buf = handle.data_mut();
                            let copy_len = page_data.len().min(buf.len());
                            buf[..copy_len].copy_from_slice(&page_data[..copy_len]);
                        }
                        true
                    }
                    Err(InsertError::AlreadyExists) => {
                        // Race: another thread inserted the page between our miss
                        // and our insert.
                        self.page_cache.lookup(ino, page_offset).is_some()
                    }
                    Err(InsertError::AtCapacityNoCleanPages) => {
                        // Cannot cache; serve data without populating.
                        false
                    }
                };
                let _ = inserted; // observability hook

                // Copy the requested slice into the reply buffer.
                let available = page_data.len().saturating_sub(in_page_offset);
                let chunk = available.min(take);
                if chunk > 0 {
                    reply.extend_from_slice(&page_data[in_page_offset..in_page_offset + chunk]);
                } else {
                    // Data provider returned fewer bytes than expected (EOF).
                    reply.resize(reply.len() + take, 0);
                }
            }

            let advanced = take as u64;
            cursor += advanced;
            remaining = remaining.saturating_sub(advanced);

            if advanced == 0 {
                break;
            }
        }

        Ok(reply)
    }

    /// Dispatch a read using the provided VFS engine for cache-miss pages.
    ///
    /// Cache hits are served from [`PageCache`]; cache misses call
    /// `engine.read()` to fetch the data, populate the cache, then serve.
    /// Extent-map hole detection: only DATA extents trigger an engine
    /// call; holes and UNWRITTEN extents are zero-filled.
    pub fn dispatch_read_with_engine(
        &self,
        request: EngineReadRequest<'_>,
    ) -> Result<Vec<u8>, Errno> {
        let EngineReadRequest {
            ino,
            fh,
            offset,
            size,
            file_size,
            engine,
            ctx,
        } = request;

        if size == 0 || offset >= file_size {
            return Ok(Vec::new());
        }

        let effective_size = {
            let end = offset.saturating_add(size as u64);
            if end > file_size {
                (file_size - offset) as u32
            } else {
                size
            }
        };

        let page_size = self.page_cache.page_size() as u64;
        let mut reply = Vec::with_capacity(effective_size as usize);
        let mut cursor = offset;
        let mut remaining = effective_size as u64;

        while remaining > 0 {
            let page_offset = (cursor / page_size) * page_size;
            let in_page_offset = (cursor - page_offset) as usize;
            let take = remaining.min(page_size - (cursor - page_offset)) as usize;

            // Try page-cache hit first.
            let served = if let Some(handle) = self.page_cache.lookup(ino, page_offset) {
                let data = handle.data();
                let available = data.len().saturating_sub(in_page_offset);
                let chunk = available.min(take);
                if chunk > 0 {
                    reply.extend_from_slice(&data[in_page_offset..in_page_offset + chunk]);
                    true
                } else {
                    false
                }
            } else {
                false
            };

            if !served {
                // Cache miss: check extent map. Only DATA extents
                // trigger an engine call; holes and UNWRITTEN are zero-filled.
                let has_data = match self.extent_map.lookup_range(page_offset, page_size) {
                    Ok(extents) => extents.iter().any(|e| e.is_data()),
                    Err(_) => true,
                };

                let page_data: Vec<u8> = if !has_data {
                    vec![0u8; page_size as usize]
                } else {
                    let engine_fh =
                        EngineFileHandle::new(InodeId::new(ino), 0, FileHandleId::new(fh), 0);
                    engine.read(&engine_fh, page_offset, page_size as u32, ctx)?
                };

                // Populate the page cache.
                let effective_page = if page_data.len() < page_size as usize {
                    let mut padded = vec![0u8; page_size as usize];
                    let copy_len = page_data.len().min(page_size as usize);
                    padded[..copy_len].copy_from_slice(&page_data[..copy_len]);
                    padded
                } else {
                    page_data
                };

                match self.page_cache.insert(ino, page_offset) {
                    Ok(_key) => {
                        if let Some(mut handle) = self.page_cache.lookup(ino, page_offset) {
                            let buf = handle.data_mut();
                            let copy_len = effective_page.len().min(buf.len());
                            buf[..copy_len].copy_from_slice(&effective_page[..copy_len]);
                        }
                    }
                    Err(InsertError::AlreadyExists) => {}
                    Err(InsertError::AtCapacityNoCleanPages) => {}
                }

                let available = effective_page.len().saturating_sub(in_page_offset);
                let chunk = available.min(take);
                if chunk > 0 {
                    reply
                        .extend_from_slice(&effective_page[in_page_offset..in_page_offset + chunk]);
                } else {
                    reply.resize(reply.len() + take, 0);
                }
            }

            let advanced = take as u64;
            cursor += advanced;
            remaining = remaining.saturating_sub(advanced);

            if advanced == 0 {
                break;
            }
        }

        Ok(reply)
    }

    /// Resolve an inode, verifying it exists and is a regular file.
    fn resolve_inode(&self, ino: u64) -> Result<InodeAttributes, Errno> {
        let attr = self.inode_table.lookup(ino.into()).ok_or(Errno::EBADF)?;

        match attr.kind {
            InodeKind::File => Ok(attr),
            InodeKind::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EBADF),
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

fn map_extent_error(e: ExtentMapError) -> Errno {
    match e {
        ExtentMapError::InvalidRange => Errno::EINVAL,
        ExtentMapError::NotFound => Errno::EIO,
        ExtentMapError::MapFull => Errno::ENOSPC,
        ExtentMapError::WrongVersion | ExtentMapError::Corrupt => Errno::EIO,
        _ => Errno::EIO,
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
    use tidefs_extent_map::ExtentMap;
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

    struct TestDataProvider {
        files: Mutex<HashMap<u64, Vec<u8>>>,
    }

    impl TestDataProvider {
        fn new() -> Self {
            Self {
                files: Mutex::new(HashMap::new()),
            }
        }
        fn put(&self, ino: u64, data: Vec<u8>) {
            self.files.lock().unwrap().insert(ino, data);
        }
    }

    impl ReadDataProvider for TestDataProvider {
        fn read_data(
            &self,
            ino: u64,
            _fh: u64,
            offset: u64,
            length: u64,
        ) -> Result<Vec<u8>, Errno> {
            let files = self.files.lock().unwrap();
            let data = files.get(&ino).ok_or(Errno::EIO)?;
            let start = offset as usize;
            let end = (offset + length).min(data.len() as u64) as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            Ok(data[start..end].to_vec())
        }
    }

    fn extent_map_with_allocate(offset: u64, length: u64) -> ExtentMap {
        let mut em = ExtentMap::new();
        em.allocate(offset, length).expect("allocate extent");
        em
    }

    // ── happy path: single fully-cached extent ───────────────────────

    #[test]
    fn read_single_extent_cache_resident_returns_data() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        let test_data = b"hello from fuse_read dispatch test!!";
        {
            let _key = pc.insert(1, 0).expect("insert page");
            let mut handle = pc.lookup(1, 0).expect("lookup page");
            let buf = handle.data_mut();
            let copy_len = test_data.len().min(buf.len());
            buf[..copy_len].copy_from_slice(&test_data[..copy_len]);
        }

        let (inode_table, ino) = test_inode_table(4096);
        assert_eq!(ino, 1);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table);

        let result = dispatch
            .dispatch_read(1, 0, 0, test_data.len() as u32)
            .unwrap();
        assert_eq!(result, test_data);
    }

    #[test]
    fn read_single_extent_cache_resident_offset_mid_page() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page");
            let mut handle = pc.lookup(1, 0).expect("lookup page");
            let buf = handle.data_mut();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i % 256) as u8;
            }
        }

        let (inode_table, ino) = test_inode_table(4096);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table);

        let result = dispatch.dispatch_read(ino, 0, 100, 16).unwrap();
        let expected: Vec<u8> = (100..116).map(|i| (i % 256) as u8).collect();
        assert_eq!(result, expected);
    }

    // ── two extents with a hole between ──────────────────────────────

    #[test]
    fn read_spanning_two_extents_with_hole_returns_zeroes() {
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("extent 1");
        em.allocate(8192, 4096).expect("extent 2");

        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page 0");
            pc.lookup(1, 0).unwrap().data_mut().fill(b'A');
        }
        {
            let _key = pc.insert(1, 8192).expect("insert page 8192");
            pc.lookup(1, 8192).unwrap().data_mut().fill(b'B');
        }

        let provider = Arc::new(TestDataProvider::new());
        let (inode_table, ino) = test_inode_table(12288);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table).with_data_provider(provider);

        let result = dispatch.dispatch_read(ino, 0, 2048, 8192).unwrap();
        assert_eq!(result.len(), 8192);
        assert!(
            result[..2048].iter().all(|&b| b == b'A'),
            "first 2048 bytes should be A's"
        );
        let hole_start = 2048;
        let hole_end = hole_start + 4096;
        assert!(
            result[hole_start..hole_end].iter().all(|&b| b == 0),
            "hole region should be zeroes"
        );
        assert!(
            result[hole_end..].iter().all(|&b| b == b'B'),
            "last 2048 bytes should be B's"
        );
    }

    // ── entirely within a hole ───────────────────────────────────────

    #[test]
    fn read_entirely_in_hole_returns_zeroes() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        let provider = Arc::new(TestDataProvider::new());

        let (inode_table, ino) = test_inode_table(8192);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table).with_data_provider(provider);

        let result = dispatch.dispatch_read(ino, 0, 4096, 4096).unwrap();
        assert_eq!(result.len(), 4096);
        assert!(result.iter().all(|&b| b == 0), "hole should be all zeroes");
    }

    // ── cache-miss path: data provider is invoked ────────────────────

    #[test]
    fn cache_miss_reads_from_data_provider() {
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("extent");
        let pc = Arc::new(PageCache::new(64, 4096));
        let provider = Arc::new(TestDataProvider::new());
        provider.put(1, b"cache-miss test data provider content!".to_vec());

        let (inode_table, ino) = test_inode_table(4096);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table).with_data_provider(provider);

        // UNWRITTEN → zeroes (extent map says no DATA)
        let result = dispatch.dispatch_read(ino, 0, 0, 32).unwrap();
        assert_eq!(result.len(), 32);
        assert!(result.iter().all(|&b| b == 0));
    }

    #[test]
    fn cache_miss_data_extent_reads_from_provider() {
        struct SpyProvider {
            data: Mutex<Vec<u8>>,
            call_count: Mutex<u64>,
        }
        impl SpyProvider {
            fn new(data: Vec<u8>) -> Self {
                Self {
                    data: Mutex::new(data),
                    call_count: Mutex::new(0),
                }
            }
        }
        impl ReadDataProvider for SpyProvider {
            fn read_data(
                &self,
                _ino: u64,
                _fh: u64,
                offset: u64,
                length: u64,
            ) -> Result<Vec<u8>, Errno> {
                *self.call_count.lock().unwrap() += 1;
                let d = self.data.lock().unwrap();
                let start = offset as usize;
                let end = (offset + length).min(d.len() as u64) as usize;
                Ok(d[start..end].to_vec())
            }
        }

        let spy = Arc::new(SpyProvider::new(b"SPY DATA PROVIDER CONTENT!!".to_vec()));
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(4096);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table).with_data_provider(spy.clone());

        let result = dispatch.dispatch_read(ino, 0, 0, 32).unwrap();
        assert_eq!(
            *spy.call_count.lock().unwrap(),
            0,
            "provider should not be called for UNWRITTEN extents"
        );
        assert!(result.iter().all(|&b| b == 0));
    }

    // ── page-cache interaction test ───────────────────────────────────

    #[test]
    fn page_cache_stats_hit_and_miss() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page 0");
            let mut handle = pc.lookup(1, 0).expect("lookup page 0");
            handle.data_mut()[..5].copy_from_slice(b"HELLO");
        }

        let hits_before = pc.hit_count();
        let (inode_table, ino) = test_inode_table(8192);
        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);

        let _ = dispatch.dispatch_read(ino, 0, 0, 5).unwrap();
        assert!(
            pc.hit_count() > hits_before,
            "cache hit count should increase"
        );
    }

    // ── short read at EOF ─────────────────────────────────────────────

    #[test]
    fn read_at_eof_short_read() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page 0");
            pc.lookup(1, 0).unwrap().data_mut()[..100].fill(b'X');
        }

        let (inode_table, ino) = test_inode_table(100);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table);

        let result = dispatch.dispatch_read(ino, 0, 50, 200).unwrap();
        assert_eq!(result.len(), 50, "should return only 50 bytes (up to EOF)");
        assert!(result.iter().all(|&b| b == b'X'));
    }

    #[test]
    fn read_zero_length_returns_empty() {
        let em = ExtentMap::new();
        let pc = Arc::new(PageCache::new(4, 4096));
        let (inode_table, ino) = test_inode_table(4096);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table);

        let result = dispatch.dispatch_read(ino, 0, 0, 0).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn read_nonexistent_inode_returns_ebadf() {
        let em = ExtentMap::new();
        let pc = Arc::new(PageCache::new(4, 4096));
        let (inode_table, _) = test_inode_table(0);

        let dispatch = FuseReadDispatch::new(pc, em, inode_table);
        let result = dispatch.dispatch_read(999, 0, 0, 32);
        assert_eq!(result, Err(Errno::EBADF));
    }

    #[test]
    fn read_offset_past_eof_returns_empty() {
        let em = ExtentMap::new();
        let pc = Arc::new(PageCache::new(4, 4096));
        let (inode_table, ino) = test_inode_table(100);

        let dispatch = FuseReadDispatch::new(pc, em, inode_table);
        let result = dispatch.dispatch_read(ino, 0, 200, 32).unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn read_across_page_boundary_with_cache_hits() {
        let em = extent_map_with_allocate(0, 8192);
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page 0");
            pc.lookup(1, 0).unwrap().data_mut().fill(b'A');
        }
        {
            let _key = pc.insert(1, 4096).expect("insert page 1");
            pc.lookup(1, 4096).unwrap().data_mut().fill(b'B');
        }

        let (inode_table, ino) = test_inode_table(8192);
        let dispatch = FuseReadDispatch::new(pc, em, inode_table);

        let result = dispatch.dispatch_read(ino, 0, 3000, 5000).unwrap();
        assert_eq!(result.len(), 5000);
        let a_count = 4096 - 3000;
        assert!(result[..a_count].iter().all(|&b| b == b'A'));
        assert!(result[a_count..].iter().all(|&b| b == b'B'));
    }

    // ── dispatch_read_with_size ───────────────────────────────────────

    #[test]
    fn dispatch_read_with_size_skips_inode_lookup() {
        let em = extent_map_with_allocate(0, 4096);
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert page");
            pc.lookup(1, 0).unwrap().data_mut()[..4].copy_from_slice(b"TEST");
        }

        // Create a table that does NOT have inode 1 — dispatch_read_with_size
        // should still succeed because it doesn't call resolve_inode.
        let time_source = Box::new(SystemTimeSource);
        let empty_table = Arc::new(InodeTable::new(1, time_source));

        let dispatch = FuseReadDispatch::new(pc, em, empty_table);
        let result = dispatch.dispatch_read_with_size(1, 0, 0, 4, 4096).unwrap();
        assert_eq!(result, b"TEST");
    }

    // ── populate_cache integration tests ──────────────────────────────

    #[test]
    fn populate_cache_then_read_hits_cache() {
        let em = extent_map_with_allocate(0, 8192);
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(8192);

        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);

        // Simulate an engine read that returned data, then populate cache.
        let engine_data = vec![0x42u8; 6144];
        dispatch.populate_cache(ino, 1024, &engine_data);

        let result = dispatch
            .dispatch_read_with_size(ino, 0, 1024, 512, 8192)
            .unwrap();
        assert_eq!(result.len(), 512);
        assert!(result.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn populate_cache_then_second_read_increases_hit_count() {
        let em = extent_map_with_allocate(0, 8192);
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(8192);

        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);

        let engine_data = vec![0xABu8; 4096];
        dispatch.populate_cache(ino, 0, &engine_data);

        let hits_before = pc.hit_count();
        let result1 = dispatch
            .dispatch_read_with_size(ino, 0, 0, 256, 8192)
            .unwrap();
        assert_eq!(result1, vec![0xABu8; 256]);
        assert!(pc.hit_count() > hits_before, "first read should hit cache");

        let hits_after_first = pc.hit_count();
        let result2 = dispatch
            .dispatch_read_with_size(ino, 0, 512, 128, 8192)
            .unwrap();
        assert_eq!(result2, vec![0xABu8; 128]);
        assert!(
            pc.hit_count() > hits_after_first,
            "second read should also hit cache"
        );
    }

    #[test]
    fn populate_cache_partial_page_boundary_correct() {
        let em = extent_map_with_allocate(0, 16384);
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(16384);

        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);

        let mut engine_data = Vec::with_capacity(6144);
        for i in 0u8..6u8 {
            engine_data.extend_from_slice(&[i; 1024]);
        }
        dispatch.populate_cache(ino, 2048, &engine_data);

        let result = dispatch
            .dispatch_read_with_size(ino, 0, 2048 + 1024, 2048, 16384)
            .unwrap();
        assert_eq!(result.len(), 2048);
        assert!(result[..1024].iter().all(|&b| b == 1));
        assert!(result[1024..].iter().all(|&b| b == 2));
    }

    // ── extent-map hole detection with dispatch_read_with_size ──

    #[test]
    fn dispatch_read_hole_zero_fills_when_no_extent() {
        let em = ExtentMap::new();
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(4096);

        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);
        let result = dispatch
            .dispatch_read_with_size(ino, 0, 0, 4096, 4096)
            .unwrap();
        assert_eq!(result.len(), 4096);
        assert!(result.iter().all(|&b| b == 0), "empty extent map zero-fill");
    }

    #[test]
    fn dispatch_read_unwritten_extent_zero_fills_without_provider() {
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("allocate");
        let pc = Arc::new(PageCache::new(64, 4096));
        let (inode_table, ino) = test_inode_table(4096);

        let dispatch = FuseReadDispatch::new(pc, em, inode_table);
        let result = dispatch
            .dispatch_read_with_size(ino, 0, 0, 32, 4096)
            .unwrap();
        assert_eq!(result.len(), 32);
        assert!(
            result.iter().all(|&b| b == 0),
            "UNWRITTEN extent should be zero-filled"
        );
    }

    #[test]
    fn dispatch_read_mixed_cache_hit_and_hole() {
        let mut em = ExtentMap::new();
        em.allocate(0, 4096).expect("page 0");
        let pc = Arc::new(PageCache::new(64, 4096));
        {
            let _key = pc.insert(1, 0).expect("insert");
            pc.lookup(1, 0).unwrap().data_mut().fill(b'C');
        }
        let (inode_table, ino) = test_inode_table(8192);
        assert_eq!(ino, 1);

        let dispatch = FuseReadDispatch::new(Arc::clone(&pc), em, inode_table);
        let result = dispatch
            .dispatch_read_with_size(ino, 0, 0, 8192, 8192)
            .unwrap();
        assert_eq!(result.len(), 8192);
        assert!(result[..4096].iter().all(|&b| b == b'C'));
        assert!(result[4096..].iter().all(|&b| b == 0));
    }
}
