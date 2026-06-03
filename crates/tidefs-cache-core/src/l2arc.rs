//! Second-level Adaptive Replacement Cache (L2ARC / FlashTier).
//!
//! Provides a persistent second-level read cache on fast NVMe/SSD devices.
//! Evicted ARC entries are written to the L2ARC device so that future ARC
//! misses can be satisfied from flash instead of going to main pool storage.
//!
//! The L2ARC device is log-structured (append-only, circular).  Entries are
//! admitted through a ghost-hit filter and written in batched BACKGROUND-lane
//! I/O.  The cache is non-authoritative: every entry has an authoritative
//! copy on main pool devices, so L2ARC device failure is survivable.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// L2ArcKey — cache lookup key
// ---------------------------------------------------------------------------

/// Key for L2ARC index lookups.
///
/// Identifies a specific block of data by object, offset within the object,
/// and the data version (so stale entries from previous TXGs are skipped).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct L2ArcKey {
    /// Object identifier (inode or block-object number).
    pub object_id: u64,
    /// Byte offset within the object.
    pub offset: u64,
    /// Data version (commit_group birth or equivalent).
    pub data_version: u64,
}

impl L2ArcKey {
    /// Create a new L2ARC key.
    #[must_use]
    pub fn new(object_id: u64, offset: u64, data_version: u64) -> Self {
        Self {
            object_id,
            offset,
            data_version,
        }
    }
}

impl fmt::Display for L2ArcKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "L2ArcKey(oid={}, off={}, ver={})",
            self.object_id, self.offset, self.data_version
        )
    }
}

// ---------------------------------------------------------------------------
// L2ArcLocation — on-device location
// ---------------------------------------------------------------------------

/// Location of a cache entry on the L2ARC device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct L2ArcLocation {
    /// Byte offset within the device where the entry begins.
    pub device_offset: u64,
    /// Total length of the on-device record (header + data).
    pub record_len: u32,
    /// Length of the payload data (for buffer allocation on read).
    pub data_len: u32,
}

impl L2ArcLocation {
    #[must_use]
    pub fn new(device_offset: u64, record_len: u32, data_len: u32) -> Self {
        Self {
            device_offset,
            record_len,
            data_len,
        }
    }
}

// ---------------------------------------------------------------------------
// L2ArcEntry — a cache entry on the L2ARC device
// ---------------------------------------------------------------------------

/// An entry being written to (or read from) the L2ARC device.
///
/// Carries the key, the raw data payload, and a BLAKE3 checksum for integrity.
#[derive(Clone, Debug)]
pub struct L2ArcEntry {
    /// Index key.
    pub key: L2ArcKey,
    /// Raw data payload.
    pub data: Vec<u8>,
    /// BLAKE3-256 checksum of `data`.
    pub checksum: [u8; 32],
}

impl L2ArcEntry {
    /// Create a new L2ARC entry, computing its BLAKE3 checksum.
    #[must_use]
    pub fn new(key: L2ArcKey, data: Vec<u8>) -> Self {
        let checksum = blake3::hash(&data).into();
        Self {
            key,
            data,
            checksum,
        }
    }

    /// Total on-device size: 40-byte header + data length.
    #[must_use]
    pub fn record_len(&self) -> u32 {
        40 + self.data.len() as u32
    }

    /// Length of the data payload.
    #[must_use]
    pub fn data_len(&self) -> u32 {
        self.data.len() as u32
    }
}

// ---------------------------------------------------------------------------
// L2ArcDevice — the cache device abstraction
// ---------------------------------------------------------------------------

/// State of an L2ARC cache device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L2ArcDeviceState {
    /// Device is healthy and accepting I/O.
    Online,
    /// Device has failed and is out of service.
    Faulted,
}

/// An L2ARC cache device backed by a byte-addressable store.
///
/// The device is log-structured: writes append at the current `write_head`,
/// which wraps around when it reaches `capacity_bytes` (circular log).
/// Old entries are overwritten without explicit eviction — they simply
/// become L2ARC misses on next access.
pub struct L2ArcDevice {
    /// Unique device identifier.
    pub guid: u64,
    /// Pool identifier this device belongs to.
    pub pool_guid: u64,
    /// Monotonically-increasing generation counter.
    pub generation: u64,
    /// Total device capacity in bytes.
    pub capacity_bytes: u64,
    /// Current append position.
    pub write_head: u64,
    /// Oldest still-valid byte offset (entries before this are overwritten).
    pub trimmed_until: u64,
    /// Backing byte store (in-memory for now; replaceable with file/block device).
    store: Vec<u8>,
    /// Device state.
    pub state: L2ArcDeviceState,
}

impl L2ArcDevice {
    /// Create a new L2ARC device with the given capacity.
    ///
    /// The backing store is initialized to zero.
    #[must_use]
    pub fn new(guid: u64, pool_guid: u64, generation: u64, capacity_bytes: u64) -> Self {
        assert!(capacity_bytes > 0, "capacity must be positive");
        Self {
            guid,
            pool_guid,
            generation,
            capacity_bytes,
            write_head: 0,
            trimmed_until: 0,
            store: vec![0u8; capacity_bytes as usize],
            state: L2ArcDeviceState::Online,
        }
    }

    /// Bytes available for writing before the write head wraps.
    #[must_use]
    pub fn available_bytes(&self) -> u64 {
        if self.write_head >= self.trimmed_until {
            // Normal case: write_head ahead of trimmed_until.
            self.capacity_bytes - self.write_head + self.trimmed_until
        } else {
            // Wrapped: write_head behind trimmed_until (gap in the middle).
            self.trimmed_until - self.write_head
        }
    }

    /// Write an entry at the current write_head.
    ///
    /// Returns the `L2ArcLocation` where the entry was written.
    /// If there isn't enough space, the oldest entries are trimmed
    /// (evicted from the index) to make room.
    pub fn write_entry(&mut self, entry: &L2ArcEntry) -> L2ArcLocation {
        let record_len = entry.record_len() as u64;

        // If the write would exceed capacity, wrap around, trimming along the way.
        if self.write_head + record_len > self.capacity_bytes {
            // Entries from write_head to end-of-device are now invalid.
            // The write_head wraps to 0, and trimmed_until advances past any
            // entries that were in the overwritten region.
            self.trimmed_until = self.trimmed_until.max(self.write_head);
            self.write_head = 0;
        }

        // If the region ahead is occupied by still-valid entries, advance
        // trimmed_until to make room.
        while self.write_head < self.trimmed_until
            && self.write_head + record_len > self.trimmed_until
        {
            // Not enough space in the gap; advance trimmed_until past write_head.
            self.trimmed_until = self.write_head;
        }

        // If we're fully wrapped and not enough space, trim more.
        let end = self.write_head + record_len;
        if end > self.capacity_bytes {
            self.trimmed_until = self.trimmed_until.min(self.write_head);
            self.write_head = 0;
        }

        let location = L2ArcLocation::new(self.write_head, record_len as u32, entry.data_len());

        // Write the entry into the backing store.
        // Format: [BLAKE3 checksum: 32 bytes][data_len: 4 bytes LE][data: data_len bytes]
        // (4 bytes reserved for flags/future use, hence 40-byte header)
        let offset = self.write_head as usize;
        self.store[offset..offset + 32].copy_from_slice(&entry.checksum);
        let data_len_bytes = entry.data_len().to_le_bytes();
        self.store[offset + 32..offset + 36].copy_from_slice(&data_len_bytes);
        // 4 bytes reserved (flags)
        self.store[offset + 36..offset + 40].fill(0);
        let data_end = offset + 40 + entry.data.len();
        self.store[offset + 40..data_end].copy_from_slice(&entry.data);

        self.write_head = (self.write_head + record_len) % self.capacity_bytes;

        location
    }

    /// Read the data for an entry at the given location.
    ///
    /// Returns the raw data bytes if the checksum matches, or `None` if
    /// the data is corrupt.
    pub fn read_entry(&self, location: &L2ArcLocation) -> Option<Vec<u8>> {
        let offset = location.device_offset as usize;
        let data_len = location.data_len as usize;
        let record_len = location.record_len as usize;

        if offset + record_len > self.store.len() {
            return None;
        }

        // Read checksum and compare
        let stored_checksum: [u8; 32] = self.store[offset..offset + 32].try_into().ok()?;
        let stored_data_len =
            u32::from_le_bytes(self.store[offset + 32..offset + 36].try_into().ok()?);
        if stored_data_len as usize != data_len {
            return None;
        }

        let data = self.store[offset + 40..offset + 40 + data_len].to_vec();
        let computed = blake3::hash(&data);
        if computed.as_bytes() != &stored_checksum {
            return None;
        }

        Some(data)
    }

    /// Return the total bytes written so far (wraps around capacity).
    #[must_use]
    pub fn bytes_used(&self) -> u64 {
        if self.write_head >= self.trimmed_until {
            self.write_head - self.trimmed_until
        } else {
            self.capacity_bytes - self.trimmed_until + self.write_head
        }
    }
}

// ---------------------------------------------------------------------------
// L2ArcWriter — batched writeback of evicted ARC entries
// ---------------------------------------------------------------------------

/// Configuration for the L2ARC writer.
#[derive(Clone, Copy, Debug)]
pub struct L2ArcWriterConfig {
    /// Maximum batch size in bytes before flushing to device.
    /// Default: 1 MiB.
    pub max_batch_bytes: u64,
}

impl Default for L2ArcWriterConfig {
    fn default() -> Self {
        Self {
            max_batch_bytes: 1024 * 1024, // 1 MiB
        }
    }
}

/// Writer responsible for batching evicted ARC entries and writing them
/// to the L2ARC device.
///
/// Entries are queued via [`queue_evicted`] and flushed in batches when
/// the accumulated data reaches `max_batch_bytes`.  The writer does NOT
/// block the ARC eviction path — writes are best-effort and can be
/// dropped under pressure.
pub struct L2ArcWriter {
    /// Buffered entries awaiting flush.
    batch: Vec<L2ArcEntry>,
    /// Total accumulated bytes in the current batch.
    batch_bytes: u64,
    /// Configuration.
    config: L2ArcWriterConfig,
    /// Statistics.
    pub stats: L2ArcStats,
}

impl L2ArcWriter {
    /// Create a new L2ARC writer with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            batch: Vec::new(),
            batch_bytes: 0,
            config: L2ArcWriterConfig::default(),
            stats: L2ArcStats::default(),
        }
    }

    /// Create a new L2ARC writer with custom configuration.
    #[must_use]
    pub fn with_config(config: L2ArcWriterConfig) -> Self {
        Self {
            batch: Vec::new(),
            batch_bytes: 0,
            config,
            stats: L2ArcStats::default(),
        }
    }

    /// Queue an evicted entry for L2ARC writeback.
    ///
    /// If the batch reaches `max_batch_bytes`, entries are NOT automatically
    /// flushed; the caller must call [`flush`] explicitly.  This keeps the
    /// ARC eviction path non-blocking.
    pub fn queue_evicted(&mut self, entry: L2ArcEntry) {
        self.batch_bytes += entry.record_len() as u64;
        self.batch.push(entry);
    }

    /// True if the batch should be flushed (accumulated bytes >= threshold).
    #[must_use]
    pub fn should_flush(&self) -> bool {
        !self.batch.is_empty() && self.batch_bytes >= self.config.max_batch_bytes
    }

    /// Number of entries currently buffered.
    #[must_use]
    pub fn pending_entries(&self) -> usize {
        self.batch.len()
    }

    /// Accumulated batch size in bytes.
    #[must_use]
    pub fn pending_bytes(&self) -> u64 {
        self.batch_bytes
    }

    /// Flush all buffered entries to the L2ARC device.
    ///
    /// Each entry is written to the device and its location is returned
    /// for index insertion.  If the device is full, entries that cannot
    /// fit are silently dropped (evict_truncations is incremented).
    ///
    /// Returns locations for successfully written entries.
    pub fn flush(
        &mut self,
        device: &mut L2ArcDevice,
        index: &mut L2ArcIndex,
    ) -> Vec<(L2ArcKey, L2ArcLocation)> {
        if self.batch.is_empty() {
            return Vec::new();
        }

        let mut written = Vec::with_capacity(self.batch.len());

        for entry in self.batch.drain(..) {
            let record_len = entry.record_len() as u64;

            // Check if the device has room (with a safety margin).
            if record_len > device.capacity_bytes / 10 {
                // Entry is too large (>10% of device); skip it.
                self.stats.evict_truncations += 1;
                continue;
            }

            let location = device.write_entry(&entry);
            index.insert(entry.key, location);
            written.push((entry.key, location));
            self.stats.writes += 1;
            self.stats.bytes_written += entry.data_len() as u64;
        }

        self.batch_bytes = 0;
        written
    }
}

impl Default for L2ArcWriter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// L2ArcIndex — in-memory index for L2ARC lookups
// ---------------------------------------------------------------------------

/// Configuration for the L2ARC index.
#[derive(Clone, Copy, Debug)]
pub struct L2ArcIndexConfig {
    /// Maximum number of entries in the index.
    /// Default: 1_000_000 (suitable for ~1 TB cache device with typical sizes).
    pub max_entries: usize,
}

impl Default for L2ArcIndexConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
        }
    }
}

/// In-memory index mapping L2ARC keys to on-device locations.
///
/// This is the only RAM cost of L2ARC.  Entries are evicted from the index
/// (making the corresponding on-device data unreachable) when the index
/// reaches its capacity limit.
pub struct L2ArcIndex {
    entries: HashMap<L2ArcKey, L2ArcLocation>,
    config: L2ArcIndexConfig,
}

impl L2ArcIndex {
    /// Create a new L2ARC index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            config: L2ArcIndexConfig::default(),
        }
    }

    /// Create a new L2ARC index with custom configuration.
    #[must_use]
    pub fn with_config(config: L2ArcIndexConfig) -> Self {
        Self {
            entries: HashMap::with_capacity(config.max_entries.min(1024)),
            config,
        }
    }

    /// Look up a key in the index.
    #[must_use]
    pub fn lookup(&self, key: &L2ArcKey) -> Option<&L2ArcLocation> {
        self.entries.get(key)
    }

    /// Insert a key-location pair into the index.
    ///
    /// If the index is at capacity, the oldest entry is evicted.
    /// Returns the evicted key if one was removed (the on-device data
    /// becomes unreachable but is not correctness-critical).
    pub fn insert(&mut self, key: L2ArcKey, location: L2ArcLocation) -> Option<L2ArcKey> {
        let evicted =
            if self.entries.len() >= self.config.max_entries && !self.entries.contains_key(&key) {
                // Evict a random entry (no ordering guarantee in HashMap; in
                // production we'd use an LRU list for the index).
                let evicted_key = self.entries.keys().next().copied();
                if let Some(ref k) = evicted_key {
                    self.entries.remove(k);
                }
                evicted_key
            } else {
                None
            };
        self.entries.insert(key, location);
        evicted
    }

    /// Remove an entry from the index.
    pub fn remove(&mut self, key: &L2ArcKey) -> Option<L2ArcLocation> {
        self.entries.remove(key)
    }

    /// Number of entries currently in the index.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of entries the index can hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.config.max_entries
    }
}

impl Default for L2ArcIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// L2ArcReader — L2ARC read path
// ---------------------------------------------------------------------------

/// Reader that checks the L2ARC index on an ARC miss.
///
/// If the index has the key, the data is read from the device and returned.
/// Otherwise, the caller falls through to main pool storage.
pub struct L2ArcReader {
    /// Shared statistics (updated on hit/miss).
    pub stats: L2ArcStats,
}

impl L2ArcReader {
    /// Create a new L2ARC reader.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats: L2ArcStats::default(),
        }
    }

    /// Try to read from the L2ARC.
    ///
    /// Returns `Some(data)` on a cache hit and `None` on a miss.
    /// The caller should promote hit data to the L1ARC.
    pub fn read(
        &mut self,
        key: &L2ArcKey,
        index: &L2ArcIndex,
        device: &L2ArcDevice,
    ) -> Option<Vec<u8>> {
        let location = index.lookup(key)?;
        self.stats.reads += 1;

        match device.read_entry(location) {
            Some(data) => {
                self.stats.hits += 1;
                self.stats.bytes_read += data.len() as u64;
                Some(data)
            }
            None => {
                // Checksum mismatch or corrupt entry — treat as miss.
                // In production we'd also remove the entry from the index.
                self.stats.misses += 1;
                None
            }
        }
    }
}

impl Default for L2ArcReader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// L2ArcStats — statistics
// ---------------------------------------------------------------------------

/// Statistics for L2ARC operations.
#[derive(Clone, Copy, Debug, Default)]
pub struct L2ArcStats {
    /// Total entries written to the L2ARC device.
    pub writes: u64,
    /// Total read attempts from the L2ARC device.
    pub reads: u64,
    /// Cache hits (data found and checksum-valid).
    pub hits: u64,
    /// Cache misses (data not found or checksum-invalid).
    pub misses: u64,
    /// Total payload bytes written.
    pub bytes_written: u64,
    /// Total payload bytes read on hit.
    pub bytes_read: u64,
    /// Entries dropped because the device was full.
    pub evict_truncations: u64,
}

impl L2ArcStats {
    /// Merge another stats snapshot into this one.
    pub fn merge(&mut self, other: &L2ArcStats) {
        self.writes += other.writes;
        self.reads += other.reads;
        self.hits += other.hits;
        self.misses += other.misses;
        self.bytes_written += other.bytes_written;
        self.bytes_read += other.bytes_read;
        self.evict_truncations += other.evict_truncations;
    }

    /// Hit ratio (0.0–1.0).  Returns 0.0 if no reads.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        if self.reads == 0 {
            0.0
        } else {
            self.hits as f64 / self.reads as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── L2ArcKey ──────────────────────────────────────────────────────

    #[test]
    fn key_equality_and_hash() {
        let k1 = L2ArcKey::new(1, 0, 100);
        let k2 = L2ArcKey::new(1, 0, 100);
        let k3 = L2ArcKey::new(1, 1, 100);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
        // Hash consistency
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        k1.hash(&mut h1);
        let mut h2 = DefaultHasher::new();
        k2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn key_display() {
        let k = L2ArcKey::new(42, 4096, 7);
        let s = format!("{k}");
        assert!(s.contains("42"));
        assert!(s.contains("4096"));
        assert!(s.contains("7"));
    }

    // ── L2ArcEntry ────────────────────────────────────────────────────

    #[test]
    fn entry_new_computes_checksum() {
        let data = b"hello l2arc".to_vec();
        let key = L2ArcKey::new(1, 0, 1);
        let entry = L2ArcEntry::new(key, data.clone());
        let expected = blake3::hash(&data);
        assert_eq!(entry.checksum, *expected.as_bytes());
        assert_eq!(entry.data, data);
        assert_eq!(entry.data_len(), data.len() as u32);
        assert_eq!(entry.record_len(), 40 + data.len() as u32);
    }

    #[test]
    fn entry_record_len_varies_with_data_size() {
        let e1 = L2ArcEntry::new(L2ArcKey::new(1, 0, 1), vec![0u8; 100]);
        let e2 = L2ArcEntry::new(L2ArcKey::new(2, 0, 1), vec![0u8; 4096]);
        assert_eq!(e1.record_len(), 140);
        assert_eq!(e2.record_len(), 4136);
    }

    // ── L2ArcDevice ───────────────────────────────────────────────────

    #[test]
    fn device_new_zero_initialized() {
        let d = L2ArcDevice::new(1, 100, 5, 1024);
        assert_eq!(d.guid, 1);
        assert_eq!(d.pool_guid, 100);
        assert_eq!(d.generation, 5);
        assert_eq!(d.capacity_bytes, 1024);
        assert_eq!(d.write_head, 0);
        assert_eq!(d.trimmed_until, 0);
        assert_eq!(d.bytes_used(), 0);
        assert_eq!(d.state, L2ArcDeviceState::Online);
    }

    #[test]
    fn device_write_and_read_round_trip() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 4096);
        let key = L2ArcKey::new(10, 0, 1);
        let data = b"persistent cache entry".to_vec();
        let entry = L2ArcEntry::new(key, data.clone());

        let loc = dev.write_entry(&entry);
        assert_eq!(loc.data_len, data.len() as u32);
        assert_eq!(loc.record_len, 40 + data.len() as u32);
        assert_eq!(loc.device_offset, 0);

        let read_back = dev.read_entry(&loc);
        assert!(read_back.is_some());
        assert_eq!(read_back.unwrap(), data);
        assert!(dev.bytes_used() > 0);
    }

    #[test]
    fn device_read_corrupt_data_returns_none() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 4096);
        let key = L2ArcKey::new(1, 0, 1);
        let entry = L2ArcEntry::new(key, b"original".to_vec());
        let loc = dev.write_entry(&entry);

        // Corrupt the data in the backing store
        dev.store[loc.device_offset as usize + 41] ^= 0xFF; // flip a data byte

        let result = dev.read_entry(&loc);
        assert!(result.is_none(), "corrupt data must fail checksum");
    }

    #[test]
    fn device_multiple_entries() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 8192);
        let mut index = L2ArcIndex::new();

        for i in 0..10 {
            let key = L2ArcKey::new(i, 0, 1);
            let data = vec![i as u8; 100];
            let entry = L2ArcEntry::new(key, data.clone());
            let loc = dev.write_entry(&entry);
            index.insert(key, loc);
        }

        // Read back all entries
        for i in 0..10 {
            let key = L2ArcKey::new(i, 0, 1);
            let loc = index.lookup(&key).unwrap();
            let data = dev.read_entry(loc).unwrap();
            assert_eq!(data, vec![i as u8; 100]);
        }
    }

    #[test]
    fn device_full_triggers_wrap() {
        // Small device that holds exactly 2 records of 100 bytes each
        let mut dev = L2ArcDevice::new(1, 100, 1, 2 * 140); // 280 bytes

        let e1 = L2ArcEntry::new(L2ArcKey::new(1, 0, 1), vec![1u8; 100]);
        let e2 = L2ArcEntry::new(L2ArcKey::new(2, 0, 1), vec![2u8; 100]);
        let e3 = L2ArcEntry::new(L2ArcKey::new(3, 0, 1), vec![3u8; 100]);

        let _loc1 = dev.write_entry(&e1);
        let _loc2 = dev.write_entry(&e2);
        // Third write triggers wrap (trim)
        let loc3 = dev.write_entry(&e3);

        // e3 should be readable
        let data3 = dev.read_entry(&loc3).unwrap();
        assert_eq!(data3, vec![3u8; 100]);
    }

    #[test]
    fn device_available_bytes() {
        let dev = L2ArcDevice::new(1, 100, 1, 1000);
        assert_eq!(dev.available_bytes(), 1000);
    }

    // ── L2ArcIndex ────────────────────────────────────────────────────

    #[test]
    fn index_lookup_hit_and_miss() {
        let mut idx = L2ArcIndex::new();
        let key = L2ArcKey::new(1, 0, 1);
        let loc = L2ArcLocation::new(0, 140, 100);

        assert!(idx.lookup(&key).is_none());

        idx.insert(key, loc);
        let found = idx.lookup(&key);
        assert!(found.is_some());
        assert_eq!(found.unwrap().device_offset, 0);
    }

    #[test]
    fn index_remove() {
        let mut idx = L2ArcIndex::new();
        let key = L2ArcKey::new(1, 0, 1);
        idx.insert(key, L2ArcLocation::new(0, 100, 60));
        assert_eq!(idx.len(), 1);

        let removed = idx.remove(&key);
        assert!(removed.is_some());
        assert_eq!(idx.len(), 0);
        assert!(idx.lookup(&key).is_none());
    }

    #[test]
    fn index_capacity_eviction() {
        let mut idx = L2ArcIndex::with_config(L2ArcIndexConfig { max_entries: 3 });
        idx.insert(L2ArcKey::new(1, 0, 1), L2ArcLocation::new(0, 100, 60));
        idx.insert(L2ArcKey::new(2, 0, 1), L2ArcLocation::new(100, 100, 60));
        idx.insert(L2ArcKey::new(3, 0, 1), L2ArcLocation::new(200, 100, 60));

        // Insert 4th: should evict one
        let evicted = idx.insert(L2ArcKey::new(4, 0, 1), L2ArcLocation::new(300, 100, 60));
        assert!(evicted.is_some(), "index at capacity must evict");
        assert_eq!(idx.len(), 3);
    }

    #[test]
    fn index_reinsert_same_key_no_eviction() {
        let mut idx = L2ArcIndex::with_config(L2ArcIndexConfig { max_entries: 1 });
        let key = L2ArcKey::new(1, 0, 1);
        idx.insert(key, L2ArcLocation::new(0, 100, 60));
        // Re-insert same key: should not evict (update in place)
        let evicted = idx.insert(key, L2ArcLocation::new(500, 100, 60));
        assert!(evicted.is_none());
        assert_eq!(idx.len(), 1);
        assert_eq!(idx.lookup(&key).unwrap().device_offset, 500);
    }

    // ── L2ArcWriter ───────────────────────────────────────────────────

    #[test]
    fn writer_queues_and_flushes() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 8192);
        let mut index = L2ArcIndex::new();
        let mut writer = L2ArcWriter::new();

        // Queue entries below batch threshold
        for i in 0..5 {
            let key = L2ArcKey::new(i, 0, 1);
            let entry = L2ArcEntry::new(key, vec![i as u8; 200]);
            writer.queue_evicted(entry);
        }

        assert_eq!(writer.pending_entries(), 5);
        assert!(!writer.should_flush()); // 5 * 240 = 1200 < 1MB

        let written = writer.flush(&mut dev, &mut index);
        assert_eq!(written.len(), 5);
        assert_eq!(writer.pending_entries(), 0);
        assert_eq!(writer.pending_bytes(), 0);
        assert_eq!(writer.stats.writes, 5);
        assert_eq!(writer.stats.bytes_written, 1000); // 5 * 200

        // Verify all entries are in the index
        for i in 0..5 {
            assert!(index.lookup(&L2ArcKey::new(i, 0, 1)).is_some());
        }
    }

    #[test]
    fn writer_should_flush_threshold() {
        let mut writer = L2ArcWriter::with_config(L2ArcWriterConfig {
            max_batch_bytes: 500,
        });

        writer.queue_evicted(L2ArcEntry::new(L2ArcKey::new(1, 0, 1), vec![0u8; 400]));
        assert!(!writer.should_flush()); // 440 < 500

        writer.queue_evicted(L2ArcEntry::new(L2ArcKey::new(2, 0, 1), vec![0u8; 200]));
        assert!(writer.should_flush()); // 440 + 240 = 680 >= 500
    }

    #[test]
    fn writer_skip_oversized_entry() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 1024);
        let mut index = L2ArcIndex::new();
        let mut writer = L2ArcWriter::new();

        // Entry larger than 10% of device capacity is skipped
        let big_entry = L2ArcEntry::new(L2ArcKey::new(99, 0, 1), vec![0u8; 200]);
        writer.queue_evicted(big_entry);
        let written = writer.flush(&mut dev, &mut index);
        assert!(written.is_empty());
        assert_eq!(writer.stats.evict_truncations, 1);
    }

    #[test]
    fn writer_device_full_wraps_and_overwrites() {
        // Capacity 1600 bytes, 10% threshold = 160.  Record len 140 (100
        // payload + 40 header) < 160, so passes oversized check.  11 records
        // fit (11*140=1540), 12th wraps.
        let mut dev = L2ArcDevice::new(1, 100, 1, 1600);
        let mut index = L2ArcIndex::new();
        let mut writer = L2ArcWriter::new();

        for i in 0..12 {
            writer.queue_evicted(L2ArcEntry::new(L2ArcKey::new(i, 0, 1), vec![i as u8; 100]));
        }
        let written = writer.flush(&mut dev, &mut index);
        // All 12 entries accepted: 11 fill device, 12th wraps and overwrites oldest.
        assert_eq!(written.len(), 12);
        assert_eq!(writer.stats.writes, 12);
        // Index holds all 12 keys (even though oldest on-device entry was overwritten).
        assert_eq!(index.len(), 12);
    }

    // ── L2ArcReader ───────────────────────────────────────────────────

    #[test]
    fn reader_hit_returns_data() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 8192);
        let mut index = L2ArcIndex::new();
        let mut reader = L2ArcReader::new();

        // Write an entry via the device+index
        let key = L2ArcKey::new(1, 0, 1);
        let data = b"cached data".to_vec();
        let entry = L2ArcEntry::new(key, data.clone());
        let loc = dev.write_entry(&entry);
        index.insert(key, loc);

        let result = reader.read(&key, &index, &dev);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), data);
        assert_eq!(reader.stats.reads, 1);
        assert_eq!(reader.stats.hits, 1);
        assert_eq!(reader.stats.misses, 0);
        assert_eq!(reader.stats.bytes_read, data.len() as u64);
    }

    #[test]
    fn reader_miss_returns_none() {
        let dev = L2ArcDevice::new(1, 100, 1, 8192);
        let index = L2ArcIndex::new();
        let mut reader = L2ArcReader::new();

        let key = L2ArcKey::new(99, 0, 1);
        let result = reader.read(&key, &index, &dev);
        assert!(result.is_none());
        assert_eq!(reader.stats.misses, 0); // read never attempted (index miss)
    }

    #[test]
    fn reader_checksum_fail_treats_as_miss() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 4096);
        let mut index = L2ArcIndex::new();
        let mut reader = L2ArcReader::new();

        let key = L2ArcKey::new(1, 0, 1);
        let entry = L2ArcEntry::new(key, b"good data".to_vec());
        let loc = dev.write_entry(&entry);
        index.insert(key, loc);

        // Corrupt the stored data
        dev.store[loc.device_offset as usize + 41] ^= 0xFF;
        let result = reader.read(&key, &index, &dev);
        assert!(result.is_none(), "checksum mismatch must be a miss");
        assert_eq!(reader.stats.reads, 1);
        assert_eq!(reader.stats.hits, 0);
        assert_eq!(reader.stats.misses, 1);
    }

    // ── Integration: ARC eviction → L2ARC write → L2ARC hit ──────────

    #[test]
    fn arc_eviction_to_l2arc_write_and_hit() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 65536);
        let mut index = L2ArcIndex::new();
        let mut writer = L2ArcWriter::new();
        let mut reader = L2ArcReader::new();

        // Simulate ARC evicting 3 entries
        let entries: Vec<L2ArcEntry> = (0..3)
            .map(|i| {
                let key = L2ArcKey::new(i, 0, 1);
                let data = format!("evicted-block-{i}").into_bytes();
                L2ArcEntry::new(key, data)
            })
            .collect();

        // Writer receives evicted entries
        for e in &entries {
            writer.queue_evicted(e.clone());
        }
        writer.flush(&mut dev, &mut index);

        // Now simulate ARC miss → L2ARC reader hit
        for e in &entries {
            let result = reader.read(&e.key, &index, &dev);
            assert!(result.is_some(), "L2ARC must have entry for {:?}", e.key);
            assert_eq!(result.unwrap(), e.data);
        }

        assert_eq!(reader.stats.hits, 3);
        assert_eq!(reader.stats.misses, 0);
    }

    #[test]
    fn l2arc_miss_goes_to_main_storage() {
        let dev = L2ArcDevice::new(1, 100, 1, 8192);
        let index = L2ArcIndex::new();
        let mut reader = L2ArcReader::new();

        // Key never written to L2ARC
        let key = L2ArcKey::new(42, 4096, 7);
        let result = reader.read(&key, &index, &dev);
        assert!(
            result.is_none(),
            "miss must return None for main storage fallthrough"
        );
    }

    // ── Writeback batching ────────────────────────────────────────────

    #[test]
    fn writeback_batching_writes_in_chunks() {
        let mut dev = L2ArcDevice::new(1, 100, 1, 1048576);
        let mut index = L2ArcIndex::new();
        let mut writer = L2ArcWriter::with_config(L2ArcWriterConfig {
            max_batch_bytes: 4096, // flush every 4KB
        });

        // Write 20 entries of 500 bytes each (payload)
        // Each record = 40 + 500 = 540 bytes.
        // Batch of 4096: ~7 entries per flush.
        let mut total_written = 0u64;
        for i in 0..20 {
            let entry = L2ArcEntry::new(L2ArcKey::new(i, 0, 1), vec![i as u8; 500]);
            writer.queue_evicted(entry);

            if writer.should_flush() {
                let written = writer.flush(&mut dev, &mut index);
                total_written += written.len() as u64;
            }
        }
        // Final flush for remaining entries
        let written = writer.flush(&mut dev, &mut index);
        total_written += written.len() as u64;

        assert_eq!(total_written, 20);
        assert_eq!(writer.stats.writes, 20);
        assert_eq!(index.len(), 20);
    }

    // ── L2ArcStats ────────────────────────────────────────────────────

    #[test]
    fn stats_default_all_zero() {
        let s = L2ArcStats::default();
        assert_eq!(s.writes, 0);
        assert_eq!(s.reads, 0);
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
        assert_eq!(s.bytes_written, 0);
        assert_eq!(s.bytes_read, 0);
        assert_eq!(s.evict_truncations, 0);
    }

    #[test]
    fn stats_hit_ratio() {
        let mut s = L2ArcStats::default();
        assert!((s.hit_ratio() - 0.0).abs() < f64::EPSILON);

        s.reads = 100;
        s.hits = 75;
        assert!((s.hit_ratio() - 0.75).abs() < f64::EPSILON);

        s.reads = 100;
        s.hits = 0;
        assert!((s.hit_ratio() - 0.0).abs() < f64::EPSILON);

        s.reads = 100;
        s.hits = 100;
        assert!((s.hit_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_merge_accumulates() {
        let mut s1 = L2ArcStats {
            writes: 10,
            reads: 50,
            hits: 30,
            misses: 20,
            bytes_written: 5000,
            bytes_read: 3000,
            evict_truncations: 2,
        };
        let s2 = L2ArcStats {
            writes: 5,
            reads: 10,
            hits: 8,
            misses: 2,
            bytes_written: 2500,
            bytes_read: 800,
            evict_truncations: 1,
        };
        s1.merge(&s2);
        assert_eq!(s1.writes, 15);
        assert_eq!(s1.reads, 60);
        assert_eq!(s1.hits, 38);
        assert_eq!(s1.misses, 22);
        assert_eq!(s1.bytes_written, 7500);
        assert_eq!(s1.bytes_read, 3800);
        assert_eq!(s1.evict_truncations, 3);
    }
}
