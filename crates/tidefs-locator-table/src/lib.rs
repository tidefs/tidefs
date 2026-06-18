// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! V1 inline-hash locator table: O(1) logical-offset-to-physical-extent
//! mapping and O(1) extent_id-to-entry reverse lookup, both persisted
//! in the object store.
//!
//! Each inode's mapping is stored as a single blob with two
//! open-addressing hash regions: a primary region keyed by
//! `logical_offset` and a secondary region keyed by `extent_id`.
//! Both use the same slot format with `u64::MAX` as the empty sentinel
//! and `u64::MAX - 1` as the tombstone sentinel.  Growth is
//! caller-initiated and rehashes both regions.

mod extent_id;
#[allow(dead_code)]
mod locator_table_types;
#[allow(dead_code)]
mod spec;

pub use extent_id::ExtentId;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError};

// ── Constants ───────────────────────────────────────────────────

/// Blob format version byte.
const FORMAT_VERSION: u8 = 2;

/// Sentinel `logical_offset` for an empty slot.
const EMPTY_SENTINEL: u64 = u64::MAX;

/// Sentinel `logical_offset` for a tombstone slot (deleted entry).
const TOMBSTONE_SENTINEL: u64 = u64::MAX - 1;

/// Maximum load factor numerator / denominator before `insert`
/// returns `WouldGrow`.
const MAX_LOAD_NUM: usize = 7;
const MAX_LOAD_DEN: usize = 10;

/// Default initial capacity (number of slots) for a new table.
const DEFAULT_CAPACITY: usize = 16;

/// Size of one serialized `LocatorEntry` in bytes (packed, no padding).
const ENTRY_BYTES: usize = 69; // v2: device_id + checksum, packed
const ENTRY_BYTES_V1: usize = 29; // v1: no checksum

/// Blob key prefix for locator tables.
const KEY_PREFIX: &[u8] = b"loctab:v1:";

// ── LocatorEntry ────────────────────────────────────────────────

/// One slot in the open-addressing hash table.
///
/// An empty slot has `logical_offset == u64::MAX`.
/// A tombstone slot has `logical_offset == u64::MAX - 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocatorEntry {
    /// Logical byte offset within the file (the hash key for the
    /// primary region).
    pub logical_offset: u64,
    /// Pool-wide unique extent identifier.
    pub extent_id: ExtentId,
    /// Device identifier for the underlying block device.
    pub device_id: u64,
    /// Physical byte offset on the underlying device.
    pub physical_offset: u64,
    /// Length of this extent in bytes.
    pub length: u32,
    /// Bit 0 = compressed, bit 1 = encrypted, bits 2-3 = checksum type.
    pub flags: u8,
    /// SHA-256 checksum of the extent payload (integrity, dedup).
    /// Zero-filled when not computed or deserializing v1 blobs.
    pub checksum: [u8; 32],
}

impl LocatorEntry {
    /// Create a new live entry.
    #[must_use]
    pub const fn new(
        logical_offset: u64,
        extent_id: ExtentId,
        device_id: u64,
        physical_offset: u64,
        length: u32,
        flags: u8,
    ) -> Self {
        Self {
            logical_offset,
            extent_id,
            device_id,
            physical_offset,
            length,
            flags,
            checksum: [0u8; 32],
        }
    }

    /// Create a new live entry with an explicit checksum.
    #[must_use]
    pub const fn with_checksum(
        logical_offset: u64,
        extent_id: ExtentId,
        device_id: u64,
        physical_offset: u64,
        length: u32,
        flags: u8,
        checksum: [u8; 32],
    ) -> Self {
        Self {
            logical_offset,
            extent_id,
            device_id,
            physical_offset,
            length,
            flags,
            checksum,
        }
    }

    /// An empty slot (sentinel: `u64::MAX`).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            logical_offset: EMPTY_SENTINEL,
            extent_id: ExtentId::NONE,
            device_id: 0,
            physical_offset: 0,
            length: 0,
            flags: 0,
            checksum: [0u8; 32],
        }
    }

    /// A tombstone slot (sentinel: `u64::MAX - 1`).
    #[must_use]
    pub const fn tombstone() -> Self {
        Self {
            logical_offset: TOMBSTONE_SENTINEL,
            extent_id: ExtentId::NONE,
            device_id: 0,
            physical_offset: 0,
            length: 0,
            flags: 0,
            checksum: [0u8; 32],
        }
    }

    /// Whether this slot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.logical_offset == EMPTY_SENTINEL
    }

    /// Whether this slot is a tombstone.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.logical_offset == TOMBSTONE_SENTINEL
    }

    /// Whether this is a live entry (neither empty nor tombstone).
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.logical_offset != EMPTY_SENTINEL && self.logical_offset != TOMBSTONE_SENTINEL
    }

    // ── Lifecycle flags (bits 4-5) ─────────────────────────────
    // bits 0-3: compressed, encrypted, checksum type (existing)

    /// Extent was created by a live write and has not yet been
    /// rebaked to base placement (INGEST state).
    pub const FLAG_INGEST: u8 = 0x10;

    /// Extent has been fully rebaked into durable base placement
    /// (BASE_COMPLETE state).
    pub const FLAG_BASE_COMPLETE: u8 = 0x20;

    /// Whether this entry is in the ingest state.
    #[must_use]
    pub const fn is_ingest(&self) -> bool {
        (self.flags & Self::FLAG_INGEST) != 0
    }

    /// Mark this entry as ingest (write-path creation).
    pub fn set_ingest(&mut self) {
        self.flags |= Self::FLAG_INGEST;
    }

    /// Whether this entry has reached base-complete.
    #[must_use]
    pub const fn is_base_complete(&self) -> bool {
        (self.flags & Self::FLAG_BASE_COMPLETE) != 0
    }

    /// Transition from INGEST to BASE_COMPLETE (rebake completion).
    pub fn set_base_complete(&mut self) {
        self.flags = (self.flags & !Self::FLAG_INGEST) | Self::FLAG_BASE_COMPLETE;
    }
}

// ── Serialization ───────────────────────────────────────────────

fn serialize_entry(entry: &LocatorEntry, buf: &mut [u8]) {
    buf[0..8].copy_from_slice(&entry.logical_offset.to_le_bytes());
    buf[8..16].copy_from_slice(&entry.extent_id.0.to_le_bytes());
    buf[16..24].copy_from_slice(&entry.device_id.to_le_bytes());
    buf[24..32].copy_from_slice(&entry.physical_offset.to_le_bytes());
    buf[32..36].copy_from_slice(&entry.length.to_le_bytes());
    buf[36] = entry.flags;
    buf[37..69].copy_from_slice(&entry.checksum);
}

fn deserialize_entry(buf: &[u8]) -> LocatorEntry {
    let logical_offset = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let extent_id = ExtentId(u64::from_le_bytes(buf[8..16].try_into().unwrap()));
    let device_id = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let physical_offset = u64::from_le_bytes(buf[24..32].try_into().unwrap());
    let length = u32::from_le_bytes(buf[32..36].try_into().unwrap());
    let flags = buf[36];
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&buf[37..69]);
    LocatorEntry {
        logical_offset,
        extent_id,
        device_id,
        physical_offset,
        length,
        flags,
        checksum,
    }
}

/// Deserialize a V1 entry (29 bytes, no checksum).
fn deserialize_entry_v1(buf: &[u8]) -> LocatorEntry {
    let logical_offset = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let extent_id = ExtentId(u64::from_le_bytes(buf[8..16].try_into().unwrap()));
    let physical_offset = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let length = u32::from_le_bytes(buf[24..28].try_into().unwrap());
    let flags = buf[28];
    LocatorEntry {
        logical_offset,
        extent_id,
        device_id: 0,
        physical_offset,
        length,
        flags,
        checksum: [0u8; 32],
    }
}

/// Serialize one region: [capacity: u64 LE][entries...].
fn serialize_region(slots: &[LocatorEntry]) -> Vec<u8> {
    let capacity = slots.len() as u64;
    let mut out = Vec::with_capacity(8 + slots.len() * ENTRY_BYTES);
    out.extend_from_slice(&capacity.to_le_bytes());
    for entry in slots {
        let mut buf = [0u8; ENTRY_BYTES];
        serialize_entry(entry, &mut buf);
        out.extend_from_slice(&buf);
    }
    out
}

/// Deserialize one region, returning `None` on corrupt data.
fn deserialize_region(data: &[u8]) -> Option<Vec<LocatorEntry>> {
    if data.len() < 8 {
        return None;
    }
    let capacity = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let expected = 8 + capacity * ENTRY_BYTES;
    if data.len() < expected {
        return None;
    }
    let mut slots = Vec::with_capacity(capacity);
    for i in 0..capacity {
        let start = 8 + i * ENTRY_BYTES;
        slots.push(deserialize_entry(&data[start..start + ENTRY_BYTES]));
    }
    Some(slots)
}

/// Deserialize a V1 region (29-byte entries, no checksum).
fn deserialize_region_v1(data: &[u8]) -> Option<Vec<LocatorEntry>> {
    if data.len() < 8 {
        return None;
    }
    let capacity = u64::from_le_bytes(data[0..8].try_into().unwrap()) as usize;
    let expected = 8 + capacity * ENTRY_BYTES_V1;
    if data.len() < expected {
        return None;
    }
    let mut slots = Vec::with_capacity(capacity);
    for i in 0..capacity {
        let start = 8 + i * ENTRY_BYTES_V1;
        slots.push(deserialize_entry_v1(&data[start..start + ENTRY_BYTES_V1]));
    }
    Some(slots)
}

/// Full blob: [version: u8]`primary_region`, `secondary_region`.
fn serialize_blob(primary: &[LocatorEntry], secondary: &[LocatorEntry]) -> Vec<u8> {
    let prim_data = serialize_region(primary);
    let sec_data = serialize_region(secondary);
    let mut out = Vec::with_capacity(1 + prim_data.len() + sec_data.len());
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&prim_data);
    out.extend_from_slice(&sec_data);
    out
}

/// Deserialize a full blob.  Handles:
///   v2 (`data[0] == 2`): two-region format with 61-byte entries.
///   v1 (`data[0] == 1`): two-region format with 29-byte entries.
///   legacy (no version byte): single-region 29-byte entries.
fn deserialize_blob(data: &[u8]) -> Option<(Vec<LocatorEntry>, Vec<LocatorEntry>)> {
    if data.is_empty() {
        return None;
    }

    if data[0] == 2 {
        // V2: version byte + two regions with 61-byte entries.
        if data.len() < 9 {
            return None;
        }
        let primary = deserialize_region(&data[1..])?;
        let prim_byte_len = 8 + primary.len() * ENTRY_BYTES;
        let sec_start = 1 + prim_byte_len;
        let secondary = deserialize_region(&data[sec_start..])?;
        Some((primary, secondary))
    } else if data[0] == 1 {
        // V1: version byte + two regions with 29-byte entries.
        if data.len() < 9 {
            return None;
        }
        let primary = deserialize_region_v1(&data[1..])?;
        let prim_byte_len = 8 + primary.len() * ENTRY_BYTES_V1;
        let sec_start = 1 + prim_byte_len;
        let secondary = deserialize_region_v1(&data[sec_start..])?;
        Some((primary, secondary))
    } else {
        // Legacy format: single region, no version byte.
        let primary = deserialize_region_v1(data)?;
        let secondary = vec![LocatorEntry::empty(); primary.len()];
        Some((primary, secondary))
    }
}

// ── Blob key helpers ────────────────────────────────────────────

fn blob_key(pool_id: u64, ino: u64) -> ObjectKey {
    let mut name = Vec::with_capacity(KEY_PREFIX.len() + 16 + 16 + 1);
    name.extend_from_slice(KEY_PREFIX);
    name.extend_from_slice(&pool_id.to_le_bytes());
    name.push(b':');
    name.extend_from_slice(&ino.to_le_bytes());
    ObjectKey::from_name(&name)
}

// ── Errors ──────────────────────────────────────────────────────

/// Errors produced by locator table operations.
#[derive(Debug, Eq, PartialEq)]
pub enum LocatorError {
    /// The requested entry was not found.
    NotFound,
    /// The table is too full; caller must grow.
    WouldGrow { capacity: usize },
    /// An error from the underlying object store.
    Store(String),
    /// The on-disk blob is corrupt or has an unexpected format.
    Corrupt,
    /// The extent is pinned or locked and cannot be relocated.
    ExtentPinned,
    /// An invalid argument was provided.
    InvalidArgument,
}

impl std::fmt::Display for LocatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("locator entry not found"),
            Self::WouldGrow { capacity } => {
                write!(f, "table at capacity {capacity}, caller must grow")
            }
            Self::Store(msg) => write!(f, "object store error: {msg}"),
            Self::Corrupt => f.write_str("locator table blob corrupt"),
            Self::ExtentPinned => f.write_str("extent is pinned or locked"),
            Self::InvalidArgument => f.write_str("invalid argument"),
        }
    }
}

impl std::error::Error for LocatorError {}

impl From<StoreError> for LocatorError {
    fn from(e: StoreError) -> Self {
        LocatorError::Store(e.to_string())
    }
}

/// Result alias for locator table operations.
pub type Result<T> = std::result::Result<T, LocatorError>;

// ── ExtentMapNotifier trait ─────────────────────────────────────

/// Fire-and-forget notifications for extent-map lifecycle integration.
///
/// Implementors receive callbacks when the locator table inserts or
/// removes entries so the extent map can maintain secondary indices.
pub trait ExtentMapNotifier: Send + Sync {
    /// Called after a successful `insert`.
    fn on_insert(&self, ino: u64, entry: &LocatorEntry);
    /// Called after a successful `remove`.
    fn on_remove(&self, ino: u64, extent_id: ExtentId);
}

// ── ExtentPinCheck trait ────────────────────────────────────────

/// Optional validation callback for extent relocation.
///
/// Implementors can prevent relocation of extents that are currently
/// pinned, write-locked, or otherwise ineligible for movement.
/// When no pin check is configured, `relocate_extent` always proceeds.
pub trait ExtentPinCheck: Send + Sync {
    /// Return `true` if the extent should not be relocated.
    fn is_pinned(&self, ino: u64, extent_id: ExtentId) -> bool;
}

// ── RelocationDataMover trait ────────────────────────────────────

/// Optional data-movement callback for extent relocation.
///
/// When set via [`LocatorTable::set_data_mover`], the locator table
/// will read extent data from the old location and write it to the
/// new location during [`LocatorTable::relocate_commit`], before
/// updating the locator metadata.
///
/// If no data mover is configured, relocation is metadata-only
/// and the caller is responsible for moving the data.
pub trait RelocationDataMover: Send + Sync {
    /// Read extent payload from a device at the given physical offset.
    ///
    /// Returns the raw bytes of the extent (length bytes).
    fn read_extent(&self, device_id: u64, physical_offset: u64, length: u32) -> Result<Vec<u8>>;

    /// Write extent payload to a device at the given physical offset.
    fn write_extent(&self, device_id: u64, physical_offset: u64, data: &[u8]) -> Result<()>;
}

// ── Per-inode cached state ──────────────────────────────────────

struct InodeSlots {
    primary: Vec<LocatorEntry>,
    secondary: Vec<LocatorEntry>,
}

// ── LocatorTable ────────────────────────────────────────────────

/// V1 inline-hash locator table persisted in the object store.
///
/// Each inode's mapping is stored as a single blob containing two
/// open-addressing hash regions: a primary region keyed by
/// `logical_offset` and a secondary region keyed by `extent_id`, both
/// with the same capacity.  The two-region design provides O(1)
/// lookup in both directions without a separate index structure.
pub struct LocatorTable {
    store: Arc<Mutex<LocalObjectStore>>,
    pool_id: u64,
    notifier: Option<Arc<dyn ExtentMapNotifier>>,
    pin_check: Option<Arc<dyn ExtentPinCheck>>,
    data_mover: Option<Arc<dyn RelocationDataMover>>,
    /// Per-inode cached slot arrays (primary + secondary).
    cache: Mutex<HashMap<u64, InodeSlots>>,
    /// Set of all inode numbers that have entries in this table (in-memory).
    known_inodes: std::sync::Mutex<std::collections::BTreeSet<u64>>,
}

impl LocatorTable {
    /// Create a new locator table backed by `store` for the given pool.
    pub fn new(store: LocalObjectStore, pool_id: u64) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            pool_id,
            notifier: None,
            pin_check: None,
            data_mover: None,
            cache: Mutex::new(HashMap::new()),
            known_inodes: std::sync::Mutex::new(std::collections::BTreeSet::new()),
        }
    }

    /// Set the extent-map notifier for lifecycle callbacks.
    pub fn set_notifier(&mut self, notifier: Arc<dyn ExtentMapNotifier>) {
        self.notifier = Some(notifier);
    }

    /// Set the extent pin-check callback for relocation validation.
    ///
    /// When configured, `relocate_extent` will call this before
    /// moving an extent and return [`LocatorError::ExtentPinned`]
    /// if the extent is pinned or write-locked.
    pub fn set_pin_check(&mut self, pin_check: Arc<dyn ExtentPinCheck>) {
        self.pin_check = Some(pin_check);
    }

    /// Set the data-mover callback for relocation data copy.
    ///
    /// When configured, `relocate_commit` will call the mover to
    /// read old extent data and write it to the new location before
    /// updating the locator metadata.  Without a mover, relocation
    /// is metadata-only.
    pub fn set_data_mover(&mut self, mover: Arc<dyn RelocationDataMover>) {
        self.data_mover = Some(mover);
    }

    /// Return the pool id this table belongs to.
    #[must_use]
    pub fn pool_id(&self) -> u64 {
        self.pool_id
    }
    /// Return the set of known inode numbers.
    ///
    /// The set is maintained in memory and updated on every `insert`.
    /// It may not include inodes that were inserted before this process
    /// started (those are discovered when their blobs are loaded).
    #[must_use]
    pub fn known_inode_numbers(&self) -> std::collections::BTreeSet<u64> {
        self.known_inodes.lock().unwrap().clone()
    }

    /// Find all extent IDs that reside on the given device.
    ///
    /// Iterates every known inode, loads its locator entries, and collects
    /// extent IDs where `device_id` matches.  This is the reverse-lookup
    /// used by the resilver scan.
    ///
    /// Returns an empty vector when no extents are found on the device.
    pub fn find_extents_for_device(
        &self,
        inode_numbers: &[u64],
        device_id: u64,
    ) -> Result<Vec<ExtentId>> {
        let mut result = Vec::new();
        for &ino in inode_numbers {
            let iter = self.iterate(ino)?;
            for entry in iter {
                if entry.device_id == device_id {
                    result.push(entry.extent_id);
                }
            }
        }
        Ok(result)
    }

    // ── Private helpers ────────────────────────────────────────

    /// Load both slot arrays for `ino` from the store, or return
    /// fresh empty tables.
    fn load_slots(&self, ino: u64) -> Result<InodeSlots> {
        let store = self.store.lock().unwrap();
        let key = blob_key(self.pool_id, ino);
        match store.get(key) {
            Ok(Some(data)) => {
                let (primary, secondary) = deserialize_blob(&data).ok_or(LocatorError::Corrupt)?;
                Ok(InodeSlots { primary, secondary })
            }
            Ok(None) => Ok(InodeSlots {
                primary: vec![LocatorEntry::empty(); DEFAULT_CAPACITY],
                secondary: vec![LocatorEntry::empty(); DEFAULT_CAPACITY],
            }),
            Err(e) => Err(LocatorError::Store(e.to_string())),
        }
    }

    /// Save both slot arrays for `ino` to the store.
    fn save_slots(&self, ino: u64, slots: &InodeSlots) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        let key = blob_key(self.pool_id, ino);
        let data = serialize_blob(&slots.primary, &slots.secondary);
        store
            .put(key, &data)
            .map(|_| ())
            .map_err(|e| LocatorError::Store(e.to_string()))
    }

    /// Hash a logical offset to a slot index.
    fn hash_offset(offset: u64, capacity: usize) -> usize {
        (offset as usize) % capacity
    }

    /// Hash an extent id to a slot index in the secondary region.
    fn hash_extent(eid: ExtentId, capacity: usize) -> usize {
        (eid.0 as usize) % capacity
    }

    /// Get or load the slots for an inode, returning a clone.
    fn get_slots(&self, ino: u64) -> Result<InodeSlots> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(cached) = cache.get(&ino) {
            Ok(InodeSlots {
                primary: cached.primary.clone(),
                secondary: cached.secondary.clone(),
            })
        } else {
            let loaded = self.load_slots(ino)?;
            let cloned = InodeSlots {
                primary: loaded.primary.clone(),
                secondary: loaded.secondary.clone(),
            };
            cache.insert(ino, loaded);
            Ok(cloned)
        }
    }

    /// Update the cached slots for an inode.
    fn put_slots(&self, ino: u64, slots: InodeSlots) {
        self.cache.lock().unwrap().insert(ino, slots);
    }

    // ── Public operations ──────────────────────────────────────

    /// Look up the extent covering `logical_offset` in inode `ino`.
    ///
    /// O(1) expected via the primary hash region.  Returns
    /// `Ok(Some(entry))` when found, `Ok(None)` when the offset has
    /// no mapping.
    pub fn lookup(&self, ino: u64, logical_offset: u64) -> Result<Option<LocatorEntry>> {
        if logical_offset >= TOMBSTONE_SENTINEL {
            return Err(LocatorError::InvalidArgument);
        }

        let slots = self.get_slots(ino)?;
        let capacity = slots.primary.len();
        let start = Self::hash_offset(logical_offset, capacity);
        let mut idx = start;

        loop {
            let slot = &slots.primary[idx];
            if slot.logical_offset == logical_offset {
                return Ok(Some(*slot));
            }
            if slot.is_empty() {
                return Ok(None);
            }
            idx = (idx + 1) % capacity;
            if idx == start {
                return Ok(None);
            }
        }
    }

    /// Insert `entry` into the table for inode `ino`.
    ///
    /// Inserts into both the primary (logical_offset) and secondary
    /// (extent_id) hash regions.  If a live entry with the same
    /// `logical_offset` exists it is overwritten in both regions.
    /// If the load factor would exceed 0.7 after insert,
    /// `Err(WouldGrow)` is returned and the insert is *not* performed.
    pub fn insert(&self, ino: u64, entry: LocatorEntry) -> Result<()> {
        if entry.logical_offset >= TOMBSTONE_SENTINEL {
            return Err(LocatorError::InvalidArgument);
        }

        let mut slots = self.get_slots(ino)?;
        let capacity = slots.primary.len();

        // ── Primary region ──────────────────────────────────

        let prim_start = Self::hash_offset(entry.logical_offset, capacity);
        let mut prim_idx = prim_start;
        let mut prim_target: Option<usize> = None;

        loop {
            let slot = &slots.primary[prim_idx];
            if slot.logical_offset == entry.logical_offset {
                // Overwrite existing: remove old entry from secondary first.
                Self::secondary_remove(&mut slots.secondary, slot.extent_id);
                // Then insert new entry into both.
                slots.primary[prim_idx] = entry;
                Self::secondary_insert(&mut slots.secondary, &entry);
                self.save_slots(ino, &slots)?;
                self.known_inodes.lock().unwrap().insert(ino);
                self.put_slots(ino, slots);
                if let Some(ref n) = self.notifier {
                    n.on_insert(ino, &entry);
                }
                return Ok(());
            }
            if prim_target.is_none() && (slot.is_empty() || slot.is_tombstone()) {
                prim_target = Some(prim_idx);
            }
            prim_idx = (prim_idx + 1) % capacity;
            if prim_idx == prim_start {
                break;
            }
        }

        let target = prim_target.ok_or(LocatorError::WouldGrow { capacity })?;

        // Check load factor *before* inserting.
        let live_before = slots.primary.iter().filter(|e| e.is_live()).count();
        if (live_before + 1) * MAX_LOAD_DEN > capacity * MAX_LOAD_NUM {
            return Err(LocatorError::WouldGrow { capacity });
        }

        // Insert into primary.
        slots.primary[target] = entry;
        // Insert into secondary.
        Self::secondary_insert(&mut slots.secondary, &entry);

        self.save_slots(ino, &slots)?;
        self.known_inodes.lock().unwrap().insert(ino);
        self.put_slots(ino, slots);

        if let Some(ref n) = self.notifier {
            n.on_insert(ino, &entry);
        }
        Ok(())
    }

    /// Remove the entry at `logical_offset` for inode `ino`.
    ///
    /// Tombstones the slot in both the primary and secondary regions.
    /// Returns `Err(NotFound)` if no matching entry exists.
    pub fn remove(&self, ino: u64, logical_offset: u64) -> Result<()> {
        if logical_offset >= TOMBSTONE_SENTINEL {
            return Err(LocatorError::InvalidArgument);
        }

        let mut slots = self.get_slots(ino)?;
        let capacity = slots.primary.len();
        let start = Self::hash_offset(logical_offset, capacity);
        let mut idx = start;

        loop {
            let slot = &slots.primary[idx];
            if slot.is_empty() {
                return Err(LocatorError::NotFound);
            }
            if slot.logical_offset == logical_offset {
                let extent_id = slot.extent_id;
                slots.primary[idx] = LocatorEntry::tombstone();
                Self::secondary_remove(&mut slots.secondary, extent_id);
                self.save_slots(ino, &slots)?;
                self.put_slots(ino, slots);
                if let Some(ref n) = self.notifier {
                    n.on_remove(ino, extent_id);
                }
                return Ok(());
            }
            idx = (idx + 1) % capacity;
            if idx == start {
                return Err(LocatorError::NotFound);
            }
        }
    }

    /// Reverse lookup: find the entry with the given `extent_id` for
    /// inode `ino`.  O(1) expected via the secondary hash region.
    pub fn lookup_extent(&self, ino: u64, extent_id: ExtentId) -> Result<Option<LocatorEntry>> {
        let slots = self.get_slots(ino)?;
        let capacity = slots.secondary.len();
        let start = Self::hash_extent(extent_id, capacity);
        let mut idx = start;

        loop {
            let slot = &slots.secondary[idx];
            if slot.is_empty() {
                return Ok(None);
            }
            if slot.is_live() && slot.extent_id == extent_id {
                return Ok(Some(*slot));
            }
            idx = (idx + 1) % capacity;
            if idx == start {
                return Ok(None);
            }
        }
    }

    /// Yield all live entries for `ino` in slot order (from the
    /// primary region).  The returned iterator owns a snapshot.
    pub fn iterate(&self, ino: u64) -> Result<LocatorIter> {
        let slots = self.get_slots(ino)?;
        let live: Vec<LocatorEntry> = slots.primary.into_iter().filter(|e| e.is_live()).collect();
        Ok(LocatorIter {
            entries: live,
            pos: 0,
        })
    }

    /// Grow the table for `ino` to `new_capacity` slots in both
    /// regions.  All live entries are rehashed and persisted.
    pub fn grow(&self, ino: u64, new_capacity: usize) -> Result<()> {
        if new_capacity < DEFAULT_CAPACITY {
            return Err(LocatorError::InvalidArgument);
        }

        let old_slots = self.get_slots(ino)?;
        let live: Vec<LocatorEntry> = old_slots
            .primary
            .iter()
            .filter(|e| e.is_live())
            .copied()
            .collect();

        if live.is_empty() {
            let new_slots = InodeSlots {
                primary: vec![LocatorEntry::empty(); new_capacity],
                secondary: vec![LocatorEntry::empty(); new_capacity],
            };
            self.save_slots(ino, &new_slots)?;
            self.put_slots(ino, new_slots);
            return Ok(());
        }

        if live.len() * MAX_LOAD_DEN >= new_capacity * MAX_LOAD_NUM {
            return Err(LocatorError::InvalidArgument);
        }

        let mut new_primary = vec![LocatorEntry::empty(); new_capacity];
        let mut new_secondary = vec![LocatorEntry::empty(); new_capacity];

        for entry in &live {
            // Rehash into primary.
            let p_start = Self::hash_offset(entry.logical_offset, new_capacity);
            let mut p_idx = p_start;
            loop {
                if new_primary[p_idx].is_empty() || new_primary[p_idx].is_tombstone() {
                    new_primary[p_idx] = *entry;
                    break;
                }
                p_idx = (p_idx + 1) % new_capacity;
                if p_idx == p_start {
                    return Err(LocatorError::WouldGrow {
                        capacity: new_capacity,
                    });
                }
            }
            // Rehash into secondary.
            let s_start = Self::hash_extent(entry.extent_id, new_capacity);
            let mut s_idx = s_start;
            loop {
                if new_secondary[s_idx].is_empty() || new_secondary[s_idx].is_tombstone() {
                    new_secondary[s_idx] = *entry;
                    break;
                }
                s_idx = (s_idx + 1) % new_capacity;
            }
        }

        let new_slots = InodeSlots {
            primary: new_primary,
            secondary: new_secondary,
        };
        self.save_slots(ino, &new_slots)?;
        self.put_slots(ino, new_slots);
        Ok(())
    }

    /// Return the number of live entries for `ino`, or 0 if the table
    /// has not been loaded.
    #[must_use]
    pub fn len(&self, ino: u64) -> usize {
        let cache = self.cache.lock().unwrap();
        cache
            .get(&ino)
            .map(|s| s.primary.iter().filter(|e| e.is_live()).count())
            .unwrap_or(0)
    }

    // ── Secondary region helpers (private) ────────────────────

    /// Insert `entry` into the secondary hash region (in-place).
    /// Panics if the region is full (caller must ensure load factor).
    fn secondary_insert(secondary: &mut [LocatorEntry], entry: &LocatorEntry) {
        let capacity = secondary.len();
        let start = Self::hash_extent(entry.extent_id, capacity);
        let mut idx = start;
        loop {
            let slot = &secondary[idx];
            if slot.is_empty() || slot.is_tombstone() {
                secondary[idx] = *entry;
                return;
            }
            if slot.is_live() && slot.extent_id == entry.extent_id {
                secondary[idx] = *entry;
                return;
            }
            idx = (idx + 1) % capacity;
            // The caller guarantees capacity is sufficient; this
            // would only loop forever if the table is full.
            debug_assert!(idx != start, "secondary region full");
        }
    }

    /// Remove the entry with `extent_id` from the secondary hash
    /// region (in-place).  No-op if not found.
    fn secondary_remove(secondary: &mut [LocatorEntry], extent_id: ExtentId) {
        let capacity = secondary.len();
        let start = Self::hash_extent(extent_id, capacity);
        let mut idx = start;
        loop {
            let slot = &secondary[idx];
            if slot.is_empty() {
                return;
            }
            if slot.is_live() && slot.extent_id == extent_id {
                secondary[idx] = LocatorEntry::tombstone();
                return;
            }
            idx = (idx + 1) % capacity;
            if idx == start {
                return;
            }
        }
    }
    // ── Compaction ────────────────────────────────────────────

    /// Produce a plan to compact the table for inode `ino`.
    ///
    /// Collects all live entries, calculates the optimal capacity for
    /// the current live set (keeping load factor <= 0.7), and returns
    /// a [`CompactionPlan`] with the new packed regions.  The returned
    /// plan is not yet applied; call `swap_commit` when ready to
    /// atomically install the compacted table.
    ///
    /// An empty table produces a plan with `DEFAULT_CAPACITY` slots.
    /// A fully-packed table with no tombstones is a no-op that
    /// returns a plan whose regions match the current live set.
    pub fn compact(&self, ino: u64) -> Result<CompactionPlan> {
        let slots = self.get_slots(ino)?;
        let live: Vec<LocatorEntry> = slots
            .primary
            .iter()
            .filter(|e| e.is_live())
            .copied()
            .collect();

        if live.is_empty() {
            return Ok(CompactionPlan {
                ino,
                new_primary: vec![LocatorEntry::empty(); DEFAULT_CAPACITY],
                new_secondary: vec![LocatorEntry::empty(); DEFAULT_CAPACITY],
            });
        }

        // Choose a capacity so load factor <= MAX_LOAD_NUM / MAX_LOAD_DEN.
        let mut new_capacity = DEFAULT_CAPACITY;
        while live.len() * MAX_LOAD_DEN > new_capacity * MAX_LOAD_NUM {
            new_capacity = new_capacity.saturating_mul(2);
        }

        let mut new_primary = vec![LocatorEntry::empty(); new_capacity];
        let mut new_secondary = vec![LocatorEntry::empty(); new_capacity];

        for entry in &live {
            // Rehash into primary region.
            let p_start = Self::hash_offset(entry.logical_offset, new_capacity);
            let mut p_idx = p_start;
            loop {
                let slot = &new_primary[p_idx];
                if slot.is_empty() || slot.is_tombstone() {
                    new_primary[p_idx] = *entry;
                    break;
                }
                p_idx = (p_idx + 1) % new_capacity;
                // Guaranteed: load factor ensures enough empty slots.
                debug_assert!(p_idx != p_start, "primary region full during compact");
            }

            // Rehash into secondary region.
            let s_start = Self::hash_extent(entry.extent_id, new_capacity);
            let mut s_idx = s_start;
            loop {
                let slot = &new_secondary[s_idx];
                if slot.is_empty() || slot.is_tombstone() {
                    new_secondary[s_idx] = *entry;
                    break;
                }
                s_idx = (s_idx + 1) % new_capacity;
                debug_assert!(s_idx != s_start, "secondary region full during compact");
            }
        }

        Ok(CompactionPlan {
            ino,
            new_primary,
            new_secondary,
        })
    }

    /// Atomically install a compacted table produced by `compact`.
    ///
    /// The old table is replaced with the new packed regions in both
    /// the in-memory cache and the persistent object store.  Lookups
    /// during the swap see either the old or new table consistently.
    pub fn swap_commit(&self, plan: CompactionPlan) -> Result<()> {
        let slots = InodeSlots {
            primary: plan.new_primary,
            secondary: plan.new_secondary,
        };
        self.save_slots(plan.ino, &slots)?;
        self.put_slots(plan.ino, slots);
        Ok(())
    }
    // ── Relocation ────────────────────────────────────────────

    /// Relocate a single extent identified by `extent_id` in inode
    /// `ino` to a new physical offset, updating both the primary and
    /// secondary hash regions and persisting the change.
    ///
    /// Returns [`LocatorError::NotFound`] if no live entry with
    /// `extent_id` exists in the table.
    ///
    /// This is the entry point used by online defrag to move
    /// individual extents without blocking concurrent lookups.
    pub fn relocate_extent(
        &self,
        ino: u64,
        extent_id: ExtentId,
        new_device_id: u64,
        new_physical_offset: u64,
    ) -> Result<()> {
        let mut slots = self.get_slots(ino)?;
        let capacity = slots.secondary.len();

        // Find the entry in the secondary region by extent_id.
        let s_start = Self::hash_extent(extent_id, capacity);
        let mut s_idx = s_start;

        loop {
            let slot = &slots.secondary[s_idx];
            if slot.is_empty() {
                return Err(LocatorError::NotFound);
            }
            if slot.is_live() && slot.extent_id == extent_id {
                // Reject relocation if the extent is pinned.
                if let Some(ref pc) = self.pin_check {
                    if pc.is_pinned(ino, extent_id) {
                        return Err(LocatorError::ExtentPinned);
                    }
                }

                let logical_offset = slot.logical_offset;
                let mut updated = *slot;
                updated.device_id = new_device_id;
                updated.physical_offset = new_physical_offset;

                slots.secondary[s_idx] = updated;

                // Update the primary region entry at the same logical_offset.
                let p_start = Self::hash_offset(logical_offset, capacity);
                let mut p_idx = p_start;
                loop {
                    let p_slot = &slots.primary[p_idx];
                    if p_slot.is_live() && p_slot.extent_id == extent_id {
                        slots.primary[p_idx] = updated;
                        break;
                    }
                    p_idx = (p_idx + 1) % capacity;
                    debug_assert!(
                        p_idx != p_start,
                        "primary entry for extent {} not found",
                        extent_id.0
                    );
                }

                self.save_slots(ino, &slots)?;
                self.put_slots(ino, slots);
                return Ok(());
            }
            s_idx = (s_idx + 1) % capacity;
            if s_idx == s_start {
                return Err(LocatorError::NotFound);
            }
        }
    }

    /// Prepare an extent for relocation to a new device and offset.
    ///
    /// This captures the relocation plan without mutating the table
    /// so the caller can copy data from the old location to the new
    /// one. After the data copy, call `relocate_commit` to
    /// atomically swap to the new location. Call `relocate_abort`
    /// to discard the prepared relocation.
    ///
    /// Returns [`LocatorError::NotFound`] if the extent is not found,
    /// or [`LocatorError::ExtentPinned`] if the extent is pinned.
    pub fn relocate_prepare(
        &self,
        ino: u64,
        extent_id: ExtentId,
        new_device_id: u64,
        new_physical_offset: u64,
    ) -> Result<RelocatePlan> {
        let slots = self.get_slots(ino)?;
        let capacity = slots.secondary.len();

        let s_start = Self::hash_extent(extent_id, capacity);
        let mut s_idx = s_start;
        loop {
            let slot = &slots.secondary[s_idx];
            if slot.is_empty() {
                return Err(LocatorError::NotFound);
            }
            if slot.is_live() && slot.extent_id == extent_id {
                if let Some(ref pc) = self.pin_check {
                    if pc.is_pinned(ino, extent_id) {
                        return Err(LocatorError::ExtentPinned);
                    }
                }

                return Ok(RelocatePlan {
                    ino,
                    extent_id,
                    logical_offset: slot.logical_offset,
                    old_device_id: slot.device_id,
                    old_physical_offset: slot.physical_offset,
                    new_device_id,
                    new_physical_offset,
                    length: slot.length,
                    flags: slot.flags,
                });
            }
            s_idx = (s_idx + 1) % capacity;
            if s_idx == s_start {
                return Err(LocatorError::NotFound);
            }
        }
    }

    /// Commit a prepared relocation plan.
    ///
    /// If a [`RelocationDataMover`] is configured and the location
    /// changed, data is read from the old location and written to the
    /// new location before updating metadata. The metadata update is
    /// atomic: both hash regions are updated and the change is
    /// persisted in a single save.
    pub fn relocate_commit(&self, plan: RelocatePlan) -> Result<RelocationStats> {
        use std::time::Instant;

        let start = Instant::now();

        // If a data mover is configured and the extent actually moved
        // to a new location, copy the data before updating metadata.
        let location_changed = plan.old_device_id != plan.new_device_id
            || plan.old_physical_offset != plan.new_physical_offset;
        if location_changed {
            if let Some(ref mover) = self.data_mover {
                let data =
                    mover.read_extent(plan.old_device_id, plan.old_physical_offset, plan.length)?;
                mover.write_extent(plan.new_device_id, plan.new_physical_offset, &data)?;
            }
        }

        let mut slots = self.get_slots(plan.ino)?;
        let capacity = slots.secondary.len();
        let extent_id = plan.extent_id;

        let updated = LocatorEntry::new(
            plan.logical_offset,
            extent_id,
            plan.new_device_id,
            plan.new_physical_offset,
            plan.length,
            plan.flags,
        );

        // Update secondary region.
        let s_start = Self::hash_extent(extent_id, capacity);
        let mut s_idx = s_start;
        let mut found = false;
        loop {
            let slot = &slots.secondary[s_idx];
            if slot.is_empty() {
                break;
            }
            if slot.is_live() && slot.extent_id == extent_id {
                slots.secondary[s_idx] = updated;
                found = true;
                break;
            }
            s_idx = (s_idx + 1) % capacity;
            if s_idx == s_start {
                break;
            }
        }

        if !found {
            return Err(LocatorError::NotFound);
        }

        // Update primary region.
        let p_start = Self::hash_offset(plan.logical_offset, capacity);
        let mut p_idx = p_start;
        loop {
            let p_slot = &slots.primary[p_idx];
            if p_slot.is_live() && p_slot.extent_id == extent_id {
                slots.primary[p_idx] = updated;
                break;
            }
            p_idx = (p_idx + 1) % capacity;
            if p_idx == p_start {
                return Err(LocatorError::NotFound);
            }
        }

        self.save_slots(plan.ino, &slots)?;
        self.put_slots(plan.ino, slots);

        let elapsed_ms = start.elapsed().as_millis() as u64;
        Ok(RelocationStats {
            extents_relocated: 1,
            bytes_relocated: plan.length as u64,
            relocation_time_ms: elapsed_ms,
        })
    }

    /// Abort a prepared relocation plan (no-op, plan is discarded).
    ///
    /// The old location remains valid and unchanged. This is a
    /// no-op because prepare does not mutate the table state.
    pub fn relocate_abort(&self, _plan: RelocatePlan) {
        // No state was mutated during prepare; plan is simply discarded.
    }
}

// ── RelocatePlan ─────────────────────────────────────────────

/// A prepared extent relocation, returned by
/// [`LocatorTable::relocate_prepare`].
///
/// Contains both the old and new locations so the caller can
/// copy data before calling [`LocatorTable::relocate_commit`].
#[derive(Clone, Debug)]
pub struct RelocatePlan {
    /// The inode the extent belongs to.
    pub ino: u64,
    /// The extent being relocated.
    pub extent_id: ExtentId,
    /// Logical offset (unchanged by relocation).
    pub logical_offset: u64,
    /// Old device id (source for data copy).
    pub old_device_id: u64,
    /// Old physical offset (source for data copy).
    pub old_physical_offset: u64,
    /// New device id for the relocated extent.
    pub new_device_id: u64,
    /// New physical offset for the relocated extent.
    pub new_physical_offset: u64,
    /// Length of the extent in bytes.
    pub length: u32,
    /// Extent flags (compressed, encrypted, checksum type).
    pub flags: u8,
}

// ── RelocationStats ──────────────────────────────────────────

/// Statistics for a completed relocation operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelocationStats {
    /// Number of extents relocated.
    pub extents_relocated: u64,
    /// Total bytes relocated.
    pub bytes_relocated: u64,
    /// Wall-clock duration of the relocation commit in milliseconds.
    pub relocation_time_ms: u64,
}

// ── CompactionPlan ─────────────────────────────────────────

/// Describes the result of [`LocatorTable::compact`].
///
/// Contains the new packed region vectors and the inode they
/// belong to.  Call [`LocatorTable::swap_commit`] to atomically
/// install the compacted table.
#[derive(Clone, Debug)]
pub struct CompactionPlan {
    ino: u64,
    new_primary: Vec<LocatorEntry>,
    new_secondary: Vec<LocatorEntry>,
}

// ── LocatorIter ─────────────────────────────────────────────────

/// An iterator over live entries in a locator table.
///
/// Created by [`LocatorTable::iterate`].  Yields [`LocatorEntry`]
/// values in the order they appear in the primary slot array.
pub struct LocatorIter {
    entries: Vec<LocatorEntry>,
    pos: usize,
}

impl Iterator for LocatorIter {
    type Item = LocatorEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.entries.len() {
            return None;
        }
        let entry = self.entries[self.pos];
        self.pos += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.entries.len() - self.pos;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for LocatorIter {}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tidefs_local_object_store::StoreOptions;

    fn make_store(dir: &std::path::Path) -> LocalObjectStore {
        let mut opts = StoreOptions::test_fast();
        opts.max_segment_bytes = 8192;
        LocalObjectStore::open_with_options(dir, opts).expect("open store")
    }

    fn make_table(dir: &std::path::Path) -> LocatorTable {
        LocatorTable::new(make_store(dir), 1)
    }

    // ── Notifier spy ──────────────────────────────────────────

    struct SpyNotifier {
        inserts: StdMutex<Vec<(u64, LocatorEntry)>>,
        removes: StdMutex<Vec<(u64, ExtentId)>>,
    }

    impl SpyNotifier {
        fn new() -> Self {
            Self {
                inserts: StdMutex::new(Vec::new()),
                removes: StdMutex::new(Vec::new()),
            }
        }

        fn insert_calls(&self) -> Vec<(u64, LocatorEntry)> {
            self.inserts.lock().unwrap().clone()
        }

        fn remove_calls(&self) -> Vec<(u64, ExtentId)> {
            self.removes.lock().unwrap().clone()
        }
    }

    impl ExtentMapNotifier for SpyNotifier {
        fn on_insert(&self, ino: u64, entry: &LocatorEntry) {
            self.inserts.lock().unwrap().push((ino, *entry));
        }

        fn on_remove(&self, ino: u64, extent_id: ExtentId) {
            self.removes.lock().unwrap().push((ino, extent_id));
        }
    }

    // ── Core insert / lookup ──────────────────────────────────

    #[test]
    fn insert_and_lookup_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let entry = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0);
        table.insert(1, entry).unwrap();

        let found = table.lookup(1, 0).unwrap();
        assert_eq!(found, Some(entry));
    }

    #[test]
    fn lookup_empty_table_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let found = table.lookup(1, 1024).unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn insert_duplicate_offset_overwrites_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let entry1 = LocatorEntry::new(4096, ExtentId(10), 0, 0, 4096, 0);
        table.insert(1, entry1).unwrap();

        let entry2 = LocatorEntry::new(4096, ExtentId(20), 0, 8192, 4096, 0);
        table.insert(1, entry2).unwrap();

        let found = table.lookup(1, 4096).unwrap();
        assert_eq!(found, Some(entry2));
        assert_eq!(table.len(1), 1);
    }

    // ── Remove ────────────────────────────────────────────────

    #[test]
    fn insert_and_remove_then_lookup_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let entry = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0);
        table.insert(1, entry).unwrap();
        table.remove(1, 0).unwrap();

        let found = table.lookup(1, 0).unwrap();
        assert_eq!(found, None);
        assert_eq!(table.len(1), 0);
    }

    #[test]
    fn insert_past_tombstone_then_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        // With capacity 16, offsets 0 and 16 both hash to slot 0.
        let entry0 = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0);
        table.insert(1, entry0).unwrap();
        table.remove(1, 0).unwrap();

        let entry16 = LocatorEntry::new(16, ExtentId(2), 0, 8192, 4096, 0);
        table.insert(1, entry16).unwrap();

        assert_eq!(table.lookup(1, 0).unwrap(), None);
        assert_eq!(table.lookup(1, 16).unwrap(), Some(entry16));
    }

    #[test]
    fn remove_nonexistent_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        assert_eq!(table.remove(1, 4096), Err(LocatorError::NotFound));
    }

    // ── Error paths ───────────────────────────────────────────

    #[test]
    fn lookup_with_invalid_offset_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        assert_eq!(
            table.lookup(1, u64::MAX),
            Err(LocatorError::InvalidArgument)
        );
        assert_eq!(
            table.lookup(1, u64::MAX - 1),
            Err(LocatorError::InvalidArgument)
        );
    }

    #[test]
    fn insert_with_invalid_offset_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        assert_eq!(
            table.insert(1, LocatorEntry::new(u64::MAX, ExtentId(1), 0, 0, 1, 0)),
            Err(LocatorError::InvalidArgument)
        );
    }

    // ── Multiple inodes ───────────────────────────────────────

    #[test]
    fn multiple_inodes_independent() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0);
        let e2 = LocatorEntry::new(0, ExtentId(2), 0, 8192, 4096, 0);

        table.insert(100, e1).unwrap();
        table.insert(200, e2).unwrap();

        assert_eq!(table.lookup(100, 0).unwrap(), Some(e1));
        assert_eq!(table.lookup(200, 0).unwrap(), Some(e2));

        table.remove(100, 0).unwrap();
        assert_eq!(table.lookup(100, 0).unwrap(), None);
        assert_eq!(table.lookup(200, 0).unwrap(), Some(e2));
    }

    // ── WouldGrow / capacity ──────────────────────────────────

    #[test]
    fn insert_triggers_would_grow_at_load_factor() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        // Default capacity is 16. Max load is 7/10, so max live = 11.
        for i in 0..11 {
            let offset = i * 64;
            table
                .insert(
                    1,
                    LocatorEntry::new(offset, ExtentId(i + 1), 0, offset * 2, 64, 0),
                )
                .unwrap();
        }

        let result = table.insert(
            1,
            LocatorEntry::new(11 * 64, ExtentId(12), 0, 11 * 64 * 2, 64, 0),
        );
        match result {
            Err(LocatorError::WouldGrow { capacity }) => assert_eq!(capacity, 16),
            other => panic!("expected WouldGrow, got {other:?}"),
        }
    }

    #[test]
    fn grow_doubles_capacity_and_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let mut entries = Vec::new();
        for i in 0..8 {
            let e = LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        table.grow(1, 24).unwrap();

        for e in &entries {
            let found = table.lookup(1, e.logical_offset).unwrap();
            assert_eq!(found, Some(*e));
        }
    }

    // ── Persistence ───────────────────────────────────────────

    #[test]
    fn persistence_round_trip() {
        let dir = tempfile::tempdir().unwrap();

        let e1 = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0x01);
        let e2 = LocatorEntry::new(4096, ExtentId(43), 0, 12288, 4096, 0x02);

        {
            let table = make_table(dir.path());
            table.insert(1, e1).unwrap();
            table.insert(1, e2).unwrap();
        }

        // Re-open a fresh table pointing at the same store.
        {
            let store = make_store(dir.path());
            let table = LocatorTable::new(store, 1);
            assert_eq!(table.lookup(1, 0).unwrap(), Some(e1));
            assert_eq!(table.lookup(1, 4096).unwrap(), Some(e2));
        }
    }

    // ── Serialization ─────────────────────────────────────────

    #[test]
    fn serialize_deserialize_blob_round_trip() {
        let entries = vec![
            LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0),
            LocatorEntry::empty(),
            LocatorEntry::new(8192, ExtentId(3), 0, 16384, 4096, 0x03),
            LocatorEntry::tombstone(),
            LocatorEntry::new(4096, ExtentId(2), 0, 8192, 2048, 0x01),
        ];

        let data = serialize_blob(&entries, &entries);
        let (primary, secondary) = deserialize_blob(&data).unwrap();
        assert_eq!(primary, entries);
        assert_eq!(secondary, entries);
    }

    #[test]
    fn legacy_format_still_readable() {
        // Simulate a V0 blob (no version byte, single region, 29-byte entries).
        let entries = vec![
            LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0),
            LocatorEntry::empty(),
            LocatorEntry::new(64, ExtentId(2), 0, 64, 4096, 0),
        ];
        // Manually construct a V1/legacy blob with 29-byte entries.
        let capacity = entries.len() as u64;
        let mut legacy = Vec::with_capacity(8 + entries.len() * ENTRY_BYTES_V1);
        legacy.extend_from_slice(&capacity.to_le_bytes());
        for e in &entries {
            let mut buf = [0u8; ENTRY_BYTES_V1];
            buf[0..8].copy_from_slice(&e.logical_offset.to_le_bytes());
            buf[8..16].copy_from_slice(&e.extent_id.0.to_le_bytes());
            buf[16..24].copy_from_slice(&e.physical_offset.to_le_bytes());
            buf[24..28].copy_from_slice(&e.length.to_le_bytes());
            buf[28] = e.flags;
            legacy.extend_from_slice(&buf);
        }
        let (primary, secondary) = deserialize_blob(&legacy).unwrap();
        assert_eq!(primary, entries, "legacy primary region");
        assert_eq!(secondary.len(), entries.len(), "secondary same capacity");
        assert!(
            secondary.iter().all(|e| e.is_empty()),
            "secondary all empty"
        );
    }

    // ── lookup_extent (O(1) via secondary hash) ───────────────

    #[test]
    fn lookup_extent_finds_entry() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(42), 0, 0, 4096, 0);
        let e2 = LocatorEntry::new(4096, ExtentId(99), 0, 8192, 2048, 0);
        table.insert(1, e1).unwrap();
        table.insert(1, e2).unwrap();

        assert_eq!(table.lookup_extent(1, ExtentId(42)).unwrap(), Some(e1));
        assert_eq!(table.lookup_extent(1, ExtentId(99)).unwrap(), Some(e2));
    }

    #[test]
    fn lookup_extent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
            .unwrap();

        assert_eq!(table.lookup_extent(1, ExtentId(999)).unwrap(), None);
    }

    #[test]
    fn lookup_extent_empty_table_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        assert_eq!(table.lookup_extent(1, ExtentId(1)).unwrap(), None);
    }

    #[test]
    fn lookup_extent_skips_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0))
            .unwrap();
        table.remove(1, 0).unwrap();

        // After remove, the secondary index should also be tombstoned.
        assert_eq!(table.lookup_extent(1, ExtentId(10)).unwrap(), None);
    }

    #[test]
    fn lookup_extent_after_overwrite_returns_new_entry() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let old = LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0);
        table.insert(1, old).unwrap();

        let new = LocatorEntry::new(0, ExtentId(20), 0, 8192, 4096, 0);
        table.insert(1, new).unwrap();

        // Old extent_id should not be findable after overwrite.
        assert_eq!(table.lookup_extent(1, ExtentId(10)).unwrap(), None);
        // New extent_id should be findable.
        assert_eq!(table.lookup_extent(1, ExtentId(20)).unwrap(), Some(new));
    }

    // ── iterate ───────────────────────────────────────────────

    #[test]
    fn iterate_yields_all_live_entries() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0);
        let e2 = LocatorEntry::new(64, ExtentId(2), 0, 64, 64, 0);
        let e3 = LocatorEntry::new(128, ExtentId(3), 0, 128, 64, 0);
        table.insert(1, e1).unwrap();
        table.insert(1, e2).unwrap();
        table.insert(1, e3).unwrap();

        let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
        assert_eq!(entries.len(), 3);
        assert!(entries.contains(&e1));
        assert!(entries.contains(&e2));
        assert!(entries.contains(&e3));
    }

    #[test]
    fn iterate_empty_table_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn iterate_skips_tombstones() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0))
            .unwrap();
        table
            .insert(1, LocatorEntry::new(64, ExtentId(2), 0, 64, 64, 0))
            .unwrap();
        table.remove(1, 0).unwrap();

        let entries: Vec<LocatorEntry> = table.iterate(1).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].logical_offset, 64);
    }

    #[test]
    fn iterate_is_exact_size() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        for i in 0..5 {
            table
                .insert(
                    1,
                    LocatorEntry::new(i * 64, ExtentId(i + 1), 0, i * 64, 64, 0),
                )
                .unwrap();
        }

        let iter = table.iterate(1).unwrap();
        assert_eq!(iter.len(), 5);
    }

    // ── notifier ──────────────────────────────────────────────

    #[test]
    fn notifier_on_insert_called() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyNotifier::new());
        table.set_notifier(spy.clone());

        let entry = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0);
        table.insert(1, entry).unwrap();

        let calls = spy.insert_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 1);
        assert_eq!(calls[0].1, entry);
    }

    #[test]
    fn notifier_on_remove_called() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyNotifier::new());
        table.set_notifier(spy.clone());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0))
            .unwrap();
        table.remove(1, 0).unwrap();

        let calls = spy.remove_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 1);
        assert_eq!(calls[0].1, ExtentId(42));
    }

    #[test]
    fn notifier_not_called_on_failed_insert() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyNotifier::new());
        table.set_notifier(spy.clone());

        let _ = table.insert(1, LocatorEntry::new(u64::MAX, ExtentId(1), 0, 0, 1, 0));

        assert!(spy.insert_calls().is_empty());
        assert!(spy.remove_calls().is_empty());
    }

    #[test]
    fn notifier_not_called_on_failed_remove() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyNotifier::new());
        table.set_notifier(spy.clone());

        let _ = table.remove(1, 4096);

        assert!(spy.remove_calls().is_empty());
    }

    #[test]
    fn notifier_on_insert_overwrite_called_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyNotifier::new());
        table.set_notifier(spy.clone());

        let e1 = LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0);
        table.insert(1, e1).unwrap();

        let e2 = LocatorEntry::new(0, ExtentId(20), 0, 8192, 4096, 0);
        table.insert(1, e2).unwrap();

        let calls = spy.insert_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, e1);
        assert_eq!(calls[1].1, e2);

        // No remove was issued for overwrite.
        assert!(spy.remove_calls().is_empty());
    }

    // ── Secondary index integrity ─────────────────────────────

    #[test]
    fn secondary_index_consistent_after_many_inserts() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let mut entries = Vec::new();
        for i in 0..10 {
            let e = LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        // Every entry should be findable via lookup_extent.
        for e in &entries {
            let found = table.lookup_extent(1, e.extent_id).unwrap();
            assert_eq!(found, Some(*e), "missing for extent_id {}", e.extent_id);
        }
    }

    #[test]
    fn secondary_index_consistent_after_grow() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let mut entries = Vec::new();
        for i in 0..8 {
            let e = LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        table.grow(1, 24).unwrap();

        // All entries still findable via secondary after grow.
        for e in &entries {
            let found = table.lookup_extent(1, e.extent_id).unwrap();
            assert_eq!(found, Some(*e), "missing after grow for {}", e.extent_id);
        }
    }

    #[test]
    fn secondary_index_consistent_after_remove_and_reinsert() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0);
        let e2 = LocatorEntry::new(64, ExtentId(20), 0, 64, 4096, 0);

        table.insert(1, e1).unwrap();
        table.insert(1, e2).unwrap();
        table.remove(1, 0).unwrap();

        // Reuse the same logical offset with a new extent_id.
        let e3 = LocatorEntry::new(0, ExtentId(30), 0, 8192, 4096, 0);
        table.insert(1, e3).unwrap();

        assert_eq!(table.lookup_extent(1, ExtentId(10)).unwrap(), None);
        assert_eq!(table.lookup_extent(1, ExtentId(20)).unwrap(), Some(e2));
        assert_eq!(table.lookup_extent(1, ExtentId(30)).unwrap(), Some(e3));
    }

    // ── Compaction ──────────────────────────────────────────────

    #[test]
    fn compact_preserves_all_live_entries() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        // Allocate 10 extents at distinct offsets.
        let mut entries = Vec::new();
        for i in 0..10 {
            let e = LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        // Free every other one (indices 1, 3, 5, 7, 9 → offsets 64, 192, ...).
        for i in (1..10).step_by(2) {
            table.remove(1, i * 64).unwrap();
        }

        // Compact and swap-commit.
        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        // Remaining entries (offsets 0, 128, 256, 384, 512) must be reachable.
        let expected_ids: Vec<u64> = vec![0, 2, 4, 6, 8];
        for idx in &expected_ids {
            let offset = idx * 64;
            let found = table.lookup(1, offset).unwrap();
            assert_eq!(found, Some(entries[*idx as usize]));
        }

        // Freed entries must NOT be reachable.
        for i in (1..10).step_by(2) {
            assert_eq!(table.lookup(1, i * 64).unwrap(), None);
        }

        // lookup_extent still works.
        for idx in &expected_ids {
            let eid = ExtentId(100 + idx);
            let found = table.lookup_extent(1, eid).unwrap();
            assert_eq!(found, Some(entries[*idx as usize]));
        }

        assert_eq!(table.len(1), 5);
    }

    #[test]
    fn compact_empty_table_produces_default_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let plan = table.compact(1).unwrap();
        assert_eq!(plan.new_primary.len(), DEFAULT_CAPACITY);
        assert!(plan.new_primary.iter().all(|e| e.is_empty()));

        table.swap_commit(plan).unwrap();
        assert_eq!(table.lookup(1, 0).unwrap(), None);
        assert_eq!(table.len(1), 0);
    }

    #[test]
    fn compact_fully_packed_noop() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let mut entries = Vec::new();
        // Default capacity is 16, max load is 11. Insert 10 entries.
        for i in 0..10 {
            let e = LocatorEntry::new(i * 64, ExtentId(50 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        // All entries still reachable.
        for e in &entries {
            let found = table.lookup(1, e.logical_offset).unwrap();
            assert_eq!(found, Some(*e));
        }
        assert_eq!(table.len(1), 10);
    }

    #[test]
    fn compact_single_entry() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e = LocatorEntry::new(4096, ExtentId(77), 0, 8192, 2048, 0);
        table.insert(1, e).unwrap();

        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        assert_eq!(table.lookup(1, 4096).unwrap(), Some(e));
        assert_eq!(table.lookup_extent(1, ExtentId(77)).unwrap(), Some(e));
        assert_eq!(table.len(1), 1);
    }

    #[test]
    fn compact_after_grow_preserves_secondary_index() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let mut entries = Vec::new();
        // Insert 10 entries at default capacity, then grow for the rest.
        for i in 0..10 {
            let e = LocatorEntry::new(i * 64, ExtentId(200 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }
        table.grow(1, 24).unwrap();
        for i in 10..12 {
            let e = LocatorEntry::new(i * 64, ExtentId(200 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        // Remove a few to create tombstones.
        table.remove(1, 0).unwrap();
        table.remove(1, 192).unwrap();
        table.remove(1, 448).unwrap();

        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        // Remaining entries must be findable via both indexes.
        // Removed offsets 0 (idx 0), 192 (idx 3), 448 (idx 7).
        let keep: Vec<usize> = vec![1, 2, 4, 5, 6, 8, 9, 10, 11];
        for idx in &keep {
            let e = entries[*idx];
            assert_eq!(
                table.lookup(1, e.logical_offset).unwrap(),
                Some(e),
                "missing lookup for offset {}",
                e.logical_offset
            );
            assert_eq!(
                table.lookup_extent(1, e.extent_id).unwrap(),
                Some(e),
                "missing lookup_extent for {}",
                e.extent_id
            );
        }

        // Removed entries must not be findable.
        assert_eq!(table.lookup(1, 0).unwrap(), None);
        assert_eq!(table.lookup(1, 192).unwrap(), None);
        assert_eq!(table.lookup(1, 448).unwrap(), None);
    }

    // ── Relocation ──────────────────────────────────────────────

    #[test]
    fn relocate_extent_updates_physical_offset() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e = LocatorEntry::new(0, ExtentId(42), 0, 4096, 8192, 0);
        table.insert(1, e).unwrap();

        // Relocate to a new physical offset.
        table.relocate_extent(1, ExtentId(42), 0, 16384).unwrap();

        let found = table.lookup(1, 0).unwrap();
        assert_eq!(found.unwrap().physical_offset, 16384);
        assert_eq!(found.unwrap().extent_id, ExtentId(42));
        assert_eq!(found.unwrap().logical_offset, 0);
        assert_eq!(found.unwrap().length, 8192);
    }

    #[test]
    fn relocate_nonexistent_extent_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        assert_eq!(
            table.relocate_extent(1, ExtentId(999), 0, 0),
            Err(LocatorError::NotFound)
        );
    }

    #[test]
    fn relocate_extent_into_compacted_table() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        // Insert several entries and remove some to create fragmentation.
        for i in 0..10 {
            table
                .insert(
                    1,
                    LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0),
                )
                .unwrap();
        }
        for i in (1..10).step_by(2) {
            table.remove(1, i * 64).unwrap();
        }

        // Compact, then relocate one of the remaining entries.
        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        table.relocate_extent(1, ExtentId(100), 0, 99999).unwrap();

        let found = table.lookup(1, 0).unwrap();
        assert_eq!(found.unwrap().physical_offset, 99999);
    }

    #[test]
    fn relocate_across_multiple_inodes_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0);
        let e2 = LocatorEntry::new(0, ExtentId(20), 0, 0, 4096, 0);
        table.insert(100, e1).unwrap();
        table.insert(200, e2).unwrap();

        // Relocate inode 100's extent.
        table.relocate_extent(100, ExtentId(10), 0, 8192).unwrap();

        // Inode 100 should see the new offset.
        assert_eq!(table.lookup(100, 0).unwrap().unwrap().physical_offset, 8192);

        // Inode 200 should be unaffected.
        assert_eq!(table.lookup(200, 0).unwrap().unwrap().physical_offset, 0);
    }

    #[test]
    fn relocate_extent_preserves_secondary_index() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e = LocatorEntry::new(4096, ExtentId(77), 0, 0, 2048, 0);
        table.insert(1, e).unwrap();

        table.relocate_extent(1, ExtentId(77), 0, 65536).unwrap();

        let found = table.lookup_extent(1, ExtentId(77)).unwrap();
        assert_eq!(found.unwrap().physical_offset, 65536);
    }

    #[test]
    fn relocate_then_compact_is_coherent() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e = LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0);
        table.insert(1, e).unwrap();

        table.relocate_extent(1, ExtentId(1), 0, 128).unwrap();
        table.relocate_extent(1, ExtentId(1), 0, 256).unwrap();

        // Compact and verify the final offset is preserved.
        let plan = table.compact(1).unwrap();
        table.swap_commit(plan).unwrap();

        let found = table.lookup(1, 0).unwrap();
        assert_eq!(found.unwrap().physical_offset, 256);
        assert_eq!(found.unwrap().extent_id, ExtentId(1));
    }

    #[test]
    fn relocate_does_not_affect_other_entries() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        let e1 = LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0);
        let e2 = LocatorEntry::new(64, ExtentId(2), 0, 64, 64, 0);
        let e3 = LocatorEntry::new(128, ExtentId(3), 0, 128, 64, 0);
        table.insert(1, e1).unwrap();
        table.insert(1, e2).unwrap();
        table.insert(1, e3).unwrap();

        table.relocate_extent(1, ExtentId(2), 0, 99999).unwrap();

        assert_eq!(table.lookup(1, 0).unwrap().unwrap().physical_offset, 0);
        assert_eq!(table.lookup(1, 64).unwrap().unwrap().physical_offset, 99999);
        assert_eq!(table.lookup(1, 128).unwrap().unwrap().physical_offset, 128);
    }

    // ── Concurrent swap-commit safety ────────────────────────────

    #[test]
    fn concurrent_lookup_during_swap_commit_sees_consistent_state() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        // Insert 5 entries.
        let mut entries = Vec::new();
        for i in 0..5 {
            let e = LocatorEntry::new(i * 64, ExtentId(100 + i), 0, i * 128, 64, 0);
            table.insert(1, e).unwrap();
            entries.push(e);
        }

        // Free 2 entries to create tombstones.
        table.remove(1, 64).unwrap();
        table.remove(1, 192).unwrap();

        let plan = table.compact(1).unwrap();

        // Wrap in Arc for shared access across threads.
        let table_ref = Arc::new(table);
        let barrier = Arc::new(Barrier::new(2));

        let table_clone = Arc::clone(&table_ref);
        let barrier_clone = Arc::clone(&barrier);

        // Reader thread: look up remaining entries during swap.
        let handle = thread::spawn(move || {
            barrier_clone.wait();
            // After barrier, try lookups — the swap may or may not have completed.
            for _attempt in 0..100 {
                let found_0 = table_clone.lookup(1, 0).unwrap();
                let found_128 = table_clone.lookup(1, 128).unwrap();
                let found_256 = table_clone.lookup(1, 256).unwrap();
                // Regardless of swap state, entries must be findable or absent,
                // but never corrupted (non-matching extent_id).
                if let Some(e) = found_0 {
                    assert_eq!(e.extent_id, ExtentId(100));
                }
                if let Some(e) = found_128 {
                    assert_eq!(e.extent_id, ExtentId(102));
                }
                if let Some(e) = found_256 {
                    assert_eq!(e.extent_id, ExtentId(104));
                }
            }
        });

        // Main thread: commit the swap.
        barrier.wait();
        table_ref.swap_commit(plan).unwrap();

        handle.join().unwrap();

        // Post-swap: all remaining entries must be present.
        assert!(table_ref.lookup(1, 0).unwrap().is_some());
        assert!(table_ref.lookup(1, 128).unwrap().is_some());
        assert!(table_ref.lookup(1, 256).unwrap().is_some());
        assert_eq!(table_ref.lookup(1, 64).unwrap(), None);
        assert_eq!(table_ref.lookup(1, 192).unwrap(), None);
    }

    // ── Pin check validation ─────────────────────────────────────

    struct AlwaysPinnedCheck;

    impl ExtentPinCheck for AlwaysPinnedCheck {
        fn is_pinned(&self, _ino: u64, _extent_id: ExtentId) -> bool {
            true
        }
    }

    #[test]
    fn relocate_pinned_extent_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(42), 0, 0, 4096, 0))
            .unwrap();

        table.set_pin_check(Arc::new(AlwaysPinnedCheck));

        let result = table.relocate_extent(1, ExtentId(42), 0, 99999);
        assert_eq!(result, Err(LocatorError::ExtentPinned));
    }

    struct SelectivePinCheck {
        pinned_ids: std::collections::HashSet<u64>,
    }

    impl ExtentPinCheck for SelectivePinCheck {
        fn is_pinned(&self, _ino: u64, extent_id: ExtentId) -> bool {
            self.pinned_ids.contains(&extent_id.0)
        }
    }

    #[test]
    fn relocate_unpinned_extent_succeeds_when_others_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(10), 0, 0, 4096, 0))
            .unwrap();
        table
            .insert(1, LocatorEntry::new(64, ExtentId(20), 0, 64, 4096, 0))
            .unwrap();

        let mut pinned = std::collections::HashSet::new();
        pinned.insert(20);
        table.set_pin_check(Arc::new(SelectivePinCheck { pinned_ids: pinned }));

        // Extent 10 is not pinned, should relocate.
        table.relocate_extent(1, ExtentId(10), 0, 88888).unwrap();
        assert_eq!(table.lookup(1, 0).unwrap().unwrap().physical_offset, 88888);

        // Extent 20 is pinned, should fail.
        assert_eq!(
            table.relocate_extent(1, ExtentId(20), 0, 99999),
            Err(LocatorError::ExtentPinned)
        );
    }

    #[test]
    fn relocate_without_pin_check_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 4096, 0))
            .unwrap();

        // No pin check set — relocation always succeeds.
        table.relocate_extent(1, ExtentId(1), 0, 12345).unwrap();
        assert_eq!(table.lookup(1, 0).unwrap().unwrap().physical_offset, 12345);
    }

    // ── Data mover validation ────────────────────────────────────

    struct SpyDataMover {
        reads: Mutex<Vec<(u64, u64, u32)>>,
        writes: Mutex<Vec<(u64, u64, Vec<u8>)>>,
        read_data: Mutex<Vec<u8>>,
    }

    impl SpyDataMover {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                reads: Mutex::new(Vec::new()),
                writes: Mutex::new(Vec::new()),
                read_data: Mutex::new(read_data),
            }
        }
    }

    impl RelocationDataMover for SpyDataMover {
        fn read_extent(
            &self,
            device_id: u64,
            physical_offset: u64,
            _length: u32,
        ) -> Result<Vec<u8>> {
            self.reads
                .lock()
                .unwrap()
                .push((device_id, physical_offset, _length));
            Ok(self.read_data.lock().unwrap().clone())
        }

        fn write_extent(&self, device_id: u64, physical_offset: u64, data: &[u8]) -> Result<()> {
            self.writes
                .lock()
                .unwrap()
                .push((device_id, physical_offset, data.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn data_mover_called_during_relocate_commit() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let data = vec![0xAB; 4096];
        let spy = Arc::new(SpyDataMover::new(data.clone()));
        table.set_data_mover(spy.clone());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(42), 0, 0, 4096, 0))
            .unwrap();

        let plan = table.relocate_prepare(1, ExtentId(42), 1, 8192).unwrap();

        let stats = table.relocate_commit(plan).unwrap();
        assert_eq!(stats.extents_relocated, 1);
        assert_eq!(stats.bytes_relocated, 4096);
        // relocation_time_ms is u64, always non-negative

        // Verify reads and writes were issued.
        let reads = spy.reads.lock().unwrap();
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0], (0, 0, 4096));

        let writes = spy.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, 1);
        assert_eq!(writes[0].1, 8192);
        assert_eq!(writes[0].2, data);

        // Metadata updated.
        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.device_id, 1);
        assert_eq!(found.physical_offset, 8192);
    }

    #[test]
    fn data_mover_not_called_when_location_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        let spy = Arc::new(SpyDataMover::new(vec![0; 64]));
        table.set_data_mover(spy.clone());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(1), 0, 0, 64, 0))
            .unwrap();

        // Prepare relocation to the SAME location.
        let plan = table.relocate_prepare(1, ExtentId(1), 0, 0).unwrap();

        table.relocate_commit(plan).unwrap();

        // No reads or writes should have been issued.
        assert!(spy.reads.lock().unwrap().is_empty());
        assert!(spy.writes.lock().unwrap().is_empty());
    }

    #[test]
    fn relocate_commit_metadata_only_when_no_data_mover() {
        let dir = tempfile::tempdir().unwrap();
        let table = make_table(dir.path());

        table
            .insert(1, LocatorEntry::new(0, ExtentId(77), 0, 0, 4096, 0))
            .unwrap();

        let plan = table.relocate_prepare(1, ExtentId(77), 2, 16384).unwrap();

        // No data mover set — should succeed metadata-only.
        let stats = table.relocate_commit(plan).unwrap();
        assert_eq!(stats.extents_relocated, 1);

        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.device_id, 2);
        assert_eq!(found.physical_offset, 16384);
    }

    #[test]
    fn data_mover_read_failure_preserves_old_location() {
        struct FailingReadMover;

        impl RelocationDataMover for FailingReadMover {
            fn read_extent(
                &self,
                _device_id: u64,
                _physical_offset: u64,
                _length: u32,
            ) -> Result<Vec<u8>> {
                Err(LocatorError::Store("read failed".into()))
            }

            fn write_extent(
                &self,
                _device_id: u64,
                _physical_offset: u64,
                _data: &[u8],
            ) -> Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        table.set_data_mover(Arc::new(FailingReadMover));

        table
            .insert(1, LocatorEntry::new(0, ExtentId(5), 0, 0, 64, 0))
            .unwrap();

        let plan = table.relocate_prepare(1, ExtentId(5), 1, 128).unwrap();

        let result = table.relocate_commit(plan);
        assert!(result.is_err());

        // Old location must still be valid.
        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.device_id, 0);
        assert_eq!(found.physical_offset, 0);
    }

    #[test]
    fn data_mover_write_failure_preserves_old_location() {
        struct FailingWriteMover;

        impl RelocationDataMover for FailingWriteMover {
            fn read_extent(
                &self,
                _device_id: u64,
                _physical_offset: u64,
                _length: u32,
            ) -> Result<Vec<u8>> {
                Ok(vec![0xCC; 64])
            }

            fn write_extent(
                &self,
                _device_id: u64,
                _physical_offset: u64,
                _data: &[u8],
            ) -> Result<()> {
                Err(LocatorError::Store("write failed".into()))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let mut table = make_table(dir.path());

        table.set_data_mover(Arc::new(FailingWriteMover));

        table
            .insert(1, LocatorEntry::new(0, ExtentId(9), 0, 0, 64, 0))
            .unwrap();

        let plan = table.relocate_prepare(1, ExtentId(9), 3, 256).unwrap();

        let result = table.relocate_commit(plan);
        assert!(result.is_err());

        // Old location must still be valid.
        let found = table.lookup(1, 0).unwrap().unwrap();
        assert_eq!(found.device_id, 0);
        assert_eq!(found.physical_offset, 0);
    }
}
