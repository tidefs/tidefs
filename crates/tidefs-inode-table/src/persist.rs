// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-store persistence for the inode table.
//!
//! Provides binary encoding/decoding for [`InodeAttributes`] and the
//! [`InodeTableHeader`], plus store-backed save/load routines consumed
//! by [`super::InodeTable::open`] and [`super::InodeTable::commit`].
//!
//! # On-disk format
//!
//! Each inode is stored as a fixed-size 96-byte record. The header
//! is a variable-length blob. Both are stored in a
//! [`tidefs_local_object_store::LocalObjectStore`] via the named API.

use std::collections::BTreeMap;
use std::time::Duration;

use tidefs_local_object_store::LocalObjectStore;

use crate::{InodeAttributes, InodeKind};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Fixed size of a serialized inode record in bytes.
pub const INODE_RECORD_SIZE: usize = 96;

/// Key prefix for inode records in the named store API.
const INODE_KEY_PREFIX: &str = "tidefs:inode:";

/// Key for the persistent header.
const HEADER_KEY: &str = "tidefs:inode:header";

// ---------------------------------------------------------------------------
// Primitive encode / decode (little-endian)
// ---------------------------------------------------------------------------

fn write_u32_le(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

fn write_u64_le(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

#[allow(clippy::cast_possible_truncation)]
fn dur_to_secs_nanos(d: Duration) -> (u64, u32) {
    (d.as_secs(), d.subsec_nanos())
}

fn secs_nanos_to_dur(secs: u64, nanos: u32) -> Duration {
    Duration::new(secs, nanos)
}

// ---------------------------------------------------------------------------
// InodeAttributes binary format (96 bytes)
//
// Offset  Size  Field
// 0       4     mode (u32 LE)
// 4       4     uid (u32 LE)
// 8       4     gid (u32 LE)
// 12      8     size (u64 LE)
// 20      8     blocks (u64 LE)
// 28      8     atime_secs (u64 LE)
// 36      4     atime_nanos (u32 LE)
// 40      8     mtime_secs (u64 LE)
// 48      4     mtime_nanos (u32 LE)
// 52      8     ctime_secs (u64 LE)
// 60      4     ctime_nanos (u32 LE)
// 64      4     nlink (u32 LE)
// 68      8     generation (u64 LE)
// 76      1     kind (0=File, 1=Dir, 2=Symlink)
// 77..80  3     _reserved
// 80      4     dirty_bits (u32 LE) -- runtime dirty-tracking state
// 84      8     mutation_gen (u64 LE) -- monotonic mutation counter
// 92..96  4     _reserved2
// ---------------------------------------------------------------------------

impl InodeAttributes {
    /// Encode these attributes into a 96-byte fixed-size record.
    #[must_use]
    pub fn encode(&self) -> [u8; INODE_RECORD_SIZE] {
        let mut buf = [0u8; INODE_RECORD_SIZE];

        write_u32_le(&mut buf, 0, self.mode);
        write_u32_le(&mut buf, 4, self.uid);
        write_u32_le(&mut buf, 8, self.gid);
        write_u64_le(&mut buf, 12, self.size);
        write_u64_le(&mut buf, 20, self.blocks);
        let (atime_s, atime_ns) = dur_to_secs_nanos(self.atime);
        write_u64_le(&mut buf, 28, atime_s);
        write_u32_le(&mut buf, 36, atime_ns);
        let (mtime_s, mtime_ns) = dur_to_secs_nanos(self.mtime);
        write_u64_le(&mut buf, 40, mtime_s);
        write_u32_le(&mut buf, 48, mtime_ns);
        let (ctime_s, ctime_ns) = dur_to_secs_nanos(self.ctime);
        write_u64_le(&mut buf, 52, ctime_s);
        write_u32_le(&mut buf, 60, ctime_ns);
        write_u32_le(&mut buf, 64, self.nlink);
        write_u64_le(&mut buf, 68, self.generation);
        buf[76] = match self.kind {
            InodeKind::File => 0,
            InodeKind::Directory => 1,
            InodeKind::Symlink => 2,
        };
        write_u32_le(&mut buf, 80, self.dirty_bits);
        write_u64_le(&mut buf, 84, self.mutation_gen);

        buf
    }

    /// Decode a 96-byte record into [`InodeAttributes`].
    ///
    /// Returns `None` if the buffer is not exactly `INODE_RECORD_SIZE`
    /// bytes or the kind byte is out of range.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() != INODE_RECORD_SIZE {
            return None;
        }

        let mode = read_u32_le(data, 0);
        let uid = read_u32_le(data, 4);
        let gid = read_u32_le(data, 8);
        let size = read_u64_le(data, 12);
        let blocks = read_u64_le(data, 20);
        let atime_s = read_u64_le(data, 28);
        let atime_ns = read_u32_le(data, 36);
        let mtime_s = read_u64_le(data, 40);
        let mtime_ns = read_u32_le(data, 48);
        let ctime_s = read_u64_le(data, 52);
        let ctime_ns = read_u32_le(data, 60);
        let nlink = read_u32_le(data, 64);
        let generation = read_u64_le(data, 68);
        let kind = match data[76] {
            0 => InodeKind::File,
            1 => InodeKind::Directory,
            2 => InodeKind::Symlink,
            _ => return None,
        };

        let dirty_bits = read_u32_le(data, 80);
        let mutation_gen = read_u64_le(data, 84);

        Some(InodeAttributes {
            mode,
            uid,
            gid,
            size,
            blocks,
            atime: secs_nanos_to_dur(atime_s, atime_ns),
            mtime: secs_nanos_to_dur(mtime_s, mtime_ns),
            ctime: secs_nanos_to_dur(ctime_s, ctime_ns),
            nlink,
            generation,
            kind,
            xattrs: std::collections::BTreeMap::new(),
            dirty_bits,
            mutation_gen,
        })
    }
}

// ---------------------------------------------------------------------------
// InodeTableHeader — persistent header (variable-length)
// ---------------------------------------------------------------------------

/// Persistent state serialised to the object store under [`HEADER_KEY`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InodeTableHeader {
    /// Highest inode number ever allocated (cursor for new allocations).
    pub next_free_cursor: u64,
    /// Next generation number to assign.
    pub next_generation: u64,
    /// Freed inode numbers available for reuse (free list).
    pub free_list: Vec<u64>,
    /// Maximum capacity of the table.
    pub max_capacity: usize,
}

impl InodeTableHeader {
    /// Create a default header for a fresh table.
    #[must_use]
    pub fn new(max_capacity: usize) -> Self {
        Self {
            next_free_cursor: 1, // slot 0 reserved
            next_generation: 1,
            free_list: Vec::new(),
            max_capacity,
        }
    }

    /// Serialize the header to a byte vector for storage.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.free_list.len() * 8 + 8);
        buf.extend_from_slice(&self.next_free_cursor.to_le_bytes());
        buf.extend_from_slice(&self.next_generation.to_le_bytes());
        buf.extend_from_slice(&(self.free_list.len() as u32).to_le_bytes());
        for &ino in &self.free_list {
            buf.extend_from_slice(&ino.to_le_bytes());
        }
        buf.extend_from_slice(&(self.max_capacity as u64).to_le_bytes());
        buf
    }

    /// Deserialize a header from bytes.
    ///
    /// Returns `None` if the buffer is too short or corrupted.
    #[must_use]
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let next_free_cursor = u64::from_le_bytes(data[0..8].try_into().ok()?);
        let next_generation = u64::from_le_bytes(data[8..16].try_into().ok()?);
        let free_list_len = u32::from_le_bytes(data[16..20].try_into().ok()?) as usize;

        let expected_len = 20 + free_list_len * 8 + 8;
        if data.len() < expected_len {
            return None;
        }

        let mut free_list = Vec::with_capacity(free_list_len);
        for i in 0..free_list_len {
            let offset = 20 + i * 8;
            free_list.push(u64::from_le_bytes(
                data[offset..offset + 8].try_into().ok()?,
            ));
        }

        let cap_offset = 20 + free_list_len * 8;
        let max_capacity =
            u64::from_le_bytes(data[cap_offset..cap_offset + 8].try_into().ok()?) as usize;

        Some(Self {
            next_free_cursor,
            next_generation,
            free_list,
            max_capacity,
        })
    }
}

// ---------------------------------------------------------------------------
// Name helpers
// ---------------------------------------------------------------------------

fn inode_name(ino_num: u64) -> String {
    format!("{INODE_KEY_PREFIX}{ino_num}")
}

fn xattr_name(ino_num: u64) -> String {
    format!("{INODE_KEY_PREFIX}{ino_num}:xattrs")
}

fn header_name() -> &'static str {
    HEADER_KEY
}

// ---------------------------------------------------------------------------
// Persistence errors
// ---------------------------------------------------------------------------

/// Errors returned by persistence operations.
#[derive(Debug)]
pub enum PersistError {
    /// An error from the underlying object store.
    Store(String),
    /// Corrupt or unreadable data in the store.
    Corrupt(String),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(msg) => write!(f, "store error: {msg}"),
            Self::Corrupt(msg) => write!(f, "corrupt data: {msg}"),
        }
    }
}

impl std::error::Error for PersistError {}

impl From<tidefs_local_object_store::StoreError> for PersistError {
    fn from(e: tidefs_local_object_store::StoreError) -> Self {
        Self::Store(format!("{e}"))
    }
}

// ---------------------------------------------------------------------------
// Xattr encode / decode (variable-length)
// ---------------------------------------------------------------------------

/// Encode a xattr map into a byte vector.
#[must_use]
pub fn encode_xattrs(xattrs: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
    let mut buf = Vec::new();
    // Count: u32 LE
    buf.extend_from_slice(&(xattrs.len() as u32).to_le_bytes());
    for (name, value) in xattrs {
        // name_len: u16 LE
        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        buf.extend_from_slice(name);
        // value_len: u32 LE
        buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        buf.extend_from_slice(value);
    }
    buf
}

/// Decode a xattr map from bytes.
///
/// Returns `None` if the data is corrupt or truncated.
#[must_use]
pub fn decode_xattrs(data: &[u8]) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut xattrs = BTreeMap::new();
    let mut pos = 0;
    if data.len() < 4 {
        return None;
    }
    let count = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
    pos += 4;

    for _ in 0..count {
        if pos + 2 > data.len() {
            return None;
        }
        let name_len = u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as usize;
        pos += 2;
        if pos + name_len + 4 > data.len() {
            return None;
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;
        let value_len = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?) as usize;
        pos += 4;
        if pos + value_len > data.len() {
            return None;
        }
        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;
        xattrs.insert(name, value);
    }
    Some(xattrs)
}

// ---------------------------------------------------------------------------
// Save / load operations
// ---------------------------------------------------------------------------

/// Internal inode entry type exported from the parent module.
pub(crate) use crate::InodeEntry;

/// Load all inodes from `store` and return the slots vector.
pub(crate) fn load_all_inodes(
    store: &LocalObjectStore,
    header: &InodeTableHeader,
) -> Result<Vec<Option<InodeEntry>>, PersistError> {
    // Allocate enough slots to cover the highest known inode number.
    // The table grows dynamically up to max_capacity as new inodes are
    // allocated, so we don't pre-allocate the full capacity here.
    let slot_count = header.next_free_cursor as usize;
    let mut slots: Vec<Option<InodeEntry>> = vec![None; slot_count];

    // Iterate inode numbers from 1..next_free_cursor and load each.
    for ino_num in 1..header.next_free_cursor {
        if let Some(entry) = load_inode_entry_at(store, ino_num)? {
            if (ino_num as usize) < slots.len() {
                slots[ino_num as usize] = Some(entry);
            }
        }
    }

    Ok(slots)
}

fn load_inode_entry_at(
    store: &LocalObjectStore,
    ino_num: u64,
) -> Result<Option<InodeEntry>, PersistError> {
    let name = inode_name(ino_num);
    let Some(data) = store.get_named(&name)? else {
        return Ok(None);
    };
    let Some(mut attrs) = InodeAttributes::decode(&data) else {
        return Err(PersistError::Corrupt(format!(
            "invalid inode record for ino {ino_num}"
        )));
    };

    let xname = xattr_name(ino_num);
    if let Some(xdata) = store.get_named(&xname)? {
        let Some(xattrs) = decode_xattrs(&xdata) else {
            return Err(PersistError::Corrupt(format!(
                "invalid xattr record for ino {ino_num}"
            )));
        };
        attrs.xattrs = xattrs;
    }

    let ino = crate::Ino(ino_num);
    Ok(Some(InodeEntry { ino, attrs }))
}

/// Load one persisted inode directly from the store without building slots.
pub(crate) fn load_inode(
    store: &LocalObjectStore,
    header: &InodeTableHeader,
    ino: crate::Ino,
) -> Result<Option<InodeEntry>, PersistError> {
    if ino.0 == 0 || ino.0 >= header.next_free_cursor {
        return Ok(None);
    }

    load_inode_entry_at(store, ino.0)
}

/// Read a bounded live-inode window directly from the store.
pub(crate) fn load_inode_window(
    store: &LocalObjectStore,
    header: &InodeTableHeader,
    start_ino: crate::Ino,
    max_entries: usize,
) -> Result<(Vec<InodeEntry>, Option<crate::Ino>), PersistError> {
    let mut entries = Vec::with_capacity(max_entries.min(128));
    let mut cursor = start_ino.0.max(1);

    if cursor >= header.next_free_cursor {
        return Ok((entries, None));
    }
    if max_entries == 0 {
        return Ok((entries, Some(crate::Ino(cursor))));
    }

    while cursor < header.next_free_cursor {
        if let Some(entry) = load_inode_entry_at(store, cursor)? {
            entries.push(entry);
            if entries.len() == max_entries {
                let next = cursor
                    .checked_add(1)
                    .filter(|next_cursor| *next_cursor < header.next_free_cursor)
                    .map(crate::Ino);
                return Ok((entries, next));
            }
        }
        cursor += 1;
    }

    Ok((entries, None))
}

/// Write a dirty inode to the store.
pub(crate) fn save_inode(
    store: &mut LocalObjectStore,
    ino_num: u64,
    entry: &InodeEntry,
) -> Result<(), PersistError> {
    let name = inode_name(ino_num);
    let data = entry.attrs.encode();
    store.put_named(&name, &data)?;

    // Save xattrs separately if non-empty.
    if !entry.attrs.xattrs.is_empty() {
        let xname = xattr_name(ino_num);
        let xdata = encode_xattrs(&entry.attrs.xattrs);
        store.put_named(&xname, &xdata)?;
    }

    Ok(())
}

/// Write the persistent header to the store, overwriting any previous header.
pub(crate) fn save_header(
    store: &mut LocalObjectStore,
    header: &InodeTableHeader,
) -> Result<(), PersistError> {
    store.put_named(header_name(), &header.encode())?;
    Ok(())
}

/// Load the persistent header from the store, returning `None` when no
/// header has been written yet (fresh store).
pub(crate) fn load_header(
    store: &LocalObjectStore,
) -> Result<Option<InodeTableHeader>, PersistError> {
    match store.get_named(header_name())? {
        Some(data) => InodeTableHeader::decode(&data)
            .map(Some)
            .ok_or_else(|| PersistError::Corrupt("invalid inode table header".to_string())),
        None => Ok(None),
    }
}

/// Delete an inode record from the store.
pub(crate) fn delete_inode(
    store: &mut LocalObjectStore,
    ino_num: u64,
) -> Result<bool, PersistError> {
    let name = inode_name(ino_num);
    let xname = xattr_name(ino_num);
    // Delete xattr entry if it exists (ignore errors if not present).
    let _ = store.delete_named(&xname);
    Ok(store.delete_named(&name)?)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let attrs = InodeAttributes {
            mode: 0o755,
            uid: 1000,
            gid: 100,
            size: 4096,
            blocks: 8,
            atime: Duration::new(100, 500_000_000),
            mtime: Duration::new(200, 250_000_000),
            ctime: Duration::new(300, 750_000_000),
            nlink: 3,
            generation: 42,
            kind: InodeKind::File,
            xattrs: std::collections::BTreeMap::new(),
            dirty_bits: 0,
            mutation_gen: 0,
        };

        let encoded = attrs.encode();
        assert_eq!(encoded.len(), INODE_RECORD_SIZE);

        let decoded = InodeAttributes::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, attrs);
    }

    #[test]
    fn encode_decode_all_kinds() {
        for kind in [InodeKind::File, InodeKind::Directory, InodeKind::Symlink] {
            let attrs = InodeAttributes::new(0o644, 0, 0, kind);
            let encoded = attrs.encode();
            let decoded = InodeAttributes::decode(&encoded).unwrap();
            assert_eq!(decoded.kind, kind);
        }
    }

    #[test]
    fn decode_wrong_size_returns_none() {
        assert!(InodeAttributes::decode(&[0u8; 95]).is_none());
        assert!(InodeAttributes::decode(&[0u8; 97]).is_none());
        assert!(InodeAttributes::decode(&[]).is_none());
    }

    #[test]
    fn decode_bad_kind_returns_none() {
        let attrs = InodeAttributes::new(0o644, 0, 0, InodeKind::File);
        let mut encoded = attrs.encode();
        encoded[76] = 99;
        assert!(InodeAttributes::decode(&encoded).is_none());
    }

    #[test]
    fn header_encode_decode_roundtrip() {
        let header = InodeTableHeader {
            next_free_cursor: 15,
            next_generation: 100,
            free_list: vec![3, 7, 11],
            max_capacity: 1024,
        };

        let data = header.encode();
        let decoded = InodeTableHeader::decode(&data).expect("decode should succeed");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_decode_empty_free_list() {
        let header = InodeTableHeader::new(512);
        let data = header.encode();
        let decoded = InodeTableHeader::decode(&data).unwrap();
        assert!(decoded.free_list.is_empty());
        assert_eq!(decoded.next_generation, 1);
        assert_eq!(decoded.max_capacity, 512);
    }

    #[test]
    fn header_decode_too_short_returns_none() {
        assert!(InodeTableHeader::decode(&[0u8; 19]).is_none());
        assert!(InodeTableHeader::decode(&[]).is_none());
    }

    #[test]
    fn header_decode_corrupt_free_list_returns_none() {
        let header = InodeTableHeader {
            next_free_cursor: 10,
            next_generation: 5,
            free_list: vec![1, 2, 3],
            max_capacity: 64,
        };
        let mut data = header.encode();
        data.truncate(data.len() - 5);
        assert!(InodeTableHeader::decode(&data).is_none());
    }

    #[test]
    fn encode_zero_duration() {
        let attrs = InodeAttributes::new(0o644, 0, 0, InodeKind::File);
        let encoded = attrs.encode();
        let decoded = InodeAttributes::decode(&encoded).unwrap();
        assert_eq!(decoded.atime, Duration::ZERO);
        assert_eq!(decoded.mtime, Duration::ZERO);
        assert_eq!(decoded.ctime, Duration::ZERO);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Extended attribute persistence tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn xattr_encode_decode_roundtrip() {
        let mut xattrs = BTreeMap::new();
        xattrs.insert(b"user.key1".to_vec(), b"val1".to_vec());
        xattrs.insert(b"user.key2".to_vec(), b"hello world".to_vec());
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert_eq!(decoded, xattrs);
    }

    #[test]
    fn xattr_encode_decode_empty() {
        let xattrs: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert!(decoded.is_empty());
    }

    #[test]
    fn xattr_decode_corrupt_truncated_count() {
        assert!(decode_xattrs(&[0x01]).is_none());
        assert!(decode_xattrs(&[]).is_none());
    }

    #[test]
    fn xattr_decode_corrupt_truncated_name() {
        let mut data = vec![1, 0, 0, 0]; // count=1
        data.extend_from_slice(&[10, 0]); // name_len=10
        data.extend_from_slice(b"short"); // only 5 bytes, not 10
        assert!(decode_xattrs(&data).is_none());
    }

    #[test]
    fn xattr_decode_corrupt_truncated_value() {
        let mut data = vec![1, 0, 0, 0]; // count=1
        data.extend_from_slice(&[4, 0]); // name_len=4
        data.extend_from_slice(b"test");
        data.extend_from_slice(&[100, 0, 0, 0]); // value_len=100
        data.extend_from_slice(&[0u8; 50]); // only 50 bytes
        assert!(decode_xattrs(&data).is_none());
    }

    #[test]
    fn xattr_encode_decode_large_values() {
        let mut xattrs = BTreeMap::new();
        let big_value = vec![0xAB; 64 * 1024];
        xattrs.insert(b"user.big".to_vec(), big_value.clone());
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert_eq!(decoded.get(b"user.big".as_slice()), Some(&big_value));
    }

    #[test]
    fn xattr_encode_decode_multiple_keys() {
        let mut xattrs = BTreeMap::new();
        for i in 0..50 {
            xattrs.insert(format!("user.key{i}").into_bytes(), vec![i as u8; 16]);
        }
        let encoded = encode_xattrs(&xattrs);
        let decoded = decode_xattrs(&encoded).expect("decode should succeed");
        assert_eq!(decoded, xattrs);
    }

    #[test]
    fn encode_max_values() {
        let attrs = InodeAttributes {
            mode: u32::MAX,
            uid: u32::MAX,
            gid: u32::MAX,
            size: u64::MAX,
            blocks: u64::MAX,
            atime: Duration::new(u64::MAX, 999_999_999),
            mtime: Duration::new(u64::MAX, 999_999_999),
            ctime: Duration::new(u64::MAX, 999_999_999),
            nlink: u32::MAX,
            generation: u64::MAX,
            kind: InodeKind::Symlink,
            xattrs: std::collections::BTreeMap::new(),
            dirty_bits: 0,
            mutation_gen: 0,
        };
        let encoded = attrs.encode();
        let decoded = InodeAttributes::decode(&encoded).unwrap();
        assert_eq!(decoded, attrs);
    }
}
