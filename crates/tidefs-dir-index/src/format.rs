//! Binary on-media format for persistent directory pages.
//!
//! Each directory is stored as a sequence of fixed-size [`DirPage`] objects
//! (4 KiB) in the object store, keyed by directory inode and page number.
//! This enables incremental persistence, random-access lookup, and
//! readdir-pagination without loading the entire directory into memory.

#[cfg(feature = "persistent-dir-index")]
use alloc::format;
#[cfg(feature = "persistent-dir-index")]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "persistent-dir-index")]
use tidefs_local_object_store::ObjectKey;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of every DirPage: "VDIR".
pub const DIR_PAGE_MAGIC: [u8; 4] = [b'V', b'D', b'I', b'R'];

/// Fixed size of every directory page in bytes.
pub const DIR_PAGE_SIZE: usize = 4096;

/// Number of bytes used by the DirPage header.
pub const DIR_PAGE_HEADER_LEN: usize = 16;

/// Available space for packed DirEntry records within a page.
pub const DIR_PAGE_ENTRIES_AREA: usize = DIR_PAGE_SIZE - DIR_PAGE_HEADER_LEN;

/// Maximum name length stored in a DirEntry.
pub const DIR_ENTRY_MAX_NAME: usize = 255;

/// Fixed size of the per-entry header (excluding the name).
pub const DIR_ENTRY_HEADER_LEN: usize = 26;

/// Maximum on-media size of a single DirEntry.
pub const DIR_ENTRY_MAX_SIZE: usize = DIR_ENTRY_HEADER_LEN + DIR_ENTRY_MAX_NAME;

/// Entry type constants matching `tidefs_types_polymorphic_directory_index_core` `NodeKind`.
pub const DT_DIR: u8 = 0;
pub const DT_FILE: u8 = 1;
pub const DT_SYMLINK: u8 = 2;

// ---------------------------------------------------------------------------
// DirEntry -- binary on-media entry record
// ---------------------------------------------------------------------------

/// A single directory entry in its binary on-media representation.
///
/// Layout (little-endian):
/// ```text
/// Offset  Size  Field
/// 0       1     name_len    (u8, 0..=255)
/// 1       8     inode_id    (u64)
/// 9       1     entry_type  (u8, DT_DIR/DT_FILE/DT_SYMLINK)
/// 10      8     generation  (u64)
/// 18      8     offset      (u64, monotonic directory offset)
/// 26      N     name        ([u8; name_len])
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    /// Length of the name in bytes (0..=255).
    pub name_len: u8,
    /// Target inode number.
    pub inode_id: u64,
    /// Entry type: `DT_DIR`, `DT_FILE`, or `DT_SYMLINK`.
    pub entry_type: u8,
    /// Inode generation counter.
    pub generation: u64,
    /// Monotonic directory offset for telldir/seekdir correctness.
    pub offset: u64,
    /// Entry name (not NUL-terminated).
    pub name: Vec<u8>,
}

impl DirEntry {
    /// Size of this entry when serialized on-media.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        DIR_ENTRY_HEADER_LEN + self.name_len as usize
    }

    /// Serialize this entry into `buf` at the current position.
    ///
    /// Returns the number of bytes written. Panics if `buf` is too small.
    pub fn encode_into(&self, buf: &mut [u8]) -> usize {
        let total = self.encoded_len();
        assert!(buf.len() >= total, "buffer too small for DirEntry");
        buf[0] = self.name_len;
        buf[1..9].copy_from_slice(&self.inode_id.to_le_bytes());
        buf[9] = self.entry_type;
        buf[10..18].copy_from_slice(&self.generation.to_le_bytes());
        buf[18..26].copy_from_slice(&self.offset.to_le_bytes());
        buf[26..26 + self.name_len as usize].copy_from_slice(&self.name);
        total
    }

    /// Deserialize a `DirEntry` from `src`.
    ///
    /// Returns `None` if the buffer is too short or the declared name
    /// length exceeds the remaining bytes.
    #[must_use]
    pub fn decode(src: &[u8]) -> Option<Self> {
        if src.len() < DIR_ENTRY_HEADER_LEN {
            return None;
        }
        let name_len = src[0];
        if src.len() < DIR_ENTRY_HEADER_LEN + name_len as usize {
            return None;
        }
        if name_len as usize > DIR_ENTRY_MAX_NAME {
            return None;
        }
        let inode_id = u64::from_le_bytes(src[1..9].try_into().unwrap());
        let entry_type = src[9];
        let generation = u64::from_le_bytes(src[10..18].try_into().unwrap());
        let offset = u64::from_le_bytes(src[18..26].try_into().unwrap());
        let name = src[26..26 + name_len as usize].to_vec();
        Some(DirEntry {
            name_len,
            inode_id,
            entry_type,
            generation,
            offset,
            name,
        })
    }
}

// ---------------------------------------------------------------------------
// DirPage -- fixed-size 4 KiB directory page
// ---------------------------------------------------------------------------

/// A fixed-size 4 KiB directory page containing a header and packed entries.
///
/// Layout (little-endian):
/// ```text
/// Offset  Size  Field
/// 0       4     magic       ([u8; 4] = b"VDIR")
/// 4       4     page_number (u32)
/// 8       2     entry_count (u16)
/// 10      2     flags       (u16, bit 0 = has_tombstones)
/// 12      4     reserved    ([u8; 4], zero)
/// 16      N     entries     (packed DirEntry records)
/// N..4096      padding      (zero fill)
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirPage {
    /// Page number within the directory (0-based, monotonic).
    pub page_number: u32,
    /// Number of live entries in this page.
    pub entry_count: u16,
    /// Page flags. Bit 0: has_tombstones.
    pub flags: u16,
    /// Packed directory entries in this page.
    pub entries: Vec<DirEntry>,
}

impl DirPage {
    /// Create an empty page with the given page number.
    #[must_use]
    pub fn new(page_number: u32) -> Self {
        DirPage {
            page_number,
            entry_count: 0,
            flags: 0,
            entries: Vec::new(),
        }
    }

    /// Whether the page has tombstoned (deleted) entries.
    #[must_use]
    pub fn has_tombstones(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Set the tombstone flag.
    pub fn set_has_tombstones(&mut self, v: bool) {
        if v {
            self.flags |= 1;
        } else {
            self.flags &= !1;
        }
    }

    /// Number of bytes currently consumed by entries in this page.
    #[must_use]
    pub fn bytes_used(&self) -> usize {
        self.entries.iter().map(|e| e.encoded_len()).sum()
    }

    /// Number of free bytes remaining for entries.
    #[must_use]
    pub fn bytes_free(&self) -> usize {
        DIR_PAGE_ENTRIES_AREA.saturating_sub(self.bytes_used())
    }

    /// Whether a new entry of `encoded_len` bytes can fit in this page.
    #[must_use]
    pub fn can_fit(&self, encoded_len: usize) -> bool {
        self.bytes_free() >= encoded_len
    }

    /// Serialize this page into a fixed-size 4096-byte buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; DIR_PAGE_SIZE] {
        let mut buf = [0u8; DIR_PAGE_SIZE];
        buf[0..4].copy_from_slice(&DIR_PAGE_MAGIC);
        buf[4..8].copy_from_slice(&self.page_number.to_le_bytes());
        buf[8..10].copy_from_slice(&self.entry_count.to_le_bytes());
        buf[10..12].copy_from_slice(&self.flags.to_le_bytes());
        // bytes 12..16 are zero (reserved)
        let mut cursor = DIR_PAGE_HEADER_LEN;
        for entry in &self.entries {
            let n = entry.encode_into(&mut buf[cursor..]);
            cursor += n;
        }
        buf
    }

    /// Deserialize a DirPage from a 4096-byte buffer.
    ///
    /// Returns `None` if the magic is wrong or the page data is corrupt.
    #[must_use]
    pub fn decode(buf: &[u8; DIR_PAGE_SIZE]) -> Option<Self> {
        if buf[0..4] != DIR_PAGE_MAGIC {
            return None;
        }
        let page_number = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        let entry_count = u16::from_le_bytes(buf[8..10].try_into().unwrap());
        let flags = u16::from_le_bytes(buf[10..12].try_into().unwrap());

        let mut entries = Vec::with_capacity(entry_count as usize);
        let mut cursor = DIR_PAGE_HEADER_LEN;
        let mut decoded = 0u16;
        while cursor < DIR_PAGE_SIZE && decoded < entry_count {
            let remaining = DIR_PAGE_SIZE - cursor;
            if remaining < DIR_ENTRY_HEADER_LEN {
                break;
            }
            if buf[cursor..DIR_PAGE_SIZE].iter().all(|&b| b == 0) {
                break; // pure padding reached before expected entries
            }
            match DirEntry::decode(&buf[cursor..]) {
                Some(entry) => {
                    cursor += entry.encoded_len();
                    decoded += 1;
                    entries.push(entry);
                }
                None => break,
            }
        }

        if decoded != entry_count {
            return None;
        }

        if !buf[cursor..DIR_PAGE_SIZE].iter().all(|&b| b == 0) {
            return None;
        }

        Some(DirPage {
            page_number,
            entry_count,
            flags,
            entries,
        })
    }
}

// ---------------------------------------------------------------------------
// Object-store key derivation
// ---------------------------------------------------------------------------
#[cfg(feature = "persistent-dir-index")]
/// Key prefix for directory-page objects in the object store.
pub const DIR_PAGE_KEY_PREFIX: &str = "dir_page";

#[cfg(feature = "persistent-dir-index")]
/// Derive the object-store key for a specific directory page.
#[must_use]
pub fn dir_page_key(dir_ino: u64, page_number: u32) -> ObjectKey {
    let name = format!("{DIR_PAGE_KEY_PREFIX}:{dir_ino:020x}:{page_number:08x}");
    ObjectKey::from_name(name)
}

#[cfg(feature = "persistent-dir-index")]
/// Derive the object-store key prefix for all pages of a directory.
#[must_use]
pub fn dir_page_prefix(dir_ino: u64) -> String {
    format!("{DIR_PAGE_KEY_PREFIX}:{dir_ino:020x}:")
}

#[cfg(feature = "persistent-dir-index")]
/// Derive the object-store key for the namespace manifest.
#[must_use]
pub fn namespace_manifest_key() -> ObjectKey {
    ObjectKey::from_name("ns:manifest")
}

#[cfg(feature = "persistent-dir-index")]
/// Magic prefix for namespace manifest payload (4 bytes): "NSMF".
pub const NS_MANIFEST_MAGIC: [u8; 4] = [b'N', b'S', b'M', b'F'];
#[cfg(feature = "persistent-dir-index")]
/// Derive the object-store key for the dir-index batch commit marker.
///
/// The batch commit marker is written as the final step of a
/// [`crate::persistent::DirBatch::commit`] call and acts as an
/// atomicity fence: if the marker is present on load, the entire batch
/// committed; if absent, no batch operations are visible (all-or-nothing).
#[must_use]
pub fn dir_batch_commit_key(dir_ino: u64) -> ObjectKey {
    let name = alloc::format!("dir_batch:commit:{dir_ino:020x}");
    ObjectKey::from_name(name)
}

/// Magic bytes for the batch commit marker payload: "DBTC".
pub const DIR_BATCH_COMMIT_MAGIC: [u8; 4] = [b'D', b'B', b'T', b'C'];

#[cfg(feature = "persistent-dir-index")]
/// Derive the object-store key for the directory version record.
///
/// The directory version is persisted as a separate key so that
/// [`crate::persistent::PersistentDirIndex::list_from_store`] can
/// validate version-bound cookies without loading the full directory
/// index into memory.
#[must_use]
pub fn dir_version_key(dir_ino: u64) -> ObjectKey {
    let name = alloc::format!("dir_version:{dir_ino:020x}");
    ObjectKey::from_name(name)
}

// ---------------------------------------------------------------------------
// Version-bound cookie encoding (embedded in DirCookie u64 payload)
// ---------------------------------------------------------------------------

/// Bit 62 set indicates this cookie carries directory-version evidence.
pub const DIR_COOKIE_VERSIONED_BIT: u64 = 62;

/// Mask for the versioned-cookie flag.
pub const DIR_COOKIE_VERSIONED_MASK: u64 = 1u64 << DIR_COOKIE_VERSIONED_BIT;

/// Number of bits allocated to the directory-version tag within a versioned cookie.
pub const DIR_COOKIE_VERSION_TAG_BITS: u64 = 14;

/// Shift for the version tag field within a versioned cookie.
pub const DIR_COOKIE_VERSION_TAG_SHIFT: u64 = 48;

/// Mask for the version tag field (bits [48, 61]).
pub const DIR_COOKIE_VERSION_TAG_MASK: u64 =
    ((1u64 << DIR_COOKIE_VERSION_TAG_BITS) - 1) << DIR_COOKIE_VERSION_TAG_SHIFT;

/// Mask for the positional skip count (bits [0, 47]).
pub const DIR_COOKIE_POSITION_MASK: u64 = (1u64 << DIR_COOKIE_VERSION_TAG_SHIFT) - 1;

/// Encode a directory version tag from the full 64-bit version.
///
/// The tag occupies the low `DIR_COOKIE_VERSION_TAG_BITS` bits of the
/// version, providing a check that fails when the directory is mutated
/// between readdir batches.
#[inline]
#[must_use]
pub const fn dir_cookie_version_tag(version: u64) -> u64 {
    version & ((1u64 << DIR_COOKIE_VERSION_TAG_BITS) - 1)
}

/// Decode the version tag from a version-bound cookie.
///
/// Returns `None` when the cookie does not have the versioned flag set.
/// Returns `Some(tag)` where `tag` is the embedded version evidence.
#[inline]
#[must_use]
pub fn dir_cookie_decode_version(cookie_raw: u64) -> Option<u64> {
    if cookie_raw & DIR_COOKIE_VERSIONED_MASK == 0 {
        None
    } else {
        Some((cookie_raw & DIR_COOKIE_VERSION_TAG_MASK) >> DIR_COOKIE_VERSION_TAG_SHIFT)
    }
}

/// Encode a versioned positional cookie from a skip count and directory version.
#[inline]
#[must_use]
pub const fn dir_cookie_encode_versioned(skip: u64, version: u64) -> u64 {
    DIR_COOKIE_VERSIONED_MASK
        | (dir_cookie_version_tag(version) << DIR_COOKIE_VERSION_TAG_SHIFT)
        | (skip & DIR_COOKIE_POSITION_MASK)
}

/// Extract the positional skip count from a (possibly versioned) cookie.
#[inline]
#[must_use]
pub const fn dir_cookie_skip(cookie_raw: u64) -> usize {
    (cookie_raw & DIR_COOKIE_POSITION_MASK) as usize
}

/// Validate a readdir resume cookie against the current directory version.
///
/// `0` is the only unversioned cookie accepted here: it means start a fresh
/// scan. Any non-zero resume cookie must carry version evidence that matches
/// the current directory version tag.
#[inline]
#[must_use]
pub fn dir_cookie_resume_skip(cookie_raw: u64, directory_version: u64) -> Option<usize> {
    if cookie_raw == 0 {
        return Some(0);
    }
    let cookie_version = dir_cookie_decode_version(cookie_raw)?;
    if cookie_version == dir_cookie_version_tag(directory_version) {
        Some(dir_cookie_skip(cookie_raw))
    } else {
        None
    }
}

#[cfg(all(test, feature = "persistent-dir-index"))]
mod tests {
    use super::*;
    use alloc::vec;

    fn make_entry(
        name: &[u8],
        inode_id: u64,
        entry_type: u8,
        generation: u64,
        offset: u64,
    ) -> DirEntry {
        DirEntry {
            name_len: name.len() as u8,
            inode_id,
            entry_type,
            generation,
            offset,
            name: name.to_vec(),
        }
    }

    #[test]
    fn entry_roundtrip_short_name() {
        let entry = make_entry(b"hello", 42, DT_FILE, 1, 0);
        let mut buf = vec![0u8; entry.encoded_len()];
        let n = entry.encode_into(&mut buf);
        assert_eq!(n, DIR_ENTRY_HEADER_LEN + 5);
        let decoded = DirEntry::decode(&buf).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn entry_roundtrip_empty_name() {
        let entry = make_entry(b"", 0, DT_DIR, 0, 100);
        let mut buf = vec![0u8; entry.encoded_len()];
        entry.encode_into(&mut buf);
        let decoded = DirEntry::decode(&buf).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn entry_roundtrip_max_name() {
        let name = vec![b'x'; 255];
        let entry = make_entry(&name, u64::MAX, DT_SYMLINK, u64::MAX, u64::MAX);
        let mut buf = vec![0u8; entry.encoded_len()];
        entry.encode_into(&mut buf);
        let decoded = DirEntry::decode(&buf).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn entry_decode_too_short() {
        assert!(DirEntry::decode(&[]).is_none());
        assert!(DirEntry::decode(&[0u8; DIR_ENTRY_HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn entry_decode_truncated_name() {
        let mut buf = vec![0u8; DIR_ENTRY_HEADER_LEN];
        buf[0] = 10;
        assert!(DirEntry::decode(&buf).is_none());
    }

    #[test]
    fn entry_decode_name_len_exceeds_max() {
        let mut buf = vec![0u8; DIR_ENTRY_HEADER_LEN + 250];
        buf[0] = 250;
        assert!(DirEntry::decode(&buf[..DIR_ENTRY_HEADER_LEN + 250]).is_some());
    }

    #[test]
    fn page_roundtrip_empty() {
        let page = DirPage::new(0);
        let buf = page.encode();
        let decoded = DirPage::decode(&buf).unwrap();
        assert_eq!(decoded, page);
    }

    #[test]
    fn page_roundtrip_with_entries() {
        let mut page = DirPage::new(1);
        page.entries.push(make_entry(b"alpha", 10, DT_FILE, 1, 0));
        page.entry_count = 1;
        page.entries.push(make_entry(b"beta", 20, DT_DIR, 2, 1));
        page.entry_count = 2;

        let buf = page.encode();
        let decoded = DirPage::decode(&buf).unwrap();
        assert_eq!(decoded.page_number, 1);
        assert_eq!(decoded.entry_count, 2);
        assert_eq!(decoded.entries.len(), 2);
    }

    #[test]
    fn page_roundtrip_with_tombstones_flag() {
        let mut page = DirPage::new(5);
        page.set_has_tombstones(true);
        page.entries.push(make_entry(b"live", 1, DT_FILE, 0, 0));
        page.entry_count = 1;

        let buf = page.encode();
        let decoded = DirPage::decode(&buf).unwrap();
        assert!(decoded.has_tombstones());
    }

    #[test]
    fn page_decode_wrong_magic() {
        let page = DirPage::new(0);
        let mut buf = page.encode();
        buf[0] = 0;
        assert!(DirPage::decode(&buf).is_none());
    }

    #[test]
    fn page_decode_entry_count_mismatch() {
        let mut page = DirPage::new(0);
        page.entries.push(make_entry(b"a", 1, DT_FILE, 0, 0));
        page.entry_count = 5;
        let buf = page.encode();
        assert!(DirPage::decode(&buf).is_none());
    }

    #[test]
    fn page_capacity_short_names() {
        let entry_size = DIR_ENTRY_HEADER_LEN + 4;
        let max_entries = DIR_PAGE_ENTRIES_AREA / entry_size;
        let mut page = DirPage::new(0);
        for i in 0..max_entries {
            let name = format!("{i:04}");
            let entry = make_entry(name.as_bytes(), i as u64, DT_FILE, 0, i as u64);
            assert!(page.can_fit(entry.encoded_len()));
            page.entries.push(entry);
        }
        page.entry_count = max_entries as u16;
        assert!(page.bytes_free() < entry_size);

        let buf = page.encode();
        let decoded = DirPage::decode(&buf).unwrap();
        assert_eq!(decoded.entries.len(), max_entries);
    }

    #[test]
    fn page_cannot_fit_oversized_entry() {
        let page = DirPage::new(0);
        assert!(!page.can_fit(DIR_PAGE_ENTRIES_AREA + 1));
    }

    #[test]
    fn page_bytes_used_and_free() {
        let mut page = DirPage::new(0);
        assert_eq!(page.bytes_used(), 0);
        assert_eq!(page.bytes_free(), DIR_PAGE_ENTRIES_AREA);

        let e1 = make_entry(b"hello", 1, DT_FILE, 0, 0);
        let e1_size = e1.encoded_len();
        page.entries.push(e1);
        assert_eq!(page.bytes_used(), e1_size);
        assert_eq!(page.bytes_free(), DIR_PAGE_ENTRIES_AREA - e1_size);
    }

    #[test]
    fn dir_page_key_derivation() {
        let key = dir_page_key(0xABCD, 0);
        let key2 = dir_page_key(0xABCD, 1);
        assert_ne!(key, key2);
        assert_eq!(dir_page_key(1, 5), dir_page_key(1, 5));
        assert_ne!(dir_page_key(1, 0), dir_page_key(2, 0));
    }

    #[test]
    fn dir_page_prefix_matches_keys() {
        let prefix = dir_page_prefix(42);
        let expected = format!("dir_page:{:020x}:", 42);
        assert_eq!(prefix, expected);
        let key0 = dir_page_key(42, 0);
        let key1 = dir_page_key(42, 1);
        assert_ne!(key0, key1, "different pages must have different keys");
    }

    #[test]
    fn entry_all_entry_types() {
        for (name, ty) in [("dir", DT_DIR), ("file", DT_FILE), ("link", DT_SYMLINK)] {
            let entry = make_entry(name.as_bytes(), 1, ty, 0, 0);
            let mut buf = vec![0u8; entry.encoded_len()];
            entry.encode_into(&mut buf);
            let decoded = DirEntry::decode(&buf).unwrap();
            assert_eq!(decoded.entry_type, ty);
        }
    }

    #[test]
    fn page_multiple_pages_different_numbers() {
        for pn in [0u32, 1, 42, u32::MAX] {
            let page = DirPage::new(pn);
            let buf = page.encode();
            let decoded = DirPage::decode(&buf).unwrap();
            assert_eq!(decoded.page_number, pn);
        }
    }

    #[test]
    fn entry_offset_monotonic_preserved() {
        let entry = make_entry(b"test", 10, DT_FILE, 5, 0xDEAD_BEEF_CAFE_BABE);
        let mut buf = vec![0u8; entry.encoded_len()];
        entry.encode_into(&mut buf);
        let decoded = DirEntry::decode(&buf).unwrap();
        assert_eq!(decoded.offset, 0xDEAD_BEEF_CAFE_BABE);
    }

    #[test]
    fn page_empty_has_no_tombstones() {
        let page = DirPage::new(0);
        assert!(!page.has_tombstones());
    }

    #[test]
    fn page_tombstones_flag_roundtrip() {
        let mut page = DirPage::new(0);
        page.set_has_tombstones(true);
        assert!(page.has_tombstones());
        let buf = page.encode();
        let decoded = DirPage::decode(&buf).unwrap();
        assert!(decoded.has_tombstones());
        let mut decoded = decoded;
        decoded.set_has_tombstones(false);
        assert!(!decoded.has_tombstones());
    }

    #[test]
    fn dir_batch_commit_key_consistent() {
        assert_eq!(dir_batch_commit_key(1), dir_batch_commit_key(1));
        assert_ne!(dir_batch_commit_key(1), dir_batch_commit_key(2));
        assert_ne!(dir_batch_commit_key(42), dir_page_key(42, 0));
    }

    #[test]
    fn dir_batch_commit_magic_not_zero() {
        assert_ne!(DIR_BATCH_COMMIT_MAGIC, [0u8; 4]);
    }

    #[test]
    fn batch_commit_and_page_keys_independent() {
        let batch_key = dir_batch_commit_key(0xABCD);
        let page0_key = dir_page_key(0xABCD, 0);
        assert_ne!(batch_key, page0_key);
    }
}
