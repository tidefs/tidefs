// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Fixed-size 4 KB page format for persistent B+tree storage.
//!
//! Every B+tree node lives in exactly one 4096-byte page. The page header
//! carries a BLAKE3 keyed checksum over the page body, a generation number
//! for WAL sequencing, and a page-type discriminant.
//!
//! ## On-disk layout
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │ PageHeader (16 bytes)                        │
//! │  magic:      [u8; 4]   "VBTR"               │
//! │  page_type:  u8        Leaf/Internal/Free    │
//! │  generation: [u8; 3]   u24 LE, WAL seq       │
//! │  checksum:   [u8; 8]   BLAKE3 truncated      │
//! ├──────────────────────────────────────────────┤
//! │ Page body (4080 bytes)                       │
//! │  Leaf:   u32 count + entries                 │
//! │  Internal: u32 child_count + child ids + keys│
//! │  Free:   zero-filled                         │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! ## Checksum
//!
//! The checksum covers bytes `[PAGE_HEADER_SIZE..PAGE_SIZE)` — the entire
//! 4080-byte page body. Domain separation is applied by page type so leaf
//! and internal page checksums can never collide.

use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Total page size in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Size of the fixed page header.
pub const PAGE_HEADER_SIZE: usize = 16;

/// Size of the page body (everything after the header).
pub const PAGE_BODY_SIZE: usize = PAGE_SIZE - PAGE_HEADER_SIZE; // 4080

/// Magic bytes identifying a valid TideFS B+tree page: "VBTR".
pub const PAGE_MAGIC: [u8; 4] = [0x56, 0x42, 0x54, 0x52];

// ---------------------------------------------------------------------------
// PageType
// ---------------------------------------------------------------------------

/// Discriminant for page payload kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PageType {
    /// Unallocated / free page (body is zeroed).
    Free = 0x00,
    /// Leaf page holding key-value pairs.
    Leaf = 0x01,
    /// Internal page holding separator keys and child page pointers.
    Internal = 0x02,
}

impl PageType {
    /// Decode from a `u8` byte.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Free),
            0x01 => Some(Self::Leaf),
            0x02 => Some(Self::Internal),
            _ => None,
        }
    }

    /// Domain-separation label for BLAKE3 key derivation.
    #[must_use]
    pub fn domain_label(self) -> &'static str {
        match self {
            Self::Free => "tidefs-btree-page-free-v1",
            Self::Leaf => "tidefs-btree-page-leaf-v1",
            Self::Internal => "tidefs-btree-page-internal-v1",
        }
    }
}

// ---------------------------------------------------------------------------
// PageHeader
// ---------------------------------------------------------------------------

/// Persistent header prefixed to every 4 KB B+tree page.
///
/// The `checksum` covers the page body (bytes `[16..4096)`).
/// Compute with [`compute_page_checksum`] and verify with
/// [`verify_page_checksum`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageHeader {
    /// Always [`PAGE_MAGIC`].
    pub magic: [u8; 4],
    /// Page type discriminant.
    pub page_type: u8,
    /// WAL generation number (u24 little-endian).
    pub generation: [u8; 3],
    /// First 8 bytes of the BLAKE3 keyed hash of the page body.
    pub checksum: [u8; 8],
}

impl PageHeader {
    /// Create a new header for an empty page of the given type.
    #[must_use]
    pub fn new(page_type: PageType, generation: u32) -> Self {
        let gen = generation & 0x00FF_FFFF; // clamp to 24 bits
        Self {
            magic: PAGE_MAGIC,
            page_type: page_type as u8,
            generation: [gen as u8, (gen >> 8) as u8, (gen >> 16) as u8],
            checksum: [0u8; 8],
        }
    }

    /// Decode the 24-bit generation number as u32.
    #[must_use]
    pub fn generation_u32(&self) -> u32 {
        u32::from_le_bytes([
            self.generation[0],
            self.generation[1],
            self.generation[2],
            0,
        ])
    }

    /// Return the page type if valid.
    #[must_use]
    pub fn page_type(&self) -> Option<PageType> {
        PageType::from_u8(self.page_type)
    }

    /// Returns `true` if the magic bytes match [`PAGE_MAGIC`].
    #[must_use]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == PAGE_MAGIC
    }

    /// Encode this header into `buf` (must be ≥ 16 bytes).
    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.page_type;
        buf[5..8].copy_from_slice(&self.generation);
        buf[8..16].copy_from_slice(&self.checksum);
    }

    /// Decode a header from `buf` (must be ≥ 16 bytes).
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        let page_type = buf[4];
        let mut generation = [0u8; 3];
        generation.copy_from_slice(&buf[5..8]);
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&buf[8..16]);
        Self {
            magic,
            page_type,
            generation,
            checksum,
        }
    }
}

impl fmt::Display for PageHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PageHeader(type={:?}, gen={}, checksum={:02x?})",
            self.page_type(),
            self.generation_u32(),
            &self.checksum[..4]
        )
    }
}

// ---------------------------------------------------------------------------
// Page type alias
// ---------------------------------------------------------------------------

/// A full 4096-byte B+tree page.
pub type BtreePage = [u8; PAGE_SIZE];

/// Decoded leaf entries: a vector of (key, value) byte-pair copies.
pub type LeafEntries = Vec<(Vec<u8>, Vec<u8>)>;

/// Create a zero-filled page.
#[must_use]
pub fn blank_page() -> BtreePage {
    [0u8; PAGE_SIZE]
}

/// Write the header into the first 16 bytes of `page`.
pub fn write_header(page: &mut BtreePage, header: &PageHeader) {
    header.encode(&mut page[..PAGE_HEADER_SIZE]);
}

/// Read the header from the first 16 bytes of `page`.
#[must_use]
pub fn read_header(page: &BtreePage) -> PageHeader {
    PageHeader::decode(&page[..PAGE_HEADER_SIZE])
}

/// Return a reference to the page body (bytes 16..4096).
#[must_use]
pub fn page_body(page: &BtreePage) -> &[u8] {
    &page[PAGE_HEADER_SIZE..]
}

/// Return a mutable reference to the page body.
pub fn page_body_mut(page: &mut BtreePage) -> &mut [u8] {
    &mut page[PAGE_HEADER_SIZE..]
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte domain-separation key for `page_type` via BLAKE3 KDF.
#[must_use]
pub fn derive_domain_key(page_type: PageType) -> [u8; 32] {
    blake3::derive_key(page_type.domain_label(), b"")
}

/// Compute the BLAKE3 keyed checksum over the page body.
///
/// Returns the first 8 bytes of the keyed hash.
#[must_use]
pub fn compute_page_checksum(page_type: PageType, body: &[u8]) -> [u8; 8] {
    let key = derive_domain_key(page_type);
    let hash = blake3::keyed_hash(&key, body);
    let full = hash.as_bytes();
    let mut truncated = [0u8; 8];
    truncated.copy_from_slice(&full[..8]);
    truncated
}

/// Verify that the page header checksum matches the body.
pub fn verify_page_checksum(header: &PageHeader, body: &[u8]) -> Result<(), PageChecksumError> {
    let pt = header
        .page_type()
        .ok_or(PageChecksumError::UnknownPageType(header.page_type))?;
    let expected = compute_page_checksum(pt, body);
    if header.checksum == expected {
        Ok(())
    } else {
        Err(PageChecksumError::Mismatch {
            page_type: pt,
            expected,
            got: header.checksum,
        })
    }
}

/// Set the checksum field on `header` to match `body`, then write both
/// header and body into `page`.
pub fn seal_page(page: &mut BtreePage, header: &mut PageHeader, body: &[u8]) {
    assert!(body.len() <= PAGE_BODY_SIZE, "body exceeds page capacity");
    let pt = header.page_type().unwrap_or(PageType::Free);
    // Copy body into page first, then checksum the full page body.
    page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + body.len()].copy_from_slice(body);
    header.checksum = compute_page_checksum(pt, page_body(page));
    write_header(page, header);
}

/// Validate a full page in-place: check magic, then verify checksum over body.
pub fn validate_page(page: &BtreePage) -> Result<PageHeader, PageChecksumError> {
    let header = read_header(page);
    if !header.is_valid_magic() {
        return Err(PageChecksumError::BadMagic { got: header.magic });
    }
    let body = page_body(page);
    verify_page_checksum(&header, body)?;
    Ok(header)
}

// ---------------------------------------------------------------------------
// PageChecksumError
// ---------------------------------------------------------------------------

/// Error returned when page-level checksum verification fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageChecksumError {
    /// The page type byte is not a recognized [`PageType`].
    UnknownPageType(u8),
    /// The magic bytes do not match [`PAGE_MAGIC`].
    BadMagic { got: [u8; 4] },
    /// The stored checksum does not match the computed checksum.
    Mismatch {
        page_type: PageType,
        expected: [u8; 8],
        got: [u8; 8],
    },
}

impl fmt::Display for PageChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPageType(b) => write!(f, "unknown page type: 0x{b:02x}"),
            Self::BadMagic { got } => write!(f, "bad page magic: {got:02x?}, expected VBTR"),
            Self::Mismatch {
                page_type,
                expected,
                got,
            } => write!(
                f,
                "page checksum mismatch ({page_type:?}): expected {expected:02x?}, got {got:02x?}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Page serialization traits
// ---------------------------------------------------------------------------

/// Trait for keys that can be serialized into a page body.
pub trait PageSerdeKey {
    /// Serialize this key into a byte vector.
    fn serialize_to_vec(key: &Self) -> alloc::vec::Vec<u8>;

    /// Deserialize a key from a byte slice.
    /// Returns `None` if the slice does not represent a valid key.
    fn deserialize_from_slice(data: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

/// Trait for values that can be serialized into a page body.
pub trait PageSerdeValue {
    /// Serialize this value into a byte vector.
    fn serialize_to_vec(value: &Self) -> alloc::vec::Vec<u8>;

    /// Deserialize a value from a byte slice.
    /// Returns `None` if the slice does not represent a valid value.
    fn deserialize_from_slice(data: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

/// Serde impl for u64 keys.
impl PageSerdeKey for u64 {
    fn serialize_to_vec(key: &Self) -> alloc::vec::Vec<u8> {
        key.to_le_bytes().to_vec()
    }

    fn deserialize_from_slice(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        Some(u64::from_le_bytes(bytes))
    }
}

/// Serde impl for u64 values.
impl PageSerdeValue for u64 {
    fn serialize_to_vec(value: &Self) -> alloc::vec::Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn deserialize_from_slice(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[..8]);
        Some(u64::from_le_bytes(bytes))
    }
}

// ---------------------------------------------------------------------------
// Page body serialization helpers
// ---------------------------------------------------------------------------

/// Serialize leaf entries into a page body buffer.
///
/// Format: `entry_count: u32 LE`, then per entry
/// `key_len: u16 LE, key, val_len: u16 LE, val`.
///
/// Returns the number of bytes written to `body`.
pub fn encode_leaf_body(entries: &[(&[u8], &[u8])], body: &mut [u8]) -> usize {
    let mut pos = 4; // reserve space for count
    body[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (key, val) in entries {
        let kl = key.len().min(u16::MAX as usize);
        let vl = val.len().min(u16::MAX as usize);
        body[pos..pos + 2].copy_from_slice(&(kl as u16).to_le_bytes());
        pos += 2;
        body[pos..pos + kl].copy_from_slice(&key[..kl]);
        pos += kl;
        body[pos..pos + 2].copy_from_slice(&(vl as u16).to_le_bytes());
        pos += 2;
        body[pos..pos + vl].copy_from_slice(&val[..vl]);
        pos += vl;
    }
    pos
}

/// Decode leaf entries from a page body buffer.
///
/// Returns a vector of `(key, value)` byte slices copied out.
pub fn decode_leaf_body(body: &[u8]) -> Result<LeafEntries, PageFormatError> {
    if body.len() < 4 {
        return Err(PageFormatError::Truncated);
    }
    let count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let mut entries = Vec::with_capacity(count);
    let mut pos: usize = 4;
    for _ in 0..count {
        if pos + 2 > body.len() {
            return Err(PageFormatError::Truncated);
        }
        let kl = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + kl > body.len() {
            return Err(PageFormatError::Truncated);
        }
        let key = body[pos..pos + kl].to_vec();
        pos += kl;
        if pos + 2 > body.len() {
            return Err(PageFormatError::Truncated);
        }
        let vl = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + vl > body.len() {
            return Err(PageFormatError::Truncated);
        }
        let val = body[pos..pos + vl].to_vec();
        pos += vl;
        entries.push((key, val));
    }
    Ok(entries)
}

/// Serialize internal-node entries into a page body buffer.
///
/// Format: `child_count: u32 LE`, then
/// `[child_count+1] × child_page_id: u64 LE`,
/// then `[child_count] × (key_len: u16 LE, key)`.
///
/// Returns the number of bytes written to `body`.
pub fn encode_internal_body(child_ids: &[u64], keys: &[&[u8]], body: &mut [u8]) -> usize {
    assert_eq!(child_ids.len(), keys.len() + 1, "child_ids must be keys+1");
    let child_count = keys.len() as u32;
    let mut pos = 4;
    body[0..4].copy_from_slice(&child_count.to_le_bytes());
    for &cid in child_ids {
        body[pos..pos + 8].copy_from_slice(&cid.to_le_bytes());
        pos += 8;
    }
    for key in keys {
        let kl = key.len().min(u16::MAX as usize);
        body[pos..pos + 2].copy_from_slice(&(kl as u16).to_le_bytes());
        pos += 2;
        body[pos..pos + kl].copy_from_slice(&key[..kl]);
        pos += kl;
    }
    pos
}

/// Decode internal-node entries from a page body buffer.
pub fn decode_internal_body(body: &[u8]) -> Result<(Vec<u64>, Vec<Vec<u8>>), PageFormatError> {
    if body.len() < 4 {
        return Err(PageFormatError::Truncated);
    }
    let child_count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let id_bytes = 8 * (child_count + 1);
    if body.len() < 4 + id_bytes {
        return Err(PageFormatError::Truncated);
    }
    let mut child_ids = Vec::with_capacity(child_count + 1);
    let mut pos: usize = 4;
    for _ in 0..=child_count {
        let cid = u64::from_le_bytes([
            body[pos],
            body[pos + 1],
            body[pos + 2],
            body[pos + 3],
            body[pos + 4],
            body[pos + 5],
            body[pos + 6],
            body[pos + 7],
        ]);
        child_ids.push(cid);
        pos += 8;
    }
    let mut keys = Vec::with_capacity(child_count);
    for _ in 0..child_count {
        if pos + 2 > body.len() {
            return Err(PageFormatError::Truncated);
        }
        let kl = u16::from_le_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + kl > body.len() {
            return Err(PageFormatError::Truncated);
        }
        keys.push(body[pos..pos + kl].to_vec());
        pos += kl;
    }
    Ok((child_ids, keys))
}

// ---------------------------------------------------------------------------
// PageFormatError
// ---------------------------------------------------------------------------

/// Error returned when page body decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageFormatError {
    /// The body buffer ended prematurely.
    Truncated,
}

impl fmt::Display for PageFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated page body"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    // ── PageType discriminants ──────────────────────────────────────

    #[test]
    fn page_type_round_trip() {
        for pt in [PageType::Free, PageType::Leaf, PageType::Internal] {
            let b = pt as u8;
            assert_eq!(PageType::from_u8(b), Some(pt));
        }
    }

    #[test]
    fn page_type_unknown_rejected() {
        assert_eq!(PageType::from_u8(0xFF), None);
    }

    #[test]
    fn page_type_domain_labels_are_distinct() {
        assert_ne!(
            PageType::Leaf.domain_label(),
            PageType::Internal.domain_label()
        );
        assert_ne!(PageType::Free.domain_label(), PageType::Leaf.domain_label());
    }

    // ── PageHeader encode/decode round-trip ─────────────────────────

    #[test]
    fn header_encode_decode_round_trip() {
        let original = PageHeader {
            magic: PAGE_MAGIC,
            page_type: PageType::Leaf as u8,
            generation: [0x78, 0x56, 0x34],
            checksum: [0xAA; 8],
        };
        let mut buf = [0u8; 16];
        original.encode(&mut buf);
        let decoded = PageHeader::decode(&buf);
        assert_eq!(original, decoded);
    }

    #[test]
    fn header_generation_u32() {
        let h = PageHeader::new(PageType::Leaf, 0xAB_CDEF);
        assert_eq!(h.generation_u32(), 0xAB_CDEF & 0x00FF_FFFF);
    }

    #[test]
    fn header_generation_clamped() {
        let h = PageHeader::new(PageType::Leaf, 0x1FF_FFFF);
        assert_eq!(h.generation_u32(), 0x00FF_FFFF);
    }

    #[test]
    fn header_is_valid_magic() {
        let h = PageHeader::new(PageType::Free, 0);
        assert!(h.is_valid_magic());
    }

    #[test]
    fn header_bad_magic_detected() {
        let h = PageHeader {
            magic: *b"BADC",
            page_type: 0,
            generation: [0; 3],
            checksum: [0; 8],
        };
        assert!(!h.is_valid_magic());
    }

    // ── Page read/write header ──────────────────────────────────────

    #[test]
    fn write_and_read_header() {
        let header = PageHeader::new(PageType::Internal, 42);
        let mut page = blank_page();
        write_header(&mut page, &header);
        let read = read_header(&page);
        assert_eq!(header, read);
    }

    // ── Checksum compute and verify ─────────────────────────────────

    #[test]
    fn checksum_compute_and_verify_ok() {
        let body = b"hello page body";
        let cs = compute_page_checksum(PageType::Leaf, body);
        let header = PageHeader {
            magic: PAGE_MAGIC,
            page_type: PageType::Leaf as u8,
            generation: [0; 3],
            checksum: cs,
        };
        assert!(verify_page_checksum(&header, body).is_ok());
    }

    #[test]
    fn checksum_mismatch_detected() {
        let body = b"hello page body";
        let cs = compute_page_checksum(PageType::Leaf, body);
        let mut bad_cs = cs;
        bad_cs[0] ^= 1;
        let header = PageHeader {
            magic: PAGE_MAGIC,
            page_type: PageType::Leaf as u8,
            generation: [0; 3],
            checksum: bad_cs,
        };
        assert!(verify_page_checksum(&header, body).is_err());
    }

    #[test]
    fn checksum_tampered_body_detected() {
        let body = b"hello page body";
        let cs = compute_page_checksum(PageType::Leaf, body);
        let header = PageHeader {
            magic: PAGE_MAGIC,
            page_type: PageType::Leaf as u8,
            generation: [0; 3],
            checksum: cs,
        };
        let tampered = b"HELLO page body";
        assert!(verify_page_checksum(&header, tampered).is_err());
    }

    #[test]
    fn domain_separation_produces_different_checksums() {
        let body = b"same body";
        let cs_leaf = compute_page_checksum(PageType::Leaf, body);
        let cs_int = compute_page_checksum(PageType::Internal, body);
        assert_ne!(cs_leaf, cs_int);
    }

    #[test]
    fn unknown_page_type_fails_checksum_verify() {
        let header = PageHeader {
            magic: PAGE_MAGIC,
            page_type: 0xFF,
            generation: [0; 3],
            checksum: [0; 8],
        };
        assert!(matches!(
            verify_page_checksum(&header, b""),
            Err(PageChecksumError::UnknownPageType(0xFF))
        ));
    }

    // ── Seal and validate page ──────────────────────────────────────

    #[test]
    fn seal_and_validate_round_trip() {
        let mut page = blank_page();
        let mut header = PageHeader::new(PageType::Leaf, 1);
        let body_data = b"some key-value data for the page body";
        seal_page(&mut page, &mut header, body_data);

        let validated = validate_page(&page).unwrap();
        assert_eq!(validated.page_type(), Some(PageType::Leaf));
        assert_eq!(validated.generation_u32(), 1);
        assert_eq!(&page_body(&page)[..body_data.len()], body_data);
    }

    #[test]
    fn validate_detects_bad_magic() {
        let mut page = blank_page();
        let mut header = PageHeader::new(PageType::Leaf, 0);
        header.magic = *b"BADC";
        write_header(&mut page, &header);
        assert!(matches!(
            validate_page(&page),
            Err(PageChecksumError::BadMagic { .. })
        ));
    }

    #[test]
    fn validate_detects_checksum_mismatch() {
        let mut page = blank_page();
        let mut header = PageHeader::new(PageType::Leaf, 0);
        seal_page(&mut page, &mut header, b"original");
        // Tamper with body
        page[PAGE_HEADER_SIZE] ^= 0xFF;
        assert!(matches!(
            validate_page(&page),
            Err(PageChecksumError::Mismatch { .. })
        ));
    }

    // ── Leaf body encode/decode round-trip ──────────────────────────

    #[test]
    fn leaf_body_round_trip() {
        let entries: Vec<(&[u8], &[u8])> = vec![
            (b"key1", b"value1"),
            (b"key-two", b""),
            (b"k3", b"longer-value-data"),
        ];
        let mut body = [0u8; PAGE_BODY_SIZE];
        let written = encode_leaf_body(&entries, &mut body);
        assert!(written > 0 && written <= PAGE_BODY_SIZE);

        let decoded = decode_leaf_body(&body[..written]).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], (b"key1".to_vec(), b"value1".to_vec()));
        assert_eq!(decoded[1], (b"key-two".to_vec(), b"".to_vec()));
        assert_eq!(decoded[2], (b"k3".to_vec(), b"longer-value-data".to_vec()));
    }

    #[test]
    fn leaf_body_empty() {
        let mut body = [0u8; PAGE_BODY_SIZE];
        let written = encode_leaf_body(&[], &mut body);
        assert_eq!(written, 4);
        let decoded = decode_leaf_body(&body[..written]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn leaf_body_truncated() {
        let body = [0u8; 3];
        assert!(matches!(
            decode_leaf_body(&body),
            Err(PageFormatError::Truncated)
        ));
    }

    // ── Internal body encode/decode round-trip ──────────────────────

    #[test]
    fn internal_body_round_trip() {
        let child_ids = vec![100u64, 200, 300];
        let keys: Vec<&[u8]> = vec![b"mid1", b"mid2"];
        let mut body = [0u8; PAGE_BODY_SIZE];
        let written = encode_internal_body(&child_ids, &keys, &mut body);
        assert!(written > 0);

        let (decoded_ids, decoded_keys) = decode_internal_body(&body[..written]).unwrap();
        assert_eq!(decoded_ids, child_ids);
        assert_eq!(decoded_keys, vec![b"mid1".to_vec(), b"mid2".to_vec()]);
    }

    #[test]
    fn internal_body_single_child() {
        let child_ids = vec![42u64];
        let keys: Vec<&[u8]> = vec![];
        let mut body = [0u8; PAGE_BODY_SIZE];
        let written = encode_internal_body(&child_ids, &keys, &mut body);
        let (decoded_ids, decoded_keys) = decode_internal_body(&body[..written]).unwrap();
        assert_eq!(decoded_ids, child_ids);
        assert!(decoded_keys.is_empty());
    }

    #[test]
    fn internal_body_truncated() {
        let body = [0u8; 2];
        assert!(matches!(
            decode_internal_body(&body),
            Err(PageFormatError::Truncated)
        ));
    }

    // ── Page body accessors ─────────────────────────────────────────

    #[test]
    fn page_body_reflects_written_data() {
        let mut page = blank_page();
        page[PAGE_HEADER_SIZE] = 0xAB;
        page[PAGE_HEADER_SIZE + 1] = 0xCD;
        assert_eq!(page_body(&page)[0], 0xAB);
        page_body_mut(&mut page)[2] = 0xEF;
        assert_eq!(page[PAGE_HEADER_SIZE + 2], 0xEF);
    }

    // ── Display impls ───────────────────────────────────────────────

    #[test]
    fn page_checksum_error_display() {
        let e = PageChecksumError::UnknownPageType(0xFE);
        assert!(!format!("{e}").is_empty());

        let e = PageChecksumError::BadMagic { got: *b"DEAD" };
        assert!(!format!("{e}").is_empty());

        let e = PageChecksumError::Mismatch {
            page_type: PageType::Leaf,
            expected: [0xAA; 8],
            got: [0xBB; 8],
        };
        assert!(!format!("{e}").is_empty());
    }

    #[test]
    fn page_format_error_display() {
        let e = PageFormatError::Truncated;
        assert!(!format!("{e}").is_empty());
    }

    #[test]
    fn page_header_display() {
        let h = PageHeader::new(PageType::Leaf, 7);
        let s = format!("{h}");
        assert!(s.contains("Leaf"));
    }
}
