//! Persistent on-disk B+tree node format with BLAKE3-verified integrity.
//!
//! Each node (leaf or internal) is prefixed with a [`NodeHeader`] that
//! carries a BLAKE3 keyed checksum over the node body. The checksum uses
//! domain-separation via [`DomainTag`] so a leaf node checksum can never
//! collide with an internal node checksum even when the body bytes match.
//!
//! ## On-disk layout
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │ NodeHeader (32 bytes)                        │
//! │  magic:      [u8; 4]   "VBTN"               │
//! │  checksum:   [u8; 16]  BLAKE3 truncated      │
//! │  domain_tag: u8         leaf or internal      │
//! │  reserved:   [u8; 3]   padding to 8-byte     │
//! │  count:      u32        entries or children   │
//! │  body_len:   u32        variable body bytes   │
//! ├──────────────────────────────────────────────┤
//! │ Variable-length body (body_len bytes)         │
//! │  Leaf:   [count] × (key_len:u16, key,        │
//! │                      val_len:u16, val)        │
//! │  Internal: [count] × (key_len:u16, key) +     │
//! │            [count+1] × child_node_id:u64      │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! The header is always the same size regardless of node type, making
//! it cheap to read and validate before parsing the body.

use core::fmt;

// ---------------------------------------------------------------------------
// DomainTag
// ---------------------------------------------------------------------------

/// Domain-separation tag for BLAKE3 keyed hashing of B+tree nodes.
///
/// Each variant derives a distinct 32-byte key via BLAKE3 key-derivation
/// so that checksums for different node types are cryptographically
/// independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DomainTag {
    /// Leaf node payload (key-value pairs).
    LeafNode = 0x10,
    /// Internal node payload (separator keys + child pointers).
    InternalNode = 0x11,
}

impl DomainTag {
    /// Return the `u8` discriminant.
    #[must_use]
    pub fn discriminant(self) -> u8 {
        self as u8
    }

    /// Human-readable label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::LeafNode => "btree-leaf-node",
            Self::InternalNode => "btree-internal-node",
        }
    }
}

// ---------------------------------------------------------------------------
// NodeHeader
// ---------------------------------------------------------------------------

/// Magic bytes that identify a valid B+tree node on disk.
pub const NODE_MAGIC: [u8; 4] = *b"VBTN";

/// Size of the fixed [`NodeHeader`] in bytes.
pub const NODE_HEADER_SIZE: usize = 32;

/// Persistent header prefixed to every serialized B+tree node.
///
/// The `checksum` covers `body_len` bytes starting immediately after
/// the header. Compute with [`compute_checksum`] and verify with
/// [`verify_checksum`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeHeader {
    /// Always [`NODE_MAGIC`].
    pub magic: [u8; 4],
    /// First 16 bytes of the BLAKE3 keyed hash of the body.
    pub checksum: [u8; 16],
    /// Domain-separation tag (leaf or internal).
    pub domain_tag: u8,
    /// Reserved padding; must be zero on write.
    pub reserved: [u8; 3],
    /// Number of entries (leaf) or children (internal).
    pub count: u32,
    /// Length of the variable body that follows, in bytes.
    pub body_len: u32,
}

impl NodeHeader {
    /// Create a new header for a node of the given type and count.
    ///
    /// `body_len` is the exact serialized length of the body. The
    /// checksum is zeroed; call [`compute_checksum`] to fill it in.
    #[must_use]
    pub fn new(tag: DomainTag, count: u32, body_len: u32) -> Self {
        Self {
            magic: NODE_MAGIC,
            checksum: [0u8; 16],
            domain_tag: tag.discriminant(),
            reserved: [0u8; 3],
            count,
            body_len,
        }
    }

    /// Return the domain tag for this header.
    #[must_use]
    pub fn domain_tag(&self) -> Option<DomainTag> {
        match self.domain_tag {
            0x10 => Some(DomainTag::LeafNode),
            0x11 => Some(DomainTag::InternalNode),
            _ => None,
        }
    }

    /// Encode the header into `buf`, which must have at least
    /// [`NODE_HEADER_SIZE`] bytes.
    pub fn encode(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..20].copy_from_slice(&self.checksum);
        buf[20] = self.domain_tag;
        buf[21..24].copy_from_slice(&self.reserved);
        buf[24..28].copy_from_slice(&self.count.to_le_bytes());
        buf[28..32].copy_from_slice(&self.body_len.to_le_bytes());
    }

    /// Decode a header from `buf`, which must have at least
    /// [`NODE_HEADER_SIZE`] bytes.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Self {
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        let mut checksum = [0u8; 16];
        checksum.copy_from_slice(&buf[4..20]);
        let domain_tag = buf[20];
        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&buf[21..24]);
        let count = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let body_len = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        Self {
            magic,
            checksum,
            domain_tag,
            reserved,
            count,
            body_len,
        }
    }

    /// Returns `true` if the magic bytes match [`NODE_MAGIC`].
    #[must_use]
    pub fn is_valid_magic(&self) -> bool {
        self.magic == NODE_MAGIC
    }
}

impl fmt::Display for NodeHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeHeader(magic={:?}, tag={:?}, count={}, body_len={})",
            core::str::from_utf8(&self.magic).unwrap_or("???"),
            self.domain_tag(),
            self.count,
            self.body_len
        )
    }
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

/// Derive a 32-byte domain-separation key for `tag` via BLAKE3 KDF.
#[must_use]
pub fn derive_domain_key(tag: DomainTag) -> [u8; 32] {
    let tag_bytes = [tag.discriminant()];
    blake3::derive_key("tidefs-btree-node-v1", &tag_bytes)
}

/// Compute the BLAKE3 keyed checksum over `body`.
///
/// Returns the first 16 bytes of the keyed hash.
#[must_use]
pub fn compute_checksum(tag: DomainTag, body: &[u8]) -> [u8; 16] {
    let key = derive_domain_key(tag);
    let hash = blake3::keyed_hash(&key, body);
    let full = hash.as_bytes();
    let mut truncated = [0u8; 16];
    truncated.copy_from_slice(&full[..16]);
    truncated
}

/// Verify that `header.checksum` matches `compute_checksum(domain, body)`.
///
/// Returns `Ok(())` on match, `Err(ChecksumError)` on mismatch.
pub fn verify_checksum(header: &NodeHeader, body: &[u8]) -> Result<(), ChecksumError> {
    let tag = header
        .domain_tag()
        .ok_or(ChecksumError::UnknownDomainTag(header.domain_tag))?;
    let expected = compute_checksum(tag, body);
    if header.checksum == expected {
        Ok(())
    } else {
        Err(ChecksumError::Mismatch {
            tag,
            expected,
            got: header.checksum,
        })
    }
}

// ---------------------------------------------------------------------------
// ChecksumError
// ---------------------------------------------------------------------------

/// Error returned when BLAKE3 checksum verification fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumError {
    /// The domain tag byte is not a recognized [`DomainTag`].
    UnknownDomainTag(u8),
    /// The stored checksum does not match the computed checksum.
    Mismatch {
        tag: DomainTag,
        expected: [u8; 16],
        got: [u8; 16],
    },
}

impl fmt::Display for ChecksumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDomainTag(b) => write!(f, "unknown domain tag: 0x{b:02x}"),
            Self::Mismatch { tag, expected, got } => write!(
                f,
                "checksum mismatch for {tag:?}: expected {expected:02x?}, got {got:02x?}"
            ),
        }
    }
}

impl DomainTag {
    /// Derive the 32-byte domain key via BLAKE3 KDF.
    #[must_use]
    pub fn derive_key(self) -> [u8; 32] {
        derive_domain_key(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    // ── DomainTag discriminants ──────────────────────────────────────

    #[test]
    fn domain_tag_discriminants_are_distinct() {
        assert_ne!(
            DomainTag::LeafNode.discriminant(),
            DomainTag::InternalNode.discriminant()
        );
    }

    #[test]
    fn domain_tag_round_trip() {
        for tag in [DomainTag::LeafNode, DomainTag::InternalNode] {
            let disc = tag.discriminant();
            match disc {
                0x10 => assert_eq!(DomainTag::LeafNode, DomainTag::LeafNode),
                0x11 => assert_eq!(DomainTag::InternalNode, DomainTag::InternalNode),
                _ => panic!("unexpected discriminant"),
            }
        }
    }

    // ── NodeHeader encode/decode round-trip ──────────────────────────

    #[test]
    fn header_encode_decode_round_trip() {
        let original = NodeHeader {
            magic: NODE_MAGIC,
            checksum: [0xAA; 16],
            domain_tag: DomainTag::LeafNode.discriminant(),
            reserved: [0; 3],
            count: 42,
            body_len: 128,
        };
        let mut buf = [0u8; NODE_HEADER_SIZE];
        original.encode(&mut buf);
        let decoded = NodeHeader::decode(&buf);
        assert_eq!(original, decoded);
    }

    #[test]
    fn header_is_valid_magic() {
        let h = NodeHeader::new(DomainTag::LeafNode, 0, 0);
        assert!(h.is_valid_magic());
    }

    #[test]
    fn header_bad_magic_detected() {
        let h = NodeHeader {
            magic: *b"XXXX",
            checksum: [0; 16],
            domain_tag: 0x10,
            reserved: [0; 3],
            count: 0,
            body_len: 0,
        };
        assert!(!h.is_valid_magic());
    }

    // ── Checksum compute and verify ──────────────────────────────────

    #[test]
    fn checksum_compute_and_verify_ok() {
        let body = b"hello world";
        let cs = compute_checksum(DomainTag::LeafNode, body);
        let header = NodeHeader {
            magic: NODE_MAGIC,
            checksum: cs,
            domain_tag: DomainTag::LeafNode.discriminant(),
            reserved: [0; 3],
            count: 1,
            body_len: body.len() as u32,
        };
        assert!(verify_checksum(&header, body).is_ok());
    }

    #[test]
    fn checksum_mismatch_detected() {
        let body = b"hello world";
        let cs = compute_checksum(DomainTag::LeafNode, body);
        // Tamper with checksum
        let mut bad_cs = cs;
        bad_cs[0] ^= 1;
        let header = NodeHeader {
            magic: NODE_MAGIC,
            checksum: bad_cs,
            domain_tag: DomainTag::LeafNode.discriminant(),
            reserved: [0; 3],
            count: 1,
            body_len: body.len() as u32,
        };
        assert!(verify_checksum(&header, body).is_err());
    }

    #[test]
    fn checksum_tampered_body_detected() {
        let body = b"hello world";
        let cs = compute_checksum(DomainTag::LeafNode, body);
        let header = NodeHeader {
            magic: NODE_MAGIC,
            checksum: cs,
            domain_tag: DomainTag::LeafNode.discriminant(),
            reserved: [0; 3],
            count: 1,
            body_len: body.len() as u32,
        };
        // Tampered body
        let tampered = b"hello WORLD";
        assert!(verify_checksum(&header, tampered).is_err());
    }

    #[test]
    fn domain_separation_produces_different_checksums() {
        let body = b"same body";
        let cs_leaf = compute_checksum(DomainTag::LeafNode, body);
        let cs_int = compute_checksum(DomainTag::InternalNode, body);
        assert_ne!(cs_leaf, cs_int);
    }

    #[test]
    fn domain_key_different_for_different_tags() {
        let k1 = DomainTag::LeafNode.derive_key();
        let k2 = DomainTag::InternalNode.derive_key();
        assert_ne!(k1, k2);
    }

    #[test]
    fn domain_key_same_for_same_tag() {
        let k1 = DomainTag::LeafNode.derive_key();
        let k2 = DomainTag::LeafNode.derive_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn unknown_domain_tag_causes_checksum_error() {
        let header = NodeHeader {
            magic: NODE_MAGIC,
            checksum: [0; 16],
            domain_tag: 0xFF,
            reserved: [0; 3],
            count: 0,
            body_len: 0,
        };
        let result = verify_checksum(&header, b"");
        assert!(matches!(result, Err(ChecksumError::UnknownDomainTag(0xFF))));
    }

    // ── Display / Debug ─────────────────────────────────────────────

    #[test]
    fn checksum_error_display_unknown_tag() {
        let err = ChecksumError::UnknownDomainTag(0xFE);
        let s = format!("{err}");
        assert!(s.contains("0xfe") || s.contains("0xFE"));
    }

    #[test]
    fn checksum_error_display_mismatch() {
        let err = ChecksumError::Mismatch {
            tag: DomainTag::LeafNode,
            expected: [0xAA; 16],
            got: [0xBB; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("mismatch"));
    }
}
