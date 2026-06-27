// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Binary serialization format for [`ChecksumTree`] and [`ChecksumTreeNode`].
//!
//! The on-disk/wire format is self-describing with a magic number and version
//! byte, enabling forward-compatible readers to reject unknown formats before
//! attempting deserialization.
//!
//! ## Wire Format (v1)
//!
//! ```text
//! Header:
//!   magic:       [u8; 4]    = b"VBFS"  (0x56, 0x42, 0x46, 0x53)
//!   version:     u8         = 0x01
//!   block_size:  u32 (LE)
//!   block_count: u64 (LE)
//!   root_hash:   [u8; 32]
//!   node_count:  u32 (LE)
//!   dk_present:  u8         (0 or 1)
//!   domain_key:  [u8; 32]   (only if dk_present == 1)
//!   lt_present:  u8         (0 or 1)
//!   locator_token: [u8; 32] (only if lt_present == 1)
//!
//! Per-node record (repeated node_count times):
//!   child_count: u16 (LE)
//!   children:    child_count * [u8; 32]
//!   self_csum:   [u8; 32]
//! ```
//!
//! All multi-byte integers use the [`tidefs_binary_schema_core`] LE wrappers
//! ([`U16Le`], [`U32Le`], [`U64Le`]) for deterministic platform-independent
//! encoding.

use alloc::vec::Vec;

use crate::{ChecksumTree, ChecksumTreeNode, Digest, DomainKey, LocatorToken, DIGEST_SIZE};
use tidefs_binary_schema_core::{U16Le, U32Le, U64Le};

/// Magic bytes identifying this as a TideFS checksum tree blob.
pub const TREE_MAGIC: [u8; 4] = [0x56, 0x42, 0x46, 0x53]; // "VBFS"

/// Current binary format version.
pub const TREE_VERSION: u8 = 0x02;

/// Minimum valid header size: magic (4) + version (1) + block_size (4) +
/// block_count (8) + root_hash (32) + node_count (4) + dk_present (1).
/// Minimum valid header size: magic (4) + version (1) + block_size (4) +
/// block_count (8) + root_hash (32) + node_count (4) + dk_present (1) +
/// lt_present (1).
const MIN_HEADER_SIZE: usize = 4 + 1 + 4 + 8 + 32 + 4 + 1 + 1;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode a [`ChecksumTree`] into its binary representation.
///
/// Returns a `Vec<u8>` suitable for writing to disk or sending over the wire.
/// The encoding is deterministic: encoding the same tree twice produces
/// identical bytes. All multi-byte integers are written in little-endian
/// using [`tidefs_binary_schema_core`] wrappers.
pub fn encode_tree(tree: &ChecksumTree) -> Vec<u8> {
    // Estimate capacity: header + nodes
    let node_bytes: usize = tree
        .nodes
        .iter()
        .map(|n| 2 + n.children.len() * DIGEST_SIZE + DIGEST_SIZE)
        .sum();
    let dk_bytes = if tree.domain_key.is_some() {
        DIGEST_SIZE
    } else {
        0
    };
    let lt_bytes = if tree.locator_token.is_some() {
        DIGEST_SIZE
    } else {
        0
    };
    let mut buf = Vec::with_capacity(MIN_HEADER_SIZE + dk_bytes + lt_bytes + node_bytes);

    // Magic
    buf.extend_from_slice(&TREE_MAGIC);

    // Version
    buf.push(TREE_VERSION);

    // block_size (u32 LE)
    buf.extend_from_slice(&U32Le::from(tree.block_size as u32).encode());

    // block_count (u64 LE)
    buf.extend_from_slice(&U64Le::from(tree.block_count).encode());

    // root_hash
    buf.extend_from_slice(&tree.root_hash);

    // node_count (u32 LE)
    buf.extend_from_slice(&U32Le::from(tree.nodes.len() as u32).encode());

    // domain_key (optional)
    if let Some(ref dk) = tree.domain_key {
        buf.push(1u8);
        buf.extend_from_slice(dk.as_bytes());
    } else {
        buf.push(0u8);
    }

    // locator_token (optional)
    if let Some(ref lt) = tree.locator_token {
        buf.push(1u8);
        buf.extend_from_slice(lt.as_bytes());
    } else {
        buf.push(0u8);
    }

    // Nodes
    for node in &tree.nodes {
        encode_node_into(node, &mut buf);
    }

    buf
}

/// Encode a single [`ChecksumTreeNode`] into `buf`.
fn encode_node_into(node: &ChecksumTreeNode, buf: &mut Vec<u8>) {
    // child_count (u16 LE)
    buf.extend_from_slice(&U16Le::from(node.children.len() as u16).encode());

    // children
    for child in &node.children {
        buf.extend_from_slice(child);
    }

    // self_checksum
    buf.extend_from_slice(&node.self_checksum);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Errors that can occur during binary deserialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input is too short to contain a valid header.
    TruncatedHeader,
    /// Magic bytes do not match [`TREE_MAGIC`].
    BadMagic { found: [u8; 4] },
    /// Version byte is not recognized by this reader.
    UnknownVersion { version: u8 },
    /// Input ended before all expected node data was read.
    TruncatedNodes,
    /// A node's child count exceeds [`crate::FANOUT`].
    FanoutExceeded { child_count: u16 },
    /// The locator-token present flag is neither 0 nor 1.
    BadLocatorTokenPresent { value: u8 },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "input too short for checksum tree header"),
            Self::BadMagic { found } => {
                write!(
                    f,
                    "bad magic bytes: expected {TREE_MAGIC:02x?}, got {found:02x?}",
                )
            }
            Self::UnknownVersion { version } => write!(
                f,
                "unknown tree format version {version} (reader supports v{TREE_VERSION})"
            ),
            Self::TruncatedNodes => write!(f, "truncated node data"),
            Self::FanoutExceeded { child_count } => write!(
                f,
                "node child_count {child_count} exceeds FANOUT ({})",
                crate::FANOUT
            ),
            Self::BadLocatorTokenPresent { value } => {
                write!(
                    f,
                    "bad locator-token-present flag: {value} (expected 0 or 1)"
                )
            }
        }
    }
}

/// Decode a [`ChecksumTree`] from its binary representation.
///
/// Returns the decoded tree on success, or a [`DecodeError`] describing the
/// problem. All multi-byte integers are decoded from little-endian using
/// [`tidefs_binary_schema_core`] wrappers.
pub fn decode_tree(mut data: &[u8]) -> Result<ChecksumTree, DecodeError> {
    if data.len() < MIN_HEADER_SIZE {
        return Err(DecodeError::TruncatedHeader);
    }

    // Magic
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&data[..4]);
    if magic != TREE_MAGIC {
        return Err(DecodeError::BadMagic { found: magic });
    }
    data = &data[4..];

    // Version
    let version = data[0];
    if version != TREE_VERSION {
        return Err(DecodeError::UnknownVersion { version });
    }
    data = &data[1..];

    // block_size (U32Le)
    let block_size = U32Le::from_le_bytes([data[0], data[1], data[2], data[3]]).as_raw() as usize;
    data = &data[4..];

    // block_count (U64Le)
    let block_count = U64Le::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
    .as_raw();
    data = &data[8..];

    // root_hash
    let mut root_hash = Digest::default();
    root_hash.copy_from_slice(&data[..DIGEST_SIZE]);
    data = &data[DIGEST_SIZE..];

    // node_count (U32Le)
    let node_count = U32Le::from_le_bytes([data[0], data[1], data[2], data[3]]).as_raw() as usize;
    data = &data[4..];

    // domain_key (optional)
    let dk_present = data[0];
    data = &data[1..];

    let domain_key = if dk_present == 1 {
        if data.len() < DIGEST_SIZE {
            return Err(DecodeError::TruncatedNodes);
        }
        let mut key_bytes = [0u8; DIGEST_SIZE];
        key_bytes.copy_from_slice(&data[..DIGEST_SIZE]);
        data = &data[DIGEST_SIZE..];
        Some(DomainKey::from_bytes(key_bytes))
    } else {
        None
    };

    // locator_token (optional, v2+)
    if data.is_empty() {
        return Err(DecodeError::TruncatedNodes);
    }
    let lt_present = data[0];
    data = &data[1..];

    let locator_token = if lt_present == 1 {
        if data.len() < DIGEST_SIZE {
            return Err(DecodeError::TruncatedNodes);
        }
        let mut token_bytes = [0u8; DIGEST_SIZE];
        token_bytes.copy_from_slice(&data[..DIGEST_SIZE]);
        data = &data[DIGEST_SIZE..];
        Some(LocatorToken(token_bytes))
    } else if lt_present == 0 {
        None
    } else {
        return Err(DecodeError::BadLocatorTokenPresent { value: lt_present });
    };

    // Nodes
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (node, remaining) = decode_node(data)?;
        nodes.push(node);
        data = remaining;
    }

    Ok(ChecksumTree {
        nodes,
        block_count,
        block_size,
        root_hash,
        domain_key,
        locator_token,
    })
}

/// Decode a single [`ChecksumTreeNode`] from `data`.
///
/// Returns the decoded node and the remaining unread bytes.
fn decode_node(mut data: &[u8]) -> Result<(ChecksumTreeNode, &[u8]), DecodeError> {
    if data.len() < 2 {
        return Err(DecodeError::TruncatedNodes);
    }

    // child_count (U16Le)
    let child_count = U16Le::from_le_bytes([data[0], data[1]]).as_raw() as usize;
    data = &data[2..];

    if child_count > crate::FANOUT {
        return Err(DecodeError::FanoutExceeded {
            child_count: child_count as u16,
        });
    }

    // children
    let children_bytes = child_count * DIGEST_SIZE;
    if data.len() < children_bytes + DIGEST_SIZE {
        return Err(DecodeError::TruncatedNodes);
    }

    let mut children = Vec::with_capacity(child_count);
    for i in 0..child_count {
        let start = i * DIGEST_SIZE;
        let mut digest = Digest::default();
        digest.copy_from_slice(&data[start..start + DIGEST_SIZE]);
        children.push(digest);
    }
    data = &data[children_bytes..];

    // self_checksum
    let mut self_checksum = Digest::default();
    self_checksum.copy_from_slice(&data[..DIGEST_SIZE]);
    data = &data[DIGEST_SIZE..];

    let node = ChecksumTreeNode {
        children,
        self_checksum,
    };

    Ok((node, data))
}

// ---------------------------------------------------------------------------
// Convenience: DomainKey::from_bytes
// ---------------------------------------------------------------------------

impl DomainKey {
    /// Construct a [`DomainKey`] from raw key bytes.
    ///
    /// This is a deserialization constructor; the bytes are assumed to be a
    /// valid previously-derived domain key.
    pub fn from_bytes(bytes: [u8; DIGEST_SIZE]) -> Self {
        Self { key: bytes }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hash_block, zero_digest, ChecksumTreeBuilder, DomainTag, DEFAULT_BLOCK_SIZE};
    use alloc::{format, vec};

    // -- Round-trip tests --

    #[test]
    fn roundtrip_empty_tree() {
        let tree = ChecksumTree {
            nodes: Vec::new(),
            block_count: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            root_hash: zero_digest(),
            domain_key: None,
            locator_token: None,
        };

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode empty tree");
        assert_eq!(decoded.nodes.len(), 0);
        assert_eq!(decoded.block_count, 0);
        assert_eq!(decoded.block_size, DEFAULT_BLOCK_SIZE);
        assert_eq!(decoded.root_hash, zero_digest());
        assert!(decoded.domain_key.is_none());
    }

    #[test]
    fn roundtrip_single_block_tree() {
        let leaf = hash_block(b"hello checksum tree");
        let tree = ChecksumTree::from_leaves(&[leaf], DEFAULT_BLOCK_SIZE);

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode single-block tree");
        assert_eq!(decoded.block_count, 1);
        assert_eq!(decoded.block_size, DEFAULT_BLOCK_SIZE);
        assert_eq!(decoded.root_hash, tree.root_hash);
        assert_eq!(decoded.nodes.len(), tree.nodes.len());
        for (a, b) in decoded.nodes.iter().zip(tree.nodes.iter()) {
            assert!(a.verify());
            assert_eq!(a.children, b.children);
            assert_eq!(a.self_checksum, b.self_checksum);
        }
    }

    #[test]
    fn roundtrip_multi_block_tree() {
        let data = vec![0xABu8; DEFAULT_BLOCK_SIZE * 10 + 123];
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.ingest(&data);
        let tree = builder.finish();

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode multi-block tree");
        assert_eq!(decoded.block_count, tree.block_count);
        assert_eq!(decoded.root_hash, tree.root_hash);
        assert_eq!(decoded.nodes.len(), tree.nodes.len());
        for (a, b) in decoded.nodes.iter().zip(tree.nodes.iter()) {
            assert!(a.verify());
            assert_eq!(a.children, b.children);
            assert_eq!(a.self_checksum, b.self_checksum);
        }
    }

    #[test]
    fn roundtrip_large_tree() {
        // 1025 blocks: forces at least 2 tree levels (FANOUT=256, so
        // 1025/256 = 5 level-0 nodes, which combine into 1 root node).
        let data = vec![0xCCu8; DEFAULT_BLOCK_SIZE * 1025];
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.ingest(&data);
        let tree = builder.finish();

        assert!(tree.nodes.len() > 1, "large tree must have interior nodes");

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode large tree");
        assert_eq!(decoded.block_count, tree.block_count);
        assert_eq!(decoded.root_hash, tree.root_hash);
        assert_eq!(decoded.nodes.len(), tree.nodes.len());
        for (a, b) in decoded.nodes.iter().zip(tree.nodes.iter()) {
            assert!(a.verify());
            assert_eq!(a.self_checksum, b.self_checksum);
        }
    }

    #[test]
    fn roundtrip_with_domain_key() {
        let dk = DomainTag::ObjectData.derive_key();
        let data = b"domain-separated binary roundtrip test";
        let mut builder = ChecksumTreeBuilder::new_with_domain(DEFAULT_BLOCK_SIZE, dk);
        builder.ingest(data);
        let tree = builder.finish();

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode domain tree");
        assert_eq!(decoded.root_hash, tree.root_hash);
        assert_eq!(decoded.domain_key, tree.domain_key);
        assert_eq!(decoded.block_count, tree.block_count);
    }

    #[test]
    fn roundtrip_non_default_block_size() {
        let block_size = 1024;
        let data = vec![0xDDu8; block_size * 7];
        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&data);
        let tree = builder.finish();

        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode non-default block size");
        assert_eq!(decoded.block_size, block_size);
        assert_eq!(decoded.block_count, 7);
        assert_eq!(decoded.root_hash, tree.root_hash);
    }

    // -- Error path tests --

    #[test]
    fn decode_bad_magic() {
        let bad = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut full = vec![0u8; MIN_HEADER_SIZE];
        full[..4].copy_from_slice(&bad);
        let err = decode_tree(&full).unwrap_err();
        assert!(matches!(err, DecodeError::BadMagic { found: _ }));
    }

    #[test]
    fn decode_unknown_version() {
        let tree = ChecksumTree {
            nodes: Vec::new(),
            block_count: 0,
            block_size: DEFAULT_BLOCK_SIZE,
            root_hash: zero_digest(),
            domain_key: None,
            locator_token: None,
        };
        let mut encoded = encode_tree(&tree);
        // Corrupt version byte (byte at index 4)
        encoded[4] = 0xFF;
        let err = decode_tree(&encoded).unwrap_err();
        assert!(matches!(err, DecodeError::UnknownVersion { version: 0xFF }));
    }

    #[test]
    fn decode_truncated_header() {
        let data = [0x56, 0x42]; // only 2 bytes
        let err = decode_tree(&data).unwrap_err();
        assert!(matches!(err, DecodeError::TruncatedHeader));
    }

    #[test]
    fn decode_truncated_nodes() {
        let leaf = hash_block(b"test");
        let tree = ChecksumTree::from_leaves(&[leaf], DEFAULT_BLOCK_SIZE);
        let mut encoded = encode_tree(&tree);
        // Truncate the last few bytes of node data
        let truncate_to = encoded.len() - 5;
        encoded.truncate(truncate_to);
        let err = decode_tree(&encoded).unwrap_err();
        assert!(matches!(err, DecodeError::TruncatedNodes));
    }

    #[test]
    fn decode_fanout_exceeded() {
        // Build a valid tree, then corrupt a node's child_count to exceed FANOUT
        let data = vec![0xEEu8; DEFAULT_BLOCK_SIZE * 3];
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.ingest(&data);
        let tree = builder.finish();
        let mut encoded = encode_tree(&tree);

        // Find child_count bytes: after header
        let dk_offset = if tree.domain_key.is_some() {
            DIGEST_SIZE
        } else {
            0
        };
        let header_size = MIN_HEADER_SIZE + dk_offset;
        // child_count is a U16Le at header_size — set to 511 (> FANOUT 256)
        let corrupt = U16Le::from(511u16).encode();
        encoded[header_size] = corrupt[0];
        encoded[header_size + 1] = corrupt[1];

        let err = decode_tree(&encoded).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::FanoutExceeded { child_count: 511 }
        ));
    }

    #[test]
    fn empty_tree_roundtrip_domain_key_none() {
        let tree = ChecksumTree {
            nodes: Vec::new(),
            block_count: 0,
            block_size: 512,
            root_hash: zero_digest(),
            domain_key: None,
            locator_token: None,
        };
        let encoded = encode_tree(&tree);
        let decoded = decode_tree(&encoded).expect("decode empty tree");
        assert_eq!(decoded.block_size, 512);
        assert_eq!(decoded.domain_key, None);
    }

    // -- U16Le/U32Le/U64Le round-trip property --

    #[test]
    fn le_wrappers_roundtrip_edge_values() {
        // U16Le
        for &val in &[0u16, 1, 255, 256, u16::MAX] {
            let encoded = U16Le::from(val).encode();
            let decoded = U16Le::from_le_bytes(encoded).as_raw();
            assert_eq!(decoded, val, "U16Le round-trip failed for {val}");
        }

        // U32Le
        for &val in &[0u32, 1, 256, 65536, 4096, u32::MAX] {
            let encoded = U32Le::from(val).encode();
            let decoded = U32Le::from_le_bytes(encoded).as_raw();
            assert_eq!(decoded, val, "U32Le round-trip failed for {val}");
        }

        // U64Le
        for &val in &[0u64, 1, 1024, 1 << 32, u64::MAX] {
            let encoded = U64Le::from(val).encode();
            let decoded = U64Le::from_le_bytes(encoded).as_raw();
            assert_eq!(decoded, val, "U64Le round-trip failed for {val}");
        }
    }

    // -- Display impl for DecodeError --

    #[test]
    fn decode_error_display() {
        let s = format!(
            "{}",
            DecodeError::BadMagic {
                found: [0xDE, 0xAD, 0xBE, 0xEF]
            }
        );
        assert!(s.contains("bad magic"));
        assert!(s.contains("deadbeef") || s.contains("de, ad, be, ef"));

        let s = format!("{}", DecodeError::UnknownVersion { version: 7 });
        assert!(s.contains("unknown"));
        assert!(s.contains("7"));

        let s = format!("{}", DecodeError::TruncatedHeader);
        assert!(s.contains("too short"));

        let s = format!("{}", DecodeError::TruncatedNodes);
        assert!(s.contains("truncated"));

        let s = format!("{}", DecodeError::FanoutExceeded { child_count: 300 });
        assert!(s.contains("300"));
        assert!(s.contains("FANOUT"));
    }
}
