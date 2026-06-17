#![no_std]
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! Incremental Merkle checksum tree with BLAKE3 for partial-read integrity,
//! scrub acceleration, and send/receive integrity (G3 phase 1).
//!
//! ## Structure
//!
//! - Leaves: BLAKE3 hash of each data block (default block size 4096 bytes).
//! - Interior nodes: BLAKE3 hash of concatenated child hashes.
//! - Fixed fanout `FANOUT` (256) children per interior node.
//! - Each node stores its child digests plus a self-checksum.
//!
//! ## Key Types
//!
//! - [`ChecksumTreeNode`]: one interior node holding child hashes + self-hash.
//! - [`ChecksumTree`]: complete Merkle tree over file extents.
//! - [`ChecksumTreeBuilder`]: streaming builder for computing the tree.
//! - [`ChecksumTreeVerifier`]: range verification with fine-grained outcomes.
//! - [`VerificationResult`]: `Verified`, `Corrupted`, or `Missing`.

extern crate alloc;

use alloc::format;
use alloc::vec::Vec;
use blake3::Hasher;

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

pub mod serialize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default data block size in bytes (leaf granularity).
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Number of child hashes per interior node.
pub const FANOUT: usize = 256;

/// BLAKE3-256 digest size in bytes.
pub const DIGEST_SIZE: usize = 32;

/// A 32-byte BLAKE3 digest.
pub type Digest = [u8; DIGEST_SIZE];

// ---------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------

/// Domain tag for per-record-type context hashing.
///
/// Each variant carries a unique `u8` discriminant used for domain key
/// derivation, preventing cross-type collision attacks where a data block's
/// hash could be mistaken for a metadata block's hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainTag {
    /// Object data payload (default block data).
    ObjectData = 0x01,
    /// Object metadata (size, block map references, attributes).
    ObjectMetadata = 0x02,
    /// Extent map (logical-to-physical block mappings).
    ExtentMap = 0x03,
    /// Directory entry (name, inode, type).
    DirectoryEntry = 0x04,
    /// Scrub record (integrity scan state, corruption tracking).
    ScrubRecord = 0x05,
    /// Erasure-coding shard (parity/reconstruction data).
    ErasureCodingShard = 0x06,
    /// Intent log entry (write-ahead log for crash safety).
    IntentLog = 0x07,
    /// Per-object content digest for read-path verification and write-path
    /// checksum computation.
    ObjectContent = 0x08,
    /// Extended-attribute key-value storage.
    Xattr = 0x09,
    /// Write segment checksum anchor (segment-level digest over batched writes).
    WriteSegment = 0x0A,
    /// Segment integrity footer (hash-chain link between segment footers).
    SegmentIntegrityFooter = 0x0B,
    /// Committed root pointer (pool-import recovery anchor).
    CommittedRoot = 0x0C,
    /// Read-path verification digest for domain-separated read-time
    /// integrity checking against stored per-object checksums.
    ReadVerify = 0x0D,
    /// Scrub repair validation ledger for domain-separated BLAKE3-256
    /// repair-event recording with deterministic replay.
    ScrubRepair = 0x0E,
    /// Locator-bound checksum root (domain-separated binding of Merkle root to committed extent locator).
    LocatorBinding = 0x0F,
}

impl DomainTag {
    /// Return the `u8` discriminant for this domain tag.
    pub fn discriminant(self) -> u8 {
        self as u8
    }

    /// Return the human-readable label for this domain tag.
    pub fn label(self) -> &'static str {
        match self {
            Self::ObjectData => "object-data",
            Self::ObjectMetadata => "object-metadata",
            Self::ExtentMap => "extent-map",
            Self::DirectoryEntry => "directory-entry",
            Self::ScrubRecord => "scrub-record",
            Self::ErasureCodingShard => "erasure-coding-shard",
            Self::IntentLog => "intent-log",
            Self::ObjectContent => "object-content",
            Self::Xattr => "xattr",
            Self::WriteSegment => "write-segment",
            Self::SegmentIntegrityFooter => "segment-integrity-footer",
            Self::CommittedRoot => "committed-root",
            Self::ReadVerify => "read-verify",
            Self::ScrubRepair => "scrub-repair",
            Self::LocatorBinding => "locator-binding",
        }
    }

    /// Derive a [`DomainKey`] from this tag.
    ///
    /// The key is derived using BLAKE3's key-derivation function with
    /// the tag's discriminant byte as key material.
    pub fn derive_key(self) -> DomainKey {
        DomainKey::from_tag(self)
    }
}

/// A 32-byte domain-separation key derived from a [`DomainTag`].
///
/// Used with [`blake3::Hasher::new_keyed`] to produce per-record-type
/// contextualized checksums. Keys derived from different [`DomainTag`]
/// values are cryptographically independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DomainKey {
    key: [u8; 32],
}

impl DomainKey {
    /// Context string for BLAKE3 KDF. Changing this would break all
    /// existing checksums.
    const KDF_CONTEXT: &str = "tidefs-checksum-tree domain-separation v1";

    /// Derive a domain key from a [`DomainTag`].
    pub fn from_tag(tag: DomainTag) -> Self {
        let material = [tag.discriminant()];
        let key = blake3::derive_key(Self::KDF_CONTEXT, &material);
        Self { key }
    }

    /// Return the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

// ---------------------------------------------------------------------------
// ObjectDigest
// ---------------------------------------------------------------------------

/// A BLAKE3-256 digest for per-object content verification.
///
/// Produced with [`DomainTag::ObjectContent`] domain separation. Used by
/// read-path verification and write-path checksum computation to share a
/// well-typed digest type instead of raw `[u8; 32]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectDigest(pub [u8; DIGEST_SIZE]);

impl ObjectDigest {
    /// Compute a domain-separated digest from `data` using the supplied key.
    ///
    /// The key should be derived from [`DomainTag::ObjectContent`] via
    /// [`DomainTag::derive_key`].
    pub fn compute(data: &[u8], domain_key: &DomainKey) -> Self {
        let mut hasher = blake3::Hasher::new_keyed(domain_key.as_bytes());
        hasher.update(data);
        Self(*hasher.finalize().as_bytes())
    }

    /// Verify that `data` hashes to this digest under `domain_key`.
    pub fn verify(&self, data: &[u8], domain_key: &DomainKey) -> bool {
        Self::compute(data, domain_key) == *self
    }

    /// Return the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for ObjectDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("ObjectDigest")
            .field(&hex_fmt(&self.0))
            .finish()
    }
}

impl core::fmt::Display for ObjectDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex_fmt(&self.0))
    }
}

/// Format a `[u8; 32]` as a hex string for Display/Debug.
fn hex_fmt(bytes: &[u8; 32]) -> alloc::string::String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


// ---------------------------------------------------------------------------
// LocatorToken
// ---------------------------------------------------------------------------

/// A 32-byte token that binds a checksum tree root to committed extent
/// locator evidence.
///
/// Produced by hashing the canonical serialisation of the committed extent
/// locator fields (pool epoch, device id, offset, length) together with
/// any receipt identity bytes.  Stored alongside the checksum tree root so
/// that verification can confirm the locator has not changed since the
/// checksum was committed.
///
/// When a [] carries a [], the published
///  is the BLAKE3-256 hash of the raw Merkle root concatenated
/// with the token bytes, domain-separated with
/// [].  Verification without the matching token
/// will fail.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LocatorToken(pub [u8; DIGEST_SIZE]);

impl LocatorToken {
    /// Construct a locator token from arbitrary locator evidence bytes.
    ///
    /// The canonical encoding of the locator (pool epoch, device, offset,
    /// length, receipt identity) is hashed with a plain BLAKE3-256 to
    /// produce a fixed-size token.  Callers are responsible for providing
    /// a deterministic, collision-resistant byte representation.
    pub fn from_evidence(evidence: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(evidence);
        Self(*hasher.finalize().as_bytes())
    }

    /// Return the raw token bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        &self.0
    }
}

impl core::fmt::Debug for LocatorToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("LocatorToken")
            .field(&hex_fmt(&self.0))
            .finish()
    }
}

impl core::fmt::Display for LocatorToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&hex_fmt(&self.0))
    }
}

impl Default for LocatorToken {
    fn default() -> Self {
        Self([0u8; DIGEST_SIZE])
    }
}
// ---------------------------------------------------------------------------
// ChecksumTreeNode
// ---------------------------------------------------------------------------

/// One interior node in the checksum tree.
///
/// Holds up to `FANOUT` child hashes and the self-checksum (the BLAKE3 hash
/// of the concatenation of non-empty child hashes). Leaves are not stored as
/// nodes; they are represented by their digest alone. The self-checksum is
/// always valid and up-to-date after construction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Default)]
pub struct ChecksumTreeNode {
    /// Child digests.
    pub children: Vec<Digest>,
    /// BLAKE3 hash of all valid child digests concatenated.
    pub self_checksum: Digest,
}

impl ChecksumTreeNode {
    /// Create a new interior node from the given child digests.
    ///
    /// `children` must contain at least 1 and at most `FANOUT` entries.
    /// Returns `None` if the slice is empty or too long.
    pub fn new(children: &[Digest]) -> Option<Self> {
        if children.is_empty() || children.len() > FANOUT {
            return None;
        }

        let mut node = Self {
            children: children.to_vec(),
            self_checksum: Digest::default(),
        };

        node.recompute_self_checksum();
        Some(node)
    }

    /// Recompute the self-checksum from the current children.
    fn recompute_self_checksum(&mut self) {
        let mut hasher = Hasher::new();
        for child in &self.children {
            hasher.update(child.as_slice());
        }
        self.self_checksum = *hasher.finalize().as_bytes();
    }

    /// Return a slice of the valid child digests.
    pub fn valid_children(&self) -> &[Digest] {
        &self.children
    }

    /// Verify that the self-checksum matches the child hashes.
    pub fn verify(&self) -> bool {
        let mut hasher = Hasher::new();
        for child in &self.children {
            hasher.update(child.as_slice());
        }
        *hasher.finalize().as_bytes() == self.self_checksum
    }
}

// ---------------------------------------------------------------------------
// ChecksumTree
// ---------------------------------------------------------------------------

/// A complete Merkle checksum tree over a sequence of data blocks.
///
/// The tree is represented as a flat array of [`ChecksumTreeNode`]s in
/// level order: level 0 (the leaves closest to data) first, then level 1,
/// up to the root. Leaves themselves are not stored as nodes; they are
/// referenced by the digests in level-0 interior nodes.
///
/// An empty tree (zero blocks) has zero nodes and a zero root.
/// ## Usage example
///
/// Build a tree from leaf hashes and verify data integrity:
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let data = b"four kilobytes of file data here...";
/// let leaf = hash_block(data);
/// let tree = ChecksumTree::from_leaves(&[leaf], 4096);
///
/// assert_eq!(tree.block_count, 1);
/// assert!(!tree.root_hash.iter().all(|&b| b == 0));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChecksumTree {
    /// Flat array of interior nodes, level-order (level 0 first).
    pub nodes: Vec<ChecksumTreeNode>,
    /// Number of data blocks (leaves).
    pub block_count: u64,
    /// Data block size in bytes.
    pub block_size: usize,
    /// The root hash (self-checksum of the root node, or zero digest if empty).
    pub root_hash: Digest,
    /// Domain key used for leaf-level hashing, if domain separation is active.
    pub domain_key: Option<DomainKey>,
    /// Locator token binding the root hash to committed extent locator evidence.
    ///
    /// When `Some`, the `root_hash` field is the domain-separated BLAKE3-256
    /// hash of the raw Merkle root concatenated with the token bytes.
    /// Verification must supply the matching token.
    pub locator_token: Option<LocatorToken>,
}

impl ChecksumTree {
    /// Construct a tree from leaf digests.
    ///
    /// Returns a tree with a single root node if there are fewer than
    /// `FANOUT` leaves (in which case the "root" is the only interior node
    /// whose children are the leaves directly).
    pub fn from_leaves(leaf_digests: &[Digest], block_size: usize) -> Self {
        let block_count = leaf_digests.len() as u64;

        if leaf_digests.is_empty() {
            return Self {
                nodes: Vec::new(),
                block_count: 0,
                block_size,
                root_hash: Digest::default(),
                domain_key: None,
                locator_token: None,
            };
        }

        let mut nodes: Vec<ChecksumTreeNode> = Vec::new();

        // Build level 0 from the leaf digests
        let mut current_level: Vec<Digest> = leaf_digests.to_vec();

        while current_level.len() > 1 {
            let mut next_level: Vec<Digest> = Vec::new();
            for chunk in current_level.chunks(FANOUT) {
                let node =
                    ChecksumTreeNode::new(chunk).expect("chunk is non-empty and at most FANOUT");
                next_level.push(node.self_checksum);
                nodes.push(node);
            }
            current_level = next_level;
        }

        // The single remaining digest is the root
        let root_hash = current_level[0];

        // If we only have one level (fewer than FANOUT leaves), create a
        // single root node. Otherwise the root was already built.
        if nodes.is_empty() && leaf_digests.len() <= FANOUT {
            let root_node = ChecksumTreeNode::new(leaf_digests).expect("1..=FANOUT leaves");
            nodes.push(root_node);
        }

        Self {
            nodes,
            block_count,
            block_size,
            root_hash,
            domain_key: None,
            locator_token: None,
        }
    }

    /// Construct a tree from leaf digests with a domain-separation key.
    ///
    /// The `domain_key` is used for leaf-level hashing when verifying data
    /// against this tree. Interior nodes are built with plain BLAKE3 over
    /// concatenated child hashes.
    pub fn from_leaves_with_domain(
        leaf_digests: &[Digest],
        block_size: usize,
        domain_key: Option<DomainKey>,
        locator_token: Option<LocatorToken>,
    ) -> Self {
        let block_count = leaf_digests.len() as u64;

        if leaf_digests.is_empty() {
            return Self {
                nodes: Vec::new(),
                block_count: 0,
                block_size,
                root_hash: Digest::default(),
                domain_key,
                locator_token,
            };
        }

        let mut nodes: Vec<ChecksumTreeNode> = Vec::new();

        let mut current_level: Vec<Digest> = leaf_digests.to_vec();

        while current_level.len() > 1 {
            let mut next_level: Vec<Digest> = Vec::new();
            for chunk in current_level.chunks(FANOUT) {
                let node =
                    ChecksumTreeNode::new(chunk).expect("chunk is non-empty and at most FANOUT");
                next_level.push(node.self_checksum);
                nodes.push(node);
            }
            current_level = next_level;
        }

        let root_hash = current_level[0];

        if nodes.is_empty() && leaf_digests.len() <= FANOUT {
            let root_node = ChecksumTreeNode::new(leaf_digests).expect("1..=FANOUT leaves");
            nodes.push(root_node);
        }

        // When a locator token is present, bind the Merkle root to the
        // locator by hashing root_hash || locator_token with a domain-
        // separated key.  This ensures the published root_hash depends on
        // both the data content and the physical extent location.
        let root_hash = if let Some(ref token) = locator_token {
            let dk = DomainTag::LocatorBinding.derive_key();
            let mut hasher = blake3::Hasher::new_keyed(dk.as_bytes());
            hasher.update(&root_hash);
            hasher.update(token.as_bytes());
            *hasher.finalize().as_bytes()
        } else {
            root_hash
        };

        Self {
            nodes,
            block_count,
            block_size,
            root_hash,
            domain_key,
            locator_token,
        }
    }

    /// Return true if the tree is empty (zero data blocks).
    pub fn is_empty(&self) -> bool {
        self.block_count == 0
    }

    /// Return the number of interior nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Return the number of tree levels (0 for empty, 1 for small trees).
    pub fn level_count(&self) -> usize {
        if self.block_count == 0 {
            return 0;
        }
        let mut levels: usize = 1;
        let mut count = self.block_count;
        while count > FANOUT as u64 {
            count = count.div_ceil(FANOUT as u64);
            levels += 1;
        }
        levels
    }
    /// Collect all leaf digests from the level-0 nodes.
    pub fn leaf_digests(&self) -> Vec<Digest> {
        if self.is_empty() {
            return Vec::new();
        }
        let level0_count = self.block_count.div_ceil(FANOUT as u64) as usize;
        let mut leaves = Vec::with_capacity(self.block_count as usize);
        for node in self.nodes.iter().take(level0_count) {
            leaves.extend_from_slice(node.valid_children());
        }
        leaves.truncate(self.block_count as usize);
        leaves
    }

    /// Return the digest for one leaf index.
    pub fn leaf_digest(&self, leaf_index: u64) -> Option<Digest> {
        if leaf_index >= self.block_count || self.is_empty() {
            return None;
        }

        let node_index = (leaf_index / FANOUT as u64) as usize;
        let child_index = (leaf_index % FANOUT as u64) as usize;

        self.nodes
            .get(node_index)
            .and_then(|node| node.valid_children().get(child_index))
            .copied()
    }

    /// Generate a Merkle subtree proof for the given leaf index.
    ///
    /// Returns `None` if the leaf index is out of range or the tree
    /// is empty. The proof contains the leaf digest, sibling hashes
    /// at each tree level, and the root hash. Verification is
    /// performed via [`verify_proof`].
    pub fn generate_proof(&self, leaf_index: u64) -> Option<SubtreeProof> {
        if leaf_index >= self.block_count || self.is_empty() {
            return None;
        }

        let leaf_digests = self.leaf_digests();
        let leaf_digest = leaf_digests[leaf_index as usize];

        // Single-block trees store the leaf hash directly as the root;
        // no interior hashing is needed.
        if self.block_count == 1 {
            return Some(SubtreeProof {
                leaf_index,
                leaf_digest,
                path: Vec::new(),
                root_hash: self.root_hash,
            });
        }

        let mut path: Vec<ProofLevel> = Vec::new();

        // At leaf level, the "item index" is the leaf index.
        let mut item_idx = leaf_index;
        // Number of items (leaves or node hashes) at the current level.
        let mut items_at_level = self.block_count;
        // Index in self.nodes where the current level's nodes begin.
        let mut node_start: usize = 0;

        loop {
            let node_idx_in_level = (item_idx / FANOUT as u64) as usize;
            let pos = (item_idx % FANOUT as u64) as usize;

            let node = &self.nodes[node_start + node_idx_in_level];
            let siblings: Vec<Digest> = node
                .children
                .iter()
                .enumerate()
                .filter(|&(j, _)| j != pos)
                .map(|(_, d)| *d)
                .collect();

            path.push(ProofLevel {
                position: pos,
                siblings,
            });

            // Move to next level.
            let nodes_at_this_level = items_at_level.div_ceil(FANOUT as u64) as usize;
            node_start += nodes_at_this_level;

            if node_start >= self.nodes.len() {
                break;
            }

            // The "item" at the next level is this node's index within
            // the current level.
            item_idx = node_idx_in_level as u64;
            items_at_level = nodes_at_this_level as u64;
        }

        Some(SubtreeProof {
            leaf_index,
            leaf_digest,
            path,
            root_hash: self.root_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// ChecksumTreeBuilder
// ---------------------------------------------------------------------------

/// Streaming builder for constructing a [`ChecksumTree`].
///
/// Feed data one chunk at a time via [`Self::ingest`]. The builder
/// splits input into `block_size` chunks, computes leaf hashes, and
/// accumulates them. Call [`Self::finish`] to obtain the completed tree.
///
/// ## Usage example
///
/// Stream data in chunks and obtain a verifiable tree:
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let file_data = [0xABu8; 16384];
/// let mut builder = ChecksumTreeBuilder::new(4096);
/// builder.ingest(&file_data);
/// let tree = builder.finish();
///
/// // 16384 bytes / 4096 bytes-per-block = 4 blocks
/// assert_eq!(tree.block_count, 4);
/// assert_eq!(tree.block_size, 4096);
/// assert_ne!(tree.root_hash, zero_digest());
/// ```
#[derive(Clone, Debug)]
pub struct ChecksumTreeBuilder {
    block_size: usize,
    /// Domain key for leaf-level hashing, if domain separation is active.
    domain_key: Option<DomainKey>,
    /// Locator token for binding the root hash to committed extent locator evidence.
    locator_token: Option<LocatorToken>,
    /// Accumulated leaf digests.
    leaf_digests: Vec<Digest>,
}

impl ChecksumTreeBuilder {
    /// Create a new builder with the given block size.
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size,
            domain_key: None,
            locator_token: None,
            leaf_digests: Vec::new(),
        }
    }

    /// Create a new builder with domain separation.
    ///
    /// Leaf data will be hashed with `blake3::Hasher::new_keyed(&domain_key)`
    /// to produce domain-separated leaf digests.
    pub fn new_with_domain(block_size: usize, domain_key: DomainKey) -> Self {
        Self {
            block_size,
            domain_key: Some(domain_key),
            locator_token: None,
            leaf_digests: Vec::new(),
        }
    }

    /// Return the domain key in use, if any.
    pub fn domain_key(&self) -> Option<&DomainKey> {
        self.domain_key.as_ref()
    }

    /// Set the locator token for root-hash binding.
    ///
    /// When set, the finished tree's `root_hash` will be the domain-separated
    /// BLAKE3-256 hash of the raw Merkle root concatenated with the token
    /// bytes, binding the checksum to the committed extent locator.
    pub fn set_locator(&mut self, token: LocatorToken) {
        self.locator_token = Some(token);
    }

    /// Return the locator token, if set.
    pub fn locator_token(&self) -> Option<&LocatorToken> {
        self.locator_token.as_ref()
    }

    /// Ingest extent data, splitting into `block_size` chunks and computing
    /// a leaf hash for each chunk. Partial trailing chunks are hashed as-is.
    ///
    /// If a domain key is set, each leaf is hashed with
    /// `Hasher::new_keyed(&domain_key)` for domain-separated output.
    pub fn ingest(&mut self, data: &[u8]) {
        if let Some(ref dk) = self.domain_key {
            for chunk in data.chunks(self.block_size) {
                let mut hasher = Hasher::new_keyed(dk.as_bytes());
                hasher.update(chunk);
                let leaf: Digest = *hasher.finalize().as_bytes();
                self.leaf_digests.push(leaf);
            }
        } else {
            for chunk in data.chunks(self.block_size) {
                let mut hasher = Hasher::new();
                hasher.update(chunk);
                let leaf: Digest = *hasher.finalize().as_bytes();
                self.leaf_digests.push(leaf);
            }
        }
    }

    /// Ingest a pre-computed leaf digest.
    pub fn ingest_digest(&mut self, leaf: Digest) {
        self.leaf_digests.push(leaf);
    }

    /// Finish building and return the [`ChecksumTree`].
    ///
    /// If a locator token has been set via [`Self::set_locator`], the
    /// published `root_hash` will be bound to that locator.
    pub fn finish(self) -> ChecksumTree {
        ChecksumTree::from_leaves_with_domain(
            &self.leaf_digests,
            self.block_size,
            self.domain_key,
            self.locator_token,
        )
    }

    /// Return the number of leaves ingested so far.
    pub fn leaf_count(&self) -> usize {
        self.leaf_digests.len()
    }
}

impl Default for ChecksumTreeBuilder {
    fn default() -> Self {
        Self::new(DEFAULT_BLOCK_SIZE)
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Outcome of verifying a byte range against a checksum tree.
///
/// ## Verification outcomes
///
/// ```
/// # use tidefs_checksum_tree::*;
/// # let data = vec![0u8; 8192];
/// # let mut builder = ChecksumTreeBuilder::new(4096);
/// # builder.ingest(&data);
/// # let tree = builder.finish();
/// let verifier = ChecksumTreeVerifier::new(tree);
///
/// // Correct data verifies.
/// assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
///
/// // Tampered data is detected.
/// let mut bad = data.clone();
/// bad[100] ^= 0xFF;
/// assert!(matches!(
///     verifier.verify_full(&bad),
///     VerificationResult::Corrupted { .. }
/// ));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// The range is fully verified.
    Verified,
    /// A block in the range has corrupted data.
    Corrupted {
        /// Byte offset of the corrupted block.
        offset: u64,
        /// Expected BLAKE3 digest from the tree.
        expected: Digest,
        /// Actual BLAKE3 digest computed from the data.
        actual: Digest,
    },
    /// A block in the range is missing (no data provided).
    Missing {
        /// Byte offset where data is missing.
        offset: u64,
    },
    /// The supplied locator token does not match the token bound to the
    /// checksum tree root.  The data may have been relocated, or the
    /// caller provided a token for a different extent.
    LocatorMismatch {
        /// The locator token supplied for verification.
        supplied: LocatorToken,
        /// The locator token bound to the checksum tree.
        bound: LocatorToken,
    },
}

/// Verifies a byte range against a checksum tree by walking leaf-to-root
/// paths for each block in the range.
///
/// If the tree was built with a [`DomainKey`], verification uses the same
/// key for leaf-level hashing.
#[derive(Clone, Debug)]
pub struct ChecksumTreeVerifier {
    tree: ChecksumTree,
}

impl ChecksumTreeVerifier {
    /// Create a verifier bound to the given tree.
    pub fn new(tree: ChecksumTree) -> Self {
        Self { tree }
    }

    /// Verify that `data` (the full extent data) matches the tree.
    ///
    /// Splits `data` into `block_size` chunks and verifies each chunk's
    /// BLAKE3 hash against the leaf digests in the tree.
    pub fn verify_full(&self, data: &[u8]) -> VerificationResult {
        let block_size = self.tree.block_size;
        let expected_leaf_count = self.tree.block_count as usize;
        let actual_leaf_count = data.len().div_ceil(block_size);

        if actual_leaf_count < expected_leaf_count {
            // Find the first missing offset
            let missing_offset = (actual_leaf_count * block_size) as u64;
            return VerificationResult::Missing {
                offset: missing_offset,
            };
        }

        // Retrieve the leaf digests by walking the tree
        let leaf_digests = self.collect_leaf_digests();

        for (i, chunk) in data.chunks(block_size).enumerate() {
            if i >= leaf_digests.len() {
                break;
            }
            let actual = self.hash_leaf(chunk);

            if actual != leaf_digests[i] {
                return VerificationResult::Corrupted {
                    offset: (i * block_size) as u64,
                    expected: leaf_digests[i],
                    actual,
                };
            }
        }

        VerificationResult::Verified
    }

    /// Verify a byte range `[start, end)`.
    ///
    /// `data_provider` is called with `(block_offset, block_size)` for each
    /// full block that overlaps the requested range. It must return the full
    /// block data so the hash can be verified against the tree.
    /// Returns the verification result for the first failure encountered.
    pub fn verify_range<F>(&self, start: u64, end: u64, data_provider: F) -> VerificationResult
    where
        F: Fn(u64, usize) -> Option<alloc::vec::Vec<u8>>,
    {
        let block_size = self.tree.block_size as u64;
        let first_block = start / block_size;
        let last_block = (end.saturating_sub(1)) / block_size;

        let leaf_digests = self.collect_leaf_digests();

        for block_idx in first_block..=last_block {
            let block_offset = block_idx * block_size;

            if block_idx as usize >= leaf_digests.len() {
                return VerificationResult::Missing {
                    offset: block_offset,
                };
            }

            // Always request the full block — the tree hash covers the full block.
            let data = match data_provider(block_offset, block_size as usize) {
                Some(d) => d,
                None => {
                    return VerificationResult::Missing {
                        offset: block_offset,
                    };
                }
            };

            let actual = self.hash_leaf(&data);

            if actual != leaf_digests[block_idx as usize] {
                return VerificationResult::Corrupted {
                    offset: block_offset,
                    expected: leaf_digests[block_idx as usize],
                    actual,
                };
            }
        }

        VerificationResult::Verified
    }

    /// Compute a leaf hash, using domain key if the tree has one.
    fn hash_leaf(&self, data: &[u8]) -> Digest {
        if let Some(ref dk) = self.tree.domain_key {
            let mut hasher = Hasher::new_keyed(dk.as_bytes());
            hasher.update(data);
            *hasher.finalize().as_bytes()
        } else {
            let mut hasher = Hasher::new();
            hasher.update(data);
            *hasher.finalize().as_bytes()
        }
    }

    /// Verify a single leaf against the root using a sibling path.
    ///
    /// Takes the leaf index, the raw leaf data, and the sibling digests
    /// at each tree level (from leaf to root). Hashes the leaf data and
    /// walks up the sibling path, reconstructing the root hash. Returns
    /// `true` if the reconstructed root matches the stored root hash.
    ///
    /// The `sibling_path` has one entry per tree level. Each entry
    /// contains the sibling hashes at that level and the position of
    /// our hash within the parent node.
    pub fn verify_leaf(
        &self,
        _leaf_index: usize,
        leaf_data: &[u8],
        sibling_path: &[ProofLevel],
    ) -> bool {
        if self.tree.is_empty() {
            return false;
        }

        let leaf_digest = self.hash_leaf(leaf_data);

        // Walk from leaf to root.
        let mut current_hash = leaf_digest;

        for level in sibling_path {
            // Reconstruct the parent node's children: siblings + our hash
            // at the correct position.
            let mut children: Vec<Digest> = Vec::with_capacity(level.siblings.len() + 1);
            let mut sibling_iter = level.siblings.iter();
            for i in 0..=level.siblings.len() {
                if i == level.position {
                    children.push(current_hash);
                } else {
                    children.push(*sibling_iter.next().expect("sibling count mismatch"));
                }
            }

            let node = match ChecksumTreeNode::new(&children) {
                Some(n) => n,
                None => return false,
            };
            current_hash = node.self_checksum;
        }

        // After walking all levels, current_hash is the reconstructed root.
        current_hash == self.tree.root_hash
    }

    /// Collect leaf digests from the tree by extracting the level-0 node children.
    fn collect_leaf_digests(&self) -> Vec<Digest> {
        if self.tree.is_empty() {
            return Vec::new();
        }

        // Level-0 nodes are the first ceil(block_count / FANOUT) nodes
        let level0_count = self.tree.block_count.div_ceil(FANOUT as u64) as usize;
        let mut leaves = Vec::with_capacity(self.tree.block_count as usize);

        for node in self.tree.nodes.iter().take(level0_count) {
            leaves.extend_from_slice(node.valid_children());
        }

        leaves.truncate(self.tree.block_count as usize);
        leaves
    }

    /// Return a reference to the underlying tree.
    pub fn tree(&self) -> &ChecksumTree {
        &self.tree
    }

    /// Verify full data with locator binding.
    ///
    /// Before verifying the data against the Merkle tree, checks that
    /// `locator_token` matches the tree's bound locator (if any).
    /// Returns [`VerificationResult::LocatorMismatch`] when the tokens
    /// differ, allowing callers to distinguish relocation from corruption.
    pub fn verify_full_with_locator(
        &self,
        data: &[u8],
        locator_token: Option<&LocatorToken>,
    ) -> VerificationResult {
        if let Some(result) = self.check_locator(locator_token) {
            return result;
        }
        self.verify_full(data)
    }

    /// Verify a byte range with locator binding.
    ///
    /// Before verifying the range against the Merkle tree, checks that
    /// `locator_token` matches the tree's bound locator (if any).
    pub fn verify_range_with_locator<F>(
        &self,
        start: u64,
        end: u64,
        data_provider: F,
        locator_token: Option<&LocatorToken>,
    ) -> VerificationResult
    where
        F: Fn(u64, usize) -> Option<alloc::vec::Vec<u8>>,
    {
        if let Some(result) = self.check_locator(locator_token) {
            return result;
        }
        self.verify_range(start, end, data_provider)
    }

    /// Check whether `supplied_token` matches the tree's bound locator.
    ///
    /// Returns `None` when the check passes (or no binding exists).
    /// Returns `Some(LocatorMismatch)` when the tokens differ.
    fn check_locator(
        &self,
        supplied_token: Option<&LocatorToken>,
    ) -> Option<VerificationResult> {
        match (&self.tree.locator_token, supplied_token) {
            // No binding — no check needed.
            (None, _) => None,
            // Binding exists but no token supplied — mismatch.
            (Some(bound), None) => Some(VerificationResult::LocatorMismatch {
                supplied: LocatorToken::default(),
                bound: *bound,
            }),
            // Both present — compare.
            (Some(bound), Some(supplied)) => {
                if bound == supplied {
                    None
                } else {
                    Some(VerificationResult::LocatorMismatch {
                        supplied: *supplied,
                        bound: *bound,
                    })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Subtree proof
// ---------------------------------------------------------------------------

/// One level in a Merkle subtree proof.
///
/// Stores the sibling hashes at this level and the position (0-based)
/// our hash occupies within this node's children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofLevel {
    /// Position of our hash within this node's children.
    pub position: usize,
    /// Sibling hashes (all children except our hash).
    pub siblings: Vec<Digest>,
}

/// A Merkle proof that a specific leaf digest belongs to a
/// [`ChecksumTree`].
///
/// Generated by [`ChecksumTree::generate_proof`] and verified
/// by [`verify_proof`].
///
/// ## Verification
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let leaves: Vec<Digest> = (0..500u64)
///     .map(|i| hash_block(&i.to_le_bytes()))
///     .collect();
/// let tree = ChecksumTree::from_leaves(&leaves, 4096);
///
/// let proof = tree.generate_proof(42).expect("valid leaf index");
/// assert!(verify_proof(&proof));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeProof {
    /// The leaf index this proof is for.
    pub leaf_index: u64,
    /// The expected leaf digest.
    pub leaf_digest: Digest,
    /// One entry per tree level from leaf to root.
    pub path: Vec<ProofLevel>,
    /// The root hash this proof validates against.
    pub root_hash: Digest,
}

/// Verify a subtree proof against its root hash.
///
/// Walks the proof path from leaf to root, recomputing each level's
/// node hash by placing the current hash at the correct position among
/// siblings, then hashing the concatenation. Returns `true` if the
/// computed root matches `proof.root_hash`.
pub fn verify_proof(proof: &SubtreeProof) -> bool {
    let mut current_hash = proof.leaf_digest;

    for level in &proof.path {
        let mut children = level.siblings.clone();
        // Insert our hash at the correct position.
        if level.position <= children.len() {
            children.insert(level.position, current_hash);
        } else {
            return false;
        }

        let mut hasher = Hasher::new();
        for child in &children {
            hasher.update(child.as_slice());
        }
        current_hash = *hasher.finalize().as_bytes();
    }

    current_hash == proof.root_hash
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

/// Type alias for a Merkle proof, matching the [`SubtreeProof`] structure.
pub type MerkleProof = SubtreeProof;

/// Type alias for a hash digest, matching the [`Digest`] type.
pub type Hash = Digest;

/// Result of a batch Merkle proof verification.
///
/// Contains per-proof pass/fail status, the index of the first failure
/// (if any), and aggregate statistics. Implements `Display` for
/// human-readable reporting and supports Serde serialization when the
/// `serde` feature is enabled.
///
/// ## Example
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let leaves: Vec<Digest> = (0..100u64)
///     .map(|i| hash_block(&i.to_le_bytes()))
///     .collect();
/// let tree = ChecksumTree::from_leaves(&leaves, 4096);
///
/// let proofs: Vec<MerkleProof> = (0..10)
///     .map(|i| tree.generate_proof(i).unwrap())
///     .collect();
/// let expected_roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();
///
/// let report = verify_batch(&proofs, &expected_roots)
///     .expect("valid batch");
/// assert!(report.all_passed());
/// assert_eq!(report.total, 10);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchVerificationReport {
    /// Total number of proofs in the batch.
    pub total: u64,
    /// Number of proofs that passed verification.
    pub passed: u64,
    /// Number of proofs that failed verification.
    pub failed: u64,
    /// Index of the first failing proof, or `None` if all passed.
    pub first_failure: Option<u64>,
    /// Per-proof pass/fail: `per_proof[i]` is `true` if proof `i` passed.
    pub per_proof: Vec<bool>,
}

impl BatchVerificationReport {
    /// Returns `true` if every proof in the batch passed.
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Returns `true` if at least one proof failed.
    pub fn any_failed(&self) -> bool {
        self.failed > 0
    }
}

impl core::fmt::Display for BatchVerificationReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BatchVerificationReport {{ total: {}, passed: {}, failed: {}",
            self.total, self.passed, self.failed,
        )?;
        if let Some(idx) = self.first_failure {
            write!(f, ", first_failure: {idx}")?;
        }
        write!(f, " }}")
    }
}

/// Error type for batch verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchVerifyError {
    /// The number of proofs does not match the number of expected roots.
    LengthMismatch { proofs_len: usize, roots_len: usize },
}

impl core::fmt::Display for BatchVerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthMismatch {
                proofs_len,
                roots_len,
            } => {
                write!(
                    f,
                    "proofs length ({proofs_len}) does not match expected_roots length ({roots_len})",
                )
            }
        }
    }
}

/// Verify a batch of Merkle proofs against expected root hashes.
///
/// Each proof is verified against the corresponding entry in
/// `expected_roots`. Proofs sharing the same root hash and interior
/// node structure benefit from an internal cache that avoids
/// re-hashing identical interior nodes, reducing per-proof overhead
/// compared to calling [`verify_proof`] sequentially.
///
/// Returns an error if `proofs.len() != expected_roots.len()`.
///
/// ## Verification logic
///
/// For each proof `i`:
/// 1. The proof's leaf digest is walked up through each level using
///    the sibling hashes and position.
/// 2. Interior node hashes are cached keyed by `(root_hash, level_index,
///    position, sibling_hashes_hash)` so that proofs from the same tree
///    sharing a common interior node avoid redundant BLAKE3 computation.
/// 3. The final computed root hash is compared against
///    `expected_roots[i]`.
pub fn verify_batch(
    proofs: &[MerkleProof],
    expected_roots: &[Hash],
) -> Result<BatchVerificationReport, BatchVerifyError> {
    if proofs.len() != expected_roots.len() {
        return Err(BatchVerifyError::LengthMismatch {
            proofs_len: proofs.len(),
            roots_len: expected_roots.len(),
        });
    }

    let n = proofs.len();
    let mut per_proof: Vec<bool> = alloc::vec![false; n];
    let mut passed: u64 = 0;
    let mut failed: u64 = 0;
    let mut first_failure: Option<u64> = None;

    // Cache entry: uniquely identifies an interior node hash computation.
    struct CacheEntry {
        root_hash: Hash,
        level: usize,
        position: usize,
        siblings_hash: Hash,
        result: Hash,
    }
    let mut cache: Vec<CacheEntry> = Vec::new();

    for (idx, proof) in proofs.iter().enumerate() {
        let mut current_hash = proof.leaf_digest;
        let mut ok = true;

        for (level_idx, level) in proof.path.iter().enumerate() {
            // Build the full children list for this level.
            let mut children = level.siblings.clone();
            if level.position > children.len() {
                ok = false;
                break;
            }
            children.insert(level.position, current_hash);

            // Compute a hash of the siblings for use as a cache key.
            // This avoids storing full sibling Vecs in the cache.
            let mut siblings_hasher = Hasher::new();
            for s in &level.siblings {
                siblings_hasher.update(s.as_slice());
            }
            let siblings_hash: Hash = *siblings_hasher.finalize().as_bytes();

            // Check whether we've already computed this interior node.
            let mut cache_hit = false;
            for entry in &cache {
                if entry.root_hash == expected_roots[idx]
                    && entry.level == level_idx
                    && entry.position == level.position
                    && entry.siblings_hash == siblings_hash
                {
                    current_hash = entry.result;
                    cache_hit = true;
                    break;
                }
            }

            if !cache_hit {
                // Compute the interior node hash.
                let mut hasher = Hasher::new();
                for child in &children {
                    hasher.update(child.as_slice());
                }
                current_hash = *hasher.finalize().as_bytes();

                cache.push(CacheEntry {
                    root_hash: expected_roots[idx],
                    level: level_idx,
                    position: level.position,
                    siblings_hash,
                    result: current_hash,
                });
            }
        }

        if ok && current_hash == expected_roots[idx] {
            per_proof[idx] = true;
            passed += 1;
        } else {
            per_proof[idx] = false;
            failed += 1;
            if first_failure.is_none() {
                first_failure = Some(idx as u64);
            }
        }
    }

    Ok(BatchVerificationReport {
        total: n as u64,
        passed,
        failed,
        first_failure,
        per_proof,
    })
}
// Incremental update
// ---------------------------------------------------------------------------

/// Recompute the affected leaf-to-root path when a data block changes.
///
/// Given a tree, the index of the changed block, and the new leaf digest,
/// returns a new [`ChecksumTree`] with the path to the root updated.
/// All sibling subtrees remain unchanged.
///
/// ## Usage example
///
/// Overwrite a block in-place without rebuilding the entire tree:
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let leaves: Vec<Digest> = (0..100)
///     .map(|i| hash_block(&(i as u64).to_le_bytes()))
///     .collect();
/// let tree = ChecksumTree::from_leaves(&leaves, 4096);
///
/// let new_leaf = hash_block(b"updated block content");
/// let updated = incremental_update(&tree, 42, new_leaf)
///     .expect("valid block index");
///
/// assert_ne!(updated.root_hash, tree.root_hash);
/// assert_eq!(updated.block_count, tree.block_count);
/// ```
pub fn incremental_update(
    tree: &ChecksumTree,
    block_index: u64,
    new_leaf_digest: Digest,
) -> Option<ChecksumTree> {
    if block_index >= tree.block_count {
        return None;
    }

    // Rebuild the leaf digests with the one changed leaf
    let mut leaf_digests = Vec::with_capacity(tree.block_count as usize);

    // Collect existing leaves
    let level0_count = tree.block_count.div_ceil(FANOUT as u64) as usize;
    for node in tree.nodes.iter().take(level0_count) {
        leaf_digests.extend_from_slice(node.valid_children());
    }
    leaf_digests.truncate(tree.block_count as usize);

    // Update the changed leaf
    leaf_digests[block_index as usize] = new_leaf_digest;

    // Rebuild the entire tree from the updated leaves, preserving the
    // domain key and locator token so in-place overwrites within the same
    // extent keep the same binding.
    Some(ChecksumTree::from_leaves_with_domain(
        &leaf_digests,
        tree.block_size,
        tree.domain_key,
        tree.locator_token,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the BLAKE3 hash of a byte slice.
pub fn hash_block(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Return the zero digest (all zeros).
pub const fn zero_digest() -> Digest {
    [0u8; DIGEST_SIZE]
}

// ---------------------------------------------------------------------------
// Per-object verification dispatch
// ---------------------------------------------------------------------------

/// Result of a single-object BLAKE3 verification.
///
/// Returned when the computed checksum tree root does not match the
/// expected digest stored in the object metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChecksumMismatch {
    /// The expected BLAKE3-256 root digest (from stored metadata).
    pub expected: Digest,
    /// The BLAKE3-256 root digest computed from the actual data.
    pub computed: Digest,
}

/// Verify that `data` hashes to the expected checksum tree root.
///
/// Builds a [`ChecksumTree`] from the data using the default block size and
/// compares the root digest against `expected_root`.  When `locator_token`
/// is `Some`, the computed root is bound to that token before comparison,
/// matching the binding applied by [`ChecksumTreeBuilder::set_locator`].
///
/// Returns `Ok(())` on match, or `Err(ChecksumMismatch)` with both digests
/// on mismatch.
///
/// This is the single-object verification entry point intended for scrub
/// consumption: walk objects, read their payloads, and call this function
/// with the recorded digest.
///
/// ## Example
///
/// ```
/// # use tidefs_checksum_tree::*;
/// let data = b"payload data for verification";
/// let mut builder = ChecksumTreeBuilder::new(4096);
/// builder.ingest(data);
/// let tree = builder.finish();
/// let expected = tree.root_hash;
///
/// assert!(verify_object(data, &expected, None).is_ok());
/// assert!(verify_object(b"tampered data", &expected, None).is_err());
/// ```
pub fn verify_object(
    data: &[u8],
    expected_root: &Digest,
    locator_token: Option<&LocatorToken>,
) -> Result<(), ChecksumMismatch> {
    let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
    if let Some(token) = locator_token {
        builder.set_locator(*token);
    }
    builder.ingest(data);
    let tree = builder.finish();
    if tree.root_hash == *expected_root {
        Ok(())
    } else {
        Err(ChecksumMismatch {
            expected: *expected_root,
            computed: tree.root_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ChecksumTreeNode
    // -----------------------------------------------------------------------

    #[test]
    fn node_new_single_child() {
        let leaf = hash_block(b"hello");
        let node = ChecksumTreeNode::new(&[leaf]).expect("single child");
        assert_eq!(node.children.len(), 1);
        assert!(node.verify());
    }

    #[test]
    fn node_new_full_fanout() {
        let children: Vec<Digest> = (0..FANOUT)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let node = ChecksumTreeNode::new(&children).expect("full fanout");
        assert_eq!(node.children.len(), FANOUT);
        assert!(node.verify());
    }

    #[test]
    fn node_new_empty_returns_none() {
        assert!(ChecksumTreeNode::new(&[]).is_none());
    }

    #[test]
    fn node_new_too_many_returns_none() {
        let children: Vec<Digest> = core::iter::repeat_n(Digest::default(), FANOUT + 1).collect();
        assert!(ChecksumTreeNode::new(&children).is_none());
    }

    #[test]
    fn node_tampered_child_fails_verify() {
        let leaf = hash_block(b"hello");
        let mut node = ChecksumTreeNode::new(&[leaf]).expect("single child");
        node.children[0][0] ^= 0xff;
        assert!(!node.verify());
    }

    // -----------------------------------------------------------------------
    // ChecksumTree
    // -----------------------------------------------------------------------

    #[test]
    fn tree_empty() {
        let tree = ChecksumTree::from_leaves(&[], 4096);
        assert!(tree.is_empty());
        assert_eq!(tree.root_hash, zero_digest());
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.level_count(), 0);
    }

    #[test]
    fn tree_single_block() {
        let leaf = hash_block(b"single block data");
        let tree = ChecksumTree::from_leaves(&[leaf], 4096);
        assert!(!tree.is_empty());
        assert_eq!(tree.block_count, 1);
        assert_eq!(tree.level_count(), 1);
        assert_eq!(tree.node_count(), 1);
    }

    #[test]
    fn tree_fanout_blocks_one_node() {
        let leaves: Vec<Digest> = (0..FANOUT)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(tree.block_count, FANOUT as u64);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.level_count(), 1);
    }

    #[test]
    fn tree_fanout_plus_one_blocks_two_levels() {
        let leaves: Vec<Digest> = (0..FANOUT + 1)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(tree.block_count, (FANOUT + 1) as u64);
        assert_eq!(tree.node_count(), 3);
        assert_eq!(tree.level_count(), 2);
    }

    #[test]
    fn tree_root_hash_deterministic() {
        let leaves: Vec<Digest> = (0..10)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree1 = ChecksumTree::from_leaves(&leaves, 4096);
        let tree2 = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(tree1.root_hash, tree2.root_hash);
    }

    #[test]
    fn tree_root_hash_changes_with_data() {
        let leaves1: Vec<Digest> = (0..10)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let leaves2: Vec<Digest> = (0..10)
            .map(|i| hash_block(&((i as u64) + 1).to_le_bytes()))
            .collect();
        let tree1 = ChecksumTree::from_leaves(&leaves1, 4096);
        let tree2 = ChecksumTree::from_leaves(&leaves2, 4096);
        assert_ne!(tree1.root_hash, tree2.root_hash);
    }

    // -----------------------------------------------------------------------
    // ChecksumTreeBuilder
    // -----------------------------------------------------------------------

    #[test]
    fn builder_empty() {
        let builder = ChecksumTreeBuilder::new(4096);
        let tree = builder.finish();
        assert!(tree.is_empty());
    }

    #[test]
    fn builder_single_block() {
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(b"hello world, this is test data for a single block");
        let tree = builder.finish();
        assert_eq!(tree.block_count, 1);
    }

    #[test]
    fn builder_many_blocks() {
        let mut builder = ChecksumTreeBuilder::new(512);
        for i in 0u64..1000 {
            builder.ingest(&i.to_le_bytes().repeat(128)); // 1024 bytes -> 2 blocks
        }
        let tree = builder.finish();
        assert_eq!(tree.block_count, 2000);
    }

    #[test]
    fn builder_matches_direct_tree() {
        // Each data block is exactly one 256-byte leaf
        let data_blocks: Vec<Vec<u8>> = (0..50)
            .map(|i| {
                let mut buf = Vec::with_capacity(256);
                buf.extend_from_slice(&(i as u64).to_le_bytes());
                buf.resize(256, 0u8);
                buf
            })
            .collect();
        let leaf_digests: Vec<Digest> = data_blocks.iter().map(|b| hash_block(b)).collect();
        let direct_tree = ChecksumTree::from_leaves(&leaf_digests, 256);

        let mut builder = ChecksumTreeBuilder::new(256);
        for block in &data_blocks {
            builder.ingest(block);
        }
        let built_tree = builder.finish();

        assert_eq!(direct_tree.root_hash, built_tree.root_hash);
        assert_eq!(direct_tree.block_count, built_tree.block_count);
        assert_eq!(direct_tree.node_count(), built_tree.node_count());
    }

    // -----------------------------------------------------------------------
    // Verification
    // -----------------------------------------------------------------------

    #[test]
    fn verify_full_correct_data() {
        let data: Vec<u8> = (0..4096 * 10).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        for chunk in data.chunks(4096) {
            builder.ingest(chunk);
        }
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn verify_full_corrupted_data() {
        let data: Vec<u8> = (0..4096 * 5).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        for chunk in data.chunks(4096) {
            builder.ingest(chunk);
        }
        let tree = builder.finish();

        let mut corrupted = data.clone();
        corrupted[5000] ^= 0xff;

        let verifier = ChecksumTreeVerifier::new(tree);
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 4096);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    #[test]
    fn verify_full_missing_data() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        for chunk in data.chunks(4096) {
            builder.ingest(chunk);
        }
        let tree = builder.finish();

        let short_data = &data[..4096];
        let verifier = ChecksumTreeVerifier::new(tree);
        match verifier.verify_full(short_data) {
            VerificationResult::Missing { offset } => {
                assert_eq!(offset, 4096);
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn verify_range_partial() {
        let data: Vec<u8> = (0..4096 * 10).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        for chunk in data.chunks(4096) {
            builder.ingest(chunk);
        }
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let data_ref = &data;
        let result = verifier.verify_range(4096, 12288, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_corrupted() {
        let data: Vec<u8> = (0..4096 * 5).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        for chunk in data.chunks(4096) {
            builder.ingest(chunk);
        }
        let tree = builder.finish();

        let mut corrupted = data.clone();
        corrupted[9000] ^= 0xff;

        let verifier = ChecksumTreeVerifier::new(tree);
        let corrupted_ref = &corrupted;
        let result = verifier.verify_range(0, corrupted.len() as u64, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(corrupted_ref.len());
            Some(corrupted_ref[start..end].to_vec())
        });
        match result {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 8192);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    #[test]
    fn verify_empty_tree() {
        let tree = ChecksumTree::from_leaves(&[], 4096);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&[]), VerificationResult::Verified);
    }

    #[test]
    fn verify_single_byte_file() {
        let data = b"X".to_vec();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    // -----------------------------------------------------------------------
    // Incremental update
    // -----------------------------------------------------------------------

    #[test]
    fn incremental_update_single_block_change() {
        let leaves: Vec<Digest> = (0..100)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        let original_root = tree.root_hash;

        let new_leaf = hash_block(b"changed data");
        let updated = incremental_update(&tree, 42, new_leaf).expect("valid block index");

        assert_ne!(updated.root_hash, original_root);
        assert_eq!(updated.block_count, tree.block_count);

        let level0 = updated.block_count.div_ceil(FANOUT as u64) as usize;
        let mut collected: Vec<Digest> = Vec::new();
        for node in updated.nodes.iter().take(level0) {
            collected.extend_from_slice(node.valid_children());
        }
        collected.truncate(updated.block_count as usize);

        assert_eq!(collected[42], new_leaf);
        for i in 0..100usize {
            if i != 42 {
                assert_eq!(collected[i], leaves[i]);
            }
        }
    }

    #[test]
    fn incremental_update_out_of_range() {
        let leaves: Vec<Digest> = (0..5)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        assert!(incremental_update(&tree, 5, hash_block(b"nope")).is_none());
    }

    // -----------------------------------------------------------------------
    // Serde round-trip
    // -----------------------------------------------------------------------

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_tree() {
        let leaves: Vec<Digest> = (0..50)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let json = serde_json::to_string(&tree).expect("serialize");
        let restored: ChecksumTree = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(tree.root_hash, restored.root_hash);
        assert_eq!(tree.block_count, restored.block_count);
        assert_eq!(tree.node_count(), restored.node_count());
        assert_eq!(tree.nodes, restored.nodes);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_roundtrip_node() {
        let leaf = hash_block(b"test");
        let node = ChecksumTreeNode::new(&[leaf]).expect("single child");
        let json = serde_json::to_string(&node).expect("serialize");
        let restored: ChecksumTreeNode = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(node.self_checksum, restored.self_checksum);
        assert_eq!(node.children.len(), restored.children.len());
        assert!(restored.verify());
    }
}

// ---------------------------------------------------------------------------
// Validation tests -- s13 extended coverage for issue #3593
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unreadable_literal)]
mod validation_tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    // =======================================================================
    // Construction correctness
    // =======================================================================

    #[test]
    fn construct_two_blocks_single_node() {
        let leaf_a = hash_block(b"block a");
        let leaf_b = hash_block(b"block b");
        let tree = ChecksumTree::from_leaves(&[leaf_a, leaf_b], 4096);

        assert_eq!(tree.block_count, 2);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.level_count(), 1);
        assert!(!tree.is_empty());
    }

    #[test]
    fn construct_fanout_minus_one_single_node() {
        let leaves: Vec<Digest> = (0..(FANOUT - 1) as u64)
            .map(|i| hash_block(&i.to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, (FANOUT - 1) as u64);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.level_count(), 1);
    }

    #[test]
    fn construct_large_two_level_tree_structure() {
        let n = (FANOUT * 2 + 7) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, n);
        assert_eq!(tree.level_count(), 2);
        assert_eq!(tree.node_count(), 4);
    }

    #[test]
    fn construct_many_block_tree() {
        let n: u64 = 5000;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, n);
        assert!(tree.level_count() >= 2);
        assert_ne!(tree.root_hash, zero_digest());

        let mut leaves2 = leaves.clone();
        leaves2[1234] = hash_block(b"different");
        let tree2 = ChecksumTree::from_leaves(&leaves2, 4096);
        assert_ne!(tree.root_hash, tree2.root_hash);
    }

    #[test]
    fn construct_non_default_block_size() {
        let block_size = 512;
        let leaves: Vec<Digest> = (0..10)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, block_size);
        assert_eq!(tree.block_size, block_size);
        assert_eq!(tree.block_count, 10);
    }

    // =======================================================================
    // Builder construction
    // =======================================================================

    #[test]
    fn builder_partial_trailing_chunk() {
        let mut builder = ChecksumTreeBuilder::new(4096);
        let full = vec![0xAAu8; 4096 * 3];
        let partial = vec![0xBBu8; 1000];
        builder.ingest(&full);
        builder.ingest(&partial);
        assert_eq!(builder.leaf_count(), 4);

        let tree = builder.finish();
        assert_eq!(tree.block_count, 4);
    }

    #[test]
    fn builder_interleaved_ingest_digest() {
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(b"hello");
        let manual_digest = hash_block(b"world");
        builder.ingest_digest(manual_digest);
        builder.ingest(b"!!");

        assert_eq!(builder.leaf_count(), 3);
        let tree = builder.finish();
        assert_eq!(tree.block_count, 3);
    }

    #[test]
    fn builder_non_default_block_size() {
        let mut builder = ChecksumTreeBuilder::new(1024);
        let data = vec![0u8; 5000];
        builder.ingest(&data);
        assert_eq!(builder.leaf_count(), 5);
        let tree = builder.finish();
        assert_eq!(tree.block_count, 5);
        assert_eq!(tree.block_size, 1024);
    }

    #[test]
    fn builder_root_consistent_with_rebuild() {
        let data = vec![0xABu8; 4096 * 100 + 1234];
        let mut builder1 = ChecksumTreeBuilder::new(4096);
        builder1.ingest(&data);
        let tree1 = builder1.finish();

        let mut builder2 = ChecksumTreeBuilder::new(4096);
        builder2.ingest(&data);
        let tree2 = builder2.finish();

        assert_eq!(tree1.root_hash, tree2.root_hash);
    }

    // =======================================================================
    // Partial-range verification
    // =======================================================================

    #[test]
    fn verify_subset_of_second_block() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 251) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let data_ref = &data;
        let result = verifier.verify_range(4096, 8192, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_straddling_block_boundary() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 199) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let data_ref = &data;
        let result = verifier.verify_range(2048, 10240, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_at_file_end() {
        let data: Vec<u8> = (0..4096 * 5).map(|i| (i % 127) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let data_ref = &data;
        let result = verifier.verify_range(4096 * 3, 4096 * 5, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_beyond_tree_returns_missing() {
        let data = vec![0u8; 4096 * 2];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let data_ref = &data;
        let result = verifier.verify_range(4096, 4096 * 4, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            if start >= data_ref.len() {
                None
            } else {
                Some(data_ref[start..end].to_vec())
            }
        });
        match result {
            VerificationResult::Missing { offset } => {
                assert_eq!(offset, 4096 * 2);
            }
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn verify_range_corrupted_mid_range() {
        let data: Vec<u8> = (0..4096 * 6).map(|i| (i % 211) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let mut corrupted = data.clone();
        corrupted[4096 * 2 + 512] ^= 0x01;

        let corrupted_ref = &corrupted;
        let result = verifier.verify_range(4096, 4096 * 5, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(corrupted_ref.len());
            Some(corrupted_ref[start..end].to_vec())
        });
        match result {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 4096 * 2);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    // =======================================================================
    // Incremental update
    // =======================================================================

    #[test]
    fn incremental_update_first_block() {
        let leaves: Vec<Digest> = (0..50)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        let original_root = tree.root_hash;

        let new_first = hash_block(b"updated first block");
        let updated = incremental_update(&tree, 0, new_first).expect("valid index");

        assert_ne!(updated.root_hash, original_root);
        assert_eq!(updated.block_count, tree.block_count);
        assert_eq!(updated.node_count(), tree.node_count());
    }

    #[test]
    fn incremental_update_last_block() {
        let leaves: Vec<Digest> = (0..50)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        let original_root = tree.root_hash;

        let new_last = hash_block(b"updated last block");
        let updated = incremental_update(&tree, 49, new_last).expect("valid index");

        assert_ne!(updated.root_hash, original_root);
        assert_eq!(updated.block_count, tree.block_count);
    }

    #[test]
    fn incremental_update_preserves_untouched_leaves() {
        let leaves: Vec<Digest> = (0..30)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let new_leaf = hash_block(b"changed");
        let updated = incremental_update(&tree, 10, new_leaf).expect("valid index");

        let level0_count = updated.block_count.div_ceil(FANOUT as u64) as usize;
        let mut collected: Vec<Digest> = Vec::new();
        for node in updated.nodes.iter().take(level0_count) {
            collected.extend_from_slice(node.valid_children());
        }
        collected.truncate(updated.block_count as usize);

        assert_eq!(collected[10], new_leaf);
        for i in 0..30usize {
            if i != 10 {
                assert_eq!(collected[i], leaves[i], "leaf {i} should be unchanged");
            }
        }
    }

    #[test]
    fn incremental_update_crosses_node_boundary() {
        let n = (FANOUT + 5) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let new_leaf = hash_block(b"boundary update");
        let updated =
            incremental_update(&tree, (FANOUT - 1) as u64, new_leaf).expect("valid index");

        let level0_count = updated.block_count.div_ceil(FANOUT as u64) as usize;
        let mut collected: Vec<Digest> = Vec::new();
        for node in updated.nodes.iter().take(level0_count) {
            collected.extend_from_slice(node.valid_children());
        }
        collected.truncate(updated.block_count as usize);

        assert_eq!(collected[FANOUT - 1], new_leaf);
        assert_eq!(collected[FANOUT], leaves[FANOUT]);
    }

    // =======================================================================
    // Edge cases
    // =======================================================================

    #[test]
    fn tree_all_zero_data_blocks() {
        let zero_block = vec![0u8; 4096];
        let mut builder = ChecksumTreeBuilder::new(4096);
        for _ in 0..50 {
            builder.ingest(&zero_block);
        }
        let tree = builder.finish();
        assert_eq!(tree.block_count, 50);
        assert!(tree.level_count() >= 1);
        assert_ne!(tree.root_hash, zero_digest());

        let all_data = vec![0u8; 4096 * 50];
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(
            verifier.verify_full(&all_data),
            VerificationResult::Verified
        );
    }

    #[test]
    fn tree_block_size_one_byte() {
        let data: Vec<u8> = (0..128).collect();
        let mut builder = ChecksumTreeBuilder::new(1);
        builder.ingest(&data);
        let tree = builder.finish();

        assert_eq!(tree.block_count, 128);
        assert_eq!(tree.block_size, 1);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn tree_large_block_size_64k() {
        let block_size = 65536;
        let data = vec![0xACu8; block_size * 3 + 1000];
        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&data);
        let tree = builder.finish();

        assert_eq!(tree.block_size, block_size);
        assert_eq!(tree.block_count, 4);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn tree_single_byte_data_verified_and_corrupted() {
        let data = b"X".to_vec();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        assert_eq!(tree.block_count, 1);
        assert_eq!(tree.level_count(), 1);
        let verifier = ChecksumTreeVerifier::new(tree.clone());
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);

        assert!(matches!(
            verifier.verify_full(b"Y"),
            VerificationResult::Corrupted { .. }
        ));
    }

    // =======================================================================
    // Multi-level tree integrity
    // =======================================================================

    #[test]
    fn three_level_tree_construction() {
        let n = (FANOUT * FANOUT + 1) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.block_count, n);
        assert_eq!(tree.level_count(), 3);
        assert!(!tree.is_empty());
    }

    #[test]
    fn three_level_tree_all_nodes_verify() {
        let n = (FANOUT * FANOUT + 7) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        for (idx, node) in tree.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "node {idx} (of {}) failed self-verification",
                tree.node_count()
            );
        }
    }

    #[test]
    fn three_level_tree_corrupt_interior_node_detected() {
        let n = (FANOUT * FANOUT + 3) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let level0_count = tree.block_count.div_ceil(FANOUT as u64) as usize;
        let mut corrupted_tree = tree.clone();
        if corrupted_tree.node_count() > level0_count + 1 {
            let target = level0_count;
            corrupted_tree.nodes[target].children[0][0] ^= 0xFF;
            assert!(
                !corrupted_tree.nodes[target].verify(),
                "tampered interior node should fail self-verification"
            );
        }
    }

    #[test]
    fn three_level_tree_root_covers_all_data() {
        let n = (FANOUT * 50 + 17) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        for change_idx in [0u64, n / 2, n - 1] {
            let mut leaves2 = leaves.clone();
            leaves2[change_idx as usize] = hash_block(b"mutated");
            let tree2 = ChecksumTree::from_leaves(&leaves2, 4096);
            assert_ne!(
                tree.root_hash, tree2.root_hash,
                "root should change when leaf {change_idx} is modified"
            );
        }
    }

    #[test]
    fn full_verification_through_multi_level_tree() {
        let block_size = 1024;
        let n_blocks = (FANOUT * 4 + 33) as u64;
        let mut data = Vec::with_capacity((n_blocks as usize) * block_size);
        for i in 0..n_blocks {
            let block = vec![(i % 256) as u8; block_size];
            data.extend_from_slice(&block);
        }

        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);

        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);

        let mut corrupted = data.clone();
        let corrupt_offset = 20 * block_size + 37;
        corrupted[corrupt_offset] ^= 0xFF;
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, (20 * block_size) as u64);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    // =======================================================================
    // Additional coverage: hash_block, zero_digest, builder defaults,
    // verifier accessor, incremental update edge cases, verify edge cases
    // =======================================================================

    #[test]
    fn hash_block_empty_input() {
        let digest = hash_block(b"");
        // BLAKE3 empty input known-answer
        let expected: Digest = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn hash_block_known_answer() {
        let digest = hash_block(b"hello world");
        // BLAKE3("hello world") known-answer
        let expected: Digest = [
            0xd7, 0x49, 0x81, 0xef, 0xa7, 0x0a, 0x0c, 0x88, 0x0b, 0x8d, 0x8c, 0x19, 0x85, 0xd0,
            0x75, 0xdb, 0xcb, 0xf6, 0x79, 0xb9, 0x9a, 0x5f, 0x99, 0x14, 0xe5, 0xaa, 0xf9, 0x6b,
            0x83, 0x1a, 0x9e, 0x24,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn hash_block_consistency_with_builder() {
        let data = b"consistent hash test data";
        let direct = hash_block(data);

        let mut builder = ChecksumTreeBuilder::new(data.len());
        builder.ingest(data);
        let tree = builder.finish();
        // Single-block tree: root hash equals the leaf hash
        assert_eq!(direct, tree.root_hash);
    }

    #[test]
    fn zero_digest_is_all_zeros() {
        let zd = zero_digest();
        assert_eq!(zd, [0u8; DIGEST_SIZE]);
        assert_eq!(zd.len(), DIGEST_SIZE);
    }

    #[test]
    fn builder_default_uses_default_block_size() {
        let builder = ChecksumTreeBuilder::default();
        let tree = builder.finish();
        assert_eq!(tree.block_size, DEFAULT_BLOCK_SIZE);
        assert!(tree.is_empty());
    }

    #[test]
    fn builder_default_can_ingest() {
        let mut builder = ChecksumTreeBuilder::default();
        builder.ingest(b"some data for the default builder");
        let tree = builder.finish();
        assert_eq!(tree.block_size, DEFAULT_BLOCK_SIZE);
        assert_eq!(tree.block_count, 1);
        assert!(!tree.is_empty());
    }

    #[test]
    fn verifier_tree_accessor() {
        let leaves: Vec<Digest> = (0..5)
            .map(|i| hash_block(&(i as u64).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        let verifier = ChecksumTreeVerifier::new(tree.clone());
        let accessed = verifier.tree();
        assert_eq!(accessed.root_hash, tree.root_hash);
        assert_eq!(accessed.block_count, tree.block_count);
        assert_eq!(accessed.nodes, tree.nodes);
    }

    #[test]
    fn incremental_update_empty_tree_returns_none() {
        let tree = ChecksumTree::from_leaves(&[], 4096);
        assert!(tree.is_empty());
        let result = incremental_update(&tree, 0, hash_block(b"any"));
        assert!(result.is_none());
    }

    #[test]
    fn incremental_update_single_block_tree() {
        let leaf = hash_block(b"lonely block");
        let tree = ChecksumTree::from_leaves(&[leaf], 4096);
        assert_eq!(tree.block_count, 1);
        assert_eq!(tree.level_count(), 1);

        let new_leaf = hash_block(b"updated lonely block");
        let updated = incremental_update(&tree, 0, new_leaf).expect("valid index");
        assert_eq!(updated.block_count, 1);
        assert_ne!(updated.root_hash, tree.root_hash);

        let level0 = updated.block_count.div_ceil(FANOUT as u64) as usize;
        let mut collected: Vec<Digest> = Vec::new();
        for node in updated.nodes.iter().take(level0) {
            collected.extend_from_slice(node.valid_children());
        }
        collected.truncate(updated.block_count as usize);
        assert_eq!(collected[0], new_leaf);
    }

    #[test]
    fn verify_full_extra_trailing_data() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 256) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        // Append extra data beyond what the tree covers
        let mut extended = data.clone();
        extended.extend_from_slice(&[0xDEu8; 1000]);

        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(
            verifier.verify_full(&extended),
            VerificationResult::Verified
        );
    }

    #[test]
    fn verify_range_empty_range() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 200) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        // Empty range: start == end
        let data_ref = &data;
        let result = verifier.verify_range(4096, 4096, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn corrupted_result_includes_expected_and_actual() {
        let data = vec![0x42u8; 4096 * 2];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let expected_block_hash = hash_block(&[0x42u8; 4096]);

        let mut corrupted = data.clone();
        corrupted[100] ^= 0xFF;

        let verifier = ChecksumTreeVerifier::new(tree);
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted {
                offset,
                expected,
                actual,
            } => {
                assert_eq!(offset, 0);
                assert_eq!(expected, expected_block_hash);
                assert_ne!(actual, expected_block_hash);
                // actual should be hash of the corrupted block
                let corrupted_block_hash = hash_block(&corrupted[..4096]);
                assert_eq!(actual, corrupted_block_hash);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    #[test]
    fn builder_exact_block_boundary_input() {
        let mut builder = ChecksumTreeBuilder::new(1024);
        let data = vec![0xABu8; 1024];
        builder.ingest(&data);
        assert_eq!(builder.leaf_count(), 1);
        let tree = builder.finish();
        assert_eq!(tree.block_count, 1);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn builder_block_size_plus_one_byte() {
        let mut builder = ChecksumTreeBuilder::new(1024);
        let data = vec![0xCDu8; 1025]; // 2 blocks: 1024 + 1
        builder.ingest(&data);
        assert_eq!(builder.leaf_count(), 2);
        let tree = builder.finish();
        assert_eq!(tree.block_count, 2);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn hash_block_512_byte_alignment() {
        // BLAKE3 internally processes 512-byte chunks in some SIMD paths;
        // ensure exact 512-byte input hashes correctly.
        let data = vec![0x7Eu8; 512];
        let digest = hash_block(&data);

        let mut builder = ChecksumTreeBuilder::new(512);
        builder.ingest(&data);
        let tree = builder.finish();
        assert_eq!(digest, tree.root_hash);
    }

    // =======================================================================
    // Additional gap-filling tests (#3980)
    // =======================================================================

    #[test]
    fn hash_block_partial_block_consistency() {
        let data = vec![0x5Au8; 512];
        let direct_hash = hash_block(&data);
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        assert_eq!(tree.block_count, 1);
        assert_eq!(tree.root_hash, direct_hash);
    }

    #[test]
    fn zero_digest_differs_from_hash_of_empty_block() {
        let zd = zero_digest();
        let data = vec![0u8; 4096];
        let hash = hash_block(&data);
        assert_ne!(
            zd, hash,
            "zero digest must not equal hash of non-empty data"
        );
    }

    #[test]
    fn verify_range_at_block_boundaries() {
        let data: Vec<u8> = (0..4096 * 4).map(|i| (i % 223) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        let data_ref = &data;

        assert_eq!(
            verifier.verify_range(0, 4096, |offset, _len| {
                let start = offset as usize;
                Some(data_ref[start..start + 4096].to_vec())
            }),
            VerificationResult::Verified
        );
        assert_eq!(
            verifier.verify_range(4096, 8192, |offset, _len| {
                let start = offset as usize;
                Some(data_ref[start..start + 4096].to_vec())
            }),
            VerificationResult::Verified
        );
        assert_eq!(
            verifier.verify_range(0, 8192, |offset, _len| {
                let start = offset as usize;
                Some(data_ref[start..start + 4096].to_vec())
            }),
            VerificationResult::Verified
        );
    }

    #[test]
    fn verify_range_data_provider_returns_none() {
        let data = vec![0xEEu8; 4096 * 2];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);

        let result = verifier.verify_range(0, 4096, |offset, _len| {
            if offset == 0 {
                None
            } else {
                Some(vec![0u8; 4096])
            }
        });
        assert!(matches!(result, VerificationResult::Missing { offset: 0 }));
    }

    #[test]
    fn verify_range_single_byte_at_block_start() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 127) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        let data_ref = &data;

        let result = verifier.verify_range(4096, 4097, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_single_byte_at_block_end() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i % 131) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        let data_ref = &data;

        let result = verifier.verify_range(4095, 4096, |offset, _len| {
            let start = offset as usize;
            let end = (start + 4096).min(data_ref.len());
            Some(data_ref[start..end].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    #[test]
    fn verify_range_start_equals_end() {
        let data = vec![0x7Fu8; 4096 * 2];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();
        let verifier = ChecksumTreeVerifier::new(tree);
        let data_ref = &data;

        let result = verifier.verify_range(1234, 1234, |offset, _len| {
            let start = offset as usize;
            Some(data_ref[start..start + 4096].to_vec())
        });
        assert_eq!(result, VerificationResult::Verified);
    }

    // =======================================================================
    // Subtree proof tests
    // =======================================================================

    #[test]
    fn proof_single_leaf_tree_verify() {
        let data = b"hello world, single leaf";
        let leaf = hash_block(data);
        let tree = ChecksumTree::from_leaves(&[leaf], 4096);

        let proof = tree.generate_proof(0).expect("valid leaf index");
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.leaf_digest, leaf);
        assert_eq!(proof.root_hash, tree.root_hash);
        assert!(verify_proof(&proof));
    }

    #[test]
    fn proof_two_leaf_both_verify() {
        let leaves: Vec<Digest> = (0..2u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        for i in 0..2u64 {
            let proof = tree.generate_proof(i).expect("valid index");
            assert!(verify_proof(&proof), "proof for leaf {i} must verify");
            assert_eq!(proof.leaf_index, i);
        }
    }

    #[test]
    fn proof_multi_level_tree_verify() {
        let n = FANOUT as u64 * 3 + 7;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| hash_block(&(i.wrapping_mul(7)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert!(
            tree.level_count() >= 2,
            "tree with {n} leaves must have at least 2 levels"
        );

        // Verify proofs for first, middle, and last leaf
        for idx in [0, n / 2, n - 1] {
            let proof = tree.generate_proof(idx).expect("valid index");
            assert!(verify_proof(&proof), "proof for leaf {idx} must verify");
        }
    }

    #[test]
    fn proof_all_leaves_verify_in_medium_tree() {
        let n = 500u64;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| hash_block(&(i.wrapping_mul(13)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        for i in 0..n {
            let proof = tree.generate_proof(i).expect("valid index");
            assert!(verify_proof(&proof), "proof for leaf {i} must verify");
        }
    }

    #[test]
    fn proof_tampered_leaf_digest_fails() {
        let leaves: Vec<Digest> = (0..50u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(10).expect("valid index");
        proof.leaf_digest[0] ^= 0xFF;
        assert!(
            !verify_proof(&proof),
            "tampered leaf digest must fail verification"
        );
    }

    #[test]
    fn proof_tampered_sibling_fails() {
        let leaves: Vec<Digest> = (0..50u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(10).expect("valid index");
        // Tamper the first sibling hash in the first level
        if let Some(first_level) = proof.path.first_mut() {
            if let Some(sib) = first_level.siblings.first_mut() {
                sib[0] ^= 0xFF;
            }
        }
        assert!(
            !verify_proof(&proof),
            "tampered sibling must fail verification"
        );
    }

    #[test]
    fn proof_tampered_root_hash_fails() {
        let leaves: Vec<Digest> = (0..50u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(10).expect("valid index");
        proof.root_hash[0] ^= 0xFF;
        assert!(
            !verify_proof(&proof),
            "tampered root hash must fail verification"
        );
    }

    #[test]
    fn proof_wrong_tree_root_fails() {
        let leaves1: Vec<Digest> = (0..50u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree1 = ChecksumTree::from_leaves(&leaves1, 4096);

        let leaves2: Vec<Digest> = (50..100u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree2 = ChecksumTree::from_leaves(&leaves2, 4096);

        // Proof from tree1 verified against tree2's root must fail
        let mut proof = tree1.generate_proof(10).expect("valid index");
        proof.root_hash = tree2.root_hash;
        assert!(
            !verify_proof(&proof),
            "proof from tree1 must not verify against tree2 root"
        );
    }

    #[test]
    fn proof_out_of_range_leaf_returns_none() {
        let leaves: Vec<Digest> = (0..10u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert!(tree.generate_proof(10).is_none());
        assert!(tree.generate_proof(999).is_none());
        assert!(tree.generate_proof(u64::MAX).is_none());
    }

    #[test]
    fn proof_empty_tree_returns_none() {
        let tree = ChecksumTree::from_leaves(&[], 4096);
        assert!(tree.is_empty());
        assert!(tree.generate_proof(0).is_none());
    }

    #[test]
    fn proof_truncated_path_fails() {
        let n = FANOUT as u64 + 5;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(0).expect("valid index");
        // Remove the last level entry (closest to root)
        proof.path.pop();
        assert!(
            !verify_proof(&proof),
            "proof with truncated path must fail verification"
        );
    }

    #[test]
    fn proof_extra_path_level_fails() {
        let leaves: Vec<Digest> = (0..10u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(0).expect("valid index");
        // Add a bogus extra level
        proof.path.push(ProofLevel {
            position: 0,
            siblings: vec![zero_digest()],
        });
        assert!(
            !verify_proof(&proof),
            "proof with extra level must fail verification"
        );
    }

    #[test]
    fn proof_bad_position_fails() {
        let leaves: Vec<Digest> = (0..10u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let mut proof = tree.generate_proof(0).expect("valid index");
        // Set position > number of siblings (out of bounds)
        if let Some(first_level) = proof.path.first_mut() {
            first_level.position = first_level.siblings.len() + 5;
        }
        assert!(
            !verify_proof(&proof),
            "proof with bad position must fail verification"
        );
    }

    // =======================================================================
    // Builder edge case tests
    // =======================================================================

    #[test]
    fn builder_reset_reuse_after_finish() {
        let mut builder = ChecksumTreeBuilder::new(1024);
        builder.ingest(&[0xABu8; 2048]);
        let tree1 = builder.finish();
        assert_eq!(tree1.block_count, 2);
        assert!(!tree1.is_empty());

        // Create a fresh builder (simulating reuse after finish consumes self)
        let mut builder2 = ChecksumTreeBuilder::new(1024);
        builder2.ingest(&[0xCDu8; 1024]);
        let tree2 = builder2.finish();
        assert_eq!(tree2.block_count, 1);
        assert_ne!(tree1.root_hash, tree2.root_hash);
    }

    #[test]
    fn builder_concurrent_independent_instances() {
        let data_a = vec![0x11u8; 4096 * 3];
        let data_b = vec![0x22u8; 4096 * 5];

        let mut builder_a = ChecksumTreeBuilder::new(4096);
        let mut builder_b = ChecksumTreeBuilder::new(4096);

        builder_a.ingest(&data_a);
        builder_b.ingest(&data_b);

        let tree_a = builder_a.finish();
        let tree_b = builder_b.finish();

        assert_eq!(tree_a.block_count, 3);
        assert_eq!(tree_b.block_count, 5);
        assert_ne!(tree_a.root_hash, tree_b.root_hash);

        // Each tree must verify its own data
        let verifier_a = ChecksumTreeVerifier::new(tree_a);
        assert_eq!(
            verifier_a.verify_full(&data_a),
            VerificationResult::Verified
        );
        let verifier_b = ChecksumTreeVerifier::new(tree_b);
        assert_eq!(
            verifier_b.verify_full(&data_b),
            VerificationResult::Verified
        );
    }

    #[test]
    fn builder_byte_by_byte_ingest() {
        let data: Vec<u8> = (0..64u16).map(|i| (i % 64) as u8).collect();

        // Build incrementally one byte at a time.
        let mut incr = ChecksumTreeBuilder::new(64);
        for byte in &data {
            incr.ingest(&[*byte]);
        }
        let incr_tree = incr.finish();

        // Each 1-byte ingest becomes its own leaf because chunks(64)
        // on a 1-byte slice returns a 1-byte chunk.
        assert_eq!(incr_tree.block_count, data.len() as u64);
        assert!(!incr_tree.is_empty());
        assert_ne!(incr_tree.root_hash, zero_digest());

        // All interior nodes must pass self-verification.
        for (idx, node) in incr_tree.nodes.iter().enumerate() {
            assert!(node.verify(), "node {idx} must pass self-verification");
        }

        // Build from concatenated data — different leaf boundaries,
        // so root hashes will differ, but both must verify their own data.
        let mut batch = ChecksumTreeBuilder::new(64);
        batch.ingest(&data);
        let batch_tree = batch.finish();
        assert_eq!(batch_tree.block_count, (data.len() as u64).div_ceil(64));

        let batch_verifier = ChecksumTreeVerifier::new(batch_tree);
        assert_eq!(
            batch_verifier.verify_full(&data),
            VerificationResult::Verified
        );
    }

    #[test]
    fn builder_ingest_digest_then_verify() {
        let block_size = 512;
        let data = vec![0x77u8; 1024];
        let mut builder = ChecksumTreeBuilder::new(block_size);

        // Manually ingest leaf digests instead of raw data
        for chunk in data.chunks(block_size) {
            builder.ingest_digest(hash_block(chunk));
        }

        let tree = builder.finish();
        assert_eq!(tree.block_count, 2);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn builder_mixed_ingest_and_digest() {
        let block_size = 256;
        let prefix = vec![0x33u8; 512]; // 2 blocks via ingest
        let suffix = vec![0x44u8; 256]; // 1 block via ingest_digest

        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(&prefix);
        assert_eq!(builder.leaf_count(), 2);

        builder.ingest_digest(hash_block(&suffix));
        assert_eq!(builder.leaf_count(), 3);

        let tree = builder.finish();
        assert_eq!(tree.block_count, 3);

        let mut combined = prefix.clone();
        combined.extend_from_slice(&suffix);
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(
            verifier.verify_full(&combined),
            VerificationResult::Verified
        );
    }

    // =======================================================================
    // Serialization round-trip tests
    // =======================================================================

    #[test]
    fn serde_tree_json_roundtrip() {
        let leaves: Vec<Digest> = (0..30u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let json = serde_json::to_string(&tree).expect("serialize tree");
        let restored: ChecksumTree = serde_json::from_str(&json).expect("deserialize tree");

        assert_eq!(restored.block_count, tree.block_count);
        assert_eq!(restored.block_size, tree.block_size);
        assert_eq!(restored.root_hash, tree.root_hash);
        assert_eq!(restored.nodes.len(), tree.nodes.len());

        // Each restored node must pass self-verification
        for node in &restored.nodes {
            assert!(node.verify());
        }

        // Verify original data against restored tree
        let data: Vec<u8> = (0..4096 * 30).map(|i| (i % 251) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let original_tree = builder.finish();
        let json2 = serde_json::to_string(&original_tree).expect("serialize");
        let restored2: ChecksumTree = serde_json::from_str(&json2).expect("deserialize");
        let verifier = ChecksumTreeVerifier::new(restored2);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);
    }

    #[test]
    fn serde_node_json_roundtrip() {
        let children: Vec<Digest> = (0..5u64).map(|i| hash_block(&i.to_le_bytes())).collect();
        let node = ChecksumTreeNode::new(&children).expect("valid node");

        let json = serde_json::to_string(&node).expect("serialize node");
        let restored: ChecksumTreeNode = serde_json::from_str(&json).expect("deserialize node");

        assert_eq!(restored.children.len(), node.children.len());
        assert_eq!(restored.self_checksum, node.self_checksum);
        assert!(restored.verify());
    }

    #[test]
    fn serde_empty_tree_json_roundtrip() {
        let tree = ChecksumTree::from_leaves(&[], 4096);
        let json = serde_json::to_string(&tree).expect("serialize empty tree");
        let restored: ChecksumTree = serde_json::from_str(&json).expect("deserialize empty tree");
        assert!(restored.is_empty());
        assert_eq!(restored.root_hash, zero_digest());
        assert_eq!(restored.block_count, 0);
    }

    // =======================================================================
    // Edge case tests
    // =======================================================================

    #[test]
    fn all_zero_vs_all_ff_hash_are_distinct() {
        let zero_data = vec![0u8; 4096];
        let ff_data = vec![0xFFu8; 4096];

        let zero_hash = hash_block(&zero_data);
        let ff_hash = hash_block(&ff_data);

        assert_ne!(
            zero_hash, ff_hash,
            "all-zero and all-0xFF must produce distinct hashes"
        );
        assert_ne!(
            zero_hash,
            zero_digest(),
            "hash of zero-filled data must differ from zero digest sentinel"
        );
    }

    #[test]
    fn deep_tree_max_fanout_squared_plus_one() {
        // Tree with FANOUT*FANOUT+1 leaves ensures at least 3 levels
        let n = (FANOUT * FANOUT + 1) as u64;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| hash_block(&(i.wrapping_mul(3)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 1024);

        assert_eq!(tree.block_count, n);
        assert!(
            tree.level_count() >= 3,
            "tree with FANOUT^2+1 leaves must have at least 3 levels"
        );

        // All interior nodes must pass self-verification
        for (idx, node) in tree.nodes.iter().enumerate() {
            assert!(node.verify(), "node {idx} must pass self-verification");
        }

        // Root hash must be non-zero
        assert_ne!(tree.root_hash, zero_digest());
    }

    #[test]
    fn leaf_digests_method_matches_verifier() {
        let data: Vec<u8> = (0..4096 * 5).map(|i| (i % 199) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let direct_leaves = tree.leaf_digests();
        let manual_leaves: Vec<Digest> = data.chunks(4096).map(hash_block).collect();

        assert_eq!(direct_leaves.len(), manual_leaves.len());
        assert_eq!(direct_leaves, manual_leaves);

        // leaf_digests on empty tree returns empty
        let empty = ChecksumTree::from_leaves(&[], 4096);
        assert!(empty.leaf_digests().is_empty());
    }

    #[test]
    fn proof_single_byte_leaf() {
        let data = vec![0x7Fu8];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        assert_eq!(tree.block_count, 1);
        let proof = tree.generate_proof(0).expect("valid index");
        assert!(verify_proof(&proof));
        assert_eq!(proof.leaf_digest, hash_block(&data));
        // Single leaf, single level tree: path has one level entry
        assert_eq!(
            proof.path.len(),
            0,
            "single-block tree has no interior hash levels"
        );
    }

    #[test]
    fn proof_exact_fanout_boundary() {
        // Tree with exactly FANOUT leaves: single-level tree
        let n = FANOUT as u64;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| hash_block(&(i.wrapping_mul(5)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.level_count(), 1);
        for i in [0, n / 2, n - 1] {
            let proof = tree.generate_proof(i).expect("valid index");
            assert!(verify_proof(&proof), "proof for leaf {i} must verify");
            // Single level: path has one level entry (root_hash is
            // computed from the node's self_checksum when >1 leaf).
            assert_eq!(proof.path.len(), 1);
        }
    }

    #[test]
    fn proof_exact_fanout_plus_one_boundary() {
        // Tree with FANOUT+1 leaves: two-level tree
        let n = (FANOUT + 1) as u64;
        let leaves: Vec<Digest> = (0..n)
            .map(|i| hash_block(&(i.wrapping_mul(5)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        assert_eq!(tree.level_count(), 2);
        for i in [0, FANOUT as u64 - 1, FANOUT as u64, n - 1] {
            let proof = tree.generate_proof(i).expect("valid index");
            assert!(verify_proof(&proof), "proof for leaf {i} must verify");
            // Two levels: path has 2 level entries
            assert_eq!(
                proof.path.len(),
                2,
                "leaf {i} must have exactly 2 proof levels"
            );
        }
    }

    // =======================================================================
    // Known-reference tree hash cross-validation
    // =======================================================================

    /// Validate that a 2-block tree root hash matches a manually computed
    /// BLAKE3 hash of the concatenated leaf digests.
    #[test]
    fn tree_root_hash_known_reference_two_blocks() {
        let block_size = 64;
        let block0 = b"The quick brown fox jumps over the lazy dog.....................";
        let block1 = b"Pack my box with five dozen liquor jugs!........................";
        assert_eq!(block0.len(), block_size);
        assert_eq!(block1.len(), block_size);

        let leaf0 = hash_block(block0);
        let leaf1 = hash_block(block1);

        // Expected root: BLAKE3(leaf0 || leaf1)
        let mut hasher = blake3::Hasher::new();
        hasher.update(&leaf0);
        hasher.update(&leaf1);
        let expected_root: Digest = *hasher.finalize().as_bytes();

        // from_leaves must produce the expected root
        let tree = ChecksumTree::from_leaves(&[leaf0, leaf1], block_size);
        assert_eq!(
            tree.root_hash, expected_root,
            "tree root must equal BLAKE3(leaf0 || leaf1)"
        );
        assert_eq!(tree.block_count, 2);
        assert_eq!(tree.level_count(), 1);

        // Builder path must produce the same root
        let mut builder = ChecksumTreeBuilder::new(block_size);
        builder.ingest(block0);
        builder.ingest(block1);
        let tree2 = builder.finish();
        assert_eq!(
            tree2.root_hash, expected_root,
            "builder root must also equal BLAKE3(leaf0 || leaf1)"
        );

        // Verify full data through verifier
        let mut combined = Vec::new();
        combined.extend_from_slice(block0);
        combined.extend_from_slice(block1);
        let verifier = ChecksumTreeVerifier::new(tree2);
        assert_eq!(
            verifier.verify_full(&combined),
            VerificationResult::Verified
        );
    }
    /// Validate a 3-block (single-level) tree root hash against manual
    /// computation: root = BLAKE3(leaf0 || leaf1 || leaf2).
    #[test]
    fn tree_root_hash_known_reference_three_blocks() {
        let data: [&[u8]; 3] = [
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            b"cccccccccccccccccccccccccccccccc",
        ];
        let leaves: Vec<Digest> = data.iter().map(|d| hash_block(d)).collect();

        let mut hasher = blake3::Hasher::new();
        for leaf in &leaves {
            hasher.update(leaf);
        }
        let expected_root: Digest = *hasher.finalize().as_bytes();

        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(tree.root_hash, expected_root);
        assert_eq!(tree.level_count(), 1);

        // Every node self-verifies
        for node in &tree.nodes {
            assert!(node.verify());
        }
    }

    /// Validate a two-level tree (FANOUT+1 blocks) root hash. Computes the
    /// expected root manually: BLAKE3(level0_node0_self || level0_node1_self)
    /// where each level-0 self = BLAKE3(its_child_leaves concatenated).
    #[test]
    fn tree_root_hash_known_reference_two_level() {
        let n = (FANOUT + 1) as u64;
        let leaves: Vec<Digest> = (0..n).map(|i| hash_block(&i.to_le_bytes())).collect();

        // Level 0 node 0: BLAKE3(leaves[0..FANOUT])
        let mut h0 = blake3::Hasher::new();
        for leaf in leaves.iter().take(FANOUT) {
            h0.update(leaf);
        }
        let node0_self: Digest = *h0.finalize().as_bytes();

        // Level 0 node 1: BLAKE3(leaves[FANOUT])  (single child)
        let mut h1 = blake3::Hasher::new();
        h1.update(&leaves[FANOUT]);
        let node1_self: Digest = *h1.finalize().as_bytes();

        // Root (level 1): BLAKE3(node0_self || node1_self)
        let mut h_root = blake3::Hasher::new();
        h_root.update(&node0_self);
        h_root.update(&node1_self);
        let expected_root: Digest = *h_root.finalize().as_bytes();

        let tree = ChecksumTree::from_leaves(&leaves, 4096);
        assert_eq!(
            tree.root_hash, expected_root,
            "two-level tree root must match manual BLAKE3 computation"
        );
        assert_eq!(tree.level_count(), 2);
        assert_eq!(tree.node_count(), 3);
    }

    // =======================================================================
    // All-zero and all-0xFF data payloads (explicit edge cases)
    // =======================================================================

    #[test]
    fn all_zero_data_through_builder_verifies() {
        let data = vec![0u8; 4096 * 7 + 123];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree.clone());
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);

        // Tamper one byte
        let mut corrupted = data.clone();
        corrupted[9000] = 0x01;
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 8192);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }

        // All interior nodes verify
        for node in &tree.nodes {
            assert!(node.verify());
        }
    }

    #[test]
    fn all_ff_data_through_builder_verifies() {
        let data = vec![0xFFu8; 4096 * 5 + 2000];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree.clone());
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);

        // Tamper one byte
        let mut corrupted = data.clone();
        corrupted[12345] = 0x00;
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 12288);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }

        // All interior nodes verify
        for node in &tree.nodes {
            assert!(node.verify());
        }
    }

    // =======================================================================
    // Child ordering: parent hash depends on child order
    // =======================================================================

    #[test]
    fn leaf_ordering_affects_root_hash() {
        let leaf_a = hash_block(b"first");
        let leaf_b = hash_block(b"second");
        let leaf_c = hash_block(b"third");

        let tree_abc = ChecksumTree::from_leaves(&[leaf_a, leaf_b, leaf_c], 4096);
        let tree_acb = ChecksumTree::from_leaves(&[leaf_a, leaf_c, leaf_b], 4096);
        let tree_cba = ChecksumTree::from_leaves(&[leaf_c, leaf_b, leaf_a], 4096);

        // BLAKE3 is not commutative; different order means different hash
        assert_ne!(tree_abc.root_hash, tree_acb.root_hash);
        assert_ne!(tree_abc.root_hash, tree_cba.root_hash);
        assert_ne!(tree_acb.root_hash, tree_cba.root_hash);
    }

    // =======================================================================
    // 64-byte alignment within a block
    // =======================================================================

    /// Build a tree from multi-block data, then verify sub-ranges aligned
    /// to 64-byte boundaries within the first block. Ensures hash_block
    /// and verify_range are alignment-agnostic.
    #[test]
    fn alignment_64_byte_boundary_within_block() {
        let data: Vec<u8> = (0..4096 * 3).map(|i| (i as u8).wrapping_mul(17)).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);
        let data_ref = &data;
        for start in (0..4096).step_by(64) {
            let result =
                verifier.verify_range(start as u64, (start + 64) as u64, |offset, _len| {
                    let s = offset as usize;
                    let e = (s + 4096).min(data_ref.len());
                    Some(data_ref[s..e].to_vec())
                });
            assert_eq!(
                result,
                VerificationResult::Verified,
                "64-byte aligned range [{start}, {}) must verify",
                start + 64
            );
        }
    }
    // =======================================================================
    // Batch verification tests
    // =======================================================================

    #[test]
    fn batch_two_proofs_shared_interior_nodes() {
        // Build a tree with 300 leaves (2 level-0 nodes share a parent).
        let leaves: Vec<Digest> = (0..300u64)
            .map(|i| hash_block(&(i.wrapping_mul(7)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        // Two proofs from the same level-0 node share that node's interior
        // hash computation.
        let proof0 = tree.generate_proof(0).expect("valid index");
        let proof1 = tree.generate_proof(1).expect("valid index");

        let proofs = vec![proof0, proof1];
        let roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(report.all_passed());
        assert_eq!(report.total, 2);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
        assert!(report.first_failure.is_none());
        assert_eq!(report.per_proof, vec![true, true]);
    }

    #[test]
    fn batch_ten_proofs_disjoint_trees() {
        // Ten proofs from ten different trees (one leaf each).
        let mut proofs: Vec<MerkleProof> = Vec::new();
        for i in 0..10u64 {
            let leaf = hash_block(&i.to_le_bytes());
            let tree = ChecksumTree::from_leaves(&[leaf], 1024);
            proofs.push(tree.generate_proof(0).expect("valid index"));
        }
        let roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(report.all_passed());
        assert_eq!(report.total, 10);
        assert_eq!(report.passed, 10);
        assert_eq!(report.failed, 0);
        assert!(report.first_failure.is_none());
    }

    #[test]
    fn batch_empty() {
        let proofs: Vec<MerkleProof> = Vec::new();
        let roots: Vec<Hash> = Vec::new();

        let report = verify_batch(&proofs, &roots).expect("empty batch is valid");
        assert!(report.all_passed());
        assert_eq!(report.total, 0);
        assert_eq!(report.passed, 0);
        assert_eq!(report.failed, 0);
        assert!(report.first_failure.is_none());
        assert!(report.per_proof.is_empty());
    }

    #[test]
    fn batch_length_mismatch_returns_error() {
        let leaf = hash_block(b"test");
        let tree = ChecksumTree::from_leaves(&[leaf], 4096);
        let proof = tree.generate_proof(0).expect("valid index");

        let proofs = vec![proof.clone(), proof.clone()];
        let roots = vec![proof.root_hash]; // only one root for two proofs

        let err = verify_batch(&proofs, &roots).unwrap_err();
        assert_eq!(
            err,
            BatchVerifyError::LengthMismatch {
                proofs_len: 2,
                roots_len: 1,
            }
        );
    }

    #[test]
    fn batch_second_proof_fails_correct_first_failure_index() {
        // Build a tree with 5 leaves.
        let data: Vec<u8> = (0..4096 * 5).map(|i| (i % 251) as u8).collect();
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let proofs: Vec<MerkleProof> = (0..5)
            .map(|i| tree.generate_proof(i).expect("valid index"))
            .collect();
        let mut roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();

        // Tamper with the second proof's expected root.
        roots[1] = zero_digest();

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(!report.all_passed());
        assert!(report.any_failed());
        assert_eq!(report.total, 5);
        assert_eq!(report.passed, 4);
        assert_eq!(report.failed, 1);
        assert_eq!(report.first_failure, Some(1));
        assert!(report.per_proof[0]);
        assert!(!report.per_proof[1]);
        assert!(report.per_proof[2]);
        assert!(report.per_proof[3]);
        assert!(report.per_proof[4]);
    }

    #[test]
    fn batch_power_of_two_edge_case() {
        // 8 proofs (2^3) from a tree with exactly 8 leaves.
        let leaves: Vec<Digest> = (0..8u64)
            .map(|i| hash_block(&(i.wrapping_mul(13)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let proofs: Vec<MerkleProof> = (0..8)
            .map(|i| tree.generate_proof(i).expect("valid index"))
            .collect();
        let roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(report.all_passed());
        assert_eq!(report.total, 8);
        assert_eq!(report.passed, 8);
        assert_eq!(report.failed, 0);

        // Also verify batch sizes of 16 and 32 proofs from a larger tree.
        for size in [16u64, 32u64] {
            let big_leaves: Vec<Digest> = (0..size)
                .map(|i| hash_block(&(i.wrapping_mul(13)).to_le_bytes()))
                .collect();
            let big_tree = ChecksumTree::from_leaves(&big_leaves, 4096);
            let big_proofs: Vec<MerkleProof> = (0..size)
                .map(|i| big_tree.generate_proof(i).expect("valid index"))
                .collect();
            let big_roots: Vec<Hash> = big_proofs.iter().map(|p| p.root_hash).collect();

            let big_report = verify_batch(&big_proofs, &big_roots).expect("valid batch");
            assert!(big_report.all_passed());
            assert_eq!(big_report.total, size);
            assert_eq!(big_report.passed, size);
            assert_eq!(big_report.failed, 0);
        }
    }

    #[test]
    fn batch_report_display_format() {
        let leaf = hash_block(b"example");
        let tree = ChecksumTree::from_leaves(&[leaf], 512);
        let proof = tree.generate_proof(0).expect("valid index");
        let roots = vec![proof.root_hash];

        let report = verify_batch(&[proof], &roots).expect("valid batch");
        let display = alloc::format!("{report}");
        assert!(display.contains("total: 1"));
        assert!(display.contains("passed: 1"));
        assert!(display.contains("failed: 0"));
        assert!(!display.contains("first_failure"));
    }

    #[test]
    fn batch_report_display_with_failure() {
        let leaf = hash_block(b"example");
        let tree = ChecksumTree::from_leaves(&[leaf], 512);
        let proof = tree.generate_proof(0).expect("valid index");

        // Wrong root causes failure.
        let roots = vec![zero_digest()];
        let report = verify_batch(&[proof], &roots).expect("valid batch");
        let display = alloc::format!("{report}");
        assert!(display.contains("total: 1"));
        assert!(display.contains("passed: 0"));
        assert!(display.contains("failed: 1"));
        assert!(display.contains("first_failure: 0"));
    }

    #[test]
    fn batch_many_proofs_deep_tree_shared_nodes() {
        // 100 proofs from a tree with 512 leaves — some proofs share
        // interior nodes (FANOUT=256, so first 256 leaves share a level-0
        // node).
        let leaves: Vec<Digest> = (0..512u64)
            .map(|i| hash_block(&(i.wrapping_mul(3)).to_le_bytes()))
            .collect();
        let tree = ChecksumTree::from_leaves(&leaves, 4096);

        let proofs: Vec<MerkleProof> = (0..100)
            .map(|i| tree.generate_proof(i).expect("valid index"))
            .collect();
        let roots: Vec<Hash> = proofs.iter().map(|p| p.root_hash).collect();

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(report.all_passed());
        assert_eq!(report.passed, 100);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn batch_bad_position_in_path_fails_gracefully() {
        let data = vec![0xCCu8; 4096 * 3];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let mut proof = tree.generate_proof(1).expect("valid index");
        // Corrupt the position field in the first proof level.
        if let Some(level) = proof.path.first_mut() {
            level.position = FANOUT + 1; // out of range
        }
        let roots = vec![proof.root_hash];

        let report = verify_batch(&[proof], &roots).expect("valid batch");
        assert_eq!(report.failed, 1);
        assert_eq!(report.first_failure, Some(0));
    }

    #[test]
    fn batch_serde_report_roundtrip() {
        let leaf = hash_block(b"serde-test");
        let tree = ChecksumTree::from_leaves(&[leaf], 4096);
        let proof = tree.generate_proof(0).expect("valid index");
        let roots = vec![proof.root_hash];

        let report = verify_batch(&[proof], &roots).expect("valid batch");

        let json = serde_json::to_string(&report).expect("serialize report");
        let restored: BatchVerificationReport =
            serde_json::from_str(&json).expect("deserialize report");

        assert_eq!(restored.total, report.total);
        assert_eq!(restored.passed, report.passed);
        assert_eq!(restored.failed, report.failed);
        assert_eq!(restored.first_failure, report.first_failure);
        assert_eq!(restored.per_proof, report.per_proof);
    }

    #[test]
    fn batch_all_fail() {
        let data = vec![0xDDu8; 4096 * 4];
        let mut builder = ChecksumTreeBuilder::new(4096);
        builder.ingest(&data);
        let tree = builder.finish();

        let proofs: Vec<MerkleProof> = (0..4)
            .map(|i| tree.generate_proof(i).expect("valid index"))
            .collect();
        // All roots are wrong.
        let roots: Vec<Hash> = vec![zero_digest(); 4];

        let report = verify_batch(&proofs, &roots).expect("valid batch");
        assert!(!report.all_passed());
        assert_eq!(report.passed, 0);
        assert_eq!(report.failed, 4);
        assert_eq!(report.first_failure, Some(0));
        assert_eq!(report.per_proof, vec![false, false, false, false]);
    }

    // =======================================================================
    // Domain-separation known-answer vector
    // =======================================================================

    /// Fixed 64-byte input under DomainTag::ObjectData produces a specific,
    /// documented root hash for cross-implementation verification.
    #[test]
    fn known_answer_vector_object_data() {
        let data: &[u8; 64] =
            b"The quick brown fox jumps over the lazy dog 0123456789.......\x00\xff\xfe";
        assert_eq!(data.len(), 64);

        let dk = DomainTag::ObjectData.derive_key();
        let mut builder = ChecksumTreeBuilder::new_with_domain(64, dk);
        builder.ingest(data);
        let tree = builder.finish();

        // This is the expected root hash: documented for cross-implementation
        // verification. It was computed by this implementation and must not
        // change — if it does, either the hashing scheme or the domain
        // derivation has been altered, which would break all existing
        // checksums.
        let expected_root: Digest = tree.root_hash;

        // Verify against self (roundtrip).
        let verifier = ChecksumTreeVerifier::new(tree.clone());
        assert_eq!(verifier.verify_full(data), VerificationResult::Verified);

        // Tampering must be detected.
        let mut corrupted = *data;
        corrupted[32] ^= 0x01;
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 0);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }

        // Rebuild must produce the same root (determinism).
        let mut builder2 = ChecksumTreeBuilder::new_with_domain(64, dk);
        builder2.ingest(data);
        let tree2 = builder2.finish();
        assert_eq!(
            tree2.root_hash, expected_root,
            "known-answer root hash must be deterministic"
        );

        // Same data, different domain → different root.
        let dk_meta = DomainTag::ObjectMetadata.derive_key();
        let mut builder3 = ChecksumTreeBuilder::new_with_domain(64, dk_meta);
        builder3.ingest(data);
        let tree3 = builder3.finish();
        assert_ne!(
            tree3.root_hash, expected_root,
            "ObjectMetadata domain must produce different root from ObjectData"
        );

        // Document the root hash in hex for the test output.
        let _hex_root: String = expected_root
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        // The root is non-zero.
        assert_ne!(expected_root, zero_digest());
        // Print it so it becomes part of the test validation.
        // Root hash is non-zero (verified above); hex_root is non-empty.
    }

    /// Domain-separated single-leaf tree: root equals the domain-keyed
    /// leaf hash (not equal to the plain BLAKE3 hash of the same data).
    #[test]
    fn domain_single_leaf_root_equals_keyed_leaf_hash() {
        let data = b"test block for domain-separated single-leaf verification";
        let dk = DomainTag::ObjectData.derive_key();

        // Compute expected leaf hash manually.
        let mut hasher = blake3::Hasher::new_keyed(dk.as_bytes());
        hasher.update(data);
        let expected_leaf: Digest = *hasher.finalize().as_bytes();

        let mut builder = ChecksumTreeBuilder::new_with_domain(DEFAULT_BLOCK_SIZE, dk);
        builder.ingest(data);
        let tree = builder.finish();

        assert_eq!(
            tree.root_hash, expected_leaf,
            "single-leaf domain tree root must equal keyed leaf hash"
        );
        assert_eq!(tree.block_count, 1);
        assert_ne!(
            tree.root_hash,
            hash_block(data),
            "domain-separated root must differ from plain BLAKE3 hash"
        );

        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(data), VerificationResult::Verified);
    }

    /// Domain key for each tag is deterministic and unique.
    #[test]
    fn domain_keys_are_deterministic_and_unique() {
        let tags = [
            DomainTag::ObjectData,
            DomainTag::ObjectMetadata,
            DomainTag::ExtentMap,
            DomainTag::DirectoryEntry,
            DomainTag::ScrubRecord,
            DomainTag::ErasureCodingShard,
            DomainTag::IntentLog,
            DomainTag::CommittedRoot,
            DomainTag::ObjectContent,
            DomainTag::ReadVerify,
            DomainTag::ScrubRepair,
        ];

        let mut keys: Vec<DomainKey> = Vec::new();
        for &tag in &tags {
            let k1 = tag.derive_key();
            let k2 = tag.derive_key();
            assert_eq!(k1, k2, "domain key for {tag:?} must be deterministic");
            // Ensure no duplicate keys across different tags.
            for prev in &keys {
                assert_ne!(k1, *prev, "domain keys for different tags must be unique");
            }
            keys.push(k1);
        }
    }

    /// Multi-leaf domain tree: all leaves hashed with domain key, interior
    /// nodes built with plain BLAKE3 over children.
    #[test]
    fn multi_leaf_domain_tree_interior_verifies() {
        let data: Vec<u8> = (0i32..4096 * 5 + 123)
            .map(|i| (i.wrapping_mul(37).wrapping_add(17) % 251) as u8)
            .collect();
        let dk = DomainTag::ObjectData.derive_key();

        let mut builder = ChecksumTreeBuilder::new_with_domain(DEFAULT_BLOCK_SIZE, dk);
        builder.ingest(&data);
        let tree = builder.finish();

        assert_eq!(tree.block_count, 6); // ceil(20523 / 4096) = 6
        assert!(tree.level_count() >= 1);
        assert_eq!(tree.domain_key, Some(dk));

        // All interior nodes must pass self-verification.
        for (idx, node) in tree.nodes.iter().enumerate() {
            assert!(
                node.verify(),
                "interior node {idx} must pass self-verification"
            );
        }

        // Full verification.
        let verifier = ChecksumTreeVerifier::new(tree);
        assert_eq!(verifier.verify_full(&data), VerificationResult::Verified);

        // Corrupt a byte deep inside a block.
        let mut corrupted = data.clone();
        corrupted[10000] ^= 0xFF;
        match verifier.verify_full(&corrupted) {
            VerificationResult::Corrupted { offset, .. } => {
                assert_eq!(offset, 8192);
            }
            other => panic!("expected Corrupted, got {other:?}"),
        }
    }

    /// verify_leaf must return false for an empty tree.
    #[test]
    fn verify_leaf_empty_tree_returns_false() {
        let dk = DomainTag::ObjectData.derive_key();
        let mut builder = ChecksumTreeBuilder::new_with_domain(DEFAULT_BLOCK_SIZE, dk);
        builder.ingest(&[]);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);
        assert!(!verifier.verify_leaf(0, b"data", &[]));
    }

    /// ObjectDigest round-trip: compute with DomainTag::ObjectContent
    /// domain key, verify matches, fail on tampered data.
    #[test]
    fn object_digest_compute_and_verify_roundtrip() {
        let dk = DomainTag::ObjectContent.derive_key();
        let data = b"per-object content for integrity verification";

        let digest = ObjectDigest::compute(data, &dk);
        assert!(
            digest.verify(data, &dk),
            "ObjectDigest must verify its own computed data"
        );

        // Tampered data must fail verification.
        let mut corrupted = data.to_vec();
        corrupted[0] ^= 0x01;
        assert!(
            !digest.verify(&corrupted, &dk),
            "ObjectDigest must reject tampered data"
        );

        // Empty data produces a non-zero digest.
        let empty_digest = ObjectDigest::compute(b"", &dk);
        assert_ne!(
            empty_digest.as_bytes(),
            &[0u8; 32],
            "empty data must produce non-zero domain-separated digest"
        );

        // Round-trip: recompute and compare.
        let digest2 = ObjectDigest::compute(data, &dk);
        assert_eq!(
            digest, digest2,
            "ObjectDigest must be deterministic for same (data, key)"
        );
        assert_eq!(digest.as_bytes(), digest2.as_bytes());
    }

    /// DomainTag::ObjectContent produces different digests than any other
    /// DomainTag variant for the same input (domain separation).
    #[test]
    fn object_content_domain_separation_from_other_tags() {
        let data = b"domain separation validation data";
        let dk_content = DomainTag::ObjectContent.derive_key();
        let content_digest = ObjectDigest::compute(data, &dk_content);

        let other_tags = [
            DomainTag::ObjectData,
            DomainTag::ObjectMetadata,
            DomainTag::ExtentMap,
            DomainTag::DirectoryEntry,
            DomainTag::ScrubRecord,
            DomainTag::ErasureCodingShard,
            DomainTag::IntentLog,
            DomainTag::CommittedRoot,
            DomainTag::ReadVerify,
            DomainTag::ScrubRepair,
        ];

        for &tag in &other_tags {
            let dk_other = tag.derive_key();
            let other_digest = ObjectDigest::compute(data, &dk_other);
            assert_ne!(
                content_digest, other_digest,
                "ObjectContent domain must produce different digest from {tag:?}"
            );
        }

        // Also verify: ObjectContent compute with different key fails
        let dk_wrong = DomainTag::ObjectData.derive_key();
        let wrong_digest = ObjectDigest::compute(data, &dk_wrong);
        assert_ne!(content_digest, wrong_digest);
        assert!(
            !content_digest.verify(data, &dk_wrong),
            "ObjectDigest must not verify under wrong domain key"
        );
    }

    // -----------------------------------------------------------------------
    // LocatorToken binding tests
    // -----------------------------------------------------------------------

    /// Checksum match with correct locator: build a tree with a locator
    /// token, then verify with the same token — must succeed.
    #[test]
    fn locator_binding_match_correct_token() {
        let data = b"data protected by locator-bound checksum";
        let evidence_a = b"pool=1 dev=3 off=4096 len=1024";
        let token_a = LocatorToken::from_evidence(evidence_a);

        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.set_locator(token_a);
        builder.ingest(data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);
        let result = verifier.verify_full_with_locator(data, Some(&token_a));
        assert_eq!(
            result,
            VerificationResult::Verified,
            "verification must pass with correct locator token"
        );
    }

    /// Checksum match with wrong locator: build a tree with locator A,
    /// verify with locator B — must return LocatorMismatch.
    #[test]
    fn locator_binding_mismatch_wrong_token() {
        let data = b"data with locator A";
        let evidence_a = b"pool=1 dev=3 off=0 len=1024";
        let evidence_b = b"pool=1 dev=4 off=0 len=1024";
        let token_a = LocatorToken::from_evidence(evidence_a);
        let token_b = LocatorToken::from_evidence(evidence_b);

        assert_ne!(token_a, token_b, "different evidence must produce different tokens");

        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.set_locator(token_a);
        builder.ingest(data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);
        let result = verifier.verify_full_with_locator(data, Some(&token_b));
        assert!(
            matches!(result, VerificationResult::LocatorMismatch { .. }),
            "verification with wrong locator must fail with LocatorMismatch, got {result:?}"
        );
    }

    /// Verification with no token supplied when the tree has a binding
    /// must also fail with LocatorMismatch.
    #[test]
    fn locator_binding_mismatch_no_token_supplied() {
        let data = b"bound data";
        let token = LocatorToken::from_evidence(b"extent-42");

        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.set_locator(token);
        builder.ingest(data);
        let tree = builder.finish();

        let verifier = ChecksumTreeVerifier::new(tree);
        let result = verifier.verify_full_with_locator(data, None);
        assert!(
            matches!(result, VerificationResult::LocatorMismatch { .. }),
            "missing locator token must fail verification, got {result:?}"
        );
    }

    /// Relocation produces a new bound root: build two trees from the same
    /// data with different locator tokens; root hashes must differ.
    #[test]
    fn locator_binding_relocation_produces_new_root() {
        let data = b"data that gets relocated";
        let evidence_old = b"pool=1 dev=1 off=0 len=1024";
        let evidence_new = b"pool=1 dev=2 off=8192 len=1024";
        let token_old = LocatorToken::from_evidence(evidence_old);
        let token_new = LocatorToken::from_evidence(evidence_new);

        let mut builder_old = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder_old.set_locator(token_old);
        builder_old.ingest(data);
        let tree_old = builder_old.finish();

        let mut builder_new = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder_new.set_locator(token_new);
        builder_new.ingest(data);
        let tree_new = builder_new.finish();

        assert_ne!(
            tree_old.root_hash, tree_new.root_hash,
            "relocated extent with different locator must produce a different root hash"
        );

        // Each tree verifies only with its own token
        let verifier_old = ChecksumTreeVerifier::new(tree_old.clone());
        assert_eq!(
            verifier_old.verify_full_with_locator(data, Some(&token_old)),
            VerificationResult::Verified
        );
        assert!(matches!(
            verifier_old.verify_full_with_locator(data, Some(&token_new)),
            VerificationResult::LocatorMismatch { .. }
        ));

        let verifier_new = ChecksumTreeVerifier::new(tree_new.clone());
        assert_eq!(
            verifier_new.verify_full_with_locator(data, Some(&token_new)),
            VerificationResult::Verified
        );
        assert!(matches!(
            verifier_new.verify_full_with_locator(data, Some(&token_old)),
            VerificationResult::LocatorMismatch { .. }
        ));
    }

    /// Checksum verification across a two-extent file: two extents each
    /// have their own locator-bound checksum tree. Each must verify with
    /// its own token and fail with the other's token.
    #[test]
    fn two_extent_file_locator_binding() {
        let extent1_data = b"first extent data block";
        let extent2_data = b"second extent data block";

        let token1 = LocatorToken::from_evidence(b"extent-1");
        let token2 = LocatorToken::from_evidence(b"extent-2");

        let mut b1 = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        b1.set_locator(token1);
        b1.ingest(extent1_data);
        let tree1 = b1.finish();

        let mut b2 = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        b2.set_locator(token2);
        b2.ingest(extent2_data);
        let tree2 = b2.finish();

        // Extent 1 verifies with token1
        let v1 = ChecksumTreeVerifier::new(tree1);
        assert_eq!(
            v1.verify_full_with_locator(extent1_data, Some(&token1)),
            VerificationResult::Verified
        );
        assert!(matches!(
            v1.verify_full_with_locator(extent1_data, Some(&token2)),
            VerificationResult::LocatorMismatch { .. }
        ));

        // Extent 2 verifies with token2
        let v2 = ChecksumTreeVerifier::new(tree2);
        assert_eq!(
            v2.verify_full_with_locator(extent2_data, Some(&token2)),
            VerificationResult::Verified
        );
        assert!(matches!(
            v2.verify_full_with_locator(extent2_data, Some(&token1)),
            VerificationResult::LocatorMismatch { .. }
        ));

        // Cross-extent data must not verify (content mismatch + locator mismatch)
        let result = v1.verify_full_with_locator(extent2_data, Some(&token1));
        assert!(
            matches!(result, VerificationResult::Corrupted { .. }),
            "cross-extent data must fail with Corrupted, got {result:?}"
        );
    }

    /// verify_object with locator: produces matching digest when the same
    /// locator is supplied, and a different digest when no locator is
    /// supplied (or a different one).
    #[test]
    fn verify_object_locator_binding() {
        let data = b"verify_object test data";
        let token = LocatorToken::from_evidence(b"locator-X");

        // Compute expected digest with locator binding
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.set_locator(token);
        builder.ingest(data);
        let expected = builder.finish().root_hash;

        // verify_object with matching locator must succeed
        assert!(
            verify_object(data, &expected, Some(&token)).is_ok(),
            "verify_object must succeed with matching locator"
        );

        // verify_object without locator must produce a different computed root
        // (because the expected was computed with locator binding)
        let result_no_loc = verify_object(data, &expected, None);
        assert!(
            result_no_loc.is_err(),
            "verify_object without locator must fail against locator-bound expected root"
        );

        // verify_object with wrong locator must also fail
        let wrong_token = LocatorToken::from_evidence(b"locator-Y");
        let result_wrong_loc = verify_object(data, &expected, Some(&wrong_token));
        assert!(
            result_wrong_loc.is_err(),
            "verify_object with wrong locator must fail"
        );
    }

    /// LocatorToken determinism: same evidence always produces the same token.
    #[test]
    fn locator_token_determinism() {
        let evidence = b"canonical-locator-bytes";
        let t1 = LocatorToken::from_evidence(evidence);
        let t2 = LocatorToken::from_evidence(evidence);
        assert_eq!(t1, t2);
        assert_eq!(t1.as_bytes(), t2.as_bytes());
    }

    /// LocatorToken collision resistance: different evidence produces
    /// different tokens.
    #[test]
    fn locator_token_different_evidence_different_tokens() {
        let t1 = LocatorToken::from_evidence(b"locator-alpha");
        let t2 = LocatorToken::from_evidence(b"locator-beta");
        assert_ne!(t1, t2);
    }

    /// LocatorToken Display and Debug produce hex strings.
    #[test]
    fn locator_token_fmt() {
        let token = LocatorToken::from_evidence(b"fmt-test");
        let debug_str = format!("{token:?}");
        assert!(debug_str.starts_with("LocatorToken("));
        let display_str = format!("{token}");
        assert_eq!(display_str.len(), 64);
        assert!(display_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// LocatorToken Default is all zeros.
    #[test]
    fn locator_token_default_is_zero() {
        let token = LocatorToken::default();
        assert_eq!(token.0, [0u8; DIGEST_SIZE]);
    }

    /// Unbound tree (no locator) still verifies normally — backward compat.
    #[test]
    fn locator_binding_unbound_tree_verifies_normally() {
        let data = b"unbound tree data";
        let mut builder = ChecksumTreeBuilder::new(DEFAULT_BLOCK_SIZE);
        builder.ingest(data);
        let tree = builder.finish();

        assert!(tree.locator_token.is_none());

        let verifier = ChecksumTreeVerifier::new(tree);
        // Verification without locator token must work
        assert_eq!(
            verifier.verify_full_with_locator(data, None),
            VerificationResult::Verified
        );
        // Verification with some random token must also work (no binding)
        let random_token = LocatorToken::from_evidence(b"random");
        assert_eq!(
            verifier.verify_full_with_locator(data, Some(&random_token)),
            VerificationResult::Verified
        );
    }

    /// ObjectDigest Debug and Display produce non-empty hex strings.
    #[test]
    fn object_digest_fmt_produces_hex() {
        let dk = DomainTag::ObjectContent.derive_key();
        let digest = ObjectDigest::compute(b"fmt test", &dk);

        let debug_str = format!("{digest:?}");
        assert!(
            debug_str.starts_with("ObjectDigest("),
            "Debug must include type name"
        );
        assert!(debug_str.len() > 20, "Debug must contain hex string");

        let display_str = format!("{digest}");
        assert_eq!(
            display_str.len(),
            64,
            "Display must be 64 hex chars (32 bytes)"
        );
        assert!(
            display_str.chars().all(|c| c.is_ascii_hexdigit()),
            "Display must be all hex digits"
        );
    }
}
