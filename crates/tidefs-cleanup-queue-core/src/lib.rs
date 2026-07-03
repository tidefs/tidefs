// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Persistent deferred cleanup work queue.

//! The GC pipeline cleanup-queue ledger is in [`ledger`].
//!
//! Persists the cleanup queue B+tree to disk with TXG-atomic commits so
//! enqueued work items survive crashes.
//!
//! Uses the generic [`tidefs_btree::BPlusTree`] as the in-memory index and
//! serializes its entries as a named page through
//! [`tidefs_commit_group::CommitGroupStore`].

use std::fmt;

use tidefs_btree::BPlusTree;
use tidefs_commit_group::CommitGroupStore;
use tidefs_types_dataset_feature_flags_core::BtreeRootPointer;
use tidefs_types_deferred_cleanup_core::CleanupWorkItemV1;
pub mod ledger;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes for the `CleanupQueueRoot` on-media record: `b"CLNQROOT"`.
pub const CLEANUP_QUEUE_ROOT_MAGIC: [u8; 8] = *b"CLNQROOT";

/// Current on-media format version of `CleanupQueueRoot`.
pub const CLEANUP_QUEUE_ROOT_VERSION: u32 = 1;

/// Total on-media size of `CleanupQueueRoot` in bytes.
pub const CLEANUP_QUEUE_ROOT_SIZE: usize = 64;

/// Name used to store the cleanup queue page in the CommitGroupStore.
pub const CLEANUP_QUEUE_PAGE_NAME: &str = "cleanup-queue-v1";

/// BLAKE3 domain-separation context for the cleanup-queue page blob.
const CLEANUP_QUEUE_DOMAIN: &[u8] = b"TideFS CleanupQueue page v1";

/// Maximum fanout for the cleanup queue B+tree leaf nodes.
pub const MAX_LEAF: usize = 45;

/// Maximum fanout for the cleanup queue B+tree internal nodes.
pub const MAX_INTERNAL: usize = 45;

// ---------------------------------------------------------------------------
// CleanupQueueRoot — on-disk root record
// ---------------------------------------------------------------------------

/// Persisted root record for the cleanup queue.
///
/// ## On-media layout (64 bytes, fixed-size)
///
/// ```text
/// [0..8)    magic: b"CLNQROOT"
/// [8..12)   version: u32 LE (currently 1)
/// [12..44)  root_page_key: [u8; 32] — CommitGroupKey of the queue page
/// [44..52)  entry_count: u64 LE
/// [52..64)  reserved: [u8; 12]
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupQueueRoot {
    /// Magic identifier: must equal [`CLEANUP_QUEUE_ROOT_MAGIC`].
    pub magic: [u8; 8],
    /// On-media format version.
    pub version: u32,
    /// Object-store key of the queue page blob.
    pub root_page_key: [u8; 32],
    /// Number of work items in the queue when this root was committed.
    pub entry_count: u64,
    /// Reserved; zero-filled on write.
    pub reserved: [u8; 12],
}

impl CleanupQueueRoot {
    /// Create a new root record.
    #[must_use]
    pub fn new(root_page_key: [u8; 32], entry_count: u64) -> Self {
        Self {
            magic: CLEANUP_QUEUE_ROOT_MAGIC,
            version: CLEANUP_QUEUE_ROOT_VERSION,
            root_page_key,
            entry_count,
            reserved: [0u8; 12],
        }
    }

    /// Serialize to a fixed-size 64-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CLEANUP_QUEUE_ROOT_SIZE] {
        let mut buf = [0u8; CLEANUP_QUEUE_ROOT_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..44].copy_from_slice(&self.root_page_key);
        buf[44..52].copy_from_slice(&self.entry_count.to_le_bytes());
        buf[52..64].copy_from_slice(&self.reserved);
        buf
    }

    /// Deserialize from a 64-byte slice.
    ///
    /// Returns `None` if the magic or version is unrecognized.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CLEANUP_QUEUE_ROOT_SIZE]) -> Option<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != CLEANUP_QUEUE_ROOT_MAGIC {
            return None;
        }

        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != CLEANUP_QUEUE_ROOT_VERSION {
            return None;
        }

        let mut root_page_key = [0u8; 32];
        root_page_key.copy_from_slice(&bytes[12..44]);

        let entry_count = u64::from_le_bytes([
            bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
        ]);

        let mut reserved = [0u8; 12];
        reserved.copy_from_slice(&bytes[52..64]);

        Some(Self {
            magic,
            version,
            root_page_key,
            entry_count,
            reserved,
        })
    }

    /// Returns `true` if the root record validates (magic, version, reserved zeros).
    #[must_use]
    pub fn validate(&self) -> bool {
        self.magic == CLEANUP_QUEUE_ROOT_MAGIC
            && self.version == CLEANUP_QUEUE_ROOT_VERSION
            && self.reserved == [0u8; 12]
    }
}

impl Default for CleanupQueueRoot {
    fn default() -> Self {
        Self {
            magic: CLEANUP_QUEUE_ROOT_MAGIC,
            version: CLEANUP_QUEUE_ROOT_VERSION,
            root_page_key: [0u8; 32],
            entry_count: 0,
            reserved: [0u8; 12],
        }
    }
}

impl fmt::Display for CleanupQueueRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CleanupQueueRoot(version={} entries={})",
            self.version, self.entry_count
        )
    }
}

// ---------------------------------------------------------------------------
// Cleanup root replay receipts
// ---------------------------------------------------------------------------

/// Reserved-field state recorded by a cleanup root replay receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupQueueReservedStatus {
    /// Every reserved byte is zero, so the root is compatible with v1 replay.
    Zeroed,
}

/// Replay decision made by cleanup root receipt verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupQueueReplayDecision {
    /// The root and page agree and may be used as cleanup queue replay evidence.
    TreatAsDurableEvidence,
}

/// Scope of validation represented by a cleanup root replay receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupQueueReplayValidationTier {
    /// Root-record and sealed-page source evidence only.
    RootPageSourceEvidence,
}

/// Verified cleanup queue replay evidence.
///
/// This receipt proves the supplied [`CleanupQueueRoot`] and sealed cleanup
/// queue page agree on the v1 root format, page digest, entry count, and
/// reserved-field state. It is intentionally narrow evidence for cleanup queue
/// replay and is not, by itself, a full crash-recovery proof for the filesystem.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupQueueReplayReceipt {
    /// Magic bytes observed in the root record.
    pub root_magic: [u8; 8],
    /// Version observed in the root record.
    pub root_version: u32,
    /// Commit-group page key recorded by the root.
    pub root_page_key: [u8; 32],
    /// Domain-separated BLAKE3 digest stored in the sealed page prefix.
    pub page_digest: [u8; 32],
    /// Entry count observed in the root record.
    pub root_entry_count: u64,
    /// Entry count decoded from the sealed page payload.
    pub page_entry_count: u64,
    /// Reserved-field state observed after verification.
    pub reserved_status: CleanupQueueReservedStatus,
    /// Replay decision represented by this receipt.
    pub replay_decision: CleanupQueueReplayDecision,
    /// Validation tier represented by this receipt.
    pub validation_tier: CleanupQueueReplayValidationTier,
}

/// Errors produced while verifying cleanup root replay evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupQueueReplayReceiptError {
    /// Root magic did not match [`CLEANUP_QUEUE_ROOT_MAGIC`].
    InvalidMagic {
        /// Magic bytes found in the root.
        found: [u8; 8],
    },
    /// Root version is not supported by this verifier.
    UnsupportedVersion {
        /// Version found in the root.
        found: u32,
    },
    /// A reserved byte was non-zero.
    NonZeroReserved {
        /// Offset within [`CleanupQueueRoot::reserved`] of the first non-zero byte.
        first_nonzero_index: usize,
        /// The offending byte value.
        value: u8,
    },
    /// The sealed page is too short to contain its digest prefix.
    PageTooShort {
        /// Sealed page length in bytes.
        len: usize,
    },
    /// The sealed page digest prefix did not match the payload digest.
    PageDigestMismatch {
        /// Digest stored in the sealed page prefix.
        stored: [u8; 32],
        /// Digest computed from the page payload.
        computed: [u8; 32],
    },
    /// The sealed page payload could not be decoded.
    PageDecodeFailed {
        /// Decode error text.
        reason: String,
    },
    /// Root entry count and decoded page entry count do not agree.
    EntryCountMismatch {
        /// Entry count recorded by the root.
        root_entry_count: u64,
        /// Entry count decoded from the page.
        page_entry_count: u64,
    },
}

impl fmt::Display for CleanupQueueReplayReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic { .. } => write!(f, "cleanup queue root magic mismatch"),
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported cleanup queue root version {found}")
            }
            Self::NonZeroReserved {
                first_nonzero_index,
                value,
            } => write!(
                f,
                "cleanup queue root reserved byte {first_nonzero_index} is non-zero: {value:#04x}"
            ),
            Self::PageTooShort { len } => {
                write!(f, "cleanup queue sealed page too short for digest: {len} bytes")
            }
            Self::PageDigestMismatch { .. } => {
                write!(f, "cleanup queue sealed page digest mismatch")
            }
            Self::PageDecodeFailed { reason } => {
                write!(f, "cleanup queue sealed page decode failed: {reason}")
            }
            Self::EntryCountMismatch {
                root_entry_count,
                page_entry_count,
            } => write!(
                f,
                "cleanup queue entry-count mismatch: root={root_entry_count} page={page_entry_count}"
            ),
        }
    }
}

impl std::error::Error for CleanupQueueReplayReceiptError {}

impl CleanupQueueRoot {
    /// Verify this root against a stored cleanup queue page and return replay
    /// evidence when they agree.
    ///
    /// # Errors
    ///
    /// Returns an error when the root magic/version/reserved fields are invalid,
    /// the sealed page digest does not match its payload, the page cannot be
    /// decoded, or the root entry count differs from the decoded page count.
    pub fn replay_receipt<S: CommitGroupStore>(
        &self,
        store: &S,
    ) -> Result<CleanupQueueReplayReceipt, CleanupQueueReplayReceiptError> {
        let sealed = store
            .get_named(CLEANUP_QUEUE_PAGE_NAME)
            .map_err(|reason| CleanupQueueReplayReceiptError::PageDecodeFailed { reason })?
            .ok_or(CleanupQueueReplayReceiptError::PageDecodeFailed {
                reason: "cleanup queue page not found in store".to_string(),
            })?;

        verify_cleanup_queue_root_replay_receipt(self, &sealed)
    }
}

/// Verify cleanup queue root/page replay evidence and return a receipt.
///
/// The receipt is cleanup queue replay evidence only. It proves that this root
/// record and sealed queue page agree at the source-evidence tier; it does not
/// claim that every filesystem crash-recovery invariant has been proven.
///
/// # Errors
///
/// Returns an error when the root magic/version/reserved fields are invalid,
/// the sealed page digest does not match its payload, the page cannot be
/// decoded, or the root entry count differs from the decoded page count.
pub fn verify_cleanup_queue_root_replay_receipt(
    root: &CleanupQueueRoot,
    sealed_page: &[u8],
) -> Result<CleanupQueueReplayReceipt, CleanupQueueReplayReceiptError> {
    if root.magic != CLEANUP_QUEUE_ROOT_MAGIC {
        return Err(CleanupQueueReplayReceiptError::InvalidMagic { found: root.magic });
    }
    if root.version != CLEANUP_QUEUE_ROOT_VERSION {
        return Err(CleanupQueueReplayReceiptError::UnsupportedVersion {
            found: root.version,
        });
    }
    if let Some((first_nonzero_index, value)) = root
        .reserved
        .iter()
        .copied()
        .enumerate()
        .find(|(_, byte)| *byte != 0)
    {
        return Err(CleanupQueueReplayReceiptError::NonZeroReserved {
            first_nonzero_index,
            value,
        });
    }

    if sealed_page.len() < 32 {
        return Err(CleanupQueueReplayReceiptError::PageTooShort {
            len: sealed_page.len(),
        });
    }
    let mut page_digest = [0u8; 32];
    page_digest.copy_from_slice(&sealed_page[0..32]);
    let raw = &sealed_page[32..];
    let computed_digest = hash_page(raw);
    if page_digest != computed_digest {
        return Err(CleanupQueueReplayReceiptError::PageDigestMismatch {
            stored: page_digest,
            computed: computed_digest,
        });
    }

    let page_entries = deserialize_page(raw)
        .map_err(|reason| CleanupQueueReplayReceiptError::PageDecodeFailed { reason })?;
    let page_entry_count = page_entries.len() as u64;
    if root.entry_count != page_entry_count {
        return Err(CleanupQueueReplayReceiptError::EntryCountMismatch {
            root_entry_count: root.entry_count,
            page_entry_count,
        });
    }

    Ok(CleanupQueueReplayReceipt {
        root_magic: root.magic,
        root_version: root.version,
        root_page_key: root.root_page_key,
        page_digest,
        root_entry_count: root.entry_count,
        page_entry_count,
        reserved_status: CleanupQueueReservedStatus::Zeroed,
        replay_decision: CleanupQueueReplayDecision::TreatAsDurableEvidence,
        validation_tier: CleanupQueueReplayValidationTier::RootPageSourceEvidence,
    })
}

// ---------------------------------------------------------------------------
// CleanupQueue — persistent cleanup work queue
// ---------------------------------------------------------------------------

/// Persistent deferred cleanup work queue.
///
/// Wraps a [`BPlusTree`] keyed by monotonically increasing entry IDs.
/// Supports `commit` (serialize to object store) and `open` (deserialize
/// from object store) for crash-safe persistence.
#[derive(Clone, Debug)]
pub struct CleanupQueue {
    /// In-memory B+tree: entry_id → CleanupWorkItemV1.
    tree: BPlusTree<u64, CleanupWorkItemV1, MAX_LEAF, MAX_INTERNAL>,
    /// Next entry_id to assign (monotonically increasing).
    next_entry_id: u64,
    /// Whether the in-memory state differs from the last committed state.
    dirty: bool,
}

impl CleanupQueue {
    /// Create an empty cleanup queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            next_entry_id: 1,
            dirty: false,
        }
    }

    /// Enqueue a work item for background processing.
    ///
    /// Assigns a monotonically increasing entry ID and inserts into the
    /// B+tree.  The caller is responsible for setting `created_commit_group`
    /// on the work item to match the current TXG.
    ///
    /// Returns the assigned entry ID.
    pub fn enqueue(&mut self, item: CleanupWorkItemV1) -> u64 {
        let id = self.next_entry_id;
        self.next_entry_id = id.saturating_add(1);
        self.tree.insert(id, item);
        self.dirty = true;
        id
    }

    /// Remove and return the work item with the lowest entry ID (oldest
    /// enqueued item that is still pending).
    ///
    /// Returns `None` if the queue is empty or all items are complete.
    #[must_use]
    pub fn dequeue_pending(&mut self) -> Option<CleanupWorkItemV1> {
        let entries = self.tree.entries();
        for (id, item) in entries {
            if !item.is_complete() {
                self.tree.delete(&id);
                self.dirty = true;
                return Some(item);
            }
        }
        None
    }

    /// Mark a work item as complete by its entry ID.
    ///
    /// Returns `true` if the item was found and marked.
    pub fn mark_complete(&mut self, entry_id: u64) -> bool {
        let found = self.tree.update(&entry_id, |item| item.mark_complete());
        if found {
            self.dirty = true;
        }
        found
    }

    /// Remove all completed entries from the queue (garbage collection).
    ///
    /// Returns the number of entries removed.
    pub fn purge_completed(&mut self) -> usize {
        let entries = self.tree.entries();
        let mut removed = 0;
        for (id, item) in &entries {
            if item.is_complete() {
                self.tree.delete(id);
                removed += 1;
            }
        }
        if removed > 0 {
            self.dirty = true;
        }
        removed
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Serialize the queue to the object store and return a root record.
    ///
    /// The entries are serialized as a single named page in the store.
    /// The returned [`CleanupQueueRoot`] can be stored in the superblock
    /// or committed root, and later passed to [`CleanupQueue::open`]
    /// to restore the queue after a crash or remount.
    ///
    /// # Errors
    ///
    /// Returns an error string if the store operation fails.
    pub fn commit<S: CommitGroupStore>(
        &mut self,
        store: &mut S,
    ) -> Result<CleanupQueueRoot, String> {
        let entries = self.tree.entries();
        let sealed = seal_page(&entries);
        let key = store.put_named(CLEANUP_QUEUE_PAGE_NAME, &sealed)?;
        let root = CleanupQueueRoot::new(key.as_bytes32(), self.tree.len() as u64);
        self.dirty = false;
        Ok(root)
    }

    /// Deserialize the queue from the object store using a previously
    /// committed root record.
    ///
    /// The root record's `root_page_key` is used to locate the page blob.
    ///
    /// # Errors
    ///
    /// Returns an error string if the store operation fails, the page is
    /// missing, or the data is corrupt.
    pub fn open<S: CommitGroupStore>(store: &S) -> Result<Self, String> {
        let sealed = store
            .get_named(CLEANUP_QUEUE_PAGE_NAME)?
            .ok_or_else(|| "cleanup queue page not found in store".to_string())?;

        let entries = unseal_and_deserialize_page(&sealed)?;

        let mut tree: BPlusTree<u64, CleanupWorkItemV1, MAX_LEAF, MAX_INTERNAL> = BPlusTree::new();
        let mut max_id = 0u64;
        for (id, item) in entries {
            tree.insert(id, item);
            if id > max_id {
                max_id = id;
            }
        }

        Ok(Self {
            tree,
            next_entry_id: max_id.saturating_add(1),
            dirty: false,
        })
    }

    /// Open the queue, but if the page is missing (first mount), return
    /// an empty queue.
    ///
    /// # Errors
    ///
    /// Returns an error string only if the store operation itself fails.
    pub fn open_or_empty<S: CommitGroupStore>(store: &S) -> Result<Self, String> {
        match store.get_named(CLEANUP_QUEUE_PAGE_NAME)? {
            Some(page_bytes) => {
                let entries = unseal_and_deserialize_page(&page_bytes)?;
                let mut tree: BPlusTree<u64, CleanupWorkItemV1, MAX_LEAF, MAX_INTERNAL> =
                    BPlusTree::new();
                let mut max_id = 0u64;
                for (id, item) in entries {
                    tree.insert(id, item);
                    if id > max_id {
                        max_id = id;
                    }
                }
                Ok(Self {
                    tree,
                    next_entry_id: max_id.saturating_add(1),
                    dirty: false,
                })
            }
            None => Ok(Self::new()),
        }
    }

    // ------------------------------------------------------------------
    // Query
    // ------------------------------------------------------------------

    /// Number of entries in the queue (including completed items).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if the queue has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns `true` if the in-memory tree has uncommitted changes.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Number of pending (not-yet-complete) entries.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.tree
            .entries()
            .iter()
            .filter(|(_, item)| !item.is_complete())
            .count()
    }

    /// Number of completed entries.
    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.tree
            .entries()
            .iter()
            .filter(|(_, item)| item.is_complete())
            .count()
    }

    /// Look up a work item by entry ID.
    #[must_use]
    pub fn get(&self, entry_id: &u64) -> Option<&CleanupWorkItemV1> {
        self.tree.get(entry_id)
    }

    /// Return all entries in entry-ID order.
    #[must_use]
    pub fn entries(&self) -> Vec<(u64, CleanupWorkItemV1)> {
        self.tree.entries()
    }

    /// Next entry ID that will be assigned.
    #[must_use]
    pub fn next_entry_id(&self) -> u64 {
        self.next_entry_id
    }
}

impl Default for CleanupQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CleanupQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CleanupQueue(entries={} pending={} next_id={})",
            self.len(),
            self.pending_count(),
            self.next_entry_id
        )
    }
}

// ---------------------------------------------------------------------------
// Page serialization helpers
// ---------------------------------------------------------------------------

/// Compute the BLAKE3-256 hash of raw page bytes, domain-separated for the
/// cleanup queue so that a page can never be mistaken for another kind of
/// TideFS blob.
#[must_use]
fn hash_page(raw: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CLEANUP_QUEUE_DOMAIN);
    hasher.update(raw);
    hasher.finalize().into()
}

/// Seal a serialized page by prepending its BLAKE3-256 hash.
///
/// Layout: `[hash: 32 bytes][page_payload: N bytes]`
#[must_use]
fn seal_page(entries: &[(u64, CleanupWorkItemV1)]) -> Vec<u8> {
    let raw = serialize_page(entries);
    let hash = hash_page(&raw);
    let mut sealed = Vec::with_capacity(32 + raw.len());
    sealed.extend_from_slice(&hash);
    sealed.extend_from_slice(&raw);
    sealed
}

/// Verify the BLAKE3-256 hash of a sealed page blob and return the
/// deserialized entry list.
///
/// Returns an error if the blob is shorter than 32 bytes, or if the
/// hash does not match the remaining payload.
fn unseal_and_deserialize_page(sealed: &[u8]) -> Result<Vec<(u64, CleanupWorkItemV1)>, String> {
    if sealed.len() < 32 {
        return Err("cleanup queue sealed blob too short for hash".to_string());
    }
    let (hash_bytes, raw) = sealed.split_at(32);
    let expected_hash: &[u8; 32] = hash_bytes.try_into().unwrap();
    let computed = hash_page(raw);
    if computed != *expected_hash {
        return Err("cleanup queue page BLAKE3 checksum mismatch".to_string());
    }
    deserialize_page(raw)
}

/// Serialize a sorted entry list into a raw page blob (no hash prefix).
///
/// Format: `entry_count: u64 LE` followed by `entry_count` × 128-byte
/// `CleanupWorkItemV1` records packed contiguously.
fn serialize_page(entries: &[(u64, CleanupWorkItemV1)]) -> Vec<u8> {
    let count = entries.len() as u64;
    let header = count.to_le_bytes();
    let mut buf = Vec::with_capacity(8 + entries.len() * 128);
    buf.extend_from_slice(&header);
    for (_id, item) in entries {
        buf.extend_from_slice(&serialize_work_item(item));
    }
    buf
}

/// Deserialize a raw page blob (without BLAKE3 hash) into a sorted entry
/// list.
///
/// Callers should prefer [`unseal_and_deserialize_page`] which verifies
/// integrity before parsing.
///
/// Returns an error if the blob is too short, has an inconsistent size,
/// or any work item fails its magic check.
fn deserialize_page(bytes: &[u8]) -> Result<Vec<(u64, CleanupWorkItemV1)>, String> {
    if bytes.len() < 8 {
        return Err("cleanup queue page too short for header".to_string());
    }
    let count = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize;
    let expected_len = 8 + count * 128;
    if bytes.len() != expected_len {
        return Err(format!(
            "cleanup queue page size mismatch: expected {} bytes, got {}",
            expected_len,
            bytes.len()
        ));
    }
    // Assign entry IDs sequentially (1-based, in order of appearance).
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 8 + i * 128;
        let item = deserialize_work_item(&bytes[offset..offset + 128])?;
        let id = (i as u64).saturating_add(1);
        entries.push((id, item));
    }
    Ok(entries)
}

/// Serialize a `CleanupWorkItemV1` to its 128-byte on-media representation.
///
/// Layout:
/// ```text
/// [0..8)    magic [u8; 8]
/// [8..16)   inode_id u64 BE
/// [16]      kind u8
/// [17..25)  created_commit_group u64 BE
/// [25..33)  extent_map_root u64 BE (BtreeRootPointer.0)
/// [33..41)  reserved/padding (u64 zero)
/// [41..105) cursor [u8; 64]
/// [105..113) bytes_to_free_estimate u64 BE
/// [113..121) extents_processed u64 BE
/// [121]     flags u8
/// [122..128) reserved [u8; 6]
/// ```
fn serialize_work_item(item: &CleanupWorkItemV1) -> [u8; 128] {
    let mut buf = [0u8; 128];
    buf[0..8].copy_from_slice(&item.magic);
    buf[8..16].copy_from_slice(&item.inode_id.to_be_bytes());
    buf[16] = item.kind as u8;
    buf[17..25].copy_from_slice(&item.created_commit_group.to_be_bytes());
    buf[25..33].copy_from_slice(&item.extent_map_root.0.to_be_bytes());
    // bytes 33..41: reserved (zero)
    buf[41..105].copy_from_slice(&item.cursor);
    buf[105..113].copy_from_slice(&item.bytes_to_free_estimate.to_be_bytes());
    buf[113..121].copy_from_slice(&item.extents_processed.to_be_bytes());
    buf[121] = item.flags.as_u8();
    buf[122..128].copy_from_slice(&item.reserved);
    buf
}

/// Deserialize a `CleanupWorkItemV1` from its 128-byte on-media representation.
fn deserialize_work_item(bytes: &[u8]) -> Result<CleanupWorkItemV1, String> {
    if bytes.len() != 128 {
        return Err("work item must be exactly 128 bytes".to_string());
    }
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0..8]);

    let inode_id = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);

    let kind = tidefs_types_deferred_cleanup_core::WorkItemKind::try_from(bytes[16])
        .map_err(|e| format!("invalid WorkItemKind: {e}"))?;

    let created_commit_group = u64::from_be_bytes([
        bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23], bytes[24],
    ]);

    let root_ptr = u64::from_be_bytes([
        bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31], bytes[32],
    ]);

    let mut cursor = [0u8; 64];
    cursor.copy_from_slice(&bytes[41..105]);

    let bytes_to_free_estimate = u64::from_be_bytes([
        bytes[105], bytes[106], bytes[107], bytes[108], bytes[109], bytes[110], bytes[111],
        bytes[112],
    ]);

    let extents_processed = u64::from_be_bytes([
        bytes[113], bytes[114], bytes[115], bytes[116], bytes[117], bytes[118], bytes[119],
        bytes[120],
    ]);

    let flags = tidefs_types_deferred_cleanup_core::WorkItemFlags::from_u8(bytes[121]);

    let mut reserved = [0u8; 6];
    reserved.copy_from_slice(&bytes[122..128]);

    Ok(CleanupWorkItemV1 {
        magic,
        inode_id,
        kind,
        created_commit_group,
        extent_map_root: BtreeRootPointer(root_ptr),
        cursor,
        bytes_to_free_estimate,
        extents_processed,
        flags,
        reserved,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// BtreeCleanupOp — deferred B+tree node maintenance operation
// ---------------------------------------------------------------------------

/// Operation type for deferred B+tree node cleanup.
///
/// When a B+tree node falls below its minimum fill threshold after
/// deletions, one of these operations is enqueued for background
/// processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum BtreeCleanupOp {
    /// Merge this node with its left sibling.
    MergeLeft = 0,
    /// Merge this node with its right sibling.
    MergeRight = 1,
    /// Redistribute entries/children from a richer sibling to restore
    /// minimum fill without a full merge.
    Redistribute = 2,
}

impl BtreeCleanupOp {
    /// Number of defined variants.
    pub const COUNT: usize = 3;

    /// Stable name string for logging and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            BtreeCleanupOp::MergeLeft => "merge_left",
            BtreeCleanupOp::MergeRight => "merge_right",
            BtreeCleanupOp::Redistribute => "redistribute",
        }
    }
}

impl core::fmt::Display for BtreeCleanupOp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<BtreeCleanupOp> for u8 {
    fn from(op: BtreeCleanupOp) -> u8 {
        op as u8
    }
}

impl TryFrom<u8> for BtreeCleanupOp {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BtreeCleanupOp::MergeLeft),
            1 => Ok(BtreeCleanupOp::MergeRight),
            2 => Ok(BtreeCleanupOp::Redistribute),
            other => Err(format!("unknown BtreeCleanupOp discriminant: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// BtreeCleanupEntry — one deferred B+tree node maintenance entry
// ---------------------------------------------------------------------------

/// A single entry in the B+tree cleanup queue, identifying one under-full
/// node and the operation needed to restore structural invariants.
///
/// ## On-media layout (48 bytes, fixed-size)
///
/// ```text
/// [0..8)    tree_id: u64 LE
/// [8..16)   node_id: u64 LE
/// [16]      op: BtreeCleanupOp as u8
/// [17..25)  created_txg: u64 LE
/// [25]      flags: u8
/// [26..48)  reserved: [u8; 22]
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtreeCleanupEntry {
    /// Identifier of the B+tree instance (e.g., extent-map vs dir-index).
    pub tree_id: u64,
    /// Identifier of the under-full node within that tree.
    pub node_id: u64,
    /// The deferred maintenance operation.
    pub op: BtreeCleanupOp,
    /// Commit group (TXG) in which this entry was enqueued.
    pub created_txg: u64,
    /// Bitflags (bit 0 = processed, bits 1-7 reserved).
    pub flags: u8,
}

/// Total on-media size of `BtreeCleanupEntry` in bytes.
pub const BTREE_CLEANUP_ENTRY_SIZE: usize = 48;

impl BtreeCleanupEntry {
    /// Create a new pending entry.
    #[must_use]
    pub fn new(tree_id: u64, node_id: u64, op: BtreeCleanupOp, created_txg: u64) -> Self {
        Self {
            tree_id,
            node_id,
            op,
            created_txg,
            flags: 0,
        }
    }

    /// Returns `true` if this entry has been processed.
    #[must_use]
    pub fn is_processed(&self) -> bool {
        (self.flags & 1) != 0
    }

    /// Mark this entry as processed.
    pub fn mark_processed(&mut self) {
        self.flags |= 1;
    }

    /// Serialize to a fixed-size 48-byte buffer.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; BTREE_CLEANUP_ENTRY_SIZE] {
        let mut buf = [0u8; BTREE_CLEANUP_ENTRY_SIZE];
        buf[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.node_id.to_le_bytes());
        buf[16] = self.op as u8;
        buf[17..25].copy_from_slice(&self.created_txg.to_le_bytes());
        buf[25] = self.flags;
        // bytes 26..48 are reserved (zero)
        buf
    }

    /// Deserialize from a 48-byte slice.
    ///
    /// Returns an error if the operation discriminant is unrecognized.
    pub fn from_bytes(bytes: &[u8; BTREE_CLEANUP_ENTRY_SIZE]) -> Result<Self, String> {
        let tree_id = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let node_id = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let op = BtreeCleanupOp::try_from(bytes[16])?;
        let created_txg = u64::from_le_bytes([
            bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23], bytes[24],
        ]);
        let flags = bytes[25];
        Ok(Self {
            tree_id,
            node_id,
            op,
            created_txg,
            flags,
        })
    }
}

impl core::fmt::Display for BtreeCleanupEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BtreeCleanupEntry(tree={} node={} op={} txg={} {})",
            self.tree_id,
            self.node_id,
            self.op,
            self.created_txg,
            if self.is_processed() {
                "done"
            } else {
                "pending"
            }
        )
    }
}

// ---------------------------------------------------------------------------
// BtreeCleanupQueue — persistent queue for B+tree node maintenance
// ---------------------------------------------------------------------------

/// Persistent queue of deferred B+tree node maintenance operations.
///
/// Backed by a [`tidefs_btree::BPlusTree`] keyed by monotonically
/// increasing entry IDs. Supports `commit` (serialize to object store)
/// and `open` (deserialize from object store) for crash-safe persistence,
/// following the same pattern as [`CleanupQueue`].
#[derive(Clone, Debug)]
pub struct BtreeCleanupQueue {
    /// In-memory B+tree: entry_id -> BtreeCleanupEntry.
    tree: BPlusTree<u64, BtreeCleanupEntry, MAX_LEAF, MAX_INTERNAL>,
    /// Next entry_id to assign (monotonically increasing).
    next_entry_id: u64,
    /// Whether the in-memory state differs from the last committed state.
    dirty: bool,
}

/// Magic bytes for the `BtreeCleanupQueueRoot` on-media record: `b"BTCLNQRT"`.
pub const BTREE_CLEANUP_QUEUE_ROOT_MAGIC: [u8; 8] = *b"BTCLNQRT";

/// Current on-media format version.
pub const BTREE_CLEANUP_QUEUE_ROOT_VERSION: u32 = 1;

/// Total on-media size of `BtreeCleanupQueueRoot` in bytes.
pub const BTREE_CLEANUP_QUEUE_ROOT_SIZE: usize = 64;

/// Name used to store the btree cleanup queue page in the CommitGroupStore.
pub const BTREE_CLEANUP_QUEUE_PAGE_NAME: &str = "btree-cleanup-queue-v1";

/// BLAKE3 domain-separation context for the btree-cleanup-queue page blob.
const BTREE_CLEANUP_QUEUE_DOMAIN: &[u8] = b"TideFS BtreeCleanupQueue page v1";

/// Persisted root record for the btree cleanup queue.
///
/// ## On-media layout (64 bytes, fixed-size)
///
/// ```text
/// [0..8)    magic: b"BTCLNQRT"
/// [8..12)   version: u32 LE
/// [12..44)  root_page_key: [u8; 32]
/// [44..52)  entry_count: u64 LE
/// [52..64)  reserved: [u8; 12]
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtreeCleanupQueueRoot {
    /// Magic identifier.
    pub magic: [u8; 8],
    /// On-media format version.
    pub version: u32,
    /// Object-store key of the queue page blob.
    pub root_page_key: [u8; 32],
    /// Number of entries in the queue when this root was committed.
    pub entry_count: u64,
    /// Reserved; zero-filled on write.
    pub reserved: [u8; 12],
}

impl BtreeCleanupQueueRoot {
    #[must_use]
    pub fn new(root_page_key: [u8; 32], entry_count: u64) -> Self {
        Self {
            magic: BTREE_CLEANUP_QUEUE_ROOT_MAGIC,
            version: BTREE_CLEANUP_QUEUE_ROOT_VERSION,
            root_page_key,
            entry_count,
            reserved: [0u8; 12],
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; BTREE_CLEANUP_QUEUE_ROOT_SIZE] {
        let mut buf = [0u8; BTREE_CLEANUP_QUEUE_ROOT_SIZE];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..12].copy_from_slice(&self.version.to_le_bytes());
        buf[12..44].copy_from_slice(&self.root_page_key);
        buf[44..52].copy_from_slice(&self.entry_count.to_le_bytes());
        buf[52..64].copy_from_slice(&self.reserved);
        buf
    }

    #[must_use]
    pub fn from_bytes(bytes: &[u8; BTREE_CLEANUP_QUEUE_ROOT_SIZE]) -> Option<Self> {
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != BTREE_CLEANUP_QUEUE_ROOT_MAGIC {
            return None;
        }
        let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if version != BTREE_CLEANUP_QUEUE_ROOT_VERSION {
            return None;
        }
        let mut root_page_key = [0u8; 32];
        root_page_key.copy_from_slice(&bytes[12..44]);
        let entry_count = u64::from_le_bytes([
            bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
        ]);
        let mut reserved = [0u8; 12];
        reserved.copy_from_slice(&bytes[52..64]);
        Some(Self {
            magic,
            version,
            root_page_key,
            entry_count,
            reserved,
        })
    }
}

impl Default for BtreeCleanupQueueRoot {
    fn default() -> Self {
        Self {
            magic: BTREE_CLEANUP_QUEUE_ROOT_MAGIC,
            version: BTREE_CLEANUP_QUEUE_ROOT_VERSION,
            root_page_key: [0u8; 32],
            entry_count: 0,
            reserved: [0u8; 12],
        }
    }
}

impl BtreeCleanupQueue {
    /// Create an empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            next_entry_id: 1,
            dirty: false,
        }
    }

    /// Enqueue a cleanup entry for background processing.
    ///
    /// Returns the assigned entry ID.
    pub fn enqueue(&mut self, entry: BtreeCleanupEntry) -> u64 {
        let id = self.next_entry_id;
        self.next_entry_id = id.saturating_add(1);
        self.tree.insert(id, entry);
        self.dirty = true;
        id
    }

    /// Dequeue up to `max_count` pending (unprocessed) entries in
    /// entry-ID order.
    ///
    /// Returns a vector of `(entry_id, BtreeCleanupEntry)` pairs.
    /// The entries remain in the queue; call `ack_processed` after
    /// successful processing.
    #[must_use]
    pub fn dequeue_batch(&self, max_count: usize) -> Vec<(u64, BtreeCleanupEntry)> {
        let mut batch = Vec::new();
        for (id, entry) in self.tree.entries() {
            if batch.len() >= max_count {
                break;
            }
            if !entry.is_processed() {
                batch.push((id, entry));
            }
        }
        batch
    }

    /// Mark entries as processed by their IDs.
    ///
    /// Returns the number of entries that were found and marked.
    pub fn ack_processed(&mut self, entry_ids: &[u64]) -> usize {
        let mut marked = 0;
        for id in entry_ids {
            if self.tree.update(id, |e| e.mark_processed()) {
                marked += 1;
                self.dirty = true;
            }
        }
        marked
    }

    /// Remove all processed entries from the queue.
    ///
    /// Returns the number of entries removed.
    pub fn purge_processed(&mut self) -> usize {
        let to_remove: Vec<u64> = self
            .tree
            .entries()
            .iter()
            .filter(|(_, e)| e.is_processed())
            .map(|(id, _)| *id)
            .collect();
        let count = to_remove.len();
        for id in &to_remove {
            self.tree.delete(id);
        }
        if count > 0 {
            self.dirty = true;
        }
        count
    }

    /// Number of entries in the queue.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns `true` if the in-memory state differs from the last commit.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Number of pending (unprocessed) entries.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.tree
            .entries()
            .iter()
            .filter(|(_, e)| !e.is_processed())
            .count()
    }

    /// Number of processed entries awaiting purge.
    #[must_use]
    pub fn processed_count(&self) -> usize {
        self.tree
            .entries()
            .iter()
            .filter(|(_, e)| e.is_processed())
            .count()
    }

    /// Get a reference to an entry by its ID.
    #[must_use]
    pub fn get(&self, entry_id: &u64) -> Option<&BtreeCleanupEntry> {
        self.tree.get(entry_id)
    }

    /// Returns the next entry ID that will be assigned.
    #[must_use]
    pub fn next_entry_id(&self) -> u64 {
        self.next_entry_id
    }

    /// Returns all entries as a sorted vector.
    #[must_use]
    pub fn entries(&self) -> Vec<(u64, BtreeCleanupEntry)> {
        self.tree.entries()
    }

    /// Commit the queue to a [`CommitGroupStore`].
    ///
    /// Serializes the entry list to a page blob, stores it, and returns
    /// a root record suitable for persistence alongside the commit group.
    pub fn commit<S: CommitGroupStore>(
        &mut self,
        store: &mut S,
    ) -> Result<BtreeCleanupQueueRoot, String> {
        let entries = self.tree.entries();
        let sealed = seal_btree_cleanup_page(&entries);
        let key = store.put_named(BTREE_CLEANUP_QUEUE_PAGE_NAME, &sealed)?;
        let root = BtreeCleanupQueueRoot::new(key.as_bytes32(), entries.len() as u64);
        self.dirty = false;
        Ok(root)
    }

    /// Open a previously committed queue from a [`CommitGroupStore`].
    ///
    /// Returns an error if the stored page is missing, truncated, or
    /// contains an invalid entry.
    pub fn open<S: CommitGroupStore>(store: &S) -> Result<Self, String> {
        let blob = store
            .get_named(BTREE_CLEANUP_QUEUE_PAGE_NAME)?
            .ok_or_else(|| "btree cleanup queue page not found".to_string())?;
        let entries = unseal_and_deserialize_btree_cleanup_page(&blob)?;
        let mut tree = BPlusTree::new();
        let mut max_id = 0u64;
        for (id, entry) in &entries {
            tree.insert(*id, *entry);
            max_id = max_id.max(*id);
        }
        Ok(Self {
            tree,
            next_entry_id: max_id.saturating_add(1),
            dirty: false,
        })
    }

    /// Open a queue, returning an empty queue if none was previously committed.
    pub fn open_or_empty<S: CommitGroupStore>(store: &S) -> Result<Self, String> {
        match Self::open(store) {
            Ok(q) => Ok(q),
            Err(_) => Ok(Self::new()),
        }
    }
}

impl Default for BtreeCleanupQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Display for BtreeCleanupQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "BtreeCleanupQueue(entries={} pending={} next_id={})",
            self.len(),
            self.pending_count(),
            self.next_entry_id
        )
    }
}

// ---------------------------------------------------------------------------
// Btree cleanup page serialization
// ---------------------------------------------------------------------------

/// Compute the BLAKE3-256 hash of raw btree-cleanup page bytes.
#[must_use]
fn hash_btree_cleanup_page(raw: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BTREE_CLEANUP_QUEUE_DOMAIN);
    hasher.update(raw);
    hasher.finalize().into()
}

/// Seal a serialized btree-cleanup page by prepending its BLAKE3-256 hash.
#[must_use]
fn seal_btree_cleanup_page(entries: &[(u64, BtreeCleanupEntry)]) -> Vec<u8> {
    let raw = serialize_btree_cleanup_page(entries);
    let hash = hash_btree_cleanup_page(&raw);
    let mut sealed = Vec::with_capacity(32 + raw.len());
    sealed.extend_from_slice(&hash);
    sealed.extend_from_slice(&raw);
    sealed
}

/// Verify the BLAKE3-256 hash of a sealed btree-cleanup page blob and
/// return the deserialized entry list.
fn unseal_and_deserialize_btree_cleanup_page(
    sealed: &[u8],
) -> Result<Vec<(u64, BtreeCleanupEntry)>, String> {
    if sealed.len() < 32 {
        return Err("btree cleanup queue sealed blob too short for hash".to_string());
    }
    let (hash_bytes, raw) = sealed.split_at(32);
    let expected_hash: &[u8; 32] = hash_bytes.try_into().unwrap();
    let computed = hash_btree_cleanup_page(raw);
    if computed != *expected_hash {
        return Err("btree cleanup queue page BLAKE3 checksum mismatch".to_string());
    }
    deserialize_btree_cleanup_page(raw)
}

/// Serialize the entry list into a raw page blob (no hash prefix).
///
/// Format: `entry_count: u64 LE` followed by `entry_count` × 48-byte
/// `BtreeCleanupEntry` records packed contiguously.
fn serialize_btree_cleanup_page(entries: &[(u64, BtreeCleanupEntry)]) -> Vec<u8> {
    let count = entries.len() as u64;
    let mut buf = Vec::with_capacity(8 + entries.len() * BTREE_CLEANUP_ENTRY_SIZE);
    buf.extend_from_slice(&count.to_le_bytes());
    for (_id, entry) in entries {
        buf.extend_from_slice(&entry.to_bytes());
    }
    buf
}

/// Deserialize a page blob into an entry list.
fn deserialize_btree_cleanup_page(bytes: &[u8]) -> Result<Vec<(u64, BtreeCleanupEntry)>, String> {
    if bytes.len() < 8 {
        return Err("btree cleanup queue page too short for header".to_string());
    }
    let count = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]) as usize;
    let expected_len = 8 + count * BTREE_CLEANUP_ENTRY_SIZE;
    if bytes.len() != expected_len {
        return Err(format!(
            "btree cleanup queue page size mismatch: expected {}, got {}",
            expected_len,
            bytes.len()
        ));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let offset = 8 + i * BTREE_CLEANUP_ENTRY_SIZE;
        let mut entry_bytes = [0u8; BTREE_CLEANUP_ENTRY_SIZE];
        entry_bytes.copy_from_slice(&bytes[offset..offset + BTREE_CLEANUP_ENTRY_SIZE]);
        let entry = BtreeCleanupEntry::from_bytes(&entry_bytes)?;
        let id = (i as u64).saturating_add(1);
        entries.push((id, entry));
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Segment-cleanup helper
// ---------------------------------------------------------------------------

/// Create a [`CleanupWorkItemV1`] for a segment-cleanup operation.
///
/// Uses `segment_id` as the inode_id surrogate and marks the item with
/// [`WorkItemKind::TruncateFree`] as a generic reclaim-operation marker.
/// The caller is responsible for providing the correct `commit_group`.
#[must_use]
pub fn make_segment_cleanup_item(segment_id: u64, commit_group: u64) -> CleanupWorkItemV1 {
    CleanupWorkItemV1::new(
        segment_id,
        tidefs_types_deferred_cleanup_core::WorkItemKind::TruncateFree,
        commit_group,
        BtreeRootPointer::EMPTY,
        0, // bytes_to_free_estimate: filled by caller if needed
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tidefs_types_deferred_cleanup_core::{WorkItemFlags, WorkItemKind};

    // ── In-memory CommitGroupStore for tests ──────────────────────────────────

    #[derive(Debug, Default)]
    struct MemCommitGroupStore {
        blobs: HashMap<String, Vec<u8>>,
    }

    impl CommitGroupStore for MemCommitGroupStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<tidefs_commit_group::CommitGroupKey, String> {
            let key = tidefs_commit_group::CommitGroupKey::from_bytes32(
                blake3::hash(payload).as_bytes().to_owned(),
            );
            self.blobs.insert(name.to_string(), payload.to_vec());
            Ok(key)
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blobs.get(name).cloned())
        }
    }

    fn make_work_item(inode_id: u64, kind: WorkItemKind, commit_group: u64) -> CleanupWorkItemV1 {
        CleanupWorkItemV1::new(inode_id, kind, commit_group, BtreeRootPointer::EMPTY, 0)
    }

    fn cleanup_page(store: &MemCommitGroupStore) -> &[u8] {
        store
            .blobs
            .get(CLEANUP_QUEUE_PAGE_NAME)
            .expect("cleanup queue page")
            .as_slice()
    }

    // ── CleanupQueueRoot tests ────────────────────────────────────────

    #[test]
    fn root_record_roundtrip() {
        let key = [0x42u8; 32];
        let root = CleanupQueueRoot::new(key, 7);
        let bytes = root.to_bytes();
        assert_eq!(bytes.len(), CLEANUP_QUEUE_ROOT_SIZE);
        let root2 = CleanupQueueRoot::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(root, root2);
        assert_eq!(root2.entry_count, 7);
        assert_eq!(root2.root_page_key, key);
    }

    #[test]
    fn root_record_validate() {
        let root = CleanupQueueRoot::new([0u8; 32], 0);
        assert!(root.validate());
    }

    #[test]
    fn root_record_bad_magic() {
        let mut root = CleanupQueueRoot::new([0u8; 32], 0);
        root.magic = *b"BADMAGIC";
        assert!(!root.validate());
        let bytes = root.to_bytes();
        assert!(CleanupQueueRoot::from_bytes(&bytes).is_none());
    }

    #[test]
    fn root_record_bad_version() {
        let mut root = CleanupQueueRoot::new([0u8; 32], 0);
        root.version = 99;
        let bytes = root.to_bytes();
        assert!(CleanupQueueRoot::from_bytes(&bytes).is_none());
    }

    #[test]
    fn root_record_bad_reserved() {
        let mut root = CleanupQueueRoot::new([0u8; 32], 0);
        root.reserved[0] = 0xFF;
        assert!(!root.validate());
        // from_bytes should still deserialize it (it doesn't check reserved)
        let bytes = root.to_bytes();
        let root2 = CleanupQueueRoot::from_bytes(&bytes).unwrap();
        assert_eq!(root2.reserved[0], 0xFF);
    }

    #[test]
    fn root_record_display() {
        let root = CleanupQueueRoot::new([0u8; 32], 5);
        let s = format!("{root}");
        assert!(s.contains("CleanupQueueRoot"));
        assert!(s.contains("version=1"));
        assert!(s.contains("entries=5"));
    }

    #[test]
    fn root_record_default() {
        let root = CleanupQueueRoot::default();
        assert_eq!(root.magic, CLEANUP_QUEUE_ROOT_MAGIC);
        assert_eq!(root.version, CLEANUP_QUEUE_ROOT_VERSION);
        assert_eq!(root.entry_count, 0);
        assert_eq!(root.reserved, [0u8; 12]);
    }

    // ── Cleanup replay receipt tests ─────────────────────────────────

    #[test]
    fn replay_receipt_accepts_empty_queue() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit empty");

        let receipt = root.replay_receipt(&store).expect("receipt");

        assert_eq!(receipt.root_magic, CLEANUP_QUEUE_ROOT_MAGIC);
        assert_eq!(receipt.root_version, CLEANUP_QUEUE_ROOT_VERSION);
        assert_eq!(receipt.root_entry_count, 0);
        assert_eq!(receipt.page_entry_count, 0);
        assert_eq!(receipt.reserved_status, CleanupQueueReservedStatus::Zeroed);
        assert_eq!(
            receipt.replay_decision,
            CleanupQueueReplayDecision::TreatAsDurableEvidence
        );
        assert_eq!(
            receipt.validation_tier,
            CleanupQueueReplayValidationTier::RootPageSourceEvidence
        );
        let mut expected_digest = [0u8; 32];
        expected_digest.copy_from_slice(&cleanup_page(&store)[0..32]);
        assert_eq!(receipt.page_digest, expected_digest);
    }

    #[test]
    fn replay_receipt_accepts_populated_queue() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        q.enqueue(make_work_item(200, WorkItemKind::TruncateFree, 1));
        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit");

        let receipt =
            verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store)).expect("receipt");

        assert_eq!(receipt.root_entry_count, 2);
        assert_eq!(receipt.page_entry_count, 2);
        assert_eq!(receipt.root_page_key, root.root_page_key);
    }

    #[test]
    fn replay_receipt_rejects_invalid_magic() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        let mut root = q.commit(&mut store).expect("commit");
        root.magic = *b"BADMAGIC";

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("bad magic rejected");

        assert!(matches!(
            err,
            CleanupQueueReplayReceiptError::InvalidMagic { .. }
        ));
    }

    #[test]
    fn replay_receipt_rejects_unsupported_version() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        let mut root = q.commit(&mut store).expect("commit");
        root.version = CLEANUP_QUEUE_ROOT_VERSION + 1;

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("bad version rejected");

        assert_eq!(
            err,
            CleanupQueueReplayReceiptError::UnsupportedVersion {
                found: CLEANUP_QUEUE_ROOT_VERSION + 1
            }
        );
    }

    #[test]
    fn replay_receipt_rejects_nonzero_reserved_bytes() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        let mut root = q.commit(&mut store).expect("commit");
        root.reserved[3] = 0x7A;

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("reserved byte rejected");

        assert_eq!(
            err,
            CleanupQueueReplayReceiptError::NonZeroReserved {
                first_nonzero_index: 3,
                value: 0x7A
            }
        );
    }

    #[test]
    fn replay_receipt_rejects_page_digest_mismatch() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit");
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob[40] ^= 0xFF;

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("page digest mismatch rejected");

        assert!(matches!(
            err,
            CleanupQueueReplayReceiptError::PageDigestMismatch { .. }
        ));
    }

    #[test]
    fn replay_receipt_rejects_page_decode_failure() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit");
        let raw = 1u64.to_le_bytes();
        let digest = hash_page(&raw);
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob.clear();
        blob.extend_from_slice(&digest);
        blob.extend_from_slice(&raw);

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("page decode failure rejected");

        assert!(matches!(
            err,
            CleanupQueueReplayReceiptError::PageDecodeFailed { ref reason }
                if reason.contains("size mismatch")
        ));
    }

    #[test]
    fn replay_receipt_rejects_entry_count_mismatch() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        q.enqueue(make_work_item(200, WorkItemKind::TruncateFree, 1));
        let mut store = MemCommitGroupStore::default();
        let mut root = q.commit(&mut store).expect("commit");
        root.entry_count = 1;

        let err = verify_cleanup_queue_root_replay_receipt(&root, cleanup_page(&store))
            .expect_err("count mismatch rejected");

        assert_eq!(
            err,
            CleanupQueueReplayReceiptError::EntryCountMismatch {
                root_entry_count: 1,
                page_entry_count: 2
            }
        );
    }

    // ── CleanupQueue basic operations ─────────────────────────────────

    #[test]
    fn new_queue_is_empty() {
        let q = CleanupQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(!q.is_dirty());
    }

    #[test]
    fn enqueue_assigns_sequential_ids() {
        let mut q = CleanupQueue::new();
        let id1 = q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let id2 = q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 1));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(q.len(), 2);
        assert!(q.is_dirty());
    }

    #[test]
    fn dequeue_pending_returns_oldest_first() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 2));

        let item = q.dequeue_pending().expect("should have item");
        assert_eq!(item.inode_id, 100);
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn dequeue_pending_skips_completed() {
        let mut q = CleanupQueue::new();
        let id1 = q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let _id2 = q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 2));
        q.mark_complete(id1);

        let item = q.dequeue_pending().expect("should skip completed");
        assert_eq!(item.inode_id, 101); // id2, since id1 is complete
        assert_eq!(item.kind, WorkItemKind::TruncateFree);
    }

    #[test]
    fn dequeue_pending_empty_returns_none() {
        let mut q = CleanupQueue::new();
        assert!(q.dequeue_pending().is_none());
    }

    #[test]
    fn mark_complete_updates_item() {
        let mut q = CleanupQueue::new();
        let id = q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        assert!(q.mark_complete(id));
        assert!(q.get(&id).unwrap().is_complete());
        assert!(!q.mark_complete(999)); // nonexistent
    }

    #[test]
    fn purge_completed_removes_done_items() {
        let mut q = CleanupQueue::new();
        let id1 = q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let id2 = q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 1));
        q.mark_complete(id1);
        assert_eq!(q.len(), 2);
        let removed = q.purge_completed();
        assert_eq!(removed, 1);
        assert_eq!(q.len(), 1);
        assert!(q.get(&id2).is_some());
        assert!(q.get(&id1).is_none());
    }

    #[test]
    fn pending_and_completed_counts() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let id2 = q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 1));
        assert_eq!(q.pending_count(), 2);
        assert_eq!(q.completed_count(), 0);
        q.mark_complete(id2);
        assert_eq!(q.pending_count(), 1);
        assert_eq!(q.completed_count(), 1);
    }

    #[test]
    fn entries_returns_ordered() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        q.enqueue(make_work_item(101, WorkItemKind::TruncateFree, 2));
        let entries = q.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, 1);
        assert_eq!(entries[1].0, 2);
    }

    // ── Persistence: commit + open round-trip ─────────────────────────

    #[test]
    fn commit_and_open_roundtrip() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 5));
        q.enqueue(make_work_item(200, WorkItemKind::TruncateFree, 5));
        q.enqueue(make_work_item(300, WorkItemKind::RmdirFree, 5));

        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit");
        assert_eq!(root.entry_count, 3);
        assert!(!q.is_dirty());

        let q2 = CleanupQueue::open(&store).expect("open");
        assert_eq!(q2.len(), 3);
        assert!(!q2.is_dirty());

        let entries = q2.entries();
        assert_eq!(entries[0].1.inode_id, 100);
        assert_eq!(entries[1].1.inode_id, 200);
        assert_eq!(entries[2].1.inode_id, 300);
        assert_eq!(q2.next_entry_id(), 4);
    }

    #[test]
    fn open_empty_store_returns_error() {
        let store = MemCommitGroupStore::default();
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn open_or_empty_empty_store_returns_empty_queue() {
        let store = MemCommitGroupStore::default();
        let q = CleanupQueue::open_or_empty(&store).expect("open_or_empty");
        assert!(q.is_empty());
        assert_eq!(q.next_entry_id(), 1);
    }

    #[test]
    fn open_or_empty_existing_store_returns_populated_queue() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(42, WorkItemKind::SnapDelete, 3));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = CleanupQueue::open_or_empty(&store).expect("open_or_empty");
        assert_eq!(q2.len(), 1);
        assert_eq!(q2.entries()[0].1.inode_id, 42);
    }

    #[test]
    fn roundtrip_preserves_completion_state() {
        let mut q = CleanupQueue::new();
        let id1 = q.enqueue(make_work_item(10, WorkItemKind::UnlinkFree, 1));
        let id2 = q.enqueue(make_work_item(20, WorkItemKind::TruncateFree, 1));
        q.mark_complete(id2);

        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = CleanupQueue::open(&store).expect("open");
        assert_eq!(q2.pending_count(), 1);
        assert_eq!(q2.completed_count(), 1);
        assert!(q2.get(&id2).unwrap().is_complete());
        assert!(!q2.get(&id1).unwrap().is_complete());
    }

    #[test]
    fn roundtrip_preserves_cursor_and_flags() {
        let mut item = make_work_item(77, WorkItemKind::PunchHoleFree, 9);
        item.cursor[0] = 0xAB;
        item.cursor[63] = 0xCD;
        item.bytes_to_free_estimate = 1_000_000;
        item.extents_processed = 42;

        let mut q = CleanupQueue::new();
        q.enqueue(item.clone());
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = CleanupQueue::open(&store).expect("open");
        let restored = q2.entries()[0].1.clone();
        assert_eq!(restored.cursor[0], 0xAB);
        assert_eq!(restored.cursor[63], 0xCD);
        assert_eq!(restored.bytes_to_free_estimate, 1_000_000);
        assert_eq!(restored.extents_processed, 42);
    }

    #[test]
    fn roundtrip_preserves_btree_root_pointer() {
        let mut item = make_work_item(1, WorkItemKind::UnlinkFree, 1);
        item.extent_map_root = BtreeRootPointer(0xDEAD_BEEF_CAFE_BABE);

        let mut q = CleanupQueue::new();
        q.enqueue(item);
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = CleanupQueue::open(&store).expect("open");
        assert_eq!(
            q2.entries()[0].1.extent_map_root,
            BtreeRootPointer(0xDEAD_BEEF_CAFE_BABE)
        );
    }

    // ── Crash simulation ──────────────────────────────────────────────

    #[test]
    fn crash_before_commit_data_lost() {
        // This tests the expected behavior: if we crash before commit,
        // the data is gone. The queue is durable only after commit.
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));

        // Simulate crash: open from a fresh store (no commit happened)
        let store = MemCommitGroupStore::default();
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn crash_after_commit_data_survives() {
        let mut store = MemCommitGroupStore::default();

        // First session: enqueue and commit
        {
            let mut q = CleanupQueue::new();
            q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
            q.enqueue(make_work_item(200, WorkItemKind::TruncateFree, 1));
            q.commit(&mut store).expect("commit");
        }

        // Simulate crash and recovery: open from same store
        let q2 = CleanupQueue::open(&store).expect("recover");
        assert_eq!(q2.len(), 2);
        assert_eq!(q2.entries()[0].1.inode_id, 100);
        assert_eq!(q2.entries()[1].1.inode_id, 200);
    }

    #[test]
    fn crash_after_commit_preserves_partial_progress() {
        let mut store = MemCommitGroupStore::default();

        // Session 1: enqueue 3 items, complete 1, commit
        {
            let mut q = CleanupQueue::new();
            q.enqueue(make_work_item(10, WorkItemKind::UnlinkFree, 1));
            let id2 = q.enqueue(make_work_item(20, WorkItemKind::TruncateFree, 1));
            q.enqueue(make_work_item(30, WorkItemKind::RmdirFree, 1));
            q.mark_complete(id2);
            q.commit(&mut store).expect("commit");
        }

        // Session 2 (after crash): dequeue oldest pending, complete it, commit
        {
            let mut q = CleanupQueue::open(&store).expect("recover");
            assert_eq!(q.len(), 3);
            assert_eq!(q.pending_count(), 2);
            assert_eq!(q.completed_count(), 1);

            // Process the oldest pending item (entry_id=1)
            let item = q.dequeue_pending().expect("pending item");
            assert_eq!(item.inode_id, 10);
            assert_eq!(q.len(), 2);
            q.commit(&mut store).expect("commit");
        }

        // Session 3: verify state
        {
            let q = CleanupQueue::open(&store).expect("recover");
            assert_eq!(q.len(), 2);
            assert_eq!(q.pending_count(), 1); // only entry_id=3 left pending
            assert_eq!(q.completed_count(), 1); // entry_id=2
        }
    }

    // ── Page corruption detection ─────────────────────────────────────

    #[test]
    fn corrupted_page_rejected() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        // Corrupt the stored page
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob[0] = 0xFF; // corrupt the entry count
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn truncated_page_rejected() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        // Truncate the page
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob.truncate(10);
        assert!(CleanupQueue::open(&store).is_err());
    }

    // ── BLAKE3 integrity verification ──────────────────────────────

    #[test]
    fn sealed_blob_payload_tampered_rejected() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        // Corrupt a byte in the payload (after the 32-byte hash)
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        assert!(blob.len() > 33);
        blob[40] ^= 0xFF; // flip bits in the payload
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn sealed_blob_hash_corrupted_rejected() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        // Corrupt a byte in the hash prefix
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        assert!(blob.len() > 32);
        blob[5] ^= 0xFF;
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn sealed_blob_too_short_for_hash_rejected() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(100, WorkItemKind::UnlinkFree, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        // Truncate to fewer than 32 bytes (no complete hash)
        let blob = store.blobs.get_mut(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob.truncate(20);
        assert!(CleanupQueue::open(&store).is_err());
    }

    #[test]
    fn sealed_empty_queue_roundtrip_preserves_domain() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit empty");

        // Verify the sealed blob has the expected minimum size (32 hash + 8 header)
        let blob = store.blobs.get(CLEANUP_QUEUE_PAGE_NAME).unwrap();
        assert_eq!(blob.len(), 32 + 8); // hash + entry_count=0 header

        let q2 = CleanupQueue::open(&store).expect("open empty sealed");
        assert!(q2.is_empty());
    }

    #[test]
    fn empty_queue_commit_and_reopen() {
        let mut q = CleanupQueue::new();
        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit empty");
        assert_eq!(root.entry_count, 0);

        let q2 = CleanupQueue::open(&store).expect("open empty");
        assert!(q2.is_empty());
        assert_eq!(q2.next_entry_id(), 1);
    }

    // ── Large queue stress test ───────────────────────────────────────

    #[test]
    fn large_queue_roundtrip() {
        let mut q = CleanupQueue::new();
        for i in 0..500u64 {
            q.enqueue(make_work_item(i, WorkItemKind::UnlinkFree, i % 10));
        }
        assert_eq!(q.len(), 500);

        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = CleanupQueue::open(&store).expect("open");
        assert_eq!(q2.len(), 500);
        for i in 0..500u64 {
            let item = q2.get(&(i + 1)).expect("item should exist");
            assert_eq!(item.inode_id, i);
        }
    }

    // ── Work item serialization roundtrip ─────────────────────────────

    #[test]
    fn work_item_serialization_roundtrip() {
        let item = make_work_item(0xABCD, WorkItemKind::RenameOverwrite, 42);
        let bytes = serialize_work_item(&item);
        let restored = deserialize_work_item(&bytes).expect("deserialize");
        assert_eq!(item, restored);
    }

    #[test]
    fn work_item_serialization_preserves_all_fields() {
        let mut item = CleanupWorkItemV1::new(
            0xCAFE,
            WorkItemKind::PunchHoleFree,
            99,
            BtreeRootPointer(0xBEEF),
            8192,
        );
        item.cursor[10] = 0x42;
        item.extents_processed = 7;
        item.flags = WorkItemFlags::COMPLETE;

        let bytes = serialize_work_item(&item);
        let restored = deserialize_work_item(&bytes).expect("deserialize");
        assert_eq!(restored.magic, item.magic);
        assert_eq!(restored.inode_id, 0xCAFE);
        assert_eq!(restored.kind, WorkItemKind::PunchHoleFree);
        assert_eq!(restored.created_commit_group, 99);
        assert_eq!(restored.extent_map_root, BtreeRootPointer(0xBEEF));
        assert_eq!(restored.cursor, item.cursor);
        assert_eq!(restored.bytes_to_free_estimate, 8192);
        assert_eq!(restored.extents_processed, 7);
        assert!(restored.is_complete());
        assert_eq!(restored.reserved, [0u8; 6]);
    }

    #[test]
    fn deserialize_invalid_kind_rejected() {
        let item = make_work_item(1, WorkItemKind::UnlinkFree, 1);
        let mut bytes = serialize_work_item(&item);
        bytes[16] = 255; // invalid kind
        assert!(deserialize_work_item(&bytes).is_err());
    }

    // ── Display ───────────────────────────────────────────────────────

    #[test]
    fn cleanup_queue_display() {
        let mut q = CleanupQueue::new();
        q.enqueue(make_work_item(42, WorkItemKind::TruncateFree, 1));
        let s = format!("{q}");
        assert!(s.contains("CleanupQueue"));
        assert!(s.contains("entries=1"));
        assert!(s.contains("pending=1"));
    }
    // ── BtreeCleanupOp ───────────────────────────────────────────────

    #[test]
    fn btree_cleanup_op_discriminants() {
        assert_eq!(BtreeCleanupOp::MergeLeft as u8, 0);
        assert_eq!(BtreeCleanupOp::MergeRight as u8, 1);
        assert_eq!(BtreeCleanupOp::Redistribute as u8, 2);
        assert_eq!(BtreeCleanupOp::COUNT, 3);
    }

    #[test]
    fn btree_cleanup_op_roundtrip_u8() {
        for op in &[
            BtreeCleanupOp::MergeLeft,
            BtreeCleanupOp::MergeRight,
            BtreeCleanupOp::Redistribute,
        ] {
            let v: u8 = (*op).into();
            let restored = BtreeCleanupOp::try_from(v).expect("roundtrip");
            assert_eq!(restored, *op);
        }
    }

    #[test]
    fn btree_cleanup_op_invalid_discriminant() {
        assert!(BtreeCleanupOp::try_from(99).is_err());
    }

    #[test]
    fn btree_cleanup_op_display() {
        assert_eq!(format!("{}", BtreeCleanupOp::MergeLeft), "merge_left");
        assert_eq!(format!("{}", BtreeCleanupOp::MergeRight), "merge_right");
        assert_eq!(format!("{}", BtreeCleanupOp::Redistribute), "redistribute");
    }

    // ── BtreeCleanupEntry ────────────────────────────────────────────

    #[test]
    fn btree_cleanup_entry_new() {
        let e = BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 5);
        assert_eq!(e.tree_id, 1);
        assert_eq!(e.node_id, 42);
        assert_eq!(e.op, BtreeCleanupOp::MergeLeft);
        assert_eq!(e.created_txg, 5);
        assert!(!e.is_processed());
    }

    #[test]
    fn btree_cleanup_entry_mark_processed() {
        let mut e = BtreeCleanupEntry::new(1, 1, BtreeCleanupOp::Redistribute, 1);
        assert!(!e.is_processed());
        e.mark_processed();
        assert!(e.is_processed());
    }

    #[test]
    fn btree_cleanup_entry_roundtrip() {
        let e = BtreeCleanupEntry::new(0xCAFE, 0xBEEF, BtreeCleanupOp::MergeRight, 99);
        let bytes = e.to_bytes();
        assert_eq!(bytes.len(), BTREE_CLEANUP_ENTRY_SIZE);
        let restored = BtreeCleanupEntry::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(restored, e);
    }

    #[test]
    fn btree_cleanup_entry_roundtrip_processed() {
        let mut e = BtreeCleanupEntry::new(7, 3, BtreeCleanupOp::MergeLeft, 10);
        e.mark_processed();
        let bytes = e.to_bytes();
        let restored = BtreeCleanupEntry::from_bytes(&bytes).expect("roundtrip");
        assert!(restored.is_processed());
    }

    #[test]
    fn btree_cleanup_entry_display() {
        let e = BtreeCleanupEntry::new(1, 2, BtreeCleanupOp::MergeLeft, 3);
        let s = format!("{e}");
        assert!(s.contains("tree=1"));
        assert!(s.contains("node=2"));
        assert!(s.contains("merge_left"));
        assert!(s.contains("txg=3"));
        assert!(s.contains("pending"));
    }

    // ── BtreeCleanupQueue basic ──────────────────────────────────────

    #[test]
    fn btree_queue_new_is_empty() {
        let q = BtreeCleanupQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert!(!q.is_dirty());
    }

    #[test]
    fn btree_queue_enqueue() {
        let mut q = BtreeCleanupQueue::new();
        let id = q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        assert_eq!(id, 1);
        assert_eq!(q.len(), 1);
        assert!(q.is_dirty());
        assert_eq!(q.pending_count(), 1);
        assert_eq!(q.processed_count(), 0);
    }

    #[test]
    fn btree_queue_enqueue_multiple_sequential_ids() {
        let mut q = BtreeCleanupQueue::new();
        let id1 = q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        let id2 = q.enqueue(BtreeCleanupEntry::new(1, 20, BtreeCleanupOp::MergeRight, 1));
        let id3 = q.enqueue(BtreeCleanupEntry::new(
            2,
            5,
            BtreeCleanupOp::Redistribute,
            1,
        ));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn btree_queue_dequeue_batch_respects_limit() {
        let mut q = BtreeCleanupQueue::new();
        for i in 0..10 {
            q.enqueue(BtreeCleanupEntry::new(1, i, BtreeCleanupOp::MergeLeft, 1));
        }
        let batch = q.dequeue_batch(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].0, 1);
        assert_eq!(batch[1].0, 2);
        assert_eq!(batch[2].0, 3);
    }

    #[test]
    fn btree_queue_dequeue_batch_skips_processed() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        q.enqueue(BtreeCleanupEntry::new(1, 20, BtreeCleanupOp::MergeRight, 1));
        q.enqueue(BtreeCleanupEntry::new(
            1,
            30,
            BtreeCleanupOp::Redistribute,
            1,
        ));

        // Mark second entry as processed
        q.ack_processed(&[2]);

        let batch = q.dequeue_batch(10);
        assert_eq!(batch.len(), 2); // only 1 and 3 are pending
        assert_eq!(batch[0].0, 1);
        assert_eq!(batch[1].0, 3);
    }

    #[test]
    fn btree_queue_ack_processed() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        q.enqueue(BtreeCleanupEntry::new(1, 20, BtreeCleanupOp::MergeRight, 1));

        let marked = q.ack_processed(&[1]);
        assert_eq!(marked, 1);
        assert!(q.get(&1).unwrap().is_processed());
        assert_eq!(q.pending_count(), 1);
        assert_eq!(q.processed_count(), 1);
    }

    #[test]
    fn btree_queue_ack_processed_nonexistent() {
        let mut q = BtreeCleanupQueue::new();
        assert_eq!(q.ack_processed(&[999]), 0);
    }

    #[test]
    fn btree_queue_purge_processed() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        q.enqueue(BtreeCleanupEntry::new(1, 20, BtreeCleanupOp::MergeRight, 1));
        q.enqueue(BtreeCleanupEntry::new(
            1,
            30,
            BtreeCleanupOp::Redistribute,
            1,
        ));

        q.ack_processed(&[1, 3]);
        assert_eq!(q.purge_processed(), 2);
        assert_eq!(q.len(), 1);
        assert!(q.get(&2).is_some()); // only entry 2 remains
        assert!(q.get(&1).is_none());
        assert!(q.get(&3).is_none());
    }

    // ── BtreeCleanupQueue persistence ────────────────────────────────

    #[test]
    fn btree_queue_commit_and_open_roundtrip() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 5));
        q.enqueue(BtreeCleanupEntry::new(2, 20, BtreeCleanupOp::MergeRight, 5));
        q.enqueue(BtreeCleanupEntry::new(
            1,
            30,
            BtreeCleanupOp::Redistribute,
            5,
        ));

        let mut store = MemCommitGroupStore::default();
        let root = q.commit(&mut store).expect("commit");
        assert_eq!(root.entry_count, 3);
        assert!(!q.is_dirty());

        let q2 = BtreeCleanupQueue::open(&store).expect("open");
        assert_eq!(q2.len(), 3);
        assert!(!q2.is_dirty());
        assert_eq!(q2.pending_count(), 3);
    }

    #[test]
    fn btree_queue_persistence_preserves_processed_state() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 1, BtreeCleanupOp::MergeLeft, 1));
        q.enqueue(BtreeCleanupEntry::new(1, 2, BtreeCleanupOp::MergeRight, 1));
        q.ack_processed(&[1]);

        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = BtreeCleanupQueue::open(&store).expect("open");
        assert_eq!(q2.pending_count(), 1);
        assert_eq!(q2.processed_count(), 1);
        assert!(q2.get(&1).unwrap().is_processed());
        assert!(!q2.get(&2).unwrap().is_processed());
    }

    #[test]
    fn btree_queue_open_empty_store_error() {
        let store = MemCommitGroupStore::default();
        assert!(BtreeCleanupQueue::open(&store).is_err());
    }

    #[test]
    fn btree_queue_open_or_empty_returns_empty() {
        let store = MemCommitGroupStore::default();
        let q = BtreeCleanupQueue::open_or_empty(&store).expect("open_or_empty");
        assert!(q.is_empty());
    }

    #[test]
    fn btree_queue_open_or_empty_returns_populated() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(
            99,
            1,
            BtreeCleanupOp::Redistribute,
            7,
        ));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let q2 = BtreeCleanupQueue::open_or_empty(&store).expect("open_or_empty");
        assert_eq!(q2.len(), 1);
        assert_eq!(q2.entries()[0].1.tree_id, 99);
    }

    #[test]
    fn btree_queue_crash_survival() {
        let mut store = MemCommitGroupStore::default();

        // Session 1: enqueue, commit
        {
            let mut q = BtreeCleanupQueue::new();
            q.enqueue(BtreeCleanupEntry::new(1, 100, BtreeCleanupOp::MergeLeft, 1));
            q.enqueue(BtreeCleanupEntry::new(
                1,
                200,
                BtreeCleanupOp::MergeRight,
                1,
            ));
            q.commit(&mut store).expect("commit");
        }

        // Simulate crash: open from same store
        let q2 = BtreeCleanupQueue::open(&store).expect("recover");
        assert_eq!(q2.len(), 2);
        assert_eq!(q2.entries()[0].1.node_id, 100);
        assert_eq!(q2.entries()[1].1.node_id, 200);
    }

    // ── BLAKE3 integrity verification for btree cleanup queue ──────

    #[test]
    fn btree_queue_sealed_payload_tampered_rejected() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let blob = store.blobs.get_mut(BTREE_CLEANUP_QUEUE_PAGE_NAME).unwrap();
        assert!(blob.len() > 33);
        blob[40] ^= 0xFF;
        assert!(BtreeCleanupQueue::open(&store).is_err());
    }

    #[test]
    fn btree_queue_sealed_hash_corrupted_rejected() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let blob = store.blobs.get_mut(BTREE_CLEANUP_QUEUE_PAGE_NAME).unwrap();
        assert!(blob.len() > 32);
        blob[5] ^= 0xFF;
        assert!(BtreeCleanupQueue::open(&store).is_err());
    }

    #[test]
    fn btree_queue_sealed_too_short_rejected() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 1));
        let mut store = MemCommitGroupStore::default();
        q.commit(&mut store).expect("commit");

        let blob = store.blobs.get_mut(BTREE_CLEANUP_QUEUE_PAGE_NAME).unwrap();
        blob.truncate(20);
        assert!(BtreeCleanupQueue::open(&store).is_err());
    }

    #[test]
    fn btree_queue_dequeue_batch_empty() {
        let q = BtreeCleanupQueue::new();
        assert!(q.dequeue_batch(10).is_empty());
    }

    #[test]
    fn btree_queue_entries_ordered() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(
            3,
            30,
            BtreeCleanupOp::Redistribute,
            1,
        ));
        q.enqueue(BtreeCleanupEntry::new(1, 10, BtreeCleanupOp::MergeLeft, 1));
        q.enqueue(BtreeCleanupEntry::new(2, 20, BtreeCleanupOp::MergeRight, 1));

        let entries = q.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, 1);
        assert_eq!(entries[1].0, 2);
        assert_eq!(entries[2].0, 3);
    }

    #[test]
    fn btree_queue_display() {
        let mut q = BtreeCleanupQueue::new();
        q.enqueue(BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 1));
        let s = format!("{q}");
        assert!(s.contains("BtreeCleanupQueue"));
        assert!(s.contains("entries=1"));
        assert!(s.contains("pending=1"));
    }

    // ── BtreeCleanupQueueRoot ────────────────────────────────────────

    #[test]
    fn btree_queue_root_roundtrip() {
        let key = [0xABu8; 32];
        let root = BtreeCleanupQueueRoot::new(key, 42);
        let bytes = root.to_bytes();
        assert_eq!(bytes.len(), BTREE_CLEANUP_QUEUE_ROOT_SIZE);
        let root2 = BtreeCleanupQueueRoot::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(root2.entry_count, 42);
        assert_eq!(root2.root_page_key, key);
    }

    #[test]
    fn btree_queue_root_bad_magic() {
        let mut root = BtreeCleanupQueueRoot::new([0u8; 32], 0);
        root.magic = *b"BADMAGIC";
        let bytes = root.to_bytes();
        assert!(BtreeCleanupQueueRoot::from_bytes(&bytes).is_none());
    }

    #[test]
    fn btree_queue_root_default() {
        let root = BtreeCleanupQueueRoot::default();
        assert_eq!(root.magic, BTREE_CLEANUP_QUEUE_ROOT_MAGIC);
        assert_eq!(root.version, BTREE_CLEANUP_QUEUE_ROOT_VERSION);
        assert_eq!(root.entry_count, 0);
    }

    // ── B+tree underfull → BtreeCleanupQueue end-to-end ─────────────

    /// Simulates the write path: B+tree delete leaves under-full nodes,
    /// which are detected, enqueued, and processed by the cleanup queue.
    #[test]
    fn btree_underfull_to_cleanup_queue_end_to_end() {
        // MAX_LEAF=4, MAX_INTERNAL=4 for this test tree
        type TestTree = BPlusTree<u64, u64, 4, 4>;

        // Phase 1: build a tree and force an under-full leaf via rebuild()
        let mut t: TestTree = TestTree::new();
        for i in 0..9u64 {
            t.insert(i, i * 10);
        }
        let entries = t.entries();
        t.rebuild(&entries); // non-compact: leaves [4, 4, 1] -> last leaf under-full

        // Phase 2: detect under-full nodes
        let under = t.underfull_nodes(0.5);
        assert!(!under.is_empty(), "should detect under-full last leaf");

        // Phase 3: enqueue each under-full node in the cleanup queue
        let mut cq = BtreeCleanupQueue::new();
        for node in &under {
            // Determine operation based on fill ratio
            let op = if node.fill_ratio() < 0.25 {
                BtreeCleanupOp::MergeLeft
            } else {
                BtreeCleanupOp::Redistribute
            };
            let entry = BtreeCleanupEntry::new(
                1, // tree_id=1 for this test
                node.node_id.0,
                op,
                1, // txg
            );
            cq.enqueue(entry);
        }
        assert_eq!(cq.len(), under.len());
        assert_eq!(cq.pending_count(), under.len());

        // Phase 4: dequeue batch and process each entry
        let batch = cq.dequeue_batch(10);
        assert_eq!(batch.len(), under.len());

        // Mark all as processed
        let ids: Vec<u64> = batch.iter().map(|(id, _)| *id).collect();
        let marked = cq.ack_processed(&ids);
        assert_eq!(marked, ids.len());
        assert_eq!(cq.pending_count(), 0);
        assert_eq!(cq.processed_count(), ids.len());

        // Phase 5: commit and reopen — processed state survives
        let mut store = MemCommitGroupStore::default();
        cq.commit(&mut store).expect("commit");

        let cq2 = BtreeCleanupQueue::open(&store).expect("open");
        assert_eq!(cq2.len(), ids.len());
        assert_eq!(cq2.pending_count(), 0);
        assert_eq!(cq2.processed_count(), ids.len());

        // Phase 6: purge processed entries
        let mut cq3 = BtreeCleanupQueue::open(&store).expect("open");
        let purged = cq3.purge_processed();
        assert_eq!(purged, ids.len());
        assert!(cq3.is_empty());
    }

    /// Empty delete path: after a delete that leaves no under-full nodes,
    /// the cleanup queue remains empty.
    #[test]
    fn btree_no_underfull_after_delete_no_enqueue() {
        type TestTree = BPlusTree<u64, u64, 4, 4>;
        let mut t: TestTree = TestTree::new();
        // 8 entries with MAX_LEAF=4: compact produces 2 full leaves
        for i in 0..8u64 {
            t.insert(i, i * 100);
        }
        // Delete one entry — rebuild_compact redistributes evenly,
        // so no leaf falls below MIN_LEAF=2
        t.delete(&0);
        let under = t.underfull_nodes(0.5);
        assert!(under.is_empty());

        let cq = BtreeCleanupQueue::new();
        assert!(cq.is_empty());
    }

    /// Idempotent enqueue: enqueuing the same node twice results in two
    /// distinct entries (not deduplicated), since each enqueue is a
    /// separate deferred work request.
    #[test]
    fn btree_queue_idempotent_enqueue_creates_distinct_entries() {
        let mut cq = BtreeCleanupQueue::new();
        let e1 = BtreeCleanupEntry::new(1, 42, BtreeCleanupOp::MergeLeft, 1);
        let id1 = cq.enqueue(e1);
        let id2 = cq.enqueue(e1);
        assert_ne!(id1, id2);
        assert_eq!(cq.len(), 2);
        assert_eq!(cq.pending_count(), 2);
    }
}
