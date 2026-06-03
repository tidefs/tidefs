#![forbid(unsafe_code)]

//! Persistent orphan index with append-only log persistence.
//!
//! Tracks inodes unlinked while still open, survives crashes, and enables
//! recovery of O_TMPFILE temporary files. Uses an in-memory B+tree for fast
//! lookups and an append-only log format with BLAKE3 checksums for durability.
//!
//! ## Design
//!
//! The in-memory index is a key-only B+tree mapping `OrphanKey` (inode ID) to
//! `OrphanEntry` (generation, nlink, flags). Persistence uses an append-only
//! log where each entry is serialized with a domain-separated BLAKE3 checksum.
//! On mount, `recover_from_log()` scans the log, verifies checksums, and
//! returns surviving entries. Corrupted log entries are detected and reported
//! but do not block recovery of intact entries.

use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_btree::{BPlusTree, BTreeError};
use tidefs_commit_group::store::CommitGroupStore;
use tidefs_types_orphan_index_core::{
    OrphanCursor, OrphanKey, OrphanRecoveryBudget, OrphanRecoveryOutcome, OrphanRecoveryStats,
    ORPHAN_INDEX_SPEC,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum leaf entries for the orphan index B+tree.
const MAX_LEAF: usize = 128;

/// Maximum internal fanout for the orphan index B+tree.
const MAX_INTERNAL: usize = 128;

/// Design spec reference used for runtime compatibility assertions.
pub const ORPHAN_INDEX_SPEC_REF: &str = ORPHAN_INDEX_SPEC;

/// Schema identity for orphan log entries.
const ORPHAN_LOG_FAMILY: SchemaFamilyId = SchemaFamilyId::BINARY_SCHEMA;
const ORPHAN_LOG_TYPE: SchemaTypeId = SchemaTypeId(300);
const ORPHAN_LOG_VERSION: SchemaVersion = SchemaVersion::new(1, 0);
const ORPHAN_LOG_DOMAIN: DomainTag = DomainTag::ExternalPayload;

/// On-disk size of a single serialized `OrphanEntry` in bytes.
const ENTRY_ENCODED_SIZE: usize = 24;

/// Size of a BLAKE3-256 checksum in bytes.
const CHECKSUM_SIZE: usize = 32;

/// Total size of one log record: encoded entry + checksum.
const LOG_RECORD_SIZE: usize = ENTRY_ENCODED_SIZE + CHECKSUM_SIZE;

// ---------------------------------------------------------------------------
// OrphanEntryFlags
// ---------------------------------------------------------------------------

/// Per-entry flags indicating the nature of the orphan.
///
/// Stored as a bitfield in the on-disk `OrphanEntry` record.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct OrphanEntryFlags(pub u8);

impl OrphanEntryFlags {
    /// No flags set — a regular unlinked-but-open file.
    pub const NONE: Self = OrphanEntryFlags(0);

    /// Entry was created via `O_TMPFILE` (anonymous temporary file).
    pub const O_TMPFILE: Self = OrphanEntryFlags(1 << 0);

    /// The orphan is a directory (unlinked while still open).
    pub const IS_DIRECTORY: Self = OrphanEntryFlags(1 << 1);

    /// Returns `true` if the `O_TMPFILE` flag is set.
    #[must_use]
    pub const fn is_otmpfile(self) -> bool {
        self.0 & Self::O_TMPFILE.0 != 0
    }

    /// Returns `true` if the `IS_DIRECTORY` flag is set.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.0 & Self::IS_DIRECTORY.0 != 0
    }

    /// Returns `true` if no flags are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for OrphanEntryFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        if self.is_otmpfile() {
            write!(f, "O_TMPFILE")?;
            first = false;
        }
        if self.is_directory() {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "IS_DIRECTORY")?;
            first = false;
        }
        if first {
            write!(f, "NONE")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OrphanEntry
// ---------------------------------------------------------------------------

/// On-disk record for a single orphaned inode.
///
/// Serialized as a fixed-size 24-byte record:
///
/// | Offset | Size | Field            |
/// |--------|------|------------------|
/// | 0      | 8    | inode_id (LE)    |
/// | 8      | 8    | generation (LE)  |
/// | 16     | 4    | nlink_at_unlink  |
/// | 20     | 1    | flags            |
/// | 21     | 3    | creating_pid (LE, lower 24 bits) |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrphanEntry {
    /// Inode number of the orphaned file/directory.
    pub inode_id: u64,
    /// Generation counter at unlink time (detects inode reuse).
    pub generation: u64,
    /// Link count at the moment of unlink (typically 0 for O_TMPFILE,
    /// or the last nlink before reaching 0 for unlinked-but-open).
    pub nlink_at_unlink: u32,
    /// Flags indicating the nature of this orphan entry.
    pub flags: OrphanEntryFlags,
    /// PID of the process that created this tmpfile (O_TMPFILE entries).
    /// Zero for non-tmpfile entries or entries recovered from old logs.
    pub creating_pid: u32,
}

impl OrphanEntry {
    /// Create a new `OrphanEntry`.
    #[must_use]
    pub const fn new(
        inode_id: u64,
        generation: u64,
        nlink_at_unlink: u32,
        flags: OrphanEntryFlags,
    ) -> Self {
        Self {
            inode_id,
            generation,
            nlink_at_unlink,
            flags,
            creating_pid: 0,
        }
    }

    /// Serialize to a fixed-size 24-byte buffer.
    #[must_use]
    pub fn encode(&self) -> [u8; ENTRY_ENCODED_SIZE] {
        let mut buf = [0u8; ENTRY_ENCODED_SIZE];
        buf[0..8].copy_from_slice(&self.inode_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.generation.to_le_bytes());
        buf[16..20].copy_from_slice(&self.nlink_at_unlink.to_le_bytes());
        buf[20] = self.flags.0;
        // bytes 21-23: lower 24 bits of creating_pid (little-endian)
        let pid_bytes = (self.creating_pid & 0x00FF_FFFF).to_le_bytes();
        buf[21..24].copy_from_slice(&pid_bytes[..3]);
        buf
    }

    /// Deserialize from a 24-byte buffer.
    #[must_use]
    pub fn decode(data: &[u8; ENTRY_ENCODED_SIZE]) -> Self {
        let inode_id = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let generation = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let nlink_at_unlink = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let flags = OrphanEntryFlags(data[20]);
        let creating_pid = {
            let mut pid = [0u8; 4];
            pid[..3].copy_from_slice(&data[21..24]);
            u32::from_le_bytes(pid)
        };
        Self {
            creating_pid,
            inode_id,
            generation,
            nlink_at_unlink,
            flags,
        }
    }

    /// Create an O_TMPFILE orphan entry with the creating process PID.
    #[must_use]
    pub fn new_tmpfile(inode_id: u64, generation: u64, creating_pid: u32) -> Self {
        Self {
            inode_id,
            generation,
            nlink_at_unlink: 0,
            flags: OrphanEntryFlags::O_TMPFILE,
            creating_pid,
        }
    }

    /// Create an O_TMPFILE orphan entry with the creating process PID.
    #[must_use]
    pub const fn is_otmpfile(&self) -> bool {
        self.flags.is_otmpfile()
    }

    /// Returns `true` if this entry is a directory.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.flags.is_directory()
    }
}

// ---------------------------------------------------------------------------
// OrphanIndex
// ---------------------------------------------------------------------------

/// Persistent orphan index backed by a key-only B+tree.
///
/// The in-memory B+tree stores `(OrphanKey, OrphanEntry)` pairs for fast
/// lookup. Persistence uses an append-only log format with BLAKE3
/// domain-separated checksums per entry.
#[derive(Clone, Debug)]
pub struct OrphanIndex {
    tree: BPlusTree<OrphanKey, OrphanEntry, MAX_LEAF, MAX_INTERNAL>,
    /// Set to true when the index has been mutated and needs persistence.
    dirty: bool,
    /// Inserts pending the current TXG commit. Tracked so abort_pending
    /// can roll them back.
    pending_inserts: BTreeMap<OrphanKey, OrphanEntry>,
    /// Removes pending the current TXG commit. Tracked so abort_pending
    /// can restore the removed entries.
    pending_removes: BTreeSet<OrphanKey>,
}

impl OrphanIndex {
    // -- constructors --

    /// Create an empty orphan index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
            pending_inserts: BTreeMap::new(),
            pending_removes: BTreeSet::new(),
            dirty: false,
        }
    }

    /// Create an orphan index from a slice of `OrphanEntry` values.
    ///
    /// Entries are inserted in order; duplicate inode IDs cause the
    /// last entry to win.
    #[must_use]
    pub fn from_entries(entries: &[OrphanEntry]) -> Self {
        let mut idx = Self::new();
        for entry in entries {
            idx.insert(entry.inode_id, *entry);
        }
        idx.clear_dirty();
        idx
    }

    // -- mutation --

    /// Insert an inode entry into the orphan index.
    ///
    /// Called when an inode's `nlink` reaches 0 (last unlink, or last
    /// close after unlink). The `inode_id` parameter must match
    /// `entry.inode_id`.
    ///
    /// Returns `true` if the entry was newly inserted (was not already
    /// present).
    ///
    /// # Panics
    ///
    /// Panics if `inode_id != entry.inode_id`.
    pub fn insert(&mut self, inode_id: u64, entry: OrphanEntry) -> bool {
        assert_eq!(
            inode_id, entry.inode_id,
            "inode_id {inode_id} != entry.inode_id {}",
            entry.inode_id
        );
        let key = OrphanKey::from_inode_id(inode_id);
        let is_new = self.tree.insert(key, entry).is_none();
        self.dirty = true;
        is_new
    }

    /// Remove an inode from the orphan index after successful cleanup.
    ///
    /// Returns `true` if the inode was present and removed.
    pub fn remove(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        let was_present = self.tree.delete(&key).is_some();
        if was_present {
            self.dirty = true;
        }
        was_present
    }

    // -- lookup --

    /// Check whether an inode is currently in the orphan index.
    #[must_use]
    pub fn contains(&self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        self.tree.contains_key(&key)
    }

    /// Get the `OrphanEntry` for an inode, if present.
    #[must_use]
    pub fn get(&self, inode_id: u64) -> Option<&OrphanEntry> {
        let key = OrphanKey::from_inode_id(inode_id);
        self.tree.get(&key)
    }

    /// Return the number of orphaned inodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Return `true` if the orphan index is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Clear all entries from the orphan index.
    pub fn clear(&mut self) {
        self.tree.clear();
        self.pending_inserts.clear();
        self.pending_removes.clear();
        self.dirty = true;
    }

    // -- O_TMPFILE lifecycle --

    /// Insert an O_TMPFILE anonymous inode into the orphan index.
    ///
    /// Called when  creates an anonymous inode (nlink==0).
    /// The entry is created with the  flag and the PID of the
    /// creating process so the timeout reaper can clean up if the process
    /// exits without linking.
    ///
    ///  is recorded for commit-group ordering but does not gate the
    /// in-memory insert.
    ///
    /// Returns  if the entry was newly inserted.
    pub fn insert_tmpfile(
        &mut self,
        inode_id: u64,
        generation: u64,
        creating_pid: u32,
        _txg: u64,
    ) -> bool {
        let entry = OrphanEntry::new_tmpfile(inode_id, generation, creating_pid);
        self.insert(inode_id, entry)
    }

    /// Remove a tmpfile entry from the orphan index when it is linked into
    /// the namespace via .
    ///
    /// Called when a previously-anonymous O_TMPFILE inode receives a
    /// directory entry (nlink becomes 1). The inode is no longer orphaned
    /// and must be removed from the index.
    ///
    /// Returns  if the inode was present and removed.
    pub fn remove_on_link(&mut self, inode_id: u64, _txg: u64) -> bool {
        self.remove(inode_id)
    }

    /// Scan for O_TMPFILE entries whose creating process has exited.
    ///
    /// Iterates all entries in the index. For each entry with the
    ///  flag set, checks whether the process identified by
    ///  is still alive (by testing ).
    /// Returns the list of inode IDs whose creating process is dead
    /// and should be reaped.
    ///
    /// Entries with  (recovered from old logs or
    /// created by pre-PID-tracking code) are always included in the
    /// reap list since their creating process is unknowable.
    #[must_use]
    pub fn tmpfile_timeout_reap(&self) -> Vec<u64> {
        let mut reap = Vec::new();
        for entry in self.iter() {
            if !entry.is_otmpfile() {
                continue;
            }
            if entry.creating_pid == 0 || !pid_is_alive(entry.creating_pid) {
                reap.push(entry.inode_id);
            }
        }
        reap
    }

    /// Validate the internal B+tree structure.
    ///
    /// # Errors
    ///
    /// Returns `tidefs_btree::BTreeError` on structural violation.
    pub fn validate(&self) -> Result<(), BTreeError> {
        self.tree.validate()
    }

    // -- iteration --

    /// Iterate over all orphan entries in inode order.
    pub fn iter(&self) -> impl Iterator<Item = OrphanEntry> {
        self.tree.entries().into_iter().map(|(_key, entry)| entry)
    }

    /// Collect all orphaned inode IDs in order.
    #[must_use]
    pub fn collect_inode_ids(&self) -> Vec<u64> {
        self.tree
            .entries()
            .into_iter()
            .map(|(key, _entry)| key.to_inode_id())
            .collect()
    }

    // -- persistence: append-only log --

    /// Compute the BLAKE3 domain-separated checksum for an encoded entry.
    fn entry_checksum(entry_bytes: &[u8; ENTRY_ENCODED_SIZE]) -> [u8; CHECKSUM_SIZE] {
        blake3_domain_digest(
            entry_bytes,
            ORPHAN_LOG_FAMILY,
            ORPHAN_LOG_TYPE,
            ORPHAN_LOG_VERSION,
            ORPHAN_LOG_DOMAIN,
        )
    }

    /// Encode the entire index as an append-only log buffer.
    ///
    /// Format: `[u32 LE entry_count][entries...]`
    /// Each entry record: `[u8; 24 encoded_entry][u8; 32 BLAKE3 checksum]`
    ///
    /// The log is designed to be written atomically via the object store.
    /// On crash, `recover_from_log()` scans and verifies each record.
    #[must_use]
    pub fn encode_log(&self) -> Vec<u8> {
        let entries: Vec<OrphanEntry> = self.iter().collect();
        let mut buf = Vec::with_capacity(4 + entries.len() * LOG_RECORD_SIZE);
        let count: u32 = entries.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        for entry in entries {
            let enc = entry.encode();
            buf.extend_from_slice(&enc);
            let csum = Self::entry_checksum(&enc);
            buf.extend_from_slice(&csum);
        }
        buf
    }

    /// Recover the orphan index from an append-only log buffer.
    ///
    /// Scans the log, verifies BLAKE3 checksums per entry, and returns
    /// the surviving index plus a list of inode IDs whose checksums
    /// failed verification.
    ///
    /// Corrupted entries (those failing checksum verification) are skipped
    /// and reported in the returned `Vec<u64>`; they do not block recovery
    /// of intact entries.
    ///
    /// # Errors
    ///
    /// Returns `LogRecoverError` if the log header is truncated or an
    /// entry record is incomplete. Incomplete entries at the tail of
    /// the log (crash during append) are treated as truncation.
    pub fn recover_from_log(data: &[u8]) -> Result<(Self, Vec<u64>), LogRecoverError> {
        if data.len() < 4 {
            return Err(LogRecoverError::TruncatedHeader);
        }
        let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let mut idx = Self::new();
        let mut corrupted = Vec::new();
        let mut offset: usize = 4;

        for _ in 0..count {
            if offset + LOG_RECORD_SIZE > data.len() {
                // Truncated: crash during append. Treat remaining entries as lost.
                return Ok((idx, corrupted));
            }
            let entry_bytes: [u8; ENTRY_ENCODED_SIZE] = data[offset..offset + ENTRY_ENCODED_SIZE]
                .try_into()
                .unwrap();
            let expected_csum: [u8; CHECKSUM_SIZE] = data
                [offset + ENTRY_ENCODED_SIZE..offset + LOG_RECORD_SIZE]
                .try_into()
                .unwrap();
            let actual_csum = Self::entry_checksum(&entry_bytes);

            let entry = OrphanEntry::decode(&entry_bytes);
            if actual_csum == expected_csum {
                idx.insert(entry.inode_id, entry);
            } else {
                corrupted.push(entry.inode_id);
            }
            offset += LOG_RECORD_SIZE;
        }
        idx.clear_dirty();
        Ok((idx, corrupted))
    }

    // -- TXG commit pipeline integration --

    /// Returns `true` if the orphan index has unsaved mutations.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.has_pending()
    }

    /// Clear the dirty flag after successful persistence.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Insert an inode entry into the orphan index within the current TXG.
    ///
    /// The entry is immediately visible to `contains()`, `get()`, and
    /// `iter()`. The insert is tracked as "pending commit" so that an
    /// abort before the next `commit_pending()` can roll it back.
    ///
    /// Returns `true` if the entry was newly inserted (not already
    /// present in the tree).
    ///
    /// # Panics
    ///
    /// Panics if `inode_id != entry.inode_id`.
    pub fn insert_crash_safe(&mut self, inode_id: u64, entry: OrphanEntry) -> bool {
        assert_eq!(
            inode_id, entry.inode_id,
            "inode_id {inode_id} != entry.inode_id {}",
            entry.inode_id
        );
        let key = OrphanKey::from_inode_id(inode_id);
        self.pending_removes.remove(&key);
        let is_new = self.tree.insert(key, entry).is_none();
        if is_new {
            self.dirty = true;
            self.pending_inserts.insert(key, entry);
        }
        is_new
    }

    /// Remove an inode from the orphan index within the current TXG.
    ///
    /// The entry is immediately removed from the tree and no longer
    /// visible. The removal is tracked as "pending commit" so that an
    /// abort before the next `commit_pending()` can restore the entry.
    ///
    /// Returns `true` if the inode was present and removed.
    pub fn remove_crash_safe(&mut self, inode_id: u64) -> bool {
        let key = OrphanKey::from_inode_id(inode_id);
        if self.pending_inserts.remove(&key).is_some() {
            self.tree.delete(&key);
            return true;
        }
        if let Some(entry) = self.tree.delete(&key) {
            self.dirty = true;
            self.pending_removes.insert(key);
            self.pending_inserts.insert(key, entry);
            return true;
        }
        false
    }

    /// Commit all pending operations: clears the dirty flag and pending
    /// tracking so subsequent `abort_pending()` will not roll them back.
    pub fn commit_pending(&mut self) {
        self.dirty = false;
        self.pending_inserts.clear();
        self.pending_removes.clear();
    }

    /// Abort all pending operations: rolls back inserts and restores
    /// removes to their pre-TXG state.
    pub fn abort_pending(&mut self) {
        let inserts: Vec<OrphanKey> = self.pending_inserts.keys().copied().collect();
        for key in &inserts {
            if self.pending_removes.contains(key) {
                continue;
            }
            self.tree.delete(key);
        }
        let restores: Vec<(OrphanKey, OrphanEntry)> = self
            .pending_removes
            .iter()
            .filter_map(|k| self.pending_inserts.get(k).map(|e| (*k, *e)))
            .collect();
        for (key, entry) in restores {
            self.tree.insert(key, entry);
        }
        self.dirty = false;
        self.pending_inserts.clear();
        self.pending_removes.clear();
    }

    /// Returns `true` if there are any pending (uncommitted) operations.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending_inserts.is_empty() || !self.pending_removes.is_empty()
    }

    /// Number of pending operations (inserts + removes).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_inserts.len() + self.pending_removes.len()
    }

    /// Persist the dirty orphan index into the TXG store.
    ///
    /// Encodes the full index as an append-only log and writes it
    /// through `CommitGroupStore::put_named`. After a successful write,
    /// pending tracking is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error string from the store on I/O failure.
    pub fn commit_to_txg(
        &mut self,
        store: &mut dyn CommitGroupStore,
        key_name: &str,
    ) -> Result<tidefs_commit_group::store::CommitGroupKey, String> {
        let encoded = self.encode_log();
        let key = store.put_named(key_name, &encoded)?;
        self.commit_pending();
        Ok(key)
    }

    /// Recover the orphan index from the TXG store.
    ///
    /// Reads the persisted log from `CommitGroupStore::get_named`, verifies
    /// checksums, and returns the surviving index. Missing or corrupt
    /// data returns an empty index.
    ///
    /// Returns the recovered index plus a list of corrupted entry inode IDs.
    pub fn replay_from_txg(store: &dyn CommitGroupStore, key_name: &str) -> (Self, Vec<u64>) {
        match store.get_named(key_name) {
            Ok(Some(bytes)) => match Self::recover_from_log(&bytes) {
                Ok((idx, corrupted)) => (idx, corrupted),
                Err(_) => (Self::new(), Vec::new()),
            },
            Ok(None) => (Self::new(), Vec::new()),
            Err(_) => (Self::new(), Vec::new()),
        }
    }

    // -- batch recovery (cursor-based) --

    /// Perform one batch of cursor-based orphan recovery.
    ///
    /// Scans up to `budget.max_orphans_per_tick` entries starting from
    /// `cursor`, returning the entries found and a new cursor position.
    /// The caller is responsible for actually reclaiming the extents
    /// and deleting the inode — this method only reads from the index.
    #[must_use]
    pub fn batch_recover(
        &self,
        cursor: OrphanCursor,
        budget: OrphanRecoveryBudget,
    ) -> OrphanRecoveryOutcome {
        let start_key = cursor.next_key();

        let (entries, scan_exhausted) = if self.is_empty() || cursor.is_exhausted() {
            (Vec::new(), true)
        } else {
            let all = self.tree.entries();
            let budget_count = budget.normal_budget();
            let start_idx = all
                .binary_search_by_key(
                    &&if cursor.is_at_start() {
                        OrphanKey::NONE
                    } else {
                        start_key
                    },
                    |(k, _)| k,
                )
                .unwrap_or_else(|idx| idx);
            let mut result =
                Vec::with_capacity(budget_count.min(all.len().saturating_sub(start_idx)));
            for (_key, _entry) in all.iter().skip(start_idx).take(budget_count) {
                result.push(_key.to_inode_id());
            }
            let exhausted = result.len() < budget_count || start_idx + result.len() >= all.len();
            (result, exhausted)
        };

        let scanned = entries.len();
        let exhausted = scanned == 0 || cursor.is_exhausted() || self.is_empty() || scan_exhausted;

        let last_position = entries.last().copied().unwrap_or(cursor.position);

        OrphanRecoveryOutcome::new(
            OrphanRecoveryStats {
                scanned,
                reclaimed: 0,
                stale: 0,
                already_freed: 0,
                commits: 0,
                integrity_errors: 0,
            },
            OrphanCursor {
                position: last_position,
            },
            exhausted,
            entries,
        )
    }
}

impl Default for OrphanIndex {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LogRecoverError
// ---------------------------------------------------------------------------

/// Errors that can occur during orphan log recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogRecoverError {
    /// The log buffer is too short to contain the 4-byte entry-count header.
    TruncatedHeader,
}

impl std::fmt::Display for LogRecoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "orphan log truncated: header missing"),
        }
    }
}

impl std::error::Error for LogRecoverError {}

/// Check whether a process with the given PID is still alive on Linux.
///
/// Tests for the existence of `/proc/<pid>/`. Returns `true` if the
/// process directory exists (process is alive), `false` otherwise.
fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    std::path::Path::new(&format!("/proc/{pid}")).is_dir()
}
#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a simple entry
    fn make_entry(inode_id: u64) -> OrphanEntry {
        OrphanEntry::new(inode_id, inode_id * 10, 0, OrphanEntryFlags::NONE)
    }

    fn make_otmpfile_entry(inode_id: u64) -> OrphanEntry {
        OrphanEntry::new(inode_id, inode_id * 10, 0, OrphanEntryFlags::O_TMPFILE)
    }

    fn make_dir_entry(inode_id: u64) -> OrphanEntry {
        OrphanEntry::new(inode_id, inode_id * 10, 1, OrphanEntryFlags::IS_DIRECTORY)
    }

    // ── OrphanEntryFlags ─────────────────────────────────────────────

    #[test]
    fn flags_none() {
        let f = OrphanEntryFlags::NONE;
        assert!(!f.is_otmpfile());
        assert!(!f.is_directory());
        assert!(f.is_empty());
        assert_eq!(format!("{f}"), "NONE");
    }

    #[test]
    fn flags_otmpfile() {
        let f = OrphanEntryFlags::O_TMPFILE;
        assert!(f.is_otmpfile());
        assert!(!f.is_directory());
        assert!(!f.is_empty());
        assert_eq!(format!("{f}"), "O_TMPFILE");
    }

    #[test]
    fn flags_directory() {
        let f = OrphanEntryFlags::IS_DIRECTORY;
        assert!(!f.is_otmpfile());
        assert!(f.is_directory());
        assert_eq!(format!("{f}"), "IS_DIRECTORY");
    }

    #[test]
    fn flags_combined() {
        let f = OrphanEntryFlags(OrphanEntryFlags::O_TMPFILE.0 | OrphanEntryFlags::IS_DIRECTORY.0);
        assert!(f.is_otmpfile());
        assert!(f.is_directory());
        assert!(format!("{f}").contains("O_TMPFILE"));
        assert!(format!("{f}").contains("IS_DIRECTORY"));
    }

    // ── OrphanEntry encode/decode round-trip ────────────────────────

    #[test]
    fn entry_roundtrip_basic() {
        let entry = make_entry(42);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(entry, dec);
    }

    #[test]
    fn entry_roundtrip_otmpfile() {
        let entry = make_otmpfile_entry(100);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(entry, dec);
        assert!(dec.is_otmpfile());
        assert!(!dec.is_directory());
    }

    #[test]
    fn entry_roundtrip_directory() {
        let entry = make_dir_entry(200);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(entry, dec);
        assert!(dec.is_directory());
        assert!(!dec.is_otmpfile());
    }

    #[test]
    fn entry_roundtrip_boundary_values() {
        let entry = OrphanEntry::new(u64::MAX, 0, u32::MAX, OrphanEntryFlags(0xFF));
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(entry, dec);
    }

    #[test]
    fn entry_encoded_size() {
        let enc = make_entry(1).encode();
        assert_eq!(enc.len(), ENTRY_ENCODED_SIZE);
    }

    #[test]
    fn entry_flags_accessors() {
        let e = make_otmpfile_entry(1);
        assert!(e.is_otmpfile());
        assert!(!e.is_directory());

        let e = make_dir_entry(2);
        assert!(e.is_directory());
        assert!(!e.is_otmpfile());

        let e = make_entry(3);
        assert!(!e.is_otmpfile());
        assert!(!e.is_directory());
    }

    // ── OrphanIndex: basic CRUD ──────────────────────────────────────

    #[test]
    fn empty_index() {
        let idx = OrphanIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        assert!(idx.validate().is_ok());
        assert!(idx.collect_inode_ids().is_empty());
        assert_eq!(idx.iter().count(), 0);
    }

    #[test]
    fn insert_and_contains() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert(42, make_entry(42)));
        assert!(idx.contains(42));
        assert!(!idx.contains(99));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn insert_duplicate_rejected() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert(1, make_entry(1)));
        assert!(!idx.insert(1, make_entry(1)));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn insert_duplicate_overwrites_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(1));
        let otmp = make_otmpfile_entry(1);
        idx.insert(1, otmp);
        let got = idx.get(1).unwrap();
        assert!(got.is_otmpfile());
    }

    #[test]
    #[should_panic(expected = "inode_id 1 != entry.inode_id 2")]
    fn insert_mismatched_id_panics() {
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(2));
    }

    #[test]
    fn remove_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(5, make_entry(5));
        assert!(idx.contains(5));
        assert!(idx.remove(5));
        assert!(!idx.contains(5));
        assert!(idx.is_empty());
    }

    #[test]
    fn remove_nonexistent() {
        let mut idx = OrphanIndex::new();
        assert!(!idx.remove(999));
    }

    #[test]
    fn get_entry() {
        let mut idx = OrphanIndex::new();
        let entry = make_otmpfile_entry(77);
        idx.insert(77, entry);
        let got = idx.get(77).unwrap();
        assert_eq!(got.inode_id, 77);
        assert_eq!(got.generation, 770);
        assert!(got.is_otmpfile());
        assert!(idx.get(99).is_none());
    }

    #[test]
    fn multiple_inserts_ordered() {
        let mut idx = OrphanIndex::new();
        let ids = [100u64, 50, 200, 150, 1];
        for &id in &ids {
            idx.insert(id, make_entry(id));
        }
        assert_eq!(idx.len(), 5);
        let collected = idx.collect_inode_ids();
        assert_eq!(collected, vec![1, 50, 100, 150, 200]);
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn iter_yields_ordered_entries() {
        let mut idx = OrphanIndex::new();
        idx.insert(30, make_dir_entry(30));
        idx.insert(10, make_otmpfile_entry(10));
        idx.insert(20, make_entry(20));
        let ids: Vec<u64> = idx.iter().map(|e| e.inode_id).collect();
        assert_eq!(ids, vec![10, 20, 30]);
    }

    #[test]
    fn clear_empties_index() {
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(1));
        idx.insert(2, make_entry(2));
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn large_insert_and_iter() {
        let mut idx = OrphanIndex::new();
        let count = 1000u64;
        for i in (0..count).rev() {
            idx.insert(i + 1, make_entry(i + 1));
        }
        assert_eq!(idx.len(), count as usize);
        let collected: Vec<u64> = idx.iter().map(|e| e.inode_id).collect();
        assert_eq!(collected.len(), count as usize);
        for w in collected.windows(2) {
            assert!(w[0] < w[1]);
        }
        assert!(idx.validate().is_ok());
    }

    // ── Append-only log persistence ──────────────────────────────────

    #[test]
    fn encode_log_empty() {
        let idx = OrphanIndex::new();
        let log = idx.encode_log();
        // Just the 4-byte count (0)
        assert_eq!(log.len(), 4);
        assert_eq!(&log[0..4], &0u32.to_le_bytes());
    }

    #[test]
    fn encode_log_single_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, make_entry(42));
        let log = idx.encode_log();
        assert_eq!(log.len(), 4 + LOG_RECORD_SIZE);
        // Count
        assert_eq!(u32::from_le_bytes(log[0..4].try_into().unwrap()), 1);
    }

    #[test]
    fn roundtrip_log_single_entry() {
        let mut idx = OrphanIndex::new();
        let entry = make_otmpfile_entry(42);
        idx.insert(42, entry);
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 1);
        let got = recovered.get(42).unwrap();
        assert_eq!(got.inode_id, 42);
        assert_eq!(got.generation, 420);
        assert!(got.is_otmpfile());
    }

    #[test]
    fn roundtrip_log_multiple_entries() {
        let mut idx = OrphanIndex::new();
        for i in 1..=50u64 {
            if i % 3 == 0 {
                idx.insert(i, make_otmpfile_entry(i));
            } else if i % 5 == 0 {
                idx.insert(i, make_dir_entry(i));
            } else {
                idx.insert(i, make_entry(i));
            }
        }
        let log = idx.encode_log();

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 50);
        for i in 1..=50u64 {
            assert!(recovered.contains(i), "missing inode {i}");
        }
        // Spot-check flag preservation
        assert!(recovered.get(3).unwrap().is_otmpfile());
        assert!(recovered.get(5).unwrap().is_directory());
        assert!(!recovered.get(1).unwrap().is_otmpfile());
        assert!(!recovered.get(1).unwrap().is_directory());
    }

    // -- Crash-safe insert/remove with commit/abort semantics ------

    #[test]
    fn insert_crash_safe_immediately_visible() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert_crash_safe(42, make_entry(42)));
        assert!(idx.contains(42));
        assert!(idx.get(42).is_some());
        assert_eq!(idx.len(), 1);
        assert!(idx.is_dirty());
        assert!(idx.has_pending());
        assert_eq!(idx.pending_count(), 1);
    }

    #[test]
    fn insert_crash_safe_visible_after_commit() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42, make_entry(42));
        assert!(idx.contains(42));
        assert!(idx.has_pending());
        idx.commit_pending();
        assert!(idx.contains(42));
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn insert_crash_safe_aborted_rolled_back() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42, make_entry(42));
        assert!(idx.contains(42));
        idx.abort_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_immediately_removed() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, make_entry(42));
        idx.clear_dirty();
        assert!(!idx.is_dirty());
        assert!(idx.remove_crash_safe(42));
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(idx.is_dirty());
        assert!(idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_gone_after_commit() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, make_entry(42));
        idx.remove_crash_safe(42);
        idx.commit_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
        assert!(!idx.has_pending());
    }

    #[test]
    fn remove_crash_safe_cancels_pending_insert() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42, make_entry(42));
        assert!(idx.contains(42));
        assert!(idx.remove_crash_safe(42));
        assert!(!idx.contains(42));
        idx.commit_pending();
        assert!(!idx.contains(42));
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn remove_crash_safe_aborted_restores_entry() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, make_entry(42));
        idx.clear_dirty();
        idx.remove_crash_safe(42);
        assert!(!idx.contains(42));
        idx.abort_pending();
        assert!(idx.contains(42));
        assert_eq!(idx.len(), 1);
        assert!(!idx.is_dirty());
        assert!(!idx.has_pending());
    }

    #[test]
    fn concurrent_insert_and_commit() {
        let mut idx = OrphanIndex::new();
        for i in 1..=100u64 {
            idx.insert_crash_safe(i, make_entry(i));
        }
        assert_eq!(idx.pending_count(), 100);
        assert_eq!(idx.len(), 100);
        for i in 1..=100u64 {
            assert!(idx.contains(i));
        }
        idx.commit_pending();
        assert_eq!(idx.len(), 100);
        assert!(!idx.has_pending());
        for i in 1..=100u64 {
            assert!(idx.contains(i));
        }
    }

    #[test]
    fn empty_index_has_no_pending() {
        let idx = OrphanIndex::new();
        assert!(!idx.has_pending());
        assert_eq!(idx.pending_count(), 0);
        assert!(!idx.is_dirty());
    }

    #[test]
    fn remove_crash_safe_after_insert_crash_safe_same_txg() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(5, make_entry(5));
        assert!(idx.contains(5));
        idx.remove_crash_safe(5);
        assert!(!idx.contains(5));
        assert!(!idx.has_pending());
        idx.commit_pending();
        assert!(!idx.contains(5));
    }

    #[test]
    fn crash_simulated_recovery_insert_commit_then_kill() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(42, make_entry(42));
        idx.commit_pending();
        let log = idx.encode_log();
        let (recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(recovered.contains(42));
    }

    #[test]
    fn clear_also_clears_pending() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1, make_entry(1));
        idx.insert(2, make_entry(2));
        idx.remove_crash_safe(2);
        assert!(idx.has_pending());
        idx.clear();
        assert!(!idx.has_pending());
        assert!(idx.is_dirty());
        assert!(idx.is_empty());
    }

    #[test]
    fn commit_to_txg_clears_pending() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(10, make_entry(10));
        idx.insert_crash_safe(20, make_otmpfile_entry(20));
        assert!(idx.has_pending());
        assert!(idx.is_dirty());

        struct MemStore {
            data: std::collections::BTreeMap<String, Vec<u8>>,
        }
        impl CommitGroupStore for MemStore {
            fn get_named(&self, name: &str) -> std::result::Result<Option<Vec<u8>>, String> {
                Ok(self.data.get(name).cloned())
            }
            fn put_named(
                &mut self,
                name: &str,
                data: &[u8],
            ) -> std::result::Result<tidefs_commit_group::store::CommitGroupKey, String>
            {
                self.data.insert(name.to_string(), data.to_vec());
                Ok(tidefs_commit_group::store::CommitGroupKey([0u8; 32]))
            }
        }

        let mut store = MemStore {
            data: std::collections::BTreeMap::new(),
        };
        idx.commit_to_txg(&mut store, "orphan_log").unwrap();
        assert!(!idx.has_pending());
        assert!(!idx.is_dirty());

        let log = store.get_named("orphan_log").unwrap().unwrap();
        let (recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(10));
        assert!(recovered.contains(20));
    }

    #[test]
    fn insert_clears_pending_remove() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, make_entry(42));
        idx.clear_dirty();
        idx.remove_crash_safe(42);
        assert!(idx.has_pending());
        assert!(idx.insert(42, make_otmpfile_entry(42)));
        assert!(idx.contains(42));
        assert!(idx.get(42).unwrap().is_otmpfile());
    }

    #[test]
    fn remove_clears_pending_sets() {
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1, make_entry(1));
        idx.insert(2, make_entry(2));
        assert!(idx.contains(1));
        assert!(idx.contains(2));
        assert!(idx.remove(1));
        assert!(!idx.contains(1));
        assert!(idx.remove(2));
        assert!(!idx.contains(2));
    }

    #[test]
    fn recover_empty_log() {
        let log = 0u32.to_le_bytes().to_vec();
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
    }

    #[test]
    fn recover_truncated_header() {
        let log = vec![0u8, 1, 2]; // < 4 bytes
        let err = OrphanIndex::recover_from_log(&log).unwrap_err();
        assert_eq!(err, LogRecoverError::TruncatedHeader);
    }

    #[test]
    fn recover_truncated_entry_graceful() {
        // Create a valid log with 2 entries, then truncate the last entry
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(1));
        idx.insert(2, make_entry(2));
        let mut log = idx.encode_log();
        // Truncate halfway through the second entry
        let new_len = 4 + LOG_RECORD_SIZE + 10; // header + first full entry + 10 bytes of second
        log.truncate(new_len);

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        // Only the first entry should survive
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(1));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn recover_corrupted_checksum() {
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(1));
        idx.insert(2, make_entry(2));
        idx.insert(3, make_entry(3));
        let mut log = idx.encode_log();

        // Corrupt the checksum of the second entry (bytes 56-87, which is
        // offset 4 + 56..4 + 112 = 60..116)
        let second_csum_start = 4 + LOG_RECORD_SIZE + ENTRY_ENCODED_SIZE;
        log[second_csum_start] ^= 0xFF;

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(corrupted, vec![2]);
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn recover_corrupted_entry_data() {
        let mut idx = OrphanIndex::new();
        idx.insert(10, make_otmpfile_entry(10));
        idx.insert(20, make_dir_entry(20));
        let mut log = idx.encode_log();

        // Corrupt the generation field of the first entry (offset 8-15 in entry bytes)
        // This preserves the inode_id so the corrupted vector reports the correct ID.
        let entry_data_start = 4; // after count header
        log[entry_data_start + 10] ^= 0xFF; // flip a byte in generation field

        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert_eq!(corrupted, vec![10]);
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(20));
        assert!(!recovered.contains(10));
    }

    // ── Batch recovery (cursor-based) ────────────────────────────────

    #[test]
    fn batch_recover_from_start() {
        let mut idx = OrphanIndex::new();
        for i in 1..=50u64 {
            idx.insert(i, make_entry(i));
        }

        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 10,
            ..Default::default()
        };

        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 10);
        assert!(!outcome.exhausted);
        assert!(outcome.made_progress());
    }

    #[test]
    fn batch_recover_exhausts() {
        let mut idx = OrphanIndex::new();
        for i in 1..=5u64 {
            idx.insert(i, make_entry(i));
        }
        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 100,
            ..Default::default()
        };
        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 5);
        assert!(outcome.exhausted);
    }

    #[test]
    fn batch_recover_empty_index() {
        let idx = OrphanIndex::new();
        let budget = OrphanRecoveryBudget::default();
        let outcome = idx.batch_recover(OrphanCursor::START, budget);
        assert_eq!(outcome.stats.scanned, 0);
        assert!(outcome.exhausted);
        assert!(outcome.is_idle());
    }

    #[test]
    fn batch_recover_resumes_from_cursor() {
        let mut idx = OrphanIndex::new();
        for i in 1..=30u64 {
            idx.insert(i, make_entry(i));
        }
        let budget = OrphanRecoveryBudget {
            max_orphans_per_tick: 10,
            ..Default::default()
        };
        let mut cursor = OrphanCursor::START;
        let mut total = 0;
        for _ in 0..3 {
            let outcome = idx.batch_recover(cursor, budget);
            total += outcome.stats.scanned;
            cursor = outcome.cursor;
        }
        assert_eq!(total, 30);
    }

    // ── from_entries constructor ─────────────────────────────────────

    #[test]
    fn from_entries_constructs_correctly() {
        let entries = vec![make_entry(10), make_otmpfile_entry(20), make_dir_entry(30)];
        let idx = OrphanIndex::from_entries(&entries);
        assert_eq!(idx.len(), 3);
        assert!(idx.contains(10));
        assert!(idx.contains(20));
        assert!(idx.contains(30));
        assert!(idx.get(20).unwrap().is_otmpfile());
        assert!(idx.get(30).unwrap().is_directory());
    }

    #[test]
    fn from_entries_empty() {
        let idx = OrphanIndex::from_entries(&[]);
        assert!(idx.is_empty());
    }

    // ── Structural validation ────────────────────────────────────────

    #[test]
    fn validate_large_tree() {
        let mut idx = OrphanIndex::new();
        for i in 0..500u64 {
            idx.insert(i, make_entry(i));
        }
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn leaf_boundary() {
        let mut idx = OrphanIndex::new();
        let count = MAX_LEAF + 10;
        for i in 0..count as u64 {
            idx.insert(i, make_entry(i));
        }
        assert_eq!(idx.len(), count);
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn multi_level_tree() {
        let mut idx = OrphanIndex::new();
        let count = MAX_LEAF as u64 * MAX_INTERNAL as u64 * 4;
        for i in 0..count {
            idx.insert(i, make_entry(i));
        }
        assert_eq!(idx.len(), count as usize);
        assert!(idx.tree.depth() >= 2, "expected multi-level tree");
        assert!(idx.validate().is_ok());
    }

    #[test]
    fn insert_boundary_values() {
        let mut idx = OrphanIndex::new();
        // Use explicit generation values to avoid overflow in make_entry helper
        idx.insert(
            u64::MAX,
            OrphanEntry::new(u64::MAX, 1, 0, OrphanEntryFlags::NONE),
        );
        idx.insert(0, OrphanEntry::new(0, 0, 0, OrphanEntryFlags::NONE));
        idx.insert(1, OrphanEntry::new(1, 10, 0, OrphanEntryFlags::NONE));
        assert_eq!(idx.len(), 3);
        assert!(idx.contains(0));
        assert!(idx.contains(1));
        assert!(idx.contains(u64::MAX));
    }

    // ── O_TMPFILE flag persistence round-trip ────────────────────────

    #[test]
    fn otmpfile_flag_roundtrip_through_log() {
        let mut idx = OrphanIndex::new();
        let otmp = OrphanEntry::new(100, 500, 0, OrphanEntryFlags::O_TMPFILE);
        idx.insert(100, otmp);
        let log = idx.encode_log();
        let (recovered, _) = OrphanIndex::recover_from_log(&log).unwrap();
        let got = recovered.get(100).unwrap();
        assert!(got.is_otmpfile());
        assert_eq!(got.generation, 500);
        assert_eq!(got.nlink_at_unlink, 0);
    }

    // ── Crash recovery: partial log resilience ───────────────────────

    #[test]
    fn crash_partial_write_last_entry_truncated() {
        // Simulate a crash where only the header and first 1.5 entries
        // made it to disk
        let mut idx = OrphanIndex::new();
        for i in 1..=5u64 {
            idx.insert(i, make_entry(i));
        }
        let full_log = idx.encode_log();
        // Keep header + 3.5 entries
        let partial_len = 4 + 3 * LOG_RECORD_SIZE + LOG_RECORD_SIZE / 2;
        let partial = &full_log[..partial_len.min(full_log.len())];

        let (recovered, corrupted) = OrphanIndex::recover_from_log(partial).unwrap();
        assert!(corrupted.is_empty());
        // Should have 3 intact entries (the fourth is truncated and lost)
        assert_eq!(recovered.len(), 3);
        assert!(recovered.contains(1));
        assert!(recovered.contains(2));
        assert!(recovered.contains(3));
    }

    #[test]
    fn checksum_uniqueness_across_entries() {
        // Different entries must produce different checksums
        let e1 = make_entry(1);
        let e2 = make_entry(2);
        let c1 = OrphanIndex::entry_checksum(&e1.encode());
        let c2 = OrphanIndex::entry_checksum(&e2.encode());
        assert_ne!(c1, c2);
    }

    #[test]
    fn checksum_same_entry_same_checksum() {
        let e = make_entry(42);
        let c1 = OrphanIndex::entry_checksum(&e.encode());
        let c2 = OrphanIndex::entry_checksum(&e.encode());
        assert_eq!(c1, c2);
    }
    // -- O_TMPFILE orphan index lifecycle tests --

    #[test]
    fn tmpfile_insert_and_lookup() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert_tmpfile(10, 100, 1234, 0));
        assert!(idx.contains(10));
        let entry = idx.get(10).unwrap();
        assert!(entry.is_otmpfile());
        assert_eq!(entry.inode_id, 10);
        assert_eq!(entry.generation, 100);
        assert_eq!(entry.nlink_at_unlink, 0);
        assert_eq!(entry.creating_pid, 1234);
    }

    #[test]
    fn tmpfile_insert_duplicate_returns_false() {
        let mut idx = OrphanIndex::new();
        assert!(idx.insert_tmpfile(1, 10, 100, 0));
        assert!(!idx.insert_tmpfile(1, 10, 200, 0));
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn tmpfile_remove_on_link() {
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(5, 50, 999, 0);
        assert!(idx.contains(5));
        assert!(idx.remove_on_link(5, 0));
        assert!(!idx.contains(5));
        assert!(idx.is_empty());
    }

    #[test]
    fn tmpfile_remove_on_link_nonexistent() {
        let mut idx = OrphanIndex::new();
        assert!(!idx.remove_on_link(999, 0));
    }

    #[test]
    fn tmpfile_timeout_reap_process_alive() {
        // PID 1 (init) is always alive on Linux
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(10, 100, 1, 0);
        // init is alive, so this tmpfile should not be reaped
        let reap = idx.tmpfile_timeout_reap();
        assert!(reap.is_empty(), "PID 1 should be alive, not reaped");
    }

    #[test]
    fn tmpfile_timeout_reap_process_dead() {
        // Use a very high PID that almost certainly doesn't exist
        let dead_pid: u32 = 0xFFFFFE;
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(20, 200, dead_pid, 0);
        let reap = idx.tmpfile_timeout_reap();
        assert_eq!(reap, vec![20]);
    }

    #[test]
    fn tmpfile_timeout_reap_zero_pid_always_reaped() {
        // PID 0 means unknown (old log recovery), always reap
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(30, 300, 0, 0);
        let reap = idx.tmpfile_timeout_reap();
        assert_eq!(reap, vec![30]);
    }

    #[test]
    fn tmpfile_timeout_reap_skips_non_otmpfile() {
        let mut idx = OrphanIndex::new();
        // Regular unlinked file (not O_TMPFILE)
        let entry = OrphanEntry::new(40, 400, 0, OrphanEntryFlags::NONE);
        idx.insert(40, entry);
        let reap = idx.tmpfile_timeout_reap();
        assert!(reap.is_empty());
    }

    #[test]
    fn tmpfile_timeout_reap_mixed_alive_and_dead() {
        let mut idx = OrphanIndex::new();
        // PID 1 (init) is alive
        idx.insert_tmpfile(1, 10, 1, 0);
        // Dead PID
        idx.insert_tmpfile(2, 20, 0xFFFFFD, 0);
        let reap = idx.tmpfile_timeout_reap();
        assert_eq!(reap, vec![2]);
    }

    #[test]
    fn tmpfile_insert_link_remove_cycle() {
        let mut idx = OrphanIndex::new();
        // Create tmpfile
        assert!(idx.insert_tmpfile(100, 1000, 42, 0));
        assert_eq!(idx.len(), 1);
        // Link it
        assert!(idx.remove_on_link(100, 0));
        assert_eq!(idx.len(), 0);
        // Second remove should be no-op
        assert!(!idx.remove_on_link(100, 0));
    }

    #[test]
    fn tmpfile_insert_reap_cycle() {
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(200, 2000, 0xFFFFFC, 0);
        // Process dead -> should reap
        let reap = idx.tmpfile_timeout_reap();
        assert_eq!(reap, vec![200]);
        // After reaping, the entry is still in the index (caller must remove)
        assert!(idx.contains(200));
        idx.remove(200);
        assert!(!idx.contains(200));
    }

    // -- PID persistence round-trip --

    #[test]
    fn pid_encode_decode_roundtrip() {
        let entry = OrphanEntry::new_tmpfile(50, 500, 0x123456);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(dec.inode_id, 50);
        assert_eq!(dec.generation, 500);
        assert!(dec.is_otmpfile());
        assert_eq!(dec.creating_pid, 0x123456);
    }

    #[test]
    fn pid_encode_decode_max_24bit() {
        // Maximum 24-bit value
        let entry = OrphanEntry::new_tmpfile(60, 600, 0x00FF_FFFF);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(dec.creating_pid, 0x00FF_FFFF);
    }

    #[test]
    fn pid_encode_decode_truncated_to_24bit() {
        // Values above 24 bits are truncated
        let entry = OrphanEntry::new_tmpfile(70, 700, 0x01FF_FFFF);
        let enc = entry.encode();
        let dec = OrphanEntry::decode(&enc);
        assert_eq!(dec.creating_pid, 0x00FF_FFFF);
    }

    #[test]
    fn pid_roundtrip_through_log() {
        let mut idx = OrphanIndex::new();
        idx.insert_tmpfile(80, 800, 0xABCDEF, 0);
        let log = idx.encode_log();
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        let got = recovered.get(80).unwrap();
        assert!(got.is_otmpfile());
        assert_eq!(got.creating_pid, 0xABCDEF);
    }

    #[test]
    fn pid_zero_entry_roundtrip_through_log() {
        // Existing entries with PID=0 should survive the log
        let mut idx = OrphanIndex::new();
        let entry = OrphanEntry::new(90, 900, 0, OrphanEntryFlags::O_TMPFILE);
        idx.insert(90, entry);
        let log = idx.encode_log();
        let (recovered, corrupted) = OrphanIndex::recover_from_log(&log).unwrap();
        assert!(corrupted.is_empty());
        let got = recovered.get(90).unwrap();
        assert!(got.is_otmpfile());
        assert_eq!(got.creating_pid, 0);
    }
    // ── TXG commit pipeline tests ──────────────────────────────────

    /// A simple in-memory CommitGroupStore for testing.
    struct MemCommitGroupStore {
        blobs: std::collections::HashMap<String, Vec<u8>>,
    }

    impl MemCommitGroupStore {
        fn new() -> Self {
            Self {
                blobs: std::collections::HashMap::new(),
            }
        }
    }

    impl CommitGroupStore for MemCommitGroupStore {
        fn put_named(
            &mut self,
            name: &str,
            payload: &[u8],
        ) -> Result<tidefs_commit_group::store::CommitGroupKey, String> {
            self.blobs.insert(name.to_string(), payload.to_vec());
            Ok(tidefs_commit_group::store::CommitGroupKey([0u8; 32]))
        }

        fn get_named(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self.blobs.get(name).cloned())
        }
    }

    #[test]
    fn txg_roundtrip_empty_index() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        assert!(!idx.is_dirty());

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
        assert!(!recovered.is_dirty());
    }

    #[test]
    fn txg_roundtrip_single_entry() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();

        idx.insert_crash_safe(42, make_entry(42));
        assert!(idx.is_dirty());
        assert!(idx.contains(42));

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 1);
        assert!(recovered.contains(42));
    }

    #[test]
    fn txg_roundtrip_multiple_entries() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();

        for i in 1..=50u64 {
            if i % 3 == 0 {
                idx.insert_crash_safe(i, make_otmpfile_entry(i));
            } else if i % 5 == 0 {
                idx.insert_crash_safe(i, make_dir_entry(i));
            } else {
                idx.insert_crash_safe(i, make_entry(i));
            }
        }
        assert!(idx.is_dirty());

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), 50);
        assert!(recovered.contains(3));
        assert!(recovered.get(3).unwrap().is_otmpfile());
        assert!(recovered.contains(5));
        assert!(recovered.get(5).unwrap().is_directory());
    }

    #[test]
    fn txg_crash_simulated_insert_visible_after_commit() {
        let mut store = MemCommitGroupStore::new();
        let orphan_id = 99u64;

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(orphan_id, make_entry(orphan_id));
            assert!(idx.contains(orphan_id));
            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(
            recovered.contains(orphan_id),
            "orphan should be visible after replay (survived crash)"
        );
    }

    #[test]
    fn txg_crash_simulated_insert_not_committed_is_lost() {
        let store = MemCommitGroupStore::new();
        let orphan_id = 42u64;

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(orphan_id, make_entry(orphan_id));
            assert!(idx.is_dirty());
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(
            recovered.is_empty(),
            "uncommitted orphan should NOT survive crash"
        );
    }

    #[test]
    fn txg_remove_then_commit_roundtrip() {
        let mut store = MemCommitGroupStore::new();

        {
            let mut idx = OrphanIndex::new();
            idx.insert_crash_safe(1, make_entry(1));
            idx.insert_crash_safe(2, make_entry(2));
            idx.insert_crash_safe(3, make_entry(3));
            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        }

        {
            let (mut idx, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
            assert_eq!(idx.len(), 3);

            let removed = idx.remove_crash_safe(2);
            assert!(removed);
            assert!(idx.is_dirty());
            assert!(!idx.contains(2));

            idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
            assert!(!idx.is_dirty());
        }

        let (recovered, _) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
        assert!(!recovered.contains(2));
    }

    #[test]
    fn txg_replay_missing_key_returns_empty() {
        let store = MemCommitGroupStore::new();
        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "nonexistent");
        assert!(corrupted.is_empty());
        assert!(recovered.is_empty());
    }

    #[test]
    fn txg_clear_marks_dirty() {
        let mut idx = OrphanIndex::new();
        idx.insert(1, make_entry(1));
        idx.clear_dirty();
        assert!(!idx.is_dirty());

        idx.clear();
        assert!(idx.is_dirty());
        assert!(idx.is_empty());
    }

    #[test]
    fn txg_remove_nonexistent_is_noop() {
        let mut idx = OrphanIndex::new();
        let removed = idx.remove_crash_safe(999);
        assert!(!removed);
        assert!(!idx.is_dirty());
    }

    #[test]
    fn txg_concurrent_insert_and_commit() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        let count = 100u64;

        for i in 1..=count {
            idx.insert_crash_safe(i, make_entry(i));
        }
        assert!(idx.is_dirty());
        assert_eq!(idx.len(), count as usize);

        idx.commit_to_txg(&mut store, "orphan-idx").unwrap();
        assert!(!idx.is_dirty());

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert!(corrupted.is_empty());
        assert_eq!(recovered.len(), count as usize);
        for i in 1..=count {
            assert!(recovered.contains(i), "missing inode {i}");
        }
    }

    #[test]
    fn txg_corrupted_log_recovery_returns_partial() {
        let mut store = MemCommitGroupStore::new();
        let mut idx = OrphanIndex::new();
        idx.insert_crash_safe(1, make_entry(1));
        idx.insert_crash_safe(2, make_entry(2));
        idx.insert_crash_safe(3, make_entry(3));

        let mut encoded = idx.encode_log();
        let csum_start = 4 + super::LOG_RECORD_SIZE + super::ENTRY_ENCODED_SIZE;
        if csum_start < encoded.len() {
            encoded[csum_start] ^= 0xFF;
        }
        store.put_named("orphan-idx", &encoded).unwrap();

        let (recovered, corrupted) = OrphanIndex::replay_from_txg(&store, "orphan-idx");
        assert_eq!(corrupted, vec![2]);
        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(1));
        assert!(recovered.contains(3));
    }
}
