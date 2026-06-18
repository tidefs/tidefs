// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transaction group manager for the local object store.
//!
//! Wires the `tidefs-commit_group` state machine into the object-store write
//! path: every object write is accumulated in the current transaction group,
//! and on flush/sync the group is committed to produce a durable committed
//! root pointer that the crash-recovery loop can replay on next mount.
//!
//! # Architecture
//!
//! ```text
//! put(key, payload) ─► segment write (immediate)  +  commit_group accumulator
//!                                                          │
//! flush/sync ─► commit commit_group ─► write journal record ─► write committed root
//! ```
//!
//! The committed root is persisted as a named object at a well-known key
//! (`COMMITTED_ROOT_FILE`) so the crash-recovery loop can find it without
//! scanning all segments.

use crate::ObjectKey;
use tidefs_commit_group::{CommitGroupBuilder, CommitGroupId, RootPointer};

/// Well-known key under which the committed root pointer is stored.
/// Well-known file name for the committed root pointer.
/// Stored directly in the store root directory, not in the segment log,
/// to avoid polluting the object index.
pub const COMMITTED_ROOT_FILE: &str = "tidefs-committed-root";

/// Manages the transaction group lifecycle for the local object store.
///
/// Holds a [`CommitGroupBuilder`] for write accumulation with size- and
/// age-based flush triggers, and persists the committed root to a named
/// object on every successful commit_group commit.
#[derive(Debug)]
pub struct CommitGroupManager {
    /// The builder that accumulates writes and manages the two-phase
    /// prepare → commit lifecycle.
    builder: CommitGroupBuilder,
    /// The most recently committed root pointer, or NIL if no commit_group has
    /// completed yet.
    committed_root: RootPointer,
    /// Tracks how many txgs have been committed (for testing and stats).
    commit_count: u64,
}

impl CommitGroupManager {
    /// Create a new commit_group manager starting at `first_id`.
    ///
    /// The first group has parent root set to NIL. The committed root
    /// starts as NIL — a real committed root will be produced on the
    /// first flush/sync.
    #[must_use]
    pub fn new(first_id: CommitGroupId) -> Self {
        Self {
            builder: CommitGroupBuilder::new(first_id),
            committed_root: RootPointer::NIL,
            commit_count: 0,
        }
    }

    /// Create a commit_group manager resuming from a previously committed root.
    ///
    /// The first open group after recovery uses `next_id` and has
    /// `recovered_root` as its parent. Writes accumulated before the
    /// first post-recovery commit will be anchored to this lineage.
    #[must_use]
    pub fn resume(next_id: CommitGroupId, recovered_root: RootPointer) -> Self {
        Self {
            builder: CommitGroupBuilder::resume(next_id, recovered_root),
            committed_root: recovered_root,
            commit_count: 0,
        }
    }

    // ── queries ──────────────────────────────────────────────────

    /// The most recently committed root pointer.
    #[must_use]
    pub fn committed_root(&self) -> RootPointer {
        self.committed_root
    }

    /// The id of the currently open (accumulating) commit_group.
    #[must_use]
    pub fn current_id(&self) -> CommitGroupId {
        self.builder.current().commit_group_id()
    }

    /// Number of txgs committed since this manager was created.
    #[must_use]
    pub fn commit_count(&self) -> u64 {
        self.commit_count
    }

    /// Returns `true` if the current commit_group has no queued writes.
    #[must_use]
    pub fn current_is_empty(&self) -> bool {
        self.builder.current_is_empty()
    }

    /// Total bytes queued in the current commit_group.
    #[must_use]
    pub fn current_bytes(&self) -> usize {
        self.builder.current().total_bytes()
    }

    /// Number of writes queued in the current commit_group.
    #[must_use]
    pub fn current_write_count(&self) -> usize {
        self.builder.current().write_count()
    }

    /// Clone the committed root for external persistence.
    #[must_use]
    pub fn committed_root_ptr(&self) -> RootPointer {
        self.committed_root
    }

    // ── write accumulation ───────────────────────────────────────

    /// Queue a put into the current transaction group.
    ///
    /// Derives a surrogate inode number from the object key's first 8
    /// bytes so the write can be tracked through the commit_group
    /// accumulator. The actual segment write happens separately (the
    /// commit_group accumulator is a parallel tracking path, not the primary
    /// data path).
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError` if the commit_group phase rejects the write
    /// (e.g., the group is already committing).
    pub fn queue_put(
        &mut self,
        key: ObjectKey,
        payload: &[u8],
    ) -> std::result::Result<Option<RootPointer>, tidefs_commit_group::CommitGroupError> {
        let ino = key_to_ino(key);
        self.builder.write(ino, 0, payload.to_vec())
    }

    /// Commit the current transaction group if it is non-empty.
    ///
    /// This calls `prepare()` + `commit()` on the underlying group,
    /// records the new committed root, and opens a fresh group for
    /// subsequent writes.
    ///
    /// Returns `Some(new_root)` if a commit occurred, `None` if the
    /// current group was empty (no-op).
    ///
    /// # Errors
    ///
    /// Returns `CommitGroupError` if prepare or commit fails.
    pub fn commit_current(
        &mut self,
    ) -> std::result::Result<Option<RootPointer>, tidefs_commit_group::CommitGroupError> {
        let new_root = self.builder.flush()?;
        if let Some(root) = new_root {
            self.committed_root = root;
            self.commit_count = self.commit_count.saturating_add(1);
            Ok(Some(root))
        } else {
            Ok(None)
        }
    }

    /// Commit the current transaction group for filesystem-level commit
    /// sequencing.
    ///
    /// This is the integration entry point consumed by the local filesystem
    /// commit_group coordinator. It intentionally delegates to
    /// [`commit_current`](Self::commit_current) so there is one commit_group flush path
    /// and one committed-root update path.
    pub fn commit_group(
        &mut self,
    ) -> std::result::Result<Option<RootPointer>, tidefs_commit_group::CommitGroupError> {
        self.commit_current()
    }

    /// Abort the current transaction group, discarding all queued writes.
    ///
    /// After abort, a fresh group is opened for subsequent writes.
    /// The committed root is unchanged.
    pub fn abort_current(&mut self) {
        self.builder.current_mut().abort();
        // Re-create the builder with a fresh group
        let next_id = self.current_id().next();
        self.builder = CommitGroupBuilder::new(next_id);
    }

    // ── persistence helpers ──────────────────────────────────────

    /// Encode the committed root into a binary payload for storage.
    ///
    /// Format: commit_group_id (8 bytes LE) + root_handle (8 bytes LE).
    #[must_use]
    pub fn encode_root(root: RootPointer) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&root.commit_group_id.0.to_le_bytes());
        buf.extend_from_slice(&root.root_handle.to_le_bytes());
        buf
    }

    /// Decode a committed root from a binary payload.
    ///
    /// Returns `None` if the payload is too short or malformed.
    #[must_use]
    pub fn decode_root(payload: &[u8]) -> Option<RootPointer> {
        if payload.len() < 16 {
            return None;
        }
        let commit_group_id = CommitGroupId(u64::from_le_bytes(payload[0..8].try_into().ok()?));
        let root_handle = u64::from_le_bytes(payload[8..16].try_into().ok()?);
        Some(RootPointer::new(commit_group_id, root_handle))
    }

    /// Encode the committed root with a BLAKE3 chain digest.
    ///
    /// Format: commit_group_id (8 bytes LE) + root_handle (8 bytes LE)
    ///         + chain_digest (32 bytes) = 48 bytes total.
    #[must_use]
    pub fn encode_root_with_digest(root: RootPointer, chain_digest: [u8; 32]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(48);
        buf.extend_from_slice(&root.commit_group_id.0.to_le_bytes());
        buf.extend_from_slice(&root.root_handle.to_le_bytes());
        buf.extend_from_slice(&chain_digest);
        buf
    }

    /// Decode a committed root and optional chain digest from a payload.
    ///
    /// Supports both the old 16-byte format (no chain digest) and the new
    /// 48-byte format (with chain digest). Returns `(root, chain_digest)`
    /// where `chain_digest` is `None` for the old format.
    #[must_use]
    pub fn decode_root_with_digest(payload: &[u8]) -> Option<(RootPointer, Option<[u8; 32]>)> {
        if payload.len() < 16 {
            return None;
        }
        let commit_group_id = CommitGroupId(u64::from_le_bytes(payload[0..8].try_into().ok()?));
        let root_handle = u64::from_le_bytes(payload[8..16].try_into().ok()?);
        let root = RootPointer::new(commit_group_id, root_handle);

        if payload.len() >= 48 {
            let digest: [u8; 32] = payload[16..48].try_into().ok()?;
            Some((root, Some(digest)))
        } else {
            Some((root, None))
        }
    }
}

// ── Committed root anchor digest ────────────────────────────────────────

/// Compute the BLAKE3 domain-separated anchor digest for a committed root.
///
/// Produces the same digest that the committed-root validation path
/// (`validate_committed_root`) compares against, under the
/// `DomainTag::CommittedRoot` domain key.  The digest covers the
/// commit_group_id (8 bytes LE) and root_handle (8 bytes LE).
///
/// Returns NIL ([0u8; 32]) when the root is NIL (fresh filesystem).
#[must_use]
pub fn compute_committed_root_digest(root: RootPointer) -> [u8; 32] {
    if !root.commit_group_id.is_valid() {
        return [0u8; 32];
    }
    let domain_key = tidefs_checksum_tree::DomainTag::CommittedRoot.derive_key();
    let mut payload = [0u8; 16];
    payload[0..8].copy_from_slice(&root.commit_group_id.0.to_le_bytes());
    payload[8..16].copy_from_slice(&root.root_handle.to_le_bytes());
    blake3::keyed_hash(domain_key.as_bytes(), &payload).into()
}

/// Derive a surrogate inode number from an ObjectKey for commit_group accumulation.
///
/// Takes the first 8 bytes of the 32-byte key, interprets them as a
/// little-endian u64. Since ObjectKeys are content-derived (BLAKE3-256
/// or deterministic FNV-based), collisions are astronomically unlikely
/// and even a collision would only merge two unrelated writes in the
/// same commit_group — not a correctness issue.
fn key_to_ino(key: ObjectKey) -> u64 {
    let bytes = key.as_bytes32();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// ── tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_commit_group::CommitGroupId;

    #[test]
    fn new_manager_starts_at_first_id() {
        let mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        assert_eq!(mgr.current_id(), CommitGroupId::FIRST);
        assert_eq!(mgr.committed_root(), RootPointer::NIL);
        assert!(mgr.current_is_empty());
        assert_eq!(mgr.commit_count(), 0);
    }

    #[test]
    fn queue_put_adds_write() {
        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([1u8; 32]);
        mgr.queue_put(key, b"hello").unwrap();
        assert!(!mgr.current_is_empty());
        assert_eq!(mgr.current_write_count(), 1);
        assert_eq!(mgr.current_bytes(), 5);
    }

    #[test]
    fn commit_current_empty_is_noop() {
        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let result = mgr.commit_current().unwrap();
        assert!(result.is_none());
        assert_eq!(mgr.committed_root(), RootPointer::NIL);
        assert_eq!(mgr.commit_count(), 0);
    }

    #[test]
    fn commit_current_produces_root() {
        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([2u8; 32]);
        mgr.queue_put(key, b"data").unwrap();
        let root = mgr.commit_current().unwrap().unwrap();
        assert!(root.is_valid());
        assert_eq!(root.commit_group_id, CommitGroupId::FIRST);
        assert_eq!(mgr.committed_root(), root);
        assert_eq!(mgr.commit_count(), 1);
        // After commit, a new empty group is open
        assert!(mgr.current_is_empty());
    }

    #[test]
    fn commit_txg_commits_current_group() {
        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([0x42u8; 32]);
        mgr.queue_put(key, b"via-commit-commit_group").unwrap();

        let root = mgr.commit_group().unwrap().unwrap();

        assert!(root.is_valid());
        assert_eq!(root.commit_group_id, CommitGroupId::FIRST);
        assert_eq!(mgr.committed_root(), root);
        assert_eq!(mgr.commit_count(), 1);
        assert!(mgr.current_is_empty());
    }

    #[test]
    fn multiple_commits_produce_chain() {
        let mut mgr = CommitGroupManager::new(CommitGroupId(1));
        let key = ObjectKey::from_bytes32([3u8; 32]);

        mgr.queue_put(key, b"txg1").unwrap();
        let root1 = mgr.commit_current().unwrap().unwrap();
        assert_eq!(root1.commit_group_id, CommitGroupId(1));

        mgr.queue_put(key, b"txg2").unwrap();
        let root2 = mgr.commit_current().unwrap().unwrap();
        assert_eq!(root2.commit_group_id, CommitGroupId(2));

        assert_eq!(mgr.commit_count(), 2);
        // root1 should be the parent of the group that produced root2
    }

    #[test]
    fn abort_discards_writes() {
        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([4u8; 32]);
        mgr.queue_put(key, b"doomed").unwrap();
        assert!(!mgr.current_is_empty());
        mgr.abort_current();
        assert!(mgr.current_is_empty());
        // Committed root unchanged
        assert_eq!(mgr.committed_root(), RootPointer::NIL);
    }

    #[test]
    fn root_persistence_roundtrip() {
        let root = RootPointer::new(CommitGroupId(42), 99);
        let encoded = CommitGroupManager::encode_root(root);
        let decoded = CommitGroupManager::decode_root(&encoded).unwrap();
        assert_eq!(decoded, root);
    }

    #[test]
    fn decode_root_rejects_short_payload() {
        assert!(CommitGroupManager::decode_root(&[]).is_none());
        assert!(CommitGroupManager::decode_root(&[0u8; 8]).is_none());
    }

    #[test]
    fn root_encode_decode_via_file_roundtrip() {
        // Test the file-based persistence path used by sync_all.

        let mut mgr = CommitGroupManager::new(CommitGroupId::FIRST);
        let key = ObjectKey::from_bytes32([5u8; 32]);
        mgr.queue_put(key, b"persist-test").unwrap();
        let root = mgr.commit_current().unwrap().unwrap();

        let tmp = std::env::temp_dir().join("tidefs-commit_group-root-test");
        let root_path = tmp.join(COMMITTED_ROOT_FILE);
        let _ = std::fs::create_dir_all(&tmp);

        let payload = CommitGroupManager::encode_root(root);
        std::fs::write(&root_path, &payload).unwrap();

        let read_back = std::fs::read(&root_path).unwrap();
        let decoded = CommitGroupManager::decode_root(&read_back).unwrap();
        assert_eq!(decoded, root);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resume_from_recovered_root() {
        let recovered = RootPointer::new(CommitGroupId(5), 5);
        let mgr = CommitGroupManager::resume(CommitGroupId(6), recovered);
        assert_eq!(mgr.committed_root(), recovered);
        assert_eq!(mgr.current_id(), CommitGroupId(6));
        assert!(mgr.current_is_empty());
    }

    #[test]
    fn key_to_ino_is_deterministic() {
        let key = ObjectKey::from_bytes32([0xAB; 32]);
        let ino1 = key_to_ino(key);
        let ino2 = key_to_ino(key);
        assert_eq!(ino1, ino2);
    }
}
