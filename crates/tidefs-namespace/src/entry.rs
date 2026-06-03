//! Namespace entry types for in-memory directory operations.
//!
//! [`NamespaceEntry`] pairs every directory entry with a content hash computed
//! over the entry's identity fields (parent, name, target inode, kind).
//! The hash enables efficient in-memory lookup and duplicate detection; the
//! storage layer provides durability guarantees.

use crate::{EntryType, Inode};
use fxhash::FxHasher;
use std::hash::Hasher;

// ---------------------------------------------------------------------------
// NamespaceEntry
// ---------------------------------------------------------------------------

/// A directory entry binding a name to an inode.
///
/// The content hash covers `parent`, `name` (length-prefixed), `ino`, and
/// `kind` — the full identity of the entry. Two entries with the same identity
/// produce the same hash, enabling idempotent intent-log replay detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceEntry {
    /// Non-cryptographic hash of the entry's identity fields.
    pub content_hash: u64,
    /// Parent directory inode.
    pub parent: Inode,
    /// Entry name (raw bytes, not nul-terminated).
    pub name: Vec<u8>,
    /// Target inode number.
    pub ino: Inode,
    /// Entry type (directory, file, or symlink).
    pub kind: EntryType,
}

impl NamespaceEntry {
    /// Create a new entry and compute its content hash.
    ///
    /// The hash covers `parent`, `name` (length-prefixed), `ino`, and `kind`
    /// (as u32) using a fast non-cryptographic hash function.
    pub fn new(parent: Inode, name: Vec<u8>, ino: Inode, kind: EntryType) -> Self {
        let content_hash = compute_entry_hash(parent, &name, ino, kind);
        NamespaceEntry {
            content_hash,
            parent,
            name,
            ino,
            kind,
        }
    }

    /// Verify that the stored content hash matches a fresh computation.
    ///
    /// Returns `true` if the entry is intact; `false` indicates corruption
    /// or tampering.
    pub fn verify(&self) -> bool {
        let recomputed = compute_entry_hash(self.parent, &self.name, self.ino, self.kind);
        recomputed == self.content_hash
    }

    /// Return the entry type as a u32 kind constant (for DirIndex interop).
    pub fn kind_u32(&self) -> u32 {
        self.kind.to_kind()
    }

    /// Create an entry from raw components, verifying the hash.
    ///
    /// Returns `None` if the provided hash doesn't match the computed hash.
    pub fn from_parts_verified(
        content_hash: u64,
        parent: Inode,
        name: Vec<u8>,
        ino: Inode,
        kind: EntryType,
    ) -> Option<Self> {
        let entry = NamespaceEntry {
            content_hash,
            parent,
            name,
            ino,
            kind,
        };
        if entry.verify() {
            Some(entry)
        } else {
            None
        }
    }

    /// Return a copy of this entry with a freshly computed content hash.
    pub fn rehash(&self) -> Self {
        Self::new(self.parent, self.name.clone(), self.ino, self.kind)
    }
}

// ---------------------------------------------------------------------------
// Hash computation
// ---------------------------------------------------------------------------

/// Compute a non-cryptographic content hash for an entry identity.
///
/// The input order is: parent (u64 LE), name length (u16 LE), name bytes,
/// ino (u64 LE), kind (u32 LE). The hash is used for in-memory lookup
/// efficiency; durability is provided by the storage layer.
pub(crate) fn compute_entry_hash(parent: Inode, name: &[u8], ino: Inode, kind: EntryType) -> u64 {
    let mut hasher = FxHasher::default();
    hasher.write(&parent.to_le_bytes());
    hasher.write(&(name.len() as u16).to_le_bytes());
    hasher.write(name);
    hasher.write(&ino.to_le_bytes());
    hasher.write(&kind.to_kind().to_le_bytes());
    hasher.finish()
}

// ---------------------------------------------------------------------------
// NamespaceEntryTombstone
// ---------------------------------------------------------------------------

/// A tombstone record proving that an entry was safely removed.
///
/// Tombstones are written to the intent log alongside [`super::remove::remove_entry`]
/// calls so that crash recovery can distinguish "was never there" from
/// "was removed before the crash".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceEntryTombstone {
    /// Hash of the removed entry's identity (same as `NamespaceEntry::content_hash`).
    pub entry_hash: u64,
    /// Parent directory inode.
    pub parent: Inode,
    /// Name of the removed entry.
    pub name: Vec<u8>,
    /// Inode that was removed.
    pub ino: Inode,
    /// Entry type that was removed.
    pub kind: EntryType,
}

impl NamespaceEntryTombstone {
    /// Create a tombstone from a removed entry.
    pub fn from_entry(entry: &NamespaceEntry) -> Self {
        NamespaceEntryTombstone {
            entry_hash: entry.content_hash,
            parent: entry.parent,
            name: entry.name.clone(),
            ino: entry.ino,
            kind: entry.kind,
        }
    }

    /// Verify that the tombstone's hash matches a fresh computation.
    pub fn verify(&self) -> bool {
        let recomputed = compute_entry_hash(self.parent, &self.name, self.ino, self.kind);
        recomputed == self.entry_hash
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Entry creation and verification ───────────────────────────

    #[test]
    fn entry_new_computes_hash() {
        let entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        assert!(entry.verify());
    }

    #[test]
    fn entry_verify_detects_tampered_parent() {
        let mut entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        entry.parent = 999;
        assert!(!entry.verify());
    }

    #[test]
    fn entry_verify_detects_tampered_name() {
        let mut entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        entry.name = b"corrupted".to_vec();
        assert!(!entry.verify());
    }

    #[test]
    fn entry_verify_detects_tampered_ino() {
        let mut entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        entry.ino = 999;
        assert!(!entry.verify());
    }

    #[test]
    fn entry_verify_detects_tampered_kind() {
        let mut entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        entry.kind = EntryType::Directory;
        assert!(!entry.verify());
    }

    #[test]
    fn entry_verify_detects_tampered_hash() {
        let mut entry = NamespaceEntry::new(1, b"hello.txt".to_vec(), 42, EntryType::File);
        entry.content_hash ^= 1;
        assert!(!entry.verify());
    }

    #[test]
    fn identical_entries_produce_same_hash() {
        let e1 = NamespaceEntry::new(5, b"data".to_vec(), 100, EntryType::File);
        let e2 = NamespaceEntry::new(5, b"data".to_vec(), 100, EntryType::File);
        assert_eq!(e1.content_hash, e2.content_hash);
        assert_eq!(e1, e2);
    }

    #[test]
    fn different_parent_produces_different_hash() {
        let e1 = NamespaceEntry::new(1, b"data".to_vec(), 100, EntryType::File);
        let e2 = NamespaceEntry::new(2, b"data".to_vec(), 100, EntryType::File);
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn different_name_produces_different_hash() {
        let e1 = NamespaceEntry::new(1, b"alpha".to_vec(), 100, EntryType::File);
        let e2 = NamespaceEntry::new(1, b"beta".to_vec(), 100, EntryType::File);
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn different_ino_produces_different_hash() {
        let e1 = NamespaceEntry::new(1, b"data".to_vec(), 100, EntryType::File);
        let e2 = NamespaceEntry::new(1, b"data".to_vec(), 200, EntryType::File);
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn different_kind_produces_different_hash() {
        let e1 = NamespaceEntry::new(1, b"data".to_vec(), 100, EntryType::File);
        let e2 = NamespaceEntry::new(1, b"data".to_vec(), 100, EntryType::Directory);
        assert_ne!(e1.content_hash, e2.content_hash);
    }

    #[test]
    fn from_parts_verified_succeeds_for_correct_hash() {
        let entry = NamespaceEntry::new(1, b"test".to_vec(), 42, EntryType::File);
        let rebuilt = NamespaceEntry::from_parts_verified(
            entry.content_hash,
            entry.parent,
            entry.name.clone(),
            entry.ino,
            entry.kind,
        );
        assert!(rebuilt.is_some());
        assert_eq!(rebuilt.unwrap(), entry);
    }

    #[test]
    fn from_parts_verified_rejects_wrong_hash() {
        let entry = NamespaceEntry::new(1, b"test".to_vec(), 42, EntryType::File);
        let mut bad_hash = entry.content_hash;
        bad_hash ^= 1;
        let rebuilt = NamespaceEntry::from_parts_verified(
            bad_hash,
            entry.parent,
            entry.name.clone(),
            entry.ino,
            entry.kind,
        );
        assert!(rebuilt.is_none());
    }

    #[test]
    fn rehash_computes_fresh_hash() {
        let mut entry = NamespaceEntry::new(1, b"test".to_vec(), 42, EntryType::File);
        let original_hash = entry.content_hash;
        // Tamper with the hash
        entry.content_hash = 0;
        assert!(!entry.verify());
        let rehashed = entry.rehash();
        assert_eq!(rehashed.content_hash, original_hash);
        assert!(rehashed.verify());
    }

    // ── Entry type kind conversion ────────────────────────────────

    #[test]
    fn entry_kind_u32_roundtrip() {
        for kind in &[EntryType::File, EntryType::Directory, EntryType::Symlink] {
            let entry = NamespaceEntry::new(1, b"x".to_vec(), 10, *kind);
            let decoded = EntryType::from_kind(entry.kind_u32());
            assert_eq!(decoded, Some(*kind));
        }
    }

    #[test]
    fn empty_name_entry() {
        let entry = NamespaceEntry::new(1, vec![], 42, EntryType::File);
        assert!(entry.verify());
    }

    #[test]
    fn long_name_entry_255_bytes() {
        let name = vec![b'x'; 255];
        let entry = NamespaceEntry::new(1, name.clone(), 42, EntryType::File);
        assert!(entry.verify());
        assert_eq!(entry.name.len(), 255);
    }

    // ── Tombstone tests ───────────────────────────────────────────

    #[test]
    fn tombstone_from_entry_preserves_hash() {
        let entry = NamespaceEntry::new(1, b"file.txt".to_vec(), 42, EntryType::File);
        let tombstone = NamespaceEntryTombstone::from_entry(&entry);
        assert_eq!(tombstone.entry_hash, entry.content_hash);
        assert_eq!(tombstone.parent, entry.parent);
        assert_eq!(tombstone.name, entry.name);
        assert_eq!(tombstone.ino, entry.ino);
        assert_eq!(tombstone.kind, entry.kind);
        assert!(tombstone.verify());
    }

    #[test]
    fn tombstone_verify_detects_tampering() {
        let entry = NamespaceEntry::new(1, b"file.txt".to_vec(), 42, EntryType::File);
        let mut tombstone = NamespaceEntryTombstone::from_entry(&entry);
        tombstone.name = b"tampered".to_vec();
        assert!(!tombstone.verify());
    }
}
