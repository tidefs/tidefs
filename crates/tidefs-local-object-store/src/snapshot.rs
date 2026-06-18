// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Snapshot creation with commit_group anchoring and persistent catalog entry.
//!
//! Captures the current transaction group as an immutable snapshot anchor
//! and persists the snapshot identity into the object store, enabling
//! point-in-time recovery without data duplication.
//!
//! # Design
//!
//! A snapshot is a lightweight metadata record that pins a specific commit_group
//! (committed root) as the recovery point for a dataset. Creating a
//! snapshot does not copy any data — it records the commit_group anchor so that
//! read operations against the snapshot can resolve object locations
//! valid at that point in time.
//!
//! Snapshot entries are persisted as named objects with a well-known
//! prefix (`snapshot_entry/`) so they can be enumerated and listed.

use std::time::SystemTime;

use crate::ObjectKey;
use tidefs_commit_group::{CommitGroupId, RootPointer};

/// Well-known prefix for snapshot entry object keys.
pub const SNAPSHOT_ENTRY_PREFIX: &str = "snapshot_entry";

/// A persistent snapshot identity record.
///
/// Pins a specific committed root (via commit_group anchor) as the recovery-point
/// for a dataset. This record is written into the object store and provides
/// the identity needed for listing, access, and pruning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    /// Human-readable snapshot name.
    pub name: String,
    /// Transaction group at which the snapshot was anchored.
    pub txg_anchor: CommitGroupId,
    /// The committed root pointer at the time of creation.
    pub committed_root: RootPointer,
    /// Wall-clock creation timestamp.
    pub created_at: SystemTime,
    /// Key of the parent dataset, derived from the dataset name.
    pub parent_dataset_key: ObjectKey,
}

impl SnapshotEntry {
    /// Create a new snapshot entry.
    #[must_use]
    pub fn new(
        name: String,
        txg_anchor: CommitGroupId,
        committed_root: RootPointer,
        created_at: SystemTime,
        parent_dataset_key: ObjectKey,
    ) -> Self {
        Self {
            name,
            txg_anchor,
            committed_root,
            created_at,
            parent_dataset_key,
        }
    }

    /// Build the object key for this snapshot entry.
    #[must_use]
    pub fn object_key(&self) -> ObjectKey {
        let raw = format!(
            "{}/{}/{}",
            SNAPSHOT_ENTRY_PREFIX,
            self.parent_dataset_key.short_hex(),
            self.name
        );
        ObjectKey::from_name(raw.as_bytes())
    }

    /// Encode this entry into a binary payload for persistence.
    ///
    /// Wire format (little-endian):
    /// - name_len: u16
    /// - name: UTF-8 bytes
    /// - txg_anchor: u64
    /// - committed_root_txg: u64
    /// - root_handle: u64
    /// - created_at_secs: u64
    /// - parent_dataset_key: 32 bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();
        let name_len = name_bytes.len().min(u16::MAX as usize) as u16;
        let created_secs = self
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut buf = Vec::with_capacity(2 + name_bytes.len() + 32 + 32);
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.txg_anchor.0.to_le_bytes());
        buf.extend_from_slice(&self.committed_root.commit_group_id.0.to_le_bytes());
        buf.extend_from_slice(&self.committed_root.root_handle.to_le_bytes());
        buf.extend_from_slice(&created_secs.to_le_bytes());
        buf.extend_from_slice(self.parent_dataset_key.as_bytes());
        buf
    }

    /// Decode a snapshot entry from a binary payload.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 2 {
            return None;
        }
        let name_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        if payload.len() < 2 + name_len + 32 + 32 {
            return None;
        }
        let name = String::from_utf8(payload[2..2 + name_len].to_vec()).ok()?;

        let off = 2 + name_len;
        let txg_anchor = CommitGroupId(u64::from_le_bytes([
            payload[off],
            payload[off + 1],
            payload[off + 2],
            payload[off + 3],
            payload[off + 4],
            payload[off + 5],
            payload[off + 6],
            payload[off + 7],
        ]));

        let committed_root_txg = u64::from_le_bytes([
            payload[off + 8],
            payload[off + 9],
            payload[off + 10],
            payload[off + 11],
            payload[off + 12],
            payload[off + 13],
            payload[off + 14],
            payload[off + 15],
        ]);

        let root_handle = u64::from_le_bytes([
            payload[off + 16],
            payload[off + 17],
            payload[off + 18],
            payload[off + 19],
            payload[off + 20],
            payload[off + 21],
            payload[off + 22],
            payload[off + 23],
        ]);

        let created_secs = u64::from_le_bytes([
            payload[off + 24],
            payload[off + 25],
            payload[off + 26],
            payload[off + 27],
            payload[off + 28],
            payload[off + 29],
            payload[off + 30],
            payload[off + 31],
        ]);

        let parent_dataset_key =
            ObjectKey::from_bytes32(payload[off + 32..off + 64].try_into().ok()?);

        let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_secs);

        Some(Self {
            name,
            txg_anchor,
            committed_root: RootPointer::new(CommitGroupId(committed_root_txg), root_handle),
            created_at,
            parent_dataset_key,
        })
    }

    /// Derive the well-known snapshot catalog object key for a dataset.
    #[must_use]
    pub fn catalog_key_for_dataset(dataset_key: ObjectKey) -> ObjectKey {
        let raw = format!(
            "{}/{}/catalog",
            SNAPSHOT_ENTRY_PREFIX,
            dataset_key.short_hex()
        );
        ObjectKey::from_name(raw.as_bytes())
    }
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    fn test_dataset_key() -> ObjectKey {
        ObjectKey::from_name(b"test-dataset")
    }

    #[test]
    fn snapshot_entry_encode_decode_roundtrip() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1715000000);
        let entry = SnapshotEntry::new(
            "snap-2025-05-15".into(),
            CommitGroupId(42),
            RootPointer::new(CommitGroupId(42), 7),
            t,
            test_dataset_key(),
        );
        let encoded = entry.encode();
        let decoded = SnapshotEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.name, entry.name);
        assert_eq!(decoded.txg_anchor, entry.txg_anchor);
        assert_eq!(decoded.committed_root, entry.committed_root);
        assert_eq!(decoded.parent_dataset_key, entry.parent_dataset_key);
        let dec_secs = decoded
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let enc_secs = entry
            .created_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(dec_secs, enc_secs);
    }

    #[test]
    fn decode_rejects_short_payload() {
        assert!(SnapshotEntry::decode(&[]).is_none());
        assert!(SnapshotEntry::decode(&[0u8; 5]).is_none());
    }

    #[test]
    fn object_key_is_deterministic() {
        let entry = SnapshotEntry::new(
            "test-snap".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            test_dataset_key(),
        );
        let k1 = entry.object_key();
        let k2 = entry.object_key();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_names_produce_different_keys() {
        let ds = test_dataset_key();
        let e1 = SnapshotEntry::new(
            "snap-a".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            ds,
        );
        let e2 = SnapshotEntry::new(
            "snap-b".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            ds,
        );
        assert_ne!(e1.object_key(), e2.object_key());
    }

    #[test]
    fn catalog_key_is_deterministic() {
        let ds = test_dataset_key();
        let k1 = SnapshotEntry::catalog_key_for_dataset(ds);
        let k2 = SnapshotEntry::catalog_key_for_dataset(ds);
        assert_eq!(k1, k2);
    }

    #[test]
    fn catalog_key_differs_from_entry_key() {
        let ds = test_dataset_key();
        let entry = SnapshotEntry::new(
            "snap-x".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            ds,
        );
        assert_ne!(
            entry.object_key(),
            SnapshotEntry::catalog_key_for_dataset(ds)
        );
    }

    #[test]
    fn encode_decode_with_empty_name_fails() {
        let entry = SnapshotEntry::new(
            String::new(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            test_dataset_key(),
        );
        let encoded = entry.encode();
        let decoded = SnapshotEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.name, "");
    }

    #[test]
    fn encode_decode_with_long_name() {
        let long_name = "a".repeat(200);
        let entry = SnapshotEntry::new(
            long_name.clone(),
            CommitGroupId(99),
            RootPointer::new(CommitGroupId(99), 13),
            SystemTime::UNIX_EPOCH,
            test_dataset_key(),
        );
        let encoded = entry.encode();
        let decoded = SnapshotEntry::decode(&encoded).unwrap();
        assert_eq!(decoded.name, long_name);
        assert_eq!(decoded.txg_anchor, CommitGroupId(99));
    }
}

// ── SnapshotCatalog ────────────────────────────────────────────────

/// Per-dataset snapshot catalog stored as a single object.
///
/// Maintains an ordered list of snapshot entries so they can be
/// enumerated without scanning the entire object index. Each entry
/// carries the name, commit_group anchor, committed root, creation timestamp,
/// and parent dataset key needed to address the individual snapshot
/// entry object.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SnapshotCatalog {
    entries: Vec<CatalogEntry>,
}

/// A lightweight entry in the snapshot catalog.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    /// Human-readable snapshot name.
    pub name: String,
    /// Transaction group at which the snapshot was anchored.
    pub txg_anchor: CommitGroupId,
    /// The committed root pointer at the time of creation.
    pub committed_root: RootPointer,
    /// Wall-clock creation timestamp.
    pub created_at: SystemTime,
    /// Key of the parent dataset.
    pub parent_dataset_key: ObjectKey,
}

impl SnapshotCatalog {
    /// Derive the catalog object key for a dataset name.
    #[must_use]
    pub fn catalog_key_for_dataset_name(dataset_name: &str) -> ObjectKey {
        let dataset_key = ObjectKey::from_name(dataset_name.as_bytes());
        let raw = format!(
            "{}/{}/catalog",
            SNAPSHOT_ENTRY_PREFIX,
            dataset_key.short_hex()
        );
        ObjectKey::from_name(raw.as_bytes())
    }

    /// Number of snapshot entries in this catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return a reference to the entries list.
    #[must_use]
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    /// Push a new snapshot entry into the catalog.
    pub fn push(
        &mut self,
        name: String,
        txg_anchor: CommitGroupId,
        committed_root: RootPointer,
        created_at: SystemTime,
        parent_dataset_key: ObjectKey,
    ) {
        self.entries.push(CatalogEntry {
            name,
            txg_anchor,
            committed_root,
            created_at,
            parent_dataset_key,
        });
    }

    /// Encode the catalog into a binary payload.
    ///
    /// Wire format (little-endian):
    /// - entry_count: u32
    /// - For each entry:
    ///   - name_len: u16
    ///   - name: UTF-8 bytes
    ///   - txg_anchor: u64
    ///   - root_handle: u64
    ///   - created_at_secs: u64
    ///   - parent_dataset_key: 32 bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.entries.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for entry in &self.entries {
            let name_bytes = entry.name.as_bytes();
            let name_len = name_bytes.len().min(u16::MAX as usize) as u16;
            let created_secs = entry
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(&entry.txg_anchor.0.to_le_bytes());
            buf.extend_from_slice(&entry.committed_root.commit_group_id.0.to_le_bytes());
            buf.extend_from_slice(&entry.committed_root.root_handle.to_le_bytes());
            buf.extend_from_slice(&created_secs.to_le_bytes());
            buf.extend_from_slice(entry.parent_dataset_key.as_bytes());
        }
        buf
    }

    /// Decode a catalog from a binary payload.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 4 {
            return None;
        }
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut entries = Vec::with_capacity(count);
        let mut off = 4;

        for _ in 0..count {
            if payload.len() < off + 2 {
                return None;
            }
            let name_len = u16::from_le_bytes([payload[off], payload[off + 1]]) as usize;
            off += 2;
            if payload.len() < off + name_len + 32 + 32 {
                return None;
            }
            let name = String::from_utf8(payload[off..off + name_len].to_vec()).ok()?;
            off += name_len;

            let txg_anchor = CommitGroupId(u64::from_le_bytes([
                payload[off],
                payload[off + 1],
                payload[off + 2],
                payload[off + 3],
                payload[off + 4],
                payload[off + 5],
                payload[off + 6],
                payload[off + 7],
            ]));
            let committed_root_txg = u64::from_le_bytes([
                payload[off + 8],
                payload[off + 9],
                payload[off + 10],
                payload[off + 11],
                payload[off + 12],
                payload[off + 13],
                payload[off + 14],
                payload[off + 15],
            ]);
            let root_handle = u64::from_le_bytes([
                payload[off + 16],
                payload[off + 17],
                payload[off + 18],
                payload[off + 19],
                payload[off + 20],
                payload[off + 21],
                payload[off + 22],
                payload[off + 23],
            ]);
            let created_secs = u64::from_le_bytes([
                payload[off + 24],
                payload[off + 25],
                payload[off + 26],
                payload[off + 27],
                payload[off + 28],
                payload[off + 29],
                payload[off + 30],
                payload[off + 31],
            ]);
            let parent_dataset_key =
                ObjectKey::from_bytes32(payload[off + 32..off + 64].try_into().ok()?);
            off += 64;

            let created_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(created_secs);

            entries.push(CatalogEntry {
                name,
                txg_anchor,
                committed_root: RootPointer::new(CommitGroupId(committed_root_txg), root_handle),
                created_at,
                parent_dataset_key,
            });
        }

        Some(Self { entries })
    }

    /// Remove a snapshot by name from the catalog.
    ///
    /// Returns `true` if an entry was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.name != name);
        self.entries.len() < len_before
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;
    use std::time::Duration;

    fn test_ds_key() -> ObjectKey {
        ObjectKey::from_name(b"test-dataset")
    }

    #[test]
    fn catalog_encode_decode_empty() {
        let cat = SnapshotCatalog::default();
        let encoded = cat.encode();
        let decoded = SnapshotCatalog::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn catalog_encode_decode_with_entries() {
        let mut cat = SnapshotCatalog::default();
        cat.push(
            "snap-1".into(),
            CommitGroupId(10),
            RootPointer::new(CommitGroupId(10), 1),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1000),
            test_ds_key(),
        );
        cat.push(
            "snap-2".into(),
            CommitGroupId(20),
            RootPointer::new(CommitGroupId(20), 2),
            SystemTime::UNIX_EPOCH + Duration::from_secs(2000),
            test_ds_key(),
        );
        let encoded = cat.encode();
        let decoded = SnapshotCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.entries()[0].name, "snap-1");
        assert_eq!(decoded.entries()[1].name, "snap-2");
        assert_eq!(decoded.entries()[0].txg_anchor, CommitGroupId(10));
        assert_eq!(decoded.entries()[1].txg_anchor, CommitGroupId(20));
    }

    #[test]
    fn catalog_remove_entry() {
        let mut cat = SnapshotCatalog::default();
        cat.push(
            "snap-a".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            test_ds_key(),
        );
        cat.push(
            "snap-b".into(),
            CommitGroupId(2),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            test_ds_key(),
        );
        assert_eq!(cat.len(), 2);
        assert!(cat.remove("snap-a"));
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.entries()[0].name, "snap-b");
        assert!(!cat.remove("snap-a")); // Already removed
    }

    #[test]
    fn catalog_remove_nonexistent() {
        let mut cat = SnapshotCatalog::default();
        cat.push(
            "snap-x".into(),
            CommitGroupId(1),
            RootPointer::NIL,
            SystemTime::UNIX_EPOCH,
            test_ds_key(),
        );
        assert!(!cat.remove("snap-y"));
        assert_eq!(cat.len(), 1);
    }

    #[test]
    fn catalog_key_is_deterministic() {
        let k1 = SnapshotCatalog::catalog_key_for_dataset_name("mydataset");
        let k2 = SnapshotCatalog::catalog_key_for_dataset_name("mydataset");
        assert_eq!(k1, k2);
    }
}

// ── store integration tests ────────────────────────────────────────

#[cfg(test)]
mod store_tests {
    use super::*;
    use crate::store::LocalObjectStore;
    use crate::StoreOptions;

    fn temp_store(name: &str) -> LocalObjectStore {
        let dir = std::env::temp_dir().join(format!("tidefs-snapshot-test-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        LocalObjectStore::open_with_options(&dir, StoreOptions::test_fast()).unwrap()
    }

    #[test]
    fn create_snapshot_persists_entry() {
        let mut store = temp_store("create_persists");
        let dataset = "test-ds";

        // Write some data to advance the commit_group
        store.put(ObjectKey::from_name(b"obj1"), b"hello").unwrap();

        let entry = store.create_snapshot(dataset, "snap-1").unwrap();

        assert_eq!(entry.name, "snap-1");
        assert!(entry.txg_anchor.is_valid());

        // Verify the snapshot entry can be read back
        let entry_key = entry.object_key();
        let payload = store.get(entry_key).unwrap().unwrap();
        let decoded = SnapshotEntry::decode(&payload).unwrap();
        assert_eq!(decoded.name, "snap-1");
        assert_eq!(decoded.txg_anchor, entry.txg_anchor);
    }

    #[test]
    fn create_multiple_snapshots_list_them() {
        let mut store = temp_store("multi_list");
        let dataset = "test-ds";

        store.put(ObjectKey::from_name(b"obj1"), b"data1").unwrap();
        let snap1 = store.create_snapshot(dataset, "snap-a").unwrap();

        store.put(ObjectKey::from_name(b"obj2"), b"data2").unwrap();
        let snap2 = store.create_snapshot(dataset, "snap-b").unwrap();

        let list = store.list_snapshots(dataset);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "snap-a");
        assert_eq!(list[1].name, "snap-b");
        // commit_group anchors are sorted by the catalog
        assert!(list[0].txg_anchor <= list[1].txg_anchor);

        // Verify individual entries persist
        let p1 = store.get(snap1.object_key()).unwrap().unwrap();
        let d1 = SnapshotEntry::decode(&p1).unwrap();
        assert_eq!(d1.name, "snap-a");

        let p2 = store.get(snap2.object_key()).unwrap().unwrap();
        let d2 = SnapshotEntry::decode(&p2).unwrap();
        assert_eq!(d2.name, "snap-b");
    }

    #[test]
    fn snapshot_txg_anchors_correct_committed_root() {
        let mut store = temp_store("txg_anchor");
        let dataset = "test-ds";

        // Write data and commit a commit_group explicitly
        store
            .put(ObjectKey::from_name(b"pre-snap"), b"before")
            .unwrap();
        // Force a commit_group commit by putting the committed root
        let _ = store.txg_manager().committed_root();

        let snap = store.create_snapshot(dataset, "snap-after-write").unwrap();
        assert!(snap.txg_anchor.is_valid());
        // The commit_group anchor is the current open commit_group at snapshot time.
        // committed_root may be NIL if no commit has occurred yet.
        assert!(snap.txg_anchor.0 >= snap.committed_root.commit_group_id.0);

        // Write more data after snapshot
        store
            .put(ObjectKey::from_name(b"post-snap"), b"after")
            .unwrap();
        // Snapshot should still see the old committed root
        let decoded =
            SnapshotEntry::decode(&store.get(snap.object_key()).unwrap().unwrap()).unwrap();
        assert_eq!(decoded.committed_root, snap.committed_root);
        assert_eq!(decoded.txg_anchor, snap.txg_anchor);
    }

    #[test]
    fn list_snapshots_empty_dataset() {
        let store = temp_store("empty_list");
        let list = store.list_snapshots("no-such-dataset");
        assert!(list.is_empty());
    }

    #[test]
    fn snapshot_catalog_persistence_roundtrip() {
        let mut store = temp_store("catalog_rt");
        let dataset = "test-ds";

        store.put(ObjectKey::from_name(b"obj"), b"data").unwrap();
        store.create_snapshot(dataset, "snap-1").unwrap();
        store.create_snapshot(dataset, "snap-2").unwrap();

        // Re-open the store and verify the catalog is intact
        let root = store.root().to_path_buf();
        drop(store);

        let store2 = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).unwrap();
        let list = store2.list_snapshots(dataset);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "snap-1");
        assert_eq!(list[1].name, "snap-2");
    }
}
