// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Namespace entry removal with intent-log crash safety.
//!
//! [`remove_entry`] removes a directory entry from the namespace B-tree,
//! records an intent-log tombstone for crash recovery, and returns a
//! [`NamespaceEntryTombstone`] with a content hash.
//!
//! For directory entries, the directory must be empty (only `.` and `..`
//! remain). The child directory index is removed as part of the operation.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tidefs_dir_index::DirIndexError;
use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};

use crate::entry::{NamespaceEntry, NamespaceEntryTombstone};
use crate::{DirBackend, EntryType, Inode, NamespaceError};

// ---------------------------------------------------------------------------
// RemoveResult
// ---------------------------------------------------------------------------

/// Outcome of a namespace entry removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveResult {
    /// The tombstone proving the entry was removed.
    pub tombstone: NamespaceEntryTombstone,
    /// The intent-log record that was appended (if a buffer was provided).
    pub recorded: Option<IntentLogRecord>,
    /// Whether the removed entry was a directory (so its child index was
    /// also removed).
    pub was_directory: bool,
}

// ---------------------------------------------------------------------------
// remove_entry
// ---------------------------------------------------------------------------

/// Remove a directory entry from the namespace B-tree
/// and optional intent-log recording.
///
/// # Parameters
/// - `dirs`: shared directory index map (write-locked by caller).
/// - `parent`: inode of the parent directory.
/// - `name`: entry name as raw bytes.
/// - `intent_log`: optional buffer for crash-safe intent recording.
/// - `txg_id`: transaction group id for intent-log framing.
///
/// # Errors
/// - [`NamespaceError::NotFound`] if the entry doesn't exist.
/// - [`NamespaceError::NotEmpty`] if the entry is a directory that still has children.
/// - [`NamespaceError::InodeNotFound`] if the parent directory is not found.
/// - [`NamespaceError::NotDirectory`] if the parent inode is not a directory.
pub fn remove_entry(
    dirs: &Arc<RwLock<HashMap<Inode, DirBackend>>>,
    parent: Inode,
    name: Vec<u8>,
    intent_log: Option<&Arc<IntentLogBuffer>>,
    txg_id: u64,
) -> Result<RemoveResult, NamespaceError> {
    // Phase 1: look up the entry and validate (read lock).
    let (target_ino, entry_kind) = {
        let dirs_read = dirs.read().unwrap();
        let parent_dir = dirs_read
            .get(&parent)
            .ok_or(NamespaceError::InodeNotFound)?;
        let entry = parent_dir.lookup(&name).ok_or(NamespaceError::NotFound)?;
        let kind = EntryType::from_kind(entry.kind).ok_or(NamespaceError::NotSupported)?;
        (entry.inode_id, kind)
    };

    // Build the entry for the tombstone.
    let entry = NamespaceEntry::new(parent, name.clone(), target_ino, entry_kind);
    let tombstone = NamespaceEntryTombstone::from_entry(&entry);

    // Phase 2: if directory, check it's empty and remove child dir index.
    let was_directory = entry_kind == EntryType::Directory;
    if was_directory {
        {
            let dirs_read = dirs.read().unwrap();
            if let Some(child_dir) = dirs_read.get(&target_ino) {
                if child_dir.len() > 2 {
                    return Err(NamespaceError::NotEmpty);
                }
            }
        }
        dirs.write().unwrap().remove(&target_ino);
    }

    // Phase 3: remove entry from parent directory (write lock).
    {
        let mut dirs_write = dirs.write().unwrap();
        let parent_dir = dirs_write
            .get_mut(&parent)
            .ok_or(NamespaceError::InodeNotFound)?;

        parent_dir.delete(&name).map_err(|e| match e {
            DirIndexError::EntryNotFound => NamespaceError::NotFound,
            DirIndexError::DirNotEmpty => NamespaceError::NotEmpty,
            _ => NamespaceError::NotDirectory,
        })?;

        // If we removed the last subdirectory, clear the flag.
        if was_directory {
            let has_any_subdirs = parent_dir.len() > 2;
            if !has_any_subdirs {
                parent_dir.set_has_subdirs(false);
            }
        }
    }

    // Record intent-log tombstone for crash recovery.
    let recorded = if let Some(buf) = intent_log {
        let record = tombstone_to_intent_log_record(&tombstone);
        Some(buf.append(record, txg_id).record)
    } else {
        None
    };

    Ok(RemoveResult {
        tombstone,
        recorded,
        was_directory,
    })
}

// ---------------------------------------------------------------------------
// Intent-log record conversion
// ---------------------------------------------------------------------------

/// Convert a [`NamespaceEntryTombstone`] into the appropriate
/// [`IntentLogRecord`] variant for crash-safe recording.
fn tombstone_to_intent_log_record(tombstone: &NamespaceEntryTombstone) -> IntentLogRecord {
    match tombstone.kind {
        EntryType::Directory => IntentLogRecord::Rmdir {
            parent: tombstone.parent,
            name: tombstone.name.clone(),
            ino: tombstone.ino,
        },
        _ => IntentLogRecord::Unlink {
            parent: tombstone.parent,
            name: tombstone.name.clone(),
            ino: tombstone.ino,
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy;

    fn test_dirs_with_file() -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        let mut dirs = HashMap::new();
        let mut root = DirBackend::new(1, DatasetDirPolicy::DEFAULT);
        root.insert(b".", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"test.txt", 42, 0, crate::KIND_FILE).unwrap();
        dirs.insert(1, root);
        Arc::new(RwLock::new(dirs))
    }

    fn test_dirs_with_empty_dir() -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        let mut dirs = HashMap::new();
        let mut root = DirBackend::new(1, DatasetDirPolicy::DEFAULT);
        root.insert(b".", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"subdir", 50, 0, crate::KIND_DIR).unwrap();
        // Create the empty child directory
        let mut sub = DirBackend::new(50, DatasetDirPolicy::DEFAULT);
        sub.insert(b".", 50, 0, crate::KIND_DIR).unwrap();
        sub.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
        dirs.insert(1, root);
        dirs.insert(50, sub);
        Arc::new(RwLock::new(dirs))
    }

    fn test_intent_log() -> Arc<IntentLogBuffer> {
        Arc::new(IntentLogBuffer::new())
    }

    #[test]
    fn remove_existing_file_succeeds() {
        let dirs = test_dirs_with_file();
        let result = remove_entry(&dirs, 1, b"test.txt".to_vec(), None, 1).unwrap();
        assert!(result.tombstone.verify());
        assert_eq!(result.tombstone.ino, 42);
        assert_eq!(result.tombstone.kind, EntryType::File);
        assert!(!result.was_directory);
        // Verify the entry is gone
        let dirs_read = dirs.read().unwrap();
        assert!(dirs_read[&1].lookup(b"test.txt").is_none());
    }

    #[test]
    fn remove_existing_file_with_intent_log() {
        let dirs = test_dirs_with_file();
        let log = test_intent_log();
        let result = remove_entry(&dirs, 1, b"test.txt".to_vec(), Some(&log), 3).unwrap();
        assert!(result.recorded.is_some());
        let recorded = result.recorded.unwrap();
        match recorded {
            IntentLogRecord::Unlink { parent, name, ino } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"test.txt");
                assert_eq!(ino, 42);
            }
            _ => panic!("expected Unlink record"),
        }
    }

    #[test]
    fn remove_nonexistent_entry_fails() {
        let dirs = test_dirs_with_file();
        let err = remove_entry(&dirs, 1, b"nonexistent".to_vec(), None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::NotFound);
    }

    #[test]
    fn remove_from_nonexistent_parent_fails() {
        let dirs = test_dirs_with_file();
        let err = remove_entry(&dirs, 999, b"test.txt".to_vec(), None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::InodeNotFound);
    }

    #[test]
    fn remove_empty_directory_succeeds() {
        let dirs = test_dirs_with_empty_dir();
        let result = remove_entry(&dirs, 1, b"subdir".to_vec(), None, 1).unwrap();
        assert!(result.was_directory);
        assert_eq!(result.tombstone.kind, EntryType::Directory);
        // Child directory index should be removed
        let dirs_read = dirs.read().unwrap();
        assert!(!dirs_read.contains_key(&50));
        assert!(dirs_read[&1].lookup(b"subdir").is_none());
    }

    #[test]
    fn remove_nonempty_directory_fails() {
        let dirs = test_dirs_with_empty_dir();
        // Add a file inside subdir
        {
            let mut dirs_write = dirs.write().unwrap();
            dirs_write
                .get_mut(&50)
                .unwrap()
                .insert(b"child", 99, 0, crate::KIND_FILE)
                .unwrap();
        }
        let err = remove_entry(&dirs, 1, b"subdir".to_vec(), None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::NotEmpty);
        // subdir should still exist
        let dirs_read = dirs.read().unwrap();
        assert!(dirs_read.contains_key(&50));
    }

    #[test]
    fn remove_empty_directory_with_intent_log() {
        let dirs = test_dirs_with_empty_dir();
        let log = test_intent_log();
        let result = remove_entry(&dirs, 1, b"subdir".to_vec(), Some(&log), 5).unwrap();
        let recorded = result.recorded.unwrap();
        match recorded {
            IntentLogRecord::Rmdir { parent, name, ino } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"subdir");
                assert_eq!(ino, 50);
            }
            _ => panic!("expected Rmdir record"),
        }
    }

    #[test]
    fn remove_entry_tombstone_verification() {
        let dirs = test_dirs_with_file();
        let result = remove_entry(&dirs, 1, b"test.txt".to_vec(), None, 1).unwrap();
        assert!(result.tombstone.verify());
        // Tamper with the tombstone
        let mut tombstone = result.tombstone.clone();
        tombstone.name = b"tampered".to_vec();
        assert!(!tombstone.verify());
    }

    #[test]
    fn remove_intent_log_roundtrip() {
        let dirs = test_dirs_with_file();
        let log = test_intent_log();
        let _result = remove_entry(&dirs, 1, b"test.txt".to_vec(), Some(&log), 7).unwrap();

        let frames = log.drain_since(0);
        assert_eq!(frames.len(), 1);
        let decoded = IntentLogRecord::decode(&frames[0].record.encode()).unwrap();
        match decoded {
            IntentLogRecord::Unlink { parent, name, ino } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"test.txt");
                assert_eq!(ino, 42);
            }
            _ => panic!("expected Unlink after roundtrip"),
        }
    }

    #[test]
    fn double_remove_fails() {
        let dirs = test_dirs_with_file();
        remove_entry(&dirs, 1, b"test.txt".to_vec(), None, 1).unwrap();
        let err = remove_entry(&dirs, 1, b"test.txt".to_vec(), None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::NotFound);
    }
}
