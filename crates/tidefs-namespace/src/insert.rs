//! Namespace entry insertion with intent-log crash safety.
//!
//! [`insert_entry`] inserts a directory entry into the namespace B-tree,
//! records an intent-log record for crash recovery, and returns a
//! [`NamespaceEntry`] with a content hash.
//!
//! The function does not own the namespace; it takes the shared state
//! (directory map, inode table) as parameters so callers control locking
//! and transaction boundaries.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tidefs_dir_index::DirIndexError;
use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};
use tidefs_types_vfs_core::{S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK};

use crate::entry::NamespaceEntry;
use crate::{DirBackend, EntryType, Inode, NamespaceError};

// ---------------------------------------------------------------------------
// InsertResult
// ---------------------------------------------------------------------------

/// Outcome of a namespace entry insertion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InsertResult {
    /// The newly created entry with content hash.
    pub entry: NamespaceEntry,
    /// The intent-log record that was appended (if a buffer was provided).
    pub recorded: Option<IntentLogRecord>,
}

// ---------------------------------------------------------------------------
// insert_entry
// ---------------------------------------------------------------------------

/// Insert a directory entry into the namespace B-tree
/// and optional intent-log recording.
///
/// # Parameters
/// - `dirs`: shared directory index map (write-locked by caller).
/// - `parent`: inode of the parent directory.
/// - `name`: entry name as raw bytes (must be a valid basename -- validated
///   before calling).
/// - `ino`: target inode number.
/// - `kind`: entry type (file, directory, or symlink).
/// - `intent_log`: optional buffer for crash-safe intent recording.
/// - `txg_id`: transaction group id for intent-log framing.
///
/// # Errors
/// - [`NamespaceError::AlreadyExists`] if an entry with the same name exists.
/// - [`NamespaceError::InodeNotFound`] if the parent directory is not found.
/// - [`NamespaceError::NotDirectory`] if the parent inode is not a directory.
pub fn insert_entry(
    dirs: &Arc<RwLock<HashMap<Inode, DirBackend>>>,
    parent: Inode,
    name: Vec<u8>,
    ino: Inode,
    kind: EntryType,
    intent_log: Option<&Arc<IntentLogBuffer>>,
    txg_id: u64,
) -> Result<InsertResult, NamespaceError> {
    let entry = NamespaceEntry::new(parent, name.clone(), ino, kind);

    // Insert into the directory B-tree.
    {
        let mut dirs_write = dirs.write().unwrap();
        let dir = dirs_write
            .get_mut(&parent)
            .ok_or(NamespaceError::InodeNotFound)?;

        dir.insert(&name, ino, 0, kind.to_kind())
            .map_err(|e| match e {
                DirIndexError::EntryAlreadyExists => NamespaceError::AlreadyExists,
                DirIndexError::EntryNotFound => NamespaceError::NotFound,
                DirIndexError::DirNotEmpty => NamespaceError::NotEmpty,
            })?;
    }

    // Record intent-log entry for crash recovery.
    let recorded = if let Some(buf) = intent_log {
        let record = entry_to_intent_log_record(&entry);
        Some(buf.append(record, txg_id).record)
    } else {
        None
    };

    Ok(InsertResult { entry, recorded })
}

/// Insert a directory entry with explicit directory creation for new
/// subdirectories. Handles `.` and `..` initialization.
///
/// This is the variant to use for `mkdir`. After inserting the entry,
/// it creates the child directory index with `.` and `..` entries.
pub fn insert_directory_entry(
    dirs: &Arc<RwLock<HashMap<Inode, DirBackend>>>,
    parent: Inode,
    name: Vec<u8>,
    child_ino: Inode,
    intent_log: Option<&Arc<IntentLogBuffer>>,
    txg_id: u64,
    policy: tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy,
) -> Result<InsertResult, NamespaceError> {
    // Create the child directory index with . and .. entries.
    let mut child_dir = DirBackend::new(child_ino, policy);
    child_dir
        .insert(b".", child_ino, 0, crate::KIND_DIR)
        .map_err(|_| NamespaceError::AlreadyExists)?;
    child_dir
        .insert(b"..", parent, 0, crate::KIND_DIR)
        .map_err(|_| NamespaceError::AlreadyExists)?;

    let result = insert_entry(
        dirs,
        parent,
        name.clone(),
        child_ino,
        EntryType::Directory,
        intent_log,
        txg_id,
    )?;

    // Store the child directory index.
    {
        let mut dirs_write = dirs.write().unwrap();
        dirs_write.insert(child_ino, child_dir);
        // Mark parent as having subdirectories.
        if let Some(parent_dir) = dirs_write.get_mut(&parent) {
            parent_dir.set_has_subdirs(true);
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Intent-log record conversion
// ---------------------------------------------------------------------------

/// Convert a [`NamespaceEntry`] into the appropriate [`IntentLogRecord`]
/// variant for crash-safe recording.
fn entry_to_intent_log_record(entry: &NamespaceEntry) -> IntentLogRecord {
    match entry.kind {
        EntryType::File => IntentLogRecord::Create {
            parent: entry.parent,
            name: entry.name.clone(),
            mode: 0o644,
            ino: entry.ino,
        },
        EntryType::Directory => IntentLogRecord::Mkdir {
            parent: entry.parent,
            name: entry.name.clone(),
            mode: 0o755,
            ino: entry.ino,
        },
        EntryType::Symlink => IntentLogRecord::Symlink {
            parent: entry.parent,
            name: entry.name.clone(),
            target: vec![],
            ino: entry.ino,
        },
        EntryType::Fifo
        | EntryType::CharacterDevice
        | EntryType::BlockDevice
        | EntryType::Socket => {
            let mode = special_entry_mode(entry.kind);
            IntentLogRecord::Mknod {
                parent: entry.parent,
                name: entry.name.clone(),
                mode,
                // Review debt TFR-018: generic NamespaceEntry has no device-number authority.
                rdev: 0,
                ino: entry.ino,
            }
        }
    }
}

fn special_entry_mode(kind: EntryType) -> u32 {
    match kind {
        EntryType::Fifo => S_IFIFO | 0o644,
        EntryType::CharacterDevice => S_IFCHR | 0o644,
        EntryType::BlockDevice => S_IFBLK | 0o644,
        EntryType::Socket => S_IFSOCK | 0o644,
        EntryType::File | EntryType::Directory | EntryType::Symlink => unreachable!(),
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

    fn test_dirs() -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        let mut dirs = HashMap::new();
        let mut root = DirBackend::new(1, DatasetDirPolicy::DEFAULT);
        root.insert(b".", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
        dirs.insert(1, root);
        Arc::new(RwLock::new(dirs))
    }

    fn test_intent_log() -> Arc<IntentLogBuffer> {
        Arc::new(IntentLogBuffer::new())
    }

    #[test]
    fn insert_file_entry_succeeds() {
        let dirs = test_dirs();
        let result = insert_entry(
            &dirs,
            1,
            b"hello.txt".to_vec(),
            42,
            EntryType::File,
            None,
            1,
        )
        .unwrap();
        assert!(result.entry.verify());
        assert_eq!(result.entry.parent, 1);
        assert_eq!(result.entry.name, b"hello.txt");
        assert_eq!(result.entry.ino, 42);
        assert_eq!(result.entry.kind, EntryType::File);
        assert!(result.recorded.is_none());
    }

    #[test]
    fn insert_file_with_intent_log_records() {
        let dirs = test_dirs();
        let log = test_intent_log();
        let result = insert_entry(
            &dirs,
            1,
            b"data.bin".to_vec(),
            99,
            EntryType::File,
            Some(&log),
            7,
        )
        .unwrap();
        assert!(result.recorded.is_some());
        let recorded = result.recorded.unwrap();
        match recorded {
            IntentLogRecord::Create {
                parent, name, ino, ..
            } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"data.bin");
                assert_eq!(ino, 99);
            }
            _ => panic!("expected Create record"),
        }
    }

    #[test]
    fn insert_directory_entry_records_mkdir() {
        let dirs = test_dirs();
        let log = test_intent_log();
        let result = insert_directory_entry(
            &dirs,
            1,
            b"subdir".to_vec(),
            50,
            Some(&log),
            3,
            DatasetDirPolicy::DEFAULT,
        )
        .unwrap();
        assert!(result.entry.verify());
        assert_eq!(result.entry.kind, EntryType::Directory);
        {
            let dirs_read = dirs.read().unwrap();
            assert!(dirs_read.contains_key(&50));
        }
        let recorded = result.recorded.unwrap();
        match recorded {
            IntentLogRecord::Mkdir {
                parent, name, ino, ..
            } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"subdir");
                assert_eq!(ino, 50);
            }
            _ => panic!("expected Mkdir record"),
        }
    }

    #[test]
    fn insert_duplicate_entry_fails() {
        let dirs = test_dirs();
        insert_entry(&dirs, 1, b"dup".to_vec(), 10, EntryType::File, None, 1).unwrap();
        let err =
            insert_entry(&dirs, 1, b"dup".to_vec(), 20, EntryType::File, None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::AlreadyExists);
    }

    #[test]
    fn insert_into_nonexistent_parent_fails() {
        let dirs = test_dirs();
        let err =
            insert_entry(&dirs, 999, b"orphan".to_vec(), 10, EntryType::File, None, 1).unwrap_err();
        assert_eq!(err, NamespaceError::InodeNotFound);
    }

    #[test]
    fn insert_symlink_entry_records_symlink() {
        let dirs = test_dirs();
        let log = test_intent_log();
        let result = insert_entry(
            &dirs,
            1,
            b"link".to_vec(),
            77,
            EntryType::Symlink,
            Some(&log),
            1,
        )
        .unwrap();
        let recorded = result.recorded.unwrap();
        match recorded {
            IntentLogRecord::Symlink {
                parent, name, ino, ..
            } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"link");
                assert_eq!(ino, 77);
            }
            _ => panic!("expected Symlink record"),
        }
    }

    #[test]
    fn insert_special_entries_record_matching_mknod_mode() {
        for (name, kind, expected_type) in [
            (b"fifo".to_vec(), EntryType::Fifo, S_IFIFO),
            (b"char".to_vec(), EntryType::CharacterDevice, S_IFCHR),
            (b"block".to_vec(), EntryType::BlockDevice, S_IFBLK),
            (b"socket".to_vec(), EntryType::Socket, S_IFSOCK),
        ] {
            let dirs = test_dirs();
            let log = test_intent_log();
            let result = insert_entry(&dirs, 1, name.clone(), 88, kind, Some(&log), 1).unwrap();

            match result.recorded.unwrap() {
                IntentLogRecord::Mknod {
                    parent,
                    name: recorded_name,
                    mode,
                    rdev,
                    ino,
                } => {
                    assert_eq!(parent, 1);
                    assert_eq!(recorded_name, name);
                    assert_eq!(mode & 0o170000, expected_type);
                    assert_eq!(mode & 0o777, 0o644);
                    assert_eq!(rdev, 0);
                    assert_eq!(ino, 88);
                }
                other => panic!("expected Mknod record, got {other:?}"),
            }
        }
    }

    #[test]
    fn insert_result_entry_is_verified() {
        let dirs = test_dirs();
        let result = insert_entry(
            &dirs,
            1,
            b"verified.txt".to_vec(),
            42,
            EntryType::File,
            None,
            1,
        )
        .unwrap();
        assert!(result.entry.verify());
    }

    #[test]
    fn intent_log_record_roundtrip() {
        let dirs = test_dirs();
        let log = test_intent_log();
        let _result = insert_entry(
            &dirs,
            1,
            b"roundtrip".to_vec(),
            123,
            EntryType::File,
            Some(&log),
            5,
        )
        .unwrap();

        let frames = log.drain_since(0);
        assert_eq!(frames.len(), 1);
        let decoded = IntentLogRecord::decode(&frames[0].record.encode()).unwrap();
        match decoded {
            IntentLogRecord::Create {
                parent, name, ino, ..
            } => {
                assert_eq!(parent, 1);
                assert_eq!(name, b"roundtrip");
                assert_eq!(ino, 123);
            }
            _ => panic!("expected Create after roundtrip"),
        }
    }

    #[test]
    fn multiple_inserts_ordered_intent_log() {
        let dirs = test_dirs();
        let log = test_intent_log();

        insert_entry(&dirs, 1, b"a".to_vec(), 10, EntryType::File, Some(&log), 1).unwrap();
        insert_entry(&dirs, 1, b"b".to_vec(), 20, EntryType::File, Some(&log), 1).unwrap();
        insert_entry(&dirs, 1, b"c".to_vec(), 30, EntryType::File, Some(&log), 1).unwrap();

        let frames = log.drain_since(0);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].record_seq, 0);
        assert_eq!(frames[1].record_seq, 1);
        assert_eq!(frames[2].record_seq, 2);
    }

    #[test]
    fn insert_empty_name_succeeds_at_namespace_layer() {
        let dirs = test_dirs();
        // Empty names are accepted by DirIndex; name validation is the
        // caller's responsibility (done at the FUSE basename validation level).
        let result = insert_entry(&dirs, 1, vec![], 10, EntryType::File, None, 1).unwrap();
        assert!(result.entry.verify());
        assert_eq!(result.entry.name.len(), 0);
    }
}
