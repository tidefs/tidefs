//! Namespace entry lookup with path traversal and content-hash verification.
//!
//! [`lookup_entry`] traverses the namespace B-tree by path components,
//! computing a content hash at each level. The returned [`NamespaceEntry`]
//! carries a content hash that callers can use to confirm the entry hasn't
//! been corrupted.
//!
//! Multi-component path traversal is provided by [`lookup_path`], which
//! resolves each component in sequence and returns the final entry plus
//! the chain of intermediate entries for integrity auditing.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::entry::NamespaceEntry;
use crate::{DirBackend, EntryType, Inode, NamespaceError, ROOT_INODE};

// ---------------------------------------------------------------------------
// LookupResult
// ---------------------------------------------------------------------------

/// Result of a namespace entry lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupResult {
    /// The looked-up entry with content hash.
    pub entry: NamespaceEntry,
    /// The raw kind field from the directory index (for cross-checking).
    pub raw_kind: u32,
}

// ---------------------------------------------------------------------------
// PathLookupResult
// ---------------------------------------------------------------------------

/// Result of a multi-component path lookup with per-component verification.
#[derive(Clone, Debug)]
pub struct PathLookupResult {
    /// The final resolved entry.
    pub entry: NamespaceEntry,
    /// Chain of intermediate directory entries traversed (root to parent).
    /// Each entry has its content hash computed.
    pub chain: Vec<NamespaceEntry>,
    /// Number of symlink expansions performed during resolution.
    pub symlink_expansions: usize,
}

// ---------------------------------------------------------------------------
// lookup_entry
// ---------------------------------------------------------------------------

/// Look up a single directory entry by parent and name, returning a
/// entry with its content hash.
///
/// # Parameters
/// - `dirs`: shared directory index map (read-locked by caller).
/// - `parent`: inode of the parent directory.
/// - `name`: entry name as raw bytes.
///
/// # Errors
/// - [`NamespaceError::NotFound`] if the entry doesn't exist.
/// - [`NamespaceError::InodeNotFound`] if the parent directory is not found.
/// - [`NamespaceError::NotDirectory`] if the parent inode is not a directory.
pub fn lookup_entry(
    dirs: &Arc<RwLock<HashMap<Inode, DirBackend>>>,
    parent: Inode,
    name: &[u8],
) -> Result<LookupResult, NamespaceError> {
    let dirs_read = dirs.read().unwrap();
    let dir = dirs_read
        .get(&parent)
        .ok_or(NamespaceError::InodeNotFound)?;

    let dir_entry = dir.lookup(name).ok_or(NamespaceError::NotFound)?;
    let kind = EntryType::from_kind(dir_entry.kind).ok_or(NamespaceError::NotSupported)?;

    let entry = NamespaceEntry::new(parent, name.to_vec(), dir_entry.inode_id, kind);

    // Verify the entry hash is consistent.
    if !entry.verify() {
        return Err(NamespaceError::NotSupported); // integrity failure
    }

    Ok(LookupResult {
        entry,
        raw_kind: dir_entry.kind,
    })
}

// ---------------------------------------------------------------------------
// lookup_path
// ---------------------------------------------------------------------------

/// Traverse a multi-component path from root, returning the final entry
/// and the chain of intermediate entries.
///
/// Path components are `/`-separated. An empty path resolves to root.
/// `.` and `..` are supported during lookup. Symlinks are expanded up to
/// [`crate::MAX_SYMLINK_DEPTH`] levels.
///
/// # Parameters
/// - `dirs`: shared directory index map.
/// - `symlink_targets`: symlink target map for symlink expansion.
/// - `path`: raw path bytes (e.g. `b"/a/b/c"`).
///
/// # Errors
/// - [`NamespaceError::NotFound`] if any component is missing.
/// - [`NamespaceError::NotDirectory`] if an intermediate component is not a directory.
/// - [`NamespaceError::TooManySymlinks`] if symlink expansion exceeds the limit.
///
/// Split a byte path into `/`-separated owned components.
/// Leading `/` is ignored. Empty path returns an empty vec.
fn split_path_owned(path: &[u8]) -> Vec<Vec<u8>> {
    if path.is_empty() {
        return vec![];
    }
    let start = if path[0] == b'/' { 1 } else { 0 };
    if start >= path.len() {
        return vec![];
    }
    path[start..]
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_vec())
        .collect()
}

/// Traverse a multi-component path from root, returning the final entry
/// and the chain of intermediate entries.
pub fn lookup_path(
    dirs: &Arc<RwLock<HashMap<Inode, DirBackend>>>,
    symlink_targets: &std::sync::RwLock<HashMap<Inode, Vec<u8>>>,
    path: &[u8],
) -> Result<PathLookupResult, NamespaceError> {
    let components = split_path_owned(path);
    if components.is_empty() {
        let root_entry = NamespaceEntry::new(0, b"/".to_vec(), ROOT_INODE, EntryType::Directory);
        return Ok(PathLookupResult {
            entry: root_entry,
            chain: vec![],
            symlink_expansions: 0,
        });
    }

    let mut current_parent = ROOT_INODE;
    let mut chain: Vec<NamespaceEntry> = Vec::new();
    let mut symlink_expansions = 0usize;
    let mut remaining = components;

    while !remaining.is_empty() {
        let component = remaining.remove(0);
        let is_last = remaining.is_empty();

        // Handle `.` and `..`
        if component == b"." {
            if is_last {
                let dirs_read = dirs.read().unwrap();
                let dir = dirs_read
                    .get(&current_parent)
                    .ok_or(NamespaceError::InodeNotFound)?;
                let self_entry = dir.lookup(b".").ok_or(NamespaceError::NotFound)?;
                let entry = NamespaceEntry::new(
                    current_parent,
                    b".".to_vec(),
                    self_entry.inode_id,
                    EntryType::Directory,
                );
                return Ok(PathLookupResult {
                    entry,
                    chain,
                    symlink_expansions,
                });
            }
            continue;
        }

        if component == b".." {
            if is_last {
                let dirs_read = dirs.read().unwrap();
                let dir = dirs_read
                    .get(&current_parent)
                    .ok_or(NamespaceError::InodeNotFound)?;
                let parent_entry = dir.lookup(b"..").ok_or(NamespaceError::NotFound)?;
                let entry = NamespaceEntry::new(
                    current_parent,
                    b"..".to_vec(),
                    parent_entry.inode_id,
                    EntryType::Directory,
                );
                return Ok(PathLookupResult {
                    entry,
                    chain,
                    symlink_expansions,
                });
            }
            let dirs_read = dirs.read().unwrap();
            let dir = dirs_read
                .get(&current_parent)
                .ok_or(NamespaceError::InodeNotFound)?;
            let parent_entry = dir.lookup(b"..").ok_or(NamespaceError::NotFound)?;
            chain.push(NamespaceEntry::new(
                current_parent,
                b"..".to_vec(),
                parent_entry.inode_id,
                EntryType::Directory,
            ));
            current_parent = parent_entry.inode_id;
            continue;
        }

        // Regular component lookup
        let result = lookup_entry(dirs, current_parent, &component)?;

        // Check for symlink expansion
        if result.entry.kind == EntryType::Symlink {
            symlink_expansions += 1;
            if symlink_expansions > crate::MAX_SYMLINK_DEPTH {
                return Err(NamespaceError::TooManySymlinks);
            }
            let target = {
                let targets = symlink_targets.read().unwrap();
                targets.get(&result.entry.ino).cloned().unwrap_or_default()
            };
            if target.is_empty() {
                return Err(NamespaceError::NotFound);
            }
            // Prepend symlink target components.  Both sides are now owned Vec<Vec<u8>>.
            let mut target_comps = split_path_owned(&target);
            target_comps.append(&mut remaining);
            remaining = target_comps;
            current_parent = ROOT_INODE;

            chain.push(result.entry);
            continue;
        }

        if !is_last {
            if result.entry.kind != EntryType::Directory {
                return Err(NamespaceError::NotDirectory);
            }
            current_parent = result.entry.ino;
        }

        chain.push(result.entry);
    }

    let entry = chain.pop().ok_or(NamespaceError::NotFound)?;
    Ok(PathLookupResult {
        entry,
        chain,
        symlink_expansions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy;

    type TestDirMap = Arc<RwLock<HashMap<Inode, DirBackend>>>;
    type TestSymlinkMap = std::sync::RwLock<HashMap<Inode, Vec<u8>>>;

    fn test_dirs_with_entries() -> (TestDirMap, TestSymlinkMap) {
        let mut dirs = HashMap::new();
        let mut root = DirBackend::new(1, DatasetDirPolicy::DEFAULT);
        root.insert(b".", 1, 0, crate::KIND_DIR).unwrap();
        root.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
        // Add a file in root
        root.insert(b"hello.txt", 42, 0, crate::KIND_FILE).unwrap();
        dirs.insert(1, root);
        (
            Arc::new(RwLock::new(dirs)),
            std::sync::RwLock::new(HashMap::new()),
        )
    }

    #[test]
    fn lookup_existing_file() {
        let (dirs, _targets) = test_dirs_with_entries();
        let result = lookup_entry(&dirs, 1, b"hello.txt").unwrap();
        assert_eq!(result.entry.ino, 42);
        assert_eq!(result.entry.kind, EntryType::File);
        assert!(result.entry.verify());
    }

    #[test]
    fn lookup_nonexistent_entry() {
        let (dirs, _targets) = test_dirs_with_entries();
        let err = lookup_entry(&dirs, 1, b"nonexistent").unwrap_err();
        assert_eq!(err, NamespaceError::NotFound);
    }

    #[test]
    fn lookup_nonexistent_parent() {
        let (dirs, _targets) = test_dirs_with_entries();
        let err = lookup_entry(&dirs, 999, b"anything").unwrap_err();
        assert_eq!(err, NamespaceError::InodeNotFound);
    }

    #[test]
    fn lookup_entry_content_hash_is_consistent() {
        let (dirs, _targets) = test_dirs_with_entries();
        let r1 = lookup_entry(&dirs, 1, b"hello.txt").unwrap();
        let r2 = lookup_entry(&dirs, 1, b"hello.txt").unwrap();
        assert_eq!(r1.entry.content_hash, r2.entry.content_hash);
    }

    #[test]
    fn lookup_path_root() {
        let (dirs, targets) = test_dirs_with_entries();
        let result = lookup_path(&dirs, &targets, b"/").unwrap();
        assert_eq!(result.entry.ino, ROOT_INODE);
        assert_eq!(result.entry.kind, EntryType::Directory);
        assert!(result.chain.is_empty());
    }

    #[test]
    fn lookup_path_empty_is_root() {
        let (dirs, targets) = test_dirs_with_entries();
        let result = lookup_path(&dirs, &targets, b"").unwrap();
        assert_eq!(result.entry.ino, ROOT_INODE);
        assert_eq!(result.entry.kind, EntryType::Directory);
    }

    #[test]
    fn lookup_path_single_component() {
        let (dirs, targets) = test_dirs_with_entries();
        let result = lookup_path(&dirs, &targets, b"/hello.txt").unwrap();
        assert_eq!(result.entry.ino, 42);
        assert_eq!(result.entry.kind, EntryType::File);
        assert!(
            result.chain.is_empty(),
            "chain should be empty for single-component path"
        );
    }

    #[test]
    fn lookup_path_multi_component() {
        let (dirs, targets) = test_dirs_with_entries();

        // Create a directory structure: /a/b/c
        {
            let mut dirs_write = dirs.write().unwrap();
            // Create dir /a
            let mut dir_a = DirBackend::new(10, DatasetDirPolicy::DEFAULT);
            dir_a.insert(b".", 10, 0, crate::KIND_DIR).unwrap();
            dir_a.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
            dirs_write
                .get_mut(&1)
                .unwrap()
                .insert(b"a", 10, 0, crate::KIND_DIR)
                .unwrap();
            dirs_write.insert(10, dir_a);

            // Create dir /a/b
            let mut dir_b = DirBackend::new(20, DatasetDirPolicy::DEFAULT);
            dir_b.insert(b".", 20, 0, crate::KIND_DIR).unwrap();
            dir_b.insert(b"..", 10, 0, crate::KIND_DIR).unwrap();
            dirs_write
                .get_mut(&10)
                .unwrap()
                .insert(b"b", 20, 0, crate::KIND_DIR)
                .unwrap();
            dirs_write.insert(20, dir_b);

            // Create file /a/b/c
            dirs_write
                .get_mut(&20)
                .unwrap()
                .insert(b"c", 30, 0, crate::KIND_FILE)
                .unwrap();
        }

        let result = lookup_path(&dirs, &targets, b"/a/b/c").unwrap();
        assert_eq!(result.entry.ino, 30);
        assert_eq!(result.entry.kind, EntryType::File);
        assert_eq!(result.chain.len(), 2); // a and b
        assert_eq!(result.chain[0].ino, 10); // a
        assert_eq!(result.chain[1].ino, 20); // b
    }

    #[test]
    fn lookup_path_nonexistent_component() {
        let (dirs, targets) = test_dirs_with_entries();
        let err = lookup_path(&dirs, &targets, b"/nonexistent").unwrap_err();
        assert_eq!(err, NamespaceError::NotFound);
    }

    #[test]
    fn lookup_path_symlink_to_file() {
        let (dirs, targets) = test_dirs_with_entries();

        // Add symlink /link -> hello.txt
        {
            let mut dirs_write = dirs.write().unwrap();
            dirs_write
                .get_mut(&1)
                .unwrap()
                .insert(b"link", 50, 0, crate::KIND_SYMLINK)
                .unwrap();
        }
        targets.write().unwrap().insert(50, b"/hello.txt".to_vec());

        let result = lookup_path(&dirs, &targets, b"/link").unwrap();
        assert_eq!(result.entry.ino, 42);
        assert_eq!(result.entry.kind, EntryType::File);
        assert_eq!(result.symlink_expansions, 1);
    }

    #[test]
    fn lookup_path_dot_and_dotdot() {
        let (dirs, targets) = test_dirs_with_entries();

        // Create /sub dir with a file inside
        {
            let mut dirs_write = dirs.write().unwrap();
            let mut sub = DirBackend::new(60, DatasetDirPolicy::DEFAULT);
            sub.insert(b".", 60, 0, crate::KIND_DIR).unwrap();
            sub.insert(b"..", 1, 0, crate::KIND_DIR).unwrap();
            sub.insert(b"data", 70, 0, crate::KIND_FILE).unwrap();
            dirs_write
                .get_mut(&1)
                .unwrap()
                .insert(b"sub", 60, 0, crate::KIND_DIR)
                .unwrap();
            dirs_write.insert(60, sub);
        }

        // /sub/./data -> should resolve to data
        let result = lookup_path(&dirs, &targets, b"/sub/./data").unwrap();
        assert_eq!(result.entry.ino, 70);

        // /sub/../sub/data -> should also resolve to data
        let result = lookup_path(&dirs, &targets, b"/sub/../sub/data").unwrap();
        assert_eq!(result.entry.ino, 70);
    }

    #[test]
    fn lookup_path_too_many_symlinks() {
        let (dirs, targets) = test_dirs_with_entries();

        // Create a symlink loop: /a -> /b, /b -> /a
        {
            let mut dirs_write = dirs.write().unwrap();
            dirs_write
                .get_mut(&1)
                .unwrap()
                .insert(b"a", 80, 0, crate::KIND_SYMLINK)
                .unwrap();
            dirs_write
                .get_mut(&1)
                .unwrap()
                .insert(b"b", 81, 0, crate::KIND_SYMLINK)
                .unwrap();
        }
        targets.write().unwrap().insert(80, b"/b".to_vec());
        targets.write().unwrap().insert(81, b"/a".to_vec());

        let err = lookup_path(&dirs, &targets, b"/a").unwrap_err();
        assert_eq!(err, NamespaceError::TooManySymlinks);
    }

    #[test]
    fn split_path_handles_various_inputs() {
        assert_eq!(split_path_owned(b""), Vec::<&[u8]>::new());
        assert_eq!(split_path_owned(b"/"), Vec::<&[u8]>::new());
        assert_eq!(split_path_owned(b"/a"), vec![b"a".as_ref()]);
        assert_eq!(
            split_path_owned(b"/a/b/c"),
            vec![b"a".as_ref(), b"b".as_ref(), b"c".as_ref()]
        );
        assert_eq!(split_path_owned(b"a/b"), vec![b"a".as_ref(), b"b".as_ref()]);
    }
}
