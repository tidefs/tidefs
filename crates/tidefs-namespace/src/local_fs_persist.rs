//! `LocalFilesystemInodeStore` — bridges [`crate::persistence::PersistentInodeStore`]
//! to [`tidefs_local_filesystem::LocalFileSystem`]'s persistent inode storage.
//!
//! Gated behind the `local-fs-persist` feature flag.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tidefs_local_filesystem::{LocalFileSystem, PosixTimeRecord};
use tidefs_types_vfs_core::{
    Generation, InodeId, NodeFacets, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG,
    S_IFSOCK,
};

use crate::persistence::PersistentInodeStore;
use crate::{Inode, InodeAttributes, NamespaceError};

// ---------------------------------------------------------------------------
// LocalFilesystemInodeStore
// ---------------------------------------------------------------------------

/// A [`PersistentInodeStore`] that delegates to a real
/// [`LocalFileSystem`] for durable inode persistence.
pub struct LocalFilesystemInodeStore {
    fs: Arc<Mutex<LocalFileSystem>>,
}

impl LocalFilesystemInodeStore {
    /// Wrap an existing [`LocalFileSystem`] for use as a persistent inode store.
    pub fn new(fs: Arc<Mutex<LocalFileSystem>>) -> Self {
        Self { fs }
    }
}

impl PersistentInodeStore for LocalFilesystemInodeStore {
    fn alloc_inode(&self, attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError> {
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let gen = fs.generation();
        // Review debt TFR-004: namespace persistence currently delegates
        // allocation back into LocalFileSystem's global inode counter.
        // If attrs.inode is 0, it's a placeholder — generate a new ID.
        // If non-zero (e.g. ROOT_INODE=1), use it directly.
        let id = if attrs.inode != 0 {
            InodeId::new(attrs.inode)
        } else {
            InodeId::new(fs.next_inode_id().get().max(1))
        };
        let record = attrs_to_inode_record(attrs, id, gen);
        fs.insert_inode_at(id, record);
        Ok((id.get(), gen))
    }

    fn get_attrs(&self, inode: Inode) -> Option<InodeAttributes> {
        let fs = self.fs.lock().ok()?;
        fs.get_inode_by_id(InodeId::new(inode))
            .map(inode_record_to_attrs)
    }

    fn update_attrs(&self, inode: Inode, attrs: &InodeAttributes) -> Result<(), NamespaceError> {
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let id = InodeId::new(inode);
        let existing = fs
            .get_inode_by_id(id)
            .ok_or(NamespaceError::InodeNotFound)?;
        if existing.is_file_like() && attrs.size != existing.size {
            return Err(NamespaceError::NotSupported);
        }
        let mut record = existing.clone();
        record.mode = attrs.mode;
        record.uid = attrs.uid;
        record.gid = attrs.gid;
        record.size = attrs.size;
        record.nlink = attrs.nlink;
        record.rdev = attrs.rdev;
        record.metadata_version = record.metadata_version.saturating_add(1);
        fs.update_inode_record(id, record)
            .map_err(|_| NamespaceError::InodeNotFound)
    }

    fn free_inode(&self, inode: Inode) -> Result<(), NamespaceError> {
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        if fs.free_inode_id(InodeId::new(inode)) {
            Ok(())
        } else {
            Err(NamespaceError::InodeNotFound)
        }
    }

    fn next_inode_id(&self) -> Inode {
        self.fs
            .lock()
            .map(|fs| fs.next_inode_id().get())
            .unwrap_or(0)
    }

    fn generation(&self) -> u64 {
        self.fs.lock().map(|fs| fs.generation()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn attrs_to_inode_record(
    attrs: &InodeAttributes,
    next_id: InodeId,
    gen: u64,
) -> tidefs_local_filesystem::InodeRecord {
    let facets = mode_to_facets(attrs.mode);
    tidefs_local_filesystem::InodeRecord {
        dir_storage_kind: 0,
        inode_id: next_id,
        generation: Generation::new(gen),
        facets,
        mode: attrs.mode,
        uid: attrs.uid,
        gid: attrs.gid,
        nlink: attrs.nlink,
        size: attrs.size,
        data_version: 0,
        metadata_version: 0,
        posix_time: PosixTimeRecord::new(
            system_time_to_ns(attrs.atime),
            system_time_to_ns(attrs.mtime),
            system_time_to_ns(attrs.ctime),
            system_time_to_ns(attrs.ctime),
        ),
        xattr_storage_kind: 0,
        xattrs: std::collections::BTreeMap::new(),
        dir_rev: 0,
        rdev: attrs.rdev,
    }
}

fn inode_record_to_attrs(record: &tidefs_local_filesystem::InodeRecord) -> InodeAttributes {
    InodeAttributes {
        inode: record.inode_id.get(),
        mode: record.mode,
        uid: record.uid,
        gid: record.gid,
        size: record.size,
        nlink: record.nlink,
        atime: ns_to_system_time(record.posix_time.atime_ns),
        mtime: ns_to_system_time(record.posix_time.mtime_ns),
        ctime: ns_to_system_time(record.posix_time.ctime_ns),
        rdev: record.rdev,
    }
}

fn system_time_to_ns(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos().try_into().unwrap_or(i64::MAX),
        Err(error) => {
            let nanos: i64 = error.duration().as_nanos().try_into().unwrap_or(i64::MAX);
            -nanos
        }
    }
}

fn ns_to_system_time(ns: i64) -> SystemTime {
    if ns >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

fn mode_to_facets(mode: u32) -> NodeFacets {
    let masked = mode & S_IFMT;
    NodeFacets {
        has_byte_space: masked == S_IFREG || masked == S_IFLNK,
        has_child_namespace: masked == S_IFDIR,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InodeAttributes;

    #[test]
    fn attrs_to_record_roundtrip_file() {
        let attrs = InodeAttributes::new_file(42);
        let record = attrs_to_inode_record(&attrs, InodeId::new(42), 1);
        let back = inode_record_to_attrs(&record);
        assert_eq!(back.mode, attrs.mode);
        assert_eq!(back.uid, attrs.uid);
        assert_eq!(back.inode, 42);
    }

    #[test]
    fn attrs_to_record_roundtrip_dir() {
        let attrs = InodeAttributes::new_dir(1);
        let record = attrs_to_inode_record(&attrs, InodeId::new(1), 1);
        let back = inode_record_to_attrs(&record);
        assert_eq!(back.mode & S_IFMT, S_IFDIR);
    }

    #[test]
    fn attrs_to_record_roundtrip_special_rdev() {
        let mut attrs = InodeAttributes::new_file(7);
        attrs.mode = S_IFCHR | 0o660;
        attrs.rdev = 0x0103;

        let record = attrs_to_inode_record(&attrs, InodeId::new(7), 1);
        let back = inode_record_to_attrs(&record);

        assert_eq!(record.rdev, attrs.rdev);
        assert_eq!(back.mode & S_IFMT, S_IFCHR);
        assert_eq!(back.rdev, attrs.rdev);
    }

    #[test]
    fn mode_to_facets_directory() {
        let facets = mode_to_facets(S_IFDIR | 0o755);
        assert!(facets.has_child_namespace);
        assert!(!facets.has_byte_space);
    }

    #[test]
    fn mode_to_facets_file() {
        let facets = mode_to_facets(S_IFREG | 0o644);
        assert!(!facets.has_child_namespace);
        assert!(facets.has_byte_space);
    }

    #[test]
    fn mode_to_facets_symlink() {
        let facets = mode_to_facets(S_IFLNK | 0o777);
        assert!(!facets.has_child_namespace);
        assert!(facets.has_byte_space);
    }
}

// ---------------------------------------------------------------------------
// LocalFilesystemDirectoryStore
// ---------------------------------------------------------------------------

/// A [`PersistentDirectoryStore`] that delegates to a real
/// [`LocalFileSystem`] for durable directory entry persistence.
pub struct LocalFilesystemDirectoryStore {
    fs: Arc<Mutex<LocalFileSystem>>,
}

impl LocalFilesystemDirectoryStore {
    /// Wrap an existing [`LocalFileSystem`] for use as a persistent
    /// directory store.
    pub fn new(fs: Arc<Mutex<LocalFileSystem>>) -> Self {
        Self { fs }
    }
}

impl crate::persistence::PersistentDirectoryStore for LocalFilesystemDirectoryStore {
    fn lookup(
        &self,
        parent: Inode,
        name: &[u8],
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        let fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        if name == b"." {
            fs.list_dir_by_inode(InodeId::new(parent))
                .map_err(|_| NamespaceError::InodeNotFound)?;
            return Ok(Some((parent, 0, crate::KIND_DIR)));
        }
        if name == b".." {
            fs.list_dir_by_inode(InodeId::new(parent))
                .map_err(|_| NamespaceError::InodeNotFound)?;
            let parent_id = fs
                .parent_dir_for_inode(InodeId::new(parent))
                .unwrap_or(InodeId::new(parent));
            return Ok(Some((parent_id.get(), 0, crate::KIND_DIR)));
        }
        let entries = fs
            .list_dir_by_inode(InodeId::new(parent))
            .map_err(|_| NamespaceError::InodeNotFound)?;
        for entry in &entries {
            if entry.name == name {
                let kind = match entry.mode & S_IFMT {
                    S_IFDIR => crate::KIND_DIR,
                    S_IFLNK => crate::KIND_SYMLINK,
                    S_IFIFO => crate::KIND_FIFO,
                    S_IFSOCK => crate::KIND_SOCKET,
                    S_IFBLK => crate::KIND_BLOCK,
                    S_IFCHR => crate::KIND_CHAR,
                    _ => crate::KIND_FILE,
                };
                return Ok(Some((entry.inode_id.get(), entry.generation.get(), kind)));
            }
        }
        Ok(None)
    }

    fn insert(
        &self,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        generation: u64,
        kind: u32,
    ) -> Result<(), NamespaceError> {
        if name == b"." || name == b".." {
            return Ok(());
        }
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let mode = match kind {
            crate::KIND_DIR => S_IFDIR | 0o755,
            crate::KIND_SYMLINK => S_IFLNK | 0o777,
            crate::KIND_FIFO => S_IFIFO | 0o644,
            crate::KIND_SOCKET => S_IFSOCK | 0o644,
            crate::KIND_BLOCK => S_IFBLK | 0o644,
            crate::KIND_CHAR => S_IFCHR | 0o644,
            _ => S_IFREG | 0o644,
        };
        let facets = mode_to_facets(mode);
        let entry = tidefs_local_filesystem::NamespaceEntry {
            name: name.to_vec(),
            inode_id: InodeId::new(inode_id),
            generation: Generation::new(generation),
            facets,
            mode,
        };
        fs.insert_dir_entry(InodeId::new(parent), name.to_vec(), entry)
            .map_err(|_| NamespaceError::NotSupported)
    }

    fn remove(&self, parent: Inode, name: &[u8]) -> Result<(), NamespaceError> {
        if name == b"." || name == b".." {
            return Ok(());
        }
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        fs.remove_dir_entry(InodeId::new(parent), name)
            .map_err(|_| NamespaceError::NotFound)
    }

    fn list_dir(
        &self,
        parent: Inode,
        cookie: u64,
    ) -> Result<(Vec<crate::persistence::PersistentDirEntry>, u64), NamespaceError> {
        let fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let entries = fs
            .list_dir_by_inode(InodeId::new(parent))
            .map_err(|_| NamespaceError::InodeNotFound)?;
        let parent_id = fs
            .parent_dir_for_inode(InodeId::new(parent))
            .unwrap_or(InodeId::new(parent));
        let mut p_entries = Vec::with_capacity(entries.len() + 2);
        p_entries.push(crate::persistence::PersistentDirEntry {
            name: b".".to_vec(),
            inode_id: parent,
            generation: 0,
            kind: crate::KIND_DIR,
        });
        p_entries.push(crate::persistence::PersistentDirEntry {
            name: b"..".to_vec(),
            inode_id: parent_id.get(),
            generation: 0,
            kind: crate::KIND_DIR,
        });
        p_entries.extend(
            entries
                .iter()
                .map(|e| crate::persistence::PersistentDirEntry {
                    name: e.name.clone(),
                    inode_id: e.inode_id.get(),
                    generation: e.generation.get(),
                    kind: kind_from_mode(e.mode),
                }),
        );
        let skip = cookie as usize;
        let page_size = 128usize;
        let total = p_entries.len();
        if skip >= total {
            return Ok((Vec::new(), cookie));
        }
        let end = total.min(skip + page_size);
        let next_cookie = end as u64;
        Ok((p_entries[skip..end].to_vec(), next_cookie))
    }

    fn is_dir_empty(&self, parent: Inode) -> Result<bool, NamespaceError> {
        let fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let entries = fs
            .list_dir_by_inode(InodeId::new(parent))
            .map_err(|_| NamespaceError::InodeNotFound)?;
        Ok(entries.iter().all(|e| e.name == b"." || e.name == b".."))
    }

    fn atomic_swap(
        &self,
        src_parent: Inode,
        src_name: &[u8],
        dst_parent: Inode,
        dst_name: &[u8],
        mode: crate::persistence::PersistentSwapMode,
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;

        // Collect source directory entries before any mutable ops.
        let src_entries = fs
            .list_dir_by_inode(InodeId::new(src_parent))
            .map_err(|_| NamespaceError::InodeNotFound)?;
        let src_entry = src_entries
            .iter()
            .find(|e| e.name == src_name)
            .ok_or(NamespaceError::NotFound)?;
        let src_inode_id = src_entry.inode_id;
        let src_gen = src_entry.generation;
        let src_facets = src_entry.facets;
        let src_mode = src_entry.mode;

        // Look up destination entry.
        let dst_entry: Option<tidefs_local_filesystem::NamespaceEntry> = if src_parent == dst_parent
        {
            src_entries.iter().find(|e| e.name == dst_name).cloned()
        } else {
            let dst_entries = fs
                .list_dir_by_inode(InodeId::new(dst_parent))
                .map_err(|_| NamespaceError::InodeNotFound)?;
            dst_entries.into_iter().find(|e| e.name == dst_name)
        };

        match mode {
            crate::persistence::PersistentSwapMode::Exchange => {
                let dst = dst_entry.ok_or(NamespaceError::NotFound)?;

                fs.remove_dir_entry(InodeId::new(src_parent), src_name)
                    .map_err(|_| NamespaceError::NotFound)?;
                fs.remove_dir_entry(InodeId::new(dst_parent), dst_name)
                    .map_err(|_| NamespaceError::NotFound)?;

                // Swap: src_name gets dst's inode, dst_name gets src's inode.
                fs.insert_dir_entry(
                    InodeId::new(src_parent),
                    src_name.to_vec(),
                    tidefs_local_filesystem::NamespaceEntry {
                        name: src_name.to_vec(),
                        inode_id: dst.inode_id,
                        generation: dst.generation,
                        facets: dst.facets,
                        mode: dst.mode,
                    },
                )
                .map_err(|_| NamespaceError::NotSupported)?;
                fs.insert_dir_entry(
                    InodeId::new(dst_parent),
                    dst_name.to_vec(),
                    tidefs_local_filesystem::NamespaceEntry {
                        name: dst_name.to_vec(),
                        inode_id: src_inode_id,
                        generation: src_gen,
                        facets: src_facets,
                        mode: src_mode,
                    },
                )
                .map_err(|_| NamespaceError::NotSupported)?;

                Ok(None)
            }
            crate::persistence::PersistentSwapMode::NoReplace => {
                if dst_entry.is_some() {
                    return Err(NamespaceError::AlreadyExists);
                }
                // Move source to destination.
                fs.remove_dir_entry(InodeId::new(src_parent), src_name)
                    .map_err(|_| NamespaceError::NotFound)?;
                fs.insert_dir_entry(
                    InodeId::new(dst_parent),
                    dst_name.to_vec(),
                    tidefs_local_filesystem::NamespaceEntry {
                        name: dst_name.to_vec(),
                        inode_id: src_inode_id,
                        generation: src_gen,
                        facets: src_facets,
                        mode: src_mode,
                    },
                )
                .map_err(|_| NamespaceError::NotSupported)?;
                Ok(None)
            }
            crate::persistence::PersistentSwapMode::Rename => {
                let overwritten = dst_entry.as_ref().map(|de| {
                    (
                        de.inode_id.get(),
                        de.generation.get(),
                        kind_from_mode(de.mode),
                    )
                });

                // Remove source entry.
                fs.remove_dir_entry(InodeId::new(src_parent), src_name)
                    .map_err(|_| NamespaceError::NotFound)?;
                // If target exists, remove it (overwrite).
                if overwritten.is_some() {
                    fs.remove_dir_entry(InodeId::new(dst_parent), dst_name)
                        .map_err(|_| NamespaceError::NotFound)?;
                }
                // Insert source at destination name.
                fs.insert_dir_entry(
                    InodeId::new(dst_parent),
                    dst_name.to_vec(),
                    tidefs_local_filesystem::NamespaceEntry {
                        name: dst_name.to_vec(),
                        inode_id: src_inode_id,
                        generation: src_gen,
                        facets: src_facets,
                        mode: src_mode,
                    },
                )
                .map_err(|_| NamespaceError::NotSupported)?;
                Ok(overwritten)
            }
        }
    }

    fn init_dir(&self, dir_inode: Inode) -> Result<(), NamespaceError> {
        let mut fs = self.fs.lock().map_err(|_| NamespaceError::NotSupported)?;
        let id = InodeId::new(dir_inode);
        fs.init_dir_by_inode(id)
            .map_err(|_| NamespaceError::NotSupported)
    }
}

/// Map a POSIX mode ( bits) to a namespace  constant.
fn kind_from_mode(mode: u32) -> u32 {
    match mode & tidefs_types_vfs_core::S_IFMT {
        tidefs_types_vfs_core::S_IFDIR => crate::KIND_DIR,
        tidefs_types_vfs_core::S_IFLNK => crate::KIND_SYMLINK,
        tidefs_types_vfs_core::S_IFIFO => crate::KIND_FIFO,
        tidefs_types_vfs_core::S_IFSOCK => crate::KIND_SOCKET,
        tidefs_types_vfs_core::S_IFBLK => crate::KIND_BLOCK,
        tidefs_types_vfs_core::S_IFCHR => crate::KIND_CHAR,
        _ => crate::KIND_FILE,
    }
}

// ---------------------------------------------------------------------------
// Integration tests — namespace ⇄ local-filesystem round-trip
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::persistence::PersistentDirectoryStore;
    use crate::{InodeAttributes, Namespace, ROOT_INODE};
    use std::sync::Arc;

    fn test_attrs_file() -> InodeAttributes {
        InodeAttributes::new_file(0)
    }
    fn test_attrs_dir() -> InodeAttributes {
        InodeAttributes::new_dir(0)
    }

    fn test_fs(temp: &tempfile::TempDir) -> Arc<Mutex<LocalFileSystem>> {
        let root_key = tidefs_local_filesystem::RootAuthenticationKey::demo_key();
        let fs = LocalFileSystem::open_with_root_authentication_key(
            temp.path(),
            tidefs_local_filesystem::human::local_filesystem::StoreOptions::test_fast(),
            root_key,
        )
        .expect("open local filesystem");
        Arc::new(Mutex::new(fs))
    }

    fn finish_bridge_conversion_test(fs: Arc<Mutex<LocalFileSystem>>) {
        // Review debt TFR-004: direct bridge calls bypass the normal
        // LocalFileSystem mutation transaction path.
        std::mem::forget(fs);
    }

    #[test]
    fn real_inode_alloc_and_get_attrs() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-int-").unwrap();
        let fs = test_fs(&_temp);
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns = Namespace::with_persistent_stores(
            Some(inode_store as Arc<dyn PersistentInodeStore>),
            Some(dir_store as Arc<dyn PersistentDirectoryStore>),
        );

        let file_ino = ns
            .create_file(ROOT_INODE, "hello.txt", test_attrs_file())
            .expect("create file");
        let attrs = ns.get_attrs(file_ino).expect("get attrs");
        assert_eq!(attrs.inode, file_ino);
        assert!(attrs.nlink > 0);
    }

    #[test]
    fn real_inode_store_preserves_special_rdev() {
        let temp = tempfile::TempDir::with_prefix("tidefs-ns-rdev-").unwrap();
        let fs = test_fs(&temp);
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let mut attrs = InodeAttributes::new_file(0);
        attrs.mode = S_IFCHR | 0o660;
        attrs.rdev = 0x0103;

        let (ino, _) = inode_store.alloc_inode(&attrs).unwrap();
        dir_store
            .insert(ROOT_INODE, b"null", ino, 1, crate::KIND_CHAR)
            .unwrap();
        let stored = inode_store.get_attrs(ino).unwrap();
        assert_eq!(stored.mode & S_IFMT, S_IFCHR);
        assert_eq!(stored.rdev, 0x0103);

        let mut updated = stored.clone();
        updated.rdev = 0x0105;
        inode_store.update_attrs(ino, &updated).unwrap();

        let stored = inode_store.get_attrs(ino).unwrap();
        assert_eq!(stored.mode & S_IFMT, S_IFCHR);
        assert_eq!(stored.rdev, 0x0105);

        drop(dir_store);
        drop(inode_store);
        finish_bridge_conversion_test(fs);
    }

    #[test]
    fn real_inode_store_rejects_file_size_without_content_object() {
        let temp = tempfile::TempDir::with_prefix("tidefs-ns-size-gate-").unwrap();
        let fs = test_fs(&temp);
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let (ino, _) = inode_store.alloc_inode(&test_attrs_file()).unwrap();
        let mut attrs = inode_store.get_attrs(ino).unwrap();
        attrs.size = 4096;

        assert_eq!(
            inode_store.update_attrs(ino, &attrs),
            Err(NamespaceError::NotSupported)
        );

        drop(inode_store);
        finish_bridge_conversion_test(fs);
    }

    #[test]
    fn real_directory_store_lists_special_kinds() {
        let temp = tempfile::TempDir::with_prefix("tidefs-ns-kinds-").unwrap();
        let fs = test_fs(&temp);
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));

        for (name, mode, rdev, kind) in [
            (b"pipe".as_slice(), S_IFIFO | 0o644, 0, crate::KIND_FIFO),
            (
                b"null".as_slice(),
                S_IFCHR | 0o644,
                0x0103,
                crate::KIND_CHAR,
            ),
            (
                b"disk".as_slice(),
                S_IFBLK | 0o644,
                0x0801,
                crate::KIND_BLOCK,
            ),
            (b"sock".as_slice(), S_IFSOCK | 0o644, 0, crate::KIND_SOCKET),
        ] {
            let mut attrs = InodeAttributes::new_file(0);
            attrs.mode = mode;
            attrs.rdev = rdev;
            let (ino, _) = inode_store.alloc_inode(&attrs).unwrap();
            dir_store.insert(ROOT_INODE, name, ino, 1, kind).unwrap();
        }

        let (entries, _) = dir_store.list_dir(ROOT_INODE, 0).unwrap();

        for (name, kind) in [
            (b"pipe".as_slice(), crate::KIND_FIFO),
            (b"null".as_slice(), crate::KIND_CHAR),
            (b"disk".as_slice(), crate::KIND_BLOCK),
            (b"sock".as_slice(), crate::KIND_SOCKET),
        ] {
            let entry = entries
                .iter()
                .find(|entry| entry.name == name)
                .expect("listed special node");
            assert_eq!(entry.kind, kind, "wrong kind for {name:?}");
        }

        drop(dir_store);
        drop(inode_store);
        finish_bridge_conversion_test(fs);
    }

    #[test]
    fn real_directory_store_full_final_page_advances_cookie() {
        let temp = tempfile::TempDir::with_prefix("tidefs-ns-cookie-").unwrap();
        let fs = test_fs(&temp);
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));

        for i in 0..126u64 {
            let name = format!("entry_{i:03}");
            let (ino, generation) = inode_store.alloc_inode(&test_attrs_file()).unwrap();
            dir_store
                .insert(
                    ROOT_INODE,
                    name.as_bytes(),
                    ino,
                    generation,
                    crate::KIND_FILE,
                )
                .unwrap();
        }

        let (entries, next_cookie) = dir_store.list_dir(ROOT_INODE, 0).unwrap();
        assert_eq!(entries.len(), 128);
        assert_eq!(next_cookie, 128);

        let (tail, tail_cookie) = dir_store.list_dir(ROOT_INODE, next_cookie).unwrap();
        assert!(tail.is_empty());
        assert_eq!(tail_cookie, next_cookie);

        drop(dir_store);
        drop(inode_store);
        finish_bridge_conversion_test(fs);
    }

    #[test]
    fn real_dir_create_and_lookup() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-int-").unwrap();
        let fs = test_fs(&_temp);
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns = Namespace::with_persistent_stores(Some(inode_store), Some(dir_store));

        let sub_ino = ns
            .create_dir(ROOT_INODE, "subdir", test_attrs_dir())
            .expect("create dir");
        let found = ns.lookup(ROOT_INODE, "subdir").unwrap();
        assert_eq!(found, Some(sub_ino));

        // Create a file inside the subdirectory.
        let file_ino = ns
            .create_file(sub_ino, "nested.txt", test_attrs_file())
            .expect("create nested file");
        assert_eq!(ns.lookup(sub_ino, "nested.txt").unwrap(), Some(file_ino));
    }

    #[test]
    fn real_remount_inode_and_dir_survive() {
        // Verifies that inode and directory state survives when a new
        // Namespace is constructed over the same persistent stores.
        // Full on-disk remount requires deeper persistence layer
        // integration (content-object handling, . and .. exclusion
        // from serialization). Review debt TFR-004 covers durable indexing.
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-int-").unwrap();
        let root_key = tidefs_local_filesystem::RootAuthenticationKey::demo_key();
        let fs = Arc::new(Mutex::new(
            LocalFileSystem::open_with_root_authentication_key(
                _temp.path(),
                tidefs_local_filesystem::human::local_filesystem::StoreOptions::test_fast(),
                root_key,
            )
            .expect("open"),
        ));
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns1 = Namespace::with_persistent_stores(
            Some(inode_store as Arc<dyn PersistentInodeStore>),
            Some(dir_store as Arc<dyn PersistentDirectoryStore>),
        );

        let sub_ino = ns1
            .create_dir(ROOT_INODE, "docs", test_attrs_dir())
            .unwrap();
        let file_ino = ns1
            .create_file(sub_ino, "readme.md", test_attrs_file())
            .unwrap();
        let mut attrs = ns1.get_attrs(file_ino).unwrap();
        attrs.uid = 1000;
        attrs.gid = 1000;
        ns1.update_attrs(file_ino, attrs).unwrap();

        // "Remount": create a second Namespace reusing the same stores.
        let inode_store2 = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store2 = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));
        let ns2 = Namespace::with_persistent_stores(
            Some(inode_store2 as Arc<dyn PersistentInodeStore>),
            Some(dir_store2 as Arc<dyn PersistentDirectoryStore>),
        );

        // Verify directory structure is visible from the second namespace.
        let sub = ns2
            .lookup(ROOT_INODE, "docs")
            .unwrap()
            .expect("docs dir visible from ns2");
        let file = ns2
            .lookup(sub, "readme.md")
            .unwrap()
            .expect("readme.md visible from ns2");
        let reloaded = ns2.get_attrs(file).unwrap();
        assert_eq!(reloaded.uid, 1000);
        assert_eq!(reloaded.gid, 1000);
        assert_eq!(reloaded.inode, file);
        assert_eq!(
            ns2.resolve(std::path::Path::new("/docs/..")).unwrap(),
            ROOT_INODE
        );
    }

    #[test]
    fn real_remount_special_node_survives_kind_and_rdev() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-special-remount-").unwrap();
        let fs = test_fs(&_temp);
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns1 = Namespace::with_persistent_stores(
            Some(inode_store as Arc<dyn PersistentInodeStore>),
            Some(dir_store as Arc<dyn PersistentDirectoryStore>),
        );

        let special = ns1
            .mknod(ROOT_INODE, "null", S_IFCHR | 0o660, 0x0103)
            .unwrap();
        assert_eq!(ns1.get_attrs(special).unwrap().rdev, 0x0103);
        {
            let fs_guard = fs.lock().unwrap();
            assert!(!fs_guard
                .get_inode_by_id(InodeId::new(ROOT_INODE))
                .unwrap()
                .is_file_like());
            assert!(!fs_guard
                .get_inode_by_id(InodeId::new(special))
                .unwrap()
                .is_file_like());
        }

        let inode_store2 = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store2 = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));
        let ns2 = Namespace::with_persistent_stores(
            Some(inode_store2 as Arc<dyn PersistentInodeStore>),
            Some(dir_store2 as Arc<dyn PersistentDirectoryStore>),
        );

        let reloaded = ns2
            .lookup(ROOT_INODE, "null")
            .unwrap()
            .expect("special node visible from ns2");
        assert_eq!(reloaded, special);
        let attrs = ns2.get_attrs(reloaded).unwrap();
        assert_eq!(attrs.mode & S_IFMT, S_IFCHR);
        assert_eq!(attrs.rdev, 0x0103);

        let (entries, _) = ns2
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        let entry = entries
            .iter()
            .find(|entry| entry.name.as_slice() == b"null")
            .expect("special node listed after remount");
        assert_eq!(entry.kind, crate::KIND_CHAR);
    }

    #[test]
    fn real_remount_rename_updates_directory_store() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-rename-remount-").unwrap();
        let fs = test_fs(&_temp);
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns1 = Namespace::with_persistent_stores(
            Some(inode_store as Arc<dyn PersistentInodeStore>),
            Some(dir_store as Arc<dyn PersistentDirectoryStore>),
        );

        let src_dir = ns1.create_dir(ROOT_INODE, "src", test_attrs_dir()).unwrap();
        let dst_dir = ns1.create_dir(ROOT_INODE, "dst", test_attrs_dir()).unwrap();
        let file = ns1
            .create_file(src_dir, "before.txt", test_attrs_file())
            .unwrap();

        ns1.rename(src_dir, "before.txt", dst_dir, "after.txt")
            .unwrap();
        assert_eq!(ns1.lookup(src_dir, "before.txt").unwrap(), None);
        assert_eq!(ns1.lookup(dst_dir, "after.txt").unwrap(), Some(file));

        let inode_store2 = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store2 = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));
        let ns2 = Namespace::with_persistent_stores(
            Some(inode_store2 as Arc<dyn PersistentInodeStore>),
            Some(dir_store2 as Arc<dyn PersistentDirectoryStore>),
        );

        let reloaded_src = ns2
            .lookup(ROOT_INODE, "src")
            .unwrap()
            .expect("source dir visible after remount");
        let reloaded_dst = ns2
            .lookup(ROOT_INODE, "dst")
            .unwrap()
            .expect("destination dir visible after remount");
        assert_eq!(ns2.lookup(reloaded_src, "before.txt").unwrap(), None);
        assert_eq!(ns2.lookup(reloaded_dst, "after.txt").unwrap(), Some(file));
        assert_eq!(
            ns2.resolve(std::path::Path::new("/dst/..")).unwrap(),
            ROOT_INODE
        );
    }

    #[test]
    fn real_remount_exchange_updates_directory_store() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-exchange-remount-").unwrap();
        let fs = test_fs(&_temp);
        let inode_store = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));

        let ns1 = Namespace::with_persistent_stores(
            Some(inode_store as Arc<dyn PersistentInodeStore>),
            Some(dir_store as Arc<dyn PersistentDirectoryStore>),
        );

        let left = ns1
            .create_file(ROOT_INODE, "left.txt", test_attrs_file())
            .unwrap();
        let right = ns1
            .create_file(ROOT_INODE, "right.txt", test_attrs_file())
            .unwrap();

        ns1.rename_with_flags(
            ROOT_INODE,
            "left.txt",
            ROOT_INODE,
            "right.txt",
            crate::RENAME_EXCHANGE,
        )
        .unwrap();

        let inode_store2 = Arc::new(LocalFilesystemInodeStore::new(Arc::clone(&fs)));
        let dir_store2 = Arc::new(LocalFilesystemDirectoryStore::new(Arc::clone(&fs)));
        let ns2 = Namespace::with_persistent_stores(
            Some(inode_store2 as Arc<dyn PersistentInodeStore>),
            Some(dir_store2 as Arc<dyn PersistentDirectoryStore>),
        );

        assert_eq!(ns2.lookup(ROOT_INODE, "left.txt").unwrap(), Some(right));
        assert_eq!(ns2.lookup(ROOT_INODE, "right.txt").unwrap(), Some(left));
    }

    // ── atomic_swap tests ────────────────────────────────────────

    #[test]
    fn atomic_swap_rename_same_dir_moves_entry() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        // Create two files in root.
        let attr = test_attrs_file();
        let src_ino = inode_store.alloc_inode(&attr).unwrap().0;
        let dst_ino = inode_store.alloc_inode(&attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"src.txt", src_ino, 1, crate::KIND_FILE)
            .unwrap();
        dir_store
            .insert(ROOT_INODE, b"dst.txt", dst_ino, 1, crate::KIND_FILE)
            .unwrap();

        // Rename src -> dst (overwrite).
        let overwritten = dir_store
            .atomic_swap(
                ROOT_INODE,
                b"src.txt",
                ROOT_INODE,
                b"dst.txt",
                crate::persistence::PersistentSwapMode::Rename,
            )
            .unwrap();

        assert!(overwritten.is_some());
        let (ov_ino, ov_gen, ov_kind) = overwritten.unwrap();
        assert_eq!(ov_ino, dst_ino);
        assert_eq!(ov_gen, 1);
        assert_eq!(ov_kind, crate::KIND_FILE);

        // src.txt should be gone, dst.txt should now point to src_ino.
        assert!(dir_store.lookup(ROOT_INODE, b"src.txt").unwrap().is_none());
        let remaining = dir_store.lookup(ROOT_INODE, b"dst.txt").unwrap();
        assert_eq!(remaining, Some((src_ino, 1, crate::KIND_FILE)));
    }

    #[test]
    fn atomic_swap_noreplace_rejects_existing_target() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let attr = test_attrs_file();
        let src_ino = inode_store.alloc_inode(&attr).unwrap().0;
        let dst_ino = inode_store.alloc_inode(&attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"file_a", src_ino, 1, crate::KIND_FILE)
            .unwrap();
        dir_store
            .insert(ROOT_INODE, b"file_b", dst_ino, 1, crate::KIND_FILE)
            .unwrap();

        let result = dir_store.atomic_swap(
            ROOT_INODE,
            b"file_a",
            ROOT_INODE,
            b"file_b",
            crate::persistence::PersistentSwapMode::NoReplace,
        );
        assert!(matches!(result, Err(NamespaceError::AlreadyExists)));

        // Both entries should still be intact.
        assert_eq!(
            dir_store.lookup(ROOT_INODE, b"file_a").unwrap(),
            Some((src_ino, 1, crate::KIND_FILE))
        );
        assert_eq!(
            dir_store.lookup(ROOT_INODE, b"file_b").unwrap(),
            Some((dst_ino, 1, crate::KIND_FILE))
        );
    }

    #[test]
    fn atomic_swap_noreplace_succeeds_when_target_absent() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let attr = test_attrs_file();
        let src_ino = inode_store.alloc_inode(&attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"old_name", src_ino, 1, crate::KIND_FILE)
            .unwrap();

        let overwritten = dir_store
            .atomic_swap(
                ROOT_INODE,
                b"old_name",
                ROOT_INODE,
                b"new_name",
                crate::persistence::PersistentSwapMode::NoReplace,
            )
            .unwrap();
        assert!(overwritten.is_none());

        assert!(dir_store.lookup(ROOT_INODE, b"old_name").unwrap().is_none());
        assert_eq!(
            dir_store.lookup(ROOT_INODE, b"new_name").unwrap(),
            Some((src_ino, 1, crate::KIND_FILE))
        );
    }

    #[test]
    fn atomic_swap_exchange_same_dir_swaps_entries() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let attr = test_attrs_file();
        let ino_a = inode_store.alloc_inode(&attr).unwrap().0;
        let ino_b = inode_store.alloc_inode(&attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"alpha", ino_a, 1, crate::KIND_FILE)
            .unwrap();
        dir_store
            .insert(ROOT_INODE, b"beta", ino_b, 2, crate::KIND_FILE)
            .unwrap();

        let result = dir_store
            .atomic_swap(
                ROOT_INODE,
                b"alpha",
                ROOT_INODE,
                b"beta",
                crate::persistence::PersistentSwapMode::Exchange,
            )
            .unwrap();
        assert!(result.is_none());

        // Names stay, inode references swap.
        assert_eq!(
            dir_store.lookup(ROOT_INODE, b"alpha").unwrap(),
            Some((ino_b, 2, crate::KIND_FILE))
        );
        assert_eq!(
            dir_store.lookup(ROOT_INODE, b"beta").unwrap(),
            Some((ino_a, 1, crate::KIND_FILE))
        );
    }

    #[test]
    fn atomic_swap_exchange_cross_dir_swaps_entries() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let dir_attr = test_attrs_dir();
        let sub_a = inode_store.alloc_inode(&dir_attr).unwrap().0;
        let sub_b = inode_store.alloc_inode(&dir_attr).unwrap().0;
        // Also alloc root.
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"dir_a", sub_a, 1, crate::KIND_DIR)
            .unwrap();
        dir_store
            .insert(ROOT_INODE, b"dir_b", sub_b, 1, crate::KIND_DIR)
            .unwrap();
        dir_store.init_dir(sub_a).unwrap();
        dir_store.init_dir(sub_b).unwrap();

        let file_attr = test_attrs_file();
        let ino_x = inode_store.alloc_inode(&file_attr).unwrap().0;
        let ino_y = inode_store.alloc_inode(&file_attr).unwrap().0;
        dir_store
            .insert(sub_a, b"file_x", ino_x, 1, crate::KIND_FILE)
            .unwrap();
        dir_store
            .insert(sub_b, b"file_y", ino_y, 2, crate::KIND_FILE)
            .unwrap();

        let result = dir_store
            .atomic_swap(
                sub_a,
                b"file_x",
                sub_b,
                b"file_y",
                crate::persistence::PersistentSwapMode::Exchange,
            )
            .unwrap();
        assert!(result.is_none());

        assert_eq!(
            dir_store.lookup(sub_a, b"file_x").unwrap(),
            Some((ino_y, 2, crate::KIND_FILE))
        );
        assert_eq!(
            dir_store.lookup(sub_b, b"file_y").unwrap(),
            Some((ino_x, 1, crate::KIND_FILE))
        );
    }

    #[test]
    fn atomic_swap_exchange_missing_source_fails() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));

        dir_store.init_dir(ROOT_INODE).unwrap();

        let result = dir_store.atomic_swap(
            ROOT_INODE,
            b"nope",
            ROOT_INODE,
            b"also_nope",
            crate::persistence::PersistentSwapMode::Exchange,
        );
        assert!(matches!(result, Err(NamespaceError::NotFound)));
    }

    #[test]
    fn atomic_swap_exchange_missing_target_fails() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let attr = test_attrs_file();
        let ino = inode_store.alloc_inode(&attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"exists", ino, 1, crate::KIND_FILE)
            .unwrap();

        let result = dir_store.atomic_swap(
            ROOT_INODE,
            b"exists",
            ROOT_INODE,
            b"missing",
            crate::persistence::PersistentSwapMode::Exchange,
        );
        assert!(matches!(result, Err(NamespaceError::NotFound)));
    }

    #[test]
    fn atomic_swap_rename_missing_source_fails() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));

        dir_store.init_dir(ROOT_INODE).unwrap();

        let result = dir_store.atomic_swap(
            ROOT_INODE,
            b"ghost",
            ROOT_INODE,
            b"dest",
            crate::persistence::PersistentSwapMode::Rename,
        );
        assert!(matches!(result, Err(NamespaceError::NotFound)));
    }

    #[test]
    fn atomic_swap_rename_cross_dir_moves_entry() {
        let _temp = tempfile::TempDir::with_prefix("tidefs-ns-ats-").unwrap();
        let fs = test_fs(&_temp);
        let dir_store = LocalFilesystemDirectoryStore::new(Arc::clone(&fs));
        let inode_store = LocalFilesystemInodeStore::new(Arc::clone(&fs));

        let dir_attr = test_attrs_dir();
        let sub = inode_store.alloc_inode(&dir_attr).unwrap().0;
        dir_store.init_dir(ROOT_INODE).unwrap();
        dir_store
            .insert(ROOT_INODE, b"sub", sub, 1, crate::KIND_DIR)
            .unwrap();
        dir_store.init_dir(sub).unwrap();

        let file_attr = test_attrs_file();
        let ino = inode_store.alloc_inode(&file_attr).unwrap().0;
        dir_store
            .insert(ROOT_INODE, b"move_me", ino, 1, crate::KIND_FILE)
            .unwrap();

        let overwritten = dir_store
            .atomic_swap(
                ROOT_INODE,
                b"move_me",
                sub,
                b"moved",
                crate::persistence::PersistentSwapMode::Rename,
            )
            .unwrap();
        assert!(overwritten.is_none());

        assert!(dir_store.lookup(ROOT_INODE, b"move_me").unwrap().is_none());
        assert_eq!(
            dir_store.lookup(sub, b"moved").unwrap(),
            Some((ino, 1, crate::KIND_FILE))
        );
    }
}
