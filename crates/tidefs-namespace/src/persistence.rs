//! Persistent store traits and in-memory implementations for bridging
//! [`crate::Namespace`] to durable storage backends.

#[cfg(test)]
mod persistence_tests;

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, RwLock},
};

use tidefs_dir_index::DirIndexError;
use tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy;

use crate::{DirBackend, Inode, InodeAttributes, InodeTable, NamespaceError};

// ---------------------------------------------------------------------------
// PersistentInodeStore
// ---------------------------------------------------------------------------

pub trait PersistentInodeStore: Send + Sync {
    fn alloc_inode(&self, attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError>;
    fn get_attrs(&self, inode: Inode) -> Option<InodeAttributes>;
    fn update_attrs(&self, inode: Inode, attrs: &InodeAttributes) -> Result<(), NamespaceError>;
    fn free_inode(&self, inode: Inode) -> Result<(), NamespaceError>;
    fn next_inode_id(&self) -> Inode;
    fn generation(&self) -> u64;
}

// ---------------------------------------------------------------------------
// PersistentDirectoryStore
// ---------------------------------------------------------------------------

pub trait PersistentDirectoryStore: Send + Sync {
    /// Return a shared dirs map, if this store supports it.
    fn shared_dirs(&self) -> Option<Arc<RwLock<HashMap<Inode, DirBackend>>>> {
        None
    }
    fn lookup(
        &self,
        parent: Inode,
        name: &[u8],
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError>;
    fn insert(
        &self,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        generation: u64,
        kind: u32,
    ) -> Result<(), NamespaceError>;
    fn remove(&self, parent: Inode, name: &[u8]) -> Result<(), NamespaceError>;
    fn list_dir(
        &self,
        parent: Inode,
        cookie: u64,
    ) -> Result<(Vec<PersistentDirEntry>, u64), NamespaceError>;
    fn is_dir_empty(&self, parent: Inode) -> Result<bool, NamespaceError>;
    fn atomic_swap(
        &self,
        _src_parent: Inode,
        _src_name: &[u8],
        _dst_parent: Inode,
        _dst_name: &[u8],
        _mode: PersistentSwapMode,
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError>;
    fn init_dir(&self, dir_inode: Inode) -> Result<(), NamespaceError>;
}

// ---------------------------------------------------------------------------
// Supporting types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PersistentDirEntry {
    pub name: Vec<u8>,
    pub inode_id: Inode,
    pub generation: u64,
    pub kind: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistentSwapMode {
    Rename,
    NoReplace,
    Exchange,
}

// ---------------------------------------------------------------------------
// MemoryPersistentInodeStore
// ---------------------------------------------------------------------------

pub struct MemoryPersistentInodeStore {
    table: Arc<crate::MemInodeTable>,
}

impl MemoryPersistentInodeStore {
    pub fn new() -> Self {
        Self {
            table: Arc::new(crate::MemInodeTable::new()),
        }
    }
    pub fn with_table(table: Arc<crate::MemInodeTable>) -> Self {
        Self { table }
    }
}

impl Default for MemoryPersistentInodeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentInodeStore for MemoryPersistentInodeStore {
    fn alloc_inode(&self, attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError> {
        let ino = self.table.insert_allocated_attrs(attrs.clone())?;
        Ok((ino, 1))
    }
    fn get_attrs(&self, inode: Inode) -> Option<InodeAttributes> {
        self.table.get(inode)
    }
    fn update_attrs(&self, inode: Inode, attrs: &InodeAttributes) -> Result<(), NamespaceError> {
        self.table.update_attrs(inode, attrs.clone())
    }
    fn free_inode(&self, inode: Inode) -> Result<(), NamespaceError> {
        self.table.free(inode)
    }
    fn next_inode_id(&self) -> Inode {
        self.table.next.load(Ordering::Relaxed)
    }
    fn generation(&self) -> u64 {
        1
    }
}

// ---------------------------------------------------------------------------
// MemoryPersistentDirectoryStore
// ---------------------------------------------------------------------------

pub struct MemoryPersistentDirectoryStore {
    dirs: Arc<RwLock<HashMap<Inode, DirBackend>>>,
    policy: DatasetDirPolicy,
}

impl MemoryPersistentDirectoryStore {
    /// Return a clone of the shared dirs Arc, so Namespace can use the same map.
    pub fn shared_dirs_arc(&self) -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        Arc::clone(&self.dirs)
    }
    pub fn new(policy: DatasetDirPolicy) -> Self {
        Self {
            dirs: Arc::new(RwLock::new(HashMap::new())),
            policy,
        }
    }
    pub fn with_shared_dirs(
        dirs: Arc<RwLock<HashMap<Inode, DirBackend>>>,
        policy: DatasetDirPolicy,
    ) -> Self {
        Self { dirs, policy }
    }
}

impl PersistentDirectoryStore for MemoryPersistentDirectoryStore {
    fn shared_dirs(&self) -> Option<Arc<RwLock<HashMap<Inode, DirBackend>>>> {
        Some(Arc::clone(&self.dirs))
    }
    fn lookup(
        &self,
        parent: Inode,
        name: &[u8],
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        let dirs = self.dirs.read().unwrap();
        match dirs.get(&parent) {
            Some(dir) => Ok(dir.lookup(name).map(|e| (e.inode_id, e.generation, e.kind))),
            None => Err(NamespaceError::InodeNotFound),
        }
    }
    fn insert(
        &self,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        gen: u64,
        kind: u32,
    ) -> Result<(), NamespaceError> {
        let mut dirs = self.dirs.write().unwrap();
        match dirs.get_mut(&parent) {
            Some(dir) => dir.insert(name, inode_id, gen, kind).map_err(|e| match e {
                DirIndexError::EntryAlreadyExists => NamespaceError::AlreadyExists,
                _ => NamespaceError::NotDirectory,
            }),
            None => Err(NamespaceError::InodeNotFound),
        }
    }
    fn remove(&self, parent: Inode, name: &[u8]) -> Result<(), NamespaceError> {
        let mut dirs = self.dirs.write().unwrap();
        match dirs.get_mut(&parent) {
            Some(dir) => dir.delete(name).map_err(|e| match e {
                DirIndexError::EntryNotFound => NamespaceError::NotFound,
                DirIndexError::DirNotEmpty => NamespaceError::NotEmpty,
                _ => NamespaceError::NotDirectory,
            }),
            None => Err(NamespaceError::InodeNotFound),
        }
    }
    fn list_dir(
        &self,
        parent: Inode,
        cookie: u64,
    ) -> Result<(Vec<PersistentDirEntry>, u64), NamespaceError> {
        let dirs = self.dirs.read().unwrap();
        match dirs.get(&parent) {
            Some(dir) => {
                let (raw, next) = dir.list_from(tidefs_dir_index::DirCookie(cookie));
                let entries = raw
                    .into_iter()
                    .map(|e| PersistentDirEntry {
                        name: e.name,
                        inode_id: e.inode_id,
                        generation: e.generation,
                        kind: e.kind,
                    })
                    .collect();
                Ok((entries, next.0))
            }
            None => Err(NamespaceError::InodeNotFound),
        }
    }
    fn is_dir_empty(&self, parent: Inode) -> Result<bool, NamespaceError> {
        let dirs = self.dirs.read().unwrap();
        match dirs.get(&parent) {
            Some(dir) => {
                let (entries, _) = dir.list_from(tidefs_dir_index::DirCookie(0));
                Ok(entries.iter().all(|e| e.name == b"." || e.name == b".."))
            }
            None => Err(NamespaceError::InodeNotFound),
        }
    }
    fn atomic_swap(
        &self,
        _src_parent: Inode,
        _src_name: &[u8],
        _dst_parent: Inode,
        _dst_name: &[u8],
        _mode: PersistentSwapMode,
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        Ok(None)
    }
    fn init_dir(&self, dir_inode: Inode) -> Result<(), NamespaceError> {
        let mut dirs = self.dirs.write().unwrap();
        let mut dir = DirBackend::new(dir_inode, self.policy);
        dir.insert(b".", dir_inode, 0, crate::KIND_DIR)
            .map_err(|_| NamespaceError::AlreadyExists)?;
        dir.insert(b"..", dir_inode, 0, crate::KIND_DIR)
            .map_err(|_| NamespaceError::AlreadyExists)?;
        dirs.insert(dir_inode, dir);
        Ok(())
    }
}
