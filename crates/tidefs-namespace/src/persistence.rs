// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Persistent store traits and in-memory implementations for bridging
//! [`crate::Namespace`] to durable storage backends.

#[cfg(test)]
mod persistence_tests;

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use tidefs_dir_index::DirIndexError;
use tidefs_types_polymorphic_directory_index_core::DatasetDirPolicy;

use crate::{DirBackend, Inode, InodeAttributes, InodeTable, NamespaceError, ROOT_INODE};

// ---------------------------------------------------------------------------
// Dataset identity boundary
// ---------------------------------------------------------------------------

/// Identity token that binds persisted namespace roots to one dataset view.
///
/// `lineage_id` is only an authority discriminator for clone-derived namespace
/// roots. It is not a snapshot graph or full clone provenance model.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NamespaceDatasetIdentity {
    dataset_id: String,
    lineage_id: String,
}

impl NamespaceDatasetIdentity {
    /// Create an identity whose dataset id also names the lineage boundary.
    #[must_use]
    pub fn new(dataset_id: impl Into<String>) -> Self {
        let dataset_id = dataset_id.into();
        Self {
            lineage_id: dataset_id.clone(),
            dataset_id,
        }
    }

    /// Create an identity with an explicit clone-lineage discriminator.
    #[must_use]
    pub fn with_lineage(dataset_id: impl Into<String>, lineage_id: impl Into<String>) -> Self {
        Self {
            dataset_id: dataset_id.into(),
            lineage_id: lineage_id.into(),
        }
    }

    /// Return the dataset id component.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Return the lineage discriminator component.
    #[must_use]
    pub fn lineage_id(&self) -> &str {
        &self.lineage_id
    }
}

impl Default for NamespaceDatasetIdentity {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Persisted namespace root identity and generation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentNamespaceRoot {
    pub identity: NamespaceDatasetIdentity,
    pub root_inode: Inode,
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// PersistentInodeStore
// ---------------------------------------------------------------------------

pub trait PersistentInodeStore: Send + Sync {
    /// Refuse a namespace mutation before validation or no-op handling.
    ///
    /// In-memory stores accept mutations by default. Mounted stores override
    /// this hook to propagate their typed reopen-required fence.
    fn ensure_mutation_allowed(&self, _operation: &'static str) -> Result<(), NamespaceError> {
        Ok(())
    }

    fn dataset_identity(&self) -> NamespaceDatasetIdentity {
        NamespaceDatasetIdentity::default()
    }

    fn namespace_root(&self) -> Result<Option<PersistentNamespaceRoot>, NamespaceError> {
        Ok(self.get_attrs(ROOT_INODE).map(|_| PersistentNamespaceRoot {
            identity: self.dataset_identity(),
            root_inode: ROOT_INODE,
            generation: self.generation(),
        }))
    }

    fn init_namespace_root(
        &self,
        identity: &NamespaceDatasetIdentity,
        attrs: &InodeAttributes,
    ) -> Result<PersistentNamespaceRoot, NamespaceError> {
        self.ensure_mutation_allowed("initialize persistent namespace root")?;
        self.verify_dataset_identity(identity)?;
        let (root_inode, generation) = self.alloc_inode(attrs)?;
        Ok(PersistentNamespaceRoot {
            identity: identity.clone(),
            root_inode,
            generation,
        })
    }

    fn ensure_namespace_root(
        &self,
        identity: &NamespaceDatasetIdentity,
        attrs: &InodeAttributes,
    ) -> Result<PersistentNamespaceRoot, NamespaceError> {
        self.ensure_mutation_allowed("ensure persistent namespace root")?;
        match self.namespace_root()? {
            Some(root) if root.identity == *identity => Ok(root),
            Some(root) => Err(NamespaceError::DatasetIdentityMismatch {
                expected: identity.clone(),
                found: root.identity,
            }),
            None => self.init_namespace_root(identity, attrs),
        }
    }

    fn verify_dataset_identity(
        &self,
        identity: &NamespaceDatasetIdentity,
    ) -> Result<(), NamespaceError> {
        let found = self.dataset_identity();
        if found == *identity {
            Ok(())
        } else {
            Err(NamespaceError::DatasetIdentityMismatch {
                expected: identity.clone(),
                found,
            })
        }
    }

    fn alloc_inode(&self, attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError>;
    fn alloc_inode_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        attrs: &InodeAttributes,
    ) -> Result<(Inode, u64), NamespaceError> {
        self.ensure_mutation_allowed("allocate persistent namespace inode")?;
        self.verify_dataset_identity(identity)?;
        self.alloc_inode(attrs)
    }

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
    /// Refuse a namespace mutation before validation or no-op handling.
    ///
    /// In-memory stores accept mutations by default. Mounted stores override
    /// this hook to propagate their typed reopen-required fence.
    fn ensure_mutation_allowed(&self, _operation: &'static str) -> Result<(), NamespaceError> {
        Ok(())
    }

    fn dataset_identity(&self) -> NamespaceDatasetIdentity {
        NamespaceDatasetIdentity::default()
    }

    fn verify_dataset_identity(
        &self,
        identity: &NamespaceDatasetIdentity,
    ) -> Result<(), NamespaceError> {
        let found = self.dataset_identity();
        if found == *identity {
            Ok(())
        } else {
            Err(NamespaceError::DatasetIdentityMismatch {
                expected: identity.clone(),
                found,
            })
        }
    }

    /// Return a shared dirs map, if this store supports it.
    fn shared_dirs(&self) -> Option<Arc<RwLock<HashMap<Inode, DirBackend>>>> {
        None
    }

    fn shared_dirs_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
    ) -> Result<Option<Arc<RwLock<HashMap<Inode, DirBackend>>>>, NamespaceError> {
        self.verify_dataset_identity(identity)?;
        Ok(self.shared_dirs())
    }

    fn lookup(
        &self,
        parent: Inode,
        name: &[u8],
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError>;
    fn lookup_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        parent: Inode,
        name: &[u8],
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        self.verify_dataset_identity(identity)?;
        self.lookup(parent, name)
    }

    fn insert(
        &self,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        generation: u64,
        kind: u32,
    ) -> Result<(), NamespaceError>;
    fn insert_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        generation: u64,
        kind: u32,
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("insert persistent namespace directory entry")?;
        self.verify_dataset_identity(identity)?;
        self.insert(parent, name, inode_id, generation, kind)
    }

    fn remove(&self, parent: Inode, name: &[u8]) -> Result<(), NamespaceError>;
    fn remove_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        parent: Inode,
        name: &[u8],
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("remove persistent namespace directory entry")?;
        self.verify_dataset_identity(identity)?;
        self.remove(parent, name)
    }

    fn list_dir(
        &self,
        parent: Inode,
        cookie: u64,
    ) -> Result<(Vec<PersistentDirEntry>, u64), NamespaceError>;
    fn list_dir_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        parent: Inode,
        cookie: u64,
    ) -> Result<(Vec<PersistentDirEntry>, u64), NamespaceError> {
        self.verify_dataset_identity(identity)?;
        self.list_dir(parent, cookie)
    }

    fn is_dir_empty(&self, parent: Inode) -> Result<bool, NamespaceError>;
    fn is_dir_empty_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        parent: Inode,
    ) -> Result<bool, NamespaceError> {
        self.verify_dataset_identity(identity)?;
        self.is_dir_empty(parent)
    }

    fn atomic_swap(
        &self,
        _src_parent: Inode,
        _src_name: &[u8],
        _dst_parent: Inode,
        _dst_name: &[u8],
        _mode: PersistentSwapMode,
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError>;
    fn atomic_swap_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        src_parent: Inode,
        src_name: &[u8],
        dst_parent: Inode,
        dst_name: &[u8],
        mode: PersistentSwapMode,
    ) -> Result<Option<(Inode, u64, u32)>, NamespaceError> {
        self.ensure_mutation_allowed("atomically update persistent namespace entries")?;
        self.verify_dataset_identity(identity)?;
        self.atomic_swap(src_parent, src_name, dst_parent, dst_name, mode)
    }

    fn init_dir(&self, dir_inode: Inode) -> Result<(), NamespaceError>;
    fn init_dir_for_dataset(
        &self,
        identity: &NamespaceDatasetIdentity,
        dir_inode: Inode,
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("initialize persistent namespace directory")?;
        self.verify_dataset_identity(identity)?;
        self.init_dir(dir_inode)
    }
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

struct MemoryPersistentInodeDataset {
    table: Arc<crate::MemInodeTable>,
    generations: RwLock<HashMap<Inode, u64>>,
    next_generation: AtomicU64,
    root: RwLock<Option<PersistentNamespaceRoot>>,
}

impl MemoryPersistentInodeDataset {
    fn new() -> Self {
        Self {
            table: Arc::new(crate::MemInodeTable::new()),
            generations: RwLock::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            root: RwLock::new(None),
        }
    }

    fn with_table(table: Arc<crate::MemInodeTable>) -> Self {
        Self {
            table,
            generations: RwLock::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            root: RwLock::new(None),
        }
    }

    fn alloc_generation(&self) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        generation.max(1)
    }
}

pub struct MemoryPersistentInodeState {
    datasets: RwLock<HashMap<NamespaceDatasetIdentity, Arc<MemoryPersistentInodeDataset>>>,
}

impl MemoryPersistentInodeState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            datasets: RwLock::new(HashMap::new()),
        }
    }

    fn dataset(&self, identity: &NamespaceDatasetIdentity) -> Arc<MemoryPersistentInodeDataset> {
        {
            let datasets = self.datasets.read().unwrap();
            if let Some(dataset) = datasets.get(identity) {
                return Arc::clone(dataset);
            }
        }

        let mut datasets = self.datasets.write().unwrap();
        Arc::clone(
            datasets
                .entry(identity.clone())
                .or_insert_with(|| Arc::new(MemoryPersistentInodeDataset::new())),
        )
    }

    fn insert_dataset(
        &self,
        identity: NamespaceDatasetIdentity,
        dataset: MemoryPersistentInodeDataset,
    ) {
        self.datasets
            .write()
            .unwrap()
            .insert(identity, Arc::new(dataset));
    }
}

impl Default for MemoryPersistentInodeState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MemoryPersistentInodeStore {
    identity: NamespaceDatasetIdentity,
    state: Arc<MemoryPersistentInodeState>,
}

impl MemoryPersistentInodeStore {
    pub fn new() -> Self {
        Self::new_for_dataset(NamespaceDatasetIdentity::default())
    }

    pub fn new_for_dataset(identity: NamespaceDatasetIdentity) -> Self {
        Self::with_shared_state(identity, Arc::new(MemoryPersistentInodeState::new()))
    }

    pub fn with_shared_state(
        identity: NamespaceDatasetIdentity,
        state: Arc<MemoryPersistentInodeState>,
    ) -> Self {
        Self { identity, state }
    }

    pub fn with_table(table: Arc<crate::MemInodeTable>) -> Self {
        let identity = NamespaceDatasetIdentity::default();
        let state = Arc::new(MemoryPersistentInodeState::new());
        state.insert_dataset(
            identity.clone(),
            MemoryPersistentInodeDataset::with_table(table),
        );
        Self { identity, state }
    }

    fn dataset(&self) -> Arc<MemoryPersistentInodeDataset> {
        self.state.dataset(&self.identity)
    }
}

impl Default for MemoryPersistentInodeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentInodeStore for MemoryPersistentInodeStore {
    fn dataset_identity(&self) -> NamespaceDatasetIdentity {
        self.identity.clone()
    }

    fn namespace_root(&self) -> Result<Option<PersistentNamespaceRoot>, NamespaceError> {
        let dataset = self.dataset();
        if let Some(root) = dataset.root.read().unwrap().clone() {
            return Ok(Some(root));
        }
        if dataset.table.get(ROOT_INODE).is_some() {
            let generation = dataset
                .generations
                .read()
                .unwrap()
                .get(&ROOT_INODE)
                .copied()
                .unwrap_or(1);
            return Ok(Some(PersistentNamespaceRoot {
                identity: self.identity.clone(),
                root_inode: ROOT_INODE,
                generation,
            }));
        }
        Ok(None)
    }

    fn init_namespace_root(
        &self,
        identity: &NamespaceDatasetIdentity,
        attrs: &InodeAttributes,
    ) -> Result<PersistentNamespaceRoot, NamespaceError> {
        self.verify_dataset_identity(identity)?;
        if let Some(root) = self.dataset().root.read().unwrap().clone() {
            return Ok(root);
        }

        let (root_inode, generation) = if self.dataset().table.get(ROOT_INODE).is_some() {
            let generation = self
                .dataset()
                .generations
                .read()
                .unwrap()
                .get(&ROOT_INODE)
                .copied()
                .unwrap_or(1);
            (ROOT_INODE, generation)
        } else {
            self.alloc_inode(attrs)?
        };
        let root = PersistentNamespaceRoot {
            identity: identity.clone(),
            root_inode,
            generation,
        };
        *self.dataset().root.write().unwrap() = Some(root.clone());
        Ok(root)
    }

    fn alloc_inode(&self, attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError> {
        let dataset = self.dataset();
        let generation = dataset.alloc_generation();
        let ino = dataset.table.insert_allocated_attrs(attrs.clone())?;
        dataset.generations.write().unwrap().insert(ino, generation);
        Ok((ino, generation))
    }
    fn get_attrs(&self, inode: Inode) -> Option<InodeAttributes> {
        self.dataset().table.get(inode)
    }
    fn update_attrs(&self, inode: Inode, attrs: &InodeAttributes) -> Result<(), NamespaceError> {
        self.dataset().table.update_attrs(inode, attrs.clone())
    }
    fn free_inode(&self, inode: Inode) -> Result<(), NamespaceError> {
        let dataset = self.dataset();
        dataset.generations.write().unwrap().remove(&inode);
        dataset.table.free(inode)
    }
    fn next_inode_id(&self) -> Inode {
        self.dataset().table.next.load(Ordering::Relaxed)
    }
    fn generation(&self) -> u64 {
        self.dataset()
            .next_generation
            .load(Ordering::Relaxed)
            .saturating_sub(1)
    }
}

// ---------------------------------------------------------------------------
// MemoryPersistentDirectoryStore
// ---------------------------------------------------------------------------

pub struct MemoryPersistentDirectoryState {
    datasets: RwLock<HashMap<NamespaceDatasetIdentity, Arc<RwLock<HashMap<Inode, DirBackend>>>>>,
}

impl MemoryPersistentDirectoryState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            datasets: RwLock::new(HashMap::new()),
        }
    }

    fn dirs(&self, identity: &NamespaceDatasetIdentity) -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        {
            let datasets = self.datasets.read().unwrap();
            if let Some(dirs) = datasets.get(identity) {
                return Arc::clone(dirs);
            }
        }

        let mut datasets = self.datasets.write().unwrap();
        Arc::clone(
            datasets
                .entry(identity.clone())
                .or_insert_with(|| Arc::new(RwLock::new(HashMap::new()))),
        )
    }
}

impl Default for MemoryPersistentDirectoryState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MemoryPersistentDirectoryStore {
    identity: NamespaceDatasetIdentity,
    dirs: Arc<RwLock<HashMap<Inode, DirBackend>>>,
    policy: DatasetDirPolicy,
}

impl MemoryPersistentDirectoryStore {
    /// Return a clone of the shared dirs Arc, so Namespace can use the same map.
    pub fn shared_dirs_arc(&self) -> Arc<RwLock<HashMap<Inode, DirBackend>>> {
        Arc::clone(&self.dirs)
    }
    pub fn new(policy: DatasetDirPolicy) -> Self {
        Self::new_for_dataset(NamespaceDatasetIdentity::default(), policy)
    }
    pub fn new_for_dataset(identity: NamespaceDatasetIdentity, policy: DatasetDirPolicy) -> Self {
        Self {
            identity,
            dirs: Arc::new(RwLock::new(HashMap::new())),
            policy,
        }
    }
    pub fn with_shared_state(
        identity: NamespaceDatasetIdentity,
        state: Arc<MemoryPersistentDirectoryState>,
        policy: DatasetDirPolicy,
    ) -> Self {
        Self {
            dirs: state.dirs(&identity),
            identity,
            policy,
        }
    }
    pub fn with_shared_dirs(
        dirs: Arc<RwLock<HashMap<Inode, DirBackend>>>,
        policy: DatasetDirPolicy,
    ) -> Self {
        Self {
            identity: NamespaceDatasetIdentity::default(),
            dirs,
            policy,
        }
    }
}

impl PersistentDirectoryStore for MemoryPersistentDirectoryStore {
    fn dataset_identity(&self) -> NamespaceDatasetIdentity {
        self.identity.clone()
    }

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
                let (raw, next) =
                    dir.list_from(tidefs_dir_index::DirCookie(cookie))
                        .map_err(|e| match e {
                            tidefs_dir_index::DirIndexError::StaleCursor => {
                                NamespaceError::StaleCursor
                            }
                            _ => NamespaceError::NotFound,
                        })?;
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
                let (entries, _) =
                    dir.list_from(tidefs_dir_index::DirCookie(0))
                        .map_err(|e| match e {
                            tidefs_dir_index::DirIndexError::StaleCursor => {
                                NamespaceError::StaleCursor
                            }
                            _ => NamespaceError::NotFound,
                        })?;
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
