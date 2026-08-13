// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Canonical Pool-backed ownership above raw object/device I/O.
//!
//! `PoolRuntime` binds the dataset catalog, pool properties, and exact typed
//! semantic roots in one checksum-protected publication. Dataset engines write
//! immutable semantic objects first and publish the canonical root last, so a
//! reopen selects either the previous complete composition or its complete
//! successor.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use tidefs_dataset_catalog::{
    CatalogError, DatasetCatalog, DatasetFlags, DatasetId, DatasetType, SyncGuarantee,
};
use tidefs_dataset_properties::PropertySet;
use tidefs_local_object_store::pool::{Pool, PoolConfig, PoolProperties, PoolRedundancyPolicy};
use tidefs_local_object_store::{
    DeviceBacking, DeviceClass, DeviceConfig, DeviceIoClass, DeviceKind, DeviceMediaClass,
    ObjectKey, StoreError, StoreOptions,
};

const POOL_ROOT_MAGIC: &[u8; 8] = b"TFSPOOL1";
const POOL_ROOT_VERSION: u16 = 1;
const VOLUME_ROOT_MAGIC: &[u8; 8] = b"TFSVOL02";
const VOLUME_ROOT_VERSION: u16 = 2;
const VOLUME_MAP_MAGIC: &[u8; 8] = b"TFSVMAP1";
const VOLUME_MAP_VERSION: u16 = 1;
const CHECKSUM_LEN: usize = 32;
const DEFAULT_VOLUME_BLOCK_SIZE: u32 = 4096;
const VOLUME_CHUNK_SIZE: usize = 1024 * 1024;
const VOLUME_MAP_ROOT_LEVEL: u8 = 7;

/// Stable root-filesystem identity shared by all product compositions.
pub const ROOT_DATASET_ID: DatasetId = DatasetId::from_bytes([0_u8; 16]);

/// Errors from the shared Pool runtime.
#[derive(Debug)]
pub enum PoolRuntimeError {
    Store(StoreError),
    Catalog(CatalogError),
    CorruptRoot(&'static str),
    MissingRoot(DatasetId),
    WrongRootType {
        dataset_id: DatasetId,
        expected: DatasetRootKind,
        actual: DatasetRootKind,
    },
    InvalidVolume(&'static str),
    StaleVolumeHandle(DatasetId),
    PublicationRequiresReopen,
    Bounds,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for PoolRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "Pool storage error: {error}"),
            Self::Catalog(error) => write!(f, "dataset catalog error: {error}"),
            Self::CorruptRoot(reason) => write!(f, "canonical Pool root is corrupt: {reason}"),
            Self::MissingRoot(id) => write!(f, "dataset {id} has no published semantic root"),
            Self::WrongRootType {
                dataset_id,
                expected,
                actual,
            } => write!(
                f,
                "dataset {dataset_id} root type is {actual:?}, expected {expected:?}"
            ),
            Self::InvalidVolume(reason) => write!(f, "invalid volume: {reason}"),
            Self::StaleVolumeHandle(id) => {
                write!(f, "volume {id} was changed through another open handle")
            }
            Self::PublicationRequiresReopen => f.write_str(
                "canonical Pool publication outcome is uncertain; reopen before mutation",
            ),
            Self::Bounds => f.write_str("volume I/O is outside committed capacity"),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "{operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for PoolRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<StoreError> for PoolRuntimeError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<CatalogError> for PoolRuntimeError {
    fn from(value: CatalogError) -> Self {
        Self::Catalog(value)
    }
}

pub type Result<T> = std::result::Result<T, PoolRuntimeError>;

/// Semantic engine selected by a typed dataset-root reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DatasetRootKind {
    Filesystem = 1,
    Volume = 2,
    Snapshot = 3,
}

impl DatasetRootKind {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Filesystem),
            2 => Ok(Self::Volume),
            3 => Ok(Self::Snapshot),
            _ => Err(PoolRuntimeError::CorruptRoot("unknown dataset-root kind")),
        }
    }

    fn from_dataset_type(value: DatasetType) -> Self {
        match value {
            DatasetType::Filesystem => Self::Filesystem,
            DatasetType::Volume => Self::Volume,
            DatasetType::Snapshot => Self::Snapshot,
        }
    }
}

/// Exact immutable semantic object selected by the canonical Pool root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetRootRef {
    pub dataset_id: DatasetId,
    pub kind: DatasetRootKind,
    pub object_key: ObjectKey,
    pub digest: [u8; 32],
    pub semantic_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ImmutableObjectRef {
    object_key: ObjectKey,
    digest: [u8; 32],
}

/// One checksum-protected pool composition.
#[derive(Clone, Debug)]
struct CanonicalPoolRoot {
    generation: u64,
    catalog: DatasetCatalog,
    pool_properties: PropertySet,
    dataset_roots: BTreeMap<DatasetId, DatasetRootRef>,
}

#[derive(Clone, Debug)]
struct PoolMetadataCandidate {
    catalog: DatasetCatalog,
    pool_properties: PropertySet,
}

/// Neutral owner shared by filesystem and volume dataset engines.
#[derive(Debug)]
pub struct PoolRuntime {
    pool: Pool,
    root: CanonicalPoolRoot,
    pending_metadata: Option<PoolMetadataCandidate>,
    publication_requires_reopen: bool,
}

impl PoolRuntime {
    /// Open the canonical composition carried by `pool`, or an unpublished
    /// empty composition for a genuinely fresh Pool.
    pub fn open(pool: Pool) -> Result<Self> {
        let root = match pool.get(DeviceIoClass::Data, canonical_pool_root_key())? {
            Some(bytes) => decode_pool_root(&bytes)?,
            None => CanonicalPoolRoot {
                generation: 0,
                catalog: DatasetCatalog::new(),
                pool_properties: PropertySet::new(),
                dataset_roots: BTreeMap::new(),
            },
        };
        validate_catalog_root_types(&root.catalog, &root.dataset_roots)?;
        Ok(Self {
            pool,
            root,
            pending_metadata: None,
            publication_requires_reopen: false,
        })
    }

    /// Open a labelled Pool directly from operator-selected devices without
    /// constructing a filesystem engine.
    pub fn open_block_devices(
        metadata_dir: &Path,
        block_devices: &[PathBuf],
        pool_name: &str,
        redundancy_policy: PoolRedundancyPolicy,
        options: &StoreOptions,
    ) -> Result<Self> {
        let mut devices = Vec::with_capacity(block_devices.len());
        for path in block_devices {
            let backing =
                match tidefs_pool_scan::classify_pool_device_backing(path).map_err(|source| {
                    PoolRuntimeError::Io {
                        operation: "classify Pool device backing",
                        path: path.clone(),
                        source,
                    }
                })? {
                    tidefs_pool_scan::PoolDeviceBacking::BlockDevice => DeviceBacking::BlockDevice,
                    tidefs_pool_scan::PoolDeviceBacking::RegularFileDev => {
                        DeviceBacking::RegularFileDev
                    }
                };
            devices.push(DeviceConfig {
                media_class: DeviceMediaClass::Ssd,
                path: path.clone(),
                backing,
                class: DeviceClass::Data,
                kind: DeviceKind::Block { path: path.clone() },
                encryption: None,
                compression: None,
            });
        }
        let pool = Pool::create(
            PoolConfig {
                name: pool_name.to_string(),
                root_path: metadata_dir.to_path_buf(),
                devices,
            },
            PoolProperties {
                redundancy_policy,
                ..PoolProperties::default()
            },
            options,
        )?;
        Self::open(pool)
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.root.generation
    }

    #[must_use]
    pub fn dataset_catalog(&self) -> &DatasetCatalog {
        &self.root.catalog
    }

    /// Stage catalog changes without changing live reopen authority. The
    /// candidate becomes visible only after `publish_metadata` succeeds.
    pub fn dataset_catalog_mut(&mut self) -> Result<&mut DatasetCatalog> {
        self.ensure_publishable()?;
        self.ensure_metadata_candidate();
        Ok(&mut self
            .pending_metadata
            .as_mut()
            .ok_or(PoolRuntimeError::CorruptRoot(
                "metadata candidate disappeared",
            ))?
            .catalog)
    }

    #[must_use]
    pub fn pool_properties(&self) -> &PropertySet {
        &self.root.pool_properties
    }

    /// Stage pool-property changes without changing live reopen authority.
    pub fn pool_properties_mut(&mut self) -> Result<&mut PropertySet> {
        self.ensure_publishable()?;
        self.ensure_metadata_candidate();
        Ok(&mut self
            .pending_metadata
            .as_mut()
            .ok_or(PoolRuntimeError::CorruptRoot(
                "metadata candidate disappeared",
            ))?
            .pool_properties)
    }

    #[must_use]
    pub fn dataset_root(&self, id: DatasetId) -> Option<&DatasetRootRef> {
        self.root.dataset_roots.get(&id)
    }

    /// Raw Pool access for dataset engines. Canonical catalog and semantic-root
    /// publication remains private to this owner; callers use this only for
    /// engine-owned transaction, content, maintenance, and recovery objects.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Mutable raw Pool access for dataset-owned objects. Callers must publish
    /// any root that makes those objects reachable through this runtime.
    pub fn pool_mut(&mut self) -> &mut Pool {
        &mut self.pool
    }

    /// Load and verify the exact immutable semantic root selected by the Pool
    /// root. A reused filesystem slot or newer unreferenced object cannot
    /// change the result.
    pub fn load_dataset_root(&self, id: DatasetId, kind: DatasetRootKind) -> Result<Vec<u8>> {
        let reference = self
            .root
            .dataset_roots
            .get(&id)
            .ok_or(PoolRuntimeError::MissingRoot(id))?;
        if reference.kind != kind {
            return Err(PoolRuntimeError::WrongRootType {
                dataset_id: id,
                expected: kind,
                actual: reference.kind,
            });
        }
        load_immutable_object(&self.pool, *reference)
    }

    /// Publish one exact semantic root through the current catalog. The
    /// immutable semantic object becomes durable before the canonical root.
    pub fn publish_dataset_root(
        &mut self,
        id: DatasetId,
        kind: DatasetRootKind,
        semantic_generation: u64,
        bytes: &[u8],
    ) -> Result<DatasetRootRef> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before a dataset root",
            ));
        }
        validate_catalog_dataset_type(&self.root.catalog, id, kind)?;
        let reference = make_dataset_root_ref(id, kind, semantic_generation, bytes);
        self.write_semantic_root(reference, bytes)?;

        let mut next = self.root.clone();
        next.generation = next_generation(next.generation)?;
        next.dataset_roots.insert(id, reference);
        self.publish_root(next)?;
        Ok(reference)
    }

    /// Publish caller-staged catalog and property changes only after the
    /// complete candidate composition validates. Failed publication leaves
    /// the live in-memory composition unchanged.
    pub fn publish_metadata(&mut self) -> Result<()> {
        self.ensure_publishable()?;
        let candidate = self
            .pending_metadata
            .clone()
            .unwrap_or_else(|| PoolMetadataCandidate {
                catalog: self.root.catalog.clone(),
                pool_properties: self.root.pool_properties.clone(),
            });
        let mut next = self.root.clone();
        next.generation = next_generation(next.generation)?;
        next.catalog = candidate.catalog;
        next.pool_properties = candidate.pool_properties;
        next.dataset_roots
            .retain(|id, _| next.catalog.get_by_id(id).is_some());
        self.publish_root(next)?;
        self.pending_metadata = None;
        Ok(())
    }

    /// Atomically create a catalog entry and its initial typed semantic root.
    #[allow(clippy::too_many_arguments)]
    pub fn create_dataset_with_root(
        &mut self,
        path: &str,
        id: DatasetId,
        dataset_type: DatasetType,
        properties: Vec<u8>,
        flags: DatasetFlags,
        sync_guarantee: SyncGuarantee,
        semantic_generation: u64,
        semantic_root: &[u8],
    ) -> Result<DatasetRootRef> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before dataset creation",
            ));
        }
        let kind = DatasetRootKind::from_dataset_type(dataset_type);
        let reference = make_dataset_root_ref(id, kind, semantic_generation, semantic_root);
        let mut next = self.root.clone();
        next.catalog.create(
            path,
            id,
            dataset_type,
            next_generation(next.generation)?,
            properties,
            flags,
            sync_guarantee,
        )?;
        next.dataset_roots.insert(id, reference);
        next.generation = next_generation(next.generation)?;

        self.write_semantic_root(reference, semantic_root)?;
        self.publish_root(next)?;
        Ok(reference)
    }

    /// Atomically create a cataloged named volume and its empty sparse root.
    pub fn create_volume(
        &mut self,
        path: &str,
        id: DatasetId,
        capacity_bytes: u64,
        properties: Vec<u8>,
        flags: DatasetFlags,
        sync_guarantee: SyncGuarantee,
    ) -> Result<VolumeGeometry> {
        let geometry = VolumeGeometry::new(capacity_bytes)?;
        let volume_root = VolumeRoot {
            geometry,
            generation: 1,
            resize_generation: 1,
            snapshot_generation: 0,
            map_root: None,
        };
        self.create_dataset_with_root(
            path,
            id,
            DatasetType::Volume,
            properties,
            flags,
            sync_guarantee,
            volume_root.generation,
            &encode_volume_root(&volume_root),
        )?;
        Ok(geometry)
    }

    /// Open a named volume as a detached dataset handle. The Pool runtime
    /// remains with its owner, so several filesystem and volume handles can be
    /// open while the owner serializes durable publication.
    pub fn open_volume(&self, path: &str) -> Result<PoolVolume> {
        let id = self.root.catalog.lookup(path)?;
        let (_, _, dataset_type, _, _, _) =
            self.root
                .catalog
                .get_by_id(&id)
                .ok_or(PoolRuntimeError::CorruptRoot(
                    "catalog lookup lost dataset identity",
                ))?;
        if dataset_type != DatasetType::Volume {
            return Err(PoolRuntimeError::WrongRootType {
                dataset_id: id,
                expected: DatasetRootKind::Volume,
                actual: DatasetRootKind::from_dataset_type(dataset_type),
            });
        }
        let reference = *self
            .root
            .dataset_roots
            .get(&id)
            .ok_or(PoolRuntimeError::MissingRoot(id))?;
        let root = decode_volume_root(&load_immutable_object(&self.pool, reference)?)?;
        if root.generation != reference.semantic_generation {
            return Err(PoolRuntimeError::InvalidVolume(
                "volume root generation differs from typed reference",
            ));
        }
        Ok(PoolVolume {
            dataset_id: id,
            committed_reference: reference,
            root,
            dirty_chunks: BTreeMap::new(),
        })
    }

    fn write_semantic_root(&mut self, reference: DatasetRootRef, bytes: &[u8]) -> Result<()> {
        self.pool
            .put(DeviceIoClass::Data, reference.object_key, bytes)?;
        self.pool.sync_all()?;
        Ok(())
    }

    fn publish_root(&mut self, next: CanonicalPoolRoot) -> Result<()> {
        self.ensure_publishable()?;
        validate_catalog_root_types(&next.catalog, &next.dataset_roots)?;
        let bytes = encode_pool_root(&next);
        if let Err(error) = self
            .pool
            .put(DeviceIoClass::Data, canonical_pool_root_key(), &bytes)
        {
            self.publication_requires_reopen = true;
            return Err(error.into());
        }
        if let Err(error) = self.pool.sync_all() {
            self.publication_requires_reopen = true;
            return Err(error.into());
        }
        self.root = next;
        Ok(())
    }

    fn ensure_metadata_candidate(&mut self) {
        self.pending_metadata
            .get_or_insert_with(|| PoolMetadataCandidate {
                catalog: self.root.catalog.clone(),
                pool_properties: self.root.pool_properties.clone(),
            });
    }

    fn ensure_publishable(&self) -> Result<()> {
        if self.publication_requires_reopen {
            Err(PoolRuntimeError::PublicationRequiresReopen)
        } else {
            Ok(())
        }
    }
}

/// Committed local-volume geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeGeometry {
    pub capacity_bytes: u64,
    pub block_size_bytes: u32,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub optimal_io_size: u32,
    pub discard_granularity_bytes: u32,
}

impl VolumeGeometry {
    pub fn new(capacity_bytes: u64) -> Result<Self> {
        if capacity_bytes == 0 {
            return Err(PoolRuntimeError::InvalidVolume("capacity must be nonzero"));
        }
        if capacity_bytes % u64::from(DEFAULT_VOLUME_BLOCK_SIZE) != 0 {
            return Err(PoolRuntimeError::InvalidVolume(
                "capacity must be aligned to 4096 bytes",
            ));
        }
        Ok(Self {
            capacity_bytes,
            block_size_bytes: DEFAULT_VOLUME_BLOCK_SIZE,
            logical_sector_size: 512,
            physical_sector_size: DEFAULT_VOLUME_BLOCK_SIZE,
            optimal_io_size: 128 * 1024,
            discard_granularity_bytes: DEFAULT_VOLUME_BLOCK_SIZE,
        })
    }

    #[must_use]
    pub fn block_count(self) -> u64 {
        self.capacity_bytes / u64::from(self.block_size_bytes)
    }
}

#[derive(Clone, Debug)]
struct VolumeRoot {
    geometry: VolumeGeometry,
    generation: u64,
    resize_generation: u64,
    snapshot_generation: u64,
    map_root: Option<ImmutableObjectRef>,
}

#[derive(Clone, Debug)]
struct VolumeMapNode {
    level: u8,
    children: BTreeMap<u8, ImmutableObjectRef>,
}

/// Pool-backed named volume using immutable chunk and radix-map objects.
///
/// Writes remain private to this handle until `flush`. A flush writes new
/// immutable chunks and copy-on-write map nodes, syncs them, then publishes
/// one new volume root through the canonical Pool root.
pub struct PoolVolume {
    dataset_id: DatasetId,
    committed_reference: DatasetRootRef,
    root: VolumeRoot,
    dirty_chunks: BTreeMap<u64, Option<Vec<u8>>>,
}

impl PoolVolume {
    #[must_use]
    pub fn dataset_id(&self) -> DatasetId {
        self.dataset_id
    }

    #[must_use]
    pub fn geometry(&self) -> VolumeGeometry {
        self.root.geometry
    }

    pub fn read_blocks(
        &self,
        runtime: &PoolRuntime,
        start_block: u64,
        block_count: u64,
    ) -> Result<Vec<u8>> {
        self.check_range(start_block, block_count)?;
        let block_size = usize::try_from(self.root.geometry.block_size_bytes)
            .map_err(|_| PoolRuntimeError::Bounds)?;
        let byte_offset = usize::try_from(start_block)
            .ok()
            .and_then(|block| block.checked_mul(block_size))
            .ok_or(PoolRuntimeError::Bounds)?;
        let byte_len = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(block_size))
            .ok_or(PoolRuntimeError::Bounds)?;
        let mut output = vec![0_u8; byte_len];
        let mut copied = 0usize;
        while copied < byte_len {
            let absolute = byte_offset
                .checked_add(copied)
                .ok_or(PoolRuntimeError::Bounds)?;
            let chunk_index = u64::try_from(absolute / VOLUME_CHUNK_SIZE)
                .map_err(|_| PoolRuntimeError::Bounds)?;
            let within = absolute % VOLUME_CHUNK_SIZE;
            let take = (VOLUME_CHUNK_SIZE - within).min(byte_len - copied);
            if let Some(chunk) = self.visible_chunk(runtime, chunk_index)? {
                output[copied..copied + take].copy_from_slice(&chunk[within..within + take]);
            }
            copied += take;
        }
        Ok(output)
    }

    pub fn write_blocks(
        &mut self,
        runtime: &PoolRuntime,
        start_block: u64,
        payload: &[u8],
    ) -> Result<()> {
        let block_size = usize::try_from(self.root.geometry.block_size_bytes)
            .map_err(|_| PoolRuntimeError::Bounds)?;
        if payload.is_empty() || payload.len() % block_size != 0 {
            return Err(PoolRuntimeError::InvalidVolume(
                "write payload must contain whole nonempty blocks",
            ));
        }
        let block_count =
            u64::try_from(payload.len() / block_size).map_err(|_| PoolRuntimeError::Bounds)?;
        self.check_range(start_block, block_count)?;
        let byte_offset = usize::try_from(start_block)
            .ok()
            .and_then(|block| block.checked_mul(block_size))
            .ok_or(PoolRuntimeError::Bounds)?;
        let mut copied = 0usize;
        while copied < payload.len() {
            let absolute = byte_offset
                .checked_add(copied)
                .ok_or(PoolRuntimeError::Bounds)?;
            let chunk_index = u64::try_from(absolute / VOLUME_CHUNK_SIZE)
                .map_err(|_| PoolRuntimeError::Bounds)?;
            let within = absolute % VOLUME_CHUNK_SIZE;
            let take = (VOLUME_CHUNK_SIZE - within).min(payload.len() - copied);
            let chunk = self.chunk_for_mutation(runtime, chunk_index)?;
            chunk[within..within + take].copy_from_slice(&payload[copied..copied + take]);
            copied += take;
        }
        self.drop_all_zero_dirty_chunks();
        Ok(())
    }

    pub fn zero_blocks(
        &mut self,
        runtime: &PoolRuntime,
        start_block: u64,
        block_count: u64,
    ) -> Result<()> {
        self.check_range(start_block, block_count)?;
        let block_size = usize::try_from(self.root.geometry.block_size_bytes)
            .map_err(|_| PoolRuntimeError::Bounds)?;
        let byte_offset = usize::try_from(start_block)
            .ok()
            .and_then(|block| block.checked_mul(block_size))
            .ok_or(PoolRuntimeError::Bounds)?;
        let byte_len = usize::try_from(block_count)
            .ok()
            .and_then(|count| count.checked_mul(block_size))
            .ok_or(PoolRuntimeError::Bounds)?;
        let mut cleared = 0usize;
        while cleared < byte_len {
            let absolute = byte_offset
                .checked_add(cleared)
                .ok_or(PoolRuntimeError::Bounds)?;
            let chunk_index = u64::try_from(absolute / VOLUME_CHUNK_SIZE)
                .map_err(|_| PoolRuntimeError::Bounds)?;
            let within = absolute % VOLUME_CHUNK_SIZE;
            let take = (VOLUME_CHUNK_SIZE - within).min(byte_len - cleared);
            if within == 0 && take == VOLUME_CHUNK_SIZE {
                self.dirty_chunks.insert(chunk_index, None);
            } else {
                let chunk = self.chunk_for_mutation(runtime, chunk_index)?;
                chunk[within..within + take].fill(0);
            }
            cleared += take;
        }
        self.drop_all_zero_dirty_chunks();
        Ok(())
    }

    /// Commit dirty chunks, immutable map nodes, the volume root, then the
    /// canonical Pool root. A stale handle is refused before it writes.
    pub fn flush(&mut self, runtime: &mut PoolRuntime) -> Result<()> {
        let current = runtime
            .dataset_root(self.dataset_id)
            .ok_or(PoolRuntimeError::MissingRoot(self.dataset_id))?;
        if *current != self.committed_reference {
            return Err(PoolRuntimeError::StaleVolumeHandle(self.dataset_id));
        }
        if self.dirty_chunks.is_empty() {
            runtime.pool_mut().sync_all()?;
            return Ok(());
        }

        let next_volume_generation = next_generation(self.root.generation)?;
        let mut map_root = self.root.map_root;
        for (&chunk_index, staged) in &self.dirty_chunks {
            let chunk_reference = match staged {
                Some(bytes) => {
                    let digest = *blake3::hash(bytes).as_bytes();
                    let reference = ImmutableObjectRef {
                        object_key: volume_chunk_key(
                            self.dataset_id,
                            chunk_index,
                            next_volume_generation,
                            digest,
                        ),
                        digest,
                    };
                    runtime
                        .pool_mut()
                        .put(DeviceIoClass::Data, reference.object_key, bytes)?;
                    Some(reference)
                }
                None => None,
            };
            map_root = update_volume_map(
                runtime.pool_mut(),
                self.dataset_id,
                map_root,
                VOLUME_MAP_ROOT_LEVEL,
                chunk_index,
                chunk_reference,
            )?;
        }
        runtime.pool_mut().sync_all()?;

        let next_root = VolumeRoot {
            geometry: self.root.geometry,
            generation: next_volume_generation,
            resize_generation: self.root.resize_generation,
            snapshot_generation: self.root.snapshot_generation,
            map_root,
        };
        let reference = runtime.publish_dataset_root(
            self.dataset_id,
            DatasetRootKind::Volume,
            next_root.generation,
            &encode_volume_root(&next_root),
        )?;
        self.root = next_root;
        self.committed_reference = reference;
        self.dirty_chunks.clear();
        Ok(())
    }

    fn visible_chunk(&self, runtime: &PoolRuntime, chunk_index: u64) -> Result<Option<Vec<u8>>> {
        if let Some(staged) = self.dirty_chunks.get(&chunk_index) {
            return Ok(staged.clone());
        }
        load_volume_chunk(runtime.pool(), self.dataset_id, &self.root, chunk_index)
    }

    fn chunk_for_mutation(
        &mut self,
        runtime: &PoolRuntime,
        chunk_index: u64,
    ) -> Result<&mut Vec<u8>> {
        if !self.dirty_chunks.contains_key(&chunk_index) {
            let bytes =
                load_volume_chunk(runtime.pool(), self.dataset_id, &self.root, chunk_index)?
                    .unwrap_or_else(|| vec![0_u8; VOLUME_CHUNK_SIZE]);
            self.dirty_chunks.insert(chunk_index, Some(bytes));
        }
        let staged = self
            .dirty_chunks
            .get_mut(&chunk_index)
            .ok_or(PoolRuntimeError::InvalidVolume("dirty chunk disappeared"))?;
        if staged.is_none() {
            *staged = Some(vec![0_u8; VOLUME_CHUNK_SIZE]);
        }
        staged.as_mut().ok_or(PoolRuntimeError::InvalidVolume(
            "dirty chunk is unavailable",
        ))
    }

    fn drop_all_zero_dirty_chunks(&mut self) {
        for staged in self.dirty_chunks.values_mut() {
            if staged
                .as_ref()
                .is_some_and(|bytes| bytes.iter().all(|byte| *byte == 0))
            {
                *staged = None;
            }
        }
    }

    fn check_range(&self, start_block: u64, block_count: u64) -> Result<()> {
        let end = start_block
            .checked_add(block_count)
            .ok_or(PoolRuntimeError::Bounds)?;
        if end > self.root.geometry.block_count() {
            return Err(PoolRuntimeError::Bounds);
        }
        Ok(())
    }
}

fn next_generation(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(PoolRuntimeError::CorruptRoot("generation exhausted"))
}

fn canonical_pool_root_key() -> ObjectKey {
    ObjectKey::from_name(b"tidefs:canonical-pool-root:v1")
}

fn make_dataset_root_ref(
    id: DatasetId,
    kind: DatasetRootKind,
    generation: u64,
    bytes: &[u8],
) -> DatasetRootRef {
    let digest = *blake3::hash(bytes).as_bytes();
    DatasetRootRef {
        dataset_id: id,
        kind,
        object_key: semantic_root_key(id, kind, generation, digest),
        digest,
        semantic_generation: generation,
    }
}

fn semantic_root_key(
    id: DatasetId,
    kind: DatasetRootKind,
    generation: u64,
    digest: [u8; 32],
) -> ObjectKey {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(b"tidefs:semantic-root:v1\0");
    bytes.extend_from_slice(id.as_bytes());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(&digest);
    ObjectKey::from_name(bytes)
}

fn volume_chunk_key(
    id: DatasetId,
    chunk_index: u64,
    generation: u64,
    digest: [u8; 32],
) -> ObjectKey {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(b"tidefs:volume-chunk:v1\0");
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&chunk_index.to_le_bytes());
    bytes.extend_from_slice(&generation.to_le_bytes());
    bytes.extend_from_slice(&digest);
    ObjectKey::from_name(bytes)
}

fn volume_map_node_key(id: DatasetId, level: u8, digest: [u8; 32]) -> ObjectKey {
    let mut bytes = Vec::with_capacity(80);
    bytes.extend_from_slice(b"tidefs:volume-map-node:v1\0");
    bytes.extend_from_slice(id.as_bytes());
    bytes.push(level);
    bytes.extend_from_slice(&digest);
    ObjectKey::from_name(bytes)
}

fn load_immutable_object(pool: &Pool, reference: DatasetRootRef) -> Result<Vec<u8>> {
    load_immutable_ref(
        pool,
        ImmutableObjectRef {
            object_key: reference.object_key,
            digest: reference.digest,
        },
    )
}

fn load_immutable_ref(pool: &Pool, reference: ImmutableObjectRef) -> Result<Vec<u8>> {
    let bytes = pool.get(DeviceIoClass::Data, reference.object_key)?.ok_or(
        PoolRuntimeError::CorruptRoot("referenced immutable object is missing"),
    )?;
    if *blake3::hash(&bytes).as_bytes() != reference.digest {
        return Err(PoolRuntimeError::CorruptRoot(
            "referenced immutable-object digest differs",
        ));
    }
    Ok(bytes)
}

fn load_volume_chunk(
    pool: &Pool,
    id: DatasetId,
    root: &VolumeRoot,
    chunk_index: u64,
) -> Result<Option<Vec<u8>>> {
    let Some(reference) = lookup_volume_map(pool, id, root.map_root, chunk_index)? else {
        return Ok(None);
    };
    let bytes = load_immutable_ref(pool, reference)?;
    if bytes.len() != VOLUME_CHUNK_SIZE {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume chunk has the wrong length",
        ));
    }
    Ok(Some(bytes))
}

fn lookup_volume_map(
    pool: &Pool,
    id: DatasetId,
    root: Option<ImmutableObjectRef>,
    chunk_index: u64,
) -> Result<Option<ImmutableObjectRef>> {
    let Some(mut reference) = root else {
        return Ok(None);
    };
    let mut level = VOLUME_MAP_ROOT_LEVEL;
    loop {
        let node = load_volume_map_node(pool, id, reference, level)?;
        let digit = ((chunk_index >> (u32::from(level) * 8)) & 0xff) as u8;
        let Some(child) = node.children.get(&digit).copied() else {
            return Ok(None);
        };
        if level == 0 {
            return Ok(Some(child));
        }
        reference = child;
        level -= 1;
    }
}

fn update_volume_map(
    pool: &mut Pool,
    id: DatasetId,
    current: Option<ImmutableObjectRef>,
    level: u8,
    chunk_index: u64,
    replacement: Option<ImmutableObjectRef>,
) -> Result<Option<ImmutableObjectRef>> {
    let mut node = match current {
        Some(reference) => load_volume_map_node(pool, id, reference, level)?,
        None => VolumeMapNode {
            level,
            children: BTreeMap::new(),
        },
    };
    let digit = ((chunk_index >> (u32::from(level) * 8)) & 0xff) as u8;
    if level == 0 {
        match replacement {
            Some(reference) => {
                node.children.insert(digit, reference);
            }
            None => {
                node.children.remove(&digit);
            }
        }
    } else {
        let child = update_volume_map(
            pool,
            id,
            node.children.get(&digit).copied(),
            level - 1,
            chunk_index,
            replacement,
        )?;
        match child {
            Some(reference) => {
                node.children.insert(digit, reference);
            }
            None => {
                node.children.remove(&digit);
            }
        }
    }
    if node.children.is_empty() {
        return Ok(None);
    }
    let bytes = encode_volume_map_node(&node);
    let digest = *blake3::hash(&bytes).as_bytes();
    let reference = ImmutableObjectRef {
        object_key: volume_map_node_key(id, level, digest),
        digest,
    };
    pool.put(DeviceIoClass::Data, reference.object_key, &bytes)?;
    Ok(Some(reference))
}

fn load_volume_map_node(
    pool: &Pool,
    _id: DatasetId,
    reference: ImmutableObjectRef,
    expected_level: u8,
) -> Result<VolumeMapNode> {
    let node = decode_volume_map_node(&load_immutable_ref(pool, reference)?)?;
    if node.level != expected_level {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume map level differs from its parent",
        ));
    }
    Ok(node)
}

fn validate_catalog_dataset_type(
    catalog: &DatasetCatalog,
    id: DatasetId,
    kind: DatasetRootKind,
) -> Result<()> {
    let (_, _, dataset_type, _, _, _) = catalog.get_by_id(&id).ok_or(
        PoolRuntimeError::CorruptRoot("typed root has no catalog entry"),
    )?;
    let actual = DatasetRootKind::from_dataset_type(dataset_type);
    if actual != kind {
        return Err(PoolRuntimeError::WrongRootType {
            dataset_id: id,
            expected: kind,
            actual,
        });
    }
    Ok(())
}

fn validate_catalog_root_types(
    catalog: &DatasetCatalog,
    roots: &BTreeMap<DatasetId, DatasetRootRef>,
) -> Result<()> {
    for (id, reference) in roots {
        if *id != reference.dataset_id {
            return Err(PoolRuntimeError::CorruptRoot(
                "dataset-root table key differs from record identity",
            ));
        }
        validate_catalog_dataset_type(catalog, *id, reference.kind)?;
    }
    for (_, id) in catalog.entries() {
        if !roots.contains_key(&id) {
            return Err(PoolRuntimeError::CorruptRoot(
                "catalog entry has no typed semantic root",
            ));
        }
    }
    Ok(())
}

fn encode_pool_root(root: &CanonicalPoolRoot) -> Vec<u8> {
    let catalog = root.catalog.encode();
    let properties = root.pool_properties.to_key_value_blob();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(POOL_ROOT_MAGIC);
    bytes.extend_from_slice(&POOL_ROOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&root.generation.to_le_bytes());
    bytes.extend_from_slice(&(catalog.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(properties.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(root.dataset_roots.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&catalog);
    bytes.extend_from_slice(&properties);
    for reference in root.dataset_roots.values() {
        bytes.extend_from_slice(reference.dataset_id.as_bytes());
        bytes.push(reference.kind as u8);
        bytes.extend_from_slice(&reference.semantic_generation.to_le_bytes());
        bytes.extend_from_slice(reference.object_key.as_bytes());
        bytes.extend_from_slice(&reference.digest);
    }
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn decode_pool_root(bytes: &[u8]) -> Result<CanonicalPoolRoot> {
    const HEADER: usize = 8 + 2 + 8 + 4 + 4 + 4;
    const ROOT_RECORD: usize = 16 + 1 + 8 + 32 + 32;
    if bytes.len() < HEADER + CHECKSUM_LEN || &bytes[..8] != POOL_ROOT_MAGIC {
        return Err(PoolRuntimeError::CorruptRoot("bad Pool-root header"));
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    if blake3::hash(&bytes[..payload_len]).as_bytes() != &bytes[payload_len..] {
        return Err(PoolRuntimeError::CorruptRoot("Pool-root checksum mismatch"));
    }
    let mut offset = 8;
    if take_u16(bytes, &mut offset)? != POOL_ROOT_VERSION {
        return Err(PoolRuntimeError::CorruptRoot(
            "unsupported Pool-root version",
        ));
    }
    let generation = take_u64(bytes, &mut offset)?;
    let catalog_len = take_u32(bytes, &mut offset)? as usize;
    let properties_len = take_u32(bytes, &mut offset)? as usize;
    let root_count = take_u32(bytes, &mut offset)? as usize;
    let roots_len = root_count
        .checked_mul(ROOT_RECORD)
        .ok_or(PoolRuntimeError::CorruptRoot("Pool-root length overflow"))?;
    if offset
        .checked_add(catalog_len)
        .and_then(|value| value.checked_add(properties_len))
        .and_then(|value| value.checked_add(roots_len))
        != Some(payload_len)
    {
        return Err(PoolRuntimeError::CorruptRoot(
            "Pool-root length fields disagree",
        ));
    }
    let catalog_end = offset + catalog_len;
    let catalog = DatasetCatalog::decode(&bytes[offset..catalog_end])?;
    offset = catalog_end;
    let properties_end = offset + properties_len;
    let pool_properties = PropertySet::from_key_value_blob(&bytes[offset..properties_end]);
    offset = properties_end;
    let mut dataset_roots = BTreeMap::new();
    for _ in 0..root_count {
        let id = DatasetId::from_bytes(take_array::<16>(bytes, &mut offset)?);
        let kind = DatasetRootKind::decode(take_u8(bytes, &mut offset)?)?;
        let semantic_generation = take_u64(bytes, &mut offset)?;
        let object_key = ObjectKey::from_bytes32(take_array::<32>(bytes, &mut offset)?);
        let digest = take_array::<32>(bytes, &mut offset)?;
        if dataset_roots
            .insert(
                id,
                DatasetRootRef {
                    dataset_id: id,
                    kind,
                    object_key,
                    digest,
                    semantic_generation,
                },
            )
            .is_some()
        {
            return Err(PoolRuntimeError::CorruptRoot(
                "duplicate dataset-root identity",
            ));
        }
    }
    let root = CanonicalPoolRoot {
        generation,
        catalog,
        pool_properties,
        dataset_roots,
    };
    validate_catalog_root_types(&root.catalog, &root.dataset_roots)?;
    Ok(root)
}

fn encode_volume_root(root: &VolumeRoot) -> Vec<u8> {
    let geometry = root.geometry;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(VOLUME_ROOT_MAGIC);
    bytes.extend_from_slice(&VOLUME_ROOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&root.generation.to_le_bytes());
    bytes.extend_from_slice(&geometry.capacity_bytes.to_le_bytes());
    bytes.extend_from_slice(&geometry.block_size_bytes.to_le_bytes());
    bytes.extend_from_slice(&geometry.logical_sector_size.to_le_bytes());
    bytes.extend_from_slice(&geometry.physical_sector_size.to_le_bytes());
    bytes.extend_from_slice(&geometry.optimal_io_size.to_le_bytes());
    bytes.extend_from_slice(&geometry.discard_granularity_bytes.to_le_bytes());
    bytes.extend_from_slice(&root.resize_generation.to_le_bytes());
    bytes.extend_from_slice(&root.snapshot_generation.to_le_bytes());
    bytes.push(VOLUME_MAP_ROOT_LEVEL);
    bytes.push(u8::from(root.map_root.is_some()));
    if let Some(reference) = root.map_root {
        bytes.extend_from_slice(reference.object_key.as_bytes());
        bytes.extend_from_slice(&reference.digest);
    } else {
        bytes.extend_from_slice(&[0_u8; 64]);
    }
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn decode_volume_root(bytes: &[u8]) -> Result<VolumeRoot> {
    const PAYLOAD_LEN: usize = 8 + 2 + 8 + 8 + 4 * 5 + 8 + 8 + 1 + 1 + 64;
    if bytes.len() != PAYLOAD_LEN + CHECKSUM_LEN || &bytes[..8] != VOLUME_ROOT_MAGIC {
        return Err(PoolRuntimeError::InvalidVolume("bad volume-root header"));
    }
    if blake3::hash(&bytes[..PAYLOAD_LEN]).as_bytes() != &bytes[PAYLOAD_LEN..] {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume-root checksum mismatch",
        ));
    }
    let mut offset = 8;
    if take_u16(bytes, &mut offset)? != VOLUME_ROOT_VERSION {
        return Err(PoolRuntimeError::InvalidVolume(
            "unsupported volume-root version",
        ));
    }
    let generation = take_u64(bytes, &mut offset)?;
    let geometry = VolumeGeometry {
        capacity_bytes: take_u64(bytes, &mut offset)?,
        block_size_bytes: take_u32(bytes, &mut offset)?,
        logical_sector_size: take_u32(bytes, &mut offset)?,
        physical_sector_size: take_u32(bytes, &mut offset)?,
        optimal_io_size: take_u32(bytes, &mut offset)?,
        discard_granularity_bytes: take_u32(bytes, &mut offset)?,
    };
    validate_volume_geometry(geometry)?;
    let resize_generation = take_u64(bytes, &mut offset)?;
    let snapshot_generation = take_u64(bytes, &mut offset)?;
    if take_u8(bytes, &mut offset)? != VOLUME_MAP_ROOT_LEVEL {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume map has unsupported depth",
        ));
    }
    let has_map = take_u8(bytes, &mut offset)?;
    let object_key = ObjectKey::from_bytes32(take_array::<32>(bytes, &mut offset)?);
    let digest = take_array::<32>(bytes, &mut offset)?;
    let map_root = match has_map {
        0 if object_key.as_bytes().iter().all(|byte| *byte == 0)
            && digest.iter().all(|byte| *byte == 0) =>
        {
            None
        }
        1 => Some(ImmutableObjectRef { object_key, digest }),
        _ => {
            return Err(PoolRuntimeError::InvalidVolume(
                "volume map root presence is invalid",
            ));
        }
    };
    Ok(VolumeRoot {
        geometry,
        generation,
        resize_generation,
        snapshot_generation,
        map_root,
    })
}

fn validate_volume_geometry(geometry: VolumeGeometry) -> Result<()> {
    if geometry.capacity_bytes == 0
        || geometry.block_size_bytes != DEFAULT_VOLUME_BLOCK_SIZE
        || geometry.capacity_bytes % u64::from(geometry.block_size_bytes) != 0
        || geometry.logical_sector_size == 0
        || geometry.physical_sector_size < geometry.logical_sector_size
        || geometry.discard_granularity_bytes == 0
    {
        return Err(PoolRuntimeError::InvalidVolume(
            "invalid committed volume geometry",
        ));
    }
    Ok(())
}

fn encode_volume_map_node(node: &VolumeMapNode) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16 + node.children.len() * 65 + CHECKSUM_LEN);
    bytes.extend_from_slice(VOLUME_MAP_MAGIC);
    bytes.extend_from_slice(&VOLUME_MAP_VERSION.to_le_bytes());
    bytes.push(node.level);
    bytes.extend_from_slice(&(node.children.len() as u16).to_le_bytes());
    for (index, reference) in &node.children {
        bytes.push(*index);
        bytes.extend_from_slice(reference.object_key.as_bytes());
        bytes.extend_from_slice(&reference.digest);
    }
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn decode_volume_map_node(bytes: &[u8]) -> Result<VolumeMapNode> {
    const HEADER: usize = 8 + 2 + 1 + 2;
    const ENTRY: usize = 1 + 32 + 32;
    if bytes.len() < HEADER + CHECKSUM_LEN || &bytes[..8] != VOLUME_MAP_MAGIC {
        return Err(PoolRuntimeError::InvalidVolume(
            "bad volume-map node header",
        ));
    }
    let payload_len = bytes.len() - CHECKSUM_LEN;
    if blake3::hash(&bytes[..payload_len]).as_bytes() != &bytes[payload_len..] {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume-map node checksum mismatch",
        ));
    }
    let mut offset = 8;
    if take_u16(bytes, &mut offset)? != VOLUME_MAP_VERSION {
        return Err(PoolRuntimeError::InvalidVolume(
            "unsupported volume-map node version",
        ));
    }
    let level = take_u8(bytes, &mut offset)?;
    if level > VOLUME_MAP_ROOT_LEVEL {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume-map node level is invalid",
        ));
    }
    let count = usize::from(take_u16(bytes, &mut offset)?);
    if count == 0 || count > 256 || offset.checked_add(count * ENTRY) != Some(payload_len) {
        return Err(PoolRuntimeError::InvalidVolume(
            "volume-map node length is invalid",
        ));
    }
    let mut children = BTreeMap::new();
    for _ in 0..count {
        let index = take_u8(bytes, &mut offset)?;
        let reference = ImmutableObjectRef {
            object_key: ObjectKey::from_bytes32(take_array::<32>(bytes, &mut offset)?),
            digest: take_array::<32>(bytes, &mut offset)?,
        };
        if children.insert(index, reference).is_some() {
            return Err(PoolRuntimeError::InvalidVolume(
                "volume-map node contains a duplicate child",
            ));
        }
    }
    Ok(VolumeMapNode { level, children })
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    Ok(take_array::<1>(bytes, offset)?[0])
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_array(bytes, offset)?))
}

fn take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or(PoolRuntimeError::CorruptRoot("decode length overflow"))?;
    let value = bytes
        .get(*offset..end)
        .ok_or(PoolRuntimeError::CorruptRoot("truncated encoding"))?
        .try_into()
        .map_err(|_| PoolRuntimeError::CorruptRoot("truncated encoding"))?;
    *offset = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;

    fn runtime(path: &Path) -> PoolRuntime {
        let device = path.join("device.img");
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&device)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        PoolRuntime::open_block_devices(
            path,
            &[device],
            "tank",
            PoolRedundancyPolicy::default(),
            &StoreOptions::default(),
        )
        .unwrap()
    }

    fn create_volume(runtime: &mut PoolRuntime, name: &str, byte: u8) -> DatasetId {
        let id = DatasetId::from_bytes([byte; 16]);
        runtime
            .create_volume(
                name,
                id,
                4 * 1024 * 1024,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
            )
            .unwrap();
        id
    }

    fn reopen(runtime: PoolRuntime) -> PoolRuntime {
        let config = runtime.pool().config().clone();
        drop(runtime);
        let pool = Pool::open(config, PoolProperties::default(), &StoreOptions::default()).unwrap();
        PoolRuntime::open(pool).unwrap()
    }

    #[test]
    fn pool_root_refuses_checksum_corruption() {
        let root = CanonicalPoolRoot {
            generation: 1,
            catalog: DatasetCatalog::new(),
            pool_properties: PropertySet::new(),
            dataset_roots: BTreeMap::new(),
        };
        let mut bytes = encode_pool_root(&root);
        bytes[10] ^= 0x80;
        assert!(matches!(
            decode_pool_root(&bytes),
            Err(PoolRuntimeError::CorruptRoot("Pool-root checksum mismatch"))
        ));
    }

    #[test]
    fn named_volumes_share_one_owner_without_aliasing() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let first_id = create_volume(&mut owner, "first", 1);
        let second_id = create_volume(&mut owner, "second", 2);
        let digest = [9_u8; 32];
        assert_ne!(
            volume_chunk_key(first_id, 0, 2, digest),
            volume_chunk_key(second_id, 0, 2, digest)
        );

        let mut first = owner.open_volume("first").unwrap();
        let mut second = owner.open_volume("second").unwrap();
        first.write_blocks(&owner, 0, &vec![0x5a; 4096]).unwrap();
        second.write_blocks(&owner, 0, &vec![0xa5; 4096]).unwrap();
        first.flush(&mut owner).unwrap();
        second.flush(&mut owner).unwrap();

        let owner = reopen(owner);
        let first = owner.open_volume("first").unwrap();
        let second = owner.open_volume("second").unwrap();
        assert_eq!(first.read_blocks(&owner, 0, 1).unwrap(), vec![0x5a; 4096]);
        assert_eq!(second.read_blocks(&owner, 0, 1).unwrap(), vec![0xa5; 4096]);
        assert_eq!(first.read_blocks(&owner, 1, 1).unwrap(), vec![0; 4096]);
    }

    #[test]
    fn unflushed_overwrite_cannot_change_committed_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 3);
        let mut volume = owner.open_volume("vol").unwrap();
        volume.write_blocks(&owner, 0, &vec![1; 4096]).unwrap();
        volume.flush(&mut owner).unwrap();
        volume.write_blocks(&owner, 0, &vec![2; 4096]).unwrap();
        drop(volume);

        let owner = reopen(owner);
        let volume = owner.open_volume("vol").unwrap();
        assert_eq!(volume.read_blocks(&owner, 0, 1).unwrap(), vec![1; 4096]);
    }

    #[test]
    fn volume_bounds_zero_and_reopen_are_exact() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 4);
        let mut volume = owner.open_volume("vol").unwrap();
        assert!(matches!(
            volume.read_blocks(&owner, volume.geometry().block_count(), 1),
            Err(PoolRuntimeError::Bounds)
        ));
        volume.write_blocks(&owner, 2, &vec![7; 4096]).unwrap();
        volume.flush(&mut owner).unwrap();
        volume.zero_blocks(&owner, 2, 1).unwrap();
        volume.flush(&mut owner).unwrap();

        let owner = reopen(owner);
        let volume = owner.open_volume("vol").unwrap();
        assert_eq!(volume.read_blocks(&owner, 2, 1).unwrap(), vec![0; 4096]);
    }

    #[test]
    fn stale_same_volume_handle_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let id = create_volume(&mut owner, "vol", 5);
        let mut first = owner.open_volume("vol").unwrap();
        let mut stale = owner.open_volume("vol").unwrap();
        first.write_blocks(&owner, 0, &vec![1; 4096]).unwrap();
        first.flush(&mut owner).unwrap();
        stale.write_blocks(&owner, 1, &vec![2; 4096]).unwrap();
        assert!(matches!(
            stale.flush(&mut owner),
            Err(PoolRuntimeError::StaleVolumeHandle(stale_id)) if stale_id == id
        ));
    }

    #[test]
    fn invalid_metadata_candidate_does_not_change_live_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let generation = owner.generation();
        let mut candidate = owner.dataset_catalog().clone();
        candidate
            .create(
                "missing-root",
                DatasetId::from_bytes([7; 16]),
                DatasetType::Filesystem,
                1,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
            )
            .unwrap();
        *owner.dataset_catalog_mut().unwrap() = candidate;
        assert!(matches!(
            owner.publish_metadata(),
            Err(PoolRuntimeError::CorruptRoot(
                "catalog entry has no typed semantic root"
            ))
        ));
        assert_eq!(owner.generation(), generation);
        assert!(owner.dataset_catalog().lookup("missing-root").is_err());
    }

    #[test]
    fn volume_root_size_is_independent_of_allocated_chunk_count() {
        let empty = VolumeRoot {
            geometry: VolumeGeometry::new(4096).unwrap(),
            generation: 1,
            resize_generation: 1,
            snapshot_generation: 0,
            map_root: None,
        };
        let populated = VolumeRoot {
            map_root: Some(ImmutableObjectRef {
                object_key: ObjectKey::from_bytes32([1; 32]),
                digest: [2; 32],
            }),
            ..empty.clone()
        };
        assert_eq!(
            encode_volume_root(&empty).len(),
            encode_volume_root(&populated).len()
        );
    }
}
