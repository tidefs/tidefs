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
const SNAPSHOT_ROOT_MAGIC: &[u8; 8] = b"TFSSNP02";
const SNAPSHOT_ROOT_VERSION: u16 = 2;
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
    InvalidSnapshot(&'static str),
    StaleVolumeHandle(DatasetId),
    PublicationOutcomeUncertain(StoreError),
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
            Self::InvalidSnapshot(reason) => write!(f, "invalid snapshot: {reason}"),
            Self::StaleVolumeHandle(id) => {
                write!(f, "volume {id} was changed through another open handle")
            }
            Self::PublicationOutcomeUncertain(error) => write!(
                f,
                "canonical Pool publication outcome is uncertain; reopen before mutation: {error}"
            ),
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
            Self::Store(error) | Self::PublicationOutcomeUncertain(error) => Some(error),
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

/// One immutable semantic root to install with a staged metadata transition.
#[derive(Clone, Copy, Debug)]
pub struct DatasetRootUpdate<'a> {
    pub dataset_id: DatasetId,
    pub kind: DatasetRootKind,
    pub semantic_generation: u64,
    pub bytes: &'a [u8],
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
        for reference in root.dataset_roots.values().copied() {
            let _ = load_immutable_object(&pool, reference)?;
        }
        let runtime = Self {
            pool,
            root,
            pending_metadata: None,
            publication_requires_reopen: false,
        };
        runtime.validate_snapshot_roots()?;
        Ok(runtime)
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
    pub fn is_unpublished(&self) -> bool {
        self.root.generation == 0
            && self.root.catalog.entries().is_empty()
            && self.root.dataset_roots.is_empty()
    }

    #[must_use]
    pub fn publication_requires_reopen(&self) -> bool {
        self.publication_requires_reopen
    }

    #[must_use]
    pub fn dataset_catalog(&self) -> &DatasetCatalog {
        self.pending_metadata
            .as_ref()
            .map(|candidate| &candidate.catalog)
            .unwrap_or(&self.root.catalog)
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
        self.pending_metadata
            .as_ref()
            .map(|candidate| &candidate.pool_properties)
            .unwrap_or(&self.root.pool_properties)
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

    /// Abandon the caller's staged catalog/property transaction without
    /// changing the live canonical Pool composition.
    pub fn discard_metadata_candidate(&mut self) {
        self.pending_metadata = None;
    }

    #[must_use]
    pub fn dataset_root(&self, id: DatasetId) -> Option<&DatasetRootRef> {
        self.root.dataset_roots.get(&id)
    }

    /// Construct the exact immutable reference used by canonical dataset and
    /// snapshot roots. This does not write or publish the object.
    #[must_use]
    pub fn dataset_root_reference(
        id: DatasetId,
        kind: DatasetRootKind,
        semantic_generation: u64,
        bytes: &[u8],
    ) -> DatasetRootRef {
        make_dataset_root_ref(id, kind, semantic_generation, bytes)
    }

    /// Write and sync an immutable semantic root before a later snapshot-root
    /// publication makes it reachable. The caller must publish the returned
    /// reference only through a canonical Pool-root transition.
    pub fn prepare_snapshot_source_root(
        &mut self,
        id: DatasetId,
        kind: DatasetRootKind,
        semantic_generation: u64,
        bytes: &[u8],
    ) -> Result<DatasetRootRef> {
        self.ensure_publishable()?;
        if kind == DatasetRootKind::Snapshot {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source root cannot itself be a snapshot",
            ));
        }
        let reference = make_dataset_root_ref(id, kind, semantic_generation, bytes);
        self.write_semantic_root(reference, bytes)?;
        Ok(reference)
    }

    /// Load and checksum-validate one canonical typed snapshot root.
    pub fn load_snapshot_root(&self, id: DatasetId) -> Result<SnapshotRoot> {
        let reference = *self
            .root
            .dataset_roots
            .get(&id)
            .ok_or(PoolRuntimeError::MissingRoot(id))?;
        if reference.kind != DatasetRootKind::Snapshot {
            return Err(PoolRuntimeError::WrongRootType {
                dataset_id: id,
                expected: DatasetRootKind::Snapshot,
                actual: reference.kind,
            });
        }
        let root = decode_snapshot_root(&load_immutable_object(&self.pool, reference)?)?;
        if root.snapshot_generation != reference.semantic_generation {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot generation differs from its typed reference",
            ));
        }
        Ok(root)
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

    /// Consume the semantic owner after all front ends are closed.
    #[must_use]
    pub fn into_pool(self) -> Pool {
        self.pool
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

    /// Load one exact immutable semantic root by its captured reference.
    /// Unlike `load_dataset_root`, this is independent of the dataset's newer
    /// current root in the canonical table.
    pub fn load_root_reference(&self, reference: DatasetRootRef) -> Result<Vec<u8>> {
        if reference.kind == DatasetRootKind::Snapshot {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source root cannot itself be a snapshot",
            ));
        }
        load_immutable_object(&self.pool, reference)
    }

    /// Immutable object keys reachable through canonical Pool-owned roots.
    ///
    /// Filesystem transaction/content descendants remain owned by the
    /// filesystem retention walker. Volume maps and chunks are Pool-runtime
    /// objects, so this method validates and includes their complete immutable
    /// graphs for both current volume roots and captured volume snapshots.
    pub fn canonical_root_object_keys(&self) -> Result<Vec<ObjectKey>> {
        let mut keys = Vec::with_capacity(self.root.dataset_roots.len().saturating_add(1));
        keys.push(canonical_pool_root_key());
        for (dataset_id, reference) in &self.root.dataset_roots {
            keys.push(reference.object_key);
            match reference.kind {
                DatasetRootKind::Filesystem => {}
                DatasetRootKind::Volume => {
                    let root = decode_volume_root(&load_immutable_object(&self.pool, *reference)?)?;
                    collect_volume_root_object_keys(&self.pool, &root, &mut keys)?;
                }
                DatasetRootKind::Snapshot => {
                    let source = self.load_snapshot_root(*dataset_id)?.source_reference;
                    keys.push(source.object_key);
                    if source.kind == DatasetRootKind::Volume {
                        let root = decode_volume_root(&load_immutable_object(&self.pool, source)?)?;
                        collect_volume_root_object_keys(&self.pool, &root, &mut keys)?;
                    }
                }
            }
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
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
        self.publish_metadata_with_roots(&[])
    }

    /// Publish staged catalog/properties and the supplied semantic roots as
    /// one canonical composition. All immutable roots are durable before the
    /// single Pool root makes any of them reachable.
    pub fn publish_metadata_with_roots(&mut self, updates: &[DatasetRootUpdate<'_>]) -> Result<()> {
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
        let mut encoded_updates = Vec::with_capacity(updates.len());
        for update in updates {
            validate_catalog_dataset_type(&next.catalog, update.dataset_id, update.kind)?;
            let reference = make_dataset_root_ref(
                update.dataset_id,
                update.kind,
                update.semantic_generation,
                update.bytes,
            );
            encoded_updates.push((reference, update.bytes));
            next.dataset_roots.insert(update.dataset_id, reference);
        }
        validate_catalog_root_types(&next.catalog, &next.dataset_roots)?;
        for (reference, bytes) in encoded_updates {
            self.pool
                .put(DeviceIoClass::Data, reference.object_key, bytes)?;
        }
        if !updates.is_empty() {
            self.pool.sync_all()?;
        }
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

    /// Atomically rename one cataloged dataset and every direct snapshot path.
    /// Stable dataset identities and typed semantic roots remain unchanged.
    pub fn rename_dataset(&mut self, old_path: &str, new_path: &str) -> Result<DatasetId> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before dataset rename",
            ));
        }
        let dataset_id = self.root.catalog.lookup(old_path)?;
        let mut next = self.root.clone();
        next.catalog.rename(old_path, new_path)?;
        next.generation = next_generation(next.generation)?;
        self.publish_root(next)?;
        Ok(dataset_id)
    }

    /// Commit new exact geometry for one named volume.
    ///
    /// Shrink rewrites the sparse map before the new volume root becomes
    /// reachable. Every chunk beyond the new end is removed, and bytes after
    /// a partial final chunk are zeroed so a later grow cannot expose the
    /// discarded tail. Grow changes only committed geometry; newly admitted
    /// sparse ranges therefore read as zeroes.
    pub fn resize_volume(&mut self, path: &str, capacity_bytes: u64) -> Result<VolumeResizeResult> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before volume resize",
            ));
        }

        let geometry = VolumeGeometry::new(capacity_bytes)?;
        let volume = self.open_volume(path)?;
        if geometry.capacity_bytes == volume.root.geometry.capacity_bytes {
            return Err(PoolRuntimeError::InvalidVolume(
                "requested capacity already matches committed capacity",
            ));
        }

        let generation = next_generation(volume.root.generation)?;
        let resize_generation = next_generation(volume.root.resize_generation)?;
        let mut map_root = volume.root.map_root;
        if geometry.capacity_bytes < volume.root.geometry.capacity_bytes {
            let retained_chunk_count = geometry.capacity_bytes.div_ceil(VOLUME_CHUNK_SIZE as u64);
            map_root = truncate_volume_map(
                &mut self.pool,
                volume.dataset_id,
                map_root,
                VOLUME_MAP_ROOT_LEVEL,
                0,
                retained_chunk_count,
            )?;

            let tail_bytes = usize::try_from(geometry.capacity_bytes % VOLUME_CHUNK_SIZE as u64)
                .map_err(|_| PoolRuntimeError::Bounds)?;
            if tail_bytes != 0 {
                let final_chunk_index = retained_chunk_count
                    .checked_sub(1)
                    .ok_or(PoolRuntimeError::Bounds)?;
                let truncated_root = VolumeRoot {
                    map_root,
                    ..volume.root.clone()
                };
                if let Some(mut bytes) = load_volume_chunk(
                    &self.pool,
                    volume.dataset_id,
                    &truncated_root,
                    final_chunk_index,
                )? {
                    bytes[tail_bytes..].fill(0);
                    let replacement = if bytes.iter().all(|byte| *byte == 0) {
                        None
                    } else {
                        let digest = *blake3::hash(&bytes).as_bytes();
                        let reference = ImmutableObjectRef {
                            object_key: volume_chunk_key(
                                volume.dataset_id,
                                final_chunk_index,
                                generation,
                                digest,
                            ),
                            digest,
                        };
                        self.pool
                            .put(DeviceIoClass::Data, reference.object_key, &bytes)?;
                        Some(reference)
                    };
                    map_root = update_volume_map(
                        &mut self.pool,
                        volume.dataset_id,
                        map_root,
                        VOLUME_MAP_ROOT_LEVEL,
                        final_chunk_index,
                        replacement,
                    )?;
                }
            }
        }

        let next_root = VolumeRoot {
            geometry,
            generation,
            resize_generation,
            snapshot_generation: volume.root.snapshot_generation,
            map_root,
        };
        self.publish_dataset_root(
            volume.dataset_id,
            DatasetRootKind::Volume,
            next_root.generation,
            &encode_volume_root(&next_root),
        )?;
        Ok(VolumeResizeResult {
            geometry,
            generation,
            resize_generation,
        })
    }

    /// Atomically capture one committed volume root as a read-only snapshot.
    ///
    /// The exact current volume-root reference is embedded in the snapshot
    /// root. Both immutable roots become durable before one canonical Pool
    /// root publishes the snapshot catalog entry and the source volume's
    /// monotonic snapshot-generation successor.
    pub fn create_volume_snapshot(&mut self, path: &str) -> Result<VolumeSnapshotSummary> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before volume snapshot creation",
            ));
        }
        let source_path = volume_snapshot_source_path(path)?;
        let volume = self.open_volume(source_path)?;
        let snapshot_id = volume_snapshot_dataset_id(path, volume.dataset_id);
        if self.root.catalog.contains(path) {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot target already exists",
            ));
        }
        if self.root.catalog.get_by_id(&snapshot_id).is_some() {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "derived snapshot identity collides with an existing dataset",
            ));
        }

        let snapshot_generation = next_generation(volume.root.snapshot_generation)?;
        let volume_generation = next_generation(volume.root.generation)?;
        let snapshot_root = SnapshotRoot {
            snapshot_generation,
            source_reference: volume.committed_reference,
        };
        let next_volume_root = VolumeRoot {
            generation: volume_generation,
            snapshot_generation,
            ..volume.root.clone()
        };
        let snapshot_bytes = snapshot_root.encode();
        let volume_bytes = encode_volume_root(&next_volume_root);
        let snapshot_reference = make_dataset_root_ref(
            snapshot_id,
            DatasetRootKind::Snapshot,
            snapshot_generation,
            &snapshot_bytes,
        );
        let volume_reference = make_dataset_root_ref(
            volume.dataset_id,
            DatasetRootKind::Volume,
            volume_generation,
            &volume_bytes,
        );

        let mut next = self.root.clone();
        let pool_generation = next_generation(next.generation)?;
        next.catalog.create(
            path,
            snapshot_id,
            DatasetType::Snapshot,
            pool_generation,
            Vec::new(),
            DatasetFlags::READONLY.union(DatasetFlags::CHECKSUMS),
            self.root.catalog.sync_guarantee(source_path)?,
        )?;
        next.dataset_roots.insert(snapshot_id, snapshot_reference);
        next.dataset_roots
            .insert(volume.dataset_id, volume_reference);
        next.generation = pool_generation;

        self.pool.put(
            DeviceIoClass::Data,
            snapshot_reference.object_key,
            &snapshot_bytes,
        )?;
        self.pool.put(
            DeviceIoClass::Data,
            volume_reference.object_key,
            &volume_bytes,
        )?;
        self.pool.sync_all()?;
        self.publish_root(next)?;

        Ok(volume_snapshot_summary(
            path,
            snapshot_id,
            source_path,
            &snapshot_root,
            &volume.root,
        ))
    }

    /// List checksum-validated Pool volume snapshots in catalog order.
    ///
    /// Filesystem snapshot roots use their existing filesystem encoding and
    /// are deliberately left to that engine during this migration slice.
    pub fn list_volume_snapshots(&self) -> Result<Vec<VolumeSnapshotSummary>> {
        let mut snapshots = Vec::new();
        for (path, snapshot_id, dataset_type, _, flags, _) in self.root.catalog.list_all() {
            if dataset_type != DatasetType::Snapshot {
                continue;
            }
            if !flags.contains(DatasetFlags::READONLY) || !flags.contains(DatasetFlags::CHECKSUMS) {
                continue;
            }
            let reference = *self
                .root
                .dataset_roots
                .get(&snapshot_id)
                .ok_or(PoolRuntimeError::MissingRoot(snapshot_id))?;
            let snapshot_root = self.load_snapshot_root(snapshot_id)?;
            if snapshot_root.source_reference.kind != DatasetRootKind::Volume {
                continue;
            }
            let (source_path, source_root) =
                self.validate_volume_snapshot(&path, reference, &snapshot_root)?;
            snapshots.push(volume_snapshot_summary(
                &path,
                snapshot_id,
                &source_path,
                &snapshot_root,
                &source_root,
            ));
        }
        Ok(snapshots)
    }

    /// Restore a volume from its exact captured root while retaining the
    /// snapshot as an independently reachable read-only object.
    pub fn restore_volume_snapshot(&mut self, path: &str) -> Result<VolumeSnapshotRestoreResult> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before volume snapshot restore",
            ));
        }
        let (snapshot_id, snapshot_reference, snapshot_root) = self.open_volume_snapshot(path)?;
        let (source_path, captured_root) =
            self.validate_volume_snapshot(path, snapshot_reference, &snapshot_root)?;
        let current = self.open_volume(&source_path)?;
        if current.root.geometry == captured_root.geometry
            && current.root.map_root == captured_root.map_root
        {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "restore target already matches the captured volume state",
            ));
        }

        let generation = next_generation(current.root.generation.max(captured_root.generation))?;
        let resize_generation = next_generation(
            current
                .root
                .resize_generation
                .max(captured_root.resize_generation),
        )?;
        let snapshot_generation = current
            .root
            .snapshot_generation
            .max(snapshot_root.snapshot_generation);
        let restored_root = VolumeRoot {
            geometry: captured_root.geometry,
            generation,
            resize_generation,
            snapshot_generation,
            map_root: captured_root.map_root,
        };
        self.publish_dataset_root(
            current.dataset_id,
            DatasetRootKind::Volume,
            restored_root.generation,
            &encode_volume_root(&restored_root),
        )?;

        Ok(VolumeSnapshotRestoreResult {
            snapshot: volume_snapshot_summary(
                path,
                snapshot_id,
                &source_path,
                &snapshot_root,
                &captured_root,
            ),
            geometry: restored_root.geometry,
            generation,
            resize_generation,
            snapshot_generation,
        })
    }

    /// Atomically remove a volume snapshot's catalog entry and typed root.
    /// Unreachable immutable objects remain pending separate physical reclaim.
    pub fn destroy_volume_snapshot(&mut self, path: &str) -> Result<VolumeSnapshotSummary> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before volume snapshot destroy",
            ));
        }
        let (snapshot_id, snapshot_reference, snapshot_root) = self.open_volume_snapshot(path)?;
        let (source_path, source_root) =
            self.validate_volume_snapshot(path, snapshot_reference, &snapshot_root)?;
        let summary = volume_snapshot_summary(
            path,
            snapshot_id,
            &source_path,
            &snapshot_root,
            &source_root,
        );

        let mut next = self.root.clone();
        next.catalog.destroy(path)?;
        next.dataset_roots.remove(&snapshot_id);
        next.generation = next_generation(next.generation)?;
        self.publish_root(next)?;
        Ok(summary)
    }

    /// Atomically remove one volume's catalog entry and typed root.
    ///
    /// Immutable objects made unreachable by this transition are left for
    /// the separate physical-reclaim authority.
    pub fn destroy_volume(&mut self, path: &str) -> Result<DatasetId> {
        self.ensure_publishable()?;
        if self.pending_metadata.is_some() {
            return Err(PoolRuntimeError::CorruptRoot(
                "pending metadata must publish before volume destroy",
            ));
        }
        let volume = self.open_volume(path)?;
        if self
            .list_volume_snapshots()?
            .iter()
            .any(|snapshot| snapshot.source_dataset_id == volume.dataset_id)
        {
            return Err(PoolRuntimeError::InvalidVolume(
                "volume has snapshots; destroy them before destroying the volume",
            ));
        }
        let mut next = self.root.clone();
        next.catalog.destroy(path)?;
        next.dataset_roots.remove(&volume.dataset_id);
        next.generation = next_generation(next.generation)?;
        self.publish_root(next)?;
        Ok(volume.dataset_id)
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

    fn open_volume_snapshot(
        &self,
        path: &str,
    ) -> Result<(DatasetId, DatasetRootRef, SnapshotRoot)> {
        let snapshot_id = self.root.catalog.snapshot_lookup(path)?;
        let reference = *self
            .root
            .dataset_roots
            .get(&snapshot_id)
            .ok_or(PoolRuntimeError::MissingRoot(snapshot_id))?;
        if reference.kind != DatasetRootKind::Snapshot {
            return Err(PoolRuntimeError::WrongRootType {
                dataset_id: snapshot_id,
                expected: DatasetRootKind::Snapshot,
                actual: reference.kind,
            });
        }
        let root = self.load_snapshot_root(snapshot_id)?;
        if root.source_reference.kind != DatasetRootKind::Volume {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot is not a Pool volume snapshot",
            ));
        }
        Ok((snapshot_id, reference, root))
    }

    fn validate_volume_snapshot(
        &self,
        path: &str,
        snapshot_reference: DatasetRootRef,
        root: &SnapshotRoot,
    ) -> Result<(String, VolumeRoot)> {
        if snapshot_reference.kind != DatasetRootKind::Snapshot
            || root.source_reference.kind != DatasetRootKind::Volume
        {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "volume snapshot has the wrong source or target root type",
            ));
        }
        if root.snapshot_generation == 0
            || root.snapshot_generation != snapshot_reference.semantic_generation
        {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "volume snapshot generation is invalid",
            ));
        }
        let source_path = volume_snapshot_source_path(path)?.to_string();
        let source_id = self.root.catalog.lookup(&source_path)?;
        if source_id != root.source_reference.dataset_id {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source identity does not match its target path",
            ));
        }
        let (_, _, source_type, _, _, _) =
            self.root
                .catalog
                .get_by_id(&source_id)
                .ok_or(PoolRuntimeError::InvalidSnapshot(
                    "snapshot source is missing from the catalog",
                ))?;
        if source_type != DatasetType::Volume {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source is not a volume",
            ));
        }
        let source_root =
            decode_volume_root(&load_immutable_object(&self.pool, root.source_reference)?)?;
        if source_root.generation != root.source_reference.semantic_generation {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "captured volume generation differs from its exact root reference",
            ));
        }
        Ok((source_path, source_root))
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
            return Err(PoolRuntimeError::PublicationOutcomeUncertain(error));
        }
        if let Err(error) = self.pool.sync_all() {
            self.publication_requires_reopen = true;
            return Err(PoolRuntimeError::PublicationOutcomeUncertain(error));
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

    fn validate_snapshot_roots(&self) -> Result<()> {
        for (path, snapshot_id, dataset_type, _, _, _) in self.root.catalog.list_all() {
            if dataset_type != DatasetType::Snapshot {
                continue;
            }
            let snapshot = self.load_snapshot_root(snapshot_id)?;
            let source_path = snapshot_source_path(&path)?;
            let source_id = self.root.catalog.lookup(source_path)?;
            if source_id != snapshot.source_reference.dataset_id {
                return Err(PoolRuntimeError::InvalidSnapshot(
                    "snapshot source identity does not match its target path",
                ));
            }
            let (_, _, source_type, _, _, _) = self.root.catalog.get_by_id(&source_id).ok_or(
                PoolRuntimeError::InvalidSnapshot("snapshot source is missing from the catalog"),
            )?;
            if DatasetRootKind::from_dataset_type(source_type) != snapshot.source_reference.kind {
                return Err(PoolRuntimeError::InvalidSnapshot(
                    "snapshot source type differs from its exact root reference",
                ));
            }
            let _ = load_immutable_object(&self.pool, snapshot.source_reference)?;
        }
        Ok(())
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

/// Committed result of a named-volume resize.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeResizeResult {
    pub geometry: VolumeGeometry,
    pub generation: u64,
    pub resize_generation: u64,
}

/// Operator-visible identity and captured state of one Pool volume snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeSnapshotSummary {
    pub path: String,
    pub snapshot_id: DatasetId,
    pub source_path: String,
    pub source_dataset_id: DatasetId,
    pub source_kind: DatasetRootKind,
    pub source_generation: u64,
    pub snapshot_generation: u64,
    pub geometry: VolumeGeometry,
}

/// Committed result of restoring a Pool volume snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeSnapshotRestoreResult {
    pub snapshot: VolumeSnapshotSummary,
    pub geometry: VolumeGeometry,
    pub generation: u64,
    pub resize_generation: u64,
    pub snapshot_generation: u64,
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
            logical_sector_size: DEFAULT_VOLUME_BLOCK_SIZE,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct VolumeRoot {
    geometry: VolumeGeometry,
    generation: u64,
    resize_generation: u64,
    snapshot_generation: u64,
    map_root: Option<ImmutableObjectRef>,
}

/// Canonical cross-mode snapshot object selected by a typed Pool root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotRoot {
    pub snapshot_generation: u64,
    pub source_reference: DatasetRootRef,
}

impl SnapshotRoot {
    pub fn new(snapshot_generation: u64, source_reference: DatasetRootRef) -> Result<Self> {
        if snapshot_generation == 0 || source_reference.semantic_generation == 0 {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot or source generation is zero",
            ));
        }
        if source_reference.kind == DatasetRootKind::Snapshot {
            return Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source root cannot itself be a snapshot",
            ));
        }
        Ok(Self {
            snapshot_generation,
            source_reference,
        })
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        encode_snapshot_root(&self)
    }
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

fn snapshot_source_path(path: &str) -> Result<&str> {
    let Some((source, snapshot)) = path.rsplit_once('@') else {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "target must use <dataset>@<snapshot> form",
        ));
    };
    if source.is_empty() || snapshot.is_empty() || source.contains('@') {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "target must name one source dataset and one snapshot",
        ));
    }
    Ok(source)
}

fn volume_snapshot_source_path(path: &str) -> Result<&str> {
    snapshot_source_path(path)
}

fn volume_snapshot_dataset_id(path: &str, source_id: DatasetId) -> DatasetId {
    let mut identity = Vec::with_capacity(path.len().saturating_add(48));
    identity.extend_from_slice(b"tidefs:volume-snapshot-id:v1\0");
    identity.extend_from_slice(source_id.as_bytes());
    identity.extend_from_slice(path.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blake3::hash(&identity).as_bytes()[..16]);
    DatasetId::from_bytes(bytes)
}

fn volume_snapshot_summary(
    path: &str,
    snapshot_id: DatasetId,
    source_path: &str,
    snapshot_root: &SnapshotRoot,
    source_root: &VolumeRoot,
) -> VolumeSnapshotSummary {
    VolumeSnapshotSummary {
        path: path.to_string(),
        snapshot_id,
        source_path: source_path.to_string(),
        source_dataset_id: snapshot_root.source_reference.dataset_id,
        source_kind: snapshot_root.source_reference.kind,
        source_generation: source_root.generation,
        snapshot_generation: snapshot_root.snapshot_generation,
        geometry: source_root.geometry,
    }
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

fn collect_volume_root_object_keys(
    pool: &Pool,
    root: &VolumeRoot,
    keys: &mut Vec<ObjectKey>,
) -> Result<()> {
    let Some(reference) = root.map_root else {
        return Ok(());
    };
    collect_volume_map_object_keys(pool, reference, VOLUME_MAP_ROOT_LEVEL, keys)
}

fn collect_volume_map_object_keys(
    pool: &Pool,
    reference: ImmutableObjectRef,
    expected_level: u8,
    keys: &mut Vec<ObjectKey>,
) -> Result<()> {
    keys.push(reference.object_key);
    let node = load_volume_map_node(
        pool,
        DatasetId::from_bytes([0_u8; 16]),
        reference,
        expected_level,
    )?;
    for child in node.children.values().copied() {
        if expected_level == 0 {
            let bytes = load_immutable_ref(pool, child)?;
            if bytes.len() != VOLUME_CHUNK_SIZE {
                return Err(PoolRuntimeError::InvalidVolume(
                    "volume chunk has the wrong length",
                ));
            }
            keys.push(child.object_key);
        } else {
            collect_volume_map_object_keys(pool, child, expected_level - 1, keys)?;
        }
    }
    Ok(())
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

fn truncate_volume_map(
    pool: &mut Pool,
    id: DatasetId,
    current: Option<ImmutableObjectRef>,
    level: u8,
    prefix: u64,
    retained_chunk_count: u64,
) -> Result<Option<ImmutableObjectRef>> {
    let Some(reference) = current else {
        return Ok(None);
    };
    let mut node = load_volume_map_node(pool, id, reference, level)?;
    let shift = u32::from(level) * 8;
    let mut retained = BTreeMap::new();
    for (digit, child) in node.children {
        let child_prefix = prefix | (u64::from(digit) << shift);
        if level == 0 {
            if child_prefix < retained_chunk_count {
                retained.insert(digit, child);
            }
            continue;
        }

        let subtree_span = 1_u64 << shift;
        if child_prefix >= retained_chunk_count {
            continue;
        }
        let child_end = child_prefix
            .checked_add(subtree_span)
            .ok_or(PoolRuntimeError::Bounds)?;
        if child_end <= retained_chunk_count {
            retained.insert(digit, child);
            continue;
        }
        if let Some(rewritten) = truncate_volume_map(
            pool,
            id,
            Some(child),
            level - 1,
            child_prefix,
            retained_chunk_count,
        )? {
            retained.insert(digit, rewritten);
        }
    }
    node.children = retained;
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

fn encode_snapshot_root(root: &SnapshotRoot) -> Vec<u8> {
    let source = root.source_reference;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SNAPSHOT_ROOT_MAGIC);
    bytes.extend_from_slice(&SNAPSHOT_ROOT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&root.snapshot_generation.to_le_bytes());
    bytes.extend_from_slice(source.dataset_id.as_bytes());
    bytes.push(source.kind as u8);
    bytes.extend_from_slice(&source.semantic_generation.to_le_bytes());
    bytes.extend_from_slice(source.object_key.as_bytes());
    bytes.extend_from_slice(&source.digest);
    let digest = blake3::hash(&bytes);
    bytes.extend_from_slice(digest.as_bytes());
    bytes
}

fn decode_snapshot_root(bytes: &[u8]) -> Result<SnapshotRoot> {
    const PAYLOAD_LEN: usize = 8 + 2 + 8 + 16 + 1 + 8 + 32 + 32;
    if bytes.len() != PAYLOAD_LEN + CHECKSUM_LEN || &bytes[..8] != SNAPSHOT_ROOT_MAGIC {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "bad snapshot-root header",
        ));
    }
    if blake3::hash(&bytes[..PAYLOAD_LEN]).as_bytes() != &bytes[PAYLOAD_LEN..] {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "snapshot-root checksum mismatch",
        ));
    }
    let mut offset = 8;
    if take_u16(bytes, &mut offset)? != SNAPSHOT_ROOT_VERSION {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "unsupported snapshot-root version",
        ));
    }
    let snapshot_generation = take_u64(bytes, &mut offset)?;
    let dataset_id = DatasetId::from_bytes(take_array::<16>(bytes, &mut offset)?);
    let kind = DatasetRootKind::decode(take_u8(bytes, &mut offset)?)?;
    let semantic_generation = take_u64(bytes, &mut offset)?;
    let object_key = ObjectKey::from_bytes32(take_array::<32>(bytes, &mut offset)?);
    let digest = take_array::<32>(bytes, &mut offset)?;
    if kind == DatasetRootKind::Snapshot {
        return Err(PoolRuntimeError::InvalidSnapshot(
            "snapshot source root cannot itself be a snapshot",
        ));
    }
    SnapshotRoot::new(
        snapshot_generation,
        DatasetRootRef {
            dataset_id,
            kind,
            object_key,
            digest,
            semantic_generation,
        },
    )
}

fn validate_volume_geometry(geometry: VolumeGeometry) -> Result<()> {
    if geometry.capacity_bytes == 0
        || geometry.block_size_bytes != DEFAULT_VOLUME_BLOCK_SIZE
        || geometry.capacity_bytes % u64::from(geometry.block_size_bytes) != 0
        || geometry.logical_sector_size != geometry.block_size_bytes
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
    fn volume_resize_shrink_regrow_preserves_prefix_and_zeroes_removed_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 8);
        let mut volume = owner.open_volume("vol").unwrap();
        let blocks_per_chunk = VOLUME_CHUNK_SIZE / 4096;
        volume.write_blocks(&owner, 0, &vec![0x11; 4096]).unwrap();
        volume
            .write_blocks(&owner, blocks_per_chunk as u64 + 4, &vec![0x22; 4096])
            .unwrap();
        volume
            .write_blocks(&owner, 2 * blocks_per_chunk as u64, &vec![0x33; 4096])
            .unwrap();
        volume.flush(&mut owner).unwrap();

        let shrink_bytes = VOLUME_CHUNK_SIZE as u64 + 4096;
        let result = owner.resize_volume("vol", shrink_bytes).unwrap();
        assert_eq!(result.geometry.capacity_bytes, shrink_bytes);
        assert_eq!(result.resize_generation, 2);

        let owner = reopen(owner);
        let volume = owner.open_volume("vol").unwrap();
        assert_eq!(volume.geometry().capacity_bytes, shrink_bytes);
        assert_eq!(volume.read_blocks(&owner, 0, 1).unwrap(), vec![0x11; 4096]);
        assert!(matches!(
            volume.read_blocks(&owner, blocks_per_chunk as u64 + 1, 1),
            Err(PoolRuntimeError::Bounds)
        ));

        let mut owner = owner;
        let result = owner.resize_volume("vol", 4 * 1024 * 1024).unwrap();
        assert_eq!(result.resize_generation, 3);
        let owner = reopen(owner);
        let volume = owner.open_volume("vol").unwrap();
        assert_eq!(volume.read_blocks(&owner, 0, 1).unwrap(), vec![0x11; 4096]);
        assert_eq!(
            volume
                .read_blocks(&owner, blocks_per_chunk as u64 + 4, 1)
                .unwrap(),
            vec![0; 4096]
        );
        assert_eq!(
            volume
                .read_blocks(&owner, 2 * blocks_per_chunk as u64, 1)
                .unwrap(),
            vec![0; 4096]
        );
    }

    #[test]
    fn volume_resize_refuses_noop_invalid_and_non_volume_targets() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 9);
        assert!(matches!(
            owner.resize_volume("vol", 4 * 1024 * 1024),
            Err(PoolRuntimeError::InvalidVolume(
                "requested capacity already matches committed capacity"
            ))
        ));
        assert!(matches!(
            owner.resize_volume("vol", 1),
            Err(PoolRuntimeError::InvalidVolume(
                "capacity must be aligned to 4096 bytes"
            ))
        ));
        owner
            .create_dataset_with_root(
                "filesystem",
                DatasetId::from_bytes([10; 16]),
                DatasetType::Filesystem,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
                1,
                b"filesystem-root",
            )
            .unwrap();
        let non_volume = owner.resize_volume("filesystem", 8 * 1024 * 1024);
        assert!(
            matches!(
                non_volume,
                Err(PoolRuntimeError::WrongRootType {
                    expected: DatasetRootKind::Volume,
                    actual: DatasetRootKind::Filesystem,
                    ..
                })
            ),
            "unexpected non-volume resize result: {non_volume:?}"
        );
    }

    #[test]
    fn volume_destroy_removes_catalog_and_typed_root_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let id = create_volume(&mut owner, "vol", 10);

        assert_eq!(owner.destroy_volume("vol").unwrap(), id);
        assert!(owner.dataset_catalog().lookup("vol").is_err());
        assert!(owner.dataset_root(id).is_none());

        let owner = reopen(owner);
        assert!(owner.dataset_catalog().lookup("vol").is_err());
        assert!(owner.dataset_root(id).is_none());
        assert!(owner.open_volume("vol").is_err());
    }

    #[test]
    fn volume_snapshot_restore_reopens_exact_bytes_geometry_and_keeps_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let volume_id = create_volume(&mut owner, "vol", 11);
        let mut volume = owner.open_volume("vol").unwrap();
        volume.write_blocks(&owner, 0, &vec![0x11; 4096]).unwrap();
        volume.flush(&mut owner).unwrap();

        let created = owner.create_volume_snapshot("vol@before").unwrap();
        assert_eq!(created.source_dataset_id, volume_id);
        assert_eq!(created.source_kind, DatasetRootKind::Volume);
        assert_eq!(created.snapshot_generation, 1);
        assert_eq!(created.geometry.capacity_bytes, 4 * 1024 * 1024);

        let mut owner = reopen(owner);
        assert_eq!(
            owner.list_volume_snapshots().unwrap(),
            vec![created.clone()]
        );
        owner.resize_volume("vol", 8 * 1024 * 1024).unwrap();
        let mut volume = owner.open_volume("vol").unwrap();
        volume.write_blocks(&owner, 0, &vec![0x22; 4096]).unwrap();
        volume
            .write_blocks(&owner, 1024, &vec![0x33; 4096])
            .unwrap();
        volume.flush(&mut owner).unwrap();

        let restored = owner.restore_volume_snapshot("vol@before").unwrap();
        assert_eq!(restored.geometry, created.geometry);
        assert!(restored.generation > created.source_generation);
        assert!(restored.resize_generation > 2);
        assert_eq!(restored.snapshot_generation, created.snapshot_generation);
        assert_eq!(
            owner.list_volume_snapshots().unwrap(),
            vec![created.clone()]
        );

        let owner = reopen(owner);
        let volume = owner.open_volume("vol").unwrap();
        assert_eq!(volume.geometry(), created.geometry);
        assert_eq!(volume.read_blocks(&owner, 0, 1).unwrap(), vec![0x11; 4096]);
        assert_eq!(
            owner.list_volume_snapshots().unwrap(),
            vec![created.clone()]
        );

        let mut owner = owner;
        assert_eq!(
            owner.destroy_volume_snapshot("vol@before").unwrap(),
            created
        );
        let mut owner = reopen(owner);
        assert!(owner.list_volume_snapshots().unwrap().is_empty());
        assert!(matches!(
            owner.restore_volume_snapshot("vol@before"),
            Err(PoolRuntimeError::Catalog(CatalogError::NotFound))
        ));
    }

    #[test]
    fn canonical_retention_keeps_current_and_snapshotted_volume_graphs() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 44);
        let snapshot_bytes = vec![0x44; 4096];
        let current_bytes = vec![0x55; 4096];

        let mut volume = owner.open_volume("vol").unwrap();
        volume.write_blocks(&owner, 0, &snapshot_bytes).unwrap();
        volume.flush(&mut owner).unwrap();
        owner.create_volume_snapshot("vol@before").unwrap();
        let mut volume = owner.open_volume("vol").unwrap();
        volume.write_blocks(&owner, 0, &current_bytes).unwrap();
        volume.flush(&mut owner).unwrap();

        let protected = owner.canonical_root_object_keys().unwrap();
        owner.pool_mut().compact_retaining(&protected, &[]).unwrap();
        assert_eq!(
            owner
                .open_volume("vol")
                .unwrap()
                .read_blocks(&owner, 0, 1)
                .unwrap(),
            current_bytes
        );

        owner.restore_volume_snapshot("vol@before").unwrap();
        assert_eq!(
            owner
                .open_volume("vol")
                .unwrap()
                .read_blocks(&owner, 0, 1)
                .unwrap(),
            snapshot_bytes
        );
    }

    #[test]
    fn volume_snapshot_generation_is_monotonic_and_volume_destroy_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 12);
        let first = owner.create_volume_snapshot("vol@first").unwrap();
        let second = owner.create_volume_snapshot("vol@second").unwrap();
        assert_eq!(first.snapshot_generation, 1);
        assert_eq!(second.snapshot_generation, 2);
        assert!(second.source_generation > first.source_generation);
        assert!(matches!(
            owner.destroy_volume("vol"),
            Err(PoolRuntimeError::InvalidVolume(
                "volume has snapshots; destroy them before destroying the volume"
            ))
        ));

        let owner = reopen(owner);
        assert_eq!(
            owner
                .list_volume_snapshots()
                .unwrap()
                .into_iter()
                .map(|snapshot| snapshot.path)
                .collect::<Vec<_>>(),
            vec!["vol@first", "vol@second"]
        );
    }

    #[test]
    fn volume_snapshot_refuses_invalid_targets_types_noop_and_reopen_fence() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "vol", 13);
        assert!(matches!(
            owner.create_volume_snapshot("vol"),
            Err(PoolRuntimeError::InvalidSnapshot(
                "target must use <dataset>@<snapshot> form"
            ))
        ));
        assert!(matches!(
            owner.create_volume_snapshot("vol@snap@nested"),
            Err(PoolRuntimeError::InvalidSnapshot(
                "target must name one source dataset and one snapshot"
            ))
        ));
        owner
            .create_dataset_with_root(
                "filesystem",
                DatasetId::from_bytes([14; 16]),
                DatasetType::Filesystem,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
                1,
                b"filesystem-root",
            )
            .unwrap();
        assert!(matches!(
            owner.create_volume_snapshot("filesystem@snap"),
            Err(PoolRuntimeError::WrongRootType {
                expected: DatasetRootKind::Volume,
                actual: DatasetRootKind::Filesystem,
                ..
            })
        ));

        owner.create_volume_snapshot("vol@snap").unwrap();
        assert!(matches!(
            owner.restore_volume_snapshot("vol@snap"),
            Err(PoolRuntimeError::InvalidSnapshot(
                "restore target already matches the captured volume state"
            ))
        ));
        owner.publication_requires_reopen = true;
        assert!(matches!(
            owner.create_volume_snapshot("vol@fenced"),
            Err(PoolRuntimeError::PublicationRequiresReopen)
        ));
        assert!(matches!(
            owner.restore_volume_snapshot("vol@snap"),
            Err(PoolRuntimeError::PublicationRequiresReopen)
        ));
        assert!(matches!(
            owner.destroy_volume_snapshot("vol@snap"),
            Err(PoolRuntimeError::PublicationRequiresReopen)
        ));
    }

    #[test]
    fn volume_snapshot_root_checksum_and_source_type_are_validated() {
        let root = SnapshotRoot {
            snapshot_generation: 1,
            source_reference: DatasetRootRef {
                dataset_id: DatasetId::from_bytes([15; 16]),
                kind: DatasetRootKind::Volume,
                object_key: ObjectKey::from_bytes32([16; 32]),
                digest: [17; 32],
                semantic_generation: 2,
            },
        };
        let mut bytes = root.encode();
        bytes[18] ^= 0x80;
        assert!(matches!(
            decode_snapshot_root(&bytes),
            Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot-root checksum mismatch"
            ))
        ));

        let mut bytes = root.encode();
        let kind_offset = 8 + 2 + 8 + 16;
        bytes[kind_offset] = DatasetRootKind::Snapshot as u8;
        let payload_len = bytes.len() - CHECKSUM_LEN;
        let digest = blake3::hash(&bytes[..payload_len]);
        bytes[payload_len..].copy_from_slice(digest.as_bytes());
        assert!(matches!(
            decode_snapshot_root(&bytes),
            Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source root cannot itself be a snapshot"
            ))
        ));
    }

    #[test]
    fn generic_snapshot_root_accepts_filesystem_and_volume_sources() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let filesystem_id = DatasetId::from_bytes([31; 16]);
        owner
            .create_dataset_with_root(
                "filesystem",
                filesystem_id,
                DatasetType::Filesystem,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
                1,
                b"filesystem-root",
            )
            .unwrap();
        let filesystem_reference = *owner.dataset_root(filesystem_id).unwrap();
        let filesystem_snapshot_id = DatasetId::from_bytes([32; 16]);
        let filesystem_snapshot = SnapshotRoot::new(2, filesystem_reference).unwrap();
        owner
            .create_dataset_with_root(
                "filesystem@before",
                filesystem_snapshot_id,
                DatasetType::Snapshot,
                Vec::new(),
                DatasetFlags::READONLY.union(DatasetFlags::CHECKSUMS),
                SyncGuarantee::Local,
                filesystem_snapshot.snapshot_generation,
                &filesystem_snapshot.encode(),
            )
            .unwrap();

        let volume_id = create_volume(&mut owner, "volume", 33);
        let volume_reference = *owner.dataset_root(volume_id).unwrap();
        let volume_snapshot_id = DatasetId::from_bytes([34; 16]);
        let volume_snapshot = SnapshotRoot::new(3, volume_reference).unwrap();
        owner
            .create_dataset_with_root(
                "volume@before",
                volume_snapshot_id,
                DatasetType::Snapshot,
                Vec::new(),
                DatasetFlags::READONLY.union(DatasetFlags::CHECKSUMS),
                SyncGuarantee::Local,
                volume_snapshot.snapshot_generation,
                &volume_snapshot.encode(),
            )
            .unwrap();

        let owner = reopen(owner);
        assert_eq!(
            owner.load_snapshot_root(filesystem_snapshot_id).unwrap(),
            filesystem_snapshot
        );
        assert_eq!(
            owner.load_snapshot_root(volume_snapshot_id).unwrap(),
            volume_snapshot
        );
    }

    #[test]
    fn generic_snapshot_root_refuses_snapshot_sources() {
        let source = DatasetRootRef {
            dataset_id: DatasetId::from_bytes([35; 16]),
            kind: DatasetRootKind::Snapshot,
            object_key: ObjectKey::from_bytes32([36; 32]),
            digest: [37; 32],
            semantic_generation: 1,
        };
        assert!(matches!(
            SnapshotRoot::new(2, source),
            Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source root cannot itself be a snapshot"
            ))
        ));
    }

    #[test]
    fn generic_snapshot_reopen_refuses_corruption_and_source_mismatch() {
        let corrupt_dir = tempfile::tempdir().unwrap();
        let mut corrupt = runtime(corrupt_dir.path());
        let corrupt_volume_id = create_volume(&mut corrupt, "volume", 38);
        corrupt.create_volume_snapshot("volume@before").unwrap();
        let corrupt_snapshot_id = corrupt.dataset_catalog().lookup("volume@before").unwrap();
        let corrupt_reference = *corrupt.dataset_root(corrupt_snapshot_id).unwrap();
        corrupt
            .pool_mut()
            .put(
                DeviceIoClass::Data,
                corrupt_reference.object_key,
                b"corrupt snapshot root",
            )
            .unwrap();
        corrupt.pool_mut().sync_all().unwrap();
        let corrupt_config = corrupt.pool().config().clone();
        drop(corrupt);
        let corrupt_pool = Pool::open(
            corrupt_config,
            PoolProperties::default(),
            &StoreOptions::default(),
        )
        .unwrap();
        assert!(PoolRuntime::open(corrupt_pool).is_err());

        let mismatch_dir = tempfile::tempdir().unwrap();
        let mut mismatch = runtime(mismatch_dir.path());
        let source_id = DatasetId::from_bytes([39; 16]);
        mismatch
            .create_dataset_with_root(
                "filesystem",
                source_id,
                DatasetType::Filesystem,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
                1,
                b"filesystem-root",
            )
            .unwrap();
        let source_reference = *mismatch.dataset_root(source_id).unwrap();
        let snapshot_id = DatasetId::from_bytes([40; 16]);
        let snapshot = SnapshotRoot::new(2, source_reference).unwrap();
        mismatch
            .create_dataset_with_root(
                "filesystem@before",
                snapshot_id,
                DatasetType::Snapshot,
                Vec::new(),
                DatasetFlags::READONLY.union(DatasetFlags::CHECKSUMS),
                SyncGuarantee::Local,
                snapshot.snapshot_generation,
                &snapshot.encode(),
            )
            .unwrap();
        let mismatched_source = DatasetRootRef {
            dataset_id: corrupt_volume_id,
            ..source_reference
        };
        let mismatched_snapshot = SnapshotRoot::new(3, mismatched_source).unwrap();
        mismatch
            .publish_dataset_root(
                snapshot_id,
                DatasetRootKind::Snapshot,
                mismatched_snapshot.snapshot_generation,
                &mismatched_snapshot.encode(),
            )
            .unwrap();
        let mismatch_config = mismatch.pool().config().clone();
        drop(mismatch);
        let mismatch_pool = Pool::open(
            mismatch_config,
            PoolProperties::default(),
            &StoreOptions::default(),
        )
        .unwrap();
        assert!(matches!(
            PoolRuntime::open(mismatch_pool),
            Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source identity does not match its target path"
            ))
        ));
    }

    #[test]
    fn volume_snapshot_catalog_flags_require_valid_volume_root_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        owner
            .create_dataset_with_root(
                "vol@bad",
                DatasetId::from_bytes([18; 16]),
                DatasetType::Snapshot,
                Vec::new(),
                DatasetFlags::READONLY.union(DatasetFlags::CHECKSUMS),
                SyncGuarantee::Local,
                1,
                b"not-a-volume-snapshot-root",
            )
            .unwrap();

        assert!(matches!(
            owner.list_volume_snapshots(),
            Err(PoolRuntimeError::InvalidSnapshot(
                "bad snapshot-root header"
            ))
        ));
    }

    #[test]
    fn volume_snapshot_wrong_source_path_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        create_volume(&mut owner, "first", 19);
        create_volume(&mut owner, "second", 20);
        owner.create_volume_snapshot("first@before").unwrap();

        let first_id = owner.root.catalog.lookup("first").unwrap();
        let snapshot_id = owner.root.catalog.lookup("first@before").unwrap();
        let snapshot_reference = *owner.root.dataset_roots.get(&snapshot_id).unwrap();
        let snapshot_root =
            decode_snapshot_root(&load_immutable_object(&owner.pool, snapshot_reference).unwrap())
                .unwrap();
        owner.root.catalog.rename("first", "renamed").unwrap();
        owner
            .root
            .catalog
            .rename("renamed@before", "second@before")
            .unwrap();
        assert_eq!(owner.root.catalog.lookup("renamed").unwrap(), first_id);

        assert!(matches!(
            owner.validate_volume_snapshot("second@before", snapshot_reference, &snapshot_root,),
            Err(PoolRuntimeError::InvalidSnapshot(
                "snapshot source identity does not match its target path"
            ))
        ));
    }

    #[test]
    fn volume_snapshot_follows_atomic_source_rename_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = runtime(dir.path());
        let volume_id = create_volume(&mut owner, "vol", 21);
        let snapshot = owner.create_volume_snapshot("vol@before").unwrap();

        assert_eq!(owner.rename_dataset("vol", "renamed").unwrap(), volume_id);

        let owner = reopen(owner);
        assert_eq!(
            owner.open_volume("renamed").unwrap().dataset_id(),
            volume_id
        );
        assert!(owner.open_volume("vol").is_err());
        assert_eq!(
            owner.list_volume_snapshots().unwrap(),
            vec![VolumeSnapshotSummary {
                path: "renamed@before".to_string(),
                source_path: "renamed".to_string(),
                ..snapshot
            }]
        );
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
        assert!(owner.dataset_catalog().lookup("missing-root").is_ok());

        owner
            .dataset_catalog_mut()
            .unwrap()
            .destroy("missing-root")
            .unwrap();
        owner.publish_metadata().unwrap();
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
