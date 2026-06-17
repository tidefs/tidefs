//! Pool-wide dataset catalog with B+tree path-to-ID mapping and online rename.
//!
//! Maps dataset paths to stable dataset IDs so file handles survive renames.
//! Built on [`tidefs_btree::BPlusTree`] for predictable O(log n) path
//! lookups. Rename is atomic at the catalog level: old entries are removed
//! and new entries inserted as a complete operation; concurrent readers see
//! either the old state or the new state, never an intermediate state.
//!
//! # Design
//!
//! The catalog stores entries keyed by full hierarchical path (e.g.
//! `"pool/dataset_a"`, `"pool/tenants/tenant_x/volumes/vol1"`). Each entry
//! records the stable `DatasetId` (UUID) and its parent path. All file
//! handles, leases, and internal references use the stable `DatasetId`, so
//! a rename never invalidates open handles.
//!
//! ## Path format
//!
//! Paths use `/` as separator with no leading slash. The pool name is the
//! first component. Paths are UTF-8 strings, 1..4096 bytes, no `\0`, no
//! consecutive `/` separators, no trailing `/`.
//!
//! ## Anti-pattern avoided
//!
//! ZFS mistake #19 — rename requires unmount. TideFS separates dataset
//! identity (stable UUID) from mount semantics so `rename_dataset` is a
//! single catalog mutation with no unmount, no open-handle disruption.
//!
//! # Authority
//!
//! This crate is the **intended canonical dataset catalog authority** for
//! TideFS. The B+tree catalog maps hierarchical paths to stable
//! [`DatasetId`] values, supports online rename without unmount, and
//! provides [`mount_lookup`] for mount/import path resolution.
//!
//! **Current gap**: The catalog is an in-memory data structure with
//! [`encode`] / [`decode`] methods but **does not yet persist through
//! the mounted pool's object store**. Pool-level persistence wiring (issue
//! #5952) is required before this catalog becomes the live product path for
//! `tidefsctl dataset`, mount/import lookup, and local-filesystem
//! dataset/snapshot lifecycle management.
//!
//! Until that wiring is complete, the mounted snapshot authority lives in
//! `tidefs_local_filesystem::state.snapshots`, and the
//! `tidefs_control_plane_runtime::dataset_api` module is pre-production
//! scaffolding with a side-store format that is **not** pool-wide catalog
//! persistence.
//!
//! Do **not** close mounted/operator dataset gates with in-memory crate
//! tests alone. Mounted validation must involve the pool-level
//! persistence path.

use core::fmt;
use blake3::Hasher;
use tidefs_binary_schema_checksum::blake3_domain_digest;
use tidefs_binary_schema_core::{DomainTag, SchemaFamilyId, SchemaTypeId, SchemaVersion};
use tidefs_btree::BPlusTree;
use tidefs_dataset_properties::PropertySet;

/// Maximum entries per B+tree leaf.
const MAX_LEAF: usize = 64;
/// Maximum children per B+tree internal node.
const MAX_INTERNAL: usize = 64;

/// Schema identity for dataset catalog on-disk encoding.
const CATALOG_SCHEMA_FAMILY: SchemaFamilyId = SchemaFamilyId::BINARY_SCHEMA;
const CATALOG_SCHEMA_TYPE: SchemaTypeId = SchemaTypeId(400);
const CATALOG_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1, 0);
const CATALOG_SCHEMA_DOMAIN: DomainTag = DomainTag::ExternalPayload;

/// Size of a BLAKE3-256 checksum in bytes.
const CHECKSUM_SIZE: usize = 32;

/// Stable dataset identifier (UUID v4, 16 bytes).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatasetId([u8; 16]);

impl DatasetId {
    /// Create a new `DatasetId` from 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Create a `DatasetId` from a UUID string.
    ///
    /// Expected format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    pub fn from_uuid_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }
        let hex_str: String = parts.concat();
        if hex_str.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Debug for DatasetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DatasetId({self})")
    }
}

impl fmt::Display for DatasetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

// ---------------------------------------------------------------------------
// DatasetType --- class of dataset
// ---------------------------------------------------------------------------

/// The kind of dataset: filesystem, block volume, or snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DatasetType {
    /// A POSIX filesystem dataset (mountable, supports files/dirs).
    Filesystem = 1,
    /// A block volume dataset (exposed via ublk/NBD).
    Volume = 2,
    /// A point-in-time snapshot of another dataset.
    Snapshot = 3,
}

impl DatasetType {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Filesystem),
            2 => Some(Self::Volume),
            3 => Some(Self::Snapshot),
            _ => None,
        }
    }
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for DatasetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem => f.write_str("filesystem"),
            Self::Volume => f.write_str("volume"),
            Self::Snapshot => f.write_str("snapshot"),
        }
    }
}

// ---------------------------------------------------------------------------
// DatasetFlags --- per-dataset creation flags (bitmask on u16)
// ---------------------------------------------------------------------------

/// Per-dataset creation flags stored as a u16 bitmask.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DatasetFlags(u16);

impl DatasetFlags {
    pub const NONE: Self = Self(0);
    pub const READONLY: Self = Self(1 << 0);
    pub const HIDDEN_SNAPDIR: Self = Self(1 << 1);
    pub const COMPRESSION: Self = Self(1 << 2);
    pub const CHECKSUMS: Self = Self(1 << 3);
    pub const SYNC_WRITES: Self = Self(1 << 4);
    pub const NO_AUTO_SNAPSHOT: Self = Self(1 << 5);
    pub const CLONE: Self = Self(1 << 6);

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    #[must_use]
    pub const fn default_create() -> Self {
        Self(Self::COMPRESSION.0 | Self::CHECKSUMS.0)
    }
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
}

// ---------------------------------------------------------------------------
// SyncGuarantee --- per-dataset write-acknowledgment durability level
// ---------------------------------------------------------------------------

/// Write-acknowledgment durability guarantee for a dataset or volume.
///
/// Controls when a write/flush/fsync is acknowledged to the caller:
/// - `Local`: acknowledged after the local node has persisted the write
///   (intent-log append + local commit).
/// - `RemoteCopy`: acknowledged after at least one remote copy is confirmed
///   by a peer node.
/// - `FullRedundancy`: acknowledged after all distributed copies and
///   redundancy (mirror replicas or erasure parity shards) are confirmed
///   across the placement set.
///
/// The default is `Local` for compatibility with single-node deployments.
/// Clustered pools should prefer `RemoteCopy` or `FullRedundancy`.
///
/// On-disk representation: single u8 discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SyncGuarantee {
    /// Local persistence only (default).
    Local = 0,
    /// At least one remote copy confirmed.
    RemoteCopy = 1,
    /// Full distributed redundancy confirmed.
    FullRedundancy = 2,
}

impl SyncGuarantee {
    /// Decode from the on-disk u8 discriminant.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Local),
            1 => Some(Self::RemoteCopy),
            2 => Some(Self::FullRedundancy),
            _ => None,
        }
    }

    /// Encode to the on-disk u8 discriminant.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Default for SyncGuarantee {
    fn default() -> Self {
        Self::Local
    }
}

impl fmt::Display for SyncGuarantee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local => f.write_str("local"),
            Self::RemoteCopy => f.write_str("remote-copy"),
            Self::FullRedundancy => f.write_str("full-redundancy"),
        }
    }
}

impl core::ops::BitOr for DatasetFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DatasetFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Detailed child listing row: `(name, id, type, creation_txg, flags)`.
pub type DatasetChildDetails = (String, DatasetId, DatasetType, u64, DatasetFlags);

// ---------------------------------------------------------------------------
// LifecycleState
// ---------------------------------------------------------------------------

/// Dataset lifecycle state.
///
/// Governs which operations are legal on a dataset.
/// Transitions: Active → Destroying → Destroyed (one-way).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LifecycleState {
    /// Normal operation — all operations allowed.
    Active = 0,
    /// Destroy has been requested; blocking new writes, waiting for children.
    Destroying = 1,
    /// Fully destroyed; only tombstone record remains for idempotent replay.
    Destroyed = 2,
}

impl LifecycleState {
    /// Convert from the on-disk u8 representation.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Active),
            1 => Some(Self::Destroying),
            2 => Some(Self::Destroyed),
            _ => None,
        }
    }

    /// Convert to the on-disk u8 representation.
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => f.write_str("active"),
            Self::Destroying => f.write_str("destroying"),
            Self::Destroyed => f.write_str("destroyed"),
        }
    }
}
// ---------------------------------------------------------------------------
// CatalogError
// ---------------------------------------------------------------------------

/// Errors returned by catalog operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The requested path does not exist in the catalog.
    NotFound,
    /// The target path already exists (e.g. rename destination).
    AlreadyExists,
    /// The path is invalid (empty, contains `\0` or `//`, too long).
    InvalidPath,
    /// The parent dataset was not found.
    ParentNotFound,
    /// The dataset has children and cannot be destroyed.
    HasChildren,
    /// The target is a descendant of the source (rename would create a cycle).
    WouldCreateCycle,
    /// The name component is invalid (empty, too long, contains `/` or `\0`).
    InvalidName,
    /// The lifecycle state transition is not allowed (e.g. Destroyed → Active).
    InvalidStateTransition,
    /// The encoded catalog data is corrupt or failed checksum verification.
    CorruptEncoding,
    /// A cycle was detected in the clone/snapshot lineage graph.
    LineageCycle,
    /// A lineage parent DatasetId does not exist in the catalog.
    LineageParentNotFound,
    /// A lineage parent belongs to a different dataset authority than expected.
    LineageWrongDataset,
    /// A duplicate lineage edge was detected (same parent referenced more than once).
    LineageDuplicateEdge,
    /// The root has not been published yet.
    NotPublished,
    /// The root has already been published.
    AlreadyPublished,
    /// The dataset type does not support lineage (e.g., standalone filesystem).
    LineageNotSupported,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogError::NotFound => f.write_str("dataset not found in catalog"),
            CatalogError::AlreadyExists => f.write_str("dataset already exists"),
            CatalogError::InvalidPath => f.write_str("invalid path"),
            CatalogError::ParentNotFound => f.write_str("parent dataset not found"),
            CatalogError::HasChildren => {
                f.write_str("dataset has children and cannot be destroyed")
            }
            CatalogError::WouldCreateCycle => f.write_str("rename would create a cycle"),
            CatalogError::InvalidName => f.write_str("invalid dataset name"),
            CatalogError::InvalidStateTransition => {
                f.write_str("invalid lifecycle state transition")
            }
            CatalogError::CorruptEncoding => {
                f.write_str("catalog encoding is corrupt or checksum mismatch")
            }
            CatalogError::LineageCycle => {
                f.write_str("clone or snapshot lineage contains a cycle")
            }
            CatalogError::LineageParentNotFound => {
                f.write_str("lineage parent dataset not found in catalog")
            }
            CatalogError::LineageWrongDataset => {
                f.write_str("lineage parent belongs to a different dataset authority")
            }
            CatalogError::LineageDuplicateEdge => {
                f.write_str("duplicate edge in clone or snapshot lineage")
            }
            CatalogError::NotPublished => {
                f.write_str("dataset root has not been published")
            }
            CatalogError::AlreadyPublished => {
                f.write_str("dataset root has already been published")
            }
            CatalogError::LineageNotSupported => {
                f.write_str("dataset type does not support lineage")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Maximum path length in bytes.
const MAX_PATH_LEN: usize = 4096;
/// Maximum name component length in bytes.
const MAX_NAME_LEN: usize = 255;

/// Validate a dataset path.
fn validate_path(path: &str) -> Result<(), CatalogError> {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return Err(CatalogError::InvalidPath);
    }
    if path.contains('\0') {
        return Err(CatalogError::InvalidPath);
    }
    if path.contains("//") {
        return Err(CatalogError::InvalidPath);
    }
    if path.ends_with('/') {
        return Err(CatalogError::InvalidPath);
    }
    if path.starts_with('/') {
        return Err(CatalogError::InvalidPath);
    }
    for component in path.split('/') {
        if component.is_empty() || component.len() > MAX_NAME_LEN {
            return Err(CatalogError::InvalidName);
        }
    }
    Ok(())
}

/// Extract the parent path from a full path.
/// Returns `None` if the path has no parent (single component / pool root).
fn parent_path(path: &str) -> Option<String> {
    path.rsplit_once('/')
        .map(|(parent, _child)| parent.to_string())
}

/// Check if `maybe_ancestor` is an ancestor of `path`.
fn is_ancestor_of(maybe_ancestor: &str, path: &str) -> bool {
    path.starts_with(maybe_ancestor) && path.as_bytes().get(maybe_ancestor.len()) == Some(&b'/')
}

/// Compute the new path after renaming an ancestor.
/// `old_prefix` and `new_prefix` are full paths.
fn replace_prefix(path: &str, old_prefix: &str, new_prefix: &str) -> String {
    debug_assert!(path.starts_with(old_prefix));
    let rest = &path[old_prefix.len()..];
    format!("{new_prefix}{rest}")
}

// ---------------------------------------------------------------------------
// Catalog entry (stored as value in the B+tree)
// ---------------------------------------------------------------------------

/// Entry stored in the dataset catalog B+tree.
///
/// WARNING: keep fields simple; this struct is serialized for persistence
/// via local-object-store.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogEntry {
    /// Stable dataset identifier.
    dataset_id: DatasetId,
    /// Parent path, or `None` for pool root children.
    parent: Option<String>,
    /// Dataset class.
    dataset_type: DatasetType,
    /// Commit-group number at creation time.
    creation_txg: u64,
    /// Opaque property blob (serialized key/value pairs).
    /// Use an empty vec to signal no custom properties.
    properties: Vec<u8>,
    /// Per-dataset creation flags.
    /// Dataset lifecycle state.
    lifecycle_state: LifecycleState,
    flags: DatasetFlags,
    /// Write-acknowledgment durability guarantee for this dataset.
    sync_guarantee: SyncGuarantee,
    /// Clone/snapshot lineage parent DatasetId (None for independent datasets).
    lineage_parent_id: Option<DatasetId>,
    /// Whether this root has been published (lineage validated).
    published: bool,
    /// BLAKE3-256 lineage summary digest, recorded at publication time.
    lineage_summary: [u8; 32],
}

// ---------------------------------------------------------------------------
// DatasetCatalog
// ---------------------------------------------------------------------------

/// Pool-wide dataset catalog backed by a B+tree.
///
/// Maps hierarchical dataset paths to stable [`DatasetId`] values. Supports
/// create, destroy, lookup, list-children, and online rename without unmount.
#[derive(Clone, Debug)]
pub struct DatasetCatalog {
    /// B+tree keyed by full path → entry (dataset_id + parent path).
    tree: BPlusTree<String, CatalogEntry, MAX_LEAF, MAX_INTERNAL>,
}

impl DatasetCatalog {
    /// Create an empty dataset catalog.
    pub fn new() -> Self {
        Self {
            tree: BPlusTree::new(),
        }
    }

    /// Returns the number of datasets in the catalog.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.len() == 0
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Look up a dataset by its full path.
    ///
    /// Returns the stable `DatasetId` if the path exists.
    pub fn lookup(&self, path: &str) -> Result<DatasetId, CatalogError> {
        validate_path(path)?;
        self.tree
            .get(&path.to_string())
            .map(|entry| entry.dataset_id)
            .ok_or(CatalogError::NotFound)
    }

    /// Resolve a mount path to the dataset ID.
    ///
    /// Alias for [`lookup`] that signals mount-path resolution intent.
    /// File handles reference the returned `DatasetId`, which survives
    /// renames unchanged.
    pub fn mount_lookup(&self, path: &str) -> Result<DatasetId, CatalogError> {
        self.lookup(path)
    }

    /// Returns `true` if a dataset exists at the given path.
    /// Resolve a snapshot path to its stable [`DatasetId`].
    ///
    /// Supports `@` syntax for snapshot selection (e.g. `root@snap1`,
    /// `pool/dataset@snap1`, `pool/dataset`). When the path contains
    /// `@`, the part before the last `@` is the base dataset path and
    /// the part after is the snapshot name. The snapshot must exist as
    /// a catalog entry registered with the full `@` path.
    ///
    /// When no `@` is present, delegates to [`mount_lookup`] for
    /// standard dataset resolution.
    pub fn snapshot_lookup(&self, path: &str) -> Result<DatasetId, CatalogError> {
        if let Some((_base, _snap_name)) = path.rsplit_once('@') {
            // When a base path is present (e.g. "root@snap1"), look up
            // the full path directly, then verify the entry is a Snapshot.
            // The catalog stores snapshot entries under their `@` path.
            validate_path(path)?;
            let entry = self
                .tree
                .get(&path.to_string())
                .ok_or(CatalogError::NotFound)?;
            if entry.dataset_type != DatasetType::Snapshot {
                return Err(CatalogError::NotFound);
            }
            Ok(entry.dataset_id)
        } else {
            // No @ character — delegate to standard dataset lookup.
            self.mount_lookup(path)
        }
    }
    pub fn contains(&self, path: &str) -> bool {
        self.tree.contains_key(&path.to_string())
    }

    /// Look up a full catalog entry by path.
    #[allow(dead_code)]
    pub(crate) fn get_entry(&self, path: &str) -> Option<CatalogEntry> {
        validate_path(path).ok()?;
        self.tree.get(&path.to_string()).cloned()
    }

    /// Get the typed property set for a dataset, deserialized from the
    /// catalog blob. Returns an empty `PropertySet` if the dataset has no
    /// properties recorded.
    pub fn get_properties(&self, path: &str) -> Result<PropertySet, CatalogError> {
        let entry = self.get_entry(path).ok_or(CatalogError::NotFound)?;
        Ok(PropertySet::from_key_value_blob(&entry.properties))
    }

    /// Set the typed property set for a dataset, serializing it into the
    /// catalog blob. Only `PropertySource::Local` entries are persisted;
    /// inherited and default entries are discarded during serialization.
    pub fn set_properties(&mut self, path: &str, props: &PropertySet) -> Result<(), CatalogError> {
        let blob = props.to_key_value_blob();
        let path_owned = path.to_string();
        let updated = self.tree.update(&path_owned, |entry| {
            entry.properties = blob.clone();
        });
        if updated {
            Ok(())
        } else {
            Err(CatalogError::NotFound)
        }
    }

    /// Resolve a dataset's properties with full parent-chain inheritance.
    ///
    /// Walks the parent chain from the given dataset up to the root and
    /// applies inheritance rules to produce an effective `PropertySet`
    /// where every entry carries the correct source annotation.
    ///
    /// The returned set contains entries for every property in the global
    /// registry, not only the locally-set ones.
    pub fn get_properties_with_inheritance(&self, path: &str) -> Result<PropertySet, CatalogError> {
        use tidefs_dataset_properties::{build_registry, resolve_effective};
        let local = self.get_properties(path)?;
        let mut parent_sets: Vec<PropertySet> = Vec::new();
        let mut current = self.get_entry(path).ok_or(CatalogError::NotFound)?;
        while let Some(ref parent_path) = current.parent {
            if let Ok(parent_props) = self.get_properties(parent_path) {
                parent_sets.push(parent_props);
            }
            current = match self.get_entry(parent_path) {
                Some(entry) => entry,
                None => break,
            };
        }
        let parent_refs: Vec<&PropertySet> = parent_sets.iter().collect();
        let registry = build_registry();
        let mut effective = PropertySet::new();
        for def in &registry {
            let resolved = resolve_effective(&def.name, &local, &parent_refs, def);
            effective.set_with_source(def.name.clone(), resolved.value, resolved.source);
        }
        Ok(effective)
    }
    // ------------------------------------------------------------------
    // Create
    // ------------------------------------------------------------------

    /// Add a new dataset to the catalog.
    ///
    /// The `path` is the full hierarchical path (e.g. `"pool/dataset_a"`).
    /// The parent dataset must already exist in the catalog, unless the
    /// path has a single component (pool root child).
    pub fn create(
        &mut self,
        path: &str,
        dataset_id: DatasetId,
        dataset_type: DatasetType,
        creation_txg: u64,
        properties: Vec<u8>,
        flags: DatasetFlags,
        sync_guarantee: SyncGuarantee,
    ) -> Result<(), CatalogError> {
        validate_path(path)?;
        let path_owned = path.to_string();

        if self.contains(path) {
            return Err(CatalogError::AlreadyExists);
        }

        // Validate that the parent exists (unless this is a pool root child)
        let parent = parent_path(path);
        if let Some(ref parent_path_str) = parent {
            if !self.contains(parent_path_str) {
                return Err(CatalogError::ParentNotFound);
            }
        }

        let entry = CatalogEntry {
            dataset_id,
            parent,
            dataset_type,
            creation_txg,
            properties,
            flags,
            sync_guarantee,
            lifecycle_state: LifecycleState::Active,
            lineage_parent_id: None,
            published: false,
            lineage_summary: [0u8; 32],
        };
        self.tree.insert(path_owned, entry);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Destroy
    // ------------------------------------------------------------------

    /// Remove a dataset from the catalog.
    ///
    /// Fails with [`CatalogError::HasChildren`] if the dataset has
    /// descendant datasets in the catalog. The dataset itself must be
    /// destroyed separately (space reclamation, etc.).
    pub fn destroy(&mut self, path: &str) -> Result<(), CatalogError> {
        validate_path(path)?;
        if !self.contains(path) {
            return Err(CatalogError::NotFound);
        }

        // Check for children
        let prefix = format!("{path}/");
        let children: Vec<String> = self
            .tree
            .entries()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k)
            .collect();
        if !children.is_empty() {
            return Err(CatalogError::HasChildren);
        }

        self.tree.delete(&path.to_string());
        Ok(())
    }

    // ------------------------------------------------------------------
    // List children
    // ------------------------------------------------------------------

    /// List the direct children of a dataset.
    ///
    /// Returns a vector of `(name, dataset_id)` pairs for datasets whose
    /// parent is `parent_path`. For the pool root, pass the pool name as
    /// `parent_path` (e.g. `"pool"`).
    pub fn list_children(
        &self,
        parent_path: &str,
    ) -> Result<Vec<(String, DatasetId)>, CatalogError> {
        if !parent_path.is_empty() {
            validate_path(parent_path)?;
        }

        let prefix = if parent_path.is_empty() {
            String::new()
        } else {
            format!("{parent_path}/")
        };
        let prefix_len = prefix.len();

        let mut children: Vec<(String, DatasetId)> = self
            .tree
            .entries()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix) && k.len() > prefix_len)
            .filter_map(|(k, entry)| {
                let rest = &k[prefix_len..];
                if rest.contains('/') {
                    None
                } else {
                    Some((rest.to_string(), entry.dataset_id))
                }
            })
            .collect();

        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(children)
    }

    /// List the direct children of a dataset, returning full entry details.
    ///
    /// Each returned tuple is `(name, DatasetId, DatasetType, creation_txg, DatasetFlags)`.
    /// Sorted by name. For the pool root, pass the pool name as `parent_path`.
    pub fn list_children_detailed(
        &self,
        parent_path: &str,
    ) -> Result<Vec<DatasetChildDetails>, CatalogError> {
        if !parent_path.is_empty() {
            validate_path(parent_path)?;
        }

        let prefix = if parent_path.is_empty() {
            String::new()
        } else {
            format!("{parent_path}/")
        };
        let prefix_len = prefix.len();

        let mut children: Vec<_> = self
            .tree
            .entries()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix) && k.len() > prefix_len)
            .filter_map(|(k, entry)| {
                let rest = &k[prefix_len..];
                if rest.contains('/') {
                    None
                } else {
                    Some((
                        rest.to_string(),
                        entry.dataset_id,
                        entry.dataset_type,
                        entry.creation_txg,
                        entry.flags,
                    ))
                }
            })
            .collect();

        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(children)
    }

    /// Returns true if `ancestor` is a true ancestor of `descendant`.
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> bool {
        is_ancestor_of(ancestor, descendant)
    }

    // ------------------------------------------------------------------
    // Rename
    // ------------------------------------------------------------------

    /// Rename a dataset from `old_path` to `new_path`.
    ///
    /// This operation is atomic at the catalog level: all entries
    /// (the renamed dataset and its descendants) are updated together.
    /// The `DatasetId` values are preserved — open file handles,
    /// leases, and extent references remain valid.
    ///
    /// # Errors
    ///
    /// - [`CatalogError::NotFound`] if `old_path` does not exist.
    /// - [`CatalogError::AlreadyExists`] if `new_path` already exists.
    /// - [`CatalogError::WouldCreateCycle`] if the rename would move a
    ///   dataset into its own subtree.
    /// - [`CatalogError::InvalidPath`] if either path is malformed.
    /// - [`CatalogError::ParentNotFound`] if the parent of `new_path`
    ///   does not exist.
    pub fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), CatalogError> {
        validate_path(old_path)?;
        validate_path(new_path)?;

        let old_path_owned = old_path.to_string();

        // Verify old_path exists
        if !self.contains(old_path) {
            return Err(CatalogError::NotFound);
        }

        // Verify new_path does not exist
        if self.contains(new_path) {
            return Err(CatalogError::AlreadyExists);
        }

        // Verify new parent exists (if any)
        let new_parent = parent_path(new_path);
        if let Some(ref np) = new_parent {
            if !self.contains(np) {
                return Err(CatalogError::ParentNotFound);
            }
        }

        // Cycle check: if new_path is a descendant of old_path, that's a cycle
        if is_ancestor_of(old_path, new_path) {
            return Err(CatalogError::WouldCreateCycle);
        }

        // Collect all entries that need to be moved: the old_path entry
        // and all descendants (entries whose path starts with old_path/).
        let old_prefix = format!("{old_path}/");
        let mut affected: Vec<(String, CatalogEntry)> = self
            .tree
            .entries()
            .into_iter()
            .filter(|(k, _)| *k == old_path_owned || k.starts_with(&old_prefix))
            .collect();

        if affected.is_empty() {
            return Err(CatalogError::NotFound);
        }

        // Remove old entries from the tree
        for (key, _) in &affected {
            self.tree.delete(key);
        }

        // Compute new paths and re-insert
        for (old_key, entry) in &mut affected {
            let new_key = replace_prefix(old_key, old_path, new_path);

            // Update parent reference for the renamed root entry
            if *old_key == old_path_owned {
                entry.parent = parent_path(new_path);
            } else {
                // For descendants, update their parent path
                if let Some(ref parent) = entry.parent {
                    if parent.starts_with(old_path) {
                        entry.parent = Some(replace_prefix(parent, old_path, new_path));
                    }
                }
            }

            self.tree.insert(new_key, entry.clone());
        }

        Ok(())
    }

    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Lifecycle transitions
    // ------------------------------------------------------------------

    /// Transition a dataset from `Active` to `Destroying`.
    ///
    /// This blocks new writes by marking the dataset as destroying.
    /// Children may still exist; they must be destroyed before the
    /// parent can transition to `Destroyed`.
    pub fn transition_to_destroying(&mut self, path: &str) -> Result<(), CatalogError> {
        validate_path(path)?;
        let mut entry = self
            .tree
            .get(&path.to_string())
            .cloned()
            .ok_or(CatalogError::NotFound)?;
        if entry.lifecycle_state != LifecycleState::Active {
            return Err(CatalogError::InvalidStateTransition);
        }
        entry.lifecycle_state = LifecycleState::Destroying;
        self.tree.insert(path.to_string(), entry);
        Ok(())
    }

    /// Transition a dataset from `Destroying` to `Destroyed`.
    ///
    /// The dataset must have no remaining children in the catalog.
    pub fn transition_to_destroyed(&mut self, path: &str) -> Result<(), CatalogError> {
        validate_path(path)?;
        let mut entry = self
            .tree
            .get(&path.to_string())
            .cloned()
            .ok_or(CatalogError::NotFound)?;
        if entry.lifecycle_state != LifecycleState::Destroying {
            return Err(CatalogError::InvalidStateTransition);
        }
        // Check for children
        let prefix = format!("{path}/");
        let has_children = self
            .tree
            .entries()
            .into_iter()
            .any(|(k, _)| k.starts_with(&prefix));
        if has_children {
            return Err(CatalogError::HasChildren);
        }
        entry.lifecycle_state = LifecycleState::Destroyed;
        self.tree.insert(path.to_string(), entry);
        Ok(())
    }

    /// Return the current lifecycle state of a dataset.
    pub fn lifecycle_state(&self, path: &str) -> Result<LifecycleState, CatalogError> {
        validate_path(path)?;
        self.tree
            .get(&path.to_string())
            .map(|entry| entry.lifecycle_state)
            .ok_or(CatalogError::NotFound)
    }

    /// Return the write-acknowledgment sync guarantee for a dataset.
    ///
    /// Returns [`SyncGuarantee::Local`] as the default for any dataset
    /// created before this property was introduced.
    pub fn sync_guarantee(&self, path: &str) -> Result<SyncGuarantee, CatalogError> {
        validate_path(path)?;
        self.tree
            .get(&path.to_string())
            .map(|entry| entry.sync_guarantee)
            .ok_or(CatalogError::NotFound)
    }

    // ------------------------------------------------------------------
    // Lineage management
    // ------------------------------------------------------------------

    /// Set the clone/snapshot lineage parent for an existing catalog entry.
    ///
    /// Only [`DatasetType::Snapshot`] and clones ([`DatasetFlags::CLONE`])
    /// may have a lineage parent. Sets the entry's `lineage_parent_id`
    /// field without validating the lineage graph; validation happens at
    /// [`publish_root`] time.
    pub fn set_lineage_parent(
        &mut self,
        path: &str,
        lineage_parent_id: DatasetId,
    ) -> Result<(), CatalogError> {
        validate_path(path)?;
        let entry = self
            .tree
            .get(&path.to_string())
            .ok_or(CatalogError::NotFound)?;

        // Only snapshots and clones can have lineage parents.
        if entry.dataset_type != DatasetType::Snapshot
            && !entry.flags.contains(DatasetFlags::CLONE)
        {
            return Err(CatalogError::LineageNotSupported);
        }

        let mut entry = entry.clone();
        entry.lineage_parent_id = Some(lineage_parent_id);
        self.tree.insert(path.to_string(), entry);
        Ok(())
    }

    /// Publish a root after validating its clone/snapshot lineage.
    ///
    /// Checks that the lineage graph rooted at `path` is acyclic, every
    /// referenced parent root exists in the catalog under the expected
    /// dataset authority, and no duplicate edges exist. On success,
    /// records a BLAKE3-256 lineage summary digest for later snapshot-pruner
    /// and send-stream checks.
    pub fn publish_root(&mut self, path: &str) -> Result<(), CatalogError> {
        validate_path(path)?;
        let entry = self
            .tree
            .get(&path.to_string())
            .ok_or(CatalogError::NotFound)?;

        if entry.published {
            return Err(CatalogError::AlreadyPublished);
        }

        // Validate lineage and compute summary
        let lineage_summary = self.validate_lineage(path)?;

        let mut entry = entry.clone();
        entry.published = true;
        entry.lineage_summary = lineage_summary;
        self.tree.insert(path.to_string(), entry);
        Ok(())
    }

    /// Return the BLAKE3-256 lineage summary digest for a published root.
    ///
    /// Returns [`CatalogError::NotPublished`] if the root has not been
    /// published, and [`CatalogError::NotFound`] if the path is not in the
    /// catalog.
    pub fn lineage_summary(&self, path: &str) -> Result<[u8; 32], CatalogError> {
        validate_path(path)?;
        let entry = self
            .tree
            .get(&path.to_string())
            .ok_or(CatalogError::NotFound)?;
        if !entry.published {
            return Err(CatalogError::NotPublished);
        }
        Ok(entry.lineage_summary)
    }

    /// Return whether a root has been published.
    pub fn is_published(&self, path: &str) -> Result<bool, CatalogError> {
        validate_path(path)?;
        self.tree
            .get(&path.to_string())
            .map(|e| e.published)
            .ok_or(CatalogError::NotFound)
    }

    // ------------------------------------------------------------------
    // Reverse lookup
    // ------------------------------------------------------------------

    /// Look up a dataset by its stable `DatasetId`.
    ///
    /// Returns `(path, parent, DatasetType, creation_txg, DatasetFlags, LifecycleState)`
    /// if found. This is an O(n) scan and should be used sparingly; the
    /// primary access path is [`lookup`] by path.
    pub fn get_by_id(
        &self,
        id: &DatasetId,
    ) -> Option<(
        String,
        Option<String>,
        DatasetType,
        u64,
        DatasetFlags,
        LifecycleState,
    )> {
        self.tree.entries().into_iter().find_map(|(path, entry)| {
            if entry.dataset_id == *id {
                Some((
                    path,
                    entry.parent,
                    entry.dataset_type,
                    entry.creation_txg,
                    entry.flags,
                    entry.lifecycle_state,
                ))
            } else {
                None
            }
        })
    }

    /// Look up a dataset by name under a parent path.
    ///
    /// Returns the `DatasetId` if a dataset with `name` exists under
    /// `parent_path`. For the pool root, `parent_path` is the pool name
    /// (e.g. `"pool"`).
    pub fn get_by_name(&self, parent_path: &str, name: &str) -> Option<DatasetId> {
        validate_path(name).ok()?;
        let path = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{parent_path}/{name}")
        };
        self.lookup(&path).ok()
    }

    /// List all datasets in the catalog with full entry details.
    ///
    /// Returns `(path, DatasetId, DatasetType, creation_txg, DatasetFlags, LifecycleState)`.
    pub fn list_all(
        &self,
    ) -> Vec<(
        String,
        DatasetId,
        DatasetType,
        u64,
        DatasetFlags,
        LifecycleState,
    )> {
        let mut entries: Vec<_> = self
            .tree
            .entries()
            .into_iter()
            .map(|(path, entry)| {
                (
                    path,
                    entry.dataset_id,
                    entry.dataset_type,
                    entry.creation_txg,
                    entry.flags,
                    entry.lifecycle_state,
                )
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    // Iteration / introspection
    // ------------------------------------------------------------------

    /// Return all entries in the catalog as `(path, DatasetId)` pairs.
    pub fn entries(&self) -> Vec<(String, DatasetId)> {
        self.tree
            .entries()
            .into_iter()
            .map(|(k, v)| (k, v.dataset_id))
            .collect()
    }

    // ------------------------------------------------------------------
    // Lineage validation (private)
    // ------------------------------------------------------------------

    /// Validate the clone/snapshot lineage graph rooted at `path`.
    ///
    /// Returns the BLAKE3-256 lineage summary digest on success.
    fn validate_lineage(&self, path: &str) -> Result<[u8; 32], CatalogError> {
        let entry = self
            .tree
            .get(&path.to_string())
            .ok_or(CatalogError::NotFound)?;

        // Roots without a lineage parent are trivially acyclic.
        let Some(start_parent) = entry.lineage_parent_id else {
            // No lineage to validate; summary is hash of own DatasetId.
            let mut hasher = Hasher::new();
            hasher.update(entry.dataset_id.as_bytes());
            let mut digest = [0u8; 32];
            digest.copy_from_slice(hasher.finalize().as_bytes().as_ref());
            return Ok(digest);
        };

        let mut hasher = Hasher::new();
        let mut visited: Vec<DatasetId> = Vec::new();
        let mut current_parent = Some(start_parent);

        // Include the root's own DatasetId in the summary.
        hasher.update(entry.dataset_id.as_bytes());

        while let Some(parent_id) = current_parent {
            // Check for duplicate edge: same parent appears consecutively.
            if visited.last() == Some(&parent_id) {
                return Err(CatalogError::LineageDuplicateEdge);
            }

            // Check for cycle: if we've seen this parent before, we have a cycle.
            if visited.contains(&parent_id) {
                return Err(CatalogError::LineageCycle);
            }

            // Find the parent entry by scanning for its DatasetId.
            let parent_path_and_entry = self
                .tree
                .entries()
                .into_iter()
                .find(|(_, e)| e.dataset_id == parent_id);

            let (parent_path, parent_entry) =
                parent_path_and_entry.ok_or(CatalogError::LineageParentNotFound)?;

            // Verify the parent is under the expected dataset authority:
            // the parent must be in the same pool (first path component matches).
            let root_pool = path.split('/').next().unwrap_or("");
            let parent_pool = parent_path.split('/').next().unwrap_or("");
            if root_pool != parent_pool {
                return Err(CatalogError::LineageWrongDataset);
            }

            // Accumulate parent into hash
            hasher.update(parent_id.as_bytes());
            visited.push(parent_id);

            // Follow the chain
            current_parent = parent_entry.lineage_parent_id;
        }

        let mut digest = [0u8; 32];
        digest.copy_from_slice(hasher.finalize().as_bytes().as_ref());
        Ok(digest)
    }

    // ------------------------------------------------------------------
    // Persistent encoding
    // ------------------------------------------------------------------

    /// Encode the entire catalog to a binary buffer with BLAKE3-256 checksum.
    ///
    /// Format (little-endian unless noted):
    /// ```text
    /// [u32 entry_count]
    /// for each entry:
    ///   [u16 path_len][path bytes]
    ///   [u8 has_parent]
    ///   if has_parent: [u16 parent_len][parent bytes]
    ///   [u8; 16 dataset_id]
    ///   [u8 dataset_type]
    ///   [u64 creation_txg]
    ///   [u16 flags]
    ///   [u8 sync_guarantee]
    ///   [u8 lifecycle_state]
    ///   [u8 has_lineage_parent]
    ///   if has_lineage_parent: [u8; 16 lineage_parent_id]
    ///   [u8 published]
    ///   [u8; 32 lineage_summary]
    ///   [u32 properties_len][properties bytes]
    /// [u8; 32 BLAKE3-256 domain-separated checksum]
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let entries: Vec<(String, CatalogEntry)> = self.tree.entries();
        let mut buf = Vec::with_capacity(4096);

        // Header: entry count (u32 LE)
        let count: u32 = entries.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        for (path, entry) in &entries {
            // Path
            let path_bytes = path.as_bytes();
            let path_len: u16 = path_bytes.len() as u16;
            buf.extend_from_slice(&path_len.to_le_bytes());
            buf.extend_from_slice(path_bytes);

            // Parent (optional)
            if let Some(ref parent) = entry.parent {
                buf.push(1u8);
                let parent_bytes = parent.as_bytes();
                let parent_len: u16 = parent_bytes.len() as u16;
                buf.extend_from_slice(&parent_len.to_le_bytes());
                buf.extend_from_slice(parent_bytes);
            } else {
                buf.push(0u8);
            }

            // DatasetId (16 bytes)
            buf.extend_from_slice(entry.dataset_id.as_bytes());

            // DatasetType (u8)
            buf.push(entry.dataset_type.to_u8());

            // creation_txg (u64 LE)
            buf.extend_from_slice(&entry.creation_txg.to_le_bytes());

            // flags (u16 LE)
            buf.extend_from_slice(&entry.flags.bits().to_le_bytes());

            // sync_guarantee (u8)
            buf.push(entry.sync_guarantee.to_u8());

            // lifecycle_state (u8)
            buf.push(entry.lifecycle_state.to_u8());

            // lineage_parent_id (optional: u8 has_parent + [u8; 16] if present)
            if let Some(ref lpid) = entry.lineage_parent_id {
                buf.push(1u8);
                buf.extend_from_slice(lpid.as_bytes());
            } else {
                buf.push(0u8);
            }

            // published (u8 as bool)
            buf.push(if entry.published { 1u8 } else { 0u8 });

            // lineage_summary ([u8; 32])
            buf.extend_from_slice(&entry.lineage_summary);

            // Properties blob
            let props_len: u32 = entry.properties.len() as u32;
            buf.extend_from_slice(&props_len.to_le_bytes());
            buf.extend_from_slice(&entry.properties);
        }

        // Append BLAKE3-256 domain-separated checksum over all preceding bytes
        let digest = blake3_domain_digest(
            &buf,
            CATALOG_SCHEMA_FAMILY,
            CATALOG_SCHEMA_TYPE,
            CATALOG_SCHEMA_VERSION,
            CATALOG_SCHEMA_DOMAIN,
        );
        buf.extend_from_slice(&digest);

        buf
    }

    /// Decode a catalog from a binary buffer with BLAKE3-256 verification.
    ///
    /// Returns an empty catalog if the buffer is empty (no entries).
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::CorruptEncoding`] if the buffer is truncated,
    /// contains invalid data, or fails the BLAKE3 checksum verification.
    pub fn decode(data: &[u8]) -> Result<Self, CatalogError> {
        if data.is_empty() {
            return Ok(Self::new());
        }

        // Must have at least 4 bytes (count) + 32 bytes (checksum)
        if data.len() < 36 {
            return Err(CatalogError::CorruptEncoding);
        }

        // Verify BLAKE3 checksum
        let payload = &data[..data.len() - CHECKSUM_SIZE];
        let expected_checksum: &[u8; CHECKSUM_SIZE] = data[data.len() - CHECKSUM_SIZE..]
            .try_into()
            .map_err(|_| CatalogError::CorruptEncoding)?;
        let computed = blake3_domain_digest(
            payload,
            CATALOG_SCHEMA_FAMILY,
            CATALOG_SCHEMA_TYPE,
            CATALOG_SCHEMA_VERSION,
            CATALOG_SCHEMA_DOMAIN,
        );
        if computed != *expected_checksum {
            return Err(CatalogError::CorruptEncoding);
        }

        // Parse entry count
        let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
        let mut offset: usize = 4;
        let mut cat = Self::new();

        for _ in 0..count {
            if offset + 2 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }

            // Path
            let path_len =
                u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            if offset + path_len > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let path = String::from_utf8(payload[offset..offset + path_len].to_vec())
                .map_err(|_| CatalogError::CorruptEncoding)?;
            offset += path_len;

            // Parent
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let has_parent = payload[offset];
            offset += 1;
            let parent = if has_parent != 0 {
                if offset + 2 > payload.len() {
                    return Err(CatalogError::CorruptEncoding);
                }
                let parent_len =
                    u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap()) as usize;
                offset += 2;
                if offset + parent_len > payload.len() {
                    return Err(CatalogError::CorruptEncoding);
                }
                let parent_str = String::from_utf8(payload[offset..offset + parent_len].to_vec())
                    .map_err(|_| CatalogError::CorruptEncoding)?;
                offset += parent_len;
                Some(parent_str)
            } else {
                None
            };

            // DatasetId (16 bytes)
            if offset + 16 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let dataset_id =
                DatasetId::from_bytes(payload[offset..offset + 16].try_into().unwrap());
            offset += 16;

            // DatasetType (u8)
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let dataset_type =
                DatasetType::from_u8(payload[offset]).ok_or(CatalogError::CorruptEncoding)?;
            offset += 1;

            // creation_txg (u64 LE)
            if offset + 8 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let creation_txg = u64::from_le_bytes(payload[offset..offset + 8].try_into().unwrap());
            offset += 8;

            // flags (u16 LE)
            if offset + 2 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let flags_raw = u16::from_le_bytes(payload[offset..offset + 2].try_into().unwrap());
            let flags = DatasetFlags::from_bits(flags_raw);
            offset += 2;

            // sync_guarantee (u8)
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let sync_guarantee =
                SyncGuarantee::from_u8(payload[offset]).ok_or(CatalogError::CorruptEncoding)?;
            offset += 1;

            // lifecycle_state (u8)
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let lifecycle_state =
                LifecycleState::from_u8(payload[offset]).ok_or(CatalogError::CorruptEncoding)?;
            offset += 1;

            // lineage_parent_id (optional)
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let has_lineage_parent = payload[offset];
            offset += 1;
            let lineage_parent_id = if has_lineage_parent != 0 {
                if offset + 16 > payload.len() {
                    return Err(CatalogError::CorruptEncoding);
                }
                let lpid = DatasetId::from_bytes(
                    payload[offset..offset + 16].try_into().unwrap(),
                );
                offset += 16;
                Some(lpid)
            } else {
                None
            };

            // published (u8 as bool)
            if offset >= payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let published = payload[offset] != 0;
            offset += 1;

            // lineage_summary ([u8; 32])
            if offset + 32 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let lineage_summary: [u8; 32] =
                payload[offset..offset + 32].try_into().unwrap();
            offset += 32;

            // Properties blob
            if offset + 4 > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let props_len =
                u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + props_len > payload.len() {
                return Err(CatalogError::CorruptEncoding);
            }
            let properties = payload[offset..offset + props_len].to_vec();
            offset += props_len;

            let entry = CatalogEntry {
                dataset_id,
                parent,
                dataset_type,
                creation_txg,
                properties,
                flags,
                lifecycle_state,
                sync_guarantee,
                lineage_parent_id,
                published,
                lineage_summary,
            };
            cat.tree.insert(path, entry);
        }

        Ok(cat)
    }
}

impl Default for DatasetCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Property override merge
// ---------------------------------------------------------------------------

/// Merge dataset property overrides with inherited defaults.
///
/// Each property is a key-value pair separated by `=`, one per line
/// (same format as the `properties` blob stored in [`CatalogEntry`]).
/// Override values take precedence over inherited defaults. Lines in
/// the output are sorted by key.
///
/// Inherited defaults come from the parent dataset's property blob;
/// overrides come from the current dataset's property blob. When both
/// define the same key, the override wins.
pub fn merge_property_overrides(inherited: &[u8], overrides: &[u8]) -> Vec<u8> {
    let mut map: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();

    // Parse inherited defaults first
    for line in inherited.split(|&b| b == b'\n') {
        if let Ok(s) = core::str::from_utf8(line) {
            if let Some((k, v)) = s.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if !k.is_empty() {
                    map.insert(k, v);
                }
            }
        }
    }

    // Apply overrides (wins on conflict)
    for line in overrides.split(|&b| b == b'\n') {
        if let Ok(s) = core::str::from_utf8(line) {
            if let Some((k, v)) = s.split_once('=') {
                let k = k.trim();
                let v = v.trim();
                if !k.is_empty() {
                    map.insert(k, v);
                }
            }
        }
    }

    // Serialize back to byte blob (sorted by key via BTreeMap)
    let mut out = Vec::new();
    for (k, v) in &map {
        out.extend_from_slice(k.as_bytes());
        out.push(b'=');
        out.extend_from_slice(v.as_bytes());
        out.push(b'\n');
    }
    out
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::DatasetFlags;
    use super::DatasetType;
    use super::*;

    /// Helper: create a test DatasetId from a simple numeric id.
    fn did(n: u8) -> DatasetId {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = n;
        bytes[2] = n;
        bytes[3] = n;
        bytes[4] = n;
        bytes[5] = n;
        bytes[6] = n;
        bytes[7] = n;
        bytes[8] = n;
        bytes[9] = n;
        bytes[10] = n;
        bytes[11] = n;
        bytes[12] = n;
        bytes[13] = n;
        bytes[14] = n;
        bytes[15] = n;
        DatasetId::from_bytes(bytes)
    }

    /// Helper: empty properties blob.
    fn empty_props() -> Vec<u8> {
        vec![]
    }

    // ------------------------------------------------------------------
    // DatasetId tests
    // ------------------------------------------------------------------

    #[test]
    fn dataset_id_from_uuid_str() {
        let id = DatasetId::from_uuid_str("550e8400-e29b-41d4-a716-446655440000");
        assert!(id.is_some());
        let id = id.unwrap();
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn dataset_id_display_roundtrip() {
        let id = did(42);
        let s = id.to_string();
        let parsed = DatasetId::from_uuid_str(&s);
        assert_eq!(parsed, Some(id));
    }

    // ------------------------------------------------------------------
    // Path validation tests
    // ------------------------------------------------------------------

    #[test]
    fn validate_path_valid() {
        assert!(validate_path("pool").is_ok());
        assert!(validate_path("pool/dataset_a").is_ok());
        assert!(validate_path("pool/tenants/tenant_x/volumes/vol1").is_ok());
    }

    #[test]
    fn validate_path_invalid() {
        assert_eq!(validate_path(""), Err(CatalogError::InvalidPath));
        assert_eq!(validate_path("/pool"), Err(CatalogError::InvalidPath));
        assert_eq!(validate_path("pool/"), Err(CatalogError::InvalidPath));
        assert_eq!(
            validate_path("pool//dataset"),
            Err(CatalogError::InvalidPath)
        );
        assert_eq!(
            validate_path("pool/data\0set"),
            Err(CatalogError::InvalidPath)
        );
    }

    // ------------------------------------------------------------------
    // Create tests
    // ------------------------------------------------------------------

    #[test]
    fn create_root_child() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat
            .create(
                "pool/root_ds",
                did(1),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            )
            .is_ok());
        assert_eq!(cat.lookup("pool/root_ds"), Ok(did(1)));
    }

    #[test]
    fn create_nested() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.lookup("pool/a/b"), Ok(did(2)));
    }

    #[test]
    fn create_duplicate_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(
            cat.create(
                "pool/a",
                did(2),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            ),
            Err(CatalogError::AlreadyExists)
        );
    }

    #[test]
    fn create_missing_parent_fails() {
        let mut cat = DatasetCatalog::new();
        assert_eq!(
            cat.create(
                "pool/a/b",
                did(2),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            ),
            Err(CatalogError::ParentNotFound)
        );
    }

    #[test]
    fn create_invalid_path_fails() {
        let mut cat = DatasetCatalog::new();
        assert_eq!(
            cat.create(
                "pool//a",
                did(1),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            ),
            Err(CatalogError::InvalidPath)
        );
    }

    // ------------------------------------------------------------------
    // Lookup tests
    // ------------------------------------------------------------------

    #[test]
    fn lookup_nonexistent() {
        let cat = DatasetCatalog::new();
        assert_eq!(cat.lookup("pool/nonexistent"), Err(CatalogError::NotFound));
    }

    #[test]
    fn lookup_after_create() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(42),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.lookup("pool/a"), Ok(did(42)));
    }

    #[test]
    fn contains_key() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(!cat.contains("pool/a"));
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat.contains("pool/a"));
    }

    #[test]
    fn mount_lookup_resolves() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds1",
            did(7),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.mount_lookup("pool/ds1"), Ok(did(7)));
    }

    #[test]
    fn snapshot_lookup_resolves_snapshot_by_at_syntax() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds1",
            did(7),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds1@snap1",
            did(42),
            DatasetType::Snapshot,
            100,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.snapshot_lookup("pool/ds1@snap1"), Ok(did(42)));
    }

    #[test]
    fn snapshot_lookup_falls_back_to_dataset_when_no_at() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds1",
            did(7),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.snapshot_lookup("pool/ds1"), Ok(did(7)));
    }

    #[test]
    fn snapshot_lookup_rejects_filesystem_entry_for_snapshot_path() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds1",
            did(7),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        // "pool/ds1@snap1" doesn't exist as a snapshot; resolves as a dataset entry which is type mismatch
        assert!(cat.snapshot_lookup("pool/ds1@nonexistent").is_err());
    }

    #[test]
    fn snapshot_lookup_rejects_nonexistent_snapshot() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat.snapshot_lookup("pool@missing").is_err());
    }

    #[test]
    fn snapshot_lookup_root_at_syntax() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "root",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "root@snap1",
            did(99),
            DatasetType::Snapshot,
            200,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.snapshot_lookup("root@snap1"), Ok(did(99)));
        assert!(cat.snapshot_lookup("root@nonexistent").is_err());
    }

    // ------------------------------------------------------------------
    // Destroy tests
    // ------------------------------------------------------------------

    #[test]
    fn destroy_leaf_dataset() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat.destroy("pool/a").is_ok());
        assert!(!cat.contains("pool/a"));
    }

    #[test]
    fn destroy_nonexistent_fails() {
        let mut cat = DatasetCatalog::new();
        assert_eq!(cat.destroy("pool/nonexistent"), Err(CatalogError::NotFound));
    }

    #[test]
    fn destroy_with_children_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.destroy("pool/a"), Err(CatalogError::HasChildren));
    }

    #[test]
    fn destroy_then_recreate() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.destroy("pool/a").unwrap();
        assert!(cat
            .create(
                "pool/a",
                did(2),
                DatasetType::Filesystem,
                1,
                empty_props(),
                DatasetFlags::NONE,
                SyncGuarantee::default(),
            )
            .is_ok());
        assert_eq!(cat.lookup("pool/a"), Ok(did(2)));
    }

    // ------------------------------------------------------------------
    // List children tests
    // ------------------------------------------------------------------

    #[test]
    fn list_children_empty() {
        let cat = DatasetCatalog::new();
        let children = cat.list_children("pool").unwrap();
        assert!(children.is_empty());
    }

    #[test]
    fn list_children_single_level() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/c",
            did(3),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        let children = cat.list_children("pool").unwrap();
        assert_eq!(children.len(), 3);
        assert_eq!(children[0], ("a".to_string(), did(1)));
        assert_eq!(children[1], ("b".to_string(), did(2)));
        assert_eq!(children[2], ("c".to_string(), did(3)));
    }

    #[test]
    fn list_children_nested() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/sub1",
            did(10),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/sub2",
            did(11),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        let children = cat.list_children("pool/a").unwrap();
        assert_eq!(children.len(), 2);
        assert!(children.contains(&("sub1".to_string(), did(10))));
        assert!(children.contains(&("sub2".to_string(), did(11))));
    }

    #[test]
    fn list_children_sorted() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/z",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/m",
            did(3),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        let children = cat.list_children("pool").unwrap();
        let names: Vec<&str> = children.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    // ------------------------------------------------------------------
    // Rename tests
    // ------------------------------------------------------------------

    #[test]
    fn rename_simple_same_parent() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/oldname",
            did(42),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        cat.rename("pool/oldname", "pool/newname").unwrap();

        assert!(!cat.contains("pool/oldname"));
        assert!(cat.contains("pool/newname"));
        // DatasetId remains stable
        assert_eq!(cat.lookup("pool/newname"), Ok(did(42)));
    }

    #[test]
    fn rename_nonexistent_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(
            cat.rename("pool/nonexistent", "pool/new"),
            Err(CatalogError::NotFound)
        );
    }

    #[test]
    fn rename_to_existing_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        assert_eq!(
            cat.rename("pool/a", "pool/b"),
            Err(CatalogError::AlreadyExists)
        );
        // Original entry unchanged
        assert!(cat.contains("pool/a"));
    }

    #[test]
    fn rename_preserves_children() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/child1",
            did(10),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/child2",
            did(11),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/child1/grandchild",
            did(100),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        cat.rename("pool/a", "pool/renamed").unwrap();

        // Old paths gone
        assert!(!cat.contains("pool/a"));
        assert!(!cat.contains("pool/a/child1"));
        assert!(!cat.contains("pool/a/child2"));
        assert!(!cat.contains("pool/a/child1/grandchild"));

        // New paths exist with same IDs
        assert_eq!(cat.lookup("pool/renamed"), Ok(did(1)));
        assert_eq!(cat.lookup("pool/renamed/child1"), Ok(did(10)));
        assert_eq!(cat.lookup("pool/renamed/child2"), Ok(did(11)));
        assert_eq!(cat.lookup("pool/renamed/child1/grandchild"), Ok(did(100)));

        // Children list works
        let children = cat.list_children("pool/renamed").unwrap();
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn rename_reparent_preserves_children() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/child1",
            did(10),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        cat.rename("pool/a", "pool/b/sub").unwrap();

        assert!(!cat.contains("pool/a"));
        assert_eq!(cat.lookup("pool/b/sub"), Ok(did(1)));
        assert_eq!(cat.lookup("pool/b/sub/child1"), Ok(did(10)));
    }

    #[test]
    fn rename_cycle_detection() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/child",
            did(10),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        assert_eq!(
            cat.rename("pool/a", "pool/a/child/new"),
            Err(CatalogError::WouldCreateCycle)
        );
    }

    #[test]
    fn rename_to_missing_parent_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        assert_eq!(
            cat.rename("pool/a", "pool/nonexistent/new"),
            Err(CatalogError::ParentNotFound)
        );
    }

    #[test]
    fn rename_invalid_paths_fail() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        assert_eq!(
            cat.rename("pool/a", "pool//b"),
            Err(CatalogError::InvalidPath)
        );
        assert_eq!(
            cat.rename("pool//a", "pool/b"),
            Err(CatalogError::InvalidPath)
        );
    }

    // ------------------------------------------------------------------
    // Concurrent mount+rename simulation
    // ------------------------------------------------------------------

    #[test]
    fn mount_still_works_after_rename_because_dataset_id_stable() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/ds",
            did(42),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Simulate mount: resolve path to dataset_id
        let ds_id = cat.mount_lookup("pool/ds").unwrap();
        assert_eq!(ds_id, did(42));

        // Rename the dataset
        cat.rename("pool/ds", "pool/renamed_ds").unwrap();

        // The old path is gone
        assert!(cat.mount_lookup("pool/ds").is_err());

        // But the dataset_id is still valid and can be resolved through
        // the new path
        let ds_id_after = cat.mount_lookup("pool/renamed_ds").unwrap();
        assert_eq!(ds_id_after, ds_id);
        assert_eq!(ds_id_after, did(42));
    }

    // ------------------------------------------------------------------
    // Lifecycle test: create → rename → destroy
    // ------------------------------------------------------------------

    #[test]
    fn lifecycle_create_rename_destroy() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Create
        cat.create(
            "pool/my_ds",
            did(100),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.lookup("pool/my_ds"), Ok(did(100)));
        assert_eq!(cat.len(), 2);

        // Rename
        cat.rename("pool/my_ds", "pool/renamed").unwrap();
        assert!(!cat.contains("pool/my_ds"));
        assert_eq!(cat.lookup("pool/renamed"), Ok(did(100)));

        // Destroy
        cat.destroy("pool/renamed").unwrap();
        assert!(!cat.contains("pool/renamed"));
        assert_eq!(cat.len(), 1);
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn rename_to_same_name_noop() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        assert_eq!(
            cat.rename("pool/a", "pool/a"),
            Err(CatalogError::AlreadyExists)
        );
    }

    #[test]
    fn empty_catalog_properties() {
        let cat = DatasetCatalog::new();
        assert_eq!(cat.len(), 0);
        assert!(cat.is_empty());
        assert!(cat.entries().is_empty());
    }

    #[test]
    fn deep_nesting_rename() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Build a deep tree: pool/a/b/c/d/e
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b/c",
            did(3),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b/c/d",
            did(4),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/b/c/d/e",
            did(5),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Rename at the top
        cat.rename("pool/a", "pool/x").unwrap();

        // All descendants should move
        assert!(cat.contains("pool/x"));
        assert!(cat.contains("pool/x/b"));
        assert!(cat.contains("pool/x/b/c"));
        assert!(cat.contains("pool/x/b/c/d"));
        assert!(cat.contains("pool/x/b/c/d/e"));
    }
    // ------------------------------------------------------------------
    // DatasetType / DatasetFlags / detailed-list / get_entry tests
    // ------------------------------------------------------------------

    #[test]
    fn dataset_type_u8_roundtrip() {
        let types = [
            DatasetType::Filesystem,
            DatasetType::Volume,
            DatasetType::Snapshot,
        ];
        for &t in &types {
            assert_eq!(DatasetType::from_u8(t.to_u8()), Some(t));
        }
    }

    #[test]
    fn dataset_type_from_u8_invalid() {
        assert_eq!(DatasetType::from_u8(0), None);
        assert_eq!(DatasetType::from_u8(4), None);
        assert_eq!(DatasetType::from_u8(255), None);
    }

    #[test]
    fn dataset_type_display() {
        assert_eq!(DatasetType::Filesystem.to_string(), "filesystem");
        assert_eq!(DatasetType::Volume.to_string(), "volume");
        assert_eq!(DatasetType::Snapshot.to_string(), "snapshot");
    }

    #[test]
    fn dataset_flags_default_is_none() {
        assert!(DatasetFlags::default().is_empty());
        assert_eq!(DatasetFlags::default(), DatasetFlags::NONE);
    }

    #[test]
    fn dataset_flags_default_create_has_compression_and_checksums() {
        let f = DatasetFlags::default_create();
        assert!(f.contains(DatasetFlags::COMPRESSION));
        assert!(f.contains(DatasetFlags::CHECKSUMS));
        assert!(!f.contains(DatasetFlags::READONLY));
    }

    #[test]
    fn dataset_flags_bit_operations() {
        let mut f = DatasetFlags::NONE;
        assert!(f.is_empty());
        f |= DatasetFlags::READONLY;
        assert!(f.contains(DatasetFlags::READONLY));
        f |= DatasetFlags::COMPRESSION;
        assert!(f.contains(DatasetFlags::READONLY));
        assert!(f.contains(DatasetFlags::COMPRESSION));
    }

    #[test]
    fn dataset_flags_union_and_clone() {
        let f = DatasetFlags::CLONE.union(DatasetFlags::NO_AUTO_SNAPSHOT);
        assert!(f.contains(DatasetFlags::CLONE));
        assert!(f.contains(DatasetFlags::NO_AUTO_SNAPSHOT));
    }

    #[test]
    fn create_with_type_and_flags_roundtrip() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            100,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/fs",
            did(1),
            DatasetType::Filesystem,
            200,
            vec![0x01, 0x02, 0x03],
            DatasetFlags::default_create(),
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/vol",
            did(2),
            DatasetType::Volume,
            300,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/snap",
            did(3),
            DatasetType::Snapshot,
            400,
            empty_props(),
            DatasetFlags::READONLY.union(DatasetFlags::HIDDEN_SNAPDIR),
            SyncGuarantee::default(),
        )
        .unwrap();

        let children = cat.list_children_detailed("pool").unwrap();
        assert_eq!(children.len(), 3);

        let (fs_name, fs_id, fs_type, fs_txg, fs_flags) = &children[0];
        assert_eq!(fs_name, "fs");
        assert_eq!(*fs_id, did(1));
        assert_eq!(*fs_type, DatasetType::Filesystem);
        assert_eq!(*fs_txg, 200);
        assert!(fs_flags.contains(DatasetFlags::COMPRESSION));
        assert!(fs_flags.contains(DatasetFlags::CHECKSUMS));

        let (snap_name, snap_id, snap_type, snap_txg, snap_flags) = &children[1];
        assert_eq!(snap_name, "snap");
        assert_eq!(*snap_id, did(3));
        assert_eq!(*snap_type, DatasetType::Snapshot);
        assert_eq!(*snap_txg, 400);
        assert!(snap_flags.contains(DatasetFlags::READONLY));
        assert!(snap_flags.contains(DatasetFlags::HIDDEN_SNAPDIR));
    }

    #[test]
    fn list_children_detailed_empty() {
        assert!(DatasetCatalog::new()
            .list_children_detailed("pool")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_entry_returns_full_details() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(42),
            DatasetType::Filesystem,
            100,
            vec![0xAA, 0xBB],
            DatasetFlags::default_create(),
            SyncGuarantee::default(),
        )
        .unwrap();
        let entry = cat.get_entry("pool/a").unwrap();
        assert_eq!(entry.dataset_id, did(42));
        assert_eq!(entry.dataset_type, DatasetType::Filesystem);
        assert_eq!(entry.creation_txg, 100);
        assert_eq!(entry.properties, vec![0xAA, 0xBB]);
        assert!(entry.flags.contains(DatasetFlags::COMPRESSION));
    }

    #[test]
    fn rename_preserves_type_and_txg() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Volume,
            500,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.rename("pool/a", "pool/b").unwrap();
        let children = cat.list_children_detailed("pool").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].0, "b");
        assert_eq!(children[0].2, DatasetType::Volume);
        assert_eq!(children[0].3, 500);
    }

    #[test]
    fn create_clone_with_flag() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/clone1",
            did(10),
            DatasetType::Filesystem,
            100,
            empty_props(),
            DatasetFlags::CLONE.union(DatasetFlags::READONLY),
            SyncGuarantee::default(),
        )
        .unwrap();
        let entry = cat.get_entry("pool/clone1").unwrap();
        assert!(entry.flags.contains(DatasetFlags::CLONE));
        assert!(entry.flags.contains(DatasetFlags::READONLY));
    }

    #[test]
    fn properties_blob_roundtrip() {
        let props = b"compression=lz4\natime=off\n".to_vec();
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/tuned",
            did(99),
            DatasetType::Filesystem,
            200,
            props.clone(),
            DatasetFlags::COMPRESSION,
            SyncGuarantee::default(),
        )
        .unwrap();
        let entry = cat.get_entry("pool/tuned").unwrap();
        assert_eq!(entry.properties, props);
    }

    #[test]
    fn empty_properties_blob_works() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/plain",
            did(1),
            DatasetType::Filesystem,
            2,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat.get_entry("pool/plain").unwrap().properties.is_empty());
    }

    // ------------------------------------------------------------------
    // Lifecycle state transition tests
    // ------------------------------------------------------------------

    #[test]
    fn lifecycle_state_u8_roundtrip() {
        let states = [
            LifecycleState::Active,
            LifecycleState::Destroying,
            LifecycleState::Destroyed,
        ];
        for &s in &states {
            assert_eq!(LifecycleState::from_u8(s.to_u8()), Some(s));
        }
    }

    #[test]
    fn lifecycle_state_from_u8_invalid() {
        assert_eq!(LifecycleState::from_u8(3), None);
        assert_eq!(LifecycleState::from_u8(255), None);
    }

    #[test]
    fn lifecycle_state_display() {
        assert_eq!(LifecycleState::Active.to_string(), "active");
        assert_eq!(LifecycleState::Destroying.to_string(), "destroying");
        assert_eq!(LifecycleState::Destroyed.to_string(), "destroyed");
    }

    #[test]
    fn lifecycle_default_state_is_active() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.lifecycle_state("pool"), Ok(LifecycleState::Active));
    }

    #[test]
    fn lifecycle_transition_to_destroying() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool").unwrap();
        assert_eq!(cat.lifecycle_state("pool"), Ok(LifecycleState::Destroying));
    }

    #[test]
    fn lifecycle_transition_to_destroyed() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool").unwrap();
        cat.transition_to_destroyed("pool").unwrap();
        assert_eq!(cat.lifecycle_state("pool"), Ok(LifecycleState::Destroyed));
    }

    #[test]
    fn lifecycle_transition_to_destroyed_with_children_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool").unwrap();
        assert_eq!(
            cat.transition_to_destroyed("pool"),
            Err(CatalogError::HasChildren)
        );
        // State should still be Destroying
        assert_eq!(cat.lifecycle_state("pool"), Ok(LifecycleState::Destroying));
    }

    #[test]
    fn lifecycle_double_destroying_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool").unwrap();
        assert_eq!(
            cat.transition_to_destroying("pool"),
            Err(CatalogError::InvalidStateTransition)
        );
    }

    #[test]
    fn lifecycle_destroyed_to_anything_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool").unwrap();
        cat.transition_to_destroyed("pool").unwrap();
        assert_eq!(
            cat.transition_to_destroying("pool"),
            Err(CatalogError::InvalidStateTransition)
        );
        assert_eq!(
            cat.transition_to_destroyed("pool"),
            Err(CatalogError::InvalidStateTransition)
        );
    }

    #[test]
    fn lifecycle_active_to_destroyed_direct_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(
            cat.transition_to_destroyed("pool"),
            Err(CatalogError::InvalidStateTransition)
        );
    }

    // ------------------------------------------------------------------
    // get_by_id tests
    // ------------------------------------------------------------------

    #[test]
    fn get_by_id_found() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            100,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(42),
            DatasetType::Filesystem,
            200,
            empty_props(),
            DatasetFlags::default_create(),
            SyncGuarantee::default(),
        )
        .unwrap();
        let result = cat.get_by_id(&did(42)).unwrap();
        assert_eq!(result.0, "pool/a");
        assert_eq!(result.2, DatasetType::Filesystem);
        assert_eq!(result.3, 200);
        assert_eq!(result.5, LifecycleState::Active);
    }

    #[test]
    fn get_by_id_not_found() {
        let cat = DatasetCatalog::new();
        assert!(cat.get_by_id(&did(99)).is_none());
    }

    #[test]
    fn get_by_id_after_rename_still_works() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/original",
            did(77),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.rename("pool/original", "pool/renamed").unwrap();
        let result = cat.get_by_id(&did(77)).unwrap();
        assert_eq!(result.0, "pool/renamed");
    }

    // ------------------------------------------------------------------
    // get_by_name tests
    // ------------------------------------------------------------------

    #[test]
    fn get_by_name_found() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/myds",
            did(55),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert_eq!(cat.get_by_name("pool", "myds"), Some(did(55)));
    }

    #[test]
    fn get_by_name_not_found() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        assert!(cat.get_by_name("pool", "nonexistent").is_none());
    }

    // ------------------------------------------------------------------
    // list_all tests
    // ------------------------------------------------------------------

    #[test]
    fn list_all_empty() {
        assert!(DatasetCatalog::new().list_all().is_empty());
    }

    #[test]
    fn list_all_includes_lifecycle_state() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool/a").unwrap();
        let all = cat.list_all();
        assert_eq!(all.len(), 2);
        let pool_a = all
            .iter()
            .find(|(path, _, _, _, _, _)| path == "pool/a")
            .unwrap();
        assert_eq!(pool_a.5, LifecycleState::Destroying);
    }

    // ------------------------------------------------------------------
    // Encode/decode round-trip tests
    // ------------------------------------------------------------------

    #[test]
    fn encode_decode_empty_catalog() {
        let cat = DatasetCatalog::new();
        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn encode_decode_roundtrip_single_entry() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            100,
            vec![1, 2, 3],
            DatasetFlags::default_create(),
            SyncGuarantee::default(),
        )
        .unwrap();
        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();
        assert_eq!(decoded.lookup("pool"), Ok(did(0)));
        let entry = decoded.get_entry("pool").unwrap();
        assert_eq!(entry.dataset_type, DatasetType::Filesystem);
        assert_eq!(entry.creation_txg, 100);
        assert_eq!(entry.properties, vec![1, 2, 3]);
        assert_eq!(entry.lifecycle_state, LifecycleState::Active);
        assert!(entry.flags.contains(DatasetFlags::COMPRESSION));
    }

    #[test]
    fn encode_decode_roundtrip_multi_entry() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            2,
            vec![0xAA],
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Volume,
            3,
            empty_props(),
            DatasetFlags::default_create(),
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a/sub",
            did(10),
            DatasetType::Snapshot,
            4,
            empty_props(),
            DatasetFlags::CLONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();

        assert_eq!(decoded.len(), cat.len());
        assert_eq!(decoded.lookup("pool"), Ok(did(0)));
        assert_eq!(decoded.lookup("pool/a"), Ok(did(1)));
        assert_eq!(decoded.lookup("pool/b"), Ok(did(2)));
        assert_eq!(decoded.lookup("pool/a/sub"), Ok(did(10)));

        // Verify parent relationships preserved
        let entry_a = decoded.get_entry("pool/a").unwrap();
        assert_eq!(entry_a.parent, Some("pool".to_string()));
        let entry_sub = decoded.get_entry("pool/a/sub").unwrap();
        assert_eq!(entry_sub.parent, Some("pool/a".to_string()));
    }

    #[test]
    fn encode_decode_with_lifecycle_states() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/active",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/destroying",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/destroyed",
            did(3),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.transition_to_destroying("pool/destroying").unwrap();
        cat.transition_to_destroying("pool/destroyed").unwrap();
        cat.transition_to_destroyed("pool/destroyed").unwrap();

        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();

        assert_eq!(
            decoded.lifecycle_state("pool/active"),
            Ok(LifecycleState::Active)
        );
        assert_eq!(
            decoded.lifecycle_state("pool/destroying"),
            Ok(LifecycleState::Destroying)
        );
        assert_eq!(
            decoded.lifecycle_state("pool/destroyed"),
            Ok(LifecycleState::Destroyed)
        );
    }

    #[test]
    fn decode_empty_buffer_returns_empty_catalog() {
        let cat = DatasetCatalog::decode(&[]).unwrap();
        assert!(cat.is_empty());
    }

    #[test]
    fn decode_truncated_buffer_fails() {
        // Less than 36 bytes (4 header + 32 checksum)
        let data = [0u8; 10];
        assert!(matches!(
            DatasetCatalog::decode(&data),
            Err(CatalogError::CorruptEncoding)
        ));
    }

    #[test]
    fn decode_corrupt_checksum_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        let mut encoded = cat.encode();
        // Flip a byte in the middle of the checksum
        let len = encoded.len();
        encoded[len - 10] ^= 0xFF;
        assert!(matches!(
            DatasetCatalog::decode(&encoded),
            Err(CatalogError::CorruptEncoding)
        ));
    }

    #[test]
    fn decode_tampered_payload_fails() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        let mut encoded = cat.encode();
        // Corrupt the payload (not the checksum)
        if encoded.len() > 40 {
            encoded[10] ^= 0xFF;
        }
        assert!(matches!(
            DatasetCatalog::decode(&encoded),
            Err(CatalogError::CorruptEncoding)
        ));
    }

    #[test]
    fn encode_decode_roundtrip_properties_preserved() {
        let props = b"compression=lz4\natime=off\n".to_vec();
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/tuned",
            did(99),
            DatasetType::Filesystem,
            200,
            props.clone(),
            DatasetFlags::COMPRESSION,
            SyncGuarantee::default(),
        )
        .unwrap();
        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();
        let entry = decoded.get_entry("pool/tuned").unwrap();
        assert_eq!(entry.properties, props);
    }

    // ------------------------------------------------------------------
    // Property override merge tests
    // ------------------------------------------------------------------

    #[test]
    fn merge_property_overrides_empty_both() {
        let result = merge_property_overrides(b"", b"");
        assert!(result.is_empty());
    }

    #[test]
    fn merge_property_overrides_inherited_only() {
        let inherited = b"compression=lz4\natime=off\n";
        let result = merge_property_overrides(inherited, b"");
        assert_eq!(result, b"atime=off\ncompression=lz4\n");
    }

    #[test]
    fn merge_property_overrides_override_wins() {
        let inherited = b"compression=lz4\natime=off\n";
        let overrides = b"compression=zstd\nrecordsize=128k\n";
        let result = merge_property_overrides(inherited, overrides);
        // atime=off inherited, compression=zstd overrides lz4, recordsize added
        assert_eq!(result, b"atime=off\ncompression=zstd\nrecordsize=128k\n");
    }

    #[test]
    fn merge_property_overrides_override_only() {
        let overrides = b"sync=always\n";
        let result = merge_property_overrides(b"", overrides);
        assert_eq!(result, b"sync=always\n");
    }

    #[test]
    fn merge_property_overrides_empty_keys_ignored() {
        let inherited = b"=value\nkey=value\n";
        let result = merge_property_overrides(inherited, b"");
        assert_eq!(result, b"key=value\n");
    }

    #[test]
    fn merge_property_overrides_sorted_output() {
        let inherited = b"z=last\na=first\nm=middle\n";
        let result = merge_property_overrides(inherited, b"");
        assert_eq!(result, b"a=first\nm=middle\nz=last\n");
    }

    // ------------------------------------------------------------------
    // Concurrent reader safety test
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_readers_see_consistent_view() {
        // Simulate concurrent access: a read-only view should see a consistent
        // state even after mutations. Clone provides this snapshot isolation.
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/a",
            did(1),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.create(
            "pool/b",
            did(2),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();

        // Take a snapshot by cloning
        let reader = cat.clone();

        // Mutate the original
        cat.destroy("pool/a").unwrap();
        cat.rename("pool/b", "pool/c").unwrap();

        // Reader sees the old state
        assert!(reader.contains("pool/a"));
        assert!(reader.contains("pool/b"));
        assert!(!reader.contains("pool/c"));
    }

    #[test]
    fn catalog_error_display() {
        assert_eq!(
            CatalogError::NotFound.to_string(),
            "dataset not found in catalog"
        );
        assert_eq!(
            CatalogError::InvalidStateTransition.to_string(),
            "invalid lifecycle state transition"
        );
        assert_eq!(
            CatalogError::CorruptEncoding.to_string(),
            "catalog encoding is corrupt or checksum mismatch"
        );
    }

    #[test]
    fn encode_decode_roundtrip_sync_guarantee() {
        let mut cat = DatasetCatalog::new();
        cat.create(
            "pool",
            did(0),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::Local,
        )
        .unwrap();
        cat.create(
            "pool/remote",
            did(1),
            DatasetType::Filesystem,
            2,
            empty_props(),
            DatasetFlags::default_create(),
            SyncGuarantee::RemoteCopy,
        )
        .unwrap();
        cat.create(
            "pool/full",
            did(2),
            DatasetType::Volume,
            3,
            empty_props(),
            DatasetFlags::SYNC_WRITES,
            SyncGuarantee::FullRedundancy,
        )
        .unwrap();

        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();

        assert_eq!(decoded.sync_guarantee("pool"), Ok(SyncGuarantee::Local));
        assert_eq!(
            decoded.sync_guarantee("pool/remote"),
            Ok(SyncGuarantee::RemoteCopy)
        );
        assert_eq!(
            decoded.sync_guarantee("pool/full"),
            Ok(SyncGuarantee::FullRedundancy)
        );
    }

    // ------------------------------------------------------------------
    // Lineage validation tests
    // ------------------------------------------------------------------

    fn make_snap(
        cat: &mut DatasetCatalog,
        path: &str,
        id_n: u8,
        lineage_parent_id: DatasetId,
    ) {
        cat.create(
            path,
            did(id_n),
            DatasetType::Snapshot,
            100,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.set_lineage_parent(path, lineage_parent_id).unwrap();
    }

    fn make_clone(
        cat: &mut DatasetCatalog,
        path: &str,
        id_n: u8,
        lineage_parent_id: DatasetId,
    ) {
        cat.create(
            path,
            did(id_n),
            DatasetType::Filesystem,
            100,
            empty_props(),
            DatasetFlags::CLONE.union(DatasetFlags::READONLY),
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.set_lineage_parent(path, lineage_parent_id).unwrap();
    }

    fn make_filesystem(cat: &mut DatasetCatalog, path: &str, id_n: u8) {
        cat.create(
            path,
            did(id_n),
            DatasetType::Filesystem,
            1,
            empty_props(),
            DatasetFlags::NONE,
            SyncGuarantee::default(),
        )
        .unwrap();
    }

    // --- Acyclic publication -------------------------------------------------

    #[test]
    fn publish_root_acyclic_snapshot_chain() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));
        make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));

        cat.publish_root("pool/fs1@snap2").unwrap();

        assert!(cat.is_published("pool/fs1@snap2").unwrap());
        assert!(!cat.is_published("pool/fs1@snap1").unwrap());
    }

    #[test]
    fn publish_root_no_lineage_trivial_acyclic() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);

        // Filesystems without lineage parents are trivially publishable
        cat.publish_root("pool/fs1").unwrap();
        assert!(cat.is_published("pool/fs1").unwrap());
    }

    #[test]
    fn publish_root_single_snapshot_chain() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        cat.publish_root("pool/fs1@snap1").unwrap();
        assert!(cat.is_published("pool/fs1@snap1").unwrap());

        let summary = cat.lineage_summary("pool/fs1@snap1").unwrap();
        // Summary is non-zero (has content)
        assert_ne!(summary, [0u8; 32]);
    }

    // --- Direct cycle rejection -----------------------------------------------

    #[test]
    fn publish_rejects_direct_cycle_three_node_loop() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        // Create cycle: snap2 -> snap3 -> snap2 (triangular loop)
        make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));
        make_snap(&mut cat, "pool/fs1@snap3", 12, did(11));
        cat.set_lineage_parent("pool/fs1@snap2", did(12)).unwrap();

        // Publishing any node in the cycle should fail
        assert_eq!(
            cat.publish_root("pool/fs1@snap3"),
            Err(CatalogError::LineageCycle)
        );
    }

    #[test]
    fn publish_rejects_direct_cycle_simple_loop() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        // snap1 -> snap2, snap2 -> snap1 (cycle)
        make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));
        cat.set_lineage_parent("pool/fs1@snap1", did(11)).unwrap();

        assert_eq!(
            cat.publish_root("pool/fs1@snap1"),
            Err(CatalogError::LineageCycle)
        );
    }

    // --- Indirect cycle rejection ---------------------------------------------

    #[test]
    fn publish_rejects_indirect_cycle_three_nodes() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@A", 10, did(1));
        make_snap(&mut cat, "pool/fs1@B", 11, did(10));
        make_snap(&mut cat, "pool/fs1@C", 12, did(11));

        // Create cycle: A -> B -> C -> A
        cat.set_lineage_parent("pool/fs1@A", did(12)).unwrap();

        assert_eq!(
            cat.publish_root("pool/fs1@C"),
            Err(CatalogError::LineageCycle)
        );
    }

    #[test]
    fn publish_rejects_indirect_cycle_clone_chain() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_clone(&mut cat, "pool/clone1", 10, did(1));
        make_clone(&mut cat, "pool/clone2", 11, did(10));
        make_clone(&mut cat, "pool/clone3", 12, did(11));

        // Create cycle: clone1 -> clone2 -> clone3 -> clone1
        cat.set_lineage_parent("pool/clone1", did(12)).unwrap();

        assert_eq!(
            cat.publish_root("pool/clone3"),
            Err(CatalogError::LineageCycle)
        );
    }

    // --- Missing parent rejection ---------------------------------------------

    #[test]
    fn publish_rejects_missing_lineage_parent() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        // Create snap2 with a lineage parent that doesn't exist
        cat.create(
            "pool/fs1@snap2",
            did(20),
            DatasetType::Snapshot,
            100,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        // did(99) does not exist in catalog
        cat.set_lineage_parent("pool/fs1@snap2", did(99))
            .unwrap();

        assert_eq!(
            cat.publish_root("pool/fs1@snap2"),
            Err(CatalogError::LineageParentNotFound)
        );
    }

    #[test]
    fn publish_rejects_missing_transitive_parent() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        // snap2 -> snap1 (exists), but snap3 -> snap4 (doesn't exist)
        make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));
        cat.create(
            "pool/fs1@snap3",
            did(12),
            DatasetType::Snapshot,
            100,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        // did(99) does not exist, and snap3 -> did(99) -> ... is missing
        cat.set_lineage_parent("pool/fs1@snap3", did(99))
            .unwrap();

        assert_eq!(
            cat.publish_root("pool/fs1@snap3"),
            Err(CatalogError::LineageParentNotFound)
        );
    }

    // --- Wrong-dataset parent rejection ---------------------------------------

    #[test]
    fn publish_rejects_wrong_dataset_lineage_parent() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "poolA", 0);
        make_filesystem(&mut cat, "poolA/fs1", 1);
        make_filesystem(&mut cat, "poolB", 2);
        make_filesystem(&mut cat, "poolB/fs2", 3);

        // Snap in poolA claims lineage from poolB
        cat.create(
            "poolA/fs1@cross_snap",
            did(10),
            DatasetType::Snapshot,
            100,
            empty_props(),
            DatasetFlags::READONLY,
            SyncGuarantee::default(),
        )
        .unwrap();
        cat.set_lineage_parent("poolA/fs1@cross_snap", did(3))
            .unwrap();

        assert_eq!(
            cat.publish_root("poolA/fs1@cross_snap"),
            Err(CatalogError::LineageWrongDataset)
        );
    }

    // --- Duplicate edge rejection ---------------------------------------------

    #[test]
    fn publish_rejects_duplicate_edge() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);

        // Create a snapshot whose lineage_parent_id is the same as its own
        // dataset path parent -> that's fine. But duplicate edge means same
        // parent_id appearing consecutively which would require manual
        // corruption. We test: snap2 -> snap1, and snap2 has snap1 as
        // lineage_parent_id, but we also set it again somehow.
        //
        // However, a real duplicate edge would require two entries pointing
        // at the same parent. Since set_lineage_parent overwrites, we can't
        // create one naturally. Instead, test that a cycle where the same
        // node appears twice in sequence is caught.
        //
        // Actually, the duplicate edge check fires when visited.last() ==
        // Some(&parent_id). We can trigger this by having:
        // A -> B -> B (B points to itself)
        make_snap(&mut cat, "pool/fs1@A", 10, did(1));
        make_snap(&mut cat, "pool/fs1@B", 11, did(10));

        // Make B point to itself
        cat.set_lineage_parent("pool/fs1@B", did(11)).unwrap();

        // Self-loop is a duplicate edge
        assert_eq!(
            cat.publish_root("pool/fs1@B"),
            Err(CatalogError::LineageDuplicateEdge)
        );
    }

    // --- set_lineage_parent restrictions --------------------------------------

    #[test]
    fn set_lineage_parent_rejects_non_snapshot_non_clone() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);

        assert_eq!(
            cat.set_lineage_parent("pool/fs1", did(0)),
            Err(CatalogError::LineageNotSupported)
        );
    }

    #[test]
    fn set_lineage_parent_allows_snapshot() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));

        // Already set in make_snap, but verify it was accepted
        let entry = cat.get_entry("pool/fs1@snap1").unwrap();
        assert_eq!(entry.lineage_parent_id, Some(did(1)));
    }

    #[test]
    fn set_lineage_parent_allows_clone() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_clone(&mut cat, "pool/clone1", 10, did(1));

        let entry = cat.get_entry("pool/clone1").unwrap();
        assert_eq!(entry.lineage_parent_id, Some(did(1)));
    }

    // --- Already published ----------------------------------------------------

    #[test]
    fn publish_root_rejects_already_published() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);

        cat.publish_root("pool/fs1").unwrap();
        assert_eq!(
            cat.publish_root("pool/fs1"),
            Err(CatalogError::AlreadyPublished)
        );
    }

    // --- lineage_summary pre-publish -----------------------------------------

    #[test]
    fn lineage_summary_rejects_unpublished() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);

        assert_eq!(
            cat.lineage_summary("pool/fs1"),
            Err(CatalogError::NotPublished)
        );
    }

    // --- Lineage summary consistency ------------------------------------------

    #[test]
    fn lineage_summary_consistent_across_catalogs() {
        // Same lineage structure should produce the same summary
        let build = || {
            let mut cat = DatasetCatalog::new();
            make_filesystem(&mut cat, "pool", 0);
            make_filesystem(&mut cat, "pool/fs1", 1);
            make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));
            make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));
            cat.publish_root("pool/fs1@snap2").unwrap();
            cat
        };

        let cat1 = build();
        let cat2 = build();

        assert_eq!(
            cat1.lineage_summary("pool/fs1@snap2").unwrap(),
            cat2.lineage_summary("pool/fs1@snap2").unwrap()
        );
    }

    #[test]
    fn lineage_summary_differs_for_different_chains() {
        let mut cat1 = DatasetCatalog::new();
        make_filesystem(&mut cat1, "pool", 0);
        make_filesystem(&mut cat1, "pool/fs1", 1);
        make_snap(&mut cat1, "pool/fs1@snap1", 10, did(1));
        cat1.publish_root("pool/fs1@snap1").unwrap();

        let mut cat2 = DatasetCatalog::new();
        make_filesystem(&mut cat2, "pool", 0);
        make_filesystem(&mut cat2, "pool/fs1", 1);
        make_filesystem(&mut cat2, "pool/fs2", 2);
        make_snap(&mut cat2, "pool/fs1@snap1", 10, did(2)); // different parent
        cat2.publish_root("pool/fs1@snap1").unwrap();

        assert_ne!(
            cat1.lineage_summary("pool/fs1@snap1").unwrap(),
            cat2.lineage_summary("pool/fs1@snap1").unwrap()
        );
    }

    // --- Encode/decode roundtrip with lineage ---------------------------------

    #[test]
    fn encode_decode_roundtrip_lineage_data() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        make_snap(&mut cat, "pool/fs1@snap1", 10, did(1));
        make_snap(&mut cat, "pool/fs1@snap2", 11, did(10));
        cat.publish_root("pool/fs1@snap2").unwrap();

        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();

        // Verify lineage data survives roundtrip
        let entry = decoded.get_entry("pool/fs1@snap2").unwrap();
        assert_eq!(entry.lineage_parent_id, Some(did(10)));
        assert!(entry.published);
        assert_ne!(entry.lineage_summary, [0u8; 32]);

        // Unpublished entry should also survive
        let entry2 = decoded.get_entry("pool/fs1@snap1").unwrap();
        assert_eq!(entry2.lineage_parent_id, Some(did(1)));
        assert!(!entry2.published);
    }

    #[test]
    fn encode_decode_roundtrip_published_flag_independent() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        make_filesystem(&mut cat, "pool/fs1", 1);
        cat.publish_root("pool/fs1").unwrap();

        let encoded = cat.encode();
        let decoded = DatasetCatalog::decode(&encoded).unwrap();

        assert!(decoded.is_published("pool/fs1").unwrap());
        let summary = decoded.lineage_summary("pool/fs1").unwrap();
        assert_ne!(summary, [0u8; 32]);
    }

    // --- is_published tests ---------------------------------------------------

    #[test]
    fn is_published_returns_false_for_new_entries() {
        let mut cat = DatasetCatalog::new();
        make_filesystem(&mut cat, "pool", 0);
        assert!(!cat.is_published("pool").unwrap());
    }

    #[test]
    fn is_published_returns_not_found_for_missing() {
        let cat = DatasetCatalog::new();
        assert_eq!(
            cat.is_published("nonexistent"),
            Err(CatalogError::NotFound)
        );
    }

    // --- CatalogError Display for new variants --------------------------------

    #[test]
    fn catalog_error_display_lineage_variants() {
        assert_eq!(
            CatalogError::LineageCycle.to_string(),
            "clone or snapshot lineage contains a cycle"
        );
        assert_eq!(
            CatalogError::LineageParentNotFound.to_string(),
            "lineage parent dataset not found in catalog"
        );
        assert_eq!(
            CatalogError::LineageWrongDataset.to_string(),
            "lineage parent belongs to a different dataset authority"
        );
        assert_eq!(
            CatalogError::LineageDuplicateEdge.to_string(),
            "duplicate edge in clone or snapshot lineage"
        );
        assert_eq!(
            CatalogError::NotPublished.to_string(),
            "dataset root has not been published"
        );
        assert_eq!(
            CatalogError::AlreadyPublished.to_string(),
            "dataset root has already been published"
        );
        assert_eq!(
            CatalogError::LineageNotSupported.to_string(),
            "dataset type does not support lineage"
        );
    }
}
