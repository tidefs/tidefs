// Snapshot pruner: clone/origin dependency tracking, retention evaluation,
// and safe snapshot deletion.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use tidefs_local_object_store::LocalObjectStore;

use crate::retention::{group_by_bucket, BucketKind, SnapshotRetentionPolicy};

/// Well-known object-key prefix for the global clone dependency index.
pub const CLONE_INDEX_PREFIX: &str = "clone_index";
/// Well-known object-key prefix for the global origin dependency index.
pub const ORIGIN_INDEX_PREFIX: &str = "origin_index";
/// Well-known object-key prefix for snapshot integrity checksums.
pub const SNAPSHOT_CHECKSUM_PREFIX: &str = "snapshot_checksum";
/// Well-known object-key prefix for fail-closed snapshot prune pin evidence.
pub const SNAPSHOT_PIN_EVIDENCE_PREFIX: &str = "snapshot_pin_evidence";

const PIN_EVIDENCE_MAGIC: &[u8; 4] = b"SPIN";
const PIN_EVIDENCE_VERSION: u16 = 1;
const EVIDENCE_FIELD_MISSING: u8 = 0;
const EVIDENCE_FIELD_PRESENT: u8 = 1;
const CLONE_ORIGIN_PIN_CLONE_SNAPSHOT: u8 = 0;
const CLONE_ORIGIN_PIN_LIVE_DATASET: u8 = 1;

// ---------------------------------------------------------------------------
// SnapshotInfo / SnapshotPrunerStats
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub name: String,
    pub created_at: SystemTime,
    pub size_bytes: u64,
    pub txg_anchor: u64,
    pub ordinal: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotPrunerStats {
    pub datasets_processed: u64,
    pub snapshots_retained: u64,
    pub snapshots_destroyed: u64,
    pub bytes_freed: u64,
}

/// The committed root captured by a snapshot catalog entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotRootPin {
    pub txg_anchor: u64,
    pub committed_root_txg: u64,
    pub root_handle: u64,
}

impl SnapshotRootPin {
    #[must_use]
    pub fn from_snapshot_entry(entry: &tidefs_local_object_store::SnapshotEntry) -> Self {
        Self {
            txg_anchor: entry.txg_anchor.0,
            committed_root_txg: entry.committed_root.commit_group_id.0,
            root_handle: entry.committed_root.root_handle,
        }
    }

    #[must_use]
    pub fn matches_snapshot_entry(self, entry: &tidefs_local_object_store::SnapshotEntry) -> bool {
        self == Self::from_snapshot_entry(entry)
    }
}

/// A live clone or live dataset origin that protects a snapshot from pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloneOriginPinKind {
    CloneSnapshot,
    LiveDatasetOrigin,
}

impl CloneOriginPinKind {
    fn to_u8(&self) -> u8 {
        match self {
            CloneOriginPinKind::CloneSnapshot => CLONE_ORIGIN_PIN_CLONE_SNAPSHOT,
            CloneOriginPinKind::LiveDatasetOrigin => CLONE_ORIGIN_PIN_LIVE_DATASET,
        }
    }

    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            CLONE_ORIGIN_PIN_CLONE_SNAPSHOT => Some(CloneOriginPinKind::CloneSnapshot),
            CLONE_ORIGIN_PIN_LIVE_DATASET => Some(CloneOriginPinKind::LiveDatasetOrigin),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloneOriginPin {
    pub kind: CloneOriginPinKind,
    pub id: String,
}

impl CloneOriginPin {
    #[must_use]
    pub fn clone_snapshot(id: impl Into<String>) -> Self {
        Self {
            kind: CloneOriginPinKind::CloneSnapshot,
            id: id.into(),
        }
    }

    #[must_use]
    pub fn live_dataset_origin(id: impl Into<String>) -> Self {
        Self {
            kind: CloneOriginPinKind::LiveDatasetOrigin,
            id: id.into(),
        }
    }
}

/// A deadlist-protected object that blocks snapshot pruning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadlistPin {
    pub object_id: String,
}

impl DeadlistPin {
    #[must_use]
    pub fn new(object_id: impl Into<String>) -> Self {
        Self {
            object_id: object_id.into(),
        }
    }
}

/// Explicit pin evidence for one snapshot candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotPinEvidence {
    pub snapshot_root: SnapshotRootPin,
    pub clone_origin_pins: Option<Vec<CloneOriginPin>>,
    pub deadlist_pins: Option<Vec<DeadlistPin>>,
}

impl SnapshotPinEvidence {
    #[must_use]
    pub fn complete(
        snapshot_root: SnapshotRootPin,
        clone_origin_pins: Vec<CloneOriginPin>,
        deadlist_pins: Vec<DeadlistPin>,
    ) -> Self {
        Self {
            snapshot_root,
            clone_origin_pins: Some(clone_origin_pins),
            deadlist_pins: Some(deadlist_pins),
        }
    }
}

/// Persisted per-snapshot evidence used by retention planning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotPinEvidenceIndex {
    entries: BTreeMap<String, SnapshotPinEvidence>,
}

/// One candidate's prune plan decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotPruneDecision {
    pub snapshot_name: String,
    pub snapshot_id: String,
    pub snapshot_root: SnapshotRootPin,
    pub action: SnapshotPruneAction,
    pub clone_origin_pins: Vec<CloneOriginPin>,
    pub deadlist_pins: Vec<DeadlistPin>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotPruneAction {
    RetainByPolicy,
    Delete,
    Blocked(Vec<SnapshotPruneBlock>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotPruneBlock {
    IntegrityFailure(String),
    CloneOriginProtection,
    DeadlistPinProtection,
    MissingEvidence(String),
    CorruptEvidence(String),
    StoreFailure(String),
}

/// Result of a single [`SnapshotPruner::prune_dataset`] invocation.
///
/// Includes the retention delete set, protected/blocked candidates, and the
/// exact pin evidence seen while planning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneResult {
    /// Number of retention-policy candidates evaluated.
    pub candidates_evaluated: u64,
    /// Snapshots retained by policy before safety evidence was checked.
    pub retention_kept: u64,
    /// Snapshots successfully destroyed.
    pub destroyed: u64,
    /// Candidates blocked by a corrupt snapshot checksum.
    pub integrity_failures: u64,
    /// Candidates protected by live clone or live-origin evidence.
    pub clone_origin_protected: u64,
    /// Candidates protected by deadlist pin evidence.
    pub deadlist_pin_protected: u64,
    /// Candidates blocked because required pin evidence is missing.
    pub missing_evidence_blocks: u64,
    /// Candidates blocked because persisted pin evidence is corrupt or stale.
    pub corrupt_evidence_blocks: u64,
    /// Candidates blocked by object-store failures while planning.
    pub store_failures: u64,
    /// Retention candidates eligible for deletion after evidence checks.
    pub delete_set: Vec<String>,
    /// Per-snapshot plan decisions, including retention keeps.
    pub decisions: Vec<SnapshotPruneDecision>,
}
// ---------------------------------------------------------------------------
// SnapshotPrunerError
// ---------------------------------------------------------------------------

/// Errors returned by snapshot deletion operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotPrunerError {
    /// The requested snapshot does not exist in the dataset's catalog.
    SnapshotNotFound,
    /// The snapshot has one or more held clones referencing it as origin.
    HasClones,
    /// The snapshot is the origin of a live (non-snapshot) dataset.
    IsLiveDatasetOrigin,
    /// The snapshot failed BLAKE3 integrity verification before deletion.
    IntegrityFailure(String),
    /// Required prune pin evidence was absent.
    PinEvidenceMissing { reason: String },
    /// Persisted prune pin evidence could not be trusted.
    PinEvidenceCorrupt { reason: String },
    /// A retention policy constraint was violated.
    PolicyViolation(String),
    /// A store-level I/O or integrity error occurred.
    Store(String),
}

impl fmt::Display for SnapshotPrunerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotPrunerError::SnapshotNotFound => f.write_str("snapshot not found"),
            SnapshotPrunerError::HasClones => f.write_str("snapshot has held clones"),
            SnapshotPrunerError::IsLiveDatasetOrigin => {
                f.write_str("snapshot is the origin of a live dataset")
            }
            SnapshotPrunerError::IntegrityFailure(msg) => {
                write!(f, "snapshot integrity failure: {msg}")
            }
            SnapshotPrunerError::PinEvidenceMissing { reason } => {
                write!(f, "snapshot pin evidence missing: {reason}")
            }
            SnapshotPrunerError::PinEvidenceCorrupt { reason } => {
                write!(f, "snapshot pin evidence corrupt: {reason}")
            }
            SnapshotPrunerError::PolicyViolation(msg) => {
                write!(f, "policy violation: {msg}")
            }
            SnapshotPrunerError::Store(msg) => write!(f, "store error: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------

// CloneIndex — tracks parent→child clone dependency edges
// ---------------------------------------------------------------------------

/// Build the object key for a snapshot integrity checksum.
#[must_use]
pub fn snapshot_checksum_key(
    dataset_name: &str,
    snapshot_name: &str,
) -> tidefs_local_object_store::ObjectKey {
    tidefs_local_object_store::ObjectKey::from_name(
        format!("{SNAPSHOT_CHECKSUM_PREFIX}/{dataset_name}/{snapshot_name}").as_bytes(),
    )
}

/// Well-known object key for the snapshot prune pin-evidence singleton.
pub fn snapshot_pin_evidence_object_key() -> tidefs_local_object_store::ObjectKey {
    tidefs_local_object_store::ObjectKey::from_name(SNAPSHOT_PIN_EVIDENCE_PREFIX.as_bytes())
}

impl SnapshotPinEvidenceIndex {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(&self, snapshot_id: &str) -> Option<&SnapshotPinEvidence> {
        self.entries.get(snapshot_id)
    }

    pub fn insert(
        &mut self,
        snapshot_id: impl Into<String>,
        evidence: SnapshotPinEvidence,
    ) -> Option<SnapshotPinEvidence> {
        self.entries.insert(snapshot_id.into(), evidence)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(PIN_EVIDENCE_MAGIC);
        buf.extend_from_slice(&PIN_EVIDENCE_VERSION.to_le_bytes());
        buf.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());

        for (snapshot_id, evidence) in &self.entries {
            write_string(&mut buf, snapshot_id);
            buf.extend_from_slice(&evidence.snapshot_root.txg_anchor.to_le_bytes());
            buf.extend_from_slice(&evidence.snapshot_root.committed_root_txg.to_le_bytes());
            buf.extend_from_slice(&evidence.snapshot_root.root_handle.to_le_bytes());

            match &evidence.clone_origin_pins {
                Some(pins) => {
                    buf.push(EVIDENCE_FIELD_PRESENT);
                    buf.extend_from_slice(&(pins.len() as u32).to_le_bytes());
                    for pin in pins {
                        buf.push(pin.kind.to_u8());
                        write_string(&mut buf, &pin.id);
                    }
                }
                None => buf.push(EVIDENCE_FIELD_MISSING),
            }

            match &evidence.deadlist_pins {
                Some(pins) => {
                    buf.push(EVIDENCE_FIELD_PRESENT);
                    buf.extend_from_slice(&(pins.len() as u32).to_le_bytes());
                    for pin in pins {
                        write_string(&mut buf, &pin.object_id);
                    }
                }
                None => buf.push(EVIDENCE_FIELD_MISSING),
            }
        }

        buf
    }

    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        let mut off = 0usize;
        if payload.len() < PIN_EVIDENCE_MAGIC.len() + 2 + 4 {
            return None;
        }
        if &payload[..PIN_EVIDENCE_MAGIC.len()] != PIN_EVIDENCE_MAGIC {
            return None;
        }
        off += PIN_EVIDENCE_MAGIC.len();
        let version = read_u16(payload, &mut off)?;
        if version != PIN_EVIDENCE_VERSION {
            return None;
        }
        let count = read_u32(payload, &mut off)? as usize;
        let mut entries = BTreeMap::new();

        for _ in 0..count {
            let snapshot_id = read_string(payload, &mut off)?;
            let txg_anchor = read_u64(payload, &mut off)?;
            let committed_root_txg = read_u64(payload, &mut off)?;
            let root_handle = read_u64(payload, &mut off)?;
            let snapshot_root = SnapshotRootPin {
                txg_anchor,
                committed_root_txg,
                root_handle,
            };

            let clone_origin_pins = match read_u8(payload, &mut off)? {
                EVIDENCE_FIELD_MISSING => None,
                EVIDENCE_FIELD_PRESENT => {
                    let pin_count = read_u32(payload, &mut off)? as usize;
                    let mut pins = Vec::new();
                    for _ in 0..pin_count {
                        let kind = CloneOriginPinKind::from_u8(read_u8(payload, &mut off)?)?;
                        let id = read_string(payload, &mut off)?;
                        pins.push(CloneOriginPin { kind, id });
                    }
                    Some(pins)
                }
                _ => return None,
            };

            let deadlist_pins = match read_u8(payload, &mut off)? {
                EVIDENCE_FIELD_MISSING => None,
                EVIDENCE_FIELD_PRESENT => {
                    let pin_count = read_u32(payload, &mut off)? as usize;
                    let mut pins = Vec::new();
                    for _ in 0..pin_count {
                        pins.push(DeadlistPin::new(read_string(payload, &mut off)?));
                    }
                    Some(pins)
                }
                _ => return None,
            };

            entries.insert(
                snapshot_id,
                SnapshotPinEvidence {
                    snapshot_root,
                    clone_origin_pins,
                    deadlist_pins,
                },
            );
        }

        if off != payload.len() {
            return None;
        }

        Some(Self { entries })
    }

    pub fn load(store: &LocalObjectStore) -> Result<Option<Self>, SnapshotPrunerError> {
        match store.get(snapshot_pin_evidence_object_key()) {
            Ok(Some(payload)) => Self::decode(&payload).map(Some).ok_or_else(|| {
                SnapshotPrunerError::PinEvidenceCorrupt {
                    reason: "snapshot pin evidence payload does not match current format".into(),
                }
            }),
            Ok(None) => Ok(None),
            Err(e) => Err(SnapshotPrunerError::Store(format!("{e}"))),
        }
    }

    pub fn save(&self, store: &mut LocalObjectStore) -> Result<(), SnapshotPrunerError> {
        store
            .put(snapshot_pin_evidence_object_key(), &self.encode())
            .map(|_| ())
            .map_err(|e| SnapshotPrunerError::Store(format!("{e}")))
    }
}

fn write_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = u16::try_from(bytes.len()).expect("snapshot prune evidence string too long");
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(bytes);
}

fn read_u8(payload: &[u8], off: &mut usize) -> Option<u8> {
    let value = *payload.get(*off)?;
    *off += 1;
    Some(value)
}

fn read_u16(payload: &[u8], off: &mut usize) -> Option<u16> {
    if payload.len() < *off + 2 {
        return None;
    }
    let value = u16::from_le_bytes([payload[*off], payload[*off + 1]]);
    *off += 2;
    Some(value)
}

fn read_u32(payload: &[u8], off: &mut usize) -> Option<u32> {
    if payload.len() < *off + 4 {
        return None;
    }
    let value = u32::from_le_bytes([
        payload[*off],
        payload[*off + 1],
        payload[*off + 2],
        payload[*off + 3],
    ]);
    *off += 4;
    Some(value)
}

fn read_u64(payload: &[u8], off: &mut usize) -> Option<u64> {
    if payload.len() < *off + 8 {
        return None;
    }
    let value = u64::from_le_bytes([
        payload[*off],
        payload[*off + 1],
        payload[*off + 2],
        payload[*off + 3],
        payload[*off + 4],
        payload[*off + 5],
        payload[*off + 6],
        payload[*off + 7],
    ]);
    *off += 8;
    Some(value)
}

fn read_string(payload: &[u8], off: &mut usize) -> Option<String> {
    let len = read_u16(payload, off)? as usize;
    if payload.len() < *off + len {
        return None;
    }
    let value = String::from_utf8(payload[*off..*off + len].to_vec()).ok()?;
    *off += len;
    Some(value)
}

/// Global index mapping parent snapshots to the set of clone snapshots
/// derived from them. Used by `validate_destroy_permission` to reject
/// deletion of a snapshot that still has living clones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CloneIndex {
    /// `parent_id` → set of `clone_id` (both formatted as `"dataset/snapshot"`).
    edges: BTreeMap<String, BTreeSet<String>>,
}

/// Well-known object key for the global clone index singleton.
pub fn clone_index_object_key() -> tidefs_local_object_store::ObjectKey {
    tidefs_local_object_store::ObjectKey::from_name(CLONE_INDEX_PREFIX.as_bytes())
}

impl CloneIndex {
    /// Record a clone relationship: `clone_id` is derived from `parent_id`.
    pub fn insert(&mut self, parent_id: &str, clone_id: &str) {
        self.edges
            .entry(parent_id.to_string())
            .or_default()
            .insert(clone_id.to_string());
    }

    /// Remove a clone relationship.
    ///
    /// Returns `true` if the relationship existed and was removed.
    pub fn remove(&mut self, parent_id: &str, clone_id: &str) -> bool {
        if let Some(children) = self.edges.get_mut(parent_id) {
            let removed = children.remove(clone_id);
            if children.is_empty() {
                self.edges.remove(parent_id);
            }
            removed
        } else {
            false
        }
    }

    /// Remove all clone edges where `clone_id` appears as a child.
    ///
    /// Used when a clone snapshot itself is destroyed.
    pub fn remove_all_clone_edges_for(&mut self, clone_id: &str) {
        self.edges.retain(|_parent, children| {
            children.remove(clone_id);
            !children.is_empty()
        });
    }

    /// Returns `true` when `parent_id` has at least one living clone.
    pub fn has_clones(&self, parent_id: &str) -> bool {
        self.edges.get(parent_id).is_some_and(|s| !s.is_empty())
    }

    /// Number of direct clones of `parent_id`.
    pub fn clone_count(&self, parent_id: &str) -> usize {
        self.edges.get(parent_id).map_or(0, |s| s.len())
    }

    /// Iterate over all clone IDs that are children of `parent_id`.
    pub fn clones_of<'a>(&'a self, parent_id: &str) -> Box<dyn Iterator<Item = &'a str> + 'a> {
        match self.edges.get(parent_id) {
            Some(set) => Box::new(set.iter().map(|s| s.as_str())),
            None => Box::new(std::iter::empty()),
        }
    }

    /// Total number of parent→child edges in the index.
    pub fn total_edges(&self) -> usize {
        self.edges.values().map(|s| s.len()).sum()
    }

    /// Number of parents that have at least one clone.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// Encode the clone index into a binary payload.
    ///
    /// Wire format (little-endian):
    /// - entry_count: u32
    /// - For each parent entry:
    ///   - parent_id_len: u16
    ///   - parent_id: UTF-8 bytes
    ///   - child_count: u32
    ///   - For each child:
    ///     - child_id_len: u16
    ///     - child_id: UTF-8 bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.edges.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        // Sort keys for deterministic encoding
        let mut sorted_parents: Vec<&String> = self.edges.keys().collect();
        sorted_parents.sort();

        for parent_id in sorted_parents {
            let parent_bytes = parent_id.as_bytes();
            let parent_len = parent_bytes.len().min(u16::MAX as usize) as u16;
            buf.extend_from_slice(&parent_len.to_le_bytes());
            buf.extend_from_slice(parent_bytes);

            let children = &self.edges[parent_id];
            let child_count = children.len() as u32;
            buf.extend_from_slice(&child_count.to_le_bytes());

            let mut sorted_children: Vec<&String> = children.iter().collect();
            sorted_children.sort();
            for child_id in sorted_children {
                let child_bytes = child_id.as_bytes();
                let child_len = child_bytes.len().min(u16::MAX as usize) as u16;
                buf.extend_from_slice(&child_len.to_le_bytes());
                buf.extend_from_slice(child_bytes);
            }
        }
        buf
    }

    /// Decode a clone index from a binary payload.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 4 {
            return None;
        }
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut edges = BTreeMap::new();
        let mut off = 4;

        for _ in 0..count {
            if payload.len() < off + 2 {
                return None;
            }
            let parent_len = u16::from_le_bytes([payload[off], payload[off + 1]]) as usize;
            off += 2;
            if payload.len() < off + parent_len + 4 {
                return None;
            }
            let parent_id = String::from_utf8(payload[off..off + parent_len].to_vec()).ok()?;
            off += parent_len;

            let child_count = u32::from_le_bytes([
                payload[off],
                payload[off + 1],
                payload[off + 2],
                payload[off + 3],
            ]) as usize;
            off += 4;

            let mut children = BTreeSet::new();
            for _ in 0..child_count {
                if payload.len() < off + 2 {
                    return None;
                }
                let child_len = u16::from_le_bytes([payload[off], payload[off + 1]]) as usize;
                off += 2;
                if payload.len() < off + child_len {
                    return None;
                }
                let child_id = String::from_utf8(payload[off..off + child_len].to_vec()).ok()?;
                off += child_len;
                children.insert(child_id);
            }
            edges.insert(parent_id, children);
        }
        Some(Self { edges })
    }

    /// Load the clone index from the object store, or return a default
    /// empty index when no persisted copy exists.
    pub fn load(store: &LocalObjectStore) -> Self {
        let key = clone_index_object_key();
        match store.get(key) {
            Ok(Some(data)) => Self::decode(&data).unwrap_or_default(),
            _ => Self::default(),
        }
    }

    /// Persist the clone index into the object store.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the write fails.
    pub fn save(&self, store: &mut LocalObjectStore) -> Result<(), String> {
        let key = clone_index_object_key();
        store.put(key, &self.encode()).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OriginIndex — tracks live-dataset → origin-snapshot edges
// ---------------------------------------------------------------------------

/// Global index mapping live (non-snapshot) dataset names to the snapshot
/// identifier from which they were created. Used by
/// `validate_destroy_permission` to reject deletion of a snapshot that is
/// still the origin of an active dataset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginIndex {
    /// `dataset_name` → `origin_snapshot_id` (formatted as `"dataset/snapshot"`).
    origins: BTreeMap<String, String>,
}

/// Well-known object key for the global origin index singleton.
pub fn origin_index_object_key() -> tidefs_local_object_store::ObjectKey {
    tidefs_local_object_store::ObjectKey::from_name(ORIGIN_INDEX_PREFIX.as_bytes())
}

impl OriginIndex {
    /// Record that `dataset_name` was created from `origin_snapshot_id`.
    ///
    /// If the dataset already had an origin, it is replaced.
    pub fn insert(&mut self, dataset_name: &str, origin_snapshot_id: &str) {
        self.origins
            .insert(dataset_name.to_string(), origin_snapshot_id.to_string());
    }

    /// Remove the origin entry for `dataset_name`.
    ///
    /// Returns `true` if an entry existed and was removed.
    pub fn remove(&mut self, dataset_name: &str) -> bool {
        self.origins.remove(dataset_name).is_some()
    }

    /// Returns `true` when `snapshot_id` is the origin of at least one
    /// live dataset.
    pub fn is_origin_of_live_dataset(&self, snapshot_id: &str) -> bool {
        self.origins.values().any(|origin| origin == snapshot_id)
    }

    /// Return the origin snapshot id for `dataset_name`, if any.
    pub fn origin_of(&self, dataset_name: &str) -> Option<&str> {
        self.origins.get(dataset_name).map(|s| s.as_str())
    }

    /// Iterate over live datasets that use `snapshot_id` as their origin.
    pub fn live_datasets_for_origin<'a>(
        &'a self,
        snapshot_id: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.origins.iter().filter_map(move |(dataset, origin)| {
            if origin == snapshot_id {
                Some(dataset.as_str())
            } else {
                None
            }
        })
    }

    /// Number of origin entries.
    pub fn len(&self) -> usize {
        self.origins.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
    }

    /// Encode the origin index into a binary payload.
    ///
    /// Wire format (little-endian):
    /// - entry_count: u32
    /// - For each entry:
    ///   - dataset_name_len: u16
    ///   - dataset_name: UTF-8 bytes
    ///   - origin_id_len: u16
    ///   - origin_id: UTF-8 bytes
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let count = self.origins.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());

        // Sort keys for deterministic encoding
        let mut sorted: Vec<&String> = self.origins.keys().collect();
        sorted.sort();

        for dataset_name in sorted {
            let name_bytes = dataset_name.as_bytes();
            let name_len = name_bytes.len().min(u16::MAX as usize) as u16;
            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(name_bytes);

            let origin_id = &self.origins[dataset_name];
            let origin_bytes = origin_id.as_bytes();
            let origin_len = origin_bytes.len().min(u16::MAX as usize) as u16;
            buf.extend_from_slice(&origin_len.to_le_bytes());
            buf.extend_from_slice(origin_bytes);
        }
        buf
    }

    /// Decode an origin index from a binary payload.
    #[must_use]
    pub fn decode(payload: &[u8]) -> Option<Self> {
        if payload.len() < 4 {
            return None;
        }
        let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        let mut origins = BTreeMap::new();
        let mut off = 4;

        for _ in 0..count {
            if payload.len() < off + 2 {
                return None;
            }
            let name_len = u16::from_le_bytes([payload[off], payload[off + 1]]) as usize;
            off += 2;
            if payload.len() < off + name_len + 2 {
                return None;
            }
            let dataset_name = String::from_utf8(payload[off..off + name_len].to_vec()).ok()?;
            off += name_len;

            let origin_len = u16::from_le_bytes([payload[off], payload[off + 1]]) as usize;
            off += 2;
            if payload.len() < off + origin_len {
                return None;
            }
            let origin_id = String::from_utf8(payload[off..off + origin_len].to_vec()).ok()?;
            off += origin_len;

            origins.insert(dataset_name, origin_id);
        }
        Some(Self { origins })
    }

    /// Load the origin index from the object store, or return a default
    /// empty index when no persisted copy exists.
    pub fn load(store: &LocalObjectStore) -> Self {
        let key = origin_index_object_key();
        match store.get(key) {
            Ok(Some(data)) => Self::decode(&data).unwrap_or_default(),
            _ => Self::default(),
        }
    }

    /// Persist the origin index into the object store.
    ///
    /// # Errors
    ///
    /// Returns `StoreError` if the write fails.
    pub fn save(&self, store: &mut LocalObjectStore) -> Result<(), String> {
        let key = origin_index_object_key();
        store.put(key, &self.encode()).map_err(|e| format!("{e}"))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SnapshotPruner

// ---------------------------------------------------------------------------

pub struct SnapshotPruner {
    extent_pin_set: Option<tidefs_gc_pin_set::SnapshotExtentPinSet>,
    policy: SnapshotRetentionPolicy,
    stats: SnapshotPrunerStats,
    clone_index: CloneIndex,
    origin_index: OriginIndex,
}

impl SnapshotPruner {
    /// Create a pruner with empty in-memory indices.
    ///
    /// Prefer [`SnapshotPruner::load`] when a store is available so that
    /// previously persisted clone and origin dependencies are respected.
    pub fn new(policy: SnapshotRetentionPolicy) -> Self {
        Self {
            policy,
            stats: SnapshotPrunerStats::default(),
            clone_index: CloneIndex::default(),
            extent_pin_set: None,
            origin_index: OriginIndex::default(),
        }
    }

    /// Load a pruner with persisted clone and origin indices from the
    /// object store.
    pub fn load(store: &LocalObjectStore, policy: SnapshotRetentionPolicy) -> Self {
        Self {
            policy,
            stats: SnapshotPrunerStats::default(),
            clone_index: CloneIndex::load(store),
            extent_pin_set: None,
            origin_index: OriginIndex::load(store),
        }
    }

    /// Borrow the clone index (read-only).
    pub fn clone_index(&self) -> &CloneIndex {
        &self.clone_index
    }

    /// Borrow the clone index mutably.
    pub fn clone_index_mut(&mut self) -> &mut CloneIndex {
        &mut self.clone_index
    }

    /// Borrow the origin index (read-only).
    pub fn origin_index(&self) -> &OriginIndex {
        &self.origin_index
    }

    /// Borrow the origin index mutably.
    pub fn origin_index_mut(&mut self) -> &mut OriginIndex {
        &mut self.origin_index
    }

    /// Record a clone relationship and persist it.
    ///
    /// `parent_id` and `clone_id` are formatted as `"dataset/snapshot"`.
    ///
    /// # Errors
    ///
    /// Returns a store error if persistence fails.
    pub fn record_clone(
        &mut self,
        store: &mut LocalObjectStore,
        parent_id: &str,
        clone_id: &str,
    ) -> Result<(), SnapshotPrunerError> {
        self.clone_index.insert(parent_id, clone_id);
        self.clone_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)
    }

    /// Remove a clone relationship and persist.
    ///
    /// # Errors
    ///
    /// Returns a store error if persistence fails.
    pub fn remove_clone(
        &mut self,
        store: &mut LocalObjectStore,
        parent_id: &str,
        clone_id: &str,
    ) -> Result<(), SnapshotPrunerError> {
        self.clone_index.remove(parent_id, clone_id);
        self.clone_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)
    }

    /// Record a dataset origin and persist.
    ///
    /// `dataset_name` is the live dataset; `origin_snapshot_id` is the
    /// snapshot from which it was created (formatted as `"dataset/snapshot"`).
    ///
    /// # Errors
    ///
    /// Returns a store error if persistence fails.
    pub fn record_origin(
        &mut self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        origin_snapshot_id: &str,
    ) -> Result<(), SnapshotPrunerError> {
        self.origin_index.insert(dataset_name, origin_snapshot_id);
        self.origin_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)
    }

    /// Remove a dataset origin entry and persist.
    ///
    /// # Errors
    ///
    /// Returns a store error if persistence fails.
    pub fn remove_origin(
        &mut self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
    ) -> Result<(), SnapshotPrunerError> {
        self.origin_index.remove(dataset_name);
        self.origin_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)
    }

    /// Persist both indices into the object store.
    ///
    /// # Errors
    ///
    /// Returns a store error if either write fails.
    pub fn save_indices(&self, store: &mut LocalObjectStore) -> Result<(), SnapshotPrunerError> {
        self.clone_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)?;
        self.origin_index
            .save(store)
            .map_err(SnapshotPrunerError::Store)
    }

    /// Reload both indices from the object store.
    pub fn reload_indices(&mut self, store: &LocalObjectStore) {
        self.clone_index = CloneIndex::load(store);
        self.origin_index = OriginIndex::load(store);
    }

    fn live_clone_origin_pins(&self, snapshot_id: &str) -> Vec<CloneOriginPin> {
        self.clone_index
            .clones_of(snapshot_id)
            .map(CloneOriginPin::clone_snapshot)
            .chain(
                self.origin_index
                    .live_datasets_for_origin(snapshot_id)
                    .map(CloneOriginPin::live_dataset_origin),
            )
            .collect()
    }

    /// Record complete fail-closed prune evidence for one snapshot.
    ///
    /// The snapshot root is read from the current snapshot catalog. Empty
    /// `clone_origin_pins` or `deadlist_pins` are explicit negative evidence;
    /// missing fields are represented only by constructing and saving
    /// [`SnapshotPinEvidenceIndex`] directly.
    pub fn record_snapshot_pin_evidence(
        &self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
        clone_origin_pins: Vec<CloneOriginPin>,
        deadlist_pins: Vec<DeadlistPin>,
    ) -> Result<(), SnapshotPrunerError> {
        let snapshots = store.list_snapshots(dataset_name);
        let entry = snapshots
            .iter()
            .find(|s| s.name == snapshot_name)
            .ok_or(SnapshotPrunerError::SnapshotNotFound)?;
        let snapshot_id = format!("{dataset_name}/{snapshot_name}");
        let evidence = SnapshotPinEvidence::complete(
            SnapshotRootPin::from_snapshot_entry(entry),
            clone_origin_pins,
            deadlist_pins,
        );

        let mut index = SnapshotPinEvidenceIndex::load(store)?.unwrap_or_default();
        index.insert(snapshot_id, evidence);
        index.save(store)
    }

    pub fn policy(&self) -> &SnapshotRetentionPolicy {
        &self.policy
    }
    pub fn set_policy(&mut self, p: SnapshotRetentionPolicy) {
        self.policy = p;
    }
    pub fn stats(&self) -> SnapshotPrunerStats {
        self.stats.clone()
    }

    /// Attach a snapshot-extent pin set for reclaim gating.
    ///
    /// After a snapshot is destroyed, its extents must be released from
    /// the pin set so that reclaim can free them. Call this before
    /// [`prune_dataset`] to enable automatic pin release.
    pub fn set_extent_pin_set(&mut self, pin_set: tidefs_gc_pin_set::SnapshotExtentPinSet) {
        self.extent_pin_set = Some(pin_set);
    }

    /// Take the pin set back out (e.g. for persistence or to pass to reclaim).
    pub fn take_extent_pin_set(&mut self) -> Option<tidefs_gc_pin_set::SnapshotExtentPinSet> {
        self.extent_pin_set.take()
    }

    // -- Retention policy evaluation (auto-pruner) -----------------------

    pub fn evaluate(&self, snapshots: &[SnapshotInfo], now: SystemTime) -> Vec<String> {
        if self.policy.is_empty() || snapshots.is_empty() {
            return Vec::new();
        }
        let mut sorted: Vec<&SnapshotInfo> = snapshots.iter().collect();
        sorted.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.txg_anchor.cmp(&a.txg_anchor))
                .then_with(|| b.ordinal.cmp(&a.ordinal))
        });

        let has_pos = self.policy.keep_last.is_some()
            || self.policy.keep_hourly.unwrap_or(0) > 0
            || self.policy.keep_daily.unwrap_or(0) > 0
            || self.policy.keep_weekly.unwrap_or(0) > 0
            || self.policy.keep_monthly.unwrap_or(0) > 0
            || self.policy.keep_yearly.unwrap_or(0) > 0;

        let mut retained: HashSet<&str> = HashSet::new();
        if !has_pos {
            for info in &sorted {
                retained.insert(info.name.as_str());
            }
        }

        if let Some(n) = self.policy.keep_last {
            for info in sorted.iter().take(n as usize) {
                retained.insert(info.name.as_str());
            }
        }

        let specs: &[(Option<u32>, BucketKind)] = &[
            (self.policy.keep_hourly, BucketKind::Hourly),
            (self.policy.keep_daily, BucketKind::Daily),
            (self.policy.keep_weekly, BucketKind::Weekly),
            (self.policy.keep_monthly, BucketKind::Monthly),
            (self.policy.keep_yearly, BucketKind::Yearly),
        ];
        for &(keep_n, kind) in specs {
            if let Some(n) = keep_n {
                if n == 0 {
                    continue;
                }
                for (_k, g) in &group_by_bucket(&sorted, kind) {
                    let mut cnt = 0u32;
                    for info in g {
                        if cnt >= n {
                            break;
                        }
                        if retained.contains(info.name.as_str()) {
                            continue;
                        }
                        retained.insert(info.name.as_str());
                        cnt += 1;
                    }
                }
            }
        }

        if let Some(d) = self.policy.max_age_days {
            let cutoff = now
                .checked_sub(Duration::from_secs(d as u64 * 86400))
                .unwrap_or(UNIX_EPOCH);
            for info in &sorted {
                if info.created_at < cutoff {
                    retained.remove(info.name.as_str());
                }
            }
        }

        if let Some(cap) = self.policy.max_snapshots {
            let surv = retained.len();
            if surv > cap as usize {
                let mut excess = surv - cap as usize;
                for info in sorted.iter().rev() {
                    if excess == 0 {
                        break;
                    }
                    if retained.remove(info.name.as_str()) {
                        excess -= 1;
                    }
                }
            }
        }

        let mut td: Vec<String> = sorted
            .iter()
            .rev()
            .filter(|info| !retained.contains(info.name.as_str()))
            .map(|info| info.name.clone())
            .collect();
        td.dedup();
        td
    }

    pub fn record_outcome(&mut self, ss: &[SnapshotInfo], destroyed: &[String]) {
        self.stats.datasets_processed = self.stats.datasets_processed.saturating_add(1);
        let ds: HashSet<&str> = destroyed.iter().map(|s| s.as_str()).collect();
        let mut bf = 0u64;
        let mut dc = 0u64;
        for i in ss {
            if ds.contains(i.name.as_str()) {
                dc += 1;
                bf = bf.saturating_add(i.size_bytes);
            }
        }
        self.stats.snapshots_destroyed = self.stats.snapshots_destroyed.saturating_add(dc);
        self.stats.snapshots_retained = self
            .stats
            .snapshots_retained
            .saturating_add(ss.len() as u64 - dc);
        self.stats.bytes_freed = self.stats.bytes_freed.saturating_add(bf);
    }

    // ------------------------------------------------------------------
    // Explicit snapshot deletion (issue #5189) — four-phase destroy
    // ------------------------------------------------------------------

    /// Compute a BLAKE3 domain-separated integrity checksum for a snapshot entry.
    ///
    /// The checksum covers the entry's name, txg_anchor, committed_root,
    /// created_at, and parent_dataset_key. It is stored as a separate
    /// object under `SNAPSHOT_CHECKSUM_PREFIX` and verified before
    /// the pruner allows deletion.
    ///
    /// # Errors
    ///
    /// Returns `IntegrityFailure` if a stored checksum exists and does not
    /// match the freshly computed one. Returns `Store` if the store
    /// read or write fails.
    pub fn verify_snapshot_integrity(
        &self,
        store: &LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<(), SnapshotPrunerError> {
        let snapshots = store.list_snapshots(dataset_name);
        let entry = snapshots
            .iter()
            .find(|s| s.name == snapshot_name)
            .ok_or(SnapshotPrunerError::SnapshotNotFound)?;

        // Domain-separated BLAKE3 hash of the encoded entry
        let mut hasher = Hasher::new_derive_key("TideFS snapshot-pruner integrity v1");
        hasher.update(entry.encode().as_slice());
        let computed = hasher.finalize();

        let ck = snapshot_checksum_key(dataset_name, snapshot_name);
        let stored = store.get(ck);
        match stored {
            Ok(Some(data)) => {
                if data.len() != 32 {
                    return Err(SnapshotPrunerError::IntegrityFailure(format!(
                        "stored checksum for {}/{} has invalid length {} (expected 32)",
                        dataset_name,
                        snapshot_name,
                        data.len()
                    )));
                }
                let mut expected = [0u8; 32];
                expected.copy_from_slice(&data);
                if computed != blake3::Hash::from(expected) {
                    return Err(SnapshotPrunerError::IntegrityFailure(
                        format!(
                            "checksum mismatch for {dataset_name}/{snapshot_name}: stored hash does not match computed entry hash",
                        ),
                    ));
                }
                Ok(())
            }
            Ok(None) => {
                // No stored checksum yet — compute and store one
                // (read-only store context; caller must store separately)
                Ok(())
            }
            Err(e) => Err(SnapshotPrunerError::Store(format!("{e}"))),
        }
    }

    /// Store a BLAKE3 integrity checksum for a snapshot entry.
    ///
    /// Computes and persists a domain-separated BLAKE3 hash of the
    /// snapshot entry, enabling future integrity verification before deletion.
    pub fn store_snapshot_checksum(
        &self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<(), SnapshotPrunerError> {
        let snapshots = store.list_snapshots(dataset_name);
        let entry = snapshots
            .iter()
            .find(|s| s.name == snapshot_name)
            .ok_or(SnapshotPrunerError::SnapshotNotFound)?;

        let mut hasher = Hasher::new_derive_key("TideFS snapshot-pruner integrity v1");
        hasher.update(entry.encode().as_slice());
        let hash = hasher.finalize();

        let ck = snapshot_checksum_key(dataset_name, snapshot_name);
        store
            .put(ck, hash.as_bytes())
            .map(|_| ())
            .map_err(|e| SnapshotPrunerError::Store(format!("{e}")))
    }

    /// Validate that a snapshot can be safely destroyed.
    ///
    /// Phase 1 of the destroy pipeline. Returns `Ok(())` when the snapshot
    /// exists, has no living clones, and is not the origin of any live
    /// dataset. Callers should gate `destroy_snapshot` behind this check
    /// before committing to deletion.
    pub fn validate_destroy_permission(
        &self,
        store: &LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<(), SnapshotPrunerError> {
        // Existence check
        let snapshots = store.list_snapshots(dataset_name);
        if !snapshots.iter().any(|s| s.name == snapshot_name) {
            return Err(SnapshotPrunerError::SnapshotNotFound);
        }

        // Clone-held check
        let snapshot_id = format!("{dataset_name}/{snapshot_name}");
        if self.clone_index.has_clones(&snapshot_id) {
            return Err(SnapshotPrunerError::HasClones);
        }

        // Live-dataset origin check
        if self.origin_index.is_origin_of_live_dataset(&snapshot_id) {
            return Err(SnapshotPrunerError::IsLiveDatasetOrigin);
        }

        Ok(())
    }

    /// Destroy a snapshot with four-phase validation and cleanup.
    ///
    /// Phase 1 (permission validation): verifies the snapshot exists.
    /// Caller is responsible for clone and origin safety checks.
    ///
    /// Phases 2-4 (commit_group anchor release, catalog entry removal, object
    /// dead-marking): delegated to [`LocalObjectStore::destroy_snapshot`],
    /// which removes the catalog entry, persists the updated catalog,
    /// deletes the entry object, and enqueues a reclaim entry so the
    /// segment cleaner can eventually reclaim the dead space.
    ///
    /// Returns the removed [`SnapshotEntry`] on success.
    pub fn destroy_snapshot(
        &mut self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        snapshot_name: &str,
    ) -> Result<tidefs_local_object_store::SnapshotEntry, SnapshotPrunerError> {
        // Phase 1: validate
        self.validate_destroy_permission(store, dataset_name, snapshot_name)?;

        // Phase 1b: BLAKE3 integrity verification
        self.verify_snapshot_integrity(store, dataset_name, snapshot_name)?;

        // Phases 2-4: delegate to the store
        let entry = store
            .destroy_snapshot(dataset_name, snapshot_name)
            .map_err(|e| SnapshotPrunerError::Store(format!("{e}")))?
            .ok_or(SnapshotPrunerError::SnapshotNotFound)?;

        // Record outcome for stats
        let info = SnapshotInfo {
            name: entry.name.clone(),
            created_at: entry.created_at,
            size_bytes: 0,
            txg_anchor: entry.txg_anchor.0,
            ordinal: 0,
        };
        self.record_outcome(&[info], &[entry.name.clone()]);

        Ok(entry)
    }

    // -- Automated dataset prune (retention + fail-closed safety) --------

    /// Plan a retention-driven prune without deleting snapshots.
    ///
    /// Every retention candidate must have explicit per-snapshot pin evidence
    /// before it can enter the delete set. Missing fields, stale/corrupt
    /// evidence, clone-origin pins, deadlist pins, and checksum failures are
    /// reported as blocked plan decisions.
    #[must_use]
    pub fn plan_dataset_prune(
        &self,
        store: &LocalObjectStore,
        dataset_name: &str,
        now: SystemTime,
    ) -> PruneResult {
        let snapshots = store.list_snapshots(dataset_name);
        if snapshots.is_empty() {
            return PruneResult::default();
        }

        let infos: Vec<SnapshotInfo> = snapshots
            .iter()
            .enumerate()
            .map(|(i, e)| SnapshotInfo {
                name: e.name.clone(),
                created_at: e.created_at,
                size_bytes: 0,
                txg_anchor: e.txg_anchor.0,
                ordinal: i as u64,
            })
            .collect();

        // Evaluate retention: candidates are oldest-first
        let candidates = self.evaluate(&infos, now);
        let total_candidates = candidates.len() as u64;
        let candidate_names: HashSet<&str> = candidates.iter().map(|s| s.as_str()).collect();
        let evidence_index = SnapshotPinEvidenceIndex::load(store);
        let mut result = PruneResult {
            candidates_evaluated: total_candidates,
            retention_kept: snapshots.len() as u64 - total_candidates,
            ..Default::default()
        };

        for entry in snapshots
            .iter()
            .filter(|entry| !candidate_names.contains(entry.name.as_str()))
        {
            let snapshot_id = format!("{dataset_name}/{}", entry.name);
            result.decisions.push(SnapshotPruneDecision {
                snapshot_name: entry.name.clone(),
                snapshot_id,
                snapshot_root: SnapshotRootPin::from_snapshot_entry(entry),
                action: SnapshotPruneAction::RetainByPolicy,
                clone_origin_pins: Vec::new(),
                deadlist_pins: Vec::new(),
            });
        }

        for name in &candidates {
            let Some(entry) = snapshots.iter().find(|s| s.name == *name) else {
                continue;
            };
            let snapshot_id = format!("{dataset_name}/{name}");
            let snapshot_root = SnapshotRootPin::from_snapshot_entry(entry);
            let mut clone_origin_pins = Vec::new();
            let mut deadlist_pins = Vec::new();
            let mut blocks = Vec::new();
            let current_clone_origin_pins = self.live_clone_origin_pins(&snapshot_id);
            let current_clone_origin_pin_set =
                clone_origin_pin_set(current_clone_origin_pins.as_slice());

            match &evidence_index {
                Ok(Some(index)) => match index.get(&snapshot_id) {
                    Some(evidence) => {
                        if !evidence.snapshot_root.matches_snapshot_entry(entry) {
                            blocks.push(SnapshotPruneBlock::CorruptEvidence(format!(
                                "snapshot root evidence for {snapshot_id} does not match catalog"
                            )));
                        }

                        match &evidence.clone_origin_pins {
                            Some(pins) => {
                                clone_origin_pins = pins.clone();
                                if clone_origin_pin_set(&clone_origin_pins)
                                    != current_clone_origin_pin_set
                                {
                                    let protecting_pins = if current_clone_origin_pins.is_empty() {
                                        clone_origin_pins.clone()
                                    } else {
                                        current_clone_origin_pins.clone()
                                    };
                                    if !protecting_pins.is_empty() {
                                        clone_origin_pins = protecting_pins;
                                        blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                                    }
                                    blocks.push(SnapshotPruneBlock::CorruptEvidence(format!(
                                        "clone-origin evidence for {snapshot_id} does not match current clone/origin index"
                                    )));
                                } else if !clone_origin_pins.is_empty() {
                                    blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                                }
                            }
                            None => {
                                if !current_clone_origin_pins.is_empty() {
                                    clone_origin_pins = current_clone_origin_pins.clone();
                                    blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                                }
                                blocks.push(SnapshotPruneBlock::MissingEvidence(format!(
                                    "clone-origin entry missing for {snapshot_id}"
                                )));
                            }
                        }

                        match &evidence.deadlist_pins {
                            Some(pins) => {
                                deadlist_pins = pins.clone();
                                if !deadlist_pins.is_empty() {
                                    blocks.push(SnapshotPruneBlock::DeadlistPinProtection);
                                }
                            }
                            None => blocks.push(SnapshotPruneBlock::MissingEvidence(format!(
                                "deadlist pin entry missing for {snapshot_id}"
                            ))),
                        }
                    }
                    None => {
                        if !current_clone_origin_pins.is_empty() {
                            clone_origin_pins = current_clone_origin_pins.clone();
                            blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                        }
                        blocks.push(SnapshotPruneBlock::MissingEvidence(format!(
                            "snapshot pin evidence missing for {snapshot_id}"
                        )));
                    }
                },
                Ok(None) => {
                    if !current_clone_origin_pins.is_empty() {
                        clone_origin_pins = current_clone_origin_pins.clone();
                        blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                    }
                    blocks.push(SnapshotPruneBlock::MissingEvidence(
                        "snapshot pin evidence index missing".into(),
                    ));
                }
                Err(SnapshotPrunerError::PinEvidenceCorrupt { reason }) => {
                    if !current_clone_origin_pins.is_empty() {
                        clone_origin_pins = current_clone_origin_pins.clone();
                        blocks.push(SnapshotPruneBlock::CloneOriginProtection);
                    }
                    blocks.push(SnapshotPruneBlock::CorruptEvidence(reason.clone()));
                }
                Err(err) => blocks.push(SnapshotPruneBlock::StoreFailure(err.to_string())),
            }

            if blocks.is_empty() {
                if let Err(err) = self.verify_snapshot_integrity(store, dataset_name, name) {
                    match err {
                        SnapshotPrunerError::IntegrityFailure(reason) => {
                            blocks.push(SnapshotPruneBlock::IntegrityFailure(reason));
                        }
                        other => blocks.push(SnapshotPruneBlock::StoreFailure(other.to_string())),
                    }
                }
            }
            let action = if blocks.is_empty() {
                result.delete_set.push(name.clone());
                SnapshotPruneAction::Delete
            } else {
                account_plan_blocks(&mut result, &blocks);
                SnapshotPruneAction::Blocked(blocks)
            };

            result.decisions.push(SnapshotPruneDecision {
                snapshot_name: name.clone(),
                snapshot_id,
                snapshot_root,
                action,
                clone_origin_pins,
                deadlist_pins,
            });
        }

        result
    }

    /// Run a full retention-driven prune of a single dataset.
    ///
    /// The delete set is first produced by [`Self::plan_dataset_prune`], so a
    /// candidate with missing, corrupt, clone-origin, or deadlist-pin evidence
    /// is never handed to the store deletion path.
    pub fn prune_dataset(
        &mut self,
        store: &mut LocalObjectStore,
        dataset_name: &str,
        now: SystemTime,
    ) -> PruneResult {
        let snapshots = store.list_snapshots(dataset_name);
        if snapshots.is_empty() {
            return PruneResult::default();
        }
        let infos: Vec<SnapshotInfo> = snapshots
            .iter()
            .enumerate()
            .map(|(i, e)| SnapshotInfo {
                name: e.name.clone(),
                created_at: e.created_at,
                size_bytes: 0,
                txg_anchor: e.txg_anchor.0,
                ordinal: i as u64,
            })
            .collect();

        let mut result = self.plan_dataset_prune(store, dataset_name, now);
        let delete_set = result.delete_set.clone();
        let mut destroyed_names = Vec::new();

        for name in delete_set {
            match store.destroy_snapshot(dataset_name, &name) {
                Ok(Some(_)) => {
                    if let Some(ref mut pin_set) = self.extent_pin_set {
                        pin_set.release_snapshot(&format!("{dataset_name}/{name}"));
                    }
                    destroyed_names.push(name);
                }
                Ok(None) => {}
                Err(err) => {
                    result.store_failures = result.store_failures.saturating_add(1);
                    if let Some(decision) = result
                        .decisions
                        .iter_mut()
                        .find(|decision| decision.snapshot_name == name)
                    {
                        decision.action =
                            SnapshotPruneAction::Blocked(vec![SnapshotPruneBlock::StoreFailure(
                                format!("{err}"),
                            )]);
                    }
                    result.delete_set.retain(|planned| planned != &name);
                }
            }
        }

        result.destroyed = destroyed_names.len() as u64;
        self.record_outcome(&infos, &destroyed_names);

        result
    }
}

// ---------------------------------------------------------------------------

fn clone_origin_pin_set(pins: &[CloneOriginPin]) -> BTreeSet<(u8, String)> {
    pins.iter()
        .map(|pin| (pin.kind.to_u8(), pin.id.clone()))
        .collect()
}

fn account_plan_blocks(result: &mut PruneResult, blocks: &[SnapshotPruneBlock]) {
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::IntegrityFailure(_)))
    {
        result.integrity_failures = result.integrity_failures.saturating_add(1);
    }
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::CloneOriginProtection))
    {
        result.clone_origin_protected = result.clone_origin_protected.saturating_add(1);
    }
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::DeadlistPinProtection))
    {
        result.deadlist_pin_protected = result.deadlist_pin_protected.saturating_add(1);
    }
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::MissingEvidence(_)))
    {
        result.missing_evidence_blocks = result.missing_evidence_blocks.saturating_add(1);
    }
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::CorruptEvidence(_)))
    {
        result.corrupt_evidence_blocks = result.corrupt_evidence_blocks.saturating_add(1);
    }
    if blocks
        .iter()
        .any(|block| matches!(block, SnapshotPruneBlock::StoreFailure(_)))
    {
        result.store_failures = result.store_failures.saturating_add(1);
    }
}
