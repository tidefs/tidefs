//! On-disk inode-table persistence layer backed by [`tidefs_local_object_store`].
//!
//! [`PersistentInodeTable`] stores each inode record as a named object in the
//! object store, keyed by inode number. Allocation metadata (next inode number,
//! free list, generation counter) is persisted in a separate meta object so
//! the table state survives restarts.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError, StoreOptions};

use crate::{Ino, InodeAttributes, InodeKind};

// ---------------------------------------------------------------------------
// On-disk record format (84 bytes, little-endian)
// ---------------------------------------------------------------------------

/// Magic bytes prefixing every valid inode record.
const INODE_RECORD_MAGIC: [u8; 4] = [b'V', b'I', b'N', b'O'];

/// Size of the on-disk inode record in bytes.
const INODE_RECORD_BYTES: usize = 84;

/// ```text
/// Offset  Bytes  Field
/// 0       4      magic "VINO"
/// 4       4      mode (u32 LE)
/// 8       4      uid (u32 LE)
/// 12      4      gid (u32 LE)
/// 16      8      size (u64 LE)
/// 24      8      blocks (u64 LE)
/// 32      8      atime_secs (u64 LE)
/// 40      4      atime_nanos (u32 LE)
/// 44      8      mtime_secs (u64 LE)
/// 52      4      mtime_nanos (u32 LE)
/// 56      8      ctime_secs (u64 LE)
/// 64      4      ctime_nanos (u32 LE)
/// 68      4      nlink (u32 LE)
/// 72      8      generation (u64 LE)
/// 80      1      kind (0=File, 1=Directory, 2=Symlink)
/// 81      3      reserved (zero)
/// ```
fn encode_inode_attrs(attrs: &InodeAttributes) -> [u8; INODE_RECORD_BYTES] {
    let mut buf = [0u8; INODE_RECORD_BYTES];
    buf[0..4].copy_from_slice(&INODE_RECORD_MAGIC);
    buf[4..8].copy_from_slice(&attrs.mode.to_le_bytes());
    buf[8..12].copy_from_slice(&attrs.uid.to_le_bytes());
    buf[12..16].copy_from_slice(&attrs.gid.to_le_bytes());
    buf[16..24].copy_from_slice(&attrs.size.to_le_bytes());
    buf[24..32].copy_from_slice(&attrs.blocks.to_le_bytes());
    buf[32..40].copy_from_slice(&attrs.atime.as_secs().to_le_bytes());
    buf[40..44].copy_from_slice(&(attrs.atime.subsec_nanos()).to_le_bytes());
    buf[44..52].copy_from_slice(&attrs.mtime.as_secs().to_le_bytes());
    buf[52..56].copy_from_slice(&(attrs.mtime.subsec_nanos()).to_le_bytes());
    buf[56..64].copy_from_slice(&attrs.ctime.as_secs().to_le_bytes());
    buf[64..68].copy_from_slice(&(attrs.ctime.subsec_nanos()).to_le_bytes());
    buf[68..72].copy_from_slice(&attrs.nlink.to_le_bytes());
    buf[72..80].copy_from_slice(&attrs.generation.to_le_bytes());
    buf[80] = match attrs.kind {
        InodeKind::File => 0,
        InodeKind::Directory => 1,
        InodeKind::Symlink => 2,
    };
    // bytes 81..84 reserved (zero)
    buf
}

fn decode_inode_attrs(bytes: &[u8]) -> Result<InodeAttributes, PersistentInodeError> {
    if bytes.len() != INODE_RECORD_BYTES {
        return Err(PersistentInodeError::SerializationError);
    }
    if bytes[0..4] != INODE_RECORD_MAGIC {
        return Err(PersistentInodeError::CorruptRecord {
            reason: "magic mismatch",
        });
    }
    let mode = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let uid = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let gid = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let blocks = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let atime = Duration::new(
        u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
        u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
    );
    let mtime = Duration::new(
        u64::from_le_bytes(bytes[44..52].try_into().unwrap()),
        u32::from_le_bytes(bytes[52..56].try_into().unwrap()),
    );
    let ctime = Duration::new(
        u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
        u32::from_le_bytes(bytes[64..68].try_into().unwrap()),
    );
    let nlink = u32::from_le_bytes(bytes[68..72].try_into().unwrap());
    let generation = u64::from_le_bytes(bytes[72..80].try_into().unwrap());
    let kind = match bytes[80] {
        0 => InodeKind::File,
        1 => InodeKind::Directory,
        2 => InodeKind::Symlink,
        _ => {
            return Err(PersistentInodeError::CorruptRecord {
                reason: "unknown inode kind byte",
            });
        }
    };
    Ok(InodeAttributes {
        mode,
        uid,
        gid,
        size,
        blocks,
        atime,
        mtime,
        ctime,
        nlink,
        generation,
        kind,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: crate::ATTR_DIRTY_ALL,
        mutation_gen: 0,
    })
}

// ---------------------------------------------------------------------------
// Meta-object format
// ---------------------------------------------------------------------------

/// Key name for the allocation-metadata object.
const META_KEY_NAME: &str = "tidefs-inode-table-meta";

/// Prefix for per-inode object key names.
const INODE_KEY_PREFIX: &str = "inode:";

/// Meta-object binary format (variable length):
///
/// ```text
/// Offset  Bytes  Field
/// 0       8      next_ino (u64 LE)
/// 8       8      next_generation (u64 LE)
/// 16      4      free_count (u32 LE)
/// 20      N*8    free_entries ([u64; free_count] LE)
/// ```
const META_HEADER_BYTES: usize = 20;

fn encode_meta(next_ino: u64, next_generation: u64, free_list: &VecDeque<u64>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(META_HEADER_BYTES + free_list.len() * 8);
    buf.extend_from_slice(&next_ino.to_le_bytes());
    buf.extend_from_slice(&next_generation.to_le_bytes());
    buf.extend_from_slice(&(free_list.len() as u32).to_le_bytes());
    for &ino in free_list {
        buf.extend_from_slice(&ino.to_le_bytes());
    }
    buf
}

fn decode_meta(bytes: &[u8]) -> Result<(u64, u64, VecDeque<u64>), PersistentInodeError> {
    if bytes.len() < META_HEADER_BYTES {
        return Err(PersistentInodeError::SerializationError);
    }
    let next_ino = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let next_generation = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let free_count = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let expected_len = META_HEADER_BYTES + free_count * 8;
    if bytes.len() < expected_len {
        return Err(PersistentInodeError::SerializationError);
    }
    let mut free_list = VecDeque::with_capacity(free_count);
    for i in 0..free_count {
        let offset = META_HEADER_BYTES + i * 8;
        let ino = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        free_list.push_back(ino);
    }
    Ok((next_ino, next_generation, free_list))
}

// ---------------------------------------------------------------------------
// PersistentInodeError
// ---------------------------------------------------------------------------

/// Errors returned by [`PersistentInodeTable`] operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistentInodeError {
    /// The requested inode number is not present.
    InodeNotFound,
    /// Attempted to free an inode that still has positive link count.
    InodeHasLinks,
    /// The inode table capacity is exhausted.
    TableFull,
    /// The on-disk record is corrupt or unreadable.
    CorruptRecord {
        /// Human-readable description of the corruption.
        reason: &'static str,
    },
    /// An I/O error occurred during a store operation.
    IoError(String),
    /// Serialization or deserialization failed.
    SerializationError,
    /// The inode is already in the free list (double-free).
    DoubleFree,
}

impl From<StoreError> for PersistentInodeError {
    fn from(e: StoreError) -> Self {
        PersistentInodeError::IoError(format!("{e:?}"))
    }
}

// ---------------------------------------------------------------------------
// PersistentInodeTable
// ---------------------------------------------------------------------------

/// On-disk persistent inode table backed by a [`LocalObjectStore`].
///
/// Each inode record is stored as a named object in the object store,
/// keyed by the inode number. Allocation metadata is persisted in a
/// separate meta object so the table state survives process restarts.
///
/// # Examples
///
/// ```rust,no_run
/// use tidefs_inode_table::persistent::PersistentInodeTable;
/// use tidefs_inode_table::{InodeKind, InodeAttributes};
///
/// let root = std::env::temp_dir().join("tidefs-it-example");
/// let mut tbl = PersistentInodeTable::open(&root).unwrap();
/// let attrs = InodeAttributes::new(0o644, 1000, 1000, InodeKind::File);
/// let ino = tbl.allocate_inode(attrs).unwrap();
/// let stored = tbl.read_inode(ino).unwrap();
/// assert_eq!(stored.mode, 0o644);
/// ```
pub struct PersistentInodeTable {
    store: LocalObjectStore,
    next_ino: u64,
    free_list: VecDeque<u64>,
    next_generation: u64,
    max_capacity: usize,
    /// Root path for diagnostics.
    root: std::path::PathBuf,
}

impl PersistentInodeTable {
    /// Open (or create) a persistent inode table rooted at `root`.
    pub fn open(root: impl AsRef<std::path::Path>) -> Result<Self, PersistentInodeError> {
        let root = root.as_ref().to_path_buf();
        let opts = StoreOptions {
            sync_on_write: true,
            repair_torn_tail: true,
            ..StoreOptions::test_fast()
        };
        let store = LocalObjectStore::open_with_options(&root, opts.clone())
            .map_err(PersistentInodeError::from)?;
        let max_capacity = (opts.segment_count as usize).saturating_mul(1024);

        let meta_key = ObjectKey::from_name(META_KEY_NAME);
        let (next_ino, next_generation, free_list) =
            match store.get(meta_key).map_err(PersistentInodeError::from)? {
                Some(meta_bytes) => decode_meta(&meta_bytes)?,
                None => (1, 1, VecDeque::new()),
            };

        Ok(Self {
            store,
            next_ino,
            free_list,
            next_generation,
            max_capacity,
            root,
        })
    }

    // ------------------------------------------------------------------
    // Key derivation helpers
    // ------------------------------------------------------------------

    fn inode_key(ino: u64) -> ObjectKey {
        ObjectKey::from_name(format!("{INODE_KEY_PREFIX}{ino:020}"))
    }

    fn meta_key() -> ObjectKey {
        ObjectKey::from_name(META_KEY_NAME)
    }

    // ------------------------------------------------------------------
    // Internal: persist allocation metadata
    // ------------------------------------------------------------------

    fn persist_meta(&mut self) -> Result<(), PersistentInodeError> {
        let meta_bytes = encode_meta(self.next_ino, self.next_generation, &self.free_list);
        self.store
            .put(Self::meta_key(), &meta_bytes)
            .map_err(PersistentInodeError::from)?;
        Ok(())
    }

    fn alloc_generation(&mut self) -> u64 {
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        let gen = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        if self.next_generation == 0 {
            self.next_generation = 1;
        }
        gen
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Allocate a new inode with the given initial attributes.
    ///
    /// Timestamps are set to the current wall-clock time. If `nlink` is
    /// zero, it is bumped to 1. A fresh `generation` is assigned.
    /// Returns the allocated inode number.
    pub fn allocate_inode(
        &mut self,
        mut attrs: InodeAttributes,
    ) -> Result<Ino, PersistentInodeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        let ino_num = if let Some(idx) = self.free_list.pop_front() {
            idx
        } else {
            let idx = self.next_ino;
            if idx == u64::MAX {
                return Err(PersistentInodeError::TableFull);
            }
            if idx as usize >= self.max_capacity {
                return Err(PersistentInodeError::TableFull);
            }
            self.next_ino = self.next_ino.saturating_add(1);
            idx
        };

        let gen = self.alloc_generation();
        attrs.atime = now;
        attrs.mtime = now;
        attrs.ctime = now;
        if attrs.nlink == 0 {
            attrs.nlink = 1;
        }
        attrs.generation = gen;

        let record = encode_inode_attrs(&attrs);
        self.store
            .put(Self::inode_key(ino_num), &record)
            .map_err(PersistentInodeError::from)?;
        self.persist_meta()?;

        Ok(Ino(ino_num))
    }

    /// Read the on-disk inode record for `ino`.
    ///
    /// Returns the deserialized attributes, or an error if the inode does
    /// not exist or the record is corrupt.
    pub fn read_inode(&self, ino: Ino) -> Result<InodeAttributes, PersistentInodeError> {
        let key = Self::inode_key(ino.0);
        let raw = self
            .store
            .get(key)
            .map_err(PersistentInodeError::from)?
            .ok_or(PersistentInodeError::InodeNotFound)?;
        decode_inode_attrs(&raw)
    }

    /// Write updated attributes to the on-disk record for `ino`.
    ///
    /// The generation field is preserved from the existing record so
    /// that stale handles cannot overwrite a reused inode slot.
    pub fn write_inode(
        &mut self,
        ino: Ino,
        mut attrs: InodeAttributes,
    ) -> Result<(), PersistentInodeError> {
        let existing = self.read_inode(ino)?;
        attrs.generation = existing.generation;

        let record = encode_inode_attrs(&attrs);
        self.store
            .put(Self::inode_key(ino.0), &record)
            .map_err(PersistentInodeError::from)?;
        Ok(())
    }

    /// Free the on-disk inode record for `ino`.
    ///
    /// Fails if the inode has `nlink > 0`, or if it is already in the
    /// free list (double-free). On success, the slot is returned to the
    /// free list for reuse and the backing object is deleted.
    pub fn free_inode(&mut self, ino: Ino) -> Result<(), PersistentInodeError> {
        if self.free_list.contains(&ino.0) {
            return Err(PersistentInodeError::DoubleFree);
        }

        let attrs = self.read_inode(ino)?;
        if attrs.nlink > 0 {
            return Err(PersistentInodeError::InodeHasLinks);
        }

        self.store
            .delete(Self::inode_key(ino.0))
            .map_err(PersistentInodeError::from)?;
        self.free_list.push_back(ino.0);
        self.persist_meta()?;
        Ok(())
    }

    /// Check whether an inode slot is currently allocated.
    pub fn exists(&self, ino: Ino) -> Result<bool, PersistentInodeError> {
        match self.store.get(Self::inode_key(ino.0)) {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(PersistentInodeError::from(e)),
        }
    }

    /// Flush all pending writes to durable storage.
    pub fn sync_all(&mut self) -> Result<(), PersistentInodeError> {
        self.store.sync_all().map_err(PersistentInodeError::from)
    }

    /// Return the filesystem root of this table.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Estimated number of currently allocated inodes.
    #[must_use]
    pub fn allocated_count(&self) -> u64 {
        self.next_ino
            .saturating_sub(1)
            .saturating_sub(self.free_list.len() as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tidefs-it-persist-{name}-{nanos}"))
    }

    fn file_attrs(mode: u32) -> InodeAttributes {
        let mut a = InodeAttributes::new(mode, 1000, 1000, InodeKind::File);
        a.dirty_bits = 0;
        a
    }

    fn dir_attrs(mode: u32) -> InodeAttributes {
        let mut a = InodeAttributes::new(mode, 1000, 1000, InodeKind::Directory);
        a.dirty_bits = 0;
        a
    }

    // ------------------------------------------------------------------
    // allocate / read round-trip
    // ------------------------------------------------------------------

    #[test]
    fn allocate_read_round_trip() {
        let root = temp_root("ar-roundtrip");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        assert!(ino.0 >= 1);

        let stored = tbl.read_inode(ino).unwrap();
        assert_eq!(stored.mode, 0o644);
        assert_eq!(stored.uid, 1000);
        assert_eq!(stored.gid, 1000);
        assert_eq!(stored.size, 0);
        assert_eq!(stored.nlink, 1);
        assert!(stored.generation > 0);
        assert_eq!(stored.kind, InodeKind::File);
        assert!(stored.atime > Duration::ZERO);
        assert!(stored.mtime > Duration::ZERO);
        assert!(stored.ctime > Duration::ZERO);

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn allocate_distinct_inos() {
        let root = temp_root("distinct-inos");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino1 = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        let ino2 = tbl.allocate_inode(file_attrs(0o755)).unwrap();
        assert_ne!(ino1, ino2);

        let a1 = tbl.read_inode(ino1).unwrap();
        let a2 = tbl.read_inode(ino2).unwrap();
        assert_eq!(a1.mode, 0o644);
        assert_eq!(a2.mode, 0o755);
        assert_ne!(a1.generation, a2.generation);

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // write / read round-trip
    // ------------------------------------------------------------------

    #[test]
    fn write_read_round_trip() {
        let root = temp_root("wr-roundtrip");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        let orig_gen = tbl.read_inode(ino).unwrap().generation;

        let mut attrs = tbl.read_inode(ino).unwrap();
        attrs.size = 4096;
        attrs.mode = 0o755;
        tbl.write_inode(ino, attrs).unwrap();

        let stored = tbl.read_inode(ino).unwrap();
        assert_eq!(stored.size, 4096);
        assert_eq!(stored.mode, 0o755);
        assert_eq!(stored.generation, orig_gen);

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // free then re-allocate
    // ------------------------------------------------------------------

    #[test]
    fn free_reallocate_clean_state() {
        let root = temp_root("free-realloc");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        let orig_gen = tbl.read_inode(ino).unwrap().generation;

        // Set nlink=0 so free succeeds.
        let mut zeroed = tbl.read_inode(ino).unwrap();
        zeroed.nlink = 0;
        tbl.write_inode(ino, zeroed).unwrap();
        tbl.free_inode(ino).unwrap();

        // Re-allocate; free list should give us the same inode number.
        let ino2 = tbl.allocate_inode(dir_attrs(0o755)).unwrap();
        assert_eq!(ino2, ino);
        let stored = tbl.read_inode(ino2).unwrap();
        assert_eq!(stored.kind, InodeKind::Directory);
        assert_eq!(stored.mode, 0o755);
        assert!(stored.generation > orig_gen);
        assert_eq!(stored.size, 0); // not stale

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // double-free rejection
    // ------------------------------------------------------------------

    #[test]
    fn double_free_rejection() {
        let root = temp_root("double-free");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        let mut zeroed = tbl.read_inode(ino).unwrap();
        zeroed.nlink = 0;
        tbl.write_inode(ino, zeroed).unwrap();

        tbl.free_inode(ino).unwrap();
        assert!(matches!(
            tbl.free_inode(ino),
            Err(PersistentInodeError::DoubleFree)
        ));

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // free-with-nlink rejection
    // ------------------------------------------------------------------

    #[test]
    fn free_with_nlink_rejection() {
        let root = temp_root("free-nlink");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        let err = tbl.free_inode(ino);
        assert!(matches!(err, Err(PersistentInodeError::InodeHasLinks)));

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // read-nonexistent / write-nonexistent
    // ------------------------------------------------------------------

    #[test]
    fn read_nonexistent() {
        let root = temp_root("read-nonex");
        let tbl = PersistentInodeTable::open(&root).unwrap();
        assert!(matches!(
            tbl.read_inode(Ino(99999)),
            Err(PersistentInodeError::InodeNotFound)
        ));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn write_nonexistent() {
        let root = temp_root("write-nonex");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();
        assert!(matches!(
            tbl.write_inode(Ino(99999), file_attrs(0o644)),
            Err(PersistentInodeError::InodeNotFound)
        ));
        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // corrupt record detection
    // ------------------------------------------------------------------

    #[test]
    fn corrupt_record_bad_magic() {
        let root = temp_root("corrupt-magic");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        // Overwrite with garbage that has the right length but wrong magic.
        let garbage = vec![0xAAu8; INODE_RECORD_BYTES];
        tbl.store
            .put(PersistentInodeTable::inode_key(ino.0), &garbage)
            .unwrap();

        assert!(matches!(
            tbl.read_inode(ino),
            Err(PersistentInodeError::CorruptRecord { .. })
        ));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn corrupt_record_wrong_size() {
        let root = temp_root("corrupt-size");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        let ino = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        tbl.store
            .put(PersistentInodeTable::inode_key(ino.0), &[0u8; 10])
            .unwrap();

        assert!(matches!(
            tbl.read_inode(ino),
            Err(PersistentInodeError::SerializationError)
        ));
        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // survive reopen
    // ------------------------------------------------------------------

    #[test]
    fn survive_reopen() {
        let root = temp_root("survive-reopen");
        let mut inos = Vec::new();

        {
            let mut tbl = PersistentInodeTable::open(&root).unwrap();
            for i in 0..5 {
                let attrs = InodeAttributes::new(0o600 | (i as u32), 1000, 1000, InodeKind::File);
                let ino = tbl.allocate_inode(attrs).unwrap();
                inos.push(ino);
            }
            tbl.sync_all().unwrap();
        }

        {
            let tbl = PersistentInodeTable::open(&root).unwrap();
            for (i, &ino) in inos.iter().enumerate() {
                let attrs = tbl.read_inode(ino).unwrap();
                assert_eq!(attrs.mode, 0o600 | (i as u32));
                assert_eq!(attrs.nlink, 1);
                assert!(attrs.generation > 0);
            }
        }

        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn free_list_survives_reopen() {
        let root = temp_root("free-survives");
        let freed;

        {
            let mut tbl = PersistentInodeTable::open(&root).unwrap();
            freed = tbl.allocate_inode(file_attrs(0o644)).unwrap();
            let mut zeroed = tbl.read_inode(freed).unwrap();
            zeroed.nlink = 0;
            tbl.write_inode(freed, zeroed).unwrap();
            tbl.free_inode(freed).unwrap();
        }

        {
            let mut tbl = PersistentInodeTable::open(&root).unwrap();
            let new_ino = tbl.allocate_inode(file_attrs(0o755)).unwrap();
            assert_eq!(new_ino, freed);
            assert_eq!(tbl.read_inode(new_ino).unwrap().mode, 0o755);
        }

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // kind round-trip
    // ------------------------------------------------------------------

    #[test]
    fn kind_round_trips() {
        let root = temp_root("kind-rt");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        for kind in [InodeKind::File, InodeKind::Directory, InodeKind::Symlink] {
            let attrs = InodeAttributes::new(0o644, 1000, 1000, kind);
            let ino = tbl.allocate_inode(attrs).unwrap();
            assert_eq!(tbl.read_inode(ino).unwrap().kind, kind);
        }

        fs::remove_dir_all(&root).ok();
    }

    // ------------------------------------------------------------------
    // allocated_count / exists
    // ------------------------------------------------------------------

    #[test]
    fn allocated_count_and_exists() {
        let root = temp_root("count-exists");
        let mut tbl = PersistentInodeTable::open(&root).unwrap();

        assert_eq!(tbl.allocated_count(), 0);
        assert!(!tbl.exists(Ino(1)).unwrap());

        let ino1 = tbl.allocate_inode(file_attrs(0o644)).unwrap();
        assert_eq!(tbl.allocated_count(), 1);
        assert!(tbl.exists(ino1).unwrap());

        let ino2 = tbl.allocate_inode(file_attrs(0o755)).unwrap();
        assert_eq!(tbl.allocated_count(), 2);

        let mut zeroed = tbl.read_inode(ino1).unwrap();
        zeroed.nlink = 0;
        tbl.write_inode(ino1, zeroed).unwrap();
        tbl.free_inode(ino1).unwrap();
        assert_eq!(tbl.allocated_count(), 1);
        assert!(!tbl.exists(ino1).unwrap());
        assert!(tbl.exists(ino2).unwrap());

        fs::remove_dir_all(&root).ok();
    }
}
