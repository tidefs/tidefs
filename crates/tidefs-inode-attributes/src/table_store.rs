// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! [`InodeTable`]-backed attribute store.
//!
//! Wraps a [`tidefs_inode_table::InodeTable`] and implements the
//! [`InodeAttributeStore`] trait, bridging the inode-table persistence
//! layer with the POSIX attribute contract used by the FUSE adapter,
//! namespace, and validation harness.
//!
//! # Conversion
//!
//! [`InodeAttributes`] (tidefs-inode-table) and [`InodeAttr`]/[`PosixAttrs`]
//! (tidefs-types-vfs-core) represent the same inode metadata in two
//! different type systems. This module provides `From`/`Into` conversions
//! between them.

use std::sync::Arc;

use tidefs_inode_table::{Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError};
use tidefs_types_vfs_core::{Generation, InodeAttr, InodeFlags, InodeId, NodeKind, PosixAttrs};

use crate::{AttrError, InodeAttributeStore, SetAttr};

// ---------------------------------------------------------------------------
// InodeKind ↔ NodeKind
// ---------------------------------------------------------------------------

fn inode_kind_to_node_kind(kind: InodeKind) -> NodeKind {
    match kind {
        InodeKind::File => NodeKind::File,
        InodeKind::Directory => NodeKind::Dir,
        InodeKind::Symlink => NodeKind::Symlink,
    }
}

fn node_kind_to_inode_kind(kind: NodeKind) -> Option<InodeKind> {
    match kind {
        NodeKind::File => Some(InodeKind::File),
        NodeKind::Dir => Some(InodeKind::Directory),
        NodeKind::Symlink => Some(InodeKind::Symlink),
        _ => None, // CharDev, BlockDev, Fifo, Socket, Whiteout not yet mapped
    }
}

// ---------------------------------------------------------------------------
// InodeAttributes ↔ InodeAttr
// ---------------------------------------------------------------------------

/// Convert a pair of inode number and [`InodeAttributes`] into an [`InodeAttr`].
#[must_use]
pub fn inode_attrs_to_inode_attr(ino: Ino, attrs: &InodeAttributes) -> InodeAttr {
    let posix = PosixAttrs {
        mode: attrs.mode | posix_mode_type_for_kind(attrs.kind),
        uid: attrs.uid,
        gid: attrs.gid,
        nlink: attrs.nlink,
        rdev: 0,
        atime_ns: duration_to_ns(attrs.atime),
        mtime_ns: duration_to_ns(attrs.mtime),
        ctime_ns: duration_to_ns(attrs.ctime),
        btime_ns: 0,
        size: attrs.size,
        blocks_512: attrs.blocks,
        blksize: 4096,
    };

    InodeAttr {
        inode_id: InodeId(ino.0),
        generation: Generation(attrs.generation),
        kind: inode_kind_to_node_kind(attrs.kind),
        posix,
        flags: InodeFlags::none(),
        subtree_rev: 0,
        dir_rev: 0,
    }
}

/// Convert an [`InodeAttr`] into an [`InodeAttributes`].
///
/// Unsupported node kinds (CharDev, BlockDev, Fifo, Socket, Whiteout)
/// default to [`InodeKind::File`].
#[must_use]
pub fn inode_attr_to_inode_attributes(attr: &InodeAttr) -> InodeAttributes {
    let kind = node_kind_to_inode_kind(attr.kind).unwrap_or(InodeKind::File);

    InodeAttributes {
        mode: attr.posix.mode & !tidefs_types_vfs_core::S_IFMT,
        uid: attr.posix.uid,
        gid: attr.posix.gid,
        size: attr.posix.size,
        blocks: attr.posix.blocks_512,
        atime: ns_to_duration(attr.posix.atime_ns),
        mtime: ns_to_duration(attr.posix.mtime_ns),
        ctime: ns_to_duration(attr.posix.ctime_ns),
        nlink: attr.posix.nlink,
        generation: attr.generation.0,
        kind,
        xattrs: std::collections::BTreeMap::new(),
        dirty_bits: tidefs_inode_table::ATTR_DIRTY_ALL,
        mutation_gen: 0,
    }
}

/// Return the POSIX mode type bits (S_IFMT mask) for an [`InodeKind`].
fn posix_mode_type_for_kind(kind: InodeKind) -> u32 {
    match kind {
        InodeKind::File => tidefs_types_vfs_core::S_IFREG,
        InodeKind::Directory => tidefs_types_vfs_core::S_IFDIR,
        InodeKind::Symlink => tidefs_types_vfs_core::S_IFLNK,
    }
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

fn duration_to_ns(d: std::time::Duration) -> i64 {
    d.as_nanos().try_into().unwrap_or(i64::MAX)
}

fn ns_to_duration(ns: i64) -> std::time::Duration {
    std::time::Duration::from_nanos(ns.max(0) as u64)
}

// ---------------------------------------------------------------------------
// Error conversion
// ---------------------------------------------------------------------------

impl From<InodeTableError> for AttrError {
    fn from(e: InodeTableError) -> Self {
        match e {
            InodeTableError::InodeNotFound => AttrError::InoNotFound,
            InodeTableError::GenerationMismatch => AttrError::InoNotFound,
            InodeTableError::InodeHasLinks => AttrError::InoNotFound,
            InodeTableError::TableFull => {
                // TableFull is a resource exhaustion, not a per-inode error.
                // Map to InoNotFound as a best-fit since the caller wants a
                // clean errno at the FUSE boundary.
                AttrError::InoNotFound
            }
            InodeTableError::LinkCountOverflow => AttrError::LinkOverflow,
        }
    }
}

// ---------------------------------------------------------------------------
// TableAttributeStore
// ---------------------------------------------------------------------------

/// An [`InodeAttributeStore`] backed by an [`InodeTable`].
///
/// This wraps a shared [`InodeTable`] (via `Arc<RwLock<...>>` — the table
/// is already thread-safe) and delegates getattr/setattr/link/unlink calls
/// to the table, converting between [`InodeAttributes`] and [`InodeAttr`]
/// at the boundary.
///
/// # Examples
///
/// ```rust
/// use std::sync::Arc;
/// use tidefs_inode_attributes::{InodeAttributeStore, InodeAttr, table_store::TableAttributeStore};
/// use tidefs_inode_table::{InodeTable, SystemTimeSource};
///
/// let tbl = InodeTable::new(64, Box::new(SystemTimeSource::default()));
/// let store = TableAttributeStore::new(Arc::new(tbl));
/// ```
#[derive(Clone, Debug)]
pub struct TableAttributeStore {
    table: Arc<InodeTable>,
}

impl TableAttributeStore {
    /// Create a new store wrapping `table`.
    #[must_use]
    pub fn new(table: Arc<InodeTable>) -> Self {
        Self { table }
    }

    /// Return a reference to the underlying [`InodeTable`].
    #[must_use]
    pub fn table(&self) -> &Arc<InodeTable> {
        &self.table
    }

    /// Insert or overwrite an inode's attributes directly.
    ///
    /// This is a low-level entry-point for initialisation scenarios
    /// (e.g. populating the root inode). The inode is allocated via
    /// [`InodeTable::allocate`](tidefs_inode_table::InodeTable::allocate)
    /// using the given `ino` as a hint (the actual allocated number may
    /// differ if the slot is occupied).
    pub fn insert(&self, _ino_num: u64, attrs: InodeAttr) -> Result<Ino, AttrError> {
        let inode_attrs = inode_attr_to_inode_attributes(&attrs);
        self.table.allocate(inode_attrs).map_err(AttrError::from)
    }

    /// Create a new inode with the given kind and attributes.
    pub fn create(
        &self,
        kind: tidefs_inode_table::InodeKind,
        attrs: InodeAttributes,
    ) -> Result<Ino, AttrError> {
        self.table.create(kind, attrs).map_err(AttrError::from)
    }
    /// Update the access time (atime) to the current clock value.
    ///
    /// Reads the current attributes, bumps atime and ctime, and writes back.
    pub fn touch_atime(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        let ino_val = Ino(ino);
        let mut current = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        let now = ns_to_duration(crate::now_ns());
        current.atime = now;
        current.ctime = now;
        self.table.setattr(ino_val, current)?;
        let updated = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        Ok(inode_attrs_to_inode_attr(ino_val, &updated))
    }

    /// Update the modification time (mtime) to the current clock value.
    ///
    /// Reads the current attributes, bumps mtime and ctime, and writes back.
    pub fn touch_mtime(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        let ino_val = Ino(ino);
        let mut current = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        let now = ns_to_duration(crate::now_ns());
        current.mtime = now;
        current.ctime = now;
        self.table.setattr(ino_val, current)?;
        let updated = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        Ok(inode_attrs_to_inode_attr(ino_val, &updated))
    }

    /// Force-update the status-change time (ctime) to the current clock value.
    pub fn touch_ctime(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        let ino_val = Ino(ino);
        let mut current = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        current.ctime = ns_to_duration(crate::now_ns());
        self.table.setattr(ino_val, current)?;
        let updated = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        Ok(inode_attrs_to_inode_attr(ino_val, &updated))
    }
}

impl InodeAttributeStore for TableAttributeStore {
    fn getattr(&self, ino: u64) -> Result<InodeAttr, AttrError> {
        let table_attrs = self.table.getattr(Ino(ino)).ok_or(AttrError::InoNotFound)?;
        let attr = inode_attrs_to_inode_attr(Ino(ino), &table_attrs);
        Ok(attr)
    }

    fn setattr(&self, ino: u64, set: &SetAttr) -> Result<InodeAttr, AttrError> {
        let ino_val = Ino(ino);

        // Read current attributes
        let mut current = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;

        // Apply the setattr mask
        apply_setattr_to_inode_attributes(&mut current, set);

        // Write back through the table
        self.table.setattr(ino_val, current)?;

        // Re-read to return the updated state
        let updated = self.table.getattr(ino_val).ok_or(AttrError::InoNotFound)?;
        Ok(inode_attrs_to_inode_attr(ino_val, &updated))
    }

    fn bump_link(&self, ino: u64) -> Result<u32, AttrError> {
        self.table.link(Ino(ino)).map_err(AttrError::from)
    }

    fn drop_link(&self, ino: u64) -> Result<u32, AttrError> {
        let ino_val = Ino(ino);
        self.table.unlink(ino_val).map_err(AttrError::from)?;
        // Return the new nlink (or 0 if the inode was auto-removed)
        match self.table.getattr(ino_val) {
            Some(a) => Ok(a.nlink),
            None => Ok(0),
        }
    }

    fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, tidefs_inode_table::XattrError> {
        self.table.get_xattr(Ino(ino), name)
    }

    fn get_xattr_size(
        &self,
        ino: u64,
        name: &[u8],
    ) -> Result<usize, tidefs_inode_table::XattrError> {
        self.table.get_xattr_size(Ino(ino), name)
    }

    fn set_xattr(
        &self,
        ino: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), tidefs_inode_table::XattrError> {
        self.table.set_xattr(Ino(ino), name, value, flags)
    }

    fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, tidefs_inode_table::XattrError> {
        self.table.list_xattr(Ino(ino))
    }

    fn list_xattr_size(&self, ino: u64) -> Result<usize, tidefs_inode_table::XattrError> {
        self.table.list_xattr_size(Ino(ino))
    }

    fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), tidefs_inode_table::XattrError> {
        self.table.remove_xattr(Ino(ino), name)
    }
}

// ---------------------------------------------------------------------------
// apply_setattr adapted for InodeAttributes
// ---------------------------------------------------------------------------

/// Apply a [`SetAttr`] mask to an [`InodeAttributes`] in-place.
///
/// This mirrors [`crate::apply_setattr`] but operates on the
/// tidefs-inode-table attribute type rather than [`InodeAttr`].
pub fn apply_setattr_to_inode_attributes(attrs: &mut InodeAttributes, set: &SetAttr) {
    let mut advance_ctime = false;
    if set.is_valid(tidefs_types_vfs_core::FATTR_MODE) {
        // InodeAttributes.mode does not store S_IFMT bits; the kind field
        // determines type. Re-derive type bits from kind to combine with
        // the caller-supplied permission bits.
        let type_bits = posix_mode_type_for_kind(attrs.kind);
        let mode = type_bits | (set.mode & !tidefs_types_vfs_core::S_IFMT);
        if attrs.mode != mode {
            attrs.mode = mode;
            advance_ctime = true;
        }
    }
    if set.is_valid(tidefs_types_vfs_core::FATTR_UID) {
        if attrs.uid != set.uid {
            attrs.uid = set.uid;
            advance_ctime = true;
        }
    }
    if set.is_valid(tidefs_types_vfs_core::FATTR_GID) {
        if attrs.gid != set.gid {
            attrs.gid = set.gid;
            advance_ctime = true;
        }
    }
    if set.is_valid(tidefs_types_vfs_core::FATTR_SIZE) {
        let blocks = crate::blocks_512_for_size(set.size);
        if attrs.size != set.size || attrs.blocks != blocks {
            attrs.size = set.size;
            attrs.blocks = blocks;
            advance_ctime = true;
        }
    }

    let now_ns = crate::now_ns();
    let mut posix = inode_attrs_to_inode_attr(Ino(0), attrs).posix;
    if crate::apply_setattr_timestamps_to_posix(set, &mut posix, now_ns, advance_ctime) {
        attrs.atime = ns_to_duration(posix.atime_ns);
        attrs.mtime = ns_to_duration(posix.mtime_ns);
        attrs.ctime = ns_to_duration(posix.ctime_ns);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tidefs_inode_table::SystemTimeSource;
    use tidefs_types_vfs_core::{
        FATTR_ATIME_NOW, FATTR_GID, FATTR_MODE, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, S_IFDIR,
        S_IFREG,
    };

    // ------------------------------------------------------------------
    // Conversion round-trip
    // ------------------------------------------------------------------

    #[test]
    fn inode_attributes_to_inode_attr_roundtrip() {
        let attrs = InodeAttributes {
            mode: 0o755,
            uid: 1000,
            gid: 100,
            size: 4096,
            blocks: 8,
            atime: Duration::new(100, 500_000_000),
            mtime: Duration::new(200, 250_000_000),
            ctime: Duration::new(300, 750_000_000),
            nlink: 3,
            generation: 42,
            kind: InodeKind::File,
            xattrs: std::collections::BTreeMap::new(),
            dirty_bits: 0,
            mutation_gen: 0,
        };
        let ino = Ino(1);

        let attr = inode_attrs_to_inode_attr(ino, &attrs);
        assert_eq!(attr.inode_id, InodeId(1));
        assert_eq!(attr.generation, Generation(42));
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.mode, S_IFREG | 0o755);
        assert_eq!(attr.posix.uid, 1000);
        assert_eq!(attr.posix.gid, 100);
        assert_eq!(attr.posix.size, 4096);
        assert_eq!(attr.posix.blocks_512, 8);
        assert_eq!(attr.posix.nlink, 3);
        assert_eq!(attr.posix.atime_ns, 100_500_000_000);
        assert_eq!(attr.posix.mtime_ns, 200_250_000_000);
        assert_eq!(attr.posix.ctime_ns, 300_750_000_000);

        // Convert back
        let attrs2 = inode_attr_to_inode_attributes(&attr);
        assert_eq!(attrs2.mode, 0o755);
        assert_eq!(attrs2.uid, attrs.uid);
        assert_eq!(attrs2.gid, attrs.gid);
        assert_eq!(attrs2.size, attrs.size);
        assert_eq!(attrs2.blocks, attrs.blocks);
        assert_eq!(attrs2.nlink, attrs.nlink);
        assert_eq!(attrs2.generation, attrs.generation);
        assert_eq!(attrs2.kind, attrs.kind);
        assert_eq!(attrs2.atime, attrs.atime);
        assert_eq!(attrs2.mtime, attrs.mtime);
        assert_eq!(attrs2.ctime, attrs.ctime);
    }

    #[test]
    fn inode_attributes_to_inode_attr_directory() {
        let attrs = InodeAttributes::new(0o755, 0, 0, InodeKind::Directory);
        let attr = inode_attrs_to_inode_attr(Ino(2), &attrs);
        assert_eq!(attr.kind, NodeKind::Dir);
        assert_eq!(attr.posix.mode & tidefs_types_vfs_core::S_IFMT, S_IFDIR);
        assert_eq!(attr.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o755);
    }

    #[test]
    fn inode_attributes_to_inode_attr_symlink() {
        let attrs = InodeAttributes::new(0o777, 0, 0, InodeKind::Symlink);
        let attr = inode_attrs_to_inode_attr(Ino(3), &attrs);
        assert_eq!(attr.kind, NodeKind::Symlink);
    }

    #[test]
    fn inode_attr_to_inode_attributes_preserves_perms() {
        let attr = InodeAttr {
            inode_id: InodeId(10),
            generation: Generation(7),
            kind: NodeKind::File,
            posix: PosixAttrs {
                mode: S_IFREG | 0o600,
                uid: 500,
                gid: 500,
                nlink: 2,
                rdev: 0,
                atime_ns: 1_000_000_000,
                mtime_ns: 2_000_000_000,
                ctime_ns: 3_000_000_000,
                btime_ns: 0,
                size: 1024,
                blocks_512: 2,
                blksize: 4096,
            },
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };

        let attrs = inode_attr_to_inode_attributes(&attr);
        assert_eq!(attrs.mode, 0o600);
        assert_eq!(attrs.uid, 500);
        assert_eq!(attrs.gid, 500);
        assert_eq!(attrs.nlink, 2);
        assert_eq!(attrs.size, 1024);
        assert_eq!(attrs.blocks, 2);
        assert_eq!(attrs.generation, 7);
        assert_eq!(attrs.kind, InodeKind::File);
        assert_eq!(attrs.atime, Duration::from_secs(1));
        assert_eq!(attrs.mtime, Duration::from_secs(2));
        assert_eq!(attrs.ctime, Duration::from_secs(3));
    }

    #[test]
    fn inode_attr_unsupported_kind_defaults_to_file() {
        let attr = InodeAttr {
            inode_id: InodeId(1),
            generation: Generation(1),
            kind: NodeKind::CharDev,
            posix: PosixAttrs::new(S_IFREG | 0o644, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4096),
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        let attrs = inode_attr_to_inode_attributes(&attr);
        assert_eq!(attrs.kind, InodeKind::File);
    }

    // ------------------------------------------------------------------
    // TableAttributeStore
    // ------------------------------------------------------------------

    fn make_store() -> TableAttributeStore {
        let tbl = InodeTable::new(64, Box::new(SystemTimeSource));
        TableAttributeStore::new(Arc::new(tbl))
    }

    #[test]
    fn table_store_getattr_not_found() {
        let store = make_store();
        assert_eq!(store.getattr(1), Err(AttrError::InoNotFound));
    }

    #[test]
    fn table_store_create_and_getattr_roundtrip() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .expect("create");
        let attr = store.getattr(ino.0).expect("getattr");
        assert_eq!(attr.inode_id, InodeId(ino.0));
        assert!(attr.generation.0 > 0);
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o644);
        assert_eq!(attr.posix.uid, 1000);
        assert_eq!(attr.posix.gid, 100);
        assert_eq!(attr.posix.nlink, 1);
    }

    #[test]
    fn table_store_setattr_mode() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o755;
        let updated = store.setattr(ino.0, &set).unwrap();
        assert_eq!(updated.posix.mode & !tidefs_types_vfs_core::S_IFMT, 0o755);
        // Type bits preserved
        assert_eq!(updated.posix.mode & tidefs_types_vfs_core::S_IFMT, S_IFREG);
    }

    #[test]
    fn table_store_setattr_size() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 8192;
        let updated = store.setattr(ino.0, &set).unwrap();
        assert_eq!(updated.posix.size, 8192);
        assert_eq!(updated.posix.blocks_512, crate::blocks_512_for_size(8192));
    }

    #[test]
    fn table_store_setattr_uid_gid() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_UID | FATTR_GID;
        set.uid = 2000;
        set.gid = 3000;
        let updated = store.setattr(ino.0, &set).unwrap();
        assert_eq!(updated.posix.uid, 2000);
        assert_eq!(updated.posix.gid, 3000);
    }

    #[test]
    fn table_store_bump_and_drop_link() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        assert_eq!(store.bump_link(ino.0).unwrap(), 2);
        assert_eq!(store.bump_link(ino.0).unwrap(), 3);

        let attr = store.getattr(ino.0).unwrap();
        assert_eq!(attr.posix.nlink, 3);

        assert_eq!(store.drop_link(ino.0).unwrap(), 2);
        assert_eq!(store.drop_link(ino.0).unwrap(), 1);
        assert_eq!(store.drop_link(ino.0).unwrap(), 0);
        // File auto-removed
        assert_eq!(store.getattr(ino.0), Err(AttrError::InoNotFound));
    }

    #[test]
    fn table_store_setattr_timestamps() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let before = crate::now_ns();
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW | FATTR_MTIME_NOW;
        let updated = store.setattr(ino.0, &set).unwrap();
        assert!(updated.posix.atime_ns >= before);
        assert!(updated.posix.mtime_ns >= before);
        // ctime should also advance
        assert!(updated.posix.ctime_ns >= before);
    }

    #[test]
    fn table_store_to_stat() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o755, 500, 500, InodeKind::File),
            )
            .unwrap();

        let st = store.to_stat(ino.0).unwrap();
        assert_eq!(st.st_ino, ino.0);
        assert_eq!(st.st_mode & !tidefs_types_vfs_core::S_IFMT, 0o755);
        assert_eq!(st.st_uid, 500);
        assert_eq!(st.st_gid, 500);
        assert_eq!(st.st_nlink, 1);
    }

    #[test]
    fn table_store_to_stat_not_found() {
        let store = make_store();
        assert!(matches!(store.to_stat(99), Err(AttrError::InoNotFound)));
    }

    // ------------------------------------------------------------------
    // apply_setattr_to_inode_attributes
    // ------------------------------------------------------------------

    #[test]
    fn apply_setattr_to_inode_attrs_mode_preserves_type() {
        let mut attrs = InodeAttributes::new(0o600, 1000, 100, InodeKind::File);
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o777;
        apply_setattr_to_inode_attributes(&mut attrs, &set);
        // Type bits come from attrs.kind (File → S_IFREG)
        assert_eq!(attrs.mode & tidefs_types_vfs_core::S_IFMT, S_IFREG);
        // Permission bits come from set.mode
        assert_eq!(attrs.mode & !tidefs_types_vfs_core::S_IFMT, 0o777);
    }

    #[test]
    fn apply_setattr_to_inode_attrs_directory_type() {
        let mut attrs = InodeAttributes::new(0o755, 0, 0, InodeKind::Directory);
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o700;
        apply_setattr_to_inode_attributes(&mut attrs, &set);
        // Type bits come from attrs.kind (Directory → S_IFDIR)
        assert_eq!(attrs.mode & tidefs_types_vfs_core::S_IFMT, S_IFDIR);
        // Permission bits come from set.mode
        assert_eq!(attrs.mode & !tidefs_types_vfs_core::S_IFMT, 0o700);
    }

    #[test]
    fn apply_setattr_to_inode_attrs_size_recomputes_blocks() {
        let mut attrs = InodeAttributes::new(0o644, 0, 0, InodeKind::File);
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 8192;
        apply_setattr_to_inode_attributes(&mut attrs, &set);
        assert_eq!(attrs.size, 8192);
        assert_eq!(attrs.blocks, crate::blocks_512_for_size(8192));
    }

    #[test]
    fn insert_explicit_ino() {
        let store = make_store();
        let attr = InodeAttr {
            inode_id: InodeId(0),      // ignored by allocate
            generation: Generation(0), // assigned fresh
            kind: NodeKind::File,
            posix: PosixAttrs::new(S_IFREG | 0o644, 1000, 100, 1, 0, 0, 0, 0, 0, 1024, 2, 4096),
            flags: InodeFlags::none(),
            subtree_rev: 0,
            dir_rev: 0,
        };
        let ino = store.insert(1, attr).unwrap();
        assert!(ino.0 > 0);
        let stored = store.getattr(ino.0).unwrap();
        assert_eq!(stored.posix.size, 1024);
        assert_eq!(stored.posix.blocks_512, 2);
    }

    // ------------------------------------------------------------------
    // touch_atime / touch_mtime / touch_ctime
    // ------------------------------------------------------------------

    #[test]
    fn touch_atime_updates_atime_and_ctime() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let before = crate::now_ns();
        let orig = store.getattr(ino.0).unwrap();
        // Sleep a tiny bit to ensure the clock advances
        std::thread::sleep(std::time::Duration::from_millis(1));
        let updated = store.touch_atime(ino.0).unwrap();
        assert!(updated.posix.atime_ns > orig.posix.atime_ns);
        assert!(updated.posix.ctime_ns >= before);
        // mtime should be unchanged
        assert_eq!(updated.posix.mtime_ns, orig.posix.mtime_ns);
    }

    #[test]
    fn touch_mtime_updates_mtime_and_ctime() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let orig = store.getattr(ino.0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let updated = store.touch_mtime(ino.0).unwrap();
        assert!(updated.posix.mtime_ns > orig.posix.mtime_ns);
        assert!(updated.posix.ctime_ns > orig.posix.ctime_ns);
        // atime should be unchanged
        assert_eq!(updated.posix.atime_ns, orig.posix.atime_ns);
    }

    #[test]
    fn touch_ctime_updates_only_ctime() {
        let store = make_store();
        let ino = store
            .create(
                InodeKind::File,
                InodeAttributes::new(0o644, 1000, 100, InodeKind::File),
            )
            .unwrap();

        let orig = store.getattr(ino.0).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let updated = store.touch_ctime(ino.0).unwrap();
        assert!(updated.posix.ctime_ns > orig.posix.ctime_ns);
        // atime and mtime unchanged
        assert_eq!(updated.posix.atime_ns, orig.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, orig.posix.mtime_ns);
    }

    #[test]
    fn touch_atime_on_missing_inode() {
        let store = make_store();
        assert_eq!(store.touch_atime(99), Err(AttrError::InoNotFound));
    }

    #[test]
    fn touch_mtime_on_missing_inode() {
        let store = make_store();
        assert_eq!(store.touch_mtime(99), Err(AttrError::InoNotFound));
    }
}
