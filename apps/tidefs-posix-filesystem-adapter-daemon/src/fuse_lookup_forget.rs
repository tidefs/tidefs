// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE lookup/forget dispatch batch with dir-index name resolution and
//! adapter-local kernel lookup-reference accounting.
//!
//! This module implements the FUSE `lookup` and `forget` operations as a
//! coherent dispatch batch.  `dispatch_lookup` resolves a path component
//! through [`tidefs_dir_index::DirIndex`] and retrieves inode attributes
//! from the current inode-table projection.  The successful lookup is then
//! recorded in [`LookupReferenceProjection`], which is adapter/kernel state
//! only.  `dispatch_forget` releases those projected kernel references; it
//! never calls inode-table link/unlink and never decides durable inode
//! allocation, existence, reuse, or reclamation.
//!
//! This legacy batch remains a #665 adapter-projection bridge around the
//! dataset-scoped inode authority selected by #655 and allocator ownership
//! extracted by #664.  The inode table is an attribute projection here, not
//! the owner of mounted dataset inode lifetime.
//!
//! # Batch dispatcher
//!
//! [`FuseLookupForgetBatch`] wraps a shared inode table and provides an
//! opcode-dispatching entry point, `handle_lookup_forget`, that routes
//! FUSE lookup (opcode 1) and forget (opcode 2) requests to the
//! appropriate handler.  It accepts the dir-index via the
//! [`DirIndexResolver`] trait while keeping lookup references in explicit
//! adapter projection state.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use libc;
use tidefs_dir_index::DirIndex;
use tidefs_inode_table::{Ino, InodeAttributes, InodeTable};
use tidefs_types_vfs_core::Errno;

// ── FUSE opcode constants ─────────────────────────────────────────────────

/// FUSE opcode for lookup (kernel → userspace name resolution).
pub const FUSE_LOOKUP: u32 = 1;
/// FUSE opcode for forget (kernel releases lookup references).
pub const FUSE_FORGET: u32 = 2;
const FUSE_ROOT_INO: u64 = 1;

// ── LookupResult ──────────────────────────────────────────────────────────

/// Successful lookup outcome: inode number, generation, and attributes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupResult {
    /// Resolved inode number.
    pub ino: u64,
    /// Inode generation at lookup time.
    pub generation: u64,
    /// Snapshot of inode attributes.
    pub attrs: InodeAttributes,
}

// ── DirIndexResolver ──────────────────────────────────────────────────────

/// Provider of directory indexes keyed by parent inode number.
///
/// The batch dispatcher uses this to resolve a `&DirIndex` for the
/// parent directory during lookup dispatch.  Implementations may read
/// from an in-memory map, load from an object store, or delegate to
/// a namespace shard.
pub trait DirIndexResolver {
    /// Return a reference to the directory index for `parent_ino`,
    /// or `None` when the parent has no directory loaded.
    fn resolve(&self, parent_ino: u64) -> Option<&DirIndex>;
}

// ── LookupReferenceProjection ────────────────────────────────────────────

/// Adapter-local projection of kernel lookup references.
///
/// This state mirrors references the FUSE kernel client has acquired through
/// successful lookup replies.  It is intentionally separate from the
/// inode-table attribute projection and from the durable dataset inode
/// authority selected by #655.  Reaching zero here only means the adapter has
/// no remaining kernel lookup references for this inode.
#[derive(Debug, Default)]
pub struct LookupReferenceProjection {
    refs: Mutex<BTreeMap<u64, u64>>,
}

/// Result of applying a FUSE forget decrement to lookup-reference projection
/// state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForgetProjection {
    /// Reference count before applying this forget.
    pub previous: u64,
    /// Reference count after applying this forget.
    pub remaining: u64,
    /// True when a tracked non-root inode reached zero references.
    pub reached_zero: bool,
    /// True when the kernel released more references than were tracked.
    pub underflow: bool,
}

impl LookupReferenceProjection {
    /// Create empty lookup-reference projection state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one successful FUSE lookup reply for `ino`.
    pub fn record_lookup(&self, ino: u64) {
        if ino == FUSE_ROOT_INO {
            return;
        }
        let mut refs = self.refs.lock().unwrap();
        let entry = refs.entry(ino).or_insert(0);
        *entry = entry.saturating_add(1);
    }

    /// Apply a FUSE forget decrement to `ino`.
    pub fn forget(&self, ino: u64, nlookup: u64) -> ForgetProjection {
        if ino == FUSE_ROOT_INO {
            return ForgetProjection {
                previous: 0,
                remaining: 0,
                reached_zero: false,
                underflow: false,
            };
        }

        let mut refs = self.refs.lock().unwrap();
        let Some(count) = refs.get_mut(&ino) else {
            return ForgetProjection {
                previous: 0,
                remaining: 0,
                reached_zero: false,
                underflow: nlookup > 0,
            };
        };

        let previous = *count;
        let remaining = previous.saturating_sub(nlookup);
        let underflow = nlookup > previous;
        if remaining == 0 {
            refs.remove(&ino);
        } else {
            *count = remaining;
        }

        ForgetProjection {
            previous,
            remaining,
            reached_zero: previous > 0 && remaining == 0,
            underflow,
        }
    }

    /// Return the projected kernel lookup-reference count for `ino`.
    #[must_use]
    pub fn refcount(&self, ino: u64) -> u64 {
        self.refs.lock().unwrap().get(&ino).copied().unwrap_or(0)
    }
}

// ── FuseLookupForgetBatch ─────────────────────────────────────────────────

/// Opcode-dispatching batch handler for FUSE lookup and forget.
///
/// Wraps a shared inode-table attribute projection plus adapter-local lookup
/// references, then routes FUSE opcodes 1 (lookup) and 2 (forget) to the
/// appropriate dispatch function.  The dir-index is provided at call time via
/// a [`DirIndexResolver`].
#[derive(Clone)]
pub struct FuseLookupForgetBatch {
    inode_table: Arc<InodeTable>,
    lookup_refs: Arc<LookupReferenceProjection>,
}

impl FuseLookupForgetBatch {
    /// Create a new batch dispatcher wrapping `inode_table`.
    #[must_use]
    pub fn new(inode_table: Arc<InodeTable>) -> Self {
        Self {
            inode_table,
            lookup_refs: Arc::new(LookupReferenceProjection::new()),
        }
    }

    /// Return a reference to the wrapped inode table.
    #[must_use]
    pub fn inode_table(&self) -> &InodeTable {
        self.inode_table.as_ref()
    }

    /// Return the adapter-local lookup-reference projection.
    #[must_use]
    pub fn lookup_refs(&self) -> &LookupReferenceProjection {
        self.lookup_refs.as_ref()
    }

    /// Dispatch a FUSE lookup or forget request by opcode.
    ///
    /// # Parameters
    ///
    /// * `opcode` — `FUSE_LOOKUP` (1) or `FUSE_FORGET` (2).
    /// * `resolver` — provides the dir-index for lookup; unused for forget.
    /// * `parent_ino` — parent directory inode (only used for lookup).
    /// * `name` — child name bytes (only used for lookup).
    /// * `ino` — target inode number (only used for forget).
    /// * `nlookup` — kernel reference count to release (only used for forget).
    ///
    /// # Returns
    ///
    /// * `Ok(Some(LookupResult))` on successful lookup.
    /// * `Ok(None)` on successful forget (forget has no return value).
    /// * `Err(Errno)` on dispatch failure.
    pub fn handle_lookup_forget(
        &self,
        opcode: u32,
        resolver: &dyn DirIndexResolver,
        parent_ino: u64,
        name: &[u8],
        ino: u64,
        nlookup: u64,
    ) -> Result<Option<LookupResult>, Errno> {
        match opcode {
            FUSE_LOOKUP => {
                let dir = resolver
                    .resolve(parent_ino)
                    .ok_or(Errno(libc::ENOENT as u16))?;
                dispatch_lookup(
                    self.inode_table.as_ref(),
                    self.lookup_refs.as_ref(),
                    dir,
                    parent_ino,
                    name,
                )
                .map(Some)
            }
            FUSE_FORGET => dispatch_forget(self.lookup_refs.as_ref(), ino, nlookup).map(|_| None),
            _ => Err(Errno(libc::ENOSYS as u16)),
        }
    }
}

// ── dispatch_lookup ───────────────────────────────────────────────────────

/// Dispatch a FUSE `lookup` request.
///
/// Resolves `name` within `parent_ino` via `dir_index`, retrieves the
/// corresponding inode attributes from the inode-table projection, and records
/// one adapter-local kernel lookup reference in `lookup_refs`.  Returns
/// [`LookupResult`] on success or an appropriate errno on failure.
///
/// # Errors
///
/// | errno     | condition                                                    |
/// |-----------|--------------------------------------------------------------|
/// | `ENOENT`  | `name` does not exist in `dir_index`.                        |
/// | `ENOTDIR` | `parent_ino` exists but is not a directory.                  |
/// | `EIO`     | The resolved inode is absent from `inode_table` (integrity). |
pub fn dispatch_lookup(
    inode_table: &InodeTable,
    lookup_refs: &LookupReferenceProjection,
    dir_index: &DirIndex,
    parent_ino: u64,
    name: &[u8],
) -> Result<LookupResult, Errno> {
    // 1. Validate parent exists and is a directory.
    let parent_attrs = inode_table
        .lookup(Ino(parent_ino))
        .ok_or(Errno(libc::ENOENT as u16))?;

    if !parent_attrs.kind.is_dir() {
        return Err(Errno(libc::ENOTDIR as u16));
    }

    // 2. Resolve the name through the directory index.
    let entry = dir_index.lookup(name).ok_or(Errno(libc::ENOENT as u16))?;

    // 3. Retrieve the inode from the inode table.
    let ino = Ino(entry.inode_id);
    let attrs = inode_table.lookup(ino).ok_or(Errno(libc::EIO as u16))?;

    let generation = attrs.generation;

    // 4. Record the kernel lookup reference in adapter projection state.
    lookup_refs.record_lookup(ino.0);

    Ok(LookupResult {
        ino: ino.0,
        generation,
        attrs,
    })
}

// ── dispatch_forget ───────────────────────────────────────────────────────

/// Dispatch a FUSE `forget` request.
///
/// Releases `nlookup` kernel references on `ino` from
/// [`LookupReferenceProjection`].  This operation never mutates the inode
/// table; durable inode lifetime remains owned by the mounted dataset
/// authority.
///
/// A zero `nlookup` is a no-op: it records no underflow and leaves any
/// existing projected reference count unchanged.
pub fn dispatch_forget(
    lookup_refs: &LookupReferenceProjection,
    ino: u64,
    nlookup: u64,
) -> Result<ForgetProjection, Errno> {
    Ok(lookup_refs.forget(ino, nlookup))
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tidefs_dir_index::DatasetDirPolicy;
    use tidefs_inode_table::{InodeKind, SystemTimeSource};

    /// Create a fresh inode table for testing.
    fn make_inode_table() -> InodeTable {
        InodeTable::new(1024, Box::new(SystemTimeSource))
    }

    /// Create a fresh, empty directory index for a given parent inode.
    fn make_dir_index(parent_ino: u64) -> DirIndex {
        DirIndex::new(parent_ino, DatasetDirPolicy::default())
    }

    /// Helper: create a directory inode and return its inode number.
    fn make_dir(tbl: &InodeTable, mode: u32, uid: u32, gid: u32) -> u64 {
        let attrs = InodeAttributes::new(mode, uid, gid, InodeKind::Directory);
        let ino = tbl.create(InodeKind::Directory, attrs).unwrap();
        ino.0
    }

    /// Helper: create a regular-file inode and return its inode number.
    fn make_file(tbl: &InodeTable, mode: u32, uid: u32, gid: u32) -> u64 {
        let attrs = InodeAttributes::new(mode, uid, gid, InodeKind::File);
        let ino = tbl.create(InodeKind::File, attrs).unwrap();
        ino.0
    }

    /// Helper: insert a name->inode entry into a directory index.
    fn insert_entry(dir: &mut DirIndex, name: &[u8], ino: u64, generation: u64, kind: u32) {
        dir.insert(name, ino, generation, kind).unwrap();
    }

    // ── In-memory DirIndexResolver for tests ─────────────────────────

    /// A simple resolver backed by a `HashMap<u64, DirIndex>`.
    struct MapResolver {
        dirs: HashMap<u64, DirIndex>,
    }

    impl MapResolver {
        fn new() -> Self {
            Self {
                dirs: HashMap::new(),
            }
        }

        fn insert(&mut self, parent_ino: u64, dir: DirIndex) {
            self.dirs.insert(parent_ino, dir);
        }
    }

    impl DirIndexResolver for MapResolver {
        fn resolve(&self, parent_ino: u64) -> Option<&DirIndex> {
            self.dirs.get(&parent_ino)
        }
    }

    // ── Successful lookup ────────────────────────────────────────────

    #[test]
    fn lookup_existing_file_returns_attrs() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 1000, 1000);
        let child_attrs = tbl.lookup(Ino(child)).unwrap();
        let child_gen = child_attrs.generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"hello.txt", child, child_gen, libc::S_IFREG);

        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, parent, b"hello.txt").unwrap();
        assert_eq!(result.ino, child);
        assert_eq!(result.generation, child_gen);
        assert_eq!(result.attrs.mode, 0o644);
        assert_eq!(result.attrs.uid, 1000);
        assert_eq!(result.attrs.gid, 1000);
        assert_eq!(result.attrs.kind, InodeKind::File);
        assert_eq!(refs.refcount(child), 1);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, child_attrs.nlink);
    }

    #[test]
    fn lookup_directory_entry_returns_dir_attrs() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let subdir = make_dir(&tbl, 0o700, 1000, 1000);
        let subdir_attrs = tbl.lookup(Ino(subdir)).unwrap();
        let subdir_gen = subdir_attrs.generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"mydir", subdir, subdir_gen, libc::S_IFDIR);

        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, parent, b"mydir").unwrap();
        assert_eq!(result.ino, subdir);
        assert_eq!(result.attrs.kind, InodeKind::Directory);
        assert_eq!(result.attrs.mode, 0o700);
        assert_eq!(refs.refcount(subdir), 1);
    }

    // ── ENOENT: missing name ─────────────────────────────────────────

    #[test]
    fn lookup_missing_name_returns_enoent() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let dir = make_dir_index(parent);

        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, parent, b"nope");
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
        assert_eq!(refs.refcount(parent), 0);
    }

    // ── ENOTDIR: parent is not a directory ───────────────────────────

    #[test]
    fn lookup_parent_not_directory_returns_enotdir() {
        let tbl = make_inode_table();
        let file_ino = make_file(&tbl, 0o644, 0, 0);
        let dir = make_dir_index(file_ino);

        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, file_ino, b"anything");
        assert_eq!(result, Err(Errno(libc::ENOTDIR as u16)));
    }

    // ── ENOENT: parent inode not in table ────────────────────────────

    #[test]
    fn lookup_missing_parent_returns_enoent() {
        let tbl = make_inode_table();
        // parent 999 was never allocated
        let dir = make_dir_index(999);

        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, 999, b"anything");
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
    }

    // ── lookup records projected kernel refs ─────────────────────────

    #[test]
    fn lookup_records_projected_refcount_without_mutating_nlink() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"f", child, child_gen, libc::S_IFREG);

        let before = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(before, 1); // only the create link

        let refs = LookupReferenceProjection::new();
        dispatch_lookup(&tbl, &refs, &dir, parent, b"f").unwrap();
        let after = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after, before);
        assert_eq!(refs.refcount(child), 1);

        dispatch_lookup(&tbl, &refs, &dir, parent, b"f").unwrap();
        let after2 = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after2, before);
        assert_eq!(refs.refcount(child), 2);
    }

    // ── forget decrement to non-zero ─────────────────────────────────

    #[test]
    fn forget_decrements_projected_refs_to_nonzero() {
        let tbl = make_inode_table();
        let _parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        let before = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(before, 1);

        let refs = LookupReferenceProjection::new();
        refs.record_lookup(child);
        refs.record_lookup(child);

        let projection = dispatch_forget(&refs, child, 1).unwrap();
        assert_eq!(projection.remaining, 1);
        assert!(!projection.reached_zero);
        let after = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after, before);
    }

    // ── forget decrement to zero ─────────────────────────────────────

    #[test]
    fn forget_decrements_projected_refs_to_zero_without_removing_inode() {
        let tbl = make_inode_table();
        let _parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        let refs = LookupReferenceProjection::new();
        refs.record_lookup(child);
        let projection = dispatch_forget(&refs, child, 1).unwrap();

        assert!(projection.reached_zero);
        assert_eq!(refs.refcount(child), 0);
        assert!(tbl.lookup(Ino(child)).is_some());
    }

    // ── forget with nlookup > 1 ──────────────────────────────────────

    #[test]
    fn forget_with_nlookup_gt_1() {
        let tbl = make_inode_table();
        let _parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);

        let refs = LookupReferenceProjection::new();
        refs.record_lookup(child);
        refs.record_lookup(child);
        refs.record_lookup(child);
        assert_eq!(refs.refcount(child), 3);

        let projection = dispatch_forget(&refs, child, 3).unwrap();
        assert!(projection.reached_zero);
        assert_eq!(refs.refcount(child), 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);
    }

    #[test]
    fn forget_nlookup_gt_refcount_reports_underflow_without_removing_inode() {
        let tbl = make_inode_table();
        let _parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        let refs = LookupReferenceProjection::new();
        refs.record_lookup(child);
        let projection = dispatch_forget(&refs, child, 5).unwrap();

        assert!(projection.reached_zero);
        assert!(projection.underflow);
        assert!(tbl.lookup(Ino(child)).is_some());
    }

    // ── forget nlookup=0 is a no-op ──────────────────────────────────

    #[test]
    fn forget_nlookup_zero_is_noop() {
        let refs = LookupReferenceProjection::new();
        refs.record_lookup(2);

        let result = dispatch_forget(&refs, 2, 0).unwrap();
        assert_eq!(
            result,
            ForgetProjection {
                previous: 1,
                remaining: 1,
                reached_zero: false,
                underflow: false,
            }
        );
        assert_eq!(refs.refcount(2), 1);
    }

    // ── forget missing inode ─────────────────────────────────────────

    #[test]
    fn forget_unknown_projection_is_noop_underflow() {
        let refs = LookupReferenceProjection::new();
        let result = dispatch_forget(&refs, 999, 1).unwrap();
        assert_eq!(
            result,
            ForgetProjection {
                previous: 0,
                remaining: 0,
                reached_zero: false,
                underflow: true,
            }
        );
    }

    // ── Lookup-then-forget round-trip ────────────────────────────────

    #[test]
    fn lookup_then_forget_roundtrip() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 1000, 1000);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"roundtrip.txt", child, child_gen, libc::S_IFREG);

        let initial_nlink = tbl.lookup(Ino(child)).unwrap().nlink;
        let refs = LookupReferenceProjection::new();
        let result = dispatch_lookup(&tbl, &refs, &dir, parent, b"roundtrip.txt").unwrap();
        assert_eq!(result.ino, child);
        assert_eq!(refs.refcount(child), 1);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, initial_nlink);

        let projection = dispatch_forget(&refs, child, 1).unwrap();
        assert!(projection.reached_zero);
        assert_eq!(refs.refcount(child), 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, initial_nlink);

        let projection = dispatch_forget(&refs, child, 1).unwrap();
        assert!(projection.underflow);
        assert!(tbl.lookup(Ino(child)).is_some());
    }

    // ── Multiple lookups balanced by single forget ───────────────────

    #[test]
    fn multiple_lookups_balanced_by_single_forget() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"multi", child, child_gen, libc::S_IFREG);

        let initial_nlink = tbl.lookup(Ino(child)).unwrap().nlink;
        let refs = LookupReferenceProjection::new();
        dispatch_lookup(&tbl, &refs, &dir, parent, b"multi").unwrap();
        dispatch_lookup(&tbl, &refs, &dir, parent, b"multi").unwrap();
        dispatch_lookup(&tbl, &refs, &dir, parent, b"multi").unwrap();
        assert_eq!(refs.refcount(child), 3);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, initial_nlink);

        let projection = dispatch_forget(&refs, child, 3).unwrap();
        assert!(projection.reached_zero);
        assert_eq!(refs.refcount(child), 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, initial_nlink);
    }

    // ── Lookup on empty directory ────────────────────────────────────

    #[test]
    fn lookup_in_empty_directory_returns_enoent() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let dir = make_dir_index(parent);
        let refs = LookupReferenceProjection::new();

        assert_eq!(
            dispatch_lookup(&tbl, &refs, &dir, parent, b"anything"),
            Err(Errno(libc::ENOENT as u16))
        );
    }

    // ── Batch dispatcher: opcode routing ─────────────────────────────

    #[test]
    fn batch_handle_lookup_forget_lookup_success() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 1000, 1000);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"batch.txt", child, child_gen, libc::S_IFREG);

        let mut resolver = MapResolver::new();
        resolver.insert(parent, dir);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let result = batch
            .handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"batch.txt", 0, 0)
            .unwrap()
            .unwrap();

        assert_eq!(result.ino, child);
        assert_eq!(result.attrs.mode, 0o644);
        assert_eq!(batch.lookup_refs().refcount(child), 1);
    }

    #[test]
    fn batch_handle_lookup_forget_missing_name() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let dir = make_dir_index(parent);
        // No entries inserted — empty directory.

        let mut resolver = MapResolver::new();
        resolver.insert(parent, dir);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let result = batch.handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"missing", 0, 0);
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
    }

    #[test]
    fn batch_handle_lookup_forget_forget_success() {
        let tbl = make_inode_table();
        let _parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        let initial_nlink = tbl.lookup(Ino(child)).unwrap().nlink;

        let resolver = MapResolver::new();
        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        batch.lookup_refs().record_lookup(child);
        let result = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(result, Ok(None));
        assert_eq!(batch.lookup_refs().refcount(child), 0);
        assert_eq!(
            batch.inode_table().lookup(Ino(child)).unwrap().nlink,
            initial_nlink
        );
    }

    #[test]
    fn batch_handle_lookup_forget_unknown_opcode() {
        let tbl = make_inode_table();
        let resolver = MapResolver::new();
        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let result = batch.handle_lookup_forget(99, &resolver, 1, b"x", 1, 1);
        assert_eq!(result, Err(Errno(libc::ENOSYS as u16)));
    }

    // ── Full lookup→forget lifecycle through batch dispatcher ────────

    #[test]
    fn batch_full_lifecycle_lookup_then_forget() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 1000, 1000);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"lifecycle.txt", child, child_gen, libc::S_IFREG);

        let mut resolver = MapResolver::new();
        resolver.insert(parent, dir);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));

        // Phase 1: kernel looks up "lifecycle.txt"
        let lookup_result = batch
            .handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"lifecycle.txt", 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(lookup_result.ino, child);
        let initial_nlink = batch.inode_table().lookup(Ino(child)).unwrap().nlink;
        assert_eq!(batch.lookup_refs().refcount(child), 1);

        // Phase 2: kernel releases the reference via forget
        let forget_result = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(forget_result, Ok(None));
        assert_eq!(batch.lookup_refs().refcount(child), 0);
        assert_eq!(
            batch.inode_table().lookup(Ino(child)).unwrap().nlink,
            initial_nlink
        );

        // Phase 3: an extra kernel forget only underflows adapter refs.
        let forget2 = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(forget2, Ok(None));
        assert!(batch.inode_table().lookup(Ino(child)).is_some());
    }

    #[test]
    fn batch_lookup_forget_across_multiple_files() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);

        let child_a = make_file(&tbl, 0o644, 1000, 1000);
        let gen_a = tbl.lookup(Ino(child_a)).unwrap().generation;

        let child_b = make_file(&tbl, 0o644, 1000, 1000);
        let gen_b = tbl.lookup(Ino(child_b)).unwrap().generation;

        let child_c = make_file(&tbl, 0o644, 1000, 1000);
        let gen_c = tbl.lookup(Ino(child_c)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"a", child_a, gen_a, libc::S_IFREG);
        insert_entry(&mut dir, b"b", child_b, gen_b, libc::S_IFREG);
        insert_entry(&mut dir, b"c", child_c, gen_c, libc::S_IFREG);

        let mut resolver = MapResolver::new();
        resolver.insert(parent, dir);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));

        // Lookup all three files
        let ra = batch
            .handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"a", 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(ra.ino, child_a);

        let rb = batch
            .handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"b", 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(rb.ino, child_b);

        let rc = batch
            .handle_lookup_forget(FUSE_LOOKUP, &resolver, parent, b"c", 0, 0)
            .unwrap()
            .unwrap();
        assert_eq!(rc.ino, child_c);

        assert_eq!(batch.lookup_refs().refcount(child_a), 1);
        assert_eq!(batch.lookup_refs().refcount(child_b), 1);
        assert_eq!(batch.lookup_refs().refcount(child_c), 1);

        // Forget a and c, keeping b
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_a, 1)
            .unwrap();
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_c, 1)
            .unwrap();

        assert_eq!(batch.lookup_refs().refcount(child_a), 0);
        assert_eq!(batch.lookup_refs().refcount(child_b), 1);
        assert_eq!(batch.lookup_refs().refcount(child_c), 0);
        assert!(batch.inode_table().lookup(Ino(child_a)).is_some());
        assert!(batch.inode_table().lookup(Ino(child_c)).is_some());

        // Forget b.
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_b, 1)
            .unwrap();
        assert_eq!(batch.lookup_refs().refcount(child_b), 0);

        // Extra forget on a leaves durable inode projection untouched.
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_a, 1)
            .unwrap();
        assert!(batch.inode_table().lookup(Ino(child_a)).is_some());
    }
}

// ── FuseLookupForgetSession ──────────────────────────────────────────────

/// A FUSE session adapter that wraps [`FuseLookupForgetBatch`] and a
/// [`DirIndexResolver`], providing methods with the same signatures as
/// the `fuser::Filesystem` trait's `lookup` and `forget` methods.
///
/// This struct is the integration point between the batch dispatcher
/// and a FUSE session loop.  Construct it with a shared inode table
/// and inject a [`DirIndexResolver`] implementation for your dir-index
/// backend (e.g. Namespace, local-filesystem, or an in-memory map).
///
/// # Example
///
/// ```ignore
/// let batch = FuseLookupForgetBatch::new(inode_table);
/// let session = FuseLookupForgetSession::new(batch);
///
/// // In the FUSE session loop (fuser::Filesystem impl):
/// fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
///     match self.lf_session.lookup(self.resolver(), parent, name.as_bytes()) {
///         Ok(Some(result)) => { /* build EntryParam from result */ }
///         Ok(None) => reply.error(libc::ENOENT),
///         Err(errno) => reply.error(errno.raw() as i32),
///     }
/// }
/// ```
pub struct FuseLookupForgetSession {
    batch: FuseLookupForgetBatch,
}

impl FuseLookupForgetSession {
    /// Create a new session adapter wrapping `batch`.
    #[must_use]
    pub fn new(batch: FuseLookupForgetBatch) -> Self {
        Self { batch }
    }

    /// Return a reference to the underlying batch dispatcher.
    #[must_use]
    pub fn batch(&self) -> &FuseLookupForgetBatch {
        &self.batch
    }

    /// Resolve a path component: `name` within directory `parent_ino`.
    ///
    /// Returns `Some(LookupResult)` on success, `None` when the name
    /// does not exist (ENOENT), or `Err(Errno)` on dispatch failure
    /// (ENOTDIR, EIO).
    pub fn lookup(
        &self,
        resolver: &dyn DirIndexResolver,
        parent_ino: u64,
        name: &[u8],
    ) -> Result<Option<LookupResult>, Errno> {
        match self
            .batch
            .handle_lookup_forget(FUSE_LOOKUP, resolver, parent_ino, name, 0, 0)
        {
            Ok(Some(result)) => Ok(Some(result)),
            Ok(None) => Ok(None),
            Err(e) if e == Errno(libc::ENOENT as u16) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Release `nlookup` kernel references on `ino`.
    ///
    /// Zero-count forget is a no-op. Durable inode lifetime is not changed
    /// by this adapter projection.
    pub fn forget(&self, ino: u64, nlookup: u64) -> Result<(), Errno> {
        self.batch
            .handle_lookup_forget(FUSE_FORGET, &NullResolver, 0, b"", ino, nlookup)
            .map(|_| ())
    }
}

// ── NullResolver ─────────────────────────────────────────────────────────

/// A resolver that always returns `None`.  Used by `forget` which does not
/// need a directory index.
struct NullResolver;

impl DirIndexResolver for NullResolver {
    fn resolve(&self, _parent_ino: u64) -> Option<&DirIndex> {
        None
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod session_tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tidefs_dir_index::DatasetDirPolicy;
    use tidefs_inode_table::{InodeAttributes, InodeKind, InodeTable, SystemTimeSource};

    fn make_table() -> InodeTable {
        InodeTable::new(1024, Box::new(SystemTimeSource))
    }

    fn make_dir_index(parent_ino: u64) -> DirIndex {
        DirIndex::new(parent_ino, DatasetDirPolicy::default())
    }

    fn make_dir(tbl: &InodeTable, mode: u32) -> u64 {
        let attrs = InodeAttributes::new(mode, 0, 0, InodeKind::Directory);
        tbl.create(InodeKind::Directory, attrs).unwrap().0
    }

    fn make_file(tbl: &InodeTable, mode: u32) -> u64 {
        let attrs = InodeAttributes::new(mode, 0, 0, InodeKind::File);
        tbl.create(InodeKind::File, attrs).unwrap().0
    }

    struct TestResolver {
        dirs: HashMap<u64, DirIndex>,
    }

    impl TestResolver {
        fn new() -> Self {
            Self {
                dirs: HashMap::new(),
            }
        }

        fn insert(&mut self, parent_ino: u64, dir: DirIndex) {
            self.dirs.insert(parent_ino, dir);
        }

        fn get_mut(&mut self, parent_ino: u64) -> Option<&mut DirIndex> {
            self.dirs.get_mut(&parent_ino)
        }
    }

    impl DirIndexResolver for TestResolver {
        fn resolve(&self, parent_ino: u64) -> Option<&DirIndex> {
            self.dirs.get(&parent_ino)
        }
    }

    fn populate(
        tbl: &InodeTable,
        resolver: &mut TestResolver,
        parent: u64,
        name: &[u8],
        mode: u32,
        kind: u32,
    ) -> u64 {
        let ino = if kind == libc::S_IFDIR {
            make_dir(tbl, mode)
        } else {
            make_file(tbl, mode)
        };
        let gen = tbl.lookup(Ino(ino)).unwrap().generation;
        let dir = resolver.get_mut(parent).unwrap();
        dir.insert(name, ino, gen, kind).unwrap();
        ino
    }

    // ── Session: lookup success ─────────────────────────────────────

    #[test]
    fn session_lookup_existing_file() {
        let tbl = make_table();
        let parent = make_dir(&tbl, 0o755);
        let mut resolver = TestResolver::new();
        resolver.insert(parent, make_dir_index(parent));

        let child = populate(
            &tbl,
            &mut resolver,
            parent,
            b"hello.txt",
            0o644,
            libc::S_IFREG,
        );

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        let result = session
            .lookup(&resolver, parent, b"hello.txt")
            .unwrap()
            .unwrap();
        assert_eq!(result.ino, child);
        assert_eq!(result.attrs.mode, 0o644);
        assert_eq!(session.batch().lookup_refs().refcount(child), 1);
    }

    #[test]
    fn session_lookup_missing_name() {
        let tbl = make_table();
        let parent = make_dir(&tbl, 0o755);
        let mut resolver = TestResolver::new();
        resolver.insert(parent, make_dir_index(parent));

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        let result = session.lookup(&resolver, parent, b"nope").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn session_lookup_parent_not_directory() {
        let tbl = make_table();
        let file_ino = make_file(&tbl, 0o644);
        let mut resolver = TestResolver::new();
        resolver.insert(file_ino, make_dir_index(file_ino));

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        let result = session.lookup(&resolver, file_ino, b"anything");
        assert_eq!(result, Err(Errno(libc::ENOTDIR as u16)));
    }

    // ── Session: forget ─────────────────────────────────────────────

    #[test]
    fn session_forget_decrements_projected_refcount() {
        let tbl = make_table();
        let _parent = make_dir(&tbl, 0o755);
        let child = make_file(&tbl, 0o644);
        let initial_nlink = tbl.lookup(Ino(child)).unwrap().nlink;

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);
        session.batch().lookup_refs().record_lookup(child);
        session.batch().lookup_refs().record_lookup(child);

        session.forget(child, 1).unwrap();
        assert_eq!(session.batch().lookup_refs().refcount(child), 1);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );
    }

    #[test]
    fn session_forget_to_zero_keeps_inode_projection() {
        let tbl = make_table();
        let _parent = make_dir(&tbl, 0o755);
        let child = make_file(&tbl, 0o644);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);
        session.batch().lookup_refs().record_lookup(child);

        session.forget(child, 1).unwrap();
        assert_eq!(session.batch().lookup_refs().refcount(child), 0);
        assert!(session.batch().inode_table().lookup(Ino(child)).is_some());
    }

    #[test]
    fn session_forget_zero_nlookup_is_noop() {
        let tbl = make_table();
        let _parent = make_dir(&tbl, 0o755);
        let child = make_file(&tbl, 0o644);
        let initial_nlink = tbl.lookup(Ino(child)).unwrap().nlink;

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);
        session.batch().lookup_refs().record_lookup(child);

        session.forget(child, 0).unwrap();
        assert_eq!(session.batch().lookup_refs().refcount(child), 1);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );
    }

    // ── Session: full lifecycle ─────────────────────────────────────

    #[test]
    fn session_full_lifecycle_lookup_then_forget() {
        let tbl = make_table();
        let parent = make_dir(&tbl, 0o755);
        let mut resolver = TestResolver::new();
        resolver.insert(parent, make_dir_index(parent));

        let child = populate(
            &tbl,
            &mut resolver,
            parent,
            b"lifecycle.txt",
            0o644,
            libc::S_IFREG,
        );

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        // Phase 1: kernel looks up the file
        let result = session
            .lookup(&resolver, parent, b"lifecycle.txt")
            .unwrap()
            .unwrap();
        assert_eq!(result.ino, child);
        let initial_nlink = session
            .batch()
            .inode_table()
            .lookup(Ino(child))
            .unwrap()
            .nlink;
        assert_eq!(session.batch().lookup_refs().refcount(child), 1);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );

        // Phase 2: kernel releases reference
        session.forget(child, 1).unwrap();
        assert_eq!(session.batch().lookup_refs().refcount(child), 0);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );

        // Phase 3: an extra forget underflows only adapter projection.
        session.forget(child, 1).unwrap();
        assert!(session.batch().inode_table().lookup(Ino(child)).is_some());
    }

    #[test]
    fn session_multiple_lookups_single_forget() {
        let tbl = make_table();
        let parent = make_dir(&tbl, 0o755);
        let mut resolver = TestResolver::new();
        resolver.insert(parent, make_dir_index(parent));

        let child = populate(&tbl, &mut resolver, parent, b"multi", 0o644, libc::S_IFREG);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        // Three lookups
        session.lookup(&resolver, parent, b"multi").unwrap();
        session.lookup(&resolver, parent, b"multi").unwrap();
        session.lookup(&resolver, parent, b"multi").unwrap();
        let initial_nlink = session
            .batch()
            .inode_table()
            .lookup(Ino(child))
            .unwrap()
            .nlink;
        assert_eq!(session.batch().lookup_refs().refcount(child), 3);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );

        // One forget with nlookup=3
        session.forget(child, 3).unwrap();
        assert_eq!(session.batch().lookup_refs().refcount(child), 0);
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            initial_nlink
        );
    }

    #[test]
    fn session_lookup_forget_multiple_files_independent() {
        let tbl = make_table();
        let parent = make_dir(&tbl, 0o755);
        let mut resolver = TestResolver::new();
        resolver.insert(parent, make_dir_index(parent));

        let child_a = populate(&tbl, &mut resolver, parent, b"a", 0o644, libc::S_IFREG);
        let child_b = populate(&tbl, &mut resolver, parent, b"b", 0o644, libc::S_IFREG);
        let child_c = populate(&tbl, &mut resolver, parent, b"c", 0o644, libc::S_IFREG);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        // Lookup all three
        session.lookup(&resolver, parent, b"a").unwrap();
        session.lookup(&resolver, parent, b"b").unwrap();
        session.lookup(&resolver, parent, b"c").unwrap();

        assert_eq!(session.batch().lookup_refs().refcount(child_a), 1);
        assert_eq!(session.batch().lookup_refs().refcount(child_b), 1);
        assert_eq!(session.batch().lookup_refs().refcount(child_c), 1);

        // Forget a and c
        session.forget(child_a, 1).unwrap();
        session.forget(child_c, 1).unwrap();

        assert_eq!(session.batch().lookup_refs().refcount(child_a), 0);
        assert_eq!(session.batch().lookup_refs().refcount(child_b), 1);
        assert_eq!(session.batch().lookup_refs().refcount(child_c), 0);
        assert!(session.batch().inode_table().lookup(Ino(child_a)).is_some());
        assert!(session.batch().inode_table().lookup(Ino(child_c)).is_some());

        // Forget b then send an extra forget for a.
        session.forget(child_b, 1).unwrap();
        session.forget(child_a, 1).unwrap();

        assert!(session.batch().inode_table().lookup(Ino(child_a)).is_some());
        assert_eq!(session.batch().lookup_refs().refcount(child_b), 0);
        assert_eq!(session.batch().lookup_refs().refcount(child_c), 0);
    }
}
