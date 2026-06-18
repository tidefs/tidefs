// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE lookup/forget dispatch batch with dir-index name resolution and
//! inode-table reference-count lifecycle integration.
//!
//! This module implements the FUSE `lookup` and `forget` operations as a
//! coherent dispatch batch.  `dispatch_lookup` resolves a path component
//! through [`tidefs_dir_index::DirIndex`], retrieves inode attributes
//! from [`tidefs_inode_table::InodeTable`], and increments the kernel
//! reference count via [`InodeTable::link`].  `dispatch_forget` releases
//! kernel references via [`InodeTable::unlink`]; when nlink reaches zero
//! the inode table auto-removes the inode, which the background reclaim
//! path may further process per existing reclaim-crate policy.
//!
//! # Batch dispatcher
//!
//! [`FuseLookupForgetBatch`] wraps a shared inode table and provides an
//! opcode-dispatching entry point, `handle_lookup_forget`, that routes
//! FUSE lookup (opcode 1) and forget (opcode 2) requests to the
//! appropriate handler.  It accepts the dir-index via the
//! [`DirIndexResolver`] trait, keeping the batch stateless across calls.

use std::sync::Arc;

use libc;
use tidefs_dir_index::DirIndex;
use tidefs_inode_table::{Ino, InodeAttributes, InodeTable, InodeTableError};
use tidefs_types_vfs_core::Errno;

// ── FUSE opcode constants ─────────────────────────────────────────────────

/// FUSE opcode for lookup (kernel → userspace name resolution).
pub const FUSE_LOOKUP: u32 = 1;
/// FUSE opcode for forget (kernel releases lookup references).
pub const FUSE_FORGET: u32 = 2;

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

// ── FuseLookupForgetBatch ─────────────────────────────────────────────────

/// Opcode-dispatching batch handler for FUSE lookup and forget.
///
/// Wraps a shared [`InodeTable`] and routes FUSE opcodes 1 (lookup) and
/// 2 (forget) to the appropriate dispatch function.  The dir-index is
/// provided at call time via a [`DirIndexResolver`], keeping the batch
/// handler stateless across calls.
#[derive(Clone)]
pub struct FuseLookupForgetBatch {
    inode_table: Arc<InodeTable>,
}

impl FuseLookupForgetBatch {
    /// Create a new batch dispatcher wrapping `inode_table`.
    #[must_use]
    pub fn new(inode_table: Arc<InodeTable>) -> Self {
        Self { inode_table }
    }

    /// Return a reference to the wrapped inode table.
    #[must_use]
    pub fn inode_table(&self) -> &InodeTable {
        &self.inode_table
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
                dispatch_lookup(&self.inode_table, dir, parent_ino, name).map(Some)
            }
            FUSE_FORGET => dispatch_forget(&self.inode_table, ino, nlookup).map(|()| None),
            _ => Err(Errno(libc::ENOSYS as u16)),
        }
    }
}

// ── dispatch_lookup ───────────────────────────────────────────────────────

/// Dispatch a FUSE `lookup` request.
///
/// Resolves `name` within `parent_ino` via `dir_index`, retrieves the
/// corresponding inode attributes from `inode_table`, and bumps the
/// kernel reference count via [`InodeTable::link`].  Returns
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

    // 4. Bump the kernel reference count so forget can later release it.
    //    Ignore errors (e.g. InodeNotFound shouldn't happen since we just
    //    retrieved the inode) — the kernel still gets valid attrs.
    let _ = inode_table.link(ino);

    Ok(LookupResult {
        ino: ino.0,
        generation,
        attrs,
    })
}

// ── dispatch_forget ───────────────────────────────────────────────────────

/// Dispatch a FUSE `forget` request.
///
/// Releases `nlookup` kernel references on `ino` via [`InodeTable::unlink`].
/// When nlink reaches zero the inode table auto-removes the inode entry;
/// the background reclaim path may further process the freed slot per
/// existing reclaim-crate policy.
///
/// # Errors
///
/// | errno     | condition                                                    |
/// |-----------|--------------------------------------------------------------|
/// | `ENOENT`  | The inode is not in the table (already freed or never alloc).|
/// | `EINVAL`  | `nlookup` is zero.                                           |
/// | `EIO`     | An underlying table error occurred.                          |
pub fn dispatch_forget(inode_table: &InodeTable, ino: u64, nlookup: u64) -> Result<(), Errno> {
    if nlookup == 0 {
        return Err(Errno(libc::EINVAL as u16));
    }

    // Validate the inode exists before we start unlinking.
    let _attrs = inode_table
        .lookup(Ino(ino))
        .ok_or(Errno(libc::ENOENT as u16))?;

    for _ in 0..nlookup {
        match inode_table.unlink(Ino(ino)) {
            Ok(()) => {}
            Err(InodeTableError::InodeNotFound) => {
                // Already removed by a prior unlink in this loop;
                // remaining releases are no-ops.
                return Ok(());
            }
            Err(_) => return Err(Errno(libc::EIO as u16)),
        }
    }

    Ok(())
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

        let result = dispatch_lookup(&tbl, &dir, parent, b"hello.txt").unwrap();
        assert_eq!(result.ino, child);
        assert_eq!(result.generation, child_gen);
        assert_eq!(result.attrs.mode, 0o644);
        assert_eq!(result.attrs.uid, 1000);
        assert_eq!(result.attrs.gid, 1000);
        assert_eq!(result.attrs.kind, InodeKind::File);

        // Kernel refcount was bumped: nlink should be 2 (1 from create + 1 from lookup)
        let updated = tbl.lookup(Ino(child)).unwrap();
        assert_eq!(updated.nlink, 2);
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

        let result = dispatch_lookup(&tbl, &dir, parent, b"mydir").unwrap();
        assert_eq!(result.ino, subdir);
        assert_eq!(result.attrs.kind, InodeKind::Directory);
        assert_eq!(result.attrs.mode, 0o700);
    }

    // ── ENOENT: missing name ─────────────────────────────────────────

    #[test]
    fn lookup_missing_name_returns_enoent() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let dir = make_dir_index(parent);

        let result = dispatch_lookup(&tbl, &dir, parent, b"nope");
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
    }

    // ── ENOTDIR: parent is not a directory ───────────────────────────

    #[test]
    fn lookup_parent_not_directory_returns_enotdir() {
        let tbl = make_inode_table();
        let file_ino = make_file(&tbl, 0o644, 0, 0);
        let dir = make_dir_index(file_ino);

        let result = dispatch_lookup(&tbl, &dir, file_ino, b"anything");
        assert_eq!(result, Err(Errno(libc::ENOTDIR as u16)));
    }

    // ── ENOENT: parent inode not in table ────────────────────────────

    #[test]
    fn lookup_missing_parent_returns_enoent() {
        let tbl = make_inode_table();
        // parent 999 was never allocated
        let dir = make_dir_index(999);

        let result = dispatch_lookup(&tbl, &dir, 999, b"anything");
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
    }

    // ── lookup bumps nlink by 1 ──────────────────────────────────────

    #[test]
    fn lookup_bumps_nlink() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let child = make_file(&tbl, 0o644, 0, 0);
        let child_gen = tbl.lookup(Ino(child)).unwrap().generation;

        let mut dir = make_dir_index(parent);
        insert_entry(&mut dir, b"f", child, child_gen, libc::S_IFREG);

        let before = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(before, 1); // only the create link

        dispatch_lookup(&tbl, &dir, parent, b"f").unwrap();
        let after = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after, 2);

        // Second lookup bumps again
        dispatch_lookup(&tbl, &dir, parent, b"f").unwrap();
        let after2 = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after2, 3);
    }

    // ── forget decrement to non-zero ─────────────────────────────────

    #[test]
    fn forget_decrements_nlink_to_nonzero() {
        let tbl = make_inode_table();
        let child = make_file(&tbl, 0o644, 0, 0);
        let before = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(before, 1);

        // Bump twice so we can decrement by 1 without hitting zero.
        tbl.link(Ino(child)).unwrap();
        tbl.link(Ino(child)).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 3);

        dispatch_forget(&tbl, child, 1).unwrap();
        let after = tbl.lookup(Ino(child)).unwrap().nlink;
        assert_eq!(after, 2);
    }

    // ── forget decrement to zero ─────────────────────────────────────

    #[test]
    fn forget_decrements_to_zero_auto_removes() {
        let tbl = make_inode_table();
        let child = make_file(&tbl, 0o644, 0, 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        dispatch_forget(&tbl, child, 1).unwrap();

        // Inode should be auto-removed when nlink hits zero.
        assert!(tbl.lookup(Ino(child)).is_none());
    }

    // ── forget with nlookup > 1 ──────────────────────────────────────

    #[test]
    fn forget_with_nlookup_gt_1() {
        let tbl = make_inode_table();
        let child = make_file(&tbl, 0o644, 0, 0);

        // Bump to nlink=4 so nlookup=3 won't hit zero.
        tbl.link(Ino(child)).unwrap();
        tbl.link(Ino(child)).unwrap();
        tbl.link(Ino(child)).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 4);

        dispatch_forget(&tbl, child, 3).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);
    }

    #[test]
    fn forget_nlookup_gt_nlink_auto_removes() {
        let tbl = make_inode_table();
        let child = make_file(&tbl, 0o644, 0, 0);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        // nlookup > nlink: first unlink removes, subsequent unlinks are
        // no-ops (InodeNotFound -> Ok).
        dispatch_forget(&tbl, child, 5).unwrap();

        assert!(tbl.lookup(Ino(child)).is_none());
    }

    // ── forget nlookup=0 is invalid ──────────────────────────────────

    #[test]
    fn forget_nlookup_zero_returns_einval() {
        let tbl = make_inode_table();
        let child = make_file(&tbl, 0o644, 0, 0);

        let result = dispatch_forget(&tbl, child, 0);
        assert_eq!(result, Err(Errno(libc::EINVAL as u16)));
    }

    // ── forget missing inode ─────────────────────────────────────────

    #[test]
    fn forget_missing_inode_returns_enoent() {
        let tbl = make_inode_table();
        // Never allocated ino 999.
        let result = dispatch_forget(&tbl, 999, 1);
        assert_eq!(result, Err(Errno(libc::ENOENT as u16)));
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

        // Initial state: nlink=1 from create
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        // Lookup bumps to 2
        let result = dispatch_lookup(&tbl, &dir, parent, b"roundtrip.txt").unwrap();
        assert_eq!(result.ino, child);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 2);

        // Forget back to 1
        dispatch_forget(&tbl, child, 1).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        // Second forget removes
        dispatch_forget(&tbl, child, 1).unwrap();
        assert!(tbl.lookup(Ino(child)).is_none());
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

        // Three lookups: nlink 1->4
        dispatch_lookup(&tbl, &dir, parent, b"multi").unwrap();
        dispatch_lookup(&tbl, &dir, parent, b"multi").unwrap();
        dispatch_lookup(&tbl, &dir, parent, b"multi").unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 4);

        // Single forget with nlookup=3 balances all three
        dispatch_forget(&tbl, child, 3).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);
    }

    // ── Lookup on empty directory ────────────────────────────────────

    #[test]
    fn lookup_in_empty_directory_returns_enoent() {
        let tbl = make_inode_table();
        let parent = make_dir(&tbl, 0o755, 0, 0);
        let dir = make_dir_index(parent);

        assert_eq!(
            dispatch_lookup(&tbl, &dir, parent, b"anything"),
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
        let child = make_file(&tbl, 0o644, 0, 0);
        // Bump nlink so forget doesn't remove
        tbl.link(Ino(child)).unwrap();
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 2);

        let resolver = MapResolver::new();
        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let result = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(result, Ok(None));
        assert_eq!(batch.inode_table().lookup(Ino(child)).unwrap().nlink, 1);
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
        assert_eq!(batch.inode_table().lookup(Ino(child)).unwrap().nlink, 2);

        // Phase 2: kernel releases the reference via forget
        let forget_result = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(forget_result, Ok(None));
        assert_eq!(batch.inode_table().lookup(Ino(child)).unwrap().nlink, 1);

        // Phase 3: kernel's last forget removes the inode
        let forget2 = batch.handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child, 1);
        assert_eq!(forget2, Ok(None));
        assert!(batch.inode_table().lookup(Ino(child)).is_none());
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

        // All have nlink=2 (1 create + 1 lookup)
        assert_eq!(batch.inode_table().lookup(Ino(child_a)).unwrap().nlink, 2);
        assert_eq!(batch.inode_table().lookup(Ino(child_b)).unwrap().nlink, 2);
        assert_eq!(batch.inode_table().lookup(Ino(child_c)).unwrap().nlink, 2);

        // Forget a and c, keeping b
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_a, 1)
            .unwrap();
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_c, 1)
            .unwrap();

        assert_eq!(batch.inode_table().lookup(Ino(child_a)).unwrap().nlink, 1);
        assert_eq!(batch.inode_table().lookup(Ino(child_b)).unwrap().nlink, 2);
        assert_eq!(batch.inode_table().lookup(Ino(child_c)).unwrap().nlink, 1);

        // Forget b (back to 1)
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_b, 1)
            .unwrap();
        assert_eq!(batch.inode_table().lookup(Ino(child_b)).unwrap().nlink, 1);

        // Final forget on a removes it
        batch
            .handle_lookup_forget(FUSE_FORGET, &resolver, 0, b"", child_a, 1)
            .unwrap();
        assert!(batch.inode_table().lookup(Ino(child_a)).is_none());
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
    /// Returns `Ok(())` on success or `Err(Errno)` on failure
    /// (EINVAL, ENOENT, EIO).  When `nlink` reaches zero the inode
    /// table auto-removes the entry.
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
    fn session_forget_decrements_nlink() {
        let tbl = make_table();
        let child = make_file(&tbl, 0o644);
        tbl.link(Ino(child)).unwrap(); // nlink: 1->2

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        session.forget(child, 1).unwrap();
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            1
        );
    }

    #[test]
    fn session_forget_to_zero_auto_removes() {
        let tbl = make_table();
        let child = make_file(&tbl, 0o644);
        assert_eq!(tbl.lookup(Ino(child)).unwrap().nlink, 1);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        session.forget(child, 1).unwrap();
        assert!(session.batch().inode_table().lookup(Ino(child)).is_none());
    }

    #[test]
    fn session_forget_zero_nlookup_is_invalid() {
        let tbl = make_table();
        let child = make_file(&tbl, 0o644);

        let batch = FuseLookupForgetBatch::new(Arc::new(tbl));
        let session = FuseLookupForgetSession::new(batch);

        let result = session.forget(child, 0);
        assert_eq!(result, Err(Errno(libc::EINVAL as u16)));
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
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            2
        );

        // Phase 2: kernel releases reference
        session.forget(child, 1).unwrap();
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            1
        );

        // Phase 3: kernel drops last reference
        session.forget(child, 1).unwrap();
        assert!(session.batch().inode_table().lookup(Ino(child)).is_none());
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
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            4
        );

        // One forget with nlookup=3
        session.forget(child, 3).unwrap();
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child))
                .unwrap()
                .nlink,
            1
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

        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_a))
                .unwrap()
                .nlink,
            2
        );
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_b))
                .unwrap()
                .nlink,
            2
        );
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_c))
                .unwrap()
                .nlink,
            2
        );

        // Forget a and c
        session.forget(child_a, 1).unwrap();
        session.forget(child_c, 1).unwrap();

        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_a))
                .unwrap()
                .nlink,
            1
        );
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_b))
                .unwrap()
                .nlink,
            2
        );
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_c))
                .unwrap()
                .nlink,
            1
        );

        // Forget b then final forget a
        session.forget(child_b, 1).unwrap();
        session.forget(child_a, 1).unwrap();

        assert!(session.batch().inode_table().lookup(Ino(child_a)).is_none());
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_b))
                .unwrap()
                .nlink,
            1
        );
        assert_eq!(
            session
                .batch()
                .inode_table()
                .lookup(Ino(child_c))
                .unwrap()
                .nlink,
            1
        );
    }
}
