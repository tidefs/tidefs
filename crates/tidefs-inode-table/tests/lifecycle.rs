// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "std")]
//! Integration tests for inode-table lifecycle semantics.
//!
//! Covers create-read-update-delete cycles, freed-inode non-discoverability,
//! double-free and invalid-transition rejection, and full state transitions
//! (FREE → ALLOCATED → STALE → FREE) for all three inode kinds.
//!
//! Uses the public [`InodeTable`] API with [`SystemTimeSource`].

use std::time::Duration;
use tidefs_inode_table::{
    Ino, InodeAttributes, InodeKind, InodeTable, InodeTableError, SystemTimeSource,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_table(capacity: usize) -> InodeTable {
    InodeTable::new(capacity, Box::new(SystemTimeSource))
}

fn file_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::File)
}

fn dir_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 0, 0, InodeKind::Directory)
}

fn symlink_attrs(mode: u32) -> InodeAttributes {
    InodeAttributes::new(mode, 1000, 1000, InodeKind::Symlink)
}

// ---------------------------------------------------------------------------
// 1. Create-read-update-free cycle (file)
// ---------------------------------------------------------------------------

#[test]
fn file_create_read_update_delete_cycle() {
    let tbl = make_table(16);

    // Phase 1: Create — FREE → ALLOCATED
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(ino, Ino::ROOT);
    assert_eq!(tbl.len(), 1);

    let attrs = tbl.lookup(ino).unwrap();
    assert_eq!(attrs.mode, 0o644);
    assert_eq!(attrs.nlink, 1);
    assert!(attrs.generation > 0);
    assert!(
        attrs.atime > Duration::ZERO,
        "atime should be set on create"
    );

    // Phase 2: Read back (getattr alias)
    let via_getattr = tbl.getattr(ino).unwrap();
    assert_eq!(via_getattr.mode, 0o644);

    // Phase 3: Update attributes
    let mut updated = tbl.lookup(ino).unwrap();
    updated.size = 8192;
    updated.mode = 0o755;
    tbl.setattr(ino, updated.clone()).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.size, 8192);
    assert_eq!(stored.mode, 0o755);
    // generation must be preserved across setattr
    assert_eq!(stored.generation, attrs.generation);

    // Phase 4: Free — ALLOCATED → FREE
    // File auto-removes on nlink→0
    tbl.unlink(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());
    assert_eq!(tbl.len(), 0);
}

// ---------------------------------------------------------------------------
// 2. Create-read-update-free cycle (directory)
// ---------------------------------------------------------------------------

#[test]
fn directory_create_read_update_delete_cycle() {
    let tbl = make_table(16);

    // Create directory
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(tbl.len(), 1);

    let attrs = tbl.lookup(ino).unwrap();
    assert_eq!(attrs.kind, InodeKind::Directory);
    assert_eq!(attrs.mode, 0o755);
    assert_eq!(attrs.nlink, 1);

    // Update directory attributes
    let mut updated = tbl.lookup(ino).unwrap();
    updated.mode = 0o700;
    updated.uid = 42;
    tbl.setattr(ino, updated).unwrap();

    let stored = tbl.lookup(ino).unwrap();
    assert_eq!(stored.mode, 0o700);
    assert_eq!(stored.uid, 42);

    // Directories do NOT auto-remove on unlink to nlink 0
    tbl.unlink(ino).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 0, "dir nlink should be 0");
    assert!(tbl.lookup(ino).is_some(), "dir must not auto-remove");

    // Explicit delete to free
    tbl.delete(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());
    assert_eq!(tbl.len(), 0);
}

// ---------------------------------------------------------------------------
// 3. Create-read-update-free cycle (symlink)
// ---------------------------------------------------------------------------

#[test]
fn symlink_create_read_update_delete_cycle() {
    let tbl = make_table(16);

    let ino = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    assert_eq!(tbl.len(), 1);

    let attrs = tbl.lookup(ino).unwrap();
    assert_eq!(attrs.kind, InodeKind::Symlink);
    assert_eq!(attrs.mode, 0o777);

    // Update symlink size
    let mut updated = tbl.lookup(ino).unwrap();
    updated.size = 42; // target path length
    tbl.setattr(ino, updated).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().size, 42);

    // Symlinks do NOT auto-remove on nlink→0; explicit delete needed
    tbl.unlink(ino).unwrap(); // nlink 1→0
    tbl.delete(ino).unwrap(); // symlinks do not auto-remove
}

// ---------------------------------------------------------------------------
// 4. Freed-inode non-discoverability
// ---------------------------------------------------------------------------

#[test]
fn freed_inode_not_discoverable_via_lookup() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino).unwrap(); // auto-remove

    assert!(tbl.lookup(ino).is_none());
    assert!(tbl.getattr(ino).is_none());
}

#[test]
fn freed_inode_not_discoverable_via_iter() {
    let tbl = make_table(16);
    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino3 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    // Free ino2
    tbl.unlink(ino2).unwrap();

    let snapshot = tbl.iter();
    let found: Vec<_> = snapshot.iter().map(|(ino, _)| *ino).collect();
    assert!(found.contains(&ino1), "ino1 should be visible");
    assert!(found.contains(&ino3), "ino3 should be visible");
    assert!(!found.contains(&ino2), "freed ino2 must not appear in iter");
    assert_eq!(found.len(), 2);
}

#[test]
fn freed_inode_not_discoverable_via_validate_generation() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen = tbl.lookup(ino).unwrap().generation;

    tbl.unlink(ino).unwrap(); // auto-remove

    assert_eq!(
        tbl.validate_generation(ino, gen),
        Err(InodeTableError::InodeNotFound)
    );
}

#[test]
fn freed_inode_cannot_be_updated() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino).unwrap();

    assert_eq!(
        tbl.setattr(ino, file_attrs(0o755)),
        Err(InodeTableError::InodeNotFound)
    );
    assert_eq!(
        tbl.update(ino, file_attrs(0o755)),
        Err(InodeTableError::InodeNotFound)
    );
}

#[test]
fn freed_inode_cannot_be_linked_or_unlinked() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino).unwrap();

    assert_eq!(tbl.link(ino), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.unlink(ino), Err(InodeTableError::InodeNotFound));
}

// ---------------------------------------------------------------------------
// 5. Double-free rejection (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn double_free_via_remove_rejected() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    tbl.unlink(ino).unwrap(); // nlink 1→0
    tbl.delete(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());

    // Second remove/delete must fail
    assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeNotFound));
    assert_eq!(tbl.delete(ino), Err(InodeTableError::InodeNotFound));
}

#[test]
fn double_free_via_auto_remove_then_remove_rejected() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    tbl.unlink(ino).unwrap(); // nlink 1→0, auto-remove for files
    assert!(tbl.lookup(ino).is_none());

    // Attempting remove on an auto-removed file must fail
    assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeNotFound));
}

// ---------------------------------------------------------------------------
// 6. Full state transitions (FREE → ALLOCATED → STALE → FREE)
// ---------------------------------------------------------------------------

#[test]
fn full_state_transition_cycle_file() {
    let tbl = make_table(4);

    // FREE → ALLOCATED
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen1 = tbl.lookup(ino).unwrap().generation;
    assert_eq!(tbl.len(), 1);

    // ALLOCATED → FREE (auto-remove)
    tbl.unlink(ino).unwrap();
    assert_eq!(tbl.len(), 0);
    assert!(tbl.lookup(ino).is_none());

    // FREE → ALLOCATED (same slot, new generation → old handle is STALE)
    let reused = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(reused.0, ino.0, "should reuse same slot");
    let gen2 = tbl.lookup(reused).unwrap().generation;
    assert_ne!(gen2, gen1, "generation must advance on reuse");

    // Old (ino, gen1) is STALE — rejected by generation-guarded ops
    assert_eq!(
        tbl.validate_generation(ino, gen1),
        Err(InodeTableError::GenerationMismatch)
    );

    // ALLOCATED → FREE again
    tbl.unlink(reused).unwrap(); // dir nlink 1→0
    tbl.delete(reused).unwrap();
    assert_eq!(tbl.len(), 0);
}

#[test]
fn full_state_transition_cycle_directory() {
    let tbl = make_table(4);

    // FREE → ALLOCATED (dir)
    let ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let gen1 = tbl.lookup(ino).unwrap().generation;
    assert_eq!(tbl.len(), 1);

    // Modify while ALLOCATED
    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.mode = 0o700;
    tbl.setattr(ino, attrs).unwrap();

    // ALLOCATED → FREE (unlink to nlink 0, then delete)
    tbl.unlink(ino).unwrap();
    tbl.delete(ino).unwrap();
    assert_eq!(tbl.len(), 0);

    // FREE → ALLOCATED (reuse, old gen is STALE)
    let reused = tbl.create(InodeKind::File, file_attrs(0o600)).unwrap();
    let gen2 = tbl.lookup(reused).unwrap().generation;
    assert_ne!(gen1, gen2);

    // Verify STALE handle rejection
    assert_eq!(
        tbl.validate_generation(ino, gen1),
        Err(InodeTableError::GenerationMismatch)
    );
    assert_eq!(
        tbl.setattr_if_generation(ino, gen1, file_attrs(0o755)),
        Err(InodeTableError::GenerationMismatch)
    );
}

// ---------------------------------------------------------------------------
// 7. Invalid transition: remove while nlink > 0 (integration-level)
// ---------------------------------------------------------------------------

#[test]
fn remove_rejected_while_links_exist() {
    let tbl = make_table(16);

    // File with nlink=1
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeHasLinks));
    assert!(
        tbl.lookup(ino).is_some(),
        "inode must survive failed remove"
    );

    // Dir with nlink=1
    let dino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    assert_eq!(tbl.remove(dino), Err(InodeTableError::InodeHasLinks));

    // Now link, so nlink=2
    tbl.link(ino).unwrap();
    assert_eq!(tbl.remove(ino), Err(InodeTableError::InodeHasLinks));
}

// ---------------------------------------------------------------------------
// 8. Lifecycle with link/unlink count correctness
// ---------------------------------------------------------------------------

#[test]
fn link_unlink_nlink_tracking() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    assert_eq!(tbl.lookup(ino).unwrap().nlink, 1, "initial nlink=1");

    let n = tbl.link(ino).unwrap();
    assert_eq!(n, 2);
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 2);

    tbl.link(ino).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 3);

    tbl.unlink(ino).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 2);

    tbl.unlink(ino).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 1);

    // Last unlink for file → nlink 0 → auto-remove
    tbl.unlink(ino).unwrap();
    assert!(tbl.lookup(ino).is_none());
}

// ---------------------------------------------------------------------------
// 9. Lifecycle across all three kinds in the same table
// ---------------------------------------------------------------------------

#[test]
fn mixed_kind_lifecycle_in_single_table() {
    let tbl = make_table(32);

    // Create one of each kind
    let f_ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let d_ino = tbl.create(InodeKind::Directory, dir_attrs(0o755)).unwrap();
    let s_ino = tbl
        .create(InodeKind::Symlink, symlink_attrs(0o777))
        .unwrap();
    assert_eq!(tbl.len(), 3);

    // Verify kinds via lookup
    assert_eq!(tbl.lookup(f_ino).unwrap().kind, InodeKind::File);
    assert_eq!(tbl.lookup(d_ino).unwrap().kind, InodeKind::Directory);
    assert_eq!(tbl.lookup(s_ino).unwrap().kind, InodeKind::Symlink);

    // Free file via auto-remove
    tbl.unlink(f_ino).unwrap();
    assert!(tbl.lookup(f_ino).is_none());

    // Free symlink via explicit delete
    tbl.unlink(s_ino).unwrap(); // nlink 1→0
    tbl.delete(s_ino).unwrap(); // symlinks do not auto-remove
                                // Free directory via explicit delete
    tbl.unlink(d_ino).unwrap();
    tbl.delete(d_ino).unwrap();
    assert!(tbl.lookup(d_ino).is_none());

    assert_eq!(tbl.len(), 0);
}

// ---------------------------------------------------------------------------
// 10. Iteration consistency through lifecycle transitions
// ---------------------------------------------------------------------------

#[test]
fn iter_reflects_create_and_delete() {
    let tbl = make_table(16);

    let snapshot = tbl.iter();
    assert!(snapshot.is_empty());

    let ino1 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let ino2 = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();

    let snapshot = tbl.iter();
    assert_eq!(snapshot.len(), 2);

    tbl.unlink(ino1).unwrap();

    let snapshot = tbl.iter();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].0, ino2);
}

// ---------------------------------------------------------------------------
// 11. Timestamp evolution across lifecycle
// ---------------------------------------------------------------------------

#[test]
fn timestamps_evolve_through_lifecycle() {
    let tbl = make_table(16);

    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let at_create = tbl.lookup(ino).unwrap();

    assert!(at_create.atime > Duration::ZERO);
    assert!(at_create.mtime > Duration::ZERO);
    assert!(at_create.ctime > Duration::ZERO);
    assert_eq!(at_create.atime, at_create.mtime);
    assert_eq!(at_create.mtime, at_create.ctime);

    // setattr should update timestamps? No — setattr preserves caller's
    // timestamps. But let's verify the stored values are what we set.
    let mut updated = at_create.clone();
    updated.size = 4096;
    tbl.setattr(ino, updated).unwrap();

    let after_setattr = tbl.lookup(ino).unwrap();
    assert_eq!(after_setattr.size, 4096);
    // Timestamps from the caller are preserved verbatim in setattr
    assert_eq!(after_setattr.atime, at_create.atime);
}

// ---------------------------------------------------------------------------
// 12. Generation-guarded lifecycle operations
// ---------------------------------------------------------------------------

#[test]
fn generation_guarded_ops_across_lifecycle() {
    let tbl = make_table(16);
    let ino = tbl.create(InodeKind::File, file_attrs(0o644)).unwrap();
    let gen = tbl.lookup(ino).unwrap().generation;

    // link_if_generation with correct gen
    let n = tbl.link_if_generation(ino, gen).unwrap();
    assert_eq!(n, 2);

    // unlink_if_generation with correct gen
    tbl.unlink_if_generation(ino, gen).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().nlink, 1);

    // setattr_if_generation with correct gen
    let mut attrs = tbl.lookup(ino).unwrap();
    attrs.size = 1024;
    tbl.setattr_if_generation(ino, gen, attrs).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().size, 1024);

    // Wrong generation is rejected on all guarded ops
    let wrong_gen = gen + 1;
    assert_eq!(
        tbl.link_if_generation(ino, wrong_gen),
        Err(InodeTableError::GenerationMismatch)
    );
    assert_eq!(
        tbl.unlink_if_generation(ino, wrong_gen),
        Err(InodeTableError::GenerationMismatch)
    );
    assert_eq!(
        tbl.setattr_if_generation(ino, wrong_gen, file_attrs(0o755)),
        Err(InodeTableError::GenerationMismatch)
    );
    assert_eq!(
        tbl.remove_if_generation(ino, wrong_gen),
        Err(InodeTableError::GenerationMismatch) // gen check fires before nlink
    );
}

// ---------------------------------------------------------------------------
// 13. allocate / update API aliases
// ---------------------------------------------------------------------------

#[test]
fn allocate_and_update_are_aliases() {
    let tbl = make_table(16);

    // allocate is alias for create
    let attrs = InodeAttributes::new(0o644, 1000, 1000, InodeKind::File);
    let ino = tbl.allocate(attrs).unwrap();
    assert_eq!(ino, Ino::ROOT);
    assert_eq!(tbl.lookup(ino).unwrap().kind, InodeKind::File);

    // update is alias for setattr
    let mut updated = tbl.lookup(ino).unwrap();
    updated.size = 999;
    tbl.update(ino, updated).unwrap();
    assert_eq!(tbl.lookup(ino).unwrap().size, 999);
}
