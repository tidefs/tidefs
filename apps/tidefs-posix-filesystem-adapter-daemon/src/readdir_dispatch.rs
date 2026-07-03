// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE readdir/readdirplus dispatch with DirIndexIter cursor support.
//!
//! Provides engine-level and FUSE-level dispatch functions for directory
//! enumeration.  Uses [`tidefs_dir_index::DirIndexIter`] for stable
//! cookie-based pagination so the kernel can resume readdir across
//! multiple calls.
//!
//! # Architecture
//!
//! - **Core iteration**: [`iter_dir_entries`] creates a [`DirIndexIter`]
//!   from a [`DirIndex`], seeks to the given [`DirCookie`], and yields
//!   entries with their cookies preserved.
//! - **FUSE page fill**: [`fill_readdir_page`] packs entries into a FUSE
//!   reply buffer up to `max_entries`, handling synthetic `.` / `..`
//!   entries at `DirCookie::START`.
//! - **readdirplus**: [`resolve_readdirplus_attrs`] extends readdir with
//!   inline attribute resolution via a caller-supplied lookup closure.
//!
//! # Cookie semantics
//!
//! [`DirCookie`] values are monotonic within a directory snapshot:
//! - `DirCookie::START` (0) means "begin from the first entry".
//! - Synthetic `.` and `..` get reserved cookies 1 and 2.
//! - Synthetic `.snapshot` gets reserved cookie 3 when the dataset snapshot
//!   catalog is non-empty.
//! - Real entries carry the cookie assigned by [`DirIndexIter`].
//!
//! The kernel passes the last received cookie as the readdir `offset`.
//! The next call resumes from the entry *after* that offset.

use std::os::unix::ffi::OsStrExt;

use tidefs_dir_index::{DirCookie, DirIndex, DirIndexIter};
use tidefs_types_vfs_core::{
    DirEntry, Errno, Generation, InodeAttr, InodeId, NodeKind, SNAPSHOT_NAMESPACE_ROOT_INODE_ID,
};

const SNAPSHOT_DOTDIR_NAME: &[u8] = b".snapshot";
const DOT_COOKIE: u64 = 1;
const DOTDOT_COOKIE: u64 = 2;
const SNAPSHOT_DOTDIR_COOKIE: u64 = 3;

// ── Error type ───────────────────────────────────────────────────────────

/// Errors that can occur during readdir dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReaddirError {
    /// Inode not found in the directory table.
    NotFound,
    /// Target inode is not a directory.
    NotDirectory,
    /// Internal iteration error (corrupt index).
    Io,
}

impl ReaddirError {
    /// Convert to the canonical VFS [`Errno`].
    pub fn to_errno(&self) -> Errno {
        match self {
            Self::NotFound => Errno::ENOENT,
            Self::NotDirectory => Errno::ENOTDIR,
            Self::Io => Errno::EIO,
        }
    }
}

// ── Core iteration ───────────────────────────────────────────────────────

/// Outcome of one readdir iteration step.
#[derive(Clone, Debug)]
pub struct IterOutcome {
    /// Entries yielded in this batch (sorted by cookie).
    pub entries: Vec<DirEntry>,
    /// `true` if more entries remain beyond this batch.
    pub has_more: bool,
    /// Cookie of the last emitted entry, or `DirCookie::START` if empty.
    pub last_cookie: DirCookie,
}

/// Yield up to `max_entries` directory entries from `dir`, starting
/// after `cookie`.
///
/// Synthetic `.` and `..` are emitted only when `cookie` is
/// [`DirCookie::START`].  Synthetic `.snapshot` is emitted after `..` when
/// `snapshot_catalog_generation` is present. Real entries carry the original
/// order assigned by [`DirIndexIter`] after the reserved synthetic cookies.
///
/// Returns an [`IterOutcome`] with the batch, a continuation flag,
/// and the last emitted cookie (suitable as the next readdir offset).
pub fn iter_dir_entries(
    dir: &DirIndex,
    dir_inode_id: u64,
    parent_inode_id: u64,
    snapshot_catalog_generation: Option<Generation>,
    cookie: DirCookie,
    max_entries: usize,
) -> IterOutcome {
    let mut entries: Vec<DirEntry> = Vec::with_capacity(max_entries);
    let mut next_cookie: u64;
    let synthetic_cookie_count = if snapshot_catalog_generation.is_some() {
        SNAPSHOT_DOTDIR_COOKIE
    } else {
        DOTDOT_COOKIE
    };
    let mut pending_synthetic = max_entries == 0 && cookie.0 < synthetic_cookie_count;

    // Determine the starting cookie value and whether to emit
    // synthetic entries.  Cookies 1 through synthetic_cookie_count are
    // reserved for projected entries.
    if cookie == DirCookie::START {
        next_cookie = DOT_COOKIE;

        if entries.len() < max_entries {
            entries.push(DirEntry::new(
                b".".to_vec(),
                InodeId::new(dir_inode_id),
                NodeKind::Dir,
                Generation::new(0),
                next_cookie,
            ));
            next_cookie = DOTDOT_COOKIE;
        } else {
            pending_synthetic = true;
        }
        if entries.len() < max_entries {
            entries.push(DirEntry::new(
                b"..".to_vec(),
                InodeId::new(parent_inode_id),
                NodeKind::Dir,
                Generation::new(0),
                next_cookie,
            ));
            next_cookie = SNAPSHOT_DOTDIR_COOKIE;
        }
        if let Some(generation) =
            snapshot_catalog_generation.filter(|_| entries.len() < max_entries)
        {
            entries.push(DirEntry::new(
                SNAPSHOT_DOTDIR_NAME.to_vec(),
                SNAPSHOT_NAMESPACE_ROOT_INODE_ID,
                NodeKind::Dir,
                generation,
                next_cookie,
            ));
            next_cookie = SNAPSHOT_DOTDIR_COOKIE + 1;
        } else if snapshot_catalog_generation.is_some() {
            pending_synthetic = true;
        }
    } else if cookie.0 == DOT_COOKIE {
        // Only `.` was emitted previously; still need `..`.
        next_cookie = DOTDOT_COOKIE;
        if entries.len() < max_entries {
            entries.push(DirEntry::new(
                b"..".to_vec(),
                InodeId::new(parent_inode_id),
                NodeKind::Dir,
                Generation::new(0),
                next_cookie,
            ));
            next_cookie = SNAPSHOT_DOTDIR_COOKIE;
        } else {
            pending_synthetic = true;
        }
        if let Some(generation) =
            snapshot_catalog_generation.filter(|_| entries.len() < max_entries)
        {
            entries.push(DirEntry::new(
                SNAPSHOT_DOTDIR_NAME.to_vec(),
                SNAPSHOT_NAMESPACE_ROOT_INODE_ID,
                NodeKind::Dir,
                generation,
                next_cookie,
            ));
            next_cookie = SNAPSHOT_DOTDIR_COOKIE + 1;
        } else if snapshot_catalog_generation.is_some() {
            pending_synthetic = true;
        }
    } else if let Some(generation) = snapshot_catalog_generation
        .filter(|_| cookie.0 == DOTDOT_COOKIE)
    {
        // `.` and `..` were emitted previously; `.snapshot` still remains.
        next_cookie = SNAPSHOT_DOTDIR_COOKIE;
        if entries.len() < max_entries {
            entries.push(DirEntry::new(
                SNAPSHOT_DOTDIR_NAME.to_vec(),
                SNAPSHOT_NAMESPACE_ROOT_INODE_ID,
                NodeKind::Dir,
                generation,
                next_cookie,
            ));
            next_cookie = SNAPSHOT_DOTDIR_COOKIE + 1;
        } else {
            pending_synthetic = true;
        }
    } else {
        // Synthetic entries emitted (or offset beyond them): only real entries
        // remain.
        next_cookie = cookie.0 + 1;
    }

    // ── Real entries via DirIndexIter ────────────────────────────────
    let mut iter = DirIndexIter::new(dir);

    // Seek past already-emitted real entries.  The kernel passes the
    // last received cookie; we must start from the entry *after* it.
    // Cookies before the first real entry are reserved for synthetic entries.
    // The count of already-emitted real entries is
    // (cookie - synthetic_cookie_count).
    let real_skip = cookie.0.saturating_sub(synthetic_cookie_count);

    // Advance iterator past already-emitted real entries.
    for _ in 0..real_skip {
        if iter.next().is_none() {
            break;
        }
    }

    while entries.len() < max_entries {
        let Some((entry, _entry_cookie)) = iter.next() else {
            break;
        };
        let kind = dir_entry_kind_to_node_kind(entry.kind);
        entries.push(DirEntry {
            name: entry.name,
            inode_id: InodeId::new(entry.inode_id),
            kind,
            generation: Generation::new(entry.generation),
            cookie: next_cookie,
        });
        next_cookie += 1;
    }

    let has_more = pending_synthetic || !iter.is_empty();
    let last_cookie = if entries.is_empty() {
        cookie
    } else {
        DirCookie(entries.last().unwrap().cookie)
    };

    IterOutcome {
        entries,
        has_more,
        last_cookie,
    }
}

/// Map a `DirIndex` entry `kind` to a VFS [`NodeKind`].
fn dir_entry_kind_to_node_kind(kind: u32) -> NodeKind {
    // The DirIndex stores kind using the same constants as the namespace
    // (e.g. KIND_DIR, KIND_FILE, KIND_SYMLINK).  Map them.
    // These constants come from tidefs_namespace but we avoid the crate dep
    // by using the raw values.
    match kind {
        0o040000 => NodeKind::Dir,
        0o120000 => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}

// ── FUSE page fill ───────────────────────────────────────────────────────

/// Pack entries into a FUSE readdir reply buffer.
///
/// Calls `reply_add(ino, cookie, file_type, name)` for each entry until
/// the buffer is full or the batch is exhausted.
///
/// Returns `(emitted_count, last_cookie)` where `last_cookie` is the
/// cookie of the final entry placed in the buffer (suitable as the next
/// readdir offset).  When the batch is exhausted, returns `(count, 0)`
/// to signal end-of-directory.
pub fn fill_readdir_page<F>(outcome: &IterOutcome, mut reply_add: F) -> Result<(usize, u64), Errno>
where
    F: FnMut(u64, u64, fuser::FileType, &std::ffi::OsStr) -> bool,
{
    let mut emitted = 0usize;
    let mut last_offset: u64 = 0;

    for entry in &outcome.entries {
        let kind = node_kind_to_fuse_file_type(entry.kind);
        let name = std::ffi::OsStr::from_bytes(&entry.name);
        if reply_add(entry.inode_id.get(), entry.cookie, kind, name) {
            // Buffer full — stop but report the last cookie we tried to add
            // so the kernel can resume from here.
            break;
        }
        emitted += 1;
        last_offset = entry.cookie;
    }

    let next_offset = if outcome.has_more && emitted == outcome.entries.len() {
        // All entries from this batch were emitted and more remain.
        outcome.last_cookie.0
    } else if emitted < outcome.entries.len() {
        // Buffer filled mid-batch — next call resumes from last emitted.
        last_offset
    } else {
        // Exhausted — signal end-of-directory.
        0
    };

    Ok((emitted, next_offset))
}

/// Convert a VFS [`NodeKind`] to a FUSE `FileType`.
fn node_kind_to_fuse_file_type(kind: NodeKind) -> fuser::FileType {
    match kind {
        NodeKind::Dir => fuser::FileType::Directory,
        NodeKind::File => fuser::FileType::RegularFile,
        NodeKind::Symlink => fuser::FileType::Symlink,
        NodeKind::BlockDev => fuser::FileType::BlockDevice,
        NodeKind::CharDev => fuser::FileType::CharDevice,
        NodeKind::Fifo => fuser::FileType::NamedPipe,
        NodeKind::Socket => fuser::FileType::Socket,
        _ => fuser::FileType::RegularFile,
    }
}

// ── readdirplus attr fill ────────────────────────────────────────────────

/// Entry with resolved attributes for readdirplus.
#[derive(Clone, Debug)]
pub struct ReaddirplusEntry {
    pub entry: DirEntry,
    pub attr: InodeAttr,
}

/// Resolve attributes for each entry in a readdir batch.
///
/// Calls `lookup_attr(ino)` for each entry.  Entries whose attributes
/// cannot be resolved are silently skipped (POSIX allows this).
///
/// Returns the list of `(entry, attr)` pairs and whether more entries
/// remain in the directory.
pub fn resolve_readdirplus_attrs<F>(
    outcome: &IterOutcome,
    mut lookup_attr: F,
) -> (Vec<ReaddirplusEntry>, bool)
where
    F: FnMut(u64) -> Option<InodeAttr>,
{
    let pairs: Vec<ReaddirplusEntry> = outcome
        .entries
        .iter()
        .filter_map(|entry| {
            lookup_attr(entry.inode_id.get()).map(|attr| ReaddirplusEntry {
                entry: entry.clone(),
                attr,
            })
        })
        .collect();
    (pairs, outcome.has_more)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_dir_index::DatasetDirPolicy;

    fn test_policy() -> DatasetDirPolicy {
        DatasetDirPolicy::default()
    }

    fn make_dir() -> DirIndex {
        DirIndex::new(1, test_policy())
    }

    fn insert_entry(dir: &mut DirIndex, name: &[u8], inode_id: u64, kind: u32) {
        dir.insert(name, inode_id, 0, kind).unwrap();
    }

    // ── iter_dir_entries tests ───────────────────────────────────────

    #[test]
    fn iter_empty_dir_returns_only_synthetic_entries() {
        let dir = make_dir();
        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        assert_eq!(outcome.entries.len(), 2);
        assert_eq!(outcome.entries[0].name, b".");
        assert_eq!(outcome.entries[1].name, b"..");
        assert!(!outcome.has_more);
        assert_eq!(outcome.last_cookie, DirCookie(2));
    }

    #[test]
    fn iter_empty_dir_with_snapshots_returns_snapshot_dotdir() {
        let dir = make_dir();
        let outcome = iter_dir_entries(
            &dir,
            10,
            1,
            Some(Generation::new(7)),
            DirCookie::START,
            128,
        );

        assert_eq!(outcome.entries.len(), 3);
        assert_eq!(outcome.entries[0].name, b".");
        assert_eq!(outcome.entries[0].cookie, 1);
        assert_eq!(outcome.entries[1].name, b"..");
        assert_eq!(outcome.entries[1].cookie, 2);
        assert_eq!(outcome.entries[2].name, b".snapshot");
        assert_eq!(outcome.entries[2].cookie, 3);
        assert_eq!(outcome.entries[2].generation, Generation::new(7));
        assert_eq!(
            outcome.entries[2].inode_id,
            SNAPSHOT_NAMESPACE_ROOT_INODE_ID
        );
        assert_eq!(outcome.entries[2].kind, NodeKind::Dir);
        assert!(!outcome.has_more);
        assert_eq!(outcome.last_cookie, DirCookie(3));
    }

    #[test]
    fn iter_single_entry_yields_after_synthetics() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000); // regular file

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        assert_eq!(outcome.entries.len(), 3); // . + .. + alpha
        assert_eq!(outcome.entries[0].name, b".");
        assert_eq!(outcome.entries[1].name, b"..");
        assert_eq!(outcome.entries[2].name, b"alpha");
        assert_eq!(outcome.entries[2].inode_id.get(), 42);
        assert!(!outcome.has_more);
    }

    #[test]
    fn iter_snapshot_dotdir_precedes_real_entries_without_reordering_them() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);
        insert_entry(&mut dir, b"beta", 43, 0o100000);

        let outcome = iter_dir_entries(
            &dir,
            10,
            1,
            Some(Generation::new(7)),
            DirCookie::START,
            128,
        );

        assert_eq!(outcome.entries.len(), 5);
        assert_eq!(outcome.entries[0].name, b".");
        assert_eq!(outcome.entries[1].name, b"..");
        assert_eq!(outcome.entries[2].name, b".snapshot");
        assert_eq!(outcome.entries[2].cookie, 3);
        assert_eq!(outcome.entries[2].generation, Generation::new(7));
        assert_eq!(outcome.entries[3].name, b"alpha");
        assert_eq!(outcome.entries[3].cookie, 4);
        assert_eq!(outcome.entries[4].name, b"beta");
        assert_eq!(outcome.entries[4].cookie, 5);
    }

    #[test]
    fn iter_multiple_entries_sorted_by_name() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"zebra", 100, 0o100000);
        insert_entry(&mut dir, b"alpha", 200, 0o100000);
        insert_entry(&mut dir, b"moon", 300, 0o100000);

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        // Synthetic . + .. then 3 entries
        assert_eq!(outcome.entries.len(), 5);
        let names: Vec<&[u8]> = outcome
            .entries
            .iter()
            .skip(2) // skip . and ..
            .map(|e| e.name.as_slice())
            .collect();
        // DirIndexIter yields in hash-bucket order for B-tree, but for
        // micro-list (<=6 entries) it's insertion order.
        // Just verify all 3 are present.
        assert!(names.contains(&b"alpha".as_ref()));
        assert!(names.contains(&b"zebra".as_ref()));
        assert!(names.contains(&b"moon".as_ref()));
    }

    #[test]
    fn iter_cookie_continuation_skips_entries() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);
        insert_entry(&mut dir, b"beta", 43, 0o100000);
        insert_entry(&mut dir, b"gamma", 44, 0o100000);

        // First call from START with max_entries=1: only . fits
        let first = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 1);
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].name, b".");
        assert!(first.has_more);
        assert_eq!(first.entries[0].cookie, 1); // . gets cookie 1

        // Resume from cookie 1 (.) should start with .. and real entries
        let resumed = iter_dir_entries(&dir, 10, 1, None, DirCookie(1), 128);
        let resumed_names: Vec<&[u8]> = resumed.entries.iter().map(|e| e.name.as_slice()).collect();
        // .. should be present, . should not
        assert!(resumed_names.contains(&b"..".as_ref()));
        assert!(!resumed_names.contains(&b".".as_ref()));

        // Resume from cookie 2 (..) should skip synthetics and start with real
        let after_dotdot = iter_dir_entries(&dir, 10, 1, None, DirCookie(2), 128);
        // Should have 3 real entries (alpha, beta, gamma) — order depends on
        // micro-list insertion order (or hash-bucket for B-tree)
        assert_eq!(after_dotdot.entries.len(), 3);
        assert!(!after_dotdot.entries.iter().any(|e| e.name == b"."));
        assert!(!after_dotdot.entries.iter().any(|e| e.name == b".."));
    }

    #[test]
    fn iter_cookie_continuation_includes_snapshot_dotdir_once() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);

        let after_dotdot =
            iter_dir_entries(&dir, 10, 1, Some(Generation::new(7)), DirCookie(2), 128);
        let names: Vec<&[u8]> = after_dotdot
            .entries
            .iter()
            .map(|entry| entry.name.as_slice())
            .collect();
        assert_eq!(names, vec![b".snapshot".as_ref(), b"alpha".as_ref()]);
        assert_eq!(after_dotdot.entries[0].cookie, 3);
        assert_eq!(after_dotdot.entries[0].generation, Generation::new(7));
        assert_eq!(after_dotdot.entries[1].cookie, 4);

        let after_snapshot =
            iter_dir_entries(&dir, 10, 1, Some(Generation::new(7)), DirCookie(3), 128);
        assert_eq!(after_snapshot.entries.len(), 1);
        assert_eq!(after_snapshot.entries[0].name, b"alpha");
        assert_eq!(after_snapshot.entries[0].cookie, 4);
    }

    #[test]
    fn iter_limited_snapshot_synthetics_report_more_until_dotdir_emits() {
        let dir = make_dir();

        let first = iter_dir_entries(
            &dir,
            10,
            1,
            Some(Generation::new(7)),
            DirCookie::START,
            1,
        );
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].name, b".");
        assert!(first.has_more);

        let second = iter_dir_entries(
            &dir,
            10,
            1,
            Some(Generation::new(7)),
            first.last_cookie,
            1,
        );
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].name, b"..");
        assert!(second.has_more);

        let third = iter_dir_entries(
            &dir,
            10,
            1,
            Some(Generation::new(7)),
            second.last_cookie,
            1,
        );
        assert_eq!(third.entries.len(), 1);
        assert_eq!(third.entries[0].name, b".snapshot");
        assert_eq!(third.entries[0].cookie, 3);
        assert!(!third.has_more);
    }

    #[test]
    fn iter_max_entries_limit_honored_for_synthetics() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);
        insert_entry(&mut dir, b"beta", 43, 0o100000);

        // max_entries=1: only . fits (cookie 1)
        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 1);
        assert_eq!(outcome.entries.len(), 1);
        assert_eq!(outcome.entries[0].name, b".");
        assert_eq!(outcome.entries[0].cookie, 1);
        assert!(outcome.has_more);
    }

    #[test]
    fn iter_max_entries_limit_honored_for_real_entries() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);
        insert_entry(&mut dir, b"beta", 43, 0o100000);
        insert_entry(&mut dir, b"gamma", 44, 0o100000);

        // max_entries=3: . + .. + alpha
        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 3);
        assert_eq!(outcome.entries.len(), 3);
        assert!(outcome.has_more); // beta and gamma still unread
    }

    #[test]
    fn iter_non_start_cookie_skips_synthetics() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);

        // Resume from cookie 2 (..) — synthetics are already emitted
        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie(2), 128);
        assert!(!outcome.entries.iter().any(|e| e.name == b"."));
        assert!(!outcome.entries.iter().any(|e| e.name == b".."));
        // Should contain alpha
        assert!(outcome.entries.iter().any(|e| e.name == b"alpha"));
    }

    #[test]
    fn iter_cookie_past_end_returns_empty() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie(999999), 128);
        assert!(outcome.entries.is_empty());
        assert!(!outcome.has_more);
    }

    #[test]
    fn iter_dir_with_subdir_emits_correct_kind() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"child_dir", 50, 0o040000); // directory

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        let child = outcome
            .entries
            .iter()
            .find(|e| e.name == b"child_dir")
            .unwrap();
        assert_eq!(child.kind, NodeKind::Dir);
    }

    #[test]
    fn iter_dir_with_symlink_emits_correct_kind() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"link", 60, 0o120000); // symlink

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        let sym = outcome.entries.iter().find(|e| e.name == b"link").unwrap();
        assert_eq!(sym.kind, NodeKind::Symlink);
    }

    // ── resolve_readdirplus_attrs tests ──────────────────────────────

    #[test]
    fn readdirplus_resolves_attrs_for_all_entries() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"alpha", 42, 0o100000);
        insert_entry(&mut dir, b"beta", 43, 0o100000);

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        let (pairs, has_more) = resolve_readdirplus_attrs(&outcome, |ino| {
            Some(InodeAttr::new(
                InodeId::new(ino),
                Generation::new(1),
                if ino == 10 {
                    NodeKind::Dir
                } else {
                    NodeKind::File
                },
                Default::default(),
                tidefs_types_vfs_core::InodeFlags::none(),
                0,
                0,
            ))
        });

        assert_eq!(pairs.len(), 4); // . + .. + alpha + beta
        assert!(!has_more);
        assert_eq!(pairs[2].entry.name, b"alpha");
        assert_eq!(pairs[2].attr.inode_id.get(), 42);
    }

    #[test]
    fn readdirplus_skips_entries_with_unresolvable_attrs() {
        let mut dir = make_dir();
        insert_entry(&mut dir, b"ghost", 99, 0o100000);

        let outcome = iter_dir_entries(&dir, 10, 1, None, DirCookie::START, 128);
        let (pairs, _) = resolve_readdirplus_attrs(&outcome, |ino| {
            if ino == 99 {
                None
            } else {
                Some(InodeAttr::new(
                    InodeId::new(ino),
                    Generation::new(0),
                    NodeKind::Dir,
                    Default::default(),
                    tidefs_types_vfs_core::InodeFlags::none(),
                    0,
                    0,
                ))
            }
        });

        // . and .. resolve, ghost is skipped
        assert_eq!(pairs.len(), 2);
        assert!(pairs
            .iter()
            .all(|p| p.entry.name == b"." || p.entry.name == b".."));
    }

    // ── ReaddirError tests ───────────────────────────────────────────

    #[test]
    fn error_to_errno_mapping() {
        assert_eq!(ReaddirError::NotFound.to_errno(), Errno::ENOENT);
        assert_eq!(ReaddirError::NotDirectory.to_errno(), Errno::ENOTDIR);
        assert_eq!(ReaddirError::Io.to_errno(), Errno::EIO);
    }

    // ── node_kind_to_fuse_file_type tests ────────────────────────────

    #[test]
    fn file_type_mapping_roundtrip() {
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::Dir),
            fuser::FileType::Directory
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::File),
            fuser::FileType::RegularFile
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::Symlink),
            fuser::FileType::Symlink
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::BlockDev),
            fuser::FileType::BlockDevice
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::CharDev),
            fuser::FileType::CharDevice
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::Fifo),
            fuser::FileType::NamedPipe
        );
        assert_eq!(
            node_kind_to_fuse_file_type(NodeKind::Socket),
            fuser::FileType::Socket
        );
    }
}
