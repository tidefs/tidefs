// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! TideFS namespace layer: inode allocation, path resolution, and core
//! namespace operations atop the polymorphic directory index.
//!
//! This crate provides [`Namespace`] which owns an in-memory inode table
//! ([`MemInodeTable`]) and per-directory [`DirIndex`] instances, and
//! implements path resolution plus create, lookup, link, readlink, unlink,
//! and rename operations.

#![forbid(unsafe_code)]

pub mod entry;
pub mod insert;
#[cfg(feature = "local-fs-persist")]
pub mod local_fs_persist;
pub mod lookup;
pub mod metadata_engine;
pub mod persistence;
pub mod remove;

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::SystemTime,
};

#[cfg(feature = "persistent-dir-index")]
use std::path::PathBuf;

#[cfg(not(feature = "persistent-dir-index"))]
use tidefs_dir_index::DirIndex;
use tidefs_dir_index::DirIndexError;

#[allow(unused_imports)]
use persistence::{
    NamespaceDatasetIdentity, PersistentDirEntry, PersistentDirectoryStore, PersistentInodeStore,
    PersistentSwapMode,
};
use tidefs_dir_index::SwapMode;
use tidefs_orphan_index::OrphanIndex;

#[cfg(feature = "persistent-dir-index")]
use tidefs_dir_index::persistent::PersistentDirIndex;
#[cfg(feature = "persistent-dir-index")]
type DirBackend = PersistentDirIndex;
#[cfg(not(feature = "persistent-dir-index"))]
type DirBackend = DirIndex;
use tidefs_types_polymorphic_directory_index_core::{DatasetDirPolicy, DirMicroEntry};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Opaque inode handle.
pub type Inode = u64;

/// Reserved root inode.
pub const ROOT_INODE: Inode = 1;

/// Entry kind constants matching `tidefs_types_polymorphic_directory_index_core`
/// `NodeKind` encoding.
pub const KIND_DIR: u32 = 0;
pub const KIND_FILE: u32 = 1;
pub const KIND_SYMLINK: u32 = 2;
pub const KIND_FIFO: u32 = 3;
pub const KIND_SOCKET: u32 = 4;
pub const KIND_CHAR: u32 = 5;
pub const KIND_BLOCK: u32 = 6;

/// Maximum symlink expansions allowed during path resolution.
pub const MAX_SYMLINK_DEPTH: usize = 40;

/// Linux/POSIX `RENAME_NOREPLACE`: fail if the destination exists.
pub const RENAME_NOREPLACE: u32 = 0x01;

/// Linux/POSIX `RENAME_EXCHANGE`: atomically exchange source and destination.
pub const RENAME_EXCHANGE: u32 = 0x02;

/// Entry type for namespace operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EntryType {
    Directory,
    File,
    Symlink,
    Fifo,
    CharacterDevice,
    BlockDevice,
    Socket,
}

impl EntryType {
    /// Encode to the `kind` field used by [`DirIndex`] entries.
    #[must_use]
    pub const fn to_kind(self) -> u32 {
        match self {
            EntryType::Directory => KIND_DIR,
            EntryType::File => KIND_FILE,
            EntryType::Symlink => KIND_SYMLINK,
            EntryType::Fifo => KIND_FIFO,
            EntryType::CharacterDevice => KIND_CHAR,
            EntryType::BlockDevice => KIND_BLOCK,
            EntryType::Socket => KIND_SOCKET,
        }
    }

    /// Decode from a `kind` field.
    #[must_use]
    pub const fn from_kind(k: u32) -> Option<Self> {
        match k {
            KIND_DIR => Some(EntryType::Directory),
            KIND_FILE => Some(EntryType::File),
            KIND_SYMLINK => Some(EntryType::Symlink),
            KIND_FIFO => Some(EntryType::Fifo),
            KIND_SOCKET => Some(EntryType::Socket),
            KIND_CHAR => Some(EntryType::CharacterDevice),
            KIND_BLOCK => Some(EntryType::BlockDevice),
            _ => None,
        }
    }

    /// Returns `true` if this is a directory.
    #[must_use]
    pub const fn is_dir(self) -> bool {
        matches!(self, EntryType::Directory)
    }
}

/// Parent directory and final component produced by symlink-aware parent
/// resolution for path-based namespace mutations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedParent {
    /// Inode of the resolved parent directory.
    pub parent: Inode,
    /// Final path component to create, unlink, or rename into.
    pub name: Vec<u8>,
}

// ---------------------------------------------------------------------------
// InodeAttributes
// ---------------------------------------------------------------------------

/// POSIX-flavoured inode attributes stored in the inode table.
#[derive(Clone, Debug)]
pub struct InodeAttributes {
    /// The inode these attributes belong to.
    pub inode: Inode,
    /// File type and permissions (`st_mode` lower bits).
    pub mode: u32,
    /// Owner user id.
    pub uid: u32,
    /// Owner group id.
    pub gid: u32,
    /// Logical file size in bytes.
    pub size: u64,
    /// Hard link count.
    pub nlink: u32,
    /// Last access time.
    pub atime: SystemTime,
    /// Last modification time.
    pub mtime: SystemTime,
    /// Last status change time.
    pub ctime: SystemTime,
    /// Device number (for char/block special nodes).
    pub rdev: u32,
}

impl InodeAttributes {
    /// Create default directory attributes for the given inode.
    #[must_use]
    pub fn new_dir(inode: Inode) -> Self {
        let now = SystemTime::now();
        InodeAttributes {
            inode,
            mode: 0o40755, // directory, rwxr-xr-x
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 2, // . and parent
            atime: now,
            mtime: now,
            ctime: now,
            rdev: 0,
        }
    }

    /// Create default regular-file attributes for the given inode.
    #[must_use]
    pub fn new_file(inode: Inode) -> Self {
        let now = SystemTime::now();
        InodeAttributes {
            inode,
            mode: 0o100644, // regular file, rw-r--r--
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 1,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: 0,
        }
    }

    /// Create default symbolic-link attributes for the given inode.
    #[must_use]
    pub fn new_symlink(inode: Inode, target_len: u64) -> Self {
        let now = SystemTime::now();
        InodeAttributes {
            inode,
            mode: 0o120777, // symbolic link, rwxrwxrwx
            uid: 0,
            gid: 0,
            size: target_len,
            nlink: 1,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: 0,
        }
    }

    /// Bump `ctime` and `mtime` to now.
    pub fn touch(&mut self) {
        let now = SystemTime::now();
        self.mtime = now;
        self.ctime = now;
    }

    /// Bump only `ctime` to now.
    pub fn touch_ctime(&mut self) {
        self.ctime = SystemTime::now();
    }
}

// ---------------------------------------------------------------------------
// NamespaceError
// ---------------------------------------------------------------------------

/// Errors returned by namespace operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceError {
    /// A path component or entry was not found.
    NotFound,
    /// An entry with the given name already exists in the directory.
    AlreadyExists,
    /// Attempted to unlink/remove a directory that still has children.
    NotEmpty,
    /// Operation expected a directory but found a non-directory.
    NotDirectory,
    /// Directory cursor is stale — the directory was mutated between
    /// paginated readdir batches.
    StaleCursor,
    /// Operation expected a non-directory but found a directory.
    IsDirectory,
    /// The name is invalid (empty, contains `/`, or is `.` / `..` where
    /// disallowed).
    InvalidName,
    /// The referenced inode does not exist.
    InodeNotFound,
    /// Rename across devices (stub—single-device only for now).
    CrossDeviceRename,
    /// Path resolution exceeded the symlink expansion limit.
    TooManySymlinks,
    /// Operation expected a symlink but found another inode type.
    NotSymlink,
    /// Link-count increment would overflow.
    LinkCountOverflow,
    /// Directory rename would create a parent/child cycle.
    RenameCycle,
    /// Operation not yet supported.
    NotSupported,
    /// The mounted local filesystem cannot safely accept more mutations until
    /// it is reopened after an indeterminate root publication.
    MutationRequiresReopen { operation: &'static str },
    /// Persisted namespace root belongs to a different dataset identity.
    DatasetIdentityMismatch {
        expected: NamespaceDatasetIdentity,
        found: NamespaceDatasetIdentity,
    },
    /// Underlying directory index error.
    DirIndex(DirIndexError),
}

impl fmt::Display for NamespaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamespaceError::NotFound => f.write_str("not found"),
            NamespaceError::AlreadyExists => f.write_str("already exists"),
            NamespaceError::NotEmpty => f.write_str("directory not empty"),
            NamespaceError::NotDirectory => f.write_str("not a directory"),
            NamespaceError::StaleCursor => f.write_str("stale directory cursor"),
            NamespaceError::IsDirectory => f.write_str("is a directory"),
            NamespaceError::InvalidName => f.write_str("invalid name"),
            NamespaceError::InodeNotFound => f.write_str("inode not found"),
            NamespaceError::CrossDeviceRename => f.write_str("cross-device rename not supported"),
            NamespaceError::TooManySymlinks => f.write_str("too many symlink levels"),
            NamespaceError::NotSymlink => f.write_str("not a symlink"),
            NamespaceError::LinkCountOverflow => f.write_str("link count overflow"),
            NamespaceError::RenameCycle => f.write_str("rename would create directory cycle"),
            NamespaceError::NotSupported => f.write_str("operation not supported"),
            NamespaceError::MutationRequiresReopen { operation } => write!(
                f,
                "mounted filesystem mutation requires reopen before {operation}"
            ),
            NamespaceError::DatasetIdentityMismatch { expected, found } => write!(
                f,
                "dataset identity mismatch: expected {}/{} found {}/{}",
                expected.dataset_id(),
                expected.lineage_id(),
                found.dataset_id(),
                found.lineage_id()
            ),
            NamespaceError::DirIndex(e) => write!(f, "dir-index error: {e:?}"),
        }
    }
}

impl std::error::Error for NamespaceError {}

impl From<DirIndexError> for NamespaceError {
    fn from(e: DirIndexError) -> Self {
        match e {
            DirIndexError::EntryAlreadyExists => NamespaceError::AlreadyExists,
            DirIndexError::EntryNotFound => NamespaceError::NotFound,
            DirIndexError::DirNotEmpty => NamespaceError::NotEmpty,
            DirIndexError::StaleCursor => NamespaceError::StaleCursor,
        }
    }
}

// ---------------------------------------------------------------------------
// InodeTable trait
// ---------------------------------------------------------------------------

/// Inode allocation and attribute management.
pub trait InodeTable: Send + Sync {
    /// Allocate a new inode with the given initial attributes, returning
    /// its inode number.
    fn alloc(&self, attrs: InodeAttributes) -> Result<Inode, NamespaceError>;

    /// Retrieve attributes for `inode`, or `None` if not present.
    fn get(&self, inode: Inode) -> Option<InodeAttributes>;

    /// Replace attributes for `inode`.
    fn update_attrs(&self, inode: Inode, attrs: InodeAttributes) -> Result<(), NamespaceError>;

    /// Free an inode so its slot may be reused.
    fn free(&self, inode: Inode) -> Result<(), NamespaceError>;
}

// ---------------------------------------------------------------------------
// MemInodeTable — in-memory bump-allocated inode table
// ---------------------------------------------------------------------------

/// In-memory inode table using a bump allocator for inode numbers and a
/// `HashMap` for attribute storage. Freed inodes are tracked so that
/// double-free and get-after-free produce errors.
///
/// Review debt TFR-004: this allocator is a namespace-local authority that
/// currently coexists with `LocalFileSystem` and `tidefs-inode-table`
/// allocation paths.
pub struct MemInodeTable {
    next: AtomicU64,
    table: RwLock<HashMap<Inode, InodeAttributes>>,
    freed: RwLock<HashSet<Inode>>,
}

impl MemInodeTable {
    /// Create an empty inode table; the next allocated inode will be 1.
    #[must_use]
    pub fn new() -> Self {
        MemInodeTable {
            next: AtomicU64::new(1),
            table: RwLock::new(HashMap::new()),
            freed: RwLock::new(HashSet::new()),
        }
    }

    /// Returns the number of live inodes.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.table.read().unwrap().len()
    }

    #[cfg(feature = "persistent-dir-index")]
    fn insert_loaded_attrs(&self, attrs: InodeAttributes) {
        let inode = attrs.inode;
        self.freed.write().unwrap().remove(&inode);
        self.table.write().unwrap().entry(inode).or_insert(attrs);
        self.advance_next_after(inode);
    }

    pub(crate) fn insert_allocated_attrs(
        &self,
        attrs: InodeAttributes,
    ) -> Result<Inode, NamespaceError> {
        if attrs.inode == 0 {
            return self.alloc(attrs);
        }

        let inode = attrs.inode;
        let mut attrs = Self::prepare_alloc_attrs(attrs, inode);
        attrs.inode = inode;

        {
            let mut freed = self.freed.write().unwrap();
            let mut table = self.table.write().unwrap();
            if table.contains_key(&inode) {
                return Err(NamespaceError::AlreadyExists);
            }
            freed.remove(&inode);
            table.insert(inode, attrs);
        }
        self.advance_next_after(inode);
        Ok(inode)
    }

    fn prepare_alloc_attrs(mut attrs: InodeAttributes, inode: Inode) -> InodeAttributes {
        attrs.inode = inode;
        attrs.ctime = SystemTime::now();
        if attrs.mtime == SystemTime::UNIX_EPOCH {
            attrs.mtime = attrs.ctime;
        }
        if attrs.atime == SystemTime::UNIX_EPOCH {
            attrs.atime = attrs.ctime;
        }
        attrs
    }

    fn advance_next_after(&self, inode: Inode) {
        let desired = inode.saturating_add(1);
        let mut current = self.next.load(Ordering::Relaxed);
        while current < desired {
            match self.next.compare_exchange_weak(
                current,
                desired,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

impl Default for MemInodeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InodeTable for MemInodeTable {
    fn alloc(&self, mut attrs: InodeAttributes) -> Result<Inode, NamespaceError> {
        let ino = self.next.fetch_add(1, Ordering::Relaxed);
        attrs = Self::prepare_alloc_attrs(attrs, ino);
        self.table.write().unwrap().insert(ino, attrs);
        Ok(ino)
    }

    fn get(&self, inode: Inode) -> Option<InodeAttributes> {
        if self.freed.read().unwrap().contains(&inode) {
            return None;
        }
        self.table.read().unwrap().get(&inode).cloned()
    }

    fn update_attrs(&self, inode: Inode, attrs: InodeAttributes) -> Result<(), NamespaceError> {
        if self.freed.read().unwrap().contains(&inode) {
            return Err(NamespaceError::InodeNotFound);
        }
        let mut table = self.table.write().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut e) = table.entry(inode) {
            e.insert(attrs);
            Ok(())
        } else {
            Err(NamespaceError::InodeNotFound)
        }
    }

    fn free(&self, inode: Inode) -> Result<(), NamespaceError> {
        {
            let mut freed = self.freed.write().unwrap();
            if freed.contains(&inode) {
                return Err(NamespaceError::InodeNotFound);
            }
            freed.insert(inode);
        }
        self.table.write().unwrap().remove(&inode);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Namespace
// ---------------------------------------------------------------------------

/// Core namespace providing path resolution and directory-entry operations
/// atop [`DirIndex`] and [`MemInodeTable`].
pub struct Namespace {
    inode_table: Arc<MemInodeTable>,
    dirs: Arc<RwLock<HashMap<Inode, DirBackend>>>,
    symlink_targets: RwLock<HashMap<Inode, Vec<u8>>>,
    orphan_index: RwLock<OrphanIndex>,
    #[allow(dead_code)]
    persistent_inodes: Option<Arc<dyn PersistentInodeStore>>,
    #[allow(dead_code)]
    persistent_dirs: Option<Arc<dyn PersistentDirectoryStore>>,
    persistent_dirs_shared: bool,
    #[cfg(feature = "persistent-dir-index")]
    persistent_object_store_root: Option<PathBuf>,
    #[cfg(feature = "persistent-dir-index")]
    persistent_manifest_dirs: RwLock<HashSet<Inode>>,
    policy: DatasetDirPolicy,
    dataset_identity: NamespaceDatasetIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PathStep {
    Root,
    Cur,
    Parent,
    Normal(Vec<u8>),
}

/// Namespace basename validation mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BasenameValidationMode {
    /// Lookup-style operations may address existing `.` and `..` entries.
    Lookup,
    /// Mutating directory-entry operations may not target `.` or `..`.
    DirectoryEntryMutation,
}

impl BasenameValidationMode {
    const fn rejects_dot_entries(self) -> bool {
        matches!(self, BasenameValidationMode::DirectoryEntryMutation)
    }
}

/// Reason a namespace basename cannot be used as a single path component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidBasenameReason {
    /// The component is empty.
    Empty,
    /// The component contains a path separator.
    ContainsSlash,
    /// The component contains an interior NUL byte.
    ContainsNul,
    /// The component is the reserved current-directory entry.
    Dot,
    /// The component is the reserved parent-directory entry.
    DotDot,
}

/// Planned validation outcome for a namespace basename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BasenameValidationPlan {
    /// Validation mode used for this component.
    pub mode: BasenameValidationMode,
    /// Length of the checked component in bytes.
    pub name_len: usize,
    /// Invalidity reason, or `None` when the component is valid.
    pub invalid_reason: Option<InvalidBasenameReason>,
}

impl BasenameValidationPlan {
    /// Returns `true` when the checked component is valid.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.invalid_reason.is_none()
    }

    /// Convert the planned outcome into the namespace operation result type.
    pub const fn validate(self) -> Result<(), NamespaceError> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(NamespaceError::InvalidName)
        }
    }
}

/// Plan validation for a single namespace basename.
///
/// Basenames are single path components. Empty names, names containing `/`,
/// names containing NUL bytes, and mutating uses of `.` or `..` are invalid.
#[must_use]
pub fn plan_basename_validation(
    name: &[u8],
    mode: BasenameValidationMode,
) -> BasenameValidationPlan {
    let invalid_reason = if name.is_empty() {
        Some(InvalidBasenameReason::Empty)
    } else if name.contains(&b'/') {
        Some(InvalidBasenameReason::ContainsSlash)
    } else if name.contains(&0) {
        Some(InvalidBasenameReason::ContainsNul)
    } else if mode.rejects_dot_entries() && name == b"." {
        Some(InvalidBasenameReason::Dot)
    } else if mode.rejects_dot_entries() && name == b".." {
        Some(InvalidBasenameReason::DotDot)
    } else {
        None
    };

    BasenameValidationPlan {
        mode,
        name_len: name.len(),
        invalid_reason,
    }
}

/// Validate a single path component name.
///
/// Rejects empty names, names containing `/` or NUL, and (when
/// `reject_dotdirs` is true) the names `.` and `..`.
fn validate_name(name: &[u8], reject_dotdirs: bool) -> Result<(), NamespaceError> {
    let mode = if reject_dotdirs {
        BasenameValidationMode::DirectoryEntryMutation
    } else {
        BasenameValidationMode::Lookup
    };
    plan_basename_validation(name, mode).validate()
}

/// Errors returned while planning POSIX rename flag handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameFlagPlanError {
    /// Flags include unsupported bits.
    InvalidFlags { flags: u32 },
    /// `RENAME_NOREPLACE` was requested but the destination exists.
    TargetExists,
    /// `RENAME_EXCHANGE` was requested but the destination is absent.
    TargetMissing,
}

/// Normalized rename mode derived from POSIX rename flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameMode {
    /// No destination existence precondition; replace existing targets.
    ReplaceExisting,
    /// `RENAME_NOREPLACE`: fail if the destination exists.
    NoReplace,
    /// `RENAME_EXCHANGE`: swap the source and destination entries.
    Exchange,
}

/// Pure POSIX rename flag plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenameFlagPlan {
    /// Original flags used to build the plan.
    pub flags: u32,
    /// Whether the destination currently exists.
    pub target_exists: bool,
    /// Normalized rename mode.
    pub mode: RenameMode,
}

impl RenameFlagPlan {
    /// Return true when this plan requires the destination to be absent.
    #[must_use]
    pub const fn requires_absent_target(self) -> bool {
        matches!(self.mode, RenameMode::NoReplace)
    }

    /// Return true when this plan requires the destination to exist.
    #[must_use]
    pub const fn requires_present_target(self) -> bool {
        matches!(self.mode, RenameMode::Exchange)
    }
}

/// Plan POSIX rename flag handling without mutating the namespace.
pub fn plan_rename_flags(
    flags: u32,
    target_exists: bool,
) -> Result<RenameFlagPlan, RenameFlagPlanError> {
    let mode = match flags {
        0 => RenameMode::ReplaceExisting,
        RENAME_NOREPLACE => RenameMode::NoReplace,
        RENAME_EXCHANGE => RenameMode::Exchange,
        _ => return Err(RenameFlagPlanError::InvalidFlags { flags }),
    };

    if mode == RenameMode::NoReplace && target_exists {
        return Err(RenameFlagPlanError::TargetExists);
    }
    if mode == RenameMode::Exchange && !target_exists {
        return Err(RenameFlagPlanError::TargetMissing);
    }

    Ok(RenameFlagPlan {
        flags,
        target_exists,
        mode,
    })
}

impl From<RenameFlagPlanError> for NamespaceError {
    fn from(error: RenameFlagPlanError) -> Self {
        match error {
            RenameFlagPlanError::InvalidFlags { .. } => NamespaceError::NotSupported,
            RenameFlagPlanError::TargetExists => NamespaceError::AlreadyExists,
            RenameFlagPlanError::TargetMissing => NamespaceError::NotFound,
        }
    }
}

/// Existing destination entry details needed to plan a POSIX rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenameExistingTarget {
    /// Destination inode.
    pub inode: Inode,
    /// Destination entry type.
    pub entry_type: EntryType,
    /// Directory entry count when the destination is a directory.
    pub directory_entry_count: Option<usize>,
}

/// Planned action for the destination side of a POSIX rename.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameTargetAction {
    /// Destination does not exist; insert the renamed entry.
    DestinationAbsent,
    /// Destination already resolves to the source inode; the rename is a no-op.
    NoOpSameInode,
    /// Destination exists and may be replaced.
    ReplaceExisting {
        /// Type of the destination being replaced.
        entry_type: EntryType,
        /// Whether the destination directory index should be removed.
        remove_directory_index: bool,
    },
}

/// Pure POSIX rename destination plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RenameTargetPlan {
    /// Type of the source entry being renamed.
    pub source_entry_type: EntryType,
    /// Destination-side action to perform.
    pub action: RenameTargetAction,
}

impl RenameTargetPlan {
    /// Return true when the rename should not mutate the namespace.
    #[must_use]
    pub const fn is_noop(self) -> bool {
        matches!(self.action, RenameTargetAction::NoOpSameInode)
    }
}

/// Errors returned while planning POSIX rename destination handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameTargetPlanError {
    /// A directory source cannot replace a non-directory destination.
    DirectoryOverNonDirectory,
    /// A non-directory source cannot replace a directory destination.
    NonDirectoryOverDirectory,
    /// A directory destination exists but is not empty.
    DirectoryNotEmpty,
}

/// Plan POSIX rename destination handling without mutating the namespace.
pub fn plan_rename_target(
    source_inode: Inode,
    source_entry_type: EntryType,
    existing: Option<RenameExistingTarget>,
) -> Result<RenameTargetPlan, RenameTargetPlanError> {
    let action = match existing {
        None => RenameTargetAction::DestinationAbsent,
        Some(existing) if existing.inode == source_inode => RenameTargetAction::NoOpSameInode,
        Some(existing) => {
            if source_entry_type.is_dir() && !existing.entry_type.is_dir() {
                return Err(RenameTargetPlanError::DirectoryOverNonDirectory);
            }
            if !source_entry_type.is_dir() && existing.entry_type.is_dir() {
                return Err(RenameTargetPlanError::NonDirectoryOverDirectory);
            }
            if existing.entry_type.is_dir()
                && matches!(existing.directory_entry_count, Some(count) if count > 2)
            {
                return Err(RenameTargetPlanError::DirectoryNotEmpty);
            }

            RenameTargetAction::ReplaceExisting {
                entry_type: existing.entry_type,
                remove_directory_index: existing.entry_type.is_dir(),
            }
        }
    };

    Ok(RenameTargetPlan {
        source_entry_type,
        action,
    })
}

impl From<RenameTargetPlanError> for NamespaceError {
    fn from(error: RenameTargetPlanError) -> Self {
        match error {
            RenameTargetPlanError::DirectoryOverNonDirectory => NamespaceError::NotDirectory,
            RenameTargetPlanError::NonDirectoryOverDirectory => NamespaceError::IsDirectory,
            RenameTargetPlanError::DirectoryNotEmpty => NamespaceError::NotEmpty,
        }
    }
}

fn path_steps(path: &Path) -> Result<VecDeque<PathStep>, NamespaceError> {
    use std::path::Component;

    let mut steps = VecDeque::new();
    for component in path.components() {
        match component {
            Component::RootDir => steps.push_back(PathStep::Root),
            Component::CurDir => steps.push_back(PathStep::Cur),
            Component::ParentDir => steps.push_back(PathStep::Parent),
            Component::Normal(name) => {
                let name = name.as_encoded_bytes();
                validate_name(name, false)?;
                steps.push_back(PathStep::Normal(name.to_vec()));
            }
            Component::Prefix(_) => return Err(NamespaceError::NotSupported),
        }
    }
    Ok(steps)
}

fn symlink_target_steps(target: &[u8]) -> Result<VecDeque<PathStep>, NamespaceError> {
    let mut steps = VecDeque::new();
    if target.starts_with(b"/") {
        steps.push_back(PathStep::Root);
    }

    for part in target.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            steps.push_back(PathStep::Parent);
        } else {
            validate_name(part, false)?;
            steps.push_back(PathStep::Normal(part.to_vec()));
        }
    }

    Ok(steps)
}

impl Namespace {
    /// Create a new namespace with an empty root directory at inode 1.
    ///
    /// The root directory initially contains self-referencing `.` and `..`
    /// entries.
    #[must_use]
    pub fn new() -> Self {
        let inode_table = Arc::new(MemInodeTable::new());
        let policy = DatasetDirPolicy::DEFAULT;

        // Allocate root inode (will be 1).
        let root_attrs = InodeAttributes::new_dir(ROOT_INODE);
        let _root = inode_table
            .alloc(root_attrs)
            .expect("first allocation must succeed");

        // Create root directory index with . and .. pointing to itself.
        let mut root_dir = DirBackend::new(ROOT_INODE, policy);
        root_dir
            .insert(b".", ROOT_INODE, 0, KIND_DIR)
            .expect("root . insert");
        root_dir
            .insert(b"..", ROOT_INODE, 0, KIND_DIR)
            .expect("root .. insert");

        let mut dirs = HashMap::new();
        dirs.insert(ROOT_INODE, root_dir);

        Namespace {
            persistent_inodes: None,
            persistent_dirs: None,
            persistent_dirs_shared: false,
            inode_table,
            dirs: Arc::new(RwLock::new(dirs)),
            symlink_targets: RwLock::new(HashMap::new()),
            orphan_index: RwLock::new(OrphanIndex::new()),
            #[cfg(feature = "persistent-dir-index")]
            persistent_object_store_root: None,
            #[cfg(feature = "persistent-dir-index")]
            persistent_manifest_dirs: RwLock::new(HashSet::new()),
            policy,
            dataset_identity: NamespaceDatasetIdentity::default(),
        }
    }

    /// Create a new namespace with a custom [`DatasetDirPolicy`].
    #[must_use]
    pub fn with_policy(policy: DatasetDirPolicy) -> Self {
        let ns = Self::new();
        // Re-create root dir with custom policy
        let mut root_dir = DirBackend::new(ROOT_INODE, policy);
        root_dir
            .insert(b".", ROOT_INODE, 0, KIND_DIR)
            .expect("root . insert");
        root_dir
            .insert(b"..", ROOT_INODE, 0, KIND_DIR)
            .expect("root .. insert");
        ns.dirs.write().unwrap().insert(ROOT_INODE, root_dir);
        Namespace {
            persistent_inodes: None,
            persistent_dirs: None,
            persistent_dirs_shared: false,
            policy,
            dataset_identity: NamespaceDatasetIdentity::default(),
            orphan_index: RwLock::new(OrphanIndex::new()),
            ..ns
        }
    }

    /// Create a new namespace backed by optional persistent stores.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_persistent_stores(
        inode_store: Option<Arc<dyn PersistentInodeStore>>,
        dir_store: Option<Arc<dyn PersistentDirectoryStore>>,
    ) -> Self {
        Self::try_with_persistent_stores_for_dataset(
            NamespaceDatasetIdentity::default(),
            inode_store,
            dir_store,
        )
        .expect("persistent namespace stores must match the default dataset identity")
    }

    /// Create a namespace for an explicit dataset identity.
    #[allow(dead_code)]
    pub fn try_with_persistent_stores_for_dataset(
        identity: NamespaceDatasetIdentity,
        inode_store: Option<Arc<dyn PersistentInodeStore>>,
        dir_store: Option<Arc<dyn PersistentDirectoryStore>>,
    ) -> Result<Self, NamespaceError> {
        let policy = DatasetDirPolicy::DEFAULT;
        let root_attrs = InodeAttributes::new_dir(ROOT_INODE);
        if let Some(ref store) = inode_store {
            let root = store.ensure_namespace_root(&identity, &root_attrs)?;
            if root.root_inode != ROOT_INODE {
                return Err(NamespaceError::NotFound);
            }
        }
        if let Some(ref dirs) = dir_store {
            dirs.verify_dataset_identity(&identity)?;
            match dirs.lookup_for_dataset(&identity, ROOT_INODE, b".") {
                Ok(Some(_)) => {}
                Ok(None) | Err(NamespaceError::InodeNotFound | NamespaceError::NotFound) => {
                    dirs.init_dir_for_dataset(&identity, ROOT_INODE)?;
                }
                Err(e) => return Err(e),
            }
        }
        let inode_table = Arc::new(MemInodeTable::new());
        if inode_store.is_none() {
            inode_table.alloc(root_attrs).expect("root fallback alloc");
        }
        let mut root_dir = DirBackend::new(ROOT_INODE, policy);
        root_dir
            .insert(b".", ROOT_INODE, 0, KIND_DIR)
            .expect("root .");
        root_dir
            .insert(b"..", ROOT_INODE, 0, KIND_DIR)
            .expect("root ..");
        let mut persistent_dirs_shared = false;
        let dirs_arc: Arc<RwLock<HashMap<Inode, DirBackend>>> = if let Some(ref store) = dir_store {
            if let Some(shared) = store.shared_dirs_for_dataset(&identity)? {
                persistent_dirs_shared = true;
                shared
            } else {
                let mut dirs = HashMap::new();
                let root_dir =
                    Self::load_delegated_dir_backend(store.as_ref(), &identity, ROOT_INODE, policy)
                        .unwrap_or(root_dir);
                dirs.insert(ROOT_INODE, root_dir);
                Arc::new(RwLock::new(dirs))
            }
        } else {
            let mut dirs = HashMap::new();
            dirs.insert(ROOT_INODE, root_dir);
            Arc::new(RwLock::new(dirs))
        };
        Ok(Namespace {
            persistent_inodes: inode_store,
            persistent_dirs: dir_store,
            persistent_dirs_shared,
            inode_table,
            dirs: dirs_arc,
            orphan_index: RwLock::new(OrphanIndex::new()),
            symlink_targets: RwLock::new(HashMap::new()),
            #[cfg(feature = "persistent-dir-index")]
            persistent_object_store_root: None,
            #[cfg(feature = "persistent-dir-index")]
            persistent_manifest_dirs: RwLock::new(HashSet::new()),
            policy,
            dataset_identity: identity,
        })
    }

    // ── Persistent-store delegation ─────────────────────────────────
    fn ensure_mutation_allowed(&self, operation: &'static str) -> Result<(), NamespaceError> {
        if let Some(ref store) = self.persistent_inodes {
            store.ensure_mutation_allowed(operation)?;
        }
        if let Some(ref store) = self.persistent_dirs {
            store.ensure_mutation_allowed(operation)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn alloc_inode_delegate(&self, attrs: InodeAttributes) -> Result<(Inode, u64), NamespaceError> {
        if let Some(ref store) = self.persistent_inodes {
            store.alloc_inode_for_dataset(&self.dataset_identity, &attrs)
        } else {
            self.fallback_inode_table().alloc(attrs).map(|ino| (ino, 0))
        }
    }
    #[allow(dead_code)]
    fn get_inode_attrs_delegate(&self, inode: Inode) -> Option<InodeAttributes> {
        if let Some(ref store) = self.persistent_inodes {
            store.get_attrs(inode)
        } else {
            self.fallback_inode_table().get(inode)
        }
    }
    #[allow(dead_code)]
    fn set_inode_attrs_delegate(
        &self,
        inode: Inode,
        attrs: InodeAttributes,
    ) -> Result<(), NamespaceError> {
        if let Some(ref store) = self.persistent_inodes {
            store.update_attrs(inode, &attrs)
        } else {
            self.fallback_inode_table().update_attrs(inode, attrs)
        }
    }
    #[allow(dead_code)]
    fn free_inode_delegate(&self, inode: Inode) -> Result<(), NamespaceError> {
        if let Some(ref store) = self.persistent_inodes {
            store.free_inode(inode)
        } else {
            self.fallback_inode_table().free(inode)
        }
    }
    #[allow(dead_code)]
    fn fallback_inode_table(&self) -> &MemInodeTable {
        &self.inode_table
    }

    fn delegated_dir_store(&self) -> Option<&Arc<dyn PersistentDirectoryStore>> {
        if self.persistent_dirs_shared {
            None
        } else {
            self.persistent_dirs.as_ref()
        }
    }

    fn load_delegated_dir_backend(
        store: &dyn PersistentDirectoryStore,
        identity: &NamespaceDatasetIdentity,
        dir_inode: Inode,
        policy: DatasetDirPolicy,
    ) -> Result<DirBackend, NamespaceError> {
        let mut dir = DirBackend::new(dir_inode, policy);
        let mut cookie = 0;

        loop {
            let (entries, next_cookie) = store.list_dir_for_dataset(identity, dir_inode, cookie)?;
            if entries.is_empty() {
                break;
            }

            for entry in entries {
                dir.insert(&entry.name, entry.inode_id, entry.generation, entry.kind)?;
            }

            if next_cookie == cookie {
                break;
            }
            cookie = next_cookie;
        }

        Ok(dir)
    }

    fn ensure_delegated_dir_loaded(&self, dir_inode: Inode) -> Result<bool, NamespaceError> {
        let Some(store) = self.delegated_dir_store() else {
            return Ok(self.dirs.read().unwrap().contains_key(&dir_inode));
        };

        if self.dirs.read().unwrap().contains_key(&dir_inode) {
            return Ok(true);
        }

        let dir = Self::load_delegated_dir_backend(
            store.as_ref(),
            &self.dataset_identity,
            dir_inode,
            self.policy,
        )?;
        self.dirs.write().unwrap().entry(dir_inode).or_insert(dir);
        Ok(true)
    }

    fn insert_delegated_dir_entry(
        &self,
        parent: Inode,
        name: &[u8],
        inode_id: Inode,
        generation: u64,
        kind: u32,
    ) -> Result<(), NamespaceError> {
        if let Some(store) = self.delegated_dir_store() {
            store.insert_for_dataset(
                &self.dataset_identity,
                parent,
                name,
                inode_id,
                generation,
                kind,
            )?;
        }
        Ok(())
    }

    fn init_delegated_dir(
        &self,
        dir_inode: Inode,
        parent_inode: Inode,
    ) -> Result<(), NamespaceError> {
        if let Some(store) = self.delegated_dir_store() {
            store.init_dir_for_dataset(&self.dataset_identity, dir_inode)?;
            if dir_inode != parent_inode {
                store.remove_for_dataset(&self.dataset_identity, dir_inode, b"..")?;
                store.insert_for_dataset(
                    &self.dataset_identity,
                    dir_inode,
                    b"..",
                    parent_inode,
                    0,
                    KIND_DIR,
                )?;
            }
        }
        Ok(())
    }

    fn remove_delegated_dir_entry(&self, parent: Inode, name: &[u8]) -> Result<(), NamespaceError> {
        if let Some(store) = self.delegated_dir_store() {
            store.remove_for_dataset(&self.dataset_identity, parent, name)?;
        }
        Ok(())
    }

    fn swap_delegated_dir_entries(
        &self,
        src_parent: Inode,
        src_name: &[u8],
        dst_parent: Inode,
        dst_name: &[u8],
        mode: SwapMode,
    ) -> Result<(), NamespaceError> {
        if let Some(store) = self.delegated_dir_store() {
            let mode = match mode {
                SwapMode::Rename => PersistentSwapMode::Rename,
                SwapMode::NoReplace => PersistentSwapMode::NoReplace,
                SwapMode::Exchange => PersistentSwapMode::Exchange,
            };
            store.atomic_swap_for_dataset(
                &self.dataset_identity,
                src_parent,
                src_name,
                dst_parent,
                dst_name,
                mode,
            )?;
        }
        Ok(())
    }

    /// Load a namespace from the object store.
    #[cfg(feature = "persistent-dir-index")]
    pub fn load(
        store: &tidefs_dir_index::tidefs_local_object_store::LocalObjectStore,
    ) -> Result<Self, NamespaceError> {
        use tidefs_dir_index::format;

        let manifest_key = format::namespace_manifest_key();
        let manifest_raw = store
            .get(manifest_key)
            .map_err(|_| NamespaceError::NotFound)?;

        let dir_inodes: Vec<u64> = match &manifest_raw {
            Some(bytes) if bytes.len() >= 8 => {
                if bytes[0..4] != format::NS_MANIFEST_MAGIC {
                    return Err(NamespaceError::NotFound);
                }
                let count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
                let mut inodes = Vec::with_capacity(count);
                let mut pos = 8;
                for _ in 0..count {
                    if pos + 8 > bytes.len() {
                        break;
                    }
                    let ino = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                    inodes.push(ino);
                    pos += 8;
                }
                inodes
            }
            _ => return Err(NamespaceError::NotFound),
        };

        if dir_inodes.is_empty() {
            return Err(NamespaceError::NotFound);
        }

        let inode_table = Arc::new(MemInodeTable::new());
        inode_table.insert_loaded_attrs(InodeAttributes::new_dir(ROOT_INODE));
        let policy = DatasetDirPolicy::DEFAULT;
        let dirs = HashMap::new();
        let manifest_dirs = dir_inodes.iter().copied().collect::<HashSet<_>>();

        if !manifest_dirs.contains(&ROOT_INODE) {
            return Err(NamespaceError::NotFound);
        }

        for &dir_ino in &dir_inodes {
            let found_pages = PersistentDirIndex::for_each_in_store(store, dir_ino, |entry| {
                Self::record_loaded_dir_entry(&inode_table, &entry);
            })
            .map_err(|_| NamespaceError::NotFound)?;

            if dir_ino == ROOT_INODE && !found_pages {
                return Err(NamespaceError::NotFound);
            }
        }

        Ok(Namespace {
            persistent_inodes: None,
            persistent_dirs: None,
            persistent_dirs_shared: false,
            inode_table,
            dirs: Arc::new(RwLock::new(dirs)),
            symlink_targets: RwLock::new(HashMap::new()),
            orphan_index: RwLock::new(OrphanIndex::new()),
            persistent_object_store_root: Some(store.root().to_path_buf()),
            persistent_manifest_dirs: RwLock::new(manifest_dirs),
            policy,
            dataset_identity: NamespaceDatasetIdentity::default(),
        })
    }

    #[cfg(feature = "persistent-dir-index")]
    fn ensure_persistent_dir_loaded(&self, dir_ino: Inode) -> Result<bool, NamespaceError> {
        if self.dirs.read().unwrap().contains_key(&dir_ino) {
            return Ok(true);
        }
        if !self
            .persistent_manifest_dirs
            .read()
            .unwrap()
            .contains(&dir_ino)
        {
            return Ok(false);
        }

        let Some(root) = self.persistent_object_store_root.clone() else {
            return Ok(false);
        };
        let Some(store) = tidefs_dir_index::tidefs_local_object_store::LocalObjectStore::open_read_only_with_options(
            &root,
            tidefs_dir_index::tidefs_local_object_store::StoreOptions::default(),
        )
        .map_err(|_| NamespaceError::NotFound)? else {
            return Ok(false);
        };
        let Some(dir) = PersistentDirIndex::load(&store, dir_ino, self.policy)
            .map_err(|_| NamespaceError::NotFound)?
        else {
            return Ok(false);
        };

        self.dirs.write().unwrap().entry(dir_ino).or_insert(dir);
        Ok(true)
    }

    #[cfg(feature = "persistent-dir-index")]
    fn open_persistent_dir_store_read_only(
        &self,
    ) -> Result<Option<tidefs_dir_index::tidefs_local_object_store::LocalObjectStore>, NamespaceError>
    {
        let Some(root) = self.persistent_object_store_root.clone() else {
            return Ok(None);
        };
        tidefs_dir_index::tidefs_local_object_store::LocalObjectStore::open_read_only_with_options(
            &root,
            tidefs_dir_index::tidefs_local_object_store::StoreOptions::default(),
        )
        .map_err(|_| NamespaceError::NotFound)
    }

    #[cfg(feature = "persistent-dir-index")]
    fn lookup_persistent_dir_entry_in_store(
        &self,
        dir_ino: Inode,
        name: &[u8],
    ) -> Result<Option<DirMicroEntry>, NamespaceError> {
        if !self
            .persistent_manifest_dirs
            .read()
            .unwrap()
            .contains(&dir_ino)
        {
            return Ok(None);
        }

        let Some(store) = self.open_persistent_dir_store_read_only()? else {
            return Ok(None);
        };
        PersistentDirIndex::lookup_in_store(&store, dir_ino, name)
            .map_err(|_| NamespaceError::NotFound)
    }

    #[cfg(feature = "persistent-dir-index")]
    fn list_persistent_dir_entries_in_store(
        &self,
        dir_ino: Inode,
        cookie: tidefs_dir_index::DirCookie,
    ) -> Result<
        Option<(
            Vec<tidefs_types_polymorphic_directory_index_core::DirMicroEntry>,
            tidefs_dir_index::DirCookie,
        )>,
        NamespaceError,
    > {
        if !self
            .persistent_manifest_dirs
            .read()
            .unwrap()
            .contains(&dir_ino)
        {
            return Ok(None);
        }

        let Some(store) = self.open_persistent_dir_store_read_only()? else {
            return Ok(None);
        };
        PersistentDirIndex::list_from_store(&store, dir_ino, cookie)
            .map(Some)
            .map_err(|e| match e {
                tidefs_dir_index::persistent::DirListError::StaleCursor => {
                    NamespaceError::StaleCursor
                }
                tidefs_dir_index::persistent::DirListError::Store(_) => NamespaceError::NotFound,
            })
    }

    #[cfg(feature = "persistent-dir-index")]
    fn persistent_dir_entry_count_in_store(
        &self,
        dir_ino: Inode,
        max_entries: usize,
    ) -> Result<Option<usize>, NamespaceError> {
        if !self
            .persistent_manifest_dirs
            .read()
            .unwrap()
            .contains(&dir_ino)
        {
            return Ok(None);
        }

        let Some(store) = self.open_persistent_dir_store_read_only()? else {
            return Ok(None);
        };
        PersistentDirIndex::entry_count_in_store(&store, dir_ino, max_entries)
            .map_err(|_| NamespaceError::NotFound)
    }

    fn lookup_dir_entry(
        &self,
        parent: Inode,
        name: &[u8],
        missing_parent: NamespaceError,
    ) -> Result<Option<DirMicroEntry>, NamespaceError> {
        #[cfg(feature = "persistent-dir-index")]
        {
            if let Some(entry) = {
                let dirs = self.dirs.read().unwrap();
                dirs.get(&parent).and_then(|dir| dir.lookup(name))
            } {
                return Ok(Some(entry));
            }
            if self
                .persistent_manifest_dirs
                .read()
                .unwrap()
                .contains(&parent)
            {
                return self.lookup_persistent_dir_entry_in_store(parent, name);
            }
        }

        if self.delegated_dir_store().is_some() && !self.dirs.read().unwrap().contains_key(&parent)
        {
            match self.ensure_delegated_dir_loaded(parent) {
                Ok(_) => {}
                Err(NamespaceError::InodeNotFound | NamespaceError::NotFound) => {
                    return if self.get_inode_attrs_delegate(parent).is_some() {
                        Err(NamespaceError::NotDirectory)
                    } else {
                        Err(missing_parent)
                    };
                }
                Err(e) => return Err(e),
            }
        }

        let dirs = self.dirs.read().unwrap();
        let dir = dirs.get(&parent).ok_or_else(|| {
            if self.get_inode_attrs_delegate(parent).is_some() {
                NamespaceError::NotDirectory
            } else {
                missing_parent
            }
        })?;
        Ok(dir.lookup(name))
    }

    fn directory_is_self_or_descendant(
        &self,
        ancestor: Inode,
        candidate: Inode,
    ) -> Result<bool, NamespaceError> {
        let mut current = candidate;
        let mut visited = HashSet::new();

        loop {
            if current == ancestor {
                return Ok(true);
            }
            if !visited.insert(current) {
                return Err(NamespaceError::RenameCycle);
            }

            let parent = self
                .lookup_dir_entry(current, b"..", NamespaceError::InodeNotFound)?
                .ok_or(NamespaceError::InodeNotFound)?;
            let parent_inode = parent.inode_id;

            if parent_inode == current {
                return Ok(false);
            }

            current = parent_inode;
        }
    }

    #[cfg(feature = "persistent-dir-index")]
    fn record_loaded_dir_entry(inode_table: &MemInodeTable, entry: &DirMicroEntry) {
        if entry.inode_id == 0 {
            return;
        }
        let attrs = match entry.kind {
            KIND_DIR => InodeAttributes::new_dir(entry.inode_id),
            KIND_SYMLINK => InodeAttributes::new_symlink(entry.inode_id, 0),
            _ => InodeAttributes::new_file(entry.inode_id),
        };
        inode_table.insert_loaded_attrs(attrs);
    }

    /// Persist all directory indexes and the namespace manifest.
    #[cfg(feature = "persistent-dir-index")]
    pub fn flush(
        &self,
        store: &mut tidefs_dir_index::tidefs_local_object_store::LocalObjectStore,
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("flush persistent namespace")?;
        use tidefs_dir_index::format;

        let mut dir_set = self.persistent_manifest_dirs.read().unwrap().clone();

        {
            let mut dirs = self.dirs.write().unwrap();
            dir_set.extend(dirs.keys().copied());

            let mut loaded_dir_inodes = dirs.keys().copied().collect::<Vec<_>>();
            loaded_dir_inodes.sort();
            for dir_ino in loaded_dir_inodes {
                if let Some(dir) = dirs.get_mut(&dir_ino) {
                    dir.flush(store).map_err(|_| NamespaceError::NotFound)?;
                }
            }
        }

        let mut dir_inodes = dir_set.iter().copied().collect::<Vec<_>>();
        dir_inodes.sort();

        let mut manifest = Vec::with_capacity(8 + dir_inodes.len() * 8);
        manifest.extend_from_slice(&format::NS_MANIFEST_MAGIC);
        manifest.extend_from_slice(&(dir_inodes.len() as u32).to_le_bytes());
        for &ino in &dir_inodes {
            manifest.extend_from_slice(&ino.to_le_bytes());
        }

        let manifest_key = format::namespace_manifest_key();
        store
            .put(manifest_key, &manifest)
            .map_err(|_| NamespaceError::NotFound)?;
        store.sync_all().map_err(|_| NamespaceError::NotFound)?;
        *self.persistent_manifest_dirs.write().unwrap() = dir_set;

        Ok(())
    }

    /// Access the inode table.
    #[must_use]
    pub fn inode_table(&self) -> &MemInodeTable {
        &self.inode_table
    }

    /// Returns the dataset directory policy.
    #[must_use]
    pub fn policy(&self) -> DatasetDirPolicy {
        self.policy
    }

    /// Return the dataset identity boundary used by persistent stores.
    #[must_use]
    pub fn dataset_identity(&self) -> &NamespaceDatasetIdentity {
        &self.dataset_identity
    }

    // ------------------------------------------------------------------
    // Path resolution
    // ------------------------------------------------------------------

    /// Resolve `path` to an inode by walking directory entries component
    /// by component.
    ///
    /// - The empty path and `/` both resolve to the root inode (1).
    /// - `.` is a no-op.
    /// - `..` walks to the parent via the directory index's `..` entry.
    /// - Symlinks are expanded with a bounded loop guard.
    pub fn resolve(&self, path: &Path) -> Result<Inode, NamespaceError> {
        self.resolve_steps(path_steps(path)?)
    }

    fn resolve_steps(&self, mut pending: VecDeque<PathStep>) -> Result<Inode, NamespaceError> {
        let mut current: Inode = ROOT_INODE;
        let mut symlink_depth = 0;

        while let Some(step) = pending.pop_front() {
            match step {
                PathStep::Root => current = ROOT_INODE,
                PathStep::Cur => {}
                PathStep::Parent => {
                    current = self.resolve_component(current, b"..")?.0;
                }
                PathStep::Normal(name) => {
                    let (inode, entry_type) = self.resolve_component(current, &name)?;
                    match entry_type {
                        EntryType::Directory
                        | EntryType::File
                        | EntryType::Fifo
                        | EntryType::CharacterDevice
                        | EntryType::BlockDevice
                        | EntryType::Socket => current = inode,
                        EntryType::Symlink => {
                            symlink_depth += 1;
                            if symlink_depth > MAX_SYMLINK_DEPTH {
                                return Err(NamespaceError::TooManySymlinks);
                            }
                            let mut target_steps = symlink_target_steps(&self.readlink(inode)?)?;
                            while let Some(target_step) = target_steps.pop_back() {
                                pending.push_front(target_step);
                            }
                        }
                    }
                }
            }
        }

        Ok(current)
    }

    /// Resolve a path's parent directory and return its final component.
    ///
    /// This follows symlinks while walking the parent path, but does not follow
    /// or look up the final component. The returned name is validated as a
    /// mutating directory-entry basename.
    pub fn resolve_parent(&self, path: &Path) -> Result<ResolvedParent, NamespaceError> {
        let mut steps = path_steps(path)?;
        let name = match steps.pop_back() {
            Some(PathStep::Normal(name)) => name,
            _ => return Err(NamespaceError::InvalidName),
        };
        validate_name(&name, true)?;

        let parent = self.resolve_steps(steps)?;
        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        if !self.dirs.read().unwrap().contains_key(&parent) {
            return Err(NamespaceError::NotDirectory);
        }

        Ok(ResolvedParent { parent, name })
    }

    /// Resolve a single component relative to `parent`.
    fn resolve_component(
        &self,
        parent: Inode,
        name: &[u8],
    ) -> Result<(Inode, EntryType), NamespaceError> {
        let entry = self
            .lookup_dir_entry(parent, name, NamespaceError::NotFound)?
            .ok_or(NamespaceError::NotFound)?;
        let entry_type = EntryType::from_kind(entry.kind).ok_or(NamespaceError::NotSupported)?;
        Ok((entry.inode_id, entry_type))
    }

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /// Look up `name` in directory `parent`.
    ///
    /// Returns `Ok(Some(inode))` when found, `Ok(None)` when not found,
    /// or an error if `parent` is not a directory.
    pub fn lookup(&self, parent: Inode, name: &str) -> Result<Option<Inode>, NamespaceError> {
        validate_name(name.as_bytes(), false)?;

        Ok(self
            .lookup_dir_entry(parent, name.as_bytes(), NamespaceError::InodeNotFound)?
            .map(|entry| entry.inode_id))
    }

    // ------------------------------------------------------------------
    // Create file
    // ------------------------------------------------------------------

    /// Create a regular file named `name` in directory `parent`.
    pub fn create_file(
        &self,
        parent: Inode,
        name: &str,
        attrs: InodeAttributes,
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace file")?;
        validate_name(name.as_bytes(), true)?;

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        let _ = self.ensure_delegated_dir_loaded(parent)?;
        // Allocate the new inode.
        let (ino, generation) = self.alloc_inode_delegate(attrs)?;

        // Insert into parent's directory index.
        {
            let mut dirs = self.dirs.write().unwrap();
            let dir = dirs.get_mut(&parent).ok_or_else(|| {
                // Rollback inode allocation.
                let _ = self.free_inode_delegate(ino);
                NamespaceError::InodeNotFound
            })?;

            if let Err(e) = dir.insert(name.as_bytes(), ino, generation, KIND_FILE) {
                // Rollback.
                let _ = self.free_inode_delegate(ino);
                return Err(e.into());
            }
        }

        if let Err(e) =
            self.insert_delegated_dir_entry(parent, name.as_bytes(), ino, generation, KIND_FILE)
        {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&parent) {
                let _ = dir.delete(name.as_bytes());
            }
            let _ = self.free_inode_delegate(ino);
            return Err(e);
        }

        Ok(ino)
    }

    // ------------------------------------------------------------------
    // Create symlink
    // ------------------------------------------------------------------

    /// Create a symbolic link named `name` in directory `parent`.
    pub fn create_symlink(
        &self,
        parent: Inode,
        name: &str,
        target: &[u8],
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace symbolic link")?;
        validate_name(name.as_bytes(), true)?;
        if target.is_empty() {
            return Err(NamespaceError::InvalidName);
        }

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        let _ = self.ensure_delegated_dir_loaded(parent)?;
        let (ino, generation) =
            self.alloc_inode_delegate(InodeAttributes::new_symlink(0, target.len() as u64))?;

        {
            let mut dirs = self.dirs.write().unwrap();
            let dir = dirs.get_mut(&parent).ok_or_else(|| {
                let _ = self.free_inode_delegate(ino);
                NamespaceError::InodeNotFound
            })?;

            if let Err(e) = dir.insert(name.as_bytes(), ino, generation, KIND_SYMLINK) {
                let _ = self.free_inode_delegate(ino);
                return Err(e.into());
            }
        }

        if let Err(e) =
            self.insert_delegated_dir_entry(parent, name.as_bytes(), ino, generation, KIND_SYMLINK)
        {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&parent) {
                let _ = dir.delete(name.as_bytes());
            }
            let _ = self.free_inode_delegate(ino);
            return Err(e);
        }

        self.symlink_targets
            .write()
            .unwrap()
            .insert(ino, target.to_vec());

        Ok(ino)
    }

    // ------------------------------------------------------------------
    // Orphan index / O_TMPFILE integration
    // ------------------------------------------------------------------

    /// Track an anonymous O_TMPFILE inode in the orphan index.
    ///
    /// Called when `open(O_TMPFILE)` creates an inode with nlink==0.
    /// The entry is stored with the O_TMPFILE flag and the creating
    /// process PID so the timeout reaper can clean up if the process
    /// exits without linking.
    pub fn track_anonymous_inode(
        &self,
        inode_id: u64,
        generation: u64,
        creating_pid: u32,
        txg: u64,
    ) -> Result<bool, NamespaceError> {
        self.ensure_mutation_allowed("track anonymous namespace inode")?;
        Ok(self.orphan_index.write().unwrap().insert_tmpfile(
            inode_id,
            generation,
            creating_pid,
            txg,
        ))
    }

    /// Remove an inode from the orphan index when it is linked into
    /// the namespace.
    ///
    /// Called when a previously-anonymous O_TMPFILE inode receives a
    /// directory entry via `linkat`, making nlink==1. The inode is
    /// no longer orphaned.
    ///
    /// Returns `true` if the inode was in the orphan index and removed.
    pub fn on_orphan_link(&self, inode_id: u64, txg: u64) -> Result<bool, NamespaceError> {
        self.ensure_mutation_allowed("link anonymous namespace inode")?;
        Ok(self
            .orphan_index
            .write()
            .unwrap()
            .remove_on_link(inode_id, txg))
    }

    /// Scan the orphan index for O_TMPFILE entries whose creating
    /// process has exited.
    ///
    /// Returns the list of inode IDs that should be reaped. The caller
    /// is responsible for reclaiming the extents and removing the entry
    /// from the index.
    #[must_use]
    pub fn reap_tmpfile_timeouts(&self) -> Vec<u64> {
        self.orphan_index.read().unwrap().tmpfile_timeout_reap()
    }

    /// Return the number of entries in the orphan index.
    #[must_use]
    pub fn orphan_count(&self) -> usize {
        self.orphan_index.read().unwrap().len()
    }

    /// Return the byte-preserved target for a symbolic link inode.
    pub fn readlink(&self, inode: Inode) -> Result<Vec<u8>, NamespaceError> {
        if let Some(target) = self.symlink_targets.read().unwrap().get(&inode) {
            return Ok(target.clone());
        }

        if self.get_inode_attrs_delegate(inode).is_some() {
            Err(NamespaceError::NotSymlink)
        } else {
            Err(NamespaceError::InodeNotFound)
        }
    }

    /// Return the byte-preserved target for a symbolic link entry in a directory.
    ///
    /// The named entry is inspected directly and is not followed during lookup.
    pub fn readlink_at(&self, parent: Inode, name: &str) -> Result<Vec<u8>, NamespaceError> {
        validate_name(name.as_bytes(), true)?;

        let entry = self
            .lookup_dir_entry(parent, name.as_bytes(), NamespaceError::InodeNotFound)?
            .ok_or(NamespaceError::NotFound)?;
        let inode = entry.inode_id;
        let entry_type = EntryType::from_kind(entry.kind).ok_or(NamespaceError::NotSupported)?;

        if entry_type != EntryType::Symlink {
            return Err(NamespaceError::NotSymlink);
        }

        self.readlink(inode)
    }

    // ------------------------------------------------------------------
    // Create hard link
    // ------------------------------------------------------------------

    /// Create a new directory entry for an existing non-directory inode.
    pub fn create_hard_link(
        &self,
        old_parent: Inode,
        old_name: &str,
        new_parent: Inode,
        new_name: &str,
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace hard link")?;
        validate_name(old_name.as_bytes(), true)?;
        validate_name(new_name.as_bytes(), true)?;

        #[cfg(feature = "persistent-dir-index")]
        {
            let _ = self.ensure_persistent_dir_loaded(old_parent)?;
            let _ = self.ensure_persistent_dir_loaded(new_parent)?;
        }
        let _ = self.ensure_delegated_dir_loaded(old_parent)?;
        let _ = self.ensure_delegated_dir_loaded(new_parent)?;

        let (target_inode, target_kind, target_generation, entry_kind) = {
            let dirs = self.dirs.read().unwrap();
            let old_dir = dirs.get(&old_parent).ok_or(NamespaceError::InodeNotFound)?;
            let old_entry = old_dir
                .lookup(old_name.as_bytes())
                .ok_or(NamespaceError::NotFound)?;
            let target_kind = old_entry.kind;
            let entry_kind =
                EntryType::from_kind(target_kind).ok_or(NamespaceError::NotSupported)?;
            (
                old_entry.inode_id,
                target_kind,
                old_entry.generation,
                entry_kind,
            )
        };

        if entry_kind == EntryType::Directory {
            return Err(NamespaceError::IsDirectory);
        }

        let mut attrs = self
            .get_inode_attrs_delegate(target_inode)
            .ok_or(NamespaceError::InodeNotFound)?;
        attrs.nlink = attrs
            .nlink
            .checked_add(1)
            .ok_or(NamespaceError::LinkCountOverflow)?;
        attrs.touch_ctime();

        {
            let mut dirs = self.dirs.write().unwrap();
            let new_dir = dirs
                .get_mut(&new_parent)
                .ok_or(NamespaceError::InodeNotFound)?;

            if let Err(e) = new_dir.insert(
                new_name.as_bytes(),
                target_inode,
                target_generation,
                target_kind,
            ) {
                return Err(e.into());
            }
        }

        if let Err(e) = self.insert_delegated_dir_entry(
            new_parent,
            new_name.as_bytes(),
            target_inode,
            target_generation,
            target_kind,
        ) {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&new_parent) {
                let _ = dir.delete(new_name.as_bytes());
            }
            return Err(e);
        }

        if let Err(e) = self.set_inode_attrs_delegate(target_inode, attrs) {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&new_parent) {
                let _ = dir.delete(new_name.as_bytes());
            }
            let _ = self.remove_delegated_dir_entry(new_parent, new_name.as_bytes());
            return Err(e);
        }

        Ok(target_inode)
    }

    /// Create a hard link from an existing inode (resolved by caller).
    ///
    /// Inserts `new_name` into `new_parent`'s directory index pointing to
    /// `target_inode` and increments the target's link count.
    /// Directories cannot be hard-linked (POSIX).
    pub fn create_hard_link_by_inode(
        &self,
        target_inode: Inode,
        new_parent: Inode,
        new_name: &str,
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace hard link by inode")?;
        validate_name(new_name.as_bytes(), true)?;

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(new_parent)?;
        let _ = self.ensure_delegated_dir_loaded(new_parent)?;
        // Verify target exists and is not a directory.
        let target_attrs = self
            .get_inode_attrs_delegate(target_inode)
            .ok_or(NamespaceError::InodeNotFound)?;
        let target_kind = EntryType::from_kind(match target_attrs.mode & 0o170000 {
            0o040000 => KIND_DIR,
            0o120000 => KIND_SYMLINK,
            _ => KIND_FILE,
        })
        .unwrap_or(EntryType::File);

        if target_kind == EntryType::Directory {
            return Err(NamespaceError::IsDirectory);
        }

        // Use generation 0 (caller is responsible for correctness).
        let target_generation: u64 = 0;

        let mut attrs = self
            .get_inode_attrs_delegate(target_inode)
            .ok_or(NamespaceError::InodeNotFound)?;
        attrs.nlink = attrs
            .nlink
            .checked_add(1)
            .ok_or(NamespaceError::LinkCountOverflow)?;
        attrs.touch_ctime();

        let target_kind_u32 = target_kind.to_kind();
        {
            let mut dirs = self.dirs.write().unwrap();
            let new_dir = dirs
                .get_mut(&new_parent)
                .ok_or(NamespaceError::InodeNotFound)?;

            if let Err(e) = new_dir.insert(
                new_name.as_bytes(),
                target_inode,
                target_generation,
                target_kind_u32,
            ) {
                return Err(e.into());
            }
        }

        if let Err(e) = self.insert_delegated_dir_entry(
            new_parent,
            new_name.as_bytes(),
            target_inode,
            target_generation,
            target_kind_u32,
        ) {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&new_parent) {
                let _ = dir.delete(new_name.as_bytes());
            }
            return Err(e);
        }

        if let Err(e) = self.set_inode_attrs_delegate(target_inode, attrs) {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&new_parent) {
                let _ = dir.delete(new_name.as_bytes());
            }
            let _ = self.remove_delegated_dir_entry(new_parent, new_name.as_bytes());
            return Err(e);
        }

        Ok(target_inode)
    }

    /// Create a special file node (pipe, block/char device, or socket).
    /// Create a special file node (pipe, block/char device, or socket).
    ///
    /// Allocates a new inode with the given `mode` and `rdev`, inserts
    /// `name` into `parent`'s directory index.  The device number is
    /// stored in the inode attributes (later retrieval via getattr).
    pub fn mknod(
        &self,
        parent: Inode,
        name: &str,
        mode: u32,
        rdev: u32,
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace special inode")?;
        validate_name(name.as_bytes(), true)?;

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        let _ = self.ensure_delegated_dir_loaded(parent)?;
        let file_type = mode & 0o170000;

        let attrs = InodeAttributes {
            inode: 0, // allocated below
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: 1,
            atime: std::time::SystemTime::now(),
            mtime: std::time::SystemTime::now(),
            ctime: std::time::SystemTime::now(),
            rdev,
        };

        let (ino, generation) = self.alloc_inode_delegate(attrs)?;

        // Map mode to directory index entry kind.
        let kind = match file_type {
            0o040000 => KIND_DIR,
            0o120000 => KIND_SYMLINK,
            0o010000 => KIND_FIFO,
            0o140000 => KIND_SOCKET,
            0o060000 => KIND_BLOCK,
            0o020000 => KIND_CHAR,
            _ => KIND_FILE,
        };

        // Insert into parent directory.
        {
            let mut dirs = self.dirs.write().unwrap();
            let parent_dir = dirs.get_mut(&parent).ok_or_else(|| {
                let _ = self.free_inode_delegate(ino);
                NamespaceError::InodeNotFound
            })?;

            if let Err(e) = parent_dir.insert(name.as_bytes(), ino, generation, kind) {
                let _ = self.free_inode_delegate(ino);
                return Err(e.into());
            }
        }

        if let Err(e) =
            self.insert_delegated_dir_entry(parent, name.as_bytes(), ino, generation, kind)
        {
            if let Some(dir) = self.dirs.write().unwrap().get_mut(&parent) {
                let _ = dir.delete(name.as_bytes());
            }
            let _ = self.free_inode_delegate(ino);
            return Err(e);
        }

        Ok(ino)
    }
    fn remove_link_to_inode(
        &self,
        inode: Inode,
        entry_kind: EntryType,
    ) -> Result<(), NamespaceError> {
        let attrs = self
            .get_inode_attrs_delegate(inode)
            .ok_or(NamespaceError::InodeNotFound)?;

        if entry_kind != EntryType::Directory && attrs.nlink > 1 {
            let mut attrs = attrs;
            attrs.nlink -= 1;
            attrs.touch_ctime();
            return self.set_inode_attrs_delegate(inode, attrs);
        }

        if entry_kind == EntryType::Symlink {
            self.symlink_targets.write().unwrap().remove(&inode);
        }
        #[cfg(feature = "persistent-dir-index")]
        if entry_kind == EntryType::Directory {
            self.persistent_manifest_dirs
                .write()
                .unwrap()
                .remove(&inode);
        }
        self.free_inode_delegate(inode)
    }

    // ------------------------------------------------------------------
    // Create directory
    // ------------------------------------------------------------------

    /// Create a subdirectory named `name` in directory `parent`.
    pub fn create_dir(
        &self,
        parent: Inode,
        name: &str,
        attrs: InodeAttributes,
    ) -> Result<Inode, NamespaceError> {
        self.ensure_mutation_allowed("create namespace directory")?;
        validate_name(name.as_bytes(), true)?;

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        let _ = self.ensure_delegated_dir_loaded(parent)?;
        // Allocate the new inode.
        let (ino, generation) = self.alloc_inode_delegate(attrs)?;

        // Create the new directory's index with . and .. entries.
        let mut child_dir = DirBackend::new(ino, self.policy);
        child_dir
            .insert(b".", ino, generation, KIND_DIR)
            .expect("self . insert");
        child_dir
            .insert(b"..", parent, 0, KIND_DIR)
            .expect("parent .. insert");

        // Insert into parent's directory index.
        {
            let mut dirs = self.dirs.write().unwrap();
            let parent_dir = dirs.get_mut(&parent).ok_or_else(|| {
                let _ = self.free_inode_delegate(ino);
                NamespaceError::InodeNotFound
            })?;

            if let Err(e) = parent_dir.insert(name.as_bytes(), ino, generation, KIND_DIR) {
                let _ = self.free_inode_delegate(ino);
                return Err(e.into());
            }

            parent_dir.set_has_subdirs(true);

            // Store the child directory index.
            dirs.insert(ino, child_dir);
        }

        if let Err(e) =
            self.insert_delegated_dir_entry(parent, name.as_bytes(), ino, generation, KIND_DIR)
        {
            let mut dirs = self.dirs.write().unwrap();
            if let Some(parent_dir) = dirs.get_mut(&parent) {
                let _ = parent_dir.delete(name.as_bytes());
            }
            dirs.remove(&ino);
            let _ = self.free_inode_delegate(ino);
            return Err(e);
        }

        if let Err(e) = self.init_delegated_dir(ino, parent) {
            let _ = self.remove_delegated_dir_entry(parent, name.as_bytes());
            let mut dirs = self.dirs.write().unwrap();
            if let Some(parent_dir) = dirs.get_mut(&parent) {
                let _ = parent_dir.delete(name.as_bytes());
            }
            dirs.remove(&ino);
            let _ = self.free_inode_delegate(ino);
            return Err(e);
        }

        Ok(ino)
    }

    // ------------------------------------------------------------------
    // Unlink
    // ------------------------------------------------------------------

    /// Remove `name` from directory `parent`.
    ///
    /// - Files are unlinked and their inode freed.
    /// - Directories must be empty (only `.` and `..` entries remain)
    ///   and their inode is freed.
    /// - The root inode cannot be unlinked.
    pub fn unlink(&self, parent: Inode, name: &str) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("unlink namespace entry")?;
        validate_name(name.as_bytes(), true)?;

        if parent == ROOT_INODE && (name.as_bytes() == b"." || name.as_bytes() == b"..") {
            return Err(NamespaceError::InvalidName);
        }

        #[cfg(feature = "persistent-dir-index")]
        let _ = self.ensure_persistent_dir_loaded(parent)?;
        let _ = self.ensure_delegated_dir_loaded(parent)?;
        // Phase 1: look up the entry and collect needed info (read lock).
        let (target_inode, entry_kind) = {
            let dirs = self.dirs.read().unwrap();
            let parent_dir = dirs.get(&parent).ok_or(NamespaceError::InodeNotFound)?;
            let entry = parent_dir
                .lookup(name.as_bytes())
                .ok_or(NamespaceError::NotFound)?;
            (
                entry.inode_id,
                EntryType::from_kind(entry.kind).ok_or(NamespaceError::NotSupported)?,
            )
        };

        // Phase 2: check directory-empty constraint and remove child dir index.
        if entry_kind == EntryType::Directory {
            #[cfg(feature = "persistent-dir-index")]
            let _ = self.ensure_persistent_dir_loaded(target_inode)?;
            let _ = self.ensure_delegated_dir_loaded(target_inode)?;
            {
                let dirs = self.dirs.read().unwrap();
                if let Some(child_dir) = dirs.get(&target_inode) {
                    // A directory is empty if it only has '.' and '..'.
                    if child_dir.len() > 2 {
                        return Err(NamespaceError::NotEmpty);
                    }
                }
            }
            self.dirs.write().unwrap().remove(&target_inode);
        }

        // Phase 3: remove entry from parent directory (write lock).
        {
            let mut dirs = self.dirs.write().unwrap();
            let parent_dir = dirs.get_mut(&parent).ok_or(NamespaceError::InodeNotFound)?;

            parent_dir.delete(name.as_bytes())?;

            // If we removed the last subdirectory, clear the flag.
            if entry_kind == EntryType::Directory {
                let has_any_subdirs = parent_dir.len() > 2;
                if !has_any_subdirs {
                    parent_dir.set_has_subdirs(false);
                }
            }
        }

        self.remove_delegated_dir_entry(parent, name.as_bytes())?;

        self.remove_link_to_inode(target_inode, entry_kind)?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Rename
    // ------------------------------------------------------------------

    /// Rename (or move) an entry from `old_parent`/`old_name` to
    /// `new_parent`/`new_name`.
    ///
    /// If the target already exists:
    /// - A file target is replaced (its inode is freed).
    /// - A directory target must be empty; it is then replaced.
    pub fn rename(
        &self,
        old_parent: Inode,
        old_name: &str,
        new_parent: Inode,
        new_name: &str,
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("rename namespace entry")?;
        self.rename_with_flags(old_parent, old_name, new_parent, new_name, 0)
    }

    /// Rename (or move) an entry using POSIX rename flags.
    ///
    /// Supports [`RENAME_NOREPLACE`] and [`RENAME_EXCHANGE`].
    pub fn rename_with_flags(
        &self,
        old_parent: Inode,
        old_name: &str,
        new_parent: Inode,
        new_name: &str,
        flags: u32,
    ) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("rename namespace entry with flags")?;
        validate_name(old_name.as_bytes(), true)?;
        validate_name(new_name.as_bytes(), true)?;

        if old_parent == new_parent && old_name == new_name {
            return Ok(());
        }

        #[cfg(feature = "persistent-dir-index")]
        {
            let _ = self.ensure_persistent_dir_loaded(old_parent)?;
            let _ = self.ensure_persistent_dir_loaded(new_parent)?;
        }
        let _ = self.ensure_delegated_dir_loaded(old_parent)?;
        let _ = self.ensure_delegated_dir_loaded(new_parent)?;
        // ── Pre-validation under read lock ─────────────────────────
        let (target_inode, target_kind, target_gen, target_entry_kind, existing, existing_target) = {
            let dirs = self.dirs.read().unwrap();

            let old_dir = dirs.get(&old_parent).ok_or(NamespaceError::InodeNotFound)?;
            let old_entry = old_dir
                .lookup(old_name.as_bytes())
                .ok_or(NamespaceError::NotFound)?;

            let target_inode = old_entry.inode_id;
            let target_kind = old_entry.kind;
            let target_gen = old_entry.generation;
            let target_entry_kind =
                EntryType::from_kind(target_kind).ok_or(NamespaceError::NotSupported)?;

            if !dirs.contains_key(&new_parent) {
                return Err(NamespaceError::InodeNotFound);
            }

            let new_dir = dirs.get(&new_parent).unwrap();
            let existing = new_dir.lookup(new_name.as_bytes());

            let existing_target = if let Some(existing) = existing.as_ref() {
                let existing_kind =
                    EntryType::from_kind(existing.kind).ok_or(NamespaceError::NotSupported)?;
                let directory_entry_count = if existing_kind.is_dir() {
                    dirs.get(&existing.inode_id).map(|dir| dir.len())
                } else {
                    None
                };
                Some(RenameExistingTarget {
                    inode: existing.inode_id,
                    entry_type: existing_kind,
                    directory_entry_count,
                })
            } else {
                None
            };

            (
                target_inode,
                target_kind,
                target_gen,
                target_entry_kind,
                existing,
                existing_target,
            )
        };

        #[cfg(feature = "persistent-dir-index")]
        let mut existing_target = existing_target;

        // ── Flag plan (fail-fast before mutation) ──────────────────
        let flag_plan = plan_rename_flags(flags, existing.is_some())?;

        #[cfg(feature = "persistent-dir-index")]
        {
            if target_entry_kind.is_dir() {
                let _ = self.ensure_persistent_dir_loaded(target_inode)?;
            }
            if let Some(target) = existing_target.as_mut() {
                if target.entry_type.is_dir() {
                    if flag_plan.mode == RenameMode::Exchange {
                        let _ = self.ensure_persistent_dir_loaded(target.inode)?;
                        target.directory_entry_count = self
                            .dirs
                            .read()
                            .unwrap()
                            .get(&target.inode)
                            .map(|dir| dir.len());
                    } else if target.directory_entry_count.is_none() {
                        target.directory_entry_count =
                            self.persistent_dir_entry_count_in_store(target.inode, 3)?;
                    }
                }
            }
        }

        if target_entry_kind.is_dir() {
            let _ = self.ensure_delegated_dir_loaded(target_inode)?;
        }
        if let Some(target) = existing_target.as_ref() {
            if target.entry_type.is_dir() {
                let _ = self.ensure_delegated_dir_loaded(target.inode)?;
            }
        }

        // Cycle detection: source directory cannot be moved into itself
        // or a descendant.
        if target_entry_kind.is_dir()
            && self.directory_is_self_or_descendant(target_inode, new_parent)?
        {
            return Err(NamespaceError::RenameCycle);
        }

        // Target plan: applicable only to Rename/NoReplace modes.
        // Exchange allows type-mismatch and non-empty directory swaps.
        let target_plan = if flag_plan.mode != RenameMode::Exchange {
            Some(plan_rename_target(
                target_inode,
                target_entry_kind,
                existing_target,
            )?)
        } else {
            None
        };

        // ── Exchange mode ──────────────────────────────────────────
        if flag_plan.mode == RenameMode::Exchange {
            let exchange_target = existing.expect("exchange plan requires existing target");
            let exchange_target_kind =
                EntryType::from_kind(exchange_target.kind).ok_or(NamespaceError::NotSupported)?;

            // Additional cycle detection for exchange.
            if exchange_target_kind.is_dir()
                && self.directory_is_self_or_descendant(exchange_target.inode_id, old_parent)?
            {
                return Err(NamespaceError::RenameCycle);
            }

            self.swap_delegated_dir_entries(
                old_parent,
                old_name.as_bytes(),
                new_parent,
                new_name.as_bytes(),
                SwapMode::Exchange,
            )?;

            if old_parent == new_parent {
                // Same-directory exchange: swap entries in-place.
                let mut dirs = self.dirs.write().unwrap();
                let dir = dirs
                    .get_mut(&old_parent)
                    .ok_or(NamespaceError::InodeNotFound)?;
                dir.replace(
                    old_name.as_bytes(),
                    exchange_target.inode_id,
                    exchange_target.generation,
                    exchange_target.kind,
                );
                dir.replace(new_name.as_bytes(), target_inode, target_gen, target_kind);
            } else {
                // Cross-directory exchange via atomic_swap.
                let mut dirs = self.dirs.write().unwrap();
                let mut old_dir = dirs
                    .remove(&old_parent)
                    .ok_or(NamespaceError::InodeNotFound)?;
                let mut new_dir = dirs
                    .remove(&new_parent)
                    .ok_or(NamespaceError::InodeNotFound)?;
                let result = old_dir.atomic_swap(
                    old_name.as_bytes(),
                    &mut new_dir,
                    new_name.as_bytes(),
                    SwapMode::Exchange,
                );
                dirs.insert(old_parent, old_dir);
                dirs.insert(new_parent, new_dir);
                result?;
            }

            // Update ".." entries for directories.
            if target_kind == KIND_DIR {
                let mut dirs = self.dirs.write().unwrap();
                if let Some(child_dir) = dirs.get_mut(&target_inode) {
                    child_dir.replace(b"..", new_parent, 0, KIND_DIR);
                }
            }
            if exchange_target.kind == KIND_DIR {
                let mut dirs = self.dirs.write().unwrap();
                if let Some(child_dir) = dirs.get_mut(&exchange_target.inode_id) {
                    child_dir.replace(b"..", old_parent, 0, KIND_DIR);
                }
            }

            return Ok(());
        }

        // ── Same-directory rename (Rename / NoReplace) ─────────────
        if old_parent == new_parent {
            let target_plan = target_plan.expect("target_plan required for non-Exchange modes");
            let (overwritten, existing_kind, remove_directory_index) = match target_plan.action {
                RenameTargetAction::NoOpSameInode => return Ok(()),
                RenameTargetAction::DestinationAbsent => {
                    let mode = if flag_plan.mode == RenameMode::NoReplace {
                        SwapMode::NoReplace
                    } else {
                        SwapMode::Rename
                    };
                    self.swap_delegated_dir_entries(
                        old_parent,
                        old_name.as_bytes(),
                        new_parent,
                        new_name.as_bytes(),
                        mode,
                    )?;

                    let mut dirs = self.dirs.write().unwrap();
                    let dir = dirs
                        .get_mut(&old_parent)
                        .ok_or(NamespaceError::InodeNotFound)?;
                    dir.rename(old_name.as_bytes(), new_name.as_bytes())?;
                    return Ok(());
                }
                RenameTargetAction::ReplaceExisting {
                    entry_type,
                    remove_directory_index,
                } => {
                    let mut dirs = self.dirs.write().unwrap();
                    let dir = dirs
                        .get_mut(&old_parent)
                        .ok_or(NamespaceError::InodeNotFound)?;
                    self.swap_delegated_dir_entries(
                        old_parent,
                        old_name.as_bytes(),
                        new_parent,
                        new_name.as_bytes(),
                        SwapMode::Rename,
                    )?;
                    let overwritten =
                        dir.rename_overwrite(old_name.as_bytes(), new_name.as_bytes())?;
                    let victim = overwritten.expect("replacement plan must overwrite target");
                    (victim, entry_type, remove_directory_index)
                }
            };

            if remove_directory_index {
                let mut dirs = self.dirs.write().unwrap();
                dirs.remove(&overwritten.inode_id);
            }
            self.remove_link_to_inode(overwritten.inode_id, existing_kind)?;

            return Ok(());
        }

        // ── Cross-directory rename (Rename / NoReplace) ────────────
        let mode = if flag_plan.mode == RenameMode::NoReplace {
            SwapMode::NoReplace
        } else {
            SwapMode::Rename
        };

        self.swap_delegated_dir_entries(
            old_parent,
            old_name.as_bytes(),
            new_parent,
            new_name.as_bytes(),
            mode,
        )?;

        let overwritten = {
            let mut dirs = self.dirs.write().unwrap();
            let mut old_dir = dirs
                .remove(&old_parent)
                .ok_or(NamespaceError::InodeNotFound)?;
            let mut new_dir = dirs
                .remove(&new_parent)
                .ok_or(NamespaceError::InodeNotFound)?;
            let result =
                old_dir.atomic_swap(old_name.as_bytes(), &mut new_dir, new_name.as_bytes(), mode);
            dirs.insert(old_parent, old_dir);
            dirs.insert(new_parent, new_dir);
            result?
        };

        // Handle overwritten entry (nlink decrement, inode cleanup).
        if let Some(victim) = overwritten {
            let target_plan = target_plan.expect("target_plan required for non-Exchange modes");
            let (existing_kind, remove_directory_index) = match target_plan.action {
                RenameTargetAction::ReplaceExisting {
                    entry_type,
                    remove_directory_index,
                } => (entry_type, remove_directory_index),
                _ => unreachable!("overwritten entry requires ReplaceExisting plan"),
            };

            if remove_directory_index {
                let mut dirs = self.dirs.write().unwrap();
                dirs.remove(&victim.inode_id);
            }
            self.remove_link_to_inode(victim.inode_id, existing_kind)?;
        }

        // If we moved a directory, update its ".." entry.
        if target_kind == KIND_DIR {
            let mut dirs = self.dirs.write().unwrap();
            if let Some(child_dir) = dirs.get_mut(&target_inode) {
                child_dir.replace(b"..", new_parent, 0, KIND_DIR);
            }
        }

        Ok(())
    }

    // Accessors
    // ------------------------------------------------------------------

    /// Get attributes for an inode.
    #[must_use]
    pub fn get_attrs(&self, inode: Inode) -> Option<InodeAttributes> {
        self.get_inode_attrs_delegate(inode)
    }

    /// Update attributes for an inode.
    pub fn update_attrs(&self, inode: Inode, attrs: InodeAttributes) -> Result<(), NamespaceError> {
        self.ensure_mutation_allowed("update namespace inode attributes")?;
        self.set_inode_attrs_delegate(inode, attrs)
    }

    // ── Internal helper for read_dir ───────────────────────────────────

    /// Collect a page of entries from a directory backend starting at
    /// the position encoded in `cookie`.  Returns the entries and the
    /// next cookie for pagination.
    #[cfg(feature = "persistent-dir-index")]
    fn collect_dir_entries(
        dir: &PersistentDirIndex,
        cookie: tidefs_dir_index::DirCookie,
    ) -> Result<
        (
            Vec<tidefs_types_polymorphic_directory_index_core::DirMicroEntry>,
            tidefs_dir_index::DirCookie,
        ),
        NamespaceError,
    > {
        dir.list_from(cookie).map_err(|e| match e {
            tidefs_dir_index::DirIndexError::StaleCursor => NamespaceError::StaleCursor,
            _ => NamespaceError::NotFound,
        })
    }

    #[cfg(not(feature = "persistent-dir-index"))]
    fn collect_dir_entries(
        dir: &DirIndex,
        cookie: tidefs_dir_index::DirCookie,
    ) -> Result<
        (
            Vec<tidefs_types_polymorphic_directory_index_core::DirMicroEntry>,
            tidefs_dir_index::DirCookie,
        ),
        NamespaceError,
    > {
        let start = if cookie.0 == 0 {
            0
        } else if tidefs_dir_index::format::dir_cookie_decode_version(cookie.0).is_some() {
            tidefs_dir_index::format::dir_cookie_skip(cookie.0)
        } else if let Some(index) = cookie.as_micro_entry_index() {
            index as usize
        } else if let Some((page, entry)) = cookie.as_btree_indices() {
            (page as usize).saturating_mul(128) + (entry as usize)
        } else {
            cookie.payload() as usize
        };
        let (mut entries, _) = dir.list_from(cookie).map_err(NamespaceError::from)?;
        if entries.len() > 128 {
            entries.truncate(128);
        }
        let next = if entries.is_empty() {
            cookie
        } else {
            tidefs_dir_index::DirCookie(tidefs_dir_index::format::dir_cookie_encode_versioned(
                start.saturating_add(entries.len()) as u64,
                dir.directory_version(),
            ))
        };
        Ok((entries, next))
    }

    /// up to 128 entries and the next cookie for pagination.
    ///
    /// Pass [`tidefs_dir_index::DirCookie::START`] to begin from
    /// the first entry.  The returned `next_cookie.0` is the offset
    /// to pass for the next page.  When the returned vector is shorter
    /// than 128 entries (or empty), the caller knows the directory is
    /// exhausted.
    pub fn read_dir(
        &self,
        dir_inode: Inode,
        cookie: tidefs_dir_index::DirCookie,
    ) -> Result<
        (
            Vec<tidefs_types_polymorphic_directory_index_core::DirMicroEntry>,
            tidefs_dir_index::DirCookie,
        ),
        NamespaceError,
    > {
        let _ = self.ensure_delegated_dir_loaded(dir_inode)?;

        #[cfg(feature = "persistent-dir-index")]
        {
            if let Some(result) = {
                let dirs = self.dirs.read().unwrap();
                dirs.get(&dir_inode)
                    .map(|dir| Self::collect_dir_entries(dir, cookie))
            } {
                return result;
            }

            if let Some(result) = self.list_persistent_dir_entries_in_store(dir_inode, cookie)? {
                return Ok(result);
            }
        }

        let dirs = self.dirs.read().unwrap();
        let dir = dirs.get(&dir_inode).ok_or(NamespaceError::InodeNotFound)?;

        let (entries, next_cookie) = Self::collect_dir_entries(dir, cookie)?;
        Ok((entries, next_cookie))
    }

    #[cfg(all(test, feature = "persistent-dir-index"))]
    fn loaded_dir_count_for_test(&self) -> usize {
        self.dirs.read().unwrap().len()
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct FencedPersistentInodeStore;

    impl PersistentInodeStore for FencedPersistentInodeStore {
        fn ensure_mutation_allowed(&self, operation: &'static str) -> Result<(), NamespaceError> {
            Err(NamespaceError::MutationRequiresReopen { operation })
        }

        fn alloc_inode(&self, _attrs: &InodeAttributes) -> Result<(Inode, u64), NamespaceError> {
            unreachable!("outer namespace preflight must run first")
        }

        fn get_attrs(&self, _inode: Inode) -> Option<InodeAttributes> {
            None
        }

        fn update_attrs(
            &self,
            _inode: Inode,
            _attrs: &InodeAttributes,
        ) -> Result<(), NamespaceError> {
            unreachable!("outer namespace preflight must run first")
        }

        fn free_inode(&self, _inode: Inode) -> Result<(), NamespaceError> {
            unreachable!("outer namespace preflight must run first")
        }

        fn next_inode_id(&self) -> Inode {
            0
        }

        fn generation(&self) -> u64 {
            0
        }
    }

    fn test_ns() -> Namespace {
        Namespace::new()
    }

    fn fenced_persistent_ns() -> Namespace {
        let mut namespace = Namespace::new();
        namespace.persistent_inodes = Some(Arc::new(FencedPersistentInodeStore));
        namespace
    }

    fn test_file_attrs(ino: Inode) -> InodeAttributes {
        InodeAttributes::new_file(ino)
    }

    fn test_dir_attrs(ino: Inode) -> InodeAttributes {
        InodeAttributes::new_dir(ino)
    }

    #[cfg(feature = "persistent-dir-index")]
    fn open_object_store() -> (
        tempfile::TempDir,
        tidefs_dir_index::tidefs_local_object_store::LocalObjectStore,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let store = tidefs_dir_index::tidefs_local_object_store::LocalObjectStore::open(tmp.path())
            .unwrap();
        (tmp, store)
    }

    // ------------------------------------------------------------------
    // Basename validation tests
    // ------------------------------------------------------------------

    #[test]
    fn mounted_reopen_refusal_precedes_namespace_validation_and_noops() {
        let namespace = fenced_persistent_ns();

        assert!(matches!(
            namespace.create_file(ROOT_INODE, "", test_file_attrs(0)),
            Err(NamespaceError::MutationRequiresReopen { .. })
        ));
        assert!(matches!(
            namespace.unlink(ROOT_INODE, ""),
            Err(NamespaceError::MutationRequiresReopen { .. })
        ));
        assert!(matches!(
            namespace.rename(ROOT_INODE, "same", ROOT_INODE, "same"),
            Err(NamespaceError::MutationRequiresReopen { .. })
        ));
        assert!(matches!(
            namespace.track_anonymous_inode(9, 1, 1, 0),
            Err(NamespaceError::MutationRequiresReopen { .. })
        ));
    }

    #[test]
    fn basename_validation_plan_classifies_invalid_names() {
        let cases: &[(&[u8], BasenameValidationMode, Option<InvalidBasenameReason>)] = &[
            (
                b"",
                BasenameValidationMode::DirectoryEntryMutation,
                Some(InvalidBasenameReason::Empty),
            ),
            (
                b"bad/name",
                BasenameValidationMode::DirectoryEntryMutation,
                Some(InvalidBasenameReason::ContainsSlash),
            ),
            (
                b"bad\0name",
                BasenameValidationMode::DirectoryEntryMutation,
                Some(InvalidBasenameReason::ContainsNul),
            ),
            (
                b".",
                BasenameValidationMode::DirectoryEntryMutation,
                Some(InvalidBasenameReason::Dot),
            ),
            (
                b"..",
                BasenameValidationMode::DirectoryEntryMutation,
                Some(InvalidBasenameReason::DotDot),
            ),
            (b".", BasenameValidationMode::Lookup, None),
            (b"..", BasenameValidationMode::Lookup, None),
            (
                b"ordinary-name",
                BasenameValidationMode::DirectoryEntryMutation,
                None,
            ),
        ];

        for (name, mode, expected_reason) in cases {
            let plan = plan_basename_validation(name, *mode);
            assert_eq!(plan.mode, *mode);
            assert_eq!(plan.name_len, name.len());
            assert_eq!(plan.invalid_reason, *expected_reason);
            assert_eq!(plan.is_valid(), expected_reason.is_none());
            assert_eq!(plan.validate().is_ok(), expected_reason.is_none());
        }
    }

    #[test]
    fn lookup_allows_dot_entries_but_rejects_invalid_basenames() {
        let ns = test_ns();

        assert_eq!(ns.lookup(ROOT_INODE, ".").unwrap(), Some(ROOT_INODE));
        assert_eq!(ns.lookup(ROOT_INODE, "..").unwrap(), Some(ROOT_INODE));
        assert_eq!(
            ns.lookup(ROOT_INODE, "bad/name"),
            Err(NamespaceError::InvalidName)
        );
        assert_eq!(
            ns.lookup(ROOT_INODE, "bad\0name"),
            Err(NamespaceError::InvalidName)
        );
    }

    // ------------------------------------------------------------------
    // InodeTable tests
    // ------------------------------------------------------------------

    #[test]
    fn inode_table_alloc_returns_unique_inodes() {
        let t = MemInodeTable::new();
        let a = t.alloc(test_file_attrs(0)).unwrap();
        let b = t.alloc(test_file_attrs(0)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn inode_table_get_retrieves_attrs() {
        let t = MemInodeTable::new();
        let attrs = InodeAttributes {
            mode: 0o100755,
            ..test_file_attrs(0)
        };
        let ino = t.alloc(attrs.clone()).unwrap();
        let stored = t.get(ino).unwrap();
        assert_eq!(stored.mode, 0o100755);
        assert_eq!(stored.inode, ino);
    }

    #[test]
    fn inode_table_update_attrs_modifies_fields() {
        let t = MemInodeTable::new();
        let ino = t.alloc(test_file_attrs(0)).unwrap();
        let mut new_attrs = t.get(ino).unwrap();
        new_attrs.size = 4096;
        t.update_attrs(ino, new_attrs.clone()).unwrap();
        assert_eq!(t.get(ino).unwrap().size, 4096);
    }

    #[test]
    fn inode_table_free_makes_inode_unavailable() {
        let t = MemInodeTable::new();
        let ino = t.alloc(test_file_attrs(0)).unwrap();
        assert!(t.get(ino).is_some());
        t.free(ino).unwrap();
        assert!(t.get(ino).is_none());
    }

    #[test]
    fn inode_table_double_free_is_error() {
        let t = MemInodeTable::new();
        let ino = t.alloc(test_file_attrs(0)).unwrap();
        t.free(ino).unwrap();
        assert_eq!(t.free(ino), Err(NamespaceError::InodeNotFound));
    }

    #[test]
    fn inode_table_get_after_free_is_none() {
        let t = MemInodeTable::new();
        let ino = t.alloc(test_file_attrs(0)).unwrap();
        t.free(ino).unwrap();
        assert!(t.get(ino).is_none());
    }

    #[test]
    fn inode_table_update_after_free_is_error() {
        let t = MemInodeTable::new();
        let ino = t.alloc(test_file_attrs(0)).unwrap();
        t.free(ino).unwrap();
        assert_eq!(
            t.update_attrs(ino, test_file_attrs(ino)),
            Err(NamespaceError::InodeNotFound)
        );
    }

    #[test]
    fn inode_table_free_and_reuse_inode() {
        let t = MemInodeTable::new();
        let ino1 = t.alloc(test_file_attrs(0)).unwrap();
        t.free(ino1).unwrap();
        // After freeing, the inode should be unavailable.
        assert!(t.get(ino1).is_none());
        // Allocating a new inode should get a different number.
        let ino2 = t.alloc(test_file_attrs(0)).unwrap();
        assert_ne!(ino1, ino2);
    }

    // ------------------------------------------------------------------
    // Path resolution tests
    // ------------------------------------------------------------------

    #[test]
    fn resolve_root() {
        let ns = test_ns();
        assert_eq!(ns.resolve(Path::new("/")).unwrap(), ROOT_INODE);
        assert_eq!(ns.resolve(Path::new("")).unwrap(), ROOT_INODE);
    }

    #[test]
    fn resolve_single_component() {
        let ns = test_ns();
        let ino = ns
            .create_file(ROOT_INODE, "hello", test_file_attrs(0))
            .unwrap();
        assert_eq!(ns.resolve(Path::new("/hello")).unwrap(), ino);
        assert_eq!(ns.resolve(Path::new("hello")).unwrap(), ino);
    }

    #[test]
    fn resolve_nested() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "sub", test_dir_attrs(0)).unwrap();
        let file = ns.create_file(dir, "deep", test_file_attrs(0)).unwrap();
        assert_eq!(ns.resolve(Path::new("/sub/deep")).unwrap(), file);
    }

    #[test]
    fn resolve_rejects_nul_component() {
        let ns = test_ns();
        assert_eq!(
            ns.resolve(Path::new("/bad\0name")),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn resolve_dot_noop() {
        let ns = test_ns();
        let file = ns.create_file(ROOT_INODE, "x", test_file_attrs(0)).unwrap();
        assert_eq!(ns.resolve(Path::new("/./x")).unwrap(), file);
        assert_eq!(ns.resolve(Path::new("/././x")).unwrap(), file);
    }

    #[test]
    fn resolve_dotdot() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "d", test_dir_attrs(0)).unwrap();
        assert_eq!(ns.resolve(Path::new("/d/..")).unwrap(), ROOT_INODE);
        assert_eq!(ns.resolve(Path::new("/d/../d")).unwrap(), dir);
    }

    #[test]
    fn resolve_nonexistent() {
        let ns = test_ns();
        assert_eq!(
            ns.resolve(Path::new("/nope")),
            Err(NamespaceError::NotFound)
        );
    }

    #[test]
    fn resolve_through_file_is_error() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "f", test_file_attrs(0)).unwrap();
        assert_eq!(
            ns.resolve(Path::new("/f/sub")),
            Err(NamespaceError::NotDirectory)
        ); // f is not a dir, so lookup of sub fails
    }

    #[test]
    fn resolve_follows_relative_symlink_target() {
        let ns = test_ns();
        let dir = ns
            .create_dir(ROOT_INODE, "real", test_dir_attrs(0))
            .unwrap();
        let file = ns.create_file(dir, "file", test_file_attrs(0)).unwrap();
        ns.create_symlink(ROOT_INODE, "link", b"real/file").unwrap();

        assert_eq!(ns.resolve(Path::new("/link")).unwrap(), file);
    }

    #[test]
    fn resolve_follows_symlink_to_directory_with_remaining_path() {
        let ns = test_ns();
        let dir = ns
            .create_dir(ROOT_INODE, "real", test_dir_attrs(0))
            .unwrap();
        let file = ns.create_file(dir, "file", test_file_attrs(0)).unwrap();
        ns.create_symlink(ROOT_INODE, "linkdir", b"real").unwrap();

        assert_eq!(ns.resolve(Path::new("/linkdir/file")).unwrap(), file);
    }

    #[test]
    fn resolve_rejects_nul_component_from_symlink_target() {
        let ns = test_ns();
        ns.create_symlink(ROOT_INODE, "link", b"bad\0target")
            .unwrap();

        assert_eq!(
            ns.resolve(Path::new("/link")),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn resolve_follows_absolute_symlink_target() {
        let ns = test_ns();
        let dir = ns
            .create_dir(ROOT_INODE, "real", test_dir_attrs(0))
            .unwrap();
        let file = ns.create_file(dir, "file", test_file_attrs(0)).unwrap();
        let sub = ns.create_dir(ROOT_INODE, "sub", test_dir_attrs(0)).unwrap();
        ns.create_symlink(sub, "link", b"/real/file").unwrap();

        assert_eq!(ns.resolve(Path::new("/sub/link")).unwrap(), file);
    }

    #[test]
    fn resolve_refuses_symlink_loop() {
        let ns = test_ns();
        ns.create_symlink(ROOT_INODE, "a", b"b").unwrap();
        ns.create_symlink(ROOT_INODE, "b", b"a").unwrap();

        assert_eq!(
            ns.resolve(Path::new("/a")),
            Err(NamespaceError::TooManySymlinks)
        );
    }

    #[test]
    fn resolve_file_midpath_returns_not_directory() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        assert_eq!(
            ns.resolve(Path::new("/file/child")),
            Err(NamespaceError::NotDirectory)
        );
    }

    #[test]
    fn resolve_file_deep_midpath_returns_not_directory() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();
        ns.create_file(dir, "file", test_file_attrs(0)).unwrap();
        assert_eq!(
            ns.resolve(Path::new("/dir/file/child")),
            Err(NamespaceError::NotDirectory)
        );
    }

    #[test]
    fn resolve_nonexistent_midpath_returns_not_found() {
        let ns = test_ns();
        assert_eq!(
            ns.resolve(Path::new("/nonexistent/child")),
            Err(NamespaceError::NotFound)
        );
    }

    #[test]
    fn resolve_parent_returns_root_for_single_component() {
        let ns = test_ns();
        let resolved = ns.resolve_parent(Path::new("new-file")).unwrap();

        assert_eq!(
            resolved,
            ResolvedParent {
                parent: ROOT_INODE,
                name: b"new-file".to_vec()
            }
        );
    }

    #[test]
    fn resolve_parent_follows_symlinked_directory() {
        let ns = test_ns();
        let real = ns
            .create_dir(ROOT_INODE, "real", test_dir_attrs(0))
            .unwrap();
        ns.create_symlink(ROOT_INODE, "linkdir", b"real").unwrap();

        let resolved = ns.resolve_parent(Path::new("/linkdir/new-file")).unwrap();

        assert_eq!(resolved.parent, real);
        assert_eq!(resolved.name, b"new-file");
    }

    #[test]
    fn resolve_parent_rejects_symlink_loop() {
        let ns = test_ns();
        ns.create_symlink(ROOT_INODE, "a", b"b").unwrap();
        ns.create_symlink(ROOT_INODE, "b", b"a").unwrap();

        assert_eq!(
            ns.resolve_parent(Path::new("/a/new-file")),
            Err(NamespaceError::TooManySymlinks)
        );
    }

    #[test]
    fn resolve_parent_rejects_invalid_final_component() {
        let ns = test_ns();

        assert_eq!(
            ns.resolve_parent(Path::new("/")),
            Err(NamespaceError::InvalidName)
        );
        assert_eq!(
            ns.resolve_parent(Path::new("/dir/..")),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn resolve_parent_rejects_non_directory_parent() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.resolve_parent(Path::new("/file/child")),
            Err(NamespaceError::NotDirectory)
        );
    }

    // ------------------------------------------------------------------
    // Create / lookup cycle
    // ------------------------------------------------------------------

    #[test]
    fn create_file_and_lookup() {
        let ns = test_ns();
        let ino = ns
            .create_file(ROOT_INODE, "test.txt", test_file_attrs(0))
            .unwrap();
        assert_eq!(ino, 2); // root is 1, so first file is 2
        let found = ns.lookup(ROOT_INODE, "test.txt").unwrap();
        assert_eq!(found, Some(ino));
    }

    #[test]
    fn create_dir_and_lookup() {
        let ns = test_ns();
        let ino = ns
            .create_dir(ROOT_INODE, "mydir", test_dir_attrs(0))
            .unwrap();
        let found = ns.lookup(ROOT_INODE, "mydir").unwrap();
        assert_eq!(found, Some(ino));
    }

    #[test]
    fn create_symlink_and_readlink_preserves_target_bytes() {
        let ns = test_ns();
        let target = b"../raw/\xff-name\0-tail".to_vec();
        let ino = ns.create_symlink(ROOT_INODE, "link", &target).unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), Some(ino));
        assert_eq!(ns.readlink(ino).unwrap(), target);
        let attrs = ns.get_attrs(ino).unwrap();
        assert_eq!(attrs.mode & 0o170000, 0o120000);
        assert_eq!(attrs.size, target.len() as u64);
    }

    #[test]
    fn create_symlink_rejects_empty_target() {
        let ns = test_ns();
        assert_eq!(
            ns.create_symlink(ROOT_INODE, "empty", b""),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn readlink_non_symlink_returns_not_symlink() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        assert_eq!(ns.readlink(file), Err(NamespaceError::NotSymlink));
    }

    #[test]
    fn readlink_at_returns_named_symlink_without_following_it() {
        let ns = test_ns();
        let target = b"real/file".to_vec();
        ns.create_symlink(ROOT_INODE, "link", &target).unwrap();

        assert_eq!(ns.readlink_at(ROOT_INODE, "link").unwrap(), target);
    }

    #[test]
    fn readlink_at_non_symlink_returns_not_symlink() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.readlink_at(ROOT_INODE, "file"),
            Err(NamespaceError::NotSymlink)
        );
    }

    #[test]
    fn readlink_at_rejects_missing_parent_and_invalid_name() {
        let ns = test_ns();

        assert_eq!(
            ns.readlink_at(9999, "link"),
            Err(NamespaceError::InodeNotFound)
        );
        assert_eq!(
            ns.readlink_at(ROOT_INODE, ""),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn create_symlink_under_nonexistent_parent_rolls_back_inode() {
        let ns = test_ns();

        assert_eq!(
            ns.create_symlink(9999, "link", b"target"),
            Err(NamespaceError::InodeNotFound)
        );
        assert_eq!(ns.inode_table().live_count(), 1);
    }

    #[test]
    fn lookup_nonexistent_returns_none() {
        let ns = test_ns();
        let found = ns.lookup(ROOT_INODE, "no_such").unwrap();
        assert_eq!(found, None);
    }

    #[test]
    fn lookup_in_nonexistent_parent() {
        let ns = test_ns();
        assert_eq!(ns.lookup(999, "x"), Err(NamespaceError::InodeNotFound));
    }

    #[test]
    fn lookup_under_regular_file_returns_not_directory_without_mutation() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        let live_count = ns.inode_table().live_count();
        let attrs = ns.get_attrs(file).unwrap();

        assert_eq!(ns.lookup(file, "child"), Err(NamespaceError::NotDirectory));

        assert_eq!(ns.inode_table().live_count(), live_count);
        assert_eq!(ns.lookup(ROOT_INODE, "file").unwrap(), Some(file));
        assert_eq!(ns.get_attrs(file).unwrap().nlink, attrs.nlink);
    }

    #[test]
    fn create_duplicate_returns_already_exists() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "dup", test_file_attrs(0))
            .unwrap();
        assert_eq!(
            ns.create_file(ROOT_INODE, "dup", test_file_attrs(0)),
            Err(NamespaceError::AlreadyExists)
        );
    }

    // ------------------------------------------------------------------
    // Hard link tests
    // ------------------------------------------------------------------

    #[test]
    fn create_hard_link_shares_inode_and_tracks_nlink() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();

        let linked = ns
            .create_hard_link(ROOT_INODE, "source", dir, "alias")
            .unwrap();

        assert_eq!(linked, file);
        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), Some(file));
        assert_eq!(ns.lookup(dir, "alias").unwrap(), Some(file));
        assert_eq!(ns.get_attrs(file).unwrap().nlink, 2);

        ns.unlink(ROOT_INODE, "source").unwrap();
        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), None);
        assert_eq!(ns.lookup(dir, "alias").unwrap(), Some(file));
        assert_eq!(ns.get_attrs(file).unwrap().nlink, 1);

        ns.unlink(dir, "alias").unwrap();
        assert!(ns.get_attrs(file).is_none());
    }

    #[test]
    fn unlink_one_hard_link_preserves_remaining_name_until_last_unlink() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();
        let unrelated = ns
            .create_file(ROOT_INODE, "unrelated", test_file_attrs(0))
            .unwrap();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();
        let sibling = ns.create_file(dir, "sibling", test_file_attrs(0)).unwrap();

        let linked = ns
            .create_hard_link(ROOT_INODE, "source", dir, "alias")
            .unwrap();

        assert_eq!(linked, file);
        assert_eq!(ns.get_attrs(file).unwrap().nlink, 2);

        ns.unlink(ROOT_INODE, "source").unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), None);
        assert_eq!(ns.lookup(dir, "alias").unwrap(), Some(file));
        assert_eq!(ns.lookup(ROOT_INODE, "unrelated").unwrap(), Some(unrelated));
        assert_eq!(ns.lookup(dir, "sibling").unwrap(), Some(sibling));
        assert_eq!(ns.get_attrs(file).unwrap().nlink, 1);

        ns.unlink(dir, "alias").unwrap();

        assert_eq!(ns.lookup(dir, "alias").unwrap(), None);
        assert!(ns.get_attrs(file).is_none());
        assert_eq!(ns.lookup(ROOT_INODE, "unrelated").unwrap(), Some(unrelated));
        assert_eq!(ns.lookup(dir, "sibling").unwrap(), Some(sibling));
    }

    #[test]
    fn create_hard_link_rejects_directory_and_existing_destination() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();
        assert_eq!(
            ns.create_hard_link(ROOT_INODE, "dir", ROOT_INODE, "dir_alias"),
            Err(NamespaceError::IsDirectory)
        );

        let file = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();
        ns.create_file(ROOT_INODE, "existing", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.create_hard_link(ROOT_INODE, "source", ROOT_INODE, "existing"),
            Err(NamespaceError::AlreadyExists)
        );
        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), Some(file));
        assert_eq!(ns.get_attrs(file).unwrap().nlink, 1);
        assert_eq!(ns.lookup(ROOT_INODE, "dir").unwrap(), Some(dir));
    }

    #[test]
    fn create_hard_link_rejects_missing_source_parent_and_invalid_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_hard_link(ROOT_INODE, "missing", ROOT_INODE, "alias"),
            Err(NamespaceError::NotFound)
        );
        assert_eq!(
            ns.create_hard_link(9999, "missing", ROOT_INODE, "alias"),
            Err(NamespaceError::InodeNotFound)
        );
        assert_eq!(
            ns.create_hard_link(ROOT_INODE, "missing", ROOT_INODE, "."),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn rename_over_hard_link_decrements_replaced_inode() {
        let ns = test_ns();
        let kept = ns
            .create_file(ROOT_INODE, "kept", test_file_attrs(0))
            .unwrap();
        ns.create_hard_link(ROOT_INODE, "kept", ROOT_INODE, "replaced")
            .unwrap();
        let source = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();

        ns.rename(ROOT_INODE, "source", ROOT_INODE, "replaced")
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "kept").unwrap(), Some(kept));
        assert_eq!(ns.lookup(ROOT_INODE, "replaced").unwrap(), Some(source));
        assert_eq!(ns.get_attrs(kept).unwrap().nlink, 1);
        assert_eq!(ns.get_attrs(source).unwrap().nlink, 1);
    }

    #[test]
    fn unlink_hard_linked_symlink_preserves_target_until_last_link() {
        let ns = test_ns();
        let link = ns.create_symlink(ROOT_INODE, "link", b"target").unwrap();
        ns.create_hard_link(ROOT_INODE, "link", ROOT_INODE, "alias")
            .unwrap();

        ns.unlink(ROOT_INODE, "link").unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "alias").unwrap(), Some(link));
        assert_eq!(ns.readlink(link).unwrap(), b"target".to_vec());
        assert_eq!(ns.get_attrs(link).unwrap().nlink, 1);

        ns.unlink(ROOT_INODE, "alias").unwrap();
        assert_eq!(ns.readlink(link), Err(NamespaceError::InodeNotFound));
    }

    // ------------------------------------------------------------------
    // Unlink tests
    // ------------------------------------------------------------------

    #[test]
    fn unlink_file_removes_entry() {
        let ns = test_ns();
        let ino = ns
            .create_file(ROOT_INODE, "bye", test_file_attrs(0))
            .unwrap();
        ns.unlink(ROOT_INODE, "bye").unwrap();
        assert_eq!(ns.lookup(ROOT_INODE, "bye").unwrap(), None);
        // Inode is freed.
        assert!(ns.get_attrs(ino).is_none());
    }

    #[test]
    fn unlink_nonexistent_returns_not_found() {
        let ns = test_ns();
        assert_eq!(
            ns.unlink(ROOT_INODE, "ghost"),
            Err(NamespaceError::NotFound)
        );
    }

    #[test]
    fn unlink_empty_dir_succeeds() {
        let ns = test_ns();
        let d = ns
            .create_dir(ROOT_INODE, "emptydir", test_dir_attrs(0))
            .unwrap();
        ns.unlink(ROOT_INODE, "emptydir").unwrap();
        assert_eq!(ns.lookup(ROOT_INODE, "emptydir").unwrap(), None);
        assert!(ns.get_attrs(d).is_none());
    }

    #[test]
    fn unlink_symlink_removes_target() {
        let ns = test_ns();
        let link = ns.create_symlink(ROOT_INODE, "link", b"target").unwrap();
        ns.unlink(ROOT_INODE, "link").unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), None);
        assert_eq!(ns.readlink(link), Err(NamespaceError::InodeNotFound));
    }

    #[test]
    fn unlink_symlink_preserves_referenced_target_inode() {
        let ns = test_ns();
        let target = ns
            .create_file(ROOT_INODE, "target", test_file_attrs(0))
            .unwrap();
        let target_attrs = ns.get_attrs(target).unwrap();
        let link = ns.create_symlink(ROOT_INODE, "link", b"target").unwrap();

        assert_eq!(ns.resolve(Path::new("/link")).unwrap(), target);

        ns.unlink(ROOT_INODE, "link").unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), None);
        assert_eq!(
            ns.resolve(Path::new("/link")),
            Err(NamespaceError::NotFound)
        );
        assert_eq!(
            ns.readlink_at(ROOT_INODE, "link"),
            Err(NamespaceError::NotFound)
        );
        assert_eq!(ns.readlink(link), Err(NamespaceError::InodeNotFound));
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(target));
        assert_eq!(ns.resolve(Path::new("/target")).unwrap(), target);
        assert_eq!(ns.get_attrs(target).unwrap().nlink, target_attrs.nlink);
    }

    #[test]
    fn unlink_nonempty_dir_fails() {
        let ns = test_ns();
        let d = ns
            .create_dir(ROOT_INODE, "parent", test_dir_attrs(0))
            .unwrap();
        ns.create_file(d, "child", test_file_attrs(0)).unwrap();
        assert_eq!(
            ns.unlink(ROOT_INODE, "parent"),
            Err(NamespaceError::NotEmpty)
        );
    }

    #[test]
    fn unlink_with_invalid_name() {
        let ns = test_ns();
        assert_eq!(ns.unlink(ROOT_INODE, ""), Err(NamespaceError::InvalidName));
        assert_eq!(ns.unlink(ROOT_INODE, "."), Err(NamespaceError::InvalidName));
    }

    // ------------------------------------------------------------------
    // Rename tests
    // ------------------------------------------------------------------

    #[test]
    fn rename_file_to_new_dir() {
        let ns = test_ns();
        let f = ns.create_file(ROOT_INODE, "f", test_file_attrs(0)).unwrap();
        let d = ns.create_dir(ROOT_INODE, "b", test_dir_attrs(0)).unwrap();
        ns.rename(ROOT_INODE, "f", d, "g").unwrap();
        // Old name gone.
        assert_eq!(ns.lookup(ROOT_INODE, "f").unwrap(), None);
        // New name present.
        assert_eq!(ns.lookup(d, "g").unwrap(), Some(f));
    }

    #[test]
    fn rename_same_dir() {
        let ns = test_ns();
        let f = ns
            .create_file(ROOT_INODE, "old", test_file_attrs(0))
            .unwrap();
        ns.rename(ROOT_INODE, "old", ROOT_INODE, "new").unwrap();
        assert_eq!(ns.lookup(ROOT_INODE, "old").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "new").unwrap(), Some(f));
    }

    #[test]
    fn rename_overwrite_file() {
        let ns = test_ns();
        let f1 = ns.create_file(ROOT_INODE, "a", test_file_attrs(0)).unwrap();
        let f2 = ns.create_file(ROOT_INODE, "b", test_file_attrs(0)).unwrap();
        ns.rename(ROOT_INODE, "a", ROOT_INODE, "b").unwrap();
        assert_eq!(ns.lookup(ROOT_INODE, "a").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "b").unwrap(), Some(f1));
        // f2 should be freed.
        assert!(ns.get_attrs(f2).is_none());
    }

    #[test]
    fn namespace_rename_file_replaces_existing_file() {
        let ns = test_ns();
        let source = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();
        let replaced = ns
            .create_file(ROOT_INODE, "target", test_file_attrs(0))
            .unwrap();
        let unrelated = ns
            .create_file(ROOT_INODE, "unrelated", test_file_attrs(0))
            .unwrap();
        let (before_version, before_len) = {
            let dirs = ns.dirs.read().unwrap();
            let root = dirs.get(&ROOT_INODE).unwrap();
            (root.directory_version(), root.len())
        };

        ns.rename(ROOT_INODE, "source", ROOT_INODE, "target")
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(source));
        assert_eq!(ns.lookup(ROOT_INODE, "unrelated").unwrap(), Some(unrelated));
        assert_eq!(ns.resolve(Path::new("/target")).unwrap(), source);
        assert_eq!(
            ns.resolve(Path::new("/source")),
            Err(NamespaceError::NotFound)
        );
        assert_eq!(ns.resolve(Path::new("/unrelated")).unwrap(), unrelated);
        assert!(ns.get_attrs(source).is_some());
        assert!(ns.get_attrs(replaced).is_none());

        let (after_version, after_len) = {
            let dirs = ns.dirs.read().unwrap();
            let root = dirs.get(&ROOT_INODE).unwrap();
            (root.directory_version(), root.len())
        };
        assert_eq!(after_version, before_version + 1);
        assert_eq!(after_len, before_len - 1);
    }

    #[test]
    fn rename_flag_plan_classifies_replace_and_noreplace() {
        let replace = plan_rename_flags(0, true).unwrap();
        assert_eq!(replace.flags, 0);
        assert!(replace.target_exists);
        assert_eq!(replace.mode, RenameMode::ReplaceExisting);
        assert!(!replace.requires_absent_target());

        let no_replace = plan_rename_flags(RENAME_NOREPLACE, false).unwrap();
        assert_eq!(no_replace.flags, RENAME_NOREPLACE);
        assert!(!no_replace.target_exists);
        assert_eq!(no_replace.mode, RenameMode::NoReplace);
        assert!(no_replace.requires_absent_target());
        assert!(!no_replace.requires_present_target());

        let exchange = plan_rename_flags(RENAME_EXCHANGE, true).unwrap();
        assert_eq!(exchange.flags, RENAME_EXCHANGE);
        assert!(exchange.target_exists);
        assert_eq!(exchange.mode, RenameMode::Exchange);
        assert!(!exchange.requires_absent_target());
        assert!(exchange.requires_present_target());

        assert_eq!(
            plan_rename_flags(RENAME_NOREPLACE, true),
            Err(RenameFlagPlanError::TargetExists)
        );
        assert_eq!(
            plan_rename_flags(RENAME_EXCHANGE, false),
            Err(RenameFlagPlanError::TargetMissing)
        );
        assert_eq!(
            plan_rename_flags(0x04, false),
            Err(RenameFlagPlanError::InvalidFlags { flags: 0x04 })
        );
    }

    #[test]
    fn rename_target_plan_classifies_destination_outcomes() {
        let absent = plan_rename_target(10, EntryType::File, None).unwrap();
        assert_eq!(absent.source_entry_type, EntryType::File);
        assert_eq!(absent.action, RenameTargetAction::DestinationAbsent);
        assert!(!absent.is_noop());

        let same_inode = plan_rename_target(
            10,
            EntryType::File,
            Some(RenameExistingTarget {
                inode: 10,
                entry_type: EntryType::File,
                directory_entry_count: None,
            }),
        )
        .unwrap();
        assert_eq!(same_inode.action, RenameTargetAction::NoOpSameInode);
        assert!(same_inode.is_noop());

        let replace_file = plan_rename_target(
            10,
            EntryType::File,
            Some(RenameExistingTarget {
                inode: 11,
                entry_type: EntryType::File,
                directory_entry_count: None,
            }),
        )
        .unwrap();
        assert_eq!(
            replace_file.action,
            RenameTargetAction::ReplaceExisting {
                entry_type: EntryType::File,
                remove_directory_index: false,
            }
        );

        let replace_empty_directory = plan_rename_target(
            12,
            EntryType::Directory,
            Some(RenameExistingTarget {
                inode: 13,
                entry_type: EntryType::Directory,
                directory_entry_count: Some(2),
            }),
        )
        .unwrap();
        assert_eq!(
            replace_empty_directory.action,
            RenameTargetAction::ReplaceExisting {
                entry_type: EntryType::Directory,
                remove_directory_index: true,
            }
        );
    }

    #[test]
    fn rename_target_plan_rejects_incompatible_or_nonempty_targets() {
        assert_eq!(
            plan_rename_target(
                10,
                EntryType::Directory,
                Some(RenameExistingTarget {
                    inode: 11,
                    entry_type: EntryType::File,
                    directory_entry_count: None,
                }),
            ),
            Err(RenameTargetPlanError::DirectoryOverNonDirectory)
        );

        assert_eq!(
            plan_rename_target(
                10,
                EntryType::File,
                Some(RenameExistingTarget {
                    inode: 11,
                    entry_type: EntryType::Directory,
                    directory_entry_count: Some(2),
                }),
            ),
            Err(RenameTargetPlanError::NonDirectoryOverDirectory)
        );

        assert_eq!(
            plan_rename_target(
                10,
                EntryType::Directory,
                Some(RenameExistingTarget {
                    inode: 11,
                    entry_type: EntryType::Directory,
                    directory_entry_count: Some(3),
                }),
            ),
            Err(RenameTargetPlanError::DirectoryNotEmpty)
        );
    }

    #[test]
    fn rename_with_noreplace_moves_when_target_absent() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();

        ns.rename_with_flags(ROOT_INODE, "source", ROOT_INODE, "target", RENAME_NOREPLACE)
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(file));
        assert!(ns.get_attrs(file).is_some());
    }

    #[test]
    fn rename_with_noreplace_rejects_existing_target() {
        let ns = test_ns();
        let source = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();
        let target = ns
            .create_file(ROOT_INODE, "target", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.rename_with_flags(ROOT_INODE, "source", ROOT_INODE, "target", RENAME_NOREPLACE),
            Err(NamespaceError::AlreadyExists)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), Some(source));
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(target));
        assert!(ns.get_attrs(source).is_some());
        assert!(ns.get_attrs(target).is_some());
    }

    #[test]
    fn rename_exchange_swaps_files() {
        let ns = test_ns();
        let source_dir = ns
            .create_dir(ROOT_INODE, "source-dir", test_dir_attrs(0))
            .unwrap();
        let target_dir = ns
            .create_dir(ROOT_INODE, "target-dir", test_dir_attrs(0))
            .unwrap();
        let source = ns
            .create_file(source_dir, "source", test_file_attrs(0))
            .unwrap();
        let target = ns
            .create_file(target_dir, "target", test_file_attrs(0))
            .unwrap();

        ns.rename_with_flags(source_dir, "source", target_dir, "target", RENAME_EXCHANGE)
            .unwrap();

        assert_eq!(ns.lookup(source_dir, "source").unwrap(), Some(target));
        assert_eq!(ns.lookup(target_dir, "target").unwrap(), Some(source));
        assert!(ns.get_attrs(source).is_some());
        assert!(ns.get_attrs(target).is_some());
    }

    #[test]
    fn rename_exchange_rejects_absent_target() {
        let ns = test_ns();
        let source = ns
            .create_file(ROOT_INODE, "source", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.rename_with_flags(ROOT_INODE, "source", ROOT_INODE, "target", RENAME_EXCHANGE),
            Err(NamespaceError::NotFound)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), Some(source));
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), None);
        assert!(ns.get_attrs(source).is_some());
    }

    #[test]
    fn rename_exchange_swaps_symlinks() {
        let ns = test_ns();
        let left = ns
            .create_symlink(ROOT_INODE, "left", b"left-target")
            .unwrap();
        let right = ns
            .create_symlink(ROOT_INODE, "right", b"right-target")
            .unwrap();

        ns.rename_with_flags(ROOT_INODE, "left", ROOT_INODE, "right", RENAME_EXCHANGE)
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "left").unwrap(), Some(right));
        assert_eq!(ns.lookup(ROOT_INODE, "right").unwrap(), Some(left));
        assert_eq!(ns.readlink(left).unwrap(), b"left-target".to_vec());
        assert_eq!(ns.readlink(right).unwrap(), b"right-target".to_vec());
        assert_eq!(
            ns.readlink_at(ROOT_INODE, "left").unwrap(),
            b"right-target".to_vec()
        );
        assert_eq!(
            ns.readlink_at(ROOT_INODE, "right").unwrap(),
            b"left-target".to_vec()
        );
    }

    #[test]
    fn rename_exchange_same_name_noop() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "same", test_file_attrs(0))
            .unwrap();

        ns.rename_with_flags(ROOT_INODE, "same", ROOT_INODE, "same", RENAME_EXCHANGE)
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "same").unwrap(), Some(file));
        assert!(ns.get_attrs(file).is_some());
    }

    #[test]
    fn rename_exchange_swaps_file_and_nonempty_directory() {
        let ns = test_ns();
        let parent = ns
            .create_dir(ROOT_INODE, "parent", test_dir_attrs(0))
            .unwrap();
        let source_file = ns
            .create_file(ROOT_INODE, "source-file", test_file_attrs(0))
            .unwrap();
        let target_dir = ns
            .create_dir(parent, "target-dir", test_dir_attrs(0))
            .unwrap();
        let child = ns
            .create_file(target_dir, "child", test_file_attrs(0))
            .unwrap();

        ns.rename_with_flags(
            ROOT_INODE,
            "source-file",
            parent,
            "target-dir",
            RENAME_EXCHANGE,
        )
        .unwrap();

        assert_eq!(
            ns.lookup(ROOT_INODE, "source-file").unwrap(),
            Some(target_dir)
        );
        assert_eq!(ns.lookup(parent, "target-dir").unwrap(), Some(source_file));
        assert_eq!(ns.resolve(Path::new("/source-file/child")).unwrap(), child);
        assert_eq!(
            ns.resolve(Path::new("/source-file/..")).unwrap(),
            ROOT_INODE
        );
        assert!(ns.get_attrs(source_file).is_some());
        assert!(ns.get_attrs(target_dir).is_some());
    }

    #[test]
    fn rename_overwrite_symlink_removes_replaced_target() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        let link = ns
            .create_symlink(ROOT_INODE, "link", b"old-target")
            .unwrap();

        ns.rename(ROOT_INODE, "file", ROOT_INODE, "link").unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "link").unwrap(), Some(file));
        assert_eq!(ns.readlink(link), Err(NamespaceError::InodeNotFound));
    }

    #[test]
    fn rename_overwrite_file_across_dirs_replaces_target_only() {
        let ns = test_ns();
        let src_dir = ns.create_dir(ROOT_INODE, "src", test_dir_attrs(0)).unwrap();
        let dst_dir = ns.create_dir(ROOT_INODE, "dst", test_dir_attrs(0)).unwrap();
        let src_file = ns
            .create_file(src_dir, "source", test_file_attrs(0))
            .unwrap();
        let dst_file = ns
            .create_file(dst_dir, "target", test_file_attrs(0))
            .unwrap();

        ns.rename(src_dir, "source", dst_dir, "target").unwrap();

        assert_eq!(ns.lookup(src_dir, "source").unwrap(), None);
        assert_eq!(ns.lookup(dst_dir, "target").unwrap(), Some(src_file));
        assert!(ns.get_attrs(src_file).is_some());
        assert!(ns.get_attrs(dst_file).is_none());
    }

    #[test]
    fn rename_file_over_empty_directory_fails_and_preserves_both() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "file", ROOT_INODE, "dir"),
            Err(NamespaceError::IsDirectory)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "file").unwrap(), Some(file));
        assert_eq!(ns.lookup(ROOT_INODE, "dir").unwrap(), Some(dir));
        assert!(ns.get_attrs(file).is_some());
        assert!(ns.get_attrs(dir).is_some());
    }

    #[test]
    fn rename_file_over_nonempty_directory_fails_and_preserves_both() {
        let ns = test_ns();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();
        let child = ns.create_file(dir, "child", test_file_attrs(0)).unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "file", ROOT_INODE, "dir"),
            Err(NamespaceError::IsDirectory)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "file").unwrap(), Some(file));
        assert_eq!(ns.lookup(ROOT_INODE, "dir").unwrap(), Some(dir));
        assert_eq!(ns.lookup(dir, "child").unwrap(), Some(child));
    }

    #[test]
    fn rename_directory_over_file_fails_and_preserves_both() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();
        let file = ns
            .create_file(ROOT_INODE, "file", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "dir", ROOT_INODE, "file"),
            Err(NamespaceError::NotDirectory)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "dir").unwrap(), Some(dir));
        assert_eq!(ns.lookup(ROOT_INODE, "file").unwrap(), Some(file));
        assert!(ns.get_attrs(dir).is_some());
        assert!(ns.get_attrs(file).is_some());
    }

    #[test]
    fn rename_directory_over_empty_directory_replaces_target() {
        let ns = test_ns();
        let source = ns
            .create_dir(ROOT_INODE, "source", test_dir_attrs(0))
            .unwrap();
        let child = ns.create_file(source, "child", test_file_attrs(0)).unwrap();
        let replaced = ns
            .create_dir(ROOT_INODE, "target", test_dir_attrs(0))
            .unwrap();

        ns.rename(ROOT_INODE, "source", ROOT_INODE, "target")
            .unwrap();

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), None);
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(source));
        assert_eq!(ns.resolve(Path::new("/target/child")).unwrap(), child);
        assert_eq!(ns.resolve(Path::new("/target/..")).unwrap(), ROOT_INODE);
        assert!(ns.get_attrs(source).is_some());
        assert!(ns.get_attrs(replaced).is_none());
    }

    #[test]
    fn rename_directory_updates_dotdot() {
        let ns = test_ns();
        let d1 = ns.create_dir(ROOT_INODE, "d1", test_dir_attrs(0)).unwrap();
        let d2 = ns.create_dir(ROOT_INODE, "d2", test_dir_attrs(0)).unwrap();
        let f = ns.create_file(d1, "nested", test_file_attrs(0)).unwrap();
        ns.rename(d1, "nested", d2, "moved").unwrap();
        assert_eq!(ns.lookup(d2, "moved").unwrap(), Some(f));
    }

    #[test]
    fn rename_directory_into_own_descendant_is_rejected() {
        let ns = test_ns();
        let parent = ns
            .create_dir(ROOT_INODE, "parent", test_dir_attrs(0))
            .unwrap();
        let child = ns.create_dir(parent, "child", test_dir_attrs(0)).unwrap();
        let leaf = ns.create_file(child, "leaf", test_file_attrs(0)).unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "parent", child, "moved"),
            Err(NamespaceError::RenameCycle)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "parent").unwrap(), Some(parent));
        assert_eq!(ns.lookup(parent, "child").unwrap(), Some(child));
        assert_eq!(ns.lookup(child, "moved").unwrap(), None);
        assert_eq!(ns.resolve(Path::new("/parent/child/leaf")).unwrap(), leaf);
        assert_eq!(ns.resolve(Path::new("/parent/child/..")).unwrap(), parent);
    }

    #[test]
    fn rename_directory_into_itself_is_rejected() {
        let ns = test_ns();
        let dir = ns.create_dir(ROOT_INODE, "dir", test_dir_attrs(0)).unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "dir", dir, "moved"),
            Err(NamespaceError::RenameCycle)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "dir").unwrap(), Some(dir));
        assert_eq!(ns.lookup(dir, "moved").unwrap(), None);
    }

    #[test]
    fn rename_nonexistent_source() {
        let ns = test_ns();
        assert_eq!(
            ns.rename(ROOT_INODE, "nope", ROOT_INODE, "dest"),
            Err(NamespaceError::NotFound)
        );
    }

    #[test]
    fn rename_nonexistent_new_parent() {
        let ns = test_ns();
        let _f = ns.create_file(ROOT_INODE, "f", test_file_attrs(0)).unwrap();
        assert_eq!(
            ns.rename(ROOT_INODE, "f", 9999, "dest"),
            Err(NamespaceError::InodeNotFound)
        );
    }

    #[test]
    fn rename_same_name_noop() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "x", test_file_attrs(0)).unwrap();
        assert!(ns.rename(ROOT_INODE, "x", ROOT_INODE, "x").is_ok());
    }

    #[test]
    fn rename_directory_over_nonempty_directory_fails_and_preserves_both() {
        let ns = test_ns();
        let source = ns
            .create_dir(ROOT_INODE, "source", test_dir_attrs(0))
            .unwrap();
        let source_child = ns
            .create_file(source, "source-child", test_file_attrs(0))
            .unwrap();
        let target = ns
            .create_dir(ROOT_INODE, "target", test_dir_attrs(0))
            .unwrap();
        let target_child = ns
            .create_file(target, "target-child", test_file_attrs(0))
            .unwrap();

        assert_eq!(
            ns.rename(ROOT_INODE, "source", ROOT_INODE, "target"),
            Err(NamespaceError::NotEmpty)
        );

        assert_eq!(ns.lookup(ROOT_INODE, "source").unwrap(), Some(source));
        assert_eq!(ns.lookup(ROOT_INODE, "target").unwrap(), Some(target));
        assert_eq!(
            ns.lookup(source, "source-child").unwrap(),
            Some(source_child)
        );
        assert_eq!(
            ns.lookup(target, "target-child").unwrap(),
            Some(target_child)
        );
        assert_eq!(ns.resolve(Path::new("/source/..")).unwrap(), ROOT_INODE);
        assert_eq!(ns.resolve(Path::new("/target/..")).unwrap(), ROOT_INODE);
        assert!(ns.get_attrs(source).is_some());
        assert!(ns.get_attrs(target).is_some());
    }

    // ------------------------------------------------------------------
    // Error tests
    // ------------------------------------------------------------------

    #[test]
    fn create_file_under_nonexistent_parent() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(9999, "f", test_file_attrs(0)),
            Err(NamespaceError::InodeNotFound)
        );
    }

    #[test]
    fn create_dir_under_nonexistent_parent() {
        let ns = test_ns();
        assert_eq!(
            ns.create_dir(9999, "d", test_dir_attrs(0)),
            Err(NamespaceError::InodeNotFound)
        );
    }

    #[test]
    fn create_with_empty_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(ROOT_INODE, "", test_file_attrs(0)),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn create_with_dot_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(ROOT_INODE, ".", test_file_attrs(0)),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn create_with_dotdot_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(ROOT_INODE, "..", test_file_attrs(0)),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn create_with_slash_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(ROOT_INODE, "bad/name", test_file_attrs(0)),
            Err(NamespaceError::InvalidName)
        );
    }

    #[test]
    fn create_with_nul_name() {
        let ns = test_ns();
        assert_eq!(
            ns.create_file(ROOT_INODE, "bad\0name", test_file_attrs(0)),
            Err(NamespaceError::InvalidName)
        );
    }

    // ------------------------------------------------------------------
    // EntryType tests
    // ------------------------------------------------------------------

    #[test]
    fn entry_type_roundtrip() {
        assert_eq!(EntryType::from_kind(KIND_DIR), Some(EntryType::Directory));
        assert_eq!(EntryType::from_kind(KIND_FILE), Some(EntryType::File));
        assert_eq!(EntryType::from_kind(KIND_SYMLINK), Some(EntryType::Symlink));
        assert_eq!(EntryType::from_kind(99), None);
        assert_eq!(EntryType::Directory.to_kind(), KIND_DIR);
        assert_eq!(EntryType::File.to_kind(), KIND_FILE);
        assert_eq!(EntryType::Symlink.to_kind(), KIND_SYMLINK);
    }

    // ------------------------------------------------------------------
    // ReadDir tests
    // ------------------------------------------------------------------

    #[test]
    fn readdir_empty_root() {
        let ns = test_ns();
        let (entries, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        // Root has . and .. entries.
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn readdir_with_entries() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "a", test_file_attrs(0)).unwrap();
        ns.create_file(ROOT_INODE, "b", test_file_attrs(0)).unwrap();
        let (entries, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        // . + .. + a + b = 4
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn readdir_nonexistent_inode() {
        let ns = test_ns();
        assert_eq!(
            ns.read_dir(999, tidefs_dir_index::DirCookie(0)),
            Err(NamespaceError::InodeNotFound)
        );
    }

    #[test]
    fn readdir_cookie_pagination_first_page() {
        let ns = test_ns();
        // Create 5 files in root (DirIndex micro-list threshold is 6).
        for i in 0..5u64 {
            let name = format!("page_{i:02}");
            ns.create_file(ROOT_INODE, &name, test_file_attrs(0))
                .unwrap();
        }
        // First call from START: should return . + .. + up to 5 entries.
        let (entries, next_skip) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        // . + .. + 5 files = 7 entries.
        assert_eq!(entries.len(), 7);
        // The skip must be non-zero when entries were emitted.
        assert_ne!(
            next_skip,
            tidefs_dir_index::DirCookie::START,
            "skip must be non-zero after first page"
        );
    }

    #[test]
    fn readdir_cookie_resume_from_middle() {
        let ns = test_ns();
        for i in 0..5u64 {
            let name = format!("mid_{i:02}");
            ns.create_file(ROOT_INODE, &name, test_file_attrs(0))
                .unwrap();
        }
        // First call: get entries and cookie.
        // Root dir has . + .. pre-populated, plus 5 files = 7 entries.
        let (entries, next_skip) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        assert_eq!(entries.len(), 7, ". + .. + 5 files = 7 entries");
        assert_ne!(
            next_skip,
            tidefs_dir_index::DirCookie::START,
            "skip must be non-zero"
        );

        // Resume from the returned cookie: should get empty result.
        let (remaining, next_skip2) = ns.read_dir(ROOT_INODE, next_skip).unwrap();
        assert!(
            remaining.is_empty(),
            "resume after last entry returns empty"
        );
        // When no entries remain, next_cookie equals the input cookie.
        // After consuming all entries, next call returns empty with same skip count.
        assert_eq!(
            next_skip2, next_skip,
            "skip unchanged when no entries remain"
        );
    }

    #[test]
    fn readdir_cookie_pagination_many_entries() {
        let ns = test_ns();
        // Create enough entries to test the 128-entry page limit.
        // Root dir has . + .. pre-populated = 2 entries.
        for i in 0..200u64 {
            let name = format!("many_{i:03}");
            ns.create_file(ROOT_INODE, &name, test_file_attrs(0))
                .unwrap();
        }
        // First page: 128 entries (includes . and ..).
        let (page1, skip1) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        assert_eq!(page1.len(), 128, "first page: 128 entries");
        assert_ne!(skip1, tidefs_dir_index::DirCookie::START);

        // Second page: 202 - 128 = 74 remaining entries.
        let (page2, skip2) = ns.read_dir(ROOT_INODE, skip1).unwrap();
        assert_eq!(page2.len(), 74, "second page: 74 remaining entries");
        assert_ne!(skip2, skip1, "skip advances between pages");

        // Third page: empty.
        let (page3, skip3) = ns.read_dir(ROOT_INODE, skip2).ok().unwrap();
        assert!(page3.is_empty());
        assert_eq!(skip3, skip2, "skip unchanged on empty page");
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_load_rebuilds_inode_attrs_past_first_directory_window() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let mut late_inode = 0;

        for i in 0..200u64 {
            let name = format!("persist_{i:03}");
            let inode = ns
                .create_file(ROOT_INODE, &name, test_file_attrs(0))
                .unwrap();
            if i == 199 {
                late_inode = inode;
            }
        }

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read-only import should not retain the root directory index"
        );

        assert_eq!(
            loaded.lookup(ROOT_INODE, "persist_199").unwrap(),
            Some(late_inode)
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "root lookup should use persisted pages without loading root"
        );
        assert_eq!(loaded.get_attrs(late_inode).unwrap().inode, late_inode);

        let mut cookie = tidefs_dir_index::DirCookie::START;
        let mut names = Vec::new();
        loop {
            let (entries, next_cookie) = loaded.read_dir(ROOT_INODE, cookie).unwrap();
            if entries.is_empty() {
                break;
            }
            names.extend(entries.into_iter().map(|entry| entry.name));
            if next_cookie == cookie {
                break;
            }
            cookie = next_cookie;
        }

        assert_eq!(names.len(), 202);
        assert!(names.iter().any(|name| name == b"persist_199"));
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "root read_dir should use persisted pages without loading root"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_load_streams_manifest_dirs_and_lazily_loads_children() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let mut target_dir = 0;
        let mut late_child = 0;

        for dir_idx in 0..6u64 {
            let dir_name = format!("dir_{dir_idx:03}");
            let dir = ns
                .create_dir(ROOT_INODE, &dir_name, test_dir_attrs(0))
                .unwrap();
            if dir_idx == 5 {
                target_dir = dir;
            }
            for file_idx in 0..160u64 {
                let file_name = format!("file_{file_idx:03}");
                let inode = ns.create_file(dir, &file_name, test_file_attrs(0)).unwrap();
                if dir_idx == 5 && file_idx == 159 {
                    late_child = inode;
                }
            }
        }

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();

        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "import should not retain directory indexes initially"
        );
        assert_eq!(loaded.get_attrs(late_child).unwrap().inode, late_child);
        assert_eq!(
            loaded.lookup(ROOT_INODE, "dir_005").unwrap(),
            Some(target_dir)
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "root lookup must not eagerly load directory indexes"
        );
        assert_eq!(
            loaded.lookup(target_dir, "file_159").unwrap(),
            Some(late_child)
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read-only child lookup should use persisted pages without loading the child"
        );
        assert_eq!(
            loaded
                .resolve(std::path::Path::new("/dir_005/file_159"))
                .unwrap(),
            late_child
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "path resolution should not retain the child directory for read-only lookup"
        );

        let (entries, next_cookie) = loaded
            .read_dir(target_dir, tidefs_dir_index::DirCookie::START)
            .unwrap();
        assert_eq!(entries.len(), 128);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[127].name, b"file_125");
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read_dir should use persisted pages without loading the child"
        );

        let (tail, tail_next) = loaded.read_dir(target_dir, next_cookie).unwrap();
        assert_eq!(tail.len(), 34);
        assert_eq!(tail[0].name, b"file_126");
        assert_eq!(tail[33].name, b"file_159");
        assert_eq!(tidefs_dir_index::format::dir_cookie_skip(tail_next.0), 162);
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read_dir pagination should keep the child unloaded"
        );

        let (empty, empty_next) = loaded.read_dir(target_dir, tail_next).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty_next, tail_next);
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read_dir exhaustion should keep the child unloaded"
        );

        let created = loaded
            .create_file(ROOT_INODE, "root_mutation_loads", test_file_attrs(0))
            .unwrap();
        assert_eq!(
            loaded.lookup(ROOT_INODE, "root_mutation_loads").unwrap(),
            Some(created)
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            1,
            "root mutation should lazy-load only the mutable root index"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_flush_preserves_unloaded_manifest_dirs() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let cold_dir = ns
            .create_dir(ROOT_INODE, "cold", test_dir_attrs(0))
            .unwrap();
        let leaf = ns
            .create_file(cold_dir, "leaf", test_file_attrs(0))
            .unwrap();

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "lazy import should keep all directory indexes unloaded"
        );

        loaded.flush(&mut store).unwrap();
        let manifest = tidefs_dir_index::persistent::read_namespace_manifest(&store).unwrap();
        assert!(
            manifest.contains(&cold_dir),
            "flush must preserve unloaded manifest directories"
        );

        let reloaded = Namespace::load(&store).unwrap();
        assert_eq!(reloaded.lookup(cold_dir, "leaf").unwrap(), Some(leaf));
        assert_eq!(
            reloaded.loaded_dir_count_for_test(),
            0,
            "store-backed lookup after manifest-preserving flush should not load a directory"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_load_rejects_manifest_missing_root() {
        let (_tmp, mut store) = open_object_store();

        tidefs_dir_index::persistent::write_namespace_manifest(&mut store, &[42]).unwrap();

        assert!(matches!(
            Namespace::load(&store),
            Err(NamespaceError::NotFound)
        ));
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_load_rejects_manifest_root_without_pages() {
        let (_tmp, mut store) = open_object_store();

        tidefs_dir_index::persistent::write_namespace_manifest(&mut store, &[ROOT_INODE]).unwrap();

        assert!(matches!(
            Namespace::load(&store),
            Err(NamespaceError::NotFound)
        ));
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_flush_drops_removed_manifest_dirs() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let doomed = ns
            .create_dir(ROOT_INODE, "doomed", test_dir_attrs(0))
            .unwrap();

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        loaded.unlink(ROOT_INODE, "doomed").unwrap();
        loaded.flush(&mut store).unwrap();

        let manifest = tidefs_dir_index::persistent::read_namespace_manifest(&store).unwrap();
        assert!(
            !manifest.contains(&doomed),
            "removed directory inode must not remain in the manifest"
        );

        let reloaded = Namespace::load(&store).unwrap();
        assert_eq!(reloaded.lookup(ROOT_INODE, "doomed").unwrap(), None);
        assert!(
            reloaded.get_attrs(doomed).is_none(),
            "removed directory attrs must not be resurrected from stale pages"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_rename_cycle_check_keeps_cold_ancestors_unloaded() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let source = ns
            .create_dir(ROOT_INODE, "source", test_dir_attrs(0))
            .unwrap();
        let cold = ns
            .create_dir(ROOT_INODE, "cold", test_dir_attrs(0))
            .unwrap();
        let a = ns.create_dir(cold, "a", test_dir_attrs(0)).unwrap();
        let b = ns.create_dir(a, "b", test_dir_attrs(0)).unwrap();
        let leaf = ns.create_dir(b, "leaf", test_dir_attrs(0)).unwrap();

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read-only import should not load any directory indexes"
        );

        loaded.rename(ROOT_INODE, "source", leaf, "moved").unwrap();

        assert_eq!(loaded.lookup(leaf, "moved").unwrap(), Some(source));
        assert_eq!(
            loaded.lookup(b, "leaf").unwrap(),
            Some(leaf),
            "cold ancestor directory should still be served from persisted pages"
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            3,
            "rename should retain only root, destination parent, and moved directory"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_rename_replace_empty_target_keeps_cold_target_unloaded() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let source = ns
            .create_dir(ROOT_INODE, "source", test_dir_attrs(0))
            .unwrap();
        let target = ns
            .create_dir(ROOT_INODE, "target", test_dir_attrs(0))
            .unwrap();

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read-only import should not load any directory indexes"
        );

        loaded
            .rename(ROOT_INODE, "source", ROOT_INODE, "target")
            .unwrap();

        assert_eq!(loaded.lookup(ROOT_INODE, "target").unwrap(), Some(source));
        assert!(
            loaded.get_attrs(target).is_none(),
            "replaced cold target directory inode should be removed"
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            2,
            "rename should retain root and moved directory, not the replaced target"
        );

        loaded.flush(&mut store).unwrap();
        let manifest = tidefs_dir_index::persistent::read_namespace_manifest(&store).unwrap();
        assert!(
            !manifest.contains(&target),
            "replaced cold target directory must be pruned from the manifest"
        );
    }

    #[cfg(feature = "persistent-dir-index")]
    #[test]
    fn persistent_rename_replace_nonempty_target_rejects_without_loading_target() {
        let (_tmp, mut store) = open_object_store();
        let ns = test_ns();
        let source = ns
            .create_dir(ROOT_INODE, "source", test_dir_attrs(0))
            .unwrap();
        let target = ns
            .create_dir(ROOT_INODE, "target", test_dir_attrs(0))
            .unwrap();
        let child = ns.create_file(target, "child", test_file_attrs(0)).unwrap();

        ns.flush(&mut store).unwrap();
        let loaded = Namespace::load(&store).unwrap();
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            0,
            "read-only import should not load any directory indexes"
        );

        assert_eq!(
            loaded.rename(ROOT_INODE, "source", ROOT_INODE, "target"),
            Err(NamespaceError::NotEmpty)
        );

        assert_eq!(loaded.lookup(ROOT_INODE, "source").unwrap(), Some(source));
        assert_eq!(loaded.lookup(ROOT_INODE, "target").unwrap(), Some(target));
        assert_eq!(
            loaded.lookup(target, "child").unwrap(),
            Some(child),
            "cold target contents should remain readable through store-backed lookup"
        );
        assert_eq!(
            loaded.loaded_dir_count_for_test(),
            2,
            "non-empty rejection should retain root and moved directory, not the target"
        );
    }

    #[test]
    fn readdir_cookie_start_zero_restarts() {
        let ns = test_ns();
        ns.create_file(ROOT_INODE, "x", test_file_attrs(0)).unwrap();
        ns.create_file(ROOT_INODE, "y", test_file_attrs(0)).unwrap();

        // Read all.
        let (all1, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        // Read again from START: should get same entries.
        let (all2, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();
        assert_eq!(all1.len(), all2.len());
        for (a, b) in all1.iter().zip(all2.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.inode_id, b.inode_id);
        }
    }

    #[test]
    fn readdirplus_attr_resolution_through_get_attrs() {
        // Simulates the readdirplus dispatch path: iterate entries via
        // read_dir, then resolve each entry's attributes via get_attrs.
        let ns = test_ns();
        let file_ino = ns
            .create_file(ROOT_INODE, "config.toml", test_file_attrs(0))
            .unwrap();
        ns.create_dir(ROOT_INODE, "lib", test_dir_attrs(0)).unwrap();

        // Update file attributes to verify readdirplus sees current values.
        let mut updated = test_file_attrs(0);
        updated.size = 4096;
        updated.nlink = 3;
        ns.update_attrs(file_ino, updated.clone()).unwrap();

        let (entries, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();

        // . + .. + config.toml + lib = 4 entries.
        assert_eq!(entries.len(), 4);

        for entry in &entries {
            if entry.name == b"." || entry.name == b".." {
                continue;
            }
            let attrs = ns
                .get_attrs(entry.inode_id)
                .expect("get_attrs for dir entry");
            if entry.name == b"config.toml" {
                assert_eq!(attrs.size, 4096, "readdirplus should see updated size");
                assert_eq!(attrs.nlink, 3, "readdirplus should see updated nlink");
            }
            // Verify entry name matches the inode's namespace entry.
            let kind = if entry.name.contains(&b'.') {
                KIND_FILE
            } else {
                KIND_DIR
            };
            assert_eq!(entry.kind, kind);
        }
    }

    #[test]
    fn readdirplus_unresolvable_entry_gracefully_skipped() {
        // Entries whose attributes cannot be resolved (e.g. inode removed
        // between read_dir and get_attrs) should be silently skipped,
        // matching the FUSE readdirplus contract.
        let ns = test_ns();
        let _file_ino = ns
            .create_file(ROOT_INODE, "ephemeral", test_file_attrs(0))
            .unwrap();
        ns.create_file(ROOT_INODE, "permanent", test_file_attrs(0))
            .unwrap();

        let (entries, _) = ns
            .read_dir(ROOT_INODE, tidefs_dir_index::DirCookie(0))
            .unwrap();

        let resolvable_count = entries
            .iter()
            .filter(|e| ns.get_attrs(e.inode_id).is_some())
            .count();
        // All entries (including . and ..) should have resolveable attrs
        // in this test since nothing is unlinked.
        assert_eq!(
            resolvable_count,
            entries.len(),
            "all entries should be resolvable"
        );
    }

    // ------------------------------------------------------------------
    // Concurrent resolution stress test
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_resolution_stress() {
        let ns = std::sync::Arc::new(test_ns());

        // Build a directory tree: /a/b/c, /a/d/e, /x/y/z, /x/y/w
        let dir_a = ns.create_dir(ROOT_INODE, "a", test_dir_attrs(0)).unwrap();
        let dir_b = ns.create_dir(dir_a, "b", test_dir_attrs(0)).unwrap();
        let _file_c = ns.create_file(dir_b, "c", test_file_attrs(0)).unwrap();

        let dir_d = ns.create_dir(dir_a, "d", test_dir_attrs(0)).unwrap();
        let _file_e = ns.create_file(dir_d, "e", test_file_attrs(0)).unwrap();

        let dir_x = ns.create_dir(ROOT_INODE, "x", test_dir_attrs(0)).unwrap();
        let dir_y = ns.create_dir(dir_x, "y", test_dir_attrs(0)).unwrap();
        let _file_z = ns.create_file(dir_y, "z", test_file_attrs(0)).unwrap();
        let _file_w = ns.create_file(dir_y, "w", test_file_attrs(0)).unwrap();

        // Symlink: /link1 -> a/b, /link2 -> link1/c
        ns.create_symlink(ROOT_INODE, "link1", b"a/b").unwrap();
        ns.create_symlink(ROOT_INODE, "link2", b"link1/c").unwrap();

        let paths = vec![
            "/a/b/c",
            "/a/d/e",
            "/x/y/z",
            "/x/y/w",
            "/a",
            "/x/y",
            "/",
            "/link1",
            "/link2",
            "/a/b/../d/e",
        ];

        let thread_count = 8;
        let iterations = 50;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(thread_count));
        let mut handles = Vec::new();

        for _tid in 0..thread_count {
            let ns = std::sync::Arc::clone(&ns);
            let paths = paths.clone();
            let barrier = std::sync::Arc::clone(&barrier);

            handles.push(std::thread::spawn(move || {
                barrier.wait();

                for _i in 0..iterations {
                    for path_str in &paths {
                        let path = std::path::Path::new(path_str);
                        let result = ns.resolve(path);
                        assert!(
                            result.is_ok(),
                            "thread failed to resolve {path_str}: {result:?}"
                        );
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }
    // ── Orphan index / O_TMPFILE integration tests ──────────────────

    #[test]
    fn orphan_index_starts_empty() {
        let ns = Namespace::new();
        assert_eq!(ns.orphan_count(), 0);
    }

    #[test]
    fn track_anonymous_inode_inserts_into_orphan_index() {
        let ns = Namespace::new();
        assert!(ns.track_anonymous_inode(10, 100, 1234, 0).unwrap());
        assert_eq!(ns.orphan_count(), 1);
    }

    #[test]
    fn track_anonymous_inode_duplicate_returns_false() {
        let ns = Namespace::new();
        assert!(ns.track_anonymous_inode(1, 10, 100, 0).unwrap());
        assert!(!ns.track_anonymous_inode(1, 20, 200, 0).unwrap());
        assert_eq!(ns.orphan_count(), 1);
    }

    #[test]
    fn on_orphan_link_removes_from_index() {
        let ns = Namespace::new();
        ns.track_anonymous_inode(5, 50, 999, 0).unwrap();
        assert_eq!(ns.orphan_count(), 1);
        assert!(ns.on_orphan_link(5, 0).unwrap());
        assert_eq!(ns.orphan_count(), 0);
    }

    #[test]
    fn on_orphan_link_nonexistent_returns_false() {
        let ns = Namespace::new();
        assert!(!ns.on_orphan_link(999, 0).unwrap());
    }

    #[test]
    fn reap_tmpfile_timeouts_uses_process_liveness() {
        let ns = Namespace::new();
        // PID 1 (init) is always alive
        ns.track_anonymous_inode(10, 100, 1, 0).unwrap();
        let reap = ns.reap_tmpfile_timeouts();
        assert!(reap.is_empty(), "PID 1 should be alive");
    }

    #[test]
    fn reap_tmpfile_timeouts_detects_dead_process() {
        let ns = Namespace::new();
        // Very high PID that does not exist
        ns.track_anonymous_inode(20, 200, 0xFFFFFD, 0).unwrap();
        let reap = ns.reap_tmpfile_timeouts();
        assert_eq!(reap, vec![20]);
    }

    #[test]
    fn track_link_reap_cycle() {
        let ns = Namespace::new();
        // Create tmpfile
        assert!(ns.track_anonymous_inode(100, 1000, 42, 0).unwrap());
        assert_eq!(ns.orphan_count(), 1);
        // Link it
        assert!(ns.on_orphan_link(100, 0).unwrap());
        assert_eq!(ns.orphan_count(), 0);
        // Link again is no-op
        assert!(!ns.on_orphan_link(100, 0).unwrap());
    }

    #[test]
    fn multiple_tmpfiles_mixed_reap() {
        let ns = Namespace::new();
        // PID 1 is alive
        ns.track_anonymous_inode(1, 10, 1, 0).unwrap();
        // Dead PID
        ns.track_anonymous_inode(2, 20, 0xFFFFFC, 0).unwrap();
        // Zero PID (old recovery) is always reaped
        ns.track_anonymous_inode(3, 30, 0, 0).unwrap();
        let reap = ns.reap_tmpfile_timeouts();
        // Both dead-PID and zero-PID should be reaped
        assert_eq!(reap.len(), 2);
        assert!(reap.contains(&2));
        assert!(reap.contains(&3));
        // PID 1 should not be reaped
        assert!(!reap.contains(&1));
    }

    // ------------------------------------------------------------------
    // mknod special node kind / rdev preservation tests (#6635)
    // ------------------------------------------------------------------

    #[test]
    fn mknod_fifo_preserves_kind_and_mode() {
        let ns = test_ns();
        let parent = ROOT_INODE;
        let ino = ns.mknod(parent, "testpipe", 0o010644, 0).unwrap();
        let attrs = ns.get_attrs(ino).unwrap();
        let file_type = attrs.mode & 0o170000;
        assert_eq!(file_type, 0o010000, "mode must be S_IFIFO");
        assert_eq!(attrs.rdev, 0);
        let looked_up = ns.lookup(parent, "testpipe").unwrap().unwrap();
        assert_eq!(looked_up, ino);
    }

    #[test]
    fn mknod_char_device_preserves_kind_and_rdev() {
        let ns = test_ns();
        let parent = ROOT_INODE;
        let rdev: u32 = 0x0103; // major 1, minor 3 (/dev/null)
        let ino = ns.mknod(parent, "nulldev", 0o020644, rdev).unwrap();
        let attrs = ns.get_attrs(ino).unwrap();
        let file_type = attrs.mode & 0o170000;
        assert_eq!(file_type, 0o020000, "mode must be S_IFCHR");
        assert_eq!(attrs.rdev, rdev, "rdev must be preserved");
    }

    #[test]
    fn mknod_block_device_preserves_kind_and_rdev() {
        let ns = test_ns();
        let parent = ROOT_INODE;
        let rdev: u32 = 0x0801; // major 8, minor 1 (/dev/sda1)
        let ino = ns.mknod(parent, "diskpart", 0o060644, rdev).unwrap();
        let attrs = ns.get_attrs(ino).unwrap();
        let file_type = attrs.mode & 0o170000;
        assert_eq!(file_type, 0o060000, "mode must be S_IFBLK");
        assert_eq!(attrs.rdev, rdev, "rdev must be preserved");
    }

    #[test]
    fn mknod_socket_preserves_kind() {
        let ns = test_ns();
        let parent = ROOT_INODE;
        let ino = ns.mknod(parent, "testsock", 0o140644, 0).unwrap();
        let attrs = ns.get_attrs(ino).unwrap();
        let file_type = attrs.mode & 0o170000;
        assert_eq!(file_type, 0o140000, "mode must be S_IFSOCK");
        assert_eq!(attrs.rdev, 0);
    }

    #[test]
    fn mknod_all_special_kinds_lookup_preserves_existence() {
        let ns = test_ns();
        let parent = ROOT_INODE;
        let names = ["fifo1", "chardev1", "blkdev1", "sock1"];
        ns.mknod(parent, names[0], 0o010644, 0).unwrap();
        ns.mknod(parent, names[1], 0o020644, 0x0103).unwrap();
        ns.mknod(parent, names[2], 0o060644, 0x0801).unwrap();
        ns.mknod(parent, names[3], 0o140644, 0).unwrap();
        for name in names {
            assert!(
                ns.lookup(parent, name).unwrap().is_some(),
                "special node '{name}' must be visible via lookup"
            );
        }
    }
}
