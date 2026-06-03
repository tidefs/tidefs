//! P5-02 FUSE namespace mutation worker pool (queue_class_2.namespace_mut)
//! and directory-stream readdir/readdirplus path.
//!
//! Part of the P5-02 classified multipool topology for the userspace FUSE runtime.
//! This seam family is one of 10 explicit crate boundaries that separate ingress,
//! scheduling, workers, reply commit, and maintenance so they do not blur
//! into one daemon blob.
//!
//! # Directory stream support (issue #2523)
//!
//! While the primary queue class is `namespace_mut` (create, unlink, rename, etc.),
//! the namespace worker also owns the directory-entry iteration path.  The kernel
//! READDIR/READDIRPLUS calls arrive on `queue_class_3.dir_stream`, but the actual
//! entry resolution — converting ordered dir-index entries into inode‑resolved
//! VFS `DirEntry` items — happens inside the namespace worker because it has
//! access to the inode table for attribute resolution.

use std::vec::Vec;

use tidefs_dir_index::{DirCookie, DirIndex, DirMicroEntry};

use crate::reply::{commit_rename_error, commit_rename_reply, commit_small_reply};
use tidefs_dir_index::{DirEntry, DirIndexError};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterReplyCommitRecord, PosixFilesystemAdapterRequestClass,
    PosixFilesystemAdapterRequestContextMirrorRecord,
};

/// Re-export all P5-02 request-queue types and runtime functions for this seam family.
pub const SEAM_FAMILY_DOC: &str = concat!("seam.", env!("CARGO_PKG_NAME"), ".    P5-02.v0");

// ── Namespace-mutation dispatch ──────────────────────────────────────────

#[must_use]
pub fn dispatch_namespace_mut(
    ctx: PosixFilesystemAdapterRequestContextMirrorRecord,
) -> PosixFilesystemAdapterRequestContextMirrorRecord {
    ctx
}

#[must_use]
pub fn is_namespace_mut_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    ctx.request_class == PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32()
}

#[must_use]
pub fn namespace_mut_shard_key(nodeid: u64) -> u64 {
    nodeid
}

// ── Namespace mutation worker helpers (issue #2538) ──────────────────────

/// Maximum POSIX path component length accepted by namespace mutation handlers.
pub const NS_NAME_MAX: usize = 255;

/// POSIX mode used for symbolic-link inodes.
pub const NS_SYMLINK_MODE: u32 = 0o120777;

/// Directory entry kind used by `tidefs-dir-index` for directories.
pub const NS_DIR_ENTRY_KIND_DIRECTORY: u32 = 0;

/// Directory entry kind used by `tidefs-dir-index` for regular files.
pub const NS_DIR_ENTRY_KIND_FILE: u32 = 1;

/// Directory entry kind used by `tidefs-dir-index` for symbolic links.
pub const NS_DIR_ENTRY_KIND_SYMLINK: u32 = 2;

/// POSIX errno values returned by [`NsOpError::errno`].
pub mod ns_errno {
    pub const EPERM: i32 = 1;
    pub const ENOENT: i32 = 2;
    pub const EIO: i32 = 5;
    pub const EEXIST: i32 = 17;
    pub const ENOTDIR: i32 = 20;
    pub const EISDIR: i32 = 21;
    pub const EINVAL: i32 = 22;
    pub const ENOSPC: i32 = 28;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ENOTEMPTY: i32 = 39;
    pub const EBADF: i32 = 9;
    pub const ENODATA: i32 = 61;
    pub const E2BIG: i32 = 7;
    pub const EOPNOTSUPP: i32 = 95;
    pub const ERANGE: i32 = 34;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NsNodeKind {
    Directory,
    File,
    Symlink,
    Other(u32),
}

impl NsNodeKind {
    #[must_use]
    pub const fn from_dir_entry_kind(kind: u32) -> Self {
        match kind {
            NS_DIR_ENTRY_KIND_DIRECTORY => Self::Directory,
            NS_DIR_ENTRY_KIND_FILE => Self::File,
            NS_DIR_ENTRY_KIND_SYMLINK => Self::Symlink,
            other => Self::Other(other),
        }
    }

    #[must_use]
    pub const fn dir_entry_kind(self) -> u32 {
        match self {
            Self::Directory => NS_DIR_ENTRY_KIND_DIRECTORY,
            Self::File => NS_DIR_ENTRY_KIND_FILE,
            Self::Symlink => NS_DIR_ENTRY_KIND_SYMLINK,
            Self::Other(kind) => kind,
        }
    }

    #[must_use]
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsInodeAttr {
    pub ino: u64,
    pub generation: u64,
    pub kind: NsNodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub rdev: u32,
}

use tidefs_types_posix_filesystem_adapter_core::rename_flags::{RENAME_EXCHANGE, RENAME_NOREPLACE};

const SUPPORTED_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Negative POSIX errno for `ENOENT`.
pub const RENAME_ERRNO_ENOENT: i32 = -2;

/// Negative POSIX errno for `EIO`.
pub const RENAME_ERRNO_EIO: i32 = -5;

/// Negative POSIX errno for `EEXIST`.
pub const RENAME_ERRNO_EEXIST: i32 = -17;

/// Negative POSIX errno for `EINVAL`.
pub const RENAME_ERRNO_EINVAL: i32 = -22;

/// Negative POSIX errno for `ENOTEMPTY`.
pub const RENAME_ERRNO_ENOTEMPTY: i32 = -39;

/// FUSE rename request payload after ingress has decoded the wire names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceRenameRequest<'a> {
    pub old_parent_ino: u64,
    pub old_name: &'a [u8],
    pub new_parent_ino: u64,
    pub new_name: &'a [u8],
    pub flags: NamespaceRenameFlags,
}

impl<'a> NamespaceRenameRequest<'a> {
    #[must_use]
    pub const fn new(
        old_parent_ino: u64,
        old_name: &'a [u8],
        new_parent_ino: u64,
        new_name: &'a [u8],
        flags: NamespaceRenameFlags,
    ) -> Self {
        Self {
            old_parent_ino,
            old_name,
            new_parent_ino,
            new_name,
            flags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsDirEntry {
    pub ino: u64,
    pub generation: u64,
    pub kind: NsNodeKind,
}

impl NsDirEntry {
    #[must_use]
    pub const fn new(ino: u64, generation: u64, kind: NsNodeKind) -> Self {
        Self {
            ino,
            generation,
            kind,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsCreateRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
    pub mode: u32,
    pub umask: u32,
    pub flags: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsMkdirRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
    pub mode: u32,
    pub umask: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Request for creating special files (FIFOs, sockets, devices) or regular files via mknod(2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsMknodRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
    pub mode: u32,
    pub umask: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsSymlinkRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
    pub target: &'a [u8],
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsLinkRequest<'a> {
    pub source: u64,
    pub parent: u64,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsRemoveRequest<'a> {
    pub parent: u64,
    pub name: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NsRemoveIntent {
    Unlink,
    Rmdir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsRemovePlan<'a> {
    pub intent: NsRemoveIntent,
    pub parent: NsInodeAttr,
    pub name: &'a [u8],
    pub dir_entry: NsDirEntry,
    pub target: NsInodeAttr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsCreateResult {
    pub child: NsInodeAttr,
    pub parent: NsInodeAttr,
    pub dir_entry: NsDirEntry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsRemoveResult {
    pub removed: NsInodeAttr,
    pub parent: NsInodeAttr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NsOpError {
    ParentNotFound,
    ParentNotDirectory,
    InodeNotFound,
    EntryNotFound,
    EntryAlreadyExists,
    NameInvalid,
    NameTooLong,
    NoSpace,
    DirectoryNotEmpty,
    IsDirectory,
    NotDirectory,
    NotSymlink,
    LinkUnderflow,
    PermissionDenied,
    Io,
    BadHandle,
    XattrNotFound,
    XattrExists,
    XattrTooLarge,
    XattrInvalidName,
    XattrNotSupported,
}

impl NsOpError {
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            Self::ParentNotFound | Self::InodeNotFound | Self::EntryNotFound => ns_errno::ENOENT,
            Self::ParentNotDirectory | Self::NotDirectory => ns_errno::ENOTDIR,
            Self::NotSymlink => ns_errno::EINVAL,
            Self::EntryAlreadyExists => ns_errno::EEXIST,
            Self::NameInvalid => ns_errno::EINVAL,
            Self::NameTooLong => ns_errno::ENAMETOOLONG,
            Self::NoSpace => ns_errno::ENOSPC,
            Self::DirectoryNotEmpty => ns_errno::ENOTEMPTY,
            Self::IsDirectory => ns_errno::EISDIR,
            Self::LinkUnderflow | Self::Io => ns_errno::EIO,
            Self::PermissionDenied => ns_errno::EPERM,
            Self::BadHandle => ns_errno::EBADF,
            Self::XattrNotFound => ns_errno::ENODATA,
            Self::XattrExists => ns_errno::EEXIST,
            Self::XattrTooLarge => ns_errno::E2BIG,
            Self::XattrInvalidName => ns_errno::EINVAL,
            Self::XattrNotSupported => ns_errno::EOPNOTSUPP,
        }
    }
}
// ── Xattr dispatch helpers ────────────────────────────────────────────────

/// `XATTR_CREATE`: fail if the attribute already exists.
pub const XATTR_CREATE: u32 = 1;

/// `XATTR_REPLACE`: fail if the attribute does not exist.
pub const XATTR_REPLACE: u32 = 2;

/// Maximum xattr name length (Linux limit).
pub const XATTR_NAME_MAX: usize = 255;

/// Maximum xattr value size (Linux limit: 64 KiB).
pub const XATTR_VALUE_MAX: usize = 64 * 1024;

/// Backend trait for extended-attribute storage consumed by xattr dispatch.
///
/// This is a local projection of what the `XattrStore` trait in
/// `tidefs-inode-attributes` delivers. Implementations bridge to the
/// in-memory store or a persistent on-disk store.
pub trait XattrBackend {
    /// Check whether `ino` exists.
    fn inode_exists(&self, ino: u64) -> bool;

    /// Get the value of an extended attribute.
    fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, NsOpError>;

    /// Set the value of an extended attribute.
    fn set_xattr(&self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), NsOpError>;

    /// List all attribute names for `ino`, returning null-separated name bytes.
    fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, NsOpError>;

    /// Remove the extended attribute `name` from `ino`.
    fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), NsOpError>;
}

/// Validate an xattr name: non-empty, no NUL, within length limit.
fn validate_xattr_name(name: &[u8]) -> Result<(), NsOpError> {
    if name.is_empty() || name.contains(&0) {
        return Err(NsOpError::XattrInvalidName);
    }
    if name.len() > XATTR_NAME_MAX {
        return Err(NsOpError::XattrInvalidName);
    }
    Ok(())
}

/// Validate an xattr value: within the 64 KiB size limit.
fn validate_xattr_value(value: &[u8]) -> Result<(), NsOpError> {
    if value.len() > XATTR_VALUE_MAX {
        return Err(NsOpError::XattrTooLarge);
    }
    Ok(())
}

/// Validate xattr set flags: must be 0, XATTR_CREATE, or XATTR_REPLACE.
fn validate_xattr_flags(flags: u32) -> Result<(), NsOpError> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
        return Err(NsOpError::XattrInvalidName);
    }
    Ok(())
}

/// Core getxattr logic: validate name, check inode, retrieve value.
pub fn handle_getxattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
) -> Result<Vec<u8>, NsOpError> {
    validate_xattr_name(name)?;
    if !backend.inode_exists(ino) {
        return Err(NsOpError::InodeNotFound);
    }
    backend.get_xattr(ino, name)
}

/// Core setxattr logic: validate inputs, check inode, apply with flags.
pub fn handle_setxattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
    value: &[u8],
    flags: u32,
) -> Result<(), NsOpError> {
    validate_xattr_name(name)?;
    validate_xattr_value(value)?;
    validate_xattr_flags(flags)?;
    if !backend.inode_exists(ino) {
        return Err(NsOpError::InodeNotFound);
    }
    backend.set_xattr(ino, name, value, flags)
}

/// Core listxattr logic: check inode, enumerate.
pub fn handle_listxattr<B: XattrBackend>(backend: &B, ino: u64) -> Result<Vec<u8>, NsOpError> {
    if !backend.inode_exists(ino) {
        return Err(NsOpError::InodeNotFound);
    }
    backend.list_xattr(ino)
}

/// Core removexattr logic: validate name, check inode, delete.
pub fn handle_removexattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
) -> Result<(), NsOpError> {
    validate_xattr_name(name)?;
    if !backend.inode_exists(ino) {
        return Err(NsOpError::InodeNotFound);
    }
    backend.remove_xattr(ino, name)
}

/// Dispatch a FUSE getxattr request.
pub fn dispatch_getxattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
) -> Result<Vec<u8>, NsOpError> {
    handle_getxattr(backend, ino, name)
}

/// Dispatch a FUSE setxattr request.
pub fn dispatch_setxattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
    value: &[u8],
    flags: u32,
) -> Result<(), NsOpError> {
    handle_setxattr(backend, ino, name, value, flags)
}

/// Dispatch a FUSE listxattr request.
pub fn dispatch_listxattr<B: XattrBackend>(backend: &B, ino: u64) -> Result<Vec<u8>, NsOpError> {
    handle_listxattr(backend, ino)
}

/// Dispatch a FUSE removexattr request.
pub fn dispatch_removexattr<B: XattrBackend>(
    backend: &B,
    ino: u64,
    name: &[u8],
) -> Result<(), NsOpError> {
    handle_removexattr(backend, ino, name)
}

// ── XattrStoreBridge ──────────────────────────────────────────────────────

/// Bridges [`tidefs_inode_attributes::xattr::MemXattrStore`] to the local
/// [`XattrBackend`] trait, translating `XattrError` into `NsOpError`.
///
/// Maintains a set of valid inode numbers to satisfy the `inode_exists`
/// query required by the dispatch handlers.
pub struct XattrStoreBridge {
    store: tidefs_inode_attributes::xattr::MemXattrStore,
    existing_inodes: std::collections::BTreeSet<u64>,
}

impl XattrStoreBridge {
    /// Create a bridge with an empty xattr store and the given set of
    /// known-valid inode numbers.
    #[must_use]
    pub fn new(existing_inodes: std::collections::BTreeSet<u64>) -> Self {
        Self {
            store: tidefs_inode_attributes::xattr::MemXattrStore::new(),
            existing_inodes,
        }
    }

    /// Return a shared reference to the underlying `MemXattrStore`.
    #[must_use]
    pub fn store(&self) -> &tidefs_inode_attributes::xattr::MemXattrStore {
        &self.store
    }

    /// Register an inode as existing (for use after inode allocation).
    pub fn add_inode(&mut self, ino: u64) {
        self.existing_inodes.insert(ino);
    }

    /// The number of inodes tracked.
    #[must_use]
    pub fn tracked_inodes(&self) -> usize {
        self.existing_inodes.len()
    }
}

impl XattrBackend for XattrStoreBridge {
    fn inode_exists(&self, ino: u64) -> bool {
        self.existing_inodes.contains(&ino)
    }

    fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, NsOpError> {
        use tidefs_inode_attributes::xattr::XattrStore;
        XattrStore::get(&self.store, ino, name).map_err(xattr_err_to_ns)
    }

    fn set_xattr(&self, ino: u64, name: &[u8], value: &[u8], flags: u32) -> Result<(), NsOpError> {
        use tidefs_inode_attributes::xattr::XattrStore;
        XattrStore::set(&self.store, ino, name, value, flags).map_err(xattr_err_to_ns)
    }

    fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, NsOpError> {
        use tidefs_inode_attributes::xattr::XattrStore;
        XattrStore::list(&self.store, ino).map_err(xattr_err_to_ns)
    }

    fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), NsOpError> {
        use tidefs_inode_attributes::xattr::XattrStore;
        XattrStore::remove(&self.store, ino, name).map_err(xattr_err_to_ns)
    }
}

/// Translate a [`tidefs_inode_attributes::xattr::XattrError`] into a local
/// [`NsOpError`].
#[must_use]
pub fn xattr_err_to_ns(err: tidefs_inode_attributes::xattr::XattrError) -> NsOpError {
    match err {
        tidefs_inode_attributes::xattr::XattrError::InvalidName
        | tidefs_inode_attributes::xattr::XattrError::NameTooLong => NsOpError::XattrInvalidName,
        tidefs_inode_attributes::xattr::XattrError::ValueTooLarge => NsOpError::XattrTooLarge,
        tidefs_inode_attributes::xattr::XattrError::UnsupportedNamespace => {
            NsOpError::XattrNotSupported
        }
        tidefs_inode_attributes::xattr::XattrError::AttrNotFound => NsOpError::XattrNotFound,
        tidefs_inode_attributes::xattr::XattrError::AttrExists => NsOpError::XattrExists,
        tidefs_inode_attributes::xattr::XattrError::PermissionDenied => NsOpError::PermissionDenied,
        tidefs_inode_attributes::xattr::XattrError::InodeXattrLimit => NsOpError::NoSpace,
        tidefs_inode_attributes::xattr::XattrError::Internal(_) => NsOpError::Io,
    }
}

/// Map a POSIX `mode` field to a [`NsNodeKind`] for mknod.
///
/// Regular files map to [`NsNodeKind::File`]; all other file types
/// (FIFO, socket, block device, character device) map to
/// [`NsNodeKind::Other`] with the file-type bits preserved.
#[must_use]
pub const fn mknod_node_kind(mode: u32) -> NsNodeKind {
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    if mode & S_IFMT == S_IFREG {
        NsNodeKind::File
    } else {
        NsNodeKind::Other(mode & S_IFMT)
    }
}

pub trait NamespaceMutationBackend {
    fn inode_attr(&self, ino: u64) -> Result<NsInodeAttr, NsOpError>;

    fn allocate_inode(
        &mut self,
        kind: NsNodeKind,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        rdev: u32,
    ) -> Result<NsInodeAttr, NsOpError>;

    fn lookup_child(&self, parent: u64, name: &[u8]) -> Result<Option<NsDirEntry>, NsOpError>;

    fn insert_child(
        &mut self,
        parent: u64,
        name: &[u8],
        child: NsDirEntry,
    ) -> Result<(), NsOpError>;

    fn remove_child(&mut self, parent: u64, name: &[u8]) -> Result<NsDirEntry, NsOpError>;

    fn init_dir(&mut self, ino: u64) -> Result<(), NsOpError>;

    fn set_symlink_target(&mut self, ino: u64, target: &[u8]) -> Result<(), NsOpError>;

    fn get_symlink_target(&self, ino: u64) -> Result<Vec<u8>, NsOpError>;

    fn is_dir_empty(&self, ino: u64) -> Result<bool, NsOpError>;

    fn increment_nlink(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError>;

    fn decrement_nlink(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError>;

    fn touch_parent(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError>;
}

#[must_use]
pub const fn apply_umask(mode: u32, umask: u32) -> u32 {
    mode & !umask
}

pub fn validate_namespace_name(name: &[u8]) -> Result<(), NsOpError> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&0) {
        return Err(NsOpError::NameInvalid);
    }
    if name.len() > NS_NAME_MAX {
        return Err(NsOpError::NameTooLong);
    }
    Ok(())
}

#[must_use]
pub fn dir_index_lookup_child(dir_index: &DirIndex, name: &[u8]) -> Option<NsDirEntry> {
    dir_index.lookup(name).map(|entry| {
        NsDirEntry::new(
            entry.inode_id,
            entry.generation,
            NsNodeKind::from_dir_entry_kind(entry.kind),
        )
    })
}

pub fn dir_index_insert_child(
    dir_index: &mut DirIndex,
    name: &[u8],
    child: NsDirEntry,
) -> Result<(), NsOpError> {
    dir_index
        .insert(
            name,
            child.ino,
            child.generation,
            child.kind.dir_entry_kind(),
        )
        .map_err(dir_index_error_to_ns_error)
}

pub fn dir_index_remove_child(
    dir_index: &mut DirIndex,
    name: &[u8],
) -> Result<NsDirEntry, NsOpError> {
    let entry = dir_index_lookup_child(dir_index, name).ok_or(NsOpError::EntryNotFound)?;
    dir_index
        .delete(name)
        .map_err(dir_index_error_to_ns_error)?;
    Ok(entry)
}

pub fn handle_create<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsCreateRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    require_parent_dir(backend, request.parent)?;
    require_name_absent(backend, request.parent, name)?;

    let child = backend.allocate_inode(
        NsNodeKind::File,
        apply_umask(request.mode, request.umask),
        request.uid,
        request.gid,
        1,
        0,
    )?;
    let dir_entry = NsDirEntry::new(child.ino, child.generation, child.kind);
    backend.insert_child(request.parent, name, dir_entry)?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsCreateResult {
        child,
        parent,
        dir_entry,
    })
}

pub fn handle_mkdir<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsMkdirRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    require_parent_dir(backend, request.parent)?;
    require_name_absent(backend, request.parent, name)?;

    let child = backend.allocate_inode(
        NsNodeKind::Directory,
        apply_umask(request.mode, request.umask),
        request.uid,
        request.gid,
        2,
        0,
    )?;
    backend.init_dir(child.ino)?;
    let dir_entry = NsDirEntry::new(child.ino, child.generation, child.kind);
    backend.insert_child(request.parent, name, dir_entry)?;
    backend.increment_nlink(request.parent)?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsCreateResult {
        child,
        parent,
        dir_entry,
    })
}

/// Handle a FUSE mknod request through the namespace mutation backend.
///
/// Core logic for `mknod(2)` / `mknodat(2)`: validates the name, resolves
/// the parent directory, allocates an inode with the node kind derived from
/// the file-type bits in `mode`, and inserts the child into the directory
/// index.  The `rdev` field is stored in the inode for block/character
/// device nodes; it is zero for FIFOs, sockets, and regular files.
pub fn handle_mknod<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsMknodRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    require_parent_dir(backend, request.parent)?;
    require_name_absent(backend, request.parent, name)?;

    let kind = mknod_node_kind(request.mode);
    let child = backend.allocate_inode(
        kind,
        apply_umask(request.mode, request.umask),
        request.uid,
        request.gid,
        1,
        request.rdev,
    )?;
    let dir_entry = NsDirEntry::new(child.ino, child.generation, child.kind);
    backend.insert_child(request.parent, name, dir_entry)?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsCreateResult {
        child,
        parent,
        dir_entry,
    })
}

/// Dispatch a FUSE mkdir request through the namespace mutation backend.
///
/// Builds an [`NsMkdirRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_mkdir`] for the core directory-creation logic.
/// All error paths (missing parent, file parent, existing name, overlong name,
/// out of space) are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_mkdir<B: NamespaceMutationBackend>(
    backend: &mut B,
    parent: u64,
    name: &[u8],
    mode: u32,
    umask: u32,
    uid: u32,
    gid: u32,
) -> Result<NsCreateResult, NsOpError> {
    let request = NsMkdirRequest {
        parent,
        name,
        mode,
        umask,
        uid,
        gid,
    };
    handle_mkdir(backend, request)
}

/// Dispatch a FUSE rmdir request through the namespace mutation backend.
///
/// Builds an [`NsRemoveRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_rmdir`] for the core directory-removal logic.
/// All error paths (missing parent, file parent, non-empty directory,
/// invalid name) are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_rmdir<B: NamespaceMutationBackend>(
    backend: &mut B,
    parent: u64,
    name: &[u8],
) -> Result<NsRemoveResult, NsOpError> {
    let request = NsRemoveRequest { parent, name };
    handle_rmdir(backend, request)
}

/// Dispatch a FUSE rename request through the namespace mutation backend.
///
/// Builds a [`NamespaceRenameRequest`] from the individual FUSE-level
/// parameters and delegates to [`handle_rename`].
pub fn dispatch_rename<B: NamespaceMutationBackend>(
    backend: &mut B,
    old_parent: u64,
    old_name: &[u8],
    new_parent: u64,
    new_name: &[u8],
    flags: u32,
) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
    let request = NamespaceRenameRequest {
        old_parent_ino: old_parent,
        old_name,
        new_parent_ino: new_parent,
        new_name,
        flags: NamespaceRenameFlags::from_bits(flags),
    };
    handle_rename(backend, request)
}
/// Dispatch a FUSE create request through the namespace mutation backend.
///
/// Builds an [`NsCreateRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_create`] for the core file-creation logic.
/// All error paths (missing parent, file parent, existing name, overlong name,
/// out of space) are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_create<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsCreateRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    handle_create(backend, request)
}

/// Dispatch a FUSE mknod request through the namespace mutation backend.
///
/// Builds an [`NsMknodRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_mknod`] for the core mknod logic.
/// All error paths (missing parent, file parent, existing name, overlong
/// name, out of space) are mapped through [`NsOpError`] with POSIX errno
/// values.  The `rdev` field is only meaningful for block/character
/// device nodes; pass 0 for FIFOs, sockets, and regular files.
pub fn dispatch_mknod<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsMknodRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    handle_mknod(backend, request)
}

/// Dispatch a FUSE symlink request through the namespace mutation backend.
///
/// Builds an [`NsSymlinkRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_symlink`] for the core symlink-creation logic.
/// All error paths (missing parent, file parent, existing name, invalid
/// target) are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_symlink<B: NamespaceMutationBackend>(
    backend: &mut B,
    parent: u64,
    name: &[u8],
    target: &[u8],
    uid: u32,
    gid: u32,
) -> Result<NsCreateResult, NsOpError> {
    let request = NsSymlinkRequest {
        parent,
        name,
        target,
        uid,
        gid,
    };
    handle_symlink(backend, request)
}

/// Dispatch a FUSE readlink request through the namespace mutation backend.
///
/// Resolves the symlink target stored against `ino`. Returns
/// [`NsOpError::InodeNotFound`] when the inode does not exist and
/// [`NsOpError::NotSymlink`] when the inode exists but is not a symlink.
pub fn dispatch_readlink<B: NamespaceMutationBackend>(
    backend: &B,
    ino: u64,
) -> Result<Vec<u8>, NsOpError> {
    backend.get_symlink_target(ino)
}

/// Dispatch a FUSE link request through the namespace mutation backend.
///
/// Builds an [`NsLinkRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_link`] for the core hard-link logic.
/// All error paths (missing parent, file parent, source not file,
/// existing name) are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_link<B: NamespaceMutationBackend>(
    backend: &mut B,
    source: u64,
    parent: u64,
    name: &[u8],
) -> Result<NsCreateResult, NsOpError> {
    let request = NsLinkRequest {
        source,
        parent,
        name,
    };
    handle_link(backend, request)
}

/// Dispatch a FUSE unlink request through the namespace mutation backend.
///
/// Builds an [`NsRemoveRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_unlink`] for the core file-unlink logic.
/// All error paths (missing parent, entry not found, directory target)
/// are mapped through [`NsOpError`] with POSIX errno values.
pub fn dispatch_unlink<B: NamespaceMutationBackend>(
    backend: &mut B,
    parent: u64,
    name: &[u8],
) -> Result<NsRemoveResult, NsOpError> {
    let request = NsRemoveRequest { parent, name };
    handle_unlink(backend, request)
}

pub fn handle_symlink<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsSymlinkRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    let target = checked_symlink_target(request.target)?;
    require_parent_dir(backend, request.parent)?;
    require_name_absent(backend, request.parent, name)?;

    let child = backend.allocate_inode(
        NsNodeKind::Symlink,
        NS_SYMLINK_MODE,
        request.uid,
        request.gid,
        1,
        0,
    )?;
    backend.set_symlink_target(child.ino, target)?;
    let dir_entry = NsDirEntry::new(child.ino, child.generation, child.kind);
    backend.insert_child(request.parent, name, dir_entry)?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsCreateResult {
        child,
        parent,
        dir_entry,
    })
}

pub fn handle_link<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsLinkRequest<'_>,
) -> Result<NsCreateResult, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    require_parent_dir(backend, request.parent)?;
    require_name_absent(backend, request.parent, name)?;

    let source = backend.inode_attr(request.source)?;
    if source.kind.is_directory() {
        return Err(NsOpError::IsDirectory);
    }
    if source.kind != NsNodeKind::File {
        return Err(NsOpError::PermissionDenied);
    }

    let child = backend.increment_nlink(source.ino)?;
    let dir_entry = NsDirEntry::new(child.ino, child.generation, child.kind);
    backend.insert_child(request.parent, name, dir_entry)?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsCreateResult {
        child,
        parent,
        dir_entry,
    })
}

pub fn handle_unlink<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsRemoveRequest<'_>,
) -> Result<NsRemoveResult, NsOpError> {
    let plan = plan_remove(backend, request, NsRemoveIntent::Unlink)?;

    backend.remove_child(plan.parent.ino, plan.name)?;
    let removed = backend.decrement_nlink(plan.target.ino)?;
    let parent = backend.touch_parent(plan.parent.ino)?;

    Ok(NsRemoveResult { removed, parent })
}

pub fn handle_rmdir<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsRemoveRequest<'_>,
) -> Result<NsRemoveResult, NsOpError> {
    let plan = plan_remove(backend, request, NsRemoveIntent::Rmdir)?;

    backend.remove_child(plan.parent.ino, plan.name)?;
    backend.decrement_nlink(plan.parent.ino)?;
    backend.decrement_nlink(plan.target.ino)?;
    let removed = backend.decrement_nlink(plan.target.ino)?;
    let parent = backend.touch_parent(plan.parent.ino)?;

    Ok(NsRemoveResult { removed, parent })
}

// ── Namespace rename dispatch ───────────────────────────────────────

/// Map a backend [`NsOpError`] into a [`NamespaceRenameError`] suitable
/// for the rename code path.  Entry-not-found errors become
/// [`NamespaceRenameError::SourceNotFound`]; index-level errors are
/// wrapped in [`NamespaceRenameError::DirectoryIndex`].
fn ns_error_to_rename_error(err: NsOpError) -> NamespaceRenameError {
    match err {
        NsOpError::EntryNotFound | NsOpError::InodeNotFound | NsOpError::ParentNotFound => {
            NamespaceRenameError::SourceNotFound
        }
        NsOpError::EntryAlreadyExists => {
            NamespaceRenameError::DirectoryIndex(DirIndexError::EntryAlreadyExists)
        }
        NsOpError::DirectoryNotEmpty => {
            NamespaceRenameError::DirectoryIndex(DirIndexError::DirNotEmpty)
        }
        NsOpError::NameInvalid | NsOpError::NameTooLong => NamespaceRenameError::InvalidFlags,
        _ => NamespaceRenameError::DirectoryIndex(DirIndexError::EntryNotFound),
    }
}

/// Execute a namespace rename through the mutation backend.
///
/// Accepts a pre-built [`NamespaceRenameRequest`] and performs the
/// entry-level move or atomic swap using the backend's directory-index
/// and inode mutation methods.  Supports zero-flag rename, `RENAME_NOREPLACE`,
/// and `RENAME_EXCHANGE`.
pub fn handle_rename<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NamespaceRenameRequest<'_>,
) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
    validate_rename_flags(request.flags)?;

    let old_name = checked_namespace_name(request.old_name).map_err(ns_error_to_rename_error)?;
    let new_name = checked_namespace_name(request.new_name).map_err(ns_error_to_rename_error)?;

    // Self-rename: same parent and same name is a no-op.
    if request.old_parent_ino == request.new_parent_ino && old_name == new_name {
        return Ok(NamespaceRenameOutcome::renamed(None));
    }

    // Look up source entry.
    let _old_parent_attr =
        require_parent_dir(backend, request.old_parent_ino).map_err(ns_error_to_rename_error)?;
    let source_entry = require_child_entry(backend, request.old_parent_ino, old_name)
        .map_err(ns_error_to_rename_error)?;

    // Validate new parent is a directory.
    let _new_parent_attr =
        require_parent_dir(backend, request.new_parent_ino).map_err(ns_error_to_rename_error)?;

    // --- RENAME_EXCHANGE ---
    if request.flags.exchange() {
        // Target must exist for exchange.
        let _target_entry = require_child_entry(backend, request.new_parent_ino, new_name)
            .map_err(|e| match e {
                NsOpError::EntryNotFound => NamespaceRenameError::TargetNotFound,
                other => ns_error_to_rename_error(other),
            })?;

        // Atomically swap: remove both entries, re-insert swapped.
        let removed_source = backend
            .remove_child(request.old_parent_ino, old_name)
            .map_err(ns_error_to_rename_error)?;
        let removed_target = backend
            .remove_child(request.new_parent_ino, new_name)
            .map_err(ns_error_to_rename_error)?;

        backend
            .insert_child(request.old_parent_ino, old_name, removed_target)
            .map_err(ns_error_to_rename_error)?;
        backend
            .insert_child(request.new_parent_ino, new_name, removed_source)
            .map_err(ns_error_to_rename_error)?;

        // Touch both parents (ctime update).
        let _ = backend.touch_parent(request.old_parent_ino);
        if request.old_parent_ino != request.new_parent_ino {
            let _ = backend.touch_parent(request.new_parent_ino);
        }

        return Ok(NamespaceRenameOutcome::exchanged());
    }

    // Check if destination entry already exists.
    let existing = backend
        .lookup_child(request.new_parent_ino, new_name)
        .map_err(ns_error_to_rename_error)?;

    // --- RENAME_NOREPLACE ---
    if request.flags.no_replace() && existing.is_some() {
        return Err(NamespaceRenameError::TargetExists);
    }

    // --- Overwrite handling ---
    // If a destination entry exists, remove it and decrement its link count.
    let overwritten: Option<DirEntry> = if let Some(existing_entry) = existing {
        backend
            .remove_child(request.new_parent_ino, new_name)
            .map_err(ns_error_to_rename_error)?;
        let _ = backend.decrement_nlink(existing_entry.ino);
        Some(DirEntry {
            name_len: new_name.len() as u32,
            inode_id: existing_entry.ino,
            generation: existing_entry.generation,
            kind: existing_entry.kind.dir_entry_kind(),
            name: std::vec::Vec::from(new_name),
        })
    } else {
        None
    };

    // Remove source from old parent.
    backend
        .remove_child(request.old_parent_ino, old_name)
        .map_err(ns_error_to_rename_error)?;

    // Insert source at destination.
    backend
        .insert_child(request.new_parent_ino, new_name, source_entry)
        .map_err(ns_error_to_rename_error)?;

    // Touch both parents (ctime update).
    let _ = backend.touch_parent(request.old_parent_ino);
    if request.old_parent_ino != request.new_parent_ino {
        let _ = backend.touch_parent(request.new_parent_ino);
    }

    Ok(NamespaceRenameOutcome::renamed(overwritten))
}

pub fn plan_remove<'a, B: NamespaceMutationBackend>(
    backend: &B,
    request: NsRemoveRequest<'a>,
    intent: NsRemoveIntent,
) -> Result<NsRemovePlan<'a>, NsOpError> {
    let name = checked_namespace_name(request.name)?;
    let parent = require_parent_dir(backend, request.parent)?;
    let dir_entry = require_child_entry(backend, request.parent, name)?;
    let target = backend.inode_attr(dir_entry.ino)?;

    match intent {
        NsRemoveIntent::Unlink if target.kind.is_directory() => return Err(NsOpError::IsDirectory),
        NsRemoveIntent::Rmdir if !target.kind.is_directory() => {
            return Err(NsOpError::NotDirectory)
        }
        NsRemoveIntent::Rmdir if !backend.is_dir_empty(target.ino)? => {
            return Err(NsOpError::DirectoryNotEmpty);
        }
        _ => {}
    }

    Ok(NsRemovePlan {
        intent,
        parent,
        name,
        dir_entry,
        target,
    })
}

#[must_use]
pub const fn namespace_remove_errno(error: NsOpError) -> i32 {
    -error.errno()
}

#[must_use]
pub fn plan_remove_reply(
    unique: u64,
    result: Result<NsRemovePlan<'_>, NsOpError>,
) -> PosixFilesystemAdapterReplyCommitRecord {
    match result {
        Ok(_) => commit_small_reply(unique, 0, 0),
        Err(error) => commit_small_reply(unique, namespace_remove_errno(error), 0),
    }
}

fn checked_namespace_name(name: &[u8]) -> Result<&[u8], NsOpError> {
    validate_namespace_name(name)?;
    Ok(name)
}

fn checked_symlink_target(target: &[u8]) -> Result<&[u8], NsOpError> {
    if target.is_empty() {
        return Err(NsOpError::NameInvalid);
    }
    Ok(target)
}

fn require_parent_dir<B: NamespaceMutationBackend>(
    backend: &B,
    parent: u64,
) -> Result<NsInodeAttr, NsOpError> {
    let attr = backend.inode_attr(parent).map_err(|error| match error {
        NsOpError::InodeNotFound | NsOpError::EntryNotFound => NsOpError::ParentNotFound,
        other => other,
    })?;
    if !attr.kind.is_directory() {
        return Err(NsOpError::ParentNotDirectory);
    }
    Ok(attr)
}

fn require_name_absent<B: NamespaceMutationBackend>(
    backend: &B,
    parent: u64,
    name: &[u8],
) -> Result<(), NsOpError> {
    if backend.lookup_child(parent, name)?.is_some() {
        return Err(NsOpError::EntryAlreadyExists);
    }
    Ok(())
}

fn require_child_entry<B: NamespaceMutationBackend>(
    backend: &B,
    parent: u64,
    name: &[u8],
) -> Result<NsDirEntry, NsOpError> {
    backend
        .lookup_child(parent, name)?
        .ok_or(NsOpError::EntryNotFound)
}

fn dir_index_error_to_ns_error(error: tidefs_dir_index::DirIndexError) -> NsOpError {
    match error {
        tidefs_dir_index::DirIndexError::EntryAlreadyExists => NsOpError::EntryAlreadyExists,
        tidefs_dir_index::DirIndexError::EntryNotFound => NsOpError::EntryNotFound,
        tidefs_dir_index::DirIndexError::DirNotEmpty => NsOpError::DirectoryNotEmpty,
    }
}

// ── Directory stream types (issue #2523) ────────────────────────────────

/// Maximum length of a single directory entry name in bytes.
pub const DIR_STREAM_MAX_NAME: usize = 255;

/// A directory entry name stored inline (no_std friendly).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirStreamName {
    pub data: [u8; DIR_STREAM_MAX_NAME],
    pub len: u8,
}

impl DirStreamName {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            data: [0u8; DIR_STREAM_MAX_NAME],
            len: 0,
        }
    }

    pub fn from_bytes(name: &[u8]) -> Self {
        let mut s = Self::empty();
        let n = name.len().min(DIR_STREAM_MAX_NAME);
        s.data[..n].copy_from_slice(&name[..n]);
        s.len = n as u8;
        s
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

impl Default for DirStreamName {
    fn default() -> Self {
        Self::empty()
    }
}

/// A single directory entry returned by the namespace worker for readdir/readdirplus.
///
/// This is the P5-02 counterpart of `tidefs_types_vfs_core::DirEntry` —
/// using a fixed-size name for no_std compatibility.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DirStreamEntry {
    pub name: DirStreamName,
    pub inode_id: u64,
    pub generation: u64,
    pub cookie: u64,
    /// Kind encoded as raw u32: 0=unknown, 1=dir, 2=file, 3=symlink, etc.
    pub kind: u32,
}

impl DirStreamEntry {
    #[must_use]
    pub const fn new(
        name: DirStreamName,
        inode_id: u64,
        generation: u64,
        cookie: u64,
        kind: u32,
    ) -> Self {
        Self {
            name,
            inode_id,
            generation,
            cookie,
            kind,
        }
    }
}
/// Raw Linux rename flags carried by FUSE_RENAME2.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NamespaceRenameFlags {
    bits: u32,
}

impl NamespaceRenameFlags {
    #[must_use]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.bits
    }

    #[must_use]
    pub const fn no_replace(self) -> bool {
        self.bits & RENAME_NOREPLACE != 0
    }

    #[must_use]
    pub const fn exchange(self) -> bool {
        self.bits & RENAME_EXCHANGE != 0
    }

    #[must_use]
    pub const fn unsupported_bits(self) -> u32 {
        self.bits & !SUPPORTED_RENAME_FLAGS
    }

    #[must_use]
    pub const fn has_invalid_combination(self) -> bool {
        self.no_replace() && self.exchange()
    }
}

/// Result of a pure namespace rename mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamespaceRenameOutcome {
    pub overwritten: Option<DirEntry>,
    pub exchanged: bool,
}

impl NamespaceRenameOutcome {
    #[must_use]
    pub const fn renamed(overwritten: Option<DirEntry>) -> Self {
        Self {
            overwritten,
            exchanged: false,
        }
    }

    #[must_use]
    pub const fn exchanged() -> Self {
        Self {
            overwritten: None,
            exchanged: true,
        }
    }
}

// ── Directory stream worker helpers ──────────────────────────────────────

/// Check whether a request context is a directory-stream request
/// (queue_class_3.dir_stream: OPENDIR, READDIR, READDIRPLUS, RELEASEDIR, FSYNCDIR).
#[must_use]
pub fn is_dir_stream_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    ctx.request_class == PosixFilesystemAdapterRequestClass::DirStream.as_u32()
}

/// Derive a shard key for directory-stream operations.
///
/// Directory streams are sharded by the parent directory inode (nodeid),
/// ensuring that all readdir calls for a given directory land on the same
/// namespace worker.
#[must_use]
pub fn dir_stream_shard_key(nodeid: u64) -> u64 {
    nodeid
}

/// Compute the next cookie for a directory entry at position `idx` within a page.
///
/// The cookie is a kernel-opaque offset used to resume iteration.  We use
/// `(offset + idx + 1)` semantics consistent with the FUSE convention.
/// When the entry already carries an explicit cookie (non-zero), that value
/// is returned unchanged.
#[must_use]
pub fn compute_readdir_cookie(entry_cookie: u64, offset: u64, idx: usize) -> u64 {
    if entry_cookie != 0 {
        entry_cookie
    } else {
        offset.saturating_add(idx as u64).saturating_add(1)
    }
}

/// Check whether the dir stream request has the `READDIRPLUS` opcode
/// (which needs attribute resolution in addition to entry names).
#[must_use]
pub fn is_readdirplus_request(ctx: &PosixFilesystemAdapterRequestContextMirrorRecord) -> bool {
    // FUSE_READDIRPLUS = 44 per Linux fuse_kernel.h
    ctx.opcode == 44
}

// ── DirIndex → DirStreamEntry bridge (issue #2523) ──────────────────────

/// Convert a `DirIndex` entry (`DirMicroEntry`) into a `DirStreamEntry`.
///
/// The `cookie` is the kernel-opaque offset for this entry.  When `entry_cookie`
/// is non-zero it is used directly; otherwise it falls back to
/// `compute_readdir_cookie` semantics.
#[must_use]
pub fn entry_from_dir_micro_entry(
    entry: &DirMicroEntry,
    entry_cookie: u64,
    offset: u64,
    idx: usize,
) -> DirStreamEntry {
    let name = DirStreamName::from_bytes(&entry.name);
    let cookie = compute_readdir_cookie(entry_cookie, offset, idx);
    DirStreamEntry::new(name, entry.inode_id, entry.generation, cookie, entry.kind)
}

/// Deterministic plan for one FUSE `READDIR` resume step.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaddirResumePlan {
    pub start_offset: u64,
    pub max_entries: usize,
    pub available_entries: usize,
    pub entries: Vec<DirStreamEntry>,
    pub next_offset: u64,
    pub eof: bool,
}

impl ReaddirResumePlan {
    #[must_use]
    pub fn returned_entries(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn remaining_entries(&self) -> usize {
        self.available_entries
            .saturating_sub(self.returned_entries())
    }
}

/// Iterate a [`DirIndex`] from `offset` and return the next page of directory
/// entries as [`DirStreamEntry`] items.
///
/// `max_entries` caps the number of returned entries (typically 128–1024).
/// The returned plan records the emitted entries, remaining entry count,
/// whether this page reached EOF, and the cookie to pass on the next
/// `READDIR` call.
///
/// When `offset` is 0 the iteration starts from the beginning; otherwise
/// `offset` is treated as a [`DirCookie`] resume point.
#[must_use]
pub fn plan_readdir_resume(
    dir_index: &DirIndex,
    offset: u64,
    max_entries: usize,
) -> ReaddirResumePlan {
    let cookie = DirCookie(offset);
    let (raw_entries, _) = dir_index.list_from(cookie);

    let count = raw_entries.len().min(max_entries);
    let entries: Vec<DirStreamEntry> = raw_entries[..count]
        .iter()
        .enumerate()
        .map(|(i, e)| entry_from_dir_micro_entry(e, 0, offset, i))
        .collect();

    let eof = count >= raw_entries.len();
    let next_offset = if eof {
        0
    } else if count == 0 {
        offset
    } else {
        entries.last().map_or(offset, |entry| entry.cookie)
    };

    ReaddirResumePlan {
        start_offset: offset,
        max_entries,
        available_entries: raw_entries.len(),
        entries,
        next_offset,
        eof,
    }
}

/// Iterate a [`DirIndex`] from `offset` and return the next page of directory
/// entries plus the FUSE resume offset for the following call.
#[must_use]
pub fn handle_readdir(
    dir_index: &DirIndex,
    offset: u64,
    max_entries: usize,
) -> (Vec<DirStreamEntry>, u64) {
    let plan = plan_readdir_resume(dir_index, offset, max_entries);
    (plan.entries, plan.next_offset)
}

/// Convenience: iterate all remaining entries unconditionally.
#[must_use]
pub fn handle_readdir_all(dir_index: &DirIndex) -> Vec<DirStreamEntry> {
    let (entries, _) = handle_readdir(dir_index, 0, usize::MAX);
    entries
}

/// Check whether the dir-index is at EOF (no more entries beyond `offset`).
#[must_use]
pub fn is_readdir_eof(dir_index: &DirIndex, offset: u64) -> bool {
    let cookie = DirCookie(offset);
    let (entries, next_cookie) = dir_index.list_from(cookie);
    entries.is_empty() && next_cookie.0 == 0
}
/// Pure rename errors before reply-layer errno mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceRenameError {
    SourceNotFound,
    TargetNotFound,
    TargetExists,
    InvalidFlags,
    ParentTopologyMismatch,
    DirectoryIndex(DirIndexError),
}

/// Handle a same-directory rename against one directory index.
pub fn handle_rename_same_directory(
    request: NamespaceRenameRequest<'_>,
    directory: &mut DirIndex,
) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
    validate_rename_flags(request.flags)?;
    if request.old_parent_ino != request.new_parent_ino {
        return Err(NamespaceRenameError::ParentTopologyMismatch);
    }

    if request.flags.exchange() {
        exchange_same_directory(directory, request.old_name, request.new_name)?;
        return Ok(NamespaceRenameOutcome::exchanged());
    }

    if request.flags.no_replace()
        && request.old_name != request.new_name
        && directory.contains(request.new_name)
    {
        return Err(NamespaceRenameError::TargetExists);
    }

    let overwritten = directory
        .rename_overwrite(request.old_name, request.new_name)
        .map_err(map_dir_index_error)?;
    Ok(NamespaceRenameOutcome::renamed(overwritten))
}

/// Handle a cross-directory rename against source and target directory indexes.
pub fn handle_rename_cross_directory(
    request: NamespaceRenameRequest<'_>,
    source_directory: &mut DirIndex,
    target_directory: &mut DirIndex,
) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
    validate_rename_flags(request.flags)?;
    if request.old_parent_ino == request.new_parent_ino {
        return Err(NamespaceRenameError::ParentTopologyMismatch);
    }

    if request.flags.exchange() {
        exchange_cross_directory(
            source_directory,
            request.old_name,
            target_directory,
            request.new_name,
        )?;
        return Ok(NamespaceRenameOutcome::exchanged());
    }

    if request.flags.no_replace() && target_directory.contains(request.new_name) {
        return Err(NamespaceRenameError::TargetExists);
    }

    let overwritten = source_directory
        .move_entry_to(request.old_name, target_directory, request.new_name)
        .map_err(map_dir_index_error)?;
    Ok(NamespaceRenameOutcome::renamed(overwritten))
}

/// Map a pure rename error to the negative POSIX errno used by FUSE replies.
#[must_use]
pub const fn namespace_rename_errno(error: NamespaceRenameError) -> i32 {
    match error {
        NamespaceRenameError::SourceNotFound | NamespaceRenameError::TargetNotFound => {
            RENAME_ERRNO_ENOENT
        }
        NamespaceRenameError::TargetExists => RENAME_ERRNO_EEXIST,
        NamespaceRenameError::InvalidFlags | NamespaceRenameError::ParentTopologyMismatch => {
            RENAME_ERRNO_EINVAL
        }
        NamespaceRenameError::DirectoryIndex(DirIndexError::EntryNotFound) => RENAME_ERRNO_ENOENT,
        NamespaceRenameError::DirectoryIndex(DirIndexError::EntryAlreadyExists) => {
            RENAME_ERRNO_EEXIST
        }
        NamespaceRenameError::DirectoryIndex(DirIndexError::DirNotEmpty) => RENAME_ERRNO_ENOTEMPTY,
    }
}

/// Plan the small reply commit for a completed rename handler result.
#[must_use]
pub fn plan_rename_reply(
    unique: u64,
    result: Result<NamespaceRenameOutcome, NamespaceRenameError>,
) -> PosixFilesystemAdapterReplyCommitRecord {
    match result {
        Ok(_) => commit_rename_reply(unique),
        Err(error) => commit_rename_error(unique, namespace_rename_errno(error)),
    }
}

/// Backend boundary used by workers-ns rename dispatch.
pub trait NamespaceRenameBackend {
    fn rename(
        &mut self,
        request: NamespaceRenameRequest<'_>,
    ) -> Result<NamespaceRenameOutcome, NamespaceRenameError>;
}

/// Same-directory backend adapter over one directory index.
pub struct SameDirectoryRenameBackend<'a> {
    directory: &'a mut DirIndex,
}

impl<'a> SameDirectoryRenameBackend<'a> {
    #[must_use]
    pub fn new(directory: &'a mut DirIndex) -> Self {
        Self { directory }
    }
}

impl NamespaceRenameBackend for SameDirectoryRenameBackend<'_> {
    fn rename(
        &mut self,
        request: NamespaceRenameRequest<'_>,
    ) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
        handle_rename_same_directory(request, self.directory)
    }
}

/// Cross-directory backend adapter over source and target directory indexes.
pub struct CrossDirectoryRenameBackend<'a> {
    source_directory: &'a mut DirIndex,
    target_directory: &'a mut DirIndex,
}

impl<'a> CrossDirectoryRenameBackend<'a> {
    #[must_use]
    pub fn new(source_directory: &'a mut DirIndex, target_directory: &'a mut DirIndex) -> Self {
        Self {
            source_directory,
            target_directory,
        }
    }
}

impl NamespaceRenameBackend for CrossDirectoryRenameBackend<'_> {
    fn rename(
        &mut self,
        request: NamespaceRenameRequest<'_>,
    ) -> Result<NamespaceRenameOutcome, NamespaceRenameError> {
        handle_rename_cross_directory(request, self.source_directory, self.target_directory)
    }
}

/// Execute rename through a backend and return the planned FUSE reply commit.
pub fn dispatch_rename_with_backend(
    unique: u64,
    request: NamespaceRenameRequest<'_>,
    backend: &mut impl NamespaceRenameBackend,
) -> PosixFilesystemAdapterReplyCommitRecord {
    plan_rename_reply(unique, backend.rename(request))
}

fn validate_rename_flags(flags: NamespaceRenameFlags) -> Result<(), NamespaceRenameError> {
    if flags.unsupported_bits() != 0 || flags.has_invalid_combination() {
        return Err(NamespaceRenameError::InvalidFlags);
    }
    Ok(())
}

fn exchange_same_directory(
    directory: &mut DirIndex,
    old_name: &[u8],
    new_name: &[u8],
) -> Result<(), NamespaceRenameError> {
    let old_entry = directory
        .lookup(old_name)
        .ok_or(NamespaceRenameError::SourceNotFound)?;
    if old_name == new_name {
        return Ok(());
    }
    let new_entry = directory
        .lookup(new_name)
        .ok_or(NamespaceRenameError::TargetNotFound)?;

    directory.replace(
        old_name,
        new_entry.inode_id,
        new_entry.generation,
        new_entry.kind,
    );
    directory.replace(
        new_name,
        old_entry.inode_id,
        old_entry.generation,
        old_entry.kind,
    );
    Ok(())
}

fn exchange_cross_directory(
    source_directory: &mut DirIndex,
    old_name: &[u8],
    target_directory: &mut DirIndex,
    new_name: &[u8],
) -> Result<(), NamespaceRenameError> {
    let old_entry = source_directory
        .lookup(old_name)
        .ok_or(NamespaceRenameError::SourceNotFound)?;
    let new_entry = target_directory
        .lookup(new_name)
        .ok_or(NamespaceRenameError::TargetNotFound)?;

    source_directory
        .remove(old_name)
        .ok_or(NamespaceRenameError::SourceNotFound)?;
    target_directory
        .remove(new_name)
        .ok_or(NamespaceRenameError::TargetNotFound)?;
    source_directory
        .insert(
            old_name,
            new_entry.inode_id,
            new_entry.generation,
            new_entry.kind,
        )
        .map_err(map_dir_index_error)?;
    target_directory
        .insert(
            new_name,
            old_entry.inode_id,
            old_entry.generation,
            old_entry.kind,
        )
        .map_err(map_dir_index_error)?;
    Ok(())
}

const fn map_dir_index_error(error: DirIndexError) -> NamespaceRenameError {
    match error {
        DirIndexError::EntryNotFound => NamespaceRenameError::SourceNotFound,
        other => NamespaceRenameError::DirectoryIndex(other),
    }
}

// ── Directory stream dispatch (opendir / readdir / releasedir) ───────────

/// Backend for directory-stream operations (OPENDIR, READDIR, RELEASEDIR).
///
/// The daemon runtime implements this trait to bridge the namespace worker
/// to the inode table, directory index storage, and the dir-handle table.
pub trait DirStreamBackend {
    /// Return a reference to the [`DirIndex`] for directory inode `ino`,
    /// or `None` if the inode does not exist or is not a directory.
    fn get_dir_index(&self, ino: u64) -> Option<&DirIndex>;

    /// Return the inode attributes for `ino`.
    fn get_dir_attr(&self, ino: u64) -> Result<NsInodeAttr, NsOpError>;

    /// Allocate a new opaque directory handle for `ino` and return the
    /// handle value (the `fh` field of `fuse_open_out`).
    fn alloc_dir_handle(&mut self, ino: u64) -> Result<u64, NsOpError>;

    /// Release the directory handle `handle`.  Subsequent use of this
    /// handle must fail with [`NsOpError::BadHandle`].
    fn release_dir_handle(&mut self, handle: u64) -> Result<(), NsOpError>;

    /// Return the directory inode associated with `handle`, or `None` if
    /// the handle is not valid.
    fn lookup_dir_handle(&self, handle: u64) -> Option<u64>;
}

/// Outcome of a successful [`dispatch_opendir`] call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirStreamOpenResult {
    /// Opaque directory handle (the `fh` field of `fuse_open_out`).
    pub handle: u64,
    /// Open flags echoed back to the kernel.
    pub open_flags: u32,
}

/// Outcome of a successful [`dispatch_readdir`] call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirStreamReadResult {
    /// Directory entries for this page.
    pub entries: Vec<DirStreamEntry>,
    /// Cookie to pass as the offset on the next READDIR call.
    pub next_offset: u64,
    /// True when no more entries remain beyond the returned page.
    pub eof: bool,
}

/// Dispatch a FUSE OPENDIR request through the directory-stream backend.
///
/// Validates that `ino` is a directory, then allocates an opaque handle
/// and returns it together with the open flags.  On failure the caller
/// should emit a FUSE error reply with the [`NsOpError::errno`] value.
///
/// # Errors
///
/// Returns [`NsOpError::InodeNotFound`] when the inode does not exist,
/// [`NsOpError::NotDirectory`] when it exists but is not a directory,
/// and backend-specific errors for handle-allocation failures.
pub fn dispatch_opendir<B: DirStreamBackend>(
    backend: &mut B,
    ino: u64,
    flags: u32,
) -> Result<DirStreamOpenResult, NsOpError> {
    let attr = backend.get_dir_attr(ino)?;
    if !attr.kind.is_directory() {
        return Err(NsOpError::NotDirectory);
    }
    if backend.get_dir_index(ino).is_none() {
        return Err(NsOpError::NotDirectory);
    }
    let handle = backend.alloc_dir_handle(ino)?;
    Ok(DirStreamOpenResult {
        handle,
        open_flags: flags,
    })
}

/// Dispatch a FUSE READDIR / READDIRPLUS request through the dir-stream
/// backend.
///
/// Looks up the directory index for the given handle, iterates entries
/// starting from `offset`, and returns at most `max_entries` items.
///
/// The returned [`DirStreamReadResult::next_offset`] must be passed as the
/// offset of the next READDIR call.  When [`DirStreamReadResult::eof`] is
/// true the kernel should send no more READDIR calls for this handle.
///
/// # Errors
///
/// Returns [`NsOpError::BadHandle`] when the handle is not valid.
pub fn dispatch_readdir<B: DirStreamBackend>(
    backend: &B,
    handle: u64,
    offset: u64,
    max_entries: usize,
) -> Result<DirStreamReadResult, NsOpError> {
    let dir_ino = backend
        .lookup_dir_handle(handle)
        .ok_or(NsOpError::BadHandle)?;
    let dir_index = backend
        .get_dir_index(dir_ino)
        .ok_or(NsOpError::NotDirectory)?;

    let plan = plan_readdir_resume(dir_index, offset, max_entries);

    Ok(DirStreamReadResult {
        entries: plan.entries,
        next_offset: plan.next_offset,
        eof: plan.eof,
    })
}

/// Dispatch a FUSE RELEASEDIR request through the dir-stream backend.
///
/// Releases the directory handle.  After this call returns `Ok(())`,
/// further use of the handle must produce [`NsOpError::BadHandle`].
///
/// # Errors
///
/// Returns [`NsOpError::BadHandle`] when the handle is not valid.
pub fn dispatch_releasedir<B: DirStreamBackend>(
    backend: &mut B,
    handle: u64,
) -> Result<(), NsOpError> {
    backend.release_dir_handle(handle)
}

// ── Dir stream reply planning helpers ─────────────────────────────────

/// Plan the FUSE `fuse_out_header` error-or-zero for an opendir result.
#[must_use]
pub const fn plan_opendir_errno(result: &Result<DirStreamOpenResult, NsOpError>) -> i32 {
    match result {
        Ok(_) => 0,
        Err(e) => -(e.errno()),
    }
}

/// Plan the FUSE `fuse_out_header` error-or-zero for a readdir result.
#[must_use]
pub const fn plan_readdir_errno(result: &Result<DirStreamReadResult, NsOpError>) -> i32 {
    match result {
        Ok(_) => 0,
        Err(e) => -(e.errno()),
    }
}

/// Plan the FUSE `fuse_out_header` error-or-zero for a releasedir result.
#[must_use]
pub const fn plan_releasedir_errno(result: &Result<(), NsOpError>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(e) => -(e.errno()),
    }
}

// ── TMPFILE dispatch ──────────────────────────────────────────────────

/// Request to create an unnamed temporary file (O_TMPFILE semantics).
///
/// Unlike [`NsCreateRequest`], there is no `name` field — the inode is
/// created without a directory entry and with `nlink == 0` until a
/// subsequent `linkat` materialises it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsTmpfileRequest {
    /// Parent directory inode number.
    pub parent: u64,
    /// File mode bits (subject to umask).
    pub mode: u32,
    /// Umask to apply to `mode`.
    pub umask: u32,
    /// Open flags (carries O_RDWR, O_EXCL, O_APPEND, etc.).
    pub flags: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
}

/// Result of a successful TMPFILE creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NsTmpfileResult {
    /// Attributes of the newly created unnamed inode (nlink == 0).
    pub child: NsInodeAttr,
    /// Updated parent directory attributes (mtime/ctime bumped).
    pub parent: NsInodeAttr,
}

/// Core handler for O_TMPFILE: creates an unnamed regular file in
/// `request.parent` with no directory entry and `nlink == 0`.
///
/// The inode is tracked by the orphan index until a `linkat` call
/// materialises a directory entry for it. Data written before the
/// link is preserved.
pub fn handle_tmpfile<B: NamespaceMutationBackend>(
    backend: &mut B,
    request: NsTmpfileRequest,
) -> Result<NsTmpfileResult, NsOpError> {
    require_parent_dir(backend, request.parent)?;

    let child = backend.allocate_inode(
        NsNodeKind::File,
        apply_umask(request.mode, request.umask),
        request.uid,
        request.gid,
        0, // nlink == 0: O_TMPFILE creates an orphaned inode
        0, // rdev: not a device
    )?;
    let parent = backend.touch_parent(request.parent)?;

    Ok(NsTmpfileResult { child, parent })
}

/// Dispatch a FUSE O_TMPFILE request through the namespace mutation backend.
///
/// Builds an [`NsTmpfileRequest`] from the individual FUSE-level parameters
/// and delegates to [`handle_tmpfile`] for the core tmpfile logic.
/// All error paths (missing parent, file parent, out of space) are mapped
/// through [`NsOpError`] with POSIX errno values.
pub fn dispatch_tmpfile<B: NamespaceMutationBackend>(
    backend: &mut B,
    parent: u64,
    mode: u32,
    umask: u32,
    flags: u32,
    uid: u32,
    gid: u32,
) -> Result<NsTmpfileResult, NsOpError> {
    let request = NsTmpfileRequest {
        parent,
        mode,
        umask,
        flags,
        uid,
        gid,
    };
    handle_tmpfile(backend, request)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    use std::vec::Vec;
    use tidefs_dir_index::{DatasetDirPolicy, DirStorageKind};
    use tidefs_types_posix_filesystem_adapter_core::{
        PosixFilesystemAdapterReplyClass, PosixFilesystemAdapterShardKeyPolicy,
    };

    fn test_policy() -> DatasetDirPolicy {
        DatasetDirPolicy {
            dir_micro_max_entries: 6,
            dir_micro_max_name_bytes: 512,
            dir_btree_downshift_entries: 3,
            dir_btree_downshift_name_bytes: 128,
        }
    }

    fn request<'a>(
        old_parent_ino: u64,
        old_name: &'a [u8],
        new_parent_ino: u64,
        new_name: &'a [u8],
        flags: u32,
    ) -> NamespaceRenameRequest<'a> {
        NamespaceRenameRequest::new(
            old_parent_ino,
            old_name,
            new_parent_ino,
            new_name,
            NamespaceRenameFlags::from_bits(flags),
        )
    }

    fn test_dir_index(populate: usize) -> DirIndex {
        let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        for i in 0..populate {
            let name = format!("file_{i:03}.txt");
            idx.insert(
                name.as_bytes(),
                (100 + i) as u64,
                i as u64,
                if i % 3 == 0 { 1 } else { 2 },
            )
            .unwrap();
        }
        idx
    }

    #[derive(Debug)]
    struct TestBackend {
        next_ino: u64,
        next_generation: u64,
        inodes: Vec<NsInodeAttr>,
        dirs: Vec<(u64, DirIndex)>,
        symlink_targets: Vec<(u64, Vec<u8>)>,
        touched: Vec<u64>,
    }

    impl TestBackend {
        fn new() -> Self {
            Self {
                next_ino: 2,
                next_generation: 2,
                inodes: vec![NsInodeAttr {
                    ino: 1,
                    generation: 1,
                    kind: NsNodeKind::Directory,
                    mode: 0o40755,
                    uid: 0,
                    gid: 0,
                    nlink: 2,
                    rdev: 0,
                }],
                dirs: vec![(1, DirIndex::new(1, DatasetDirPolicy::DEFAULT))],
                symlink_targets: Vec::new(),
                touched: Vec::new(),
            }
        }

        fn inode_pos(&self, ino: u64) -> Option<usize> {
            self.inodes.iter().position(|attr| attr.ino == ino)
        }

        fn dir_pos(&self, ino: u64) -> Option<usize> {
            self.dirs.iter().position(|(dir_ino, _)| *dir_ino == ino)
        }

        fn attr(&self, ino: u64) -> NsInodeAttr {
            self.inode_attr(ino).unwrap()
        }

        fn lookup(&self, parent: u64, name: &[u8]) -> Option<NsDirEntry> {
            self.lookup_child(parent, name).unwrap()
        }

        fn symlink_target(&self, ino: u64) -> Option<&[u8]> {
            self.symlink_targets
                .iter()
                .find(|(target_ino, _)| *target_ino == ino)
                .map(|(_, target)| target.as_slice())
        }
    }

    impl NamespaceMutationBackend for TestBackend {
        fn inode_attr(&self, ino: u64) -> Result<NsInodeAttr, NsOpError> {
            self.inode_pos(ino)
                .map(|pos| self.inodes[pos])
                .ok_or(NsOpError::InodeNotFound)
        }

        fn allocate_inode(
            &mut self,
            kind: NsNodeKind,
            mode: u32,
            uid: u32,
            gid: u32,
            nlink: u32,
            rdev: u32,
        ) -> Result<NsInodeAttr, NsOpError> {
            let attr = NsInodeAttr {
                ino: self.next_ino,
                generation: self.next_generation,
                kind,
                mode,
                uid,
                gid,
                nlink,
                rdev,
            };
            self.next_ino += 1;
            self.next_generation += 1;
            self.inodes.push(attr);
            Ok(attr)
        }

        fn lookup_child(&self, parent: u64, name: &[u8]) -> Result<Option<NsDirEntry>, NsOpError> {
            let dir_pos = self.dir_pos(parent).ok_or(NsOpError::ParentNotDirectory)?;
            Ok(dir_index_lookup_child(&self.dirs[dir_pos].1, name))
        }

        fn insert_child(
            &mut self,
            parent: u64,
            name: &[u8],
            child: NsDirEntry,
        ) -> Result<(), NsOpError> {
            let dir_pos = self.dir_pos(parent).ok_or(NsOpError::ParentNotDirectory)?;
            dir_index_insert_child(&mut self.dirs[dir_pos].1, name, child)
        }

        fn remove_child(&mut self, parent: u64, name: &[u8]) -> Result<NsDirEntry, NsOpError> {
            let dir_pos = self.dir_pos(parent).ok_or(NsOpError::ParentNotDirectory)?;
            dir_index_remove_child(&mut self.dirs[dir_pos].1, name)
        }

        fn init_dir(&mut self, ino: u64) -> Result<(), NsOpError> {
            if self.dir_pos(ino).is_some() {
                return Err(NsOpError::EntryAlreadyExists);
            }
            self.dirs
                .push((ino, DirIndex::new(ino, DatasetDirPolicy::DEFAULT)));
            Ok(())
        }

        fn set_symlink_target(&mut self, ino: u64, target: &[u8]) -> Result<(), NsOpError> {
            self.inode_attr(ino)?;
            self.symlink_targets.push((ino, target.to_vec()));
            Ok(())
        }

        fn get_symlink_target(&self, ino: u64) -> Result<Vec<u8>, NsOpError> {
            self.inode_attr(ino)?;
            self.symlink_targets
                .iter()
                .find(|(target_ino, _)| *target_ino == ino)
                .map(|(_, target)| target.clone())
                .ok_or(NsOpError::NotSymlink)
        }

        fn is_dir_empty(&self, ino: u64) -> Result<bool, NsOpError> {
            let dir_pos = self.dir_pos(ino).ok_or(NsOpError::NotDirectory)?;
            Ok(self.dirs[dir_pos].1.is_empty())
        }

        fn increment_nlink(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError> {
            let inode_pos = self.inode_pos(ino).ok_or(NsOpError::InodeNotFound)?;
            self.inodes[inode_pos].nlink += 1;
            Ok(self.inodes[inode_pos])
        }

        fn decrement_nlink(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError> {
            let inode_pos = self.inode_pos(ino).ok_or(NsOpError::InodeNotFound)?;
            if self.inodes[inode_pos].nlink == 0 {
                return Err(NsOpError::LinkUnderflow);
            }
            self.inodes[inode_pos].nlink -= 1;
            Ok(self.inodes[inode_pos])
        }

        fn touch_parent(&mut self, ino: u64) -> Result<NsInodeAttr, NsOpError> {
            let attr = self.inode_attr(ino)?;
            self.touched.push(ino);
            Ok(attr)
        }
    }

    fn create_request<'a>(parent: u64, name: &'a [u8]) -> NsCreateRequest<'a> {
        NsCreateRequest {
            parent,
            name,
            mode: 0o100666,
            umask: 0o022,
            flags: 0,
            uid: 1000,
            gid: 1000,
        }
    }

    fn mkdir_request<'a>(parent: u64, name: &'a [u8]) -> NsMkdirRequest<'a> {
        NsMkdirRequest {
            parent,
            name,
            mode: 0o40777,
            umask: 0o022,
            uid: 1000,
            gid: 1000,
        }
    }

    fn symlink_request<'a>(parent: u64, name: &'a [u8], target: &'a [u8]) -> NsSymlinkRequest<'a> {
        NsSymlinkRequest {
            parent,
            name,
            target,
            uid: 1000,
            gid: 1000,
        }
    }

    fn mknod_request<'a>(parent: u64, name: &'a [u8]) -> NsMknodRequest<'a> {
        NsMknodRequest {
            parent,
            name,
            mode: 0o100666,
            umask: 0o022,
            uid: 1000,
            gid: 1000,
            rdev: 0,
        }
    }

    fn link_request<'a>(source: u64, parent: u64, name: &'a [u8]) -> NsLinkRequest<'a> {
        NsLinkRequest {
            source,
            parent,
            name,
        }
    }

    fn remove_request<'a>(parent: u64, name: &'a [u8]) -> NsRemoveRequest<'a> {
        NsRemoveRequest { parent, name }
    }

    // ── Namespace mutation tests (issue #2538) ────────────────────────

    #[test]
    fn namespace_name_validation_rejects_invalid_names() {
        assert_eq!(validate_namespace_name(b""), Err(NsOpError::NameInvalid));
        assert_eq!(validate_namespace_name(b"."), Err(NsOpError::NameInvalid));
        assert_eq!(validate_namespace_name(b".."), Err(NsOpError::NameInvalid));
        assert_eq!(
            validate_namespace_name(b"has\0nul"),
            Err(NsOpError::NameInvalid)
        );
        assert_eq!(
            validate_namespace_name(&[b'x'; NS_NAME_MAX + 1]),
            Err(NsOpError::NameTooLong)
        );
        assert_eq!(NsOpError::NameTooLong.errno(), ns_errno::ENAMETOOLONG);
    }

    #[test]
    fn create_inserts_file_and_bumps_parent() {
        let mut backend = TestBackend::new();
        let result = handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::File);
        assert_eq!(result.child.mode, 0o100644);
        assert_eq!(result.child.nlink, 1);
        assert_eq!(
            backend.lookup(1, b"file.txt").unwrap().ino,
            result.child.ino
        );
        assert_eq!(backend.touched, vec![1]);
    }

    #[test]
    fn create_missing_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = handle_create(&mut backend, create_request(99, b"file.txt")).unwrap_err();
        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn create_into_file_parent_returns_enotdir() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;
        let error = handle_create(&mut backend, create_request(file.ino, b"child")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn mkdir_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        handle_mkdir(&mut backend, mkdir_request(1, b"dir")).unwrap();
        let error = handle_mkdir(&mut backend, mkdir_request(1, b"dir")).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn mkdir_creates_empty_dir_and_parent_link() {
        let mut backend = TestBackend::new();
        let result = handle_mkdir(&mut backend, mkdir_request(1, b"dir")).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Directory);
        assert_eq!(result.child.mode, 0o40755);
        assert_eq!(result.child.nlink, 2);
        assert_eq!(result.parent.nlink, 3);
        assert!(backend.is_dir_empty(result.child.ino).unwrap());
        assert_eq!(
            backend.lookup(1, b"dir").unwrap().kind,
            NsNodeKind::Directory
        );
    }

    // ── dispatch_mkdir tests ───────────────────────────────────────────

    #[test]
    fn dispatch_mkdir_valid_parent_creates_directory() {
        let mut backend = TestBackend::new();
        let result =
            dispatch_mkdir(&mut backend, 1, b"newdir", 0o40777, 0o022, 1000, 1000).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Directory);
        assert_eq!(result.child.mode, 0o40755);
        assert_eq!(result.child.uid, 1000);
        assert_eq!(result.child.gid, 1000);
        assert_eq!(result.child.nlink, 2);
        assert_eq!(result.parent.nlink, 3);
        assert!(backend.is_dir_empty(result.child.ino).unwrap());
        assert_eq!(
            backend.lookup(1, b"newdir").unwrap().kind,
            NsNodeKind::Directory
        );
    }

    #[test]
    fn dispatch_mkdir_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error =
            dispatch_mkdir(&mut backend, 999, b"dir", 0o40777, 0o022, 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_mkdir_file_parent_returns_enotdir() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let error = dispatch_mkdir(
            &mut backend,
            file.ino,
            b"subdir",
            0o40777,
            0o022,
            1000,
            1000,
        )
        .unwrap_err();

        assert_eq!(error, NsOpError::ParentNotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn dispatch_mkdir_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        dispatch_mkdir(&mut backend, 1, b"dir", 0o40777, 0o022, 1000, 1000).unwrap();

        let error =
            dispatch_mkdir(&mut backend, 1, b"dir", 0o40777, 0o022, 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn dispatch_mkdir_overlong_name_returns_enametoolong() {
        let mut backend = TestBackend::new();
        let long_name = [b'x'; NS_NAME_MAX + 1];

        let error =
            dispatch_mkdir(&mut backend, 1, &long_name, 0o40777, 0o022, 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::NameTooLong);
        assert_eq!(error.errno(), ns_errno::ENAMETOOLONG);
    }

    #[test]
    fn dispatch_mkdir_empty_name_returns_einval() {
        let mut backend = TestBackend::new();

        let error = dispatch_mkdir(&mut backend, 1, b"", 0o40777, 0o022, 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_mkdir_umask_strips_bits() {
        let mut backend = TestBackend::new();
        // mode 0o40777 with umask 0o077 → 0o40700
        let result =
            dispatch_mkdir(&mut backend, 1, b"restricted", 0o40777, 0o077, 1000, 1000).unwrap();

        assert_eq!(result.child.mode, 0o40700);
        assert_eq!(result.child.kind, NsNodeKind::Directory);
    }

    // ── dispatch_rmdir tests ───────────────────────────────────────────

    #[test]
    fn dispatch_rmdir_empty_directory_success() {
        let mut backend = TestBackend::new();
        let dir = dispatch_mkdir(&mut backend, 1, b"dir", 0o40777, 0o022, 1000, 1000)
            .unwrap()
            .child;

        let result = dispatch_rmdir(&mut backend, 1, b"dir").unwrap();

        assert_eq!(result.removed.ino, dir.ino);
        assert_eq!(result.removed.nlink, 0);
        assert_eq!(result.parent.nlink, 2);
        assert!(backend.lookup(1, b"dir").is_none());
        assert_eq!(backend.attr(dir.ino).nlink, 0);
    }

    #[test]
    fn dispatch_rmdir_nonempty_fails_enotempty() {
        let mut backend = TestBackend::new();
        let dir = dispatch_mkdir(&mut backend, 1, b"dir", 0o40777, 0o022, 1000, 1000)
            .unwrap()
            .child;
        handle_create(&mut backend, create_request(dir.ino, b"file.txt")).unwrap();

        let error = dispatch_rmdir(&mut backend, 1, b"dir").unwrap_err();

        assert_eq!(error, NsOpError::DirectoryNotEmpty);
        assert_eq!(error.errno(), ns_errno::ENOTEMPTY);
        assert!(backend.lookup(1, b"dir").is_some());
    }

    #[test]
    fn dispatch_rmdir_missing_parent_enoent() {
        let mut backend = TestBackend::new();

        let error = dispatch_rmdir(&mut backend, 999, b"dir").unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_rmdir_target_not_directory_enotdir() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let error = dispatch_rmdir(&mut backend, 1, b"file.txt").unwrap_err();

        assert_eq!(error, NsOpError::NotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    // ── dispatch_create tests ──────────────────────────────────────────

    #[test]
    fn dispatch_create_valid_parent_creates_file() {
        let mut backend = TestBackend::new();
        let result = dispatch_create(&mut backend, create_request(1, b"newfile.txt")).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::File);
        assert_eq!(result.child.mode, 0o100644); // 0o100666 & ~0o022
        assert_eq!(result.child.uid, 1000);
        assert_eq!(result.child.gid, 1000);
        assert_eq!(result.child.nlink, 1);
        assert_eq!(result.dir_entry.kind, NsNodeKind::File);
        let lookup = backend.lookup(1, b"newfile.txt").unwrap();
        assert_eq!(lookup.ino, result.child.ino);
        assert_eq!(backend.touched, vec![1]);
    }

    #[test]
    fn dispatch_create_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = dispatch_create(&mut backend, create_request(999, b"file.txt")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_create_file_parent_returns_enotdir() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let error =
            dispatch_create(&mut backend, create_request(file.ino, b"child.txt")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn dispatch_create_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let error = dispatch_create(&mut backend, create_request(1, b"file.txt")).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn dispatch_create_empty_name_returns_einval() {
        let mut backend = TestBackend::new();
        let error = dispatch_create(&mut backend, create_request(1, b"")).unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_create_umask_strips_bits() {
        let mut backend = TestBackend::new();
        let result = dispatch_create(
            &mut backend,
            NsCreateRequest {
                umask: 0o077,
                ..create_request(1, b"restricted")
            },
        )
        .unwrap();

        assert_eq!(result.child.mode, 0o100600); // 0o100666 & ~0o077
    }

    // ── dispatch_symlink tests ────────────────────────────────────────

    #[test]
    fn dispatch_symlink_valid_parent_creates_symlink() {
        let mut backend = TestBackend::new();
        let result =
            dispatch_symlink(&mut backend, 1, b"link", b"target/file", 1000, 1000).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Symlink);
        assert_eq!(result.child.mode, NS_SYMLINK_MODE);
        assert_eq!(result.child.uid, 1000);
        assert_eq!(result.child.gid, 1000);
        assert_eq!(result.dir_entry.kind, NsNodeKind::Symlink);
        let lookup = backend.lookup(1, b"link").unwrap();
        assert_eq!(lookup.ino, result.child.ino);
        assert_eq!(
            backend.symlink_target(result.child.ino),
            Some(&b"target/file"[..])
        );
    }

    #[test]
    fn dispatch_symlink_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error =
            dispatch_symlink(&mut backend, 999, b"link", b"target", 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_symlink_empty_target_returns_einval() {
        let mut backend = TestBackend::new();
        let error = dispatch_symlink(&mut backend, 1, b"link", b"", 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_symlink_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"existing.txt")).unwrap();

        let error =
            dispatch_symlink(&mut backend, 1, b"existing.txt", b"target", 1000, 1000).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    // ── dispatch_readlink tests ───────────────────────────────────────

    #[test]
    fn dispatch_readlink_returns_target_for_valid_symlink() {
        let mut backend = TestBackend::new();
        let result =
            dispatch_symlink(&mut backend, 1, b"link", b"target/file", 1000, 1000).unwrap();
        let target = dispatch_readlink(&backend, result.child.ino).unwrap();
        assert_eq!(target, b"target/file");
    }

    #[test]
    fn dispatch_readlink_nonexistent_inode_returns_enoent() {
        let backend = TestBackend::new();
        let error = dispatch_readlink(&backend, 999).unwrap_err();
        assert_eq!(error, NsOpError::InodeNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_readlink_regular_file_returns_einval() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();
        let error = dispatch_readlink(&backend, file.child.ino).unwrap_err();
        assert_eq!(error, NsOpError::NotSymlink);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_readlink_directory_returns_not_symlink() {
        let backend = TestBackend::new();
        // Root inode (1) is a directory
        let error = dispatch_readlink(&backend, 1).unwrap_err();
        assert_eq!(error, NsOpError::NotSymlink);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_readlink_single_byte_target() {
        let mut backend = TestBackend::new();
        let result = dispatch_symlink(&mut backend, 1, b"one", b"x", 1000, 1000).unwrap();
        let target = dispatch_readlink(&backend, result.child.ino).unwrap();
        assert_eq!(target, b"x");
    }

    #[test]
    fn dispatch_readlink_long_target() {
        let mut backend = TestBackend::new();
        let long_target = [b'x'; 4096];
        let result =
            dispatch_symlink(&mut backend, 1, b"long-link", &long_target, 1000, 1000).unwrap();
        let target = dispatch_readlink(&backend, result.child.ino).unwrap();
        assert_eq!(target, &long_target[..]);
    }

    #[test]
    fn dispatch_readlink_symlink_roundtrip_preserves_target_bytes() {
        let mut backend = TestBackend::new();
        let targets = [
            &b"/absolute/path/to/target"[..],
            b"relative/path",
            b"../parent/../sibling",
            b"with spaces and more",
        ];
        for &target in &targets {
            let result = dispatch_symlink(&mut backend, 1, target, target, 1000, 1000).unwrap();
            let got = dispatch_readlink(&backend, result.child.ino).unwrap();
            assert_eq!(got, target);
        }
    }

    // ── dispatch_link tests ───────────────────────────────────────────

    #[test]
    fn dispatch_link_creates_hard_link() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"source.txt"))
            .unwrap()
            .child;

        let result = dispatch_link(&mut backend, file.ino, 1, b"alias.txt").unwrap();

        assert_eq!(result.child.ino, file.ino);
        assert_eq!(result.child.kind, NsNodeKind::File);
        assert_eq!(result.dir_entry.kind, NsNodeKind::File);
        let lookup = backend.lookup(1, b"alias.txt").unwrap();
        assert_eq!(lookup.ino, file.ino);
        // nlink should have increased
        let attr = backend.attr(file.ino);
        assert_eq!(attr.nlink, 2);
    }

    #[test]
    fn dispatch_link_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"source.txt"))
            .unwrap()
            .child;
        handle_create(&mut backend, create_request(1, b"existing.txt")).unwrap();

        let error = dispatch_link(&mut backend, file.ino, 1, b"existing.txt").unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn dispatch_link_source_is_directory_returns_eisdir() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"subdir"))
            .unwrap()
            .child;

        let error = dispatch_link(&mut backend, dir.ino, 1, b"dir_alias").unwrap_err();

        assert_eq!(error, NsOpError::IsDirectory);
        assert_eq!(error.errno(), ns_errno::EISDIR);
    }

    #[test]
    fn dispatch_link_nonexistent_source_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = dispatch_link(&mut backend, 99, 1, b"alias.txt").unwrap_err();

        assert_eq!(error, NsOpError::InodeNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_link_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"source.txt"))
            .unwrap()
            .child;

        let error = dispatch_link(&mut backend, file.ino, 99, b"alias.txt").unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    // ── dispatch_unlink tests ─────────────────────────────────────────

    #[test]
    fn dispatch_unlink_removes_file() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let result = dispatch_unlink(&mut backend, 1, b"file.txt").unwrap();

        assert_eq!(result.removed.ino, file.ino);
        assert_eq!(result.parent.ino, 1);
        assert!(backend.lookup(1, b"file.txt").is_none());
    }

    #[test]
    fn dispatch_unlink_directory_returns_eisdir() {
        let mut backend = TestBackend::new();
        handle_mkdir(&mut backend, mkdir_request(1, b"subdir")).unwrap();

        let error = dispatch_unlink(&mut backend, 1, b"subdir").unwrap_err();

        assert_eq!(error, NsOpError::IsDirectory);
        assert_eq!(error.errno(), ns_errno::EISDIR);
    }

    #[test]
    fn dispatch_unlink_missing_entry_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = dispatch_unlink(&mut backend, 1, b"missing").unwrap_err();

        assert_eq!(error, NsOpError::EntryNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_unlink_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = dispatch_unlink(&mut backend, 99, b"file.txt").unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_unlink_empty_name_returns_einval() {
        let mut backend = TestBackend::new();
        let error = dispatch_unlink(&mut backend, 1, b"").unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn symlink_inserts_link_and_stores_target() {
        let mut backend = TestBackend::new();

        let result =
            handle_symlink(&mut backend, symlink_request(1, b"link", b"target/file")).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Symlink);
        assert_eq!(result.child.mode, NS_SYMLINK_MODE);
        assert_eq!(result.child.uid, 1000);
        assert_eq!(result.child.gid, 1000);
        assert_eq!(result.child.nlink, 1);
        assert_eq!(result.dir_entry.kind, NsNodeKind::Symlink);
        assert_eq!(backend.lookup(1, b"link").unwrap().ino, result.child.ino);
        assert_eq!(
            backend.symlink_target(result.child.ino),
            Some(&b"target/file"[..])
        );
        assert_eq!(backend.touched, vec![1]);
    }

    #[test]
    fn symlink_empty_target_returns_einval_without_entry() {
        let mut backend = TestBackend::new();

        let error = handle_symlink(&mut backend, symlink_request(1, b"link", b"")).unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
        assert!(backend.lookup(1, b"link").is_none());
        assert!(backend.symlink_targets.is_empty());
    }

    #[test]
    fn symlink_name_too_long_returns_enametoolong() {
        let mut backend = TestBackend::new();
        let long_name = [b'x'; NS_NAME_MAX + 1];

        let error =
            handle_symlink(&mut backend, symlink_request(1, &long_name, b"target")).unwrap_err();

        assert_eq!(error, NsOpError::NameTooLong);
        assert_eq!(error.errno(), ns_errno::ENAMETOOLONG);
        assert!(backend.symlink_targets.is_empty());
    }

    #[test]
    fn symlink_file_parent_returns_enotdir() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let error = handle_symlink(&mut backend, symlink_request(file.ino, b"link", b"target"))
            .unwrap_err();

        assert_eq!(error, NsOpError::ParentNotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
        assert!(backend.symlink_targets.is_empty());
    }

    #[test]
    fn symlink_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"existing.txt")).unwrap();

        let error = handle_symlink(&mut backend, symlink_request(1, b"existing.txt", b"target"))
            .unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
        assert!(backend.symlink_targets.is_empty());
    }

    #[test]
    fn link_inserts_alias_and_bumps_source_link() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let result = handle_link(&mut backend, link_request(file.ino, 1, b"alias.txt")).unwrap();

        assert_eq!(result.child.ino, file.ino);
        assert_eq!(result.child.kind, NsNodeKind::File);
        assert_eq!(result.child.nlink, 2);
        assert_eq!(result.dir_entry.ino, file.ino);
        assert_eq!(backend.lookup(1, b"file.txt").unwrap().ino, file.ino);
        assert_eq!(backend.lookup(1, b"alias.txt").unwrap().ino, file.ino);
        assert_eq!(backend.attr(file.ino).nlink, 2);
        assert_eq!(backend.touched, vec![1, 1]);
    }

    #[test]
    fn link_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;
        handle_create(&mut backend, create_request(1, b"existing.txt")).unwrap();

        let error =
            handle_link(&mut backend, link_request(file.ino, 1, b"existing.txt")).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
        assert_eq!(backend.attr(file.ino).nlink, 1);
    }

    #[test]
    fn link_directory_source_returns_eisdir() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"dir"))
            .unwrap()
            .child;

        let error = handle_link(&mut backend, link_request(dir.ino, 1, b"dir_alias")).unwrap_err();

        assert_eq!(error, NsOpError::IsDirectory);
        assert_eq!(error.errno(), ns_errno::EISDIR);
        assert!(backend.lookup(1, b"dir_alias").is_none());
        assert_eq!(backend.attr(dir.ino).nlink, 2);
    }

    #[test]
    fn link_missing_source_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = handle_link(&mut backend, link_request(99, 1, b"alias.txt")).unwrap_err();

        assert_eq!(error, NsOpError::InodeNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
        assert!(backend.lookup(1, b"alias.txt").is_none());
    }

    #[test]
    fn link_missing_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let error =
            handle_link(&mut backend, link_request(file.ino, 99, b"alias.txt")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
        assert_eq!(backend.attr(file.ino).nlink, 1);
    }

    #[test]
    fn unlink_removes_file_and_drops_child_link() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let result = handle_unlink(&mut backend, remove_request(1, b"file.txt")).unwrap();

        assert_eq!(backend.lookup(1, b"file.txt"), None);
        assert_eq!(result.removed.ino, file.ino);
        assert_eq!(result.removed.nlink, 0);
        assert_eq!(backend.attr(file.ino).nlink, 0);
    }

    #[test]
    fn plan_unlink_records_parent_target_identity_and_intent() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let plan = plan_remove(
            &backend,
            remove_request(1, b"file.txt"),
            NsRemoveIntent::Unlink,
        )
        .unwrap();

        assert_eq!(plan.intent, NsRemoveIntent::Unlink);
        assert_eq!(plan.parent.ino, 1);
        assert_eq!(plan.name, b"file.txt");
        assert_eq!(plan.dir_entry.ino, file.ino);
        assert_eq!(plan.dir_entry.kind, NsNodeKind::File);
        assert_eq!(plan.target, file);
        assert_eq!(backend.lookup(1, b"file.txt").unwrap().ino, file.ino);
    }

    #[test]
    fn unlink_directory_returns_eisdir() {
        let mut backend = TestBackend::new();
        handle_mkdir(&mut backend, mkdir_request(1, b"dir")).unwrap();
        let error = handle_unlink(&mut backend, remove_request(1, b"dir")).unwrap_err();

        assert_eq!(error, NsOpError::IsDirectory);
        assert_eq!(error.errno(), ns_errno::EISDIR);
    }

    #[test]
    fn unlink_missing_name_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = handle_unlink(&mut backend, remove_request(1, b"missing")).unwrap_err();

        assert_eq!(error, NsOpError::EntryNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn plan_unlink_missing_name_projects_negative_enoent_reply() {
        let backend = TestBackend::new();
        let result = plan_remove(
            &backend,
            remove_request(1, b"missing"),
            NsRemoveIntent::Unlink,
        );
        let error = result.unwrap_err();
        let commit = plan_remove_reply(700, Err(error));

        assert_eq!(error, NsOpError::EntryNotFound);
        assert_eq!(namespace_remove_errno(error), -ns_errno::ENOENT);
        assert_eq!(commit.unique, 700);
        assert_eq!(commit.error_or_zero, -ns_errno::ENOENT);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn rmdir_removes_empty_dir_and_drops_links() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"dir"))
            .unwrap()
            .child;

        let result = handle_rmdir(&mut backend, remove_request(1, b"dir")).unwrap();

        assert_eq!(backend.lookup(1, b"dir"), None);
        assert_eq!(result.removed.ino, dir.ino);
        assert_eq!(result.removed.nlink, 0);
        assert_eq!(result.parent.nlink, 2);
        assert_eq!(backend.attr(dir.ino).nlink, 0);
    }

    #[test]
    fn plan_rmdir_records_directory_intent_and_success_reply() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"dir"))
            .unwrap()
            .child;

        let plan = plan_remove(&backend, remove_request(1, b"dir"), NsRemoveIntent::Rmdir).unwrap();
        let commit = plan_remove_reply(701, Ok(plan));

        assert_eq!(plan.intent, NsRemoveIntent::Rmdir);
        assert_eq!(plan.parent.ino, 1);
        assert_eq!(plan.dir_entry.ino, dir.ino);
        assert_eq!(plan.target, dir);
        assert_eq!(commit.unique, 701);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert_eq!(backend.lookup(1, b"dir").unwrap().ino, dir.ino);
    }

    #[test]
    fn rmdir_non_empty_returns_enotempty() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"dir"))
            .unwrap()
            .child;
        handle_create(&mut backend, create_request(dir.ino, b"file.txt")).unwrap();

        let error = handle_rmdir(&mut backend, remove_request(1, b"dir")).unwrap_err();

        assert_eq!(error, NsOpError::DirectoryNotEmpty);
        assert_eq!(error.errno(), ns_errno::ENOTEMPTY);
        assert!(backend.lookup(1, b"dir").is_some());
    }

    #[test]
    fn plan_rmdir_non_empty_refuses_before_mutation() {
        let mut backend = TestBackend::new();
        let dir = handle_mkdir(&mut backend, mkdir_request(1, b"dir"))
            .unwrap()
            .child;
        handle_create(&mut backend, create_request(dir.ino, b"file.txt")).unwrap();

        let error =
            plan_remove(&backend, remove_request(1, b"dir"), NsRemoveIntent::Rmdir).unwrap_err();

        assert_eq!(error, NsOpError::DirectoryNotEmpty);
        assert_eq!(namespace_remove_errno(error), -ns_errno::ENOTEMPTY);
        assert!(backend.lookup(1, b"dir").is_some());
        assert_eq!(
            backend.lookup(dir.ino, b"file.txt").unwrap().kind,
            NsNodeKind::File
        );
    }

    #[test]
    fn rmdir_file_returns_enotdir() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();
        let error = handle_rmdir(&mut backend, remove_request(1, b"file.txt")).unwrap_err();

        assert_eq!(error, NsOpError::NotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn is_namespace_mut_detects_correct_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            nodeid: 10,
            ..Default::default()
        };
        assert!(is_namespace_mut_request(&ctx));
    }

    #[test]
    fn is_namespace_mut_rejects_other_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::DirStream.as_u32(),
            ..Default::default()
        };
        assert!(!is_namespace_mut_request(&ctx));
    }

    #[test]
    fn dispatch_preserves_context() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            unique: 200,
            nodeid: 10,
            request_class: PosixFilesystemAdapterRequestClass::NamespaceMut.as_u32(),
            shard_key_policy: PosixFilesystemAdapterShardKeyPolicy::ParentDir.as_u32(),
            ..Default::default()
        };
        let dispatched = dispatch_namespace_mut(ctx);
        assert_eq!(dispatched.unique, ctx.unique);
        assert_eq!(dispatched.nodeid, 10);
    }

    #[test]
    fn shard_key_is_nodeid() {
        assert_eq!(namespace_mut_shard_key(10), 10);
    }

    // ── DirStreamEntry tests ──────────────────────────────────────────

    #[test]
    fn dir_stream_name_from_bytes() {
        let name = DirStreamName::from_bytes(b"hello.txt");
        assert_eq!(name.len, 9);
        assert_eq!(name.as_bytes(), b"hello.txt");
    }

    #[test]
    fn dir_stream_name_truncation() {
        let long = [b'x'; 300];
        let name = DirStreamName::from_bytes(&long);
        assert_eq!(name.len as usize, DIR_STREAM_MAX_NAME);
    }

    #[test]
    fn dir_stream_name_empty() {
        let name = DirStreamName::empty();
        assert_eq!(name.len, 0);
        assert!(name.as_bytes().is_empty());
    }

    #[test]
    fn dir_stream_entry_construction() {
        let name = DirStreamName::from_bytes(b"README.md");
        let entry = DirStreamEntry::new(name, 42, 1, 5, 2);
        assert_eq!(entry.inode_id, 42);
        assert_eq!(entry.generation, 1);
        assert_eq!(entry.cookie, 5);
        assert_eq!(entry.kind, 2);
    }

    // ── dir-stream helpers ────────────────────────────────────────────

    #[test]
    fn is_dir_stream_detects_dir_stream_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::DirStream.as_u32(),
            ..Default::default()
        };
        assert!(is_dir_stream_request(&ctx));
    }

    #[test]
    fn is_dir_stream_rejects_other_class() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            request_class: PosixFilesystemAdapterRequestClass::MetaRead.as_u32(),
            ..Default::default()
        };
        assert!(!is_dir_stream_request(&ctx));
    }

    #[test]
    fn dir_stream_shard_key_uses_nodeid() {
        assert_eq!(dir_stream_shard_key(100), 100);
    }

    #[test]
    fn compute_readdir_cookie_uses_explicit_cookie() {
        assert_eq!(compute_readdir_cookie(99, 0, 0), 99);
    }

    #[test]
    fn compute_readdir_cookie_falls_back_to_offset_idx() {
        assert_eq!(compute_readdir_cookie(0, 10, 0), 11);
        assert_eq!(compute_readdir_cookie(0, 10, 1), 12);
        assert_eq!(compute_readdir_cookie(0, 0, 4), 5);
    }

    #[test]
    fn compute_readdir_cookie_saturates_on_large_offset() {
        assert_eq!(compute_readdir_cookie(0, u64::MAX, 0), u64::MAX);
        assert_eq!(compute_readdir_cookie(0, u64::MAX - 1, 8), u64::MAX);
    }

    #[test]
    fn is_readdirplus_detects_opcode_44() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            opcode: 44, // FUSE_READDIRPLUS
            ..Default::default()
        };
        assert!(is_readdirplus_request(&ctx));
    }

    #[test]
    fn is_readdirplus_rejects_readdir_opcode() {
        let ctx = PosixFilesystemAdapterRequestContextMirrorRecord {
            opcode: 28, // FUSE_READDIR
            ..Default::default()
        };
        assert!(!is_readdirplus_request(&ctx));
    }

    // ── DirIndex bridge tests (issue #2523) ───────────────────────────

    #[test]
    fn entry_from_dir_micro_entry_preserves_fields() {
        let idx = test_dir_index(1);
        let raw = idx.lookup(b"file_000.txt").unwrap();
        let e = entry_from_dir_micro_entry(&raw, 0, 50, 3);
        assert_eq!(e.inode_id, 100);
        assert_eq!(e.generation, 0);
        assert_eq!(e.kind, 1); // DirMicroEntry kind 1 = File (i%3==0 → 1)
        assert_eq!(e.cookie, 54); // offset(50) + idx(3) + 1
    }

    #[test]
    fn handle_readdir_empty_dir() {
        let idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        let (entries, next_off) = handle_readdir(&idx, 0, 128);
        assert!(entries.is_empty());
        assert_eq!(next_off, 0);
        assert!(is_readdir_eof(&idx, 0));
    }

    #[test]
    fn plan_readdir_resume_records_page_boundary() {
        let idx = test_dir_index(8);
        let plan = plan_readdir_resume(&idx, 0, 3);

        assert_eq!(plan.start_offset, 0);
        assert_eq!(plan.max_entries, 3);
        assert_eq!(plan.available_entries, 8);
        assert_eq!(plan.returned_entries(), 3);
        assert_eq!(plan.remaining_entries(), 5);
        assert_eq!(plan.next_offset, 3);
        assert!(!plan.eof);
        assert_eq!(plan.entries[0].name.as_bytes(), b"file_000.txt");
        assert_eq!(plan.entries[2].name.as_bytes(), b"file_002.txt");
    }

    #[test]
    fn plan_readdir_resume_continues_after_last_cookie() {
        let idx = test_dir_index(8);
        let first = plan_readdir_resume(&idx, 0, 3);
        let second = plan_readdir_resume(&idx, first.next_offset, 3);

        assert_eq!(second.start_offset, first.next_offset);
        assert_eq!(second.available_entries, 5);
        assert_eq!(second.returned_entries(), 3);
        assert_eq!(second.next_offset, 6);
        assert!(!second.eof);
        assert_eq!(second.entries[0].name.as_bytes(), b"file_003.txt");
        assert_eq!(second.entries[2].name.as_bytes(), b"file_005.txt");
    }

    #[test]
    fn plan_readdir_resume_marks_eof_only_when_drained() {
        let idx = test_dir_index(5);
        let plan = plan_readdir_resume(&idx, 4, 10);

        assert_eq!(plan.available_entries, 1);
        assert_eq!(plan.returned_entries(), 1);
        assert_eq!(plan.remaining_entries(), 0);
        assert_eq!(plan.next_offset, 0);
        assert!(plan.eof);
        assert_eq!(plan.entries[0].name.as_bytes(), b"file_004.txt");
    }

    #[test]
    fn plan_readdir_resume_zero_limit_does_not_claim_eof() {
        let idx = test_dir_index(5);
        let plan = plan_readdir_resume(&idx, 2, 0);

        assert_eq!(plan.start_offset, 2);
        assert_eq!(plan.available_entries, 3);
        assert_eq!(plan.returned_entries(), 0);
        assert_eq!(plan.remaining_entries(), 3);
        assert_eq!(plan.next_offset, 2);
        assert!(!plan.eof);
        assert!(plan.entries.is_empty());
    }

    #[test]
    fn handle_readdir_single_page() {
        let idx = test_dir_index(5);
        let (entries, next_off) = handle_readdir(&idx, 0, 128);
        assert_eq!(entries.len(), 5);
        // Names are sorted by dir-index ordering
        assert_eq!(entries[0].name.as_bytes(), b"file_000.txt");
        assert_eq!(entries[4].name.as_bytes(), b"file_004.txt");
        // Next offset should be 0 (EOF) since all entries consumed
        assert_eq!(next_off, 0);
        // EOF for empty-remaining: list_from(0) would re-start from beginning,
        // but next_off == 0 is the FUSE EOF signal
        assert!(is_readdir_eof(&idx, entries[4].cookie));
    }

    #[test]
    fn handle_readdir_multi_page() {
        let idx = test_dir_index(10);
        // Request only 3 entries per page
        let (page1, off1) = handle_readdir(&idx, 0, 3);
        assert_eq!(page1.len(), 3);
        assert_eq!(page1[0].cookie, 1);
        assert_eq!(page1[2].cookie, 3);
        assert!(off1 > 0); // more entries remain

        // Resume from page1's last cookie (kernel passes cookie as-is)
        let (page2, off2) = handle_readdir(&idx, off1, 3);
        assert_eq!(page2.len(), 3);
        assert_eq!(page2[0].name.as_bytes(), b"file_003.txt");
        assert_eq!(page2[2].name.as_bytes(), b"file_005.txt");
        assert!(off2 > 0);

        // Last page (4 remaining)
        let (page3, off3) = handle_readdir(&idx, off2, 3);
        assert_eq!(page3.len(), 3);
        let (page4, off4) = handle_readdir(&idx, off3, 3);
        assert_eq!(page4.len(), 1); // only file_009.txt left
        assert_eq!(off4, 0); // EOF

        // Total entries across pages = 10
        let total = page1.len() + page2.len() + page3.len() + page4.len();
        assert_eq!(total, 10);
    }

    #[test]
    fn handle_readdir_respects_max_entries() {
        let idx = test_dir_index(10);
        let (entries, _) = handle_readdir(&idx, 0, 4);
        assert_eq!(entries.len(), 4);
    }

    #[test]
    fn handle_readdir_all_returns_all() {
        let idx = test_dir_index(7);
        let entries = handle_readdir_all(&idx);
        assert_eq!(entries.len(), 7);
    }

    #[test]
    fn entry_conversion_directory_kind() {
        let mut idx = DirIndex::new(1, DatasetDirPolicy::DEFAULT);
        idx.insert(b"subdir", 200, 0, 0).unwrap(); // kind 0 = dir
        let raw = idx.lookup(b"subdir").unwrap();
        let e = entry_from_dir_micro_entry(&raw, 0, 0, 0);
        assert_eq!(e.kind, 0); // directory
        assert_eq!(e.inode_id, 200);
    }

    #[test]
    fn handle_readdir_from_mid_offset_basic() {
        let idx = test_dir_index(5);
        // offset 2 should mean "start after the entry with cookie <= 2"
        let (entries, _) = handle_readdir(&idx, 2, 128);
        // dir-index list_from returns all entries >= cookie
        // In micro-list mode, offset 2 = DirCookie(2) = entry index 2
        // So we get entries [2..], i.e. file_002, file_003, file_004
        assert!(!entries.is_empty());
    }
    #[test]
    fn same_directory_rename_overwrites_target() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();
        directory.insert(b"new", 20, 3, 4).unwrap();

        let outcome =
            handle_rename_same_directory(request(1, b"old", 1, b"new", 0), &mut directory).unwrap();

        let overwritten = outcome.overwritten.expect("target should be overwritten");
        assert_eq!(overwritten.inode_id, 20);
        assert!(!outcome.exchanged);
        assert!(!directory.contains(b"old"));
        assert_eq!(directory.lookup(b"new").unwrap().inode_id, 10);
        assert_eq!(directory.len(), 1);
    }

    #[test]
    fn same_directory_no_replace_rejects_existing_target() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();
        directory.insert(b"new", 20, 3, 4).unwrap();

        assert_eq!(
            handle_rename_same_directory(
                request(1, b"old", 1, b"new", RENAME_NOREPLACE),
                &mut directory,
            ),
            Err(NamespaceRenameError::TargetExists)
        );
        assert_eq!(directory.lookup(b"old").unwrap().inode_id, 10);
        assert_eq!(directory.lookup(b"new").unwrap().inode_id, 20);
    }

    #[test]
    fn same_directory_exchange_swaps_entries() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"left", 10, 1, 2).unwrap();
        directory.insert(b"right", 20, 3, 4).unwrap();

        let outcome = handle_rename_same_directory(
            request(1, b"left", 1, b"right", RENAME_EXCHANGE),
            &mut directory,
        )
        .unwrap();

        assert!(outcome.exchanged);
        assert!(outcome.overwritten.is_none());
        assert_eq!(directory.lookup(b"left").unwrap().inode_id, 20);
        assert_eq!(directory.lookup(b"right").unwrap().inode_id, 10);
    }

    #[test]
    fn cross_directory_rename_moves_entry() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();

        let outcome = handle_rename_cross_directory(
            request(1, b"old", 2, b"new", 0),
            &mut source_directory,
            &mut target_directory,
        )
        .unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(!source_directory.contains(b"old"));
        assert_eq!(target_directory.lookup(b"new").unwrap().inode_id, 10);
    }

    #[test]
    fn cross_directory_no_replace_rejects_existing_target() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();
        target_directory.insert(b"new", 20, 3, 4).unwrap();

        assert_eq!(
            handle_rename_cross_directory(
                request(1, b"old", 2, b"new", RENAME_NOREPLACE),
                &mut source_directory,
                &mut target_directory,
            ),
            Err(NamespaceRenameError::TargetExists)
        );
        assert_eq!(source_directory.lookup(b"old").unwrap().inode_id, 10);
        assert_eq!(target_directory.lookup(b"new").unwrap().inode_id, 20);
    }

    #[test]
    fn cross_directory_exchange_swaps_entries() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();
        target_directory.insert(b"new", 20, 3, 4).unwrap();

        let outcome = handle_rename_cross_directory(
            request(1, b"old", 2, b"new", RENAME_EXCHANGE),
            &mut source_directory,
            &mut target_directory,
        )
        .unwrap();

        assert!(outcome.exchanged);
        assert_eq!(source_directory.lookup(b"old").unwrap().inode_id, 20);
        assert_eq!(target_directory.lookup(b"new").unwrap().inode_id, 10);
    }

    #[test]
    fn exchange_requires_existing_target() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();

        assert_eq!(
            handle_rename_cross_directory(
                request(1, b"old", 2, b"missing", RENAME_EXCHANGE),
                &mut source_directory,
                &mut target_directory,
            ),
            Err(NamespaceRenameError::TargetNotFound)
        );
        assert_eq!(source_directory.lookup(b"old").unwrap().inode_id, 10);
        assert!(target_directory.is_empty());
    }

    #[test]
    fn invalid_flag_combinations_are_rejected() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();

        assert_eq!(
            handle_rename_same_directory(
                request(1, b"old", 1, b"new", RENAME_NOREPLACE | RENAME_EXCHANGE),
                &mut directory,
            ),
            Err(NamespaceRenameError::InvalidFlags)
        );
        assert_eq!(
            handle_rename_same_directory(request(1, b"old", 1, b"new", 4), &mut directory),
            Err(NamespaceRenameError::InvalidFlags)
        );
    }

    #[test]
    fn parent_topology_mismatch_is_rejected() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();

        assert_eq!(
            handle_rename_same_directory(request(1, b"old", 2, b"new", 0), &mut directory),
            Err(NamespaceRenameError::ParentTopologyMismatch)
        );
    }

    #[test]
    fn namespace_rename_errno_maps_expected_errors() {
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::SourceNotFound),
            RENAME_ERRNO_ENOENT
        );
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::TargetNotFound),
            RENAME_ERRNO_ENOENT
        );
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::TargetExists),
            RENAME_ERRNO_EEXIST
        );
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::InvalidFlags),
            RENAME_ERRNO_EINVAL
        );
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::ParentTopologyMismatch),
            RENAME_ERRNO_EINVAL
        );
        assert_eq!(
            namespace_rename_errno(NamespaceRenameError::DirectoryIndex(
                DirIndexError::DirNotEmpty
            )),
            RENAME_ERRNO_ENOTEMPTY
        );
    }

    #[test]
    fn plan_rename_reply_success_uses_empty_small_reply() {
        let commit = plan_rename_reply(500, Ok(NamespaceRenameOutcome::renamed(None)));

        assert_eq!(commit.unique, 500);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn plan_rename_reply_error_uses_mapped_errno() {
        let commit = plan_rename_reply(501, Err(NamespaceRenameError::TargetExists));

        assert_eq!(commit.unique, 501);
        assert_eq!(commit.error_or_zero, RENAME_ERRNO_EEXIST);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
    }

    #[test]
    fn plan_rename_reply_accepts_handler_result_directly() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();
        directory.insert(b"new", 20, 3, 4).unwrap();

        let result = handle_rename_same_directory(
            request(1, b"old", 1, b"new", RENAME_NOREPLACE),
            &mut directory,
        );
        let commit = plan_rename_reply(502, result);

        assert_eq!(commit.error_or_zero, RENAME_ERRNO_EEXIST);
        assert_eq!(directory.lookup(b"old").unwrap().inode_id, 10);
        assert_eq!(directory.lookup(b"new").unwrap().inode_id, 20);
    }

    #[test]
    fn same_directory_backend_dispatch_plans_success_and_mutates_directory() {
        let mut directory = DirIndex::new(1, test_policy());
        directory.insert(b"old", 10, 1, 2).unwrap();

        let commit = {
            let mut backend = SameDirectoryRenameBackend::new(&mut directory);
            dispatch_rename_with_backend(600, request(1, b"old", 1, b"new", 0), &mut backend)
        };

        assert_eq!(commit.unique, 600);
        assert_eq!(commit.error_or_zero, 0);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(
            commit.reply_class,
            PosixFilesystemAdapterReplyClass::SmallReply.as_u32()
        );
        assert!(!directory.contains(b"old"));
        assert_eq!(directory.lookup(b"new").unwrap().inode_id, 10);
    }

    #[test]
    fn cross_directory_backend_dispatch_plans_mapped_error() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();
        target_directory.insert(b"new", 20, 3, 4).unwrap();

        let commit = {
            let mut backend =
                CrossDirectoryRenameBackend::new(&mut source_directory, &mut target_directory);
            dispatch_rename_with_backend(
                601,
                request(1, b"old", 2, b"new", RENAME_NOREPLACE),
                &mut backend,
            )
        };

        assert_eq!(commit.unique, 601);
        assert_eq!(commit.error_or_zero, RENAME_ERRNO_EEXIST);
        assert_eq!(commit.payload_len, 0);
        assert_eq!(source_directory.lookup(b"old").unwrap().inode_id, 10);
        assert_eq!(target_directory.lookup(b"new").unwrap().inode_id, 20);
    }

    #[test]
    fn cross_directory_backend_dispatch_plans_success_and_moves_entry() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        source_directory.insert(b"old", 10, 1, 2).unwrap();

        let commit = {
            let mut backend =
                CrossDirectoryRenameBackend::new(&mut source_directory, &mut target_directory);
            dispatch_rename_with_backend(602, request(1, b"old", 2, b"new", 0), &mut backend)
        };

        assert_eq!(commit.unique, 602);
        assert_eq!(commit.error_or_zero, 0);
        assert!(!source_directory.contains(b"old"));
        assert_eq!(target_directory.lookup(b"new").unwrap().inode_id, 10);
    }

    #[test]
    fn cross_directory_rename_works_with_btree_indexes() {
        let mut source_directory = DirIndex::new(1, test_policy());
        let mut target_directory = DirIndex::new(2, test_policy());
        for index in 0..10 {
            source_directory
                .insert(format!("source{index:02}").as_bytes(), index, 0, 0)
                .unwrap();
            target_directory
                .insert(format!("target{index:02}").as_bytes(), 100 + index, 0, 0)
                .unwrap();
        }
        assert_eq!(source_directory.representation(), DirStorageKind::BTREE);
        assert_eq!(target_directory.representation(), DirStorageKind::BTREE);

        let outcome = handle_rename_cross_directory(
            request(1, b"source05", 2, b"target05", 0),
            &mut source_directory,
            &mut target_directory,
        )
        .unwrap();

        assert_eq!(outcome.overwritten.unwrap().inode_id, 105);
        assert_eq!(target_directory.lookup(b"target05").unwrap().inode_id, 5);
        assert!(!source_directory.contains(b"source05"));
    }

    // ── Dir-stream dispatch tests (issue #3142) ────────────────────────

    /// Minimal [`DirStreamBackend`] for unit testing the dispatch functions.
    struct TestDirStreamBackend {
        inodes: Vec<NsInodeAttr>,
        dirs: Vec<(u64, DirIndex)>,
        handles: Vec<(u64, u64)>, // (handle, dir_ino)
        next_handle: u64,
    }

    impl TestDirStreamBackend {
        fn new() -> Self {
            Self {
                inodes: vec![NsInodeAttr {
                    ino: 1,
                    generation: 1,
                    kind: NsNodeKind::Directory,
                    mode: 0o40755,
                    uid: 0,
                    gid: 0,
                    nlink: 2,
                    rdev: 0,
                }],
                dirs: vec![(1, DirIndex::new(1, DatasetDirPolicy::DEFAULT))],
                handles: Vec::new(),
                next_handle: 100,
            }
        }

        fn add_inode(&mut self, ino: u64, kind: NsNodeKind) {
            self.inodes.push(NsInodeAttr {
                ino,
                generation: 1,
                kind,
                mode: 0o644,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
            });
        }

        fn add_dir_with_inode(&mut self, ino: u64) {
            self.inodes.push(NsInodeAttr {
                ino,
                generation: 1,
                kind: NsNodeKind::Directory,
                mode: 0o40755,
                uid: 0,
                gid: 0,
                nlink: 2,
                rdev: 0,
            });
            self.dirs
                .push((ino, DirIndex::new(ino, DatasetDirPolicy::DEFAULT)));
        }

        fn dir_index_mut(&mut self, ino: u64) -> Option<&mut DirIndex> {
            self.dirs
                .iter_mut()
                .find(|(dir_ino, _)| *dir_ino == ino)
                .map(|(_, idx)| idx)
        }

        fn populate_dir(&mut self, dir_ino: u64, count: usize) {
            let dir = self.dir_index_mut(dir_ino).unwrap();
            for i in 0..count {
                let name = format!("entry_{i:03}.txt");
                dir.insert(name.as_bytes(), (200 + i) as u64, i as u64, 1)
                    .unwrap();
            }
        }
    }

    impl DirStreamBackend for TestDirStreamBackend {
        fn get_dir_index(&self, ino: u64) -> Option<&DirIndex> {
            self.dirs
                .iter()
                .find(|(dir_ino, _)| *dir_ino == ino)
                .map(|(_, idx)| idx)
        }

        fn get_dir_attr(&self, ino: u64) -> Result<NsInodeAttr, NsOpError> {
            self.inodes
                .iter()
                .find(|attr| attr.ino == ino)
                .copied()
                .ok_or(NsOpError::InodeNotFound)
        }

        fn alloc_dir_handle(&mut self, ino: u64) -> Result<u64, NsOpError> {
            let handle = self.next_handle;
            self.next_handle += 1;
            self.handles.push((handle, ino));
            Ok(handle)
        }

        fn release_dir_handle(&mut self, handle: u64) -> Result<(), NsOpError> {
            let pos = self
                .handles
                .iter()
                .position(|(h, _)| *h == handle)
                .ok_or(NsOpError::BadHandle)?;
            self.handles.remove(pos);
            Ok(())
        }

        fn lookup_dir_handle(&self, handle: u64) -> Option<u64> {
            self.handles
                .iter()
                .find(|(h, _)| *h == handle)
                .map(|(_, ino)| *ino)
        }
    }

    #[test]
    fn dispatch_opendir_succeeds_for_directory() {
        let mut backend = TestDirStreamBackend::new();
        let result = dispatch_opendir(&mut backend, 1, 0).unwrap();
        assert!(result.handle >= 100);
        assert_eq!(result.open_flags, 0);
        assert_eq!(backend.lookup_dir_handle(result.handle), Some(1));
    }

    #[test]
    fn dispatch_opendir_returns_enotdir_for_file() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_inode(2, NsNodeKind::File);
        let err = dispatch_opendir(&mut backend, 2, 0).unwrap_err();
        assert_eq!(err, NsOpError::NotDirectory);
        assert_eq!(err.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn dispatch_opendir_returns_enoent_for_missing_inode() {
        let mut backend = TestDirStreamBackend::new();
        let err = dispatch_opendir(&mut backend, 99, 0).unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
        assert_eq!(err.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_opendir_returns_enotdir_when_no_dir_index() {
        // Inode is a directory but dirs table has no entry for it
        let mut backend = TestDirStreamBackend::new();
        backend.add_inode(5, NsNodeKind::Directory);
        // But we never called add_dir_with_inode, so get_dir_index returns None
        let err = dispatch_opendir(&mut backend, 5, 0).unwrap_err();
        assert_eq!(err, NsOpError::NotDirectory);
        assert_eq!(err.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn dispatch_readdir_empty_dir_returns_eof() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        let result = dispatch_readdir(&backend, h, 0, 128).unwrap();
        assert!(result.entries.is_empty());
        assert!(result.eof);
        assert_eq!(result.next_offset, 0);
    }

    #[test]
    fn dispatch_readdir_returns_entries_with_correct_names() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        backend.populate_dir(2, 5);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        let result = dispatch_readdir(&backend, h, 0, 128).unwrap();
        assert_eq!(result.entries.len(), 5);
        assert_eq!(result.entries[0].name.as_bytes(), b"entry_000.txt");
        assert_eq!(result.entries[4].name.as_bytes(), b"entry_004.txt");
        assert!(result.eof);
    }

    #[test]
    fn dispatch_readdir_pagination_across_pages() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        backend.populate_dir(2, 10);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        let page1 = dispatch_readdir(&backend, h, 0, 3).unwrap();
        assert_eq!(page1.entries.len(), 3);
        assert_eq!(page1.entries[0].name.as_bytes(), b"entry_000.txt");
        assert_eq!(page1.entries[2].name.as_bytes(), b"entry_002.txt");
        assert!(!page1.eof);
        assert!(page1.next_offset > 0);

        let page2 = dispatch_readdir(&backend, h, page1.next_offset, 3).unwrap();
        assert_eq!(page2.entries.len(), 3);
        assert_eq!(page2.entries[0].name.as_bytes(), b"entry_003.txt");
        assert_eq!(page2.entries[2].name.as_bytes(), b"entry_005.txt");
        assert!(!page2.eof);

        let page3 = dispatch_readdir(&backend, h, page2.next_offset, 3).unwrap();
        assert_eq!(page3.entries.len(), 3);
        let page4 = dispatch_readdir(&backend, h, page3.next_offset, 3).unwrap();
        assert_eq!(page4.entries.len(), 1);
        assert_eq!(page4.entries[0].name.as_bytes(), b"entry_009.txt");
        assert!(page4.eof);

        let total =
            page1.entries.len() + page2.entries.len() + page3.entries.len() + page4.entries.len();
        assert_eq!(total, 10);
    }

    #[test]
    fn dispatch_readdir_offset_beyond_end_returns_empty_eof() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        backend.populate_dir(2, 3);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        // First, drain the directory
        let r1 = dispatch_readdir(&backend, h, 0, 128).unwrap();
        assert_eq!(r1.entries.len(), 3);
        assert!(r1.eof);
        // FUSE cookies are 1-indexed offsets; 3 entries => last cookie is 3.
        // Reading from an offset past the last entry returns empty with eof.
        let result = dispatch_readdir(&backend, h, 999, 128).unwrap();
        assert!(result.entries.is_empty());
        assert!(result.eof);
    }

    #[test]
    fn dispatch_readdir_bad_handle_returns_ebadf() {
        let backend = TestDirStreamBackend::new();
        let err = dispatch_readdir(&backend, 999, 0, 128).unwrap_err();
        assert_eq!(err, NsOpError::BadHandle);
        assert_eq!(err.errno(), ns_errno::EBADF);
    }

    #[test]
    fn dispatch_releasedir_releases_valid_handle() {
        let mut backend = TestDirStreamBackend::new();
        let h = dispatch_opendir(&mut backend, 1, 0).unwrap().handle;
        assert!(backend.lookup_dir_handle(h).is_some());

        dispatch_releasedir(&mut backend, h).unwrap();
        assert!(backend.lookup_dir_handle(h).is_none());
    }

    #[test]
    fn dispatch_releasedir_bad_handle_returns_ebadf() {
        let mut backend = TestDirStreamBackend::new();
        let err = dispatch_releasedir(&mut backend, 999).unwrap_err();
        assert_eq!(err, NsOpError::BadHandle);
        assert_eq!(err.errno(), ns_errno::EBADF);
    }

    #[test]
    fn dispatch_readdir_after_releasedir_returns_ebadf() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        backend.populate_dir(2, 3);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        dispatch_releasedir(&mut backend, h).unwrap();
        let err = dispatch_readdir(&backend, h, 0, 128).unwrap_err();
        assert_eq!(err, NsOpError::BadHandle);
        assert_eq!(err.errno(), ns_errno::EBADF);
    }

    #[test]
    fn dispatch_opendir_preserves_handle_uniqueness() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        let h1 = dispatch_opendir(&mut backend, 1, 0).unwrap().handle;
        let h2 = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;
        assert_ne!(h1, h2);
        assert_eq!(backend.lookup_dir_handle(h1), Some(1));
        assert_eq!(backend.lookup_dir_handle(h2), Some(2));
    }

    #[test]
    fn dispatch_readdir_max_entries_respected() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        backend.populate_dir(2, 10);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;

        let result = dispatch_readdir(&backend, h, 0, 4).unwrap();
        assert_eq!(result.entries.len(), 4);
        assert!(!result.eof);
    }

    #[test]
    fn plan_opendir_errno_success_is_zero() {
        let mut backend = TestDirStreamBackend::new();
        let result = dispatch_opendir(&mut backend, 1, 0x01);
        assert_eq!(plan_opendir_errno(&result), 0);
    }

    #[test]
    fn plan_opendir_errno_notdir_is_neg_enotdir() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_inode(5, NsNodeKind::File);
        let result = dispatch_opendir(&mut backend, 5, 0);
        assert_eq!(plan_opendir_errno(&result), -(ns_errno::ENOTDIR));
    }

    #[test]
    fn plan_readdir_errno_success_is_zero() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_dir_with_inode(2);
        let h = dispatch_opendir(&mut backend, 2, 0).unwrap().handle;
        let result = dispatch_readdir(&backend, h, 0, 128);
        assert_eq!(plan_readdir_errno(&result), 0);
    }

    #[test]
    fn plan_readdir_errno_bad_handle_is_neg_ebadf() {
        let backend = TestDirStreamBackend::new();
        let result = dispatch_readdir(&backend, 999, 0, 128);
        assert_eq!(plan_readdir_errno(&result), -(ns_errno::EBADF));
    }

    #[test]
    fn plan_releasedir_errno_success_is_zero() {
        let mut backend = TestDirStreamBackend::new();
        let h = dispatch_opendir(&mut backend, 1, 0).unwrap().handle;
        let result = dispatch_releasedir(&mut backend, h);
        assert_eq!(plan_releasedir_errno(&result), 0);
    }

    #[test]
    fn plan_releasedir_errno_bad_handle_is_neg_ebadf() {
        let mut backend = TestDirStreamBackend::new();
        let result = dispatch_releasedir(&mut backend, 999);
        assert_eq!(plan_releasedir_errno(&result), -(ns_errno::EBADF));
    }

    #[test]
    fn dispatch_opendir_on_symlink_returns_enotdir() {
        let mut backend = TestDirStreamBackend::new();
        backend.add_inode(3, NsNodeKind::Symlink);
        let err = dispatch_opendir(&mut backend, 3, 0).unwrap_err();
        assert_eq!(err, NsOpError::NotDirectory);
        assert_eq!(err.errno(), ns_errno::ENOTDIR);
    }
    // ── handle_rename / dispatch_rename tests ─────────────────────────

    fn rename_request<'a>(
        old_parent: u64,
        old_name: &'a [u8],
        new_parent: u64,
        new_name: &'a [u8],
        flags: u32,
    ) -> NamespaceRenameRequest<'a> {
        NamespaceRenameRequest {
            old_parent_ino: old_parent,
            old_name,
            new_parent_ino: new_parent,
            new_name,
            flags: NamespaceRenameFlags::from_bits(flags),
        }
    }

    #[test]
    fn handle_rename_same_directory_moves_entry() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"old.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"old.txt", 1, b"new.txt", 0),
        )
        .unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(!outcome.exchanged);
        // old name gone
        assert!(backend.lookup(1, b"old.txt").is_none());
        // new name points to same inode
        let new_lookup = backend.lookup(1, b"new.txt").unwrap();
        assert_eq!(new_lookup.ino, file.ino);
        assert_eq!(new_lookup.kind, NsNodeKind::File);
    }

    #[test]
    fn handle_rename_cross_directory_moves_entry() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"source.txt"))
            .unwrap()
            .child;
        let subdir = handle_mkdir(&mut backend, mkdir_request(1, b"subdir"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"source.txt", subdir.ino, b"moved.txt", 0),
        )
        .unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(backend.lookup(1, b"source.txt").is_none());
        let moved = backend.lookup(subdir.ino, b"moved.txt").unwrap();
        assert_eq!(moved.ino, file.ino);
    }

    #[test]
    fn handle_rename_overwrites_existing_target_and_decrements_nlink() {
        let mut backend = TestBackend::new();
        let old_file = handle_create(&mut backend, create_request(1, b"old.txt"))
            .unwrap()
            .child;
        let target_file = handle_create(&mut backend, create_request(1, b"new.txt"))
            .unwrap()
            .child;

        let target_nlink_before = backend.attr(target_file.ino).nlink;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"old.txt", 1, b"new.txt", 0),
        )
        .unwrap();

        let overwritten = outcome.overwritten.expect("target should be overwritten");
        assert_eq!(overwritten.inode_id, target_file.ino);
        // old is gone, new points to old_file
        assert!(backend.lookup(1, b"old.txt").is_none());
        assert_eq!(backend.lookup(1, b"new.txt").unwrap().ino, old_file.ino);
        // overwritten inode nlink decremented
        let target_nlink_after = backend.attr(target_file.ino).nlink;
        assert_eq!(target_nlink_after, target_nlink_before - 1);
    }

    #[test]
    fn handle_rename_noreplace_rejects_existing_target() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"old.txt")).unwrap();
        handle_create(&mut backend, create_request(1, b"new.txt")).unwrap();

        let err = handle_rename(
            &mut backend,
            rename_request(1, b"old.txt", 1, b"new.txt", RENAME_NOREPLACE),
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::TargetExists);
        // Both entries still present
        assert!(backend.lookup(1, b"old.txt").is_some());
        assert!(backend.lookup(1, b"new.txt").is_some());
    }

    #[test]
    fn handle_rename_noreplace_succeeds_when_target_missing() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"old.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"old.txt", 1, b"absent.txt", RENAME_NOREPLACE),
        )
        .unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(backend.lookup(1, b"old.txt").is_none());
        assert_eq!(backend.lookup(1, b"absent.txt").unwrap().ino, file.ino);
    }

    #[test]
    fn handle_rename_nonexistent_source_returns_error() {
        let mut backend = TestBackend::new();

        let err = handle_rename(
            &mut backend,
            rename_request(1, b"missing.txt", 1, b"new.txt", 0),
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::SourceNotFound);
    }

    #[test]
    fn handle_rename_missing_old_parent_returns_error() {
        let mut backend = TestBackend::new();

        let err = handle_rename(
            &mut backend,
            rename_request(999, b"some.txt", 1, b"new.txt", 0),
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::SourceNotFound);
    }

    #[test]
    fn handle_rename_missing_new_parent_returns_error() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let err = handle_rename(
            &mut backend,
            rename_request(1, b"file.txt", 999, b"moved.txt", 0),
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::SourceNotFound);
    }

    #[test]
    fn handle_rename_invalid_flags_returns_error() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let err = handle_rename(
            &mut backend,
            rename_request(1, b"file.txt", 1, b"new.txt", 0x10), // unsupported flag
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::InvalidFlags);
    }

    #[test]
    fn handle_rename_self_is_noop() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"same.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"same.txt", 1, b"same.txt", 0),
        )
        .unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(!outcome.exchanged);
        assert_eq!(backend.lookup(1, b"same.txt").unwrap().ino, file.ino);
    }

    #[test]
    fn handle_rename_empty_name_returns_error() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let err =
            handle_rename(&mut backend, rename_request(1, b"file.txt", 1, b"", 0)).unwrap_err();

        assert_eq!(err, NamespaceRenameError::InvalidFlags);
    }

    #[test]
    fn dispatch_rename_wraps_individual_params() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"src.txt"))
            .unwrap()
            .child;

        let outcome = dispatch_rename(&mut backend, 1, b"src.txt", 1, b"dst.txt", 0).unwrap();

        assert!(outcome.overwritten.is_none());
        assert!(backend.lookup(1, b"src.txt").is_none());
        assert_eq!(backend.lookup(1, b"dst.txt").unwrap().ino, file.ino);
    }

    #[test]
    fn dispatch_rename_noreplace_flag_rejects_existing() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"a.txt")).unwrap();
        handle_create(&mut backend, create_request(1, b"b.txt")).unwrap();

        let err =
            dispatch_rename(&mut backend, 1, b"a.txt", 1, b"b.txt", RENAME_NOREPLACE).unwrap_err();

        assert_eq!(err, NamespaceRenameError::TargetExists);
    }

    // ── RENAME_EXCHANGE handle_rename tests ────────────────────────

    #[test]
    fn handle_rename_exchange_swaps_files_same_directory() {
        let mut backend = TestBackend::new();
        let left = handle_create(&mut backend, create_request(1, b"left.txt"))
            .unwrap()
            .child;
        let right = handle_create(&mut backend, create_request(1, b"right.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"left.txt", 1, b"right.txt", RENAME_EXCHANGE),
        )
        .unwrap();

        assert!(outcome.exchanged);
        assert!(outcome.overwritten.is_none());
        // left name now points to right inode
        assert_eq!(backend.lookup(1, b"left.txt").unwrap().ino, right.ino);
        // right name now points to left inode
        assert_eq!(backend.lookup(1, b"right.txt").unwrap().ino, left.ino);
    }

    #[test]
    fn handle_rename_exchange_swaps_files_cross_directory() {
        let mut backend = TestBackend::new();
        let left = handle_create(&mut backend, create_request(1, b"left.txt"))
            .unwrap()
            .child;
        let subdir = handle_mkdir(&mut backend, mkdir_request(1, b"subdir"))
            .unwrap()
            .child;
        let right = handle_create(&mut backend, create_request(subdir.ino, b"right.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"left.txt", subdir.ino, b"right.txt", RENAME_EXCHANGE),
        )
        .unwrap();

        assert!(outcome.exchanged);
        // left name (in root) now points to right inode
        assert_eq!(backend.lookup(1, b"left.txt").unwrap().ino, right.ino);
        // right name (in subdir) now points to left inode
        assert_eq!(
            backend.lookup(subdir.ino, b"right.txt").unwrap().ino,
            left.ino
        );
        // left.txt no longer in root? No — after exchange both names still exist,
        // but swapped.
        assert!(backend.lookup(1, b"left.txt").is_some());
        assert!(backend.lookup(subdir.ino, b"right.txt").is_some());
    }

    #[test]
    fn handle_rename_exchange_requires_existing_target() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"present.txt")).unwrap();

        let err = handle_rename(
            &mut backend,
            rename_request(1, b"present.txt", 1, b"missing.txt", RENAME_EXCHANGE),
        )
        .unwrap_err();

        assert_eq!(err, NamespaceRenameError::TargetNotFound);
        // Source must still exist.
        assert!(backend.lookup(1, b"present.txt").is_some());
    }

    #[test]
    fn handle_rename_exchange_same_name_is_noop() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"same.txt"))
            .unwrap()
            .child;

        let outcome = handle_rename(
            &mut backend,
            rename_request(1, b"same.txt", 1, b"same.txt", RENAME_EXCHANGE),
        )
        .unwrap();

        // Same-name exchange is detected as no-op before the exchange arm.
        assert!(!outcome.exchanged);
        assert!(outcome.overwritten.is_none());
        assert_eq!(backend.lookup(1, b"same.txt").unwrap().ino, file.ino);
    }

    #[test]
    fn dispatch_rename_exchange_swaps() {
        let mut backend = TestBackend::new();
        let left = handle_create(&mut backend, create_request(1, b"a.txt"))
            .unwrap()
            .child;
        let right = handle_create(&mut backend, create_request(1, b"b.txt"))
            .unwrap()
            .child;

        let outcome =
            dispatch_rename(&mut backend, 1, b"a.txt", 1, b"b.txt", RENAME_EXCHANGE).unwrap();

        assert!(outcome.exchanged);
        assert_eq!(backend.lookup(1, b"a.txt").unwrap().ino, right.ino);
        assert_eq!(backend.lookup(1, b"b.txt").unwrap().ino, left.ino);
    }

    // ── Xattr test backend ──────────────────────────────────────────

    use core::cell::RefCell;
    use std::collections::BTreeMap;

    type TestXattrMap = RefCell<BTreeMap<(u64, Vec<u8>), Vec<u8>>>;

    struct TestXattrBackend {
        xattrs: TestXattrMap,
        existing_inodes: Vec<u64>,
    }

    impl TestXattrBackend {
        fn new() -> Self {
            Self {
                xattrs: RefCell::new(BTreeMap::new()),
                existing_inodes: vec![1, 2, 3],
            }
        }
    }

    impl XattrBackend for TestXattrBackend {
        fn inode_exists(&self, ino: u64) -> bool {
            self.existing_inodes.contains(&ino)
        }

        fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, NsOpError> {
            self.xattrs
                .borrow()
                .get(&(ino, name.to_vec()))
                .cloned()
                .ok_or(NsOpError::XattrNotFound)
        }

        fn set_xattr(
            &self,
            ino: u64,
            name: &[u8],
            value: &[u8],
            flags: u32,
        ) -> Result<(), NsOpError> {
            let key = (ino, name.to_vec());
            let mut xattrs = self.xattrs.borrow_mut();
            match flags {
                XATTR_CREATE => {
                    if xattrs.contains_key(&key) {
                        return Err(NsOpError::XattrExists);
                    }
                }
                XATTR_REPLACE => {
                    if !xattrs.contains_key(&key) {
                        return Err(NsOpError::XattrNotFound);
                    }
                }
                _ => {}
            }
            xattrs.insert(key, value.to_vec());
            Ok(())
        }

        fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, NsOpError> {
            let mut buf = Vec::new();
            for ((i, name), _value) in self.xattrs.borrow().iter() {
                if *i == ino {
                    buf.extend_from_slice(name);
                    buf.push(0);
                }
            }
            Ok(buf)
        }

        fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), NsOpError> {
            let key = (ino, name.to_vec());
            let mut xattrs = self.xattrs.borrow_mut();
            if !xattrs.contains_key(&key) {
                return Err(NsOpError::XattrNotFound);
            }
            xattrs.remove(&key);
            Ok(())
        }
    }

    // ── Xattr dispatch tests ──────────────────────────────────────────

    #[test]
    fn xattr_validate_name_rejects_empty() {
        assert_eq!(validate_xattr_name(b""), Err(NsOpError::XattrInvalidName));
    }

    #[test]
    fn xattr_validate_name_rejects_nul() {
        assert_eq!(
            validate_xattr_name(b"user.bad\0"),
            Err(NsOpError::XattrInvalidName)
        );
    }

    #[test]
    fn xattr_validate_name_rejects_too_long() {
        let long = vec![b'x'; XATTR_NAME_MAX + 1];
        assert_eq!(validate_xattr_name(&long), Err(NsOpError::XattrInvalidName));
    }

    #[test]
    fn xattr_validate_name_accepts_max() {
        let exact = vec![b'x'; XATTR_NAME_MAX];
        assert_eq!(validate_xattr_name(&exact), Ok(()));
    }

    #[test]
    fn xattr_validate_name_accepts_valid() {
        assert_eq!(validate_xattr_name(b"user.test"), Ok(()));
    }

    #[test]
    fn xattr_validate_value_rejects_too_large() {
        let big = vec![0xCCu8; XATTR_VALUE_MAX + 1];
        assert_eq!(validate_xattr_value(&big), Err(NsOpError::XattrTooLarge));
    }

    #[test]
    fn xattr_validate_value_accepts_max() {
        let exact = vec![0xBBu8; XATTR_VALUE_MAX];
        assert_eq!(validate_xattr_value(&exact), Ok(()));
    }

    #[test]
    fn xattr_validate_value_accepts_empty() {
        assert_eq!(validate_xattr_value(b""), Ok(()));
    }

    #[test]
    fn xattr_flags_zero_is_valid() {
        assert_eq!(validate_xattr_flags(0), Ok(()));
    }

    #[test]
    fn xattr_flags_create_is_valid() {
        assert_eq!(validate_xattr_flags(XATTR_CREATE), Ok(()));
    }

    #[test]
    fn xattr_flags_replace_is_valid() {
        assert_eq!(validate_xattr_flags(XATTR_REPLACE), Ok(()));
    }

    #[test]
    fn xattr_flags_both_is_invalid() {
        assert_eq!(
            validate_xattr_flags(XATTR_CREATE | XATTR_REPLACE),
            Err(NsOpError::XattrInvalidName)
        );
    }

    #[test]
    fn xattr_flags_unknown_is_invalid() {
        assert_eq!(validate_xattr_flags(4), Err(NsOpError::XattrInvalidName));
    }

    #[test]
    fn dispatch_getxattr_retrieves_value() {
        let backend = TestXattrBackend::new();
        backend
            .xattrs
            .borrow_mut()
            .insert((1, b"user.key".to_vec()), b"val".to_vec());
        let result = dispatch_getxattr(&backend, 1, b"user.key").unwrap();
        assert_eq!(result, b"val");
    }

    #[test]
    fn dispatch_getxattr_missing_attr_returns_enodata() {
        let backend = TestXattrBackend::new();
        let err = dispatch_getxattr(&backend, 1, b"user.missing").unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
        assert_eq!(err.errno(), ns_errno::ENODATA);
    }

    #[test]
    fn dispatch_getxattr_nonexistent_inode_returns_enoent() {
        let backend = TestXattrBackend::new();
        let err = dispatch_getxattr(&backend, 999, b"user.key").unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
    }

    #[test]
    fn dispatch_getxattr_invalid_name_returns_einval() {
        let backend = TestXattrBackend::new();
        let err = dispatch_getxattr(&backend, 1, b"").unwrap_err();
        assert_eq!(err, NsOpError::XattrInvalidName);
    }

    #[test]
    fn dispatch_setxattr_creates_new_attr() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.key", b"val", 0).unwrap();
        assert_eq!(backend.get_xattr(1, b"user.key").unwrap(), b"val");
    }

    #[test]
    fn dispatch_setxattr_overwrites_with_flag_zero() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.key", b"first", 0).unwrap();
        dispatch_setxattr(&backend, 1, b"user.key", b"second", 0).unwrap();
        assert_eq!(backend.get_xattr(1, b"user.key").unwrap(), b"second");
    }

    #[test]
    fn dispatch_setxattr_create_flag_succeeds_on_new() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.newkey", b"val", XATTR_CREATE).unwrap();
        assert_eq!(backend.get_xattr(1, b"user.newkey").unwrap(), b"val");
    }

    #[test]
    fn dispatch_setxattr_create_flag_fails_on_existing() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.dup", b"first", 0).unwrap();
        let err = dispatch_setxattr(&backend, 1, b"user.dup", b"second", XATTR_CREATE).unwrap_err();
        assert_eq!(err, NsOpError::XattrExists);
        assert_eq!(err.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn dispatch_setxattr_replace_flag_succeeds_on_existing() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.rep", b"old", 0).unwrap();
        dispatch_setxattr(&backend, 1, b"user.rep", b"new", XATTR_REPLACE).unwrap();
        assert_eq!(backend.get_xattr(1, b"user.rep").unwrap(), b"new");
    }

    #[test]
    fn dispatch_setxattr_replace_flag_fails_on_missing() {
        let backend = TestXattrBackend::new();
        let err =
            dispatch_setxattr(&backend, 1, b"user.missing", b"val", XATTR_REPLACE).unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn dispatch_setxattr_nonexistent_inode() {
        let backend = TestXattrBackend::new();
        let err = dispatch_setxattr(&backend, 999, b"user.key", b"val", 0).unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
    }

    #[test]
    fn dispatch_setxattr_value_too_large() {
        let backend = TestXattrBackend::new();
        let big = vec![0xCCu8; XATTR_VALUE_MAX + 1];
        let err = dispatch_setxattr(&backend, 1, b"user.big", &big, 0).unwrap_err();
        assert_eq!(err, NsOpError::XattrTooLarge);
        assert_eq!(err.errno(), ns_errno::E2BIG);
    }

    #[test]
    fn dispatch_setxattr_accepts_exact_max_value() {
        let backend = TestXattrBackend::new();
        let exact = vec![0xBBu8; XATTR_VALUE_MAX];
        dispatch_setxattr(&backend, 1, b"user.exact", &exact, 0).unwrap();
        assert_eq!(backend.get_xattr(1, b"user.exact").unwrap(), exact);
    }

    #[test]
    fn dispatch_listxattr_returns_key_list() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.a", b"1", 0).unwrap();
        dispatch_setxattr(&backend, 1, b"user.b", b"2", 0).unwrap();
        let list = dispatch_listxattr(&backend, 1).unwrap();
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".as_slice()));
        assert!(names.contains(&b"user.b".as_slice()));
    }

    #[test]
    fn dispatch_listxattr_empty_inode() {
        let backend = TestXattrBackend::new();
        let list = dispatch_listxattr(&backend, 1).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn dispatch_listxattr_nonexistent_inode() {
        let backend = TestXattrBackend::new();
        let err = dispatch_listxattr(&backend, 999).unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
    }

    #[test]
    fn dispatch_listxattr_ends_with_null() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.z", b"x", 0).unwrap();
        let list = dispatch_listxattr(&backend, 1).unwrap();
        assert_eq!(list.last(), Some(&0));
    }

    #[test]
    fn dispatch_removexattr_removes_existing() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.del", b"val", 0).unwrap();
        dispatch_removexattr(&backend, 1, b"user.del").unwrap();
        let err = backend.get_xattr(1, b"user.del").unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn dispatch_removexattr_missing_returns_enodata() {
        let backend = TestXattrBackend::new();
        let err = dispatch_removexattr(&backend, 1, b"user.missing").unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn dispatch_removexattr_nonexistent_inode() {
        let backend = TestXattrBackend::new();
        let err = dispatch_removexattr(&backend, 999, b"user.key").unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
    }

    #[test]
    fn dispatch_removexattr_invalid_name() {
        let backend = TestXattrBackend::new();
        let err = dispatch_removexattr(&backend, 1, b"").unwrap_err();
        assert_eq!(err, NsOpError::XattrInvalidName);
    }

    #[test]
    fn xattrs_are_per_inode() {
        let backend = TestXattrBackend::new();
        dispatch_setxattr(&backend, 1, b"user.shared", b"inode1", 0).unwrap();
        dispatch_setxattr(&backend, 2, b"user.shared", b"inode2", 0).unwrap();
        assert_eq!(
            dispatch_getxattr(&backend, 1, b"user.shared").unwrap(),
            b"inode1"
        );
        assert_eq!(
            dispatch_getxattr(&backend, 2, b"user.shared").unwrap(),
            b"inode2"
        );
        assert_eq!(
            dispatch_getxattr(&backend, 3, b"user.shared").unwrap_err(),
            NsOpError::XattrNotFound
        );
    }

    #[test]
    fn xattr_error_maps_correct_errnos() {
        assert_eq!(NsOpError::XattrNotFound.errno(), ns_errno::ENODATA);
        assert_eq!(NsOpError::XattrExists.errno(), ns_errno::EEXIST);
        assert_eq!(NsOpError::XattrTooLarge.errno(), ns_errno::E2BIG);
        assert_eq!(NsOpError::XattrInvalidName.errno(), ns_errno::EINVAL);
        assert_eq!(NsOpError::XattrNotSupported.errno(), ns_errno::EOPNOTSUPP);
    }

    #[test]
    fn many_xattrs_per_inode() {
        let backend = TestXattrBackend::new();
        for i in 0..256u32 {
            let name_buf = format!("user.attr_{i:03}");
            let val_buf = format!("value_{i:03}");
            dispatch_setxattr(&backend, 1, name_buf.as_bytes(), val_buf.as_bytes(), 0).unwrap();
        }
        let list = dispatch_listxattr(&backend, 1).unwrap();
        let count = list.split(|b| *b == 0).filter(|s| !s.is_empty()).count();
        assert_eq!(count, 256);
    }

    // ── XattrStoreBridge integration tests ──────────────────────────

    #[test]
    fn bridge_set_get_roundtrip() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        let result = dispatch_setxattr(&bridge, 1, b"user.key", b"val", 0);
        assert!(result.is_ok(), "set failed: {:?}", result.err());
        let val = dispatch_getxattr(&bridge, 1, b"user.key").unwrap();
        assert_eq!(val, b"val");
    }

    #[test]
    fn bridge_nonexistent_inode_rejected() {
        let inodes = std::collections::BTreeSet::new();
        let bridge = XattrStoreBridge::new(inodes);
        let err = dispatch_getxattr(&bridge, 1, b"user.key").unwrap_err();
        assert_eq!(err, NsOpError::InodeNotFound);
    }

    #[test]
    fn bridge_create_flag_on_existing_returns_eexist() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.dup", b"first", 0).unwrap();
        let err = dispatch_setxattr(&bridge, 1, b"user.dup", b"second", XATTR_CREATE).unwrap_err();
        assert_eq!(err, NsOpError::XattrExists);
    }

    #[test]
    fn bridge_replace_flag_on_missing_returns_xattr_not_found() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        let err =
            dispatch_setxattr(&bridge, 1, b"user.missing", b"val", XATTR_REPLACE).unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn bridge_list_returns_sorted_names() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.c", b"3", 0).unwrap();
        dispatch_setxattr(&bridge, 1, b"user.a", b"1", 0).unwrap();
        dispatch_setxattr(&bridge, 1, b"user.b", b"2", 0).unwrap();
        let list = dispatch_listxattr(&bridge, 1).unwrap();
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 3);
        // BTreeMap iteration order is sorted by key bytes
        assert_eq!(names[0], b"user.a");
        assert_eq!(names[1], b"user.b");
        assert_eq!(names[2], b"user.c");
    }

    #[test]
    fn bridge_remove_deletes_xattr() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.del", b"val", 0).unwrap();
        dispatch_removexattr(&bridge, 1, b"user.del").unwrap();
        let err = dispatch_getxattr(&bridge, 1, b"user.del").unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn bridge_large_value_roundtrip() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        let big_val = vec![0xABu8; 64 * 1024]; // 64 KiB exact
        dispatch_setxattr(&bridge, 1, b"user.big", &big_val, 0).unwrap();
        let val = dispatch_getxattr(&bridge, 1, b"user.big").unwrap();
        assert_eq!(val, big_val);
    }

    #[test]
    fn bridge_multi_inode_isolation() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        inodes.insert(2);
        inodes.insert(3);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.shared", b"inode1", 0).unwrap();
        dispatch_setxattr(&bridge, 2, b"user.shared", b"inode2", 0).unwrap();
        assert_eq!(
            dispatch_getxattr(&bridge, 1, b"user.shared").unwrap(),
            b"inode1"
        );
        assert_eq!(
            dispatch_getxattr(&bridge, 2, b"user.shared").unwrap(),
            b"inode2"
        );
        assert_eq!(
            dispatch_getxattr(&bridge, 3, b"user.shared").unwrap_err(),
            NsOpError::XattrNotFound
        );
    }

    #[test]
    fn bridge_invalid_name_rejected() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        let err = dispatch_getxattr(&bridge, 1, b"").unwrap_err();
        assert_eq!(err, NsOpError::XattrInvalidName);
    }

    #[test]
    fn bridge_value_too_large() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        let big = vec![0xCCu8; XATTR_VALUE_MAX + 1];
        let err = dispatch_setxattr(&bridge, 1, b"user.big", &big, 0).unwrap_err();
        assert_eq!(err, NsOpError::XattrTooLarge);
    }

    #[test]
    fn bridge_unsupported_namespace() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        // The MemXattrStore::XattrStore impl validates namespace
        let err = dispatch_setxattr(&bridge, 1, b"custom.myattr", b"val", 0).unwrap_err();
        assert_eq!(err, NsOpError::XattrNotSupported);
    }

    #[test]
    fn bridge_256_xattr_stress() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        for i in 0..256u32 {
            let name_buf = format!("user.attr_{i:03}");
            let val_buf = format!("bridge_value_{i:03}");
            dispatch_setxattr(&bridge, 1, name_buf.as_bytes(), val_buf.as_bytes(), 0).unwrap();
        }
        let list = dispatch_listxattr(&bridge, 1).unwrap();
        let count = list.split(|b| *b == 0).filter(|s| !s.is_empty()).count();
        assert_eq!(count, 256);
        assert_eq!(
            dispatch_getxattr(&bridge, 1, b"user.attr_000").unwrap(),
            b"bridge_value_000"
        );
        assert_eq!(
            dispatch_getxattr(&bridge, 1, b"user.attr_255").unwrap(),
            b"bridge_value_255"
        );
    }

    #[test]
    fn bridge_overwrite_preserves_other_xattrs() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.a", b"val_a", 0).unwrap();
        dispatch_setxattr(&bridge, 1, b"user.b", b"val_b", 0).unwrap();
        // Overwrite user.a
        dispatch_setxattr(&bridge, 1, b"user.a", b"new_a", 0).unwrap();
        assert_eq!(dispatch_getxattr(&bridge, 1, b"user.a").unwrap(), b"new_a");
        assert_eq!(dispatch_getxattr(&bridge, 1, b"user.b").unwrap(), b"val_b");
        let list = dispatch_listxattr(&bridge, 1).unwrap();
        let count = list.split(|b| *b == 0).filter(|s| !s.is_empty()).count();
        assert_eq!(count, 2);
    }

    #[test]
    fn bridge_delete_then_recreate() {
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let bridge = XattrStoreBridge::new(inodes);
        dispatch_setxattr(&bridge, 1, b"user.cycle", b"first", 0).unwrap();
        dispatch_removexattr(&bridge, 1, b"user.cycle").unwrap();
        dispatch_setxattr(&bridge, 1, b"user.cycle", b"second", 0).unwrap();
        assert_eq!(
            dispatch_getxattr(&bridge, 1, b"user.cycle").unwrap(),
            b"second"
        );
    }

    // ── SplitXattrStore: large-value persistence through object store ─

    /// Threshold above which xattr values are stored in the object store
    /// rather than inline in the `MemXattrStore`.
    const SPLIT_THRESHOLD: usize = 128;

    /// Magic marker prefix stored inline when a value is split to the
    /// object store.  `[0xFE, 0xED]` followed by 32 bytes of `ObjectKey`.
    const SPLIT_MAGIC: [u8; 2] = [0xFE, 0xED];

    /// A backend that splits xattr storage: small values (`
    /// `SPLIT_THRESHOLD`) are stored inline in a `MemXattrStore`;
    /// large values are written to a `LocalObjectStore` and the
    /// resulting `ObjectKey` is stored inline.
    ///
    /// This is a **test-only prototype** demonstrating the two-tier
    /// persistence design.  Production wiring would use a feature-gated
    /// module with `std::sync::Mutex` or an async lock.
    struct SplitXattrStore {
        small: tidefs_inode_attributes::xattr::MemXattrStore,
        large: std::sync::Mutex<tidefs_local_object_store::store::LocalObjectStore>,
        existing_inodes: std::collections::BTreeSet<u64>,
    }

    impl SplitXattrStore {
        fn new(
            obj_store: tidefs_local_object_store::store::LocalObjectStore,
            inodes: std::collections::BTreeSet<u64>,
        ) -> Self {
            Self {
                small: tidefs_inode_attributes::xattr::MemXattrStore::new(),
                large: std::sync::Mutex::new(obj_store),
                existing_inodes: inodes,
            }
        }

        /// Encode an `ObjectKey` as an inline value with the split magic.
        fn encode_split_ref(key: &tidefs_local_object_store::ObjectKey) -> Vec<u8> {
            let mut buf = Vec::with_capacity(34);
            buf.extend_from_slice(&SPLIT_MAGIC);
            buf.extend_from_slice(key.as_bytes());
            buf
        }

        /// Decode a split reference back into an `ObjectKey`, returning
        /// `None` when the bytes do not start with the magic prefix.
        fn decode_split_ref(data: &[u8]) -> Option<tidefs_local_object_store::ObjectKey> {
            if data.len() == 34 && data[..2] == SPLIT_MAGIC {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&data[2..]);
                Some(tidefs_local_object_store::ObjectKey::from_bytes(key_bytes))
            } else {
                None
            }
        }
    }

    impl XattrBackend for SplitXattrStore {
        fn inode_exists(&self, ino: u64) -> bool {
            self.existing_inodes.contains(&ino)
        }

        fn get_xattr(&self, ino: u64, name: &[u8]) -> Result<Vec<u8>, NsOpError> {
            use tidefs_inode_attributes::xattr::XattrStore;
            let raw = XattrStore::get(&self.small, ino, name).map_err(xattr_err_to_ns)?;
            // If the value is a split reference, resolve from the object store
            if let Some(key) = Self::decode_split_ref(&raw) {
                let store = self.large.lock().unwrap();
                tidefs_local_object_store::ObjectStore::get(&*store, key)
                    .map_err(|_| NsOpError::Io)?
                    .ok_or(NsOpError::XattrNotFound)
            } else {
                Ok(raw)
            }
        }

        fn set_xattr(
            &self,
            ino: u64,
            name: &[u8],
            value: &[u8],
            flags: u32,
        ) -> Result<(), NsOpError> {
            use tidefs_inode_attributes::xattr::XattrStore;
            validate_xattr_name(name)?;
            validate_xattr_value(value)?;
            validate_xattr_flags(flags)?;

            if value.len() < SPLIT_THRESHOLD {
                // Small value: store inline
                XattrStore::set(&self.small, ino, name, value, flags).map_err(xattr_err_to_ns)
            } else {
                // Large value: put into object store, store the key inline
                let key = {
                    let mut store = self.large.lock().unwrap();
                    tidefs_local_object_store::ObjectStore::put(&mut *store, value)
                        .map_err(|_| NsOpError::Io)?
                };
                let ref_bytes = Self::encode_split_ref(&key);
                XattrStore::set(&self.small, ino, name, &ref_bytes, flags).map_err(xattr_err_to_ns)
            }
        }

        fn list_xattr(&self, ino: u64) -> Result<Vec<u8>, NsOpError> {
            use tidefs_inode_attributes::xattr::XattrStore;
            XattrStore::list(&self.small, ino).map_err(xattr_err_to_ns)
        }

        fn remove_xattr(&self, ino: u64, name: &[u8]) -> Result<(), NsOpError> {
            use tidefs_inode_attributes::xattr::XattrStore;
            // Check if the value is a split reference and delete from object store too
            if let Ok(raw) = XattrStore::get(&self.small, ino, name) {
                if let Some(key) = Self::decode_split_ref(&raw) {
                    let mut store = self.large.lock().unwrap();
                    let _ = tidefs_local_object_store::ObjectStore::delete(&mut *store, key);
                }
            }
            XattrStore::remove(&self.small, ino, name).map_err(xattr_err_to_ns)
        }
    }

    // ── SplitXattrStore tests ────────────────────────────────────────

    fn temp_obj_store() -> (
        tempfile::TempDir,
        tidefs_local_object_store::store::LocalObjectStore,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = tidefs_local_object_store::store::LocalObjectStore::open(dir.path())
            .expect("open object store");
        (dir, store)
    }

    #[test]
    fn split_store_small_value_roundtrip() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let small_val = vec![b'a'; 64]; // well under SPLIT_THRESHOLD
        dispatch_setxattr(&backend, 1, b"user.small", &small_val, 0).unwrap();
        let val = dispatch_getxattr(&backend, 1, b"user.small").unwrap();
        assert_eq!(val, small_val);
    }

    #[test]
    fn split_store_large_value_roundtrip() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let large_val = vec![0xBBu8; 1024]; // 1 KiB, well over SPLIT_THRESHOLD
        dispatch_setxattr(&backend, 1, b"user.large", &large_val, 0).unwrap();
        let val = dispatch_getxattr(&backend, 1, b"user.large").unwrap();
        assert_eq!(val, large_val);
    }

    #[test]
    fn split_store_exact_threshold_value_inline() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let exact_threshold = vec![b'T'; SPLIT_THRESHOLD - 1]; // 127 bytes
        dispatch_setxattr(&backend, 1, b"user.thresh", &exact_threshold, 0).unwrap();
        let val = dispatch_getxattr(&backend, 1, b"user.thresh").unwrap();
        assert_eq!(val, exact_threshold);
    }

    #[test]
    fn split_store_large_value_delete_cleans_up() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let large_val = vec![0xDDu8; 300];
        dispatch_setxattr(&backend, 1, b"user.large_del", &large_val, 0).unwrap();
        // Remove it
        dispatch_removexattr(&backend, 1, b"user.large_del").unwrap();
        // Verify it's gone
        let err = dispatch_getxattr(&backend, 1, b"user.large_del").unwrap_err();
        assert_eq!(err, NsOpError::XattrNotFound);
    }

    #[test]
    fn split_store_mixed_small_and_large() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let small = vec![b's'; 50];
        let large = vec![b'L'; 500];

        dispatch_setxattr(&backend, 1, b"user.small", &small, 0).unwrap();
        dispatch_setxattr(&backend, 1, b"user.large", &large, 0).unwrap();

        assert_eq!(
            dispatch_getxattr(&backend, 1, b"user.small").unwrap(),
            small
        );
        assert_eq!(
            dispatch_getxattr(&backend, 1, b"user.large").unwrap(),
            large
        );

        // List should have both
        let list = dispatch_listxattr(&backend, 1).unwrap();
        let count = list.split(|b| *b == 0).filter(|s| !s.is_empty()).count();
        assert_eq!(count, 2);
    }

    #[test]
    fn split_store_overwrite_large_value() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let first = vec![0x11u8; 200];
        let second = vec![0x22u8; 200];

        dispatch_setxattr(&backend, 1, b"user.overwrite", &first, 0).unwrap();
        dispatch_setxattr(&backend, 1, b"user.overwrite", &second, 0).unwrap();

        assert_eq!(
            dispatch_getxattr(&backend, 1, b"user.overwrite").unwrap(),
            second
        );
    }

    #[test]
    fn split_store_max_size_value() {
        let (_dir, obj_store) = temp_obj_store();
        let mut inodes = std::collections::BTreeSet::new();
        inodes.insert(1);
        let backend = SplitXattrStore::new(obj_store, inodes);

        let max_val = vec![0xAAu8; XATTR_VALUE_MAX];
        dispatch_setxattr(&backend, 1, b"user.max", &max_val, 0).unwrap();
        let val = dispatch_getxattr(&backend, 1, b"user.max").unwrap();
        assert_eq!(val, max_val);
    }

    // ── dispatch_mknod tests ──────────────────────────────────────────

    #[test]
    fn dispatch_mknod_creates_regular_file() {
        let mut backend = TestBackend::new();
        let result = dispatch_mknod(&mut backend, mknod_request(1, b"newfile")).unwrap();

        assert_eq!(result.child.kind, NsNodeKind::File);
        assert_eq!(result.child.mode, 0o100644); // 0o100666 & ~0o022
        assert_eq!(result.child.uid, 1000);
        assert_eq!(result.child.gid, 1000);
        assert_eq!(result.child.nlink, 1);
        assert_eq!(result.child.rdev, 0);
        assert_eq!(result.dir_entry.kind, NsNodeKind::File);
        let lookup = backend.lookup(1, b"newfile").unwrap();
        assert_eq!(lookup.ino, result.child.ino);
    }

    #[test]
    fn dispatch_mknod_creates_fifo() {
        let mut backend = TestBackend::new();
        let result = dispatch_mknod(
            &mut backend,
            NsMknodRequest {
                mode: 0o010666,
                ..mknod_request(1, b"myfifo")
            },
        )
        .unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Other(0o010000));
        assert_eq!(result.child.mode, 0o010644);
        assert_eq!(result.child.rdev, 0);
        assert!(backend.lookup(1, b"myfifo").is_some());
    }

    #[test]
    fn dispatch_mknod_creates_block_device_with_rdev() {
        let mut backend = TestBackend::new();
        let rdev = (8 << 8) | 1; // /dev/sda1
        let result = dispatch_mknod(
            &mut backend,
            NsMknodRequest {
                mode: 0o060666,
                uid: 0,
                gid: 0,
                rdev,
                ..mknod_request(1, b"sda1")
            },
        )
        .unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Other(0o060000));
        assert_eq!(result.child.mode, 0o060644);
        assert_eq!(result.child.rdev, rdev);
    }

    #[test]
    fn dispatch_mknod_creates_char_device_with_rdev() {
        let mut backend = TestBackend::new();
        let rdev = (1 << 8) | 3; // /dev/null
        let result = dispatch_mknod(
            &mut backend,
            NsMknodRequest {
                mode: 0o020666,
                uid: 0,
                gid: 0,
                rdev,
                ..mknod_request(1, b"null")
            },
        )
        .unwrap();

        assert_eq!(result.child.kind, NsNodeKind::Other(0o020000));
        assert_eq!(result.child.rdev, rdev);
    }

    #[test]
    fn dispatch_mknod_nonexistent_parent_returns_enoent() {
        let mut backend = TestBackend::new();
        let error = dispatch_mknod(&mut backend, mknod_request(999, b"file")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotFound);
        assert_eq!(error.errno(), ns_errno::ENOENT);
    }

    #[test]
    fn dispatch_mknod_file_parent_returns_enotdir() {
        let mut backend = TestBackend::new();
        let file = handle_create(&mut backend, create_request(1, b"file.txt"))
            .unwrap()
            .child;

        let error = dispatch_mknod(&mut backend, mknod_request(file.ino, b"child")).unwrap_err();

        assert_eq!(error, NsOpError::ParentNotDirectory);
        assert_eq!(error.errno(), ns_errno::ENOTDIR);
    }

    #[test]
    fn dispatch_mknod_existing_name_returns_eexist() {
        let mut backend = TestBackend::new();
        handle_create(&mut backend, create_request(1, b"file.txt")).unwrap();

        let error = dispatch_mknod(&mut backend, mknod_request(1, b"file.txt")).unwrap_err();

        assert_eq!(error, NsOpError::EntryAlreadyExists);
        assert_eq!(error.errno(), ns_errno::EEXIST);
    }

    #[test]
    fn dispatch_mknod_empty_name_returns_einval() {
        let mut backend = TestBackend::new();
        let error = dispatch_mknod(&mut backend, mknod_request(1, b"")).unwrap_err();

        assert_eq!(error, NsOpError::NameInvalid);
        assert_eq!(error.errno(), ns_errno::EINVAL);
    }

    #[test]
    fn dispatch_mknod_umask_strips_bits() {
        let mut backend = TestBackend::new();
        let result = dispatch_mknod(
            &mut backend,
            NsMknodRequest {
                umask: 0o077,
                ..mknod_request(1, b"restricted")
            },
        )
        .unwrap();

        assert_eq!(result.child.mode, 0o100600);
        assert_eq!(result.child.kind, NsNodeKind::File);
    }
}
