// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VfsEngine trait implementation wrapping PoolDatasetOwner.
//!
//! Wraps `PoolDatasetOwner` in a shared mutex to provide interior mutability,
//! matching the VfsEngine `&self` contract while allowing other front ends to
//! take the same Pool owner for bounded operations. Most namespace operations map to
//! existing PoolDatasetOwner path-based methods using a lazy inode-to-path
//! resolution layer; hot inode-native operations such as xattrs avoid that
//! path reconstruction.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use serde_json::{json, Value};
use tidefs_local_object_store::{DeviceIoClass, IntegrityDigest64, ObjectKey, StoreError};
use tidefs_types_extent_map_core::ExtentMapOps;
use tidefs_types_reclaim_queue_core::{
    ObjectKey as ReclaimObjectKey, QueueFamily as ReclaimQueueFamily, ReclaimQueueEntry,
};
use tidefs_types_vfs_core::{
    DirEntry, DirHandleId, EngineDirHandle, EngineFileHandle, Errno, Generation, InodeAttr,
    InodeId, LockSpec, NodeKind, RequestCtx, SetAttr, StatFs, FALLOC_FL_COLLAPSE_RANGE,
    FALLOC_FL_INSERT_RANGE, FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_ZERO_RANGE,
    FATTR_ATIME, FATTR_ATIME_NOW, FATTR_CTIME, FATTR_FH, FATTR_GID, FATTR_LOCKOWNER, FATTR_MODE,
    FATTR_MTIME, FATTR_MTIME_NOW, FATTR_SIZE, FATTR_UID, ROOT_INODE_ID, S_IFBLK, S_IFCHR, S_IFDIR,
    S_IFIFO, S_IFMT, S_IFREG, S_IFSOCK,
};
use tidefs_types_vfs_core::{LockRange, LockType};
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminError,
    LivePoolAdminRequest, LivePoolAdminResponse, LseekDataRange, VfsEngine, VfsEngineStatFs,
};
#[cfg(test)]
use tidefs_vfs_engine::{LivePoolAdminOutput, LivePoolAdminResponseBody};

use crate::content::{reflink_chunked_content, FilesystemContentWriteStore};
use crate::encoding::{encode_content_manifest, encode_content_manifest_sparse};
use crate::error::FileSystemError;
use crate::fuse_getattr;
use crate::fuse_setattr;
use crate::fuse_statfs;
use crate::helpers::{kind_bits, validate_name};
use crate::open_dispatch::{self, FileHandleState, FileHandleTable};
use crate::records::RootCommitRecord;
use crate::release_dispatch;
#[cfg(feature = "replication-io")]
use crate::types::CommittedRootSummary;
use crate::types::CONTENT_MANIFEST_SPARSE_MAGIC;
use crate::types::{
    InodeRecord, IntentLogReplyState, NamespaceEntry, OnlineVerifierIssue, OnlineVerifierIssueKind,
    OnlineVerifierIssueSeverity, OnlineVerifierOutcome, OnlineVerifierReport,
};
use crate::xattr_dispatch;
use tidefs_inode_attributes::timestamp::{TimestampPolicy, TimestampUpdate};
use tidefs_posix_semantics::apply_setgid_inheritance_for_create;
use tidefs_posix_semantics::sticky_dir_allows_unlink_or_rename;

use crate::namespace::rename::RenameAt2Flags;
use tidefs_dataset_lifecycle::{
    DatasetCatalog, DatasetFlags, DatasetId, DatasetType, SyncGuarantee,
};
use tidefs_dataset_properties::{PropertySet, PropertyType, PropertyValue};
#[cfg(feature = "encryption")]
use tidefs_encryption::key_hierarchy::{DatasetDEK, PoolWrappingKey, SALT_LEN};
#[cfg(feature = "encryption")]
use tidefs_encryption::key_manager::{BorrowedKeyStore, KeyManager, KeyRotation};
use tidefs_types_dataset_feature_flags_core::{get_feature_class, FeatureClass, FeatureName};

use crate::{CopyFileRangeIntent, FileSystemState, PoolDatasetOwner, SharedPoolDatasetOwner};

#[cfg(test)]
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_ACCMODE: u32 = 0o3;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const COPY_FILE_RANGE_DIRECT_FALLBACK_BATCH_BYTES: usize = 4 * 1024 * 1024;

fn open_flags_allow_read(flags: u32) -> bool {
    flags & O_ACCMODE != O_WRONLY
}

fn open_flags_allow_write(flags: u32) -> bool {
    matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
}

fn vfs_op_diagnostics_enabled() -> bool {
    fn enabled_var(name: &str) -> bool {
        matches!(
            std::env::var(name).as_deref(),
            Ok("1") | Ok("true") | Ok("yes")
        )
    }

    enabled_var("TIDEFS_VFS_OP_DIAGNOSTICS") || enabled_var("TIDEFS_FUSE_OP_DIAGNOSTICS")
}

// ── Path helpers ─────────────────────────────────────────────────────────

fn bytes_to_str(bytes: &[u8]) -> std::result::Result<&str, Errno> {
    std::str::from_utf8(bytes).map_err(|_| Errno::EINVAL)
}

fn child_name_to_str(bytes: &[u8]) -> std::result::Result<&str, Errno> {
    let name_str = bytes_to_str(bytes)?;
    validate_name(bytes).map_err(|err| match err {
        FileSystemError::InvalidName { reason, .. } if reason.contains("too long") => {
            Errno::ENAMETOOLONG
        }
        FileSystemError::InvalidName { .. } => Errno::EINVAL,
        _ => Errno::EINVAL,
    })?;
    Ok(name_str)
}

fn build_child_path(parent_path: &str, name: &[u8]) -> std::result::Result<String, Errno> {
    let name_str = child_name_to_str(name)?;
    if parent_path == "/" {
        Ok(format!("/{name_str}"))
    } else {
        Ok(format!("{parent_path}/{name_str}"))
    }
}

/// Map a PoolDatasetOwner error to the canonical VFS Errno.
fn map_errno(err: &FileSystemError) -> Errno {
    match err {
        FileSystemError::NotFound { .. } => Errno::ENOENT,
        FileSystemError::AlreadyExists { .. } => Errno::EEXIST,
        FileSystemError::NotDirectory { .. } => Errno::ENOTDIR,
        FileSystemError::AclValidationFailed { .. } => Errno::EINVAL,
        FileSystemError::IsDirectory { .. } => Errno::EISDIR,
        FileSystemError::DirectoryNotEmpty { .. } => Errno::ENOTEMPTY,
        FileSystemError::NoSpace { .. } => Errno::ENOSPC,
        FileSystemError::NotFile { .. } => Errno::EINVAL,
        FileSystemError::QuotaExceeded { .. } => Errno::ENOSPC,
        FileSystemError::InvalidName { .. } => Errno::ENAMETOOLONG,
        FileSystemError::InvalidPath { .. } => Errno::EINVAL,
        FileSystemError::CorruptState { .. } => Errno::EIO,
        FileSystemError::CorruptContent { .. } => Errno::EIO,
        FileSystemError::Unsupported { .. } => Errno::EOPNOTSUPP,
        FileSystemError::SizeOverflow { .. } => Errno::EFBIG,
        #[cfg(feature = "policy-observation")]
        FileSystemError::ReadServingRefused { .. } => Errno::EIO,
        FileSystemError::Store(StoreError::NoSpace) => Errno::ENOSPC,
        _ => Errno::EIO,
    }
}

// ── VfsLocalFileSystem ────────────────────────────────────────────────────

/// VfsEngine adapter wrapping `PoolDatasetOwner` with interior mutability.
///
/// Maintains a lazy inode→path cache that bridges the VfsEngine inode
/// space to PoolDatasetOwner path space.  The cache is populated by a
/// single tree walk from root on first miss and invalidated as needed.
pub struct VfsLocalFileSystem {
    fs: SharedPoolDatasetOwner,
    read_only: bool,
    path_cache: RefCell<BTreeMap<InodeId, String>>,
    file_handle_table: RefCell<FileHandleTable>,
    active_dir_handles: RefCell<BTreeMap<DirHandleId, InodeId>>,
    next_dir_handle_id: RefCell<u64>,
    /// When set, all path resolution is scoped to this filesystem directory,
    /// typically the backing directory of a non-root dataset.  The root inode
    /// (ROOT_INODE_ID) maps to this path instead of "/".
    dataset_root_path: Option<String>,
    /// Mount-level atime policy (relatime, noatime, strictatime).
    timestamp_policy: TimestampPolicy,
    /// Per-dataset write-acknowledgment durability guarantee.
    sync_guarantee: SyncGuarantee,
}

// ActiveFileHandle replaced by FileHandleState from open_dispatch

impl VfsLocalFileSystem {
    const POSIX_ACL_ACCESS_XATTR: &[u8] = b"system.posix_acl_access";
    const POSIX_ACL_DEFAULT_XATTR: &[u8] = b"system.posix_acl_default";

    /// Wrap an open `PoolDatasetOwner` into a VfsEngine adapter.
    pub fn new(fs: PoolDatasetOwner) -> Self {
        let mut path_cache = BTreeMap::new();
        path_cache.insert(ROOT_INODE_ID, "/".to_string());
        Self {
            fs: SharedPoolDatasetOwner::new(fs),
            read_only: false,
            path_cache: RefCell::new(path_cache),
            file_handle_table: RefCell::new(FileHandleTable::new()),
            active_dir_handles: RefCell::new(BTreeMap::new()),
            next_dir_handle_id: RefCell::new(1),
            dataset_root_path: None,
            timestamp_policy: TimestampPolicy::Relatime,
            sync_guarantee: SyncGuarantee::Local,
        }
    }

    /// Scope all path resolution to a dataset directory within the pool.
    ///
    /// When set, `ROOT_INODE_ID` maps to `root_path` instead of `"/"`,
    /// so the FUSE mount root exposes only that dataset's contents.
    /// `root_path` must be an absolute path relative to the pool root.
    pub fn with_dataset_root(mut self, root_path: &str) -> Self {
        let root = root_path.to_string();
        self.path_cache.borrow_mut().clear();
        self.path_cache
            .borrow_mut()
            .insert(ROOT_INODE_ID, root.clone());
        self.dataset_root_path = Some(root);
        self
    }

    /// Set the per-dataset write-acknowledgment durability guarantee.
    ///
    /// Controls when write/flush/fsync operations acknowledge completion.
    /// Default: [`SyncGuarantee::Local`].
    pub fn with_sync_guarantee(mut self, guarantee: SyncGuarantee) -> Self {
        self.sync_guarantee = guarantee;
        self
    }

    /// Force the VFS adapter to reject namespace and data mutations.
    pub fn with_read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[inline]
    fn ensure_writable(&self) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("mutate mounted filesystem through VFS")?;
        if self.read_only {
            return Err(Errno::EROFS);
        }
        self.fs
            .borrow()
            .check_write_admission(0)
            .map_err(|error| map_errno(&FileSystemError::from(error)))
    }

    #[inline]
    fn automatic_read_timestamp_admitted(&self) -> bool {
        !self.read_only && self.ensure_writable().is_ok()
    }

    #[inline]
    fn ensure_mounted_mutation_allowed(
        &self,
        operation: &'static str,
    ) -> std::result::Result<(), Errno> {
        self.fs
            .borrow()
            .ensure_mutation_allowed(operation)
            .map_err(|e| map_errno(&e))
    }

    /// Return the effective root path for path resolution.
    ///
    /// When [`dataset_root_path`] is set, it is the dataset directory.
    /// Otherwise it is `"/"` (the pool root).
    fn root_path(&self) -> String {
        self.dataset_root_path
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "/".to_string())
    }

    fn reset_path_cache(&self) {
        let mut cache = self.path_cache.borrow_mut();
        cache.clear();
        cache.insert(ROOT_INODE_ID, self.root_path());
    }

    /// Consume the adapter and return the inner `PoolDatasetOwner`.
    pub fn into_inner(self) -> PoolDatasetOwner {
        self.fs.into_inner()
    }

    /// Share the one mounted Pool/filesystem owner with another in-process
    /// front end. Callers must hold the mutex only for one bounded operation.
    #[must_use]
    pub fn shared_pool_owner(&self) -> SharedPoolDatasetOwner {
        self.fs.clone()
    }

    /// Set the mount-level atime policy for automatic timestamp updates.
    ///
    /// Defaults to [`TimestampPolicy::Relatime`].
    pub fn set_timestamp_policy(&mut self, policy: TimestampPolicy) -> crate::Result<()> {
        self.fs
            .borrow()
            .ensure_mutation_allowed("set mounted VFS timestamp policy")?;
        self.timestamp_policy = policy;
        Ok(())
    }

    /// Access the file-handle table for inspection or direct validation.
    ///
    /// The adapter layer typically validates handles through the engine's
    /// IO methods (read, write, etc.), which query this table internally.
    /// This accessor is only needed when callers must inspect handle state
    /// without performing IO.
    pub fn file_handle_table(&self) -> &RefCell<FileHandleTable> {
        &self.file_handle_table
    }

    /// Direct inode-ID-based attribute lookup (bypasses path resolution).
    ///
    /// Calls `engine_getattr` on the inner
    /// [`PoolDatasetOwner`], resolving the inode through the ARC cache
    /// and inode table without converting to a path first.
    ///
    /// This is the preferred entry point for FUSE GETATTR dispatch when
    /// the caller already has an inode number.
    pub fn getattr_by_ino(&self, ino: u64) -> std::result::Result<InodeAttr, Errno> {
        fuse_getattr::engine_getattr(&self.fs.borrow(), ino).map_err(|e| e.to_errno())
    }

    /// Direct inode-ID-based attribute mutation (bypasses path resolution).
    ///
    /// Calls `engine_setattr` on the inner
    /// [`PoolDatasetOwner`], applying the metadata-only fields of `set`
    /// (mode, uid, gid, timestamps) through the mutation machinery.
    ///
    /// `FATTR_SIZE` is not handled here; the caller is responsible for
    /// file-content manipulation before invoking this method.
    ///
    /// This is the preferred entry point for FUSE SETATTR metadata dispatch.
    pub fn setattr_by_ino(&self, ino: u64, set: &SetAttr) -> std::result::Result<InodeAttr, Errno> {
        fuse_setattr::engine_setattr(&mut self.fs.borrow_mut(), ino, set).map_err(|e| e.to_errno())
    }

    fn allocate_dir_handle_id(&self) -> std::result::Result<DirHandleId, Errno> {
        let mut next = self.next_dir_handle_id.borrow_mut();
        let id = *next;
        if id == 0 {
            return Err(Errno::EIO);
        }
        *next = next.checked_add(1).unwrap_or(0);
        Ok(DirHandleId::new(id))
    }

    // allocate_file_handle_id replaced by FileHandleTable::register()

    fn register_file_handle(
        &self,
        inode: InodeId,
        open_flags: u32,
        enforce_access_mode: bool,
    ) -> std::result::Result<EngineFileHandle, Errno> {
        self.file_handle_table
            .borrow_mut()
            .register(inode, open_flags, enforce_access_mode)
            .map_err(|e| e.to_errno())
    }

    fn validate_file_handle(
        &self,
        fh: &EngineFileHandle,
    ) -> std::result::Result<FileHandleState, Errno> {
        self.file_handle_table
            .borrow()
            .validate(fh)
            .map_err(|e| e.to_errno())
    }

    fn validate_optional_file_handle(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
    ) -> std::result::Result<(), Errno> {
        if let Some(fh) = handle {
            let live = self.validate_file_handle(fh)?;
            if live.inode_id != inode {
                return Err(Errno::EBADF);
            }
        }
        Ok(())
    }

    fn validate_dir_handle(&self, dh: &EngineDirHandle) -> std::result::Result<(), Errno> {
        if self
            .active_dir_handles
            .borrow()
            .get(&dh.dh_id)
            .is_some_and(|inode| *inode == dh.inode_id)
        {
            Ok(())
        } else {
            Err(Errno::EBADF)
        }
    }

    /// Walk the entire directory tree from root, populating the path cache.
    /// Called once on first cache miss.
    fn rebuild_path_cache(&self) {
        let mut cache = self.path_cache.borrow_mut();
        let fs = self.fs.borrow();

        // BFS from root.
        let mut queue: Vec<(InodeId, String)> = Vec::new();
        let root_path = self.root_path();
        queue.push((ROOT_INODE_ID, root_path.clone()));

        // When a dataset root is configured, also register the real pool
        // inode for the root directory so inode-based operations
        // (list_dir_by_inode) can resolve it back to the dataset path.
        if self.dataset_root_path.is_some() {
            if let Ok(record) = fs.stat(&root_path) {
                cache.insert(record.inode_id, root_path);
            }
        }

        while let Some((_dir_id, dir_path)) = queue.pop() {
            let entries = match fs.list_dir(&dir_path) {
                Ok(v) => v,
                Err(_) => continue,
            };
            for entry in entries {
                let child_path = if dir_path == "/" {
                    if let Ok(s) = std::str::from_utf8(&entry.name) {
                        format!("/{s}")
                    } else {
                        continue;
                    }
                } else if let Ok(s) = std::str::from_utf8(&entry.name) {
                    format!("{dir_path}/{s}")
                } else {
                    continue;
                };
                cache.insert(entry.inode_id, child_path.clone());
                if entry.kind() == NodeKind::Dir {
                    queue.push((entry.inode_id, child_path));
                }
            }
        }
    }

    /// Resolve an `InodeId` to its absolute path.
    fn inode_path(&self, inode_id: InodeId) -> std::result::Result<String, Errno> {
        // Fast path: root.
        if inode_id == ROOT_INODE_ID {
            return Ok(self.root_path());
        }

        // Check cache.
        {
            let cache = self.path_cache.borrow();
            if let Some(path) = cache.get(&inode_id) {
                return Ok(path.clone());
            }
        }

        // Cache miss — rebuild from root and check again.
        self.rebuild_path_cache();

        let cache = self.path_cache.borrow();
        cache.get(&inode_id).cloned().ok_or(Errno::ENOENT)
    }

    fn parent_and_child_records(
        &self,
        parent: InodeId,
        parent_path: &str,
        name: &[u8],
    ) -> std::result::Result<(InodeRecord, InodeRecord), Errno> {
        let fs = self.fs.borrow();
        let parent_record = self.parent_record_for_path(&fs, parent, parent_path)?;
        if !parent_record.is_directory() {
            return Err(Errno::ENOTDIR);
        }
        let child = fs
            .dir_entry_by_inode(parent_record.inode_id, name, parent_path)
            .map_err(|e| map_errno(&e))?
            .ok_or(Errno::ENOENT)?;
        let child_record = fs.inode(child.inode_id).map_err(|e| map_errno(&e))?;
        Ok((parent_record, child_record))
    }

    fn parent_record_for_path(
        &self,
        fs: &PoolDatasetOwner,
        parent: InodeId,
        parent_path: &str,
    ) -> std::result::Result<InodeRecord, Errno> {
        if parent == ROOT_INODE_ID && self.dataset_root_path.is_some() {
            fs.stat(parent_path).map_err(|e| map_errno(&e))
        } else {
            fs.inode(parent).map_err(|e| map_errno(&e))
        }
    }

    fn path_is_at_or_under(path: &str, prefix: &str) -> bool {
        if path == prefix {
            return true;
        }
        path.strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
    }

    fn rewrite_path_prefix(path: &str, old_prefix: &str, new_prefix: &str) -> Option<String> {
        if path == old_prefix {
            return Some(new_prefix.to_string());
        }
        let suffix = path.strip_prefix(old_prefix)?;
        if suffix.starts_with('/') {
            Some(format!("{new_prefix}{suffix}"))
        } else {
            None
        }
    }

    fn invalidate_cached_path_subtree(&self, root_path: &str) {
        self.path_cache
            .borrow_mut()
            .retain(|_, path| !Self::path_is_at_or_under(path, root_path));
    }

    fn remove_cached_path_if_matches(&self, inode_id: InodeId, removed_path: &str) {
        let mut cache = self.path_cache.borrow_mut();
        if cache
            .get(&inode_id)
            .is_some_and(|path| Self::path_is_at_or_under(path, removed_path))
        {
            cache.remove(&inode_id);
        }
    }

    fn rewrite_cached_path_subtree(&self, old_path: &str, new_path: &str) {
        for path in self.path_cache.borrow_mut().values_mut() {
            if let Some(updated) = Self::rewrite_path_prefix(path, old_path, new_path) {
                *path = updated;
            }
        }
    }

    fn move_cached_path(&self, inode_id: InodeId, kind: NodeKind, old_path: &str, new_path: &str) {
        if kind.has_child_namespace() {
            self.rewrite_cached_path_subtree(old_path, new_path);
        }
        self.path_cache
            .borrow_mut()
            .insert(inode_id, new_path.to_string());
    }

    fn exchange_cached_path_subtrees(&self, old_path: &str, new_path: &str) {
        let updates: Vec<_> = self
            .path_cache
            .borrow()
            .iter()
            .filter_map(|(inode_id, path)| {
                Self::rewrite_path_prefix(path, old_path, new_path)
                    .or_else(|| Self::rewrite_path_prefix(path, new_path, old_path))
                    .map(|path| (*inode_id, path))
            })
            .collect();
        let mut cache = self.path_cache.borrow_mut();
        for (inode_id, path) in updates {
            cache.insert(inode_id, path);
        }
    }

    fn exchange_cached_paths(
        &self,
        old_record: &InodeAttr,
        old_path: &str,
        target_record: &InodeAttr,
        new_path: &str,
    ) {
        let old_is_directory = old_record.kind.has_child_namespace();
        let target_is_directory = target_record.kind.has_child_namespace();
        if old_is_directory || target_is_directory {
            self.exchange_cached_path_subtrees(old_path, new_path);
        }
        let mut cache = self.path_cache.borrow_mut();
        cache.insert(old_record.inode_id, new_path.to_string());
        cache.insert(target_record.inode_id, old_path.to_string());
    }

    #[allow(dead_code)] // INTENT: VFS engine helpers for planned FUSE operation dispatch
    /// Validate an xattr name against Linux namespace and size rules.
    fn validate_xattr_name(name: &[u8]) -> std::result::Result<(), Errno> {
        const XATTR_NAME_MAX: usize = 255;

        if name.is_empty() || name.contains(&0) {
            return Err(Errno::EINVAL);
        }
        if name.len() > XATTR_NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if (name.starts_with(b"user.") && name.len() > b"user.".len())
            || (name.starts_with(b"system.") && name.len() > b"system.".len())
            || (name.starts_with(b"security.") && name.len() > b"security.".len())
            || (name.starts_with(b"trusted.") && name.len() > b"trusted.".len())
        {
            return Ok(());
        }

        Err(Errno::EOPNOTSUPP)
    }

    fn validate_posix_acl_xattr_value(name: &[u8], value: &[u8]) -> std::result::Result<(), Errno> {
        if name != Self::POSIX_ACL_ACCESS_XATTR && name != Self::POSIX_ACL_DEFAULT_XATTR {
            return Ok(());
        }

        let acl = tidefs_posix_acl::decode_posix_acl_xattr(value).map_err(|_| Errno::EINVAL)?;
        if name == Self::POSIX_ACL_DEFAULT_XATTR && acl.is_empty() {
            return Ok(());
        }
        tidefs_posix_acl::validate_posix_acl_access_structure(&acl).map_err(|_| Errno::EINVAL)
    }

    fn parent_default_acl_entries(record: &InodeRecord) -> Option<tidefs_posix_acl::PosixAcl> {
        record
            .xattrs
            .get(Self::POSIX_ACL_DEFAULT_XATTR)
            .and_then(|raw| tidefs_posix_acl::decode_posix_acl_xattr(raw).ok())
    }

    fn creation_permissions_for_parent(
        parent_default_acl_entries: Option<&tidefs_posix_acl::PosixAcl>,
        mode: u32,
        umask: u32,
    ) -> u32 {
        let requested = mode & 0o7777;
        if parent_default_acl_entries.is_some() {
            requested
        } else {
            requested & !umask
        }
    }

    fn metadata_setattr_is_noop(attr: &SetAttr, size_changed: bool) -> bool {
        const METADATA_SETATTR_BITS: u32 = FATTR_MODE
            | FATTR_UID
            | FATTR_GID
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_CTIME
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW;
        attr.valid & METADATA_SETATTR_BITS == 0 && !size_changed
    }

    fn apply_metadata_setattr_to_inode(
        fs: &mut PoolDatasetOwner,
        inode_id: InodeId,
        attr: &SetAttr,
        size_changed: bool,
    ) -> std::result::Result<(), Errno> {
        if Self::metadata_setattr_is_noop(attr, size_changed) {
            return Ok(());
        }

        // Metadata-only setattr must mutate the live inode so it cannot
        // restore the Pool predecessor's stale size or data version while a
        // buffered write is pending. Content persistence still belongs to the
        // write-buffer flush.
        let record = fs.inode(inode_id).map_err(|e| map_errno(&e))?;
        let mut updated = record.clone();

        let now_ns = crate::types::current_posix_time_ns();
        let mut changed = false;
        let mut should_bump_ctime = size_changed;

        if attr.valid & FATTR_MODE != 0 {
            let mode = (updated.mode & S_IFMT) | (attr.mode & !S_IFMT);
            if updated.mode != mode {
                updated.mode = mode;
                if let Some(raw_acl) = updated.xattrs.get(b"system.posix_acl_access" as &[u8]) {
                    if let Ok(decoded) = tidefs_posix_acl::decode_posix_acl_xattr(raw_acl) {
                        if let Ok(sync_plan) =
                            tidefs_posix_acl::plan_posix_acl_mode_sync(&decoded, mode)
                        {
                            updated.xattrs.insert(
                                b"system.posix_acl_access".to_vec(),
                                tidefs_posix_acl::encode_posix_acl_xattr(&sync_plan.updated_acl),
                            );
                        }
                    }
                }
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_UID != 0 {
            if updated.uid != attr.uid {
                updated.uid = attr.uid;
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_GID != 0 {
            if updated.gid != attr.gid {
                updated.gid = attr.gid;
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_ATIME != 0 {
            if updated.posix_time.atime_ns != attr.atime_ns {
                updated.posix_time.atime_ns = attr.atime_ns;
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_CTIME != 0 {
            if updated.posix_time.ctime_ns != attr.ctime_ns {
                updated.posix_time.ctime_ns = attr.ctime_ns;
                changed = true;
            }
        }
        if attr.valid & FATTR_ATIME_NOW != 0 {
            if updated.posix_time.atime_ns != now_ns {
                updated.posix_time.atime_ns = now_ns;
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_MTIME != 0 {
            if updated.posix_time.mtime_ns != attr.mtime_ns {
                updated.posix_time.mtime_ns = attr.mtime_ns;
                changed = true;
                should_bump_ctime = true;
            }
        }
        if attr.valid & FATTR_MTIME_NOW != 0 {
            if updated.posix_time.mtime_ns != now_ns {
                updated.posix_time.mtime_ns = now_ns;
                changed = true;
                should_bump_ctime = true;
            }
        }
        // Advance ctime via a fresh tick when any metadata field changed
        // but the caller did not supply an explicit ctime value. This
        // preserves the explicit-value path for atime while still
        // ensuring ctime advances per POSIX semantics.
        if should_bump_ctime && attr.valid & FATTR_CTIME == 0 {
            let next_ctime = now_ns.max(updated.posix_time.ctime_ns.saturating_add(1));
            if updated.posix_time.ctime_ns != next_ctime {
                updated.posix_time.ctime_ns = next_ctime;
                changed = true;
            }
        }

        if !changed {
            return Ok(());
        }

        fs.begin_mutation("set VFS inode attributes")
            .map_err(|e| map_errno(&e))?;
        let tick = fs.bump_generation();
        updated.metadata_version = updated.metadata_version.max(tick);
        updated.subtree_rev = updated.subtree_rev.saturating_add(1).max(1);

        let intent_state = match fs.metadata_setattr_group_commit_intent(&updated) {
            Ok(state) => state,
            Err(err) => {
                fs.rollback_mutation_delta();
                return Err(map_errno(&err));
            }
        };

        fs.mark_inode_metadata_dirty(inode_id);
        Arc::make_mut(&mut fs.state.inodes).insert(inode_id, updated);
        fs.inode_cache.borrow_mut().invalidate(inode_id);
        let committed = if intent_state == IntentLogReplyState::Refused {
            fs.force_commit(())
        } else {
            fs.commit_mutation(())
        };
        committed.map_err(|e| map_errno(&e))
    }

    fn create_metadata_only_node(
        &self,
        parent: InodeId,
        name: &[u8],
        kind: NodeKind,
        mode: u32,
        rdev: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;

        let parent_record = self
            .fs
            .borrow()
            .stat(&parent_path)
            .map_err(|e| map_errno(&e))?;
        let parent_default_acl_entries = Self::parent_default_acl_entries(&parent_record);
        let permissions = Self::creation_permissions_for_parent(
            parent_default_acl_entries.as_ref(),
            mode,
            ctx.umask,
        );
        let initial_mode = kind_bits(kind) | permissions;
        let (effective_mode, effective_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            initial_mode,
            ctx.gid,
        );

        let parent_id = parent_record.inode_id;
        let name = name.to_vec();
        let mut fs = self.fs.borrow_mut();
        if fs
            .dir_entry_by_inode(parent_id, &name, &parent_path)
            .map_err(|e| map_errno(&e))?
            .is_some()
        {
            return Err(Errno::EEXIST);
        }
        fs.ensure_inode_capacity_for_new_inode()
            .map_err(|e| map_errno(&e))?;

        fs.begin_mutation("create VFS metadata node")
            .map_err(|e| map_errno(&e))?;
        if !fs.state.inodes.contains_key(&parent_id) {
            fs.rollback_mutation_delta();
            return Err(Errno::ENOENT);
        }
        if !fs.state.directories.contains_key(&parent_id) {
            let err = FileSystemError::CorruptState {
                reason: "parent directory object is missing",
            };
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        let tick = fs.bump_generation();
        let inode_id = fs.allocate_inode_id();
        let generation = Generation::new(tick);
        let mut new_mode = effective_mode;
        let mut xattrs = BTreeMap::new();
        if let Some(ref acl_entries) = parent_default_acl_entries {
            for (name, value) in
                tidefs_posix_acl::default_acl_inheritance_for_parent(acl_entries, new_mode, false)
            {
                if name == Self::POSIX_ACL_ACCESS_XATTR {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        new_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, new_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }
        let record = InodeRecord {
            dir_storage_kind: 0,
            inode_id,
            generation,
            facets: kind.to_facets(),
            mode: new_mode,
            uid: ctx.uid,
            gid: effective_gid,
            nlink: 1,
            size: 0,
            data_version: tick,
            metadata_version: tick,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs,
            dir_rev: 0,
            subtree_rev: 0,
            rdev,
        };
        let entry = NamespaceEntry {
            name: name.clone(),
            inode_id,
            generation,
            facets: kind.to_facets(),
            mode: new_mode,
        };

        let _ = fs.intent_log_buffer.as_ref().map(|buf| {
            let record = match kind {
                NodeKind::File => tidefs_intent_log::IntentLogRecord::Create {
                    parent: parent_id.get(),
                    name: name.clone(),
                    mode: new_mode,
                    ino: inode_id.get(),
                },
                NodeKind::Fifo | NodeKind::CharDev | NodeKind::BlockDev | NodeKind::Socket => {
                    tidefs_intent_log::IntentLogRecord::Mknod {
                        parent: parent_id.get(),
                        name: name.clone(),
                        mode: new_mode,
                        rdev: u64::from(record.rdev),
                        ino: inode_id.get(),
                    }
                }
                NodeKind::Dir | NodeKind::Symlink | NodeKind::Whiteout => unreachable!(),
            };
            let _frame = buf.append(record, 0);
        });
        let create_intent_state =
            match fs.namespace_create_group_commit_intent(parent_id, entry.clone(), &record) {
                Ok(state) => state,
                Err(err) => {
                    fs.rollback_mutation_delta();
                    return Err(map_errno(&err));
                }
            };

        fs.mark_inode_metadata_dirty(inode_id);
        fs.mark_dir_dirty(parent_id);
        fs.mark_inode_metadata_dirty(parent_id);
        Arc::make_mut(&mut fs.state.inodes).insert(inode_id, record.clone());
        fs.inode_cache.borrow_mut().invalidate(inode_id);
        if let Err(err) = fs.insert_directory_entry(parent_id, name, entry, tick) {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        fs.update_parent_metadata_timestamps(parent_id, tick);

        let committed = if create_intent_state == IntentLogReplyState::Refused {
            fs.force_commit(record)
        } else {
            fs.commit_mutation(record)
        };

        committed
            .map(|record| record.to_inode_attr())
            .map_err(|e| map_errno(&e))
            .inspect(|attr| {
                self.path_cache
                    .borrow_mut()
                    .insert(attr.inode_id, child_path.clone());
            })
    }

    fn create_empty_directory(
        &self,
        parent_id: InodeId,
        parent_path: &str,
        child_path: &str,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        parent_default_acl_entries: Option<&tidefs_posix_acl::PosixAcl>,
    ) -> std::result::Result<InodeRecord, Errno> {
        let mut fs = self.fs.borrow_mut();
        if fs
            .dir_entry_by_inode(parent_id, name, parent_path)
            .map_err(|e| map_errno(&e))?
            .is_some()
        {
            return Err(Errno::EEXIST);
        }
        fs.ensure_inode_capacity_for_new_inode()
            .map_err(|e| map_errno(&e))?;

        fs.begin_mutation("create VFS directory")
            .map_err(|e| map_errno(&e))?;
        if !fs.state.inodes.contains_key(&parent_id) {
            fs.rollback_mutation_delta();
            return Err(Errno::ENOENT);
        }
        match fs.dir_entry_by_inode(parent_id, name, parent_path) {
            Ok(Some(_)) => {
                fs.rollback_mutation_delta();
                return Err(Errno::EEXIST);
            }
            Ok(None) => {}
            Err(err) => {
                fs.rollback_mutation_delta();
                return Err(map_errno(&err));
            }
        }

        let tick = fs.bump_generation();
        let inode_id = fs.allocate_inode_id();
        let generation = Generation::new(tick);
        let mut new_mode = mode;
        let mut xattrs = BTreeMap::new();
        if let Some(acl_entries) = parent_default_acl_entries {
            for (name, value) in
                tidefs_posix_acl::default_acl_inheritance_for_parent(acl_entries, new_mode, true)
            {
                if name == Self::POSIX_ACL_ACCESS_XATTR {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        new_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, new_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }

        let record = InodeRecord {
            rdev: 0,
            inode_id,
            generation,
            facets: NodeKind::Dir.to_facets(),
            mode: new_mode,
            uid,
            gid,
            nlink: 2,
            size: 0,
            data_version: tick,
            metadata_version: tick,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs,
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };

        let name_vec = name.to_vec();
        let _ = fs.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Mkdir {
                    parent: parent_id.get(),
                    name: name_vec.clone(),
                    mode: new_mode,
                    ino: inode_id.get(),
                },
                0,
            );
        });
        let entry = NamespaceEntry {
            name: name_vec.clone(),
            inode_id,
            generation,
            facets: NodeKind::Dir.to_facets(),
            mode: new_mode,
        };

        fs.mark_inode_metadata_dirty(inode_id);
        fs.mark_dir_dirty(parent_id);
        fs.mark_inode_metadata_dirty(parent_id);
        Arc::make_mut(&mut fs.state.inodes).insert(inode_id, record.clone());
        fs.inode_cache.borrow_mut().invalidate(inode_id);
        Arc::make_mut(&mut fs.state.directories).insert(inode_id, BTreeMap::new());
        if let Err(err) = fs.insert_directory_entry(parent_id, name_vec, entry, tick) {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        fs.update_parent_metadata_for_subdir_add(parent_id, tick);

        let record = fs.commit_mutation(record).map_err(|e| map_errno(&e))?;
        self.path_cache
            .borrow_mut()
            .insert(record.inode_id, child_path.to_string());
        Ok(record)
    }

    fn create_empty_regular_file(
        &self,
        parent_id: InodeId,
        parent_path: &str,
        child_path: &str,
        name: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
        parent_default_acl_entries: Option<&tidefs_posix_acl::PosixAcl>,
    ) -> std::result::Result<InodeRecord, Errno> {
        let mut fs = self.fs.borrow_mut();
        if fs
            .dir_entry_by_inode(parent_id, name, parent_path)
            .map_err(|e| map_errno(&e))?
            .is_some()
        {
            return Err(Errno::EEXIST);
        }

        let inode_ancestors = fs.quota_ancestors_for_parent(parent_id);
        let delta_bytes = crate::quota::allocation_grains_for_len(0);
        let pool_free = fs.pool_free_bytes_for_quota();
        let decision =
            fs.state
                .quota_table
                .check_delta(&inode_ancestors, delta_bytes, 1, pool_free);
        if decision.is_refusal() {
            return Err(map_errno(&FileSystemError::from(decision)));
        }

        fs.ensure_inode_capacity_for_new_inode()
            .map_err(|e| map_errno(&e))?;

        fs.begin_mutation("create VFS file-like node")
            .map_err(|e| map_errno(&e))?;
        if !fs.state.inodes.contains_key(&parent_id) {
            fs.rollback_mutation_delta();
            return Err(Errno::ENOENT);
        }
        match fs.dir_entry_by_inode(parent_id, name, parent_path) {
            Ok(Some(_)) => {
                fs.rollback_mutation_delta();
                return Err(Errno::EEXIST);
            }
            Ok(None) => {}
            Err(err) => {
                fs.rollback_mutation_delta();
                return Err(map_errno(&err));
            }
        }

        let tick = fs.bump_generation();
        let inode_id = fs.allocate_inode_id();
        let generation = Generation::new(tick);
        let mut new_mode = mode;
        let mut xattrs = BTreeMap::new();
        if let Some(acl_entries) = parent_default_acl_entries {
            for (name, value) in
                tidefs_posix_acl::default_acl_inheritance_for_parent(acl_entries, new_mode, false)
            {
                if name == Self::POSIX_ACL_ACCESS_XATTR {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        new_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, new_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }

        let record = InodeRecord {
            rdev: 0,
            inode_id,
            generation,
            facets: NodeKind::File.to_facets(),
            mode: new_mode,
            uid,
            gid,
            nlink: 1,
            size: 0,
            data_version: tick,
            metadata_version: tick,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs,
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        };

        let name_vec = name.to_vec();
        let _ = fs.intent_log_buffer.as_ref().map(|buf| {
            let _frame = buf.append(
                tidefs_intent_log::IntentLogRecord::Create {
                    parent: parent_id.get(),
                    name: name_vec.clone(),
                    mode: new_mode,
                    ino: inode_id.get(),
                },
                0,
            );
        });
        let entry = NamespaceEntry {
            name: name_vec.clone(),
            inode_id,
            generation,
            facets: NodeKind::File.to_facets(),
            mode: new_mode,
        };
        let create_intent_state =
            match fs.namespace_create_group_commit_intent(parent_id, entry.clone(), &record) {
                Ok(state) => state,
                Err(err) => {
                    fs.rollback_mutation_delta();
                    return Err(map_errno(&err));
                }
            };

        fs.mark_inode_metadata_dirty(inode_id);
        fs.mark_dir_dirty(parent_id);
        fs.mark_inode_metadata_dirty(parent_id);
        Arc::make_mut(&mut fs.state.inodes).insert(inode_id, record.clone());
        fs.inode_cache.borrow_mut().invalidate(inode_id);
        if let Err(err) = fs.insert_directory_entry(parent_id, name_vec, entry, tick) {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        fs.update_parent_metadata_timestamps(parent_id, tick);

        let committed = if create_intent_state == IntentLogReplyState::Refused {
            fs.force_commit(record)
        } else {
            fs.commit_mutation(record)
        };
        let record = committed.map_err(|e| map_errno(&e))?;
        fs.state
            .quota_table
            .apply_delta(&inode_ancestors, delta_bytes, 1);
        self.path_cache
            .borrow_mut()
            .insert(record.inode_id, child_path.to_string());
        Ok(record)
    }

    /// Return the configured sync guarantee for this dataset mount.
    pub fn sync_guarantee(&self) -> SyncGuarantee {
        self.sync_guarantee
    }

    /// Wait for the required sync guarantee level before acknowledging.
    ///
    /// For [`SyncGuarantee::Local`], this is a no-op: the write is already
    /// durable after local intent-log append + commit.
    ///
    /// For [`SyncGuarantee::RemoteCopy`] and [`SyncGuarantee::FullRedundancy`],
    /// callers should additionally wait on placement receipt acknowledgments
    /// from peer nodes.  Currently returns `Ok(())` unconditionally;
    /// the distributed confirmation path is tracked by Review debt TFR-017
    /// (historical issue #6654).
    fn wait_for_sync_guarantee(&self) -> std::result::Result<(), Errno> {
        match self.sync_guarantee {
            SyncGuarantee::Local => Ok(()),
            SyncGuarantee::RemoteCopy | SyncGuarantee::FullRedundancy => {
                eprintln!(
                    "tidefs-vfs: sync_guarantee={} — distributed confirmation not yet wired; using local-only durability",
                    self.sync_guarantee
                );
                Ok(())
            }
        }
    }

    fn handle_live_pool_admin_request(
        &self,
        request: &LivePoolAdminRequest,
    ) -> std::result::Result<LivePoolAdminResponse, Errno> {
        if Self::live_admin_request_mutates_mounted_state(request) {
            self.ensure_mounted_mutation_allowed("administer mounted pool")?;
        }
        if let Err(err) = request.validate_version() {
            return Ok(live_admin_typed_error(err));
        }
        let pool = request.pool.as_str();
        let wants_json = request.output.wants_json();

        Ok(match &request.command {
            LivePoolAdminCommand::PerformanceAdmissionSnapshot => {
                self.live_performance_admission_snapshot(pool, &request.args)
            }
            command => {
                let args = live_admin_args_to_json(&request.args);
                match command {
                    LivePoolAdminCommand::DatasetCreate => {
                        self.live_dataset_create(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetList => {
                        self.live_dataset_list(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetResize => {
                        self.live_dataset_resize(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetRename => self.live_dataset_rename(pool, &args),
                    LivePoolAdminCommand::DatasetDestroy => {
                        self.live_dataset_destroy(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetSetStrategy => {
                        self.live_dataset_set_strategy(&args)
                    }
                    LivePoolAdminCommand::DatasetUpgrade => self.live_dataset_upgrade(&args),
                    LivePoolAdminCommand::DatasetSealKey => self.live_dataset_seal_key(&args),
                    LivePoolAdminCommand::DatasetRotateKey => self.live_dataset_rotate_key(&args),
                    LivePoolAdminCommand::DatasetGet => {
                        self.live_dataset_get(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetSet => {
                        self.live_dataset_set(pool, &args, wants_json)
                    }
                    LivePoolAdminCommand::DatasetListProps => {
                        self.live_dataset_list_props(pool, &args)
                    }
                    LivePoolAdminCommand::SnapshotCreate => {
                        self.live_snapshot_create(&args, wants_json)
                    }
                    LivePoolAdminCommand::SnapshotList => self.live_snapshot_list(wants_json),
                    LivePoolAdminCommand::SnapshotCloneCreate => {
                        self.live_snapshot_clone_create(&args, wants_json)
                    }
                    LivePoolAdminCommand::SnapshotCloneDelete => {
                        self.live_snapshot_clone_delete(&args, wants_json)
                    }
                    LivePoolAdminCommand::SnapshotClonePromote => {
                        self.live_snapshot_clone_promote(&args, wants_json)
                    }
                    LivePoolAdminCommand::SnapshotDestroy => {
                        self.live_snapshot_destroy(&args, wants_json)
                    }
                    LivePoolAdminCommand::SnapshotRollback => self.live_snapshot_rollback(&args),
                    LivePoolAdminCommand::SnapshotExtract => {
                        self.live_snapshot_extract(&args, wants_json)
                    }
                    #[cfg(feature = "replication-io")]
                    LivePoolAdminCommand::SnapshotSend => {
                        self.live_snapshot_send(&args, wants_json)
                    }
                    command => {
                        let (command_name, operation) = command.parts();
                        live_admin_typed_error(LivePoolAdminError::unsupported_command(
                            command_name,
                            operation,
                        ))
                    }
                }
            }
        })
    }

    fn live_admin_request_mutates_mounted_state(request: &LivePoolAdminRequest) -> bool {
        match request.command {
            LivePoolAdminCommand::PoolImport
            | LivePoolAdminCommand::PoolMount
            | LivePoolAdminCommand::PoolExport
            | LivePoolAdminCommand::PoolDestroy
            | LivePoolAdminCommand::PoolRepair
            | LivePoolAdminCommand::DatasetCreate
            | LivePoolAdminCommand::DatasetResize
            | LivePoolAdminCommand::DatasetRename
            | LivePoolAdminCommand::DatasetDestroy
            | LivePoolAdminCommand::DatasetUpgrade
            | LivePoolAdminCommand::DatasetSet
            | LivePoolAdminCommand::DatasetSealKey
            | LivePoolAdminCommand::DatasetRotateKey
            | LivePoolAdminCommand::SnapshotCreate
            | LivePoolAdminCommand::SnapshotCloneCreate
            | LivePoolAdminCommand::SnapshotCloneDelete
            | LivePoolAdminCommand::SnapshotClonePromote
            | LivePoolAdminCommand::SnapshotDestroy
            | LivePoolAdminCommand::SnapshotRollback
            | LivePoolAdminCommand::SnapshotExtract
            | LivePoolAdminCommand::SnapshotSend
            | LivePoolAdminCommand::PerformanceAdmissionSnapshot
            | LivePoolAdminCommand::BlockAttach => true,
            LivePoolAdminCommand::DatasetSetStrategy => !matches!(
                request.args.0.get("list"),
                Some(LivePoolAdminArg::Bool(true))
            ),
            LivePoolAdminCommand::PoolStatus
            | LivePoolAdminCommand::PoolGet
            | LivePoolAdminCommand::PoolSet
            | LivePoolAdminCommand::PoolListProps
            | LivePoolAdminCommand::PoolIntegrityCheck
            | LivePoolAdminCommand::PoolScrub
            | LivePoolAdminCommand::DatasetList
            | LivePoolAdminCommand::DatasetGet
            | LivePoolAdminCommand::DatasetListProps
            | LivePoolAdminCommand::SnapshotList
            | LivePoolAdminCommand::DeviceStatus
            | LivePoolAdminCommand::DeviceOffline
            | LivePoolAdminCommand::DeviceOnline
            | LivePoolAdminCommand::DeviceRemove
            | LivePoolAdminCommand::DeviceReplace
            | LivePoolAdminCommand::DeviceRebuild => false,
        }
    }

    fn live_performance_admission_snapshot(
        &self,
        pool: &str,
        args: &LivePoolAdminArgs,
    ) -> LivePoolAdminResponse {
        let (workload, mount_adapter, artifact_path) =
            match live_performance_admission_snapshot_args(args) {
                Ok(args) => args,
                Err(err) => return live_admin_typed_error(err),
            };
        let mut fs = self.fs.borrow_mut();
        let config = fs.admission_config();
        let snapshot = match fs.take_admission_snapshot() {
            Ok(snapshot) => snapshot.as_evidence_record(),
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("performance admission snapshot refused: {err}"),
                )
            }
        };

        live_admin_ok_json(json!({
            "schema_version": 1,
            "evidence_class": "queue-depth-runtime-artifact",
            "evidence_scope": "bounded mounted FUSE runtime dirty-write admission queue-depth snapshot",
            "source": "tidefsctl mounted lifecycle",
            "claim_ids": [
                "perf.local.no_unbounded_dirty_debt.v1"
            ],
            "runtime_claim_boundary": "runtime queue-depth evidence only; claim validation still requires the no-hidden queue gate, admission budget model, and claims-gate review before status can move from blocked",
            "pool": pool,
            "mount_adapter": mount_adapter,
            "workload": workload,
            "artifact_path": artifact_path,
            "no_hidden_queue_gate": {
                "registry_path": "validation/performance/no-hidden-queues.toml",
                "command": "cargo run -p tidefs-xtask -- check-no-hidden-queues",
                "registered_queue_roots": [
                    "performance_contract.budgeted_queue",
                    "local_fs.write_admission",
                    "local_fs.write_buffers",
                    "local_fs.dirty_set",
                    "local_fs.dirty_page_tracker",
                    "local_fs.page_cache_lru"
                ]
            },
            "admission": {
                "peak_dirty_bytes": snapshot.peak_dirty_bytes,
                "peak_dirty_ops": snapshot.peak_dirty_ops,
                "peak_outstanding_permits": snapshot.peak_outstanding_permits,
                "current_dirty_bytes": snapshot.current_dirty_bytes,
                "current_dirty_ops": snapshot.current_dirty_ops,
                "current_outstanding_permits": snapshot.current_outstanding_permits,
                "current_tick": snapshot.current_tick
            },
            "invariant_checks": {
                "peak_dirty_bytes_within_effective_cap": snapshot.peak_dirty_bytes <= config.effective_max_dirty_bytes(),
                "peak_dirty_ops_within_effective_cap": snapshot.peak_dirty_ops <= config.effective_max_dirty_ops(),
                "peak_outstanding_permits_within_hard_cap": snapshot.peak_outstanding_permits <= config.hard_max_permits,
                "current_dirty_bytes_within_effective_cap": snapshot.current_dirty_bytes <= config.effective_max_dirty_bytes(),
                "current_dirty_ops_within_effective_cap": snapshot.current_dirty_ops <= config.effective_max_dirty_ops(),
                "current_outstanding_permits_within_hard_cap": snapshot.current_outstanding_permits <= config.hard_max_permits
            },
            "hard_caps": {
                "dirty_bytes": config.hard_max_dirty_bytes,
                "dirty_ops": config.hard_max_dirty_ops,
                "dirty_age_ticks": config.hard_max_dirty_age_ticks,
                "permits": config.hard_max_permits
            },
            "effective_caps": {
                "dirty_bytes": config.effective_max_dirty_bytes(),
                "dirty_ops": config.effective_max_dirty_ops(),
                "dirty_age_ticks": config.effective_max_dirty_age_ticks(),
                "permits": config.hard_max_permits
            },
            "determinism": {
                "workload": "fixed canonical mounted lifecycle workload",
                "admission_state": "single mounted local filesystem with default hard caps",
                "tolerance": {
                    "peak_dirty_bytes": 0,
                    "peak_dirty_ops": 0,
                    "peak_outstanding_permits": 0
                }
            },
            "non_claims": [
                "does not validate crash recovery",
                "does not validate scrub/read isolation",
                "does not move perf.local.no_unbounded_dirty_debt.v1 out of blocked status"
            ]
        }))
    }

    fn live_dataset_create(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let parent = live_admin_arg(args, "parent").unwrap_or("root");
        let sync = live_admin_arg(args, "sync").unwrap_or("local");
        let dataset_type = match live_dataset_type_arg(args) {
            Ok(value) => value,
            Err(err) => return live_admin_error(1, err),
        };
        let properties = match live_property_set_from_request(args) {
            Ok(value) => value,
            Err(err) => return live_admin_error(1, err),
        };
        let features = match live_feature_names_from_request(args) {
            Ok(value) => value,
            Err(err) => return live_admin_error(1, err),
        };
        let mountpoint = live_admin_optional_arg(args, "mountpoint");
        let capacity = args.get("size").and_then(Value::as_u64);

        if name == "root" {
            return live_admin_error(1, "dataset create: 'root' dataset cannot be re-created");
        }

        if dataset_type == DatasetType::Snapshot {
            return live_admin_error(
                1,
                "dataset create: snapshots must be created by the owning filesystem or volume engine",
            );
        }
        if mountpoint.is_some() {
            return live_admin_error(
                1,
                match dataset_type {
                    DatasetType::Filesystem => "dataset create: --mountpoint is not available for local filesystem creation; mount the dataset explicitly with 'pool mount --dataset'",
                    DatasetType::Volume => "dataset create: --mountpoint is not valid for a block volume",
                    DatasetType::Snapshot => unreachable!(),
                },
            );
        }
        if !features.is_empty() {
            return live_admin_error(
                1,
                match dataset_type {
                    DatasetType::Filesystem => "dataset create: filesystem feature flags are not available until the named filesystem engine consumes them",
                    DatasetType::Volume => "dataset create: volume feature flags are not available until the volume engine consumes them",
                    DatasetType::Snapshot => unreachable!(),
                },
            );
        }

        let sync_guarantee = match parse_sync_guarantee(sync) {
            Some(value) => value,
            None => {
                return live_admin_error(
                    1,
                    format!(
                        "dataset create: invalid sync value {sync}; expected local, remote-copy, or full-redundancy"
                    ),
                )
            }
        };
        if sync_guarantee != SyncGuarantee::Local {
            return live_admin_error(
                1,
                "dataset create: local dataset creation supports only --sync local; clustered guarantees require committed cluster ownership",
            );
        }
        let capacity = match (dataset_type, capacity) {
            (DatasetType::Filesystem, None) => None,
            (DatasetType::Filesystem, Some(_)) => {
                return live_admin_error(
                    1,
                    "dataset create: --size is valid only for block volumes",
                )
            }
            (DatasetType::Volume, Some(capacity)) if capacity > 0 && capacity % 4096 == 0 => {
                Some(capacity)
            }
            (DatasetType::Volume, Some(_)) => {
                return live_admin_error(
                    1,
                    "dataset create: volume size must be nonzero and aligned to 4096 bytes",
                )
            }
            (DatasetType::Volume, None) => {
                return live_admin_error(
                    1,
                    "dataset create: --size <bytes> is required for --type volume",
                )
            }
            (DatasetType::Snapshot, _) => unreachable!(),
        };

        let full_path = if parent == "root" {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        };
        let dataset_id = dataset_id_from_name(&full_path);

        let mut fs = self.fs.borrow_mut();
        if !fs.dataset_catalog().contains(parent) {
            return live_admin_error(
                1,
                format!("dataset create: parent dataset '{parent}' does not exist in the catalog"),
            );
        }
        if fs.dataset_catalog().contains(&full_path) {
            return live_admin_error(
                1,
                format!("dataset create: dataset '{full_path}' already exists in the catalog"),
            );
        }

        let geometry = match dataset_type {
            DatasetType::Filesystem => match fs.create_filesystem_dataset(
                &full_path,
                dataset_id,
                properties.to_key_value_blob(),
                DatasetFlags::default_create(),
                sync_guarantee,
            ) {
                Ok(_) => None,
                Err(err) => return live_admin_error(1, format!("dataset create: {err}")),
            },
            DatasetType::Volume => match fs.create_volume_dataset(
                &full_path,
                dataset_id,
                capacity.expect("volume capacity was validated"),
                properties.to_key_value_blob(),
                DatasetFlags::default_create(),
                sync_guarantee,
            ) {
                Ok(geometry) => Some(geometry),
                Err(err) => return live_admin_error(1, format!("dataset create: {err}")),
            },
            DatasetType::Snapshot => unreachable!(),
        };

        let requested_properties = args.get("properties").cloned().unwrap_or_else(|| json!([]));

        if wants_json {
            return live_admin_ok_json(json!({
                "ok": true,
                "operation": "create",
                "pool": pool,
                "dataset": full_path,
                "id": dataset_id.to_string(),
                "type": dataset_type.to_string(),
                "size": geometry.as_ref().map(|geometry| geometry.capacity_bytes),
                "block_size": geometry.as_ref().map(|geometry| geometry.block_size_bytes),
                "parent": parent,
                "mountpoint": mountpoint,
                "properties": requested_properties,
                "features": features,
            }));
        }

        let detail = geometry.map_or_else(
            || "filesystem_root=published".to_string(),
            |geometry| {
                format!(
                    "size={}  block_size={}",
                    geometry.capacity_bytes, geometry.block_size_bytes
                )
            },
        );
        live_admin_ok_text(format!(
            "dataset '{full_path}' created in imported pool '{pool}'\n  id={}  parent='{parent}'  {detail}",
            format_dataset_id(&dataset_id),
        ))
    }

    fn live_dataset_list(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let type_filter = match live_dataset_type_filter_arg(args) {
            Ok(value) => value,
            Err(err) => return live_admin_error(1, err),
        };
        let mut fs = self.fs.borrow_mut();
        let available_bytes = fs
            .statfs()
            .ok()
            .map(|stats| stats.bavail.saturating_mul(u64::from(stats.bsize)));
        let catalog = fs.dataset_catalog();
        let entries: Vec<_> = catalog
            .list_all()
            .into_iter()
            .filter(|(_, _, dataset_type, _, _, _)| {
                type_filter
                    .map(|filter| filter == *dataset_type)
                    .unwrap_or(true)
            })
            .collect();

        if wants_json {
            let values: Vec<_> = entries
                .iter()
                .map(|(path, id, dataset_type, _, _, _)| {
                    json!({
                        "pool": pool,
                        "name": format!("{pool}/{path}"),
                        "path": path,
                        "type": dataset_type.to_string(),
                        "used": Value::Null,
                        "available": available_bytes,
                        "mountpoint": Value::Null,
                        "id": id.to_string(),
                        "sync": catalog.sync_guarantee(path).ok().map(|value| value.to_string()),
                        "state": catalog.lifecycle_state(path).ok().map(|value| format!("{value:?}")),
                    })
                })
                .collect();
            return live_admin_ok_json(json!({
                "ok": true,
                "pool": pool,
                "datasets": values,
            }));
        }

        if entries.is_empty() {
            return live_admin_ok_text(format!("pool '{pool}' has no datasets"));
        }

        let mut out = format!(
            "{:<40} {:<12} {:>14} {:>14} {}",
            "NAME", "TYPE", "USED", "AVAILABLE", "MOUNTPOINT"
        );
        for (path, _, dataset_type, _, _, _) in &entries {
            let _ = write!(
                out,
                "\n{:<40} {:<12} {:>14} {:>14} {}",
                format!("{pool}/{path}"),
                dataset_type,
                "-",
                available_bytes
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                "-"
            );
        }
        live_admin_ok_text(out)
    }

    fn live_dataset_resize(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let Some(capacity_bytes) = args.get("size").and_then(Value::as_u64) else {
            return live_admin_error(2, "dataset resize: --size <bytes> is required");
        };

        let mut fs = self.fs.borrow_mut();
        let result = match fs.resize_volume_dataset(name, capacity_bytes) {
            Ok(result) => result,
            Err(err) => return live_admin_error(1, format!("dataset resize: {err}")),
        };
        if wants_json {
            return live_admin_ok_json(json!({
                "ok": true,
                "operation": "resize",
                "pool": pool,
                "dataset": name,
                "size": result.geometry.capacity_bytes,
                "block_size": result.geometry.block_size_bytes,
                "generation": result.generation,
                "resize_generation": result.resize_generation,
            }));
        }
        live_admin_ok_text(format!(
            "dataset '{name}' resized in imported pool '{pool}'\n  size={}  block_size={}  generation={}  resize_generation={}",
            result.geometry.capacity_bytes,
            result.geometry.block_size_bytes,
            result.generation,
            result.resize_generation,
        ))
    }

    fn live_dataset_rename(&self, pool: &str, args: &Value) -> LivePoolAdminResponse {
        let old_name = match live_admin_arg(args, "old_name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let new_name = match live_admin_arg(args, "new_name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        if old_name == "root" || new_name == "root" {
            return live_admin_error(1, "dataset rename: root dataset cannot be renamed");
        }

        if let Err(err) = self.fs.borrow_mut().rename_pool_dataset(old_name, new_name) {
            return live_admin_error(
                1,
                format!("dataset rename: failed to rename '{old_name}' -> '{new_name}': {err}"),
            );
        }

        live_admin_ok_text(format!(
            "dataset '{old_name}' renamed to '{new_name}' in imported pool '{pool}'"
        ))
    }

    fn live_dataset_destroy(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
        if name == "root" {
            return live_admin_error(1, "dataset destroy: 'root' dataset cannot be destroyed");
        }

        let mut fs = self.fs.borrow_mut();
        if !fs.dataset_catalog().contains(name) {
            return live_admin_error(
                1,
                format!("dataset destroy: dataset '{name}' does not exist in the catalog"),
            );
        }
        let child_count = match fs.dataset_catalog().list_children(name) {
            Ok(children) => children.len(),
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset destroy: catalog error listing children of '{name}': {err}"),
                )
            }
        };
        let snapshot_count = match live_dataset_snapshot_count(fs.dataset_catalog(), name) {
            Ok(count) => count,
            Err(err) => return live_admin_error(1, err),
        };
        let live_mount = fs
            .dataset_catalog()
            .lookup(name)
            .map(|dataset_id| *dataset_id.as_bytes() == fs.mounted_dataset_id())
            .unwrap_or(false);
        let mut hazards = Vec::new();
        if child_count > 0 {
            hazards.push(format!("{child_count} child dataset(s)"));
        }
        if snapshot_count > 0 {
            hazards.push(format!("{snapshot_count} snapshot(s)"));
        }
        if live_mount {
            hazards.push("a live mount".to_string());
        }
        if !hazards.is_empty() && !force {
            return live_admin_error(
                1,
                format!(
                    "dataset destroy: dataset '{name}' has {}; retry with --force to destroy it",
                    hazards.join(", ")
                ),
            );
        }

        let dataset_type = fs
            .dataset_catalog()
            .get_by_id(
                &fs.dataset_catalog()
                    .lookup(name)
                    .expect("existing dataset retains identity"),
            )
            .map(|(_, _, dataset_type, _, _, _)| dataset_type)
            .expect("existing dataset retains catalog type");
        if dataset_type == DatasetType::Volume {
            match fs.destroy_volume_dataset(name) {
                Ok(result) => {
                    if wants_json {
                        return live_admin_ok_json(json!({
                            "ok": true,
                            "operation": "destroy",
                            "pool": pool,
                            "dataset": name,
                            "force": force,
                            "destroyed_entries": 1,
                            "child_count": child_count,
                            "snapshot_count": snapshot_count,
                            "live_mount": live_mount,
                            "reclaim": volume_reclaim_json(&result.reclaim),
                        }));
                    }
                    return live_admin_ok_text(format!(
                        "dataset '{name}' logically destroyed; {}",
                        volume_reclaim_line(&result.reclaim),
                    ));
                }
                Err(err) => {
                    return live_admin_error(1, format!("dataset destroy: {err}"));
                }
            }
        }
        if dataset_type != DatasetType::Filesystem {
            return live_admin_error(1, "dataset destroy: unsupported dataset type");
        }
        if child_count != 0 || snapshot_count != 0 || live_mount {
            return live_admin_error(
                1,
                "dataset destroy: recursive or live filesystem destruction is not implemented; destroy snapshots and children and unmount the target first",
            );
        }
        if let Err(err) = fs.destroy_filesystem_dataset(name) {
            return live_admin_error(1, format!("dataset destroy: {err}"));
        }
        if wants_json {
            return live_admin_ok_json(json!({
                "ok": true,
                "operation": "destroy",
                "pool": pool,
                "dataset": name,
                "force": force,
                "destroyed_entries": 1,
                "child_count": child_count,
                "snapshot_count": snapshot_count,
                "live_mount": live_mount,
            }));
        }
        live_admin_ok_text(format!("dataset '{name}' destroyed"))
    }

    fn live_dataset_set_strategy(&self, args: &Value) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let enable = match live_admin_string_vec(args, "enable") {
            Ok(values) => values,
            Err(err) => return live_admin_error(2, err),
        };
        let disable = match live_admin_string_vec(args, "disable") {
            Ok(values) => values,
            Err(err) => return live_admin_error(2, err),
        };
        let list = args.get("list").and_then(Value::as_bool).unwrap_or(false);
        let class = live_admin_optional_arg(args, "class").unwrap_or("auto");

        let mut fs = self.fs.borrow_mut();
        if !fs.dataset_catalog().contains(name) {
            return live_admin_error(
                1,
                format!("dataset set-strategy: dataset '{name}' does not exist in the catalog"),
            );
        }
        let target_id = fs
            .dataset_catalog()
            .lookup(name)
            .expect("existing dataset retains identity");
        if *target_id.as_bytes() != fs.mounted_dataset_id() {
            return live_admin_error(
                1,
                "dataset set-strategy: named filesystem feature flags require that dataset's mounted owner; refusing to mutate the root filesystem",
            );
        }

        if list {
            let flags = fs.feature_flags();
            if flags.is_empty() {
                return live_admin_ok_text(format!(
                    "dataset '{name}' has no feature flags enabled"
                ));
            }
            let mut out = format!("dataset '{name}' feature flags:");
            for (class, feature, value) in flags.all_features() {
                let _ = write!(out, "\n  {class}  {feature}  ({})", value.to_u8());
            }
            return live_admin_ok_text(out);
        }

        let feature_class = match resolve_feature_class(class, &enable) {
            Ok(value) => value,
            Err(err) => return live_admin_error(1, err),
        };

        let mut changed = false;
        let mut out = Vec::new();

        for feature_str in enable.iter().map(String::as_str).map(str::trim) {
            if feature_str.is_empty() {
                continue;
            }
            let Some(feature) = FeatureName::from_str(feature_str) else {
                return live_admin_error(
                    1,
                    format!(
                        "dataset set-strategy: invalid feature name '{feature_str}'; expected format org.tidefs:<name>"
                    ),
                );
            };
            if !crate::feature_available_in_current_build(&feature) {
                return live_admin_error(
                    1,
                    format!(
                        "dataset set-strategy: feature '{feature_str}' requires a data-policy build"
                    ),
                );
            }
            let enable_result = match fs.feature_flags_mut() {
                Ok(flags) => flags.enable_feature_with_prereqs(feature, feature_class),
                Err(err) => {
                    return live_admin_error(
                        1,
                        format!("dataset set-strategy: mutation requires reopen: {err}"),
                    )
                }
            };
            match enable_result {
                Ok(()) => {
                    out.push(format!(
                        "enabled feature '{feature_str}' (class: {feature_class})"
                    ));
                    changed = true;
                }
                Err(err) => {
                    return live_admin_error(
                        1,
                        format!("dataset set-strategy: failed to enable '{feature_str}': {err}"),
                    )
                }
            }
        }

        for feature_str in disable.iter().map(String::as_str).map(str::trim) {
            if feature_str.is_empty() {
                continue;
            }
            let Some(feature) = FeatureName::from_str(feature_str) else {
                return live_admin_error(
                    1,
                    format!(
                        "dataset set-strategy: invalid feature name '{feature_str}'; expected format org.tidefs:<name>"
                    ),
                );
            };
            let disable_result = match fs.feature_flags_mut() {
                Ok(flags) => flags.disable_feature(&feature),
                Err(err) => {
                    return live_admin_error(
                        1,
                        format!("dataset set-strategy: mutation requires reopen: {err}"),
                    )
                }
            };
            match disable_result {
                Ok(()) => {
                    out.push(format!("disabled feature '{feature_str}'"));
                    changed = true;
                }
                Err(err) => {
                    return live_admin_error(
                        1,
                        format!("dataset set-strategy: failed to disable '{feature_str}': {err}"),
                    )
                }
            }
        }

        if changed {
            if let Err(err) = fs.persist_feature_flags() {
                return live_admin_error(
                    1,
                    format!("dataset set-strategy: failed to persist feature flags: {err}"),
                );
            }
            #[cfg(feature = "data-policy")]
            if let Err(err) = fs.refresh_policies_from_features() {
                return live_admin_error(
                    1,
                    format!("dataset set-strategy: failed to refresh mounted policies: {err}"),
                );
            }
            out.push(format!("feature flags persisted for dataset '{name}'"));
        }

        if out.is_empty() {
            live_admin_ok_text(format!("dataset '{name}' feature flags unchanged"))
        } else {
            live_admin_ok_text(out.join("\n"))
        }
    }

    fn live_dataset_upgrade(&self, args: &Value) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };

        let mut fs = self.fs.borrow_mut();
        if !fs.dataset_catalog().contains(name) {
            return live_admin_error(
                1,
                format!("dataset upgrade: dataset '{name}' does not exist in the catalog"),
            );
        }
        let target_id = fs
            .dataset_catalog()
            .lookup(name)
            .expect("existing dataset retains identity");
        if *target_id.as_bytes() != fs.mounted_dataset_id() {
            return live_admin_error(
                1,
                "dataset upgrade: named filesystem feature flags require that dataset's mounted owner; refusing to mutate the root filesystem",
            );
        }

        let supported = tidefs_dataset_feature_flags::SupportedFeaturesV1::current();
        let available: Vec<_> = supported
            .as_slice()
            .iter()
            .filter(|feature| crate::feature_available_in_current_build(feature))
            .cloned()
            .collect();
        let to_enable: Vec<_> = available
            .iter()
            .filter(|feature| !fs.feature_flags().is_enabled(feature))
            .cloned()
            .collect();

        if to_enable.is_empty() {
            return live_admin_ok_text(format!(
                "dataset '{name}': all {} supported features are already enabled",
                available.len()
            ));
        }

        let before_count = fs.feature_flags().len();
        let mut enabled_count = 0u32;
        let mut skipped_count = 0u32;
        let mut failed = Vec::new();
        let mut out = vec![format!(
            "dataset '{name}': upgrading from {before_count} enabled to {} supported features...",
            available.len()
        )];

        let mut pending = to_enable;
        while !pending.is_empty() {
            let mut deferred = Vec::new();
            let mut made_progress = false;

            for feature in pending {
                if fs.feature_flags().is_enabled(&feature) {
                    continue;
                }
                let Some(class) = get_feature_class(&feature) else {
                    skipped_count += 1;
                    continue;
                };
                let enable_result = match fs.feature_flags_mut() {
                    Ok(flags) => flags.enable_feature_with_prereqs(feature.clone(), class),
                    Err(err) => {
                        return live_admin_error(
                            1,
                            format!("dataset upgrade: mutation requires reopen: {err}"),
                        )
                    }
                };
                match enable_result {
                    Ok(()) => {
                        out.push(format!("  enabled {feature} ({class})"));
                        enabled_count += 1;
                        made_progress = true;
                    }
                    Err(tidefs_dataset_feature_flags::FeatureFlagsError::MissingPrerequisite {
                        ..
                    }) => deferred.push(feature),
                    Err(err) => {
                        let msg = err.to_string();
                        out.push(format!("  FAILED {feature} ({class}) : {msg}"));
                        failed.push((feature.to_string(), msg));
                    }
                }
            }

            if deferred.is_empty() {
                break;
            }
            if !made_progress {
                for feature in deferred {
                    let Some(class) = get_feature_class(&feature) else {
                        skipped_count += 1;
                        continue;
                    };
                    let enable_result = match fs.feature_flags_mut() {
                        Ok(flags) => flags.enable_feature_with_prereqs(feature.clone(), class),
                        Err(err) => {
                            return live_admin_error(
                                1,
                                format!("dataset upgrade: mutation requires reopen: {err}"),
                            )
                        }
                    };
                    if let Err(err) = enable_result {
                        let msg = err.to_string();
                        out.push(format!("  FAILED {feature} ({class}) : {msg}"));
                        failed.push((feature.to_string(), msg));
                    }
                }
                break;
            }
            pending = deferred;
        }

        if enabled_count > 0 {
            if let Err(err) = fs.persist_feature_flags() {
                return live_admin_error(
                    1,
                    format!("dataset upgrade: failed to persist feature flags: {err}"),
                );
            }
            #[cfg(feature = "data-policy")]
            if let Err(err) = fs.refresh_policies_from_features() {
                return live_admin_error(
                    1,
                    format!("dataset upgrade: failed to refresh mounted policies: {err}"),
                );
            }
            out.push(format!("feature flags persisted for dataset '{name}'"));
        }

        out.push(format!(
            "dataset '{name}' upgrade complete: {enabled_count} enabled, {skipped_count} skipped, {} failed",
            failed.len()
        ));

        if failed.is_empty() {
            live_admin_ok_text(out.join("\n"))
        } else {
            for (feature, reason) in &failed {
                out.push(format!("  {feature}: {reason}"));
            }
            live_admin_error(1, out.join("\n"))
        }
    }

    #[cfg(feature = "encryption")]
    fn live_dataset_seal_key(&self, args: &Value) -> LivePoolAdminResponse {
        if let Err(err) = self
            .fs
            .borrow()
            .ensure_mutation_allowed("seal mounted dataset encryption key")
        {
            return live_admin_error(
                1,
                format!("dataset seal-key: mutation requires reopen: {err}"),
            );
        }
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let passphrase = match live_admin_arg(args, "passphrase") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };

        if !self.fs.borrow().dataset_catalog().contains(name) {
            return live_admin_error(
                1,
                format!("dataset seal-key: dataset '{name}' does not exist in the catalog"),
            );
        }

        let salt = PoolWrappingKey::generate_salt();
        let wk = match PoolWrappingKey::derive(passphrase, &salt) {
            Ok(key) => key,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset seal-key: failed to derive wrapping key: {err}"),
                )
            }
        };
        let dek = DatasetDEK::generate();
        let sealed = match KeyManager::seal_dek(&dek, &wk, name, 1) {
            Ok(sealed) => sealed,
            Err(err) => {
                return live_admin_error(1, format!("dataset seal-key: failed to seal DEK: {err}"))
            }
        };

        let mut fs = self.fs.borrow_mut();
        let mut keystore = BorrowedKeyStore::new(fs.store.pool_mut().raw_primary_store_mut(), salt);
        if let Err(err) = keystore.store_sealed_dek(&sealed) {
            return live_admin_error(
                1,
                format!("dataset seal-key: failed to store sealed DEK: {err}"),
            );
        }

        let salt_hex = salt_to_hex(&salt);
        live_admin_ok_text(format!(
            "dataset '{name}' encryption key sealed (kek_generation=1)\n  salt: {salt_hex}\n  save this salt; it is required for key rotation"
        ))
    }

    #[cfg(not(feature = "encryption"))]
    fn live_dataset_seal_key(&self, _args: &Value) -> LivePoolAdminResponse {
        live_admin_error(
            1,
            "dataset seal-key: live owner was built without encryption support",
        )
    }

    #[cfg(feature = "encryption")]
    fn live_dataset_rotate_key(&self, args: &Value) -> LivePoolAdminResponse {
        if let Err(err) = self
            .fs
            .borrow()
            .ensure_mutation_allowed("rotate mounted dataset encryption key")
        {
            return live_admin_error(
                1,
                format!("dataset rotate-key: mutation requires reopen: {err}"),
            );
        }
        let old_passphrase = match live_admin_arg(args, "old_passphrase") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let old_salt_hex = match live_admin_arg(args, "old_salt") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let new_passphrase = match live_admin_arg(args, "new_passphrase") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let old_salt = match live_admin_hex_to_salt(old_salt_hex) {
            Ok(salt) => salt,
            Err(err) => {
                return live_admin_error(1, format!("dataset rotate-key: invalid old_salt: {err}"))
            }
        };
        let new_salt = PoolWrappingKey::generate_salt();

        let mut fs = self.fs.borrow_mut();
        let mut keystore =
            BorrowedKeyStore::new(fs.store.pool_mut().raw_primary_store_mut(), old_salt);
        let datasets = match keystore.list_datasets() {
            Ok(datasets) => datasets,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset rotate-key: failed to list datasets: {err}"),
                )
            }
        };
        if datasets.is_empty() {
            return live_admin_error(
                1,
                "dataset rotate-key: no datasets with sealed DEKs in imported pool",
            );
        }

        let stats = match KeyRotation::rekey_borrowed_wrapping_key(
            old_passphrase,
            new_passphrase,
            &new_salt,
            &mut keystore,
        ) {
            Ok(stats) => stats,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset rotate-key: key rotation failed: {err}"),
                )
            }
        };

        let new_salt_hex = salt_to_hex(&new_salt);
        live_admin_ok_text(format!(
            "key rotation complete: {} dataset(s) re-wrapped\n  new salt: {new_salt_hex}\n  save this salt for future rotations",
            stats.keys_rotated
        ))
    }

    #[cfg(not(feature = "encryption"))]
    fn live_dataset_rotate_key(&self, _args: &Value) -> LivePoolAdminResponse {
        live_admin_error(
            1,
            "dataset rotate-key: live owner was built without encryption support",
        )
    }

    fn live_dataset_get(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let property = match live_admin_arg(args, "property") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let registry = tidefs_dataset_properties::build_registry();
        let key = tidefs_dataset_properties::PropertyKey::new(property);
        if tidefs_dataset_properties::lookup_property(&registry, &key).is_none() {
            return live_admin_error(1, format!("dataset get: unknown property '{property}'"));
        }

        let path = name;
        let fs = self.fs.borrow();
        let effective = match fs.dataset_catalog().get_properties_with_inheritance(&path) {
            Ok(props) => props,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset get: cannot read properties for '{name}': {err}"),
                )
            }
        };
        match effective.get(&key) {
            Some(entry) => {
                if wants_json {
                    live_admin_ok_json(json!({
                        "ok": true,
                        "operation": "get",
                        "pool": pool,
                        "dataset": name,
                        "property": property,
                        "value": live_property_value_json(&entry.value),
                        "display_value": entry.value.to_string(),
                        "source": entry.source.to_string(),
                    }))
                } else {
                    live_admin_ok_text(format!(
                        "property:  {property}\nvalue:     {}\nsource:    {}",
                        entry.value, entry.source
                    ))
                }
            }
            None => live_admin_error(
                1,
                format!("dataset get: internal error resolving '{property}'"),
            ),
        }
    }

    fn live_dataset_set(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let assignment = live_admin_optional_arg(args, "assignment");
        let (prop_name, prop_val_str) = match live_admin_optional_arg(args, "property") {
            Some(property) => (
                property.trim(),
                live_admin_optional_arg(args, "display_value"),
            ),
            None => match assignment.and_then(|value| value.split_once('=')) {
                Some((key, value)) => (key.trim(), Some(value.trim())),
                None => {
                    return live_admin_error(
                        1,
                        format!(
                            "dataset set: invalid assignment '{}' (expected key=value)",
                            assignment.unwrap_or("")
                        ),
                    )
                }
            },
        };
        if prop_name.is_empty() {
            return live_admin_error(1, "dataset set: property name must not be empty");
        }

        let registry = tidefs_dataset_properties::build_registry();
        let key = tidefs_dataset_properties::PropertyKey::new(prop_name);
        let def = match tidefs_dataset_properties::lookup_property(&registry, &key) {
            Some(def) => def,
            None => {
                return live_admin_error(1, format!("dataset set: unknown property '{prop_name}'"))
            }
        };
        let is_clear = args
            .get("clear")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| prop_val_str.map_or(true, |value| value.is_empty() || value == "-"));
        let value = if is_clear {
            tidefs_dataset_properties::PropertyValue::None
        } else if let Some(value_json) = args.get("value") {
            match live_property_value_from_json(value_json, def.value_type) {
                Ok(value) => value,
                Err(err) => return live_admin_error(1, format!("dataset set: {err}")),
            }
        } else {
            let Some(prop_val_str) = prop_val_str else {
                return live_admin_error(1, "dataset set: property value must not be empty");
            };
            match live_property_value_from_str(prop_val_str, def.value_type) {
                Ok(value) => value,
                Err(err) => return live_admin_error(1, format!("dataset set: {err}")),
            }
        };
        let path = name;
        let mut fs = self.fs.borrow_mut();
        let existing_props = fs
            .dataset_catalog()
            .get_properties(&path)
            .unwrap_or_default();
        if let Err(err) =
            tidefs_dataset_properties::validate_set(&key, &value, def, &existing_props)
        {
            return live_admin_error(1, format!("dataset set: validation failed: {err}"));
        }
        let mut props = existing_props;
        if is_clear {
            props.remove_local_override(&key);
        } else {
            props.set_local(key.clone(), value.clone());
        }
        let catalog = match fs.dataset_catalog_mut() {
            Ok(catalog) => catalog,
            Err(err) => {
                return live_admin_error(1, format!("dataset set: mutation requires reopen: {err}"))
            }
        };
        if let Err(err) = catalog.set_properties(&path, &props) {
            return live_admin_error(
                1,
                format!("dataset set: cannot write properties for '{name}': {err}"),
            );
        }
        if let Err(err) = fs.persist_dataset_catalog() {
            return live_admin_error(
                1,
                format!("dataset set: property set but catalog persist failed: {err}"),
            );
        }
        if wants_json {
            live_admin_ok_json(json!({
                "ok": true,
                "operation": "set",
                "pool": pool,
                "dataset": name,
                "property": prop_name,
                "value": live_property_value_json(&value),
                "display_value": value.to_string(),
                "clear": is_clear,
            }))
        } else if is_clear {
            live_admin_ok_text(format!(
                "cleared '{prop_name}' (now using default/inherited value)"
            ))
        } else {
            live_admin_ok_text(format!("{prop_name} = {value}"))
        }
    }

    fn live_dataset_list_props(&self, _pool: &str, args: &Value) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let family = live_admin_optional_arg(args, "family");
        let path = name;
        let fs = self.fs.borrow();
        let props = match fs.dataset_catalog().get_properties(&path) {
            Ok(props) => props,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("dataset list-props: cannot read properties for '{name}': {err}"),
                )
            }
        };
        live_property_table("dataset list-props", &props, family)
    }

    fn live_snapshot_create(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        if let Some(target) = live_admin_optional_arg(args, "target") {
            let mut fs = self.fs.borrow_mut();
            return match fs.create_volume_snapshot_dataset(target) {
                Ok(summary) => volume_snapshot_response("created", &summary, wants_json),
                Err(err) => live_admin_error(
                    1,
                    format!("snapshot create: failed to create '{target}': {err}"),
                ),
            };
        }
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let mut fs = self.fs.borrow_mut();
        match fs.create_snapshot(name) {
            Ok(summary) => {
                live_admin_ok_text(format!("{} created", snapshot_summary_line(&summary)))
            }
            Err(err) => live_admin_error(
                1,
                format!("snapshot create: failed to create snapshot '{name}': {err}"),
            ),
        }
    }

    fn live_snapshot_clone_create(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let clone = match live_admin_arg(args, "clone") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let source = match live_admin_arg(args, "source") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        if !is_volume_snapshot_clone_source(source) {
            return filesystem_clone_unsupported("create", source);
        }
        let mut fs = self.fs.borrow_mut();
        match fs.create_volume_clone_dataset(clone, source) {
            Ok(summary) => volume_clone_response("created", &summary, wants_json),
            Err(err) => live_admin_error(
                1,
                format!(
                    "snapshot clone create: failed to create volume clone '{clone}' from '{source}': {err}"
                ),
            ),
        }
    }

    fn live_snapshot_clone_delete(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let clone = match live_admin_arg(args, "clone") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let mut fs = self.fs.borrow_mut();
        match fs.destroy_volume_clone_dataset(clone) {
            Ok(result) => volume_clone_destroy_response(&result, wants_json),
            Err(err) => live_admin_error(
                1,
                format!(
                    "snapshot clone delete: '{clone}' is not an unpromoted writable Pool volume clone: {err}"
                ),
            ),
        }
    }

    fn live_snapshot_clone_promote(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let clone = match live_admin_arg(args, "clone") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let mut fs = self.fs.borrow_mut();
        match fs.promote_volume_clone_dataset(clone) {
            Ok(summary) => volume_clone_response("promoted", &summary, wants_json),
            Err(err) => live_admin_error(
                1,
                format!(
                    "snapshot clone promote: '{clone}' is not an unpromoted writable Pool volume clone: {err}"
                ),
            ),
        }
    }

    fn live_snapshot_list(&self, wants_json: bool) -> LivePoolAdminResponse {
        let fs = self.fs.borrow();
        let mut snapshots = match fs.list_snapshots_checked() {
            Ok(snapshots) => snapshots,
            Err(err) => return live_admin_error(1, format!("snapshot list: {err}")),
        };
        let volume_snapshots = match fs.list_volume_snapshot_datasets() {
            Ok(snapshots) => snapshots,
            Err(err) => return live_admin_error(1, format!("snapshot list: {err}")),
        };
        snapshots.sort_by(|a, b| {
            a.created_at_generation
                .cmp(&b.created_at_generation)
                .then_with(|| a.name.cmp(&b.name))
        });
        if wants_json {
            let values: Vec<_> = snapshots
                .iter()
                .map(|summary| {
                    json!({
                        "name": summary.name,
                        "source_transaction_id": summary.source_transaction_id,
                        "source_generation": summary.source_generation,
                        "created_at_generation": summary.created_at_generation,
                    })
                })
                .collect();
            let volume_values = volume_snapshots
                .iter()
                .map(volume_snapshot_json)
                .collect::<Vec<_>>();
            return live_admin_ok_json(json!({
                "snapshots": values,
                "volume_snapshots": volume_values,
            }));
        }
        if snapshots.is_empty() && volume_snapshots.is_empty() {
            return live_admin_ok_text("no snapshots");
        }
        live_admin_ok_text(
            snapshots
                .iter()
                .map(snapshot_summary_line)
                .chain(volume_snapshots.iter().map(volume_snapshot_line))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    fn live_snapshot_destroy(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        if let Some(target) = live_admin_optional_arg(args, "target") {
            let mut fs = self.fs.borrow_mut();
            return match fs.destroy_volume_snapshot_dataset(target) {
                Ok(result) => volume_snapshot_destroy_response(&result, wants_json),
                Err(err) => live_admin_error(
                    1,
                    format!("snapshot destroy: failed to destroy '{target}': {err}"),
                ),
            };
        }
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let mut fs = self.fs.borrow_mut();
        match fs.delete_snapshot(name) {
            Ok(summary) => {
                live_admin_ok_text(format!("{} destroyed", snapshot_summary_line(&summary)))
            }
            Err(err) => live_admin_error(
                1,
                format!("snapshot destroy: failed to destroy snapshot '{name}': {err}"),
            ),
        }
    }

    fn live_snapshot_rollback(&self, args: &Value) -> LivePoolAdminResponse {
        if let Some(target) = live_admin_optional_arg(args, "target") {
            let mut fs = self.fs.borrow_mut();
            return match fs.restore_volume_snapshot_dataset(target) {
                Ok(result) => live_admin_ok_text(format!(
                    "volume snapshot '{}' restored to '{}' (size={} generation={} resize_generation={} snapshot_generation={})",
                    result.snapshot.path,
                    result.snapshot.source_path,
                    result.geometry.capacity_bytes,
                    result.generation,
                    result.resize_generation,
                    result.snapshot_generation,
                )),
                Err(err) => live_admin_error(
                    1,
                    format!("snapshot rollback: failed to restore '{target}': {err}"),
                ),
            };
        }
        let name = match live_admin_arg(args, "name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let rollback = self.fs.borrow_mut().rollback_to_snapshot(name);
        match rollback {
            Ok(report) => {
                self.reset_path_cache();
                live_admin_ok_text(format!(
                    "rolled back to snapshot '{}' (generation {} -> {}, restored source gen {}, {} snapshot entries)",
                    report.snapshot.name,
                    report.generation_before,
                    report.published_generation,
                    report.restored_source_generation,
                    report.snapshot_catalog_entries,
                ))
            }
            Err(err) => live_admin_error(
                1,
                format!("snapshot rollback: failed to rollback to snapshot '{name}': {err}"),
            ),
        }
    }

    fn live_snapshot_extract(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let name = match live_admin_arg(args, "snapshot_name") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let file_path = match live_admin_arg(args, "file_path") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let normalized_path = match PoolDatasetOwner::normalize_snapshot_extract_path(file_path) {
            Ok(path) => path,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!("snapshot extract: invalid file path '{file_path}': {err}"),
                )
            }
        };
        let output = live_admin_optional_arg(args, "output").map(std::path::PathBuf::from);
        let bytes = {
            let mut fs = self.fs.borrow_mut();
            match fs.extract_snapshot_file_from_open_pool(name, &normalized_path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    return live_admin_error(
                        1,
                        format!(
                            "snapshot extract: failed to read '{normalized_path}' from snapshot '{name}': {err}"
                        ),
                    )
                }
            }
        };

        if let Some(output) = output {
            if let Err(err) = std::fs::write(&output, &bytes) {
                return live_admin_error(
                    1,
                    format!(
                        "snapshot extract: failed to write output {}: {err}",
                        output.display()
                    ),
                );
            }
            if wants_json {
                return live_admin_ok_json(json!({
                    "snapshot_name": name,
                    "file_path": normalized_path,
                    "output": output.display().to_string(),
                    "bytes": bytes.len(),
                }));
            }
            return live_admin_ok_text(format!(
                "wrote {} bytes from snapshot '{name}' path '{normalized_path}' to {}",
                bytes.len(),
                output.display()
            ));
        }

        if wants_json {
            live_admin_ok_json(json!({
                "snapshot_name": name,
                "file_path": normalized_path,
                "bytes": bytes.len(),
                "bytes_hex": live_admin_hex_encode(&bytes),
            }))
        } else {
            live_admin_ok_bytes_hex(&bytes)
        }
    }

    #[cfg(feature = "replication-io")]
    fn live_snapshot_send(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let mut fs = self.fs.borrow_mut();
        let plan = match live_snapshot_send_plan(args, &mut fs) {
            Ok(plan) => plan,
            Err(err) => return live_admin_error(1, err),
        };

        if let LiveSnapshotSendDestination::TargetAddress {
            target_addr,
            output,
        } = &plan.destination
        {
            let output_note = output
                .as_ref()
                .map(|path| format!("; requested output {} was not written", path.display()))
                .unwrap_or_default();
            return live_admin_error(
                1,
                format!(
                    "snapshot send: live owner target-address send to {target_addr} is not implemented; remote admission and response surfacing are not yet wired{output_note}"
                ),
            );
        }

        let output = match &plan.destination {
            LiveSnapshotSendDestination::Output(output) => output,
            LiveSnapshotSendDestination::TargetAddress { .. } => unreachable!(),
        };
        let stream = match live_snapshot_send_export(&mut fs, &plan) {
            Ok(stream) => stream,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!(
                        "snapshot send: failed to export {} stream: {err}",
                        plan.mode.label()
                    ),
                )
            }
        };

        if let Err(err) = std::fs::write(output, &stream.encoded) {
            return live_admin_error(
                1,
                format!(
                    "snapshot send: failed to write stream to {}: {err}",
                    output.display()
                ),
            );
        }

        if wants_json {
            live_admin_ok_json(json!({
                "output": output.display().to_string(),
                "bytes": stream.encoded.len(),
                "format": plan.format.label(),
                "incremental": plan.mode.is_incremental(),
                "roots": stream.roots_len,
                "records": stream.total_records,
                "payload_bytes": stream.payload_bytes,
            }))
        } else {
            live_admin_ok_text(format!(
                "wrote {} stream to {} ({} bytes, format={}, roots={}, records={}, payload={} bytes)",
                plan.mode.label(),
                output.display(),
                stream.encoded.len(),
                plan.format.label(),
                stream.roots_len,
                stream.total_records,
                stream.payload_bytes,
            ))
        }
    }
}

fn mounted_canonical_verifier_report(fs: &mut PoolDatasetOwner) -> OnlineVerifierReport {
    let dataset_id = DatasetId::from_bytes(fs.filesystem.mounted_dataset_id);
    let root_authentication_key = fs.filesystem.root_authentication_key;
    match crate::recovery::verify_online_canonical_dataset(
        &mut fs.store,
        dataset_id,
        root_authentication_key,
    ) {
        Ok(report) => report,
        Err(err) => {
            let mut report = OnlineVerifierReport::empty();
            report.root_slot_count = 1;
            report.root_slots_seen = 1;
            report.root_slot_records_seen = 1;
            report.root_candidates_seen = 1;
            report.invalid_root_candidates = 1;
            report.issues.push(OnlineVerifierIssue {
                severity: OnlineVerifierIssueSeverity::Error,
                kind: OnlineVerifierIssueKind::RootCommitValidation,
                slot: None,
                location: None,
                transaction_id: None,
                generation: Some(fs.filesystem.state.generation),
                reason: format!("canonical mounted verifier failed: {err}"),
            });
            report.outcome = OnlineVerifierOutcome::IssuesFound;
            report
        }
    }
}

fn mounted_scrub_block_kind(kind: crate::types::ScrubBlockKind) -> (&'static str, Option<u64>) {
    match kind {
        crate::types::ScrubBlockKind::InlineContent => ("inline-content", None),
        crate::types::ScrubBlockKind::ContentManifest => ("content-manifest", None),
        crate::types::ScrubBlockKind::ContentChunk { chunk_index } => {
            ("content-chunk", Some(chunk_index))
        }
    }
}

fn mounted_scrub_checksum_layer(layer: crate::types::MountedContentChecksumLayer) -> &'static str {
    match layer {
        crate::types::MountedContentChecksumLayer::InlineContentBody => "inline-content-body",
        crate::types::MountedContentChecksumLayer::EncodedContentChunk => "encoded-content-chunk",
        crate::types::MountedContentChecksumLayer::SparseHole => "sparse-hole",
    }
}

fn mounted_scrub_digest(digest: tidefs_local_object_store::IntegrityDigest64) -> String {
    format!("{:016x}", digest.get())
}

fn mounted_scrub_placement_json(evidence: &crate::types::MountedContentPlacementEvidence) -> Value {
    match evidence {
        crate::types::MountedContentPlacementEvidence::SparseHole => {
            json!({"state": "sparse-hole"})
        }
        #[cfg(feature = "distributed-repair")]
        crate::types::MountedContentPlacementEvidence::ReceiptVerified { generation, .. } => {
            json!({"state": "receipt-verified", "generation": generation})
        }
        crate::types::MountedContentPlacementEvidence::ReceiptObservedButUnbound { generation } => {
            json!({
                "state": "receipt-observed-but-unbound",
                "generation": generation,
            })
        }
        crate::types::MountedContentPlacementEvidence::ReceiptMissing {
            expected_generation,
        } => json!({
            "state": "receipt-missing",
            "expected_generation": expected_generation,
        }),
        crate::types::MountedContentPlacementEvidence::ReceiptStale {
            expected_generation,
            observed_generation,
        } => json!({
            "state": "receipt-stale",
            "expected_generation": expected_generation,
            "observed_generation": observed_generation,
        }),
        crate::types::MountedContentPlacementEvidence::ReceiptUnavailable {
            expected_generation,
        } => json!({
            "state": "receipt-unavailable",
            "expected_generation": expected_generation,
        }),
    }
}

fn mounted_scrub_finding_json(
    report: &crate::scrub::ScrubReport,
    violation: &crate::scrub::ScrubViolation,
) -> Value {
    let (kind, chunk_index) = mounted_scrub_block_kind(violation.block_id.kind);
    let evidence = report.block_evidence.get(&violation.block_id);
    let outcome = match &violation.outcome {
        crate::scrub::ScrubBlockOutcome::Clean => json!({"kind": "clean"}),
        crate::scrub::ScrubBlockOutcome::Corrupt { expected, actual } => json!({
            "kind": "corrupt",
            "expected_checksum": mounted_scrub_digest(*expected),
            "actual_checksum": mounted_scrub_digest(*actual),
        }),
        crate::scrub::ScrubBlockOutcome::Unreadable(reason) => json!({
            "kind": "unreadable",
            "reason": reason,
        }),
        crate::scrub::ScrubBlockOutcome::NoChecksum => json!({"kind": "no-checksum"}),
    };
    let checksum = evidence
        .and_then(|entry| entry.checksum_layer.as_ref())
        .map(|checksum| {
            json!({
                "layer": mounted_scrub_checksum_layer(checksum.layer),
                "expected": checksum.expected.map(mounted_scrub_digest),
                "actual": mounted_scrub_digest(checksum.actual),
                "encoded_len": checksum.encoded_len,
                "matches": checksum.matches_expected(),
            })
        });
    let placement = evidence.map(|entry| mounted_scrub_placement_json(&entry.placement_evidence));

    json!({
        "block_id": {
            "inode_id": violation.block_id.inode_id,
            "data_version": violation.block_id.data_version,
            "kind": kind,
            "chunk_index": chunk_index,
        },
        "object_key": evidence
            .and_then(|entry| entry.raw_media_diagnostic.object_key_hex.as_deref())
            .unwrap_or(violation.key_hex.as_str()),
        "outcome": outcome,
        "plaintext": {
            "expected_len": evidence.map(|entry| entry.plaintext_identity.expected_plaintext_len),
            "observed_len": evidence.and_then(|entry| entry.plaintext_identity.observed_plaintext_len),
        },
        "checksum": checksum,
        "placement": placement,
        "media_reason": evidence.and_then(|entry| entry.raw_media_diagnostic.reason.as_deref()),
    })
}

fn mounted_scrub_finding_text(violation: &crate::scrub::ScrubViolation) -> String {
    let (kind, chunk_index) = mounted_scrub_block_kind(violation.block_id.kind);
    let block = chunk_index.map_or_else(
        || kind.to_string(),
        |chunk_index| format!("{kind}[{chunk_index}]"),
    );
    let outcome = match &violation.outcome {
        crate::scrub::ScrubBlockOutcome::Clean => "clean".to_string(),
        crate::scrub::ScrubBlockOutcome::Corrupt { expected, actual } => format!(
            "corrupt expected={} actual={}",
            mounted_scrub_digest(*expected),
            mounted_scrub_digest(*actual),
        ),
        crate::scrub::ScrubBlockOutcome::Unreadable(reason) => {
            format!("unreadable reason={reason}")
        }
        crate::scrub::ScrubBlockOutcome::NoChecksum => "no-checksum".to_string(),
    };
    format!(
        "inode={} data_version={} block={} object={} outcome={}",
        violation.block_id.inode_id,
        violation.block_id.data_version,
        block,
        violation.key_hex,
        outcome,
    )
}

impl SharedPoolDatasetOwner {
    fn live_pool_get(&self, args: &Value) -> LivePoolAdminResponse {
        let property = match live_admin_arg(args, "property") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let registry = tidefs_dataset_properties::build_registry();
        let key = tidefs_dataset_properties::PropertyKey::new(property);
        let Some(def) = tidefs_dataset_properties::lookup_property(&registry, &key) else {
            return live_admin_error(1, format!("pool get: unknown property '{property}'"));
        };
        let fs = self.borrow();
        match fs.pool_properties().get(&key) {
            Some(entry) => live_admin_ok_text(format!(
                "property:  {property}\nvalue:     {}\nsource:    {}",
                entry.value, entry.source
            )),
            None => live_admin_ok_text(format!(
                "property:  {property}\nvalue:     {}\nsource:    default",
                def.default_value
            )),
        }
    }

    fn live_pool_set(&self, args: &Value) -> LivePoolAdminResponse {
        let assignment = match live_admin_arg(args, "assignment") {
            Ok(value) => value,
            Err(err) => return live_admin_error(2, err),
        };
        let (prop_name, prop_val_str) = match assignment.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => {
                return live_admin_error(
                    1,
                    format!("pool set: invalid assignment '{assignment}' (expected key=value)"),
                )
            }
        };
        if prop_name.is_empty() {
            return live_admin_error(1, "pool set: property name must not be empty");
        }

        let registry = tidefs_dataset_properties::build_registry();
        let key = tidefs_dataset_properties::PropertyKey::new(prop_name);
        let def = match tidefs_dataset_properties::lookup_property(&registry, &key) {
            Some(def) => def,
            None => {
                return live_admin_error(1, format!("pool set: unknown property '{prop_name}'"))
            }
        };
        let is_clear = prop_val_str.is_empty() || prop_val_str == "-";
        let value = if is_clear {
            tidefs_dataset_properties::PropertyValue::None
        } else {
            tidefs_dataset_properties::PropertySet::parse_value_from_str(prop_val_str)
        };

        let mut fs = self.borrow_mut();
        if let Err(err) =
            tidefs_dataset_properties::validate_set(&key, &value, def, fs.pool_properties())
        {
            return live_admin_error(1, format!("pool set: validation failed: {err}"));
        }
        let mut props = fs.pool_properties().clone();
        if is_clear {
            props.remove_local_override(&key);
        } else {
            props.set_local(key.clone(), value.clone());
        }
        let pool_properties = match fs.pool_properties_mut() {
            Ok(properties) => properties,
            Err(err) => {
                return live_admin_error(1, format!("pool set: mutation requires reopen: {err}"))
            }
        };
        pool_properties.clone_from(&props);
        if let Err(err) = fs.persist_pool_properties() {
            return live_admin_error(
                1,
                format!("pool set: property set but persist failed: {err}"),
            );
        }
        if is_clear {
            live_admin_ok_text(format!(
                "cleared '{prop_name}' (now using default/inherited value)"
            ))
        } else {
            live_admin_ok_text(format!("{prop_name} = {value}"))
        }
    }

    fn live_pool_list_props(&self, args: &Value) -> LivePoolAdminResponse {
        let family = live_admin_optional_arg(args, "family");
        let fs = self.borrow();
        live_property_table("pool list-props", fs.pool_properties(), family)
    }

    fn live_pool_scrub(&self, pool: &str, wants_json: bool) -> LivePoolAdminResponse {
        let fs = self.borrow();
        let report = match fs.scrub_mounted_content() {
            Ok(report) => report,
            Err(err) => {
                let message = format!("pool scrub: mounted content scan failed: {err}");
                if wants_json {
                    return live_admin_report_json(
                        1,
                        json!({
                            "pool": pool,
                            "pass": false,
                            "state_source": "live-owner",
                            "owner_state": "mounted PoolDatasetOwner",
                            "repair_attempted": false,
                            "repair_writeback": false,
                            "blocks_scanned": 0,
                            "blocks_clean": 0,
                            "blocks_corrupt": 0,
                            "blocks_unreadable": 0,
                            "blocks_no_checksum": 0,
                            "findings": [],
                            "scan_error": message,
                        }),
                    );
                }
                return live_admin_report_text(
                    1,
                    format!(
                        "pool scrub: {pool}\n  source:      live owner (mounted PoolDatasetOwner)\n  pass:        no\n  repair:      not attempted\n  scan error:  {message}"
                    ),
                );
            }
        };
        let pass = report.is_clean() && report.blocks_no_checksum == 0;

        if wants_json {
            let findings = report
                .violations
                .iter()
                .map(|violation| mounted_scrub_finding_json(&report, violation))
                .collect::<Vec<_>>();
            let output = json!({
                "pool": pool,
                "pass": pass,
                "state_source": "live-owner",
                "owner_state": "mounted PoolDatasetOwner",
                "repair_attempted": false,
                "repair_writeback": false,
                "blocks_scanned": report.blocks_scanned,
                "blocks_clean": report.blocks_clean,
                "blocks_corrupt": report.blocks_corrupt,
                "blocks_unreadable": report.blocks_unreadable,
                "blocks_no_checksum": report.blocks_no_checksum,
                "findings": findings,
            });
            return if pass {
                live_admin_ok_json(output)
            } else {
                live_admin_report_json(1, output)
            };
        }

        let mut output = format!(
            "pool scrub: {pool}\n  source:      live owner (mounted PoolDatasetOwner)\n  pass:        {}\n  repair:      not attempted\n  blocks:      scanned={} clean={} corrupt={} unreadable={} no-checksum={}\n  findings:    {}",
            if pass { "yes" } else { "no" },
            report.blocks_scanned,
            report.blocks_clean,
            report.blocks_corrupt,
            report.blocks_unreadable,
            report.blocks_no_checksum,
            report.violations.len(),
        );
        for violation in &report.violations {
            let _ = write!(output, "\n    - {}", mounted_scrub_finding_text(violation));
        }
        if report.blocks_no_checksum > 0 {
            let _ = write!(
                output,
                "\n    - {} scanned block(s) had no applicable checksum",
                report.blocks_no_checksum,
            );
        }
        if pass {
            live_admin_ok_text(output)
        } else {
            live_admin_report_text(1, output)
        }
    }

    fn live_pool_integrity_check(
        &self,
        pool: &str,
        args: &Value,
        wants_json: bool,
    ) -> LivePoolAdminResponse {
        let max_records = args.get("max_records").and_then(Value::as_u64);
        let max_bytes = args.get("max_bytes").and_then(Value::as_u64);
        let backing_dir_arg = live_admin_optional_arg(args, "backing_dir").map(ToString::to_string);
        let device_arg_count = args
            .get("devices")
            .and_then(Value::as_array)
            .map(|devices| {
                devices
                    .iter()
                    .filter(|value| value.as_str().is_some_and(|path| !path.is_empty()))
                    .count()
            })
            .unwrap_or(0);

        let mut fs = self.borrow_mut();
        let verifier = mounted_canonical_verifier_report(&mut fs);
        let statfs = fs.statfs();
        let fs_stats = fs.stats();
        let suspect_stats = fs.suspect_log_stats();
        let intent_log_pending = fs.intent_log_pending();
        let pass = verifier.passed()
            && !verifier.production_fsck_required
            && suspect_stats.unresolved == 0
            && statfs.is_ok();

        if wants_json {
            let selected_root = verifier.selected_root.as_ref().map(|root| {
                json!({
                    "slot": root.slot,
                    "transaction_id": root.transaction_id,
                    "generation": root.generation,
                    "next_inode_id": root.next_inode_id,
                    "inode_count": root.inode_count,
                    "has_transaction_manifest": root.has_transaction_manifest,
                    "manifest_entry_count": root.manifest_entry_count,
                    "has_root_authentication": root.has_root_authentication,
                })
            });
            let issues: Vec<_> = verifier
                .issues
                .iter()
                .map(|issue| {
                    json!({
                        "severity": issue.severity.human_name(),
                        "kind": issue.kind.human_name(),
                        "slot": issue.slot,
                        "transaction_id": issue.transaction_id,
                        "generation": issue.generation,
                        "reason": &issue.reason,
                    })
                })
                .collect();
            let statfs_report = match &statfs {
                Ok(statfs) => json!({
                    "available": true,
                    "blocks": statfs.blocks,
                    "bfree": statfs.bfree,
                    "bavail": statfs.bavail,
                    "files": statfs.files,
                    "ffree": statfs.ffree,
                    "bsize": statfs.bsize,
                    "frsize": statfs.frsize,
                    "namelen": statfs.namelen,
                    "fsid_hi": statfs.fsid_hi,
                    "fsid_lo": statfs.fsid_lo,
                }),
                Err(error) => json!({
                    "available": false,
                    "error": error.to_string(),
                }),
            };

            let report = json!({
                "pool": pool,
                "pass": pass,
                "state_source": "live-owner",
                "owner_state": "mounted PoolDatasetOwner",
                "offline_inputs_ignored": backing_dir_arg.is_some() || device_arg_count > 0,
                "requested_limits": {
                    "max_records": max_records,
                    "max_bytes": max_bytes,
                    "applied": false,
                    "reason": "current live verifier API is full-scope",
                },
                "offline_inputs": {
                    "backing_dir": backing_dir_arg,
                    "device_count": device_arg_count,
                },
                "verifier": {
                    "outcome": verifier.outcome.human_name(),
                    "root_slot_count": verifier.root_slot_count,
                    "root_slots_seen": verifier.root_slots_seen,
                    "root_slot_records_seen": verifier.root_slot_records_seen,
                    "root_candidates_seen": verifier.root_candidates_seen,
                    "verified_committed_roots": verifier.verified_committed_roots.len(),
                    "invalid_root_candidates": verifier.invalid_root_candidates,
                    "checked_transaction_manifests": verifier.checked_transaction_manifests,
                    "checked_content_objects": verifier.checked_content_objects,
                    "checked_content_chunks": verifier.checked_content_chunks,
                    "verified_snapshot_roots": verifier.verified_snapshot_roots,
                    "production_fsck_required": verifier.production_fsck_required,
                    "mutating_repair_attempted": verifier.mutating_repair_attempted,
                    "selected_root": selected_root,
                    "issues": issues,
                },
                "statfs": statfs_report,
                "filesystem": {
                    "inode_count": fs_stats.inode_count,
                    "directory_count": fs_stats.directory_count,
                    "file_count": fs_stats.file_count,
                    "symlink_count": fs_stats.symlink_count,
                    "snapshot_count": fs_stats.snapshot_count,
                    "next_inode_id": fs_stats.next_inode_id,
                    "generation": fs_stats.filesystem_generation,
                    "intent_log_pending": intent_log_pending,
                },
                "object_store": {
                    "live_objects": fs_stats.object_store.live_objects,
                    "live_bytes": fs_stats.object_store.live_bytes,
                    "segment_count": fs_stats.object_store.segment_count,
                    "free_segments": fs_stats.object_store.free_segments,
                    "free_bytes": fs_stats.object_store.free_bytes,
                    "next_sequence": fs_stats.object_store.next_sequence,
                    "tombstone_count": fs_stats.object_store.tombstone_count,
                    "mirror_degraded": fs_stats.object_store.mirror_degraded,
                    "mirror_live_objects": fs_stats.object_store.mirror_live_objects,
                    "mirror_live_bytes": fs_stats.object_store.mirror_live_bytes,
                    "replica_healthy": fs_stats.object_store.replica_healthy,
                    "replica_live_objects": fs_stats.object_store.replica_live_objects,
                    "last_scrub_secs": fs_stats.object_store.last_scrub_secs,
                    "committed_root_txg": fs_stats.object_store.committed_root_txg,
                    "committed_root_generation": fs_stats.object_store.committed_root_generation,
                },
                "suspect_log": {
                    "total_entries": suspect_stats.total_entries,
                    "unresolved": suspect_stats.unresolved,
                    "resolved": suspect_stats.resolved,
                    "oldest_unresolved_age": suspect_stats.oldest_unresolved_age,
                },
            });
            return if pass {
                live_admin_ok_json(report)
            } else {
                live_admin_report_json(1, report)
            };
        }

        let statfs_summary = match &statfs {
            Ok(statfs) => format!(
                "blocks={} free={} avail={}",
                statfs.blocks, statfs.bfree, statfs.bavail,
            ),
            Err(error) => format!("unavailable ({error})"),
        };
        let mut out = format!(
            "pool integrity-check: {pool}\n  source:        live owner (mounted PoolDatasetOwner)\n  pass:          {}\n  verifier:      {}\n  roots:         verified={} candidates={} invalid={}\n  objects:       checked={} chunks={}\n  suspect-log:   unresolved={} total={}\n  intent-log:    pending={}\n  statfs:        {}\n  inodes:        count={} next={}\n  object-store:  live_objects={} live_bytes={} segments={}",
            if pass { "yes" } else { "no" },
            verifier.outcome.human_name(),
            verifier.verified_committed_roots.len(),
            verifier.root_candidates_seen,
            verifier.invalid_root_candidates,
            verifier.checked_content_objects,
            verifier.checked_content_chunks,
            suspect_stats.unresolved,
            suspect_stats.total_entries,
            intent_log_pending,
            statfs_summary,
            fs_stats.inode_count,
            fs_stats.next_inode_id,
            fs_stats.object_store.live_objects,
            fs_stats.object_store.live_bytes,
            fs_stats.object_store.segment_count,
        );
        if backing_dir_arg.is_some() || device_arg_count > 0 {
            let _ = write!(
                out,
                "\n  offline args: ignored by live owner (backing_dir={} devices={device_arg_count})",
                backing_dir_arg.as_deref().unwrap_or("-"),
            );
        }
        if max_records.is_some() || max_bytes.is_some() {
            let _ = write!(
                out,
                "\n  limits:       requested max_records={} max_bytes={} (not applied; live verifier is full-scope)",
                max_records
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                max_bytes
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        if verifier.production_fsck_required {
            out.push_str("\n  recovery:     production fsck/operator repair required");
        }
        if !verifier.issues.is_empty() {
            out.push_str("\n  issues:");
            for issue in verifier.issues.iter().take(8) {
                let _ = write!(
                    out,
                    "\n    {} {}: {}",
                    issue.severity.human_name(),
                    issue.kind.human_name(),
                    issue.reason
                );
            }
            if verifier.issues.len() > 8 {
                let _ = write!(out, "\n    ... {} more", verifier.issues.len() - 8);
            }
        }
        if pass {
            live_admin_ok_text(out)
        } else {
            live_admin_report_text(1, out)
        }
    }
    /// Serve bounded Pool-wide administration through the one already-open
    /// mounted owner, without routing through VFS semantics.
    pub fn handle_live_pool_owner_admin_request(
        &self,
        request: &LivePoolAdminRequest,
    ) -> LivePoolAdminResponse {
        if let Err(err) = request.validate_version() {
            return live_admin_typed_error(err);
        }

        let args = live_admin_args_to_json(&request.args);
        let wants_json = request.output.wants_json();
        match request.command {
            LivePoolAdminCommand::PoolGet => self.live_pool_get(&args),
            LivePoolAdminCommand::PoolSet => self.live_pool_set(&args),
            LivePoolAdminCommand::PoolListProps => self.live_pool_list_props(&args),
            LivePoolAdminCommand::PoolIntegrityCheck => {
                self.live_pool_integrity_check(&request.pool, &args, wants_json)
            }
            LivePoolAdminCommand::PoolScrub => self.live_pool_scrub(&request.pool, wants_json),
            LivePoolAdminCommand::PoolRepair => self.live_pool_repair(&request.pool, wants_json),
            LivePoolAdminCommand::DeviceStatus => self.live_device_status(wants_json),
            LivePoolAdminCommand::DeviceOffline => {
                self.live_device_administrative_state(&args, wants_json, true)
            }
            LivePoolAdminCommand::DeviceOnline => {
                self.live_device_administrative_state(&args, wants_json, false)
            }
            LivePoolAdminCommand::DeviceRemove => self.live_device_remove(&args, wants_json),
            LivePoolAdminCommand::DeviceReplace => self.live_device_replace(&args, wants_json),
            LivePoolAdminCommand::DeviceRebuild => self.live_device_rebuild(&args, wants_json),
            command => {
                let (command_name, operation) = command.parts();
                live_admin_typed_error(LivePoolAdminError::unsupported_command(
                    command_name,
                    operation,
                ))
            }
        }
    }

    fn live_device_status(&self, wants_json: bool) -> LivePoolAdminResponse {
        let fs = self.borrow();
        let topology = fs.store.pool().topology_status();
        let replacement = fs.store.pool().device_replacement_result();
        let state_name = |state| match state {
            tidefs_local_object_store::pool::ReplacementRebuildStatusState::Pending => "pending",
            tidefs_local_object_store::pool::ReplacementRebuildStatusState::Resuming => "resuming",
            tidefs_local_object_store::pool::ReplacementRebuildStatusState::Completed => {
                "completed"
            }
            tidefs_local_object_store::pool::ReplacementRebuildStatusState::Refused => "refused",
        };
        let guid = |value: &[u8; 16]| {
            value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };

        if wants_json {
            let members = topology
                .members
                .iter()
                .map(|member| {
                    json!({
                        "device_index": member.device_index,
                        "device_guid": guid(&member.device_guid),
                        "present": member.present,
                        "operational_state": member.operational_state.map(|state| format!("{state:?}")),
                    })
                })
                .collect::<Vec<_>>();
            let replacement = replacement.map(|result| {
                json!({
                    "state": state_name(result.state),
                    "old_device_path": result.old_path.display().to_string(),
                    "new_device_path": result.new_path.display().to_string(),
                    "old_device_guid": guid(&result.old_device_guid),
                    "new_device_guid": guid(&result.new_device_guid),
                    "topology_generation": result.topology_generation,
                    "objects_total": result.objects_total,
                    "objects_rebuilt": result.objects_rebuilt,
                    "objects_failed": result.objects_failed,
                    "verified_receipt_count": result.verified_receipt_count,
                    "bytes_rebuilt": result.bytes_rebuilt,
                    "topology_commit_pending": result.topology_commit_pending,
                    "complete": result.complete,
                    "old_device_detach_allowed": result.detach_decision.is_safe(),
                    "media_privacy_claimed": false,
                    "secure_erase_claimed": false,
                    "sanitization_claimed": false,
                    "decommissioning_claimed": false,
                })
            });
            return LivePoolAdminResponse::ok_machine_json(
                json!({
                    "health": format!("{:?}", topology.health),
                    "access": if topology.read_only { "ReadOnly" } else { "ReadWrite" },
                    "members_expected": topology.expected_members,
                    "members_present": topology.present_members,
                    "members_missing": topology.missing_members,
                    "members": members,
                    "replacement": replacement,
                })
                .to_string(),
            );
        }

        let mut message = format!(
            "device status: health={:?} access={} members_expected={} members_present={} members_missing={}",
            topology.health,
            if topology.read_only { "ReadOnly" } else { "ReadWrite" },
            topology.expected_members,
            topology.present_members,
            topology.missing_members,
        );
        if let Some(result) = replacement {
            let _ = write!(
                message,
                "\n  replacement: state={} old={} ({}) new={} ({}) objects={}/{} failed={} verified_receipts={} bytes={} topology_generation={} topology_commit_pending={} old_device_detach_allowed={}\n  remanence: media_privacy=false secure_erase=false sanitization=false decommissioning=false",
                state_name(result.state),
                result.old_path.display(),
                guid(&result.old_device_guid),
                result.new_path.display(),
                guid(&result.new_device_guid),
                result.objects_rebuilt,
                result.objects_total,
                result.objects_failed,
                result.verified_receipt_count,
                result.bytes_rebuilt,
                result.topology_generation,
                result.topology_commit_pending,
                result.detach_decision.is_safe(),
            );
        } else {
            message.push_str("\n  replacement: none");
        }
        for member in &topology.members {
            let _ = write!(
                message,
                "\n  member[{}]: guid={} present={} state={}",
                member.device_index,
                guid(&member.device_guid),
                member.present,
                member
                    .operational_state
                    .map(|state| format!("{state:?}"))
                    .unwrap_or_else(|| "Missing".to_string()),
            );
        }
        live_admin_ok_text(message)
    }

    fn live_device_administrative_state(
        &self,
        args: &Value,
        wants_json: bool,
        offline: bool,
    ) -> LivePoolAdminResponse {
        let operation = if offline { "offline" } else { "online" };
        let device_guid = match live_admin_arg(args, "device_guid").and_then(live_admin_exact_guid)
        {
            Ok(value) => value,
            Err(error) => {
                return live_admin_error(2, format!("device {operation}: {error}"));
            }
        };
        let guid_hex = live_admin_hex_encode(&device_guid);
        if let Err(error) = self
            .borrow()
            .ensure_mutation_allowed("change mounted Pool device availability")
        {
            return live_admin_error(
                1,
                format!("device {operation}: mutation requires a writable owner: {error}"),
            );
        }

        let mut fs = self.borrow_mut();
        if offline {
            if let Err(error) = fs.sync_all() {
                return live_admin_error(
                    1,
                    format!(
                        "device offline: could not sync mounted filesystem state before excluding {guid_hex}: {error}"
                    ),
                );
            }
        }
        let result = if offline {
            fs.store.pool_mut().device_offline(device_guid)
        } else {
            fs.store.pool_mut().device_online(device_guid)
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                let message =
                    format!("device {operation}: Pool owner refused member {guid_hex}: {error}");
                return if wants_json {
                    LivePoolAdminResponse::error_machine_json(
                        1,
                        message.clone(),
                        json!({
                            "status": "refused",
                            "operation": operation,
                            "device_guid": guid_hex,
                            "message": message,
                        })
                        .to_string(),
                    )
                } else {
                    live_admin_error(1, message)
                };
            }
        };
        let state = format!("{:?}", result.state);
        let health = format!("{:?}", result.pool_health);
        let message = format!(
            "device {operation}: member {} at durable index {} is {} (pool_health={}, topology_generation={}, verified_receipts={})",
            guid_hex,
            result.device_index,
            state,
            health,
            result.topology_generation,
            result.verified_receipts,
        );
        if wants_json {
            LivePoolAdminResponse::ok_machine_json(
                json!({
                    "status": "completed",
                    "operation": operation,
                    "device_guid": guid_hex,
                    "device_index": result.device_index,
                    "operational_state": state,
                    "pool_health": health,
                    "topology_generation": result.topology_generation,
                    "verified_receipts": result.verified_receipts,
                    "message": message,
                })
                .to_string(),
            )
        } else {
            live_admin_ok_text(message)
        }
    }

    fn live_device_replace(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let old_device_path = match live_admin_arg(args, "old_device_path") {
            Ok(value) => std::path::PathBuf::from(value),
            Err(err) => return live_admin_error(2, err),
        };
        let new_device_path = match live_admin_arg(args, "new_device_path") {
            Ok(value) => std::path::PathBuf::from(value),
            Err(err) => return live_admin_error(2, err),
        };
        let guid = |value: &[u8; 16]| {
            value
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let refusal = |exit_code: i32,
                       message: String,
                       evidence: Option<
            tidefs_local_object_store::pool::DeviceReplacementResult,
        >| {
            if wants_json {
                let old_device_guid = evidence
                    .as_ref()
                    .map(|result| guid(&result.old_device_guid));
                let new_device_guid = evidence
                    .as_ref()
                    .map(|result| guid(&result.new_device_guid));
                let topology_generation =
                    evidence.as_ref().map(|result| result.topology_generation);
                return LivePoolAdminResponse::error_machine_json(
                    exit_code,
                    message.clone(),
                    json!({
                        "status": "refused",
                        "old_device_path": old_device_path.display().to_string(),
                        "new_device_path": new_device_path.display().to_string(),
                        "old_device_guid": old_device_guid,
                        "new_device_guid": new_device_guid,
                        "topology_generation": topology_generation,
                        "topology_committed": false,
                        "old_device_detach_allowed": false,
                        "media_privacy_claimed": false,
                        "secure_erase_claimed": false,
                        "sanitization_claimed": false,
                        "decommissioning_claimed": false,
                        "message": message,
                    })
                    .to_string(),
                );
            }
            live_admin_error(exit_code, message)
        };
        if old_device_path == new_device_path {
            return refusal(
                2,
                "device replace: old and new device paths must differ".to_string(),
                None,
            );
        }
        if let Err(err) = self
            .borrow()
            .ensure_mutation_allowed("replace mounted pool device")
        {
            let evidence = self.borrow().store.pool().device_replacement_result();
            return refusal(
                1,
                format!("device replace: mutation requires reopen: {err}"),
                evidence,
            );
        }

        let mut fs = self.borrow_mut();
        // A reopened replacement is deliberately generation-fenced until Pool
        // reattaches the exact recorded candidate or finishes terminal
        // evidence for an already-published topology. Resume that Pool
        // boundary first; the mounted replacement path below then reconciles
        // authenticated roots and syncs them before terminal publication.
        // Fresh replacement still requires the ordinary pre-rebuild mounted
        // sync.
        let replacement_resume = fs.store.pool().has_device_replacement_resume();
        if !replacement_resume {
            if let Err(err) = fs.sync_all() {
                let evidence = fs.store.pool().device_replacement_result();
                return refusal(
                    1,
                    format!(
                        "device replace: could not sync mounted filesystem state before rebuilding '{}': {err}",
                        old_device_path.display()
                    ),
                    evidence,
                );
            }
        }
        let result =
            match fs.complete_mounted_device_replacement(&old_device_path, &new_device_path) {
                Ok(result) => result,
                Err(err) => {
                    let evidence = fs.store.pool().device_replacement_result();
                    return refusal(
                        1,
                        format!(
                    "device replace: mounted pool owner could not replace '{}' with '{}': {err}",
                    old_device_path.display(),
                    new_device_path.display()
                ),
                        evidence,
                    );
                }
            };
        if !result.complete || result.objects_failed > 0 {
            let message = format!(
                "device replace: rebuild remains incomplete; old member '{}' remains attached and no replacement topology was committed (objects_rebuilt={}, objects_total={}, objects_failed={}, verified_receipts={}, bytes_rebuilt={})",
                old_device_path.display(),
                result.objects_rebuilt,
                result.objects_total,
                result.objects_failed,
                result.verified_receipt_count,
                result.bytes_rebuilt,
            );
            return if wants_json {
                LivePoolAdminResponse::error_machine_json(
                    1,
                    message,
                    json!({
                        "status": "incomplete",
                        "old_device_path": old_device_path.display().to_string(),
                        "new_device_path": new_device_path.display().to_string(),
                        "old_device_guid": guid(&result.old_device_guid),
                        "new_device_guid": guid(&result.new_device_guid),
                        "objects_rebuilt": result.objects_rebuilt,
                        "objects_total": result.objects_total,
                        "objects_failed": result.objects_failed,
                        "verified_receipt_count": result.verified_receipt_count,
                        "bytes_rebuilt": result.bytes_rebuilt,
                        "topology_committed": false,
                        "old_device_detach_allowed": false,
                    })
                    .to_string(),
                )
            } else {
                live_admin_error(1, message)
            };
        }

        let message = format!(
            "device replace: replaced '{}' ({}) with '{}' ({}) after receipt-backed rebuild and durable same-cardinality topology commit (objects_rebuilt={}, verified_receipts={}, bytes_rebuilt={}, topology_generation={}); old-device detach is allowed, but this does not establish secure erase, media-remanence, sanitization, or decommissioning guarantees",
            old_device_path.display(),
            guid(&result.old_device_guid),
            new_device_path.display(),
            guid(&result.new_device_guid),
            result.objects_rebuilt,
            result.verified_receipt_count,
            result.bytes_rebuilt,
            result.topology_generation,
        );
        if wants_json {
            LivePoolAdminResponse::ok_machine_json(
                json!({
                    "status": "completed",
                    "old_device_path": old_device_path.display().to_string(),
                    "new_device_path": new_device_path.display().to_string(),
                    "old_device_guid": guid(&result.old_device_guid),
                    "new_device_guid": guid(&result.new_device_guid),
                    "objects_total": result.objects_total,
                    "objects_rebuilt": result.objects_rebuilt,
                    "objects_failed": result.objects_failed,
                    "verified_receipt_count": result.verified_receipt_count,
                    "bytes_rebuilt": result.bytes_rebuilt,
                    "topology_generation": result.topology_generation,
                    "topology_committed": true,
                    "old_device_detach_allowed": true,
                    "media_privacy_claimed": false,
                    "secure_erase_claimed": false,
                    "sanitization_claimed": false,
                    "decommissioning_claimed": false,
                    "message": message,
                })
                .to_string(),
            )
        } else {
            live_admin_ok_text(message)
        }
    }

    fn live_device_rebuild(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        let missing_device_guid =
            match live_admin_arg(args, "missing_device_guid").and_then(live_admin_exact_guid) {
                Ok(value) => value,
                Err(err) => return live_admin_error(2, format!("device rebuild: {err}")),
            };
        let new_device_path = match live_admin_arg(args, "new_device_path") {
            Ok(value) => std::path::PathBuf::from(value),
            Err(err) => return live_admin_error(2, format!("device rebuild: {err}")),
        };
        let missing_guid_hex = live_admin_hex_encode(&missing_device_guid);
        let refusal = |exit_code: i32,
                       message: String,
                       evidence: Option<
            tidefs_local_object_store::pool::DeviceReplacementResult,
        >| {
            if wants_json {
                return LivePoolAdminResponse::error_machine_json(
                    exit_code,
                    message.clone(),
                    json!({
                        "status": "refused",
                        "recovery_mode": "device-rebuild-only",
                        "namespace_read_only": true,
                        "missing_device_guid": missing_guid_hex,
                        "new_device_path": new_device_path.display().to_string(),
                        "durable_device_index": evidence.as_ref().map(|result| result.device_index),
                        "new_device_guid": evidence.as_ref().map(|result| live_admin_hex_encode(&result.new_device_guid)),
                        "objects_total": evidence.as_ref().map(|result| result.objects_total),
                        "objects_rebuilt": evidence.as_ref().map(|result| result.objects_rebuilt),
                        "objects_failed": evidence.as_ref().map(|result| result.objects_failed),
                        "verified_receipt_count": evidence.as_ref().map(|result| result.verified_receipt_count),
                        "bytes_rebuilt": evidence.as_ref().map(|result| result.bytes_rebuilt),
                        "topology_generation": evidence.as_ref().map(|result| result.topology_generation),
                        "topology_committed": false,
                        "message": message,
                    })
                    .to_string(),
                );
            }
            let evidence = evidence.as_ref();
            live_admin_error(
                exit_code,
                format!(
                    "{message} (recovery_mode=device-rebuild-only, missing_device_guid={missing_guid_hex}, new_device_path='{}', durable_device_index={}, new_device_guid={}, objects_total={}, objects_rebuilt={}, objects_failed={}, verified_receipts={}, bytes_rebuilt={}, topology_generation={}, topology_committed=false, namespace_read_only=true)",
                    new_device_path.display(),
                    evidence
                        .map(|result| result.device_index.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| live_admin_hex_encode(&result.new_device_guid))
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.objects_total.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.objects_rebuilt.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.objects_failed.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.verified_receipt_count.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.bytes_rebuilt.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    evidence
                        .map(|result| result.topology_generation.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                ),
            )
        };

        {
            let fs = self.borrow();
            if !fs.filesystem.recovery_policy.allows_device_rebuild()
                || !fs.store.pool().is_read_only()
            {
                return refusal(
                    1,
                    "device rebuild: command requires an explicit --read-only --rebuild-only mounted owner"
                        .to_string(),
                    fs.store.pool().device_replacement_result(),
                );
            }
            let topology = fs.store.pool().topology_status();
            let exact_missing_member = topology
                .members
                .iter()
                .any(|member| !member.present && member.device_guid == missing_device_guid);
            // A crash can leave the successor roster durable while the
            // terminal lifecycle record is still pending. In that state the
            // roster names the new GUID, but the retry remains bound to the
            // operator's original missing GUID through the exact label
            // evidence. Admit only that one old/new/index transition.
            let successor_topology_resume = fs
                .store
                .pool()
                .device_replacement_result()
                .is_some_and(|evidence| {
                    !evidence.old_member_present
                        && !evidence.complete
                        && evidence.old_device_guid == missing_device_guid
                        && topology.members.iter().any(|member| {
                            !member.present
                                && member.device_index as usize == evidence.device_index
                                && member.device_guid == evidence.new_device_guid
                        })
                });
            if topology.expected_members != 2
                || topology.present_members != 1
                || topology.missing_members != 1
                || (!exact_missing_member && !successor_topology_resume)
            {
                return refusal(
                    1,
                    format!(
                        "device rebuild: GUID {missing_guid_hex} is not the one durable missing member of an exact two-member Pool"
                    ),
                    fs.store.pool().device_replacement_result(),
                );
            }
        }

        let mut fs = self.borrow_mut();
        let result = match fs
            .complete_mounted_missing_member_rebuild(missing_device_guid, &new_device_path)
        {
            Ok(result) => result,
            Err(err) => {
                let evidence = fs.store.pool().device_replacement_result();
                return refusal(
                    1,
                    format!(
                        "device rebuild: recovery-only mounted owner could not rebuild missing member {missing_guid_hex} onto '{}': {err}",
                        new_device_path.display(),
                    ),
                    evidence,
                );
            }
        };
        if !result.complete || result.objects_failed > 0 {
            let message = format!(
                "device rebuild: rebuild of missing member {} at durable index {} onto '{}' ({}) remains incomplete (recovery_mode=device-rebuild-only, objects_rebuilt={}, objects_total={}, objects_failed={}, verified_receipts={}, bytes_rebuilt={}, topology_generation={}, topology_committed=false, namespace_read_only=true)",
                missing_guid_hex,
                result.device_index,
                new_device_path.display(),
                live_admin_hex_encode(&result.new_device_guid),
                result.objects_rebuilt,
                result.objects_total,
                result.objects_failed,
                result.verified_receipt_count,
                result.bytes_rebuilt,
                result.topology_generation,
            );
            return if wants_json {
                LivePoolAdminResponse::error_machine_json(
                    1,
                    message.clone(),
                    json!({
                        "status": "incomplete",
                        "recovery_mode": "device-rebuild-only",
                        "namespace_read_only": true,
                        "missing_device_guid": missing_guid_hex,
                        "new_device_path": new_device_path.display().to_string(),
                        "new_device_guid": live_admin_hex_encode(&result.new_device_guid),
                        "durable_device_index": result.device_index,
                        "objects_total": result.objects_total,
                        "objects_rebuilt": result.objects_rebuilt,
                        "objects_failed": result.objects_failed,
                        "verified_receipt_count": result.verified_receipt_count,
                        "bytes_rebuilt": result.bytes_rebuilt,
                        "topology_generation": result.topology_generation,
                        "topology_committed": false,
                        "message": message,
                    })
                    .to_string(),
                )
            } else {
                live_admin_error(1, message)
            };
        }

        let message = format!(
            "device rebuild: rebuilt missing member {} at durable index {} onto '{}' ({}) through the recovery-only owner after durable same-cardinality topology commit (recovery_mode=device-rebuild-only, objects_rebuilt={}, objects_total={}, objects_failed={}, verified_receipts={}, bytes_rebuilt={}, topology_generation={}, topology_committed=true, namespace_read_only=true)",
            missing_guid_hex,
            result.device_index,
            new_device_path.display(),
            live_admin_hex_encode(&result.new_device_guid),
            result.objects_rebuilt,
            result.objects_total,
            result.objects_failed,
            result.verified_receipt_count,
            result.bytes_rebuilt,
            result.topology_generation,
        );
        if wants_json {
            LivePoolAdminResponse::ok_machine_json(
                json!({
                    "status": "completed",
                    "recovery_mode": "device-rebuild-only",
                    "namespace_read_only": true,
                    "missing_device_guid": missing_guid_hex,
                    "new_device_path": new_device_path.display().to_string(),
                    "new_device_guid": live_admin_hex_encode(&result.new_device_guid),
                    "durable_device_index": result.device_index,
                    "objects_total": result.objects_total,
                    "objects_rebuilt": result.objects_rebuilt,
                    "objects_failed": result.objects_failed,
                    "verified_receipt_count": result.verified_receipt_count,
                    "bytes_rebuilt": result.bytes_rebuilt,
                    "topology_generation": result.topology_generation,
                    "topology_committed": true,
                    "message": message,
                })
                .to_string(),
            )
        } else {
            live_admin_ok_text(message)
        }
    }

    fn live_device_remove(&self, args: &Value, wants_json: bool) -> LivePoolAdminResponse {
        if let Err(err) = self
            .borrow()
            .ensure_mutation_allowed("remove mounted pool device")
        {
            return live_admin_error(1, format!("device remove: mutation requires reopen: {err}"));
        }
        let device_path = match live_admin_arg(args, "device_path") {
            Ok(value) => std::path::PathBuf::from(value),
            Err(err) => return live_admin_error(2, err),
        };

        let force = args.get("force").and_then(Value::as_bool).unwrap_or(false);
        if force {
            return live_admin_error(
                1,
                "device remove: --force is not supported through the live owner; live removal must evacuate every object cleanly",
            );
        }

        let mut fs = self.borrow_mut();
        if let Err(err) = fs.sync_all() {
            return live_admin_error(
                1,
                format!(
                    "device remove: could not sync mounted filesystem state before evacuating '{}': {err}",
                    device_path.display()
                ),
            );
        }
        let result = match fs.complete_mounted_device_removal(&device_path) {
            Ok(result) => result,
            Err(err) => {
                return live_admin_error(
                    1,
                    format!(
                        "device remove: mounted pool owner could not remove '{}': {err}",
                        device_path.display()
                    ),
                )
            }
        };

        if !result.complete || result.objects_failed > 0 {
            let remaining_devices = fs.store.pool().stats().device_count;
            let machine = json!({
                "status": "evacuation_incomplete",
                "device_path": device_path.display().to_string(),
                "topology_committed": false,
                "marker_retained": true,
                "target_attached": true,
                "target_allocation_fenced": true,
                "objects_evacuated": result.objects_evacuated,
                "objects_failed": result.objects_failed,
                "bytes_evacuated": result.bytes_evacuated,
                "remaining_devices": remaining_devices,
                "action": "repair the reported object failures and retry; keep the target attached and do not decommission or treat it as removed",
            });
            let message = format!(
                "device remove: evacuation of '{}' did not complete; the target remains attached and allocation-fenced, the recovery marker remains durable, and no reduced topology was committed (objects_evacuated={}, objects_failed={}, bytes_evacuated={}, remaining_devices={})",
                device_path.display(),
                result.objects_evacuated,
                result.objects_failed,
                result.bytes_evacuated,
                remaining_devices,
            );
            return if wants_json {
                LivePoolAdminResponse::error_machine_json(1, message, machine.to_string())
            } else {
                live_admin_error(1, message)
            };
        }

        let topology_generation = fs.store.pool().placement_epoch();
        let remaining_devices = fs.store.pool().stats().device_count;
        let message = format!(
            "device remove: removed '{}' after receipt-backed evacuation and durable survivor topology commit (objects_evacuated={}, bytes_evacuated={}, topology_generation={}, remaining_devices={}); this does not establish secure erase, media-remanence, or decommissioning guarantees",
            device_path.display(),
            result.objects_evacuated,
            result.bytes_evacuated,
            topology_generation,
            remaining_devices,
        );
        if wants_json {
            LivePoolAdminResponse::ok_machine_json(
                json!({
                    "status": "removed",
                    "device_path": device_path.display().to_string(),
                    "topology_committed": true,
                    "topology_generation": topology_generation,
                    "objects_evacuated": result.objects_evacuated,
                    "objects_failed": result.objects_failed,
                    "bytes_evacuated": result.bytes_evacuated,
                    "remaining_devices": remaining_devices,
                    "remanence_guarantee": false,
                    "message": message,
                })
                .to_string(),
            )
        } else {
            live_admin_ok_text(message)
        }
    }
}

struct DeviceLifecycleFilesystemState {
    dataset_path: String,
    state: FileSystemState,
    root: RootCommitRecord,
    snapshots: Vec<DeviceLifecycleSnapshotState>,
}

struct DeviceLifecycleSnapshotState {
    name: Vec<u8>,
    dataset_id: DatasetId,
    previous_typed_root: tidefs_pool_runtime::SnapshotRoot,
    captured_state: FileSystemState,
    captured_root: RootCommitRecord,
}

struct DeviceLifecycleRootAuthority {
    unmounted_filesystems: Vec<DeviceLifecycleFilesystemState>,
    mounted_snapshots: Vec<DeviceLifecycleSnapshotState>,
}

struct RelocatedContentReceiptReplacement {
    record: InodeRecord,
    manifest: crate::records::ContentManifestObject,
    sparse: bool,
    old_manifest_key: ObjectKey,
}

impl PoolDatasetOwner {
    /// Complete a mounted device removal without invalidating the exact Pool
    /// receipt generations embedded in content manifests.
    pub(crate) fn complete_mounted_device_removal(
        &mut self,
        device_path: &std::path::Path,
    ) -> crate::Result<tidefs_local_object_store::device_removal::EvacuationResult> {
        let mut root_authority =
            self.ensure_device_lifecycle_root_authority("remove device from mounted pool")?;
        let preparation = self
            .store
            .pool_mut()
            .prepare_safe_remove_device(device_path)
            .map_err(FileSystemError::from);
        if preparation.is_err() && self.store.pool().pending_device_removal_path()?.is_none() {
            return preparation;
        }

        // Preparation can fail after one or more replacement receipts became
        // current. Always repair every valid manifest reference that can now
        // be advanced before returning the preparation error.
        self.reconcile_unmounted_filesystem_receipts(&mut root_authority.unmounted_filesystems)?;
        self.reconcile_mounted_snapshot_receipts(&mut root_authority.mounted_snapshots)?;
        self.reconcile_relocated_content_receipts()?;
        self.store.pool_mut().sync_all()?;

        // Receipt reconciliation copy-on-writes every changed content
        // manifest under a new inode data version and publishes that state in
        // one authenticated transaction. Replace every retained fallback root
        // slot before detach so none can name the predecessor generations.
        // Always turn the complete ring: a resumed removal may have crashed
        // after publishing only a prefix.
        for _ in 0..crate::constants::FILESYSTEM_ROOT_SLOT_COUNT {
            self.persist_dataset_catalog()?;
        }
        self.store.pool_mut().sync_all()?;

        let preparation = preparation?;
        if preparation.objects_failed > 0 {
            return Ok(preparation);
        }

        let result = self
            .store
            .pool_mut()
            .finish_safe_remove_device(device_path)?;
        self.store.pool_mut().sync_all()?;
        Ok(result)
    }

    /// Resume a marker-bound mounted removal before a reopened filesystem is
    /// exposed to namespace or content I/O.
    pub(crate) fn resume_pending_mounted_device_removal(
        &mut self,
    ) -> crate::Result<Option<tidefs_local_object_store::device_removal::EvacuationResult>> {
        let Some(device_path) = self.store.pool().pending_device_removal_path()? else {
            return Ok(None);
        };
        self.complete_mounted_device_removal(&device_path).map(Some)
    }

    /// Complete a receipt-backed mounted member replacement and publish the
    /// replacement topology only after every authenticated filesystem root
    /// slot refers to successor receipts.
    pub(crate) fn complete_mounted_device_replacement(
        &mut self,
        old_device_path: &std::path::Path,
        new_device_path: &std::path::Path,
    ) -> crate::Result<tidefs_local_object_store::pool::DeviceReplacementResult> {
        let mut root_authority =
            self.ensure_device_lifecycle_root_authority("replace device in mounted pool")?;
        let old_config = self
            .store
            .pool()
            .config()
            .devices
            .iter()
            .find(|config| config.path == old_device_path)
            .cloned()
            .ok_or(FileSystemError::Unsupported {
                operation: "replace device in mounted pool",
                reason: "the old device path is not an exact current Pool member",
            })?;
        let mut replacement_config = old_config;
        replacement_config.path = new_device_path.to_path_buf();
        replacement_config.kind = match replacement_config.kind {
            tidefs_local_object_store::DeviceKind::Block { .. } => {
                tidefs_local_object_store::DeviceKind::Block {
                    path: new_device_path.to_path_buf(),
                }
            }
            tidefs_local_object_store::DeviceKind::Single { .. } => {
                tidefs_local_object_store::DeviceKind::Single {
                    path: new_device_path.to_path_buf(),
                }
            }
            _ => {
                return Err(FileSystemError::Unsupported {
                    operation: "replace device in mounted pool",
                    reason: "mounted replacement supports only one byte-addressable member per device configuration",
                })
            }
        };

        let preparation = self.store.pool_mut().replace_device(
            old_device_path,
            replacement_config,
            &tidefs_local_object_store::StoreOptions::default(),
        );
        if preparation.as_ref().is_ok_and(|result| result.complete) {
            return preparation.map_err(FileSystemError::from);
        }
        if preparation.is_err() && self.store.pool().device_replacement_result().is_none() {
            return preparation.map_err(FileSystemError::from);
        }

        // Preparation may have published a prefix of successor receipts.
        // Reconcile every valid content manifest before propagating an error,
        // preserving the same predecessor-root recovery rule as removal.
        self.reconcile_unmounted_filesystem_receipts(&mut root_authority.unmounted_filesystems)?;
        self.reconcile_mounted_snapshot_receipts(&mut root_authority.mounted_snapshots)?;
        self.reconcile_relocated_content_receipts()?;
        self.store.pool_mut().sync_all()?;
        for _ in 0..crate::constants::FILESYSTEM_ROOT_SLOT_COUNT {
            self.persist_dataset_catalog()?;
        }
        self.store.pool_mut().sync_all()?;

        let preparation = preparation.map_err(FileSystemError::from)?;
        if preparation.objects_failed > 0 {
            return Ok(preparation);
        }
        let result = self
            .store
            .pool_mut()
            .finish_safe_replace_device(old_device_path)?;
        self.store.pool_mut().sync_all()?;
        self.rebuild_capacity_authority_from_committed_content()?;
        Ok(result)
    }

    /// Rebuild one absent member through the explicitly recovery-only owner.
    ///
    /// Root and retained-dataset authority is authenticated before the Pool
    /// capability is armed. The capability remains scoped to this call and is
    /// dropped on every returned success or error; the mounted namespace and
    /// all ordinary recovery mutation remain read-only throughout.
    pub(crate) fn complete_mounted_missing_member_rebuild(
        &mut self,
        missing_device_guid: [u8; 16],
        new_device_path: &std::path::Path,
    ) -> crate::Result<tidefs_local_object_store::pool::DeviceReplacementResult> {
        if !self.filesystem.recovery_policy.allows_device_rebuild()
            || !self.store.pool().is_read_only()
        {
            return Err(FileSystemError::Unsupported {
                operation: "rebuild missing mounted Pool member",
                reason: "missing-member rebuild requires an explicit recovery-only owner",
            });
        }
        let mut root_authority =
            self.ensure_device_lifecycle_root_authority("rebuild missing mounted Pool member")?;
        let survivor_config = self.store.pool().config().devices.first().cloned().ok_or(
            FileSystemError::Unsupported {
                operation: "rebuild missing mounted Pool member",
                reason: "recovery-only Pool has no surviving member configuration",
            },
        )?;
        if !matches!(
            survivor_config.kind,
            tidefs_local_object_store::DeviceKind::Block { .. }
        ) {
            return Err(FileSystemError::Unsupported {
                operation: "rebuild missing mounted Pool member",
                reason: "missing-member rebuild supports only byte-addressable Pool members",
            });
        }
        let replacement_backing = Self::byte_addressable_device_backing(new_device_path)?;
        if replacement_backing != survivor_config.backing {
            return Err(FileSystemError::Unsupported {
                operation: "rebuild missing mounted Pool member",
                reason: "missing-member rebuild candidate backing does not match the survivor",
            });
        }
        let mut replacement_config = survivor_config;
        replacement_config.path = new_device_path.to_path_buf();
        replacement_config.backing = replacement_backing;
        replacement_config.kind = tidefs_local_object_store::DeviceKind::Block {
            path: new_device_path.to_path_buf(),
        };

        self.store
            .pool_mut()
            .begin_missing_member_rebuild_mutation()?;
        let outcome = (|| {
            let preparation = self.store.pool_mut().rebuild_missing_member(
                missing_device_guid,
                replacement_config,
                &tidefs_local_object_store::StoreOptions::default(),
            );

            // Evidence is deliberately durable before candidate mutation. If
            // candidate admission failed, no successor receipt exists and the
            // one-member Pool cannot publish roots; preserve the evidence and
            // return the admission error without manufacturing another write.
            if self.store.pool().config().devices.len() != 2 {
                return preparation.map_err(FileSystemError::from);
            }

            // A candidate-backed preparation can fail after publishing a
            // prefix of successor receipts. Reconcile every admitted root and
            // rotate the complete fallback ring before returning that error.
            self.reconcile_unmounted_filesystem_receipts(
                &mut root_authority.unmounted_filesystems,
            )?;
            self.reconcile_mounted_snapshot_receipts(&mut root_authority.mounted_snapshots)?;
            self.reconcile_relocated_content_receipts()?;
            self.store.pool_mut().sync_all()?;
            for _ in 0..crate::constants::FILESYSTEM_ROOT_SLOT_COUNT {
                self.persist_dataset_catalog()?;
            }
            self.store.pool_mut().sync_all()?;

            let preparation = preparation.map_err(FileSystemError::from)?;
            if preparation.objects_failed > 0 {
                return Ok(preparation);
            }
            let result = self
                .store
                .pool_mut()
                .finish_missing_member_rebuild(missing_device_guid)?;
            self.store.pool_mut().sync_all()?;
            self.rebuild_capacity_authority_from_committed_content()?;
            Ok(result)
        })();
        self.store.pool_mut().end_missing_member_rebuild_mutation();
        outcome
    }

    fn ensure_device_lifecycle_root_authority(
        &self,
        operation: &'static str,
    ) -> crate::Result<DeviceLifecycleRootAuthority> {
        if let Some(reason) = self.mounted_mutation_quiescence_failure() {
            return Err(FileSystemError::Unsupported { operation, reason });
        }
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        let (persisted_state, persisted_root) = crate::load_canonical_committed_state_for_dataset(
            &self.store,
            mounted_dataset_id,
            self.root_authentication_key,
        )?;
        if persisted_root.generation != self.state.generation
            || persisted_state.generation != self.state.generation
            || persisted_root.next_inode_id != self.state.next_inode_id_raw()
            || persisted_root.inode_count != self.state.inodes.len() as u64
        {
            return Err(FileSystemError::CorruptState {
                reason: "authenticated mounted root no longer matches the quiescent live owner",
            });
        }
        self.ensure_snapshot_authority_consistent()?;
        let mut mounted_snapshots = Vec::new();
        for record in self
            .state
            .snapshots
            .values()
            .filter(|record| crate::snapshot::snapshot_record_retains_data(record))
        {
            self.ensure_snapshot_record_authority(record)?;
            let dataset_id =
                crate::snapshot::snapshot_record_dataset_id_for_dataset(record, mounted_dataset_id);
            let previous_typed_root = self.store.load_snapshot_root(dataset_id)?;
            let captured_root = crate::root_commit_from_summary(&record.root);
            let captured_state =
                crate::load_state_from_transaction_pool_admitting_pending_device_lifecycle(
                    self.store.pool(),
                    mounted_dataset_id,
                    &captured_root,
                    self.root_authentication_key,
                )?;
            mounted_snapshots.push(DeviceLifecycleSnapshotState {
                name: record.name.clone(),
                dataset_id,
                previous_typed_root,
                captured_state,
                captured_root,
            });
        }

        let mut has_pool_owned_volume_roots = false;
        let mut unmounted_filesystems = Vec::new();
        for (path, dataset_id, dataset_type, _, flags, lifecycle_state) in
            self.dataset_catalog().list_all()
        {
            if dataset_id == mounted_dataset_id {
                continue;
            }
            match dataset_type {
                DatasetType::Volume => has_pool_owned_volume_roots = true,
                DatasetType::Filesystem => {
                    if flags.contains(DatasetFlags::CLONE) || lifecycle_state.to_u8() != 0 {
                        return Err(FileSystemError::Unsupported {
                            operation,
                            reason: "filesystem clones or non-active filesystem datasets require a separate lifecycle authority row",
                        });
                    }
                    let (state, root) = crate::load_canonical_committed_state_for_dataset(
                        &self.store,
                        dataset_id,
                        self.root_authentication_key,
                    )?;
                    let snapshots = self.load_unmounted_device_lifecycle_snapshot_states(
                        &state, &path, dataset_id,
                    )?;
                    unmounted_filesystems.push(DeviceLifecycleFilesystemState {
                        dataset_path: path,
                        state,
                        root,
                        snapshots,
                    });
                }
                DatasetType::Snapshot => {}
            }
        }

        let admitted_filesystem_ids = unmounted_filesystems
            .iter()
            .map(|filesystem| filesystem.state.dataset_id())
            .collect::<BTreeSet<_>>();
        for (path, dataset_id, dataset_type, _, _, _) in self.dataset_catalog().list_all() {
            if dataset_type != DatasetType::Snapshot {
                continue;
            }
            let source_dataset_id = self.dataset_catalog().lineage_parent(&path).map_err(|_| {
                FileSystemError::CorruptState {
                    reason: "device lifecycle could not inspect snapshot lineage",
                }
            })?;
            if source_dataset_id == Some(mounted_dataset_id)
                || source_dataset_id.is_some_and(|id| admitted_filesystem_ids.contains(&id))
            {
                continue;
            }
            let snapshot = self.store.load_snapshot_root(dataset_id)?;
            if snapshot.source_reference.kind != tidefs_pool_runtime::DatasetRootKind::Volume {
                return Err(FileSystemError::Unsupported {
                    operation,
                    reason: "a filesystem-sourced snapshot root belongs to a non-active or independently mounted dataset",
                });
            }
            has_pool_owned_volume_roots = true;
        }

        if has_pool_owned_volume_roots {
            // Volume roots carry immutable object keys and digests, not Pool
            // placement-receipt generations. Validate their complete current,
            // snapshot, clone, map, and chunk graphs before Pool evacuation or
            // rebuild mutates any receipt authority. Pool lifecycle then moves
            // those exact objects without rewriting their typed roots.
            let _ = self.store.canonical_root_object_keys()?;
        }
        Ok(DeviceLifecycleRootAuthority {
            unmounted_filesystems,
            mounted_snapshots,
        })
    }

    fn load_unmounted_device_lifecycle_snapshot_states(
        &self,
        state: &FileSystemState,
        dataset_path: &str,
        dataset_id: DatasetId,
    ) -> crate::Result<Vec<DeviceLifecycleSnapshotState>> {
        let mut snapshots = Vec::new();
        let mut expected_catalog_names = BTreeSet::new();
        for record in state
            .snapshots
            .values()
            .filter(|record| crate::snapshot::snapshot_record_retains_data(record))
        {
            if !crate::snapshot::snapshot_catalog_entry_matches(
                self.dataset_catalog(),
                record,
                dataset_path,
                dataset_id,
            ) {
                return Err(FileSystemError::CorruptState {
                    reason: "independent filesystem snapshot catalog entry does not match snapshot state",
                });
            }
            let snapshot_dataset_id =
                crate::snapshot::snapshot_record_dataset_id_for_dataset(record, dataset_id);
            let previous_typed_root = self.store.load_snapshot_root(snapshot_dataset_id)?;
            let expected_typed_root =
                crate::snapshot::snapshot_record_typed_root_for_dataset(record, dataset_id)?;
            if previous_typed_root != expected_typed_root {
                return Err(FileSystemError::CorruptState {
                    reason:
                        "independent filesystem typed snapshot root does not match snapshot state",
                });
            }
            let _ = crate::snapshot::snapshot_record_traversal_root(record)?;
            let captured_root = crate::root_commit_from_summary(&record.root);
            let captured_state =
                crate::load_state_from_transaction_pool_admitting_pending_device_lifecycle(
                    self.store.pool(),
                    dataset_id,
                    &captured_root,
                    self.root_authentication_key,
                )?;
            expected_catalog_names.insert(
                crate::snapshot::snapshot_record_catalog_name_for_dataset(record, dataset_path),
            );
            snapshots.push(DeviceLifecycleSnapshotState {
                name: record.name.clone(),
                dataset_id: snapshot_dataset_id,
                previous_typed_root,
                captured_state,
                captured_root,
            });
        }

        for (path, _, dataset_type, _, _, _) in self.dataset_catalog().list_all() {
            if dataset_type == DatasetType::Snapshot
                && self.dataset_catalog().lineage_parent(&path).map_err(|_| {
                    FileSystemError::CorruptState {
                        reason: "device lifecycle could not inspect independent snapshot lineage",
                    }
                })? == Some(dataset_id)
                && !expected_catalog_names.contains(&path)
            {
                return Err(FileSystemError::CorruptState {
                    reason: "independent filesystem catalog contains an orphan snapshot entry",
                });
            }
        }
        Ok(snapshots)
    }

    fn reconcile_mounted_snapshot_receipts(
        &mut self,
        snapshots: &mut [DeviceLifecycleSnapshotState],
    ) -> crate::Result<u64> {
        if snapshots.is_empty() {
            return Ok(0);
        }

        // Snapshot source transactions share the owning filesystem's object
        // keyspace. Start above every currently reachable root, not merely
        // above each snapshot's predecessor: snapshot creation has already
        // published a newer mounted root that otherwise owns the predecessor's
        // immediate successor transaction identity.
        let canonical_root = self.selected_committed_root_summary()?;
        let mut next_snapshot_transaction_id =
            canonical_root
                .transaction_id
                .checked_add(1)
                .ok_or(FileSystemError::CorruptState {
                    reason: "mounted snapshot transaction id space is exhausted",
                })?;
        for snapshot in snapshots.iter() {
            next_snapshot_transaction_id = next_snapshot_transaction_id.max(
                snapshot.captured_root.transaction_id.checked_add(1).ok_or(
                    FileSystemError::CorruptState {
                        reason: "mounted snapshot transaction id space is exhausted",
                    },
                )?,
            );
        }

        let reconcile = (|| {
            let mut migrated = Vec::new();
            let mut total_replacements = 0_u64;
            for snapshot in snapshots {
                let (replacement_count, obsolete_manifests) =
                    Self::reconcile_relocated_content_receipts_for_state(
                        self.store.pool_mut(),
                        &mut snapshot.captured_state,
                    )?;
                if replacement_count == 0 {
                    continue;
                }

                self.persist_device_lifecycle_reclaim_queue(
                    snapshot.captured_state.dataset_id(),
                    &obsolete_manifests,
                )?;
                let transaction_id = self.next_absent_snapshot_source_transaction_id(
                    &snapshot.captured_state,
                    next_snapshot_transaction_id,
                )?;
                next_snapshot_transaction_id =
                    transaction_id
                        .checked_add(1)
                        .ok_or(FileSystemError::CorruptState {
                            reason: "mounted snapshot transaction id space is exhausted",
                        })?;
                let signed_root = crate::prepare_state_with_pool_at_transaction(
                    self.store.pool_mut(),
                    &snapshot.captured_state,
                    transaction_id,
                    self.filesystem.root_authentication_key,
                )?;
                let root_bytes = crate::encoding::encode_root_commit(&signed_root);
                let source_reference = self.store.prepare_snapshot_source_root(
                    snapshot.captured_state.dataset_id(),
                    tidefs_pool_runtime::DatasetRootKind::Filesystem,
                    signed_root.generation,
                    &root_bytes,
                )?;
                let next_typed_root = tidefs_pool_runtime::SnapshotRoot::new(
                    snapshot.previous_typed_root.snapshot_generation,
                    source_reference,
                )?;
                migrated.push((
                    snapshot.name.clone(),
                    snapshot.dataset_id,
                    snapshot.previous_typed_root,
                    snapshot.captured_root.summary(),
                    signed_root.summary(),
                    next_typed_root,
                ));
                total_replacements = total_replacements.saturating_add(replacement_count);
            }

            if migrated.is_empty() {
                return Ok(0);
            }

            self.begin_mutation("reconcile mounted snapshot placement receipts")?;
            self.bump_generation();
            let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
            let mounted_dataset_path = self.mounted_dataset_path().to_string();
            for (
                name,
                dataset_id,
                previous_typed_root,
                previous_source_root,
                next_source_root,
                next_typed_root,
            ) in migrated
            {
                let previous_record = self.state.snapshots.get(&name).cloned().ok_or(
                    FileSystemError::CorruptState {
                        reason: "device lifecycle snapshot record disappeared before publication",
                    },
                )?;
                if previous_record.root != previous_source_root
                    || crate::snapshot::snapshot_record_dataset_id_for_dataset(
                        &previous_record,
                        mounted_dataset_id,
                    ) != dataset_id
                    || crate::snapshot::snapshot_record_typed_root_for_dataset(
                        &previous_record,
                        mounted_dataset_id,
                    )? != previous_typed_root
                {
                    return Err(FileSystemError::CorruptState {
                        reason: "device lifecycle snapshot authority changed after preflight",
                    });
                }
                let mut next_record = previous_record.clone();
                next_record.root = next_source_root;
                let expected_next = crate::snapshot::snapshot_record_typed_root_for_dataset(
                    &next_record,
                    mounted_dataset_id,
                )?;
                if expected_next != next_typed_root {
                    return Err(FileSystemError::CorruptState {
                        reason: "device lifecycle snapshot successor changed before publication",
                    });
                }

                let previous_traversal_root =
                    crate::snapshot::snapshot_record_traversal_root(&previous_record)?;
                let next_traversal_root =
                    crate::snapshot::snapshot_record_traversal_root(&next_record)?;
                self.lifecycle.unpin_root(previous_traversal_root);
                self.lifecycle.pin_root(next_traversal_root).map_err(|_| {
                    FileSystemError::CorruptState {
                        reason: "device lifecycle snapshot successor pin set is full",
                    }
                })?;
                crate::snapshot::reconcile_snapshot_record_catalog_entry(
                    self.dataset_catalog_mut()?,
                    &next_record,
                    &mounted_dataset_path,
                    mounted_dataset_id,
                )?;
                self.state.snapshots.insert(name, next_record);
                if self
                    .pending_snapshot_root_rewrites
                    .insert(dataset_id, previous_typed_root)
                    .is_some()
                {
                    return Err(FileSystemError::CorruptState {
                        reason: "device lifecycle snapshot predecessor was duplicated",
                    });
                }
            }
            self.mark_inode_metadata_dirty(ROOT_INODE_ID);
            self.mark_dir_dirty(ROOT_INODE_ID);
            Ok(total_replacements)
        })();

        match reconcile {
            Ok(count) => Ok(count),
            Err(error) => {
                self.rollback_mutation_delta();
                Err(error)
            }
        }
    }

    fn reconcile_unmounted_filesystem_receipts(
        &mut self,
        filesystems: &mut [DeviceLifecycleFilesystemState],
    ) -> crate::Result<u64> {
        let mut total_replacements = 0_u64;
        for filesystem in filesystems {
            let reconcile = (|| {
                let (snapshot_rewrites, snapshot_replacements) =
                    self.reconcile_unmounted_filesystem_snapshot_receipts(filesystem)?;
                let (current_replacements, obsolete_manifests) =
                    Self::reconcile_relocated_content_receipts_for_state(
                        self.store.pool_mut(),
                        &mut filesystem.state,
                    )?;
                if current_replacements > 0 {
                    // Queue predecessor manifests before publishing the
                    // successor root. The current canonical root keeps them
                    // protected if a crash occurs here; after publication the
                    // durable queue owns the exact now-unreachable objects.
                    self.persist_device_lifecycle_reclaim_queue(
                        filesystem.state.dataset_id(),
                        &obsolete_manifests,
                    )?;
                }
                if current_replacements == 0 && snapshot_rewrites.is_empty() {
                    return Ok(0);
                }

                let transaction_id = crate::next_mounted_commit_transaction_id(
                    filesystem.state.generation,
                    &filesystem.root.summary(),
                )?;
                filesystem.root =
                    crate::persist_state_with_runtime_at_transaction_and_snapshot_rewrites(
                        &mut self.store,
                        &filesystem.state,
                        transaction_id,
                        self.filesystem.root_authentication_key,
                        &snapshot_rewrites,
                    )?;
                self.store.pool_mut().sync_all()?;
                let _ = crate::load_canonical_committed_state_for_dataset(
                    &self.store,
                    filesystem.state.dataset_id(),
                    self.root_authentication_key,
                )?;
                Ok(current_replacements.saturating_add(snapshot_replacements))
            })();
            match reconcile {
                Ok(replacements) => {
                    total_replacements = total_replacements.saturating_add(replacements);
                }
                Err(error) => {
                    self.store.discard_metadata_candidate();
                    return Err(error);
                }
            }
        }
        Ok(total_replacements)
    }

    fn reconcile_unmounted_filesystem_snapshot_receipts(
        &mut self,
        filesystem: &mut DeviceLifecycleFilesystemState,
    ) -> crate::Result<(BTreeMap<DatasetId, tidefs_pool_runtime::SnapshotRoot>, u64)> {
        let mut migrated = Vec::new();
        let mut total_replacements = 0_u64;
        for snapshot in &mut filesystem.snapshots {
            let (replacement_count, obsolete_manifests) =
                Self::reconcile_relocated_content_receipts_for_state(
                    self.store.pool_mut(),
                    &mut snapshot.captured_state,
                )?;
            if replacement_count == 0 {
                continue;
            }

            self.persist_device_lifecycle_reclaim_queue(
                snapshot.captured_state.dataset_id(),
                &obsolete_manifests,
            )?;
            let transaction_id = crate::next_mounted_commit_transaction_id(
                snapshot.captured_state.generation,
                &snapshot.captured_root.summary(),
            )?;
            let signed_root = crate::prepare_state_with_pool_at_transaction(
                self.store.pool_mut(),
                &snapshot.captured_state,
                transaction_id,
                self.filesystem.root_authentication_key,
            )?;
            let root_bytes = crate::encoding::encode_root_commit(&signed_root);
            let source_reference = self.store.prepare_snapshot_source_root(
                snapshot.captured_state.dataset_id(),
                tidefs_pool_runtime::DatasetRootKind::Filesystem,
                signed_root.generation,
                &root_bytes,
            )?;
            let next_typed_root = tidefs_pool_runtime::SnapshotRoot::new(
                snapshot.previous_typed_root.snapshot_generation,
                source_reference,
            )?;
            migrated.push((
                snapshot.name.clone(),
                snapshot.dataset_id,
                snapshot.previous_typed_root,
                snapshot.captured_root.summary(),
                signed_root.summary(),
                next_typed_root,
            ));
            total_replacements = total_replacements.saturating_add(replacement_count);
        }

        if migrated.is_empty() {
            return Ok((BTreeMap::new(), 0));
        }

        filesystem.state.generation = filesystem.state.generation.saturating_add(1).max(1);
        let source_dataset_id = filesystem.state.dataset_id();
        let mut rewrites = BTreeMap::new();
        for (
            name,
            snapshot_dataset_id,
            previous_typed_root,
            previous_source_root,
            next_source_root,
            next_typed_root,
        ) in migrated
        {
            let previous_record = filesystem.state.snapshots.get(&name).cloned().ok_or(
                FileSystemError::CorruptState {
                    reason: "independent filesystem snapshot record disappeared after preflight",
                },
            )?;
            if previous_record.root != previous_source_root
                || crate::snapshot::snapshot_record_dataset_id_for_dataset(
                    &previous_record,
                    source_dataset_id,
                ) != snapshot_dataset_id
                || crate::snapshot::snapshot_record_typed_root_for_dataset(
                    &previous_record,
                    source_dataset_id,
                )? != previous_typed_root
            {
                return Err(FileSystemError::CorruptState {
                    reason: "independent filesystem snapshot authority changed after preflight",
                });
            }
            let mut next_record = previous_record;
            next_record.root = next_source_root;
            if crate::snapshot::snapshot_record_typed_root_for_dataset(
                &next_record,
                source_dataset_id,
            )? != next_typed_root
            {
                return Err(FileSystemError::CorruptState {
                    reason: "independent filesystem snapshot successor changed before publication",
                });
            }
            crate::snapshot::reconcile_snapshot_record_catalog_entry(
                self.dataset_catalog_mut()?,
                &next_record,
                &filesystem.dataset_path,
                source_dataset_id,
            )?;
            filesystem.state.snapshots.insert(name, next_record);
            if rewrites
                .insert(snapshot_dataset_id, previous_typed_root)
                .is_some()
            {
                return Err(FileSystemError::CorruptState {
                    reason: "independent filesystem snapshot predecessor was duplicated",
                });
            }
        }
        filesystem.state.dirty_inodes.insert(ROOT_INODE_ID);
        filesystem.state.dirty_dirs.insert(ROOT_INODE_ID);
        Ok((rewrites, total_replacements))
    }

    fn plan_relocated_content_receipts(
        pool: &tidefs_local_object_store::Pool,
        state: &FileSystemState,
    ) -> crate::Result<Vec<RelocatedContentReceiptReplacement>> {
        let keyspace = crate::FilesystemObjectKeyspace::new(state.dataset_id());
        let current_inodes = state
            .inodes
            .values()
            .filter(|record| {
                record.size > 0 && matches!(record.kind(), NodeKind::File | NodeKind::Symlink)
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut replacements = Vec::new();

        for record in current_inodes {
            let content_key = keyspace.content(record.inode_id, record.data_version);
            let Some((bytes, _)) =
                pool.get_with_current_receipt(DeviceIoClass::Data, content_key)?
            else {
                return Err(FileSystemError::CorruptState {
                    reason: "device lifecycle lost a current filesystem content manifest",
                });
            };
            let sparse = bytes.starts_with(&CONTENT_MANIFEST_SPARSE_MAGIC);
            let layout = crate::content::decode_content_layout(&bytes)?;
            crate::content::validate_content_layout(record.inode_id, &record, &layout)?;
            let crate::records::ContentLayout::Chunked(mut manifest) = layout else {
                continue;
            };

            let mut changed = false;
            let manifest_inode_id = manifest.inode_id;
            for chunk_ref in &mut manifest.chunks {
                if chunk_ref.is_hole() {
                    continue;
                }
                let chunk_key = crate::object_keys::content_chunk_object_key_for_version(
                    manifest_inode_id,
                    chunk_ref.data_version,
                    chunk_ref.chunk_index,
                );
                let scoped_chunk_key = keyspace.scope(chunk_key);
                let Some((chunk_bytes, current_chunk_receipt)) =
                    pool.get_with_current_receipt(DeviceIoClass::Data, scoped_chunk_key)?
                else {
                    return Err(FileSystemError::CorruptState {
                        reason: "device lifecycle lost a current filesystem content chunk",
                    });
                };
                let mut candidate = chunk_ref.clone();
                candidate.placement_receipt_generation = current_chunk_receipt.generation;
                if current_chunk_receipt.generation == 0
                    || current_chunk_receipt.generation < chunk_ref.placement_receipt_generation
                    || !crate::allocation::pending_device_lifecycle_chunk_payload_matches_ref(
                        pool,
                        &candidate,
                        chunk_key,
                        &chunk_bytes,
                        keyspace,
                    )
                {
                    return Err(FileSystemError::CorruptState {
                        reason:
                            "device lifecycle replacement receipt does not match filesystem content",
                    });
                }
                if chunk_ref.placement_receipt_generation != current_chunk_receipt.generation {
                    chunk_ref.placement_receipt_generation = current_chunk_receipt.generation;
                    changed = true;
                }
            }

            if changed {
                replacements.push(RelocatedContentReceiptReplacement {
                    record,
                    manifest,
                    sparse,
                    old_manifest_key: content_key,
                });
            }
        }
        Ok(replacements)
    }

    fn reconcile_relocated_content_receipts_for_state(
        pool: &mut tidefs_local_object_store::Pool,
        state: &mut FileSystemState,
    ) -> crate::Result<(u64, Vec<ObjectKey>)> {
        let replacements = Self::plan_relocated_content_receipts(pool, state)?;
        let replacement_count = replacements.len() as u64;
        if replacements.is_empty() {
            return Ok((0, Vec::new()));
        }

        let keyspace = crate::FilesystemObjectKeyspace::new(state.dataset_id());
        state.generation = state.generation.saturating_add(1).max(1);
        let tick = state.generation;
        let mut obsolete_manifests = Vec::with_capacity(replacements.len());
        for replacement in replacements {
            let mut updated_record = replacement.record;
            updated_record.data_version = tick;
            updated_record.metadata_version = tick;
            Self::advance_subtree_revision(&mut updated_record);
            let mut manifest = replacement.manifest;
            manifest.data_version = tick;
            let encoded = if replacement.sparse {
                encode_content_manifest_sparse(&manifest)
            } else {
                encode_content_manifest(&manifest)
            };
            let replacement_key = keyspace.content(updated_record.inode_id, tick);
            pool.put_with_receipt(DeviceIoClass::Data, replacement_key, &encoded)?;
            state.dirty_content.insert(updated_record.inode_id);
            state.dirty_inodes.insert(updated_record.inode_id);
            Arc::make_mut(&mut state.inodes).insert(updated_record.inode_id, updated_record);
            obsolete_manifests.push(replacement.old_manifest_key);
        }
        Ok((replacement_count, obsolete_manifests))
    }

    fn persist_device_lifecycle_reclaim_queue(
        &mut self,
        dataset_id: DatasetId,
        obsolete_manifests: &[ObjectKey],
    ) -> crate::Result<()> {
        if obsolete_manifests.is_empty() {
            return Ok(());
        }
        let keyspace = crate::FilesystemObjectKeyspace::new(dataset_id);
        let mut queue = crate::load_filesystem_reclaim_queue(self.store.pool(), keyspace)?;
        for key in obsolete_manifests {
            queue.insert(ReclaimQueueEntry::new(
                ReclaimObjectKey(*key.as_bytes()),
                -1,
                ReclaimQueueFamily::Extent,
            ));
        }
        let key = keyspace.scope(ObjectKey::from_name(
            tidefs_local_object_store::FILESYSTEM_RECLAIM_QUEUE_OBJECT_NAME.as_bytes(),
        ));
        self.store
            .pool_mut()
            .put_with_receipt(DeviceIoClass::Data, key, &queue.encode())?;
        self.store.pool_mut().sync_all()?;
        Ok(())
    }

    fn reconcile_relocated_content_receipts(&mut self) -> crate::Result<u64> {
        let keyspace = self.object_keyspace();
        let replacements = Self::plan_relocated_content_receipts(self.store.pool(), &self.state)?;

        let replacement_count = replacements.len() as u64;
        if replacements.is_empty() {
            if !self.pending_snapshot_root_rewrites.is_empty() {
                self.force_commit(())?;
            }
            return Ok(0);
        }

        self.begin_mutation("reconcile device-removal placement receipts")?;
        let reconcile = (|| {
            let tick = self.bump_generation();
            let mut updates = Vec::with_capacity(replacements.len());
            for replacement in replacements {
                let old_layout =
                    crate::records::ContentLayout::Chunked(replacement.manifest.clone());
                let mut updated_record = replacement.record;
                updated_record.data_version = tick;
                updated_record.metadata_version = tick;
                Self::advance_subtree_revision(&mut updated_record);

                let mut manifest = replacement.manifest;
                manifest.data_version = tick;
                let encoded = if replacement.sparse {
                    encode_content_manifest_sparse(&manifest)
                } else {
                    encode_content_manifest(&manifest)
                };
                let replacement_key = keyspace.content(updated_record.inode_id, tick);
                self.store.pool_mut().put_with_receipt(
                    DeviceIoClass::Data,
                    replacement_key,
                    &encoded,
                )?;
                let trim_plan = self.rewrite_trim_plan_for_layout(
                    updated_record.inode_id,
                    &old_layout,
                    &updated_record,
                )?;
                updates.push((updated_record, trim_plan));
            }

            for (record, _) in &updates {
                self.mark_inode_metadata_dirty(record.inode_id);
                self.mark_inode_content_dirty(record.inode_id);
                Arc::make_mut(&mut self.state.inodes).insert(record.inode_id, record.clone());
                self.inode_cache.borrow_mut().invalidate(record.inode_id);
            }
            Ok::<_, FileSystemError>(updates)
        })();
        let updates = match reconcile {
            Ok(updates) => updates,
            Err(error) => {
                self.rollback_mutation_delta();
                return Err(error);
            }
        };

        self.force_commit(())?;
        for (_, trim_plan) in updates {
            self.apply_rewrite_trim_plan(trim_plan);
        }
        Ok(replacement_count)
    }
}

fn live_admin_arg<'a>(args: &'a Value, key: &str) -> std::result::Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing live admin argument '{key}'"))
}

fn live_admin_optional_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn live_admin_exact_guid(raw: &str) -> Result<[u8; 16], String> {
    if raw.len() != 32 {
        return Err("device GUID must contain exactly 32 hexadecimal digits".to_string());
    }
    let mut guid = [0_u8; 16];
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let byte = std::str::from_utf8(chunk)
            .map_err(|_| "device GUID must contain exactly 32 hexadecimal digits".to_string())?;
        guid[index] = u8::from_str_radix(byte, 16)
            .map_err(|_| "device GUID must contain exactly 32 hexadecimal digits".to_string())?;
    }
    Ok(guid)
}

fn live_performance_admission_snapshot_args(
    args: &LivePoolAdminArgs,
) -> Result<(&str, &str, Option<&str>), LivePoolAdminError> {
    const ALLOWED: &[&str] = &["workload", "mount_adapter", "artifact_path"];
    if let Some(name) = args.0.keys().find(|name| !ALLOWED.contains(&name.as_str())) {
        return Err(LivePoolAdminError::malformed(format!(
            "live-owner request has unsupported argument '{name}'"
        )));
    }

    Ok((
        live_admin_typed_optional_string_arg(args, "workload")?
            .filter(|value| !value.is_empty())
            .unwrap_or("local-mounted-filesystem"),
        live_admin_typed_optional_string_arg(args, "mount_adapter")?
            .filter(|value| !value.is_empty())
            .unwrap_or("fuse"),
        live_admin_typed_optional_string_arg(args, "artifact_path")?
            .filter(|value| !value.is_empty()),
    ))
}

fn live_admin_typed_optional_string_arg<'a>(
    args: &'a LivePoolAdminArgs,
    key: &str,
) -> Result<Option<&'a str>, LivePoolAdminError> {
    match args.0.get(key) {
        None | Some(LivePoolAdminArg::Null) => Ok(None),
        Some(LivePoolAdminArg::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(LivePoolAdminError::malformed(format!(
            "live-owner request argument '{key}' must be a string"
        ))),
    }
}

fn live_dataset_type_arg(args: &Value) -> Result<DatasetType, String> {
    match live_admin_optional_arg(args, "type").unwrap_or("filesystem") {
        "filesystem" => Ok(DatasetType::Filesystem),
        "volume" => Ok(DatasetType::Volume),
        "snapshot" => Ok(DatasetType::Snapshot),
        other => Err(format!(
            "dataset create: invalid dataset type '{other}' (expected filesystem, volume, or snapshot)"
        )),
    }
}

fn live_dataset_type_filter_arg(args: &Value) -> Result<Option<DatasetType>, String> {
    match live_admin_optional_arg(args, "type") {
        Some("filesystem") => Ok(Some(DatasetType::Filesystem)),
        Some("volume") => Ok(Some(DatasetType::Volume)),
        Some("snapshot") => Ok(Some(DatasetType::Snapshot)),
        Some(other) => Err(format!(
            "dataset list: invalid dataset type '{other}' (expected filesystem, volume, or snapshot)"
        )),
        None => Ok(None),
    }
}

fn live_property_set_from_request(args: &Value) -> Result<PropertySet, String> {
    let Some(values) = args.get("properties") else {
        return Ok(PropertySet::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| "dataset create: properties must be an array argument".to_string())?;
    let registry = tidefs_dataset_properties::build_registry();
    let mut properties = PropertySet::new();
    let mut seen = BTreeSet::new();
    for entry in values {
        let key_name = entry
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| "dataset create: property entry is missing key".to_string())?;
        let key = tidefs_dataset_properties::PropertyKey::new(key_name);
        if !seen.insert(key_name.to_string()) {
            return Err(format!(
                "dataset create: duplicate dataset property key: {key_name}"
            ));
        }
        let def = tidefs_dataset_properties::lookup_property(&registry, &key).ok_or_else(|| {
            format!("dataset create: unsupported dataset property key: {key_name}")
        })?;
        let clear = entry.get("clear").and_then(Value::as_bool).unwrap_or(false);
        if clear {
            continue;
        }
        let value_json = entry
            .get("value")
            .ok_or_else(|| format!("dataset create: property '{key_name}' is missing value"))?;
        let value = live_property_value_from_json(value_json, def.value_type)?;
        tidefs_dataset_properties::validate_set(&key, &value, def, &properties)
            .map_err(|err| format!("dataset create: invalid value for {key_name}: {err}"))?;
        properties.set_local(key, value);
    }
    Ok(properties)
}

fn live_feature_names_from_request(args: &Value) -> Result<Vec<String>, String> {
    let Some(values) = args.get("features") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| "dataset create: features must be an array argument".to_string())?;
    let mut features = Vec::with_capacity(values.len());
    let mut seen = BTreeSet::new();
    for value in values {
        let feature = value
            .as_str()
            .ok_or_else(|| "dataset create: feature names must be strings".to_string())?;
        let name = FeatureName::from_str(feature)
            .ok_or_else(|| format!("dataset create: invalid feature flag name: {feature}"))?;
        if get_feature_class(&name).is_none() {
            return Err(format!(
                "dataset create: unsupported dataset feature flag: {feature}"
            ));
        }
        if !seen.insert(feature.to_string()) {
            return Err(format!(
                "dataset create: duplicate dataset feature flag: {feature}"
            ));
        }
        features.push(feature.to_string());
    }
    Ok(features)
}

fn live_dataset_snapshot_count(catalog: &DatasetCatalog, path: &str) -> Result<usize, String> {
    let target_id = catalog
        .lookup(path)
        .map_err(|err| format!("dataset destroy: catalog error resolving '{path}': {err}"))?;
    let mut count = 0;
    for (snapshot_path, _, dataset_type, _, _, _) in catalog.list_all() {
        if dataset_type != DatasetType::Snapshot {
            continue;
        }
        if catalog.lineage_parent(&snapshot_path).map_err(|err| {
            format!("dataset destroy: catalog error resolving lineage for '{snapshot_path}': {err}")
        })? == Some(target_id)
        {
            count += 1;
        }
    }
    Ok(count)
}

fn live_property_value_json(value: &PropertyValue) -> Value {
    match value {
        PropertyValue::None => Value::Null,
        PropertyValue::U64(value) => json!(value),
        PropertyValue::I64(value) => json!(value),
        PropertyValue::String(value) => json!(value),
        PropertyValue::Bool(value) => json!(value),
        PropertyValue::EnumVariant(value) => json!(value),
        PropertyValue::Bytes(value) => json!(value),
        PropertyValue::Size(value) => json!(value),
    }
}

fn live_property_value_from_json(
    value: &Value,
    value_type: PropertyType,
) -> Result<PropertyValue, String> {
    if value.is_null() {
        return Ok(PropertyValue::None);
    }
    match value_type {
        PropertyType::Bool => value
            .as_bool()
            .map(PropertyValue::Bool)
            .ok_or_else(|| "expected boolean property value".to_string()),
        PropertyType::U64 => value
            .as_u64()
            .map(PropertyValue::U64)
            .ok_or_else(|| "expected unsigned integer property value".to_string()),
        PropertyType::I64 => value
            .as_i64()
            .map(PropertyValue::I64)
            .ok_or_else(|| "expected signed integer property value".to_string()),
        PropertyType::String => value
            .as_str()
            .map(|value| PropertyValue::String(value.to_string()))
            .ok_or_else(|| "expected string property value".to_string()),
        PropertyType::Enum => value
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .map(PropertyValue::EnumVariant)
            .ok_or_else(|| "expected enum variant number 0..255".to_string()),
        PropertyType::Bytes => {
            let values = value
                .as_array()
                .ok_or_else(|| "expected byte array property value".to_string())?;
            values
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| "expected byte value 0..255".to_string())
                })
                .collect::<Result<Vec<_>, _>>()
                .map(PropertyValue::Bytes)
        }
        PropertyType::Size => value
            .as_u64()
            .map(PropertyValue::Size)
            .ok_or_else(|| "expected size property value in bytes".to_string()),
    }
}

fn live_property_value_from_str(
    raw: &str,
    value_type: PropertyType,
) -> Result<PropertyValue, String> {
    match value_type {
        PropertyType::Bool => match raw.to_ascii_lowercase().as_str() {
            "on" | "true" | "yes" | "1" => Ok(PropertyValue::Bool(true)),
            "off" | "false" | "no" | "0" => Ok(PropertyValue::Bool(false)),
            _ => Err("expected on/off, true/false, yes/no, or 1/0".to_string()),
        },
        PropertyType::U64 => raw
            .parse::<u64>()
            .map(PropertyValue::U64)
            .map_err(|err| format!("expected unsigned integer: {err}")),
        PropertyType::I64 => raw
            .parse::<i64>()
            .map(PropertyValue::I64)
            .map_err(|err| format!("expected signed integer: {err}")),
        PropertyType::String => Ok(PropertyValue::String(raw.to_string())),
        PropertyType::Enum => {
            let raw = raw
                .strip_prefix("variant(")
                .and_then(|inner| inner.strip_suffix(')'))
                .unwrap_or(raw);
            raw.parse::<u8>()
                .map(PropertyValue::EnumVariant)
                .map_err(|err| format!("expected enum variant number 0..255: {err}"))
        }
        PropertyType::Bytes => {
            let hex = raw.strip_prefix("0x").unwrap_or(raw);
            if hex.len() % 2 != 0 {
                return Err("hex byte value must contain an even number of digits".to_string());
            }
            hex.as_bytes()
                .chunks(2)
                .map(|chunk| {
                    let part = std::str::from_utf8(chunk)
                        .map_err(|err| format!("invalid UTF-8: {err}"))?;
                    u8::from_str_radix(part, 16)
                        .map_err(|err| format!("invalid hex byte {part}: {err}"))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(PropertyValue::Bytes)
        }
        PropertyType::Size => parse_live_size(raw).map(PropertyValue::Size),
    }
}

fn parse_live_size(raw: &str) -> Result<u64, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    let (number, multiplier) = match normalized.as_str() {
        value if value.ends_with("kib") => (&value[..value.len() - 3], 1024),
        value if value.ends_with("kb") => (&value[..value.len() - 2], 1024),
        value if value.ends_with('k') => (&value[..value.len() - 1], 1024),
        value if value.ends_with("mib") => (&value[..value.len() - 3], 1024_u64.pow(2)),
        value if value.ends_with("mb") => (&value[..value.len() - 2], 1024_u64.pow(2)),
        value if value.ends_with('m') => (&value[..value.len() - 1], 1024_u64.pow(2)),
        value if value.ends_with("gib") => (&value[..value.len() - 3], 1024_u64.pow(3)),
        value if value.ends_with("gb") => (&value[..value.len() - 2], 1024_u64.pow(3)),
        value if value.ends_with('g') => (&value[..value.len() - 1], 1024_u64.pow(3)),
        value if value.ends_with("tib") => (&value[..value.len() - 3], 1024_u64.pow(4)),
        value if value.ends_with("tb") => (&value[..value.len() - 2], 1024_u64.pow(4)),
        value if value.ends_with('t') => (&value[..value.len() - 1], 1024_u64.pow(4)),
        value if value.ends_with('b') => (&value[..value.len() - 1], 1),
        value => (value, 1),
    };
    if number.is_empty() {
        return Err("size value must include a number".to_string());
    }
    let base = number
        .parse::<u64>()
        .map_err(|err| format!("expected size in bytes or KiB/MiB/GiB/TiB form: {err}"))?;
    base.checked_mul(multiplier)
        .ok_or_else(|| "size value overflows u64".to_string())
}

fn live_admin_string_vec(args: &Value, key: &str) -> Result<Vec<String>, String> {
    let Some(value) = args.get(key) else {
        return Ok(Vec::new());
    };
    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToString::to_string)
                    .ok_or_else(|| format!("live admin argument '{key}' must be a string array"))
            })
            .collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(format!(
            "live admin argument '{key}' must be a string array"
        )),
    }
}

#[cfg(feature = "replication-io")]
fn live_admin_hex_16_or_default(args: &Value, key: &str) -> Result<[u8; 16], String> {
    match live_admin_optional_arg(args, key) {
        Some(value) => live_admin_hex_to_16(value),
        None => Ok([0; 16]),
    }
}

#[cfg(feature = "replication-io")]
fn live_admin_hex_to_16(value: &str) -> Result<[u8; 16], String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() != 32 {
        return Err(format!(
            "expected 32 hex chars (16 bytes), got {}",
            hex.len()
        ));
    }
    let mut out = [0_u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_string())?,
            16,
        )
        .map_err(|err| format!("invalid hex byte at position {}: {err}", i * 2))?;
        out[i] = byte;
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "replication-io")]
enum LiveSnapshotSendFormat {
    Vfssend1,
    Vfssend2,
}

#[cfg(feature = "replication-io")]
impl LiveSnapshotSendFormat {
    fn parse(args: &Value) -> Result<Self, String> {
        match live_admin_optional_arg(args, "format").unwrap_or("vfssend1") {
            "vfssend1" => Ok(Self::Vfssend1),
            "vfssend2" => Ok(Self::Vfssend2),
            other => Err(format!("snapshot send: unknown stream format '{other}'")),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Vfssend1 => "vfssend1",
            Self::Vfssend2 => "vfssend2",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "replication-io")]
enum LiveSnapshotSendMode {
    Full,
    Incremental { from_root: CommittedRootSummary },
}

#[cfg(feature = "replication-io")]
impl LiveSnapshotSendMode {
    const fn is_incremental(&self) -> bool {
        matches!(self, Self::Incremental { .. })
    }

    const fn label(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Incremental { .. } => "incremental",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "replication-io")]
enum LiveSnapshotSendDestination {
    Output(std::path::PathBuf),
    TargetAddress {
        target_addr: String,
        output: Option<std::path::PathBuf>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "replication-io")]
struct LiveSnapshotSendPlan {
    destination: LiveSnapshotSendDestination,
    format: LiveSnapshotSendFormat,
    mode: LiveSnapshotSendMode,
    pool_id: [u8; 16],
    dataset_id: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(feature = "replication-io")]
struct LiveSnapshotEncodedStream {
    encoded: Vec<u8>,
    total_records: u64,
    payload_bytes: u64,
    roots_len: usize,
}

#[cfg(feature = "replication-io")]
fn live_snapshot_send_plan(
    args: &Value,
    fs: &mut PoolDatasetOwner,
) -> Result<LiveSnapshotSendPlan, String> {
    let format = LiveSnapshotSendFormat::parse(args)?;
    let pool_id = live_admin_hex_16_or_default(args, "pool_id")
        .map_err(|err| format!("snapshot send: invalid pool-id: {err}"))?;
    let dataset_id = live_admin_hex_16_or_default(args, "dataset_id")
        .map_err(|err| format!("snapshot send: invalid dataset-id: {err}"))?;
    let mode = if args
        .get("incremental")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        LiveSnapshotSendMode::Incremental {
            from_root: live_snapshot_send_from_root_arg(args, fs)?,
        }
    } else {
        LiveSnapshotSendMode::Full
    };
    let destination = live_snapshot_send_destination(args)?;

    Ok(LiveSnapshotSendPlan {
        destination,
        format,
        mode,
        pool_id,
        dataset_id,
    })
}

#[cfg(feature = "replication-io")]
fn live_snapshot_send_destination(args: &Value) -> Result<LiveSnapshotSendDestination, String> {
    let output = live_admin_optional_arg(args, "output").map(std::path::PathBuf::from);
    match live_admin_optional_arg(args, "target_addr") {
        Some(target_addr) => Ok(LiveSnapshotSendDestination::TargetAddress {
            target_addr: target_addr.to_string(),
            output,
        }),
        None => output.map(LiveSnapshotSendDestination::Output).ok_or_else(|| {
            "snapshot send: --output is required for live pools unless target-address send is implemented"
                .to_string()
        }),
    }
}

#[cfg(feature = "replication-io")]
fn live_snapshot_send_from_root_arg(
    args: &Value,
    fs: &mut PoolDatasetOwner,
) -> Result<CommittedRootSummary, String> {
    let hex = live_admin_arg(args, "from_root")
        .map_err(|_| "snapshot send: --from-root required for incremental live-owner send")?;
    let bytes = live_admin_hex_to_bytes(hex)
        .map_err(|err| format!("snapshot send: invalid --from-root: {err}"))?;
    if bytes.len() != 24 {
        return Err(format!(
            "snapshot send: --from-root must be 24 bytes (48 hex chars), got {}",
            bytes.len()
        ));
    }

    let tid = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let gen = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let csum = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let audit = fs
        .recovery_audit()
        .map_err(|err| format!("snapshot send: audit recovery for --from-root: {err}"))?;
    audit
        .valid_committed_roots
        .iter()
        .find(|root| {
            root.transaction_id == tid
                && root.generation == gen
                && root.superblock_checksum == IntegrityDigest64(csum)
        })
        .cloned()
        .ok_or_else(|| {
            format!(
                "snapshot send: from_root not found in live owner committed roots: tid={tid} gen={gen} csum={csum:#016x}"
            )
        })
}

#[cfg(feature = "replication-io")]
fn live_admin_hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if !hex.len().is_multiple_of(2) {
        return Err(format!(
            "hex string must have even length, got {}",
            hex.len()
        ));
    }

    hex.as_bytes()
        .chunks(2)
        .enumerate()
        .map(|(i, chunk)| {
            let byte = std::str::from_utf8(chunk)
                .map_err(|_| format!("invalid UTF-8 in hex string at position {}", i * 2))?;
            u8::from_str_radix(byte, 16)
                .map_err(|err| format!("invalid hex at position {}: {err}", i * 2))
        })
        .collect()
}

#[cfg(feature = "replication-io")]
fn live_snapshot_send_export(
    fs: &mut PoolDatasetOwner,
    plan: &LiveSnapshotSendPlan,
) -> crate::Result<LiveSnapshotEncodedStream> {
    let export = match &plan.mode {
        LiveSnapshotSendMode::Full => fs.export_changed_records()?,
        LiveSnapshotSendMode::Incremental { from_root } => {
            fs.export_incremental_changed_records(from_root)?
        }
    };
    let encoded = match plan.format {
        LiveSnapshotSendFormat::Vfssend1 => export.encode(),
        LiveSnapshotSendFormat::Vfssend2 if plan.mode.is_incremental() => {
            crate::vfssend2_bridge::export_incremental_vfssend2_from_changed_records(
                &export,
                plan.pool_id,
                plan.dataset_id,
            )?
        }
        LiveSnapshotSendFormat::Vfssend2 => {
            crate::vfssend2_bridge::export_vfssend2_from_changed_records(
                &export,
                plan.pool_id,
                plan.dataset_id,
            )?
        }
    };

    Ok(LiveSnapshotEncodedStream {
        encoded,
        total_records: export.total_records,
        payload_bytes: export.payload_bytes,
        roots_len: export.roots.len(),
    })
}

fn live_admin_ok_text(text: impl Into<String>) -> LivePoolAdminResponse {
    LivePoolAdminResponse::ok_text(text)
}

fn live_admin_ok_json(value: Value) -> LivePoolAdminResponse {
    LivePoolAdminResponse::ok_machine_json(value.to_string())
}

fn live_admin_report_text(exit_code: i32, text: impl Into<String>) -> LivePoolAdminResponse {
    LivePoolAdminResponse::command_report_text(exit_code, text)
}

fn live_admin_report_json(exit_code: i32, value: Value) -> LivePoolAdminResponse {
    LivePoolAdminResponse::command_report_machine_json(exit_code, value.to_string())
}

fn live_admin_ok_bytes_hex(bytes: &[u8]) -> LivePoolAdminResponse {
    LivePoolAdminResponse::ok_bytes_hex(live_admin_hex_encode(bytes), bytes.len())
}

fn live_admin_error(exit_code: i32, message: impl Into<String>) -> LivePoolAdminResponse {
    LivePoolAdminResponse::error(exit_code, message)
}

fn live_admin_typed_error(err: LivePoolAdminError) -> LivePoolAdminResponse {
    match serde_json::to_string(&err.kind) {
        Ok(machine_json) => {
            LivePoolAdminResponse::error_machine_json(err.exit_code, err.message, machine_json)
        }
        Err(_) => LivePoolAdminResponse::error(err.exit_code, err.message),
    }
}

fn live_admin_hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn live_admin_args_to_json(args: &LivePoolAdminArgs) -> Value {
    let mut out = serde_json::Map::new();
    for (key, value) in &args.0 {
        out.insert(key.clone(), live_admin_arg_to_json(value));
    }
    Value::Object(out)
}

fn live_admin_arg_to_json(value: &LivePoolAdminArg) -> Value {
    match value {
        LivePoolAdminArg::Null => Value::Null,
        LivePoolAdminArg::Bool(value) => Value::Bool(*value),
        LivePoolAdminArg::I64(value) => Value::Number((*value).into()),
        LivePoolAdminArg::U64(value) => Value::Number((*value).into()),
        LivePoolAdminArg::String(value) => Value::String(value.clone()),
        LivePoolAdminArg::Array(values) => {
            Value::Array(values.iter().map(live_admin_arg_to_json).collect())
        }
        LivePoolAdminArg::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), live_admin_arg_to_json(value)))
                .collect(),
        ),
    }
}

#[cfg(feature = "encryption")]
fn salt_to_hex(salt: &[u8; SALT_LEN]) -> String {
    salt.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(feature = "encryption")]
fn live_admin_hex_to_salt(hex: &str) -> Result<[u8; SALT_LEN], String> {
    let hex = hex.trim();
    if hex.len() != SALT_LEN * 2 {
        return Err(format!(
            "expected {} hex chars ({} bytes), got {}",
            SALT_LEN * 2,
            SALT_LEN,
            hex.len()
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_string())?,
            16,
        )
        .map_err(|err| format!("invalid hex byte at position {}: {err}", i * 2))?;
        salt[i] = byte;
    }
    Ok(salt)
}

fn parse_sync_guarantee(value: &str) -> Option<SyncGuarantee> {
    match value {
        "local" => Some(SyncGuarantee::Local),
        "remote-copy" => Some(SyncGuarantee::RemoteCopy),
        "full-redundancy" => Some(SyncGuarantee::FullRedundancy),
        _ => None,
    }
}

fn resolve_feature_class(class: &str, enable: &[String]) -> Result<FeatureClass, String> {
    let explicit = match class {
        "compat" => Some(FeatureClass::Compat),
        "ro_compat" | "ro-compat" => Some(FeatureClass::RoCompat),
        "incompat" => Some(FeatureClass::Incompat),
        "auto" => None,
        other => {
            return Err(format!(
                "dataset set-strategy: unknown feature class '{other}'; expected auto, compat, ro_compat, or incompat"
            ))
        }
    };
    if let Some(class) = explicit {
        return Ok(class);
    }

    let Some(first) = enable
        .iter()
        .map(String::as_str)
        .map(str::trim)
        .find(|s| !s.is_empty())
    else {
        return Ok(FeatureClass::Compat);
    };
    let Some(name) = FeatureName::from_str(first) else {
        return Err(format!(
            "dataset set-strategy: invalid feature name '{first}'"
        ));
    };
    get_feature_class(&name).ok_or_else(|| {
        format!(
            "dataset set-strategy: cannot auto-resolve class for '{first}' (unknown feature); specify --class explicitly"
        )
    })
}

fn dataset_id_from_name(name: &str) -> DatasetId {
    let mut id_bytes = [0u8; 16];
    let hash = blake3::hash(name.as_bytes());
    id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    DatasetId::from_bytes(id_bytes)
}

fn format_dataset_id(id: &DatasetId) -> String {
    id.to_string().chars().take(8).collect()
}

fn snapshot_summary_line(summary: &crate::types::SnapshotSummary) -> String {
    format!(
        "snapshot '{}' (source tx={}, source gen={}, created gen={})",
        summary.name,
        summary.source_transaction_id,
        summary.source_generation,
        summary.created_at_generation
    )
}

fn volume_snapshot_line(summary: &tidefs_pool_runtime::VolumeSnapshotSummary) -> String {
    format!(
        "volume snapshot '{}' source='{}' kind=volume source_generation={} snapshot_generation={} size={} block_size={}",
        summary.path,
        summary.source_path,
        summary.source_generation,
        summary.snapshot_generation,
        summary.geometry.capacity_bytes,
        summary.geometry.block_size_bytes,
    )
}

fn volume_snapshot_json(summary: &tidefs_pool_runtime::VolumeSnapshotSummary) -> Value {
    json!({
        "path": summary.path,
        "id": summary.snapshot_id.to_string(),
        "source": summary.source_path,
        "source_id": summary.source_dataset_id.to_string(),
        "source_kind": "volume",
        "source_generation": summary.source_generation,
        "snapshot_generation": summary.snapshot_generation,
        "size": summary.geometry.capacity_bytes,
        "block_size": summary.geometry.block_size_bytes,
    })
}

fn volume_snapshot_response(
    outcome: &str,
    summary: &tidefs_pool_runtime::VolumeSnapshotSummary,
    wants_json: bool,
) -> LivePoolAdminResponse {
    if wants_json {
        return live_admin_ok_json(json!({
            "ok": true,
            "outcome": outcome,
            "snapshot": volume_snapshot_json(summary),
        }));
    }
    live_admin_ok_text(format!("{} {outcome}", volume_snapshot_line(summary)))
}

fn volume_snapshot_destroy_response(
    result: &tidefs_pool_runtime::VolumeSnapshotDestroyResult,
    wants_json: bool,
) -> LivePoolAdminResponse {
    if wants_json {
        return live_admin_ok_json(json!({
            "ok": true,
            "outcome": "logically destroyed",
            "snapshot": volume_snapshot_json(&result.snapshot),
            "reclaim": volume_reclaim_json(&result.reclaim),
        }));
    }
    live_admin_ok_text(format!(
        "{} logically destroyed\n{}",
        volume_snapshot_line(&result.snapshot),
        volume_reclaim_line(&result.reclaim),
    ))
}

fn is_volume_snapshot_clone_source(source: &str) -> bool {
    source.split_once('@').is_some_and(|(volume, snapshot)| {
        !volume.is_empty() && !snapshot.is_empty() && !snapshot.contains('@')
    })
}

fn filesystem_clone_unsupported(operation: &str, source: &str) -> LivePoolAdminResponse {
    live_admin_error(
        1,
        format!(
            "snapshot clone {operation}: source '{source}' is not a canonical volume snapshot; filesystem SnapshotRecord clones are metadata aliases, not independently writable datasets, and are unsupported by the product clone command"
        ),
    )
}

fn volume_clone_line(summary: &tidefs_pool_runtime::VolumeCloneSummary) -> String {
    format!(
        "volume clone '{}' source_snapshot='{}' source_volume='{}' kind=volume promoted={} generation={} size={} block_size={}",
        summary.path,
        summary.source_snapshot_path,
        summary.source_volume_path,
        summary.promoted,
        summary.generation,
        summary.geometry.capacity_bytes,
        summary.geometry.block_size_bytes,
    )
}

fn volume_clone_json(summary: &tidefs_pool_runtime::VolumeCloneSummary) -> Value {
    json!({
        "path": summary.path,
        "id": summary.clone_id.to_string(),
        "source_snapshot": summary.source_snapshot_path,
        "source_snapshot_id": summary.source_snapshot_id.to_string(),
        "source_volume": summary.source_volume_path,
        "source_volume_id": summary.source_volume_id.to_string(),
        "kind": "volume",
        "promoted": summary.promoted,
        "generation": summary.generation,
        "size": summary.geometry.capacity_bytes,
        "block_size": summary.geometry.block_size_bytes,
    })
}

fn volume_clone_response(
    outcome: &str,
    summary: &tidefs_pool_runtime::VolumeCloneSummary,
    wants_json: bool,
) -> LivePoolAdminResponse {
    if wants_json {
        return live_admin_ok_json(json!({
            "ok": true,
            "outcome": outcome,
            "clone": volume_clone_json(summary),
        }));
    }
    live_admin_ok_text(format!("{} {outcome}", volume_clone_line(summary)))
}

fn volume_clone_destroy_response(
    result: &tidefs_pool_runtime::VolumeCloneDestroyResult,
    wants_json: bool,
) -> LivePoolAdminResponse {
    if wants_json {
        return live_admin_ok_json(json!({
            "ok": true,
            "outcome": "logically destroyed",
            "clone": volume_clone_json(&result.clone),
            "reclaim": volume_reclaim_json(&result.reclaim),
        }));
    }
    live_admin_ok_text(format!(
        "{} logically destroyed\n{}",
        volume_clone_line(&result.clone),
        volume_reclaim_line(&result.reclaim),
    ))
}

fn volume_reclaim_json(outcome: &tidefs_pool_runtime::VolumeReclaimOutcome) -> Value {
    json!({
        "authority": "pool-delete",
        "candidate_objects": outcome.candidate_objects,
        "handed_off_objects": outcome.handed_off_objects,
        "pending_objects": outcome.pending_objects,
        "pending_plans": outcome.pending_plans,
        "handoff_error": outcome.handoff_error,
        "secure_erasure": false,
    })
}

fn volume_reclaim_line(outcome: &tidefs_pool_runtime::VolumeReclaimOutcome) -> String {
    let mut line = format!(
        "reclaim authority=pool-delete candidates={} handed_off={} pending_objects={} pending_plans={} secure_erasure=false",
        outcome.candidate_objects,
        outcome.handed_off_objects,
        outcome.pending_objects,
        outcome.pending_plans,
    );
    if let Some(error) = &outcome.handoff_error {
        line.push_str(&format!(" handoff_error={error}"));
    }
    line
}

fn property_family_from_str(value: &str) -> Option<tidefs_dataset_properties::PropertyFamily> {
    match value.to_lowercase().as_str() {
        "compression" => Some(tidefs_dataset_properties::PropertyFamily::Compression),
        "encryption" => Some(tidefs_dataset_properties::PropertyFamily::Encryption),
        "space" => Some(tidefs_dataset_properties::PropertyFamily::Space),
        "layout" => Some(tidefs_dataset_properties::PropertyFamily::Layout),
        "integrity" => Some(tidefs_dataset_properties::PropertyFamily::Integrity),
        "access" => Some(tidefs_dataset_properties::PropertyFamily::Access),
        "performance" | "perf" => Some(tidefs_dataset_properties::PropertyFamily::Performance),
        "snapshot" => Some(tidefs_dataset_properties::PropertyFamily::Snapshot),
        _ => None,
    }
}

fn live_property_table(
    operation: &str,
    props: &tidefs_dataset_properties::PropertySet,
    family: Option<&str>,
) -> LivePoolAdminResponse {
    let registry = tidefs_dataset_properties::build_registry();
    let defs: Vec<_> = if let Some(family_str) = family {
        let Some(family) = property_family_from_str(family_str) else {
            return live_admin_error(
                1,
                format!(
                    "{operation}: unknown family '{family_str}' (valid: compression, encryption, space, layout, integrity, access, performance, snapshot)"
                ),
            );
        };
        tidefs_dataset_properties::filter_registry_by_family(&registry, family)
    } else {
        registry.iter().collect()
    };

    if defs.is_empty() {
        return live_admin_ok_text("(no properties registered)");
    }

    let mut out = format!(
        "{:<35} {:<20} {:<12} {}\n{:-<35} {:-<20} {:-<12} {:-<20}",
        "PROPERTY", "VALUE", "TYPE", "SOURCE", "", "", "", ""
    );
    for def in &defs {
        let local_entry = props.get(&def.name);
        let (value, source) = match local_entry {
            Some(entry) => (entry.value.clone(), entry.source.clone()),
            None => (
                def.default_value.clone(),
                tidefs_dataset_properties::PropertySource::Default,
            ),
        };
        let source_str = match &source {
            tidefs_dataset_properties::PropertySource::Local => "local",
            tidefs_dataset_properties::PropertySource::Inherited { .. } => "inherited",
            tidefs_dataset_properties::PropertySource::Default => "default",
        };
        let _ = write!(
            out,
            "\n{:<35} {:<20} {:<12} {}",
            def.name.as_str(),
            value.to_string(),
            def.value_type.label(),
            source_str,
        );
    }
    live_admin_ok_text(out)
}

impl VfsLocalFileSystem {
    fn flush_copy_file_range_direct_segments(
        &self,
        dest_path: &str,
        source_fh: &EngineFileHandle,
        dest_fh: &EngineFileHandle,
        segments: &mut Vec<(u64, Vec<u8>)>,
        batch_bytes: &mut usize,
        copied: u64,
        requested: u64,
    ) -> std::result::Result<bool, Errno> {
        if segments.is_empty() {
            return Ok(false);
        }
        let segment_count = segments.len();
        let first_write_offset = segments
            .first()
            .map(|(offset, _)| *offset)
            .unwrap_or_default();
        let batch_len = *batch_bytes;
        let batch = std::mem::take(segments);
        *batch_bytes = 0;
        match self
            .fs
            .borrow_mut()
            .write_file_ranges_direct(dest_path, batch)
        {
            Ok(_) => Ok(true),
            Err(err) => {
                let errno = map_errno(&err);
                if vfs_op_diagnostics_enabled() {
                    eprintln!(
                        "tidefs-diagnostic: vfs copy_file_range direct batch write error src_ino={} src_fh={} dst_ino={} dst_fh={} first_write_offset={} batch_bytes={} segments={} copied={} requested={} errno={:?} err={:?}",
                        source_fh.inode_id.get(),
                        source_fh.fh_id.0,
                        dest_fh.inode_id.get(),
                        dest_fh.fh_id.0,
                        first_write_offset,
                        batch_len,
                        segment_count,
                        copied,
                        requested,
                        errno,
                        err
                    );
                }
                Err(errno)
            }
        }
    }

    fn try_reflink_whole_file_copy(
        &self,
        source_fh: &EngineFileHandle,
        offset_in: u64,
        dest_fh: &EngineFileHandle,
        offset_out: u64,
        requested: u64,
    ) -> std::result::Result<Option<u32>, Errno> {
        if offset_in != 0 || offset_out != 0 || source_fh.inode_id == dest_fh.inode_id {
            return Ok(None);
        }

        let mut fs = self.fs.borrow_mut();
        let source_record = fs.inode(source_fh.inode_id).map_err(|e| map_errno(&e))?;
        if source_record.kind() != NodeKind::File {
            return Ok(None);
        }
        let dest_record = fs.inode(dest_fh.inode_id).map_err(|e| map_errno(&e))?;
        if dest_record.kind() != NodeKind::File {
            return Ok(None);
        }

        let source_size = fs.effective_file_size(source_fh.inode_id);
        if source_size == 0 || source_size > requested {
            return Ok(None);
        }
        if fs.effective_file_size(dest_fh.inode_id) != 0 {
            return Ok(None);
        }
        if fs
            .write_buffers
            .get(&dest_fh.inode_id)
            .is_some_and(|buffer| !buffer.is_empty())
        {
            return Ok(None);
        }

        if fs
            .write_buffers
            .get(&source_fh.inode_id)
            .is_some_and(|buffer| !buffer.is_empty())
        {
            fs.flush_write_buffer(source_fh.inode_id)
                .map_err(|e| map_errno(&e))?;
        }
        let source_record = fs
            .inode(source_fh.inode_id)
            .map_err(|e| map_errno(&e))?
            .clone();
        let source_size = source_record.size;
        if source_size == 0 || source_size > requested {
            return Ok(None);
        }

        let planned_tick = crate::allocation::next_generation_after(fs.state.generation);
        let mut dest_record = fs
            .inode(dest_fh.inode_id)
            .map_err(|e| map_errno(&e))?
            .clone();
        dest_record.size = source_size;
        dest_record.data_version = planned_tick;
        dest_record.metadata_version = planned_tick;

        let (planned_entries, allocation_bytes, materialized_bytes) = fs
            .reflink_clone_content_plan(source_fh.inode_id, &source_record, &dest_record)
            .map_err(|e| map_errno(&e))?;
        #[cfg(feature = "policy-observation")]
        let new_blocks = allocation_bytes / u64::from(crate::constants::content_chunk_size());
        #[cfg(feature = "policy-observation")]
        fs.ensure_obligation_capacity("staging_dirty", new_blocks, Some(dest_fh.inode_id))
            .map_err(|e| map_errno(&e))?;
        fs.ensure_content_capacity_with_planned_inode(Some(dest_fh.inode_id), planned_entries)
            .map_err(|e| map_errno(&e))?;

        fs.begin_mutation("clone VFS file content")
            .map_err(|e| map_errno(&e))?;
        let tick = fs.bump_generation();
        debug_assert_eq!(tick, planned_tick);
        dest_record.data_version = tick;
        dest_record.metadata_version = tick;
        PoolDatasetOwner::advance_subtree_revision(&mut dest_record);
        if let Err(err) = fs.account_new_file_content(
            dest_fh.inode_id,
            materialized_bytes,
            allocation_bytes,
            tick,
        ) {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        let result = {
            let fs = &mut *fs;
            let dedup_enabled = fs.dedup_enabled;
            let compression_policy = fs.content_compression_policy.clone();
            let dataset_id = DatasetId::from_bytes(fs.mounted_dataset_id);
            let pool_store = fs.store.pool_mut().pool_store_mut();
            let mut content_store = FilesystemContentWriteStore::new(pool_store, dataset_id);
            let mut dedup = fs.filesystem.dedup_index.borrow_mut();
            reflink_chunked_content(
                dedup_enabled,
                &mut content_store,
                source_fh.inode_id,
                &source_record,
                &dest_record,
                &mut dedup,
                &compression_policy,
            )
        };
        if let Err(err) = result {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        if let Err(err) = fs.record_file_content_extents_from_layout(dest_fh.inode_id, &dest_record)
        {
            fs.rollback_mutation_delta();
            return Err(map_errno(&err));
        }
        fs.mark_inode_metadata_dirty(dest_fh.inode_id);
        Arc::make_mut(&mut fs.state.inodes).insert(dest_fh.inode_id, dest_record.clone());
        fs.inode_cache.borrow_mut().invalidate(dest_fh.inode_id);
        fs.mark_inode_content_dirty(dest_fh.inode_id);
        fs.commit_mutation(dest_record).map_err(|e| map_errno(&e))?;

        let _ = fs.apply_deferred_timestamp_update(
            source_fh.inode_id,
            TimestampUpdate::Read,
            self.timestamp_policy,
        );
        let _ = fs.apply_deferred_timestamp_update(
            dest_fh.inode_id,
            TimestampUpdate::Write,
            self.timestamp_policy,
        );

        u32::try_from(source_size)
            .map(Some)
            .map_err(|_| Errno::EFBIG)
    }

    fn read_impl(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        _ctx: &RequestCtx,
        record_access: bool,
    ) -> std::result::Result<Vec<u8>, Errno> {
        let live = self.validate_file_handle(fh)?;
        if live.enforce_access_mode && !open_flags_allow_read(live.open_flags) {
            return Err(Errno::EBADF);
        }
        let data = match self.fs.borrow().read_file_range_by_inode(
            fh.inode_id,
            offset,
            size as usize,
        ) {
            Ok(data) => data,
            Err(err) => {
                let errno = map_errno(&err);
                if errno == Errno::EIO && vfs_op_diagnostics_enabled() {
                    eprintln!(
                        "tidefs-diagnostic: vfs read error ino={} fh={} offset={} size={} errno={:?} err={:?}",
                        fh.inode_id.get(),
                        fh.fh_id.0,
                        offset,
                        size,
                        errno,
                        err
                    );
                }
                return Err(errno);
            }
        };
        if record_access && self.automatic_read_timestamp_admitted() {
            let _ = self.fs.borrow_mut().apply_deferred_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Read,
                self.timestamp_policy,
            );
        }

        Ok(data)
    }
}

// ── VfsEngine for VfsLocalFileSystem ──────────────────────────────────────

impl VfsEngine for VfsLocalFileSystem {
    // == Namespace operations ==============================================

    fn get_root_inode(&self, _ctx: &RequestCtx) -> std::result::Result<InodeId, Errno> {
        Ok(ROOT_INODE_ID)
    }

    fn lookup(
        &self,
        parent: InodeId,
        name: &[u8],
        _ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        if name.is_empty() && parent == ROOT_INODE_ID {
            let root_path = self.root_path();
            let attr = self
                .fs
                .borrow()
                .stat_attr(&root_path)
                .map_err(|e| map_errno(&e))?;
            // Register the dataset root inode in the path cache so
            // subsequent inode-based operations (readdir, list_dir_by_inode)
            // can resolve the real pool inode back to the dataset root path.
            self.path_cache
                .borrow_mut()
                .insert(attr.inode_id, root_path);
            return Ok(attr);
        }

        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;
        let (_parent_record, child_record) =
            self.parent_and_child_records(parent, &parent_path, name)?;
        let attr = child_record.to_inode_attr();
        self.path_cache
            .borrow_mut()
            .insert(attr.inode_id, child_path);
        Ok(attr)
    }

    fn getattr(
        &self,
        inode: InodeId,
        handle: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.validate_optional_file_handle(inode, handle)?;
        if inode == ROOT_INODE_ID && self.dataset_root_path.is_some() {
            let root_path = self.root_path();
            let attr = self
                .fs
                .borrow()
                .stat_attr(&root_path)
                .map_err(|e| map_errno(&e))?;
            self.path_cache
                .borrow_mut()
                .insert(attr.inode_id, root_path);
            return Ok(attr);
        }
        self.getattr_by_ino(inode.get())
    }

    fn setattr(
        &self,
        inode: InodeId,
        attr: &SetAttr,
        handle: Option<&EngineFileHandle>,
        _ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.ensure_writable()?;
        self.validate_optional_file_handle(inode, handle)?;
        const SUPPORTED_SETATTR_BITS: u32 = FATTR_MODE
            | FATTR_UID
            | FATTR_GID
            | FATTR_SIZE
            | FATTR_ATIME
            | FATTR_MTIME
            | FATTR_FH
            | FATTR_ATIME_NOW
            | FATTR_MTIME_NOW
            | FATTR_LOCKOWNER
            | FATTR_CTIME;
        if attr.valid & !SUPPORTED_SETATTR_BITS != 0 {
            return Err(Errno::EINVAL);
        }

        let mut fs = self.fs.borrow_mut();
        if !fs.inode_id_is_allocated(inode) {
            return Err(Errno::ENOENT);
        }

        if attr.valid & FATTR_SIZE != 0 {
            // Use effective size accounting for buffered writes so the
            // size comparison is correct when truncate follows a buffered
            // write that extended the file but hasn't been flushed yet.
            let logical_size = fs.effective_file_size(inode);
            let size_changed = attr.size != logical_size;
            if size_changed {
                fs.truncate_file_by_inode(inode, attr.size)
                    .map_err(|e| map_errno(&e))?;
            }
            Self::apply_metadata_setattr_to_inode(&mut fs, inode, attr, size_changed)?;
        } else {
            Self::apply_metadata_setattr_to_inode(&mut fs, inode, attr, false)?;
        }

        drop(fs);
        self.getattr_by_ino(inode.get())
    }

    fn mkdir(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let parent_record = {
            let fs = self.fs.borrow();
            self.parent_record_for_path(&fs, parent, &parent_path)?
        };
        let parent_default_acl_entries = Self::parent_default_acl_entries(&parent_record);
        let child_permissions = Self::creation_permissions_for_parent(
            parent_default_acl_entries.as_ref(),
            mode,
            ctx.umask,
        );
        let (child_mode, child_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            S_IFDIR | child_permissions,
            ctx.gid,
        );
        let child_path = build_child_path(&parent_path, name)?;
        let record = self.create_empty_directory(
            parent_record.inode_id,
            &parent_path,
            &child_path,
            name,
            child_mode,
            ctx.uid,
            child_gid,
            parent_default_acl_entries.as_ref(),
        )?;
        Ok(record.to_inode_attr())
    }

    fn create(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<(InodeAttr, EngineFileHandle), Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;

        let parent_record = {
            let fs = self.fs.borrow();
            self.parent_record_for_path(&fs, parent, &parent_path)?
        };
        let parent_default_acl_entries = Self::parent_default_acl_entries(&parent_record);
        let child_permissions = Self::creation_permissions_for_parent(
            parent_default_acl_entries.as_ref(),
            mode,
            ctx.umask,
        );
        let (child_mode, child_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            S_IFREG | child_permissions,
            ctx.gid,
        );
        let existing = {
            let fs = self.fs.borrow();
            fs.dir_entry_by_inode(parent_record.inode_id, name, &parent_path)
                .and_then(|entry| {
                    entry
                        .map(|entry| {
                            fs.get_inode_by_id(entry.inode_id).cloned().ok_or(
                                FileSystemError::CorruptState {
                                    reason: "directory entry references missing inode",
                                },
                            )
                        })
                        .transpose()
                })
        };
        match existing {
            Ok(Some(record)) => {
                if flags & O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                if flags & O_TRUNC == 0 {
                    // Existing file, no O_EXCL, no O_TRUNC: open existing.
                    let attr = record.to_inode_attr();
                    let fh = self.register_file_handle(record.inode_id, flags, false)?;
                    self.path_cache
                        .borrow_mut()
                        .insert(record.inode_id, child_path);
                    return Ok((attr, fh));
                }

                let attr = self
                    .fs
                    .borrow_mut()
                    .truncate_file(&child_path, 0)
                    .map(|record| record.to_inode_attr())
                    .map_err(|e| map_errno(&e))?;
                let fh = self.register_file_handle(record.inode_id, flags, false)?;
                self.path_cache
                    .borrow_mut()
                    .insert(record.inode_id, child_path);
                return Ok((attr, fh));
            }
            Ok(None) => {}
            Err(err) => {
                return Err(map_errno(&err));
            }
        }

        let record = self.create_empty_regular_file(
            parent_record.inode_id,
            &parent_path,
            &child_path,
            name,
            child_mode,
            ctx.uid,
            child_gid,
            parent_default_acl_entries.as_ref(),
        )?;
        let attr = record.to_inode_attr();
        let fh = self.register_file_handle(record.inode_id, flags, false)?;
        Ok((attr, fh))
    }

    fn create_excl(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<(InodeAttr, EngineFileHandle), Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;

        let parent_record = {
            let fs = self.fs.borrow();
            self.parent_record_for_path(&fs, parent, &parent_path)?
        };
        let parent_default_acl_entries = Self::parent_default_acl_entries(&parent_record);
        let child_permissions = Self::creation_permissions_for_parent(
            parent_default_acl_entries.as_ref(),
            mode,
            ctx.umask,
        );
        let (child_mode, child_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            S_IFREG | child_permissions,
            ctx.gid,
        );

        if self
            .fs
            .borrow()
            .dir_entry_by_inode(parent_record.inode_id, name, &parent_path)
            .map_err(|e| map_errno(&e))?
            .is_some()
        {
            return Err(Errno::EEXIST);
        }

        let record = self.create_empty_regular_file(
            parent_record.inode_id,
            &parent_path,
            &child_path,
            name,
            child_mode,
            ctx.uid,
            child_gid,
            parent_default_acl_entries.as_ref(),
        )?;
        let attr = record.to_inode_attr();
        // Preserve the caller's open flags so subsequent data-plane operations
        // validate against the same (inode, flags, fh_id) triple.
        let fh = self.register_file_handle(record.inode_id, flags, false)?;
        Ok((attr, fh))
    }

    fn tmpfile(
        &self,
        parent: InodeId,
        mode: u32,
        flags: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<(InodeAttr, EngineFileHandle), Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let parent_record = self
            .fs
            .borrow()
            .stat(&parent_path)
            .map_err(|e| map_errno(&e))?;
        if !parent_record.is_directory() {
            return Err(Errno::ENOTDIR);
        }

        let parent_default_acl_entries = Self::parent_default_acl_entries(&parent_record);
        let permissions = Self::creation_permissions_for_parent(
            parent_default_acl_entries.as_ref(),
            mode,
            ctx.umask,
        );
        let (mut file_mode, file_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            S_IFREG | permissions,
            ctx.gid,
        );
        let mut xattrs = BTreeMap::new();
        if let Some(acl_entries) = parent_default_acl_entries.as_ref() {
            for (name, value) in
                tidefs_posix_acl::default_acl_inheritance_for_parent(acl_entries, file_mode, false)
            {
                if name == Self::POSIX_ACL_ACCESS_XATTR {
                    if let Ok(access_acl) = tidefs_posix_acl::decode_posix_acl_xattr(&value) {
                        file_mode =
                            tidefs_posix_acl::posix_mode_from_access_acl(&access_acl, file_mode);
                    }
                }
                xattrs.insert(name.to_vec(), value);
            }
        }
        let record = self
            .fs
            .borrow_mut()
            .create_unlinked_regular_file(
                parent_record.inode_id,
                file_mode,
                ctx.uid,
                file_gid,
                xattrs,
            )
            .map_err(|error| map_errno(&error))?;
        let inode_id = record.inode_id;
        let attr = record.to_inode_attr();

        let fh = match self.register_file_handle(inode_id, flags, true) {
            Ok(fh) => fh,
            Err(err) => {
                let _ = self.fs.borrow_mut().finalize_orphan_inode(inode_id);
                return Err(err);
            }
        };

        Ok((attr, fh))
    }

    fn unlink(
        &self,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;
        let (parent_record, record) = self.parent_and_child_records(parent, &parent_path, name)?;
        if !sticky_dir_allows_unlink_or_rename(
            parent_record.mode,
            parent_record.uid,
            record.uid,
            ctx.uid,
        ) {
            return Err(Errno::EPERM);
        }
        let has_open_handles = self
            .file_handle_table
            .borrow()
            .contains_inode(record.inode_id);
        if has_open_handles {
            if record.nlink <= 1 {
                self.fs
                    .borrow_mut()
                    .unlink_child_retaining_inode(parent_record.inode_id, name, &child_path)
                    .map_err(|e| map_errno(&e))?;
            } else {
                self.fs
                    .borrow_mut()
                    .unlink_child_by_inode(parent_record.inode_id, name, &child_path)
                    .map_err(|e| map_errno(&e))?;
            }
        } else {
            self.fs
                .borrow_mut()
                .unlink_child_by_inode(parent_record.inode_id, name, &child_path)
                .map_err(|e| map_errno(&e))?;
        }
        self.remove_cached_path_if_matches(record.inode_id, &child_path);
        Ok(())
    }

    fn rmdir(
        &self,
        parent: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;
        let (parent_record, record) = self.parent_and_child_records(parent, &parent_path, name)?;
        if !sticky_dir_allows_unlink_or_rename(
            parent_record.mode,
            parent_record.uid,
            record.uid,
            ctx.uid,
        ) {
            return Err(Errno::EPERM);
        }
        self.fs
            .borrow_mut()
            .remove_dir_child_by_inode(parent_record.inode_id, name, &child_path)
            .map_err(|e| map_errno(&e))?;
        self.remove_cached_path_if_matches(record.inode_id, &child_path);
        Ok(())
    }

    fn rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        let old_parent_path = self.inode_path(old_parent)?;
        let new_parent_path = self.inode_path(new_parent)?;
        let old_path = build_child_path(&old_parent_path, old_name)?;
        let new_path = build_child_path(&new_parent_path, new_name)?;

        // Map POSIX renameat2 flags to RenameAt2Flags.
        // RENAME_WHITEOUT (4) is not yet supported.
        const RENAME_NOREPLACE_BIT: u32 = 1;
        const RENAME_EXCHANGE_BIT: u32 = 2;
        const SUPPORTED_MASK: u32 = RENAME_NOREPLACE_BIT | RENAME_EXCHANGE_BIT;

        if flags & !SUPPORTED_MASK != 0
            || (flags & RENAME_NOREPLACE_BIT != 0 && flags & RENAME_EXCHANGE_BIT != 0)
        {
            return Err(Errno::EINVAL);
        }

        let renameat2_flags = if flags & RENAME_EXCHANGE_BIT != 0 {
            RenameAt2Flags::EXCHANGE
        } else if flags & RENAME_NOREPLACE_BIT != 0 {
            RenameAt2Flags::NOREPLACE
        } else {
            RenameAt2Flags::EMPTY
        };

        let old_record = self
            .fs
            .borrow()
            .stat(&old_path)
            .map_err(|e| map_errno(&e))?;
        let target_record = self.fs.borrow().stat(&new_path).ok();

        // Sticky-bit check: when overwriting a target, the caller must
        // pass the sticky-bit gate on the target's parent directory.
        if renameat2_flags != RenameAt2Flags::EXCHANGE {
            if let Some(target_record) = target_record.as_ref() {
                let new_parent_record = self
                    .fs
                    .borrow()
                    .stat(&new_parent_path)
                    .map_err(|e| map_errno(&e))?;
                if !sticky_dir_allows_unlink_or_rename(
                    new_parent_record.mode,
                    new_parent_record.uid,
                    target_record.uid,
                    ctx.uid,
                ) {
                    return Err(Errno::EPERM);
                }
            }
        }

        self.fs
            .borrow_mut()
            .renameat2(&old_path, &new_path, renameat2_flags)
            .map_err(|e| map_errno(&e))?;

        if renameat2_flags == RenameAt2Flags::EXCHANGE {
            if let Some(target_record) = target_record.as_ref() {
                if target_record.inode_id != old_record.inode_id {
                    let old_attr = old_record.to_inode_attr();
                    let target_attr = target_record.to_inode_attr();
                    self.exchange_cached_paths(&old_attr, &old_path, &target_attr, &new_path);
                    return Ok(());
                }
            }
        } else if target_record
            .as_ref()
            .is_some_and(|target| target.inode_id != old_record.inode_id)
        {
            // Non-directory overwrite: the target inode is gone, but its
            // path prefix does not anchor any child entries.  Remove only
            // the target entry itself instead of scanning the entire cache.
            if target_record
                .as_ref()
                .is_some_and(|t| t.kind().has_child_namespace())
            {
                self.invalidate_cached_path_subtree(&new_path);
            } else {
                self.remove_cached_path_if_matches(
                    target_record.as_ref().unwrap().inode_id,
                    &new_path,
                );
            }
        }

        self.move_cached_path(old_record.inode_id, old_record.kind(), &old_path, &new_path);
        Ok(())
    }

    fn link(
        &self,
        target: InodeId,
        new_parent: InodeId,
        new_name: &[u8],
        _ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.ensure_writable()?;
        let target_record = self
            .fs
            .borrow()
            .get_inode_by_id(target)
            .cloned()
            .ok_or(Errno::ENOENT)?;
        if target_record.nlink == 0 {
            let new_parent_path = self.inode_path(new_parent)?;
            let new_path = build_child_path(&new_parent_path, new_name)?;
            let linked = self
                .fs
                .borrow_mut()
                .link_file_by_inode(target, new_parent, new_name, &new_path)
                .map_err(|error| map_errno(&error))?;
            self.path_cache.borrow_mut().insert(target, new_path);
            return Ok(linked.to_inode_attr());
        }

        let target_path = self.inode_path(target)?;
        let new_parent_path = self.inode_path(new_parent)?;
        let new_path = build_child_path(&new_parent_path, new_name)?;

        /* POSIX link(2) pre-checks: directory targets return EPERM,
         * nlink overflow returns EMLINK. */
        {
            let fs = self.fs.borrow();
            let target_attr = fs.stat_attr(&target_path).map_err(|e| map_errno(&e))?;
            if target_attr.kind == NodeKind::Dir {
                return Err(Errno::EPERM);
            }
            if target_attr.posix.nlink == u32::MAX {
                return Err(Errno::EMLINK);
            }
        }

        self.fs
            .borrow_mut()
            .link_file(&target_path, &new_path)
            .map_err(|e| map_errno(&e))?;
        self.path_cache.borrow_mut().insert(target, new_path);

        self.fs
            .borrow()
            .stat_attr(&target_path)
            .map_err(|e| map_errno(&e))
    }

    fn symlink(
        &self,
        parent: InodeId,
        name: &[u8],
        target: &[u8],
        ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.ensure_writable()?;
        let parent_path = self.inode_path(parent)?;
        let child_path = build_child_path(&parent_path, name)?;
        let target_str = bytes_to_str(target)?;

        let parent_record = {
            let fs = self.fs.borrow();
            self.parent_record_for_path(&fs, parent, &parent_path)?
        };
        let child_mode = crate::constants::DEFAULT_SYMLINK_PERMISSIONS & !ctx.umask;
        let (child_mode, child_gid) = apply_setgid_inheritance_for_create(
            parent_record.mode,
            parent_record.gid,
            tidefs_types_vfs_core::S_IFLNK | child_mode,
            ctx.gid,
        );

        let record = self
            .fs
            .borrow_mut()
            .create_symlink(&child_path, target_str)
            .map_err(|e| map_errno(&e))?;

        let mut attr_update = SetAttr::new();
        attr_update.valid = FATTR_MODE | FATTR_UID | FATTR_GID;
        attr_update.mode = child_mode;
        attr_update.uid = ctx.uid;
        attr_update.gid = child_gid;
        let attr = {
            let mut fs = self.fs.borrow_mut();
            Self::apply_metadata_setattr_to_inode(&mut fs, record.inode_id, &attr_update, false)?;
            fs.inode(record.inode_id)
                .map(|record| record.to_inode_attr())
                .map_err(|e| map_errno(&e))?
        };
        self.path_cache
            .borrow_mut()
            .insert(record.inode_id, child_path);
        Ok(attr)
    }

    fn readlink(&self, inode: InodeId, _ctx: &RequestCtx) -> std::result::Result<Vec<u8>, Errno> {
        let path = self.inode_path(inode)?;
        self.fs.borrow().read_symlink(&path).map_err(|e| match e {
            FileSystemError::NotFile { .. } => Errno::EINVAL,
            _ => map_errno(&e),
        })
    }

    fn mknod(
        &self,
        parent: InodeId,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<InodeAttr, Errno> {
        self.ensure_writable()?;
        let file_type = mode & S_IFMT;
        let rdev = match file_type {
            S_IFCHR | S_IFBLK => rdev,
            _ => 0,
        };

        match file_type {
            S_IFREG => {
                self.create_metadata_only_node(parent, name, NodeKind::File, mode, rdev, ctx)
            }
            S_IFIFO => {
                self.create_metadata_only_node(parent, name, NodeKind::Fifo, mode, rdev, ctx)
            }
            S_IFCHR => {
                self.create_metadata_only_node(parent, name, NodeKind::CharDev, mode, rdev, ctx)
            }
            S_IFBLK => {
                self.create_metadata_only_node(parent, name, NodeKind::BlockDev, mode, rdev, ctx)
            }
            S_IFSOCK => {
                self.create_metadata_only_node(parent, name, NodeKind::Socket, mode, rdev, ctx)
            }
            _ => Err(Errno::EOPNOTSUPP),
        }
    }

    // == File I/O operations ================================================

    fn open(
        &self,
        inode: InodeId,
        flags: u32,
        _ctx: &RequestCtx,
    ) -> std::result::Result<EngineFileHandle, Errno> {
        if open_flags_allow_write(flags) || flags & O_TRUNC != 0 {
            self.ensure_mounted_mutation_allowed("open writable mounted file handle")?;
        }
        if self.read_only && (open_flags_allow_write(flags) || flags & O_TRUNC != 0) {
            return Err(Errno::EROFS);
        }
        let path = self.inode_path(inode)?;
        let kind = {
            let record = self.fs.borrow().stat(&path).map_err(|e| map_errno(&e))?;
            record.kind()
        };

        // Reject directories before mutating anything.
        if kind == NodeKind::Dir {
            return Err(Errno::EISDIR);
        }

        // O_TRUNC: truncate before allocating the handle.
        if flags & O_TRUNC != 0 {
            self.fs
                .borrow_mut()
                .truncate_file(&path, 0)
                .map_err(|e| map_errno(&e))?;
        }

        // Delegate handle allocation to the open dispatch module.
        open_dispatch::engine_open(
            &self.fs.borrow(),
            &self.file_handle_table,
            kind,
            inode,
            flags,
            true,
        )
    }

    fn release(&self, fh: &EngineFileHandle) -> std::result::Result<(), Errno> {
        // Delegate handle release to the release dispatch module.
        let released = release_dispatch::engine_release(&self.file_handle_table, fh)?;

        if !self.file_handle_table.borrow().contains_inode(released) {
            let should_finalize = self
                .fs
                .borrow()
                .get_inode_by_id(released)
                .is_some_and(|record| record.nlink == 0);
            if should_finalize {
                self.fs
                    .borrow_mut()
                    .finalize_orphan_inode(released)
                    .map_err(|error| map_errno(&error))?;
            }
        }
        Ok(())
    }

    fn read(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<Vec<u8>, Errno> {
        self.read_impl(fh, offset, size, ctx, true)
    }

    fn read_for_cache_fill(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        size: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<Vec<u8>, Errno> {
        self.read_impl(fh, offset, size, ctx, false)
    }

    fn record_read_access(
        &self,
        inode: InodeId,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        if !self.automatic_read_timestamp_admitted() {
            return Ok(());
        }
        self.fs
            .borrow_mut()
            .apply_deferred_timestamp_update(inode, TimestampUpdate::Read, self.timestamp_policy)
            .map_err(|e| map_errno(&e))
    }

    fn write(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        data: &[u8],
        _ctx: &RequestCtx,
    ) -> std::result::Result<u32, Errno> {
        self.ensure_writable()?;
        let live = self.validate_file_handle(fh)?;
        if live.enforce_access_mode && !open_flags_allow_write(live.open_flags) {
            return Err(Errno::EBADF);
        }
        if live.enforce_access_mode && live.open_flags & O_APPEND != 0 {
            // Hold the mutable borrow across both stat and write so that
            // the file-size read and the subsequent write are atomic with
            // respect to other append writers (POSIX O_APPEND semantics).
            let mut fs = self.fs.borrow_mut();
            let write_offset = fs.get_inode_by_id(fh.inode_id).ok_or(Errno::ENOENT)?.size;
            if let Err(err) = fs.write_file_by_inode(fh.inode_id, write_offset, data) {
                let errno = map_errno(&err);
                if errno == Errno::EIO && vfs_op_diagnostics_enabled() {
                    eprintln!(
                        "tidefs-diagnostic: vfs append write error ino={} fh={} offset={} len={} errno={:?} err={:?}",
                        fh.inode_id.get(),
                        fh.fh_id.0,
                        write_offset,
                        data.len(),
                        errno,
                        err
                    );
                }
                return Err(errno);
            }
            if !data.is_empty() {
                let _ = fs.apply_deferred_timestamp_update(
                    fh.inode_id,
                    TimestampUpdate::Write,
                    self.timestamp_policy,
                );
            }
            return Ok(data.len() as u32);
        }

        let mut fs = self.fs.borrow_mut();
        if let Err(err) = fs.write_file_by_inode(fh.inode_id, offset, data) {
            let errno = map_errno(&err);
            if errno == Errno::EIO && vfs_op_diagnostics_enabled() {
                eprintln!(
                    "tidefs-diagnostic: vfs write error ino={} fh={} offset={} len={} errno={:?} err={:?}",
                    fh.inode_id.get(),
                    fh.fh_id.0,
                    offset,
                    data.len(),
                    errno,
                    err
                );
            }
            return Err(errno);
        }
        if !data.is_empty() {
            let _ = fs.apply_deferred_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        }
        Ok(data.len() as u32)
    }

    fn flush(&self, fh: &EngineFileHandle, _ctx: &RequestCtx) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("flush mounted file handle")?;
        self.validate_file_handle(fh)?;
        if self.read_only {
            return Ok(());
        }
        self.fs
            .borrow_mut()
            .flush_write_buffer(fh.inode_id)
            .map_err(|e| map_errno(&e))?;
        Ok(())
    }

    fn fsync(
        &self,
        fh: &EngineFileHandle,
        datasync: bool,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("synchronize mounted file handle")?;
        self.validate_file_handle(fh)?;
        if self.read_only {
            return Ok(());
        }
        if datasync {
            self.fs
                .borrow_mut()
                .fdatasync_inode(fh.inode_id, true)
                .map_err(|e| map_errno(&e))?;
        } else {
            self.fs
                .borrow_mut()
                .sync_inode(fh.inode_id)
                .map_err(|e| map_errno(&e))?;
        }
        self.wait_for_sync_guarantee()?;
        Ok(())
    }

    fn fallocate(
        &self,
        fh: &EngineFileHandle,
        mode: u32,
        offset: u64,
        length: u64,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        self.validate_file_handle(fh)?;
        let mut fs = self.fs.borrow_mut();

        // Known modes: COLLAPSE_RANGE, INSERT_RANGE, KEEP_SIZE, PUNCH_HOLE, ZERO_RANGE.
        let known_mask = FALLOC_FL_COLLAPSE_RANGE
            | FALLOC_FL_INSERT_RANGE
            | FALLOC_FL_KEEP_SIZE
            | FALLOC_FL_PUNCH_HOLE
            | FALLOC_FL_ZERO_RANGE;
        if mode & !known_mask != 0 {
            // Unknown or unsupported flag combination.
            return Err(Errno::EOPNOTSUPP);
        }

        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            // PUNCH_HOLE requires KEEP_SIZE per POSIX; reject otherwise.
            if mode & FALLOC_FL_KEEP_SIZE == 0 || mode & FALLOC_FL_ZERO_RANGE != 0 {
                return Err(Errno::EINVAL);
            }
            fs.punch_hole_by_inode(fh.inode_id, offset, length)
                .map_err(|e| map_errno(&e))?;
            let _ = fs.apply_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        } else if mode & FALLOC_FL_ZERO_RANGE != 0 {
            if mode & FALLOC_FL_KEEP_SIZE == 0 && length > 0 {
                let end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
                let record = fs
                    .get_inode_by_id(fh.inode_id)
                    .cloned()
                    .ok_or(Errno::ENOENT)?;
                if end > record.size {
                    fs.truncate_file_by_inode(fh.inode_id, end)
                        .map_err(|e| map_errno(&e))?;
                }
            }
            fs.zero_range_by_inode(fh.inode_id, offset, length)
                .map_err(|e| map_errno(&e))?;
            let _ = fs.apply_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        } else if mode & FALLOC_FL_COLLAPSE_RANGE != 0 {
            // COLLAPSE_RANGE: remove bytes in [offset, offset+length) and shift
            // tail left.  collapse_range() internally clamps to EOF and handles
            // offset>=size as a no-op.
            fs.collapse_range_by_inode(fh.inode_id, offset, length)
                .map_err(|e| map_errno(&e))?;
            let _ = fs.apply_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        } else if mode & FALLOC_FL_INSERT_RANGE != 0 {
            // INSERT_RANGE: insert `length` zero bytes at `offset`, shifting
            // tail right.  insert_range() handles offset beyond EOF as
            // allocate+extend.
            fs.insert_range_by_inode(fh.inode_id, offset, length)
                .map_err(|e| map_errno(&e))?;
            let _ = fs.apply_timestamp_update(
                fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        } else if mode & FALLOC_FL_KEEP_SIZE != 0 {
            // Allocate Unwritten extents without extending file size.
            fs.reserve_unwritten_by_inode(fh.inode_id, offset, length)
                .map_err(|e| map_errno(&e))?;
            let _ = fs.apply_timestamp_update(
                fh.inode_id,
                TimestampUpdate::MetadataChange,
                self.timestamp_policy,
            );
        } else {
            // Default (mode 0): allocate + extend file size.
            if length > 0 {
                let _end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
                fs.fallocate_file_by_inode(fh.inode_id, offset, length)
                    .map_err(|e| map_errno(&e))?;
                let _ = fs.apply_timestamp_update(
                    fh.inode_id,
                    TimestampUpdate::Write,
                    self.timestamp_policy,
                );
            }
        }
        Ok(())
    }

    fn copy_file_range(
        &self,
        source_fh: &EngineFileHandle,
        offset_in: u64,
        dest_fh: &EngineFileHandle,
        offset_out: u64,
        length: u64,
        ctx: &RequestCtx,
    ) -> std::result::Result<u32, Errno> {
        self.ensure_writable()?;
        if length == 0 {
            return Ok(0);
        }

        let src = self.validate_file_handle(source_fh)?;
        let dst = self.validate_file_handle(dest_fh)?;
        if src.enforce_access_mode && !open_flags_allow_read(src.open_flags) {
            return Err(Errno::EBADF);
        }
        if dst.enforce_access_mode && !open_flags_allow_write(dst.open_flags) {
            return Err(Errno::EBADF);
        }

        let requested = length.min(u64::from(u32::MAX));
        let source_end = offset_in.checked_add(requested).ok_or(Errno::EINVAL)?;
        let dest_end = offset_out.checked_add(requested).ok_or(Errno::EINVAL)?;
        if source_fh.inode_id == dest_fh.inode_id && offset_in < dest_end && offset_out < source_end
        {
            return Err(Errno::EINVAL);
        }

        self.fs
            .borrow_mut()
            .record_copy_file_range_intent(CopyFileRangeIntent {
                src_ino: source_fh.inode_id,
                src_fh: source_fh.fh_id.0,
                dst_ino: dest_fh.inode_id,
                dst_fh: dest_fh.fh_id.0,
                src_offset: offset_in,
                dst_offset: offset_out,
                len: length,
            })
            .map_err(|e| map_errno(&e))?;

        let source_path = self.inode_path(source_fh.inode_id).ok();
        let dest_path = self.inode_path(dest_fh.inode_id).ok();
        if let (Some(source_path), Some(dest_path)) = (source_path.as_deref(), dest_path.as_deref())
        {
            let sparse_zero_copy = self
                .fs
                .borrow()
                .sparse_zero_range_copy_len(source_path, offset_in, requested)
                .map_err(|e| map_errno(&e))?;
            if let Some(copied) = sparse_zero_copy {
                let copied_u32 = u32::try_from(copied).map_err(|_| Errno::EFBIG)?;
                {
                    let mut fs = self.fs.borrow_mut();
                    if copied > 0 {
                        let dest_end = offset_out.checked_add(copied).ok_or(Errno::EINVAL)?;
                        let dest_size = fs.stat(dest_path).map_err(|e| map_errno(&e))?.size;
                        if dest_end > dest_size {
                            fs.truncate_file(dest_path, dest_end)
                                .map_err(|e| map_errno(&e))?;
                        }
                        fs.punch_hole(dest_path, offset_out, copied)
                            .map_err(|e| map_errno(&e))?;
                    }
                    let _ = fs.apply_deferred_timestamp_update(
                        source_fh.inode_id,
                        TimestampUpdate::Read,
                        self.timestamp_policy,
                    );
                    if copied > 0 {
                        let _ = fs.apply_deferred_timestamp_update(
                            dest_fh.inode_id,
                            TimestampUpdate::Write,
                            self.timestamp_policy,
                        );
                    }
                }
                return Ok(copied_u32);
            }
            if let Some(copied) = self
                .try_reflink_whole_file_copy(source_fh, offset_in, dest_fh, offset_out, requested)?
            {
                return Ok(copied);
            }
        }

        let direct_dest_path = if dst.enforce_access_mode && dst.open_flags & O_APPEND != 0 {
            None
        } else {
            dest_path
        };

        // Perform the copy via the read/write path.
        let mut copied = 0_u64;
        let mut source_was_read = false;
        let mut dest_was_direct_written = false;
        let mut direct_segments = Vec::new();
        let mut direct_batch_bytes = 0_usize;
        while copied < requested {
            let remaining = requested - copied;
            let chunk_len = remaining.min(131_072);
            let chunk_size = u32::try_from(chunk_len).map_err(|_| Errno::EFBIG)?;
            let read_offset = offset_in.checked_add(copied).ok_or(Errno::EINVAL)?;
            let chunk = match self.read_impl(source_fh, read_offset, chunk_size, ctx, false) {
                Ok(chunk) => chunk,
                Err(errno) => {
                    if let Some(dest_path) = direct_dest_path.as_deref() {
                        match self.flush_copy_file_range_direct_segments(
                            dest_path,
                            source_fh,
                            dest_fh,
                            &mut direct_segments,
                            &mut direct_batch_bytes,
                            copied,
                            requested,
                        ) {
                            Ok(flushed) => {
                                dest_was_direct_written |= flushed;
                            }
                            Err(write_errno) => {
                                if source_was_read || dest_was_direct_written {
                                    let mut fs = self.fs.borrow_mut();
                                    if source_was_read {
                                        let _ = fs.apply_deferred_timestamp_update(
                                            source_fh.inode_id,
                                            TimestampUpdate::Read,
                                            self.timestamp_policy,
                                        );
                                    }
                                    if dest_was_direct_written {
                                        let _ = fs.apply_deferred_timestamp_update(
                                            dest_fh.inode_id,
                                            TimestampUpdate::Write,
                                            self.timestamp_policy,
                                        );
                                    }
                                }
                                return Err(write_errno);
                            }
                        }
                    }
                    if vfs_op_diagnostics_enabled() {
                        eprintln!(
                            "tidefs-diagnostic: vfs copy_file_range read error src_ino={} src_fh={} dst_ino={} dst_fh={} read_offset={} write_offset={} chunk_size={} copied={} requested={} errno={:?}",
                            source_fh.inode_id.get(),
                            source_fh.fh_id.0,
                            dest_fh.inode_id.get(),
                            dest_fh.fh_id.0,
                            read_offset,
                            offset_out.saturating_add(copied),
                            chunk_size,
                            copied,
                            requested,
                            errno
                        );
                    }
                    if source_was_read {
                        let mut fs = self.fs.borrow_mut();
                        let _ = fs.apply_deferred_timestamp_update(
                            source_fh.inode_id,
                            TimestampUpdate::Read,
                            self.timestamp_policy,
                        );
                        if dest_was_direct_written {
                            let _ = fs.apply_deferred_timestamp_update(
                                dest_fh.inode_id,
                                TimestampUpdate::Write,
                                self.timestamp_policy,
                            );
                        }
                    }
                    return Err(errno);
                }
            };
            if chunk.is_empty() {
                break;
            }
            source_was_read = true;
            let write_offset = offset_out.checked_add(copied).ok_or(Errno::EINVAL)?;
            if let Some(dest_path) = direct_dest_path.as_deref() {
                let chunk_len = chunk.len();
                let chunk_len_u64 = u64::try_from(chunk_len).map_err(|_| Errno::EFBIG)?;
                direct_batch_bytes = direct_batch_bytes
                    .checked_add(chunk_len)
                    .ok_or(Errno::EFBIG)?;
                direct_segments.push((write_offset, chunk));
                copied = copied.checked_add(chunk_len_u64).ok_or(Errno::EFBIG)?;
                if direct_batch_bytes >= COPY_FILE_RANGE_DIRECT_FALLBACK_BATCH_BYTES {
                    match self.flush_copy_file_range_direct_segments(
                        dest_path,
                        source_fh,
                        dest_fh,
                        &mut direct_segments,
                        &mut direct_batch_bytes,
                        copied,
                        requested,
                    ) {
                        Ok(flushed) => {
                            dest_was_direct_written |= flushed;
                        }
                        Err(errno) => {
                            if source_was_read || dest_was_direct_written {
                                let mut fs = self.fs.borrow_mut();
                                if source_was_read {
                                    let _ = fs.apply_deferred_timestamp_update(
                                        source_fh.inode_id,
                                        TimestampUpdate::Read,
                                        self.timestamp_policy,
                                    );
                                }
                                if dest_was_direct_written {
                                    let _ = fs.apply_deferred_timestamp_update(
                                        dest_fh.inode_id,
                                        TimestampUpdate::Write,
                                        self.timestamp_policy,
                                    );
                                }
                            }
                            return Err(errno);
                        }
                    }
                }
            } else {
                let written = match self.write(dest_fh, write_offset, &chunk, ctx) {
                    Ok(written) => written,
                    Err(errno) => {
                        if vfs_op_diagnostics_enabled() {
                            eprintln!(
                                "tidefs-diagnostic: vfs copy_file_range write error src_ino={} src_fh={} dst_ino={} dst_fh={} read_offset={} write_offset={} chunk_len={} copied={} requested={} errno={:?}",
                                source_fh.inode_id.get(),
                                source_fh.fh_id.0,
                                dest_fh.inode_id.get(),
                                dest_fh.fh_id.0,
                                read_offset,
                                write_offset,
                                chunk.len(),
                                copied,
                                requested,
                                errno
                            );
                        }
                        let _ = self.fs.borrow_mut().apply_deferred_timestamp_update(
                            source_fh.inode_id,
                            TimestampUpdate::Read,
                            self.timestamp_policy,
                        );
                        return Err(errno);
                    }
                };
                copied = copied.checked_add(u64::from(written)).ok_or(Errno::EFBIG)?;
                if written == 0 || u64::from(written) < chunk.len() as u64 {
                    break;
                }
            }
        }

        if let Some(dest_path) = direct_dest_path.as_deref() {
            match self.flush_copy_file_range_direct_segments(
                dest_path,
                source_fh,
                dest_fh,
                &mut direct_segments,
                &mut direct_batch_bytes,
                copied,
                requested,
            ) {
                Ok(flushed) => {
                    dest_was_direct_written |= flushed;
                }
                Err(errno) => {
                    if source_was_read || dest_was_direct_written {
                        let mut fs = self.fs.borrow_mut();
                        if source_was_read {
                            let _ = fs.apply_deferred_timestamp_update(
                                source_fh.inode_id,
                                TimestampUpdate::Read,
                                self.timestamp_policy,
                            );
                        }
                        if dest_was_direct_written {
                            let _ = fs.apply_deferred_timestamp_update(
                                dest_fh.inode_id,
                                TimestampUpdate::Write,
                                self.timestamp_policy,
                            );
                        }
                    }
                    return Err(errno);
                }
            }
        }

        if source_was_read {
            let _ = self.fs.borrow_mut().apply_deferred_timestamp_update(
                source_fh.inode_id,
                TimestampUpdate::Read,
                self.timestamp_policy,
            );
        }
        if dest_was_direct_written {
            let _ = self.fs.borrow_mut().apply_deferred_timestamp_update(
                dest_fh.inode_id,
                TimestampUpdate::Write,
                self.timestamp_policy,
            );
        }

        u32::try_from(copied).map_err(|_| Errno::EFBIG)
    }

    fn data_ranges(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u64,
        _ctx: &RequestCtx,
    ) -> std::result::Result<Vec<LseekDataRange>, Errno> {
        self.validate_file_handle(fh)?;
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset.checked_add(length).ok_or(Errno::EINVAL)?;
        let fs = self.fs.borrow();
        let mut ranges = Vec::new();
        for (data_start, data_end) in fs
            .mounted_data_ranges(fh.inode_id)
            .map_err(|e| map_errno(&e))?
        {
            let clipped_start = data_start.max(offset);
            let clipped_end = data_end.min(end);
            if clipped_start < clipped_end {
                ranges.push(LseekDataRange::new(clipped_start, clipped_end));
            }
        }

        Ok(ranges)
    }

    fn fiemap_file(
        &self,
        fh: &EngineFileHandle,
        offset: u64,
        length: u64,
        max_extents: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<Vec<tidefs_types_extent_map_core::FiemapExtent>, Errno> {
        self.validate_file_handle(fh)?;
        if length == 0 {
            return Err(Errno::EINVAL);
        }
        let fs = self.fs.borrow();
        // Prefer the authoritative extent map when it exists (fallocate-managed).
        let extent_maps = fs.state.extent_maps.lock().unwrap();
        if let Some(extent_map) = extent_maps.get(&fh.inode_id) {
            let mut extents = extent_map
                .inner()
                .fiemap(offset, length)
                .map_err(|e| match e {
                    tidefs_types_extent_map_core::ExtentMapError::InvalidRange => Errno::EINVAL,
                    _ => Errno::EIO,
                })?;
            if max_extents > 0 && extents.len() > max_extents as usize {
                extents.truncate(max_extents as usize);
            }
            return Ok(extents);
        }
        drop(extent_maps);
        drop(fs);
        // Fallback: when no explicit extent map exists, report a single
        // dense extent covering the queried range up to the file size.
        let attr = self.getattr(fh.inode_id, Some(fh), ctx)?;
        let file_size = attr.posix.size;
        if offset >= file_size {
            return Ok(Vec::new());
        }
        let range_end = (offset + length).min(file_size);
        let len = range_end - offset;
        let mut extents = vec![tidefs_types_extent_map_core::FiemapExtent::new(
            offset,
            0,
            len,
            tidefs_types_extent_map_core::FiemapExtent::FLAG_LAST,
        )];
        if max_extents > 0 && extents.len() > max_extents as usize {
            extents.truncate(max_extents as usize);
        }
        Ok(extents)
    }

    // == Directory operations ===============================================

    fn opendir(
        &self,
        inode: InodeId,
        _ctx: &RequestCtx,
    ) -> std::result::Result<EngineDirHandle, Errno> {
        let path = self.inode_path(inode)?;
        let record = self.fs.borrow().stat(&path).map_err(|e| map_errno(&e))?;
        if !record.is_directory() {
            return Err(Errno::ENOTDIR);
        }
        // Use the real pool inode for the dir handle so readdir can
        // call list_dir_by_inode with the authoritative pool inode.
        let real_inode = record.inode_id;
        let dh_id = self.allocate_dir_handle_id()?;
        let dh = EngineDirHandle {
            inode_id: real_inode,
            dh_id,
        };
        self.active_dir_handles
            .borrow_mut()
            .insert(dh_id, real_inode);
        Ok(dh)
    }

    fn releasedir(&self, dh: &EngineDirHandle) -> std::result::Result<(), Errno> {
        let mut active = self.active_dir_handles.borrow_mut();
        match active.get(&dh.dh_id).copied() {
            Some(inode) if inode == dh.inode_id => {
                active.remove(&dh.dh_id);
                Ok(())
            }
            _ => Err(Errno::EBADF),
        }
    }

    fn readdir(
        &self,
        dh: &EngineDirHandle,
        offset: u64,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(Vec<DirEntry>, bool), Errno> {
        self.validate_dir_handle(dh)?;

        // Validate the inode still exists and is a directory.
        let inode_id = dh.inode_id;
        let batch_limit = 128usize;
        let (entries, has_more) = {
            let fs = self.fs.borrow();
            let record = fs.inode(inode_id).map_err(|e| map_errno(&e))?;
            if !record.is_directory() {
                return Err(Errno::ENOTDIR);
            }
            fs.list_dir_by_inode_window(inode_id, offset, batch_limit)
                .map_err(|e| map_errno(&e))?
        };

        let mut dir_entries: Vec<DirEntry> = Vec::with_capacity(batch_limit);
        for (index, entry) in entries.into_iter().enumerate() {
            let cookie = offset
                .checked_add(u64::try_from(index).map_err(|_| Errno::EOVERFLOW)?)
                .and_then(|value| value.checked_add(1))
                .ok_or(Errno::EOVERFLOW)?;
            let kind = entry.kind();
            dir_entries.push(DirEntry {
                name: entry.name,
                inode_id: entry.inode_id,
                kind,
                generation: entry.generation,
                cookie,
            });
        }

        Ok((dir_entries, has_more))
    }
    fn fdatasync_inode(
        &self,
        fh: &EngineFileHandle,
        datasync: bool,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("synchronize mounted inode data")?;
        self.validate_file_handle(fh)?;
        if self.read_only {
            return Ok(());
        }
        self.fs
            .borrow_mut()
            .fdatasync_inode(fh.inode_id, datasync)
            .map_err(|e| map_errno(&e))
    }

    fn fsyncdir(
        &self,
        dh: &EngineDirHandle,
        _datasync: bool,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("synchronize mounted directory")?;
        self.validate_dir_handle(dh)?;
        if self.read_only {
            return Ok(());
        }
        let path = self.inode_path(dh.inode_id)?;
        self.fs
            .borrow_mut()
            .fsync_directory(&path)
            .map_err(|e| map_errno(&e))
    }

    fn syncfs(&self, _ctx: &RequestCtx) -> std::result::Result<(), Errno> {
        self.ensure_mounted_mutation_allowed("synchronize mounted filesystem")?;
        if self.read_only {
            return Ok(());
        }
        self.fs.borrow_mut().sync_all().map_err(|e| map_errno(&e))
    }

    // == Extended attribute operations ======================================

    fn getxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> std::result::Result<Vec<u8>, Errno> {
        if name.starts_with(b"trusted.") && ctx.uid != 0 {
            return Err(Errno::EPERM);
        }
        xattr_dispatch::engine_getxattr_by_inode(&self.fs.borrow(), inode, name)
            .map_err(xattr_dispatch::errno_from_dispatch_error)?
            .ok_or(Errno::ENODATA)
    }
    fn setxattr(
        &self,
        inode: InodeId,
        name: &[u8],
        value: &[u8],
        flags: u32,
        ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        if name.starts_with(b"trusted.") && ctx.uid != 0 {
            return Err(Errno::EPERM);
        }
        Self::validate_posix_acl_xattr_value(name, value)?;
        xattr_dispatch::engine_setxattr_by_inode(
            &mut self.fs.borrow_mut(),
            inode,
            name,
            value,
            flags,
        )
        .map_err(xattr_dispatch::errno_from_dispatch_error)
    }
    fn listxattr(&self, inode: InodeId, ctx: &RequestCtx) -> std::result::Result<Vec<u8>, Errno> {
        let names = xattr_dispatch::engine_listxattr_by_inode(&self.fs.borrow(), inode)
            .map_err(xattr_dispatch::errno_from_dispatch_error)?;

        if ctx.uid == 0 {
            return Ok(names);
        }

        // Filter trusted.* for non-root callers.
        let mut filtered = Vec::new();
        for name in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            if !name.starts_with(b"trusted.") {
                filtered.extend_from_slice(name);
                filtered.push(0);
            }
        }
        Ok(filtered)
    }
    fn removexattr(
        &self,
        inode: InodeId,
        name: &[u8],
        ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        if name.starts_with(b"trusted.") && ctx.uid != 0 {
            return Err(Errno::EPERM);
        }
        xattr_dispatch::engine_removexattr_by_inode(&mut self.fs.borrow_mut(), inode, name)
            .map_err(xattr_dispatch::errno_from_dispatch_error)
    }

    fn getlk(
        &self,
        inode: InodeId,
        lock: &LockSpec,
        _ctx: &RequestCtx,
    ) -> std::result::Result<Option<LockSpec>, Errno> {
        let requested = lock_range_from_spec(lock)?;
        let fs = self.fs.borrow();
        match fs.getlk(inode, requested) {
            Some(conflict) => {
                let existing = conflict.existing;
                let end = existing
                    .end_exclusive()
                    .map_or(u64::MAX, |e| e.saturating_sub(1));
                Ok(Some(LockSpec {
                    typ: existing.lock_type.as_fcntl() as u32,
                    whence: 0,
                    start: existing.start,
                    end,
                    pid: existing.pid,
                }))
            }
            None => Ok(None),
        }
    }

    fn setlk(
        &self,
        inode: InodeId,
        lock: &LockSpec,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        if lock.typ != LockType::Unlock.as_fcntl() as u32 {
            self.ensure_mounted_mutation_allowed("acquire mounted advisory lock")?;
        }
        let requested = lock_range_from_spec(lock)?;
        let fs = self.fs.borrow_mut();
        fs.setlk(inode, requested).map_err(|err| match err {
            FileSystemError::AdvisoryLockConflict { .. } => Errno::EAGAIN,
            other => map_errno(&other),
        })
    }
    fn setlkw(
        &self,
        inode: InodeId,
        lock: &LockSpec,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(), Errno> {
        if lock.typ != LockType::Unlock.as_fcntl() as u32 {
            self.ensure_mounted_mutation_allowed("wait for mounted advisory lock")?;
        }
        let requested = lock_range_from_spec(lock)?;
        let fs = self.fs.borrow();
        fs.lock_wait_acquire(inode, requested, Some(std::time::Duration::from_secs(30)))
            .map_err(|err| match err {
                FileSystemError::AdvisoryLockConflict { .. } => Errno::EAGAIN,
                other => map_errno(&other),
            })
    }

    fn check_write_admission(&self, byte_count: u64) -> std::result::Result<(), Errno> {
        self.ensure_writable()?;
        self.fs
            .borrow()
            .check_write_admission(byte_count)
            .map_err(|error| map_errno(&FileSystemError::from(error)))
    }

    fn defrag_file(
        &self,
        ino: InodeId,
        _ctx: &RequestCtx,
    ) -> std::result::Result<(u64, u64), Errno> {
        self.ensure_writable()?;
        let mut fs = self.fs.borrow_mut();
        let before_after = fs.defrag_extent_map(ino).map_err(|e| map_errno(&e))?;
        if before_after.1 < before_after.0 {
            fs.state.dirty_extent_maps.insert(ino);
        }
        Ok(before_after)
    }

    fn lookup_extents(
        &self,
        inode: InodeId,
        offset: u64,
        length: u64,
    ) -> Vec<tidefs_types_extent_map_core::ExtentMapEntryV2> {
        self.fs.borrow().lookup_extents(inode.get(), offset, length)
    }
}

impl VfsLocalFileSystem {
    /// Set the pool free-space low-watermark threshold in bytes.
    /// Data writes that would reduce available capacity below this
    /// threshold are refused with `ENOSPC`.  Set to 0 to disable.
    pub fn set_low_watermark_bytes(&self, bytes: u64) -> std::result::Result<(), FileSystemError> {
        self.fs.borrow_mut().set_low_watermark_bytes(bytes)
    }
}

// ── VfsEngineStatFs ───────────────────────────────────────────────────────

impl VfsEngineStatFs for VfsLocalFileSystem {
    fn statfs(&self, _ctx: &RequestCtx) -> std::result::Result<StatFs, Errno> {
        let mut fs = self.fs.borrow_mut();
        fuse_statfs::engine_statfs(&mut fs).map_err(|e| e.to_errno())
    }

    fn live_pool_admin_request(
        &self,
        request: &LivePoolAdminRequest,
    ) -> std::result::Result<LivePoolAdminResponse, Errno> {
        self.handle_live_pool_admin_request(request)
    }
}

/// Convert a LockSpec (FUSE protocol) to a LockRange (internal tracker type).
/// Returns `EINVAL` on bad whence or type.
fn lock_range_from_spec(lock: &LockSpec) -> Result<LockRange, Errno> {
    if lock.whence != 0 {
        return Err(Errno::EINVAL);
    }
    let lock_type = LockType::from_fcntl(lock.typ as u16).ok_or(Errno::EINVAL)?;
    let len = if lock.end < lock.start {
        return Err(Errno::EINVAL);
    } else if lock.end == u64::MAX {
        0
    } else {
        lock.end.saturating_sub(lock.start).saturating_add(1)
    };
    Ok(LockRange::new(lock.start, len, lock_type, 0, lock.pid))
}
// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_buffer::WriteBufferConfig;
    use crate::RootAuthenticationKey;
    use std::io::{Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tidefs_space_accounting::{DatasetQuotaConfig, DatasetQuotaHierarchy};
    use tidefs_types_reclaim_queue_core::DeadObjectEntry;
    use tidefs_types_vfs_core::{
        FileHandleId, FATTR_ATIME, FATTR_CTIME, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE,
        FATTR_UID, RENAME_EXCHANGE, RENAME_NOREPLACE, S_IFDIR, S_IFMT, S_ISGID, XATTR_CREATE,
        XATTR_REPLACE,
    };
    use tidefs_vfs_engine::VfsEngine;

    fn ctx() -> RequestCtx {
        RequestCtx {
            uid: 1000,
            gid: 1000,
            pid: 1,
            umask: 0o022,
            groups: vec![1000],
        }
    }

    fn temp_fs() -> (VfsLocalFileSystem, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = PoolDatasetOwner::open(dir.path()).expect("open");
        (VfsLocalFileSystem::new(fs), dir)
    }

    fn cached_path(engine: &VfsLocalFileSystem, inode: InodeId) -> Option<String> {
        engine.path_cache.borrow().get(&inode).cloned()
    }

    #[test]
    fn mutation_fence_refuses_vfs_configuration_and_lock_acquisition_but_allows_unlock() {
        let (mut engine, _td) = temp_fs();
        let inode = ROOT_INODE_ID;
        let write_lock = LockSpec {
            typ: LockType::Write.as_fcntl() as u32,
            whence: 0,
            start: 0,
            end: 9,
            pid: 41,
        };
        engine
            .setlk(inode, &write_lock, &ctx())
            .expect("acquire setup lock");

        engine.fs.borrow_mut().arm_mutation_reopen_fence();

        assert!(matches!(
            engine.set_timestamp_policy(TimestampPolicy::Noatime),
            Err(FileSystemError::MutationRequiresReopen { .. })
        ));
        let second_lock = LockSpec {
            start: 20,
            end: 29,
            pid: 42,
            ..write_lock.clone()
        };
        assert_eq!(
            engine.setlk(inode, &second_lock, &ctx()).unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            engine.setlkw(inode, &second_lock, &ctx()).unwrap_err(),
            Errno::EIO
        );
        let malformed_lock = LockSpec {
            typ: u32::MAX,
            whence: 1,
            ..second_lock
        };
        assert_eq!(
            engine.setlk(inode, &malformed_lock, &ctx()).unwrap_err(),
            Errno::EIO
        );
        assert_eq!(
            engine.setlkw(inode, &malformed_lock, &ctx()).unwrap_err(),
            Errno::EIO
        );

        let unlock = LockSpec {
            typ: LockType::Unlock.as_fcntl() as u32,
            ..write_lock
        };
        engine
            .setlk(inode, &unlock, &ctx())
            .expect("unlock remains available as cleanup");

        engine.read_only = true;
        assert_eq!(
            engine.setxattr(inode, b"", b"", u32::MAX, &ctx()),
            Err(Errno::EIO),
            "the reopen fence must outrank read-only and xattr validation errors"
        );
    }

    #[test]
    fn mutation_fence_precedes_sync_handle_validation() {
        let (engine, _td) = temp_fs();
        engine.fs.borrow_mut().arm_mutation_reopen_fence();

        let unknown_file =
            EngineFileHandle::new(ROOT_INODE_ID, O_RDWR, FileHandleId::new(u64::MAX), 0);
        assert_eq!(engine.flush(&unknown_file, &ctx()), Err(Errno::EIO));
        assert_eq!(engine.fsync(&unknown_file, false, &ctx()), Err(Errno::EIO));
        assert_eq!(
            engine.fdatasync_inode(&unknown_file, true, &ctx()),
            Err(Errno::EIO)
        );

        let unknown_dir = EngineDirHandle::new(ROOT_INODE_ID, DirHandleId::new(u64::MAX));
        assert_eq!(
            engine.fsyncdir(&unknown_dir, false, &ctx()),
            Err(Errno::EIO)
        );
        assert_eq!(engine.syncfs(&ctx()), Err(Errno::EIO));
    }

    #[test]
    fn fdatasync_inode_accepts_pool_placed_buffered_content() {
        let (engine, td, devices) = temp_fs_with_block_devices(2);
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("disable auto-commit for mounted fdatasync boundary");
        let root = engine.get_root_inode(&ctx()).expect("root inode");
        let (_attr, fh) = engine
            .create(root, b"pool-fdatasync.txt", 0o644, O_RDWR, &ctx())
            .expect("create file");
        let payload = b"buffered content placed through the mounted Pool";

        assert_eq!(
            engine.write(&fh, 0, payload, &ctx()).expect("buffer write"),
            payload.len() as u32,
        );
        engine
            .fdatasync_inode(&fh, true, &ctx())
            .expect("fdatasync Pool-placed content");

        assert_eq!(
            engine
                .read(&fh, 0, payload.len() as u32, &ctx())
                .expect("read Pool-placed content"),
            payload,
        );
        assert!(
            engine
                .fs
                .borrow()
                .current_content_object_exists_for_diagnostic("/pool-fdatasync.txt")
                .expect("Pool content diagnostic"),
            "fdatasync must retain a current receipt-backed content object",
        );

        // Model abrupt mount-owner death: forbid Drop from committing anything
        // that fdatasync itself did not publish, then reopen the same devices.
        engine.fs.borrow_mut().arm_mutation_reopen_fence();
        drop(engine);

        let reopened = PoolDatasetOwner::open_with_block_devices(
            td.path().join("metadata"),
            &devices,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen fdatasync block-device filesystem");
        let reopened_engine = VfsLocalFileSystem::new(reopened);
        let root = reopened_engine
            .get_root_inode(&ctx())
            .expect("reopened root inode");
        let attr = reopened_engine
            .lookup(root, b"pool-fdatasync.txt", &ctx())
            .expect("lookup fdatasync file after reopen");
        assert_eq!(attr.posix.size, payload.len() as u64);
        let fh = reopened_engine
            .open(attr.inode_id, O_RDONLY, &ctx())
            .expect("open fdatasync file after reopen");
        assert_eq!(
            reopened_engine
                .read(&fh, 0, payload.len() as u32, &ctx())
                .expect("read fdatasync file after reopen"),
            payload,
        );
    }

    #[test]
    fn mutation_fence_precedes_live_admin_validation_but_preserves_read_only_modes() {
        let (engine, _td) = temp_fs();
        engine.fs.borrow_mut().arm_mutation_reopen_fence();

        let mut create = LivePoolAdminRequest::new(LivePoolAdminCommand::DatasetCreate, "tank");
        create.version = 0;
        assert_eq!(engine.live_pool_admin_request(&create), Err(Errno::EIO));

        let performance =
            LivePoolAdminRequest::new(LivePoolAdminCommand::PerformanceAdmissionSnapshot, "tank");
        assert_eq!(
            engine.live_pool_admin_request(&performance),
            Err(Errno::EIO)
        );

        let rollback = LivePoolAdminRequest::new(LivePoolAdminCommand::SnapshotRollback, "tank");
        assert_eq!(engine.live_pool_admin_request(&rollback), Err(Errno::EIO));

        let extract = LivePoolAdminRequest::new(LivePoolAdminCommand::SnapshotExtract, "tank");
        assert_eq!(engine.live_pool_admin_request(&extract), Err(Errno::EIO));

        let send = LivePoolAdminRequest::new(LivePoolAdminCommand::SnapshotSend, "tank");
        assert_eq!(engine.live_pool_admin_request(&send), Err(Errno::EIO));

        let list = LivePoolAdminRequest::new(LivePoolAdminCommand::DatasetList, "tank");
        assert!(engine.live_pool_admin_request(&list).is_ok());

        let mut strategy =
            LivePoolAdminRequest::new(LivePoolAdminCommand::DatasetSetStrategy, "tank");
        strategy.args = live_admin_args_from_json(json!({ "name": "root", "list": true }));
        assert!(engine.live_pool_admin_request(&strategy).is_ok());
    }

    #[test]
    fn read_atime_after_reopen_persists_without_ctime() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_key = RootAuthenticationKey::demo_key();
        let file_name = b"reopen-read-atime.txt";
        let inode_id;

        {
            let local_fs = PoolDatasetOwner::open_with_root_authentication_key(
                dir.path(),
                tidefs_local_object_store::StoreOptions::test_fast(),
                root_key,
            )
            .expect("open local filesystem");
            let mut engine = VfsLocalFileSystem::new(local_fs);
            engine
                .set_timestamp_policy(TimestampPolicy::Strictatime)
                .expect("set strict-atime policy");
            let root = engine.get_root_inode(&ctx()).expect("root inode");
            let (attr, fh) = engine
                .create(root, file_name, 0o644, O_RDWR, &ctx())
                .expect("create file");
            inode_id = attr.inode_id;
            engine
                .write(&fh, 0, b"timestamp payload", &ctx())
                .expect("write payload");
            engine
                .fs
                .borrow_mut()
                .commit_if_dirty()
                .expect("commit created file");
        }

        let after_read;
        {
            let local_fs = PoolDatasetOwner::open_with_root_authentication_key(
                dir.path(),
                tidefs_local_object_store::StoreOptions::test_fast(),
                root_key,
            )
            .expect("reopen local filesystem");
            let mut engine = VfsLocalFileSystem::new(local_fs);
            engine
                .set_timestamp_policy(TimestampPolicy::Strictatime)
                .expect("set strict-atime policy");
            let root = engine.get_root_inode(&ctx()).expect("root inode");
            let before = engine.lookup(root, file_name, &ctx()).expect("lookup file");
            assert_eq!(before.inode_id, inode_id);

            std::thread::sleep(std::time::Duration::from_millis(1));
            engine
                .record_read_access(inode_id, &ctx())
                .expect("record read access");
            after_read = engine
                .getattr(inode_id, None, &ctx())
                .expect("getattr after read access");
            assert!(
                after_read.posix.atime_ns > before.posix.atime_ns,
                "strictatime read access must advance atime"
            );
            assert_eq!(
                after_read.posix.ctime_ns, before.posix.ctime_ns,
                "read access after reopen must not advance ctime"
            );
            engine
                .fs
                .borrow_mut()
                .commit_if_dirty()
                .expect("commit read atime");
        }

        let reopened = PoolDatasetOwner::open_with_root_authentication_key(
            dir.path(),
            tidefs_local_object_store::StoreOptions::test_fast(),
            root_key,
        )
        .expect("reopen after read atime commit");
        let persisted = reopened
            .stat_attr("/reopen-read-atime.txt")
            .expect("persisted file attr");
        assert_eq!(persisted.posix.atime_ns, after_read.posix.atime_ns);
        assert_eq!(persisted.posix.ctime_ns, after_read.posix.ctime_ns);
    }

    #[test]
    fn vfs_read_atime_is_visible_without_counting_deferred_mutation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_key = RootAuthenticationKey::demo_key();
        let file_name = b"deferred-read-atime.txt";

        {
            let local_fs = PoolDatasetOwner::open_with_root_authentication_key(
                dir.path(),
                tidefs_local_object_store::StoreOptions::test_fast(),
                root_key,
            )
            .expect("open local filesystem");
            let mut engine = VfsLocalFileSystem::new(local_fs);
            engine
                .set_timestamp_policy(TimestampPolicy::Strictatime)
                .expect("set strict-atime policy");
            let root = engine.get_root_inode(&ctx()).expect("root inode");
            let (_attr, fh) = engine
                .create(root, file_name, 0o644, O_RDWR, &ctx())
                .expect("create file");
            engine.write(&fh, 0, b"timestamp payload", &ctx()).unwrap();
            engine
                .fs
                .borrow_mut()
                .commit_if_dirty()
                .expect("commit setup");
        }

        let after_read;
        {
            let mut local_fs = PoolDatasetOwner::open_with_root_authentication_key(
                dir.path(),
                tidefs_local_object_store::StoreOptions::test_fast(),
                root_key,
            )
            .expect("reopen local filesystem");
            local_fs
                .set_auto_commit(false)
                .expect("test setup mutation must be admitted");
            let mut engine = VfsLocalFileSystem::new(local_fs);
            engine
                .set_timestamp_policy(TimestampPolicy::Strictatime)
                .expect("set strict-atime policy");
            let root = engine.get_root_inode(&ctx()).expect("root inode");
            let before = engine.lookup(root, file_name, &ctx()).expect("lookup file");
            let fh = engine
                .open(before.inode_id, O_RDONLY, &ctx())
                .expect("open read handle");
            let before_mutations = engine.fs.borrow().uncommitted_mutation_count();

            std::thread::sleep(std::time::Duration::from_millis(1));
            assert_eq!(engine.read(&fh, 0, 4, &ctx()).expect("read bytes"), b"time");
            after_read = engine
                .getattr(before.inode_id, None, &ctx())
                .expect("getattr after read");

            assert!(
                after_read.posix.atime_ns > before.posix.atime_ns,
                "strictatime read access must be visible through getattr"
            );
            assert_eq!(
                engine.fs.borrow().uncommitted_mutation_count(),
                before_mutations,
                "read atime should ride the existing dirty-commit path"
            );
            engine
                .fs
                .borrow_mut()
                .commit_if_dirty()
                .expect("commit read atime");
        }

        let reopened = PoolDatasetOwner::open_with_root_authentication_key(
            dir.path(),
            tidefs_local_object_store::StoreOptions::test_fast(),
            root_key,
        )
        .expect("reopen after read atime commit");
        let persisted = reopened
            .stat_attr("/deferred-read-atime.txt")
            .expect("persisted file attr");
        assert_eq!(persisted.posix.atime_ns, after_read.posix.atime_ns);
    }

    fn live_dataset_admin(engine: &VfsLocalFileSystem, operation: &str, args: Value) -> Value {
        live_admin(engine, "dataset", operation, args, false)
    }

    fn live_snapshot_admin(
        engine: &VfsLocalFileSystem,
        operation: &str,
        args: Value,
        wants_json: bool,
    ) -> Value {
        live_admin(engine, "snapshot", operation, args, wants_json)
    }

    #[cfg(feature = "replication-io")]
    fn live_from_root_hex(root: &CommittedRootSummary) -> String {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&root.transaction_id.to_le_bytes());
        bytes.extend_from_slice(&root.generation.to_le_bytes());
        bytes.extend_from_slice(&root.superblock_checksum.get().to_le_bytes());
        live_admin_hex_encode(&bytes)
    }

    fn live_device_admin(
        engine: &VfsLocalFileSystem,
        operation: &str,
        args: Value,
        wants_json: bool,
    ) -> Value {
        let command = LivePoolAdminCommand::from_parts("device", operation)
            .expect("test live device admin command");
        let mut request = LivePoolAdminRequest::new(command, "tank");
        request.output = if wants_json {
            LivePoolAdminOutput::MachineJson
        } else {
            LivePoolAdminOutput::Human
        };
        request.args = live_admin_args_from_json(args);
        let response = engine
            .shared_pool_owner()
            .handle_live_pool_owner_admin_request(&request);
        live_admin_response_to_assertion_json(response)
    }

    fn live_pool_admin(
        engine: &VfsLocalFileSystem,
        operation: &str,
        args: Value,
        wants_json: bool,
    ) -> Value {
        let command = LivePoolAdminCommand::from_parts("pool", operation)
            .expect("test live Pool admin command");
        let mut request = LivePoolAdminRequest::new(command, "tank");
        request.output = if wants_json {
            LivePoolAdminOutput::MachineJson
        } else {
            LivePoolAdminOutput::Human
        };
        request.args = live_admin_args_from_json(args);
        let response = engine
            .shared_pool_owner()
            .handle_live_pool_owner_admin_request(&request);
        live_admin_response_to_assertion_json(response)
    }

    fn live_admin(
        engine: &VfsLocalFileSystem,
        command: &str,
        operation: &str,
        args: Value,
        wants_json: bool,
    ) -> Value {
        let command =
            LivePoolAdminCommand::from_parts(command, operation).expect("test live admin command");
        let mut request = LivePoolAdminRequest::new(command, "tank");
        request.output = if wants_json {
            LivePoolAdminOutput::MachineJson
        } else {
            LivePoolAdminOutput::Human
        };
        request.args = live_admin_args_from_json(args);
        let response = engine
            .handle_live_pool_admin_request(&request)
            .expect("dispatch live admin request");
        live_admin_response_to_assertion_json(response)
    }

    fn live_admin_args_from_json(args: Value) -> LivePoolAdminArgs {
        let Value::Object(values) = args else {
            return LivePoolAdminArgs::default();
        };
        LivePoolAdminArgs(
            values
                .into_iter()
                .map(|(key, value)| (key, live_admin_arg_from_json(value)))
                .collect(),
        )
    }

    fn live_admin_arg_from_json(value: Value) -> LivePoolAdminArg {
        match value {
            Value::Null => LivePoolAdminArg::Null,
            Value::Bool(value) => LivePoolAdminArg::Bool(value),
            Value::Number(value) => value
                .as_i64()
                .map(LivePoolAdminArg::I64)
                .or_else(|| value.as_u64().map(LivePoolAdminArg::U64))
                .expect("test live admin number must fit typed arg"),
            Value::String(value) => LivePoolAdminArg::String(value),
            Value::Array(values) => {
                LivePoolAdminArg::Array(values.into_iter().map(live_admin_arg_from_json).collect())
            }
            Value::Object(values) => LivePoolAdminArg::Object(
                values
                    .into_iter()
                    .map(|(key, value)| (key, live_admin_arg_from_json(value)))
                    .collect(),
            ),
        }
    }

    fn live_admin_response_to_assertion_json(response: LivePoolAdminResponse) -> Value {
        match response.body {
            LivePoolAdminResponseBody::Empty => {
                json!({ "ok": response.exit_code == 0 })
            }
            LivePoolAdminResponseBody::Text(text) => {
                json!({ "ok": response.exit_code == 0, "text": text })
            }
            LivePoolAdminResponseBody::MachineJson(machine_json) => json!({
                "ok": response.exit_code == 0,
                "json": serde_json::from_str::<Value>(&machine_json)
                    .expect("test live admin machine JSON")
            }),
            LivePoolAdminResponseBody::BytesHex { bytes_hex, bytes } => json!({
                "ok": response.exit_code == 0,
                "bytes_hex": bytes_hex,
                "bytes": bytes
            }),
            LivePoolAdminResponseBody::Error {
                message,
                machine_json,
            } => {
                let mut value = json!({
                    "ok": false,
                    "exit_code": response.exit_code,
                    "error": message,
                });
                if let Some(machine_json) = machine_json {
                    value["json"] = serde_json::from_str::<Value>(&machine_json)
                        .expect("test live admin error machine JSON");
                }
                value
            }
        }
    }

    fn temp_fs_with_block_devices(
        device_count: usize,
    ) -> (VfsLocalFileSystem, tempfile::TempDir, Vec<PathBuf>) {
        let root = tempfile::tempdir().expect("tempdir");
        let metadata = root.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create metadata dir");
        let mut devices = Vec::with_capacity(device_count);
        for idx in 0..device_count {
            let path = root.path().join(format!("dev{idx}.img"));
            let file = std::fs::File::create(&path).expect("create device image");
            file.set_len(8 * 1024 * 1024).expect("size device image");
            devices.push(path);
        }
        let fs = PoolDatasetOwner::open_with_block_devices(
            metadata,
            &devices,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open block-device filesystem");
        (VfsLocalFileSystem::new(fs), root, devices)
    }

    fn corrupt_current_scrub_content(engine: &VfsLocalFileSystem, path: &str, payload: &[u8]) {
        assert!(!payload.is_empty(), "corruption payload must be non-empty");
        let mut fs = engine.fs.borrow_mut();
        let record = fs.stat(path).expect("stat committed scrub fixture");
        let keyspace = fs.object_keyspace();
        let manifest_key = keyspace.content(record.inode_id, record.data_version);
        let (manifest_bytes, _) = fs
            .store
            .pool()
            .get_with_current_receipt(DeviceIoClass::Data, manifest_key)
            .expect("read scrub content manifest")
            .expect("scrub content manifest exists");
        let manifest = crate::encoding::decode_content_manifest(&manifest_bytes)
            .expect("decode scrub content manifest");
        let chunk = manifest
            .chunks
            .iter()
            .find(|chunk| !chunk.is_hole())
            .expect("scrub content chunk");
        let chunk_key =
            keyspace.content_chunk(record.inode_id, chunk.data_version, chunk.chunk_index);
        let (mut encoded, _) = fs
            .store
            .pool()
            .get_with_current_receipt(DeviceIoClass::Data, chunk_key)
            .expect("read scrub content chunk")
            .expect("scrub content chunk exists");
        let payload_offset = encoded
            .windows(payload.len())
            .position(|candidate| candidate == payload)
            .expect("scrub payload appears in encoded chunk");
        encoded[payload_offset] = b'X';
        fs.store
            .pool_mut()
            .put_with_receipt(DeviceIoClass::Data, chunk_key, &encoded)
            .expect("write checksum-invalid scrub content through Pool fixture");
    }

    fn open_named_test_filesystem(
        metadata: &std::path::Path,
        devices: &[PathBuf],
        pool_name: &str,
        policy: tidefs_local_object_store::pool::PoolRedundancyPolicy,
        dataset_path: &str,
    ) -> PoolDatasetOwner {
        PoolDatasetOwner::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
            metadata,
            pool_name,
            policy,
            dataset_path,
            crate::LocalFileSystemOpenConfig {
                options: tidefs_local_object_store::StoreOptions::default(),
                allocator_policy: crate::LocalStorageAllocatorPolicy::default(),
                root_authentication_key: RootAuthenticationKey::demo_key(),
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy: crate::RecoveryPolicy::default(),
                block_devices: Some(devices),
            },
        )
        .expect("open named test filesystem")
    }

    fn fixed_offset_pool_label(path: &std::path::Path) -> Vec<u8> {
        fixed_offset_pool_label_at(path, 0)
    }

    fn fixed_offset_backup_pool_label(path: &std::path::Path) -> Vec<u8> {
        let size = std::fs::metadata(path).expect("stat device image").len();
        fixed_offset_pool_label_at(
            path,
            size - tidefs_types_pool_label_core::POOL_LABEL_SIZE as u64,
        )
    }

    fn fixed_offset_pool_label_at(path: &std::path::Path, offset: u64) -> Vec<u8> {
        let mut file = std::fs::File::open(path).expect("open device image label");
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(offset))
            .expect("seek fixed-offset pool label");
        let mut label = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
        std::io::Read::read_exact(&mut file, &mut label).expect("read fixed-offset pool label");
        label
    }

    fn remove_legacy_device_lifecycle_files(metadata: &std::path::Path) {
        for name in [
            ".tidefs_device_removal_pending",
            ".tidefs_device_removal_pending.tmp",
            ".tidefs_device_replacement_evidence",
            ".tidefs_device_replacement_evidence.tmp",
        ] {
            match std::fs::remove_file(metadata.join(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove obsolete lifecycle side file {name}: {error}"),
            }
        }
    }

    fn assert_legacy_device_lifecycle_files_absent(metadata: &std::path::Path) {
        for name in [
            ".tidefs_device_removal_pending",
            ".tidefs_device_removal_pending.tmp",
            ".tidefs_device_replacement_evidence",
            ".tidefs_device_replacement_evidence.tmp",
        ] {
            assert!(
                !metadata.join(name).exists(),
                "obsolete lifecycle side file {name} must not be recovery authority"
            );
        }
    }

    #[test]
    fn live_pool_admin_unsupported_local_command_returns_typed_error() {
        let (engine, _td) = temp_fs();
        let request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolStatus, "tank");
        let response = engine
            .handle_live_pool_admin_request(&request)
            .expect("dispatch live admin request");
        let value = live_admin_response_to_assertion_json(response);

        assert_eq!(value["ok"], false);
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["json"]["kind"], "unsupported_command");
        assert_eq!(value["json"]["command"], "pool");
        assert_eq!(value["json"]["operation"], "status");
    }

    #[test]
    fn live_pool_admin_uses_shared_owner_not_vfs_dispatch() {
        let (engine, _td) = temp_fs();

        for (command, operation) in [
            (LivePoolAdminCommand::PoolGet, "get"),
            (LivePoolAdminCommand::PoolSet, "set"),
            (LivePoolAdminCommand::PoolListProps, "list-props"),
            (LivePoolAdminCommand::PoolIntegrityCheck, "integrity-check"),
            (LivePoolAdminCommand::PoolScrub, "scrub"),
            (LivePoolAdminCommand::PoolRepair, "repair"),
        ] {
            let request = LivePoolAdminRequest::new(command, "tank");
            let vfs_response = engine
                .handle_live_pool_admin_request(&request)
                .expect("dispatch through VFS");
            let vfs_value = live_admin_response_to_assertion_json(vfs_response);
            assert_eq!(vfs_value["ok"], false);
            assert_eq!(vfs_value["json"]["kind"], "unsupported_command");
            assert_eq!(vfs_value["json"]["command"], "pool");
            assert_eq!(vfs_value["json"]["operation"], operation);
        }

        let request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolListProps, "tank");
        let owner_response = engine
            .shared_pool_owner()
            .handle_live_pool_owner_admin_request(&request);
        let owner_value = live_admin_response_to_assertion_json(owner_response);
        assert_eq!(owner_value["ok"], true);
        assert!(owner_value["text"]
            .as_str()
            .is_some_and(|output| output.contains("PROPERTY")));
    }

    #[test]
    fn live_pool_properties_use_shared_owner() {
        let (engine, _td) = temp_fs();

        let set = live_pool_admin(
            &engine,
            "set",
            json!({ "assignment": "access.readonly=on" }),
            false,
        );
        assert_eq!(set["ok"], true, "set response: {set}");

        let get = live_pool_admin(
            &engine,
            "get",
            json!({ "property": "access.readonly" }),
            false,
        );
        assert_eq!(get["ok"], true, "get response: {get}");
        assert!(get["text"]
            .as_str()
            .is_some_and(|output| output.contains("value:     on")));

        let listed = live_pool_admin(&engine, "list-props", json!({}), false);
        assert_eq!(listed["ok"], true, "list response: {listed}");
        assert!(listed["text"]
            .as_str()
            .is_some_and(|output| output.contains("access.readonly")));
    }

    #[test]
    fn live_device_admin_uses_shared_owner_not_vfs_dispatch() {
        let (engine, _td) = temp_fs();

        for (command, operation) in [
            (LivePoolAdminCommand::DeviceStatus, "status"),
            (LivePoolAdminCommand::DeviceOffline, "offline"),
            (LivePoolAdminCommand::DeviceOnline, "online"),
            (LivePoolAdminCommand::DeviceRemove, "remove"),
            (LivePoolAdminCommand::DeviceReplace, "replace"),
        ] {
            let request = LivePoolAdminRequest::new(command, "tank");
            let vfs_response = engine
                .handle_live_pool_admin_request(&request)
                .expect("dispatch through VFS");
            let vfs_value = live_admin_response_to_assertion_json(vfs_response);
            assert_eq!(vfs_value["ok"], false);
            assert_eq!(vfs_value["json"]["kind"], "unsupported_command");
            assert_eq!(vfs_value["json"]["command"], "device");
            assert_eq!(vfs_value["json"]["operation"], operation);
        }

        let request = LivePoolAdminRequest::new(LivePoolAdminCommand::DeviceStatus, "tank");
        let owner_response = engine
            .shared_pool_owner()
            .handle_live_pool_owner_admin_request(&request);
        let owner_value = live_admin_response_to_assertion_json(owner_response);
        assert_eq!(owner_value["ok"], true);
        assert!(owner_value["text"]
            .as_str()
            .is_some_and(|output| output.starts_with("device status:")));
    }

    #[test]
    fn live_performance_admission_snapshot_rejects_malformed_args() {
        let (engine, _td) = temp_fs();

        for (name, value, detail) in [
            (
                "workload",
                LivePoolAdminArg::Bool(true),
                "argument 'workload' must be a string",
            ),
            (
                "unexpected",
                LivePoolAdminArg::String("ignored".to_string()),
                "unsupported argument 'unexpected'",
            ),
        ] {
            let mut request = LivePoolAdminRequest::new(
                LivePoolAdminCommand::PerformanceAdmissionSnapshot,
                "tank",
            );
            request.args.0.insert(name.to_string(), value);
            let response = engine
                .handle_live_pool_admin_request(&request)
                .expect("dispatch live admin request");
            let response = live_admin_response_to_assertion_json(response);

            assert_eq!(response["ok"], false);
            assert_eq!(response["exit_code"], 2);
            assert_eq!(response["json"]["kind"], "malformed");
            assert!(response["error"]
                .as_str()
                .is_some_and(|message| message.contains(detail)));
        }
    }

    #[test]
    fn live_block_admin_commands_return_typed_unsupported_errors() {
        let (engine, _td) = temp_fs();

        for operation in ["attach", "send", "receive"] {
            let value = live_admin(&engine, "block", operation, json!({}), true);

            assert_eq!(value["ok"], false);
            assert_eq!(value["exit_code"], 1);
            assert_eq!(value["json"]["kind"], "unsupported_command");
            assert_eq!(value["json"]["command"], "block");
            assert_eq!(value["json"]["operation"], operation);
        }
    }

    #[test]
    fn live_dataset_create_publishes_named_volume_catalog_and_root_together() {
        let (engine, _td) = temp_fs();

        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "volume0",
                "parent": "root",
                "type": "volume",
                "size": 8192,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");
        assert!(created["text"]
            .as_str()
            .is_some_and(|text| text.contains("size=8192") && text.contains("block_size=4096")));

        let fs = engine.fs.borrow();
        let id = fs
            .dataset_catalog()
            .lookup("volume0")
            .expect("cataloged named volume");
        let reference = fs.store.dataset_root(id).expect("typed volume root");
        assert_eq!(reference.dataset_id, id);
        assert_eq!(reference.kind, tidefs_pool_runtime::DatasetRootKind::Volume);
        let volume = fs.store.open_volume("volume0").expect("open named volume");
        assert_eq!(volume.dataset_id(), id);
        assert_eq!(volume.geometry().capacity_bytes, 8192);
        assert_eq!(volume.geometry().block_size_bytes, 4096);
    }

    #[test]
    fn live_volume_reclaim_lifecycle_resizes_then_destroys_canonical_root() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "volume0",
                "parent": "root",
                "type": "volume",
                "size": 8192,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        let resized =
            live_dataset_admin(&engine, "resize", json!({"name": "volume0", "size": 16384}));
        assert_eq!(resized["ok"], true, "resize response: {resized}");
        assert!(resized["text"].as_str().is_some_and(|text| {
            text.contains("size=16384") && text.contains("resize_generation=2")
        }));
        assert_eq!(
            engine
                .fs
                .borrow()
                .open_pool_volume("volume0")
                .expect("resized volume")
                .geometry()
                .capacity_bytes,
            16384
        );

        let destroyed = live_dataset_admin(
            &engine,
            "destroy",
            json!({"name": "volume0", "force": false}),
        );
        assert_eq!(destroyed["ok"], true, "destroy response: {destroyed}");
        assert!(destroyed["text"].as_str().is_some_and(|text| {
            text.contains("logically destroyed")
                && text.contains("reclaim authority=pool-delete")
                && text.contains("pending_objects=0")
                && text.contains("secure_erasure=false")
        }));
        assert!(engine.fs.borrow().open_pool_volume("volume0").is_err());
    }

    #[test]
    fn live_volume_reclaim_snapshot_commands_restore_bytes_and_retain_snapshot() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "volume0",
                "parent": "root",
                "type": "volume",
                "size": 8192,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        {
            let mut fs = engine.fs.borrow_mut();
            let mut volume = fs.open_pool_volume("volume0").unwrap();
            fs.write_pool_volume_blocks(&mut volume, 0, &[0x11; 4096])
                .unwrap();
            fs.flush_pool_volume(&mut volume).unwrap();
        }

        let snapshot = live_snapshot_admin(
            &engine,
            "create",
            json!({"target": "volume0@before"}),
            false,
        );
        assert_eq!(snapshot["ok"], true, "snapshot response: {snapshot}");
        assert!(snapshot["text"]
            .as_str()
            .is_some_and(|text| text.contains("volume0@before") && text.contains("created")));

        let renamed = live_dataset_admin(
            &engine,
            "rename",
            json!({"old_name": "volume0", "new_name": "renamed"}),
        );
        assert_eq!(renamed["ok"], true, "rename response: {renamed}");
        let listed = live_snapshot_admin(&engine, "list", json!({}), true);
        assert_eq!(
            listed["json"]["volume_snapshots"][0]["path"],
            "renamed@before"
        );

        {
            let mut fs = engine.fs.borrow_mut();
            let mut volume = fs.open_pool_volume("renamed").unwrap();
            fs.write_pool_volume_blocks(&mut volume, 0, &[0x22; 4096])
                .unwrap();
            fs.flush_pool_volume(&mut volume).unwrap();
        }

        let rollback = live_snapshot_admin(
            &engine,
            "rollback",
            json!({"target": "renamed@before"}),
            false,
        );
        assert_eq!(rollback["ok"], true, "rollback response: {rollback}");
        let restored_bytes = {
            let fs = engine.fs.borrow();
            let volume = fs.open_pool_volume("renamed").unwrap();
            fs.read_pool_volume_blocks(&volume, 0, 1).unwrap()
        };
        assert_eq!(restored_bytes, vec![0x11; 4096]);

        let listed = live_snapshot_admin(&engine, "list", json!({}), true);
        assert_eq!(listed["ok"], true, "list response: {listed}");
        assert_eq!(
            listed["json"]["volume_snapshots"][0]["path"],
            "renamed@before"
        );

        let destroyed = live_snapshot_admin(
            &engine,
            "destroy",
            json!({"target": "renamed@before"}),
            true,
        );
        assert_eq!(destroyed["ok"], true, "destroy response: {destroyed}");
        assert_eq!(destroyed["json"]["reclaim"]["authority"], "pool-delete");
        assert!(destroyed["json"]["reclaim"]["candidate_objects"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(destroyed["json"]["reclaim"]["pending_objects"], 0);
        assert_eq!(destroyed["json"]["reclaim"]["pending_plans"], 0);
        assert_eq!(destroyed["json"]["reclaim"]["secure_erasure"], false);
        assert!(engine
            .fs
            .borrow()
            .list_volume_snapshot_datasets()
            .unwrap()
            .is_empty());

        let filesystem_snapshot = live_snapshot_admin(
            &engine,
            "create",
            json!({"name": "filesystem-before"}),
            false,
        );
        assert_eq!(
            filesystem_snapshot["ok"], true,
            "filesystem snapshot response: {filesystem_snapshot}"
        );
        let listed = live_snapshot_admin(&engine, "list", json!({}), true);
        assert_eq!(listed["json"]["snapshots"][0]["name"], "filesystem-before");
        let filesystem_destroy = live_snapshot_admin(
            &engine,
            "destroy",
            json!({"name": "filesystem-before"}),
            false,
        );
        assert_eq!(
            filesystem_destroy["ok"], true,
            "filesystem snapshot destroy response: {filesystem_destroy}"
        );
    }

    #[test]
    fn live_volume_reclaim_clone_is_writable_cow_and_filesystem_aliases_are_refused() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "source",
                "parent": "root",
                "type": "volume",
                "size": 8192,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        {
            let mut fs = engine.fs.borrow_mut();
            let mut volume = fs.open_pool_volume("source").unwrap();
            fs.write_pool_volume_blocks(&mut volume, 0, &[0x11; 4096])
                .unwrap();
            fs.flush_pool_volume(&mut volume).unwrap();
        }
        let snapshot =
            live_snapshot_admin(&engine, "create", json!({"target": "source@base"}), false);
        assert_eq!(snapshot["ok"], true, "snapshot response: {snapshot}");

        let disposable = live_snapshot_admin(
            &engine,
            "clone-create",
            json!({"clone": "disposable", "source": "source@base"}),
            false,
        );
        assert_eq!(disposable["ok"], true, "clone response: {disposable}");
        let deleted = live_snapshot_admin(
            &engine,
            "clone-delete",
            json!({"clone": "disposable"}),
            true,
        );
        assert_eq!(deleted["ok"], true, "clone delete response: {deleted}");
        assert_eq!(deleted["json"]["reclaim"]["authority"], "pool-delete");
        assert_eq!(deleted["json"]["reclaim"]["pending_objects"], 0);
        assert_eq!(deleted["json"]["reclaim"]["pending_plans"], 0);
        assert_eq!(deleted["json"]["reclaim"]["secure_erasure"], false);

        let clone = live_snapshot_admin(
            &engine,
            "clone-create",
            json!({"clone": "clone", "source": "source@base"}),
            true,
        );
        assert_eq!(clone["ok"], true, "clone response: {clone}");
        assert_eq!(clone["json"]["clone"]["path"], "clone");
        assert_eq!(clone["json"]["clone"]["source_snapshot"], "source@base");
        assert_eq!(clone["json"]["clone"]["kind"], "volume");
        assert_eq!(clone["json"]["clone"]["promoted"], false);

        {
            let mut fs = engine.fs.borrow_mut();
            let source = fs.open_pool_volume("source").unwrap();
            let mut clone = fs.open_pool_volume("clone").unwrap();
            assert_eq!(
                fs.read_pool_volume_blocks(&clone, 0, 1).unwrap(),
                vec![0x11; 4096]
            );
            fs.write_pool_volume_blocks(&mut clone, 0, &[0x22; 4096])
                .unwrap();
            fs.flush_pool_volume(&mut clone).unwrap();
            assert_eq!(
                fs.read_pool_volume_blocks(&source, 0, 1).unwrap(),
                vec![0x11; 4096]
            );
        }

        let retained =
            live_snapshot_admin(&engine, "destroy", json!({"target": "source@base"}), false);
        assert_eq!(retained["ok"], false, "snapshot destroy: {retained}");
        assert!(retained["error"]
            .as_str()
            .is_some_and(|error| error.contains("lineage")));

        let promoted =
            live_snapshot_admin(&engine, "clone-promote", json!({"clone": "clone"}), true);
        assert_eq!(promoted["ok"], true, "promote response: {promoted}");
        assert_eq!(promoted["json"]["clone"]["promoted"], true);
        assert_eq!(
            live_snapshot_admin(&engine, "destroy", json!({"target": "source@base"}), false,)["ok"],
            true
        );
        {
            let fs = engine.fs.borrow();
            let clone = fs.open_pool_volume("clone").unwrap();
            assert_eq!(
                fs.read_pool_volume_blocks(&clone, 0, 1).unwrap(),
                vec![0x22; 4096]
            );
        }

        assert_eq!(
            live_snapshot_admin(
                &engine,
                "create",
                json!({"name": "filesystem-before"}),
                false,
            )["ok"],
            true
        );
        let unsupported = live_snapshot_admin(
            &engine,
            "clone-create",
            json!({"clone": "not-a-dataset", "source": "filesystem-before"}),
            false,
        );
        assert_eq!(unsupported["ok"], false);
        assert!(unsupported["error"].as_str().is_some_and(|error| {
            error.contains("metadata aliases") && error.contains("not independently writable")
        }));
    }

    #[test]
    fn live_filesystem_rollback_discards_post_snapshot_path_projection() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let snapshot = live_snapshot_admin(
            &engine,
            "create",
            json!({"name": "before-extra-path"}),
            false,
        );
        assert_eq!(snapshot["ok"], true, "snapshot response: {snapshot}");

        let (post_snapshot, _fh) = engine
            .create(root, b"after-snapshot", 0o644, O_RDWR, &ctx())
            .unwrap();
        assert_eq!(
            cached_path(&engine, post_snapshot.inode_id).as_deref(),
            Some("/after-snapshot")
        );

        let rollback = live_snapshot_admin(
            &engine,
            "rollback",
            json!({"name": "before-extra-path"}),
            false,
        );
        assert_eq!(rollback["ok"], true, "rollback response: {rollback}");
        assert_eq!(cached_path(&engine, ROOT_INODE_ID).as_deref(), Some("/"));
        assert_eq!(cached_path(&engine, post_snapshot.inode_id), None);
        assert_eq!(
            engine.inode_path(post_snapshot.inode_id),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn live_dataset_create_refuses_rootless_or_invalid_objects() {
        let (engine, _td) = temp_fs();

        for (name, args, expected) in [
            (
                "filesystem0",
                json!({
                    "name": "filesystem0",
                    "parent": "root",
                    "type": "filesystem",
                    "sync": "local",
                }),
                "filesystem engine can publish its typed root",
            ),
            (
                "snapshot0",
                json!({
                    "name": "snapshot0",
                    "parent": "root",
                    "type": "snapshot",
                    "sync": "local",
                }),
                "owning filesystem or volume engine",
            ),
            (
                "missing-size",
                json!({
                    "name": "missing-size",
                    "parent": "root",
                    "type": "volume",
                    "sync": "local",
                }),
                "--size <bytes> is required",
            ),
            (
                "zero-size",
                json!({
                    "name": "zero-size",
                    "parent": "root",
                    "type": "volume",
                    "size": 0,
                    "sync": "local",
                }),
                "nonzero and aligned to 4096 bytes",
            ),
            (
                "misaligned-size",
                json!({
                    "name": "misaligned-size",
                    "parent": "root",
                    "type": "volume",
                    "size": 4097,
                    "sync": "local",
                }),
                "nonzero and aligned to 4096 bytes",
            ),
        ] {
            let refused = live_dataset_admin(&engine, "create", args);
            assert_eq!(refused["ok"], false, "{name} response: {refused}");
            assert!(
                refused["error"]
                    .as_str()
                    .is_some_and(|error| error.contains(expected)),
                "{name} response did not contain {expected:?}: {refused}",
            );
            assert!(!engine.fs.borrow().dataset_catalog().contains(name));
        }
    }

    #[test]
    fn live_dataset_properties_use_pool_local_catalog_path() {
        let (engine, _td) = temp_fs();

        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "demo",
                "parent": "root",
                "type": "volume",
                "size": 4096,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true);

        let set = live_dataset_admin(
            &engine,
            "set",
            json!({
                "name": "demo",
                "assignment": "access.readonly=on",
            }),
        );
        assert_eq!(set["ok"], true, "set response: {set}");

        let get = live_dataset_admin(
            &engine,
            "get",
            json!({
                "name": "demo",
                "property": "access.readonly",
            }),
        );
        assert_eq!(get["ok"], true, "get response: {get}");
        assert!(
            get["text"]
                .as_str()
                .is_some_and(|text| text.contains("source:    local")),
            "expected local property source, got {get}",
        );

        let fs = engine.fs.borrow();
        let key = tidefs_dataset_properties::PropertyKey::new("access.readonly");
        assert!(fs.dataset_catalog().contains("demo"));
        assert!(!fs.dataset_catalog().contains("tank/demo"));
        assert!(
            fs.dataset_catalog()
                .get_properties("demo")
                .expect("demo properties")
                .get(&key)
                .is_some(),
            "property should be stored on pool-local dataset path",
        );
    }

    #[test]
    fn live_pool_integrity_check_uses_mounted_owner_state() {
        let (engine, _td) = temp_fs();
        {
            let mut fs = engine.fs.borrow_mut();
            fs.create_file("/live.txt", 0o644)
                .expect("create live file");
            fs.write_file("/live.txt", 0, b"live owner integrity check")
                .expect("write live file");
            fs.sync_all().expect("sync live file");
        }

        let checked = live_pool_admin(
            &engine,
            "integrity-check",
            json!({
                "backing_dir": "/run/tidefs/pools/ignored-by-owner",
                "devices": ["/dev/ignored-by-owner"],
                "max_records": 4,
                "max_bytes": 4096,
            }),
            true,
        );

        assert_eq!(checked["ok"], true, "integrity response: {checked}");
        let report = &checked["json"];
        assert_eq!(report["state_source"], "live-owner");
        assert_eq!(report["owner_state"], "mounted PoolDatasetOwner");
        assert_eq!(report["offline_inputs_ignored"], true);
        assert_eq!(report["requested_limits"]["applied"], false);
        assert_eq!(report["statfs"]["available"], true);
        assert!(report["filesystem"]["file_count"].as_u64().unwrap_or(0) >= 1);
        assert!(
            report["object_store"]["live_objects"].as_u64().unwrap_or(0) > 0,
            "live owner report should reflect mounted object-store state: {report}"
        );

        {
            let mut fs = engine.fs.borrow_mut();
            let generation = fs.stats().filesystem_generation.saturating_add(1);
            fs.store
                .publish_dataset_root(
                    tidefs_pool_runtime::ROOT_DATASET_ID,
                    tidefs_pool_runtime::DatasetRootKind::Filesystem,
                    generation,
                    b"invalid mounted canonical root",
                )
                .expect("publish invalid mounted canonical root");
        }

        let failed_json = live_pool_admin(&engine, "integrity-check", json!({}), true);
        assert_eq!(failed_json["ok"], false, "failed response: {failed_json}");
        assert_eq!(failed_json["json"]["pass"], false);
        assert_eq!(failed_json["json"]["state_source"], "live-owner");
        assert_eq!(failed_json["json"]["statfs"]["available"], false);
        assert!(failed_json["json"]["statfs"]["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()));
        assert_eq!(failed_json["json"]["verifier"]["root_slot_count"], 1);
        assert_eq!(failed_json["json"]["verifier"]["root_candidates_seen"], 1);
        assert!(
            failed_json["json"]["verifier"]["issues"]
                .as_array()
                .is_some_and(|issues| !issues.is_empty()),
            "failed report should retain verifier issues: {failed_json}"
        );

        let failed_human = live_pool_admin(&engine, "integrity-check", json!({}), false);
        assert_eq!(failed_human["ok"], false, "failed response: {failed_human}");
        assert!(
            failed_human["text"]
                .as_str()
                .is_some_and(|text| text.contains("pass:          no") && text.contains("issues:")),
            "human report should retain failed findings: {failed_human}"
        );
    }

    #[test]
    fn live_pool_scrub_scans_current_pool_content_and_reports_corruption() {
        let (engine, _td, _devices) = temp_fs_with_block_devices(2);
        let payload = b"TideFS-live-owner-scrub-corruption-fixture";
        {
            let mut fs = engine.fs.borrow_mut();
            fs.create_file("/scrub.txt", 0o644)
                .expect("create scrub fixture");
            fs.write_file("/scrub.txt", 0, payload)
                .expect("write scrub fixture");
            fs.sync_all().expect("commit scrub fixture");
        }

        let clean = live_pool_admin(&engine, "scrub", json!({}), true);
        assert_eq!(clean["ok"], true, "clean scrub response: {clean}");
        let clean_report = &clean["json"];
        assert_eq!(clean_report["pass"], true);
        assert_eq!(clean_report["state_source"], "live-owner");
        assert_eq!(clean_report["repair_attempted"], false);
        assert_eq!(clean_report["repair_writeback"], false);
        assert!(
            clean_report["blocks_scanned"].as_u64().unwrap_or(0) > 0,
            "clean scrub must scan committed content: {clean}"
        );

        corrupt_current_scrub_content(&engine, "/scrub.txt", payload);

        let failed = live_pool_admin(&engine, "scrub", json!({}), true);
        assert_eq!(failed["ok"], false, "corrupt scrub response: {failed}");
        let failed_report = &failed["json"];
        assert_eq!(failed_report["pass"], false);
        assert_eq!(failed_report["state_source"], "live-owner");
        assert_eq!(failed_report["repair_attempted"], false);
        assert_eq!(failed_report["repair_writeback"], false);
        assert!(
            failed_report["blocks_corrupt"].as_u64().unwrap_or(0)
                + failed_report["blocks_unreadable"].as_u64().unwrap_or(0)
                > 0,
            "corrupt scrub must retain failed counters: {failed}"
        );
        let finding = failed_report["findings"]
            .as_array()
            .and_then(|findings| findings.first())
            .expect("corrupt scrub finding");
        assert!(finding["block_id"]["inode_id"].as_u64().unwrap_or(0) > 0);
        assert!(finding["object_key"]
            .as_str()
            .is_some_and(|key| !key.is_empty()));
        assert!(
            finding["outcome"]["kind"] == "corrupt" || finding["outcome"]["kind"] == "unreadable",
            "corrupt scrub must classify its finding: {finding}"
        );

        let failed_human = live_pool_admin(&engine, "scrub", json!({}), false);
        assert_eq!(
            failed_human["ok"], false,
            "human scrub response: {failed_human}"
        );
        assert!(
            failed_human["text"].as_str().is_some_and(|text| {
                text.contains("pool scrub: tank")
                    && text.contains("pass:        no")
                    && text.contains("repair:      not attempted")
                    && text.contains("inode=")
            }),
            "human scrub must preserve detailed failed findings: {failed_human}"
        );
    }

    #[test]
    #[cfg(feature = "data-policy")]
    fn live_dataset_set_strategy_updates_mounted_feature_flags() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "demo",
                "parent": "root",
                "type": "volume",
                "size": 4096,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        let set = live_dataset_admin(
            &engine,
            "set-strategy",
            json!({
                "name": "demo",
                "enable": ["org.tidefs:compression_lz4"],
                "disable": [],
                "list": false,
                "class": "auto",
            }),
        );

        assert_eq!(set["ok"], true, "set-strategy response: {set}");
        let feature = FeatureName::from_str("org.tidefs:compression_lz4").unwrap();
        assert!(
            engine.fs.borrow().feature_flags().is_enabled(&feature),
            "feature should be enabled through live owner path",
        );
    }

    #[test]
    fn live_dataset_upgrade_uses_mounted_feature_flags() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "demo",
                "parent": "root",
                "type": "volume",
                "size": 4096,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        let upgraded = live_dataset_admin(
            &engine,
            "upgrade",
            json!({
                "name": "demo",
            }),
        );

        assert_eq!(upgraded["ok"], true, "upgrade response: {upgraded}");
        let supported = tidefs_dataset_feature_flags::SupportedFeaturesV1::current();
        let fs = engine.fs.borrow();
        for feature in supported
            .as_slice()
            .iter()
            .filter(|feature| crate::feature_available_in_current_build(feature))
        {
            assert!(
                fs.feature_flags().is_enabled(feature),
                "supported feature {feature} should be enabled",
            );
        }
    }

    #[test]
    fn live_device_remove_commits_topology_and_reopens_survivor() {
        let (engine, td, devices) = temp_fs_with_block_devices(2);
        let payload = b"live owner device remove keeps receipt-backed data reachable";
        let (target_path, target_guid, object_key) = {
            let mut fs = engine.fs.borrow_mut();
            // Device zero also owns raw filesystem transaction metadata. Pick
            // a receipt-backed object placed on the other member so this test
            // isolates the mounted device-removal boundary.
            let mut selected = None;
            for candidate in 0..64 {
                let object_key = tidefs_local_object_store::ObjectKey::from_name(
                    format!("mounted-live-owner-device-removal-data-{candidate}").as_bytes(),
                );
                fs.store
                    .pool_mut()
                    .put(
                        tidefs_local_object_store::DeviceIoClass::Data,
                        object_key,
                        payload,
                    )
                    .expect("write receipt-backed data through mounted pool owner");
                let receipt = fs
                    .store
                    .pool()
                    .placement_receipt_for_key(
                        tidefs_local_object_store::DeviceIoClass::Data,
                        object_key,
                    )
                    .expect("load data placement receipt")
                    .expect("written data has placement receipt");
                assert_eq!(receipt.targets.len(), 1, "test expects one receipt target");
                let target = receipt.targets.first().expect("data receipt target");
                let target_index = target.device_index as usize;
                if target_index != 0 {
                    selected = Some((
                        devices
                            .get(target_index)
                            .expect("receipt target maps to configured device")
                            .clone(),
                        target.device_guid,
                        object_key,
                    ));
                    break;
                }
            }
            fs.store
                .pool_mut()
                .sync_all()
                .expect("sync receipt-backed data before removal");
            assert_eq!(fs.store.pool().stats().device_count, 2);
            selected.expect("planner must place a bounded candidate on the non-primary device")
        };
        let original_labels: Vec<_> = devices
            .iter()
            .map(|path| fixed_offset_pool_label(path))
            .collect();
        let metadata = td.path().join("metadata");

        let removed = live_device_admin(
            &engine,
            "remove",
            json!({
                "device_path": target_path.display().to_string(),
                "force": false,
            }),
            true,
        );

        assert_eq!(removed["ok"], true, "remove response: {removed}");
        assert_eq!(removed["json"]["status"], "removed");
        assert_eq!(removed["json"]["topology_committed"], true);
        assert_eq!(removed["json"]["objects_failed"], 0);
        assert!(
            removed["json"]["objects_evacuated"]
                .as_u64()
                .is_some_and(|count| count > 0),
            "evacuation count must be numeric and nonzero: {removed}"
        );
        assert!(
            removed["json"]["bytes_evacuated"]
                .as_u64()
                .is_some_and(|count| count >= payload.len() as u64),
            "evacuated byte count must cover the selected content: {removed}"
        );
        assert_eq!(removed["json"]["remaining_devices"], 1);
        assert_eq!(removed["json"]["remanence_guarantee"], false);
        assert!(
            removed["json"]["message"].as_str().is_some_and(|message| {
                message.contains("receipt-backed evacuation")
                    && message.contains("durable survivor topology commit")
                    && message.contains("does not establish secure erase")
                    && message.contains("media-remanence")
                    && message.contains("decommissioning guarantees")
            }),
            "success response must report committed authority and its remanence limit: {removed}"
        );
        assert_legacy_device_lifecycle_files_absent(&metadata);

        let fs = engine.fs.borrow();
        assert_eq!(fs.store.pool().stats().device_count, 1);
        assert_eq!(
            fs.store
                .pool()
                .get(tidefs_local_object_store::DeviceIoClass::Data, object_key)
                .expect("read after live removal"),
            Some(payload.to_vec())
        );
        let survivor_receipt = fs
            .store
            .pool()
            .placement_receipt_for_key(tidefs_local_object_store::DeviceIoClass::Data, object_key)
            .expect("load survivor receipt after live removal")
            .expect("survivor receipt exists after live removal");
        assert!(
            survivor_receipt
                .targets
                .iter()
                .all(|target| target.device_guid != target_guid),
            "current receipt must exclude the detached device"
        );
        fs.stat("/").expect("mounted namespace remains readable");
        drop(fs);

        let target_index = devices
            .iter()
            .position(|path| path == &target_path)
            .expect("removed path belongs to configured devices");
        let survivor_index = (0..devices.len())
            .find(|index| *index != target_index)
            .expect("one survivor remains");
        let survivor_path = devices[survivor_index].clone();
        let original_target =
            tidefs_types_pool_label_core::decode_label(&original_labels[target_index])
                .expect("decode original target topology");
        for retired_bytes in [
            fixed_offset_pool_label(&target_path),
            fixed_offset_backup_pool_label(&target_path),
        ] {
            let retired = tidefs_types_pool_label_core::decode_label(&retired_bytes)
                .expect("decode retired-member label");
            let roster = tidefs_types_pool_label_core::decode_topology_roster_v1(&retired_bytes)
                .expect("decode retired-member roster")
                .expect("retired member retains predecessor roster");
            let lifecycle = tidefs_types_pool_label_core::decode_pool_lifecycle_v1(&retired_bytes)
                .expect("decode retired-member lifecycle")
                .expect("retired member retains removal intent");
            assert_eq!(retired.device_guid, original_target.device_guid);
            assert_eq!(retired.device_index, original_target.device_index);
            assert_eq!(retired.device_count, original_target.device_count);
            assert_eq!(
                retired.topology_generation,
                original_target.topology_generation
            );
            assert_eq!(roster.len(), devices.len());
            assert_eq!(roster.member_guid(target_index), Some(target_guid));
            assert_eq!(
                lifecycle.kind(),
                tidefs_types_pool_label_core::PoolLifecycleKindV1::DeviceRemoval
            );
        }

        let expected_generation = removed["json"]["topology_generation"]
            .as_u64()
            .expect("numeric topology generation");
        let survivor_primary = fixed_offset_pool_label(&survivor_path);
        let survivor_backup = fixed_offset_backup_pool_label(&survivor_path);
        for label_bytes in [&survivor_primary, &survivor_backup] {
            let label = tidefs_types_pool_label_core::decode_label(label_bytes)
                .expect("decode committed survivor label copy");
            let roster = tidefs_types_pool_label_core::decode_topology_roster_v1(label_bytes)
                .expect("decode committed survivor roster")
                .expect("survivor label has topology roster");
            assert_eq!(label.device_count, 1);
            assert_eq!(label.device_index, 0);
            assert_eq!(label.topology_generation, expected_generation);
            assert_eq!(roster.len(), 1);
            assert_ne!(roster.member_guid(0), Some(target_guid));
        }
        drop(engine);

        let reopened = PoolDatasetOwner::open_with_block_devices(
            &metadata,
            std::slice::from_ref(&survivor_path),
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen committed survivor-only topology");
        assert_legacy_device_lifecycle_files_absent(&metadata);
        assert_eq!(reopened.store.pool().stats().device_count, 1);
        assert_eq!(
            reopened
                .store
                .pool()
                .get(tidefs_local_object_store::DeviceIoClass::Data, object_key)
                .expect("read after survivor-only reopen"),
            Some(payload.to_vec())
        );
        let reopened_receipt = reopened
            .store
            .pool()
            .placement_receipt_for_key(tidefs_local_object_store::DeviceIoClass::Data, object_key)
            .expect("load receipt after survivor-only reopen")
            .expect("receipt exists after survivor-only reopen");
        assert!(
            reopened_receipt
                .targets
                .iter()
                .all(|target| target.device_guid != target_guid),
            "reopen must retain survivor receipt authority"
        );
        reopened
            .stat("/")
            .expect("reopened mounted namespace remains readable");
    }

    #[test]
    fn live_device_replace_json_refusal_is_structured() {
        let (engine, td, devices) = temp_fs_with_block_devices(2);
        let refused = live_device_admin(
            &engine,
            "replace",
            json!({
                "old_device_path": devices[0].display().to_string(),
                "new_device_path": devices[0].display().to_string(),
            }),
            true,
        );

        assert_eq!(refused["ok"], false, "replacement refusal: {refused}");
        assert_eq!(refused["json"]["status"], "refused");
        assert_eq!(
            refused["json"]["old_device_path"],
            devices[0].display().to_string()
        );
        assert_eq!(
            refused["json"]["new_device_path"],
            devices[0].display().to_string()
        );
        assert_eq!(refused["json"]["old_device_guid"], Value::Null);
        assert_eq!(refused["json"]["new_device_guid"], Value::Null);
        assert_eq!(refused["json"]["topology_committed"], false);
        assert_eq!(refused["json"]["old_device_detach_allowed"], false);
        assert_eq!(refused["json"]["media_privacy_claimed"], false);
        assert_eq!(refused["json"]["secure_erase_claimed"], false);
        assert_eq!(refused["json"]["sanitization_claimed"], false);
        assert_eq!(refused["json"]["decommissioning_claimed"], false);
        assert_eq!(engine.fs.borrow().store.pool().stats().device_count, 2);
        drop(engine);
        drop(td);
    }

    #[test]
    fn live_device_offline_and_online_report_member_state_and_gate_writes() {
        let td = tempfile::tempdir().expect("administrative device fixture");
        let metadata = td.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create administrative metadata dir");
        let devices = [td.path().join("dev0.img"), td.path().join("dev1.img")];
        for path in &devices {
            let file = std::fs::File::create(path).expect("create administrative device image");
            file.set_len(16 * 1024 * 1024)
                .expect("size administrative device image");
        }
        let policy = tidefs_local_object_store::pool::PoolRedundancyPolicy::replicated(2);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &devices,
            "live-device-offline",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("create administrative device filesystem");
        let payload = b"mounted bytes remain readable while one member is offline";
        filesystem
            .create_file("/offline.bin", 0o600)
            .expect("create administrative test file");
        filesystem
            .write_file("/offline.bin", 0, payload)
            .expect("write administrative test file");
        filesystem
            .sync_all()
            .expect("sync administrative test file");
        let target_guid = filesystem.store.pool().topology_status().members[0].device_guid;
        let target_guid_hex = live_admin_hex_encode(&target_guid);
        let engine = VfsLocalFileSystem::new(filesystem);
        let root = engine.get_root_inode(&ctx()).expect("administrative root");
        let existing = engine
            .lookup(root, b"offline.bin", &ctx())
            .expect("lookup administrative test file");
        let existing_fh = engine
            .open(existing.inode_id, O_RDWR, &ctx())
            .expect("open administrative test file");

        let offline = live_device_admin(
            &engine,
            "offline",
            json!({ "device_guid": target_guid_hex.clone() }),
            true,
        );
        assert_eq!(offline["ok"], true, "offline response: {offline}");
        assert_eq!(offline["json"]["status"], "completed");
        assert_eq!(offline["json"]["operational_state"], "Offline");
        assert_eq!(offline["json"]["pool_health"], "Degraded");
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_file("/offline.bin")
                .expect("read mounted bytes with one member offline"),
            payload
        );
        assert_eq!(engine.check_write_admission(1), Err(Errno::EIO));
        assert!(matches!(
            engine.create(root, b"offline-refused.bin", 0o600, O_RDWR, &ctx()),
            Err(Errno::EIO)
        ));
        assert!(matches!(
            engine.lookup(root, b"offline-refused.bin", &ctx()),
            Err(Errno::ENOENT)
        ));
        assert_eq!(
            engine.write(&existing_fh, 0, b"must refuse", &ctx()),
            Err(Errno::EIO)
        );
        assert_eq!(
            engine
                .read(&existing_fh, 0, payload.len() as u32, &ctx())
                .expect("read unchanged mounted bytes after refused write"),
            payload
        );
        assert_eq!(
            engine.fs.borrow().mounted_mutation_quiescence_failure(),
            None,
            "offline read and refused mutations must leave a clean exportable owner"
        );

        let status = live_device_admin(&engine, "status", json!({}), true);
        assert_eq!(status["ok"], true, "status response: {status}");
        assert_eq!(status["json"]["members"][0]["device_guid"], target_guid_hex);
        assert_eq!(status["json"]["members"][0]["operational_state"], "Offline");

        let mut filesystem = engine.into_inner();
        filesystem
            .close_mounted()
            .expect("clean offline owner closes without manufacturing a write");
        drop(filesystem);
        let filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &devices,
            "live-device-offline",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen clean offline owner");
        let engine = VfsLocalFileSystem::new(filesystem);
        let persisted = live_device_admin(&engine, "status", json!({}), true);
        assert_eq!(
            persisted["ok"], true,
            "reopened status response: {persisted}"
        );
        assert_eq!(
            persisted["json"]["members"][0]["device_guid"],
            target_guid_hex
        );
        assert_eq!(
            persisted["json"]["members"][0]["operational_state"],
            "Offline"
        );

        let online = live_device_admin(
            &engine,
            "online",
            json!({ "device_guid": target_guid_hex.clone() }),
            true,
        );
        assert_eq!(online["ok"], true, "online response: {online}");
        assert_eq!(online["json"]["operational_state"], "Online");
        assert_eq!(online["json"]["pool_health"], "Online");
        assert!(online["json"]["verified_receipts"].as_u64().unwrap() > 0);
        let (_, resumed_fh) = engine
            .create(root, b"online-admitted.bin", 0o600, O_RDWR, &ctx())
            .expect("create resumes after verified readmission");
        assert_eq!(
            engine
                .write(&resumed_fh, 0, b"now admitted", &ctx())
                .expect("write resumes after verified readmission"),
            b"now admitted".len() as u32
        );
    }

    #[test]
    fn live_device_replace_rebuilds_mounted_bytes_and_reopens_new_topology() {
        let td = tempfile::tempdir().expect("replacement fixture");
        let metadata = td.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create replacement metadata dir");
        let old_devices = [td.path().join("dev0.img"), td.path().join("dev1.img")];
        let replacement = td.path().join("replacement.img");
        for path in old_devices.iter().chain(std::iter::once(&replacement)) {
            let file = std::fs::File::create(path).expect("create replacement device image");
            file.set_len(16 * 1024 * 1024)
                .expect("size replacement device image");
        }
        let policy = tidefs_local_object_store::pool::PoolRedundancyPolicy::replicated(2);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "live-device-replace",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("create replicated mounted filesystem");
        let payload = b"mounted replacement keeps exact committed bytes";
        filesystem
            .create_file("/replace.bin", 0o600)
            .expect("create replacement test file");
        filesystem
            .write_file("/replace.bin", 0, payload)
            .expect("write replacement test file");
        filesystem.sync_all().expect("commit replacement test file");
        filesystem
            .create_filesystem_dataset(
                "other",
                DatasetId::from_bytes([0xD6; 16]),
                Vec::new(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .expect("create independently rooted replacement filesystem");
        drop(filesystem);
        let independent_payload = b"replacement preserves independent filesystem bytes";
        let mut independent = open_named_test_filesystem(
            &metadata,
            &old_devices,
            "live-device-replace",
            policy,
            "other",
        );
        independent
            .create_file("/independent.bin", 0o600)
            .expect("create independent replacement file");
        independent
            .write_file("/independent.bin", 0, independent_payload)
            .expect("write independent replacement file");
        independent
            .sync_all()
            .expect("commit independent replacement file");
        drop(independent);
        let filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "live-device-replace",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen root filesystem for replacement");
        let engine = VfsLocalFileSystem::new(filesystem);

        let replaced = live_device_admin(
            &engine,
            "replace",
            json!({
                "old_device_path": old_devices[0].display().to_string(),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(replaced["ok"], true, "replace response: {replaced}");
        assert_eq!(replaced["json"]["status"], "completed");
        assert_eq!(replaced["json"]["topology_committed"], true);
        assert_eq!(replaced["json"]["objects_failed"], 0);
        assert_eq!(replaced["json"]["old_device_detach_allowed"], true);
        assert_eq!(replaced["json"]["media_privacy_claimed"], false);
        assert_eq!(replaced["json"]["secure_erase_claimed"], false);
        assert_eq!(replaced["json"]["sanitization_claimed"], false);
        assert_eq!(replaced["json"]["decommissioning_claimed"], false);
        assert_legacy_device_lifecycle_files_absent(&metadata);
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_file("/replace.bin")
                .expect("read through live owner after replacement"),
            payload
        );
        drop(engine);

        let reopened = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &[replacement.clone(), old_devices[1].clone()],
            "live-device-replace",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen replacement plus survivor");
        assert_eq!(
            reopened
                .read_file("/replace.bin")
                .expect("read exact bytes after replacement reimport"),
            payload
        );
        drop(reopened);
        let independent = open_named_test_filesystem(
            &metadata,
            &[replacement, old_devices[1].clone()],
            "live-device-replace",
            policy,
            "other",
        );
        assert_eq!(
            independent
                .read_file("/independent.bin")
                .expect("read independent bytes after replacement reimport"),
            independent_payload
        );
    }

    #[test]
    fn missing_member_rebuild_is_scoped_to_recovery_only_read_only_owner() {
        let td = tempfile::tempdir().expect("missing-member rebuild fixture");
        let metadata = td.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create rebuild metadata dir");
        let old_devices = [td.path().join("dev0.img"), td.path().join("dev1.img")];
        let replacement = td.path().join("replacement.img");
        for path in old_devices.iter().chain(std::iter::once(&replacement)) {
            let file = std::fs::File::create(path).expect("create rebuild device image");
            file.set_len(16 * 1024 * 1024)
                .expect("size rebuild device image");
        }
        let policy = tidefs_local_object_store::pool::PoolRedundancyPolicy::replicated(2);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "missing-member-rebuild",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("create two-copy mounted filesystem");
        let payload = b"recovery-only rebuild preserves exact mounted bytes";
        filesystem
            .create_file("/rebuild.bin", 0o600)
            .expect("create rebuild file");
        filesystem
            .write_file("/rebuild.bin", 0, payload)
            .expect("write rebuild file");
        filesystem.sync_all().expect("commit rebuild file");
        filesystem
            .create_snapshot("retained")
            .expect("retain rebuild snapshot");
        let missing_guid = filesystem
            .store
            .pool()
            .topology_status()
            .members
            .into_iter()
            .find(|member| member.device_index == 0)
            .expect("durable member zero")
            .device_guid;
        drop(filesystem);

        std::fs::remove_file(&old_devices[0]).expect("remove exact failed member fixture");
        let survivor = vec![old_devices[1].clone()];

        let ordinary_read_only = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &survivor,
            "missing-member-rebuild",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::ReadOnly,
        )
        .expect("open ordinary read-only survivor");
        let ordinary_engine = VfsLocalFileSystem::new(ordinary_read_only).with_read_only();
        let refused = live_device_admin(
            &ordinary_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&missing_guid),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(
            refused["ok"], false,
            "ordinary read-only refusal: {refused}"
        );
        assert_eq!(refused["json"]["status"], "refused");
        assert_eq!(refused["json"]["recovery_mode"], "device-rebuild-only");
        assert_eq!(refused["json"]["namespace_read_only"], true);
        assert!(refused["error"]
            .as_str()
            .is_some_and(|message| message.contains("--read-only --rebuild-only")));
        let human_refused = live_device_admin(
            &ordinary_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&missing_guid),
                "new_device_path": replacement.display().to_string(),
            }),
            false,
        );
        assert_eq!(human_refused["ok"], false);
        assert!(human_refused["error"].as_str().is_some_and(|message| {
            message.contains("recovery_mode=device-rebuild-only")
                && message.contains("topology_committed=false")
                && message.contains("namespace_read_only=true")
                && message.contains(&live_admin_hex_encode(&missing_guid))
        }));
        drop(ordinary_engine);

        let recovery = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &survivor,
            "missing-member-rebuild",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::DeviceRebuildOnly,
        )
        .expect("open recovery-only survivor");
        let recovery_engine = VfsLocalFileSystem::new(recovery).with_read_only();
        assert_eq!(
            recovery_engine.create(ROOT_INODE_ID, b"forbidden", 0o600, 0, &ctx()),
            Err(Errno::EROFS),
            "recovery-only namespace mutation must remain read-only"
        );
        assert_eq!(
            recovery_engine
                .fs
                .borrow()
                .read_file("/rebuild.bin")
                .expect("read mounted bytes before rebuild"),
            payload
        );

        let wrong_guid = [0xEE; 16];
        assert_ne!(wrong_guid, missing_guid);
        let wrong = live_device_admin(
            &recovery_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&wrong_guid),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(wrong["ok"], false, "wrong GUID refusal: {wrong}");
        assert_eq!(wrong["json"]["status"], "refused");
        assert_eq!(wrong["json"]["topology_committed"], false);

        let wrong_backing = td.path().join("replacement-directory");
        std::fs::create_dir(&wrong_backing).expect("create wrong-backing candidate");
        let wrong_backing_refusal = live_device_admin(
            &recovery_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&missing_guid),
                "new_device_path": wrong_backing.display().to_string(),
            }),
            true,
        );
        assert_eq!(
            wrong_backing_refusal["ok"], false,
            "wrong-backing refusal: {wrong_backing_refusal}"
        );
        assert_eq!(wrong_backing_refusal["json"]["status"], "refused");
        assert_eq!(wrong_backing_refusal["json"]["topology_committed"], false);
        assert!(recovery_engine
            .fs
            .borrow()
            .store
            .pool()
            .device_replacement_result()
            .is_none());

        let rebuilt = live_device_admin(
            &recovery_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&missing_guid),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(rebuilt["ok"], true, "rebuild response: {rebuilt}");
        assert_eq!(rebuilt["json"]["status"], "completed");
        assert_eq!(rebuilt["json"]["recovery_mode"], "device-rebuild-only");
        assert_eq!(rebuilt["json"]["namespace_read_only"], true);
        assert_eq!(rebuilt["json"]["durable_device_index"], 0);
        assert_eq!(rebuilt["json"]["objects_failed"], 0);
        assert_eq!(rebuilt["json"]["topology_committed"], true);
        assert!(rebuilt["json"]["message"].as_str().is_some_and(|message| {
            message.contains("durable same-cardinality topology commit")
                && message.contains("recovery_mode=device-rebuild-only")
                && message.contains("topology_committed=true")
                && message.contains("namespace_read_only=true")
        }));
        assert_eq!(
            recovery_engine.create(ROOT_INODE_ID, b"still-forbidden", 0o600, 0, &ctx()),
            Err(Errno::EROFS),
            "completed rebuild must not widen mounted namespace authority"
        );
        assert_eq!(
            recovery_engine
                .fs
                .borrow()
                .read_file("/rebuild.bin")
                .expect("read mounted bytes after rebuild"),
            payload
        );
        drop(recovery_engine);

        let reopened = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &[replacement.clone(), old_devices[1].clone()],
            "missing-member-rebuild",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen normal writable survivor-plus-replacement topology");
        assert_eq!(
            reopened
                .read_file("/rebuild.bin")
                .expect("read rebuilt bytes after normal reopen"),
            payload
        );
        assert_eq!(
            reopened
                .list_snapshots_checked()
                .expect("list retained snapshot after rebuild")
                .len(),
            1
        );
        let scrub = reopened
            .scrub_mounted_content()
            .expect("scrub rebuilt topology");
        assert!(scrub.is_clean(), "rebuilt topology scrub: {scrub:?}");
    }

    #[test]
    fn missing_member_rebuild_resumes_during_mounted_root_reconciliation() {
        let td = tempfile::tempdir().expect("missing-member reconciliation fixture");
        let metadata = td.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create rebuild metadata dir");
        let old_devices = [td.path().join("dev0.img"), td.path().join("dev1.img")];
        let replacement = td.path().join("replacement.img");
        for path in old_devices.iter().chain(std::iter::once(&replacement)) {
            let file = std::fs::File::create(path).expect("create rebuild device image");
            file.set_len(16 * 1024 * 1024)
                .expect("size rebuild device image");
        }
        let policy = tidefs_local_object_store::pool::PoolRedundancyPolicy::replicated(2);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "missing-member-rebuild-reconciliation",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("create two-copy mounted filesystem");
        let snapshot_payload = b"snapshot bytes survive rebuild reconciliation";
        filesystem
            .create_file("/reconcile.bin", 0o600)
            .expect("create reconciliation file");
        filesystem
            .write_file("/reconcile.bin", 0, snapshot_payload)
            .expect("write snapshot reconciliation bytes");
        filesystem
            .sync_all()
            .expect("commit snapshot reconciliation bytes");
        filesystem
            .create_snapshot("before-reconcile-overwrite")
            .expect("retain reconciliation snapshot");
        let current_payload = b"current bytes survive interrupted root reconciliation";
        filesystem
            .write_file("/reconcile.bin", 0, current_payload)
            .expect("write current reconciliation bytes");
        filesystem
            .sync_all()
            .expect("commit current reconciliation bytes");
        let missing_guid = filesystem
            .store
            .pool()
            .topology_status()
            .members
            .into_iter()
            .find(|member| member.device_index == 0)
            .expect("durable member zero")
            .device_guid;
        drop(filesystem);

        std::fs::remove_file(&old_devices[0]).expect("remove exact failed member fixture");
        let survivor = vec![old_devices[1].clone()];
        let mut recovery = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &survivor,
            "missing-member-rebuild-reconciliation",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::DeviceRebuildOnly,
        )
        .expect("open recovery-only survivor");
        let mut root_authority = recovery
            .ensure_device_lifecycle_root_authority(
                "test interrupted missing-member root reconciliation",
            )
            .expect("authenticate current and retained roots");
        let survivor_config = recovery
            .store
            .pool()
            .config()
            .devices
            .first()
            .cloned()
            .expect("surviving member configuration");
        let replacement_config = tidefs_local_object_store::DeviceConfig {
            media_class: survivor_config.media_class,
            path: replacement.clone(),
            backing: survivor_config.backing,
            class: survivor_config.class,
            kind: tidefs_local_object_store::DeviceKind::Block {
                path: replacement.clone(),
            },
            encryption: survivor_config.encryption,
            compression: survivor_config.compression,
        };
        recovery
            .store
            .pool_mut()
            .begin_missing_member_rebuild_mutation()
            .expect("arm exact rebuild mutation");
        let prepared = recovery
            .store
            .pool_mut()
            .rebuild_missing_member(
                missing_guid,
                replacement_config,
                &tidefs_local_object_store::StoreOptions::default(),
            )
            .expect("publish successor receipts before root reconciliation");
        assert_eq!(prepared.objects_failed, 0);
        assert!(!prepared.complete);

        // Follow the production ordering through retained mounted snapshots,
        // then crash before current-root reconciliation and before successor
        // topology publication. Reopen must accept the already advanced
        // snapshot root and the predecessor current root together.
        recovery
            .reconcile_mounted_snapshot_receipts(&mut root_authority.mounted_snapshots)
            .expect("reconcile retained snapshot before crash cut");
        recovery
            .store
            .pool_mut()
            .sync_all()
            .expect("sync partial root reconciliation");
        assert_legacy_device_lifecycle_files_absent(&metadata);
        drop(recovery);

        let resumed = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &survivor,
            "missing-member-rebuild-reconciliation",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::DeviceRebuildOnly,
        )
        .expect("reopen interrupted root reconciliation from label authority");
        let resumed_engine = VfsLocalFileSystem::new(resumed).with_read_only();
        let result = live_device_admin(
            &resumed_engine,
            "rebuild",
            json!({
                "missing_device_guid": live_admin_hex_encode(&missing_guid),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(result["ok"], true, "reconciliation resume: {result}");
        assert_eq!(result["json"]["status"], "completed");
        assert_eq!(result["json"]["topology_committed"], true);
        assert_eq!(
            resumed_engine
                .fs
                .borrow()
                .read_file("/reconcile.bin")
                .expect("read current bytes after reconciliation resume"),
            current_payload
        );
        drop(resumed_engine);

        let mut reopened = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &[replacement.clone(), old_devices[1].clone()],
            "missing-member-rebuild-reconciliation",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen completed topology after reconciliation resume");
        assert_eq!(
            reopened
                .read_file("/reconcile.bin")
                .expect("read current bytes after normal reopen"),
            current_payload
        );
        reopened
            .rollback_to_snapshot("before-reconcile-overwrite")
            .expect("rollback retained snapshot after rebuild resume");
        assert_eq!(
            reopened
                .read_file("/reconcile.bin")
                .expect("read retained snapshot bytes after rebuild resume"),
            snapshot_payload
        );
        let scrub = reopened
            .scrub_mounted_content()
            .expect("scrub resumed rebuilt topology");
        assert!(scrub.is_clean(), "resumed rebuild scrub: {scrub:?}");
        assert_legacy_device_lifecycle_files_absent(&metadata);
    }

    #[test]
    fn live_device_replace_resumes_stable_prepublication_evidence() {
        let td = tempfile::tempdir().expect("replacement resume fixture");
        let metadata = td.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create replacement resume metadata dir");
        let old_devices = [td.path().join("dev0.img"), td.path().join("dev1.img")];
        let replacement = td.path().join("replacement.img");
        for path in old_devices.iter().chain(std::iter::once(&replacement)) {
            let file = std::fs::File::create(path).expect("create replacement resume image");
            file.set_len(16 * 1024 * 1024)
                .expect("size replacement resume image");
        }
        let policy = tidefs_local_object_store::pool::PoolRedundancyPolicy::replicated(2);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "live-device-replace-resume",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("create replacement resume filesystem");
        let payload = b"resume reconciles predecessor manifests before topology commit";
        filesystem
            .create_file("/resume.bin", 0o600)
            .expect("create replacement resume file");
        filesystem
            .write_file("/resume.bin", 0, payload)
            .expect("write replacement resume file");
        filesystem
            .sync_all()
            .expect("commit replacement resume file");
        filesystem
            .create_filesystem_dataset(
                "other",
                DatasetId::from_bytes([0xD7; 16]),
                Vec::new(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .expect("create independent replacement-resume filesystem");
        drop(filesystem);
        let independent_payload = b"replacement resume preserves independent bytes";
        let mut independent = open_named_test_filesystem(
            &metadata,
            &old_devices,
            "live-device-replace-resume",
            policy,
            "other",
        );
        independent
            .create_file("/independent.bin", 0o600)
            .expect("create independent replacement-resume file");
        independent
            .write_file("/independent.bin", 0, independent_payload)
            .expect("write independent replacement-resume file");
        independent
            .sync_all()
            .expect("commit independent replacement-resume file");
        drop(independent);
        let mut filesystem = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "live-device-replace-resume",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen root before preparing replacement evidence");

        let old_config = filesystem.store.pool().config().devices[0].clone();
        let mut replacement_config = old_config;
        replacement_config.path = replacement.clone();
        replacement_config.kind = tidefs_local_object_store::DeviceKind::Block {
            path: replacement.clone(),
        };
        let prepared = filesystem
            .store
            .pool_mut()
            .replace_device(
                &old_devices[0],
                replacement_config,
                &tidefs_local_object_store::StoreOptions::default(),
            )
            .expect("prepare replacement before simulated crash");
        assert!(!prepared.complete);
        assert_eq!(prepared.objects_failed, 0);
        assert_legacy_device_lifecycle_files_absent(&metadata);
        remove_legacy_device_lifecycle_files(&metadata);
        assert_legacy_device_lifecycle_files_absent(&metadata);
        drop(filesystem);

        let reopened = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &old_devices,
            "live-device-replace-resume",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen predecessor topology with replacement evidence");
        let engine = VfsLocalFileSystem::new(reopened);
        let resumed = live_device_admin(
            &engine,
            "replace",
            json!({
                "old_device_path": old_devices[0].display().to_string(),
                "new_device_path": replacement.display().to_string(),
            }),
            true,
        );
        assert_eq!(
            resumed["ok"], true,
            "replacement resume response: {resumed}"
        );
        assert_eq!(resumed["json"]["status"], "completed");
        let post_resume_payload = b"writes resume only after replacement authority converges";
        {
            let mut filesystem = engine.fs.borrow_mut();
            assert_eq!(
                filesystem
                    .read_file("/resume.bin")
                    .expect("read after replacement resume"),
                payload
            );
            filesystem
                .create_file("/post-resume.bin", 0o600)
                .expect("create after replacement resume");
            filesystem
                .write_file("/post-resume.bin", 0, post_resume_payload)
                .expect("write after replacement resume");
            filesystem
                .sync_all()
                .expect("commit write after replacement resume");
        }
        drop(engine);

        let reopened = PoolDatasetOwner::open_with_block_devices_and_recovery_policy(
            &metadata,
            &[replacement.clone(), old_devices[1].clone()],
            "live-device-replace-resume",
            policy,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
            crate::RecoveryPolicy::default(),
        )
        .expect("reopen completed resumed replacement topology");
        assert_eq!(
            reopened
                .read_file("/resume.bin")
                .expect("read after resumed replacement reimport"),
            payload
        );
        assert_eq!(
            reopened
                .read_file("/post-resume.bin")
                .expect("read post-resume write after replacement reimport"),
            post_resume_payload
        );
        drop(reopened);
        let independent = open_named_test_filesystem(
            &metadata,
            &[replacement, old_devices[1].clone()],
            "live-device-replace-resume",
            policy,
            "other",
        );
        assert_eq!(
            independent
                .read_file("/independent.bin")
                .expect("read independent bytes after replacement resume"),
            independent_payload
        );
    }

    #[test]
    fn live_device_remove_pending_evacuation_recovers_before_cow_root_publication() {
        let (engine, td, devices) = temp_fs_with_block_devices(2);
        let metadata = td.path().join("metadata");
        engine
            .fs
            .borrow_mut()
            .create_filesystem_dataset(
                "other",
                DatasetId::from_bytes([0xD8; 16]),
                Vec::new(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .expect("create independent removal-resume filesystem");
        drop(engine);
        let independent_payload = b"removal resume preserves independent bytes";
        let mut independent = open_named_test_filesystem(
            &metadata,
            &devices,
            "tidefs",
            tidefs_local_object_store::pool::PoolRedundancyPolicy::default(),
            "other",
        );
        independent
            .create_file("/independent.bin", 0o600)
            .expect("create independent removal-resume file");
        independent
            .write_file("/independent.bin", 0, independent_payload)
            .expect("write independent removal-resume file");
        independent
            .sync_all()
            .expect("commit independent removal-resume file");
        drop(independent);
        let engine = VfsLocalFileSystem::new(
            PoolDatasetOwner::open_with_block_devices(
                &metadata,
                &devices,
                tidefs_local_object_store::StoreOptions::default(),
                RootAuthenticationKey::demo_key(),
            )
            .expect("reopen root before preparing removal evidence"),
        );
        let (selected_path, selected_payload, target_path, _, _) = {
            let mut fs = engine.fs.borrow_mut();
            let mut selected = None;
            for candidate in 0..64_u8 {
                let path = format!("/pending-remove-{candidate:02}.bin");
                let payload = vec![candidate.wrapping_add(1); 4096 + candidate as usize];
                fs.create_file(&path, 0o600).expect("create candidate file");
                fs.write_file(&path, 0, &payload)
                    .expect("write candidate file");
                fs.sync_all().expect("commit candidate file");

                let inode = fs.stat(&path).expect("stat candidate file");
                let content_key = fs
                    .object_keyspace()
                    .content(inode.inode_id, inode.data_version);
                let (content_bytes, _) = fs
                    .store
                    .pool()
                    .get_with_current_receipt(DeviceIoClass::Data, content_key)
                    .expect("read candidate content manifest")
                    .expect("candidate content manifest exists");
                let crate::records::ContentLayout::Chunked(manifest) =
                    crate::content::decode_content_layout(&content_bytes)
                        .expect("decode candidate content manifest")
                else {
                    continue;
                };
                for chunk_ref in manifest.chunks.iter().filter(|chunk| !chunk.is_hole()) {
                    let chunk_key = fs.object_keyspace().content_chunk(
                        manifest.inode_id,
                        chunk_ref.data_version,
                        chunk_ref.chunk_index,
                    );
                    let receipt = fs
                        .store
                        .pool()
                        .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                        .expect("read candidate chunk receipt")
                        .expect("candidate chunk receipt exists");
                    let target = receipt.targets.first().expect("one chunk target");
                    if target.device_index == 0 {
                        // Device zero also owns raw filesystem transaction
                        // metadata. Select the other member so this test
                        // isolates the authenticated content-manifest crash
                        // window rather than unrelated raw-metadata refusal.
                        continue;
                    }
                    let target_path = devices
                        .get(target.device_index as usize)
                        .expect("receipt target maps to configured member")
                        .clone();
                    selected = Some((
                        path.clone(),
                        payload.clone(),
                        target_path,
                        content_key,
                        content_bytes.clone(),
                    ));
                    break;
                }
                if selected.is_some() {
                    break;
                }
            }
            let selected = selected.expect("find receipt-backed chunk removal target");

            let preparation = fs
                .store
                .pool_mut()
                .prepare_safe_remove_device(&selected.2)
                .expect("evacuate target without detaching it");
            assert_eq!(preparation.objects_failed, 0, "{preparation:?}");
            let (still_authenticated, _) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, selected.3)
                .expect("read authenticated predecessor manifest after evacuation")
                .expect("authenticated predecessor manifest remains readable");
            assert_eq!(
                still_authenticated, selected.4,
                "evacuation must not rewrite authenticated predecessor-manifest bytes in place"
            );
            fs.store
                .pool_mut()
                .sync_all()
                .expect("sync survivor evacuation before simulated crash");
            assert_legacy_device_lifecycle_files_absent(&metadata);
            selected
        };

        // Drop without finish_safe_remove_device(): this simulates the exact
        // crash window after receipt relocation but before copy-on-write
        // manifest reconciliation publishes its replacement root.
        remove_legacy_device_lifecycle_files(&metadata);
        assert_legacy_device_lifecycle_files_absent(&metadata);
        drop(engine);

        let reopened = PoolDatasetOwner::open_with_block_devices(
            &metadata,
            &devices,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("marker-bound recovery republishes roots and finishes removal");
        assert_legacy_device_lifecycle_files_absent(&metadata);
        assert_eq!(reopened.store.pool().stats().device_count, 1);
        assert_eq!(
            reopened
                .read_file(&selected_path)
                .expect("read reconciled file after recovery"),
            selected_payload
        );
        assert!(
            reopened
                .store
                .pool()
                .config()
                .devices
                .iter()
                .all(|device| device.path != target_path),
            "recovered topology must exclude the retired target"
        );
        let survivor = devices
            .iter()
            .find(|device| **device != target_path)
            .expect("one removal-resume survivor")
            .clone();
        drop(reopened);
        let independent = open_named_test_filesystem(
            &metadata,
            std::slice::from_ref(&survivor),
            "tidefs",
            tidefs_local_object_store::pool::PoolRedundancyPolicy::default(),
            "other",
        );
        assert_eq!(
            independent
                .read_file("/independent.bin")
                .expect("read independent bytes after removal resume"),
            independent_payload
        );
    }

    #[test]
    fn live_device_remove_preserves_snapshot_roots_and_independent_filesystem() {
        let (snapshot_engine, snapshot_root, snapshot_devices) = temp_fs_with_block_devices(2);
        let snapshot_payload = vec![0x53; 8193];
        let current_payload = vec![0x71; 8193];
        {
            let mut filesystem = snapshot_engine.fs.borrow_mut();
            filesystem
                .create_file("/snapshot.bin", 0o600)
                .expect("create mounted snapshot file");
            filesystem
                .write_file("/snapshot.bin", 0, &snapshot_payload)
                .expect("write mounted snapshot bytes");
            filesystem
                .sync_all()
                .expect("commit mounted snapshot bytes");
            filesystem
                .create_snapshot("retained")
                .expect("create data-retaining snapshot");
            filesystem
                .create_clone("retained-clone", "retained")
                .expect("create shared-root snapshot-table clone");
            filesystem
                .write_file("/snapshot.bin", 0, &current_payload)
                .expect("overwrite current bytes after snapshot");
            filesystem
                .sync_all()
                .expect("commit current bytes after snapshot");
        }
        let snapshot_removal = live_device_admin(
            &snapshot_engine,
            "remove",
            json!({
                "device_path": snapshot_devices[1].display().to_string(),
                "force": false,
            }),
            true,
        );
        assert_eq!(snapshot_removal["ok"], true, "{snapshot_removal}");
        assert_legacy_device_lifecycle_files_absent(&snapshot_root.path().join("metadata"));
        assert_eq!(
            snapshot_engine
                .fs
                .borrow()
                .store
                .pool()
                .stats()
                .device_count,
            1
        );
        assert!(
            snapshot_engine
                .fs
                .borrow()
                .pending_snapshot_root_rewrites
                .is_empty(),
            "device lifecycle predecessor authorization must not leak past publication"
        );
        {
            let mut filesystem = snapshot_engine.fs.borrow_mut();
            filesystem
                .create_file("/after-removal.bin", 0o600)
                .expect("create file after snapshot-preserving removal");
            filesystem
                .write_file("/after-removal.bin", 0, b"ordinary successor commit")
                .expect("write after snapshot-preserving removal");
            filesystem
                .sync_all()
                .expect("ordinary commit after device lifecycle publication");
        }
        assert_eq!(
            snapshot_engine
                .fs
                .borrow()
                .read_file("/snapshot.bin")
                .expect("read current bytes after snapshot-preserving removal"),
            current_payload
        );
        let snapshot_metadata = snapshot_root.path().join("metadata");
        drop(snapshot_engine);
        let mut snapshot_reopened = PoolDatasetOwner::open_with_block_devices(
            &snapshot_metadata,
            std::slice::from_ref(&snapshot_devices[0]),
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen survivor with retained filesystem snapshot");
        assert_eq!(
            snapshot_reopened
                .list_snapshots_checked()
                .expect("validate retained snapshot and clone authority")
                .len(),
            2
        );
        assert_eq!(
            snapshot_reopened
                .read_file("/snapshot.bin")
                .expect("read current bytes after survivor reopen"),
            current_payload
        );
        snapshot_reopened
            .rollback_to_snapshot("retained")
            .expect("rollback retained snapshot after survivor reopen");
        assert_eq!(
            snapshot_reopened
                .read_file("/snapshot.bin")
                .expect("read snapshot bytes after survivor rollback"),
            snapshot_payload
        );
        drop(snapshot_reopened);

        let (corrupt_engine, corrupt_root, corrupt_devices) = temp_fs_with_block_devices(2);
        let corrupt_dataset_id = DatasetId::from_bytes([0xD4; 16]);
        {
            let mut filesystem = corrupt_engine.fs.borrow_mut();
            filesystem
                .create_filesystem_dataset(
                    "other",
                    corrupt_dataset_id,
                    Vec::new(),
                    DatasetFlags::default_create(),
                    SyncGuarantee::Local,
                )
                .expect("create independent corruption preflight filesystem");
            let root_key = filesystem
                .store
                .dataset_root(corrupt_dataset_id)
                .expect("independent filesystem has a typed root")
                .object_key;
            assert!(filesystem
                .store
                .pool_mut()
                .delete(DeviceIoClass::Data, root_key)
                .expect("remove independent typed root for corruption preflight"));
            filesystem
                .store
                .pool_mut()
                .sync_all()
                .expect("sync corrupt independent typed-root fixture");
        }
        let corrupt_refusal = live_device_admin(
            &corrupt_engine,
            "remove",
            json!({
                "device_path": corrupt_devices[1].display().to_string(),
                "force": false,
            }),
            true,
        );
        assert_eq!(corrupt_refusal["ok"], false, "{corrupt_refusal}");
        assert_legacy_device_lifecycle_files_absent(&corrupt_root.path().join("metadata"));
        assert_eq!(
            corrupt_engine.fs.borrow().store.pool().stats().device_count,
            2
        );

        let (dataset_engine, dataset_root, dataset_devices) = temp_fs_with_block_devices(2);
        dataset_engine
            .fs
            .borrow_mut()
            .create_filesystem_dataset(
                "other",
                DatasetId::from_bytes([0xD5; 16]),
                Vec::new(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .expect("create second filesystem dataset");
        drop(dataset_engine);
        let metadata = dataset_root.path().join("metadata");
        let independent_payload = b"removal preserves independent filesystem bytes";
        let mut independent = open_named_test_filesystem(
            &metadata,
            &dataset_devices,
            "tidefs",
            tidefs_local_object_store::pool::PoolRedundancyPolicy::default(),
            "other",
        );
        independent
            .create_file("/independent.bin", 0o600)
            .expect("create independent removal file");
        independent
            .write_file("/independent.bin", 0, independent_payload)
            .expect("write independent removal file");
        independent
            .sync_all()
            .expect("commit independent removal file");
        drop(independent);
        let dataset_engine = VfsLocalFileSystem::new(
            PoolDatasetOwner::open_with_block_devices(
                &metadata,
                &dataset_devices,
                tidefs_local_object_store::StoreOptions::default(),
                RootAuthenticationKey::demo_key(),
            )
            .expect("reopen root filesystem for removal"),
        );
        let dataset_removal = live_device_admin(
            &dataset_engine,
            "remove",
            json!({
                "device_path": dataset_devices[1].display().to_string(),
                "force": false,
            }),
            true,
        );
        assert_eq!(dataset_removal["ok"], true, "{dataset_removal}");
        assert_legacy_device_lifecycle_files_absent(&metadata);
        assert_eq!(
            dataset_engine.fs.borrow().store.pool().stats().device_count,
            1
        );
        drop(dataset_engine);
        let independent = open_named_test_filesystem(
            &metadata,
            std::slice::from_ref(&dataset_devices[0]),
            "tidefs",
            tidefs_local_object_store::pool::PoolRedundancyPolicy::default(),
            "other",
        );
        assert_eq!(
            independent
                .read_file("/independent.bin")
                .expect("read independent bytes after survivor reopen"),
            independent_payload
        );
        drop(corrupt_engine);
    }

    #[test]
    fn live_device_remove_refuses_corrupt_mounted_snapshot_before_topology_mutation() {
        let (engine, _root, devices) = temp_fs_with_block_devices(2);
        {
            let mut filesystem = engine.fs.borrow_mut();
            filesystem
                .create_snapshot("corrupt-snapshot")
                .expect("create mounted snapshot corruption fixture");
            let mounted_dataset_id = DatasetId::from_bytes(filesystem.mounted_dataset_id());
            let record = filesystem
                .state
                .snapshots
                .get(b"corrupt-snapshot".as_slice())
                .expect("snapshot record exists");
            let snapshot_dataset_id =
                crate::snapshot::snapshot_record_dataset_id_for_dataset(record, mounted_dataset_id);
            let typed_root_key = filesystem
                .store
                .dataset_root(snapshot_dataset_id)
                .expect("snapshot has canonical typed root")
                .object_key;
            assert!(filesystem
                .store
                .pool_mut()
                .delete(DeviceIoClass::Data, typed_root_key)
                .expect("delete snapshot typed-root fixture object"));
            filesystem
                .store
                .pool_mut()
                .sync_all()
                .expect("sync corrupt snapshot fixture");
        }

        let refusal = live_device_admin(
            &engine,
            "remove",
            json!({
                "device_path": devices[1].display().to_string(),
                "force": false,
            }),
            true,
        );
        assert_eq!(refusal["ok"], false, "{refusal}");
        assert_eq!(engine.fs.borrow().store.pool().stats().device_count, 2);
        assert!(engine
            .fs
            .borrow()
            .store
            .pool()
            .pending_device_removal_path()
            .expect("inspect removal marker")
            .is_none());
    }

    #[test]
    fn live_device_remove_refuses_corrupt_independent_snapshot_before_topology_mutation() {
        let (engine, root, devices) = temp_fs_with_block_devices(2);
        let independent_dataset_id = DatasetId::from_bytes([0xD6; 16]);
        engine
            .fs
            .borrow_mut()
            .create_filesystem_dataset(
                "other",
                independent_dataset_id,
                Vec::new(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .expect("create independent snapshot corruption filesystem");
        drop(engine);

        let metadata = root.path().join("metadata");
        let mut independent = open_named_test_filesystem(
            &metadata,
            &devices,
            "tidefs",
            tidefs_local_object_store::pool::PoolRedundancyPolicy::default(),
            "other",
        );
        independent
            .create_snapshot("corrupt-independent")
            .expect("create independent snapshot corruption fixture");
        let record = independent
            .state
            .snapshots
            .get(b"corrupt-independent".as_slice())
            .expect("independent snapshot record exists");
        let snapshot_dataset_id =
            crate::snapshot::snapshot_record_dataset_id_for_dataset(record, independent_dataset_id);
        drop(independent);

        let filesystem = PoolDatasetOwner::open_with_block_devices(
            &metadata,
            &devices,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("reopen root owner before independent snapshot corruption");
        let engine = VfsLocalFileSystem::new(filesystem);
        {
            let mut filesystem = engine.fs.borrow_mut();
            let typed_root_key = filesystem
                .store
                .dataset_root(snapshot_dataset_id)
                .expect("independent snapshot has canonical typed root")
                .object_key;
            assert!(filesystem
                .store
                .pool_mut()
                .delete(DeviceIoClass::Data, typed_root_key)
                .expect("delete independent snapshot typed-root fixture object"));
            filesystem
                .store
                .pool_mut()
                .sync_all()
                .expect("sync corrupt independent snapshot fixture");
        }

        let refusal = live_device_admin(
            &engine,
            "remove",
            json!({
                "device_path": devices[1].display().to_string(),
                "force": false,
            }),
            true,
        );
        assert_eq!(refusal["ok"], false, "{refusal}");
        assert_eq!(engine.fs.borrow().store.pool().stats().device_count, 2);
        assert!(engine
            .fs
            .borrow()
            .store
            .pool()
            .pending_device_removal_path()
            .expect("inspect independent corruption removal marker")
            .is_none());
    }

    #[cfg(feature = "replication-io")]
    #[test]
    fn live_snapshot_send_exports_from_mounted_pool_owner() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/live.txt", 0o644).expect("create file");
        fs.write_file("/live.txt", 0, b"live owner snapshot send")
            .expect("write file");
        let engine = VfsLocalFileSystem::new(fs);
        let output = root.path().join("live-send.vfs");

        let sent = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "vfssend1",
                "incremental": false,
            }),
            true,
        );

        assert_eq!(sent["ok"], true, "send response: {sent}");
        assert_eq!(sent["json"]["format"], "vfssend1");
        assert_eq!(sent["json"]["incremental"], false);
        assert!(sent["json"]["bytes"].as_u64().unwrap_or(0) > 0);
        let encoded = std::fs::read(&output).expect("read live send output");
        let decoded =
            crate::ChangedRecordExport::decode(&encoded).expect("decode live send output");
        assert!(!decoded.incremental);
        assert!(decoded.total_records > 0);
        assert!(decoded.payload_bytes > 0);
    }

    #[cfg(feature = "replication-io")]
    #[test]
    fn live_snapshot_send_incremental_exports_from_authorized_live_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/base.txt", 0o644).expect("create base");
        fs.write_file("/base.txt", 0, b"base bytes")
            .expect("write base");
        fs.sync_all().expect("sync baseline");
        // Incremental send succeeds only while the base root's objects remain retained.
        let baseline = fs.create_snapshot("baseline").expect("snapshot baseline");
        let baseline_root = baseline.source_root;
        fs.set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        fs.replace_file("/base.txt", b"updated base bytes")
            .expect("replace base");
        fs.create_file("/delta.txt", 0o644).expect("create delta");
        fs.write_file("/delta.txt", 0, b"incremental live bytes")
            .expect("write delta");
        let engine = VfsLocalFileSystem::new(fs);
        let output = root.path().join("live-incremental.vfs");

        let sent = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "vfssend1",
                "incremental": true,
                "from_root": live_from_root_hex(&baseline_root),
            }),
            true,
        );

        assert_eq!(sent["ok"], true, "incremental send response: {sent}");
        assert_eq!(sent["json"]["format"], "vfssend1");
        assert_eq!(sent["json"]["incremental"], true);
        assert!(sent["json"]["bytes"].as_u64().unwrap_or(0) > 0);
        let encoded = std::fs::read(&output).expect("read incremental output");
        let decoded =
            crate::ChangedRecordExport::decode(&encoded).expect("decode incremental output");
        assert!(decoded.incremental);
        assert_eq!(decoded.from_root.as_ref(), Some(&baseline_root));
        assert!(decoded.total_records > 0);
    }

    #[cfg(feature = "replication-io")]
    #[test]
    fn live_snapshot_send_incremental_requires_authorized_from_root() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/live.txt", 0o644).expect("create file");
        fs.write_file("/live.txt", 0, b"live owner snapshot send")
            .expect("write file");
        let engine = VfsLocalFileSystem::new(fs);
        let output = root.path().join("missing-from-root.vfs");

        let missing = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "vfssend1",
                "incremental": true,
            }),
            true,
        );
        assert_eq!(missing["ok"], false, "missing response: {missing}");
        assert_eq!(missing["exit_code"], 1);
        assert!(missing["json"].is_null());
        assert!(missing["text"].is_null());
        assert!(
            missing["error"]
                .as_str()
                .is_some_and(|err| err.contains("--from-root required")),
            "missing response should explain from-root requirement: {missing}"
        );
        assert!(!output.exists());

        let unknown = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "vfssend1",
                "incremental": true,
                "from_root": "000000000000000000000000000000000000000000000000",
            }),
            false,
        );
        assert_eq!(unknown["ok"], false, "unknown response: {unknown}");
        assert_eq!(unknown["exit_code"], 1);
        assert!(unknown["json"].is_null());
        assert!(unknown["text"].is_null());
        assert!(
            unknown["error"]
                .as_str()
                .is_some_and(|err| err.contains("from_root not found")),
            "unknown response should explain root authority failure: {unknown}"
        );
        assert!(!output.exists());

        let malformed = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "vfssend1",
                "incremental": true,
                "from_root": "\u{20ac}a",
            }),
            true,
        );
        assert_eq!(malformed["ok"], false, "malformed response: {malformed}");
        assert_eq!(malformed["exit_code"], 1);
        assert!(malformed["json"].is_null());
        assert!(malformed["text"].is_null());
        assert!(
            malformed["error"]
                .as_str()
                .is_some_and(|err| err.contains("invalid --from-root")),
            "malformed response should stay structured for non-ASCII hex: {malformed}"
        );
        assert!(!output.exists());
    }

    #[cfg(feature = "replication-io")]
    #[test]
    fn live_snapshot_send_rejects_target_addr_until_remote_admission_is_wired() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/live.txt", 0o644).expect("create file");
        fs.write_file("/live.txt", 0, b"live owner snapshot send")
            .expect("write file");
        let engine = VfsLocalFileSystem::new(fs);
        let output = root.path().join("target-refusal.vfs");

        let refused = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "target_addr": "127.0.0.1:9000",
                "format": "vfssend1",
                "incremental": false,
            }),
            true,
        );

        assert_eq!(refused["ok"], false, "target response: {refused}");
        assert_eq!(refused["exit_code"], 1);
        assert!(refused["json"].is_null());
        assert!(
            refused["error"].as_str().is_some_and(|err| {
                err.contains("target-address send")
                    && err.contains("remote admission")
                    && err.contains("127.0.0.1:9000")
            }),
            "target response should explain fail-closed remote boundary: {refused}"
        );
        assert!(!output.exists());
    }

    #[cfg(feature = "replication-io")]
    #[test]
    fn live_snapshot_send_rejects_unknown_format_before_exporting() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/live.txt", 0o644).expect("create file");
        fs.write_file("/live.txt", 0, b"live owner snapshot send")
            .expect("write file");
        let engine = VfsLocalFileSystem::new(fs);
        let output = root.path().join("unknown-format.vfs");

        let refused = live_snapshot_admin(
            &engine,
            "send",
            json!({
                "output": output.display().to_string(),
                "format": "unknown",
                "incremental": false,
            }),
            true,
        );

        assert_eq!(refused["ok"], false, "format response: {refused}");
        assert_eq!(refused["exit_code"], 1);
        assert!(refused["json"].is_null());
        assert!(refused["text"].is_null());
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|err| err.contains("unknown stream format 'unknown'")),
            "format response should name rejected format: {refused}"
        );
        assert!(!output.exists());
    }

    #[test]
    fn live_snapshot_extract_reads_snapshot_file_and_output_path() {
        let root = tempfile::tempdir().expect("tempdir");
        let store = root.path().join("store");
        let mut fs = PoolDatasetOwner::open(&store).expect("open fs");
        fs.create_file("/lost.txt", 0o644).expect("create file");
        fs.write_file("/lost.txt", 0, b"snapshot bytes")
            .expect("write file");
        fs.create_snapshot("snap0").expect("create snapshot");
        fs.write_file("/lost.txt", 0, b"live bytesdata")
            .expect("mutate live file");
        let engine = VfsLocalFileSystem::new(fs);

        let stdout = live_snapshot_admin(
            &engine,
            "extract",
            json!({
                "snapshot_name": "snap0",
                "file_path": "lost.txt",
            }),
            false,
        );
        assert_eq!(stdout["ok"], true, "extract response: {stdout}");
        assert_eq!(stdout["bytes"], 14);
        assert_eq!(stdout["bytes_hex"], "736e617073686f74206279746573");

        let output = root.path().join("recovered.bin");
        let written = live_snapshot_admin(
            &engine,
            "extract",
            json!({
                "snapshot_name": "snap0",
                "file_path": "/lost.txt",
                "output": output.display().to_string(),
            }),
            true,
        );
        assert_eq!(written["ok"], true, "extract output response: {written}");
        assert_eq!(written["json"]["bytes"], 14);
        assert_eq!(
            std::fs::read(&output).expect("read recovered output"),
            b"snapshot bytes"
        );
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_file("/lost.txt")
                .expect("read live file"),
            b"live bytesdata"
        );
    }

    #[cfg(feature = "encryption")]
    fn live_response_salt(response: &Value, label: &str) -> [u8; SALT_LEN] {
        let text = response["text"].as_str().expect("live admin text");
        let hex = text
            .lines()
            .find_map(|line| line.trim().strip_prefix(label))
            .map(str::trim)
            .expect("salt line");
        live_admin_hex_to_salt(hex).expect("salt hex")
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn live_dataset_seal_key_stores_mounted_keystore_entry() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "demo",
                "parent": "root",
                "type": "volume",
                "size": 4096,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        let sealed = live_dataset_admin(
            &engine,
            "seal-key",
            json!({
                "name": "demo",
                "passphrase": "initial passphrase",
            }),
        );

        assert_eq!(sealed["ok"], true, "seal-key response: {sealed}");
        let _salt = live_response_salt(&sealed, "salt:");

        let mut fs = engine.fs.borrow_mut();
        let keystore =
            BorrowedKeyStore::new(fs.store.pool_mut().raw_primary_store_mut(), [0; SALT_LEN]);
        let datasets = keystore.list_datasets().expect("list live keystore");
        assert_eq!(datasets, vec!["demo".to_string()]);
        let loaded = keystore
            .load_sealed_dek("demo")
            .expect("load live sealed DEK")
            .expect("sealed DEK");
        assert_eq!(loaded.dataset_id, "demo");
        assert_eq!(loaded.kek_generation, 1);
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn live_dataset_rotate_key_rewraps_mounted_keystore_entry() {
        let (engine, _td) = temp_fs();
        let created = live_dataset_admin(
            &engine,
            "create",
            json!({
                "name": "demo",
                "parent": "root",
                "type": "volume",
                "size": 4096,
                "sync": "local",
            }),
        );
        assert_eq!(created["ok"], true, "create response: {created}");

        let sealed = live_dataset_admin(
            &engine,
            "seal-key",
            json!({
                "name": "demo",
                "passphrase": "initial passphrase",
            }),
        );
        assert_eq!(sealed["ok"], true, "seal-key response: {sealed}");
        let old_salt = live_response_salt(&sealed, "salt:");

        let rotated = live_dataset_admin(
            &engine,
            "rotate-key",
            json!({
                "old_passphrase": "initial passphrase",
                "old_salt": salt_to_hex(&old_salt),
                "new_passphrase": "rotated passphrase",
            }),
        );

        assert_eq!(rotated["ok"], true, "rotate-key response: {rotated}");
        let new_salt = live_response_salt(&rotated, "new salt:");

        let mut fs = engine.fs.borrow_mut();
        let keystore = BorrowedKeyStore::new(fs.store.pool_mut().raw_primary_store_mut(), new_salt);
        let loaded = keystore
            .load_sealed_dek("demo")
            .expect("load rotated sealed DEK")
            .expect("sealed DEK");
        assert_eq!(loaded.kek_generation, 2);

        let new_wk = PoolWrappingKey::derive("rotated passphrase", &new_salt).unwrap();
        assert!(KeyManager::unseal_dek(&loaded, &new_wk).is_ok());
        let old_wk = PoolWrappingKey::derive("initial passphrase", &old_salt).unwrap();
        assert!(KeyManager::unseal_dek(&loaded, &old_wk).is_err());
    }

    fn temp_fs_with_content_capacity(
        content_capacity_bytes: u64,
    ) -> (VfsLocalFileSystem, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = PoolDatasetOwner::open_with_allocator_policy(
            dir.path(),
            crate::human::local_filesystem::StoreOptions::default(),
            crate::types::LocalStorageAllocatorPolicy::new(content_capacity_bytes, 1_000_000),
        )
        .expect("open with allocator policy");
        (VfsLocalFileSystem::new(fs), dir)
    }

    fn root_ctx() -> RequestCtx {
        RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0o022,
            groups: vec![0],
        }
    }

    fn create_xattr_file(engine: &VfsLocalFileSystem, name: &[u8]) -> InodeId {
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, name, 0o644, 0, &ctx()).unwrap();
        attr.inode_id
    }

    fn default_acl_for_inheritance_regression() -> tidefs_posix_acl::PosixAcl {
        vec![
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER,
                perm: 7,
                id: 1234,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_GROUP_OBJ,
                perm: 5,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_MASK,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_OTHER,
                perm: 7,
                id: 0,
            },
        ]
    }

    fn assert_attr_has_wall_clock_posix_times(attr: &InodeAttr, before_ns: i64, after_ns: i64) {
        let timestamps = [
            attr.posix.atime_ns,
            attr.posix.mtime_ns,
            attr.posix.ctime_ns,
            attr.posix.btime_ns,
        ];
        for timestamp in timestamps {
            assert!(
                timestamp >= before_ns && timestamp <= after_ns,
                "timestamp {timestamp} outside [{before_ns}, {after_ns}]"
            );
            assert!(
                timestamp / 1_000_000_000 > 0,
                "timestamp seconds should not truncate to zero"
            );
        }
    }

    // ── Namespace tests ───────────────────────────────────────────────

    #[test]
    fn root_inode_is_known() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        assert_eq!(root, ROOT_INODE_ID);
        assert_eq!(engine.inode_path(root).unwrap(), "/");
    }

    #[test]
    fn mkdir_and_lookup() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine.mkdir(root, b"subdir", 0o755, &ctx()).unwrap();
        assert_eq!(attr.kind, NodeKind::Dir);

        let looked_up = engine.lookup(root, b"subdir", &ctx()).unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
    }

    #[test]
    fn mkdir_under_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let missing_parent = InodeId::new(999_999);

        let result = engine.mkdir(missing_parent, b"subdir", 0o755, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn mkdir_under_file_parent_returns_enotdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file_attr, _fh) = engine.create(root, b"not-dir", 0o644, 0, &ctx()).unwrap();

        let result = engine.mkdir(file_attr.inode_id, b"child", 0o755, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);
    }

    #[test]
    fn mkdir_creates_directory_with_mode_and_umask_applied() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o022,
            groups: vec![4343],
        };

        let attr = engine.mkdir(root, b"owned-dir", 0o777, &caller).unwrap();

        assert_eq!(attr.kind, NodeKind::Dir);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFDIR);
        assert_eq!(attr.posix.mode & 0o777, 0o755);
        assert_eq!(attr.posix.uid, 4242);
        assert_eq!(attr.posix.gid, 4343);
    }

    #[test]
    fn mkdir_initial_record_uses_effective_metadata() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o022,
            groups: vec![4343],
        };

        let attr = engine
            .mkdir(root, b"single-commit-dir", 0o777, &caller)
            .unwrap();
        let fs = engine.fs.borrow();
        let record = fs.inode(attr.inode_id).unwrap();

        assert_eq!(record.kind(), NodeKind::Dir);
        assert_eq!(record.mode & S_IFMT, S_IFDIR);
        assert_eq!(record.mode & 0o777, 0o755);
        assert_eq!(record.uid, 4242);
        assert_eq!(record.gid, 4343);
        assert_eq!(record.generation.get(), record.metadata_version);
        assert_eq!(record.generation.get(), record.data_version);
    }

    #[test]
    fn mkdir_name_with_invalid_characters_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.mkdir(root, b"bad/name", 0o755, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn mkdir_setgid_parent_inherits_gid_and_sgid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent directory with S_ISGID and a specific GID
        let parent_attr = engine.mkdir(root, b"sgiddir", 0o2755, &ctx()).unwrap();
        // Set the parent GID to a value different from the caller
        let mut set = SetAttr::new();
        set.valid = FATTR_GID | FATTR_MODE;
        set.gid = 4242;
        set.mode = S_IFDIR | S_ISGID | 0o755;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create subdirectory under the setgid parent
        let child_attr = engine
            .mkdir(parent_attr.inode_id, b"child", 0o777, &ctx())
            .unwrap();
        assert_eq!(
            child_attr.posix.gid, 4242,
            "child inherits parent GID via setgid"
        );
        assert!(
            child_attr.posix.mode & S_ISGID != 0,
            "child directory inherits S_ISGID from setgid parent"
        );
    }

    #[test]
    fn mkdir_no_setgid_parent_keeps_caller_gid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent directory without S_ISGID
        let parent_attr = engine.mkdir(root, b"normaldir", 0o755, &ctx()).unwrap();
        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 9999;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create subdirectory under non-setgid parent
        let child_attr = engine
            .mkdir(parent_attr.inode_id, b"child", 0o777, &ctx())
            .unwrap();
        assert_eq!(
            child_attr.posix.gid,
            ctx().gid,
            "child keeps caller GID without setgid"
        );
        assert!(
            child_attr.posix.mode & S_ISGID == 0,
            "child does NOT inherit S_ISGID from non-setgid parent"
        );
    }

    #[test]
    fn create_file_setgid_parent_inherits_gid_but_not_sgid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent directory with S_ISGID and a specific GID
        let parent_attr = engine.mkdir(root, b"sgiddir", 0o2755, &ctx()).unwrap();
        let mut set = SetAttr::new();
        set.valid = FATTR_GID | FATTR_MODE;
        set.gid = 4242;
        set.mode = S_IFDIR | S_ISGID | 0o755;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create regular file under the setgid parent
        let (child_attr, _fh) = engine
            .create(parent_attr.inode_id, b"file", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            child_attr.posix.gid, 4242,
            "regular file inherits parent GID via setgid"
        );
        assert!(
            child_attr.posix.mode & S_ISGID == 0,
            "regular file does NOT inherit S_ISGID from setgid parent"
        );
    }

    #[test]
    fn create_file_no_setgid_parent_keeps_caller_gid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent directory without S_ISGID and a different GID
        let parent_attr = engine.mkdir(root, b"normaldir", 0o755, &ctx()).unwrap();
        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 9999;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create regular file under non-setgid parent
        let (child_attr, _fh) = engine
            .create(parent_attr.inode_id, b"file", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            child_attr.posix.gid,
            ctx().gid,
            "regular file keeps caller GID without setgid"
        );
    }

    // ── Sticky-bit (S_ISVTX) enforcement tests ────────────────────────

    #[test]
    fn sticky_bit_owner_can_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create a sticky directory owned by uid 1000
        let dir = engine.mkdir(root, b"sticky", 0o1777, &ctx()).unwrap();
        // Create a file owned by uid 4242 inside the sticky dir
        let other_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let (_file_attr, _fh) = engine
            .create(dir.inode_id, b"victim", 0o644, 0, &other_ctx)
            .unwrap();
        // Owner of the directory (uid 1000) can unlink
        let result = engine.unlink(dir.inode_id, b"victim", &ctx());
        assert!(result.is_ok(), "dir owner can unlink in sticky dir");
    }

    #[test]
    fn sticky_bit_file_owner_can_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create a sticky directory, owner uid 4242
        let other_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let dir = engine.mkdir(root, b"sticky2", 0o1777, &other_ctx).unwrap();
        // Create a file inside also owned by uid 4242
        let (_file_attr, _fh) = engine
            .create(dir.inode_id, b"mine", 0o644, 0, &other_ctx)
            .unwrap();
        // File owner can unlink their own file
        let result = engine.unlink(dir.inode_id, b"mine", &other_ctx);
        assert!(
            result.is_ok(),
            "file owner can unlink own file in sticky dir"
        );
    }

    #[test]
    fn sticky_bit_root_can_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create a sticky directory owned by uid 4242
        let other_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let dir = engine.mkdir(root, b"sticky3", 0o1777, &other_ctx).unwrap();
        let (_file_attr, _fh) = engine
            .create(dir.inode_id, b"nobody", 0o644, 0, &other_ctx)
            .unwrap();
        // Root (uid 0) can always unlink
        let result = engine.unlink(dir.inode_id, b"nobody", &root_ctx());
        assert!(result.is_ok(), "root can unlink in sticky dir");
    }

    #[test]
    fn sticky_bit_stranger_denied_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create a sticky directory owned by uid 1000
        let dir = engine.mkdir(root, b"sticky4", 0o1777, &ctx()).unwrap();
        // Create a file owned by uid 4242 inside
        let owner_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let (_file_attr, _fh) = engine
            .create(dir.inode_id, b"target", 0o644, 0, &owner_ctx)
            .unwrap();
        // Third party uid 9999 tries to unlink
        let stranger_ctx = RequestCtx {
            uid: 9999,
            gid: 9999,
            pid: 1,
            umask: 0,
            groups: vec![9999],
        };
        let result = engine.unlink(dir.inode_id, b"target", &stranger_ctx);
        assert_eq!(result.unwrap_err(), Errno::EPERM);
    }

    #[test]
    fn sticky_bit_stranger_denied_rmdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create a sticky directory owned by uid 1000
        let dir = engine.mkdir(root, b"sticky5", 0o1777, &ctx()).unwrap();
        // Create a subdir owned by uid 4242
        let owner_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let _sub = engine
            .mkdir(dir.inode_id, b"subdir", 0o755, &owner_ctx)
            .unwrap();
        // Third party tries to rmdir
        let stranger_ctx = RequestCtx {
            uid: 9999,
            gid: 9999,
            pid: 1,
            umask: 0,
            groups: vec![9999],
        };
        let result = engine.rmdir(dir.inode_id, b"subdir", &stranger_ctx);
        assert_eq!(result.unwrap_err(), Errno::EPERM);
    }

    #[test]
    fn sticky_bit_stranger_denied_rename_overwrite() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create sticky dir owned by uid 1000
        let dir = engine.mkdir(root, b"sticky6", 0o1777, &ctx()).unwrap();
        // Create a file owned by uid 4242 inside sticky dir
        let owner_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let (_target_attr, _fh) = engine
            .create(dir.inode_id, b"target", 0o644, 0, &owner_ctx)
            .unwrap();
        // Third party creates their own file in root
        let stranger_ctx = RequestCtx {
            uid: 9999,
            gid: 9999,
            pid: 1,
            umask: 0,
            groups: vec![9999],
        };
        let (_src_attr, _fh2) = engine
            .create(root, b"source", 0o644, 0, &stranger_ctx)
            .unwrap();
        // Third party tries to rename over target in sticky dir
        let result = engine.rename(root, b"source", dir.inode_id, b"target", 0, &stranger_ctx);
        assert_eq!(result.unwrap_err(), Errno::EPERM);
    }

    #[test]
    fn non_sticky_dir_allows_anyone_to_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create non-sticky directory, owner uid 1000, mode 0o777
        let dir = engine.mkdir(root, b"public", 0o777, &ctx()).unwrap();
        // Create file owned by uid 4242
        let owner_ctx = RequestCtx {
            uid: 4242,
            gid: 4242,
            pid: 1,
            umask: 0,
            groups: vec![4242],
        };
        let (_file_attr, _fh) = engine
            .create(dir.inode_id, b"loose", 0o644, 0, &owner_ctx)
            .unwrap();
        // Third party can unlink (sticky-bit not set)
        let stranger_ctx = RequestCtx {
            uid: 9999,
            gid: 9999,
            pid: 1,
            umask: 0,
            groups: vec![9999],
        };
        let result = engine.unlink(dir.inode_id, b"loose", &stranger_ctx);
        assert!(result.is_ok(), "anyone can unlink in non-sticky dir");
    }

    // ── Symlink setgid inheritance tests ───────────────────────────────

    #[test]
    fn symlink_setgid_parent_inherits_gid_but_not_sgid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent directory with S_ISGID and a specific GID
        let parent_attr = engine.mkdir(root, b"sgid-sym", 0o2755, &ctx()).unwrap();
        let mut set = SetAttr::new();
        set.valid = FATTR_GID | FATTR_MODE;
        set.gid = 4242;
        set.mode = S_IFDIR | S_ISGID | 0o755;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create symlink under setgid parent
        let sym_attr = engine
            .symlink(parent_attr.inode_id, b"link", b"/tmp/target", &ctx())
            .unwrap();
        assert_eq!(
            sym_attr.posix.gid, 4242,
            "symlink inherits parent GID via setgid"
        );
        assert!(
            sym_attr.posix.mode & S_ISGID == 0,
            "symlink does NOT inherit S_ISGID"
        );
    }

    #[test]
    fn symlink_no_setgid_parent_keeps_caller_gid() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        // Create parent without S_ISGID, different GID
        let parent_attr = engine.mkdir(root, b"normal-sym", 0o755, &ctx()).unwrap();
        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 9999;
        engine
            .setattr(parent_attr.inode_id, &set, None, &ctx())
            .unwrap();
        // Create symlink
        let sym_attr = engine
            .symlink(parent_attr.inode_id, b"link", b"/tmp/target", &ctx())
            .unwrap();
        assert_eq!(
            sym_attr.posix.gid,
            ctx().gid,
            "symlink keeps caller GID without setgid"
        );
    }

    #[test]
    fn lookup_root_returns_dir_attrs() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let looked_up = engine.lookup(root, b"", &ctx()).unwrap();

        assert_eq!(looked_up.inode_id, root);
        assert_eq!(looked_up.kind, NodeKind::Dir);
        assert!(looked_up.posix.is_dir());
        assert_eq!(engine.inode_path(looked_up.inode_id).unwrap(), "/");
    }

    // ── Dataset-root mount tests ──────────────────────────────────────

    /// Create a temp filesystem with a subdirectory, then wrap it with
    /// with_dataset_root to simulate a per-dataset mount.
    /// The dataset directory is created through the VFS engine so it is
    /// visible to the PoolDatasetOwner layer.
    fn temp_dataset_fs(ds_name: &str) -> (VfsLocalFileSystem, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs = PoolDatasetOwner::open(dir.path()).expect("open");
        let ds_path = format!("/{ds_name}");

        // Create the dataset directory through the VFS engine.
        {
            let engine = VfsLocalFileSystem::new(fs);
            let root = engine.get_root_inode(&ctx()).unwrap();
            engine
                .mkdir(root, ds_name.as_bytes(), 0o755, &ctx())
                .expect("create dataset dir via engine");
        }

        // Re-open and wrap with dataset root.
        let fs = PoolDatasetOwner::open(dir.path()).expect("reopen");
        let engine = VfsLocalFileSystem::new(fs).with_dataset_root(&ds_path);
        (engine, dir)
    }

    #[test]
    fn dataset_root_lookup_returns_dataset_root_attrs() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();
        assert_eq!(
            root, ROOT_INODE_ID,
            "get_root_inode must return ROOT_INODE_ID for FUSE protocol"
        );

        let attr = engine.lookup(root, b"", &ctx()).unwrap();
        // The real pool inode is returned; the path cache maps it to /ds1.
        assert_eq!(attr.kind, NodeKind::Dir, "dataset root must be a directory");
        let cached_path = engine.inode_path(attr.inode_id).unwrap();
        assert_eq!(
            cached_path, "/ds1",
            "real pool inode must resolve to dataset root path"
        );
    }

    #[test]
    fn dataset_root_getattr_via_root_inode() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();
        // getattr via ROOT_INODE_ID resolves through root_path() to /ds1
        let attr = engine.getattr(root, None, &ctx()).unwrap();
        assert_eq!(
            attr.kind,
            NodeKind::Dir,
            "getattr on ROOT_INODE_ID must return dataset root attrs"
        );
    }

    #[test]
    fn dataset_root_inode_path_uses_dataset_dir() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let path = engine.inode_path(root).unwrap();
        assert_eq!(
            path, "/ds1",
            "root inode path must be the dataset directory"
        );
    }

    #[test]
    fn dataset_root_create_and_lookup_stays_within_dataset() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();

        // Create a file in the dataset root
        let (created, fh) = engine
            .create(root, b"dataset-file.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"dataset content", &ctx()).unwrap();

        // Lookup must find the file within the dataset
        let looked_up = engine.lookup(root, b"dataset-file.txt", &ctx()).unwrap();
        assert_eq!(looked_up.inode_id, created.inode_id);
        assert_eq!(looked_up.kind, NodeKind::File);

        // Inode path should be within the dataset
        let file_path = engine.inode_path(looked_up.inode_id).unwrap();
        assert_eq!(
            file_path, "/ds1/dataset-file.txt",
            "file path must be scoped within the dataset directory"
        );
    }

    #[test]
    fn dataset_root_readdir_shows_dataset_contents() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();

        // Create entries within the dataset
        engine.create(root, b"a.txt", 0o644, 0, &ctx()).unwrap();
        engine.mkdir(root, b"sub", 0o755, &ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, _more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        let names: Vec<String> = entries
            .into_iter()
            .map(|e| String::from_utf8_lossy(&e.name).to_string())
            .collect();

        assert!(
            names.iter().any(|n| n == "a.txt"),
            "readdir must show entries within the dataset"
        );
        assert!(
            names.iter().any(|n| n == "sub"),
            "readdir must show subdirectories within the dataset"
        );
    }

    #[test]
    fn dataset_root_path_does_not_escape() {
        let (engine, _td) = temp_dataset_fs("ds1");
        let root = engine.get_root_inode(&ctx()).unwrap();

        // Create a file OUTSIDE the dataset (at pool root)
        // via direct PoolDatasetOwner access, then verify it's not visible
        // through the VFS engine.
        let mut fs = engine.fs.borrow_mut();
        fs.create_file("/outside.txt", 0o644)
            .expect("create outside file");
        drop(fs);

        // Lookup within dataset should NOT find the outside file
        let result = engine.lookup(root, b"outside.txt", &ctx());
        assert!(
            result.is_err(),
            "lookup must not escape the dataset boundary"
        );
    }

    #[test]
    fn lookup_regular_file_after_create() {
        let (engine, _td) = temp_fs();
        {
            let mut fs = engine.fs.borrow_mut();
            fs.set_auto_commit(false).expect("defer mounted mutations");
            fs.set_max_uncommitted_mutations(1_000_000)
                .expect("keep the create/write group open");
        }
        let root = engine.get_root_inode(&ctx()).unwrap();
        let directory = engine.mkdir(root, b"lookup-dir", 0o750, &ctx()).unwrap();
        let (created, fh) = engine
            .create(directory.inode_id, b"lookup-file.txt", 0o640, 0, &ctx())
            .unwrap();
        let payload = b"lookup bytes";
        engine.write(&fh, 0, payload, &ctx()).unwrap();
        let pending_data_version = engine
            .fs
            .borrow()
            .get_inode_by_id(created.inode_id)
            .expect("pending inode remains live")
            .data_version;

        let mut timestamps = SetAttr::new();
        timestamps.valid = FATTR_ATIME | FATTR_MTIME;
        timestamps.atime_ns = 1_778_800_000_000_000_000;
        timestamps.mtime_ns = 1_778_800_000_100_000_000;
        engine
            .setattr(created.inode_id, &timestamps, None, &ctx())
            .expect("timestamp setattr after buffered write");

        let after_setattr = engine
            .fs
            .borrow()
            .get_inode_by_id(created.inode_id)
            .expect("setattr must retain the pending inode")
            .clone();
        assert_eq!(after_setattr.size, payload.len() as u64);
        assert_eq!(after_setattr.data_version, pending_data_version);

        engine.flush(&fh, &ctx()).expect("flush pending write");
        engine
            .getattr(directory.inode_id, None, &ctx())
            .expect("parent directory remains reachable after flush");

        let looked_up = engine
            .lookup(directory.inode_id, b"lookup-file.txt", &ctx())
            .unwrap();

        assert_eq!(looked_up.inode_id, created.inode_id);
        assert_eq!(looked_up.kind, NodeKind::File);
        assert!(looked_up.posix.is_file());
        assert_eq!(looked_up.posix.mode & !S_IFMT, 0o640);
        assert_eq!(looked_up.posix.size, payload.len() as u64);
        assert_eq!(
            engine
                .read(&fh, 0, payload.len() as u32, &ctx())
                .expect("read flushed file"),
            payload
        );
    }

    #[test]
    fn lookup_directory_after_mkdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"lookup-dir", 0o750, &ctx()).unwrap();

        let looked_up = engine.lookup(root, b"lookup-dir", &ctx()).unwrap();

        assert_eq!(looked_up.inode_id, dir.inode_id);
        assert_eq!(looked_up.kind, NodeKind::Dir);
        assert!(looked_up.posix.is_dir());
        assert_eq!(looked_up.posix.mode & !S_IFMT, 0o750);
        assert!(looked_up.posix.nlink >= 2);
    }

    #[test]
    fn lookup_symlink_after_symlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let symlink = engine
            .symlink(root, b"lookup-link", b"/target/path", &ctx())
            .unwrap();

        let looked_up = engine.lookup(root, b"lookup-link", &ctx()).unwrap();

        assert_eq!(looked_up.inode_id, symlink.inode_id);
        assert_eq!(looked_up.kind, NodeKind::Symlink);
        assert!(looked_up.posix.is_symlink());
        assert_eq!(
            engine.inode_path(looked_up.inode_id).unwrap(),
            "/lookup-link"
        );
        assert_eq!(
            engine.readlink(looked_up.inode_id, &ctx()).unwrap(),
            b"/target/path"
        );
    }

    #[test]
    fn lookup_after_rename_cross_directory() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"lookup-source", 0o755, &ctx()).unwrap();
        let target_dir = engine.mkdir(root, b"lookup-target", 0o755, &ctx()).unwrap();
        let (created, _fh) = engine
            .create(source_dir.inode_id, b"before.txt", 0o644, 0, &ctx())
            .unwrap();

        engine
            .rename(
                source_dir.inode_id,
                b"before.txt",
                target_dir.inode_id,
                b"after.txt",
                0,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            engine
                .lookup(source_dir.inode_id, b"before.txt", &ctx())
                .unwrap_err(),
            Errno::ENOENT
        );
        let moved = engine
            .lookup(target_dir.inode_id, b"after.txt", &ctx())
            .unwrap();
        assert_eq!(moved.inode_id, created.inode_id);
        assert_eq!(
            engine.inode_path(moved.inode_id).unwrap(),
            "/lookup-target/after.txt"
        );
    }

    #[test]
    fn lookup_after_unlink_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, _fh) = engine
            .create(root, b"lookup-gone.txt", 0o644, 0, &ctx())
            .unwrap();

        assert_eq!(
            engine
                .lookup(root, b"lookup-gone.txt", &ctx())
                .unwrap()
                .inode_id,
            created.inode_id
        );
        engine.unlink(root, b"lookup-gone.txt", &ctx()).unwrap();
        assert_eq!(
            engine.lookup(root, b"lookup-gone.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn create_file_and_read() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.create(root, b"hello.txt", 0o644, 0, &ctx()).unwrap();
        assert_eq!(attr.kind, NodeKind::File);

        let w = engine.write(&fh, 0, b"hello world", &ctx()).unwrap();
        assert_eq!(w, 11);

        let data = engine.read(&fh, 0, 11, &ctx()).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn create_file_records_namespace_create_intent() {
        use crate::intent_log::IntentLogEntryKind;

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        let (attr, fh) = engine
            .create(root, b"regular", 0o600, 0, &root_ctx())
            .unwrap();
        engine.release(&fh).unwrap();

        let fs = engine.fs.borrow();
        let intent = fs
            .intent_log
            .pending_entries()
            .iter()
            .find_map(|entry| match &entry.entry_kind {
                IntentLogEntryKind::NamespaceCreateIntent(intent) => Some(intent),
                _ => None,
            })
            .expect("regular create should leave a namespace create intent");
        assert_eq!(intent.parent_inode_id, root);
        assert_eq!(intent.entry.name, b"regular");
        assert_eq!(intent.entry.inode_id, attr.inode_id);
        assert_eq!(intent.entry.kind(), NodeKind::File);
        assert_eq!(intent.entry.mode, S_IFREG | 0o600);
        assert_eq!(intent.inode.inode_id, attr.inode_id);
        assert_eq!(intent.inode.kind(), NodeKind::File);
        assert_eq!(intent.inode.rdev, 0);
    }

    #[test]
    fn create_file_initializes_posix_times_from_wall_clock() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let before_ns = crate::types::current_posix_time_ns();

        let (attr, _fh) = engine
            .create(root, b"wall-clock.txt", 0o644, 0, &ctx())
            .unwrap();
        let observed = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
        let after_ns = crate::types::current_posix_time_ns().saturating_add(1_000_000_000);

        assert_attr_has_wall_clock_posix_times(&attr, before_ns, after_ns);
        assert_attr_has_wall_clock_posix_times(&observed, before_ns, after_ns);
    }

    #[test]
    fn create_file_excl() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();

        const O_EXCL: u32 = 0o200;
        let result = engine.create(root, b"file.txt", 0o644, O_EXCL, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn create_duplicate_name_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine
            .create(root, b"file.txt", 0o644, O_EXCL, &ctx())
            .unwrap();

        // O_EXCL on existing name must return EEXIST.
        let result = engine.create(root, b"file.txt", 0o644, O_EXCL, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn create_existing_file_without_flags_opens_existing_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, fh) = engine
            .create(root, b"existing.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"data", &ctx()).unwrap();

        let (attr, reopen_fh) = engine
            .create(root, b"existing.txt", 0o644, O_WRONLY, &ctx())
            .expect("create on existing file without O_EXCL should open it");
        assert_eq!(attr.inode_id, original.inode_id);
        // Data preserved (no truncation)
        assert_eq!(engine.read(&reopen_fh, 0, 16, &ctx()).unwrap(), b"data");
    }

    #[test]
    fn create_with_trunc_truncates_existing_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();
        assert_eq!(engine.write(&fh, 0, b"payload", &ctx()).unwrap(), 7);

        const O_TRUNC: u32 = 0o1000;
        let (truncated, trunc_fh) = engine
            .create(root, b"file.txt", 0o644, O_TRUNC, &ctx())
            .unwrap();

        assert_eq!(truncated.inode_id, created.inode_id);
        assert_eq!(truncated.posix.size, 0);
        assert_eq!(engine.read(&trunc_fh, 0, 16, &ctx()).unwrap(), b"");
    }

    #[test]
    fn create_in_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let missing_parent = InodeId::new(999_999);

        let result = engine.create(missing_parent, b"file.txt", 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn create_under_file_parent_returns_enotdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file_attr, _fh) = engine.create(root, b"not-dir", 0o644, 0, &ctx()).unwrap();

        let result = engine.create(file_attr.inode_id, b"child.txt", 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);
    }

    #[test]
    fn create_empty_name_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.create(root, b"", 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn create_name_with_invalid_characters_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.create(root, b"bad/name.txt", 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn create_returns_usable_handle() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();

        assert_eq!(fh.inode_id, attr.inode_id);
        assert_ne!(fh.fh_id.get(), 0);
        assert_eq!(engine.write(&fh, 0, b"vfs-create", &ctx()).unwrap(), 10);
        assert_eq!(engine.read(&fh, 0, 10, &ctx()).unwrap(), b"vfs-create");
    }

    #[test]
    fn create_mode_and_ownership_reflected_in_attrs() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o027,
            groups: vec![4343],
        };

        let (attr, _fh) = engine
            .create(root, b"owned.txt", 0o666, 0, &caller)
            .unwrap();

        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.mode & 0o777, 0o640);
        assert_eq!(attr.posix.uid, 4242);
        assert_eq!(attr.posix.gid, 4343);
    }

    #[test]
    fn create_burst_empty_files_stays_metadata_only_until_write() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut fs = PoolDatasetOwner::open(dir.path()).expect("open");
        fs.set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        fs.set_commit_group_throughput_profile()
            .expect("test setup mutation must be admitted");
        fs.set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let engine = VfsLocalFileSystem::new(fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o077,
            groups: vec![4343],
        };

        let mut first_fh = None;
        for idx in 0..512 {
            let name = format!("perm-{idx:03}");
            let (attr, fh) = engine
                .create(root, name.as_bytes(), 0o666, 0, &caller)
                .unwrap();
            if idx == 0 {
                assert_eq!(attr.posix.mode & 0o777, 0o600);
                assert_eq!(attr.posix.uid, caller.uid);
                assert_eq!(attr.posix.gid, caller.gid);
                first_fh = Some(fh);
            } else {
                engine.release(&fh).unwrap();
            }
        }

        {
            let fs = engine.fs.borrow();
            assert_eq!(fs.uncommitted_mutation_count(), 512);
            assert!(
                fs.state.dirty_content.is_empty(),
                "empty creates should not dirty file content"
            );
            assert_eq!(fs.list_dir_by_inode(ROOT_INODE_ID).unwrap().len(), 512);
        }

        engine.fs.borrow_mut().sync_all().unwrap();
        let report =
            crate::inspect_filesystem_content_objects(dir.path(), crate::StoreOptions::default())
                .unwrap();
        assert_eq!(report.file_like_inodes, 512);
        assert_eq!(report.referenced_objects.len(), 0);
        assert_eq!(report.missing_objects, 0);
        assert_eq!(report.malformed_records, 0);

        let first_fh = first_fh.unwrap();
        assert_eq!(engine.read(&first_fh, 0, 1, &caller).unwrap(), b"");
        assert_eq!(engine.write(&first_fh, 0, b"x", &caller).unwrap(), 1);
        assert_eq!(engine.read(&first_fh, 0, 1, &caller).unwrap(), b"x");
        engine.unlink(root, b"perm-000", &caller).unwrap();
        assert_eq!(
            engine.lookup(root, b"perm-000", &caller),
            Err(Errno::ENOENT)
        );
        assert_eq!(engine.read(&first_fh, 0, 1, &caller).unwrap(), b"x");
        engine.release(&first_fh).unwrap();
        drop(engine);

        let mut reopened = PoolDatasetOwner::open(dir.path()).unwrap();
        assert_eq!(reopened.read_file("/perm-001").unwrap(), b"");
        reopened.write_file("/perm-001", 0, b"y").unwrap();
        assert_eq!(reopened.read_file("/perm-001").unwrap(), b"y");
    }

    #[test]
    fn mknod_fifo_creates_lookup_and_readdir_visible_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let attr = engine
            .mknod(root, b"pipe", S_IFIFO | 0o666, 0, &ctx())
            .unwrap();

        assert_eq!(attr.kind, NodeKind::Fifo);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFIFO);
        assert_eq!(attr.posix.mode & 0o777, 0o644);
        assert_eq!(attr.posix.uid, 1000);
        assert_eq!(attr.posix.gid, 1000);
        assert_eq!(attr.posix.rdev, 0);

        let looked_up = engine.lookup(root, b"pipe", &ctx()).unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
        assert_eq!(looked_up.kind, NodeKind::Fifo);

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert!(!has_more);
        let pipe = entries
            .iter()
            .find(|entry| entry.name.as_slice() == b"pipe")
            .expect("pipe entry");
        assert_eq!(pipe.inode_id, attr.inode_id);
        assert_eq!(pipe.kind, NodeKind::Fifo);
    }

    #[test]
    fn mknod_fifo_duplicate_name_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine
            .mknod(root, b"pipe", S_IFIFO | 0o644, 0, &ctx())
            .unwrap();

        let result = engine.mknod(root, b"pipe", S_IFIFO | 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn mknod_fifo_under_file_parent_returns_enotdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file_attr, _fh) = engine.create(root, b"not-dir", 0o644, 0, &ctx()).unwrap();

        let result = engine.mknod(file_attr.inode_id, b"pipe", S_IFIFO | 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);
    }

    #[test]
    fn mknod_fifo_under_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let missing_parent = InodeId::new(999_999);

        let result = engine.mknod(missing_parent, b"pipe", S_IFIFO | 0o644, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn mknod_fifo_explicit_mode_and_umask_reflected_in_attrs() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o027,
            groups: vec![4343],
        };

        let attr = engine
            .mknod(root, b"mode-pipe", S_IFIFO | 0o666, 0, &caller)
            .unwrap();

        assert_eq!(attr.kind, NodeKind::Fifo);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFIFO);
        assert_eq!(attr.posix.mode & 0o777, 0o640);
        assert_eq!(attr.posix.uid, 4242);
        assert_eq!(attr.posix.gid, 4343);
    }

    #[test]
    fn mknod_fifo_inherits_parent_default_acl_with_umask_masked_access_acl() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();
        let parent_default_acl = default_acl_for_inheritance_regression();
        let parent_default_raw = tidefs_posix_acl::encode_posix_acl_xattr(&parent_default_acl);
        engine
            .setxattr(
                root,
                b"system.posix_acl_default",
                &parent_default_raw,
                0,
                &root_ctx(),
            )
            .unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o077,
            groups: vec![4343],
        };

        let attr = engine
            .mknod(root, b"acl-pipe", S_IFIFO | 0o666, 0, &caller)
            .unwrap();

        assert_eq!(attr.posix.mode & 0o777, 0o666);
        let raw_acl = engine
            .getxattr(attr.inode_id, b"system.posix_acl_access", &root_ctx())
            .unwrap();
        let decoded = tidefs_posix_acl::decode_posix_acl_xattr(&raw_acl).unwrap();
        assert_eq!(decoded[0].perm, 6);
        assert_eq!(decoded[1].perm, 7);
        assert_eq!(decoded[2].perm, 5);
        assert_eq!(decoded[3].perm, 6);
        assert_eq!(decoded[4].perm, 6);
        assert_eq!(
            engine
                .getxattr(attr.inode_id, b"system.posix_acl_default", &root_ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
    }

    #[test]
    fn mknod_fifo_in_subdirectory_is_lookup_and_readdir_visible() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let parent = engine.mkdir(root, b"pipes", 0o755, &ctx()).unwrap();

        let attr = engine
            .mknod(parent.inode_id, b"child-pipe", S_IFIFO | 0o600, 0, &ctx())
            .unwrap();

        let looked_up = engine
            .lookup(parent.inode_id, b"child-pipe", &ctx())
            .unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
        assert_eq!(looked_up.kind, NodeKind::Fifo);
        assert_eq!(looked_up.posix.mode & 0o777, 0o600);

        let dh = engine.opendir(parent.inode_id, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert!(!has_more);
        assert!(entries
            .iter()
            .any(|entry| entry.name.as_slice() == b"child-pipe"
                && entry.inode_id == attr.inode_id
                && entry.kind == NodeKind::Fifo));
    }

    #[test]
    fn mknod_fifo_multiple_in_same_directory_have_independent_inodes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let first = engine
            .mknod(root, b"pipe-a", S_IFIFO | 0o600, 0, &ctx())
            .unwrap();
        let second = engine
            .mknod(root, b"pipe-b", S_IFIFO | 0o644, 0, &ctx())
            .unwrap();

        assert_ne!(first.inode_id, second.inode_id);
        assert_eq!(
            engine.lookup(root, b"pipe-a", &ctx()).unwrap().inode_id,
            first.inode_id
        );
        assert_eq!(
            engine.lookup(root, b"pipe-b", &ctx()).unwrap().inode_id,
            second.inode_id
        );
        assert_eq!(first.posix.mode & 0o777, 0o600);
        assert_eq!(second.posix.mode & 0o777, 0o644);
    }

    #[test]
    fn mknod_fifo_reuse_name_after_unlink_allocates_new_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let original = engine
            .mknod(root, b"pipe", S_IFIFO | 0o600, 0, &ctx())
            .unwrap();

        engine.unlink(root, b"pipe", &ctx()).unwrap();
        assert_eq!(
            engine.lookup(root, b"pipe", &ctx()).unwrap_err(),
            Errno::ENOENT
        );

        let recreated = engine
            .mknod(root, b"pipe", S_IFIFO | 0o644, 0, &ctx())
            .unwrap();

        assert_ne!(recreated.inode_id, original.inode_id);
        assert_eq!(
            engine.lookup(root, b"pipe", &ctx()).unwrap().inode_id,
            recreated.inode_id
        );
        assert_eq!(recreated.posix.mode & 0o777, 0o644);
    }

    #[test]
    fn mknod_fifo_invalid_names_return_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        assert_eq!(
            engine
                .mknod(root, b"", S_IFIFO | 0o644, 0, &ctx())
                .unwrap_err(),
            Errno::EINVAL
        );
        assert_eq!(
            engine
                .mknod(root, b"bad/name", S_IFIFO | 0o644, 0, &ctx())
                .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn mknod_fifo_zero_permissions_creates_visible_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let attr = engine
            .mknod(root, b"zero-perm", S_IFIFO, 0, &ctx())
            .unwrap();

        assert_eq!(attr.kind, NodeKind::Fifo);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFIFO);
        assert_eq!(attr.posix.mode & 0o777, 0);
        assert_eq!(
            engine.lookup(root, b"zero-perm", &ctx()).unwrap().inode_id,
            attr.inode_id
        );
    }

    #[test]
    fn mknod_char_device_creates_and_persists_rdev() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        let attr = engine
            .mknod(root, b"null", S_IFCHR | 0o666, 0x0103, &root_ctx())
            .unwrap();
        assert_eq!(attr.kind, NodeKind::CharDev);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFCHR);
        assert_eq!(attr.posix.rdev, 0x0103);

        let looked_up = engine.lookup(root, b"null", &root_ctx()).unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
        assert_eq!(looked_up.posix.rdev, 0x0103);
    }

    #[test]
    fn mknod_char_device_records_rdev_intent() {
        use tidefs_intent_log::{IntentLogBuffer, IntentLogRecord};

        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();
        let buf = Arc::new(IntentLogBuffer::new());
        engine
            .fs
            .borrow_mut()
            .set_intent_log_buffer(buf.clone())
            .expect("test setup mutation must be admitted");

        let attr = engine
            .mknod(root, b"null", S_IFCHR | 0o600, 0x0103, &root_ctx())
            .unwrap();

        let frames = buf.drain_since(0);
        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert!(frame.verify().is_ok());
        match &frame.record {
            IntentLogRecord::Mknod {
                parent,
                name,
                mode,
                rdev,
                ino,
            } => {
                assert_eq!(*parent, root.get());
                assert_eq!(name, b"null");
                assert_eq!(*mode, S_IFCHR | 0o600);
                assert_eq!(*rdev, 0x0103);
                assert_eq!(*ino, attr.inode_id.get());
            }
            other => panic!("expected Mknod record, got {other:?}"),
        }
    }

    #[test]
    fn mknod_block_device_creates_and_persists_rdev() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        let attr = engine
            .mknod(root, b"sda1", S_IFBLK | 0o660, 0x0801, &root_ctx())
            .unwrap();
        assert_eq!(attr.kind, NodeKind::BlockDev);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFBLK);
        assert_eq!(attr.posix.rdev, 0x0801);

        let looked_up = engine.lookup(root, b"sda1", &root_ctx()).unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
        assert_eq!(looked_up.posix.rdev, 0x0801);
    }

    #[test]
    fn mknod_socket_creates_lookupable_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        let attr = engine
            .mknod(root, b"mysock", S_IFSOCK | 0o700, 0, &root_ctx())
            .unwrap();
        assert_eq!(attr.kind, NodeKind::Socket);
        assert_eq!(attr.posix.mode & S_IFMT, S_IFSOCK);
        assert_eq!(attr.posix.rdev, 0);

        let looked_up = engine.lookup(root, b"mysock", &root_ctx()).unwrap();
        assert_eq!(looked_up.inode_id, attr.inode_id);
    }

    #[test]
    fn mknod_rejects_unsupported_type_bits() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        assert_eq!(
            engine
                .mknod(root, b"dir-node", S_IFDIR | 0o755, 0, &root_ctx())
                .unwrap_err(),
            Errno::EOPNOTSUPP
        );
        assert_eq!(
            engine
                .mknod(
                    root,
                    b"symlink-node",
                    tidefs_types_vfs_core::S_IFLNK | 0o777,
                    0,
                    &root_ctx()
                )
                .unwrap_err(),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn mknod_device_and_socket_nodes_create_correct_node_kinds() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();

        let cases: &[(&[u8], u32, u32, NodeKind)] = &[
            (b"char-dev", S_IFCHR | 0o600, 0x0103, NodeKind::CharDev),
            (b"block-dev", S_IFBLK | 0o660, 0x0801, NodeKind::BlockDev),
            (b"unix-sock", S_IFSOCK | 0o700, 0, NodeKind::Socket),
        ];

        for &(name, mode, rdev, kind) in cases {
            let attr = engine.mknod(root, name, mode, rdev, &root_ctx()).unwrap();
            assert_eq!(attr.kind, kind, "wrong NodeKind for {name:?}");
            assert_eq!(attr.posix.rdev, rdev, "wrong rdev for {name:?}");
            let looked_up = engine.lookup(root, name, &root_ctx()).unwrap();
            assert_eq!(looked_up.inode_id, attr.inode_id);
        }
    }

    #[test]
    fn unlink_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"gone.txt", 0o644, 0, &ctx()).unwrap();
        engine.unlink(root, b"gone.txt", &ctx()).unwrap();

        let result = engine.lookup(root, b"gone.txt", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn unlink_directory_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"directory", 0o755, &ctx()).unwrap();

        let result = engine.unlink(root, b"directory", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EISDIR);
        assert_eq!(
            engine.lookup(root, b"directory", &ctx()).unwrap().inode_id,
            dir.inode_id
        );
    }

    #[test]
    fn unlink_nonexistent_entry_returns_enoent_and_preserves_parent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (survivor, _fh) = engine
            .create(root, b"survivor.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.unlink(root, b"missing.txt", &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
        assert_eq!(
            engine
                .lookup(root, b"survivor.txt", &ctx())
                .unwrap()
                .inode_id,
            survivor.inode_id
        );
    }

    #[test]
    fn unlink_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let missing_parent = InodeId::new(999_999);

        let result = engine.unlink(missing_parent, b"child.txt", &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn unlink_empty_name_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.unlink(root, b"", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn unlink_symlink_removes_link_not_target() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (target, target_fh) = engine
            .create(root, b"target.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&target_fh, 0, b"target-data", &ctx()).unwrap();
        let link = engine
            .symlink(root, b"link.txt", b"/target.txt", &ctx())
            .unwrap();

        engine.unlink(root, b"link.txt", &ctx()).unwrap();

        assert_eq!(
            engine.lookup(root, b"link.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            engine.readlink(link.inode_id, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        let target_after = engine.lookup(root, b"target.txt", &ctx()).unwrap();
        assert_eq!(target_after.inode_id, target.inode_id);
        assert_eq!(
            engine
                .read(&target_fh, 0, b"target-data".len() as u32, &ctx())
                .unwrap(),
            b"target-data"
        );
    }

    #[test]
    fn unlink_open_file_allows_release_and_removes_name() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"open-gone.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"before unlink", &ctx()).unwrap();

        engine.unlink(root, b"open-gone.txt", &ctx()).unwrap();

        // Name is gone from the directory.
        assert_eq!(
            engine.lookup(root, b"open-gone.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        // The canonical zero-link inode remains reachable through the live handle.
        let attr_after = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
        assert_eq!(attr_after.inode_id, attr.inode_id);
        assert_eq!(attr_after.posix.nlink, 0);
        let mut set_mtime = SetAttr::new();
        set_mtime.valid = FATTR_MTIME;
        set_mtime.mtime_ns = 1_700_000_789_000_000_000;
        let timestamp_attr = engine
            .setattr(attr.inode_id, &set_mtime, None, &ctx())
            .unwrap();
        assert_eq!(timestamp_attr.posix.mtime_ns, set_mtime.mtime_ns);
        assert!(timestamp_attr.posix.ctime_ns >= attr_after.posix.ctime_ns);
        assert_eq!(
            engine
                .read(&fh, 0, b"before unlink".len() as u32, &ctx())
                .unwrap(),
            b"before unlink"
        );
        engine.release(&fh).unwrap();
        // Last release reclaims the canonical zero-link inode.
        assert_eq!(
            engine.getattr(attr.inode_id, None, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(engine.release(&fh).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn unlink_open_file_after_buffered_flush_removes_name_without_content_corruption() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"hello.txt", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"hello\n", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine.unlink(root, b"hello.txt", &ctx()).unwrap();
        assert_eq!(
            engine.lookup(root, b"hello.txt", &ctx()),
            Err(Errno::ENOENT)
        );
        engine.release(&fh).unwrap();
    }

    #[test]
    fn unlink_open_sparse_file_keeps_canonical_inode_and_sparse_pool_content() {
        let (engine, _td) = temp_fs_with_content_capacity(2_u64 * 1024 * 1024 * 1024);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"sparse-open-gone.dat", 0o644, O_RDWR, &ctx())
            .unwrap();
        let file_size = 100_u64 * 1024 * 1024;
        let chunk_len = 64_usize * 1024;
        let stride = 5_u64 * 1024 * 1024;
        let payload = vec![0x5a; chunk_len];
        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = file_size;
        engine
            .setattr(attr.inode_id, &set, Some(&fh), &ctx())
            .unwrap();

        for i in 0..16_u64 {
            engine.write(&fh, i * stride, &payload, &ctx()).unwrap();
        }

        engine
            .unlink(root, b"sparse-open-gone.dat", &ctx())
            .unwrap();

        assert_eq!(
            engine
                .lookup(root, b"sparse-open-gone.dat", &ctx())
                .unwrap_err(),
            Errno::ENOENT
        );
        {
            let fs = engine.fs.borrow();
            let record = fs
                .get_inode_by_id(attr.inode_id)
                .expect("retained canonical inode");
            assert_eq!(record.nlink, 0);
            assert_eq!(record.size, file_size);
            let ranges = fs
                .mounted_data_ranges(attr.inode_id)
                .expect("canonical sparse Pool ranges");
            assert_eq!(ranges.len(), 16);
            // The canonical Pool carrier allocates chunk-granular content.
            // Each sub-chunk write therefore owns one materialized chunk even
            // though the unwritten half still reads as a sparse zero region.
            assert_eq!(
                ranges.iter().map(|(start, end)| end - start).sum::<u64>(),
                16 * crate::constants::FILESYSTEM_CONTENT_CHUNK_SIZE as u64
            );
        }

        assert_eq!(
            engine.read(&fh, 0, chunk_len as u32, &ctx()).unwrap(),
            payload
        );
        assert_eq!(
            engine
                .read(&fh, chunk_len as u64, chunk_len as u32, &ctx())
                .unwrap(),
            vec![0; chunk_len]
        );
        engine
            .write(&fh, file_size - chunk_len as u64, &payload, &ctx())
            .expect("write retained inode through canonical handle path");
        engine
            .fsync(&fh, false, &ctx())
            .expect("fsync retained inode through Pool authority");
        engine
            .fdatasync_inode(&fh, true, &ctx())
            .expect("fdatasync retained inode through Pool authority");
        engine.release(&fh).unwrap();
        assert_eq!(
            engine.getattr(attr.inode_id, None, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rmdir_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.mkdir(root, b"emptydir", 0o755, &ctx()).unwrap();
        engine.rmdir(root, b"emptydir", &ctx()).unwrap();

        let result = engine.lookup(root, b"emptydir", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn rmdir_non_empty_directory_returns_enotempty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"parent", 0o755, &ctx()).unwrap();
        engine
            .create(dir.inode_id, b"child.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.rmdir(root, b"parent", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTEMPTY);

        let looked_up = engine.lookup(root, b"parent", &ctx()).unwrap();
        assert_eq!(looked_up.inode_id, dir.inode_id);
    }

    #[test]
    fn rmdir_regular_file_returns_enotdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file_attr, _fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();

        let result = engine.rmdir(root, b"file.txt", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);

        let looked_up = engine.lookup(root, b"file.txt", &ctx()).unwrap();
        assert_eq!(looked_up.inode_id, file_attr.inode_id);
    }

    #[test]
    fn rmdir_nonexistent_entry_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.rmdir(root, b"missing", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn rmdir_dot_and_dotdot_names_return_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let dot = engine.rmdir(root, b".", &ctx());
        assert_eq!(dot.unwrap_err(), Errno::EINVAL);

        let dotdot = engine.rmdir(root, b"..", &ctx());
        assert_eq!(dotdot.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn rmdir_empty_name_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.rmdir(root, b"", &ctx());
        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn rmdir_rejects_slash_and_nul_names() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let slash = engine.rmdir(root, b"bad/name", &ctx());
        assert_eq!(slash.unwrap_err(), Errno::EINVAL);

        let nul = engine.rmdir(root, b"bad\0name", &ctx());
        assert_eq!(nul.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn rmdir_name_too_long_returns_enametoolong() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let name = vec![b'a'; 256];

        let result = engine.rmdir(root, &name, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENAMETOOLONG);
    }

    #[test]
    fn rmdir_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();

        let result = engine.rmdir(InodeId::new(999_999), b"child", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn rmdir_after_unlinking_last_child_succeeds() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let parent = engine.mkdir(root, b"parent", 0o755, &ctx()).unwrap();
        engine
            .create(parent.inode_id, b"child.txt", 0o644, 0, &ctx())
            .unwrap();

        engine
            .unlink(parent.inode_id, b"child.txt", &ctx())
            .unwrap();
        engine.rmdir(root, b"parent", &ctx()).unwrap();

        assert_eq!(
            engine.lookup(root, b"parent", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rmdir_nested_leaf_preserves_parent_directory() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let parent = engine.mkdir(root, b"parent", 0o755, &ctx()).unwrap();
        let leaf = engine
            .mkdir(parent.inode_id, b"leaf", 0o755, &ctx())
            .unwrap();

        engine.rmdir(parent.inode_id, b"leaf", &ctx()).unwrap();

        assert_eq!(
            engine.lookup(root, b"parent", &ctx()).unwrap().inode_id,
            parent.inode_id
        );
        assert_eq!(
            engine.lookup(parent.inode_id, b"leaf", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            engine.getattr(leaf.inode_id, None, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rename_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"old.txt", 0o644, 0, &ctx()).unwrap();
        engine
            .rename(root, b"old.txt", root, b"new.txt", 0, &ctx())
            .unwrap();

        let looked = engine.lookup(root, b"new.txt", &ctx()).unwrap();
        assert_eq!(looked.inode_id, attr.inode_id);
        assert!(engine.lookup(root, b"old.txt", &ctx()).is_err());
    }

    #[test]
    fn rename_source_enoent_preserves_destination_absence() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.rename(root, b"missing.txt", root, b"new.txt", 0, &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
        assert_eq!(
            engine.lookup(root, b"new.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rename_into_nonempty_dir_returns_enotempty_and_preserves_entries() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"source-dir", 0o755, &ctx()).unwrap();
        let target_dir = engine.mkdir(root, b"target-dir", 0o755, &ctx()).unwrap();
        let (nested, _nested_fh) = engine
            .create(target_dir.inode_id, b"nested.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.rename(root, b"source-dir", root, b"target-dir", 0, &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOTEMPTY);
        assert_eq!(
            engine.lookup(root, b"source-dir", &ctx()).unwrap().inode_id,
            source_dir.inode_id
        );
        assert_eq!(
            engine.lookup(root, b"target-dir", &ctx()).unwrap().inode_id,
            target_dir.inode_id
        );
        assert_eq!(
            engine
                .lookup(target_dir.inode_id, b"nested.txt", &ctx())
                .unwrap()
                .inode_id,
            nested.inode_id
        );
    }

    #[test]
    fn rename_cross_directory_moves_file_and_preserves_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"source-dir", 0o755, &ctx()).unwrap();
        let target_dir = engine.mkdir(root, b"target-dir", 0o755, &ctx()).unwrap();
        let (file, _fh) = engine
            .create(source_dir.inode_id, b"file.txt", 0o644, 0, &ctx())
            .unwrap();

        engine
            .rename(
                source_dir.inode_id,
                b"file.txt",
                target_dir.inode_id,
                b"file.txt",
                0,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            engine
                .lookup(target_dir.inode_id, b"file.txt", &ctx())
                .unwrap()
                .inode_id,
            file.inode_id
        );
        assert_eq!(
            engine
                .lookup(source_dir.inode_id, b"file.txt", &ctx())
                .unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn rename_noreplace_rejects_existing_target() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (alpha, alpha_fh) = engine.create(root, b"alpha.txt", 0o644, 0, &ctx()).unwrap();
        let (beta, beta_fh) = engine.create(root, b"beta.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&alpha_fh, 0, b"alpha", &ctx()).unwrap();
        engine.write(&beta_fh, 0, b"beta", &ctx()).unwrap();

        let result = engine.rename(
            root,
            b"alpha.txt",
            root,
            b"beta.txt",
            RENAME_NOREPLACE,
            &ctx(),
        );

        assert_eq!(result.unwrap_err(), Errno::EEXIST);
        assert_eq!(
            engine.lookup(root, b"alpha.txt", &ctx()).unwrap().inode_id,
            alpha.inode_id
        );
        assert_eq!(
            engine.lookup(root, b"beta.txt", &ctx()).unwrap().inode_id,
            beta.inode_id
        );
        assert_eq!(
            engine.read(&alpha_fh, 0, 16, &ctx()).unwrap(),
            b"alpha".to_vec()
        );
        assert_eq!(
            engine.read(&beta_fh, 0, 16, &ctx()).unwrap(),
            b"beta".to_vec()
        );
    }

    #[test]
    fn rename_noreplace_cross_directory_rejects_existing_target() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"source-dir", 0o755, &ctx()).unwrap();
        let target_dir = engine.mkdir(root, b"target-dir", 0o755, &ctx()).unwrap();
        let (alpha, _alpha_fh) = engine
            .create(source_dir.inode_id, b"file.txt", 0o644, 0, &ctx())
            .unwrap();
        let (beta, _beta_fh) = engine
            .create(target_dir.inode_id, b"file.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.rename(
            source_dir.inode_id,
            b"file.txt",
            target_dir.inode_id,
            b"file.txt",
            RENAME_NOREPLACE,
            &ctx(),
        );

        assert_eq!(result.unwrap_err(), Errno::EEXIST);
        assert_eq!(
            engine
                .lookup(source_dir.inode_id, b"file.txt", &ctx())
                .unwrap()
                .inode_id,
            alpha.inode_id
        );
        assert_eq!(
            engine
                .lookup(target_dir.inode_id, b"file.txt", &ctx())
                .unwrap()
                .inode_id,
            beta.inode_id
        );
    }

    #[test]
    fn rename_exchange_swaps_file_entries() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (alpha, _alpha_fh) = engine.create(root, b"alpha.txt", 0o644, 0, &ctx()).unwrap();
        let (beta, _beta_fh) = engine.create(root, b"beta.txt", 0o644, 0, &ctx()).unwrap();

        engine
            .rename(
                root,
                b"alpha.txt",
                root,
                b"beta.txt",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            engine.lookup(root, b"alpha.txt", &ctx()).unwrap().inode_id,
            beta.inode_id
        );
        assert_eq!(
            engine.lookup(root, b"beta.txt", &ctx()).unwrap().inode_id,
            alpha.inode_id
        );
    }

    #[test]
    fn rename_exchange_cross_directory_swaps_files() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"source-dir", 0o755, &ctx()).unwrap();
        let target_dir = engine.mkdir(root, b"target-dir", 0o755, &ctx()).unwrap();
        let (alpha, alpha_fh) = engine
            .create(source_dir.inode_id, b"alpha.txt", 0o644, 0, &ctx())
            .unwrap();
        let (beta, beta_fh) = engine
            .create(target_dir.inode_id, b"beta.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&alpha_fh, 0, b"alpha", &ctx()).unwrap();
        engine.write(&beta_fh, 0, b"beta", &ctx()).unwrap();

        engine
            .rename(
                source_dir.inode_id,
                b"alpha.txt",
                target_dir.inode_id,
                b"beta.txt",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            engine
                .lookup(source_dir.inode_id, b"alpha.txt", &ctx())
                .unwrap()
                .inode_id,
            beta.inode_id
        );
        assert_eq!(
            engine
                .lookup(target_dir.inode_id, b"beta.txt", &ctx())
                .unwrap()
                .inode_id,
            alpha.inode_id
        );
        assert_eq!(
            engine.read(&alpha_fh, 0, 16, &ctx()).unwrap(),
            b"alpha".to_vec()
        );
        assert_eq!(
            engine.read(&beta_fh, 0, 16, &ctx()).unwrap(),
            b"beta".to_vec()
        );
    }

    #[test]
    fn rename_exchange_swaps_directories() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let left_dir = engine.mkdir(root, b"left", 0o755, &ctx()).unwrap();
        let right_dir = engine.mkdir(root, b"right", 0o755, &ctx()).unwrap();
        let (left_child, _left_child_fh) = engine
            .create(left_dir.inode_id, b"left-child.txt", 0o644, 0, &ctx())
            .unwrap();
        let (right_child, _right_child_fh) = engine
            .create(right_dir.inode_id, b"right-child.txt", 0o644, 0, &ctx())
            .unwrap();

        engine
            .rename(root, b"left", root, b"right", RENAME_EXCHANGE, &ctx())
            .unwrap();

        assert_eq!(
            engine.lookup(root, b"left", &ctx()).unwrap().inode_id,
            right_dir.inode_id
        );
        assert_eq!(
            engine.lookup(root, b"right", &ctx()).unwrap().inode_id,
            left_dir.inode_id
        );
        assert_eq!(
            engine
                .lookup(left_dir.inode_id, b"left-child.txt", &ctx())
                .unwrap()
                .inode_id,
            left_child.inode_id
        );
        assert_eq!(
            engine
                .lookup(right_dir.inode_id, b"right-child.txt", &ctx())
                .unwrap()
                .inode_id,
            right_child.inode_id
        );
        assert_eq!(engine.inode_path(left_dir.inode_id).unwrap(), "/right");
        assert_eq!(engine.inode_path(right_dir.inode_id).unwrap(), "/left");
    }

    #[test]
    fn rename_exchange_swaps_symlinks() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let alpha = engine
            .symlink(root, b"alpha.link", b"/alpha-target", &ctx())
            .unwrap();
        let beta = engine
            .symlink(root, b"beta.link", b"/beta-target", &ctx())
            .unwrap();

        engine
            .rename(
                root,
                b"alpha.link",
                root,
                b"beta.link",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        let alpha_name = engine.lookup(root, b"alpha.link", &ctx()).unwrap();
        let beta_name = engine.lookup(root, b"beta.link", &ctx()).unwrap();
        assert_eq!(alpha_name.inode_id, beta.inode_id);
        assert_eq!(beta_name.inode_id, alpha.inode_id);
        assert_eq!(
            engine.readlink(alpha_name.inode_id, &ctx()).unwrap(),
            b"/beta-target".to_vec()
        );
        assert_eq!(
            engine.readlink(beta_name.inode_id, &ctx()).unwrap(),
            b"/alpha-target".to_vec()
        );
    }

    #[test]
    fn rename_exchange_same_name_is_noop() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file, fh) = engine.create(root, b"same.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"same bytes", &ctx()).unwrap();
        let before = engine.getattr(file.inode_id, None, &ctx()).unwrap();

        engine
            .rename(
                root,
                b"same.txt",
                root,
                b"same.txt",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        let after = engine.lookup(root, b"same.txt", &ctx()).unwrap();
        assert_eq!(after.inode_id, file.inode_id);
        assert_eq!(after.posix.size, before.posix.size);
        assert_eq!(
            engine.read(&fh, 0, 32, &ctx()).unwrap(),
            b"same bytes".to_vec()
        );
        assert_eq!(engine.inode_path(file.inode_id).unwrap(), "/same.txt");
    }

    #[test]
    fn rename_updates_moved_inode_ctime() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file, fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();
        let before = engine.getattr(file.inode_id, None, &ctx()).unwrap();

        // Sleep to ensure any time-based ctime would advance, but TideFS
        // uses a monotonic metadata version so the sleep is just insurance.
        std::thread::sleep(std::time::Duration::from_millis(5));

        engine
            .rename(root, b"original.txt", root, b"renamed.txt", 0, &ctx())
            .unwrap();

        let after = engine.getattr(file.inode_id, None, &ctx()).unwrap();
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "renamed inode ctime must advance: before={}, after={}",
            before.posix.ctime_ns,
            after.posix.ctime_ns
        );
        // Verify the file is at the new path
        assert!(engine.lookup(root, b"renamed.txt", &ctx()).is_ok());
        assert!(engine.lookup(root, b"original.txt", &ctx()).is_err());
        // Clean up
        let _ = engine.release(&fh);
    }

    #[test]
    fn rename_exchange_updates_both_inode_ctimes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (left, _fh_l) = engine.create(root, b"left.txt", 0o644, 0, &ctx()).unwrap();
        let (right, _fh_r) = engine.create(root, b"right.txt", 0o644, 0, &ctx()).unwrap();
        let left_before = engine.getattr(left.inode_id, None, &ctx()).unwrap();
        let right_before = engine.getattr(right.inode_id, None, &ctx()).unwrap();

        engine
            .rename(
                root,
                b"left.txt",
                root,
                b"right.txt",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        let left_after = engine.getattr(left.inode_id, None, &ctx()).unwrap();
        let right_after = engine.getattr(right.inode_id, None, &ctx()).unwrap();
        assert!(
            left_after.posix.ctime_ns > left_before.posix.ctime_ns,
            "exchanged left inode ctime must advance"
        );
        assert!(
            right_after.posix.ctime_ns > right_before.posix.ctime_ns,
            "exchanged right inode ctime must advance"
        );
    }

    #[test]
    fn link_creates_hard_link_and_both_names_share_inode_attributes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"linked bytes", &ctx()).unwrap();

        let linked = engine
            .link(original.inode_id, root, b"alias.txt", &ctx())
            .unwrap();

        let original_lookup = engine.lookup(root, b"original.txt", &ctx()).unwrap();
        let alias_lookup = engine.lookup(root, b"alias.txt", &ctx()).unwrap();
        assert_eq!(linked.inode_id, original.inode_id);
        assert_eq!(alias_lookup.inode_id, original.inode_id);
        assert_eq!(original_lookup.inode_id, original.inode_id);
        assert_eq!(alias_lookup.kind, NodeKind::File);
        assert_eq!(alias_lookup.posix.mode, original_lookup.posix.mode);
        assert_eq!(alias_lookup.posix.size, original_lookup.posix.size);
    }

    #[test]
    fn link_increments_nlink_on_target_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, _fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();

        let linked = engine
            .link(original.inode_id, root, b"alias.txt", &ctx())
            .unwrap();

        assert_eq!(linked.posix.nlink, 2);
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx())
                .unwrap()
                .posix
                .nlink,
            2
        );
    }

    #[test]
    fn link_nonexistent_target_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.link(InodeId::new(99_999), root, b"alias.txt", &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
        assert_eq!(
            engine.lookup(root, b"alias.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn link_to_existing_destination_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, _fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .create(root, b"existing.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.link(original.inode_id, root, b"existing.txt", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EEXIST);
        assert_eq!(
            engine
                .getattr(original.inode_id, None, &ctx())
                .unwrap()
                .posix
                .nlink,
            1
        );
    }

    #[test]
    fn link_on_directory_returns_eopnotsupp() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"dir", 0o755, &ctx()).unwrap();

        let result = engine.link(dir.inode_id, root, b"dir-link", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EPERM);
        assert_eq!(
            engine.lookup(root, b"dir-link", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn unlink_after_link_preserves_inode_until_last_link_removed() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"survives unlink", &ctx()).unwrap();
        engine
            .link(original.inode_id, root, b"alias.txt", &ctx())
            .unwrap();

        engine.unlink(root, b"original.txt", &ctx()).unwrap();

        assert_eq!(
            engine.lookup(root, b"original.txt", &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        let alias = engine.lookup(root, b"alias.txt", &ctx()).unwrap();
        assert_eq!(alias.inode_id, original.inode_id);
        assert_eq!(alias.posix.nlink, 1);
        engine
            .write(&fh, b"survives unlink".len() as u64, b" via fd", &ctx())
            .unwrap();
        let alias_fh = engine.open(alias.inode_id, 0, &ctx()).unwrap();
        assert_eq!(
            engine
                .read(&alias_fh, 0, b"survives unlink via fd".len() as u32, &ctx())
                .unwrap(),
            b"survives unlink via fd"
        );
    }

    #[test]
    fn link_updates_path_cache_for_new_link_name() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (original, _fh) = engine
            .create(root, b"original.txt", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            engine.inode_path(original.inode_id).unwrap(),
            "/original.txt"
        );

        engine
            .link(original.inode_id, root, b"alias.txt", &ctx())
            .unwrap();
        let alias = engine.lookup(root, b"alias.txt", &ctx()).unwrap();

        assert_eq!(alias.inode_id, original.inode_id);
        assert_eq!(engine.inode_path(original.inode_id).unwrap(), "/alias.txt");
    }

    #[test]
    fn link_across_directories_preserves_shared_inode_and_content() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let source_dir = engine.mkdir(root, b"source", 0o755, &ctx()).unwrap();
        let alias_dir = engine.mkdir(root, b"alias", 0o755, &ctx()).unwrap();
        let (original, fh) = engine
            .create(source_dir.inode_id, b"data.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .write(&fh, 0, b"cross-directory link", &ctx())
            .unwrap();

        let linked = engine
            .link(
                original.inode_id,
                alias_dir.inode_id,
                b"data-alias.txt",
                &ctx(),
            )
            .unwrap();

        let original_lookup = engine
            .lookup(source_dir.inode_id, b"data.txt", &ctx())
            .unwrap();
        let alias_lookup = engine
            .lookup(alias_dir.inode_id, b"data-alias.txt", &ctx())
            .unwrap();
        assert_eq!(linked.inode_id, original.inode_id);
        assert_eq!(alias_lookup.inode_id, original.inode_id);
        assert_eq!(original_lookup.inode_id, original.inode_id);
        assert_eq!(linked.posix.nlink, 2);
        assert_eq!(alias_lookup.posix.nlink, 2);

        let alias_fh = engine
            .open(alias_lookup.inode_id, O_RDONLY, &ctx())
            .unwrap();
        assert_eq!(
            engine
                .read(&alias_fh, 0, b"cross-directory link".len() as u32, &ctx())
                .unwrap(),
            b"cross-directory link"
        );
    }

    #[test]
    fn symlink_create_and_read() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine.symlink(root, b"mylink", b"/target", &ctx()).unwrap();
        assert_eq!(attr.kind, NodeKind::Symlink);

        let target = engine.readlink(attr.inode_id, &ctx()).unwrap();
        assert_eq!(target, b"/target");
    }

    #[test]
    fn symlink_under_nonexistent_parent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let missing_parent = InodeId::new(999_999);

        let result = engine.symlink(missing_parent, b"orphan-link", b"target", &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn symlink_with_empty_name_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let result = engine.symlink(root, b"", b"target", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn symlink_with_existing_name_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"taken", 0o644, 0, &ctx()).unwrap();

        let result = engine.symlink(root, b"taken", b"target", &ctx());

        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn readlink_returns_target_for_valid_symlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine
            .symlink(root, b"readlink-target", b"../target/path", &ctx())
            .unwrap();

        let target = engine.readlink(attr.inode_id, &ctx()).unwrap();

        assert_eq!(target, b"../target/path");
    }

    #[test]
    fn readlink_on_regular_file_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"not-a-link.txt", 0o644, 0, &ctx())
            .unwrap();

        let result = engine.readlink(attr.inode_id, &ctx());

        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn readlink_on_directory_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine
            .mkdir(root, b"not-a-link-dir", 0o755, &ctx())
            .unwrap();

        let result = engine.readlink(attr.inode_id, &ctx());

        assert_eq!(result.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn readlink_on_nonexistent_inode_returns_enoent() {
        let (engine, _td) = temp_fs();

        let result = engine.readlink(InodeId::new(999_999), &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn readlink_preserves_long_target_path() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let target = vec![b'a'; 1024];
        let attr = engine
            .symlink(root, b"long-target", target.as_slice(), &ctx())
            .unwrap();

        let result = engine.readlink(attr.inode_id, &ctx()).unwrap();

        assert_eq!(result, target);
    }

    #[test]
    fn readlink_after_symlink_overwrite_returns_new_target() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine
            .symlink(root, b"replace-link", b"old-target", &ctx())
            .unwrap();
        engine.unlink(root, b"replace-link", &ctx()).unwrap();
        let replacement = engine
            .symlink(root, b"replace-link", b"new-target", &ctx())
            .unwrap();

        let target = engine.readlink(replacement.inode_id, &ctx()).unwrap();

        assert_eq!(target, b"new-target");
    }

    #[test]
    fn readlink_after_symlink_unlink_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine
            .symlink(root, b"removed-link", b"target-before-unlink", &ctx())
            .unwrap();

        engine.unlink(root, b"removed-link", &ctx()).unwrap();
        let result = engine.readlink(attr.inode_id, &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn getattr_for_root() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let attr = engine.getattr(root, None, &ctx()).unwrap();
        assert_eq!(attr.inode_id, root);
        assert_eq!(attr.kind, NodeKind::Dir);
    }

    #[test]
    fn getattr_regular_file_returns_correct_attrs() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, fh) = engine.create(root, b"file.txt", 0o640, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"hello", &ctx()).unwrap();

        let attr = engine.getattr(created.inode_id, None, &ctx()).unwrap();

        assert_eq!(attr.inode_id, created.inode_id);
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.size, 5);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o640);
        assert_eq!(attr.posix.nlink, 1);
    }

    #[test]
    fn getattr_directory_returns_dir_kind_and_nlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"dir", 0o750, &ctx()).unwrap();

        let attr = engine.getattr(dir.inode_id, None, &ctx()).unwrap();

        assert_eq!(attr.inode_id, dir.inode_id);
        assert_eq!(attr.kind, NodeKind::Dir);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o750);
        assert!(attr.posix.nlink >= 2);
    }

    #[test]
    fn getattr_symlink_returns_symlink_kind() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let symlink = engine.symlink(root, b"link", b"/target", &ctx()).unwrap();

        let attr = engine.getattr(symlink.inode_id, None, &ctx()).unwrap();

        assert_eq!(attr.inode_id, symlink.inode_id);
        assert_eq!(attr.kind, NodeKind::Symlink);
        assert_eq!(attr.posix.size, b"/target".len() as u64);
    }

    #[test]
    fn getattr_after_setattr_size_reflects_new_size() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, _fh) = engine.create(root, b"size.txt", 0o644, 0, &ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_SIZE;
        update.size = 8192;
        engine
            .setattr(created.inode_id, &update, None, &ctx())
            .unwrap();

        let attr = engine.getattr(created.inode_id, None, &ctx()).unwrap();
        assert_eq!(attr.posix.size, 8192);
    }

    #[test]
    fn getattr_after_setattr_mode_reflects_mode_with_file_type_preserved() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, _fh) = engine.create(root, b"mode.txt", 0o644, 0, &ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_MODE;
        update.mode = S_IFDIR | 0o600;
        engine
            .setattr(created.inode_id, &update, None, &ctx())
            .unwrap();

        let attr = engine.getattr(created.inode_id, None, &ctx()).unwrap();
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.mode & S_IFMT, created.posix.mode & S_IFMT);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o600);
    }

    #[test]
    fn getattr_hard_linked_file_reports_nlink_two() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, _fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();
        engine
            .link(created.inode_id, root, b"alias.txt", &ctx())
            .unwrap();

        let attr = engine.getattr(created.inode_id, None, &ctx()).unwrap();

        assert_eq!(attr.inode_id, created.inode_id);
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.nlink, 2);
    }

    #[test]
    fn getattr_missing_inode_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (created, fh) = engine.create(root, b"gone.txt", 0o644, 0, &ctx()).unwrap();
        // Release before unlink so no open handles keep the inode alive.
        engine.release(&fh).unwrap();

        engine.unlink(root, b"gone.txt", &ctx()).unwrap();

        assert_eq!(
            engine.getattr(created.inode_id, None, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn getattr_with_released_file_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"released-getattr.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(
            engine
                .getattr(attr.inode_id, Some(&fh), &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn getattr_with_unknown_file_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"unknown-getattr.txt", 0o644, 0, &ctx())
            .unwrap();
        let unknown = EngineFileHandle::new(attr.inode_id, 0, FileHandleId::new(999_999), 0);

        assert_eq!(
            engine
                .getattr(attr.inode_id, Some(&unknown), &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn getattr_via_handle_after_write_reflects_updated_size() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"handle-size.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"handle-sized", &ctx()).unwrap();

        let updated = engine.getattr(attr.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(updated.posix.size, b"handle-sized".len() as u64);
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(attr.inode_id, 0, b"handle-sized".len())
                .as_deref(),
            Some(&b"handle-sized"[..]),
            "ordinary VFS writes should remain buffered until flush/fsync"
        );
    }

    // ── Setattr tests ───────────────────────────────────────────────

    #[test]
    fn setattr_mode_preserves_file_type_bits() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"mode.txt", 0o644, 0, &ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_MODE;
        update.mode = S_IFDIR | 0o600;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx())
            .unwrap();

        assert_eq!(updated.kind, NodeKind::File);
        assert_eq!(updated.posix.mode & S_IFMT, attr.posix.mode & S_IFMT);
        assert_eq!(updated.posix.mode & !S_IFMT, 0o600);
    }

    #[test]
    fn setattr_uid_gid_updates_owner_fields() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"owner.txt", 0o644, 0, &ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_UID | FATTR_GID;
        update.uid = 42;
        update.gid = 43;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx())
            .unwrap();

        assert_eq!(updated.posix.uid, 42);
        assert_eq!(updated.posix.gid, 43);
    }

    #[test]
    fn setattr_size_truncates_and_extends_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.create(root, b"size.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 3;
        let shrunk = engine
            .setattr(attr.inode_id, &shrink, None, &ctx())
            .unwrap();
        assert_eq!(shrunk.posix.size, 3);
        assert_eq!(engine.read(&fh, 0, 8, &ctx()).unwrap(), b"abc");

        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = 8;
        let grown = engine.setattr(attr.inode_id, &grow, None, &ctx()).unwrap();
        assert_eq!(grown.posix.size, 8);
        assert_eq!(engine.read(&fh, 0, 8, &ctx()).unwrap(), b"abc\0\0\0\0\0");
    }

    #[test]
    fn setattr_truncate_after_buffered_write_keeps_extent_map_consistent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.create(root, b"buf.dat", 0o644, 0, &ctx()).unwrap();

        // Buffered write that extends the file — below the 256 KiB flush
        // threshold so data stays in the write buffer.
        let payload = vec![b'X'; 4096];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        // Truncate to a smaller size while the write is still buffered.
        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 1024;
        let shrunk = engine
            .setattr(attr.inode_id, &shrink, None, &ctx())
            .unwrap();
        assert_eq!(shrunk.posix.size, 1024);

        // Read must return only the first 1024 bytes, not stale buffered
        // data past the truncation point.
        let content = engine.read(&fh, 0, 4096, &ctx()).unwrap();
        assert_eq!(content.len(), 1024);
        assert!(content.iter().all(|&b| b == b'X'));

        // Fsync and re-stat to ensure committed state is clean.
        engine.fsync(&fh, false, &ctx()).unwrap();
        let after = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
        assert_eq!(after.posix.size, 1024);

        // The extent allocator must have no extents beyond the new size.
        let fs = engine.fs.borrow();
        let extents = fs
            .extent_allocator()
            .lookup_extents(attr.inode_id.0, 1024, 4096);
        assert!(
            extents.is_empty(),
            "extent allocator has extents beyond truncated size 1024: {extents:?}"
        );
    }

    #[test]
    fn setattr_truncate_after_buffered_write_then_extend() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.create(root, b"buf2.dat", 0o644, 0, &ctx()).unwrap();

        // Buffered write extending to 4096.
        let payload = vec![b'Y'; 4096];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        // Truncate down to 512.
        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 512;
        engine
            .setattr(attr.inode_id, &shrink, None, &ctx())
            .unwrap();

        // Extend back to 2048 — zeros should fill the gap.
        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = 2048;
        let grown = engine.setattr(attr.inode_id, &grow, None, &ctx()).unwrap();
        assert_eq!(grown.posix.size, 2048);

        // Read: first 512 are Y, next 1536 should be zeros.
        let content = engine.read(&fh, 0, 2048, &ctx()).unwrap();
        assert_eq!(content.len(), 2048);
        assert!(content[..512].iter().all(|&b| b == b'Y'));
        assert!(content[512..].iter().all(|&b| b == 0));

        // Fsync + stat round-trip.
        engine.fsync(&fh, false, &ctx()).unwrap();
        let after = engine.getattr(attr.inode_id, None, &ctx()).unwrap();
        assert_eq!(after.posix.size, 2048);
    }

    #[test]
    fn setattr_size_on_directory_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_SIZE;
        update.size = 1;

        let result = engine.setattr(root, &update, None, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EISDIR);
    }

    #[test]
    fn setattr_timestamps_update_attr_versions() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"time.txt", 0o644, 0, &ctx()).unwrap();

        let mut update = SetAttr::new();
        update.valid = FATTR_ATIME | FATTR_MTIME | FATTR_CTIME;
        update.atime_ns = 100;
        update.mtime_ns = 200;
        update.ctime_ns = 100;

        let updated = engine
            .setattr(attr.inode_id, &update, None, &ctx())
            .unwrap();

        assert_eq!(updated.posix.atime_ns, 100);
        assert_eq!(updated.posix.ctime_ns, 100);
        assert_eq!(updated.posix.mtime_ns, 200);
    }

    #[test]
    fn setattr_missing_inode_returns_enoent() {
        let (engine, _td) = temp_fs();

        let mut update = SetAttr::new();
        update.valid = FATTR_MODE;
        update.mode = 0o600;

        let result = engine.setattr(InodeId::new(99_999), &update, None, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn setattr_with_released_file_handle_and_fh_bit_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"released-setattr.txt", 0o644, 0, &ctx())
            .unwrap();
        let mut update = SetAttr::new();
        update.valid = FATTR_FH | FATTR_MODE;
        update.mode = 0o600;

        engine.release(&fh).unwrap();

        assert_eq!(
            engine
                .setattr(attr.inode_id, &update, Some(&fh), &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn setattr_with_unknown_file_handle_and_fh_bit_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"unknown-setattr.txt", 0o644, 0, &ctx())
            .unwrap();
        let unknown = EngineFileHandle::new(attr.inode_id, 0, FileHandleId::new(999_999), 0);
        let mut update = SetAttr::new();
        update.valid = FATTR_FH | FATTR_MODE;
        update.mode = 0o600;

        assert_eq!(
            engine
                .setattr(attr.inode_id, &update, Some(&unknown), &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    // ── File I/O tests ────────────────────────────────────────────────

    #[test]
    fn read_partial() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"data.bin", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"abcdefghij", &ctx()).unwrap();

        let data = engine.read(&fh, 2, 5, &ctx()).unwrap();
        assert_eq!(data, b"cdefg");
    }

    #[test]
    fn read_beyond_eof() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"small.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"abc", &ctx()).unwrap();

        let data = engine.read(&fh, 10, 5, &ctx()).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_zero_size_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"zero-size.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        let data = engine.read(&fh, 2, 0, &ctx()).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_at_eof_boundary_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"eof.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        let data = engine.read(&fh, 6, 4, &ctx()).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_that_extends_past_eof_returns_available_tail() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"tail.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        let data = engine.read(&fh, 4, 16, &ctx()).unwrap();
        assert_eq!(data, b"ef");
    }

    #[test]
    fn read_large_payload_across_content_chunks() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"large-read.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload: Vec<u8> = (0..(chunk * 2 + 17)).map(|i| (i % 251) as u8).collect();
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        let data = engine
            .read(&fh, (chunk - 9) as u64, (chunk + 20) as u32, &ctx())
            .unwrap();
        assert_eq!(data, payload[(chunk - 9)..(chunk * 2 + 11)].to_vec());
    }

    #[test]
    fn read_sparse_hole_returns_zeroes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"sparse-read.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        engine
            .write(&fh, (chunk + 2) as u64, b"tail", &ctx())
            .unwrap();

        let data = engine.read(&fh, 0, (chunk + 6) as u32, &ctx()).unwrap();
        assert_eq!(data.len(), chunk + 6);
        assert!(data[..(chunk + 2)].iter().all(|byte| *byte == 0));
        assert_eq!(&data[(chunk + 2)..], b"tail");
    }

    #[test]
    fn read_after_truncate_does_not_return_removed_tail() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"truncate-read.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 4;
        engine
            .setattr(attr.inode_id, &shrink, None, &ctx())
            .unwrap();

        assert_eq!(engine.read(&fh, 0, 16, &ctx()).unwrap(), b"abcd");
        assert!(engine.read(&fh, 4, 4, &ctx()).unwrap().is_empty());
    }

    #[test]
    fn read_empty_file_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"empty.txt", 0o644, 0, &ctx()).unwrap();

        let data = engine.read(&fh, 0, 16, &ctx()).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"released-read.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"data", &ctx()).unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.read(&fh, 0, 4, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn copy_file_range_copies_between_open_file_handles() {
        let (mut engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine
            .write(&source_create, 0, b"0123456789", &ctx())
            .unwrap();
        engine
            .write(&dest_create, 0, b"abcdefghij", &ctx())
            .unwrap();
        engine
            .set_timestamp_policy(TimestampPolicy::Strictatime)
            .expect("set strict-atime policy");
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        let source_before = engine
            .getattr(source_create.inode_id, None, &ctx())
            .expect("source attr before copy");
        let before_mutations = engine.fs.borrow().uncommitted_mutation_count();
        std::thread::sleep(std::time::Duration::from_millis(1));

        // Copy between open file handles; write buffers serve read-your-writes.
        let copied = engine
            .copy_file_range(&source_create, 2, &dest_create, 3, 4, &ctx())
            .unwrap();

        assert_eq!(copied, 4);
        let source_after = engine
            .getattr(source_create.inode_id, None, &ctx())
            .expect("source attr after copy");
        assert!(
            source_after.posix.atime_ns > source_before.posix.atime_ns,
            "partial copy_file_range must record source read access"
        );
        assert_eq!(
            engine.fs.borrow().uncommitted_mutation_count(),
            before_mutations + 1,
            "partial copy_file_range should count the destination data rewrite only"
        );
        assert_eq!(
            engine.read(&dest_create, 0, 10, &ctx()).unwrap(),
            b"abc2345hij"
        );
    }

    #[test]
    fn copy_file_range_short_copies_at_source_eof() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-short-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-short-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&source_create, 0, b"abc", &ctx()).unwrap();
        // Copy between open handles; write buffer serves read-your-writes for short copies.
        let copied = engine
            .copy_file_range(&source_create, 1, &dest_create, 0, 16, &ctx())
            .unwrap();

        assert_eq!(copied, 2);
        assert_eq!(engine.read(&dest_create, 0, 16, &ctx()).unwrap(), b"bc");
    }

    #[test]
    fn copy_file_range_direct_fallback_keeps_unrelated_dest_buffered_writes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-direct-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-direct-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let source: Vec<u8> = (0..128).map(|idx| (idx + 1) as u8).collect();
        let baseline = vec![0x11; 512];
        engine.write(&source_create, 0, &source, &ctx()).unwrap();
        engine.write(&dest_create, 0, &baseline, &ctx()).unwrap();
        engine
            .fs
            .borrow_mut()
            .flush_write_buffer(dest_create.inode_id)
            .unwrap();
        engine
            .fs
            .borrow_mut()
            .set_write_buffer_config(WriteBufferConfig {
                flush_threshold_bytes: 64,
            })
            .expect("test setup mutation must be admitted");
        let outside_dirty = vec![0x5a; 60];
        engine
            .write(&dest_create, 384, &outside_dirty, &ctx())
            .unwrap();

        let copied = engine
            .copy_file_range(&source_create, 8, &dest_create, 64, 16, &ctx())
            .unwrap();

        assert_eq!(copied, 16);
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, 384, outside_dirty.len())
                .as_deref(),
            Some(outside_dirty.as_slice()),
            "copy_file_range must not flush unrelated dirty destination bytes"
        );
        assert_eq!(
            engine.read(&dest_create, 64, 16, &ctx()).unwrap(),
            source[8..24]
        );
        assert_eq!(
            engine
                .read(&dest_create, 384, outside_dirty.len() as u32, &ctx())
                .unwrap(),
            outside_dirty
        );
    }

    #[test]
    fn copy_file_range_direct_fallback_batches_multichunk_writes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-direct-batch-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-direct-batch-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let copy_len = crate::constants::FILESYSTEM_CONTENT_CHUNK_SIZE * 3 + 17;
        let payload: Vec<u8> = (0..copy_len)
            .map(|idx| 0x40_u8.wrapping_add((idx % 191) as u8))
            .collect();
        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        engine
            .fs
            .borrow_mut()
            .set_write_buffer_config(WriteBufferConfig {
                flush_threshold_bytes: 64,
            })
            .expect("test setup mutation must be admitted");
        let outside_offset = (copy_len + 4096) as u64;
        let outside_dirty = vec![0x7c; 60];
        engine
            .write(&dest_create, outside_offset, &outside_dirty, &ctx())
            .unwrap();
        let before_version = engine
            .fs
            .borrow()
            .stat("/copy-direct-batch-dest.txt")
            .unwrap()
            .data_version;

        let copied = engine
            .copy_file_range(&source_create, 0, &dest_create, 0, copy_len as u64, &ctx())
            .unwrap();

        assert_eq!(copied, copy_len as u32);
        let after_version = engine
            .fs
            .borrow()
            .stat("/copy-direct-batch-dest.txt")
            .unwrap()
            .data_version;
        assert_eq!(
            after_version,
            before_version + 1,
            "multi-chunk direct fallback should publish through one content mutation"
        );
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, outside_offset, outside_dirty.len())
                .as_deref(),
            Some(outside_dirty.as_slice()),
            "batched copy_file_range must not flush unrelated dirty destination bytes"
        );
        assert_eq!(
            engine
                .read(&dest_create, 0, copy_len as u32, &ctx())
                .unwrap(),
            payload
        );
    }

    #[test]
    fn copy_file_range_whole_file_accounts_and_releases_destination_capacity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_len = crate::constants::content_chunk_size() as usize;
        let local_fs = PoolDatasetOwner::open_with_capacity(
            dir.path(),
            tidefs_local_object_store::StoreOptions::test_fast(),
            (data_len as u64) * 2,
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(local_fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-capacity-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-capacity-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let payload = vec![0x5a; data_len];

        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            data_len as u64
        );

        let copied = engine
            .copy_file_range(&source_create, 0, &dest_create, 0, data_len as u64, &ctx())
            .unwrap();

        assert_eq!(copied, data_len as u32);
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            (data_len as u64) * 2,
            "whole-file copy fast path must charge the destination bytes"
        );
        assert_eq!(
            engine
                .read(&dest_create, 0, data_len as u32, &ctx())
                .unwrap(),
            payload
        );

        engine.release(&dest_create).unwrap();
        engine
            .unlink(root, b"copy-capacity-dest.txt", &ctx())
            .unwrap();
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            data_len as u64,
            "unlink of whole-file copy destination must release its charged capacity"
        );
    }

    #[test]
    fn copy_file_range_whole_file_advances_destination_subtree_rev() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-rev-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-rev-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let payload = b"whole-file copy revision payload";

        engine.write(&source_create, 0, payload, &ctx()).unwrap();
        {
            let mut fs = engine.fs.borrow_mut();
            let mut seeded = fs
                .get_inode_by_id(dest_create.inode_id)
                .expect("destination inode before copy")
                .clone();
            seeded.subtree_rev = 64;
            fs.update_inode_record(dest_create.inode_id, seeded)
                .expect("seed independent destination subtree_rev");
        }
        let before = engine
            .getattr(dest_create.inode_id, None, &ctx())
            .expect("destination attr before copy");

        let copied = engine
            .copy_file_range(
                &source_create,
                0,
                &dest_create,
                0,
                payload.len() as u64,
                &ctx(),
            )
            .unwrap();

        assert_eq!(copied, payload.len() as u32);
        let after = engine
            .getattr(dest_create.inode_id, None, &ctx())
            .expect("destination attr after copy");
        assert!(
            after.subtree_rev > before.subtree_rev,
            "whole-file copy fast path must advance destination subtree_rev"
        );
        let stored = engine
            .fs
            .borrow()
            .get_inode_by_id(dest_create.inode_id)
            .expect("destination inode")
            .clone();
        assert_eq!(
            after.subtree_rev, stored.subtree_rev,
            "VFS attr must project the stored subtree_rev"
        );
        assert!(
            stored.subtree_rev > stored.metadata_version,
            "seeded subtree_rev must stay independent from metadata_version after reflink copy"
        );
    }

    #[test]
    fn copy_file_range_whole_file_charges_sparse_source_materialized_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let chunk = crate::constants::content_chunk_size() as usize;
        let local_fs = PoolDatasetOwner::open_with_capacity(
            dir.path(),
            tidefs_local_object_store::StoreOptions::test_fast(),
            (chunk as u64) * 5,
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(local_fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-sparse-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-sparse-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let payload = vec![0x5a; chunk * 3];

        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        {
            let mut fs = engine.fs.borrow_mut();
            fs.flush_write_buffer(source_create.inode_id)
                .expect("flush source");
            fs.punch_hole("/copy-sparse-source.txt", chunk as u64, chunk as u64)
                .expect("punch source hole");
        }
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            (chunk as u64) * 2,
            "sparse source setup should charge only materialized chunks"
        );

        let copied = engine
            .copy_file_range(
                &source_create,
                0,
                &dest_create,
                0,
                (chunk as u64) * 3,
                &ctx(),
            )
            .unwrap();

        assert_eq!(copied, (chunk * 3) as u32);
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            (chunk as u64) * 4,
            "whole-file sparse copy must charge only source materialized bytes"
        );
        assert_eq!(
            engine
                .data_ranges(&dest_create, 0, (chunk as u64) * 3, &ctx())
                .unwrap(),
            vec![
                LseekDataRange::new(0, chunk as u64),
                LseekDataRange::new((chunk as u64) * 2, (chunk as u64) * 3),
            ],
            "whole-file copy should preserve sparse source holes"
        );

        engine.release(&dest_create).unwrap();
        engine
            .unlink(root, b"copy-sparse-dest.txt", &ctx())
            .unwrap();
        assert_eq!(
            engine.fs.borrow().capacity_authority().used_bytes(),
            (chunk as u64) * 2,
            "unlink of sparse copy destination must release only materialized clone bytes"
        );
    }

    #[test]
    fn copy_file_range_whole_file_publishes_pool_receipts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_len = crate::constants::content_chunk_size() as usize;
        let local_fs = PoolDatasetOwner::open_with_capacity(
            dir.path(),
            tidefs_local_object_store::StoreOptions::test_fast(),
            (data_len as u64) * 3,
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(local_fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-receipt-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-receipt-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let payload = vec![0x31; data_len];

        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        let copied = engine
            .copy_file_range(&source_create, 0, &dest_create, 0, data_len as u64, &ctx())
            .unwrap();

        assert_eq!(copied, data_len as u32);
        let fs = engine.fs.borrow();
        let dest_record = fs.inode(dest_create.inode_id).unwrap();
        let receipt_generations = fs
            .chunked_content_receipt_generations_for_test(dest_create.inode_id, &dest_record)
            .unwrap()
            .expect("whole-file copy should publish chunked destination content");
        assert!(
            !receipt_generations.is_empty(),
            "whole-file copy should materialize destination chunks"
        );
        assert!(
            receipt_generations.iter().all(|generation| *generation > 0),
            "whole-file copy chunks must carry durable pool receipt generations"
        );
    }

    #[test]
    fn copy_file_range_direct_fallback_clears_batched_dest_ranges() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(
                root,
                b"copy-direct-batch-clear-source.txt",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(
                root,
                b"copy-direct-batch-clear-dest.txt",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();
        let copy_len = crate::constants::FILESYSTEM_CONTENT_CHUNK_SIZE * 2 + 8192;
        let payload: Vec<u8> = (0..copy_len)
            .map(|idx| 0x20_u8.wrapping_add((idx % 173) as u8))
            .collect();
        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        engine
            .write(&dest_create, 0, &vec![0x11; copy_len + 16384], &ctx())
            .unwrap();
        engine
            .fs
            .borrow_mut()
            .flush_write_buffer(dest_create.inode_id)
            .unwrap();

        let dirty_prefix = vec![0xa1; 4096];
        let stale_overlap = vec![0xb2; copy_len - 8192];
        let dirty_suffix = vec![0xc3; 4096];
        engine
            .write(&dest_create, 0, &dirty_prefix, &ctx())
            .unwrap();
        engine
            .write(&dest_create, 4096, &stale_overlap, &ctx())
            .unwrap();
        engine
            .write(
                &dest_create,
                (copy_len - 4096) as u64,
                &dirty_suffix,
                &ctx(),
            )
            .unwrap();

        let copied = engine
            .copy_file_range(
                &source_create,
                0,
                &dest_create,
                4096,
                (copy_len - 8192) as u64,
                &ctx(),
            )
            .unwrap();

        assert_eq!(copied, (copy_len - 8192) as u32);
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, 0, dirty_prefix.len())
                .as_deref(),
            Some(dirty_prefix.as_slice()),
            "dirty prefix outside the copied range should remain buffered"
        );
        assert!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, 4096, stale_overlap.len())
                .is_none(),
            "batched direct copy must clear every overwritten dirty byte"
        );
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(
                    dest_create.inode_id,
                    (copy_len - 4096) as u64,
                    dirty_suffix.len()
                )
                .as_deref(),
            Some(dirty_suffix.as_slice()),
            "dirty suffix outside the copied range should remain buffered"
        );
        assert_eq!(
            engine.read(&dest_create, 4096, copied, &ctx()).unwrap(),
            payload[..copied as usize]
        );
    }

    #[test]
    fn copy_file_range_direct_fallback_clears_overwritten_dest_buffered_writes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"copy-direct-clear-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"copy-direct-clear-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let source: Vec<u8> = (0..96).map(|idx| 0xa0_u8.wrapping_add(idx as u8)).collect();
        engine.write(&source_create, 0, &source, &ctx()).unwrap();
        engine.write(&dest_create, 0, &[0x33; 160], &ctx()).unwrap();
        engine
            .fs
            .borrow_mut()
            .flush_write_buffer(dest_create.inode_id)
            .unwrap();
        let stale = b"stale buffered bytes";
        engine.write(&dest_create, 40, stale, &ctx()).unwrap();
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, 40, stale.len())
                .as_deref(),
            Some(stale.as_slice())
        );

        let copied = engine
            .copy_file_range(
                &source_create,
                12,
                &dest_create,
                40,
                stale.len() as u64,
                &ctx(),
            )
            .unwrap();

        assert_eq!(copied, stale.len() as u32);
        assert!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(dest_create.inode_id, 40, stale.len())
                .is_none(),
            "overwritten destination bytes must not remain buffered"
        );
        assert_eq!(
            engine
                .read(&dest_create, 40, stale.len() as u32, &ctx())
                .unwrap(),
            source[12..12 + stale.len()]
        );
    }

    #[test]
    fn copy_file_range_whole_file_to_empty_dest_flushes_buffered_source() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_source_attr, source_create) = engine
            .create(root, b"generic001-source.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dest_attr, dest_create) = engine
            .create(root, b"generic001-dest.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let payload: Vec<u8> = (0..819_200).map(|idx| (idx % 251) as u8).collect();
        engine.write(&source_create, 0, &payload, &ctx()).unwrap();
        assert!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(source_create.inode_id, 0, payload.len())
                .is_some(),
            "test setup should leave source data in the engine write buffer"
        );

        let copied = engine
            .copy_file_range(
                &source_create,
                0,
                &dest_create,
                0,
                payload.len() as u64,
                &ctx(),
            )
            .unwrap();

        assert_eq!(copied, payload.len() as u32);
        assert!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(source_create.inode_id, 0, payload.len())
                .is_none(),
            "whole-file copy should publish the source before reflinking"
        );
        assert_eq!(
            engine
                .read(&dest_create, 0, payload.len() as u32, &ctx())
                .unwrap(),
            payload
        );
    }

    #[test]
    fn copy_file_range_after_fsx075_prefix_preserves_sparse_bytes() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add((idx % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut [u8], offset: usize, len: usize) {
            let end = offset.saturating_add(len).min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-prefix.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let mut expected = Vec::new();

        let first = pattern(0xb92e, 0x31);
        engine.write(&fh, 0x1db8f, &first, &ctx()).unwrap();
        overlay(&mut expected, 0x1db8f, &first);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x2a3a,
                0xf74,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x2a3a, 0xf74);

        assert_eq!(
            engine.read(&fh, 0x17ffa, 0xb584, &ctx()).unwrap(),
            expected[0x17ffa..0x17ffa + 0xb584]
        );

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x12e33,
                0x62c8,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x12e33, 0x62c8);

        assert_eq!(
            engine.read(&fh, 0x20525, 0xe46, &ctx()).unwrap(),
            expected[0x20525..0x20525 + 0xe46]
        );
        assert_eq!(
            engine.read(&fh, 0x19fc7, 0xf4f6, &ctx()).unwrap(),
            expected[0x19fc7..0x19fc7 + 0xf4f6]
        );

        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 0xb4e4;
        engine
            .setattr(fh.inode_id, &shrink, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0xb4e4);

        let second = pattern(0x94bd, 0x73);
        engine.write(&fh, 0x36b43, &second, &ctx()).unwrap();
        overlay(&mut expected, 0x36b43, &second);

        assert_eq!(
            engine.read(&fh, 0x3985f, 0x67a1, &ctx()).unwrap(),
            expected[0x3985f..0x3985f + 0x67a1]
        );

        let copied = engine
            .copy_file_range(&fh, 0x2bb0b, &fh, 0x170e0, 0xb520, &ctx())
            .unwrap();
        assert_eq!(copied, 0xb520);
        let copied_bytes = expected[0x2bb0b..0x2bb0b + 0xb520].to_vec();
        overlay(&mut expected, 0x170e0, &copied_bytes);

        assert_eq!(
            engine.read(&fh, 0x170e0, 0xb520, &ctx()).unwrap(),
            copied_bytes
        );
    }

    #[test]
    fn copy_file_range_after_fsx075_writeback_prefix_preserves_sparse_bytes() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add((idx % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut [u8], offset: usize, len: usize) {
            let end = offset.saturating_add(len).min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-writeback-prefix.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let mut expected = Vec::new();

        let first = pattern(0x6ae8, 0x41);
        engine.write(&fh, 0x39518, &first, &ctx()).unwrap();
        overlay(&mut expected, 0x39518, &first);

        let mut shrink = SetAttr::new();
        shrink.valid = FATTR_SIZE;
        shrink.size = 0x25bf;
        engine
            .setattr(fh.inode_id, &shrink, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x25bf);

        assert_eq!(
            engine.read(&fh, 0x17f2, 0xdcd, &ctx()).unwrap(),
            expected[0x17f2..0x17f2 + 0xdcd]
        );
        assert_eq!(
            engine.read(&fh, 0x31f, 0x22a0, &ctx()).unwrap(),
            expected[0x31f..0x31f + 0x22a0]
        );

        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = 0x22a95;
        engine
            .setattr(fh.inode_id, &grow, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x22a95, 0);

        shrink.size = 0x219e6;
        engine
            .setattr(fh.inode_id, &shrink, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x219e6);

        let second = pattern(0x3aac, 0x91);
        engine.write(&fh, 0x216fc, &second, &ctx()).unwrap();
        overlay(&mut expected, 0x216fc, &second);

        assert_eq!(
            engine.read(&fh, 0xd117, 0xa010, &ctx()).unwrap(),
            expected[0xd117..0xd117 + 0xa010]
        );

        grow.size = 0x32888;
        engine
            .setattr(fh.inode_id, &grow, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x32888, 0);

        assert_eq!(
            engine.read(&fh, 0x1d8fc, 0xa8e9, &ctx()).unwrap(),
            expected[0x1d8fc..0x1d8fc + 0xa8e9]
        );

        grow.size = 0x3f390;
        engine
            .setattr(fh.inode_id, &grow, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x3f390, 0);

        assert_eq!(
            engine.read(&fh, 0x1927e, 0x9d6e, &ctx()).unwrap(),
            expected[0x1927e..0x1927e + 0x9d6e]
        );

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x1f6d6,
                0xe322,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x1f6d6, 0xe322);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x1a2b0,
                0xd85e,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x1a2b0, 0xd85e);

        let copied = engine
            .copy_file_range(&fh, 0x4c6b, &fh, 0x2f46d, 0x6457, &ctx())
            .unwrap();
        assert_eq!(copied, 0x6457);
        let copied_bytes = expected[0x4c6b..0x4c6b + 0x6457].to_vec();
        overlay(&mut expected, 0x2f46d, &copied_bytes);

        assert_eq!(
            engine.read(&fh, 0x2f46d, 0x6457, &ctx()).unwrap(),
            copied_bytes
        );
    }

    #[test]
    fn zero_range_without_keep_size_extends_before_fsx075_sparse_copy() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-zero-copy.bin", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x25c2d, 0x6201, &ctx())
            .unwrap();
        assert_eq!(
            engine
                .getattr(fh.inode_id, Some(&fh), &ctx())
                .unwrap()
                .posix
                .size,
            0x2be2e
        );
        assert_eq!(
            engine.read(&fh, 0x25c2d, 0x6201, &ctx()).unwrap(),
            vec![0; 0x6201]
        );

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x2afd7,
                0x530f,
                &ctx(),
            )
            .unwrap();
        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x12f42,
                0x6239,
                &ctx(),
            )
            .unwrap();

        let copied = engine
            .copy_file_range(&fh, 0x28341, &fh, 0x3b1e6, 0x1e91, &ctx())
            .unwrap();
        assert_eq!(copied, 0x1e91);
        assert_eq!(
            engine
                .getattr(fh.inode_id, Some(&fh), &ctx())
                .unwrap()
                .posix
                .size,
            0x3d077
        );
        assert_eq!(
            engine.read(&fh, 0x3b1e6, 0x1e91, &ctx()).unwrap(),
            vec![0; 0x1e91]
        );
    }

    #[test]
    fn copy_file_range_after_fsx075_sparse_truncate_copies_zeroes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(
                root,
                b"fsx075-sparse-truncate-copy.bin",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();

        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;
        truncate.size = 0x351e5;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();

        assert_eq!(
            engine.read(&fh, 0x22535, 0xd1bc, &ctx()).unwrap(),
            vec![0; 0xd1bc]
        );
        assert_eq!(
            engine.read(&fh, 0x10713, 0x808a, &ctx()).unwrap(),
            vec![0; 0x808a]
        );

        let copied = engine
            .copy_file_range(&fh, 0x20c96, &fh, 0x1351e, 0xb039, &ctx())
            .unwrap();
        assert_eq!(copied, 0xb039);
        assert_eq!(
            engine.read(&fh, 0x1351e, 0xb039, &ctx()).unwrap(),
            vec![0; 0xb039]
        );
    }

    #[test]
    fn deferred_copy_file_range_after_fsx075_sparse_truncate_commits_consistently() {
        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(
                root,
                b"fsx075-deferred-sparse-truncate-copy.bin",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();

        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;
        truncate.size = 0x351e5;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();

        assert_eq!(
            engine.read(&fh, 0x22535, 0xd1bc, &ctx()).unwrap(),
            vec![0; 0xd1bc]
        );
        assert_eq!(
            engine.read(&fh, 0x10713, 0x808a, &ctx()).unwrap(),
            vec![0; 0x808a]
        );

        let copied = engine
            .copy_file_range(&fh, 0x20c96, &fh, 0x1351e, 0xb039, &ctx())
            .unwrap();
        assert_eq!(copied, 0xb039);
        assert_eq!(
            engine.read(&fh, 0x1351e, 0xb039, &ctx()).unwrap(),
            vec![0; 0xb039]
        );
        engine.fs.borrow_mut().sync_all().unwrap();
    }

    #[test]
    fn copy_file_range_sparse_zero_source_clears_dirty_destination() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(
                root,
                b"fsx075-zero-copy-clears-dirty.bin",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();
        let len = 8192usize;
        let source_offset = u64::from(crate::constants::content_chunk_size()) * 2;
        let dirty = vec![0x5a; len];

        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = source_offset + len as u64;
        engine
            .setattr(fh.inode_id, &grow, Some(&fh), &ctx())
            .unwrap();
        engine.write(&fh, 0, &dirty, &ctx()).unwrap();

        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(fh.inode_id, 0, len)
                .as_deref(),
            Some(dirty.as_slice())
        );

        let copied = engine
            .copy_file_range(&fh, source_offset, &fh, 0, len as u64, &ctx())
            .unwrap();
        assert_eq!(copied, len as u32);
        assert_eq!(
            engine.read(&fh, 0, len as u32, &ctx()).unwrap(),
            vec![0; len]
        );
        assert!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(fh.inode_id, 0, len)
                .is_none(),
            "zero-source copy should clear overwritten dirty destination bytes"
        );
    }

    #[test]
    fn copy_file_range_sparse_zero_source_extends_destination() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_src_attr, src_fh) = engine
            .create(root, b"fsx075-zero-copy-source.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (_dst_attr, dst_fh) = engine
            .create(root, b"fsx075-zero-copy-dest.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let chunk = u64::from(crate::constants::content_chunk_size());
        let len = 4096_u64;

        let mut grow = SetAttr::new();
        grow.valid = FATTR_SIZE;
        grow.size = chunk * 3;
        engine
            .setattr(src_fh.inode_id, &grow, Some(&src_fh), &ctx())
            .unwrap();

        let dest_offset = chunk * 2;
        let copied = engine
            .copy_file_range(&src_fh, chunk, &dst_fh, dest_offset, len, &ctx())
            .unwrap();
        assert_eq!(copied, len as u32);
        assert_eq!(
            engine
                .getattr(dst_fh.inode_id, Some(&dst_fh), &ctx())
                .unwrap()
                .posix
                .size,
            dest_offset + len
        );
        assert_eq!(
            engine
                .read(&dst_fh, dest_offset, len as u32, &ctx())
                .unwrap(),
            vec![0; len as usize]
        );
        assert_eq!(
            engine
                .data_ranges(&dst_fh, 0, dest_offset + len, &ctx())
                .unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn deferred_fsx075_seed0_sparse_copy_truncate_write_commits_consistently() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add((idx % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut [u8], offset: usize, len: usize) {
            let end = offset.saturating_add(len).min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-seed0.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let mut expected = Vec::new();

        let first = pattern(0xb218, 0x11);
        engine.write(&fh, 0x267e2, &first, &ctx()).unwrap();
        overlay(&mut expected, 0x267e2, &first);
        let mut atime = SetAttr::new();
        atime.valid = FATTR_ATIME_NOW;
        engine
            .setattr(fh.inode_id, &atime, Some(&fh), &ctx())
            .unwrap();
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_from_write_buffer(fh.inode_id, 0x267e2, first.len())
                .as_deref(),
            Some(first.as_slice())
        );
        assert_eq!(
            engine.read(&fh, 0x2045a, 0xe1f6, &ctx()).unwrap(),
            expected[0x2045a..0x2045a + 0xe1f6]
        );

        let copied = engine
            .copy_file_range(&fh, 0x2045a, &fh, 0x5380, 0xe1f6, &ctx())
            .unwrap();
        assert_eq!(copied, 0xe1f6);
        let copied_bytes = expected[0x2045a..0x2045a + 0xe1f6].to_vec();
        overlay(&mut expected, 0x5380, &copied_bytes);

        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;
        truncate.size = 0x1098c;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x1098c);

        let second = pattern(0x78c4, 0x42);
        engine.write(&fh, 0x15110, &second, &ctx()).unwrap();
        overlay(&mut expected, 0x15110, &second);

        truncate.size = 0x2b2c;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x2b2c);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x2612,
                0x51a,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x2612, 0x51a);

        let copied = engine
            .copy_file_range(&fh, 0x4a8, &fh, 0x67b1, 0x2001, &ctx())
            .unwrap();
        assert_eq!(copied, 0x2001);
        let copied_bytes = expected[0x4a8..0x4a8 + 0x2001].to_vec();
        overlay(&mut expected, 0x67b1, &copied_bytes);

        let third = pattern(0x782a, 0x93);
        engine.write(&fh, 0x6f15, &third, &ctx()).unwrap();
        overlay(&mut expected, 0x6f15, &third);

        assert_eq!(
            engine.read(&fh, 0, expected.len() as u32, &ctx()).unwrap(),
            expected
        );
        engine.fs.borrow_mut().sync_all().unwrap();
    }

    #[test]
    fn fsx075_late_sparse_copy_after_zero_punch_truncate_reads_source() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add((idx % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut Vec<u8>, offset: usize, len: usize, keep_size: bool) {
            let end = offset.checked_add(len).expect("zero end");
            if !keep_size && expected.len() < end {
                expected.resize(end, 0);
            }
            let end = end.min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        fn resize(expected: &mut Vec<u8>, size: usize) {
            expected.resize(size, 0);
        }

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-late-sparse-copy.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let mut expected = Vec::new();

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x7ba8, 0x3fb5, &ctx())
            .unwrap();
        zero(&mut expected, 0x7ba8, 0x3fb5, false);

        let first = pattern(0x2d4b, 0x21);
        engine.write(&fh, 0x16c18, &first, &ctx()).unwrap();
        overlay(&mut expected, 0x16c18, &first);

        engine.fallocate(&fh, 0, 0x33f5b, 0xb011, &ctx()).unwrap();
        resize(&mut expected, 0x3ef6c);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0xa402,
                0xd8ec,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0xa402, 0xd8ec, true);

        let second = pattern(0x28e0, 0x42);
        engine.write(&fh, 0x2cd5, &second, &ctx()).unwrap();
        overlay(&mut expected, 0x2cd5, &second);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x30c58,
                0x1c80,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x30c58, 0x1c80, true);

        let third = pattern(0x739b, 0x63);
        engine.write(&fh, 0x33335, &third, &ctx()).unwrap();
        overlay(&mut expected, 0x33335, &third);

        engine.fallocate(&fh, 0, 0x323aa, 0x5a10, &ctx()).unwrap();

        let fourth = pattern(0x37ec, 0x84);
        engine.write(&fh, 0x3c814, &fourth, &ctx()).unwrap();
        overlay(&mut expected, 0x3c814, &fourth);

        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;
        truncate.size = 0x33952;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x33952);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x231c3,
                0x517b,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x231c3, 0x517b, true);

        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x2c381, 0xfaf3, &ctx())
            .unwrap();
        zero(&mut expected, 0x2c381, 0xfaf3, false);

        let fifth = pattern(0x360f, 0xa5);
        engine.write(&fh, 0x13b37, &fifth, &ctx()).unwrap();
        overlay(&mut expected, 0x13b37, &fifth);

        let sixth = pattern(0x57c6, 0xc6);
        engine.write(&fh, 0xe1a7, &sixth, &ctx()).unwrap();
        overlay(&mut expected, 0xe1a7, &sixth);

        let copied = engine
            .copy_file_range(&fh, 0xde31, &fh, 0x1c07e, 0xb6d2, &ctx())
            .unwrap();
        assert_eq!(copied, 0xb6d2);
        let copied_bytes = expected[0xde31..0xde31 + 0xb6d2].to_vec();
        overlay(&mut expected, 0x1c07e, &copied_bytes);

        assert_eq!(
            engine.read(&fh, 0x1c07e, 0xb6d2, &ctx()).unwrap(),
            copied_bytes
        );
        engine.fs.borrow_mut().sync_all().unwrap();
    }

    #[test]
    fn fsx075_qemu_copy_after_mapwrite_zero_write_commits_consistently() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add(((idx * 47) % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut Vec<u8>, offset: usize, len: usize, keep_size: bool) {
            let end = offset.checked_add(len).expect("zero end");
            if !keep_size && expected.len() < end {
                expected.resize(end, 0);
            }
            let end = end.min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(
                root,
                b"fsx075-qemu-mapwrite-copy.bin",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();
        let mut expected = Vec::new();

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0x8ab4, 0xee3f, &ctx())
            .unwrap();
        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x2c9d2,
                0xb237,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x2c9d2, 0xb237, true);

        let first = pattern(0xd3dc, 0x11);
        engine.write(&fh, 0xe8bb, &first, &ctx()).unwrap();
        overlay(&mut expected, 0xe8bb, &first);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0xbac,
                0x5ce3,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0xbac, 0x5ce3, true);

        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;
        truncate.size = 0x1d720;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x1d720, 0);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x1b6c8,
                0x2058,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x1b6c8, 0x2058, true);

        truncate.size = 0x2b22f;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x2b22f, 0);

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0x37a99, 0x17d1, &ctx())
            .unwrap();

        truncate.size = 0x1298a;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x1298a);

        let mapped = pattern(0xcbe0, 0x33);
        engine.write(&fh, 0x1ac43, &mapped, &ctx()).unwrap();
        overlay(&mut expected, 0x1ac43, &mapped);

        let second = pattern(0x1eeb, 0x55);
        engine.write(&fh, 0x15631, &second, &ctx()).unwrap();
        overlay(&mut expected, 0x15631, &second);

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0x2be05, 0x909b, &ctx())
            .unwrap();
        assert_eq!(
            engine.read(&fh, 0xe72c, 0xc85e, &ctx()).unwrap(),
            expected[0xe72c..0xe72c + 0xc85e]
        );

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x3a761,
                0x103b,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x3a761, 0x103b, true);

        let third = pattern(0x25fe, 0x77);
        engine.write(&fh, 0x39037, &third, &ctx()).unwrap();
        overlay(&mut expected, 0x39037, &third);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                0x273ea,
                0x6e1c,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x273ea, 0x6e1c, true);

        let fourth = pattern(0x685c, 0x99);
        engine.write(&fh, 0x2abfa, &fourth, &ctx()).unwrap();
        overlay(&mut expected, 0x2abfa, &fourth);

        let copied = engine
            .copy_file_range(&fh, 0x1f07b, &fh, 0x6bfd, 0xd646, &ctx())
            .unwrap();
        assert_eq!(copied, 0xd646);
        let copied_bytes = expected[0x1f07b..0x1f07b + 0xd646].to_vec();
        overlay(&mut expected, 0x6bfd, &copied_bytes);

        assert_eq!(
            engine.read(&fh, 0x6bfd, 0xd646, &ctx()).unwrap(),
            copied_bytes
        );
        engine.fs.borrow_mut().sync_all().unwrap();
    }

    #[test]
    fn fsx075_qemu_seed0_copy_after_late_truncate_commits_consistently() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add(((idx * 43) % 251) as u8))
                .collect()
        }

        fn overlay(expected: &mut Vec<u8>, offset: usize, data: &[u8]) {
            let end = offset.checked_add(data.len()).expect("overlay end");
            if expected.len() < end {
                expected.resize(end, 0);
            }
            expected[offset..end].copy_from_slice(data);
        }

        fn zero(expected: &mut Vec<u8>, offset: usize, len: usize, keep_size: bool) {
            let end = offset.checked_add(len).expect("zero end");
            if !keep_size && expected.len() < end {
                expected.resize(end, 0);
            }
            let end = end.min(expected.len());
            if offset < end {
                expected[offset..end].fill(0);
            }
        }

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(
                root,
                b"fsx075-qemu-late-truncate-copy.bin",
                0o644,
                O_RDWR,
                &ctx(),
            )
            .unwrap();
        let mut expected = Vec::new();
        let mut truncate = SetAttr::new();
        truncate.valid = FATTR_SIZE;

        let first = pattern(0xa75b, 0x13);
        engine.write(&fh, 0x2b0b5, &first, &ctx()).unwrap();
        overlay(&mut expected, 0x2b0b5, &first);

        truncate.size = 0x2a832;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0x2a832);

        let mapwrite_a = pattern(0x88dc, 0x35);
        engine.write(&fh, 0x2ac, &mapwrite_a, &ctx()).unwrap();
        overlay(&mut expected, 0x2ac, &mapwrite_a);

        truncate.size = 0x2fe75;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x2fe75, 0);

        let high_a = pattern(0x1d9d, 0x57);
        engine.write(&fh, 0x3e263, &high_a, &ctx()).unwrap();
        overlay(&mut expected, 0x3e263, &high_a);

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0x2b831, 0x55d2, &ctx())
            .unwrap();

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x21108,
                0x6e8f,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0x21108, 0x6e8f, true);

        assert_eq!(
            engine.read(&fh, 0x37755, 0x1f53, &ctx()).unwrap(),
            expected[0x37755..0x37755 + 0x1f53]
        );

        let high_b = pattern(0x3f9b, 0x79);
        engine.write(&fh, 0x3c065, &high_b, &ctx()).unwrap();
        overlay(&mut expected, 0x3c065, &high_b);

        engine.fallocate(&fh, 0, 0x2ccd9, 0x604c, &ctx()).unwrap();

        let mid = pattern(0x42ce, 0x9b);
        engine.write(&fh, 0x1f3d4, &mid, &ctx()).unwrap();
        overlay(&mut expected, 0x1f3d4, &mid);

        let mapwrite_b = pattern(0xd9ab, 0xbd);
        engine.write(&fh, 0x17ef2, &mapwrite_b, &ctx()).unwrap();
        overlay(&mut expected, 0x17ef2, &mapwrite_b);

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0x3635e, 0x9ca2, &ctx())
            .unwrap();

        truncate.size = 0xc04d;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.truncate(0xc04d);

        truncate.size = 0xfc8a;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0xfc8a, 0);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0xd754,
                0x2536,
                &ctx(),
            )
            .unwrap();
        zero(&mut expected, 0xd754, 0x2536, true);

        truncate.size = 0x10a1d;
        engine
            .setattr(fh.inode_id, &truncate, Some(&fh), &ctx())
            .unwrap();
        expected.resize(0x10a1d, 0);

        let copied = engine
            .copy_file_range(&fh, 0x895e, &fh, 0x1c9b5, 0x5c8d, &ctx())
            .unwrap();
        assert_eq!(copied, 0x5c8d);
        let copied_bytes = expected[0x895e..0x895e + 0x5c8d].to_vec();
        overlay(&mut expected, 0x1c9b5, &copied_bytes);

        assert_eq!(
            engine.read(&fh, 0x1c9b5, 0x5c8d, &ctx()).unwrap(),
            copied_bytes
        );
        engine.fs.borrow_mut().sync_all().unwrap();
    }

    #[test]
    fn fsx075_qemu_seed0_punch_op120_returns() {
        fn pattern(len: usize, seed: u8) -> Vec<u8> {
            (0..len)
                .map(|idx| seed.wrapping_add(((idx * 37) % 251) as u8))
                .collect()
        }

        fn truncate(engine: &VfsLocalFileSystem, inode: InodeId, fh: &EngineFileHandle, size: u64) {
            let mut attr = SetAttr::new();
            attr.valid = FATTR_SIZE;
            attr.size = size;
            engine.setattr(inode, &attr, Some(fh), &ctx()).unwrap();
        }

        fn write(engine: &VfsLocalFileSystem, fh: &EngineFileHandle, offset: u64, len: usize) {
            let data = pattern(len, (offset as u8).wrapping_add(len as u8));
            engine.write(fh, offset, &data, &ctx()).unwrap();
        }

        fn read(engine: &VfsLocalFileSystem, fh: &EngineFileHandle, offset: u64, len: u32) {
            let _ = engine.read(fh, offset, len, &ctx()).unwrap();
        }

        let (engine, _td) = temp_fs();
        engine
            .fs
            .borrow_mut()
            .set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        engine
            .fs
            .borrow_mut()
            .set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fsx075-qemu-seed0-op120.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        let inode = fh.inode_id;

        write(&engine, &fh, 0x71301c, 0xc0cf);
        truncate(&engine, inode, &fh, 0x873298);
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x22281c, &fh, 0x700273, 0x30e, &ctx())
                .unwrap(),
            0x30e
        );
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x1a7640,
                0x7edb,
                &ctx(),
            )
            .unwrap();
        write(&engine, &fh, 0x10f81d, 0x95e7);
        read(&engine, &fh, 0xcb34e, 0xce8);
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x529e03,
                0x8b88,
                &ctx(),
            )
            .unwrap();
        write(&engine, &fh, 0x610c0b, 0x701b);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x4c2a4b, 0x9c77, &ctx())
            .unwrap();
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x832095, &fh, 0x4044e3, 0x3c3, &ctx())
                .unwrap(),
            0x3c3
        );
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x799a6a, &fh, 0x9cb6b8, 0xbb0b, &ctx())
                .unwrap(),
            0xbb0b
        );
        read(&engine, &fh, 0x1bf83e, 0xe405);
        write(&engine, &fh, 0x980e91, 0x1c68);
        write(&engine, &fh, 0x3c1c6e, 0xbe3b);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x301fed, 0xd3d7, &ctx())
            .unwrap();
        read(&engine, &fh, 0x856a9f, 0x12fe);
        write(&engine, &fh, 0x977ab0, 0x6481);
        read(&engine, &fh, 0x72d32d, 0x6a7c);
        read(&engine, &fh, 0x3d5e61, 0xc5c9);
        truncate(&engine, inode, &fh, 0x3ce150);
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x331abb,
                0x9d06,
                &ctx(),
            )
            .unwrap();
        read(&engine, &fh, 0x38dab7, 0x85d0);
        write(&engine, &fh, 0x76a58f, 0x7855);
        write(&engine, &fh, 0x1ec936, 0x870);
        write(&engine, &fh, 0x6f96a5, 0x7ac1);
        engine.fallocate(&fh, 0, 0x697b56, 0x4014, &ctx()).unwrap();
        read(&engine, &fh, 0x431db4, 0xaa8b);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x56fec8, 0x29a, &ctx())
            .unwrap();
        write(&engine, &fh, 0x87a863, 0x146c);
        truncate(&engine, inode, &fh, 0x7ddbfb);
        read(&engine, &fh, 0x335357, 0x5595);
        read(&engine, &fh, 0x1b3eae, 0x5212);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x422e9b, 0x7238, &ctx())
            .unwrap();
        write(&engine, &fh, 0x177b27, 0x8b18);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x1cc9e9, 0xb8dd, &ctx())
            .unwrap();
        write(&engine, &fh, 0x6f86de, 0x3817);
        truncate(&engine, inode, &fh, 0x4667a3);
        truncate(&engine, inode, &fh, 0x3d0eec);
        write(&engine, &fh, 0x360425, 0x268a);
        read(&engine, &fh, 0x217989, 0xf923);
        assert_eq!(
            engine
                .copy_file_range(&fh, 0xcba3c, &fh, 0x4c462b, 0x234c, &ctx())
                .unwrap(),
            0x234c
        );
        read(&engine, &fh, 0x352039, 0x5225);
        engine.fallocate(&fh, 0, 0x9f1d2c, 0x3191, &ctx()).unwrap();
        write(&engine, &fh, 0x3c4d46, 0xef33);
        truncate(&engine, inode, &fh, 0x461ee6);
        read(&engine, &fh, 0x3493f1, 0x213c);
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x11f791, &fh, 0x2b0463, 0x9b23, &ctx())
                .unwrap(),
            0x9b23
        );
        engine.fallocate(&fh, 0, 0x159e81, 0x6c02, &ctx()).unwrap();
        write(&engine, &fh, 0x9f5755, 0x9162);
        engine.fallocate(&fh, 0, 0x4295c, 0xf36b, &ctx()).unwrap();
        write(&engine, &fh, 0x3667f3, 0x9558);
        read(&engine, &fh, 0x311ecf, 0xb9cf);
        write(&engine, &fh, 0x33e512, 0x3db5);
        write(&engine, &fh, 0x4de64b, 0xc649);
        read(&engine, &fh, 0x71095c, 0x9a27);
        read(&engine, &fh, 0x8c742, 0xa79a);
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x54ff67, 0xa723, &ctx())
            .unwrap();
        write(&engine, &fh, 0x6a8f2d, 0xd655);
        write(&engine, &fh, 0x43f746, 0xd632);
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x7a265d, &fh, 0x478aac, 0xb17a, &ctx())
                .unwrap(),
            0xb17a
        );
        engine.fallocate(&fh, 0, 0x34737d, 0xeae7, &ctx()).unwrap();
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x659b24,
                0xd2f,
                &ctx(),
            )
            .unwrap();
        write(&engine, &fh, 0x42ac29, 0x1c19);
        engine.fallocate(&fh, 0, 0x6a19bf, 0x9edc, &ctx()).unwrap();
        engine.fallocate(&fh, 0, 0x62eeb9, 0x1629, &ctx()).unwrap();
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x21a1cd,
                0x42e6,
                &ctx(),
            )
            .unwrap();
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x408892, &fh, 0x707697, 0x1873, &ctx())
                .unwrap(),
            0x1873
        );
        engine
            .fallocate(&fh, FALLOC_FL_ZERO_RANGE, 0x8c9c97, 0x41c1, &ctx())
            .unwrap();
        truncate(&engine, inode, &fh, 0x9877b8);
        write(&engine, &fh, 0x824086, 0x4dfb);
        assert_eq!(
            engine
                .copy_file_range(&fh, 0x80b115, &fh, 0x9ed46b, 0x7b06, &ctx())
                .unwrap(),
            0x7b06
        );
        truncate(&engine, inode, &fh, 0x298065);
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x204d56,
                0x7d6e,
                &ctx(),
            )
            .unwrap();
        read(&engine, &fh, 0x452bb, 0xe3d6);

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0x100968,
                0x4c51,
                &ctx(),
            )
            .unwrap();
    }

    #[test]
    fn copy_file_range_rejects_bad_access_released_handles_and_overlap() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (source_attr, source_create) = engine
            .create(root, b"copy-errors-source.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let (dest_attr, dest_create) = engine
            .create(root, b"copy-errors-dest.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine
            .write(&source_create, 0, b"abcdefgh", &ctx())
            .unwrap();
        engine.write(&dest_create, 0, b"target", &ctx()).unwrap();
        // Flush before release so subsequent open sees durable data.
        engine.flush(&source_create, &ctx()).unwrap();
        engine.flush(&dest_create, &ctx()).unwrap();
        engine.release(&source_create).unwrap();
        engine.release(&dest_create).unwrap();

        // Bad access: source write-only.
        let source_write_only = engine.open(source_attr.inode_id, O_WRONLY, &ctx()).unwrap();
        let dest_read_write = engine.open(dest_attr.inode_id, O_RDWR, &ctx()).unwrap();
        assert_eq!(
            engine
                .copy_file_range(&source_write_only, 0, &dest_read_write, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
        engine.release(&source_write_only).unwrap();

        // Bad access: dest read-only.
        let source_read_only = engine.open(source_attr.inode_id, O_RDONLY, &ctx()).unwrap();
        let dest_read_only = engine.open(dest_attr.inode_id, O_RDONLY, &ctx()).unwrap();
        assert_eq!(
            engine
                .copy_file_range(&source_read_only, 0, &dest_read_only, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
        engine.release(&dest_read_only).unwrap();

        // Successful copy via flushed open handles.
        assert_eq!(
            engine
                .copy_file_range(&source_read_only, 0, &dest_read_write, 0, 1, &ctx())
                .unwrap(),
            1
        );
        engine.release(&dest_read_write).unwrap();

        // Released handles: fail.
        assert_eq!(
            engine
                .copy_file_range(&source_read_only, 0, &dest_read_write, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );

        // Self-overlap: same inode, overlapping ranges.
        let same_inode_source = engine.open(source_attr.inode_id, O_RDWR, &ctx()).unwrap();
        let same_inode_dest = engine.open(source_attr.inode_id, O_RDWR, &ctx()).unwrap();
        assert_eq!(
            engine
                .copy_file_range(&same_inode_source, 0, &same_inode_dest, 1, 4, &ctx())
                .unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn open_and_release() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"hello", &ctx()).unwrap();
        let fh2 = engine.open(fh.inode_id, 0, &ctx()).unwrap();
        assert_eq!(fh2.inode_id, fh.inode_id);
        assert_ne!(fh2.fh_id, FileHandleId::default());
        assert_eq!(engine.read(&fh2, 0, 5, &ctx()).unwrap(), b"hello");
        engine.release(&fh2).unwrap();
        assert_eq!(engine.read(&fh2, 0, 5, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn open_rdonly_allows_read_rejects_write() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"rdonly.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"readable", &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        let rdonly = engine.open(attr.inode_id, 0, &ctx()).unwrap();

        assert_eq!(engine.read(&rdonly, 0, 8, &ctx()).unwrap(), b"readable");
        assert_eq!(
            engine.write(&rdonly, 0, b"denied", &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn open_wronly_allows_write_rejects_read() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"wronly.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"before", &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        let wronly = engine.open(attr.inode_id, O_WRONLY, &ctx()).unwrap();

        assert_eq!(engine.write(&wronly, 6, b"-after", &ctx()).unwrap(), 6);
        assert_eq!(
            engine.read(&wronly, 0, 5, &ctx()).unwrap_err(),
            Errno::EBADF
        );

        engine.release(&wronly).unwrap();
        let rdonly = engine.open(attr.inode_id, 0, &ctx()).unwrap();
        assert_eq!(
            engine.read(&rdonly, 0, 12, &ctx()).unwrap(),
            b"before-after"
        );
    }

    #[test]
    fn open_rdwr_allows_read_and_write() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"rdwr.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"alpha", &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        let rdwr = engine.open(attr.inode_id, O_RDWR, &ctx()).unwrap();

        assert_eq!(engine.read(&rdwr, 0, 5, &ctx()).unwrap(), b"alpha");
        assert_eq!(engine.write(&rdwr, 5, b"-beta", &ctx()).unwrap(), 5);
        assert_eq!(engine.read(&rdwr, 0, 10, &ctx()).unwrap(), b"alpha-beta");
    }

    #[test]
    fn open_directory_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        assert_eq!(
            engine.open(root, O_RDONLY, &ctx()).unwrap_err(),
            Errno::EISDIR
        );
    }

    #[test]
    fn open_nonexistent_inode_returns_enoent() {
        let (engine, _td) = temp_fs();

        assert_eq!(
            engine
                .open(InodeId::new(999_999), O_RDONLY, &ctx())
                .unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn open_append_writes_extend_at_eof() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"append.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"head", &ctx()).unwrap();
        engine.fsync(&create_fh, false, &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        let append = engine
            .open(attr.inode_id, O_WRONLY | O_APPEND, &ctx())
            .unwrap();
        assert_eq!(engine.write(&append, 0, b"-tail", &ctx()).unwrap(), 5);
        engine.release(&append).unwrap();

        let rdonly = engine.open(attr.inode_id, O_RDONLY, &ctx()).unwrap();
        assert_eq!(engine.read(&rdonly, 0, 9, &ctx()).unwrap(), b"head-tail");
    }

    #[test]
    fn open_append_concurrent_handles_do_not_overwrite() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"concurrent-append.bin", 0o644, O_RDWR, &ctx())
            .unwrap();
        // Seed the file with content and fsync so the size is durable.
        engine.write(&create_fh, 0, b"SEED", &ctx()).unwrap();
        engine.fsync(&create_fh, false, &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        // Open two separate O_APPEND handles.
        let fh_a = engine
            .open(attr.inode_id, O_WRONLY | O_APPEND, &ctx())
            .unwrap();
        let fh_b = engine
            .open(attr.inode_id, O_WRONLY | O_APPEND, &ctx())
            .unwrap();

        // Both writes specify offset 0 but O_APPEND must ignore it and
        // atomically resolve the current file size (4 bytes from SEED).
        let wrote_a = engine.write(&fh_a, 0, b"AAAA", &ctx()).unwrap();
        assert_eq!(wrote_a, 4);

        // Flush so the second handle sees the updated size.
        engine.fsync(&fh_a, false, &ctx()).unwrap();

        let wrote_b = engine.write(&fh_b, 0, b"BBBB", &ctx()).unwrap();
        assert_eq!(wrote_b, 4);

        engine.fsync(&fh_b, false, &ctx()).unwrap();
        engine.release(&fh_a).unwrap();
        engine.release(&fh_b).unwrap();

        let rdonly = engine.open(attr.inode_id, O_RDONLY, &ctx()).unwrap();
        let attr_after = engine
            .getattr(attr.inode_id, Some(&rdonly), &ctx())
            .unwrap();
        // SEED (4) + AAAA (4) + BBBB (4) = 12
        assert_eq!(attr_after.posix.size, 12, "file must be exactly 12 bytes");
        let data = engine.read(&rdonly, 0, 12, &ctx()).unwrap();
        assert_eq!(&data[0..4], b"SEED", "SEED must be at offset 0");
        assert_eq!(&data[4..8], b"AAAA", "AAAA must be at offset 4");
        assert_eq!(&data[8..12], b"BBBB", "BBBB must be at offset 8");
        engine.release(&rdonly).unwrap();
    }

    #[test]
    fn open_trunc_zeroes_existing_file_content() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"truncate-open.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"remove this", &ctx()).unwrap();
        engine.release(&create_fh).unwrap();

        let truncated = engine
            .open(attr.inode_id, O_RDWR | O_TRUNC, &ctx())
            .unwrap();
        let truncated_attr = engine
            .getattr(attr.inode_id, Some(&truncated), &ctx())
            .unwrap();

        assert_eq!(truncated_attr.posix.size, 0);
        assert!(engine.read(&truncated, 0, 16, &ctx()).unwrap().is_empty());
    }

    #[test]
    fn released_file_handle_is_rejected_by_file_io_operations() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"released.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.read(&fh, 0, 1, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(
            engine.write(&fh, 0, b"x", &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(engine.flush(&fh, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(engine.fsync(&fh, false, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(
            engine
                .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(
            engine.data_ranges(&fh, 0, 0, &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn multi_handle_same_file_release_one_other_still_works() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, create_fh) = engine
            .create(root, b"multi.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine.write(&create_fh, 0, b"shared", &ctx()).unwrap();

        // Open a second handle on the same inode.
        let fh2 = engine.open(create_fh.inode_id, O_RDONLY, &ctx()).unwrap();

        // Release the first handle.
        engine.release(&create_fh).unwrap();

        // The second handle should still be valid.
        assert_eq!(engine.read(&fh2, 0, 6, &ctx()).unwrap(), b"shared");

        // Release the second handle.
        engine.release(&fh2).unwrap();

        // Both handles are now released.
        assert_eq!(engine.read(&fh2, 0, 1, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn release_twice_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"twice.txt", 0o644, 0, &ctx()).unwrap();

        engine.release(&fh).unwrap();
        assert_eq!(engine.release(&fh).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn stale_handle_after_release_and_reopen_rejected() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh1) = engine
            .create(root, b"stale.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let inode = attr.inode_id;

        engine.write(&fh1, 0, b"xyz", &ctx()).unwrap();
        engine.release(&fh1).unwrap();

        // Open a new handle for the same inode.
        let fh2 = engine.open(inode, O_RDONLY, &ctx()).unwrap();
        assert_eq!(engine.read(&fh2, 0, 3, &ctx()).unwrap(), b"xyz");

        // The old (released) handle should be rejected.
        assert_eq!(engine.read(&fh1, 0, 1, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(
            engine.write(&fh1, 0, b"a", &ctx()).unwrap_err(),
            Errno::EBADF
        );

        engine.release(&fh2).unwrap();
    }

    #[test]
    fn flush_after_write_succeeds_and_keeps_data_visible() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"flush-write.txt", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"flush-visible", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();
        assert_eq!(
            engine
                .read(&fh, 0, b"flush-visible".len() as u32, &ctx())
                .unwrap(),
            b"flush-visible"
        );

        engine.release(&fh).unwrap();
        let reopened = engine.open(attr.inode_id, O_RDONLY, &ctx()).unwrap();
        assert_eq!(
            engine
                .read(&reopened, 0, b"flush-visible".len() as u32, &ctx())
                .unwrap(),
            b"flush-visible"
        );
    }

    #[test]
    fn flush_does_not_record_fsync_durability_barrier() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"flush-not-fsync.txt", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"flush-only", &ctx()).unwrap();
        let before = engine.fs.borrow().fsync_stats_snapshot();
        engine.flush(&fh, &ctx()).unwrap();
        let after = engine.fs.borrow().fsync_stats_snapshot();

        assert_eq!(after.fsync_count, before.fsync_count);
        assert_eq!(
            after.fsync_do_commit_fallback_count,
            before.fsync_do_commit_fallback_count
        );
    }

    #[test]
    fn flush_on_read_only_handle_succeeds() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, create_fh) = engine
            .create(root, b"flush-readonly.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        engine
            .write(&create_fh, 0, b"readonly-flush", &ctx())
            .unwrap();
        engine.release(&create_fh).unwrap();

        let readonly = engine.open(attr.inode_id, O_RDONLY, &ctx()).unwrap();

        engine.flush(&readonly, &ctx()).unwrap();
        assert_eq!(
            engine
                .read(&readonly, 0, b"readonly-flush".len() as u32, &ctx())
                .unwrap(),
            b"readonly-flush"
        );
    }

    #[test]
    fn flush_on_unlinked_tmpfile_succeeds() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();

        engine.write(&fh, 0, b"tmpfile-flush", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        assert_eq!(
            engine
                .read(&fh, 0, b"tmpfile-flush".len() as u32, &ctx())
                .unwrap(),
            b"tmpfile-flush"
        );
        let after_flush = engine.getattr(attr.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(after_flush.posix.size, b"tmpfile-flush".len() as u64);
    }

    #[test]
    fn flush_with_unknown_file_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"flush-unknown.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let unknown = EngineFileHandle::new(attr.inode_id, O_RDWR, FileHandleId::new(999), 0);

        assert_eq!(engine.flush(&unknown, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn flush_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"flush-released.txt", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.flush(&fh, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn fsync_file_handle_succeeds_for_data_and_metadata_modes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"sync-modes.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"durable", &ctx()).unwrap();

        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.fsync(&fh, true, &ctx()).unwrap();
    }

    #[test]
    fn fdatasync_file_handle_uses_inode_data_barrier() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fdatasync-inode.txt", 0o644, O_RDWR, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"data-only", &ctx()).unwrap();
        let before = engine.fs.borrow().fsync_stats_snapshot();
        engine.fsync(&fh, true, &ctx()).unwrap();
        let after = engine.fs.borrow().fsync_stats_snapshot();

        assert_eq!(after.fdatasync_count, before.fdatasync_count + 1);
        assert_eq!(
            after.fsync_do_commit_fallback_count,
            before.fsync_do_commit_fallback_count
        );
    }

    #[test]
    fn fsync_written_data_survives_close_and_reopen() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"sync-reopen.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.write(&fh, 0, b"persist me", &ctx()).unwrap();
        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.release(&fh).unwrap();

        let reopened = engine.open(attr.inode_id, O_RDONLY, &ctx()).unwrap();
        assert_eq!(
            engine.read(&reopened, 0, 16, &ctx()).unwrap(),
            b"persist me"
        );
    }

    #[test]
    fn fsync_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"sync-released.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.fsync(&fh, false, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(engine.fsync(&fh, true, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn fsync_with_mismatched_file_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"sync-mismatch.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let mismatched_flags = EngineFileHandle::new(attr.inode_id, O_RDONLY, fh.fh_id, 0);

        assert_eq!(
            engine.fsync(&mismatched_flags, false, &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(
            engine.fsync(&mismatched_flags, true, &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fsync_unlinked_tmpfile_succeeds_for_data_and_metadata_modes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();

        engine.write(&fh, 0, b"unlinked", &ctx()).unwrap();

        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.fsync(&fh, true, &ctx()).unwrap();
        assert_eq!(engine.read(&fh, 0, 8, &ctx()).unwrap(), b"unlinked");
    }

    #[test]
    fn open_unlinked_write_fsync_fallocate_survives_until_final_close() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"sync-unlinked.txt", 0o644, O_RDWR, &ctx())
            .unwrap();
        let initial = b"before unlink";
        let appended = b" and after";
        engine.write(&fh, 0, initial, &ctx()).unwrap();

        engine.unlink(root, b"sync-unlinked.txt", &ctx()).unwrap();
        assert_eq!(
            engine
                .getattr(attr.inode_id, Some(&fh), &ctx())
                .unwrap()
                .posix
                .nlink,
            0
        );
        engine
            .write(&fh, initial.len() as u64, appended, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 4096, 4096, &ctx()).unwrap();

        engine.fsync(&fh, false, &ctx()).unwrap();
        engine.fsync(&fh, true, &ctx()).unwrap();
        assert_eq!(
            engine
                .read(&fh, 0, (initial.len() + appended.len()) as u32, &ctx())
                .unwrap(),
            [initial.as_slice(), appended.as_slice()].concat()
        );
        assert_eq!(engine.read(&fh, 4096, 32, &ctx()).unwrap(), vec![0; 32]);
        assert_eq!(
            engine
                .getattr(attr.inode_id, Some(&fh), &ctx())
                .unwrap()
                .posix
                .size,
            8192
        );

        engine.release(&fh).unwrap();
        assert_eq!(
            engine.getattr(attr.inode_id, None, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
    }

    #[test]
    fn fallocate_mode_zero_extends_file_and_reads_as_zeroes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fallocate-zeroes.bin", 0o644, 0, &ctx())
            .unwrap();

        engine.fallocate(&fh, 0, 4, 8, &ctx()).unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 12);
        assert_eq!(engine.read(&fh, 0, 12, &ctx()).unwrap(), vec![0; 12]);
    }

    #[test]
    fn fallocate_mode_zero_offset_past_eof_keeps_leading_hole_unreserved() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fallocate-offset-hole.bin", 0o644, 0, &ctx())
            .unwrap();

        let chunk = crate::constants::content_chunk_size() as u64;
        let offset = chunk * 2;
        let length = chunk;
        engine.fallocate(&fh, 0, offset, length, &ctx()).unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, offset + length);
        assert_eq!(
            engine.read(&fh, 0, 4096, &ctx()).unwrap(),
            vec![0; 4096],
            "leading hole must read as zeros"
        );

        let fs = engine.fs.borrow();
        assert!(
            fs.extent_allocator()
                .lookup_extents(fh.inode_id.0, 0, offset)
                .is_empty(),
            "default fallocate must not reserve bytes before the requested range"
        );
        let extents = fs
            .extent_allocator()
            .lookup_extents(fh.inode_id.0, offset, length);
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_offset, offset);
        assert_eq!(extents[0].length, length);
        assert!(extents[0].is_unwritten());
    }

    #[test]
    fn fallocate_keep_size_preserves_existing_data_and_size() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fallocate-keep-size.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 2, 3, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 6, "KEEP_SIZE must not extend file size");
        assert_eq!(engine.read(&fh, 0, 6, &ctx()).unwrap(), b"abcdef");

        // Existing data remains allocated as DATA; KEEP_SIZE must not
        // overwrite it with an UNWRITTEN reservation.
        let fs = engine.fs.borrow();
        let extents = fs.extent_allocator().lookup_extents(fh.inode_id.0, 2, 3);
        assert!(
            !extents.is_empty(),
            "written data extents must remain visible"
        );
        for e in &extents {
            assert!(e.is_data(), "existing data extents must remain DATA");
        }
    }

    #[test]
    fn fallocate_keep_size_beyond_eof_reserves_unwritten() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"falloc-keep-beyondeof.bin", 0o644, 0, &ctx())
            .unwrap();
        // Empty file, KEEP_SIZE far beyond EOF.
        engine
            .fallocate(&fh, FALLOC_FL_KEEP_SIZE, 100, 4096, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 0, "KEEP_SIZE must not extend file size");

        // Extents must be reserved in the range [100, 4196).
        let fs = engine.fs.borrow();
        let extents = fs
            .extent_allocator()
            .lookup_extents(fh.inode_id.0, 100, 4096);
        assert!(
            !extents.is_empty(),
            "KEEP_SIZE beyond EOF must reserve extents"
        );
        for e in &extents {
            assert!(e.is_unwritten(), "KEEP_SIZE extents must be Unwritten");
        }
    }

    #[test]
    fn fallocate_punch_hole_keep_size_creates_sparse_gap() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fallocate-hole.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload = vec![0xAB; chunk * 3];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                chunk as u64,
                chunk as u64,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            engine.read(&fh, chunk as u64, 4, &ctx()).unwrap(),
            vec![0; 4]
        );
        assert_eq!(
            engine
                .data_ranges(&fh, 0, (chunk * 3) as u64, &ctx())
                .unwrap(),
            vec![
                LseekDataRange::new(0, chunk as u64),
                LseekDataRange::new((chunk * 2) as u64, (chunk * 3) as u64),
            ]
        );
    }

    #[test]
    fn fallocate_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"fallocate-released.bin", 0o644, 0, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(
            engine.fallocate(&fh, 0, 0, 1, &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fallocate_on_directory_handle_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let fh = engine.register_file_handle(root, 0, false).unwrap();

        assert_eq!(
            engine.fallocate(&fh, 0, 0, 1, &ctx()).unwrap_err(),
            Errno::EISDIR
        );
    }

    #[test]
    fn fallocate_collapse_range_removes_middle_bytes_and_shifts_tail() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"collapse-middle.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 0, 16, &ctx()).unwrap();
        engine
            .write(&fh, 0, &(0..16u8).collect::<Vec<_>>(), &ctx())
            .unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_COLLAPSE_RANGE, 4, 8, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 8);
        let data = engine.read(&fh, 0, 8, &ctx()).unwrap();
        assert_eq!(data, vec![0, 1, 2, 3, 12, 13, 14, 15]);
    }

    #[test]
    fn fallocate_collapse_range_beyond_eof_is_noop() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"collapse-beyondeof.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 0, 6, &ctx()).unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_COLLAPSE_RANGE, 100, 4, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 6);
        assert_eq!(engine.read(&fh, 0, 6, &ctx()).unwrap(), b"abcdef");
    }

    #[test]
    fn fallocate_collapse_range_zero_length_is_noop() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"collapse-zerolen.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 0, 4, &ctx()).unwrap();
        engine.write(&fh, 0, b"data", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_COLLAPSE_RANGE, 0, 0, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 4);
        assert_eq!(engine.read(&fh, 0, 4, &ctx()).unwrap(), b"data");
    }

    #[test]
    fn fallocate_insert_range_allocates_zeros_and_shifts_tail() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"insert-middle.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 0, 8, &ctx()).unwrap();
        engine
            .write(&fh, 0, &(0..8u8).collect::<Vec<_>>(), &ctx())
            .unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_INSERT_RANGE, 4, 4, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 12);
        let data = engine.read(&fh, 0, 12, &ctx()).unwrap();
        assert_eq!(data, vec![0, 1, 2, 3, 0, 0, 0, 0, 4, 5, 6, 7]);
    }

    #[test]
    fn fallocate_insert_range_zero_length_is_noop() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"insert-zerolen.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.fallocate(&fh, 0, 0, 4, &ctx()).unwrap();
        engine.write(&fh, 0, b"data", &ctx()).unwrap();
        engine.flush(&fh, &ctx()).unwrap();

        engine
            .fallocate(&fh, FALLOC_FL_INSERT_RANGE, 2, 0, &ctx())
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 4);
        assert_eq!(engine.read(&fh, 0, 4, &ctx()).unwrap(), b"data");
    }

    #[test]
    fn fallocate_collapse_range_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"collapse-released.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.release(&fh).unwrap();
        assert_eq!(
            engine
                .fallocate(&fh, FALLOC_FL_COLLAPSE_RANGE, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fallocate_collapse_range_on_directory_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let fh = engine.register_file_handle(root, 0, false).unwrap();
        assert_eq!(
            engine
                .fallocate(&fh, FALLOC_FL_COLLAPSE_RANGE, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EISDIR
        );
    }

    #[test]
    fn fallocate_insert_range_after_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"insert-released.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.release(&fh).unwrap();
        assert_eq!(
            engine
                .fallocate(&fh, FALLOC_FL_INSERT_RANGE, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fallocate_insert_range_on_directory_returns_eisdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let fh = engine.register_file_handle(root, 0, false).unwrap();
        assert_eq!(
            engine
                .fallocate(&fh, FALLOC_FL_INSERT_RANGE, 0, 1, &ctx())
                .unwrap_err(),
            Errno::EISDIR
        );
    }

    // ── Fallocate timestamp authority regression ─────────────────────

    /// Fallocate default (mode 0, extend) advances mtime and ctime
    /// through the same timestamp authority as dispatch_write.
    #[test]
    fn fallocate_extend_advances_mtime_and_ctime() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"falloc-extend.txt", 0o644, 0, &ctx())
            .unwrap();
        let before = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();

        // Fallocate 4096 bytes at offset 0 (default mode, extends file).
        engine
            .fallocate(&fh, 0, 0, 4096, &ctx())
            .expect("fallocate extend");

        let after = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert!(
            after.posix.mtime_ns > before.posix.mtime_ns,
            "mtime_ns must advance after fallocate extend: before={before}, after={after}",
            before = before.posix.mtime_ns,
            after = after.posix.mtime_ns
        );
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "ctime_ns must advance after fallocate extend: before={before}, after={after}",
            before = before.posix.ctime_ns,
            after = after.posix.ctime_ns
        );
    }

    /// Fallocate PUNCH_HOLE advances mtime and ctime (data is modified).
    #[test]
    fn fallocate_punch_hole_advances_mtime_and_ctime() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"falloc-punch.txt", 0o644, 0, &ctx())
            .unwrap();
        // Allocate some data first then punch a hole.
        engine
            .write(&fh, 0, &[0xAAu8; 4096], &ctx())
            .expect("write before punch");
        let before = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();

        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0,
                2048,
                &ctx(),
            )
            .expect("fallocate punch hole");

        let after = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert!(
            after.posix.mtime_ns > before.posix.mtime_ns,
            "mtime_ns must advance after fallocate punch hole"
        );
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "ctime_ns must advance after fallocate punch hole"
        );
    }

    #[test]
    fn double_release_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"double-release.txt", 0o644, 0, &ctx())
            .unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.release(&fh).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn unknown_file_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"unknown-handle.txt", 0o644, 0, &ctx())
            .unwrap();
        let unknown = EngineFileHandle::new(attr.inode_id, 0, FileHandleId::new(999_999), 0);

        assert_eq!(
            engine.read(&unknown, 0, 1, &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(engine.release(&unknown).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn releasing_one_file_handle_keeps_other_handles_live() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh1) = engine
            .create(root, b"multi-handle.txt", 0o644, 0, &ctx())
            .unwrap();
        let fh2 = engine.open(attr.inode_id, 0, &ctx()).unwrap();
        assert_ne!(fh1.fh_id, fh2.fh_id);

        engine.write(&fh1, 0, b"live", &ctx()).unwrap();
        engine.release(&fh1).unwrap();

        assert_eq!(
            engine.write(&fh1, 0, b"dead", &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(engine.read(&fh2, 0, 4, &ctx()).unwrap(), b"live");
        engine.release(&fh2).unwrap();
    }

    #[test]
    fn write_multiple() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine.create(root, b"multi.bin", 0o644, 0, &ctx()).unwrap();
        engine.write(&fh, 0, b"AAAA", &ctx()).unwrap();
        engine.write(&fh, 4, b"BBBB", &ctx()).unwrap();

        let data = engine.read(&fh, 0, 8, &ctx()).unwrap();
        assert_eq!(data, b"AAAABBBB");
    }

    #[test]
    fn write_beyond_eof_extends_size_and_zero_fills_gap() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"beyond-eof.bin", 0o644, 0, &ctx())
            .unwrap();

        assert_eq!(engine.write(&fh, 5, b"xyz", &ctx()).unwrap(), 3);

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 8);
        assert_eq!(
            engine.read(&fh, 0, 8, &ctx()).unwrap(),
            vec![0, 0, 0, 0, 0, b'x', b'y', b'z']
        );
    }

    #[test]
    fn write_empty_payload_is_noop() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"empty-write.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abc", &ctx()).unwrap();

        assert_eq!(engine.write(&fh, 1, b"", &ctx()).unwrap(), 0);

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 3);
        assert_eq!(engine.read(&fh, 0, 3, &ctx()).unwrap(), b"abc");
    }

    #[test]
    fn write_overwrite_then_read_preserves_surrounding_bytes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"overwrite.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abcdef", &ctx()).unwrap();

        assert_eq!(engine.write(&fh, 2, b"XY", &ctx()).unwrap(), 2);

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, 6);
        assert_eq!(engine.read(&fh, 0, 6, &ctx()).unwrap(), b"abXYef");
    }

    #[test]
    fn write_at_chunk_boundary_extends_to_exact_end() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"chunk-boundary.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as u64;

        assert_eq!(engine.write(&fh, chunk, b"edge", &ctx()).unwrap(), 4);

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, chunk + 4);
        assert_eq!(engine.read(&fh, chunk, 4, &ctx()).unwrap(), b"edge");
        assert_eq!(
            engine.read(&fh, chunk - 1, 5, &ctx()).unwrap(),
            vec![0, b'e', b'd', b'g', b'e']
        );
    }

    #[test]
    fn write_unaligned_offset_across_chunk_boundary_preserves_neighbors() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"unaligned-boundary.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload = vec![b'a'; chunk + 8];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        assert_eq!(
            engine
                .write(&fh, (chunk - 3) as u64, b"xyzpq", &ctx())
                .unwrap(),
            5
        );

        assert_eq!(
            engine.read(&fh, (chunk - 5) as u64, 9, &ctx()).unwrap(),
            vec![b'a', b'a', b'x', b'y', b'z', b'p', b'q', b'a', b'a']
        );
    }

    // ── Extent allocation verification ──────────────────────────────

    #[test]
    fn write_triggers_extent_allocation() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"extent-check.bin", 0o644, 0, &ctx())
            .unwrap();

        engine.write(&fh, 0, &[0xAA_u8; 4096], &ctx()).unwrap();

        let fs = engine.fs.borrow();
        let extents = fs
            .extent_allocator()
            .lookup_extents(attr.inode_id.0, 0, 4096);
        assert!(!extents.is_empty(), "extent must be allocated after write");
        assert_eq!(extents.len(), 1, "single write should create single extent");
        assert_eq!(extents[0].logical_offset, 0);
        assert_eq!(extents[0].length, 4096);
    }

    #[test]
    fn multiple_writes_produce_multiple_extents() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine
            .create(root, b"multi-extent.bin", 0o644, 0, &ctx())
            .unwrap();

        engine.write(&fh, 0, &[0x11_u8; 4096], &ctx()).unwrap();
        engine.write(&fh, 8192, &[0x22_u8; 4096], &ctx()).unwrap();

        let fs = engine.fs.borrow();
        let extents = fs
            .extent_allocator()
            .lookup_extents(attr.inode_id.0, 0, 12288);
        assert_eq!(extents.len(), 2, "two non-contiguous writes -> two extents");

        let first = extents.iter().find(|e| e.logical_offset == 0).unwrap();
        assert_eq!(first.length, 4096);
        let second = extents.iter().find(|e| e.logical_offset == 8192).unwrap();
        assert_eq!(second.length, 4096);
    }

    // ── Error mapping tests ─────────────────────────────────────────

    #[test]
    fn map_errno_maps_corrupt_state_to_eio() {
        use crate::error::FileSystemError;

        let err = FileSystemError::CorruptState { reason: "test" };
        assert_eq!(map_errno(&err), Errno::EIO);
    }

    #[test]
    fn map_errno_maps_corrupt_content_to_eio() {
        use crate::error::FileSystemError;

        let err = FileSystemError::CorruptContent {
            inode_id: tidefs_types_vfs_core::InodeId::new(1),
        };
        assert_eq!(map_errno(&err), Errno::EIO);
    }

    #[test]
    fn map_errno_maps_unknown_error_to_eio() {
        use crate::error::FileSystemError;

        let err = FileSystemError::Store(StoreError::ReadOnly { operation: "write" });
        assert_eq!(map_errno(&err), Errno::EIO);
    }

    #[test]
    fn data_ranges_reports_sparse_chunks() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"sparse.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload = vec![0xAB; chunk * 3];
        engine
            .fs
            .borrow_mut()
            .write_file("/sparse.bin", 0, &payload)
            .unwrap();
        engine
            .fallocate(
                &fh,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                chunk as u64,
                chunk as u64,
                &ctx(),
            )
            .unwrap();

        let ranges = engine
            .data_ranges(&fh, 0, (chunk * 3) as u64, &ctx())
            .unwrap();

        assert_eq!(
            ranges,
            vec![
                LseekDataRange::new(0, chunk as u64),
                LseekDataRange::new((chunk * 2) as u64, (chunk * 3) as u64),
            ]
        );
    }

    #[test]
    fn data_ranges_clips_to_requested_window() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"window.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload = vec![0xCD; chunk * 2];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        let ranges = engine
            .data_ranges(&fh, (chunk / 2) as u64, chunk as u64, &ctx())
            .unwrap();

        assert_eq!(
            ranges,
            vec![LseekDataRange::new(
                (chunk / 2) as u64,
                (chunk + chunk / 2) as u64
            )]
        );
    }

    #[test]
    fn data_ranges_returns_empty_past_eof() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"past-eof.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abc", &ctx()).unwrap();

        assert_eq!(engine.data_ranges(&fh, 3, 10, &ctx()).unwrap(), Vec::new());
        assert_eq!(engine.data_ranges(&fh, 10, 10, &ctx()).unwrap(), Vec::new());
    }

    #[test]
    fn data_ranges_empty_file_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"empty-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();

        assert_eq!(engine.data_ranges(&fh, 0, 1, &ctx()).unwrap(), Vec::new());
    }

    #[test]
    fn data_ranges_fully_written_file_returns_single_range() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"dense-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as usize;
        let payload = vec![0xEF; chunk * 2 + 17];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();

        let ranges = engine
            .data_ranges(&fh, 0, payload.len() as u64, &ctx())
            .unwrap();

        assert_eq!(ranges, vec![LseekDataRange::new(0, payload.len() as u64)]);
    }

    #[test]
    fn data_ranges_hole_only_file_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"hole-only-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as u64;
        engine
            .fs
            .borrow_mut()
            .truncate_file("/hole-only-data-ranges.bin", chunk)
            .unwrap();

        let attr = engine.getattr(fh.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(attr.posix.size, chunk);
        assert_eq!(
            engine.data_ranges(&fh, 0, chunk, &ctx()).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn data_ranges_start_equals_end_returns_empty() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"zero-window-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();
        engine.write(&fh, 0, b"abc", &ctx()).unwrap();

        assert_eq!(engine.data_ranges(&fh, 1, 0, &ctx()).unwrap(), Vec::new());
    }

    #[test]
    fn data_ranges_offset_plus_length_overflow_returns_einval() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"overflow-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();

        assert_eq!(
            engine.data_ranges(&fh, u64::MAX, 1, &ctx()).unwrap_err(),
            Errno::EINVAL
        );
    }

    #[test]
    fn data_ranges_window_at_chunk_boundary() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"boundary-data-ranges.bin", 0o644, 0, &ctx())
            .unwrap();
        let chunk = crate::constants::content_chunk_size() as u64;
        engine.write(&fh, chunk, b"edge", &ctx()).unwrap();

        let ranges = engine.data_ranges(&fh, chunk, 4, &ctx()).unwrap();

        assert_eq!(ranges, vec![LseekDataRange::new(chunk, chunk + 4)]);
    }

    // ── Directory tests ─────────────────────────────────────────────

    fn assert_statfs_invariants(st: StatFs) {
        assert!(st.block_size > 0);
        assert!(st.fragment_size > 0);
        assert!(st.total_blocks > 0);
        assert!(st.free_blocks <= st.total_blocks);
        assert!(st.avail_blocks <= st.free_blocks);
        assert!(st.files > 0);
        assert!(st.files_free <= st.files);
        assert!(st.name_max > 0);
        assert_eq!(st.fsid_hi, 0);
        assert!(
            st.fsid_lo > 0,
            "fsid_lo should be non-zero, got {}",
            st.fsid_lo
        );
    }

    #[test]
    fn statfs_reports_valid_info() {
        let (engine, _td) = temp_fs();
        let st = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();
        assert_statfs_invariants(st);
    }

    #[test]
    fn statfs_preserves_quota_clamped_engine_counters() {
        let quota_bytes = 8 * u64::from(crate::constants::content_chunk_size());
        let (engine, _td) = temp_fs();
        let mut hierarchy = DatasetQuotaHierarchy::new();
        hierarchy.set_quota(
            crate::ROOT_DATASET_ID,
            DatasetQuotaConfig {
                hard_limit_bytes: quota_bytes,
                ..Default::default()
            },
        );

        let canonical = {
            let mut fs = engine.fs.borrow_mut();
            fs.set_quota_hierarchy(hierarchy)
                .expect("test setup mutation must be admitted");
            fs.statfs().unwrap()
        };
        let st = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();

        assert_eq!(canonical.blocks, quota_bytes / u64::from(canonical.bsize));
        assert_eq!(st.total_blocks, canonical.blocks);
        assert_eq!(st.free_blocks, canonical.bfree);
        assert_eq!(st.avail_blocks, canonical.bavail);
        assert!(st.free_blocks <= st.total_blocks);
        assert!(st.avail_blocks <= st.free_blocks);
    }

    #[test]
    fn statfs_reports_inode_capacity_fields() {
        let (engine, _td) = temp_fs();
        let st = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();

        assert_statfs_invariants(st);
        assert!(st.files_free > 0);
        assert!(
            st.files_free <= st.files,
            "files_free {0} must be <= files {1}",
            st.files_free,
            st.files
        );
    }

    #[test]
    fn statfs_reflects_written_file_block_usage() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let before = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"statfs-data.bin", 0o644, 0, &ctx())
            .unwrap();
        let payload = vec![0x5a; 16 * 1024];

        assert_eq!(
            engine.write(&fh, 0, &payload, &ctx()).unwrap(),
            payload.len() as u32
        );

        let after = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();
        assert_statfs_invariants(after);
        assert!(after.free_blocks <= before.free_blocks);
        assert!(after.avail_blocks <= before.avail_blocks);
    }

    #[test]
    fn statfs_free_blocks_recover_after_unlink() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_attr, fh) = engine
            .create(root, b"statfs-delete.bin", 0o644, 0, &ctx())
            .unwrap();
        let payload = vec![0x33; 16 * 1024];
        engine.write(&fh, 0, &payload, &ctx()).unwrap();
        let after_write = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();

        engine.release(&fh).unwrap();
        engine.unlink(root, b"statfs-delete.bin", &ctx()).unwrap();

        let after_unlink = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();
        assert_statfs_invariants(after_unlink);
        assert!(after_unlink.free_blocks >= after_write.free_blocks);
        assert!(after_unlink.avail_blocks >= after_write.avail_blocks);
    }

    #[test]
    fn statfs_is_independent_of_request_credentials() {
        let (engine, _td) = temp_fs();
        let user_st = VfsEngineStatFs::statfs(&engine, &ctx()).unwrap();
        let root_st = VfsEngineStatFs::statfs(&engine, &root_ctx()).unwrap();

        assert_statfs_invariants(user_st);
        assert_eq!(user_st, root_st);
    }

    #[test]
    fn readdir_empty_root() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert!(entries.is_empty());
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_with_entries() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"aaa.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"bbb.txt", 0o644, 0, &ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"aaa.txt");
        assert_eq!(entries[1].name, b"bbb.txt");
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_open_handle_is_authoritative_by_inode_not_path_cache_alias() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"dir", 0o755, &ctx()).unwrap();
        let (_child, fh) = engine
            .create(dir.inode_id, b"child.txt", 0o644, 0, &ctx())
            .unwrap();
        engine.release(&fh).unwrap();

        let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();
        engine
            .path_cache
            .borrow_mut()
            .insert(dir.inode_id, "/stale-dir-alias".to_string());

        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();

        assert!(!has_more);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"child.txt");
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_offset_zero_returns_entries_with_sequential_cookies() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"aaa.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"bbb.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"ccc.txt", 0o644, 0, &ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();

        let names: Vec<Vec<u8>> = entries.iter().map(|entry| entry.name.clone()).collect();
        let cookies: Vec<u64> = entries.iter().map(|entry| entry.cookie).collect();
        assert_eq!(
            names,
            vec![
                b"aaa.txt".to_vec(),
                b"bbb.txt".to_vec(),
                b"ccc.txt".to_vec()
            ]
        );
        assert_eq!(cookies, vec![1, 2, 3]);
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_offset_continuation_returns_remaining_entries() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"aaa.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"bbb.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"ccc.txt", 0o644, 0, &ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (first_batch, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert_eq!(first_batch.len(), 3);
        assert!(!has_more);

        let resume_offset = first_batch[0].cookie; // aaa.txt cookie = 1
        let (second_batch, has_more) = engine.readdir(&dh, resume_offset, &ctx()).unwrap();

        let names: Vec<Vec<u8>> = second_batch
            .iter()
            .map(|entry| entry.name.clone())
            .collect();
        let cookies: Vec<u64> = second_batch.iter().map(|entry| entry.cookie).collect();
        assert_eq!(names, vec![b"bbb.txt".to_vec(), b"ccc.txt".to_vec()]);
        assert_eq!(cookies, vec![2, 3]);
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_offset_past_end_returns_empty_batch() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.create(root, b"aaa.txt", 0o644, 0, &ctx()).unwrap();
        engine.create(root, b"bbb.txt", 0o644, 0, &ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 9999, &ctx()).unwrap();

        assert!(entries.is_empty());
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_large_directory_batches_at_cursor_window_limit() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        for i in 0..140u64 {
            let name = format!("bulk_{i:04}.txt").into_bytes();
            let entry = NamespaceEntry {
                name: name.clone(),
                inode_id: InodeId::new(10_000 + i),
                generation: Generation::new(i + 1),
                facets: NodeKind::File.to_facets(),
                mode: S_IFREG | 0o644,
            };
            engine
                .fs
                .borrow_mut()
                .insert_dir_entry(root, name, entry)
                .unwrap();
        }

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (first, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert_eq!(first.len(), 128);
        assert!(has_more);
        assert_eq!(first[0].name, b"bulk_0000.txt");
        assert_eq!(first.last().unwrap().name, b"bulk_0127.txt");
        assert_eq!(first.last().unwrap().cookie, 128);

        let (second, has_more) = engine
            .readdir(&dh, first.last().unwrap().cookie, &ctx())
            .unwrap();
        assert_eq!(second.len(), 12);
        assert!(!has_more);
        assert_eq!(second[0].name, b"bulk_0128.txt");
        assert_eq!(second.last().unwrap().name, b"bulk_0139.txt");
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_permname_sized_directory_returns_all_entries_in_windows() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        for i in 0..4096u64 {
            let mut value = i;
            let mut name = vec![b'a'; 6];
            for byte in name.iter_mut().rev() {
                *byte = b'a' + u8::try_from(value % 4).unwrap();
                value /= 4;
            }
            let entry = NamespaceEntry {
                name: name.clone(),
                inode_id: InodeId::new(30_000 + i),
                generation: Generation::new(i + 1),
                facets: NodeKind::File.to_facets(),
                mode: S_IFREG | 0o644,
            };
            engine
                .fs
                .borrow_mut()
                .insert_dir_entry(root, name, entry)
                .unwrap();
        }

        let dh = engine.opendir(root, &ctx()).unwrap();
        let mut offset = 0;
        let mut seen = 0usize;
        let mut pages = 0usize;
        loop {
            let (entries, has_more) = engine.readdir(&dh, offset, &ctx()).unwrap();
            assert!(entries.len() <= 128);
            pages += 1;
            for entry in &entries {
                seen += 1;
                assert_eq!(entry.cookie, seen as u64);
                assert_eq!(entry.name.len(), 6);
            }
            if let Some(last) = entries.last() {
                offset = last.cookie;
            } else {
                assert!(!has_more);
            }
            if !has_more {
                break;
            }
        }

        assert_eq!(seen, 4096);
        assert_eq!(pages, 32);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_exact_cursor_window_limit_reports_eof_on_resume() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        for i in 0..128u64 {
            let name = format!("exact_{i:04}.txt").into_bytes();
            let entry = NamespaceEntry {
                name: name.clone(),
                inode_id: InodeId::new(20_000 + i),
                generation: Generation::new(i + 1),
                facets: NodeKind::File.to_facets(),
                mode: S_IFREG | 0o644,
            };
            engine
                .fs
                .borrow_mut()
                .insert_dir_entry(root, name, entry)
                .unwrap();
        }

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (first, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert_eq!(first.len(), 128);
        assert!(!has_more);
        assert_eq!(first[0].name, b"exact_0000.txt");
        assert_eq!(first.last().unwrap().name, b"exact_0127.txt");
        assert_eq!(first.last().unwrap().cookie, 128);

        let (tail, has_more) = engine
            .readdir(&dh, first.last().unwrap().cookie, &ctx())
            .unwrap();
        assert!(tail.is_empty());
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn opendir_on_valid_directory_allocates_live_handle() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine.mkdir(root, b"subdir", 0o755, &ctx()).unwrap();

        let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();

        assert_eq!(dh.inode_id, dir.inode_id);
        assert_ne!(dh.dh_id, DirHandleId::default());
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn opendir_on_nonexistent_inode_returns_enoent() {
        let (engine, _td) = temp_fs();

        let result = engine.opendir(InodeId::new(999_999), &ctx());

        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn opendir_on_file_fails() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"file.txt", 0o644, 0, &ctx()).unwrap();
        let result = engine.opendir(attr.inode_id, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);
    }

    #[test]
    fn releasedir_after_valid_opendir_succeeds_once() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();

        engine.releasedir(&dh).unwrap();
        assert_eq!(engine.releasedir(&dh).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn releasedir_with_unknown_dir_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dh = EngineDirHandle::new(root, DirHandleId::new(999));

        assert_eq!(engine.releasedir(&dh).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn fsyncdir_on_valid_directory_handle_succeeds() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine
            .mkdir(root, b"fsyncdir-subdir", 0o755, &ctx())
            .unwrap();
        let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();

        engine.fsyncdir(&dh, false, &ctx()).unwrap();
        engine.fsyncdir(&dh, true, &ctx()).unwrap();
    }

    #[test]
    fn fsyncdir_after_releasedir_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dh = engine.opendir(root, &ctx()).unwrap();

        engine.releasedir(&dh).unwrap();

        assert_eq!(
            engine.fsyncdir(&dh, false, &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(
            engine.fsyncdir(&dh, true, &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fsyncdir_with_mismatched_dir_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine
            .mkdir(root, b"fsyncdir-mismatch", 0o755, &ctx())
            .unwrap();
        let root_handle = engine.opendir(root, &ctx()).unwrap();
        let mismatched = EngineDirHandle::new(dir.inode_id, root_handle.dh_id);

        assert_eq!(
            engine.fsyncdir(&mismatched, false, &ctx()).unwrap_err(),
            Errno::EBADF
        );
        assert_eq!(
            engine.fsyncdir(&mismatched, true, &ctx()).unwrap_err(),
            Errno::EBADF
        );
    }

    #[test]
    fn fsyncdir_open_removed_directory_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dir = engine
            .mkdir(root, b"fsyncdir-removed", 0o755, &ctx())
            .unwrap();
        let dh = engine.opendir(dir.inode_id, &ctx()).unwrap();

        engine.rmdir(root, b"fsyncdir-removed", &ctx()).unwrap();

        assert_eq!(
            engine.fsyncdir(&dh, false, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            engine.fsyncdir(&dh, true, &ctx()).unwrap_err(),
            Errno::ENOENT
        );
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn readdir_after_releasedir_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();

        let dh = engine.opendir(root, &ctx()).unwrap();
        engine.releasedir(&dh).unwrap();

        assert_eq!(engine.readdir(&dh, 0, &ctx()).unwrap_err(), Errno::EBADF);
    }

    #[test]
    fn readdir_with_unknown_dir_handle_returns_ebadf() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let dh = EngineDirHandle::new(root, DirHandleId::new(999));

        assert_eq!(engine.readdir(&dh, 0, &ctx()).unwrap_err(), Errno::EBADF);
    }

    // ── Xattr tests ─────────────────────────────────────────────────

    #[test]
    fn setxattr_getxattr_roundtrip() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"xfile.txt", 0o644, 0, &ctx()).unwrap();
        engine
            .setxattr(attr.inode_id, b"user.test", b"hello", 0, &ctx())
            .unwrap();
        let val = engine
            .getxattr(attr.inode_id, b"user.test", &ctx())
            .unwrap();
        assert_eq!(val, b"hello");
    }

    #[test]
    fn xattr_ops_are_authoritative_by_inode_not_path_cache_alias() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (target, _target_fh) = engine
            .create(root, b"xattr-target.txt", 0o644, 0, &ctx())
            .unwrap();
        let (wrong, _wrong_fh) = engine
            .create(root, b"xattr-wrong.txt", 0o644, 0, &ctx())
            .unwrap();

        engine
            .path_cache
            .borrow_mut()
            .insert(target.inode_id, "/xattr-wrong.txt".to_string());

        engine
            .setxattr(target.inode_id, b"user.alias", b"target", 0, &ctx())
            .unwrap();

        assert_eq!(
            engine
                .getxattr(target.inode_id, b"user.alias", &ctx())
                .unwrap(),
            b"target"
        );
        assert_eq!(
            engine
                .getxattr(wrong.inode_id, b"user.alias", &ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
        assert_eq!(
            engine.listxattr(target.inode_id, &ctx()).unwrap(),
            b"user.alias\0"
        );

        engine
            .removexattr(target.inode_id, b"user.alias", &ctx())
            .unwrap();
        assert_eq!(
            engine
                .getxattr(target.inode_id, b"user.alias", &ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
    }

    #[test]
    fn getattr_is_authoritative_by_inode_not_path_cache_alias() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (target, _target_fh) = engine
            .create(root, b"getattr-target.txt", 0o640, 0, &ctx())
            .unwrap();
        let (wrong, wrong_fh) = engine
            .create(root, b"getattr-wrong.txt", 0o600, 0, &ctx())
            .unwrap();
        engine
            .write(&wrong_fh, 0, b"wrong inode bytes", &ctx())
            .unwrap();

        engine
            .path_cache
            .borrow_mut()
            .insert(target.inode_id, "/getattr-wrong.txt".to_string());

        let attr = engine.getattr(target.inode_id, None, &ctx()).unwrap();

        assert_eq!(attr.inode_id, target.inode_id);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o640);
        assert_eq!(attr.posix.size, 0);
        assert_ne!(attr.inode_id, wrong.inode_id);
    }

    #[test]
    fn xattr_burst_with_deferred_commit_stays_batched_below_threshold() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut fs = PoolDatasetOwner::open(dir.path()).expect("open");
        fs.set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        fs.set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        fs.set_commit_group_throughput_profile()
            .expect("test setup mutation must be admitted");
        let engine = VfsLocalFileSystem::new(fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"xattr-burst.txt", 0o644, 0, &ctx())
            .unwrap();
        let before_burst = engine.fs.borrow().uncommitted_mutation_count;

        for i in 0..128 {
            let name = format!("user.burst{i:03}");
            engine
                .setxattr(attr.inode_id, name.as_bytes(), b"value", 0, &ctx())
                .unwrap();
        }
        for i in 0..128 {
            let name = format!("user.burst{i:03}");
            engine
                .removexattr(attr.inode_id, name.as_bytes(), &ctx())
                .unwrap();
        }

        assert!(engine.listxattr(attr.inode_id, &ctx()).unwrap().is_empty());
        assert_eq!(
            engine.fs.borrow().uncommitted_mutation_count,
            before_burst + 256,
            "xattr stress below the daemon threshold should remain commit-group batched"
        );
    }

    #[test]
    fn listxattr_returns_set_keys() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"listfile.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .setxattr(attr.inode_id, b"user.a", b"1", 0, &ctx())
            .unwrap();
        engine
            .setxattr(attr.inode_id, b"user.b", b"2", 0, &ctx())
            .unwrap();
        let list = engine.listxattr(attr.inode_id, &ctx()).unwrap();
        // Null-separated list
        let names: Vec<&[u8]> = list.split(|b| *b == 0).filter(|s| !s.is_empty()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"user.a".as_slice()));
        assert!(names.contains(&b"user.b".as_slice()));
    }

    #[test]
    fn removexattr_then_getxattr_returns_enodata() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"remfile.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .setxattr(attr.inode_id, b"user.del", b"val", 0, &ctx())
            .unwrap();
        engine
            .removexattr(attr.inode_id, b"user.del", &ctx())
            .unwrap();
        let result = engine.getxattr(attr.inode_id, b"user.del", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENODATA);
    }

    #[test]
    fn setxattr_create_fails_on_existing() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"dupfile.txt", 0o644, 0, &ctx())
            .unwrap();
        engine
            .setxattr(attr.inode_id, b"user.dup", b"first", 0, &ctx())
            .unwrap();
        let result = engine.setxattr(attr.inode_id, b"user.dup", b"second", XATTR_CREATE, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn setxattr_replace_fails_on_missing() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"repfile.txt", 0o644, 0, &ctx())
            .unwrap();
        let result = engine.setxattr(
            attr.inode_id,
            b"user.missing",
            b"val",
            XATTR_REPLACE,
            &ctx(),
        );
        assert_eq!(result.unwrap_err(), Errno::ENODATA);
    }

    #[test]
    fn large_xattr_value_roundtrip() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"bigfile.txt", 0o644, 0, &ctx())
            .unwrap();
        let big = vec![0xABu8; 8192];
        engine
            .setxattr(attr.inode_id, b"user.big", &big, 0, &ctx())
            .unwrap();
        let val = engine.getxattr(attr.inode_id, b"user.big", &ctx()).unwrap();
        assert_eq!(val, big);
    }

    #[test]
    fn trusted_xattr_requires_cap_sys_admin() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"trustfile.txt", 0o644, 0, &ctx())
            .unwrap();
        // non-root uid=1000 should be denied
        let result = engine.setxattr(attr.inode_id, b"trusted.myattr", b"val", 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EPERM);
    }

    #[test]
    fn setxattr_rejects_empty_and_nul_names() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"badname.txt");

        let empty = engine.setxattr(inode, b"", b"value", 0, &ctx());
        assert_eq!(empty.unwrap_err(), Errno::EINVAL);

        let nul = engine.setxattr(inode, b"user.bad\0name", b"value", 0, &ctx());
        assert_eq!(nul.unwrap_err(), Errno::EINVAL);

        let get_empty = engine.getxattr(inode, b"", &ctx());
        assert_eq!(get_empty.unwrap_err(), Errno::EINVAL);

        let remove_nul = engine.removexattr(inode, b"user.bad\0name", &ctx());
        assert_eq!(remove_nul.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn setxattr_rejects_unsupported_namespaces() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"namespace.txt");

        let no_prefix = engine.setxattr(inode, b"plain", b"value", 0, &ctx());
        assert_eq!(no_prefix.unwrap_err(), Errno::EOPNOTSUPP);

        let unknown_prefix = engine.setxattr(inode, b"custom.attr", b"value", 0, &ctx());
        assert_eq!(unknown_prefix.unwrap_err(), Errno::EOPNOTSUPP);

        let empty_suffix = engine.setxattr(inode, b"user.", b"value", 0, &ctx());
        assert_eq!(empty_suffix.unwrap_err(), Errno::EOPNOTSUPP);
    }

    #[test]
    fn setxattr_rejects_invalid_flag_combinations() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"flags.txt");

        let create_and_replace = engine.setxattr(
            inode,
            b"user.flags",
            b"value",
            XATTR_CREATE | XATTR_REPLACE,
            &ctx(),
        );
        assert_eq!(create_and_replace.unwrap_err(), Errno::EINVAL);

        let unsupported = engine.setxattr(inode, b"user.flags", b"value", 4, &ctx());
        assert_eq!(unsupported.unwrap_err(), Errno::EINVAL);
    }

    #[test]
    fn setxattr_rejects_oversized_value() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"huge-xattr.txt");
        let value = vec![0xCD; 64 * 1024 + 1];

        let result = engine.setxattr(inode, b"user.huge", &value, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::E2BIG);
    }

    #[test]
    fn trusted_xattr_root_roundtrips_and_nonroot_is_hidden() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"trusted-root.txt");

        engine
            .setxattr(inode, b"trusted.visible", b"secret", 0, &root_ctx())
            .unwrap();
        let value = engine
            .getxattr(inode, b"trusted.visible", &root_ctx())
            .unwrap();
        assert_eq!(value, b"secret");

        let nonroot_get = engine.getxattr(inode, b"trusted.visible", &ctx());
        assert_eq!(nonroot_get.unwrap_err(), Errno::EPERM);

        engine
            .setxattr(inode, b"user.visible", b"public", 0, &ctx())
            .unwrap();
        assert_eq!(engine.listxattr(inode, &ctx()).unwrap(), b"user.visible\0");
        assert_eq!(
            engine.listxattr(inode, &root_ctx()).unwrap(),
            b"trusted.visible\0user.visible\0"
        );
    }

    #[test]
    fn posix_acl_xattr_accepts_structurally_valid_payload() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"acl-valid.txt");
        let acl = tidefs_posix_acl::minimal_access_acl_from_mode(0o640);
        let encoded = tidefs_posix_acl::encode_posix_acl_xattr(&acl);

        engine
            .setxattr(inode, b"system.posix_acl_access", &encoded, 0, &root_ctx())
            .unwrap();

        let attr = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert_eq!(attr.posix.mode & 0o777, 0o640);
        assert_eq!(
            engine
                .getxattr(inode, b"system.posix_acl_access", &root_ctx())
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn posix_acl_xattr_accepts_linux_undefined_special_ids() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"acl-linux-ids.txt");
        let acl = vec![
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER_OBJ,
                perm: 4,
                id: tidefs_posix_acl::ACL_UNDEFINED_ID,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_GROUP_OBJ,
                perm: 7,
                id: tidefs_posix_acl::ACL_UNDEFINED_ID,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_OTHER,
                perm: 6,
                id: tidefs_posix_acl::ACL_UNDEFINED_ID,
            },
        ];
        let encoded = tidefs_posix_acl::encode_posix_acl_xattr(&acl);

        engine
            .setxattr(inode, b"system.posix_acl_access", &encoded, 0, &root_ctx())
            .unwrap();

        let attr = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert_eq!(attr.posix.mode & 0o777, 0o476);
        assert_eq!(
            engine
                .getxattr(inode, b"system.posix_acl_access", &root_ctx())
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn setxattr_advances_ctime() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"xattr-ctime.txt");
        let before = engine.getattr(inode, None, &root_ctx()).unwrap();

        engine
            .setxattr(inode, b"user.ctime", b"value", 0, &root_ctx())
            .unwrap();

        let after = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "setxattr must advance ctime: before={}, after={}",
            before.posix.ctime_ns,
            after.posix.ctime_ns
        );
    }

    #[test]
    fn removexattr_advances_ctime_and_missing_reports_enodata() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"xattr-remove-ctime.txt");

        engine
            .setxattr(inode, b"user.remove", b"value", 0, &root_ctx())
            .unwrap();
        let before = engine.getattr(inode, None, &root_ctx()).unwrap();

        engine
            .removexattr(inode, b"user.remove", &root_ctx())
            .unwrap();

        let after = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "removexattr must advance ctime: before={}, after={}",
            before.posix.ctime_ns,
            after.posix.ctime_ns
        );
        assert_eq!(
            engine
                .getxattr(inode, b"user.remove", &root_ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
        assert_eq!(
            engine
                .removexattr(inode, b"user.remove", &root_ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
    }

    #[test]
    fn removexattr_posix_acl_access_removes_acl_without_mode_drift() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"acl-remove.txt");
        let acl = tidefs_posix_acl::minimal_access_acl_from_mode(0o640);
        let encoded = tidefs_posix_acl::encode_posix_acl_xattr(&acl);

        engine
            .setxattr(inode, b"system.posix_acl_access", &encoded, 0, &root_ctx())
            .unwrap();
        let before = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert_eq!(before.posix.mode & 0o777, 0o640);

        engine
            .removexattr(inode, b"system.posix_acl_access", &root_ctx())
            .unwrap();

        let after = engine.getattr(inode, None, &root_ctx()).unwrap();
        assert_eq!(after.posix.mode & 0o777, 0o640);
        assert!(
            after.posix.ctime_ns > before.posix.ctime_ns,
            "ACL removexattr must advance ctime"
        );
        assert_eq!(
            engine
                .getxattr(inode, b"system.posix_acl_access", &root_ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
    }

    #[test]
    fn setxattr_rejects_structurally_invalid_access_acl_payloads() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"acl-invalid.txt");
        let invalid_acl = tidefs_posix_acl::encode_posix_acl_xattr(&[]);

        let access = engine.setxattr(
            inode,
            b"system.posix_acl_access",
            &invalid_acl,
            0,
            &root_ctx(),
        );
        assert_eq!(access.unwrap_err(), Errno::EINVAL);

        let missing = engine.getxattr(inode, b"system.posix_acl_access", &root_ctx());
        assert_eq!(missing.unwrap_err(), Errno::ENODATA);
    }

    #[test]
    fn setxattr_empty_default_acl_removes_default_acl() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();
        let default_acl = default_acl_for_inheritance_regression();
        let default_raw = tidefs_posix_acl::encode_posix_acl_xattr(&default_acl);
        engine
            .setxattr(
                root,
                b"system.posix_acl_default",
                &default_raw,
                0,
                &root_ctx(),
            )
            .unwrap();

        let empty_default = tidefs_posix_acl::encode_posix_acl_xattr(&[]);
        engine
            .setxattr(
                root,
                b"system.posix_acl_default",
                &empty_default,
                0,
                &root_ctx(),
            )
            .unwrap();

        assert_eq!(
            engine
                .getxattr(root, b"system.posix_acl_default", &root_ctx())
                .unwrap_err(),
            Errno::ENODATA
        );
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o077,
            groups: vec![4343],
        };
        let child = engine
            .mkdir(root, b"mode-masked-after-empty-default", 0o777, &caller)
            .unwrap();
        assert_eq!(child.posix.mode & 0o777, 0o700);
    }

    #[test]
    fn setxattr_minimal_default_acl_allows_generic319_inheritance() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&root_ctx()).unwrap();
        let testdir = engine
            .mkdir(root, b"generic319-testdir", 0o755, &root_ctx())
            .unwrap();
        let empty_default = tidefs_posix_acl::encode_posix_acl_xattr(&[]);
        engine
            .setxattr(
                testdir.inode_id,
                b"system.posix_acl_default",
                &empty_default,
                0,
                &root_ctx(),
            )
            .unwrap();

        let generic319_default_acl = vec![
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_GROUP_OBJ,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_OTHER,
                perm: 0,
                id: 0,
            },
        ];
        let default_raw = tidefs_posix_acl::encode_posix_acl_xattr(&generic319_default_acl);
        engine
            .setxattr(
                testdir.inode_id,
                b"system.posix_acl_default",
                &default_raw,
                0,
                &root_ctx(),
            )
            .unwrap();

        let child = engine
            .mkdir(testdir.inode_id, b"testsubdir", 0o777, &root_ctx())
            .unwrap();
        assert_eq!(child.posix.mode & 0o777, 0o770);
        let child_access = engine
            .getxattr(child.inode_id, b"system.posix_acl_access", &root_ctx())
            .unwrap();
        assert_eq!(
            tidefs_posix_acl::decode_posix_acl_xattr(&child_access).unwrap(),
            generic319_default_acl
        );
        let child_default = engine
            .getxattr(child.inode_id, b"system.posix_acl_default", &root_ctx())
            .unwrap();
        assert_eq!(
            tidefs_posix_acl::decode_posix_acl_xattr(&child_default).unwrap(),
            generic319_default_acl
        );
    }

    #[test]
    fn listxattr_preserves_linux_null_terminated_layout() {
        let (engine, _td) = temp_fs();
        let inode = create_xattr_file(&engine, b"layout.txt");

        engine.setxattr(inode, b"user.a", b"1", 0, &ctx()).unwrap();
        engine
            .setxattr(inode, b"security.b", b"2", 0, &ctx())
            .unwrap();

        assert_eq!(
            engine.listxattr(inode, &ctx()).unwrap(),
            b"security.b\0user.a\0"
        );
    }

    #[test]
    fn getxattr_not_found() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let result = engine.getxattr(root, b"user.nonexistent", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENODATA);
    }

    #[test]
    fn listxattr_empty_by_default() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let list = engine.listxattr(root, &ctx()).unwrap();
        assert!(list.is_empty());
    }
    // ── Error mapping tests ──────────────────────────────────────────

    #[test]
    fn lookup_nonexistent_returns_enoent() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let result = engine.lookup(root, b"no-such-file", &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn mkdir_duplicate_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        engine.mkdir(root, b"dupdir", 0o755, &ctx()).unwrap();
        let result = engine.mkdir(root, b"dupdir", 0o755, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EEXIST);
    }

    #[test]
    fn mknod_returns_eopnotsupp() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let result = engine.mknod(root, b"dev", 0o600, 0, &ctx());
        assert_eq!(result.unwrap_err(), Errno::EOPNOTSUPP);
    }

    #[test]
    fn tmpfile_creates_unnamed_read_write_file() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();

        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.mode & S_IFMT, tidefs_types_vfs_core::S_IFREG);
        assert_eq!(attr.posix.mode & !S_IFMT, 0o600);
        assert_eq!(attr.posix.nlink, 0);
        assert_eq!(fh.inode_id, attr.inode_id);

        let written = engine.write(&fh, 0, b"tmpfile bytes", &ctx()).unwrap();
        assert_eq!(written, b"tmpfile bytes".len() as u32);
        let data = engine
            .read(&fh, 0, b"tmpfile bytes".len() as u32, &ctx())
            .unwrap();
        assert_eq!(data, b"tmpfile bytes");

        let after_write = engine.getattr(attr.inode_id, Some(&fh), &ctx()).unwrap();
        assert_eq!(after_write.posix.size, b"tmpfile bytes".len() as u64);
    }

    #[test]
    fn tmpfile_does_not_publish_directory_entry() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();

        assert_eq!(engine.inode_path(attr.inode_id).unwrap_err(), Errno::ENOENT);

        let dh = engine.opendir(root, &ctx()).unwrap();
        let (entries, has_more) = engine.readdir(&dh, 0, &ctx()).unwrap();
        assert!(entries.is_empty());
        assert!(!has_more);
        engine.releasedir(&dh).unwrap();
    }

    #[test]
    fn tmpfile_parent_not_directory_returns_enotdir() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (file, _fh) = engine
            .create(root, b"not-a-dir", 0o600, O_RDWR, &ctx())
            .unwrap();

        let result = engine.tmpfile(file.inode_id, 0o600, O_RDWR, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOTDIR);
    }

    #[test]
    fn tmpfile_missing_parent_returns_enoent() {
        let (engine, _td) = temp_fs();

        let result = engine.tmpfile(InodeId::new(999_999), 0o600, O_RDWR, &ctx());
        assert_eq!(result.unwrap_err(), Errno::ENOENT);
    }

    #[test]
    fn tmpfile_applies_umask_and_request_owner() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 4242,
            gid: 4343,
            pid: 77,
            umask: 0o027,
            groups: vec![4343],
        };

        let (attr, _fh) = engine.tmpfile(root, 0o777, O_RDWR, &caller).unwrap();

        assert_eq!(attr.posix.mode & !S_IFMT, 0o750);
        assert_eq!(attr.posix.uid, 4242);
        assert_eq!(attr.posix.gid, 4343);
    }

    #[test]
    fn tmpfile_final_release_reclaims_zero_link_inode() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();
        engine.write(&fh, 0, b"released", &ctx()).unwrap();

        engine.release(&fh).unwrap();

        assert_eq!(engine.read(&fh, 0, 8, &ctx()).unwrap_err(), Errno::EBADF);
        assert_eq!(engine.inode_path(attr.inode_id).unwrap_err(), Errno::ENOENT);
    }

    // ── tmpfile direct-inode linking ─────────────────────────────────

    #[test]
    fn tmpfile_write_fsync_link_preserves_inode_and_bytes_after_original_release() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, fh) = engine.tmpfile(root, 0o644, O_RDWR, &ctx()).unwrap();
        let ino = attr.inode_id;
        let payload = b"linked tmpfile content";
        engine.write(&fh, 0, payload, &ctx()).unwrap();
        engine.fsync(&fh, false, &ctx()).unwrap();

        assert_eq!(engine.inode_path(ino).unwrap_err(), Errno::ENOENT);

        let linked_attr = engine.link(ino, root, b"linked-tmpfile", &ctx()).unwrap();
        assert_eq!(linked_attr.inode_id, ino);
        assert_eq!(linked_attr.posix.nlink, 1);
        assert_eq!(linked_attr.posix.size, payload.len() as u64);
        assert_eq!(engine.inode_path(ino).unwrap(), "/linked-tmpfile");
        assert_eq!(
            engine.read(&fh, 0, payload.len() as u32, &ctx()).unwrap(),
            payload
        );

        engine.release(&fh).unwrap();
        assert_eq!(engine.getattr(ino, None, &ctx()).unwrap().inode_id, ino);

        let read_fh = engine.open(ino, O_RDONLY, &ctx()).unwrap();
        let data = engine
            .read(&read_fh, 0, payload.len() as u32, &ctx())
            .unwrap();
        assert_eq!(data, payload);
        engine.release(&read_fh).unwrap();
    }

    #[test]
    fn tmpfile_link_duplicate_name_returns_eexist() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (_fa, fh) = engine.create(root, b"existing", 0o644, 0, &ctx()).unwrap();
        engine.release(&fh).unwrap();
        let (attr, _fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();
        let err = engine
            .link(attr.inode_id, root, b"existing", &ctx())
            .unwrap_err();
        assert_eq!(err, Errno::EEXIST);
    }

    #[test]
    fn tmpfile_link_preserves_ownership() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let caller = RequestCtx {
            uid: 1234,
            gid: 5678,
            pid: 77,
            umask: 0o022,
            groups: vec![5678],
        };
        let (tattr, tfh) = engine.tmpfile(root, 0o640, O_RDWR, &caller).unwrap();
        engine.write(&tfh, 0, b"owned", &caller).unwrap();
        let linked = engine
            .link(tattr.inode_id, root, b"owned-file", &caller)
            .unwrap();
        assert_eq!(linked.posix.uid, 1234);
        assert_eq!(linked.posix.gid, 5678);
    }

    #[test]
    fn tmpfile_link_empty_file_is_accessible() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.tmpfile(root, 0o600, O_RDWR, &ctx()).unwrap();
        let linked = engine
            .link(attr.inode_id, root, b"empty-linked", &ctx())
            .unwrap();
        assert_eq!(linked.posix.size, 0);
        assert_eq!(engine.inode_path(attr.inode_id).unwrap(), "/empty-linked");
    }

    // ── Path cache tests ─────────────────────────────────────────────

    #[test]
    fn path_cache_populated_for_new_inodes() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let child = engine.mkdir(root, b"sub", 0o755, &ctx()).unwrap();
        let grandchild = engine
            .mkdir(child.inode_id, b"nested", 0o755, &ctx())
            .unwrap();

        assert_eq!(engine.inode_path(child.inode_id).unwrap(), "/sub");
        assert_eq!(
            engine.inode_path(grandchild.inode_id).unwrap(),
            "/sub/nested"
        );
    }

    #[test]
    fn path_cache_updated_on_rename() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"oldname", 0o644, 0, &ctx()).unwrap();
        engine
            .rename(root, b"oldname", root, b"newname", 0, &ctx())
            .unwrap();

        let path = engine.inode_path(attr.inode_id).unwrap();
        assert_eq!(path, "/newname");
    }

    #[test]
    fn path_cache_file_rename_does_not_rewrite_non_directory_descendants() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"oldname", 0o644, 0, &ctx()).unwrap();
        let synthetic = InodeId::new(999_001);
        engine
            .path_cache
            .borrow_mut()
            .insert(synthetic, "/oldname/not-a-child".to_string());

        engine
            .rename(root, b"oldname", root, b"newname", 0, &ctx())
            .unwrap();

        assert_eq!(
            cached_path(&engine, attr.inode_id).as_deref(),
            Some("/newname")
        );
        assert_eq!(
            cached_path(&engine, synthetic).as_deref(),
            Some("/oldname/not-a-child")
        );
    }

    #[test]
    fn path_cache_file_exchange_does_not_rewrite_non_directory_descendants() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (alpha, _alpha_fh) = engine.create(root, b"alpha.txt", 0o644, 0, &ctx()).unwrap();
        let (beta, _beta_fh) = engine.create(root, b"beta.txt", 0o644, 0, &ctx()).unwrap();
        let synthetic_alpha = InodeId::new(999_002);
        let synthetic_beta = InodeId::new(999_003);
        {
            let mut cache = engine.path_cache.borrow_mut();
            cache.insert(synthetic_alpha, "/alpha.txt/not-a-child".to_string());
            cache.insert(synthetic_beta, "/beta.txt/not-a-child".to_string());
        }

        engine
            .rename(
                root,
                b"alpha.txt",
                root,
                b"beta.txt",
                RENAME_EXCHANGE,
                &ctx(),
            )
            .unwrap();

        assert_eq!(
            cached_path(&engine, alpha.inode_id).as_deref(),
            Some("/beta.txt")
        );
        assert_eq!(
            cached_path(&engine, beta.inode_id).as_deref(),
            Some("/alpha.txt")
        );
        assert_eq!(
            cached_path(&engine, synthetic_alpha).as_deref(),
            Some("/alpha.txt/not-a-child")
        );
        assert_eq!(
            cached_path(&engine, synthetic_beta).as_deref(),
            Some("/beta.txt/not-a-child")
        );
    }

    #[test]
    fn namespace_churn_preserves_unrelated_cached_paths() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let stable = engine.mkdir(root, b"stable", 0o755, &ctx()).unwrap();
        let (nested, _nested_fh) = engine
            .create(stable.inode_id, b"nested.txt", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            engine.inode_path(nested.inode_id).unwrap(),
            "/stable/nested.txt"
        );

        for idx in 0..16 {
            let file_name = format!("churn-{idx}.txt");
            let (created, _fh) = engine
                .create(root, file_name.as_bytes(), 0o644, 0, &ctx())
                .unwrap();
            assert_eq!(
                cached_path(&engine, nested.inode_id).as_deref(),
                Some("/stable/nested.txt")
            );

            engine.unlink(root, file_name.as_bytes(), &ctx()).unwrap();
            assert_eq!(
                cached_path(&engine, nested.inode_id).as_deref(),
                Some("/stable/nested.txt")
            );
            assert_eq!(cached_path(&engine, created.inode_id), None);

            let dir_name = format!("churn-dir-{idx}");
            let removed_dir = engine
                .mkdir(root, dir_name.as_bytes(), 0o755, &ctx())
                .unwrap();
            engine.rmdir(root, dir_name.as_bytes(), &ctx()).unwrap();
            assert_eq!(
                cached_path(&engine, nested.inode_id).as_deref(),
                Some("/stable/nested.txt")
            );
            assert_eq!(cached_path(&engine, removed_dir.inode_id), None);
        }
    }

    #[test]
    fn unlink_burst_prunes_removed_cached_paths() {
        let td = tempfile::tempdir().expect("tempdir");
        let mut fs = PoolDatasetOwner::open(td.path()).expect("open");
        fs.set_auto_commit(false)
            .expect("test setup mutation must be admitted");
        fs.set_commit_group_throughput_profile()
            .expect("test setup mutation must be admitted");
        fs.set_max_uncommitted_mutations(16 * 1024)
            .expect("test setup mutation must be admitted");
        let engine = VfsLocalFileSystem::new(fs);
        let root = engine.get_root_inode(&ctx()).unwrap();
        let parent = engine.mkdir(root, b"permname", 0o755, &ctx()).unwrap();
        let target = engine.mkdir(parent.inode_id, b"b", 0o755, &ctx()).unwrap();
        let stable = engine
            .mkdir(parent.inode_id, b"stable", 0o755, &ctx())
            .unwrap();
        let mut created = Vec::new();

        for idx in 0..4096u64 {
            let mut value = idx;
            let mut name = vec![b'a'; 6];
            for byte in name.iter_mut().rev() {
                *byte = b'a' + u8::try_from(value % 4).unwrap();
                value /= 4;
            }
            let (attr, fh) = engine
                .create(target.inode_id, &name, 0o644, 0, &ctx())
                .unwrap();
            engine.release(&fh).unwrap();
            created.push((attr.inode_id, name));
        }

        assert_eq!(
            cached_path(&engine, stable.inode_id).as_deref(),
            Some("/permname/stable")
        );

        for (inode_id, name) in &created {
            engine.unlink(target.inode_id, name, &ctx()).unwrap();
            assert_eq!(cached_path(&engine, *inode_id), None);
            assert_eq!(
                cached_path(&engine, stable.inode_id).as_deref(),
                Some("/permname/stable")
            );
        }
        engine.rmdir(parent.inode_id, b"b", &ctx()).unwrap();
    }

    #[test]
    fn path_cache_rewrites_directory_descendants_on_rename() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let old_dir = engine.mkdir(root, b"old", 0o755, &ctx()).unwrap();
        let child_dir = engine
            .mkdir(old_dir.inode_id, b"child", 0o755, &ctx())
            .unwrap();
        let (leaf, _fh) = engine
            .create(child_dir.inode_id, b"leaf.txt", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            engine.inode_path(leaf.inode_id).unwrap(),
            "/old/child/leaf.txt"
        );

        engine
            .rename(root, b"old", root, b"new", 0, &ctx())
            .unwrap();

        assert_eq!(
            cached_path(&engine, old_dir.inode_id).as_deref(),
            Some("/new")
        );
        assert_eq!(
            cached_path(&engine, child_dir.inode_id).as_deref(),
            Some("/new/child")
        );
        assert_eq!(
            cached_path(&engine, leaf.inode_id).as_deref(),
            Some("/new/child/leaf.txt")
        );
        assert_eq!(
            engine
                .lookup(child_dir.inode_id, b"leaf.txt", &ctx())
                .unwrap()
                .inode_id,
            leaf.inode_id
        );
    }

    #[test]
    fn path_cache_rewrites_directory_descendants_on_exchange() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let left_dir = engine.mkdir(root, b"left", 0o755, &ctx()).unwrap();
        let right_dir = engine.mkdir(root, b"right", 0o755, &ctx()).unwrap();
        let (left_child, _left_fh) = engine
            .create(left_dir.inode_id, b"left-child.txt", 0o644, 0, &ctx())
            .unwrap();
        let (right_child, _right_fh) = engine
            .create(right_dir.inode_id, b"right-child.txt", 0o644, 0, &ctx())
            .unwrap();
        assert_eq!(
            engine.inode_path(left_child.inode_id).unwrap(),
            "/left/left-child.txt"
        );
        assert_eq!(
            engine.inode_path(right_child.inode_id).unwrap(),
            "/right/right-child.txt"
        );

        engine
            .rename(root, b"left", root, b"right", RENAME_EXCHANGE, &ctx())
            .unwrap();

        assert_eq!(
            cached_path(&engine, left_dir.inode_id).as_deref(),
            Some("/right")
        );
        assert_eq!(
            cached_path(&engine, left_child.inode_id).as_deref(),
            Some("/right/left-child.txt")
        );
        assert_eq!(
            cached_path(&engine, right_dir.inode_id).as_deref(),
            Some("/left")
        );
        assert_eq!(
            cached_path(&engine, right_child.inode_id).as_deref(),
            Some("/left/right-child.txt")
        );
    }

    // ── ctime advancement on setattr (#3566) ──────────────────────────────────

    #[test]
    fn setattr_ctime_advances_on_mode_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"mode-file", 0o644, 0, &ctx()).unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o600;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on mode change"
        );
    }

    #[test]
    fn setattr_chmod_synchronizes_acl_access_xattr() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"acl-file", 0o640, 0, &ctx()).unwrap();

        // Set a posix_acl_access xattr with mode-matching entries.
        let acl = tidefs_posix_acl::encode_posix_acl_xattr(
            &tidefs_posix_acl::minimal_access_acl_from_mode(0o640),
        );
        engine
            .setxattr(attr.inode_id, b"system.posix_acl_access", &acl, 0, &ctx())
            .unwrap();

        // chmod to 0o751 should update the ACL entry permissions.
        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o751;
        let _updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();

        let acl_raw = engine
            .getxattr(attr.inode_id, b"system.posix_acl_access", &ctx())
            .unwrap();
        let decoded = tidefs_posix_acl::decode_posix_acl_xattr(&acl_raw).unwrap();

        // After chmod to 0o751, ACL entries should reflect new mode bits:
        // user_obj = 7 (rwx), group_obj = 5 (r-x), other = 1 (--x)
        assert_eq!(decoded[0].perm, 7); // user_obj
        assert_eq!(decoded[1].perm, 5); // group_obj
        assert_eq!(decoded[2].perm, 1); // other
    }

    #[test]
    fn setattr_chmod_updates_acl_mask_without_group_obj_drift() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"acl-mask-file", 0o755, 0, &ctx())
            .unwrap();
        let acl = vec![
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER_OBJ,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_USER,
                perm: 7,
                id: 1234,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_GROUP_OBJ,
                perm: 5,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_GROUP,
                perm: 6,
                id: 2222,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_MASK,
                perm: 7,
                id: 0,
            },
            tidefs_posix_acl::PosixAclEntry {
                tag: tidefs_posix_acl::ACL_OTHER,
                perm: 5,
                id: 0,
            },
        ];
        let encoded = tidefs_posix_acl::encode_posix_acl_xattr(&acl);
        engine
            .setxattr(
                attr.inode_id,
                b"system.posix_acl_access",
                &encoded,
                0,
                &ctx(),
            )
            .unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o640;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert_eq!(updated.posix.mode & 0o777, 0o640);

        let acl_raw = engine
            .getxattr(attr.inode_id, b"system.posix_acl_access", &ctx())
            .unwrap();
        let decoded = tidefs_posix_acl::decode_posix_acl_xattr(&acl_raw).unwrap();

        assert_eq!(decoded[0].perm, 6); // user_obj
        assert_eq!(decoded[1].perm, 7); // named user unchanged
        assert_eq!(decoded[2].perm, 5); // group_obj unchanged when mask exists
        assert_eq!(decoded[3].perm, 6); // named group unchanged
        assert_eq!(decoded[4].perm, 4); // mask receives chmod group bits
        assert_eq!(decoded[5].perm, 0); // other
    }

    #[test]
    fn setattr_chmod_no_acl_leaves_xattrs_untouched() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"noacl-file", 0o644, 0, &ctx())
            .unwrap();

        // Set a non-ACL xattr; chmod should not disturb it.
        engine
            .setxattr(attr.inode_id, b"user.comment", b"hello", 0, &ctx())
            .unwrap();

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE;
        set.mode = 0o600;
        let _updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();

        let val = engine
            .getxattr(attr.inode_id, b"user.comment", &ctx())
            .unwrap();
        assert_eq!(val, b"hello");

        // No ACL should have been created.
        assert_eq!(
            engine
                .getxattr(attr.inode_id, b"system.posix_acl_access", &ctx())
                .unwrap_err(),
            Errno::ENODATA,
        );
    }

    #[test]
    fn setattr_ctime_advances_on_uid_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"uid-file", 0o644, 0, &ctx()).unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_UID;
        set.uid = 999;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on uid change"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_gid_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"gid-file", 0o644, 0, &ctx()).unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_GID;
        set.gid = 999;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on gid change"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_size_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"size-file", 0o644, 0, &ctx()).unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_SIZE;
        set.size = 8192;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on size change"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_mtime_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"mtime-file", 0o644, 0, &ctx())
            .unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME;
        set.mtime_ns = 9_000_000_000;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on mtime change (POSIX semantics)"
        );
        assert_eq!(
            updated.posix.mtime_ns, 9_000_000_000,
            "mtime should be set to explicit value"
        );
    }

    #[test]
    fn setattr_preserves_signed_explicit_times_without_data_version_drift() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"signed-time-file", 0o644, 0, &ctx())
            .unwrap();

        let stored_before = engine
            .fs
            .borrow()
            .get_inode_by_id(attr.inode_id)
            .expect("created inode present")
            .clone();
        let data_version_before = stored_before.data_version;
        let metadata_version_before = stored_before.metadata_version;

        let atime_1960_ns = -315_619_200_000_000_000_i64;
        let mtime_1960_ns = atime_1960_ns + 123_456_789;
        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = atime_1960_ns;
        set.mtime_ns = mtime_1960_ns;

        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert_eq!(updated.posix.atime_ns, atime_1960_ns);
        assert_eq!(updated.posix.mtime_ns, mtime_1960_ns);
        assert!(
            updated.posix.ctime_ns > attr.posix.ctime_ns,
            "ctime should advance on explicit timestamp mutation"
        );

        let stored_after = engine
            .fs
            .borrow()
            .get_inode_by_id(attr.inode_id)
            .expect("updated inode present")
            .clone();
        assert_eq!(stored_after.posix_time.atime_ns, atime_1960_ns);
        assert_eq!(stored_after.posix_time.mtime_ns, mtime_1960_ns);
        assert_eq!(
            stored_after.data_version, data_version_before,
            "timestamp-only setattr must not rewrite content version identity"
        );
        assert!(
            stored_after.metadata_version > metadata_version_before,
            "metadata revision should advance separately from POSIX time"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_mtime_now() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"mtime-now-file", 0o644, 0, &ctx())
            .unwrap();
        let orig_mtime = attr.posix.mtime_ns;
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_MTIME_NOW;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.mtime_ns > orig_mtime,
            "mtime should advance with MTIME_NOW"
        );
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on MTIME_NOW (POSIX semantics)"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_atime_change() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"atime-file", 0o644, 0, &ctx())
            .unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME;
        set.atime_ns = 9_000_000_000;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on atime change"
        );
    }

    #[test]
    fn setattr_ctime_advances_on_atime_now() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"atime-now-file", 0o644, 0, &ctx())
            .unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME_NOW;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on ATIME_NOW"
        );
    }

    #[test]
    fn setattr_noop_does_not_bump_ctime() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine.create(root, b"noop-file", 0o644, 0, &ctx()).unwrap();
        let orig_ctime = attr.posix.ctime_ns;
        let orig_atime = attr.posix.atime_ns;
        let orig_mtime = attr.posix.mtime_ns;

        let set = SetAttr::new(); // valid == 0, no changes
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert_eq!(
            updated.posix.ctime_ns, orig_ctime,
            "ctime should not advance on no-op setattr"
        );
        assert_eq!(
            updated.posix.atime_ns, orig_atime,
            "atime should not change on no-op setattr"
        );
        assert_eq!(
            updated.posix.mtime_ns, orig_mtime,
            "mtime should not change on no-op setattr"
        );
    }

    #[test]
    fn setattr_unchanged_explicit_times_preserves_ctime_and_versions() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"unchanged-times-file", 0o644, 0, &ctx())
            .unwrap();
        let stored_before = engine
            .fs
            .borrow()
            .get_inode_by_id(attr.inode_id)
            .expect("created inode present")
            .clone();

        let mut set = SetAttr::new();
        set.valid = FATTR_ATIME | FATTR_MTIME;
        set.atime_ns = attr.posix.atime_ns;
        set.mtime_ns = attr.posix.mtime_ns;

        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert_eq!(updated.posix.atime_ns, attr.posix.atime_ns);
        assert_eq!(updated.posix.mtime_ns, attr.posix.mtime_ns);
        assert_eq!(updated.posix.ctime_ns, attr.posix.ctime_ns);

        let stored_after = engine
            .fs
            .borrow()
            .get_inode_by_id(attr.inode_id)
            .expect("updated inode present")
            .clone();
        assert_eq!(stored_after.data_version, stored_before.data_version);
        assert_eq!(
            stored_after.metadata_version,
            stored_before.metadata_version
        );
    }

    #[test]
    fn setattr_ctime_advances_on_multi_field_update() {
        let (engine, _td) = temp_fs();
        let root = engine.get_root_inode(&ctx()).unwrap();
        let (attr, _fh) = engine
            .create(root, b"multi-file", 0o644, 0, &ctx())
            .unwrap();
        let orig_ctime = attr.posix.ctime_ns;

        let mut set = SetAttr::new();
        set.valid = FATTR_MODE | FATTR_UID | FATTR_SIZE;
        set.mode = 0o755;
        set.uid = 2000;
        set.size = 100;
        let updated = engine.setattr(attr.inode_id, &set, None, &ctx()).unwrap();
        assert!(
            updated.posix.ctime_ns > orig_ctime,
            "ctime should advance on multi-field setattr"
        );
        assert_eq!(updated.posix.mode & 0o777, 0o755);
        assert_eq!(updated.posix.uid, 2000);
        assert_eq!(updated.posix.size, 100);
    }

    #[test]
    fn map_errno_converts_store_nospace_to_enospc() {
        // StoreError::NoSpace wrapped as FileSystemError::Store must map to
        // ENOSPC, not EIO. This is the key fix for issue #4957.
        let store_err = StoreError::NoSpace;
        let fs_err = FileSystemError::Store(store_err);
        assert_eq!(map_errno(&fs_err), Errno::ENOSPC);

        // Verify that other StoreError variants still map to EIO.
        let io_err = StoreError::ReadOnly { operation: "write" };
        let fs_io_err = FileSystemError::Store(io_err);
        assert_eq!(map_errno(&fs_io_err), Errno::EIO);

        // Verify that FileSystemError::NoSpace still maps correctly.
        let fs_nospace = FileSystemError::NoSpace {
            resource: crate::types::LocalStorageResource::ContentBytes,
            requested: 1024,
            available: 0,
            capacity: 1024,
            allocated: 1024,
        };
        assert_eq!(map_errno(&fs_nospace), Errno::ENOSPC);
    }

    // ── Write admission watermark tests ─────────────────────────────

    static NEXT_WATERMARK_TEMP_ID: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(1);

    /// Create a temp filesystem for watermark tests.
    fn watermark_temp_fs() -> (VfsLocalFileSystem, PathBuf) {
        let temp_id = NEXT_WATERMARK_TEMP_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "tidefs-watermark-test-{}-{temp_id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        let local_fs = PoolDatasetOwner::open_with_root_authentication_key(
            &root,
            tidefs_local_object_store::StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(local_fs);
        (engine, root)
    }

    #[test]
    fn write_admission_default_allows_all_writes() {
        let (engine, root) = watermark_temp_fs();
        let _ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0o022,
            groups: vec![0],
        };

        // Default watermark (0) means all writes are admitted.
        assert_eq!(engine.check_write_admission(4096), Ok(()));
        assert_eq!(engine.check_write_admission(u64::MAX / 2), Ok(()));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_admission_refuses_when_watermark_breached() {
        let (engine, root) = watermark_temp_fs();
        let _ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0o022,
            groups: vec![0],
        };

        engine
            .set_low_watermark_bytes(u64::MAX)
            .expect("test setup mutation must be admitted");

        assert_eq!(engine.check_write_admission(1), Err(Errno::ENOSPC));
        assert_eq!(engine.check_write_admission(4096), Err(Errno::ENOSPC));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_admission_allows_metadata_bypass() {
        let (engine, root) = watermark_temp_fs();
        let _ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0o022,
            groups: vec![0],
        };

        engine
            .set_low_watermark_bytes(u64::MAX)
            .expect("test setup mutation must be admitted");

        // At the VfsEngine level, check_write_admission checks data writes.
        // The pool-level bypass for metadata is tested in pool/mod.rs.
        assert_eq!(engine.check_write_admission(1), Err(Errno::ENOSPC));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_admission_refuses_before_buffering_after_watermark_set() {
        let (engine, root) = watermark_temp_fs();
        let ctx = RequestCtx {
            uid: 0,
            gid: 0,
            pid: 1,
            umask: 0o022,
            groups: vec![0],
        };

        // Create a test file and write some data normally.
        let root_inode = engine.get_root_inode(&ctx).expect("root inode");
        let (_attr, fh) = engine
            .create(root_inode, b"test.bin", 0o644, O_WRONLY, &ctx)
            .expect("create file");

        // Write data first to verify writes work normally.
        assert!(engine.write(&fh, 0, b"hello", &ctx).is_ok());

        // Flush to persist buffered writes to the pool.
        engine.flush(&fh, &ctx).expect("flush");

        // Now set watermark to block all subsequent data writes.
        engine
            .set_low_watermark_bytes(u64::MAX)
            .expect("test setup mutation must be admitted");

        // check_write_admission should reject.
        assert_eq!(engine.check_write_admission(1), Err(Errno::ENOSPC));

        // Mounted admission fails before bytes enter the write buffer, so the
        // existing committed content remains the complete readable state.
        assert_eq!(engine.write(&fh, 10, b"buffered", &ctx), Err(Errno::ENOSPC));
        assert_eq!(
            engine
                .fs
                .borrow()
                .read_file("/test.bin")
                .expect("read content after refused mounted write"),
            b"hello"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    mod replicated_repair {
        use super::*;

        fn corrupt_current_pool_chunk_on_primary(
            engine: &VfsLocalFileSystem,
            path: &str,
            payload: &[u8],
        ) -> (
            ObjectKey,
            tidefs_local_object_store::PlacementReceipt,
            crate::types::ScrubBlockId,
        ) {
            assert!(!payload.is_empty(), "corruption payload must be non-empty");
            let mut fs = engine.fs.borrow_mut();
            let record = fs.stat(path).expect("stat committed repair fixture");
            let keyspace = fs.object_keyspace();
            let manifest_key = keyspace.content(record.inode_id, record.data_version);
            let (manifest_bytes, _) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, manifest_key)
                .expect("read repair content manifest")
                .expect("repair content manifest exists");
            let manifest = crate::encoding::decode_content_manifest(&manifest_bytes)
                .expect("decode repair content manifest");
            let chunk = manifest
                .chunks
                .iter()
                .find(|chunk| !chunk.is_hole())
                .expect("repair content chunk");
            let chunk_key =
                keyspace.content_chunk(record.inode_id, chunk.data_version, chunk.chunk_index);
            let block_id = crate::types::ScrubBlockId {
                inode_id: record.inode_id.get(),
                data_version: chunk.data_version,
                kind: crate::types::ScrubBlockKind::ContentChunk {
                    chunk_index: chunk.chunk_index,
                },
            };
            let (mut encoded, receipt) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, chunk_key)
                .expect("read repair content chunk")
                .expect("repair content chunk exists");
            let payload_offset = encoded
                .windows(payload.len())
                .position(|candidate| candidate == payload)
                .expect("repair payload appears in encoded chunk");
            encoded[payload_offset] ^= 0x5a;
            fs.store
                .pool_mut()
                .raw_primary_store_mut()
                .put(chunk_key, &encoded)
                .expect("corrupt exactly the primary receipt target");
            fs.store
                .pool_mut()
                .sync_all()
                .expect("sync one-target corruption fixture");
            (chunk_key, receipt, block_id)
        }

        fn corrupt_current_pool_chunk_on_block_device(
            engine: &VfsLocalFileSystem,
            path: &str,
            payload: &[u8],
            device_path: &std::path::Path,
            expected_device_index: u32,
        ) -> (
            ObjectKey,
            tidefs_local_object_store::PlacementReceipt,
            crate::types::ScrubBlockId,
        ) {
            assert!(!payload.is_empty(), "corruption payload must be non-empty");
            let fs = engine.fs.borrow();
            let record = fs.stat(path).expect("stat block-device repair fixture");
            let keyspace = fs.object_keyspace();
            let manifest_key = keyspace.content(record.inode_id, record.data_version);
            let (manifest_bytes, _) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, manifest_key)
                .expect("read block-device repair content manifest")
                .expect("block-device repair content manifest exists");
            let manifest = crate::encoding::decode_content_manifest(&manifest_bytes)
                .expect("decode block-device repair content manifest");
            let chunk = manifest
                .chunks
                .iter()
                .find(|chunk| !chunk.is_hole())
                .expect("block-device repair content chunk");
            let chunk_key =
                keyspace.content_chunk(record.inode_id, chunk.data_version, chunk.chunk_index);
            let block_id = crate::types::ScrubBlockId {
                inode_id: record.inode_id.get(),
                data_version: chunk.data_version,
                kind: crate::types::ScrubBlockKind::ContentChunk {
                    chunk_index: chunk.chunk_index,
                },
            };
            let (_, receipt) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, chunk_key)
                .expect("read block-device repair content chunk")
                .expect("block-device repair content chunk exists");
            assert!(
                receipt
                    .targets
                    .iter()
                    .any(|target| target.device_index == expected_device_index),
                "current receipt must name the selected corruption target"
            );
            drop(fs);

            let image = std::fs::read(device_path).expect("read selected block-device image");
            let matches = image
                .windows(payload.len())
                .enumerate()
                .filter_map(|(offset, candidate)| (candidate == payload).then_some(offset))
                .collect::<Vec<_>>();
            let [payload_offset] = matches.as_slice() else {
                panic!(
                    "selected block-device image must contain exactly one repair payload, found {}",
                    matches.len()
                );
            };
            let payload_offset = *payload_offset;
            let corrupt_offset = payload_offset + payload.len() / 2;
            let corrupt_byte = [image[corrupt_offset] ^ 0x5a];
            let mut device = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(device_path)
                .expect("open selected block-device image for corruption");
            device
                .seek(SeekFrom::Start(
                    u64::try_from(corrupt_offset).expect("corruption offset fits u64"),
                ))
                .expect("seek selected block-device corruption byte");
            device
                .write_all(&corrupt_byte)
                .expect("corrupt selected block-device target");
            device
                .sync_all()
                .expect("sync selected block-device corruption");

            (chunk_key, receipt, block_id)
        }

        fn corrupt_one_current_replicated_chunk(
            engine: &VfsLocalFileSystem,
            path: &str,
            payload: &[u8],
        ) -> (ObjectKey, u64, crate::types::ScrubBlockId) {
            let (chunk_key, receipt, block_id) =
                corrupt_current_pool_chunk_on_primary(engine, path, payload);
            assert_eq!(
                receipt.policy,
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 }
            );
            let fs = engine.fs.borrow();
            let evidence = fs
                .store
                .pool()
                .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                .expect("read target evidence after corruption")
                .expect("current receipt after corruption");
            assert_eq!(
                evidence
                    .targets
                    .iter()
                    .filter(|target| matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                    ))
                    .count(),
                1,
                "fixture must retain exactly one clean source"
            );
            assert_eq!(
                evidence
                    .targets
                    .iter()
                    .filter(|target| matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt { .. }
                    ))
                    .count(),
                1,
                "fixture must corrupt exactly one current target"
            );
            (chunk_key, receipt.generation, block_id)
        }

        fn publish_target_only_repair(
            engine: &VfsLocalFileSystem,
            chunk_key: ObjectKey,
        ) -> tidefs_local_object_store::pool::ReplicatedRepairResult {
            let mut fs = engine.fs.borrow_mut();
            let evidence = fs
                .store
                .pool()
                .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                .expect("read direct-repair target evidence")
                .expect("direct-repair receipt evidence");
            let source_device_index = evidence
                .targets
                .iter()
                .find(|target| {
                    matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                    )
                })
                .expect("direct repair has one clean source")
                .target
                .device_index;
            let corrupt_device_index = evidence
                .targets
                .iter()
                .find(|target| {
                    matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt { .. }
                    )
                })
                .expect("direct repair has one corrupt target")
                .target
                .device_index;
            let repair = fs
                .store
                .pool_mut()
                .repair_current_replicated_target(
                    DeviceIoClass::Data,
                    chunk_key,
                    &evidence.receipt,
                    source_device_index,
                    corrupt_device_index,
                )
                .expect("publish target-only repair without filesystem reconciliation");
            fs.store
                .pool_mut()
                .sync_all()
                .expect("sync direct target-only repair");
            repair
        }

        fn stage_pending_target_repair_for_recovery(
            engine: &VfsLocalFileSystem,
            chunk_key: ObjectKey,
            receipt_copies: tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies,
        ) -> tidefs_local_object_store::pool::PendingReplicatedRepairRecoveryEvidence {
            let mut fs = engine.fs.borrow_mut();
            let pool = fs.store.pool_mut();
            let evidence = pool
                .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                .expect("read pending-repair target evidence")
                .expect("pending-repair receipt exists");
            let source_device_index = evidence
                .targets
                .iter()
                .find(|target| {
                    matches!(
                        target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                    )
                })
                .expect("pending repair has one clean source")
                .target
                .device_index;
            let repaired_device_index = evidence
                .targets
                .iter()
                .find(|target| {
                    matches!(
                        target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt { .. }
                            | tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Unreadable
                    )
                })
                .expect("pending repair has one failed target")
                .target
                .device_index;
            let pending = pool
                .stage_pending_replicated_repair_for_recovery_test(
                    DeviceIoClass::Data,
                    chunk_key,
                    source_device_index,
                    repaired_device_index,
                    receipt_copies,
                )
                .expect("stage exact target-repair recovery cut");
            assert_eq!(pending.predecessor_receipt, evidence.receipt);
            assert!(
                pending.replacement_receipt.generation > pending.predecessor_receipt.generation
            );
            assert_eq!(pending.receipt_copies, receipt_copies);
            pending
        }

        fn complete_device_hashes(devices: &[PathBuf]) -> Vec<blake3::Hash> {
            devices
                .iter()
                .map(|device| {
                    let bytes = std::fs::read(device).expect("read complete device image");
                    blake3::hash(&bytes)
                })
                .collect()
        }

        fn current_file_chunk_authority(
            fs: &PoolDatasetOwner,
            path: &str,
        ) -> (ObjectKey, u64, u64) {
            let record = fs.stat(path).expect("stat current repair fixture");
            let keyspace = fs.object_keyspace();
            let manifest_key = keyspace.content(record.inode_id, record.data_version);
            let (manifest_bytes, _) = fs
                .store
                .pool()
                .get_with_current_receipt(DeviceIoClass::Data, manifest_key)
                .expect("read current repair manifest")
                .expect("current repair manifest exists");
            let manifest = crate::encoding::decode_content_manifest(&manifest_bytes)
                .expect("decode current repair manifest");
            let chunks = manifest
                .chunks
                .iter()
                .filter(|chunk| !chunk.is_hole())
                .collect::<Vec<_>>();
            let [chunk] = chunks.as_slice() else {
                panic!("repair fixture must contain exactly one physical chunk");
            };
            (
                keyspace.content_chunk(record.inode_id, chunk.data_version, chunk.chunk_index),
                chunk.placement_receipt_generation,
                record.data_version,
            )
        }

        fn temp_fs_with_policy_and_block_devices(
            device_count: usize,
            policy: tidefs_local_object_store::pool::PoolRedundancyPolicy,
        ) -> (VfsLocalFileSystem, tempfile::TempDir, Vec<PathBuf>) {
            let root = tempfile::tempdir().expect("tempdir");
            let metadata = root.path().join("metadata");
            std::fs::create_dir_all(&metadata).expect("create metadata dir");
            let mut devices = Vec::with_capacity(device_count);
            for idx in 0..device_count {
                let path = root.path().join(format!("dev{idx}.img"));
                let file = std::fs::File::create(&path).expect("create device image");
                file.set_len(8 * 1024 * 1024).expect("size device image");
                devices.push(path);
            }
            let fs = open_named_test_filesystem(&metadata, &devices, "tank", policy, "root");
            (VfsLocalFileSystem::new(fs), root, devices)
        }

        fn temp_replicated_fs_with_block_devices(
        ) -> (VfsLocalFileSystem, tempfile::TempDir, Vec<PathBuf>) {
            temp_fs_with_policy_and_block_devices(
                2,
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
            )
        }

        #[test]
        fn live_pool_repair_reconciles_one_target_and_survives_reopen() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-current-receipt-fixture";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair.txt", 0o644)
                    .expect("create repair fixture");
                fs.write_file("/repair.txt", 0, payload)
                    .expect("write repair fixture");
                fs.sync_all().expect("commit repair fixture");
                fs.create_snapshot("repair-retained")
                    .expect("retain a snapshot sharing the repair chunk");
            }

            let (chunk_key, predecessor_receipt, _) = corrupt_current_pool_chunk_on_block_device(
                &engine,
                "/repair.txt",
                payload,
                &devices[1],
                1,
            );
            let old_generation = predecessor_receipt.generation;
            let repaired = live_pool_admin(&engine, "repair", json!({}), true);
            assert_eq!(repaired["ok"], true, "repair response: {repaired}");
            let report = &repaired["json"];
            assert_eq!(report["pass"], true);
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "completed");
            assert_eq!(report["repair_attempted"], true);
            assert_eq!(report["repair_completed"], true);
            assert_eq!(report["repair_writeback"], true);
            assert_eq!(
                report["comparison"]["classification"],
                "SingleReplicaCorruption"
            );
            assert_eq!(
                report["comparison"]["checksum_layer"],
                "encoded-content-chunk"
            );
            assert_eq!(report["comparison"]["target_count"], 2);
            assert!(report["comparison"].get("membership_epoch").is_none());
            assert!(report["comparison"]["targets"]
                .as_array()
                .is_some_and(|targets| targets.iter().all(|target| {
                    target.get("evidence_accepted").is_none()
                        && target.get("evidence_rejection").is_none()
                })));
            assert_eq!(
                report["previous_receipt_generation"].as_u64(),
                Some(old_generation)
            );
            assert!(
                report["replacement_receipt_generation"]
                    .as_u64()
                    .is_some_and(|generation| generation > old_generation),
                "replacement receipt must advance: {report}"
            );
            assert_eq!(report["replacement_receipt_attached"], true);
            assert_eq!(report["clean_source"]["device_index"], 0);
            assert_eq!(report["corrupt_target"]["device_index"], 1);
            assert!(
                report["reconciled_manifest_count"]
                    .as_u64()
                    .is_some_and(|count| count >= 2),
                "chunk repair must reconcile current and retained snapshot manifests: {report}"
            );
            assert_eq!(report["reconciled_current_manifest_count"], 1);
            assert_eq!(report["reconciled_snapshot_manifest_count"], 1);
            assert_eq!(report["authenticated_root_published"], true);
            assert_eq!(report["re_scrub"]["pass"], true);
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .store
                    .pool()
                    .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                    .expect("replacement target evidence")
                    .expect("replacement receipt")
                    .targets
                    .iter()
                    .filter(|target| matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                    ))
                    .count(),
                2
            );
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/repair.txt")
                    .expect("read repaired file"),
                payload
            );

            drop(engine);
            let mut reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .read_file("/repair.txt")
                    .expect("read repaired file after reopen"),
                payload
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub repaired content after reopen");
            assert!(re_scrub.is_clean(), "post-reopen scrub: {re_scrub:?}");
            assert_eq!(
                reopened
                    .list_snapshots_checked()
                    .expect("retained repair snapshot remains authoritative")
                    .len(),
                1
            );
            reopened
                .rollback_to_snapshot("repair-retained")
                .expect("rollback retained snapshot after repair reopen");
            assert_eq!(
                reopened
                    .read_file("/repair.txt")
                    .expect("read repaired snapshot content after rollback"),
                payload
            );
        }

        #[test]
        fn live_pool_repair_after_reopen_preserves_clean_transaction_inode_references() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let repair_payload = b"TideFS-live-owner-repair-after-replay";
            {
                let mut fs = engine.fs.borrow_mut();
                for (path, payload) in [
                    ("/older.txt", b"older committed inode".as_slice()),
                    ("/repair.txt", repair_payload.as_slice()),
                    ("/newer.txt", b"newer committed inode".as_slice()),
                ] {
                    fs.create_file(path, 0o644)
                        .expect("create historical repair fixture");
                    fs.write_file(path, 0, payload)
                        .expect("write historical repair fixture");
                    fs.sync_all()
                        .expect("commit historical repair fixture independently");
                }
                for _ in 0..3 {
                    fs.persist_dataset_catalog()
                        .expect("advance transaction identity without a logical mutation");
                }
                let committed = fs
                    .selected_committed_root_summary()
                    .expect("read pre-crash committed root");
                assert!(
                    committed.transaction_id > fs.state.generation,
                    "fixture must reproduce a transaction identity ahead of logical generation"
                );
                fs.set_auto_commit(false)
                    .expect("defer the crash-bounded namespace commit");
                fs.set_max_uncommitted_mutations(1_000_000)
                    .expect("keep the crash-bounded namespace intent uncommitted");
            }
            let ctx = RequestCtx {
                uid: 0,
                gid: 0,
                pid: 1,
                umask: 0o022,
                groups: vec![0],
            };
            let root_inode = engine.get_root_inode(&ctx).expect("lookup root inode");
            engine
                .create(root_inode, b"crash-bounded.txt", 0o644, O_WRONLY, &ctx)
                .expect("stage a replayable namespace create");
            {
                let mut fs = engine.fs.borrow_mut();
                assert!(!fs.intent_log_is_empty());
                // Suppress the best-effort Drop commit so reopening observes
                // the same durable-intent/canonical-root boundary as an
                // abruptly terminated mounted owner.
                fs.arm_mutation_reopen_fence();
            }

            drop(engine);
            let reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            let engine = VfsLocalFileSystem::new(reopened);
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/crash-bounded.txt")
                    .expect("read the crash-replayed empty inode"),
                b""
            );
            let (_, predecessor_receipt, _) = corrupt_current_pool_chunk_on_block_device(
                &engine,
                "/repair.txt",
                repair_payload,
                &devices[1],
                1,
            );

            let repaired = live_pool_admin(&engine, "repair", json!({}), true);
            assert_eq!(repaired["ok"], true, "repair response: {repaired}");
            assert_eq!(repaired["json"]["pass"], true);
            assert!(repaired["json"]["replacement_receipt_generation"]
                .as_u64()
                .is_some_and(|generation| generation > predecessor_receipt.generation));
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/older.txt")
                    .expect("read older clean inode after repair"),
                b"older committed inode"
            );
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/newer.txt")
                    .expect("read newer clean inode after repair"),
                b"newer committed inode"
            );
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/repair.txt")
                    .expect("read repaired inode"),
                repair_payload
            );
        }

        #[test]
        fn live_pool_repair_same_owner_retry_reuses_pending_generation_after_enospc_before_target_write(
        ) {
            const DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME: &str = "tidefs-dead-object-reclaim-queue";
            const RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN: u64 = 64;

            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-same-owner-enospc-retry";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-enospc.txt", 0o644)
                    .expect("create ENOSPC repair fixture");
                fs.write_file("/repair-enospc.txt", 0, payload)
                    .expect("write ENOSPC repair fixture");
                fs.sync_all().expect("commit ENOSPC repair fixture");
            }

            // Reopen before corruption so raw-store ENOSPC accounting starts at
            // the exact corruption write performed below.
            drop(engine);
            let reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            let engine = VfsLocalFileSystem::new(reopened);
            let (chunk_key, predecessor_generation, block_id) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-enospc.txt", payload);

            let comparison = {
                let fs = engine.fs.borrow();
                crate::scrub::compare_mounted_replicated_repair(
                    fs.store.pool(),
                    &fs.filesystem.state.inodes,
                    fs.object_keyspace(),
                    &block_id,
                )
                .expect("compare ENOSPC repair fixture")
            };
            let comparison_corrupt_device_index = match &comparison.classification {
                crate::scrub::MountedRepairClassification::SingleReplicaCorruption {
                    corrupt_target,
                    ..
                } => *corrupt_target,
                classification => {
                    panic!("expected single-replica corruption, got {classification:?}")
                }
            };
            assert_eq!(
                comparison_corrupt_device_index, 0,
                "the existing corruption helper must corrupt the comparison-selected raw primary"
            );

            let (corrupt_encoded_len, successor_queue_encoded_len) = {
                let fs = engine.fs.borrow();
                let raw_primary = fs.store.pool().raw_primary_store();
                let corrupt_encoded_len = u64::try_from(
                    raw_primary
                        .get(chunk_key)
                        .expect("read corrupt raw-primary target")
                        .expect("corrupt raw-primary target exists")
                        .len(),
                )
                .expect("corrupt payload length fits ENOSPC accounting");
                let queue = match raw_primary
                    .get_named(DEAD_OBJECT_RECLAIM_QUEUE_OBJECT_NAME)
                    .expect("read pre-repair dead-object queue")
                {
                    Some(bytes) => {
                        tidefs_reclaim_queue_core::DeadObjectReclaimQueue::decode(&bytes)
                            .expect("decode pre-repair dead-object queue")
                    }
                    None => tidefs_reclaim_queue_core::DeadObjectReclaimQueue::new(),
                };
                assert_eq!(
                    tidefs_reclaim_queue_core::DeadObjectReclaimQueue::new().encoded_len(),
                    44,
                    "an absent dead-object queue has the empty wire-format length"
                );
                assert!(
                    queue.all_entries().iter().all(|entry| {
                        entry.object_id != ReclaimObjectKey(*chunk_key.as_bytes())
                    }),
                    "the repair chunk must add a new target-lifetime row"
                );
                let successor_queue_encoded_len = queue
                    .encoded_len()
                    .checked_add(DeadObjectEntry::ENCODED_SIZE)
                    .expect("one-entry dead-object queue length remains representable");
                assert_eq!(DeadObjectEntry::ENCODED_SIZE, 159);
                assert_eq!(
                    successor_queue_encoded_len - queue.encoded_len(),
                    DeadObjectEntry::ENCODED_SIZE
                );
                (corrupt_encoded_len, successor_queue_encoded_len)
            };
            let enospc_after_bytes = corrupt_encoded_len
                .checked_add(RECEIPT_GENERATION_HIGH_WATER_ENCODED_LEN)
                .and_then(|bytes| {
                    bytes.checked_add(
                        u64::try_from(successor_queue_encoded_len)
                            .expect("queue length fits ENOSPC accounting"),
                    )
                })
                .expect("ENOSPC byte limit remains representable");
            let mut fault = tidefs_local_object_store::FaultInjectionConfig::off();
            fault.enospc_after_bytes = Some(enospc_after_bytes);
            engine
                .fs
                .borrow_mut()
                .store
                .pool_mut()
                .raw_primary_store_mut()
                .enable_fault_injection(fault);

            let failed = live_pool_admin(&engine, "repair", json!({}), true);
            engine
                .fs
                .borrow_mut()
                .store
                .pool_mut()
                .raw_primary_store_mut()
                .disable_fault_injection();

            assert_eq!(failed["ok"], false, "ENOSPC repair response: {failed}");
            let failed_report = &failed["json"];
            assert_eq!(failed_report["pass"], false);
            assert_eq!(failed_report["state_source"], "live-owner");
            assert_eq!(failed_report["outcome"], "incomplete");
            assert_eq!(failed_report["repair_attempted"], true);
            assert_eq!(failed_report["repair_completed"], false);
            assert_eq!(failed_report["repair_writeback"], true);
            assert_eq!(failed_report["receipt_publication"], "not-attempted");
            assert_eq!(
                failed_report["failure"]["code"],
                "writeback-revalidation-refused"
            );
            assert_eq!(
                failed_report["comparison"]["classification"],
                "SingleReplicaCorruption"
            );
            assert_eq!(
                failed_report["previous_receipt_generation"].as_u64(),
                Some(predecessor_generation)
            );
            assert_eq!(
                failed_report["corrupt_target"]["device_index"].as_u64(),
                Some(u64::from(comparison_corrupt_device_index))
            );
            let replacement_generation = failed_report["replacement_receipt_generation"]
                .as_u64()
                .expect("failed repair reports its burned replacement generation");
            assert!(replacement_generation > predecessor_generation);

            let pending = engine
                .fs
                .borrow()
                .store
                .pool()
                .pending_replicated_repair_recovery_evidence(DeviceIoClass::Data)
                .expect("inspect pending ENOSPC repair")
                .expect("ENOSPC leaves one durable pending repair");
            assert_eq!(
                pending.predecessor_receipt.generation,
                predecessor_generation
            );
            assert_eq!(
                pending.replacement_receipt.generation,
                replacement_generation
            );
            assert_eq!(
                pending.receipt_copies,
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor
            );
            assert_eq!(
                pending.target_state,
                tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::NeedsRewrite
            );
            let hashes_before_refused_mutation = complete_device_hashes(&devices);
            let mutation_error = engine
                .fs
                .borrow_mut()
                .write_file("/repair-enospc.txt", 0, b"must remain refused")
                .expect_err("pending repair must refuse unrelated mounted mutation");
            assert!(matches!(
                mutation_error,
                FileSystemError::Unsupported {
                    reason: "complete or reopen the pending replicated repair before another mounted mutation",
                    ..
                }
            ));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before_refused_mutation,
                "retry-only repair authority must refuse unrelated mutation before touching a device"
            );

            let retried = live_pool_admin(&engine, "repair", json!({}), true);
            assert_eq!(retried["ok"], true, "same-owner retry response: {retried}");
            let retried_report = &retried["json"];
            assert_eq!(retried_report["pass"], true);
            assert_eq!(retried_report["state_source"], "live-owner");
            assert_eq!(retried_report["outcome"], "completed");
            assert_eq!(retried_report["repair_attempted"], true);
            assert_eq!(retried_report["repair_completed"], true);
            assert_eq!(retried_report["repair_writeback"], true);
            assert_eq!(retried_report["receipt_publication"], "completed");
            assert_eq!(
                retried_report["previous_receipt_generation"].as_u64(),
                Some(predecessor_generation)
            );
            assert_eq!(
                retried_report["replacement_receipt_generation"].as_u64(),
                Some(replacement_generation),
                "same-owner retry must reuse the pending transition generation"
            );
            assert_eq!(retried_report["replacement_receipt_attached"], true);
            assert_eq!(retried_report["reconciled_current_manifest_count"], 1);
            assert_eq!(retried_report["authenticated_root_published"], true);
            assert_eq!(retried_report["authenticated_root_state"], "published");
            assert_eq!(retried_report["re_scrub"]["pass"], true);

            let fs = engine.fs.borrow_mut();
            assert_eq!(
                fs.read_file("/repair-enospc.txt")
                    .expect("read same-owner repaired file"),
                payload
            );
            let re_scrub = fs
                .scrub_mounted_content()
                .expect("scrub same-owner repaired content");
            assert!(re_scrub.is_clean(), "same-owner retry scrub: {re_scrub:?}");
        }

        #[test]
        fn live_pool_repair_snapshot_reconciliation_failure_requires_reopen_and_resumes_without_second_target_write(
        ) {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-reconciliation-sync-failure";
            let filesystem_generation_before = {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-reconciliation-failure.txt", 0o644)
                    .expect("create reconciliation-failure fixture");
                fs.write_file("/repair-reconciliation-failure.txt", 0, payload)
                    .expect("write reconciliation-failure fixture");
                fs.sync_all()
                    .expect("commit reconciliation-failure fixture");
                fs.create_snapshot("repair-reconciliation-failure-retained-a")
                    .expect("retain first snapshot across reconciliation failure");
                fs.create_snapshot("repair-reconciliation-failure-retained-b")
                    .expect("retain second snapshot across reconciliation failure");
                fs.stats().filesystem_generation
            };

            let (chunk_key, predecessor_generation, _) = corrupt_one_current_replicated_chunk(
                &engine,
                "/repair-reconciliation-failure.txt",
                payload,
            );
            crate::persistence::inject_next_sync_failure_after_boundary(
                crate::types::FilesystemCommitBoundary::TransactionObjectsWritten,
            );

            let failed = live_pool_admin(&engine, "repair", json!({}), true);
            assert_eq!(
                failed["ok"], false,
                "reconciliation-failure response: {failed}"
            );
            let report = &failed["json"];
            assert_eq!(report["pass"], false);
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "incomplete");
            assert_eq!(report["repair_attempted"], true);
            assert_eq!(report["repair_completed"], false);
            assert_eq!(report["repair_writeback"], true);
            assert_eq!(report["receipt_publication"], "completed");
            assert_eq!(report["failure"]["code"], "snapshot-reconciliation-failed");
            assert_eq!(
                report["comparison"]["classification"],
                "SingleReplicaCorruption"
            );
            assert_eq!(
                report["previous_receipt_generation"].as_u64(),
                Some(predecessor_generation)
            );
            let replacement_generation = report["replacement_receipt_generation"]
                .as_u64()
                .expect("failed reconciliation reports replacement generation");
            assert!(replacement_generation > predecessor_generation);
            assert_eq!(report["corrupt_target"]["device_index"], 0);
            assert_ne!(
                report["clean_source"]["device_index"],
                report["corrupt_target"]["device_index"]
            );
            assert_eq!(report["authenticated_root_published"], false);
            assert_eq!(report["authenticated_root_state"], "not-started");

            let (replacement_receipt, repaired_target_location) = {
                let fs = engine.fs.borrow();
                let replacement_receipt = fs
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read replacement receipt after reconciliation failure")
                    .expect("replacement receipt remains current");
                assert_eq!(replacement_receipt.generation, replacement_generation);
                let repaired_target_location = fs
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_key)
                    .expect("repaired target location after reconciliation failure");
                (replacement_receipt, repaired_target_location)
            };
            assert!(matches!(
                engine
                    .fs
                    .borrow()
                    .ensure_mutation_allowed("mutate after repair reconciliation failure"),
                Err(FileSystemError::MutationRequiresReopen { .. })
            ));

            drop(engine);
            let mut reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read receipt after reconciliation recovery"),
                Some(replacement_receipt),
                "reopen reconciliation must not publish a second receipt"
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_key),
                Some(repaired_target_location),
                "reopen reconciliation must not rewrite the repaired target"
            );
            assert!(
                reopened.stats().filesystem_generation > filesystem_generation_before,
                "reopen reconciliation must publish a successor authenticated root"
            );
            assert_eq!(
                reopened
                    .read_file("/repair-reconciliation-failure.txt")
                    .expect("read current content after reconciliation recovery"),
                payload
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub content after reconciliation recovery");
            assert!(
                re_scrub.is_clean(),
                "reopen reconciliation scrub: {re_scrub:?}"
            );
            assert_eq!(
                reopened
                    .list_snapshots_checked()
                    .expect("retained snapshots remain authoritative")
                    .len(),
                2
            );
            reopened
                .rollback_to_snapshot("repair-reconciliation-failure-retained-a")
                .expect("rollback first retained snapshot after reconciliation recovery");
            assert_eq!(
                reopened
                    .read_file("/repair-reconciliation-failure.txt")
                    .expect("read retained snapshot content after reconciliation recovery"),
                payload
            );
        }

        #[test]
        fn live_pool_repair_resumes_published_target_repair_without_second_target_write() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-reconciliation-resume";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-resume.txt", 0o644)
                    .expect("create repair-resume fixture");
                fs.write_file("/repair-resume.txt", 0, payload)
                    .expect("write repair-resume fixture");
                fs.sync_all().expect("commit repair-resume fixture");
                fs.create_snapshot("repair-resume-retained")
                    .expect("retain a snapshot sharing the repaired chunk");
            }

            let (chunk_key, old_generation, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-resume.txt", payload);
            let direct_repair = publish_target_only_repair(&engine, chunk_key);
            assert_eq!(
                direct_repair.previous_receipt.generation, old_generation,
                "direct repair must advance the generation embedded in the filesystem root"
            );
            let replacement_generation = direct_repair.replacement_receipt.generation;
            assert!(replacement_generation > old_generation);
            let repaired_target_location = engine
                .fs
                .borrow()
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_key)
                .expect("repaired primary target location");

            let wrong_generation = if old_generation > 1 {
                old_generation - 1
            } else {
                assert!(
                    replacement_generation > old_generation + 1,
                    "fixture needs a distinct nonzero predecessor candidate"
                );
                old_generation + 1
            };
            assert!(
                engine
                    .fs
                    .borrow()
                    .store
                    .pool()
                    .replicated_repair_reconciliation_evidence(
                        DeviceIoClass::Data,
                        chunk_key,
                        wrong_generation,
                    )
                    .expect("query wrong predecessor generation")
                    .is_none(),
                "target-only repair evidence must bind the exact embedded predecessor generation"
            );

            let resumed = live_pool_admin(&engine, "repair", json!({}), true);
            assert_eq!(resumed["ok"], true, "repair-resume response: {resumed}");
            let report = &resumed["json"];
            assert_eq!(report["pass"], true);
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "completed");
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_completed"], true);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["target_write_previously_completed"], true);
            assert_eq!(report["receipt_publication"], "previously-completed");
            assert_eq!(report["reconciliation_resumed"], true);
            assert_eq!(report["reconciliation_attempted"], true);
            assert_eq!(report["reconciliation_completed"], true);
            assert_eq!(report["reconciliation_writeback"], true);
            assert_eq!(
                report["comparison"]["classification"],
                "TargetRepairReconciliation"
            );
            assert_eq!(
                report["previous_receipt_generation"].as_u64(),
                Some(old_generation)
            );
            assert_eq!(
                report["replacement_receipt_generation"].as_u64(),
                Some(replacement_generation)
            );
            assert_eq!(report["reconciled_current_manifest_count"], 1);
            assert_eq!(report["reconciled_snapshot_manifest_count"], 1);
            assert_eq!(report["authenticated_root_published"], true);
            assert_eq!(report["re_scrub"]["pass"], true);

            {
                let fs = engine.fs.borrow();
                assert_eq!(
                    fs.store
                        .pool()
                        .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                        .expect("read receipt after resumed reconciliation"),
                    Some(direct_repair.replacement_receipt.clone()),
                    "reconciliation-only retry must not publish a second chunk receipt"
                );
                assert_eq!(
                    fs.store.pool().raw_primary_store().location_of(chunk_key),
                    Some(repaired_target_location),
                    "reconciliation-only retry must not write the repaired target again"
                );
                assert_eq!(
                    fs.read_file("/repair-resume.txt")
                        .expect("read repair-resume file"),
                    payload
                );
            }

            drop(engine);
            let mut reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .read_file("/repair-resume.txt")
                    .expect("read reconciled file after reopen"),
                payload
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub reconciled content after reopen");
            assert!(re_scrub.is_clean(), "post-reopen scrub: {re_scrub:?}");
            reopened
                .rollback_to_snapshot("repair-resume-retained")
                .expect("rollback retained snapshot after reconciliation resume");
            assert_eq!(
                reopened
                    .read_file("/repair-resume.txt")
                    .expect("read retained repaired content after rollback"),
                payload
            );
        }

        #[test]
        fn mounted_open_reconciles_published_target_repair_before_owner_publication() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-pre-owner-repair-reconciliation";
            let filesystem_generation_before = {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-open.txt", 0o644)
                    .expect("create pre-owner repair fixture");
                fs.write_file("/repair-open.txt", 0, payload)
                    .expect("write pre-owner repair fixture");
                fs.sync_all().expect("commit pre-owner repair fixture");
                fs.create_snapshot("repair-open-retained")
                    .expect("retain snapshot across pre-owner repair");
                fs.stats().filesystem_generation
            };

            let (chunk_key, old_generation, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-open.txt", payload);
            let direct_repair = publish_target_only_repair(&engine, chunk_key);
            assert_eq!(direct_repair.previous_receipt.generation, old_generation);
            let replacement_receipt = direct_repair.replacement_receipt.clone();
            let repaired_target_location = engine
                .fs
                .borrow()
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_key)
                .expect("repaired target location before owner loss");

            // Lose the only live owner after Pool receipt publication and before
            // any filesystem manifest or authenticated-root reconciliation.
            drop(engine);

            let mut reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read receipt after pre-owner reconciliation"),
                Some(replacement_receipt),
                "mounted open must reconcile without publishing a second chunk receipt"
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_key),
                Some(repaired_target_location),
                "mounted open must not repeat the repaired target write"
            );
            assert!(
                reopened.stats().filesystem_generation > filesystem_generation_before,
                "pre-owner reconciliation must publish a successor authenticated root"
            );
            assert_eq!(
                reopened
                    .read_file("/repair-open.txt")
                    .expect("read repair fixture after pre-owner reconciliation"),
                payload
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub repair fixture after pre-owner reconciliation");
            assert!(re_scrub.is_clean(), "post-reopen scrub: {re_scrub:?}");
            reopened
                .rollback_to_snapshot("repair-open-retained")
                .expect("rollback retained snapshot after pre-owner reconciliation");
            assert_eq!(
                reopened
                    .read_file("/repair-open.txt")
                    .expect("read retained snapshot after pre-owner reconciliation"),
                payload
            );
        }

        #[test]
        fn mounted_open_batch_reconciles_mixed_and_pending_repairs_before_owner_publication() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload_a = b"TideFS-batch-open-completed-repair";
            let payload_b = b"TideFS-batch-open-pending-repair";
            let (filesystem_generation_before, snapshot_id, snapshot_root_before) = {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-batch-a.txt", 0o644)
                    .expect("create completed batch-repair fixture");
                fs.write_file("/repair-batch-a.txt", 0, payload_a)
                    .expect("write completed batch-repair fixture");
                fs.create_file("/repair-batch-b.txt", 0o644)
                    .expect("create pending batch-repair fixture");
                fs.write_file("/repair-batch-b.txt", 0, payload_b)
                    .expect("write pending batch-repair fixture");
                fs.sync_all().expect("commit batch-repair fixtures");
                fs.create_snapshot("repair-batch-retained")
                    .expect("retain both batch-repair chunks");
                let snapshot_id = fs
                    .dataset_catalog()
                    .lookup("root@repair-batch-retained")
                    .expect("batch-repair snapshot catalog entry");
                let snapshot_root = fs
                    .store
                    .load_snapshot_root(snapshot_id)
                    .expect("batch-repair typed snapshot root");
                (fs.stats().filesystem_generation, snapshot_id, snapshot_root)
            };
            let (_, embedded_a_before, data_version_a_before) =
                current_file_chunk_authority(&engine.fs.borrow(), "/repair-batch-a.txt");
            let (_, embedded_b_before, data_version_b_before) =
                current_file_chunk_authority(&engine.fs.borrow(), "/repair-batch-b.txt");

            let (chunk_a, old_generation_a, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-batch-a.txt", payload_a);
            assert_eq!(old_generation_a, embedded_a_before);
            let completed_a = publish_target_only_repair(&engine, chunk_a);
            assert_eq!(completed_a.previous_receipt.generation, embedded_a_before);
            let replacement_a = completed_a.replacement_receipt.clone();
            let repaired_location_a = engine
                .fs
                .borrow()
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_a)
                .expect("completed batch-repair target location");

            let (chunk_b, old_generation_b, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-batch-b.txt", payload_b);
            assert_eq!(old_generation_b, embedded_b_before);
            let pending_b = stage_pending_target_repair_for_recovery(
                &engine,
                chunk_b,
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor,
            );
            assert_eq!(pending_b.predecessor_receipt.generation, embedded_b_before);
            assert_eq!(
                pending_b.target_state,
                tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::NeedsRewrite
            );

            // Lose the mounted owner with A durably completed and B stopped at
            // predecessor receipts. Open must authenticate that complete
            // exception set (including retained roots) before it completes B.
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);

            let reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_a)
                    .expect("read completed A receipt after batch open"),
                Some(replacement_a.clone()),
                "batch open must not publish another receipt for completed A"
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_b)
                    .expect("read completed B receipt after batch open"),
                Some(pending_b.replacement_receipt.clone()),
                "batch open must converge B to its already-reserved replacement receipt"
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_a),
                Some(repaired_location_a),
                "batch open must not repeat A's completed target write"
            );
            let repaired_location_b = reopened
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_b)
                .expect("completed B target location after batch open");

            let (observed_chunk_a, embedded_a_after, data_version_a_after) =
                current_file_chunk_authority(&reopened, "/repair-batch-a.txt");
            let (observed_chunk_b, embedded_b_after, data_version_b_after) =
                current_file_chunk_authority(&reopened, "/repair-batch-b.txt");
            assert_eq!(observed_chunk_a, chunk_a);
            assert_eq!(observed_chunk_b, chunk_b);
            assert_eq!(embedded_a_after, replacement_a.generation);
            assert_eq!(embedded_b_after, pending_b.replacement_receipt.generation);
            assert_eq!(
                data_version_a_after, data_version_b_after,
                "A and B must enter one logical successor state, not separately published repairs"
            );
            assert!(data_version_a_after > data_version_a_before);
            assert!(data_version_b_after > data_version_b_before);
            let filesystem_generation_after = reopened.stats().filesystem_generation;
            assert!(filesystem_generation_after > filesystem_generation_before);
            assert_eq!(
                reopened
                    .read_file("/repair-batch-a.txt")
                    .expect("read completed A after batch open"),
                payload_a
            );
            assert_eq!(
                reopened
                    .read_file("/repair-batch-b.txt")
                    .expect("read completed B after batch open"),
                payload_b
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub both files after batch open");
            assert!(re_scrub.is_clean(), "batch-open scrub: {re_scrub:?}");
            assert!(
                reopened
                    .store
                    .pool()
                    .pending_replicated_repair_recovery_evidence_all(DeviceIoClass::Data)
                    .expect("scan pending repairs after batch open")
                    .is_empty(),
                "batch open must complete every pending transition"
            );
            for chunk_key in [chunk_a, chunk_b] {
                let evidence = reopened
                    .store
                    .pool()
                    .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                    .expect("read converged batch-repair target evidence")
                    .expect("converged batch-repair receipt exists");
                assert!(
                    evidence.targets.iter().all(|target| matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                    )),
                    "batch open must leave both targets clean for {chunk_key}"
                );
            }

            let snapshot_root_after = reopened
                .store
                .load_snapshot_root(snapshot_id)
                .expect("reconciled batch-repair typed snapshot root");
            assert_eq!(
                snapshot_root_after.snapshot_generation,
                snapshot_root_before.snapshot_generation
            );
            assert_ne!(
                snapshot_root_after.source_reference, snapshot_root_before.source_reference,
                "retained root must advance in the same pre-owner reconciliation"
            );

            drop(reopened);
            let mut reopened_again = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened_again.stats().filesystem_generation,
                filesystem_generation_after,
                "idempotent second reopen must not publish another filesystem state"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_a)
                    .expect("read A receipt after second reopen"),
                Some(replacement_a.clone()),
                "second reopen must not publish another A receipt"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_a),
                Some(repaired_location_a),
                "second reopen must not repeat A's target write"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_b),
                Some(repaired_location_b),
                "second reopen must not repeat B's recovered target write"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_b)
                    .expect("read B receipt after second reopen"),
                Some(pending_b.replacement_receipt.clone()),
                "second reopen must not publish another B receipt"
            );
            assert_eq!(
                reopened_again
                    .read_file("/repair-batch-a.txt")
                    .expect("read A after second reopen"),
                payload_a
            );
            assert_eq!(
                reopened_again
                    .read_file("/repair-batch-b.txt")
                    .expect("read B after second reopen"),
                payload_b
            );
            let second_scrub = reopened_again
                .scrub_mounted_content()
                .expect("scrub both files after second reopen");
            assert!(
                second_scrub.is_clean(),
                "second batch scrub: {second_scrub:?}"
            );

            reopened_again
                .rollback_to_snapshot("repair-batch-retained")
                .expect("rollback reconciled batch snapshot");
            assert_eq!(
                reopened_again
                    .read_file("/repair-batch-a.txt")
                    .expect("read snapshot A after batch reconciliation"),
                payload_a
            );
            assert_eq!(
                reopened_again
                    .read_file("/repair-batch-b.txt")
                    .expect("read snapshot B after batch reconciliation"),
                payload_b
            );
            let (_, snapshot_a_generation, snapshot_a_data_version) =
                current_file_chunk_authority(&reopened_again, "/repair-batch-a.txt");
            let (_, snapshot_b_generation, snapshot_b_data_version) =
                current_file_chunk_authority(&reopened_again, "/repair-batch-b.txt");
            assert_eq!(snapshot_a_generation, replacement_a.generation);
            assert_eq!(
                snapshot_b_generation,
                pending_b.replacement_receipt.generation
            );
            assert_eq!(snapshot_a_data_version, snapshot_b_data_version);
        }

        #[test]
        fn mounted_open_batch_refuses_invalid_retained_root_before_any_repair_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload_a = b"TideFS-batch-preflight-completed-repair";
            let payload_b = b"TideFS-batch-preflight-pending-repair";
            let snapshot_id = {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-preflight-a.txt", 0o644)
                    .expect("create completed preflight fixture");
                fs.write_file("/repair-preflight-a.txt", 0, payload_a)
                    .expect("write completed preflight fixture");
                fs.create_file("/repair-preflight-b.txt", 0o644)
                    .expect("create pending preflight fixture");
                fs.write_file("/repair-preflight-b.txt", 0, payload_b)
                    .expect("write pending preflight fixture");
                fs.sync_all().expect("commit repair-preflight fixtures");
                fs.create_snapshot("repair-preflight-invalid-b-authority")
                    .expect("retain both preflight chunks");
                fs.dataset_catalog()
                    .lookup("root@repair-preflight-invalid-b-authority")
                    .expect("preflight snapshot catalog entry")
            };

            let (chunk_a, _, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-preflight-a.txt", payload_a);
            let completed_a = publish_target_only_repair(&engine, chunk_a);
            let (chunk_b, _, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-preflight-b.txt", payload_b);
            let pending_b = stage_pending_target_repair_for_recovery(
                &engine,
                chunk_b,
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor,
            );
            assert!(engine
                .fs
                .borrow()
                .store
                .pool()
                .replicated_repair_reconciliation_evidence(
                    DeviceIoClass::Data,
                    chunk_a,
                    completed_a.previous_receipt.generation,
                )
                .expect("read completed A preflight evidence")
                .is_some());
            assert_eq!(
                pending_b.target_state,
                tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::NeedsRewrite
            );

            // Keep a structurally valid typed root while severing its agreement
            // with the retained filesystem record. The complete current A+B root
            // still authenticates, so this specifically exercises the retained-
            // root preflight before either transition may advance further.
            {
                let mut fs = engine.fs.borrow_mut();
                let stored = fs
                    .store
                    .load_snapshot_root(snapshot_id)
                    .expect("load valid preflight snapshot root");
                let invalid = tidefs_pool_runtime::SnapshotRoot::new(
                    stored
                        .snapshot_generation
                        .checked_add(1)
                        .expect("preflight snapshot generation remains representable"),
                    stored.source_reference,
                )
                .expect("construct internally valid mismatched snapshot root");
                fs.store
                    .publish_dataset_root(
                        snapshot_id,
                        tidefs_pool_runtime::DatasetRootKind::Snapshot,
                        invalid.snapshot_generation,
                        &invalid.encode(),
                    )
                    .expect("publish mismatched retained-root authority");
                fs.store
                    .pool_mut()
                    .sync_all()
                    .expect("sync mismatched retained-root authority");
                fs.arm_mutation_reopen_fence();
            }
            drop(engine);
            let hashes_before = complete_device_hashes(&devices);

            let reopened = PoolDatasetOwner::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
                root.path().join("metadata"),
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
                crate::LocalFileSystemOpenConfig {
                    options: tidefs_local_object_store::StoreOptions::default(),
                    allocator_policy: crate::LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: RootAuthenticationKey::demo_key(),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: crate::RecoveryPolicy::default(),
                    block_devices: Some(&devices),
                },
            );
            assert!(matches!(
                reopened,
                Err(FileSystemError::CorruptState { reason })
                    if reason == "pending replicated repair snapshot typed root is inconsistent"
            ));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "invalid B/retained-root preflight must not complete A, rewrite B, converge either receipt, or publish any filesystem root"
            );
        }

        fn assert_mounted_open_reconciles_repeated_same_key_repair(
            receipt_copies: tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies,
            fixture_name: &str,
        ) {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let path = format!("/{fixture_name}.txt");
            let snapshot_name = format!("{fixture_name}-retained");
            let payload = format!("TideFS repeated same-key repair {fixture_name}").into_bytes();
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file(&path, 0o644)
                    .expect("create repeated same-key repair fixture");
                fs.write_file(&path, 0, &payload)
                    .expect("write repeated same-key repair fixture");
                fs.sync_all()
                    .expect("commit repeated same-key repair fixture");
                fs.create_snapshot(&snapshot_name)
                    .expect("retain repeated same-key repair chunk");
            }

            let (chunk_key, generation_0, _) =
                corrupt_one_current_replicated_chunk(&engine, &path, &payload);
            let repair_1 = publish_target_only_repair(&engine, chunk_key);
            assert_eq!(repair_1.previous_receipt.generation, generation_0);
            let generation_1 = repair_1.replacement_receipt.generation;
            assert!(generation_1 > generation_0);
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);

            // First reopen finishes G0 -> G1 all the way through the current and
            // retained filesystem roots. Only then stage a second physical
            // lifetime of the same logical key for G1 -> G2.
            let reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            let engine = VfsLocalFileSystem::new(reopened);
            let (observed_key, embedded_generation_1, _) =
                current_file_chunk_authority(&engine.fs.borrow(), &path);
            assert_eq!(observed_key, chunk_key);
            assert_eq!(embedded_generation_1, generation_1);
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read reconciled first same-key receipt"),
                Some(repair_1.replacement_receipt)
            );
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .list_snapshots_checked()
                    .expect("first same-key repair retains its snapshot authority")
                    .len(),
                1
            );
            let first_scrub = engine
                .fs
                .borrow_mut()
                .scrub_mounted_content()
                .expect("scrub fully reconciled G1 same-key authority");
            assert!(
                first_scrub.is_clean(),
                "first same-key repair scrub: {first_scrub:?}"
            );

            let (same_chunk_key, repeated_predecessor_generation, _) =
                corrupt_one_current_replicated_chunk(&engine, &path, &payload);
            assert_eq!(same_chunk_key, chunk_key);
            assert_eq!(repeated_predecessor_generation, generation_1);
            let pending_2 =
                stage_pending_target_repair_for_recovery(&engine, chunk_key, receipt_copies);
            assert_eq!(pending_2.predecessor_receipt.generation, generation_1);
            let generation_2 = pending_2.replacement_receipt.generation;
            assert!(generation_2 > generation_1);
            let target_location_at_cut = engine
                .fs
                .borrow()
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_key)
                .expect("same-key target location at second crash cut");
            match receipt_copies {
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor => {
                    assert_eq!(
                        pending_2.target_state,
                        tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::NeedsRewrite
                    );
                }
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Mixed => {
                    assert_eq!(
                        pending_2.target_state,
                        tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::Clean
                    );
                }
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Replacement => {
                    panic!("repeated same-key VFS regression expects Predecessor or Mixed")
                }
            }
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);

            let reopened = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read second same-key replacement receipt"),
                Some(pending_2.replacement_receipt.clone()),
                "G1 -> G2 must converge to the already-reserved generation"
            );
            let target_location_after_recovery = reopened
                .store
                .pool()
                .raw_primary_store()
                .location_of(chunk_key)
                .expect("same-key target location after second recovery");
            if receipt_copies
                == tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Mixed
            {
                assert_eq!(
                    target_location_after_recovery, target_location_at_cut,
                    "Mixed recovery must not repeat the already-completed G1 -> G2 target write"
                );
            } else {
                assert_ne!(
                    target_location_after_recovery, target_location_at_cut,
                    "Predecessor recovery must replace the corrupt G1 physical lifetime exactly once"
                );
            }
            let (observed_key, embedded_generation_2, _) =
                current_file_chunk_authority(&reopened, &path);
            assert_eq!(observed_key, chunk_key);
            assert_eq!(embedded_generation_2, generation_2);
            assert_eq!(
                reopened
                    .read_file(&path)
                    .expect("read twice-repaired same-key file"),
                payload
            );
            let re_scrub = reopened
                .scrub_mounted_content()
                .expect("scrub twice-repaired same-key file");
            assert!(re_scrub.is_clean(), "same-key recovery scrub: {re_scrub:?}");
            let filesystem_generation_after_recovery = reopened.stats().filesystem_generation;

            drop(reopened);
            let mut reopened_again = open_named_test_filesystem(
                &root.path().join("metadata"),
                &devices,
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
            );
            assert_eq!(
                reopened_again.stats().filesystem_generation,
                filesystem_generation_after_recovery,
                "idempotent same-key reopen must not publish another filesystem state"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .raw_primary_store()
                    .location_of(chunk_key),
                Some(target_location_after_recovery),
                "second reopen must not rewrite the G1 -> G2 target again"
            );
            assert_eq!(
                reopened_again
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read same-key receipt after idempotent reopen"),
                Some(pending_2.replacement_receipt.clone()),
                "second reopen must retain G2 without allocating G3"
            );
            assert_eq!(
                reopened_again
                    .read_file(&path)
                    .expect("read same-key file after idempotent reopen"),
                payload
            );
            let second_scrub = reopened_again
                .scrub_mounted_content()
                .expect("scrub same-key file after idempotent reopen");
            assert!(
                second_scrub.is_clean(),
                "idempotent same-key reopen scrub: {second_scrub:?}"
            );

            reopened_again
                .rollback_to_snapshot(&snapshot_name)
                .expect("rollback twice-reconciled same-key retained root");
            assert_eq!(
                reopened_again
                    .read_file(&path)
                    .expect("read same-key file from twice-reconciled snapshot"),
                payload
            );
            let (_, snapshot_generation_2, _) =
                current_file_chunk_authority(&reopened_again, &path);
            assert_eq!(snapshot_generation_2, generation_2);
        }

        #[test]
        fn mounted_open_reconciles_repeated_same_key_pending_predecessor_repair() {
            assert_mounted_open_reconciles_repeated_same_key_repair(
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor,
                "repair-same-key-predecessor",
            );
        }

        #[test]
        fn mounted_open_reconciles_repeated_same_key_mixed_receipt_repair() {
            assert_mounted_open_reconciles_repeated_same_key_repair(
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Mixed,
                "repair-same-key-mixed",
            );
        }

        #[test]
        fn live_pool_repair_read_only_reopen_refuses_pending_transition_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-read-only-pending-repair-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-read-only.txt", 0o644)
                    .expect("create read-only pending-repair fixture");
                fs.write_file("/repair-read-only.txt", 0, payload)
                    .expect("write read-only pending-repair fixture");
                fs.sync_all()
                    .expect("commit read-only pending-repair fixture");
            }

            let (chunk_key, predecessor_generation, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-read-only.txt", payload);
            let pending = stage_pending_target_repair_for_recovery(
                &engine,
                chunk_key,
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor,
            );
            let replacement_generation = pending.replacement_receipt.generation;
            assert!(replacement_generation > predecessor_generation);
            assert_eq!(
                pending.target_state,
                tidefs_local_object_store::pool::PendingReplicatedRepairTargetState::NeedsRewrite
            );

            // Model owner loss at the durable post-reclaim-intent boundary. The
            // fence only suppresses Drop's best-effort final commit; it is not
            // persisted and cannot affect the subsequent read-only open.
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);
            let hashes_before = complete_device_hashes(&devices);

            let reopened = PoolDatasetOwner::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
                root.path().join("metadata"),
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
                crate::LocalFileSystemOpenConfig {
                    options: tidefs_local_object_store::StoreOptions::default(),
                    allocator_policy: crate::LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: RootAuthenticationKey::demo_key(),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: crate::RecoveryPolicy::ReadOnly,
                    block_devices: Some(&devices),
                },
            );

            assert!(matches!(
                reopened,
                Err(FileSystemError::CorruptState { reason })
                    if reason == "read-only open refuses an unfinished replicated repair transition"
            ));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "read-only pending-repair refusal must leave complete device images unchanged"
            );
        }

        #[test]
        fn mounted_open_refuses_pending_repair_before_mutating_with_durable_intent() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-pending-repair-intent-log-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-intent-refusal.txt", 0o644)
                    .expect("create intent-log refusal fixture");
                fs.write_file("/repair-intent-refusal.txt", 0, payload)
                    .expect("write intent-log refusal fixture");
                fs.sync_all().expect("commit intent-log refusal fixture");
            }

            let (chunk_key, _, _) = corrupt_one_current_replicated_chunk(
                &engine,
                "/repair-intent-refusal.txt",
                payload,
            );
            stage_pending_target_repair_for_recovery(
                &engine,
                chunk_key,
                tidefs_local_object_store::pool::PendingReplicatedRepairReceiptCopies::Predecessor,
            );
            {
                let mut fs = engine.fs.borrow_mut();
                let mut updated_root = fs.stat("/").expect("stat root for durable intent");
                updated_root.mode ^= 0o001;
                assert_eq!(
                    fs.metadata_setattr_intent(&updated_root)
                        .expect("append unrelated durable metadata intent"),
                    IntentLogReplyState::IntentDurable,
                );
                assert!(!fs.intent_log_is_empty());
                fs.arm_mutation_reopen_fence();
            }
            drop(engine);
            let hashes_before = complete_device_hashes(&devices);

            let reopened = PoolDatasetOwner::open_named_pool_filesystem_dataset_with_allocator_policy_and_root_authentication_key(
                root.path().join("metadata"),
                "tank",
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 },
                "root",
                crate::LocalFileSystemOpenConfig {
                    options: tidefs_local_object_store::StoreOptions::default(),
                    allocator_policy: crate::LocalStorageAllocatorPolicy::default(),
                    root_authentication_key: RootAuthenticationKey::demo_key(),
                    encryption: None,
                    compression: None,
                    log_device_device_path: None,
                    recovery_policy: crate::RecoveryPolicy::default(),
                    block_devices: Some(&devices),
                },
            );

            assert!(matches!(
                reopened,
                Err(FileSystemError::CorruptState { reason })
                    if reason == "replicated repair recovery requires an empty dataset intent log before writeback"
            ));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "intent-log refusal must happen before pending-repair device mutation"
            );
        }

        #[test]
        fn live_pool_repair_reconciliation_human_report_preserves_subject_identity() {
            let (engine, root, _devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-reconciliation-human-report";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-resume-human.txt", 0o644)
                    .expect("create human reconciliation fixture");
                fs.write_file("/repair-resume-human.txt", 0, payload)
                    .expect("write human reconciliation fixture");
                fs.sync_all().expect("commit human reconciliation fixture");
                fs.create_snapshot("repair-resume-human-retained")
                    .expect("retain human reconciliation snapshot");
            }

            let (chunk_key, old_generation, expected_block_id) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-resume-human.txt", payload);
            let direct_repair = publish_target_only_repair(&engine, chunk_key);
            let expected_source = direct_repair
                .replacement_receipt
                .targets
                .iter()
                .find(|target| target.device_index == direct_repair.source_device_index)
                .map(mounted_repair_receipt_target_identity_text)
                .expect("replacement receipt retains the clean source identity");
            let expected_target = direct_repair
                .replacement_receipt
                .targets
                .iter()
                .find(|target| target.device_index == direct_repair.repaired_device_index)
                .map(mounted_repair_receipt_target_identity_text)
                .expect("replacement receipt retains the repaired target identity");
            let expected_object = format!("object:                 {chunk_key}");
            assert_eq!(chunk_key.to_string().len(), 64);
            let (expected_kind, expected_chunk_index) =
                mounted_scrub_block_kind(expected_block_id.kind);
            let expected_subject = format!(
                "subject:                inode={} data-version={} kind={} chunk={}",
                expected_block_id.inode_id,
                expected_block_id.data_version,
                expected_kind,
                expected_chunk_index
                    .map_or_else(|| "none".to_string(), |chunk_index| chunk_index.to_string()),
            );
            let expected_receipt_generation = format!(
                "receipt generation:     {} -> {}",
                old_generation, direct_repair.replacement_receipt.generation,
            );

            let resumed = live_pool_admin(&engine, "repair", json!({}), false);

            assert_eq!(
                resumed["ok"], true,
                "human repair-resume response: {resumed}"
            );
            assert!(
                resumed["text"].as_str().is_some_and(|text| {
                    text.contains("pool repair: tank")
                        && text.contains("outcome:                completed")
                        && text
                            .contains("target write:           previously completed (not repeated)")
                        && text.contains("reconciliation:         resumed and completed")
                        && text.contains("comparison:             TargetRepairReconciliation")
                        && text.contains(&expected_subject)
                        && text.contains(&expected_object)
                        && text.contains(&format!("clean source:           {expected_source}"))
                        && text.contains(&format!("repaired target:        {expected_target}"))
                        && text.contains(&expected_receipt_generation)
                        && text.contains("authenticated root:     published")
                        && text.contains("re-scrub:               clean")
                }),
                "human reconciliation report must retain its exact repair subject: {resumed}"
            );
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/repair-resume-human.txt")
                    .expect("read human reconciliation repaired file"),
                payload
            );
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_ordinary_same_payload_rewrite_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-ordinary-rewrite-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-ordinary-rewrite.txt", 0o644)
                    .expect("create ordinary-rewrite fixture");
                fs.write_file("/repair-ordinary-rewrite.txt", 0, payload)
                    .expect("write ordinary-rewrite fixture");
                fs.sync_all().expect("commit ordinary-rewrite fixture");
            }

            let (chunk_key, encoded_chunk, old_generation) = {
                let fs = engine.fs.borrow();
                let record = fs
                    .stat("/repair-ordinary-rewrite.txt")
                    .expect("stat ordinary-rewrite fixture");
                let keyspace = fs.object_keyspace();
                let manifest_key = keyspace.content(record.inode_id, record.data_version);
                let (manifest_bytes, _) = fs
                    .store
                    .pool()
                    .get_with_current_receipt(DeviceIoClass::Data, manifest_key)
                    .expect("read ordinary-rewrite manifest")
                    .expect("ordinary-rewrite manifest exists");
                let manifest = crate::encoding::decode_content_manifest(&manifest_bytes)
                    .expect("decode ordinary-rewrite manifest");
                let chunk = manifest
                    .chunks
                    .iter()
                    .find(|chunk| !chunk.is_hole())
                    .expect("ordinary-rewrite content chunk");
                let chunk_key =
                    keyspace.content_chunk(record.inode_id, chunk.data_version, chunk.chunk_index);
                let (encoded_chunk, receipt) = fs
                    .store
                    .pool()
                    .get_with_current_receipt(DeviceIoClass::Data, chunk_key)
                    .expect("read ordinary-rewrite chunk")
                    .expect("ordinary-rewrite chunk exists");
                (chunk_key, encoded_chunk, receipt.generation)
            };
            let replacement_receipt = {
                let mut fs = engine.fs.borrow_mut();
                let (_, receipt) = fs
                    .store
                    .pool_mut()
                    .put_with_receipt(DeviceIoClass::Data, chunk_key, &encoded_chunk)
                    .expect("rewrite the exact same payload through ordinary Pool authority");
                fs.store
                    .pool_mut()
                    .sync_all()
                    .expect("sync ordinary same-payload rewrite");
                receipt
            };
            assert!(replacement_receipt.generation > old_generation);
            assert!(
                engine
                    .fs
                    .borrow()
                    .store
                    .pool()
                    .replicated_repair_reconciliation_evidence(
                        DeviceIoClass::Data,
                        chunk_key,
                        old_generation,
                    )
                    .expect("query ordinary-rewrite repair evidence")
                    .is_none(),
                "ordinary two-target rewrite must not impersonate target-only repair evidence"
            );
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(
                refused["ok"], false,
                "ordinary-rewrite repair response: {refused}"
            );
            let report = &refused["json"];
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "refused");
            assert_eq!(
                report["refusal"]["code"],
                "stale-content-receipt-generation"
            );
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Data, chunk_key)
                    .expect("read ordinary-rewrite receipt after refusal"),
                Some(replacement_receipt),
                "refusal must retain the existing ordinary rewrite authority"
            );
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "ordinary-rewrite refusal must leave complete device images unchanged"
            );
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_missing_current_target_evidence_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"missing-current-repair-target-evidence";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-missing-target.txt", 0o644)
                    .expect("create missing-target repair fixture");
                fs.write_file("/repair-missing-target.txt", 0, payload)
                    .expect("write missing-target repair fixture");
                fs.sync_all().expect("commit missing-target repair fixture");
            }
            let (chunk_key, _, _) = corrupt_one_current_replicated_chunk(
                &engine,
                "/repair-missing-target.txt",
                payload,
            );
            {
                let mut fs = engine.fs.borrow_mut();
                assert!(
                    fs.store
                        .pool_mut()
                        .raw_primary_store_mut()
                        .delete(chunk_key)
                        .expect("remove exactly one current receipt target"),
                    "missing-target fixture must remove the primary target payload"
                );
                fs.store
                    .pool_mut()
                    .sync_all()
                    .expect("sync missing-target fixture");
            }
            let evidence = engine
                .fs
                .borrow()
                .store
                .pool()
                .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                .expect("read missing-target comparison evidence")
                .expect("missing-target receipt remains current");
            assert_eq!(
                evidence
                    .targets
                    .iter()
                    .filter(|target| matches!(
                        &target.outcome,
                        tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Missing
                    ))
                    .count(),
                1,
                "fixture must omit exactly one current target"
            );
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(
                refused["ok"], false,
                "missing-target repair response: {refused}"
            );
            let report = &refused["json"];
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "refused");
            assert_eq!(report["refusal"]["code"], "comparison-refused-writeback");
            assert_eq!(
                report["comparison"]["classification"],
                "IncompleteComparison"
            );
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert!(report["comparison"]["targets"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|target| {
                    target["receipt_payload_outcome"]["kind"] == "missing"
                        && target["mounted_checksum_outcome"]["kind"] == "missing"
                })));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "missing-target refusal must leave complete device images unchanged"
            );
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_wrong_width_pool_policy_without_device_mutation() {
            let (engine, root, devices) = temp_fs_with_policy_and_block_devices(
                3,
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 3 },
            );
            let payload = b"wrong-width-repair-policy-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-wrong-width.txt", 0o644)
                    .expect("create wrong-width repair fixture");
                fs.write_file("/repair-wrong-width.txt", 0, payload)
                    .expect("write wrong-width repair fixture");
                fs.sync_all().expect("commit wrong-width repair fixture");
            }
            let (_, receipt, _) =
                corrupt_current_pool_chunk_on_primary(&engine, "/repair-wrong-width.txt", payload);
            assert_eq!(
                receipt.policy,
                tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 3 }
            );
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(
                refused["ok"], false,
                "wrong-width repair response: {refused}"
            );
            let report = &refused["json"];
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "refused");
            assert_eq!(report["refusal"]["code"], "receipt-evidence-refused");
            assert!(report["refusal"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("exact two-copy current pool policy")));
            assert!(report["comparison"].is_null());
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "wrong-width policy refusal must leave complete device images unchanged"
            );
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_clean_state_refuses_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/clean.txt", 0o644)
                    .expect("create clean repair fixture");
                fs.write_file("/clean.txt", 0, b"clean-repair-refusal-fixture")
                    .expect("write clean repair fixture");
                fs.sync_all().expect("commit clean repair fixture");
            }
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(refused["ok"], false, "clean repair response: {refused}");
            let report = &refused["json"];
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "refused");
            assert_eq!(report["refusal"]["code"], "no-repair-needed");
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["initial_scrub"]["pass"], true);
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "clean repair refusal must not mutate complete device images"
            );
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_corrupt_canonical_root_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"corrupt-canonical-root-repair-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-corrupt-root.txt", 0o644)
                    .expect("create corrupt-root repair fixture");
                fs.write_file("/repair-corrupt-root.txt", 0, payload)
                    .expect("write corrupt-root repair fixture");
                fs.sync_all().expect("commit corrupt-root repair fixture");
            }
            let (chunk_key, _, _) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-corrupt-root.txt", payload);
            let (expected_source, expected_target) = {
                let fs = engine.fs.borrow();
                let evidence = fs
                    .store
                    .pool()
                    .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                    .expect("read corrupt-root repair identities")
                    .expect("corrupt-root repair receipt");
                let source = evidence
                    .targets
                    .iter()
                    .find(|target| {
                        matches!(
                            &target.outcome,
                            tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                        )
                    })
                    .map(|target| mounted_repair_receipt_target_identity_text(&target.target))
                    .expect("corrupt-root repair has a clean source");
                let target = evidence
                    .targets
                    .iter()
                    .find(|target| {
                        matches!(
                            &target.outcome,
                            tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt { .. }
                        )
                    })
                    .map(|target| mounted_repair_receipt_target_identity_text(&target.target))
                    .expect("corrupt-root repair has one corrupt target");
                (source, target)
            };
            {
                let mut fs = engine.fs.borrow_mut();
                let dataset_id = DatasetId::from_bytes(fs.mounted_dataset_id());
                let generation = fs.stats().filesystem_generation.saturating_add(1);
                fs.store
                    .publish_dataset_root(
                        dataset_id,
                        tidefs_pool_runtime::DatasetRootKind::Filesystem,
                        generation,
                        b"invalid mounted canonical root",
                    )
                    .expect("publish invalid mounted canonical root");
                fs.store
                    .pool_mut()
                    .sync_all()
                    .expect("sync invalid mounted canonical root fixture");
            }
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(
                refused["ok"], false,
                "corrupt-root repair response: {refused}"
            );
            let report = &refused["json"];
            assert_eq!(report["state_source"], "live-owner");
            assert_eq!(report["outcome"], "refused");
            assert_eq!(
                report["comparison"]["classification"],
                "SingleReplicaCorruption"
            );
            assert_eq!(
                report["refusal"]["code"],
                "filesystem-root-preflight-failed"
            );
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert_eq!(report["authenticated_root_published"], false);
            assert_eq!(report["authenticated_root_state"], "not-started");
            let refused_human = live_pool_admin(&engine, "repair", json!({}), false);
            assert_eq!(
                refused_human["ok"], false,
                "human corrupt-root refusal: {refused_human}"
            );
            assert!(refused_human["text"].as_str().is_some_and(|text| {
                text.contains(&format!("object:                 {chunk_key}"))
                    && text.contains(&format!("clean source:           {expected_source}"))
                    && text.contains(&format!("corrupt target:         {expected_target}"))
                    && text.contains("refusal:                filesystem-root-preflight-failed:")
            }));
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "corrupt canonical-root refusal must leave complete device images unchanged"
            );
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_dirty_mounted_state_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"dirty-mounted-state-repair-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.set_auto_commit(false)
                    .expect("disable automatic commit for dirty-state fixture");
                fs.create_file("/repair-dirty.txt", 0o644)
                    .expect("create repair fixture");
                fs.write_file("/repair-dirty.txt", 0, payload)
                    .expect("write repair fixture");
                fs.sync_all().expect("commit repair fixture");
            }
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/uncommitted.txt", 0o644)
                    .expect("create unrelated uncommitted state");
                assert!(fs.is_state_dirty(), "fixture must remain dirty");
            }
            corrupt_one_current_replicated_chunk(&engine, "/repair-dirty.txt", payload);
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(refused["ok"], false, "dirty repair response: {refused}");
            let report = &refused["json"];
            assert_eq!(report["outcome"], "refused");
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert_eq!(report["refusal"]["code"], "mounted-state-not-quiescent");
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "dirty-state refusal must not commit or otherwise mutate device images"
            );
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_refuses_fenced_owner_without_device_mutation() {
            let (engine, root, devices) = temp_replicated_fs_with_block_devices();
            let payload = b"fenced-mounted-owner-repair-refusal";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-fenced.txt", 0o644)
                    .expect("create repair fixture");
                fs.write_file("/repair-fenced.txt", 0, payload)
                    .expect("write repair fixture");
                fs.sync_all().expect("commit repair fixture");
            }
            corrupt_one_current_replicated_chunk(&engine, "/repair-fenced.txt", payload);
            engine.fs.borrow_mut().arm_mutation_reopen_fence();
            let hashes_before = complete_device_hashes(&devices);

            let refused = live_pool_admin(&engine, "repair", json!({}), true);

            assert_eq!(refused["ok"], false, "fenced repair response: {refused}");
            let report = &refused["json"];
            assert_eq!(report["outcome"], "refused");
            assert_eq!(report["repair_attempted"], false);
            assert_eq!(report["repair_writeback"], false);
            assert_eq!(report["receipt_publication"], "not-attempted");
            assert_eq!(report["refusal"]["code"], "mutation-authority-refused");
            assert_eq!(
                complete_device_hashes(&devices),
                hashes_before,
                "fenced-owner refusal must leave complete device images unchanged"
            );
            drop(engine);
            drop(root);
        }

        #[test]
        fn live_pool_repair_human_report_preserves_repair_authority() {
            let (engine, root, _devices) = temp_replicated_fs_with_block_devices();
            let payload = b"TideFS-live-owner-repair-human-report-fixture";
            {
                let mut fs = engine.fs.borrow_mut();
                fs.create_file("/repair-human.txt", 0o644)
                    .expect("create human repair fixture");
                fs.write_file("/repair-human.txt", 0, payload)
                    .expect("write human repair fixture");
                fs.sync_all().expect("commit human repair fixture");
            }
            let (chunk_key, _, expected_block_id) =
                corrupt_one_current_replicated_chunk(&engine, "/repair-human.txt", payload);
            let (expected_source, expected_target) = {
                let fs = engine.fs.borrow();
                let evidence = fs
                    .store
                    .pool()
                    .replicated_receipt_evidence(DeviceIoClass::Data, chunk_key)
                    .expect("read human repair identities")
                    .expect("human repair receipt");
                let source = evidence
                    .targets
                    .iter()
                    .find(|target| {
                        matches!(
                            &target.outcome,
                            tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean
                        )
                    })
                    .map(|target| mounted_repair_receipt_target_identity_text(&target.target))
                    .expect("human repair has a clean source");
                let target = evidence
                    .targets
                    .iter()
                    .find(|target| {
                        matches!(
                            &target.outcome,
                            tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt { .. }
                        )
                    })
                    .map(|target| mounted_repair_receipt_target_identity_text(&target.target))
                    .expect("human repair has one corrupt target");
                (source, target)
            };
            let expected_object = format!("object:                 {chunk_key}");
            assert_eq!(chunk_key.to_string().len(), 64);

            let (expected_kind, expected_chunk_index) =
                mounted_scrub_block_kind(expected_block_id.kind);
            let expected_subject = format!(
                "subject:                inode={} data-version={} kind={} chunk={}",
                expected_block_id.inode_id,
                expected_block_id.data_version,
                expected_kind,
                expected_chunk_index
                    .map_or_else(|| "none".to_string(), |chunk_index| chunk_index.to_string()),
            );

            let repaired = live_pool_admin(&engine, "repair", json!({}), false);

            assert_eq!(repaired["ok"], true, "human repair response: {repaired}");
            assert!(repaired["text"].as_str().is_some_and(|text| {
                text.contains("pool repair: tank")
                    && text.contains("source:                 live owner")
                    && text.contains("outcome:                completed")
                    && text.contains("comparison:             SingleReplicaCorruption")
                    && text.contains(&expected_subject)
                    && text.contains(&expected_object)
                    && text.contains(&format!("clean source:           {expected_source}"))
                    && text.contains(&format!("repaired target:        {expected_target}"))
                    && text.contains("receipt generation:")
                    && text.contains("authenticated root:     published")
                    && text.contains("re-scrub:               clean")
            }));
            assert_eq!(
                engine
                    .fs
                    .borrow()
                    .read_file("/repair-human.txt")
                    .expect("read human-report repaired file"),
                payload
            );
            drop(engine);
            drop(root);
        }
    }
}

fn mounted_repair_scrub_summary(report: &crate::scrub::ScrubReport) -> Value {
    let findings = report
        .violations
        .iter()
        .map(|violation| mounted_scrub_finding_json(report, violation))
        .collect::<Vec<_>>();
    json!({
        "pass": report.is_clean() && report.blocks_no_checksum == 0,
        "blocks_scanned": report.blocks_scanned,
        "blocks_clean": report.blocks_clean,
        "blocks_corrupt": report.blocks_corrupt,
        "blocks_unreadable": report.blocks_unreadable,
        "blocks_no_checksum": report.blocks_no_checksum,
        "finding_count": report.violations.len(),
        "findings": findings,
    })
}

fn mounted_repair_classification_name(
    classification: &crate::scrub::MountedRepairClassification,
) -> &'static str {
    match classification {
        crate::scrub::MountedRepairClassification::CleanAgreement => "CleanAgreement",
        crate::scrub::MountedRepairClassification::SingleReplicaCorruption { .. } => {
            "SingleReplicaCorruption"
        }
        crate::scrub::MountedRepairClassification::IncompleteComparison { .. } => {
            "IncompleteComparison"
        }
        crate::scrub::MountedRepairClassification::ReceiptTargetDisagreement => {
            "ReceiptTargetDisagreement"
        }
        crate::scrub::MountedRepairClassification::ChecksumAuthorityDisagreement => {
            "ChecksumAuthorityDisagreement"
        }
        crate::scrub::MountedRepairClassification::MissingChecksumEvidence { .. } => {
            "MissingChecksumEvidence"
        }
    }
}

fn mounted_repair_checksum_token(checksum: IntegrityDigest64) -> String {
    mounted_scrub_digest(checksum)
}

fn mounted_repair_read_outcome_json(
    outcome: &crate::scrub::MountedRepairTargetChecksumOutcome,
) -> Value {
    match outcome {
        crate::scrub::MountedRepairTargetChecksumOutcome::Clean { checksum } => json!({
            "kind": "clean",
            "checksum_token": mounted_repair_checksum_token(*checksum),
        }),
        crate::scrub::MountedRepairTargetChecksumOutcome::Mismatch { expected, actual } => json!({
            "kind": "mismatch",
            "expected_checksum_token": mounted_repair_checksum_token(*expected),
            "actual_checksum_token": mounted_repair_checksum_token(*actual),
        }),
        crate::scrub::MountedRepairTargetChecksumOutcome::ReceiptMismatch { checksum } => json!({
            "kind": "receipt-mismatch",
            "checksum_token": mounted_repair_checksum_token(*checksum),
        }),
        crate::scrub::MountedRepairTargetChecksumOutcome::Missing => {
            json!({ "kind": "missing" })
        }
        crate::scrub::MountedRepairTargetChecksumOutcome::Unreadable => {
            json!({ "kind": "unreadable" })
        }
        crate::scrub::MountedRepairTargetChecksumOutcome::NoChecksum => {
            json!({ "kind": "no-checksum" })
        }
    }
}

fn mounted_repair_target_identity_json(
    comparison: &crate::scrub::MountedReplicatedRepairComparison,
    device_index: u32,
) -> Value {
    comparison
        .receipt_evidence
        .targets
        .iter()
        .find(|target| target.target.device_index == device_index)
        .map_or(Value::Null, |target| {
            mounted_repair_receipt_target_identity_json(&target.target)
        })
}

fn mounted_repair_receipt_target_identity_json(
    target: &tidefs_local_object_store::PlacementReceiptTarget,
) -> Value {
    json!({
        "device_index": target.device_index,
        "device_guid": live_admin_hex_encode(&target.device_guid),
        "shard_index": target.shard_index,
    })
}

fn mounted_repair_receipt_target_identity_text(
    target: &tidefs_local_object_store::PlacementReceiptTarget,
) -> String {
    format!(
        "device {} guid={} shard={}",
        target.device_index,
        live_admin_hex_encode(&target.device_guid),
        target.shard_index,
    )
}

fn mounted_repair_target_identity_text(
    comparison: &crate::scrub::MountedReplicatedRepairComparison,
    device_index: u32,
) -> String {
    comparison
        .receipt_evidence
        .targets
        .iter()
        .find(|target| target.target.device_index == device_index)
        .map_or_else(
            || format!("device {device_index} guid=not-established shard=not-established"),
            |target| mounted_repair_receipt_target_identity_text(&target.target),
        )
}

fn mounted_repair_comparison_json(
    comparison: &crate::scrub::MountedReplicatedRepairComparison,
) -> Value {
    let targets = comparison
        .receipt_evidence
        .targets
        .iter()
        .map(|target| {
            let mounted = comparison
                .target_outcomes
                .iter()
                .find(|outcome| outcome.device_index == target.target.device_index);
            let physical = match &target.outcome {
                tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Clean => {
                    json!({ "kind": "clean" })
                }
                tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Corrupt {
                    actual_len,
                    actual_digest,
                } => json!({
                    "kind": "corrupt",
                    "actual_len": actual_len,
                    "actual_digest": live_admin_hex_encode(actual_digest),
                }),
                tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Missing => {
                    json!({ "kind": "missing" })
                }
                tidefs_local_object_store::pool::ReplicatedTargetReadOutcome::Unreadable => {
                    json!({ "kind": "unreadable" })
                }
            };
            json!({
                "device_index": target.target.device_index,
                "device_guid": live_admin_hex_encode(&target.target.device_guid),
                "shard_index": target.target.shard_index,
                "receipt_payload_outcome": physical,
                "mounted_checksum_outcome": mounted
                    .map(|outcome| mounted_repair_read_outcome_json(&outcome.outcome)),
            })
        })
        .collect::<Vec<_>>();
    let (kind, chunk_index) = mounted_scrub_block_kind(comparison.block_id.kind);
    json!({
        "classification": mounted_repair_classification_name(&comparison.classification),
        "subject": {
            "inode_id": comparison.block_id.inode_id,
            "data_version": comparison.block_id.data_version,
            "kind": kind,
            "chunk_index": chunk_index,
        },
        "object_key": live_admin_hex_encode(comparison.object_key.as_bytes()),
        "checksum_layer": mounted_scrub_checksum_layer(comparison.checksum_layer),
        "receipt_epoch": comparison.receipt_evidence.receipt.epoch,
        "receipt_generation": comparison.receipt_evidence.receipt.generation,
        "redundancy_policy": "replicated-2",
        "target_count": comparison.target_outcomes.len(),
        "targets": targets,
    })
}

#[derive(Clone, Copy)]
struct LivePoolRepairProgress<'a> {
    attempted: bool,
    writeback_started: bool,
    receipt_publication: &'static str,
    initial_scrub: Option<&'a crate::scrub::ScrubReport>,
    comparison: Option<&'a crate::scrub::MountedReplicatedRepairComparison>,
    previous_receipt_generation: Option<u64>,
    replacement_receipt_generation: Option<u64>,
    source_device_index: Option<u32>,
    corrupt_device_index: Option<u32>,
    authenticated_root_state: &'static str,
    re_scrub: Option<&'a crate::scrub::ScrubReport>,
}

impl Default for LivePoolRepairProgress<'_> {
    fn default() -> Self {
        Self {
            attempted: false,
            writeback_started: false,
            receipt_publication: "not-attempted",
            initial_scrub: None,
            comparison: None,
            previous_receipt_generation: None,
            replacement_receipt_generation: None,
            source_device_index: None,
            corrupt_device_index: None,
            authenticated_root_state: "not-started",
            re_scrub: None,
        }
    }
}

fn live_pool_repair_failure(
    pool: &str,
    wants_json: bool,
    code: &'static str,
    message: impl Into<String>,
    progress: LivePoolRepairProgress<'_>,
) -> LivePoolAdminResponse {
    let message = message.into();
    let outcome = if progress.writeback_started {
        "incomplete"
    } else {
        "refused"
    };
    let previous_receipt_generation = progress.previous_receipt_generation.or_else(|| {
        progress
            .comparison
            .map(|comparison| comparison.receipt_evidence.receipt.generation)
    });
    let source = progress
        .comparison
        .zip(progress.source_device_index)
        .map_or(Value::Null, |(comparison, device_index)| {
            mounted_repair_target_identity_json(comparison, device_index)
        });
    let corrupt = progress
        .comparison
        .zip(progress.corrupt_device_index)
        .map_or(Value::Null, |(comparison, device_index)| {
            mounted_repair_target_identity_json(comparison, device_index)
        });
    if wants_json {
        let detail = json!({
            "code": code,
            "message": message,
        });
        return live_admin_report_json(
            1,
            json!({
                "pool": pool,
                "pass": false,
                "state_source": "live-owner",
                "owner_state": "mounted PoolDatasetOwner",
                "outcome": outcome,
                "repair_attempted": progress.attempted,
                "repair_completed": false,
                "repair_writeback": progress.writeback_started,
                "receipt_publication": progress.receipt_publication,
                "refusal": (!progress.writeback_started).then_some(detail.clone()),
                "failure": progress.writeback_started.then_some(detail),
                "initial_scrub": progress.initial_scrub.map(mounted_repair_scrub_summary),
                "comparison": progress.comparison.map(mounted_repair_comparison_json),
                "previous_receipt_generation": previous_receipt_generation,
                "replacement_receipt_generation": progress.replacement_receipt_generation,
                "clean_source": source,
                "corrupt_target": corrupt,
                "authenticated_root_published": progress.authenticated_root_state == "published",
                "authenticated_root_state": progress.authenticated_root_state,
                "re_scrub": progress.re_scrub.map(mounted_repair_scrub_summary),
            }),
        );
    }
    let classification = progress.comparison.map_or("not established", |comparison| {
        mounted_repair_classification_name(&comparison.classification)
    });
    let subject = progress.comparison.map_or_else(
        || "not established".to_string(),
        |comparison| {
            let (kind, chunk_index) = mounted_scrub_block_kind(comparison.block_id.kind);
            format!(
                "inode={} data-version={} kind={} chunk={}",
                comparison.block_id.inode_id,
                comparison.block_id.data_version,
                kind,
                chunk_index.map_or_else(|| "none".to_string(), |index| index.to_string())
            )
        },
    );
    let object = progress.comparison.map_or_else(
        || "not established".to_string(),
        |comparison| comparison.object_key.to_string(),
    );
    let source = progress
        .comparison
        .zip(progress.source_device_index)
        .map_or_else(
            || "not established".to_string(),
            |(comparison, index)| mounted_repair_target_identity_text(comparison, index),
        );
    let corrupt = progress
        .comparison
        .zip(progress.corrupt_device_index)
        .map_or_else(
            || "not established".to_string(),
            |(comparison, index)| mounted_repair_target_identity_text(comparison, index),
        );
    let previous_generation = previous_receipt_generation
        .map_or_else(|| "not established".to_string(), |value| value.to_string());
    let replacement_generation = progress
        .replacement_receipt_generation
        .map_or_else(|| "not established".to_string(), |value| value.to_string());
    let re_scrub = progress.re_scrub.map_or("not run", |report| {
        if report.is_clean() && report.blocks_no_checksum == 0 {
            "clean"
        } else {
            "not clean"
        }
    });
    let failure_label = if progress.writeback_started {
        "failure"
    } else {
        "refusal"
    };
    live_admin_report_text(
        1,
        format!(
            "pool repair: {pool}\n  source:                 live owner (mounted PoolDatasetOwner)\n  outcome:                {outcome}\n  repair attempt:         {}\n  writeback:              {}\n  receipt publication:    {}\n  comparison:             {classification}\n  subject:                {subject}\n  object:                 {object}\n  clean source:           {source}\n  corrupt target:         {corrupt}\n  receipt generation:     {previous_generation} -> {replacement_generation}\n  authenticated root:     {}\n  re-scrub:               {re_scrub}\n  {failure_label}:                {code}: {message}",
            if progress.attempted { "yes" } else { "no" },
            if progress.writeback_started { "started" } else { "none" },
            progress.receipt_publication,
            progress.authenticated_root_state,
        ),
    )
}

fn live_pool_repair_refusal(
    pool: &str,
    wants_json: bool,
    code: &'static str,
    message: impl Into<String>,
    attempted: bool,
    writeback_started: bool,
    scrub: Option<&crate::scrub::ScrubReport>,
    comparison: Option<&crate::scrub::MountedReplicatedRepairComparison>,
    replacement_receipt_generation: Option<u64>,
) -> LivePoolAdminResponse {
    live_pool_repair_failure(
        pool,
        wants_json,
        code,
        message,
        LivePoolRepairProgress {
            attempted,
            writeback_started,
            receipt_publication: if replacement_receipt_generation.is_some() {
                "completed"
            } else {
                "not-attempted"
            },
            initial_scrub: scrub,
            comparison,
            previous_receipt_generation: comparison
                .map(|comparison| comparison.receipt_evidence.receipt.generation),
            replacement_receipt_generation,
            authenticated_root_state: if writeback_started {
                "incomplete"
            } else {
                "not-started"
            },
            ..LivePoolRepairProgress::default()
        },
    )
}

#[derive(Clone, Copy)]
struct LivePoolRepairReconciliationProgress<'a> {
    initial_scrub: &'a crate::scrub::ScrubReport,
    block_id: &'a crate::types::ScrubBlockId,
    object_key: ObjectKey,
    evidence: &'a tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
    reconciliation_started: bool,
    authenticated_root_state: &'static str,
    re_scrub: Option<&'a crate::scrub::ScrubReport>,
}

struct MountedRepairReconciliationOutcome {
    evidence: tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
    reconciled_current_manifests: u64,
    reconciled_snapshot_manifests: u64,
    filesystem_generation_before: u64,
    filesystem_generation_after: u64,
    re_scrub: crate::scrub::ScrubReport,
}

struct MountedRepairReconciliationFailure {
    code: &'static str,
    message: String,
    evidence: tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
    reconciliation_started: bool,
    authenticated_root_state: &'static str,
    re_scrub: Option<crate::scrub::ScrubReport>,
}

impl MountedRepairReconciliationFailure {
    fn new(
        code: &'static str,
        message: impl Into<String>,
        evidence: tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
        reconciliation_started: bool,
        authenticated_root_state: &'static str,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            evidence,
            reconciliation_started,
            authenticated_root_state,
            re_scrub: None,
        }
    }

    fn with_re_scrub(mut self, re_scrub: crate::scrub::ScrubReport) -> Self {
        self.re_scrub = Some(re_scrub);
        self
    }
}

impl LivePoolRepairReconciliationProgress<'_> {
    fn clean_source(&self) -> Option<&tidefs_local_object_store::PlacementReceiptTarget> {
        self.evidence.current_receipt.targets.iter().find(|target| {
            target.device_index != self.evidence.repaired_target.device_index
                || target.device_guid != self.evidence.repaired_target.device_guid
        })
    }
}

fn mounted_repair_reconciliation_comparison_json(
    progress: LivePoolRepairReconciliationProgress<'_>,
) -> Value {
    let (kind, chunk_index) = mounted_scrub_block_kind(progress.block_id.kind);
    json!({
        "classification": "TargetRepairReconciliation",
        "subject": {
            "inode_id": progress.block_id.inode_id,
            "data_version": progress.block_id.data_version,
            "kind": kind,
            "chunk_index": chunk_index,
        },
        "object_key": live_admin_hex_encode(progress.object_key.as_bytes()),
        "receipt_epoch": progress.evidence.current_receipt.epoch,
        "embedded_predecessor_generation": progress.evidence.embedded_predecessor_generation,
        "receipt_generation": progress.evidence.current_receipt.generation,
        "redundancy_policy": "replicated-2",
        "target_count": progress.evidence.current_receipt.targets.len(),
        "durable_target_only_repair_evidence": true,
        "replacement_receipt_attached": progress.evidence.replacement_receipt_attached,
    })
}

fn live_pool_repair_reconciliation_failure(
    pool: &str,
    wants_json: bool,
    code: &'static str,
    message: impl Into<String>,
    progress: LivePoolRepairReconciliationProgress<'_>,
) -> LivePoolAdminResponse {
    let message = message.into();
    let source = progress.clean_source();
    if wants_json {
        return live_admin_report_json(
            1,
            json!({
                "pool": pool,
                "pass": false,
                "state_source": "live-owner",
                "owner_state": "mounted PoolDatasetOwner",
                "outcome": "incomplete",
                "repair_attempted": false,
                "repair_completed": false,
                "repair_writeback": false,
                "target_write_previously_completed": true,
                "receipt_publication": "previously-completed",
                "reconciliation_resumed": true,
                "reconciliation_attempted": progress.reconciliation_started,
                "reconciliation_completed": false,
                "reconciliation_writeback": progress.reconciliation_started,
                "failure": {
                    "code": code,
                    "message": message,
                },
                "initial_scrub": mounted_repair_scrub_summary(progress.initial_scrub),
                "comparison": mounted_repair_reconciliation_comparison_json(progress),
                "previous_receipt_generation": progress.evidence.embedded_predecessor_generation,
                "replacement_receipt_generation": progress.evidence.current_receipt.generation,
                "clean_source": source.map(mounted_repair_receipt_target_identity_json),
                "corrupt_target": mounted_repair_receipt_target_identity_json(&progress.evidence.repaired_target),
                "authenticated_root_published": progress.authenticated_root_state == "published",
                "authenticated_root_state": progress.authenticated_root_state,
                "re_scrub": progress.re_scrub.map(mounted_repair_scrub_summary),
            }),
        );
    }

    let (kind, chunk_index) = mounted_scrub_block_kind(progress.block_id.kind);
    let source_identity = source.map_or_else(
        || "not established".to_string(),
        mounted_repair_receipt_target_identity_text,
    );
    let repaired_identity =
        mounted_repair_receipt_target_identity_text(&progress.evidence.repaired_target);
    let re_scrub = progress.re_scrub.map_or("not run", |report| {
        if report.is_clean() && report.blocks_no_checksum == 0 {
            "clean"
        } else {
            "not clean"
        }
    });
    live_admin_report_text(
        1,
        format!(
            "pool repair: {pool}\n  source:                 live owner (mounted PoolDatasetOwner)\n  outcome:                incomplete\n  target write:           previously completed (not repeated)\n  reconciliation:         {}\n  comparison:             TargetRepairReconciliation\n  subject:                inode={} data-version={} kind={} chunk={}\n  object:                 {}\n  clean source:           {source_identity}\n  repaired target:        {repaired_identity}\n  receipt generation:     {} -> {}\n  authenticated root:     {}\n  re-scrub:               {re_scrub}\n  failure:                {code}: {message}",
            if progress.reconciliation_started {
                "started"
            } else {
                "not started"
            },
            progress.block_id.inode_id,
            progress.block_id.data_version,
            kind,
            chunk_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
            progress.object_key,
            progress.evidence.embedded_predecessor_generation,
            progress.evidence.current_receipt.generation,
            progress.authenticated_root_state,
        ),
    )
}

fn live_pool_repair_reconciliation_success(
    pool: &str,
    wants_json: bool,
    progress: LivePoolRepairReconciliationProgress<'_>,
    reconciled_current_manifests: u64,
    reconciled_snapshot_manifests: u64,
    filesystem_generation_before: u64,
    filesystem_generation_after: u64,
) -> LivePoolAdminResponse {
    let reconciled_manifests =
        reconciled_current_manifests.saturating_add(reconciled_snapshot_manifests);
    let source = progress.clean_source();
    let re_scrub = progress
        .re_scrub
        .expect("successful repair reconciliation has a clean re-scrub");
    if wants_json {
        return live_admin_ok_json(json!({
            "pool": pool,
            "pass": true,
            "state_source": "live-owner",
            "owner_state": "mounted PoolDatasetOwner",
            "outcome": "completed",
            "repair_attempted": false,
            "repair_completed": true,
            "repair_writeback": false,
            "target_write_previously_completed": true,
            "receipt_publication": "previously-completed",
            "reconciliation_resumed": true,
            "reconciliation_attempted": true,
            "reconciliation_completed": true,
            "reconciliation_writeback": true,
            "comparison": mounted_repair_reconciliation_comparison_json(progress),
            "previous_receipt_generation": progress.evidence.embedded_predecessor_generation,
            "replacement_receipt_generation": progress.evidence.current_receipt.generation,
            "clean_source": source.map(mounted_repair_receipt_target_identity_json),
            "corrupt_target": mounted_repair_receipt_target_identity_json(&progress.evidence.repaired_target),
            "reconciled_manifest_count": reconciled_manifests,
            "reconciled_current_manifest_count": reconciled_current_manifests,
            "reconciled_snapshot_manifest_count": reconciled_snapshot_manifests,
            "filesystem_generation_before": filesystem_generation_before,
            "filesystem_generation_after": filesystem_generation_after,
            "authenticated_root_published": true,
            "authenticated_root_state": "published",
            "re_scrub": mounted_repair_scrub_summary(re_scrub),
        }));
    }

    let source_identity = source.map_or_else(
        || "not established".to_string(),
        mounted_repair_receipt_target_identity_text,
    );
    let repaired_identity =
        mounted_repair_receipt_target_identity_text(&progress.evidence.repaired_target);
    let (kind, chunk_index) = mounted_scrub_block_kind(progress.block_id.kind);
    live_admin_ok_text(format!(
        "pool repair: {pool}\n  source:                 live owner (mounted PoolDatasetOwner)\n  outcome:                completed\n  target write:           previously completed (not repeated)\n  reconciliation:         resumed and completed\n  comparison:             TargetRepairReconciliation\n  subject:                inode={} data-version={} kind={} chunk={}\n  object:                 {}\n  clean source:           {source_identity}\n  repaired target:        {repaired_identity}\n  receipt generation:     {} -> {}\n  reconciled manifests:   {reconciled_manifests}\n  authenticated root:     published\n  re-scrub:               clean ({} blocks)",
        progress.block_id.inode_id,
        progress.block_id.data_version,
        kind,
        chunk_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
        progress.object_key,
        progress.evidence.embedded_predecessor_generation,
        progress.evidence.current_receipt.generation,
        re_scrub.blocks_scanned,
    ))
}

struct MountedRepairSnapshotRootAuthority {
    name: Vec<u8>,
    dataset_id: DatasetId,
    previous_typed_root: tidefs_pool_runtime::SnapshotRoot,
    captured_root: RootCommitRecord,
}
impl SharedPoolDatasetOwner {
    fn live_pool_repair(&self, pool: &str, wants_json: bool) -> LivePoolAdminResponse {
        let mut fs = self.borrow_mut();
        if let Err(error) = fs.ensure_mutation_allowed("repair mounted pool replica") {
            return live_pool_repair_failure(
                pool,
                wants_json,
                "mutation-authority-refused",
                format!("mounted owner cannot authorize repair mutation: {error}"),
                LivePoolRepairProgress::default(),
            );
        }
        if fs.store.pool().is_read_only() {
            return live_pool_repair_failure(
                pool,
                wants_json,
                "read-only-pool-authority",
                "mounted Pool authority is read-only",
                LivePoolRepairProgress::default(),
            );
        }
        if let Some(reason) = fs.mounted_mutation_quiescence_failure() {
            return live_pool_repair_failure(
                pool,
                wants_json,
                "mounted-state-not-quiescent",
                format!("repair requires clean quiescent mounted state: {reason}"),
                LivePoolRepairProgress::default(),
            );
        }
        let initial_scrub = match fs.scrub_mounted_content() {
            Ok(report) => report,
            Err(error) => {
                return live_pool_repair_refusal(
                    pool,
                    wants_json,
                    "initial-scrub-failed",
                    format!("mounted content scan failed before repair: {error}"),
                    false,
                    false,
                    None,
                    None,
                    None,
                )
            }
        };

        // Refuse clean, incomplete, or non-authoritative evidence without
        // synchronizing the Pool. Pool::sync_all advances physical state even
        // when the mounted filesystem has no dirty records, so running it
        // before these read-only gates would mutate complete device images for
        // a repair that was never authorized.
        if initial_scrub.blocks_no_checksum > 0 {
            return live_pool_repair_refusal(
                pool,
                wants_json,
                "missing-checksum-evidence",
                "mounted scrub found content without an applicable checksum",
                false,
                false,
                Some(&initial_scrub),
                None,
                None,
            );
        }
        if initial_scrub.violations.is_empty() {
            return live_pool_repair_refusal(
                pool,
                wants_json,
                "no-repair-needed",
                "mounted scrub is clean; no repair writeback is authorized",
                false,
                false,
                Some(&initial_scrub),
                None,
                None,
            );
        }
        if initial_scrub.violations.len() != 1 {
            return live_pool_repair_refusal(
                pool,
                wants_json,
                "multiple-scrub-findings",
                format!(
                    "mounted repair requires exactly one finding, observed {}",
                    initial_scrub.violations.len()
                ),
                false,
                false,
                Some(&initial_scrub),
                None,
                None,
            );
        }

        let block_id = initial_scrub.violations[0].block_id.clone();
        let keyspace = fs.object_keyspace();
        let compared = match crate::scrub::compare_mounted_replicated_repair(
            fs.store.pool(),
            &fs.filesystem.state.inodes,
            keyspace,
            &block_id,
        ) {
            Ok(comparison) => comparison,
            Err(error) => {
                let stale_receipt_authority = error.code == "stale-content-receipt-generation";
                if stale_receipt_authority {
                    if let (Some(object_key), Some(embedded_generation)) =
                        (error.object_key, error.embedded_receipt_generation)
                    {
                        match fs.store.pool().replicated_repair_reconciliation_evidence(
                            DeviceIoClass::Data,
                            object_key,
                            embedded_generation,
                        ) {
                            Ok(Some(evidence))
                                if evidence.current_receipt.object_key == object_key
                                    && evidence.embedded_predecessor_generation
                                        == embedded_generation =>
                            {
                                return fs.resume_mounted_repair_reconciliation(
                                    pool,
                                    wants_json,
                                    &initial_scrub,
                                    &block_id,
                                    object_key,
                                    evidence,
                                )
                            }
                            Ok(_) => {}
                            Err(evidence_error) => {
                                fs.arm_mutation_reopen_fence();
                                return live_pool_repair_refusal(
                                    pool,
                                    wants_json,
                                    "repair-reconciliation-evidence-failed",
                                    format!(
                                        "target-only repair reconciliation evidence could not be read: {evidence_error}"
                                    ),
                                    false,
                                    false,
                                    Some(&initial_scrub),
                                    None,
                                    None,
                                );
                            }
                        }
                    }
                }
                if stale_receipt_authority {
                    fs.arm_mutation_reopen_fence();
                }
                return live_pool_repair_refusal(
                    pool,
                    wants_json,
                    error.code,
                    error.message,
                    false,
                    false,
                    Some(&initial_scrub),
                    None,
                    None,
                );
            }
        };
        let (source_device_index, corrupt_device_index) = match &compared.classification {
            crate::scrub::MountedRepairClassification::SingleReplicaCorruption {
                corrupt_target,
                clean_sources,
            } if clean_sources.len() == 1 => (clean_sources[0], *corrupt_target),
            classification => {
                return live_pool_repair_refusal(
                    pool,
                    wants_json,
                    "comparison-refused-writeback",
                    format!(
                        "{} does not authorize one local target repair",
                        mounted_repair_classification_name(classification)
                    ),
                    false,
                    false,
                    Some(&initial_scrub),
                    Some(&compared),
                    None,
                )
            }
        };
        let selected_progress = LivePoolRepairProgress {
            initial_scrub: Some(&initial_scrub),
            comparison: Some(&compared),
            previous_receipt_generation: Some(compared.receipt_evidence.receipt.generation),
            source_device_index: Some(source_device_index),
            corrupt_device_index: Some(corrupt_device_index),
            ..LivePoolRepairProgress::default()
        };

        if let Err(error) = fs.authenticate_mounted_repair_prewrite_current_root(
            compared.object_key,
            &compared.receipt_evidence.receipt,
            source_device_index,
            corrupt_device_index,
        ) {
            return live_pool_repair_failure(
                pool,
                wants_json,
                "filesystem-root-preflight-failed",
                format!(
                    "mounted repair could not authenticate the current filesystem root before writeback: {error}"
                ),
                selected_progress,
            );
        }
        if let Err(error) = fs.authenticate_mounted_repair_prewrite_snapshot_roots(
            compared.object_key,
            &compared.receipt_evidence.receipt,
            source_device_index,
            corrupt_device_index,
        ) {
            return live_pool_repair_failure(
                pool,
                wants_json,
                "retained-root-preflight-failed",
                format!(
                    "mounted repair could not authenticate retained snapshot state before writeback: {error}"
                ),
                selected_progress,
            );
        }

        // Refresh the complete mounted and receipt evidence immediately before
        // writeback.  The owner lock prevents a concurrent mounted mutation,
        // while the Pool repair entry point performs the final receipt and
        // payload revalidation after this comparison.
        let refreshed = match crate::scrub::compare_mounted_replicated_repair(
            fs.store.pool(),
            &fs.filesystem.state.inodes,
            keyspace,
            &block_id,
        ) {
            Ok(comparison)
                if comparison.object_key == compared.object_key
                    && comparison.receipt_evidence.receipt == compared.receipt_evidence.receipt
                    && comparison.checksum_layer == compared.checksum_layer
                    && comparison.target_outcomes == compared.target_outcomes
                    && comparison.classification == compared.classification =>
            {
                comparison
            }
            Ok(_) => {
                return live_pool_repair_failure(
                    pool,
                    wants_json,
                    "stale-comparison-evidence",
                    "mounted content or receipt authority changed before writeback",
                    selected_progress,
                )
            }
            Err(error) => {
                return live_pool_repair_failure(
                    pool,
                    wants_json,
                    error.code,
                    format!("stale-authority revalidation failed: {}", error.message),
                    selected_progress,
                )
            }
        };

        let repair = match fs.store.pool_mut().repair_current_replicated_target(
            DeviceIoClass::Data,
            refreshed.object_key,
            &refreshed.receipt_evidence.receipt,
            source_device_index,
            corrupt_device_index,
        ) {
            Ok(repair) => repair,
            Err(failure) => {
                // Generation reservation, reclaim-intent enqueue, and target
                // rewrite all precede replacement-receipt publication. The
                // predecessor receipt/root remain authoritative in those
                // phases, so a reopen fence would prevent the same live owner
                // from retrying the exact pending transition. Once receipt
                // publication completed or became uncertain, however, the
                // embedded filesystem root can be stale and every later
                // mutation must wait for reopen reconciliation.
                if failure.receipt_publication
                    != tidefs_local_object_store::pool::ReplicatedRepairReceiptPublicationState::NotAttempted
                {
                    fs.arm_mutation_reopen_fence();
                } else if failure.writeback_started {
                    // Generation reservation or the exact pending reclaim row
                    // is already durable. Permit the repair carrier to resume
                    // that transition, but do not let unrelated mounted work
                    // advance the canonical root out from under its evidence.
                    fs.arm_replicated_repair_retry_only();
                }
                let receipt_publication = match failure.receipt_publication {
                    tidefs_local_object_store::pool::ReplicatedRepairReceiptPublicationState::NotAttempted => {
                        "not-attempted"
                    }
                    tidefs_local_object_store::pool::ReplicatedRepairReceiptPublicationState::Completed => {
                        "completed"
                    }
                    tidefs_local_object_store::pool::ReplicatedRepairReceiptPublicationState::Uncertain => {
                        "uncertain"
                    }
                };
                return live_pool_repair_failure(
                    pool,
                    wants_json,
                    "writeback-revalidation-refused",
                    format!("Pool repair writeback did not complete: {}", failure.error),
                    LivePoolRepairProgress {
                        attempted: true,
                        writeback_started: failure.writeback_started,
                        receipt_publication,
                        initial_scrub: Some(&initial_scrub),
                        comparison: Some(&refreshed),
                        previous_receipt_generation: Some(
                            refreshed.receipt_evidence.receipt.generation,
                        ),
                        replacement_receipt_generation: failure.replacement_generation,
                        source_device_index: Some(source_device_index),
                        corrupt_device_index: Some(corrupt_device_index),
                        ..LivePoolRepairProgress::default()
                    },
                );
            }
        };
        // The Pool has now published and attached the exact replacement
        // receipt. Reconciliation below runs while this owner remains locked;
        // every failure after this point arms the stronger reopen fence.
        fs.clear_replicated_repair_retry_only();
        let replacement_generation = repair.replacement_receipt.generation;
        let mut repair_progress = LivePoolRepairProgress {
            attempted: true,
            writeback_started: true,
            receipt_publication: "completed",
            initial_scrub: Some(&initial_scrub),
            comparison: Some(&refreshed),
            previous_receipt_generation: Some(repair.previous_receipt.generation),
            replacement_receipt_generation: Some(replacement_generation),
            source_device_index: Some(source_device_index),
            corrupt_device_index: Some(corrupt_device_index),
            ..LivePoolRepairProgress::default()
        };
        if let Err(error) = fs.store.pool_mut().sync_all() {
            fs.arm_mutation_reopen_fence();
            return live_pool_repair_failure(
                pool,
                wants_json,
                "replacement-receipt-sync-failed",
                format!("replacement receipt could not be synchronized: {error}"),
                repair_progress,
            );
        }

        let reconciliation_evidence =
            match fs.store.pool().replicated_repair_reconciliation_evidence(
                DeviceIoClass::Data,
                refreshed.object_key,
                repair.previous_receipt.generation,
            ) {
                Ok(Some(evidence))
                    if evidence.current_receipt == repair.replacement_receipt
                        && evidence.repaired_target.device_index == corrupt_device_index =>
                {
                    evidence
                }
                Ok(Some(_)) => {
                    fs.arm_mutation_reopen_fence();
                    return live_pool_repair_failure(
                    pool,
                    wants_json,
                    "repair-reconciliation-evidence-mismatch",
                    "replacement receipt no longer matches the exact target-only repair evidence",
                    repair_progress,
                );
                }
                Ok(None) => {
                    fs.arm_mutation_reopen_fence();
                    return live_pool_repair_failure(
                        pool,
                        wants_json,
                        "repair-reconciliation-evidence-missing",
                        "replacement receipt has no exact target-only repair evidence",
                        repair_progress,
                    );
                }
                Err(error) => {
                    fs.arm_mutation_reopen_fence();
                    return live_pool_repair_failure(
                        pool,
                        wants_json,
                        "repair-reconciliation-evidence-failed",
                        format!("replacement receipt evidence could not be authenticated: {error}"),
                        repair_progress,
                    );
                }
            };
        let reconciliation = match fs
            .reconcile_mounted_repair_transition(refreshed.object_key, reconciliation_evidence)
        {
            Ok(outcome) => outcome,
            Err(failure) => {
                let message = format!(
                    "replacement receipt was published but repair reconciliation did not complete: {}",
                    failure.message
                );
                repair_progress.authenticated_root_state = failure.authenticated_root_state;
                repair_progress.re_scrub = failure.re_scrub.as_ref();
                fs.arm_mutation_reopen_fence();
                return live_pool_repair_failure(
                    pool,
                    wants_json,
                    failure.code,
                    message,
                    repair_progress,
                );
            }
        };
        if !reconciliation.evidence.replacement_receipt_attached {
            repair_progress.authenticated_root_state = "published";
            repair_progress.re_scrub = Some(&reconciliation.re_scrub);
            fs.arm_mutation_reopen_fence();
            return live_pool_repair_failure(
                pool,
                wants_json,
                "repair-reclaim-attachment-incomplete",
                "repair reconciliation completed without durable replacement-receipt attachment",
                repair_progress,
            );
        }

        let reconciled_current_manifests = reconciliation.reconciled_current_manifests;
        let reconciled_snapshot_manifests = reconciliation.reconciled_snapshot_manifests;
        let reconciled_manifests =
            reconciled_snapshot_manifests.saturating_add(reconciled_current_manifests);
        let root_generation_before = reconciliation.filesystem_generation_before;
        let root_generation_after = reconciliation.filesystem_generation_after;
        let re_scrub = &reconciliation.re_scrub;

        let source = mounted_repair_target_identity_json(&refreshed, source_device_index);
        let corrupt = mounted_repair_target_identity_json(&refreshed, corrupt_device_index);
        if wants_json {
            return live_admin_ok_json(json!({
                "pool": pool,
                "pass": true,
                "state_source": "live-owner",
                "owner_state": "mounted PoolDatasetOwner",
                "outcome": "completed",
                "repair_attempted": true,
                "repair_completed": true,
                "repair_writeback": true,
                "receipt_publication": "completed",
                "comparison": mounted_repair_comparison_json(&refreshed),
                "previous_receipt_generation": repair.previous_receipt.generation,
                "replacement_receipt_generation": repair.replacement_receipt.generation,
                "replacement_receipt_attached": reconciliation.evidence.replacement_receipt_attached,
                "clean_source": source,
                "corrupt_target": corrupt,
                "reconciled_manifest_count": reconciled_manifests,
                "reconciled_current_manifest_count": reconciled_current_manifests,
                "reconciled_snapshot_manifest_count": reconciled_snapshot_manifests,
                "filesystem_generation_before": root_generation_before,
                "filesystem_generation_after": root_generation_after,
                "authenticated_root_published": true,
                "authenticated_root_state": "published",
                "re_scrub": mounted_repair_scrub_summary(&re_scrub),
            }));
        }

        let (kind, chunk_index) = mounted_scrub_block_kind(refreshed.block_id.kind);
        let source_identity = mounted_repair_target_identity_text(&refreshed, source_device_index);
        let repaired_identity =
            mounted_repair_target_identity_text(&refreshed, corrupt_device_index);
        live_admin_ok_text(format!(
            "pool repair: {pool}\n  source:                 live owner (mounted PoolDatasetOwner)\n  outcome:                completed\n  comparison:             SingleReplicaCorruption\n  subject:                inode={} data-version={} kind={} chunk={}\n  object:                 {}\n  clean source:           {source_identity}\n  repaired target:        {repaired_identity}\n  receipt generation:     {} -> {}\n  reconciled manifests:   {}\n  authenticated root:     published\n  re-scrub:               clean ({} blocks)",
            refreshed.block_id.inode_id,
            refreshed.block_id.data_version,
            kind,
            chunk_index.map_or_else(|| "none".to_string(), |index| index.to_string()),
            refreshed.object_key,
            repair.previous_receipt.generation,
            repair.replacement_receipt.generation,
            reconciled_manifests,
            re_scrub.blocks_scanned,
        ))
    }
}

impl PoolDatasetOwner {
    fn authenticate_mounted_repair_prewrite_current_root(
        &self,
        object_key: ObjectKey,
        expected_receipt: &tidefs_local_object_store::PlacementReceipt,
        source_device_index: u32,
        corrupt_device_index: u32,
    ) -> crate::Result<()> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        let root_bytes = self.store.load_dataset_root(
            mounted_dataset_id,
            tidefs_pool_runtime::DatasetRootKind::Filesystem,
        )?;
        let root = crate::encoding::decode_root_commit(&root_bytes)?;
        let (persisted_state, persisted_root) =
            crate::load_replicated_repair_prewrite_root_requiring_reference(
                self.store.pool(),
                mounted_dataset_id,
                &root,
                self.root_authentication_key,
                object_key,
                expected_receipt,
                source_device_index,
                corrupt_device_index,
            )?;
        if persisted_root != root
            || persisted_root.generation != self.state.generation
            || persisted_state.generation != self.state.generation
            || persisted_root.next_inode_id != self.state.next_inode_id_raw()
            || persisted_root.inode_count != self.state.inodes.len() as u64
        {
            return Err(crate::FileSystemError::CorruptState {
                reason: "authenticated mounted root no longer matches the quiescent live owner",
            });
        }
        Ok(())
    }

    fn authenticate_mounted_repair_prewrite_snapshot_roots(
        &self,
        object_key: ObjectKey,
        expected_receipt: &tidefs_local_object_store::PlacementReceipt,
        source_device_index: u32,
        corrupt_device_index: u32,
    ) -> crate::Result<()> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        for root in self.capture_mounted_repair_snapshot_roots()? {
            let (captured_state, authenticated_root) = crate::load_replicated_repair_prewrite_root(
                self.store.pool(),
                mounted_dataset_id,
                &root.captured_root,
                self.root_authentication_key,
                object_key,
                expected_receipt,
                source_device_index,
                corrupt_device_index,
            )?;
            if authenticated_root != root.captured_root
                || captured_state.generation != root.captured_root.generation
                || authenticated_root.next_inode_id != root.captured_root.next_inode_id
                || authenticated_root.inode_count != root.captured_root.inode_count
            {
                return Err(crate::FileSystemError::CorruptState {
                    reason: "authenticated retained root no longer matches snapshot authority",
                });
            }
        }
        Ok(())
    }

    fn capture_mounted_repair_snapshot_roots(
        &self,
    ) -> crate::Result<Vec<MountedRepairSnapshotRootAuthority>> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        self.ensure_snapshot_authority_consistent()?;
        let mut mounted_snapshots = Vec::new();
        for record in self
            .state
            .snapshots
            .values()
            .filter(|record| crate::snapshot::snapshot_record_retains_data(record))
        {
            self.ensure_snapshot_record_authority(record)?;
            let dataset_id =
                crate::snapshot::snapshot_record_dataset_id_for_dataset(record, mounted_dataset_id);
            mounted_snapshots.push(MountedRepairSnapshotRootAuthority {
                name: record.name.clone(),
                dataset_id,
                previous_typed_root: self.store.load_snapshot_root(dataset_id)?,
                captured_root: crate::root_commit_from_summary(&record.root),
            });
        }
        Ok(mounted_snapshots)
    }

    fn load_mounted_repair_snapshot_states(
        &self,
        roots: Vec<MountedRepairSnapshotRootAuthority>,
        object_key: ObjectKey,
        embedded_receipt_generation: u64,
    ) -> crate::Result<Vec<DeviceLifecycleSnapshotState>> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        roots
            .into_iter()
            .map(|root| {
                let captured_state =
                    crate::load_state_from_transaction_pool_for_replicated_repair_reconciliation(
                        self.store.pool(),
                        mounted_dataset_id,
                        &root.captured_root,
                        self.root_authentication_key,
                        object_key,
                        embedded_receipt_generation,
                    )?;
                Ok(DeviceLifecycleSnapshotState {
                    name: root.name,
                    dataset_id: root.dataset_id,
                    previous_typed_root: root.previous_typed_root,
                    captured_state,
                    captured_root: root.captured_root,
                })
            })
            .collect()
    }

    fn load_mounted_repair_snapshot_states_for_transitions(
        &self,
        roots: Vec<MountedRepairSnapshotRootAuthority>,
        transitions: &[crate::recovery::PendingReplicatedRepairReconciliation],
    ) -> crate::Result<Vec<DeviceLifecycleSnapshotState>> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        roots
            .into_iter()
            .map(|root| {
                let captured_state =
                    crate::load_state_from_transaction_pool_for_replicated_repair_reconciliations(
                        self.store.pool(),
                        mounted_dataset_id,
                        &root.captured_root,
                        self.root_authentication_key,
                        transitions,
                    )?;
                Ok(DeviceLifecycleSnapshotState {
                    name: root.name,
                    dataset_id: root.dataset_id,
                    previous_typed_root: root.previous_typed_root,
                    captured_state,
                    captured_root: root.captured_root,
                })
            })
            .collect()
    }

    fn authenticate_mounted_repair_current_root(
        &self,
        object_key: ObjectKey,
        embedded_receipt_generation: u64,
    ) -> crate::Result<()> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        let root_bytes = self.store.load_dataset_root(
            mounted_dataset_id,
            tidefs_pool_runtime::DatasetRootKind::Filesystem,
        )?;
        let root = crate::encoding::decode_root_commit(&root_bytes)?;
        let _ = crate::load_state_from_transaction_pool_for_replicated_repair_reconciliation_requiring_reference(
            self.store.pool(),
            mounted_dataset_id,
            &root,
            self.root_authentication_key,
            object_key,
            embedded_receipt_generation,
        )?;
        Ok(())
    }

    fn authenticate_mounted_repair_current_root_for_transitions(
        &self,
        transitions: &[crate::recovery::PendingReplicatedRepairReconciliation],
    ) -> crate::Result<()> {
        let mounted_dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        let root_bytes = self.store.load_dataset_root(
            mounted_dataset_id,
            tidefs_pool_runtime::DatasetRootKind::Filesystem,
        )?;
        let root = crate::encoding::decode_root_commit(&root_bytes)?;
        let _ = crate::load_state_from_transaction_pool_for_replicated_repair_reconciliations_requiring_references(
            self.store.pool(),
            mounted_dataset_id,
            &root,
            self.root_authentication_key,
            transitions,
        )?;
        Ok(())
    }

    fn resume_mounted_repair_reconciliation(
        &mut self,
        pool_name: &str,
        wants_json: bool,
        initial_scrub: &crate::scrub::ScrubReport,
        block_id: &crate::types::ScrubBlockId,
        object_key: ObjectKey,
        evidence: tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
    ) -> LivePoolAdminResponse {
        match self.reconcile_mounted_repair_transition(object_key, evidence) {
            Ok(outcome) => {
                let progress = LivePoolRepairReconciliationProgress {
                    initial_scrub,
                    block_id,
                    object_key,
                    evidence: &outcome.evidence,
                    reconciliation_started: true,
                    authenticated_root_state: "published",
                    re_scrub: Some(&outcome.re_scrub),
                };
                live_pool_repair_reconciliation_success(
                    pool_name,
                    wants_json,
                    progress,
                    outcome.reconciled_current_manifests,
                    outcome.reconciled_snapshot_manifests,
                    outcome.filesystem_generation_before,
                    outcome.filesystem_generation_after,
                )
            }
            Err(failure) => {
                self.arm_mutation_reopen_fence();
                live_pool_repair_reconciliation_failure(
                    pool_name,
                    wants_json,
                    failure.code,
                    failure.message.clone(),
                    LivePoolRepairReconciliationProgress {
                        initial_scrub,
                        block_id,
                        object_key,
                        evidence: &failure.evidence,
                        reconciliation_started: failure.reconciliation_started,
                        authenticated_root_state: failure.authenticated_root_state,
                        re_scrub: failure.re_scrub.as_ref(),
                    },
                )
            }
        }
    }

    fn reconcile_mounted_repair_transition(
        &mut self,
        object_key: ObjectKey,
        evidence: tidefs_local_object_store::pool::ReplicatedRepairReconciliationEvidence,
    ) -> std::result::Result<MountedRepairReconciliationOutcome, MountedRepairReconciliationFailure>
    {
        if let Some(reason) = self.mounted_mutation_quiescence_failure() {
            return Err(MountedRepairReconciliationFailure::new(
                "mounted-state-not-quiescent",
                format!("repair reconciliation requires clean quiescent state: {reason}"),
                evidence,
                false,
                "not-started",
            ));
        }

        let evidence = match self.store.pool().replicated_repair_reconciliation_evidence(
            DeviceIoClass::Data,
            object_key,
            evidence.embedded_predecessor_generation,
        ) {
            Ok(Some(current))
                if current.current_receipt == evidence.current_receipt
                    && current.repaired_target == evidence.repaired_target
                    && current.embedded_predecessor_generation
                        == evidence.embedded_predecessor_generation =>
            {
                current
            }
            Ok(Some(_)) => {
                return Err(MountedRepairReconciliationFailure::new(
                    "repair-reconciliation-evidence-mismatch",
                    "current Pool evidence changed before repair reconciliation",
                    evidence,
                    false,
                    "not-started",
                ))
            }
            Ok(None) => {
                return Err(MountedRepairReconciliationFailure::new(
                    "repair-reclaim-evidence-disappeared",
                    "exact target-only repair evidence disappeared before reconciliation",
                    evidence,
                    false,
                    "not-started",
                ))
            }
            Err(error) => {
                return Err(MountedRepairReconciliationFailure::new(
                    "repair-reconciliation-evidence-failed",
                    format!("exact target-only repair evidence could not be revalidated: {error}"),
                    evidence,
                    false,
                    "not-started",
                ))
            }
        };

        let roots = self
            .capture_mounted_repair_snapshot_roots()
            .map_err(|error| {
                MountedRepairReconciliationFailure::new(
                    "retained-root-preflight-failed",
                    format!(
                    "repair reconciliation could not authenticate retained snapshot roots: {error}"
                ),
                    evidence.clone(),
                    false,
                    "not-started",
                )
            })?;
        let embedded_generation = evidence.embedded_predecessor_generation;
        self.authenticate_mounted_repair_current_root(object_key, embedded_generation)
            .map_err(|error| {
                MountedRepairReconciliationFailure::new(
                    "filesystem-root-reconciliation-preflight-failed",
                    format!(
                        "the predecessor filesystem root could not be authenticated for repair reconciliation: {error}"
                    ),
                    evidence.clone(),
                    false,
                    "not-started",
                )
            })?;
        let mut mounted_snapshots = self
            .load_mounted_repair_snapshot_states(roots, object_key, embedded_generation)
            .map_err(|error| {
                MountedRepairReconciliationFailure::new(
                    "retained-root-reconciliation-preflight-failed",
                    format!(
                        "retained snapshot state could not be authenticated for repair reconciliation: {error}"
                    ),
                    evidence.clone(),
                    false,
                    "not-started",
                )
            })?;

        let evidence = if evidence.replacement_receipt_attached {
            evidence
        } else {
            match self
                .store
                .pool_mut()
                .complete_replicated_repair_reclaim_attachment(
                    DeviceIoClass::Data,
                    object_key,
                    evidence.embedded_predecessor_generation,
                ) {
                Ok(Some(completed))
                    if completed.current_receipt == evidence.current_receipt
                        && completed.repaired_target == evidence.repaired_target
                        && completed.embedded_predecessor_generation
                            == evidence.embedded_predecessor_generation =>
                {
                    completed
                }
                Ok(Some(_)) => {
                    return Err(MountedRepairReconciliationFailure::new(
                        "repair-reclaim-attachment-mismatch",
                        "pending reclaim attachment changed the exact target-only repair evidence",
                        evidence,
                        true,
                        "not-started",
                    ))
                }
                Ok(None) => {
                    return Err(MountedRepairReconciliationFailure::new(
                        "repair-reclaim-evidence-disappeared",
                        "exact target-only repair evidence disappeared before pending reclaim attachment",
                        evidence,
                        false,
                        "not-started",
                    ))
                }
                Err(error) => {
                    return Err(MountedRepairReconciliationFailure::new(
                        "repair-reclaim-attachment-failed",
                        format!(
                            "pending target-only repair reclaim attachment did not complete: {error}"
                        ),
                        evidence,
                        true,
                        "not-started",
                    ))
                }
            }
        };

        let filesystem_generation_before = self.stats().filesystem_generation;
        let reconciled_snapshot_manifests = self
            .reconcile_mounted_snapshot_receipts(&mut mounted_snapshots)
            .map_err(|error| {
                MountedRepairReconciliationFailure::new(
                    "snapshot-reconciliation-failed",
                    format!("retained snapshot repair reconciliation failed: {error}"),
                    evidence.clone(),
                    true,
                    "not-started",
                )
            })?;
        let filesystem_generation_before_current_reconciliation =
            self.stats().filesystem_generation;
        let reconciled_current_manifests = match self.reconcile_relocated_content_receipts() {
            Ok(reconciled) => reconciled,
            Err(error) => {
                // `force_commit` can fail before publishing a successor,
                // after an uncertain root write, or during fallible work
                // after the new root was durably published and verified.
                // Preserve that boundary in the operator report instead
                // of claiming publication never started in every case.
                let authenticated_root_state =
                    if matches!(&error, FileSystemError::PublishOutcomeUncertain { .. }) {
                        "publication-uncertain"
                    } else if self.stats().filesystem_generation
                        > filesystem_generation_before_current_reconciliation
                    {
                        "published"
                    } else {
                        "not-started"
                    };
                return Err(MountedRepairReconciliationFailure::new(
                    "filesystem-reconciliation-failed",
                    format!("current filesystem repair reconciliation failed: {error}"),
                    evidence.clone(),
                    true,
                    authenticated_root_state,
                ));
            }
        };
        if reconciled_current_manifests == 0 {
            return Err(MountedRepairReconciliationFailure::new(
                "filesystem-reconciliation-missing",
                "repair evidence named no stale manifest in the current filesystem root",
                evidence,
                true,
                "not-started",
            ));
        }

        // `reconcile_relocated_content_receipts` already published the
        // current filesystem and every pending snapshot-root successor in one
        // canonical Pool-root transition. Mounted reopen never selects the
        // non-canonical raw root-slot history, so republishing the same state
        // cannot provide fallback convergence.
        self.store.pool_mut().sync_all().map_err(|error| {
            MountedRepairReconciliationFailure::new(
                "authenticated-root-sync-failed",
                format!("repair reconciliation root sync failed: {error}"),
                evidence.clone(),
                true,
                "published",
            )
        })?;

        let dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        let root_authentication_key = self.filesystem.root_authentication_key;
        crate::load_canonical_committed_state_for_dataset(
            &self.store,
            dataset_id,
            root_authentication_key,
        )
        .map_err(|error| {
            MountedRepairReconciliationFailure::new(
                "authenticated-root-verification-failed",
                format!("published repair reconciliation root did not authenticate: {error}"),
                evidence.clone(),
                true,
                "published",
            )
        })?;

        let re_scrub = self.scrub_mounted_content().map_err(|error| {
            MountedRepairReconciliationFailure::new(
                "re-scrub-failed",
                format!("published repair reconciliation re-scrub failed: {error}"),
                evidence.clone(),
                true,
                "published",
            )
        })?;
        if !re_scrub.is_clean() || re_scrub.blocks_no_checksum != 0 {
            return Err(MountedRepairReconciliationFailure::new(
                "re-scrub-not-clean",
                "published repair reconciliation still has mounted integrity findings",
                evidence,
                true,
                "published",
            )
            .with_re_scrub(re_scrub));
        }

        Ok(MountedRepairReconciliationOutcome {
            evidence,
            reconciled_current_manifests,
            reconciled_snapshot_manifests,
            filesystem_generation_before,
            filesystem_generation_after: self.stats().filesystem_generation,
            re_scrub,
        })
    }

    pub(crate) fn reconcile_pending_replicated_repairs_before_owner(
        &mut self,
        transitions: Vec<crate::recovery::PendingReplicatedRepairReconciliation>,
    ) -> crate::Result<()> {
        if transitions.is_empty() {
            return Err(crate::FileSystemError::CorruptState {
                reason: "pending replicated repair reconciliation batch is empty",
            });
        }
        if let Some(reason) = self.mounted_mutation_quiescence_failure() {
            return Err(crate::FileSystemError::CorruptState { reason });
        }

        // Revalidate and authenticate the complete deterministic exception set
        // before any mounted or Pool state changes. A crash can leave an older
        // row fully attached while a later row is still being completed; both
        // must remain one predecessor-root authority set.
        let mut previous_order = None;
        for transition in &transitions {
            let order = (
                transition.object_key,
                transition.evidence.embedded_predecessor_generation,
                transition.evidence.current_receipt.generation,
            );
            if previous_order.is_some_and(|previous| previous >= order)
                || transition.evidence.current_receipt.object_key != transition.object_key
                || !transition.evidence.replacement_receipt_attached
            {
                return Err(crate::FileSystemError::CorruptState {
                    reason:
                        "pending replicated repair reconciliation batch is not exact and ordered",
                });
            }
            let current = self
                .store
                .pool()
                .replicated_repair_reconciliation_evidence(
                    DeviceIoClass::Data,
                    transition.object_key,
                    transition.evidence.embedded_predecessor_generation,
                )?
                .ok_or(crate::FileSystemError::CorruptState {
                    reason: "pending replicated repair reconciliation evidence disappeared",
                })?;
            if current != transition.evidence {
                return Err(crate::FileSystemError::CorruptState {
                    reason: "pending replicated repair reconciliation evidence changed",
                });
            }
            previous_order = Some(order);
        }

        let roots = self.capture_mounted_repair_snapshot_roots()?;
        self.authenticate_mounted_repair_current_root_for_transitions(&transitions)?;
        let mut mounted_snapshots =
            self.load_mounted_repair_snapshot_states_for_transitions(roots, &transitions)?;

        // All snapshot and current-manifest successor changes are now planned
        // from the same predecessor authority. The established snapshot
        // publication code stages every changed typed root, while the current
        // reconciliation performs the single logical successor commit.
        let reconciled_snapshot_manifests =
            self.reconcile_mounted_snapshot_receipts(&mut mounted_snapshots)?;
        let reconciled_current_manifests = self.reconcile_relocated_content_receipts()?;
        if reconciled_current_manifests == 0 {
            return Err(crate::FileSystemError::CorruptState {
                reason:
                    "pending replicated repair batch named no stale manifest in the current root",
            });
        }

        // The current reconciliation committed this complete batch and its
        // snapshot-root successors through one canonical Pool root. Raw
        // root-slot history is diagnostic only and must not drive duplicate
        // publications here.
        self.store.pool_mut().sync_all()?;

        let dataset_id = DatasetId::from_bytes(self.mounted_dataset_id());
        crate::load_canonical_committed_state_for_dataset(
            &self.store,
            dataset_id,
            self.root_authentication_key,
        )?;
        let re_scrub = self.scrub_mounted_content()?;
        if !re_scrub.is_clean() || re_scrub.blocks_no_checksum != 0 {
            return Err(crate::FileSystemError::CorruptState {
                reason: "pending replicated repair batch did not produce a clean mounted scrub",
            });
        }

        eprintln!(
            "recovery: reconciled {} target-only replica repair transitions before mounted owner publication (current_manifests={}, snapshot_manifests={})",
            transitions.len(),
            reconciled_current_manifests,
            reconciled_snapshot_manifests,
        );
        Ok(())
    }

    fn next_absent_snapshot_source_transaction_id(
        &self,
        state: &FileSystemState,
        transaction_floor: u64,
    ) -> crate::Result<u64> {
        let keyspace = crate::FilesystemObjectKeyspace::new(state.dataset_id());
        let mut transaction_id = transaction_floor
            .max(state.generation)
            .max(crate::types::ROOT_COMMIT_MIN_TRANSACTION_ID);

        loop {
            let mut prospective_keys = BTreeSet::new();
            prospective_keys.insert(keyspace.transaction_superblock(transaction_id));
            prospective_keys.insert(keyspace.transaction_manifest(transaction_id));
            for inode in state.inodes.values() {
                prospective_keys.insert(keyspace.transaction_inode(transaction_id, inode.inode_id));
                if inode.carries_child_namespace() {
                    prospective_keys
                        .insert(keyspace.transaction_directory(transaction_id, inode.inode_id));
                }
                if inode.is_file_like() {
                    prospective_keys
                        .insert(keyspace.transaction_extent_map(transaction_id, inode.inode_id));
                }
            }
            for snapshot in state.snapshots.values() {
                prospective_keys
                    .insert(keyspace.transaction_snapshot(transaction_id, &snapshot.name));
            }

            let mut occupied = false;
            for key in prospective_keys {
                let receipt = self
                    .store
                    .pool()
                    .placement_receipt_for_key(DeviceIoClass::Metadata, key)?;
                let payload = self.store.pool().get(DeviceIoClass::Metadata, key)?;
                if receipt.is_some() || payload.is_some() {
                    occupied = true;
                    break;
                }
            }
            if !occupied {
                return Ok(transaction_id);
            }
            transaction_id =
                transaction_id
                    .checked_add(1)
                    .ok_or(FileSystemError::CorruptState {
                        reason: "mounted snapshot transaction id space is exhausted",
                    })?;
        }
    }
}
