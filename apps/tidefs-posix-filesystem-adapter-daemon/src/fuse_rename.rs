// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! FUSE rename dispatch with namespace renameat2 integration.
//!
//! This module provides the FUSE `rename` / `renameat2` operation dispatch
//! that chains FUSE protocol argument extraction, POSIX constraint validation,
//! namespace `renameat2` delegation, dir-index entry swap, and inode-table
//! link-count updates.
//!
//! Supported modes:
//! - `RENAME` (flags=0): plain POSIX rename with overwrite semantics
//! - `RENAME_NOREPLACE`: fail with EEXIST if destination exists
//! - `RENAME_EXCHANGE`: atomically swap source and destination entries

use std::sync::Arc;

use tidefs_namespace::Namespace;
use tidefs_types_vfs_core::InodeId;
use tidefs_vfs_engine::{Errno, RequestCtx, VfsEngine};

use tidefs_types_posix_filesystem_adapter_core::rename_flags::{RENAME_EXCHANGE, RENAME_NOREPLACE};
const SUPPORTED_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Result of a rename operation.
pub type RenameResult = Result<(), Errno>;

/// Engine-level rename request including renameat2 flags.
pub struct EngineRenameRequest<'a> {
    pub engine: &'a dyn VfsEngine,
    pub ctx: &'a RequestCtx,
    pub old_parent: InodeId,
    pub old_name: &'a [u8],
    pub new_parent: InodeId,
    pub new_name: &'a [u8],
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// FuseRenameDispatch
// ---------------------------------------------------------------------------

/// Stateful FUSE rename dispatcher that validates FUSE protocol arguments,
/// applies POSIX rename constraints, and delegates to the VFS engine or
/// namespace for atomic directory-entry manipulation.
pub struct FuseRenameDispatch {
    /// Optional namespace handle for direct namespace-level rename.
    /// When present, renames go through the namespace instead of the engine.
    namespace: Option<Arc<Namespace>>,
}

impl FuseRenameDispatch {
    /// Create a new rename dispatcher without a namespace.
    ///
    /// Renames will be dispatched through the VFS engine via
    /// `dispatch_engine_rename`.
    #[must_use]
    pub fn new() -> Self {
        Self { namespace: None }
    }

    /// Attach a [`Namespace`] for direct namespace-level rename operations.
    #[must_use]
    pub fn with_namespace(mut self, ns: Arc<Namespace>) -> Self {
        self.namespace = Some(ns);
        self
    }

    /// Standard POSIX rename: atomically moves `oldname` under `old_parent`
    /// to `newname` under `new_parent`, replacing any existing target.
    ///
    /// Delegates to the engine's [`VfsEngine::rename`] with flags=0.
    ///
    /// # Errors
    ///
    /// Returns `ENOENT`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `EINVAL`, or
    /// `EXDEV` on failure.
    pub fn dispatch_engine_rename(
        &self,
        engine: &dyn VfsEngine,
        ctx: &RequestCtx,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_engine_with_flags(EngineRenameRequest {
            engine,
            ctx,
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags: 0,
        })
    }

    /// `RENAME_NOREPLACE`: same as standard rename but fails with `EEXIST`
    /// if the target name already exists in the destination directory.
    ///
    /// Delegates to the engine's [`VfsEngine::rename`] with
    /// `RENAME_NOREPLACE` flag.
    ///
    /// # Errors
    ///
    /// Returns `ENOENT`, `ENOTDIR`, `EISDIR`, `ENOTEMPTY`, `EINVAL`,
    /// `EEXIST`, or `EXDEV` on failure.
    pub fn dispatch_engine_rename_noreplace(
        &self,
        engine: &dyn VfsEngine,
        ctx: &RequestCtx,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_engine_with_flags(EngineRenameRequest {
            engine,
            ctx,
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags: RENAME_NOREPLACE,
        })
    }

    /// `RENAME_EXCHANGE`: atomically swap source and target directory
    /// entries.  Both must exist and be type-compatible.
    ///
    /// # Errors
    ///
    /// Returns `ENOENT` (source or target missing), `ENOTDIR`,
    /// `EINVAL` (type mismatch or invalid flags), or `EXDEV` on failure.
    pub fn dispatch_engine_rename_exchange(
        &self,
        engine: &dyn VfsEngine,
        ctx: &RequestCtx,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_engine_with_flags(EngineRenameRequest {
            engine,
            ctx,
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags: RENAME_EXCHANGE,
        })
    }

    /// Core engine dispatch with flags: validates the combined flags set,
    /// rejects conflicting flag combinations, and delegates to the engine.
    pub fn dispatch_engine_with_flags(&self, request: EngineRenameRequest<'_>) -> RenameResult {
        let EngineRenameRequest {
            engine,
            ctx,
            old_parent,
            old_name,
            new_parent,
            new_name,
            flags,
        } = request;

        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(Errno(libc::EINVAL as u16));
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(Errno(libc::EINVAL as u16));
        }

        engine.rename(old_parent, old_name, new_parent, new_name, flags, ctx)
    }

    /// Standard POSIX rename through the namespace.
    ///
    /// Prefer this path when a namespace is attached and the caller wants
    /// namespace-level semantics (direct dir-index manipulation, finer error
    /// reporting).
    ///
    /// # Panics
    ///
    /// Panics if no namespace was attached via `with_namespace`.
    pub fn dispatch_namespace_rename(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_namespace_with_flags(old_parent, old_name, new_parent, new_name, 0)
    }

    /// `RENAME_NOREPLACE` through the namespace.
    ///
    /// # Panics
    ///
    /// Panics if no namespace was attached via `with_namespace`.
    pub fn dispatch_namespace_rename_noreplace(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_namespace_with_flags(
            old_parent,
            old_name,
            new_parent,
            new_name,
            RENAME_NOREPLACE,
        )
    }

    /// `RENAME_EXCHANGE` through the namespace.
    ///
    /// # Panics
    ///
    /// Panics if no namespace was attached via `with_namespace`.
    pub fn dispatch_namespace_rename_exchange(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
    ) -> RenameResult {
        self.dispatch_namespace_with_flags(
            old_parent,
            old_name,
            new_parent,
            new_name,
            RENAME_EXCHANGE,
        )
    }

    /// Core namespace dispatch with flags.
    fn dispatch_namespace_with_flags(
        &self,
        old_parent: InodeId,
        old_name: &[u8],
        new_parent: InodeId,
        new_name: &[u8],
        flags: u32,
    ) -> RenameResult {
        let ns = self
            .namespace
            .as_ref()
            .expect("FuseRenameDispatch::dispatch_namespace_* called without a namespace");

        let old_name_str = std::str::from_utf8(old_name).map_err(|_| Errno(libc::EINVAL as u16))?;
        let new_name_str = std::str::from_utf8(new_name).map_err(|_| Errno(libc::EINVAL as u16))?;

        let old_parent_raw = old_parent.get();
        let new_parent_raw = new_parent.get();
        ns.rename_with_flags(
            old_parent_raw,
            old_name_str,
            new_parent_raw,
            new_name_str,
            flags,
        )
        .map_err(map_namespace_error)
    }
}

impl Default for FuseRenameDispatch {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map `tidefs_namespace::NamespaceError` to a FUSE `Errno`.
pub fn map_namespace_error(err: tidefs_namespace::NamespaceError) -> Errno {
    use tidefs_namespace::NamespaceError;
    match err {
        NamespaceError::NotFound | NamespaceError::InodeNotFound => Errno(libc::ENOENT as u16),
        NamespaceError::AlreadyExists => Errno(libc::EEXIST as u16),
        NamespaceError::NotEmpty => Errno(libc::ENOTEMPTY as u16),
        NamespaceError::NotDirectory => Errno(libc::ENOTDIR as u16),
        NamespaceError::IsDirectory => Errno(libc::EISDIR as u16),
        NamespaceError::InvalidName => Errno(libc::EINVAL as u16),
        NamespaceError::CrossDeviceRename => Errno(libc::EXDEV as u16),
        NamespaceError::RenameCycle => Errno(libc::EINVAL as u16),
        NamespaceError::LinkCountOverflow => Errno(libc::EMLINK as u16),
        NamespaceError::TooManySymlinks => Errno(libc::ELOOP as u16),
        NamespaceError::NotSymlink => Errno(libc::EINVAL as u16),
        NamespaceError::NotSupported => Errno(libc::EOPNOTSUPP as u16),
        NamespaceError::DirIndex(_) => Errno(libc::EIO as u16),

        NamespaceError::StaleCursor => Errno(libc::EAGAIN as u16),

        NamespaceError::DatasetIdentityMismatch { .. } => Errno(libc::EIO as u16),

    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_local_filesystem::{
        human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem,
        LocalFileSystem, RootAuthenticationKey,
    };
    use tidefs_vfs_engine::{RequestCtx, VfsEngine};

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![0],
        }
    }

    fn test_engine() -> (tempfile::TempDir, Box<dyn VfsEngine + Send>) {
        let tmp = tempfile::tempdir().expect("tempdir for rename tests");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = Box::new(VfsLocalFileSystem::new(lfs));
        (tmp, engine)
    }

    // ── same-directory rename ─────────────────────────────────────────

    #[test]
    fn rename_same_directory_moves_entry() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"old.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create source file");

        dispatch
            .dispatch_engine_rename(engine.as_ref(), &ctx, root, b"old.txt", root, b"new.txt")
            .expect("same-dir rename");

        assert!(
            engine.lookup(root, b"old.txt", &ctx).is_err(),
            "old name must be gone after rename"
        );
        assert!(
            engine.lookup(root, b"new.txt", &ctx).is_ok(),
            "new name must exist after rename"
        );
    }

    #[test]
    fn rename_nonexistent_source_returns_enoent() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let result =
            dispatch.dispatch_engine_rename(engine.as_ref(), &ctx, root, b"missing", root, b"dest");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn rename_noreplace_rejects_existing_target() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"src.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create src");
        engine
            .mknod(root, b"dst.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create dst");

        let result = dispatch.dispatch_engine_rename_noreplace(
            engine.as_ref(),
            &ctx,
            root,
            b"src.txt",
            root,
            b"dst.txt",
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::EEXIST as u16);
    }

    #[test]
    fn rename_noreplace_succeeds_when_target_missing() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"src.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create src");

        dispatch
            .dispatch_engine_rename_noreplace(
                engine.as_ref(),
                &ctx,
                root,
                b"src.txt",
                root,
                b"dst.txt",
            )
            .expect("noreplace rename to absent target");

        assert!(engine.lookup(root, b"src.txt", &ctx).is_err());
        assert!(engine.lookup(root, b"dst.txt", &ctx).is_ok());
    }

    #[test]
    fn rename_invalid_flags_returns_einval() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"file.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");

        let result = dispatch.dispatch_engine_with_flags(EngineRenameRequest {
            engine: engine.as_ref(),
            ctx: &ctx,
            old_parent: root,
            old_name: b"file.txt",
            new_parent: root,
            new_name: b"other.txt",
            flags: RENAME_NOREPLACE | RENAME_EXCHANGE,
        });
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn rename_overwrite_existing_file() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let src_attr = engine
            .mknod(root, b"alpha.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create alpha");
        engine
            .mknod(root, b"beta.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create beta");

        dispatch
            .dispatch_engine_rename(engine.as_ref(), &ctx, root, b"alpha.txt", root, b"beta.txt")
            .expect("rename overwrite");

        assert!(engine.lookup(root, b"alpha.txt", &ctx).is_err());
        let beta = engine.lookup(root, b"beta.txt", &ctx).expect("beta exists");
        assert_eq!(beta.inode_id, src_attr.inode_id);
    }

    #[test]
    fn rename_exchange_swaps_file_entries() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let left_attr = engine
            .mknod(root, b"left.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create left");
        let right_attr = engine
            .mknod(root, b"right.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create right");

        dispatch
            .dispatch_engine_rename_exchange(
                engine.as_ref(),
                &ctx,
                root,
                b"left.txt",
                root,
                b"right.txt",
            )
            .expect("rename exchange");

        let left = engine
            .lookup(root, b"left.txt", &ctx)
            .expect("left entry still exists");
        let right = engine
            .lookup(root, b"right.txt", &ctx)
            .expect("right entry still exists");

        assert_eq!(left.inode_id, right_attr.inode_id);
        assert_eq!(right.inode_id, left_attr.inode_id);
    }

    #[test]
    fn rename_exchange_missing_target_returns_enoent() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"present.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");

        let result = dispatch.dispatch_engine_rename_exchange(
            engine.as_ref(),
            &ctx,
            root,
            b"present.txt",
            root,
            b"missing.txt",
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::ENOENT as u16);
    }

    #[test]
    fn rename_cross_directory_moves_entry() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let src_dir = engine
            .mkdir(root, b"src", 0o755, &ctx)
            .expect("create src dir");
        let dst_dir = engine
            .mkdir(root, b"dst", 0o755, &ctx)
            .expect("create dst dir");
        let file_attr = engine
            .mknod(
                src_dir.inode_id,
                b"file.txt",
                libc::S_IFREG | 0o644,
                0,
                &ctx,
            )
            .expect("create file");

        dispatch
            .dispatch_engine_rename(
                engine.as_ref(),
                &ctx,
                src_dir.inode_id,
                b"file.txt",
                dst_dir.inode_id,
                b"moved.txt",
            )
            .expect("cross-dir rename");

        assert!(engine.lookup(src_dir.inode_id, b"file.txt", &ctx).is_err());
        let moved = engine
            .lookup(dst_dir.inode_id, b"moved.txt", &ctx)
            .expect("moved file exists");
        assert_eq!(moved.inode_id, file_attr.inode_id);
    }

    // ── error mapping ────────────────────────────────────────────────

    #[test]
    fn error_mapping_covers_all_variants() {
        use tidefs_namespace::NamespaceError;
        let cases = [
            (NamespaceError::NotFound, libc::ENOENT),
            (NamespaceError::InodeNotFound, libc::ENOENT),
            (NamespaceError::AlreadyExists, libc::EEXIST),
            (NamespaceError::NotEmpty, libc::ENOTEMPTY),
            (NamespaceError::NotDirectory, libc::ENOTDIR),
            (NamespaceError::IsDirectory, libc::EISDIR),
            (NamespaceError::InvalidName, libc::EINVAL),
            (NamespaceError::CrossDeviceRename, libc::EXDEV),
            (NamespaceError::RenameCycle, libc::EINVAL),
            (NamespaceError::LinkCountOverflow, libc::EMLINK),
            (NamespaceError::TooManySymlinks, libc::ELOOP),
            (NamespaceError::NotSymlink, libc::EINVAL),
            (NamespaceError::NotSupported, libc::EOPNOTSUPP),
        ];
        for (err, expected) in &cases {
            assert_eq!(
                map_namespace_error(err.clone()).0,
                *expected as u16,
                "unexpected errno for {err:?}"
            );
        }
    }

    #[test]
    fn namespace_rename_wired_to_dispatch() {
        let ns = Arc::new(tidefs_namespace::Namespace::new());
        ns.create_dir(1, "d1", tidefs_namespace::InodeAttributes::new_dir(0))
            .expect("create d1");
        let file = ns
            .create_file(1, "f.txt", tidefs_namespace::InodeAttributes::new_file(0))
            .expect("create file");

        let dispatch = FuseRenameDispatch::new().with_namespace(Arc::clone(&ns));

        dispatch
            .dispatch_namespace_rename(InodeId::new(1), b"f.txt", InodeId::new(1), b"g.txt")
            .expect("namespace rename");

        assert!(ns.lookup(1, "f.txt").unwrap().is_none());
        assert_eq!(ns.lookup(1, "g.txt").unwrap(), Some(file));
    }

    #[test]
    fn namespace_rename_noreplace_rejects_existing_target() {
        let ns = Arc::new(tidefs_namespace::Namespace::new());
        ns.create_file(1, "src", tidefs_namespace::InodeAttributes::new_file(0))
            .expect("create src");
        ns.create_file(1, "dst", tidefs_namespace::InodeAttributes::new_file(0))
            .expect("create dst");

        let dispatch = FuseRenameDispatch::new().with_namespace(Arc::clone(&ns));

        let result = dispatch.dispatch_namespace_rename_noreplace(
            InodeId::new(1),
            b"src",
            InodeId::new(1),
            b"dst",
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::EEXIST as u16);
    }

    #[test]
    fn namespace_rename_exchange_swaps() {
        let ns = Arc::new(tidefs_namespace::Namespace::new());
        let left = ns
            .create_file(1, "left", tidefs_namespace::InodeAttributes::new_file(0))
            .expect("create left");
        let right = ns
            .create_file(1, "right", tidefs_namespace::InodeAttributes::new_file(0))
            .expect("create right");

        let dispatch = FuseRenameDispatch::new().with_namespace(Arc::clone(&ns));

        dispatch
            .dispatch_namespace_rename_exchange(InodeId::new(1), b"left", InodeId::new(1), b"right")
            .expect("namespace exchange");

        assert_eq!(ns.lookup(1, "left").unwrap(), Some(right));
        assert_eq!(ns.lookup(1, "right").unwrap(), Some(left));
    }

    // ── directory rename tests ──────────────────────────────────────

    #[test]
    fn rename_empty_dir_over_empty_dir_replaces_target() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let src = engine
            .mkdir(root, b"src-dir", 0o755, &ctx)
            .expect("create src dir");
        engine
            .mkdir(root, b"dst-dir", 0o755, &ctx)
            .expect("create dst dir");

        dispatch
            .dispatch_engine_rename(engine.as_ref(), &ctx, root, b"src-dir", root, b"dst-dir")
            .expect("rename empty dir over empty dir");

        assert!(engine.lookup(root, b"src-dir", &ctx).is_err());
        let dst = engine
            .lookup(root, b"dst-dir", &ctx)
            .expect("dst-dir exists");
        assert_eq!(dst.inode_id, src.inode_id);
    }

    #[test]
    fn rename_dir_over_nonempty_dir_returns_enotempty() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mkdir(root, b"src-dir", 0o755, &ctx)
            .expect("create src dir");
        let dst = engine
            .mkdir(root, b"dst-dir", 0o755, &ctx)
            .expect("create dst dir");
        engine
            .mknod(dst.inode_id, b"child.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create child in dst");

        let result = dispatch.dispatch_engine_rename(
            engine.as_ref(),
            &ctx,
            root,
            b"src-dir",
            root,
            b"dst-dir",
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::ENOTEMPTY as u16);
    }

    #[test]
    fn rename_dir_into_descendant_is_rejected() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        let parent = engine
            .mkdir(root, b"parent", 0o755, &ctx)
            .expect("create parent dir");
        let child = engine
            .mkdir(parent.inode_id, b"child", 0o755, &ctx)
            .expect("create child dir");

        // Try to rename parent into its own child — should be rejected.
        let result = dispatch.dispatch_engine_rename(
            engine.as_ref(),
            &ctx,
            root,
            b"parent",
            child.inode_id,
            b"moved",
        );
        assert!(result.is_err());
        // The engine should return EINVAL for rename cycle.
        assert_eq!(result.unwrap_err().0, libc::EINVAL as u16);
    }

    #[test]
    fn rename_file_over_dir_returns_eisdir() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine
            .mknod(root, b"file.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");
        engine.mkdir(root, b"dir", 0o755, &ctx).expect("create dir");

        let result =
            dispatch.dispatch_engine_rename(engine.as_ref(), &ctx, root, b"file.txt", root, b"dir");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::EISDIR as u16);
    }

    #[test]
    fn rename_dir_over_file_returns_enotdir() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);
        let dispatch = FuseRenameDispatch::new();

        engine.mkdir(root, b"dir", 0o755, &ctx).expect("create dir");
        engine
            .mknod(root, b"file.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");

        let result =
            dispatch.dispatch_engine_rename(engine.as_ref(), &ctx, root, b"dir", root, b"file.txt");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().0, libc::ENOTDIR as u16);
    }
}

// ── Parent directory mtime/ctime update tests ─────────────────────────

#[cfg(test)]
mod parent_timestamp_tests {
    use super::*;
    use tidefs_local_filesystem::{
        human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem,
        LocalFileSystem, RootAuthenticationKey,
    };

    fn test_engine() -> (tempfile::TempDir, Box<dyn VfsEngine + Send>) {
        let tmp = tempfile::tempdir().expect("tempdir for parent timestamp tests");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = Box::new(VfsLocalFileSystem::new(lfs));
        (tmp, engine)
    }

    fn test_ctx() -> RequestCtx {
        RequestCtx {
            uid: 0,
            gid: 0,
            pid: 0,
            umask: 0,
            groups: vec![0],
        }
    }

    /// Return (mtime_ns, ctime_ns) for an inode.
    fn get_timestamps(engine: &dyn VfsEngine, ino: InodeId, ctx: &RequestCtx) -> (i64, i64) {
        let attr = engine.getattr(ino, None, ctx).expect("getattr");
        (attr.posix.mtime_ns, attr.posix.ctime_ns)
    }

    #[test]
    fn mkdir_updates_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine.mkdir(root, b"subdir", 0o755, &ctx).expect("mkdir");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after mkdir"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after mkdir"
        );
        assert!(engine.lookup(root, b"subdir", &ctx).is_ok());
    }

    #[test]
    fn create_updates_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine
            .mknod(root, b"newfile", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("mknod (create file)");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after file creation"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after file creation"
        );
        assert!(engine.lookup(root, b"newfile", &ctx).is_ok());
    }

    #[test]
    fn create_existing_file_does_not_update_parent_timestamps() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // First create the file.
        engine
            .mknod(root, b"existing", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");

        // Record timestamps after first creation.
        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);

        // Open the existing file with O_CREAT (no O_EXCL, no O_TRUNC).
        let (_, _fh) = engine
            .create(root, b"existing", 0o644, 0, &ctx)
            .expect("open existing");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert_eq!(
            mtime_after, mtime_before,
            "parent mtime must NOT change when opening existing file"
        );
        assert_eq!(
            ctime_after, ctime_before,
            "parent ctime must NOT change when opening existing file"
        );
    }

    #[test]
    fn unlink_updates_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create and release a file first so it can be unlinked.
        let (_, fh) = engine
            .create(root, b"victim", 0o644, 0, &ctx)
            .expect("create file");
        engine.release(&fh).expect("release handle");

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine.unlink(root, b"victim", &ctx).expect("unlink");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after unlink"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after unlink"
        );
        assert!(engine.lookup(root, b"victim", &ctx).is_err());
    }

    #[test]
    fn rmdir_updates_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        engine.mkdir(root, b"emptydir", 0o755, &ctx).expect("mkdir");

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine.rmdir(root, b"emptydir", &ctx).expect("rmdir");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after rmdir"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after rmdir"
        );
        assert!(engine.lookup(root, b"emptydir", &ctx).is_err());
    }

    #[test]
    fn symlink_updates_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine
            .symlink(root, b"mylink", b"/target", &ctx)
            .expect("symlink");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after symlink"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after symlink"
        );
        assert!(engine.lookup(root, b"mylink", &ctx).is_ok());
    }

    #[test]
    fn link_updates_new_parent_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file.
        let (src_attr, src_fh) = engine
            .create(root, b"source", 0o644, 0, &ctx)
            .expect("create source");
        engine.release(&src_fh).expect("release source handle");

        // Create subdirectory to link into.
        let subdir = engine
            .mkdir(root, b"sub", 0o755, &ctx)
            .expect("mkdir subdir");

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), subdir.inode_id, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine
            .link(src_attr.inode_id, subdir.inode_id, b"alias", &ctx)
            .expect("link");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), subdir.inode_id, &ctx);
        assert!(
            mtime_after > mtime_before,
            "new parent mtime must advance after link"
        );
        assert!(
            ctime_after > ctime_before,
            "new parent ctime must advance after link"
        );
        assert!(engine.lookup(subdir.inode_id, b"alias", &ctx).is_ok());
    }

    #[test]
    fn rename_updates_both_parents_mtime_and_ctime() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        // Create source file in root.
        engine
            .mknod(root, b"src.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create src");

        // Create target directory.
        let dst_dir = engine.mkdir(root, b"dst", 0o755, &ctx).expect("mkdir dst");

        let (src_mtime_before, src_ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        let (dst_mtime_before, dst_ctime_before) =
            get_timestamps(engine.as_ref(), dst_dir.inode_id, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine
            .rename(root, b"src.txt", dst_dir.inode_id, b"moved.txt", 0, &ctx)
            .expect("cross-dir rename");

        let (src_mtime_after, src_ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        let (dst_mtime_after, dst_ctime_after) =
            get_timestamps(engine.as_ref(), dst_dir.inode_id, &ctx);

        assert!(
            src_mtime_after > src_mtime_before,
            "old parent mtime must advance after rename"
        );
        assert!(
            src_ctime_after > src_ctime_before,
            "old parent ctime must advance after rename"
        );
        assert!(
            dst_mtime_after > dst_mtime_before,
            "new parent mtime must advance after rename"
        );
        assert!(
            dst_ctime_after > dst_ctime_before,
            "new parent ctime must advance after rename"
        );

        assert!(engine.lookup(root, b"src.txt", &ctx).is_err());
        assert!(engine.lookup(dst_dir.inode_id, b"moved.txt", &ctx).is_ok());
    }

    #[test]
    fn rename_same_directory_updates_parent_once() {
        let (_tmp, engine) = test_engine();
        let ctx = test_ctx();
        let root = InodeId::new(1);

        engine
            .mknod(root, b"old.txt", libc::S_IFREG | 0o644, 0, &ctx)
            .expect("create file");

        let (mtime_before, ctime_before) = get_timestamps(engine.as_ref(), root, &ctx);
        std::thread::sleep(std::time::Duration::from_millis(1));

        engine
            .rename(root, b"old.txt", root, b"new.txt", 0, &ctx)
            .expect("same-dir rename");

        let (mtime_after, ctime_after) = get_timestamps(engine.as_ref(), root, &ctx);
        assert!(
            mtime_after > mtime_before,
            "parent mtime must advance after same-dir rename"
        );
        assert!(
            ctime_after > ctime_before,
            "parent ctime must advance after same-dir rename"
        );
        assert!(engine.lookup(root, b"old.txt", &ctx).is_err());
        assert!(engine.lookup(root, b"new.txt", &ctx).is_ok());
    }
}
