// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! End-to-end FUSE mount-path smoke test harness for committed dispatch
//! surfaces.
//!
//! Exercises `FuseRenameDispatch` and `FileHandleTable` through the daemon's
//! dispatch modules without requiring an actual kernel FUSE mount. Each test
//! creates a temporary in-memory TideFS stack and dispatches operations
//! directly through the VFS engine and dispatch modules.
//!
//! An adapter-level harness (`AdapterTestHarness`) wraps
//! `FuseVfsAdapter` to exercise the full daemon dispatch path for
//! operations that have committed adapter dispatch methods
//! (e.g. rename, lookup).
//!
//! ## Feature gating
//!
//! Tests declare their minimum `FeatureGate`:
//! - `Committed`: module is landed and wired; test runs unconditionally.
//! - `Claimed`: module has an active implementation issue; test is a stub.
//! - `NotReady`: module is not yet scoped; test is a stub.

use std::cell::RefCell;

use std::sync::Arc;
use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, open_dispatch::FileHandleTable,
    vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem, RootAuthenticationKey,
};
use tidefs_namespace::Namespace;
use tidefs_posix_filesystem_adapter_daemon::fuse_rename::{
    EngineRenameRequest, FuseRenameDispatch,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::{FuseVfsAdapter, VfsCreateDispatch};
use tidefs_posix_filesystem_adapter_daemon::workers_meta::FuseAttrOut;
use tidefs_vfs_engine::{
    EngineFileHandle, Errno, FileHandleId, InodeAttr, InodeId, RequestCtx, VfsEngine,
};

// ── Feature gate ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum FeatureGate {
    Committed,
    #[allow(dead_code)]
    Claimed,
    #[allow(dead_code)]
    NotReady,
}

// ── Test harness ─────────────────────────────────────────────────────────

/// Holds a running VFS engine backed by a temporary object store.
struct TestHarness {
    _temp: tempfile::TempDir,
    engine: VfsLocalFileSystem,
    rename_dispatch: FuseRenameDispatch,
}

impl TestHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir for FUSE e2e harness");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem for e2e harness");
        let engine = VfsLocalFileSystem::new(lfs);
        let rename_dispatch = FuseRenameDispatch::new();
        Self {
            _temp: tmp,
            engine,
            rename_dispatch,
        }
    }

    fn vfs(&self) -> &VfsLocalFileSystem {
        &self.engine
    }

    fn fh_table(&self) -> &RefCell<FileHandleTable> {
        self.engine.file_handle_table()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

const ROOT_INODE: u64 = 1;

fn test_ctx() -> RequestCtx {
    RequestCtx {
        uid: 0,
        gid: 0,
        pid: 0,
        umask: 0,
        groups: vec![0],
    }
}

fn root() -> InodeId {
    InodeId::new(ROOT_INODE)
}

fn create_file(harness: &TestHarness, name: &[u8], mode: u32) -> Result<InodeAttr, Errno> {
    let ctx = test_ctx();
    harness
        .vfs()
        .mknod(root(), name, libc::S_IFREG | mode, 0 /* rdev */, &ctx)
}

fn lookup(harness: &TestHarness, name: &[u8]) -> Result<InodeAttr, Errno> {
    let ctx = test_ctx();
    harness.vfs().lookup(root(), name, &ctx)
}

fn create_dir(harness: &TestHarness, name: &[u8], mode: u32) -> Result<InodeAttr, Errno> {
    let ctx = test_ctx();
    harness.vfs().mkdir(root(), name, mode, &ctx)
}

// ── Phase A: Rename tests (committed surface) ────────────────────────────

#[test]
fn test_rename_basic_file() {
    let h = TestHarness::new();

    create_file(&h, b"old.txt", 0o644).expect("create old.txt");

    let ctx = test_ctx();
    h.rename_dispatch
        .dispatch_engine_rename(h.vfs(), &ctx, root(), b"old.txt", root(), b"new.txt")
        .expect("rename old.txt -> new.txt");

    assert!(
        lookup(&h, b"old.txt").is_err(),
        "old.txt must not exist after rename"
    );
    assert!(
        lookup(&h, b"new.txt").is_ok(),
        "new.txt must exist after rename"
    );
}

#[test]
fn test_rename_exchange() {
    let h = TestHarness::new();

    let left = create_file(&h, b"left.txt", 0o644).expect("create left.txt");
    let right = create_file(&h, b"right.txt", 0o644).expect("create right.txt");

    let ctx = test_ctx();
    h.rename_dispatch
        .dispatch_engine_rename_exchange(h.vfs(), &ctx, root(), b"left.txt", root(), b"right.txt")
        .expect("rename exchange left <-> right");

    let new_left = lookup(&h, b"left.txt").expect("left.txt must exist after exchange");
    let new_right = lookup(&h, b"right.txt").expect("right.txt must exist after exchange");

    assert_eq!(
        new_left.inode_id, right.inode_id,
        "left.txt should now have right's inode"
    );
    assert_eq!(
        new_right.inode_id, left.inode_id,
        "right.txt should now have left's inode"
    );
}

#[test]
fn test_rename_overwrite() {
    let h = TestHarness::new();

    let src = create_file(&h, b"src.txt", 0o644).expect("create src.txt");
    let _dst = create_file(&h, b"dst.txt", 0o644).expect("create dst.txt");

    let ctx = test_ctx();
    h.rename_dispatch
        .dispatch_engine_rename(h.vfs(), &ctx, root(), b"src.txt", root(), b"dst.txt")
        .expect("rename src.txt -> dst.txt (overwrite)");

    assert!(
        lookup(&h, b"src.txt").is_err(),
        "src.txt must not exist after overwrite rename"
    );
    let dst = lookup(&h, b"dst.txt").expect("dst.txt must exist after rename");
    assert_eq!(
        dst.inode_id, src.inode_id,
        "dst.txt should have src's inode after overwrite"
    );
}

#[test]
fn test_rename_enoent_source() {
    let h = TestHarness::new();

    let ctx = test_ctx();
    let result = h.rename_dispatch.dispatch_engine_rename(
        h.vfs(),
        &ctx,
        root(),
        b"missing.txt",
        root(),
        b"dest.txt",
    );

    assert!(result.is_err(), "rename of nonexistent source must fail");
    assert_eq!(result.unwrap_err().0, libc::ENOENT as u16);
}

#[test]
fn test_rename_noreplace_rejects_existing_target() {
    let h = TestHarness::new();

    create_file(&h, b"src.txt", 0o644).expect("create src.txt");
    create_file(&h, b"dst.txt", 0o644).expect("create dst.txt");

    let ctx = test_ctx();
    let result = h.rename_dispatch.dispatch_engine_rename_noreplace(
        h.vfs(),
        &ctx,
        root(),
        b"src.txt",
        root(),
        b"dst.txt",
    );

    assert!(
        result.is_err(),
        "RENAME_NOREPLACE must fail when target exists"
    );
    assert_eq!(result.unwrap_err().0, libc::EEXIST as u16);
}

#[test]
fn test_rename_noreplace_succeeds_when_target_missing() {
    let h = TestHarness::new();

    create_file(&h, b"src.txt", 0o644).expect("create src.txt");

    let ctx = test_ctx();
    h.rename_dispatch
        .dispatch_engine_rename_noreplace(h.vfs(), &ctx, root(), b"src.txt", root(), b"dst.txt")
        .expect("RENAME_NOREPLACE must succeed when target is missing");

    assert!(lookup(&h, b"src.txt").is_err(), "src.txt must be gone");
    assert!(lookup(&h, b"dst.txt").is_ok(), "dst.txt must exist");
}

// ── Phase A: Open / release tests (committed surface) ────────────────────

#[test]
fn test_open_valid_fh() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"test.bin", 0o644).expect("create test.bin");
    let ctx = test_ctx();

    let fh = h
        .vfs()
        .open(attr.inode_id, 0 /* O_RDONLY */, &ctx)
        .expect("open test.bin");

    // The allocated handle is tracked in the file-handle table.
    let table = h.fh_table().borrow();
    assert!(
        table.lookup(fh.fh_id).is_some(),
        "open handle must be in the file-handle table"
    );
    assert!(fh.fh_id.get() > 0, "allocated handle id must be non-zero");
}

#[test]
fn test_release_removes_fh() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"release_me.bin", 0o644).expect("create file");
    let ctx = test_ctx();
    let fh = h.vfs().open(attr.inode_id, 0, &ctx).expect("open file");

    assert!(
        h.fh_table().borrow().lookup(fh.fh_id).is_some(),
        "handle must be present before release"
    );

    h.vfs().release(&fh).expect("release file handle");

    assert!(
        h.fh_table().borrow().lookup(fh.fh_id).is_none(),
        "handle must be removed after release"
    );
}

#[test]
fn test_stale_fh_rejected() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"stale.bin", 0o644).expect("create file");
    let ctx = test_ctx();
    let fh = h
        .vfs()
        .open(attr.inode_id, 2 /* O_RDWR */, &ctx)
        .expect("open file");
    h.vfs().release(&fh).expect("release file");

    // Read with a released (stale) handle must return EBADF.
    let result = h.vfs().read(&fh, 0, 16, &ctx);
    assert!(result.is_err(), "read with stale fh must fail");
    assert_eq!(
        result.unwrap_err(),
        Errno::EBADF,
        "expected EBADF for stale handle"
    );
}

#[test]
fn test_open_readonly_write_rejected() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"readonly.bin", 0o644).expect("create file");
    let ctx = test_ctx();
    let fh = h
        .vfs()
        .open(attr.inode_id, 0 /* O_RDONLY */, &ctx)
        .expect("open readonly");

    // Write on O_RDONLY handle must fail with EBADF.
    let result = h.vfs().write(&fh, 0, b"data", &ctx);
    assert!(result.is_err(), "write on O_RDONLY handle must fail");
    assert_eq!(
        result.unwrap_err(),
        Errno::EBADF,
        "expected EBADF for write on read-only handle"
    );
}

#[test]
fn test_open_writeonly_read_rejected() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"writeonly.bin", 0o644).expect("create file");
    let ctx = test_ctx();
    let fh = h
        .vfs()
        .open(attr.inode_id, 1 /* O_WRONLY */, &ctx)
        .expect("open writeonly");

    // Read on O_WRONLY handle must fail with EBADF.
    let result = h.vfs().read(&fh, 0, 16, &ctx);
    assert!(result.is_err(), "read on O_WRONLY handle must fail");
    assert_eq!(
        result.unwrap_err(),
        Errno::EBADF,
        "expected EBADF for read on write-only handle"
    );
}

#[test]
fn test_open_release_idempotent() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"idem.bin", 0o644).expect("create file");
    let ctx = test_ctx();
    let fh = h.vfs().open(attr.inode_id, 0, &ctx).expect("open file");

    h.vfs().release(&fh).expect("first release");

    // Second release on the same handle must also return EBADF.
    let result = h.vfs().release(&fh);
    assert!(result.is_err(), "second release must fail");
    assert_eq!(
        result.unwrap_err(),
        Errno::EBADF,
        "expected EBADF on double release"
    );
}

#[test]
fn test_fabricated_fh_rejected() {
    let h = TestHarness::new();

    let fake_fh = EngineFileHandle {
        inode_id: InodeId::new(999),
        open_flags: 0,
        fh_id: FileHandleId::new(9999),
        lock_owner: 0,
    };

    let ctx = test_ctx();
    let result = h.vfs().read(&fake_fh, 0, 16, &ctx);
    assert!(result.is_err(), "fabricated handle must be rejected");
    assert_eq!(
        result.unwrap_err(),
        Errno::EBADF,
        "expected EBADF for fabricated handle"
    );
}

// ── Phase A extension: Additional committed-surface tests ──────────────

#[test]
fn test_rename_cross_directory() {
    let h = TestHarness::new();

    let subdir = create_dir(&h, b"subdir", 0o755).expect("create subdir");
    let file_attr = create_file(&h, b"file.txt", 0o644).expect("create file");

    let ctx = test_ctx();
    h.rename_dispatch
        .dispatch_engine_rename(
            h.vfs(),
            &ctx,
            root(),
            b"file.txt",
            subdir.inode_id,
            b"moved.txt",
        )
        .expect("rename file.txt into subdir/moved.txt");

    // Source must be gone from root.
    assert!(
        lookup(&h, b"file.txt").is_err(),
        "file.txt must be gone from root"
    );
    // Target must exist under subdir.
    let moved = h
        .vfs()
        .lookup(subdir.inode_id, b"moved.txt", &ctx)
        .expect("moved.txt must exist under subdir");
    assert_eq!(
        moved.inode_id, file_attr.inode_id,
        "moved.txt should have the original inode"
    );
}

#[test]
fn test_rename_invalid_flags() {
    let h = TestHarness::new();

    create_file(&h, b"a.txt", 0o644).expect("create a.txt");

    // RENAME_NOREPLACE | RENAME_EXCHANGE is a conflicting combination.
    let ctx = test_ctx();
    let result = h
        .rename_dispatch
        .dispatch_engine_with_flags(EngineRenameRequest {
            engine: h.vfs(),
            ctx: &ctx,
            old_parent: root(),
            old_name: b"a.txt",
            new_parent: root(),
            new_name: b"b.txt",
            flags: 0x01 | 0x02, /* NOREPLACE | EXCHANGE */
        });

    assert!(result.is_err(), "conflicting rename flags must fail");
    assert_eq!(result.unwrap_err().0, libc::EINVAL as u16);
}

#[test]
fn test_rename_unsupported_flag() {
    let h = TestHarness::new();

    create_file(&h, b"a.txt", 0o644).expect("create a.txt");

    // Bit not in SUPPORTED_FLAGS (0x04 = RENAME_WHITEOUT).
    let ctx = test_ctx();
    let result = h
        .rename_dispatch
        .dispatch_engine_with_flags(EngineRenameRequest {
            engine: h.vfs(),
            ctx: &ctx,
            old_parent: root(),
            old_name: b"a.txt",
            new_parent: root(),
            new_name: b"b.txt",
            flags: 0x04, /* RENAME_WHITEOUT, unsupported */
        });

    assert!(result.is_err(), "unsupported rename flag must fail");
    assert_eq!(result.unwrap_err().0, libc::EINVAL as u16);
}

#[test]
fn test_open_with_o_trunc() {
    let h = TestHarness::new();

    let attr = create_file(&h, b"trunc.bin", 0o644).expect("create file");
    let ctx = test_ctx();

    // Write some data first.
    let fh = h
        .vfs()
        .open(attr.inode_id, 2 /* O_RDWR */, &ctx)
        .expect("open for write");
    h.vfs()
        .write(&fh, 0, b"hello world", &ctx)
        .expect("write data");
    h.vfs().release(&fh).expect("release after write");

    // Re-open with O_TRUNC: file should be emptied.
    const O_TRUNC: u32 = 0o1000;
    let fh2 = h
        .vfs()
        .open(attr.inode_id, 2 | O_TRUNC, &ctx)
        .expect("open with O_TRUNC");

    let data = h.vfs().read(&fh2, 0, 32, &ctx).expect("read after trunc");
    assert!(data.is_empty(), "file must be empty after O_TRUNC open");
    h.vfs().release(&fh2).expect("release truncated handle");
}

// ── Adapter-level harness ────────────────────────────────────────────────

/// Harness wrapping a `FuseVfsAdapter` for tests that exercise the full
/// daemon dispatch path (engine → adapter → FUSE protocol boundary).
///
/// Unlike `TestHarness` which calls engine/dispatch functions directly,
/// this harness routes operations through the adapter's `dispatch_*`
/// methods, providing higher-fidelity integration coverage.
struct AdapterTestHarness {
    _temp: tempfile::TempDir,
    adapter: FuseVfsAdapter,
}

impl AdapterTestHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir for adapter harness");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem for adapter harness");
        let engine = VfsLocalFileSystem::new(lfs);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create FuseVfsAdapter");
        Self {
            _temp: tmp,
            adapter,
        }
    }

    /// Send a synthetic FUSE request through the adapter's dispatch loop.
    ///
    /// Currently supports the subset of FUSE operations whose adapter
    /// dispatch methods are committed.  Expand as new dispatch batches land.
    fn send_fuse_request(
        &self,
        ctx: &RequestCtx,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<InodeAttr, Errno> {
        // Uses dispatch_mknod as the canonical "create entity" path
        // through the adapter layer.
        self.adapter
            .dispatch_mknod(ctx, parent, name, mode, 0 /* rdev */)
    }

    /// Adapter-level rename: routes through dispatch_rename (adapter
    /// validates flags via FuseRenameDispatch, acquires engine lock, and
    /// delegates to the engine).
    fn rename(
        &self,
        ctx: &RequestCtx,
        old_parent: u64,
        old_name: &[u8],
        new_parent: u64,
        new_name: &[u8],
        flags: u32,
    ) -> Result<(), Errno> {
        self.adapter
            .dispatch_rename(ctx, old_parent, old_name, new_parent, new_name, flags)
    }

    /// Adapter-level lookup: routes through dispatch_lookup.
    fn lookup(&self, ctx: &RequestCtx, parent: u64, name: &[u8]) -> Result<InodeAttr, Errno> {
        self.adapter.dispatch_lookup(ctx, parent, name)
    }
}

/// Adapter-level harness that wires a [`Namespace`] into the FUSE adapter
/// so that dispatched operations exercise the namespace-backed code paths
/// (dir-index lookup, inode-table attribute retrieval).
struct NamespaceAdapterTestHarness {
    _temp: tempfile::TempDir,
    adapter: FuseVfsAdapter,
    ns: Arc<Namespace>,
}

impl NamespaceAdapterTestHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir for namespace adapter harness");
        let lfs = LocalFileSystem::open_with_root_authentication_key(
            tmp.path(),
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem for namespace harness");
        let engine = VfsLocalFileSystem::new(lfs);
        let ns = Arc::new(Namespace::new());
        let adapter = FuseVfsAdapter::new(Box::new(engine))
            .expect("create FuseVfsAdapter")
            .with_namespace(Arc::clone(&ns));
        Self {
            _temp: tmp,
            adapter,
            ns,
        }
    }

    /// Pre-populate a directory entry through the namespace so the
    /// namespace-backed lookup path can resolve it.  Uses the engine
    /// mkdir/create path to build the parent directory, then inserts
    /// the child entry directly into the namespace.
    fn insert_namespace_entry(&self, parent: u64, name: &str, mode: u32) -> u64 {
        use tidefs_namespace::InodeAttributes;
        let now = std::time::SystemTime::now();
        let kind_bits = mode & libc::S_IFMT;
        let attrs = InodeAttributes {
            inode: 0,
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            nlink: if kind_bits == libc::S_IFDIR { 2 } else { 1 },
            atime: now,
            mtime: now,
            ctime: now,
            rdev: 0,
        };

        if kind_bits == libc::S_IFDIR {
            self.ns
                .create_dir(parent, name, attrs)
                .expect("namespace create_dir")
        } else {
            self.ns
                .create_file(parent, name, attrs)
                .expect("namespace create_file")
        }
    }

    /// Look up a path component through the adapter's dispatch_lookup,
    /// which routes through the namespace when one is attached.
    fn lookup(&self, ctx: &RequestCtx, parent: u64, name: &[u8]) -> Result<InodeAttr, Errno> {
        self.adapter.dispatch_lookup(ctx, parent, name)
    }
}

// ── Adapter-level integration tests ──────────────────────────────────────

#[test]
fn test_adapter_create_and_lookup() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    // Create a file through the adapter dispatch path.
    let attr = h
        .send_fuse_request(&ctx, ROOT_INODE, b"adapter_file.txt", libc::S_IFREG | 0o644)
        .expect("create file via adapter");

    assert!(
        attr.inode_id.get() > ROOT_INODE,
        "adapter-created file must have a valid inode"
    );

    // Look it up through the adapter path.
    let found = h
        .lookup(&ctx, ROOT_INODE, b"adapter_file.txt")
        .expect("lookup via adapter");
    assert_eq!(
        found.inode_id, attr.inode_id,
        "lookup must return the same inode as creation"
    );
}

#[test]
fn test_adapter_rename_roundtrip() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    // Create source file through adapter.
    h.send_fuse_request(&ctx, ROOT_INODE, b"src.txt", libc::S_IFREG | 0o644)
        .expect("create src via adapter");

    // Rename through adapter dispatch_rename.
    h.rename(&ctx, ROOT_INODE, b"src.txt", ROOT_INODE, b"dst.txt", 0)
        .expect("rename via adapter");

    // Old name gone, new name resolves.
    assert!(
        h.lookup(&ctx, ROOT_INODE, b"src.txt").is_err(),
        "old name must be gone after adapter rename"
    );
    assert!(
        h.lookup(&ctx, ROOT_INODE, b"dst.txt").is_ok(),
        "new name must resolve after adapter rename"
    );
}

#[test]
fn test_adapter_lookup_enoent() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    let result = h.lookup(&ctx, ROOT_INODE, b"nonexistent");
    assert!(result.is_err(), "adapter lookup of missing file must fail");
    assert_eq!(result.unwrap_err(), Errno::ENOENT);
}

// ── Adapter-level extension: create, mkdir, getattr ────────────────────

impl AdapterTestHarness {
    /// Create a regular file through the adapter's `dispatch_create` path,
    /// returning the inode attributes and adapter file handle.
    fn create_file(
        &self,
        ctx: &RequestCtx,
        parent: u64,
        name: &[u8],
        mode: u32,
        open_flags: u32,
    ) -> Result<VfsCreateDispatch, Errno> {
        self.adapter
            .dispatch_create(ctx, parent, name, mode, open_flags)
    }

    /// Create a directory through the adapter's `dispatch_mkdir` path.
    fn mkdir(
        &self,
        ctx: &RequestCtx,
        parent: u64,
        name: &[u8],
        mode: u32,
    ) -> Result<InodeAttr, Errno> {
        self.adapter.dispatch_mkdir(ctx, parent, name, mode)
    }

    /// Get attributes through the adapter's `dispatch_getattr` path.
    fn getattr(&self, ctx: &RequestCtx, ino: u64) -> Result<FuseAttrOut, Errno> {
        self.adapter
            .dispatch_getattr(ctx, ino, 0 /* unique */, None /* fh */)
    }
}

#[test]
fn test_adapter_create_file_with_handle() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    let result = h
        .create_file(
            &ctx,
            ROOT_INODE,
            b"created.bin",
            libc::S_IFREG | 0o644,
            0, /* O_RDONLY */
        )
        .expect("dispatch_create via adapter");

    assert!(
        result.inode() > ROOT_INODE,
        "created file must have a valid inode"
    );
    assert!(
        result.file_handle() > 0,
        "create must return a valid adapter file handle"
    );
}

#[test]
fn test_adapter_mkdir_and_lookup() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    let dir_attr = h
        .mkdir(&ctx, ROOT_INODE, b"newdir", 0o755)
        .expect("dispatch_mkdir via adapter");

    assert!(
        dir_attr.inode_id.get() > ROOT_INODE,
        "created directory must have a valid inode"
    );

    let found = h
        .lookup(&ctx, ROOT_INODE, b"newdir")
        .expect("lookup of created directory via adapter");
    assert_eq!(
        found.inode_id, dir_attr.inode_id,
        "lookup must return same inode as mkdir"
    );
}

#[test]
fn test_adapter_getattr_roundtrip() {
    let h = AdapterTestHarness::new();
    let ctx = test_ctx();

    // Create a file through adapter mknod.
    let created = h
        .send_fuse_request(&ctx, ROOT_INODE, b"attr_test.bin", libc::S_IFREG | 0o644)
        .expect("create file for attr test");

    // Get attributes through adapter dispatch_getattr.
    let attr = h
        .getattr(&ctx, created.inode_id.get())
        .expect("dispatch_getattr via adapter");

    assert_eq!(
        attr.attr.ino,
        created.inode_id.get(),
        "getattr ino must match created inode"
    );
    assert!(
        attr.attr.mode & libc::S_IFMT == libc::S_IFREG,
        "getattr mode must indicate RegularFile"
    );
}

// ── Phase B stubs (gated behind Claimed / NotReady) ──────────────────────

// ── Namespace-backed lookup tests ────────────────────────────────────────

#[test]
fn test_namespace_lookup_existing_file() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    // Pre-populate a file entry in the namespace root dir.
    let child_ino = h.insert_namespace_entry(root, "hello.txt", libc::S_IFREG | 0o644);

    // Resolve it through the adapter dispatch_lookup -> namespace path.
    let found = h
        .lookup(&ctx, root, b"hello.txt")
        .expect("namespace-backed lookup should find existing file");
    assert_eq!(
        found.inode_id.get(),
        child_ino,
        "lookup must return the correct inode"
    );
    assert_eq!(
        found.kind,
        tidefs_vfs_engine::NodeKind::File,
        "lookup must report File kind"
    );
}

#[test]
fn test_namespace_lookup_existing_directory() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    let subdir_ino = h.insert_namespace_entry(root, "mydir", libc::S_IFDIR | 0o755);

    let found = h
        .lookup(&ctx, root, b"mydir")
        .expect("namespace-backed lookup should find directory");
    assert_eq!(found.inode_id.get(), subdir_ino);
    assert_eq!(found.kind, tidefs_vfs_engine::NodeKind::Dir);
}

#[test]
fn test_namespace_lookup_enoent() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    let err = h
        .lookup(&ctx, root, b"not_there")
        .expect_err("lookup for nonexistent name must fail");
    assert_eq!(err, Errno::ENOENT);
}

#[test]
fn test_namespace_lookup_empty_directory() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    // Create a subdirectory via namespace, then lookup a name in it.
    let subdir_ino = h.insert_namespace_entry(root, "empty_dir", libc::S_IFDIR | 0o755);

    // Looking up a nonexistent name in an empty directory should return ENOENT.
    let err = h
        .lookup(&ctx, subdir_ino, b"nobody_home")
        .expect_err("lookup in empty directory should return ENOENT");
    assert_eq!(err, Errno::ENOENT);
}

#[test]
fn test_namespace_lookup_enotdir() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    // Create a regular file via namespace.
    let file_ino = h.insert_namespace_entry(root, "regular.txt", libc::S_IFREG | 0o644);

    // Trying to look up 'anything' inside a regular file should return ENOTDIR.
    let err = h
        .lookup(&ctx, file_ino, b"anything")
        .expect_err("lookup inside a regular file must return ENOTDIR");
    assert_eq!(err, Errno::ENOTDIR);
}

#[test]
fn test_namespace_lookup_enoent_missing_parent() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();

    // Parent inode 9999 was never allocated.
    let err = h
        .lookup(&ctx, 9999, b"anything")
        .expect_err("lookup on nonexistent parent must fail");
    assert_eq!(err, Errno::ENOENT);
}

#[test]
fn test_namespace_lookup_created_then_resolved() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    // Create a file via the namespace-backed adapter create dispatch.
    let created = h
        .adapter
        .dispatch_create(
            &ctx,
            root,
            b"newfile.bin",
            libc::S_IFREG | 0o600,
            0, /* flags */
        )
        .expect("create via namespace-backed adapter");

    // Resolve it through lookup (also namespace-backed).
    let found = h
        .lookup(&ctx, root, b"newfile.bin")
        .expect("lookup after create should succeed");
    assert_eq!(
        found.inode_id.get(),
        created.inode(),
        "lookup ino must match create ino"
    );
}

#[test]
fn test_namespace_lookup_multiple_children() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    let mut inos = Vec::new();
    for i in 0..5 {
        let name = format!("child_{i}");
        let ino = h.insert_namespace_entry(root, &name, libc::S_IFREG | 0o644);
        inos.push(ino);
    }

    for (i, &expected_ino) in inos.iter().enumerate() {
        let name = format!("child_{i}");
        let found = h
            .lookup(&ctx, root, name.as_bytes())
            .expect("namespace-backed lookup for multiple children");
        assert_eq!(found.inode_id.get(), expected_ino);
    }
}

#[test]
fn test_namespace_lookup_invalid_name_rejected() {
    let h = NamespaceAdapterTestHarness::new();
    let ctx = test_ctx();
    let root = ROOT_INODE;

    // Names containing '/' should be rejected (EINVAL).
    let err = h
        .lookup(&ctx, root, b"bad/name")
        .expect_err("lookup with invalid name must fail");
    assert!(
        err == Errno::EINVAL || err == Errno::ENOENT,
        "invalid name lookup should return EINVAL or ENOENT, got {err:?}"
    );
}

#[test]
fn test_create_gated_behind_claimed() {
    let _gate = FeatureGate::Claimed;
    eprintln!("SKIP: create dispatch not yet committed (see #3582)");
}
