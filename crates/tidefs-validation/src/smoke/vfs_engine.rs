// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFS engine smoke: deterministic runtime checks through `VfsEngine`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_local_filesystem::{vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem};
use tidefs_vfs_engine::{Errno, NodeKind, RequestCtx, SetAttr, VfsEngine, FATTR_SIZE};

/// Run the full VFS engine smoke sequence and return the harness.
#[must_use]
pub fn run_vfs_engine_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("vfs-engine/smoke");

    let dir = tempfile::TempDir::new().expect("tempdir for vfs-engine smoke");
    let root_path = dir.path().to_str().unwrap().to_string();
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));

    h.record(TraceEvent::FsOpen {
        root_path: root_path.clone(),
    });
    let fs = LocalFileSystem::open(&root_path).expect("open local filesystem");
    let engine = VfsLocalFileSystem::new(fs);
    let ctx = request_ctx();

    let root = engine.get_root_inode(&ctx).expect("root inode");
    h.record(TraceEvent::InodeGetattr {
        inode_id: root.get(),
    });
    let root_attr = engine.getattr(root, None, &ctx).expect("root getattr");
    h.assert_ev("root inode id is nonzero", root.get() > 0);
    h.assert_eq_ev("root is a directory", root_attr.kind, NodeKind::Dir);

    h.record(TraceEvent::NamespaceCreate {
        parent: root.get(),
        name: b"engine.txt".to_vec(),
        mode: 0o644,
    });
    let (file_attr, file_handle) = engine
        .create(root, b"engine.txt", 0o644, 0, &ctx)
        .expect("create engine smoke file");
    h.assert_eq_ev("created node is a file", file_attr.kind, NodeKind::File);

    h.record(TraceEvent::DirLookup {
        name: b"engine.txt".to_vec(),
    });
    let looked_up = engine
        .lookup(root, b"engine.txt", &ctx)
        .expect("lookup created file");
    h.assert_eq_ev(
        "lookup returns created inode",
        looked_up.inode_id,
        file_attr.inode_id,
    );
    h.assert_eq_ev("new file starts empty", looked_up.posix.size, 0u64);

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file_attr.inode_id.get(),
        op_name: "vfs_engine.write".to_string(),
        payload: b"vfs smoke".to_vec(),
    });
    let written = engine
        .write(&file_handle, 0, b"vfs smoke", &ctx)
        .expect("write through vfs engine");
    h.assert_eq_ev("write returns byte count", written, 9u32);

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file_attr.inode_id.get(),
        op_name: "vfs_engine.read".to_string(),
        payload: Vec::new(),
    });
    let data = engine
        .read(&file_handle, 0, 9, &ctx)
        .expect("read through vfs engine");
    h.assert_eq_ev("read returns written bytes", data, b"vfs smoke".to_vec());

    h.record(TraceEvent::InodeSetattr {
        inode_id: file_attr.inode_id.get(),
        attr_mask: u64::from(FATTR_SIZE),
    });
    let mut set_size = SetAttr::new();
    set_size.valid = FATTR_SIZE;
    set_size.size = 4;
    let shrunk = engine
        .setattr(file_attr.inode_id, &set_size, Some(&file_handle), &ctx)
        .expect("setattr size through vfs engine");
    h.assert_eq_ev("setattr updates file size", shrunk.posix.size, 4u64);

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file_attr.inode_id.get(),
        op_name: "vfs_engine.read_after_setattr".to_string(),
        payload: Vec::new(),
    });
    let shrunk_data = engine
        .read(&file_handle, 0, 9, &ctx)
        .expect("read after setattr through vfs engine");
    h.assert_eq_ev(
        "read after shrink returns truncated bytes",
        shrunk_data,
        b"vfs ".to_vec(),
    );

    h.record(TraceEvent::NamespaceCreate {
        parent: root.get(),
        name: b"subdir".to_vec(),
        mode: 0o755,
    });
    let dir_attr = engine
        .mkdir(root, b"subdir", 0o755, &ctx)
        .expect("mkdir through vfs engine");
    h.assert_eq_ev("mkdir creates directory", dir_attr.kind, NodeKind::Dir);

    let dir_handle = engine.opendir(root, &ctx).expect("opendir root");
    h.record(TraceEvent::DirIter { cookie: 0 });
    let (entries, has_more) = engine
        .readdir(&dir_handle, 0, &ctx)
        .expect("readdir through vfs engine");
    h.assert_ev("root readdir is complete", !has_more);
    h.assert_ev(
        "root readdir includes created directory",
        entries.iter().any(|entry| {
            entry.name.as_slice() == b"subdir"
                && entry.inode_id == dir_attr.inode_id
                && entry.kind == NodeKind::Dir
        }),
    );
    engine
        .releasedir(&dir_handle)
        .expect("release root directory handle");

    h.record(TraceEvent::NamespaceUnlink {
        parent: root.get(),
        name: b"engine.txt".to_vec(),
    });
    engine
        .unlink(root, b"engine.txt", &ctx)
        .expect("unlink through vfs engine");
    h.record(TraceEvent::DirLookup {
        name: b"engine.txt".to_vec(),
    });
    let missing = engine.lookup(root, b"engine.txt", &ctx);
    h.assert_ev(
        "lookup after unlink returns ENOENT",
        matches!(missing, Err(Errno::ENOENT)),
    );

    h.record(TraceEvent::FsClose);
    drop(engine);
    dir.close().ok();

    h.scenario_end("vfs-engine/smoke");
    h
}

fn request_ctx() -> RequestCtx {
    RequestCtx {
        uid: 1000,
        gid: 1000,
        pid: 1,
        umask: 0o022,
        groups: vec![1000],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vfs_engine_smoke_passes() {
        let h = run_vfs_engine_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }

    #[test]
    fn vfs_engine_smoke_trace_round_trips() {
        let h = run_vfs_engine_smoke();
        let data = crate::trace::serialize_trace(&h.trace).expect("serialize vfs-engine smoke");
        let round_trip =
            crate::trace::deserialize_trace(&data).expect("deserialize vfs-engine smoke");
        assert_eq!(h.trace, round_trip);
    }
}
