// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local-filesystem smoke: deterministic open/create/write/read/close checks
//! against `LocalFileSystem`.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_local_filesystem::LocalFileSystem;

/// Run the full local-filesystem smoke sequence and return the harness.
#[must_use]
pub fn run_local_fs_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("local-fs/smoke");

    // Set root auth key required by LocalFileSystem::open.
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));

    // Open: create a temp directory as the store root.
    let dir = tempfile::TempDir::new().expect("tempdir for local-fs smoke");
    let root_path = dir.path().to_str().unwrap().to_string();

    h.record(TraceEvent::FsOpen {
        root_path: root_path.clone(),
    });

    // Open the filesystem and perform a small real readback operation.
    let mut fs = LocalFileSystem::open(&root_path).expect("open LocalFileSystem");
    let file_path = "/smoke-file";
    let payload = b"local-fs smoke";
    let file = fs
        .create_file(file_path, 0o644)
        .expect("create local-fs smoke file");
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file.inode_id.get(),
        op_name: "local_fs.write".to_string(),
        payload: payload.to_vec(),
    });
    fs.write_file(file_path, 0, payload)
        .expect("write local-fs smoke file");

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: file.inode_id.get(),
        op_name: "local_fs.read".to_string(),
        payload: Vec::new(),
    });
    let read_back = fs.read_file(file_path).expect("read local-fs smoke file");
    h.assert_eq_ev(
        "local-fs readback matches write",
        read_back,
        payload.to_vec(),
    );

    // Close.
    h.record(TraceEvent::FsClose);

    drop(fs);
    dir.close().ok();

    h.scenario_end("local-fs/smoke");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_fs_smoke_passes() {
        let h = run_local_fs_smoke();
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
}
