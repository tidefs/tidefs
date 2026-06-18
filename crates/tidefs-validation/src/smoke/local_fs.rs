// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local-filesystem smoke: deterministic open/close and lifecycle operation
//! recording against `LocalFileSystem`.
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

    // Open the filesystem.
    let _fs = LocalFileSystem::open(&root_path).expect("open LocalFileSystem");

    // Record a placeholder lifecycle op.
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "mount".to_string(),
        payload: b"".to_vec(),
    });

    h.assert_ev("local-fs opened", true);

    // Close.
    h.record(TraceEvent::FsClose);

    drop(_fs);
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
