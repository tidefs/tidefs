// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Focused public fsync commit/reopen coverage.

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_local_object_store::checksum64;

// ── helpers ───────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("tidefs-wb-val-{label}-"))
        .tempdir()
        .expect("create temp dir")
}

fn open_fs(dir: &tempfile::TempDir) -> LocalFileSystem {
    LocalFileSystem::open(dir.path()).expect("open filesystem")
}

// ── tests ─────────────────────────────────────────────────────────

// ── fsync/fdatasync intent-log boundaries ──────────────────────────

#[test]
fn fsync_commits_clears_intent_and_survives_reopen() {
    set_test_key();
    let dir = temp_dir("fsync_commit_reopen");
    let payload: Vec<u8> = b"fsync-committed-intent-data".to_vec();

    {
        let mut fs = open_fs(&dir);
        let rec = fs
            .create_file("/fsynced", DEFAULT_FILE_PERMISSIONS)
            .expect("create file");
        fs.sync_write_intent(
            rec.inode_id,
            0,
            payload.len() as u64,
            checksum64(&payload),
            &payload,
        )
        .expect("record sync-write intent");
        assert!(fs.intent_log_entry_count() > 0);

        fs.fsync_file("/fsynced").expect("fsync file");
        assert!(fs.intent_log_is_empty());
        assert_eq!(fs.read_file("/fsynced").expect("read live data"), payload);
    }

    let fs = open_fs(&dir);
    assert_eq!(
        fs.read_file("/fsynced").expect("read reopened data"),
        payload
    );
    assert!(fs.intent_log_is_empty());
}
