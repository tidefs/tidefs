// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Retention and GC validation for content-addressed chunk dedup canonical
//! targets (#5966, #6167).
//!
//! Verifies that dedup redirects resolve correctly after partial file deletion
//! (retention), and that canonical objects are reclaimed through the durable
//! `DedupRefCount` authority when all file references are removed.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_FILE_PERMISSIONS, FILESYSTEM_ROOT_SLOT_COUNT,
};

const CHUNK_SIZE: usize = 65536;
const DATA_SIZE: usize = CHUNK_SIZE; // single chunk for simple fingerprint tracking

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-dgc-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_data(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = 0xABu8;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// ── Retention: canonical object survives while any file references it ─

#[test]
fn canonical_object_retained_while_any_file_references_it() {
    set_test_key();
    let dir = temp_dir("dedup_retention");
    let payload = make_data(DATA_SIZE);

    // Write two files with identical content.  The first write creates a
    // canonical chunk object; the second produces a dedup redirect.
    {
        let mut fs = open_fs(&dir);
        fs.set_dedup_enabled(true)
            .expect("test setup mutation must be admitted");

        fs.create_file("/a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create a");
        fs.write_file("/a.bin", 0, &payload).expect("write a");

        fs.create_file("/b.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create b");
        fs.write_file("/b.bin", 0, &payload).expect("write b");

        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        assert!(
            stats.dedup_hits > 0,
            "expected dedup hits with dedup enabled, got hits={} total={}",
            stats.dedup_hits,
            stats.total_chunks
        );

        // Both files must be readable
        assert_eq!(fs.read_file("/a.bin").unwrap(), payload);
        assert_eq!(fs.read_file("/b.bin").unwrap(), payload);
    }

    // Delete file A, reopen — file B must still be readable.
    {
        let mut fs = open_fs(&dir);
        fs.unlink("/a.bin").expect("unlink a");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        assert_eq!(
            fs.read_file("/b.bin").unwrap(),
            payload,
            "file B must be readable after A is deleted"
        );
    }
}

// ── Orphan GC gap: canonical objects survive when all files are deleted ─

#[test]
fn canonical_object_reclaimed_after_all_files_deleted() {
    set_test_key();
    let dir = temp_dir("dedup_reclaim_all");
    let payload = make_data(DATA_SIZE);

    // Write content with dedup enabled, creating a canonical object.
    {
        let mut fs = open_fs(&dir);
        fs.set_dedup_enabled(true)
            .expect("test setup mutation must be admitted");

        fs.create_file("/only.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/only.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        assert_eq!(
            stats.total_chunks, 1,
            "expected 1 chunk written, got {}",
            stats.total_chunks
        );
    }

    // Delete and close before the retained fallback ring advances. The
    // per-inode chunk is a redirect even for the first deduplicated write;
    // its exact reclaim obligation must survive this reopen boundary.
    {
        let mut fs = open_fs(&dir);
        fs.unlink("/only.bin").expect("unlink");
        fs.sync_all().expect("sync");
        assert!(
            fs.reclaim_queue_depth() > 0,
            "the pre-delete fallback root must keep exact content reclaim pending"
        );
    }

    // Reopen proves the local queue is durable. Reclaim must remain pending
    // while the pre-delete root can still be selected. Then publish enough
    // later roots to retire every slot that can reference the deleted file.
    {
        let mut fs = open_fs(&dir);
        assert!(
            fs.reclaim_queue_depth() > 0,
            "exact reclaim obligations must survive close/reopen"
        );
        fs.tick_background_services()
            .expect("tick background services");
        assert!(
            fs.reclaim_queue_depth() > 0,
            "reclaim must not bypass a still-mountable fallback root"
        );

        for index in 0..FILESYSTEM_ROOT_SLOT_COUNT {
            fs.create_file(
                format!("/retire-fallback-{index}"),
                DEFAULT_FILE_PERMISSIONS,
            )
            .expect("publish post-delete mutation");
            fs.sync_all().expect("commit post-delete mutation");
        }
        fs.tick_background_services()
            .expect("drain after fallback retirement");
        assert_eq!(
            fs.reclaim_queue_depth(),
            0,
            "exact queue must drain after every referencing fallback root retires"
        );
    }

    // Reopen with dedup enabled and write the same content again.
    // With the DedupRefCount authority (#6167), the canonical object
    // should be reclaimed after all references are gone.  A same-content
    // rewrite will be a miss (no cross-session canonical-object probe hit)
    // and a new canonical object is created.
    {
        let mut fs = open_fs(&dir);
        fs.set_dedup_enabled(true)
            .expect("test setup mutation must be admitted");

        fs.create_file("/again.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create again");
        fs.write_file("/again.bin", 0, &payload)
            .expect("write again");
        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        // After reclaim, the canonical object is gone.  A same-content
        // rewrite creates a new canonical with dedup_hits=0 (no existing
        // canonical to redirect to).
        assert_eq!(
            stats.dedup_hits, 0,
            "canonical dedup object was reclaimed: expected miss, got hits={} total={}",
            stats.dedup_hits, stats.total_chunks
        );

        // Data integrity: the new file must read correctly
        assert_eq!(
            fs.read_file("/again.bin").unwrap(),
            payload,
            "file re-written after orphan reclamation must be readable"
        );
    }
}

// ── Retention: canonical dedup redirects resolve after reopen ────────

#[test]
fn dedup_redirects_resolve_after_reopen() {
    set_test_key();
    let dir = temp_dir("dedup_reopen_resolve");
    let payload = make_data(DATA_SIZE);

    // Write two identical files with dedup enabled.
    {
        let mut fs = open_fs(&dir);
        fs.set_dedup_enabled(true)
            .expect("test setup mutation must be admitted");
        fs.create_file("/first.bin", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/first.bin", 0, &payload).unwrap();
        fs.create_file("/second.bin", DEFAULT_FILE_PERMISSIONS)
            .unwrap();
        fs.write_file("/second.bin", 0, &payload).unwrap();
        fs.sync_all().unwrap();
    }

    // Reopen — both files must still be readable. The second file's
    // content is stored as a dedup redirect pointing at the canonical
    // object; read resolution must follow that redirect.
    {
        let fs = open_fs(&dir);
        assert_eq!(fs.read_file("/first.bin").unwrap(), payload);
        assert_eq!(fs.read_file("/second.bin").unwrap(), payload);
    }
}
