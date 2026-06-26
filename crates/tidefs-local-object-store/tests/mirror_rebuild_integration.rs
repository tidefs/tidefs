// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Mirror rebuild integration test: device-loss simulation and rebuild
//! from surviving replica.
//!
//! Covers the full mirror-rebuild pipeline:
//! 1. Create a mirror-configured store (primary + mirror replica)
//! 2. Write objects through the primary store
//! 3. Verify the mirror holds a complete copy
//! 4. Delete the primary store's segment files (simulating device loss)
//! 5. Rebuild from the surviving mirror into a fresh replacement store
//! 6. Verify the replacement store has all objects intact

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreOptions};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-mirror-rebuild-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn mirror_opts(mirror_path: PathBuf) -> StoreOptions {
    let mut opts = StoreOptions::test_fast();
    opts.mirror_path = Some(mirror_path);
    opts
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

/// Full mirror-rebuild lifecycle: write -> lose primary -> rebuild -> verify.
#[test]
fn mirror_loss_and_rebuild() {
    let primary_root = temp_root("primary");
    let mirror_root = temp_root("mirror");
    let replacement_root = temp_root("replacement");

    // -- Phase 1: Write data through mirror-configured store --------------
    let payloads: Vec<&[u8]> = vec![
        b"zero",
        b"one-one",
        b"two-two-two",
        b"three-three-three",
        b"four-four-four-four",
        b"five-five-five-five-five",
    ];
    let mut written_keys: Vec<ObjectKey> = Vec::new();

    {
        let mut primary =
            LocalObjectStore::open_with_options(&primary_root, mirror_opts(mirror_root.clone()))
                .expect("open primary with mirror");

        for payload in &payloads {
            let key = primary.put_content_addressed(payload).expect("put");
            written_keys.push(key);
        }
        primary.sync_all().expect("sync primary");
    }

    // -- Phase 2: Verify mirror holds a complete copy ---------------------
    {
        let mirror = LocalObjectStore::open_with_options(&mirror_root, StoreOptions::test_fast())
            .expect("open mirror");
        let mirror_keys: Vec<_> = mirror.list_keys();
        assert_eq!(
            mirror_keys.len(),
            payloads.len(),
            "mirror should have all written objects"
        );
        for (key, expected) in written_keys.iter().zip(payloads.iter()) {
            let got = mirror.get(*key).expect("mirror get").expect("present");
            assert_eq!(&got, expected, "mirror payload mismatch for {key:?}");
        }
    }

    // -- Phase 3: Simulate device loss — delete primary segment files -----
    let segments_dir = primary_root.join("segments");
    if segments_dir.is_dir() {
        for entry in fs::read_dir(&segments_dir).expect("read segments dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_file() {
                fs::remove_file(&path).expect("remove segment file");
            }
        }
    }

    // -- Phase 4: Rebuild from surviving mirror into replacement ----------
    {
        let surviving =
            LocalObjectStore::open_with_options(&mirror_root, StoreOptions::test_fast())
                .expect("open surviving");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            StoreOptions::test_fast(),
        )
        .expect("rebuild from mirror");

        // Verify replacement has all objects.
        let repl_keys: Vec<_> = replacement.list_keys();
        assert_eq!(
            repl_keys.len(),
            payloads.len(),
            "replacement should have all objects after rebuild"
        );
        for (key, expected) in written_keys.iter().zip(payloads.iter()) {
            let got = replacement.get(*key).expect("repl get").expect("present");
            assert_eq!(&got, expected, "replacement payload mismatch for {key:?}");
        }
    }

    // -- Phase 5: Verify replacement persists across reopen ----------------
    {
        let reopened =
            LocalObjectStore::open_with_options(&replacement_root, StoreOptions::test_fast())
                .expect("reopen replacement");
        let reopened_keys: Vec<_> = reopened.list_keys();
        assert_eq!(
            reopened_keys.len(),
            payloads.len(),
            "replacement persists across reopen"
        );
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
    cleanup(&replacement_root);
}

/// Rebuild from empty surviving store (no data ever written to mirror).
#[test]
fn rebuild_after_total_loss_no_data() {
    let primary_root = temp_root("total-loss-pri");
    let mirror_root = temp_root("total-loss-mir");
    let replacement_root = temp_root("total-loss-repl");

    // Open and immediately close — no data written.
    {
        let _primary =
            LocalObjectStore::open_with_options(&primary_root, mirror_opts(mirror_root.clone()))
                .expect("open empty");
    }

    // Delete primary segments.
    let seg_dir = primary_root.join("segments");
    if seg_dir.is_dir() {
        for entry in fs::read_dir(&seg_dir).expect("read seg dir") {
            let path = entry.expect("entry").path();
            if path.is_file() {
                fs::remove_file(&path).expect("rm");
            }
        }
    }

    // Rebuild from surviving (empty) mirror.
    {
        let surviving =
            LocalObjectStore::open_with_options(&mirror_root, StoreOptions::test_fast())
                .expect("open surviving");
        let replacement = LocalObjectStore::rebuild_replica_from_surviving(
            &surviving,
            &replacement_root,
            StoreOptions::test_fast(),
        )
        .expect("rebuild empty");
        assert!(replacement.list_keys().is_empty(), "empty replacement");
    }

    cleanup(&primary_root);
    cleanup(&mirror_root);
    cleanup(&replacement_root);
}
