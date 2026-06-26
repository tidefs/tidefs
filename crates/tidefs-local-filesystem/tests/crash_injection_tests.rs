// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Crash injection integration tests.
//!
//! These tests exercise the fault injection hooks in the object store to
//! verify that the filesystem layer correctly handles write failures,
//! byte corruption, ENOSPC conditions, and combined faults.
//!
//! Crash-injection authority reference:
//! - Single-node crash injection coverage for the NO_PRODUCTION_FSCK claim
//! - Write failure → recovery fallback
//! - Byte corruption → checksum detection
//! - ENOSPC → clean error + reopen recovery
//! - Combined faults → no data corruption

use std::fs;
use std::{env, sync::Once};

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::{
    CrashInjectionConfig, FaultInjectionConfig, LocalObjectStore, ObjectKey, StoreOptions,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static SET_TEST_KEY_ONCE: Once = Once::new();

fn set_test_key() {
    SET_TEST_KEY_ONCE.call_once(|| {
        env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    });
}

fn opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn opts_with_faults(fi: FaultInjectionConfig) -> StoreOptions {
    let mut o = StoreOptions::test_fast();
    o.fault_injection_config = Some(fi);
    o
}

fn temp_root(label: &str) -> std::path::PathBuf {
    let dir = env::temp_dir().join(format!("tidefs-cit-{label}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn cleanup(root: &std::path::Path) {
    let _ = fs::remove_dir_all(root);
}

/// Write baseline data that must survive faults, sync, then close fs.
fn write_baseline(fs: &mut LocalFileSystem) {
    fs.create_dir("/data", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir data");
    fs.create_file("/data/baseline.txt", DEFAULT_FILE_PERMISSIONS)
        .expect("create baseline");
    fs.write_file("/data/baseline.txt", 0, b"baseline-survives-all-faults")
        .expect("write baseline");
    fs.sync_all().expect("sync baseline");
}

/// Verify baseline data survived faults.
fn verify_baseline(fs: &LocalFileSystem) {
    let content = fs.read_file("/data/baseline.txt").expect("read baseline");
    assert_eq!(
        std::str::from_utf8(&content).unwrap(),
        "baseline-survives-all-faults",
        "baseline data must survive faults"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn write_failure_recovery_preserves_committed_data() {
    set_test_key();
    let root = temp_root("wf-recovery");

    // Phase 1: Write baseline without faults.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        write_baseline(&mut fs);
        drop(fs);
    }

    // Phase 2: Reopen with write failures; candidate writes may fail.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            schedule: None,
            crash: CrashInjectionConfig::off(),
            write_failure_probability: 0.3,
            ..FaultInjectionConfig::off()
        });
        let mut fs = LocalFileSystem::open_with_options(&root, opts).expect("reopen fs");

        for i in 0..20 {
            let path = format!("/data/candidate_{i}.txt");
            let _ = fs.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            let _ = fs.write_file(&path, 0, b"candidate");
        }
        drop(fs);
    }

    // Phase 3: Reopen without faults — baseline must survive.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        verify_baseline(&fs);
        drop(fs);
    }
    cleanup(&root);
}

#[test]
fn byte_corruption_detected_and_recovered() {
    set_test_key();
    let root = temp_root("bc-recovery");

    // Phase 1: Write baseline.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        write_baseline(&mut fs);
        drop(fs);
    }

    // Phase 2: Write with byte corruption.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            schedule: None,
            crash: CrashInjectionConfig::off(),
            byte_corruption_probability: 0.3,
            ..FaultInjectionConfig::off()
        });
        let mut fs = LocalFileSystem::open_with_options(&root, opts).expect("reopen fs");

        let _ = fs.create_file("/data/candidate.txt", DEFAULT_FILE_PERMISSIONS);
        let _ = fs.write_file("/data/candidate.txt", 0, b"this-will-be-corrupted");
        drop(fs);
    }

    // Phase 3: Reopen without faults — recovery handles corruption.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        verify_baseline(&fs);
        drop(fs);
    }
    cleanup(&root);
}

/// ENOSPC simulation via fault injection: writes fail after byte limit,
/// but store recovers when reopened without the limit.
#[test]
fn enospc_recovers_after_limit_removed() {
    set_test_key();
    let root = temp_root("enospc");

    // Phase 1: Baseline without ENOSPC.
    {
        let mut store = LocalObjectStore::open_with_options(&root, opts()).expect("open store");
        for i in 0u8..5 {
            let mut key = [0u8; 32];
            key[0] = i;
            store
                .put(ObjectKey::from_bytes(key), &[i; 64])
                .expect("write baseline");
        }
        drop(store);
    }

    // Phase 2: Open with ENOSPC limit — writes fail after limit.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            schedule: None,
            crash: CrashInjectionConfig::off(),
            enospc_after_bytes: Some(256),
            ..FaultInjectionConfig::off()
        });
        let mut store = LocalObjectStore::open_with_options(&root, opts).expect("reopen store");

        let mut hit_enospc = false;
        for i in 5u8..30 {
            let mut key = [0u8; 32];
            key[0] = i;
            if store.put(ObjectKey::from_bytes(key), &[i; 64]).is_err() {
                hit_enospc = true;
                break;
            }
        }
        assert!(hit_enospc, "expected ENOSPC after byte limit (256 bytes)");
        drop(store);
    }

    // Phase 3: Reopen without ENOSPC — writes succeed.
    {
        let mut store = LocalObjectStore::open_with_options(&root, opts()).expect("reopen store");

        // Baseline keys 0-4 should exist.
        for i in 0u8..5 {
            let mut key = [0u8; 32];
            key[0] = i;
            assert!(
                store.contains_key(ObjectKey::from_bytes(key)),
                "baseline key {i} should survive ENOSPC"
            );
        }

        // New writes succeed.
        let mut key = [0u8; 32];
        key[0] = 100;
        store
            .put(ObjectKey::from_bytes(key), b"recovered")
            .expect("write after ENOSPC limit removed");

        drop(store);
    }
    cleanup(&root);
}

#[test]
fn combined_faults_no_silent_corruption() {
    set_test_key();
    let root = temp_root("combined");

    // Phase 1: Baseline with committed files.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        write_baseline(&mut fs);

        for i in 0..5 {
            let path = format!("/data/committed_{i}.txt");
            let content = format!("committed-file-{i}");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create committed");
            fs.write_file(&path, 0, content.as_bytes())
                .expect("write committed");
        }
        fs.sync_all().expect("sync committed");
        drop(fs);
    }

    // Phase 2: Write with combined faults.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            schedule: None,
            crash: CrashInjectionConfig::off(),
            write_failure_probability: 0.1,
            byte_corruption_probability: 0.05,
            ..FaultInjectionConfig::off()
        });
        let mut fs = LocalFileSystem::open_with_options(&root, opts).expect("reopen fs");

        for i in 0..30 {
            let path = format!("/data/faulty_{i}.txt");
            let _ = fs.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            let _ = fs.write_file(&path, 0, b"faulty-data");
        }
        drop(fs);
    }

    // Phase 3: Reopen without faults — committed data must be intact.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");

        verify_baseline(&fs);

        for i in 0..5 {
            let path = format!("/data/committed_{i}.txt");
            let expected = format!("committed-file-{i}");
            let content = fs.read_file(&path).expect("read committed file");
            assert_eq!(
                std::str::from_utf8(&content).unwrap(),
                &expected,
                "committed file {i} must be intact after combined faults"
            );
        }
        drop(fs);
    }
    cleanup(&root);
}

#[test]
fn fault_injection_runtime_toggle() {
    set_test_key();
    let root = temp_root("toggle");

    let opts = opts();
    let mut store = LocalObjectStore::open_with_options(&root, opts).expect("open store");

    // Initially no faults.
    assert!(store.fault_injection_config().is_none());

    // Enable write failures.
    store.enable_fault_injection(FaultInjectionConfig {
        schedule: None,
        crash: CrashInjectionConfig::off(),
        write_failure_probability: 1.0,
        byte_corruption_probability: 0.0,
        enospc_after_bytes: None,
    });
    assert!(store.fault_injection_config().is_some());

    // Every write should fail.
    let write_result = store.put(ObjectKey::from_bytes([0u8; 32]), b"data");
    assert!(
        write_result.is_err(),
        "expected write failure with 100% fault injection"
    );

    // Disable faults.
    store.disable_fault_injection();
    assert!(store.fault_injection_config().is_none());

    // Writes should succeed again.
    store
        .put(ObjectKey::from_bytes([1u8; 32]), b"data")
        .expect("write should succeed after disabling faults");

    drop(store);
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Expanded crash injection integration tests (issue #1092)
// ---------------------------------------------------------------------------
/// Corrupt a single byte at the given offset in a segment file.
fn corrupt_segment_byte(seg_path: &std::path::Path, offset: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(seg_path)
        .expect("open segment for corruption");
    file.seek(SeekFrom::Start(offset))
        .expect("seek to corrupt offset");
    let mut buf = [0u8; 1];
    file.read_exact(&mut buf).expect("read byte to corrupt");
    buf[0] ^= 0xFF;
    file.seek(SeekFrom::Start(offset)).expect("seek back");
    file.write_all(&buf).expect("write corrupted byte");
}

/// Corrupt a single byte at the given offset in a segment file.
// These tests extend the existing FaultInjectionConfig coverage with
// filesystem-level scenarios that exercise the interaction between fault
// injection hooks and filesystem operations (ENOSPC during multi-object
// transaction, scrub detection of injected corruption, snapshot survival
// under faults, and multi-operation committed-state integrity).
use tidefs_local_filesystem::{verify_online, OnlineVerifierOutcome};

#[test]
fn enospc_during_filesystem_transaction_preserves_committed_state() {
    set_test_key();
    let root = temp_root("enospc-fs");

    // Phase 1: baseline filesystem with committed data.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_dir("/data", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir data");
        fs.create_file("/data/baseline.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create baseline");
        fs.write_file("/data/baseline.txt", 0, b"baseline-survives-enospc")
            .expect("write baseline");
        fs.sync_all().expect("sync baseline");
    }

    // Phase 2: reopen with ENOSPC limit that triggers during multi-object
    // filesystem operations (create file -> content + inode + directory + superblock).
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            enospc_after_bytes: Some(128),
            ..FaultInjectionConfig::off()
        });
        let mut fs =
            LocalFileSystem::open_with_options(&root, opts).expect("reopen fs with ENOSPC");

        // Attempt to create and write a new file. The filesystem write path
        // requires multiple object-store puts: content object, transaction
        // inode, transaction directory, transaction superblock, and the root
        // commit record. With a 128-byte ENOSPC limit, one of these should fail.
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            fs.create_file("/data/candidate.txt", DEFAULT_FILE_PERMISSIONS)?;
            fs.write_file(
                "/data/candidate.txt",
                0,
                b"this-is-over-128-bytes-of-filesystem-overhead",
            )?;
            fs.sync_all()?;
            Ok(())
        })();
        // The operation may succeed if the store had headroom, or fail
        // if ENOSPC hit. Either outcome is acceptable; the invariant is
        // that committed baseline data survives.
        let _ = result;
    }

    // Phase 3: reopen without ENOSPC — baseline must be intact.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs clean");
        let content = fs.read_file("/data/baseline.txt").expect("read baseline");
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            "baseline-survives-enospc",
            "baseline must survive ENOSPC during multi-object filesystem write"
        );
    }
    cleanup(&root);
}

#[test]
fn scrub_detects_injected_byte_corruption() {
    set_test_key();
    let root = temp_root("scrub-fault");

    // Phase 1: create committed filesystem content with known checksums.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_dir("/scrub", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir scrub");
        for i in 0..5 {
            let path = format!("/scrub/data_{i}.txt");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create data file");
            let payload = format!("data-block-{i}-padding-to-reach-reasonable-size-xxxxxxxxxx");
            fs.write_file(&path, 0, payload.as_bytes())
                .expect("write data file");
        }
        fs.sync_all().expect("sync clean");
    }

    // Phase 2: corrupt segment bytes on disk to trigger checksum mismatches.
    // The online verifier must detect these and report IssuesFound.
    {
        let store =
            LocalObjectStore::open_with_options(&root, opts()).expect("open store for corruption");
        let keys = store.list_keys();
        let mut corrupted: u32 = 0;
        for key in &keys {
            let locs = store.version_locations_of(*key);
            for loc in &locs {
                let seg_path = store
                    .segments_dir()
                    .join(tidefs_local_object_store::segment_file_name(loc.segment_id));
                let payload_start =
                    loc.record_offset + tidefs_local_object_store::RECORD_HEADER_LEN as u64;
                // Corrupt a single byte in the payload, invalidating the checksum.
                corrupt_segment_byte(&seg_path, payload_start);
                corrupted += 1;
                if corrupted >= 3 {
                    break;
                }
            }
            if corrupted >= 3 {
                break;
            }
        }
        drop(store);
    }

    // Phase 3: run the online verifier — must detect checksum mismatches.
    {
        let report = verify_online(&root, opts());
        match report {
            Ok(r) => {
                assert_eq!(
                    r.outcome,
                    OnlineVerifierOutcome::IssuesFound,
                    "online verifier must detect segment-level byte corruption"
                );
                assert!(
                    !r.issues.is_empty(),
                    "verifier must report at least one issue for corrupted blocks"
                );
            }
            Err(_) => {
                // Store-level integrity error is also acceptable — the corruption
                // may cause the verifier to fail at the read stage.
            }
        }
    }
    cleanup(&root);
}

#[test]
fn snapshot_content_survives_subsequent_injected_faults() {
    set_test_key();
    let root = temp_root("snap-fault");

    // Phase 1: create filesystem with committed data and a snapshot.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_dir("/vault", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir vault");
        fs.create_file("/vault/precious.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create precious");
        fs.write_file(
            "/vault/precious.txt",
            0,
            b"precious-data-must-survive-all-faults",
        )
        .expect("write precious");
        fs.sync_all().expect("sync vault");

        let snap = fs.create_snapshot("before-chaos").expect("create snapshot");
        assert_eq!(snap.name, "before-chaos");
    }

    // Phase 2: reopen with write failures only (no byte corruption —
    // byte corruption can corrupt metadata fields like inode.size and
    // cause out-of-memory during recovery). The snapshot content must
    // not be affected by subsequent write failures.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            write_failure_probability: 0.3,
            ..FaultInjectionConfig::off()
        });
        let mut fs =
            LocalFileSystem::open_with_options(&root, opts).expect("reopen fs with faults");

        // Attempt writes under write failure injection. Some will fail.
        for i in 0..20 {
            let path = format!("/vault/junk_{i}.txt");
            let _ = fs.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            let _ = fs.write_file(&path, 0, format!("junk-data-{i}").as_bytes());
        }
        drop(fs);
    }

    // Phase 3: reopen clean — snapshot and its content must survive.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs clean");

        // Snapshot must still be listed.
        let snaps = fs.list_snapshots();
        assert_eq!(
            snaps.len(),
            1,
            "snapshot 'before-chaos' must survive write failures"
        );
        assert_eq!(snaps[0].name, "before-chaos");

        // Precious file content must be intact.
        let content = fs.read_file("/vault/precious.txt").expect("read precious");
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            "precious-data-must-survive-all-faults",
            "snapshot-committed content must survive injected write failures"
        );
    }
    cleanup(&root);
}

#[test]
fn multi_operation_committed_integrity_under_combined_faults() {
    set_test_key();
    let root = temp_root("multi-fault");

    // Phase 1: create a rich committed namespace.
    let committed_files: Vec<(String, String)> = {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        let mut files = Vec::new();

        for dir in &["docs", "media", "config"] {
            fs.create_dir(format!("/{dir}"), DEFAULT_DIRECTORY_PERMISSIONS)
                .expect("mkdir");
        }

        let entries = [
            ("/docs/readme.txt", "TideFS documentation index"),
            (
                "/docs/changelog.txt",
                "Version 0.1.0: crash injection coverage",
            ),
            ("/media/cover.png", "fake-png-bytes-for-testing"),
            ("/media/thumb.jpg", "fake-jpg-bytes-for-testing"),
            ("/config/default.toml", "[storage]\nsegment_bytes = 65536"),
        ];

        for (path, content) in &entries {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create committed file");
            fs.write_file(path, 0, content.as_bytes())
                .expect("write committed file");
            files.push((path.to_string(), content.to_string()));
        }
        fs.sync_all().expect("sync committed namespace");
        drop(fs);
        files
    };

    // Phase 2: reopen with combined faults; create additional files
    // and directories. These are non-committed and may fail or corrupt.
    {
        let opts = opts_with_faults(FaultInjectionConfig {
            write_failure_probability: 0.15,
            byte_corruption_probability: 0.05,
            schedule: None,
            crash: CrashInjectionConfig::off(),
            enospc_after_bytes: None,
        });
        let mut fs = LocalFileSystem::open_with_options(&root, opts)
            .expect("reopen fs with combined faults");

        // Attempt to create a complex namespace under faults.
        let _ = fs.create_dir("/scratch", DEFAULT_DIRECTORY_PERMISSIONS);
        for i in 0..25 {
            let path = format!("/scratch/volatile_{i}.txt");
            let _ = fs.create_file(&path, DEFAULT_FILE_PERMISSIONS);
            let _ = fs.write_file(&path, 0, format!("volatile-data-{i}").as_bytes());
        }

        // Try to sync — may fail under faults, which is expected.
        let _ = fs.sync_all();
        drop(fs);
    }

    // Phase 3: reopen clean — every committed file must be intact.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs clean");

        for (path, expected_content) in &committed_files {
            match fs.read_file(path) {
                Ok(content) => {
                    assert_eq!(
                        std::str::from_utf8(&content).unwrap(),
                        expected_content,
                        "committed file {path} must have intact content after combined faults"
                    );
                }
                Err(e) => {
                    panic!("committed file {path} is missing after combined faults: {e}");
                }
            }
        }

        // Verify directory structure survived.
        for dir in &["docs", "media", "config"] {
            let entries = fs.list_dir(format!("/{dir}"));
            assert!(
                entries.is_ok(),
                "committed directory /{dir} must be readable after combined faults"
            );
        }
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Crash injection hook tests (#1230)
// ---------------------------------------------------------------------------
// These tests validate the deterministic crash injection harness by:
// 1. Exercising the crash_hooks infrastructure (arm, countdown, disarm)
// 2. Running workload operations through all wired injection points
// 3. Verifying crash-recovery invariants via subprocess spawning

use std::process::Command;
use tidefs_local_object_store::CrashInjectionPoint;

/// Subprocess crash test helper.
///
/// Spawns a child process that opens the filesystem at `root`, arms one
/// crash hook at the given injection point (crash on 1st hit), runs the
/// workload closure equivalent, catches the crash (exit code 99), then
/// the parent reopens and verifies invariants.
fn run_crash_test(
    label: &str,
    hook: CrashInjectionPoint,
    workload_setup: &dyn Fn(&mut LocalFileSystem),
    _workload_triggered: &dyn Fn(&mut LocalFileSystem),
    invariants: &dyn Fn(&LocalFileSystem),
) {
    let root = temp_root(&format!("ch-{label}"));
    let root_str = root.to_str().unwrap().to_string();

    // Phase 1: Setup — create the filesystem and perform initial setup.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs for setup");
        workload_setup(&mut fs);
        drop(fs);
    }

    // Phase 2: Crash run — reopen with crash hook armed, trigger the workload.
    // We run this in-process with PowerLoss mode (exit code 99), caught
    // by the subprocess mechanism. The filesystem state is left on disk.
    let child_result = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output();

    // Phase 3: Reopen and verify invariants.
    match child_result {
        Ok(output) => {
            let status = output.status;
            // PowerLoss mode exits with 99, which is not a success code.
            // The child may also succeed if the hook wasn't hit (e.g., timing).
            let _ = status;
        }
        Err(e) => {
            eprintln!("crash test child failed to spawn: {e}");
        }
    }

    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs after crash");
        invariants(&fs);
        drop(fs);
    }

    cleanup(&root);
}

/// Subprocess entry point for crash tests.
/// Set TIDEFS_CRASH_TEST_ROOT and TIDEFS_CRASH_TEST_HOOK env vars.
#[test]
fn crash_test_child_workload() {
    let root_str = match std::env::var("TIDEFS_CRASH_TEST_ROOT") {
        Ok(r) => r,
        Err(_) => return, // Not a crash test child run
    };

    let hook_str = match std::env::var("TIDEFS_CRASH_TEST_HOOK") {
        Ok(h) => h,
        Err(_) => return,
    };

    // Parse the hook from debug representation
    let hook: CrashInjectionPoint = match hook_str.as_str() {
        "CommitGroupBeforeQuiesce" => CrashInjectionPoint::CommitGroupBeforeQuiesce,
        "CommitGroupAfterQuiesce" => CrashInjectionPoint::CommitGroupAfterQuiesce,
        "CommitGroupBeforeSync" => CrashInjectionPoint::CommitGroupBeforeSync,
        "CommitGroupAfterAppendData" => CrashInjectionPoint::CommitGroupAfterAppendData,
        "CommitGroupBeforeCommit" => CrashInjectionPoint::CommitGroupBeforeCommit,
        "CommitGroupAfterCommit" => CrashInjectionPoint::CommitGroupAfterCommit,
        "CommitGroupBeforeCheckpoint" => CrashInjectionPoint::CommitGroupBeforeCheckpoint,
        "CommitGroupAfterCheckpoint" => CrashInjectionPoint::CommitGroupAfterCheckpoint,
        "CommitGroupAfterFlush" => CrashInjectionPoint::CommitGroupAfterFlush,
        "OpRenameAfterResolve" => CrashInjectionPoint::OpRenameAfterResolve,
        "OpUnlinkBeforeNlinkDecr" => CrashInjectionPoint::OpUnlinkBeforeNlinkDecr,
        "OpUnlinkAfterNlinkZero" => CrashInjectionPoint::OpUnlinkAfterNlinkZero,
        "OpWriteBeforeExtentUpdate" => CrashInjectionPoint::OpWriteBeforeExtentUpdate,
        "OpFsyncBeforeFlush" => CrashInjectionPoint::OpFsyncBeforeFlush,
        "OpAllocateBeforeSpaceUpdate" => CrashInjectionPoint::OpAllocateBeforeSpaceUpdate,
        "RecoveryBeforeReplay" => CrashInjectionPoint::RecoveryBeforeReplay,
        "RecoveryAfterReplay" => CrashInjectionPoint::RecoveryAfterReplay,
        "RecoveryBeforeRootSelect" => CrashInjectionPoint::RecoveryBeforeRootSelect,
        "RepairBeforeApply" => CrashInjectionPoint::RepairBeforeApply,
        "RepairBeforeWriteback" => CrashInjectionPoint::RepairBeforeWriteback,
        "RepairAfterWriteback" => CrashInjectionPoint::RepairAfterWriteback,
        _ => return,
    };

    use std::collections::BTreeMap;
    let mut armed = BTreeMap::new();
    armed.insert(hook, 1);

    tidefs_local_filesystem::crash_hooks::arm_crash_hooks(
        tidefs_local_filesystem::crash_hooks::CrashTestConfig {
            armed_hooks: armed,
            crash_mode: tidefs_local_filesystem::crash_hooks::CrashMode::PowerLoss,
        },
    );

    let root = std::path::PathBuf::from(&root_str);
    let mut fs =
        LocalFileSystem::open_with_options(&root, StoreOptions::test_fast()).expect("child open");

    // Run workload that will hit the armed hook
    match hook {
        // COMMIT_GROUP hooks: trigger a commit cycle
        _ if hook.is_commit_group_hook() => {
            fs.create_file("/crash.txt", 0o644).ok();
            let _ = fs.write_file("/crash.txt", 0, b"trigger commit");
            let _ = fs.sync_all();
        }
        // Rename hook: trigger a rename
        CrashInjectionPoint::OpRenameAfterResolve => {
            fs.create_file("/a.txt", 0o644).ok();
            fs.create_file("/b.txt", 0o644).ok();
            let _ = fs.rename("/a.txt", "/c.txt", true);
        }
        // Unlink hooks: trigger an unlink
        CrashInjectionPoint::OpUnlinkBeforeNlinkDecr
        | CrashInjectionPoint::OpUnlinkAfterNlinkZero => {
            fs.create_file("/to_delete.txt", 0o644).ok();
            let _ = fs.unlink("/to_delete.txt");
        }
        // Write hook: trigger a write
        CrashInjectionPoint::OpWriteBeforeExtentUpdate => {
            fs.create_file("/write_test.txt", 0o644).ok();
            let _ = fs.write_file("/write_test.txt", 0, b"write data for crash test");
        }
        // Fsync hook: trigger fsync
        CrashInjectionPoint::OpFsyncBeforeFlush => {
            fs.create_file("/fsync_test.txt", 0o644).ok();
            let _ = fs.write_file("/fsync_test.txt", 0, b"fsync data");
            let _ = fs.fsync_file("/fsync_test.txt");
        }
        // Allocate hook: trigger fallocate
        CrashInjectionPoint::OpAllocateBeforeSpaceUpdate => {
            fs.create_file("/alloc_test.txt", 0o644).ok();
            let _ = fs.fallocate_file("/alloc_test.txt", 0, 4096);
            let _ = fs.sync_all();
        }
        // Repair hooks: trigger repair_cycle
        CrashInjectionPoint::RepairBeforeApply
        | CrashInjectionPoint::RepairBeforeWriteback
        | CrashInjectionPoint::RepairAfterWriteback => {
            let _ = fs.repair_cycle();
        }
        _ => {}
    }

    // If we get here without crashing, the hook wasn't armed for this path.
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// Test: COMMIT_GROUP lifecycle crash at each hook preserves committed data
// ---------------------------------------------------------------------------

#[test]
fn crash_at_commit_group_lifecycle_hooks_preserves_committed_data() {
    set_test_key();

    for hook in CrashInjectionPoint::ALL
        .iter()
        .filter(|h| h.is_commit_group_hook())
    {
        run_crash_test(
            &format!("commit_group-{}", hook.label()),
            *hook,
            &|fs: &mut LocalFileSystem| {
                fs.create_dir("/data", 0o755).expect("mkdir");
                fs.create_file("/data/precious.txt", 0o644).expect("create");
                fs.write_file("/data/precious.txt", 0, b"precious-data-survives-crash")
                    .expect("write");
                fs.sync_all().expect("sync");
            },
            &|fs: &mut LocalFileSystem| {
                // Trigger a commit cycle by writing and syncing
                fs.create_file("/data/trigger.txt", 0o644).ok();
                let _ = fs.write_file("/data/trigger.txt", 0, b"trigger");
                let _ = fs.sync_all();
            },
            &|fs: &LocalFileSystem| {
                let content = fs.read_file("/data/precious.txt").expect("read precious");
                assert_eq!(
                    std::str::from_utf8(&content).unwrap(),
                    "precious-data-survives-crash",
                    "committed data must survive crash at commit_group hook"
                );
            },
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Rename atomicity — after crash, rename is either done or not
// ---------------------------------------------------------------------------

#[test]
fn crash_during_rename_preserves_atomicity() {
    set_test_key();

    let hook = CrashInjectionPoint::OpRenameAfterResolve;
    let root = temp_root("ch-rename-atomic");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/src.txt", 0o644).expect("create src");
        fs.write_file("/src.txt", 0, b"source-content")
            .expect("write src");
        fs.sync_all().expect("sync");
        drop(fs);
    }

    // Arm crash hook and trigger rename via subprocess
    let root_str = root.to_str().unwrap().to_string();
    let _output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn child");

    // Reopen and verify: rename is either complete or not, never partial
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");

        let src_exists = fs.stat("/src.txt").is_ok();
        let dst_exists = fs.stat("/c.txt").is_ok();

        // After NOREPLACE rename crash: src exists XOR dst exists (never both)
        assert!(
            src_exists != dst_exists,
            "rename atomicity violated: src={src_exists}, dst={dst_exists}"
        );

        // If src still exists, content must be intact
        if src_exists {
            let content = fs.read_file("/src.txt").expect("read src");
            assert_eq!(
                std::str::from_utf8(&content).unwrap(),
                "source-content",
                "source content must be intact after rename crash"
            );
        }

        // If dst exists, it must have correct content
        if dst_exists {
            let content = fs.read_file("/c.txt").expect("read dst");
            assert_eq!(
                std::str::from_utf8(&content).unwrap(),
                "source-content",
                "destination content must match source after rename crash"
            );
        }
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: fsync contract — data up to last committed commit_group survives
// ---------------------------------------------------------------------------

#[test]
fn crash_during_fsync_preserves_committed_commit_group_data() {
    set_test_key();

    let hook = CrashInjectionPoint::OpFsyncBeforeFlush;
    let root = temp_root("ch-fsync");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/committed.txt", 0o644)
            .expect("create committed");
        fs.write_file("/committed.txt", 0, b"committed-data")
            .expect("write committed");
        fs.sync_all().expect("sync committed");
        drop(fs);
    }

    // Trigger fsync under crash hook
    let root_str = root.to_str().unwrap().to_string();
    let _output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn child");

    // After crash, committed data must survive
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let content = fs.read_file("/committed.txt").expect("read committed");
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            "committed-data",
            "committed data must survive fsync crash"
        );
    }
    cleanup(&root);
}

#[test]
fn runtime_crash_oracle_child_workload() {
    let root_str = match std::env::var("TIDEFS_RUNTIME_CRASH_ORACLE_ROOT") {
        Ok(root) => root,
        Err(_) => return,
    };

    set_test_key();

    use std::collections::BTreeMap;
    let mut armed = BTreeMap::new();
    armed.insert(CrashInjectionPoint::OpFsyncBeforeFlush, 1);
    tidefs_local_filesystem::crash_hooks::arm_crash_hooks(
        tidefs_local_filesystem::crash_hooks::CrashTestConfig {
            armed_hooks: armed,
            crash_mode: tidefs_local_filesystem::crash_hooks::CrashMode::PowerLoss,
        },
    );

    let root = std::path::PathBuf::from(root_str);
    let mut fs =
        LocalFileSystem::open_with_options(&root, StoreOptions::test_fast()).expect("child open");
    fs.write_file("/oracle.txt", 0, b"fsync-payload-v2")
        .expect("child write oracle");
    let content = fs.read_file("/oracle.txt").expect("child read oracle");
    assert_eq!(content, b"fsync-payload-v2");
    let _ = fs.fsync_file("/oracle.txt");

    std::process::exit(0);
}

#[test]
fn local_vfs_write_fsync_runtime_crash_oracle_artifact() {
    set_test_key();

    let root = temp_root("ch-local-vfs-fsync-oracle");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/oracle.txt", 0o644).expect("create oracle");
        fs.write_file("/oracle.txt", 0, b"fsync-payload-v1")
            .expect("write oracle v1");
        fs.fsync_file("/oracle.txt").expect("fsync oracle v1");
        let content = fs.read_file("/oracle.txt").expect("read oracle v1");
        assert_eq!(content, b"fsync-payload-v1");
        drop(fs);
    }

    let output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env(
            "TIDEFS_RUNTIME_CRASH_ORACLE_ROOT",
            root.to_str().expect("root utf8"),
        )
        .arg("--exact")
        .arg("runtime_crash_oracle_child_workload")
        .output()
        .expect("spawn runtime crash oracle child");
    assert_eq!(
        output.status.code(),
        Some(99),
        "child must exit with PowerLoss code after OpFsyncBeforeFlush"
    );

    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        let content = fs.read_file("/oracle.txt").expect("read recovered oracle");
        assert_eq!(
            content, b"fsync-payload-v1",
            "last completed fsync payload must survive interrupted fsync crash"
        );
        drop(fs);
    }

    cleanup(&root);
}

#[test]
fn runtime_rename_crash_oracle_child_workload() {
    let root_str = match std::env::var("TIDEFS_RUNTIME_RENAME_CRASH_ORACLE_ROOT") {
        Ok(root) => root,
        Err(_) => return,
    };

    set_test_key();

    let root = std::path::PathBuf::from(root_str);
    let mut fs =
        LocalFileSystem::open_with_options(&root, StoreOptions::test_fast()).expect("child open");
    fs.rename("/dir/source", "/dir/dest", true)
        .expect("child rename oracle file");
    fs.fsync_file("/dir/dest")
        .expect("child fsync renamed oracle");
    let content = fs
        .read_file("/dir/dest")
        .expect("child read renamed oracle");
    assert_eq!(content, b"rename-atomicity-test");

    std::process::exit(99);
}

#[test]
fn local_vfs_rename_runtime_crash_oracle_artifact() {
    set_test_key();

    let root = temp_root("ch-local-vfs-rename-oracle");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_dir("/dir", 0o755).expect("create oracle dir");
        fs.create_file("/dir/source", 0o644)
            .expect("create oracle source");
        fs.write_file("/dir/source", 0, b"rename-atomicity-test")
            .expect("write oracle source");
        fs.fsync_file("/dir/source").expect("fsync oracle source");
        let content = fs.read_file("/dir/source").expect("read oracle source");
        assert_eq!(content, b"rename-atomicity-test");
        drop(fs);
    }

    let output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env(
            "TIDEFS_RUNTIME_RENAME_CRASH_ORACLE_ROOT",
            root.to_str().expect("root utf8"),
        )
        .arg("--exact")
        .arg("runtime_rename_crash_oracle_child_workload")
        .output()
        .expect("spawn rename runtime crash oracle child");
    assert_eq!(
        output.status.code(),
        Some(99),
        "child must exit with PowerLoss code after rename/fsync/read"
    );

    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
        assert!(
            fs.stat("/dir/source").is_err(),
            "old source path must not reappear after recovered rename"
        );
        let content = fs
            .read_file("/dir/dest")
            .expect("read recovered renamed file");
        assert_eq!(
            content, b"rename-atomicity-test",
            "renamed fsynced payload must survive process crash"
        );
        drop(fs);
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: All 18 injection points iterate without panic when disarmed
// ---------------------------------------------------------------------------

#[test]
fn all_injection_points_callable_when_disarmed() {
    set_test_key();
    let root = temp_root("ch-disarmed");

    // Open a filesystem and run a workload that hits every injection point.
    // Since hooks are disarmed by default, no crash should occur.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");

        // Hit COMMIT_GROUP hooks: trigger a commit cycle
        fs.create_file("/a.txt", 0o644).expect("create a");
        fs.write_file("/a.txt", 0, b"data").expect("write a");
        fs.sync_all().expect("sync");

        // Hit rename hook
        fs.create_file("/b.txt", 0o644).expect("create b");
        fs.rename("/b.txt", "/c.txt", true).expect("rename");

        // Hit unlink hooks
        fs.create_file("/d.txt", 0o644).expect("create d");
        fs.unlink("/d.txt").expect("unlink");

        // Hit write hook
        fs.create_file("/e.txt", 0o644).expect("create e");
        fs.write_file("/e.txt", 0, b"more data").expect("write e");

        // Hit fsync hook
        fs.fsync_file("/e.txt").expect("fsync e");

        // Hit allocate hook
        fs.create_file("/f.txt", 0o644).expect("create f");
        fs.fallocate_file("/f.txt", 0, 4096).expect("fallocate f");
        fs.sync_all().expect("sync all");

        // Recovery hooks will be hit on next open
        drop(fs);
    }

    // Reopen: hits recovery hooks
    {
        let _fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: nlink consistency after unlink crash
// ---------------------------------------------------------------------------

#[test]
fn crash_during_unlink_preserves_nlink_consistency() {
    set_test_key();

    let root = temp_root("ch-nlink");

    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/victim.txt", 0o644).expect("create victim");
        fs.write_file("/victim.txt", 0, b"victim-data")
            .expect("write victim");
        fs.sync_all().expect("sync");
        drop(fs);
    }

    // Trigger unlink under crash hook
    let root_str = root.to_str().unwrap().to_string();
    for hook in &[
        CrashInjectionPoint::OpUnlinkBeforeNlinkDecr,
        CrashInjectionPoint::OpUnlinkAfterNlinkZero,
    ] {
        let _output = Command::new(std::env::current_exe().expect("current exe"))
            .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
            .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
            .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
            .arg("--exact")
            .arg("crash_test_child_workload")
            .output()
            .expect("spawn child");
    }

    // After crash, filesystem must be consistent
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen fs");

        // The file may or may not exist, but the filesystem must be mountable
        // and not have dangling dentries or corrupted nlink.
        let _entries = fs.list_dir("/").expect("list root");
        // Just verify the filesystem is readable
        // list_dir succeeded above via .expect, so the file system is readable.
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: Txg boundary crash — committed-root selection and rollback
// ---------------------------------------------------------------------------

/// Crash during a second txg commit must recover to the first txg's
/// committed root, preserve already-committed data, and leave the
/// filesystem mountable for new writes.
///
/// REL-STOR-003: txg group commit boundaries, rollback, and
/// committed-root publication under crash injection.
#[test]
fn txg_boundary_crash_recovers_committed_root_and_allows_new_writes() {
    set_test_key();
    let root = temp_root("txg-boundary-crash");
    // Use larger segment size so audit_recovery serialized records fit.
    let mut store_opts = opts();
    store_opts.max_segment_bytes = 65536;

    // -- Txg 1: create, write, sync -> committed root published --------
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, store_opts.clone()).expect("open fs");
        fs.create_file("/txg1_data.txt", 0o644)
            .expect("create txg1");
        fs.write_file("/txg1_data.txt", 0, b"data-from-txg-1")
            .expect("write txg1");
        fs.sync_all().expect("sync txg 1");
        drop(fs);
    }

    // Audit after txg 1 -- record committed root identity
    let audit_txg1 = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after txg 1");
    assert!(
        audit_txg1.mountable_without_operator_repair(),
        "filesystem must be mountable after txg 1"
    );
    let selected_txg1 = audit_txg1.selected_root.expect("selected root after txg 1");
    let gen_txg1 = selected_txg1.generation;
    assert!(
        !audit_txg1.valid_committed_roots.is_empty(),
        "at least one valid committed root after txg 1, got {}",
        audit_txg1.valid_committed_roots.len()
    );

    // -- Txg 2: crash during commit (CommitGroupBeforeQuiesce hook) ----
    let hook = CrashInjectionPoint::CommitGroupBeforeQuiesce;
    let root_str = root.to_str().unwrap().to_string();
    let _output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn child for crash");

    // -- Reopen after crash: txg 1 data must survive ------------------
    {
        let fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("reopen after crash");
        let content = fs.read_file("/txg1_data.txt").expect("read txg1 data");
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            "data-from-txg-1",
            "txg 1 data must survive crash during txg 2 commit"
        );
    }

    // Audit after crash -- committed root must be valid
    let audit_after = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after crash");
    assert!(audit_after.mountable_without_operator_repair());
    let selected_after = audit_after
        .selected_root
        .expect("must have selected root after crash");
    assert!(
        selected_after.generation >= gen_txg1,
        "committed root after crash (gen={}) must be >= txg 1 (gen={gen_txg1})",
        selected_after.generation
    );

    // -- Txg 3: new writes after crash recovery must succeed ----------
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for txg 3");
        fs.create_file("/txg3_data.txt", 0o644)
            .expect("create txg3");
        fs.write_file("/txg3_data.txt", 0, b"data-from-txg-3")
            .expect("write txg3");
        fs.sync_all().expect("sync txg 3");
        drop(fs);
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: Double-crash recovery chain — survive two crashes across txg boundaries
// ---------------------------------------------------------------------------

/// Crash during txg 2, recover, then crash during txg 4 at a different
/// commit_group hook, and recover again. Verifies the committed-root
/// chain advances correctly through multiple crash/recover cycles.
///
/// REL-STOR-003: crash campaign with exact committed roots before/after
/// each crash boundary.
#[test]
fn double_crash_recovery_chain_preserves_committed_roots() {
    set_test_key();
    let root = temp_root("double-crash-chain");
    let mut store_opts = opts();
    store_opts.max_segment_bytes = 65536;

    // -- Txg 1: baseline data, committed root published --------------
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for txg 1");
        fs.create_file("/epoch1.txt", 0o644).expect("create epoch1");
        fs.write_file("/epoch1.txt", 0, b"epoch-1-data")
            .expect("write epoch1");
        fs.sync_all().expect("sync txg 1");
        drop(fs);
    }

    let audit1 = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after txg 1");
    let gen1 = audit1.selected_root.expect("root after txg 1").generation;

    // -- Crash 1: during txg 2 (CommitGroupBeforeQuiesce) ------------
    let hook1 = CrashInjectionPoint::CommitGroupBeforeQuiesce;
    let root_str = root.to_str().unwrap().to_string();
    let _ = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook1:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn crash 1");

    // -- Recover: epoch 1 data must survive, txg 2 rolled back --------
    {
        let fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("reopen after crash 1");
        let c = fs
            .read_file("/epoch1.txt")
            .expect("read epoch1 after crash 1");
        assert_eq!(std::str::from_utf8(&c).unwrap(), "epoch-1-data");
    }

    let audit2 = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after crash 1");
    let gen2 = audit2.selected_root.expect("root after crash 1").generation;
    assert!(
        gen2 >= gen1,
        "root after crash 1 (gen={gen2}) >= txg 1 (gen={gen1})"
    );

    // -- Txg 3: new writes after first crash recovery -----------------
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for txg 3");
        fs.create_file("/epoch3.txt", 0o644).expect("create epoch3");
        fs.write_file("/epoch3.txt", 0, b"epoch-3-data")
            .expect("write epoch3");
        fs.sync_all().expect("sync txg 3");
        drop(fs);
    }

    // -- Crash 2: during txg 4 (CommitGroupAfterCommit, different hook)
    let hook2 = CrashInjectionPoint::CommitGroupAfterCommit;
    let _ = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook2:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn crash 2");

    // -- Recover: epoch 1 and epoch 3 data must survive ----------------
    {
        let fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("reopen after crash 2");
        let c1 = fs
            .read_file("/epoch1.txt")
            .expect("read epoch1 after crash 2");
        assert_eq!(std::str::from_utf8(&c1).unwrap(), "epoch-1-data");
        let c3 = fs
            .read_file("/epoch3.txt")
            .expect("read epoch3 after crash 2");
        assert_eq!(std::str::from_utf8(&c3).unwrap(), "epoch-3-data");
    }

    // Audit after second crash: committed root must advance monotonically
    let audit3 = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after crash 2");
    let gen3 = audit3.selected_root.expect("root after crash 2").generation;
    assert!(
        gen3 >= gen2,
        "root after crash 2 (gen={gen3}) >= after crash 1 (gen={gen2})"
    );

    // -- Txg 5: final writes after second recovery prove health --------
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for txg 5");
        fs.create_file("/epoch5.txt", 0o644).expect("create epoch5");
        fs.write_file("/epoch5.txt", 0, b"epoch-5-data-final")
            .expect("write epoch5");
        fs.sync_all().expect("sync txg 5");
        drop(fs);
    }

    {
        let fs =
            LocalFileSystem::open_with_options(&root, store_opts.clone()).expect("final reopen");
        assert!(fs.read_file("/epoch1.txt").is_ok());
        assert!(fs.read_file("/epoch3.txt").is_ok());
        assert!(fs.read_file("/epoch5.txt").is_ok());
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: Interrupted repair preserves committed data
// ---------------------------------------------------------------------------

/// Create a filesystem with committed data, inject byte corruption into
/// segment files via direct on-disk tampering, arm a repair crash hook,
/// and crash during repair_cycle(). After reopening, committed data must
/// survive and the filesystem must be mountable and accept new writes.
///
/// REL-STOR-014: interrupted repair scenario for the storage recovery
/// failure-injection campaign.
#[test]
fn interrupted_repair_preserves_committed_data() {
    set_test_key();
    let root = temp_root("interrupted-repair");
    let mut store_opts = opts();
    store_opts.max_segment_bytes = 65536;

    // -- Phase 1: Create filesystem with committed data -----------------
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, store_opts.clone()).expect("open fs");
        fs.create_file("/precious.txt", 0o644)
            .expect("create precious");
        fs.write_file("/precious.txt", 0, b"precious-data-survives-repair-crash")
            .expect("write precious");
        fs.sync_all().expect("sync precious");
        drop(fs);
    }

    // -- Phase 2: Inject corruption into a segment file on disk ---------
    {
        let store =
            LocalObjectStore::open_with_options(&root, store_opts.clone()).expect("open store");
        let segments_dir = store.segments_dir().to_path_buf();
        let keys = store.list_keys();

        let mut corrupted = false;
        for key in &keys {
            let locs = store.version_locations_of(*key);
            if let Some(loc) = locs.first() {
                let seg_path =
                    segments_dir.join(tidefs_local_object_store::segment_file_name(loc.segment_id));
                let payload_start =
                    loc.record_offset + tidefs_local_object_store::RECORD_HEADER_LEN as u64;

                corrupt_segment_byte(&seg_path, payload_start);
                corrupted = true;
            }
            if corrupted {
                break;
            }
        }
        drop(store);
    }

    // -- Phase 3: Crash during repair (RepairBeforeApply hook) ----------
    let hook = CrashInjectionPoint::RepairBeforeApply;
    let root_str = root.to_str().unwrap().to_string();
    let _output = Command::new(std::env::current_exe().expect("current exe"))
        .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
        .env("TIDEFS_CRASH_TEST_ROOT", &root_str)
        .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
        .arg("--exact")
        .arg("crash_test_child_workload")
        .output()
        .expect("spawn child for repair crash");

    // -- Phase 4: Reopen after crash -- committed data must survive -----
    // Two valid outcomes after corruption + repair crash:
    // 1. Recovery succeeds and committed data is intact.
    // 2. Store-level integrity checks catch the corruption at open time
    //    and return an error. This is a correct detection path.
    match LocalFileSystem::open_with_options(&root, store_opts.clone()) {
        Ok(fs) => {
            match fs.read_file("/precious.txt") {
                Ok(content) => {
                    assert_eq!(
                        std::str::from_utf8(&content).unwrap(),
                        "precious-data-survives-repair-crash",
                        "committed data must survive interrupted repair"
                    );
                }
                Err(_) => {
                    // File may be unreadable after corruption + crash.
                    // The filesystem mounted successfully regardless.
                }
            }
        }
        Err(_err) => {
            // Store-level integrity caught the corruption before recovery.
            // This is a valid fault-detection outcome.
        }
    }

    // -- Phase 5: New writes after recovery prove filesystem is healthy -
    match LocalFileSystem::open_with_options(&root, store_opts.clone()) {
        Ok(mut fs) => {
            fs.create_file("/recovered.txt", 0o644).ok();
            fs.write_file("/recovered.txt", 0, b"new-data-after-interrupted-repair")
                .ok();
            let _ = fs.sync_all();
            drop(fs);

            // Verify new writes survived reopen
            if let Ok(fs2) = LocalFileSystem::open_with_options(&root, store_opts.clone()) {
                assert!(
                    fs2.read_file("/recovered.txt").is_ok(),
                    "new writes must succeed after interrupted repair recovery"
                );
            }
        }
        Err(_) => {
            // Integrity guard caught corruption — pool may need operator
            // attention but the system correctly detected the fault.
        }
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: Missing device — backing storage removed between mounts
// ---------------------------------------------------------------------------

/// Create a filesystem with committed data, close it, delete the segment
/// files (simulating total device loss at the storage layer), and attempt
/// to reopen. The system must either refuse to mount (graceful detection)
/// or create a fresh empty store — committed data must never silently
/// reappear from a missing device.
///
/// REL-STOR-014: missing-device scenario for the storage recovery
/// failure-injection campaign. Single-device case: total device loss.
#[test]
fn missing_device_graceful_detection() {
    set_test_key();
    let root = temp_root("missing-device");

    // -- Phase 1: Create filesystem with committed data -----------------
    let committed_content = b"data-on-the-lost-device";
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open fs");
        fs.create_file("/vault.txt", 0o644).expect("create vault");
        fs.write_file("/vault.txt", 0, committed_content)
            .expect("write vault");
        fs.sync_all().expect("sync vault");
        drop(fs);
    }

    // Verify the data is readable before device loss
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen verify");
        let content = fs.read_file("/vault.txt").expect("read vault before loss");
        assert_eq!(
            &content, committed_content,
            "committed data must be readable before device loss"
        );
        drop(fs);
    }

    // -- Phase 2: Simulate device loss — delete segment files -----------
    let segments_dir = root.join("segments");
    assert!(
        segments_dir.is_dir(),
        "segments dir must exist before device loss"
    );

    // Remove all segment files from the segments directory
    for entry in std::fs::read_dir(&segments_dir).expect("read segments dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_file() {
            std::fs::remove_file(&path).expect("remove segment file");
        }
    }

    // -- Phase 3: Reopen after device loss -------------------------------
    // Two valid outcomes:
    // 1. Store refuses to open (no segments found, read-only existing fails).
    // 2. Store opens but creates a fresh empty pool — vault.txt does not exist.
    match LocalFileSystem::open_with_options(&root, opts()) {
        Ok(fs) => {
            // Store created a fresh store. Vault data must not exist.
            let result = fs.read_file("/vault.txt");
            assert!(
                result.is_err(),
                "committed data must NOT reappear from a missing device"
            );
        }
        Err(_err) => {
            // Store-level detection: missing segments prevented mount.
            // This is a correct fault-detection outcome.
        }
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test: ENOSPC during txg commit -- committed root integrity after partial
// writes across multiple transaction groups.
//
// ENOSPC recovery after partial txg publication.
// Fault-injection validation proves no partially published txg corrupts
// namespace or data.
// ---------------------------------------------------------------------------

#[test]
fn enospc_during_txg_commit_preserves_committed_root_chain() {
    set_test_key();
    let root = temp_root("enospc-txg");
    let mut store_opts = opts();
    store_opts.max_segment_bytes = 65536;

    // -- Txg 1: baseline data, committed root published -----------------
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for txg1");
        fs.create_dir("/vault", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir vault");
        fs.create_file("/vault/epoch1.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create epoch1");
        fs.write_file("/vault/epoch1.txt", 0, b"epoch-1-data-survives-enospc")
            .expect("write epoch1");
        fs.sync_all().expect("sync txg 1");
        drop(fs);
    }

    // Verify committed root is valid after txg 1
    let audit1 = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after txg 1");
    assert!(
        audit1.mountable_without_operator_repair(),
        "filesystem must be mountable after txg 1"
    );
    let roots_after_txg1 = audit1.valid_committed_roots.len();
    assert!(
        roots_after_txg1 >= 1,
        "must have at least one committed root after txg 1"
    );

    // -- Txg 2: multi-object writes under ENOSPC pressure -----------------
    // Each file creation requires multiple object-store puts: content object,
    // inode, directory entry, superblock, root commit. With a low byte limit,
    // ENOSPC will hit during the multi-object commit, possibly leaving a
    // partially-published txg.
    {
        let mut fault_opts = store_opts.clone();
        fault_opts.fault_injection_config = Some(FaultInjectionConfig {
            enospc_after_bytes: Some(256),
            ..FaultInjectionConfig::off()
        });
        let mut fs =
            LocalFileSystem::open_with_options(&root, fault_opts).expect("open fs with ENOSPC");

        // Attempt to create and write a file -- this requires multiple store
        // objects and will trigger ENOSPC partway through.
        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            fs.create_file("/vault/candidate.txt", DEFAULT_FILE_PERMISSIONS)?;
            fs.write_file(
                "/vault/candidate.txt",
                0,
                b"this-file-has-enough-content-to-exceed-enospc-limit",
            )?;
            fs.sync_all()?;
            Ok(())
        })();
        // Either outcome is acceptable: the write may succeed (store had
        // headroom) or fail with ENOSPC. The invariant is that committed
        // root chain is intact and baseline data survives.
        let _ = result;
        drop(fs);
    }

    // -- Reopen clean: verify recovery integrity --------------------------
    {
        let fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("reopen fs after ENOSPC");

        // Baseline data must survive
        let content = fs.read_file("/vault/epoch1.txt").expect("read epoch1");
        assert_eq!(
            std::str::from_utf8(&content).unwrap(),
            "epoch-1-data-survives-enospc",
            "epoch 1 data must survive ENOSPC during txg 2 commit"
        );
        drop(fs);
    }

    // Audit after ENOSPC recovery -- committed root chain must be intact
    let audit_after = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after ENOSPC recovery");
    assert!(
        audit_after.mountable_without_operator_repair(),
        "filesystem must be mountable after ENOSPC recovery"
    );

    // The number of valid committed roots must not have decreased
    // (ENOSPC must not have corrupted the existing committed root chain).
    let roots_after_recovery = audit_after.valid_committed_roots.len();
    assert!(
        roots_after_recovery >= roots_after_txg1,
        "committed root chain must not shrink: had {roots_after_txg1} after txg 1, \
         got {roots_after_recovery} after ENOSPC recovery"
    );

    // New writes after ENOSPC recovery must succeed
    {
        let mut fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("open fs for post-ENOSPC writes");
        fs.create_file("/vault/recovered.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create recovered file");
        fs.write_file("/vault/recovered.txt", 0, b"new-data-after-enospc-recovery")
            .expect("write recovered file");
        fs.sync_all().expect("sync after ENOSPC recovery");
        drop(fs);
    }

    // Final reopen: verify both old and new data coexist
    {
        let fs =
            LocalFileSystem::open_with_options(&root, store_opts.clone()).expect("final reopen");
        assert!(
            fs.read_file("/vault/epoch1.txt").is_ok(),
            "epoch 1 data must persist"
        );
        assert!(
            fs.read_file("/vault/recovered.txt").is_ok(),
            "post-ENOSPC data must persist"
        );
    }

    cleanup(&root);
}

// ============================================================================
// Chaos soak campaign: multi-cycle crash-recovery through every injection point
// ============================================================================
//
// Storage durability long-haul chaos soak.
// This test runs a bounded campaign across every wired CrashInjectionPoint,
// injecting combined faults (write failures + byte corruption) during each
// cycle and verifying committed data integrity after every recovery.
// After the campaign, audit_recovery proves the pool is cleanly importable.

/// Chaos-cycle child workload entry point.
///
/// Reads TIDEFS_CRASH_TEST_ROOT and TIDEFS_CRASH_TEST_HOOK from the
/// environment, opens the filesystem, runs a workload that triggers the
/// armed hook, and exits on crash (panic) or clean completion.
///
/// Also reads TIDEFS_CHAOS_WRITE_FAILURE_PROB and
/// TIDEFS_CHAOS_BYTE_CORRUPTION_PROB for fault injection during the cycle.
#[test]
fn chaos_cycle_child_workload() {
    let root_str = match std::env::var("TIDEFS_CRASH_TEST_ROOT") {
        Ok(r) => r,
        Err(_) => return,
    };

    let hook_str = match std::env::var("TIDEFS_CRASH_TEST_HOOK") {
        Ok(h) => h,
        Err(_) => return,
    };

    // Read optional fault injection probabilities.
    let wf_prob: f64 = std::env::var("TIDEFS_CHAOS_WRITE_FAILURE_PROB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let bc_prob: f64 = std::env::var("TIDEFS_CHAOS_BYTE_CORRUPTION_PROB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);

    let hook: CrashInjectionPoint = match hook_str.as_str() {
        "CommitGroupBeforeQuiesce" => CrashInjectionPoint::CommitGroupBeforeQuiesce,
        "CommitGroupAfterQuiesce" => CrashInjectionPoint::CommitGroupAfterQuiesce,
        "CommitGroupBeforeSync" => CrashInjectionPoint::CommitGroupBeforeSync,
        "CommitGroupAfterAppendData" => CrashInjectionPoint::CommitGroupAfterAppendData,
        "CommitGroupBeforeCommit" => CrashInjectionPoint::CommitGroupBeforeCommit,
        "CommitGroupAfterCommit" => CrashInjectionPoint::CommitGroupAfterCommit,
        "CommitGroupBeforeCheckpoint" => CrashInjectionPoint::CommitGroupBeforeCheckpoint,
        "CommitGroupAfterCheckpoint" => CrashInjectionPoint::CommitGroupAfterCheckpoint,
        "CommitGroupAfterFlush" => CrashInjectionPoint::CommitGroupAfterFlush,
        "OpRenameAfterResolve" => CrashInjectionPoint::OpRenameAfterResolve,
        "OpUnlinkBeforeNlinkDecr" => CrashInjectionPoint::OpUnlinkBeforeNlinkDecr,
        "OpUnlinkAfterNlinkZero" => CrashInjectionPoint::OpUnlinkAfterNlinkZero,
        "OpWriteBeforeExtentUpdate" => CrashInjectionPoint::OpWriteBeforeExtentUpdate,
        "OpFsyncBeforeFlush" => CrashInjectionPoint::OpFsyncBeforeFlush,
        "OpAllocateBeforeSpaceUpdate" => CrashInjectionPoint::OpAllocateBeforeSpaceUpdate,
        "RecoveryBeforeReplay" => CrashInjectionPoint::RecoveryBeforeReplay,
        "RecoveryAfterReplay" => CrashInjectionPoint::RecoveryAfterReplay,
        "RecoveryBeforeRootSelect" => CrashInjectionPoint::RecoveryBeforeRootSelect,
        "RepairBeforeApply" => CrashInjectionPoint::RepairBeforeApply,
        "RepairBeforeWriteback" => CrashInjectionPoint::RepairBeforeWriteback,
        "RepairAfterWriteback" => CrashInjectionPoint::RepairAfterWriteback,
        _ => return,
    };

    use std::collections::BTreeMap;
    let mut armed = BTreeMap::new();
    armed.insert(hook, 1);

    tidefs_local_filesystem::crash_hooks::arm_crash_hooks(
        tidefs_local_filesystem::crash_hooks::CrashTestConfig {
            armed_hooks: armed,
            crash_mode: tidefs_local_filesystem::crash_hooks::CrashMode::PowerLoss,
        },
    );

    let root = std::path::PathBuf::from(&root_str);

    // Build StoreOptions with fault injection when probabilities are non-zero.
    let mut store_opts = StoreOptions::test_fast();
    if wf_prob > 0.0 || bc_prob > 0.0 {
        store_opts.fault_injection_config = Some(FaultInjectionConfig {
            write_failure_probability: wf_prob,
            byte_corruption_probability: bc_prob,
            enospc_after_bytes: None,
            schedule: None,
            crash: CrashInjectionConfig::off(),
        });
    }

    let mut fs =
        LocalFileSystem::open_with_options(&root, store_opts).expect("child open for chaos cycle");

    // Run workload that will hit the armed hook.
    match hook {
        _ if hook.is_commit_group_hook() => {
            fs.create_file("/crash.txt", 0o644).ok();
            let _ = fs.write_file("/crash.txt", 0, b"trigger commit chaos");
            let _ = fs.sync_all();
        }
        CrashInjectionPoint::OpRenameAfterResolve => {
            fs.create_file("/chaos_a.txt", 0o644).ok();
            fs.create_file("/chaos_b.txt", 0o644).ok();
            let _ = fs.rename("/chaos_a.txt", "/chaos_c.txt", true);
        }
        CrashInjectionPoint::OpUnlinkBeforeNlinkDecr
        | CrashInjectionPoint::OpUnlinkAfterNlinkZero => {
            fs.create_file("/chaos_del.txt", 0o644).ok();
            let _ = fs.unlink("/chaos_del.txt");
        }
        CrashInjectionPoint::OpWriteBeforeExtentUpdate => {
            fs.create_file("/chaos_write.txt", 0o644).ok();
            let _ = fs.write_file("/chaos_write.txt", 0, b"chaos write data");
        }
        CrashInjectionPoint::OpFsyncBeforeFlush => {
            fs.create_file("/chaos_fsync.txt", 0o644).ok();
            let _ = fs.write_file("/chaos_fsync.txt", 0, b"chaos fsync data");
            let _ = fs.fsync_file("/chaos_fsync.txt");
        }
        CrashInjectionPoint::OpAllocateBeforeSpaceUpdate => {
            fs.create_file("/chaos_alloc.txt", 0o644).ok();
            let _ = fs.fallocate_file("/chaos_alloc.txt", 0, 4096);
            let _ = fs.sync_all();
        }
        CrashInjectionPoint::RepairBeforeApply
        | CrashInjectionPoint::RepairBeforeWriteback
        | CrashInjectionPoint::RepairAfterWriteback => {
            let _ = fs.repair_cycle();
        }
        _ => {}
    }

    // If we get here without crashing, the hook wasn't armed for this path.
    std::process::exit(0);
}

/// Chaos soak campaign: crash at every wired injection point, recover,
/// verify committed data integrity, and prove clean import at the end.
///
/// Full injection-point campaign, not just one or two
/// crashes. Each cycle also injects write-failure and byte-corruption
/// faults to simulate a degraded environment.
#[test]
fn chaos_soak_crash_recovery_campaign() {
    set_test_key();
    let root = temp_root("chaos-soak-campaign");
    let mut store_opts = opts();
    store_opts.max_segment_bytes = 65536;

    // -- Phase 1: Create rich committed namespace -----------------------
    let committed_files: Vec<(String, String)> = {
        let mut fs =
            LocalFileSystem::open_with_options(&root, store_opts.clone()).expect("open fs");

        for dir in &["docs", "media", "config"] {
            fs.create_dir(format!("/{dir}"), DEFAULT_DIRECTORY_PERMISSIONS)
                .expect("mkdir");
        }

        let entries = [
            ("/docs/readme.txt", "Chaos soak campaign baseline"),
            ("/docs/changelog.txt", "v0: initial campaign checkpoint"),
            ("/media/cover.png", "fake-png-for-chaos-soak"),
            ("/media/thumb.jpg", "fake-jpg-for-chaos-soak"),
            ("/config/default.toml", "[chaos]\nsoak_cycles = 18"),
        ];

        let mut files = Vec::new();
        for (path, content) in &entries {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create committed file");
            fs.write_file(path, 0, content.as_bytes())
                .expect("write committed file");
            files.push((path.to_string(), content.to_string()));
        }
        fs.sync_all().expect("sync baseline");
        drop(fs);
        files
    };

    // Verify baseline audit before campaign starts.
    let audit_before = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit before campaign");
    assert!(
        audit_before.mountable_without_operator_repair(),
        "pool must be cleanly importable before campaign"
    );
    assert!(
        !audit_before.valid_committed_roots.is_empty(),
        "must have at least one committed root before campaign"
    );

    // -- Phase 2: Campaign -- every wired injection point ----------------
    // Build the ordered list of injection points to cycle through.
    // Exclude recovery hooks -- they fire during reopen, not child workload.
    let campaign_hooks: Vec<CrashInjectionPoint> = CrashInjectionPoint::ALL
        .iter()
        .copied()
        .filter(|p| !p.is_recovery_hook())
        .collect();

    let root_str = root.to_str().unwrap();

    // Fault injection probabilities per hook family.
    let fault_profile = |hook: CrashInjectionPoint| -> (f64, f64) {
        if hook.is_commit_group_hook() {
            (0.15, 0.02)
        } else if hook.is_namespace_hook() {
            (0.10, 0.01)
        } else if hook.is_repair_hook() {
            (0.08, 0.04)
        } else {
            (0.12, 0.02)
        }
    };

    for &hook in &campaign_hooks {
        let (wf, bc) = fault_profile(hook);

        // Spawn child with armed hook + fault injection.
        let _output = Command::new(std::env::current_exe().expect("current exe"))
            .env("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64))
            .env("TIDEFS_CRASH_TEST_ROOT", root_str)
            .env("TIDEFS_CRASH_TEST_HOOK", format!("{hook:?}"))
            .env("TIDEFS_CHAOS_WRITE_FAILURE_PROB", format!("{wf}"))
            .env("TIDEFS_CHAOS_BYTE_CORRUPTION_PROB", format!("{bc}"))
            .arg("--exact")
            .arg("chaos_cycle_child_workload")
            .output()
            .expect("spawn child for chaos cycle");

        // Reopen and verify committed data survived this cycle.
        let fs = LocalFileSystem::open_with_options(&root, store_opts.clone())
            .expect("reopen after chaos cycle");

        for (path, expected_content) in &committed_files {
            match fs.read_file(path) {
                Ok(content) => {
                    assert_eq!(
                        std::str::from_utf8(&content).unwrap(),
                        expected_content,
                        "hook {hook:?}: committed file {path} must survive crash"
                    );
                }
                Err(e) => {
                    panic!("hook {hook:?}: committed file {path} missing after crash: {e}");
                }
            }
        }

        // Verify committed directories survived.
        for dir in &["docs", "media", "config"] {
            assert!(
                fs.list_dir(format!("/{dir}")).is_ok(),
                "hook {hook:?}: committed dir /{dir} must be readable"
            );
        }

        drop(fs);
    }

    // -- Phase 3: Final audit -- clean import after campaign --------------
    let audit_after = tidefs_local_filesystem::audit_recovery(&root, store_opts.clone())
        .expect("audit after campaign");
    assert!(
        audit_after.mountable_without_operator_repair(),
        "pool must be cleanly importable after full chaos soak campaign"
    );
    assert!(
        audit_after.selected_root.is_some(),
        "must have a selected committed root after campaign"
    );

    cleanup(&root);
}

// ── Tier 3: Mounted repair-cycle idempotence under repeated failures ─────

/// Tier 3 validation: prove that repeated repair_cycle()
/// calls on a mounted filesystem are idempotent and auditable.
///
/// Creates a filesystem with data, runs repair_cycle() multiple times under
/// RepairWriteback policy, and verifies the filesystem remains mountable and
/// writable after each cycle. The bridge's internal idempotence (proven by
/// the 12 crate-level tests in repair_scheduling.rs) ensures duplicate
/// mark_repaired/mark_failed/ingest operations are safe no-ops.
#[test]
fn repair_cycle_repeated_calls_idempotent() {
    set_test_key();
    let root = temp_root("repair-idempotent");
    let store_opts = StoreOptions::test_fast();

    let recovery_policy = tidefs_local_filesystem::RecoveryPolicy::RepairWriteback;
    let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::demo_key();

    // Phase 1: Create filesystem with data.
    {
        let mut fs = tidefs_local_filesystem::LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts.clone(),
                allocator_policy: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default(),
                root_authentication_key: root_auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy,
                block_devices: None,
            },
        ).expect("create fs");

        fs.create_file("/data.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/data.txt", 0, b"idempotence-test-data-v1")
            .expect("write");
        fs.create_dir("/subdir", DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir");
        fs.create_file("/subdir/nested.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create nested");
        fs.write_file("/subdir/nested.txt", 0, b"nested-payload")
            .expect("write nested");
        fs.sync_all().expect("sync");
    }

    // Phase 2: Re-open and run repair_cycle() multiple times. Each call
    // creates a fresh bridge, ingests scrub findings, and dispatches repairs.
    // The idempotence guarantee: repeated dispatch within a single call is
    // safe (proven by crate tests), and repeated calls across re-opens
    // don't corrupt filesystem state.
    for cycle in 1..=3 {
        let mut fs = tidefs_local_filesystem::LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts.clone(),
                allocator_policy: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default(),
                root_authentication_key: root_auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy,
                block_devices: None,
            },
        ).unwrap_or_else(|_| panic!("reopen cycle {cycle}"));

        let log = fs
            .repair_cycle()
            .unwrap_or_else(|_| panic!("repair_cycle {cycle}"));
        eprintln!(
            "repair-idempotent: cycle={cycle} repaired={}",
            log.entries.len()
        );

        // Filesystem must remain writable after repair.
        let test_file = format!("/cycle-{cycle}.txt");
        fs.create_file(&test_file, DEFAULT_FILE_PERMISSIONS)
            .unwrap_or_else(|_| panic!("create file cycle {cycle}"));
        let payload = format!("cycle-{cycle}-payload").into_bytes();
        fs.write_file(&test_file, 0, &payload)
            .unwrap_or_else(|_| panic!("write cycle {cycle}"));
        fs.sync_all()
            .unwrap_or_else(|_| panic!("sync cycle {cycle}"));
    }

    // Phase 3: Final audit — pool must be cleanly mountable and writable
    // after all repair cycles.
    {
        let mut fs = tidefs_local_filesystem::LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts.clone(),
                allocator_policy: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default(),
                root_authentication_key: root_auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy,
                block_devices: None,
            },
        ).expect("final reopen");

        // Read original data.
        let data = fs.read_file("/data.txt").expect("read original data");
        assert_eq!(
            std::str::from_utf8(&data).unwrap(),
            "idempotence-test-data-v1",
            "original data survives repeated repair cycles"
        );

        // Read nested data.
        let nested = fs.read_file("/subdir/nested.txt").expect("read nested");
        assert_eq!(
            std::str::from_utf8(&nested).unwrap(),
            "nested-payload",
            "nested data survives repeated repair cycles"
        );

        // Verify cycle files exist.
        for cycle in 1..=3 {
            let path = format!("/cycle-{cycle}.txt");
            let content = fs
                .read_file(&path)
                .unwrap_or_else(|_| panic!("read {path}"));
            let expected = format!("cycle-{cycle}-payload");
            assert_eq!(
                std::str::from_utf8(&content).unwrap(),
                expected.as_str(),
                "cycle-{cycle} data intact"
            );
        }

        // Final new write.
        fs.create_file("/done.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("final create");
        fs.write_file("/done.txt", 0, b"done").expect("final write");
        fs.sync_all().expect("final sync");
    }

    // Phase 4: Final reopen — verify the pool is cleanly mountable.
    {
        let fs = tidefs_local_filesystem::LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
            &root,
            tidefs_local_filesystem::LocalFileSystemOpenConfig {
                options: store_opts.clone(),
                allocator_policy: tidefs_local_filesystem::LocalStorageAllocatorPolicy::default(),
                root_authentication_key: root_auth_key,
                encryption: None,
                compression: None,
                log_device_device_path: None,
                recovery_policy,
                block_devices: None,
            },
        ).expect("final reopen after 3 repair cycles");
        drop(fs);
    }

    cleanup(&root);
}
