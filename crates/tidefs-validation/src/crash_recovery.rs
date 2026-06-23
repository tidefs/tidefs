// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Crash recovery integration tests: SIGKILL + remount verifies fsyncd data
//! survives byte-for-byte.
//!
//! Exercises the FUSE crash recovery contract beyond the single baseline test
//! in `write_durability.rs`. Covers multi-file isolation, overwrite, empty
//! files, directory structure, unlink/rename atomicity, fdatasync, large
//! files, append-after-crash cycles, no-fsync data-loss expectations, and
//! partial-fsync mix scenarios.
//!
//! Every test skips gracefully when the daemon binary or /dev/fuse is
//! unavailable.

#[cfg(test)]
use crate::mount_harness::MountHarness;

#[cfg(test)]
fn make_test_buffer(seed: u64, count: usize) -> Vec<u8> {
    use std::hash::{Hash, Hasher};

    let mut buf = Vec::with_capacity(count + 16);
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    for _ in 0..count {
        buf.push((state >> 32) as u8);
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    (count as u64).hash(&mut hasher);
    buf.hash(&mut hasher);
    let h64 = hasher.finish();
    let mut footer = [0u8; 16];
    footer[..8].copy_from_slice(&h64.to_le_bytes());
    footer[8..].copy_from_slice(&h64.to_le_bytes());
    buf.extend_from_slice(&footer);
    buf
}

#[cfg(test)]
fn verify_test_buffer(seed: u64, data: &[u8]) -> Result<(), String> {
    let data_len = data.len().saturating_sub(16);
    let expected = make_test_buffer(seed, data_len);
    if data.len() != expected.len() {
        return Err(format!(
            "length mismatch: got {} bytes, expected {}",
            data.len(),
            expected.len()
        ));
    }
    if data != expected.as_slice() {
        for (i, (a, b)) in data.iter().zip(expected.iter()).enumerate() {
            if a != b {
                return Err(format!(
                    "byte mismatch at offset {i}: got 0x{a:02x}, expected 0x{b:02x}"
                ));
            }
        }
        return Err("data mismatch (unknown offset)".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn try_mount() -> Option<MountHarness> {
        match MountHarness::new() {
            Ok(h) => Some(h),
            Err(e) => {
                eprintln!(
                    "SKIP: daemon not available (set TIDEFS_DAEMON_BIN or \
                     build the workspace) -- {e}"
                );
                None
            }
        }
    }

    // ── Baseline: single file, fsync, crash, remount, verify ─────────

    #[test]
    fn crash_recovery_single_file_small() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0xca5cade;
        let data = make_test_buffer(seed, 1024);

        h.create_file("recover.bin", &data)
            .expect("create recover.bin");
        h.fsync_file("recover.bin").expect("fsync recover.bin");
        h.crash_and_remount().expect("crash and remount");

        let after = h.read_file("recover.bin").expect("read after crash");
        verify_test_buffer(seed, &after).expect("byte-for-byte recovery");
    }

    // ── Multi-file isolation: only fsyncd files survive ──────────────

    #[test]
    fn crash_recovery_multi_file_isolation() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed_a: u64 = 0xa1;
        let seed_b: u64 = 0xb2;
        let data_a = make_test_buffer(seed_a, 2048);
        let data_b = make_test_buffer(seed_b, 2048);

        h.create_file("fsyncd.bin", &data_a)
            .expect("create fsyncd.bin");
        h.fsync_file("fsyncd.bin").expect("fsync fsyncd.bin");

        // File B: written but NOT fsyncd before crash.
        h.create_file("not_fsyncd.bin", &data_b)
            .expect("create not_fsyncd.bin");
        // No fsync on not_fsyncd.bin.

        h.crash_and_remount().expect("crash and remount");

        // Fsyncd file must survive byte-for-byte.
        let after_a = h
            .read_file("fsyncd.bin")
            .expect("read fsyncd.bin after crash");
        verify_test_buffer(seed_a, &after_a).expect("fsyncd file integrity");

        // Non-fsyncd file must NOT appear (never committed).
        assert!(
            !h.exists("not_fsyncd.bin"),
            "file without fsync must not survive crash"
        );
    }

    // ── Overwrite survives crash ─────────────────────────────────────

    #[test]
    fn crash_recovery_overwrite_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let v1 = make_test_buffer(0x10, 4096);
        h.create_file("over.bin", &v1).expect("create v1");
        h.fsync_file("over.bin").expect("fsync v1");

        // Overwrite in-place then fsync.
        let v2 = make_test_buffer(0x20, 4096);
        {
            use std::io::Write;
            let path = h.mount_path().join("over.bin");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("open over.bin for rewrite");
            f.write_all(&v2).expect("overwrite v2");
            f.sync_all().expect("fsync v2");
        }

        h.crash_and_remount().expect("crash and remount");

        let after = h.read_file("over.bin").expect("read after crash");
        verify_test_buffer(0x20, &after).expect("post-crash is v2, not v1");
    }

    // ── fdatasync survives crash ─────────────────────────────────────

    #[test]
    fn crash_recovery_fdatasync_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed: u64 = 0xfda7a;
        let data = make_test_buffer(seed, 8192);

        h.create_file("fdatasync.bin", &data)
            .expect("create fdatasync.bin");
        h.fdatasync_file("fdatasync.bin").expect("fdatasync");
        h.crash_and_remount().expect("crash and remount");

        let after = h.read_file("fdatasync.bin").expect("read after crash");
        verify_test_buffer(seed, &after).expect("fdatasync crash recovery integrity");
    }

    // ── Empty file survives crash ────────────────────────────────────

    #[test]
    fn crash_recovery_empty_file_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        h.create_file("empty.bin", b"").expect("create empty.bin");
        h.fsync_file("empty.bin").expect("fsync empty.bin");
        h.crash_and_remount().expect("crash and remount");

        let after = h
            .read_file("empty.bin")
            .expect("read empty.bin after crash");
        assert!(after.is_empty(), "empty file must stay empty after crash");
    }

    // ── Directory structure survives crash ───────────────────────────

    #[test]
    fn crash_recovery_directory_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        h.mkdir_all("sub/deep").expect("mkdir -p sub/deep");

        let seed: u64 = 0xd1;
        let data = make_test_buffer(seed, 512);
        h.create_file("sub/deep/child.bin", &data)
            .expect("create child.bin");

        // fsync the child to commit its content; the parent dirs are committed
        // as a side effect of the create+fsync chain.
        h.fsync_file("sub/deep/child.bin").expect("fsync child.bin");

        h.crash_and_remount().expect("crash and remount");

        assert!(h.exists("sub"), "directory sub must survive crash");
        assert!(
            h.exists("sub/deep"),
            "directory sub/deep must survive crash"
        );
        assert!(
            h.exists("sub/deep/child.bin"),
            "child file must survive crash"
        );

        let after = h
            .read_file("sub/deep/child.bin")
            .expect("read child after crash");
        verify_test_buffer(seed, &after).expect("child file integrity after crash");
    }

    // ── Unlink survives crash ────────────────────────────────────────

    #[test]
    fn crash_recovery_unlink_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let data = make_test_buffer(0xde, 1024);
        h.create_file("to_delete.bin", &data)
            .expect("create to_delete.bin");
        h.create_file("keep.bin", &data).expect("create keep.bin");
        h.fsync_file("keep.bin").expect("fsync keep.bin");

        h.remove_file("to_delete.bin")
            .expect("unlink to_delete.bin");
        // fsync the root directory to commit the unlink.
        h.fsync_file("keep.bin")
            .expect("fsync keep.bin after unlink");

        h.crash_and_remount().expect("crash and remount");

        assert!(
            !h.exists("to_delete.bin"),
            "unlinked file must stay gone after crash"
        );
        assert!(h.exists("keep.bin"), "unrelated file must survive crash");
    }

    // ── Rename survives crash ────────────────────────────────────────

    #[test]
    fn crash_recovery_rename_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed: u64 = 0x6e;
        let data = make_test_buffer(seed, 2048);
        h.create_file("old_name.bin", &data)
            .expect("create old_name.bin");
        h.fsync_file("old_name.bin").expect("fsync old_name.bin");

        h.rename("old_name.bin", "new_name.bin")
            .expect("rename old -> new");
        // fsync a stable file to commit the rename's directory changes.
        h.create_file("stable.bin", b"anchor")
            .expect("create stable.bin");
        h.fsync_file("stable.bin").expect("fsync stable.bin");

        h.crash_and_remount().expect("crash and remount");

        assert!(
            !h.exists("old_name.bin"),
            "old name must not exist after rename+crash"
        );
        assert!(
            h.exists("new_name.bin"),
            "new name must exist after rename+crash"
        );

        let after = h
            .read_file("new_name.bin")
            .expect("read new_name.bin after crash");
        verify_test_buffer(seed, &after).expect("renamed file integrity after crash");
    }

    // ── No fsync = data loss after crash ─────────────────────────────

    #[test]
    fn crash_recovery_no_fsync_loses_data() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let data = make_test_buffer(0xbade, 4096);
        h.create_file("lost.bin", &data).expect("create lost.bin");
        // Deliberately do NOT fsync.

        h.crash_and_remount().expect("crash and remount");

        // The file without fsync must not appear after crash recovery.
        assert!(
            !h.exists("lost.bin"),
            "file without fsync must not survive crash"
        );
    }

    // ── Large file survives crash ────────────────────────────────────

    #[test]
    fn crash_recovery_large_file_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed: u64 = 0x1a63;
        let size: usize = 128 * 1024; // 128 KB, multi-segment
        let data = make_test_buffer(seed, size);

        h.create_file("large.bin", &data).expect("create large.bin");
        h.fsync_file("large.bin").expect("fsync large.bin");
        h.crash_and_remount().expect("crash and remount");

        let after = h
            .read_file("large.bin")
            .expect("read large.bin after crash");
        verify_test_buffer(seed, &after).expect("large file byte-for-byte recovery");
    }

    // ── Append after crash + second crash cycle ─────────────────────

    #[test]
    fn crash_recovery_append_after_crash() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed1: u64 = 0xa1;
        let seed2: u64 = 0xa2;
        let data1 = make_test_buffer(seed1, 2048);
        let data2 = make_test_buffer(seed2, 2048);

        h.create_file("append.bin", &data1).expect("create v1");
        h.fsync_file("append.bin").expect("fsync v1");
        h.crash_and_remount().expect("first crash and remount");

        // Append more data after first crash recovery.
        {
            use std::io::Write;
            let path = h.mount_path().join("append.bin");
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append.bin for append");
            f.write_all(&data2).expect("append v2");
            f.sync_all().expect("fsync after append");
        }

        h.crash_and_remount().expect("second crash and remount");

        let after = h.read_file("append.bin").expect("read after second crash");
        let expected_len = data1.len() + data2.len();
        assert_eq!(
            after.len(),
            expected_len,
            "appended file must have combined length after two crash cycles"
        );
        // Verify v1 prefix.
        verify_test_buffer(seed1, &after[..data1.len()])
            .expect("v1 prefix integrity after two crash cycles");
        // Verify v2 suffix.
        verify_test_buffer(seed2, &after[data1.len()..])
            .expect("v2 suffix integrity after two crash cycles");
    }

    // ── Crash with no prior writes (clean mount) ────────────────────

    #[test]
    fn crash_recovery_clean_mount_no_writes() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        // Immediately crash without writing anything.
        h.crash_and_remount()
            .expect("crash clean mount and remount");

        // Must still be mountable and have a functional root.
        let _entries = h.readdir(".").expect("readdir root after clean crash");
        // Root directory must be readable after clean crash.
        // (readdir already succeeded via expect above; assert the dir exists.)
        assert!(
            h.exists(".") || h.readdir(".").is_ok(),
            "root directory must be accessible after clean crash"
        );
    }

    // ── Partial fsync mix: only fsyncd files survive ─────────────────

    #[test]
    fn crash_recovery_partial_fsync_mix() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed_safe: u64 = 0x501;
        let seed_lost_a: u64 = 0x502;
        let seed_lost_b: u64 = 0x503;

        let data_safe = make_test_buffer(seed_safe, 1024);
        let data_lost_a = make_test_buffer(seed_lost_a, 1024);
        let data_lost_b = make_test_buffer(seed_lost_b, 2048);

        // File 1: fsyncd.
        h.create_file("safe.bin", &data_safe)
            .expect("create safe.bin");
        h.fsync_file("safe.bin").expect("fsync safe.bin");

        // File 2: NOT fsyncd.
        h.create_file("lost_a.bin", &data_lost_a)
            .expect("create lost_a.bin");
        // No fsync.

        // File 3: NOT fsyncd.
        h.create_file("lost_b.bin", &data_lost_b)
            .expect("create lost_b.bin");
        // No fsync.

        h.crash_and_remount().expect("crash and remount");

        // Only safe.bin must survive.
        assert!(h.exists("safe.bin"), "fsyncd file must survive crash");
        let after_safe = h.read_file("safe.bin").expect("read safe.bin after crash");
        verify_test_buffer(seed_safe, &after_safe).expect("safe.bin integrity");

        assert!(
            !h.exists("lost_a.bin"),
            "non-fsyncd lost_a must not survive crash"
        );
        assert!(
            !h.exists("lost_b.bin"),
            "non-fsyncd lost_b must not survive crash"
        );
    }

    // ── Multiple fsyncd files all survive ────────────────────────────

    #[test]
    fn crash_recovery_multiple_fsyncd_files() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seeds: [(u64, usize, &str); 5] = [
            (0x01, 512, "a.bin"),
            (0x02, 1024, "b.bin"),
            (0x03, 2048, "c.bin"),
            (0x04, 4096, "d.bin"),
            (0x05, 8192, "e.bin"),
        ];

        for &(seed, size, name) in &seeds {
            let data = make_test_buffer(seed, size);
            h.create_file(name, &data).expect("create file");
            h.fsync_file(name).expect("fsync file");
        }

        h.crash_and_remount().expect("crash and remount");

        for &(seed, _size, name) in &seeds {
            assert!(h.exists(name), "{name} must survive crash");
            let after = h.read_file(name).expect("read after crash");
            verify_test_buffer(seed, &after).unwrap_or_else(|_| panic!("{name} integrity"));
        }
    }

    // ── Truncate before crash ────────────────────────────────────────

    #[test]
    fn crash_recovery_truncate_survives() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seed: u64 = 0x7a;
        let full = make_test_buffer(seed, 8192);
        h.create_file("trunc.bin", &full).expect("create trunc.bin");
        h.fsync_file("trunc.bin").expect("fsync full");

        // Truncate to half size then fsync.
        h.truncate("trunc.bin", 4096).expect("truncate to 4K");
        h.fsync_file("trunc.bin").expect("fsync truncated");

        h.crash_and_remount().expect("crash and remount");

        let after = h.read_file("trunc.bin").expect("read after crash");
        assert_eq!(after.len(), 4096, "truncated size must survive crash");
        verify_test_buffer(seed, &after).expect("truncated content integrity");
    }

    // ── Crash with no fsync on any file ──────────────────────────────

    #[test]
    fn crash_recovery_no_fsync_any_file() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        // Create several files, none fsyncd.
        for i in 0..4 {
            let data = make_test_buffer(i, 512);
            let name = format!("nosync_{i}.bin");
            h.create_file(&name, &data).expect("create file");
        }

        h.crash_and_remount().expect("crash and remount");

        // None of the non-fsyncd files should survive.
        for i in 0..4 {
            let name = format!("nosync_{i}.bin");
            assert!(
                !h.exists(&name),
                "{name} without fsync must not survive crash"
            );
        }
    }

    // =================================================================
    // Chaos soak campaign: multi-cycle crash-recover through FUSE mount
    // =================================================================
    //
    // Storage durability long-haul chaos soak.
    // This Tier 3 test mounts a FUSE filesystem, writes a committed
    // baseline, then runs a multi-cycle crash+remount campaign,
    // verifying committed data integrity after every cycle.
    // At the end, a graceful-shutdown+remount proves clean import.

    #[test]
    fn chaos_soak_fuse_crash_campaign() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        // -- Phase 1: Create rich committed namespace -----------------
        // Write baseline files and directories, fsync everything.
        let seed_base: u64 = 0x50a_bae;
        let committed: Vec<(String, u64, usize)> = vec![
            ("docs/readme.txt".into(), seed_base, 1024),
            ("docs/changelog.txt".into(), seed_base + 1, 2048),
            ("media/cover.png".into(), seed_base + 2, 4096),
            ("media/thumb.jpg".into(), seed_base + 3, 512),
            ("config/default.toml".into(), seed_base + 4, 256),
        ];

        for dir in &["docs", "media", "config"] {
            h.mkdir(dir).expect("mkdir");
        }

        for (path, seed, size) in &committed {
            let data = make_test_buffer(*seed, *size);
            h.create_file(path, &data).expect("create committed file");
            h.fsync_file(path).expect("fsync committed file");
        }

        // Verify baseline before campaign starts.
        for (path, seed, _size) in &committed {
            assert!(h.exists(path), "baseline {path} must exist before campaign");
            let content = h.read_file(path).expect("read baseline");
            verify_test_buffer(*seed, &content).expect("baseline integrity");
        }

        // -- Phase 2: Campaign -- crash+remount cycles -----------------
        let cycle_count: usize = 8;
        for cycle in 0..cycle_count {
            // Write cycle-specific data with mixed fsync.
            let cycle_seed = seed_base + 100 + cycle as u64;
            for i in 0..3 {
                let name = format!("cycle_{cycle}_file_{i}.txt");
                let data = make_test_buffer(cycle_seed + i as u64, 512 + i * 256);
                h.create_file(&name, &data).expect("create cycle file");
            }

            // Fsync alternating files to get mixed survival.
            for i in 0..3 {
                if i % 2 == 0 {
                    let name = format!("cycle_{cycle}_file_{i}.txt");
                    h.fsync_file(&name).expect("fsync cycle file");
                }
            }

            // Crash (SIGKILL) and remount.
            h.crash_and_remount()
                .unwrap_or_else(|_| panic!("crash and remount cycle {cycle}"));

            // Verify all committed baseline files survived this cycle.
            for (path, seed, _size) in &committed {
                assert!(
                    h.exists(path),
                    "cycle {cycle}: committed {path} must survive crash"
                );
                let content = h.read_file(path).expect("read after crash");
                verify_test_buffer(*seed, &content)
                    .unwrap_or_else(|_| panic!("cycle {cycle}: {path} integrity after crash"));
            }

            // Verify committed directories survived.
            for dir in &["docs", "media", "config"] {
                let entries = h
                    .readdir(dir)
                    .unwrap_or_else(|_| panic!("cycle {cycle}: readdir /{dir}"));
                assert!(
                    !entries.is_empty(),
                    "cycle {cycle}: directory /{dir} must have entries"
                );
            }
        }

        // -- Phase 3: Graceful shutdown + remount = clean import -------
        h.graceful_shutdown_and_remount()
            .expect("graceful shutdown and remount");

        // Final verification: all committed data accessible.
        for (path, seed, _size) in &committed {
            assert!(
                h.exists(path),
                "final: committed {path} must survive campaign"
            );
            let content = h.read_file(path).expect("final read");
            verify_test_buffer(*seed, &content)
                .unwrap_or_else(|_| panic!("final: {path} integrity after campaign"));
        }

        for dir in &["docs", "media", "config"] {
            let entries = h
                .readdir(dir)
                .unwrap_or_else(|_| panic!("final: readdir /{dir}"));
            assert!(!entries.is_empty(), "final: /{dir} must be populated");
        }

        // h is dropped here, cleaning up the mount and temp directory.
    }
}
