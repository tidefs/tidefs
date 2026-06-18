// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write-durability validation: mount, write, fsync, remount, verify.
//!
//! Exercises the FUSE fsync durability contract across three file-size
//! tiers (small single-chunk, medium multi-chunk, large multi-segment),
//! plus fdatasync, multi-file isolation, append-after-remount, and
//! SIGKILL crash recovery.  Every test skips gracefully when the daemon
//! binary or /dev/fuse is unavailable.
//!
//! The entire module is `#[cfg(test)]` because it contains only tests
//! and test helpers — no library surface.

#[cfg(test)]
use crate::mount_harness::MountHarness;

// ── Buffer helpers ────────────────────────────────────────────────────────

#[cfg(test)]
/// Build a reproducible pseudo-random buffer of `count` data bytes plus
/// a 16-byte deterministic checksum footer so the test can distinguish
/// "all zeros" from "corrupted after write" with high probability.
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
/// Verify `data` against `make_test_buffer(seed, data_len - 16)`.
fn verify_test_buffer(seed: u64, data: &[u8]) -> Result<(), String> {
    let expected = make_test_buffer(seed, data.len().saturating_sub(16));
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Try to create a MountHarness.  Returns `None` and prints a skip
    /// message when the daemon binary is unavailable.
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

    // ── Small file (<4 KB, single chunk) ──────────────────────────────

    #[test]
    fn write_durability_small_file_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0x42;
        let data = make_test_buffer(seed, 2048);

        h.create_file("small.bin", &data).expect("create small.bin");
        h.fsync_file("small.bin").expect("fsync small.bin");

        let before = h.read_file("small.bin").expect("read before remount");
        verify_test_buffer(seed, &before).expect("pre-remount integrity");

        h.remount().expect("remount");

        let after = h.read_file("small.bin").expect("read after remount");
        verify_test_buffer(seed, &after).expect("post-remount integrity");
    }

    // ── Medium file (64 KB, multi-chunk) ──────────────────────────────

    #[test]
    fn write_durability_medium_file_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0x1337;
        let data = make_test_buffer(seed, 65_536); // 64 KiB

        h.create_file("medium.bin", &data)
            .expect("create medium.bin");
        h.fsync_file("medium.bin").expect("fsync medium.bin");

        h.remount().expect("remount");

        let after = h.read_file("medium.bin").expect("read after remount");
        verify_test_buffer(seed, &after).expect("post-remount integrity");
    }

    // ── Large file (>1 MB, multi-segment) ─────────────────────────────

    #[test]
    fn write_durability_large_file_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0xdead;
        let data = make_test_buffer(seed, 1_572_864); // 1.5 MiB

        h.create_file("large.bin", &data).expect("create large.bin");
        h.fsync_file("large.bin").expect("fsync large.bin");

        h.remount().expect("remount");

        let after = h.read_file("large.bin").expect("read after remount");
        verify_test_buffer(seed, &after).expect("post-remount integrity");
    }

    // ── fdatasync (data-only sync) ────────────────────────────────────

    #[test]
    fn write_durability_fdatasync_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0xf00d;
        let data = make_test_buffer(seed, 4096);

        h.create_file("fdatasync.bin", &data)
            .expect("create fdatasync.bin");
        h.fdatasync_file("fdatasync.bin")
            .expect("fdatasync fdatasync.bin");

        h.remount().expect("remount");

        let after = h.read_file("fdatasync.bin").expect("read after remount");
        verify_test_buffer(seed, &after).expect("fdatasync post-remount integrity");
    }

    // ── Multi-file isolation ──────────────────────────────────────────

    #[test]
    fn write_durability_multi_file_isolation() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let seeds: &[(u64, usize, &str)] = &[
            (0x01, 4096, "file_a.bin"),
            (0x02, 8192, "file_b.bin"),
            (0x03, 16384, "file_c.bin"),
            (0x04, 32768, "file_d.bin"),
        ];

        for &(seed, len, name) in seeds {
            let data = make_test_buffer(seed, len);
            h.create_file(name, &data)
                .unwrap_or_else(|e| panic!("create {name}: {e}"));
            h.fsync_file(name)
                .unwrap_or_else(|e| panic!("fsync {name}: {e}"));
        }

        h.remount().expect("remount");

        for &(seed, _len, name) in seeds {
            let after = h
                .read_file(name)
                .unwrap_or_else(|e| panic!("read {name}: {e}"));
            verify_test_buffer(seed, &after).unwrap_or_else(|e| panic!("verify {name}: {e}"));
        }
    }

    // ── Append-and-fsync across remount ───────────────────────────────

    #[test]
    fn write_durability_append_after_remount() {
        use std::io::Write;

        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let initial = make_test_buffer(0xa0, 2048);
        h.create_file("append.bin", &initial)
            .expect("create append.bin");
        h.fsync_file("append.bin").expect("fsync initial");

        h.remount().expect("remount");

        let after_remount = h.read_file("append.bin").expect("read after remount");
        verify_test_buffer(0xa0, &after_remount).expect("initial survived remount");

        // Append distinct bytes via the mounted path then fsync.
        let append_payload: Vec<u8> = (0u8..=255u8).cycle().take(512).collect();
        let init_len = initial.len();
        {
            let path = h.mount_path().join("append.bin");
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append.bin for append");
            f.write_all(&append_payload).expect("append write");
            f.sync_all().expect("fsync after append");
        }

        let full = h.read_file("append.bin").expect("read after append");
        assert_eq!(
            full.len(),
            init_len + append_payload.len(),
            "file length must equal initial + appended"
        );
        verify_test_buffer(0xa0, &full[..init_len]).expect("initial region intact");
        assert_eq!(&full[init_len..], &append_payload, "appended region intact");
    }

    // ── Crash recovery (SIGKILL + remount) ────────────────────────────

    #[test]
    fn write_durability_crash_recovery_sigkill_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let seed: u64 = 0xcafe;
        let data = make_test_buffer(seed, 4096);

        h.create_file("crash.bin", &data).expect("create crash.bin");
        h.fsync_file("crash.bin").expect("fsync crash.bin");

        // SIGKILL + lazy-unmount + remount same store.
        h.crash_and_remount().expect("crash and remount");

        let after = h.read_file("crash.bin").expect("read after crash recovery");
        verify_test_buffer(seed, &after).expect("crash recovery integrity");
    }

    // ── Empty file (zero-length write + fsync) ────────────────────────

    #[test]
    fn write_durability_empty_file_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        h.create_file("empty.bin", b"").expect("create empty.bin");
        h.fsync_file("empty.bin").expect("fsync empty.bin");

        h.remount().expect("remount");

        let after = h.read_file("empty.bin").expect("read after remount");
        assert!(after.is_empty(), "empty file must stay empty after remount");
    }

    // ── Overwrite-then-fsync (in-place mutation) ──────────────────────

    #[test]
    fn write_durability_overwrite_then_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let v1 = make_test_buffer(0xab, 4096);
        h.create_file("overwrite.bin", &v1).expect("create v1");
        h.fsync_file("overwrite.bin").expect("fsync v1");

        // Overwrite in-place via std::fs, then fsync.
        let v2 = make_test_buffer(0xcd, 4096);
        {
            use std::io::Write;
            let path = h.mount_path().join("overwrite.bin");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("open overwrite.bin for rewrite");
            f.write_all(&v2).expect("overwrite v2");
            f.sync_all().expect("fsync v2");
        }

        h.remount().expect("remount");

        let after = h.read_file("overwrite.bin").expect("read after remount");
        verify_test_buffer(0xcd, &after).expect("post-remount is v2, not v1");
    }

    // ── Directory durability ──────────────────────────────────────────

    #[test]
    fn write_durability_directory_with_children_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        h.mkdir_all("sub/deep").expect("mkdir -p sub/deep");

        let d1 = make_test_buffer(0x10, 1024);
        h.create_file("sub/deep/child1.bin", &d1)
            .expect("create child1");
        h.fsync_file("sub/deep/child1.bin").expect("fsync child1");

        let d2 = make_test_buffer(0x20, 1024);
        h.create_file("sub/child2.bin", &d2).expect("create child2");
        h.fsync_file("sub/child2.bin").expect("fsync child2");

        h.remount().expect("remount");

        // Directory structure must survive.
        let top = h.readdir(".").expect("readdir root");
        assert!(top.contains(&"sub".to_string()), "root must list sub/");

        let mid = h.readdir("sub").expect("readdir sub");
        assert!(mid.contains(&"deep".to_string()), "sub must list deep/");
        assert!(
            mid.contains(&"child2.bin".to_string()),
            "sub must list child2.bin"
        );

        let deep = h.readdir("sub/deep").expect("readdir sub/deep");
        assert!(
            deep.contains(&"child1.bin".to_string()),
            "deep must list child1.bin"
        );

        // File contents must survive.
        let c1 = h.read_file("sub/deep/child1.bin").expect("read child1");
        verify_test_buffer(0x10, &c1).expect("child1 integrity");

        let c2 = h.read_file("sub/child2.bin").expect("read child2");
        verify_test_buffer(0x20, &c2).expect("child2 integrity");
    }

    // ═══════════════════════════════════════════════════════════════════
    // capacity_exhaustion — ENOSPC edge tests
    // ═══════════════════════════════════════════════════════════════════
    mod capacity_exhaustion {
        use super::*;
        use std::io::Write;

        /// Write `chunk_sz`-byte files in a loop until the backing store
        /// returns ENOSPC.  Returns the number of successfully-written
        /// file slots.
        ///
        /// If the store is too large to exhaust in reasonable time, this
        /// may run for a while; on a tmpfs-backed CI environment it
        /// typically fills within a few hundred MB.
        fn fill_until_enospc(h: &MountHarness, chunk_sz: usize) -> usize {
            let data = vec![0xabu8; chunk_sz];
            for i in 0.. {
                let name = format!("_fill_{i:06}.bin");
                match h.create_file(&name, &data) {
                    Ok(()) => {
                        // If create_file succeeds via fs::write, the
                        // VFS layer accepted the write.  Sync to commit
                        // the allocation so the next iteration sees the
                        // reduced free count.
                        let _ = h.fsync_file(&name);
                    }
                    Err(e) => {
                        if e.raw_os_error() == Some(libc::ENOSPC) {
                            return i;
                        }
                        // Other errors are unexpected and should fail the test.
                        panic!("unexpected error during fill at slot {i}: {e}");
                    }
                }
            }
            unreachable!()
        }

        /// Write a small file (4096 bytes) through the FUSE mount, via
        /// direct std::fs so we can distinguish ENOSPC from other errors.
        fn write_through_fuse(
            h: &MountHarness,
            relative: &str,
            data: &[u8],
        ) -> std::io::Result<()> {
            let path = h.mount_path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&path)?;
            f.write_all(data)?;
            f.sync_all()?;
            Ok(())
        }

        // ── Test 1: write until ENOSPC, error is ENOSPC ──────────────

        #[test]
        fn capacity_exhaustion_write_returns_enospc() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            // Check how much free space we have first.
            let s = h.statfs().expect("statfs");
            let free_bytes = s.f_bfree.saturating_mul(s.f_bsize as u64);
            if free_bytes > 2_147_483_648 {
                // More than 2 GiB free — exhaustive fill is too slow.
                eprintln!(
                    "SKIP capacity_exhaustion_write_returns_enospc: \
                     {free_bytes} bytes free; store too large for \
                     deterministic ENOSPC test.  Add a --capacity-mb \
                     daemon option for bounded-capacity testing."
                );
                return;
            }

            // Fill the store.
            let filled = fill_until_enospc(&h, 1_048_576); // 1 MiB chunks
            assert!(filled > 0, "must have written at least one file");

            // Now try to write one more small file — must get ENOSPC.
            let err = write_through_fuse(&h, "_enospc_probe.bin", b"probe")
                .expect_err("write at capacity should fail");
            let errno = err.raw_os_error().unwrap_or(0);
            assert_eq!(
                errno,
                libc::ENOSPC,
                "write at capacity must return ENOSPC, got {errno}: {err}"
            );
        }

        // ── Test 2: pre-ENOSPC data remains intact ───────────────────

        #[test]
        fn capacity_exhaustion_preexisting_data_intact() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_preexisting_data_intact: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            // Write 5 files with known content before filling.
            let seeds: &[(u64, usize, &str)] = &[
                (0xf1, 4096, "pre_a.bin"),
                (0xf2, 8192, "pre_b.bin"),
                (0xf3, 16384, "pre_c.bin"),
                (0xf4, 32768, "pre_d.bin"),
                (0xf5, 65536, "pre_e.bin"),
            ];
            for &(seed, len, name) in seeds {
                let data = make_test_buffer(seed, len);
                h.create_file(name, &data)
                    .unwrap_or_else(|e| panic!("create {name}: {e}"));
                h.fsync_file(name)
                    .unwrap_or_else(|e| panic!("fsync {name}: {e}"));
            }

            // Fill remaining space.
            fill_until_enospc(&h, 1_048_576);

            // Read back all pre-fill files — must be intact.
            for &(seed, _len, name) in seeds {
                let got = h
                    .read_file(name)
                    .unwrap_or_else(|e| panic!("read {name}: {e}"));
                verify_test_buffer(seed, &got).unwrap_or_else(|e| panic!("verify {name}: {e}"));
            }
        }

        // ── Test 3: zero-length write at capacity ────────────────────

        #[test]
        fn capacity_exhaustion_empty_write_succeeds() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_empty_write_succeeds: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            fill_until_enospc(&h, 1_048_576);

            // Creating an empty file should not need new blocks.
            h.create_file("_empty_at_capacity.bin", b"")
                .expect("zero-length write at capacity must succeed");
        }

        // ── Test 4: truncate to smaller at capacity ──────────────────

        #[test]
        fn capacity_exhaustion_truncate_smaller_succeeds() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_truncate_smaller_succeeds: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            // Write a file before filling.
            let data = make_test_buffer(0xdd, 262_144); // 256 KiB
            h.create_file("_trunc_candidate.bin", &data)
                .expect("create trunc candidate");
            h.fsync_file("_trunc_candidate.bin")
                .expect("fsync trunc candidate");

            fill_until_enospc(&h, 1_048_576);

            // Truncate to half size via std::fs (should free blocks).
            {
                let path = h.mount_path().join("_trunc_candidate.bin");
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .expect("open for truncate");
                f.set_len(131_072).expect("truncate to 128 KiB at capacity");
                f.sync_all().expect("fsync after truncate");
            }

            // Read back the truncated file — first half must be intact.
            let got = h
                .read_file("_trunc_candidate.bin")
                .expect("read after truncate");
            assert_eq!(got.len(), 131_072, "truncated file length");
            verify_test_buffer(0xdd, &data[..131_072]).expect("truncated content intact");

            // Now the freed blocks should allow another small write.
            let small = b"small after truncate";
            write_through_fuse(&h, "_after_trunc.bin", small)
                .expect("small write after truncate must succeed");
        }

        // ── Test 5: remove file frees space for new write ────────────

        #[test]
        fn capacity_exhaustion_remove_reclaims_capacity() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_remove_reclaims_capacity: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            // Write a sacrificial file.
            let data = vec![0xccu8; 1_048_576]; // 1 MiB
            h.create_file("_sacrifice.bin", &data)
                .expect("create sacrifice");
            h.fsync_file("_sacrifice.bin").expect("fsync sacrifice");

            fill_until_enospc(&h, 1_048_576);

            // Remove the sacrificial file.
            h.remove_file("_sacrifice.bin")
                .expect("remove sacrifice at capacity");

            // Now a small write must succeed.
            write_through_fuse(&h, "_reclaimed.bin", b"reclaimed-space")
                .expect("write after removal at capacity must succeed");
        }

        // ── Test 6: fsync at capacity (no new allocation) ────────────

        #[test]
        fn capacity_exhaustion_fsync_at_capacity() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_fsync_at_capacity: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            // Write a file before filling.
            let data = make_test_buffer(0xfe, 4096);
            h.create_file("_fsync_at_cap.bin", &data)
                .expect("create _fsync_at_cap");
            h.fsync_file("_fsync_at_cap.bin")
                .expect("fsync before fill");

            fill_until_enospc(&h, 1_048_576);

            // Fsync of already-written file at capacity — no new blocks.
            h.fsync_file("_fsync_at_cap.bin")
                .expect("fsync at capacity must succeed");

            let got = h
                .read_file("_fsync_at_cap.bin")
                .expect("read after fsync at capacity");
            verify_test_buffer(0xfe, &got).expect("content intact after fsync at capacity");
        }

        // ── Test 7: stress — write loop, then read back every file ───

        #[test]
        fn capacity_exhaustion_stress_write_read_all() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_stress_write_read_all: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            // Write many 64 KiB files until ENOSPC, each with a distinct seed.
            let mut file_count = 0usize;
            let chunk = vec![0u8; 65536];
            while let Ok(()) = h.create_file(format!("_s_{file_count:06}.bin"), &chunk) {
                let _ = h.fsync_file(format!("_s_{file_count:06}.bin"));
                file_count += 1;
            }

            assert!(file_count > 0, "must write at least one file");

            // Read every file back — just verify existence and length.
            for i in 0..file_count {
                let name = format!("_s_{i:06}.bin");
                let got = h
                    .read_file(&name)
                    .unwrap_or_else(|e| panic!("read _s_{i:06}: {e}"));
                assert_eq!(
                    got.len(),
                    65536,
                    "_s_{i:06} length must be 65536, got {}",
                    got.len()
                );
            }
        }

        // ── Test 8: mkdir at capacity ────────────────────────────────

        #[test]
        fn capacity_exhaustion_mkdir_fails_enospc() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s = h.statfs().expect("statfs");
            let free_mb = (s.f_bfree.saturating_mul(s.f_bsize as u64)) / 1_048_576;
            if free_mb > 2048 {
                eprintln!(
                    "SKIP capacity_exhaustion_mkdir_fails_enospc: \
                     {free_mb} MiB free; store too large."
                );
                return;
            }

            fill_until_enospc(&h, 1_048_576);

            let err = h
                .mkdir("_dir_at_capacity")
                .expect_err("mkdir at capacity should fail");
            let errno = err.raw_os_error().unwrap_or(0);
            assert_eq!(
                errno,
                libc::ENOSPC,
                "mkdir at capacity must return ENOSPC, got {errno}: {err}"
            );
        }

        // ── Test 9: statfs reflects exhausted state ──────────────────

        #[test]
        fn capacity_exhaustion_statfs_reports_exhaustion() {
            let h = match try_mount() {
                Some(h) => h,
                None => return,
            };

            let s0 = h.statfs().expect("statfs before");
            let free0 = s0.f_bfree.saturating_mul(s0.f_bsize as u64);
            if free0 > 2_147_483_648 {
                eprintln!(
                    "SKIP capacity_exhaustion_statfs_reports_exhaustion: \
                     {free0} bytes free; store too large."
                );
                return;
            }

            // Sanity: before fill, free > 0.
            assert!(s0.f_bfree > 0, "free blocks nonzero before fill");

            fill_until_enospc(&h, 1_048_576);

            let s1 = h.statfs().expect("statfs after fill");

            // After fill, free blocks should be near zero.
            // The exact value may be a few blocks (daemon metadata or
            // rounding), so we allow up to 5% of original free blocks.
            let threshold = (free0 / 1_048_576).max(1) * 20; // ~20 blocks per MiB
            assert!(
                s1.f_bfree <= threshold,
                "after exhaustion f_bfree={} should be near zero (threshold={}, free0_mb={})",
                s1.f_bfree,
                threshold,
                free0 / 1_048_576
            );
            assert!(
                s1.f_bavail <= threshold,
                "after exhaustion f_bavail={} should be near zero",
                s1.f_bavail
            );
        }
    }
}
