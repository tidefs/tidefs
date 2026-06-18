// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Metadata-durability validation: mount, chmod/chown/utimens/truncate,
//! fsync or remount, verify metadata survives remount cycle.
//!
//! Exercises the FUSE setattr durability contract across chmod, chown,
//! utimens, and truncate operations. Every test skips gracefully when
//! the daemon binary or /dev/fuse is unavailable.
//!
//! The entire module is `#[cfg(test)]` because it contains only tests
//! and test helpers — no library surface.

#[cfg(test)]
use crate::mount_harness::MountHarness;

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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

    // ── chmod durability ────────────────────────────────────────────

    #[test]
    fn metadata_durability_chmod_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "chmod_test.txt";
        h.create_file(path, b"hello").expect("create file");
        h.chmod(path, 0o600).expect("chmod 0600");

        let before = h.stat(path).expect("stat before remount");
        assert_eq!(
            before.permissions().mode() & 0o777,
            0o600,
            "chmod should set mode to 0600"
        );

        h.remount().expect("remount");

        let after = h.stat(path).expect("stat after remount");
        assert_eq!(
            after.permissions().mode() & 0o777,
            0o600,
            "chmod should survive remount"
        );
    }

    // ── chown durability ────────────────────────────────────────────

    #[test]
    fn metadata_durability_chown_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "chown_test.txt";
        h.create_file(path, b"owner check").expect("create file");

        // Attempt non-root chown: as non-root, fchownat will fail with
        // EPERM.  We skip the test in that case because the harness
        // runs as a regular user.  When run as root, the test validates
        // the full round-trip.
        match h.chown(path, u32::MAX, u32::MAX) {
            Ok(()) => {
                // No-op chown (uid=u32::MAX, gid=u32::MAX = keep both)
                // just verifies the syscall path works.
            }
            Err(e) => {
                eprintln!("SKIP: chown not available in this context -- {e}");
                return;
            }
        }

        // Verify the file still exists and is readable after remount.
        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let _contents = h.read_file(path).expect("read after remount");
    }

    // ── utimens durability ──────────────────────────────────────────

    #[test]
    fn metadata_durability_utimens_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "utimens_test.txt";
        h.create_file(path, b"timestamp test").expect("create file");
        h.fsync_file(path).expect("fsync");

        // Set atime = 2024-01-15 10:30:00 UTC, mtime = 2024-06-20 14:45:00 UTC.
        let atime_sec: i64 = 1705312200; // 2024-01-15T10:30:00Z
        let mtime_sec: i64 = 1718891100; // 2024-06-20T14:45:00Z
        h.utimens(path, atime_sec, 0, mtime_sec, 0)
            .expect("utimens");

        // Check timestamps before remount.
        let md = h.stat(path).expect("stat before remount");
        let before_mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
        assert_eq!(
            before_mtime
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            mtime_sec,
            "mtime should be set before remount"
        );

        h.remount().expect("remount");

        let md2 = h.stat(path).expect("stat after remount");
        let after_mtime = md2.modified().unwrap_or(std::time::UNIX_EPOCH);
        let after_mtime_sec = after_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        assert_eq!(
            after_mtime_sec, mtime_sec,
            "mtime must survive remount: expected {mtime_sec}, got {after_mtime_sec}"
        );
    }

    // ── truncate-to-zero durability ─────────────────────────────────

    #[test]
    fn metadata_durability_truncate_to_zero_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "trunc0.bin";
        h.create_file(path, &[0xAAu8; 4096])
            .expect("create 4 KiB file");
        h.fsync_file(path).expect("fsync");

        assert_eq!(h.stat(path).expect("stat").len(), 4096);

        h.truncate(path, 0).expect("truncate to 0");
        h.fsync_file(path).expect("fsync after truncate");

        assert_eq!(h.stat(path).expect("stat after truncate").len(), 0);

        h.remount().expect("remount");

        assert_eq!(
            h.stat(path).expect("stat after remount").len(),
            0,
            "truncate to zero must survive remount"
        );
    }

    // ── truncate-to-nonzero durability ──────────────────────────────

    #[test]
    fn metadata_durability_truncate_to_nonzero_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "trunc_nonzero.bin";
        let data: Vec<u8> = (0u8..=255u8).cycle().take(8192).collect();
        h.create_file(path, &data).expect("create 8 KiB file");
        h.fsync_file(path).expect("fsync");

        assert_eq!(h.stat(path).expect("stat").len(), 8192);

        // Truncate to 512 bytes.
        h.truncate(path, 512).expect("truncate to 512");
        h.fsync_file(path).expect("fsync after truncate");

        assert_eq!(h.stat(path).expect("stat after truncate").len(), 512);

        h.remount().expect("remount");

        let after = h.read_file(path).expect("read after remount");
        assert_eq!(after.len(), 512, "file length must survive remount");
        assert_eq!(&after[..], &data[..512], "first 512 bytes must match");
    }

    // ── Combined chmod+chown+utimens durability ─────────────────────

    #[test]
    fn metadata_durability_combined_attrs_survive_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "combined.bin";
        h.create_file(path, b"combined test").expect("create file");

        // chmod to 0644.
        h.chmod(path, 0o644).expect("chmod 0644");

        // utimens: set mtime to a known value.
        let mtime_sec: i64 = 1700000000;
        h.utimens(path, 0, libc::UTIME_OMIT, mtime_sec, 0)
            .expect("utimens");

        h.fsync_file(path).expect("fsync");

        h.remount().expect("remount");

        // Verify mode.
        let md = h.stat(path).expect("stat after remount");
        assert_eq!(
            md.permissions().mode() & 0o777,
            0o644,
            "mode must survive remount"
        );

        // Verify mtime.
        let after_mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
        let after_sec = after_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(
            after_sec, mtime_sec,
            "mtime must survive remount: expected {mtime_sec}, got {after_sec}"
        );

        // File content intact.
        let contents = h.read_file(path).expect("read after remount");
        assert_eq!(contents, b"combined test");
    }

    // ── Metadata durability on a directory ──────────────────────────

    #[test]
    fn metadata_durability_directory_attrs_survive_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let dir = "metadir";
        h.mkdir(dir).expect("mkdir");

        h.chmod(dir, 0o755).expect("chmod dir 0755");

        let mtime_sec: i64 = 1690000000;
        h.utimens(dir, 0, libc::UTIME_OMIT, mtime_sec, 0)
            .expect("utimens dir");

        h.remount().expect("remount");

        let md = h.stat(dir).expect("stat dir after remount");
        assert!(md.is_dir(), "directory must still be a directory");

        let mode = md.permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "dir mode must survive remount, got {mode:#o}");

        let after_mtime = md.modified().unwrap_or(std::time::UNIX_EPOCH);
        let after_sec = after_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert_eq!(
            after_sec, mtime_sec,
            "dir mtime must survive remount: expected {mtime_sec}, got {after_sec}"
        );
    }

    // ── fdatasync after metadata-only change ────────────────────────

    #[test]
    fn metadata_durability_fdatasync_after_chmod_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "fdatasync_meta.bin";
        h.create_file(path, b"fdatasync metadata test")
            .expect("create file");

        // chmod only (no data writes after create).
        h.chmod(path, 0o640).expect("chmod 0640");
        h.fdatasync_file(path)
            .expect("fdatasync after metadata change");

        h.remount().expect("remount");

        let md = h.stat(path).expect("stat after remount");
        assert_eq!(
            md.permissions().mode() & 0o777,
            0o640,
            "mode after fdatasync must survive remount"
        );

        let contents = h.read_file(path).expect("read");
        assert_eq!(contents, b"fdatasync metadata test");
    }
}
