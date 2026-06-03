//! Xattr-durability validation: mount, set/get/list/remove user extended
//! attributes, fsync or remount, verify xattr data survives remount cycle.
//!
//! Exercises the FUSE xattr durability contract across set, get, list, and
//! remove operations. Every test skips gracefully when the daemon binary or
//! /dev/fuse is unavailable.
//!
//! The entire module is `#[cfg(test)]` because it contains only tests
//! and test helpers — no library surface.

#[cfg(test)]
use crate::mount_harness::MountHarness;

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

    // ── set+get durability ──────────────────────────────────────────

    #[test]
    fn xattr_durability_set_get_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_setget.txt";
        h.create_file(path, b"xattr test").expect("create file");
        h.set_xattr(path, "mykey", b"myvalue").expect("set xattr");

        let before = h.get_xattr(path, "mykey").expect("get xattr before");
        assert_eq!(
            before.as_deref(),
            Some(&b"myvalue"[..]),
            "xattr value must be readable before remount"
        );

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let after = h.get_xattr(path, "mykey").expect("get xattr after");
        assert_eq!(
            after.as_deref(),
            Some(&b"myvalue"[..]),
            "xattr value must survive remount"
        );
    }

    // ── list durability ─────────────────────────────────────────────

    #[test]
    fn xattr_durability_list_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_list.txt";
        h.create_file(path, b"list test").expect("create file");
        h.set_xattr(path, "alpha", b"1").expect("set alpha");
        h.set_xattr(path, "beta", b"2").expect("set beta");
        h.set_xattr(path, "gamma", b"3").expect("set gamma");

        let before: std::collections::BTreeSet<String> = h
            .list_xattr(path)
            .expect("list xattr before")
            .into_iter()
            .collect();
        assert!(before.contains("alpha"));
        assert!(before.contains("beta"));
        assert!(before.contains("gamma"));

        h.remount().expect("remount");

        let after: std::collections::BTreeSet<String> = h
            .list_xattr(path)
            .expect("list xattr after")
            .into_iter()
            .collect();
        assert!(after.contains("alpha"), "alpha must survive remount");
        assert!(after.contains("beta"), "beta must survive remount");
        assert!(after.contains("gamma"), "gamma must survive remount");
    }

    // ── remove durability ───────────────────────────────────────────

    #[test]
    fn xattr_durability_remove_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_remove.txt";
        h.create_file(path, b"remove test").expect("create file");
        h.set_xattr(path, "todelete", b"will be removed")
            .expect("set xattr");
        h.remove_xattr(path, "todelete").expect("remove xattr");

        // Verify removal before remount.
        let before = h.get_xattr(path, "todelete").expect("get before");
        assert!(before.is_none(), "xattr must be absent after remove");

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let after = h.get_xattr(path, "todelete").expect("get after");
        assert!(
            after.is_none(),
            "xattr removal must survive remount: still absent"
        );
    }

    // ── multiple xattrs durability ──────────────────────────────────

    #[test]
    fn xattr_durability_multiple_values_survive_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_multi.txt";
        h.create_file(path, b"multi test").expect("create file");
        h.set_xattr(path, "key_a", b"value_a").expect("set key_a");
        h.set_xattr(path, "key_b", b"value_b").expect("set key_b");
        h.set_xattr(path, "key_c", b"value_c").expect("set key_c");

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        assert_eq!(
            h.get_xattr(path, "key_a").expect("get key_a").as_deref(),
            Some(&b"value_a"[..]),
            "key_a must survive remount"
        );
        assert_eq!(
            h.get_xattr(path, "key_b").expect("get key_b").as_deref(),
            Some(&b"value_b"[..]),
            "key_b must survive remount"
        );
        assert_eq!(
            h.get_xattr(path, "key_c").expect("get key_c").as_deref(),
            Some(&b"value_c"[..]),
            "key_c must survive remount"
        );

        // Also verify a non-existent key returns None.
        let missing = h.get_xattr(path, "nonexistent").expect("get missing");
        assert!(missing.is_none(), "unset xattr must return None");
    }

    // ── directory xattr durability ──────────────────────────────────

    #[test]
    fn xattr_durability_directory_xattr_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let dir = "xattrdir";
        h.mkdir(dir).expect("mkdir");
        h.set_xattr(dir, "dirkey", b"dirval")
            .expect("set xattr on dir");

        let before = h.get_xattr(dir, "dirkey").expect("get before");
        assert_eq!(
            before.as_deref(),
            Some(&b"dirval"[..]),
            "directory xattr must be readable before remount"
        );

        h.remount().expect("remount");

        let after = h.get_xattr(dir, "dirkey").expect("get after");
        assert_eq!(
            after.as_deref(),
            Some(&b"dirval"[..]),
            "directory xattr must survive remount"
        );
    }

    // ── empty value durability ──────────────────────────────────────

    #[test]
    fn xattr_durability_empty_value_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_empty.txt";
        h.create_file(path, b"empty test").expect("create file");
        h.set_xattr(path, "emptykey", b"").expect("set empty xattr");

        let before = h.get_xattr(path, "emptykey").expect("get before");
        assert_eq!(
            before.as_deref(),
            Some(&b""[..]),
            "empty xattr must be readable before remount"
        );

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let after = h.get_xattr(path, "emptykey").expect("get after");
        assert_eq!(
            after.as_deref(),
            Some(&b""[..]),
            "empty xattr must survive remount"
        );
    }

    // ── binary value durability ─────────────────────────────────────

    #[test]
    fn xattr_durability_binary_value_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_binary.bin";
        h.create_file(path, b"binary test").expect("create file");

        let binary_val: Vec<u8> = (0u8..=255u8).collect(); // all byte values
        h.set_xattr(path, "rawdata", &binary_val)
            .expect("set binary xattr");

        let before = h.get_xattr(path, "rawdata").expect("get before");
        assert_eq!(
            before.as_deref(),
            Some(&binary_val[..]),
            "binary xattr must be readable before remount"
        );

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let after = h.get_xattr(path, "rawdata").expect("get after");
        assert_eq!(
            after.as_deref(),
            Some(&binary_val[..]),
            "binary xattr must survive remount byte-for-byte"
        );
    }

    // ── modify durability ───────────────────────────────────────────

    #[test]
    fn xattr_durability_modify_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_mod.txt";
        h.create_file(path, b"mod test").expect("create file");
        h.set_xattr(path, "mutable", b"v1").expect("set v1");

        // Modify the same xattr.
        h.set_xattr(path, "mutable", b"v2_updated").expect("set v2");

        h.fsync_file(path).expect("fsync");
        h.remount().expect("remount");

        let after = h.get_xattr(path, "mutable").expect("get after");
        assert_eq!(
            after.as_deref(),
            Some(&b"v2_updated"[..]),
            "modified xattr value must survive remount, not the original"
        );
    }

    // ── fdatasync after xattr-only change ───────────────────────────

    #[test]
    fn xattr_durability_fdatasync_after_xattr_survives_remount() {
        let mut h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let path = "xattr_fdatasync.bin";
        h.create_file(path, b"fdatasync xattr test")
            .expect("create file");

        // xattr-only change (no data writes after create).
        h.set_xattr(path, "fdatakey", b"fdataval")
            .expect("set xattr");
        h.fdatasync_file(path)
            .expect("fdatasync after xattr change");

        h.remount().expect("remount");

        let after = h.get_xattr(path, "fdatakey").expect("get after");
        assert_eq!(
            after.as_deref(),
            Some(&b"fdataval"[..]),
            "xattr after fdatasync must survive remount"
        );

        // File content intact.
        let contents = h.read_file(path).expect("read");
        assert_eq!(contents, b"fdatasync xattr test");
    }
}
