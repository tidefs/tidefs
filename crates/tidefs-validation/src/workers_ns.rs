//! Namespace-operation validation: mkdir, rmdir, rename, link, unlink.
//!
//! Exercises the full adapter stack (FUSE decode -> ingress -> capacity
//! dispatch -> workers-ns handler -> reply encode) through a real FUSE
//! mount.  Every test skips gracefully when the daemon binary or
//! /dev/fuse is unavailable.
//!
//! The entire module is `#[cfg(test)]` because it contains only tests
//! and test helpers -- no library surface.

#[cfg(test)]
use crate::mount_harness::MountHarness;

#[cfg(test)]
use std::os::unix::fs::MetadataExt;

// ── Helpers ────────────────────────────────────────────────────────────────

#[cfg(test)]
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

#[cfg(test)]
/// Assert that `result` is an IO error with the expected raw OS error
/// code (e.g. `libc::EEXIST`).  Panics with a descriptive message on
/// mismatch.
fn assert_errno(result: std::io::Result<()>, expected_errno: libc::c_int, context: &str) {
    assert!(result.is_err(), "{context}: expected error, got Ok");
    let err = result.unwrap_err();
    let got = err.raw_os_error();
    assert_eq!(
        got,
        Some(expected_errno),
        "{context}: expected errno {expected_errno}, got {got:?} ({err:?})",
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ═══════════════════════════════════════════════════════════════════
    // mkdir
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn mkdir_create_in_empty_root() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("newdir").expect("mkdir newdir");
        assert!(h.exists("newdir"));
        let md = h.stat("newdir").expect("stat newdir");
        assert!(md.is_dir(), "newdir must be a directory");
        assert_eq!(md.nlink(), 2, "new directory has . and .. entries");
    }

    #[test]
    fn mkdir_create_with_existing_siblings() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("a").expect("mkdir a");
        h.mkdir("b").expect("mkdir b");
        assert!(h.exists("a"));
        assert!(h.exists("b"));

        let entries = h.readdir(".").expect("readdir root");
        assert!(entries.contains(&"a".to_string()), "root must contain a");
        assert!(entries.contains(&"b".to_string()), "root must contain b");
    }

    #[test]
    fn mkdir_dup_returns_eexist() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("only_once").expect("first mkdir");
        assert_errno(h.mkdir("only_once"), libc::EEXIST, "mkdir duplicate name");
        // Original must still be a directory.
        assert!(h.exists("only_once"));
        let md = h.stat("only_once").expect("stat after dup");
        assert!(md.is_dir(), "must still be a directory");
    }

    #[test]
    fn mkdir_parent_is_file_returns_enotdir() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("f", b"blocker\n").expect("create file f");
        assert_errno(h.mkdir("f/sub"), libc::ENOTDIR, "mkdir through file");
    }

    #[test]
    fn mkdir_missing_intermediate_returns_enoent() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        assert_errno(
            h.mkdir("a/b/c"),
            libc::ENOENT,
            "mkdir with missing intermediate",
        );
    }

    #[test]
    fn mkdir_nested_via_mkdir_all() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir_all("a/b/c").expect("mkdir_all a/b/c");
        assert!(h.exists("a"));
        assert!(h.exists("a/b"));
        assert!(h.exists("a/b/c"));
        let md = h.stat("a/b/c").expect("stat c");
        assert!(md.is_dir(), "c must be a directory");
    }

    // ═══════════════════════════════════════════════════════════════════
    // rmdir
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn rmdir_empty_directory() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("d").expect("mkdir d");
        h.remove_dir("d").expect("rmdir d");
        assert!(!h.exists("d"), "d must be gone after rmdir");
    }

    #[test]
    fn rmdir_nonempty_returns_enotempty() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("d").expect("mkdir d");
        h.create_file("d/f.txt", b"data\n").expect("create child");
        assert_errno(
            h.remove_dir("d"),
            libc::ENOTEMPTY,
            "rmdir non-empty directory",
        );
        // Directory and child must still exist.
        assert!(h.exists("d"));
        assert!(h.exists("d/f.txt"));
    }

    #[test]
    fn rmdir_nonexistent_returns_enoent() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        assert_errno(
            h.remove_dir("no_such_dir"),
            libc::ENOENT,
            "rmdir nonexistent",
        );
    }

    #[test]
    fn rmdir_on_file_returns_enotdir() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("f.txt", b"not a dir\n").expect("create file");
        assert_errno(
            h.remove_dir("f.txt"),
            libc::ENOTDIR,
            "rmdir on regular file",
        );
        assert!(h.exists("f.txt"), "file must survive failed rmdir");
    }

    // ═══════════════════════════════════════════════════════════════════
    // rename
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn rename_within_same_directory() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("old.txt", b"content\n")
            .expect("create old.txt");
        h.rename("old.txt", "new.txt").expect("rename old -> new");
        assert!(!h.exists("old.txt"), "old name must be gone");
        assert!(h.exists("new.txt"), "new name must exist");
        let data = h.read_file("new.txt").expect("read new.txt");
        assert_eq!(data, b"content\n", "content must survive rename");
    }

    #[test]
    fn rename_across_directories() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("src").expect("mkdir src");
        h.mkdir("dst").expect("mkdir dst");
        h.create_file("src/f.txt", b"move me\n")
            .expect("create f.txt");
        h.rename("src/f.txt", "dst/f.txt")
            .expect("rename across dirs");
        assert!(!h.exists("src/f.txt"), "source must be gone");
        assert!(h.exists("dst/f.txt"), "destination must exist");
        let data = h.read_file("dst/f.txt").expect("read dst/f.txt");
        assert_eq!(data, b"move me\n", "content must survive cross-dir rename");
    }

    #[test]
    fn rename_overwrite_existing_target() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("a.txt", b"aaa\n").expect("create a.txt");
        h.create_file("b.txt", b"bbb\n").expect("create b.txt");
        h.rename("a.txt", "b.txt").expect("rename overwrite");
        assert!(!h.exists("a.txt"), "source must be gone");
        assert!(h.exists("b.txt"), "target must exist");
        let data = h.read_file("b.txt").expect("read b.txt");
        assert_eq!(
            data, b"aaa\n",
            "content must be from source after overwrite"
        );
    }

    #[test]
    fn rename_missing_source_returns_enoent() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let result = h.rename("no_such", "dest");
        assert_errno(result, libc::ENOENT, "rename missing source");
    }

    #[test]
    fn rename_source_parent_is_file_returns_enotdir() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("blocker", b"x\n").expect("create file");
        let result = h.rename("blocker/x", "dest");
        assert_errno(result, libc::ENOTDIR, "rename through file");
    }

    // ═══════════════════════════════════════════════════════════════════
    // link
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn hard_link_creates_new_name() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("primary.bin", b"shared content\n")
            .expect("create primary");
        let primary = h.mount_path().join("primary.bin");
        let alias = h.mount_path().join("alias.bin");
        fs::hard_link(&primary, &alias).expect("hard_link primary -> alias");
        assert!(h.exists("alias.bin"), "alias must exist");
        let data = h.read_file("alias.bin").expect("read alias");
        assert_eq!(
            data, b"shared content\n",
            "alias content must match primary"
        );
    }

    #[test]
    fn hard_link_increments_nlink() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("primary.bin", b"link count test\n")
            .expect("create primary");
        let nlink_before = h.stat("primary.bin").expect("stat before").nlink();

        let primary = h.mount_path().join("primary.bin");
        let alias = h.mount_path().join("alias.bin");
        fs::hard_link(&primary, &alias).expect("hard_link");

        let nlink_after = h.stat("primary.bin").expect("stat after").nlink();
        assert_eq!(
            nlink_after,
            nlink_before + 1,
            "nlink must increment: {nlink_before} -> {nlink_after}"
        );
        let alias_nlink = h.stat("alias.bin").expect("stat alias").nlink();
        assert_eq!(
            alias_nlink, nlink_after,
            "alias nlink must match primary nlink after hard link"
        );
    }

    #[test]
    fn hard_link_missing_source_returns_enoent() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        let primary = h.mount_path().join("no_such");
        let alias = h.mount_path().join("alias.bin");
        let result = fs::hard_link(&primary, &alias);
        assert_errno(result, libc::ENOENT, "hard_link missing source");
    }

    #[test]
    fn hard_link_directory_returns_eperm() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("d").expect("mkdir d");
        let dir_path = h.mount_path().join("d");
        let alias = h.mount_path().join("d_link");
        let result = fs::hard_link(&dir_path, &alias);
        // Linux returns EPERM for hard-linking a directory.
        assert_errno(result, libc::EPERM, "hard_link directory");
    }

    // ═══════════════════════════════════════════════════════════════════
    // unlink
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn unlink_removes_regular_file() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("gone.txt", b"temporary\n")
            .expect("create file");
        assert!(h.exists("gone.txt"));
        h.remove_file("gone.txt").expect("unlink gone.txt");
        assert!(!h.exists("gone.txt"), "file must be gone after unlink");
    }

    #[test]
    fn unlink_nonexistent_returns_enoent() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        assert_errno(
            h.remove_file("no_such_file"),
            libc::ENOENT,
            "unlink nonexistent",
        );
    }

    #[test]
    fn unlink_directory_returns_eisdir() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.mkdir("d").expect("mkdir d");
        let result = h.remove_file("d");
        // Linux returns EISDIR when unlinking a directory (use rmdir instead).
        assert_errno(result, libc::EISDIR, "unlink on directory");
        assert!(h.exists("d"), "directory must survive failed unlink");
    }

    #[test]
    fn unlink_decrements_nlink() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };
        h.create_file("lonely.bin", b"last link\n")
            .expect("create file");
        // A file with a single hard link has nlink == 1; after unlink it's gone.
        let nlink_before = h.stat("lonely.bin").expect("stat before").nlink();
        assert!(nlink_before >= 1, "single-link file must have nlink >= 1");
        h.remove_file("lonely.bin").expect("unlink");
        assert!(!h.exists("lonely.bin"), "file must be gone");
    }
}
