// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! End-to-end FUSE mount harness for the TideFS POSIX filesystem adapter daemon.
//!
//! `MountHarness` spawns the `tidefs-posix-filesystem-adapter-daemon` binary,
//! waits for the mount point to become ready, and exposes helper methods for
//! file IO, metadata, and directory operations through the mounted filesystem
//! path. Cleanup (unmount and temp directory removal) happens on `Drop`.
//!
//! The daemon binary is located via, in order:
//! 1. `TIDEFS_DAEMON_BIN` environment variable (absolute path)
//! 2. `CARGO_TARGET_DIR`/debug/ or `CARGO_TARGET_DIR`/release/
//! 3. `target/debug/` or `target/release/` relative to the workspace root

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

/// Manages a FUSE-mounted TideFS instance backed by a local filesystem store.
pub struct MountHarness {
    /// Temporary root directory (parent of both store and mount).
    #[allow(dead_code)]
    work_dir: tempfile::TempDir,
    /// Path to the backing store directory.
    store_path: PathBuf,
    /// Path to the FUSE mount point.
    mount_path: PathBuf,
    /// Handle to the daemon child process.
    child: Child,
    /// PID of the daemon process (cached before possible reap).
    daemon_pid: u32,
}

// ── builder ────────────────────────────────────────────────────────

/// Builder for [`MountHarness`] with optional configuration overrides.
pub struct MountHarnessBuilder {
    daemon_bin: Option<PathBuf>,
    extra_args: Vec<String>,
}

impl MountHarnessBuilder {
    fn new() -> Self {
        Self {
            daemon_bin: None,
            extra_args: Vec::new(),
        }
    }

    /// Override the daemon binary path. When unset, the builder falls
    /// back to [`find_daemon_binary`].
    pub fn daemon_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.daemon_bin = Some(path.into());
        self
    }

    /// Extra command-line arguments appended after the required
    /// `mount-vfs --store ... --mount ... --root-auth-key-hex ...`
    /// arguments.
    ///
    /// Use this to pass FUSE mount options such as `-o allow_other`.
    pub fn extra_args(mut self, args: &[&str]) -> Self {
        self.extra_args = args.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Enable per-object compression on the backing store by passing
    /// `--compress-algo` to the daemon.
    ///
    /// Valid values: `"zstd"`, `"lz4"`, `"off"`.
    pub fn compress_algo(mut self, algo: &str) -> Self {
        self.extra_args.push("--compress-algo".to_string());
        self.extra_args.push(algo.to_string());
        self
    }

    /// Build a [`MountHarness`] with the configured options.
    ///
    /// Creates a temp working directory, spawns the daemon, and blocks
    /// until the FUSE mount point becomes ready.
    /// Enable the org.tidefs:dedup dataset feature flag on mount so
    /// inline content-addressed chunk dedup is active during writes.
    pub fn enable_dedup(mut self) -> Self {
        self.extra_args.push("--enable-dedup".to_string());
        self
    }

    pub fn build(self) -> io::Result<MountHarness> {
        let daemon_bin = match self.daemon_bin {
            Some(ref p) => p.clone(),
            None => find_daemon_binary()?,
        };

        let work_dir = tempfile::TempDir::new()
            .map_err(|e| io::Error::other(format!("create harness work dir: {e}")))?;

        let store_path = work_dir.path().join("store");
        let mount_path = work_dir.path().join("mnt");

        fs::create_dir_all(&store_path).map_err(|e| {
            io::Error::other(format!("create store dir {}: {e}", store_path.display()))
        })?;
        fs::create_dir_all(&mount_path).map_err(|e| {
            io::Error::other(format!("create mount dir {}: {e}", mount_path.display()))
        })?;

        // Demo root authentication key avoids requiring env setup.
        let root_auth_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";

        let mut cmd = Command::new(&daemon_bin);
        cmd.arg("mount-vfs")
            .arg("--store")
            .arg(&store_path)
            .arg("--mount")
            .arg(&mount_path)
            .arg("--root-auth-key-hex")
            .arg(root_auth_key_hex);

        for arg in &self.extra_args {
            cmd.arg(arg);
        }

        let child = cmd
            .spawn()
            .map_err(|e| io::Error::other(format!("spawn daemon {}: {e}", daemon_bin.display())))?;

        let daemon_pid = child.id();

        wait_for_mount(&mount_path, Duration::from_secs(10)).map_err(|e| {
            kill_child(daemon_pid);
            io::Error::other(format!(
                "mount point {} did not become ready: {e}",
                mount_path.display()
            ))
        })?;

        Ok(MountHarness {
            work_dir,
            store_path,
            mount_path,
            child,
            daemon_pid,
        })
    }
}

/// Alias for [`MountHarness`] matching the original issue naming convention.
pub type FuseMountFixture = MountHarness;

impl MountHarness {
    /// Spawn the daemon binary, create a temp backing store, mount at a temp
    /// mount point, and block until the mount point responds to `stat`.
    ///
    /// Uses the binary location from `find_daemon_binary`.  The backing store
    /// is initialised with a demo root authentication key so no environment
    /// setup is required.
    pub fn new() -> io::Result<Self> {
        Self::builder().build()
    }

    /// Format the mounted-runtime refusal emitted when the daemon, FUSE device,
    /// or another substrate prerequisite is absent.
    ///
    /// This is harness/refusal signal only. Callers that claim mounted product
    /// behavior should fail closed with [`Self::new_or_fail`] instead of
    /// returning success after printing the message.
    pub fn runtime_refusal_message(scope: &str, error: impl std::fmt::Display) -> String {
        format!(
            "RUNTIME REFUSAL {scope}: mounted runtime substrate unavailable; \
             this is harness/refusal signal only, not mounted product proof -- {error}"
        )
    }

    /// Return a mount harness when the daemon is available, or print an
    /// explicit runtime-refusal receipt and let harness-only callers return.
    pub fn new_or_skip(scope: &str) -> Option<Self> {
        match Self::new() {
            Ok(harness) => Some(harness),
            Err(e) => {
                eprintln!("{}", Self::runtime_refusal_message(scope, e));
                None
            }
        }
    }

    /// Return a mount harness or fail closed when mounted runtime prerequisites
    /// are absent.
    pub fn new_or_fail(scope: &str) -> Self {
        Self::new().unwrap_or_else(|e| panic!("{}", Self::runtime_refusal_message(scope, e)))
    }

    /// Create a [`MountHarnessBuilder`] for customised harness setup.
    ///
    /// Use the builder when you need to override the daemon binary path,
    /// pass extra FUSE mount options, or configure pool parameters.
    pub fn builder() -> MountHarnessBuilder {
        MountHarnessBuilder::new()
    }

    /// Absolute path to the mounted filesystem root.
    pub fn mount_path(&self) -> &Path {
        &self.mount_path
    }

    /// Absolute path to the backing store directory.
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// PID of the daemon process.
    pub fn daemon_pid(&self) -> u32 {
        self.daemon_pid
    }

    // ── helpers ────────────────────────────────────────────────────

    /// Resolve a relative path under the mount point.
    fn mounted(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.mount_path.join(relative)
    }

    /// Create a file at `relative` under the mount point with `contents`.
    /// Creates missing parent directories automatically.
    pub fn create_file(&self, relative: impl AsRef<Path>, contents: &[u8]) -> io::Result<()> {
        let path = self.mounted(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, contents)
    }

    /// Read the full contents of a file at `relative` under the mount point.
    pub fn read_file(&self, relative: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        fs::read(self.mounted(relative))
    }

    /// `stat` the file at `relative`, returning `std::fs::Metadata`.
    pub fn stat(&self, relative: impl AsRef<Path>) -> io::Result<fs::Metadata> {
        fs::metadata(self.mounted(relative))
    }

    /// Return `true` if a file or directory exists at `relative`.
    pub fn exists(&self, relative: impl AsRef<Path>) -> bool {
        self.mounted(relative).exists()
    }

    /// Create a directory at `relative` under the mount point.
    pub fn mkdir(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        fs::create_dir(self.mounted(relative))
    }

    /// Create a directory and all missing parents at `relative`.
    pub fn mkdir_all(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        fs::create_dir_all(self.mounted(relative))
    }

    /// List directory entry names (excluding `.` and `..`) at `relative`.
    /// Entries are returned sorted for deterministic assertions.
    pub fn readdir(&self, relative: impl AsRef<Path>) -> io::Result<Vec<String>> {
        let dir = self.mounted(relative);
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir)
            .map_err(|e| io::Error::other(format!("readdir {}: {e}", dir.display())))?
        {
            let entry = entry
                .map_err(|e| io::Error::other(format!("readdir entry {}: {e}", dir.display())))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != "." && name != ".." {
                entries.push(name);
            }
        }
        entries.sort();
        Ok(entries)
    }

    /// Remove a file at `relative` under the mount point.
    pub fn remove_file(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        fs::remove_file(self.mounted(relative))
    }

    /// Remove an empty directory at `relative` under the mount point.
    pub fn remove_dir(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        fs::remove_dir(self.mounted(relative))
    }

    /// Rename (move) a file or directory at `old` to `new` under the mount point.
    /// Both paths are interpreted relative to the mount root.
    pub fn rename(&self, old: impl AsRef<Path>, new: impl AsRef<Path>) -> io::Result<()> {
        fs::rename(self.mounted(old), self.mounted(new))
    }

    /// Change the mode (permission bits) of a file at `relative`.
    pub fn chmod(&self, relative: impl AsRef<Path>, mode: u32) -> io::Result<()> {
        let path = self.mounted(relative);
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&path, perms)
    }

    /// chown(2) a file at `relative` under the mount point.
    /// Changes both owner (uid) and group (gid). Pass `u32::MAX` for
    /// either to leave it unchanged (matches -1 semantics).
    pub fn chown(&self, relative: impl AsRef<Path>, uid: u32, gid: u32) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        // SAFETY: fchownat is a C FFI call; path_c is a valid null-terminated
        // CString; AT_FDCWD is a valid sentinel; uid/gid are valid integer UID/GID.
        let rc = unsafe { libc::fchownat(libc::AT_FDCWD, path_c.as_ptr(), uid, gid, 0) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// utimens(2) a file at `relative` under the mount point.
    /// Sets access time (atime_sec / atime_nsec) and modification time
    /// (mtime_sec / mtime_nsec). Pass `0` for tv_nsec to set to the
    /// given seconds; pass `libc::UTIME_NOW` to set to current time;
    /// pass `libc::UTIME_OMIT` to leave unchanged.
    pub fn utimens(
        &self,
        relative: impl AsRef<Path>,
        atime_sec: i64,
        atime_nsec: i64,
        mtime_sec: i64,
        mtime_nsec: i64,
    ) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        let times = [
            libc::timespec {
                tv_sec: atime_sec as libc::time_t,
                tv_nsec: atime_nsec,
            },
            libc::timespec {
                tv_sec: mtime_sec as libc::time_t,
                tv_nsec: mtime_nsec,
            },
        ];
        // SAFETY: utimensat is a C FFI call; path_c is a valid null-terminated
        // CString; times is a live [libc::timespec; 2] on the stack; AT_FDCWD
        // is a valid sentinel.
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// symlink(2): create a symbolic link at `linkpath` pointing to
    /// `target`, both resolved relative to the mount root.
    pub fn symlink(&self, target: impl AsRef<Path>, linkpath: impl AsRef<Path>) -> io::Result<()> {
        let link = self.mounted(linkpath);
        let link_c = CString::new(link.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("linkpath with nul: {e}")))?;
        let target_c = CString::new(target.as_ref().as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("target with nul: {e}")))?;
        // SAFETY: symlinkat is a C FFI call; target_c and link_c are valid
        // null-terminated CStrings; AT_FDCWD is a valid sentinel.
        let rc = unsafe { libc::symlinkat(target_c.as_ptr(), libc::AT_FDCWD, link_c.as_ptr()) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// link(2): create a hard link at `new` pointing to `existing`,
    /// both resolved relative to the mount root.
    pub fn hardlink(&self, existing: impl AsRef<Path>, new: impl AsRef<Path>) -> io::Result<()> {
        let existing_path = self.mounted(existing);
        let new_path = self.mounted(new);
        let existing_c = CString::new(existing_path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("existing path with nul: {e}")))?;
        let new_c = CString::new(new_path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("new path with nul: {e}")))?;
        // SAFETY: linkat is a C FFI call; existing_c and new_c are valid
        // null-terminated CStrings; AT_FDCWD is a valid sentinel; flags=0.
        let rc = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                existing_c.as_ptr(),
                libc::AT_FDCWD,
                new_c.as_ptr(),
                0,
            )
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    /// mknod(2): create a special file (FIFO, socket, block/char device
    /// node) at `relative` with the given `mode` and `rdev`, resolved
    /// relative to the mount root.
    pub fn mknod(
        &self,
        relative: impl AsRef<Path>,
        mode: libc::mode_t,
        rdev: libc::dev_t,
    ) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        // SAFETY: mknodat is a C FFI call; path_c is a valid CString;
        // AT_FDCWD is a valid sentinel; mode and rdev are valid values.
        let rc = unsafe { libc::mknodat(libc::AT_FDCWD, path_c.as_ptr(), mode, rdev) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// readlink(2): read the target of the symbolic link at `relative`.
    /// Returns the symlink target as a `PathBuf`.
    pub fn readlink(&self, relative: impl AsRef<Path>) -> io::Result<PathBuf> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        let mut buf = vec![0u8; 4096]; // PATH_MAX-sized buffer
                                       // SAFETY: readlinkat is a C FFI call; path_c is a valid CString;
                                       // buf is a Vec<u8> with PATH_MAX capacity; AT_FDCWD is a valid sentinel.
        let rc = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(rc as usize);
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf)))
    }

    /// Return the `st_nlink` count for a file. Uses lstat to follow
    /// symlink semantics: returns the link count of the symlink itself,
    /// not its target.
    pub fn nlink(&self, relative: impl AsRef<Path>) -> io::Result<u64> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        // SAFETY: libc::stat is a C struct of integers; zero is a valid bit
        // pattern for all fields. The struct is passed by reference to fstatat
        // which fills it, so no UB from reading uninitialized data.
        let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstatat is a C FFI call; path_c is a valid null-terminated
        // CString; the stat buffer is a live local on the stack; AT_FDCWD
        // is a valid sentinel; AT_SYMLINK_NOFOLLOW is a valid flag.
        let rc = unsafe {
            libc::fstatat(
                libc::AT_FDCWD,
                path_c.as_ptr(),
                &mut stat_buf,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stat_buf.st_nlink)
    }

    pub fn truncate(&self, relative: impl AsRef<Path>, size: u64) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        // SAFETY: truncate is a C FFI call; path_c is a valid null-terminated
        // CString; size is a valid off_t.
        let rc = unsafe { libc::truncate(path_c.as_ptr(), size as libc::off_t) };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// fsync (sync_all) a file at `relative` under the mount point.
    pub fn fsync_file(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        use std::fs::File;
        let path = self.mounted(relative);
        let file = File::open(&path)
            .map_err(|e| io::Error::other(format!("open for fsync {}: {e}", path.display())))?;
        file.sync_all()
            .map_err(|e| io::Error::other(format!("fsync {}: {e}", path.display())))
    }

    /// fdatasync (sync_data) a file at `relative` under the mount point.
    /// Unlike fsync, fdatasync skips metadata sync; file content is flushed
    /// but mtime may be stale after crash recovery.
    pub fn fdatasync_file(&self, relative: impl AsRef<Path>) -> io::Result<()> {
        use std::fs::File;
        let path = self.mounted(relative);
        let file = File::open(&path)
            .map_err(|e| io::Error::other(format!("open for fdatasync {}: {e}", path.display())))?;
        file.sync_data()
            .map_err(|e| io::Error::other(format!("fdatasync {}: {e}", path.display())))
    }

    // ── xattr helpers ──────────────────────────────────────────────

    /// Set a user extended attribute on the file at `relative`.  The
    /// attribute name is automatically prefixed with `user.`.
    pub fn set_xattr(
        &self,
        relative: impl AsRef<Path>,
        name: &str,
        value: &[u8],
    ) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        let full_name = format!("user.{name}");
        let name_c = CString::new(full_name.as_bytes())
            .map_err(|e| io::Error::other(format!("xattr name with nul: {e}")))?;

        // SAFETY: setxattr is a C FFI call; path_c and name_c are valid
        // CStrings; value is a valid slice; flags=0 per POSIX (create or replace).
        let rc = unsafe {
            libc::setxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0, // 0 = create or replace
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Get the value of a user extended attribute from the file at
    /// `relative`.  The attribute name is automatically prefixed with
    /// `user.`.  Returns `None` if the attribute does not exist.
    pub fn get_xattr(&self, relative: impl AsRef<Path>, name: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        let full_name = format!("user.{name}");
        let name_c = CString::new(full_name.as_bytes())
            .map_err(|e| io::Error::other(format!("xattr name with nul: {e}")))?;

        // First call: get the value size.
        let size =
            // SAFETY: getxattr is a C FFI call; path_c and name_c are valid
            // null-terminated CStrings; null buffer with size 0 queries the
            // attribute size per POSIX semantics.
            unsafe { libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            return Err(err);
        }

        // Second call: read the value.
        let mut buf = vec![0u8; size as usize];
        // SAFETY: getxattr is a C FFI call; path_c and name_c are valid
        // CStrings; buf has the correct size from the prior size query.
        let rc = unsafe {
            libc::getxattr(
                path_c.as_ptr(),
                name_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(rc as usize);
        Ok(Some(buf))
    }

    /// List user extended attribute names on the file at `relative`.
    /// Only names in the `user.` namespace are returned (with the
    /// `user.` prefix stripped).
    pub fn list_xattr(&self, relative: impl AsRef<Path>) -> io::Result<Vec<String>> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;

        // First call: get the buffer size.
        // SAFETY: listxattr is a C FFI call; path_c is a valid CString;
        // null buffer with size 0 returns required buffer size per POSIX.
        let size = unsafe { libc::listxattr(path_c.as_ptr(), std::ptr::null_mut(), 0) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size == 0 {
            return Ok(Vec::new());
        }

        // Second call: read the list.
        let mut buf = vec![0u8; size as usize];
        // SAFETY: listxattr is a C FFI call; path_c is a valid CString;
        // buf size matches the prior size query result.
        let rc = unsafe {
            libc::listxattr(
                path_c.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(rc as usize);

        // The buffer contains null-terminated names. Split and filter
        // for the `user.` namespace.
        let names: Vec<String> = buf
            .split(|b| *b == 0)
            .filter_map(|chunk| {
                if chunk.is_empty() {
                    return None;
                }
                let name = String::from_utf8_lossy(chunk).into_owned();
                name.strip_prefix("user.").map(|rest| rest.to_string())
            })
            .collect();
        Ok(names)
    }

    /// Remove a user extended attribute from the file at `relative`.
    /// The attribute name is automatically prefixed with `user.`.
    pub fn remove_xattr(&self, relative: impl AsRef<Path>, name: &str) -> io::Result<()> {
        let path = self.mounted(relative);
        let path_c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("path with nul: {e}")))?;
        let full_name = format!("user.{name}");
        let name_c = CString::new(full_name.as_bytes())
            .map_err(|e| io::Error::other(format!("xattr name with nul: {e}")))?;

        // SAFETY: removexattr is a C FFI call; path_c and name_c are valid
        // null-terminated CStrings.
        let rc = unsafe { libc::removexattr(path_c.as_ptr(), name_c.as_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    // ── statfs helper ──────────────────────────────────────────────

    /// Return raw `libc::statfs` for the mount root.  Callers can
    /// inspect fields such as `f_bsize`, `f_blocks`, `f_bfree`,
    /// `f_namelen`, and `f_type`.
    pub fn statfs(&self) -> io::Result<libc::statfs> {
        let path_c = CString::new(self.mount_path.as_os_str().as_bytes())
            .map_err(|e| io::Error::other(format!("mount path with nul: {e}")))?;
        // SAFETY: libc::statfs is a C struct of integers; zero is a valid
        // bit pattern. The struct is filled by statfs below.
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: statfs is a C FFI call; path_c is a valid CString; buf
        // is a valid pointer to a statfs struct on the stack.
        let rc = unsafe { libc::statfs(path_c.as_ptr(), &mut buf) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    // ── lifetime ───────────────────────────────────────────────────

    /// Unmount the filesystem and kill the daemon, but keep the work
    /// directory alive.  Useful for persistence tests that remount the
    /// same backing store.
    pub fn unmount_only(&mut self, graceful: bool) -> io::Result<()> {
        if graceful {
            let result = Command::new("fusermount")
                .arg("-u")
                .arg(&self.mount_path)
                .output();
            match result {
                Ok(out) if out.status.success() => {}
                _ => {
                    kill_child(self.daemon_pid);
                }
            }
        } else {
            kill_child(self.daemon_pid);
        }

        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        Ok(())
    }

    /// SIGKILL the daemon, lazy-unmount, and restart with a fresh daemon
    /// on the same backing store. This simulates a crash where the daemon
    /// cannot run its Drop cleanup (no writeback flush, no PID file removal).
    ///
    /// After this call the harness is ready for continued IO through the
    /// same `mount_path`.
    pub fn crash_and_remount(&mut self) -> io::Result<()> {
        // Send SIGKILL to the daemon.
        // SAFETY: kill(2) is a C FFI call; daemon_pid is the PID of the
        // spawned daemon process; SIGKILL is a valid signal number.
        unsafe {
            libc::kill(self.daemon_pid as i32, libc::SIGKILL);
        }

        // Wait for the child process to terminate.
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if start.elapsed() < Duration::from_secs(5) => {
                    thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }

        // Lazy-unmount: the daemon is dead so we need fusermount -uz.
        let _ = Command::new("fusermount")
            .arg("-uz")
            .arg(&self.mount_path)
            .output();

        // Brief pause so the kernel releases the mount.
        thread::sleep(Duration::from_millis(200));

        // Spawn a fresh daemon on the same store + mount.
        let daemon_bin = find_daemon_binary()?;
        let child = Command::new(&daemon_bin)
            .arg("mount-vfs")
            .arg("--store")
            .arg(&self.store_path)
            .arg("--mount")
            .arg(&self.mount_path)
            .arg("--root-auth-key-hex")
            .arg("0000000000000000000000000000000000000000000000000000000000000001")
            .spawn()
            .map_err(|e| {
                io::Error::other(format!(
                    "spawn daemon (crash-remount) {}: {e}",
                    daemon_bin.display()
                ))
            })?;

        self.daemon_pid = child.id();
        self.child = child;
        wait_for_mount(&self.mount_path, Duration::from_secs(10))?;
        Ok(())
    }

    /// Send SIGTERM to the daemon, wait for clean exit, and restart with a
    /// fresh daemon on the same backing store. This exercises the graceful
    /// shutdown path: writeback flush, final commit_group commit, clean mount-state
    /// write, and FUSE unmount.
    ///
    /// After this call the harness is ready for continued IO through the
    /// same `mount_path`.
    pub fn graceful_shutdown_and_remount(&mut self) -> io::Result<()> {
        // Send SIGTERM to trigger graceful shutdown.
        // SAFETY: kill(2) is a C FFI call; daemon_pid is valid; SIGTERM
        // is a valid signal number.
        unsafe {
            libc::kill(self.daemon_pid as i32, libc::SIGTERM);
        }

        // Wait for the daemon to exit cleanly.
        let start = Instant::now();
        let exit_status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if start.elapsed() < Duration::from_secs(10) => {
                    thread::sleep(Duration::from_millis(100));
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return Err(io::Error::other(
                        "daemon did not exit within 10s after SIGTERM",
                    ));
                }
            }
        };

        if !exit_status.success() {
            eprintln!("graceful_shutdown_and_remount: daemon exited with {exit_status:?}");
        }

        // After graceful shutdown the daemon should have unmounted itself.
        // Use lazy-unmount as a fallback in case the kernel hasn't released it.
        let _ = Command::new("fusermount")
            .arg("-uz")
            .arg(&self.mount_path)
            .output();

        // Brief pause so the kernel releases the mount.
        thread::sleep(Duration::from_millis(200));

        // Spawn a fresh daemon on the same store + mount.
        let daemon_bin = find_daemon_binary()?;
        let child = Command::new(&daemon_bin)
            .arg("mount-vfs")
            .arg("--store")
            .arg(&self.store_path)
            .arg("--mount")
            .arg(&self.mount_path)
            .arg("--root-auth-key-hex")
            .arg("0000000000000000000000000000000000000000000000000000000000000001")
            .spawn()
            .map_err(|e| {
                io::Error::other(format!(
                    "spawn daemon (graceful-remount) {}: {e}",
                    daemon_bin.display()
                ))
            })?;

        self.daemon_pid = child.id();
        self.child = child;
        wait_for_mount(&self.mount_path, Duration::from_secs(10))?;
        Ok(())
    }

    /// Unmount and then remount the same backing store with a fresh daemon.
    ///
    /// After this call the harness is ready for continued IO through the
    /// same `mount_path`.  Returns an error if the daemon binary cannot be
    /// found or the remount does not become ready within the timeout.
    pub fn remount(&mut self) -> io::Result<()> {
        self.unmount_only(true)?;

        let daemon_bin = find_daemon_binary()?;
        let child = Command::new(&daemon_bin)
            .arg("mount-vfs")
            .arg("--store")
            .arg(&self.store_path)
            .arg("--mount")
            .arg(&self.mount_path)
            .arg("--root-auth-key-hex")
            .arg("0000000000000000000000000000000000000000000000000000000000000001")
            .spawn()
            .map_err(|e| {
                io::Error::other(format!(
                    "spawn daemon (remount) {}: {e}",
                    daemon_bin.display()
                ))
            })?;

        self.daemon_pid = child.id();
        self.child = child;
        wait_for_mount(&self.mount_path, Duration::from_secs(10))?;
        Ok(())
    }
}

impl Drop for MountHarness {
    fn drop(&mut self) {
        let _ = self.unmount_only(true);
        // TempDir cleanup runs when `work_dir` is dropped.
    }
}

// ── internal helpers ────────────────────────────────────────────────

/// Poll `mount_path` with `stat` every 100 ms until success or `timeout`.
fn wait_for_mount(mount_path: &Path, timeout: Duration) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match fs::metadata(mount_path) {
            Ok(_) => return Ok(()),
            Err(_) if start.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send SIGTERM to a process by pid.
pub fn kill_child(pid: u32) {
    // SAFETY: kill(2) is a C FFI call with no memory safety preconditions
    // beyond a valid pid and signal number, both satisfied here.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

/// Send SIGKILL to a process by pid.
pub fn sigkill_child(pid: u32) {
    // SAFETY: kill(2) is a C FFI call with no memory safety preconditions
    // beyond a valid pid and signal number, both satisfied here.
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

/// Locate the daemon binary, checking (in order):
/// 1. `TIDEFS_DAEMON_BIN` env var
/// 2. `CARGO_TARGET_DIR`/debug/ and `CARGO_TARGET_DIR`/release/
/// 3. `<workspace>/target/debug/` and `<workspace>/target/release/`
pub fn find_daemon_binary() -> io::Result<PathBuf> {
    // 1. Explicit environment variable.
    if let Ok(path) = std::env::var("TIDEFS_DAEMON_BIN") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            return Ok(p);
        }
    }

    // 2. CARGO_TARGET_DIR (set when target dir is non-default).
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let dbg = Path::new(&td).join("debug/tidefs-posix-filesystem-adapter-daemon");
        if dbg.is_file() {
            return Ok(dbg);
        }
        let rel = Path::new(&td).join("release/tidefs-posix-filesystem-adapter-daemon");
        if rel.is_file() {
            return Ok(rel);
        }
    }

    // 3. Workspace-relative target dir.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("cannot determine workspace root"))?;

    let candidates = [
        workspace_root.join("target/debug/tidefs-posix-filesystem-adapter-daemon"),
        workspace_root.join("target/release/tidefs-posix-filesystem-adapter-daemon"),
    ];

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }

    Err(io::Error::other(format!(
        "daemon binary not found; set TIDEFS_DAEMON_BIN or build the daemon first. \
         Looked in: {}",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn runtime_refusal_message_marks_harness_signal() {
        let msg = MountHarness::runtime_refusal_message(
            "mount_harness helper test",
            io::Error::other("daemon missing"),
        );

        assert!(msg.contains("RUNTIME REFUSAL mount_harness helper test"));
        assert!(msg.contains("mounted runtime substrate unavailable"));
        assert!(msg.contains("harness/refusal signal only"));
        assert!(msg.contains("not mounted product proof"));
        assert!(msg.contains("daemon missing"));
    }

    /// Smoke test: verify the harness can mount and unmount cleanly.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_mount_unmount_cleanup() {
        let harness = MountHarness::new_or_fail("test_mount_unmount_cleanup");
        let md = harness.stat(".").expect("stat mount root");
        assert!(md.is_dir(), "mount root must be a directory");
        eprintln!(
            "harness: mount={} store={} pid={}",
            harness.mount_path().display(),
            harness.store_path().display(),
            harness.daemon_pid(),
        );
        // Drop triggers unmount + cleanup.
    }

    /// Basic IO round-trip: create, write, read, verify byte-identical.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_create_read_write_roundtrip() {
        let harness = MountHarness::new_or_fail("test_create_read_write_roundtrip");
        let data = b"Hello, TideFS! This is a round-trip test.\n";
        harness.create_file("test.txt", data).expect("create_file");
        let read_back = harness.read_file("test.txt").expect("read_file");
        assert_eq!(read_back, data, "round-trip data mismatch");
    }

    /// Metadata round-trip: chmod then stat, verify mode bits changed.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_metadata_chmod_roundtrip() {
        let harness = MountHarness::new_or_fail("test_metadata_chmod_roundtrip");
        harness
            .create_file("meta.txt", b"metadata test")
            .expect("create_file");

        let md_before = harness.stat("meta.txt").expect("stat before");
        let mode_before = md_before.permissions().mode();

        let new_mode = 0o600;
        harness.chmod("meta.txt", new_mode).expect("chmod");

        let md_after = harness.stat("meta.txt").expect("stat after");
        let mode_after = md_after.permissions().mode();

        assert_ne!(
            mode_before & 0o777,
            mode_after & 0o777,
            "mode permission bits should change after chmod"
        );
        assert_eq!(
            mode_after & 0o777,
            new_mode & 0o777,
            "mode permission bits should match requested mode"
        );
    }

    /// Directory round-trip: mkdir, create entries, readdir, verify.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_directory_roundtrip() {
        let harness = MountHarness::new_or_fail("test_directory_roundtrip");
        harness.mkdir("subdir").expect("mkdir subdir");
        harness
            .create_file("subdir/a.txt", b"alpha")
            .expect("create a.txt");
        harness
            .create_file("subdir/b.txt", b"beta")
            .expect("create b.txt");
        harness
            .create_file("subdir/c.txt", b"gamma")
            .expect("create c.txt");

        let entries = harness.readdir("subdir").expect("readdir subdir");
        assert_eq!(
            entries,
            vec!["a.txt", "b.txt", "c.txt"],
            "readdir should list all created entries sorted"
        );
    }

    /// Persistence: unmount, verify backing store exists, remount,
    /// verify all files and data survive.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_persistence_roundtrip() {
        let data = b"persistent data that survives remount\n";

        let mut harness = MountHarness::new_or_fail("test_persistence_roundtrip");
        harness
            .create_file("persist.txt", data)
            .expect("create_file session 1");
        harness
            .create_file("sub/persist_deep.txt", data)
            .expect("create deep file session 1");

        let store_path = harness.store_path().to_path_buf();
        let mount_path = harness.mount_path().to_path_buf();

        harness.unmount_only(true).expect("unmount session 1");

        assert!(
            store_path.exists(),
            "backing store must exist after unmount"
        );

        // Spawn a new daemon on the same store.
        let daemon_bin = find_daemon_binary().expect("find daemon binary");
        let root_auth_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";

        let child2 = Command::new(&daemon_bin)
            .arg("mount-vfs")
            .arg("--store")
            .arg(&store_path)
            .arg("--mount")
            .arg(&mount_path)
            .arg("--root-auth-key-hex")
            .arg(root_auth_key_hex)
            .spawn()
            .expect("spawn daemon session 2");

        let daemon_pid2 = child2.id();
        wait_for_mount(&mount_path, Duration::from_secs(10)).expect("mount point ready session 2");

        let read_back =
            fs::read(mount_path.join("persist.txt")).expect("read persist.txt session 2");
        assert_eq!(read_back, data, "persistence data mismatch for persist.txt");

        let read_back_deep = fs::read(mount_path.join("sub/persist_deep.txt"))
            .expect("read sub/persist_deep.txt session 2");
        assert_eq!(
            read_back_deep, data,
            "persistence data mismatch for sub/persist_deep.txt"
        );

        kill_child(daemon_pid2);
        let _ = Command::new("fusermount")
            .arg("-u")
            .arg(&mount_path)
            .output();
        let _ = child2.wait_with_output();
        drop(harness);
    }

    /// Concurrent FD: open two fds on the same file, write from one,
    /// read from the other, verify visibility after flush.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_concurrent_fd_visibility() {
        use std::fs::{File, OpenOptions};
        use std::io::{Read, Seek, SeekFrom, Write};

        let harness = MountHarness::new_or_fail("test_concurrent_fd_visibility");
        let path = harness.mounted("concurrent.txt");

        harness
            .create_file("concurrent.txt", b"initial content\n")
            .expect("seed file");

        let mut fd1 = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open fd1");
        let mut fd2 = File::open(&path).expect("open fd2");

        fd1.write_all(b"updated from fd1\n").expect("fd1 write");
        fd1.flush().expect("fd1 flush");

        fd2.seek(SeekFrom::Start(0)).expect("fd2 seek");
        let mut buf = String::new();
        fd2.read_to_string(&mut buf).expect("fd2 read");

        assert_eq!(
            buf, "updated from fd1\n",
            "fd2 should see the write from fd1 after flush"
        );
    }

    // ── remount persistence ─────────────────────────────────────────
    //
    // These tests exercise the primary advancement gate for the
    // `fuse-mount-rw-persistence` strategy slice:
    //
    //   mount(RW) -> write -> sync -> unmount -> remount -> read -> verify
    //
    // Prerequisites (tracked as separate Forgejo issues):
    //
    //   #3651  mount-vfs subcommand uses MountOption::RW by default
    //     The daemon must spawn with a read-write FUSE mount.
    //     The current mount-vfs subcommand already uses RW; if a
    //     future build regresses to RO, writes will fail with a
    //     permission-denied or read-only-fs error.
    //
    //   #3652  LocalFileSystem::Drop calls do_commit/sync_all
    //     Without explicit commit on Drop, dirty writeback data
    //     may not reach the object store before the daemon exits.
    //     Remount reads will return zeros, stale content, or a
    //     file-not-found error.
    //
    //     On remount the filesystem must reconstruct namespace,
    //     inode metadata, and extent maps from the object store's
    //     committed roots.  Without this the remount may not find
    //     the previously written file at all.
    //
    // Expected failure modes (before all prerequisites land):
    //
    //   - mount fails: RO mount option (#3651)
    //   - write succeeds, remount reads zeros or stale data (#3652)
    //   - test harness fails to find daemon binary (build needed)
    //
    // Once all three prerequisites land, test_remount_persistence
    // must pass 5/5 consecutive runs (matching the strategy
    // advancement_criteria reliability requirement).

    /// Build a reproducible test buffer: `count` bytes of seeded
    /// pseudo-random data followed by a 16-byte checksum footer.
    ///
    /// The checksum is computed with std DefaultHasher over (seed,
    /// count, data) and repeated to fill 16 bytes.  This lets the
    /// test distinguish "all zeros" from "corrupted after write"
    /// with high probability.
    fn make_test_buffer(seed: u64, count: usize) -> Vec<u8> {
        use std::hash::{Hash, Hasher};
        let mut buf = Vec::with_capacity(count + 16);
        let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        for _ in 0..count {
            buf.push((state >> 32) as u8);
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
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

    /// Verify that `data` matches the `make_test_buffer(seed, _)`
    /// contract: length must be original_count + 16, content must
    /// be identical byte-for-byte.
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

    /// Primary advancement-gate test:
    ///
    ///   mount(RW) -> write -> sync -> unmount -> remount -> read -> verify
    ///
    /// Writes a single test file with known reproducible content,
    /// calls fsync on the file descriptor, unmounts the daemon,
    /// remounts the same backing store via MountHarness::remount,
    /// reads the file back, and asserts byte-for-byte equality.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn test_remount_persistence() {
        let seed: u64 = 0xcafef00d_deadbeef;
        let data_len: usize = 4096;
        let test_data = make_test_buffer(seed, data_len);

        let mut harness = MountHarness::new_or_fail("test_remount_persistence");
        harness
            .create_file("remount_test.bin", &test_data)
            .expect("create_file through FUSE mount");

        harness
            .fsync_file("remount_test.bin")
            .expect("fsync remount_test.bin");

        harness.unmount_only(true).expect("unmount session 1");

        // Remount via the harness helper, which keeps the TempDir
        // alive so the backing store survives.
        harness.remount().expect("remount session 2");

        let read_back = harness
            .read_file("remount_test.bin")
            .expect("read remount_test.bin session 2");

        if let Err(e) = verify_test_buffer(seed, &read_back) {
            panic!(
                "remount persistence verification failed: {e}
                 Expected test buffer with seed=0x{seed:x},                  data_len={data_len}.
                 The failure may indicate one of:
                 - Drop flush missing -> stale/zero data
                 - writeback flush bug"
            );
        }
    }

    // ── negative / error-path tests ──────────────────────────────────

    /// Verify that MountHarnessBuilder with a non-existent daemon binary
    /// returns an error from build() rather than panicking.
    #[test]
    fn builder_nonexistent_daemon_bin() {
        let result = MountHarness::builder()
            .daemon_bin("/nonexistent/path/to/tidefs-daemon")
            .build();
        match result {
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("nonexistent")
                        || msg.contains("No such file")
                        || msg.contains("cannot find")
                        || msg.contains("not found"),
                    "error should mention the path problem: {e}"
                );
            }
            Ok(_) => panic!(
                "builder with nonexistent daemon binary should fail,                  but mount succeeded (daemon found on PATH?)"
            ),
        }
    }

    /// Verify that the harness returns an error when the daemon binary
    /// exists but cannot execute (e.g., a directory passed as binary).
    #[test]
    fn builder_non_executable_daemon_bin() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        // A directory is not an executable binary.
        let result = MountHarness::builder().daemon_bin(dir.path()).build();
        match result {
            Err(_) => { /* expected: directory is not executable */ }
            Ok(_) => panic!("builder with directory as daemon bin should fail"),
        }
    }

    /// Verify that two MountHarness instances can coexist on different
    /// store/mount paths without interfering with each other.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn two_independent_harnesses() {
        let h1 = MountHarness::new_or_fail("two_independent_harnesses h1");
        let h2 = MountHarness::new_or_fail("two_independent_harnesses h2");

        // Verify mounts are at different paths.
        assert_ne!(
            h1.mount_path(),
            h2.mount_path(),
            "independent harnesses must have different mount points"
        );
        assert_ne!(
            h1.store_path(),
            h2.store_path(),
            "independent harnesses must have different store paths"
        );

        // Write to each and verify no cross-talk.
        h1.create_file("h1.txt", b"data-from-h1")
            .expect("h1 create_file");
        h2.create_file("h2.txt", b"data-from-h2")
            .expect("h2 create_file");

        assert_eq!(
            h1.read_file("h1.txt").expect("h1 read"),
            b"data-from-h1",
            "h1 data integrity"
        );
        assert_eq!(
            h2.read_file("h2.txt").expect("h2 read"),
            b"data-from-h2",
            "h2 data integrity"
        );

        // Verify no cross-talk: h1 cannot see h2's files.
        assert!(!h1.exists("h2.txt"), "h1 must not see h2 files");
        assert!(!h2.exists("h1.txt"), "h2 must not see h1 files");
    }

    /// Verify that FuseMountFixture type alias works as MountHarness.
    #[test]
    #[ignore = "requires mounted TideFS runtime substrate; run explicitly with daemon/FUSE available"]
    fn fuse_mount_fixture_alias() {
        let harness: FuseMountFixture = MountHarness::new_or_fail("fuse_mount_fixture_alias");
        assert!(harness.mount_path().exists(), "mount path must exist");
    }
}
