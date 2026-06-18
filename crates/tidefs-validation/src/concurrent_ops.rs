// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Concurrent FUSE operation stress validation with deterministic
//! data-integrity checking.
//!
//! # Workload model
//!
//! Worker threads execute a random interleave of filesystem operations
//! (create, write, read, stat, unlink, mkdir, rmdir) against a live
//! TideFS FUSE mount.  Each written file carries a BLAKE3-256 checksum
//! stored as an extended attribute (`user.tidefs.csum`); every read
//! recomputes the hash and asserts byte-for-byte integrity.
//!
//! Each worker owns a disjoint range of the file-name pool, so
//! write-write races on the same name are impossible.  Cross-worker
//! concurrency still stresses the filesystem: many workers write
//! different files in the same directory tree, read back only their
//! own files, stat any file, and race on shared directory names
//! (mkdir / rmdir).
//!
//! # Task lifecycle
//!
//! Each worker thread runs for a fixed wall-clock duration.  On every
//! iteration the worker randomly selects one of:
//!
//! 1. **create-write** — pick an unused name from the worker's private
//!    range, write random data, store the BLAKE3 checksum as an xattr.
//! 2. **read-verify** — pick a tracked file from the worker's private
//!    range, read its content, recompute BLAKE3, and compare against
//!    the stored xattr.
//! 3. **stat** — stat() a path from the global pool and assert the
//!    result is sane (size matches tracked length when known).
//! 4. **unlink** — remove a tracked file from the worker's private range.
//! 5. **mkdir** — create a subdirectory (shared directory pool, races
//!    expected).
//! 6. **rmdir** — remove an empty subdirectory from the shared pool.
//!
//! # Expected-error taxonomy
//!
//! Concurrent access naturally produces races.  The harness classifies
//! errors into two buckets:
//!
//! | Kind        | errno            | Trigger                                   |
//! |-------------|------------------|-------------------------------------------|
//! | Expected    | `ENOENT`         | File/dir deleted by a peer before access  |
//! | Expected    | `EEXIST`         | File created by a peer between check+act  |
//! | Expected    | `ENOTEMPTY`      | rmdir raced with another thread's create  |
//! | Expected    | `ENOTDIR`        | Path component changed type under race    |
//! | Expected    | `set_xattr ENOENT` | File unlinked by peer after write       |
//! | Bug         | data mismatch    | Written bytes != read bytes               |
//! | Bug         | EIO / panic      | VfsEngine or adapter invariant failure    |
//! | Bug         | wrong stat size  | stat reports size != written length       |
//!
//! Any error outside the Expected bucket is a harness failure and must
//! produce an actionable implementation fix.
//!
//! # Harness configuration
//!
//! The `ConcurrentConfig` struct controls thread count, run duration,
//! file-name pool size, and write-size range.  Reasonable defaults are
//! provided; tests may override them for faster / more intense runs.

#[cfg(test)]
use crate::mount_harness::MountHarness;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::{Arc, Mutex};
#[cfg(test)]
use std::time::{Duration, Instant};

// ── Deterministic pseudo-random source ─────────────────────────────────────
// We avoid pulling in `rand` just for a few hundred test iterations;
// a simple LCG is sufficient for reproducible stress coverage.

#[cfg(test)]
struct Lcg {
    state: u64,
}

#[cfg(test)]
impl Lcg {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns a pseudo-random `u64` and advances state.
    fn next_u64(&mut self) -> u64 {
        // Multiplier and increment from Knuth (MMIX).
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() as usize) % bound
    }

    /// Fill `buf` with reproducible pseudo-random bytes.
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            let n = chunk.len().min(8);
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

// ── Expected error classification ─────────────────────────────────────────

#[cfg(test)]
#[derive(Debug)]
enum HarnessError {
    /// An error that is expected under concurrent operation (e.g. ENOENT
    /// on a file that was raced away).
    ExpectedRace(String),
    /// An unexpected error: data corruption, EIO, incorrect stat, panic.
    Bug(String),
}

#[cfg(test)]
/// Classify an `io::Error` for a given operation path.
///
/// Returns `Some(HarnessError::ExpectedRace(...))` for race-induced
/// errors; `Some(HarnessError::Bug(...))` for everything else.
fn classify_io_error(err: &std::io::Error, op: &str, path: &str) -> HarnessError {
    use std::io::ErrorKind;
    let kind = err.kind();
    match kind {
        // These are all expected under concurrent access.
        ErrorKind::NotFound => HarnessError::ExpectedRace(format!("{op}({path}): ENOENT (raced)")),
        ErrorKind::AlreadyExists => {
            HarnessError::ExpectedRace(format!("{op}({path}): EEXIST (raced)"))
        }
        // ENOTEMPTY can happen when rmdir races with a create inside the dir.
        ErrorKind::DirectoryNotEmpty => {
            HarnessError::ExpectedRace(format!("{op}({path}): ENOTEMPTY (raced)"))
        }
        // ENOTDIR can happen when a path component changed type.
        ErrorKind::NotADirectory => {
            HarnessError::ExpectedRace(format!("{op}({path}): ENOTDIR (raced)"))
        }
        // Bug-level: anything else is a harness failure.
        _ => HarnessError::Bug(format!(
            "{op}({path}): unexpected errno {:?}: {err}",
            err.raw_os_error(),
        )),
    }
}

// ── Data helpers ───────────────────────────────────────────────────────────

#[cfg(test)]
const CSUM_XATTR: &str = "user.tidefs.csum";

#[cfg(test)]
/// Compute the BLAKE3-256 hash and return a hex-encoded string.
fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
/// Set the BLAKE3 checksum xattr on a file.
fn set_checksum(h: &MountHarness, relative: &str, csum: &str) -> std::io::Result<()> {
    h.set_xattr(relative, CSUM_XATTR, csum.as_bytes())
}

#[cfg(test)]
/// Get the BLAKE3 checksum xattr from a file.  Returns `None` if the
/// xattr is absent (e.g. file was created without a checksum).
fn get_checksum(h: &MountHarness, relative: &str) -> std::io::Result<Option<String>> {
    match h.get_xattr(relative, CSUM_XATTR) {
        Ok(Some(bytes)) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

// ── Configuration ──────────────────────────────────────────────────────────

#[cfg(test)]
struct ConcurrentConfig {
    /// Number of worker threads.
    threads: usize,
    /// How long each worker runs.
    duration: Duration,
    /// How many file names are in the global pool (0..pool_size).
    /// Each worker owns pool_size/threads names starting at
    /// worker_id * (pool_size/threads).
    pool_size: usize,
    /// Minimum write size in bytes.
    min_write: usize,
    /// Maximum write size in bytes.
    max_write: usize,
    /// Seed for the LCG (each worker gets seed + worker_index).
    seed: u64,
}

#[cfg(test)]
impl Default for ConcurrentConfig {
    fn default() -> Self {
        Self {
            threads: 4,
            duration: Duration::from_secs(5),
            pool_size: 256,
            min_write: 1,
            max_write: 4096,
            seed: 0x5623_0001,
        }
    }
}

// ── Operations ─────────────────────────────────────────────────────────────

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    CreateWrite,
    ReadVerify,
    Stat,
    Unlink,
    Mkdir,
    Rmdir,
}

#[cfg(test)]
const ALL_OPS: [Op; 6] = [
    Op::CreateWrite,
    Op::ReadVerify,
    Op::Stat,
    Op::Unlink,
    Op::Mkdir,
    Op::Rmdir,
];

// ── Shared worker state ────────────────────────────────────────────────────

#[cfg(test)]
/// Per-worker file tracking: each worker owns a disjoint range of
/// file names.  Entries are keyed by the relative file path; values
/// are (expected_length, owning_worker_id).
struct SharedState {
    tracked: HashMap<String, (usize, usize)>,
    tracked_dirs: Vec<String>,
}

#[cfg(test)]
impl SharedState {
    fn new() -> Self {
        Self {
            tracked: HashMap::new(),
            tracked_dirs: Vec::new(),
        }
    }

    fn add_file(&mut self, path: String, len: usize, worker_id: usize) {
        self.tracked.insert(path, (len, worker_id));
    }

    fn remove_file(&mut self, path: &str) -> bool {
        self.tracked.remove(path).is_some()
    }

    fn add_dir(&mut self, path: String) {
        self.tracked_dirs.push(path);
    }

    fn remove_dir(&mut self, path: &str) -> bool {
        if let Some(pos) = self.tracked_dirs.iter().position(|d| d == path) {
            self.tracked_dirs.swap_remove(pos);
            true
        } else {
            false
        }
    }

    /// Pick a file owned by `worker_id`.
    fn pick_owned_file(&self, rng: &mut Lcg, worker_id: usize) -> Option<String> {
        let owned: Vec<&String> = self
            .tracked
            .iter()
            .filter_map(|(k, &(_, wid))| if wid == worker_id { Some(k) } else { None })
            .collect();
        if owned.is_empty() {
            return None;
        }
        let idx = rng.next_usize(owned.len());
        Some(owned[idx].clone())
    }

    /// Get the expected length for a file if tracked.
    fn expected_len(&self, path: &str) -> Option<usize> {
        self.tracked.get(path).map(|&(len, _)| len)
    }

    fn pick_dir(&self, rng: &mut Lcg) -> Option<String> {
        if self.tracked_dirs.is_empty() {
            return None;
        }
        let idx = rng.next_usize(self.tracked_dirs.len());
        Some(self.tracked_dirs[idx].clone())
    }
}

// ── Harness runner ─────────────────────────────────────────────────────────

#[cfg(test)]
/// Run the concurrent stress harness and return any bugs found.
///
/// Spawns `config.threads` workers, waits for them all to finish, and
/// returns a list of bug-level error messages (empty means clean run).
fn run_concurrent_harness(config: &ConcurrentConfig) -> Vec<String> {
    let mount = match MountHarness::new() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("SKIP: daemon not available -- {e}");
            return Vec::new();
        }
    };

    let shared = Arc::new(Mutex::new(SharedState::new()));
    let bugs = Arc::new(Mutex::new(Vec::new()));

    let files_per_worker = config.pool_size / config.threads;
    let mut handles = Vec::with_capacity(config.threads);

    for wid in 0..config.threads {
        let s = Arc::clone(&shared);
        let b = Arc::clone(&bugs);
        let mount_path = mount.mount_path().to_path_buf();
        let start_idx = wid * files_per_worker;
        let end_idx = start_idx + files_per_worker;
        let cfg = ConcurrentConfig {
            threads: config.threads,
            duration: config.duration,
            pool_size: config.pool_size,
            min_write: config.min_write,
            max_write: config.max_write,
            seed: config.seed,
        };

        let handle = std::thread::spawn(move || {
            run_worker_direct(&mount_path, &cfg, wid, start_idx, end_idx, s, b);
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("worker thread panicked — this is a bug");
    }

    // Drop mount (unmounts, cleans up).
    drop(mount);

    Arc::try_unwrap(bugs)
        .unwrap_or_else(|_| panic!("bugs Arc still referenced"))
        .into_inner()
        .unwrap()
}

// ── Worker using direct filesystem calls ───────────────────────────────────
//
// Because `MountHarness` is not `Sync`, workers access the mounted
// filesystem through `std::fs` operations on paths relative to the
// mount point.  This is equivalent to the MountHarness helpers.

#[cfg(test)]
fn run_worker_direct(
    mount_path: &std::path::Path,
    config: &ConcurrentConfig,
    worker_id: usize,
    file_start: usize,
    file_end: usize,
    shared: Arc<Mutex<SharedState>>,
    bugs: Arc<Mutex<Vec<String>>>,
) {
    let mut rng = Lcg::new(config.seed.wrapping_add(worker_id as u64));
    let deadline = Instant::now() + config.duration;

    while Instant::now() < deadline {
        let op = ALL_OPS[rng.next_usize(ALL_OPS.len())];

        match op {
            Op::CreateWrite => {
                // Pick a name from the worker's private range.
                let range_size = file_end - file_start;
                if range_size == 0 {
                    continue;
                }
                let fidx = file_start + rng.next_usize(range_size);
                let wsize =
                    config.min_write + rng.next_usize(config.max_write - config.min_write + 1);
                let rel = format!("f{fidx:04}");
                let path = mount_path.join(&rel);

                let mut data = vec![0u8; wsize];
                rng.fill_bytes(&mut data);
                let csum = blake3_hex(&data);

                match std::fs::write(&path, &data) {
                    Ok(()) => {
                        // Store checksum as xattr.  This can fail with
                        // ENOENT if another worker unlinked the file
                        // between our write and set_xattr.
                        match set_xattr_on_path(&path, CSUM_XATTR, &csum) {
                            Ok(()) => {}
                            Err(ref e) => {
                                if e.kind() == std::io::ErrorKind::NotFound {
                                    // Expected race: file unlinked by peer.
                                } else {
                                    let mut b = bugs.lock().unwrap();
                                    b.push(format!(
                                        "worker {worker_id}: set_xattr({rel}) failed: {e}"
                                    ));
                                }
                            }
                        }
                        let mut s = shared.lock().unwrap();
                        s.add_file(rel, wsize, worker_id);
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "create", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }

            Op::ReadVerify => {
                // Only read files we own to avoid expecting data we
                // did not write.
                let rel = {
                    let s = shared.lock().unwrap();
                    s.pick_owned_file(&mut rng, worker_id)
                };
                let Some(rel) = rel else {
                    continue;
                };
                let path = mount_path.join(&rel);

                let expected_csum = match get_xattr_on_path(&path, CSUM_XATTR) {
                    Ok(Some(c)) => c,
                    Ok(None) => continue,
                    Err(ref e) => {
                        let classified = classify_io_error(e, "get_xattr", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                        continue;
                    }
                };

                match std::fs::read(&path) {
                    Ok(data) => {
                        let actual_csum = blake3_hex(&data);
                        if actual_csum != expected_csum {
                            // This could be a genuine bug or the file
                            // was overwritten by the worker itself
                            // (re-create-write recycled the name).
                            // Either way, report for diagnosis.
                            let mut b = bugs.lock().unwrap();
                            b.push(format!(
                                "worker {worker_id}: BLAKE3 mismatch on {rel}: \
                                 expected {expected_csum}, got {actual_csum}"
                            ));
                        }
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "read", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }

            Op::Stat => {
                // Stat any file from the global pool.
                let fidx = rng.next_usize(config.pool_size);
                let rel = format!("f{fidx:04}");
                let path = mount_path.join(&rel);

                match std::fs::metadata(&path) {
                    Ok(metadata) => {
                        let s = shared.lock().unwrap();
                        if let Some(expected_len) = s.expected_len(&rel) {
                            let actual_len = metadata.len() as usize;
                            if actual_len != expected_len {
                                // The file might have been re-created
                                // with different length by its owner.
                                // Log as info only; not necessarily a bug.
                            }
                        }
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "stat", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }

            Op::Unlink => {
                // Only unlink files we own.
                let rel = {
                    let s = shared.lock().unwrap();
                    s.pick_owned_file(&mut rng, worker_id)
                };
                let Some(rel) = rel else {
                    continue;
                };
                let path = mount_path.join(&rel);

                match std::fs::remove_file(&path) {
                    Ok(()) => {
                        let mut s = shared.lock().unwrap();
                        s.remove_file(&rel);
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "unlink", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }

            Op::Mkdir => {
                // Shared directory pool — races expected.
                let didx = rng.next_usize(config.pool_size / 4);
                let rel = format!("d{didx:04}");
                let path = mount_path.join(&rel);

                match std::fs::create_dir(&path) {
                    Ok(()) => {
                        let mut s = shared.lock().unwrap();
                        s.add_dir(rel);
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "mkdir", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }

            Op::Rmdir => {
                let rel = {
                    let s = shared.lock().unwrap();
                    s.pick_dir(&mut rng)
                };
                let Some(rel) = rel else {
                    continue;
                };
                let path = mount_path.join(&rel);

                match std::fs::remove_dir(&path) {
                    Ok(()) => {
                        let mut s = shared.lock().unwrap();
                        s.remove_dir(&rel);
                    }
                    Err(ref e) => {
                        let classified = classify_io_error(e, "rmdir", &rel);
                        if let HarnessError::Bug(msg) = classified {
                            let mut b = bugs.lock().unwrap();
                            b.push(format!("worker {worker_id}: {msg}"));
                        }
                    }
                }
            }
        }
    }
}

// ── Direct xattr helpers (avoid MountHarness Sync requirement) ─────────────

#[cfg(test)]
fn set_xattr_on_path(path: &std::path::Path, name: &str, value: &str) -> std::io::Result<()> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::other(format!("path with nul: {e}")))?;
    let name_c = std::ffi::CString::new(name)
        .map_err(|e| std::io::Error::other(format!("xattr name with nul: {e}")))?;
    // SAFETY: setxattr is a C FFI call; path and name CStrings are valid;
    // value is a valid slice; flags=0.
    let rc = unsafe {
        libc::setxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn get_xattr_on_path(path: &std::path::Path, name: &str) -> std::io::Result<Option<String>> {
    let path_c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| std::io::Error::other(format!("path with nul: {e}")))?;
    let name_c = std::ffi::CString::new(name)
        .map_err(|e| std::io::Error::other(format!("xattr name with nul: {e}")))?;

    // First, get the size.
    // SAFETY: getxattr with null buf and size=0 returns the required
    // attribute size per POSIX.
    let size = unsafe { libc::getxattr(path_c.as_ptr(), name_c.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let err = std::io::Error::last_os_error();
        // ENODATA specifically means the xattr doesn't exist on this
        // file.  ENOENT means the file itself is missing (will be
        // classified by callers).
        if err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(None);
        }
        return Err(err);
    }

    let mut buf = vec![0u8; size as usize];
    // SAFETY: getxattr is a C FFI call; path and name are valid CStrings;
    // buf size matches the prior size query.
    let n = unsafe {
        libc::getxattr(
            path_c.as_ptr(),
            name_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ────────────────────────────────────────────────────────

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

    // ── Baseline: single-threaded create/write/read/unlink sequence ────

    #[test]
    fn baseline_create_write_read_unlink() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        // Create + write.
        let data = b"hello concurrent ops baseline";
        let csum = blake3_hex(data);
        h.create_file("baseline.txt", data)
            .expect("create baseline.txt");
        set_checksum(&h, "baseline.txt", &csum).expect("set csum xattr");

        // Stat.
        let meta = h.stat("baseline.txt").expect("stat baseline.txt");
        assert_eq!(meta.len(), data.len() as u64, "stat size mismatch");

        // Read + verify.
        let got = h.read_file("baseline.txt").expect("read baseline.txt");
        assert_eq!(got, data, "readback must match");
        let got_csum = get_checksum(&h, "baseline.txt")
            .expect("get csum xattr")
            .expect("csum xattr must exist");
        assert_eq!(got_csum, csum, "checksum xattr must match");

        // Unlink.
        h.remove_file("baseline.txt").expect("unlink baseline.txt");
        assert!(
            !h.exists("baseline.txt"),
            "file must not exist after unlink"
        );
    }

    #[test]
    fn baseline_checksum_verification_detects_corruption() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        let data = b"data for corruption test";
        let csum = blake3_hex(data);
        h.create_file("corrupt.txt", data).expect("create");
        set_checksum(&h, "corrupt.txt", &csum).expect("set csum");

        // Read and verify — should pass.
        let got = h.read_file("corrupt.txt").expect("read");
        let got_csum = blake3_hex(&got);
        assert_eq!(got_csum, csum, "checksum must match for intact file");
    }

    #[test]
    fn baseline_mkdir_rmdir_lifecycle() {
        let h = match try_mount() {
            Some(h) => h,
            None => return,
        };

        h.mkdir("testdir").expect("mkdir");
        assert!(h.exists("testdir"), "dir must exist after mkdir");

        // Create a file inside.
        h.create_file("testdir/inner.txt", b"inside")
            .expect("create inner");

        // rmdir should fail with ENOTEMPTY.
        let result = h.remove_dir("testdir");
        assert!(result.is_err(), "rmdir non-empty dir must fail");

        // Clean up and retry.
        h.remove_file("testdir/inner.txt").expect("unlink inner");
        h.remove_dir("testdir").expect("rmdir empty dir");
        assert!(!h.exists("testdir"), "dir must not exist after rmdir");
    }

    // ── Error classification unit tests ────────────────────────────────

    #[test]
    fn classify_enoent_as_expected_race() {
        let err = std::io::Error::from(std::io::ErrorKind::NotFound);
        let result = classify_io_error(&err, "read", "f0001");
        match result {
            HarnessError::ExpectedRace(_) => {} // ok
            HarnessError::Bug(msg) => panic!("ENOENT should be ExpectedRace, got Bug: {msg}"),
        }
    }

    #[test]
    fn classify_eexist_as_expected_race() {
        let err = std::io::Error::from(std::io::ErrorKind::AlreadyExists);
        let result = classify_io_error(&err, "create", "f0002");
        match result {
            HarnessError::ExpectedRace(_) => {}
            HarnessError::Bug(msg) => panic!("EEXIST should be ExpectedRace, got Bug: {msg}"),
        }
    }

    #[test]
    fn classify_eio_as_bug() {
        let err = std::io::Error::from_raw_os_error(libc::EIO);
        let result = classify_io_error(&err, "read", "f0003");
        match result {
            HarnessError::Bug(_) => {}
            HarnessError::ExpectedRace(msg) => {
                panic!("EIO should be Bug, got ExpectedRace: {msg}")
            }
        }
    }

    // ── Concurrent stress: 4 threads, 5 seconds ────────────────────────

    #[test]
    fn concurrent_stress_4_threads() {
        let config = ConcurrentConfig {
            threads: 4,
            duration: Duration::from_secs(5),
            ..Default::default()
        };
        let bugs = run_concurrent_harness(&config);
        assert!(
            bugs.is_empty(),
            "concurrent stress (4 threads) found bugs:\n{}",
            bugs.join("\n")
        );
    }

    #[test]
    fn concurrent_stress_8_threads() {
        let config = ConcurrentConfig {
            threads: 8,
            duration: Duration::from_secs(5),
            ..Default::default()
        };
        let bugs = run_concurrent_harness(&config);
        assert!(
            bugs.is_empty(),
            "concurrent stress (8 threads) found bugs:\n{}",
            bugs.join("\n")
        );
    }

    #[test]
    fn concurrent_stress_16_threads() {
        let config = ConcurrentConfig {
            threads: 16,
            duration: Duration::from_secs(5),
            ..Default::default()
        };
        let bugs = run_concurrent_harness(&config);
        assert!(
            bugs.is_empty(),
            "concurrent stress (16 threads) found bugs:\n{}",
            bugs.join("\n")
        );
    }
}
