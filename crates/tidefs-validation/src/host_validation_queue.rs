//! Host-validation capacity gate: QEMU job queue fairness.
//!
//! Provides a cross-process capacity semaphore so that multiple Nexus
//! worker slots do not oversubscribe the host with concurrent QEMU VMs.
//! Uses `flock`-based file locking under a shared gate directory,
//! compatible with the `scripts/tidefs-host-validation-gate.sh` shell
//! wrapper.
//!
//! # Design
//!
//! - Max capacity (default 2) is configured via the
//!   `TIDEFS_HOST_VALIDATION_MAX_CAPACITY` env var.
//! - Slot files `slot-0` .. `slot-<N-1>` live under the gate directory
//!   (`TIDEFS_HOST_VALIDATION_GATE_DIR`, default
//!   `/tmp/tidefs-workers/host-validation-gate`).
//! - Acquiring a slot takes an exclusive `flock` on a free slot file; the
//!   lock is held until the returned `CapacityGuard` is dropped.
//! - The `status` function reads metadata from all slot files without
//!   blocking.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ── configuration ──────────────────────────────────────────────────────────

fn gate_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TIDEFS_HOST_VALIDATION_GATE_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    PathBuf::from("/tmp/tidefs-workers/host-validation-gate")
}

fn max_capacity() -> usize {
    if let Ok(val) = std::env::var("TIDEFS_HOST_VALIDATION_MAX_CAPACITY") {
        if let Ok(n) = val.parse::<usize>() {
            if n > 0 {
                return n;
            }
        }
    }
    2
}

fn default_timeout() -> Duration {
    if let Ok(val) = std::env::var("TIDEFS_HOST_VALIDATION_TIMEOUT") {
        if let Ok(n) = val.parse::<u64>() {
            return Duration::from_secs(n);
        }
    }
    Duration::from_secs(3600)
}

// ── types ──────────────────────────────────────────────────────────────────

/// Snapshot of a single capacity slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    pub slot: usize,
    pub status: String,
    pub owner: String,
    pub pid: u32,
    pub started_at: u64,
}

/// Aggregate capacity-gate state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateStatus {
    pub gate_dir: String,
    pub max_capacity: usize,
    pub slots: Vec<SlotInfo>,
    pub occupied: usize,
    pub free: usize,
}

/// RAII guard that holds an acquired capacity slot.  The slot is
/// released when this guard is dropped.
#[derive(Debug)]
pub struct CapacityGuard {
    slot: usize,
    _file: File, // held open to keep the flock alive
}

impl CapacityGuard {
    /// Return the zero-based slot index.
    pub fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for CapacityGuard {
    fn drop(&mut self) {
        // Mark slot as free in metadata (best-effort; the flock release is
        // the authoritative signal).
        let slot_path = gate_dir().join(format!("slot-{}", self.slot));
        if let Ok(mut f) = OpenOptions::new().write(true).open(&slot_path) {
            let free_meta = serde_json::json!({
                "slot": self.slot,
                "status": "free",
                "owner": "",
                "pid": 0,
                "started_at": 0,
            });
            let _ = write!(f, "{free_meta}");
        }
    }
}

// ── internal helpers ───────────────────────────────────────────────────────

/// Apply an exclusive non-blocking `flock` to `fd`.
/// Returns `true` if the lock was acquired.
fn try_flock_exclusive(fd: i32) -> bool {
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    ret == 0
}

/// Read slot metadata from a slot file.  Returns a free-slot default on
/// any error.
fn read_slot_meta(slot: usize) -> SlotInfo {
    let slot_path = gate_dir().join(format!("slot-{slot}"));
    match fs::read_to_string(&slot_path) {
        Ok(contents) => serde_json::from_str::<SlotInfo>(&contents).unwrap_or(SlotInfo {
            slot,
            status: "free".into(),
            owner: String::new(),
            pid: 0,
            started_at: 0,
        }),
        Err(_) => SlotInfo {
            slot,
            status: "free".into(),
            owner: String::new(),
            pid: 0,
            started_at: 0,
        },
    }
}

/// Write slot metadata without holding a lock (best-effort status update).
fn write_slot_meta(slot: usize, status: &str, owner: &str, pid: u32, started_at: u64) {
    let slot_path = gate_dir().join(format!("slot-{slot}"));
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&slot_path)
    {
        let meta = serde_json::json!({
            "slot": slot,
            "status": status,
            "owner": owner,
            "pid": pid,
            "started_at": started_at,
        });
        let _ = write!(f, "{meta}");
    }
}

/// Ensure the gate directory and slot files exist.
fn init_gate_dir() -> io::Result<()> {
    let dir = gate_dir();
    fs::create_dir_all(&dir)?;
    let cap = max_capacity();
    for i in 0..cap {
        let slot_path = dir.join(format!("slot-{i}"));
        if !slot_path.exists() {
            write_slot_meta(i, "free", "", 0, 0);
        }
    }
    Ok(())
}

/// Try to acquire the lock on a specific slot file.
/// Returns `(slot, File)` on success, or `None` if the slot is already held.
fn try_acquire_slot(slot: usize, owner: &str) -> Option<CapacityGuard> {
    let slot_path = gate_dir().join(format!("slot-{slot}"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&slot_path)
        .ok()?;

    let fd = file.as_raw_fd();
    if !try_flock_exclusive(fd) {
        return None;
    }

    // We hold the lock — write metadata.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pid = std::process::id();
    write_slot_meta(slot, "occupied", owner, pid, now);

    Some(CapacityGuard { slot, _file: file })
}

// ── public API ─────────────────────────────────────────────────────────────

/// Acquire a capacity slot, blocking up to `timeout` with exponential
/// backoff.  Returns a [`CapacityGuard`] that releases the slot on drop.
///
/// Returns `None` on timeout.
pub fn acquire(timeout: Duration, owner: &str) -> Option<CapacityGuard> {
    let _ = init_gate_dir();
    let deadline = Instant::now() + timeout;
    let cap = max_capacity();
    let mut wait = Duration::from_secs(1);

    loop {
        for i in 0..cap {
            if let Some(guard) = try_acquire_slot(i, owner) {
                return Some(guard);
            }
        }

        if Instant::now() >= deadline {
            return None;
        }

        std::thread::sleep(wait);
        // Cap backoff at 8 seconds.
        wait = (wait * 2).min(Duration::from_secs(8));
    }
}

/// Query current capacity-gate status without blocking.
pub fn status() -> GateStatus {
    let _ = init_gate_dir();
    let cap = max_capacity();
    let mut slots = Vec::with_capacity(cap);
    let mut occupied = 0usize;
    let mut free = 0usize;

    for i in 0..cap {
        let info = read_slot_meta(i);
        if info.status == "occupied" {
            occupied += 1;
        } else {
            free += 1;
        }
        slots.push(info);
    }

    GateStatus {
        gate_dir: gate_dir().to_string_lossy().into_owned(),
        max_capacity: cap,
        slots,
        occupied,
        free,
    }
}

/// Run `f` under a capacity guard.  Acquires a slot, runs `f`, and
/// releases the slot (even on panic).  Returns `None` if the slot
/// could not be acquired within the default timeout.
pub fn run_gated<F, T>(owner: &str, f: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    run_gated_timeout(owner, default_timeout(), f)
}

/// Run `f` under a capacity guard with an explicit timeout.
pub fn run_gated_timeout<F, T>(owner: &str, timeout: Duration, f: F) -> Option<T>
where
    F: FnOnce() -> T,
{
    let _guard = acquire(timeout, owner)?;
    Some(f())
}

// ── tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn test_gate_dir() -> PathBuf {
        let dir = std::env::temp_dir().join("tidefs-gate-test");
        let _ = fs::create_dir_all(&dir);
        dir
    }

    fn with_test_env<F: FnOnce()>(f: F) {
        let dir = test_gate_dir();
        env::set_var(
            "TIDEFS_HOST_VALIDATION_GATE_DIR",
            dir.to_string_lossy().as_ref(),
        );
        env::set_var("TIDEFS_HOST_VALIDATION_MAX_CAPACITY", "2");

        // Clean any leftover slot files from previous runs.
        for i in 0..4 {
            let _ = fs::remove_file(dir.join(format!("slot-{i}")));
        }

        f();
    }

    #[test]
    fn status_reports_initial_free_slots() {
        with_test_env(|| {
            let s = status();
            assert_eq!(s.max_capacity, 2);
            assert_eq!(s.free, 2);
            assert_eq!(s.occupied, 0);
            assert_eq!(s.slots.len(), 2);
            for slot in &s.slots {
                assert_eq!(slot.status, "free");
            }
        });
    }

    #[test]
    fn acquire_and_release_slot() {
        with_test_env(|| {
            let s_before = status();
            assert_eq!(s_before.free, 2);

            let guard = acquire(Duration::from_secs(5), "test-acquire");
            assert!(guard.is_some());

            let s_during = status();
            assert_eq!(s_during.occupied, 1);
            assert_eq!(s_during.free, 1);

            drop(guard);

            let s_after = status();
            assert_eq!(s_after.free, 2);
            assert_eq!(s_after.occupied, 0);
        });
    }

    #[test]
    fn timeout_when_capacity_exhausted() {
        with_test_env(|| {
            // Acquire both slots.
            let g1 = acquire(Duration::from_secs(5), "test-1").expect("first slot");
            let _g2 = acquire(Duration::from_secs(5), "test-2").expect("second slot");

            let s = status();
            assert_eq!(s.free, 0);
            assert_eq!(s.occupied, 2);

            // Third acquisition should time out quickly.
            let g3 = acquire(Duration::from_millis(500), "test-3");
            assert!(g3.is_none(), "third acquire should time out");

            drop(g1);
            // After releasing one, acquisition should succeed.
            let g3 = acquire(Duration::from_secs(2), "test-3");
            assert!(g3.is_some(), "acquire should succeed after release");
        });
    }

    #[test]
    fn run_gated_executes_with_capacity() {
        with_test_env(|| {
            let result = run_gated("test-run", || 42);
            assert_eq!(result, Some(42));

            // Slot should be released.
            let s = status();
            assert_eq!(s.free, 2);
        });
    }

    #[test]
    fn run_gated_timeout_returns_none_when_full() {
        with_test_env(|| {
            let _g1 = acquire(Duration::from_secs(5), "test-1").expect("first");
            let _g2 = acquire(Duration::from_secs(5), "test-2").expect("second");

            let result = run_gated_timeout("test-3", Duration::from_millis(200), || 99);
            assert_eq!(result, None);
        });
    }

    #[test]
    fn status_json_roundtrip() {
        with_test_env(|| {
            let s = status();
            let json = serde_json::to_string(&s).expect("serialize");
            let parsed: GateStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(parsed.max_capacity, s.max_capacity);
            assert_eq!(parsed.free, s.free);
            assert_eq!(parsed.occupied, s.occupied);
        });
    }
}
