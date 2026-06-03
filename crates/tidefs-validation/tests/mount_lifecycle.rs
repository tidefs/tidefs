// Worker slot: s6
//! FUSE mount lifecycle tests: mount/unmount roundtrip, double-mount
//! rejection, and mount/unmount stress.
//!
//! These tests validate the mount-teardown codepath for resource
//! safety and error handling, covering mount/unmount races and
//! double-mount rejection that existing tests do not exercise.

#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "linux")]
use tidefs_validation::mount_harness::{self, MountHarness};

// ── mount_unmount_roundtrip ───────────────────────────────────────────────

/// Mount, verify root inode accessible, unmount, repeat N=10 times.
/// Each iteration creates a fresh MountHarness (separate store + mount
/// point), verifies the mount root responds to stat, then drops the
/// harness which triggers graceful unmount.
#[cfg(target_os = "linux")]
#[test]
fn mount_unmount_roundtrip() {
    const ITERATIONS: usize = 10;
    for i in 0..ITERATIONS {
        let harness = match MountHarness::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SKIP mount_unmount_roundtrip: daemon not available -- {e}");
                return;
            }
        };
        // Verify root inode accessible.
        let md = harness
            .stat(".")
            .unwrap_or_else(|e| panic!("iteration {i}: stat root failed: {e}"));
        assert!(md.is_dir(), "iteration {i}: mount root must be a directory");
        // Drop triggers unmount; the harness's work_dir is cleaned up.
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn mount_unmount_roundtrip() {}

// ── mount_reject_double ───────────────────────────────────────────────────

/// Attempt to mount a second daemon on an already-mounted path.
/// Expects a clean error (either the daemon exits non-zero or the
/// mount point check detects the existing mount) rather than a panic
/// or hang.
#[cfg(target_os = "linux")]
#[test]
fn mount_reject_double() {
    let harness = match MountHarness::new() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mount_reject_double: daemon not available -- {e}");
            return;
        }
    };

    let daemon_bin = match mount_harness::find_daemon_binary() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP mount_reject_double: cannot locate daemon binary -- {e}");
            return;
        }
    };

    let root_auth_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";

    // Attempt to start a second daemon on the already-mounted path.
    let output = std::process::Command::new(&daemon_bin)
        .arg("mount-vfs")
        .arg("--store")
        .arg(harness.store_path())
        .arg("--mount")
        .arg(harness.mount_path())
        .arg("--root-auth-key-hex")
        .arg(root_auth_key_hex)
        .output();

    match output {
        Ok(out) => {
            assert!(
                !out.status.success()
                    || String::from_utf8_lossy(&out.stderr).contains("already")
                    || String::from_utf8_lossy(&out.stderr).contains("busy")
                    || String::from_utf8_lossy(&out.stderr).contains("exist"),
                "second daemon should not mount successfully on an occupied path;\
                 exit={}, stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!("mount_reject_double: second daemon spawn failed (clean): {e}");
        }
    }

    // Verify the original mount is still functional.
    assert!(
        harness.stat(".").is_ok(),
        "original mount must survive double-mount attempt"
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn mount_reject_double() {}

// ── mount_unmount_stress ──────────────────────────────────────────────────

/// Tight loop of mount/unmount (100 cycles) checking for resource
/// exhaustion or latency drift.
///
/// Each cycle: MountHarness::new() → stat root → drop (unmount).
/// Tracks per-cycle latency.  Fails if median latency drifts upward
/// by more than 10× over the first 10-cycle baseline, which would
/// indicate resource leaks (FD exhaustion, zombie processes, etc.).
#[cfg(target_os = "linux")]
#[test]
fn mount_unmount_stress() {
    const CYCLES: usize = 100;
    const BASELINE: usize = 10;
    let mut latencies: Vec<u64> = Vec::with_capacity(CYCLES);

    // First cycle also validates daemon availability.
    {
        let h = match MountHarness::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!("SKIP mount_unmount_stress: daemon not available -- {e}");
                return;
            }
        };
        assert!(h.stat(".").is_ok(), "root must be accessible");
        drop(h);
    }

    for i in 0..CYCLES {
        let t0 = Instant::now();
        let harness = MountHarness::new()
            .unwrap_or_else(|e| panic!("cycle {i}: MountHarness::new failed: {e}"));
        harness
            .stat(".")
            .unwrap_or_else(|e| panic!("cycle {i}: stat root failed: {e}"));
        let elapsed_ms = t0.elapsed().as_millis() as u64;
        latencies.push(elapsed_ms);
        drop(harness);
    }

    // Compute baseline and drift.
    let baseline_median = median(&latencies[..BASELINE.min(CYCLES)]);
    let overall_median = median(&latencies);

    eprintln!(
        "mount_unmount_stress: {CYCLES} cycles, \
         baseline_median={baseline_median}ms, \
         overall_median={overall_median}ms, \
         max={}ms",
        latencies.iter().max().unwrap_or(&0)
    );

    // Fail if median drifts upward by > 10x baseline.
    if baseline_median > 0 && overall_median > baseline_median * 10 {
        panic!(
            "mount_unmount_stress: latency drift detected: \
             baseline_median={baseline_median}ms, \
             overall_median={overall_median}ms (>10x)"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
#[ignore = "FUSE mount tests require Linux"]
fn mount_unmount_stress() {}

#[cfg(target_os = "linux")]
fn median(data: &[u64]) -> u64 {
    let mut v = data.to_vec();
    v.sort_unstable();
    if v.is_empty() {
        return 0;
    }
    let mid = v.len() / 2;
    if v.len() % 2 == 0 {
        (v[mid - 1] + v[mid]) / 2
    } else {
        v[mid]
    }
}
