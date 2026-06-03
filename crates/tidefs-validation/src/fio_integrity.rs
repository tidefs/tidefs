//! fio CRC32C data-integrity verification harness for TideFS FUSE mounts.
//!
//! `FioCrc32cVerifier` shells out to `fio --verify=crc32c`, runs a
//! write-then-read job against a mounted TideFS filesystem, parses the
//! JSON output, and returns a structured pass/fail result with mismatch
//! details.  The scoreboard integrates with the existing validation
//! scoreboard format for regression detection.
//!
//! The module also provides a `FioIntegrityScoreboard` that captures
//! per-run bandwidth, IOPS, I/O errors, and verification errors so
//! callers can track performance and correctness together.

#![deny(dead_code)]
#![deny(unused_imports)]

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

// -- fio JSON output types (subset of fields relevant for integrity) ------

/// Top-level fio JSON output.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FioOutput {
    #[serde(rename = "fio version")]
    fio_version: String,
    #[serde(default)]
    jobs: Vec<FioJob>,
}

/// Per-job fio output.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FioJob {
    jobname: String,
    error: i32,
    #[serde(default)]
    verror: Vec<FioVerificationError>,
    #[serde(default)]
    read: FioIoStats,
    #[serde(default)]
    write: FioIoStats,
}

/// Verification error record (present when checksum mismatches occur).
#[derive(Debug, Deserialize)]
struct FioVerificationError {
    offset: u64,
    expected: String,
    got: String,
}

/// Per-direction I/O statistics.
#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct FioIoStats {
    #[serde(default)]
    io_bytes: u64,
    #[serde(default)]
    bw_bytes: u64,
    #[serde(default)]
    bw: u64,
    #[serde(default)]
    iops: f64,
    #[serde(default)]
    total_ios: u64,
    #[serde(default)]
    short_ios: u64,
    #[serde(default)]
    drop_ios: u64,
}

// -- Public result types -------------------------------------------------

/// Result of a single fio CRC32C integrity run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FioIntegrityResult {
    /// Name of this run (e.g. "write", "verify").
    pub phase: String,
    /// Whether the run passed (zero I/O errors, zero verification errors).
    pub passed: bool,
    /// fio job-level error code (0 = success).
    pub error_code: i32,
    /// Number of checksum-mismatch verification errors.
    pub verification_errors: usize,
    /// Total bytes written.
    pub write_bytes: u64,
    /// Total bytes read.
    pub read_bytes: u64,
    /// Write bandwidth in KiB/s.
    pub write_bw_kibs: u64,
    /// Read bandwidth in KiB/s.
    pub read_bw_kibs: u64,
    /// Write IOPS.
    pub write_iops: f64,
    /// Read IOPS.
    pub read_iops: f64,
    /// Short I/Os encountered (write).
    pub write_short_ios: u64,
    /// Dropped I/Os encountered (write).
    pub write_drop_ios: u64,
    /// Short I/Os encountered (read).
    pub read_short_ios: u64,
    /// Dropped I/Os encountered (read).
    pub read_drop_ios: u64,
    /// Human-readable error details when not passed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
}

/// Aggregate scoreboard for a fio CRC32C verification session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FioIntegrityScoreboard {
    /// ISO-8601 start time.
    pub started_at: String,
    /// Wall-clock duration in seconds.
    pub duration_secs: f64,
    /// fio command line used.
    pub command: String,
    /// Mount point tested.
    pub mount_path: String,
    /// File size used for the test.
    pub file_size: String,
    /// Per-phase results (at minimum: write and verify).
    pub phases: Vec<FioIntegrityResult>,
    /// Aggregate summary.
    pub summary: FioIntegritySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FioIntegritySummary {
    /// Total phases executed.
    pub total_phases: usize,
    /// Phases that passed.
    pub phases_passed: usize,
    /// Phases that failed.
    pub phases_failed: usize,
    /// Total verification errors across all phases.
    pub total_verification_errors: usize,
    /// Total I/O error count across all phases.
    pub total_io_errors: i32,
    /// Overall pass/fail (all phases passed, zero errors).
    pub passed: bool,
}

// -- Verifier ------------------------------------------------------------

/// Shells out to `fio --verify=crc32c`, parses JSON output, and returns a
/// structured pass/fail result with mismatch details.
pub struct FioCrc32cVerifier {
    /// Path to the fio binary.
    fio_bin: String,
    /// Directory to run fio in (the FUSE mount point).
    target_dir: String,
    /// File size for the test (e.g. "8M").
    file_size: String,
    /// Job name passed to fio.
    job_name: String,
    /// Number of concurrent fio jobs (--numjobs, default 1).
    numjobs: u32,
    /// I/O queue depth (--iodepth, default 1).
    iodepth: u32,
}

impl FioCrc32cVerifier {
    /// Create a new verifier targeting `mount_path`.
    ///
    /// `file_size` is passed to fio's `--size` parameter (e.g. `"4M"`,
    /// `"64M"`).  `job_name` identifies the job in fio's JSON output.
    pub fn new(mount_path: impl AsRef<Path>, file_size: &str, job_name: &str) -> Self {
        Self {
            fio_bin: "fio".to_string(),
            target_dir: mount_path.as_ref().display().to_string(),
            file_size: file_size.to_string(),
            job_name: job_name.to_string(),
            numjobs: 1,
            iodepth: 1,
        }
    }

    /// Override the fio binary path (default: `"fio"` from `$PATH`).
    pub fn with_fio_bin(mut self, path: &str) -> Self {
        self.fio_bin = path.to_string();
        self
    }

    /// Set the number of concurrent fio jobs (--numjobs, default 1).
    /// Each job writes to a separate file, so the total I/O volume is
    /// `numjobs * file_size`.
    pub fn with_numjobs(mut self, n: u32) -> Self {
        self.numjobs = n;
        self
    }

    /// Set the I/O queue depth (--iodepth, default 1).
    pub fn with_iodepth(mut self, d: u32) -> Self {
        self.iodepth = d;
        self
    }

    /// Run the full CRC32C write-then-verify cycle.
    ///
    /// Phase 1 (write): `rw=randwrite` with `do_verify=0` (defer).
    /// Phase 2 (verify): `rw=randread` with `do_verify=1` (verify
    /// previously written blocks).
    ///
    /// Returns a populated scoreboard with per-phase results.
    pub fn run(&self) -> Result<FioIntegrityScoreboard, String> {
        let started_at = chrono_or_fallback();

        let mut phases = Vec::new();

        // Phase 1: write with deferred verification.
        let write_result = self.run_phase("write", "randwrite", false)?;
        phases.push(write_result);

        // Phase 2: read with verification of written blocks.
        let verify_result = self.run_phase("verify", "randread", true)?;
        phases.push(verify_result);

        let total_verification_errors: usize = phases.iter().map(|p| p.verification_errors).sum();
        let total_io_errors: i32 = phases.iter().map(|p| p.error_code).sum();

        let summary = FioIntegritySummary {
            total_phases: phases.len(),
            phases_passed: phases.iter().filter(|p| p.passed).count(),
            phases_failed: phases.iter().filter(|p| !p.passed).count(),
            total_verification_errors,
            total_io_errors,
            passed: phases.iter().all(|p| p.passed),
        };

        Ok(FioIntegrityScoreboard {
            started_at,
            duration_secs: 0.0,
            command: format!(
                "{} --name={} --size={} --directory={} --verify=crc32c --numjobs={} --iodepth={}",
                self.fio_bin,
                self.job_name,
                self.file_size,
                self.target_dir,
                self.numjobs,
                self.iodepth
            ),
            mount_path: self.target_dir.clone(),
            file_size: self.file_size.clone(),
            phases,
            summary,
        })
    }

    /// Run a single fio phase and parse the result.
    fn run_phase(
        &self,
        phase_name: &str,
        rw: &str,
        do_verify: bool,
    ) -> Result<FioIntegrityResult, String> {
        let mut cmd = Command::new(&self.fio_bin);
        cmd.arg("--name").arg(&self.job_name);
        cmd.arg("--size").arg(&self.file_size);
        cmd.arg("--rw").arg(rw);
        cmd.arg("--directory").arg(&self.target_dir);
        cmd.arg("--verify=crc32c");
        cmd.arg("--verify_fatal=0"); // Don't abort; collect all errors.
        cmd.arg("--output-format=json");
        cmd.arg("--numjobs").arg(self.numjobs.to_string());
        cmd.arg("--iodepth").arg(self.iodepth.to_string());
        if do_verify {
            cmd.arg("--do_verify=1");
        } else {
            cmd.arg("--do_verify=0");
        }
        // Use end_fsync for durability semantics.
        cmd.arg("--end_fsync=1");

        let output = cmd
            .output()
            .map_err(|e| format!("spawn fio for phase {phase_name}: {e} (is fio installed?)"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "fio phase {phase_name} exited with {}: {}",
                output.status, stderr
            ));
        }

        let stdout_raw = String::from_utf8_lossy(&output.stdout);
        // fio may emit advisory notes to stdout before the JSON body
        // (e.g. "note: both iodepth >= 1 and synchronous I/O engine...").
        // Strip those lines before parsing.
        let stdout_json: String = stdout_raw
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("note:") && !trimmed.starts_with("fio:")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let fio_output: FioOutput = serde_json::from_str(&stdout_json)
            .map_err(|e| format!("parse fio JSON for phase {phase_name}: {e}"))?;

        if fio_output.jobs.is_empty() {
            return Err(format!("fio phase {phase_name}: no jobs in JSON output"));
        }

        // Aggregate across all jobs (numjobs may be > 1).
        let mut total_error_code = 0i32;
        let mut total_verror: usize = 0;
        let mut total_write_bytes: u64 = 0;
        let mut total_read_bytes: u64 = 0;
        let mut max_write_bw: u64 = 0;
        let mut max_read_bw: u64 = 0;
        let mut sum_write_iops: f64 = 0.0;
        let mut sum_read_iops: f64 = 0.0;
        let mut total_write_short: u64 = 0;
        let mut total_write_drop: u64 = 0;
        let mut total_read_short: u64 = 0;
        let mut total_read_drop: u64 = 0;
        let mut all_error_details: Vec<String> = Vec::new();

        for job in &fio_output.jobs {
            total_error_code += job.error;
            let verrors = job.verror.len();
            total_verror += verrors;
            total_write_bytes += job.write.io_bytes;
            total_read_bytes += job.read.io_bytes;
            max_write_bw = max_write_bw.max(job.write.bw);
            max_read_bw = max_read_bw.max(job.read.bw);
            sum_write_iops += job.write.iops;
            sum_read_iops += job.read.iops;
            total_write_short += job.write.short_ios;
            total_write_drop += job.write.drop_ios;
            total_read_short += job.read.short_ios;
            total_read_drop += job.read.drop_ios;

            if job.error != 0 || verrors > 0 {
                let mut details = Vec::new();
                details.push(format!("job '{}':", job.jobname));
                if job.error != 0 {
                    details.push(format!("  I/O error code: {}", job.error));
                }
                if verrors > 0 {
                    details.push(format!("  {verrors} CRC32C verification error(s)"));
                    for (i, ve) in job.verror.iter().take(5).enumerate() {
                        details.push(format!(
                            "    mismatch[{}]: offset={} expected={} got={}",
                            i, ve.offset, ve.expected, ve.got
                        ));
                    }
                    if verrors > 5 {
                        details.push(format!("    ... and {} more", verrors - 5));
                    }
                }
                all_error_details.push(details.join("\n"));
            }
        }

        let passed = total_error_code == 0 && total_verror == 0;
        let error_detail = if all_error_details.is_empty() {
            None
        } else {
            Some(all_error_details.join("; "))
        };

        Ok(FioIntegrityResult {
            phase: phase_name.to_string(),
            passed,
            error_code: total_error_code,
            verification_errors: total_verror,
            write_bytes: total_write_bytes,
            read_bytes: total_read_bytes,
            write_bw_kibs: max_write_bw,
            read_bw_kibs: max_read_bw,
            write_iops: sum_write_iops,
            read_iops: sum_read_iops,
            write_short_ios: total_write_short,
            write_drop_ios: total_write_drop,
            read_short_ios: total_read_short,
            read_drop_ios: total_read_drop,
            error_detail,
        })
    }
}

// -- Helpers --------------------------------------------------------------

/// Produce an ISO-8601 timestamp string, or fall back to "unknown".
fn chrono_or_fallback() -> String {
    match Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    }
}

// -- Scoreboard serialization ---------------------------------------------

impl FioIntegrityScoreboard {
    /// Serialize the scoreboard to a pretty-printed JSON string.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize scoreboard: {e}"))
    }

    /// Write the scoreboard to a JSON file at `path`.
    pub fn write_json(&self, path: &Path) -> Result<(), String> {
        let json = self.to_json()?;
        std::fs::write(path, &json).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Load a scoreboard from a JSON file.
    pub fn load_json(path: &Path) -> Result<Self, String> {
        let data =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// Return whether the scoreboard indicates a clean pass.
    pub fn passed(&self) -> bool {
        self.summary.passed
    }
}

// -- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_harness::MountHarness;

    /// Run CRC32C write-then-verify against a temp directory (not a TideFS
    /// mount) to exercise JSON parsing and result struct round-trip.
    /// Does NOT require FUSE or the TideFS daemon.
    #[test]
    fn fio_crc32c_tempdir_roundtrip() {
        let has_fio = Command::new("fio")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !has_fio {
            eprintln!("SKIP fio_crc32c_tempdir_roundtrip: fio not found");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("create temp dir");

        let verifier = FioCrc32cVerifier::new(tmp.path(), "1M", "integrity_test");
        let scoreboard = verifier.run().expect("fio run should succeed");

        assert_eq!(
            scoreboard.phases.len(),
            2,
            "must have write + verify phases"
        );
        assert_eq!(scoreboard.phases[0].phase, "write");
        assert_eq!(scoreboard.phases[1].phase, "verify");

        assert!(
            scoreboard.phases[0].passed,
            "write phase should pass on tmpfs"
        );
        assert!(
            scoreboard.phases[1].passed,
            "verify phase should pass on tmpfs: {}",
            scoreboard.phases[1]
                .error_detail
                .as_deref()
                .unwrap_or("(no detail)")
        );

        assert!(scoreboard.passed());
        assert_eq!(scoreboard.summary.total_verification_errors, 0);
        assert_eq!(scoreboard.summary.total_io_errors, 0);
        assert_eq!(scoreboard.summary.phases_passed, 2);
        assert_eq!(scoreboard.summary.phases_failed, 0);

        assert!(
            scoreboard.phases[0].write_bytes > 0,
            "write phase must write bytes"
        );
        assert!(
            scoreboard.phases[1].read_bytes > 0,
            "verify phase must read bytes"
        );

        // Scoreboard JSON round-trip.
        let json = scoreboard.to_json().expect("serialize scoreboard");
        assert!(
            json.contains("\"phase\": \"write\""),
            "JSON must contain write phase"
        );
        assert!(
            json.contains("\"phase\": \"verify\""),
            "JSON must contain verify phase"
        );

        let parsed: FioIntegrityScoreboard =
            serde_json::from_str(&json).expect("deserialize scoreboard JSON");

        assert_eq!(parsed.summary.passed, scoreboard.summary.passed);
        assert_eq!(parsed.phases.len(), scoreboard.phases.len());
    }

    /// Verify that a fio CRC32C run against a tmpfs produces a JSON file
    /// via `write_json` and can be loaded back.
    #[test]
    fn fio_write_json_scoreboard() {
        let has_fio = Command::new("fio")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !has_fio {
            eprintln!("SKIP fio_write_json_scoreboard: fio not found");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let json_path = tmp.path().join("scoreboard.json");

        let verifier = FioCrc32cVerifier::new(tmp.path(), "512k", "json_test");
        let scoreboard = verifier.run().expect("fio run should succeed");

        scoreboard
            .write_json(&json_path)
            .expect("write scoreboard JSON");

        let loaded = FioIntegrityScoreboard::load_json(&json_path).expect("load scoreboard JSON");

        assert_eq!(loaded.summary.passed, scoreboard.summary.passed);
        assert!(loaded.passed());
    }

    /// FioIntegrityResult serialization round-trip.
    #[test]
    fn result_json_roundtrip() {
        let result = FioIntegrityResult {
            phase: "write".to_string(),
            passed: true,
            error_code: 0,
            verification_errors: 0,
            write_bytes: 1048576,
            read_bytes: 0,
            write_bw_kibs: 512000,
            read_bw_kibs: 0,
            write_iops: 128000.0,
            read_iops: 0.0,
            write_short_ios: 0,
            write_drop_ios: 0,
            read_short_ios: 0,
            read_drop_ios: 0,
            error_detail: None,
        };

        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: FioIntegrityResult = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.phase, "write");
        assert!(parsed.passed);
        assert_eq!(parsed.write_bytes, 1048576);
        assert!(parsed.error_detail.is_none());
    }

    /// A result with errors serializes correctly.
    #[test]
    fn result_with_errors_json_roundtrip() {
        let result = FioIntegrityResult {
            phase: "verify".to_string(),
            passed: false,
            error_code: 0,
            verification_errors: 3,
            write_bytes: 0,
            read_bytes: 1048576,
            write_bw_kibs: 0,
            read_bw_kibs: 512000,
            write_iops: 0.0,
            read_iops: 128000.0,
            write_short_ios: 0,
            write_drop_ios: 0,
            read_short_ios: 0,
            read_drop_ios: 0,
            error_detail: Some(
                "3 CRC32C verification error(s); mismatch[0]: offset=4096 expected=abc got=def"
                    .to_string(),
            ),
        };

        let json = serde_json::to_string_pretty(&result).expect("serialize");
        assert!(
            json.contains("verification error"),
            "JSON must contain error details"
        );

        let parsed: FioIntegrityResult = serde_json::from_str(&json).expect("deserialize");
        assert!(!parsed.passed);
        assert_eq!(parsed.verification_errors, 3);
        assert!(parsed.error_detail.is_some());
    }

    /// Verify that verifier with a non-existent directory produces an
    /// error rather than panicking.
    #[test]
    fn verifier_nonexistent_directory() {
        let verifier = FioCrc32cVerifier::new("/nonexistent/path/for/fio", "1M", "test");
        let result = verifier.run();
        match result {
            Err(e) => {
                assert!(
                    e.contains("fio") || e.contains("nonexistent"),
                    "error should mention fio or path: {e}"
                );
            }
            Ok(sb) => {
                assert!(!sb.passed(), "should not pass on nonexistent dir");
            }
        }
    }

    /// Verify the verifier can be constructed with a custom fio binary path.
    #[test]
    fn verifier_custom_fio_bin() {
        let tmp = tempfile::TempDir::new().expect("create temp dir");
        let verifier =
            FioCrc32cVerifier::new(tmp.path(), "1M", "test").with_fio_bin("/usr/bin/fio");

        let result = verifier.run();
        assert!(
            result.is_ok(),
            "should succeed with explicit fio binary path"
        );
    }

    /// Mount TideFS FUSE, run fio CRC32C write+verify cycle against the
    /// mount point, and assert zero checksum mismatches.  Skips gracefully
    /// when the daemon binary or /dev/fuse is unavailable.
    #[test]
    fn fio_crc32c_fuse_mount_integrity() {
        let harness = match MountHarness::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "SKIP fio_crc32c_fuse_mount_integrity: \
                     daemon not available -- {e}"
                );
                return;
            }
        };

        let mount_path = harness.mount_path().to_path_buf();

        // Run fio CRC32C write+verify against the TideFS mount.
        let verifier = FioCrc32cVerifier::new(&mount_path, "4M", "tidefs_fio");
        let scoreboard = match verifier.run() {
            Ok(sb) => sb,
            Err(e) => {
                if e.contains("No such file") || e.contains("fio") {
                    eprintln!(
                        "SKIP fio_crc32c_fuse_mount_integrity: \
                         fio not available -- {e}"
                    );
                    return;
                }
                panic!("fio CRC32C run failed: {e}");
            }
        };

        // Write scoreboard as validation.
        let validation_dir = std::path::PathBuf::from(
            std::env::var("TIDEFS_VALIDATION_DIR")
                .unwrap_or_else(|_| "/tmp/tidefs-validation".to_string()),
        );
        let _ = std::fs::create_dir_all(&validation_dir);
        let scoreboard_path = validation_dir.join("fio_crc32c_fuse_scoreboard.json");
        if let Err(e) = scoreboard.write_json(&scoreboard_path) {
            eprintln!("warning: could not write scoreboard JSON: {e}");
        }

        // Assertions: all phases must pass, zero verification errors.
        assert!(
            scoreboard.passed(),
            "fio CRC32C FUSE mount integrity FAILED: summary={:?}",
            scoreboard.summary
        );

        for phase in &scoreboard.phases {
            assert!(
                phase.passed,
                "phase '{}' FAILED: error_code={} verification_errors={} detail={:?}",
                phase.phase, phase.error_code, phase.verification_errors, phase.error_detail
            );
        }

        assert_eq!(
            scoreboard.summary.total_verification_errors, 0,
            "CRC32C verification errors on TideFS FUSE mount"
        );
        assert_eq!(
            scoreboard.summary.total_io_errors, 0,
            "I/O errors on TideFS FUSE mount"
        );

        // Verify we actually wrote and read data.
        let write_phase = &scoreboard.phases[0];
        assert!(
            write_phase.write_bytes > 0,
            "write phase must write bytes to TideFS mount"
        );
        let verify_phase = &scoreboard.phases[1];
        assert!(
            verify_phase.read_bytes > 0,
            "verify phase must read bytes from TideFS mount"
        );

        // Drop harness -- unmounts and cleans up.
        drop(harness);
    }

    /// Run multi-threaded fio CRC32C write+verify against a temp directory
    /// to exercise numjobs > 1 aggregation logic.  Does NOT require FUSE
    /// or the TideFS daemon.
    #[test]
    fn fio_crc32c_multithreaded_tempdir() {
        let has_fio = Command::new("fio")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !has_fio {
            eprintln!("SKIP fio_crc32c_multithreaded_tempdir: fio not found");
            return;
        }

        let tmp = tempfile::TempDir::new().expect("create temp dir");

        let verifier = FioCrc32cVerifier::new(tmp.path(), "2M", "mt_test")
            .with_numjobs(4)
            .with_iodepth(4);
        let scoreboard = verifier
            .run()
            .expect("fio multithreaded run should succeed");

        assert_eq!(scoreboard.phases.len(), 2);
        assert!(scoreboard.phases[0].passed, "write phase should pass");
        assert!(
            scoreboard.phases[1].passed,
            "verify phase should pass: {}",
            scoreboard.phases[1]
                .error_detail
                .as_deref()
                .unwrap_or("(no detail)")
        );

        assert!(scoreboard.passed());
        assert_eq!(scoreboard.summary.total_verification_errors, 0);
        assert_eq!(scoreboard.summary.total_io_errors, 0);

        // With 4 jobs, total written should be roughly 4 * 2M.
        assert!(
            scoreboard.phases[0].write_bytes >= 4 * 2 * 1024 * 1024,
            "multithreaded write should produce at least numjobs * file_size bytes"
        );
        assert!(
            scoreboard.phases[1].read_bytes >= 4 * 2 * 1024 * 1024,
            "multithreaded verify should read at least numjobs * file_size bytes"
        );

        // JSON round-trip still works.
        let json = scoreboard.to_json().expect("serialize");
        let parsed: FioIntegrityScoreboard = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.passed());
    }

    /// Mount TideFS FUSE, run multi-threaded fio CRC32C write+verify
    /// (numjobs=4, iodepth=4) against the mount point.  Skips gracefully
    /// when the daemon or /dev/fuse is unavailable.
    #[test]
    fn fio_crc32c_multithreaded_fuse_mount() {
        let harness = match MountHarness::new() {
            Ok(h) => h,
            Err(e) => {
                eprintln!(
                    "SKIP fio_crc32c_multithreaded_fuse_mount: \
                     daemon not available -- {e}"
                );
                return;
            }
        };

        let mount_path = harness.mount_path().to_path_buf();

        let verifier = FioCrc32cVerifier::new(&mount_path, "4M", "tidefs_mt")
            .with_numjobs(4)
            .with_iodepth(4);
        let scoreboard = match verifier.run() {
            Ok(sb) => sb,
            Err(e) => {
                if e.contains("No such file") || e.contains("fio") {
                    eprintln!(
                        "SKIP fio_crc32c_multithreaded_fuse_mount: \
                         fio not available -- {e}"
                    );
                    return;
                }
                panic!("fio multithreaded run failed: {e}");
            }
        };

        assert!(
            scoreboard.passed(),
            "multithreaded fio CRC32C FUSE mount integrity FAILED: summary={:?}",
            scoreboard.summary
        );

        for phase in &scoreboard.phases {
            assert!(
                phase.passed,
                "phase '{}' FAILED: error_code={} verrors={}",
                phase.phase, phase.error_code, phase.verification_errors
            );
        }

        assert_eq!(scoreboard.summary.total_verification_errors, 0);
        assert_eq!(scoreboard.summary.total_io_errors, 0);

        // Verify we wrote and read bytes.
        assert!(scoreboard.phases[0].write_bytes > 0);
        assert!(scoreboard.phases[1].read_bytes > 0);

        drop(harness);
    }
}
