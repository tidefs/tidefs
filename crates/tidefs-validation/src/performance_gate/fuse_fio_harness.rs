// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::benchmark_harness::{BenchmarkResult, FioHarness};
use super::gate_entry::MeasuredKpi;
use super::validation_tier::ValidationTier;
use std::process::Command;
use std::time::Instant;

pub struct FuseFioHarness {
    pub repo_root: String,
    pub daemon_bin: String,
}
impl FuseFioHarness {
    pub fn new(repo_root: impl Into<String>) -> Self {
        let r = repo_root.into();
        FuseFioHarness {
            daemon_bin: format!("{r}/target/debug/tidefs-posix-filesystem-adapter-daemon"),
            repo_root: r,
        }
    }
    pub fn run_smoke(&self) -> BenchmarkResult {
        self.run_profile("smoke", "default smoke")
    }
    /// Run a multi-block-size baseline sweep: 4K, 64K, 128K, 1M across
    /// seq read/write, rand read/write, and sync write workloads.
    /// Returns combined BenchmarkResult with latency percentiles.
    pub fn run_baseline(&self) -> BenchmarkResult {
        self.run_profile("baseline", "multi-block-size latency/throughput baseline")
    }
    fn run_profile(&self, profile: &str, desc: &str) -> BenchmarkResult {
        let s = "mounted-fuse";
        if !std::path::Path::new(&self.daemon_bin).exists() {
            return BenchmarkResult::refused(
                s,
                format!("daemon bin not found at {}", self.daemon_bin),
                ValidationTier::MountedUserspace,
            );
        }
        let scr = format!("{}/benchmarking/fio/run-benchmarks.sh", self.repo_root);
        if !std::path::Path::new(&scr).exists() {
            return BenchmarkResult::refused(
                s,
                "fio script not found",
                ValidationTier::MountedUserspace,
            );
        }
        let tr = std::env::var("TIDEFS_FIO_TEMP")
            .unwrap_or_else(|_| "/tmp/tidefs-fuse-fio-harness".into());
        let mp = format!("{tr}/mnt");
        let sp = format!("{tr}/store");
        let _ = std::fs::remove_dir_all(&tr);
        if let Err(e) = std::fs::create_dir_all(&mp) {
            return BenchmarkResult::refused(
                s,
                format!("mnt dir {mp}: {e}"),
                ValidationTier::MountedUserspace,
            );
        }
        if let Err(e) = std::fs::create_dir_all(&sp) {
            return BenchmarkResult::refused(
                s,
                format!("store dir {sp}: {e}"),
                ValidationTier::MountedUserspace,
            );
        }
        std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
        let mut dm = match Command::new(&self.daemon_bin)
            .arg("--store")
            .arg(&sp)
            .arg("--mount")
            .arg(&mp)
            .arg("--no-writeback-cache")
            .arg("-f")
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&tr);
                return BenchmarkResult::refused(
                    s,
                    format!("spawn: {e}"),
                    ValidationTier::MountedUserspace,
                );
            }
        };
        std::thread::sleep(std::time::Duration::from_secs(2));
        if !is_mount(&mp) {
            let _ = dm.kill();
            let _ = std::fs::remove_dir_all(&tr);
            return BenchmarkResult::refused(
                s,
                "not mount after 2s",
                ValidationTier::MountedUserspace,
            );
        }
        // Collect metadata create/stat/unlink throughput
        let meta = run_metadata_bench(&mp);

        let fio = FioHarness::new(&self.repo_root);
        let mut res = fio.run(
            format!("{s}-fio-{profile}"),
            "fuse",
            &mp,
            profile,
            ValidationTier::MountedUserspace,
        );
        let _ = dm.kill();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let _ = std::fs::remove_dir_all(&tr);
        res.subject = s.to_string();
        res.description = format!("fio {profile} mount: {desc}");
        if res.executed {
            res.kpis.push(MeasuredKpi {
                ref_id: "kpi.latency".into(),
                name: format!("{s}/fio-{profile}-dur"),
                value: res.duration_secs,
                unit: "s".into(),
                passed: None,
                percentile: None,
            });
        }
        // Append metadata KPIs
        if let Ok(mk) = meta {
            res.kpis.extend(mk);
        }
        res
    }
}

/// Run a lightweight create/stat/unlink throughput benchmark inside the
/// given mount point. Returns KPIs for metadata operations per second.
fn run_metadata_bench(mount: &str) -> Result<Vec<MeasuredKpi>, String> {
    let dir = format!("{mount}/tidefs-meta-bench");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;

    let num: u32 = 200;
    let start = Instant::now();
    for i in 0..num {
        let p = format!("{dir}/f{i:04}");
        std::fs::File::create(&p).map_err(|e| format!("create {p}: {e}"))?;
    }
    let create_s = start.elapsed().as_secs_f64();
    let create_ops = num as f64 / create_s;

    let start2 = Instant::now();
    for i in 0..num {
        let p = format!("{dir}/f{i:04}");
        let _ = std::fs::metadata(&p).map_err(|e| format!("stat {p}: {e}"))?;
    }
    let stat_s = start2.elapsed().as_secs_f64();
    let stat_ops = num as f64 / stat_s;

    let start3 = Instant::now();
    for i in 0..num {
        let p = format!("{dir}/f{i:04}");
        std::fs::remove_file(&p).map_err(|e| format!("unlink {p}: {e}"))?;
    }
    let unlink_s = start3.elapsed().as_secs_f64();
    let unlink_ops = num as f64 / unlink_s;
    let _ = std::fs::remove_dir(&dir);

    let s = "mounted-fuse";
    Ok(vec![
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-create-ops"),
            value: (create_ops * 10.0).round() / 10.0,
            unit: "files/s".into(),
            passed: None,
            percentile: None,
        },
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-stat-ops"),
            value: (stat_ops * 10.0).round() / 10.0,
            unit: "stats/s".into(),
            passed: None,
            percentile: None,
        },
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-unlink-ops"),
            value: (unlink_ops * 10.0).round() / 10.0,
            unit: "unlinks/s".into(),
            passed: None,
            percentile: None,
        },
    ])
}

fn is_mount(path: &str) -> bool {
    if let Ok(o) = Command::new("mountpoint").arg("-q").arg(path).output() {
        return o.status.success();
    }
    if let Ok(m) = std::fs::read_to_string("/proc/mounts") {
        return m.lines().any(|l| l.split_whitespace().nth(1) == Some(path));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_no_daemon() {
        assert!(!FuseFioHarness::new("/nx").run_smoke().executed);
    }
    #[test]
    fn non_mount() {
        assert!(!is_mount("/usr/share/doc/missing"));
    }
}
