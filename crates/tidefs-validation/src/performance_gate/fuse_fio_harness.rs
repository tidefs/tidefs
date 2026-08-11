// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::benchmark_harness::{BenchmarkResult, FioHarness};
use super::gate_entry::MeasuredKpi;
use super::validation_tier::ValidationTier;
use std::time::Instant;

pub struct FuseFioHarness {
    pub repo_root: String,
}
impl FuseFioHarness {
    pub fn new(repo_root: impl Into<String>) -> Self {
        FuseFioHarness {
            repo_root: repo_root.into(),
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
        let scr = format!("{}/benchmarking/fio/run-benchmarks.sh", self.repo_root);
        if !std::path::Path::new(&scr).exists() {
            return BenchmarkResult::refused(
                s,
                "fio script not found",
                ValidationTier::MountedUserspace,
            );
        }
        let harness = match crate::mount_harness::MountHarness::new() {
            Ok(harness) => harness,
            Err(error) => {
                return BenchmarkResult::refused(
                    s,
                    format!("canonical pool mount unavailable: {error}"),
                    ValidationTier::MountedUserspace,
                )
            }
        };
        let mp = harness.mount_path().display().to_string();
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
        res.subject = s.to_string();
        res.description = format!("fio {profile} canonical pool mount: {desc}");
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_missing_fio_script() {
        assert!(!FuseFioHarness::new("/nx").run_smoke().executed);
    }
}
