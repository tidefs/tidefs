// Metadata-heavy workload baseline harness for NEXT-PERF-004.
//
// Measures create, stat, rename, and unlink operations on a mounted
// filesystem path, producing ops/sec throughput and per-operation latency
// percentiles (p50, p95, p99).

use super::benchmark_harness::BenchmarkResult;
use super::validation_tier::ValidationTier;
use super::gate_entry::MeasuredKpi;
use std::time::Instant;

/// Default file count for a lightweight smoke run.
pub const DEFAULT_METADATA_FILE_COUNT: u32 = 5000;

/// Operational KPIs from a single metadata workload run.
#[derive(Debug, Clone)]
pub struct MetadataKpis {
    pub num_files: u32,
    pub create_ops_per_sec: f64,
    pub create_latency_p50_us: f64,
    pub create_latency_p95_us: f64,
    pub create_latency_p99_us: f64,
    pub stat_ops_per_sec: f64,
    pub stat_latency_p50_us: f64,
    pub stat_latency_p95_us: f64,
    pub stat_latency_p99_us: f64,
    pub rename_ops_per_sec: f64,
    pub rename_latency_p50_us: f64,
    pub rename_latency_p95_us: f64,
    pub rename_latency_p99_us: f64,
    pub unlink_ops_per_sec: f64,
    pub unlink_latency_p50_us: f64,
    pub unlink_latency_p95_us: f64,
    pub unlink_latency_p99_us: f64,
}

/// Serde-compatible JSON rendering of metadata workload validation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetadataValidation {
    pub num_files: u32,
    pub create_ops_per_sec: f64,
    pub create_latency_p50_us: f64,
    pub create_latency_p95_us: f64,
    pub create_latency_p99_us: f64,
    pub stat_ops_per_sec: f64,
    pub stat_latency_p50_us: f64,
    pub stat_latency_p95_us: f64,
    pub stat_latency_p99_us: f64,
    pub rename_ops_per_sec: f64,
    pub rename_latency_p50_us: f64,
    pub rename_latency_p95_us: f64,
    pub rename_latency_p99_us: f64,
    pub unlink_ops_per_sec: f64,
    pub unlink_latency_p50_us: f64,
    pub unlink_latency_p95_us: f64,
    pub unlink_latency_p99_us: f64,
}

impl From<&MetadataKpis> for MetadataValidation {
    fn from(k: &MetadataKpis) -> Self {
        MetadataValidation {
            num_files: k.num_files,
            create_ops_per_sec: k.create_ops_per_sec,
            create_latency_p50_us: k.create_latency_p50_us,
            create_latency_p95_us: k.create_latency_p95_us,
            create_latency_p99_us: k.create_latency_p99_us,
            stat_ops_per_sec: k.stat_ops_per_sec,
            stat_latency_p50_us: k.stat_latency_p50_us,
            stat_latency_p95_us: k.stat_latency_p95_us,
            stat_latency_p99_us: k.stat_latency_p99_us,
            rename_ops_per_sec: k.rename_ops_per_sec,
            rename_latency_p50_us: k.rename_latency_p50_us,
            rename_latency_p95_us: k.rename_latency_p95_us,
            rename_latency_p99_us: k.rename_latency_p99_us,
            unlink_ops_per_sec: k.unlink_ops_per_sec,
            unlink_latency_p50_us: k.unlink_latency_p50_us,
            unlink_latency_p95_us: k.unlink_latency_p95_us,
            unlink_latency_p99_us: k.unlink_latency_p99_us,
        }
    }
}

/// Harness that runs a metadata-heavy workload (create/stat/rename/unlink)
/// against a filesystem path and returns structured KPIs.
pub struct MetadataHarness {
    pub repo_root: String,
}

impl MetadataHarness {
    pub fn new(repo_root: impl Into<String>) -> Self {
        MetadataHarness {
            repo_root: repo_root.into(),
        }
    }

    /// Run a full metadata workload baseline against the given path.
    pub fn run_baseline(&self, path: &str, num_files: u32) -> BenchmarkResult {
        let s = "mounted-fuse-metadata";
        let dir = format!("{path}/tidefs-meta-harness-bench");
        let _ = std::fs::remove_dir_all(&dir);

        if let Err(e) = std::fs::create_dir_all(&dir) {
            return BenchmarkResult::refused(
                s,
                format!("mkdir {dir}: {e}"),
                ValidationTier::MountedUserspace,
            );
        }

        let t0 = Instant::now();
        match run_metadata_workload(&dir, num_files) {
            Ok(kpis) => {
                let dur = t0.elapsed().as_secs_f64();
                let _ = std::fs::remove_dir_all(&dir);
                BenchmarkResult {
                    subject: s.to_string(),
                    description: format!(
                        "metadata workload: {num_files} create/stat/rename/unlink on {path}"
                    ),
                    executed: true,
                    exit_code: Some(0),
                    duration_secs: dur,
                    kpis: metadata_kpis_to_vec(&kpis),
                    validation_tier: ValidationTier::MountedUserspace,
                    stdout_tail: String::new(),
                    stderr_tail: String::new(),
                }
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                BenchmarkResult::refused(
                    s,
                    format!("metadata workload failed: {e}"),
                    ValidationTier::MountedUserspace,
                )
            }
        }
    }

    /// Smoke run with DEFAULT_METADATA_FILE_COUNT.
    pub fn run_smoke(&self, path: &str) -> BenchmarkResult {
        self.run_baseline(path, DEFAULT_METADATA_FILE_COUNT)
    }
}

/// Run create / stat / rename / unlink on `num_files` files inside `dir`,
/// measuring per-operation latency and throughput.
pub fn run_metadata_workload(dir: &str, num_files: u32) -> Result<MetadataKpis, String> {
    let n = num_files as usize;
    let mut lat_create: Vec<f64> = Vec::with_capacity(n);
    let mut lat_stat: Vec<f64> = Vec::with_capacity(n);
    let mut lat_rename: Vec<f64> = Vec::with_capacity(n);
    let mut lat_unlink: Vec<f64> = Vec::with_capacity(n);

    // —— create ——
    let t0 = Instant::now();
    for i in 0..num_files {
        let p = format!("{dir}/f{i:06}");
        let t = Instant::now();
        std::fs::File::create(&p).map_err(|e| format!("create {p}: {e}"))?;
        lat_create.push(t.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let create_s = t0.elapsed().as_secs_f64();
    let create_ops = if create_s > 0.0 {
        num_files as f64 / create_s
    } else {
        0.0
    };

    // —— stat ——
    let t0 = Instant::now();
    for i in 0..num_files {
        let p = format!("{dir}/f{i:06}");
        let t = Instant::now();
        let _ = std::fs::metadata(&p).map_err(|e| format!("stat {p}: {e}"))?;
        lat_stat.push(t.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let stat_s = t0.elapsed().as_secs_f64();
    let stat_ops = if stat_s > 0.0 {
        num_files as f64 / stat_s
    } else {
        0.0
    };

    // —— rename ——
    let t0 = Instant::now();
    for i in 0..num_files {
        let src = format!("{dir}/f{i:06}");
        let dst = format!("{dir}/r{i:06}");
        let t = Instant::now();
        std::fs::rename(&src, &dst).map_err(|e| format!("rename {src} → {dst}: {e}"))?;
        lat_rename.push(t.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let rename_s = t0.elapsed().as_secs_f64();
    let rename_ops = if rename_s > 0.0 {
        num_files as f64 / rename_s
    } else {
        0.0
    };

    // —— unlink (files now named r000000..r{num_files-1}) ——
    let t0 = Instant::now();
    for i in 0..num_files {
        let p = format!("{dir}/r{i:06}");
        let t = Instant::now();
        std::fs::remove_file(&p).map_err(|e| format!("unlink {p}: {e}"))?;
        lat_unlink.push(t.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let unlink_s = t0.elapsed().as_secs_f64();
    let unlink_ops = if unlink_s > 0.0 {
        num_files as f64 / unlink_s
    } else {
        0.0
    };

    // —— percentiles ——
    lat_create.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    lat_stat.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    lat_rename.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    lat_unlink.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let pct = |v: &[f64], p: f64| -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        let idx = ((p / 100.0) * (v.len() as f64 - 1.0)).round() as usize;
        v[idx.min(v.len() - 1)]
    };

    Ok(MetadataKpis {
        num_files,
        create_ops_per_sec: round2(create_ops),
        create_latency_p50_us: round2(pct(&lat_create, 50.0)),
        create_latency_p95_us: round2(pct(&lat_create, 95.0)),
        create_latency_p99_us: round2(pct(&lat_create, 99.0)),
        stat_ops_per_sec: round2(stat_ops),
        stat_latency_p50_us: round2(pct(&lat_stat, 50.0)),
        stat_latency_p95_us: round2(pct(&lat_stat, 95.0)),
        stat_latency_p99_us: round2(pct(&lat_stat, 99.0)),
        rename_ops_per_sec: round2(rename_ops),
        rename_latency_p50_us: round2(pct(&lat_rename, 50.0)),
        rename_latency_p95_us: round2(pct(&lat_rename, 95.0)),
        rename_latency_p99_us: round2(pct(&lat_rename, 99.0)),
        unlink_ops_per_sec: round2(unlink_ops),
        unlink_latency_p50_us: round2(pct(&lat_unlink, 50.0)),
        unlink_latency_p95_us: round2(pct(&lat_unlink, 95.0)),
        unlink_latency_p99_us: round2(pct(&lat_unlink, 99.0)),
    })
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn metadata_kpis_to_vec(kpis: &MetadataKpis) -> Vec<MeasuredKpi> {
    let s = "mounted-fuse-metadata";
    vec![
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-create-ops"),
            value: kpis.create_ops_per_sec,
            unit: "files/s".into(),
            passed: None,
            percentile: Some("0".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-create-lat-p50"),
            value: kpis.create_latency_p50_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("50".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-create-lat-p95"),
            value: kpis.create_latency_p95_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("95".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-create-lat-p99"),
            value: kpis.create_latency_p99_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("99".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-stat-ops"),
            value: kpis.stat_ops_per_sec,
            unit: "stats/s".into(),
            passed: None,
            percentile: Some("0".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-stat-lat-p50"),
            value: kpis.stat_latency_p50_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("50".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-stat-lat-p95"),
            value: kpis.stat_latency_p95_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("95".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-stat-lat-p99"),
            value: kpis.stat_latency_p99_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("99".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-rename-ops"),
            value: kpis.rename_ops_per_sec,
            unit: "renames/s".into(),
            passed: None,
            percentile: Some("0".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-rename-lat-p50"),
            value: kpis.rename_latency_p50_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("50".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-rename-lat-p95"),
            value: kpis.rename_latency_p95_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("95".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-rename-lat-p99"),
            value: kpis.rename_latency_p99_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("99".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.throughput".into(),
            name: format!("{s}/meta-unlink-ops"),
            value: kpis.unlink_ops_per_sec,
            unit: "unlinks/s".into(),
            passed: None,
            percentile: Some("0".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-unlink-lat-p50"),
            value: kpis.unlink_latency_p50_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("50".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-unlink-lat-p95"),
            value: kpis.unlink_latency_p95_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("95".into()),
        },
        MeasuredKpi {
            ref_id: "kpi.latency".into(),
            name: format!("{s}/meta-unlink-lat-p99"),
            value: kpis.unlink_latency_p99_us,
            unit: "us".into(),
            passed: None,
            percentile: Some("99".into()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_workload_local_tmpdir() {
        let dir = std::env::temp_dir().join("tidefs-meta-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        let kpis = run_metadata_workload(dir.to_str().unwrap(), 64).expect("should succeed");

        assert_eq!(kpis.num_files, 64);
        assert!(kpis.create_ops_per_sec > 0.0);
        assert!(kpis.stat_ops_per_sec > 0.0);
        assert!(kpis.rename_ops_per_sec > 0.0);
        assert!(kpis.unlink_ops_per_sec > 0.0);
        assert!(kpis.create_latency_p50_us <= kpis.create_latency_p95_us);
        assert!(kpis.create_latency_p95_us <= kpis.create_latency_p99_us);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kpi_vec_has_16_entries() {
        let k = MetadataKpis {
            num_files: 1,
            create_ops_per_sec: 1.0,
            stat_ops_per_sec: 2.0,
            rename_ops_per_sec: 3.0,
            unlink_ops_per_sec: 4.0,
            create_latency_p50_us: 10.0,
            create_latency_p95_us: 20.0,
            create_latency_p99_us: 30.0,
            stat_latency_p50_us: 11.0,
            stat_latency_p95_us: 21.0,
            stat_latency_p99_us: 31.0,
            rename_latency_p50_us: 12.0,
            rename_latency_p95_us: 22.0,
            rename_latency_p99_us: 32.0,
            unlink_latency_p50_us: 13.0,
            unlink_latency_p95_us: 23.0,
            unlink_latency_p99_us: 33.0,
        };
        let v = metadata_kpis_to_vec(&k);
        assert_eq!(v.len(), 16);
        for kpi in &v {
            assert!(!kpi.name.is_empty());
        }
    }

    #[test]
    fn harness_refuses_bad_path() {
        let h = MetadataHarness::new("/tmp");
        let res = h.run_baseline("/nonexistent/p/tidefs-meta-harness", 10);
        assert!(!res.executed);
    }

    #[test]
    fn harness_smoke_local_tmpdir() {
        let dir = std::env::temp_dir().join("tidefs-meta-smoke");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        let h = MetadataHarness::new("/tmp");
        let res = h.run_baseline(dir.to_str().unwrap(), 50);
        assert!(res.executed);
        assert!(!res.kpis.is_empty());

        let throughput: Vec<_> = res
            .kpis
            .iter()
            .filter(|k| k.ref_id == "kpi.throughput")
            .collect();
        assert_eq!(throughput.len(), 4);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
