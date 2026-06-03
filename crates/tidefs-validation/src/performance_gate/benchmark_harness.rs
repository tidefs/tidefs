use super::validation_tier::ValidationTier;
use super::gate_entry::{BudgetDecision, MeasuredKpi};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub subject: String,
    pub description: String,
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub duration_secs: f64,
    pub kpis: Vec<MeasuredKpi>,
    pub validation_tier: ValidationTier,
    pub stdout_tail: String,
    pub stderr_tail: String,
}
impl BenchmarkResult {
    pub fn refused(
        subject: impl Into<String>,
        reason: impl Into<String>,
        tier: ValidationTier,
    ) -> Self {
        BenchmarkResult {
            subject: subject.into(),
            description: reason.into(),
            executed: false,
            exit_code: None,
            duration_secs: 0.0,
            kpis: Vec::new(),
            validation_tier: tier,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
        }
    }
    pub fn budget_decision(&self) -> BudgetDecision {
        if !self.executed {
            return BudgetDecision::Refuse;
        }
        if self.exit_code != Some(0) {
            return BudgetDecision::Fail;
        }
        if self.kpis.iter().any(|k| k.passed == Some(false)) {
            return BudgetDecision::Fail;
        }
        BudgetDecision::Pass
    }
    pub fn verdict(&self) -> super::runner::RunVerdict {
        match self.budget_decision() {
            BudgetDecision::Pass => super::runner::RunVerdict::Passed,
            BudgetDecision::Fail => super::runner::RunVerdict::Failed,
            BudgetDecision::Refuse => super::runner::RunVerdict::Refused,
        }
    }
}

pub struct CriterionHarness {
    pub repo_root: String,
    pub target_dir: String,
}
impl CriterionHarness {
    pub fn new(repo_root: impl Into<String>, target_dir: impl Into<String>) -> Self {
        CriterionHarness {
            repo_root: repo_root.into(),
            target_dir: target_dir.into(),
        }
    }
    pub fn run(
        &self,
        subject: impl Into<String>,
        crate_name: &str,
        bench_name: &str,
        tier: ValidationTier,
    ) -> BenchmarkResult {
        let s = subject.into();
        let st = Instant::now();
        let res = Command::new("cargo")
            .arg("bench")
            .arg("-p")
            .arg(crate_name)
            .arg("--bench")
            .arg(bench_name)
            .arg("--")
            .arg("--output-format")
            .arg("bencher")
            .env("CARGO_TARGET_DIR", &self.target_dir)
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(&self.repo_root)
            .output();
        let el = st.elapsed().as_secs_f64();
        match res {
            Ok(o) => {
                let so = String::from_utf8_lossy(&o.stdout).to_string();
                let se = String::from_utf8_lossy(&o.stderr).to_string();
                BenchmarkResult {
                    subject: s.clone(),
                    description: format!("cargo bench -p {crate_name} --bench {bench_name}"),
                    executed: true,
                    exit_code: Some(o.status.code().unwrap_or(-1)),
                    duration_secs: el,
                    kpis: parse_criterion(&so, &s),
                    validation_tier: tier,
                    stdout_tail: tail(&so, 500),
                    stderr_tail: tail(&se, 200),
                }
            }
            Err(e) => BenchmarkResult::refused(s, format!("cargo bench failed: {e}"), tier),
        }
    }
}

pub struct FioHarness {
    pub repo_root: String,
}
impl FioHarness {
    pub fn new(repo_root: impl Into<String>) -> Self {
        FioHarness {
            repo_root: repo_root.into(),
        }
    }
    pub fn run(
        &self,
        subject: impl Into<String>,
        mode: &str,
        target: &str,
        profile: &str,
        tier: ValidationTier,
    ) -> BenchmarkResult {
        let s = subject.into();
        let scr = format!("{}/benchmarking/fio/run-benchmarks.sh", self.repo_root);
        let st = Instant::now();
        let res = Command::new("bash")
            .arg(&scr)
            .arg(mode)
            .arg(target)
            .arg(profile)
            .current_dir(&self.repo_root)
            .output();
        let el = st.elapsed().as_secs_f64();
        match res {
            Ok(o) => {
                let so = String::from_utf8_lossy(&o.stdout).to_string();
                let se = String::from_utf8_lossy(&o.stderr).to_string();
                BenchmarkResult {
                    subject: s.clone(),
                    description: format!("fio {mode} {target} {profile}"),
                    executed: true,
                    exit_code: Some(o.status.code().unwrap_or(-1)),
                    duration_secs: el,
                    kpis: parse_fio(&so, &s),
                    validation_tier: tier,
                    stdout_tail: tail(&so, 500),
                    stderr_tail: tail(&se, 200),
                }
            }
            Err(e) => BenchmarkResult::refused(s, format!("fio failed: {e}"), tier),
        }
    }
}

fn parse_criterion(stdout: &str, subject: &str) -> Vec<MeasuredKpi> {
    let mut kps = Vec::new();
    for l in stdout.lines() {
        if !l.starts_with("test ") {
            continue;
        }
        if let Some(p) = l.find(" bench:") {
            let bn = l[5..p].trim().trim_end_matches('.').trim();
            let rest = l[p + 7..].trim();
            if let Some(sl) = rest.find('/') {
                let mut pts = rest[..sl].split_whitespace();
                let ns = pts.next().unwrap_or("0");
                let u = pts.next().unwrap_or("?");
                if let Ok(v) = ns.replace('_', "").parse::<f64>() {
                    let fu = if u == "ns" {
                        "ns/iter"
                    } else if u == "us" || u == "µs" {
                        "µs/iter"
                    } else if u == "ms" {
                        "ms/iter"
                    } else if u == "s" {
                        "s/iter"
                    } else {
                        u
                    };
                    kps.push(MeasuredKpi {
                        ref_id: format!("kpi.latency.{bn}"),
                        name: format!("{subject}/{bn}"),
                        value: v,
                        unit: fu.to_string(),
                        passed: None,
                        percentile: None,
                    });
                }
            }
        }
    }
    kps
}

fn parse_fio(stdout: &str, subject: &str) -> Vec<MeasuredKpi> {
    let mut kps = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(jobs) = v.get("jobs").and_then(|j| j.as_array()) {
            for job in jobs {
                let jn = job.get("jobname").and_then(|n| n.as_str()).unwrap_or("fio");
                if let Some(r) = job.get("read") {
                    if let Some(io) = r.get("iops").and_then(|v| v.as_f64()) {
                        kps.push(MeasuredKpi {
                            ref_id: "kpi.throughput".into(),
                            name: format!("{subject}/{jn}-riops"),
                            value: io,
                            unit: "iops".into(),
                            passed: None,
                            percentile: None,
                        });
                    }
                }
                if let Some(w) = job.get("write") {
                    if let Some(io) = w.get("iops").and_then(|v| v.as_f64()) {
                        kps.push(MeasuredKpi {
                            ref_id: "kpi.throughput".into(),
                            name: format!("{subject}/{jn}-wiops"),
                            value: io,
                            unit: "iops".into(),
                            passed: None,
                            percentile: None,
                        });
                    }
                }
            }
        }
        return kps;
    }
    for l in stdout.lines() {
        if let Some(p) = l.find("IOPS=") {
            let a = &l[p + 5..];
            if let Some(c) = a.find(',') {
                if let Ok(k) = a[..c].replace('k', "").parse::<f64>() {
                    let av = if a[..c].contains('k') { k * 1000.0 } else { k };
                    kps.push(MeasuredKpi {
                        ref_id: "kpi.throughput".into(),
                        name: format!("{subject}/fiops"),
                        value: av,
                        unit: "iops".into(),
                        passed: None,
                        percentile: None,
                    });
                }
            }
        }
    }
    kps
}

fn tail(s: &str, m: usize) -> String {
    if s.len() <= m {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - m..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refused() {
        let r = BenchmarkResult::refused("f", "n", ValidationTier::QemuGuest);
        assert!(!r.executed);
        assert_eq!(r.budget_decision(), BudgetDecision::Refuse);
    }
    #[test]
    fn criterion_parse() {
        let k=parse_criterion("test fs/cf ... bench: 1_234 ns/iter (+/- 123)\ntest os/ps ... bench: 567 ns/iter (+/- 89)\n","fs");
        assert_eq!(k.len(), 2);
        assert_eq!(k[0].value, 1234.0);
    }
    #[test]
    fn criterion_ms() {
        let k = parse_criterion("test s/o ... bench: 250 ms/iter (+/- 10)\n", "s");
        assert_eq!(k[0].value, 250.0);
        assert_eq!(k[0].unit, "ms/iter");
    }
    #[test]
    fn criterion_empty() {
        assert!(parse_criterion("", "t").is_empty());
    }
    #[test]
    fn fio_json() {
        let k = parse_fio(
            r#"{"jobs":[{"jobname":"rr","read":{"iops":12345.6}}]}"#,
            "fuse",
        );
        assert!(!k.is_empty());
    }
    #[test]
    fn fio_text() {
        let k = parse_fio("  read: IOPS=12.3k, BW=98.4MiB/s, ...", "u");
        assert_eq!(
            k.iter().find(|x| x.name.contains("fiops")).unwrap().value,
            12300.0
        );
    }
    #[test]
    fn tail_trunc() {
        assert!(tail(&"x".repeat(1000), 100).starts_with("..."));
    }
    #[test]
    fn tail_no() {
        assert_eq!(tail("s", 100), "s");
    }
}

// ── UblkFioHarness ──────────────────────────────────────────────────
// Queue-depth latency budget harness for ublk block devices.
// Runs fio at varying iodepths and captures latency/throughput KPIs.

/// Queue-depth latency measurement harness for ublk block devices.
///
/// Runs a randrw (70/30) fio workload at six queue depths (1, 4, 8, 16, 32,
/// 64) and collects per-depth latency percentiles (p50, p95, p99) plus total
/// throughput in MiB/s.  Each depth produces KPIs suitable for the
/// `block_random_queue` budget class (r3: p99 <= 25 ms).
pub struct UblkFioHarness {
    /// Path to the ublk block device (e.g. `/dev/ublkb0`).
    pub device_path: String,
    /// Path to the fio binary (default: `"fio"` from `$PATH`).
    pub fio_bin: String,
    /// Queue depths to test.
    pub iodepths: Vec<u32>,
}

impl UblkFioHarness {
    /// Create a new harness targeting `device_path` with defaults.
    #[must_use]
    pub fn new(device_path: impl Into<String>) -> Self {
        Self {
            device_path: device_path.into(),
            fio_bin: "fio".to_string(),
            iodepths: vec![1, 4, 8, 16, 32, 64],
        }
    }

    /// Override the fio binary path.
    pub fn with_fio_bin(mut self, path: &str) -> Self {
        self.fio_bin = path.to_string();
        self
    }

    /// Override the queue depths to test.
    pub fn with_iodepths(mut self, depths: Vec<u32>) -> Self {
        self.iodepths = depths;
        self
    }

    /// Run the queue-depth latency budget measurement.
    ///
    /// Returns a [`BenchmarkResult`] with per-depth latency/throughput KPIs.
    /// If the device does not exist or fio is not found, returns a refused
    /// result with the exact reason.
    pub fn run(&self, subject: &str) -> BenchmarkResult {
        let tier = ValidationTier::QemuGuest;

        if !Path::new(&self.device_path).exists() {
            return BenchmarkResult::refused(
                subject,
                format!("ublk device not found at {}", self.device_path),
                tier,
            );
        }

        // Check that fio is available.
        let fio_check = Command::new(&self.fio_bin).arg("--version").output();
        if fio_check.is_err() {
            return BenchmarkResult::refused(
                subject,
                format!("fio binary not found: {}", self.fio_bin),
                tier,
            );
        }

        let started = Instant::now();
        let mut all_kpis: Vec<MeasuredKpi> = Vec::new();
        let mut all_passed = true;
        let mut errors: Vec<String> = Vec::new();

        for &qd in &self.iodepths {
            let kpi_prefix = format!("{subject}/qd{qd}");

            // Run fio: randrw 70/30, direct I/O, 4k blocks, 2M job size
            let output = Command::new(&self.fio_bin)
                .arg("--name=ublk-qd")
                .arg("--rw=randrw")
                .arg("--rwmixread=70")
                .arg("--size=2M")
                .arg("--direct=1")
                .arg("--bs=4k")
                .arg("--iodepth")
                .arg(qd.to_string())
                .arg("--filename")
                .arg(&self.device_path)
                .arg("--output-format=json")
                .arg("--end_fsync=1")
                .output();

            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                    let stderr = String::from_utf8_lossy(&o.stderr).to_string();

                    if !o.status.success() {
                        all_passed = false;
                        errors.push(format!("fio qd={} exited {}: {}", qd, o.status, stderr));
                        continue;
                    }

                    match parse_fio_json_depth(&stdout, &kpi_prefix, qd) {
                        Ok(mut kpis) => {
                            all_kpis.append(&mut kpis);
                        }
                        Err(e) => {
                            all_passed = false;
                            errors.push(format!("fio qd={qd} parse: {e}"));
                        }
                    }
                }
                Err(e) => {
                    all_passed = false;
                    errors.push(format!("fio qd={qd} spawn: {e}"));
                }
            }
        }

        let elapsed = started.elapsed().as_secs_f64();
        let desc = format!(
            "ublk queue-depth latency budget: {} depths (1-64) on {}",
            self.iodepths.len(),
            self.device_path
        );

        if !all_passed {
            let reason = errors.join("; ");
            BenchmarkResult {
                subject: subject.to_string(),
                description: format!("{desc} -- partial failure: {reason}"),
                executed: true,
                exit_code: Some(1),
                duration_secs: elapsed,
                kpis: all_kpis,
                validation_tier: tier,
                stdout_tail: String::new(),
                stderr_tail: reason,
            }
        } else {
            BenchmarkResult {
                subject: subject.to_string(),
                description: desc,
                executed: true,
                exit_code: Some(0),
                duration_secs: elapsed,
                kpis: all_kpis,
                validation_tier: tier,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            }
        }
    }
    /// Run flush/FUA overhead measurement against the ublk block device.
    ///
    /// Runs three fio write phases and compares latency to isolate fsync and
    /// FUA overhead: plain writes (no sync), fsync-after-each-write, and
    /// FUA writes. Each phase uses direct I/O, 4 KiB blocks, 2 MiB job size,
    /// and single-queue-depth to measure per-operation latency.
    ///
    /// Returns KPIs: plain write p50/p95/p99 latency, fsync write latency,
    /// FUA write latency, and write IOPS for each phase.
    pub fn run_flush_fua(&self, subject: &str) -> BenchmarkResult {
        let tier = ValidationTier::QemuGuest;

        if !Path::new(&self.device_path).exists() {
            return BenchmarkResult::refused(
                subject,
                format!("ublk device not found at {}", self.device_path),
                tier,
            );
        }

        let fio_check = Command::new(&self.fio_bin).arg("--version").output();
        if fio_check.is_err() {
            return BenchmarkResult::refused(
                subject,
                format!("fio binary not found: {}", self.fio_bin),
                tier,
            );
        }

        let started = Instant::now();
        let mut all_kpis: Vec<MeasuredKpi> = Vec::new();
        let mut all_passed = true;
        let mut errors: Vec<String> = Vec::new();

        // Phase 1: plain writes (no fsync, no FUA) - baseline
        let plain_out = Command::new(&self.fio_bin)
            .arg("--name=ublk-flushfua-plain")
            .arg("--rw=randwrite")
            .arg("--size=2M")
            .arg("--direct=1")
            .arg("--bs=4k")
            .arg("--iodepth=1")
            .arg("--filename")
            .arg(&self.device_path)
            .arg("--output-format=json")
            .arg("--end_fsync=1")
            .output();

        match plain_out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if !o.status.success() {
                    all_passed = false;
                    errors.push(format!("plain-write fio exited {}: {}", o.status, stderr));
                } else {
                    match parse_fio_flush_fua_latency(
                        &stdout,
                        &format!("{subject}/flushfua"),
                        "plain_write",
                    ) {
                        Ok(mut kpis) => all_kpis.append(&mut kpis),
                        Err(e) => {
                            all_passed = false;
                            errors.push(format!("plain-write parse: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                all_passed = false;
                errors.push(format!("plain-write spawn: {e}"));
            }
        }

        // Phase 2: fsync writes (fsync after each write block)
        let fsync_out = Command::new(&self.fio_bin)
            .arg("--name=ublk-flushfua-fsync")
            .arg("--rw=randwrite")
            .arg("--size=2M")
            .arg("--direct=1")
            .arg("--bs=4k")
            .arg("--iodepth=1")
            .arg("--fsync=1")
            .arg("--filename")
            .arg(&self.device_path)
            .arg("--output-format=json")
            .output();

        match fsync_out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if !o.status.success() {
                    all_passed = false;
                    errors.push(format!("fsync-write fio exited {}: {}", o.status, stderr));
                } else {
                    match parse_fio_flush_fua_latency(
                        &stdout,
                        &format!("{subject}/flushfua"),
                        "fsync_write",
                    ) {
                        Ok(mut kpis) => all_kpis.append(&mut kpis),
                        Err(e) => {
                            all_passed = false;
                            errors.push(format!("fsync-write parse: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                all_passed = false;
                errors.push(format!("fsync-write spawn: {e}"));
            }
        }

        // Phase 3: FUA writes (force unit access)
        let fua_out = Command::new(&self.fio_bin)
            .arg("--name=ublk-flushfua-fua")
            .arg("--rw=write")
            .arg("--size=2M")
            .arg("--direct=1")
            .arg("--bs=4k")
            .arg("--iodepth=1")
            .arg("--fua=1")
            .arg("--filename")
            .arg(&self.device_path)
            .arg("--output-format=json")
            .output();

        match fua_out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout).to_string();
                let stderr = String::from_utf8_lossy(&o.stderr).to_string();
                if !o.status.success() {
                    all_passed = false;
                    errors.push(format!("fua-write fio exited {}: {}", o.status, stderr));
                } else {
                    match parse_fio_flush_fua_latency(
                        &stdout,
                        &format!("{subject}/flushfua"),
                        "fua_write",
                    ) {
                        Ok(mut kpis) => all_kpis.append(&mut kpis),
                        Err(e) => {
                            all_passed = false;
                            errors.push(format!("fua-write parse: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                all_passed = false;
                errors.push(format!("fua-write spawn: {e}"));
            }
        }

        let elapsed = started.elapsed().as_secs_f64();
        let desc = format!(
            "ublk flush/FUA overhead measurement on {} (plain+fsync+fua writes)",
            self.device_path
        );

        if !all_passed {
            let reason = errors.join("; ");
            BenchmarkResult {
                subject: subject.to_string(),
                description: format!("{desc} -- partial failure: {reason}"),
                executed: true,
                exit_code: Some(1),
                duration_secs: elapsed,
                kpis: all_kpis,
                validation_tier: tier,
                stdout_tail: String::new(),
                stderr_tail: reason,
            }
        } else {
            BenchmarkResult {
                subject: subject.to_string(),
                description: desc,
                executed: true,
                exit_code: Some(0),
                duration_secs: elapsed,
                kpis: all_kpis,
                validation_tier: tier,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
            }
        }
    }

    /// Run the full baseline: queue-depth latency budget and flush/FUA overhead.
    ///
    /// Returns a vector of two [`BenchmarkResult`]s: queue-depth latency from
    /// [`run`] and flush/FUA overhead from [`run_flush_fua`].
    pub fn run_full_baseline(&self, subject: &str) -> Vec<BenchmarkResult> {
        vec![
            self.run(&format!("{subject}/qd-latency")),
            self.run_flush_fua(&format!("{subject}/flush-fua")),
        ]
    }
}

/// Parse fio JSON output for a single queue-depth run, extracting latency
/// percentiles (p50, p95, p99) and total throughput (MiB/s).
fn parse_fio_json_depth(
    stdout: &str,
    kpi_prefix: &str,
    qd: u32,
) -> Result<Vec<MeasuredKpi>, String> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).map_err(|e| format!("json parse: {e}"))?;

    let jobs = v
        .get("jobs")
        .and_then(|j| j.as_array())
        .ok_or("no jobs array in fio output")?;

    if jobs.is_empty() {
        return Err("empty jobs array".to_string());
    }

    let job = &jobs[0];
    let mut kpis = Vec::new();

    // Extract latency percentiles (nanoseconds -> microseconds).
    if let Some(lat_ns) = job.get("lat_ns") {
        let percentiles = lat_ns.get("percentile").and_then(|p| p.as_object());
        if let Some(pct_obj) = percentiles {
            // p50
            if let Some(serde_json::Value::Number(n)) = pct_obj.get("50.000000") {
                let us = n.as_f64().unwrap_or(0.0) / 1000.0;
                kpis.push(MeasuredKpi {
                    ref_id: format!("kpi.latency.p50.qd{qd}"),
                    name: format!("{kpi_prefix}/p50_us"),
                    value: (us * 100.0).round() / 100.0,
                    unit: "us".to_string(),
                    passed: None,
                    percentile: Some("p50".to_string()),
                });
            }
            // p95
            if let Some(serde_json::Value::Number(n)) = pct_obj.get("95.000000") {
                let us = n.as_f64().unwrap_or(0.0) / 1000.0;
                kpis.push(MeasuredKpi {
                    ref_id: format!("kpi.latency.p95.qd{qd}"),
                    name: format!("{kpi_prefix}/p95_us"),
                    value: (us * 100.0).round() / 100.0,
                    unit: "us".to_string(),
                    passed: Some(us <= 25000.0),
                    percentile: Some("p95".to_string()),
                });
            }
            // p99
            if let Some(serde_json::Value::Number(n)) = pct_obj.get("99.000000") {
                let us = n.as_f64().unwrap_or(0.0) / 1000.0;
                kpis.push(MeasuredKpi {
                    ref_id: format!("kpi.latency.p99.qd{qd}"),
                    name: format!("{kpi_prefix}/p99_us"),
                    value: (us * 100.0).round() / 100.0,
                    unit: "us".to_string(),
                    passed: Some(us <= 25000.0),
                    percentile: Some("p99".to_string()),
                });
            }
        }
    }

    // Extract throughput: sum of read + write bw_bytes, convert to MiB/s.
    let read_bw = job
        .get("read")
        .and_then(|r| r.get("bw_bytes"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let write_bw = job
        .get("write")
        .and_then(|w| w.get("bw_bytes"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let bw_mb_s = (read_bw + write_bw) / (1024.0 * 1024.0);

    kpis.push(MeasuredKpi {
        ref_id: format!("kpi.throughput.qd{qd}"),
        name: format!("{kpi_prefix}/bw_mb_s"),
        value: (bw_mb_s * 100.0).round() / 100.0,
        unit: "MiB/s".to_string(),
        passed: None,
        percentile: None,
    });

    Ok(kpis)
}

/// Parse fio JSON output from a flush/FUA phase, extracting write latency
/// percentiles (p50, p95, p99) as microsecond KPIs and write IOPS.
fn parse_fio_flush_fua_latency(
    stdout: &str,
    kpi_prefix: &str,
    phase_name: &str,
) -> Result<Vec<MeasuredKpi>, String> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).map_err(|e| format!("json parse: {e}"))?;

    let jobs = v
        .get("jobs")
        .and_then(|j| j.as_array())
        .ok_or("no jobs array in fio output")?;

    if jobs.is_empty() {
        return Err("empty jobs array".to_string());
    }

    let job = &jobs[0];
    let mut kpis = Vec::new();

    // Extract write latency percentiles (nanoseconds -> microseconds).
    if let Some(lat_ns) = job.get("lat_ns") {
        let percentiles = lat_ns.get("percentile").and_then(|p| p.as_object());
        if let Some(pct_obj) = percentiles {
            for (pct_key, pct_label) in &[
                ("50.000000", "p50"),
                ("95.000000", "p95"),
                ("99.000000", "p99"),
            ] {
                if let Some(serde_json::Value::Number(n)) = pct_obj.get(*pct_key) {
                    let us = n.as_f64().unwrap_or(0.0) / 1000.0;
                    kpis.push(MeasuredKpi {
                        ref_id: format!("kpi.flushfua.latency.{phase_name}.{pct_label}"),
                        name: format!("{kpi_prefix}/{phase_name}-{pct_label}_us"),
                        value: (us * 100.0).round() / 100.0,
                        unit: "us".to_string(),
                        passed: None,
                        percentile: Some(pct_label.to_string()),
                    });
                }
            }
        }
    }

    // Extract write IOPS.
    if let Some(w) = job.get("write") {
        if let Some(iops) = w.get("iops").and_then(|v| v.as_f64()) {
            kpis.push(MeasuredKpi {
                ref_id: format!("kpi.flushfua.iops.{phase_name}"),
                name: format!("{kpi_prefix}/{phase_name}-wiops"),
                value: (iops * 100.0).round() / 100.0,
                unit: "iops".to_string(),
                passed: None,
                percentile: None,
            });
        }
    }

    Ok(kpis)
}

#[cfg(test)]
mod ublk_fio_tests {
    use super::*;

    #[test]
    fn harness_new_sets_defaults() {
        let h = UblkFioHarness::new("/dev/ublkb0");
        assert_eq!(h.device_path, "/dev/ublkb0");
        assert_eq!(h.fio_bin, "fio");
        assert_eq!(h.iodepths, vec![1, 4, 8, 16, 32, 64]);
    }

    #[test]
    fn harness_run_refuses_missing_device() {
        let h = UblkFioHarness::new("/nonexistent/ublkb99");
        let result = h.run("ublk-direct");
        assert!(!result.executed);
        assert!(result.description.contains("not found"));
    }

    #[test]
    fn parse_fio_json_empty_returns_error() {
        let result = parse_fio_json_depth("{}", "test", 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_fio_json_no_latency_still_gives_throughput() {
        let json = r#"{
            "jobs": [{
                "jobname": "test",
                "read": {"bw_bytes": 52428800},
                "write": {"bw_bytes": 26214400}
            }]
        }"#;
        let kpis = parse_fio_json_depth(json, "test/qd1", 1).expect("parse");
        let tp = kpis.iter().find(|k| k.unit == "MiB/s");
        assert!(tp.is_some());
        assert!((tp.unwrap().value - 75.0).abs() < 0.1);
    }

    #[test]
    fn run_flush_fua_refuses_missing_device() {
        let h = UblkFioHarness::new("/nonexistent/ublkb99");
        let result = h.run_flush_fua("ublk-ff");
        assert!(!result.executed);
        assert!(result.description.contains("not found"));
    }

    #[test]
    fn parse_flush_fua_empty_json_returns_error() {
        let result = parse_fio_flush_fua_latency("{}", "test", "plain_write");
        assert!(result.is_err());
    }

    #[test]
    fn parse_flush_fua_extracts_latency_and_iops() {
        let json = r#"{
            "jobs": [{
                "jobname": "test",
                "lat_ns": {
                    "percentile": {
                        "50.000000": 50000,
                        "95.000000": 200000,
                        "99.000000": 1000000
                    }
                },
                "write": {"iops": 1234.5}
            }]
        }"#;
        let kpis = parse_fio_flush_fua_latency(json, "ublk/ff", "plain_write").expect("parse");
        assert!(
            kpis.len() >= 4,
            "expected at least 4 KPIs, got {}",
            kpis.len()
        );

        let p50 = kpis.iter().find(|k| k.percentile.as_deref() == Some("p50"));
        assert!(p50.is_some());
        assert!((p50.unwrap().value - 50.0).abs() < 0.1);

        let p99 = kpis.iter().find(|k| k.percentile.as_deref() == Some("p99"));
        assert!(p99.is_some());
        assert!((p99.unwrap().value - 1000.0).abs() < 0.1);

        let iops = kpis.iter().find(|k| k.unit == "iops");
        assert!(iops.is_some());
        assert!((iops.unwrap().value - 1234.5).abs() < 0.1);
    }

    #[test]
    fn run_full_baseline_returns_two_results() {
        let h = UblkFioHarness::new("/nonexistent/ublkb99");
        let results = h.run_full_baseline("ublk-baseline");
        assert_eq!(results.len(), 2);
        assert!(!results[0].executed); // missing device
        assert!(!results[1].executed); // missing device
    }
}
