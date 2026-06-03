//! Support bundle and diagnostics collection.
//!
//! Produces a redacted JSON bundle with system metadata, TideFS pool/dataset
//! state, validation summaries, and environment capabilities for
//! operator triage.  Hostnames, IP addresses, and absolute filesystem paths
//! outside the pool are redacted by default.
//!
//! The module is designed to be called from `tidefsctl diag` so that pool-
//! and dataset-specific collection can use the rich dependency set already
//! available to the CLI binary.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Redacted support bundle suitable for operator triage.
///
/// All fields that might contain personally-identifiable or host-identifying
/// information are redacted by default.  The `redacted` flag records whether
/// redaction was applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    /// UTC timestamp in ISO-8601.
    pub collected_at: String,
    /// TideFS version (from the compiling binary).
    pub tidefs_version: String,
    /// Set to `true` when hostnames, IPs, and external paths have been
    /// stripped or replaced with placeholders.
    pub redacted: bool,
    /// Operating system and kernel metadata.
    pub system: SystemInfo,
    /// Build and toolchain information.
    pub build: BuildInfo,
    /// Environment capability checks (FUSE, ublk, kernel module presence).
    pub environment: EnvironmentCapabilities,
    /// Pool-level information filled by the CLI caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<PoolSummary>,
    /// Dataset catalog information filled by the CLI caller.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub datasets: Vec<DatasetSummary>,
    /// Validation summary (counts by tier and status).
    #[serde(default)]
    pub validation_summary: Option<ValidationSummary>,
    /// Arbitrary free-form notes the caller may attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Operating-system and kernel metadata with hostname redacted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system name (e.g. "Linux").
    pub os: String,
    /// OS release string (e.g. "6.13.0").
    pub os_release: String,
    /// Machine architecture (e.g. "x86_64").
    pub architecture: String,
    /// Redacted hostname -- always the literal "redacted".
    pub hostname: String,
    /// System uptime in seconds (best-effort, may be 0 if unavailable).
    pub uptime_secs: u64,
}

/// Build and toolchain information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    /// Rust compiler version.
    pub rustc_version: String,
    /// Cargo version.
    pub cargo_version: String,
    /// TideFS workspace version.
    pub tidefs_version: String,
    /// Git commit hash at build time (may be "unknown").
    pub git_commit: String,
    /// Build profile ("debug" or "release").
    pub profile: String,
}

/// Environment capabilities detected at collection time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentCapabilities {
    /// Whether `/dev/fuse` exists and appears readable.
    pub fuse_available: bool,
    /// Whether `/dev/ublk-control` exists.
    pub ublk_available: bool,
    /// Whether `/dev/kvm` exists.
    pub kvm_available: bool,
    /// Whether an RDMA device was detected (best-effort).
    pub rdma_available: bool,
    /// Additional capability notes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Summary of a single TideFS pool (filled by CLI caller).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSummary {
    /// Pool name.
    pub name: String,
    /// Pool GUID as hex.
    pub guid: String,
    /// Pool state label.
    pub state: String,
    /// Number of known member devices.
    pub device_count: usize,
    /// Committed root count found.
    pub committed_root_count: usize,
    /// Top-level committed root TXG (best-effort).
    pub latest_txg: Option<u64>,
}

/// Summary of a single dataset (filled by CLI caller).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSummary {
    /// Dataset name.
    pub name: String,
    /// Dataset ID as hex.
    pub id: String,
    /// Dataset type label.
    pub dataset_type: String,
    /// Current lifecycle state.
    pub state: String,
    /// Flags set on the dataset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

/// Validation count summary classified by tier and status.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationSummary {
    /// Total validation rows tracked.
    pub total_rows: usize,
    /// Counts per status label.
    pub by_status: BTreeMap<String, usize>,
    /// Counts per tier label.
    pub by_tier: BTreeMap<String, usize>,
}

// ---------------------------------------------------------------------------
// Collection helpers
// ---------------------------------------------------------------------------

/// Collect system information with hostname always redacted.
///
/// On Linux this reads `/proc/version` and `/proc/uptime`.
/// Falls back to compile-time constants on other platforms.
pub fn collect_system_info() -> SystemInfo {
    let os_release = read_first_line("/proc/version").unwrap_or_else(|| "unknown".to_string());
    let architecture = std::env::consts::ARCH.to_string();

    let uptime_secs = read_first_line("/proc/uptime")
        .and_then(|line| line.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as u64)
        .unwrap_or(0);

    SystemInfo {
        os: "Linux".to_string(),
        os_release,
        architecture,
        hostname: "redacted".to_string(),
        uptime_secs,
    }
}

/// Collect build information using compile-time environment variables.
///
/// Callers can override `git_commit` via the `TIDEFS_GIT_COMMIT` env var at
/// build time.
pub fn collect_build_info() -> BuildInfo {
    let rustc_version = option_env!("RUSTC_VERSION")
        .unwrap_or("unknown")
        .to_string();
    let cargo_version = option_env!("CARGO_VERSION")
        .unwrap_or("unknown")
        .to_string();
    let tidefs_version = option_env!("CARGO_PKG_VERSION")
        .unwrap_or("unknown")
        .to_string();
    let git_commit = option_env!("TIDEFS_GIT_COMMIT")
        .unwrap_or("unknown")
        .to_string();
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
    .to_string();

    BuildInfo {
        rustc_version,
        cargo_version,
        tidefs_version,
        git_commit,
        profile,
    }
}

/// Check environment capabilities (FUSE, ublk, KVM, RDMA).
pub fn collect_environment_capabilities() -> EnvironmentCapabilities {
    let fuse_available = std::path::Path::new("/dev/fuse").exists();
    let ublk_available = std::path::Path::new("/dev/ublk-control").exists();
    let kvm_available = std::path::Path::new("/dev/kvm").exists();

    // Best-effort RDMA detection: check for any /dev/infiniband device.
    let rdma_available = std::fs::read_dir("/dev/infiniband")
        .map(|mut dir| dir.any(|e| e.is_ok()))
        .unwrap_or(false);

    let mut notes = Vec::new();
    if !fuse_available {
        notes.push("/dev/fuse not found -- FUSE not available".to_string());
    }
    if !ublk_available {
        notes.push("/dev/ublk-control not found -- ublk not available".to_string());
    }
    if !kvm_available {
        notes.push("/dev/kvm not found -- QEMU/KVM not available".to_string());
    }
    if !rdma_available {
        notes.push("/dev/infiniband not found -- RDMA not available".to_string());
    }

    EnvironmentCapabilities {
        fuse_available,
        ublk_available,
        kvm_available,
        rdma_available,
        notes,
    }
}

/// Create a new support bundle with system, build, and environment sections
/// populated.  Pool, dataset, and validation summaries must be filled by the
/// caller before serialization.
pub fn new_support_bundle() -> SupportBundle {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let collected_at = format_iso8601(now.as_secs());

    SupportBundle {
        collected_at,
        tidefs_version: option_env!("CARGO_PKG_VERSION")
            .unwrap_or("unknown")
            .to_string(),
        redacted: true,
        system: collect_system_info(),
        build: collect_build_info(),
        environment: collect_environment_capabilities(),
        pools: Vec::new(),
        datasets: Vec::new(),
        validation_summary: None,
        notes: None,
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize the bundle as pretty-printed JSON and write to `path`.
pub fn write_bundle_json(bundle: &SupportBundle, path: &std::path::Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(bundle).map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_first_line(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.lines().next().unwrap_or("").to_string())
}

fn format_iso8601(unix_secs: u64) -> String {
    let secs = (unix_secs % 86400) as u32;
    let days = (unix_secs / 86400) as u32;
    let (y, m, d) = civil_from_days(days);
    let h = secs / 3600;
    let mi = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
/// Algorithm from Howard Hinnant's chrono-compatible date computation.
fn civil_from_days(days: u32) -> (u32, u32, u32) {
    let z = days.wrapping_add(719468);
    let era = z / 146097;
    let doe = z.wrapping_sub(era.wrapping_mul(146097));
    let yoe = (doe
        .wrapping_sub(doe / 1460)
        .wrapping_add(doe / 36524)
        .wrapping_sub(doe / 146096))
        / 365;
    let y = yoe.wrapping_add(era.wrapping_mul(400));
    let doy = doe.wrapping_sub(365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy.wrapping_sub((153 * mp + 2) / 5).wrapping_add(1);
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_bundle_has_redacted_hostname() {
        let bundle = new_support_bundle();
        assert_eq!(bundle.system.hostname, "redacted");
        assert!(bundle.redacted);
    }

    #[test]
    fn collect_environment_capabilities_returns_booleans() {
        let caps = collect_environment_capabilities();
        let _ = caps.fuse_available;
        let _ = caps.ublk_available;
        let _ = caps.kvm_available;
        let _ = caps.rdma_available;
    }

    #[test]
    fn write_and_roundtrip_json() {
        let mut bundle = new_support_bundle();
        bundle.pools.push(PoolSummary {
            name: "testpool".to_string(),
            guid: "deadbeef".to_string(),
            state: "active".to_string(),
            device_count: 2,
            committed_root_count: 1,
            latest_txg: Some(42),
        });
        bundle.datasets.push(DatasetSummary {
            name: "root".to_string(),
            id: "cafe".to_string(),
            dataset_type: "filesystem".to_string(),
            state: "active".to_string(),
            flags: vec!["encryption".to_string()],
        });
        bundle.validation_summary = Some(ValidationSummary {
            total_rows: 10,
            by_status: {
                let mut m = BTreeMap::new();
                m.insert("PASS".to_string(), 8);
                m.insert("SKIP".to_string(), 2);
                m
            },
            by_tier: {
                let mut m = BTreeMap::new();
                m.insert("cargo-unit".to_string(), 10);
                m
            },
        });

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.json");
        write_bundle_json(&bundle, &path).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        let round: SupportBundle = serde_json::from_str(&raw).unwrap();
        assert_eq!(round.pools.len(), 1);
        assert_eq!(round.pools[0].name, "testpool");
        assert_eq!(round.datasets.len(), 1);
        assert_eq!(round.validation_summary.unwrap().total_rows, 10);
    }

    #[test]
    fn iso8601_format_epoch() {
        let s = format_iso8601(0);
        assert_eq!(s, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_format_known_date() {
        // 2026-05-24T12:00:00Z
        // 2026-01-01 is 56 years after 1970 (14 leap days in 1972-2024)
        // Days from 1970 to 2026-01-01: 56*365 + 14 = 20454
        // Day of year for May 24: 31+28+31+30+23 = 143
        // Total days: 20454 + 143 = 20597
        let unix = 20597u64 * 86400 + 12 * 3600;
        let s = format_iso8601(unix);
        assert_eq!(s, "2026-05-24T12:00:00Z");
    }
}
