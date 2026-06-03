//! `tidefsctl diag` -- support bundle and diagnostics command.
//!
//! Collects a redacted support bundle with system information, environment
//! capabilities, and validation summaries, then writes it as JSON
//! to a timestamped file.  Pool and dataset sections are populated only when
//! the caller provides device paths.

use std::path::PathBuf;
use std::process;

use tidefs_validation::support_bundle::{self, ValidationSummary};

/// Handle the `tidefsctl diag` subcommand.
pub fn handle_diag(output_dir: Option<PathBuf>, device_paths: &[PathBuf]) {
    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));

    let mut bundle = support_bundle::new_support_bundle();

    // Optionally populate pool summaries when device paths are given.
    if !device_paths.is_empty() {
        if let Some(pool) = collect_pool_from_devices(device_paths) {
            bundle.pools.push(pool);
        }
    }

    // Populate validation summary with tier/status taxonomy.
    bundle.validation_summary = Some(build_validation_summary());

    let timestamp = &bundle.collected_at;
    let filename = format!("tidefs-diag-{timestamp}.json").replace(':', "-");
    let output_path = output_dir.join(&filename);

    match support_bundle::write_bundle_json(&bundle, &output_path) {
        Ok(()) => {
            eprintln!(
                "tidefsctl diag: support bundle written to {}",
                output_path.display()
            );
        }
        Err(err) => {
            eprintln!("tidefsctl diag: failed to write support bundle: {err}");
            process::exit(1);
        }
    }
}

/// Attempt to scan a pool from the given device paths and return a summary.
fn collect_pool_from_devices(device_paths: &[PathBuf]) -> Option<support_bundle::PoolSummary> {
    use tidefs_pool_scan::{PoolScanConfig, PoolScanner};

    let config = PoolScanConfig::new(device_paths.to_vec());
    let result = match PoolScanner::scan(&config) {
        Ok(r) => r,
        Err(_) => return None,
    };

    // Extract all needed fields before the struct is dropped.
    let name = result.pool_name.clone();
    let guid = hex_encode(&result.pool_guid);
    let state = result.pool_state.to_string();
    let device_count = result.devices.len();
    let has_root = result.has_committed_root();
    let txg = result.committed_txg();

    Some(support_bundle::PoolSummary {
        name,
        guid,
        state,
        device_count,
        committed_root_count: if has_root { 1 } else { 0 },
        latest_txg: txg,
    })
}

/// Build a validation summary enumerating all known tiers and statuses.
fn build_validation_summary() -> ValidationSummary {
    use std::collections::BTreeMap;
    use tidefs_validation::validation_schema::ValidationTier;
    use tidefs_validation::validation_status::ValidationStatus;

    let mut by_tier = BTreeMap::new();
    let mut by_status = BTreeMap::new();

    let tiers: &[ValidationTier] = &[
        ValidationTier::SourceModel,
        ValidationTier::CargoUnit,
        ValidationTier::HarnessOnly,
        ValidationTier::MountedUserspace,
        ValidationTier::QemuGuest,
        ValidationTier::Kbuild,
        ValidationTier::QemuModuleLoad,
        ValidationTier::MountedKernelVfs,
        ValidationTier::KernelBlockIo,
        ValidationTier::FullKernelNoDaemon,
        ValidationTier::MultiProcessDistributed,
    ];
    for tier in tiers {
        by_tier.insert(tier.label().to_string(), 0usize);
    }

    let statuses: &[ValidationStatus] = &[
        ValidationStatus::Pass,
        ValidationStatus::ProductFail,
        ValidationStatus::HarnessFail,
        ValidationStatus::EnvironmentRefusal,
        ValidationStatus::Skip,
    ];
    for st in statuses {
        by_status.insert(st.label().to_string(), 0usize);
    }

    ValidationSummary {
        total_rows: 0,
        by_status,
        by_tier,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_validation_summary_has_all_tiers() {
        let s = build_validation_summary();
        assert!(s.by_tier.contains_key("source-model"));
        assert!(s.by_tier.contains_key("mounted-userspace"));
        assert!(s.by_tier.contains_key("full-kernel-no-daemon"));
        assert_eq!(s.total_rows, 0);
    }

    #[test]
    fn build_validation_summary_has_all_statuses() {
        let s = build_validation_summary();
        assert!(s.by_status.contains_key("PASS"));
        assert!(s.by_status.contains_key("PRODUCT_FAIL"));
        assert!(s.by_status.contains_key("SKIP"));
    }
}
