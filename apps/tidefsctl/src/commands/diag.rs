// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! `tidefsctl diag` -- support bundle and diagnostics command.
//!
//! Collects a redacted support bundle with source-qualified operator evidence.
//! Passive host probes, command classification, explicit offline device scans,
//! live-owner facts, and unavailable placeholders are labeled separately so a
//! bundle is not mistaken for storage authority or validation evidence.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use tidefs_types_pool_label_core::PoolState;
use tidefs_validation::support_bundle::{
    self, CommandSurfaceSection, CommandSurfaceSummary, EvidenceAvailability, EvidenceSection,
    EvidenceSource, PoolSummary, ValidationSummary,
};

/// Handle the `tidefsctl diag` subcommand.
pub fn handle_diag(output_dir: Option<PathBuf>, device_paths: &[PathBuf], json: bool) {
    let bundle = build_diag_bundle(device_paths);

    if json {
        match serde_json::to_string_pretty(&bundle) {
            Ok(raw) => println!("{raw}"),
            Err(err) => {
                eprintln!("tidefsctl diag: failed to format support bundle: {err}");
                process::exit(1);
            }
        }
        return;
    }

    let output_dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    let timestamp = &bundle.collected_at;
    let filename = format!("tidefs-diag-{timestamp}.json").replace(':', "-");
    let output_path = output_dir.join(&filename);

    match support_bundle::write_bundle_json(&bundle, &output_path) {
        Ok(()) => {
            eprintln!(
                "tidefsctl diag: source={} maturity={} redacted={}",
                bundle.report_source.source.label(),
                bundle.maturity.label,
                bundle.redacted
            );
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

fn build_diag_bundle(device_paths: &[PathBuf]) -> support_bundle::SupportBundle {
    let mut bundle = support_bundle::new_support_bundle();
    bundle.command_surface = build_command_surface_section();
    bundle.pools = collect_pool_section_from_devices(device_paths);
    bundle.datasets = EvidenceSection::unavailable(
        "dataset catalog facts require a live-owner source; diag does not reopen cached imported-pool state or offline devices as dataset authority",
    );
    bundle.validation_summary = build_validation_summary();
    bundle
}

fn build_command_surface_section() -> CommandSurfaceSection {
    let entries = super::classification::COMMAND_SURFACES
        .iter()
        .map(|surface| {
            let admission = super::authz::command_admission(surface.path)
                .expect("classified command surface admission");
            CommandSurfaceSummary {
                source: EvidenceSource::CommandClassificationRegistry,
                command: surface.path.to_string(),
                class: surface.class.label().to_string(),
                routing: surface.routing.label().to_string(),
                admission: admission.label().to_string(),
                help: if surface.visible_in_root_help() {
                    "visible".to_string()
                } else {
                    "hidden".to_string()
                },
                summary: surface.summary.to_string(),
            }
        })
        .collect();

    CommandSurfaceSection {
        source: EvidenceSource::CommandClassificationRegistry,
        registry_marker: super::classification::COMMAND_CLASSIFICATION_DOC_MARKER.to_string(),
        registry_source_path: super::classification::COMMAND_CLASSIFICATION_SOURCE_PATH.to_string(),
        entries,
    }
}

/// Scan explicit offline device inputs without turning them into live authority.
fn collect_pool_section_from_devices(device_paths: &[PathBuf]) -> EvidenceSection<PoolSummary> {
    if device_paths.is_empty() {
        return EvidenceSection::unavailable(
            "no explicit --devices were provided and no live-owner diagnostic path was requested",
        );
    }

    let label_entries = match tidefs_pool_scan::scan_labels(device_paths) {
        Ok(entries) => entries,
        Err(_) => {
            return EvidenceSection {
                source: EvidenceSource::OfflineDeviceScan,
                availability: EvidenceAvailability::Unavailable,
                source_count: 1,
                entries: Vec::new(),
                note: Some(
                    "explicit offline device scan failed; path and device-error details are redacted"
                        .to_string(),
                ),
            };
        }
    };

    let mut by_pool: BTreeMap<[u8; 16], Vec<tidefs_pool_scan::DeviceScanEntry>> = BTreeMap::new();
    for entry in label_entries {
        if entry.label_valid {
            if let Some(pool_guid) = entry.pool_guid {
                by_pool.entry(pool_guid).or_default().push(entry);
            }
        }
    }

    if by_pool.is_empty() {
        return EvidenceSection {
            source: EvidenceSource::OfflineDeviceScan,
            availability: EvidenceAvailability::Unavailable,
            source_count: 1,
            entries: Vec::new(),
            note: Some(
                "explicit offline device scan found no valid TideFS pool labels".to_string(),
            ),
        };
    }

    let mut summaries = Vec::new();
    let mut limited = false;
    for (pool_guid, entries) in by_pool {
        let (summary, availability) = pool_summary_from_label_group(pool_guid, &entries);
        limited |= availability != EvidenceAvailability::Available;
        summaries.push(summary);
    }

    if limited {
        EvidenceSection::limited(
            EvidenceSource::OfflineDeviceScan,
            summaries,
            "one or more pool entries are label-only because imported or unavailable state cannot be reopened behind a live owner",
        )
    } else {
        EvidenceSection::available(EvidenceSource::OfflineDeviceScan, summaries)
    }
}

fn pool_summary_from_label_group(
    pool_guid: [u8; 16],
    entries: &[tidefs_pool_scan::DeviceScanEntry],
) -> (PoolSummary, EvidenceAvailability) {
    let pool_name = entries
        .iter()
        .find_map(|entry| entry.pool_name.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let pool_state = entries.iter().find_map(|entry| entry.pool_state);
    let state = pool_state
        .map(|state| state.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string());
    let label_device_count = entries
        .iter()
        .filter_map(|entry| entry.device_count)
        .max()
        .map(|count| count as usize)
        .unwrap_or(entries.len());

    match pool_state {
        Some(PoolState::Exported) => exported_pool_summary(pool_guid, entries, pool_name, state),
        Some(PoolState::Active) => (
            PoolSummary {
                source: EvidenceSource::OfflineDeviceScan,
                fact_set: "imported-active-label-only".to_string(),
                live_owner_required: true,
                name: pool_name,
                guid: hex_encode(&pool_guid),
                state,
                device_count: label_device_count,
                committed_root_count: 0,
                latest_txg: None,
            },
            EvidenceAvailability::Limited,
        ),
        _ => (
            PoolSummary {
                source: EvidenceSource::OfflineDeviceScan,
                fact_set: "non-exported-label-only".to_string(),
                live_owner_required: false,
                name: pool_name,
                guid: hex_encode(&pool_guid),
                state,
                device_count: label_device_count,
                committed_root_count: 0,
                latest_txg: None,
            },
            EvidenceAvailability::Limited,
        ),
    }
}

fn exported_pool_summary(
    pool_guid: [u8; 16],
    entries: &[tidefs_pool_scan::DeviceScanEntry],
    fallback_name: String,
    fallback_state: String,
) -> (PoolSummary, EvidenceAvailability) {
    use tidefs_pool_scan::{PoolScanConfig, PoolScanner};

    let device_paths = entries
        .iter()
        .map(|entry| entry.device_path.clone())
        .collect::<Vec<_>>();
    let config = PoolScanConfig::new(device_paths);
    let result = match PoolScanner::scan(&config) {
        Ok(result) => result,
        Err(_) => {
            return (
                PoolSummary {
                    source: EvidenceSource::OfflineDeviceScan,
                    fact_set: "exported-label-only-scan-unavailable".to_string(),
                    live_owner_required: false,
                    name: fallback_name,
                    guid: hex_encode(&pool_guid),
                    state: fallback_state,
                    device_count: entries.len(),
                    committed_root_count: 0,
                    latest_txg: None,
                },
                EvidenceAvailability::Limited,
            );
        }
    };

    let has_root = result.has_committed_root();
    let summary = PoolSummary {
        source: EvidenceSource::OfflineDeviceScan,
        fact_set: "exported-offline-device-scan".to_string(),
        live_owner_required: false,
        name: result.pool_name.clone(),
        guid: hex_encode(&result.pool_guid),
        state: result.pool_state.to_string(),
        device_count: result.devices.len(),
        committed_root_count: if has_root { 1 } else { 0 },
        latest_txg: result.committed_txg(),
    };
    (summary, EvidenceAvailability::Available)
}

/// Build a validation summary that does not imply measured evidence.
fn build_validation_summary() -> ValidationSummary {
    support_bundle::unavailable_validation_summary()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diag_bundle_labels_all_static_sections() {
        let bundle = build_diag_bundle(&[]);

        assert_eq!(
            bundle.report_source.source,
            EvidenceSource::PassiveHostProbe
        );
        assert_eq!(bundle.system.source, EvidenceSource::PassiveHostProbe);
        assert_eq!(bundle.environment.source, EvidenceSource::PassiveHostProbe);
        assert_eq!(
            bundle.command_surface.source,
            EvidenceSource::CommandClassificationRegistry
        );
        assert_eq!(bundle.pools.source, EvidenceSource::Unavailable);
        assert_eq!(bundle.datasets.source, EvidenceSource::Unavailable);
        assert_eq!(
            bundle.validation_summary.source,
            EvidenceSource::Unavailable
        );
        assert_eq!(bundle.validation_summary.source_count, 0);
        assert!(!bundle.validation_summary.claims_advanced);
    }

    #[test]
    fn command_surface_evidence_comes_from_classification_registry() {
        let section = build_command_surface_section();
        let diag = section
            .entries
            .iter()
            .find(|entry| entry.command == "diag")
            .expect("diag command surface");

        assert_eq!(diag.source, EvidenceSource::CommandClassificationRegistry);
        assert_eq!(diag.class, "operator-diagnostic");
        assert_eq!(diag.routing, "passive-diagnostic");
        assert_eq!(diag.admission, "unguarded");
        assert_eq!(
            section.registry_marker,
            super::super::classification::COMMAND_CLASSIFICATION_DOC_MARKER
        );
    }

    #[test]
    fn explicit_device_scan_section_is_source_labeled_and_redacted_on_failure() {
        let device = PathBuf::from("/definitely/not/a/tidefs/device");
        let section = collect_pool_section_from_devices(&[device]);

        assert_eq!(section.source, EvidenceSource::OfflineDeviceScan);
        assert_eq!(section.source_count, 1);
        assert!(matches!(
            section.availability,
            EvidenceAvailability::Unavailable | EvidenceAvailability::Limited
        ));
        let note = section.note.unwrap_or_default();
        assert!(!note.contains("/definitely/"));
    }

    #[test]
    fn active_label_scan_reports_label_only_live_owner_required() {
        let pool_guid = [0x42; 16];
        let entry = tidefs_pool_scan::DeviceScanEntry {
            device_path: PathBuf::from("/redacted/device"),
            size_bytes: 0,
            kind: tidefs_pool_scan::DeviceKind::Unknown,
            model: None,
            serial: None,
            has_tidefs_label: true,
            pool_guid: Some(pool_guid),
            pool_name: Some("tank".to_string()),
            pool_state: Some(PoolState::Active),
            device_guid: Some([0x24; 16]),
            label_valid: true,
            label_status: "valid".to_string(),
            device_index: Some(0),
            device_count: Some(1),
            topology_generation: None,
            device_class: None,
            device_capacity_bytes: None,
            device_health: None,
            device_read_errors: None,
            device_write_errors: None,
            device_checksum_errors: None,
            redundancy_policy: None,
            completed_evacuations: vec![],
        };

        let (summary, availability) = pool_summary_from_label_group(pool_guid, &[entry]);

        assert_eq!(availability, EvidenceAvailability::Limited);
        assert_eq!(summary.source, EvidenceSource::OfflineDeviceScan);
        assert_eq!(summary.fact_set, "imported-active-label-only");
        assert!(summary.live_owner_required);
        assert_eq!(summary.committed_root_count, 0);
        assert_eq!(summary.latest_txg, None);
    }

    #[test]
    fn validation_summary_is_unavailable_when_no_rows_are_consulted() {
        let summary = build_validation_summary();

        assert_eq!(summary.source, EvidenceSource::Unavailable);
        assert_eq!(summary.availability, EvidenceAvailability::Unavailable);
        assert_eq!(summary.source_count, 0);
        assert!(summary.by_status.is_empty());
        assert!(summary.by_tier.is_empty());
    }
}
