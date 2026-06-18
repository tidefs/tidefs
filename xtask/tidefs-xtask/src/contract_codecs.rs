// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use tidefs_schema_codec_vfs::{
    contract_codec_self_check, contract_vfs_write_fsync_read_v1_fixtures,
    validate_contract_vfs_write_fsync_read_fixture, ContractGoldenRecordKind,
};

const CONTRACT_MANIFEST_REL: &str =
    "validation/format-golden/request-contract-vfs-write-fsync-read-v1/MANIFEST.json";

#[derive(Deserialize)]
struct ContractGoldenManifest {
    format_version: String,
    group: String,
    evidence_scope: String,
    runtime_claims: bool,
    close_release_supported: bool,
    entries: BTreeMap<String, ContractGoldenEntry>,
}

#[derive(Deserialize)]
struct ContractGoldenEntry {
    file: String,
    record: String,
    operation: String,
    encoded_length: usize,
    sha256: String,
    runtime_evidence: bool,
    reserved_zero_fields: Vec<String>,
    canonical_field_values: serde_json::Value,
}

pub fn check_contract_codecs_current_workspace() -> Result<(), String> {
    contract_codec_self_check()
        .map_err(|err| format!("contract codec self-check failed: {err:?}"))?;
    let fixture_count = validate_contract_manifest_current_workspace()?;
    println!(
        "contract codecs ok: embedded v1 request/completion vectors plus {fixture_count} write-fsync-read contract fixture files validated"
    );
    Ok(())
}

fn validate_contract_manifest_current_workspace() -> Result<usize, String> {
    let manifest_path = repo_root().join(CONTRACT_MANIFEST_REL);
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| format!("manifest path has no parent: {}", manifest_path.display()))?;
    let manifest_data = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
    let manifest: ContractGoldenManifest = serde_json::from_str(&manifest_data)
        .map_err(|err| format!("parse {}: {err}", manifest_path.display()))?;

    let mut errors = Vec::new();
    if manifest.format_version != "v1" {
        errors.push(format!(
            "contract manifest format_version must be v1, got {}",
            manifest.format_version
        ));
    }
    if manifest.group != "request-contract-vfs-write-fsync-read-v1" {
        errors.push(format!(
            "contract manifest group must be request-contract-vfs-write-fsync-read-v1, got {}",
            manifest.group
        ));
    }
    if manifest.evidence_scope != "contract-codec-only-not-mounted-runtime" {
        errors.push(format!(
            "contract manifest evidence_scope must be contract-codec-only-not-mounted-runtime, got {}",
            manifest.evidence_scope
        ));
    }
    if manifest.runtime_claims {
        errors.push("contract manifest must not claim runtime evidence".to_string());
    }
    if manifest.close_release_supported {
        errors.push(
            "contract manifest must keep close_release_supported=false until v1 names a close/release opcode"
                .to_string(),
        );
    }

    let fixtures = contract_vfs_write_fsync_read_v1_fixtures();
    let expected_names = fixtures
        .iter()
        .map(|fixture| fixture.manifest_name)
        .collect::<BTreeSet<_>>();
    let manifest_files = manifest
        .entries
        .values()
        .map(|entry| entry.file.clone())
        .collect::<BTreeSet<_>>();

    for entry_name in manifest.entries.keys() {
        if !expected_names.contains(entry_name.as_str()) {
            errors.push(format!("unexpected contract manifest entry: {entry_name}"));
        }
    }

    for fixture in fixtures {
        let Some(entry) = manifest.entries.get(fixture.manifest_name) else {
            errors.push(format!(
                "missing contract manifest entry: {}",
                fixture.manifest_name
            ));
            continue;
        };

        let expected_record = record_kind_manifest_name(fixture.record_kind);
        if entry.file != fixture.file_name {
            errors.push(format!(
                "{} file mismatch: expected {}, got {}",
                fixture.manifest_name, fixture.file_name, entry.file
            ));
        }
        if entry.record != expected_record {
            errors.push(format!(
                "{} record mismatch: expected {}, got {}",
                fixture.manifest_name, expected_record, entry.record
            ));
        }
        if entry.operation != fixture.operation {
            errors.push(format!(
                "{} operation mismatch: expected {}, got {}",
                fixture.manifest_name, fixture.operation, entry.operation
            ));
        }
        if entry.encoded_length != fixture.encoded_len {
            errors.push(format!(
                "{} encoded_length mismatch: expected {}, got {}",
                fixture.manifest_name, fixture.encoded_len, entry.encoded_length
            ));
        }
        if entry.runtime_evidence {
            errors.push(format!(
                "{} must be marked runtime_evidence=false",
                fixture.manifest_name
            ));
        }
        if entry.reserved_zero_fields.is_empty() {
            errors.push(format!(
                "{} must name the reserved fields that are expected to stay zero",
                fixture.manifest_name
            ));
        }
        if !entry.canonical_field_values.is_object() {
            errors.push(format!(
                "{} canonical_field_values must be a JSON object",
                fixture.manifest_name
            ));
        }

        let file_path = manifest_dir.join(&entry.file);
        let data = match fs::read(&file_path) {
            Ok(data) => data,
            Err(err) => {
                errors.push(format!("read {}: {err}", file_path.display()));
                continue;
            }
        };

        let actual_hash = sha256_hex(&data);
        if actual_hash != entry.sha256 {
            errors.push(format!(
                "{} hash mismatch: expected {}, got {}",
                entry.file, entry.sha256, actual_hash
            ));
        }

        match validate_contract_vfs_write_fsync_read_fixture(&entry.file, &data) {
            Some(Ok(())) => {}
            Some(Err(err)) => errors.push(format!("{} decode check failed: {err:?}", entry.file)),
            None => errors.push(format!("{} has no contract fixture decoder", entry.file)),
        }
    }

    find_unmanifested_contract_bins(manifest_dir, &manifest_files, &mut errors)?;

    if errors.is_empty() {
        Ok(fixtures.len())
    } else {
        for error in &errors {
            eprintln!("{error}");
        }
        Err(format!(
            "{} contract codec manifest validation errors",
            errors.len()
        ))
    }
}

fn repo_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("../..");
    root
}

fn record_kind_manifest_name(kind: ContractGoldenRecordKind) -> &'static str {
    match kind {
        ContractGoldenRecordKind::RequestEnvelopeV1 => "request-envelope-v1",
        ContractGoldenRecordKind::TideCompletionV1 => "tide-completion-v1",
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn find_unmanifested_contract_bins(
    manifest_dir: &Path,
    manifest_files: &BTreeSet<String>,
    errors: &mut Vec<String>,
) -> Result<(), String> {
    for entry in fs::read_dir(manifest_dir)
        .map_err(|err| format!("read {}: {err}", manifest_dir.display()))?
    {
        let entry = entry.map_err(|err| format!("read manifest dir entry: {err}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("bin") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            errors.push(format!(
                "invalid contract fixture file name: {}",
                path.display()
            ));
            continue;
        };
        if !manifest_files.contains(file_name) {
            errors.push(format!("unmanifested contract fixture file: {file_name}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_contract_codecs_validates_manifest() {
        check_contract_codecs_current_workspace().expect("contract codec manifest");
    }
}
