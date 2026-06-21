// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Gate that validates format-golden VFS codec vectors against the compiled
//! contract constants.  Drift detection lives here, not in runtime adapters;
//! this is codec/tooling evidence, not runtime adapter proof.
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
    eprintln!(
        "contract codecs ok: embedded v1 request/completion vectors plus {fixture_count} write-fsync-read contract fixture files validated"
    );
    Ok(())
}

fn validate_contract_manifest_current_workspace() -> Result<usize, String> {
    let manifest_path = repo_root().join(CONTRACT_MANIFEST_REL);
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| {
            format!(
                "format-golden manifest path has no parent directory: {}",
                manifest_path.display()
            )
        })?;
    let manifest_data = fs::read_to_string(&manifest_path)
        .map_err(|err| format!("read format-golden manifest {}: {err}", manifest_path.display()))?;
    let manifest: ContractGoldenManifest = serde_json::from_str(&manifest_data)
        .map_err(|err| {
            format!(
                "parse format-golden manifest {}: {err}",
                manifest_path.display()
            )
        })?;

    let mut errors = Vec::new();
    if manifest.format_version != "v1" {
        errors.push(format!(
            "format-golden manifest in group {}: format_version must be v1, got {}",
            manifest.group, manifest.format_version
        ));
    }
    if manifest.group != "request-contract-vfs-write-fsync-read-v1" {
        errors.push(format!(
            "format-golden manifest at {}: group must be request-contract-vfs-write-fsync-read-v1, got {}",
            manifest_path.display(),
            manifest.group
        ));
    }
    if manifest.evidence_scope != "contract-codec-only-not-mounted-runtime" {
        errors.push(format!(
            "format-golden manifest in group {}: evidence_scope must be contract-codec-only-not-mounted-runtime, got {}",
            manifest.group, manifest.evidence_scope
        ));
    }
    if manifest.runtime_claims {
        errors.push(format!(
            "format-golden manifest in group {}: must not claim runtime evidence",
            manifest.group
        ));
    }
    if manifest.close_release_supported {
        errors.push(format!(
            "format-golden manifest in group {}: close_release_supported must be false until v1 names a close/release opcode",
            manifest.group
        ));
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
            errors.push(format!(
                "format-golden manifest in group {}: unexpected manifest entry {entry_name} has no matching compiled codec golden vector",
                manifest.group
            ));
        }
    }

    for fixture in fixtures {
        let Some(entry) = manifest.entries.get(fixture.manifest_name) else {
            errors.push(format!(
                "format-golden manifest in group {}: missing manifest entry for compiled codec golden vector {} — the manifest at {} must be regenerated",
                manifest.group,
                fixture.manifest_name,
                manifest_path.display(),
            ));
            continue;
        };

        let expected_record = record_kind_manifest_name(fixture.record_kind);
        if entry.file != fixture.file_name {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: file mismatch — codec expects {}, manifest says {}",
                fixture.manifest_name, manifest.group, fixture.file_name, entry.file
            ));
        }
        if entry.record != expected_record {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: record mismatch — codec expects {}, manifest says {}",
                fixture.manifest_name, manifest.group, expected_record, entry.record
            ));
        }
        if entry.operation != fixture.operation {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: operation mismatch — codec expects {}, manifest says {}",
                fixture.manifest_name, manifest.group, fixture.operation, entry.operation
            ));
        }
        if entry.encoded_length != fixture.encoded_len {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: encoded_length mismatch — codec expects {}, manifest says {}",
                fixture.manifest_name, manifest.group, fixture.encoded_len, entry.encoded_length
            ));
        }
        if entry.runtime_evidence {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: must be marked runtime_evidence=false",
                fixture.manifest_name, manifest.group
            ));
        }
        if entry.reserved_zero_fields.is_empty() {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: must name the reserved fields that are expected to stay zero",
                fixture.manifest_name, manifest.group
            ));
        }
        if !entry.canonical_field_values.is_object() {
            errors.push(format!(
                "format-golden manifest entry {} in group {}: canonical_field_values must be a JSON object",
                fixture.manifest_name, manifest.group
            ));
        }

        // Embedded-codec vs manifest SHA256 cross-check.
        // This catches codec constant changes that were not followed by a
        // manifest and on-disk vector regeneration.  It is the primary
        // coherence gate: if the compiled golden bytes no longer match the
        // manifest SHA256, the format-golden tooling must be re-run.
        let embedded_hash = sha256_hex(fixture.bytes);
        if embedded_hash != entry.sha256 {
            errors.push(format!(
                "format-golden vector drift in group {}: compiled codec golden vector {} for file {} SHA256 {} does not match manifest SHA256 {} in {} — the codec constants, manifest, or on-disk golden vectors are stale; regenerate them together",
                manifest.group,
                fixture.manifest_name,
                entry.file,
                embedded_hash,
                entry.sha256,
                manifest_path.display()
            ));
        }

        let file_path = manifest_dir.join(&entry.file);
        let data = match fs::read(&file_path) {
            Ok(data) => data,
            Err(err) => {
                errors.push(format!(
                    "format-golden file {} in group {}: read failed: {err}",
                    file_path.display(),
                    manifest.group
                ));
                continue;
            }
        };

        let actual_hash = sha256_hex(&data);
        if actual_hash != entry.sha256 {
            errors.push(format!(
                "format-golden file {} in group {}: on-disk SHA256 {} does not match manifest SHA256 {} — the on-disk golden file is stale; regenerate with format-golden tooling",
                entry.file, manifest.group, actual_hash, entry.sha256
            ));
        }

        // Disk bytes vs embedded codec golden bytes.
        // Catches the case where the manifest and disk agree but the compiled
        // constants have drifted independently.
        match validate_contract_vfs_write_fsync_read_fixture(&entry.file, &data) {
            Some(Ok(())) => {}
            Some(Err(err)) => errors.push(format!(
                "format-golden vector drift in group {}: on-disk file {} does not match compiled codec golden vector — {err:?}; the golden file must be regenerated after codec constant changes",
                manifest.group, entry.file
            )),
            None => errors.push(format!(
                "format-golden file {} in group {}: has no contract fixture decoder in the compiled codec — a new fixture may need a corresponding validate_contract_* function",
                entry.file, manifest.group
            )),
        }
    }

    find_unmanifested_contract_bins(manifest_dir, &manifest_files, &manifest.group, &mut errors)?;

    if errors.is_empty() {
        Ok(fixtures.len())
    } else {
        for error in &errors {
            eprintln!("{error}");
        }
        Err(format!(
            "{} format-golden drift error(s) in group {} — see details above",
            errors.len(),
            manifest.group
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
    group_name: &str,
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
                "format-golden group {}: invalid contract fixture file name: {}",
                group_name,
                path.display()
            ));
            continue;
        };
        if !manifest_files.contains(file_name) {
            errors.push(format!(
                "format-golden group {}: unmanifested contract fixture file {} has no matching MANIFEST.json entry — the file may be stale or the manifest is missing an entry",
                group_name,
                file_name,
            ));
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
