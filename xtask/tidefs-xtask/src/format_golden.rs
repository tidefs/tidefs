// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use tidefs_schema_codec_posix_filesystem_adapter::CanonicalFixedWidth as PfaCfw;
use tidefs_schema_codec_vfs::CanonicalFixedWidth as VfsCfw;
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterDigest32, PosixFilesystemAdapterId128,
    PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs,
    PosixFilesystemAdapterProductWakeReceiptRecord,
};
use tidefs_types_vfs_core::{
    DirHandleId, EngineDirHandle, EngineFileHandle, FileHandleId, Generation, InodeId, NodeKind,
};

// ── Manifest schema ───────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct GoldenManifest {
    format_version: String,
    generator: String,
    description: String,
    entries: BTreeMap<String, GoldenEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GoldenEntry {
    group: String,
    file: String,
    encoded_length: usize,
    sha256: String,
    description: String,
    canonical_field_values: serde_json::Value,
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn pid(n: u8) -> PosixFilesystemAdapterId128 {
    PosixFilesystemAdapterId128([n; 16])
}

fn digest(n: u8) -> PosixFilesystemAdapterDigest32 {
    [n; 32]
}

fn golden_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../../validation/format-golden");
    d
}

fn is_golden_bin(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("bin")
}

fn remove_existing_golden_bins(dir: &Path) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|e| format!("read golden dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read golden dir entry: {e}"))?;
        let path = entry.path();
        if is_golden_bin(&path) {
            fs::remove_file(&path)
                .map_err(|e| format!("remove stale golden file {}: {e}", path.display()))?;
        }
    }
    Ok(())
}

fn write_golden<T: VfsCfw>(
    name: &str,
    group: &str,
    val: &T,
    fields_json: serde_json::Value,
    entries: &mut BTreeMap<String, GoldenEntry>,
) {
    let mut buf = vec![0u8; T::ENCODED_LEN];
    val.encode_le(&mut buf);
    let filename = format!("{}_{}.bin", group, name.to_lowercase().replace('_', "-"));
    let filepath = golden_dir().join(&filename);
    fs::create_dir_all(golden_dir()).expect("create golden dir");
    fs::write(&filepath, &buf).expect("write golden file");

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hex::encode(hasher.finalize());

    entries.insert(
        name.to_string(),
        GoldenEntry {
            group: group.to_string(),
            file: filename,
            encoded_length: T::ENCODED_LEN,
            sha256: hash,
            description: format!("Golden binary for {name}"),
            canonical_field_values: fields_json,
        },
    );
}

fn write_golden_pfa<T: PfaCfw>(
    name: &str,
    group: &str,
    val: &T,
    fields_json: serde_json::Value,
    entries: &mut BTreeMap<String, GoldenEntry>,
) {
    let mut buf = vec![0u8; T::ENCODED_LEN];
    val.encode_le(&mut buf);
    let filename = format!("{}_{}.bin", group, name.to_lowercase().replace('_', "-"));
    let filepath = golden_dir().join(&filename);
    fs::create_dir_all(golden_dir()).expect("create golden dir");
    fs::write(&filepath, &buf).expect("write golden file");

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hex::encode(hasher.finalize());

    entries.insert(
        name.to_string(),
        GoldenEntry {
            group: group.to_string(),
            file: filename,
            encoded_length: T::ENCODED_LEN,
            sha256: hash,
            description: format!("Golden binary for {name}"),
            canonical_field_values: fields_json,
        },
    );
}

// ── Generate all golden files ─────────────────────────────────────────────

pub fn generate_format_golden() -> Result<(), String> {
    let dir = golden_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;
    remove_existing_golden_bins(&dir)?;

    let mut entries: BTreeMap<String, GoldenEntry> = BTreeMap::new();

    // ═══ VFS group ═══
    write_golden(
        "InodeId",
        "vfs",
        &InodeId(42),
        serde_json::json!({"inode_id": 42u64}),
        &mut entries,
    );
    write_golden(
        "Generation",
        "vfs",
        &Generation(7),
        serde_json::json!({"generation": 7u64}),
        &mut entries,
    );
    write_golden(
        "FileHandleId",
        "vfs",
        &FileHandleId(100),
        serde_json::json!({"fh_id": 100u64}),
        &mut entries,
    );
    write_golden(
        "DirHandleId",
        "vfs",
        &DirHandleId(200),
        serde_json::json!({"dh_id": 200u64}),
        &mut entries,
    );
    write_golden(
        "NodeKind",
        "vfs",
        &NodeKind::File,
        serde_json::json!({"kind": "File", "tag": 0u32}),
        &mut entries,
    );
    write_golden(
        "EngineFileHandle",
        "vfs",
        &EngineFileHandle {
            inode_id: InodeId(1),
            open_flags: 0x8000,
            fh_id: FileHandleId(10),
            lock_owner: 0,
        },
        serde_json::json!({"inode_id": 1, "open_flags": 32768, "fh_id": 10, "lock_owner": 0}),
        &mut entries,
    );
    write_golden(
        "EngineDirHandle",
        "vfs",
        &EngineDirHandle {
            inode_id: InodeId(2),
            dh_id: DirHandleId(20),
        },
        serde_json::json!({"inode_id": 2, "dh_id": 20}),
        &mut entries,
    );

    // ═══ posix-filesystem-adapter group ═══
    write_golden_pfa(
        "PosixFilesystemAdapterProductWakeReceiptRecord",
        "posix-filesystem-adapter",
        &PosixFilesystemAdapterProductWakeReceiptRecord {
            wake_receipt_id: pid(0xA1),
            request_id: pid(0xA2),
            journal_id: pid(0xA3),
            response_registry_receipt_id: pid(0xA4),
            publication_pipeline_ticket_id_or_zero: pid(0),
            wake_class: 1,
            visibility_class: 2,
            _reserved0: 0,
            answer_digest: digest(0xE1),
            artifact_locator_digest: digest(0xE2),
            witness_refs: PosixFilesystemAdapterPolicyBudgetRecipeWitnessRefs {
                witness_join_id: pid(0xB1),
                policy_witness_id: pid(0xB2),
                budget_witness_id: pid(0xB3),
                recipe_witness_id: pid(0xB4),
                witness_join_digest: digest(0xE3),
            },
        },
        serde_json::json!({"wake_receipt_id": 161}),
        &mut entries,
    );

    // Write MANIFEST.json
    let manifest = GoldenManifest {
        format_version: "v1".to_string(),
        generator: "tidefs-format-golden v1".to_string(),
        description:
            "Format golden vector corpus for cross-implementation encode/decode validation"
                .to_string(),
        entries,
    };

    let manifest_path = dir.join("MANIFEST.json");
    let json = serde_json::to_string_pretty(&manifest).map_err(|e| format!("serialize: {e}"))?;
    fs::write(&manifest_path, json + "\n").map_err(|e| format!("write: {e}"))?;

    println!(
        "Generated golden files and MANIFEST.json in {}",
        dir.display()
    );
    Ok(())
}

// ── Validate golden files against manifest ────────────────────────────────

pub fn validate_format_golden() -> Result<(), String> {
    // ── Round-trip helper: decode → re-encode → compare bytes ──────────
    macro_rules! check_roundtrip {
        ($trait:ident, $ty:ty, $name:expr, $data:expr, $errors:expr) => {{
            let decoded = <$ty as $trait>::decode_le(&$data[..]).map_err(|e| {
                format!(
                    "decode failed for {}: expected_len={}, actual_len={}",
                    $name, e.expected_len, e.actual_len
                )
            });
            match decoded {
                Ok(val) => {
                    let mut re_buf = vec![0u8; $data.len()];
                    <$ty as $trait>::encode_le(&val, &mut re_buf);
                    if re_buf != *$data {
                        $errors.push(format!("re-encode mismatch for {}", $name));
                    }
                }
                Err(e) => $errors.push(e),
            }
        }};
    }

    let dir = golden_dir();
    let manifest_path = dir.join("MANIFEST.json");
    let manifest_data =
        fs::read_to_string(&manifest_path).map_err(|e| format!("read MANIFEST.json: {e}"))?;
    let manifest: GoldenManifest =
        serde_json::from_str(&manifest_data).map_err(|e| format!("parse MANIFEST.json: {e}"))?;

    let mut errors = Vec::new();
    let manifest_files = manifest
        .entries
        .values()
        .map(|entry| entry.file.clone())
        .collect::<BTreeSet<_>>();

    for (_name, entry) in &manifest.entries {
        let filepath = dir.join(&entry.file);

        // Check file exists
        if !filepath.exists() {
            errors.push(format!("missing golden file: {}", entry.file));
            continue;
        }

        // Check sha256
        let data = fs::read(&filepath).map_err(|e| format!("read {}: {e}", entry.file))?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let actual_hash = hex::encode(hasher.finalize());

        if actual_hash != entry.sha256 {
            errors.push(format!(
                "hash mismatch for {}: expected {}, got {}",
                entry.file, entry.sha256, actual_hash
            ));
        }

        // Check encoded length
        if data.len() != entry.encoded_length {
            errors.push(format!(
                "length mismatch for {}: expected {}, got {}",
                entry.file,
                entry.encoded_length,
                data.len()
            ));
        }

        // ── Format round-trip: decode → re-encode → compare bytes ──────
        match (entry.group.as_str(), _name.as_str()) {
            // ── VFS group ──
            ("vfs", "InodeId") => check_roundtrip!(VfsCfw, InodeId, _name, data, errors),
            ("vfs", "Generation") => check_roundtrip!(VfsCfw, Generation, _name, data, errors),
            ("vfs", "FileHandleId") => check_roundtrip!(VfsCfw, FileHandleId, _name, data, errors),
            ("vfs", "DirHandleId") => check_roundtrip!(VfsCfw, DirHandleId, _name, data, errors),
            ("vfs", "NodeKind") => check_roundtrip!(VfsCfw, NodeKind, _name, data, errors),
            ("vfs", "EngineFileHandle") => {
                check_roundtrip!(VfsCfw, EngineFileHandle, _name, data, errors)
            }
            ("vfs", "EngineDirHandle") => {
                check_roundtrip!(VfsCfw, EngineDirHandle, _name, data, errors)
            }

            // ── posix-filesystem-adapter group ──
            ("posix-filesystem-adapter", "PosixFilesystemAdapterProductWakeReceiptRecord") => {
                check_roundtrip!(
                    PfaCfw,
                    PosixFilesystemAdapterProductWakeReceiptRecord,
                    _name,
                    data,
                    errors
                )
            }

            _ => errors.push(format!("no round-trip dispatch for {_name}")),
        }
    }

    for entry in fs::read_dir(&dir).map_err(|e| format!("read golden dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read golden dir entry: {e}"))?;
        let path = entry.path();
        if !is_golden_bin(&path) {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            errors.push(format!("invalid golden file name: {}", path.display()));
            continue;
        };
        if !manifest_files.contains(file_name) {
            errors.push(format!("unmanifested golden file: {file_name}"));
        }
    }

    if errors.is_empty() {
        println!(
            "All {} golden format files validated successfully (file integrity + round-trip).",
            manifest.entries.len()
        );
        Ok(())
    } else {
        for e in &errors {
            eprintln!("{e}");
        }
        Err(format!("{} golden file validation errors", errors.len()))
    }
}
