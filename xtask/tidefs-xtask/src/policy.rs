use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Family {
    Types,
    SchemaCodec,
    PolicyAuthority,
    AuthorityPublication,
    ClaimReserveWitness,
    #[allow(dead_code)]
    ResponseRegistry,
    ResponseNormalizer,
    PosixFilesystemAdapter,
    BlockVolumeAdapter,
    ControlPlane,
    ExplanationQuery,
    Observe,
    Storage,
    Test,
    Xtask,
    #[allow(dead_code)]
    Unknown,
}

impl Family {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Types => "types",
            Self::SchemaCodec => "schema_codec",
            Self::PolicyAuthority => "policy_authority",
            Self::AuthorityPublication => "authority_publication",
            Self::ClaimReserveWitness => "claim_reserve_witness",
            Self::ResponseRegistry => "response_registry",
            Self::ResponseNormalizer => "response_normalizer",
            Self::PosixFilesystemAdapter => "posix_filesystem_adapter",
            Self::BlockVolumeAdapter => "block_volume_adapter",
            Self::ControlPlane => "control_plane",
            Self::ExplanationQuery => "explanation_query",
            Self::Observe => "observe",
            Self::Storage => "storage",
            Self::Test => "test",
            Self::Xtask => "xtask",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NodeKind {
    Library,
    AppRoot,
    Xtask,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrateClass {
    Types,
    Schema,
    Api,
    Core,
    Runtime,
    Client,
    Render,
    Query,
    Observe,
    Storage,
    ServiceRoot,
    TestOrXtask,
    #[allow(dead_code)]
    Unknown,
}

impl CrateClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Types => "types",
            Self::Schema => "schema",
            Self::Api => "api",
            Self::Core => "core",
            Self::Runtime => "runtime",
            Self::Client => "client",
            Self::Render => "render",
            Self::Query => "query",
            Self::Observe => "observe",
            Self::Storage => "storage",
            Self::ServiceRoot => "service_root",
            Self::TestOrXtask => "test_or_xtask",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug)]
struct Member {
    name: String,
    rel_path: String,
    family: Family,
    kind: NodeKind,
    class: CrateClass,
    dependencies: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassificationStatus {
    WorkspaceMember,
    WorkspaceExcluded,
}

impl ClassificationStatus {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "workspace-member" => Some(Self::WorkspaceMember),
            "workspace-excluded" => Some(Self::WorkspaceExcluded),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceMember => "workspace-member",
            Self::WorkspaceExcluded => "workspace-excluded",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageRole {
    ProductCode,
    AdapterOperator,
    PolicyTooling,
    ProofHarness,
    VendoredThirdParty,
    StandaloneFuzz,
    ScaffoldTransitional,
    ArchiveDeleteCandidate,
}

impl PackageRole {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "product-code" => Some(Self::ProductCode),
            "adapter-operator" => Some(Self::AdapterOperator),
            "policy-tooling" => Some(Self::PolicyTooling),
            "proof-harness" => Some(Self::ProofHarness),
            "vendored-third-party" => Some(Self::VendoredThirdParty),
            "standalone-fuzz" => Some(Self::StandaloneFuzz),
            "scaffold-transitional" => Some(Self::ScaffoldTransitional),
            "archive-delete-candidate" => Some(Self::ArchiveDeleteCandidate),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ProductCode => "product-code",
            Self::AdapterOperator => "adapter-operator",
            Self::PolicyTooling => "policy-tooling",
            Self::ProofHarness => "proof-harness",
            Self::VendoredThirdParty => "vendored-third-party",
            Self::StandaloneFuzz => "standalone-fuzz",
            Self::ScaffoldTransitional => "scaffold-transitional",
            Self::ArchiveDeleteCandidate => "archive-delete-candidate",
        }
    }
}

#[derive(Clone, Debug)]
struct PackageClassificationRow {
    package_root: String,
    package_name: String,
    status: ClassificationStatus,
    role: PackageRole,
    disposition: String,
}

#[derive(Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoMetadataPackage>,
    workspace_members: Vec<String>,
}

#[derive(Deserialize)]
struct CargoMetadataPackage {
    name: String,
    id: String,
    manifest_path: String,
}

#[derive(Debug)]
pub struct WorkspacePolicyError {
    violations: Vec<String>,
}

impl fmt::Display for WorkspacePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "workspace policy check failed:")?;
        for violation in &self.violations {
            writeln!(f, "- {violation}")?;
        }
        Ok(())
    }
}

pub fn check_current_workspace() -> Result<(), WorkspacePolicyError> {
    let root = find_workspace_root().ok_or_else(|| WorkspacePolicyError {
        violations: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let members = discover_members(&root).map_err(|err| WorkspacePolicyError {
        violations: vec![err],
    })?;
    let member_map: BTreeMap<_, _> = members.iter().map(|m| (m.name.as_str(), m)).collect();
    let mut edges_checked = 0_usize;
    let mut violations = Vec::new();
    for member in &members {
        for dependency in &member.dependencies {
            if let Some(target) = member_map.get(dependency.as_str()) {
                edges_checked += 1;
                if !is_edge_allowed(member, target) {
                    violations.push(format!(
                        "{} ({}::{}) -> {} ({}::{}) is forbidden by workspace_layout",
                        member.name,
                        member.family.as_str(),
                        member.class.as_str(),
                        target.name,
                        target.family.as_str(),
                        target.class.as_str(),
                    ));
                }
            }
        }
    }
    check_package_profile_doc_name_drift(&root, &mut violations);
    check_excluded_fuzz_manifest_licenses(&root, &mut violations);
    check_file_local_provenance_markers(&root, &mut violations);
    check_package_classification_authority(&root, &members, &mut violations);

    // ── Member-consistency audit: warn but don't fail ──
    let mut member_consistency_warnings = Vec::new();
    check_workspace_member_consistency(&root, &mut member_consistency_warnings);
    for w in &member_consistency_warnings {
        eprintln!("note: {w}");
    }

    // ── Dead crate audit: report library members with zero reverse deps ──
    let mut rev_count: BTreeMap<&str, usize> = BTreeMap::new();
    for member in &members {
        for dep in &member.dependencies {
            if member_map.contains_key(dep.as_str()) {
                *rev_count.entry(dep.as_str()).or_insert(0) += 1;
            }
        }
    }
    for member in &members {
        if member.kind != NodeKind::Library {
            continue;
        }
        if rev_count.get(member.name.as_str()).copied().unwrap_or(0) == 0 {
            eprintln!(
                "note: {} has zero intra-workspace Cargo.toml consumers -- verify before removal",
                member.name
            );
        }
    }

    if violations.is_empty() {
        println!(
            "workspace policy ok: {} members, {} internal dependency edges checked",
            members.len(),
            edges_checked
        );
        Ok(())
    } else {
        Err(WorkspacePolicyError { violations })
    }
}

const TIDEFS_LICENSE: &str = "GPL-2.0-only WITH Linux-syscall-note";

const EXCLUDED_FUZZ_MANIFESTS: &[&str] = &[
    "fuzz/Cargo.toml",
    "crates/tidefs-binary_schema-core/fuzz/Cargo.toml",
    "crates/tidefs-local-filesystem/fuzz/Cargo.toml",
    "crates/tidefs-local-object-store/fuzz/Cargo.toml",
    "crates/tidefs-validation/fuzz/Cargo.toml",
];

fn check_excluded_fuzz_manifest_licenses(root: &Path, violations: &mut Vec<String>) {
    for rel in EXCLUDED_FUZZ_MANIFESTS {
        let path = root.join(rel);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                violations.push(format!("cannot read excluded fuzz manifest {rel}: {err}"));
                continue;
            }
        };
        match manifest_package_license(&text) {
            Some(license) if license == TIDEFS_LICENSE => {}
            Some(license) => violations.push(format!(
                "excluded fuzz manifest {rel} declares license `{license}`, expected `{TIDEFS_LICENSE}`"
            )),
            None => violations.push(format!(
                "excluded fuzz manifest {rel} must declare package license `{TIDEFS_LICENSE}` explicitly"
            )),
        }
    }
}

fn manifest_package_license(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "license" {
            continue;
        }
        return parse_manifest_string_value(value.trim());
    }
    None
}

fn parse_manifest_string_value(value: &str) -> Option<String> {
    let mut chars = value.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }

    let mut result = String::new();
    let mut escaped = false;
    for ch in chars {
        if quote == '"' && escaped {
            result.push(ch);
            escaped = false;
            continue;
        }
        if quote == '"' && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some(result);
        }
        result.push(ch);
    }
    None
}

const FUSER_GPLV2_EXAMPLE_FILES: &[&str] = &[
    "crates/tidefs-fuser/examples/notify_inval_entry.rs",
    "crates/tidefs-fuser/examples/notify_inval_inode.rs",
    "crates/tidefs-fuser/examples/poll.rs",
    "crates/tidefs-fuser/examples/poll_client.rs",
];

const KERNEL_GPL2_SPDX_FILES: &[&str] = &[
    "crates/tidefs-block-kmod/tidefs_block_kmod.rs",
    "crates/tidefs-kmod-posix-vfs/src/kernel_intent_writer.rs",
    "crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs",
    "crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_shim.c",
    "kmod/smoke_module/rust_tidefs_smoke.rs",
];

const STANDALONE_GPL2_ONLY_SPDX_FILES: &[&str] = ["nix/vm/tidefs-fsync-guest-helper.c"];

const KERNEL_MODULE_LICENSE_FILES: &[&str] = &[
    "crates/tidefs-block-kmod/tidefs_block_kmod.rs",
    "crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs",
    "kmod/smoke_module/rust_tidefs_smoke.rs",
];

const REQUIRED_PROVENANCE_DOC_ENTRIES: &[(&str, &str)] = &[
    ("crates/tidefs-fuser", "MIT"),
    (
        "crates/tidefs-fuser/examples/notify_inval_entry.rs",
        "GPLv2",
    ),
    (
        "crates/tidefs-fuser/examples/notify_inval_inode.rs",
        "GPLv2",
    ),
    ("crates/tidefs-fuser/examples/poll.rs", "GPLv2"),
    ("crates/tidefs-fuser/examples/poll_client.rs", "GPLv2"),
    ("crates/tidefs-block-kmod/tidefs_block_kmod.rs", "GPL-2.0"),
    (
        "crates/tidefs-kmod-posix-vfs/src/kernel_intent_writer.rs",
        "GPL-2.0",
    ),
    (
        "crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_main.rs",
        "GPL-2.0",
    ),
    (
        "crates/tidefs-kmod-posix-vfs/tidefs_posix_vfs_shim.c",
        "GPL-2.0",
    ),
    ("kmod/smoke_module/rust_tidefs_smoke.rs", "GPL-2.0"),
    ("nix/vm/tidefs-fsync-guest-helper.c", "GPL-2.0-only"),
];

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProvenanceMarkerKind {
    SpdxLicense,
    ManifestLicense,
    KernelModuleLicense,
    CopyrightNotice,
    LicenseNotice,
    PermissionNotice,
    StaleLicenseString,
}

impl ProvenanceMarkerKind {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::SpdxLicense => "SPDX license",
            Self::ManifestLicense => "manifest license",
            Self::KernelModuleLicense => "kernel module license",
            Self::CopyrightNotice => "copyright",
            Self::LicenseNotice => "license notice",
            Self::PermissionNotice => "permission notice",
            Self::StaleLicenseString => "stale license string",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProvenanceMarker {
    line: usize,
    kind: ProvenanceMarkerKind,
    value: String,
}

fn check_file_local_provenance_markers(root: &Path, violations: &mut Vec<String>) {
    check_required_provenance_doc_entries(root, violations);

    let files = match tracked_provenance_files(root) {
        Ok(files) => files,
        Err(err) => {
            violations.push(err);
            return;
        }
    };

    for rel_path in files {
        let path = root.join(&rel_path);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                violations.push(format!("cannot read provenance input {rel_path}: {err}"));
                continue;
            }
        };

        for marker in collect_file_local_provenance_markers(&rel_path, &text) {
            if is_registered_provenance_marker(&rel_path, &marker) {
                continue;
            }
            violations.push(format!(
                "{}:{} has unregistered file-local {} marker `{}`; document the exception in docs/LICENSING.md or align it with `{}`",
                rel_path,
                marker.line,
                marker.kind.as_str(),
                provenance_marker_snippet(&marker.value),
                TIDEFS_LICENSE,
            ));
        }
    }
}

fn check_required_provenance_doc_entries(root: &Path, violations: &mut Vec<String>) {
    let rel = "docs/LICENSING.md";
    let text = match fs::read_to_string(root.join(rel)) {
        Ok(text) => text,
        Err(err) => {
            violations.push(format!("cannot read {rel} for provenance inventory: {err}"));
            return;
        }
    };

    for (path, license) in REQUIRED_PROVENANCE_DOC_ENTRIES {
        if !text.contains(path) || !text.contains(license) {
            violations.push(format!(
                "{rel} must document provenance exception `{path}` with license `{license}`"
            ));
        }
    }
}

fn tracked_provenance_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|err| format!("cannot run git ls-files for provenance audit: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "git ls-files failed for provenance audit with status {}",
            output.status
        ));
    }

    Ok(output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8_lossy(entry).into_owned())
        .filter(|rel_path| should_scan_provenance_file(rel_path))
        .collect())
}

fn should_scan_provenance_file(rel_path: &str) -> bool {
    if rel_path == "Cargo.lock"
        || rel_path == "COPYING"
        || rel_path == "docs/LICENSING.md"
        || rel_path.starts_with("LICENSES/")
    {
        return false;
    }

    rel_path == "Cargo.toml"
        || rel_path.ends_with("/Cargo.toml")
        || rel_path.ends_with(".adoc")
        || rel_path.ends_with(".c")
        || rel_path.ends_with(".fio")
        || rel_path.ends_with(".h")
        || rel_path.ends_with(".inc")
        || rel_path.ends_with(".json")
        || rel_path.ends_with(".jsonl")
        || rel_path.ends_with(".md")
        || rel_path.ends_with(".nix")
        || rel_path.ends_with(".patch")
        || rel_path.ends_with(".rs")
        || rel_path.ends_with(".sh")
        || rel_path.ends_with(".txt")
        || rel_path.ends_with(".toml")
        || rel_path.ends_with(".yaml")
        || rel_path.ends_with(".yml")
        || rel_path.ends_with("Dockerfile")
        || rel_path.ends_with(".Dockerfile")
        || rel_path.ends_with("Makefile")
}

fn collect_file_local_provenance_markers(rel_path: &str, text: &str) -> Vec<ProvenanceMarker> {
    let mut markers = Vec::new();
    for (line_idx, raw_line) in text.lines().enumerate() {
        let line_number = line_idx + 1;
        let trimmed = raw_line.trim();
        if trimmed.is_empty() {
            continue;
        }

        if rel_path == "Cargo.toml" || rel_path.ends_with("/Cargo.toml") {
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim() == "license" {
                    if let Some(value) = parse_manifest_string_value(value.trim()) {
                        markers.push(ProvenanceMarker {
                            line: line_number,
                            kind: ProvenanceMarkerKind::ManifestLicense,
                            value,
                        });
                    }
                }
            }
        }

        if let Some((key, value)) = trimmed.split_once(':') {
            if key.trim() == "license" {
                if let Some(value) = parse_manifest_string_value(value.trim()) {
                    markers.push(ProvenanceMarker {
                        line: line_number,
                        kind: ProvenanceMarkerKind::KernelModuleLicense,
                        value,
                    });
                }
            }
        }

        let Some(notice_text) = provenance_notice_text(rel_path, trimmed) else {
            continue;
        };
        let lower_notice = notice_text.to_ascii_lowercase();

        if notice_text.contains("UNLICENSED") || lower_notice.contains("proprietary codebase") {
            markers.push(ProvenanceMarker {
                line: line_number,
                kind: ProvenanceMarkerKind::StaleLicenseString,
                value: notice_text.to_string(),
            });
        }

        if let Some(value) = notice_text.strip_prefix("SPDX-License-Identifier:") {
            markers.push(ProvenanceMarker {
                line: line_number,
                kind: ProvenanceMarkerKind::SpdxLicense,
                value: value.trim().to_string(),
            });
        }

        if notice_text.contains("Copyright") || notice_text.starts_with("SPDX-FileCopyrightText:") {
            markers.push(ProvenanceMarker {
                line: line_number,
                kind: ProvenanceMarkerKind::CopyrightNotice,
                value: notice_text.to_string(),
            });
        }

        if notice_text.contains("Permission is hereby granted") {
            markers.push(ProvenanceMarker {
                line: line_number,
                kind: ProvenanceMarkerKind::PermissionNotice,
                value: notice_text.to_string(),
            });
        }

        if lower_notice.contains("licensed under")
            || notice_text.contains("MIT License")
            || notice_text.contains("Apache License")
            || notice_text.contains("BSD 2-Clause License")
            || notice_text.contains("BSD 3-Clause License")
            || notice_text.contains("Mozilla Public License")
            || notice_text.contains("ISC License")
        {
            markers.push(ProvenanceMarker {
                line: line_number,
                kind: ProvenanceMarkerKind::LicenseNotice,
                value: notice_text.to_string(),
            });
        }
    }
    markers
}

fn provenance_notice_text<'a>(rel_path: &str, trimmed: &'a str) -> Option<&'a str> {
    if is_comment_or_script_style_file(rel_path) {
        return strip_provenance_comment_prefix(trimmed);
    }
    Some(trimmed)
}

fn is_comment_or_script_style_file(rel_path: &str) -> bool {
    rel_path.ends_with(".c")
        || rel_path.ends_with(".fio")
        || rel_path.ends_with(".h")
        || rel_path.ends_with(".inc")
        || rel_path.ends_with(".json")
        || rel_path.ends_with(".nix")
        || rel_path.ends_with(".patch")
        || rel_path.ends_with(".rs")
        || rel_path.ends_with(".sh")
        || rel_path.ends_with(".toml")
        || rel_path.ends_with(".yaml")
        || rel_path.ends_with(".yml")
        || rel_path.ends_with("Dockerfile")
        || rel_path.ends_with(".Dockerfile")
        || rel_path.ends_with("Makefile")
}

fn strip_provenance_comment_prefix(trimmed: &str) -> Option<&str> {
    for prefix in [
        "+//!", "-//!", "+///", "-///", "+//", "-//", "+#", "-#", "//!", "///", "//", "#", ";",
        "*", "/*", "<!--",
    ] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(rest.trim());
        }
    }
    None
}

fn is_registered_provenance_marker(rel_path: &str, marker: &ProvenanceMarker) -> bool {
    match marker.kind {
        ProvenanceMarkerKind::StaleLicenseString => false,
        ProvenanceMarkerKind::SpdxLicense => {
            marker.value == TIDEFS_LICENSE
                || (marker.value == "GPL-2.0" && KERNEL_GPL2_SPDX_FILES.contains(&rel_path))
                || (marker.value == "GPL-2.0-only"
                    && STANDALONE_GPL2_ONLY_SPDX_FILES.contains(&rel_path))
        }
        ProvenanceMarkerKind::ManifestLicense => {
            marker.value == TIDEFS_LICENSE
                || (marker.value == "MIT" && rel_path == "crates/tidefs-fuser/Cargo.toml")
        }
        ProvenanceMarkerKind::KernelModuleLicense => {
            marker.value == "GPL" && KERNEL_MODULE_LICENSE_FILES.contains(&rel_path)
        }
        ProvenanceMarkerKind::CopyrightNotice
        | ProvenanceMarkerKind::LicenseNotice
        | ProvenanceMarkerKind::PermissionNotice => is_registered_notice_file(rel_path),
    }
}

fn is_registered_notice_file(rel_path: &str) -> bool {
    rel_path == "crates/tidefs-fuser/LICENSE.md"
        || rel_path == "crates/tidefs-fuser/README.md"
        || FUSER_GPLV2_EXAMPLE_FILES.contains(&rel_path)
}

fn provenance_marker_snippet(value: &str) -> String {
    const MAX: usize = 96;
    let flattened = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.chars().count() <= MAX {
        flattened
    } else {
        format!("{}...", flattened.chars().take(MAX).collect::<String>())
    }
}

/// Check that workspace members in root Cargo.toml match on-disk crate
/// directories under crates/, apps/, and xtask/. Reports:
/// - Directories with a Cargo.toml that are missing from the members array.
/// - Members entries that point to non-existent directories.
fn check_workspace_member_consistency(root: &Path, violations: &mut Vec<String>) {
    let manifest_path = root.join("Cargo.toml");
    let text = match fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(err) => {
            violations.push(format!(
                "cannot read workspace Cargo.toml {}: {err}",
                manifest_path.display()
            ));
            return;
        }
    };

    // Parse the [workspace] members array from root Cargo.toml
    let mut member_paths: Vec<String> = Vec::new();
    let mut in_workspace = false;
    let mut in_members = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_workspace = trimmed == "[workspace]";
            in_members = false;
            continue;
        }
        if !in_workspace {
            continue;
        }
        if trimmed.starts_with('[') {
            in_workspace = false;
            continue;
        }
        if trimmed.starts_with("members") {
            in_members = true;
            // Parse inline entries on the same line:  members = ["a", "b"]
            if let Some((_, rhs)) = trimmed.split_once('=') {
                let rhs = rhs.trim();
                if rhs.starts_with('[') {
                    // Multi-line: collect quoted strings until ']'
                    collect_member_entries(rhs, &mut member_paths);
                    continue;
                }
            }
        }
        if in_members {
            if trimmed.contains(']') {
                collect_member_entries(trimmed, &mut member_paths);
                in_members = false;
            } else {
                collect_member_entries(trimmed, &mut member_paths);
            }
        }
    }

    let member_set: std::collections::BTreeSet<&str> =
        member_paths.iter().map(|s| s.as_str()).collect();

    // Enumerate on-disk directories under crates/, apps/, and xtask/
    let mut disk_dirs: BTreeMap<String, &str> = BTreeMap::new(); // normalized path -> root_name
    for root_name in ["crates", "apps", "xtask"] {
        let dir = root.join(root_name);
        if !dir.exists() {
            continue;
        }
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            if !path.join("Cargo.toml").exists() {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            disk_dirs.insert(rel, root_name);
        }
    }

    // Check: directories on disk but not in workspace members
    for disk_path in disk_dirs.keys() {
        if !member_set.contains(disk_path.as_str()) {
            violations.push(format!(
                "crate directory {disk_path} exists on disk but is not listed in workspace members"
            ));
        }
    }

    // Check: workspace members pointing to non-existent directories
    for member_path in &member_paths {
        let full = root.join(member_path);
        if !full.exists() || !full.is_dir() || !full.join("Cargo.toml").exists() {
            violations.push(format!(
                "workspace member \"{member_path}\" points to a non-existent directory",
            ));
        }
    }
}

/// Collect double-quoted strings from a TOML array entry line.
/// Strips leading '[' and trailing ']' / ','.
fn collect_member_entries(line: &str, out: &mut Vec<String>) {
    let mut current = String::new();
    let mut in_quote = false;
    for ch in line.chars() {
        match ch {
            '"' => {
                if in_quote {
                    if !current.is_empty() {
                        out.push(current.clone());
                        current.clear();
                    }
                    in_quote = false;
                } else {
                    in_quote = true;
                }
            }
            _ if in_quote => current.push(ch),
            _ => {}
        }
    }
}

const PACKAGE_CLASSIFICATION_DOC: &str = "docs/workspace-package-classification.md";

fn check_package_classification_authority(
    root: &Path,
    members: &[Member],
    violations: &mut Vec<String>,
) {
    let rows = match load_package_classification_rows(root) {
        Ok(rows) => rows,
        Err(err) => {
            violations.push(err);
            return;
        }
    };
    let cargo_members = match cargo_metadata_workspace_packages(root) {
        Ok(packages) => packages,
        Err(err) => {
            violations.push(err);
            return;
        }
    };
    let discovered_manifests = match discover_package_manifest_roots(root) {
        Ok(manifests) => manifests,
        Err(err) => {
            violations.push(err);
            return;
        }
    };

    let workspace_roots: BTreeSet<String> = cargo_members.keys().cloned().collect();
    let excluded_roots = parse_workspace_exclude_set(root);
    let classified_roots: BTreeSet<String> =
        rows.iter().map(|row| row.package_root.clone()).collect();
    let expected_roots: BTreeSet<String> =
        workspace_roots.union(&excluded_roots).cloned().collect();

    check_classification_summary_counts(
        root,
        workspace_roots.len(),
        excluded_roots.len(),
        discovered_manifests.len(),
        rows.len(),
        violations,
    );

    for package_root in expected_roots.difference(&classified_roots) {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} lacks package classification for `{package_root}`"
        ));
    }
    for package_root in classified_roots.difference(&expected_roots) {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} classifies `{package_root}`, but Cargo metadata and workspace.exclude do not"
        ));
    }
    for package_root in discovered_manifests.keys() {
        if !expected_roots.contains(package_root) {
            violations.push(format!(
                "Cargo manifest `{package_root}/Cargo.toml` is neither a workspace member nor listed in workspace.exclude"
            ));
        }
    }
    for package_root in &excluded_roots {
        if !discovered_manifests.contains_key(package_root) {
            violations.push(format!(
                "workspace.exclude lists `{package_root}`, but `{package_root}/Cargo.toml` is not a package manifest"
            ));
        }
    }

    let mut rows_by_root: BTreeMap<&str, &PackageClassificationRow> = BTreeMap::new();
    let mut rows_by_package: BTreeMap<&str, &PackageClassificationRow> = BTreeMap::new();
    for row in &rows {
        if let Some(previous) = rows_by_root.insert(row.package_root.as_str(), row) {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} has duplicate package-root rows `{}` and `{}`",
                previous.package_root, row.package_root
            ));
        }
        if let Some(previous) = rows_by_package.insert(row.package_name.as_str(), row) {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} has duplicate package rows `{}` at `{}` and `{}`",
                row.package_name, previous.package_root, row.package_root
            ));
        }

        let actual_status = if workspace_roots.contains(&row.package_root) {
            Some(ClassificationStatus::WorkspaceMember)
        } else if excluded_roots.contains(&row.package_root) {
            Some(ClassificationStatus::WorkspaceExcluded)
        } else {
            None
        };
        if let Some(actual_status) = actual_status {
            if row.status != actual_status {
                violations.push(format!(
                    "{PACKAGE_CLASSIFICATION_DOC} classifies `{}` as `{}`, but Cargo state is `{}`",
                    row.package_root,
                    row.status.as_str(),
                    actual_status.as_str()
                ));
            }
        }

        let actual_name = cargo_members
            .get(&row.package_root)
            .or_else(|| discovered_manifests.get(&row.package_root));
        match actual_name {
            Some(actual_name) if actual_name == &row.package_name => {}
            Some(actual_name) => violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} names `{}` as `{}`, but its manifest declares `{}`",
                row.package_root, row.package_name, actual_name
            )),
            None => {}
        }

        check_classification_role_boundary(row, violations);
    }

    let excluded_classified_roots: BTreeSet<String> = rows
        .iter()
        .filter(|row| row.status == ClassificationStatus::WorkspaceExcluded)
        .map(|row| row.package_root.clone())
        .collect();
    if excluded_classified_roots != excluded_roots {
        for package_root in excluded_roots.difference(&excluded_classified_roots) {
            violations.push(format!(
                "workspace.exclude lists `{package_root}`, but {PACKAGE_CLASSIFICATION_DOC} does not mark it as workspace-excluded"
            ));
        }
        for package_root in excluded_classified_roots.difference(&excluded_roots) {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} marks `{package_root}` as workspace-excluded, but root Cargo.toml does not exclude it"
            ));
        }
    }

    let reverse_counts = workspace_reverse_dependency_counts(members);
    for member in members {
        let Some(row) = rows_by_package.get(member.name.as_str()) else {
            continue;
        };
        let reverse_count = reverse_counts
            .get(member.name.as_str())
            .copied()
            .unwrap_or(0);
        if reverse_count == 0 && !has_concrete_zero_reverse_disposition(&row.disposition) {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{}` has zero workspace reverse dependencies but disposition `{}` is not concrete",
                row.package_name, row.disposition
            ));
        }
        if row.role == PackageRole::ScaffoldTransitional
            && !has_scaffold_followup_disposition(&row.disposition)
        {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{}` is scaffold-transitional without a TFR-002 follow-up disposition",
                row.package_name
            ));
        }
    }

    check_dependency_role_boundaries(members, &rows_by_package, violations);
}

fn load_package_classification_rows(root: &Path) -> Result<Vec<PackageClassificationRow>, String> {
    let path = root.join(PACKAGE_CLASSIFICATION_DOC);
    let text = fs::read_to_string(&path)
        .map_err(|err| format!("cannot read {PACKAGE_CLASSIFICATION_DOC}: {err}"))?;
    parse_package_classification_rows(&text)
}

fn parse_package_classification_rows(text: &str) -> Result<Vec<PackageClassificationRow>, String> {
    const HEADER: &str = "| Package root | Package | Cargo status | Role | Disposition |";

    let mut rows = Vec::new();
    let mut in_table = false;
    let mut saw_header = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == HEADER {
            in_table = true;
            saw_header = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cells = split_markdown_table_row(line);
        if cells.iter().all(|cell| is_markdown_separator_cell(cell)) {
            continue;
        }
        if cells.len() != 5 {
            return Err(format!(
                "{PACKAGE_CLASSIFICATION_DOC} package table row has {} cells, expected 5: {line}",
                cells.len()
            ));
        }
        let package_root = strip_markdown_code(&cells[0]);
        let package_name = strip_markdown_code(&cells[1]);
        let status_text = strip_markdown_code(&cells[2]);
        let role_text = strip_markdown_code(&cells[3]);
        let status = ClassificationStatus::parse(&status_text).ok_or_else(|| {
            format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{package_root}` has invalid Cargo status `{status_text}`"
            )
        })?;
        let role = PackageRole::parse(&role_text).ok_or_else(|| {
            format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{package_root}` has invalid role `{role_text}`"
            )
        })?;
        let disposition = cells[4].trim().to_string();
        if package_root.is_empty() || package_name.is_empty() || disposition.is_empty() {
            return Err(format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{package_root}` must have non-empty root, package, and disposition"
            ));
        }
        rows.push(PackageClassificationRow {
            package_root,
            package_name,
            status,
            role,
            disposition,
        });
    }

    if !saw_header {
        return Err(format!(
            "{PACKAGE_CLASSIFICATION_DOC} must contain package classification table header `{HEADER}`"
        ));
    }
    Ok(rows)
}

fn split_markdown_table_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn is_markdown_separator_cell(cell: &str) -> bool {
    let trimmed = cell.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch == '-' || ch == ':' || ch == ' ')
}

fn strip_markdown_code(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed
        .strip_prefix('`')
        .and_then(|value| value.strip_suffix('`'))
    {
        stripped.to_string()
    } else {
        trimmed.to_string()
    }
}

fn cargo_metadata_workspace_packages(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let output = Command::new("cargo")
        .current_dir(root)
        .args(["metadata", "--no-deps", "--format-version=1"])
        .output()
        .map_err(|err| format!("cannot run cargo metadata for package classification: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "cargo metadata for package classification failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let metadata: CargoMetadata = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("cannot parse cargo metadata JSON: {err}"))?;
    let workspace_members: BTreeSet<String> = metadata.workspace_members.into_iter().collect();
    let mut packages = BTreeMap::new();
    for package in metadata.packages {
        if !workspace_members.contains(&package.id) {
            continue;
        }
        let package_root = cargo_manifest_package_root(root, &package.manifest_path)?;
        packages.insert(package_root, package.name);
    }
    Ok(packages)
}

fn cargo_manifest_package_root(root: &Path, manifest_path: &str) -> Result<String, String> {
    let manifest_path = Path::new(manifest_path);
    let rel = manifest_path.strip_prefix(root).map_err(|err| {
        format!(
            "cargo metadata manifest path {} is outside root: {err}",
            manifest_path.display()
        )
    })?;
    let rel = rel.to_string_lossy().replace('\\', "/");
    rel.strip_suffix("/Cargo.toml")
        .map(|path| path.to_string())
        .ok_or_else(|| format!("cargo metadata manifest path `{rel}` does not end in /Cargo.toml"))
}

fn discover_package_manifest_roots(root: &Path) -> Result<BTreeMap<String, String>, String> {
    let mut manifests = BTreeMap::new();
    collect_package_manifest_roots(root, root, &mut manifests)?;
    Ok(manifests)
}

fn collect_package_manifest_roots(
    root: &Path,
    current_dir: &Path,
    manifests: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let manifest_path = current_dir.join("Cargo.toml");
    if manifest_path.exists() {
        let text = fs::read_to_string(&manifest_path)
            .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
        if let Some(package_name) = manifest_package_name(&text) {
            let rel_dir = current_dir
                .strip_prefix(root)
                .map_err(|err| format!("strip_prefix {}: {err}", current_dir.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            if !rel_dir.is_empty() {
                manifests.insert(rel_dir, package_name);
            }
        }
    }

    let entries = fs::read_dir(current_dir)
        .map_err(|err| format!("read_dir {}: {err}", current_dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("read_dir {} entry: {err}", current_dir.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if matches!(name, ".git" | "target" | ".direnv" | ".cargo" | ".github") {
            continue;
        }
        collect_package_manifest_roots(root, &path, manifests)?;
    }
    Ok(())
}

fn manifest_package_name(text: &str) -> Option<String> {
    let mut in_package = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "name" {
            continue;
        }
        return parse_manifest_string_value(value.trim());
    }
    None
}

fn parse_workspace_exclude_set(root: &Path) -> BTreeSet<String> {
    parse_workspace_string_array_set(root, "exclude")
}

fn parse_workspace_string_array_set(root: &Path, key: &str) -> BTreeSet<String> {
    let manifest_path = root.join("Cargo.toml");
    let text = match fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(_) => return BTreeSet::new(),
    };
    let mut paths: Vec<String> = Vec::new();
    let mut in_workspace = false;
    let mut in_array = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_workspace = trimmed == "[workspace]";
            in_array = false;
            continue;
        }
        if !in_workspace {
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            if lhs.trim() == key {
                in_array = true;
                collect_member_entries(rhs.trim(), &mut paths);
                if rhs.contains(']') {
                    in_array = false;
                }
                continue;
            }
        }
        if in_array {
            collect_member_entries(trimmed, &mut paths);
            if trimmed.contains(']') {
                in_array = false;
            }
        }
    }
    paths.into_iter().collect()
}

fn check_classification_summary_counts(
    root: &Path,
    workspace_count: usize,
    excluded_count: usize,
    discovered_count: usize,
    classified_count: usize,
    violations: &mut Vec<String>,
) {
    let path = root.join(PACKAGE_CLASSIFICATION_DOC);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            violations.push(format!(
                "cannot read {PACKAGE_CLASSIFICATION_DOC} for count table: {err}"
            ));
            return;
        }
    };
    let counts = parse_classification_count_rows(&text);
    for (label, expected) in [
        ("Workspace packages", workspace_count),
        ("Explicitly excluded package roots", excluded_count),
        ("Discovered package manifests", discovered_count),
        ("Classified package roots", classified_count),
    ] {
        match counts.get(label).copied() {
            Some(actual) if actual == expected => {}
            Some(actual) => violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} count `{label}` is {actual}, expected {expected}"
            )),
            None => violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} must document count `{label}`"
            )),
        }
    }
}

fn parse_classification_count_rows(text: &str) -> BTreeMap<String, usize> {
    const HEADER: &str = "| Counted set | Value |";

    let mut counts = BTreeMap::new();
    let mut in_table = false;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == HEADER {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        if !line.starts_with('|') {
            break;
        }
        let cells = split_markdown_table_row(line);
        if cells.iter().all(|cell| is_markdown_separator_cell(cell)) {
            continue;
        }
        if cells.len() != 2 {
            continue;
        }
        if let Ok(value) = strip_markdown_code(&cells[1]).parse::<usize>() {
            counts.insert(strip_markdown_code(&cells[0]), value);
        }
    }
    counts
}

fn check_classification_role_boundary(
    row: &PackageClassificationRow,
    violations: &mut Vec<String>,
) {
    if row.status == ClassificationStatus::WorkspaceExcluded
        && !matches!(row.role, PackageRole::StandaloneFuzz)
    {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} row `{}` is workspace-excluded but role is `{}`",
            row.package_root,
            row.role.as_str()
        ));
    }
    if row.role == PackageRole::StandaloneFuzz {
        if row.status != ClassificationStatus::WorkspaceExcluded {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{}` is standalone-fuzz but is not workspace-excluded",
                row.package_root
            ));
        }
        if row.package_root != "fuzz" && !row.package_root.ends_with("/fuzz") {
            violations.push(format!(
                "{PACKAGE_CLASSIFICATION_DOC} row `{}` is standalone-fuzz but is not a fuzz package root",
                row.package_root
            ));
        }
    }
    if row.role == PackageRole::VendoredThirdParty
        && (row.package_name != "fuser" || row.package_root != "crates/tidefs-fuser")
    {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} row `{}` uses vendored-third-party outside the vendored fuser package",
            row.package_root
        ));
    }
    if matches!(
        row.role,
        PackageRole::ScaffoldTransitional | PackageRole::ArchiveDeleteCandidate
    ) {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} row `{}` has retired role `{}`; no current package may use a retired role",
            row.package_root,
            row.role.as_str()
        ));
    }
    if row.package_root.starts_with("apps/")
        && !matches!(
            row.role,
            PackageRole::AdapterOperator | PackageRole::ProofHarness
        )
    {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} app root `{}` has role `{}`, expected adapter-operator or proof-harness",
            row.package_root,
            row.role.as_str()
        ));
    }
    if row.package_root.starts_with("xtask/") && row.role != PackageRole::PolicyTooling {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} xtask root `{}` has role `{}`, expected policy-tooling",
            row.package_root,
            row.role.as_str()
        ));
    }
    if (row.package_root == "kmod"
        || row.package_root == "crates/tidefs-block-kmod"
        || row.package_root == "crates/tidefs-kmod-posix-vfs")
        && row.role != PackageRole::AdapterOperator
    {
        violations.push(format!(
            "{PACKAGE_CLASSIFICATION_DOC} kernel-facing root `{}` has role `{}`, expected adapter-operator",
            row.package_root,
            row.role.as_str()
        ));
    }
}

fn workspace_reverse_dependency_counts(members: &[Member]) -> BTreeMap<String, usize> {
    let member_names: BTreeSet<&str> = members.iter().map(|member| member.name.as_str()).collect();
    let mut reverse_counts = BTreeMap::new();
    for member in members {
        for dependency in &member.dependencies {
            if member_names.contains(dependency.as_str()) {
                *reverse_counts.entry(dependency.clone()).or_insert(0) += 1;
            }
        }
    }
    reverse_counts
}

fn has_concrete_zero_reverse_disposition(disposition: &str) -> bool {
    let lower = disposition.to_ascii_lowercase();
    [
        "live entrypoint",
        "operator entrypoint",
        "demo entrypoint",
        "policy gate",
        "planned authority surface",
        "follow-up issue required",
        "vendored dependency",
        "archive/delete candidate",
        "standalone-checkable",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn has_scaffold_followup_disposition(disposition: &str) -> bool {
    let lower = disposition.to_ascii_lowercase();
    lower.contains("tfr-002") && lower.contains("follow-up issue required")
}

fn check_dependency_role_boundaries(
    members: &[Member],
    rows_by_package: &BTreeMap<&str, &PackageClassificationRow>,
    violations: &mut Vec<String>,
) {
    let member_map: BTreeMap<_, _> = members.iter().map(|m| (m.name.as_str(), m)).collect();
    for member in members {
        let Some(source_row) = rows_by_package.get(member.name.as_str()) else {
            continue;
        };
        for dependency in &member.dependencies {
            let Some(_target) = member_map.get(dependency.as_str()) else {
                continue;
            };
            let Some(target_row) = rows_by_package.get(dependency.as_str()) else {
                continue;
            };
            if target_row.role == PackageRole::ArchiveDeleteCandidate
                && source_row.role != PackageRole::ProofHarness
            {
                violations.push(format!(
                    "{} ({}) depends on archive-delete-candidate {}",
                    source_row.package_name,
                    source_row.role.as_str(),
                    target_row.package_name
                ));
            }
            if target_row.role == PackageRole::ScaffoldTransitional
                && matches!(
                    source_row.role,
                    PackageRole::ProductCode
                        | PackageRole::AdapterOperator
                        | PackageRole::PolicyTooling
                )
            {
                violations.push(format!(
                    "{} ({}) depends on scaffold-transitional {}",
                    source_row.package_name,
                    source_row.role.as_str(),
                    target_row.package_name
                ));
            }
        }
    }
}

const STALE_PACKAGE_PROFILE_DOC_NAMES: &[(&str, &str)] = &[
    (
        "cap.package_profile_catalog.block_userspace.c3",
        "cap.package_profile_catalog.block_volume_userspace.c3",
    ),
    (
        "bundle.package_profile_catalog.runtime.block_userspace.b4",
        "bundle.package_profile_catalog.runtime.block_volume_userspace.b4",
    ),
    (
        "tidefs-block_volume_adapterd",
        "tidefs-block-volume-adapter-daemon",
    ),
    (
        "tidefs-explanation_queryd",
        "tidefs-explanation-query-daemon",
    ),
];

fn check_package_profile_doc_name_drift(root: &Path, violations: &mut Vec<String>) {
    let docs_dir = root.join("docs");
    if let Err(err) =
        scan_markdown_for_stale_package_profile_names(&docs_dir, &docs_dir, violations)
    {
        violations.push(err);
    }
}

fn scan_markdown_for_stale_package_profile_names(
    docs_dir: &Path,
    current_dir: &Path,
    violations: &mut Vec<String>,
) -> Result<(), String> {
    if !current_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(current_dir)
        .map_err(|err| format!("read_dir {}: {err}", current_dir.display()))?
    {
        let entry =
            entry.map_err(|err| format!("read_dir {} entry: {err}", current_dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            scan_markdown_for_stale_package_profile_names(docs_dir, &path, violations)?;
            continue;
        }
        if path.extension().and_then(|extension| extension.to_str()) != Some("md") {
            continue;
        }
        let text =
            fs::read_to_string(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
        let rel_path = path
            .strip_prefix(docs_dir)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        collect_stale_package_profile_name_violations(&rel_path, &text, violations);
    }
    Ok(())
}

fn collect_stale_package_profile_name_violations(
    rel_path: &str,
    text: &str,
    violations: &mut Vec<String>,
) {
    for (stale, replacement) in STALE_PACKAGE_PROFILE_DOC_NAMES {
        if text.contains(stale) {
            violations.push(format!(
                "docs/{rel_path} uses stale package-profile spelling `{stale}`; use `{replacement}`"
            ));
        }
    }
}

// ── Secret policy gate ──────────────────────────────────────────────────

/// Classification for a detected forbidden GitHub secret surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SecretViolationClass {
    /// `secrets.*` context expression in a GitHub Actions workflow.
    SecretsContext,
    /// Deploy-key reference (any spelling).
    DeployKey,
    /// Runner registration token reference.
    RunnerToken,
    /// Encrypted secret blob wording that suggests committing encrypted
    /// material to the repository.
    EncryptedBlob,
}

impl SecretViolationClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SecretsContext => "secrets-context",
            Self::DeployKey => "deploy-key",
            Self::RunnerToken => "runner-token",
            Self::EncryptedBlob => "encrypted-blob",
        }
    }
}

impl std::fmt::Display for SecretViolationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Relative paths scanned by the secret-policy gate.
const SECRET_POLICY_SCAN_PATHS: &[&str] = &[".github/workflows/", "docs/GITHUB_CI.md", "AGENTS.md"];

/// Per-line allowlist: (file_rel_path, line_substring).
///
/// These entries suppress false positives where a policy document or
/// detection machinery mentions a forbidden surface for educational or
/// enforcement purposes.
const SECRET_POLICY_ALLOWLIST: &[(&str, &str)] = &[
    // docs/GITHUB_CI.md explains the policy; its mentions are educational.
    ("docs/GITHUB_CI.md", "Do not use GitHub deploy keys"),
    ("docs/GITHUB_CI.md", "`secrets.*` workflow expressions"),
    (
        "docs/GITHUB_CI.md",
        "Secrets such as runner registration tokens",
    ),
    ("docs/GITHUB_CI.md", "encrypted secret payloads"),
    // AGENTS.md references the policy; not secret storage.
    ("AGENTS.md", "`secrets.*`"),
    ("AGENTS.md", "deploy keys"),
    ("AGENTS.md", "runner registration tokens"),
    ("AGENTS.md", "encrypted secret payloads"),
    ("AGENTS.md", "encrypted secret blobs"),
    // The nexus relay workflow references a host-local secret file.
    (
        ".github/workflows/tidefs-codex-nexus-relay.yml",
        "NEXUS_SECRET_FILE",
    ),
    (
        ".github/workflows/tidefs-codex-nexus-relay.yml",
        "/etc/tidefs-codex-nexus/webhook-secret",
    ),
];

const SECRET_POLICY_SEEDED_VIOLATION_FIXTURES: &[(&str, &str, SecretViolationClass)] = &[
    (
        ".github/workflows/seeded-secret-policy-fixture.yml",
        "          TOKEN: ${{ secrets.TIDEFS_SEEDED_TOKEN }}",
        SecretViolationClass::SecretsContext,
    ),
    (
        ".github/workflows/seeded-secret-policy-fixture.yml",
        "          deploy-key: inert-public-fixture",
        SecretViolationClass::DeployKey,
    ),
    (
        ".github/workflows/seeded-secret-policy-fixture.yml",
        "          RUNNER_TOKEN: inert-public-fixture",
        SecretViolationClass::RunnerToken,
    ),
    (
        ".github/workflows/seeded-secret-policy-fixture.yml",
        "          # Store the encrypted secret in GitHub for recovery",
        SecretViolationClass::EncryptedBlob,
    ),
];

// ── Pattern matchers (no regex dependency — simple substring matching) ──

/// Returns the violation class if `line` contains a forbidden secret surface,
/// and the match is not covered by the allowlist for `rel_path`.
fn classify_secret_violation(rel_path: &str, line: &str) -> Option<SecretViolationClass> {
    let lower = line.to_lowercase();

    // 1. secrets.* context — the primary GitHub Actions secret surface.
    if has_secrets_context(line) {
        return Some(SecretViolationClass::SecretsContext);
    }

    if is_secret_policy_allowed(rel_path, line) {
        return None;
    }

    // 2. Deploy key references.
    if lower.contains("deploy_key") || lower.contains("deploy-key") || lower.contains("deploy key")
    {
        return Some(SecretViolationClass::DeployKey);
    }

    // 3. Runner registration token references.
    if lower.contains("registration-token")
        || lower.contains("registration_token")
        || lower.contains("registration token")
        || line.contains("RUNNER_TOKEN")
    {
        return Some(SecretViolationClass::RunnerToken);
    }

    // 4. Encrypted blob wording.
    if lower.contains("encrypted secret")
        || lower.contains("gpg --encrypt")
        || lower.contains("gpg --decrypt")
        || lower.contains("age --encrypt")
        || lower.contains("age --decrypt")
        || lower.contains("openssl enc")
        || lower.contains("openssl rsautl")
        || lower.contains("committed encrypted")
        || line.contains("AGE-SECRET-KEY-1")
    {
        return Some(SecretViolationClass::EncryptedBlob);
    }

    None
}

/// Returns true when `line` uses a `secrets.*` GitHub Actions context
/// expression (both `${{ secrets.X }}` and bare `secrets.X` forms).
fn has_secrets_context(line: &str) -> bool {
    // `${{ secrets.XXX }}` — the canonical expression form.
    if line.contains("${{ secrets.") || line.contains("${{secrets.") {
        return true;
    }
    // Bare `secrets.XXX` used in shell or script steps (without the
    // expression braces).  Must be word-bounded to avoid matching
    // e.g. `nosecrets.foo`.
    let mut search_start = 0;
    while let Some(offset) = line[search_start..].find("secrets.") {
        let pos = search_start + offset;
        // Check left boundary.
        let left_ok = pos == 0 || {
            let before = line.as_bytes()[pos - 1];
            !before.is_ascii_alphanumeric() && before != b'_'
        };
        let after_dot = pos + "secrets.".len();
        let right_ok = matches!(
            line.as_bytes().get(after_dot),
            Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'_'
        );
        if left_ok && right_ok {
            return true;
        }
        search_start = pos + "secrets.".len();
    }
    search_start = 0;
    while let Some(offset) = line[search_start..].find("secrets[") {
        let pos = search_start + offset;
        let left_ok = pos == 0 || {
            let before = line.as_bytes()[pos - 1];
            !before.is_ascii_alphanumeric() && before != b'_'
        };
        let after_bracket = pos + "secrets[".len();
        let right_ok = matches!(line.as_bytes().get(after_bracket), Some(b'\'' | b'"'));
        if left_ok && right_ok {
            return true;
        }
        search_start = pos + "secrets[".len();
    }
    false
}

fn is_secret_policy_allowed(rel_path: &str, line: &str) -> bool {
    for (allow_file, allow_substr) in SECRET_POLICY_ALLOWLIST {
        if rel_path == *allow_file && line.contains(allow_substr) {
            return true;
        }
    }
    // Host-local secret file paths are allowed (secrets live on the runner,
    // not in GitHub).
    if is_host_local_secret_path(line) {
        return true;
    }
    false
}

/// Returns true when `line` references a host-local secret file under
/// `/etc`, `/root`, or `/var/lib` — paths that are clearly not stored in
/// GitHub.
fn is_host_local_secret_path(line: &str) -> bool {
    let lower = line.to_lowercase();
    let mentions_secret = lower.contains("secret");
    if !mentions_secret {
        return false;
    }
    for prefix in &["/etc/", "/root/", "/var/lib/"] {
        if line.contains(prefix) {
            return true;
        }
    }
    false
}

fn format_secret_violation(rel_path: &str, line_no: usize, class: SecretViolationClass) -> String {
    format!("{rel_path}:{line_no}: forbidden GitHub secret surface ({class})")
}

// ── Public entry point ─────────────────────────────────────────────────

pub fn check_secret_policy_current_workspace() -> Result<(), WorkspacePolicyError> {
    let root = find_workspace_root().ok_or_else(|| WorkspacePolicyError {
        violations: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;

    let mut violations = Vec::new();
    let mut seen_any_file = false;

    for rel_glob in SECRET_POLICY_SCAN_PATHS {
        let target = root.join(rel_glob);
        if !target.exists() {
            continue;
        }
        if target.is_dir() {
            let dir_entries = match std::fs::read_dir(&target) {
                Ok(entries) => entries,
                Err(err) => {
                    violations.push(format!(
                        "cannot read secret-policy scan dir {}: {err}",
                        target.display()
                    ));
                    continue;
                }
            };
            for entry in dir_entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(err) => {
                        violations
                            .push(format!("cannot read entry in {}: {err}", target.display()));
                        continue;
                    }
                };
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext != "yml" && ext != "yaml" {
                    continue;
                }
                let rel = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                seen_any_file = true;
                scan_file_for_secret_violations(&root, &rel, &mut violations);
            }
        } else if target.is_file() {
            let rel = rel_glob.to_string();
            seen_any_file = true;
            scan_file_for_secret_violations(&root, &rel, &mut violations);
        }
    }

    if !seen_any_file {
        eprintln!(
            "secret-policy: no scan targets found under {}",
            root.display()
        );
    }

    if violations.is_empty() {
        println!("secret-policy ok");
        Ok(())
    } else {
        Err(WorkspacePolicyError { violations })
    }
}

pub fn check_secret_policy_seeded_violation_fixtures() -> Result<(), WorkspacePolicyError> {
    let mut violations = Vec::new();

    for (idx, (rel_path, line, expected)) in
        SECRET_POLICY_SEEDED_VIOLATION_FIXTURES.iter().enumerate()
    {
        match classify_secret_violation(rel_path, line) {
            Some(actual) if actual == *expected => {}
            Some(actual) => violations.push(format!(
                "secret-policy seeded violation fixture {} classified as {actual}, expected {expected}",
                idx + 1
            )),
            None => violations.push(format!(
                "secret-policy seeded violation fixture {} did not report {expected}",
                idx + 1
            )),
        }
    }

    if violations.is_empty() {
        println!("secret-policy seeded violation fixtures ok");
        Ok(())
    } else {
        Err(WorkspacePolicyError { violations })
    }
}

fn scan_file_for_secret_violations(root: &Path, rel_path: &str, violations: &mut Vec<String>) {
    let full_path = root.join(rel_path);
    let text = match std::fs::read_to_string(&full_path) {
        Ok(t) => t,
        Err(err) => {
            violations.push(format!("cannot read {rel_path}: {err}"));
            return;
        }
    };

    for (line_idx, line_text) in text.lines().enumerate() {
        let line_no = line_idx + 1; // 1-based for human reports.
        if let Some(class) = classify_secret_violation(rel_path, line_text) {
            violations.push(format_secret_violation(rel_path, line_no, class));
        }
    }
}
fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Parse the workspace members list from root Cargo.toml and return
/// the relative paths as a set for efficient lookup.
fn parse_workspace_members_set(root: &Path) -> BTreeSet<String> {
    let manifest_path = root.join("Cargo.toml");
    let text = match fs::read_to_string(&manifest_path) {
        Ok(t) => t,
        Err(_) => return BTreeSet::new(),
    };
    let mut paths: Vec<String> = Vec::new();
    let mut in_workspace = false;
    let mut in_members = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_workspace = trimmed == "[workspace]";
            in_members = false;
            continue;
        }
        if !in_workspace {
            continue;
        }
        if trimmed.starts_with('[') {
            in_workspace = false;
            continue;
        }
        if trimmed.starts_with("members") {
            in_members = true;
            if let Some((_, rhs)) = trimmed.split_once('=') {
                let rhs = rhs.trim();
                if rhs.starts_with('[') {
                    collect_member_entries(rhs, &mut paths);
                    continue;
                }
            }
        }
        if in_members {
            if trimmed.contains(']') {
                collect_member_entries(trimmed, &mut paths);
                in_members = false;
            } else {
                collect_member_entries(trimmed, &mut paths);
            }
        }
    }
    paths.into_iter().collect()
}

/// Resolve a member's relative path from the workspace root.
fn resolve_member_rel_path(_root: &Path, member: &Member) -> String {
    member.rel_path.clone()
}

fn discover_members(root: &Path) -> Result<Vec<Member>, String> {
    let mut members = Vec::new();
    for root_name in ["crates", "apps", "xtask"] {
        let dir = root.join(root_name);
        if !dir.exists() {
            continue;
        }
        let entries =
            fs::read_dir(&dir).map_err(|err| format!("read_dir {}: {err}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("read_dir entry {}: {err}", dir.display()))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("Cargo.toml");
            if !manifest_path.exists() {
                continue;
            }
            members.push(parse_member(root, &manifest_path)?);
        }
    }
    // Scan root-level directories (e.g. kmod/) for workspace members
    // that are not nested under crates/apps/xtask.
    {
        let entries =
            fs::read_dir(root).map_err(|err| format!("read_dir {}: {err}", root.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("read_dir entry {}: {err}", root.display()))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if dir_name == "crates"
                || dir_name == "apps"
                || dir_name == "xtask"
                || dir_name == "docs"
            {
                continue;
            }
            let manifest_path = path.join("Cargo.toml");
            if !manifest_path.exists() {
                continue;
            }
            members.push(parse_member(root, &manifest_path)?);
        }
    }

    // Filter to only include actual workspace members (not all on-disk crates).
    let workspace_member_set = parse_workspace_members_set(root);
    members.retain(|m| {
        let member_path = resolve_member_rel_path(root, m);
        workspace_member_set.contains(&member_path)
    });
    members.sort_by(|lhs, rhs| lhs.name.cmp(&rhs.name));
    Ok(members)
}

fn parse_member(root: &Path, manifest_path: &Path) -> Result<Member, String> {
    let text = fs::read_to_string(manifest_path)
        .map_err(|err| format!("read {}: {err}", manifest_path.display()))?;
    let mut name = None;
    let mut dependencies = Vec::new();
    let mut current_section = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_section.clear();
            current_section.push_str(line);
            continue;
        }
        if current_section == "[package]" && line.starts_with("name") {
            if let Some((_, rhs)) = line.split_once('=') {
                name = Some(trim_quotes(rhs.trim()).to_string());
            }
            continue;
        }
        if current_section == "[dependencies]" {
            if let Some((dep_name, _)) = line.split_once('=') {
                let dep_name = dep_name.trim();
                if dep_name
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
                {
                    dependencies.push(dep_name.to_string());
                }
            }
        }
    }
    let name =
        name.ok_or_else(|| format!("missing package.name in {}", manifest_path.display()))?;
    let rel = manifest_path
        .strip_prefix(root)
        .map_err(|err| format!("strip_prefix {}: {err}", manifest_path.display()))?;
    let rel_path = rel
        .parent()
        .ok_or_else(|| format!("missing parent for {}", manifest_path.display()))?
        .to_string_lossy()
        .to_string();
    let (kind, family, class) = classify_member(rel, &name);
    Ok(Member {
        name,
        rel_path,
        family,
        kind,
        class,
        dependencies,
    })
}

fn trim_quotes(input: &str) -> &str {
    input.trim_matches('"')
}

fn classify_member(rel_manifest_path: &Path, name: &str) -> (NodeKind, Family, CrateClass) {
    let rel = rel_manifest_path.to_string_lossy();
    if rel.starts_with("apps/") {
        return (
            NodeKind::AppRoot,
            classify_app_family(name),
            CrateClass::ServiceRoot,
        );
    }
    if rel.starts_with("xtask/") {
        return (NodeKind::Xtask, Family::Xtask, CrateClass::TestOrXtask);
    }
    (
        NodeKind::Library,
        classify_library_family(name),
        classify_library_class(name),
    )
}

fn classify_app_family(name: &str) -> Family {
    if name == "tidefs-policy-authority-daemon" {
        Family::PolicyAuthority
    } else if name == "tidefs-posix-filesystem-adapter-daemon" {
        Family::PosixFilesystemAdapter
    } else if name == "tidefs-block-volume-adapter-daemon" {
        Family::BlockVolumeAdapter
    } else if name == "tidefs-control-plane-daemon" || name == "tidefsctl" {
        Family::ControlPlane
    } else if name == "tidefs-explanation-query-daemon" || name == "tidefsq" {
        Family::ExplanationQuery
    } else if name == "tidefs-observe-cored" {
        Family::Observe
    } else if name == "tidefs-store-demo" || name == "tidefs-filesystem-demo" {
        Family::Storage
    } else if name == "tidefs-stress" {
        Family::Test
    } else if name == "tidefs-scrub" || name == "tidefs-storage-node" {
        Family::Storage
    } else {
        Family::Unknown
    }
}

fn classify_library_family(name: &str) -> Family {
    if name.starts_with("tidefs-types-") {
        Family::Types
    } else if name.starts_with("tidefs-schema-codec-") {
        Family::SchemaCodec
    } else if name.starts_with("tidefs-policy-authority-") || name == "tidefs-policy-authority" {
        Family::PolicyAuthority
    } else if name.starts_with("tidefs-authority-publication-") {
        Family::AuthorityPublication
    } else if name.starts_with("tidefs-claim-reserve-witness-")
        || name.starts_with("tidefs-claim_reserve_witness-")
    {
        Family::ClaimReserveWitness
    } else if name.starts_with("tidefs-response-normalizer-") {
        Family::ResponseNormalizer
    } else if name.starts_with("tidefs-posix-filesystem-adapter-") {
        Family::PosixFilesystemAdapter
    } else if name.starts_with("tidefs-block-volume-adapter-") || name == "tidefs-ublk-abi" {
        Family::BlockVolumeAdapter
    } else if name.starts_with("tidefs-control-plane-") {
        Family::ControlPlane
    } else if name.starts_with("tidefs-explanation-query-") {
        Family::ExplanationQuery
    } else if name.starts_with("tidefs-secret-key-policy-") {
        Family::PolicyAuthority
    } else if name == "tidefs-observe-core" || name.starts_with("tidefs-observe-core-") {
        Family::Observe
    } else if name.starts_with("tidefs-response-registry-") {
        Family::ResponseRegistry
    } else if name.starts_with("tidefs-local-")
        || name.starts_with("tidefs-storage-")
        || name == "tidefs-membership-epoch"
        || name == "tidefs-replication-model"
        || name.starts_with("tidefs-anti-entropy-")
        || name == "tidefs-auth"
        || name == "tidefs-btree"
        || name.starts_with("tidefs-chunk-shipper")
        || name.starts_with("tidefs-cleanup-")
        || name == "tidefs-clock-timing"
        || name == "tidefs-compression"
        || name.starts_with("tidefs-dir-index")
        || name == "tidefs-encryption"
        || name.starts_with("tidefs-erasure-cod")
        || name.starts_with("tidefs-extent-map")
        || name.starts_with("tidefs-flow-commit-")
        || name == "tidefs-frame"
        || name.starts_with("tidefs-incremental-job-")
        || name == "tidefs-lease"
        || name.starts_with("tidefs-locator-table")
        || name == "tidefs-membership-live"
        || name == "tidefs-membership-types"
        || name == "tidefs-online-verifier"
        || name.starts_with("tidefs-orphan-")
        || name.starts_with("tidefs-placement-")
        || name.starts_with("tidefs-performance-contract")
        || name.starts_with("tidefs-pool-allocator")
        || name.starts_with("tidefs-posix-acl")
        || name.starts_with("tidefs-posix-semantics")
        || name.starts_with("tidefs-quorum-write")
        || name.starts_with("tidefs-rebuild-")
        || name.starts_with("tidefs-reclaim")
        || name.starts_with("tidefs-relocation-")
        || name.starts_with("tidefs-replica-health")
        || name.starts_with("tidefs-replicated-")
        || name == "tidefs-background-scheduler"
        || name == "tidefs-dataset-lifecycle"
        || name == "tidefs-gc-pin-set"
        || name.starts_with("tidefs-spacemap-")
        || name == "tidefs-transport"
        || name.starts_with("tidefs-verification-engine")
        || name.starts_with("tidefs-witness-set")
        || name.starts_with("tidefs-xattr-storage")
        // ── Well-known storage crates not covered by existing prefixes ──
        || name.starts_with("tidefs-binary_schema-")
        || name.starts_with("tidefs-block-")
        || name.starts_with("tidefs-cache-")
        || name.starts_with("tidefs-checksum-")
        || name.starts_with("tidefs-claim-")
        || name.starts_with("tidefs-commit_group")
        || name.starts_with("tidefs-compaction")
        || name.starts_with("tidefs-contention-")
        || name.starts_with("tidefs-coordination-")
        || name.starts_with("tidefs-dataset-")
        || name.starts_with("tidefs-data-")
        || name.starts_with("tidefs-dedup")
        || name.starts_with("tidefs-derived-")
        || name.starts_with("tidefs-device-")
        || name.starts_with("tidefs-durability-")
        || name == "tidefs-fuser"
        || name == "fuser"
        || name.starts_with("tidefs-geometry-")
        || name.starts_with("tidefs-inode-")
        || name.starts_with("tidefs-intent-")
        || name.starts_with("tidefs-invalidation-")
        || name.starts_with("tidefs-kernel-")
        || name.starts_with("tidefs-kmod-")
        || name.starts_with("tidefs-lease-")
        || name.starts_with("tidefs-lock-")
        || name.starts_with("tidefs-namespace")
        || name.starts_with("tidefs-node-")
        || name.starts_with("tidefs-offload-")
        || name.starts_with("tidefs-object-")
        || name.starts_with("tidefs-online-")
        || name.starts_with("tidefs-partition-")
        || name.starts_with("tidefs-permission")
        || name.starts_with("tidefs-pool-")
        || name.starts_with("tidefs-posix-guarantee-")
        || name.starts_with("tidefs-rebalance-")
        || name.starts_with("tidefs-receive-")
        || name.starts_with("tidefs-recovery-")
        || name == "tidefs-replication"
        || name.starts_with("tidefs-reserve-")
        || name.starts_with("tidefs-scrub-")
        || name.starts_with("tidefs-segment-")
        || name.starts_with("tidefs-send-")
        || name.starts_with("tidefs-shard-")
        || name.starts_with("tidefs-snapshot-")
        || name.starts_with("tidefs-space-accounting")
        || name.starts_with("tidefs-strategy-")
        || name.starts_with("tidefs-tdma-")
        || name.starts_with("tidefs-vfs-")
        || name == "tidefs-cluster"
        || name == "tidefs-workload"
    {
        Family::Storage
    } else if name.starts_with("tidefs-test-")
        || name == "tidefs-model-core"
        || name == "tidefs-crash-oracle"
        || name == "tidefs-distributed-model-check"
        || name == "tidefs-env-fuse-model"
        || name == "tidefs-env-ublk-model"
        || name == "tidefs-trace-oracle"
        || name == "tidefs-two-node-harness"
        || name == "tidefs-validation"
    {
        Family::Test
    } else {
        Family::Unknown
    }
}

fn classify_library_class(name: &str) -> CrateClass {
    if name == "tidefs-model-core"
        || name == "tidefs-crash-oracle"
        || name == "tidefs-distributed-model-check"
        || name == "tidefs-env-fuse-model"
        || name == "tidefs-env-ublk-model"
    {
        CrateClass::TestOrXtask
    } else if name.starts_with("tidefs-types-") {
        CrateClass::Types
    } else if name.starts_with("tidefs-schema-codec-") {
        CrateClass::Schema
    } else if name.ends_with("-api")
        || name.ends_with("-abi")
        || name.ends_with("-contract")
        || name.ends_with("-traits")
    {
        CrateClass::Api
    } else if name == "tidefs-observe-core" {
        CrateClass::Observe
    } else if name.ends_with("-core")
        || name.ends_with("-policy")
        || name.ends_with("-planner")
        || name.ends_with("-scheduler")
        || name.ends_with("-workers-io")
        || name.ends_with("-workers-locks")
    {
        CrateClass::Core
    } else if name.ends_with("-runtime") || name.ends_with("-async") || name.ends_with("-exec") {
        CrateClass::Runtime
    } else if name.ends_with("-client") {
        CrateClass::Client
    } else if name.ends_with("-render") || name.ends_with("-view") || name.ends_with("-trace") {
        CrateClass::Render
    } else if name.ends_with("-query") {
        CrateClass::Query
    } else if name.ends_with("-observe") || name.ends_with("-gate") || name.ends_with("-validation")
    {
        CrateClass::Observe
    } else if name == "tidefs-membership-epoch"
        || name == "tidefs-membership-types"
        || name == "tidefs-replication-model"
    {
        CrateClass::Core
    } else if name.ends_with("-store")
        || name.contains("-object-store")
        || name.contains("-filesystem")
    {
        CrateClass::Storage
    } else if name.starts_with("tidefs-test-") || name == "tidefs-trace-oracle" {
        CrateClass::TestOrXtask
    } else {
        // Default for Storage-family crates without a recognized suffix.
        CrateClass::Core
    }
}

fn is_edge_allowed(source: &Member, target: &Member) -> bool {
    // Xtask targets are never allowed; AppRoot targets allowed only
    // when source and target have different families (exe-depends-on-exe)
    if matches!(target.kind, NodeKind::Xtask) {
        return false;
    }
    if target.kind == NodeKind::AppRoot && source.family == target.family {
        return false;
    }
    if source.family == Family::Unknown || target.family == Family::Unknown {
        return false;
    }
    if source.kind == NodeKind::Xtask {
        return true;
    }
    if source.kind == NodeKind::AppRoot {
        // AppRoot targets (exe-depends-on-exe) are allowed across different families
        if target.kind == NodeKind::AppRoot && source.family != target.family {
            return true;
        }
        // BlockVolumeAdapter targets: any class
        if target.family == Family::BlockVolumeAdapter {
            return true;
        }
        // PosixFilesystemAdapter targets: any class
        if target.family == Family::PosixFilesystemAdapter
            && source.family != Family::PosixFilesystemAdapter
        {
            return true;
        }
        return matches!(
            target.family,
            Family::Types | Family::SchemaCodec | Family::Observe | Family::Storage | Family::Test
        ) || (target.family == source.family
            && matches!(
                target.class,
                CrateClass::Runtime
                    | CrateClass::Client
                    | CrateClass::Api
                    | CrateClass::Core
                    | CrateClass::Storage
            ))
            || (source.family == Family::Storage
                && target.family == Family::Storage
                && matches!(
                    target.class,
                    CrateClass::Core | CrateClass::Runtime | CrateClass::Client
                ));
    }
    if source.family == target.family {
        return true;
    }
    match source.family {
        Family::Types => matches!(target.family, Family::Types),
        Family::SchemaCodec => matches!(target.family, Family::Types | Family::SchemaCodec),
        Family::AuthorityPublication
        | Family::ClaimReserveWitness
        | Family::ResponseRegistry
        | Family::ResponseNormalizer => {
            matches!(target.family, Family::Types | Family::SchemaCodec)
        }
        Family::PolicyAuthority => matches!(
            target.family,
            Family::Types
                | Family::SchemaCodec
                | Family::AuthorityPublication
                | Family::ClaimReserveWitness
                | Family::ResponseNormalizer
                | Family::Observe
        ),
        Family::PosixFilesystemAdapter | Family::BlockVolumeAdapter => {
            matches!(
                target.family,
                Family::Types
                    | Family::SchemaCodec
                    | Family::ResponseRegistry
                    | Family::ResponseNormalizer
                    | Family::Observe
                    | Family::Storage
            ) || (target.family == Family::PolicyAuthority
                && matches!(target.class, CrateClass::Api | CrateClass::Client))
        }
        Family::ControlPlane | Family::ExplanationQuery => {
            matches!(
                target.family,
                Family::Types
                    | Family::SchemaCodec
                    | Family::ResponseRegistry
                    | Family::ResponseNormalizer
                    | Family::Observe
                    | Family::Storage
            ) || (target.family == Family::PolicyAuthority
                && matches!(target.class, CrateClass::Api | CrateClass::Client))
        }
        Family::Observe => {
            matches!(target.family, Family::Types | Family::SchemaCodec)
                || matches!(
                    target.class,
                    CrateClass::Api | CrateClass::Render | CrateClass::Schema
                )
        }
        Family::Storage => matches!(
            target.family,
            Family::Types | Family::SchemaCodec | Family::Storage | Family::PosixFilesystemAdapter
        ),
        Family::Test => target.kind == NodeKind::Library || target.kind == NodeKind::AppRoot,
        Family::Xtask | Family::Unknown => false,
    }
}

/// Check which workspace crates have zero consumers (dead crates).
/// Scans all workspace member Cargo.toml files for `dependencies`,
/// [dev-dependencies], and [build-dependencies] sections to build a
/// consumer set, then reports any crate that appears in zero dependency
/// lists as potentially dead.
///
/// Also scans Rust source files for `use <crate_name>::` patterns as a
/// secondary signal: a crate may be imported via a renamed dependency or
/// through a path dependency with a different package name.
pub fn check_dead_crates_current_workspace() -> Result<(), WorkspacePolicyError> {
    let root = find_workspace_root().ok_or_else(|| WorkspacePolicyError {
        violations: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let members = discover_members(&root).map_err(|err| WorkspacePolicyError {
        violations: vec![err],
    })?;

    // Only audit library crates (not app daemons, xtask, or test helpers)
    let library_members: Vec<&Member> = members
        .iter()
        .filter(|m| matches!(m.kind, NodeKind::Library))
        .collect();

    // Collect all dependency names from every workspace Cargo.toml
    // (includes [dependencies], [dev-dependencies], [build-dependencies])
    let mut consumers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for member in &members {
        let manifest_path = resolve_member_manifest(&root, member);
        let deps = extract_all_dependency_names(&manifest_path);
        for dep_name in deps {
            consumers
                .entry(dep_name)
                .or_default()
                .push(member.name.clone());
        }
    }

    // Rust use-statement scan as secondary signal
    let mut rust_importers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for member in &members {
        let crate_dir = resolve_member_dir(&root, member);
        let imported = scan_rust_use_statements(&crate_dir);
        for imported_name in imported {
            // Exclude self-imports (a crate importing its own types)
            if imported_name == member.name {
                continue;
            }
            rust_importers
                .entry(imported_name)
                .or_default()
                .push(member.name.clone());
        }
    }

    // Dead = not in Cargo.toml consumer set AND not in Rust use-import set
    let dead: Vec<&&Member> = library_members
        .iter()
        .filter(|m| !consumers.contains_key(&m.name) && !rust_importers.contains_key(&m.name))
        .collect();

    // Suspicious = Rust use-imports exist but no Cargo.toml dependency entry
    let suspicious: Vec<&&Member> = library_members
        .iter()
        .filter(|m| !consumers.contains_key(&m.name) && rust_importers.contains_key(&m.name))
        .collect();

    if dead.is_empty() && suspicious.is_empty() {
        println!(
            "dead-crate audit ok: all {} library crates have consumers ({} total workspace members)",
            library_members.len(),
            members.len()
        );
        return Ok(());
    }

    if !dead.is_empty() {
        println!("=== DEAD CRATES (zero Cargo.toml consumers, zero Rust imports) ===");
        for m in &dead {
            let dir = resolve_member_dir(&root, m);
            let loc = count_rs_loc(&dir);
            println!("  {}  ({} Rust LOC, {})", m.name, loc, dir.display());
        }
    }

    if !suspicious.is_empty() {
        println!();
        println!("=== SUSPICIOUS (Rust use-imports exist but no Cargo.toml dependency) ===");
        println!("    These have Rust `use` references but no Cargo.toml [dependencies] entry.");
        println!("    They may be path dependencies with renamed keys. Do NOT remove without");
        println!("    verifying the Cargo.toml dependency key matches the package name.");
        for m in &suspicious {
            let importers = rust_importers
                .get(&m.name)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let dir = resolve_member_dir(&root, m);
            let loc = count_rs_loc(&dir);
            println!(
                "  {}  ({} Rust LOC, imported by: [{}], {})",
                m.name,
                loc,
                importers.join(", "),
                dir.display()
            );
        }
    }

    println!();
    println!(
        "audit complete: {} library crates, {} dead, {} suspicious, {} total members",
        library_members.len(),
        dead.len(),
        suspicious.len(),
        members.len()
    );

    // Never error-exit: dead crates are informational, not policy violations
    Ok(())
}

/// Build the on-disk Cargo.toml path for a workspace member.
fn resolve_member_manifest(root: &Path, member: &Member) -> PathBuf {
    root.join(&member.rel_path).join("Cargo.toml")
}

/// Build the on-disk directory path for a workspace member.
fn resolve_member_dir(root: &Path, member: &Member) -> PathBuf {
    resolve_member_manifest(root, member)
        .parent()
        .unwrap_or(root)
        .to_path_buf()
}

/// Extract all dependency names from a Cargo.toml file, scanning
/// `dependencies`, [dev-dependencies], and [build-dependencies] sections.
/// Handles both `"dep-name"` and `dep-name = { ... }` syntax.
fn extract_all_dependency_names(manifest_path: &Path) -> Vec<String> {
    let text = match fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let mut names = Vec::new();
    let dep_sections = [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
    ];
    let mut in_target_section = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_target_section = dep_sections.contains(&trimmed);
            continue;
        }
        if !in_target_section {
            continue;
        }
        if trimmed.starts_with('[') {
            in_target_section = false;
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=') {
            let key = key.trim();
            let dep_name = if key.starts_with('"') && key.ends_with('"') {
                key[1..key.len() - 1].to_string()
            } else if key
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            {
                key.to_string()
            } else {
                continue;
            };
            if !dep_name.is_empty() {
                names.push(dep_name);
            }
        }
    }

    names
}

/// Scan Rust source files in a directory for `use <crate>::...` patterns,
/// returning crate names that are imported.
fn scan_rust_use_statements(dir: &Path) -> Vec<String> {
    let mut crate_names: BTreeSet<String> = BTreeSet::new();
    let src_dir = dir.join("src");
    if !src_dir.exists() {
        return Vec::new();
    }
    let entries = match fs::read_dir(&src_dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with("use ") {
                continue;
            }
            let rest = &trimmed[4..]; // skip "use "
            if let Some(first_seg) = rest.split("::").next() {
                let name = first_seg.trim();
                if name != "self" && name != "super" && name != "crate" && !name.is_empty() {
                    crate_names.insert(name.replace('_', "-"));
                }
            }
        }
    }
    crate_names.into_iter().collect()
}

/// Count lines of Rust source code in a crate directory.
fn count_rs_loc(dir: &Path) -> usize {
    let src_dir = dir.join("src");
    if !src_dir.exists() {
        return 0;
    }
    let mut total = 0_usize;
    let entries = match fs::read_dir(&src_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&path) {
            total += text.lines().count();
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(kind: NodeKind, family: Family, class: CrateClass) -> Member {
        Member {
            name: "synthetic".to_string(),
            rel_path: "crates/synthetic".to_string(),
            family,
            kind,
            class,
            dependencies: Vec::new(),
        }
    }

    #[test]
    fn control_plane_library_may_use_policy_authority_client_but_not_runtime() {
        let source = member(NodeKind::Library, Family::ControlPlane, CrateClass::Api);
        let policy_authority_client = member(
            NodeKind::Library,
            Family::PolicyAuthority,
            CrateClass::Client,
        );
        let policy_authority_runtime = member(
            NodeKind::Library,
            Family::PolicyAuthority,
            CrateClass::Runtime,
        );
        assert!(is_edge_allowed(&source, &policy_authority_client));
        assert!(!is_edge_allowed(&source, &policy_authority_runtime));
    }

    #[test]
    fn app_root_may_reach_into_same_family_api_and_core() {
        let source = member(
            NodeKind::AppRoot,
            Family::ControlPlane,
            CrateClass::ServiceRoot,
        );
        let control_plane_api = member(NodeKind::Library, Family::ControlPlane, CrateClass::Api);
        let control_plane_runtime =
            member(NodeKind::Library, Family::ControlPlane, CrateClass::Runtime);
        let types = member(NodeKind::Library, Family::Types, CrateClass::Types);
        let block_app = member(
            NodeKind::AppRoot,
            Family::BlockVolumeAdapter,
            CrateClass::ServiceRoot,
        );
        let block_core = member(
            NodeKind::Library,
            Family::BlockVolumeAdapter,
            CrateClass::Core,
        );
        let block_api = member(
            NodeKind::Library,
            Family::BlockVolumeAdapter,
            CrateClass::Api,
        );
        assert!(is_edge_allowed(&source, &control_plane_api));
        assert!(is_edge_allowed(&source, &control_plane_runtime));
        assert!(is_edge_allowed(&source, &types));
        assert!(is_edge_allowed(&block_app, &block_core));
        assert!(is_edge_allowed(&block_app, &block_api));
    }

    #[test]
    fn schema_codec_and_types_keep_foundation_direction() {
        let types = member(NodeKind::Library, Family::Types, CrateClass::Types);
        let schema_codec = member(NodeKind::Library, Family::SchemaCodec, CrateClass::Schema);
        let control_plane = member(NodeKind::Library, Family::ControlPlane, CrateClass::Api);
        assert!(is_edge_allowed(&schema_codec, &types));
        assert!(!is_edge_allowed(&types, &schema_codec));
        assert!(!is_edge_allowed(&schema_codec, &control_plane));
    }

    #[test]
    fn control_plane_runtime_may_use_policy_authority_client_and_schema_codec_control_plane() {
        let source = member(NodeKind::Library, Family::ControlPlane, CrateClass::Runtime);
        let policy_authority_client = member(
            NodeKind::Library,
            Family::PolicyAuthority,
            CrateClass::Client,
        );
        let schema_codec_schema =
            member(NodeKind::Library, Family::SchemaCodec, CrateClass::Schema);
        assert!(is_edge_allowed(&source, &policy_authority_client));
        assert!(is_edge_allowed(&source, &schema_codec_schema));
    }

    #[test]
    fn name_classifiers_cover_current_workspace_families() {
        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-types-vfs-core/Cargo.toml"),
            "tidefs-types-vfs-core",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Types);
        assert_eq!(class, CrateClass::Types);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-schema-codec-vfs/Cargo.toml"),
            "tidefs-schema-codec-vfs",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::SchemaCodec);
        assert_eq!(class, CrateClass::Schema);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-secret-key-policy-runtime/Cargo.toml"),
            "tidefs-secret-key-policy-runtime",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::PolicyAuthority);
        assert_eq!(class, CrateClass::Runtime);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-local-object-store/Cargo.toml"),
            "tidefs-local-object-store",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Storage);
        assert_eq!(class, CrateClass::Storage);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-local-filesystem/Cargo.toml"),
            "tidefs-local-filesystem",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Storage);
        assert_eq!(class, CrateClass::Storage);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-membership-epoch/Cargo.toml"),
            "tidefs-membership-epoch",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Storage);
        assert_eq!(class, CrateClass::Core);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-replication-model/Cargo.toml"),
            "tidefs-replication-model",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Storage);
        assert_eq!(class, CrateClass::Core);

        let (kind, family, class) = classify_member(
            Path::new("apps/tidefs-filesystem-demo/Cargo.toml"),
            "tidefs-filesystem-demo",
        );
        assert_eq!(kind, NodeKind::AppRoot);
        assert_eq!(family, Family::Storage);
        assert_eq!(class, CrateClass::ServiceRoot);

        let (kind, family, class) =
            classify_member(Path::new("apps/tidefsctl/Cargo.toml"), "tidefsctl");
        assert_eq!(kind, NodeKind::AppRoot);
        assert_eq!(family, Family::ControlPlane);
        assert_eq!(class, CrateClass::ServiceRoot);

        let (kind, family, class) =
            classify_member(Path::new("xtask/tidefs-xtask/Cargo.toml"), "tidefs-xtask");
        assert_eq!(kind, NodeKind::Xtask);
        assert_eq!(family, Family::Xtask);
        assert_eq!(class, CrateClass::TestOrXtask);
    }

    #[test]
    fn package_classification_table_parses_structured_rows() {
        let text = r#"
# Example

| Package root | Package | Cargo status | Role | Disposition |
| --- | --- | --- | --- | --- |
| `crates/tidefs-local-object-store` | `tidefs-local-object-store` | `workspace-member` | `product-code` | current product component; capability claims remain limited. |
| `fuzz` | `tidefs-fuzz` | `workspace-excluded` | `standalone-fuzz` | standalone-checkable fuzz package. |
"#;
        let rows = parse_package_classification_rows(text).expect("classification rows");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].package_root, "crates/tidefs-local-object-store");
        assert_eq!(rows[0].status, ClassificationStatus::WorkspaceMember);
        assert_eq!(rows[0].role, PackageRole::ProductCode);
        assert_eq!(rows[1].package_root, "fuzz");
        assert_eq!(rows[1].status, ClassificationStatus::WorkspaceExcluded);
        assert_eq!(rows[1].role, PackageRole::StandaloneFuzz);
    }

    #[test]
    fn current_workspace_policy_authority_is_current() {
        check_current_workspace().expect("workspace policy authority is current");
    }

    #[test]
    fn retired_package_roles_are_rejected() {
        let mut violations = Vec::new();
        for role in [
            PackageRole::ScaffoldTransitional,
            PackageRole::ArchiveDeleteCandidate,
        ] {
            let row = PackageClassificationRow {
                package_root: format!("crates/{}", role.as_str()),
                package_name: role.as_str().to_string(),
                status: ClassificationStatus::WorkspaceMember,
                role,
                disposition: "retired role fixture".to_string(),
            };
            check_classification_role_boundary(&row, &mut violations);
        }

        assert_eq!(violations.len(), 2);
        assert!(violations
            .iter()
            .any(|violation| violation.contains("retired role `scaffold-transitional`")));
        assert!(violations
            .iter()
            .any(|violation| violation.contains("retired role `archive-delete-candidate`")));
    }

    #[test]
    fn stale_package_profile_doc_names_are_reported() {
        let mut violations = Vec::new();
        collect_stale_package_profile_name_violations(
            "example.md",
            "`bundle.package_profile_catalog.runtime.block_userspace.b4` names `tidefs-block_volume_adapterd`",
            &mut violations,
        );

        assert_eq!(violations.len(), 2);
        assert!(violations[0].contains("block_userspace"));
        assert!(violations[1].contains("tidefs-block_volume_adapterd"));
    }

    #[test]
    fn current_package_profile_doc_names_are_accepted() {
        let mut violations = Vec::new();
        collect_stale_package_profile_name_violations(
            "example.md",
            "`bundle.package_profile_catalog.runtime.block_volume_userspace.b4` names `tidefs-block-volume-adapter-daemon`",
            &mut violations,
        );

        assert!(violations.is_empty());
    }

    #[test]
    fn file_local_provenance_accepts_tidefs_spdx_marker() {
        let text = "// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note\n";
        let markers =
            collect_file_local_provenance_markers("crates/tidefs-example/src/lib.rs", text);

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::SpdxLicense);
        assert!(is_registered_provenance_marker(
            "crates/tidefs-example/src/lib.rs",
            &markers[0],
        ));
    }

    #[test]
    fn file_local_provenance_rejects_unregistered_apache_spdx_marker() {
        let text = "// SPDX-License-Identifier: Apache-2.0\n";
        let markers =
            collect_file_local_provenance_markers("crates/tidefs-example/src/lib.rs", text);

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::SpdxLicense);
        assert!(!is_registered_provenance_marker(
            "crates/tidefs-example/src/lib.rs",
            &markers[0],
        ));
    }

    #[test]
    fn file_local_provenance_accepts_registered_kernel_module_markers() {
        let text = concat!(
            "// SPDX-License-Identifier: GPL-2.0\n",
            "license: \"GPL\",\n",
        );
        let markers =
            collect_file_local_provenance_markers("kmod/smoke_module/rust_tidefs_smoke.rs", text);

        assert_eq!(markers.len(), 2);
        assert!(markers.iter().all(|marker| is_registered_provenance_marker(
            "kmod/smoke_module/rust_tidefs_smoke.rs",
            marker,
        )));
    }

    #[test]
    fn file_local_provenance_accepts_registered_fuser_notices() {
        let text = r#"
The MIT License (MIT)
Copyright (c) 2020-present Christopher Berner
Permission is hereby granted, free of charge, to any person obtaining a copy of
"#;
        let markers = collect_file_local_provenance_markers("crates/tidefs-fuser/LICENSE.md", text);

        assert_eq!(markers.len(), 3);
        assert!(markers.iter().all(|marker| is_registered_provenance_marker(
            "crates/tidefs-fuser/LICENSE.md",
            marker,
        )));
    }

    #[test]
    fn file_local_provenance_flags_stale_license_strings() {
        let text = "# Permissive licenses compatible with UNLICENSED proprietary codebase\n";
        let markers = collect_file_local_provenance_markers("deny.toml", text);

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::StaleLicenseString);
        assert!(!is_registered_provenance_marker("deny.toml", &markers[0]));
    }

    #[test]
    fn file_local_provenance_accepts_registered_fuser_manifest_license() {
        let text = r#"
[package]
name = "fuser"
license = "MIT"
"#;
        let markers = collect_file_local_provenance_markers("crates/tidefs-fuser/Cargo.toml", text);

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::ManifestLicense);
        assert!(is_registered_provenance_marker(
            "crates/tidefs-fuser/Cargo.toml",
            &markers[0],
        ));
    }

    #[test]
    fn file_local_provenance_scans_docs_and_harness_inputs() {
        for rel_path in [
            "docs/book/chapters/00-preface.adoc",
            "validation/fio/rand-read.fio",
            "benchmarking/fio/common/global.inc",
            "traces/golden/smoke_churn/pool_trace.jsonl",
            "validation/seed-corpus/fsx-seeds.txt",
            "crates/tidefs-witness-set/tests/witness_convergence_fix.patch",
        ] {
            assert!(
                should_scan_provenance_file(rel_path),
                "expected {rel_path} to be scanned"
            );
        }
    }

    #[test]
    fn file_local_provenance_keeps_canonical_license_texts_out_of_scan() {
        for rel_path in [
            "Cargo.lock",
            "COPYING",
            "docs/LICENSING.md",
            "LICENSES/preferred/GPL-2.0",
        ] {
            assert!(
                !should_scan_provenance_file(rel_path),
                "expected {rel_path} to be excluded"
            );
        }
    }

    #[test]
    fn file_local_provenance_flags_plaintext_harness_spdx_marker() {
        let text = "SPDX-License-Identifier: Apache-2.0\n";
        let markers =
            collect_file_local_provenance_markers("validation/seed-corpus/fsx-seeds.txt", text);

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::SpdxLicense);
        assert!(!is_registered_provenance_marker(
            "validation/seed-corpus/fsx-seeds.txt",
            &markers[0],
        ));
    }

    #[test]
    fn file_local_provenance_flags_patch_comment_spdx_marker() {
        let text = "+// SPDX-License-Identifier: Apache-2.0\n";
        let markers = collect_file_local_provenance_markers(
            "crates/tidefs-witness-set/tests/witness_convergence_fix.patch",
            text,
        );

        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].kind, ProvenanceMarkerKind::SpdxLicense);
        assert!(!is_registered_provenance_marker(
            "crates/tidefs-witness-set/tests/witness_convergence_fix.patch",
            &markers[0],
        ));
    }

    #[test]
    fn manifest_package_license_reads_package_section_only() {
        let text = r#"
[package.metadata]
license = "MIT"

[package]
name = "example"
license = "GPL-2.0-only WITH Linux-syscall-note" # inline note

[[bin]]
name = "example"
"#;

        assert_eq!(
            manifest_package_license(text).as_deref(),
            Some("GPL-2.0-only WITH Linux-syscall-note")
        );
    }

    #[test]
    fn manifest_package_license_ignores_nonpackage_license() {
        let text = r#"
[package.metadata]
license = "GPL-2.0-only WITH Linux-syscall-note"
"#;

        assert_eq!(manifest_package_license(text), None);
    }

    // ── Secret policy gate tests ───────────────────────────────────────

    #[test]
    fn secrets_context_expression_is_detected() {
        let line = "          TOKEN: ${{ secrets.DEPLOY_TOKEN }}";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn secrets_context_without_spaces_is_detected() {
        let line = "          TOKEN: ${{secrets.DEPLOY_TOKEN}}";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn bare_secrets_dot_is_detected() {
        let line = "          run: echo \"$SECRET\" | secrets.REGISTRY_PASS";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn indexed_secrets_context_expression_is_detected() {
        let line = "          TOKEN: ${{ secrets['DEPLOY_TOKEN'] }}";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn indexed_secrets_context_without_spaces_is_detected() {
        let line = "          TOKEN: ${{secrets[\"DEPLOY_TOKEN\"]}}";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn wildcard_secret_context_doc_pattern_is_not_bare_use() {
        let line = "Do not use `secrets.*` workflow expressions";
        assert!(!has_secrets_context(line));
    }

    #[test]
    fn non_secrets_word_is_not_flagged() {
        let line = "          run: echo \"no secrets here\"";
        assert!(!has_secrets_context(line));
    }

    #[test]
    fn adjacent_word_nosecrets_is_not_flagged() {
        let line = "          run: echo nosecrets.foo";
        // "nosecrets." — the 'e' before 's' is alphanumeric, so not a hit.
        assert!(!has_secrets_context(line));
    }

    #[test]
    fn later_bare_secrets_dot_after_adjacent_word_is_detected() {
        let line = "          run: echo nosecrets.foo && echo secrets.REGISTRY_PASS";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn later_bare_secrets_dot_after_wildcard_is_detected() {
        let line = "          run: echo 'secrets.*' && echo secrets.REGISTRY_PASS";
        assert!(has_secrets_context(line));
    }

    #[test]
    fn deploy_key_lowercase_is_detected() {
        let line = "          deploy_key: ${{ secrets.SSH_KEY }}";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn deploy_key_hyphenated_is_detected() {
        let line = "          deploy-key: value";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn deploy_key_with_space_is_detected() {
        let line = "# Add a deploy key to the repository";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn runner_registration_token_is_detected() {
        let line = "          run: ./config.sh --token ${{ secrets.RUNNER_REGISTRATION_TOKEN }}";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn runner_token_env_var_is_detected() {
        let line = "          RUNNER_TOKEN: ${{ secrets.RUNNER_TOKEN }}";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn encrypted_secret_wording_is_detected() {
        let line = "          # Store the encrypted secret in the repo for recovery";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn gpg_encrypt_command_is_detected() {
        let line = "          run: gpg --encrypt --recipient ci@example.com secret.txt";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn age_encrypt_command_is_detected() {
        let line = "          run: age --encrypt -r age1... secret.txt";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn age_secret_key_literal_is_detected() {
        let line = "          AGE-SECRET-KEY-1: base64-encoded-key-material";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn committed_encrypted_wording_is_detected() {
        let line = "# A committed encrypted secret blob for disaster recovery";
        assert!(classify_secret_violation("test.yml", line).is_some());
    }

    #[test]
    fn public_secret_name_in_policy_doc_is_allowed() {
        // docs/GITHUB_CI.md mentioning `secrets.*` is educational.
        let line = "Do not use `secrets.*` workflow expressions";
        assert!(classify_secret_violation("docs/GITHUB_CI.md", line).is_none());
    }

    #[test]
    fn host_local_secret_file_path_is_allowed() {
        let line = "          NEXUS_SECRET_FILE: /etc/tidefs-codex-nexus/webhook-secret";
        assert!(classify_secret_violation("test.yml", line).is_none());
    }

    #[test]
    fn host_local_secret_in_var_lib_is_allowed() {
        let line = "          SECRET_FILE: /var/lib/tidefs/secrets/token";
        assert!(classify_secret_violation("test.yml", line).is_none());
    }

    #[test]
    fn host_local_path_does_not_allow_github_secrets_context() {
        let line = "          TOKEN: ${{ secrets.DEPLOY_TOKEN }} # /etc/tidefs/local-secret";
        assert_eq!(
            classify_secret_violation("test.yml", line),
            Some(SecretViolationClass::SecretsContext)
        );
    }

    #[test]
    fn violation_report_omits_source_line_snippet() {
        let report = format_secret_violation("test.yml", 42, SecretViolationClass::SecretsContext);
        assert_eq!(
            report,
            "test.yml:42: forbidden GitHub secret surface (secrets-context)"
        );
        assert!(!report.contains("DEPLOY_TOKEN"));
    }

    #[test]
    fn secret_policy_command_name_is_not_a_secret_surface() {
        let line = "          cargo run -p tidefs-xtask -- check-secret-policy";
        assert!(classify_secret_violation(".github/workflows/secret-policy.yml", line).is_none());
    }

    #[test]
    fn secret_policy_workflow_secrets_context_is_not_allowlisted() {
        let line = "          TOKEN: ${{ secrets.DEPLOY_TOKEN }}";
        assert_eq!(
            classify_secret_violation(".github/workflows/secret-policy.yml", line),
            Some(SecretViolationClass::SecretsContext)
        );
    }

    #[test]
    fn seeded_secret_policy_violation_fixtures_fail_closed() {
        check_secret_policy_seeded_violation_fixtures()
            .expect("seeded violation fixtures should fail closed");
    }

    #[test]
    fn nexus_relay_secret_file_is_allowlisted() {
        let line = "      NEXUS_SECRET_FILE: /etc/tidefs-codex-nexus/webhook-secret";
        assert!(
            classify_secret_violation(".github/workflows/tidefs-codex-nexus-relay.yml", line)
                .is_none()
        );
    }

    #[test]
    fn clean_line_is_not_flagged() {
        let line = "          run: cargo build --release";
        assert!(classify_secret_violation("test.yml", line).is_none());
    }
}
