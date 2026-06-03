use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

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
                    dependencies.push(dep_name.replace('_', "-"));
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
    if name.starts_with("tidefs-types-") {
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
                key.replace('_', "-")
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
            Path::new("crates/tidefs-types-control-plane-core/Cargo.toml"),
            "tidefs-types-control-plane-core",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Types);
        assert_eq!(class, CrateClass::Types);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-schema-codec-control-plane/Cargo.toml"),
            "tidefs-schema-codec-control-plane",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::SchemaCodec);
        assert_eq!(class, CrateClass::Schema);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-policy-authority-client/Cargo.toml"),
            "tidefs-policy-authority-client",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::PolicyAuthority);
        assert_eq!(class, CrateClass::Client);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-control-plane-runtime/Cargo.toml"),
            "tidefs-control-plane-runtime",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::ControlPlane);
        assert_eq!(class, CrateClass::Runtime);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-schema-codec-outcome/Cargo.toml"),
            "tidefs-schema-codec-outcome",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::SchemaCodec);
        assert_eq!(class, CrateClass::Schema);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-observe-core/Cargo.toml"),
            "tidefs-observe-core",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Observe);
        assert_eq!(class, CrateClass::Observe);

        let (kind, family, class) = classify_member(
            Path::new("crates/tidefs-observe-core-truth-view-render/Cargo.toml"),
            "tidefs-observe-core-truth-view-render",
        );
        assert_eq!(kind, NodeKind::Library);
        assert_eq!(family, Family::Observe);
        assert_eq!(class, CrateClass::Render);

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

        let (kind, family, class) = classify_member(
            Path::new("apps/tidefs-control-plane-daemon/Cargo.toml"),
            "tidefs-control-plane-daemon",
        );
        assert_eq!(kind, NodeKind::AppRoot);
        assert_eq!(family, Family::ControlPlane);
        assert_eq!(class, CrateClass::ServiceRoot);
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
}
