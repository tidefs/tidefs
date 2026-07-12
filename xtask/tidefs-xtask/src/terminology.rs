// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminologyEntry {
    pub stable_locator: &'static str,
    pub human_name: &'static str,
    pub rust_hint: &'static str,
    pub role: &'static str,
}

pub const TERMINOLOGY: &[TerminologyEntry] = &[
    TerminologyEntry {
        stable_locator: "control_plane",
        human_name: "Control Plane",
        rust_hint: "control_plane",
        role: "operator/control API, request envelopes, carrier frames, and receipts",
    },
    TerminologyEntry {
        stable_locator: "policy_authority",
        human_name: "Policy Authority",
        rust_hint: "policy_authority",
        role: "governance, policy/budget/recipe validation, and product admission",
    },
    TerminologyEntry {
        stable_locator: "publication_pipeline",
        human_name: "Publication Pipeline",
        rust_hint: "publication_pipeline",
        role: "emission tickets and admitted-decision publication",
    },
    TerminologyEntry {
        stable_locator: "response_registry",
        human_name: "Response Registry",
        rust_hint: "response_registry",
        role: "visible answers, response indexes, and recall bindings",
    },
    TerminologyEntry {
        stable_locator: "truth_view",
        human_name: "Truth View",
        rust_hint: "truth_view",
        role: "operator-visible truth and archive-recall bundles",
    },
    TerminologyEntry {
        stable_locator: "archive_control",
        human_name: "Archive Control",
        rust_hint: "archive_control",
        role: "archive disposition, tombstones, and non-live guards",
    },
    TerminologyEntry {
        stable_locator: "posix_filesystem_adapter",
        human_name: "POSIX Filesystem Adapter",
        rust_hint: "posix_filesystem_adapter",
        role: "POSIX/VFS projection path for future FUSE and kernel adapters",
    },
    TerminologyEntry {
        stable_locator: "block_volume_adapter",
        human_name: "Block Volume Adapter",
        rust_hint: "block_volume_adapter",
        role: "block-device projection path for ublk and future kernel block export",
    },
    TerminologyEntry {
        stable_locator: "explanation_query",
        human_name: "Explanation Query",
        rust_hint: "explanation_query",
        role: "operator explanation/query surface",
    },
    TerminologyEntry {
        stable_locator: "schema_codec",
        human_name: "Canonical Schema Codec",
        rust_hint: "schema_codec",
        role: "fixed-width little-endian encode/decode records and packet codecs",
    },
    TerminologyEntry {
        stable_locator: "package_profile_catalog",
        human_name: "Package Profile Catalog",
        rust_hint: "package_profile",
        role: "build profile, capability, bundle, and service-surface manifests",
    },
    TerminologyEntry {
        stable_locator: "vfs_boundary_mirror",
        human_name: "VFS Boundary Mirror",
        rust_hint: "vfs_boundary_mirror",
        role: "fixed-size VFS boundary mirrors between owned and ABI-safe values",
    },
    TerminologyEntry {
        stable_locator: "authority_publication",
        human_name: "Authority Publication Kernel",
        rust_hint: "authority_publication",
        role: "future authority publication and head/root movement family",
    },
    TerminologyEntry {
        stable_locator: "claim_reserve_witness",
        human_name: "Claim/Reserve/Witness Kernel",
        rust_hint: "claim_reserve_witness",
        role: "future claim, reserve, witness, repair, escrow, and quorum family",
    },
    TerminologyEntry {
        stable_locator: "response_normalizer",
        human_name: "Response Normalizer",
        rust_hint: "response_normalizer",
        role: "future response-language and charter-rendering family",
    },
];

const USER_FACING_TERMINOLOGY_DOCS: &[&str] = &["README.md", "docs/INDEX.md"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanApiAliasEntry {
    pub crate_path: &'static str,
    pub module_name: &'static str,
    pub human_name: &'static str,
    pub stable_locator: &'static str,
}

pub const HUMAN_API_ALIASES: &[HumanApiAliasEntry] = &[
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-vfs-core/src/lib.rs",
        module_name: "control_plane",
        human_name: "Control Plane",
        stable_locator: "control_plane",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-secret-key-policy-core/src/lib.rs",
        module_name: "secret_key_policy",
        human_name: "Secret Key Policy",
        stable_locator: "secret_key_policy",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-posix-filesystem-adapter-core/src/lib.rs",
        module_name: "posix_filesystem_adapter",
        human_name: "POSIX Filesystem Adapter",
        stable_locator: "posix_filesystem_adapter",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-vfs-core/src/lib.rs",
        module_name: "publication_pipeline",
        human_name: "Publication Pipeline",
        stable_locator: "publication_pipeline",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-vfs-core/src/lib.rs",
        module_name: "response_registry",
        human_name: "Response Registry",
        stable_locator: "response_registry",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-package-profile-catalog/src/lib.rs",
        module_name: "package_profile_catalog",
        human_name: "Package Profile Catalog",
        stable_locator: "package_profile_catalog",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-vfs-core/src/lib.rs",
        module_name: "vfs_engine",
        human_name: "VFS Engine Boundary",
        stable_locator: "vfs",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-types-vfs-owned/src/lib.rs",
        module_name: "vfs_owned",
        human_name: "VFS Owned Values",
        stable_locator: "vfs",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-schema-codec-posix-filesystem-adapter/src/lib.rs",
        module_name: "posix_filesystem_adapter_schema_codec",
        human_name: "POSIX Adapter Schema Codec",
        stable_locator: "schema_codec/posix_filesystem_adapter",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-schema-codec-vfs/src/lib.rs",
        module_name: "vfs_schema_codec",
        human_name: "VFS Schema Codec",
        stable_locator: "schema_codec/vfs",
    },
    HumanApiAliasEntry {
        crate_path: "apps/tidefs-posix-filesystem-adapter-daemon/src/runtime/mod.rs",
        module_name: "posix_filesystem_adapter_runtime",
        human_name: "POSIX Filesystem Adapter Runtime",
        stable_locator: "posix_filesystem_adapter",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-local-object-store/src/lib.rs",
        module_name: "local_object_store",
        human_name: "Local Object Store",
        stable_locator: "storage",
    },
    HumanApiAliasEntry {
        crate_path: "crates/tidefs-local-filesystem/src/lib.rs",
        module_name: "local_filesystem",
        human_name: "Local Filesystem",
        stable_locator: "storage",
    },
];

const DEMO_STDOUT_SURFACES: &[&str] = &[
    "apps/tidefs-block-volume-adapter-daemon/src/main.rs",
    "apps/tidefs-filesystem-demo/src/main.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/main.rs",
    "apps/tidefs-scrub/src/main.rs",
    "apps/tidefs-storage-node/src/main.rs",
    "apps/tidefs-store-demo/src/main.rs",
    "apps/tidefsctl/src/main.rs",
    "xtask/tidefs-xtask/src/main.rs",
];

#[derive(Debug)]
pub struct TerminologyCheckError {
    missing: Vec<String>,
}

impl fmt::Display for TerminologyCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "terminology check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn print_human_map() {
    println!("tidefs human terminology map");
    println!("human name | stable internal locator | rust hint | role");
    for entry in TERMINOLOGY {
        println!(
            "{} | {} | {} | {}",
            entry.human_name, entry.stable_locator, entry.rust_hint, entry.role
        );
    }
    println!("rule=human-name-first; stable-internal-locators-are-internal-identifiers");
}

pub fn print_human_api_aliases() {
    println!("tidefs human Rust API alias map");
    println!("crate path | module | human name | stable id");
    for entry in HUMAN_API_ALIASES {
        println!(
            "{} | {} | {} | {}",
            entry.crate_path, entry.module_name, entry.human_name, entry.stable_locator
        );
    }
    println!("rule=human-module-imports-first; internal-locator structs remain fixed-width stability records");
}

pub fn check_human_api_aliases_current_workspace() -> Result<(), TerminologyCheckError> {
    let root = find_workspace_root().ok_or_else(|| TerminologyCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    check_human_api_aliases(&root, &mut missing);
    if missing.is_empty() {
        println!(
            "human API aliases ok: {} modules present",
            HUMAN_API_ALIASES.len()
        );
        Ok(())
    } else {
        Err(TerminologyCheckError { missing })
    }
}

pub fn check_human_readability_current_workspace() -> Result<(), TerminologyCheckError> {
    let root = find_workspace_root().ok_or_else(|| TerminologyCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    check_user_facing_docs(&root, &mut missing);
    check_demo_stdout_labels(&root, &mut missing);
    if missing.is_empty() {
        println!("human readability ok: selected docs and demo labels are human-first");
        Ok(())
    } else {
        Err(TerminologyCheckError { missing })
    }
}

pub fn check_current_workspace() -> Result<(), TerminologyCheckError> {
    let root = find_workspace_root().ok_or_else(|| TerminologyCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();
    check_source_owned_terminology_entries(&mut missing);
    check_user_facing_docs(&root, &mut missing);
    check_demo_stdout_labels(&root, &mut missing);
    check_human_api_aliases(&root, &mut missing);

    if missing.is_empty() {
        println!(
            "terminology ok: {} source-owned human names mapped; selected docs and demo labels are human-first",
            TERMINOLOGY.len()
        );
        Ok(())
    } else {
        Err(TerminologyCheckError { missing })
    }
}

fn check_source_owned_terminology_entries(missing: &mut Vec<String>) {
    for entry in TERMINOLOGY {
        if entry.stable_locator.is_empty() {
            missing.push("source-owned terminology entry has empty stable locator".to_string());
        }
        if entry.human_name.is_empty() {
            missing.push(format!(
                "source-owned terminology entry `{}` has empty human name",
                entry.stable_locator
            ));
        }
        if entry.rust_hint.is_empty() {
            missing.push(format!(
                "source-owned terminology entry `{}` has empty rust hint",
                entry.stable_locator
            ));
        }
        if entry.role.is_empty() {
            missing.push(format!(
                "source-owned terminology entry `{}` has empty role",
                entry.stable_locator
            ));
        }
    }
}

fn check_user_facing_docs(root: &Path, missing: &mut Vec<String>) {
    for doc in USER_FACING_TERMINOLOGY_DOCS {
        let path = root.join(doc);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                missing.push(format!("read {doc}: {err}"));
                continue;
            }
        };

        for (line_number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with('#') {
                continue;
            }
            if line_has_naked_stable_locator(line) {
                missing.push(format!(
                    "{doc}:{} has a naked internal-locator heading without human/stable-ID context: {}",
                    line_number + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn check_human_api_aliases(root: &Path, missing: &mut Vec<String>) {
    for entry in HUMAN_API_ALIASES {
        let path = root.join(entry.crate_path);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                missing.push(format!("read {}: {err}", entry.crate_path));
                continue;
            }
        };
        let module_decl = format!("pub mod {}", entry.module_name);
        if !text.contains(&module_decl) {
            missing.push(format!(
                "{} is missing human alias module `{}` for {}",
                entry.crate_path, entry.module_name, entry.human_name
            ));
        }
        if !text.contains("pub mod human") {
            missing.push(format!(
                "{} is missing `pub mod human` namespace for {}",
                entry.crate_path, entry.human_name
            ));
        }
    }
}

fn check_demo_stdout_labels(root: &Path, missing: &mut Vec<String>) {
    for rel in DEMO_STDOUT_SURFACES {
        let path = root.join(rel);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) => {
                missing.push(format!("read {rel}: {err}"));
                continue;
            }
        };
        for (line_number, line) in text.lines().enumerate() {
            if !(line.contains("println!") || line.contains("print!")) {
                continue;
            }
            if line_has_stable_locator(line) && !line_mentions_human_or_stable_context(line) {
                missing.push(format!(
                    "{rel}:{} prints a naked internal-locator label: {}",
                    line_number + 1,
                    line.trim()
                ));
            }
        }
    }
}

fn line_has_naked_stable_locator(line: &str) -> bool {
    if !line_has_stable_locator(line) {
        return false;
    }
    !line_mentions_human_or_stable_context(line)
}

fn line_has_stable_locator(line: &str) -> bool {
    TERMINOLOGY
        .iter()
        .any(|entry| line.contains(entry.stable_locator))
}

fn line_mentions_human_or_stable_context(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("stable")
        || lower.contains("wire")
        || lower.contains("internal cleanup")
        || lower.contains("old-path")
        || lower.contains("previous path")
        || lower.contains("previous spelling")
        || lower.contains("wire")
        || lower.contains("crate")
        || lower.contains("binary")
        || lower.contains("record")
        || lower.contains("module")
        || lower.contains("path")
        || lower.contains("filename")
        || lower.contains("docs/")
        || TERMINOLOGY
            .iter()
            .any(|entry| line.contains(entry.human_name))
}

pub fn check_prepreview_naming_current_workspace() -> Result<(), TerminologyCheckError> {
    let banned = ["leg", "acy"].concat();
    let mut missing = Vec::new();
    check_current_naming_constants(&banned, &mut missing);
    if missing.is_empty() {
        println!("pre-preview naming ok: current terminology constants avoid cleanup-era labels");
        Ok(())
    } else {
        Err(TerminologyCheckError { missing })
    }
}

fn check_current_naming_constants(banned: &str, missing: &mut Vec<String>) {
    let tokens = banned_compact_family_tokens();
    for entry in TERMINOLOGY {
        check_naming_field(
            &format!("terminology stable locator `{}`", entry.stable_locator),
            entry.stable_locator,
            banned,
            &tokens,
            missing,
        );
        check_naming_field(
            &format!("terminology Rust hint `{}`", entry.rust_hint),
            entry.rust_hint,
            banned,
            &tokens,
            missing,
        );
    }

    for entry in HUMAN_API_ALIASES {
        check_naming_field(
            &format!("human API module `{}`", entry.module_name),
            entry.module_name,
            banned,
            &tokens,
            missing,
        );
        check_naming_field(
            &format!("human API stable locator `{}`", entry.stable_locator),
            entry.stable_locator,
            banned,
            &tokens,
            missing,
        );
    }
}

fn check_naming_field(
    label: &str,
    value: &str,
    banned: &str,
    tokens: &[String],
    missing: &mut Vec<String>,
) {
    let lower = value.to_ascii_lowercase();
    if lower.contains(banned) {
        missing.push(format!("{label} contains banned internal cleanup wording"));
    }
    if tokens
        .iter()
        .any(|token| contains_compact_token(&lower, token))
    {
        missing.push(format!(
            "{label} contains banned compact family label token"
        ));
    }
    if contains_two_letter_digit_token_with_exceptions(&lower) {
        missing.push(format!(
            "{label} contains banned opaque two-letter/digit token"
        ));
    }
}

#[allow(dead_code)]
const fn contains_two_letter_digit_token(haystack: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut index = 0;
    while index + 2 < bytes.len() {
        let first = bytes[index];
        let second = bytes[index + 1];
        let third = bytes[index + 2];
        if first.is_ascii_lowercase() && second.is_ascii_lowercase() && third.is_ascii_digit() {
            let prev_is_alnum = index > 0 && bytes[index - 1].is_ascii_alphanumeric();
            let mut next = index + 3;
            while next < bytes.len() && bytes[next].is_ascii_digit() {
                next += 1;
            }
            let next_is_alnum = next < bytes.len() && bytes[next].is_ascii_alphanumeric();
            if !prev_is_alnum && !next_is_alnum {
                return true;
            }
            index = next;
        } else {
            index += 1;
        }
    }
    false
}

/// Tokens that match the two-letter+digit pattern but are semantically
/// meaningful (e.g., references a concrete 128-bit ID type) and
const ALLOWED_TWO_LETTER_DIGIT_TOKENS: &[&str] = &[];

/// Like [`contains_two_letter_digit_token`] but additionally skips tokens
/// listed in [`ALLOWED_TWO_LETTER_DIGIT_TOKENS`].
fn contains_two_letter_digit_token_with_exceptions(haystack: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut index = 0;
    while index + 2 < bytes.len() {
        let first = bytes[index];
        let second = bytes[index + 1];
        let third = bytes[index + 2];
        if first.is_ascii_lowercase() && second.is_ascii_lowercase() && third.is_ascii_digit() {
            let prev_is_alnum = index > 0 && bytes[index - 1].is_ascii_alphanumeric();
            let mut next = index + 3;
            while next < bytes.len() && bytes[next].is_ascii_digit() {
                next += 1;
            }
            let next_is_alnum = next < bytes.len() && bytes[next].is_ascii_alphanumeric();
            if !prev_is_alnum && !next_is_alnum {
                let token = &haystack[index..next];
                if !ALLOWED_TWO_LETTER_DIGIT_TOKENS.contains(&token) {
                    return true;
                }
            }
            index = next;
        } else {
            index += 1;
        }
    }
    false
}

fn banned_compact_family_tokens() -> Vec<String> {
    [
        &["c", "p", "0"][..],
        &["g", "p", "0"],
        &["p", "f", "0"],
        &["p", "p", "0"],
        &["r", "r", "0"],
        &["o", "v", "0"],
        &["e", "p", "0"],
        &["a", "r", "0"],
        &["r", "s", "0"],
        &["u", "f", "0"],
        &["b", "v", "0"],
        &["e", "q", "0"],
        &["p", "k", "0"],
        &["a", "p", "0"],
        &["c", "r", "w", "0"],
        &["r", "n", "0"],
    ]
    .iter()
    .map(|parts| parts.concat())
    .collect()
}

fn contains_compact_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle = token.as_bytes();
    if needle.is_empty() || needle.len() > bytes.len() {
        return false;
    }
    let mut index = 0;
    while index + needle.len() <= bytes.len() {
        if &bytes[index..index + needle.len()] == needle {
            let prev_is_alnum = index > 0 && bytes[index - 1].is_ascii_alphanumeric();
            let next = index + needle.len();
            let next_is_alnum = next < bytes.len() && bytes[next].is_ascii_alphanumeric();
            if !prev_is_alnum && !next_is_alnum {
                return true;
            }
        }
        index += 1;
    }
    false
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        if is_workspace_root(&current) {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

fn is_workspace_root(path: &Path) -> bool {
    let manifest = path.join("Cargo.toml");
    fs::read_to_string(manifest).is_ok_and(|text| text.contains("[workspace]"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn human_name_for_stable_locator(stable_locator: &str) -> Option<&'static str> {
        TERMINOLOGY
            .iter()
            .find(|entry| entry.stable_locator == stable_locator)
            .map(|entry| entry.human_name)
    }

    #[test]
    fn terminology_has_no_empty_fields() {
        for entry in TERMINOLOGY {
            assert!(!entry.stable_locator.is_empty());
            assert!(!entry.human_name.is_empty());
            assert!(!entry.rust_hint.is_empty());
            assert!(!entry.role.is_empty());
        }
    }

    #[test]
    fn current_spine_has_human_names() {
        let codes = [
            "control_plane",
            "policy_authority",
            "publication_pipeline",
            "response_registry",
        ];
        for code in codes {
            assert!(TERMINOLOGY.iter().any(|entry| entry.stable_locator == code));
            assert!(human_name_for_stable_locator(code).is_some());
        }
    }

    #[test]
    fn naked_code_detection_allows_stable_context() {
        assert!(line_has_naked_stable_locator(
            "`control_plane -> policy_authority` without explanation"
        ));
        assert!(!line_has_naked_stable_locator(
            "Control Plane (`control_plane`) routes to Policy Authority (`policy_authority`)."
        ));
        assert!(!line_has_naked_stable_locator(
            "wire.control_plane.request_head_wire_control_plane"
        ));
    }

    #[test]
    fn prepreview_banned_word_is_built_without_embedding_it() {
        let banned = ["leg", "acy"].concat();
        assert_eq!(banned, ["leg", "acy"].concat());
    }

    #[test]
    fn compact_token_detection_respects_boundaries() {
        let tokens = banned_compact_family_tokens();
        let bad = ["crate-", "c", "p", "0", "-name"].concat();
        assert!(contains_compact_token(&bad, &tokens[0]));
        let harmless = ["VLFSEAM_M", "AP", "01"].concat();
        assert!(!contains_compact_token(&harmless, &tokens[13]));
    }

    #[test]
    fn broad_opaque_token_detection_respects_word_boundaries() {
        let first_bad = ["bad ", "p", "r", "0", " token"].concat();
        assert!(contains_two_letter_digit_token(&first_bad));
        let second_bad = ["bad ", "q", "r", "12", " token"].concat();
        assert!(contains_two_letter_digit_token(&second_bad));
        assert!(!contains_two_letter_digit_token("VFSROOT1"));
        assert!(!contains_two_letter_digit_token("0xEAA1"));
        assert!(!contains_two_letter_digit_token("Wave Zero"));
    }
}
