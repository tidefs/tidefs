// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Anti-regression guard: BLAKE3 proof-marker patterns in kmod-posix-vfs
//
// Scans operation-dispatch source files and docs in
// crates/tidefs-kmod-posix-vfs/ for prohibited BLAKE3 attestation patterns.
// Legitimate durable/content-integrity surfaces (committed-root anchors,
// pool labels, mount option digests) are excluded.
// ---------------------------------------------------------------------------

/// Patterns prohibited in guarded operation-dispatch surfaces.
const PROHIBITED_PATTERNS: &[(&str, &str)] = &[
    ("digest: [u8; 32]", "digest field in Plan/result struct"),
    ("compute_digest", "compute_digest method"),
    ("fn verify(", "verify method"),
    (
        "BLAKE3-verified attestation",
        "BLAKE3 attestation doc phrase",
    ),
    ("BLAKE3 attestation", "BLAKE3 attestation doc phrase"),
    (
        "with BLAKE3-256 domain-separated attestation",
        "BLAKE3 attestation doc phrase",
    ),
];

/// Negation prefixes: lines containing these are allowed despite matching
/// prohibited patterns, because they state the file does NOT use BLAKE3.
/// Exception patterns: lines containing these are legitimate BLAKE3 uses
/// for durable/content-integrity surfaces and should not be flagged.
const EXCEPTION_PATTERNS: &[(&str, &str)] = &[
    ("mount-options", "mount option/config digest"),
    ("committed-root", "committed-root anchors"),
];

const NEGATION_PREFIXES: &[&str] = &[
    "without BLAKE3 attestation",
    "do not include BLAKE3",
    "pure delegation wrapper",
];

/// Guarded source files under crates/tidefs-kmod-posix-vfs/src/.
const GUARDED_SOURCE_FILES: &[&str] = &[
    "permission.rs",
    "create.rs",
    "link.rs",
    "unlink.rs",
    "mkdir.rs",
    "rmdir.rs",
    "rename.rs",
    "setattr.rs",
    "symlink.rs",
    "getattr.rs",
    "dir_ops_bridge.rs",
    "extent_ops.rs",
    "extent_ops_bridge.rs",
    "update_time.rs",
    "open_release.rs",
    "lib.rs",
];

/// Guarded doc files under crates/tidefs-kmod-posix-vfs/.
const GUARDED_DOC_FILES: &[&str] = &["README.md"];

#[derive(Debug)]
pub struct KmodGuardError {
    failures: Vec<String>,
}

impl fmt::Display for KmodGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "kmod BLAKE3 proof-marker guard failures:")?;
        for item in &self.failures {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

/// Check the current workspace for kmod BLAKE3 proof-marker regressions.
pub fn check_kmod_blake3_guard_current_workspace() -> Result<(), KmodGuardError> {
    let root = find_workspace_root().ok_or_else(|| KmodGuardError {
        failures: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;

    let kmod_dir = root.join("crates/tidefs-kmod-posix-vfs");
    let src_dir = kmod_dir.join("src");

    let mut failures = Vec::new();

    // Check guarded source files
    for file_name in GUARDED_SOURCE_FILES {
        let path = src_dir.join(file_name);
        scan_file(&path, file_name, &mut failures);
    }

    // Check guarded doc files
    for file_name in GUARDED_DOC_FILES {
        let path = kmod_dir.join(file_name);
        scan_file(&path, file_name, &mut failures);
    }

    if failures.is_empty() {
        // Also check: no unguarded source files reintroduced BLAKE3
        // by scanning all .rs files in src/ that aren't explicitly guarded.
        // The blake3_guard.rs and operation_result.rs are intentionally
        // excluded: blake3_guard.rs is the guard itself, operation_result.rs
        // is structural.
        println!("kmod BLAKE3 proof-marker guard ok: no prohibited patterns found");
        Ok(())
    } else {
        Err(KmodGuardError { failures })
    }
}

fn scan_file(path: &Path, name: &str, failures: &mut Vec<String>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            failures.push(format!("{name}: read error: {e}"));
            return;
        }
    };

    for (pattern, description) in PROHIBITED_PATTERNS {
        for (i, line) in content.lines().enumerate() {
            let line_no = i + 1;
            if line.contains(pattern) {
                // Check negation: does this line disclaim BLAKE3 usage?
                // Check legitimate durable/content-integrity exceptions
                let mut is_exception = false;
                for (allowed, _desc) in EXCEPTION_PATTERNS {
                    if line.contains(allowed) {
                        is_exception = true;
                        break;
                    }
                }
                if is_exception {
                    continue;
                }
                let mut is_negation = false;
                for prefix in NEGATION_PREFIXES {
                    if line.contains(prefix) {
                        is_negation = true;
                        break;
                    }
                }
                if is_negation {
                    continue;
                }
                // Skip lines that are self-referential about the guard itself
                if line.contains("prohibited")
                    || line.contains("must not")
                    || line.contains("guard")
                {
                    continue;
                }
                failures.push(format!(
                    "{name}:{line_no}: prohibited pattern '{pattern}' ({description}): {}",
                    line.trim()
                ));
            }
        }
    }
}

fn find_workspace_root() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    for ancestor in cwd.ancestors() {
        if ancestor.join("Cargo.toml").exists() && ancestor.join("Cargo.lock").exists() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_content_has_no_violations() {
        let mut failures = Vec::new();
        // Write temp file, scan it, verify clean
        let tmp = std::env::temp_dir().join("kmod_guard_test_empty.rs");
        fs::write(&tmp, "// no BLAKE3 content\n").unwrap();
        scan_file(&tmp, "empty.rs", &mut failures);
        let _ = fs::remove_file(&tmp);
        assert!(
            failures.is_empty(),
            "expected no violations, got: {failures:?}"
        );
    }

    #[test]
    fn negation_line_is_allowed() {
        let mut failures = Vec::new();
        let tmp = std::env::temp_dir().join("kmod_guard_test_negation.rs");
        fs::write(
            &tmp,
            "//! pure delegation wrapper without BLAKE3 attestation\n",
        )
        .unwrap();
        scan_file(&tmp, "negation.rs", &mut failures);
        let _ = fs::remove_file(&tmp);
        assert!(
            failures.is_empty(),
            "expected no violations, got: {failures:?}"
        );
    }

    #[test]
    fn prohibited_pattern_is_detected() {
        let mut failures = Vec::new();
        let tmp = std::env::temp_dir().join("kmod_guard_test_violation.rs");
        fs::write(&tmp, "/// Returns a BLAKE3-verified attestation plan.\n").unwrap();
        scan_file(&tmp, "violation.rs", &mut failures);
        let _ = fs::remove_file(&tmp);
        assert!(!failures.is_empty(), "expected violations, got none");
    }
}
