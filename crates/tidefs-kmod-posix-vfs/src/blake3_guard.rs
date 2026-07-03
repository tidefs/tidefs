// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Anti-regression guard for BLAKE3 attestation patterns in
//! operation-dispatch source files.
//!
//! Scans known operation-dispatch and doc files for prohibited
//! BLAKE3 proof-marker patterns. Legitimate durable/content-integrity
//! surfaces (committed-root anchors, pool labels, mount option digests)
//! are excluded.
//!
//! Prohibited in operation-dispatch surfaces:
//!   - `BLAKE3.*attestation` / `attestation.*BLAKE3`
//!   - `compute_digest`
//!   - `verify(` (when combined with digest-like field context)
//!   - `digest: [u8; 32]` in Plan structs
//!
//! This module is itself excluded from self-scan.

/// Patterns that are prohibited in guarded files.
#[allow(unused_imports)]
use crate::TideString as String;

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

/// Patterns that are allowed in guarded files when they appear as
/// negations (stating the file does NOT use BLAKE3 attestation).
/// Exception patterns: lines containing these are legitimate BLAKE3 uses
/// for durable/content-integrity surfaces and should not be flagged.
const EXCEPTION_PATTERNS: &[(&str, &str)] = &[
    ("mount-options", "mount option/config digest"),
    (
        "MountOptions",
        "mount option/config digest (camelCase variant)",
    ),
    ("committed-root", "committed-root anchors"),
];

const NEGATION_PREFIXES: &[&str] = &[
    "without BLAKE3 attestation",
    "do not include BLAKE3",
    "pure delegation wrapper",
];

/// Scan `content` (the full text of a guarded source file) and return
/// a list of violations. Each violation is (line_number, pattern, context).
pub fn scan_for_prohibited(content: &str) -> crate::TideVec<(usize, &'static str, String)> {
    let mut violations = crate::TideVec::new();

    for (pattern, description) in PROHIBITED_PATTERNS {
        for (line_no, line) in content.lines().enumerate() {
            let line_no = line_no + 1; // 1-indexed
            if line.contains(pattern) {
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
                if line.contains("prohibited")
                    || line.contains("must not")
                    || line.contains("guard")
                {
                    continue;
                }
                violations.push((line_no, *description, String::from(line.trim())));
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guarded_files_have_no_prohibited_patterns() {
        let mut failures: crate::TideVec<String> = crate::TideVec::new();

        check_file(
            include_str!("permission.rs"),
            "permission.rs",
            &mut failures,
        );
        check_file(include_str!("create.rs"), "create.rs", &mut failures);
        check_file(include_str!("link.rs"), "link.rs", &mut failures);
        check_file(include_str!("unlink.rs"), "unlink.rs", &mut failures);
        check_file(include_str!("mkdir.rs"), "mkdir.rs", &mut failures);
        check_file(include_str!("rmdir.rs"), "rmdir.rs", &mut failures);
        check_file(include_str!("rename.rs"), "rename.rs", &mut failures);
        check_file(include_str!("setattr.rs"), "setattr.rs", &mut failures);
        check_file(include_str!("symlink.rs"), "symlink.rs", &mut failures);
        check_file(include_str!("getattr.rs"), "getattr.rs", &mut failures);
        check_file(
            include_str!("dir_ops_bridge.rs"),
            "dir_ops_bridge.rs",
            &mut failures,
        );
        check_file(
            include_str!("extent_ops.rs"),
            "extent_ops.rs",
            &mut failures,
        );
        check_file(
            include_str!("extent_ops_bridge.rs"),
            "extent_ops_bridge.rs",
            &mut failures,
        );
        check_file(
            include_str!("update_time.rs"),
            "update_time.rs",
            &mut failures,
        );
        check_file(
            include_str!("open_release.rs"),
            "open_release.rs",
            &mut failures,
        );

        // lib.rs is checked but exclusion for its own BLAKE3 annotations on
        // mount_lifecycle and the guard module docs is handled by pattern scope.
        check_file(include_str!("lib.rs"), "lib.rs", &mut failures);

        // The package README remains guarded against reintroducing BLAKE3
        // attestation language for ordinary operation dispatch surfaces.
        check_file(include_str!("../README.md"), "README.md", &mut failures);

        if !failures.is_empty() {
            panic!(
                "BLAKE3 attestation guard failures:\n{}",
                failures.join("\n")
            );
        }
    }

    fn check_file(content: &str, name: &str, failures: &mut crate::TideVec<String>) {
        let violations = scan_for_prohibited(content);
        for (line_no, pattern, context) in violations {
            {
                use core::fmt::Write;
                let mut s = String::new();
                let _ = write!(
                    s,
                    "  {name}:{line_no}: prohibited pattern '{pattern}' found: {context}"
                );
                failures.push(s);
            }
        }
    }
}
