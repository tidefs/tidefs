//! Source guard for FUSE adapter semantic mutation boundaries.
//!
//! The guard is intentionally scoped to production adapter-boundary files. Unit
//! tests may construct concrete `LocalFileSystem` backends, and `main.rs` may
//! assemble a mounted daemon backend. The request handlers themselves must not
//! reach around the contract/VfsEngine executor and mutate storage directly.

use std::fmt;
use std::path::Path;

const ADAPTER_BOUNDARY_FILES: &[&str] = &[
    "apps/tidefs-posix-filesystem-adapter-daemon/src/capacity/dispatch.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/dispatch_helpers.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fsync_handler.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_create_unlink_dispatch.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_flush_fsync.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_read.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_rename.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_vfs_adapter.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/fuse_write.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/workers_ns/mod.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/workers_writeback/mod.rs",
    "apps/tidefs-posix-filesystem-adapter-daemon/src/write_dispatch.rs",
];

const FORBIDDEN_PRODUCTION_PATTERNS: &[(&str, &str)] = &[
    (
        "LocalFileSystem::",
        "adapter request handlers must dispatch through VfsEngine/contract paths",
    ),
    (
        "tidefs_local_filesystem::LocalFileSystem",
        "adapter request handlers must not construct local filesystem semantics directly",
    ),
    (
        "VfsLocalFileSystem::new",
        "adapter request handlers must not wrap concrete local storage directly",
    ),
    (
        "tidefs_local_object_store::store::LocalObjectStore",
        "adapter request handlers must not construct object-store mutation authority",
    ),
    (
        "tidefs_local_object_store::ObjectStore::put",
        "adapter request handlers must not write object-store data directly",
    ),
    (
        "tidefs_local_object_store::ObjectStore::delete",
        "adapter request handlers must not delete object-store data directly",
    ),
    (
        "ObjectStore::put",
        "adapter request handlers must not write object-store data directly",
    ),
    (
        "ObjectStore::delete",
        "adapter request handlers must not delete object-store data directly",
    ),
];

/// One production-source boundary violation found by the adapter guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterGuardViolation {
    pub file: String,
    pub line: usize,
    pub pattern: &'static str,
    pub reason: String,
}

impl fmt::Display for AdapterGuardViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} contains {:?}: {}",
            self.file, self.line, self.pattern, self.reason
        )
    }
}

/// Check the adapter-owned production files for direct storage mutation
/// bypasses.
///
/// # Errors
///
/// Returns every discovered violation so review can fix the full write set in
/// one pass.
pub fn check_adapter_semantic_boundary(root: &Path) -> Result<(), Vec<AdapterGuardViolation>> {
    let mut violations = Vec::new();

    for rel in ADAPTER_BOUNDARY_FILES {
        let path = root.join(rel);
        let source = match std::fs::read_to_string(&path) {
            Ok(source) => source,
            Err(err) => {
                violations.push(AdapterGuardViolation {
                    file: (*rel).to_string(),
                    line: 0,
                    pattern: "<read>",
                    reason: format!("failed to read adapter file: {err}"),
                });
                continue;
            }
        };
        violations.extend(check_adapter_source_text(rel, &source));
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn check_adapter_source_text(file: &str, source: &str) -> Vec<AdapterGuardViolation> {
    let mut violations = Vec::new();
    for (line, code) in production_code_lines(source) {
        for (pattern, reason) in FORBIDDEN_PRODUCTION_PATTERNS {
            if code.contains(pattern) {
                violations.push(AdapterGuardViolation {
                    file: file.to_string(),
                    line,
                    pattern,
                    reason: (*reason).to_string(),
                });
                break;
            }
        }
    }
    violations
}

fn production_code_lines(source: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        if is_cfg_test_module_start(&lines, index) {
            index = skip_braced_module(&lines, index);
            continue;
        }

        let line = lines[index];
        let code = line.split_once("//").map_or(line, |(code, _)| code).trim();
        if !code.is_empty() {
            out.push((index + 1, code.to_string()));
        }
        index += 1;
    }

    out
}

fn is_cfg_test_module_start(lines: &[&str], index: usize) -> bool {
    if lines[index].trim() != "#[cfg(test)]" {
        return false;
    }

    let mut next = index + 1;
    while next < lines.len() && lines[next].trim().starts_with("#[") {
        next += 1;
    }

    next < lines.len() && lines[next].trim_start().starts_with("mod ")
}

fn skip_braced_module(lines: &[&str], start: usize) -> usize {
    let mut index = start;
    while index < lines.len() && !lines[index].contains('{') {
        index += 1;
    }
    if index == lines.len() {
        return lines.len();
    }

    let mut depth = 0_usize;
    while index < lines.len() {
        for byte in lines[index].bytes() {
            match byte {
                b'{' => depth = depth.saturating_add(1),
                b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        index += 1;
        if depth == 0 {
            break;
        }
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_ignores_test_fixture_storage_construction() {
        let source = r#"
fn production() {}

#[cfg(test)]
mod tests {
    use tidefs_local_filesystem::LocalFileSystem;

    fn fixture() {
        let _ = LocalFileSystem::open("/tmp/example");
    }
}
"#;

        assert!(check_adapter_source_text("fixture.rs", source).is_empty());
    }

    #[test]
    fn guard_rejects_production_storage_construction() {
        let source = r#"
fn production() {
    let _ = tidefs_local_filesystem::LocalFileSystem::open("/tmp/example");
}
"#;

        let violations = check_adapter_source_text("fixture.rs", source);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, 3);
    }
}
