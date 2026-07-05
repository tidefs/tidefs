// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Kernel-portable storage-core dependency closure guard.
//!
//! Replaces the manifest-string "transitive guard" from
//! `crates/tidefs-local-filesystem/build.rs` with a real `cargo metadata`
//! dependency-closure check.
//!
//! The check:
//! 1. Runs `cargo metadata --no-deps` to discover all workspace members and
//!    their direct intra-workspace dependencies.
//! 2. Builds a directed graph of workspace-internal crate dependencies.
//! 3. For each crate in the canonical kernel-portable storage-core set,
//!    computes the transitive closure and ensures no forbidden
//!    control-plane/adapter scaffold crate appears.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Canonical kernel-portable storage-core set.
// These crates must not depend (directly or transitively) on any
// control-plane or POSIX-adapter scaffold crate.
// ---------------------------------------------------------------------------
const KERNEL_PORTABLE_CORE: &[&str] = &[
    "tidefs-local-filesystem",
    "tidefs-types-claim-ledger-core",
    "tidefs-claim-ledger",
    "tidefs-reserve-ledger",
    // Broader kernel-core set from the informational list in build.rs,
    // now enforced as part of the same canonical guard.
    "tidefs-types-vfs-core",
    "tidefs-types-space-accounting-core",
    "tidefs-types-extent-map-core",
    "tidefs-vfs-engine",
    "tidefs-inode-table",
    "tidefs-inode-attributes",
    "tidefs-block-allocator",
    "tidefs-local-object-store",
    "tidefs-intent-log",
    "tidefs-recovery-loop",
    "tidefs-dir-index",
    "tidefs-extent-map",
    "tidefs-posix-semantics",
    "tidefs-orphan-index",
    "tidefs-scrub-core",
    "tidefs-posix-acl",
    "tidefs-space-accounting",
    "tidefs-erasure-coding",
    "tidefs-commit_group",
    "tidefs-cleanup-engine",
    "tidefs-reclaim-queue-core",
    "tidefs-dataset-lifecycle",
    "tidefs-dataset-feature-flags",
    "tidefs-pool-scan",
];

// ---------------------------------------------------------------------------
// Forbidden control-plane / POSIX-adapter scaffold crates.
// Kernel-portable crates MUST NOT depend on these, directly or transitively.
// ---------------------------------------------------------------------------
const FORBIDDEN_CRATES: &[&str] = &[
    // Primary control-plane / adapter scaffold crates named in the issue.
    "tidefs-types-control-plane-core",
    "tidefs-posix-filesystem-adapter-workers-locks",
    // Additional adapter/daemon crates that sit above the storage-core layer.
    "tidefs-types-posix-filesystem-adapter-core",
    "tidefs-schema-codec-posix-filesystem-adapter",
    "tidefs-posix-filesystem-adapter-runtime",
    "tidefs-posix-filesystem-adapter-reply",
    "tidefs-posix-filesystem-adapter-workers-io",
    "tidefs-posix-filesystem-adapter-daemon",
    "tidefs-block-volume-adapter-core",
    "tidefs-block-volume-adapter-daemon",
    "tidefs-block-volume-adapter-ublk-control-runtime",
];

// ---------------------------------------------------------------------------
// Public entrypoint
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ClosureCheckError {
    violations: Vec<Violation>,
}

#[derive(Debug)]
struct Violation {
    /// The kernel-portable crate that has a forbidden transitive dependency.
    kernel_crate: String,
    /// The forbidden crate it reaches.
    forbidden_crate: String,
    /// A workspace-internal dependency path from kernel_crate to forbidden_crate.
    path: Vec<String>,
}

impl fmt::Display for ClosureCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "KERNEL PORTABILITY CLOSURE VIOLATION: {} forbidden transitive \
             dependency path(s) found:",
            self.violations.len()
        )?;
        for v in &self.violations {
            writeln!(
                f,
                "  {} -> ... -> {}  (path: {})",
                v.kernel_crate,
                v.forbidden_crate,
                v.path.join(" -> ")
            )?;
        }
        writeln!(
            f,
            "\nStorage-core crates must not depend on control-plane or \
             POSIX-adapter scaffold crates. Check the dependency chain, keep \
             the canonical kernel-portable storage-core set below the adapter \
             boundary, and remove the offending edge."
        )?;
        Ok(())
    }
}

/// Run the kernel-portable dependency closure check on the current workspace.
///
/// Returns `Ok(())` when all kernel-portable crates have a clean transitive
/// closure.  Returns `Err(ClosureCheckError)` with one entry for each distinct
/// `(kernel_crate, forbidden_crate)` violation, showing the shortest
/// workspace-internal dependency path.
pub fn check_kernel_closure(workspace_root: &Path) -> Result<(), ClosureCheckError> {
    let graph = build_dep_graph(workspace_root).map_err(|e| {
        eprintln!("xtask kernel-closure: cargo metadata failed: {e}");
        // Return an empty-violations error so the check fails visibly.
        ClosureCheckError { violations: vec![] }
    })?;
    let mut violations = Vec::new();

    let kernel_set: BTreeSet<&str> = KERNEL_PORTABLE_CORE.iter().copied().collect();
    let forbidden_set: BTreeSet<&str> = FORBIDDEN_CRATES.iter().copied().collect();

    // Warn about crates in the kernel set that don't exist in the workspace.
    // This guards against stale entries in KERNEL_PORTABLE_CORE after renames.
    let workspace_names: BTreeSet<&str> = graph.keys().map(|s| s.as_str()).collect();
    for &k in &kernel_set {
        if !workspace_names.contains(k) {
            eprintln!(
                "xtask kernel-closure: kernel-portable crate '{k}' not found \
                 in workspace -- update KERNEL_PORTABLE_CORE?"
            );
        }
    }

    for kernel_crate in &kernel_set {
        let Some(transitive_closure) = compute_transitive_closure(&graph, kernel_crate) else {
            // Crate not found in graph (already warned above).
            continue;
        };
        for forbidden in &forbidden_set {
            if transitive_closure.contains(*forbidden) {
                // Find shortest path for diagnostics.
                let path = shortest_path(&graph, kernel_crate, forbidden)
                    .unwrap_or_else(|| vec![kernel_crate.to_string(), forbidden.to_string()]);
                violations.push(Violation {
                    kernel_crate: kernel_crate.to_string(),
                    forbidden_crate: forbidden.to_string(),
                    path,
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ClosureCheckError { violations })
    }
}

// ---------------------------------------------------------------------------
// Internal: dependency graph
// ---------------------------------------------------------------------------

type DepGraph = BTreeMap<String, Vec<String>>;

/// Build a directed graph of workspace-internal dependencies from
/// `cargo metadata --no-deps`.
fn build_dep_graph(workspace_root: &Path) -> Result<DepGraph, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root)
        .output()
        .map_err(|e| format!("failed to run cargo metadata: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cargo metadata failed: {stderr}"));
    }

    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("failed to parse cargo metadata JSON: {e}"))?;

    let packages = meta["packages"]
        .as_array()
        .ok_or_else(|| "cargo metadata: missing 'packages' array".to_string())?;

    let mut graph: DepGraph = BTreeMap::new();

    // First pass: collect all workspace package names.
    let mut workspace_names: BTreeSet<String> = BTreeSet::new();
    for pkg in packages {
        if let Some(name) = pkg["name"].as_str() {
            workspace_names.insert(name.to_string());
        }
    }

    // Second pass: build adjacency list using only intra-workspace deps
    // (dependencies that have a `path` field).
    for pkg in packages {
        let name = match pkg["name"].as_str() {
            Some(n) => n.to_string(),
            None => continue,
        };

        let deps = graph.entry(name.clone()).or_default();

        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            let dep_name = match dep["name"].as_str() {
                Some(n) => n,
                None => continue,
            };
            // Only include workspace-internal deps (those with a path field).
            if dep.get("path").is_some() && workspace_names.contains(dep_name) {
                deps.push(dep_name.to_string());
            }
        }
    }

    Ok(graph)
}

/// Compute the set of all workspace-internal crates reachable from `start`
/// (including `start` itself).
fn compute_transitive_closure(graph: &DepGraph, start: &str) -> Option<BTreeSet<String>> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    if !graph.contains_key(start) {
        return None;
    }

    queue.push_back(start.to_string());
    visited.insert(start.to_string());

    while let Some(current) = queue.pop_front() {
        if let Some(deps) = graph.get(&current) {
            for dep in deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }

    Some(visited)
}

/// BFS shortest path from `src` to `dst` in the dependency graph.
fn shortest_path(graph: &DepGraph, src: &str, dst: &str) -> Option<Vec<String>> {
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();

    queue.push_back(vec![src.to_string()]);
    visited.insert(src.to_string());

    while let Some(path) = queue.pop_front() {
        let last = path.last()?;
        if last == dst {
            return Some(path);
        }
        if let Some(deps) = graph.get(last) {
            for dep in deps {
                if !visited.contains(dep) {
                    visited.insert(dep.clone());
                    let mut new_path = path.clone();
                    new_path.push(dep.clone());
                    queue.push_back(new_path);
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Integration entrypoint (called from main.rs)
// ---------------------------------------------------------------------------

pub fn check_current_workspace() -> Result<(), String> {
    let workspace_root = workspace_root()?;
    check_kernel_closure(&workspace_root).map_err(|e| e.to_string())
}

/// Locate the workspace root by walking up from the xtask binary or cwd.
fn workspace_root() -> Result<PathBuf, String> {
    // Prefer the current directory (cargo xtask runs from workspace root).
    let cwd = std::env::current_dir().map_err(|e| format!("cannot get current dir: {e}"))?;

    // Simple heuristic: look for a top-level Cargo.toml with [workspace].
    for ancestor in cwd.ancestors() {
        let cargo_toml = ancestor.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return Ok(ancestor.to_path_buf());
                }
            }
        }
    }

    Err("cannot find workspace root (no Cargo.toml with [workspace] found)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_graph_has_no_violations() {
        let graph: DepGraph = BTreeMap::new();
        let closure = compute_transitive_closure(&graph, "nonexistent");
        assert!(closure.is_none());
    }

    #[test]
    fn single_node_closure() {
        let mut graph: DepGraph = BTreeMap::new();
        graph.insert("a".to_string(), vec![]);
        let closure = compute_transitive_closure(&graph, "a").unwrap();
        assert_eq!(closure, BTreeSet::from(["a".to_string()]));
    }

    #[test]
    fn chain_closure_includes_all_reachable() {
        let mut graph: DepGraph = BTreeMap::new();
        graph.insert("a".to_string(), vec!["b".to_string()]);
        graph.insert("b".to_string(), vec!["c".to_string()]);
        graph.insert("c".to_string(), vec![]);
        let closure = compute_transitive_closure(&graph, "a").unwrap();
        assert_eq!(
            closure,
            BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn shortest_path_direct() {
        let mut graph: DepGraph = BTreeMap::new();
        graph.insert("a".to_string(), vec!["b".to_string()]);
        graph.insert("b".to_string(), vec![]);
        let path = shortest_path(&graph, "a", "b").unwrap();
        assert_eq!(path, vec!["a", "b"]);
    }

    #[test]
    fn shortest_path_multi_hop() {
        let mut graph: DepGraph = BTreeMap::new();
        graph.insert("a".to_string(), vec!["b".to_string()]);
        graph.insert("b".to_string(), vec!["c".to_string(), "d".to_string()]);
        graph.insert("c".to_string(), vec![]);
        graph.insert("d".to_string(), vec![]);
        let path = shortest_path(&graph, "a", "d").unwrap();
        assert_eq!(path, vec!["a", "b", "d"]);
    }
}
