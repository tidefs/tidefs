// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pool rollback (export) and import validation surface.
//!
//! This module captures the current-head state of three validation surfaces:
//!
//! 1. **Pool export** (rollback path) — `tidefs-control-plane-runtime` writes
//!    `Exported` state labels to devices so a pool can be safely detached.
//!    Source: `crates/tidefs-control-plane-runtime/src/pool_api.rs`'s
//!    `execute_pool_export`.
//!
//! 2. **Pool import** — `tidefs-pool-import` scans devices, verifies
//!    superblocks, replays intent log, recovers the committed root, and
//!    activates the pool for mount.  Source: `crates/tidefs-pool-import/src/lib.rs`'s
//!    `pool_import` and `ImportError`.
//!
//! 3. **Snapshot rollback** — `tidefs-local-filesystem`'s
//!    `rollback_to_snapshot` replaces the live filesystem state with a
//!    previously captured snapshot, incrementally reloading only changed
//!    inodes and clearing stale write buffers.  Source: `crates/tidefs-local-filesystem/src/lib.rs`'s
//!    `rollback_to_snapshot`.
//!
//! ## Validation Tiers
//!
//! | Surface | Source/Cargo (T0-T1) | Harness (T2) | QEMU Guest (T3) | Kernel (T4+) |
//! |---|---|---|---|---|
//! | Pool export | `pool_api.rs` tests + `pool_export_*` unit tests | `pool-e2e-blockdev-validation.nix` | **GAP**: no QEMU validation output for export→reimport cycle | N/A |
//! | Pool import | `tidefs-pool-import` + `tidefs-storage-node` integration tests | `pool-remount-lifecycle-validation.nix` + `pool-e2e-blockdev-validation.nix` | **GAP**: no QEMU validation output | `kernel-pool-import-validation.nix` retired |
//! | Snapshot rollback | `snapshot.rs` + `tests.rs` rollback tests | none dedicated | **GAP**: no QEMU harness for rollback persistence after export/import | N/A |
//!
//! ## Current-Head Blockers
//!
//! 1. **No Tier 3 pool export/import QEMU validation output.** The Nix VMs
//!    `pool-remount-lifecycle-validation.nix` and `pool-e2e-blockdev-validation.nix`
//!    are harness-functional but no `/root/ai/tmp/tidefs-validation/` artifact with a real
//!    `qemu-system-x86_64` log exists for the export→reimport persistence
//!    cycle.
//! 2. **Kernel pool import validation retired.** `kernel-pool-import-validation.nix`
//!    intentionally fails closed because the previous wrapper used regular-file
//!    backing and lazy unmount/remount cycles as crash validation.  A real
//!    replacement requires Linux 7.0 QEMU with kmod-posix-vfs loaded and
//!    actual hard reset cycles.
//! 3. **Snapshot rollback persistence after pool export/import is not
//!    validated.** The `rollback_to_snapshot` path is tested at the cargo/unit
//!    tier but no harness exercises rollback across pool export→reimport→mount
//!    cycles.
//!
//! ## Next Steps for Tier 3 Closure
//!
//! - Run `pool-remount-lifecycle-validation.nix` or
//!   `pool-e2e-blockdev-validation.nix` with `--keep-tmp` and write the QEMU
//!   log under `/root/ai/tmp/tidefs-validation/<run-id>/`.
//! - Capture `validation-manifest.json` for the run with the E2E validation schema.
//! - For snapshot rollback: extend an existing pool lifecycle harness to
//!   create a snapshot before export, import on a fresh mount, and verify
//!   rollback state matches.

use std::path::PathBuf;

/// A single validation surface in the rollback/import domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackImportSurface {
    /// Human-readable surface name (e.g. "pool-export", "pool-import",
    /// "snapshot-rollback").
    pub name: String,
    /// Current validation tier reached (T0 through T6, or empty if not run).
    pub validation_tier: String,
    /// Whether this surface has /root/ai/tmp/tidefs-validation/ artifacts.
    pub has_validation_output: bool,
    /// Paths to existing harnesses (Nix VMs, scripts) that can exercise
    /// this surface.
    pub harness_paths: Vec<PathBuf>,
    /// Source crate/module paths implementing the surface.
    pub source_paths: Vec<PathBuf>,
    /// Active blockers preventing this surface from reaching the next tier.
    pub blockers: Vec<String>,
}

/// The set of rollback/import validation surfaces on current head.
pub fn rollback_import_surfaces() -> Vec<RollbackImportSurface> {
    vec![
        RollbackImportSurface {
            name: "pool-export".into(),
            validation_tier: "T1 (cargo/unit)".into(),
            has_validation_output: false,
            harness_paths: vec![
                PathBuf::from("nix/vm/pool-e2e-blockdev-validation.nix"),
                PathBuf::from("nix/vm/pool-remount-lifecycle-validation.nix"),
            ],
            source_paths: vec![
                PathBuf::from("crates/tidefs-control-plane-runtime/src/pool_api.rs"),
            ],
            blockers: vec![
                "No QEMU validation output for export→reimport persistence cycle"
                    .into(),
            ],
        },
        RollbackImportSurface {
            name: "pool-import".into(),
            validation_tier: "T1 (cargo/unit + storage-node integration)".into(),
            has_validation_output: false,
            harness_paths: vec![
                PathBuf::from("nix/vm/pool-e2e-blockdev-validation.nix"),
                PathBuf::from("nix/vm/pool-remount-lifecycle-validation.nix"),
            ],
            source_paths: vec![
                PathBuf::from("crates/tidefs-pool-import/src/lib.rs"),
                PathBuf::from("apps/tidefs-storage-node/src/server.rs"),
            ],
            blockers: vec![
                "No QEMU validation output for import-after-export persistence"
                    .into(),
                "Kernel pool-import validation wrapper retired; needs Linux 7.0 QEMU replacement"
                    .into(),
            ],
        },
        RollbackImportSurface {
            name: "snapshot-rollback".into(),
            validation_tier: "T1 (cargo/unit)".into(),
            has_validation_output: false,
            harness_paths: vec![],
            source_paths: vec![
                PathBuf::from("crates/tidefs-local-filesystem/src/lib.rs"),
                PathBuf::from("crates/tidefs-local-filesystem/src/snapshot.rs"),
                PathBuf::from("crates/tidefs-local-filesystem/src/tests.rs"),
            ],
            blockers: vec![
                "No dedicated harness for rollback persistence across pool export/import cycles"
                    .into(),
                "rollback_to_snapshot committed state does not persist across remount (known limitation in snapshot.rs:1133)"
                    .into(),
            ],
        },
    ]
}

/// Current-head rollback/import validation summary as markdown.
///
/// Produces a table showing each surface, its current tier, harness paths,
/// and active blockers.  Suitable for embedding in validation manifests or
/// release documentation.
pub fn render_rollback_import_summary_md() -> String {
    let surfaces = rollback_import_surfaces();
    let mut md = String::new();
    md.push_str("## Rollback and Import Validation (Current Head)\n\n");
    md.push_str("| Surface | Validation Tier | Output? | Harnesses | Active Blockers |\n");
    md.push_str("|---|---|---|---|---|\n");
    for s in &surfaces {
        let hpaths = s
            .harness_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let hpaths = if hpaths.is_empty() { "none" } else { &hpaths };
        let blockers = s.blockers.join("; ");
        let blockers = if blockers.is_empty() {
            "none"
        } else {
            &blockers
        };
        let output = if s.has_validation_output { "yes" } else { "no" };
        md.push_str(&format!(
            "| {} | {} | {output} | {hpaths} | {blockers} |\n",
            s.name, s.validation_tier
        ));
    }
    md.push_str("\nSource paths:\n");
    for s in &surfaces {
        for sp in &s.source_paths {
            md.push_str(&format!("- `{}`\n", sp.display()));
        }
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surfaces_are_non_empty() {
        let surfaces = rollback_import_surfaces();
        assert!(!surfaces.is_empty(), "expected at least one surface");
    }

    #[test]
    fn pool_export_surface_has_harness() {
        let surfaces = rollback_import_surfaces();
        let export = surfaces
            .iter()
            .find(|s| s.name == "pool-export")
            .expect("pool-export surface missing");
        assert!(
            !export.harness_paths.is_empty(),
            "pool-export must reference at least one harness"
        );
        assert!(
            !export.blockers.is_empty(),
            "pool-export must record its Tier 3 gap"
        );
    }

    #[test]
    fn pool_import_surface_has_source() {
        let surfaces = rollback_import_surfaces();
        let import = surfaces
            .iter()
            .find(|s| s.name == "pool-import")
            .expect("pool-import surface missing");
        assert!(
            !import.source_paths.is_empty(),
            "pool-import must reference source paths"
        );
    }

    #[test]
    fn snapshot_rollback_surface_present() {
        let surfaces = rollback_import_surfaces();
        let snap = surfaces
            .iter()
            .find(|s| s.name == "snapshot-rollback")
            .expect("snapshot-rollback surface missing");
        assert!(
            snap.source_paths
                .iter()
                .any(|p| { p.to_string_lossy().contains("local-filesystem") }),
            "snapshot-rollback must reference local-filesystem source"
        );
    }

    #[test]
    fn render_produces_markdown_table() {
        let md = render_rollback_import_summary_md();
        assert!(md.contains("| Surface |"), "missing table header");
        assert!(md.contains("| pool-export |"), "missing pool-export row");
        assert!(md.contains("| pool-import |"), "missing pool-import row");
        assert!(
            md.contains("| snapshot-rollback |"),
            "missing snapshot-rollback row"
        );
        assert!(md.contains("## Rollback"), "missing section header");
    }

    #[test]
    fn no_surface_claims_false_validation_output() {
        for s in &rollback_import_surfaces() {
            assert!(
                !s.has_validation_output,
                "surface '{}' claims validation output but none exists yet",
                s.name
            );
        }
    }
}
