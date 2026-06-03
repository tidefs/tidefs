use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

// ── Gate receipt types inlined from tidefs-types-gate-receipt (removed per #3291) ──
// Only the subset needed by xtask coverage closure checker is kept here.
// Original crate: crates/tidefs-types-gate-receipt/src/lib.rs (413 lines, zero other consumers).

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ValidationFamily {
    E0DesignRuleReview,
    E1KernelCharterConformance,
    E2PublicationRepairFailure,
    E3ContinuityCharter,
    E4ProductEconomy,
    E5LocalityCoordination,
    E6OperatorTruthfulness,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GateClass {
    Admit,
    Refuse,
    Skip,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
pub struct FalsificationBucket {
    pub bucket_id: String,
    pub closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ArtifactRequirement {
    pub artifact_class: String,
    pub emitted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct GateReceiptV1 {
    pub schema: String,
    pub matrix_family: String,
    pub row_id: String,
    pub row_label: String,
    pub suite_family: String,
    pub profile: String,
    pub variant: String,
    pub gate_class: GateClass,
    pub executed_utc: String,
    pub repo_commit: String,
    pub repo_dirty: bool,
    pub required_validation_families: Vec<ValidationFamily>,
    pub satisfied_validation_families: Vec<ValidationFamily>,
    pub required_artifacts: Vec<ArtifactRequirement>,
    pub falsification_buckets: Vec<FalsificationBucket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_log_path: Option<String>,
}

impl GateReceiptV1 {
    #[must_use]
    pub fn all_validation_families_satisfied(&self) -> bool {
        if self.required_validation_families.is_empty() {
            return false;
        }
        for required in &self.required_validation_families {
            if !self.satisfied_validation_families.contains(required) {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn all_artifacts_emitted(&self) -> bool {
        self.required_artifacts.iter().all(|a| a.emitted)
    }

    #[must_use]
    pub fn all_buckets_closed(&self) -> bool {
        if self.falsification_buckets.is_empty() {
            return false;
        }
        self.falsification_buckets.iter().all(|b| b.closed)
    }

    #[must_use]
    pub fn is_coverage_closed(&self) -> bool {
        self.gate_class == GateClass::Admit
            && self.all_validation_families_satisfied()
            && self.all_artifacts_emitted()
            && self.all_buckets_closed()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct MatrixFamilyClosureSnapshot {
    pub matrix_family: String,
    pub registered_rows: usize,
    pub source_bound: usize,
    pub executed_validation: usize,
    pub coverage_closed: usize,
    pub rows: Vec<RowClosureStatus>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RowClosureStatus {
    pub row_id: String,
    pub row_label: String,
    pub source_bound: bool,
    pub executed_validation: bool,
    pub coverage_closed: bool,
}

#[derive(Debug)]
pub struct CoverageClosureError {
    message: String,
}

impl fmt::Display for CoverageClosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "coverage closure check failed: {}", self.message)
    }
}

/// Entry point for `tidefs-xtask check-coverage-closure`.
///
/// Scans `/root/ai/tmp/tidefs-validation/` for `GateReceiptV1` JSON files, aggregates
/// per-matrix-family coverage status, and prints a closure snapshot.
pub fn check_coverage_closure_current_workspace() -> Result<(), CoverageClosureError> {
    let runs_dir = std::env::var_os("TIDEFS_VALIDATION_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root/ai/tmp/tidefs-validation"));
    if !runs_dir.is_dir() {
        println!(
            "coverage closure: no /root/ai/tmp/tidefs-validation/ directory found — {}",
            runs_dir.display()
        );
        println!("0 receipts loaded; 0 rows coverage-closed.");
        return Ok(());
    }

    let receipts = load_all_receipts(&runs_dir);
    println!(
        "coverage closure: loaded {} receipt(s) from {}",
        receipts.len(),
        runs_dir.display()
    );

    if receipts.is_empty() {
        println!("0 rows coverage-closed.");
        return Ok(());
    }

    let snapshots = build_closure_snapshots(&receipts);

    // Print table
    println!();
    println!(
        "{:<52} {:>3} {:>3} {:>3} {:>3}",
        "Matrix family", "Reg", "SB", "Ev", "Cls"
    );
    println!("{}", "-".repeat(70));

    let mut total_registered = 0usize;
    let mut total_source_bound = 0usize;
    let mut total_executed = 0usize;
    let mut total_closed = 0usize;

    for snap in &snapshots {
        println!(
            "{:<52} {:>3} {:>3} {:>3} {:>3}",
            snap.matrix_family,
            snap.registered_rows,
            snap.source_bound,
            snap.executed_validation,
            snap.coverage_closed,
        );
        total_registered += snap.registered_rows;
        total_source_bound += snap.source_bound;
        total_executed += snap.executed_validation;
        total_closed += snap.coverage_closed;
    }

    println!("{}", "-".repeat(70));
    println!(
        "{:<52} {:>3} {:>3} {:>3} {:>3}",
        "TOTAL", total_registered, total_source_bound, total_executed, total_closed,
    );
    println!();
    println!("Reg=registered  SB=implementation-tracked non-release  Ev=executed-validation  Cls=coverage-closed");

    // Per-row detail for rows that are not yet coverage-closed
    let any_open = snapshots
        .iter()
        .any(|s| s.coverage_closed < s.registered_rows);
    if any_open {
        println!();
        println!("Rows not yet coverage-closed:");
        for snap in &snapshots {
            for row in &snap.rows {
                if !row.coverage_closed {
                    let status = if row.executed_validation {
                        "executed-validation"
                    } else if row.source_bound {
                        "implementation-tracked non-release"
                    } else {
                        "registered"
                    };
                    println!("  {}/{}  [{status}]", snap.matrix_family, row.row_id);
                }
            }
        }
    }

    Ok(())
}

/// Recursively load all `*.gate_receipt.json` files from the runs directory.
fn load_all_receipts(runs_dir: &Path) -> Vec<GateReceiptV1> {
    let mut receipts = Vec::new();
    load_receipts_recursive(runs_dir, &mut receipts);
    receipts
}

fn load_receipts_recursive(dir: &Path, out: &mut Vec<GateReceiptV1>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            load_receipts_recursive(&path, out);
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".gate_receipt.json"))
        {
            if let Ok(data) = fs::read_to_string(&path) {
                if let Ok(receipt) = serde_json::from_str::<GateReceiptV1>(&data) {
                    out.push(receipt);
                }
            }
        }
    }
}

/// Build per-matrix-family closure snapshots from loaded receipts.
fn build_closure_snapshots(receipts: &[GateReceiptV1]) -> Vec<MatrixFamilyClosureSnapshot> {
    // Group receipts by matrix family then by row_id
    use std::collections::BTreeMap;

    let mut families: BTreeMap<String, BTreeMap<String, Vec<&GateReceiptV1>>> = BTreeMap::new();
    for r in receipts {
        families
            .entry(r.matrix_family.clone())
            .or_default()
            .entry(r.row_id.clone())
            .or_default()
            .push(r);
    }

    let mut snapshots: Vec<MatrixFamilyClosureSnapshot> = Vec::new();

    for (family_name, rows) in &families {
        let registered_rows = rows.len();
        let mut source_bound = 0usize;
        let mut executed_validation = 0usize;
        let mut coverage_closed = 0usize;
        let mut row_statuses = Vec::new();

        for (row_id, receipts) in rows {
            // Determine best status for this row across all receipts
            let latest = receipts.iter().max_by_key(|r| &r.executed_utc).copied();

            let is_source_bound = receipts.iter().any(|r| !r.suite_family.is_empty());
            // Actually, a row is executed-validation if there's at least one receipt
            // with a non-empty executed_utc
            let is_executed = latest.is_some_and(|r| !r.executed_utc.is_empty());
            let is_closed = latest.is_some_and(|r| r.is_coverage_closed());

            if is_source_bound {
                source_bound += 1;
            }
            if is_executed {
                executed_validation += 1;
            }
            if is_closed {
                coverage_closed += 1;
            }

            row_statuses.push(RowClosureStatus {
                row_id: row_id.clone(),
                row_label: latest.map_or_else(String::new, |r| r.row_label.clone()),
                source_bound: is_source_bound,
                executed_validation: is_executed,
                coverage_closed: is_closed,
            });
        }

        snapshots.push(MatrixFamilyClosureSnapshot {
            matrix_family: family_name.clone(),
            registered_rows,
            source_bound,
            executed_validation,
            coverage_closed,
            rows: row_statuses,
        });
    }

    snapshots
}
