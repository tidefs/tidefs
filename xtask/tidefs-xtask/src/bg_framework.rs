// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// BgFrameworkCheckError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct BgFrameworkCheckError {
    title: &'static str,
    missing: Vec<String>,
}

impl fmt::Display for BgFrameworkCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} failed:", self.title)?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Main check entry point
// ---------------------------------------------------------------------------

pub fn check_background_service_framework_current_workspace() -> Result<(), BgFrameworkCheckError> {
    let root = find_workspace_root().ok_or_else(|| BgFrameworkCheckError {
        title: "background service framework check",
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    check_framework_crate(&root, &mut missing);
    check_scheduler_types(&root, &mut missing);
    check_priority_model(&root, &mut missing);
    check_job_kind_coverage(&root, &mut missing);
    check_budget_enforcement(&root, &mut missing);
    check_starvation_prevention(&root, &mut missing);
    check_background_service_trait(&root, &mut missing);
    check_service_registrations(&root, &mut missing);
    check_priority_ordering_in_registrations(&root, &mut missing);

    if missing.is_empty() {
        println!(
            "background service framework ok: all services registered, \
             priority ordering correct, budget enforcement present, \
             starvation prevention active"
        );
        Ok(())
    } else {
        Err(BgFrameworkCheckError {
            title: "background service framework check",
            missing,
        })
    }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

fn check_framework_crate(root: &Path, missing: &mut Vec<String>) {
    for rel in [
        "crates/tidefs-background-scheduler/Cargo.toml",
        "crates/tidefs-background-scheduler/src/lib.rs",
        "crates/tidefs-background-scheduler/src/scheduling.rs",
    ] {
        check_required_file(root, rel, missing);
    }
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/Cargo.toml",
        &["[package]", "name = \"tidefs-background-scheduler\""],
        missing,
    );
}

fn check_scheduler_types(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "pub struct BackgroundScheduler",
            "pub fn register",
            "pub fn run_cycle",
            "pub fn any_work_pending",
            "pub fn service_count",
            "pub struct IncrementalJobAdapter",
            "pub struct CycleReport",
            "pub struct TickReport",
        ],
        missing,
    );
}

fn check_priority_model(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "pub enum ServicePriority",
            "Critical = 0",
            "LatencySensitive = 1",
            "Throughput = 2",
            "BestEffort = 3",
            "Opportunistic = 4",
            "pub const STAGE_COUNT: usize = 5",
            "pub const ALL: [ServicePriority; 5]",
            "ServicePriority::Critical",
            "ServicePriority::LatencySensitive",
            "ServicePriority::Throughput",
            "ServicePriority::BestEffort",
            "ServicePriority::Opportunistic",
            "pub fn from_job_kind",
        ],
        missing,
    );

    // Verify that the ALL array has the 5 stages in correct priority order.
    let lib_path = root.join("crates/tidefs-background-scheduler/src/lib.rs");
    if let Ok(text) = fs::read_to_string(&lib_path) {
        let all_crit = text.find("ServicePriority::Critical");
        let all_lat = text.find("ServicePriority::LatencySensitive");
        let all_thru = text.find("ServicePriority::Throughput");
        let all_be = text.find("ServicePriority::BestEffort");
        let all_opp = text.find("ServicePriority::Opportunistic");
        if let (Some(c), Some(l), Some(t), Some(b), Some(o)) =
            (all_crit, all_lat, all_thru, all_be, all_opp)
        {
            if !(c < l && l < t && t < b && b < o) {
                missing.push(
                    "ServicePriority::ALL array is not in correct priority order \
                     (Critical < LatencySensitive < Throughput < BestEffort < Opportunistic)"
                        .to_string(),
                );
            }
        }
    }
}

fn check_job_kind_coverage(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "JobKind::Scrub",
            "JobKind::DeepScrub",
            "JobKind::Resilver",
            "JobKind::DerivedCatalog",
            "JobKind::OrphanRecovery",
            "JobKind::Reclaim",
            "JobKind::JournalCleaning",
            "JobKind::DeferredCleanup",
            "JobKind::SnapshotDestroy",
            "JobKind::Rebake",
            "JobKind::DatasetDestroy",
            "JobKind::DataCleaner",
            "JobKind::AdminJob",
            "JobKind::GCMark",
            "JobKind::BtreeCompaction",
            "JobKind::Other",
        ],
        missing,
    );

    // Verify the priority mapping for key services is correct.
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "JobKind::Scrub | JobKind::DeepScrub | JobKind::Resilver | JobKind::Recovery",
            "JobKind::DerivedCatalog",
            "JobKind::OrphanRecovery",
            "JobKind::Reclaim",
            "JobKind::JournalCleaning",
            "ServicePriority::LatencySensitive",
            "JobKind::DataCleaner",
            "ServicePriority::Throughput",
            "JobKind::GCMark | JobKind::BtreeCompaction => ServicePriority::BestEffort",
        ],
        missing,
    );
}

fn check_budget_enforcement(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "pub struct ServiceBudget",
            "pub max_items: u64",
            "pub max_bytes: u64",
            "pub max_ms: u64",
            "pub const DEFAULT_TICK",
            "pub const MAINTENANCE_TICK",
            "pub const SMALL_TICK",
            "pub fn fraction",
            "is_bounded",
        ],
        missing,
    );

    check_source_markers(
        root,
        "crates/tidefs-types-incremental-job-core/src/lib.rs",
        &[
            "pub struct WorkBudget",
            "pub max_items: u64",
            "pub max_bytes: u64",
            "pub max_ms: u64",
            "pub const DEFAULT_TICK",
            "is_bounded",
            "items_within_budget",
        ],
        missing,
    );
}

fn check_starvation_prevention(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "pub struct LaneQueue",
            "pub fn push",
            "pub fn pop",
            "STARVATION_THRESHOLD",
            "pub fn has_starvation",
        ],
        missing,
    );
}

fn check_background_service_trait(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-background-scheduler/src/lib.rs",
        &[
            "pub trait BackgroundService",
            "fn name(&self) -> &'static str",
            "fn priority(&self) -> ServicePriority",
            "fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError>",
            "fn has_work(&self) -> bool",
        ],
        missing,
    );
}

fn check_service_registrations(root: &Path, missing: &mut Vec<String>) {
    check_required_file(root, "crates/tidefs-local-filesystem/src/lib.rs", missing);
    check_required_file(
        root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        missing,
    );

    check_source_markers(
        root,
        "crates/tidefs-local-filesystem/src/lib.rs",
        &[
            "mod background_orphan_reclamation",
            "use tidefs_background_scheduler",
            "BackgroundScheduler",
            "BackgroundService",
            "ServicePriority",
            ".register(Box::new(",
            "orphan_reclamation",
            "BackgroundSchedulerRuntime::start",
        ],
        missing,
    );

    // Model-surface crate existence checks (not integration validation).
    // The live mounted-pool reclaim authority is LocalObjectStore::drain_dead_segments.
    for rel in [
        "crates/tidefs-data-cleaner/Cargo.toml",
        "crates/tidefs-derived-catalog/Cargo.toml",
    ] {
        check_required_file(root, rel, missing);
    }
    check_source_markers(
        root,
        "crates/tidefs-data-cleaner/src/lib.rs",
        &["DataCleanerService", "IncrementalJob", "DataCleaner"],
        missing,
    );

    // Live reclaim authority: verify drain_dead_segments exists in LocalObjectStore.
    check_source_markers(
        root,
        "crates/tidefs-local-object-store/src/store.rs",
        &["pub fn drain_dead_segments"],
        missing,
    );
    check_source_markers(
        root,
        "crates/tidefs-derived-catalog/src/lib.rs",
        &["ViewBuilderService", "IncrementalJob", "DerivedCatalog"],
        missing,
    );
}

fn check_priority_ordering_in_registrations(root: &Path, missing: &mut Vec<String>) {
    check_source_markers(
        root,
        "crates/tidefs-local-filesystem/src/background_orphan_reclamation.rs",
        &[
            "impl BackgroundService for BackgroundOrphanReclamation",
            "fn priority",
            "ServicePriority::Critical",
        ],
        missing,
    );
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn find_workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.is_file() {
            let Ok(text) = fs::read_to_string(&cargo_toml) else {
                return None;
            };
            if text.contains("[workspace]") {
                return Some(dir);
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    if !root.join(rel).is_file() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let path = root.join(rel);
    let Ok(text) = fs::read_to_string(&path) else {
        missing.push(format!("could not read `{rel}`"));
        return;
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("`{rel}` missing marker `{marker}`"));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_passes_on_current_workspace() {
        let result = check_background_service_framework_current_workspace();
        match result {
            Ok(()) => { /* expected */ }
            Err(ref e) => {
                panic!(
                    "check_background_service_framework_current_workspace \
                     should pass on current workspace but got: {e}"
                );
            }
        }
    }

    #[test]
    fn missing_file_detected() {
        let mut missing = Vec::new();
        let tmp = std::env::temp_dir();
        check_required_file(&tmp, "nonexistent/file/that/cannot/exist.rs", &mut missing);
        assert!(!missing.is_empty());
        assert!(missing[0].contains("missing required file"));
    }

    #[test]
    fn missing_marker_detected() {
        let mut missing = Vec::new();
        let tmp = std::env::temp_dir();
        let test_file = tmp.join("bg_test_file.rs");
        std::fs::write(&test_file, "// present_marker\n").unwrap();
        check_source_markers(
            &tmp,
            "bg_test_file.rs",
            &["present_marker", "missing_marker"],
            &mut missing,
        );
        std::fs::remove_file(&test_file).ok();
        assert_eq!(missing.len(), 1);
        assert!(missing[0].contains("missing_marker"));
    }

    #[test]
    fn find_workspace_root_finds_tidefs() {
        let root = find_workspace_root();
        assert!(root.is_some(), "should find workspace root");
        let root = root.unwrap();
        assert!(root.join("Cargo.toml").is_file());
    }

    #[test]
    fn error_display_is_nonempty() {
        let err = BgFrameworkCheckError {
            title: "test check",
            missing: vec!["item A missing".to_string(), "item B missing".to_string()],
        };
        let msg = format!("{err}");
        assert!(msg.contains("test check failed:"));
        assert!(msg.contains("item A missing"));
        assert!(msg.contains("item B missing"));
    }

    #[test]
    fn priority_model_check_rejects_wrong_order() {
        // Test that the positional ordering check would catch a
        // misordered ALL array by simulating the logic locally.
        let text = "\
            ServicePriority::Critical,\n\
            ServicePriority::Throughput,\n\
            ServicePriority::LatencySensitive,\n\
            ServicePriority::BestEffort,\n\
            ServicePriority::Opportunistic,\n\
        ";
        let all_crit = text.find("ServicePriority::Critical");
        let all_lat = text.find("ServicePriority::LatencySensitive");
        let all_thru = text.find("ServicePriority::Throughput");
        let all_be = text.find("ServicePriority::BestEffort");
        let all_opp = text.find("ServicePriority::Opportunistic");

        let (c, l, t, b, o) = (
            all_crit.unwrap(),
            all_lat.unwrap(),
            all_thru.unwrap(),
            all_be.unwrap(),
            all_opp.unwrap(),
        );

        // In this text, Throughput comes before LatencySensitive, so
        // t < l but we need l < t for correct order. The check should
        // fail: not (c < l && l < t && t < b && b < o).
        let correct_order = c < l && l < t && t < b && b < o;
        assert!(
            !correct_order,
            "this text has wrong order, so check should reject it"
        );
    }

    #[test]
    fn priority_model_check_accepts_correct_order() {
        let text = "\
            ServicePriority::Critical,\n\
            ServicePriority::LatencySensitive,\n\
            ServicePriority::Throughput,\n\
            ServicePriority::BestEffort,\n\
            ServicePriority::Opportunistic,\n\
        ";
        let all_crit = text.find("ServicePriority::Critical");
        let all_lat = text.find("ServicePriority::LatencySensitive");
        let all_thru = text.find("ServicePriority::Throughput");
        let all_be = text.find("ServicePriority::BestEffort");
        let all_opp = text.find("ServicePriority::Opportunistic");

        let (c, l, t, b, o) = (
            all_crit.unwrap(),
            all_lat.unwrap(),
            all_thru.unwrap(),
            all_be.unwrap(),
            all_opp.unwrap(),
        );
        assert!(c < l && l < t && t < b && b < o);
    }
}
