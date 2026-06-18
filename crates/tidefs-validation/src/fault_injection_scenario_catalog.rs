// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Fault injection scenario catalog (NEXT-VAL-012).
//!
//! Maps required failure scenarios to fault classes, crash injection points,
//! scripts, Forgejo tickets, and release gates across every TideFS subsystem.
//!
//! This is a prerequisite/documentation artifact. It documents what fault
//! injection coverage TideFS needs for release readiness, what already exists,
//! and where the remaining gaps are. It does not close runtime, QEMU, Kbuild,
//! mounted-kernel, or kernel block-I/O gates by itself.
//!
//! ## Relationship to existing fault injection infrastructure
//!
//! `tidefs-local-object-store::fault_catalog` defines the *taxonomy* of fault
//! classes (31 classes across 6 families) and the schedule/manifest types.
//! `tidefs-local-object-store::fault_injection` defines the 21 concrete
//! `CrashInjectionPoint` variants wired into commit_group, namespace, I/O,
//! recovery, and repair paths. `tidefs-local-filesystem::crash_hooks` provides
//! the thread-local injection mechanism (arm, check, disarm).
//!
//! This module defines the *scenario layer*: it binds fault classes and
//! injection points into named, release-gate-mapped scenarios with concrete
//! scripts and tickets so release readiness can be evaluated systematically.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Scenario types
// ---------------------------------------------------------------------------

/// A single fault injection scenario.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultInjectionScenario {
    /// Unique scenario identifier (e.g. "fi-fuse-crash-commit-before-sync").
    pub id: String,
    /// Human-readable short name.
    pub name: String,
    /// Longer description of what is injected and what is verified.
    pub description: String,
    /// TideFS subsystem(s) affected.
    pub subsystem: Vec<Subsystem>,
    /// Fault class reference(s) from the P10-02 fault catalog (by label string).
    pub fault_classes: Vec<String>,
    /// Crash injection point(s) from CrashInjectionPoint (by label string).
    pub crash_injection_points: Vec<String>,
    /// Release gate(s) this scenario validates.
    pub release_gates: Vec<ReleaseGateRef>,
    /// Existing Forgejo ticket(s) that own this scenario.
    pub tickets: Vec<u64>,
    /// Script path(s) that execute this scenario (Nix VM, shell, xtask).
    pub scripts: Vec<String>,
    /// Current coverage status.
    pub coverage: ScenarioCoverage,
    /// Validation tier required to close the scenario.
    pub required_validation_tier: ValidationTier,
}

/// TideFS subsystem classification for fault injection scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Subsystem {
    /// FUSE userspace POSIX adapter.
    Fuse,
    /// ublk block-volume adapter.
    Ublk,
    /// Kernel POSIX VFS (kmod-posix-vfs).
    KernelVfs,
    /// Kernel block I/O (kmod-block).
    KernelBlock,
    /// Local object store, commit_group, intent-log, recovery.
    StorageCore,
    /// Transport/session layer.
    Transport,
    /// Membership, placement, epoch.
    Membership,
    /// RDMA data path.
    Rdma,
    /// Pool import, device lifecycle.
    PoolLifecycle,
    /// Repair, scrub, rebuild.
    Repair,
    /// Multi-node distributed operation.
    MultiNode,
}

impl Subsystem {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fuse => "FUSE",
            Self::Ublk => "ublk",
            Self::KernelVfs => "kernel-VFS",
            Self::KernelBlock => "kernel-block",
            Self::StorageCore => "storage-core",
            Self::Transport => "transport",
            Self::Membership => "membership",
            Self::Rdma => "RDMA",
            Self::PoolLifecycle => "pool-lifecycle",
            Self::Repair => "repair",
            Self::MultiNode => "multi-node",
        }
    }
}

/// Reference to a release gate (from FEATURE_MATRIX.md or CURRENT_RELEASE_FOCUS.md).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReleaseGateRef {
    /// Gate identifier (e.g. "FUSE crash recovery", "Kernel block crash consistency").
    pub gate: String,
    /// Matrix row or document section where the gate is defined.
    pub source: String,
}

/// Coverage status of a fault injection scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScenarioCoverage {
    /// Scenario has passing cargo-level tests.
    CargoCovered,
    /// Scenario has a Nix VM / QEMU script but runtime validation not yet recorded.
    ScriptExists,
    /// Scenario is owned by an open Forgejo ticket.
    TicketOwned,
    /// Scenario has runtime validation output (T3+).
    RuntimeValidation,
    /// No coverage exists; this is a gap.
    Gap,
}

/// Validation tier per the CURRENT_RELEASE_FOCUS.md tier table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ValidationTier {
    /// Tier 0: Source/model/schema/proposal state.
    Tier0,
    /// Tier 1: Cargo/unit/focused crate tests.
    Tier1,
    /// Tier 2: Harness without a mounted/live product path.
    Tier2,
    /// Tier 3: Mounted userspace or QEMU guest runtime.
    Tier3,
    /// Tier 4: Linux 7.0 Kbuild and QEMU module load.
    Tier4,
    /// Tier 5: Mounted kernel VFS or kernel block I/O.
    Tier5,
    /// Tier 6: Full-kernel no-daemon mounted operation.
    Tier6,
    /// Tier 7: Multi-process distributed/RDMA runtime.
    Tier7,
}

impl ValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Tier0 => "T0-source-model",
            Self::Tier1 => "T1-cargo-unit",
            Self::Tier2 => "T2-harness",
            Self::Tier3 => "T3-mounted-userspace",
            Self::Tier4 => "T4-kbuild-module-load",
            Self::Tier5 => "T5-mounted-kernel",
            Self::Tier6 => "T6-full-kernel-no-daemon",
            Self::Tier7 => "T7-distributed-rdma",
        }
    }
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

/// The complete fault injection scenario catalog.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaultInjectionScenarioCatalog {
    /// Catalog version (incremented when scenarios are added/removed).
    pub version: u32,
    /// Total scenarios defined.
    pub scenario_count: usize,
    /// All scenarios.
    pub scenarios: Vec<FaultInjectionScenario>,
}

impl FaultInjectionScenarioCatalog {
    /// Build the canonical fault injection scenario catalog.
    pub fn canonical() -> Self {
        let scenarios = build_catalog();
        let count = scenarios.len();
        Self {
            version: 1,
            scenario_count: count,
            scenarios,
        }
    }

    /// Count scenarios by coverage status.
    pub fn count_by_coverage(&self, coverage: ScenarioCoverage) -> usize {
        self.scenarios
            .iter()
            .filter(|s| s.coverage == coverage)
            .count()
    }

    /// Count scenarios by subsystem.
    pub fn count_by_subsystem(&self, subsystem: Subsystem) -> usize {
        self.scenarios
            .iter()
            .filter(|s| s.subsystem.contains(&subsystem))
            .count()
    }

    /// Return only gap scenarios (no coverage).
    pub fn gaps(&self) -> Vec<&FaultInjectionScenario> {
        self.scenarios
            .iter()
            .filter(|s| s.coverage == ScenarioCoverage::Gap)
            .collect()
    }

    /// Return scenarios for a specific validation tier.
    pub fn by_tier(&self, tier: ValidationTier) -> Vec<&FaultInjectionScenario> {
        self.scenarios
            .iter()
            .filter(|s| s.required_validation_tier == tier)
            .collect()
    }

    /// Render the catalog as a markdown table suitable for docs/.
    pub fn to_markdown_table(&self) -> String {
        let mut out = String::new();
        out.push_str("# Fault Injection Scenario Catalog\n\n");
        out.push_str(&format!("Version: {}\n", self.version));
        out.push_str(&format!("Total scenarios: {}\n\n", self.scenario_count));

        // Summary by subsystem
        out.push_str("## Coverage Summary\n\n");
        out.push_str("| Subsystem | Total | Cargo | Script | Ticket | Runtime | Gap |\n");
        out.push_str("|---|---|---|---|---|---|---|\n");
        for sub in ALL_SUBSYSTEMS {
            let total = self.count_by_subsystem(*sub);
            if total == 0 {
                continue;
            }
            let cargo = self
                .scenarios
                .iter()
                .filter(|s| {
                    s.subsystem.contains(sub) && s.coverage == ScenarioCoverage::CargoCovered
                })
                .count();
            let script = self
                .scenarios
                .iter()
                .filter(|s| {
                    s.subsystem.contains(sub) && s.coverage == ScenarioCoverage::ScriptExists
                })
                .count();
            let ticket = self
                .scenarios
                .iter()
                .filter(|s| {
                    s.subsystem.contains(sub) && s.coverage == ScenarioCoverage::TicketOwned
                })
                .count();
            let runtime = self
                .scenarios
                .iter()
                .filter(|s| {
                    s.subsystem.contains(sub) && s.coverage == ScenarioCoverage::RuntimeValidation
                })
                .count();
            let gap = self
                .scenarios
                .iter()
                .filter(|s| s.subsystem.contains(sub) && s.coverage == ScenarioCoverage::Gap)
                .count();
            out.push_str(&format!(
                "| {} | {total} | {cargo} | {script} | {ticket} | {runtime} | {gap} |\n",
                sub.label()
            ));
        }

        // Detailed scenario table
        out.push_str("\n## Scenario Catalog\n\n");
        out.push_str("| ID | Name | Subsystem | Fault Classes | Injection Points | Release Gates | Tickets | Scripts | Coverage | Tier |\n");
        out.push_str("|---|---|---|---|---|---|---|---|---|---|\n");
        for s in &self.scenarios {
            let subs: Vec<&str> = s.subsystem.iter().map(|x| x.label()).collect();
            let gates: Vec<&str> = s.release_gates.iter().map(|g| g.gate.as_str()).collect();
            let coverage_str = match s.coverage {
                ScenarioCoverage::CargoCovered => "cargo",
                ScenarioCoverage::ScriptExists => "script",
                ScenarioCoverage::TicketOwned => "ticket",
                ScenarioCoverage::RuntimeValidation => "runtime",
                ScenarioCoverage::Gap => "**GAP**",
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                s.id,
                s.name,
                subs.join(", "),
                s.fault_classes.join(", "),
                s.crash_injection_points.join(", "),
                gates.join("; "),
                format_tickets(&s.tickets),
                s.scripts.join(", "),
                coverage_str,
                s.required_validation_tier.label(),
            ));
        }

        out
    }

    /// Produce a JSON gap report for programmatic consumption.
    pub fn gap_report_json(&self) -> String {
        let gaps: Vec<&FaultInjectionScenario> = self.gaps();
        let report = serde_json::json!({
            "catalog_version": self.version,
            "total_scenarios": self.scenario_count,
            "gap_count": gaps.len(),
            "gaps": gaps.iter().map(|s| serde_json::json!({
                "id": s.id,
                "name": s.name,
                "subsystem": s.subsystem.iter().map(|x| x.label()).collect::<Vec<_>>(),
                "release_gates": s.release_gates.iter().map(|g| &g.gate).collect::<Vec<_>>(),
                "required_tier": s.required_validation_tier.label(),
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&report).unwrap_or_default()
    }
}

fn format_tickets(tickets: &[u64]) -> String {
    if tickets.is_empty() {
        return "-".to_string();
    }
    tickets
        .iter()
        .map(|t| format!("#{t}"))
        .collect::<Vec<_>>()
        .join(", ")
}

const ALL_SUBSYSTEMS: &[Subsystem] = &[
    Subsystem::Fuse,
    Subsystem::Ublk,
    Subsystem::KernelVfs,
    Subsystem::KernelBlock,
    Subsystem::StorageCore,
    Subsystem::Transport,
    Subsystem::Membership,
    Subsystem::Rdma,
    Subsystem::PoolLifecycle,
    Subsystem::Repair,
    Subsystem::MultiNode,
];

// ---------------------------------------------------------------------------
// Scenario definitions
// ---------------------------------------------------------------------------

/// Build the complete catalog of required fault injection scenarios.
fn build_catalog() -> Vec<FaultInjectionScenario> {
    let mut s = Vec::with_capacity(64);

    // ── Storage Core: Commit group crash boundary ──
    s.push(FaultInjectionScenario {
        id: "fi-storage-commit-before-quiesce".into(),
        name: "Crash before commit group quiesce".into(),
        description: "Kill process after txg open but before quiesce phase. Verifies uncommitted txg data is discarded and pool remounts cleanly.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["COMMIT_GROUP_BEFORE_QUIESCE".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "TXG group commit and crash boundary".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6319, 6253],
        scripts: vec!["crates/tidefs-local-filesystem/tests/crash_injection_tests.rs".into()],
        coverage: ScenarioCoverage::CargoCovered,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-commit-before-commit".into(),
        name: "Crash after data sync, before commit record".into(),
        description: "Kill process after data sync but before the commit record is written. Verifies sync'd data survives and intent-log replay recovers to last committed root.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["COMMIT_GROUP_BEFORE_COMMIT".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "TXG group commit and crash boundary".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6319],
        scripts: vec!["crates/tidefs-local-filesystem/tests/crash_injection_tests.rs".into()],
        coverage: ScenarioCoverage::CargoCovered,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-commit-after-append".into(),
        name: "Crash after intent-log append, before commit".into(),
        description: "Kill process after intent-log entries are appended but before commit record is finalized. Verifies intent-log replay restores operations correctly.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["COMMIT_GROUP_AFTER_APPEND_DATA".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "Intent-log crash replay".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6253, 6254],
        scripts: vec!["crates/tidefs-local-filesystem/tests/crash_injection_tests.rs".into()],
        coverage: ScenarioCoverage::CargoCovered,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-double-crash-chain".into(),
        name: "Double crash recovery chain".into(),
        description: "Crash, recover, write new data, crash again. Verifies second recovery finds correct committed root and does not replay stale intent-log entries.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["COMMIT_GROUP_BEFORE_COMMIT".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "TXG group commit and crash boundary".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6319],
        scripts: vec!["crates/tidefs-local-filesystem/tests/crash_injection_tests.rs".into()],
        coverage: ScenarioCoverage::CargoCovered,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Storage Core: Recovery path ──
    s.push(FaultInjectionScenario {
        id: "fi-storage-recovery-before-replay".into(),
        name: "Crash before intent-log replay".into(),
        description: "Kill process after pool import but before intent-log replay begins. Verifies next mount detects incomplete recovery and replays from correct starting point.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["RECOVERY_BEFORE_REPLAY".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "Pool import and recovery".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-recovery-before-root-select".into(),
        name: "Crash before committed root selection".into(),
        description: "Kill process during recovery before committed root is selected. Verifies root selection is idempotent and pool is not left indeterminate.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["RECOVERY_BEFORE_ROOT_SELECT".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "Pool import and recovery".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── FUSE: Crash after write, fsync, namespace ops ──
    s.push(FaultInjectionScenario {
        id: "fi-fuse-write-before-extent-update".into(),
        name: "FUSE crash after write, before extent map update".into(),
        description: "Kill FUSE daemon after write payload stored but before extent map updated. Verifies either old data (atomic) or write is replayed, never partial corruption.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_WRITE_BEFORE_EXTENT_UPDATE".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE write durability".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427, 6431],
        scripts: vec!["nix/vm/fuse-writeback-cache-validation.nix".into()],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-fuse-fsync-before-flush".into(),
        name: "FUSE crash after fsync, before flush".into(),
        description: "Kill FUSE daemon after fsync returns but before underlying flush completes. Torn-write boundary; verifies fsync'd data survives or operation is replayed atomically.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_FSYNC_BEFORE_FLUSH".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE fsync durability".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── FUSE: Namespace crash ──
    s.push(FaultInjectionScenario {
        id: "fi-fuse-rename-after-resolve".into(),
        name: "FUSE crash after rename resolve, before commit".into(),
        description: "Kill FUSE daemon mid-rename after source/target resolved but before directory entries committed. Verifies atomic rename: either completed or not, never split state.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_RENAME_AFTER_RESOLVE".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE rename atomicity".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-fuse-unlink-before-nlink".into(),
        name: "FUSE crash before nlink decrement on unlink".into(),
        description: "Kill FUSE daemon during unlink before link count decremented. Verifies file is either still linked or fully unlinked, never a dangling inode.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_UNLINK_BEFORE_NLINK_DECR".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE unlink atomicity".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-fuse-unlink-after-nlink-zero".into(),
        name: "FUSE crash after nlink reaches zero, before inode removal".into(),
        description: "Kill FUSE daemon after last link removed but before inode freed. Verifies inode is properly cleaned up on remount.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_UNLINK_AFTER_NLINK_ZERO".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE unlink atomicity".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── FUSE: Space accounting crash ──
    s.push(FaultInjectionScenario {
        id: "fi-fuse-allocate-before-space".into(),
        name: "FUSE crash after fallocate, before space accounting update".into(),
        description: "Kill FUSE daemon after fallocate allocates extents but before space accounting records allocation. Verifies remount space accounting matches actual extent usage.".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["OP_ALLOCATE_BEFORE_SPACE_UPDATE".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE fallocate and space accounting".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6423, 6427],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Repair path crash ──
    s.push(FaultInjectionScenario {
        id: "fi-repair-before-apply".into(),
        name: "Crash during repair before applying fix".into(),
        description: "Kill process during repair cycle after detecting corruption but before repair entry applied. Verifies next mount re-detects and repairs same corruption.".into(),
        subsystem: vec![Subsystem::Repair, Subsystem::StorageCore],
        fault_classes: vec![
            "fi.process.crash_subject".into(),
            "cm.storage.bitflip.payload".into(),
        ],
        crash_injection_points: vec!["REPAIR_BEFORE_APPLY".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "Repair: automatic mount-time repair_cycle".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6330],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-repair-before-writeback".into(),
        name: "Crash during repair before writeback".into(),
        description: "Kill process after repair entries computed but before durably written. Verifies repair is idempotent and does not produce partial writes.".into(),
        subsystem: vec![Subsystem::Repair, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec!["REPAIR_BEFORE_WRITEBACK".into()],
        release_gates: vec![ReleaseGateRef {
            gate: "Repair: automatic mount-time repair_cycle".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6330],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Kernel VFS: Crash-loop campaign ──
    s.push(FaultInjectionScenario {
        id: "fi-kvfs-crash-loop-all-mutations".into(),
        name: "Kernel VFS crash-loop across every mutating inode op".into(),
        description: "Systematically crash the kernel module at every mutating VFS op (create, mkdir, rmdir, unlink, rename, write, truncate, fallocate, setattr, setxattr, removexattr) and verify recovery after each crash.".into(),
        subsystem: vec![Subsystem::KernelVfs, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Kernel crash-loop replay campaign".into(),
            source: "CURRENT_RELEASE_FOCUS.md".into(),
        }],
        tickets: vec![6396],
        scripts: vec!["nix/vm/kernel-xfstests-crash-consistency.nix".into()],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier5,
    });

    // ── Kernel Block: Crash during I/O ──
    s.push(FaultInjectionScenario {
        id: "fi-kblock-crash-fio-campaign".into(),
        name: "Kernel block I/O crash during fio workload".into(),
        description: "Run fio with verify against ublk device, crash kernel module mid-I/O, verify data integrity on remount. Covers buffered and direct I/O paths.".into(),
        subsystem: vec![Subsystem::KernelBlock, Subsystem::Ublk],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Kernel block crash consistency".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6280],
        scripts: vec![
            "nix/vm/kernel-block-fio-powercut-campaign.nix".into(),
            "nix/vm/kernel-block-crash-consistency.nix".into(),
        ],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier5,
    });

    // ── Kernel Block: gendisk teardown crash ──
    s.push(FaultInjectionScenario {
        id: "fi-kblock-teardown-crash".into(),
        name: "Crash during kernel block device teardown".into(),
        description: "Crash kernel module while ublk device being torn down. Verifies resources reclaimed and device can be re-attached.".into(),
        subsystem: vec![Subsystem::KernelBlock, Subsystem::Ublk],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "ublk multi-queue teardown".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6376],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier5,
    });

    // ── Storage corruption: bitflips (GAPS) ──
    s.push(FaultInjectionScenario {
        id: "fi-storage-bitflip-checkpoint".into(),
        name: "Bitflip in committed-root checkpoint region".into(),
        description: "Corrupt a byte in committed-root checkpoint region. Verify pool detects corruption and falls back to previous root or fails safely with checksum error.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.bitflip.checkpoint".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Checksum integrity on read".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-bitflip-metadata".into(),
        name: "Bitflip in metadata (inode table, extent map)".into(),
        description: "Corrupt a byte in inode table entry or extent map B-tree node. Verify corruption detected at read time via checksum failure rather than silent bad data.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.bitflip.metadata".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Checksum integrity on read".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-bitflip-payload".into(),
        name: "Bitflip in file payload data".into(),
        description: "Corrupt a byte in file payload data. Verify read path detects corruption via checksum and returns EIO rather than silently returning corrupted data.".into(),
        subsystem: vec![Subsystem::StorageCore, Subsystem::Fuse],
        fault_classes: vec!["cm.storage.bitflip.payload".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Checksum integrity on read".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Storage corruption: truncation, partial header, flush omission (GAPS) ──
    s.push(FaultInjectionScenario {
        id: "fi-storage-truncate-tail".into(),
        name: "Truncated log/file tail".into(),
        description: "Truncate tail of intent log or data file (simulating partial write/flush). Verify pool detects truncation at mount and recovers to last valid committed root.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.truncate_tail".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Intent-log crash replay".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-partial-header".into(),
        name: "Partial or malformed record header".into(),
        description: "Write partial or malformed record header simulating torn write at block-device level. Verify reader detects malformed header and either skips or fails safely.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.partial_header".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Intent-log crash replay".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-flush-omission".into(),
        name: "Flush/fsync omission".into(),
        description: "Suppress flush/fsync operation to simulate storage layer ignoring flush commands. Verify next mount detects missing data via checksums and recovers from intent log or committed root.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.flush_omission".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Flush/FUA txg barrier".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-zeroed-range".into(),
        name: "Zeroed-out data range".into(),
        description: "Zero out a range of stored data (simulating silent disk corruption). Verify checksum verification detects zeroed range and either repairs from redundancy or returns EIO.".into(),
        subsystem: vec![Subsystem::StorageCore, Subsystem::Repair],
        fault_classes: vec!["cm.storage.zeroed_range".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Scrub/repair verification".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-storage-replay-stale-copy".into(),
        name: "Replay from stale committed-root copy".into(),
        description: "Force pool to attempt replay from older committed root (simulating split-brain or stale replica). Verify committed-root selection logic picks newest valid root.".into(),
        subsystem: vec![Subsystem::StorageCore],
        fault_classes: vec!["cm.storage.replay_stale_copy".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Committed-root selection".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── ublk: Crash during block I/O ──
    s.push(FaultInjectionScenario {
        id: "fi-ublk-crash-mid-io".into(),
        name: "ublk daemon crash during inflight I/O".into(),
        description: "Kill ublk daemon while I/O requests inflight. Verify inflight I/O drained, device stopped cleanly, subsequent attach succeeds without EBUSY.".into(),
        subsystem: vec![Subsystem::Ublk],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "ublk inflight I/O drain".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6376],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-ublk-detach-reattach-cycle".into(),
        name: "ublk detach/reattach crash cycle".into(),
        description: "Repeatedly detach and reattach ublk device, crashing daemon at random lifecycle points. Verify device state machine handles all transitions correctly.".into(),
        subsystem: vec![Subsystem::Ublk],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "ublk device lifecycle".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6374],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Pool lifecycle crash ──
    s.push(FaultInjectionScenario {
        id: "fi-pool-import-crash".into(),
        name: "Crash during pool import".into(),
        description: "Kill process during pool import (between device scan and committed-root selection). Verify pool can be re-imported cleanly.".into(),
        subsystem: vec![Subsystem::PoolLifecycle, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Pool import lifecycle".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-pool-remount-crash-cycle".into(),
        name: "Pool repeated remount crash cycle".into(),
        description: "Mount, write data, crash, remount, verify integrity. Repeat N times with different crash points. Power-cut simulation campaign.".into(),
        subsystem: vec![Subsystem::PoolLifecycle, Subsystem::StorageCore, Subsystem::Fuse],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Pool remount lifecycle".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec!["nix/vm/pool-remount-lifecycle-validation.nix".into()],
        coverage: ScenarioCoverage::ScriptExists,
        required_validation_tier: ValidationTier::Tier3,
    });

    // ── Transport fault injection (GAPS) ──
    s.push(FaultInjectionScenario {
        id: "fi-transport-pause-link".into(),
        name: "Pause transport link during data transfer".into(),
        description: "Pause transport link mid-transfer. Verify session either resumes after pause lifted or cleanly tears down and re-establishes.".into(),
        subsystem: vec![Subsystem::Transport],
        fault_classes: vec!["fi.transport.pause_link".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Transport link resilience".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    s.push(FaultInjectionScenario {
        id: "fi-transport-drop-messages".into(),
        name: "Drop transport messages during handshake".into(),
        description: "Drop next N messages on transport link during session establishment. Verify handshake retries or fails cleanly with timeout.".into(),
        subsystem: vec![Subsystem::Transport],
        fault_classes: vec!["fi.transport.drop_next".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Transport session establishment".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    s.push(FaultInjectionScenario {
        id: "fi-transport-partition-bidir".into(),
        name: "Bidirectional partition between two nodes".into(),
        description: "Create bidirectional network partition between two storage nodes. Verify membership layer detects partition, fences isolated node, re-admits after partition heals.".into(),
        subsystem: vec![Subsystem::Transport, Subsystem::Membership, Subsystem::MultiNode],
        fault_classes: vec!["fi.transport.partition_bidir".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Multi-node partition and heal".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    // ── Process fault injection (GAPS) ──
    s.push(FaultInjectionScenario {
        id: "fi-process-restart-subject".into(),
        name: "Restart storage node after clean shutdown".into(),
        description: "Cleanly shut down storage node, restart it. Verify it rejoins cluster, replays intent log, resumes serving I/O.".into(),
        subsystem: vec![Subsystem::Membership, Subsystem::StorageCore, Subsystem::MultiNode],
        fault_classes: vec!["fi.process.restart_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Node restart and rejoin".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    s.push(FaultInjectionScenario {
        id: "fi-process-wipe-local-state".into(),
        name: "Wipe local state and recover from peers".into(),
        description: "Wipe local state of storage node (simulating disk failure). Verify node reconstructs state from peer replicas via rebuild/backfill.".into(),
        subsystem: vec![Subsystem::Membership, Subsystem::Repair, Subsystem::MultiNode],
        fault_classes: vec!["fi.process.wipe_local_state".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Rebuild from peer replicas".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    // ── Resource pressure ──
    s.push(FaultInjectionScenario {
        id: "fi-resource-enospc-during-write".into(),
        name: "ENOSPC during write workload".into(),
        description: "Fill pool to capacity. Verify writes fail with ENOSPC cleanly (no corruption, no panic). Then free space and verify writes resume.".into(),
        subsystem: vec![Subsystem::StorageCore, Subsystem::Fuse],
        fault_classes: vec!["fi.resource.reserve_floor_pressure".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Pool capacity enforcement".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-resource-memory-pressure".into(),
        name: "Memory pressure during heavy writeback".into(),
        description: "Induce memory pressure while system under heavy writeback load. Verify kernel module reclaims pages without losing dirty data and writeback completes correctly.".into(),
        subsystem: vec![Subsystem::KernelVfs, Subsystem::KernelBlock],
        fault_classes: vec!["fi.resource.memory_pressure".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Kernel memory-pressure reclaim".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6394],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier5,
    });

    // ── RDMA fault injection ──
    s.push(FaultInjectionScenario {
        id: "fi-rdma-link-flap".into(),
        name: "RDMA link flap during bulk transfer".into(),
        description: "Flap RDMA link (down, up) during bulk data transfer. Verify transport layer falls back to TCP, completes transfer, re-establishes RDMA when link returns.".into(),
        subsystem: vec![Subsystem::Rdma, Subsystem::Transport],
        fault_classes: vec!["fi.transport.pause_link".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "RDMA carrier failover".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6502],
        scripts: vec!["nix/vm/rdma-two-node-validation.nix".into()],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier7,
    });

    // ── Time/clock fault injection (GAPS) ──
    s.push(FaultInjectionScenario {
        id: "fi-time-heartbeat-gap".into(),
        name: "Heartbeat gap during lease renewal".into(),
        description: "Create heartbeat gap that exceeds lease timeout. Verify lease holder fenced, lease reassigned, no split-brain writes occur.".into(),
        subsystem: vec![Subsystem::Membership, Subsystem::MultiNode],
        fault_classes: vec![
            "fi.time.heartbeat_gap".into(),
            "fi.time.lease_expiry_race".into(),
        ],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "Membership lease and fencing".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![],
        scripts: vec![],
        coverage: ScenarioCoverage::Gap,
        required_validation_tier: ValidationTier::Tier7,
    });

    // ── FUSE combined scenarios ──
    s.push(FaultInjectionScenario {
        id: "fi-fuse-writeback-cache-crash".into(),
        name: "FUSE writeback-cache crash with dirty pages".into(),
        description: "Enable FUSE writeback cache, write data, crash before kernel flushes dirty pages. Verify after remount data is either intact or write lost atomically (no partial corruption).".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE writeback-cache correctness".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6371, 6427],
        scripts: vec!["nix/vm/fuse-writeback-cache-validation.nix".into()],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s.push(FaultInjectionScenario {
        id: "fi-fuse-mmap-crash".into(),
        name: "FUSE mmap crash with dirty mappings".into(),
        description: "mmap a file, write via mapping, crash before msync. Verify after remount file state is consistent (either pre-mmap or post-mmap, no torn pages).".into(),
        subsystem: vec![Subsystem::Fuse, Subsystem::StorageCore],
        fault_classes: vec!["fi.process.crash_subject".into()],
        crash_injection_points: vec![],
        release_gates: vec![ReleaseGateRef {
            gate: "FUSE mmap coherence".into(),
            source: "FEATURE_MATRIX.md".into(),
        }],
        tickets: vec![6426],
        scripts: vec![],
        coverage: ScenarioCoverage::TicketOwned,
        required_validation_tier: ValidationTier::Tier3,
    });

    s
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_minimum_scenarios() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        assert!(
            cat.scenario_count >= 25,
            "catalog must have at least 25 scenarios, has {}",
            cat.scenario_count
        );
    }

    #[test]
    fn all_scenario_ids_are_unique() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let mut ids: Vec<&str> = cat.scenarios.iter().map(|s| s.id.as_str()).collect();
        ids.sort();
        let orig_len = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), orig_len, "duplicate scenario IDs found");
    }

    #[test]
    fn every_scenario_has_at_least_one_subsystem() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        for s in &cat.scenarios {
            assert!(
                !s.subsystem.is_empty(),
                "scenario {} has no subsystems",
                s.id
            );
        }
    }

    #[test]
    fn every_scenario_has_release_gate() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        for s in &cat.scenarios {
            assert!(
                !s.release_gates.is_empty(),
                "scenario {} has no release gates",
                s.id
            );
        }
    }

    #[test]
    fn gaps_count_is_reasonable() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let gaps = cat.count_by_coverage(ScenarioCoverage::Gap);
        assert!(
            gaps < cat.scenario_count,
            "all scenarios are gaps; none covered"
        );
        assert!(
            gaps > 0,
            "no gaps found; either all covered or catalog incomplete"
        );
    }

    #[test]
    fn covered_scenarios_exist() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let covered = cat.count_by_coverage(ScenarioCoverage::CargoCovered)
            + cat.count_by_coverage(ScenarioCoverage::ScriptExists)
            + cat.count_by_coverage(ScenarioCoverage::TicketOwned)
            + cat.count_by_coverage(ScenarioCoverage::RuntimeValidation);
        assert!(covered > 0, "no covered scenarios; all are gaps");
    }

    #[test]
    fn markdown_table_renders() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let md = cat.to_markdown_table();
        assert!(md.contains("Fault Injection Scenario Catalog"));
        assert!(md.contains("Coverage Summary"));
        assert!(md.contains("Scenario Catalog"));
        assert!(md.contains("**GAP**"));
    }

    #[test]
    fn subsystem_labels_are_unique() {
        let mut labels: Vec<&str> = ALL_SUBSYSTEMS.iter().map(|s| s.label()).collect();
        labels.sort();
        let orig_len = labels.len();
        labels.dedup();
        assert_eq!(labels.len(), orig_len, "duplicate subsystem labels");
    }

    #[test]
    fn serde_roundtrip() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let json = serde_json::to_string_pretty(&cat).unwrap();
        let roundtripped: FaultInjectionScenarioCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat.version, roundtripped.version);
        assert_eq!(cat.scenario_count, roundtripped.scenario_count);
        assert_eq!(cat.scenarios.len(), roundtripped.scenarios.len());
    }

    #[test]
    fn filter_by_tier() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let t3 = cat.by_tier(ValidationTier::Tier3);
        assert!(!t3.is_empty(), "should have T3 scenarios");
        for s in &t3 {
            assert_eq!(s.required_validation_tier, ValidationTier::Tier3);
        }
    }

    #[test]
    fn count_by_subsystem() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let storage_count = cat.count_by_subsystem(Subsystem::StorageCore);
        assert!(storage_count > 5, "storage core should have many scenarios");

        let fuse_count = cat.count_by_subsystem(Subsystem::Fuse);
        assert!(fuse_count > 3, "FUSE should have several scenarios");
    }

    #[test]
    fn validation_tier_ordering() {
        assert!(ValidationTier::Tier0 < ValidationTier::Tier3);
        assert!(ValidationTier::Tier3 < ValidationTier::Tier7);
        assert!(ValidationTier::Tier5 < ValidationTier::Tier6);
    }

    #[test]
    fn gap_report_json_is_valid() {
        let cat = FaultInjectionScenarioCatalog::canonical();
        let report = cat.gap_report_json();
        let parsed: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert!(parsed.get("gap_count").is_some());
        assert!(parsed.get("gaps").is_some());
    }
}
