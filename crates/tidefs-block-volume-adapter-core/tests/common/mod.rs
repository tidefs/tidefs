//! Shared stress harness framework for `P6-04` block acceptance testing.
#![allow(clippy::too_many_arguments)]
//!
//! Provides:
//! - result tracking with lane/profile/gate/clause linkage
//! - failure bucket grammar
//! - structured text report generation
//! - reusable scenario helpers exercising the core runtime types

use std::fmt;
use std::time::{Duration, Instant};

// ── Validation lanes ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum ValidationLane {
    ClauseProperty = 0,
    GuestFs = 1,
    FioWorkload = 2,
    DifferentialOracle = 3,
    StressSoak = 4,
    FailoverCutover = 5,
    UpgradeReplay = 6,
}

impl fmt::Display for ValidationLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClauseProperty => write!(f, "A"),
            Self::GuestFs => write!(f, "B"),
            Self::FioWorkload => write!(f, "C"),
            Self::DifferentialOracle => write!(f, "D"),
            Self::StressSoak => write!(f, "E"),
            Self::FailoverCutover => write!(f, "F"),
            Self::UpgradeReplay => write!(f, "G"),
        }
    }
}

// ── Harness profiles ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum HarnessProfile {
    Smoke = 0,
    QuickRequired = 1,
    QuickPressure = 2,
    Oracle = 3,
    Soak = 4,
    Failover = 5,
}

impl fmt::Display for HarnessProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Smoke => write!(f, "block_acceptance_profile_0.smoke"),
            Self::QuickRequired => write!(f, "block_acceptance_profile_1.quick_required"),
            Self::QuickPressure => write!(f, "block_acceptance_profile_2.quick_pressure"),
            Self::Oracle => write!(f, "block_acceptance_profile_3.oracle"),
            Self::Soak => write!(f, "block_acceptance_profile_4.soak"),
            Self::Failover => write!(f, "block_acceptance_profile_5.failover"),
        }
    }
}

// ── Release gates ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum ReleaseGate {
    G0Smoke = 0,
    G1QuickRequired = 1,
    G2PressureFailover = 2,
    G3Oracle = 3,
    G4Soak = 4,
    G5UpgradeReplay = 5,
}

impl fmt::Display for ReleaseGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::G0Smoke => write!(f, "gate.block_volume_adapter.g0.smoke"),
            Self::G1QuickRequired => write!(f, "gate.block_volume_adapter.g1.quick_required"),
            Self::G2PressureFailover => {
                write!(f, "gate.block_volume_adapter.g2.pressure_and_failover")
            }
            Self::G3Oracle => write!(f, "gate.block_volume_adapter.g3.oracle_green"),
            Self::G4Soak => write!(f, "gate.block_volume_adapter.g4.soak"),
            Self::G5UpgradeReplay => write!(f, "gate.block_volume_adapter.g5.upgrade_replay"),
        }
    }
}

// ── Charter clause references ──────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum CharterClause {
    BlockIdentityGeometryProjection,
    ReadWriteOrderingAndCompletion,
    FlushFuaBarrierTruth,
    DiscardZeroResizeTransition,
    ExportFenceFailoverReplayVisibility,
    DirectCachedOverlapCoherency,
    ReservePressureAdmissionAndDenial,
    IntentionalCutsVisible,
}

impl fmt::Display for CharterClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockIdentityGeometryProjection => {
                write!(f, "clause.block_identity_geometry_projection")
            }
            Self::ReadWriteOrderingAndCompletion => {
                write!(f, "clause.read_write_ordering_and_completion")
            }
            Self::FlushFuaBarrierTruth => write!(f, "clause.flush_fua_barrier_truth"),
            Self::DiscardZeroResizeTransition => {
                write!(f, "clause.discard_zero_resize_transition")
            }
            Self::ExportFenceFailoverReplayVisibility => {
                write!(f, "clause.export_fence_failover_replay_visibility")
            }
            Self::DirectCachedOverlapCoherency => {
                write!(f, "clause.direct_cached_overlap_coherency")
            }
            Self::ReservePressureAdmissionAndDenial => {
                write!(f, "clause.reserve_pressure_admission_and_denial")
            }
            Self::IntentionalCutsVisible => write!(f, "clause.intentional_cuts_visible"),
        }
    }
}

// ── Failure buckets ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum FailureBucket {
    OrderingViolation,
    FlushOrFuaLie,
    DiscardZeroVisibilityViolation,
    ResizeTransitionBug,
    FailoverReplayBug,
    ReservePressureMisclassification,
    QueueRuntimeDeadlockOrLeak,
    IntentionalCutMisrendered,
}

impl fmt::Display for FailureBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrderingViolation => write!(f, "bucket.ordering_violation"),
            Self::FlushOrFuaLie => write!(f, "bucket.flush_or_fua_lie"),
            Self::DiscardZeroVisibilityViolation => {
                write!(f, "bucket.discard_zero_visibility_violation")
            }
            Self::ResizeTransitionBug => write!(f, "bucket.resize_transition_bug"),
            Self::FailoverReplayBug => write!(f, "bucket.failover_replay_bug"),
            Self::ReservePressureMisclassification => {
                write!(f, "bucket.reserve_pressure_misclassification")
            }
            Self::QueueRuntimeDeadlockOrLeak => {
                write!(f, "bucket.queue_runtime_deadlock_or_leak")
            }
            Self::IntentionalCutMisrendered => write!(f, "bucket.intentional_cut_misrendered"),
        }
    }
}

// ── Test result ────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct HarnessResult {
    pub test_name: String,
    pub lane: ValidationLane,
    pub profile: HarnessProfile,
    pub gates: Vec<ReleaseGate>,
    pub clauses: Vec<CharterClause>,
    pub passed: bool,
    pub duration: Duration,
    pub failure_bucket: Option<FailureBucket>,
    pub detail: Option<String>,
}

// ── Harness context (global accumulator) ───────────────────────────────

use std::sync::LazyLock;
use std::sync::Mutex;

static HARNESS: LazyLock<Mutex<HarnessContext>> =
    LazyLock::new(|| Mutex::new(HarnessContext::default()));

#[derive(Clone, Debug, Default)]
pub struct HarnessContext {
    pub results: Vec<HarnessResult>,
    pub profile_name: Option<String>,
}

impl HarnessContext {
    pub fn global() -> &'static Mutex<Self> {
        &HARNESS
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_result(
        name: &str,
        lane: ValidationLane,
        profile: HarnessProfile,
        gates: Vec<ReleaseGate>,
        clauses: Vec<CharterClause>,
        passed: bool,
        duration: Duration,
    ) {
        let mut ctx = HARNESS.lock().unwrap();
        ctx.results.push(HarnessResult {
            test_name: name.into(),
            lane,
            profile,
            gates,
            clauses,
            passed,
            duration,
            failure_bucket: None,
            detail: None,
        });
    }

    #[allow(dead_code)]
    pub fn record_failure(
        name: &str,
        lane: ValidationLane,
        profile: HarnessProfile,
        gates: Vec<ReleaseGate>,
        clauses: Vec<CharterClause>,
        duration: Duration,
        bucket: FailureBucket,
        detail: Option<&str>,
    ) {
        let mut ctx = HARNESS.lock().unwrap();
        ctx.results.push(HarnessResult {
            test_name: name.into(),
            lane,
            profile,
            gates,
            clauses,
            passed: false,
            duration,
            failure_bucket: Some(bucket),
            detail: detail.map(|s| s.into()),
        });
    }
}

// ── Report generation ──────────────────────────────────────────────────

pub fn render_report() -> String {
    let ctx = HARNESS.lock().unwrap();
    let results = &ctx.results;
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;

    let mut out = String::new();
    out.push_str("=== P6-04 block acceptance stress harness report ===\n");
    if let Some(ref profile_name) = ctx.profile_name {
        out.push_str(&format!("Profile: {profile_name}\n"));
    }
    out.push_str(&format!(
        "Results: {passed}/{total} passed, {failed} failed\n\n"
    ));

    if !results.is_empty() {
        out.push_str(&format!(
            "{:<50} {:>6} {:>6} {:>7}\n",
            "Test", "Lane", "Status", "Dur(ms)"
        ));
        out.push_str(&format!("{:-<50} {:-<6} {:-<6} {:-<7}\n", "", "", "", ""));
        for r in results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "{:<50} {:>6} {:>6} {:>7}\n",
                &r.test_name[..r.test_name.len().min(50)],
                r.lane,
                status,
                r.duration.as_millis(),
            ));
        }
        out.push('\n');
    }

    // Per-lane summary
    for lane in &[
        ValidationLane::ClauseProperty,
        ValidationLane::GuestFs,
        ValidationLane::FioWorkload,
        ValidationLane::DifferentialOracle,
        ValidationLane::StressSoak,
        ValidationLane::FailoverCutover,
        ValidationLane::UpgradeReplay,
    ] {
        let lane_results: Vec<_> = results.iter().filter(|r| r.lane == *lane).collect();
        if lane_results.is_empty() {
            continue;
        }
        let lane_passed = lane_results.iter().filter(|r| r.passed).count();
        out.push_str(&format!(
            "Lane {}: {}/{} green\n",
            lane,
            lane_passed,
            lane_results.len(),
        ));
    }
    out.push('\n');

    // Per-gate summary
    for gate in &[
        ReleaseGate::G0Smoke,
        ReleaseGate::G1QuickRequired,
        ReleaseGate::G2PressureFailover,
        ReleaseGate::G3Oracle,
        ReleaseGate::G4Soak,
        ReleaseGate::G5UpgradeReplay,
    ] {
        let gate_results: Vec<_> = results.iter().filter(|r| r.gates.contains(gate)).collect();
        if gate_results.is_empty() {
            continue;
        }
        let gate_passed = gate_results.iter().filter(|r| r.passed).count();
        let gate_failed: Vec<_> = gate_results.iter().filter(|r| !r.passed).collect();
        out.push_str(&format!(
            "{}: {}/{} green",
            gate,
            gate_passed,
            gate_results.len(),
        ));
        if !gate_failed.is_empty() {
            out.push_str(" [BLOCKED:");
            for f in gate_failed {
                if let Some(ref bucket) = f.failure_bucket {
                    out.push_str(&format!(" {bucket}"));
                }
            }
            out.push_str(" ]");
        }
        out.push('\n');
    }

    // Failure details
    let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    if !failures.is_empty() {
        out.push_str("\n--- Failure details ---\n");
        for f in failures {
            out.push_str(&format!("\n  {} ({})\n", f.test_name, f.lane));
            if let Some(ref bucket) = f.failure_bucket {
                out.push_str(&format!("    Bucket: {bucket}\n"));
            }
            if let Some(ref detail) = f.detail {
                out.push_str(&format!("    Detail: {detail}\n"));
            }
        }
    }

    out
}

// ── Shared test scenario helpers ───────────────────────────────────────

use tidefs_block_volume_adapter_core::{
    BlockVolumeCacheCoherencyRuntime, BlockVolumeExportLifecycleRuntime,
    BlockVolumeExportTransitionClass, BlockVolumeGeometryRecord, BlockVolumeId,
    BlockVolumeQueueRuntime, BlockVolumeResizeFenceRuntime,
};

pub fn standard_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(1), 4096, 256, 4)
}

#[allow(dead_code)]
pub fn small_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(2), 512, 64, 0)
}

#[allow(dead_code)]
pub fn large_geometry() -> BlockVolumeGeometryRecord {
    BlockVolumeGeometryRecord::new(BlockVolumeId::new(3), 65536, 16384, 128)
}

#[allow(dead_code)]
pub fn build_queue(geometry: BlockVolumeGeometryRecord) -> BlockVolumeQueueRuntime {
    BlockVolumeQueueRuntime::open(geometry, 4, 64, 1 << 20).expect("queue open")
}

pub fn build_live_lifecycle(
    geometry: BlockVolumeGeometryRecord,
) -> BlockVolumeExportLifecycleRuntime {
    let mut lc = BlockVolumeExportLifecycleRuntime::bootstrap(geometry, 4, 64, 1 << 20)
        .expect("lifecycle bootstrap");
    lc.admit_export();
    lc.start_queues();
    lc
}

#[allow(dead_code)]
pub fn build_fenced_lifecycle(
    geometry: BlockVolumeGeometryRecord,
) -> BlockVolumeExportLifecycleRuntime {
    let mut lc = build_live_lifecycle(geometry);
    lc.begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
    lc.fence_after_drain();
    lc
}

#[allow(dead_code)]
pub fn build_cache(volume_id: BlockVolumeId) -> BlockVolumeCacheCoherencyRuntime {
    BlockVolumeCacheCoherencyRuntime::open(volume_id)
}

#[allow(dead_code)]
pub fn build_live_resize_runtime() -> BlockVolumeResizeFenceRuntime {
    let geom = standard_geometry();
    let mut rt =
        BlockVolumeResizeFenceRuntime::open(geom, 4, 64, 1 << 20).expect("resize runtime open");
    rt.lifecycle_runtime.admit_export();
    rt.lifecycle_runtime.start_queues();
    rt
}

#[allow(dead_code)]
pub fn build_fenced_resize_runtime() -> BlockVolumeResizeFenceRuntime {
    let geom = standard_geometry();
    let mut rt =
        BlockVolumeResizeFenceRuntime::open(geom, 4, 64, 1 << 20).expect("resize runtime open");
    rt.lifecycle_runtime.admit_export();
    rt.lifecycle_runtime.start_queues();
    rt.lifecycle_runtime
        .begin_quiesce(BlockVolumeExportTransitionClass::ResizeQuiesce);
    rt.lifecycle_runtime.fence_after_drain();
    rt
}

pub fn timed<F: FnOnce()>(f: F) -> (bool, Duration) {
    let start = Instant::now();
    (
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_ok(),
        start.elapsed(),
    )
}
