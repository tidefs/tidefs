// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Typed fault and corruption catalog.
//!
//! This module defines the canonical set of fault classes, hook bindings,
//! campaign schedule templates, and seed/replay manifests required by the
//! production fault-injection law. It replaces ad hoc fault injection
//! parameters with a typed, reproducible catalog.
//!
//! # Anti-regression rule
//!
//! No ad hoc chaos result without a typed fault catalog, hook binding, and
//! seed/schedule manifest.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Transport and link fault classes.
// ---------------------------------------------------------------------------

/// Transport/link fault classes for distributed and shadow-pair rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportFaultClass {
    /// Pause a directional or bidirectional link lane.
    PauseLink,
    /// Drop the next N messages on a link.
    DropNext,
    /// Reorder the next N messages on a link.
    ReorderNext,
    /// Inject latency stretch on a link.
    LatencyStretch,
    /// Clamp bandwidth on a link.
    BandwidthClamp,
    /// Create a bidirectional partition between two nodes.
    PartitionBidir,
}

impl TransportFaultClass {
    /// Human-readable label for this fault class.
    pub fn label(&self) -> &'static str {
        match self {
            Self::PauseLink => "fi.transport.pause_link",
            Self::DropNext => "fi.transport.drop_next",
            Self::ReorderNext => "fi.transport.reorder_next",
            Self::LatencyStretch => "fi.transport.latency_stretch",
            Self::BandwidthClamp => "fi.transport.bandwidth_clamp",
            Self::PartitionBidir => "fi.transport.partition_bidir",
        }
    }
}

impl fmt::Display for TransportFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Process and runtime fault classes.
// ---------------------------------------------------------------------------

/// Process/runtime fault classes for nodes, authorities, and workers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessFaultClass {
    /// Crash a subject node or daemon.
    CrashSubject,
    /// Restart a subject node or daemon.
    RestartSubject,
    /// Wipe local state of a subject.
    WipeLocalState,
    /// Quiesce a worker group.
    QuiesceWorkerGroup,
    /// Kill a subject before it can send an acknowledgment.
    KillBeforeAck,
}

impl ProcessFaultClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::CrashSubject => "fi.process.crash_subject",
            Self::RestartSubject => "fi.process.restart_subject",
            Self::WipeLocalState => "fi.process.wipe_local_state",
            Self::QuiesceWorkerGroup => "fi.process.quiesce_worker_group",
            Self::KillBeforeAck => "fi.process.kill_before_ack",
        }
    }
}

impl fmt::Display for ProcessFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Storage media and corruption classes.
// ---------------------------------------------------------------------------

/// Storage-media and corruption fault classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageFaultClass {
    /// Bit-flip in a checkpoint region.
    BitflipCheckpoint,
    /// Bit-flip in metadata.
    BitflipMetadata,
    /// Bit-flip in payload data.
    BitflipPayload,
    /// Truncate the tail of a file or log.
    TruncateTail,
    /// Replay from a stale copy.
    ReplayStaleCopy,
    /// Zero out a declared range.
    ZeroedRange,
    /// Omit a flush/fsync operation.
    FlushOmission,
    /// Write a partial or malformed header.
    PartialHeader,
}

impl StorageFaultClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::BitflipCheckpoint => "cm.storage.bitflip.checkpoint",
            Self::BitflipMetadata => "cm.storage.bitflip.metadata",
            Self::BitflipPayload => "cm.storage.bitflip.payload",
            Self::TruncateTail => "cm.storage.truncate_tail",
            Self::ReplayStaleCopy => "cm.storage.replay_stale_copy",
            Self::ZeroedRange => "cm.storage.zeroed_range",
            Self::FlushOmission => "cm.storage.flush_omission",
            Self::PartialHeader => "cm.storage.partial_header",
        }
    }
}

impl fmt::Display for StorageFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Time and clock fault classes.
// ---------------------------------------------------------------------------

/// Time/clock fault classes for drift, heartbeat, and lease scenarios.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeFaultClass {
    /// Inject clock drift.
    Drift,
    /// Create heartbeat gaps.
    HeartbeatGap,
    /// Race lease expiry against an operation.
    LeaseExpiryRace,
    /// Present a stale fence observation to a subject.
    StaleFenceObservation,
}

impl TimeFaultClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Drift => "fi.time.drift",
            Self::HeartbeatGap => "fi.time.heartbeat_gap",
            Self::LeaseExpiryRace => "fi.time.lease_expiry_race",
            Self::StaleFenceObservation => "fi.time.stale_fence_observation",
        }
    }
}

impl fmt::Display for TimeFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Resource pressure fault classes.
// ---------------------------------------------------------------------------

/// Resource pressure fault classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceFaultClass {
    /// Induce memory pressure.
    MemoryPressure,
    /// Pressure the reserve floor.
    ReserveFloorPressure,
    /// Exhaust queue credits.
    QueueCreditExhaustion,
    /// Pressure the validation store.
    ValidationStorePressure,
}

impl ResourceFaultClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::MemoryPressure => "fi.resource.memory_pressure",
            Self::ReserveFloorPressure => "fi.resource.reserve_floor_pressure",
            Self::QueueCreditExhaustion => "fi.resource.queue_credit_exhaustion",
            Self::ValidationStorePressure => "fi.resource.validation_store_pressure",
        }
    }
}

impl fmt::Display for ResourceFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Operator surface fault classes.
// ---------------------------------------------------------------------------

/// Operator surface interruption fault classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperatorFaultClass {
    /// Interrupt a publish step.
    InterruptPublish,
    /// Interrupt an override step.
    InterruptOverride,
    /// Interrupt a rollback step.
    InterruptRollback,
    /// Interrupt a cutover step.
    InterruptCutover,
}

impl OperatorFaultClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::InterruptPublish => "fi.operator.interrupt_publish",
            Self::InterruptOverride => "fi.operator.interrupt_override",
            Self::InterruptRollback => "fi.operator.interrupt_rollback",
            Self::InterruptCutover => "fi.operator.interrupt_cutover",
        }
    }
}

impl fmt::Display for OperatorFaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Combined fault class enum.
// ---------------------------------------------------------------------------

/// Canonical fault class — the union of all typed fault families.
///
/// This enum carries the typed fault classes required for validation scenarios:
/// 6 transport, 5 process, 8 storage, 4 time, 4 resource, 4 operator = 31 total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultClass {
    Transport(TransportFaultClass),
    Process(ProcessFaultClass),
    Storage(StorageFaultClass),
    Time(TimeFaultClass),
    Resource(ResourceFaultClass),
    Operator(OperatorFaultClass),
}

impl FaultClass {
    /// Human-readable label for this fault class (matching the spec naming).
    pub fn label(&self) -> &'static str {
        match self {
            Self::Transport(c) => c.label(),
            Self::Process(c) => c.label(),
            Self::Storage(c) => c.label(),
            Self::Time(c) => c.label(),
            Self::Resource(c) => c.label(),
            Self::Operator(c) => c.label(),
        }
    }

    /// The family this fault class belongs to.
    pub fn family(&self) -> FaultFamily {
        match self {
            Self::Transport(_) => FaultFamily::Transport,
            Self::Process(_) => FaultFamily::Process,
            Self::Storage(_) => FaultFamily::Storage,
            Self::Time(_) => FaultFamily::Time,
            Self::Resource(_) => FaultFamily::Resource,
            Self::Operator(_) => FaultFamily::Operator,
        }
    }

    /// Whether this fault class is reversible (has a heal path).
    pub fn is_reversible(&self) -> bool {
        match self {
            Self::Transport(_) => true, // All transport faults can be healed
            Self::Process(c) => !matches!(c, ProcessFaultClass::WipeLocalState),
            Self::Storage(c) => !matches!(
                c,
                StorageFaultClass::BitflipCheckpoint
                    | StorageFaultClass::TruncateTail
                    | StorageFaultClass::ZeroedRange
            ),
            Self::Time(_) => true,
            Self::Resource(_) => true,
            Self::Operator(_) => true,
        }
    }
}

impl fmt::Display for FaultClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// Fault family.
// ---------------------------------------------------------------------------

/// Top-level fault family grouping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultFamily {
    Transport,
    Process,
    Storage,
    Time,
    Resource,
    Operator,
}

impl FaultFamily {
    /// The suite family name for this fault family.
    pub fn suite_label(&self) -> &'static str {
        match self {
            Self::Transport => "suite.cutover_control_0.transport.time_clock_0",
            Self::Process => "suite.cutover_control_0.process.time_clock_1",
            Self::Storage => "suite.cutover_control_0.storage_media.time_clock_2",
            Self::Time => "suite.cutover_control_0.time.time_clock_3",
            Self::Resource => "suite.cutover_control_0.resource.time_clock_4",
            Self::Operator => "suite.cutover_control_0.operator.time_clock_9",
        }
    }
}

// ---------------------------------------------------------------------------
// Campaign depth classes.
// ---------------------------------------------------------------------------

/// Campaign depth — controls how many concurrent faults may be active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CampaignDepth {
    /// Single fault active at a time.
    SingleFault,
    /// Two paired faults active.
    PairedFault,
    /// Cascading fault sequence.
    CascadingFault,
    /// Shadow cutover with faults.
    ShadowCutoverFault,
    /// Soak/disaster campaign with many concurrent faults.
    SoakDisaster,
}

impl CampaignDepth {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SingleFault => "campaign.cutover_control_0.single_fault",
            Self::PairedFault => "campaign.cutover_control_1.paired_fault",
            Self::CascadingFault => "campaign.cutover_control_2.cascading_fault",
            Self::ShadowCutoverFault => "campaign.cutover_control_3.shadow_cutover_fault",
            Self::SoakDisaster => "campaign.cutover_control_4.soak_disaster",
        }
    }
}

// ---------------------------------------------------------------------------
// Fault schedule entry
// ---------------------------------------------------------------------------

/// A single fault injection step in a campaign schedule.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FaultScheduleEntry {
    /// The fault class to inject.
    pub fault_class: FaultClass,
    /// Nanoseconds after campaign start to inject this fault.
    pub inject_at_ns: u64,
    /// Nanoseconds after injection to heal (None = terminal/irreversible).
    pub heal_at_ns: Option<u64>,
    /// Concurrency limit during this fault window.
    pub concurrency_limit: Option<u32>,
    /// Observation window duration after healing (None = no observation).
    pub observation_window_ns: Option<u64>,
}

// ---------------------------------------------------------------------------
// Fault schedule.
// ---------------------------------------------------------------------------

/// A fault campaign schedule — ordered list of fault injection steps.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FaultSchedule {
    /// Canonical seed vector for deterministic replay.
    pub seed: u64,
    /// Campaign depth class.
    pub depth: CampaignDepth,
    /// Ordered fault injection entries.
    pub entries: Vec<FaultScheduleEntry>,
    /// Terminal condition: stop after all entries complete, or after first failure.
    pub stop_condition: ScheduleStopCondition,
}

impl FaultSchedule {
    /// Create a single-fault campaign with one fault entry.
    pub fn single_fault(seed: u64, entry: FaultScheduleEntry) -> Self {
        Self {
            seed,
            depth: CampaignDepth::SingleFault,
            entries: vec![entry],
            stop_condition: ScheduleStopCondition::AfterAll,
        }
    }

    /// Create a soak/disaster campaign with multiple entries.
    pub fn soak(seed: u64, entries: Vec<FaultScheduleEntry>) -> Self {
        Self {
            seed,
            depth: CampaignDepth::SoakDisaster,
            entries,
            stop_condition: ScheduleStopCondition::AfterAll,
        }
    }
}

/// When to stop the campaign schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScheduleStopCondition {
    /// Run all entries regardless of intermediate outcomes.
    AfterAll,
    /// Stop after the first fault that triggers a forbidden outcome.
    OnFirstForbidden,
    /// Stop after the first unrecovered fault.
    OnFirstUnrecovered,
}

// ---------------------------------------------------------------------------
// Hook binding.
// ---------------------------------------------------------------------------

/// A hook binding declares how a fault class is injected into a subject.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HookBinding {
    /// Hook family reference (e.g. "hook.cutover_control_0.storage.region_mutator").
    pub hook_family_ref: String,
    /// Subject selector — identifies the target of the fault.
    pub subject_selector_ref: String,
    /// Fault classes this hook can inject.
    pub fault_class_refs: Vec<FaultClass>,
    /// Safety scope — what this fault is allowed to affect.
    pub safety_scope_ref: String,
    /// Action to restore or heal after fault (None = irreversible).
    pub restore_or_heal_action_ref: Option<String>,
    /// Whether this hook produces replayable campaigns.
    pub replayability_class: ReplayabilityClass,
    /// Rule for capturing artifacts during fault.
    pub artifact_capture_rule_ref: String,
}

/// Whether a hook's fault injections can be deterministically replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReplayabilityClass {
    /// Fully deterministic given the seed.
    Deterministic,
    /// Probabilistic but seed-controlled (same seed = same outcome).
    SeedDeterministic,
    /// Not guaranteed to be replayable.
    NonReplayable,
}

// ---------------------------------------------------------------------------
// Fault manifest.
// ---------------------------------------------------------------------------

/// A fault campaign manifest — the canonical record of a chaos run.
///
/// The anti-regression rule requires that every fault campaign produce
/// a manifest declaring the fault class, target, seed/schedule, expected
/// outcomes, forbidden outcomes, and required artifacts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FaultManifest {
    /// Row identifier for this campaign.
    pub row_id: String,
    /// Fault catalog reference.
    pub fault_catalog_ref: String,
    /// Hook binding used.
    pub hook_binding_ref: String,
    /// Campaign schedule.
    pub schedule: FaultSchedule,
    /// Expected legal outcomes.
    pub expected_outcomes: Vec<String>,
    /// Forbidden outcomes that must not occur.
    pub forbidden_outcomes: Vec<String>,
    /// Required recovery receipt classes.
    pub required_recovery_receipts: Vec<String>,
    /// Required artifact classes to retain.
    pub required_artifact_classes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_class_count_meets_minimum() {
        // Count all variants across sub-enums
        let transport = [
            TransportFaultClass::PauseLink,
            TransportFaultClass::DropNext,
            TransportFaultClass::ReorderNext,
            TransportFaultClass::LatencyStretch,
            TransportFaultClass::BandwidthClamp,
            TransportFaultClass::PartitionBidir,
        ];
        let process = [
            ProcessFaultClass::CrashSubject,
            ProcessFaultClass::RestartSubject,
            ProcessFaultClass::WipeLocalState,
            ProcessFaultClass::QuiesceWorkerGroup,
            ProcessFaultClass::KillBeforeAck,
        ];
        let storage = [
            StorageFaultClass::BitflipCheckpoint,
            StorageFaultClass::BitflipMetadata,
            StorageFaultClass::BitflipPayload,
            StorageFaultClass::TruncateTail,
            StorageFaultClass::ReplayStaleCopy,
            StorageFaultClass::ZeroedRange,
            StorageFaultClass::FlushOmission,
            StorageFaultClass::PartialHeader,
        ];
        let time = [
            TimeFaultClass::Drift,
            TimeFaultClass::HeartbeatGap,
            TimeFaultClass::LeaseExpiryRace,
            TimeFaultClass::StaleFenceObservation,
        ];
        let resource = [
            ResourceFaultClass::MemoryPressure,
            ResourceFaultClass::ReserveFloorPressure,
            ResourceFaultClass::QueueCreditExhaustion,
            ResourceFaultClass::ValidationStorePressure,
        ];
        let operator = [
            OperatorFaultClass::InterruptPublish,
            OperatorFaultClass::InterruptOverride,
            OperatorFaultClass::InterruptRollback,
            OperatorFaultClass::InterruptCutover,
        ];

        let total = transport.len()
            + process.len()
            + storage.len()
            + time.len()
            + resource.len()
            + operator.len();
        // Preserve enough typed classes to keep scenario rows meaningful.
        assert!(total >= 18, "fault catalog has {total} classes, need >= 18");
    }

    #[test]
    fn fault_labels_match_spec_naming() {
        assert_eq!(
            TransportFaultClass::PauseLink.label(),
            "fi.transport.pause_link"
        );
        assert_eq!(
            ProcessFaultClass::CrashSubject.label(),
            "fi.process.crash_subject"
        );
        assert_eq!(
            StorageFaultClass::BitflipCheckpoint.label(),
            "cm.storage.bitflip.checkpoint"
        );
        assert_eq!(TimeFaultClass::Drift.label(), "fi.time.drift");
        assert_eq!(
            ResourceFaultClass::MemoryPressure.label(),
            "fi.resource.memory_pressure"
        );
        assert_eq!(
            OperatorFaultClass::InterruptPublish.label(),
            "fi.operator.interrupt_publish"
        );
    }

    #[test]
    fn fault_family_mapping() {
        let fc = FaultClass::Transport(TransportFaultClass::PauseLink);
        assert_eq!(fc.family(), FaultFamily::Transport);

        let fc = FaultClass::Storage(StorageFaultClass::BitflipPayload);
        assert_eq!(fc.family(), FaultFamily::Storage);
    }

    #[test]
    fn reversibility_rules() {
        // Transport faults are reversible
        assert!(FaultClass::Transport(TransportFaultClass::PartitionBidir).is_reversible());

        // Most process faults are reversible, except wipe
        assert!(FaultClass::Process(ProcessFaultClass::CrashSubject).is_reversible());
        assert!(!FaultClass::Process(ProcessFaultClass::WipeLocalState).is_reversible());

        // Irreversible storage faults
        assert!(!FaultClass::Storage(StorageFaultClass::BitflipCheckpoint).is_reversible());
        assert!(!FaultClass::Storage(StorageFaultClass::TruncateTail).is_reversible());
        assert!(!FaultClass::Storage(StorageFaultClass::ZeroedRange).is_reversible());

        // Reversible storage faults
        assert!(FaultClass::Storage(StorageFaultClass::FlushOmission).is_reversible());
        assert!(FaultClass::Storage(StorageFaultClass::BitflipPayload).is_reversible());
    }

    #[test]
    fn schedule_single_fault() {
        let entry = FaultScheduleEntry {
            fault_class: FaultClass::Storage(StorageFaultClass::BitflipPayload),
            inject_at_ns: 1_000_000_000,
            heal_at_ns: Some(2_000_000_000),
            concurrency_limit: Some(1),
            observation_window_ns: Some(500_000_000),
        };
        let schedule = FaultSchedule::single_fault(42, entry);
        assert_eq!(schedule.seed, 42);
        assert_eq!(schedule.depth, CampaignDepth::SingleFault);
        assert_eq!(schedule.entries.len(), 1);
    }

    #[test]
    fn manifest_roundtrips_via_serde() {
        let schedule = FaultSchedule::single_fault(
            12345,
            FaultScheduleEntry {
                fault_class: FaultClass::Process(ProcessFaultClass::CrashSubject),
                inject_at_ns: 500_000_000,
                heal_at_ns: Some(2_000_000_000),
                concurrency_limit: None,
                observation_window_ns: Some(1_000_000_000),
            },
        );

        let manifest = FaultManifest {
            row_id: "test-row-001".into(),
            fault_catalog_ref: "tidefs-local-object-store.fault_catalog.v1".into(),
            hook_binding_ref: "hook.cutover_control_0.runtime.subject_lifecycle".into(),
            schedule,
            expected_outcomes: vec!["restart_recovery".into()],
            forbidden_outcomes: vec!["silent_data_loss".into()],
            required_recovery_receipts: vec!["receipt.restart".into()],
            required_artifact_classes: vec!["artifact.chaos_log".into()],
        };

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let roundtripped: FaultManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest.row_id, roundtripped.row_id);
        assert_eq!(manifest.schedule.seed, roundtripped.schedule.seed);
    }

    #[test]
    fn campaign_depth_labels() {
        assert_eq!(
            CampaignDepth::SingleFault.label(),
            "campaign.cutover_control_0.single_fault"
        );
        assert_eq!(
            CampaignDepth::SoakDisaster.label(),
            "campaign.cutover_control_4.soak_disaster"
        );
    }

    #[test]
    fn hook_binding_construction() {
        let hook = HookBinding {
            hook_family_ref: "hook.cutover_control_0.storage.region_mutator".into(),
            subject_selector_ref: "device.primary".into(),
            fault_class_refs: vec![
                FaultClass::Storage(StorageFaultClass::BitflipPayload),
                FaultClass::Storage(StorageFaultClass::FlushOmission),
            ],
            safety_scope_ref: "single_object".into(),
            restore_or_heal_action_ref: Some("repair_from_checkpoint".into()),
            replayability_class: ReplayabilityClass::SeedDeterministic,
            artifact_capture_rule_ref: "capture_pre_post_snapshot".into(),
        };

        assert_eq!(hook.fault_class_refs.len(), 2);
        assert_eq!(
            hook.replayability_class,
            ReplayabilityClass::SeedDeterministic
        );
    }
}
