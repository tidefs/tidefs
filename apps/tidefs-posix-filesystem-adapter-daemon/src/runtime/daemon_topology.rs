use core::convert::TryFrom;
use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterDecodeError;
use tidefs_types_posix_filesystem_adapter_core::PosixFilesystemAdapterId128;

pub const SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_KERNEL_RESIDENT_K0: &str =
    "service.posix_filesystem_adapter.runtime.kernel_resident.k0";
pub const SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_LAB_MIRROR_L0: &str =
    "service.posix_filesystem_adapter.runtime.lab_mirror.tidefs-posix-filesystem-adapter-daemon.l0";
pub const HELPER_POSIX_FILESYSTEM_ADAPTER_MOUNT_FUSE_H0: &str =
    "helper.posix_filesystem_adapter.mount.mount_fuse_tidefs.h0";
pub const BUDGET_POSIX_FILESYSTEM_ADAPTER_GLOBAL: &str = "budget.posix_filesystem_adapter.global";
pub const BUDGET_POSIX_FILESYSTEM_ADAPTER_PER_MOUNT: &str =
    "budget.posix_filesystem_adapter.per_mount";
pub const BUDGET_POSIX_FILESYSTEM_ADAPTER_PER_SESSION: &str =
    "budget.posix_filesystem_adapter.per_session";

// ── Execution Classes (P5-01 §1) ──────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterExecClass {
    KernelRuntimeK0 = 0,
    MountHelperP1 = 1,
    SessionMirrorL1 = 2,
}

impl PosixFilesystemAdapterExecClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelRuntimeK0 => "exec.posix_filesystem_adapter.kernel_runtime.k0",
            Self::MountHelperP1 => "exec.posix_filesystem_adapter.mount_helper.p1",
            Self::SessionMirrorL1 => "exec.posix_filesystem_adapter.session_mirror.l1",
        }
    }
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::KernelRuntimeK0)
    }
    #[must_use]
    pub const fn is_non_production_by_law(self) -> bool {
        matches!(self, Self::SessionMirrorL1)
    }
}

impl Default for PosixFilesystemAdapterExecClass {
    fn default() -> Self {
        Self::KernelRuntimeK0
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterExecClass {
    type Error = PosixFilesystemAdapterDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::KernelRuntimeK0),
            1 => Ok(Self::MountHelperP1),
            2 => Ok(Self::SessionMirrorL1),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownExecClass(value)),
        }
    }
}

// ── Thread-Set Classes (P5-01 §3) ─────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterThreadSetClass {
    Control = 0,
    Request = 1,
    PageWriteback = 2,
    PublicationBridge = 3,
    ResponseBridge = 4,
    Drain = 5,
    Recovery = 6,
}

impl PosixFilesystemAdapterThreadSetClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "threads.posix_filesystem_adapter.control",
            Self::Request => "threads.posix_filesystem_adapter.request",
            Self::PageWriteback => "threads.posix_filesystem_adapter.page_writeback",
            Self::PublicationBridge => "threads.posix_filesystem_adapter.publication_bridge",
            Self::ResponseBridge => "threads.posix_filesystem_adapter.response_bridge",
            Self::Drain => "threads.posix_filesystem_adapter.drain",
            Self::Recovery => "threads.posix_filesystem_adapter.recovery",
        }
    }
    #[must_use]
    pub const fn is_control_plane(self) -> bool {
        matches!(self, Self::Control | Self::Recovery)
    }
    #[must_use]
    pub const fn is_data_plane(self) -> bool {
        matches!(self, Self::Request | Self::PageWriteback)
    }
}

impl Default for PosixFilesystemAdapterThreadSetClass {
    fn default() -> Self {
        Self::Control
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterThreadSetClass {
    type Error = PosixFilesystemAdapterDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Request),
            2 => Ok(Self::PageWriteback),
            3 => Ok(Self::PublicationBridge),
            4 => Ok(Self::ResponseBridge),
            5 => Ok(Self::Drain),
            6 => Ok(Self::Recovery),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownThreadSetClass(
                value,
            )),
        }
    }
}

// ── Phase Classes (P5-01 §4) ──────────────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterPhaseClass {
    Bootstrap = 0,
    SteadyState = 1,
    ShadowPilotCompare = 2,
    PageCacheWarm = 3,
    Drain = 4,
    QuarantineOrRecovery = 5,
}

impl PosixFilesystemAdapterPhaseClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "phase.posix_filesystem_adapter.bootstrap",
            Self::SteadyState => "phase.posix_filesystem_adapter.steady_state",
            Self::ShadowPilotCompare => "phase.posix_filesystem_adapter.shadow_pilot_compare",
            Self::PageCacheWarm => "phase.posix_filesystem_adapter.page_cache_warm",
            Self::Drain => "phase.posix_filesystem_adapter.drain",
            Self::QuarantineOrRecovery => "phase.posix_filesystem_adapter.quarantine_or_recovery",
        }
    }
    #[must_use]
    pub const fn is_serving(self) -> bool {
        matches!(self, Self::SteadyState | Self::PageCacheWarm)
    }
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Drain | Self::QuarantineOrRecovery)
    }
}

impl Default for PosixFilesystemAdapterPhaseClass {
    fn default() -> Self {
        Self::Bootstrap
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterPhaseClass {
    type Error = PosixFilesystemAdapterDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::SteadyState),
            2 => Ok(Self::ShadowPilotCompare),
            3 => Ok(Self::PageCacheWarm),
            4 => Ok(Self::Drain),
            5 => Ok(Self::QuarantineOrRecovery),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownPhaseClass(value)),
        }
    }
}

// ── Restart Verdict Classes (P5-01 §5) ────────────────────────────────────

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PosixFilesystemAdapterRestartVerdictClass {
    Clean = 0,
    CrashNoCorruption = 1,
    CrashLedgerHealable = 2,
    CrashQuarantineRequired = 3,
    RecoveryInProgress = 4,
    Fatal = 5,
}

impl PosixFilesystemAdapterRestartVerdictClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clean => "restart.posix_filesystem_adapter.clean",
            Self::CrashNoCorruption => "restart.posix_filesystem_adapter.crash_no_corruption",
            Self::CrashLedgerHealable => "restart.posix_filesystem_adapter.crash_ledger_healable",
            Self::CrashQuarantineRequired => {
                "restart.posix_filesystem_adapter.crash_quarantine_required"
            }
            Self::RecoveryInProgress => "restart.posix_filesystem_adapter.recovery_in_progress",
            Self::Fatal => "restart.posix_filesystem_adapter.fatal",
        }
    }
    #[must_use]
    pub const fn is_servable(self) -> bool {
        matches!(
            self,
            Self::Clean | Self::CrashNoCorruption | Self::CrashLedgerHealable
        )
    }
    #[must_use]
    pub const fn requires_quarantine(self) -> bool {
        matches!(self, Self::CrashQuarantineRequired)
    }
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(self, Self::Fatal)
    }
}

impl Default for PosixFilesystemAdapterRestartVerdictClass {
    fn default() -> Self {
        Self::Clean
    }
}

impl TryFrom<u32> for PosixFilesystemAdapterRestartVerdictClass {
    type Error = PosixFilesystemAdapterDecodeError;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Clean),
            1 => Ok(Self::CrashNoCorruption),
            2 => Ok(Self::CrashLedgerHealable),
            3 => Ok(Self::CrashQuarantineRequired),
            4 => Ok(Self::RecoveryInProgress),
            5 => Ok(Self::Fatal),
            _ => Err(PosixFilesystemAdapterDecodeError::UnknownRestartVerdictClass(value)),
        }
    }
}

// ── Budget Summary ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterBudgetSummary {
    pub global_max_sessions: u32,
    pub per_mount_dirty_window_bytes: u64,
    pub per_mount_read_ahead_bytes: u64,
    pub per_mount_cache_bytes: u64,
    pub per_session_max_inflight_requests: u32,
    pub per_session_max_reply_bytes: u64,
}

// ── Record Families (P5-01 §7) ────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterMountIntentRecord {
    pub mount_intent_id: PosixFilesystemAdapterId128,
    pub exec_class: u32,
    pub mount_path_len_bytes: u16,
    pub charter_budget_domain_id: PosixFilesystemAdapterId128,
    pub backend_locator_id: PosixFilesystemAdapterId128,
    pub flags: u32,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterSessionStateRecord {
    pub session_id: PosixFilesystemAdapterId128,
    pub mount_intent_id: PosixFilesystemAdapterId128,
    pub exec_class: u32,
    pub phase: u32,
    pub previous_phase: u32,
    pub phase_transition_count: u32,
    pub live_thread_set_count: u32,
    pub backpressure_state: u8,
    pub _reserved: [u8; 31],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterThreadSetBindingRecord {
    pub thread_set_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub thread_class: u32,
    pub worker_count: u16,
    pub max_queue_depth: u16,
    pub health: u8,
    pub drain_progress: u8,
    pub _reserved: [u8; 14],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterRestartVerdictRecord {
    pub verdict_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub verdict_class: u32,
    pub last_phase: u32,
    pub consecutive_crash_count: u32,
    pub quarantine_locator_id: PosixFilesystemAdapterId128,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterDrainReceipt {
    pub drain_receipt_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub drained_request_count: u64,
    pub flushed_dirty_page_count: u64,
    pub finalized_orphan_count: u64,
    pub drain_complete: u8,
    pub _reserved: [u8; 31],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterBudgetBindingRecord {
    pub binding_id: PosixFilesystemAdapterId128,
    pub scope_id: PosixFilesystemAdapterId128,
    pub budget_domain_kind: u8,
    pub thread_ceiling: u16,
    pub fd_ceiling: u16,
    pub reply_byte_ceiling: u64,
    pub pin_loan_ceiling: u64,
    pub _reserved: [u8; 16],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterCharterProjectionRecord {
    pub projection_id: PosixFilesystemAdapterId128,
    pub mount_intent_id: PosixFilesystemAdapterId128,
    pub charter_version: u32,
    pub flags: u32,
    pub capability_bitmap: u64,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterPublicationBridgeBindingRecord {
    pub bridge_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub publication_channel_id: PosixFilesystemAdapterId128,
    pub max_batch_size: u32,
    pub flags: u32,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterResponseBridgeBindingRecord {
    pub bridge_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub response_registry_channel_id: PosixFilesystemAdapterId128,
    pub max_inflight_responses: u32,
    pub flags: u32,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterQuarantineStateRecord {
    pub quarantine_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub mount_intent_id: PosixFilesystemAdapterId128,
    pub trigger_verdict_class: u32,
    pub quarantine_since_secs: u64,
    pub auto_recoverable: u8,
    pub _reserved: [u8; 23],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterCrashIncidentRecord {
    pub incident_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub last_phase: u32,
    pub implicated_scope: u32,
    pub verdict_hint: u32,
    pub _reserved: [u8; 32],
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterRestartRecoveryRecord {
    pub recovery_id: PosixFilesystemAdapterId128,
    pub session_id: PosixFilesystemAdapterId128,
    pub verdict_class: u32,
    pub quarantine_locator_id: PosixFilesystemAdapterId128,
    pub recovery_attempt_count: u32,
    pub recovery_complete: u8,
    pub _reserved: [u8; 23],
}

// ── Topology Error Type ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixFilesystemAdapterTopologyError {
    MountIntentRejected,
    SessionNotFound,
    IllegalPhaseTransition,
    ThreadSetAllocationFailed,
    BudgetCeilingExceeded,
    DrainIncomplete,
    QuarantineRequired,
    RecoveryFailed,
    InvalidState,
}

// ── Topology Declaration (P5-01 §10 algorithm #1) ─────────────────────────

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PosixFilesystemAdapterTopologyDeclaration {
    pub kernel_resident_family_id: &'static str,
    pub lab_mirror_family_id: &'static str,
    pub mount_helper_family_id: &'static str,
    pub exec_class_count: u32,
    pub thread_set_class_count: u32,
    pub phase_class_count: u32,
    pub restart_verdict_class_count: u32,
    pub required_record_family_count: u32,
    pub required_algorithm_count: u32,
}

#[must_use]
pub const fn declare_posix_filesystem_adapter_runtime_topology_and_execution_classes(
) -> PosixFilesystemAdapterTopologyDeclaration {
    PosixFilesystemAdapterTopologyDeclaration {
        kernel_resident_family_id: SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_KERNEL_RESIDENT_K0,
        lab_mirror_family_id: SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_LAB_MIRROR_L0,
        mount_helper_family_id: HELPER_POSIX_FILESYSTEM_ADAPTER_MOUNT_FUSE_H0,
        exec_class_count: 3,
        thread_set_class_count: 7,
        phase_class_count: 6,
        restart_verdict_class_count: 6,
        required_record_family_count: 10,
        required_algorithm_count: 10,
    }
}

// ── Algorithm Stubs (P5-01 §10 algorithms #2-#10) ─────────────────────────

#[must_use]
pub fn normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
    _mount_intent_id: PosixFilesystemAdapterId128,
) -> PosixFilesystemAdapterMountIntentRecord {
    PosixFilesystemAdapterMountIntentRecord::default()
}

pub fn admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
    _intent: &PosixFilesystemAdapterMountIntentRecord,
) -> Result<PosixFilesystemAdapterSessionStateRecord, PosixFilesystemAdapterTopologyError> {
    Ok(PosixFilesystemAdapterSessionStateRecord::default())
}

pub fn spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(
    _session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterSessionStateRecord, PosixFilesystemAdapterTopologyError> {
    Ok(PosixFilesystemAdapterSessionStateRecord::default())
}

pub fn materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws(
    _session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<[PosixFilesystemAdapterThreadSetBindingRecord; 7], PosixFilesystemAdapterTopologyError>
{
    Ok([PosixFilesystemAdapterThreadSetBindingRecord::default(); 7])
}

pub fn bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces(
    _session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<
    (
        PosixFilesystemAdapterPublicationBridgeBindingRecord,
        PosixFilesystemAdapterResponseBridgeBindingRecord,
    ),
    PosixFilesystemAdapterTopologyError,
> {
    Ok((
        PosixFilesystemAdapterPublicationBridgeBindingRecord::default(),
        PosixFilesystemAdapterResponseBridgeBindingRecord::default(),
    ))
}

pub fn issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper(
    _session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<(), PosixFilesystemAdapterTopologyError> {
    Ok(())
}

pub fn drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure(
    _session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterDrainReceipt, PosixFilesystemAdapterTopologyError> {
    Ok(PosixFilesystemAdapterDrainReceipt::default())
}

#[must_use]
pub fn classify_posix_filesystem_adapter_session_crash_or_abnormal_stop(
    _session_id: PosixFilesystemAdapterId128,
    _last_phase: PosixFilesystemAdapterPhaseClass,
) -> PosixFilesystemAdapterCrashIncidentRecord {
    PosixFilesystemAdapterCrashIncidentRecord::default()
}

pub fn recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(
    _incident: &PosixFilesystemAdapterCrashIncidentRecord,
) -> Result<PosixFilesystemAdapterRestartRecoveryRecord, PosixFilesystemAdapterTopologyError> {
    Ok(PosixFilesystemAdapterRestartRecoveryRecord::default())
}

// ── Convenience: Phase Transition & Restart Probe ─────────────────────────

#[must_use]
pub const fn is_legal_phase_transition(
    from: PosixFilesystemAdapterPhaseClass,
    to: PosixFilesystemAdapterPhaseClass,
) -> bool {
    use PosixFilesystemAdapterPhaseClass::*;
    match (from, to) {
        (Bootstrap, SteadyState) | (Bootstrap, QuarantineOrRecovery) => true,
        (SteadyState, ShadowPilotCompare)
        | (SteadyState, PageCacheWarm)
        | (SteadyState, Drain)
        | (SteadyState, QuarantineOrRecovery) => true,
        (ShadowPilotCompare, SteadyState) | (ShadowPilotCompare, QuarantineOrRecovery) => true,
        (PageCacheWarm, SteadyState)
        | (PageCacheWarm, Drain)
        | (PageCacheWarm, QuarantineOrRecovery) => true,
        (Drain, QuarantineOrRecovery) => true,
        (a, b) if a.as_u32() == b.as_u32() => true,
        (QuarantineOrRecovery, _) => false,
        _ => false,
    }
}

pub fn transition_posix_filesystem_adapter_to_phase(
    session: &mut PosixFilesystemAdapterSessionStateRecord,
    new_phase: PosixFilesystemAdapterPhaseClass,
) -> Result<PosixFilesystemAdapterPhaseClass, PosixFilesystemAdapterTopologyError> {
    let current_phase = match PosixFilesystemAdapterPhaseClass::try_from(session.phase) {
        Ok(p) => p,
        Err(_) => return Err(PosixFilesystemAdapterTopologyError::InvalidState),
    };
    if !is_legal_phase_transition(current_phase, new_phase) {
        return Err(PosixFilesystemAdapterTopologyError::IllegalPhaseTransition);
    }
    session.previous_phase = session.phase;
    session.phase = new_phase.as_u32();
    session.phase_transition_count = session.phase_transition_count.wrapping_add(1);
    Ok(new_phase)
}

#[must_use]
pub fn probe_restart_state_and_emit_restart_verdict(
    session_id: PosixFilesystemAdapterId128,
    last_phase: PosixFilesystemAdapterPhaseClass,
    dirty_pages_remain: bool,
    ledger_healable: bool,
    consecutive_crash_count: u32,
    max_crash_before_quarantine: u32,
) -> PosixFilesystemAdapterRestartVerdictRecord {
    let verdict_class = if !dirty_pages_remain && !ledger_healable {
        PosixFilesystemAdapterRestartVerdictClass::Clean
    } else if !dirty_pages_remain && consecutive_crash_count < max_crash_before_quarantine {
        PosixFilesystemAdapterRestartVerdictClass::CrashNoCorruption
    } else if ledger_healable && consecutive_crash_count < max_crash_before_quarantine {
        PosixFilesystemAdapterRestartVerdictClass::CrashLedgerHealable
    } else if consecutive_crash_count < max_crash_before_quarantine {
        PosixFilesystemAdapterRestartVerdictClass::CrashQuarantineRequired
    } else if consecutive_crash_count >= max_crash_before_quarantine {
        PosixFilesystemAdapterRestartVerdictClass::Fatal
    } else {
        PosixFilesystemAdapterRestartVerdictClass::RecoveryInProgress
    };
    PosixFilesystemAdapterRestartVerdictRecord {
        verdict_id: PosixFilesystemAdapterId128::ZERO,
        session_id,
        verdict_class: verdict_class.as_u32(),
        last_phase: last_phase.as_u32(),
        consecutive_crash_count,
        quarantine_locator_id: PosixFilesystemAdapterId128::ZERO,
        _reserved: [0u8; 32],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_class_count_is_three() {
        assert_eq!(PosixFilesystemAdapterExecClass::KernelRuntimeK0.as_u32(), 0);
        assert_eq!(PosixFilesystemAdapterExecClass::MountHelperP1.as_u32(), 1);
        assert_eq!(PosixFilesystemAdapterExecClass::SessionMirrorL1.as_u32(), 2);
    }
    #[test]
    fn exec_class_try_from_roundtrips() {
        for i in 0u32..3 {
            let c = PosixFilesystemAdapterExecClass::try_from(i).expect("valid");
            assert_eq!(c.as_u32(), i);
        }
    }
    #[test]
    fn exec_class_production() {
        assert!(PosixFilesystemAdapterExecClass::KernelRuntimeK0.is_production());
        assert!(!PosixFilesystemAdapterExecClass::SessionMirrorL1.is_production());
    }
    #[test]
    fn exec_class_as_str_has_prefix() {
        assert!(PosixFilesystemAdapterExecClass::KernelRuntimeK0
            .as_str()
            .contains("exec.posix_filesystem_adapter"));
    }

    #[test]
    fn thread_set_class_count_is_seven() {
        for i in 0u32..7 {
            assert!(PosixFilesystemAdapterThreadSetClass::try_from(i).is_ok());
        }
        assert!(PosixFilesystemAdapterThreadSetClass::try_from(7).is_err());
    }

    #[test]
    fn phase_class_count_is_six() {
        for i in 0u32..6 {
            assert!(PosixFilesystemAdapterPhaseClass::try_from(i).is_ok());
        }
        assert!(PosixFilesystemAdapterPhaseClass::try_from(6).is_err());
    }

    #[test]
    fn restart_verdict_class_count_is_six() {
        for i in 0u32..6 {
            assert!(PosixFilesystemAdapterRestartVerdictClass::try_from(i).is_ok());
        }
        assert!(PosixFilesystemAdapterRestartVerdictClass::try_from(6).is_err());
    }

    #[test]
    fn topology_declaration_counts() {
        let d = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
        assert_eq!(d.exec_class_count, 3);
        assert_eq!(d.thread_set_class_count, 7);
        assert_eq!(d.phase_class_count, 6);
        assert_eq!(d.restart_verdict_class_count, 6);
        assert_eq!(d.required_record_family_count, 10);
        assert_eq!(d.required_algorithm_count, 10);
    }

    #[test]
    fn legal_transitions() {
        use PosixFilesystemAdapterPhaseClass::*;
        assert!(is_legal_phase_transition(Bootstrap, SteadyState));
        assert!(is_legal_phase_transition(SteadyState, Drain));
        assert!(is_legal_phase_transition(SteadyState, QuarantineOrRecovery));
        assert!(is_legal_phase_transition(PageCacheWarm, Drain));
    }

    #[test]
    fn quarantine_no_return() {
        assert!(!is_legal_phase_transition(
            PosixFilesystemAdapterPhaseClass::QuarantineOrRecovery,
            PosixFilesystemAdapterPhaseClass::SteadyState,
        ));
    }

    #[test]
    fn self_transition_legal() {
        for i in 0u32..6 {
            let p = PosixFilesystemAdapterPhaseClass::try_from(i).unwrap();
            assert!(is_legal_phase_transition(p, p));
        }
    }

    #[test]
    fn transition_phase_updates_session() {
        let mut s = PosixFilesystemAdapterSessionStateRecord {
            phase: PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32(),
            ..Default::default()
        };
        let r = transition_posix_filesystem_adapter_to_phase(
            &mut s,
            PosixFilesystemAdapterPhaseClass::SteadyState,
        );
        assert!(r.is_ok());
        assert_eq!(
            s.phase,
            PosixFilesystemAdapterPhaseClass::SteadyState.as_u32()
        );
        assert_eq!(
            s.previous_phase,
            PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32()
        );
        assert_eq!(s.phase_transition_count, 1);
    }

    #[test]
    fn all_record_defaults_zero() {
        let m = PosixFilesystemAdapterMountIntentRecord::default();
        assert_eq!(m.exec_class, 0);
        let s = PosixFilesystemAdapterSessionStateRecord::default();
        assert_eq!(s.phase, 0);
        let d = PosixFilesystemAdapterDrainReceipt::default();
        assert_eq!(d.drain_complete, 0);
        let v = PosixFilesystemAdapterRestartVerdictRecord::default();
        assert_eq!(v.verdict_class, 0);
    }

    #[test]
    fn algorithm_stubs_compile() {
        let _ = normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
            PosixFilesystemAdapterId128::ZERO,
        );
        let _ = admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
            &PosixFilesystemAdapterMountIntentRecord::default(),
        );
        let _ = spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(
            &PosixFilesystemAdapterSessionStateRecord::default(),
        );
        let _ = materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws(
            &PosixFilesystemAdapterSessionStateRecord::default(),
        );
        let _ = bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces(&PosixFilesystemAdapterSessionStateRecord::default());
        let _ = issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper(
            &PosixFilesystemAdapterSessionStateRecord::default(),
        );
        let _ = drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure(
            &PosixFilesystemAdapterSessionStateRecord::default(),
        );
        let _ = classify_posix_filesystem_adapter_session_crash_or_abnormal_stop(
            PosixFilesystemAdapterId128::ZERO,
            PosixFilesystemAdapterPhaseClass::SteadyState,
        );
        let _ = recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(&PosixFilesystemAdapterCrashIncidentRecord::default());
    }

    #[test]
    fn restart_verdict_class_predicates() {
        assert!(PosixFilesystemAdapterRestartVerdictClass::Clean.is_servable());
        assert!(!PosixFilesystemAdapterRestartVerdictClass::Fatal.is_servable());
        assert!(
            PosixFilesystemAdapterRestartVerdictClass::CrashQuarantineRequired
                .requires_quarantine()
        );
        assert!(PosixFilesystemAdapterRestartVerdictClass::Fatal.is_fatal());
    }

    #[test]
    fn exec_class_default_is_kernel_runtime() {
        assert_eq!(
            PosixFilesystemAdapterExecClass::default(),
            PosixFilesystemAdapterExecClass::KernelRuntimeK0
        );
    }

    #[test]
    fn exec_class_try_from_invalid_rejects() {
        assert!(PosixFilesystemAdapterExecClass::try_from(3).is_err());
        assert!(PosixFilesystemAdapterExecClass::try_from(100).is_err());
        assert!(PosixFilesystemAdapterExecClass::try_from(u32::MAX).is_err());
    }

    #[test]
    fn exec_class_is_non_production_by_law() {
        assert!(!PosixFilesystemAdapterExecClass::KernelRuntimeK0.is_non_production_by_law());
        assert!(!PosixFilesystemAdapterExecClass::MountHelperP1.is_non_production_by_law());
        assert!(PosixFilesystemAdapterExecClass::SessionMirrorL1.is_non_production_by_law());
    }

    #[test]
    fn exec_class_as_str_exact_match() {
        assert_eq!(
            PosixFilesystemAdapterExecClass::KernelRuntimeK0.as_str(),
            "exec.posix_filesystem_adapter.kernel_runtime.k0"
        );
        assert_eq!(
            PosixFilesystemAdapterExecClass::MountHelperP1.as_str(),
            "exec.posix_filesystem_adapter.mount_helper.p1"
        );
        assert_eq!(
            PosixFilesystemAdapterExecClass::SessionMirrorL1.as_str(),
            "exec.posix_filesystem_adapter.session_mirror.l1"
        );
    }

    #[test]
    fn exec_class_is_production_all_variants() {
        assert!(PosixFilesystemAdapterExecClass::KernelRuntimeK0.is_production());
        assert!(!PosixFilesystemAdapterExecClass::MountHelperP1.is_production());
        assert!(!PosixFilesystemAdapterExecClass::SessionMirrorL1.is_production());
    }

    // ── Topology declaration tests ───────────────────────────────────────

    #[test]
    fn topology_declaration_default_all_fields_zero_or_empty() {
        let d = PosixFilesystemAdapterTopologyDeclaration::default();
        assert!(d.kernel_resident_family_id.is_empty());
        assert!(d.lab_mirror_family_id.is_empty());
        assert!(d.mount_helper_family_id.is_empty());
        assert_eq!(d.exec_class_count, 0);
        assert_eq!(d.thread_set_class_count, 0);
        assert_eq!(d.phase_class_count, 0);
        assert_eq!(d.restart_verdict_class_count, 0);
        assert_eq!(d.required_record_family_count, 0);
        assert_eq!(d.required_algorithm_count, 0);
    }

    #[test]
    fn topology_declaration_declare_has_expected_constants() {
        let d = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
        assert_eq!(
            d.kernel_resident_family_id,
            SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_KERNEL_RESIDENT_K0
        );
        assert_eq!(
            d.lab_mirror_family_id,
            SERVICE_POSIX_FILESYSTEM_ADAPTER_RUNTIME_LAB_MIRROR_L0
        );
        assert_eq!(
            d.mount_helper_family_id,
            HELPER_POSIX_FILESYSTEM_ADAPTER_MOUNT_FUSE_H0
        );
    }

    #[test]
    fn topology_declaration_declare_constant_stability() {
        let d1 = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
        let d2 = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
        assert_eq!(d1, d2);
        assert_eq!(d1.exec_class_count, 3);
        assert_eq!(d1.thread_set_class_count, 7);
        assert_eq!(d1.phase_class_count, 6);
    }

    #[test]
    fn budget_summary_default_all_fields_zero() {
        let b = PosixFilesystemAdapterBudgetSummary::default();
        assert_eq!(b.global_max_sessions, 0);
        assert_eq!(b.per_mount_dirty_window_bytes, 0);
        assert_eq!(b.per_mount_read_ahead_bytes, 0);
        assert_eq!(b.per_mount_cache_bytes, 0);
        assert_eq!(b.per_session_max_inflight_requests, 0);
        assert_eq!(b.per_session_max_reply_bytes, 0);
    }

    #[test]
    fn restart_verdict_probe_clean() {
        let v = probe_restart_state_and_emit_restart_verdict(
            PosixFilesystemAdapterId128::ZERO,
            PosixFilesystemAdapterPhaseClass::SteadyState,
            false, // no dirty pages
            false, // ledger not healable
            0,
            3,
        );
        assert_eq!(
            v.verdict_class,
            PosixFilesystemAdapterRestartVerdictClass::Clean.as_u32()
        );
    }

    #[test]
    fn restart_verdict_probe_fatal_after_max_crashes() {
        let v = probe_restart_state_and_emit_restart_verdict(
            PosixFilesystemAdapterId128::ZERO,
            PosixFilesystemAdapterPhaseClass::SteadyState,
            true,
            true,
            5,
            3,
        );
        assert_eq!(
            v.verdict_class,
            PosixFilesystemAdapterRestartVerdictClass::Fatal.as_u32()
        );
    }

    #[test]
    fn restart_verdict_probe_crash_no_corruption() {
        let v = probe_restart_state_and_emit_restart_verdict(
            PosixFilesystemAdapterId128::ZERO,
            PosixFilesystemAdapterPhaseClass::SteadyState,
            false, // no dirty pages
            true,  // ledger healable (but !dirty_pages skips this check)
            1,
            3,
        );
        // !dirty_pages_remain && consecutive_crash_count < max → CrashNoCorruption
        assert_eq!(
            v.verdict_class,
            PosixFilesystemAdapterRestartVerdictClass::CrashNoCorruption.as_u32()
        );
    }

    #[test]
    fn thread_set_class_predicates() {
        assert!(PosixFilesystemAdapterThreadSetClass::Control.is_control_plane());
        assert!(PosixFilesystemAdapterThreadSetClass::Recovery.is_control_plane());
        assert!(!PosixFilesystemAdapterThreadSetClass::Request.is_control_plane());
        assert!(PosixFilesystemAdapterThreadSetClass::Request.is_data_plane());
        assert!(PosixFilesystemAdapterThreadSetClass::PageWriteback.is_data_plane());
        assert!(!PosixFilesystemAdapterThreadSetClass::Control.is_data_plane());
    }

    #[test]
    fn phase_class_predicates() {
        assert!(PosixFilesystemAdapterPhaseClass::SteadyState.is_serving());
        assert!(PosixFilesystemAdapterPhaseClass::PageCacheWarm.is_serving());
        assert!(!PosixFilesystemAdapterPhaseClass::Bootstrap.is_serving());
        assert!(PosixFilesystemAdapterPhaseClass::Drain.is_terminal());
        assert!(PosixFilesystemAdapterPhaseClass::QuarantineOrRecovery.is_terminal());
        assert!(!PosixFilesystemAdapterPhaseClass::SteadyState.is_terminal());
    }

    #[test]
    fn illegal_phase_transition_rejected() {
        use PosixFilesystemAdapterPhaseClass::*;
        assert!(!is_legal_phase_transition(SteadyState, Bootstrap));
        assert!(!is_legal_phase_transition(Drain, SteadyState));
        assert!(!is_legal_phase_transition(QuarantineOrRecovery, Bootstrap));
        assert!(!is_legal_phase_transition(Drain, PageCacheWarm));
    }

    #[test]
    fn transition_with_invalid_current_phase_errors() {
        let mut s = PosixFilesystemAdapterSessionStateRecord {
            phase: 99,
            ..Default::default()
        };
        let r = transition_posix_filesystem_adapter_to_phase(
            &mut s,
            PosixFilesystemAdapterPhaseClass::SteadyState,
        );
        assert!(r.is_err());
    }
}

// ── Extended ExecClass tests ──────────────────────────────────────

#[test]
fn exec_class_is_non_production_by_law() {
    // SessionMirrorL1 is the only non-production-by-law class
    assert!(!PosixFilesystemAdapterExecClass::KernelRuntimeK0.is_non_production_by_law());
    assert!(!PosixFilesystemAdapterExecClass::MountHelperP1.is_non_production_by_law());
    assert!(PosixFilesystemAdapterExecClass::SessionMirrorL1.is_non_production_by_law());
}

#[test]
fn exec_class_default_is_kernel_runtime() {
    assert_eq!(
        PosixFilesystemAdapterExecClass::default(),
        PosixFilesystemAdapterExecClass::KernelRuntimeK0
    );
}

#[test]
fn exec_class_try_from_invalid_rejects() {
    assert!(PosixFilesystemAdapterExecClass::try_from(3).is_err());
    assert!(PosixFilesystemAdapterExecClass::try_from(99).is_err());
    assert!(PosixFilesystemAdapterExecClass::try_from(u32::MAX).is_err());
}

#[test]
fn exec_class_as_str_exact_values() {
    assert_eq!(
        PosixFilesystemAdapterExecClass::KernelRuntimeK0.as_str(),
        "exec.posix_filesystem_adapter.kernel_runtime.k0"
    );
    assert_eq!(
        PosixFilesystemAdapterExecClass::MountHelperP1.as_str(),
        "exec.posix_filesystem_adapter.mount_helper.p1"
    );
    assert_eq!(
        PosixFilesystemAdapterExecClass::SessionMirrorL1.as_str(),
        "exec.posix_filesystem_adapter.session_mirror.l1"
    );
}

// ── PhaseClass predicates ─────────────────────────────────────────

#[test]
fn phase_class_is_serving() {
    use PosixFilesystemAdapterPhaseClass::*;
    assert!(!Bootstrap.is_serving());
    assert!(SteadyState.is_serving());
    assert!(!ShadowPilotCompare.is_serving());
    assert!(PageCacheWarm.is_serving());
    assert!(!Drain.is_serving());
    assert!(!QuarantineOrRecovery.is_serving());
}

#[test]
fn phase_class_is_terminal() {
    use PosixFilesystemAdapterPhaseClass::*;
    assert!(!Bootstrap.is_terminal());
    assert!(!SteadyState.is_terminal());
    assert!(!ShadowPilotCompare.is_terminal());
    assert!(!PageCacheWarm.is_terminal());
    assert!(Drain.is_terminal());
    assert!(QuarantineOrRecovery.is_terminal());
}

#[test]
fn phase_class_default_is_bootstrap() {
    assert_eq!(
        PosixFilesystemAdapterPhaseClass::default(),
        PosixFilesystemAdapterPhaseClass::Bootstrap
    );
}

// ── RestartVerdictClass predicates exhaustiveness ─────────────────

#[test]
fn restart_verdict_all_variants_predicates() {
    use PosixFilesystemAdapterRestartVerdictClass::*;
    // is_servable
    assert!(Clean.is_servable());
    assert!(CrashNoCorruption.is_servable());
    assert!(CrashLedgerHealable.is_servable());
    assert!(!CrashQuarantineRequired.is_servable());
    assert!(!RecoveryInProgress.is_servable());
    assert!(!Fatal.is_servable());
    // requires_quarantine
    assert!(!Clean.requires_quarantine());
    assert!(!CrashNoCorruption.requires_quarantine());
    assert!(!CrashLedgerHealable.requires_quarantine());
    assert!(CrashQuarantineRequired.requires_quarantine());
    assert!(!Fatal.requires_quarantine());
    // is_fatal
    assert!(!Clean.is_fatal());
    assert!(!CrashNoCorruption.is_fatal());
    assert!(!CrashLedgerHealable.is_fatal());
    assert!(!CrashQuarantineRequired.is_fatal());
    assert!(Fatal.is_fatal());
}

#[test]
fn restart_verdict_default_is_clean() {
    assert_eq!(
        PosixFilesystemAdapterRestartVerdictClass::default(),
        PosixFilesystemAdapterRestartVerdictClass::Clean
    );
}

// ── TopologyConfig constant stability ─────────────────────────────

#[test]
fn topology_declaration_family_ids_are_non_empty() {
    let d = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
    assert!(!d.kernel_resident_family_id.is_empty());
    assert!(!d.lab_mirror_family_id.is_empty());
    assert!(!d.mount_helper_family_id.is_empty());
}

#[test]
fn topology_declaration_is_deterministic() {
    let d1 = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
    let d2 = declare_posix_filesystem_adapter_runtime_topology_and_execution_classes();
    assert_eq!(d1, d2);
}
