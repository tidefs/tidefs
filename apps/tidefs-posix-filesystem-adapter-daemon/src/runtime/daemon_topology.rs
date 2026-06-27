// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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

// ── Algorithm Bodies (P5-01 §10 algorithms #2-#10) ────────────────────────

const MOUNT_INTENT_FLAG_NORMALIZED: u32 = 1 << 0;
const SESSION_BRIDGE_FLAG_POLICY_AUTHORITY_BOUND: u32 = 1 << 0;
const SESSION_BRIDGE_FLAG_PUBLICATION_PIPELINE_BOUND: u32 = 1 << 1;
const SESSION_BRIDGE_FLAG_RESPONSE_REGISTRY_BOUND: u32 = 1 << 2;
const SESSION_BRIDGE_FLAG_OBSERVE_SURFACE_BOUND: u32 = 1 << 3;
const THREAD_SET_HEALTH_READY: u8 = 1;
const THREAD_SET_DRAIN_PROGRESS_IDLE: u8 = 0;
const DRAIN_RECEIPT_COMPLETE: u8 = 1;
const SESSION_BACKPRESSURE_READY: u8 = 0;
const PUBLICATION_MAX_BATCH_SIZE: u32 = 64;
const RESPONSE_MAX_INFLIGHT: u32 = 128;
const CONTROL_QUEUE_DEPTH: u16 = 16;
const RUNTIME_QUEUE_DEPTH: u16 = 128;
const PAGE_QUEUE_DEPTH: u16 = 64;
const BRIDGE_QUEUE_DEPTH: u16 = 64;
const MAINTENANCE_QUEUE_DEPTH: u16 = 32;
const CRASH_SCOPE_BOOTSTRAP: u32 = 1;
const CRASH_SCOPE_REQUEST_RUNTIME: u32 = 2;
const CRASH_SCOPE_PAGE_RUNTIME: u32 = 3;
const CRASH_SCOPE_DRAIN: u32 = 4;
const CRASH_SCOPE_QUARANTINE: u32 = 5;

const fn derive_posix_filesystem_adapter_lifecycle_id(
    seed: PosixFilesystemAdapterId128,
    domain: u8,
) -> PosixFilesystemAdapterId128 {
    let mut out = [0_u8; 16];
    let mut index = 0;
    while index < out.len() {
        out[index] = seed.0[index] ^ domain.wrapping_add((index as u8).wrapping_mul(17));
        index += 1;
    }
    PosixFilesystemAdapterId128(out)
}

fn session_phase(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterPhaseClass, PosixFilesystemAdapterTopologyError> {
    if session.session_id.is_zero() || session.mount_intent_id.is_zero() {
        return Err(PosixFilesystemAdapterTopologyError::InvalidState);
    }
    PosixFilesystemAdapterPhaseClass::try_from(session.phase)
        .map_err(|_| PosixFilesystemAdapterTopologyError::InvalidState)
}

fn session_exec_class(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterExecClass, PosixFilesystemAdapterTopologyError> {
    PosixFilesystemAdapterExecClass::try_from(session.exec_class)
        .map_err(|_| PosixFilesystemAdapterTopologyError::InvalidState)
}

fn validate_session_runtime(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterPhaseClass, PosixFilesystemAdapterTopologyError> {
    let phase = session_phase(session)?;
    match session_exec_class(session)? {
        PosixFilesystemAdapterExecClass::KernelRuntimeK0
        | PosixFilesystemAdapterExecClass::SessionMirrorL1 => Ok(phase),
        PosixFilesystemAdapterExecClass::MountHelperP1 => {
            Err(PosixFilesystemAdapterTopologyError::InvalidState)
        }
    }
}

#[must_use]
pub fn normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
    mount_intent_id: PosixFilesystemAdapterId128,
) -> PosixFilesystemAdapterMountIntentRecord {
    PosixFilesystemAdapterMountIntentRecord {
        mount_intent_id,
        exec_class: PosixFilesystemAdapterExecClass::SessionMirrorL1.as_u32(),
        mount_path_len_bytes: 0,
        charter_budget_domain_id: derive_posix_filesystem_adapter_lifecycle_id(
            mount_intent_id,
            0x11,
        ),
        backend_locator_id: derive_posix_filesystem_adapter_lifecycle_id(mount_intent_id, 0x12),
        flags: MOUNT_INTENT_FLAG_NORMALIZED,
        _reserved: [0u8; 32],
    }
}

pub fn admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
    intent: &PosixFilesystemAdapterMountIntentRecord,
) -> Result<PosixFilesystemAdapterSessionStateRecord, PosixFilesystemAdapterTopologyError> {
    if intent.mount_intent_id.is_zero()
        || intent.charter_budget_domain_id.is_zero()
        || intent.backend_locator_id.is_zero()
        || (intent.flags & MOUNT_INTENT_FLAG_NORMALIZED) == 0
    {
        return Err(PosixFilesystemAdapterTopologyError::MountIntentRejected);
    }

    let exec_class = PosixFilesystemAdapterExecClass::try_from(intent.exec_class)
        .map_err(|_| PosixFilesystemAdapterTopologyError::MountIntentRejected)?;
    if matches!(exec_class, PosixFilesystemAdapterExecClass::MountHelperP1) {
        return Err(PosixFilesystemAdapterTopologyError::MountIntentRejected);
    }

    Ok(PosixFilesystemAdapterSessionStateRecord {
        session_id: derive_posix_filesystem_adapter_lifecycle_id(intent.mount_intent_id, 0x21),
        mount_intent_id: intent.mount_intent_id,
        exec_class: exec_class.as_u32(),
        phase: PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32(),
        previous_phase: PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32(),
        phase_transition_count: 0,
        live_thread_set_count: 0,
        backpressure_state: SESSION_BACKPRESSURE_READY,
        _reserved: [0u8; 31],
    })
}

pub fn spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterSessionStateRecord, PosixFilesystemAdapterTopologyError> {
    let phase = validate_session_runtime(session)?;
    if !matches!(phase, PosixFilesystemAdapterPhaseClass::Bootstrap) {
        return Err(PosixFilesystemAdapterTopologyError::IllegalPhaseTransition);
    }

    Ok(PosixFilesystemAdapterSessionStateRecord {
        phase: PosixFilesystemAdapterPhaseClass::SteadyState.as_u32(),
        previous_phase: phase.as_u32(),
        phase_transition_count: session.phase_transition_count.wrapping_add(1),
        live_thread_set_count: 7,
        ..*session
    })
}

pub fn materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<[PosixFilesystemAdapterThreadSetBindingRecord; 7], PosixFilesystemAdapterTopologyError>
{
    let phase = validate_session_runtime(session)?;
    if !phase.is_serving() {
        return Err(PosixFilesystemAdapterTopologyError::InvalidState);
    }

    Ok([
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::Control,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::Request,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::PageWriteback,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::PublicationBridge,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::ResponseBridge,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::Drain,
        ),
        thread_set_binding(
            session.session_id,
            PosixFilesystemAdapterThreadSetClass::Recovery,
        ),
    ])
}

pub fn bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<
    (
        PosixFilesystemAdapterPublicationBridgeBindingRecord,
        PosixFilesystemAdapterResponseBridgeBindingRecord,
    ),
    PosixFilesystemAdapterTopologyError,
> {
    let phase = validate_session_runtime(session)?;
    if !phase.is_serving() || session.live_thread_set_count != 7 {
        return Err(PosixFilesystemAdapterTopologyError::ThreadSetAllocationFailed);
    }

    Ok((
        PosixFilesystemAdapterPublicationBridgeBindingRecord {
            bridge_id: derive_posix_filesystem_adapter_lifecycle_id(session.session_id, 0x41),
            session_id: session.session_id,
            publication_channel_id: derive_posix_filesystem_adapter_lifecycle_id(
                session.session_id,
                0x42,
            ),
            max_batch_size: PUBLICATION_MAX_BATCH_SIZE,
            flags: SESSION_BRIDGE_FLAG_POLICY_AUTHORITY_BOUND
                | SESSION_BRIDGE_FLAG_PUBLICATION_PIPELINE_BOUND
                | SESSION_BRIDGE_FLAG_OBSERVE_SURFACE_BOUND,
            _reserved: [0u8; 32],
        },
        PosixFilesystemAdapterResponseBridgeBindingRecord {
            bridge_id: derive_posix_filesystem_adapter_lifecycle_id(session.session_id, 0x43),
            session_id: session.session_id,
            response_registry_channel_id: derive_posix_filesystem_adapter_lifecycle_id(
                session.session_id,
                0x44,
            ),
            max_inflight_responses: RESPONSE_MAX_INFLIGHT,
            flags: SESSION_BRIDGE_FLAG_POLICY_AUTHORITY_BOUND
                | SESSION_BRIDGE_FLAG_RESPONSE_REGISTRY_BOUND
                | SESSION_BRIDGE_FLAG_OBSERVE_SURFACE_BOUND,
            _reserved: [0u8; 32],
        },
    ))
}

pub fn issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<(), PosixFilesystemAdapterTopologyError> {
    let phase = validate_session_runtime(session)?;
    if !phase.is_serving() || session.live_thread_set_count != 7 {
        return Err(PosixFilesystemAdapterTopologyError::MountIntentRejected);
    }
    Ok(())
}

pub fn drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure(
    session: &PosixFilesystemAdapterSessionStateRecord,
) -> Result<PosixFilesystemAdapterDrainReceipt, PosixFilesystemAdapterTopologyError> {
    let phase = validate_session_runtime(session)?;
    if !(phase.is_serving() || matches!(phase, PosixFilesystemAdapterPhaseClass::Drain)) {
        return Err(PosixFilesystemAdapterTopologyError::DrainIncomplete);
    }

    Ok(PosixFilesystemAdapterDrainReceipt {
        drain_receipt_id: derive_posix_filesystem_adapter_lifecycle_id(session.session_id, 0x51),
        session_id: session.session_id,
        drained_request_count: 0,
        flushed_dirty_page_count: 0,
        finalized_orphan_count: 0,
        drain_complete: DRAIN_RECEIPT_COMPLETE,
        _reserved: [0u8; 31],
    })
}

#[must_use]
pub fn classify_posix_filesystem_adapter_session_crash_or_abnormal_stop(
    session_id: PosixFilesystemAdapterId128,
    last_phase: PosixFilesystemAdapterPhaseClass,
) -> PosixFilesystemAdapterCrashIncidentRecord {
    let (implicated_scope, verdict_hint) = match last_phase {
        PosixFilesystemAdapterPhaseClass::Bootstrap => (
            CRASH_SCOPE_BOOTSTRAP,
            PosixFilesystemAdapterRestartVerdictClass::CrashNoCorruption,
        ),
        PosixFilesystemAdapterPhaseClass::SteadyState
        | PosixFilesystemAdapterPhaseClass::ShadowPilotCompare => (
            CRASH_SCOPE_REQUEST_RUNTIME,
            PosixFilesystemAdapterRestartVerdictClass::CrashLedgerHealable,
        ),
        PosixFilesystemAdapterPhaseClass::PageCacheWarm => (
            CRASH_SCOPE_PAGE_RUNTIME,
            PosixFilesystemAdapterRestartVerdictClass::CrashQuarantineRequired,
        ),
        PosixFilesystemAdapterPhaseClass::Drain => (
            CRASH_SCOPE_DRAIN,
            PosixFilesystemAdapterRestartVerdictClass::RecoveryInProgress,
        ),
        PosixFilesystemAdapterPhaseClass::QuarantineOrRecovery => (
            CRASH_SCOPE_QUARANTINE,
            PosixFilesystemAdapterRestartVerdictClass::Fatal,
        ),
    };

    PosixFilesystemAdapterCrashIncidentRecord {
        incident_id: derive_posix_filesystem_adapter_lifecycle_id(session_id, 0x61),
        session_id,
        last_phase: last_phase.as_u32(),
        implicated_scope,
        verdict_hint: verdict_hint.as_u32(),
        _reserved: [0u8; 32],
    }
}

pub fn recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(
    incident: &PosixFilesystemAdapterCrashIncidentRecord,
) -> Result<PosixFilesystemAdapterRestartRecoveryRecord, PosixFilesystemAdapterTopologyError> {
    if incident.incident_id.is_zero() || incident.session_id.is_zero() {
        return Err(PosixFilesystemAdapterTopologyError::InvalidState);
    }

    let _last_phase = PosixFilesystemAdapterPhaseClass::try_from(incident.last_phase)
        .map_err(|_| PosixFilesystemAdapterTopologyError::InvalidState)?;
    let verdict = PosixFilesystemAdapterRestartVerdictClass::try_from(incident.verdict_hint)
        .map_err(|_| PosixFilesystemAdapterTopologyError::InvalidState)?;

    let requires_quarantine = verdict.requires_quarantine() || verdict.is_fatal();
    let recovery_complete = if verdict.is_servable() { 1 } else { 0 };
    let recovery_attempt_count =
        if matches!(verdict, PosixFilesystemAdapterRestartVerdictClass::Clean) {
            0
        } else {
            1
        };

    Ok(PosixFilesystemAdapterRestartRecoveryRecord {
        recovery_id: derive_posix_filesystem_adapter_lifecycle_id(incident.incident_id, 0x71),
        session_id: incident.session_id,
        verdict_class: verdict.as_u32(),
        quarantine_locator_id: if requires_quarantine {
            derive_posix_filesystem_adapter_lifecycle_id(incident.session_id, 0x72)
        } else {
            PosixFilesystemAdapterId128::ZERO
        },
        recovery_attempt_count,
        recovery_complete,
        _reserved: [0u8; 23],
    })
}

fn thread_set_binding(
    session_id: PosixFilesystemAdapterId128,
    thread_class: PosixFilesystemAdapterThreadSetClass,
) -> PosixFilesystemAdapterThreadSetBindingRecord {
    let (worker_count, max_queue_depth) = match thread_class {
        PosixFilesystemAdapterThreadSetClass::Control => (1, CONTROL_QUEUE_DEPTH),
        PosixFilesystemAdapterThreadSetClass::Request => (2, RUNTIME_QUEUE_DEPTH),
        PosixFilesystemAdapterThreadSetClass::PageWriteback => (2, PAGE_QUEUE_DEPTH),
        PosixFilesystemAdapterThreadSetClass::PublicationBridge
        | PosixFilesystemAdapterThreadSetClass::ResponseBridge => (1, BRIDGE_QUEUE_DEPTH),
        PosixFilesystemAdapterThreadSetClass::Drain
        | PosixFilesystemAdapterThreadSetClass::Recovery => (1, MAINTENANCE_QUEUE_DEPTH),
    };

    PosixFilesystemAdapterThreadSetBindingRecord {
        thread_set_id: derive_posix_filesystem_adapter_lifecycle_id(
            session_id,
            0x30_u8.wrapping_add(thread_class.as_u32() as u8),
        ),
        session_id,
        thread_class: thread_class.as_u32(),
        worker_count,
        max_queue_depth,
        health: THREAD_SET_HEALTH_READY,
        drain_progress: THREAD_SET_DRAIN_PROGRESS_IDLE,
        _reserved: [0u8; 14],
    }
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

    fn admitted_spawned_session() -> PosixFilesystemAdapterSessionStateRecord {
        let intent = normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
            PosixFilesystemAdapterId128::from_u128_le(0x784),
        );
        let admitted =
            admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
                &intent,
            )
            .expect("normalized intent is admitted");
        spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(&admitted)
            .expect("admitted session spawns")
    }

    #[test]
    fn lifecycle_algorithms_materialize_session_state() {
        let mount_intent_id = PosixFilesystemAdapterId128::from_u128_le(0x784);
        let intent = normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
            mount_intent_id,
        );
        assert_eq!(intent.mount_intent_id, mount_intent_id);
        assert_eq!(
            intent.exec_class,
            PosixFilesystemAdapterExecClass::SessionMirrorL1.as_u32()
        );
        assert!(!intent.charter_budget_domain_id.is_zero());
        assert!(!intent.backend_locator_id.is_zero());
        assert_ne!(intent.flags & MOUNT_INTENT_FLAG_NORMALIZED, 0);

        let admitted =
            admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
                &intent,
            )
            .expect("normalized intent is admitted");
        assert!(!admitted.session_id.is_zero());
        assert_eq!(admitted.mount_intent_id, mount_intent_id);
        assert_eq!(
            admitted.phase,
            PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32()
        );
        assert_eq!(admitted.live_thread_set_count, 0);

        let spawned =
            spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(&admitted)
                .expect("admitted session spawns");
        assert_eq!(
            spawned.phase,
            PosixFilesystemAdapterPhaseClass::SteadyState.as_u32()
        );
        assert_eq!(
            spawned.previous_phase,
            PosixFilesystemAdapterPhaseClass::Bootstrap.as_u32()
        );
        assert_eq!(spawned.phase_transition_count, 1);
        assert_eq!(spawned.live_thread_set_count, 7);

        let thread_sets =
            materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws(
                &spawned,
            )
            .expect("serving session materializes thread sets");
        for (index, binding) in thread_sets.iter().enumerate() {
            assert_eq!(binding.session_id, spawned.session_id);
            assert_eq!(binding.thread_class, index as u32);
            assert!(binding.worker_count > 0);
            assert!(binding.max_queue_depth > 0);
            assert_eq!(binding.health, THREAD_SET_HEALTH_READY);
            assert_eq!(binding.drain_progress, THREAD_SET_DRAIN_PROGRESS_IDLE);
        }

        let (publication, response) = bind_posix_filesystem_adapter_session_to_policy_authority_publication_pipeline_response_registry_and_observe_surfaces(&spawned)
            .expect("serving session binds bridge surfaces");
        assert_eq!(publication.session_id, spawned.session_id);
        assert_eq!(publication.max_batch_size, PUBLICATION_MAX_BATCH_SIZE);
        assert_ne!(
            publication.flags & SESSION_BRIDGE_FLAG_PUBLICATION_PIPELINE_BOUND,
            0
        );
        assert_eq!(response.session_id, spawned.session_id);
        assert_eq!(response.max_inflight_responses, RESPONSE_MAX_INFLIGHT);
        assert_ne!(
            response.flags & SESSION_BRIDGE_FLAG_RESPONSE_REGISTRY_BOUND,
            0
        );

        issue_posix_filesystem_adapter_ready_or_refusal_receipt_and_release_mount_helper(&spawned)
            .expect("serving session emits ready receipt");

        let drain =
            drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure(
                &spawned,
            )
            .expect("serving session drains");
        assert_eq!(drain.session_id, spawned.session_id);
        assert!(!drain.drain_receipt_id.is_zero());
        assert_eq!(drain.drain_complete, DRAIN_RECEIPT_COMPLETE);
    }

    #[test]
    fn lifecycle_algorithms_reject_unadmitted_defaults() {
        let default_intent = PosixFilesystemAdapterMountIntentRecord::default();
        assert_eq!(
            admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
                &default_intent,
            ),
            Err(PosixFilesystemAdapterTopologyError::MountIntentRejected)
        );
        assert_eq!(
            spawn_posix_filesystem_adapter_session_runtime_and_transfer_mount_capsule(
                &PosixFilesystemAdapterSessionStateRecord::default(),
            ),
            Err(PosixFilesystemAdapterTopologyError::InvalidState)
        );
        assert_eq!(
            materialize_posix_filesystem_adapter_session_thread_sets_from_p5_02_and_p5_03_laws(
                &PosixFilesystemAdapterSessionStateRecord::default(),
            ),
            Err(PosixFilesystemAdapterTopologyError::InvalidState)
        );
        assert_eq!(
            drain_posix_filesystem_adapter_session_for_unmount_cutover_failover_or_pressure(
                &PosixFilesystemAdapterSessionStateRecord::default(),
            ),
            Err(PosixFilesystemAdapterTopologyError::InvalidState)
        );
        assert_eq!(
            recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(
                &PosixFilesystemAdapterCrashIncidentRecord::default(),
            ),
            Err(PosixFilesystemAdapterTopologyError::InvalidState)
        );
    }

    #[test]
    fn mount_helper_exec_class_is_not_admissible_as_session_owner() {
        let mut intent = normalize_mount_helper_argv_env_to_posix_filesystem_adapter_mount_intent(
            PosixFilesystemAdapterId128::from_u128_le(0x785),
        );
        intent.exec_class = PosixFilesystemAdapterExecClass::MountHelperP1.as_u32();
        assert_eq!(
            admit_posix_filesystem_adapter_mount_intent_under_package_policy_and_global_budget(
                &intent,
            ),
            Err(PosixFilesystemAdapterTopologyError::MountIntentRejected)
        );
    }

    #[test]
    fn crash_classification_quarantines_page_cache_runtime_ambiguity() {
        let session = admitted_spawned_session();
        let incident = classify_posix_filesystem_adapter_session_crash_or_abnormal_stop(
            session.session_id,
            PosixFilesystemAdapterPhaseClass::PageCacheWarm,
        );
        assert!(!incident.incident_id.is_zero());
        assert_eq!(incident.session_id, session.session_id);
        assert_eq!(incident.implicated_scope, CRASH_SCOPE_PAGE_RUNTIME);
        assert_eq!(
            incident.verdict_hint,
            PosixFilesystemAdapterRestartVerdictClass::CrashQuarantineRequired.as_u32()
        );

        let recovery =
            recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(
                &incident,
            )
            .expect("quarantine record is emitted");
        assert_eq!(recovery.session_id, session.session_id);
        assert_eq!(
            recovery.verdict_class,
            PosixFilesystemAdapterRestartVerdictClass::CrashQuarantineRequired.as_u32()
        );
        assert!(!recovery.quarantine_locator_id.is_zero());
        assert_eq!(recovery.recovery_attempt_count, 1);
        assert_eq!(recovery.recovery_complete, 0);
    }

    #[test]
    fn bootstrap_crash_recovery_completes_without_quarantine() {
        let session = admitted_spawned_session();
        let incident = classify_posix_filesystem_adapter_session_crash_or_abnormal_stop(
            session.session_id,
            PosixFilesystemAdapterPhaseClass::Bootstrap,
        );
        assert_eq!(incident.implicated_scope, CRASH_SCOPE_BOOTSTRAP);
        assert_eq!(
            incident.verdict_hint,
            PosixFilesystemAdapterRestartVerdictClass::CrashNoCorruption.as_u32()
        );

        let recovery =
            recover_or_quarantine_posix_filesystem_adapter_session_after_crash_or_supervisor_restart(
                &incident,
            )
            .expect("recovery record is emitted");
        assert_eq!(
            recovery.verdict_class,
            PosixFilesystemAdapterRestartVerdictClass::CrashNoCorruption.as_u32()
        );
        assert!(recovery.quarantine_locator_id.is_zero());
        assert_eq!(recovery.recovery_attempt_count, 1);
        assert_eq!(recovery.recovery_complete, 1);
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
