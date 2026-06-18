// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Pure source model for Linux VFS callback context and teardown ordering.
//!
//! This module is a proof-harness seed for kernel-facing TideFS work. It does
//! not register Linux callbacks, run FUSE operations, or exercise the mounted
//! C shim. Its job is narrower: make kernel VFS assumptions explicit and keep
//! the no-work-after-teardown race proof separate from runtime evidence.

use alloc::vec::Vec;
use core::fmt;

/// Claim id covered by this source model.
pub const KERNEL_TEARDOWN_CLAIM_ID: &str = "kernel.teardown.no_work_after.v1";

/// Stable source-model version recorded by the durable proof artifact.
pub const KERNEL_TEARDOWN_MODEL_VERSION: &str = "kernel-env-model-v1";

/// Bounded schedule depth used by the checked-in claim evidence artifact.
pub const KERNEL_TEARDOWN_PROOF_MAX_DEPTH: usize = 8;

/// Whether a kernel callback or deferred work body may sleep.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SleepToken {
    /// The context may block, allocate with sleeping flags, or wait on I/O.
    Sleepable,
    /// The context must not sleep, for example atomic page-cache callbacks.
    NonSleepable,
}

/// Kernel lifetime authority carried by a callback or deferred work body.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifetimeToken {
    /// VFS callback arguments are valid only for the callback duration.
    CallbackBorrow,
    /// A kernel reference or pin keeps the object alive beyond the callback.
    PinnedReference,
    /// The context is protected by an RCU read-side critical section.
    RcuRead,
    /// Deferred work owns the reference needed to execute later.
    WorkqueueOwned,
}

/// Page-cache or mmap boundary represented by a kernel callback.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CacheBoundaryToken {
    /// Not a page-cache or mmap callback.
    None,
    /// `read_folio` style page-cache population.
    ReadFolio,
    /// `dirty_folio` style dirty accounting.
    DirtyFolio,
    /// `write_begin`/`write_end` buffered write boundary.
    WriteBeginEnd,
    /// `writepages` or deferred writeback boundary.
    Writeback,
    /// Linux filemap invalidation or truncate discard boundary.
    Invalidate,
    /// `mmap`/fault-side boundary.
    MmapFault,
}

/// Teardown assumption carried by a kernel operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TeardownToken {
    /// Operation may enter only while the mount is live and accepting work.
    LiveOnly,
    /// Work may drain after teardown begins, but before final teardown.
    DrainBeforeFinalTeardown,
    /// Operation is part of the teardown path itself.
    TeardownCallback,
}

/// Explicit kernel context assumptions attached to an operation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelContextToken {
    /// Sleepability for this context.
    pub sleep: SleepToken,
    /// Pointer/ref lifetime authority for this context.
    pub lifetime: LifetimeToken,
    /// Page-cache or mmap boundary for this context.
    pub cache: CacheBoundaryToken,
    /// Teardown assumption for this context.
    pub teardown: TeardownToken,
}

impl KernelContextToken {
    /// Construct a token from explicit assumptions.
    #[must_use]
    pub const fn new(
        sleep: SleepToken,
        lifetime: LifetimeToken,
        cache: CacheBoundaryToken,
        teardown: TeardownToken,
    ) -> Self {
        Self {
            sleep,
            lifetime,
            cache,
            teardown,
        }
    }

    /// True when every field has been explicitly placed on the modeled axis.
    #[must_use]
    pub fn is_explicit(self) -> bool {
        true
    }

    /// True when this context is allowed to become a deferred work body.
    #[must_use]
    pub fn can_run_as_workqueue_body(self) -> bool {
        matches!(self.sleep, SleepToken::Sleepable)
            && matches!(self.lifetime, LifetimeToken::WorkqueueOwned)
            && matches!(self.teardown, TeardownToken::DrainBeforeFinalTeardown)
    }
}

/// Modeled kernel operation families that need explicit context tokens.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KernelOperationKind {
    /// Sleepable VFS setattr/truncate callback.
    SetattrTruncate,
    /// Non-sleepable dirty-folio callback.
    DirtyFolio,
    /// Sleepable read-folio callback.
    ReadFolio,
    /// Buffered write begin/end callback pair.
    WriteBeginEnd,
    /// Mounted page-cache invalidation helper path.
    InvalidateRange,
    /// Mmap or fault-side source-model boundary.
    MmapFault,
    /// Deferred engine writeback work item.
    DeferredWriteback,
    /// Deferred flush/fsync work item.
    DeferredFlush,
    /// `umount_begin` style teardown callback.
    UmountBegin,
    /// Final superblock teardown callback.
    PutSuper,
}

impl KernelOperationKind {
    /// Stable label used by model reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SetattrTruncate => "setattr-truncate",
            Self::DirtyFolio => "dirty-folio",
            Self::ReadFolio => "read-folio",
            Self::WriteBeginEnd => "write-begin-end",
            Self::InvalidateRange => "invalidate-range",
            Self::MmapFault => "mmap-fault",
            Self::DeferredWriteback => "deferred-writeback",
            Self::DeferredFlush => "deferred-flush",
            Self::UmountBegin => "umount-begin",
            Self::PutSuper => "put-super",
        }
    }

    /// Required context token for this operation in the current model.
    #[must_use]
    pub const fn required_context(self) -> KernelContextToken {
        match self {
            Self::SetattrTruncate => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::CallbackBorrow,
                CacheBoundaryToken::Invalidate,
                TeardownToken::LiveOnly,
            ),
            Self::DirtyFolio => KernelContextToken::new(
                SleepToken::NonSleepable,
                LifetimeToken::CallbackBorrow,
                CacheBoundaryToken::DirtyFolio,
                TeardownToken::LiveOnly,
            ),
            Self::ReadFolio => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::PinnedReference,
                CacheBoundaryToken::ReadFolio,
                TeardownToken::LiveOnly,
            ),
            Self::WriteBeginEnd => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::PinnedReference,
                CacheBoundaryToken::WriteBeginEnd,
                TeardownToken::LiveOnly,
            ),
            Self::InvalidateRange => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::PinnedReference,
                CacheBoundaryToken::Invalidate,
                TeardownToken::LiveOnly,
            ),
            Self::MmapFault => KernelContextToken::new(
                SleepToken::NonSleepable,
                LifetimeToken::RcuRead,
                CacheBoundaryToken::MmapFault,
                TeardownToken::LiveOnly,
            ),
            Self::DeferredWriteback => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::WorkqueueOwned,
                CacheBoundaryToken::Writeback,
                TeardownToken::DrainBeforeFinalTeardown,
            ),
            Self::DeferredFlush => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::WorkqueueOwned,
                CacheBoundaryToken::None,
                TeardownToken::DrainBeforeFinalTeardown,
            ),
            Self::UmountBegin | Self::PutSuper => KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::PinnedReference,
                CacheBoundaryToken::None,
                TeardownToken::TeardownCallback,
            ),
        }
    }
}

impl fmt::Display for KernelOperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A modeled operation with its explicit kernel context token.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KernelOperation {
    /// Operation family being modeled.
    pub kind: KernelOperationKind,
    /// Explicit kernel context assumptions carried by the operation.
    pub context: KernelContextToken,
}

impl KernelOperation {
    /// Create a modeled operation from an explicit token.
    #[must_use]
    pub const fn new(kind: KernelOperationKind, context: KernelContextToken) -> Self {
        Self { kind, context }
    }

    /// Create a modeled operation with the current required context token.
    #[must_use]
    pub const fn required(kind: KernelOperationKind) -> Self {
        Self {
            kind,
            context: kind.required_context(),
        }
    }

    /// Validate that this operation carries the required context token.
    pub fn validate(self) -> Result<(), ContextTokenError> {
        let required = self.kind.required_context();
        if self.context == required && self.context.is_explicit() {
            Ok(())
        } else {
            Err(ContextTokenError {
                kind: self.kind,
                expected: required,
                actual: self.context,
            })
        }
    }
}

/// Context token mismatch detected by the model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextTokenError {
    /// Operation whose token did not match the model requirement.
    pub kind: KernelOperationKind,
    /// Required token.
    pub expected: KernelContextToken,
    /// Actual token.
    pub actual: KernelContextToken,
}

/// Current modeled kernel operations.
pub const MODELED_KERNEL_OPERATIONS: [KernelOperation; 10] = [
    KernelOperation::required(KernelOperationKind::SetattrTruncate),
    KernelOperation::required(KernelOperationKind::DirtyFolio),
    KernelOperation::required(KernelOperationKind::ReadFolio),
    KernelOperation::required(KernelOperationKind::WriteBeginEnd),
    KernelOperation::required(KernelOperationKind::InvalidateRange),
    KernelOperation::required(KernelOperationKind::MmapFault),
    KernelOperation::required(KernelOperationKind::DeferredWriteback),
    KernelOperation::required(KernelOperationKind::DeferredFlush),
    KernelOperation::required(KernelOperationKind::UmountBegin),
    KernelOperation::required(KernelOperationKind::PutSuper),
];

/// Validate the complete operation table.
pub fn validate_modeled_kernel_operations() -> Result<(), ContextTokenError> {
    for operation in MODELED_KERNEL_OPERATIONS {
        operation.validate()?;
    }
    Ok(())
}

/// Kernel callbacks that may hand off to deferred work bodies in this model.
pub const MODELED_WORKQUEUE_HANDOFFS: [WorkqueueHandoff; 4] = [
    WorkqueueHandoff::new(
        KernelOperation::required(KernelOperationKind::SetattrTruncate),
        KernelOperation::required(KernelOperationKind::DeferredFlush),
    ),
    WorkqueueHandoff::new(
        KernelOperation::required(KernelOperationKind::DirtyFolio),
        KernelOperation::required(KernelOperationKind::DeferredWriteback),
    ),
    WorkqueueHandoff::new(
        KernelOperation::required(KernelOperationKind::WriteBeginEnd),
        KernelOperation::required(KernelOperationKind::DeferredWriteback),
    ),
    WorkqueueHandoff::new(
        KernelOperation::required(KernelOperationKind::InvalidateRange),
        KernelOperation::required(KernelOperationKind::DeferredFlush),
    ),
];

/// Validate every modeled callback-to-workqueue handoff.
pub fn validate_modeled_workqueue_handoffs() -> Result<(), WorkqueueHandoffError> {
    for handoff in MODELED_WORKQUEUE_HANDOFFS {
        handoff.validate()?;
    }
    Ok(())
}

/// A handoff from a kernel callback into deferred workqueue ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkqueueHandoff {
    /// Callback that submits the work.
    pub source: KernelOperation,
    /// Deferred work body that may run later.
    pub work: KernelOperation,
}

impl WorkqueueHandoff {
    /// Construct a workqueue handoff.
    #[must_use]
    pub const fn new(source: KernelOperation, work: KernelOperation) -> Self {
        Self { source, work }
    }

    /// Validate the source callback and workqueue-owned body tokens.
    pub fn validate(self) -> Result<(), WorkqueueHandoffError> {
        self.source
            .validate()
            .map_err(WorkqueueHandoffError::SourceToken)?;
        self.work
            .validate()
            .map_err(WorkqueueHandoffError::WorkToken)?;

        if !self.work.context.can_run_as_workqueue_body() {
            return Err(WorkqueueHandoffError::WorkDoesNotOwnLifetime);
        }
        if matches!(
            self.source.context.teardown,
            TeardownToken::TeardownCallback
        ) {
            return Err(WorkqueueHandoffError::SourceIsTeardownCallback);
        }

        Ok(())
    }
}

/// Workqueue handoff validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkqueueHandoffError {
    /// Source operation context token is invalid.
    SourceToken(ContextTokenError),
    /// Work operation context token is invalid.
    WorkToken(ContextTokenError),
    /// Deferred work body does not own a lifetime-stable reference.
    WorkDoesNotOwnLifetime,
    /// Teardown callbacks may not enqueue normal deferred work.
    SourceIsTeardownCallback,
}

/// Workqueue lifetime token. Generation changes after final teardown.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkqueueOwnerToken {
    /// Logical queue id in the model.
    pub queue_id: u64,
    /// Owner generation. Work from earlier generations is stale.
    pub generation: u64,
}

impl WorkqueueOwnerToken {
    /// Create a workqueue owner token.
    #[must_use]
    pub const fn new(queue_id: u64, generation: u64) -> Self {
        Self {
            queue_id,
            generation,
        }
    }
}

/// Workqueue state in the teardown race model.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WorkqueueState {
    /// Queue accepts new work and may run queued work.
    Accepting,
    /// Queue refuses new work and drains already queued/running work.
    Draining,
    /// Final teardown completed; no work may start.
    TornDown,
}

/// Deferred work item in the model.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkItem {
    /// Model-local work id.
    pub id: u64,
    /// Operation body.
    pub operation: KernelOperation,
    /// Owner token captured when the item was queued.
    pub owner: WorkqueueOwnerToken,
}

/// Recorded execution transition.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExecutionEvent {
    /// Work id.
    pub work_id: u64,
    /// Operation body.
    pub operation: KernelOperationKind,
    /// Queue state when the transition happened.
    pub state: WorkqueueState,
    /// Owner generation observed by the work item.
    pub owner_generation: u64,
}

/// A no-work-after-teardown violation in an explored schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownViolation {
    /// Schedule prefix that reached the violation.
    pub schedule: Vec<ModelAction>,
    /// Event that attempted to run after final teardown.
    pub event: ExecutionEvent,
}

/// Workqueue transition error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkqueueError {
    /// Queue is draining or torn down and no longer accepts new work.
    NotAccepting(WorkqueueState),
    /// Work operation did not carry a valid workqueue body token.
    InvalidWorkToken,
    /// No queued work is available.
    NoQueuedWork,
    /// No running work is available.
    NoRunningWork,
    /// Teardown was requested in an invalid state.
    InvalidTeardownState(WorkqueueState),
    /// Final teardown cannot complete while work is queued or running.
    InFlightWork,
    /// A stale work item from a previous owner generation was observed.
    StaleOwnerGeneration,
}

/// Deterministic model of one kernel-owned workqueue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelWorkqueueModel {
    state: WorkqueueState,
    owner: WorkqueueOwnerToken,
    next_work_id: u64,
    queued: Vec<WorkItem>,
    running: Option<WorkItem>,
    started: Vec<ExecutionEvent>,
    finished: Vec<ExecutionEvent>,
}

impl KernelWorkqueueModel {
    /// Construct a fresh accepting queue.
    #[must_use]
    pub fn new(queue_id: u64) -> Self {
        Self {
            state: WorkqueueState::Accepting,
            owner: WorkqueueOwnerToken::new(queue_id, 0),
            next_work_id: 1,
            queued: Vec::new(),
            running: None,
            started: Vec::new(),
            finished: Vec::new(),
        }
    }

    /// Current queue state.
    #[must_use]
    pub const fn state(&self) -> WorkqueueState {
        self.state
    }

    /// Current queue owner token. Final teardown invalidates this generation.
    #[must_use]
    pub const fn owner_token(&self) -> WorkqueueOwnerToken {
        self.owner
    }

    /// Number of queued work items.
    #[must_use]
    pub fn queued_len(&self) -> usize {
        self.queued.len()
    }

    /// True when a work item is running.
    #[must_use]
    pub fn has_running(&self) -> bool {
        self.running.is_some()
    }

    /// Started work events.
    #[must_use]
    pub fn started_events(&self) -> &[ExecutionEvent] {
        &self.started
    }

    /// Finished work events.
    #[must_use]
    pub fn finished_events(&self) -> &[ExecutionEvent] {
        &self.finished
    }

    /// Queue a deferred work item.
    pub fn submit(&mut self, operation: KernelOperation) -> Result<u64, WorkqueueError> {
        if self.state != WorkqueueState::Accepting {
            return Err(WorkqueueError::NotAccepting(self.state));
        }
        operation
            .validate()
            .map_err(|_| WorkqueueError::InvalidWorkToken)?;
        if !operation.context.can_run_as_workqueue_body() {
            return Err(WorkqueueError::InvalidWorkToken);
        }

        let id = self.next_work_id;
        self.next_work_id += 1;
        self.queued.push(WorkItem {
            id,
            operation,
            owner: self.owner,
        });
        Ok(id)
    }

    /// Begin teardown: new work is refused and already queued work may drain.
    pub fn begin_teardown(&mut self) -> Result<(), WorkqueueError> {
        match self.state {
            WorkqueueState::Accepting => {
                self.state = WorkqueueState::Draining;
                Ok(())
            }
            WorkqueueState::Draining | WorkqueueState::TornDown => {
                Err(WorkqueueError::InvalidTeardownState(self.state))
            }
        }
    }

    /// Start one queued work item.
    pub fn start_next(&mut self) -> Result<(), WorkqueueError> {
        if self.state == WorkqueueState::TornDown {
            return Err(WorkqueueError::NotAccepting(self.state));
        }
        if self.running.is_some() {
            return Err(WorkqueueError::InFlightWork);
        }
        if self.queued.is_empty() {
            return Err(WorkqueueError::NoQueuedWork);
        }

        let item = self.queued.remove(0);
        if item.owner.generation != self.owner.generation {
            return Err(WorkqueueError::StaleOwnerGeneration);
        }

        self.started.push(ExecutionEvent {
            work_id: item.id,
            operation: item.operation.kind,
            state: self.state,
            owner_generation: item.owner.generation,
        });
        self.running = Some(item);
        Ok(())
    }

    /// Finish the currently running work item.
    pub fn finish_running(&mut self) -> Result<(), WorkqueueError> {
        let item = self.running.take().ok_or(WorkqueueError::NoRunningWork)?;
        self.finished.push(ExecutionEvent {
            work_id: item.id,
            operation: item.operation.kind,
            state: self.state,
            owner_generation: item.owner.generation,
        });
        Ok(())
    }

    /// Complete final teardown after all queued/running work has drained.
    pub fn complete_teardown(&mut self) -> Result<(), WorkqueueError> {
        if self.state != WorkqueueState::Draining {
            return Err(WorkqueueError::InvalidTeardownState(self.state));
        }
        if !self.queued.is_empty() || self.running.is_some() {
            return Err(WorkqueueError::InFlightWork);
        }

        self.state = WorkqueueState::TornDown;
        self.owner.generation += 1;
        Ok(())
    }

    /// Return any no-work-after-teardown violations observed by this model.
    #[must_use]
    pub fn no_work_after_teardown_violations(&self) -> Vec<ExecutionEvent> {
        self.started
            .iter()
            .copied()
            .filter(|event| event.state == WorkqueueState::TornDown)
            .collect()
    }
}

impl Default for KernelWorkqueueModel {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Action alphabet for deterministic teardown race exploration.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ModelAction {
    /// Submit deferred writeback work.
    SubmitWriteback,
    /// Submit deferred flush work.
    SubmitFlush,
    /// Begin teardown.
    BeginTeardown,
    /// Start one queued work item.
    StartOne,
    /// Finish the running work item.
    FinishOne,
    /// Complete final teardown.
    CompleteTeardown,
}

impl ModelAction {
    /// Stable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SubmitWriteback => "submit-writeback",
            Self::SubmitFlush => "submit-flush",
            Self::BeginTeardown => "begin-teardown",
            Self::StartOne => "start-one",
            Self::FinishOne => "finish-one",
            Self::CompleteTeardown => "complete-teardown",
        }
    }
}

impl fmt::Display for ModelAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

const MODEL_ACTIONS: [ModelAction; 6] = [
    ModelAction::SubmitWriteback,
    ModelAction::SubmitFlush,
    ModelAction::BeginTeardown,
    ModelAction::StartOne,
    ModelAction::FinishOne,
    ModelAction::CompleteTeardown,
];

/// Summary of a bounded deterministic teardown exploration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownProofReport {
    /// Maximum explored schedule depth.
    pub max_depth: usize,
    /// Number of action prefixes explored.
    pub explored_prefixes: u64,
    /// Number of prefixes that reached final teardown.
    pub completed_teardown_prefixes: u64,
    /// Number of rejected submissions or starts after teardown began.
    pub refused_after_teardown_started: u64,
    /// Number of rejected submissions after begin-teardown or final teardown.
    pub refused_enqueue_after_teardown_started: u64,
    /// Number of rejected work starts after final teardown.
    pub refused_start_after_final_teardown: u64,
    /// Number of final-teardown attempts blocked by queued or running work.
    pub blocked_final_teardown_with_inflight_work: u64,
    /// Violations found by the proof harness.
    pub violations: Vec<TeardownViolation>,
}

impl TeardownProofReport {
    /// True when no explored schedule starts work after final teardown.
    #[must_use]
    pub fn proves_no_work_after_teardown(&self) -> bool {
        self.violations.is_empty()
            && self.completed_teardown_prefixes > 0
            && self.refused_enqueue_after_teardown_started > 0
            && self.refused_start_after_final_teardown > 0
            && self.blocked_final_teardown_with_inflight_work > 0
    }
}

/// Explore all action prefixes up to `max_depth`.
#[must_use]
pub fn prove_no_work_after_teardown(max_depth: usize) -> TeardownProofReport {
    let mut report = TeardownProofReport {
        max_depth,
        explored_prefixes: 0,
        completed_teardown_prefixes: 0,
        refused_after_teardown_started: 0,
        refused_enqueue_after_teardown_started: 0,
        refused_start_after_final_teardown: 0,
        blocked_final_teardown_with_inflight_work: 0,
        violations: Vec::new(),
    };

    explore_prefix(
        KernelWorkqueueModel::default(),
        Vec::new(),
        max_depth,
        &mut report,
    );

    report
}

fn explore_prefix(
    model: KernelWorkqueueModel,
    schedule: Vec<ModelAction>,
    remaining_depth: usize,
    report: &mut TeardownProofReport,
) {
    report.explored_prefixes += 1;
    if model.state() == WorkqueueState::TornDown {
        report.completed_teardown_prefixes += 1;
    }

    for event in model.no_work_after_teardown_violations() {
        report.violations.push(TeardownViolation {
            schedule: schedule.clone(),
            event,
        });
    }

    if remaining_depth == 0 {
        return;
    }

    for action in MODEL_ACTIONS {
        let mut next_model = model.clone();
        let result = apply_action(&mut next_model, action);
        if matches!(
            (action, result),
            (
                ModelAction::SubmitWriteback | ModelAction::SubmitFlush,
                Err(WorkqueueError::NotAccepting(
                    WorkqueueState::Draining | WorkqueueState::TornDown
                ))
            )
        ) {
            report.refused_enqueue_after_teardown_started += 1;
        }
        if matches!(
            (action, result),
            (
                ModelAction::StartOne,
                Err(WorkqueueError::NotAccepting(WorkqueueState::TornDown))
            )
        ) {
            report.refused_start_after_final_teardown += 1;
        }
        if matches!(
            (action, result),
            (
                ModelAction::CompleteTeardown,
                Err(WorkqueueError::InFlightWork)
            )
        ) {
            report.blocked_final_teardown_with_inflight_work += 1;
        }
        if matches!(
            result,
            Err(WorkqueueError::NotAccepting(
                WorkqueueState::Draining | WorkqueueState::TornDown
            ))
        ) {
            report.refused_after_teardown_started += 1;
        }

        let mut next_schedule = schedule.clone();
        next_schedule.push(action);
        explore_prefix(next_model, next_schedule, remaining_depth - 1, report);
    }
}

fn apply_action(
    model: &mut KernelWorkqueueModel,
    action: ModelAction,
) -> Result<(), WorkqueueError> {
    match action {
        ModelAction::SubmitWriteback => model
            .submit(KernelOperation::required(
                KernelOperationKind::DeferredWriteback,
            ))
            .map(|_| ()),
        ModelAction::SubmitFlush => model
            .submit(KernelOperation::required(
                KernelOperationKind::DeferredFlush,
            ))
            .map(|_| ()),
        ModelAction::BeginTeardown => model.begin_teardown(),
        ModelAction::StartOne => model.start_next(),
        ModelAction::FinishOne => model.finish_running(),
        ModelAction::CompleteTeardown => model.complete_teardown(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn kernel_env_model_operations_carry_explicit_context_tokens() {
        validate_modeled_kernel_operations().unwrap();
        validate_modeled_workqueue_handoffs().unwrap();

        let mut saw_rcu = false;
        let mut saw_page_cache = false;
        let mut saw_teardown_callback = false;
        let mut saw_drain_work = false;

        for operation in MODELED_KERNEL_OPERATIONS {
            saw_rcu |= operation.context.lifetime == LifetimeToken::RcuRead;
            saw_page_cache |= operation.context.cache != CacheBoundaryToken::None;
            saw_teardown_callback |= operation.context.teardown == TeardownToken::TeardownCallback;
            saw_drain_work |= operation.context.teardown == TeardownToken::DrainBeforeFinalTeardown;
        }

        assert!(saw_rcu);
        assert!(saw_page_cache);
        assert!(saw_teardown_callback);
        assert!(saw_drain_work);
    }

    #[test]
    fn kernel_env_model_teardown_callbacks_cannot_schedule_work() {
        for source in [
            KernelOperationKind::UmountBegin,
            KernelOperationKind::PutSuper,
        ] {
            let handoff = WorkqueueHandoff::new(
                KernelOperation::required(source),
                KernelOperation::required(KernelOperationKind::DeferredFlush),
            );

            assert_eq!(
                handoff.validate(),
                Err(WorkqueueHandoffError::SourceIsTeardownCallback)
            );
        }
    }

    #[test]
    fn kernel_env_model_dirty_folio_handoff_to_owned_sleepable_writeback_work() {
        let handoff = WorkqueueHandoff::new(
            KernelOperation::required(KernelOperationKind::DirtyFolio),
            KernelOperation::required(KernelOperationKind::DeferredWriteback),
        );

        assert_eq!(handoff.validate(), Ok(()));
    }

    #[test]
    fn kernel_env_model_rejects_callback_borrowed_workqueue_handoff() {
        let invalid_work = KernelOperation::new(
            KernelOperationKind::DeferredWriteback,
            KernelContextToken::new(
                SleepToken::Sleepable,
                LifetimeToken::CallbackBorrow,
                CacheBoundaryToken::Writeback,
                TeardownToken::DrainBeforeFinalTeardown,
            ),
        );
        let handoff = WorkqueueHandoff::new(
            KernelOperation::required(KernelOperationKind::DirtyFolio),
            invalid_work,
        );

        assert!(matches!(
            handoff.validate(),
            Err(WorkqueueHandoffError::WorkToken(_))
        ));
    }

    #[test]
    fn kernel_env_model_teardown_completion_refuses_inflight_work() {
        let mut model = KernelWorkqueueModel::new(7);
        model
            .submit(KernelOperation::required(
                KernelOperationKind::DeferredWriteback,
            ))
            .unwrap();
        model.begin_teardown().unwrap();

        assert_eq!(model.complete_teardown(), Err(WorkqueueError::InFlightWork));

        model.start_next().unwrap();
        assert_eq!(model.complete_teardown(), Err(WorkqueueError::InFlightWork));

        model.finish_running().unwrap();
        let generation_before_final = model.owner_token().generation;
        model.complete_teardown().unwrap();
        assert_eq!(model.state(), WorkqueueState::TornDown);
        assert_eq!(model.owner_token().generation, generation_before_final + 1);
        assert_eq!(
            model.submit(KernelOperation::required(
                KernelOperationKind::DeferredFlush
            )),
            Err(WorkqueueError::NotAccepting(WorkqueueState::TornDown))
        );
    }

    #[test]
    fn kernel_env_model_deterministic_teardown_proves_no_work_after_teardown() {
        let report = prove_no_work_after_teardown(KERNEL_TEARDOWN_PROOF_MAX_DEPTH);

        assert!(report.proves_no_work_after_teardown());
        assert!(report.explored_prefixes > 1);
        assert!(report.completed_teardown_prefixes > 0);
        assert!(report.refused_after_teardown_started > 0);
        assert!(report.refused_enqueue_after_teardown_started > 0);
        assert!(report.refused_start_after_final_teardown > 0);
        assert!(report.blocked_final_teardown_with_inflight_work > 0);
        assert_eq!(report.violations, vec![]);
    }

    #[test]
    fn kernel_env_model_teardown_artifact_matches_report() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../validation/artifacts/kernel/teardown-race-proof-artifact.json"
        ))
        .expect("teardown proof artifact parses as JSON");
        let report = prove_no_work_after_teardown(KERNEL_TEARDOWN_PROOF_MAX_DEPTH);

        assert_eq!(artifact["claim_id"], KERNEL_TEARDOWN_CLAIM_ID);
        assert_eq!(artifact["evidence_class"], "teardown-race-proof-artifact");
        assert_eq!(artifact["model"]["version"], KERNEL_TEARDOWN_MODEL_VERSION);
        assert_eq!(
            artifact["bounds"]["max_depth"].as_u64(),
            Some(report.max_depth as u64)
        );
        assert_eq!(
            artifact["bounds"]["explored_prefixes"].as_u64(),
            Some(report.explored_prefixes)
        );
        assert_eq!(
            artifact["proof_counters"]["completed_teardown_prefixes"].as_u64(),
            Some(report.completed_teardown_prefixes)
        );
        assert_eq!(
            artifact["proof_counters"]["refused_enqueue_after_teardown_started"].as_u64(),
            Some(report.refused_enqueue_after_teardown_started)
        );
        assert_eq!(
            artifact["proof_counters"]["refused_start_after_final_teardown"].as_u64(),
            Some(report.refused_start_after_final_teardown)
        );
        assert_eq!(
            artifact["proof_counters"]["blocked_final_teardown_with_inflight_work"].as_u64(),
            Some(report.blocked_final_teardown_with_inflight_work)
        );
        assert_eq!(artifact["verdict"]["passed"], true);
        assert_eq!(
            artifact["verdict"]["violation_count"].as_u64(),
            Some(report.violations.len() as u64)
        );

        let action_count = artifact["bounds"]["action_alphabet"]
            .as_array()
            .expect("artifact action alphabet is an array")
            .len();
        assert_eq!(action_count, MODEL_ACTIONS.len());

        let operation_count = artifact["covered_operation_classes"]
            .as_array()
            .expect("artifact operation class list is an array")
            .len();
        assert_eq!(operation_count, MODELED_KERNEL_OPERATIONS.len());

        let handoff_count = artifact["covered_workqueue_handoffs"]
            .as_array()
            .expect("artifact handoff list is an array")
            .len();
        assert_eq!(handoff_count, MODELED_WORKQUEUE_HANDOFFS.len());

        assert_eq!(
            artifact["runtime_boundary"],
            "source model only; not mounted runtime evidence"
        );
    }
}
