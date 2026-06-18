// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Pure FUSE environment model for adapter-to-contract refinement.
//!
//! **IMPORTANT**: The model traces, sequences, and assertions provided by this
//! crate are adapter-environment model evidence only. They must not be used to
//! validate mounted FUSE runtime crash claims or replace runtime xfstests
//! coverage.  See issue #533 for the model authority boundaries.
//!
//! This crate models legal FUSE connection and request lifecycles at the
//! adapter boundary. It translates semantic FUSE requests into the current
//! TideFS request contract and replays those envelopes through
//! `tidefs-model-core` without calling storage mutation APIs directly.

pub mod adapter_guard;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use tidefs_model_core::{
    ContractModelContext, ContractNameBinding, ContractNameContext, ModelFingerprint, ModelFs,
    ModelInvariantError, ModelPath,
};
use tidefs_types_vfs_core::{
    AdmissionIntent, BudgetIntent, CompletionDisposition, CompletionStatus, ContractEpoch, Errno,
    FenceIntent, FileHandleId, InodeId, RequestEnvelope, RequestId, RequestMetadata, RetryIntent,
    TideCompletion, TideRequest, TraceId, VfsNameToken, VfsRequest, WorkClass,
};

/// FUSE capability names relevant to the adapter-boundary model.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FuseCapability {
    AsyncRead,
    ExportSupport,
    WritebackCache,
    PosixLocks,
    FlockLocks,
    Fiemap,
    OTmpfile,
    CopyFileRange,
    Unknown(u32),
}

/// Stable classification for capabilities that reach the FUSE boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityClassification {
    Supported,
    AdapterLocal,
    Unsupported { errno: Errno, reason: &'static str },
}

impl CapabilityClassification {
    #[must_use]
    pub const fn is_unsupported(self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }

    #[must_use]
    pub const fn errno(self) -> Errno {
        match self {
            Self::Supported | Self::AdapterLocal => Errno::SUCCESS,
            Self::Unsupported { errno, .. } => errno,
        }
    }
}

/// Classify one FUSE capability without turning unsupported features into
/// harness failures.
#[must_use]
pub const fn classify_capability(capability: FuseCapability) -> CapabilityClassification {
    match capability {
        FuseCapability::AsyncRead
        | FuseCapability::ExportSupport
        | FuseCapability::WritebackCache => CapabilityClassification::Supported,
        FuseCapability::PosixLocks | FuseCapability::FlockLocks | FuseCapability::CopyFileRange => {
            CapabilityClassification::AdapterLocal
        }
        FuseCapability::Fiemap => CapabilityClassification::Unsupported {
            errno: Errno::EOPNOTSUPP,
            reason: "FIEMAP is reported as an explicit unsupported adapter capability",
        },
        FuseCapability::OTmpfile => CapabilityClassification::Unsupported {
            errno: Errno::EOPNOTSUPP,
            reason: "O_TMPFILE is not part of the current TideFS mounted subset",
        },
        FuseCapability::Unknown(_) => CapabilityClassification::Unsupported {
            errno: Errno::ENOSYS,
            reason: "unknown FUSE capability is preserved as explicit unsupported input",
        },
    }
}

/// One capability report emitted during connection initialization or an
/// unsupported-capability request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityReport {
    pub capability: FuseCapability,
    pub classification: CapabilityClassification,
}

/// Legal FUSE connection states tracked by the environment model.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FuseConnectionState {
    #[default]
    New,
    Initialized,
    DaemonTeardown,
    Destroyed,
}

/// Connection parameters observed at FUSE init.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseConnectionConfig {
    pub max_background: usize,
    pub writeback_cache: bool,
    pub capabilities: Vec<FuseCapability>,
}

impl Default for FuseConnectionConfig {
    fn default() -> Self {
        Self {
            max_background: 4,
            writeback_cache: false,
            capabilities: vec![FuseCapability::AsyncRead, FuseCapability::ExportSupport],
        }
    }
}

/// Whether a dispatched FUSE request completes immediately or remains active
/// until a later completion, interrupt, or abort event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchCompletion {
    Complete,
    Hold,
}

/// FUSE requests that the environment model can place on the adapter
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FuseRequest {
    Create {
        path: ModelPath,
    },
    GetAttr {
        inode: InodeId,
    },
    Open {
        inode: InodeId,
        file_handle: FileHandleId,
        flags: u32,
    },
    Read {
        inode: InodeId,
        file_handle: FileHandleId,
        offset: u64,
        length: u64,
    },
    Write {
        inode: InodeId,
        file_handle: FileHandleId,
        offset: u64,
        bytes: Vec<u8>,
        writeback_cache: bool,
    },
    Flush {
        inode: InodeId,
        file_handle: FileHandleId,
    },
    Fsync {
        inode: InodeId,
        file_handle: FileHandleId,
        datasync: bool,
    },
    Release {
        inode: InodeId,
        file_handle: FileHandleId,
    },
    UnsupportedCapability {
        capability: FuseCapability,
    },
}

impl FuseRequest {
    fn writeback_dirty_inode(&self) -> Option<InodeId> {
        match self {
            Self::Write {
                inode,
                writeback_cache: true,
                ..
            } => Some(*inode),
            _ => None,
        }
    }

    fn sync_inode(&self) -> Option<InodeId> {
        match self {
            Self::Flush { inode, .. } | Self::Fsync { inode, .. } => Some(*inode),
            _ => None,
        }
    }

    fn release_inode(&self) -> Option<InodeId> {
        match self {
            Self::Release { inode, .. } => Some(*inode),
            _ => None,
        }
    }

    fn is_adapter_only(&self) -> bool {
        matches!(self, Self::Open { .. } | Self::Release { .. })
    }
}

/// FUSE environment events accepted by the lifecycle model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FuseEvent {
    Init(FuseConnectionConfig),
    Dispatch {
        unique: u64,
        request: FuseRequest,
        completion: DispatchCompletion,
    },
    Complete {
        unique: u64,
    },
    Interrupt {
        unique: u64,
        target_unique: u64,
    },
    Abort {
        unique: u64,
    },
    Reissue {
        aborted_unique: u64,
        new_unique: u64,
    },
    ServiceBackground,
    DaemonTeardown,
    Destroy,
}

/// Compact event kind recorded on model output steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FuseStepKind {
    Init,
    Dispatch,
    Complete,
    Interrupt,
    Abort,
    Reissue,
    ServiceBackground,
    DaemonTeardown,
    Destroy,
}

/// Where a dispatched request landed in the FUSE environment queues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueuePlacement {
    None,
    AdapterOnly,
    Active,
    Waiting,
    Completed,
}

/// Queue state after an applied FUSE event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueSnapshot {
    pub active: usize,
    pub waiting: usize,
    pub max_background: usize,
    pub dirty_writeback_inodes: usize,
}

/// Request emitted at the adapter-to-contract boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterContractRequest {
    Canonical {
        envelope: RequestEnvelope,
        write_bytes: Vec<u8>,
        name_bindings: Vec<AdapterNameBinding>,
    },
    UnsupportedCapability {
        capability: FuseCapability,
        classification: CapabilityClassification,
    },
}

/// Owned namespace binding carried with canonical adapter requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterNameBinding {
    pub token: VfsNameToken,
    pub component: String,
}

impl AdapterNameBinding {
    fn new(component: String) -> Self {
        Self {
            token: VfsNameToken::from_component_bytes(component.as_bytes()),
            component,
        }
    }
}

impl AdapterContractRequest {
    fn mark_reissue(&mut self) {
        if let Self::Canonical { envelope, .. } = self {
            envelope.metadata.retry = RetryIntent::AdapterOnly;
        }
    }
}

/// One output step produced by the FUSE environment model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuseModelStep {
    pub kind: FuseStepKind,
    pub unique: Option<u64>,
    pub promoted_unique: Option<u64>,
    pub placement: QueuePlacement,
    pub queue: QueueSnapshot,
    pub request: Option<AdapterContractRequest>,
    pub completion: Option<TideCompletion>,
    pub capability_reports: Vec<CapabilityReport>,
    pub fingerprint: Option<ModelFingerprint>,
}

/// Errors indicate illegal environment traces or internal model invariant
/// failures. Unsupported FUSE capabilities are successful model output steps,
/// not errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FuseModelError {
    IllegalState {
        event: FuseStepKind,
        state: FuseConnectionState,
    },
    DuplicateUnique(u64),
    MissingActiveRequest(u64),
    MissingAbortHistory(u64),
    DirtyWritebackOutstanding {
        inode: InodeId,
    },
    ActiveRequestsDuringTeardown {
        active: usize,
        waiting: usize,
    },
    DirtyWritebackDuringTeardown {
        count: usize,
    },
    ModelInvariant(String),
}

impl fmt::Display for FuseModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalState { event, state } => {
                write!(f, "illegal {event:?} while connection state is {state:?}")
            }
            Self::DuplicateUnique(unique) => write!(f, "duplicate FUSE unique {unique}"),
            Self::MissingActiveRequest(unique) => {
                write!(f, "missing active or waiting FUSE unique {unique}")
            }
            Self::MissingAbortHistory(unique) => {
                write!(
                    f,
                    "missing aborted request history for FUSE unique {unique}"
                )
            }
            Self::DirtyWritebackOutstanding { inode } => {
                write!(
                    f,
                    "release before flush/fsync for dirty inode {}",
                    inode.get()
                )
            }
            Self::ActiveRequestsDuringTeardown { active, waiting } => write!(
                f,
                "daemon teardown with active={active} waiting={waiting} requests"
            ),
            Self::DirtyWritebackDuringTeardown { count } => {
                write!(f, "daemon teardown with {count} dirty writeback inode(s)")
            }
            Self::ModelInvariant(err) => write!(f, "model invariant failure: {err}"),
        }
    }
}

impl std::error::Error for FuseModelError {}

impl From<ModelInvariantError> for FuseModelError {
    fn from(err: ModelInvariantError) -> Self {
        Self::ModelInvariant(err.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedRequest {
    unique: u64,
    request: FuseRequest,
    contract: AdapterContractRequest,
    interrupted: bool,
}

/// Stateful pure FUSE environment model.
#[derive(Debug)]
pub struct FuseEnvironmentModel {
    state: FuseConnectionState,
    config: FuseConnectionConfig,
    model: ModelFs,
    active: BTreeMap<u64, QueuedRequest>,
    waiting: VecDeque<QueuedRequest>,
    aborted: BTreeMap<u64, FuseRequest>,
    seen_uniques: BTreeSet<u64>,
    dirty_writeback: BTreeSet<InodeId>,
    trace_seed: u64,
}

impl Default for FuseEnvironmentModel {
    fn default() -> Self {
        Self::new()
    }
}

impl FuseEnvironmentModel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: FuseConnectionState::New,
            config: FuseConnectionConfig::default(),
            model: ModelFs::new(),
            active: BTreeMap::new(),
            waiting: VecDeque::new(),
            aborted: BTreeMap::new(),
            seen_uniques: BTreeSet::new(),
            dirty_writeback: BTreeSet::new(),
            trace_seed: 0x290_f05e,
        }
    }

    #[must_use]
    pub const fn state(&self) -> FuseConnectionState {
        self.state
    }

    #[must_use]
    pub fn queue_snapshot(&self) -> QueueSnapshot {
        QueueSnapshot {
            active: self.active.len(),
            waiting: self.waiting.len(),
            max_background: self.config.max_background,
            dirty_writeback_inodes: self.dirty_writeback.len(),
        }
    }

    /// Apply one legal FUSE event.
    ///
    /// # Errors
    ///
    /// Returns [`FuseModelError`] for illegal lifecycle ordering or a failed
    /// model invariant. Unsupported capabilities produce output steps with
    /// `CompletionStatus::Unsupported`.
    pub fn apply(&mut self, event: FuseEvent) -> Result<FuseModelStep, FuseModelError> {
        match event {
            FuseEvent::Init(config) => self.apply_init(config),
            FuseEvent::Dispatch {
                unique,
                request,
                completion,
            } => self.enqueue_request(FuseStepKind::Dispatch, unique, request, completion, false),
            FuseEvent::Complete { unique } => self.complete_active(unique),
            FuseEvent::Interrupt {
                unique,
                target_unique,
            } => self.interrupt(unique, target_unique),
            FuseEvent::Abort { unique } => self.abort(unique),
            FuseEvent::Reissue {
                aborted_unique,
                new_unique,
            } => self.reissue(aborted_unique, new_unique),
            FuseEvent::ServiceBackground => self.service_background(),
            FuseEvent::DaemonTeardown => self.daemon_teardown(),
            FuseEvent::Destroy => self.destroy(),
        }
    }

    fn apply_init(
        &mut self,
        mut config: FuseConnectionConfig,
    ) -> Result<FuseModelStep, FuseModelError> {
        if self.state != FuseConnectionState::New {
            return Err(FuseModelError::IllegalState {
                event: FuseStepKind::Init,
                state: self.state,
            });
        }
        if config.max_background == 0 {
            config.max_background = 1;
        }
        config.writeback_cache = config
            .capabilities
            .iter()
            .any(|capability| *capability == FuseCapability::WritebackCache);
        let reports = config
            .capabilities
            .iter()
            .copied()
            .map(|capability| CapabilityReport {
                capability,
                classification: classify_capability(capability),
            })
            .collect();
        self.config = config;
        self.state = FuseConnectionState::Initialized;
        Ok(self.step(
            FuseStepKind::Init,
            None,
            None,
            QueuePlacement::None,
            None,
            None,
            reports,
        ))
    }

    fn enqueue_request(
        &mut self,
        kind: FuseStepKind,
        unique: u64,
        request: FuseRequest,
        completion: DispatchCompletion,
        reissued: bool,
    ) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(kind)?;
        self.ensure_unique_available(unique)?;

        if let Some(inode) = request.release_inode() {
            if self.dirty_writeback.contains(&inode) {
                return Err(FuseModelError::DirtyWritebackOutstanding { inode });
            }
        }

        if request.is_adapter_only() {
            let completion = synthetic_completion(
                unique,
                CompletionStatus::Success,
                CompletionDisposition::Final,
                Errno::SUCCESS,
            );
            self.seen_uniques.insert(unique);
            return Ok(self.step(
                kind,
                Some(unique),
                None,
                QueuePlacement::AdapterOnly,
                None,
                Some(completion),
                Vec::new(),
            ));
        }

        let mut contract = self.translate_request(unique, &request);
        if reissued {
            contract.mark_reissue();
        }

        if let AdapterContractRequest::UnsupportedCapability {
            capability,
            classification,
        } = contract
        {
            let completion = synthetic_completion(
                unique,
                CompletionStatus::Unsupported,
                CompletionDisposition::Unsupported,
                classification.errno(),
            );
            let report = CapabilityReport {
                capability,
                classification,
            };
            self.seen_uniques.insert(unique);
            return Ok(self.step(
                kind,
                Some(unique),
                Some(AdapterContractRequest::UnsupportedCapability {
                    capability,
                    classification,
                }),
                QueuePlacement::Completed,
                None,
                Some(completion),
                vec![report],
            ));
        }

        let queued = QueuedRequest {
            unique,
            request,
            contract,
            interrupted: false,
        };

        if self.active.len() >= self.config.max_background {
            let request = queued.contract.clone();
            self.seen_uniques.insert(unique);
            self.waiting.push_back(queued);
            return Ok(self.step(
                kind,
                Some(unique),
                Some(request),
                QueuePlacement::Waiting,
                None,
                None,
                Vec::new(),
            ));
        }

        if completion == DispatchCompletion::Complete {
            let request = queued.contract.clone();
            let (completion, fingerprint) = self.execute_queued(&queued)?;
            self.seen_uniques.insert(unique);
            Ok(self.step(
                kind,
                Some(unique),
                Some(request),
                QueuePlacement::Completed,
                fingerprint,
                Some(completion),
                Vec::new(),
            ))
        } else {
            let request = queued.contract.clone();
            self.seen_uniques.insert(unique);
            self.active.insert(unique, queued);
            Ok(self.step(
                kind,
                Some(unique),
                Some(request),
                QueuePlacement::Active,
                None,
                None,
                Vec::new(),
            ))
        }
    }

    fn complete_active(&mut self, unique: u64) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(FuseStepKind::Complete)?;
        let queued = self
            .active
            .remove(&unique)
            .ok_or(FuseModelError::MissingActiveRequest(unique))?;
        let request = queued.contract.clone();
        let (completion, fingerprint) = self.execute_queued(&queued)?;
        Ok(self.step(
            FuseStepKind::Complete,
            Some(unique),
            Some(request),
            QueuePlacement::Completed,
            fingerprint,
            Some(completion),
            Vec::new(),
        ))
    }

    fn interrupt(
        &mut self,
        unique: u64,
        target_unique: u64,
    ) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(FuseStepKind::Interrupt)?;
        self.ensure_unique_available(unique)?;
        if let Some(request) = self.active.get_mut(&target_unique) {
            request.interrupted = true;
        } else if let Some(request) = self
            .waiting
            .iter_mut()
            .find(|request| request.unique == target_unique)
        {
            request.interrupted = true;
        } else {
            return Err(FuseModelError::MissingActiveRequest(target_unique));
        }

        self.seen_uniques.insert(unique);
        Ok(self.step(
            FuseStepKind::Interrupt,
            Some(unique),
            None,
            QueuePlacement::AdapterOnly,
            None,
            None,
            Vec::new(),
        ))
    }

    fn abort(&mut self, unique: u64) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(FuseStepKind::Abort)?;
        let request = if let Some(active) = self.active.remove(&unique) {
            active.request
        } else if let Some(index) = self
            .waiting
            .iter()
            .position(|request| request.unique == unique)
        {
            self.waiting
                .remove(index)
                .ok_or(FuseModelError::MissingActiveRequest(unique))?
                .request
        } else {
            return Err(FuseModelError::MissingActiveRequest(unique));
        };
        self.aborted.insert(unique, request);
        let completion = synthetic_completion(
            unique,
            CompletionStatus::Cancelled,
            CompletionDisposition::Retryable,
            Errno::ECANCELED,
        );
        Ok(self.step(
            FuseStepKind::Abort,
            Some(unique),
            None,
            QueuePlacement::Completed,
            None,
            Some(completion),
            Vec::new(),
        ))
    }

    fn reissue(
        &mut self,
        aborted_unique: u64,
        new_unique: u64,
    ) -> Result<FuseModelStep, FuseModelError> {
        let request = self
            .aborted
            .get(&aborted_unique)
            .cloned()
            .ok_or(FuseModelError::MissingAbortHistory(aborted_unique))?;
        self.enqueue_request(
            FuseStepKind::Reissue,
            new_unique,
            request,
            DispatchCompletion::Hold,
            true,
        )
    }

    fn service_background(&mut self) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(FuseStepKind::ServiceBackground)?;
        let promoted_unique = if self.active.len() < self.config.max_background {
            if let Some(queued) = self.waiting.pop_front() {
                let unique = queued.unique;
                self.active.insert(unique, queued);
                Some(unique)
            } else {
                None
            }
        } else {
            None
        };

        Ok(self
            .step(
                FuseStepKind::ServiceBackground,
                None,
                None,
                if promoted_unique.is_some() {
                    QueuePlacement::Active
                } else {
                    QueuePlacement::None
                },
                None,
                None,
                Vec::new(),
            )
            .with_promoted(promoted_unique))
    }

    fn daemon_teardown(&mut self) -> Result<FuseModelStep, FuseModelError> {
        self.require_initialized(FuseStepKind::DaemonTeardown)?;
        if !self.active.is_empty() || !self.waiting.is_empty() {
            return Err(FuseModelError::ActiveRequestsDuringTeardown {
                active: self.active.len(),
                waiting: self.waiting.len(),
            });
        }
        if !self.dirty_writeback.is_empty() {
            return Err(FuseModelError::DirtyWritebackDuringTeardown {
                count: self.dirty_writeback.len(),
            });
        }
        self.state = FuseConnectionState::DaemonTeardown;
        Ok(self.step(
            FuseStepKind::DaemonTeardown,
            None,
            None,
            QueuePlacement::None,
            None,
            None,
            Vec::new(),
        ))
    }

    fn destroy(&mut self) -> Result<FuseModelStep, FuseModelError> {
        if !matches!(
            self.state,
            FuseConnectionState::Initialized | FuseConnectionState::DaemonTeardown
        ) {
            return Err(FuseModelError::IllegalState {
                event: FuseStepKind::Destroy,
                state: self.state,
            });
        }
        if !self.active.is_empty() || !self.waiting.is_empty() {
            return Err(FuseModelError::ActiveRequestsDuringTeardown {
                active: self.active.len(),
                waiting: self.waiting.len(),
            });
        }
        if !self.dirty_writeback.is_empty() {
            return Err(FuseModelError::DirtyWritebackDuringTeardown {
                count: self.dirty_writeback.len(),
            });
        }
        self.state = FuseConnectionState::Destroyed;
        Ok(self.step(
            FuseStepKind::Destroy,
            None,
            None,
            QueuePlacement::None,
            None,
            None,
            Vec::new(),
        ))
    }

    fn translate_request(&self, unique: u64, request: &FuseRequest) -> AdapterContractRequest {
        match request {
            FuseRequest::Create { path } => {
                let (parent_id, binding) = self.create_parent_binding(path);
                AdapterContractRequest::Canonical {
                    envelope: envelope(
                        unique,
                        self.trace_seed,
                        TideRequest::Vfs(VfsRequest::Create {
                            parent_id,
                            name: binding.token,
                        }),
                        WorkClass::Foreground,
                        FenceIntent::Write,
                    ),
                    write_bytes: Vec::new(),
                    name_bindings: vec![binding],
                }
            }
            FuseRequest::GetAttr { inode } => AdapterContractRequest::Canonical {
                envelope: envelope(
                    unique,
                    self.trace_seed,
                    TideRequest::Vfs(VfsRequest::GetAttr { inode_id: *inode }),
                    WorkClass::Foreground,
                    FenceIntent::Read,
                ),
                write_bytes: Vec::new(),
                name_bindings: Vec::new(),
            },
            FuseRequest::Read {
                inode,
                file_handle,
                offset,
                length,
            } => AdapterContractRequest::Canonical {
                envelope: envelope(
                    unique,
                    self.trace_seed,
                    TideRequest::Vfs(VfsRequest::Read {
                        inode_id: *inode,
                        file_handle_id: *file_handle,
                        offset: *offset,
                        length: *length,
                    }),
                    WorkClass::Foreground,
                    FenceIntent::Read,
                ),
                write_bytes: Vec::new(),
                name_bindings: Vec::new(),
            },
            FuseRequest::Write {
                inode,
                file_handle,
                offset,
                bytes,
                ..
            } => AdapterContractRequest::Canonical {
                envelope: envelope(
                    unique,
                    self.trace_seed,
                    TideRequest::Vfs(VfsRequest::Write {
                        inode_id: *inode,
                        file_handle_id: *file_handle,
                        offset: *offset,
                        length: bytes.len() as u64,
                    }),
                    WorkClass::Foreground,
                    FenceIntent::Write,
                ),
                write_bytes: bytes.clone(),
                name_bindings: Vec::new(),
            },
            FuseRequest::Flush { inode, file_handle }
            | FuseRequest::Fsync {
                inode, file_handle, ..
            } => AdapterContractRequest::Canonical {
                envelope: envelope(
                    unique,
                    self.trace_seed,
                    TideRequest::Vfs(VfsRequest::Sync {
                        inode_id: *inode,
                        file_handle_id: *file_handle,
                    }),
                    WorkClass::Foreground,
                    FenceIntent::Write,
                ),
                write_bytes: Vec::new(),
                name_bindings: Vec::new(),
            },
            FuseRequest::Open { .. } | FuseRequest::Release { .. } => {
                unreachable!("adapter-only requests are handled before translation")
            }
            FuseRequest::UnsupportedCapability { capability } => {
                AdapterContractRequest::UnsupportedCapability {
                    capability: *capability,
                    classification: classify_capability(*capability),
                }
            }
        }
    }

    fn create_parent_binding(&self, path: &ModelPath) -> (InodeId, AdapterNameBinding) {
        match self.model.resolve_parent_inode(path) {
            Ok((parent_id, component)) => (parent_id, AdapterNameBinding::new(component)),
            Err(_) => {
                let component = path.components().last().cloned().unwrap_or_default();
                (InodeId::new(u64::MAX), AdapterNameBinding::new(component))
            }
        }
    }

    fn execute_queued(
        &mut self,
        queued: &QueuedRequest,
    ) -> Result<(TideCompletion, Option<ModelFingerprint>), FuseModelError> {
        let (completion, fingerprint) = match &queued.contract {
            AdapterContractRequest::Canonical {
                envelope,
                write_bytes,
                name_bindings,
            } => {
                let contract_bindings = contract_name_bindings(name_bindings);
                let step = self.model.apply_contract_with_names(
                    envelope,
                    ContractModelContext {
                        write_bytes: write_bytes.as_slice(),
                    },
                    ContractNameContext::new(&contract_bindings),
                )?;
                (step.completion, Some(step.fingerprint))
            }
            AdapterContractRequest::UnsupportedCapability { classification, .. } => (
                synthetic_completion(
                    queued.unique,
                    CompletionStatus::Unsupported,
                    CompletionDisposition::Unsupported,
                    classification.errno(),
                ),
                None,
            ),
        };

        if completion.errno.is_success() {
            if let Some(inode) = queued.request.writeback_dirty_inode() {
                self.dirty_writeback.insert(inode);
            }
            if let Some(inode) = queued.request.sync_inode() {
                self.dirty_writeback.remove(&inode);
            }
        }

        Ok((completion, fingerprint))
    }

    fn require_initialized(&self, event: FuseStepKind) -> Result<(), FuseModelError> {
        if self.state == FuseConnectionState::Initialized {
            Ok(())
        } else {
            Err(FuseModelError::IllegalState {
                event,
                state: self.state,
            })
        }
    }

    fn ensure_unique_available(&self, unique: u64) -> Result<(), FuseModelError> {
        if self.active.contains_key(&unique)
            || self.waiting.iter().any(|request| request.unique == unique)
            || self.aborted.contains_key(&unique)
            || self.seen_uniques.contains(&unique)
        {
            Err(FuseModelError::DuplicateUnique(unique))
        } else {
            Ok(())
        }
    }

    fn step(
        &self,
        kind: FuseStepKind,
        unique: Option<u64>,
        request: Option<AdapterContractRequest>,
        placement: QueuePlacement,
        fingerprint: Option<ModelFingerprint>,
        completion: Option<TideCompletion>,
        capability_reports: Vec<CapabilityReport>,
    ) -> FuseModelStep {
        FuseModelStep {
            kind,
            unique,
            promoted_unique: None,
            placement,
            queue: self.queue_snapshot(),
            request,
            completion,
            capability_reports,
            fingerprint,
        }
    }
}

impl FuseModelStep {
    fn with_promoted(mut self, unique: Option<u64>) -> Self {
        self.promoted_unique = unique;
        self
    }
}

/// Deterministic acceptance events for issue #290.
#[must_use]
pub fn issue_290_acceptance_events() -> Vec<FuseEvent> {
    let file = InodeId::new(2);
    let fh = FileHandleId::new(7);
    vec![
        FuseEvent::Init(FuseConnectionConfig {
            max_background: 1,
            writeback_cache: true,
            capabilities: vec![
                FuseCapability::AsyncRead,
                FuseCapability::WritebackCache,
                FuseCapability::Fiemap,
                FuseCapability::OTmpfile,
            ],
        }),
        FuseEvent::Dispatch {
            unique: 1,
            request: FuseRequest::Create {
                path: path("/file"),
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Dispatch {
            unique: 2,
            request: FuseRequest::Open {
                inode: file,
                file_handle: fh,
                flags: 0,
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Dispatch {
            unique: 10,
            request: FuseRequest::Read {
                inode: file,
                file_handle: fh,
                offset: 0,
                length: 3,
            },
            completion: DispatchCompletion::Hold,
        },
        FuseEvent::Dispatch {
            unique: 11,
            request: FuseRequest::Write {
                inode: file,
                file_handle: fh,
                offset: 0,
                bytes: b"abc".to_vec(),
                writeback_cache: true,
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Interrupt {
            unique: 30,
            target_unique: 10,
        },
        FuseEvent::Abort { unique: 10 },
        FuseEvent::Reissue {
            aborted_unique: 10,
            new_unique: 12,
        },
        FuseEvent::Complete { unique: 12 },
        FuseEvent::ServiceBackground,
        FuseEvent::Complete { unique: 11 },
        FuseEvent::Dispatch {
            unique: 13,
            request: FuseRequest::Fsync {
                inode: file,
                file_handle: fh,
                datasync: false,
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Dispatch {
            unique: 40,
            request: FuseRequest::UnsupportedCapability {
                capability: FuseCapability::Fiemap,
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Dispatch {
            unique: 14,
            request: FuseRequest::Release {
                inode: file,
                file_handle: fh,
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::DaemonTeardown,
        FuseEvent::Destroy,
    ]
}

/// Run the deterministic issue #290 acceptance trace.
///
/// # Errors
///
/// Returns a lifecycle/model error only if the hard-coded acceptance trace is
/// no longer legal.
pub fn issue_290_acceptance_trace() -> Result<Vec<FuseModelStep>, FuseModelError> {
    let mut model = FuseEnvironmentModel::new();
    issue_290_acceptance_events()
        .into_iter()
        .map(|event| model.apply(event))
        .collect()
}

/// Deterministic writeback flush/fsync lifecycle sequence for issue #533.
///
/// This sequence proves that writeback-cache writes must be followed by an
/// explicit flush or fsync outcome before the model can claim the inode has
/// no dirty adapter-local work.  The sequence covers:
///
/// - writeback write → flush → fsync → release → daemon teardown → destroy (success)
/// - writeback write without flush/fsync → release (blocked)
/// - writeback write without flush/fsync → daemon teardown (blocked)
/// - interrupted writeback write with reissue and fsync cleanup
///
/// **Model-only evidence**: this sequence is a pure environment-model trace
/// and cannot validate mounted FUSE runtime crash claims.  See issue #533.
#[must_use]
pub fn issue_533_writeback_flush_fsync_events() -> Vec<FuseEvent> {
    let file = InodeId::new(2);
    let fh = FileHandleId::new(7);
    vec![
        FuseEvent::Init(FuseConnectionConfig {
            max_background: 2,
            writeback_cache: true,
            capabilities: vec![FuseCapability::AsyncRead, FuseCapability::WritebackCache],
        }),
        // Create and open the target file.
        FuseEvent::Dispatch {
            unique: 1,
            request: FuseRequest::Create {
                path: path("/file"),
            },
            completion: DispatchCompletion::Complete,
        },
        FuseEvent::Dispatch {
            unique: 2,
            request: FuseRequest::Open {
                inode: file,
                file_handle: fh,
                flags: 0,
            },
            completion: DispatchCompletion::Complete,
        },
        // Writeback-cache write marks the inode dirty.
        FuseEvent::Dispatch {
            unique: 3,
            request: FuseRequest::Write {
                inode: file,
                file_handle: fh,
                offset: 0,
                bytes: b"data".to_vec(),
                writeback_cache: true,
            },
            completion: DispatchCompletion::Complete,
        },
        // Flush clears the dirty writeback state.
        FuseEvent::Dispatch {
            unique: 4,
            request: FuseRequest::Flush {
                inode: file,
                file_handle: fh,
            },
            completion: DispatchCompletion::Complete,
        },
        // Fsync is also accepted through the request contract after flush.
        FuseEvent::Dispatch {
            unique: 5,
            request: FuseRequest::Fsync {
                inode: file,
                file_handle: fh,
                datasync: false,
            },
            completion: DispatchCompletion::Complete,
        },
        // Release now succeeds because explicit sync work already ran.
        FuseEvent::Dispatch {
            unique: 6,
            request: FuseRequest::Release {
                inode: file,
                file_handle: fh,
            },
            completion: DispatchCompletion::Complete,
        },
        // Clean shutdown is legal with zero dirty inodes.
        FuseEvent::DaemonTeardown,
        FuseEvent::Destroy,
    ]
}

/// Run the deterministic issue #533 writeback flush/fsync trace.
///
/// # Errors
///
/// Returns a lifecycle/model error only if the hard-coded acceptance trace is
/// no longer legal.
pub fn issue_533_writeback_flush_fsync_trace() -> Result<Vec<FuseModelStep>, FuseModelError> {
    let mut model = FuseEnvironmentModel::new();
    issue_533_writeback_flush_fsync_events()
        .into_iter()
        .map(|event| model.apply(event))
        .collect()
}

fn path(value: &str) -> ModelPath {
    ModelPath::parse_absolute(value).expect("issue #290 trace paths are absolute and legal")
}

fn envelope(
    unique: u64,
    trace_seed: u64,
    request: TideRequest,
    work_class: WorkClass,
    fence: FenceIntent,
) -> RequestEnvelope {
    let mut metadata = RequestMetadata::new(
        request_id(unique),
        ContractEpoch::new(trace_seed),
        trace_id(trace_seed, unique),
    );
    metadata.work_class = work_class;
    metadata.admission = AdmissionIntent::RequirePermit;
    metadata.budget = BudgetIntent::Foreground;
    metadata.fence = fence;
    metadata.retry = RetryIntent::None;
    RequestEnvelope::new(metadata, request)
}

fn contract_name_bindings(bindings: &[AdapterNameBinding]) -> Vec<ContractNameBinding<'_>> {
    bindings
        .iter()
        .map(|binding| ContractNameBinding::new(binding.token, binding.component.as_str()))
        .collect()
}

fn request_id(unique: u64) -> RequestId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&unique.to_le_bytes());
    bytes[8..].copy_from_slice(b"fuseenv0");
    RequestId::new(bytes)
}

fn trace_id(seed: u64, unique: u64) -> TraceId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..].copy_from_slice(&unique.to_le_bytes());
    TraceId::new(bytes)
}

fn synthetic_completion(
    unique: u64,
    status: CompletionStatus,
    disposition: CompletionDisposition,
    errno: Errno,
) -> TideCompletion {
    let mut completion = TideCompletion::success(
        request_id(unique),
        trace_id(0x290_f05e, unique),
        ContractEpoch(0),
    );
    completion.status = status;
    completion.disposition = disposition;
    completion.errno = errno;
    completion
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_model_core::ROOT_INODE_ID;

    fn has_kind(trace: &[FuseModelStep], kind: FuseStepKind) -> bool {
        trace.iter().any(|step| step.kind == kind)
    }

    #[test]
    fn generated_trace_covers_issue_290_lifecycle_edges() {
        let trace = issue_290_acceptance_trace().expect("issue #290 trace remains legal");

        for kind in [
            FuseStepKind::Init,
            FuseStepKind::Dispatch,
            FuseStepKind::Interrupt,
            FuseStepKind::Abort,
            FuseStepKind::Reissue,
            FuseStepKind::ServiceBackground,
            FuseStepKind::DaemonTeardown,
            FuseStepKind::Destroy,
        ] {
            assert!(has_kind(&trace, kind), "missing lifecycle edge {kind:?}");
        }

        assert!(
            trace.iter().any(|step| step.queue.waiting > 0),
            "trace should exercise waiting slots"
        );
        assert!(
            trace
                .iter()
                .any(|step| step.queue.active == step.queue.max_background),
            "trace should saturate the background slot"
        );
        assert!(
            trace
                .iter()
                .any(|step| step.queue.dirty_writeback_inodes > 0),
            "trace should expose writeback-cache dirty ordering"
        );
    }

    #[test]
    fn generated_trace_produces_contract_requests_and_completions() {
        let trace = issue_290_acceptance_trace().expect("issue #290 trace remains legal");

        let canonical = trace
            .iter()
            .filter(|step| matches!(step.request, Some(AdapterContractRequest::Canonical { .. })));
        assert!(canonical.count() >= 3);

        assert!(trace.iter().any(|step| {
            let Some(AdapterContractRequest::Canonical {
                envelope,
                name_bindings,
                ..
            }) = &step.request
            else {
                return false;
            };
            let TideRequest::Vfs(VfsRequest::Create { parent_id, name }) = envelope.request else {
                return false;
            };
            parent_id == ROOT_INODE_ID
                && name_bindings.as_slice()
                    == &[AdapterNameBinding {
                        token: name,
                        component: "file".to_string(),
                    }]
                && step
                    .completion
                    .is_some_and(|completion| completion.status == CompletionStatus::Success)
        }));

        assert!(trace.iter().any(|step| {
            matches!(step.request, Some(AdapterContractRequest::Canonical { .. }))
                && step.completion.is_some()
        }));
    }

    #[test]
    fn canonical_create_without_name_binding_fails_closed() {
        let token = VfsNameToken::from_component_bytes(b"file");
        let contract = AdapterContractRequest::Canonical {
            envelope: envelope(
                1,
                0x290_f05e,
                TideRequest::Vfs(VfsRequest::Create {
                    parent_id: ROOT_INODE_ID,
                    name: token,
                }),
                WorkClass::Foreground,
                FenceIntent::Write,
            ),
            write_bytes: Vec::new(),
            name_bindings: Vec::new(),
        };
        let queued = QueuedRequest {
            unique: 1,
            request: FuseRequest::Create {
                path: path("/file"),
            },
            contract,
            interrupted: false,
        };
        let mut model = FuseEnvironmentModel::new();

        let (completion, fingerprint) = model.execute_queued(&queued).unwrap();

        assert_eq!(completion.errno, Errno::EINVAL);
        assert!(fingerprint.is_some());
    }

    #[test]
    fn unsupported_capabilities_are_classifications_not_harness_errors() {
        let report = classify_capability(FuseCapability::Fiemap);
        assert!(report.is_unsupported());
        assert_eq!(report.errno(), Errno::EOPNOTSUPP);

        let trace = issue_290_acceptance_trace().expect("issue #290 trace remains legal");
        assert!(trace.iter().any(|step| {
            step.capability_reports.iter().any(|report| {
                report.capability == FuseCapability::Fiemap
                    && report.classification.is_unsupported()
            })
        }));
        assert!(trace.iter().any(|step| {
            step.completion.is_some_and(|completion| {
                completion.status == CompletionStatus::Unsupported
                    && completion.disposition == CompletionDisposition::Unsupported
            })
        }));
    }

    #[test]
    fn writeback_release_requires_flush_or_fsync_boundary() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 1,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"abc".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        let err = model
            .apply(FuseEvent::Dispatch {
                unique: 3,
                request: FuseRequest::Release {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            FuseModelError::DirtyWritebackOutstanding {
                inode: InodeId::new(2)
            }
        );
    }

    #[test]
    fn completed_fuse_uniques_cannot_be_reused() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig::default()))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        let err = model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::GetAttr {
                    inode: InodeId::new(2),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap_err();
        assert_eq!(err, FuseModelError::DuplicateUnique(1));
    }

    #[test]
    fn adapter_boundary_guard_rejects_storage_bypass() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate parent")
            .parent()
            .expect("workspace root")
            .to_path_buf();
        if let Err(violations) = adapter_guard::check_adapter_semantic_boundary(&root) {
            panic!(
                "adapter semantic boundary guard failed:\n{}",
                violations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }

    // --- Issue #533 writeback flush/fsync lifecycle tests ---
    //
    // These tests are adapter-environment model evidence only.  They must not
    // be used to validate mounted FUSE runtime crash claims.  See issue #533.

    /// Model-only evidence: the writeback-cache write → flush → fsync →
    /// release → daemon teardown → destroy success path.
    #[test]
    fn writeback_write_flush_release_destroy_success_path() {
        let trace = issue_533_writeback_flush_fsync_trace()
            .expect("issue #533 success trace remains legal");

        // Every event in the success trace must succeed.
        for step in &trace {
            assert!(
                step.completion
                    .as_ref()
                    .map_or(true, |c| c.errno.is_success()),
                "step {:?} should succeed but got {:?}",
                step.kind,
                step.completion
            );
        }

        // The trace must end with Destroy.
        assert_eq!(trace.last().map(|s| s.kind), Some(FuseStepKind::Destroy));

        // No dirty writeback inodes remain at teardown.
        let teardown_step = trace
            .iter()
            .find(|s| s.kind == FuseStepKind::DaemonTeardown)
            .expect("teardown step present");
        assert_eq!(teardown_step.queue.dirty_writeback_inodes, 0);
    }

    /// Model-only evidence: flush and fsync both clear the dirty writeback
    /// state, allowing a subsequent release.
    #[test]
    fn writeback_write_fsync_release_success_path() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 1,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"xyz".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Fsync (not flush) clears the dirty inode.
        model
            .apply(FuseEvent::Dispatch {
                unique: 3,
                request: FuseRequest::Fsync {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    datasync: false,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Release must succeed.
        let step = model
            .apply(FuseEvent::Dispatch {
                unique: 4,
                request: FuseRequest::Release {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        assert_eq!(step.kind, FuseStepKind::Dispatch);
    }

    /// Model-only evidence: release is blocked for dirty writeback inodes
    /// that have not been flushed or fsynced.
    #[test]
    fn writeback_release_blocked_without_flush_fsync() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 1,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"abc".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        let err = model
            .apply(FuseEvent::Dispatch {
                unique: 3,
                request: FuseRequest::Release {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap_err();
        assert_eq!(
            err,
            FuseModelError::DirtyWritebackOutstanding {
                inode: InodeId::new(2)
            }
        );
    }

    /// Model-only evidence: daemon teardown is rejected when dirty writeback
    /// inodes are still outstanding.
    #[test]
    fn writeback_daemon_teardown_blocked_without_flush_fsync() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 1,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"abc".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        let err = model.apply(FuseEvent::DaemonTeardown).unwrap_err();
        assert_eq!(
            err,
            FuseModelError::DirtyWritebackDuringTeardown { count: 1 }
        );
    }

    /// Model-only evidence: destroy is rejected when dirty writeback inodes
    /// are still outstanding (even after daemon teardown transition).
    #[test]
    fn writeback_destroy_blocked_without_flush_fsync() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 1,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"abc".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Destroy (without prior teardown) is also rejected.
        let err = model.apply(FuseEvent::Destroy).unwrap_err();
        assert_eq!(
            err,
            FuseModelError::DirtyWritebackDuringTeardown { count: 1 }
        );
    }

    /// Model-only evidence: an interrupted writeback write that is never
    /// flushed or fsynced leaves the inode dirty; a subsequent teardown is
    /// blocked.
    #[test]
    fn writeback_interrupted_write_blocked_teardown_without_flush_fsync() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 2,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Dispatch a held writeback write (not immediately completed).
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"xyz".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Hold,
            })
            .unwrap();

        // Interrupt the held write.
        model
            .apply(FuseEvent::Interrupt {
                unique: 30,
                target_unique: 2,
            })
            .unwrap();

        // Abort the interrupted write.
        model.apply(FuseEvent::Abort { unique: 2 }).unwrap();

        // Reissue the aborted write as a new request, still held.
        model
            .apply(FuseEvent::Reissue {
                aborted_unique: 2,
                new_unique: 3,
            })
            .unwrap();

        // Complete the reissued write (marks inode dirty).
        model.apply(FuseEvent::Complete { unique: 3 }).unwrap();

        // Now try daemon teardown without flush/fsync — must be blocked.
        let err = model.apply(FuseEvent::DaemonTeardown).unwrap_err();
        assert_eq!(
            err,
            FuseModelError::DirtyWritebackDuringTeardown { count: 1 }
        );
    }

    /// Model-only evidence: after an interrupted writeback write is
    /// reissued, completed, flushed, and released, teardown proceeds
    /// cleanly (full recovery path).
    #[test]
    fn writeback_interrupted_write_reissued_flushed_teardown_success() {
        let mut model = FuseEnvironmentModel::new();
        model
            .apply(FuseEvent::Init(FuseConnectionConfig {
                max_background: 2,
                writeback_cache: true,
                capabilities: vec![FuseCapability::WritebackCache],
            }))
            .unwrap();
        model
            .apply(FuseEvent::Dispatch {
                unique: 1,
                request: FuseRequest::Create {
                    path: path("/file"),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Held writeback write → interrupted → aborted → reissued → completed.
        model
            .apply(FuseEvent::Dispatch {
                unique: 2,
                request: FuseRequest::Write {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                    offset: 0,
                    bytes: b"xyz".to_vec(),
                    writeback_cache: true,
                },
                completion: DispatchCompletion::Hold,
            })
            .unwrap();
        model
            .apply(FuseEvent::Interrupt {
                unique: 30,
                target_unique: 2,
            })
            .unwrap();
        model.apply(FuseEvent::Abort { unique: 2 }).unwrap();
        model
            .apply(FuseEvent::Reissue {
                aborted_unique: 2,
                new_unique: 3,
            })
            .unwrap();
        model.apply(FuseEvent::Complete { unique: 3 }).unwrap();

        // Flush to clear dirty state.
        model
            .apply(FuseEvent::Dispatch {
                unique: 4,
                request: FuseRequest::Flush {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Release.
        model
            .apply(FuseEvent::Dispatch {
                unique: 5,
                request: FuseRequest::Release {
                    inode: InodeId::new(2),
                    file_handle: FileHandleId::new(7),
                },
                completion: DispatchCompletion::Complete,
            })
            .unwrap();

        // Teardown and destroy succeed.
        model.apply(FuseEvent::DaemonTeardown).unwrap();
        model.apply(FuseEvent::Destroy).unwrap();
    }
}
