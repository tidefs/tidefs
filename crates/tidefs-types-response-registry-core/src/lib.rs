#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` `response_registry` response-envelope core types.
//!
//! This is the narrow Wave Zero shape required to terminate one admitted or refused
//! control-plane write in a lawful visible-answer record and to bind the first
//! recall-facing response indexes and archive-recall bindings around the `truth_view` seam.

use core::convert::TryFrom;
use tidefs_types_control_plane_core::{
    ControlPlaneDigest32, ControlPlaneJournalId, ControlPlaneReceiptId, ControlPlaneRequestId,
    ControlPlaneRouteClass,
};

pub const RESPONSE_REGISTRY_REFUSAL_CLASS_NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseRegistryRecordDecodeError {
    InvalidRouteClass(u32),
    InvalidIndexClass(u32),
    InvalidRetentionClass(u32),
    InvalidDisclosureClass(u32),
    InvalidAnswerKind(u32),
    InvalidRefusalClass(u32),
    InvalidScopeClass(u32),
    InvalidCutClass(u32),
    InvalidRenderClass(u32),
}

fn decode_route_class(
    value: u32,
) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
    ControlPlaneRouteClass::try_from(value)
        .map_err(|_| ResponseRegistryRecordDecodeError::InvalidRouteClass(value))
}

fn decode_index_class(
    value: u32,
) -> Result<ResponseRegistryIndexClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryIndexClass::try_from(value)
}

fn decode_retention_class(
    value: u32,
) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRetentionClass::try_from(value)
}

fn decode_disclosure_class(
    value: u32,
) -> Result<ResponseRegistryDisclosureClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryDisclosureClass::try_from(value)
}

fn decode_answer_kind(
    value: u32,
) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
    ResponseRegistryAnswerKind::try_from(value)
}

fn decode_refusal_class(
    value: u32,
) -> Result<ResponseRegistryRefusalClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRefusalClass::try_from(value)
}

fn decode_scope_class(
    value: u32,
) -> Result<ResponseRegistryScopeClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryScopeClass::try_from(value)
}

fn decode_cut_class(
    value: u32,
) -> Result<ResponseRegistryCutClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryCutClass::try_from(value)
}

fn decode_render_class(
    value: u32,
) -> Result<ResponseRegistryRenderClass, ResponseRegistryRecordDecodeError> {
    ResponseRegistryRenderClass::try_from(value)
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryScopeClass {
    CharterRead = 0,
    CharterMutation = 1,
    ControlWrite = 2,
    ControlRead = 3,
    RunbookStage = 4,
    TruthOrRecall = 5,
    ShadowOrGate = 6,
    TestOrCampaign = 7,
}

impl ResponseRegistryScopeClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CharterRead => "scope.response_registry.charter.read.s0",
            Self::CharterMutation => "scope.response_registry.charter.mutation.s1",
            Self::ControlWrite => "scope.response_registry.control.write.s2",
            Self::ControlRead => "scope.response_registry.control.read.s3",
            Self::RunbookStage => "scope.response_registry.runbook.stage.s4",
            Self::TruthOrRecall => "scope.response_registry.truth_or_recall.s5",
            Self::ShadowOrGate => "scope.response_registry.shadow_or_gate.s6",
            Self::TestOrCampaign => "scope.response_registry.test_or_campaign.s7",
        }
    }
}

impl Default for ResponseRegistryScopeClass {
    fn default() -> Self {
        Self::CharterRead
    }
}

impl TryFrom<u32> for ResponseRegistryScopeClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CharterRead),
            1 => Ok(Self::CharterMutation),
            2 => Ok(Self::ControlWrite),
            3 => Ok(Self::ControlRead),
            4 => Ok(Self::RunbookStage),
            5 => Ok(Self::TruthOrRecall),
            6 => Ok(Self::ShadowOrGate),
            7 => Ok(Self::TestOrCampaign),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidScopeClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryCutClass {
    CommittedAuthority = 0,
    ReadAnchorExact = 1,
    ReadAnchorDegraded = 2,
    StopOrRefusal = 3,
    RecallArchive = 4,
}

impl ResponseRegistryCutClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommittedAuthority => "cut.response_registry.committed_authority.c0",
            Self::ReadAnchorExact => "cut.response_registry.read_anchor_exact.c1",
            Self::ReadAnchorDegraded => "cut.response_registry.read_anchor_degraded.c2",
            Self::StopOrRefusal => "cut.response_registry.stop_or_refusal.c3",
            Self::RecallArchive => "cut.response_registry.recall_archive.c4",
        }
    }
}

impl Default for ResponseRegistryCutClass {
    fn default() -> Self {
        Self::CommittedAuthority
    }
}

impl TryFrom<u32> for ResponseRegistryCutClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::CommittedAuthority),
            1 => Ok(Self::ReadAnchorExact),
            2 => Ok(Self::ReadAnchorDegraded),
            3 => Ok(Self::StopOrRefusal),
            4 => Ok(Self::RecallArchive),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidCutClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRenderClass {
    PosixFilesystemAdapterWire = 0,
    BlockVolumeAdapterCompletion = 1,
    ControlPlaneJsonRpc = 2,
    ExplanationQueryFieldset = 3,
    TruthViewBundle = 4,
    ValidationPreservationRecall = 5,
    TestCampaignReport = 6,
    RefusalOnly = 7,
}

impl ResponseRegistryRenderClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PosixFilesystemAdapterWire => {
                "render.response_registry.posix_filesystem_adapter_wire.r0"
            }
            Self::BlockVolumeAdapterCompletion => {
                "render.response_registry.block_volume_adapter_completion.r1"
            }
            Self::ControlPlaneJsonRpc => "render.response_registry.control_plane_json_rpc.r2",
            Self::ExplanationQueryFieldset => {
                "render.response_registry.explanation_query_fieldset.r3"
            }
            Self::TruthViewBundle => "render.response_registry.truth_view_bundle.r4",
            Self::ValidationPreservationRecall => {
                "render.response_registry.validation_output_recall.r5"
            }
            Self::TestCampaignReport => "render.response_registry.test_campaign_report.r6",
            Self::RefusalOnly => "render.response_registry.refusal_only.r7",
        }
    }
}

impl Default for ResponseRegistryRenderClass {
    fn default() -> Self {
        Self::ControlPlaneJsonRpc
    }
}

impl TryFrom<u32> for ResponseRegistryRenderClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PosixFilesystemAdapterWire),
            1 => Ok(Self::BlockVolumeAdapterCompletion),
            2 => Ok(Self::ControlPlaneJsonRpc),
            3 => Ok(Self::ExplanationQueryFieldset),
            4 => Ok(Self::TruthViewBundle),
            5 => Ok(Self::ValidationPreservationRecall),
            6 => Ok(Self::TestCampaignReport),
            7 => Ok(Self::RefusalOnly),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRenderClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryAnswerKind {
    Bundle = 0,
    Refusal = 1,
}

impl ResponseRegistryAnswerKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "answer.response_registry.bundle.k0",
            Self::Refusal => "answer.response_registry.refusal.k1",
        }
    }
}

impl Default for ResponseRegistryAnswerKind {
    fn default() -> Self {
        Self::Bundle
    }
}

impl TryFrom<u32> for ResponseRegistryAnswerKind {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bundle),
            1 => Ok(Self::Refusal),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidAnswerKind(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRefusalClass {
    AuthOrPolicy = 0,
    ReserveOrBudget = 1,
    PreparedNotPublished = 2,
    StaleOrDegradedNotAdmitted = 3,
    UnsupportedCutOrSurface = 4,
    StopTicketOrHazard = 5,
    DeliveryOrRecallBlocked = 6,
}

impl ResponseRegistryRefusalClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthOrPolicy => "refusal.response_registry.auth_or_policy.f0",
            Self::ReserveOrBudget => "refusal.response_registry.reserve_or_budget.f1",
            Self::PreparedNotPublished => "refusal.response_registry.prepared_not_published.f2",
            Self::StaleOrDegradedNotAdmitted => {
                "refusal.response_registry.stale_or_degraded_not_admitted.f3"
            }
            Self::UnsupportedCutOrSurface => {
                "refusal.response_registry.unsupported_cut_or_surface.f4"
            }
            Self::StopTicketOrHazard => "refusal.response_registry.stop_ticket_or_hazard.f5",
            Self::DeliveryOrRecallBlocked => {
                "refusal.response_registry.delivery_or_recall_blocked.f6"
            }
        }
    }
}

impl Default for ResponseRegistryRefusalClass {
    fn default() -> Self {
        Self::AuthOrPolicy
    }
}

impl TryFrom<u32> for ResponseRegistryRefusalClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::AuthOrPolicy),
            1 => Ok(Self::ReserveOrBudget),
            2 => Ok(Self::PreparedNotPublished),
            3 => Ok(Self::StaleOrDegradedNotAdmitted),
            4 => Ok(Self::UnsupportedCutOrSurface),
            5 => Ok(Self::StopTicketOrHazard),
            6 => Ok(Self::DeliveryOrRecallBlocked),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRefusalClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryRetentionClass {
    Ephemeral = 0,
    IndexedHot = 1,
    RecallableArchive = 2,
    StopHold = 3,
}

impl ResponseRegistryRetentionClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "retain.response_registry.ephemeral.r0",
            Self::IndexedHot => "retain.response_registry.indexed_hot.r1",
            Self::RecallableArchive => "retain.response_registry.recallable_archive.r2",
            Self::StopHold => "retain.response_registry.stop_hold.r3",
        }
    }
}

impl Default for ResponseRegistryRetentionClass {
    fn default() -> Self {
        Self::Ephemeral
    }
}

impl TryFrom<u32> for ResponseRegistryRetentionClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ephemeral),
            1 => Ok(Self::IndexedHot),
            2 => Ok(Self::RecallableArchive),
            3 => Ok(Self::StopHold),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidRetentionClass(
                value,
            )),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryIndexClass {
    RequestOrIdempotency = 0,
    SubjectAnchor = 1,
    ResponseReceipt = 2,
    RouteStage = 3,
    ArtifactLocator = 4,
}

impl ResponseRegistryIndexClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequestOrIdempotency => "index.response_registry.request_or_idempotency.i0",
            Self::SubjectAnchor => "index.response_registry.subject_anchor.i1",
            Self::ResponseReceipt => "index.response_registry.response_receipt.i2",
            Self::RouteStage => "index.response_registry.route_stage.i3",
            Self::ArtifactLocator => "index.response_registry.artifact_locator.i4",
        }
    }
}

impl Default for ResponseRegistryIndexClass {
    fn default() -> Self {
        Self::RequestOrIdempotency
    }
}

impl TryFrom<u32> for ResponseRegistryIndexClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::RequestOrIdempotency),
            1 => Ok(Self::SubjectAnchor),
            2 => Ok(Self::ResponseReceipt),
            3 => Ok(Self::RouteStage),
            4 => Ok(Self::ArtifactLocator),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidIndexClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ResponseRegistryDisclosureClass {
    MachineCanonical = 0,
    OperatorSummary = 1,
    ArchiveReader = 2,
}

impl ResponseRegistryDisclosureClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MachineCanonical => "disclosure.response_registry.machine_canonical.d0",
            Self::OperatorSummary => "disclosure.response_registry.operator_summary.d1",
            Self::ArchiveReader => "disclosure.response_registry.archive_reader.d2",
        }
    }
}

impl Default for ResponseRegistryDisclosureClass {
    fn default() -> Self {
        Self::OperatorSummary
    }
}

impl TryFrom<u32> for ResponseRegistryDisclosureClass {
    type Error = ResponseRegistryRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::MachineCanonical),
            1 => Ok(Self::OperatorSummary),
            2 => Ok(Self::ArchiveReader),
            _ => Err(ResponseRegistryRecordDecodeError::InvalidDisclosureClass(
                value,
            )),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseRegistryResponseIndexEntryRecord {
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id_or_zero: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub _reserved0: u32,
    pub index_key_digest: ControlPlaneDigest32,
    pub lineage_digest: ControlPlaneDigest32,
    pub superseded_by_id_or_zero: ControlPlaneReceiptId,
}

impl ResponseRegistryResponseIndexEntryRecord {
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn index_class(
        self,
    ) -> Result<ResponseRegistryIndexClass, ResponseRegistryRecordDecodeError> {
        decode_index_class(self.index_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn retention(
        self,
    ) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
        decode_retention_class(self.retention_class)
    }

    #[must_use]
    pub const fn has_bundle_receipt(&self) -> bool {
        !self.bundle_receipt_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }

    #[must_use]
    pub const fn has_supersession(&self) -> bool {
        !self.superseded_by_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseRegistryResponseRecallBindingRecord {
    pub binding_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub hold_receipt_id: ControlPlaneReceiptId,
    pub recall_receipt_id: ControlPlaneReceiptId,
    pub disposition_receipt_id: ControlPlaneReceiptId,
    pub route_class: u32,
    pub truth_view_surface_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub refusal_class_or_none: u32,
    pub _reserved0: u32,
    pub archive_locator_digest: ControlPlaneDigest32,
    pub binding_digest: ControlPlaneDigest32,
}

impl ResponseRegistryResponseRecallBindingRecord {
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ResponseRegistryRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn disclosure(
        self,
    ) -> Result<ResponseRegistryDisclosureClass, ResponseRegistryRecordDecodeError> {
        decode_disclosure_class(self.disclosure_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn answer_kind(
        self,
    ) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
        decode_answer_kind(self.answer_kind)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<ResponseRegistryRefusalClass>, ResponseRegistryRecordDecodeError> {
        if self.refusal_class_or_none == RESPONSE_REGISTRY_REFUSAL_CLASS_NONE {
            Ok(None)
        } else {
            decode_refusal_class(self.refusal_class_or_none).map(Some)
        }
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseRegistryVisibleAnswerRecord {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: u32,
    pub cut_class: u32,
    pub render_class: u32,
    pub answer_kind: u32,
    pub retention_class: u32,
    pub refusal_class_or_none: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl Default for ResponseRegistryVisibleAnswerRecord {
    fn default() -> Self {
        Self {
            receipt_id: ControlPlaneReceiptId::ZERO,
            request_id: ControlPlaneRequestId::ZERO,
            journal_id: ControlPlaneJournalId::ZERO,
            scope_class: ResponseRegistryScopeClass::ControlWrite.as_u32(),
            cut_class: ResponseRegistryCutClass::CommittedAuthority.as_u32(),
            render_class: ResponseRegistryRenderClass::ControlPlaneJsonRpc.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Bundle.as_u32(),
            retention_class: ResponseRegistryRetentionClass::IndexedHot.as_u32(),
            refusal_class_or_none: RESPONSE_REGISTRY_REFUSAL_CLASS_NONE,
            _reserved0: 0,
            answer_digest: [0_u8; 32],
            artifact_locator_digest: [0_u8; 32],
        }
    }
}

/// Parameter shape for `ResponseRegistryVisibleAnswerRecord::bundle`.
pub struct VisibleAnswerBundleParams {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: ResponseRegistryScopeClass,
    pub cut_class: ResponseRegistryCutClass,
    pub render_class: ResponseRegistryRenderClass,
    pub retention_class: ResponseRegistryRetentionClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

/// Parameter shape for `ResponseRegistryVisibleAnswerRecord::refusal`.
pub struct VisibleAnswerRefusalParams {
    pub receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub scope_class: ResponseRegistryScopeClass,
    pub cut_class: ResponseRegistryCutClass,
    pub render_class: ResponseRegistryRenderClass,
    pub retention_class: ResponseRegistryRetentionClass,
    pub refusal_class: ResponseRegistryRefusalClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl ResponseRegistryVisibleAnswerRecord {
    #[must_use]
    pub const fn bundle(params: VisibleAnswerBundleParams) -> Self {
        Self {
            receipt_id: params.receipt_id,
            request_id: params.request_id,
            journal_id: params.journal_id,
            scope_class: params.scope_class.as_u32(),
            cut_class: params.cut_class.as_u32(),
            render_class: params.render_class.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Bundle.as_u32(),
            retention_class: params.retention_class.as_u32(),
            refusal_class_or_none: RESPONSE_REGISTRY_REFUSAL_CLASS_NONE,
            _reserved0: 0,
            answer_digest: params.answer_digest,
            artifact_locator_digest: params.artifact_locator_digest,
        }
    }

    #[must_use]
    pub const fn refusal(params: VisibleAnswerRefusalParams) -> Self {
        Self {
            receipt_id: params.receipt_id,
            request_id: params.request_id,
            journal_id: params.journal_id,
            scope_class: params.scope_class.as_u32(),
            cut_class: params.cut_class.as_u32(),
            render_class: params.render_class.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Refusal.as_u32(),
            retention_class: params.retention_class.as_u32(),
            refusal_class_or_none: params.refusal_class.as_u32(),
            _reserved0: 0,
            answer_digest: params.answer_digest,
            artifact_locator_digest: params.artifact_locator_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn scope(self) -> Result<ResponseRegistryScopeClass, ResponseRegistryRecordDecodeError> {
        decode_scope_class(self.scope_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn cut(self) -> Result<ResponseRegistryCutClass, ResponseRegistryRecordDecodeError> {
        decode_cut_class(self.cut_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn render(self) -> Result<ResponseRegistryRenderClass, ResponseRegistryRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn answer_kind(
        self,
    ) -> Result<ResponseRegistryAnswerKind, ResponseRegistryRecordDecodeError> {
        decode_answer_kind(self.answer_kind)
    }

    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn retention(
        self,
    ) -> Result<ResponseRegistryRetentionClass, ResponseRegistryRecordDecodeError> {
        decode_retention_class(self.retention_class)
    }
    /// # Errors
    ///
    /// Returns [`ResponseRegistryRecordDecodeError`] on failure.
    pub fn refusal_class(
        self,
    ) -> Result<Option<ResponseRegistryRefusalClass>, ResponseRegistryRecordDecodeError> {
        if self.refusal_class_or_none == RESPONSE_REGISTRY_REFUSAL_CLASS_NONE {
            Ok(None)
        } else {
            decode_refusal_class(self.refusal_class_or_none).map(Some)
        }
    }
}

const _: [(); 176] = [(); core::mem::size_of::<ResponseRegistryResponseIndexEntryRecord>()];
const _: [(); 200] = [(); core::mem::size_of::<ResponseRegistryResponseRecallBindingRecord>()];
const _: [(); 140] = [(); core::mem::size_of::<ResponseRegistryVisibleAnswerRecord>()];

// TURN3_HUMAN_RESPONSE_REGISTRY_ALIASES
/// Human-named module for the Response Registry family.
pub mod response_registry {
    pub const FAMILY_NAME: &str = "Response Registry";
    pub const STABLE_SOURCE_LOCATOR: &str = "response_registry";
    pub const ROLE: &str = "visible answers, response indexes, and recall bindings";

    pub use super::{
        ResponseRegistryAnswerKind as AnswerKind, ResponseRegistryCutClass as CutClass,
        ResponseRegistryDisclosureClass as DisclosureClass,
        ResponseRegistryIndexClass as IndexClass, ResponseRegistryRefusalClass as RefusalClass,
        ResponseRegistryRenderClass as RenderClass,
        ResponseRegistryResponseIndexEntryRecord as ResponseIndexEntryRecord,
        ResponseRegistryResponseRecallBindingRecord as ResponseRecallBindingRecord,
        ResponseRegistryRetentionClass as RetentionClass, ResponseRegistryScopeClass as ScopeClass,
        ResponseRegistryVisibleAnswerRecord as VisibleAnswerRecord,
    };

    pub const REFUSAL_CLASS_NONE: u32 = super::RESPONSE_REGISTRY_REFUSAL_CLASS_NONE;
}

/// Human alias namespace. Prefer `human::response_registry::*` in new examples.
pub mod human {
    pub mod response_registry {
        pub use crate::response_registry::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_has_no_refusal_class() {
        let record = ResponseRegistryVisibleAnswerRecord::bundle(VisibleAnswerBundleParams {
            receipt_id: ControlPlaneReceiptId::from_u128_le(0x11),
            request_id: ControlPlaneRequestId::from_u128_le(0x22),
            journal_id: ControlPlaneJournalId::from_u128_le(0x33),
            scope_class: ResponseRegistryScopeClass::ControlWrite,
            cut_class: ResponseRegistryCutClass::CommittedAuthority,
            render_class: ResponseRegistryRenderClass::ControlPlaneJsonRpc,
            retention_class: ResponseRegistryRetentionClass::IndexedHot,
            answer_digest: [0xAA_u8; 32],
            artifact_locator_digest: [0xBB_u8; 32],
        });
        assert_eq!(record.answer_kind(), Ok(ResponseRegistryAnswerKind::Bundle));
        assert_eq!(record.refusal_class(), Ok(None));
    }

    #[test]
    fn refusal_record_round_trips_class_and_render() {
        let record = ResponseRegistryVisibleAnswerRecord::refusal(VisibleAnswerRefusalParams {
            receipt_id: ControlPlaneReceiptId::from_u128_le(0x11),
            request_id: ControlPlaneRequestId::from_u128_le(0x22),
            journal_id: ControlPlaneJournalId::from_u128_le(0x33),
            scope_class: ResponseRegistryScopeClass::ControlWrite,
            cut_class: ResponseRegistryCutClass::StopOrRefusal,
            render_class: ResponseRegistryRenderClass::RefusalOnly,
            retention_class: ResponseRegistryRetentionClass::StopHold,
            refusal_class: ResponseRegistryRefusalClass::ReserveOrBudget,
            answer_digest: [0xCC_u8; 32],
            artifact_locator_digest: [0xDD_u8; 32],
        });
        assert_eq!(
            record.answer_kind(),
            Ok(ResponseRegistryAnswerKind::Refusal)
        );
        assert_eq!(
            record.render(),
            Ok(ResponseRegistryRenderClass::RefusalOnly)
        );
        assert_eq!(
            record.refusal_class(),
            Ok(Some(ResponseRegistryRefusalClass::ReserveOrBudget))
        );
    }

    #[test]
    fn index_entry_tracks_terminal_and_supersession_sentinels() {
        let record = ResponseRegistryResponseIndexEntryRecord {
            index_entry_id: ControlPlaneReceiptId::from_u128_le(0x41),
            response_receipt_id: ControlPlaneReceiptId::from_u128_le(0x42),
            bundle_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x43),
            terminal_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x44),
            journal_id: ControlPlaneJournalId::from_u128_le(0x45),
            route_class: ControlPlaneRouteClass::Recall.as_u32(),
            index_class: ResponseRegistryIndexClass::ArtifactLocator.as_u32(),
            retention_class: ResponseRegistryRetentionClass::RecallableArchive.as_u32(),
            _reserved0: 0,
            index_key_digest: [0x51_u8; 32],
            lineage_digest: [0x52_u8; 32],
            superseded_by_id_or_zero: ControlPlaneReceiptId::ZERO,
        };
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Recall));
        assert_eq!(
            record.index_class(),
            Ok(ResponseRegistryIndexClass::ArtifactLocator)
        );
        assert_eq!(
            record.retention(),
            Ok(ResponseRegistryRetentionClass::RecallableArchive)
        );
        assert!(record.has_bundle_receipt());
        assert!(record.has_terminal_receipt());
        assert!(!record.has_supersession());
    }

    #[test]
    fn recall_binding_preserves_disclosure_and_refusal_shape() {
        let binding = ResponseRegistryResponseRecallBindingRecord {
            binding_id: ControlPlaneReceiptId::from_u128_le(0x61),
            response_receipt_id: ControlPlaneReceiptId::from_u128_le(0x62),
            bundle_receipt_id: ControlPlaneReceiptId::from_u128_le(0x63),
            terminal_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x64),
            hold_receipt_id: ControlPlaneReceiptId::from_u128_le(0x65),
            recall_receipt_id: ControlPlaneReceiptId::from_u128_le(0x66),
            disposition_receipt_id: ControlPlaneReceiptId::from_u128_le(0x67),
            route_class: ControlPlaneRouteClass::TruthSurface.as_u32(),
            truth_view_surface_class: 4,
            disclosure_class: ResponseRegistryDisclosureClass::ArchiveReader.as_u32(),
            answer_kind: ResponseRegistryAnswerKind::Refusal.as_u32(),
            refusal_class_or_none: ResponseRegistryRefusalClass::DeliveryOrRecallBlocked.as_u32(),
            _reserved0: 0,
            archive_locator_digest: [0x71_u8; 32],
            binding_digest: [0x72_u8; 32],
        };
        assert_eq!(binding.route(), Ok(ControlPlaneRouteClass::TruthSurface));
        assert_eq!(
            binding.disclosure(),
            Ok(ResponseRegistryDisclosureClass::ArchiveReader)
        );
        assert_eq!(
            binding.answer_kind(),
            Ok(ResponseRegistryAnswerKind::Refusal)
        );
        assert_eq!(
            binding.refusal_class(),
            Ok(Some(ResponseRegistryRefusalClass::DeliveryOrRecallBlocked))
        );
        assert!(binding.has_terminal_receipt());
    }

    #[test]
    fn record_accessors_report_invalid_numeric_classes() {
        let index = ResponseRegistryResponseIndexEntryRecord {
            route_class: 91,
            index_class: 92,
            retention_class: 93,
            ..Default::default()
        };
        assert_eq!(
            index.route(),
            Err(ResponseRegistryRecordDecodeError::InvalidRouteClass(91))
        );
        assert_eq!(
            index.index_class(),
            Err(ResponseRegistryRecordDecodeError::InvalidIndexClass(92))
        );
        assert_eq!(
            index.retention(),
            Err(ResponseRegistryRecordDecodeError::InvalidRetentionClass(93))
        );

        let binding = ResponseRegistryResponseRecallBindingRecord {
            route_class: 94,
            disclosure_class: 95,
            answer_kind: 96,
            refusal_class_or_none: 97,
            ..Default::default()
        };
        assert_eq!(
            binding.route(),
            Err(ResponseRegistryRecordDecodeError::InvalidRouteClass(94))
        );
        assert_eq!(
            binding.disclosure(),
            Err(ResponseRegistryRecordDecodeError::InvalidDisclosureClass(
                95
            ))
        );
        assert_eq!(
            binding.answer_kind(),
            Err(ResponseRegistryRecordDecodeError::InvalidAnswerKind(96))
        );
        assert_eq!(
            binding.refusal_class(),
            Err(ResponseRegistryRecordDecodeError::InvalidRefusalClass(97))
        );

        let visible = ResponseRegistryVisibleAnswerRecord {
            scope_class: 98,
            cut_class: 99,
            render_class: 100,
            answer_kind: 101,
            retention_class: 102,
            refusal_class_or_none: 103,
            ..Default::default()
        };
        assert_eq!(
            visible.scope(),
            Err(ResponseRegistryRecordDecodeError::InvalidScopeClass(98))
        );
        assert_eq!(
            visible.cut(),
            Err(ResponseRegistryRecordDecodeError::InvalidCutClass(99))
        );
        assert_eq!(
            visible.render(),
            Err(ResponseRegistryRecordDecodeError::InvalidRenderClass(100))
        );
        assert_eq!(
            visible.answer_kind(),
            Err(ResponseRegistryRecordDecodeError::InvalidAnswerKind(101))
        );
        assert_eq!(
            visible.retention(),
            Err(ResponseRegistryRecordDecodeError::InvalidRetentionClass(
                102
            ))
        );
        assert_eq!(
            visible.refusal_class(),
            Err(ResponseRegistryRecordDecodeError::InvalidRefusalClass(103))
        );
    }

    #[test]
    fn index_entry_record_all_fields_set_and_accessors_work() {
        let record = ResponseRegistryResponseIndexEntryRecord {
            index_entry_id: ControlPlaneReceiptId::from_u128_le(0xAAA),
            response_receipt_id: ControlPlaneReceiptId::from_u128_le(0xBBB),
            bundle_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0xCCC),
            terminal_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0xDDD),
            journal_id: ControlPlaneJournalId::from_u128_le(0xEEE),
            route_class: ControlPlaneRouteClass::Write.as_u32(),
            index_class: ResponseRegistryIndexClass::ArtifactLocator.as_u32(),
            retention_class: ResponseRegistryRetentionClass::IndexedHot.as_u32(),
            _reserved0: 0,
            index_key_digest: [0x11_u8; 32],
            lineage_digest: [0x22_u8; 32],
            superseded_by_id_or_zero: ControlPlaneReceiptId::from_u128_le(0xFFF),
        };
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Write));
        assert_eq!(
            record.index_class(),
            Ok(ResponseRegistryIndexClass::ArtifactLocator)
        );
        assert_eq!(
            record.retention(),
            Ok(ResponseRegistryRetentionClass::IndexedHot)
        );
        assert!(record.has_bundle_receipt());
        assert!(record.has_terminal_receipt());
        assert!(record.has_supersession());
        assert_eq!(record.index_key_digest, [0x11_u8; 32]);
        assert_eq!(record.lineage_digest, [0x22_u8; 32]);
        assert_eq!(record.index_entry_id.as_u128_le(), 0xAAA);
        assert_eq!(record.response_receipt_id.as_u128_le(), 0xBBB);
        assert_eq!(record.journal_id.as_u128_le(), 0xEEE);
    }

    #[test]
    fn scope_class_round_trips() {
        for v in [0_u32, 1, 2] {
            let parsed = ResponseRegistryScopeClass::try_from(v).unwrap();
            assert_eq!(parsed.as_u32(), v);
        }
    }
    #[test]
    fn cut_class_round_trips() {
        for v in [0_u32, 1, 2, 3] {
            let parsed = ResponseRegistryCutClass::try_from(v).unwrap();
            assert_eq!(parsed.as_u32(), v);
        }
    }
    #[test]
    fn answer_kind_round_trips() {
        for v in [0_u32, 1] {
            let parsed = ResponseRegistryAnswerKind::try_from(v).unwrap();
            assert_eq!(parsed.as_u32(), v);
        }
    }
    #[test]
    fn default_index_entry_has_none_sentinels() {
        let rec = ResponseRegistryResponseIndexEntryRecord::default();
        assert_eq!(rec.index_entry_id, ControlPlaneReceiptId::ZERO);
        assert_eq!(rec.response_receipt_id, ControlPlaneReceiptId::ZERO);
        assert!(!rec.has_bundle_receipt());
        assert!(!rec.has_terminal_receipt());
        assert!(!rec.has_supersession());
    }
    #[test]
    fn index_entry_with_non_zero_ids_has_all_sentinels() {
        let rec = ResponseRegistryResponseIndexEntryRecord {
            index_entry_id: ControlPlaneReceiptId::from_u128_le(0x11),
            response_receipt_id: ControlPlaneReceiptId::from_u128_le(0x22),
            bundle_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x33),
            terminal_receipt_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x44),
            journal_id: ControlPlaneJournalId::from_u128_le(0x55),
            route_class: ControlPlaneRouteClass::Write.as_u32(),
            index_class: ResponseRegistryIndexClass::ArtifactLocator.as_u32(),
            retention_class: ResponseRegistryRetentionClass::IndexedHot.as_u32(),
            _reserved0: 0,
            index_key_digest: [0xAA_u8; 32],
            lineage_digest: [0xBB_u8; 32],
            superseded_by_id_or_zero: ControlPlaneReceiptId::from_u128_le(0x66),
        };
        assert!(rec.has_bundle_receipt());
        assert!(rec.has_terminal_receipt());
        assert!(rec.has_supersession());
        assert_eq!(rec.route(), Ok(ControlPlaneRouteClass::Write));
        assert_eq!(
            rec.index_class(),
            Ok(ResponseRegistryIndexClass::ArtifactLocator)
        );
        assert_eq!(
            rec.retention(),
            Ok(ResponseRegistryRetentionClass::IndexedHot)
        );
        assert_eq!(rec.index_key_digest, [0xAA_u8; 32]);
        assert_eq!(rec.lineage_digest, [0xBB_u8; 32]);
    }
}
