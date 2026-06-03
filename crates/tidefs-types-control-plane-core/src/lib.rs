#![no_std]
#![forbid(unsafe_code)]

//! Portable `no_std` `control_plane` scalar/newtype/fixed-width core types.
//!
//! This crate owns the fixed-width control-plane shapes that need a stable home
//! beneath `schema_codec` codecs and above family-specific API/runtime helpers.

use core::convert::TryFrom;

/// Control plane component classes per P9-01 g0-g10 taxonomy.
/// Each component class represents a distinct architectural responsibility within
/// the control plane's internal processing graph.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneComponentClass {
    PolicyAdmission = 0,
    TruthView = 1,
    ExplanationQuery = 2,
    SecretLeaseBroker = 3,
    PublicationGateway = 4,
    PlacementController = 5,
    MembershipController = 6,
    TransportController = 7,
    HealthMonitor = 8,
    RecallArchive = 9,
    CutoverCoordinator = 10,
}

impl ControlPlaneComponentClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAdmission => "component.control_plane.policy_admission.g0",
            Self::TruthView => "component.control_plane.truth_view.g1",
            Self::ExplanationQuery => "component.control_plane.explanation_query.g2",
            Self::SecretLeaseBroker => "component.control_plane.secret_lease_broker.g3",
            Self::PublicationGateway => "component.control_plane.publication_gateway.g4",
            Self::PlacementController => "component.control_plane.placement_controller.g5",
            Self::MembershipController => "component.control_plane.membership_controller.g6",
            Self::TransportController => "component.control_plane.transport_controller.g7",
            Self::HealthMonitor => "component.control_plane.health_monitor.g8",
            Self::RecallArchive => "component.control_plane.recall_archive.g9",
            Self::CutoverCoordinator => "component.control_plane.cutover_coordinator.g10",
        }
    }
}

impl Default for ControlPlaneComponentClass {
    fn default() -> Self {
        Self::PolicyAdmission
    }
}

impl TryFrom<u32> for ControlPlaneComponentClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PolicyAdmission),
            1 => Ok(Self::TruthView),
            2 => Ok(Self::ExplanationQuery),
            3 => Ok(Self::SecretLeaseBroker),
            4 => Ok(Self::PublicationGateway),
            5 => Ok(Self::PlacementController),
            6 => Ok(Self::MembershipController),
            7 => Ok(Self::TransportController),
            8 => Ok(Self::HealthMonitor),
            9 => Ok(Self::RecallArchive),
            10 => Ok(Self::CutoverCoordinator),
            _ => Err(ControlPlaneRecordDecodeError::InvalidComponentClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneCarrierClass {
    LocalKernelUapi = 0,
    RemoteMtlsGateway = 1,
    InternalKernelStub = 2,
}

impl ControlPlaneCarrierClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalKernelUapi => "carrier.control_plane.local.kernel_uapi.c0",
            Self::RemoteMtlsGateway => "carrier.control_plane.remote.mtls_gateway.c1",
            Self::InternalKernelStub => "carrier.control_plane.internal.kernel_stub.c2",
        }
    }
}

impl Default for ControlPlaneCarrierClass {
    fn default() -> Self {
        Self::LocalKernelUapi
    }
}

impl TryFrom<u32> for ControlPlaneCarrierClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::LocalKernelUapi),
            1 => Ok(Self::RemoteMtlsGateway),
            2 => Ok(Self::InternalKernelStub),
            _ => Err(ControlPlaneRecordDecodeError::InvalidCarrierClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRouteClass {
    Session = 0,
    Write = 1,
    Runbook = 2,
    SecretControl = 3,
    TruthSurface = 4,
    Recall = 5,
    /// r6 — Admin membership: manage cluster members, join, depart, epoch transitions
    AdminMembership = 6,
    /// r7 — Admin transport: manage transport configuration, gateway connectivity, RDMA setup
    AdminTransport = 7,
}

impl ControlPlaneRouteClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "route.control_plane.session.r0",
            Self::Write => "route.control_plane.write.r1",
            Self::Runbook => "route.control_plane.runbook.r2",
            Self::SecretControl => "route.control_plane.secret_control.r3",
            Self::TruthSurface => "route.control_plane.truth_surface.r4",
            Self::Recall => "route.control_plane.recall.r5",
            Self::AdminMembership => "route.control_plane.admin_membership.r6",
            Self::AdminTransport => "route.control_plane.admin_transport.r7",
        }
    }

    /// Map route class to its primary P9-01 component class
    pub const fn primary_component_class(
        self,
    ) -> Result<ControlPlaneComponentClass, ControlPlaneRecordDecodeError> {
        match self {
            Self::Session => Ok(ControlPlaneComponentClass::HealthMonitor),
            Self::Write => Ok(ControlPlaneComponentClass::PolicyAdmission),
            Self::Runbook => Ok(ControlPlaneComponentClass::CutoverCoordinator),
            Self::SecretControl => Ok(ControlPlaneComponentClass::SecretLeaseBroker),
            Self::TruthSurface => Ok(ControlPlaneComponentClass::TruthView),
            Self::Recall => Ok(ControlPlaneComponentClass::RecallArchive),
            Self::AdminMembership => Ok(ControlPlaneComponentClass::MembershipController),
            Self::AdminTransport => Ok(ControlPlaneComponentClass::TransportController),
        }
    }
}

impl Default for ControlPlaneRouteClass {
    fn default() -> Self {
        Self::Session
    }
}

impl TryFrom<u32> for ControlPlaneRouteClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Session),
            1 => Ok(Self::Write),
            2 => Ok(Self::Runbook),
            3 => Ok(Self::SecretControl),
            4 => Ok(Self::TruthSurface),
            5 => Ok(Self::Recall),
            6 => Ok(Self::AdminMembership),
            7 => Ok(Self::AdminTransport),
            _ => Err(ControlPlaneRecordDecodeError::InvalidRouteClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRenderClass {
    Machine = 0,
    OperatorText = 1,
}

impl ControlPlaneRenderClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "render.control_plane.machine.r0",
            Self::OperatorText => "render.control_plane.operator_text.r1",
        }
    }
}

impl Default for ControlPlaneRenderClass {
    fn default() -> Self {
        Self::Machine
    }
}

impl TryFrom<u32> for ControlPlaneRenderClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Machine),
            1 => Ok(Self::OperatorText),
            _ => Err(ControlPlaneRecordDecodeError::InvalidRenderClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneVisibilityClass {
    PublicRedacted = 0,
    OperatorScoped = 1,
}

impl ControlPlaneVisibilityClass {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PublicRedacted => "visibility.control_plane.public_redacted.v0",
            Self::OperatorScoped => "visibility.control_plane.operator_scoped.v1",
        }
    }
}

impl Default for ControlPlaneVisibilityClass {
    fn default() -> Self {
        Self::PublicRedacted
    }
}

impl TryFrom<u32> for ControlPlaneVisibilityClass {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PublicRedacted),
            1 => Ok(Self::OperatorScoped),
            _ => Err(ControlPlaneRecordDecodeError::InvalidVisibilityClass(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneResponseKind {
    Bundle = 0,
    Refusal = 1,
}

impl ControlPlaneResponseKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "response.control_plane.bundle.k0",
            Self::Refusal => "response.control_plane.refusal.k1",
        }
    }
}

impl Default for ControlPlaneResponseKind {
    fn default() -> Self {
        Self::Bundle
    }
}

impl TryFrom<u32> for ControlPlaneResponseKind {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Bundle),
            1 => Ok(Self::Refusal),
            _ => Err(ControlPlaneRecordDecodeError::InvalidResponseKind(value)),
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneWriteRequestKind {
    ProductAdmissionManual = 0,
}

impl ControlPlaneWriteRequestKind {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProductAdmissionManual => "req.product_admission.manual.r0",
        }
    }
}

impl Default for ControlPlaneWriteRequestKind {
    fn default() -> Self {
        Self::ProductAdmissionManual
    }
}

impl TryFrom<u32> for ControlPlaneWriteRequestKind {
    type Error = ControlPlaneRecordDecodeError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ProductAdmissionManual),
            _ => Err(ControlPlaneRecordDecodeError::InvalidWriteRequestKind(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlPlaneRecordDecodeError {
    InvalidCarrierClass(u32),
    InvalidRouteClass(u32),
    InvalidRenderClass(u32),
    InvalidVisibilityClass(u32),
    InvalidResponseKind(u32),
    InvalidWriteRequestKind(u32),
    InvalidComponentClass(u32),
}

fn decode_carrier_class(
    value: u32,
) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
    ControlPlaneCarrierClass::try_from(value)
}

fn decode_route_class(value: u32) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
    ControlPlaneRouteClass::try_from(value)
}

fn decode_render_class(
    value: u32,
) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
    ControlPlaneRenderClass::try_from(value)
}

fn decode_visibility_class(
    value: u32,
) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
    ControlPlaneVisibilityClass::try_from(value)
}

fn decode_response_kind(
    value: u32,
) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
    ControlPlaneResponseKind::try_from(value)
}

fn decode_write_request_kind(
    value: u32,
) -> Result<ControlPlaneWriteRequestKind, ControlPlaneRecordDecodeError> {
    ControlPlaneWriteRequestKind::try_from(value)
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ControlPlaneId128(pub [u8; 16]);

impl ControlPlaneId128 {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn from_u128_le(value: u128) -> Self {
        Self(value.to_le_bytes())
    }

    #[must_use]
    pub const fn as_u128_le(self) -> u128 {
        u128::from_le_bytes(self.0)
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        let mut index = 0;
        while index < self.0.len() {
            if self.0[index] != 0 {
                return false;
            }
            index += 1;
        }
        true
    }
}

pub type ControlPlaneRequestId = ControlPlaneId128;
pub type ControlPlaneSessionId = ControlPlaneId128;
pub type ControlPlaneJournalId = ControlPlaneId128;
pub type ControlPlaneReceiptId = ControlPlaneId128;
pub type ControlPlaneIdempotencyKey = ControlPlaneId128;
pub type ControlPlaneDigest32 = [u8; 32];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlanePolicyBudgetRecipeWitnessRefs {
    pub witness_join_id: ControlPlaneId128,
    pub policy_witness_id: ControlPlaneId128,
    pub budget_witness_id: ControlPlaneId128,
    pub recipe_witness_id: ControlPlaneId128,
    pub witness_join_digest: ControlPlaneDigest32,
}

impl ControlPlanePolicyBudgetRecipeWitnessRefs {
    pub const ZERO: Self = Self {
        witness_join_id: ControlPlaneId128::ZERO,
        policy_witness_id: ControlPlaneId128::ZERO,
        budget_witness_id: ControlPlaneId128::ZERO,
        recipe_witness_id: ControlPlaneId128::ZERO,
        witness_join_digest: [0_u8; 32],
    };

    #[must_use]
    pub const fn new(
        witness_join_id: ControlPlaneId128,
        policy_witness_id: ControlPlaneId128,
        budget_witness_id: ControlPlaneId128,
        recipe_witness_id: ControlPlaneId128,
        witness_join_digest: ControlPlaneDigest32,
    ) -> Self {
        Self {
            witness_join_id,
            policy_witness_id,
            budget_witness_id,
            recipe_witness_id,
            witness_join_digest,
        }
    }

    #[must_use]
    pub const fn has_join(&self) -> bool {
        !self.witness_join_id.is_zero()
    }
}

pub const CONTROL_PLANE_CANON_VERSION_1: u32 = 1;
pub const CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT: u32 = 1 << 0;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY: u32 = u32::MAX;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY: u32 = u32::MAX;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT: u32 = 1 << 0;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED: u32 = 1 << 1;
pub const CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT: u32 = 1 << 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupRequestRecord {
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_filter_or_any: u32,
    pub answer_kind_filter_or_any: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub _reserved1: u32,
    pub index_key_digest: ControlPlaneDigest32,
}

impl Default for ControlPlaneTruthRecallLookupRequestRecord {
    fn default() -> Self {
        Self {
            route_class: 0,
            index_class: 0,
            retention_class: 0,
            disclosure_filter_or_any: CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY,
            answer_kind_filter_or_any: CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY,
            flags: 0,
            _reserved0: 0,
            _reserved1: 0,
            index_key_digest: [0_u8; 32],
        }
    }
}

impl ControlPlaneTruthRecallLookupRequestRecord {
    #[must_use]
    pub const fn new(
        route_class: ControlPlaneRouteClass,
        index_class: u32,
        retention_class: u32,
        disclosure_filter_or_any: u32,
        answer_kind_filter_or_any: u32,
        flags: u32,
        index_key_digest: ControlPlaneDigest32,
    ) -> Self {
        Self {
            route_class: route_class.as_u32(),
            index_class,
            retention_class,
            disclosure_filter_or_any,
            answer_kind_filter_or_any,
            flags,
            _reserved0: 0,
            _reserved1: 0,
            index_key_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn requires_terminal_receipt(&self) -> bool {
        self.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT)
    }

    #[must_use]
    pub const fn allows_superseded(&self) -> bool {
        self.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED)
    }

    #[must_use]
    pub const fn has_disclosure_filter(&self) -> bool {
        self.disclosure_filter_or_any != CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY
    }

    #[must_use]
    pub const fn has_answer_kind_filter(&self) -> bool {
        self.answer_kind_filter_or_any != CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupHitRecord {
    pub route_class: u32,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub _reserved1: u32,
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub binding_id: ControlPlaneReceiptId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupHitRecordInput {
    pub route_class: ControlPlaneRouteClass,
    pub index_class: u32,
    pub retention_class: u32,
    pub disclosure_class: u32,
    pub answer_kind: u32,
    pub index_entry_id: ControlPlaneReceiptId,
    pub response_receipt_id: ControlPlaneReceiptId,
    pub bundle_receipt_id: ControlPlaneReceiptId,
    pub terminal_receipt_id_or_zero: ControlPlaneReceiptId,
    pub binding_id: ControlPlaneReceiptId,
}

impl ControlPlaneTruthRecallLookupHitRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneTruthRecallLookupHitRecordInput) -> Self {
        Self {
            route_class: input.route_class.as_u32(),
            index_class: input.index_class,
            retention_class: input.retention_class,
            disclosure_class: input.disclosure_class,
            answer_kind: input.answer_kind,
            flags: if input.terminal_receipt_id_or_zero.is_zero() {
                0
            } else {
                CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT
            },
            _reserved0: 0,
            _reserved1: 0,
            index_entry_id: input.index_entry_id,
            response_receipt_id: input.response_receipt_id,
            bundle_receipt_id: input.bundle_receipt_id,
            terminal_receipt_id_or_zero: input.terminal_receipt_id_or_zero,
            binding_id: input.binding_id,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn has_terminal_receipt(&self) -> bool {
        !self.terminal_receipt_id_or_zero.is_zero()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupBatchReceiptRecord {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub carrier_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub query_count: u32,
    pub hit_count: u32,
    pub flags: u32,
    pub _reserved0: u32,
    pub query_stream_digest: ControlPlaneDigest32,
    pub hit_stream_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneTruthRecallLookupBatchReceiptRecordInput {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: ControlPlaneRouteClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub query_count: u32,
    pub hit_count: u32,
    pub all_hits_have_terminal_receipt: bool,
    pub query_stream_digest: ControlPlaneDigest32,
    pub hit_stream_digest: ControlPlaneDigest32,
}

impl ControlPlaneTruthRecallLookupBatchReceiptRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneTruthRecallLookupBatchReceiptRecordInput) -> Self {
        Self {
            receipt_id: input.receipt_id,
            journal_id: input.journal_id,
            route_class: input.route_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            query_count: input.query_count,
            hit_count: input.hit_count,
            flags: if input.all_hits_have_terminal_receipt {
                1 // all-terminal-receipts flag
            } else {
                0
            },
            _reserved0: 0,
            query_stream_digest: input.query_stream_digest,
            hit_stream_digest: input.hit_stream_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRequestEnvelopeHead {
    pub version: u32,
    pub carrier_class: u32,
    pub route_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub flags: u32,
    pub payload_len: u32,
    pub _reserved0: u32,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub normalized_request_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneRequestEnvelopeHeadInput {
    pub carrier_class: ControlPlaneCarrierClass,
    pub route_class: ControlPlaneRouteClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub flags: u32,
    pub payload_len: u32,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub normalized_request_digest: ControlPlaneDigest32,
}

impl ControlPlaneRequestEnvelopeHead {
    #[must_use]
    pub const fn new(input: ControlPlaneRequestEnvelopeHeadInput) -> Self {
        Self {
            version: CONTROL_PLANE_CANON_VERSION_1,
            carrier_class: input.carrier_class.as_u32(),
            route_class: input.route_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            flags: input.flags,
            payload_len: input.payload_len,
            _reserved0: 0,
            request_id: input.request_id,
            session_id: input.session_id,
            idempotency_key: input.idempotency_key,
            normalized_request_digest: input.normalized_request_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    #[must_use]
    pub const fn has_flag(&self, flag: u32) -> bool {
        (self.flags & flag) != 0
    }

    #[must_use]
    pub const fn project_journal_record(
        self,
        journal_id: ControlPlaneJournalId,
    ) -> ControlPlaneRequestJournalRecord {
        ControlPlaneRequestJournalRecord {
            journal_id,
            request_id: self.request_id,
            session_id: self.session_id,
            carrier_class: self.carrier_class,
            route_class: self.route_class,
            normalized_request_digest: self.normalized_request_digest,
            idempotency_key: self.idempotency_key,
            upstream_receipt_count: 0,
            _reserved0: 0,
            terminal_render_receipt_id: ControlPlaneReceiptId::ZERO,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRequestJournalRecord {
    pub journal_id: ControlPlaneJournalId,
    pub request_id: ControlPlaneRequestId,
    pub session_id: ControlPlaneSessionId,
    pub carrier_class: u32,
    pub route_class: u32,
    pub normalized_request_digest: ControlPlaneDigest32,
    pub idempotency_key: ControlPlaneIdempotencyKey,
    pub upstream_receipt_count: u32,
    pub _reserved0: u32,
    pub terminal_render_receipt_id: ControlPlaneReceiptId,
}

impl ControlPlaneRequestJournalRecord {
    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    #[must_use]
    pub const fn with_terminal_render_receipt(
        mut self,
        receipt_id: ControlPlaneReceiptId,
        upstream_receipt_count: u32,
    ) -> Self {
        self.terminal_render_receipt_id = receipt_id;
        self.upstream_receipt_count = upstream_receipt_count;
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneResponseRenderReceipt {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub carrier_class: u32,
    pub response_kind: u32,
    pub _reserved0: u32,
    pub bundle_or_refusal_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneResponseRenderReceiptInput {
    pub receipt_id: ControlPlaneReceiptId,
    pub journal_id: ControlPlaneJournalId,
    pub route_class: ControlPlaneRouteClass,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub response_kind: ControlPlaneResponseKind,
    pub bundle_or_refusal_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
}

impl ControlPlaneResponseRenderReceipt {
    #[must_use]
    pub const fn new(input: ControlPlaneResponseRenderReceiptInput) -> Self {
        Self {
            receipt_id: input.receipt_id,
            journal_id: input.journal_id,
            route_class: input.route_class.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            response_kind: input.response_kind.as_u32(),
            _reserved0: 0,
            bundle_or_refusal_digest: input.bundle_or_refusal_digest,
            artifact_locator_digest: input.artifact_locator_digest,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidResponseKind`] if the stored
    /// raw tag does not correspond to a valid response_kind.
    pub fn response_kind(self) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
        decode_response_kind(self.response_kind)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneRouteTerminalReceiptRecord {
    pub terminal_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub render_receipt_id: ControlPlaneReceiptId,
    pub route_class: u32,
    pub response_kind: u32,
    pub render_class: u32,
    pub visibility_class: u32,
    pub carrier_class: u32,
    pub _reserved0: u32,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPlaneRouteTerminalReceiptRecordInput {
    pub terminal_receipt_id: ControlPlaneReceiptId,
    pub request_id: ControlPlaneRequestId,
    pub journal_id: ControlPlaneJournalId,
    pub response_registry_receipt_id: ControlPlaneReceiptId,
    pub render_receipt_id: ControlPlaneReceiptId,
    pub route_class: ControlPlaneRouteClass,
    pub response_kind: ControlPlaneResponseKind,
    pub render_class: ControlPlaneRenderClass,
    pub visibility_class: ControlPlaneVisibilityClass,
    pub carrier_class: ControlPlaneCarrierClass,
    pub answer_digest: ControlPlaneDigest32,
    pub artifact_locator_digest: ControlPlaneDigest32,
    pub witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs,
}

impl ControlPlaneRouteTerminalReceiptRecord {
    #[must_use]
    pub const fn new(input: ControlPlaneRouteTerminalReceiptRecordInput) -> Self {
        Self {
            terminal_receipt_id: input.terminal_receipt_id,
            request_id: input.request_id,
            journal_id: input.journal_id,
            response_registry_receipt_id: input.response_registry_receipt_id,
            render_receipt_id: input.render_receipt_id,
            route_class: input.route_class.as_u32(),
            response_kind: input.response_kind.as_u32(),
            render_class: input.render_class.as_u32(),
            visibility_class: input.visibility_class.as_u32(),
            carrier_class: input.carrier_class.as_u32(),
            _reserved0: 0,
            answer_digest: input.answer_digest,
            artifact_locator_digest: input.artifact_locator_digest,
            witness_refs: input.witness_refs,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRouteClass`] if the stored
    /// raw tag does not correspond to a valid route.
    pub fn route(self) -> Result<ControlPlaneRouteClass, ControlPlaneRecordDecodeError> {
        decode_route_class(self.route_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidResponseKind`] if the stored
    /// raw tag does not correspond to a valid response_kind.
    pub fn response_kind(self) -> Result<ControlPlaneResponseKind, ControlPlaneRecordDecodeError> {
        decode_response_kind(self.response_kind)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidRenderClass`] if the stored
    /// raw tag does not correspond to a valid render.
    pub fn render(self) -> Result<ControlPlaneRenderClass, ControlPlaneRecordDecodeError> {
        decode_render_class(self.render_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidVisibilityClass`] if the stored
    /// raw tag does not correspond to a valid visibility.
    pub fn visibility(self) -> Result<ControlPlaneVisibilityClass, ControlPlaneRecordDecodeError> {
        decode_visibility_class(self.visibility_class)
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidCarrierClass`] if the stored
    /// raw tag does not correspond to a valid carrier.
    pub fn carrier(self) -> Result<ControlPlaneCarrierClass, ControlPlaneRecordDecodeError> {
        decode_carrier_class(self.carrier_class)
    }

    #[must_use]
    pub const fn has_witness_join(&self) -> bool {
        self.witness_refs.has_join()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ControlPlaneWriteManualProductAdmissionPayload {
    pub write_request_kind: u32,
    pub flags: u32,
    pub _reserved0: u64,
    pub product_recipe_digest: ControlPlaneDigest32,
    pub subject_scope_digest: ControlPlaneDigest32,
    pub required_anchor_set_id: ControlPlaneId128,
    pub budget_domain_id: ControlPlaneId128,
}

impl ControlPlaneWriteManualProductAdmissionPayload {
    #[must_use]
    pub const fn new(
        flags: u32,
        product_recipe_digest: ControlPlaneDigest32,
        subject_scope_digest: ControlPlaneDigest32,
        required_anchor_set_id: ControlPlaneId128,
        budget_domain_id: ControlPlaneId128,
    ) -> Self {
        Self {
            write_request_kind: ControlPlaneWriteRequestKind::ProductAdmissionManual.as_u32(),
            flags,
            _reserved0: 0,
            product_recipe_digest,
            subject_scope_digest,
            required_anchor_set_id,
            budget_domain_id,
        }
    }

    /// # Errors
    ///
    /// Returns [`ControlPlaneRecordDecodeError::InvalidWriteRequestKind`] if the stored
    /// raw tag does not correspond to a valid kind.
    pub fn kind(self) -> Result<ControlPlaneWriteRequestKind, ControlPlaneRecordDecodeError> {
        decode_write_request_kind(self.write_request_kind)
    }
}

const _: [(); 16] = [(); core::mem::size_of::<ControlPlaneId128>()];
const _: [(); 96] = [(); core::mem::size_of::<ControlPlanePolicyBudgetRecipeWitnessRefs>()];
const _: [(); 64] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupRequestRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupHitRecord>()];
const _: [(); 128] = [(); core::mem::size_of::<ControlPlaneTruthRecallLookupBatchReceiptRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneRequestEnvelopeHead>()];
const _: [(); 128] = [(); core::mem::size_of::<ControlPlaneRequestJournalRecord>()];
const _: [(); 120] = [(); core::mem::size_of::<ControlPlaneResponseRenderReceipt>()];
const _: [(); 264] = [(); core::mem::size_of::<ControlPlaneRouteTerminalReceiptRecord>()];
const _: [(); 112] = [(); core::mem::size_of::<ControlPlaneWriteManualProductAdmissionPayload>()];

// TURN3_HUMAN_CONTROL_PLANE_ALIASES
/// Human-named module for the Control Plane family.
///
/// The `ControlPlane*` internal-locator names remain the canonical fixed-width record names and
/// wire/layout stability identifiers. New reader-facing Rust code can
/// import this module to avoid spreading the internal locator into application
/// logic, while codecs and serialized records continue to use the same types.
pub mod control_plane {
    pub const FAMILY_NAME: &str = "Control Plane";
    pub const STABLE_SOURCE_LOCATOR: &str = "control_plane";
    pub const ROLE: &str = "operator/control API, request envelopes, carrier frames, and receipts";

    pub use super::{
        ControlPlaneCarrierClass as CarrierClass, ControlPlaneDigest32 as Digest32,
        ControlPlaneId128 as Id128, ControlPlaneIdempotencyKey as IdempotencyKey,
        ControlPlaneJournalId as JournalId,
        ControlPlanePolicyBudgetRecipeWitnessRefs as PolicyBudgetRecipeWitnessRefs,
        ControlPlaneReceiptId as ReceiptId, ControlPlaneRenderClass as RenderClass,
        ControlPlaneRequestEnvelopeHead as RequestEnvelopeHead,
        ControlPlaneRequestEnvelopeHeadInput as RequestEnvelopeHeadInput,
        ControlPlaneRequestId as RequestId,
        ControlPlaneRequestJournalRecord as RequestJournalRecord,
        ControlPlaneResponseKind as ResponseKind,
        ControlPlaneResponseRenderReceipt as ResponseRenderReceipt,
        ControlPlaneResponseRenderReceiptInput as ResponseRenderReceiptInput,
        ControlPlaneRouteClass as RouteClass,
        ControlPlaneRouteTerminalReceiptRecord as RouteTerminalReceiptRecord,
        ControlPlaneRouteTerminalReceiptRecordInput as RouteTerminalReceiptRecordInput,
        ControlPlaneSessionId as SessionId,
        ControlPlaneTruthRecallLookupBatchReceiptRecord as TruthRecallLookupBatchReceiptRecord,
        ControlPlaneTruthRecallLookupBatchReceiptRecordInput as TruthRecallLookupBatchReceiptRecordInput,
        ControlPlaneTruthRecallLookupHitRecord as TruthRecallLookupHitRecord,
        ControlPlaneTruthRecallLookupHitRecordInput as TruthRecallLookupHitRecordInput,
        ControlPlaneTruthRecallLookupRequestRecord as TruthRecallLookupRequestRecord,
        ControlPlaneVisibilityClass as VisibilityClass,
        ControlPlaneWriteManualProductAdmissionPayload as ManualProductAdmissionPayload,
        ControlPlaneWriteRequestKind as WriteRequestKind,
    };

    pub const CANON_VERSION_1: u32 = super::CONTROL_PLANE_CANON_VERSION_1;
    pub const REQUEST_FLAG_IDEMPOTENT: u32 = super::CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT;
    pub const TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY;
    pub const TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY;
    pub const TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT;
    pub const TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED;
    pub const TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT: u32 =
        super::CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT;
}

/// Human alias namespace. Prefer `human::control_plane::*` in new examples.
pub mod human {
    pub mod control_plane {
        pub use crate::control_plane::*;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truth_recall_lookup_request_record_tracks_any_filters_and_flags() {
        let record = ControlPlaneTruthRecallLookupRequestRecord::new(
            ControlPlaneRouteClass::Recall,
            4,
            2,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT
                | CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED,
            [0xAB_u8; 32],
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Recall));
        assert!(!record.has_disclosure_filter());
        assert!(!record.has_answer_kind_filter());
        assert!(record.requires_terminal_receipt());
        assert!(record.allows_superseded());
        assert_eq!(record.index_key_digest, [0xAB_u8; 32]);
    }

    #[test]
    fn truth_recall_lookup_hit_record_tracks_terminal_flag_from_payload() {
        let with_terminal = ControlPlaneTruthRecallLookupHitRecord::new(
            ControlPlaneTruthRecallLookupHitRecordInput {
                route_class: ControlPlaneRouteClass::TruthSurface,
                index_class: 0,
                retention_class: 2,
                disclosure_class: 1,
                answer_kind: 0,
                index_entry_id: ControlPlaneId128::from_u128_le(0x11),
                response_receipt_id: ControlPlaneId128::from_u128_le(0x22),
                bundle_receipt_id: ControlPlaneId128::from_u128_le(0x33),
                terminal_receipt_id_or_zero: ControlPlaneId128::from_u128_le(0x44),
                binding_id: ControlPlaneId128::from_u128_le(0x55),
            },
        );
        assert_eq!(
            with_terminal.route(),
            Ok(ControlPlaneRouteClass::TruthSurface)
        );
        assert!(with_terminal.has_terminal_receipt());
        assert!(with_terminal.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT));

        let without_terminal = ControlPlaneTruthRecallLookupHitRecord::new(
            ControlPlaneTruthRecallLookupHitRecordInput {
                route_class: ControlPlaneRouteClass::Recall,
                index_class: 4,
                retention_class: 2,
                disclosure_class: 2,
                answer_kind: 1,
                index_entry_id: ControlPlaneId128::from_u128_le(0x66),
                response_receipt_id: ControlPlaneId128::from_u128_le(0x77),
                bundle_receipt_id: ControlPlaneId128::from_u128_le(0x88),
                terminal_receipt_id_or_zero: ControlPlaneId128::ZERO,
                binding_id: ControlPlaneId128::from_u128_le(0x99),
            },
        );
        assert_eq!(without_terminal.route(), Ok(ControlPlaneRouteClass::Recall));
        assert!(!without_terminal.has_terminal_receipt());
        assert!(
            !without_terminal.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT)
        );
    }

    #[test]
    fn truth_recall_lookup_batch_receipt_tracks_counts_and_terminal_flag() {
        let record = ControlPlaneTruthRecallLookupBatchReceiptRecord::new(
            ControlPlaneTruthRecallLookupBatchReceiptRecordInput {
                receipt_id: ControlPlaneId128::from_u128_le(0x101),
                journal_id: ControlPlaneId128::from_u128_le(0x202),
                route_class: ControlPlaneRouteClass::Recall,
                carrier_class: ControlPlaneCarrierClass::RemoteMtlsGateway,
                render_class: ControlPlaneRenderClass::Machine,
                visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
                query_count: 2,
                hit_count: 2,
                all_hits_have_terminal_receipt: true,
                query_stream_digest: [0xAA_u8; 32],
                hit_stream_digest: [0xBB_u8; 32],
            },
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Recall));
        assert_eq!(
            record.carrier(),
            Ok(ControlPlaneCarrierClass::RemoteMtlsGateway)
        );
        assert_eq!(record.render(), Ok(ControlPlaneRenderClass::Machine));
        assert_eq!(
            record.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert_eq!(record.query_count, 2);
        assert_eq!(record.hit_count, 2);
        assert!(record.has_flag(1));
        assert!(record.has_flag(1));
        assert_eq!(record.query_stream_digest, [0xAA_u8; 32]);
        assert_eq!(record.hit_stream_digest, [0xBB_u8; 32]);
    }

    #[test]
    fn route_classes_round_trip_through_u32() {
        for route in [
            ControlPlaneRouteClass::Session,
            ControlPlaneRouteClass::Write,
            ControlPlaneRouteClass::Runbook,
            ControlPlaneRouteClass::SecretControl,
            ControlPlaneRouteClass::TruthSurface,
            ControlPlaneRouteClass::Recall,
        ] {
            assert_eq!(ControlPlaneRouteClass::try_from(route.as_u32()), Ok(route));
        }
    }

    #[test]
    fn request_head_projects_journal_record() {
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
            route_class: ControlPlaneRouteClass::Write,
            render_class: ControlPlaneRenderClass::OperatorText,
            visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
            flags: CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT | CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT,
            payload_len: 144,
            request_id: ControlPlaneRequestId::from_u128_le(0x11),
            session_id: ControlPlaneSessionId::from_u128_le(0x22),
            idempotency_key: ControlPlaneIdempotencyKey::from_u128_le(0x33),
            normalized_request_digest: [0xA5_u8; 32],
        });
        let journal = head.project_journal_record(ControlPlaneJournalId::from_u128_le(0x44));
        assert_eq!(head.route(), Ok(ControlPlaneRouteClass::Write));
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert_eq!(
            journal.carrier(),
            Ok(ControlPlaneCarrierClass::LocalKernelUapi)
        );
        assert_eq!(journal.route(), Ok(ControlPlaneRouteClass::Write));
        assert_eq!(journal.request_id.as_u128_le(), 0x11);
        assert_eq!(journal.session_id.as_u128_le(), 0x22);
        assert_eq!(journal.idempotency_key.as_u128_le(), 0x33);
        assert_eq!(journal.journal_id.as_u128_le(), 0x44);
        assert_eq!(journal.normalized_request_digest, [0xA5_u8; 32]);
        assert!(journal.terminal_render_receipt_id.is_zero());
    }

    #[test]
    fn render_receipt_preserves_kind_and_route() {
        let receipt =
            ControlPlaneResponseRenderReceipt::new(ControlPlaneResponseRenderReceiptInput {
                receipt_id: ControlPlaneReceiptId::from_u128_le(7),
                journal_id: ControlPlaneJournalId::from_u128_le(8),
                route_class: ControlPlaneRouteClass::TruthSurface,
                render_class: ControlPlaneRenderClass::Machine,
                visibility_class: ControlPlaneVisibilityClass::PublicRedacted,
                carrier_class: ControlPlaneCarrierClass::RemoteMtlsGateway,
                response_kind: ControlPlaneResponseKind::Bundle,
                bundle_or_refusal_digest: [0x10_u8; 32],
                artifact_locator_digest: [0x20_u8; 32],
            });
        assert_eq!(receipt.route(), Ok(ControlPlaneRouteClass::TruthSurface));
        assert_eq!(receipt.render(), Ok(ControlPlaneRenderClass::Machine));
        assert_eq!(
            receipt.visibility(),
            Ok(ControlPlaneVisibilityClass::PublicRedacted)
        );
        assert_eq!(
            receipt.carrier(),
            Ok(ControlPlaneCarrierClass::RemoteMtlsGateway)
        );
        assert_eq!(
            receipt.response_kind(),
            Ok(ControlPlaneResponseKind::Bundle)
        );
        assert_eq!(receipt.receipt_id.as_u128_le(), 7);
        assert_eq!(receipt.journal_id.as_u128_le(), 8);
    }

    #[test]
    fn manual_product_admission_payload_preserves_kind_and_ids() {
        let payload = ControlPlaneWriteManualProductAdmissionPayload::new(
            0x7,
            [0x11_u8; 32],
            [0x22_u8; 32],
            ControlPlaneId128::from_u128_le(0x33),
            ControlPlaneId128::from_u128_le(0x44),
        );
        assert_eq!(
            payload.kind(),
            Ok(ControlPlaneWriteRequestKind::ProductAdmissionManual)
        );
        assert_eq!(payload.flags, 0x7);
        assert_eq!(payload.product_recipe_digest, [0x11_u8; 32]);
        assert_eq!(payload.subject_scope_digest, [0x22_u8; 32]);
        assert_eq!(payload.required_anchor_set_id.as_u128_le(), 0x33);
        assert_eq!(payload.budget_domain_id.as_u128_le(), 0x44);
    }

    #[test]
    fn record_accessors_report_invalid_numeric_classes() {
        let batch = ControlPlaneTruthRecallLookupBatchReceiptRecord {
            route_class: 99,
            carrier_class: 98,
            render_class: 97,
            visibility_class: 96,
            ..Default::default()
        };
        assert_eq!(
            batch.route(),
            Err(ControlPlaneRecordDecodeError::InvalidRouteClass(99))
        );
        assert_eq!(
            batch.carrier(),
            Err(ControlPlaneRecordDecodeError::InvalidCarrierClass(98))
        );
        assert_eq!(
            batch.render(),
            Err(ControlPlaneRecordDecodeError::InvalidRenderClass(97))
        );
        assert_eq!(
            batch.visibility(),
            Err(ControlPlaneRecordDecodeError::InvalidVisibilityClass(96))
        );

        let receipt = ControlPlaneResponseRenderReceipt {
            response_kind: 95,
            ..Default::default()
        };
        assert_eq!(
            receipt.response_kind(),
            Err(ControlPlaneRecordDecodeError::InvalidResponseKind(95))
        );

        let payload = ControlPlaneWriteManualProductAdmissionPayload {
            write_request_kind: 94,
            ..Default::default()
        };
        assert_eq!(
            payload.kind(),
            Err(ControlPlaneRecordDecodeError::InvalidWriteRequestKind(94))
        );
    }

    #[test]
    fn route_terminal_receipt_preserves_control_plane_surface_fields() {
        let record = ControlPlaneRouteTerminalReceiptRecord::new(
            ControlPlaneRouteTerminalReceiptRecordInput {
                terminal_receipt_id: ControlPlaneId128::from_u128_le(0x11),
                request_id: ControlPlaneId128::from_u128_le(0x22),
                journal_id: ControlPlaneId128::from_u128_le(0x33),
                response_registry_receipt_id: ControlPlaneId128::from_u128_le(0x44),
                render_receipt_id: ControlPlaneId128::from_u128_le(0x55),
                route_class: ControlPlaneRouteClass::Write,
                response_kind: ControlPlaneResponseKind::Refusal,
                render_class: ControlPlaneRenderClass::OperatorText,
                visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
                carrier_class: ControlPlaneCarrierClass::RemoteMtlsGateway,
                answer_digest: [0xAA_u8; 32],
                artifact_locator_digest: [0xBB_u8; 32],
                witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs::new(
                    ControlPlaneId128::from_u128_le(0x66),
                    ControlPlaneId128::from_u128_le(0x77),
                    ControlPlaneId128::from_u128_le(0x88),
                    ControlPlaneId128::from_u128_le(0x99),
                    [0xCC_u8; 32],
                ),
            },
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Write));
        assert_eq!(
            record.response_kind(),
            Ok(ControlPlaneResponseKind::Refusal)
        );
        assert_eq!(record.render(), Ok(ControlPlaneRenderClass::OperatorText));
        assert_eq!(
            record.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert_eq!(
            record.carrier(),
            Ok(ControlPlaneCarrierClass::RemoteMtlsGateway)
        );
        assert!(record.has_witness_join());
        assert_eq!(record.witness_refs.policy_witness_id.as_u128_le(), 0x77);
    }

    #[test]
    fn witness_refs_zero_sentinel_has_no_join() {
        assert!(!ControlPlanePolicyBudgetRecipeWitnessRefs::ZERO.has_join());
    }

    #[test]
    fn control_plane_id_encode_decode_round_trip_with_specific_bytes() {
        let id = ControlPlaneId128([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        let decoded = id.as_u128_le();
        let re_encoded = ControlPlaneId128::from_u128_le(decoded);
        assert_eq!(re_encoded.0, id.0);
        assert_eq!(decoded, 0x100F_0E0D_0C0B_0A09_0807_0605_0403_0201);

        let zero = ControlPlaneId128::ZERO;
        assert_eq!(ControlPlaneId128::from_u128_le(zero.as_u128_le()).0, zero.0);
        assert_eq!(zero.as_u128_le(), 0);
    }

    // ── Enum variant exhaustive roundtrip tests ────────────────────────

    #[test]
    fn carrier_class_all_variants_roundtrip() {
        let variants = [
            ControlPlaneCarrierClass::LocalKernelUapi,
            ControlPlaneCarrierClass::RemoteMtlsGateway,
            ControlPlaneCarrierClass::InternalKernelStub,
        ];
        for v in &variants {
            let round = ControlPlaneCarrierClass::try_from(v.as_u32());
            assert_eq!(round, Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            ControlPlaneCarrierClass::default(),
            ControlPlaneCarrierClass::LocalKernelUapi
        );
        assert_ne!(variants[0].as_u32(), variants[1].as_u32());
        assert_ne!(variants[1].as_u32(), variants[2].as_u32());
    }

    #[test]
    fn route_class_all_variants_roundtrip() {
        let variants = [
            ControlPlaneRouteClass::Session,
            ControlPlaneRouteClass::Write,
            ControlPlaneRouteClass::Runbook,
            ControlPlaneRouteClass::SecretControl,
            ControlPlaneRouteClass::TruthSurface,
            ControlPlaneRouteClass::Recall,
        ];
        for v in &variants {
            assert_eq!(ControlPlaneRouteClass::try_from(v.as_u32()), Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            ControlPlaneRouteClass::default(),
            ControlPlaneRouteClass::Session
        );
    }

    #[test]
    fn render_class_all_variants_roundtrip() {
        let variants = [
            ControlPlaneRenderClass::Machine,
            ControlPlaneRenderClass::OperatorText,
            ControlPlaneRenderClass::OperatorText,
        ];
        for v in &variants {
            assert_eq!(ControlPlaneRenderClass::try_from(v.as_u32()), Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            ControlPlaneRenderClass::default(),
            ControlPlaneRenderClass::Machine
        );
    }

    #[test]
    fn visibility_class_all_variants_roundtrip() {
        let variants = [
            ControlPlaneVisibilityClass::PublicRedacted,
            ControlPlaneVisibilityClass::OperatorScoped,
            ControlPlaneVisibilityClass::OperatorScoped,
        ];
        for v in &variants {
            assert_eq!(ControlPlaneVisibilityClass::try_from(v.as_u32()), Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            ControlPlaneVisibilityClass::default(),
            ControlPlaneVisibilityClass::PublicRedacted
        );
    }

    #[test]
    fn response_kind_all_variants_roundtrip() {
        let variants = [
            ControlPlaneResponseKind::Bundle,
            ControlPlaneResponseKind::Refusal,
        ];
        for v in &variants {
            assert_eq!(ControlPlaneResponseKind::try_from(v.as_u32()), Ok(*v));
            assert!(!v.as_str().is_empty());
        }
        assert_eq!(
            ControlPlaneResponseKind::default(),
            ControlPlaneResponseKind::Bundle
        );
    }

    #[test]
    fn write_request_kind_roundtrip() {
        let v = ControlPlaneWriteRequestKind::ProductAdmissionManual;
        assert_eq!(ControlPlaneWriteRequestKind::try_from(v.as_u32()), Ok(v));
        assert!(!v.as_str().is_empty());
        assert_eq!(
            ControlPlaneWriteRequestKind::default(),
            ControlPlaneWriteRequestKind::ProductAdmissionManual
        );
    }

    // ── Record exhaustive roundtrip tests ──────────────────────────────

    #[test]
    fn truth_recall_lookup_request_record_exhaustive_roundtrip() {
        let record = ControlPlaneTruthRecallLookupRequestRecord::new(
            ControlPlaneRouteClass::Recall,
            5,
            3,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_REQUIRE_TERMINAL_RECEIPT
                | CONTROL_PLANE_TRUTH_RECALL_LOOKUP_REQUEST_FLAG_ALLOW_SUPERSEDED,
            [0xAB_u8; 32],
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Recall));
        assert_eq!(record.index_class, 5);
        assert_eq!(record.retention_class, 3);
        assert_eq!(
            record.disclosure_filter_or_any,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY
        );
        assert_eq!(
            record.answer_kind_filter_or_any,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_ANSWER_KIND_FILTER_ANY
        );
        assert!(!record.has_disclosure_filter());
        assert!(!record.has_answer_kind_filter());
        assert!(record.requires_terminal_receipt());
        assert!(record.allows_superseded());
        assert_eq!(record.index_key_digest, [0xAB_u8; 32]);
    }

    #[test]
    fn truth_recall_lookup_hit_record_exhaustive_roundtrip() {
        let record = ControlPlaneTruthRecallLookupHitRecord::new(
            ControlPlaneTruthRecallLookupHitRecordInput {
                route_class: ControlPlaneRouteClass::TruthSurface,
                index_class: 2,
                retention_class: 4,
                disclosure_class: 1,
                answer_kind: 3,
                index_entry_id: ControlPlaneId128::from_u128_le(0xAA),
                response_receipt_id: ControlPlaneId128::from_u128_le(0xBB),
                bundle_receipt_id: ControlPlaneId128::from_u128_le(0xCC),
                terminal_receipt_id_or_zero: ControlPlaneId128::from_u128_le(0xDD),
                binding_id: ControlPlaneId128::from_u128_le(0xEE),
            },
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::TruthSurface));
        assert_eq!(record.index_class, 2);
        assert_eq!(record.retention_class, 4);
        assert_eq!(record.disclosure_class, 1);
        assert_eq!(record.answer_kind, 3);
        assert_eq!(record.index_entry_id.as_u128_le(), 0xAA);
        assert_eq!(record.response_receipt_id.as_u128_le(), 0xBB);
        assert_eq!(record.bundle_receipt_id.as_u128_le(), 0xCC);
        assert_eq!(record.binding_id.as_u128_le(), 0xEE);
        assert!(record.has_terminal_receipt());
        assert!(record.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT));
    }

    #[test]
    fn truth_recall_lookup_hit_record_without_terminal_receipt() {
        let record = ControlPlaneTruthRecallLookupHitRecord::new(
            ControlPlaneTruthRecallLookupHitRecordInput {
                route_class: ControlPlaneRouteClass::Recall,
                index_class: 0,
                retention_class: 0,
                disclosure_class: 0,
                answer_kind: 0,
                index_entry_id: ControlPlaneId128::ZERO,
                response_receipt_id: ControlPlaneId128::ZERO,
                bundle_receipt_id: ControlPlaneId128::ZERO,
                terminal_receipt_id_or_zero: ControlPlaneId128::ZERO,
                binding_id: ControlPlaneId128::ZERO,
            },
        );
        assert!(!record.has_terminal_receipt());
        assert!(!record.has_flag(CONTROL_PLANE_TRUTH_RECALL_LOOKUP_HIT_FLAG_TERMINAL_RECEIPT));
    }

    #[test]
    fn truth_recall_lookup_batch_receipt_exhaustive_roundtrip() {
        let record = ControlPlaneTruthRecallLookupBatchReceiptRecord::new(
            ControlPlaneTruthRecallLookupBatchReceiptRecordInput {
                receipt_id: ControlPlaneId128::from_u128_le(0x111),
                journal_id: ControlPlaneId128::from_u128_le(0x222),
                route_class: ControlPlaneRouteClass::Write,
                carrier_class: ControlPlaneCarrierClass::RemoteMtlsGateway,
                render_class: ControlPlaneRenderClass::Machine,
                visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
                query_count: 7,
                hit_count: 5,
                all_hits_have_terminal_receipt: true,
                query_stream_digest: [0xA1_u8; 32],
                hit_stream_digest: [0xA2_u8; 32],
            },
        );
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Write));
        assert_eq!(
            record.carrier(),
            Ok(ControlPlaneCarrierClass::RemoteMtlsGateway)
        );
        assert_eq!(record.render(), Ok(ControlPlaneRenderClass::Machine));
        assert_eq!(
            record.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert_eq!(record.receipt_id.as_u128_le(), 0x111);
        assert_eq!(record.journal_id.as_u128_le(), 0x222);
        assert_eq!(record.query_count, 7);
        assert_eq!(record.hit_count, 5);
        assert!(record.has_flag(1));
        assert!(record.has_flag(1));
        assert_eq!(record.query_stream_digest, [0xA1_u8; 32]);
        assert_eq!(record.hit_stream_digest, [0xA2_u8; 32]);
    }

    #[test]
    fn request_envelope_head_exhaustive_roundtrip() {
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::InternalKernelStub,
            route_class: ControlPlaneRouteClass::Runbook,
            render_class: ControlPlaneRenderClass::OperatorText,
            visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
            flags: CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT,
            payload_len: 256,
            request_id: ControlPlaneRequestId::from_u128_le(0xDEAD),
            session_id: ControlPlaneSessionId::from_u128_le(0xBEEF),
            idempotency_key: ControlPlaneIdempotencyKey::from_u128_le(0xCAFE),
            normalized_request_digest: [0x7E_u8; 32],
        });
        assert_eq!(
            head.carrier(),
            Ok(ControlPlaneCarrierClass::InternalKernelStub)
        );
        assert_eq!(head.route(), Ok(ControlPlaneRouteClass::Runbook));
        assert_eq!(head.render(), Ok(ControlPlaneRenderClass::OperatorText));
        assert_eq!(
            head.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert_eq!(head.payload_len, 256);
        assert_eq!(head.request_id.as_u128_le(), 0xDEAD);
        assert_eq!(head.session_id.as_u128_le(), 0xBEEF);
        assert_eq!(head.idempotency_key.as_u128_le(), 0xCAFE);
        assert_eq!(head.normalized_request_digest, [0x7E_u8; 32]);
    }

    #[test]
    fn request_journal_record_fields_preserved() {
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
            route_class: ControlPlaneRouteClass::SecretControl,
            render_class: ControlPlaneRenderClass::OperatorText,
            visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
            flags: CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT,
            payload_len: 512,
            request_id: ControlPlaneRequestId::from_u128_le(0x10),
            session_id: ControlPlaneSessionId::from_u128_le(0x20),
            idempotency_key: ControlPlaneIdempotencyKey::from_u128_le(0x30),
            normalized_request_digest: [0x42_u8; 32],
        });
        let journal_id = ControlPlaneJournalId::from_u128_le(0x40);
        let journal = head.project_journal_record(journal_id);
        assert_eq!(
            journal.carrier(),
            Ok(ControlPlaneCarrierClass::LocalKernelUapi)
        );
        assert_eq!(journal.route(), Ok(ControlPlaneRouteClass::SecretControl));
        assert_eq!(journal.request_id.as_u128_le(), 0x10);
        assert_eq!(journal.session_id.as_u128_le(), 0x20);
        assert_eq!(journal.idempotency_key.as_u128_le(), 0x30);
        assert_eq!(journal.journal_id.as_u128_le(), 0x40);
        assert!(journal.terminal_render_receipt_id.is_zero());
        assert_eq!(journal.normalized_request_digest, [0x42_u8; 32]);
    }

    #[test]
    fn request_journal_record_with_terminal_receipt() {
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
            route_class: ControlPlaneRouteClass::Write,
            render_class: ControlPlaneRenderClass::Machine,
            visibility_class: ControlPlaneVisibilityClass::PublicRedacted,
            flags: 0,
            payload_len: 0,
            request_id: ControlPlaneRequestId::ZERO,
            session_id: ControlPlaneSessionId::ZERO,
            idempotency_key: ControlPlaneIdempotencyKey::ZERO,
            normalized_request_digest: [0_u8; 32],
        });
        let journal_id = ControlPlaneJournalId::from_u128_le(0x77);
        let terminal_id = ControlPlaneId128::from_u128_le(0x88);
        let journal = head
            .project_journal_record(journal_id)
            .with_terminal_render_receipt(terminal_id, 3);
        assert_eq!(journal.terminal_render_receipt_id.as_u128_le(), 0x88);
        assert_eq!(journal.upstream_receipt_count, 3);
    }

    #[test]
    fn response_render_receipt_exhaustive_roundtrip() {
        let receipt =
            ControlPlaneResponseRenderReceipt::new(ControlPlaneResponseRenderReceiptInput {
                receipt_id: ControlPlaneReceiptId::from_u128_le(0x1111),
                journal_id: ControlPlaneJournalId::from_u128_le(0x2222),
                route_class: ControlPlaneRouteClass::Runbook,
                render_class: ControlPlaneRenderClass::OperatorText,
                visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
                carrier_class: ControlPlaneCarrierClass::InternalKernelStub,
                response_kind: ControlPlaneResponseKind::Refusal,
                bundle_or_refusal_digest: [0x33_u8; 32],
                artifact_locator_digest: [0x44_u8; 32],
            });
        assert_eq!(receipt.receipt_id.as_u128_le(), 0x1111);
        assert_eq!(receipt.journal_id.as_u128_le(), 0x2222);
        assert_eq!(receipt.route(), Ok(ControlPlaneRouteClass::Runbook));
        assert_eq!(receipt.render(), Ok(ControlPlaneRenderClass::OperatorText));
        assert_eq!(
            receipt.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert_eq!(
            receipt.carrier(),
            Ok(ControlPlaneCarrierClass::InternalKernelStub)
        );
        assert_eq!(
            receipt.response_kind(),
            Ok(ControlPlaneResponseKind::Refusal)
        );
        assert_eq!(receipt.bundle_or_refusal_digest, [0x33_u8; 32]);
        assert_eq!(receipt.artifact_locator_digest, [0x44_u8; 32]);
    }

    #[test]
    fn route_terminal_receipt_exhaustive_roundtrip() {
        let record = ControlPlaneRouteTerminalReceiptRecord::new(
            ControlPlaneRouteTerminalReceiptRecordInput {
                terminal_receipt_id: ControlPlaneId128::from_u128_le(0xA1),
                request_id: ControlPlaneId128::from_u128_le(0xA2),
                journal_id: ControlPlaneId128::from_u128_le(0xA3),
                response_registry_receipt_id: ControlPlaneId128::from_u128_le(0xA4),
                render_receipt_id: ControlPlaneId128::from_u128_le(0xA5),
                route_class: ControlPlaneRouteClass::Session,
                response_kind: ControlPlaneResponseKind::Bundle,
                render_class: ControlPlaneRenderClass::Machine,
                visibility_class: ControlPlaneVisibilityClass::OperatorScoped,
                carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
                answer_digest: [0xB1_u8; 32],
                artifact_locator_digest: [0xB2_u8; 32],
                witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs::new(
                    ControlPlaneId128::from_u128_le(0xC1),
                    ControlPlaneId128::from_u128_le(0xC2),
                    ControlPlaneId128::from_u128_le(0xC3),
                    ControlPlaneId128::from_u128_le(0xC4),
                    [0xD1_u8; 32],
                ),
            },
        );
        assert_eq!(record.terminal_receipt_id.as_u128_le(), 0xA1);
        assert_eq!(record.request_id.as_u128_le(), 0xA2);
        assert_eq!(record.journal_id.as_u128_le(), 0xA3);
        assert_eq!(record.response_registry_receipt_id.as_u128_le(), 0xA4);
        assert_eq!(record.render_receipt_id.as_u128_le(), 0xA5);
        assert_eq!(record.route(), Ok(ControlPlaneRouteClass::Session));
        assert_eq!(record.response_kind(), Ok(ControlPlaneResponseKind::Bundle));
        assert_eq!(record.render(), Ok(ControlPlaneRenderClass::Machine));
        assert_eq!(
            record.visibility(),
            Ok(ControlPlaneVisibilityClass::OperatorScoped)
        );
        assert_eq!(
            record.carrier(),
            Ok(ControlPlaneCarrierClass::LocalKernelUapi)
        );
        assert_eq!(record.answer_digest, [0xB1_u8; 32]);
        assert_eq!(record.artifact_locator_digest, [0xB2_u8; 32]);
        assert!(record.has_witness_join());
        assert_eq!(record.witness_refs.policy_witness_id.as_u128_le(), 0xC2);
        assert_eq!(record.witness_refs.budget_witness_id.as_u128_le(), 0xC3);
        assert_eq!(record.witness_refs.recipe_witness_id.as_u128_le(), 0xC4);
    }

    #[test]
    fn route_terminal_receipt_without_witness_join() {
        let record = ControlPlaneRouteTerminalReceiptRecord::new(
            ControlPlaneRouteTerminalReceiptRecordInput {
                terminal_receipt_id: ControlPlaneId128::ZERO,
                request_id: ControlPlaneId128::ZERO,
                journal_id: ControlPlaneId128::ZERO,
                response_registry_receipt_id: ControlPlaneId128::ZERO,
                render_receipt_id: ControlPlaneId128::ZERO,
                route_class: ControlPlaneRouteClass::Session,
                response_kind: ControlPlaneResponseKind::Bundle,
                render_class: ControlPlaneRenderClass::Machine,
                visibility_class: ControlPlaneVisibilityClass::PublicRedacted,
                carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
                answer_digest: [0_u8; 32],
                artifact_locator_digest: [0_u8; 32],
                witness_refs: ControlPlanePolicyBudgetRecipeWitnessRefs::ZERO,
            },
        );
        assert!(!record.has_witness_join());
    }

    #[test]
    fn write_manual_product_admission_exhaustive_roundtrip() {
        let payload = ControlPlaneWriteManualProductAdmissionPayload::new(
            0x3,
            [0x51_u8; 32],
            [0x52_u8; 32],
            ControlPlaneId128::from_u128_le(0x600D),
            ControlPlaneId128::from_u128_le(0xF00D),
        );
        assert_eq!(
            payload.kind(),
            Ok(ControlPlaneWriteRequestKind::ProductAdmissionManual)
        );
        assert_eq!(payload.flags, 0x3);
        assert_eq!(payload.product_recipe_digest, [0x51_u8; 32]);
        assert_eq!(payload.subject_scope_digest, [0x52_u8; 32]);
        assert_eq!(payload.required_anchor_set_id.as_u128_le(), 0x600D);
        assert_eq!(payload.budget_domain_id.as_u128_le(), 0xF00D);
    }

    // ── ControlPlaneId128 exhaustive roundtrip ─────────────────────────

    #[test]
    fn control_plane_id_all_zeros_roundtrip() {
        let id = ControlPlaneId128::ZERO;
        assert!(id.is_zero());
        assert_eq!(id.as_u128_le(), 0);
        let re = ControlPlaneId128::from_u128_le(0);
        assert_eq!(re.0, id.0);
    }

    #[test]
    fn control_plane_id_all_ones_roundtrip() {
        let val = u128::MAX;
        let id = ControlPlaneId128::from_u128_le(val);
        assert_eq!(id.as_u128_le(), val);
        assert!(!id.is_zero());
    }

    #[test]
    fn control_plane_id_alternating_bits_roundtrip() {
        let val = 0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000_1111_u128;
        let id = ControlPlaneId128::from_u128_le(val);
        assert_eq!(id.as_u128_le(), val);
        let decoded_id = ControlPlaneId128::from_u128_le(id.as_u128_le());
        assert_eq!(decoded_id.0, id.0);
    }

    #[test]
    fn control_plane_id_preserves_byte_order() {
        let id = ControlPlaneId128([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        let roundtripped = ControlPlaneId128::from_u128_le(id.as_u128_le());
        assert_eq!(roundtripped.0, id.0);
    }

    // ── Enum / class validation edge cases ─────────────────────────────

    #[test]
    fn try_from_u32_accepts_only_valid_variants() {
        let valid_routes = [0_u32, 1, 2, 3, 4, 5];
        let valid_carriers = [0_u32, 1, 2];
        let valid_renders = [0_u32, 1];
        let valid_visibilities = [0_u32, 1];
        let valid_responses = [0_u32, 1];
        for v in &valid_routes {
            assert!(ControlPlaneRouteClass::try_from(*v).is_ok());
        }
        assert!(ControlPlaneRouteClass::try_from(99_u32).is_err());
        for v in &valid_carriers {
            assert!(ControlPlaneCarrierClass::try_from(*v).is_ok());
        }
        assert!(ControlPlaneCarrierClass::try_from(99_u32).is_err());
        for v in &valid_renders {
            assert!(ControlPlaneRenderClass::try_from(*v).is_ok());
        }
        assert!(ControlPlaneRenderClass::try_from(99_u32).is_err());
        for v in &valid_visibilities {
            assert!(ControlPlaneVisibilityClass::try_from(*v).is_ok());
        }
        assert!(ControlPlaneVisibilityClass::try_from(99_u32).is_err());
        for v in &valid_responses {
            assert!(ControlPlaneResponseKind::try_from(*v).is_ok());
        }
        assert!(ControlPlaneResponseKind::try_from(99_u32).is_err());
    }

    // ── Flag combination boundary tests ────────────────────────────────

    #[test]
    fn request_envelope_head_no_flags() {
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
            route_class: ControlPlaneRouteClass::Session,
            render_class: ControlPlaneRenderClass::Machine,
            visibility_class: ControlPlaneVisibilityClass::PublicRedacted,
            flags: 0,
            payload_len: 0,
            request_id: ControlPlaneRequestId::ZERO,
            session_id: ControlPlaneSessionId::ZERO,
            idempotency_key: ControlPlaneIdempotencyKey::ZERO,
            normalized_request_digest: [0_u8; 32],
        });
        assert!(!head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(!head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(!head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(!head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert_eq!(head.payload_len, 0);
    }

    #[test]
    fn request_envelope_head_all_flags() {
        let all_flags = CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT
            | CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT
            | CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT
            | CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT;
        let head = ControlPlaneRequestEnvelopeHead::new(ControlPlaneRequestEnvelopeHeadInput {
            carrier_class: ControlPlaneCarrierClass::LocalKernelUapi,
            route_class: ControlPlaneRouteClass::Session,
            render_class: ControlPlaneRenderClass::Machine,
            visibility_class: ControlPlaneVisibilityClass::PublicRedacted,
            flags: all_flags,
            payload_len: u32::MAX,
            request_id: ControlPlaneRequestId::from_u128_le(u128::MAX),
            session_id: ControlPlaneSessionId::from_u128_le(u128::MAX),
            idempotency_key: ControlPlaneIdempotencyKey::from_u128_le(u128::MAX),
            normalized_request_digest: [0xFF_u8; 32],
        });
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert!(head.has_flag(CONTROL_PLANE_REQUEST_FLAG_IDEMPOTENT));
        assert_eq!(head.payload_len, u32::MAX);
        assert_eq!(head.request_id.as_u128_le(), u128::MAX);
    }

    // ── Record default / zero-value tests ──────────────────────────────

    #[test]
    fn witness_refs_default_is_zero() {
        let w = ControlPlanePolicyBudgetRecipeWitnessRefs::default();
        assert!(!w.has_join());
        assert!(w.witness_join_id.is_zero());
        assert!(w.policy_witness_id.is_zero());
        assert!(w.budget_witness_id.is_zero());
        assert!(w.recipe_witness_id.is_zero());
        assert_eq!(w.witness_join_digest, [0_u8; 32]);
    }

    #[test]
    fn truth_recall_lookup_request_record_default() {
        let r = ControlPlaneTruthRecallLookupRequestRecord::default();
        assert_eq!(r.route(), Ok(ControlPlaneRouteClass::Session));
        assert_eq!(r.retention_class, 0);
        assert_eq!(
            r.disclosure_filter_or_any,
            CONTROL_PLANE_TRUTH_RECALL_LOOKUP_DISCLOSURE_FILTER_ANY
        );
        assert_eq!(r.index_key_digest, [0_u8; 32]);
    }

    #[test]
    fn control_plane_id_ordering_and_equality() {
        let a = ControlPlaneId128::from_u128_le(1);
        let b = ControlPlaneId128::from_u128_le(2);
        let a2 = ControlPlaneId128::from_u128_le(1);
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(a < b);
    }

    #[test]
    fn decode_error_invalid_route_variant() {
        let err = ControlPlaneRecordDecodeError::InvalidRouteClass(99);
        match err {
            ControlPlaneRecordDecodeError::InvalidRouteClass(v) => assert_eq!(v, 99),
            _ => panic!("wrong variant"),
        }
    }
}
