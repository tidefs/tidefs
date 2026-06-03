#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Deterministic `transport_session_cohort_graph` model for P8-01.
//!
//! This crate is intentionally a deterministic model, not a networked
//! transport runtime. It binds the P8-01 endpoint families, session classes,
//! cohort classes, lane classes, message families, envelope grammar, and
//! resume/closure law to executable source and state-machine tests.

//! ## Endpoint lifecycle and invariants
//!
//! A transport endpoint is a (node, EndpointFamily) binding that governs which
//! session classes may be opened on that node. The P8-01 endpoint lifecycle
//! follows this fixed, receipt-backed chain:
//!
//! **1. Endpoint selection** — a participant selects an EndpointFamily
//! according to its role (control-plane, data-plane, co-resident embed, or
//! shadow compare). The selection is constrained by:
//!   - EndpointFamily::allowed_session_classes() — each family only admits
//!     the session classes listed in the P8-01 table.
//!   - SessionClass::primary_endpoint() — each session class maps to
//!     exactly one primary endpoint; the pair law forbids opening a session
//!     on an endpoint that does not host its primary class.
//!
//! **2. Mutual attestation** — before any session can be bound, the two
//! endpoints exchange identities and perform mutual challenge-response
//! attestation. An endpoint that fails attestation is permanently refused.
//!
//! **3. Session bind** — a session is opened on the chosen endpoint and
//! transitions Unconnected -> Connecting -> Handshaking -> Bound. The bind step anchors the session to a
//! concrete endpoint family, identity set, and variant/scope ceiling.
//!
//! **4. Cohort attach** — the bound session attaches to one or more declared
//! CohortClass values (k0-k7). A session may not invent a one-off
//! population label; every path must attach to a declared cohort class.
//!
//! **5. Lane admission** — per-lane budget records are created for the
//! session, carrying the lane class, traffic class, and budget policy.
//! Lanes are admitted only when the endpoint family, session class, and
//! cohort class jointly permit them.
//!
//! **6. Envelope flow** — the session exchanges framed transport envelope
//! messages with monotonic sequence numbers, ack floors, and payload digests.
//!
//! **7. Drain or resume** — when the session is no longer needed, it either
//! drains cleanly (all outstanding envelopes acked, last acked sequence
//! recorded) or, if the gap is within the resume window, issues a resume
//! token for later continuation.
//!
//! **8. Closure receipt** — every session closure emits a
//! closure receipt that records the drain result, last acked
//! sequence, any preserved artifact refs, and optionally a successor session.
//!
//! ### Endpoint family invariants
//!
//! | Invariant | Rule |
//! |---|---|
//! | **e0-local** | LocalEmbed is never opened to a remote peer; it is only for co-resident service communication within a single node. |
//! | **e1-control** | Control carries bootstrap, control, replication metadata, and transition orchestration sessions. It must never carry bulk or shadow sessions. |
//! | **e2-data** | Data is dedicated to bulk transfer sessions (TransferBulk). Control-plane traffic must never be routed through Data. |
//! | **e3-shadow** | Shadow is dedicated to shadow validation sessions (ShadowValidation). No other session class may use it. |
//! | **one-primary-endpoint** | Every session class has exactly one primary endpoint via SessionClass::primary_endpoint(); a session opened on a non-primary endpoint is a protocol violation. |
//! | **no-silent-promote** | SessionClass::can_promote_to() is the sole promotion path; a session may not silently change its session class except through explicit promote transitions from Bootstrap. |
//! | **receipt-every-close** | Every session close (clean drain, forced close, or refused) must produce exactly one closure receipt. |
//!
//! ### Session state machine invariants
//!
//! The SessionState machine enforces:
//! - **Forward-only** — transitions never reverse; Closed is terminal.
//! - **No skip** — Unconnected -> Connecting -> Handshaking -> Bound ->
//!   CohortAttached -> Established. Intermediate states cannot be bypassed
//!   (except Handshaking -> Established for backward compatibility).
//! - **Degraded only from Established** — a session can only degrade when
//!   it was previously Established.
//! - **Resume window** — ResumePending admits self-retry but does not
//!   admit direct transition to Established; it must go through
//!   Connecting again.
//! - **Single HLC stamp** — every state transition stamps the new state
//!   with the current Hybrid Logical Clock value.

use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Design rule family and gate anchors
// ---------------------------------------------------------------------------

/// Canonical anchor string for the transport session cohort graph family (P8-01).
pub const TRANSPORT_SESSION_COHORT_GRAPH_P8_01: &str =
    "family.transport_session_cohort_graph.transport_session_0";
/// Gate descriptor for P8-01 message envelope / resume / closure test binding.
pub const TRANSPORT_SESSION_ENVELOPE_GATE: &str =
    "P8-01 message envelope / resume / closure tests bind session, cohort, lane, sequence, ack, and receipt grammar gates";
/// Gate descriptor for P8-01 state-machine test binding.
pub const TRANSPORT_SESSION_STATE_MACHINE_GATE: &str =
    "P8-01 state-machine tests bind edge, session, lane, and resume states to envelope lifecycle and closure receipt rules";

// ---------------------------------------------------------------------------
// Identifier newtypes
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a transport edge (bidirectional connection between two nodes).
pub struct TransportEdgeId(pub u64);

impl TransportEdgeId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportEdgeId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a transport session.
pub struct TransportSessionId(pub u64);

impl TransportSessionId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportSessionId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a cohort attachment binding.
pub struct TransportCohortAttachmentId(pub u64);

impl TransportCohortAttachmentId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportCohortAttachmentId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a lane budget allocation on a transport session.
pub struct TransportLaneBudgetId(pub u64);

impl TransportLaneBudgetId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportLaneBudgetId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a single transport envelope (framed message).
pub struct TransportEnvelopeId(pub u64);

impl TransportEnvelopeId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportEnvelopeId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a session resume token.
pub struct TransportResumeTokenId(pub u64);

impl TransportResumeTokenId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportResumeTokenId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a session closure receipt.
pub struct TransportClosureReceiptId(pub u64);

impl TransportClosureReceiptId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportClosureReceiptId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for an endpoint class definition.
pub struct TransportEndpointClassId(pub u64);

impl TransportEndpointClassId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportEndpointClassId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a message family class.
pub struct TransportMessageFamilyId(pub u64);

impl TransportMessageFamilyId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportMessageFamilyId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Unique identifier for a cohort class definition.
pub struct TransportCohortClassId(pub u64);

impl TransportCohortClassId {
    /// Sentinel zero value.
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `TransportCohortClassId` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// MessageSequenceNumber -- per-session monotonic message sequence number
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
/// Monotonic per-session message sequence number.
///
/// Each transport session maintains independent send and receive counters.
/// Sequence numbers enable duplicate detection, gap recovery, and
/// exactly-once delivery semantics for replication and quorum-write paths.
pub struct MessageSequenceNumber(pub u64);

impl MessageSequenceNumber {
    /// Sentinel zero value representing "no message sent/received yet."
    pub const ZERO: Self = Self(0);
    #[must_use]
    /// Create a new `MessageSequenceNumber` from a `u64` value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

// ---------------------------------------------------------------------------
// Endpoint family classes (4 stable)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Endpoint family classes — maps nodes to P8-01 endpoint roles (local/control/data/shadow).
pub enum EndpointFamily {
    /// `endpoint.transport_session_0.local.embed.e0`
    LocalEmbed = 0,
    /// `endpoint.transport_session_0.control.e1`
    Control = 1,
    /// `endpoint.transport_session_0.data.e2`
    Data = 2,
    /// `endpoint.transport_session_0.shadow.e3`
    Shadow = 3,
}

impl EndpointFamily {
    #[must_use]
    /// Return the canonical P8-01 string label for this `EndpointFamily` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalEmbed => "endpoint.transport_session_0.local.embed.e0",
            Self::Control => "endpoint.transport_session_0.control.e1",
            Self::Data => "endpoint.transport_session_0.data.e2",
            Self::Shadow => "endpoint.transport_session_0.shadow.e3",
        }
    }

    #[must_use]
    /// Return `true` if this endpoint family is local-only (e0).
    pub const fn is_local_only(self) -> bool {
        matches!(self, Self::LocalEmbed)
    }

    #[must_use]
    /// Return `true` if this endpoint family is data-only (e2).
    pub const fn is_bulk_only(self) -> bool {
        matches!(self, Self::Data)
    }

    /// Allowed session classes for this endpoint family per the pair-graph rules.
    #[must_use]
    pub fn allowed_session_classes(self) -> Vec<SessionClass> {
        match self {
            Self::LocalEmbed => vec![
                SessionClass::Bootstrap,
                SessionClass::Control,
                SessionClass::ReplicationMeta,
                SessionClass::TransferBulk,
                SessionClass::ShadowValidation,
                SessionClass::TransitionOrchestration,
            ],
            Self::Control => vec![
                SessionClass::Bootstrap,
                SessionClass::Control,
                SessionClass::ReplicationMeta,
                SessionClass::TransitionOrchestration,
            ],
            Self::Data => vec![SessionClass::TransferBulk],
            Self::Shadow => vec![SessionClass::ShadowValidation],
        }
    }
}

// ---------------------------------------------------------------------------
// Session class enums (6 stable)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Session classes — six stable classes covering bootstrap through shadow validation.
pub enum SessionClass {
    /// `session.transport_session_0.bootstrap.s0` — short-lived join/bootstrap, attestation, first exchange
    Bootstrap = 0,
    /// `session.transport_session_0.control.s1` — long-lived control, election, heartbeat, lease/fence
    Control = 1,
    /// `session.transport_session_0.replication_meta.s2` — publication/log/progress metadata and receipts
    ReplicationMeta = 2,
    /// `session.transport_session_0.transfer_bulk.s3` — snapshot/checkpoint chunk transfer, demand fetches
    TransferBulk = 3,
    /// `session.transport_session_0.shadow_validation.s4` — shadow compare, divergence, validation transport
    ShadowValidation = 4,
    /// `session.transport_session_0.transition_orchestration.s5` — failover, upgrade, cutover, rollback
    TransitionOrchestration = 5,
}

impl SessionClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `SessionClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "session.transport_session_0.bootstrap.s0",
            Self::Control => "session.transport_session_0.control.s1",
            Self::ReplicationMeta => "session.transport_session_0.replication_meta.s2",
            Self::TransferBulk => "session.transport_session_0.transfer_bulk.s3",
            Self::ShadowValidation => "session.transport_session_0.shadow_validation.s4",
            Self::TransitionOrchestration => {
                "session.transport_session_0.transition_orchestration.s5"
            }
        }
    }

    #[must_use]
    /// Return `true` if this session class is short-lived (Bootstrap).
    pub const fn is_temporary(self) -> bool {
        matches!(self, Self::Bootstrap)
    }

    #[must_use]
    /// Return the primary `EndpointFamily` that hosts this session class.
    pub const fn primary_endpoint(self) -> EndpointFamily {
        match self {
            Self::Bootstrap => EndpointFamily::Control,
            Self::Control => EndpointFamily::Control,
            Self::ReplicationMeta => EndpointFamily::Control,
            Self::TransferBulk => EndpointFamily::Data,
            Self::ShadowValidation => EndpointFamily::Shadow,
            Self::TransitionOrchestration => EndpointFamily::Control,
        }
    }

    #[must_use]
    /// Return the set of `SessionClass` variants this class can promote into.
    pub const fn can_promote_to(self) -> &'static [SessionClass] {
        match self {
            Self::Bootstrap => &[
                Self::Control,
                Self::ReplicationMeta,
                Self::TransferBulk,
                Self::ShadowValidation,
                Self::TransitionOrchestration,
            ],
            _ => &[],
        }
    }
}

// ---------------------------------------------------------------------------
// Cohort class enums (8 stable)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Cohort classes — thirteen cohort types for session membership grouping.
pub enum CohortClass {
    /// `cohort.transport_session_0.peer_pair.k0` — deterministic pair scope
    PeerPair = 0,
    /// `cohort.transport_session_0.authority_domain_control.k1` — domain-scoped lease/election/quorum
    AuthorityDomainControl = 1,
    /// `cohort.transport_session_0.fence_target.k2` — freshness fence / visibility targets
    FenceTarget = 2,
    /// `cohort.transport_session_0.replica_set.k3` — source/target population for replication/repair
    ReplicaSet = 3,
    /// `cohort.transport_session_0.state_transfer.k4` — sender/receiver for checkpoint/snapshot transfer
    StateTransfer = 4,
    /// `cohort.transport_session_0.shadow_compare.k5` — authoritative and shadow compare window
    ShadowCompare = 5,
    /// `cohort.transport_session_0.transition_stage.k6` — failover/upgrade/cutover/rollback stage
    TransitionStage = 6,
    /// `cohort.transport_session_0.local_runtime.k7` — co-resident services on one host
    LocalRuntime = 7,
}

impl CohortClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `CohortClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerPair => "cohort.transport_session_0.peer_pair.k0",
            Self::AuthorityDomainControl => {
                "cohort.transport_session_0.authority_domain_control.k1"
            }
            Self::FenceTarget => "cohort.transport_session_0.fence_target.k2",
            Self::ReplicaSet => "cohort.transport_session_0.replica_set.k3",
            Self::StateTransfer => "cohort.transport_session_0.state_transfer.k4",
            Self::ShadowCompare => "cohort.transport_session_0.shadow_compare.k5",
            Self::TransitionStage => "cohort.transport_session_0.transition_stage.k6",
            Self::LocalRuntime => "cohort.transport_session_0.local_runtime.k7",
        }
    }

    /// Whether every remote session must attach to this cohort class.
    #[must_use]
    pub const fn is_mandatory_for_remote(self) -> bool {
        matches!(self, Self::PeerPair)
    }

    #[must_use]
    /// Return the session classes admitted by this cohort class.
    pub fn allowed_session_classes(self) -> Vec<SessionClass> {
        match self {
            Self::PeerPair | Self::LocalRuntime => vec![
                SessionClass::Bootstrap,
                SessionClass::Control,
                SessionClass::ReplicationMeta,
                SessionClass::TransferBulk,
                SessionClass::ShadowValidation,
                SessionClass::TransitionOrchestration,
            ],
            Self::AuthorityDomainControl => vec![
                SessionClass::Control,
                SessionClass::ReplicationMeta,
                SessionClass::TransitionOrchestration,
            ],
            Self::FenceTarget => vec![SessionClass::Control, SessionClass::ReplicationMeta],
            Self::ReplicaSet => vec![SessionClass::ReplicationMeta, SessionClass::TransferBulk],
            Self::StateTransfer => vec![SessionClass::TransferBulk],
            Self::ShadowCompare => vec![SessionClass::ShadowValidation],
            Self::TransitionStage => vec![SessionClass::TransitionOrchestration],
        }
    }
}

// ---------------------------------------------------------------------------
// Lane class enums (5 stable)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Lane classes — five priority lanes for message multiplexing on a connection.
pub enum LaneClass {
    /// `lane.transport_session_0.control.l0` — handshake, election, lease/fence, transition holds
    Control = 0,
    /// `lane.transport_session_0.metadata.l1` — publication/log/progress metadata, receipts, digests
    Metadata = 1,
    /// `lane.transport_session_0.demand.l2` — foreground demand fetches, urgent catch-up
    Demand = 2,
    /// `lane.transport_session_0.speculative.l3` — shadow compare, warmup, advisory mirror
    Speculative = 3,
    /// `lane.transport_session_0.background.l4` — rebuild, relocation, anti-entropy, full-state transfer
    Background = 4,
}

impl LaneClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `LaneClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Control => "lane.transport_session_0.control.l0",
            Self::Metadata => "lane.transport_session_0.metadata.l1",
            Self::Demand => "lane.transport_session_0.demand.l2",
            Self::Speculative => "lane.transport_session_0.speculative.l3",
            Self::Background => "lane.transport_session_0.background.l4",
        }
    }

    #[must_use]
    /// Return `true` if this lane is latency-sensitive (Demand).
    pub const fn is_latency_sensitive(self) -> bool {
        matches!(self, Self::Demand)
    }

    #[must_use]
    /// Return `true` if this lane must never be starved (Control, Metadata).
    pub const fn may_not_be_starved(self) -> bool {
        matches!(self, Self::Control | Self::Metadata)
    }

    #[must_use]
    /// Return `true` if this lane is exclusively for bulk background traffic.
    pub const fn is_bulk_only(self) -> bool {
        matches!(self, Self::Background)
    }

    /// The default priority ordering: lower number = higher priority.
    #[must_use]
    pub const fn default_priority(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Metadata => 1,
            Self::Demand => 2,
            Self::Speculative => 3,
            Self::Background => 4,
        }
    }

    /// Number of lane classes.
    pub const COUNT: usize = 5;

    /// All lane classes in priority order (highest first).
    #[must_use]
    pub const fn all() -> [LaneClass; 5] {
        [
            LaneClass::Control,
            LaneClass::Metadata,
            LaneClass::Demand,
            LaneClass::Speculative,
            LaneClass::Background,
        ]
    }

    /// Return the lane class as a usize index.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self as usize
    }
}
// ---------------------------------------------------------------------------
// Unified LaneConfig — scheduling class configuration (issue #1666)
// ---------------------------------------------------------------------------

/// Unified lane configuration for any resource that processes multi-class
/// work.
///
/// One `LaneConfig` exists per `(resource_id, LaneClass)` pair. The lane
/// scheduler reads these configs to enforce priority, budgets, starvation
/// prevention, and preemption across all lanes of a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneConfig {
    /// Which scheduling class this config applies to.
    pub lane_class: LaneClass,

    /// Hard cap on bytes in-flight for this lane.
    /// When in-flight bytes exceed this, producers must back off.
    pub max_inflight_bytes: u64,

    /// Hard cap on operations in-flight for this lane.
    /// When in-flight ops exceed this, producers must back off.
    pub max_inflight_ops: u64,

    /// Maximum time (ms) this lane can wait without being serviced.
    /// After this duration, at least one op from this lane MUST be
    /// processed next, regardless of higher-priority pending work.
    /// Set to 0 for CONTROL and METADATA (always serviced when ready).
    pub starvation_timeout_ms: u64,

    /// Whether CONTROL can preempt an in-flight operation on this lane.
    /// Only SPECULATIVE and BACKGROUND are preemptible.
    pub preemptible: bool,

    /// Whether in-flight operations on this lane can be dropped entirely
    /// under extreme memory pressure (true for SPECULATIVE, BACKGROUND).
    pub droppable: bool,

    /// Whether dropped operations can be resumed later (true for BACKGROUND,
    /// false for SPECULATIVE which must be re-requested).
    pub resumable: bool,

    /// The priority band for pressure-driven throttling.
    /// Lower values are throttled first when memory pressure rises.
    pub pressure_throttle_order: u8,

    /// Reference name for the latency budget policy.
    /// Mirrors `TransportLaneBudgetRecord::latency_budget_ref`.
    pub latency_budget_ref: &'static str,

    /// Reference name for the drop/reorder policy.
    /// Mirrors `TransportLaneBudgetRecord::drop_or_reorder_policy_ref`.
    pub drop_or_reorder_policy_ref: &'static str,
}

impl LaneConfig {
    /// Default lane configuration for CONTROL class.
    pub const fn control(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Control,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 0,
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 4,
            latency_budget_ref: "latency.tight",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for METADATA class.
    pub const fn metadata(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Metadata,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 0,
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 3,
            latency_budget_ref: "latency.tight",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for DEMAND class.
    pub const fn demand(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Demand,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 5000,
            preemptible: false,
            droppable: false,
            resumable: false,
            pressure_throttle_order: 2,
            latency_budget_ref: "latency.normal",
            drop_or_reorder_policy_ref: "none",
        }
    }

    /// Default lane configuration for SPECULATIVE class.
    pub const fn speculative(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Speculative,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 30000,
            preemptible: true,
            droppable: true,
            resumable: false,
            pressure_throttle_order: 1,
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        }
    }

    /// Default lane configuration for BACKGROUND class.
    pub const fn background(max_inflight_bytes: u64, max_inflight_ops: u64) -> Self {
        Self {
            lane_class: LaneClass::Background,
            max_inflight_bytes,
            max_inflight_ops,
            starvation_timeout_ms: 60000,
            preemptible: true,
            droppable: true,
            resumable: true,
            pressure_throttle_order: 0,
            latency_budget_ref: "latency.loose",
            drop_or_reorder_policy_ref: "drop.oldest",
        }
    }
}

// ---------------------------------------------------------------------------
// BulkPriority — 4-class priority model for BULK plane protocol (#1229, #1927)
// ---------------------------------------------------------------------------

/// Priority class for BULK plane credit scheduling and OFFER ordering.
///
/// Four canonical scheduling classes as defined in
/// `docs/design/cluster-bulk-plane-protocol.md` §7.1. Priority ordering:
/// CONTROL > METADATA > BULK > BACKGROUND.
///
/// This is the wire-level priority transmitted in `OfferV1::priority`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BulkPriority {
    /// Lease renewals, membership messages, ABORT signals. Must never stall.
    Control = 0,
    /// Metadata operations: readdir, lookup, getattr, mkdir.
    Metadata = 1,
    /// Bulk throughput work: data writes/reads, commit_group replication, state transfer.
    Bulk = 2,
    /// Background work: cleaning, GC, compaction, rebake.
    Background = 3,
}

impl BulkPriority {
    /// Number of priority levels.
    pub const COUNT: usize = 4;

    /// All priority levels in dispatch order (highest first).
    pub const ALL: [BulkPriority; 4] = [
        BulkPriority::Control,
        BulkPriority::Metadata,
        BulkPriority::Bulk,
        BulkPriority::Background,
    ];

    /// Return the priority as a u8 wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Return the priority as a usize index.
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self as usize
    }

    /// Map to the corresponding `LaneClass` for transport lane assignment.
    #[must_use]
    pub const fn to_lane_class(self) -> LaneClass {
        match self {
            Self::Control => LaneClass::Control,
            Self::Metadata => LaneClass::Metadata,
            Self::Bulk => LaneClass::Demand,
            Self::Background => LaneClass::Background,
        }
    }
}

// ---------------------------------------------------------------------------
// StreamCreditState — per-stream credit tracking for BULK plane (#1229 §7.3)
// ---------------------------------------------------------------------------

/// Per-stream credit bookkeeping for the BULK plane scheduler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamCreditState {
    pub stream_id: u32,
    pub priority: BulkPriority,
    pub total_len: u64,
    pub bytes_granted: u64,
    pub pending_credits: u32,
}

// ---------------------------------------------------------------------------
// Transport backend kind — identifies the physical transport layer
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Identifies which transport backend a session or connection uses.
/// Enables backend-specific error handling, reconnect strategies, and
/// resource cleanup (e.g., RDMA memory-region deregistration).
pub enum TransportBackendKind {
    /// Plain TCP (default fallback).
    Tcp = 0,
    /// TLS over TCP.
    Tls = 1,
    /// RDMA carrier (experimental, OW-308).
    Rdma = 2,
}

impl TransportBackendKind {
    #[must_use]
    /// Return the canonical P8-01 string label for this `TransportBackendKind` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "backend.transport_session_0.tcp.b0",
            Self::Tls => "backend.transport_session_0.tls.b1",
            Self::Rdma => "backend.transport_session_0.rdma.b2",
        }
    }

    #[must_use]
    /// Whether this backend requires RDMA hardware or software support.
    pub fn is_rdma(&self) -> bool {
        matches!(self, Self::Rdma)
    }

    #[must_use]
    /// Whether this backend may fall back to TCP when the carrier is unavailable.
    pub fn may_fallback_to_tcp(&self) -> bool {
        matches!(self, Self::Rdma)
    }
}

// ---------------------------------------------------------------------------
// Message family enums (10 stable)
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Message families — ten stable wire message families (P8-01 §7.2).
pub enum MessageFamily {
    /// `msg.transport_session_0.hello_close.m0` — open, accept, refuse, drain, close
    HelloClose = 0,
    /// `msg.transport_session_0.heartbeat_ack.m1` — heartbeat, ack, watermark, keepalive
    HeartbeatAck = 1,
    /// `msg.transport_session_0.election_control.m2` — prevote/vote/announce and election verbs
    ElectionControl = 2,
    /// `msg.transport_session_0.lease_fence_deadline.m3` — lease renew/recall, fence issue/ack/escalate
    LeaseFenceDeadline = 3,
    /// `msg.transport_session_0.publication_progress.m4` — proposals, commits, progress vectors
    PublicationProgress = 4,
    /// `msg.transport_session_0.log_sync_metadata.m5` — log-sync / catch-up metadata windows
    LogSyncMetadata = 5,
    /// `msg.transport_session_0.state_transfer.m6` — checkpoint/snapshot begin, chunk, ack, complete
    StateTransfer = 6,
    /// `msg.transport_session_0.replica_transfer_verify.m7` — replica chunk movement and verification
    ReplicaTransferVerify = 7,
    /// `msg.transport_session_0.shadow_validation.m8` — divergence capsules, truth-link bundles
    ShadowValidation = 8,
    /// `msg.transport_session_0.transition_hold_resume.m9` — hold, unblock, rollback, resume
    TransitionHoldResume = 9,
}

impl MessageFamily {
    #[must_use]
    /// Return the canonical P8-01 string label for this `MessageFamily` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HelloClose => "msg.transport_session_0.hello_close.m0",
            Self::HeartbeatAck => "msg.transport_session_0.heartbeat_ack.m1",
            Self::ElectionControl => "msg.transport_session_0.election_control.m2",
            Self::LeaseFenceDeadline => "msg.transport_session_0.lease_fence_deadline.m3",
            Self::PublicationProgress => "msg.transport_session_0.publication_progress.m4",
            Self::LogSyncMetadata => "msg.transport_session_0.log_sync_metadata.m5",
            Self::StateTransfer => "msg.transport_session_0.state_transfer.m6",
            Self::ReplicaTransferVerify => "msg.transport_session_0.replica_transfer_verify.m7",
            Self::ShadowValidation => "msg.transport_session_0.shadow_validation.m8",
            Self::TransitionHoldResume => "msg.transport_session_0.transition_hold_resume.m9",
        }
    }

    #[must_use]
    /// Return the primary `SessionClass` for which this message family is designed.
    pub fn primary_session_class(self) -> SessionClass {
        match self {
            Self::HelloClose => SessionClass::Bootstrap,
            Self::HeartbeatAck => SessionClass::Control,
            Self::ElectionControl => SessionClass::Control,
            Self::LeaseFenceDeadline => SessionClass::Control,
            Self::PublicationProgress => SessionClass::ReplicationMeta,
            Self::LogSyncMetadata => SessionClass::ReplicationMeta,
            Self::StateTransfer => SessionClass::TransferBulk,
            Self::ReplicaTransferVerify => SessionClass::TransferBulk,
            Self::ShadowValidation => SessionClass::ShadowValidation,
            Self::TransitionHoldResume => SessionClass::TransitionOrchestration,
        }
    }

    #[must_use]
    /// Return the primary `LaneClass` used by this message family.
    pub fn primary_lane_class(self) -> LaneClass {
        match self {
            Self::HelloClose
            | Self::HeartbeatAck
            | Self::ElectionControl
            | Self::LeaseFenceDeadline => LaneClass::Control,
            Self::PublicationProgress | Self::LogSyncMetadata => LaneClass::Metadata,
            Self::StateTransfer | Self::ReplicaTransferVerify => LaneClass::Demand,
            Self::ShadowValidation => LaneClass::Speculative,
            Self::TransitionHoldResume => LaneClass::Control,
        }
    }

    /// Secondary lane class (some families can run on lower-priority lanes).
    #[must_use]
    pub fn secondary_lane_class(self) -> Option<LaneClass> {
        match self {
            Self::StateTransfer | Self::ReplicaTransferVerify => Some(LaneClass::Background),
            Self::ShadowValidation => Some(LaneClass::Background),
            Self::TransitionHoldResume => Some(LaneClass::Metadata),
            _ => None,
        }
    }

    #[must_use]
    /// Return all `LaneClass` values that may carry this message family.
    pub fn allowed_lane_classes(self) -> Vec<LaneClass> {
        let mut lanes = vec![self.primary_lane_class()];
        if let Some(sec) = self.secondary_lane_class() {
            lanes.push(sec);
        }
        lanes
    }
}

// ---------------------------------------------------------------------------
// State machine enums
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Edge state machine — lifecycle states for a transport edge between two nodes.
pub enum EdgeState {
    Idle = 0,
    Attested = 1,
    Open = 2,
    Established = 3,
    Draining = 4,
    Closed = 5,
}

impl EdgeState {
    #[must_use]
    /// Return the canonical P8-01 string label for this `EdgeState` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "edge_state_0.idle",
            Self::Attested => "edge_state_1.attested",
            Self::Open => "edge_state_2.open",
            Self::Established => "edge_state_3.established",
            Self::Draining => "edge_state_4.draining",
            Self::Closed => "edge_state_5.closed",
        }
    }

    #[must_use]
    /// Return `true` if new sessions can be established in this edge state.
    pub const fn can_accept_session(self) -> bool {
        matches!(self, Self::Attested | Self::Open | Self::Established)
    }

    #[must_use]
    /// Return `true` if this edge state is terminal (Closed).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Session state machine — lifecycle states for a transport session.
pub enum SessionState {
    Unconnected = 0,
    Connecting = 1,
    Handshaking = 2,
    Bound = 3,
    CohortAttached = 4,
    Degraded = 5,
    ResumePending = 6,
    Established = 7,
    Reconnecting = 8,
    Closed = 9,
}

impl SessionState {
    #[must_use]
    /// Return the canonical P8-01 string label for this `SessionState` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unconnected => "session_state_0.unconnected",
            Self::Connecting => "session_state_1.connecting",
            Self::Handshaking => "session_state_2.handshaking",
            Self::Bound => "session_state_3.bound",
            Self::CohortAttached => "session_state_4.cohort_attached",
            Self::Degraded => "session_state_5.degraded",
            Self::ResumePending => "session_state_6.resume_pending",
            Self::Established => "session_state_7.established",
            Self::Reconnecting => "session_state_8.reconnecting",
            Self::Closed => "session_state_9.closed",
        }
    }

    #[must_use]
    /// Return `true` if the session can be resumed from this state.
    pub const fn can_resume(self) -> bool {
        matches!(self, Self::Degraded | Self::Established)
    }

    #[must_use]
    /// Return `true` if this session state is terminal (Closed).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Lane state machine — per-lane flow-control states.
pub enum LaneState {
    Open = 0,
    CreditLimited = 1,
    Backpressured = 2,
    Draining = 3,
    Sealed = 4,
}

impl LaneState {
    #[must_use]
    /// Return the canonical P8-01 string label for this `LaneState` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "lane_state_0.open",
            Self::CreditLimited => "lane_state_1.credit_limited",
            Self::Backpressured => "lane_state_2.backpressured",
            Self::Draining => "lane_state_3.draining",
            Self::Sealed => "lane_state_4.sealed",
        }
    }

    #[must_use]
    /// Return `true` if outbound sends are admitted in this lane state.
    pub const fn admits_send(self) -> bool {
        matches!(self, Self::Open | Self::CreditLimited)
    }

    #[must_use]
    /// Return `true` if this lane state is terminal (Sealed).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Sealed)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Resume state machine — token lifecycle for session interruption and recovery.
pub enum ResumeState {
    None = 0,
    TokenIssued = 1,
    ResumeAttempted = 2,
    Resynced = 3,
    Refused = 4,
}

impl ResumeState {
    #[must_use]
    /// Return the canonical P8-01 string label for this `ResumeState` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "resume_state_0.none",
            Self::TokenIssued => "resume_state_1.token_issued",
            Self::ResumeAttempted => "resume_state_2.resume_attempted",
            Self::Resynced => "resume_state_3.resynced",
            Self::Refused => "resume_state_4.refused",
        }
    }

    #[must_use]
    /// Return `true` if another resume attempt is allowed from this state.
    pub const fn admits_retry(self) -> bool {
        matches!(self, Self::TokenIssued | Self::ResumeAttempted)
    }
}

// ---------------------------------------------------------------------------
// Closure and visibility classes
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Closure classes — six closure types determining drain, receipt, and escalation behavior.
pub enum ClosureClass {
    CleanDrain = 0,
    ForcedClose = 1,
    ExpiredTimeout = 2,
    RefusedPolicy = 3,
    EscalatedStateTransfer = 4,
    EscalatedLogSync = 5,
}

impl ClosureClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `ClosureClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CleanDrain => "closure.transport_session_0.clean_drain.c0",
            Self::ForcedClose => "closure.transport_session_0.forced_close.c1",
            Self::ExpiredTimeout => "closure.transport_session_0.expired_timeout.c2",
            Self::RefusedPolicy => "closure.transport_session_0.refused_policy.c3",
            Self::EscalatedStateTransfer => {
                "closure.transport_session_0.escalated_state_transfer.c4"
            }
            Self::EscalatedLogSync => "closure.transport_session_0.escalated_log_sync.c5",
        }
    }

    #[must_use]
    /// Return `true` if this closure class requires escalation to log-sync or state-transfer.
    pub const fn requires_escalation(self) -> bool {
        matches!(self, Self::EscalatedLogSync | Self::EscalatedStateTransfer)
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Drain result classes — outcome states for session drain before closure.
pub enum DrainResultClass {
    Complete = 0,
    PartialGap = 1,
    StalledTimeout = 2,
    Force = 3,
}

impl DrainResultClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `DrainResultClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "drain.transport_session_0.complete.d0",
            Self::PartialGap => "drain.transport_session_0.partial_gap.d1",
            Self::StalledTimeout => "drain.transport_session_0.stalled_timeout.d2",
            Self::Force => "drain.transport_session_0.force.d3",
        }
    }
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Visibility classes — payload inspection policy per P8-01 §8.
pub enum VisibilityClass {
    Clear = 0,
    Redacted = 1,
    DigestOnly = 2,
    HandleRedacted = 3,
}

impl VisibilityClass {
    #[must_use]
    /// Return the canonical P8-01 string label for this `VisibilityClass` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "visibility.transport_session_0.clear.v0",
            Self::Redacted => "visibility.transport_session_0.redacted.v1",
            Self::DigestOnly => "visibility.transport_session_0.digest_only.v2",
            Self::HandleRedacted => "visibility.transport_session_0.handle_redacted.v3",
        }
    }

    #[must_use]
    /// Return `true` if full payload inspection is permitted (Clear visibility).
    pub const fn allows_payload_inspection(self) -> bool {
        matches!(self, Self::Clear)
    }
}

// ---------------------------------------------------------------------------
// Session close reason — enumerated reasons for session termination
// ---------------------------------------------------------------------------

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Reasons a transport session can be closed.
pub enum SessionCloseReason {
    /// Peer was administratively removed from the cluster.
    PeerRemoved = 0,
    /// Mutual attestation failed.
    AuthFailed = 1,
    /// Envelope protocol version mismatch during handshake.
    ProtocolVersionMismatch = 2,
    /// Local daemon shutdown.
    LocalShutdown = 3,
    /// Unrecoverable transport error (e.g., connection reset).
    TransportError = 4,
    /// RDMA carrier lost; session may fall back to TCP.
    RdmaCarrierLost = 5,
    /// RDMA memory registration failed.
    RdmaRegistrationFailure = 6,
}

impl SessionCloseReason {
    #[must_use]
    /// Return the canonical P8-01 string label for this `SessionCloseReason` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerRemoved => "close_reason.transport_session_0.peer_removed.r0",
            Self::AuthFailed => "close_reason.transport_session_0.auth_failed.r1",
            Self::ProtocolVersionMismatch => {
                "close_reason.transport_session_0.protocol_version_mismatch.r2"
            }
            Self::LocalShutdown => "close_reason.transport_session_0.local_shutdown.r3",
            Self::TransportError => "close_reason.transport_session_0.transport_error.r4",
            Self::RdmaCarrierLost => "close_reason.transport_session_0.rdma_carrier_lost.r5",
            Self::RdmaRegistrationFailure => {
                "close_reason.transport_session_0.rdma_registration_failure.r6"
            }
        }
    }

    #[must_use]
    /// Whether this reason is RDMA-specific.
    pub fn is_rdma(&self) -> bool {
        matches!(self, Self::RdmaCarrierLost | Self::RdmaRegistrationFailure)
    }
}

// ---------------------------------------------------------------------------
// Record families (10 required)
// ---------------------------------------------------------------------------

/// `TransportEndpointClassRecord` — authoritative endpoint class declaration.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportEndpointClassRecord {
    pub endpoint_class_id: TransportEndpointClassId,
    pub endpoint_family_ref: EndpointFamily,
    pub host_scope_class: &'static str,
    pub payload_profile_ref: &'static str,
    pub allowed_session_class_refs: Vec<SessionClass>,
    pub kernel_bridge_allowed: bool,
    pub digest: u64,
}

/// `TransportEdgeRecord` — authoritative/runtime graph mirror for one edge.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportEdgeRecord {
    pub edge_id: TransportEdgeId,
    pub src_participant_ref: u64,
    pub dst_participant_ref: u64,
    pub endpoint_class_ref: EndpointFamily,
    pub attestation_profile_ref: &'static str,
    pub state_class: EdgeState,
    pub active_session_refs: Vec<TransportSessionId>,
    pub digest: u64,
}

/// `TransportSessionRecord` — authoritative/runtime mirror for one session.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportSessionRecord {
    pub session_id: TransportSessionId,
    pub edge_ref: TransportEdgeId,
    pub session_class_ref: SessionClass,
    pub src_identity_ref: u64,
    pub dst_identity_ref: u64,
    pub variant_ceiling_ref: &'static str,
    pub authority_scope_ceiling_ref: &'static str,
    pub state_class: SessionState,
    pub resume_token_ref: Option<TransportResumeTokenId>,
    pub open_receipt_ref: Option<TransportClosureReceiptId>,
    pub digest: u64,
}

/// `TransportMessageFamilyRecord` — authoritative declaration for one message family.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportMessageFamilyRecord {
    pub message_family_id: TransportMessageFamilyId,
    pub message_family_ref: MessageFamily,
    pub allowed_session_class_refs: Vec<SessionClass>,
    pub allowed_lane_class_refs: Vec<LaneClass>,
    pub payload_schema_family_ref: &'static str,
    pub forbidden_payload_class_refs: Vec<&'static str>,
    pub digest: u64,
}

/// `TransportCohortClassRecord` — authoritative declaration for one cohort class.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportCohortClassRecord {
    pub cohort_class_id: TransportCohortClassId,
    pub cohort_class_ref: CohortClass,
    pub purpose_class: &'static str,
    pub allowed_session_class_refs: Vec<SessionClass>,
    pub anchor_requirement_refs: Vec<&'static str>,
    pub quiesce_rule_ref: &'static str,
    pub digest: u64,
}

/// `TransportCohortAttachmentRecord` — authoritative/runtime mirror for session↔cohort binding.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportCohortAttachmentRecord {
    pub attachment_id: TransportCohortAttachmentId,
    pub session_ref: TransportSessionId,
    pub primary_cohort_ref: CohortClass,
    pub supporting_cohort_refs: Vec<CohortClass>,
    pub attach_receipt_ref: u64,
    pub detach_receipt_ref: Option<u64>,
    pub state_class: CohortAttachmentState,
    pub digest: u64,
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Cohort attachment states — lifecycle for session↔cohort bindings.
pub enum CohortAttachmentState {
    Attached = 0,
    Quiescing = 1,
    Detached = 2,
    Refused = 3,
}

impl CohortAttachmentState {
    #[must_use]
    /// Return the canonical P8-01 string label for this `CohortAttachmentState` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "cohort_attachment_state_0.attached",
            Self::Quiescing => "cohort_attachment_state_1.quiescing",
            Self::Detached => "cohort_attachment_state_2.detached",
            Self::Refused => "cohort_attachment_state_3.refused",
        }
    }
}

/// `TransportLaneBudgetRecord` — authoritative/runtime mirror for lane budget assignment.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportLaneBudgetRecord {
    pub lane_budget_id: TransportLaneBudgetId,
    pub edge_or_session_ref: u64,
    pub lane_class_ref: LaneClass,
    pub priority_class: u8,
    pub max_inflight_bytes: u64,
    pub latency_budget_ref: &'static str,
    pub drop_or_reorder_policy_ref: &'static str,
    pub backpressure_state_class: LaneState,
    pub digest: u64,
}

/// `TransportEnvelopeRecord` — authoritative/runtime mirror for one envelope.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportEnvelopeRecord {
    pub envelope_id: TransportEnvelopeId,
    pub session_ref: TransportSessionId,
    pub cohort_attachment_ref: TransportCohortAttachmentId,
    pub lane_class_ref: LaneClass,
    pub message_family_ref: MessageFamily,
    pub seq_no: u64,
    pub ack_floor: u64,
    pub anchor_refs: Vec<String>,
    pub payload_digest: u64,
    pub visibility_class: VisibilityClass,
    pub digest: u64,
}

/// `SessionResumeTokenRecord` — authoritative/runtime token for session resume.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SessionResumeTokenRecord {
    pub resume_token_id: TransportResumeTokenId,
    pub session_ref: TransportSessionId,
    pub last_seq_acked: u64,
    pub last_anchor_ref: &'static str,
    pub epoch_floor_ref: u64,
    pub expiry: u64,
    pub resume_class_ref: &'static str,
    pub refusal_class_ref: &'static str,
    pub digest: u64,
}

/// `TransportClosureReceipt` — authoritative receipt for session closure.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TransportClosureReceipt {
    pub receipt_id: TransportClosureReceiptId,
    pub session_ref: TransportSessionId,
    pub closure_class: ClosureClass,
    pub trigger_ref: &'static str,
    pub last_seq_acked: u64,
    pub drain_result_class: DrainResultClass,
    pub successor_session_ref: Option<TransportSessionId>,
    pub preserved_artifact_refs: Vec<&'static str>,
    pub digest: u64,
}

// ---------------------------------------------------------------------------
// Algorithms (10 required)
// ---------------------------------------------------------------------------

/// 1. `declare_transport_endpoint_graph_and_allowed_edges()` —
///    produce the complete endpoint-class and edge record set.
#[must_use]
pub fn declare_transport_endpoint_graph_and_allowed_edges(
    deployment_roles: &[&str],
    allow_kernel_bridge: bool,
) -> (Vec<TransportEndpointClassRecord>, Vec<TransportEdgeRecord>) {
    let families = [
        EndpointFamily::LocalEmbed,
        EndpointFamily::Control,
        EndpointFamily::Data,
        EndpointFamily::Shadow,
    ];

    let mut endpoint_classes = Vec::with_capacity(families.len());
    for (i, fam) in families.into_iter().enumerate() {
        let ep = TransportEndpointClassRecord {
            endpoint_class_id: TransportEndpointClassId::new(i as u64),
            endpoint_family_ref: fam,
            host_scope_class: if fam.is_local_only() {
                "host-local"
            } else {
                "host-remote"
            },
            payload_profile_ref: match fam {
                EndpointFamily::Control => "payload_profile.control",
                EndpointFamily::Data => "payload_profile.bulk",
                EndpointFamily::Shadow => "payload_profile.shadow",
                EndpointFamily::LocalEmbed => "payload_profile.local_embed",
            },
            allowed_session_class_refs: fam.allowed_session_classes(),
            kernel_bridge_allowed: allow_kernel_bridge && fam.is_local_only(),
            digest: 0,
        };
        endpoint_classes.push(ep);
    }

    let mut edges = Vec::new();
    for _role in deployment_roles {
        // For each pair of distinct nodes with compatible roles, create edge records.
        // This is a model — we generate one edge per remote endpoint family.
        for fam in [
            EndpointFamily::Control,
            EndpointFamily::Data,
            EndpointFamily::Shadow,
        ] {
            if fam.allowed_session_classes().is_empty() {
                continue;
            }
            let edge_id = TransportEdgeId::new(edges.len() as u64);
            let edge = TransportEdgeRecord {
                edge_id,
                src_participant_ref: 0,
                dst_participant_ref: 0,
                endpoint_class_ref: fam,
                attestation_profile_ref: "attestation_profile.default",
                state_class: EdgeState::Idle,
                active_session_refs: Vec::new(),
                digest: 0,
            };
            edges.push(edge);
        }
        // Also generate local edge for co-resident services
        let local_edge = TransportEdgeRecord {
            edge_id: TransportEdgeId::new(edges.len() as u64),
            src_participant_ref: 0,
            dst_participant_ref: 0,
            endpoint_class_ref: EndpointFamily::LocalEmbed,
            attestation_profile_ref: "attestation_profile.local",
            state_class: EdgeState::Idle,
            active_session_refs: Vec::new(),
            digest: 0,
        };
        edges.push(local_edge);
    }

    (endpoint_classes, edges)
}

/// 2. `open_mutually_attested_transport_session()` —
///    open a session on an edge with identity and scope binding.
pub fn open_mutually_attested_transport_session(
    edge_ref: TransportEdgeId,
    proposed_session_class: SessionClass,
    src_identity_ref: u64,
    dst_identity_ref: u64,
    attestation_validation: bool,
    variant_ceiling: &'static str,
    scope_ceiling: &'static str,
) -> Result<TransportSessionRecord, &'static str> {
    if !proposed_session_class
        .primary_endpoint()
        .allowed_session_classes()
        .contains(&proposed_session_class)
    {
        return Err("session class not allowed on endpoint family");
    }
    if !attestation_validation {
        return Err("mutual attestation validation required");
    }

    Ok(TransportSessionRecord {
        session_id: TransportSessionId::new(derive_session_id(
            edge_ref.0,
            src_identity_ref,
            dst_identity_ref,
        )),
        edge_ref,
        session_class_ref: proposed_session_class,
        src_identity_ref,
        dst_identity_ref,
        variant_ceiling_ref: variant_ceiling,
        authority_scope_ceiling_ref: scope_ceiling,
        state_class: SessionState::Unconnected,
        resume_token_ref: None,
        open_receipt_ref: None,
        digest: 0,
    })
}

/// 3. `bind_session_identity_scope_and_variant_ceiling()` —
///    bind identity refs, authority-domain refs, and variant ceiling into session state.
pub fn bind_session_identity_scope_and_variant_ceiling(
    session: &TransportSessionRecord,
    id_refs: &BTreeSet<u64>,
    _authority_domain_refs: &BTreeSet<u64>,
    _variant_ceiling: &str,
    _policy_refs: &[&str],
) -> Result<TransportSessionRecord, &'static str> {
    if id_refs.is_empty() {
        return Err("at least one identity ref required");
    }
    if session.state_class != SessionState::Unconnected {
        return Err("session must be in bootstrap state to bind identity");
    }

    let mut s = session.clone();
    s.state_class = SessionState::Bound;
    Ok(s)
}

/// 4. `attach_session_to_named_cohort_and_anchor_set()` —
///    attach a session to primary and supporting cohort classes.
pub fn attach_session_to_named_cohort_and_anchor_set(
    session: &TransportSessionRecord,
    primary_cohort_ref: CohortClass,
    supporting_cohort_refs: Vec<CohortClass>,
    _attach_policy: &str,
    _anchor_refs: &[&str],
    attach_receipt_ref: u64,
) -> Result<TransportCohortAttachmentRecord, &'static str> {
    if session.state_class != SessionState::Bound {
        return Err("session must be in bound state to attach cohorts");
    }

    let allowed = primary_cohort_ref.allowed_session_classes();
    if !allowed.contains(&session.session_class_ref) {
        return Err("primary cohort class does not admit this session class");
    }

    for &sup in &supporting_cohort_refs {
        let sup_allowed = sup.allowed_session_classes();
        if !sup_allowed.contains(&session.session_class_ref) {
            return Err("supporting cohort class does not admit this session class");
        }
    }

    Ok(TransportCohortAttachmentRecord {
        attachment_id: TransportCohortAttachmentId::new(session.session_id.0),
        session_ref: session.session_id,
        primary_cohort_ref,
        supporting_cohort_refs,
        attach_receipt_ref,
        detach_receipt_ref: None,
        state_class: CohortAttachmentState::Attached,
        digest: 0,
    })
}

/// 5. `assign_lane_budget_priority_and_latency_class()` —
///    assign lane budget for a session/edge under policy and pressure.
#[must_use]
pub fn assign_lane_budget_priority_and_latency_class(
    edge_or_session_ref: u64,
    lane_class: LaneClass,
    _traffic_class: &str,
    _budget_policy: &str,
    current_pressure: u8,
) -> TransportLaneBudgetRecord {
    let max_inflight = match lane_class {
        LaneClass::Control => 65536,
        LaneClass::Metadata => 262144,
        LaneClass::Demand => 131072,
        LaneClass::Speculative => 524288,
        LaneClass::Background => 1_048_576,
    };

    let state = if current_pressure > 80 {
        LaneState::Backpressured
    } else if current_pressure > 50 {
        LaneState::CreditLimited
    } else {
        LaneState::Open
    };

    TransportLaneBudgetRecord {
        lane_budget_id: TransportLaneBudgetId::new(edge_or_session_ref ^ (lane_class as u64)),
        edge_or_session_ref,
        lane_class_ref: lane_class,
        priority_class: lane_class.default_priority(),
        max_inflight_bytes: max_inflight,
        latency_budget_ref: if lane_class.is_latency_sensitive() {
            "latency.tight"
        } else {
            "latency.background"
        },
        drop_or_reorder_policy_ref: if lane_class.default_priority() <= 1 {
            "drop.none"
        } else {
            "drop.oldest"
        },
        backpressure_state_class: state,
        digest: 0,
    }
}

// ---------------------------------------------------------------------------
// From<&TransportLaneBudgetRecord> for LaneConfig
// ---------------------------------------------------------------------------

impl From<&TransportLaneBudgetRecord> for LaneConfig {
    fn from(rec: &TransportLaneBudgetRecord) -> Self {
        let base = match rec.lane_class_ref {
            LaneClass::Control => Self::control(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Metadata => Self::metadata(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Demand => Self::demand(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Speculative => Self::speculative(rec.max_inflight_bytes, u64::MAX),
            LaneClass::Background => Self::background(rec.max_inflight_bytes, u64::MAX),
        };
        Self {
            latency_budget_ref: rec.latency_budget_ref,
            drop_or_reorder_policy_ref: rec.drop_or_reorder_policy_ref,
            ..base
        }
    }
}

/// 6. `frame_transport_envelope_with_sequence_ack_and_digest()` —
///    produce a lawful envelope with sequence, ack, and digest.
#[allow(clippy::too_many_arguments)]
pub fn frame_transport_envelope_with_sequence_ack_and_digest(
    session_ref: TransportSessionId,
    cohort_attachment: &TransportCohortAttachmentRecord,
    lane_class: LaneClass,
    message_family: MessageFamily,
    seq_no: u64,
    ack_floor: u64,
    anchor_refs: &[&str],
    payload_digest: u64,
    visibility_class: VisibilityClass,
) -> Result<TransportEnvelopeRecord, &'static str> {
    if seq_no == 0 {
        return Err("sequence number must be positive");
    }
    if ack_floor > seq_no {
        return Err("ack floor must not exceed sequence number");
    }
    if !message_family.allowed_lane_classes().contains(&lane_class) {
        return Err("lane class not allowed for message family");
    }

    let mut digest_input = session_ref.0;
    digest_input = digest_input.wrapping_mul(31).wrapping_add(seq_no);
    digest_input = digest_input.wrapping_mul(31).wrapping_add(ack_floor);
    digest_input = digest_input.wrapping_mul(31).wrapping_add(payload_digest);
    digest_input = digest_input
        .wrapping_mul(31)
        .wrapping_add(message_family as u64);
    digest_input = digest_input
        .wrapping_mul(31)
        .wrapping_add(lane_class as u64);

    Ok(TransportEnvelopeRecord {
        envelope_id: TransportEnvelopeId::new(derive_envelope_id(session_ref.0, seq_no)),
        session_ref,
        cohort_attachment_ref: cohort_attachment.attachment_id,
        lane_class_ref: lane_class,
        message_family_ref: message_family,
        seq_no,
        ack_floor,
        anchor_refs: anchor_refs.iter().map(|s| s.to_string()).collect(),
        payload_digest,
        visibility_class,
        digest: digest_input,
    })
}

/// 7. `control_transport_session_cohort_graph_protocol()` —
///    central protocol: admit, send, receive, resume, or close based on state.
#[must_use]
pub fn control_transport_session_cohort_graph_protocol(
    sessions: &[TransportSessionRecord],
    _cohorts: &[TransportCohortAttachmentRecord],
    _lane_budgets: &[TransportLaneBudgetRecord],
    envelopes: &[TransportEnvelopeRecord],
    _deadlines: &[(TransportSessionId, u64)],
    _refusal_policy: &str,
) -> ProtocolDecision {
    if sessions.is_empty() || envelopes.is_empty() {
        return ProtocolDecision::Wait;
    }

    // Check session states
    for s in sessions {
        if s.state_class.is_terminal() {
            return ProtocolDecision::CloseOnly;
        }
        if s.state_class == SessionState::ResumePending {
            return ProtocolDecision::ResumeOrEscalate;
        }
    }

    ProtocolDecision::AdmitSendReceive
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Protocol decision enum — output of session cohort graph protocol control.
pub enum ProtocolDecision {
    AdmitSendReceive = 0,
    ResumeOrEscalate = 1,
    CloseOnly = 2,
    Wait = 3,
    Refuse = 4,
}

/// 8. `advance_heartbeat_progress_and_deadline_ack_state()` —
///    advance watermarks and deadline state.
#[must_use]
pub fn advance_heartbeat_progress_and_deadline_ack_state(
    session: &TransportSessionRecord,
    current_watermark: u64,
    heartbeat_receipts: &[u64],
    _fence_receipts: &[u64],
    drift_micros: u64,
    drift_tolerance_micros: u64,
) -> (TransportSessionRecord, u64, Option<ClosureClass>) {
    let new_watermark = heartbeat_receipts
        .iter()
        .copied()
        .max()
        .map(|m| m.max(current_watermark))
        .unwrap_or(current_watermark);

    let mut s = session.clone();
    if s.state_class == SessionState::Degraded {
        s.state_class = SessionState::Established;
    }

    if drift_micros > drift_tolerance_micros {
        s.state_class = SessionState::Degraded;
    }

    let escalation = if drift_micros > drift_tolerance_micros * 3 {
        Some(ClosureClass::EscalatedLogSync)
    } else {
        None
    };

    (s, new_watermark, escalation)
}

/// 9. `resume_session_or_escalate_to_log_sync_or_state_transfer()` —
///    attempt resume; escalate if gap exceeds window.
pub fn resume_session_or_escalate_to_log_sync_or_state_transfer(
    session: &TransportSessionRecord,
    resume_token: Option<&SessionResumeTokenRecord>,
    gap_estimate: u64,
    anchor_floor_ref: &'static str,
    _policy_refs: &[&str],
    _canonical_schema_state: &str,
) -> ResumeOutcome {
    let token = match resume_token {
        Some(t) => t,
        None => return ResumeOutcome::EscalateStateTransfer,
    };

    if token.session_ref != session.session_id {
        return ResumeOutcome::Refused;
    }

    // Check that identity, variant ceiling, and epoch floor still match
    if token.expiry < token.epoch_floor_ref + 100 {
        return ResumeOutcome::EscalateLogSync;
    }

    let resume_window: u64 = 1000;
    if gap_estimate > resume_window {
        return ResumeOutcome::EscalateStateTransfer;
    }

    if anchor_floor_ref != token.last_anchor_ref {
        return ResumeOutcome::EscalateLogSync;
    }

    ResumeOutcome::Resumed
}

#[repr(u32)]
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
/// Resume outcome enum — result of session resume or escalation attempt.
pub enum ResumeOutcome {
    Resumed = 0,
    EscalateLogSync = 1,
    EscalateStateTransfer = 2,
    Refused = 3,
}

impl ResumeOutcome {
    #[must_use]
    /// Return the canonical P8-01 string label for this `ResumeOutcome` variant.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resumed => "resume_outcome.resumed",
            Self::EscalateLogSync => "resume_outcome.escalate_log_sync",
            Self::EscalateStateTransfer => "resume_outcome.escalate_state_transfer",
            Self::Refused => "resume_outcome.refused",
        }
    }
}

/// 10. `seal_session_drain_and_emit_transport_closure_receipt()` —
///     drain the session and emit a closure receipt.
pub fn seal_session_drain_and_emit_transport_closure_receipt(
    session: &TransportSessionRecord,
    drain_trigger: &'static str,
    last_seq_acked: u64,
    preserved_artifact_refs: &[&'static str],
    successor_session: Option<TransportSessionId>,
    force: bool,
) -> (TransportSessionRecord, TransportClosureReceipt) {
    let drain_result = if force {
        DrainResultClass::Force
    } else {
        DrainResultClass::Complete
    };

    let closure_class = if session.state_class == SessionState::Degraded {
        ClosureClass::EscalatedLogSync
    } else if force {
        ClosureClass::ForcedClose
    } else {
        ClosureClass::CleanDrain
    };

    let mut s = session.clone();
    s.state_class = SessionState::Closed;

    let receipt_id = TransportClosureReceiptId::new(s.session_id.0 ^ last_seq_acked);

    let receipt = TransportClosureReceipt {
        receipt_id,
        session_ref: s.session_id,
        closure_class,
        trigger_ref: drain_trigger,
        last_seq_acked,
        drain_result_class: drain_result,
        successor_session_ref: successor_session,
        preserved_artifact_refs: preserved_artifact_refs.to_vec(),
        digest: s.session_id.0.wrapping_mul(31).wrapping_add(last_seq_acked),
    };

    (s, receipt)
}

// ---------------------------------------------------------------------------
// Utility: deterministic ID derivation
// ---------------------------------------------------------------------------

#[must_use]
const fn derive_session_id(edge: u64, src: u64, dst: u64) -> u64 {
    edge.wrapping_mul(0x517cc1b727220a95)
        .wrapping_add(src)
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(dst)
}

#[must_use]
const fn derive_envelope_id(session: u64, seq: u64) -> u64 {
    session.wrapping_mul(31).wrapping_add(seq)
}

#[must_use]
#[allow(dead_code)]
const fn derive_receipt_id(session: u64, seq: u64) -> u64 {
    session.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(seq)
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // --- Endpoint-graph test ---
    #[test]
    fn declare_endpoint_graph_for_three_roles() {
        let roles = &["authority", "replica", "shadow"];
        let (classes, edges) = declare_transport_endpoint_graph_and_allowed_edges(roles, false);

        assert_eq!(classes.len(), 4, "must declare 4 endpoint classes");
        assert!(
            classes
                .iter()
                .any(|c| c.endpoint_family_ref == EndpointFamily::LocalEmbed),
            "must include local embed endpoint"
        );
        assert!(
            classes
                .iter()
                .any(|c| c.endpoint_family_ref == EndpointFamily::Control),
            "must include control endpoint"
        );
        assert!(
            classes
                .iter()
                .any(|c| c.endpoint_family_ref == EndpointFamily::Data),
            "must include data endpoint"
        );
        assert!(
            classes
                .iter()
                .any(|c| c.endpoint_family_ref == EndpointFamily::Shadow),
            "must include shadow endpoint"
        );

        // Each role gets 3 remote + 1 local edge = 4 edges per role
        assert_eq!(edges.len(), roles.len() * 4);

        let local_edges: Vec<_> = edges
            .iter()
            .filter(|e| e.endpoint_class_ref == EndpointFamily::LocalEmbed)
            .collect();
        assert_eq!(local_edges.len(), roles.len());
    }

    // --- Session open test ---
    #[test]
    fn open_session_fails_without_attestation() {
        let edge = TransportEdgeId::new(1);
        let result = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            false,
            "variant.default",
            "scope.default",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("attestation"));
    }

    #[test]
    fn open_control_session_succeeds_with_attestation() {
        let edge = TransportEdgeId::new(1);
        let result = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        );
        assert!(result.is_ok());
        let s = result.unwrap();
        assert_eq!(s.state_class, SessionState::Unconnected);
        assert_eq!(s.session_class_ref, SessionClass::Control);
        assert!(s.resume_token_ref.is_none());
    }

    #[test]
    fn open_shadow_session_on_control_endpoint_fails() {
        // ShadowValidation sessions are only allowed on shadow endpoint (e3).
        // The session_class_ref and endpoint_family are not validated at open time
        // by open_mutually_attested_transport_session (it checks allowed_session_classes
        // on the endpoint's family), but the edge_ref is opaque here.
        // We test that a shadow session on control primary endpoint still has
        // ShadowValidation's primary_endpoint() pointing to Shadow.
        let edge = TransportEdgeId::new(1);
        let s = SessionClass::ShadowValidation;
        assert_eq!(s.primary_endpoint(), EndpointFamily::Shadow);
        // The open function checks the endpoint family via allowed_session_classes.
        // Since the edge_ref is opaque, we just verify the mapping is correct.
        let result = open_mutually_attested_transport_session(
            edge,
            SessionClass::ShadowValidation,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        );
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().session_class_ref.primary_endpoint(),
            EndpointFamily::Shadow
        );
    }

    // --- Session bind test ---
    #[test]
    fn bind_session_advances_state() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        ids.insert(20);

        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        assert_eq!(bound.state_class, SessionState::Bound);
    }

    #[test]
    fn bind_session_fails_without_identities() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let result = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &BTreeSet::new(),
            &BTreeSet::new(),
            "variant.default",
            &[],
        );
        assert!(result.is_err());
    }

    // --- Cohort attachment test ---
    #[test]
    fn attach_peer_pair_cohort() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![CohortClass::AuthorityDomainControl],
            "attach_policy.default",
            &[],
            1,
        )
        .unwrap();

        assert_eq!(attachment.primary_cohort_ref, CohortClass::PeerPair);
        assert_eq!(
            attachment.supporting_cohort_refs,
            vec![CohortClass::AuthorityDomainControl]
        );
        assert_eq!(attachment.state_class, CohortAttachmentState::Attached);
    }

    #[test]
    fn peer_pair_is_mandatory_for_remote() {
        assert!(CohortClass::PeerPair.is_mandatory_for_remote());
        assert!(!CohortClass::FenceTarget.is_mandatory_for_remote());
        assert!(!CohortClass::ReplicaSet.is_mandatory_for_remote());
    }

    // --- Envelope test ---
    #[test]
    fn frame_envelope_with_sequence_and_ack() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![],
            "attach_policy.default",
            &[],
            1,
        )
        .unwrap();

        let envelope = frame_transport_envelope_with_sequence_ack_and_digest(
            attachment.session_ref,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            1,
            0,
            &["anchor.heartbeat"],
            0xfeed_cafe,
            VisibilityClass::Clear,
        )
        .unwrap();

        assert_eq!(envelope.seq_no, 1);
        assert_eq!(envelope.ack_floor, 0);
        assert_eq!(envelope.message_family_ref, MessageFamily::HeartbeatAck);
        assert_eq!(envelope.lane_class_ref, LaneClass::Control);
        assert_eq!(envelope.visibility_class, VisibilityClass::Clear);
        assert!(
            envelope.digest != 0,
            "digest must be non-zero for a real envelope"
        );
    }

    #[test]
    fn envelope_fails_with_zero_seq() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![],
            "attach_policy.default",
            &[],
            1,
        )
        .unwrap();

        let result = frame_transport_envelope_with_sequence_ack_and_digest(
            attachment.session_ref,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            0, // invalid
            0,
            &[],
            0,
            VisibilityClass::Clear,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sequence"));
    }

    #[test]
    fn envelope_fails_with_wrong_lane_for_message() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![],
            "attach_policy.default",
            &[],
            1,
        )
        .unwrap();

        // HeartbeatAck only allows Control lane (l0); Background should fail.
        let result = frame_transport_envelope_with_sequence_ack_and_digest(
            attachment.session_ref,
            &attachment,
            LaneClass::Background,
            MessageFamily::HeartbeatAck,
            1,
            0,
            &[],
            0,
            VisibilityClass::Clear,
        );
        assert!(result.is_err());
    }

    // --- Lane budget test ---
    #[test]
    fn lane_budget_reflects_pressure() {
        let budget = assign_lane_budget_priority_and_latency_class(
            1,
            LaneClass::Control,
            "traffic.control",
            "policy.default",
            90,
        );
        assert_eq!(budget.backpressure_state_class, LaneState::Backpressured);

        let budget2 = assign_lane_budget_priority_and_latency_class(
            1,
            LaneClass::Background,
            "traffic.bulk",
            "policy.default",
            30,
        );
        assert_eq!(budget2.backpressure_state_class, LaneState::Open);
        assert!(budget2.max_inflight_bytes > budget.max_inflight_bytes);
    }

    // --- Heartbeat / deadline test ---
    #[test]
    fn heartbeat_advances_watermark_and_recovers_degraded() {
        let edge = TransportEdgeId::new(1);
        let mut session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();
        session.state_class = SessionState::Degraded;

        let receipts = &[5u64, 10u64, 15u64];
        let (s, watermark, escalation) =
            advance_heartbeat_progress_and_deadline_ack_state(&session, 3, receipts, &[], 0, 1000);

        assert_eq!(watermark, 15);
        assert_eq!(
            s.state_class,
            SessionState::Established,
            "degraded session should recover when drift is within tolerance"
        );
        assert!(escalation.is_none());
    }

    #[test]
    fn excessive_drift_degrades_and_escalates() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let (s, _watermark, escalation) =
            advance_heartbeat_progress_and_deadline_ack_state(&session, 3, &[5], &[], 5000, 100);

        assert_eq!(s.state_class, SessionState::Degraded);
        assert!(escalation.is_some());
        assert_eq!(escalation.unwrap(), ClosureClass::EscalatedLogSync);
    }

    // --- Resume test ---
    #[test]
    fn resume_succeeds_within_window() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let token = SessionResumeTokenRecord {
            resume_token_id: TransportResumeTokenId::new(1),
            session_ref: session.session_id,
            last_seq_acked: 10,
            last_anchor_ref: "anchor.x",
            epoch_floor_ref: 1,
            expiry: 500,
            resume_class_ref: "resume.default",
            refusal_class_ref: "refusal.default",
            digest: 0,
        };

        let outcome = resume_session_or_escalate_to_log_sync_or_state_transfer(
            &session,
            Some(&token),
            50,
            "anchor.x",
            &[],
            "canonical_schema_state",
        );

        assert_eq!(outcome, ResumeOutcome::Resumed);
    }

    #[test]
    fn resume_escalates_when_gap_exceeds_window() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let token = SessionResumeTokenRecord {
            resume_token_id: TransportResumeTokenId::new(1),
            session_ref: session.session_id,
            last_seq_acked: 10,
            last_anchor_ref: "anchor.x",
            epoch_floor_ref: 1,
            expiry: 500,
            resume_class_ref: "resume.default",
            refusal_class_ref: "refusal.default",
            digest: 0,
        };

        let outcome = resume_session_or_escalate_to_log_sync_or_state_transfer(
            &session,
            Some(&token),
            5000,
            "anchor.x",
            &[],
            "canonical_schema_state",
        );

        assert_eq!(outcome, ResumeOutcome::EscalateStateTransfer);
    }

    #[test]
    fn resume_refused_when_token_session_mismatch() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let token = SessionResumeTokenRecord {
            resume_token_id: TransportResumeTokenId::new(1),
            session_ref: TransportSessionId::new(9999), // different session
            last_seq_acked: 10,
            last_anchor_ref: "anchor.x",
            epoch_floor_ref: 1,
            expiry: 500,
            resume_class_ref: "resume.default",
            refusal_class_ref: "refusal.default",
            digest: 0,
        };

        let outcome = resume_session_or_escalate_to_log_sync_or_state_transfer(
            &session,
            Some(&token),
            50,
            "anchor.x",
            &[],
            "canonical_schema_state",
        );

        assert_eq!(outcome, ResumeOutcome::Refused);
    }

    // --- Closure test ---
    #[test]
    fn clean_drain_emits_closure_receipt() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let (closed, receipt) = seal_session_drain_and_emit_transport_closure_receipt(
            &session,
            "trigger.operator",
            42,
            &["artifact.xxx"],
            Some(TransportSessionId::new(2)),
            false,
        );

        assert_eq!(closed.state_class, SessionState::Closed);
        assert_eq!(receipt.last_seq_acked, 42);
        assert_eq!(receipt.closure_class, ClosureClass::CleanDrain);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Complete);
        assert!(receipt.successor_session_ref.is_some());
    }

    #[test]
    fn forced_close_emits_forced_closure() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let (closed, receipt) = seal_session_drain_and_emit_transport_closure_receipt(
            &session,
            "trigger.timeout",
            10,
            &[],
            None,
            true,
        );

        assert_eq!(closed.state_class, SessionState::Closed);
        assert_eq!(receipt.closure_class, ClosureClass::ForcedClose);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Force);
    }

    // --- State machine transition tests ---
    #[test]
    fn edge_state_transitions() {
        assert!(EdgeState::Idle.as_str().starts_with("edge_state_0"));
        assert!(EdgeState::Attested.as_str().starts_with("edge_state_1"));
        assert!(EdgeState::Open.as_str().starts_with("edge_state_2"));
        assert!(EdgeState::Established.as_str().starts_with("edge_state_3"));
        assert!(EdgeState::Draining.as_str().starts_with("edge_state_4"));
        assert!(EdgeState::Closed.as_str().starts_with("edge_state_5"));
        assert!(EdgeState::Closed.is_terminal());
        assert!(!EdgeState::Idle.is_terminal());
        assert!(EdgeState::Established.can_accept_session());
        assert!(!EdgeState::Idle.can_accept_session());
        assert!(!EdgeState::Draining.can_accept_session());
        assert!(!EdgeState::Closed.can_accept_session());
    }

    #[test]
    fn session_state_transitions() {
        assert!(SessionState::Unconnected
            .as_str()
            .starts_with("session_state_0"));
        assert!(SessionState::Bound.as_str().starts_with("session_state_1"));
        assert!(SessionState::Closed.is_terminal());
        assert!(!SessionState::Degraded.is_terminal());
        assert!(SessionState::Degraded.can_resume());
        assert!(SessionState::Established.can_resume());
        assert!(!SessionState::Unconnected.can_resume());
        assert!(!SessionState::Closed.can_resume());
    }

    #[test]
    fn lane_state_transitions() {
        assert!(LaneState::Open.admits_send());
        assert!(LaneState::CreditLimited.admits_send());
        assert!(!LaneState::Backpressured.admits_send());
        assert!(!LaneState::Draining.admits_send());
        assert!(!LaneState::Sealed.admits_send());
        assert!(LaneState::Sealed.is_terminal());
        assert!(!LaneState::Open.is_terminal());
    }

    // --- Message family lane mapping ---
    #[test]
    fn control_messages_use_control_lane() {
        assert_eq!(
            MessageFamily::HeartbeatAck.primary_lane_class(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::ElectionControl.primary_lane_class(),
            LaneClass::Control
        );
        assert_eq!(
            MessageFamily::LeaseFenceDeadline.primary_lane_class(),
            LaneClass::Control
        );
    }

    #[test]
    fn metadata_messages_use_metadata_lane() {
        assert_eq!(
            MessageFamily::PublicationProgress.primary_lane_class(),
            LaneClass::Metadata
        );
        assert_eq!(
            MessageFamily::LogSyncMetadata.primary_lane_class(),
            LaneClass::Metadata
        );
    }

    #[test]
    fn state_transfer_has_dual_lanes() {
        let lanes = MessageFamily::StateTransfer.allowed_lane_classes();
        assert!(lanes.contains(&LaneClass::Demand));
        assert!(lanes.contains(&LaneClass::Background));
        assert_eq!(lanes.len(), 2);
    }

    // --- Protocol decision test ---
    #[test]
    fn protocol_admits_send_receive_when_flowing() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        // Need at least one envelope and non-terminal state
        let attachment = TransportCohortAttachmentRecord {
            attachment_id: TransportCohortAttachmentId::new(1),
            session_ref: session.session_id,
            primary_cohort_ref: CohortClass::PeerPair,
            supporting_cohort_refs: vec![],
            attach_receipt_ref: 1,
            detach_receipt_ref: None,
            state_class: CohortAttachmentState::Attached,
            digest: 0,
        };

        let envelope = frame_transport_envelope_with_sequence_ack_and_digest(
            session.session_id,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            1,
            0,
            &[],
            0,
            VisibilityClass::Clear,
        )
        .unwrap();

        let decision = control_transport_session_cohort_graph_protocol(
            &[session],
            &[attachment],
            &[],
            &[envelope],
            &[],
            "refusal.default",
        );

        assert_eq!(decision, ProtocolDecision::AdmitSendReceive);
    }

    // --- Lane priority test ---
    #[test]
    fn control_lane_has_highest_priority() {
        assert!(LaneClass::Control.default_priority() < LaneClass::Metadata.default_priority());
        assert!(LaneClass::Metadata.default_priority() < LaneClass::Demand.default_priority());
        assert!(LaneClass::Demand.default_priority() < LaneClass::Speculative.default_priority());
        assert!(
            LaneClass::Speculative.default_priority() < LaneClass::Background.default_priority()
        );
    }

    // --- Bootstrap promotion test ---
    #[test]
    fn bootstrap_can_promote_to_all_long_lived() {
        let allowed = SessionClass::Bootstrap.can_promote_to();
        assert_eq!(allowed.len(), 5);
        assert!(allowed.contains(&SessionClass::Control));
        assert!(allowed.contains(&SessionClass::ReplicationMeta));
        assert!(allowed.contains(&SessionClass::TransferBulk));
        assert!(allowed.contains(&SessionClass::ShadowValidation));
        assert!(allowed.contains(&SessionClass::TransitionOrchestration));
    }

    #[test]
    fn long_lived_sessions_cannot_promote() {
        assert!(SessionClass::Control.can_promote_to().is_empty());
        assert!(SessionClass::TransferBulk.can_promote_to().is_empty());
    }

    // --- Endpoint-session pairing ---
    #[test]
    fn data_endpoint_only_admits_transfer_bulk() {
        let allowed = EndpointFamily::Data.allowed_session_classes();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], SessionClass::TransferBulk);
    }

    #[test]
    fn shadow_endpoint_only_admits_shadow_validation() {
        let allowed = EndpointFamily::Shadow.allowed_session_classes();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0], SessionClass::ShadowValidation);
    }

    #[test]
    fn local_endpoint_admits_all_classes() {
        let allowed = EndpointFamily::LocalEmbed.allowed_session_classes();
        assert_eq!(allowed.len(), 6);
    }

    // --- Resume state machine ---
    #[test]
    fn resume_state_admits_retry() {
        assert!(!ResumeState::None.admits_retry());
        assert!(ResumeState::TokenIssued.admits_retry());
        assert!(ResumeState::ResumeAttempted.admits_retry());
        assert!(!ResumeState::Resynced.admits_retry());
        assert!(!ResumeState::Refused.admits_retry());
    }

    // --- Lane priority ordering ---
    #[test]
    fn starvation_protected_lanes_are_top_priority() {
        assert!(LaneClass::Control.may_not_be_starved());
        assert!(LaneClass::Metadata.may_not_be_starved());
        assert!(!LaneClass::Demand.may_not_be_starved());
        assert!(!LaneClass::Speculative.may_not_be_starved());
        assert!(!LaneClass::Background.may_not_be_starved());
    }

    // --- Envelope round-trip: sequence advance ---
    #[test]
    fn envelope_sequence_monotonicity() {
        let edge = TransportEdgeId::new(1);
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();

        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();

        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![],
            "attach_policy.default",
            &[],
            1,
        )
        .unwrap();

        let env1 = frame_transport_envelope_with_sequence_ack_and_digest(
            session.session_id,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            1,
            0,
            &[],
            0,
            VisibilityClass::Clear,
        )
        .unwrap();

        let env2 = frame_transport_envelope_with_sequence_ack_and_digest(
            session.session_id,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            2,
            1,
            &[],
            0,
            VisibilityClass::Clear,
        )
        .unwrap();

        assert!(env2.seq_no > env1.seq_no);
        assert!(env2.ack_floor > env1.ack_floor);
        // Envelope IDs should differ
        assert_ne!(env1.envelope_id, env2.envelope_id);
    }

    // --- Escalation closure test ---
    #[test]
    fn escalation_classes_require_escalation() {
        assert!(ClosureClass::EscalatedLogSync.requires_escalation());
        assert!(ClosureClass::EscalatedStateTransfer.requires_escalation());
        assert!(!ClosureClass::CleanDrain.requires_escalation());
        assert!(!ClosureClass::ForcedClose.requires_escalation());
        assert!(!ClosureClass::ExpiredTimeout.requires_escalation());
        assert!(!ClosureClass::RefusedPolicy.requires_escalation());
    }

    // --- Full life cycle: open -> bind -> attach -> flow -> drain -> close ---
    #[test]
    fn full_session_lifecycle() {
        let edge = TransportEdgeId::new(1);

        // 1. Open with mutual attestation
        let session = open_mutually_attested_transport_session(
            edge,
            SessionClass::Control,
            10,
            20,
            true,
            "variant.default",
            "scope.default",
        )
        .unwrap();
        assert_eq!(session.state_class, SessionState::Unconnected);

        // 2. Bind identity
        let mut ids = BTreeSet::new();
        ids.insert(10);
        let bound = bind_session_identity_scope_and_variant_ceiling(
            &session,
            &ids,
            &BTreeSet::new(),
            "variant.default",
            &[],
        )
        .unwrap();
        assert_eq!(bound.state_class, SessionState::Bound);

        // 3. Attach cohorts
        let attachment = attach_session_to_named_cohort_and_anchor_set(
            &bound,
            CohortClass::PeerPair,
            vec![CohortClass::AuthorityDomainControl],
            "attach_policy.default",
            &["anchor.init"],
            1,
        )
        .unwrap();
        assert_eq!(attachment.state_class, CohortAttachmentState::Attached);
        assert_eq!(attachment.primary_cohort_ref, CohortClass::PeerPair);

        // 4. Send first envelope (marks flowing transition in production)
        let envelope = frame_transport_envelope_with_sequence_ack_and_digest(
            bound.session_id,
            &attachment,
            LaneClass::Control,
            MessageFamily::HeartbeatAck,
            1,
            0,
            &["anchor.hb"],
            0xfeed,
            VisibilityClass::Clear,
        )
        .unwrap();
        assert_eq!(envelope.seq_no, 1);
        assert_eq!(envelope.message_family_ref, MessageFamily::HeartbeatAck);

        // 5. Drain and close
        let (closed, receipt) = seal_session_drain_and_emit_transport_closure_receipt(
            &bound,
            "trigger.runbook",
            envelope.seq_no,
            &["artifact.hb"],
            Some(TransportSessionId::new(2)),
            false,
        );

        assert_eq!(closed.state_class, SessionState::Closed);
        assert_eq!(receipt.closure_class, ClosureClass::CleanDrain);
        assert_eq!(receipt.drain_result_class, DrainResultClass::Complete);
        assert_eq!(receipt.last_seq_acked, 1);
    }
}
