// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Deterministic cluster membership lease transitions for TideFS.
//!
//! Provides the foundational lease protocol that governs which nodes hold
//! valid membership slots. Each cluster member acquires and holds a lease
//! on its membership slot; lease acquisition, renewal, expiration, and
//! release follow a deterministic state machine with BLAKE3-verified state
//! integrity (domain `tidefs-cluster-membership-lease-v1`).
//!
//! ## Architecture
//!
//! - [`types`]: Core types — `MembershipLease`, `LeaseState`, errors, status.
//! - [`lease_state_machine`]: Deterministic state machine with BLAKE3-256
//!   state digests covering all transitions.
//! - [`protocol`]: Wire protocol message types with per-frame BLAKE3
//!   integrity (domain `tidefs-cluster-membership-lease-protocol-v1`).
//! - [`runtime`]: `ClusterLeaseRuntime` — tokio-based runtime driving the
//!   lease lifecycle per node, with transport send/receive integration and
//!   status query API.
//! - [`placement_transfer`]: Placement transfer coordinator bridging
//!   placement plans to transport data movement.
//! - [`dataset_catalog`]: Cluster-aware dataset catalog authority gated by
//!   lease/fence ownership, wrapping the canonical
//!   [`tidefs_dataset_catalog::DatasetCatalog`] for single-writer
//!   serialization of create/destroy/rename mutations.
//! - [`rebuild_backfill`]: Rebuild backfill initiator bridging
//!   rebuild-planner outputs to transport state-transfer commands.
//!
//! ## Integration
//!
//! The cluster lease runtime integrates with:
//! - `tidefs-transport`: Lease protocol messages are sent/received over
//!   established transport sessions via the membership lease dispatch
//!   module.
//! - `tidefs-membership-live`: Epoch transition events trigger lease
//!   renegotiation via [`ClusterLeaseRuntime::on_epoch_transition`].
//!
//! ## Data Integrity
//!
//! Every state transition produces a BLAKE3-256 digest computed over the
//! full machine state (node_id, state discriminant, epoch, transition count,
//! lease fields). Every wire message carries a BLAKE3-256 digest over its
//! bincode payload. All hashing uses unique domain-separation strings to
//! bind digests to their context and prevent cross-domain replay.

pub mod catalog_commit_handler;
pub mod client_mode;
pub mod dataset_catalog;
pub mod placement_transfer;
pub mod rebuild_backfill;
pub mod write_fence;

pub mod channel_transport;
pub mod placement_heal;
pub mod pool_config;
pub mod pool_label_bridge;
pub mod pool_lease_client;
pub mod pool_lease_token;
pub mod pool_orchestrator;
pub mod pool_protocol;

pub mod authority;
pub mod cluster_authority_record;
pub mod cluster_authority_snapshot;
pub mod cluster_authority_store;
pub mod lease_state_machine;
pub mod protocol;
pub mod runtime;
pub mod types;

// Re-exports
pub use authority::{AcquireOutcome, LeaseAuthority, RenewOutcome};
pub use catalog_commit_handler::{make_coordinator_handler, CatalogDeltaSubscriber};
pub use channel_transport::{ChannelPoolTransport, ChannelTransportError};
pub use client_mode::{
    ClientMode, ClientModeConfig, ClientModeSnapshot, ClientModeTracker, ModeTransitionError,
};
pub use cluster_authority_record::{
    validate_authority_chain, validate_authority_record, AuthorityRefusalReason,
    ClusterAuthorityRecord, ClusterAuthorityRecordBuilder, ClusterAuthorityVerdict,
    CLUSTER_AUTHORITY_MAGIC, CLUSTER_AUTHORITY_VERSION,
};
pub use cluster_authority_snapshot::{
    BootAuthorityOutcome, ClusterAuthorityBootstrapper, ClusterAuthoritySnapshot,
    DeviceAuthorityStatus,
};
pub use cluster_authority_store::{
    append_authority_record_to_device, read_all_records_from_device, scan_authority_from_device,
    scan_authority_from_devices, write_authority_chain_to_device, AuthorityStoreError,
    CLUSTER_AUTHORITY_HEADER_SIZE, CLUSTER_AUTHORITY_REGION_MAX, CLUSTER_AUTHORITY_REGION_OFFSET,
};
pub use dataset_catalog::{
    CatalogDelta, ClusterCatalogError, ClusterDatasetCatalog, ClusterPoolCatalog,
};
pub use lease_state_machine::LeaseStateMachine;
pub use placement_heal::{
    HealState, HealStats, LossEvent, PlacementHealCoordinator, PlacementMap,
    PlacementObjectReceipt, RebuildFlowCommitPlacementPublication,
    RebuildHealCompletionPublication, RebuildPublicationHealFinalization,
};
pub use placement_transfer::{
    ObjectRange, PlacementTransferCoordinator, PlanEntry, TransferError, TransferPlan,
    TransferSession, TransferState,
};
pub use pool_config::{
    ClusterPlacementPolicy, ClusterPoolConfig, ClusterRedundancy, FailureDomain, NodeDevice,
};
pub use pool_label_bridge::{BridgeError, CLUSTER_POOL_COMPAT, CLUSTER_POOL_INCOMPAT};
pub use pool_lease_token::PoolLeaseToken;
pub use pool_orchestrator::{
    ClusterPoolOrchestrator, CreateOutcome, ImportOutcome, NodeCreateResult, NodeImportResult,
    OrchestratorError, PoolTransport,
};
pub use pool_protocol::{
    CatalogEntryRow, CatalogQueryType, ClusterPoolCatalogDeltaRequest,
    ClusterPoolCatalogDeltaResponse, ClusterPoolCatalogQueryRequest,
    ClusterPoolCatalogQueryResponse, ClusterPoolCreateRequest, ClusterPoolCreateResponse,
    ClusterPoolImportRequest, ClusterPoolImportResponse, ClusterPoolMessage, NodeDeviceSpec,
    PoolProtocolError,
};
pub use protocol::{
    AcquireAck, AcquireNack, AcquireRequest, ExpireNotify, MembershipLeaseMessage, ProtocolError,
    ReleaseAck, ReleaseRequest, RenewAck, RenewNack, RenewRequest,
};
pub use rebuild_backfill::{
    BackfillBatch, BackfillCommand, BackfillError, BackfillSession, BackfillState,
    RebuildBackfillInitiator, RebuildPlan, ReconstructionTask,
};
pub use runtime::{ClusterLeaseConfig, ClusterLeaseRuntime, MessageDirection};
pub use tidefs_membership_epoch::EpochId;
pub use types::{DataPathCarrier, LeaseState, LeaseStatus, LeaseTransitionError, MembershipLease};
pub use write_fence::{FenceAuthority, FenceValidator, StaleFence, WriteFence};
