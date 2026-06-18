// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! P8-02 live membership runtime for TideFS.
//!
//! Implements SWIM-based failure detection with the 3-phase epoch transition
//! protocol. Provides the `MembershipRuntime` service that drives heartbeat,
//! failure detection, and epoch transitions for the distributed cluster.
//!
//! ## Architecture
//!
//! - [`types`]: SWIM ping/ack/indirect ping wire messages, epoch transition
//!   proposal/accept/commit messages, suspicion records, and runtime types.
//! - [`failure_detector`]: Per-peer SWIM-style liveness tracking with direct
//!   ping, indirect-ping relay via k random peers, timeout escalation, and
//!   suspicion confirmation.
//! - [`indirect_ping`]: Indirect-ping relay protocol: initiation, response
//!   collection, timeout management, and BLAKE3-verified result aggregation.
//! - [`epoch_transition`]: 3-phase quorum-commit protocol for membership state
//!   changes: Propose → Accept → Commit.
//! - [`runtime`]: The `MembershipRuntime` long-running service, coordinating
//!   the failure detector, epoch engine, peer registration, and callbacks.
//! - [`transport_wiring`]: Connects the membership runtime to `tidefs-transport`
//!   so that SWIM and epoch-transition messages flow over TCP sessions.
//! - [`membership_inbound_dispatch`]: Centralized inbound message dispatch that
//!   registers as a single transport receive hook for
//!   `MessageFamily::PublicationProgress` and routes decoded
//!   `MembershipMessage` variants to the correct subsystem handler
//!   (epoch push receiver, catch-up handler, proposal coordinator) by
//!   discriminant. Eliminates per-handler transport registration
//!   fragmentation.
//!
//! ## Data Integrity
//!
//! Every SWIM ack carries a BLAKE3-256 digest computed over the canonical
//! serialization of its membership data payload (suspicion list plus membership
//! deltas).  Indirect ping requests and responses also carry BLAKE3-256 digests
//! with unique domain separation strings to bind requests to responses and
//! reject stale, replayed, or tampered relay messages. Ingesting a heartbeat
//! response verifies this digest before merging peer state into the live
//! membership view.
//!
//! ## Integration
//!
//! The membership runtime integrates with:
//! - [`tidefs-membership-epoch`]: Deterministic epoch model — live transitions
//!   drive epoch state in the deterministic model.
//! - [`tidefs-auth`]: Node identities for signing protocol messages.
//! - [`reconnect_handshake`]: Peer-reconnect handshake that delivers the
//!   current committed epoch via a [`ReconnectStatePushMessage`] to a
//!   reconnecting known peer and re-binds its transport session through
//!   [`SessionAcceptor`] and [`RosterSessionRegistry`]. This bridges the
//!   gap between initial node-join (unknown peers) and post-commit roster
//!   push (passive synchronization).
//! - [`tidefs-transport`]: Membership protocol messages (SWIM pings, epoch
//!   proposals) are sent/received over established Transport sessions via the
//!   `MembershipTransport` adapter.
//! - [`membership_inbound_dispatch`]: The single transport receive hook for
//!   all inbound `MembershipMessage` variants. Implements the transport-level
//!   `MessageHandler` trait and routes decoded messages by discriminant to
//!   subsystem handlers (epoch push receiver, catch-up responder, catch-up
//!   response handler).

pub mod backend_disclosure;
pub mod capability_view;
pub mod checkpoint_persistence;
pub mod cluster_lease_wiring;
pub mod commit_coordinator_bridge;
pub mod connection_acceptance;
pub mod connection_establishment;
pub mod connection_teardown;
pub mod coordinator_lease;
pub mod deterministic_replay;
pub mod deterministic_transport;
pub mod dispatch_router;
pub mod drain;
pub mod drain_verifier;
pub mod epoch_catch_up;
pub mod epoch_coordinator;
pub mod epoch_fence;
pub mod epoch_push;
pub mod epoch_state_machine;
pub mod epoch_transition;
pub mod escalation;
pub mod event_bridge;
pub mod failure_detector;
pub mod fencing_watchdog;
pub mod gossip;
pub mod gossip_batcher;
pub mod harness;
pub mod heartbeat;
pub mod indirect_ping;
pub mod lease_messages;
pub mod liveness;
pub mod liveness_trigger;
pub mod membership_inbound_dispatch;
pub mod membership_outbound_dispatch;
pub mod peer_add_connector;
pub mod peer_address_registry;
pub mod peer_eviction;
pub mod peer_health;
pub mod peer_health_scorer;
pub mod peer_join;
pub mod peer_liveness;
pub mod peer_unreachable;
pub mod reconnect_handshake;
pub mod roster;
pub mod roster_gossip;
pub mod runtime;
pub mod send_gate;
pub mod session_binding;
pub mod suspicion_accumulator;
pub mod transport_bridge;
pub mod transport_event_recorder;
pub mod transport_session_manager;
pub mod transport_wiring;
pub mod types;

pub mod coordinator_promotion;
pub mod departure_initiator;
pub mod incarnation_validator;
pub mod join_handler;
pub mod join_initiator;
pub mod join_request;
pub mod join_response;
pub mod journal_sync_trigger;
pub mod membership_vote_handler;
pub mod proposal_commit;
pub mod roster_leave_notify;
pub mod roster_notify;
pub mod roster_session_bridge;
pub mod roster_sync;
pub mod seed_discovery;
// Re-exports
pub use backend_disclosure::BackendDisclosure;
pub use checkpoint_persistence::CheckpointPersistence;
pub use cluster_lease_wiring::renegotiate_lease_on_epoch;
pub use commit_coordinator_bridge::CommitCoordinatorTransportBridge;
pub use connection_acceptance::ConnectionAcceptor;
pub use connection_establishment::{
    ConnectionEstablishmentConfig, ConnectionEstablishmentSubscriber, EstablishCallback,
};
pub use connection_teardown::{EpochTeardownSubscriber, TeardownAction, TeardownCallback};
pub use coordinator_lease::{
    evaluate_lease, handle_inbound_heartbeat, CoordinatorHeartbeatRequest, CoordinatorLease,
    CoordinatorLeaseConfig, HeartbeatResponse, LeaseStatus,
};
pub use deterministic_replay::{
    DeterministicReplayHarness, ReplayEpochTransition, ReplayFault, ReplayOutcome,
};
pub use deterministic_transport::{
    DeterministicEndpoint, DeterministicSession, DeterministicSessionState, DeterministicTransport,
};
pub use dispatch_router::{
    MembershipDispatchError, MembershipDispatchRouter, MembershipMessage, MembershipMessageHandler,
};
pub use drain::{DrainConfig, DrainOrchestrator, DrainState};
pub use drain_verifier::DrainMembershipVerifier;
pub use epoch_push::{EpochPushBroadcaster, EpochPushReceiveHandler};
pub use epoch_state_machine::{
    EpochProtocolConfig, EpochProtocolState, EpochStateMachine, RejectReason,
};
pub use epoch_transition::{
    AcceptanceStatus, AppliedTransition, EpochTransitionEngine, EpochTransitionProposalRequest,
    TransitionError,
};
pub use escalation::{
    EscalationEngine, EscalationMemberState, EscalationProposalRequest, EscalationThreshold,
};
pub use event_bridge::{
    MembershipEvent, MembershipEventPublisher, MembershipEventSubscriber, SubscriberId,
};
pub use failure_detector::{
    AckResult, FailureDetector, FailureDetectorError, IndirectRelayOutbound,
};
pub use fencing_watchdog::{FencingAction, FencingWatchdog};
pub use gossip::{
    AntiEntropyRound, DisseminationConfig, GossipBroadcastEngine, GossipConfig, GossipMessage,
    GossipState, MemberState, RumorMongerer,
};
pub use gossip_batcher::{
    GossipBatch, GossipBatcher, GossipBatcherConfig, GossipUpdate, PerPeerOutboundQueue,
};
pub use heartbeat::{
    HeartbeatConfig, HeartbeatTransmitter, LivenessStatus, PeerLiveness, PeerLivenessTracker,
};
pub use indirect_ping::{
    IndirectPingConfig, IndirectPingRelay, RelayError, RelayRequestHandler, RelayResult,
};
pub use join_handler::{
    JoinHandler, JoinHandlerResult, JoinIdempotencyKey, JoinProposal, JoinRejectionReason,
};
pub use join_initiator::{JoinInitiator, JoinInitiatorConfig, JoinInitiatorState, JoinResult};
pub use join_request::{AdmissionState, JoinRequestHandler, PendingJoin};
pub use join_response::{JoinOutcome, JoinResponseDispatcher, JoinResponseHandler};
pub use journal_sync_trigger::JournalSyncTrigger;
pub use lease_messages::{
    build_lease_acknowledge, build_lease_acknowledge_at, build_lease_expire, build_lease_expire_at,
    build_lease_grant, build_lease_grant_at, build_lease_renew, build_lease_renew_at,
    build_lease_revoke, build_lease_revoke_at, LeaseId, LeaseTerm,
};
pub use liveness::{LivenessConfig, LivenessTracker};
pub use liveness_trigger::{LivenessTriggerConfig, LivenessTriggerDispatcher, TriggerOutcome};
pub use membership_inbound_dispatch::{HandlerSet, MembershipInboundDispatch};
pub use membership_outbound_dispatch::{
    BroadcastResult, MembershipOutboundDispatch, MembershipOutboundMessage, OutboundDispatchError,
};
pub use peer_add_connector::{PeerAddCallback, PeerAddConnector, PeerAddOutcome, PeerAddStatus};
pub use peer_address_registry::PeerAddressRegistry;
pub use peer_eviction::{EvictionAction, EvictionCallback, EvictionExecutor, EvictionOutcome};
pub use peer_health::{PeerHealthHandle, PeerHealthTracker};
pub use peer_health_scorer::{
    keepalive_subscore, rtt_subscore, throughput_subscore, PeerHealthScorer, PeerStatus,
    PeerStatusTransition, ScorerConfig, ScorerConfigBuilder,
};
pub use peer_join::{JoinQueue, PeerJoinHandshake, PeerJoinOutcome};
pub use peer_unreachable::{PeerUnreachableConfig, PeerUnreachableStatus, PeerUnreachableTracker};
pub use proposal_commit::{
    ProposalCommitError, ProposalCommitPipeline, ProposalKind, ProposalSequencer,
};
pub use reconnect_handshake::{PeerReconnectHandshake, PeerReconnectOutcome, ReconnectError};
pub use roster::{MembershipRoster, RosterError, RosterSnapshot, RosterState};
pub use roster_gossip::{
    MergeConflict, MergeOutcome, RosterEntry, RosterGossipConfig, RosterGossipHandle,
    RosterGossipHandler, RosterGossipRound, RosterMerge,
};
pub use roster_session_bridge::{RosterSessionHandle, SessionReady, TransportSessionOps};
pub use runtime::{
    MembershipRuntime, PeerPlacementVersionObservation, PendingTransition,
    PlacementVersionConvergence, RuntimeTickResult,
};
pub use seed_discovery::{
    DiscoveredSeed, SeedDiscovery, SeedDiscoveryConfig, SeedDiscoveryError, SeedFailureReason,
};
pub use send_gate::MembershipSendGate;
pub use session_binding::{
    admission_policy, binding_policy, PeerSessionBinding, SessionBindingTable, SessionId,
    SessionPolicy,
};
pub use suspicion_accumulator::{
    SuspicionAccumulator, SuspicionConfig, SuspicionEvent, SuspicionScore, SuspicionState,
    SuspicionValidation,
};
pub use transport_bridge::{MembershipTransportBridge, TransportSessionManager};
pub use transport_event_recorder::{
    EventLog, MembershipTransportEvent, TimestampedEvent, TransportEventRecorder,
};
pub use transport_session_manager::TransportBridgeManager;
pub use transport_wiring::{
    recv_membership_msg, send_membership_msg, MembershipTransport, MembershipWireMessage,
};
pub use types::{
    EpochCommit, EpochProposal, EpochTransitionAccept, EpochTransitionCommit,
    EpochTransitionProposal, EpochVote, MembershipConfig, MembershipDelta, MembershipDeltaKind,
    MembershipView, MembershipViewNode, PeerState, QuorumProof, RejectionReason, SignedAccept,
    SuspicionRecord, SuspicionSource, SwimAck, SwimIndirectPingRequest, SwimIndirectPingResponse,
    SwimPing, TransitionReason,
};
