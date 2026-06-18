// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![deny(unsafe_code)]

//! Transport/session layer for TideFS distributed runtime.
//!
//! ## Endpoint lifecycle
//!
//! The transport layer manages the full lifecycle of P8-01 transport endpoints.
//! An endpoint is a (node, EndpointFamily) binding selected from the four stable
//! endpoint families: `LocalEmbed` (e0), `Control` (e1), `Data` (e2), and
//! `Shadow` (e3). The canonical lifecycle proceeds through eight fixed,
//! receipt-backed stages:
//!
//! **1. Endpoint selection** — a participant selects an endpoint family
//! according to its role (control-plane, data-plane, co-resident embed, or
//! shadow compare). The selection is constrained by:
//!   - `EndpointFamily::allowed_session_classes()` — each family only admits
//!     the session classes listed in the P8-01 table.
//!   - `SessionClass::primary_endpoint()` — each session class maps to
//!     exactly one primary endpoint; opening a session on a non-primary
//!     endpoint is a protocol violation.
//!
//! **2. Mutual attestation** — for every non-LocalEmbed session, the two
//! endpoints exchange identities and perform mutual challenge-response
//! attestation. LocalEmbed (e0) sessions are exempt for local/test/harness use; Control/Data/Shadow sessions require attestation or are refused.
//!
//! **3. Session bind** — a session is opened on the chosen endpoint and
//! transitions Bootstrap → Bound. The bind step anchors the session to a
//! concrete endpoint family, identity set, and variant/scope ceiling.
//!
//! **4. Cohort attach** — the bound session attaches to one or more declared
//! `CohortClass` values (k0–k7). A session may not invent a one-off
//! population label; every path must attach to a declared cohort class.
//!
//! **5. Lane admission** — per-lane budget records are created for the
//! session, carrying the lane class, traffic class, and budget policy.
//! Lanes are admitted only when the endpoint family, session class, and
//! cohort class jointly permit them.
//!
//! **6. Envelope flow** — the session exchanges framed transport envelope
//! messages with monotonic sequence numbers, ack floors, payload digests,
//! and optional per-message compression (see [`compression`] module).
//! Messages enqueued for outbound delivery can be cancelled before transmission
//! via [`SendCancelHandle`] (see [`SendCancelHandle`] in [`message_priority`]), allowing upper
//! layers to discard stale messages after epoch transitions or coordinator
//! changes.
//!
//! **7. Drain or resume** — when the session is no longer needed, it either
//! drains cleanly (all outstanding envelopes acked, last acked sequence
//! recorded) or, if the gap is within the resume window, issues a resume
//! token for later continuation.
//!
//! **8. Closure receipt** — every session closure emits a closure receipt
//! that records the drain result, last acked sequence, any preserved artifact
//! refs, and optionally a successor session.
//!
//! ## Wire protocol compatibility guarantees
//!
//! TideFS wire protocols obey a strict compatibility contract across all
//! node-to-node communication paths. The contract is organized into five
//! independent pillars:
//!
//! ### Pillar 1: Envelope format stability
//!
//! Every transport frame opens with the 4-byte magic `VEFS` followed by a
//! single `u8` format version byte. The magic and version field positions
//! are **permanently frozen** — they will never move or change meaning.
//!
//! | Field | Stability | Rule |
//! |---|---|---|
//! | `ENVELOPE_MAGIC` (`VEFS`) | Frozen | Never changes; used for protocol identification |
//! | `ENVELOPE_VERSION` (1) | Frozen position | Incremented for breaking format changes; old peers immediately reject unknown versions |
//! | `FRAME_HEADER_SIZE` (40) | Version-locked | Tied to `ENVELOPE_VERSION`; changes only with version bump |
//!
//! **Negotiation rule**: During HELLO handshake, each peer advertises its
//! supported envelope version. If the two sides differ, the connection is
//! refused with a version-mismatch closure reason. There is no downgrade
//! negotiation at the envelope level — both sides must agree on the exact
//! version.
//!
//! ### Pillar 2: Stable identifier spaces
//!
//! The following identifier spaces are **permanently stable** — values never
//! change meaning once assigned:
//!
//! | Space | Count | Governance |
//! |---|---|---|
//! | `MessageFamily` (m0–m9) | 10 stable families | New families require `ENVELOPE_VERSION` bump |
//! | `EndpointFamily` (e0–e3) | 4 stable families | P8-01 §4.2; e0=LocalEmbed, e1=Control, e2=Data, e3=Shadow |
//! | `SessionClass` | 7 stable classes | P8-01 §4.1; primary-endpoint mappings are frozen |
//! | `CohortClass` (k0–k7) | 8 stable cohorts | P8-01 §6; new cohorts require cohort-class extension |
//! | `LaneClass` | 5 priority lanes | Control > Metadata > Demand > Speculative > Background; starvation-prevention ordering is frozen |
//! | `ServiceId` | Per-service registry | Service IDs (VFS_RPC=0x06, ADMIN=0x09, etc.) never change |
//!
//! **Method ID stability per service**: Each service owns its method ID table.
//! Method IDs are stable — a method never changes its ID after assignment.
//! Behavior changes within a method are gated by:
//! - Dataset-level feature flags (`org.tidefs:*` namespace in `DatasetFeatureFlagsV1`)
//! - Per-family `FamilyVersion` negotiation during session handshake
//!
//! ### Pillar 3: Forward-compatibility rules
//!
//! Every receiver MUST tolerate unknown extensions without faulting:
//!
//! - **Reserved bytes**: All reserved bytes in frame headers, common request
//!   headers, and per-method payloads MUST be zero on send and MUST be ignored
//!   on receive. Non-zero reserved bytes are silently skipped; they are never
//!   a protocol error.
//! - **Unknown method IDs**: Receivers return `ENOSYS` for unknown method IDs.
//!   The caller treats `ENOSYS` as a capability signal: the peer does not
//!   support this operation.
//! - **Unknown message families**: Envelopes carrying an unrecognized
//!   `MessageFamily` discriminant are dropped (not acked) and counted as
//!   skipped frames. The session remains `Established`.
//! - **TLV extensions**: All TLV-encoded payload sections use a skip rule:
//!   known TLVs are parsed, unknown TLVs are skipped by length. A TLV with a
//!   reserved-but-unrecognized type is never a parse error.
//! - **VisibilityClass additions**: New `VisibilityClass` variants are
//!   permitted without version bump. Receivers treat unknown visibility
//!   classes as `Clear`.
//!
//! ### Pillar 4: Backward-compatibility rules
//!
//! New senders MUST interoperate with old receivers:
//!
//! - **Add-only changes**: New methods, new message families (through version
//!   bump), and new cohort classes are add-only. An old receiver that does not
//!   recognize a new addition either returns `ENOSYS` or drops the frame —
//!   both are safe outcomes.
//! - **Field extensions**: New fields are appended, never inserted. Old
//!   decoders stop at their known field count; new decoders parse the full
//!   payload. Field reordering is prohibited.
//! - **Semantic narrowing**: A method's semantics may narrow (e.g., a new flag
//!   refines behavior) but must never widen in a way that would surprise an
//!   old sender. Old senders that do not set the new flag get the original
//!   behavior.
//! - **Deprecation**: Methods and message families are deprecated by
//!   advertising their removal in a future `ENVELOPE_VERSION`. Deprecated
//!   items remain functional for at least two minor releases before removal.
//!
//! ### Pillar 5: Session handshake negotiation
//!
//! Compatibility is negotiated per-session during the HELLO handshake via
//! `FamilyVersion` vectors:
//!
//! ```text
//! Peer A ──[HELLO: envelope=1, families=[(m0,1,0), (m4,1,0), ...]]──▶ Peer B
//! Peer A ◀──[HELLO_ACK: envelope=1, families=[(m0,1,0), (m4,1,0), ...]]── Peer B
//! ```
//!
//! Each peer advertises its supported `(family_id, version_major,
//! version_minor)` tuples. The intersection of the two sets determines the
//! usable protocol surface for the session. A message family not present in
//! both advertisements is unavailable for that session.
//!
//! **Negotiation rules**:
//! - Envelope version must match exactly — mismatch → refuse.
//! - Message family version is matched by major; minor differences are
//!   tolerated (highest common minor is used).
//! - Session classes beyond `Bootstrap` require matching `FamilyVersion` sets
//!   for the families that the session class depends on.
//! - Cohort attachment (`CohortClass`) is gated: a cohort class unsupported
//!   by the peer is refused at attach time.
//!
//! ### Summary matrix
//!
//! | Change | Compatibility impact | Safe? |
//! |---|---|---|
//! | Add new method ID | Old peer returns `ENOSYS` | ✅ Forward-compatible |
//! | Add new message family | Requires `ENVELOPE_VERSION` bump | ❌ Breaking |
//! | Add new cohort class | Old peer refuses attach | ✅ Forward-compatible |
//! | Append field to payload | Old decoder ignores trailing bytes | ✅ Backward-compatible |
//! | Reorder fields | Old decoder misreads | ❌ Breaking |
//! | Change method ID assignment | Old callers route to wrong handler | ❌ Breaking |
//! | Narrow method semantics | Old senders unchanged | ✅ Backward-compatible |
//! | Widen method semantics | Old senders may get unexpected behavior | ⚠️ Requires feature flag |
//! | Bump `ENVELOPE_VERSION` | Old peers refuse connection | ❌ Breaking |
//! | Add TLV extension type | Old decoder skips by length | ✅ Forward-compatible |
//!
//! ### Endpoint family invariants
//!
//! | Invariant | Rule |
//! |---|---|
//! | **e0-local** | `LocalEmbed` is never opened to a remote peer; it is only for co-resident service communication within a single node. |
//! | **e1-control** | `Control` carries bootstrap, control, replication metadata, and transition orchestration sessions. It must never carry bulk or shadow sessions. |
//! | **e2-data** | `Data` is dedicated to bulk transfer sessions (`TransferBulk`). Control-plane traffic must never be routed through `Data`. |
//! | **e3-shadow** | `Shadow` is dedicated to shadow validation sessions (`ShadowValidation`). No other session class may use it. |
//! | **one-primary-endpoint** | Every session class has exactly one primary endpoint via `SessionClass::primary_endpoint()`; a session opened on a non-primary endpoint is a protocol violation. |
//! | **no-silent-promote** | `SessionClass::can_promote_to()` is the sole promotion path; a session may not silently change its session class except through explicit promote transitions from `Bootstrap`. |
//! | **receipt-every-close** | Every session close (clean drain, forced close, or refused) must produce exactly one closure receipt. |
//! | **one-per-peer-pair** | Per P8-01 §4.2, at most one Control/Data/Shadow session per peer pair is permitted. |
//! | **family-stable** | Every session is bound to exactly one endpoint family at creation time; the endpoint family never changes for the lifetime of the session. |
//! | **lane-gated** | Lane admission is gated by endpoint family, session class, and cohort class compatibility. |
//!
//! ### Session state machine invariants
//!
//! The `SessionState` machine enforces:
//! - **Forward-only** — transitions never reverse; `Closed` is terminal.
//! - **No skip** — `Unconnected` → `Connecting` → `Handshaking` → `Bound` →
//!   `CohortAttached` → `Established`. Intermediate states cannot be bypassed
//!   (except `Handshaking` → `Established` for backward compatibility).
//! - **Degraded only from Established** — a session can only degrade when
//!   it was previously `Established`.
//! - **Resume window** — `ResumePending` admits self-retry but does not
//!   admit direct transition to `Established`; it must go through
//!   `Connecting` again.
//! - **Single HLC stamp** — every state transition stamps the new state
//!   with the current Hybrid Logical Clock value.
//!
//! This crate implements:
//! - [Transport]: TCP listener, connection pool, session manager
//! - [Session]: named, authenticated, lane-multiplexed, reconnectable sessions
//! - [SessionCohortGraph]: cohort-based session population per P8-01 §6
//! - [LaneDemux]: 5-lane priority multiplexing with per-lane backpressure
//! - [ChunkShipper]: immutable chunk payload transport with resume
//! - [Keepalive]: heartbeat keepalive with dead-connection detection and domain-separated state-digest verification
//! - [IdleTimeout]: passive activity-watch timeout with drain/close on idle connections
//! - [TransportBackend]: abstraction over TCP (default) and RDMA (OW-308)
//!
//!
//! ## P8-03 role: data_copy_1.transfer_orchestrator
//!
//! Serves as the `TransferOrchestrator` for P8-03 distributed runtime data
//! movement, providing chunk shipping, session management, lane multiplexing,
//! and transport backend abstraction for cross-node data copy coordination.
//! This is the physical layer of the distributed system.

pub mod addr;
pub mod backend;
pub mod backpressure;
pub mod barrier;
pub mod boundedness;
pub mod broadcast;
pub mod carrier_selection;
pub mod channel;
pub mod chunk_shipper;
pub mod circuit_breaker;
pub mod codec;
pub mod committed_roster_push;
pub mod compression;
pub mod config;
pub mod connect_lifecycle;
pub mod connect_tracker;
pub mod connection;
pub mod connection_admission;
pub mod connection_init;
pub mod connection_pool;
pub mod connection_registry;
pub mod connection_retry;
pub mod connection_state;
pub mod connection_telemetry;
pub mod correlation_frame;
pub mod cross_session_scheduler;
pub mod dedup_filter;
pub mod delivery_confirmation;
pub mod dispatch;
pub mod drain_protocol;
pub mod envelope;
pub mod epoch_barrier;
pub mod epoch_bridge;
pub mod epoch_fence;
pub mod epoch_gate;
pub mod error;
pub mod error_classification;
pub mod flow_control;
pub mod fragmentation;
pub mod frame_governance;
pub mod harness;
pub mod idle_timeout;
pub mod io_runtime;
pub mod join_state_push;
pub mod keepalive;
pub mod lane_demux;
pub mod lease_dispatch;
pub mod listener;
pub mod listener_overload;
#[cfg(feature = "loopback")]
pub mod loopback_v2;
pub mod membership_guard;
pub mod membership_lease_dispatch;
pub mod message_batcher;
pub mod message_dispatch;
pub mod message_priority;
pub mod messages;
pub mod object_enumerator;
pub mod object_list;
pub mod object_transfer;
pub mod outbound_send;
pub mod peer_address_registry;
pub mod peer_admission;
pub mod peer_drain_coordinator;
pub mod peer_health;
pub mod peer_manager;
pub mod peer_send_queue;
pub mod placement_dispatch;
pub mod placement_version_tracker;
pub mod rdma;
pub mod receive_flow;
pub mod receive_loop;
pub mod reconnect;
pub mod reconnect_state_push;
pub mod recv_batch;
pub mod reorder_buffer;
pub mod replication;
pub mod request_concurrency;
pub mod request_response;
pub mod rollback_compat;
pub mod routing;
pub mod secure_transport;
pub mod segment_fetch;
pub mod send_admission;
pub mod send_backpressure;
pub mod send_batcher;
pub mod send_buffer;
pub mod send_coalesce;
pub mod send_completion;
pub mod send_concurrency;
pub mod send_deadline;
pub mod send_dispatch;
pub mod send_gate;
pub mod send_queue_depth;
pub mod send_scheduler;
pub mod session;
pub mod session_cipher;
pub mod session_cohort;
pub mod session_concurrency;
pub mod session_drain;
pub mod session_establishment;
pub mod session_handshake;
pub mod session_reconnector;
pub mod session_rekey;
pub mod stream_mux;
pub mod tcp;
#[cfg(feature = "tdma")]
pub mod tdma_gate;
#[cfg(feature = "tls")]
pub mod tls;
pub mod transfer_control;
pub mod transport;
pub mod transport_session_set;
pub mod types;
pub mod unreachable_peer;
pub mod write_gate;
pub mod writev_batcher;

pub use addr::{AddrParseError, TransportAddr, TransportCarrier};
pub use backend::TransportBackend;
pub use backend::TransportBackendKind;
pub use chunk_shipper::{
    ChunkShipper, ChunkTransfer, ChunkTransferHeader, ChunkTransferState, RefuseReason,
    TransferDirection,
};
pub use envelope::{
    EnvelopeError, IntegrityEnvelope, IntegrityError, MessageFamily, SequenceTracker,
    TransportEnvelope, VisibilityClass,
};
pub use epoch_barrier::{EpochBarrier, EpochBarrierError, EpochStamped};
pub use error::{ChunkError, ChunkTransferError, SessionError, TransportError};
pub use fragmentation::{
    decode_fragment, encode_fragment, fragment_message, fragment_overhead, is_fragment,
    FragmentError, FragmentHeader, FragmentReassembler, DEFAULT_MTU, DEFAULT_REASSEMBLY_TIMEOUT_MS,
    FRAGMENT_HEADER_MIN_SIZE, FRAGMENT_MAGIC, MAX_FRAGMENTS_PER_MESSAGE,
};
pub use lane_demux::{LaneBackpressure, LaneClass, LaneDemux, WriteResult};
pub use lease_dispatch::{
    decode_lease_message, encode_lease_message, LeaseMessageHandler, LeaseSimNode,
    LEASE_MESSAGE_FAMILY,
};
pub use membership_lease_dispatch::{
    decode_membership_lease_message, encode_membership_lease_message,
    MembershipLeaseMessageHandler, MEMBERSHIP_LEASE_MESSAGE_FAMILY,
};
pub use messages::{StateTransferChunk, StateTransferRequest};
pub use object_enumerator::{
    compute_per_node_object_deltas, ObjectEnumerator, ObjectPlacementEntry, PerNodeObjectDelta,
    PlacementMap, PlacementTableObjectEnumerator, ShardKind,
};
pub use object_list::{
    recv_list_objects_request, recv_list_objects_response, send_list_objects_request,
    send_list_objects_response, serve_list_objects_request, ListObjectsError, ListObjectsHandler,
    ListObjectsRequest, ListObjectsResponse, ObjectListEntry,
};
pub use peer_manager::{
    new_peer_manager_handle, MembershipEvent, MembershipEventSink, PeerEntry, PeerManager,
    PeerManagerError, PeerManagerHandle, PeerState,
};

pub use object_transfer::{
    build_read_responses, build_write_requests, chunk_payload, dispatch_read_request,
    dispatch_write_request, recv_read_response, recv_write_ack, recv_write_request, send_write_ack,
    ChunkReassembler, ChunkReassemblyError, ObjectTransferMessage, TransferDispatchError,
    TransferHandle, TransferTimeoutAction, WriteStatus, DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT, MAX_CHUNK_PAYLOAD,
};
pub use segment_fetch::{
    recv_segment_fetch, recv_segment_fetch_response, send_segment_fetch,
    send_segment_fetch_response, SegmentFetchRequest, SegmentFetchResponse,
    SEGMENT_FETCH_REQUEST_MAGIC, SEGMENT_FETCH_RESPONSE_MAGIC,
};

pub use join_state_push::{JoinStatePushDispatcher, JoinStatePushHandler, JoinStatePushMessage};
pub use rdma::RdmaTransport;
pub use reconnect::{
    ReconnectConfig, ReconnectError, ReconnectPhase, ReconnectPolicy, ReconnectState,
    SessionResumeRequest, SessionResumeResponse,
};
pub use reconnect_state_push::{
    ReconnectStatePushDispatcher, ReconnectStatePushHandler, ReconnectStatePushMessage, ReconnectStatePushOutcome,
};
pub use replication::{
    recv_replication_msg, send_replication_msg, PlacementMapRefusalReason, ReplicationMessage,
    SyncEntry,
};
pub use secure_transport::{SecureTransport, SecureTransportStats};
pub use session::{
    handshake, MessageSequenceNumber, PeerSessionInfo, SeqReceiveOutcome, Session,
    SessionCloseReason, SessionState,
};
pub use session_cipher::{CipherError, Direction, SessionKeyMaterial, TransportSessionCipher};
pub use session_cohort::{NodeInfo, SessionCohortGraph, TransportCohortId};
pub use session_handshake::{
    initiate_handshake, respond_to_handshake, Accept, HandshakeCodecError, HandshakeError,
    HandshakeFrame, HandshakeStateMachine, Hello, LifecycleError, Reject, RejectReason,
    SessionLifecycle, SessionLifecycleState, DEFAULT_HANDSHAKE_TIMEOUT,
};
pub use session_reconnector::{
    PermanentFailureReason, ReconnectAction, SessionReconnectConfig, SessionReconnector,
};
pub use tcp::TcpTransport;
#[cfg(feature = "tls")]
pub use tls::{generate_self_signed_cert, TlsTransport};
pub use transport::{ConnectionPool, Transport};
pub use types::{
    ChunkId, ChunkTransferId, CohortMembership, FamilyVersion, FenceVersion, Hash, HlcTimestamp,
    NodeIdentityPublic, SessionId,
};

pub use boundedness::{
    bulk_deadline_default, hello_timeout, transport_tick_interval, validate_boundedness_constants,
    validate_transport_against_design_documents, ConnectionBounds, DeliveryBudget, TransportLane,
    BACKGROUND_LANE_CAP, BULK_CHUNK_SIZE_DEFAULT, BULK_DEADLINE_DEFAULT_MS, BULK_LANE_CAP,
    CONTROL_LANE_CAP, DEDUP_ENTRY_MAX_BYTES, DEDUP_WINDOW_OPS, FRAME_HEADER_SIZE,
    GLOBAL_MAX_BYTES_PER_TICK, GLOBAL_MAX_DELIVERIES_PER_TICK, HELLO_TIMEOUT_MS, MAX_FRAME_BYTES,
    MAX_INFLIGHT_BULK_TOKENS, MAX_INFLIGHT_FRAMES, METADATA_LANE_CAP, TRANSPORT_TICK_INTERVAL_MS,
};
pub use reorder_buffer::{GapEvent, InsertResult, ReorderBuffer};

pub use broadcast::{
    BroadcastConfig, BroadcastError, BroadcastFailureMode, BroadcastOutcome, BroadcastResults,
};
pub use channel::{
    envelope_to_decoded_message, new_shared_channel_table, ChannelAllocator, ChannelEntry,
    ChannelEnvelope, ChannelEnvelopeSendError, ChannelEnvelopeSender, ChannelError, ChannelId,
    ChannelMultiplexer, ChannelMultiplexerError, ChannelState, ChannelTable, SharedChannelTable,
};
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitDecision, CircuitState, PeerCircuit, PeerId,
};
pub use codec::{CodecError, MessageCodec, CODEC_FRAME_HEADER_SIZE, DEFAULT_MAX_FRAME_SIZE};
pub use compression::{
    compress_frame, compress_frame_with_threshold, decode_compressed_payload, decompress_frame,
    encode_compressed_payload, is_marked_compression, CompressedFrame, CompressionAlgorithm,
    CompressionConfig, CompressionError, CompressionState, COMPRESSION_MARKER,
};
pub use connection_init::{
    ConnectionInitError, ConnectionInitState, HandshakeInitiator, HandshakeMessage,
    HandshakeResponder, HANDSHAKE_PROTOCOL_VERSION,
};
pub use correlation_frame::{
    decode_correlation_frame, encode_correlation_request, encode_correlation_response,
    has_correlation_header, CorrelationFrameError, CorrelationFrameKind, CORRELATION_HEADER_LEN,
};
pub use cross_session_scheduler::{
    CrossSessionScheduler, CrossSessionSchedulerConfig, SessionSendEntry,
};
pub use dedup_filter::{DedupFilter, DedupFilterConfig, DedupFilterStats, DeliveryVerdict};
pub use delivery_confirmation::{
    AcknowledgmentFrame, DeliveryConfirmationEngine, DeliveryOutcome, DeliverySequence,
    DeliveryTracker,
};
pub use dispatch::{DecodedMessage, MessageDispatch};
pub use epoch_bridge::{EpochEventBridge, PeerStateDelta, TransportEpochSubscriber};
pub use epoch_fence::{check_reconnect_admission, EpochFence, EpochFenceRuntime, EpochTransition, FenceOutcome, FenceSummary, ReconnectAdmission};
pub use listener::{TransportConnection, TransportListener};
pub use listener_overload::{
    AcceptRateLimiter, ConnectionRejectedEvent, ConnectionRejectedReason, ListenerOverloadConfig,
    OverloadEventSubscriber, OverloadGuard, PendingAcceptCounter,
};
pub use membership_guard::{
    MembershipSessionGuard, MembershipSessionGuardRuntime, TeardownOutcome, TeardownReason,
};
pub use message_batcher::{BatchConfig, BatchError, BatchStats, MessageBatch, MessageBatcher};
pub use message_dispatch::{
    DispatchError, MessageDispatcher, MessageEnvelope, MessageHandler, MessageType,
};
pub use message_priority::SendCancelHandle;
pub use message_priority::{
    MessagePriority, MessagePriorityConfig, MessagePriorityError, MessagePriorityQueue,
};
pub use placement_dispatch::{
    PlacementDispatch, PlacementDispatchError, ResolvedPlacement, WriteTarget,
};
pub use placement_version_tracker::PlacementVersionTracker;
pub use request_response::{
    CorrelationError, RequestResponseHandle, RequestResponseTable, TimeoutConfig,
};
pub use routing::{RouteEntry, RoutingTable};
pub use send_admission::{
    DroppedSendEvidence, SendAdmission, SendAdmissionEvidence, SendAdmissionOutcome,
    SendAdmissionPolicy, SendCapacityClass, SendCapacityEvidence, SendWakeEvidence,
};
pub use send_backpressure::{
    data_lane_pressure_fn, SendCapacity, SendCapacitySet, SendCapacitySnapshot, SendWatermarkConfig,
};
pub use send_batcher::{BatchResult, SendBatchConfig, SendBatcher};
pub use send_coalesce::{CoalesceConfig, CoalesceFlush, CoalesceKey, SendCoalescer};
pub use send_deadline::{
    deadline_channel, resolve_deadline, DeadlineOutcome, DeadlineToken, MessageDeadline,
    SendDeadlineConfig,
};
pub use send_dispatch::{
    DrainedBatch, OutboundMessage, SendDispatcher, SendDrainer, SendError, SendQueue,
    SendQueueConfig,
};
pub use send_gate::SendGate;
pub use send_scheduler::{QueuedMessage, SendPriority, SendScheduler, SendSchedulerConfig};
pub use session_concurrency::{
    SessionConcurrencyConfig, SessionConcurrencyError, SessionConcurrencyLimitHit,
    SessionConcurrencyLimiter, SessionPermit,
};
pub use session_rekey::{
    RekeyConfig, RekeyError, RekeyFailureReason, RekeyTrigger, SessionRekeyEngine,
};
pub use transfer_control::{
    decode_transfer_control_message, TransferAbort, TransferChunk, TransferChunkAck,
    TransferComplete, TransferControlDiscriminant, TransferControlError, TransferControlMessage,
    TransferInitiate, TransferRange,
};
pub use transport_session_set::{SessionBinding, SessionHealth, TransportSessionSet};
pub use unreachable_peer::{UnreachablePeerCallback, UnreachablePeerCallbackRef};
pub use write_gate::WriteGate;
pub use writev_batcher::{WritevBatcher, WritevBatcherConfig};

pub use backpressure::{
    BackpressureCallback, BackpressureController, BackpressureMode, BackpressureRejected,
    BackpressureSnapshot, BackpressureStatus, ChannelBackpressureConfig, ChannelSnapshot,
    OutboundBackpressure, OutboundBackpressureConfig, SendSlot, WouldBlock,
};
pub use error_classification::{
    default_recovery_action, DefaultRecoveryDispatcher, ErrorClassifier, ErrorObserver,
    ErrorRateTracker, RecoveryAction, RecoveryDispatcher, TransportErrorKind,
};

pub use connect_tracker::{ConnectAttemptState, ConnectTimeout, ConnectionStateTracker};
pub use connection_pool::{PoolConfig, PoolStats, PooledConnection, TcpConnectionPool};
pub use connection_retry::{
    connect_with_retry, is_retryable, PeerConnectGate, RetryConfig, RetryError,
};
pub use connection_state::{
    ConnectionLifecycle, ConnectionState, InvalidTransition, LifecycleBus, LifecycleEvent,
    LifecycleSubscriber,
};

pub use io_runtime::{
    decode_frame, encode_frame, read_frame, write_frame, ConnectionHandle, IoError, IoRuntime,
    IO_FRAME_HEADER_SIZE, MAX_FRAME_PAYLOAD,
};
pub use outbound_send::{
    SendBackpressureConfig, SendBackpressureState, SendFramer, SendPipeline, SendPipelineError,
    SendPipelineHandle, DEFAULT_CHANNEL_CAPACITY, DEFAULT_MAX_BATCH_FRAMES, ENVELOPE_HEADER_SIZE,
};
pub use receive_loop::{
    build_frame, family_id_to_message_family, message_family_to_family_id, ConnectionReceiver,
    DrainVelocityTracker, ReceiveLoopConfig, ReceiveLoopDiagnostics, ReceiveLoopError,
    SpawnedReceiver, DEFAULT_READ_BUF_SIZE, TRANSPORT_FAMILY_ID_BASE,
};
pub use recv_batch::{RecvBatchConfig, RecvBatchDecoder, RecvBatchDiagnostics};
pub use send_completion::{
    CompletionDispatcher, CompletionOutcome, SendCompletion, SendCompletionToken,
};

pub use frame_governance::{
    ClassFrameSizeLimits, FrameSizeConfig, FrameSizeError, FrameSizeGovernor,
    DEFAULT_MAX_RECV_FRAME_BYTES, DEFAULT_MAX_SEND_PAYLOAD_BYTES,
};
pub use idle_timeout::{
    ActivitySource, IdleTimeoutConfig, IdleTimeoutController, IdleTimeoutEvent, IdleTimeoutRunner,
    IdleTimeoutSubscriber, IdleTracker,
};
pub use peer_address_registry::PeerAddressRegistry;
pub use peer_drain_coordinator::{
    PeerDrainCoordinator, PeerDrainDriver, PeerDrainError, PeerDrainHandle, PeerDrainOutcome,
};
pub use peer_health::{
    new_shared_registry, ConnectionHealthEvent, HealthScoreConfig, HealthScoreRegistry,
    HealthSignal, HealthSignalSink, HealthTier, PeerHealthAggregator,
    PeerHealthLifecycleSubscriber, SharedHealthScoreRegistry, SignalWeight,
};
pub use receive_flow::{
    build_receive_credit, ReceiveCredit, ReceiveFlowConfig, ReceiveFlowController,
    SenderCreditTracker, DEFAULT_INITIAL_CREDITS, DEFAULT_MAX_CREDITS, DEFAULT_REFRESH_AMOUNT,
    DEFAULT_REFRESH_THRESHOLD, RECEIVE_CREDIT_FRAME_SIZE,
};
pub use session_drain::{
    poll_queue_until_empty, DrainConfig, DrainError, DrainOutcome, DrainToken, GracefulDrainConfig,
    SessionDrainError, SessionDrainHandle,
};
