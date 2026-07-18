// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! VFS_RPC control/inline adapter for the TideFS transport envelope.
//!
//! This module binds the existing VFS_RPC service frame surface to the
//! transport CONTROL path. It does not dispatch to a VFS engine; when callers
//! supply the same-session BULK service state, it admits VFS_RPC BULK
//! descriptors against active service `0x07` transfers and keeps them pending
//! until DONE, ABORT, or timeout retirement.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use tidefs_bulk_service::{
    BulkService, BulkToken, ConnectionId, VfsRpcBulkAbort, VfsRpcBulkAdmission,
    VfsRpcBulkCompletion, VfsRpcBulkDescriptor, VfsRpcBulkHandoff, VfsRpcBulkHandoffError,
};
use tidefs_transport::{
    ConnectionBounds, ControlServiceFrame, EndpointFamily, LaneClass, MessageFamily, SessionHealth,
    SessionId, TransportCohortId, TransportEnvelope, TransportError, TransportSessionSet,
    VisibilityClass, CONTROL_SERVICE_ENDPOINT_FAMILY, CONTROL_SERVICE_FRAME_HEADER_LEN,
    CONTROL_SERVICE_LANE, CONTROL_SERVICE_MESSAGE_FAMILY,
};
use tidefs_types_vfs_core::Errno;

use crate::{
    InlineOrBulk, OpId, PeerId, VfsRpcError, VfsRpcMessageKind, VfsRpcRequest,
    VfsRpcRequestPayload, VfsRpcResponse, VfsRpcResponsePayload, VfsRpcTransportFrame,
    REQ_FLAG_BULK_PENDING, RESP_FLAG_BULK,
};

/// Endpoint family selected for VFS_RPC control/inline frames.
pub const VFS_RPC_CONTROL_ENDPOINT_FAMILY: EndpointFamily = CONTROL_SERVICE_ENDPOINT_FAMILY;
/// Transport message family used for VFS_RPC control/inline frames.
pub const VFS_RPC_CONTROL_MESSAGE_FAMILY: MessageFamily = CONTROL_SERVICE_MESSAGE_FAMILY;
/// Lane selected by [`VFS_RPC_CONTROL_MESSAGE_FAMILY`].
pub const VFS_RPC_CONTROL_LANE: LaneClass = CONTROL_SERVICE_LANE;

/// Adapter configuration for frame bounds and retry timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcTransportAdapterConfig {
    pub max_frame_bytes: usize,
    pub request_timeout: Duration,
    pub retry_after: Duration,
}

impl Default for VfsRpcTransportAdapterConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: ConnectionBounds::default().max_frame_bytes as usize,
            request_timeout: Duration::from_secs(30),
            retry_after: Duration::from_millis(250),
        }
    }
}

/// Per-frame envelope fields supplied by the transport session runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcEnvelopeContext {
    pub cohort_id: TransportCohortId,
    pub sequence_number: u64,
    pub ack_floor: u64,
    pub visibility_class: VisibilityClass,
}

impl Default for VfsRpcEnvelopeContext {
    fn default() -> Self {
        Self {
            cohort_id: TransportCohortId::zero(),
            sequence_number: 0,
            ack_floor: 0,
            visibility_class: VisibilityClass::Internal,
        }
    }
}

/// Encoded VFS_RPC service frame and the transport envelope selected for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcOutboundFrame {
    pub peer: PeerId,
    pub session_id: SessionId,
    pub op_id: OpId,
    pub envelope: TransportEnvelope,
    pub payload: Vec<u8>,
}

/// Decoded inbound VFS_RPC frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcInboundFrame {
    Request {
        peer: PeerId,
        session_id: SessionId,
        request: VfsRpcRequest,
    },
    Response {
        peer: PeerId,
        session_id: SessionId,
        response: VfsRpcResponse,
    },
}

/// Retry signal for a still-pending outbound request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcRetrySignal {
    pub peer: PeerId,
    pub session_id: SessionId,
    pub op_id: OpId,
    pub method: crate::VfsRpcMethod,
    pub retries: u32,
    pub retry_after: Duration,
}

/// Timeout signal for an expired outbound request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcTimeoutSignal {
    pub peer: PeerId,
    pub session_id: SessionId,
    pub op_id: OpId,
    pub method: crate::VfsRpcMethod,
    pub timeout: Duration,
    pub bulk: Option<VfsRpcBulkAdmissionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingTransportRequest {
    peer: PeerId,
    session_id: SessionId,
    method: crate::VfsRpcMethod,
    sent_at: Instant,
    last_attempt_at: Instant,
    retries: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingTransportKey {
    peer: PeerId,
    op_id: OpId,
}

/// Same-session BULK descriptor admitted by the VFS_RPC transport adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VfsRpcBulkAdmissionRecord {
    pub peer: PeerId,
    pub session_id: SessionId,
    pub connection_id: ConnectionId,
    pub stream_id: tidefs_bulk_service::StreamId,
    pub token: BulkToken,
    pub op_id: OpId,
    pub method: crate::VfsRpcMethod,
    pub direction: VfsRpcFrameDirection,
    pub handoff: VfsRpcBulkHandoff,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PendingBulkKey {
    connection_id: ConnectionId,
    token: BulkToken,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingBulkAdmission {
    peer: PeerId,
    session_id: SessionId,
    op_id: OpId,
    method: crate::VfsRpcMethod,
    direction: VfsRpcFrameDirection,
    handoff: VfsRpcBulkHandoff,
    len: u64,
    stream_id: tidefs_bulk_service::StreamId,
}

impl PendingBulkAdmission {
    fn as_record(self, connection_id: ConnectionId, token: BulkToken) -> VfsRpcBulkAdmissionRecord {
        VfsRpcBulkAdmissionRecord {
            peer: self.peer,
            session_id: self.session_id,
            connection_id,
            stream_id: self.stream_id,
            token,
            op_id: self.op_id,
            method: self.method,
            direction: self.direction,
            handoff: self.handoff,
            len: self.len,
        }
    }
}

/// VFS_RPC transport-envelope adapter.
#[derive(Clone, Debug)]
pub struct VfsRpcTransportAdapter {
    config: VfsRpcTransportAdapterConfig,
    sessions: TransportSessionSet,
    pending: BTreeMap<PendingTransportKey, PendingTransportRequest>,
    pending_bulk: BTreeMap<PendingBulkKey, PendingBulkAdmission>,
}

impl VfsRpcTransportAdapter {
    #[must_use]
    pub fn new(config: VfsRpcTransportAdapterConfig, sessions: TransportSessionSet) -> Self {
        Self {
            config,
            sessions,
            pending: BTreeMap::new(),
            pending_bulk: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn config(&self) -> VfsRpcTransportAdapterConfig {
        self.config
    }

    #[must_use]
    pub fn sessions(&self) -> &TransportSessionSet {
        &self.sessions
    }

    #[must_use]
    pub fn sessions_mut(&mut self) -> &mut TransportSessionSet {
        &mut self.sessions
    }

    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn pending_bulk_len(&self) -> usize {
        self.pending_bulk.len()
    }

    /// Wrap an outbound request and record its `op_id` for response correlation.
    pub fn begin_request(
        &mut self,
        peer: PeerId,
        request: &VfsRpcRequest,
        now: Instant,
        context: VfsRpcEnvelopeContext,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        reject_request_bulk(request)?;
        let session_id = self.healthy_session_for(peer)?;
        let outbound = self.wrap_request_for_session(peer, session_id, request, context)?;
        let key = PendingTransportKey {
            peer,
            op_id: request.header.op_id,
        };
        self.pending.insert(
            key,
            PendingTransportRequest {
                peer,
                session_id,
                method: request.header.method,
                sent_at: now,
                last_attempt_at: now,
                retries: 0,
            },
        );
        Ok(outbound)
    }

    /// Wrap an outbound request after admitting any BULK descriptor against
    /// the same authenticated transport session.
    pub fn begin_request_with_bulk(
        &mut self,
        peer: PeerId,
        request: &VfsRpcRequest,
        now: Instant,
        context: VfsRpcEnvelopeContext,
        bulk_service: &BulkService,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        let session_id = self.healthy_session_for(peer)?;
        let outbound = self.wrap_request_for_session_with_bulk(
            peer,
            session_id,
            request,
            context,
            bulk_service,
        )?;
        let key = PendingTransportKey {
            peer,
            op_id: request.header.op_id,
        };
        self.pending.insert(
            key,
            PendingTransportRequest {
                peer,
                session_id,
                method: request.header.method,
                sent_at: now,
                last_attempt_at: now,
                retries: 0,
            },
        );
        Ok(outbound)
    }

    /// Wrap an outbound request for an already-selected session without
    /// modifying the correlation table.
    pub fn wrap_request_for_session(
        &self,
        peer: PeerId,
        session_id: SessionId,
        request: &VfsRpcRequest,
        context: VfsRpcEnvelopeContext,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        reject_request_bulk(request)?;
        let frame = VfsRpcTransportFrame::from_request(request)?;
        let payload = encode_control_service_frame(frame)?;
        let envelope = self.envelope_for(session_id, context, payload.len())?;
        Ok(VfsRpcOutboundFrame {
            peer,
            session_id,
            op_id: request.header.op_id,
            envelope,
            payload,
        })
    }

    /// Wrap an outbound request for a selected session and admit active BULK
    /// descriptors against `bulk_service`.
    pub fn wrap_request_for_session_with_bulk(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        request: &VfsRpcRequest,
        context: VfsRpcEnvelopeContext,
        bulk_service: &BulkService,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        check_request_peer(peer, request)?;
        self.admit_request_bulk(peer, session_id, request, bulk_service)?;
        let frame = VfsRpcTransportFrame::from_request(request)?;
        let payload = encode_control_service_frame(frame)?;
        let envelope = self.envelope_for(session_id, context, payload.len())?;
        Ok(VfsRpcOutboundFrame {
            peer,
            session_id,
            op_id: request.header.op_id,
            envelope,
            payload,
        })
    }

    /// Wrap an outbound response for the control lane.
    pub fn wrap_response_for_session(
        &self,
        peer: PeerId,
        session_id: SessionId,
        response: &VfsRpcResponse,
        context: VfsRpcEnvelopeContext,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        reject_response_bulk(response)?;
        let frame = VfsRpcTransportFrame::from_response(response)?;
        let payload = encode_control_service_frame(frame)?;
        let envelope = self.envelope_for(session_id, context, payload.len())?;
        Ok(VfsRpcOutboundFrame {
            peer,
            session_id,
            op_id: response.header.op_id,
            envelope,
            payload,
        })
    }

    /// Wrap an outbound response and admit READ bulk descriptors against the
    /// same session before exposing the descriptor to the peer.
    pub fn wrap_response_for_session_with_bulk(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        response: &VfsRpcResponse,
        context: VfsRpcEnvelopeContext,
        bulk_service: &BulkService,
    ) -> Result<VfsRpcOutboundFrame, VfsRpcTransportAdapterError> {
        self.admit_response_bulk(peer, session_id, response, bulk_service, false)?;
        let frame = VfsRpcTransportFrame::from_response(response)?;
        let payload = encode_control_service_frame(frame)?;
        let envelope = self.envelope_for(session_id, context, payload.len())?;
        Ok(VfsRpcOutboundFrame {
            peer,
            session_id,
            op_id: response.header.op_id,
            envelope,
            payload,
        })
    }

    /// Decode an inbound control-lane payload and validate peer/session state.
    pub fn unwrap_inbound(
        &mut self,
        now: Instant,
        envelope: &TransportEnvelope,
        payload: &[u8],
    ) -> Result<VfsRpcInboundFrame, VfsRpcTransportAdapterError> {
        self.check_envelope(envelope, payload.len())?;
        let peer = self.peer_for_session(envelope.session_id)?;
        let service_frame = ControlServiceFrame::decode(payload)
            .map_err(VfsRpcTransportAdapterError::ControlService)?;
        let rpc_frame = VfsRpcTransportFrame {
            service_id: service_frame.service_id,
            message_type: service_frame.message_type,
            body: service_frame.body,
        };

        match VfsRpcMessageKind::from_message_type(rpc_frame.message_type)? {
            VfsRpcMessageKind::Request => {
                let request = rpc_frame.decode_request()?;
                check_request_peer(peer, &request)?;
                reject_request_bulk(&request)?;
                Ok(VfsRpcInboundFrame::Request {
                    peer,
                    session_id: envelope.session_id,
                    request,
                })
            }
            VfsRpcMessageKind::Response => {
                let response = rpc_frame.decode_response()?;
                reject_response_bulk(&response)?;
                self.complete_response(now, peer, envelope.session_id, &response)?;
                Ok(VfsRpcInboundFrame::Response {
                    peer,
                    session_id: envelope.session_id,
                    response,
                })
            }
        }
    }

    /// Decode an inbound frame and admit active BULK descriptors against the
    /// same authenticated transport session.
    pub fn unwrap_inbound_with_bulk(
        &mut self,
        now: Instant,
        envelope: &TransportEnvelope,
        payload: &[u8],
        bulk_service: &BulkService,
    ) -> Result<VfsRpcInboundFrame, VfsRpcTransportAdapterError> {
        self.check_envelope(envelope, payload.len())?;
        let service_frame = ControlServiceFrame::decode(payload)
            .map_err(VfsRpcTransportAdapterError::ControlService)?;
        self.unwrap_control_service_frame_with_bulk(
            now,
            envelope.session_id,
            service_frame,
            bulk_service,
        )
    }

    /// Decode an already-demultiplexed CONTROL service frame and admit active
    /// BULK descriptors against its authenticated session.
    ///
    /// CONTROL service handlers receive the session identity and decoded
    /// service frame from transport dispatch, not a full envelope. This entry
    /// point preserves the same VFS_RPC/BULK admission rules for that runtime
    /// path without reconstructing synthetic envelope state.
    pub fn unwrap_control_service_frame_with_bulk(
        &mut self,
        now: Instant,
        session_id: SessionId,
        service_frame: ControlServiceFrame,
        bulk_service: &BulkService,
    ) -> Result<VfsRpcInboundFrame, VfsRpcTransportAdapterError> {
        let payload_len = CONTROL_SERVICE_FRAME_HEADER_LEN
            .checked_add(service_frame.body.len())
            .ok_or(VfsRpcTransportAdapterError::FrameTooLarge {
                actual: usize::MAX,
                max: self.config.max_frame_bytes,
            })?;
        self.check_frame_size(payload_len, 0)?;
        let peer = self.peer_for_session(session_id)?;
        let rpc_frame = VfsRpcTransportFrame {
            service_id: service_frame.service_id,
            message_type: service_frame.message_type,
            body: service_frame.body,
        };

        match VfsRpcMessageKind::from_message_type(rpc_frame.message_type)? {
            VfsRpcMessageKind::Request => {
                let request = rpc_frame.decode_request()?;
                check_request_peer(peer, &request)?;
                self.admit_request_bulk(peer, session_id, &request, bulk_service)?;
                Ok(VfsRpcInboundFrame::Request {
                    peer,
                    session_id,
                    request,
                })
            }
            VfsRpcMessageKind::Response => {
                let response = rpc_frame.decode_response()?;
                let has_bulk =
                    self.admit_response_bulk(peer, session_id, &response, bulk_service, true)?;
                if !has_bulk {
                    self.complete_response(now, peer, session_id, &response)?;
                }
                Ok(VfsRpcInboundFrame::Response {
                    peer,
                    session_id,
                    response,
                })
            }
        }
    }

    /// Mark retryable requests whose retry timer has elapsed.
    pub fn retry_due(&mut self, now: Instant) -> Vec<VfsRpcRetrySignal> {
        let bulk_guarded: Vec<PendingTransportKey> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                self.bulk_admission_for_op(pending.peer, pending.session_id, key.op_id)
                    .map(|_| *key)
            })
            .collect();
        let mut due = Vec::new();
        for (key, pending) in &mut self.pending {
            if bulk_guarded.contains(key) {
                continue;
            }
            if now.saturating_duration_since(pending.last_attempt_at) >= self.config.retry_after {
                pending.last_attempt_at = now;
                pending.retries = pending.retries.saturating_add(1);
                due.push(VfsRpcRetrySignal {
                    peer: pending.peer,
                    session_id: pending.session_id,
                    op_id: key.op_id,
                    method: pending.method,
                    retries: pending.retries,
                    retry_after: self.config.retry_after,
                });
            }
        }
        due
    }

    /// Expire requests that exceeded the configured request timeout.
    pub fn expire_timed_out(&mut self, now: Instant) -> Vec<VfsRpcTimeoutSignal> {
        let expired: Vec<PendingTransportKey> = self
            .pending
            .iter()
            .filter_map(|(key, pending)| {
                if now.saturating_duration_since(pending.sent_at) >= self.config.request_timeout {
                    Some(*key)
                } else {
                    None
                }
            })
            .collect();

        let mut signals = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                signals.push(VfsRpcTimeoutSignal {
                    peer: pending.peer,
                    session_id: pending.session_id,
                    op_id: key.op_id,
                    method: pending.method,
                    timeout: self.config.request_timeout,
                    bulk: self.remove_bulk_admission_for_op(
                        pending.peer,
                        pending.session_id,
                        key.op_id,
                    ),
                });
            }
        }
        signals
    }

    /// Retire a DONE-verified BULK handoff and, for READ bulk responses, only
    /// then complete the original VFS_RPC response correlation.
    pub fn complete_bulk_handoff(
        &mut self,
        completion: &VfsRpcBulkCompletion,
    ) -> Result<VfsRpcBulkAdmissionRecord, VfsRpcTransportAdapterError> {
        let record = self.remove_matching_bulk_admission(
            completion.connection_id,
            completion.stream_id,
            completion.token,
            completion.op_id,
            completion.handoff,
            completion.len,
        )?;
        if record.direction == VfsRpcFrameDirection::Response {
            self.pending.remove(&PendingTransportKey {
                peer: record.peer,
                op_id: record.op_id,
            });
        }
        Ok(record)
    }

    /// Retire an ABORTed BULK handoff so retries must obtain a fresh token.
    pub fn abort_bulk_handoff(
        &mut self,
        abort: &VfsRpcBulkAbort,
    ) -> Result<VfsRpcBulkAdmissionRecord, VfsRpcTransportAdapterError> {
        let record = self.remove_matching_bulk_admission(
            abort.connection_id,
            abort.stream_id,
            abort.token,
            abort.op_id,
            abort.handoff,
            0,
        )?;
        if record.direction == VfsRpcFrameDirection::Response {
            self.pending.remove(&PendingTransportKey {
                peer: record.peer,
                op_id: record.op_id,
            });
        }
        Ok(record)
    }

    fn envelope_for(
        &self,
        session_id: SessionId,
        context: VfsRpcEnvelopeContext,
        payload_len: usize,
    ) -> Result<TransportEnvelope, VfsRpcTransportAdapterError> {
        self.check_frame_size(payload_len, 0)?;
        Ok(TransportEnvelope::new(
            session_id,
            context.cohort_id,
            VFS_RPC_CONTROL_LANE,
            VFS_RPC_CONTROL_MESSAGE_FAMILY,
            context.sequence_number,
            context.ack_floor,
            Vec::new(),
            context.visibility_class,
        ))
    }

    fn check_envelope(
        &self,
        envelope: &TransportEnvelope,
        payload_len: usize,
    ) -> Result<(), VfsRpcTransportAdapterError> {
        if envelope.message_family != VFS_RPC_CONTROL_MESSAGE_FAMILY {
            return Err(VfsRpcTransportAdapterError::WrongMessageFamily {
                found: envelope.message_family,
            });
        }
        if envelope.lane_class != VFS_RPC_CONTROL_LANE {
            return Err(VfsRpcTransportAdapterError::WrongLane {
                found: envelope.lane_class,
            });
        }
        self.check_frame_size(payload_len, envelope.anchor_refs.len())
    }

    fn check_frame_size(
        &self,
        payload_len: usize,
        anchor_count: usize,
    ) -> Result<(), VfsRpcTransportAdapterError> {
        let wire_size = TransportEnvelope::wire_size(payload_len, anchor_count);
        if wire_size > self.config.max_frame_bytes {
            return Err(VfsRpcTransportAdapterError::FrameTooLarge {
                actual: wire_size,
                max: self.config.max_frame_bytes,
            });
        }
        Ok(())
    }

    fn healthy_session_for(&self, peer: PeerId) -> Result<SessionId, VfsRpcTransportAdapterError> {
        match self.sessions.get_binding(peer.0) {
            Some(binding) if binding.health == SessionHealth::Healthy => Ok(binding.session_id),
            Some(binding) => Err(VfsRpcTransportAdapterError::SessionUnavailable {
                peer,
                session_id: binding.session_id,
                health: binding.health,
            }),
            None => Err(VfsRpcTransportAdapterError::PeerUnavailable { peer }),
        }
    }

    fn peer_for_session(
        &self,
        session_id: SessionId,
    ) -> Result<PeerId, VfsRpcTransportAdapterError> {
        let node = self
            .sessions
            .lookup_node(session_id)
            .ok_or(VfsRpcTransportAdapterError::SessionClosed { session_id })?;
        let peer = PeerId(node);
        self.healthy_session_for(peer)?;
        Ok(peer)
    }

    fn complete_response(
        &mut self,
        _now: Instant,
        peer: PeerId,
        session_id: SessionId,
        response: &VfsRpcResponse,
    ) -> Result<(), VfsRpcTransportAdapterError> {
        let key = PendingTransportKey {
            peer,
            op_id: response.header.op_id,
        };
        let pending =
            *self
                .pending
                .get(&key)
                .ok_or(VfsRpcTransportAdapterError::UnknownResponse {
                    op_id: response.header.op_id,
                })?;
        if pending.peer != peer || pending.session_id != session_id {
            return Err(VfsRpcTransportAdapterError::ResponsePeerMismatch {
                op_id: response.header.op_id,
                expected_peer: pending.peer,
                found_peer: peer,
                expected_session: pending.session_id,
                found_session: session_id,
            });
        }
        if pending.method != response.method {
            return Err(VfsRpcTransportAdapterError::VfsRpc(
                VfsRpcError::MethodMismatch {
                    outer: pending.method,
                    inner: response.method,
                },
            ));
        }
        self.pending.remove(&key);
        self.remove_bulk_admission_for_op(peer, session_id, response.header.op_id);
        Ok(())
    }

    fn admit_request_bulk(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        request: &VfsRpcRequest,
        bulk_service: &BulkService,
    ) -> Result<bool, VfsRpcTransportAdapterError> {
        let descriptor = match request_bulk_descriptor(request)? {
            Some(descriptor) => descriptor,
            None => return Ok(false),
        };
        let connection_id = connection_id_for_session(session_id);
        let admission = bulk_service
            .admit_vfs_rpc_write_upload(connection_id, descriptor, request.header.op_id.0)
            .map_err(|error| VfsRpcTransportAdapterError::BulkHandoff {
                op_id: request.header.op_id,
                method: request.header.method,
                direction: VfsRpcFrameDirection::Request,
                error,
            })?;
        self.record_bulk_admission(
            peer,
            session_id,
            request.header.method,
            VfsRpcFrameDirection::Request,
            admission,
        );
        Ok(true)
    }

    fn admit_response_bulk(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        response: &VfsRpcResponse,
        bulk_service: &BulkService,
        check_pending: bool,
    ) -> Result<bool, VfsRpcTransportAdapterError> {
        let descriptor = match response_bulk_descriptor(response)? {
            Some(descriptor) => descriptor,
            None => return Ok(false),
        };
        if check_pending {
            self.check_pending_response(peer, session_id, response)?;
        }
        let connection_id = connection_id_for_session(session_id);
        let admission = bulk_service
            .admit_vfs_rpc_read_download(connection_id, descriptor, response.header.op_id.0)
            .map_err(|error| VfsRpcTransportAdapterError::BulkHandoff {
                op_id: response.header.op_id,
                method: response.method,
                direction: VfsRpcFrameDirection::Response,
                error,
            })?;
        self.record_bulk_admission(
            peer,
            session_id,
            response.method,
            VfsRpcFrameDirection::Response,
            admission,
        );
        Ok(true)
    }

    fn check_pending_response(
        &self,
        peer: PeerId,
        session_id: SessionId,
        response: &VfsRpcResponse,
    ) -> Result<(), VfsRpcTransportAdapterError> {
        let key = PendingTransportKey {
            peer,
            op_id: response.header.op_id,
        };
        let pending =
            *self
                .pending
                .get(&key)
                .ok_or(VfsRpcTransportAdapterError::UnknownResponse {
                    op_id: response.header.op_id,
                })?;
        if pending.peer != peer || pending.session_id != session_id {
            return Err(VfsRpcTransportAdapterError::ResponsePeerMismatch {
                op_id: response.header.op_id,
                expected_peer: pending.peer,
                found_peer: peer,
                expected_session: pending.session_id,
                found_session: session_id,
            });
        }
        if pending.method != response.method {
            return Err(VfsRpcTransportAdapterError::VfsRpc(
                VfsRpcError::MethodMismatch {
                    outer: pending.method,
                    inner: response.method,
                },
            ));
        }
        Ok(())
    }

    fn record_bulk_admission(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        method: crate::VfsRpcMethod,
        direction: VfsRpcFrameDirection,
        admission: VfsRpcBulkAdmission,
    ) {
        let key = PendingBulkKey {
            connection_id: admission.connection_id,
            token: admission.token,
        };
        self.pending_bulk.insert(
            key,
            PendingBulkAdmission {
                peer,
                session_id,
                op_id: OpId(admission.op_id),
                method,
                direction,
                handoff: admission.handoff,
                len: admission.len,
                stream_id: admission.stream_id,
            },
        );
    }

    fn remove_matching_bulk_admission(
        &mut self,
        connection_id: ConnectionId,
        stream_id: tidefs_bulk_service::StreamId,
        token: BulkToken,
        op_id: tidefs_bulk_service::OpId,
        handoff: VfsRpcBulkHandoff,
        len: u64,
    ) -> Result<VfsRpcBulkAdmissionRecord, VfsRpcTransportAdapterError> {
        let key = PendingBulkKey {
            connection_id,
            token,
        };
        let record = *self.pending_bulk.get(&key).ok_or(
            VfsRpcTransportAdapterError::UnknownBulkCompletion {
                connection_id,
                token,
                op_id: OpId(op_id),
                handoff,
            },
        )?;
        if record.op_id != OpId(op_id)
            || record.stream_id != stream_id
            || record.handoff != handoff
            || (len != 0 && record.len != len)
        {
            return Err(VfsRpcTransportAdapterError::BulkCompletionMismatch {
                expected: record.as_record(connection_id, token),
                op_id: OpId(op_id),
                handoff,
                len,
            });
        }
        let record = self
            .pending_bulk
            .remove(&key)
            .expect("matching bulk admission remains after validation");
        Ok(record.as_record(connection_id, token))
    }

    fn bulk_admission_for_op(
        &self,
        peer: PeerId,
        session_id: SessionId,
        op_id: OpId,
    ) -> Option<VfsRpcBulkAdmissionRecord> {
        self.pending_bulk.iter().find_map(|(key, record)| {
            if record.peer == peer && record.session_id == session_id && record.op_id == op_id {
                Some(record.as_record(key.connection_id, key.token))
            } else {
                None
            }
        })
    }

    fn remove_bulk_admission_for_op(
        &mut self,
        peer: PeerId,
        session_id: SessionId,
        op_id: OpId,
    ) -> Option<VfsRpcBulkAdmissionRecord> {
        let key = self.pending_bulk.iter().find_map(|(key, record)| {
            if record.peer == peer && record.session_id == session_id && record.op_id == op_id {
                Some(*key)
            } else {
                None
            }
        })?;
        self.pending_bulk
            .remove(&key)
            .map(|record| record.as_record(key.connection_id, key.token))
    }
}

fn encode_control_service_frame(
    frame: VfsRpcTransportFrame,
) -> Result<Vec<u8>, VfsRpcTransportAdapterError> {
    ControlServiceFrame::new(frame.service_id, frame.message_type, frame.body)
        .encode()
        .map_err(VfsRpcTransportAdapterError::ControlService)
}

fn reject_request_bulk(request: &VfsRpcRequest) -> Result<(), VfsRpcTransportAdapterError> {
    if request.header.flags & REQ_FLAG_BULK_PENDING != 0
        || request_payload_has_bulk(&request.payload)
    {
        return Err(VfsRpcTransportAdapterError::BulkUnsupported {
            op_id: request.header.op_id,
            method: request.header.method,
            direction: VfsRpcFrameDirection::Request,
        });
    }
    Ok(())
}

fn reject_response_bulk(response: &VfsRpcResponse) -> Result<(), VfsRpcTransportAdapterError> {
    if response.header.flags & RESP_FLAG_BULK != 0 || response_payload_has_bulk(&response.payload) {
        return Err(VfsRpcTransportAdapterError::BulkUnsupported {
            op_id: response.header.op_id,
            method: response.method,
            direction: VfsRpcFrameDirection::Response,
        });
    }
    Ok(())
}

fn request_bulk_descriptor(
    request: &VfsRpcRequest,
) -> Result<Option<VfsRpcBulkDescriptor>, VfsRpcTransportAdapterError> {
    let flag = request.header.flags & REQ_FLAG_BULK_PENDING != 0;
    match &request.payload {
        VfsRpcRequestPayload::Write {
            data: InlineOrBulk::Bulk { token, len },
            ..
        } if flag => Ok(Some(VfsRpcBulkDescriptor {
            token: *token,
            len: *len,
        })),
        VfsRpcRequestPayload::Write {
            data: InlineOrBulk::Bulk { .. },
            ..
        } => Err(VfsRpcTransportAdapterError::BulkDescriptorInvalid {
            op_id: request.header.op_id,
            method: request.header.method,
            direction: VfsRpcFrameDirection::Request,
            reason: "WRITE bulk descriptor missing REQ_FLAG_BULK_PENDING",
        }),
        _ if flag => Err(VfsRpcTransportAdapterError::BulkDescriptorInvalid {
            op_id: request.header.op_id,
            method: request.header.method,
            direction: VfsRpcFrameDirection::Request,
            reason: "REQ_FLAG_BULK_PENDING without WRITE bulk descriptor",
        }),
        _ => Ok(None),
    }
}

fn response_bulk_descriptor(
    response: &VfsRpcResponse,
) -> Result<Option<VfsRpcBulkDescriptor>, VfsRpcTransportAdapterError> {
    let flag = response.header.flags & RESP_FLAG_BULK != 0;
    match &response.payload {
        VfsRpcResponsePayload::Data(InlineOrBulk::Bulk { token, len }) if flag => {
            Ok(Some(VfsRpcBulkDescriptor {
                token: *token,
                len: *len,
            }))
        }
        VfsRpcResponsePayload::Data(InlineOrBulk::Bulk { .. }) => {
            Err(VfsRpcTransportAdapterError::BulkDescriptorInvalid {
                op_id: response.header.op_id,
                method: response.method,
                direction: VfsRpcFrameDirection::Response,
                reason: "READ bulk descriptor missing RESP_FLAG_BULK",
            })
        }
        _ if flag => Err(VfsRpcTransportAdapterError::BulkDescriptorInvalid {
            op_id: response.header.op_id,
            method: response.method,
            direction: VfsRpcFrameDirection::Response,
            reason: "RESP_FLAG_BULK without READ bulk descriptor",
        }),
        _ => Ok(None),
    }
}

fn connection_id_for_session(session_id: SessionId) -> ConnectionId {
    session_id.0
}

fn request_payload_has_bulk(payload: &VfsRpcRequestPayload) -> bool {
    matches!(
        payload,
        VfsRpcRequestPayload::Write {
            data: InlineOrBulk::Bulk { .. },
            ..
        }
    )
}

fn response_payload_has_bulk(payload: &VfsRpcResponsePayload) -> bool {
    matches!(
        payload,
        VfsRpcResponsePayload::Data(InlineOrBulk::Bulk { .. })
    )
}

fn check_request_peer(
    peer: PeerId,
    request: &VfsRpcRequest,
) -> Result<(), VfsRpcTransportAdapterError> {
    if let Some(credentials) = &request.credentials {
        if credentials.peer_id != peer {
            return Err(VfsRpcTransportAdapterError::PeerIdentityMismatch {
                expected: peer,
                found: credentials.peer_id,
            });
        }
    }
    Ok(())
}

/// Direction of a VFS_RPC service frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsRpcFrameDirection {
    Request,
    Response,
}

/// Transport failure classification visible to VFS_RPC callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VfsRpcTransportFailure {
    pub peer: PeerId,
    pub session_id: Option<SessionId>,
    pub errno: Errno,
    pub retryable: bool,
    pub reason: String,
}

impl VfsRpcTransportFailure {
    #[must_use]
    pub fn from_transport_error(peer: PeerId, error: &TransportError) -> Self {
        match error {
            TransportError::PeerNotInRoster {
                peer_id,
                session_id,
            } => Self {
                peer,
                session_id: Some(*session_id),
                errno: Errno::EHOSTUNREACH,
                retryable: true,
                reason: format!("peer {peer_id} refused by committed-roster send gate"),
            },
            TransportError::SessionNotFound { session_id }
            | TransportError::SendBufferShutdown { session_id } => Self {
                peer,
                session_id: Some(*session_id),
                errno: Errno::ENOTCONN,
                retryable: true,
                reason: error.to_string(),
            },
            TransportError::SessionInWrongState { session_id, .. } => Self {
                peer,
                session_id: Some(*session_id),
                errno: Errno::EPIPE,
                retryable: true,
                reason: error.to_string(),
            },
            TransportError::SendBufferFull { session_id, .. }
            | TransportError::SendConcurrencyLimitExceeded { session_id, .. } => Self {
                peer,
                session_id: Some(*session_id),
                errno: Errno::EAGAIN,
                retryable: true,
                reason: error.to_string(),
            },
            TransportError::WouldBlock(_) => Self {
                peer,
                session_id: None,
                errno: Errno::EAGAIN,
                retryable: true,
                reason: error.to_string(),
            },
            _ => Self {
                peer,
                session_id: None,
                errno: Errno::EIO,
                retryable: false,
                reason: error.to_string(),
            },
        }
    }
}

/// Errors emitted by the VFS_RPC transport adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VfsRpcTransportAdapterError {
    VfsRpc(VfsRpcError),
    ControlService(tidefs_transport::ControlServiceDispatchError),
    PeerUnavailable {
        peer: PeerId,
    },
    SessionUnavailable {
        peer: PeerId,
        session_id: SessionId,
        health: SessionHealth,
    },
    SessionClosed {
        session_id: SessionId,
    },
    PeerIdentityMismatch {
        expected: PeerId,
        found: PeerId,
    },
    WrongMessageFamily {
        found: MessageFamily,
    },
    WrongLane {
        found: LaneClass,
    },
    FrameTooLarge {
        actual: usize,
        max: usize,
    },
    BulkUnsupported {
        op_id: OpId,
        method: crate::VfsRpcMethod,
        direction: VfsRpcFrameDirection,
    },
    BulkDescriptorInvalid {
        op_id: OpId,
        method: crate::VfsRpcMethod,
        direction: VfsRpcFrameDirection,
        reason: &'static str,
    },
    BulkHandoff {
        op_id: OpId,
        method: crate::VfsRpcMethod,
        direction: VfsRpcFrameDirection,
        error: VfsRpcBulkHandoffError,
    },
    UnknownBulkCompletion {
        connection_id: ConnectionId,
        token: BulkToken,
        op_id: OpId,
        handoff: VfsRpcBulkHandoff,
    },
    BulkCompletionMismatch {
        expected: VfsRpcBulkAdmissionRecord,
        op_id: OpId,
        handoff: VfsRpcBulkHandoff,
        len: u64,
    },
    UnknownResponse {
        op_id: OpId,
    },
    ResponsePeerMismatch {
        op_id: OpId,
        expected_peer: PeerId,
        found_peer: PeerId,
        expected_session: SessionId,
        found_session: SessionId,
    },
    TransportFailure(VfsRpcTransportFailure),
}

impl VfsRpcTransportAdapterError {
    #[must_use]
    pub fn errno(&self) -> Errno {
        match self {
            Self::VfsRpc(_) | Self::ControlService(_) | Self::WrongMessageFamily { .. } => {
                Errno::EPROTO
            }
            Self::PeerUnavailable { .. } | Self::SessionUnavailable { .. } => Errno::EHOSTUNREACH,
            Self::SessionClosed { .. } => Errno::ENOTCONN,
            Self::PeerIdentityMismatch { .. } => Errno::EACCES,
            Self::WrongLane { .. } => Errno::EINVAL,
            Self::FrameTooLarge { .. } => Errno::EMSGSIZE,
            Self::BulkUnsupported { .. } => Errno::EOPNOTSUPP,
            Self::BulkDescriptorInvalid { .. }
            | Self::BulkHandoff { .. }
            | Self::UnknownBulkCompletion { .. }
            | Self::BulkCompletionMismatch { .. } => Errno::EPROTO,
            Self::UnknownResponse { .. } | Self::ResponsePeerMismatch { .. } => Errno::EPROTO,
            Self::TransportFailure(failure) => failure.errno,
        }
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::PeerUnavailable { .. }
            | Self::SessionUnavailable { .. }
            | Self::SessionClosed { .. } => true,
            Self::TransportFailure(failure) => failure.retryable,
            _ => false,
        }
    }

    pub fn response_for_request(
        &self,
        request: &VfsRpcRequest,
    ) -> Result<VfsRpcResponse, VfsRpcError> {
        VfsRpcResponse::error(request.header.op_id, request.header.method, self.errno())
    }
}

impl From<VfsRpcError> for VfsRpcTransportAdapterError {
    fn from(value: VfsRpcError) -> Self {
        Self::VfsRpc(value)
    }
}

impl From<VfsRpcTransportFailure> for VfsRpcTransportAdapterError {
    fn from(value: VfsRpcTransportFailure) -> Self {
        Self::TransportFailure(value)
    }
}

impl fmt::Display for VfsRpcTransportAdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VfsRpc(error) => write!(f, "{error}"),
            Self::ControlService(error) => write!(f, "{error}"),
            Self::PeerUnavailable { peer } => write!(f, "VFS_RPC peer {} unavailable", peer.0),
            Self::SessionUnavailable {
                peer,
                session_id,
                health,
            } => write!(
                f,
                "VFS_RPC peer {} session {session_id} unavailable: {health:?}",
                peer.0
            ),
            Self::SessionClosed { session_id } => {
                write!(f, "VFS_RPC session {session_id} is closed or unknown")
            }
            Self::PeerIdentityMismatch { expected, found } => write!(
                f,
                "VFS_RPC credential peer mismatch: expected {}, found {}",
                expected.0, found.0
            ),
            Self::WrongMessageFamily { found } => {
                write!(f, "VFS_RPC received on wrong transport family {found}")
            }
            Self::WrongLane { found } => write!(f, "VFS_RPC received on wrong lane {found:?}"),
            Self::FrameTooLarge { actual, max } => {
                write!(f, "VFS_RPC transport frame size {actual} exceeds {max}")
            }
            Self::BulkUnsupported {
                op_id,
                method,
                direction,
            } => write!(
                f,
                "VFS_RPC {direction:?} {method:?}/{} requires BULK, but BULK is not bound",
                op_id.0
            ),
            Self::BulkDescriptorInvalid {
                op_id,
                method,
                direction,
                reason,
            } => write!(
                f,
                "VFS_RPC {direction:?} {method:?}/{} has invalid BULK descriptor: {reason}",
                op_id.0
            ),
            Self::BulkHandoff {
                op_id,
                method,
                direction,
                error,
            } => write!(
                f,
                "VFS_RPC {direction:?} {method:?}/{} rejected by BULK handoff: {error}",
                op_id.0
            ),
            Self::UnknownBulkCompletion {
                connection_id,
                op_id,
                handoff,
                ..
            } => write!(
                f,
                "VFS_RPC BULK {handoff:?}/{} completed without admission on connection {connection_id}",
                op_id.0
            ),
            Self::BulkCompletionMismatch {
                expected,
                op_id,
                handoff,
                len,
            } => write!(
                f,
                "VFS_RPC BULK completion {handoff:?}/{} len {len} does not match admitted {:?}/{} len {}",
                op_id.0, expected.handoff, expected.op_id.0, expected.len
            ),
            Self::UnknownResponse { op_id } => {
                write!(f, "unknown VFS_RPC transport response op_id {}", op_id.0)
            }
            Self::ResponsePeerMismatch {
                op_id,
                expected_peer,
                found_peer,
                expected_session,
                found_session,
            } => write!(
                f,
                "VFS_RPC response {} arrived from peer {}/session {found_session}, expected peer {}/session {expected_session}",
                op_id.0, found_peer.0, expected_peer.0
            ),
            Self::TransportFailure(failure) => write!(f, "{}", failure.reason),
        }
    }
}

impl std::error::Error for VfsRpcTransportAdapterError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatasetId, VfsRpcCredentials, VfsRpcMethod, VFS_RPC_SERVICE_ID};
    use tidefs_bulk_service::{BulkAbortReason, BulkPriority, BulkService, BulkServiceConfig};
    use tidefs_transport::TransportError;
    use tidefs_types_vfs_core::{Generation, InodeId};

    fn healthy_sessions(peer: PeerId, session_id: SessionId) -> TransportSessionSet {
        let mut sessions = TransportSessionSet::new();
        sessions.add_binding(peer.0, session_id);
        sessions.mark_healthy(session_id);
        sessions
    }

    fn sample_request() -> VfsRpcRequest {
        VfsRpcRequest::new(
            OpId(7),
            2,
            3,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId(1),
                name: b"name".to_vec(),
            },
            Some(VfsRpcCredentials::root(PeerId(9))),
        )
        .expect("request")
    }

    fn sample_file_handle() -> crate::VfsRpcHandle {
        crate::VfsRpcHandle {
            handle_type: crate::VfsRpcHandleType::File,
            flags: 0,
            dataset_id: DatasetId(1),
            inode: InodeId(2),
            generation: Generation(3),
            writer_node: 4,
            handle_cookie: 5,
        }
    }

    fn bulk_service() -> BulkService {
        BulkService::new(BulkServiceConfig {
            receiver_node_id: 42,
            max_transfer_len: 64 * 1024,
            ..BulkServiceConfig::default()
        })
    }

    fn encode_response_payload(response: &VfsRpcResponse) -> (TransportEnvelope, Vec<u8>) {
        let frame = VfsRpcTransportFrame::from_response(response).expect("rpc frame");
        let payload = encode_control_service_frame(frame).expect("control frame");
        let envelope = TransportEnvelope::new(
            SessionId::new(33),
            TransportCohortId::zero(),
            VFS_RPC_CONTROL_LANE,
            VFS_RPC_CONTROL_MESSAGE_FAMILY,
            0,
            0,
            Vec::new(),
            VisibilityClass::Internal,
        );
        (envelope, payload)
    }

    #[test]
    fn request_roundtrips_through_control_envelope_without_wire_change() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let request = sample_request();
        let original_body = request.encode().expect("request body");

        let outbound = adapter
            .begin_request(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext {
                    cohort_id: TransportCohortId::new(5),
                    sequence_number: 11,
                    ack_floor: 10,
                    visibility_class: VisibilityClass::Internal,
                },
            )
            .expect("wrap request");

        assert_eq!(
            outbound.envelope.message_family,
            VFS_RPC_CONTROL_MESSAGE_FAMILY
        );
        assert_eq!(outbound.envelope.lane_class, VFS_RPC_CONTROL_LANE);
        assert_eq!(outbound.envelope.session_id, session_id);

        let service_frame = ControlServiceFrame::decode(&outbound.payload).expect("service frame");
        assert_eq!(service_frame.service_id, VFS_RPC_SERVICE_ID);
        assert_eq!(service_frame.message_type, request.message_type());
        assert_eq!(service_frame.body, original_body);

        let inbound = adapter
            .unwrap_inbound(Instant::now(), &outbound.envelope, &outbound.payload)
            .expect("unwrap request");
        match inbound {
            VfsRpcInboundFrame::Request {
                peer: got_peer,
                session_id: got_session,
                request: decoded,
            } => {
                assert_eq!(got_peer, peer);
                assert_eq!(got_session, session_id);
                assert_eq!(decoded, request);
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn response_completion_correlates_op_id_and_clears_pending() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let now = Instant::now();
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let request = sample_request();
        adapter
            .begin_request(peer, &request, now, VfsRpcEnvelopeContext::default())
            .expect("begin");
        assert_eq!(adapter.pending_len(), 1);

        let response =
            VfsRpcResponse::error(OpId(7), VfsRpcMethod::Lookup, Errno::ENOENT).expect("response");
        let outbound = adapter
            .wrap_response_for_session(
                peer,
                session_id,
                &response,
                VfsRpcEnvelopeContext::default(),
            )
            .expect("wrap response");

        let inbound = adapter
            .unwrap_inbound(now, &outbound.envelope, &outbound.payload)
            .expect("unwrap response");

        match inbound {
            VfsRpcInboundFrame::Response {
                peer: got_peer,
                response: decoded,
                ..
            } => {
                assert_eq!(got_peer, peer);
                assert_eq!(decoded, response);
            }
            other => panic!("expected response, got {other:?}"),
        }
        assert_eq!(adapter.pending_len(), 0);
    }

    #[test]
    fn response_completion_keys_op_id_by_peer() {
        let peer_a = PeerId(9);
        let peer_b = PeerId(10);
        let session_a = SessionId::new(33);
        let session_b = SessionId::new(34);
        let now = Instant::now();
        let mut sessions = healthy_sessions(peer_a, session_a);
        sessions.add_binding(peer_b.0, session_b);
        sessions.mark_healthy(session_b);
        let mut adapter =
            VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
        let request = VfsRpcRequest::new(
            OpId(7),
            2,
            3,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId(1),
                name: b"name".to_vec(),
            },
            None,
        )
        .expect("request");

        adapter
            .begin_request(peer_a, &request, now, VfsRpcEnvelopeContext::default())
            .expect("begin peer a");
        adapter
            .begin_request(peer_b, &request, now, VfsRpcEnvelopeContext::default())
            .expect("begin peer b");
        assert_eq!(adapter.pending_len(), 2);

        let response =
            VfsRpcResponse::error(OpId(7), VfsRpcMethod::Lookup, Errno::ENOENT).expect("response");
        let outbound_a = adapter
            .wrap_response_for_session(
                peer_a,
                session_a,
                &response,
                VfsRpcEnvelopeContext::default(),
            )
            .expect("wrap peer a response");
        adapter
            .unwrap_inbound(now, &outbound_a.envelope, &outbound_a.payload)
            .expect("unwrap peer a response");
        assert_eq!(adapter.pending_len(), 1);

        let outbound_b = adapter
            .wrap_response_for_session(
                peer_b,
                session_b,
                &response,
                VfsRpcEnvelopeContext::default(),
            )
            .expect("wrap peer b response");
        adapter
            .unwrap_inbound(now, &outbound_b.envelope, &outbound_b.payload)
            .expect("unwrap peer b response");
        assert_eq!(adapter.pending_len(), 0);
    }

    #[test]
    fn mismatched_response_does_not_clear_pending_request() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let other_peer = PeerId(10);
        let other_session = SessionId::new(34);
        let now = Instant::now();
        let mut sessions = healthy_sessions(peer, session_id);
        sessions.add_binding(other_peer.0, other_session);
        sessions.mark_healthy(other_session);
        let mut adapter =
            VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
        let request = sample_request();
        adapter
            .begin_request(peer, &request, now, VfsRpcEnvelopeContext::default())
            .expect("begin");

        let response =
            VfsRpcResponse::error(OpId(7), VfsRpcMethod::Lookup, Errno::ENOENT).expect("response");
        let outbound = adapter
            .wrap_response_for_session(
                other_peer,
                other_session,
                &response,
                VfsRpcEnvelopeContext::default(),
            )
            .expect("wrap response");

        let err = adapter
            .unwrap_inbound(now, &outbound.envelope, &outbound.payload)
            .expect_err("peer mismatch");

        assert_eq!(err.errno(), Errno::EPROTO);
        assert_eq!(adapter.pending_len(), 1);
    }

    #[test]
    fn bulk_request_flag_and_descriptor_are_rejected_as_unsupported() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let flagged = VfsRpcRequest::new(
            OpId(8),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId(1),
                name: b"name".to_vec(),
            },
            None,
        )
        .expect("request");

        let err = adapter
            .begin_request(
                peer,
                &flagged,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
            )
            .expect_err("bulk flag rejected");
        assert_eq!(err.errno(), Errno::EOPNOTSUPP);
        assert!(!err.is_retryable());
        assert_eq!(adapter.pending_len(), 0);

        let bulk = VfsRpcRequest::new(
            OpId(9),
            2,
            3,
            0,
            VfsRpcRequestPayload::Write {
                handle: crate::VfsRpcHandle {
                    handle_type: crate::VfsRpcHandleType::File,
                    flags: 0,
                    dataset_id: DatasetId(1),
                    inode: InodeId(2),
                    generation: tidefs_types_vfs_core::Generation(3),
                    writer_node: 4,
                    handle_cookie: 5,
                },
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: [7; 32],
                    len: 4096,
                },
            },
            None,
        )
        .expect("bulk request");

        assert_eq!(
            adapter
                .begin_request(
                    peer,
                    &bulk,
                    Instant::now(),
                    VfsRpcEnvelopeContext::default()
                )
                .unwrap_err()
                .errno(),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn bulk_write_request_is_admitted_only_on_same_session_service() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let mut bulk = bulk_service();
        let accept =
            bulk.accept_vfs_rpc_write_upload(session_id.0, 11, 42, 4096, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 4096).expect("descriptor");
        let request = VfsRpcRequest::new(
            OpId(42),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle: sample_file_handle(),
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: descriptor.token,
                    len: descriptor.len,
                },
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("request");

        adapter
            .begin_request_with_bulk(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect("bulk admitted");

        assert_eq!(adapter.pending_len(), 1);
        assert_eq!(adapter.pending_bulk_len(), 1);

        let other_session = SessionId::new(34);
        let mut sessions = healthy_sessions(peer, other_session);
        sessions.add_binding(99, session_id);
        let mut wrong_session =
            VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
        let err = wrong_session
            .wrap_request_for_session_with_bulk(
                peer,
                other_session,
                &request,
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect_err("wrong connection rejected");
        assert_eq!(err.errno(), Errno::EPROTO);
        assert_eq!(wrong_session.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_read_response_keeps_request_pending_until_done() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let now = Instant::now();
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let read = VfsRpcRequest::new(
            OpId(55),
            2,
            3,
            0,
            VfsRpcRequestPayload::Read {
                handle: sample_file_handle(),
                offset: 0,
                length: 8192,
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("read request");
        adapter
            .begin_request(peer, &read, now, VfsRpcEnvelopeContext::default())
            .expect("begin read");

        let mut bulk = bulk_service();
        let accept = bulk.accept_vfs_rpc_read_download(
            session_id.0,
            12,
            read.header.op_id.0,
            8192,
            BulkPriority::Bulk,
        );
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 8192).expect("descriptor");
        let response = VfsRpcResponse::ok(
            read.header.op_id,
            VfsRpcMethod::Read,
            RESP_FLAG_BULK,
            VfsRpcResponsePayload::Data(InlineOrBulk::Bulk {
                token: descriptor.token,
                len: descriptor.len,
            }),
        )
        .expect("bulk response");
        let (envelope, payload) = encode_response_payload(&response);

        adapter
            .unwrap_inbound_with_bulk(now, &envelope, &payload, &bulk)
            .expect("bulk response admitted");
        assert_eq!(adapter.pending_len(), 1);
        assert_eq!(adapter.pending_bulk_len(), 1);
        assert!(adapter.retry_due(now + Duration::from_secs(1)).is_empty());

        let completion = VfsRpcBulkCompletion {
            connection_id: session_id.0,
            stream_id: 12,
            token: descriptor.token,
            op_id: read.header.op_id.0,
            handoff: VfsRpcBulkHandoff::ReadDownload,
            len: descriptor.len,
            bytes: vec![0; descriptor.len as usize],
        };
        let retired = adapter
            .complete_bulk_handoff(&completion)
            .expect("complete bulk");

        assert_eq!(retired.peer, peer);
        assert_eq!(retired.session_id, session_id);
        assert_eq!(adapter.pending_len(), 0);
        assert_eq!(adapter.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_timeout_retires_admission_for_abort_mapping() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let start = Instant::now();
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                request_timeout: Duration::from_millis(20),
                ..VfsRpcTransportAdapterConfig::default()
            },
            healthy_sessions(peer, session_id),
        );
        let mut bulk = bulk_service();
        let accept = bulk.accept_vfs_rpc_write_upload(session_id.0, 11, 90, 3, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 3).expect("descriptor");
        let request = VfsRpcRequest::new(
            OpId(90),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle: sample_file_handle(),
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: descriptor.token,
                    len: descriptor.len,
                },
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("request");
        adapter
            .begin_request_with_bulk(
                peer,
                &request,
                start,
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect("begin bulk");

        let timeouts = adapter.expire_timed_out(start + Duration::from_millis(20));

        assert_eq!(timeouts.len(), 1);
        let bulk_record = timeouts[0].bulk.expect("bulk timeout record");
        assert_eq!(bulk_record.token, descriptor.token);
        assert_eq!(bulk_record.handoff, VfsRpcBulkHandoff::WriteUpload);
        assert_eq!(adapter.pending_len(), 0);
        assert_eq!(adapter.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_completion_mismatch_does_not_retire_admission() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let mut bulk = bulk_service();
        let accept = bulk.accept_vfs_rpc_write_upload(session_id.0, 11, 90, 3, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 3).expect("descriptor");
        let request = VfsRpcRequest::new(
            OpId(90),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle: sample_file_handle(),
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: descriptor.token,
                    len: descriptor.len,
                },
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("request");
        adapter
            .begin_request_with_bulk(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect("begin bulk");

        let wrong = VfsRpcBulkCompletion {
            connection_id: session_id.0,
            stream_id: 12,
            token: descriptor.token,
            op_id: request.header.op_id.0,
            handoff: VfsRpcBulkHandoff::WriteUpload,
            len: descriptor.len,
            bytes: b"abc".to_vec(),
        };
        let err = adapter
            .complete_bulk_handoff(&wrong)
            .expect_err("mismatched completion rejected");

        assert_eq!(err.errno(), Errno::EPROTO);
        assert_eq!(adapter.pending_bulk_len(), 1);

        let correct = VfsRpcBulkCompletion {
            stream_id: 11,
            ..wrong
        };
        adapter
            .complete_bulk_handoff(&correct)
            .expect("matching completion still retires");
        assert_eq!(adapter.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_completion_length_mismatch_does_not_retire_admission() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let mut bulk = bulk_service();
        let accept = bulk.accept_vfs_rpc_write_upload(session_id.0, 11, 90, 3, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 3).expect("descriptor");
        let request = VfsRpcRequest::new(
            OpId(90),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle: sample_file_handle(),
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: descriptor.token,
                    len: descriptor.len,
                },
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("request");
        adapter
            .begin_request_with_bulk(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect("begin bulk");

        let wrong = VfsRpcBulkCompletion {
            connection_id: session_id.0,
            stream_id: 11,
            token: descriptor.token,
            op_id: request.header.op_id.0,
            handoff: VfsRpcBulkHandoff::WriteUpload,
            len: descriptor.len + 1,
            bytes: b"abcd".to_vec(),
        };
        let err = adapter
            .complete_bulk_handoff(&wrong)
            .expect_err("length-mismatched completion rejected");

        assert_eq!(err.errno(), Errno::EPROTO);
        assert_eq!(adapter.pending_bulk_len(), 1);

        let correct = VfsRpcBulkCompletion {
            len: descriptor.len,
            bytes: b"abc".to_vec(),
            ..wrong
        };
        adapter
            .complete_bulk_handoff(&correct)
            .expect("matching completion still retires");
        assert_eq!(adapter.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_abort_mismatch_does_not_retire_admission() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let mut bulk = bulk_service();
        let accept = bulk.accept_vfs_rpc_write_upload(session_id.0, 11, 90, 3, BulkPriority::Bulk);
        let descriptor = VfsRpcBulkDescriptor::from_accept(&accept, 3).expect("descriptor");
        let request = VfsRpcRequest::new(
            OpId(90),
            2,
            3,
            REQ_FLAG_BULK_PENDING,
            VfsRpcRequestPayload::Write {
                handle: sample_file_handle(),
                offset: 0,
                data: InlineOrBulk::Bulk {
                    token: descriptor.token,
                    len: descriptor.len,
                },
            },
            Some(VfsRpcCredentials::root(peer)),
        )
        .expect("request");
        adapter
            .begin_request_with_bulk(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
                &bulk,
            )
            .expect("begin bulk");

        let wrong = VfsRpcBulkAbort {
            connection_id: session_id.0,
            stream_id: 12,
            token: descriptor.token,
            op_id: request.header.op_id.0,
            handoff: VfsRpcBulkHandoff::WriteUpload,
            reason: BulkAbortReason::ProtocolError,
        };
        let err = adapter
            .abort_bulk_handoff(&wrong)
            .expect_err("mismatched abort rejected");

        assert_eq!(err.errno(), Errno::EPROTO);
        assert_eq!(adapter.pending_bulk_len(), 1);

        let correct = VfsRpcBulkAbort {
            stream_id: 11,
            ..wrong
        };
        adapter
            .abort_bulk_handoff(&correct)
            .expect("matching abort still retires");
        assert_eq!(adapter.pending_bulk_len(), 0);
    }

    #[test]
    fn bulk_response_flag_and_descriptor_are_rejected_as_unsupported() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let flagged = VfsRpcResponse::ok(
            OpId(1),
            VfsRpcMethod::Read,
            RESP_FLAG_BULK,
            VfsRpcResponsePayload::Empty,
        )
        .expect("response");

        assert_eq!(
            adapter
                .wrap_response_for_session(
                    peer,
                    session_id,
                    &flagged,
                    VfsRpcEnvelopeContext::default()
                )
                .unwrap_err()
                .errno(),
            Errno::EOPNOTSUPP
        );

        let descriptor = VfsRpcResponse::ok(
            OpId(1),
            VfsRpcMethod::Read,
            0,
            VfsRpcResponsePayload::Data(InlineOrBulk::Bulk {
                token: [1; 32],
                len: 8192,
            }),
        )
        .expect("response");

        assert_eq!(
            adapter
                .wrap_response_for_session(
                    peer,
                    session_id,
                    &descriptor,
                    VfsRpcEnvelopeContext::default()
                )
                .unwrap_err()
                .errno(),
            Errno::EOPNOTSUPP
        );
    }

    #[test]
    fn frame_size_limit_maps_to_emsgsize() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                max_frame_bytes: 16,
                ..VfsRpcTransportAdapterConfig::default()
            },
            healthy_sessions(peer, session_id),
        );
        let request = sample_request();

        let err = adapter
            .begin_request(
                peer,
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
            )
            .expect_err("oversized frame rejected");

        assert_eq!(err.errno(), Errno::EMSGSIZE);
        assert_eq!(adapter.pending_len(), 0);
    }

    #[test]
    fn demultiplexed_control_frame_enforces_adapter_size_limit() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let request = sample_request();
        let rpc_frame = VfsRpcTransportFrame::from_request(&request).expect("request frame");
        let control_frame =
            ControlServiceFrame::new(rpc_frame.service_id, rpc_frame.message_type, rpc_frame.body);
        let wire_size = TransportEnvelope::wire_size(
            CONTROL_SERVICE_FRAME_HEADER_LEN + control_frame.body.len(),
            0,
        );
        let bulk = bulk_service();

        let mut undersized = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                max_frame_bytes: wire_size - 1,
                ..VfsRpcTransportAdapterConfig::default()
            },
            healthy_sessions(peer, session_id),
        );
        assert_eq!(
            undersized
                .unwrap_control_service_frame_with_bulk(
                    Instant::now(),
                    session_id,
                    control_frame.clone(),
                    &bulk,
                )
                .expect_err("oversized demultiplexed frame rejected"),
            VfsRpcTransportAdapterError::FrameTooLarge {
                actual: wire_size,
                max: wire_size - 1,
            }
        );

        let mut exact = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                max_frame_bytes: wire_size,
                ..VfsRpcTransportAdapterConfig::default()
            },
            healthy_sessions(peer, session_id),
        );
        match exact
            .unwrap_control_service_frame_with_bulk(
                Instant::now(),
                session_id,
                control_frame,
                &bulk,
            )
            .expect("exact-boundary demultiplexed frame accepted")
        {
            VfsRpcInboundFrame::Request {
                request: actual, ..
            } => assert_eq!(actual, request),
            other => panic!("unexpected inbound frame: {other:?}"),
        }
    }

    #[test]
    fn unavailable_or_unhealthy_session_maps_to_retryable_vfs_error() {
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            TransportSessionSet::new(),
        );
        let request = sample_request();
        let err = adapter
            .begin_request(
                PeerId(99),
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
            )
            .expect_err("missing peer");
        assert_eq!(err.errno(), Errno::EHOSTUNREACH);
        assert!(err.is_retryable());

        let mut sessions = TransportSessionSet::new();
        sessions.add_binding(PeerId(99).0, SessionId::new(5));
        sessions.mark_unhealthy(SessionId::new(5));
        let mut adapter =
            VfsRpcTransportAdapter::new(VfsRpcTransportAdapterConfig::default(), sessions);
        let err = adapter
            .begin_request(
                PeerId(99),
                &request,
                Instant::now(),
                VfsRpcEnvelopeContext::default(),
            )
            .expect_err("unhealthy peer");
        assert_eq!(err.errno(), Errno::EHOSTUNREACH);
        assert!(err.is_retryable());
    }

    #[test]
    fn peer_identity_mismatch_maps_to_eacces_response() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig::default(),
            healthy_sessions(peer, session_id),
        );
        let request = VfsRpcRequest::new(
            OpId(7),
            2,
            3,
            0,
            VfsRpcRequestPayload::Lookup {
                parent: InodeId(1),
                name: b"name".to_vec(),
            },
            Some(VfsRpcCredentials::root(PeerId(10))),
        )
        .expect("request");
        let outbound = adapter
            .wrap_request_for_session(peer, session_id, &request, VfsRpcEnvelopeContext::default())
            .expect("wrap");

        let err = adapter
            .unwrap_inbound(Instant::now(), &outbound.envelope, &outbound.payload)
            .expect_err("credential mismatch");
        assert_eq!(err.errno(), Errno::EACCES);
        let response = err.response_for_request(&request).expect("error response");
        assert_eq!(response.header.errno, Errno::EACCES);
    }

    #[test]
    fn retry_and_timeout_surfaces_track_pending_requests() {
        let peer = PeerId(9);
        let session_id = SessionId::new(33);
        let start = Instant::now();
        let mut adapter = VfsRpcTransportAdapter::new(
            VfsRpcTransportAdapterConfig {
                request_timeout: Duration::from_millis(20),
                retry_after: Duration::from_millis(10),
                ..VfsRpcTransportAdapterConfig::default()
            },
            healthy_sessions(peer, session_id),
        );
        let request = sample_request();
        adapter
            .begin_request(peer, &request, start, VfsRpcEnvelopeContext::default())
            .expect("begin");

        assert!(adapter
            .retry_due(start + Duration::from_millis(9))
            .is_empty());
        let retry = adapter.retry_due(start + Duration::from_millis(10));
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].op_id, request.header.op_id);
        assert_eq!(retry[0].retries, 1);

        let timeouts = adapter.expire_timed_out(start + Duration::from_millis(20));
        assert_eq!(timeouts.len(), 1);
        assert_eq!(timeouts[0].op_id, request.header.op_id);
        assert_eq!(adapter.pending_len(), 0);
    }

    #[test]
    fn transport_send_failures_map_to_vfs_visible_errno_and_retry_class() {
        let peer = PeerId(9);
        let roster = VfsRpcTransportFailure::from_transport_error(
            peer,
            &TransportError::PeerNotInRoster {
                peer_id: 9,
                session_id: SessionId::new(3),
            },
        );
        assert_eq!(roster.errno, Errno::EHOSTUNREACH);
        assert!(roster.retryable);

        let full = VfsRpcTransportFailure::from_transport_error(
            peer,
            &TransportError::SendBufferFull {
                session_id: SessionId::new(3),
                capacity: 1,
                needed: 2,
            },
        );
        assert_eq!(full.errno, Errno::EAGAIN);
        assert!(full.retryable);

        let closed = VfsRpcTransportFailure::from_transport_error(
            peer,
            &TransportError::SessionNotFound {
                session_id: SessionId::new(3),
            },
        );
        assert_eq!(closed.errno, Errno::ENOTCONN);
        assert!(closed.retryable);
    }

    #[test]
    fn adapter_constants_match_control_service_path() {
        assert_eq!(VFS_RPC_CONTROL_ENDPOINT_FAMILY, EndpointFamily::Control);
        assert_eq!(
            VFS_RPC_CONTROL_MESSAGE_FAMILY,
            MessageFamily::LeaseFenceDeadline
        );
        assert_eq!(VFS_RPC_CONTROL_LANE, LaneClass::Control);
        assert_eq!(
            VFS_RPC_CONTROL_MESSAGE_FAMILY.preferred_lane(),
            VFS_RPC_CONTROL_LANE
        );
    }
}
