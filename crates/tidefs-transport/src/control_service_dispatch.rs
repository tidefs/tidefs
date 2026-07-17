// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! CONTROL-lane service-id dispatch for inline control services.
//!
//! Some service protocols, such as LOCK and VFS_RPC, already carry a stable
//! service id in their own frame surface. This module provides the transport
//! side registry for those service-id frames without adding a new transport
//! [`MessageFamily`] value.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use tidefs_types_transport_session::EndpointFamily;

use crate::dispatch::{
    DecodedMessage, DispatchError, MessageDispatch, MessageHandler as FamilyMessageHandler,
};
use crate::envelope::MessageFamily;
use crate::lane_demux::LaneClass;
use crate::types::SessionId;

/// Endpoint family used by service-id control frames.
pub const CONTROL_SERVICE_ENDPOINT_FAMILY: EndpointFamily = EndpointFamily::Control;
/// Existing transport family used to carry inline service control frames.
pub const CONTROL_SERVICE_MESSAGE_FAMILY: MessageFamily = MessageFamily::LeaseFenceDeadline;
/// Lane selected by [`CONTROL_SERVICE_MESSAGE_FAMILY`].
pub const CONTROL_SERVICE_LANE: LaneClass = LaneClass::Control;
/// Header length for a service-id control frame.
pub const CONTROL_SERVICE_FRAME_HEADER_LEN: usize = 8;

/// A decoded inline service frame carried inside a transport control payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlServiceFrame {
    pub service_id: u8,
    pub message_type: u8,
    pub body: Vec<u8>,
}

impl ControlServiceFrame {
    #[must_use]
    pub fn new(service_id: u8, message_type: u8, body: Vec<u8>) -> Self {
        Self {
            service_id,
            message_type,
            body,
        }
    }

    /// Encode as `[service_id u8][message_type u8][reserved u16][body_len u32][body]`.
    ///
    /// The service body is opaque to transport and remains owned by the
    /// service crate.
    pub fn encode(&self) -> Result<Vec<u8>, ControlServiceDispatchError> {
        let body_len = u32::try_from(self.body.len()).map_err(|_| {
            ControlServiceDispatchError::BodyTooLarge {
                len: self.body.len(),
            }
        })?;
        let mut out = Vec::with_capacity(CONTROL_SERVICE_FRAME_HEADER_LEN + self.body.len());
        out.push(self.service_id);
        out.push(self.message_type);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ControlServiceDispatchError> {
        if bytes.len() < CONTROL_SERVICE_FRAME_HEADER_LEN {
            return Err(ControlServiceDispatchError::FrameTooShort { got: bytes.len() });
        }

        let service_id = bytes[0];
        let message_type = bytes[1];
        let reserved = u16::from_le_bytes([bytes[2], bytes[3]]);
        if reserved != 0 {
            return Err(ControlServiceDispatchError::ReservedNonZero(reserved));
        }

        let body_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let expected = CONTROL_SERVICE_FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or(ControlServiceDispatchError::FrameLengthOverflow)?;
        if bytes.len() != expected {
            return Err(ControlServiceDispatchError::FrameLengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            service_id,
            message_type,
            body: bytes[CONTROL_SERVICE_FRAME_HEADER_LEN..].to_vec(),
        })
    }
}

/// Outcome from a service frame handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlServiceDispatchOutcome {
    Consumed,
    Reply(ControlServiceFrame),
}

/// Handler for one service id on the inline control surface.
pub trait ControlServiceHandler: Send + Sync {
    fn handle_control_service_frame(
        &self,
        session_id: SessionId,
        frame: ControlServiceFrame,
    ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError>;
}

/// Outbound sink for CONTROL service replies produced by receive-side handlers.
pub trait ControlServiceReplySink: Send + Sync {
    fn send_control_service_reply(
        &self,
        session_id: SessionId,
        frame: ControlServiceFrame,
    ) -> Result<(), ControlServiceDispatchError>;
}

/// Registry keyed by service id for inline control-service frames.
#[derive(Clone, Default)]
pub struct ControlServiceDispatch {
    handlers: Arc<RwLock<BTreeMap<u8, Arc<dyn ControlServiceHandler>>>>,
}

impl ControlServiceDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, service_id: u8, handler: Arc<dyn ControlServiceHandler>) {
        self.handlers.write().unwrap().insert(service_id, handler);
    }

    pub fn unregister(&self, service_id: u8) -> Option<Arc<dyn ControlServiceHandler>> {
        self.handlers.write().unwrap().remove(&service_id)
    }

    #[must_use]
    pub fn has_handler(&self, service_id: u8) -> bool {
        self.handlers.read().unwrap().contains_key(&service_id)
    }

    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.read().unwrap().len()
    }

    pub fn dispatch(
        &self,
        session_id: SessionId,
        payload: &[u8],
    ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError> {
        let frame = ControlServiceFrame::decode(payload)?;
        let service_id = frame.service_id;
        let handler = self
            .handlers
            .read()
            .unwrap()
            .get(&service_id)
            .cloned()
            .ok_or(ControlServiceDispatchError::HandlerNotFound { service_id })?;

        handler.handle_control_service_frame(session_id, frame)
    }
}

/// [`MessageDispatch`] handler that routes CONTROL frames by service id.
pub struct ControlServiceMessageHandler {
    dispatch: ControlServiceDispatch,
    reply_sink: Arc<dyn ControlServiceReplySink>,
}

impl ControlServiceMessageHandler {
    #[must_use]
    pub fn new(
        dispatch: ControlServiceDispatch,
        reply_sink: Arc<dyn ControlServiceReplySink>,
    ) -> Self {
        Self {
            dispatch,
            reply_sink,
        }
    }
}

impl FamilyMessageHandler for ControlServiceMessageHandler {
    fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
        if msg.family != CONTROL_SERVICE_MESSAGE_FAMILY {
            return Err(DispatchError::HandlerError(Box::new(
                ControlServiceDispatchError::WrongMessageFamily {
                    expected: CONTROL_SERVICE_MESSAGE_FAMILY,
                    actual: msg.family,
                },
            )));
        }
        let session_id = msg.session_id.ok_or_else(|| {
            DispatchError::HandlerError(Box::new(ControlServiceDispatchError::MissingSessionId))
        })?;

        match self
            .dispatch
            .dispatch(session_id, &msg.payload)
            .map_err(|err| DispatchError::HandlerError(Box::new(err)))?
        {
            ControlServiceDispatchOutcome::Consumed => Ok(()),
            ControlServiceDispatchOutcome::Reply(frame) => self
                .reply_sink
                .send_control_service_reply(session_id, frame)
                .map_err(|err| DispatchError::HandlerError(Box::new(err))),
        }
    }
}

/// Register CONTROL service dispatch on the transport control receive path.
pub fn register_control_service_dispatch(
    message_dispatch: &MessageDispatch,
    dispatch: ControlServiceDispatch,
    reply_sink: Arc<dyn ControlServiceReplySink>,
) {
    message_dispatch.register(
        CONTROL_SERVICE_MESSAGE_FAMILY,
        Box::new(ControlServiceMessageHandler::new(dispatch, reply_sink)),
    );
}

/// Errors from service-id control dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlServiceDispatchError {
    FrameTooShort {
        got: usize,
    },
    ReservedNonZero(u16),
    FrameLengthOverflow,
    FrameLengthMismatch {
        expected: usize,
        actual: usize,
    },
    BodyTooLarge {
        len: usize,
    },
    HandlerNotFound {
        service_id: u8,
    },
    HandlerRejected {
        service_id: u8,
        reason: String,
    },
    MissingSessionId,
    WrongMessageFamily {
        expected: MessageFamily,
        actual: MessageFamily,
    },
    ReplyRejected {
        reason: String,
    },
}

impl fmt::Display for ControlServiceDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { got } => {
                write!(f, "control service frame too short: {got} bytes")
            }
            Self::ReservedNonZero(value) => {
                write!(f, "control service reserved field is non-zero: {value}")
            }
            Self::FrameLengthOverflow => f.write_str("control service frame length overflow"),
            Self::FrameLengthMismatch { expected, actual } => write!(
                f,
                "control service frame length mismatch: expected {expected}, actual {actual}"
            ),
            Self::BodyTooLarge { len } => {
                write!(f, "control service body length {len} exceeds u32::MAX")
            }
            Self::HandlerNotFound { service_id } => {
                write!(
                    f,
                    "no control service handler registered for {service_id:#04x}"
                )
            }
            Self::HandlerRejected { service_id, reason } => {
                write!(
                    f,
                    "control service handler {service_id:#04x} rejected frame: {reason}"
                )
            }
            Self::MissingSessionId => f.write_str("control service frame is missing session id"),
            Self::WrongMessageFamily { expected, actual } => write!(
                f,
                "control service dispatch expected {expected:?}, got {actual:?}"
            ),
            Self::ReplyRejected { reason } => {
                write!(f, "control service reply rejected: {reason}")
            }
        }
    }
}

impl std::error::Error for ControlServiceDispatchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn control_service_frame_roundtrips_header_and_body() {
        let frame = ControlServiceFrame::new(0x06, 0x40, b"rpc-body".to_vec());
        let encoded = frame.encode().expect("encode");
        assert_eq!(encoded.len(), CONTROL_SERVICE_FRAME_HEADER_LEN + 8);

        let decoded = ControlServiceFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn control_service_frame_rejects_truncated_and_mismatched_lengths() {
        assert_eq!(
            ControlServiceFrame::decode(&[0; 3]).unwrap_err(),
            ControlServiceDispatchError::FrameTooShort { got: 3 }
        );

        let mut encoded = ControlServiceFrame::new(0x06, 0, vec![1, 2, 3])
            .encode()
            .expect("encode");
        encoded[4] = 9;
        assert_eq!(
            ControlServiceFrame::decode(&encoded).unwrap_err(),
            ControlServiceDispatchError::FrameLengthMismatch {
                expected: CONTROL_SERVICE_FRAME_HEADER_LEN + 9,
                actual: CONTROL_SERVICE_FRAME_HEADER_LEN + 3,
            }
        );
    }

    #[derive(Default)]
    struct RecordingHandler {
        seen: Mutex<Vec<(SessionId, ControlServiceFrame)>>,
    }

    impl ControlServiceHandler for RecordingHandler {
        fn handle_control_service_frame(
            &self,
            session_id: SessionId,
            frame: ControlServiceFrame,
        ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError> {
            self.seen.lock().unwrap().push((session_id, frame));
            Ok(ControlServiceDispatchOutcome::Consumed)
        }
    }

    struct ReplyingHandler;

    impl ControlServiceHandler for ReplyingHandler {
        fn handle_control_service_frame(
            &self,
            _session_id: SessionId,
            frame: ControlServiceFrame,
        ) -> Result<ControlServiceDispatchOutcome, ControlServiceDispatchError> {
            Ok(ControlServiceDispatchOutcome::Reply(
                ControlServiceFrame::new(
                    frame.service_id,
                    frame.message_type | 0x40,
                    b"reply".to_vec(),
                ),
            ))
        }
    }

    #[derive(Default)]
    struct RecordingReplySink {
        replies: Mutex<Vec<(SessionId, ControlServiceFrame)>>,
    }

    impl ControlServiceReplySink for RecordingReplySink {
        fn send_control_service_reply(
            &self,
            session_id: SessionId,
            frame: ControlServiceFrame,
        ) -> Result<(), ControlServiceDispatchError> {
            self.replies.lock().unwrap().push((session_id, frame));
            Ok(())
        }
    }

    #[test]
    fn dispatch_routes_by_service_id() {
        let dispatch = ControlServiceDispatch::new();
        let handler = Arc::new(RecordingHandler::default());
        dispatch.register(0x06, handler.clone());

        let frame = ControlServiceFrame::new(0x06, 0x01, b"payload".to_vec());
        let payload = frame.encode().expect("encode");
        let outcome = dispatch
            .dispatch(SessionId::new(44), &payload)
            .expect("dispatch");

        assert_eq!(outcome, ControlServiceDispatchOutcome::Consumed);
        let seen = handler.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, SessionId::new(44));
        assert_eq!(seen[0].1, frame);
    }

    #[test]
    fn dispatch_reports_unregistered_service_id() {
        let dispatch = ControlServiceDispatch::new();
        let frame = ControlServiceFrame::new(0x06, 0x01, Vec::new());
        let payload = frame.encode().expect("encode");

        assert_eq!(
            dispatch.dispatch(SessionId::new(1), &payload).unwrap_err(),
            ControlServiceDispatchError::HandlerNotFound { service_id: 0x06 }
        );
    }

    #[test]
    fn registered_message_handler_routes_authenticated_session_and_reply() {
        let control_dispatch = ControlServiceDispatch::new();
        control_dispatch.register(0x06, Arc::new(ReplyingHandler));
        let reply_sink = Arc::new(RecordingReplySink::default());
        let message_dispatch = MessageDispatch::new();
        register_control_service_dispatch(&message_dispatch, control_dispatch, reply_sink.clone());

        let payload = ControlServiceFrame::new(0x06, 0x01, b"request".to_vec())
            .encode()
            .expect("encode");
        message_dispatch
            .dispatch(
                DecodedMessage::new(CONTROL_SERVICE_MESSAGE_FAMILY, payload)
                    .with_session_id(SessionId::new(42)),
            )
            .expect("dispatch");

        assert_eq!(
            reply_sink.replies.lock().unwrap().as_slice(),
            &[(
                SessionId::new(42),
                ControlServiceFrame::new(0x06, 0x41, b"reply".to_vec())
            )]
        );
    }

    #[test]
    fn message_handler_requires_receive_loop_session_identity() {
        let control_dispatch = ControlServiceDispatch::new();
        control_dispatch.register(0x06, Arc::new(RecordingHandler::default()));
        let handler = ControlServiceMessageHandler::new(
            control_dispatch,
            Arc::new(RecordingReplySink::default()),
        );
        let payload = ControlServiceFrame::new(0x06, 0x01, b"request".to_vec())
            .encode()
            .expect("encode");

        let err = handler
            .handle(DecodedMessage::new(CONTROL_SERVICE_MESSAGE_FAMILY, payload))
            .unwrap_err();
        assert!(matches!(err, DispatchError::HandlerError(_)));
        assert!(err.to_string().contains("missing session id"));
    }

    #[test]
    fn control_service_constants_select_control_path() {
        assert_eq!(CONTROL_SERVICE_ENDPOINT_FAMILY, EndpointFamily::Control);
        assert_eq!(
            CONTROL_SERVICE_MESSAGE_FAMILY,
            MessageFamily::LeaseFenceDeadline
        );
        assert_eq!(CONTROL_SERVICE_LANE, LaneClass::Control);
        assert_eq!(
            CONTROL_SERVICE_MESSAGE_FAMILY.preferred_lane(),
            CONTROL_SERVICE_LANE
        );
    }
}
