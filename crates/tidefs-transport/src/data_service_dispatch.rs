// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! DATA-endpoint service-id dispatch for bulk data services.
//!
//! This module provides the transport-owned frame wrapper for services that
//! move bytes on the DATA endpoint. It deliberately does not register any
//! product service by itself: service crates own their method codecs and a
//! caller must still bind the registry to an authenticated data session.

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

/// Endpoint family used by DATA service-id frames.
pub const DATA_SERVICE_ENDPOINT_FAMILY: EndpointFamily = EndpointFamily::Data;
/// Existing transport family used to carry DATA service frames.
pub const DATA_SERVICE_MESSAGE_FAMILY: MessageFamily = MessageFamily::StateTransfer;
/// Lane selected by [`DATA_SERVICE_MESSAGE_FAMILY`].
pub const DATA_SERVICE_LANE: LaneClass = LaneClass::Demand;
/// Header length for a DATA service frame.
pub const DATA_SERVICE_FRAME_HEADER_LEN: usize = 8;

/// A decoded service frame carried inside a transport DATA payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataServiceFrame {
    pub service_id: u8,
    pub message_type: u8,
    pub body: Vec<u8>,
}

impl DataServiceFrame {
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
    pub fn encode(&self) -> Result<Vec<u8>, DataServiceDispatchError> {
        let body_len =
            u32::try_from(self.body.len()).map_err(|_| DataServiceDispatchError::BodyTooLarge {
                len: self.body.len(),
            })?;
        let mut out = Vec::with_capacity(DATA_SERVICE_FRAME_HEADER_LEN + self.body.len());
        out.push(self.service_id);
        out.push(self.message_type);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DataServiceDispatchError> {
        if bytes.len() < DATA_SERVICE_FRAME_HEADER_LEN {
            return Err(DataServiceDispatchError::FrameTooShort { got: bytes.len() });
        }

        let service_id = bytes[0];
        let message_type = bytes[1];

        let body_len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
        let expected = DATA_SERVICE_FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or(DataServiceDispatchError::FrameLengthOverflow)?;
        if bytes.len() != expected {
            return Err(DataServiceDispatchError::FrameLengthMismatch {
                expected,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            service_id,
            message_type,
            body: bytes[DATA_SERVICE_FRAME_HEADER_LEN..].to_vec(),
        })
    }
}

/// Outcome from a DATA service frame handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataServiceDispatchOutcome {
    Consumed,
    Reply(DataServiceFrame),
}

/// Handler for one service id on the DATA endpoint service surface.
pub trait DataServiceHandler: Send + Sync {
    fn handle_data_service_frame(
        &self,
        session_id: SessionId,
        frame: DataServiceFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError>;
}

/// Outbound sink for DATA service replies produced by receive-side handlers.
pub trait DataServiceReplySink: Send + Sync {
    fn send_data_service_reply(
        &self,
        session_id: SessionId,
        frame: DataServiceFrame,
    ) -> Result<(), DataServiceDispatchError>;
}

/// Registry keyed by service id for DATA service frames.
#[derive(Clone, Default)]
pub struct DataServiceDispatch {
    handlers: Arc<RwLock<BTreeMap<u8, Arc<dyn DataServiceHandler>>>>,
}

impl DataServiceDispatch {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, service_id: u8, handler: Arc<dyn DataServiceHandler>) {
        self.handlers.write().unwrap().insert(service_id, handler);
    }

    pub fn unregister(&self, service_id: u8) -> Option<Arc<dyn DataServiceHandler>> {
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
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let frame = DataServiceFrame::decode(payload)?;
        let service_id = frame.service_id;
        let handler = self
            .handlers
            .read()
            .unwrap()
            .get(&service_id)
            .cloned()
            .ok_or(DataServiceDispatchError::HandlerNotFound { service_id })?;

        handler.handle_data_service_frame(session_id, frame)
    }
}

/// [`MessageDispatch`] handler that routes StateTransfer DATA frames by service id.
pub struct DataServiceMessageHandler {
    dispatch: DataServiceDispatch,
    reply_sink: Arc<dyn DataServiceReplySink>,
}

impl DataServiceMessageHandler {
    #[must_use]
    pub fn new(dispatch: DataServiceDispatch, reply_sink: Arc<dyn DataServiceReplySink>) -> Self {
        Self {
            dispatch,
            reply_sink,
        }
    }
}

impl FamilyMessageHandler for DataServiceMessageHandler {
    fn handle(&self, msg: DecodedMessage) -> Result<(), DispatchError> {
        if msg.family != DATA_SERVICE_MESSAGE_FAMILY {
            return Err(DispatchError::HandlerError(Box::new(
                DataServiceDispatchError::WrongMessageFamily {
                    expected: DATA_SERVICE_MESSAGE_FAMILY,
                    actual: msg.family,
                },
            )));
        }
        let session_id = msg.session_id.ok_or_else(|| {
            DispatchError::HandlerError(Box::new(DataServiceDispatchError::MissingSessionId))
        })?;

        match self
            .dispatch
            .dispatch(session_id, &msg.payload)
            .map_err(|err| DispatchError::HandlerError(Box::new(err)))?
        {
            DataServiceDispatchOutcome::Consumed => Ok(()),
            DataServiceDispatchOutcome::Reply(frame) => self
                .reply_sink
                .send_data_service_reply(session_id, frame)
                .map_err(|err| DispatchError::HandlerError(Box::new(err))),
        }
    }
}

/// Register DATA service dispatch on the transport StateTransfer receive path.
pub fn register_data_service_dispatch(
    message_dispatch: &MessageDispatch,
    dispatch: DataServiceDispatch,
    reply_sink: Arc<dyn DataServiceReplySink>,
) {
    message_dispatch.register(
        DATA_SERVICE_MESSAGE_FAMILY,
        Box::new(DataServiceMessageHandler::new(dispatch, reply_sink)),
    );
}

/// Errors from DATA service dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataServiceDispatchError {
    FrameTooShort {
        got: usize,
    },
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

impl fmt::Display for DataServiceDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameTooShort { got } => {
                write!(f, "data service frame too short: {got} bytes")
            }
            Self::FrameLengthOverflow => f.write_str("data service frame length overflow"),
            Self::FrameLengthMismatch { expected, actual } => write!(
                f,
                "data service frame length mismatch: expected {expected}, actual {actual}"
            ),
            Self::BodyTooLarge { len } => {
                write!(f, "data service body length {len} exceeds u32::MAX")
            }
            Self::HandlerNotFound { service_id } => {
                write!(
                    f,
                    "no data service handler registered for {service_id:#04x}"
                )
            }
            Self::HandlerRejected { service_id, reason } => {
                write!(
                    f,
                    "data service handler {service_id:#04x} rejected frame: {reason}"
                )
            }
            Self::MissingSessionId => f.write_str("DATA service frame missing session id"),
            Self::WrongMessageFamily { expected, actual } => write!(
                f,
                "DATA service frame arrived on {actual}, expected {expected}"
            ),
            Self::ReplyRejected { reason } => {
                write!(f, "DATA service reply sink rejected frame: {reason}")
            }
        }
    }
}

impl std::error::Error for DataServiceDispatchError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn data_service_frame_roundtrips_header_and_body() {
        let frame = DataServiceFrame::new(0x07, 0x02, b"bulk-body".to_vec());
        let encoded = frame.encode().expect("encode");
        assert_eq!(encoded.len(), DATA_SERVICE_FRAME_HEADER_LEN + 9);

        let decoded = DataServiceFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn data_service_frame_rejects_truncated_and_mismatched_lengths() {
        assert_eq!(
            DataServiceFrame::decode(&[0; 3]).unwrap_err(),
            DataServiceDispatchError::FrameTooShort { got: 3 }
        );

        let mut encoded = DataServiceFrame::new(0x07, 0, vec![1, 2, 3])
            .encode()
            .expect("encode");
        encoded[4] = 9;
        assert_eq!(
            DataServiceFrame::decode(&encoded).unwrap_err(),
            DataServiceDispatchError::FrameLengthMismatch {
                expected: DATA_SERVICE_FRAME_HEADER_LEN + 9,
                actual: DATA_SERVICE_FRAME_HEADER_LEN + 3,
            }
        );
    }

    #[test]
    fn data_service_frame_ignores_reserved_header_bytes() {
        let frame = DataServiceFrame::new(0x07, 0x02, b"bulk-body".to_vec());
        let mut encoded = frame.encode().expect("encode");
        encoded[2] = 0xaa;
        encoded[3] = 0x55;

        let decoded = DataServiceFrame::decode(&encoded).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[derive(Default)]
    struct RecordingHandler {
        seen: Mutex<Vec<(SessionId, DataServiceFrame)>>,
    }

    impl DataServiceHandler for RecordingHandler {
        fn handle_data_service_frame(
            &self,
            session_id: SessionId,
            frame: DataServiceFrame,
        ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
            self.seen.lock().unwrap().push((session_id, frame));
            Ok(DataServiceDispatchOutcome::Consumed)
        }
    }

    #[derive(Default)]
    struct ReplyingHandler;

    impl DataServiceHandler for ReplyingHandler {
        fn handle_data_service_frame(
            &self,
            _session_id: SessionId,
            frame: DataServiceFrame,
        ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
            Ok(DataServiceDispatchOutcome::Reply(DataServiceFrame::new(
                frame.service_id,
                frame.message_type | 0x40,
                b"reply".to_vec(),
            )))
        }
    }

    #[derive(Default)]
    struct RecordingReplySink {
        replies: Mutex<Vec<(SessionId, DataServiceFrame)>>,
    }

    impl DataServiceReplySink for RecordingReplySink {
        fn send_data_service_reply(
            &self,
            session_id: SessionId,
            frame: DataServiceFrame,
        ) -> Result<(), DataServiceDispatchError> {
            self.replies.lock().unwrap().push((session_id, frame));
            Ok(())
        }
    }

    #[test]
    fn dispatch_routes_by_service_id() {
        let dispatch = DataServiceDispatch::new();
        let handler = Arc::new(RecordingHandler::default());
        dispatch.register(0x07, handler.clone());

        let frame = DataServiceFrame::new(0x07, 0x00, b"offer".to_vec());
        let payload = frame.encode().expect("encode");
        assert_eq!(
            dispatch.dispatch(SessionId::new(11), &payload).unwrap(),
            DataServiceDispatchOutcome::Consumed
        );

        assert_eq!(
            handler.seen.lock().unwrap().as_slice(),
            &[(SessionId::new(11), frame)]
        );
    }

    #[test]
    fn dispatch_rejects_unregistered_service_id() {
        let dispatch = DataServiceDispatch::new();
        let payload = DataServiceFrame::new(0x07, 0x00, vec![])
            .encode()
            .expect("encode");

        assert_eq!(
            dispatch.dispatch(SessionId::new(1), &payload).unwrap_err(),
            DataServiceDispatchError::HandlerNotFound { service_id: 0x07 }
        );
    }

    #[test]
    fn message_handler_routes_state_transfer_with_session_and_reply() {
        let data_dispatch = DataServiceDispatch::new();
        data_dispatch.register(0x07, Arc::new(ReplyingHandler));
        let reply_sink = Arc::new(RecordingReplySink::default());
        let handler = DataServiceMessageHandler::new(data_dispatch, reply_sink.clone());

        let payload = DataServiceFrame::new(0x07, 0x00, b"offer".to_vec())
            .encode()
            .expect("encode");
        handler
            .handle(
                DecodedMessage::new(DATA_SERVICE_MESSAGE_FAMILY, payload)
                    .with_session_id(SessionId::new(42)),
            )
            .expect("handle");

        assert_eq!(
            reply_sink.replies.lock().unwrap().as_slice(),
            &[(
                SessionId::new(42),
                DataServiceFrame::new(0x07, 0x40, b"reply".to_vec())
            )]
        );
    }

    #[test]
    fn message_handler_requires_receive_loop_session_identity() {
        let data_dispatch = DataServiceDispatch::new();
        data_dispatch.register(0x07, Arc::new(RecordingHandler::default()));
        let reply_sink = Arc::new(RecordingReplySink::default());
        let handler = DataServiceMessageHandler::new(data_dispatch, reply_sink);
        let payload = DataServiceFrame::new(0x07, 0x00, b"offer".to_vec())
            .encode()
            .expect("encode");

        let err = handler
            .handle(DecodedMessage::new(DATA_SERVICE_MESSAGE_FAMILY, payload))
            .unwrap_err();
        assert!(matches!(err, DispatchError::HandlerError(_)));
        assert!(err.to_string().contains("missing session id"));
    }

    #[test]
    fn constants_bind_data_endpoint_and_demand_lane() {
        assert_eq!(DATA_SERVICE_ENDPOINT_FAMILY, EndpointFamily::Data);
        assert_eq!(DATA_SERVICE_MESSAGE_FAMILY, MessageFamily::StateTransfer);
        assert_eq!(DATA_SERVICE_LANE, LaneClass::Demand);
    }
}
