// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport DATA-service handler for BULK `service_id = 0x07` frames.
//!
//! The handler binds an authenticated transport `SessionId` to the BULK
//! connection id and drives the TCP_STREAM state machine for
//! OFFER/CREDIT/DONE/ABORT frames. It does not make VFS_RPC descriptor
//! acceptance or RDMA carriers live by itself.

use std::sync::Mutex;

use tidefs_transport::{
    DataServiceDispatchError, DataServiceDispatchOutcome, DataServiceFrame, DataServiceHandler,
    SessionId,
};

use crate::{
    AbortedBulkTransfer, BulkAbortFrame, BulkAcceptFrame, BulkCreditGrantFrame,
    BulkCreditRequestFrame, BulkCreditResult, BulkDoneFrame, BulkError, BulkFrame,
    BulkProtocolError, BulkService, BulkTcpChunkFrame, BulkToken, CompletedBulkTransfer,
    ConnectionId, StreamId, VfsRpcBulkAbort, VfsRpcBulkHandoff, VfsRpcBulkHandoffError,
    BULK_SERVICE_ID,
};

/// BULK service-id handler suitable for registration in `DataServiceDispatch`.
pub struct BulkDataServiceHandler {
    service: Mutex<BulkService>,
    completed: Mutex<Vec<CompletedBulkTransfer>>,
    aborted: Mutex<Vec<AbortedBulkTransfer>>,
}

/// Terminal record produced while handling one DATA service frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkDataServiceTerminal {
    Completed(CompletedBulkTransfer),
    Aborted(AbortedBulkTransfer),
}

impl BulkDataServiceHandler {
    #[must_use]
    pub fn new(service: BulkService) -> Self {
        Self {
            service: Mutex::new(service),
            completed: Mutex::new(Vec::new()),
            aborted: Mutex::new(Vec::new()),
        }
    }

    /// Run a read-only operation against the same BULK state that receives
    /// DATA service frames.
    ///
    /// This keeps same-session descriptor admission tied to the authenticated
    /// receiver state without exposing mutable BULK state to the caller.
    pub fn with_service<R>(&self, operation: impl FnOnce(&BulkService) -> R) -> R {
        let service = self.service.lock().unwrap();
        operation(&service)
    }

    /// Write an already-granted TCP_STREAM chunk into BULK reassembly state.
    pub fn write_tcp_chunk(
        &self,
        connection_id: ConnectionId,
        token: BulkToken,
        chunk_seq: u32,
        offset: u64,
        payload: &[u8],
    ) -> Result<(), BulkError> {
        self.service.lock().unwrap().write_tcp_chunk(
            connection_id,
            token,
            chunk_seq,
            offset,
            payload,
        )
    }

    /// Write a decoded, token-bound TCP_STREAM chunk into BULK reassembly state.
    pub fn handle_tcp_chunk(
        &self,
        connection_id: ConnectionId,
        chunk: BulkTcpChunkFrame,
    ) -> Result<(), BulkError> {
        self.service.lock().unwrap().write_tcp_chunk_for_stream(
            connection_id,
            chunk.stream_id,
            chunk.token,
            chunk.chunk_seq,
            chunk.offset,
            &chunk.payload,
        )
    }

    /// Retire an active VFS_RPC handoff from a runtime timeout path.
    ///
    /// DATA-frame ABORT handling records its terminal event in
    /// [`Self::drain_aborted`]. This direct path is for a caller that owns the
    /// timeout and must reclaim the same active transfer before it reports the
    /// VFS_RPC timeout.
    pub fn abort_vfs_rpc_handoff(
        &self,
        connection_id: ConnectionId,
        token: BulkToken,
        op_id: crate::OpId,
        handoff: VfsRpcBulkHandoff,
        reason: crate::BulkAbortReason,
    ) -> Result<VfsRpcBulkAbort, VfsRpcBulkHandoffError> {
        self.service.lock().unwrap().abort_vfs_rpc_handoff(
            connection_id,
            token,
            op_id,
            handoff,
            reason,
        )
    }

    /// Reclaim every active transfer owned by a lost authenticated
    /// connection.
    #[must_use]
    pub fn connection_lost(&self, connection_id: ConnectionId) -> Vec<AbortedBulkTransfer> {
        self.service.lock().unwrap().connection_lost(connection_id)
    }

    #[must_use]
    pub fn active_transfer_count(&self, connection_id: ConnectionId) -> usize {
        self.service
            .lock()
            .unwrap()
            .active_transfer_count(connection_id)
    }

    #[must_use]
    pub fn pinned_bytes(&self, connection_id: ConnectionId) -> u64 {
        self.service.lock().unwrap().pinned_bytes(connection_id)
    }

    #[must_use]
    pub fn drain_completed(&self) -> Vec<CompletedBulkTransfer> {
        std::mem::take(&mut *self.completed.lock().unwrap())
    }

    #[must_use]
    pub fn drain_aborted(&self) -> Vec<AbortedBulkTransfer> {
        std::mem::take(&mut *self.aborted.lock().unwrap())
    }

    /// Handle one DATA frame and return its terminal record to the same caller.
    ///
    /// This frame-scoped path lets a runtime preserve DONE/ABORT ownership
    /// under concurrent dispatch instead of publishing the record through the
    /// handler-global drain queues.
    pub fn handle_data_service_frame_with_terminal(
        &self,
        session_id: SessionId,
        frame: DataServiceFrame,
    ) -> (
        Result<DataServiceDispatchOutcome, DataServiceDispatchError>,
        Option<BulkDataServiceTerminal>,
    ) {
        let connection_id = session_id.0;
        let frame = match BulkFrame::from_data_service_frame(frame) {
            Ok(frame) => frame,
            Err(error) => return (Err(reject_protocol(error)), None),
        };
        match frame {
            BulkFrame::Offer(frame) => (self.handle_offer(connection_id, frame), None),
            BulkFrame::CreditRequest(frame) => (self.handle_credit(connection_id, frame), None),
            BulkFrame::Done(frame) => self.handle_done_with_terminal(connection_id, frame),
            BulkFrame::Abort(frame) => self.handle_abort_with_terminal(connection_id, frame),
            BulkFrame::Accept(_) | BulkFrame::CreditGrant(_) => (
                Err(reject_reason(
                    "BULK response frames require a sender-side coordinator",
                )),
                None,
            ),
        }
    }

    fn record_terminal(&self, terminal: BulkDataServiceTerminal) {
        match terminal {
            BulkDataServiceTerminal::Completed(completed) => {
                self.completed.lock().unwrap().push(completed);
            }
            BulkDataServiceTerminal::Aborted(aborted) => {
                self.aborted.lock().unwrap().push(aborted);
            }
        }
    }
}

impl DataServiceHandler for BulkDataServiceHandler {
    fn handle_data_service_frame(
        &self,
        session_id: SessionId,
        frame: DataServiceFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let (outcome, terminal) = self.handle_data_service_frame_with_terminal(session_id, frame);
        if let Some(terminal) = terminal {
            self.record_terminal(terminal);
        }
        outcome
    }
}

impl BulkDataServiceHandler {
    fn handle_offer(
        &self,
        connection_id: ConnectionId,
        frame: crate::BulkOfferFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let accept = self
            .service
            .lock()
            .unwrap()
            .offer(frame.into_offer(connection_id));
        reply(BulkFrame::Accept(BulkAcceptFrame::from(accept)))
    }

    fn handle_credit(
        &self,
        connection_id: ConnectionId,
        frame: BulkCreditRequestFrame,
    ) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
        let mut service = self.service.lock().unwrap();
        ensure_stream_token(&service, connection_id, frame.stream_id, frame.token)?;
        let grant = match service.credit(connection_id, frame.token, frame.chunk_seq, frame.len) {
            Ok(grant) => BulkCreditGrantFrame {
                stream_id: grant.stream_id,
                chunk_seq: grant.chunk_seq,
                result: BulkCreditResult::Granted,
                offset: grant.offset,
                rdma: None,
            },
            Err(err) => BulkCreditGrantFrame {
                stream_id: frame.stream_id,
                chunk_seq: frame.chunk_seq,
                result: credit_error_result(&err),
                offset: 0,
                rdma: None,
            },
        };
        reply(BulkFrame::CreditGrant(grant))
    }

    fn handle_done_with_terminal(
        &self,
        connection_id: ConnectionId,
        frame: BulkDoneFrame,
    ) -> (
        Result<DataServiceDispatchOutcome, DataServiceDispatchError>,
        Option<BulkDataServiceTerminal>,
    ) {
        let terminal = {
            let mut service = self.service.lock().unwrap();
            if let Err(error) =
                ensure_stream_token(&service, connection_id, frame.stream_id, frame.token)
            {
                return (Err(error), None);
            }
            service.done_with_terminal(
                connection_id,
                frame.token,
                frame.total_transferred,
                frame.checksum32,
            )
        };
        match terminal {
            Ok(completed) => (
                Ok(DataServiceDispatchOutcome::Consumed),
                Some(BulkDataServiceTerminal::Completed(completed)),
            ),
            Err((error, aborted)) => (
                Err(reject_bulk(error)),
                aborted.map(BulkDataServiceTerminal::Aborted),
            ),
        }
    }

    fn handle_abort_with_terminal(
        &self,
        connection_id: ConnectionId,
        frame: BulkAbortFrame,
    ) -> (
        Result<DataServiceDispatchOutcome, DataServiceDispatchError>,
        Option<BulkDataServiceTerminal>,
    ) {
        let aborted = {
            let mut service = self.service.lock().unwrap();
            if let Err(error) =
                ensure_stream_token(&service, connection_id, frame.stream_id, frame.token)
            {
                return (Err(error), None);
            }
            match service.abort(connection_id, frame.token, frame.reason) {
                Ok(aborted) => aborted,
                Err(error) => return (Err(reject_bulk(error)), None),
            }
        };
        (
            Ok(DataServiceDispatchOutcome::Consumed),
            Some(BulkDataServiceTerminal::Aborted(aborted)),
        )
    }
}

fn ensure_stream_token(
    service: &BulkService,
    connection_id: ConnectionId,
    stream_id: StreamId,
    token: BulkToken,
) -> Result<(), DataServiceDispatchError> {
    match service.stream_id_for_token(connection_id, token) {
        Some(actual) if actual == stream_id => Ok(()),
        Some(actual) => Err(reject_reason(format!(
            "BULK stream/token mismatch: frame stream {stream_id}, token stream {actual}"
        ))),
        None => Err(reject_bulk(BulkError::UnknownToken)),
    }
}

fn credit_error_result(error: &BulkError) -> BulkCreditResult {
    match error {
        BulkError::NoCredits | BulkError::TooManyPendingCredits { .. } => BulkCreditResult::Wait,
        _ => BulkCreditResult::Rejected,
    }
}

fn reply(frame: BulkFrame) -> Result<DataServiceDispatchOutcome, DataServiceDispatchError> {
    Ok(DataServiceDispatchOutcome::Reply(
        frame.to_data_service_frame().map_err(reject_protocol)?,
    ))
}

fn reject_protocol(error: BulkProtocolError) -> DataServiceDispatchError {
    reject_reason(error.to_string())
}

fn reject_bulk(error: BulkError) -> DataServiceDispatchError {
    reject_reason(error.to_string())
}

fn reject_reason(reason: impl Into<String>) -> DataServiceDispatchError {
    DataServiceDispatchError::HandlerRejected {
        service_id: BULK_SERVICE_ID,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BulkAbortReason, BulkAcceptResult, BulkMetadata, BulkMode, BulkOfferFrame, BulkPriority,
        BulkServiceConfig,
    };

    fn service() -> BulkService {
        BulkService::new(BulkServiceConfig {
            receiver_node_id: 42,
            max_pinned_bytes: 64,
            max_transfer_len: 64,
            max_chunk: 8,
            max_pending_credits_per_stream: 2,
            ..BulkServiceConfig::default()
        })
    }

    fn offer_frame(stream_id: StreamId, total_len: u64) -> BulkFrame {
        BulkFrame::Offer(BulkOfferFrame {
            stream_id,
            total_len,
            mode: BulkMode::TcpStream,
            priority: BulkPriority::Bulk,
            metadata: BulkMetadata::vfs_rpc_write_upload(99),
        })
    }

    fn handle_reply(
        handler: &BulkDataServiceHandler,
        session_id: SessionId,
        frame: BulkFrame,
    ) -> BulkFrame {
        let data_frame = frame.to_data_service_frame().expect("data frame");
        match handler
            .handle_data_service_frame(session_id, data_frame)
            .expect("handler")
        {
            DataServiceDispatchOutcome::Reply(reply) => {
                BulkFrame::from_data_service_frame(reply).expect("reply")
            }
            DataServiceDispatchOutcome::Consumed => panic!("expected reply"),
        }
    }

    #[test]
    fn handles_offer_credit_done_for_authenticated_session() {
        let handler = BulkDataServiceHandler::new(service());
        let session_id = SessionId::new(7);

        let accept = handle_reply(&handler, session_id, offer_frame(11, 5));
        let token = match accept {
            BulkFrame::Accept(frame) => {
                assert_eq!(frame.result, BulkAcceptResult::Accepted);
                assert_eq!(frame.stream_id, 11);
                frame.token.expect("token")
            }
            other => panic!("unexpected reply: {other:?}"),
        };

        let grant = handle_reply(
            &handler,
            session_id,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 11,
                token,
                chunk_seq: 0,
                len: 5,
            }),
        );
        let grant = match grant {
            BulkFrame::CreditGrant(frame) => {
                assert_eq!(frame.result, BulkCreditResult::Granted);
                assert_eq!(frame.offset, 0);
                frame
            }
            other => panic!("unexpected reply: {other:?}"),
        };

        assert_eq!(handler.active_transfer_count(session_id.0), 1);
        assert_eq!(handler.pinned_bytes(session_id.0), 5);
        let chunk =
            BulkTcpChunkFrame::new(11, token, grant.chunk_seq, grant.offset, b"hello".to_vec())
                .expect("chunk");
        let chunk =
            BulkTcpChunkFrame::decode(&chunk.encode().expect("chunk wire")).expect("chunk decode");
        handler
            .handle_tcp_chunk(session_id.0, chunk)
            .expect("chunk");

        let done = BulkFrame::Done(BulkDoneFrame {
            stream_id: 11,
            token,
            total_transferred: 5,
            checksum32: crc32c::crc32c(b"hello"),
        })
        .to_data_service_frame()
        .expect("done frame");
        assert_eq!(
            handler
                .handle_data_service_frame(session_id, done)
                .expect("done"),
            DataServiceDispatchOutcome::Consumed
        );

        let completed = handler.drain_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].connection_id, session_id.0);
        assert_eq!(completed[0].stream_id, 11);
        assert_eq!(completed[0].bytes, b"hello");
        assert_eq!(handler.active_transfer_count(session_id.0), 0);
    }

    #[test]
    fn rdma_offer_returns_mode_unsupported_without_live_claim() {
        let handler = BulkDataServiceHandler::new(service());
        let accept = handle_reply(
            &handler,
            SessionId::new(7),
            BulkFrame::Offer(BulkOfferFrame {
                stream_id: 12,
                total_len: 5,
                mode: BulkMode::RdmaWrite,
                priority: BulkPriority::Bulk,
                metadata: BulkMetadata::Opaque(b"rdma".to_vec()),
            }),
        );

        match accept {
            BulkFrame::Accept(frame) => {
                assert_eq!(frame.result, BulkAcceptResult::ModeUnsupported);
                assert!(frame.token.is_none());
            }
            other => panic!("unexpected reply: {other:?}"),
        }
    }

    #[test]
    fn abort_discards_transfer_and_records_event() {
        let handler = BulkDataServiceHandler::new(service());
        let session_id = SessionId::new(8);
        let accept = handle_reply(&handler, session_id, offer_frame(13, 5));
        let token = match accept {
            BulkFrame::Accept(frame) => frame.token.expect("token"),
            other => panic!("unexpected reply: {other:?}"),
        };

        let abort = BulkFrame::Abort(BulkAbortFrame {
            stream_id: 13,
            token,
            reason: BulkAbortReason::Timeout,
        })
        .to_data_service_frame()
        .expect("abort");
        assert_eq!(
            handler
                .handle_data_service_frame(session_id, abort)
                .expect("abort"),
            DataServiceDispatchOutcome::Consumed
        );

        let aborted = handler.drain_aborted();
        assert_eq!(aborted.len(), 1);
        assert_eq!(aborted[0].connection_id, session_id.0);
        assert_eq!(aborted[0].stream_id, 13);
        assert_eq!(aborted[0].reason, BulkAbortReason::Timeout);
        assert_eq!(handler.active_transfer_count(session_id.0), 0);
    }

    #[test]
    fn delayed_chunk_cannot_cross_reused_stream_token() {
        let handler = BulkDataServiceHandler::new(service());
        let session_id = SessionId::new(9);
        let old_token = match handle_reply(&handler, session_id, offer_frame(14, 3)) {
            BulkFrame::Accept(frame) => frame.token.expect("old token"),
            other => panic!("unexpected reply: {other:?}"),
        };
        let old_grant = match handle_reply(
            &handler,
            session_id,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 14,
                token: old_token,
                chunk_seq: 0,
                len: 3,
            }),
        ) {
            BulkFrame::CreditGrant(frame) => frame,
            other => panic!("unexpected reply: {other:?}"),
        };
        let delayed = BulkTcpChunkFrame::new(
            14,
            old_token,
            old_grant.chunk_seq,
            old_grant.offset,
            b"old".to_vec(),
        )
        .expect("old chunk");
        let delayed = BulkTcpChunkFrame::decode(&delayed.encode().expect("old chunk wire"))
            .expect("decode old chunk");

        let abort = BulkFrame::Abort(BulkAbortFrame {
            stream_id: 14,
            token: old_token,
            reason: BulkAbortReason::SenderCancel,
        })
        .to_data_service_frame()
        .expect("abort");
        handler
            .handle_data_service_frame(session_id, abort)
            .expect("abort old attempt");

        let new_token = match handle_reply(&handler, session_id, offer_frame(14, 3)) {
            BulkFrame::Accept(frame) => frame.token.expect("new token"),
            other => panic!("unexpected reply: {other:?}"),
        };
        assert_ne!(new_token, old_token);
        let new_grant = match handle_reply(
            &handler,
            session_id,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 14,
                token: new_token,
                chunk_seq: 0,
                len: 3,
            }),
        ) {
            BulkFrame::CreditGrant(frame) => frame,
            other => panic!("unexpected reply: {other:?}"),
        };

        assert_eq!(
            handler.handle_tcp_chunk(session_id.0, delayed),
            Err(BulkError::UnknownToken)
        );
        handler
            .handle_tcp_chunk(
                session_id.0,
                BulkTcpChunkFrame::new(
                    14,
                    new_token,
                    new_grant.chunk_seq,
                    new_grant.offset,
                    b"new".to_vec(),
                )
                .expect("new chunk"),
            )
            .expect("current attempt chunk");

        let done = BulkFrame::Done(BulkDoneFrame {
            stream_id: 14,
            token: new_token,
            total_transferred: 3,
            checksum32: crc32c::crc32c(b"new"),
        })
        .to_data_service_frame()
        .expect("done");
        handler
            .handle_data_service_frame(session_id, done)
            .expect("complete current attempt");
        let completed = handler.drain_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].token, new_token);
        assert_eq!(completed[0].bytes, b"new");
    }

    #[test]
    fn response_frames_are_rejected_without_sender_coordinator() {
        let handler = BulkDataServiceHandler::new(service());
        let frame = BulkFrame::Accept(BulkAcceptFrame {
            stream_id: 11,
            result: BulkAcceptResult::Rejected,
            token: None,
            max_chunk: 0,
            retry_after_us: 0,
        })
        .to_data_service_frame()
        .expect("accept");

        let err = handler
            .handle_data_service_frame(SessionId::new(7), frame)
            .unwrap_err();
        assert!(err.to_string().contains("sender-side coordinator"));
    }
}
