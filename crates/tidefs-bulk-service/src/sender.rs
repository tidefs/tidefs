// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Sender-side TCP_STREAM coordination for BULK `service_id = 0x07`.
//!
//! This module consumes receiver ACCEPT/CREDIT_GRANT responses and emits the
//! next CREDIT, raw TCP chunk, DONE, or ABORT item that a transport binding can
//! put on the already-authenticated connection. It does not register a transport
//! receive loop, change VFS_RPC descriptor policy, or enable RDMA.

use std::collections::BTreeMap;
use std::fmt;

use crate::{
    BulkAbortFrame, BulkAbortReason, BulkAcceptFrame, BulkAcceptResult, BulkCreditGrantFrame,
    BulkCreditRequestFrame, BulkCreditResult, BulkDoneFrame, BulkFrame, BulkMetadata, BulkMode,
    BulkOfferFrame, BulkPriority, BulkProtocolError, BulkRdmaCredit, BulkTcpChunkFrame, BulkToken,
    ConnectionId, StreamId,
};

/// Sender-side coordinator for one authenticated transport connection.
#[derive(Debug)]
pub struct BulkSenderCoordinator {
    connection_id: ConnectionId,
    transfers: BTreeMap<StreamId, SenderTransfer>,
}

impl BulkSenderCoordinator {
    #[must_use]
    pub fn new(connection_id: ConnectionId) -> Self {
        Self {
            connection_id,
            transfers: BTreeMap::new(),
        }
    }

    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    #[must_use]
    pub fn active_transfer_count(&self) -> usize {
        self.transfers.len()
    }

    pub fn start_tcp_stream(
        &mut self,
        stream_id: StreamId,
        priority: BulkPriority,
        metadata: BulkMetadata,
        payload: Vec<u8>,
    ) -> Result<BulkFrame, BulkSenderError> {
        if self.transfers.contains_key(&stream_id) {
            return Err(BulkSenderError::DuplicateStream { stream_id });
        }
        let total_len = u64::try_from(payload.len())
            .map_err(|_| BulkSenderError::PayloadTooLarge { len: payload.len() })?;
        let offer = BulkOfferFrame {
            stream_id,
            total_len,
            mode: BulkMode::TcpStream,
            priority,
            metadata,
        };
        self.transfers
            .insert(stream_id, SenderTransfer::new(stream_id, payload));
        Ok(BulkFrame::Offer(offer))
    }

    pub fn handle_response_frame(
        &mut self,
        frame: BulkFrame,
    ) -> Result<BulkSenderResponse, BulkSenderError> {
        match frame {
            BulkFrame::Accept(frame) => self.handle_accept(frame).map(BulkSenderResponse::Accepted),
            BulkFrame::CreditGrant(frame) => self
                .handle_credit_grant(frame)
                .map(BulkSenderResponse::Credit),
            other => Err(BulkSenderError::UnexpectedResponseFrame {
                frame: frame_name(&other),
            }),
        }
    }

    pub fn handle_accept(
        &mut self,
        frame: BulkAcceptFrame,
    ) -> Result<BulkSenderAccepted, BulkSenderError> {
        let stream_id = frame.stream_id;
        if !self.transfers.contains_key(&stream_id) {
            return Err(BulkSenderError::UnknownStream { stream_id });
        }
        if frame.result != BulkAcceptResult::Accepted {
            self.transfers.remove(&stream_id);
            return Err(BulkSenderError::AcceptRejected {
                stream_id,
                result: frame.result,
                retry_after_us: frame.retry_after_us,
            });
        }
        let token = match frame.token {
            Some(token) => token,
            None => {
                self.transfers.remove(&stream_id);
                return Err(BulkSenderError::MissingAcceptedToken { stream_id });
            }
        };
        if frame.max_chunk == 0 {
            self.transfers.remove(&stream_id);
            return Err(BulkSenderError::InvalidAcceptedMaxChunk { stream_id });
        }

        let transfer = self.transfer_mut(stream_id)?;
        if transfer.token.is_some() {
            return Err(BulkSenderError::AlreadyAccepted { stream_id });
        }
        transfer.token = Some(token);
        transfer.max_chunk = frame.max_chunk;
        Ok(BulkSenderAccepted {
            stream_id,
            token,
            max_chunk: frame.max_chunk,
        })
    }

    pub fn next_credit_request(
        &mut self,
        stream_id: StreamId,
    ) -> Result<Option<BulkFrame>, BulkSenderError> {
        let transfer = self.transfer_mut(stream_id)?;
        let token = transfer
            .token
            .ok_or(BulkSenderError::TransferNotAccepted { stream_id })?;

        if let Some(pending) = transfer.pending_credit {
            return Ok(Some(BulkFrame::CreditRequest(
                pending.credit_request(stream_id, token),
            )));
        }
        if transfer.next_offset >= transfer.total_len() {
            return Ok(None);
        }

        let remaining = transfer.total_len() - transfer.next_offset;
        let len = remaining.min(u64::from(transfer.max_chunk)) as u32;
        if len == 0 {
            return Err(BulkSenderError::InvalidAcceptedMaxChunk { stream_id });
        }
        let next_offset = transfer
            .next_offset
            .checked_add(u64::from(len))
            .ok_or(BulkSenderError::TransferOverflow { stream_id })?;
        let pending = PendingCredit {
            chunk_seq: transfer.next_credit_seq,
            offset: transfer.next_offset,
            len,
        };
        transfer.next_credit_seq = transfer.next_credit_seq.saturating_add(1);
        transfer.next_offset = next_offset;
        transfer.pending_credit = Some(pending);
        Ok(Some(BulkFrame::CreditRequest(
            pending.credit_request(stream_id, token),
        )))
    }

    pub fn handle_credit_grant(
        &mut self,
        frame: BulkCreditGrantFrame,
    ) -> Result<BulkSenderCreditOutcome, BulkSenderError> {
        let stream_id = frame.stream_id;
        let pending = {
            let transfer = self.transfer_mut(stream_id)?;
            let pending = transfer
                .pending_credit
                .ok_or(BulkSenderError::CreditWithoutRequest {
                    stream_id,
                    chunk_seq: frame.chunk_seq,
                })?;
            if frame.chunk_seq != pending.chunk_seq {
                return Err(BulkSenderError::UnexpectedCreditSequence {
                    stream_id,
                    expected: pending.chunk_seq,
                    actual: frame.chunk_seq,
                });
            }
            pending
        };
        match frame.result {
            BulkCreditResult::Wait => return Ok(BulkSenderCreditOutcome::Wait),
            BulkCreditResult::Rejected => {
                self.transfers.remove(&stream_id);
                return Err(BulkSenderError::CreditRejected {
                    stream_id,
                    chunk_seq: frame.chunk_seq,
                });
            }
            BulkCreditResult::Granted => {}
        }
        if let Some(rdma) = frame.rdma {
            return Err(BulkSenderError::RdmaCreditUnsupported { stream_id, rdma });
        }

        let (chunk, done, final_chunk) = {
            let transfer = self.transfer_mut(stream_id)?;
            let token = transfer
                .token
                .ok_or(BulkSenderError::TransferNotAccepted { stream_id })?;
            if frame.offset != pending.offset {
                return Err(BulkSenderError::CreditOffsetMismatch {
                    stream_id,
                    expected: pending.offset,
                    actual: frame.offset,
                });
            }

            let start = usize::try_from(pending.offset)
                .map_err(|_| BulkSenderError::TransferOverflow { stream_id })?;
            let end = start
                .checked_add(pending.len as usize)
                .ok_or(BulkSenderError::TransferOverflow { stream_id })?;
            if end > transfer.payload.len() {
                return Err(BulkSenderError::TransferOverflow { stream_id });
            }

            let chunk = BulkTcpChunkFrame::new(
                stream_id,
                pending.chunk_seq,
                pending.offset,
                transfer.payload[start..end].to_vec(),
            )
            .map_err(BulkSenderError::Protocol)?;
            transfer.pending_credit = None;

            let final_chunk = transfer.next_offset >= transfer.total_len();
            let done = final_chunk.then(|| {
                BulkFrame::Done(BulkDoneFrame {
                    stream_id,
                    token,
                    total_transferred: transfer.total_len(),
                    checksum32: crc32c::crc32c(&transfer.payload),
                })
            });
            (chunk, done, final_chunk)
        };

        if final_chunk {
            self.transfers.remove(&stream_id);
        }
        Ok(BulkSenderCreditOutcome::SendChunk { chunk, done })
    }

    pub fn abort(
        &mut self,
        stream_id: StreamId,
        reason: BulkAbortReason,
    ) -> Result<Option<BulkFrame>, BulkSenderError> {
        let transfer = self
            .transfers
            .remove(&stream_id)
            .ok_or(BulkSenderError::UnknownStream { stream_id })?;
        Ok(transfer.token.map(|token| {
            BulkFrame::Abort(BulkAbortFrame {
                stream_id,
                token,
                reason,
            })
        }))
    }

    fn transfer_mut(
        &mut self,
        stream_id: StreamId,
    ) -> Result<&mut SenderTransfer, BulkSenderError> {
        self.transfers
            .get_mut(&stream_id)
            .ok_or(BulkSenderError::UnknownStream { stream_id })
    }
}

/// Result of an accepted sender-side OFFER.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkSenderAccepted {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub max_chunk: u32,
}

/// Response-frame outcome consumed by [`BulkSenderCoordinator`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkSenderResponse {
    Accepted(BulkSenderAccepted),
    Credit(BulkSenderCreditOutcome),
}

/// Work item produced from a CREDIT_GRANT response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkSenderCreditOutcome {
    SendChunk {
        chunk: BulkTcpChunkFrame,
        done: Option<BulkFrame>,
    },
    Wait,
}

#[derive(Clone, Debug)]
struct SenderTransfer {
    payload: Vec<u8>,
    token: Option<BulkToken>,
    max_chunk: u32,
    next_credit_seq: u32,
    next_offset: u64,
    pending_credit: Option<PendingCredit>,
}

impl SenderTransfer {
    fn new(_stream_id: StreamId, payload: Vec<u8>) -> Self {
        Self {
            payload,
            token: None,
            max_chunk: 0,
            next_credit_seq: 0,
            next_offset: 0,
            pending_credit: None,
        }
    }

    fn total_len(&self) -> u64 {
        self.payload.len() as u64
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingCredit {
    chunk_seq: u32,
    offset: u64,
    len: u32,
}

impl PendingCredit {
    fn credit_request(self, stream_id: StreamId, token: BulkToken) -> BulkCreditRequestFrame {
        BulkCreditRequestFrame {
            stream_id,
            token,
            chunk_seq: self.chunk_seq,
            len: self.len,
        }
    }
}

/// Errors emitted by the sender-side BULK coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkSenderError {
    DuplicateStream {
        stream_id: StreamId,
    },
    UnknownStream {
        stream_id: StreamId,
    },
    PayloadTooLarge {
        len: usize,
    },
    AcceptRejected {
        stream_id: StreamId,
        result: BulkAcceptResult,
        retry_after_us: u32,
    },
    MissingAcceptedToken {
        stream_id: StreamId,
    },
    InvalidAcceptedMaxChunk {
        stream_id: StreamId,
    },
    AlreadyAccepted {
        stream_id: StreamId,
    },
    TransferNotAccepted {
        stream_id: StreamId,
    },
    CreditWithoutRequest {
        stream_id: StreamId,
        chunk_seq: u32,
    },
    UnexpectedCreditSequence {
        stream_id: StreamId,
        expected: u32,
        actual: u32,
    },
    CreditOffsetMismatch {
        stream_id: StreamId,
        expected: u64,
        actual: u64,
    },
    CreditRejected {
        stream_id: StreamId,
        chunk_seq: u32,
    },
    RdmaCreditUnsupported {
        stream_id: StreamId,
        rdma: BulkRdmaCredit,
    },
    TransferOverflow {
        stream_id: StreamId,
    },
    UnexpectedResponseFrame {
        frame: &'static str,
    },
    Protocol(BulkProtocolError),
}

impl fmt::Display for BulkSenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateStream { stream_id } => {
                write!(f, "BULK sender stream {stream_id} is already active")
            }
            Self::UnknownStream { stream_id } => {
                write!(f, "BULK sender stream {stream_id} is unknown")
            }
            Self::PayloadTooLarge { len } => {
                write!(f, "BULK sender payload length {len} exceeds u64::MAX")
            }
            Self::AcceptRejected {
                stream_id,
                result,
                retry_after_us,
            } => write!(
                f,
                "BULK sender stream {stream_id} ACCEPT rejected with {result:?}, retry_after_us={retry_after_us}"
            ),
            Self::MissingAcceptedToken { stream_id } => {
                write!(f, "BULK sender stream {stream_id} ACCEPTED without token")
            }
            Self::InvalidAcceptedMaxChunk { stream_id } => {
                write!(f, "BULK sender stream {stream_id} ACCEPTED with max_chunk=0")
            }
            Self::AlreadyAccepted { stream_id } => {
                write!(f, "BULK sender stream {stream_id} was already accepted")
            }
            Self::TransferNotAccepted { stream_id } => {
                write!(f, "BULK sender stream {stream_id} is not accepted")
            }
            Self::CreditWithoutRequest {
                stream_id,
                chunk_seq,
            } => write!(
                f,
                "BULK sender stream {stream_id} received CREDIT_GRANT {chunk_seq} without a request"
            ),
            Self::UnexpectedCreditSequence {
                stream_id,
                expected,
                actual,
            } => write!(
                f,
                "BULK sender stream {stream_id} CREDIT_GRANT sequence {actual} does not match expected {expected}"
            ),
            Self::CreditOffsetMismatch {
                stream_id,
                expected,
                actual,
            } => write!(
                f,
                "BULK sender stream {stream_id} CREDIT_GRANT offset {actual} does not match expected {expected}"
            ),
            Self::CreditRejected {
                stream_id,
                chunk_seq,
            } => write!(
                f,
                "BULK sender stream {stream_id} CREDIT_GRANT rejected chunk {chunk_seq}"
            ),
            Self::RdmaCreditUnsupported { stream_id, .. } => {
                write!(f, "BULK sender stream {stream_id} received RDMA credit before RDMA gates")
            }
            Self::TransferOverflow { stream_id } => {
                write!(f, "BULK sender stream {stream_id} transfer arithmetic overflow")
            }
            Self::UnexpectedResponseFrame { frame } => {
                write!(f, "BULK sender cannot consume {frame} as a response frame")
            }
            Self::Protocol(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BulkSenderError {}

fn frame_name(frame: &BulkFrame) -> &'static str {
    match frame {
        BulkFrame::Offer(_) => "OFFER",
        BulkFrame::Accept(_) => "ACCEPT",
        BulkFrame::CreditRequest(_) => "CREDIT",
        BulkFrame::CreditGrant(_) => "CREDIT_GRANT",
        BulkFrame::Done(_) => "DONE",
        BulkFrame::Abort(_) => "ABORT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(byte: u8) -> BulkToken {
        [byte; 32]
    }

    #[test]
    fn sender_coordinates_tcp_chunks_and_done() {
        let mut sender = BulkSenderCoordinator::new(7);
        let offer = sender
            .start_tcp_stream(
                11,
                BulkPriority::Bulk,
                BulkMetadata::vfs_rpc_write_upload(99),
                b"hello world".to_vec(),
            )
            .expect("offer");
        assert!(matches!(offer, BulkFrame::Offer(_)));

        sender
            .handle_accept(BulkAcceptFrame {
                stream_id: 11,
                result: BulkAcceptResult::Accepted,
                token: Some(token(0x11)),
                max_chunk: 8,
                retry_after_us: 0,
            })
            .expect("accept");

        let credit = sender
            .next_credit_request(11)
            .expect("credit")
            .expect("request");
        assert!(matches!(
            credit,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 11,
                chunk_seq: 0,
                len: 8,
                ..
            })
        ));
        let first = sender
            .handle_credit_grant(BulkCreditGrantFrame {
                stream_id: 11,
                chunk_seq: 0,
                result: BulkCreditResult::Granted,
                offset: 0,
                rdma: None,
            })
            .expect("grant");
        match first {
            BulkSenderCreditOutcome::SendChunk { chunk, done } => {
                assert_eq!(chunk.payload, b"hello wo");
                assert!(done.is_none());
            }
            BulkSenderCreditOutcome::Wait => panic!("unexpected wait"),
        }

        let credit = sender
            .next_credit_request(11)
            .expect("credit")
            .expect("request");
        assert!(matches!(
            credit,
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 11,
                chunk_seq: 1,
                len: 3,
                ..
            })
        ));
        let final_step = sender
            .handle_credit_grant(BulkCreditGrantFrame {
                stream_id: 11,
                chunk_seq: 1,
                result: BulkCreditResult::Granted,
                offset: 8,
                rdma: None,
            })
            .expect("grant");
        match final_step {
            BulkSenderCreditOutcome::SendChunk { chunk, done } => {
                assert_eq!(chunk.payload, b"rld");
                assert_eq!(
                    done,
                    Some(BulkFrame::Done(BulkDoneFrame {
                        stream_id: 11,
                        token: token(0x11),
                        total_transferred: 11,
                        checksum32: crc32c::crc32c(b"hello world"),
                    }))
                );
            }
            BulkSenderCreditOutcome::Wait => panic!("unexpected wait"),
        }
        assert_eq!(sender.active_transfer_count(), 0);
    }

    #[test]
    fn wait_credit_keeps_request_retriable_without_moving_offset() {
        let mut sender = BulkSenderCoordinator::new(7);
        sender
            .start_tcp_stream(
                11,
                BulkPriority::Bulk,
                BulkMetadata::Opaque(vec![]),
                vec![1; 9],
            )
            .expect("offer");
        sender
            .handle_accept(BulkAcceptFrame {
                stream_id: 11,
                result: BulkAcceptResult::Accepted,
                token: Some(token(0x11)),
                max_chunk: 4,
                retry_after_us: 0,
            })
            .expect("accept");

        let first = sender.next_credit_request(11).unwrap().unwrap();
        assert_eq!(
            sender
                .handle_credit_grant(BulkCreditGrantFrame {
                    stream_id: 11,
                    chunk_seq: 0,
                    result: BulkCreditResult::Wait,
                    offset: 0,
                    rdma: None,
                })
                .unwrap(),
            BulkSenderCreditOutcome::Wait
        );
        let retry = sender.next_credit_request(11).unwrap().unwrap();
        assert_eq!(retry, first);
    }

    #[test]
    fn rdma_credit_is_rejected_until_rdma_gates_exist() {
        let mut sender = BulkSenderCoordinator::new(7);
        sender
            .start_tcp_stream(
                11,
                BulkPriority::Bulk,
                BulkMetadata::Opaque(vec![]),
                vec![1; 4],
            )
            .expect("offer");
        sender
            .handle_accept(BulkAcceptFrame {
                stream_id: 11,
                result: BulkAcceptResult::Accepted,
                token: Some(token(0x11)),
                max_chunk: 4,
                retry_after_us: 0,
            })
            .expect("accept");
        sender.next_credit_request(11).unwrap();

        assert!(matches!(
            sender.handle_credit_grant(BulkCreditGrantFrame {
                stream_id: 11,
                chunk_seq: 0,
                result: BulkCreditResult::Granted,
                offset: 0,
                rdma: Some(BulkRdmaCredit { rkey: 1, addr: 2 }),
            }),
            Err(BulkSenderError::RdmaCreditUnsupported { .. })
        ));
    }
}
