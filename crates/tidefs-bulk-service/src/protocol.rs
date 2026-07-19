// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Wire codec for BULK `service_id = 0x07` DATA-endpoint frames.
//!
//! The codec maps BULK OFFER/ACCEPT/CREDIT/DONE/ABORT messages to the generic
//! transport [`tidefs_transport::DataServiceFrame`] wrapper. It does not bind a
//! live receive loop, VFS_RPC adapter, or RDMA carrier by itself.

use std::fmt;

use tidefs_transport::{DataServiceDispatchError, DataServiceFrame};

use crate::{
    BulkAbortReason, BulkAccept, BulkAcceptResult, BulkMetadata, BulkMode, BulkOffer, BulkPriority,
    BulkToken, BulkTransferDirection, ConnectionId, StreamId, VfsRpcBulkMethod, BULK_SERVICE_ID,
};

const FRAME_KIND_SHIFT: u8 = 6;
const METHOD_MASK: u8 = 0b0011_1111;
const OFFER_FIXED_BODY_LEN: usize = 16;
const ACCEPT_BODY_LEN: usize = 45;
const CREDIT_REQUEST_BODY_LEN: usize = 44;
const CREDIT_GRANT_TCP_BODY_LEN: usize = 17;
const CREDIT_GRANT_RDMA_BODY_LEN: usize = 29;
const DONE_BODY_LEN: usize = 48;
const ABORT_BODY_LEN: usize = 37;
const TCP_CHUNK_HEADER_LEN: usize = 56;

/// Magic prefix for BULK-owned VFS_RPC metadata carried in OFFER.
pub const VFS_RPC_BULK_METADATA_MAGIC: [u8; 4] = *b"VFSR";
/// Current VFS_RPC BULK metadata format version.
pub const VFS_RPC_BULK_METADATA_VERSION: u8 = 1;
const VFS_RPC_BULK_METADATA_LEN: usize = 16;

/// High two bits of the BULK message-type byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkFrameKind {
    Request = 0b00,
    Response = 0b01,
}

impl BulkFrameKind {
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        (self as u8) << FRAME_KIND_SHIFT
    }

    fn from_wire(value: u8) -> Result<Self, BulkProtocolError> {
        match value {
            0b00 => Ok(Self::Request),
            0b01 => Ok(Self::Response),
            other => Err(BulkProtocolError::UnknownFrameKind(other)),
        }
    }
}

/// Low six bits of the BULK message-type byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkMethod {
    Offer = 0x00,
    Accept = 0x01,
    Credit = 0x02,
    Done = 0x03,
    Abort = 0x04,
}

impl BulkMethod {
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    fn from_wire(value: u8) -> Result<Self, BulkProtocolError> {
        match value {
            0x00 => Ok(Self::Offer),
            0x01 => Ok(Self::Accept),
            0x02 => Ok(Self::Credit),
            0x03 => Ok(Self::Done),
            0x04 => Ok(Self::Abort),
            other => Err(BulkProtocolError::UnknownMethod(other)),
        }
    }
}

/// CREDIT response status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BulkCreditResult {
    Granted = 0,
    Wait = 1,
    Rejected = 2,
}

impl BulkCreditResult {
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        self as u8
    }

    fn from_wire(value: u8) -> Result<Self, BulkProtocolError> {
        match value {
            0 => Ok(Self::Granted),
            1 => Ok(Self::Wait),
            2 => Ok(Self::Rejected),
            other => Err(BulkProtocolError::UnknownCreditResult(other)),
        }
    }
}

/// OFFER frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkOfferFrame {
    pub stream_id: StreamId,
    pub total_len: u64,
    pub mode: BulkMode,
    pub priority: BulkPriority,
    pub metadata: BulkMetadata,
}

impl BulkOfferFrame {
    #[must_use]
    pub fn into_offer(self, connection_id: ConnectionId) -> BulkOffer {
        BulkOffer {
            connection_id,
            stream_id: self.stream_id,
            total_len: self.total_len,
            mode: self.mode,
            priority: self.priority,
            metadata: self.metadata,
        }
    }
}

impl From<BulkOffer> for BulkOfferFrame {
    fn from(offer: BulkOffer) -> Self {
        Self {
            stream_id: offer.stream_id,
            total_len: offer.total_len,
            mode: offer.mode,
            priority: offer.priority,
            metadata: offer.metadata,
        }
    }
}

/// ACCEPT frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkAcceptFrame {
    pub stream_id: StreamId,
    pub result: BulkAcceptResult,
    pub token: Option<BulkToken>,
    pub max_chunk: u32,
    pub retry_after_us: u32,
}

impl From<BulkAccept> for BulkAcceptFrame {
    fn from(accept: BulkAccept) -> Self {
        let retry_after_us = accept
            .retry_after
            .map(|duration| duration.as_micros().min(u128::from(u32::MAX)) as u32)
            .unwrap_or(0);
        Self {
            stream_id: accept.stream_id,
            result: accept.result,
            token: accept.token,
            max_chunk: accept.max_chunk,
            retry_after_us,
        }
    }
}

/// CREDIT request frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkCreditRequestFrame {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub chunk_seq: u32,
    pub len: u32,
}

/// RDMA credit fields carried only by future RDMA grant frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BulkRdmaCredit {
    pub rkey: u32,
    pub addr: u64,
}

/// CREDIT response frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkCreditGrantFrame {
    pub stream_id: StreamId,
    pub chunk_seq: u32,
    pub result: BulkCreditResult,
    pub offset: u64,
    pub rdma: Option<BulkRdmaCredit>,
}

/// DONE frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkDoneFrame {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub total_transferred: u64,
    pub checksum32: u32,
}

/// ABORT frame body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkAbortFrame {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub reason: BulkAbortReason,
}

/// A raw TCP_STREAM data chunk for a granted BULK credit.
///
/// The connection-scoped token binds the chunk to one accepted transfer
/// attempt, even when a later attempt reuses the same stream id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BulkTcpChunkFrame {
    pub stream_id: StreamId,
    pub token: BulkToken,
    pub chunk_seq: u32,
    pub offset: u64,
    pub payload: Vec<u8>,
    pub checksum32: u32,
}

impl BulkTcpChunkFrame {
    pub fn new(
        stream_id: StreamId,
        token: BulkToken,
        chunk_seq: u32,
        offset: u64,
        payload: Vec<u8>,
    ) -> Result<Self, BulkProtocolError> {
        ensure_tcp_chunk_len(payload.len())?;
        let checksum32 = crc32c::crc32c(&payload);
        Ok(Self {
            stream_id,
            token,
            chunk_seq,
            offset,
            payload,
            checksum32,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, BulkProtocolError> {
        ensure_tcp_chunk_len(self.payload.len())?;
        let mut out = Vec::with_capacity(TCP_CHUNK_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        out.extend_from_slice(&self.token);
        out.extend_from_slice(&self.chunk_seq.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.checksum32.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, BulkProtocolError> {
        require_min_len("TCP chunk", bytes, TCP_CHUNK_HEADER_LEN)?;
        let payload_len = u32::from_le_bytes(bytes[48..52].try_into().unwrap()) as usize;
        let expected = TCP_CHUNK_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(BulkProtocolError::BodyLengthOverflow { frame: "TCP chunk" })?;
        require_exact_len("TCP chunk", bytes, expected)?;

        let payload = bytes[TCP_CHUNK_HEADER_LEN..].to_vec();
        let checksum32 = u32::from_le_bytes(bytes[52..56].try_into().unwrap());
        let actual = crc32c::crc32c(&payload);
        if checksum32 != actual {
            return Err(BulkProtocolError::TcpChunkChecksumMismatch {
                expected: checksum32,
                actual,
            });
        }

        Ok(Self {
            stream_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            token: bytes[4..36].try_into().unwrap(),
            chunk_seq: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
            offset: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            payload,
            checksum32,
        })
    }
}

/// A typed BULK service frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkFrame {
    Offer(BulkOfferFrame),
    Accept(BulkAcceptFrame),
    CreditRequest(BulkCreditRequestFrame),
    CreditGrant(BulkCreditGrantFrame),
    Done(BulkDoneFrame),
    Abort(BulkAbortFrame),
}

impl BulkFrame {
    pub fn to_data_service_frame(&self) -> Result<DataServiceFrame, BulkProtocolError> {
        let (kind, method, body) = match self {
            Self::Offer(frame) => (
                BulkFrameKind::Request,
                BulkMethod::Offer,
                encode_offer_body(frame)?,
            ),
            Self::Accept(frame) => (
                BulkFrameKind::Response,
                BulkMethod::Accept,
                encode_accept_body(frame),
            ),
            Self::CreditRequest(frame) => (
                BulkFrameKind::Request,
                BulkMethod::Credit,
                encode_credit_request_body(frame),
            ),
            Self::CreditGrant(frame) => (
                BulkFrameKind::Response,
                BulkMethod::Credit,
                encode_credit_grant_body(frame),
            ),
            Self::Done(frame) => (
                BulkFrameKind::Request,
                BulkMethod::Done,
                encode_done_body(frame),
            ),
            Self::Abort(frame) => (
                BulkFrameKind::Request,
                BulkMethod::Abort,
                encode_abort_body(frame),
            ),
        };

        Ok(DataServiceFrame::new(
            BULK_SERVICE_ID,
            encode_message_type(kind, method),
            body,
        ))
    }

    pub fn from_data_service_frame(frame: DataServiceFrame) -> Result<Self, BulkProtocolError> {
        if frame.service_id != BULK_SERVICE_ID {
            return Err(BulkProtocolError::WrongServiceId {
                expected: BULK_SERVICE_ID,
                actual: frame.service_id,
            });
        }

        let (kind, method) = decode_message_type(frame.message_type)?;
        match (kind, method) {
            (BulkFrameKind::Request, BulkMethod::Offer) => {
                Ok(Self::Offer(decode_offer_body(&frame.body)?))
            }
            (BulkFrameKind::Response, BulkMethod::Accept) => {
                Ok(Self::Accept(decode_accept_body(&frame.body)?))
            }
            (BulkFrameKind::Request, BulkMethod::Credit) => Ok(Self::CreditRequest(
                decode_credit_request_body(&frame.body)?,
            )),
            (BulkFrameKind::Response, BulkMethod::Credit) => {
                Ok(Self::CreditGrant(decode_credit_grant_body(&frame.body)?))
            }
            (BulkFrameKind::Request, BulkMethod::Done) => {
                Ok(Self::Done(decode_done_body(&frame.body)?))
            }
            (BulkFrameKind::Request, BulkMethod::Abort) => {
                Ok(Self::Abort(decode_abort_body(&frame.body)?))
            }
            (kind, method) => Err(BulkProtocolError::InvalidFrameKindForMethod { kind, method }),
        }
    }

    pub fn encode_for_transport(&self) -> Result<Vec<u8>, BulkProtocolError> {
        self.to_data_service_frame()?.encode().map_err(Into::into)
    }

    pub fn decode_from_transport(bytes: &[u8]) -> Result<Self, BulkProtocolError> {
        let frame = DataServiceFrame::decode(bytes)?;
        Self::from_data_service_frame(frame)
    }
}

/// Errors emitted by the BULK wire codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BulkProtocolError {
    TransportFrame(DataServiceDispatchError),
    WrongServiceId {
        expected: u8,
        actual: u8,
    },
    UnknownFrameKind(u8),
    UnknownMethod(u8),
    InvalidFrameKindForMethod {
        kind: BulkFrameKind,
        method: BulkMethod,
    },
    BodyTooShort {
        frame: &'static str,
        min: usize,
        actual: usize,
    },
    BodyLengthOverflow {
        frame: &'static str,
    },
    BodyLengthMismatch {
        frame: &'static str,
        expected: usize,
        actual: usize,
    },
    MetadataTooLarge {
        len: usize,
    },
    UnsupportedMetadataVersion(u8),
    UnknownMode(u8),
    UnknownPriority(u8),
    UnknownAcceptResult(u8),
    UnknownCreditResult(u8),
    UnknownAbortReason(u8),
    UnknownVfsRpcMethod(u8),
    UnknownVfsRpcDirection(u8),
    TcpChunkTooLarge {
        len: usize,
    },
    TcpChunkChecksumMismatch {
        expected: u32,
        actual: u32,
    },
}

impl fmt::Display for BulkProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportFrame(err) => write!(f, "{err}"),
            Self::WrongServiceId { expected, actual } => write!(
                f,
                "BULK frame service_id {actual:#04x} does not match {expected:#04x}"
            ),
            Self::UnknownFrameKind(kind) => write!(f, "unknown BULK frame kind {kind:#04x}"),
            Self::UnknownMethod(method) => write!(f, "unknown BULK method {method:#04x}"),
            Self::InvalidFrameKindForMethod { kind, method } => {
                write!(f, "BULK {kind:?} is not valid for {method:?}")
            }
            Self::BodyTooShort { frame, min, actual } => {
                write!(f, "BULK {frame} body too short: {actual}, need {min}")
            }
            Self::BodyLengthOverflow { frame } => {
                write!(f, "BULK {frame} body length overflow")
            }
            Self::BodyLengthMismatch {
                frame,
                expected,
                actual,
            } => write!(
                f,
                "BULK {frame} body length mismatch: expected {expected}, actual {actual}"
            ),
            Self::MetadataTooLarge { len } => {
                write!(f, "BULK metadata length {len} exceeds u16::MAX")
            }
            Self::UnsupportedMetadataVersion(version) => {
                write!(f, "unsupported VFS_RPC BULK metadata version {version}")
            }
            Self::UnknownMode(value) => write!(f, "unknown BULK mode {value}"),
            Self::UnknownPriority(value) => write!(f, "unknown BULK priority {value}"),
            Self::UnknownAcceptResult(value) => write!(f, "unknown BULK ACCEPT result {value}"),
            Self::UnknownCreditResult(value) => write!(f, "unknown BULK CREDIT result {value}"),
            Self::UnknownAbortReason(value) => write!(f, "unknown BULK ABORT reason {value}"),
            Self::UnknownVfsRpcMethod(value) => write!(f, "unknown VFS_RPC BULK method {value}"),
            Self::UnknownVfsRpcDirection(value) => {
                write!(f, "unknown VFS_RPC BULK direction {value}")
            }
            Self::TcpChunkTooLarge { len } => {
                write!(f, "BULK TCP chunk payload length {len} exceeds u32::MAX")
            }
            Self::TcpChunkChecksumMismatch { expected, actual } => write!(
                f,
                "BULK TCP chunk CRC32C {actual:#010x} does not match expected {expected:#010x}"
            ),
        }
    }
}

impl std::error::Error for BulkProtocolError {}

impl From<DataServiceDispatchError> for BulkProtocolError {
    fn from(error: DataServiceDispatchError) -> Self {
        Self::TransportFrame(error)
    }
}

fn encode_message_type(kind: BulkFrameKind, method: BulkMethod) -> u8 {
    kind.to_wire() | method.to_wire()
}

fn decode_message_type(value: u8) -> Result<(BulkFrameKind, BulkMethod), BulkProtocolError> {
    let kind = BulkFrameKind::from_wire(value >> FRAME_KIND_SHIFT)?;
    let method = BulkMethod::from_wire(value & METHOD_MASK)?;
    Ok((kind, method))
}

fn encode_offer_body(frame: &BulkOfferFrame) -> Result<Vec<u8>, BulkProtocolError> {
    let metadata = encode_metadata(&frame.metadata);
    let metadata_len =
        u16::try_from(metadata.len()).map_err(|_| BulkProtocolError::MetadataTooLarge {
            len: metadata.len(),
        })?;
    let mut out = Vec::with_capacity(OFFER_FIXED_BODY_LEN + metadata.len());
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&frame.total_len.to_le_bytes());
    out.push(frame.mode.to_wire());
    out.push(frame.priority.to_wire());
    out.extend_from_slice(&metadata_len.to_le_bytes());
    out.extend_from_slice(&metadata);
    Ok(out)
}

fn decode_offer_body(body: &[u8]) -> Result<BulkOfferFrame, BulkProtocolError> {
    require_min_len("OFFER", body, OFFER_FIXED_BODY_LEN)?;
    let metadata_len = u16::from_le_bytes([body[14], body[15]]) as usize;
    let expected = OFFER_FIXED_BODY_LEN
        .checked_add(metadata_len)
        .ok_or(BulkProtocolError::BodyLengthOverflow { frame: "OFFER" })?;
    require_exact_len("OFFER", body, expected)?;

    Ok(BulkOfferFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        total_len: u64::from_le_bytes(body[4..12].try_into().unwrap()),
        mode: BulkMode::from_wire(body[12]).ok_or(BulkProtocolError::UnknownMode(body[12]))?,
        priority: BulkPriority::from_wire(body[13])
            .ok_or(BulkProtocolError::UnknownPriority(body[13]))?,
        metadata: decode_metadata(&body[OFFER_FIXED_BODY_LEN..])?,
    })
}

fn encode_accept_body(frame: &BulkAcceptFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(ACCEPT_BODY_LEN);
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.push(frame.result as u8);
    out.extend_from_slice(&frame.token.unwrap_or([0; 32]));
    out.extend_from_slice(&frame.max_chunk.to_le_bytes());
    out.extend_from_slice(&frame.retry_after_us.to_le_bytes());
    out
}

fn decode_accept_body(body: &[u8]) -> Result<BulkAcceptFrame, BulkProtocolError> {
    require_exact_len("ACCEPT", body, ACCEPT_BODY_LEN)?;
    let result = decode_accept_result(body[4])?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&body[5..37]);
    Ok(BulkAcceptFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        result,
        token: (result == BulkAcceptResult::Accepted).then_some(token),
        max_chunk: u32::from_le_bytes(body[37..41].try_into().unwrap()),
        retry_after_us: u32::from_le_bytes(body[41..45].try_into().unwrap()),
    })
}

fn encode_credit_request_body(frame: &BulkCreditRequestFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(CREDIT_REQUEST_BODY_LEN);
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&frame.token);
    out.extend_from_slice(&frame.chunk_seq.to_le_bytes());
    out.extend_from_slice(&frame.len.to_le_bytes());
    out
}

fn decode_credit_request_body(body: &[u8]) -> Result<BulkCreditRequestFrame, BulkProtocolError> {
    require_exact_len("CREDIT request", body, CREDIT_REQUEST_BODY_LEN)?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&body[4..36]);
    Ok(BulkCreditRequestFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        token,
        chunk_seq: u32::from_le_bytes(body[36..40].try_into().unwrap()),
        len: u32::from_le_bytes(body[40..44].try_into().unwrap()),
    })
}

fn encode_credit_grant_body(frame: &BulkCreditGrantFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(if frame.rdma.is_some() {
        CREDIT_GRANT_RDMA_BODY_LEN
    } else {
        CREDIT_GRANT_TCP_BODY_LEN
    });
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&frame.chunk_seq.to_le_bytes());
    out.push(frame.result.to_wire());
    out.extend_from_slice(&frame.offset.to_le_bytes());
    if let Some(rdma) = frame.rdma {
        out.extend_from_slice(&rdma.rkey.to_le_bytes());
        out.extend_from_slice(&rdma.addr.to_le_bytes());
    }
    out
}

fn decode_credit_grant_body(body: &[u8]) -> Result<BulkCreditGrantFrame, BulkProtocolError> {
    if body.len() != CREDIT_GRANT_TCP_BODY_LEN && body.len() != CREDIT_GRANT_RDMA_BODY_LEN {
        return Err(BulkProtocolError::BodyLengthMismatch {
            frame: "CREDIT grant",
            expected: CREDIT_GRANT_TCP_BODY_LEN,
            actual: body.len(),
        });
    }
    let rdma = (body.len() == CREDIT_GRANT_RDMA_BODY_LEN).then(|| BulkRdmaCredit {
        rkey: u32::from_le_bytes(body[17..21].try_into().unwrap()),
        addr: u64::from_le_bytes(body[21..29].try_into().unwrap()),
    });
    Ok(BulkCreditGrantFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        chunk_seq: u32::from_le_bytes(body[4..8].try_into().unwrap()),
        result: BulkCreditResult::from_wire(body[8])?,
        offset: u64::from_le_bytes(body[9..17].try_into().unwrap()),
        rdma,
    })
}

fn encode_done_body(frame: &BulkDoneFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(DONE_BODY_LEN);
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&frame.token);
    out.extend_from_slice(&frame.total_transferred.to_le_bytes());
    out.extend_from_slice(&frame.checksum32.to_le_bytes());
    out
}

fn decode_done_body(body: &[u8]) -> Result<BulkDoneFrame, BulkProtocolError> {
    require_exact_len("DONE", body, DONE_BODY_LEN)?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&body[4..36]);
    Ok(BulkDoneFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        token,
        total_transferred: u64::from_le_bytes(body[36..44].try_into().unwrap()),
        checksum32: u32::from_le_bytes(body[44..48].try_into().unwrap()),
    })
}

fn encode_abort_body(frame: &BulkAbortFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(ABORT_BODY_LEN);
    out.extend_from_slice(&frame.stream_id.to_le_bytes());
    out.extend_from_slice(&frame.token);
    out.push(frame.reason as u8);
    out
}

fn decode_abort_body(body: &[u8]) -> Result<BulkAbortFrame, BulkProtocolError> {
    require_exact_len("ABORT", body, ABORT_BODY_LEN)?;
    let mut token = [0u8; 32];
    token.copy_from_slice(&body[4..36]);
    Ok(BulkAbortFrame {
        stream_id: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        token,
        reason: decode_abort_reason(body[36])?,
    })
}

fn encode_metadata(metadata: &BulkMetadata) -> Vec<u8> {
    match metadata {
        BulkMetadata::VfsRpc {
            method,
            op_id,
            direction,
        } => {
            let mut out = Vec::with_capacity(VFS_RPC_BULK_METADATA_LEN);
            out.extend_from_slice(&VFS_RPC_BULK_METADATA_MAGIC);
            out.push(VFS_RPC_BULK_METADATA_VERSION);
            out.push(encode_vfs_rpc_method(*method));
            out.push(encode_vfs_rpc_direction(*direction));
            out.push(0);
            out.extend_from_slice(&op_id.to_le_bytes());
            out
        }
        BulkMetadata::Opaque(bytes) => bytes.clone(),
    }
}

fn decode_metadata(bytes: &[u8]) -> Result<BulkMetadata, BulkProtocolError> {
    if !bytes.starts_with(&VFS_RPC_BULK_METADATA_MAGIC) {
        return Ok(BulkMetadata::Opaque(bytes.to_vec()));
    }
    require_exact_len("VFS_RPC metadata", bytes, VFS_RPC_BULK_METADATA_LEN)?;
    if bytes[4] != VFS_RPC_BULK_METADATA_VERSION {
        return Err(BulkProtocolError::UnsupportedMetadataVersion(bytes[4]));
    }
    Ok(BulkMetadata::VfsRpc {
        method: decode_vfs_rpc_method(bytes[5])?,
        op_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        direction: decode_vfs_rpc_direction(bytes[6])?,
    })
}

fn decode_accept_result(value: u8) -> Result<BulkAcceptResult, BulkProtocolError> {
    match value {
        0 => Ok(BulkAcceptResult::Accepted),
        1 => Ok(BulkAcceptResult::NoCredits),
        2 => Ok(BulkAcceptResult::ModeUnsupported),
        3 => Ok(BulkAcceptResult::Rejected),
        other => Err(BulkProtocolError::UnknownAcceptResult(other)),
    }
}

fn decode_abort_reason(value: u8) -> Result<BulkAbortReason, BulkProtocolError> {
    match value {
        0 => Ok(BulkAbortReason::SenderCancel),
        1 => Ok(BulkAbortReason::ReceiverCancel),
        2 => Ok(BulkAbortReason::Timeout),
        3 => Ok(BulkAbortReason::ProtocolError),
        4 => Ok(BulkAbortReason::ConnectionLost),
        other => Err(BulkProtocolError::UnknownAbortReason(other)),
    }
}

const fn encode_vfs_rpc_method(method: VfsRpcBulkMethod) -> u8 {
    match method {
        VfsRpcBulkMethod::Write => 0,
        VfsRpcBulkMethod::Read => 1,
    }
}

fn decode_vfs_rpc_method(value: u8) -> Result<VfsRpcBulkMethod, BulkProtocolError> {
    match value {
        0 => Ok(VfsRpcBulkMethod::Write),
        1 => Ok(VfsRpcBulkMethod::Read),
        other => Err(BulkProtocolError::UnknownVfsRpcMethod(other)),
    }
}

const fn encode_vfs_rpc_direction(direction: BulkTransferDirection) -> u8 {
    match direction {
        BulkTransferDirection::WriteUpload => 0,
        BulkTransferDirection::ReadDownload => 1,
    }
}

fn decode_vfs_rpc_direction(value: u8) -> Result<BulkTransferDirection, BulkProtocolError> {
    match value {
        0 => Ok(BulkTransferDirection::WriteUpload),
        1 => Ok(BulkTransferDirection::ReadDownload),
        other => Err(BulkProtocolError::UnknownVfsRpcDirection(other)),
    }
}

fn require_min_len(frame: &'static str, body: &[u8], min: usize) -> Result<(), BulkProtocolError> {
    if body.len() < min {
        return Err(BulkProtocolError::BodyTooShort {
            frame,
            min,
            actual: body.len(),
        });
    }
    Ok(())
}

fn require_exact_len(
    frame: &'static str,
    body: &[u8],
    expected: usize,
) -> Result<(), BulkProtocolError> {
    if body.len() != expected {
        return Err(BulkProtocolError::BodyLengthMismatch {
            frame,
            expected,
            actual: body.len(),
        });
    }
    Ok(())
}

fn ensure_tcp_chunk_len(len: usize) -> Result<(), BulkProtocolError> {
    if len > u32::MAX as usize {
        return Err(BulkProtocolError::TcpChunkTooLarge { len });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BulkService, BulkServiceConfig, RdmaEvidence};

    fn token(byte: u8) -> BulkToken {
        [byte; 32]
    }

    #[test]
    fn offer_frame_roundtrips_through_data_service_transport_frame() {
        let offer = BulkOfferFrame {
            stream_id: 7,
            total_len: 4096,
            mode: BulkMode::TcpStream,
            priority: BulkPriority::Bulk,
            metadata: BulkMetadata::vfs_rpc_write_upload(99),
        };
        let frame = BulkFrame::Offer(offer);
        let data_frame = frame.to_data_service_frame().expect("data frame");

        assert_eq!(data_frame.service_id, BULK_SERVICE_ID);
        assert_eq!(
            data_frame.message_type,
            encode_message_type(BulkFrameKind::Request, BulkMethod::Offer)
        );

        let wire = frame.encode_for_transport().expect("wire");
        let decoded = BulkFrame::decode_from_transport(&wire).expect("decode");
        assert_eq!(decoded, frame);
    }

    #[test]
    fn accept_credit_done_and_abort_frames_roundtrip() {
        let frames = [
            BulkFrame::Accept(BulkAcceptFrame {
                stream_id: 11,
                result: BulkAcceptResult::Accepted,
                token: Some(token(0x11)),
                max_chunk: 8192,
                retry_after_us: 0,
            }),
            BulkFrame::CreditRequest(BulkCreditRequestFrame {
                stream_id: 11,
                token: token(0x11),
                chunk_seq: 2,
                len: 1024,
            }),
            BulkFrame::CreditGrant(BulkCreditGrantFrame {
                stream_id: 11,
                chunk_seq: 2,
                result: BulkCreditResult::Granted,
                offset: 2048,
                rdma: None,
            }),
            BulkFrame::Done(BulkDoneFrame {
                stream_id: 11,
                token: token(0x11),
                total_transferred: 3072,
                checksum32: 0x1234_5678,
            }),
            BulkFrame::Abort(BulkAbortFrame {
                stream_id: 12,
                token: token(0x12),
                reason: BulkAbortReason::Timeout,
            }),
        ];

        for frame in frames {
            let wire = frame.encode_for_transport().expect("wire");
            let decoded = BulkFrame::decode_from_transport(&wire).expect("decode");
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn tcp_chunk_frame_roundtrips_and_checksums_payload() {
        let chunk = BulkTcpChunkFrame::new(11, token(0x11), 2, 8192, b"chunk payload".to_vec())
            .expect("chunk");
        let wire = chunk.encode().expect("wire");
        let decoded = BulkTcpChunkFrame::decode(&wire).expect("decode");

        assert_eq!(decoded, chunk);

        let mut corrupted = wire;
        *corrupted.last_mut().unwrap() ^= 0xff;
        let actual = crc32c::crc32c(&corrupted[TCP_CHUNK_HEADER_LEN..]);
        assert_eq!(
            BulkTcpChunkFrame::decode(&corrupted),
            Err(BulkProtocolError::TcpChunkChecksumMismatch {
                expected: chunk.checksum32,
                actual,
            })
        );
    }

    #[test]
    fn wrong_service_id_is_rejected_before_bulk_body_decode() {
        let frame = DataServiceFrame::new(
            0x08,
            encode_message_type(BulkFrameKind::Request, BulkMethod::Offer),
            vec![],
        );

        assert_eq!(
            BulkFrame::from_data_service_frame(frame).unwrap_err(),
            BulkProtocolError::WrongServiceId {
                expected: BULK_SERVICE_ID,
                actual: 0x08,
            }
        );
    }

    #[test]
    fn rdma_offer_decodes_but_service_rejects_without_evidence() {
        let offer = BulkOfferFrame {
            stream_id: 14,
            total_len: 8,
            mode: BulkMode::RdmaWrite,
            priority: BulkPriority::Bulk,
            metadata: BulkMetadata::Opaque(b"rdma-request".to_vec()),
        };
        let wire = BulkFrame::Offer(offer.clone())
            .encode_for_transport()
            .expect("wire");
        let decoded = BulkFrame::decode_from_transport(&wire).expect("decode");
        assert_eq!(decoded, BulkFrame::Offer(offer.clone()));

        let mut service = BulkService::new(BulkServiceConfig {
            rdma_evidence: RdmaEvidence {
                transport_peer_security: true,
                pinned_memory_accounting: true,
                rkey_addr_credit_lifecycle: true,
                abort_cleanup: true,
                runtime_validation: false,
            },
            ..BulkServiceConfig::default()
        });
        let accept = service.offer(offer.into_offer(7));
        assert_eq!(accept.result, BulkAcceptResult::ModeUnsupported);
    }

    #[test]
    fn malformed_vfs_rpc_metadata_fails_closed() {
        let mut body = Vec::new();
        body.extend_from_slice(&VFS_RPC_BULK_METADATA_MAGIC);
        body.push(2);
        body.extend_from_slice(&[0; 11]);

        assert_eq!(
            decode_metadata(&body).unwrap_err(),
            BulkProtocolError::UnsupportedMetadataVersion(2)
        );
    }

    #[test]
    fn vfs_rpc_metadata_ignores_reserved_extension_byte() {
        let metadata = BulkMetadata::vfs_rpc_write_upload(123);
        let mut encoded = encode_metadata(&metadata);
        encoded[7] = 0x7f;

        assert_eq!(decode_metadata(&encoded).expect("decode"), metadata);
    }
}
