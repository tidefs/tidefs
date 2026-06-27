// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(unused_imports)]

//! VFSSEND2 dataset send-stream protocol framing.
//!
//! This crate defines the VFSSEND2 wire format (stream header, record
//! types, chunk framing, checkpoint cursors, feature negotiation) with
//! [`SendBuilder`] and [`ReceiveBuilder`] entry points. VFSSEND2 is the
//! intended canonical send/receive format for multi-node state transfer.
//!
//! **Current integration status:** VFSSEND2 is validated through the
//! deterministic two-node harness (`tidefs-two-node-harness`) and the
//! chunk-shipper/receive-stream pipeline. **Transport binding** is
//! provided by [`send_stream_adapter`] (behind the `transport` feature):
//! [`SendStreamTransportWriter`] bridges VFSSEND2 to `SendPipelineHandle`
//! using `MessageFamily::StateTransfer` / `SessionClass::TransferBulk`.
//! The live storage-node daemon (`tidefs-storage-node`) does **not** yet
//! use this crate; its `Frame::Send` / `Frame::Receive` handlers currently
//! encode and decode the older `ChangedRecordExport` format (VFSSEND1,
//! defined in `tidefs-local-filesystem`). Wiring the storage-node daemon
//! to VFSSEND2 is governed by the distributed snapshot shipping design (issue #1250). Follow-up implementation
//! issues in the #1250 follow-up map own the per-component wiring (storage-node send path, receive path, session lifecycle). The send-stream session adapter remains the canonical network delivery path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tidefs_types_dataset_feature_flags_core::FeatureName;

pub mod chunk_encoder;
pub mod dispatch;
pub mod encoder;
pub mod framer;
pub mod object_chunk_framer;
pub mod send_queue;
pub mod send_stream_writer;
pub mod send_transport_bridge;
pub mod transport;

pub use object_chunk_framer::{ChunkPacket, FrameError, ObjectChunkFramer};
pub use send_queue::SendQueue;
#[cfg(feature = "transport")]
pub use send_transport_bridge::ConnectionTransport;
pub use send_transport_bridge::{SendTransport, SendTransportBridge, SendTransportError};
#[cfg(feature = "transport")]
pub mod send_stream_adapter;
#[cfg(feature = "transport")]
pub use send_stream_adapter::{
    SendStreamAdapterError, SendStreamSession, SendStreamSessionConfig, SendStreamTransportReader,
    SendStreamTransportWriter,
};
/// VFSSEND2 magic bytes.
pub const STREAM_MAGIC: [u8; 8] = *b"VFSSEND2";

/// Canonical stream format version for this crate.
pub const STREAM_VERSION: u16 = 3;

/// Default checkpoint interval used by [`SendStreamHeader::new`].
pub const DEFAULT_CHECKPOINT_INTERVAL_RECORDS: u32 = 1_000;

/// Default maximum object-write payload length.
pub const DEFAULT_MAX_RECORD_PAYLOAD: u32 = 1024 * 1024;

const STREAM_DIGEST_CONTEXT: &str = "TideFS VFSSEND2 stream digest v1";
const RECORD_DIGEST_CONTEXT: &str = "TideFS VFSSEND2 record payload digest v1";
const CURSOR_DIGEST_CONTEXT: &str = "TideFS VFSSEND2 cursor digest v1";
const LINEAGE_ROOT_DIGEST_CONTEXT: &str = "TideFS VFSSEND2 lineage root digest v1";
const LINEAGE_MANIFEST_DIGEST_CONTEXT: &str = "TideFS VFSSEND2 lineage manifest digest v1";
const LINEAGE_MANIFEST_BASE_PRESENT: u16 = 1 << 0;
const SENDER_AUTHORITY_EXTENSION_MAGIC: [u8; 8] = *b"VFSAUTH\0";
const SENDER_AUTHORITY_EXTENSION_VERSION: u16 = 1;

const HEADER_FIXED_LEN: usize = 8 + 2 + 2 + 16 + 16 + 16 + 16 + 8 + 8 + 8 + 4 + 4 + 4;
const RECORD_HEADER_LEN: usize = 2 + 2 + 4 + 8 + 32;
const NEGOTIATION_MAGIC: [u8; 8] = *b"VFNEG2\0\0";
const NEGOTIATION_WIRE_VERSION: u16 = 1;
const NEGOTIATION_REQUEST_KIND: u8 = 1;
const NEGOTIATION_REPLY_KIND: u8 = 2;

/// Stable 128-bit id used for pools, datasets, snapshots, clusters, and streams.
pub type Id128 = [u8; 16];

/// Stable 256-bit object id and BLAKE3 digest.
pub type Bytes32 = [u8; 32];

/// Sender-pool authority carried by distributed VFSSEND2 streams.
///
/// This is identity evidence, not an authentication secret or operator
/// authorization token. Receive authorization is a separate local-filesystem
/// policy gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderAuthority {
    pub sender_pool_uuid: Id128,
    pub sender_pool_epoch: u64,
    pub sender_membership_generation: u64,
}

impl SenderAuthority {
    /// Construct validated sender authority evidence.
    pub fn new(
        sender_pool_uuid: Id128,
        sender_pool_epoch: u64,
        sender_membership_generation: u64,
    ) -> Result<Self, SendStreamError> {
        let authority = Self {
            sender_pool_uuid,
            sender_pool_epoch,
            sender_membership_generation,
        };
        authority.validate()?;
        Ok(authority)
    }

    fn validate(self) -> Result<(), SendStreamError> {
        if self.sender_pool_uuid == [0; 16] {
            return Err(SendStreamError::InvalidHeader(
                "sender authority pool uuid must be non-zero",
            ));
        }
        if self.sender_pool_epoch == 0 {
            return Err(SendStreamError::InvalidHeader(
                "sender authority pool epoch must be non-zero",
            ));
        }
        if self.sender_membership_generation == 0 {
            return Err(SendStreamError::InvalidHeader(
                "sender authority membership generation must be non-zero",
            ));
        }
        Ok(())
    }
}

/// Sender authority state decoded from a stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SenderAuthorityEvidence {
    /// No sender-authority block is present; the stream is local-only until a
    /// caller supplies an explicit distributed authority surface.
    AbsentLocalOnly,
    /// A distributed stream authority block is present.
    Distributed(SenderAuthority),
}

impl SenderAuthorityEvidence {
    #[must_use]
    pub const fn is_absent_local_only(self) -> bool {
        matches!(self, Self::AbsentLocalOnly)
    }

    #[must_use]
    pub const fn distributed(self) -> Option<SenderAuthority> {
        match self {
            Self::AbsentLocalOnly => None,
            Self::Distributed(authority) => Some(authority),
        }
    }
}

/// Stream flags from the VFSSEND2 header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamFlags(u16);

impl StreamFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Stream is an incremental delta from one snapshot to another.
    pub const INCREMENTAL: Self = Self(1 << 0);
    /// Stream can be resumed from checkpoint cursors.
    pub const RESUMABLE: Self = Self(1 << 1);
    /// Stream was prepared for cross-cluster transport.
    pub const CROSS_CLUSTER: Self = Self(1 << 2);
    /// Stream carries sender-managed property records.
    pub const EMBEDDED_PROPERTIES: Self = Self(1 << 3);

    /// Return the raw bit mask.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Construct from raw bits, rejecting reserved bits.
    pub const fn from_bits(bits: u16) -> Result<Self, SendStreamError> {
        if bits & !0x000f != 0 {
            return Err(SendStreamError::ReservedFlagBits { bits });
        }
        Ok(Self(bits))
    }

    /// Return true when all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Return a new flag set with `other` enabled.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Record flags stored in the VFSSEND2 record prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordFlags(u16);

impl RecordFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Object write is the final chunk for the object.
    pub const LAST_CHUNK: Self = Self(1 << 0);
    /// This record is a useful checkpoint boundary.
    pub const CHECKPOINT_CANDIDATE: Self = Self(1 << 1);

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn from_bits(bits: u16) -> Result<Self, SendStreamError> {
        if bits & !0x0003 != 0 {
            return Err(SendStreamError::ReservedFlagBits { bits });
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// VFSSEND2 stream header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendStreamHeader {
    pub source_pool_id: Id128,
    pub source_dataset_id: Id128,
    pub from_snapshot_id: Id128,
    pub to_snapshot_id: Id128,
    pub sender_authority: SenderAuthorityEvidence,
    pub flags: StreamFlags,
    pub features_compat: u64,
    pub features_ro_compat: u64,
    pub features_incompat: u64,
    pub checkpoint_interval_records: u32,
    pub max_record_payload: u32,
    pub header_extension: Vec<u8>,
}

impl SendStreamHeader {
    /// Build a header with resumable stream defaults.
    #[must_use]
    pub fn new(source_pool_id: Id128, source_dataset_id: Id128, to_snapshot_id: Id128) -> Self {
        Self {
            source_pool_id,
            source_dataset_id,
            from_snapshot_id: [0; 16],
            to_snapshot_id,
            sender_authority: SenderAuthorityEvidence::AbsentLocalOnly,
            flags: StreamFlags::RESUMABLE,
            features_compat: 0,
            features_ro_compat: 0,
            features_incompat: 0,
            checkpoint_interval_records: DEFAULT_CHECKPOINT_INTERVAL_RECORDS,
            max_record_payload: DEFAULT_MAX_RECORD_PAYLOAD,
            header_extension: Vec::new(),
        }
    }

    /// Mark the header as an incremental stream from `from_snapshot_id`.
    #[must_use]
    pub fn incremental_from(mut self, from_snapshot_id: Id128) -> Self {
        self.from_snapshot_id = from_snapshot_id;
        self.flags = self.flags.with(StreamFlags::INCREMENTAL);
        self
    }

    /// Attach validated sender authority evidence to the header.
    #[must_use]
    pub fn with_sender_authority(mut self, authority: SenderAuthority) -> Self {
        self.sender_authority = SenderAuthorityEvidence::Distributed(authority);
        self
    }

    /// Encode the header in canonical little-endian form.
    pub fn encode(&self) -> Result<Vec<u8>, SendStreamError> {
        if self.checkpoint_interval_records == 0 {
            return Err(SendStreamError::InvalidHeader(
                "checkpoint interval must be non-zero",
            ));
        }
        if self.max_record_payload == 0 {
            return Err(SendStreamError::InvalidHeader(
                "max record payload must be non-zero",
            ));
        }
        let header_extension = encode_header_extension(self)?;
        let ext_len = u32::try_from(header_extension.len())
            .map_err(|_| SendStreamError::LengthOverflow("header extension"))?;
        let mut out = Vec::with_capacity(HEADER_FIXED_LEN + header_extension.len());
        out.extend_from_slice(&STREAM_MAGIC);
        push_u16(&mut out, STREAM_VERSION);
        push_u16(&mut out, self.flags.bits());
        out.extend_from_slice(&self.source_pool_id);
        out.extend_from_slice(&self.source_dataset_id);
        out.extend_from_slice(&self.from_snapshot_id);
        out.extend_from_slice(&self.to_snapshot_id);
        push_u64(&mut out, self.features_compat);
        push_u64(&mut out, self.features_ro_compat);
        push_u64(&mut out, self.features_incompat);
        push_u32(&mut out, self.checkpoint_interval_records);
        push_u32(&mut out, self.max_record_payload);
        push_u32(&mut out, ext_len);
        out.extend_from_slice(&header_extension);
        Ok(out)
    }

    /// Decode a canonical header and return the remaining stream bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8]), SendStreamError> {
        let mut decoder = Decoder::new(bytes);
        decoder.expect_magic(&STREAM_MAGIC)?;
        let version = decoder.read_u16()?;
        if version != STREAM_VERSION {
            return Err(SendStreamError::UnsupportedVersion(version));
        }
        let flags = StreamFlags::from_bits(decoder.read_u16()?)?;
        let source_pool_id = decoder.read_id128()?;
        let source_dataset_id = decoder.read_id128()?;
        let from_snapshot_id = decoder.read_id128()?;
        let to_snapshot_id = decoder.read_id128()?;
        let features_compat = decoder.read_u64()?;
        let features_ro_compat = decoder.read_u64()?;
        let features_incompat = decoder.read_u64()?;
        let checkpoint_interval_records = decoder.read_u32()?;
        let max_record_payload = decoder.read_u32()?;
        let ext_len = decoder.read_len_u32()?;
        let raw_header_extension = decoder.read_bytes(ext_len)?;
        let (sender_authority, header_extension) = decode_header_extension(raw_header_extension)?;
        if checkpoint_interval_records == 0 {
            return Err(SendStreamError::InvalidHeader(
                "checkpoint interval must be non-zero",
            ));
        }
        if max_record_payload == 0 {
            return Err(SendStreamError::InvalidHeader(
                "max record payload must be non-zero",
            ));
        }
        Ok((
            Self {
                source_pool_id,
                source_dataset_id,
                from_snapshot_id,
                to_snapshot_id,
                sender_authority,
                flags,
                features_compat,
                features_ro_compat,
                features_incompat,
                checkpoint_interval_records,
                max_record_payload,
                header_extension,
            },
            decoder.remaining(),
        ))
    }
}

/// VFSSEND2 record types.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u16)]
pub enum SendRecordType {
    SnapshotBegin = 0x0001,
    ObjectBegin = 0x0002,
    ObjectWrite = 0x0003,
    ObjectTruncate = 0x0004,
    ObjectSetAttr = 0x0005,
    DirEntryAdd = 0x0006,
    DirEntryRemove = 0x0007,
    ObjectEnd = 0x0008,
    SnapshotEnd = 0x0009,
    ResumeMarker = 0x000a,
    StreamEnd = 0x000b,
    LineageManifest = 0x000c,
    SnapshotMutation = 0x000d,
}

impl TryFrom<u16> for SendRecordType {
    type Error = SendStreamError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::SnapshotBegin),
            0x0002 => Ok(Self::ObjectBegin),
            0x0003 => Ok(Self::ObjectWrite),
            0x0004 => Ok(Self::ObjectTruncate),
            0x0005 => Ok(Self::ObjectSetAttr),
            0x0006 => Ok(Self::DirEntryAdd),
            0x0007 => Ok(Self::DirEntryRemove),
            0x0008 => Ok(Self::ObjectEnd),
            0x0009 => Ok(Self::SnapshotEnd),
            0x000a => Ok(Self::ResumeMarker),
            0x000b => Ok(Self::StreamEnd),
            0x000c => Ok(Self::LineageManifest),
            0x000d => Ok(Self::SnapshotMutation),
            other => Err(SendStreamError::UnknownRecordType(other)),
        }
    }
}

/// Logical object kind carried by `ObjectBegin`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum ObjectKind {
    Inode = 0,
    Directory = 1,
    Extent = 2,
    Xattr = 3,
    SnapshotCatalog = 4,
    DatasetProperty = 5,
}

impl TryFrom<u8> for ObjectKind {
    type Error = SendStreamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Inode),
            1 => Ok(Self::Directory),
            2 => Ok(Self::Extent),
            3 => Ok(Self::Xattr),
            4 => Ok(Self::SnapshotCatalog),
            5 => Ok(Self::DatasetProperty),
            other => Err(SendStreamError::UnknownObjectKind(other)),
        }
    }
}

/// One decoded stream record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRecord {
    pub flags: RecordFlags,
    pub payload: SendRecordPayload,
}

impl SendRecord {
    #[must_use]
    pub const fn record_type(&self) -> SendRecordType {
        self.payload.record_type()
    }

    #[must_use]
    pub fn new(payload: SendRecordPayload) -> Self {
        Self {
            flags: RecordFlags::NONE,
            payload,
        }
    }

    #[must_use]
    pub fn with_flags(mut self, flags: RecordFlags) -> Self {
        self.flags = flags;
        self
    }
}

/// Record payload variants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendRecordPayload {
    LineageManifest(LineageManifest),
    SnapshotBegin(SnapshotBoundary),
    ObjectBegin(ObjectBegin),
    ObjectWrite(ObjectWrite),
    ObjectTruncate(ObjectTruncate),
    ObjectSetAttr(ObjectSetAttr),
    DirEntryAdd(DirEntryAdd),
    DirEntryRemove(DirEntryRemove),
    ObjectEnd(ObjectEnd),
    SnapshotEnd(SnapshotBoundary),
    ResumeMarker(ResumeMarker),
    StreamEnd(StreamEnd),
    SnapshotMutation(SnapshotMutation),
}

impl SendRecordPayload {
    #[must_use]
    pub const fn record_type(&self) -> SendRecordType {
        match self {
            Self::LineageManifest(_) => SendRecordType::LineageManifest,
            Self::SnapshotBegin(_) => SendRecordType::SnapshotBegin,
            Self::ObjectBegin(_) => SendRecordType::ObjectBegin,
            Self::ObjectWrite(_) => SendRecordType::ObjectWrite,
            Self::ObjectTruncate(_) => SendRecordType::ObjectTruncate,
            Self::ObjectSetAttr(_) => SendRecordType::ObjectSetAttr,
            Self::DirEntryAdd(_) => SendRecordType::DirEntryAdd,
            Self::DirEntryRemove(_) => SendRecordType::DirEntryRemove,
            Self::ObjectEnd(_) => SendRecordType::ObjectEnd,
            Self::SnapshotEnd(_) => SendRecordType::SnapshotEnd,
            Self::ResumeMarker(_) => SendRecordType::ResumeMarker,
            Self::StreamEnd(_) => SendRecordType::StreamEnd,
            Self::SnapshotMutation(_) => SendRecordType::SnapshotMutation,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, SendStreamError> {
        let mut out = Vec::new();
        match self {
            Self::LineageManifest(payload) => payload.encode_into(&mut out),
            Self::SnapshotBegin(boundary) | Self::SnapshotEnd(boundary) => {
                boundary.encode_into(&mut out)?;
            }
            Self::ObjectBegin(payload) => payload.encode_into(&mut out)?,
            Self::ObjectWrite(payload) => payload.encode_into(&mut out)?,
            Self::ObjectTruncate(payload) => payload.encode_into(&mut out),
            Self::ObjectSetAttr(payload) => payload.encode_into(&mut out)?,
            Self::DirEntryAdd(payload) => payload.encode_into(&mut out)?,
            Self::DirEntryRemove(payload) => payload.encode_into(&mut out)?,
            Self::ObjectEnd(payload) => payload.encode_into(&mut out),
            Self::ResumeMarker(payload) => payload.encode_into(&mut out),
            Self::StreamEnd(payload) => payload.encode_into(&mut out),
            Self::SnapshotMutation(payload) => payload.encode_into(&mut out)?,
        }
        Ok(out)
    }

    fn decode(record_type: SendRecordType, payload: &[u8]) -> Result<Self, SendStreamError> {
        let mut decoder = Decoder::new(payload);
        let decoded = match record_type {
            SendRecordType::LineageManifest => {
                Self::LineageManifest(LineageManifest::decode(&mut decoder)?)
            }
            SendRecordType::SnapshotBegin => {
                Self::SnapshotBegin(SnapshotBoundary::decode(&mut decoder)?)
            }
            SendRecordType::ObjectBegin => Self::ObjectBegin(ObjectBegin::decode(&mut decoder)?),
            SendRecordType::ObjectWrite => Self::ObjectWrite(ObjectWrite::decode(&mut decoder)?),
            SendRecordType::ObjectTruncate => {
                Self::ObjectTruncate(ObjectTruncate::decode(&mut decoder)?)
            }
            SendRecordType::ObjectSetAttr => {
                Self::ObjectSetAttr(ObjectSetAttr::decode(&mut decoder)?)
            }
            SendRecordType::DirEntryAdd => Self::DirEntryAdd(DirEntryAdd::decode(&mut decoder)?),
            SendRecordType::DirEntryRemove => {
                Self::DirEntryRemove(DirEntryRemove::decode(&mut decoder)?)
            }
            SendRecordType::ObjectEnd => Self::ObjectEnd(ObjectEnd::decode(&mut decoder)?),
            SendRecordType::SnapshotEnd => {
                Self::SnapshotEnd(SnapshotBoundary::decode(&mut decoder)?)
            }
            SendRecordType::ResumeMarker => Self::ResumeMarker(ResumeMarker::decode(&mut decoder)?),
            SendRecordType::StreamEnd => Self::StreamEnd(StreamEnd::decode(&mut decoder)?),
            SendRecordType::SnapshotMutation => {
                Self::SnapshotMutation(SnapshotMutation::decode(&mut decoder)?)
            }
        };
        decoder.finish()?;
        Ok(decoded)
    }
}

/// First record in every send stream, binding stream lineage before object data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineageManifest {
    pub source_pool_id: Id128,
    pub source_dataset_id: Id128,
    pub base_root_id: Option<Id128>,
    pub target_root_id: Id128,
    pub stream_format_version: u16,
    pub base_root_digest: Option<Bytes32>,
    pub target_root_digest: Bytes32,
}

impl LineageManifest {
    #[must_use]
    pub fn full(header: &SendStreamHeader, target_root_digest: Bytes32) -> Self {
        Self {
            source_pool_id: header.source_pool_id,
            source_dataset_id: header.source_dataset_id,
            base_root_id: None,
            target_root_id: header.to_snapshot_id,
            stream_format_version: STREAM_VERSION,
            base_root_digest: None,
            target_root_digest,
        }
    }

    #[must_use]
    pub fn incremental(
        header: &SendStreamHeader,
        base_root: &PinnedBaseRoot,
        target_root_digest: Bytes32,
    ) -> Self {
        Self {
            source_pool_id: header.source_pool_id,
            source_dataset_id: header.source_dataset_id,
            base_root_id: Some(base_root.root_id),
            target_root_id: header.to_snapshot_id,
            stream_format_version: STREAM_VERSION,
            base_root_digest: Some(base_root.root_digest),
            target_root_digest,
        }
    }

    #[must_use]
    pub fn declares_full_send(&self) -> bool {
        self.base_root_id.is_none() && self.base_root_digest.is_none()
    }

    #[must_use]
    pub fn declares_incremental_send(&self) -> bool {
        self.base_root_id.is_some() && self.base_root_digest.is_some()
    }

    /// Encode the manifest payload in canonical little-endian field order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(132);
        self.encode_into(&mut out);
        out
    }

    #[must_use]
    pub fn digest(&self) -> Bytes32 {
        let encoded = self.encode();
        let mut hasher = blake3::Hasher::new_derive_key(LINEAGE_MANIFEST_DIGEST_CONTEXT);
        hasher.update(&encoded);
        *hasher.finalize().as_bytes()
    }

    pub fn decode_payload(bytes: &[u8]) -> Result<Self, SendStreamError> {
        let mut decoder = Decoder::new(bytes);
        let manifest = Self::decode(&mut decoder)?;
        decoder.finish()?;
        Ok(manifest)
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        let base_present = self.base_root_id.is_some() || self.base_root_digest.is_some();
        let base_root_id = self.base_root_id.unwrap_or([0; 16]);
        let base_root_digest = self.base_root_digest.unwrap_or([0; 32]);
        out.extend_from_slice(&self.source_pool_id);
        out.extend_from_slice(&self.source_dataset_id);
        out.extend_from_slice(&base_root_id);
        out.extend_from_slice(&self.target_root_id);
        push_u16(out, self.stream_format_version);
        push_u16(
            out,
            if base_present {
                LINEAGE_MANIFEST_BASE_PRESENT
            } else {
                0
            },
        );
        out.extend_from_slice(&base_root_digest);
        out.extend_from_slice(&self.target_root_digest);
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        let source_pool_id = decoder.read_id128()?;
        let source_dataset_id = decoder.read_id128()?;
        let raw_base_root_id = decoder.read_id128()?;
        let target_root_id = decoder.read_id128()?;
        let stream_format_version = decoder.read_u16()?;
        let flags = decoder.read_u16()?;
        if flags & !LINEAGE_MANIFEST_BASE_PRESENT != 0 {
            return Err(SendStreamError::ReservedFlagBits { bits: flags });
        }
        let raw_base_root_digest = decoder.read_bytes32()?;
        let target_root_digest = decoder.read_bytes32()?;
        let base_present = flags & LINEAGE_MANIFEST_BASE_PRESENT != 0;
        if base_present && raw_base_root_id == [0; 16] {
            return Err(SendStreamError::LineageManifestMismatch(
                "base root id is absent",
            ));
        }
        if base_present && raw_base_root_digest == [0; 32] {
            return Err(SendStreamError::LineageManifestMismatch(
                "base root digest is absent",
            ));
        }
        if !base_present && (raw_base_root_id != [0; 16] || raw_base_root_digest != [0; 32]) {
            return Err(SendStreamError::LineageManifestMismatch(
                "base root fields set without base flag",
            ));
        }
        Ok(Self {
            source_pool_id,
            source_dataset_id,
            base_root_id: base_present.then_some(raw_base_root_id),
            target_root_id,
            stream_format_version,
            base_root_digest: base_present.then_some(raw_base_root_digest),
            target_root_digest,
        })
    }

    fn validate_for_header(&self, header: &SendStreamHeader) -> Result<(), SendStreamError> {
        if self.source_pool_id != header.source_pool_id {
            return Err(SendStreamError::LineageManifestMismatch(
                "source pool does not match header",
            ));
        }
        if self.source_dataset_id != header.source_dataset_id {
            return Err(SendStreamError::LineageManifestMismatch(
                "source dataset does not match header",
            ));
        }
        if self.target_root_id != header.to_snapshot_id {
            return Err(SendStreamError::LineageManifestMismatch(
                "target root does not match header",
            ));
        }
        if self.stream_format_version != STREAM_VERSION {
            return Err(SendStreamError::UnsupportedVersion(
                self.stream_format_version,
            ));
        }
        let incremental = header.flags.contains(StreamFlags::INCREMENTAL);
        if !incremental && header.from_snapshot_id != [0; 16] {
            return Err(SendStreamError::InvalidHeader(
                "full send must not name an incremental base root",
            ));
        }
        match (incremental, self.base_root_id, self.base_root_digest) {
            (false, None, None) => Ok(()),
            (true, Some(base_root_id), Some(_)) if base_root_id == header.from_snapshot_id => {
                Ok(())
            }
            (true, _, _) => Err(SendStreamError::LineageManifestMismatch(
                "incremental manifest base root does not match header",
            )),
            (false, _, _) => Err(SendStreamError::LineageManifestMismatch(
                "full send manifest must not declare a base root",
            )),
        }
    }
}

/// Base-root evidence accepted by the send side before incremental planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedBaseRoot {
    pub source_dataset_id: Id128,
    pub root_id: Id128,
    pub root_digest: Bytes32,
    pub object_digests: BTreeMap<Bytes32, Bytes32>,
    pub pinned: bool,
}

impl PinnedBaseRoot {
    #[must_use]
    pub fn new(
        source_dataset_id: Id128,
        root_id: Id128,
        root_digest: Bytes32,
        object_digests: BTreeMap<Bytes32, Bytes32>,
        pinned: bool,
    ) -> Self {
        Self {
            source_dataset_id,
            root_id,
            root_digest,
            object_digests,
            pinned,
        }
    }

    pub fn pinned_from_objects(
        source_dataset_id: Id128,
        root_id: Id128,
        object_digests: BTreeMap<Bytes32, Bytes32>,
    ) -> Result<Self, SendStreamError> {
        if root_id == [0; 16] || object_digests.is_empty() {
            return Err(SendStreamError::MissingBaseRoot);
        }
        let root_digest =
            root_digest_from_object_digests(source_dataset_id, root_id, &object_digests);
        Ok(Self::new(
            source_dataset_id,
            root_id,
            root_digest,
            object_digests,
            true,
        ))
    }

    fn validate_for_header(&self, header: &SendStreamHeader) -> Result<(), SendStreamError> {
        if header.from_snapshot_id == [0; 16] {
            return Err(SendStreamError::MissingBaseRoot);
        }
        if !self.pinned {
            return Err(SendStreamError::UnpinnedBaseRoot {
                root_id: self.root_id,
            });
        }
        if self.source_dataset_id != header.source_dataset_id {
            return Err(SendStreamError::BaseRootDatasetMismatch {
                expected: header.source_dataset_id,
                actual: self.source_dataset_id,
            });
        }
        if self.root_id != header.from_snapshot_id {
            return Err(SendStreamError::BaseRootMismatch {
                expected: header.from_snapshot_id,
                actual: self.root_id,
            });
        }
        Ok(())
    }
}

/// Snapshot boundary payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotBoundary {
    pub snapshot_id: Id128,
    pub commit_group: u64,
    pub name: Vec<u8>,
}

impl SnapshotBoundary {
    #[must_use]
    pub fn new(snapshot_id: Id128, commit_group: u64, name: impl Into<Vec<u8>>) -> Self {
        Self {
            snapshot_id,
            commit_group,
            name: name.into(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.extend_from_slice(&self.snapshot_id);
        push_u64(out, self.commit_group);
        push_bytes_u16(out, &self.name, "snapshot name")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            snapshot_id: decoder.read_id128()?,
            commit_group: decoder.read_u64()?,
            name: decoder.read_len_prefixed_u16()?.to_vec(),
        })
    }
}

/// Snapshot-record mutation carried by a [`SnapshotDelta`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum SnapshotMutationKind {
    Promote = 1,
    Delete = 2,
}

impl TryFrom<u8> for SnapshotMutationKind {
    type Error = SendStreamError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Promote),
            2 => Ok(Self::Delete),
            other => Err(SendStreamError::UnknownSnapshotMutationKind(other)),
        }
    }
}

/// Snapshot lifecycle mutation with the affected traversal-root identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotMutation {
    pub kind: SnapshotMutationKind,
    pub root_id: Id128,
    pub snapshot_name: Vec<u8>,
}

impl SnapshotMutation {
    #[must_use]
    pub fn promote(root_id: Id128, snapshot_name: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: SnapshotMutationKind::Promote,
            root_id,
            snapshot_name: snapshot_name.into(),
        }
    }

    #[must_use]
    pub fn delete(root_id: Id128, snapshot_name: impl Into<Vec<u8>>) -> Self {
        Self {
            kind: SnapshotMutationKind::Delete,
            root_id,
            snapshot_name: snapshot_name.into(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.push(self.kind as u8);
        out.extend_from_slice(&self.root_id);
        push_bytes_u16(out, &self.snapshot_name, "snapshot mutation name")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            kind: SnapshotMutationKind::try_from(decoder.read_u8()?)?,
            root_id: decoder.read_id128()?,
            snapshot_name: decoder.read_len_prefixed_u16()?.to_vec(),
        })
    }
}

/// Begin-object payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectBegin {
    pub object_id: Bytes32,
    pub kind: ObjectKind,
    pub total_len: u64,
    pub birth_commit_group: u64,
    pub object_digest: Bytes32,
    pub parent_object_id: Bytes32,
    pub object_flags: u32,
    pub metadata: Vec<u8>,
}

impl ObjectBegin {
    #[must_use]
    pub fn new(object_id: Bytes32, kind: ObjectKind, payload: &[u8]) -> Self {
        Self {
            object_id,
            kind,
            total_len: payload.len() as u64,
            birth_commit_group: 0,
            object_digest: blake3_digest(payload),
            parent_object_id: [0; 32],
            object_flags: 0,
            metadata: Vec::new(),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.push(self.kind as u8);
        out.extend_from_slice(&self.object_id);
        push_u64(out, self.total_len);
        push_u64(out, self.birth_commit_group);
        out.extend_from_slice(&self.object_digest);
        out.extend_from_slice(&self.parent_object_id);
        push_u32(out, self.object_flags);
        push_bytes_u16(out, &self.metadata, "object metadata")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            kind: ObjectKind::try_from(decoder.read_u8()?)?,
            object_id: decoder.read_bytes32()?,
            total_len: decoder.read_u64()?,
            birth_commit_group: decoder.read_u64()?,
            object_digest: decoder.read_bytes32()?,
            parent_object_id: decoder.read_bytes32()?,
            object_flags: decoder.read_u32()?,
            metadata: decoder.read_len_prefixed_u16()?.to_vec(),
        })
    }
}

/// Object payload chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectWrite {
    pub object_id: Bytes32,
    pub offset: u64,
    pub chunk_seq: u32,
    pub payload: Vec<u8>,
}

impl ObjectWrite {
    #[must_use]
    pub fn new(object_id: Bytes32, offset: u64, chunk_seq: u32, payload: Vec<u8>) -> Self {
        Self {
            object_id,
            offset,
            chunk_seq,
            payload,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| SendStreamError::LengthOverflow("object write payload"))?;
        out.extend_from_slice(&self.object_id);
        push_u64(out, self.offset);
        push_u32(out, self.chunk_seq);
        push_u32(out, payload_len);
        out.extend_from_slice(&blake3_digest(&self.payload));
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        let object_id = decoder.read_bytes32()?;
        let offset = decoder.read_u64()?;
        let chunk_seq = decoder.read_u32()?;
        let payload_len = decoder.read_len_u32()?;
        let expected = decoder.read_bytes32()?;
        let payload = decoder.read_bytes(payload_len)?.to_vec();
        let actual = blake3_digest(&payload);
        if actual != expected {
            return Err(SendStreamError::PayloadChecksumMismatch);
        }
        Ok(Self {
            object_id,
            offset,
            chunk_seq,
            payload,
        })
    }
}

/// Object truncation payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectTruncate {
    pub object_id: Bytes32,
    pub new_len: u64,
}

impl ObjectTruncate {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.object_id);
        push_u64(out, self.new_len);
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            object_id: decoder.read_bytes32()?,
            new_len: decoder.read_u64()?,
        })
    }
}

/// Object attribute update payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectSetAttr {
    pub object_id: Bytes32,
    pub attributes: Vec<u8>,
}

impl ObjectSetAttr {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.extend_from_slice(&self.object_id);
        push_bytes_u32(out, &self.attributes, "object attributes")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            object_id: decoder.read_bytes32()?,
            attributes: decoder.read_len_prefixed_u32()?.to_vec(),
        })
    }
}

/// Directory entry insertion payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntryAdd {
    pub directory_id: Bytes32,
    pub child_id: Bytes32,
    pub name: Vec<u8>,
}

impl DirEntryAdd {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.extend_from_slice(&self.directory_id);
        out.extend_from_slice(&self.child_id);
        push_bytes_u16(out, &self.name, "directory entry name")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            directory_id: decoder.read_bytes32()?,
            child_id: decoder.read_bytes32()?,
            name: decoder.read_len_prefixed_u16()?.to_vec(),
        })
    }
}

/// Directory entry removal payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntryRemove {
    pub directory_id: Bytes32,
    pub name: Vec<u8>,
}

impl DirEntryRemove {
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), SendStreamError> {
        out.extend_from_slice(&self.directory_id);
        push_bytes_u16(out, &self.name, "directory entry name")
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            directory_id: decoder.read_bytes32()?,
            name: decoder.read_len_prefixed_u16()?.to_vec(),
        })
    }
}

/// End-object payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectEnd {
    pub object_id: Bytes32,
    pub total_payload_len: u64,
    pub chunk_count: u32,
    pub reassembled_digest: Bytes32,
}

impl ObjectEnd {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.object_id);
        push_u64(out, self.total_payload_len);
        push_u32(out, self.chunk_count);
        out.extend_from_slice(&self.reassembled_digest);
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            object_id: decoder.read_bytes32()?,
            total_payload_len: decoder.read_u64()?,
            chunk_count: decoder.read_u32()?,
            reassembled_digest: decoder.read_bytes32()?,
        })
    }
}

/// Resumable send cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendCursor {
    pub snapshot_index: u32,
    pub object_index: u64,
    pub record_index: u64,
    pub payload_offset: u64,
    pub stream_offset: u64,
    pub stream_digest: Bytes32,
}

impl SendCursor {
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            snapshot_index: 0,
            object_index: 0,
            record_index: 0,
            payload_offset: 0,
            stream_offset: 0,
            stream_digest: [0; 32],
        }
    }

    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        push_u32(out, self.snapshot_index);
        push_u64(out, self.object_index);
        push_u64(out, self.record_index);
        push_u64(out, self.payload_offset);
        push_u64(out, self.stream_offset);
        out.extend_from_slice(&self.stream_digest);
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            snapshot_index: decoder.read_u32()?,
            object_index: decoder.read_u64()?,
            record_index: decoder.read_u64()?,
            payload_offset: decoder.read_u64()?,
            stream_offset: decoder.read_u64()?,
            stream_digest: decoder.read_bytes32()?,
        })
    }
}

/// Checkpoint marker emitted periodically by [`SendBuilder`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeMarker {
    pub cursor: SendCursor,
    pub records_emitted: u64,
    pub payload_bytes_emitted: u64,
}

impl ResumeMarker {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        self.cursor.encode_into(out);
        push_u64(out, self.records_emitted);
        push_u64(out, self.payload_bytes_emitted);
        out.extend_from_slice(&cursor_digest(&self.cursor));
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        let cursor = SendCursor::decode(decoder)?;
        let records_emitted = decoder.read_u64()?;
        let payload_bytes_emitted = decoder.read_u64()?;
        let expected = decoder.read_bytes32()?;
        let actual = cursor_digest(&cursor);
        if actual != expected {
            return Err(SendStreamError::CursorChecksumMismatch);
        }
        Ok(Self {
            cursor,
            records_emitted,
            payload_bytes_emitted,
        })
    }
}

/// Final stream record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamEnd {
    pub total_records: u64,
    pub total_payload_bytes: u64,
    pub total_objects: u64,
    pub snapshot_count: u32,
    pub stream_digest: Bytes32,
}

impl StreamEnd {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        push_u64(out, self.total_records);
        push_u64(out, self.total_payload_bytes);
        push_u64(out, self.total_objects);
        push_u32(out, self.snapshot_count);
        out.extend_from_slice(&self.stream_digest);
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, SendStreamError> {
        Ok(Self {
            total_records: decoder.read_u64()?,
            total_payload_bytes: decoder.read_u64()?,
            total_objects: decoder.read_u64()?,
            snapshot_count: decoder.read_u32()?,
            stream_digest: decoder.read_bytes32()?,
        })
    }
}

/// User-provided object payload used to build a send stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaObject {
    pub object_id: Bytes32,
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
    pub metadata: Vec<u8>,
    pub birth_commit_group: u64,
}

impl DeltaObject {
    #[must_use]
    pub fn new(object_id: Bytes32, kind: ObjectKind, payload: Vec<u8>) -> Self {
        Self {
            object_id,
            kind,
            payload,
            metadata: Vec::new(),
            birth_commit_group: 0,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Bytes32 {
        blake3_digest(&self.payload)
    }
}

/// Snapshot delta used by [`SendBuilder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDelta {
    pub snapshot_id: Id128,
    pub snapshot_name: Vec<u8>,
    pub commit_group: u64,
    pub objects: Vec<DeltaObject>,
    pub removed_objects: BTreeSet<Bytes32>,
    pub mutations: Vec<SnapshotMutation>,
}

impl SnapshotDelta {
    #[must_use]
    pub fn new(snapshot_id: Id128, snapshot_name: impl Into<Vec<u8>>, commit_group: u64) -> Self {
        Self {
            snapshot_id,
            snapshot_name: snapshot_name.into(),
            commit_group,
            objects: Vec::new(),
            removed_objects: BTreeSet::new(),
            mutations: Vec::new(),
        }
    }

    #[must_use]
    pub fn promote(
        snapshot_id: Id128,
        snapshot_name: impl Into<Vec<u8>>,
        commit_group: u64,
        root_id: Id128,
    ) -> Self {
        let snapshot_name = snapshot_name.into();
        let mut delta = Self::new(snapshot_id, snapshot_name.clone(), commit_group);
        delta
            .mutations
            .push(SnapshotMutation::promote(root_id, snapshot_name));
        delta
    }

    #[must_use]
    pub fn delete(
        snapshot_id: Id128,
        snapshot_name: impl Into<Vec<u8>>,
        commit_group: u64,
        root_id: Id128,
    ) -> Self {
        let snapshot_name = snapshot_name.into();
        let mut delta = Self::new(snapshot_id, snapshot_name.clone(), commit_group);
        delta
            .mutations
            .push(SnapshotMutation::delete(root_id, snapshot_name));
        delta
    }
}

/// Aggregate stream statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SendStats {
    pub objects_sent: u64,
    pub bytes_sent: u64,
    pub records_sent: u64,
    pub snapshots_sent: u32,
    pub snapshot_mutations_sent: u64,
    pub resume_points: u64,
}

/// Supported VFSSEND2 feature names for cross-cluster negotiation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SendFeatureSet {
    features: BTreeSet<FeatureName>,
}

impl SendFeatureSet {
    /// Create an empty feature set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a feature set from validated reverse-DNS feature-name strings.
    pub fn from_names<I, S>(names: I) -> Result<Self, FeatureNegotiationError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::new();
        for name in names {
            set.insert_name(name.as_ref())?;
        }
        Ok(set)
    }

    /// Insert a validated feature-name value.
    pub fn insert(&mut self, feature: FeatureName) -> bool {
        self.features.insert(feature)
    }

    /// Insert a feature by string name.
    pub fn insert_name(&mut self, name: &str) -> Result<bool, FeatureNegotiationError> {
        let feature = FeatureName::from_str(name).ok_or_else(|| {
            FeatureNegotiationError::InvalidFeatureName {
                name: name.to_string(),
            }
        })?;
        Ok(self.insert(feature))
    }

    /// Return true when this set contains `feature`.
    #[must_use]
    pub fn contains(&self, feature: &FeatureName) -> bool {
        self.features.contains(feature)
    }

    /// Return the number of feature names in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Return true when this feature set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Iterate feature names in canonical sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &FeatureName> {
        self.features.iter()
    }

    /// Return feature names present in both sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            features: self
                .features
                .intersection(&other.features)
                .cloned()
                .collect(),
        }
    }

    /// Return feature names present in `self` but absent from `other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        Self {
            features: self.features.difference(&other.features).cloned().collect(),
        }
    }

    fn union(&self, other: &Self) -> Self {
        Self {
            features: self.features.union(&other.features).cloned().collect(),
        }
    }
}

/// No stream payload compression.
pub const COMPRESSION_NONE: u64 = 1 << 0;
/// LZ4 stream payload compression.
pub const COMPRESSION_LZ4: u64 = 1 << 1;
/// Zstd stream payload compression.
pub const COMPRESSION_ZSTD: u64 = 1 << 2;
/// No stream payload encryption.
pub const ENCRYPTION_NONE: u64 = 1 << 0;
/// ChaCha20-Poly1305 stream payload encryption.
pub const ENCRYPTION_CHACHA20_POLY1305: u64 = 1 << 1;
/// BLAKE3 record and stream checksums.
pub const CHECKSUM_BLAKE3: u64 = 1 << 0;

/// Compatibility capabilities exchanged before a cross-cluster send starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendCompatibility {
    pub record_format_version: u16,
    pub compression_algorithms: u64,
    pub encryption_algorithms: u64,
    pub checksum_algorithms: u64,
}

impl SendCompatibility {
    /// Local compatibility for the currently implemented VFSSEND2 codec.
    pub const CURRENT: Self = Self {
        record_format_version: STREAM_VERSION,
        compression_algorithms: COMPRESSION_NONE,
        encryption_algorithms: ENCRYPTION_NONE,
        checksum_algorithms: CHECKSUM_BLAKE3,
    };

    /// Negotiate common algorithm sets with a peer.
    pub fn negotiate(self, peer: Self) -> Result<AgreedCompatibility, FeatureNegotiationError> {
        if self.record_format_version != peer.record_format_version {
            return Err(FeatureNegotiationError::RecordFormatVersionMismatch {
                source: self.record_format_version,
                target: peer.record_format_version,
            });
        }
        let compression_algorithms = self.compression_algorithms & peer.compression_algorithms;
        if compression_algorithms == 0 {
            return Err(FeatureNegotiationError::NoCommonCompressionAlgorithm);
        }
        let encryption_algorithms = self.encryption_algorithms & peer.encryption_algorithms;
        if encryption_algorithms == 0 {
            return Err(FeatureNegotiationError::NoCommonEncryptionAlgorithm);
        }
        let checksum_algorithms = self.checksum_algorithms & peer.checksum_algorithms;
        if checksum_algorithms == 0 {
            return Err(FeatureNegotiationError::NoCommonChecksumAlgorithm);
        }
        Ok(AgreedCompatibility {
            record_format_version: self.record_format_version,
            compression_algorithms,
            encryption_algorithms,
            checksum_algorithms,
        })
    }
}

impl Default for SendCompatibility {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Agreed compatibility result after source/target negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgreedCompatibility {
    pub record_format_version: u16,
    pub compression_algorithms: u64,
    pub encryption_algorithms: u64,
    pub checksum_algorithms: u64,
}

/// Source-to-target compatibility request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureNegotiationRequest {
    pub required_features: SendFeatureSet,
    pub optional_features: SendFeatureSet,
    pub compatibility: SendCompatibility,
}

impl FeatureNegotiationRequest {
    /// Construct a request from required and optional feature sets.
    #[must_use]
    pub const fn new(
        required_features: SendFeatureSet,
        optional_features: SendFeatureSet,
        compatibility: SendCompatibility,
    ) -> Self {
        Self {
            required_features,
            optional_features,
            compatibility,
        }
    }

    /// Encode the request for transport exchange before stream data starts.
    pub fn encode(&self) -> Result<Vec<u8>, FeatureNegotiationError> {
        let mut out = Vec::new();
        out.extend_from_slice(&NEGOTIATION_MAGIC);
        push_u16(&mut out, NEGOTIATION_WIRE_VERSION);
        out.push(NEGOTIATION_REQUEST_KIND);
        encode_compatibility(&mut out, self.compatibility);
        encode_feature_set(&mut out, &self.required_features)?;
        encode_feature_set(&mut out, &self.optional_features)?;
        Ok(out)
    }

    /// Decode a source-to-target compatibility request.
    pub fn decode(bytes: &[u8]) -> Result<Self, FeatureNegotiationError> {
        let mut decoder = negotiation_decoder(bytes, NEGOTIATION_REQUEST_KIND)?;
        let compatibility = decode_compatibility(&mut decoder)?;
        let required_features = decode_feature_set(&mut decoder)?;
        let optional_features = decode_feature_set(&mut decoder)?;
        decoder.finish().map_err(FeatureNegotiationError::Wire)?;
        Ok(Self {
            required_features,
            optional_features,
            compatibility,
        })
    }
}

/// Target capabilities used to answer a feature-negotiation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureSupport {
    pub supported_features: SendFeatureSet,
    pub compatibility: SendCompatibility,
}

impl FeatureSupport {
    /// Construct target-side support data.
    #[must_use]
    pub const fn new(supported_features: SendFeatureSet, compatibility: SendCompatibility) -> Self {
        Self {
            supported_features,
            compatibility,
        }
    }
}

/// Target-to-source compatibility response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeatureNegotiationReply {
    pub supported_features: SendFeatureSet,
    pub refused_features: SendFeatureSet,
    pub agreed_features: SendFeatureSet,
    pub compatibility: AgreedCompatibility,
}

impl FeatureNegotiationReply {
    /// Encode the reply for transport exchange before stream data starts.
    pub fn encode(&self) -> Result<Vec<u8>, FeatureNegotiationError> {
        let mut out = Vec::new();
        out.extend_from_slice(&NEGOTIATION_MAGIC);
        push_u16(&mut out, NEGOTIATION_WIRE_VERSION);
        out.push(NEGOTIATION_REPLY_KIND);
        encode_agreed_compatibility(&mut out, self.compatibility);
        encode_feature_set(&mut out, &self.supported_features)?;
        encode_feature_set(&mut out, &self.refused_features)?;
        encode_feature_set(&mut out, &self.agreed_features)?;
        Ok(out)
    }

    /// Decode a target-to-source compatibility response.
    pub fn decode(bytes: &[u8]) -> Result<Self, FeatureNegotiationError> {
        let mut decoder = negotiation_decoder(bytes, NEGOTIATION_REPLY_KIND)?;
        let compatibility = decode_agreed_compatibility(&mut decoder)?;
        let supported_features = decode_feature_set(&mut decoder)?;
        let refused_features = decode_feature_set(&mut decoder)?;
        let agreed_features = decode_feature_set(&mut decoder)?;
        decoder.finish().map_err(FeatureNegotiationError::Wire)?;
        Ok(Self {
            supported_features,
            refused_features,
            agreed_features,
            compatibility,
        })
    }
}

/// Negotiation counters retained by the caller driving cross-cluster sends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FeatureNegotiationStats {
    pub negotiations_attempted: u64,
    pub negotiations_succeeded: u64,
    pub required_feature_refusals: u64,
    pub compatibility_refusals: u64,
}

/// Stateful feature negotiator that records success/refusal counters.
#[derive(Clone, Debug, Default)]
pub struct FeatureNegotiation {
    stats: FeatureNegotiationStats,
}

impl FeatureNegotiation {
    /// Return current negotiation counters.
    #[must_use]
    pub const fn stats(&self) -> FeatureNegotiationStats {
        self.stats
    }

    /// Negotiate source-required/optional features and stream compatibility.
    pub fn negotiate(
        &mut self,
        request: &FeatureNegotiationRequest,
        target: &FeatureSupport,
    ) -> Result<FeatureNegotiationReply, FeatureNegotiationError> {
        self.stats.negotiations_attempted = self
            .stats
            .negotiations_attempted
            .checked_add(1)
            .ok_or(FeatureNegotiationError::CounterOverflow)?;

        let refused_required = request
            .required_features
            .difference(&target.supported_features);
        let refused_optional = request
            .optional_features
            .difference(&target.supported_features);
        if !refused_required.is_empty() {
            self.stats.required_feature_refusals = self
                .stats
                .required_feature_refusals
                .checked_add(refused_required.len() as u64)
                .ok_or(FeatureNegotiationError::CounterOverflow)?;
            return Err(FeatureNegotiationError::RequiredFeaturesRefused {
                features: refused_required.iter().cloned().collect(),
            });
        }

        let compatibility = match request.compatibility.negotiate(target.compatibility) {
            Ok(compatibility) => compatibility,
            Err(err) => {
                self.stats.compatibility_refusals = self
                    .stats
                    .compatibility_refusals
                    .checked_add(1)
                    .ok_or(FeatureNegotiationError::CounterOverflow)?;
                return Err(err);
            }
        };

        let agreed_optional = request
            .optional_features
            .intersection(&target.supported_features);
        let agreed_features = request.required_features.union(&agreed_optional);
        self.stats.negotiations_succeeded = self
            .stats
            .negotiations_succeeded
            .checked_add(1)
            .ok_or(FeatureNegotiationError::CounterOverflow)?;

        Ok(FeatureNegotiationReply {
            supported_features: target.supported_features.clone(),
            refused_features: refused_optional,
            agreed_features,
            compatibility,
        })
    }
}

/// Feature negotiation failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeatureNegotiationError {
    InvalidFeatureName { name: String },
    RequiredFeaturesRefused { features: Vec<FeatureName> },
    RecordFormatVersionMismatch { source: u16, target: u16 },
    NoCommonCompressionAlgorithm,
    NoCommonEncryptionAlgorithm,
    NoCommonChecksumAlgorithm,
    CounterOverflow,
    Wire(SendStreamError),
    InvalidMessageKind { expected: u8, actual: u8 },
    UnsupportedNegotiationVersion(u16),
}

impl fmt::Display for FeatureNegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFeatureName { name } => write!(f, "invalid feature name: {name}"),
            Self::RequiredFeaturesRefused { features } => {
                write!(f, "required feature(s) refused: {}", features.len())
            }
            Self::RecordFormatVersionMismatch { source, target } => {
                write!(
                    f,
                    "record format version mismatch: source {source}, target {target}"
                )
            }
            Self::NoCommonCompressionAlgorithm => f.write_str("no common compression algorithm"),
            Self::NoCommonEncryptionAlgorithm => f.write_str("no common encryption algorithm"),
            Self::NoCommonChecksumAlgorithm => f.write_str("no common checksum algorithm"),
            Self::CounterOverflow => f.write_str("feature negotiation counter overflow"),
            Self::Wire(err) => write!(f, "feature negotiation wire error: {err}"),
            Self::InvalidMessageKind { expected, actual } => write!(
                f,
                "invalid feature negotiation message kind: expected {expected}, got {actual}"
            ),
            Self::UnsupportedNegotiationVersion(version) => {
                write!(f, "unsupported feature negotiation version {version}")
            }
        }
    }
}

impl std::error::Error for FeatureNegotiationError {}

fn encode_compatibility(out: &mut Vec<u8>, compatibility: SendCompatibility) {
    push_u16(out, compatibility.record_format_version);
    push_u64(out, compatibility.compression_algorithms);
    push_u64(out, compatibility.encryption_algorithms);
    push_u64(out, compatibility.checksum_algorithms);
}

fn decode_compatibility(
    decoder: &mut Decoder<'_>,
) -> Result<SendCompatibility, FeatureNegotiationError> {
    Ok(SendCompatibility {
        record_format_version: decoder.read_u16().map_err(FeatureNegotiationError::Wire)?,
        compression_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
        encryption_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
        checksum_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
    })
}

fn encode_agreed_compatibility(out: &mut Vec<u8>, compatibility: AgreedCompatibility) {
    push_u16(out, compatibility.record_format_version);
    push_u64(out, compatibility.compression_algorithms);
    push_u64(out, compatibility.encryption_algorithms);
    push_u64(out, compatibility.checksum_algorithms);
}

fn decode_agreed_compatibility(
    decoder: &mut Decoder<'_>,
) -> Result<AgreedCompatibility, FeatureNegotiationError> {
    Ok(AgreedCompatibility {
        record_format_version: decoder.read_u16().map_err(FeatureNegotiationError::Wire)?,
        compression_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
        encryption_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
        checksum_algorithms: decoder.read_u64().map_err(FeatureNegotiationError::Wire)?,
    })
}

fn encode_feature_set(
    out: &mut Vec<u8>,
    set: &SendFeatureSet,
) -> Result<(), FeatureNegotiationError> {
    let count = u16::try_from(set.len())
        .map_err(|_| FeatureNegotiationError::Wire(SendStreamError::LengthOverflow("features")))?;
    push_u16(out, count);
    for feature in set.iter() {
        push_bytes_u16(out, feature.as_bytes(), "feature name")
            .map_err(FeatureNegotiationError::Wire)?;
    }
    Ok(())
}

fn decode_feature_set(
    decoder: &mut Decoder<'_>,
) -> Result<SendFeatureSet, FeatureNegotiationError> {
    let count = decoder.read_u16().map_err(FeatureNegotiationError::Wire)?;
    let mut set = SendFeatureSet::new();
    for _ in 0..count {
        let bytes = decoder
            .read_len_prefixed_u16()
            .map_err(FeatureNegotiationError::Wire)?;
        let feature =
            FeatureName::new(bytes).ok_or_else(|| FeatureNegotiationError::InvalidFeatureName {
                name: String::from_utf8_lossy(bytes).into_owned(),
            })?;
        set.insert(feature);
    }
    Ok(set)
}

fn negotiation_decoder(
    bytes: &[u8],
    expected_kind: u8,
) -> Result<Decoder<'_>, FeatureNegotiationError> {
    let mut decoder = Decoder::new(bytes);
    decoder
        .expect_magic(&NEGOTIATION_MAGIC)
        .map_err(FeatureNegotiationError::Wire)?;
    let version = decoder.read_u16().map_err(FeatureNegotiationError::Wire)?;
    if version != NEGOTIATION_WIRE_VERSION {
        return Err(FeatureNegotiationError::UnsupportedNegotiationVersion(
            version,
        ));
    }
    let actual_kind = decoder.read_u8().map_err(FeatureNegotiationError::Wire)?;
    if actual_kind != expected_kind {
        return Err(FeatureNegotiationError::InvalidMessageKind {
            expected: expected_kind,
            actual: actual_kind,
        });
    }
    Ok(decoder)
}

/// Builder for canonical send records.
#[derive(Clone, Debug)]
pub struct SendBuilder {
    header: SendStreamHeader,
    records: Vec<SendRecord>,
    stats: SendStats,
}

impl SendBuilder {
    /// Build a full send stream from target snapshots.
    pub fn full(
        header: SendStreamHeader,
        snapshots: Vec<SnapshotDelta>,
    ) -> Result<Self, SendStreamError> {
        if header.flags.contains(StreamFlags::INCREMENTAL) {
            return Err(SendStreamError::InvalidHeader(
                "full send must not declare an incremental base root",
            ));
        }
        if header.from_snapshot_id != [0; 16] {
            return Err(SendStreamError::InvalidHeader(
                "full send must not name an incremental base root",
            ));
        }
        Self::build(header, snapshots, None)
    }

    /// Build an incremental send stream, filtering unchanged objects by BLAKE3 digest.
    pub fn incremental(
        header: SendStreamHeader,
        snapshots: Vec<SnapshotDelta>,
        base_object_digests: BTreeMap<Bytes32, Bytes32>,
    ) -> Result<Self, SendStreamError> {
        let base_root = PinnedBaseRoot::pinned_from_objects(
            header.source_dataset_id,
            header.from_snapshot_id,
            base_object_digests,
        )?;
        Self::incremental_from_base(header, snapshots, base_root)
    }

    /// Build an incremental send stream from explicit send-side base authority.
    pub fn incremental_from_base(
        header: SendStreamHeader,
        snapshots: Vec<SnapshotDelta>,
        base_root: PinnedBaseRoot,
    ) -> Result<Self, SendStreamError> {
        if !header.flags.contains(StreamFlags::INCREMENTAL) {
            return Err(SendStreamError::MissingBaseRoot);
        }
        Self::build(header, snapshots, Some(base_root))
    }

    /// Return immutable planned records.
    #[must_use]
    pub fn records(&self) -> &[SendRecord] {
        &self.records
    }

    /// Return send statistics for the planned stream.
    #[must_use]
    pub const fn stats(&self) -> SendStats {
        self.stats
    }

    /// Encode the full stream, including header and final stream-end record.
    pub fn encode(&self) -> Result<Vec<u8>, SendStreamError> {
        let mut out = self.header.encode()?;
        let mut digest = StreamDigest::new();
        for (index, record) in self.records.iter().enumerate() {
            let encoded = encode_record(record, index as u64)?;
            digest.update(&encoded);
            out.extend_from_slice(&encoded);
        }
        let stream_end = SendRecord::new(SendRecordPayload::StreamEnd(StreamEnd {
            total_records: self.stats.records_sent,
            total_payload_bytes: self.stats.bytes_sent,
            total_objects: self.stats.objects_sent,
            snapshot_count: self.stats.snapshots_sent,
            stream_digest: digest.finalize(),
        }));
        out.extend_from_slice(&encode_record(&stream_end, self.records.len() as u64)?);
        Ok(out)
    }

    /// Return records from `cursor.record_index` after validating cursor digest.
    pub fn resume_records(&self, cursor: &SendCursor) -> Result<&[SendRecord], SendStreamError> {
        let index = usize::try_from(cursor.record_index)
            .map_err(|_| SendStreamError::LengthOverflow("cursor record index"))?;
        if index > self.records.len() {
            return Err(SendStreamError::CursorOutOfRange {
                index: cursor.record_index,
                records: self.records.len() as u64,
            });
        }
        let expected = digest_records_until(&self.records, index)?;
        if cursor.stream_digest != expected {
            return Err(SendStreamError::CursorChecksumMismatch);
        }
        Ok(&self.records[index..])
    }

    fn build(
        header: SendStreamHeader,
        mut snapshots: Vec<SnapshotDelta>,
        base_root: Option<PinnedBaseRoot>,
    ) -> Result<Self, SendStreamError> {
        if snapshots.is_empty() {
            return Err(SendStreamError::EmptyStream);
        }
        snapshots.sort_by_key(|snapshot| snapshot.commit_group);
        let target_root_digest = target_root_digest_from_snapshots(
            header.source_dataset_id,
            header.to_snapshot_id,
            &snapshots,
        )?;
        let manifest = match &base_root {
            Some(base_root) => {
                base_root.validate_for_header(&header)?;
                LineageManifest::incremental(&header, base_root, target_root_digest)
            }
            None => LineageManifest::full(&header, target_root_digest),
        };
        manifest.validate_for_header(&header)?;
        let mut records = Vec::new();
        let mut stats = SendStats::default();
        records.push(SendRecord::new(SendRecordPayload::LineageManifest(
            manifest,
        )));
        stats.records_sent += 1;
        let max_payload = usize::try_from(header.max_record_payload)
            .map_err(|_| SendStreamError::LengthOverflow("max record payload"))?;
        let checkpoint_interval = header.checkpoint_interval_records as u64;
        let mut payload_bytes_since_checkpoint = 0_u64;
        let base_object_digests = base_root
            .as_ref()
            .map(|base_root| &base_root.object_digests);

        for (snapshot_index, snapshot) in snapshots.into_iter().enumerate() {
            records.push(SendRecord::new(SendRecordPayload::SnapshotBegin(
                SnapshotBoundary::new(
                    snapshot.snapshot_id,
                    snapshot.commit_group,
                    snapshot.snapshot_name.clone(),
                ),
            )));
            stats.records_sent += 1;
            stats.snapshots_sent += 1;

            for mutation in snapshot.mutations {
                records.push(SendRecord::new(SendRecordPayload::SnapshotMutation(
                    mutation,
                )));
                stats.records_sent += 1;
                stats.snapshot_mutations_sent += 1;
                let object_index = stats.objects_sent;
                maybe_checkpoint(
                    &mut records,
                    &mut stats,
                    snapshot_index as u32,
                    object_index,
                    payload_bytes_since_checkpoint,
                    checkpoint_interval,
                )?;
                payload_bytes_since_checkpoint = 0;
            }

            for removed in snapshot.removed_objects {
                records.push(SendRecord::new(SendRecordPayload::ObjectTruncate(
                    ObjectTruncate {
                        object_id: removed,
                        new_len: 0,
                    },
                )));
                stats.records_sent += 1;
                let object_index = stats.objects_sent;
                maybe_checkpoint(
                    &mut records,
                    &mut stats,
                    snapshot_index as u32,
                    object_index,
                    payload_bytes_since_checkpoint,
                    checkpoint_interval,
                )?;
                payload_bytes_since_checkpoint = 0;
            }

            for object in snapshot.objects {
                if let Some(base) = base_object_digests {
                    if base.get(&object.object_id).copied() == Some(object.digest()) {
                        continue;
                    }
                }
                let mut begin = ObjectBegin::new(object.object_id, object.kind, &object.payload);
                begin.metadata = object.metadata.clone();
                begin.birth_commit_group = object.birth_commit_group;
                records.push(SendRecord::new(SendRecordPayload::ObjectBegin(begin)));
                stats.records_sent += 1;

                let mut chunk_count = 0_u32;
                for (chunk_seq, chunk) in object.payload.chunks(max_payload).enumerate() {
                    let chunk_seq = u32::try_from(chunk_seq)
                        .map_err(|_| SendStreamError::LengthOverflow("object chunk sequence"))?;
                    let offset = u64::from(chunk_seq) * header.max_record_payload as u64;
                    let mut flags = RecordFlags::NONE;
                    if offset + chunk.len() as u64 == object.payload.len() as u64 {
                        flags = flags.with(RecordFlags::LAST_CHUNK);
                    }
                    records.push(
                        SendRecord::new(SendRecordPayload::ObjectWrite(ObjectWrite::new(
                            object.object_id,
                            offset,
                            chunk_seq,
                            chunk.to_vec(),
                        )))
                        .with_flags(flags),
                    );
                    stats.records_sent += 1;
                    stats.bytes_sent += chunk.len() as u64;
                    payload_bytes_since_checkpoint += chunk.len() as u64;
                    chunk_count = chunk_count
                        .checked_add(1)
                        .ok_or(SendStreamError::LengthOverflow("object chunk count"))?;
                }

                records.push(SendRecord::new(SendRecordPayload::ObjectEnd(ObjectEnd {
                    object_id: object.object_id,
                    total_payload_len: object.payload.len() as u64,
                    chunk_count,
                    reassembled_digest: object.digest(),
                })));
                stats.records_sent += 1;
                stats.objects_sent += 1;
                let object_index = stats.objects_sent;
                maybe_checkpoint(
                    &mut records,
                    &mut stats,
                    snapshot_index as u32,
                    object_index,
                    payload_bytes_since_checkpoint,
                    checkpoint_interval,
                )?;
                payload_bytes_since_checkpoint = 0;
            }

            records.push(SendRecord::new(SendRecordPayload::SnapshotEnd(
                SnapshotBoundary::new(
                    snapshot.snapshot_id,
                    snapshot.commit_group,
                    snapshot.snapshot_name,
                ),
            )));
            stats.records_sent += 1;
        }

        if stats.objects_sent == 0
            && stats.snapshot_mutations_sent == 0
            && base_object_digests.is_some()
        {
            return Err(SendStreamError::EmptyIncrementalDelta);
        }

        Ok(Self {
            header,
            records,
            stats,
        })
    }
}

/// A reconstructed dataset staged by the receive side.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedDataset {
    pub dataset_id: Id128,
    pub objects: BTreeMap<Bytes32, ReceivedObject>,
    pub snapshots: BTreeMap<Id128, ReceivedSnapshot>,
    pub snapshot_mutations: Vec<SnapshotMutation>,
    pub directory_entries: BTreeMap<(Bytes32, Vec<u8>), Bytes32>,
}

impl ReceivedDataset {
    /// Create an empty receive target.
    #[must_use]
    pub fn empty(dataset_id: Id128) -> Self {
        Self {
            dataset_id,
            objects: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            snapshot_mutations: Vec::new(),
            directory_entries: BTreeMap::new(),
        }
    }
}

/// One fully received object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedObject {
    pub object_id: Bytes32,
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
    pub metadata: Vec<u8>,
    pub birth_commit_group: u64,
    pub digest: Bytes32,
}

impl ReceivedObject {
    #[must_use]
    pub fn new(object_id: Bytes32, kind: ObjectKind, payload: Vec<u8>) -> Self {
        let digest = blake3_digest(&payload);
        Self {
            object_id,
            kind,
            payload,
            metadata: Vec::new(),
            birth_commit_group: 0,
            digest,
        }
    }

    fn truncate(&mut self, new_len: u64) -> Result<(), SendStreamError> {
        let new_len = usize::try_from(new_len)
            .map_err(|_| SendStreamError::LengthOverflow("receive truncate length"))?;
        self.payload.resize(new_len, 0);
        self.digest = blake3_digest(&self.payload);
        Ok(())
    }
}

/// One completed snapshot reconstructed from stream records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedSnapshot {
    pub snapshot_id: Id128,
    pub name: Vec<u8>,
    pub commit_group: u64,
    pub object_ids: Vec<Bytes32>,
}

/// Receive progress returned by [`ReceiveBuilder::next_record`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveProgress {
    Continue,
    ObjectReceived { object_id: Bytes32, bytes: u64 },
    SnapshotReceived { snapshot_id: Id128, objects: u64 },
    ResumePoint(ReceiveCheckpoint),
    StreamComplete(ReceiveStats),
}

/// A receive-side checkpoint that carries the send cursor plus staging context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveCheckpoint {
    pub cursor: SendCursor,
    pub active_snapshot: Option<SnapshotBoundary>,
    pub active_snapshot_object_ids: Vec<Bytes32>,
}

/// Aggregate receive statistics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiveStats {
    pub objects_received: u64,
    pub bytes_received: u64,
    pub snapshots_received: u32,
    pub snapshot_mutations_received: u64,
    pub resume_count: u64,
    pub validation_passed: bool,
}

#[derive(Clone, Debug)]
struct OpenSnapshot {
    boundary: SnapshotBoundary,
    object_ids: Vec<Bytes32>,
}

#[derive(Clone, Debug)]
struct OpenObject {
    begin: ObjectBegin,
    payload: Vec<u8>,
    chunk_count: u32,
}

/// Staged receive executor for a decoded VFSSEND2 stream.
#[derive(Clone, Debug)]
pub struct ReceiveBuilder {
    header: SendStreamHeader,
    records: Vec<SendRecord>,
    next_index: usize,
    dataset: ReceivedDataset,
    current_snapshot: Option<OpenSnapshot>,
    open_object: Option<OpenObject>,
    stats: ReceiveStats,
}

impl ReceiveBuilder {
    /// Initialize receive into an empty target dataset.
    pub fn new(target_dataset_id: Id128, stream: &[u8]) -> Result<Self, SendStreamError> {
        Self::new_with_target(ReceivedDataset::empty(target_dataset_id), stream)
    }

    /// Initialize receive into an existing target dataset for incremental merge.
    pub fn new_with_target(
        target: ReceivedDataset,
        stream: &[u8],
    ) -> Result<Self, SendStreamError> {
        let (header, records) = decode_stream(stream)?;
        Self::from_decoded(target, header, records, 0, None, Vec::new())
    }

    /// Resume receive from a persisted receive checkpoint.
    pub fn resume_from_checkpoint(
        target: ReceivedDataset,
        stream: &[u8],
        checkpoint: ReceiveCheckpoint,
    ) -> Result<Self, SendStreamError> {
        let (header, records) = decode_stream(stream)?;
        let non_end_len = records
            .iter()
            .position(|record| matches!(record.payload, SendRecordPayload::StreamEnd(_)))
            .unwrap_or(records.len());
        let index = usize::try_from(checkpoint.cursor.record_index)
            .map_err(|_| SendStreamError::LengthOverflow("receive resume record index"))?;
        if index > non_end_len {
            return Err(SendStreamError::CursorOutOfRange {
                index: checkpoint.cursor.record_index,
                records: non_end_len as u64,
            });
        }
        let expected = digest_records_until(&records[..non_end_len], index)?;
        if expected != checkpoint.cursor.stream_digest {
            return Err(SendStreamError::CursorChecksumMismatch);
        }
        Self::from_decoded(
            target,
            header,
            records,
            index,
            checkpoint.active_snapshot,
            checkpoint.active_snapshot_object_ids,
        )
    }

    /// Convenience wrapper for [`ReceiveBuilder::resume_from_checkpoint`].
    pub fn receive_resume(
        target: ReceivedDataset,
        stream: &[u8],
        checkpoint: ReceiveCheckpoint,
    ) -> Result<Self, SendStreamError> {
        Self::resume_from_checkpoint(target, stream, checkpoint)
    }

    /// Return the decoded stream header.
    #[must_use]
    pub const fn header(&self) -> &SendStreamHeader {
        &self.header
    }

    /// Return current staged dataset state.
    #[must_use]
    pub const fn staged_dataset(&self) -> &ReceivedDataset {
        &self.dataset
    }

    /// Return current receive statistics.
    #[must_use]
    pub const fn stats(&self) -> ReceiveStats {
        self.stats
    }

    /// Process one stream record.
    pub fn next_record(&mut self) -> Result<ReceiveProgress, SendStreamError> {
        let record = self
            .records
            .get(self.next_index)
            .cloned()
            .ok_or(SendStreamError::MissingStreamEnd)?;
        self.next_index += 1;
        match record.payload {
            SendRecordPayload::LineageManifest(manifest) => {
                manifest.validate_for_header(&self.header)?;
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::SnapshotBegin(boundary) => {
                if self.current_snapshot.is_some() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "snapshot began before previous snapshot ended",
                    ));
                }
                self.current_snapshot = Some(OpenSnapshot {
                    boundary,
                    object_ids: Vec::new(),
                });
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::ObjectBegin(begin) => {
                if self.current_snapshot.is_none() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "object began outside a snapshot",
                    ));
                }
                if self.open_object.is_some() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "object began before previous object ended",
                    ));
                }
                self.open_object = Some(OpenObject {
                    begin,
                    payload: Vec::new(),
                    chunk_count: 0,
                });
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::ObjectWrite(write) => {
                let open = self
                    .open_object
                    .as_mut()
                    .ok_or(SendStreamError::ReceiveProtocol(
                        "object write without object begin",
                    ))?;
                if open.begin.object_id != write.object_id {
                    return Err(SendStreamError::ReceiveProtocol(
                        "object write id does not match open object",
                    ));
                }
                if open.payload.len() as u64 != write.offset {
                    return Err(SendStreamError::ReceiveProtocol(
                        "object write offset is not contiguous",
                    ));
                }
                if open.chunk_count != write.chunk_seq {
                    return Err(SendStreamError::ReceiveProtocol(
                        "object write chunk sequence is not contiguous",
                    ));
                }
                open.payload.extend_from_slice(&write.payload);
                open.chunk_count = open
                    .chunk_count
                    .checked_add(1)
                    .ok_or(SendStreamError::LengthOverflow("receive chunk count"))?;
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::ObjectEnd(end) => self.finish_object(end),
            SendRecordPayload::ObjectTruncate(truncate) => self.apply_truncate(truncate),
            SendRecordPayload::ObjectSetAttr(attrs) => self.apply_attrs(attrs),
            SendRecordPayload::DirEntryAdd(add) => {
                self.dataset
                    .directory_entries
                    .insert((add.directory_id, add.name), add.child_id);
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::DirEntryRemove(remove) => {
                self.dataset
                    .directory_entries
                    .remove(&(remove.directory_id, remove.name));
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::SnapshotMutation(mutation) => {
                if self.current_snapshot.is_none() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "snapshot mutation outside a snapshot",
                    ));
                }
                if self.open_object.is_some() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "snapshot mutation inside an open object",
                    ));
                }
                self.dataset.snapshot_mutations.push(mutation);
                self.stats.snapshot_mutations_received = self
                    .stats
                    .snapshot_mutations_received
                    .checked_add(1)
                    .ok_or(SendStreamError::LengthOverflow(
                        "receive snapshot mutation count",
                    ))?;
                Ok(ReceiveProgress::Continue)
            }
            SendRecordPayload::SnapshotEnd(boundary) => self.finish_snapshot(boundary),
            SendRecordPayload::ResumeMarker(marker) => {
                self.stats.resume_count = self
                    .stats
                    .resume_count
                    .checked_add(1)
                    .ok_or(SendStreamError::LengthOverflow("receive resume count"))?;
                Ok(ReceiveProgress::ResumePoint(ReceiveCheckpoint {
                    cursor: marker.cursor,
                    active_snapshot: self
                        .current_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.boundary.clone()),
                    active_snapshot_object_ids: self
                        .current_snapshot
                        .as_ref()
                        .map(|snapshot| snapshot.object_ids.clone())
                        .unwrap_or_default(),
                }))
            }
            SendRecordPayload::StreamEnd(_) => {
                if self.open_object.is_some() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "stream ended with an open object",
                    ));
                }
                if self.current_snapshot.is_some() {
                    return Err(SendStreamError::ReceiveProtocol(
                        "stream ended with an open snapshot",
                    ));
                }
                self.stats.validation_passed = true;
                Ok(ReceiveProgress::StreamComplete(self.stats))
            }
        }
    }

    /// Process all remaining records and return the received dataset.
    pub fn finish_all(mut self) -> Result<ReceivedDataset, SendStreamError> {
        loop {
            if matches!(self.next_record()?, ReceiveProgress::StreamComplete(_)) {
                return Ok(self.dataset);
            }
        }
    }

    fn from_decoded(
        target: ReceivedDataset,
        header: SendStreamHeader,
        records: Vec<SendRecord>,
        next_index: usize,
        active_snapshot: Option<SnapshotBoundary>,
        active_snapshot_object_ids: Vec<Bytes32>,
    ) -> Result<Self, SendStreamError> {
        if header.source_dataset_id != target.dataset_id {
            return Err(SendStreamError::ReceiveProtocol(
                "stream dataset id does not match receive target",
            ));
        }
        if next_index > records.len() {
            return Err(SendStreamError::CursorOutOfRange {
                index: next_index as u64,
                records: records.len() as u64,
            });
        }
        let current_snapshot = active_snapshot.map(|boundary| OpenSnapshot {
            boundary,
            object_ids: active_snapshot_object_ids,
        });
        Ok(Self {
            header,
            records,
            next_index,
            dataset: target,
            current_snapshot,
            open_object: None,
            stats: ReceiveStats::default(),
        })
    }

    fn finish_object(&mut self, end: ObjectEnd) -> Result<ReceiveProgress, SendStreamError> {
        let open = self
            .open_object
            .take()
            .ok_or(SendStreamError::ReceiveProtocol(
                "object end without object begin",
            ))?;
        if open.begin.object_id != end.object_id {
            return Err(SendStreamError::ReceiveProtocol(
                "object end id does not match open object",
            ));
        }
        if open.payload.len() as u64 != end.total_payload_len
            || open.payload.len() as u64 != open.begin.total_len
        {
            return Err(SendStreamError::ReceiveProtocol(
                "object length does not match object headers",
            ));
        }
        if open.chunk_count != end.chunk_count {
            return Err(SendStreamError::ReceiveProtocol(
                "object chunk count does not match object end",
            ));
        }
        let digest = blake3_digest(&open.payload);
        if digest != end.reassembled_digest || digest != open.begin.object_digest {
            return Err(SendStreamError::ObjectDigestMismatch {
                object_id: end.object_id,
            });
        }
        let object = ReceivedObject {
            object_id: open.begin.object_id,
            kind: open.begin.kind,
            payload: open.payload,
            metadata: open.begin.metadata,
            birth_commit_group: open.begin.birth_commit_group,
            digest,
        };
        let bytes = object.payload.len() as u64;
        self.dataset.objects.insert(object.object_id, object);
        if let Some(snapshot) = self.current_snapshot.as_mut() {
            snapshot.object_ids.push(end.object_id);
        }
        self.stats.objects_received = self
            .stats
            .objects_received
            .checked_add(1)
            .ok_or(SendStreamError::LengthOverflow("receive object count"))?;
        self.stats.bytes_received = self
            .stats
            .bytes_received
            .checked_add(bytes)
            .ok_or(SendStreamError::LengthOverflow("receive byte count"))?;
        Ok(ReceiveProgress::ObjectReceived {
            object_id: end.object_id,
            bytes,
        })
    }

    fn apply_truncate(
        &mut self,
        truncate: ObjectTruncate,
    ) -> Result<ReceiveProgress, SendStreamError> {
        if truncate.new_len == 0 {
            self.dataset.objects.remove(&truncate.object_id);
            return Ok(ReceiveProgress::Continue);
        }
        let object = self.dataset.objects.get_mut(&truncate.object_id).ok_or(
            SendStreamError::ReceiveProtocol("truncate target object missing"),
        )?;
        object.truncate(truncate.new_len)?;
        Ok(ReceiveProgress::Continue)
    }

    fn apply_attrs(&mut self, attrs: ObjectSetAttr) -> Result<ReceiveProgress, SendStreamError> {
        let object = self.dataset.objects.get_mut(&attrs.object_id).ok_or(
            SendStreamError::ReceiveProtocol("attribute target object missing"),
        )?;
        object.metadata = attrs.attributes;
        Ok(ReceiveProgress::Continue)
    }

    fn finish_snapshot(
        &mut self,
        boundary: SnapshotBoundary,
    ) -> Result<ReceiveProgress, SendStreamError> {
        let open = self
            .current_snapshot
            .take()
            .ok_or(SendStreamError::ReceiveProtocol(
                "snapshot end without snapshot begin",
            ))?;
        if open.boundary != boundary {
            return Err(SendStreamError::ReceiveProtocol(
                "snapshot end does not match open snapshot",
            ));
        }
        let object_count = open.object_ids.len() as u64;
        self.dataset.snapshots.insert(
            boundary.snapshot_id,
            ReceivedSnapshot {
                snapshot_id: boundary.snapshot_id,
                name: boundary.name,
                commit_group: boundary.commit_group,
                object_ids: open.object_ids,
            },
        );
        self.stats.snapshots_received = self
            .stats
            .snapshots_received
            .checked_add(1)
            .ok_or(SendStreamError::LengthOverflow("receive snapshot count"))?;
        Ok(ReceiveProgress::SnapshotReceived {
            snapshot_id: boundary.snapshot_id,
            objects: object_count,
        })
    }
}

fn maybe_checkpoint(
    records: &mut Vec<SendRecord>,
    stats: &mut SendStats,
    snapshot_index: u32,
    object_index: u64,
    payload_bytes_since_checkpoint: u64,
    checkpoint_interval: u64,
) -> Result<(), SendStreamError> {
    let records_since_manifest = stats.records_sent.saturating_sub(1);
    if checkpoint_interval == 0 || records_since_manifest == 0 {
        return Ok(());
    }
    if !records_since_manifest.is_multiple_of(checkpoint_interval) {
        return Ok(());
    }
    let digest = digest_records_until(records, records.len())?;
    let cursor = SendCursor {
        snapshot_index,
        object_index,
        record_index: stats.records_sent,
        payload_offset: payload_bytes_since_checkpoint,
        stream_offset: encoded_records_len(records)?,
        stream_digest: digest,
    };
    records.push(
        SendRecord::new(SendRecordPayload::ResumeMarker(ResumeMarker {
            cursor,
            records_emitted: stats.records_sent,
            payload_bytes_emitted: stats.bytes_sent,
        }))
        .with_flags(RecordFlags::CHECKPOINT_CANDIDATE),
    );
    stats.records_sent += 1;
    stats.resume_points += 1;
    Ok(())
}

/// Decode and verify a full stream.
pub fn decode_stream(bytes: &[u8]) -> Result<(SendStreamHeader, Vec<SendRecord>), SendStreamError> {
    let (header, mut rest) = SendStreamHeader::decode(bytes)?;
    let mut records = Vec::new();
    let mut digest = StreamDigest::new();
    let mut sequence = 0_u64;
    let mut summary = DecodedSummary::default();
    let mut saw_end = false;
    while !rest.is_empty() {
        let (record, consumed, raw_frame) = decode_record(rest, sequence)?;
        rest = &rest[consumed..];
        match &record.payload {
            SendRecordPayload::StreamEnd(end) => {
                let actual = digest.finalize();
                if actual != end.stream_digest {
                    return Err(SendStreamError::StreamChecksumMismatch);
                }
                summary.verify(end)?;
                saw_end = true;
                records.push(record);
                if !rest.is_empty() {
                    return Err(SendStreamError::TrailingBytes);
                }
            }
            _ => {
                digest.update(raw_frame);
                summary.observe(&record)?;
                records.push(record);
            }
        }
        sequence = sequence
            .checked_add(1)
            .ok_or(SendStreamError::LengthOverflow("record sequence"))?;
    }
    if !saw_end {
        return Err(SendStreamError::MissingStreamEnd);
    }
    Ok((header, records))
}

#[derive(Default)]
struct DecodedSummary {
    total_records: u64,
    total_payload_bytes: u64,
    total_objects: u64,
    snapshot_count: u32,
}

impl DecodedSummary {
    fn observe(&mut self, record: &SendRecord) -> Result<(), SendStreamError> {
        self.total_records = self
            .total_records
            .checked_add(1)
            .ok_or(SendStreamError::LengthOverflow("decoded record count"))?;
        match &record.payload {
            SendRecordPayload::SnapshotBegin(_) => {
                self.snapshot_count = self
                    .snapshot_count
                    .checked_add(1)
                    .ok_or(SendStreamError::LengthOverflow("decoded snapshot count"))?;
            }
            SendRecordPayload::ObjectBegin(_) => {
                self.total_objects = self
                    .total_objects
                    .checked_add(1)
                    .ok_or(SendStreamError::LengthOverflow("decoded object count"))?;
            }
            SendRecordPayload::ObjectWrite(write) => {
                self.total_payload_bytes = self
                    .total_payload_bytes
                    .checked_add(write.payload.len() as u64)
                    .ok_or(SendStreamError::LengthOverflow("decoded payload bytes"))?;
            }
            _ => {}
        }
        Ok(())
    }

    fn verify(&self, end: &StreamEnd) -> Result<(), SendStreamError> {
        if self.total_records != end.total_records {
            return Err(SendStreamError::StreamSummaryMismatch {
                field: "total_records",
                expected: self.total_records,
                actual: end.total_records,
            });
        }
        if self.total_payload_bytes != end.total_payload_bytes {
            return Err(SendStreamError::StreamSummaryMismatch {
                field: "total_payload_bytes",
                expected: self.total_payload_bytes,
                actual: end.total_payload_bytes,
            });
        }
        if self.total_objects != end.total_objects {
            return Err(SendStreamError::StreamSummaryMismatch {
                field: "total_objects",
                expected: self.total_objects,
                actual: end.total_objects,
            });
        }
        if self.snapshot_count != end.snapshot_count {
            return Err(SendStreamError::StreamSummaryMismatch {
                field: "snapshot_count",
                expected: self.snapshot_count as u64,
                actual: end.snapshot_count as u64,
            });
        }
        Ok(())
    }
}

fn encode_record(record: &SendRecord, sequence: u64) -> Result<Vec<u8>, SendStreamError> {
    let payload = record.payload.encode()?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| SendStreamError::LengthOverflow("record payload"))?;
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
    push_u16(&mut out, record.record_type() as u16);
    push_u16(&mut out, record.flags.bits());
    push_u32(&mut out, payload_len);
    push_u64(&mut out, sequence);
    out.extend_from_slice(&record_payload_digest(&payload));
    out.extend_from_slice(&payload);
    Ok(out)
}

fn decode_record(
    bytes: &[u8],
    expected_sequence: u64,
) -> Result<(SendRecord, usize, &[u8]), SendStreamError> {
    if bytes.len() < RECORD_HEADER_LEN {
        return Err(SendStreamError::UnexpectedEof);
    }
    let frame_len;
    let record;
    {
        let mut decoder = Decoder::new(bytes);
        let record_type = SendRecordType::try_from(decoder.read_u16()?)?;
        let flags = RecordFlags::from_bits(decoder.read_u16()?)?;
        let payload_len = decoder.read_len_u32()?;
        let sequence = decoder.read_u64()?;
        if sequence != expected_sequence {
            return Err(SendStreamError::RecordSequenceMismatch {
                expected: expected_sequence,
                actual: sequence,
            });
        }
        let expected_digest = decoder.read_bytes32()?;
        let payload = decoder.read_bytes(payload_len)?;
        let actual_digest = record_payload_digest(payload);
        if actual_digest != expected_digest {
            return Err(SendStreamError::RecordChecksumMismatch);
        }
        let payload = SendRecordPayload::decode(record_type, payload)?;
        record = SendRecord { flags, payload };
        frame_len = RECORD_HEADER_LEN + payload_len;
    }
    Ok((record, frame_len, &bytes[..frame_len]))
}

fn digest_records_until(records: &[SendRecord], end: usize) -> Result<Bytes32, SendStreamError> {
    let mut digest = StreamDigest::new();
    for (index, record) in records.iter().take(end).enumerate() {
        digest.update(&encode_record(record, index as u64)?);
    }
    Ok(digest.finalize())
}

fn encoded_records_len(records: &[SendRecord]) -> Result<u64, SendStreamError> {
    records
        .iter()
        .enumerate()
        .try_fold(0_u64, |sum, (index, record)| {
            let len = encode_record(record, index as u64)?.len() as u64;
            sum.checked_add(len)
                .ok_or(SendStreamError::LengthOverflow("encoded records"))
        })
}

struct StreamDigest(blake3::Hasher);

impl StreamDigest {
    fn new() -> Self {
        Self(blake3::Hasher::new_derive_key(STREAM_DIGEST_CONTEXT))
    }

    fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    fn finalize(&self) -> Bytes32 {
        *self.0.clone().finalize().as_bytes()
    }
}

fn record_payload_digest(payload: &[u8]) -> Bytes32 {
    let mut hasher = blake3::Hasher::new_derive_key(RECORD_DIGEST_CONTEXT);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

fn cursor_digest(cursor: &SendCursor) -> Bytes32 {
    let mut bytes = Vec::new();
    cursor.encode_into(&mut bytes);
    let mut hasher = blake3::Hasher::new_derive_key(CURSOR_DIGEST_CONTEXT);
    hasher.update(&bytes);
    *hasher.finalize().as_bytes()
}

fn root_digest_from_object_digests(
    source_dataset_id: Id128,
    root_id: Id128,
    object_digests: &BTreeMap<Bytes32, Bytes32>,
) -> Bytes32 {
    let mut hasher = blake3::Hasher::new_derive_key(LINEAGE_ROOT_DIGEST_CONTEXT);
    hasher.update(b"base");
    hasher.update(&source_dataset_id);
    hasher.update(&root_id);
    hash_u64(&mut hasher, object_digests.len() as u64);
    for (object_id, digest) in object_digests {
        hasher.update(object_id);
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn target_root_digest_from_snapshots(
    source_dataset_id: Id128,
    target_root_id: Id128,
    snapshots: &[SnapshotDelta],
) -> Result<Bytes32, SendStreamError> {
    let mut hasher = blake3::Hasher::new_derive_key(LINEAGE_ROOT_DIGEST_CONTEXT);
    hasher.update(b"target");
    hasher.update(&source_dataset_id);
    hasher.update(&target_root_id);
    hash_u64(&mut hasher, snapshots.len() as u64);
    for snapshot in snapshots {
        hasher.update(&snapshot.snapshot_id);
        hash_u64(&mut hasher, snapshot.commit_group);
        hash_bytes(&mut hasher, &snapshot.snapshot_name, "snapshot name")?;

        hash_u64(&mut hasher, snapshot.mutations.len() as u64);
        for mutation in &snapshot.mutations {
            hasher.update(&[mutation.kind as u8]);
            hasher.update(&mutation.root_id);
            hash_bytes(
                &mut hasher,
                &mutation.snapshot_name,
                "snapshot mutation name",
            )?;
        }

        let mut objects: Vec<&DeltaObject> = snapshot.objects.iter().collect();
        objects.sort_by_key(|object| object.object_id);
        hash_u64(&mut hasher, objects.len() as u64);
        for object in objects {
            hasher.update(&object.object_id);
            hasher.update(&[object.kind as u8]);
            hash_u64(&mut hasher, object.birth_commit_group);
            hash_bytes(&mut hasher, &object.metadata, "object metadata")?;
            hash_bytes(&mut hasher, &object.payload, "object payload")?;
            hasher.update(&object.digest());
        }

        hash_u64(&mut hasher, snapshot.removed_objects.len() as u64);
        for removed in &snapshot.removed_objects {
            hasher.update(removed);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn hash_bytes(
    hasher: &mut blake3::Hasher,
    bytes: &[u8],
    name: &'static str,
) -> Result<(), SendStreamError> {
    let len = u64::try_from(bytes.len()).map_err(|_| SendStreamError::LengthOverflow(name))?;
    hash_u64(hasher, len);
    hasher.update(bytes);
    Ok(())
}

fn blake3_digest(bytes: &[u8]) -> Bytes32 {
    *blake3::hash(bytes).as_bytes()
}

fn encode_header_extension(header: &SendStreamHeader) -> Result<Vec<u8>, SendStreamError> {
    match header.sender_authority {
        SenderAuthorityEvidence::AbsentLocalOnly => Ok(header.header_extension.clone()),
        SenderAuthorityEvidence::Distributed(authority) => {
            authority.validate()?;
            let opaque_len = u32::try_from(header.header_extension.len())
                .map_err(|_| SendStreamError::LengthOverflow("header extension"))?;
            let mut out = Vec::with_capacity(48 + header.header_extension.len());
            out.extend_from_slice(&SENDER_AUTHORITY_EXTENSION_MAGIC);
            push_u16(&mut out, SENDER_AUTHORITY_EXTENSION_VERSION);
            push_u16(&mut out, 0);
            out.extend_from_slice(&authority.sender_pool_uuid);
            push_u64(&mut out, authority.sender_pool_epoch);
            push_u64(&mut out, authority.sender_membership_generation);
            push_u32(&mut out, opaque_len);
            out.extend_from_slice(&header.header_extension);
            Ok(out)
        }
    }
}

fn decode_header_extension(
    raw: &[u8],
) -> Result<(SenderAuthorityEvidence, Vec<u8>), SendStreamError> {
    if !raw.starts_with(&SENDER_AUTHORITY_EXTENSION_MAGIC) {
        return Ok((SenderAuthorityEvidence::AbsentLocalOnly, raw.to_vec()));
    }

    let mut decoder = Decoder::new(raw);
    decoder.expect_magic(&SENDER_AUTHORITY_EXTENSION_MAGIC)?;
    let version = decoder.read_u16()?;
    if version != SENDER_AUTHORITY_EXTENSION_VERSION {
        return Err(SendStreamError::InvalidHeader(
            "unsupported sender authority extension version",
        ));
    }
    if decoder.read_u16()? != 0 {
        return Err(SendStreamError::InvalidHeader(
            "sender authority extension reserved field is non-zero",
        ));
    }
    let sender_pool_uuid = decoder.read_id128()?;
    let sender_pool_epoch = decoder.read_u64()?;
    let sender_membership_generation = decoder.read_u64()?;
    let opaque_len = decoder.read_len_u32()?;
    let opaque = decoder.read_bytes(opaque_len)?.to_vec();
    decoder.finish()?;

    let authority = SenderAuthority::new(
        sender_pool_uuid,
        sender_pool_epoch,
        sender_membership_generation,
    )?;
    Ok((SenderAuthorityEvidence::Distributed(authority), opaque))
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes_u16(
    out: &mut Vec<u8>,
    bytes: &[u8],
    name: &'static str,
) -> Result<(), SendStreamError> {
    let len = u16::try_from(bytes.len()).map_err(|_| SendStreamError::LengthOverflow(name))?;
    push_u16(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn push_bytes_u32(
    out: &mut Vec<u8>,
    bytes: &[u8],
    name: &'static str,
) -> Result<(), SendStreamError> {
    let len = u32::try_from(bytes.len()).map_err(|_| SendStreamError::LengthOverflow(name))?;
    push_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_magic(&mut self, magic: &[u8]) -> Result<(), SendStreamError> {
        let actual = self.read_bytes(magic.len())?;
        if actual != magic {
            return Err(SendStreamError::BadMagic);
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, SendStreamError> {
        Ok(*self
            .read_bytes(1)?
            .first()
            .ok_or(SendStreamError::UnexpectedEof)?)
    }

    fn read_u16(&mut self) -> Result<u16, SendStreamError> {
        let mut buf = [0; 2];
        buf.copy_from_slice(self.read_bytes(2)?);
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32, SendStreamError> {
        let mut buf = [0; 4];
        buf.copy_from_slice(self.read_bytes(4)?);
        Ok(u32::from_le_bytes(buf))
    }

    fn read_u64(&mut self) -> Result<u64, SendStreamError> {
        let mut buf = [0; 8];
        buf.copy_from_slice(self.read_bytes(8)?);
        Ok(u64::from_le_bytes(buf))
    }

    fn read_id128(&mut self) -> Result<Id128, SendStreamError> {
        let mut id = [0; 16];
        id.copy_from_slice(self.read_bytes(16)?);
        Ok(id)
    }

    fn read_bytes32(&mut self) -> Result<Bytes32, SendStreamError> {
        let mut bytes = [0; 32];
        bytes.copy_from_slice(self.read_bytes(32)?);
        Ok(bytes)
    }

    fn read_len_u32(&mut self) -> Result<usize, SendStreamError> {
        usize::try_from(self.read_u32()?).map_err(|_| SendStreamError::LengthOverflow("u32 length"))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], SendStreamError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SendStreamError::LengthOverflow("decoder offset"))?;
        if end > self.bytes.len() {
            return Err(SendStreamError::UnexpectedEof);
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn read_len_prefixed_u16(&mut self) -> Result<&'a [u8], SendStreamError> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    fn read_len_prefixed_u32(&mut self) -> Result<&'a [u8], SendStreamError> {
        let len = self.read_len_u32()?;
        self.read_bytes(len)
    }

    fn finish(&self) -> Result<(), SendStreamError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SendStreamError::TrailingBytes)
        }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

/// Send stream codec errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendStreamError {
    BadMagic,
    UnsupportedVersion(u16),
    ReservedFlagBits {
        bits: u16,
    },
    InvalidHeader(&'static str),
    UnknownRecordType(u16),
    UnknownObjectKind(u8),
    UnknownSnapshotMutationKind(u8),
    UnexpectedEof,
    TrailingBytes,
    MissingStreamEnd,
    EmptyStream,
    EmptyIncrementalDelta,
    MissingBaseRoot,
    UnpinnedBaseRoot {
        root_id: Id128,
    },
    BaseRootDatasetMismatch {
        expected: Id128,
        actual: Id128,
    },
    BaseRootMismatch {
        expected: Id128,
        actual: Id128,
    },
    LineageManifestMismatch(&'static str),
    LengthOverflow(&'static str),
    RecordChecksumMismatch,
    PayloadChecksumMismatch,
    StreamChecksumMismatch,
    StreamSummaryMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    CursorChecksumMismatch,
    ReceiveProtocol(&'static str),
    ObjectDigestMismatch {
        object_id: Bytes32,
    },
    CursorOutOfRange {
        index: u64,
        records: u64,
    },
    RecordSequenceMismatch {
        expected: u64,
        actual: u64,
    },
}

impl fmt::Display for SendStreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "bad VFSSEND2 stream magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported VFSSEND2 stream version {version}")
            }
            Self::ReservedFlagBits { bits } => write!(f, "reserved flag bits set: 0x{bits:04x}"),
            Self::InvalidHeader(reason) => write!(f, "invalid stream header: {reason}"),
            Self::UnknownRecordType(record_type) => {
                write!(f, "unknown VFSSEND2 record type {record_type}")
            }
            Self::UnknownObjectKind(kind) => write!(f, "unknown VFSSEND2 object kind {kind}"),
            Self::UnknownSnapshotMutationKind(kind) => {
                write!(f, "unknown VFSSEND2 snapshot mutation kind {kind}")
            }
            Self::UnexpectedEof => write!(f, "unexpected end of VFSSEND2 stream"),
            Self::TrailingBytes => write!(f, "trailing bytes in VFSSEND2 payload"),
            Self::MissingStreamEnd => write!(f, "VFSSEND2 stream is missing StreamEnd"),
            Self::EmptyStream => write!(f, "VFSSEND2 stream contains no snapshots"),
            Self::EmptyIncrementalDelta => write!(f, "incremental VFSSEND2 stream has no changes"),
            Self::MissingBaseRoot => {
                write!(f, "incremental VFSSEND2 stream is missing a base root")
            }
            Self::UnpinnedBaseRoot { root_id } => {
                write!(
                    f,
                    "incremental VFSSEND2 base root {} is not pinned",
                    Hex16(root_id)
                )
            }
            Self::BaseRootDatasetMismatch { expected, actual } => write!(
                f,
                "incremental VFSSEND2 base root dataset mismatch: expected {}, got {}",
                Hex16(expected),
                Hex16(actual)
            ),
            Self::BaseRootMismatch { expected, actual } => write!(
                f,
                "incremental VFSSEND2 base root mismatch: expected {}, got {}",
                Hex16(expected),
                Hex16(actual)
            ),
            Self::LineageManifestMismatch(reason) => {
                write!(f, "VFSSEND2 lineage manifest mismatch: {reason}")
            }
            Self::LengthOverflow(field) => write!(f, "VFSSEND2 length overflow in {field}"),
            Self::RecordChecksumMismatch => write!(f, "VFSSEND2 record checksum mismatch"),
            Self::PayloadChecksumMismatch => write!(f, "VFSSEND2 payload checksum mismatch"),
            Self::StreamChecksumMismatch => write!(f, "VFSSEND2 stream checksum mismatch"),
            Self::StreamSummaryMismatch {
                field,
                expected,
                actual,
            } => write!(
                f,
                "VFSSEND2 stream summary mismatch for {field}: expected {expected}, got {actual}"
            ),
            Self::CursorChecksumMismatch => write!(f, "VFSSEND2 cursor checksum mismatch"),
            Self::ReceiveProtocol(reason) => write!(f, "VFSSEND2 receive protocol error: {reason}"),
            Self::ObjectDigestMismatch { object_id } => {
                write!(
                    f,
                    "VFSSEND2 object digest mismatch for {}",
                    Hex32(object_id)
                )
            }
            Self::CursorOutOfRange { index, records } => {
                write!(
                    f,
                    "VFSSEND2 cursor record index {index} exceeds {records} records"
                )
            }
            Self::RecordSequenceMismatch { expected, actual } => write!(
                f,
                "VFSSEND2 record sequence mismatch: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for SendStreamError {}

struct Hex32<'a>(&'a Bytes32);

impl fmt::Display for Hex32<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

struct Hex16<'a>(&'a Id128);

impl fmt::Display for Hex16<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> Id128 {
        [byte; 16]
    }

    fn object_id(byte: u8) -> Bytes32 {
        [byte; 32]
    }

    fn header() -> SendStreamHeader {
        SendStreamHeader::new(id(1), id(2), id(3))
    }

    fn object(byte: u8, payload: &[u8]) -> DeltaObject {
        DeltaObject::new(object_id(byte), ObjectKind::Extent, payload.to_vec())
    }

    #[test]
    fn header_round_trips_with_incremental_flag() {
        let mut header = header().incremental_from(id(9));
        header.features_compat = 0x55;
        header.header_extension = b"resume-cursor".to_vec();
        let encoded = header.encode().unwrap();
        let (decoded, rest) = SendStreamHeader::decode(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, header);
        assert!(decoded.flags.contains(StreamFlags::INCREMENTAL));
    }

    #[test]
    fn header_sender_authority_round_trips_through_extension() {
        let authority = SenderAuthority::new(id(1), 7, 11).unwrap();
        let mut header = header().with_sender_authority(authority);
        header.header_extension = b"opaque-resume-cursor".to_vec();

        let encoded = header.encode().unwrap();
        let (decoded, rest) = SendStreamHeader::decode(&encoded).unwrap();

        assert!(rest.is_empty());
        assert_eq!(decoded.sender_authority.distributed(), Some(authority));
        assert_eq!(decoded.header_extension, b"opaque-resume-cursor");
        assert_eq!(decoded, header);
    }

    #[test]
    fn header_sender_authority_rejects_zero_identity_fields() {
        assert_eq!(
            SenderAuthority::new([0; 16], 7, 11).unwrap_err(),
            SendStreamError::InvalidHeader("sender authority pool uuid must be non-zero")
        );
        assert_eq!(
            SenderAuthority::new(id(1), 0, 11).unwrap_err(),
            SendStreamError::InvalidHeader("sender authority pool epoch must be non-zero")
        );
        assert_eq!(
            SenderAuthority::new(id(1), 7, 0).unwrap_err(),
            SendStreamError::InvalidHeader(
                "sender authority membership generation must be non-zero"
            )
        );
    }

    #[test]
    fn header_sender_authority_rejects_malformed_extension_fields() {
        let authority = SenderAuthority::new(id(1), 7, 11).unwrap();
        let header = header().with_sender_authority(authority);
        let encoded = header.encode().unwrap();
        let extension_start = HEADER_FIXED_LEN;

        let mut zero_pool = encoded.clone();
        zero_pool[extension_start + 12..extension_start + 28].fill(0);
        assert_eq!(
            SendStreamHeader::decode(&zero_pool).unwrap_err(),
            SendStreamError::InvalidHeader("sender authority pool uuid must be non-zero")
        );

        let mut reserved = encoded;
        reserved[extension_start + 10] = 1;
        assert_eq!(
            SendStreamHeader::decode(&reserved).unwrap_err(),
            SendStreamError::InvalidHeader("sender authority extension reserved field is non-zero")
        );
    }

    #[test]
    fn full_send_stream_round_trips_and_verifies_stream_end() {
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        snapshot.objects.push(object(11, b"goodbye"));
        let builder = SendBuilder::full(header(), vec![snapshot]).unwrap();
        let encoded = builder.encode().unwrap();
        let (decoded_header, records) = decode_stream(&encoded).unwrap();
        assert_eq!(decoded_header.to_snapshot_id, id(3));
        assert!(matches!(
            records.last().map(|record| &record.payload),
            Some(SendRecordPayload::StreamEnd(_))
        ));
        assert_eq!(builder.stats().objects_sent, 2);
    }

    #[test]
    fn receive_full_send_reconstructs_dataset() {
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        snapshot.objects.push(object(11, b"goodbye"));
        let encoded = SendBuilder::full(header(), vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();
        let received = ReceiveBuilder::new(id(2), &encoded)
            .unwrap()
            .finish_all()
            .unwrap();
        assert_eq!(
            received.objects.get(&object_id(10)).unwrap().payload,
            b"hello world"
        );
        assert_eq!(
            received.objects.get(&object_id(11)).unwrap().payload,
            b"goodbye"
        );
        assert_eq!(received.snapshots.get(&id(3)).unwrap().object_ids.len(), 2);
    }

    #[test]
    fn snapshot_mutations_round_trip_without_object_payloads() {
        let mut snapshot = SnapshotDelta::promote(id(3), "clone-a", 7, id(40));
        snapshot
            .mutations
            .push(SnapshotMutation::delete(id(41), "old-snap"));

        let builder = SendBuilder::full(header(), vec![snapshot]).unwrap();
        assert_eq!(builder.stats().objects_sent, 0);
        assert_eq!(builder.stats().snapshot_mutations_sent, 2);

        let encoded = builder.encode().unwrap();
        let received = ReceiveBuilder::new(id(2), &encoded)
            .unwrap()
            .finish_all()
            .unwrap();

        assert_eq!(
            received.snapshot_mutations,
            vec![
                SnapshotMutation::promote(id(40), "clone-a"),
                SnapshotMutation::delete(id(41), "old-snap"),
            ]
        );
        assert_eq!(received.snapshots.get(&id(3)).unwrap().object_ids.len(), 0);
    }

    #[test]
    fn mutation_only_incremental_is_not_empty() {
        let mut base = BTreeMap::new();
        base.insert(object_id(10), blake3_digest(b"base"));
        let snapshot = SnapshotDelta::delete(id(3), "old-snap", 9, id(41));

        let builder =
            SendBuilder::incremental(header().incremental_from(id(1)), vec![snapshot], base)
                .unwrap();

        assert_eq!(builder.stats().objects_sent, 0);
        assert_eq!(builder.stats().snapshot_mutations_sent, 1);
        let received = ReceiveBuilder::new(id(2), &builder.encode().unwrap())
            .unwrap()
            .finish_all()
            .unwrap();
        assert_eq!(
            received.snapshot_mutations,
            vec![SnapshotMutation::delete(id(41), "old-snap")]
        );
    }

    #[test]
    fn receive_incremental_merges_into_non_empty_target() {
        let mut base_target = ReceivedDataset::empty(id(2));
        base_target.objects.insert(
            object_id(10),
            ReceivedObject::new(object_id(10), ObjectKind::Extent, b"old".to_vec()),
        );
        base_target.objects.insert(
            object_id(99),
            ReceivedObject::new(object_id(99), ObjectKind::Extent, b"keep".to_vec()),
        );

        let changed = object(10, b"new");
        let mut base = BTreeMap::new();
        base.insert(changed.object_id, blake3_digest(b"old"));
        let mut snapshot = SnapshotDelta::new(id(3), "snap-b", 9);
        snapshot.objects.push(changed);
        snapshot.objects.push(object(12, b"added"));
        let encoded =
            SendBuilder::incremental(header().incremental_from(id(1)), vec![snapshot], base)
                .unwrap()
                .encode()
                .unwrap();
        let received = ReceiveBuilder::new_with_target(base_target, &encoded)
            .unwrap()
            .finish_all()
            .unwrap();

        assert_eq!(
            received.objects.get(&object_id(10)).unwrap().payload,
            b"new"
        );
        assert_eq!(
            received.objects.get(&object_id(12)).unwrap().payload,
            b"added"
        );
        assert_eq!(
            received.objects.get(&object_id(99)).unwrap().payload,
            b"keep"
        );
    }

    #[test]
    fn receive_resume_continues_from_checkpoint() {
        let mut header = header();
        header.checkpoint_interval_records = 3;
        header.max_record_payload = 4;
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"0123456789"));
        snapshot.objects.push(object(11, b"tail"));
        let encoded = SendBuilder::full(header, vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();

        let full = ReceiveBuilder::new(id(2), &encoded)
            .unwrap()
            .finish_all()
            .unwrap();

        let mut partial = ReceiveBuilder::new(id(2), &encoded).unwrap();
        let checkpoint = loop {
            if let ReceiveProgress::ResumePoint(checkpoint) = partial.next_record().unwrap() {
                break checkpoint;
            }
        };
        let staged = partial.staged_dataset().clone();
        let resumed = ReceiveBuilder::resume_from_checkpoint(staged, &encoded, checkpoint)
            .unwrap()
            .finish_all()
            .unwrap();
        assert_eq!(resumed, full);
    }

    #[test]
    fn receive_rejects_corrupt_stream_without_mutating_target() {
        let mut target = ReceivedDataset::empty(id(2));
        target.objects.insert(
            object_id(99),
            ReceivedObject::new(object_id(99), ObjectKind::Extent, b"keep".to_vec()),
        );
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        let mut encoded = SendBuilder::full(header(), vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();
        let last = encoded.len() - 3;
        encoded[last] ^= 0x40;
        let before = target.clone();
        assert!(ReceiveBuilder::new_with_target(target, &encoded).is_err());
        assert_eq!(before.objects.get(&object_id(99)).unwrap().payload, b"keep");
    }

    #[test]
    fn record_payload_corruption_is_rejected() {
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        let encoded = SendBuilder::full(header(), vec![snapshot])
            .unwrap()
            .encode()
            .unwrap();
        let mut corrupted = encoded;
        let last = corrupted.len() - 2;
        corrupted[last] ^= 0x80;
        assert!(matches!(
            decode_stream(&corrupted),
            Err(SendStreamError::RecordChecksumMismatch | SendStreamError::StreamChecksumMismatch)
        ));
    }

    #[test]
    fn stream_end_summary_mismatch_is_rejected() {
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"hello world"));
        let builder = SendBuilder::full(header(), vec![snapshot]).unwrap();
        let mut encoded = builder.header.encode().unwrap();
        let mut digest = StreamDigest::new();
        for (index, record) in builder.records().iter().enumerate() {
            let frame = encode_record(record, index as u64).unwrap();
            digest.update(&frame);
            encoded.extend_from_slice(&frame);
        }
        let wrong_end = SendRecord::new(SendRecordPayload::StreamEnd(StreamEnd {
            total_records: builder.stats().records_sent + 1,
            total_payload_bytes: builder.stats().bytes_sent,
            total_objects: builder.stats().objects_sent,
            snapshot_count: builder.stats().snapshots_sent,
            stream_digest: digest.finalize(),
        }));
        encoded
            .extend_from_slice(&encode_record(&wrong_end, builder.records().len() as u64).unwrap());
        assert!(matches!(
            decode_stream(&encoded),
            Err(SendStreamError::StreamSummaryMismatch {
                field: "total_records",
                ..
            })
        ));
    }

    #[test]
    fn object_write_payload_digest_is_checked_inside_payload() {
        let write = ObjectWrite::new(object_id(1), 0, 0, b"abc".to_vec());
        let mut payload = write.encode_into_vec().unwrap();
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        let mut decoder = Decoder::new(&payload);
        assert_eq!(
            ObjectWrite::decode(&mut decoder).unwrap_err(),
            SendStreamError::PayloadChecksumMismatch
        );
    }

    #[test]
    fn builder_emits_resume_markers_at_record_interval() {
        let mut header = header();
        header.checkpoint_interval_records = 3;
        header.max_record_payload = 4;
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"0123456789"));
        let builder = SendBuilder::full(header, vec![snapshot]).unwrap();
        let marker_count = builder
            .records()
            .iter()
            .filter(|record| matches!(record.payload, SendRecordPayload::ResumeMarker(_)))
            .count();
        assert!(marker_count >= 1);
        assert_eq!(builder.stats().resume_points, marker_count as u64);
    }

    #[test]
    fn incremental_filters_unchanged_objects() {
        let unchanged = object(10, b"same");
        let changed = object(11, b"new");
        let mut base = BTreeMap::new();
        base.insert(unchanged.object_id, unchanged.digest());
        base.insert(changed.object_id, blake3_digest(b"old"));
        let mut snapshot = SnapshotDelta::new(id(3), "snap-b", 9);
        snapshot.objects.push(unchanged);
        snapshot.objects.push(changed);
        let builder =
            SendBuilder::incremental(header().incremental_from(id(2)), vec![snapshot], base)
                .unwrap();
        assert_eq!(builder.stats().objects_sent, 1);
        assert!(builder.records().iter().any(|record| matches!(
            &record.payload,
            SendRecordPayload::ObjectBegin(begin) if begin.object_id == object_id(11)
        )));
        assert!(!builder.records().iter().any(|record| matches!(
            &record.payload,
            SendRecordPayload::ObjectBegin(begin) if begin.object_id == object_id(10)
        )));
    }

    #[test]
    fn incremental_empty_delta_is_rejected() {
        let unchanged = object(10, b"same");
        let mut base = BTreeMap::new();
        base.insert(unchanged.object_id, unchanged.digest());
        let mut snapshot = SnapshotDelta::new(id(3), "snap-b", 9);
        snapshot.objects.push(unchanged);
        assert_eq!(
            SendBuilder::incremental(header().incremental_from(id(2)), vec![snapshot], base)
                .unwrap_err(),
            SendStreamError::EmptyIncrementalDelta
        );
    }

    #[test]
    fn resume_cursor_validates_digest_and_slices_records() {
        let mut header = header();
        header.checkpoint_interval_records = 3;
        header.max_record_payload = 4;
        let mut snapshot = SnapshotDelta::new(id(3), "snap-a", 7);
        snapshot.objects.push(object(10, b"0123456789"));
        let builder = SendBuilder::full(header, vec![snapshot]).unwrap();
        let marker = builder
            .records()
            .iter()
            .find_map(|record| match record.payload {
                SendRecordPayload::ResumeMarker(marker) => Some(marker),
                _ => None,
            })
            .unwrap();
        let resumed = builder.resume_records(&marker.cursor).unwrap();
        assert_eq!(
            resumed.len(),
            builder.records().len() - marker.cursor.record_index as usize
        );
        let mut corrupt = marker.cursor;
        corrupt.stream_digest[0] ^= 1;
        assert_eq!(
            builder.resume_records(&corrupt).unwrap_err(),
            SendStreamError::CursorChecksumMismatch
        );
    }

    fn feature(name: &str) -> FeatureName {
        FeatureName::from_str(name).unwrap()
    }

    fn feature_set(names: &[&str]) -> SendFeatureSet {
        SendFeatureSet::from_names(names.iter().copied()).unwrap()
    }

    #[test]
    fn feature_negotiation_agrees_required_and_supported_optional_features() {
        let request = FeatureNegotiationRequest::new(
            feature_set(&[
                tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2,
                tidefs_types_dataset_feature_flags_core::FEATURE_CHECKSUM_BLAKE3,
            ]),
            feature_set(&[
                tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD,
                tidefs_types_dataset_feature_flags_core::FEATURE_ENCRYPTION_CHACHA20,
            ]),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_NONE | COMPRESSION_ZSTD,
                encryption_algorithms: ENCRYPTION_NONE | ENCRYPTION_CHACHA20_POLY1305,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );
        let target = FeatureSupport::new(
            feature_set(&[
                tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2,
                tidefs_types_dataset_feature_flags_core::FEATURE_CHECKSUM_BLAKE3,
                tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD,
            ]),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_ZSTD,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );

        let mut negotiation = FeatureNegotiation::default();
        let reply = negotiation.negotiate(&request, &target).unwrap();

        assert!(reply.agreed_features.contains(&feature(
            tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2
        )));
        assert!(reply.agreed_features.contains(&feature(
            tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD
        )));
        assert!(!reply.agreed_features.contains(&feature(
            tidefs_types_dataset_feature_flags_core::FEATURE_ENCRYPTION_CHACHA20
        )));
        assert!(reply.refused_features.contains(&feature(
            tidefs_types_dataset_feature_flags_core::FEATURE_ENCRYPTION_CHACHA20
        )));
        assert_eq!(reply.compatibility.compression_algorithms, COMPRESSION_ZSTD);
        assert_eq!(reply.compatibility.encryption_algorithms, ENCRYPTION_NONE);
        assert_eq!(
            negotiation.stats(),
            FeatureNegotiationStats {
                negotiations_attempted: 1,
                negotiations_succeeded: 1,
                required_feature_refusals: 0,
                compatibility_refusals: 0,
            }
        );
    }

    #[test]
    fn feature_negotiation_refuses_missing_required_feature() {
        let request = FeatureNegotiationRequest::new(
            feature_set(&[
                tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2,
                tidefs_types_dataset_feature_flags_core::FEATURE_SNAPSHOT_V2,
            ]),
            SendFeatureSet::new(),
            SendCompatibility::CURRENT,
        );
        let target = FeatureSupport::new(
            feature_set(&[tidefs_types_dataset_feature_flags_core::FEATURE_SNAPSHOT_V2]),
            SendCompatibility::CURRENT,
        );

        let mut negotiation = FeatureNegotiation::default();
        let err = negotiation.negotiate(&request, &target).unwrap_err();

        assert_eq!(
            err,
            FeatureNegotiationError::RequiredFeaturesRefused {
                features: vec![feature(
                    tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2
                )],
            }
        );
        assert_eq!(negotiation.stats().negotiations_attempted, 1);
        assert_eq!(negotiation.stats().required_feature_refusals, 1);
        assert_eq!(negotiation.stats().negotiations_succeeded, 0);
    }

    #[test]
    fn feature_negotiation_refuses_missing_common_algorithm() {
        let request = FeatureNegotiationRequest::new(
            feature_set(&[tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2]),
            SendFeatureSet::new(),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_LZ4,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );
        let target = FeatureSupport::new(
            feature_set(&[tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2]),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_ZSTD,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );

        let mut negotiation = FeatureNegotiation::default();
        let err = negotiation.negotiate(&request, &target).unwrap_err();

        assert_eq!(err, FeatureNegotiationError::NoCommonCompressionAlgorithm);
        assert_eq!(negotiation.stats().compatibility_refusals, 1);
        assert_eq!(negotiation.stats().negotiations_succeeded, 0);
    }

    #[test]
    fn feature_negotiation_request_and_reply_wire_round_trip() {
        let request = FeatureNegotiationRequest::new(
            feature_set(&[tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2]),
            feature_set(&[tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD]),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_NONE | COMPRESSION_ZSTD,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );
        let decoded_request =
            FeatureNegotiationRequest::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(decoded_request, request);

        let target = FeatureSupport::new(
            feature_set(&[
                tidefs_types_dataset_feature_flags_core::FEATURE_SEND_RECV_V2,
                tidefs_types_dataset_feature_flags_core::FEATURE_COMPRESSION_ZSTD,
            ]),
            SendCompatibility {
                record_format_version: STREAM_VERSION,
                compression_algorithms: COMPRESSION_ZSTD,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );
        let mut negotiation = FeatureNegotiation::default();
        let reply = negotiation.negotiate(&decoded_request, &target).unwrap();
        let decoded_reply = FeatureNegotiationReply::decode(&reply.encode().unwrap()).unwrap();

        assert_eq!(decoded_reply, reply);
        assert_eq!(
            decoded_reply.compatibility.compression_algorithms,
            COMPRESSION_ZSTD
        );
    }

    trait ObjectWriteTestExt {
        fn encode_into_vec(&self) -> Result<Vec<u8>, SendStreamError>;
    }

    impl ObjectWriteTestExt for ObjectWrite {
        fn encode_into_vec(&self) -> Result<Vec<u8>, SendStreamError> {
            let mut out = Vec::new();
            self.encode_into(&mut out)?;
            Ok(out)
        }
    }
}
