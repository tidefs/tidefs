// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Sender-side VFSSEND2 session lifecycle helpers.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;

use crate::source_admission::ShipmentKey;
use crate::{
    AgreedCompatibility, Bytes32, FeatureNegotiationError, FeatureNegotiationReply,
    FeatureNegotiationRequest, SendBuilder, SendCursor, SendFeatureSet, SendStreamError,
    SendStreamHeader, SenderAuthority, SenderAuthorityEvidence, StreamFlags,
};

const CHECKPOINT_MAGIC: [u8; 8] = *b"VFSCPT2\0";
const CHECKPOINT_VERSION: u16 = 1;

/// Persisted source-side checkpoint for a committed receiver cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendSessionCheckpoint {
    pub key: ShipmentKey,
    pub cursor: SendCursor,
    pub committed_records: u64,
    pub committed_bytes: u64,
}

impl SendSessionCheckpoint {
    #[must_use]
    pub const fn new(key: ShipmentKey, cursor: SendCursor) -> Self {
        Self {
            key,
            cursor,
            committed_records: cursor.record_index,
            committed_bytes: cursor.stream_offset,
        }
    }

    #[must_use]
    pub const fn stream_digest(&self) -> Bytes32 {
        self.cursor.stream_digest
    }

    /// Encode checkpoint state for a durable store boundary.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 2 + 16 * 4 + 8 * 8 + 32);
        out.extend_from_slice(&CHECKPOINT_MAGIC);
        push_u16(&mut out, CHECKPOINT_VERSION);
        out.extend_from_slice(&self.key.source_pool_id);
        out.extend_from_slice(&self.key.source_dataset_id);
        push_u64(&mut out, self.key.peer_node_id);
        out.extend_from_slice(&self.key.target_snapshot_id);
        out.extend_from_slice(&self.key.stream_id);
        push_u32(&mut out, self.cursor.snapshot_index);
        push_u64(&mut out, self.cursor.object_index);
        push_u64(&mut out, self.cursor.record_index);
        push_u64(&mut out, self.cursor.payload_offset);
        push_u64(&mut out, self.cursor.stream_offset);
        out.extend_from_slice(&self.cursor.stream_digest);
        push_u64(&mut out, self.committed_records);
        push_u64(&mut out, self.committed_bytes);
        out
    }

    /// Decode checkpoint state loaded from a durable store.
    pub fn decode(bytes: &[u8]) -> Result<Self, SenderSessionError> {
        let mut decoder = CheckpointDecoder::new(bytes);
        decoder.expect_magic()?;
        let version = decoder.read_u16()?;
        if version != CHECKPOINT_VERSION {
            return Err(SenderSessionError::UnsupportedCheckpointVersion(version));
        }
        let source_pool_id = decoder.read_id128()?;
        let source_dataset_id = decoder.read_id128()?;
        let peer_node_id = decoder.read_u64()?;
        let target_snapshot_id = decoder.read_id128()?;
        let stream_id = decoder.read_id128()?;
        let cursor = SendCursor {
            snapshot_index: decoder.read_u32()?,
            object_index: decoder.read_u64()?,
            record_index: decoder.read_u64()?,
            payload_offset: decoder.read_u64()?,
            stream_offset: decoder.read_u64()?,
            stream_digest: decoder.read_bytes32()?,
        };
        let committed_records = decoder.read_u64()?;
        let committed_bytes = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self {
            key: ShipmentKey {
                source_pool_id,
                source_dataset_id,
                peer_node_id,
                target_snapshot_id,
                stream_id,
            },
            cursor,
            committed_records,
            committed_bytes,
        })
    }
}

/// Persistence boundary for sender-side committed checkpoints.
pub trait SendCheckpointStore {
    type Error: fmt::Debug;

    fn load_checkpoint(
        &self,
        key: ShipmentKey,
    ) -> Result<Option<SendSessionCheckpoint>, Self::Error>;
    fn persist_checkpoint(&mut self, checkpoint: SendSessionCheckpoint) -> Result<(), Self::Error>;
    fn clear_checkpoint(&mut self, key: ShipmentKey) -> Result<(), Self::Error>;
}

/// In-memory checkpoint store for deterministic harnesses and unit tests.
#[derive(Clone, Debug, Default)]
pub struct InMemorySendCheckpointStore {
    checkpoints: BTreeMap<ShipmentKey, SendSessionCheckpoint>,
}

impl InMemorySendCheckpointStore {
    #[must_use]
    pub fn checkpoints(&self) -> &BTreeMap<ShipmentKey, SendSessionCheckpoint> {
        &self.checkpoints
    }
}

impl SendCheckpointStore for InMemorySendCheckpointStore {
    type Error = Infallible;

    fn load_checkpoint(
        &self,
        key: ShipmentKey,
    ) -> Result<Option<SendSessionCheckpoint>, Self::Error> {
        Ok(self.checkpoints.get(&key).cloned())
    }

    fn persist_checkpoint(&mut self, checkpoint: SendSessionCheckpoint) -> Result<(), Self::Error> {
        self.checkpoints.insert(checkpoint.key, checkpoint);
        Ok(())
    }

    fn clear_checkpoint(&mut self, key: ShipmentKey) -> Result<(), Self::Error> {
        self.checkpoints.remove(&key);
        Ok(())
    }
}

/// Validated feature-negotiation result accepted by the sender.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedFeatureNegotiation {
    pub agreed_features: SendFeatureSet,
    pub compatibility: AgreedCompatibility,
}

/// Resume plan for transport replay after a committed checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendResumePlan {
    pub checkpoint: Option<SendSessionCheckpoint>,
    pub start_offset: usize,
    pub remaining_records: usize,
}

/// Sender-session lifecycle errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SenderSessionError {
    Stream(SendStreamError),
    FeatureNegotiation(FeatureNegotiationError),
    MissingSenderAuthority,
    SenderAuthorityMismatch,
    NegotiationReplyRefusedRequiredFeatures,
    NegotiationReplyMissingRequiredFeatures,
    NegotiationReplyAdvertisedUnsupportedFeature,
    NegotiationReplyInvalidCompatibility,
    UnsupportedCheckpointVersion(u16),
    BadCheckpointMagic,
    TruncatedCheckpoint,
    TrailingCheckpointBytes,
    InvalidResumeCheckpoint(SendStreamError),
}

impl fmt::Display for SenderSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(err) => write!(f, "send-stream error: {err}"),
            Self::FeatureNegotiation(err) => write!(f, "feature negotiation failed: {err}"),
            Self::MissingSenderAuthority => f.write_str("missing distributed sender authority"),
            Self::SenderAuthorityMismatch => f.write_str("sender authority mismatch"),
            Self::NegotiationReplyRefusedRequiredFeatures => {
                f.write_str("feature reply refused a required feature")
            }
            Self::NegotiationReplyMissingRequiredFeatures => {
                f.write_str("feature reply omitted a required feature")
            }
            Self::NegotiationReplyAdvertisedUnsupportedFeature => {
                f.write_str("feature reply agreed to unsupported features")
            }
            Self::NegotiationReplyInvalidCompatibility => {
                f.write_str("feature reply compatibility is not a source-supported subset")
            }
            Self::UnsupportedCheckpointVersion(version) => {
                write!(f, "unsupported sender checkpoint version {version}")
            }
            Self::BadCheckpointMagic => f.write_str("bad sender checkpoint magic"),
            Self::TruncatedCheckpoint => f.write_str("truncated sender checkpoint"),
            Self::TrailingCheckpointBytes => f.write_str("trailing sender checkpoint bytes"),
            Self::InvalidResumeCheckpoint(err) => write!(f, "invalid resume checkpoint: {err}"),
        }
    }
}

impl std::error::Error for SenderSessionError {}

impl From<SendStreamError> for SenderSessionError {
    fn from(err: SendStreamError) -> Self {
        Self::Stream(err)
    }
}

impl From<FeatureNegotiationError> for SenderSessionError {
    fn from(err: FeatureNegotiationError) -> Self {
        Self::FeatureNegotiation(err)
    }
}

/// Error wrapper for checkpoint-store operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CheckpointStoreError<E: fmt::Debug> {
    Store(E),
    Session(SenderSessionError),
}

impl<E: fmt::Debug> fmt::Display for CheckpointStoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(err) => write!(f, "checkpoint store error: {err:?}"),
            Self::Session(err) => write!(f, "{err}"),
        }
    }
}

impl<E: fmt::Debug> std::error::Error for CheckpointStoreError<E> {}

/// Sender-side session controller that owns checkpoint persistence decisions.
#[derive(Clone, Debug)]
pub struct SenderSessionController<S> {
    checkpoint_store: S,
}

impl<S> SenderSessionController<S>
where
    S: SendCheckpointStore,
{
    #[must_use]
    pub const fn new(checkpoint_store: S) -> Self {
        Self { checkpoint_store }
    }

    #[must_use]
    pub const fn checkpoint_store(&self) -> &S {
        &self.checkpoint_store
    }

    #[must_use]
    pub fn checkpoint_store_mut(&mut self) -> &mut S {
        &mut self.checkpoint_store
    }

    pub fn persist_committed_checkpoint(
        &mut self,
        checkpoint: SendSessionCheckpoint,
    ) -> Result<(), CheckpointStoreError<S::Error>> {
        self.checkpoint_store
            .persist_checkpoint(checkpoint)
            .map_err(CheckpointStoreError::Store)
    }

    pub fn clear_checkpoint(
        &mut self,
        key: ShipmentKey,
    ) -> Result<(), CheckpointStoreError<S::Error>> {
        self.checkpoint_store
            .clear_checkpoint(key)
            .map_err(CheckpointStoreError::Store)
    }

    pub fn resume_plan(
        &self,
        key: ShipmentKey,
        builder: &SendBuilder,
    ) -> Result<SendResumePlan, CheckpointStoreError<S::Error>> {
        let checkpoint = self
            .checkpoint_store
            .load_checkpoint(key)
            .map_err(CheckpointStoreError::Store)?;
        match checkpoint {
            Some(checkpoint) => resume_plan_from_checkpoint(builder, checkpoint)
                .map_err(CheckpointStoreError::Session),
            None => Ok(SendResumePlan {
                checkpoint: None,
                start_offset: 0,
                remaining_records: builder.records().len(),
            }),
        }
    }
}

/// Attach sender authority and mark a stream as cross-cluster.
pub fn prepare_distributed_header(
    mut header: SendStreamHeader,
    authority: SenderAuthority,
) -> Result<SendStreamHeader, SenderSessionError> {
    header = header.with_sender_authority(authority);
    header.flags = header.flags.with(StreamFlags::CROSS_CLUSTER);
    header.encode()?;
    Ok(header)
}

/// Receiver-side authority validation helper for the session header.
pub fn validate_sender_authority(
    header: &SendStreamHeader,
    expected: SenderAuthority,
) -> Result<(), SenderSessionError> {
    match header.sender_authority {
        SenderAuthorityEvidence::Distributed(authority) if authority == expected => Ok(()),
        SenderAuthorityEvidence::Distributed(_) => Err(SenderSessionError::SenderAuthorityMismatch),
        SenderAuthorityEvidence::AbsentLocalOnly => Err(SenderSessionError::MissingSenderAuthority),
    }
}

/// Validate a decoded target reply against the request sent by the source.
pub fn validate_feature_reply(
    request: &FeatureNegotiationRequest,
    reply: &FeatureNegotiationReply,
) -> Result<ValidatedFeatureNegotiation, SenderSessionError> {
    if !request
        .required_features
        .intersection(&reply.refused_features)
        .is_empty()
    {
        return Err(SenderSessionError::NegotiationReplyRefusedRequiredFeatures);
    }
    if !request
        .required_features
        .difference(&reply.agreed_features)
        .is_empty()
    {
        return Err(SenderSessionError::NegotiationReplyMissingRequiredFeatures);
    }
    if !reply
        .agreed_features
        .difference(&reply.supported_features)
        .is_empty()
    {
        return Err(SenderSessionError::NegotiationReplyAdvertisedUnsupportedFeature);
    }
    if !compatibility_is_source_subset(request, reply.compatibility) {
        return Err(SenderSessionError::NegotiationReplyInvalidCompatibility);
    }
    Ok(ValidatedFeatureNegotiation {
        agreed_features: reply.agreed_features.clone(),
        compatibility: reply.compatibility,
    })
}

fn resume_plan_from_checkpoint(
    builder: &SendBuilder,
    checkpoint: SendSessionCheckpoint,
) -> Result<SendResumePlan, SenderSessionError> {
    let remaining = builder
        .resume_records(&checkpoint.cursor)
        .map_err(SenderSessionError::InvalidResumeCheckpoint)?;
    let header_len = builder.header().encode()?.len();
    let stream_offset = usize::try_from(checkpoint.cursor.stream_offset)
        .map_err(|_| SendStreamError::LengthOverflow("checkpoint stream offset"))?;
    let start_offset = header_len
        .checked_add(stream_offset)
        .ok_or(SendStreamError::LengthOverflow("checkpoint replay offset"))?;
    Ok(SendResumePlan {
        checkpoint: Some(checkpoint),
        start_offset,
        remaining_records: remaining.len(),
    })
}

fn compatibility_is_source_subset(
    request: &FeatureNegotiationRequest,
    compatibility: AgreedCompatibility,
) -> bool {
    compatibility.record_format_version == request.compatibility.record_format_version
        && compatibility.compression_algorithms != 0
        && compatibility.encryption_algorithms != 0
        && compatibility.checksum_algorithms != 0
        && compatibility.compression_algorithms & !request.compatibility.compression_algorithms == 0
        && compatibility.encryption_algorithms & !request.compatibility.encryption_algorithms == 0
        && compatibility.checksum_algorithms & !request.compatibility.checksum_algorithms == 0
}

#[cfg(feature = "transport")]
pub fn initiate_real_transport_writer(
    handle: tidefs_transport::outbound_send::SendPipelineHandle,
    config: crate::send_stream_adapter::SendStreamSessionConfig,
) -> crate::send_stream_adapter::SendStreamTransportWriter {
    crate::send_stream_adapter::SendStreamSession::new(config).create_writer(handle)
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

struct CheckpointDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CheckpointDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn expect_magic(&mut self) -> Result<(), SenderSessionError> {
        let got = self.read_exact(CHECKPOINT_MAGIC.len())?;
        if got != CHECKPOINT_MAGIC.as_slice() {
            return Err(SenderSessionError::BadCheckpointMagic);
        }
        Ok(())
    }

    fn read_u16(&mut self) -> Result<u16, SenderSessionError> {
        Ok(u16::from_le_bytes(
            self.read_exact(2)?
                .try_into()
                .map_err(|_| SenderSessionError::TruncatedCheckpoint)?,
        ))
    }

    fn read_u32(&mut self) -> Result<u32, SenderSessionError> {
        Ok(u32::from_le_bytes(
            self.read_exact(4)?
                .try_into()
                .map_err(|_| SenderSessionError::TruncatedCheckpoint)?,
        ))
    }

    fn read_u64(&mut self) -> Result<u64, SenderSessionError> {
        Ok(u64::from_le_bytes(
            self.read_exact(8)?
                .try_into()
                .map_err(|_| SenderSessionError::TruncatedCheckpoint)?,
        ))
    }

    fn read_id128(&mut self) -> Result<[u8; 16], SenderSessionError> {
        self.read_exact(16)?
            .try_into()
            .map_err(|_| SenderSessionError::TruncatedCheckpoint)
    }

    fn read_bytes32(&mut self) -> Result<[u8; 32], SenderSessionError> {
        self.read_exact(32)?
            .try_into()
            .map_err(|_| SenderSessionError::TruncatedCheckpoint)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], SenderSessionError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(SenderSessionError::TruncatedCheckpoint)?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(SenderSessionError::TruncatedCheckpoint)?;
        self.pos = end;
        Ok(slice)
    }

    fn finish(&self) -> Result<(), SenderSessionError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(SenderSessionError::TrailingCheckpointBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DeltaObject, FeatureNegotiation, FeatureSupport, ObjectKind, SendCompatibility,
        SendStreamHeader, SnapshotDelta, CHECKSUM_BLAKE3, COMPRESSION_NONE, ENCRYPTION_NONE,
    };

    fn id(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn key() -> ShipmentKey {
        ShipmentKey::new(id(1), id(2), 42, id(3), id(4))
    }

    fn builder_with_checkpoint() -> (SendBuilder, SendCursor) {
        let mut header = SendStreamHeader::new(id(1), id(2), id(3));
        header.checkpoint_interval_records = 2;
        let mut snapshot = SnapshotDelta::new(id(3), b"snap".to_vec(), 1);
        snapshot
            .objects
            .push(DeltaObject::new([9; 32], ObjectKind::File, vec![1; 16]));
        snapshot
            .objects
            .push(DeltaObject::new([8; 32], ObjectKind::File, vec![2; 16]));
        let builder = SendBuilder::full(header, vec![snapshot]).unwrap();
        let cursor = builder
            .records()
            .iter()
            .find_map(|record| match &record.payload {
                crate::SendRecordPayload::ResumeMarker(marker) => Some(marker.cursor),
                _ => None,
            })
            .unwrap();
        (builder, cursor)
    }

    #[test]
    fn checkpoint_roundtrips_through_stable_encoding() {
        let (_builder, cursor) = builder_with_checkpoint();
        let checkpoint = SendSessionCheckpoint::new(key(), cursor);

        let decoded = SendSessionCheckpoint::decode(&checkpoint.encode()).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.stream_digest(), cursor.stream_digest);
    }

    #[test]
    fn resume_plan_skips_acknowledged_records() {
        let (builder, cursor) = builder_with_checkpoint();
        let mut controller = SenderSessionController::new(InMemorySendCheckpointStore::default());
        controller
            .persist_committed_checkpoint(SendSessionCheckpoint::new(key(), cursor))
            .unwrap();

        let plan = controller.resume_plan(key(), &builder).unwrap();
        let checkpoint = plan.checkpoint.unwrap();
        let remaining = builder.resume_records(&checkpoint.cursor).unwrap();

        assert!(plan.start_offset > builder.header().encode().unwrap().len());
        assert_eq!(plan.remaining_records, remaining.len());
        assert!(plan.remaining_records < builder.records().len());
    }

    #[test]
    fn distributed_header_carries_and_validates_sender_authority() {
        let authority = SenderAuthority::new(id(9), 7, 11).unwrap();
        let header =
            prepare_distributed_header(SendStreamHeader::new(id(1), id(2), id(3)), authority)
                .unwrap();

        assert!(header.flags.contains(StreamFlags::CROSS_CLUSTER));
        validate_sender_authority(&header, authority).unwrap();
        assert_eq!(
            validate_sender_authority(&header, SenderAuthority::new(id(8), 7, 11).unwrap())
                .unwrap_err(),
            SenderSessionError::SenderAuthorityMismatch
        );
    }

    #[test]
    fn negotiation_reply_must_cover_required_features() {
        let required = SendFeatureSet::from_names(["org.tidefs.required"]).unwrap();
        let optional = SendFeatureSet::from_names(["org.tidefs.optional"]).unwrap();
        let request =
            FeatureNegotiationRequest::new(required.clone(), optional, SendCompatibility::CURRENT);
        let target = FeatureSupport::new(required, SendCompatibility::CURRENT);
        let mut negotiator = FeatureNegotiation::default();
        let reply = negotiator.negotiate(&request, &target).unwrap();

        let validated = validate_feature_reply(&request, &reply).unwrap();
        assert_eq!(
            validated.compatibility.record_format_version,
            SendCompatibility::CURRENT.record_format_version
        );
    }

    #[test]
    fn negotiation_reply_rejects_bad_compatibility_subset() {
        let request = FeatureNegotiationRequest::new(
            SendFeatureSet::new(),
            SendFeatureSet::new(),
            SendCompatibility {
                record_format_version: crate::STREAM_VERSION,
                compression_algorithms: COMPRESSION_NONE,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        );
        let reply = FeatureNegotiationReply {
            supported_features: SendFeatureSet::new(),
            refused_features: SendFeatureSet::new(),
            agreed_features: SendFeatureSet::new(),
            compatibility: AgreedCompatibility {
                record_format_version: crate::STREAM_VERSION,
                compression_algorithms: COMPRESSION_NONE << 1,
                encryption_algorithms: ENCRYPTION_NONE,
                checksum_algorithms: CHECKSUM_BLAKE3,
            },
        };

        assert_eq!(
            validate_feature_reply(&request, &reply).unwrap_err(),
            SenderSessionError::NegotiationReplyInvalidCompatibility
        );
    }
}
