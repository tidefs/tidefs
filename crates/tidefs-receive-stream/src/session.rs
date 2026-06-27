// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Receiver-side VFSSEND2 session admission, checkpointing, and completion.
//!
//! The session layer is deliberately policy-light: it validates receiver-local
//! evidence before accepting a stream, persists VFSSEND2 receive checkpoints at
//! resume markers, and only returns staged snapshot state after the stream-end
//! record has been decoded and verified by `tidefs-send-stream`.

use std::collections::BTreeMap;
use std::fmt;

use tidefs_send_stream::{
    Bytes32, Id128, ReceiveBuilder, ReceiveCheckpoint, ReceiveProgress, ReceiveStats,
    ReceivedDataset, SendCursor, SendStreamError, SendStreamHeader, SenderAuthority,
    SenderAuthorityEvidence, SnapshotBoundary, StreamFlags,
};

use crate::receive_persistence::{
    validate_receive_contract, BaseRootPinLookup, ReceiveContract, ReceivePersistenceError,
};

const CHECKPOINT_MAGIC: [u8; 8] = *b"VFSRCP2\0";
const CHECKPOINT_VERSION: u16 = 1;

/// Stable sender action suggested by a receiver refusal/defer reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverRecoveryAction {
    /// The sender may choose a full seed when policy/operator input permits it.
    FullSeedFallback,
    /// The sender should retry after ordinary scheduler backoff or retry-after.
    RetryBackoff,
    /// The sender must reject the resume cursor and choose another admission path.
    RejectResume,
    /// The sender must refresh membership/sender-authority evidence before retry.
    RefreshSenderAuthority,
    /// The refusal should be surfaced until operator or policy evidence changes.
    OperatorVisibleRefusal,
}

/// Stable receiver-side refusal/defer classes consumed by snapshot shipping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverRefusalReason {
    /// The receiver does not hold the declared incremental base root.
    ReceiverMissingBase,
    /// The supplied receive checkpoint cannot be matched to the stream.
    ResumeCheckpointInvalid,
    /// The receiver already has exclusive staging state for this dataset/stream.
    ReceiverBusy,
    /// Sender authority is stale for the receiver's membership view.
    SenderAuthorityStale,
    /// Required stream features are unsupported by this receiver.
    UnsupportedFeatures,
    /// Receiver trust, authorization, or local policy rejected the stream.
    ReceiverRejectedPolicy,
    /// The requested resume staging state is absent or superseded.
    ResumeStagingMissing,
}

impl ReceiverRefusalReason {
    /// Return the scheduler-policy reason string associated with this class.
    #[must_use]
    pub const fn scheduler_policy_reason(self) -> &'static str {
        match self {
            Self::ReceiverMissingBase => "receiver_missing_base",
            Self::ResumeCheckpointInvalid => "resume_checkpoint_invalid",
            Self::ReceiverBusy => "receiver_busy",
            Self::SenderAuthorityStale => "sender_authority_stale",
            Self::UnsupportedFeatures | Self::ReceiverRejectedPolicy => "receiver_rejected_policy",
            Self::ResumeStagingMissing => "resume_staging_missing",
        }
    }

    /// Return the stable sender-side action suggested by this reason.
    #[must_use]
    pub const fn recovery_action(self) -> ReceiverRecoveryAction {
        match self {
            Self::ReceiverMissingBase => ReceiverRecoveryAction::FullSeedFallback,
            Self::ResumeCheckpointInvalid | Self::ResumeStagingMissing => {
                ReceiverRecoveryAction::RejectResume
            }
            Self::ReceiverBusy => ReceiverRecoveryAction::RetryBackoff,
            Self::SenderAuthorityStale => ReceiverRecoveryAction::RefreshSenderAuthority,
            Self::UnsupportedFeatures | Self::ReceiverRejectedPolicy => {
                ReceiverRecoveryAction::OperatorVisibleRefusal
            }
        }
    }
}

impl fmt::Display for ReceiverRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.scheduler_policy_reason())
    }
}

/// Receiver evidence attached to a refusal/defer result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiverRefusalEvidence {
    None,
    BaseRoot {
        base_root_identity: Bytes32,
    },
    Checkpoint {
        record_index: u64,
    },
    SenderAuthority {
        sender_pool_uuid: Id128,
        sender_pool_epoch: u64,
        sender_membership_generation: u64,
    },
    UnsupportedFeatures {
        requested_incompat: u64,
        supported_incompat: u64,
    },
    Busy {
        retry_after_millis: Option<u64>,
    },
    Policy {
        reason: &'static str,
    },
}

/// Typed receiver refusal/defer result returned before stream data is accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiverRefusal {
    pub reason: ReceiverRefusalReason,
    pub evidence: ReceiverRefusalEvidence,
}

impl ReceiverRefusal {
    #[must_use]
    pub const fn new(reason: ReceiverRefusalReason, evidence: ReceiverRefusalEvidence) -> Self {
        Self { reason, evidence }
    }

    #[must_use]
    pub const fn policy(reason: &'static str) -> Self {
        Self::new(
            ReceiverRefusalReason::ReceiverRejectedPolicy,
            ReceiverRefusalEvidence::Policy { reason },
        )
    }
}

impl fmt::Display for ReceiverRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:?}); suggested action: {:?}",
            self.reason.scheduler_policy_reason(),
            self.evidence,
            self.reason.recovery_action()
        )
    }
}

impl std::error::Error for ReceiverRefusal {}

/// Receiver-local sender-authority view used during stream admission.
pub trait ReceiverAuthorityView {
    /// Validate the sender authority evidence decoded from the stream header.
    fn validate_sender_authority(
        &self,
        evidence: SenderAuthorityEvidence,
    ) -> Result<(), ReceiverRefusal>;
}

/// Expected sender authority tuple from the receiver's membership view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedSenderAuthority {
    pub sender_pool_uuid: Id128,
    pub min_pool_epoch: u64,
    pub min_membership_generation: u64,
}

/// Static receiver membership view for deterministic admission tests/adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaticReceiverAuthorityView {
    pub expected: Option<ExpectedSenderAuthority>,
    pub allow_local_only: bool,
}

impl StaticReceiverAuthorityView {
    #[must_use]
    pub const fn new(expected: ExpectedSenderAuthority) -> Self {
        Self {
            expected: Some(expected),
            allow_local_only: true,
        }
    }

    #[must_use]
    pub const fn local_only() -> Self {
        Self {
            expected: None,
            allow_local_only: true,
        }
    }

    #[must_use]
    pub const fn with_local_only(mut self, allow: bool) -> Self {
        self.allow_local_only = allow;
        self
    }
}

impl ReceiverAuthorityView for StaticReceiverAuthorityView {
    fn validate_sender_authority(
        &self,
        evidence: SenderAuthorityEvidence,
    ) -> Result<(), ReceiverRefusal> {
        match evidence {
            SenderAuthorityEvidence::AbsentLocalOnly if self.allow_local_only => Ok(()),
            SenderAuthorityEvidence::AbsentLocalOnly => Err(ReceiverRefusal::policy(
                "distributed receive requires sender authority evidence",
            )),
            SenderAuthorityEvidence::Distributed(sender) => {
                validate_sender_against_expected(sender, self.expected)
            }
        }
    }
}

/// Receiver-supported stream feature masks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReceiverFeatureSupport {
    pub features_incompat: u64,
}

impl ReceiverFeatureSupport {
    #[must_use]
    pub const fn new(features_incompat: u64) -> Self {
        Self { features_incompat }
    }

    pub fn validate_header(&self, header: &SendStreamHeader) -> Result<(), ReceiverRefusal> {
        let unsupported = header.features_incompat & !self.features_incompat;
        if unsupported != 0 {
            return Err(ReceiverRefusal::new(
                ReceiverRefusalReason::UnsupportedFeatures,
                ReceiverRefusalEvidence::UnsupportedFeatures {
                    requested_incompat: header.features_incompat,
                    supported_incompat: self.features_incompat,
                },
            ));
        }
        Ok(())
    }
}

/// Admission inputs required before a receiver accepts VFSSEND2 stream data.
pub struct ReceiverAdmission<'a> {
    pub authority_view: &'a dyn ReceiverAuthorityView,
    pub pin_lookup: Option<&'a dyn BaseRootPinLookup>,
    pub incremental_contract: Option<ReceiveContract>,
    pub feature_support: ReceiverFeatureSupport,
    pub staging_busy: bool,
    pub retry_after_millis: Option<u64>,
}

impl<'a> ReceiverAdmission<'a> {
    #[must_use]
    pub fn new(authority_view: &'a dyn ReceiverAuthorityView) -> Self {
        Self {
            authority_view,
            pin_lookup: None,
            incremental_contract: None,
            feature_support: ReceiverFeatureSupport {
                features_incompat: 0,
            },
            staging_busy: false,
            retry_after_millis: None,
        }
    }

    #[must_use]
    pub fn with_pin_lookup(mut self, pin_lookup: &'a dyn BaseRootPinLookup) -> Self {
        self.pin_lookup = Some(pin_lookup);
        self
    }

    #[must_use]
    pub fn with_incremental_contract(mut self, contract: ReceiveContract) -> Self {
        self.incremental_contract = Some(contract);
        self
    }

    #[must_use]
    pub fn with_feature_support(mut self, feature_support: ReceiverFeatureSupport) -> Self {
        self.feature_support = feature_support;
        self
    }

    #[must_use]
    pub fn with_staging_busy(mut self, retry_after_millis: Option<u64>) -> Self {
        self.staging_busy = true;
        self.retry_after_millis = retry_after_millis;
        self
    }

    pub fn validate_for_header(&self, header: &SendStreamHeader) -> Result<(), ReceiverRefusal> {
        if self.staging_busy {
            return Err(ReceiverRefusal::new(
                ReceiverRefusalReason::ReceiverBusy,
                ReceiverRefusalEvidence::Busy {
                    retry_after_millis: self.retry_after_millis,
                },
            ));
        }
        self.feature_support.validate_header(header)?;
        self.authority_view
            .validate_sender_authority(header.sender_authority)?;
        if header.flags.contains(StreamFlags::INCREMENTAL) {
            let contract = self.incremental_contract.ok_or_else(|| {
                ReceiverRefusal::new(
                    ReceiverRefusalReason::ReceiverMissingBase,
                    ReceiverRefusalEvidence::Policy {
                        reason: "incremental receive requires base-root contract evidence",
                    },
                )
            })?;
            let pin_lookup = self.pin_lookup.ok_or_else(|| {
                ReceiverRefusal::new(
                    ReceiverRefusalReason::ReceiverMissingBase,
                    ReceiverRefusalEvidence::BaseRoot {
                        base_root_identity: contract.base_root_identity,
                    },
                )
            })?;
            validate_receive_contract(contract, pin_lookup).map_err(ReceiverRefusal::from)?;
        }
        Ok(())
    }
}

/// Stable key for receiver checkpoint storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ReceiveSessionKey {
    pub source_pool_id: Id128,
    pub source_dataset_id: Id128,
    pub from_snapshot_id: Id128,
    pub to_snapshot_id: Id128,
}

impl ReceiveSessionKey {
    #[must_use]
    pub const fn from_header(header: &SendStreamHeader) -> Self {
        Self {
            source_pool_id: header.source_pool_id,
            source_dataset_id: header.source_dataset_id,
            from_snapshot_id: header.from_snapshot_id,
            to_snapshot_id: header.to_snapshot_id,
        }
    }
}

/// Store error for receiver checkpoint persistence adapters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveCheckpointStoreError {
    message: String,
}

impl ReceiveCheckpointStoreError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ReceiveCheckpointStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReceiveCheckpointStoreError {}

/// Receiver checkpoint persistence boundary.
pub trait ReceiveCheckpointStore {
    fn load_checkpoint(
        &self,
        key: &ReceiveSessionKey,
    ) -> Result<Option<ReceiveCheckpoint>, ReceiveCheckpointStoreError>;

    fn persist_checkpoint(
        &mut self,
        key: &ReceiveSessionKey,
        checkpoint: &ReceiveCheckpoint,
    ) -> Result<(), ReceiveCheckpointStoreError>;

    fn clear_checkpoint(
        &mut self,
        key: &ReceiveSessionKey,
    ) -> Result<(), ReceiveCheckpointStoreError>;
}

/// In-memory checkpoint store used by deterministic receive-session tests.
#[derive(Clone, Debug, Default)]
pub struct InMemoryReceiveCheckpointStore {
    checkpoints: BTreeMap<ReceiveSessionKey, Vec<u8>>,
    persist_count: u64,
}

impl InMemoryReceiveCheckpointStore {
    #[must_use]
    pub fn contains_key(&self, key: &ReceiveSessionKey) -> bool {
        self.checkpoints.contains_key(key)
    }

    #[must_use]
    pub const fn persist_count(&self) -> u64 {
        self.persist_count
    }
}

impl ReceiveCheckpointStore for InMemoryReceiveCheckpointStore {
    fn load_checkpoint(
        &self,
        key: &ReceiveSessionKey,
    ) -> Result<Option<ReceiveCheckpoint>, ReceiveCheckpointStoreError> {
        self.checkpoints
            .get(key)
            .map(|bytes| decode_receive_checkpoint(bytes))
            .transpose()
            .map_err(|err| ReceiveCheckpointStoreError::new(err.to_string()))
    }

    fn persist_checkpoint(
        &mut self,
        key: &ReceiveSessionKey,
        checkpoint: &ReceiveCheckpoint,
    ) -> Result<(), ReceiveCheckpointStoreError> {
        let encoded = encode_receive_checkpoint(checkpoint)
            .map_err(|err| ReceiveCheckpointStoreError::new(err.to_string()))?;
        self.checkpoints.insert(*key, encoded);
        self.persist_count = self
            .persist_count
            .checked_add(1)
            .ok_or_else(|| ReceiveCheckpointStoreError::new("checkpoint persist count overflow"))?;
        Ok(())
    }

    fn clear_checkpoint(
        &mut self,
        key: &ReceiveSessionKey,
    ) -> Result<(), ReceiveCheckpointStoreError> {
        self.checkpoints.remove(key);
        Ok(())
    }
}

/// Checkpoint codec failures for stable receiver resume storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiveCheckpointCodecError {
    Truncated,
    BadMagic { got: [u8; 8] },
    BadVersion { got: u16 },
    InvalidSnapshotPresence(u8),
    LengthOverflow(&'static str),
    TrailingBytes,
}

impl fmt::Display for ReceiveCheckpointCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated receive checkpoint"),
            Self::BadMagic { got } => write!(f, "bad receive checkpoint magic: {got:02x?}"),
            Self::BadVersion { got } => write!(f, "bad receive checkpoint version: {got}"),
            Self::InvalidSnapshotPresence(got) => {
                write!(
                    f,
                    "invalid receive checkpoint snapshot presence byte: {got}"
                )
            }
            Self::LengthOverflow(field) => write!(f, "receive checkpoint length overflow: {field}"),
            Self::TrailingBytes => write!(f, "trailing bytes in receive checkpoint"),
        }
    }
}

impl std::error::Error for ReceiveCheckpointCodecError {}

/// Encode a VFSSEND2 receive checkpoint for durable receiver-side resume.
pub fn encode_receive_checkpoint(
    checkpoint: &ReceiveCheckpoint,
) -> Result<Vec<u8>, ReceiveCheckpointCodecError> {
    let snapshot_name_len = checkpoint
        .active_snapshot
        .as_ref()
        .map(|snapshot| u16::try_from(snapshot.name.len()))
        .transpose()
        .map_err(|_| ReceiveCheckpointCodecError::LengthOverflow("snapshot name"))?;
    let object_count = u32::try_from(checkpoint.active_snapshot_object_ids.len())
        .map_err(|_| ReceiveCheckpointCodecError::LengthOverflow("active snapshot objects"))?;
    let mut out = Vec::new();
    out.extend_from_slice(&CHECKPOINT_MAGIC);
    push_u16(&mut out, CHECKPOINT_VERSION);
    encode_cursor(&mut out, &checkpoint.cursor);
    match (&checkpoint.active_snapshot, snapshot_name_len) {
        (Some(snapshot), Some(name_len)) => {
            out.push(1);
            out.extend_from_slice(&snapshot.snapshot_id);
            push_u64(&mut out, snapshot.commit_group);
            push_u16(&mut out, name_len);
            out.extend_from_slice(&snapshot.name);
        }
        (None, None) => out.push(0),
        _ => return Err(ReceiveCheckpointCodecError::LengthOverflow("snapshot name")),
    }
    push_u32(&mut out, object_count);
    for object_id in &checkpoint.active_snapshot_object_ids {
        out.extend_from_slice(object_id);
    }
    Ok(out)
}

/// Decode a VFSSEND2 receive checkpoint from durable receiver-side storage.
pub fn decode_receive_checkpoint(
    bytes: &[u8],
) -> Result<ReceiveCheckpoint, ReceiveCheckpointCodecError> {
    let mut decoder = CheckpointDecoder::new(bytes);
    let magic = decoder.read_array8()?;
    if magic != CHECKPOINT_MAGIC {
        return Err(ReceiveCheckpointCodecError::BadMagic { got: magic });
    }
    let version = decoder.read_u16()?;
    if version != CHECKPOINT_VERSION {
        return Err(ReceiveCheckpointCodecError::BadVersion { got: version });
    }
    let cursor = decode_cursor(&mut decoder)?;
    let active_snapshot = match decoder.read_u8()? {
        0 => None,
        1 => {
            let snapshot_id = decoder.read_id128()?;
            let commit_group = decoder.read_u64()?;
            let name_len = decoder.read_u16()? as usize;
            let name = decoder.read_bytes(name_len)?.to_vec();
            Some(SnapshotBoundary {
                snapshot_id,
                commit_group,
                name,
            })
        }
        got => return Err(ReceiveCheckpointCodecError::InvalidSnapshotPresence(got)),
    };
    let object_count = usize::try_from(decoder.read_u32()?)
        .map_err(|_| ReceiveCheckpointCodecError::LengthOverflow("object count"))?;
    let mut active_snapshot_object_ids = Vec::with_capacity(object_count);
    for _ in 0..object_count {
        active_snapshot_object_ids.push(decoder.read_bytes32()?);
    }
    decoder.finish()?;
    Ok(ReceiveCheckpoint {
        cursor,
        active_snapshot,
        active_snapshot_object_ids,
    })
}

/// Receiver session errors.
#[derive(Debug)]
pub enum ReceiveSessionError {
    Refused(ReceiverRefusal),
    Stream(SendStreamError),
    CheckpointStore(ReceiveCheckpointStoreError),
}

impl fmt::Display for ReceiveSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "receive refused: {refusal}"),
            Self::Stream(err) => write!(f, "receive stream error: {err}"),
            Self::CheckpointStore(err) => write!(f, "receive checkpoint store error: {err}"),
        }
    }
}

impl std::error::Error for ReceiveSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Refused(err) => Some(err),
            Self::Stream(err) => Some(err),
            Self::CheckpointStore(err) => Some(err),
        }
    }
}

impl From<SendStreamError> for ReceiveSessionError {
    fn from(value: SendStreamError) -> Self {
        Self::Stream(value)
    }
}

impl From<ReceiveCheckpointStoreError> for ReceiveSessionError {
    fn from(value: ReceiveCheckpointStoreError) -> Self {
        Self::CheckpointStore(value)
    }
}

impl From<ReceiverRefusal> for ReceiveSessionError {
    fn from(value: ReceiverRefusal) -> Self {
        Self::Refused(value)
    }
}

/// Completed receiver session result. The staged dataset becomes visible only here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveSessionOutcome {
    pub key: ReceiveSessionKey,
    pub received_dataset: ReceivedDataset,
    pub stats: ReceiveStats,
}

/// Receiver-side VFSSEND2 session executor.
#[derive(Clone, Debug)]
pub struct ReceiveSession {
    builder: ReceiveBuilder,
    key: ReceiveSessionKey,
}

impl ReceiveSession {
    pub fn start(
        target: ReceivedDataset,
        stream: &[u8],
        admission: &ReceiverAdmission<'_>,
    ) -> Result<Self, ReceiveSessionError> {
        let (header, _) = SendStreamHeader::decode(stream).map_err(ReceiveSessionError::Stream)?;
        admission.validate_for_header(&header)?;
        let builder =
            ReceiveBuilder::new_with_target(target, stream).map_err(ReceiveSessionError::Stream)?;
        let key = ReceiveSessionKey::from_header(builder.header());
        Ok(Self { builder, key })
    }

    pub fn resume(
        target: ReceivedDataset,
        stream: &[u8],
        checkpoint: ReceiveCheckpoint,
        admission: &ReceiverAdmission<'_>,
    ) -> Result<Self, ReceiveSessionError> {
        let (header, _) = SendStreamHeader::decode(stream).map_err(ReceiveSessionError::Stream)?;
        admission.validate_for_header(&header)?;
        let builder = ReceiveBuilder::resume_from_checkpoint(target, stream, checkpoint)
            .map_err(map_resume_error)?;
        let key = ReceiveSessionKey::from_header(builder.header());
        Ok(Self { builder, key })
    }

    pub fn resume_from_checkpoint_store(
        target: ReceivedDataset,
        stream: &[u8],
        checkpoint_store: &dyn ReceiveCheckpointStore,
        admission: &ReceiverAdmission<'_>,
    ) -> Result<Self, ReceiveSessionError> {
        let (header, _) = SendStreamHeader::decode(stream).map_err(ReceiveSessionError::Stream)?;
        admission.validate_for_header(&header)?;
        let key = ReceiveSessionKey::from_header(&header);
        let checkpoint = checkpoint_store.load_checkpoint(&key)?.ok_or_else(|| {
            ReceiverRefusal::new(
                ReceiverRefusalReason::ResumeStagingMissing,
                ReceiverRefusalEvidence::Policy {
                    reason: "receiver has no persisted checkpoint for stream",
                },
            )
        })?;
        let builder = ReceiveBuilder::resume_from_checkpoint(target, stream, checkpoint)
            .map_err(map_resume_error)?;
        Ok(Self { builder, key })
    }

    #[must_use]
    pub const fn key(&self) -> ReceiveSessionKey {
        self.key
    }

    pub fn run_to_completion(
        &mut self,
        checkpoint_store: &mut dyn ReceiveCheckpointStore,
    ) -> Result<ReceiveSessionOutcome, ReceiveSessionError> {
        loop {
            match self
                .builder
                .next_record()
                .map_err(ReceiveSessionError::Stream)?
            {
                ReceiveProgress::Continue
                | ReceiveProgress::ObjectReceived { .. }
                | ReceiveProgress::SnapshotReceived { .. } => {}
                ReceiveProgress::ResumePoint(checkpoint) => {
                    checkpoint_store.persist_checkpoint(&self.key, &checkpoint)?;
                }
                ReceiveProgress::StreamComplete(stats) => {
                    checkpoint_store.clear_checkpoint(&self.key)?;
                    return Ok(ReceiveSessionOutcome {
                        key: self.key,
                        received_dataset: self.builder.staged_dataset().clone(),
                        stats,
                    });
                }
            }
        }
    }
}

impl From<ReceivePersistenceError> for ReceiverRefusal {
    fn from(error: ReceivePersistenceError) -> Self {
        match error {
            ReceivePersistenceError::BaseRootNotPinned { base_root_identity }
            | ReceivePersistenceError::DatasetLineageUnavailable { base_root_identity } => {
                Self::new(
                    ReceiverRefusalReason::ReceiverMissingBase,
                    ReceiverRefusalEvidence::BaseRoot { base_root_identity },
                )
            }
            ReceivePersistenceError::DatasetLineageMismatch { .. } => Self::new(
                ReceiverRefusalReason::ReceiverMissingBase,
                ReceiverRefusalEvidence::Policy {
                    reason: "base root lineage does not match receiver authority",
                },
            ),
            ReceivePersistenceError::ReceiveGenerationReplayed {
                receive_generation, ..
            } => Self::new(
                ReceiverRefusalReason::ResumeCheckpointInvalid,
                ReceiverRefusalEvidence::Checkpoint {
                    record_index: receive_generation,
                },
            ),
            ReceivePersistenceError::ContractNotValidated
            | ReceivePersistenceError::ContractRequired
            | ReceivePersistenceError::Store(_) => {
                Self::policy("receiver persistence contract rejected the stream")
            }
        }
    }
}

fn validate_sender_against_expected(
    sender: SenderAuthority,
    expected: Option<ExpectedSenderAuthority>,
) -> Result<(), ReceiverRefusal> {
    let Some(expected) = expected else {
        return Err(ReceiverRefusal::policy(
            "receiver has no membership evidence for distributed sender",
        ));
    };
    if sender.sender_pool_uuid != expected.sender_pool_uuid {
        return Err(ReceiverRefusal::policy(
            "sender pool uuid is not admitted by receiver membership",
        ));
    }
    if sender.sender_pool_epoch < expected.min_pool_epoch
        || sender.sender_membership_generation < expected.min_membership_generation
    {
        return Err(ReceiverRefusal::new(
            ReceiverRefusalReason::SenderAuthorityStale,
            ReceiverRefusalEvidence::SenderAuthority {
                sender_pool_uuid: sender.sender_pool_uuid,
                sender_pool_epoch: sender.sender_pool_epoch,
                sender_membership_generation: sender.sender_membership_generation,
            },
        ));
    }
    Ok(())
}

fn map_resume_error(error: SendStreamError) -> ReceiveSessionError {
    match error {
        SendStreamError::CursorChecksumMismatch | SendStreamError::CursorOutOfRange { .. } => {
            ReceiveSessionError::Refused(ReceiverRefusal::new(
                ReceiverRefusalReason::ResumeCheckpointInvalid,
                ReceiverRefusalEvidence::Policy {
                    reason: "checkpoint cursor does not match stream prefix",
                },
            ))
        }
        other => ReceiveSessionError::Stream(other),
    }
}

fn encode_cursor(out: &mut Vec<u8>, cursor: &SendCursor) {
    push_u32(out, cursor.snapshot_index);
    push_u64(out, cursor.object_index);
    push_u64(out, cursor.record_index);
    push_u64(out, cursor.payload_offset);
    push_u64(out, cursor.stream_offset);
    out.extend_from_slice(&cursor.stream_digest);
}

fn decode_cursor(
    decoder: &mut CheckpointDecoder<'_>,
) -> Result<SendCursor, ReceiveCheckpointCodecError> {
    Ok(SendCursor {
        snapshot_index: decoder.read_u32()?,
        object_index: decoder.read_u64()?,
        record_index: decoder.read_u64()?,
        payload_offset: decoder.read_u64()?,
        stream_offset: decoder.read_u64()?,
        stream_digest: decoder.read_bytes32()?,
    })
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
    offset: usize,
}

impl<'a> CheckpointDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ReceiveCheckpointCodecError> {
        Ok(*self
            .read_bytes(1)?
            .first()
            .ok_or(ReceiveCheckpointCodecError::Truncated)?)
    }

    fn read_u16(&mut self) -> Result<u16, ReceiveCheckpointCodecError> {
        Ok(u16::from_le_bytes(
            self.read_bytes(2)?
                .try_into()
                .map_err(|_| ReceiveCheckpointCodecError::Truncated)?,
        ))
    }

    fn read_u32(&mut self) -> Result<u32, ReceiveCheckpointCodecError> {
        Ok(u32::from_le_bytes(
            self.read_bytes(4)?
                .try_into()
                .map_err(|_| ReceiveCheckpointCodecError::Truncated)?,
        ))
    }

    fn read_u64(&mut self) -> Result<u64, ReceiveCheckpointCodecError> {
        Ok(u64::from_le_bytes(
            self.read_bytes(8)?
                .try_into()
                .map_err(|_| ReceiveCheckpointCodecError::Truncated)?,
        ))
    }

    fn read_array8(&mut self) -> Result<[u8; 8], ReceiveCheckpointCodecError> {
        self.read_bytes(8)?
            .try_into()
            .map_err(|_| ReceiveCheckpointCodecError::Truncated)
    }

    fn read_id128(&mut self) -> Result<Id128, ReceiveCheckpointCodecError> {
        self.read_bytes(16)?
            .try_into()
            .map_err(|_| ReceiveCheckpointCodecError::Truncated)
    }

    fn read_bytes32(&mut self) -> Result<Bytes32, ReceiveCheckpointCodecError> {
        self.read_bytes(32)?
            .try_into()
            .map_err(|_| ReceiveCheckpointCodecError::Truncated)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ReceiveCheckpointCodecError> {
        let end =
            self.offset
                .checked_add(len)
                .ok_or(ReceiveCheckpointCodecError::LengthOverflow(
                    "decoder offset",
                ))?;
        if end > self.bytes.len() {
            return Err(ReceiveCheckpointCodecError::Truncated);
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), ReceiveCheckpointCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ReceiveCheckpointCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tidefs_send_stream::{
        DeltaObject, ObjectKind, PinnedBaseRoot, SendBuilder, SendStreamHeader, SenderAuthority,
        SnapshotDelta,
    };

    use super::*;

    #[derive(Default)]
    struct StubPinLookup {
        pinned: BTreeMap<Bytes32, Bytes32>,
        completed: BTreeMap<(Bytes32, Bytes32), u64>,
    }

    impl StubPinLookup {
        fn pin(&mut self, base: Bytes32, lineage: Bytes32) {
            self.pinned.insert(base, lineage);
        }
    }

    impl BaseRootPinLookup for StubPinLookup {
        fn is_base_root_pinned(&self, base_root_identity: &Bytes32) -> bool {
            self.pinned.contains_key(base_root_identity)
        }

        fn dataset_lineage_for_base_root(&self, base_root_identity: &Bytes32) -> Option<Bytes32> {
            self.pinned.get(base_root_identity).copied()
        }

        fn latest_completed_receive_generation(
            &self,
            base_root_identity: &Bytes32,
            dataset_lineage_identity: &Bytes32,
        ) -> Option<u64> {
            self.completed
                .get(&(*base_root_identity, *dataset_lineage_identity))
                .copied()
        }
    }

    fn id(byte: u8) -> Id128 {
        [byte; 16]
    }

    fn digest(byte: u8) -> Bytes32 {
        [byte; 32]
    }

    fn full_stream(header: SendStreamHeader) -> Vec<u8> {
        let mut snapshot = SnapshotDelta::new(header.to_snapshot_id, "snap", 1);
        snapshot.objects.push(DeltaObject::new(
            digest(0xA0),
            ObjectKind::Inode,
            b"payload".to_vec(),
        ));
        SendBuilder::full(header, vec![snapshot])
            .expect("build stream")
            .encode()
            .expect("encode stream")
    }

    fn incremental_stream(header: SendStreamHeader, base_root: PinnedBaseRoot) -> Vec<u8> {
        let mut snapshot = SnapshotDelta::new(header.to_snapshot_id, "snap", 1);
        snapshot.objects.push(DeltaObject::new(
            digest(0xA1),
            ObjectKind::Inode,
            b"incremental".to_vec(),
        ));
        SendBuilder::incremental_from_base(header, vec![snapshot], base_root)
            .expect("build incremental stream")
            .encode()
            .expect("encode incremental stream")
    }

    #[test]
    fn stale_sender_authority_refuses_before_receive() {
        let authority = SenderAuthority::new(id(1), 4, 7).expect("authority");
        let header = SendStreamHeader::new(id(1), id(2), id(3)).with_sender_authority(authority);
        let stream = full_stream(header);
        let view = StaticReceiverAuthorityView::new(ExpectedSenderAuthority {
            sender_pool_uuid: id(1),
            min_pool_epoch: 5,
            min_membership_generation: 7,
        });
        let admission = ReceiverAdmission::new(&view);

        let err =
            ReceiveSession::start(ReceivedDataset::empty(id(2)), &stream, &admission).unwrap_err();

        assert!(matches!(
            err,
            ReceiveSessionError::Refused(ReceiverRefusal {
                reason: ReceiverRefusalReason::SenderAuthorityStale,
                ..
            })
        ));
    }

    #[test]
    fn incremental_missing_base_refuses_with_full_seed_action() {
        let header = SendStreamHeader::new(id(1), id(2), id(3)).incremental_from(id(4));
        let base_root = PinnedBaseRoot::new(id(2), id(4), digest(0xB0), BTreeMap::new(), true);
        let stream = incremental_stream(header, base_root);
        let view = StaticReceiverAuthorityView::local_only();
        let pin_lookup = StubPinLookup::default();
        let contract = ReceiveContract {
            base_root_identity: digest(0xB0),
            dataset_lineage_identity: digest(0xC0),
            receive_generation: 1,
        };
        let admission = ReceiverAdmission::new(&view)
            .with_pin_lookup(&pin_lookup)
            .with_incremental_contract(contract);

        let err =
            ReceiveSession::start(ReceivedDataset::empty(id(2)), &stream, &admission).unwrap_err();

        match err {
            ReceiveSessionError::Refused(refusal) => {
                assert_eq!(refusal.reason, ReceiverRefusalReason::ReceiverMissingBase);
                assert_eq!(
                    refusal.reason.recovery_action(),
                    ReceiverRecoveryAction::FullSeedFallback
                );
            }
            other => panic!("expected receiver refusal, got {other:?}"),
        }
    }

    #[test]
    fn run_to_completion_persists_and_clears_checkpoints() {
        let mut header = SendStreamHeader::new(id(1), id(2), id(3));
        header.checkpoint_interval_records = 1;
        let stream = full_stream(header);
        let view = StaticReceiverAuthorityView::local_only();
        let admission = ReceiverAdmission::new(&view);
        let mut session = ReceiveSession::start(ReceivedDataset::empty(id(2)), &stream, &admission)
            .expect("start session");
        let key = session.key();
        let mut store = InMemoryReceiveCheckpointStore::default();

        let outcome = session
            .run_to_completion(&mut store)
            .expect("run session to completion");

        assert_eq!(outcome.stats.objects_received, 1);
        assert!(outcome.stats.validation_passed);
        assert!(store.persist_count() > 0);
        assert!(!store.contains_key(&key));
    }

    #[test]
    fn checkpoint_codec_roundtrips_active_snapshot() {
        let checkpoint = ReceiveCheckpoint {
            cursor: SendCursor {
                snapshot_index: 1,
                object_index: 2,
                record_index: 3,
                payload_offset: 4,
                stream_offset: 5,
                stream_digest: digest(0xD0),
            },
            active_snapshot: Some(SnapshotBoundary::new(id(6), 7, b"snap".to_vec())),
            active_snapshot_object_ids: vec![digest(0xE0), digest(0xE1)],
        };

        let encoded = encode_receive_checkpoint(&checkpoint).expect("encode");
        let decoded = decode_receive_checkpoint(&encoded).expect("decode");

        assert_eq!(decoded, checkpoint);
    }

    #[test]
    fn bad_resume_checkpoint_maps_to_typed_refusal() {
        let mut header = SendStreamHeader::new(id(1), id(2), id(3));
        header.checkpoint_interval_records = 1;
        let stream = full_stream(header);
        let view = StaticReceiverAuthorityView::local_only();
        let admission = ReceiverAdmission::new(&view);
        let checkpoint = ReceiveCheckpoint {
            cursor: SendCursor {
                snapshot_index: 0,
                object_index: 0,
                record_index: 1,
                payload_offset: 0,
                stream_offset: 0,
                stream_digest: digest(0xFF),
            },
            active_snapshot: None,
            active_snapshot_object_ids: Vec::new(),
        };

        let err = ReceiveSession::resume(
            ReceivedDataset::empty(id(2)),
            &stream,
            checkpoint,
            &admission,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ReceiveSessionError::Refused(ReceiverRefusal {
                reason: ReceiverRefusalReason::ResumeCheckpointInvalid,
                ..
            })
        ));
    }

    #[test]
    fn resume_from_store_refuses_missing_staging() {
        let stream = full_stream(SendStreamHeader::new(id(1), id(2), id(3)));
        let view = StaticReceiverAuthorityView::local_only();
        let admission = ReceiverAdmission::new(&view);
        let store = InMemoryReceiveCheckpointStore::default();

        let err = ReceiveSession::resume_from_checkpoint_store(
            ReceivedDataset::empty(id(2)),
            &stream,
            &store,
            &admission,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ReceiveSessionError::Refused(ReceiverRefusal {
                reason: ReceiverRefusalReason::ResumeStagingMissing,
                ..
            })
        ));
    }

    #[test]
    fn resume_from_store_loads_persisted_checkpoint() {
        let mut header = SendStreamHeader::new(id(1), id(2), id(3));
        header.checkpoint_interval_records = 1;
        let stream = full_stream(header);
        let view = StaticReceiverAuthorityView::local_only();
        let admission = ReceiverAdmission::new(&view);
        let mut session = ReceiveSession::start(ReceivedDataset::empty(id(2)), &stream, &admission)
            .expect("start session");
        let key = session.key();
        let mut store = InMemoryReceiveCheckpointStore::default();

        loop {
            match session.builder.next_record().expect("advance receive") {
                ReceiveProgress::ResumePoint(checkpoint) => {
                    store
                        .persist_checkpoint(&key, &checkpoint)
                        .expect("persist checkpoint");
                    break;
                }
                ReceiveProgress::StreamComplete(_) => panic!("stream completed before checkpoint"),
                ReceiveProgress::Continue
                | ReceiveProgress::ObjectReceived { .. }
                | ReceiveProgress::SnapshotReceived { .. } => {}
            }
        }

        let resumed = ReceiveSession::resume_from_checkpoint_store(
            ReceivedDataset::empty(id(2)),
            &stream,
            &store,
            &admission,
        )
        .expect("resume from persisted checkpoint");

        assert_eq!(resumed.key(), key);
    }

    #[test]
    fn valid_incremental_contract_admits_session() {
        let header = SendStreamHeader::new(id(1), id(2), id(3)).incremental_from(id(4));
        let base_root = PinnedBaseRoot::new(id(2), id(4), digest(0xB1), BTreeMap::new(), true);
        let stream = incremental_stream(header, base_root);
        let view = StaticReceiverAuthorityView::local_only();
        let mut pin_lookup = StubPinLookup::default();
        pin_lookup.pin(digest(0xB1), digest(0xC1));
        let contract = ReceiveContract {
            base_root_identity: digest(0xB1),
            dataset_lineage_identity: digest(0xC1),
            receive_generation: 1,
        };
        let admission = ReceiverAdmission::new(&view)
            .with_pin_lookup(&pin_lookup)
            .with_incremental_contract(contract);

        ReceiveSession::start(ReceivedDataset::empty(id(2)), &stream, &admission)
            .expect("incremental session admitted");
    }
}
