#![forbid(unsafe_code)]

//! LOCK service protocol and phase-1 runtime.
//!
//! This crate provides the transport-facing service surface for the
//! cluster-wide lock service (`service_id = 0x0A`). It deliberately reuses the
//! lease domains, lock table, owner identities, and Raft command model from
//! `tidefs-lease` so the service does not create a second lock authority.

pub mod posix_lock;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use tidefs_lease::{
    LeaseClass, LeaseDomain, LeaseGrant, LockMethod, LockOwner, LockStatus, LockTable,
    PendingLockRequest, RaftCommand, RangeLockType,
};
pub use tidefs_membership_epoch::{EpochId, MemberId};

pub use tidefs_lease::{
    LeaseClass as ServiceLeaseClass, LeaseDomain as ServiceLeaseDomain,
    LeaseGrant as ServiceLeaseGrant, LockMethod as ServiceLockMethod,
    LockOwner as ServiceLockOwner, LockStatus as ServiceLockStatus,
    RangeLockType as ServiceRangeLockType,
};

/// Stable transport service id for the LOCK protocol.
pub const LOCK_SERVICE_ID: u8 = 0x0A;
/// Current LOCK frame format version.
pub const LOCK_FRAME_VERSION: u8 = 1;
/// Length of the fixed frame header.
pub const LOCK_FRAME_HEADER_LEN: usize = 24;
const LOCK_FRAME_MAGIC: [u8; 4] = *b"VLCK";

const DEFAULT_TERM_MILLIS: u64 = 30_000;
/// Unique identifier for a specific dataset mount instance.
///
/// Changes across unmount/remount cycles, ensuring advisory locks
/// from different mounts are isolated even when inode numbers collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DatasetMountId(pub u64);

impl DatasetMountId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
}

const DEFAULT_PENDING_TIMEOUT_MILLIS: u64 = 30_000;

/// Direction class for a LOCK frame payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LockMessageKind {
    Request = 0,
    Response = 1,
    Event = 2,
}

impl LockMessageKind {
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Request),
            1 => Some(Self::Response),
            2 => Some(Self::Event),
            _ => None,
        }
    }

    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Richer operation result used by non-ACQUIRE methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LockServiceStatus {
    Granted = 0,
    Renewed = 1,
    Released = 2,
    DeniedConflict = 3,
    DeniedFenced = 4,
    DeniedQuota = 5,
    DeniedNotLeader = 6,
    Queued = 7,
    NotFound = 8,
    InvalidRequest = 9,
}

impl From<LockStatus> for LockServiceStatus {
    fn from(value: LockStatus) -> Self {
        match value {
            LockStatus::Granted => Self::Granted,
            LockStatus::DeniedConflict => Self::DeniedConflict,
            LockStatus::DeniedFenced => Self::DeniedFenced,
            LockStatus::DeniedQuota => Self::DeniedQuota,
            LockStatus::DeniedNotLeader => Self::DeniedNotLeader,
            LockStatus::Queued => Self::Queued,
        }
    }
}

/// Logical target for lock-service acquisition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseTarget {
    Pool {
        pool_id: u64,
    },
    Dataset {
        dataset_id: u64,
    },
    Directory {
        dataset_id: u64,
        prefix: String,
    },
    Inode {
        dataset_id: u64,
        ino: u64,
        parent_lease_id: u64,
    },
    ByteRange {
        dataset_id: u64,
        ino: u64,
        start: u64,
        len: u64,
    },
}

impl LeaseTarget {
    pub fn to_domain(&self) -> LeaseDomain {
        match self {
            Self::Pool { pool_id } => LeaseDomain::MembershipReconfig {
                config_id: *pool_id,
            },
            Self::Dataset { dataset_id } => LeaseDomain::Subtree {
                dataset_id: *dataset_id,
                prefix: "/".to_string(),
            },
            Self::Directory { dataset_id, prefix } => LeaseDomain::Subtree {
                dataset_id: *dataset_id,
                prefix: canonical_prefix(prefix),
            },
            Self::Inode {
                dataset_id, ino, ..
            } => LeaseDomain::Inode {
                dataset_id: *dataset_id,
                ino: *ino,
            },
            Self::ByteRange {
                dataset_id,
                ino,
                start,
                len,
            } => LeaseDomain::ByteRange {
                dataset_id: *dataset_id,
                ino: *ino,
                start: *start,
                end: range_end(*start, *len),
            },
        }
    }

    pub fn dataset_inode(&self) -> Option<(u64, u64)> {
        match self {
            Self::Inode {
                dataset_id, ino, ..
            }
            | Self::ByteRange {
                dataset_id, ino, ..
            } => Some((*dataset_id, *ino)),
            _ => None,
        }
    }
}

/// Public lock mode used by clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum LockMode {
    None = 0,
    Shared = 1,
    Exclusive = 2,
}

impl LockMode {
    pub const fn to_lease_class(self) -> LeaseClass {
        match self {
            Self::None | Self::Shared => LeaseClass::Shared,
            Self::Exclusive => LeaseClass::Exclusive,
        }
    }

    pub const fn to_range_type(self) -> RangeLockType {
        match self {
            Self::None | Self::Shared => RangeLockType::Read,
            Self::Exclusive => RangeLockType::Write,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireRequest {
    pub target: LeaseTarget,
    pub mode: LockMode,
    pub owner: LockOwner,
    pub dataset_mount_id: DatasetMountId,
    pub term: u64,
    pub epoch: EpochId,
    pub requested_term_millis: u64,
    pub blocking: bool,
    pub callback_opaque: u64,
}

impl AcquireRequest {
    pub fn new(
        target: LeaseTarget,
        mode: LockMode,
        owner: LockOwner,
        dataset_mount_id: DatasetMountId,
        term: u64,
        epoch: EpochId,
    ) -> Self {
        Self {
            target,
            mode,
            owner,
            dataset_mount_id,
            term,
            epoch,
            requested_term_millis: 0,
            blocking: false,
            callback_opaque: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireAck {
    pub status: LockStatus,
    pub lease_id: u64,
    pub dataset_mount_id: DatasetMountId,
    pub target: LeaseTarget,
    pub mode: LockMode,
    pub term: u64,
    pub epoch: EpochId,
    pub expires_at_millis: u64,
    pub conflict_holder: Option<MemberId>,
    pub conflict_lease_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewRequest {
    pub lease_id: u64,
    pub holder: MemberId,
    pub term: u64,
    pub epoch: EpochId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewAck {
    pub lease_id: u64,
    pub status: LockServiceStatus,
    pub expires_at_millis: u64,
    pub version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub lease_id: u64,
    pub owner: LockOwner,
    pub dataset_mount_id: DatasetMountId,
    pub epoch: EpochId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAck {
    pub lease_id: u64,
    pub status: LockServiceStatus,
}

/// Request to release all locks scoped to a dataset mount identity.
/// Sent on unmount or forced unmount to clean up stale locks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmountRequest {
    pub dataset_mount_id: DatasetMountId,
    pub epoch: EpochId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnmountAck {
    pub dataset_mount_id: DatasetMountId,
    pub released: u32,
    pub status: LockServiceStatus,
}


#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RecallReason {
    ConflictUpgrade = 0,
    LeaseExpiry = 1,
    AdminRevoke = 2,
    MembershipChange = 3,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallEvent {
    pub lease_id: u64,
    pub reason: RecallReason,
    pub deadline_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseIdAck {
    pub lease_id: u64,
    pub status: LockServiceStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetlkRequest {
    pub dataset_id: u64,
    pub dataset_mount_id: DatasetMountId,
    pub ino: u64,
    pub owner: LockOwner,
    pub lock_type: RangeLockType,
    pub start: u64,
    pub len: u64,
    pub term: u64,
    pub epoch: EpochId,
}

impl GetlkRequest {
    fn domain(&self) -> LeaseDomain {
        LeaseDomain::ByteRange {
            dataset_id: self.dataset_id,
            ino: self.ino,
            start: self.start,
            end: range_end(self.start, self.len),
        }
    }

    fn requested_class(&self) -> LeaseClass {
        match self.lock_type {
            RangeLockType::Read => LeaseClass::Shared,
            RangeLockType::Write => LeaseClass::Exclusive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetlkAck {
    pub status: LockServiceStatus,
    pub conflict: Option<ConflictInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetlkRequest {
    pub dataset_id: u64,
    pub dataset_mount_id: DatasetMountId,
    pub ino: u64,
    pub owner: LockOwner,
    pub lock_type: RangeLockType,
    pub start: u64,
    pub len: u64,
    pub term: u64,
    pub epoch: EpochId,
    pub blocking: bool,
    pub callback_opaque: u64,
}

impl SetlkRequest {
    fn target(&self) -> LeaseTarget {
        LeaseTarget::ByteRange {
            dataset_id: self.dataset_id,
            ino: self.ino,
            start: self.start,
            len: self.len,
        }
    }

    fn mode(&self) -> LockMode {
        match self.lock_type {
            RangeLockType::Read => LockMode::Shared,
            RangeLockType::Write => LockMode::Exclusive,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetlkAck {
    pub status: LockServiceStatus,
    pub lock_id: u64,
    pub conflict: Option<ConflictInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockGrantEvent {
    pub request_id: u64,
    pub lease_id: u64,
    pub callback_opaque: u64,
    pub expires_at_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallAllEvent {
    pub term: u64,
    pub epoch: EpochId,
    pub reason: RecallReason,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallAllAck {
    pub node_id: MemberId,
    pub released: u32,
    pub epoch: EpochId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictInfo {
    pub lease_id: u64,
    pub holder: MemberId,
    pub target: LeaseTarget,
    pub mode: LockMode,
}

/// Method-specific LOCK service payloads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockPayload {
    Acquire(AcquireRequest),
    AcquireAck(AcquireAck),
    Renew(RenewRequest),
    RenewAck(RenewAck),
    Release(ReleaseRequest),
    ReleaseAck(ReleaseAck),
    Recall(RecallEvent),
    RecallAck(LeaseIdAck),
    Break(RecallEvent),
    BreakAck(LeaseIdAck),
    Getlk(GetlkRequest),
    GetlkAck(GetlkAck),
    Setlk(SetlkRequest),
    Setlkw(SetlkRequest),
    SetlkAck(SetlkAck),
    LockGrantEvent(LockGrantEvent),
    RecallAll(RecallAllEvent),
    RecallAllAck(RecallAllAck),
    Unmount(UnmountRequest),
    UnmountAck(UnmountAck),
}

impl LockPayload {
    pub const fn method(&self) -> LockMethod {
        match self {
            Self::Acquire(_) => LockMethod::Acquire,
            Self::AcquireAck(_) => LockMethod::AcquireAck,
            Self::Renew(_) => LockMethod::Renew,
            Self::RenewAck(_) => LockMethod::RenewAck,
            Self::Release(_) => LockMethod::Release,
            Self::ReleaseAck(_) => LockMethod::ReleaseAck,
            Self::Recall(_) => LockMethod::Recall,
            Self::RecallAck(_) => LockMethod::RecallAck,
            Self::Break(_) => LockMethod::Break,
            Self::BreakAck(_) => LockMethod::BreakAck,
            Self::Getlk(_) => LockMethod::Getlk,
            Self::GetlkAck(_) => LockMethod::GetlkAck,
            Self::Setlk(_) => LockMethod::Setlk,
            Self::Setlkw(_) => LockMethod::Setlkw,
            Self::SetlkAck(_) => LockMethod::SetlkAck,
            Self::LockGrantEvent(_) => LockMethod::LockGrantEvent,
            Self::RecallAll(_) => LockMethod::RecallAll,
            Self::RecallAllAck(_) => LockMethod::RecallAllAck,
            Self::Unmount(_) | Self::UnmountAck(_) => LockMethod::Unmount,
        }
    }

    pub const fn kind(&self) -> LockMessageKind {
        match self {
            Self::Acquire(_)
            | Self::Renew(_)
            | Self::Release(_)
            | Self::Getlk(_)
            | Self::Setlk(_)
            | Self::Setlkw(_)
            | Self::Unmount(_) => LockMessageKind::Request,
            Self::AcquireAck(_)
            | Self::RenewAck(_)
            | Self::ReleaseAck(_)
            | Self::RecallAck(_)
            | Self::BreakAck(_)
            | Self::GetlkAck(_)
            | Self::SetlkAck(_)
            | Self::RecallAllAck(_)
            | Self::UnmountAck(_) => LockMessageKind::Response,
            Self::Recall(_) | Self::Break(_) | Self::LockGrantEvent(_) | Self::RecallAll(_) => {
                LockMessageKind::Event
            }
        }
    }
}

/// Full LOCK service frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockFrame {
    pub kind: LockMessageKind,
    pub method: LockMethod,
    pub op_id: u64,
    pub flags: u16,
    pub payload: LockPayload,
}

impl LockFrame {
    pub fn new(op_id: u64, payload: LockPayload) -> Self {
        Self {
            kind: payload.kind(),
            method: payload.method(),
            op_id,
            flags: 0,
            payload,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, LockServiceError> {
        if self.method != self.payload.method() {
            return Err(LockServiceError::PayloadMismatch {
                reason: format!(
                    "LOCK method/payload mismatch: header {:?}, payload {:?}",
                    self.method,
                    self.payload.method()
                ),
            });
        }
        if self.kind != self.payload.kind() {
            return Err(LockServiceError::PayloadMismatch {
                reason: format!(
                    "LOCK kind/payload mismatch: header {:?}, payload {:?}",
                    self.kind,
                    self.payload.kind()
                ),
            });
        }

        let body = bincode::serialize(&self.payload)?;
        if body.len() > u32::MAX as usize {
            return Err(LockServiceError::Frame {
                reason: format!("LOCK body is too large: {} bytes", body.len()),
            });
        }

        let mut out = Vec::with_capacity(LOCK_FRAME_HEADER_LEN + body.len());
        out.extend_from_slice(&LOCK_FRAME_MAGIC);
        out.push(LOCK_SERVICE_ID);
        out.push(LOCK_FRAME_VERSION);
        out.push(self.kind.to_u8());
        out.push(self.method.to_u8());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&0_u16.to_le_bytes());
        out.extend_from_slice(&self.op_id.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LockServiceError> {
        if bytes.len() < LOCK_FRAME_HEADER_LEN {
            return Err(LockServiceError::Frame {
                reason: "frame too short".into(),
            });
        }
        if bytes[0..4] != LOCK_FRAME_MAGIC {
            return Err(LockServiceError::Frame {
                reason: "frame magic mismatch".into(),
            });
        }
        let service_id = bytes[4];
        if service_id != LOCK_SERVICE_ID {
            return Err(LockServiceError::Frame {
                reason: format!("unexpected LOCK service id {service_id:#04x}"),
            });
        }
        let version = bytes[5];
        if version != LOCK_FRAME_VERSION {
            return Err(LockServiceError::Frame {
                reason: format!("unsupported LOCK frame version {version}"),
            });
        }
        let kind = LockMessageKind::from_u8(bytes[6]).ok_or(LockServiceError::Frame {
            reason: format!("unknown LOCK message kind {}", bytes[6]),
        })?;
        let method = LockMethod::from_u8(bytes[7]).ok_or(LockServiceError::Frame {
            reason: format!("unknown LOCK method {:#04x}", bytes[7]),
        })?;
        let flags = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed slice"));
        let reserved = u16::from_le_bytes(bytes[10..12].try_into().expect("fixed slice"));
        if reserved != 0 {
            return Err(LockServiceError::Frame {
                reason: "LOCK reserved header field is non-zero".into(),
            });
        }
        let op_id = u64::from_le_bytes(bytes[12..20].try_into().expect("fixed slice"));
        let body_len = u32::from_le_bytes(bytes[20..24].try_into().expect("fixed slice")) as usize;
        let expected_len =
            LOCK_FRAME_HEADER_LEN
                .checked_add(body_len)
                .ok_or(LockServiceError::Frame {
                    reason: "LOCK frame length overflow".into(),
                })?;
        if bytes.len() != expected_len {
            return Err(LockServiceError::Frame {
                reason: format!(
                    "LOCK frame length mismatch: expected {}, actual {}",
                    expected_len,
                    bytes.len()
                ),
            });
        }
        let payload: LockPayload = bincode::deserialize(&bytes[LOCK_FRAME_HEADER_LEN..])?;
        if payload.method() != method {
            return Err(LockServiceError::PayloadMismatch {
                reason: format!(
                    "LOCK method/payload mismatch: header {:?}, payload {:?}",
                    method,
                    payload.method()
                ),
            });
        }
        if payload.kind() != kind {
            return Err(LockServiceError::PayloadMismatch {
                reason: format!(
                    "LOCK kind/payload mismatch: header {:?}, payload {:?}",
                    kind,
                    payload.kind()
                ),
            });
        }
        Ok(Self {
            kind,
            method,
            op_id,
            flags,
            payload,
        })
    }
}

/// Trait implemented by transport adapters that can carry encoded LOCK frames.
pub trait LockFrameSink {
    fn send_lock_frame(&mut self, peer: MemberId, frame: Vec<u8>) -> Result<(), LockServiceError>;
}

/// Small transport adapter that serializes frames before handing them to a sink.
pub struct LockServiceTransport<S> {
    sink: S,
}

impl<S> LockServiceTransport<S> {
    pub fn new(sink: S) -> Self {
        Self { sink }
    }

    pub fn into_inner(self) -> S {
        self.sink
    }
}

impl<S: LockFrameSink> LockServiceTransport<S> {
    pub fn send(&mut self, peer: MemberId, frame: &LockFrame) -> Result<(), LockServiceError> {
        self.sink.send_lock_frame(peer, frame.encode()?)
    }
}

/// In-memory sink used by deterministic userspace tests and harnesses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueuedLockFrameSink {
    frames: VecDeque<(MemberId, Vec<u8>)>,
}

impl QueuedLockFrameSink {
    pub fn pop(&mut self) -> Option<(MemberId, Vec<u8>)> {
        self.frames.pop_front()
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl LockFrameSink for QueuedLockFrameSink {
    fn send_lock_frame(&mut self, peer: MemberId, frame: Vec<u8>) -> Result<(), LockServiceError> {
        self.frames.push_back((peer, frame));
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockServiceConfig {
    pub current_term: u64,
    pub current_epoch: EpochId,
    pub default_term_millis: u64,
    pub pending_timeout_millis: u64,
    pub witness_set_id: u64,
    pub witness_confirmations: usize,
    pub witness_total: usize,
}

impl Default for LockServiceConfig {
    fn default() -> Self {
        Self {
            current_term: 1,
            current_epoch: EpochId::new(1),
            default_term_millis: DEFAULT_TERM_MILLIS,
            pending_timeout_millis: DEFAULT_PENDING_TIMEOUT_MILLIS,
            witness_set_id: 1,
            witness_confirmations: 1,
            witness_total: 1,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LockServiceStats {
    pub frames_handled: u64,
    pub grants: u64,
    pub conflicts: u64,
    pub queued: u64,
    pub renewals: u64,
    pub releases: u64,
    pub recalls: u64,
    pub breaks: u64,
}

/// Phase-1 LOCK service leader.
///
/// The leader is a synchronous userspace runtime over `tidefs-lease::LockTable`.
/// It applies the same `RaftCommand` model the future replicated leader will
/// persist, but does not itself implement Raft networking.
#[derive(Clone, Debug)]
pub struct LockServiceLeader {
    table: LockTable,
    config: LockServiceConfig,
    next_lease_id: u64,
    stats: LockServiceStats,
}

impl LockServiceLeader {
    pub fn new(config: LockServiceConfig) -> Self {
        let table = LockTable::new(config.current_term, config.current_epoch);
        Self {
            table,
            config,
            next_lease_id: 1,
            stats: LockServiceStats::default(),
        }
    }

    pub fn table(&self) -> &LockTable {
        &self.table
    }

    pub fn stats(&self) -> &LockServiceStats {
        &self.stats
    }

    pub fn handle_frame(
        &mut self,
        frame: LockFrame,
        now_millis: u64,
    ) -> Result<Option<LockFrame>, LockServiceError> {
        self.stats.frames_handled = self.stats.frames_handled.saturating_add(1);
        let op_id = frame.op_id;
        let response = match frame.payload {
            LockPayload::Acquire(request) => Some(LockPayload::AcquireAck(
                self.acquire(op_id, request, now_millis),
            )),
            LockPayload::Renew(request) => {
                Some(LockPayload::RenewAck(self.renew(request, now_millis)))
            }
            LockPayload::Release(request) => Some(LockPayload::ReleaseAck(self.release(request))),
            LockPayload::Getlk(request) => Some(LockPayload::GetlkAck(self.getlk(request))),
            LockPayload::Setlk(request) => Some(LockPayload::SetlkAck(
                self.setlk(op_id, request, now_millis, false),
            )),
            LockPayload::Setlkw(request) => Some(LockPayload::SetlkAck(
                self.setlk(op_id, request, now_millis, true),
            )),
            LockPayload::RecallAck(ack) => {
                if ack.status == LockServiceStatus::Released {
                    self.table.apply(&RaftCommand::Release {
                        lease_id: ack.lease_id,
                    });
                    self.stats.recalls = self.stats.recalls.saturating_add(1);
                }
                None
            }
            LockPayload::BreakAck(ack) => {
                if ack.status == LockServiceStatus::Released {
                    self.stats.breaks = self.stats.breaks.saturating_add(1);
                }
                None
            }
            LockPayload::RecallAllAck(_) => None,
            payload => {
                return Err(LockServiceError::PayloadMismatch {
                    reason: format!(
                        "unexpected LOCK payload for service dispatch: {:?}",
                        payload.method()
                    ),
                });
            }
        };
        Ok(response.map(|payload| LockFrame::new(op_id, payload)))
    }

    pub fn acquire(&mut self, op_id: u64, request: AcquireRequest, now_millis: u64) -> AcquireAck {
        if !self.table.validate_fencing(request.term, request.epoch) {
            return AcquireAck {
                status: LockStatus::DeniedFenced,
                lease_id: 0,
                dataset_mount_id: request.dataset_mount_id,
                target: request.target,
                mode: request.mode,
                term: self.table.current_term(),
                epoch: self.table.current_epoch(),
                expires_at_millis: 0,
                conflict_holder: None,
                conflict_lease_id: None,
            };
        }

        let domain = request.target.to_domain();
        let lease_class = request.mode.to_lease_class();
        if let Some(conflict_id) = self.table.check_conflict(&domain, lease_class) {
            let conflict_holder = self.table.get_grant(conflict_id).map(|g| g.holder_id);
            self.stats.conflicts = self.stats.conflicts.saturating_add(1);
            if request.blocking {
                if let Some((dataset_id, ino)) = request.target.dataset_inode() {
                    let pending = PendingLockRequest {
                        request_id: op_id,
                        owner: request.owner,
                        domain,
                        lease_class,
                        enqueued_at_millis: now_millis,
                        timeout_millis: self.config.pending_timeout_millis,
                        callback_node_id: request.owner.node_id,
                        callback_opaque: request.callback_opaque,
                    };
                    if self.table.enqueue_pending(dataset_id, ino, pending).is_ok() {
                        self.stats.queued = self.stats.queued.saturating_add(1);
                        return AcquireAck {
                            status: LockStatus::Queued,
                            lease_id: 0,
                            dataset_mount_id: request.dataset_mount_id,
                            target: request.target,
                            mode: request.mode,
                            term: self.table.current_term(),
                            epoch: self.table.current_epoch(),
                            expires_at_millis: 0,
                            conflict_holder,
                            conflict_lease_id: Some(conflict_id),
                        };
                    }
                    return AcquireAck {
                        status: LockStatus::DeniedQuota,
                        lease_id: 0,
                        dataset_mount_id: request.dataset_mount_id,
                        target: request.target,
                        mode: request.mode,
                        term: self.table.current_term(),
                        epoch: self.table.current_epoch(),
                        expires_at_millis: 0,
                        conflict_holder,
                        conflict_lease_id: Some(conflict_id),
                    };
                }
            }

            return AcquireAck {
                status: LockStatus::DeniedConflict,
                lease_id: 0,
                dataset_mount_id: request.dataset_mount_id,
                target: request.target,
                mode: request.mode,
                term: self.table.current_term(),
                epoch: self.table.current_epoch(),
                expires_at_millis: 0,
                conflict_holder,
                conflict_lease_id: Some(conflict_id),
            };
        }

        let lease_id = self.allocate_lease_id();
        let term_millis = if request.requested_term_millis == 0 {
            self.config.default_term_millis
        } else {
            request.requested_term_millis
        };
        let grant = LeaseGrant::request(
            lease_id,
            lease_class,
            domain,
            request.owner.node_id,
            request.dataset_mount_id.0,
            term_millis,
            now_millis,
            request.epoch,
            self.config.witness_set_id,
            self.config.witness_confirmations,
            self.config.witness_total,
        );
        let expires_at_millis = grant.expires_at_millis;
        self.table.apply(&RaftCommand::Grant { grant });
        self.stats.grants = self.stats.grants.saturating_add(1);
        AcquireAck {
            status: LockStatus::Granted,
            lease_id,
            dataset_mount_id: request.dataset_mount_id,
            target: request.target,
            mode: request.mode,
            term: self.table.current_term(),
            epoch: self.table.current_epoch(),
            expires_at_millis,
            conflict_holder: None,
            conflict_lease_id: None,
        }
    }

    pub fn renew(&mut self, request: RenewRequest, now_millis: u64) -> RenewAck {
        if !self.table.validate_fencing(request.term, request.epoch) {
            return RenewAck {
                lease_id: request.lease_id,
                status: LockServiceStatus::DeniedFenced,
                expires_at_millis: 0,
                version: 0,
            };
        }
        let Some(grant) = self.table.get_grant(request.lease_id).cloned() else {
            return RenewAck {
                lease_id: request.lease_id,
                status: LockServiceStatus::NotFound,
                expires_at_millis: 0,
                version: 0,
            };
        };
        if grant.holder_id != request.holder || grant.lifecycle.is_terminal() {
            return RenewAck {
                lease_id: request.lease_id,
                status: LockServiceStatus::DeniedFenced,
                expires_at_millis: 0,
                version: grant.version,
            };
        }
        let version = grant.version.saturating_add(1);
        let expires_at_millis = now_millis.saturating_add(grant.term_millis);
        self.table.apply(&RaftCommand::Renew {
            lease_id: request.lease_id,
            new_expires_at_millis: expires_at_millis,
            version,
        });
        self.stats.renewals = self.stats.renewals.saturating_add(1);
        RenewAck {
            lease_id: request.lease_id,
            status: LockServiceStatus::Renewed,
            expires_at_millis,
            version,
        }
    }

    pub fn release(&mut self, request: ReleaseRequest) -> ReleaseAck {
        let Some(grant) = self.table.get_grant(request.lease_id) else {
            return ReleaseAck {
                lease_id: request.lease_id,
                status: LockServiceStatus::NotFound,
            };
        };
        if grant.holder_id != request.owner.node_id || grant.epoch != request.epoch {
            return ReleaseAck {
                lease_id: request.lease_id,
                status: LockServiceStatus::DeniedFenced,
            };
        }
        self.table.apply(&RaftCommand::Release {
            lease_id: request.lease_id,
        });
        self.stats.releases = self.stats.releases.saturating_add(1);
        ReleaseAck {
            lease_id: request.lease_id,
            status: LockServiceStatus::Released,
        }
    }

    pub fn getlk(&self, request: GetlkRequest) -> GetlkAck {
        if !self.table.validate_fencing(request.term, request.epoch) {
            return GetlkAck {
                status: LockServiceStatus::DeniedFenced,
                conflict: None,
            };
        }
        let conflict = self
            .table
            .check_conflict(&request.domain(), request.requested_class())
            .and_then(|lease_id| self.conflict_info(lease_id));
        GetlkAck {
            status: if conflict.is_some() {
                LockServiceStatus::DeniedConflict
            } else {
                LockServiceStatus::Granted
            },
            conflict,
        }
    }

    pub fn setlk(
        &mut self,
        op_id: u64,
        request: SetlkRequest,
        now_millis: u64,
        force_blocking: bool,
    ) -> SetlkAck {
        let mut acquire = AcquireRequest::new(
            request.target(),
            request.mode(),
            request.owner,
            request.dataset_mount_id,
            request.term,
            request.epoch,
        );
        acquire.blocking = force_blocking || request.blocking;
        acquire.callback_opaque = request.callback_opaque;
        let ack = self.acquire(op_id, acquire, now_millis);
        SetlkAck {
            status: LockServiceStatus::from(ack.status),
            lock_id: ack.lease_id,
            conflict: ack.conflict_lease_id.and_then(|id| self.conflict_info(id)),
        }
    }

    pub fn recall(
        &mut self,
        lease_id: u64,
        reason: RecallReason,
        deadline_millis: u64,
    ) -> LockFrame {
        LockFrame::new(
            lease_id,
            LockPayload::Recall(RecallEvent {
                lease_id,
                reason,
                deadline_millis,
            }),
        )
    }

    pub fn break_lease(&mut self, lease_id: u64, reason: RecallReason) -> LockFrame {
        self.table.apply(&RaftCommand::Break { lease_id });
        self.stats.breaks = self.stats.breaks.saturating_add(1);
        LockFrame::new(
            lease_id,
            LockPayload::Break(RecallEvent {
                lease_id,
                reason,
                deadline_millis: 0,
            }),
        )
    }

    /// Release every lock and pending request scoped to a dataset mount
    /// identity. Used on unmount or forced unmount.
    pub fn unmount_mount(&mut self, dataset_mount_id: DatasetMountId, epoch: EpochId) -> UnmountAck {
        let released = self.table.release_by_mount(dataset_mount_id.0, epoch);
        UnmountAck {
            dataset_mount_id,
            released,
            status: LockServiceStatus::Released,
        }
    }

    pub fn sweep_pending(&mut self, now_millis: u64) -> Vec<(u64, u64, MemberId, u64)> {
        self.table.sweep_pending(now_millis)
    }

    fn allocate_lease_id(&mut self) -> u64 {
        let lease_id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.saturating_add(1).max(1);
        lease_id
    }

    fn conflict_info(&self, lease_id: u64) -> Option<ConflictInfo> {
        let grant = self.table.get_grant(lease_id)?;
        Some(ConflictInfo {
            lease_id,
            holder: grant.holder_id,
            target: target_from_domain(&grant.domain),
            mode: mode_from_class(grant.lease_class),
        })
    }
}

/// Local client-side handle used by FUSE/VFS frontends.
#[derive(Clone, Debug)]
pub struct LockServiceHandle {
    owner: LockOwner,
    next_op_id: u64,
    held: BTreeMap<u64, LeaseGrant>,
}

impl LockServiceHandle {
    pub fn new(owner: LockOwner) -> Self {
        Self {
            owner,
            next_op_id: 1,
            held: BTreeMap::new(),
        }
    }

    pub fn owner(&self) -> LockOwner {
        self.owner
    }

    pub fn build_acquire(
        &mut self,
        target: LeaseTarget,
        mode: LockMode,
        term: u64,
        epoch: EpochId,
    ) -> LockFrame {
        let op_id = self.next_op_id();
        LockFrame::new(
            op_id,
            LockPayload::Acquire(AcquireRequest::new(target, mode, self.owner, DatasetMountId(0), term, epoch)),
        )
    }

    pub fn build_release(&mut self, lease_id: u64, epoch: EpochId) -> LockFrame {
        let op_id = self.next_op_id();
        LockFrame::new(
            op_id,
            LockPayload::Release(ReleaseRequest {
                lease_id,
                owner: self.owner,
                dataset_mount_id: DatasetMountId(0),
                epoch,
            }),
        )
    }

    pub fn accept_grant(&mut self, grant: LeaseGrant) {
        self.held.insert(grant.lease_id, grant);
    }

    pub fn accept_acquire_ack(&mut self, ack: &AcquireAck, now_millis: u64) {
        if ack.status != LockStatus::Granted || ack.lease_id == 0 {
            return;
        }
        let grant = LeaseGrant::request(
            ack.lease_id,
            ack.mode.to_lease_class(),
            ack.target.to_domain(),
            self.owner.node_id,
            ack.dataset_mount_id.0,
            ack.expires_at_millis.saturating_sub(now_millis),
            now_millis,
            ack.epoch,
            0,
            1,
            1,
        );
        self.held.insert(ack.lease_id, grant);
    }

    pub fn accept_release_ack(&mut self, ack: &ReleaseAck) {
        if ack.status == LockServiceStatus::Released {
            self.held.remove(&ack.lease_id);
        }
    }

    pub fn held_lease_ids(&self) -> Vec<u64> {
        self.held.keys().copied().collect()
    }

    fn next_op_id(&mut self) -> u64 {
        let op_id = self.next_op_id;
        self.next_op_id = self.next_op_id.saturating_add(1).max(1);
        op_id
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockServiceError {
    #[error("LOCK frame error: {reason}")]
    Frame { reason: String },
    #[error("LOCK payload mismatch: {reason}")]
    PayloadMismatch { reason: String },
    #[error("LOCK bincode error: {0}")]
    Bincode(#[from] bincode::Error),
    #[error("lock queue is full")]
    QueueFull,
    #[error("lock not found")]
    NotFound,
    #[error("lock is not upgradeable (conflicting locks or not a shared lock)")]
    NotUpgradeable,
    #[error("lock is not downgradeable (not an exclusive lock)")]
    NotDowngradeable,
    #[error("deadlock detected")]
    Deadlock,
    #[error("stale epoch: lock epoch {lock_epoch:?} != current {current_epoch:?}")]
    StaleEpoch {
        lock_epoch: EpochId,
        current_epoch: EpochId,
    },
}

fn canonical_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix == "/" {
        return "/".to_string();
    }
    let mut out = String::with_capacity(prefix.len() + 2);
    if !prefix.starts_with('/') {
        out.push('/');
    }
    out.push_str(prefix);
    if !out.ends_with('/') {
        out.push('/');
    }
    out
}

fn range_end(start: u64, len: u64) -> u64 {
    start.saturating_add(len)
}

fn mode_from_class(class: LeaseClass) -> LockMode {
    match class {
        LeaseClass::Exclusive => LockMode::Exclusive,
        LeaseClass::Shared | LeaseClass::Staging => LockMode::Shared,
    }
}

fn target_from_domain(domain: &LeaseDomain) -> LeaseTarget {
    match domain {
        LeaseDomain::Subtree { dataset_id, prefix } => LeaseTarget::Directory {
            dataset_id: *dataset_id,
            prefix: prefix.clone(),
        },
        LeaseDomain::Inode { dataset_id, ino } => LeaseTarget::Inode {
            dataset_id: *dataset_id,
            ino: *ino,
            parent_lease_id: 0,
        },
        LeaseDomain::ByteRange {
            dataset_id,
            ino,
            start,
            end,
        } => LeaseTarget::ByteRange {
            dataset_id: *dataset_id,
            ino: *ino,
            start: *start,
            len: end.saturating_sub(*start),
        },
        LeaseDomain::MembershipReconfig { config_id } => LeaseTarget::Pool {
            pool_id: *config_id,
        },
        _ => LeaseTarget::Dataset { dataset_id: 0 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(node: u64, pid: u32, key: u64) -> LockOwner {
        LockOwner::new(MemberId::new(node), pid, key)
    }

    fn leader() -> LockServiceLeader {
        LockServiceLeader::new(LockServiceConfig::default())
    }

    fn sample_payloads() -> Vec<LockPayload> {
        let owner = owner(7, 42, 9001);
        vec![
            LockPayload::Acquire(AcquireRequest::new(
                LeaseTarget::Directory {
                    dataset_id: 1,
                    prefix: "/data".into(),
                },
                LockMode::Exclusive,
                owner,
                DatasetMountId(1),
                1,
                EpochId::new(1),
            )),
            LockPayload::AcquireAck(AcquireAck {
                status: LockStatus::Granted,
                lease_id: 1,
                dataset_mount_id: DatasetMountId(1),
                target: LeaseTarget::Directory {
                    dataset_id: 1,
                    prefix: "/data/".into(),
                },
                mode: LockMode::Exclusive,
                term: 1,
                epoch: EpochId::new(1),
                expires_at_millis: 30_000,
                conflict_holder: None,
                conflict_lease_id: None,
            }),
            LockPayload::Renew(RenewRequest {
                lease_id: 1,
                holder: MemberId::new(7),
                term: 1,
                epoch: EpochId::new(1),
            }),
            LockPayload::RenewAck(RenewAck {
                lease_id: 1,
                status: LockServiceStatus::Renewed,
                expires_at_millis: 60_000,
                version: 2,
            }),
            LockPayload::Release(ReleaseRequest {
                    dataset_mount_id: DatasetMountId(1),
                lease_id: 1,
                owner,
                epoch: EpochId::new(1),
            }),
            LockPayload::ReleaseAck(ReleaseAck {
                lease_id: 1,
                status: LockServiceStatus::Released,
            }),
            LockPayload::Recall(RecallEvent {
                lease_id: 1,
                reason: RecallReason::ConflictUpgrade,
                deadline_millis: 10,
            }),
            LockPayload::RecallAck(LeaseIdAck {
                lease_id: 1,
                status: LockServiceStatus::Released,
            }),
            LockPayload::Break(RecallEvent {
                lease_id: 1,
                reason: RecallReason::MembershipChange,
                deadline_millis: 0,
            }),
            LockPayload::BreakAck(LeaseIdAck {
                lease_id: 1,
                status: LockServiceStatus::Released,
            }),
            LockPayload::Getlk(GetlkRequest {
                dataset_mount_id: DatasetMountId(1),
                dataset_id: 1,
                ino: 10,
                owner,
                lock_type: RangeLockType::Write,
                start: 0,
                len: 4096,
                term: 1,
                epoch: EpochId::new(1),
            }),
            LockPayload::GetlkAck(GetlkAck {
                status: LockServiceStatus::Granted,
                conflict: None,
            }),
            LockPayload::Setlk(SetlkRequest {
                dataset_mount_id: DatasetMountId(1),
                dataset_id: 1,
                ino: 10,
                owner,
                lock_type: RangeLockType::Read,
                start: 0,
                len: 4096,
                term: 1,
                epoch: EpochId::new(1),
                blocking: false,
                callback_opaque: 0,
            }),
            LockPayload::Setlkw(SetlkRequest {
                dataset_mount_id: DatasetMountId(1),
                dataset_id: 1,
                ino: 10,
                owner,
                lock_type: RangeLockType::Write,
                start: 0,
                len: 4096,
                term: 1,
                epoch: EpochId::new(1),
                blocking: true,
                callback_opaque: 88,
            }),
            LockPayload::SetlkAck(SetlkAck {
                status: LockServiceStatus::Granted,
                lock_id: 2,
                conflict: None,
            }),
            LockPayload::LockGrantEvent(LockGrantEvent {
                request_id: 9,
                lease_id: 3,
                callback_opaque: 88,
                expires_at_millis: 99,
            }),
            LockPayload::RecallAll(RecallAllEvent {
                term: 2,
                epoch: EpochId::new(2),
                reason: RecallReason::MembershipChange,
            }),
            LockPayload::RecallAllAck(RecallAllAck {
                node_id: MemberId::new(7),
                released: 3,
                epoch: EpochId::new(2),
            }),
        ]
    }

    #[test]
    fn method_ids_are_stable() {
        let methods = [
            LockMethod::Acquire,
            LockMethod::AcquireAck,
            LockMethod::Renew,
            LockMethod::RenewAck,
            LockMethod::Release,
            LockMethod::ReleaseAck,
            LockMethod::Recall,
            LockMethod::RecallAck,
            LockMethod::Break,
            LockMethod::BreakAck,
            LockMethod::Getlk,
            LockMethod::GetlkAck,
            LockMethod::Setlk,
            LockMethod::Setlkw,
            LockMethod::SetlkAck,
            LockMethod::LockGrantEvent,
            LockMethod::RecallAll,
            LockMethod::RecallAllAck,
        ];
        for (expected, method) in methods.into_iter().enumerate() {
            assert_eq!(method.to_u8(), expected as u8);
            assert_eq!(LockMethod::from_u8(expected as u8), Some(method));
        }
        assert_eq!(LockMethod::SERVICE_ID, LOCK_SERVICE_ID);
    }

    #[test]
    fn frame_roundtrips_all_methods() {
        for (idx, payload) in sample_payloads().into_iter().enumerate() {
            let frame = LockFrame::new(idx as u64 + 1, payload.clone());
            let encoded = frame.encode().expect("encode");
            assert_eq!(&encoded[0..4], b"VLCK");
            assert_eq!(encoded[4], LOCK_SERVICE_ID);
            let decoded = LockFrame::decode(&encoded).expect("decode");
            assert_eq!(decoded, frame);
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn frame_rejects_wrong_service_reserved_and_length() {
        let frame = LockFrame::new(1, sample_payloads().remove(0));
        let mut encoded = frame.encode().expect("encode");
        encoded[4] = 0xFF;
        assert!(matches!(
            LockFrame::decode(&encoded),
            Err(LockServiceError::Frame { .. })
        ));

        let mut encoded = frame.encode().expect("encode");
        encoded[10] = 1;
        assert!(matches!(
            LockFrame::decode(&encoded),
            Err(LockServiceError::Frame { .. })
        ));

        let mut encoded = frame.encode().expect("encode");
        encoded.pop();
        assert!(matches!(
            LockFrame::decode(&encoded),
            Err(LockServiceError::Frame { .. })
        ));
    }

    #[test]
    fn leader_acquire_renew_release_lifecycle() {
        let mut leader = leader();
        let owner = owner(2, 100, 55);
        let request = AcquireRequest::new(
            LeaseTarget::Inode {
                dataset_id: 1,
                ino: 42,
                parent_lease_id: 0,
            },
            LockMode::Exclusive,
            owner,
            DatasetMountId(1),
            1,
            EpochId::new(1),
        );
        let ack = leader.acquire(10, request, 1_000);
        assert_eq!(ack.status, LockStatus::Granted);
        assert_eq!(ack.lease_id, 1);
        assert_eq!(leader.table().grant_count(), 1);

        let renew = leader.renew(
            RenewRequest {
                lease_id: ack.lease_id,
                holder: owner.node_id,
                term: 1,
                epoch: EpochId::new(1),
            },
            2_000,
        );
        assert_eq!(renew.status, LockServiceStatus::Renewed);
        assert_eq!(renew.version, 2);

        let release = leader.release(ReleaseRequest {
                    dataset_mount_id: DatasetMountId(1),
            lease_id: ack.lease_id,
            owner,
            epoch: EpochId::new(1),
        });
        assert_eq!(release.status, LockServiceStatus::Released);
        assert_eq!(leader.table().grant_count(), 0);
    }

    #[test]
    fn conflicting_exclusive_acquire_is_denied() {
        let mut leader = leader();
        let first = leader.acquire(
            1,
            AcquireRequest::new(
                LeaseTarget::Directory {
                    dataset_id: 5,
                    prefix: "/alpha/".into(),
                },
                LockMode::Exclusive,
                owner(1, 1, 1),
                DatasetMountId(1),
                1,
                EpochId::new(1),
            ),
            10,
        );
        assert_eq!(first.status, LockStatus::Granted);

        let second = leader.acquire(
            2,
            AcquireRequest::new(
                LeaseTarget::Directory {
                    dataset_id: 5,
                    prefix: "/alpha/beta/".into(),
                },
                LockMode::Shared,
                owner(2, 2, 2),
                DatasetMountId(1),
                1,
                EpochId::new(1),
            ),
            11,
        );
        assert_eq!(second.status, LockStatus::DeniedConflict);
        assert_eq!(second.conflict_lease_id, Some(first.lease_id));
        assert_eq!(second.conflict_holder, Some(MemberId::new(1)));
    }

    #[test]
    fn blocking_setlkw_queues_on_conflict() {
        let mut leader = leader();
        let write = SetlkRequest {
                dataset_mount_id: DatasetMountId(1),
            dataset_id: 9,
            ino: 99,
            owner: owner(1, 10, 1),
            lock_type: RangeLockType::Write,
            start: 0,
            len: 100,
            term: 1,
            epoch: EpochId::new(1),
            blocking: false,
            callback_opaque: 0,
        };
        let first = leader.setlk(1, write, 10, false);
        assert_eq!(first.status, LockServiceStatus::Granted);

        let blocked = SetlkRequest {
                dataset_mount_id: DatasetMountId(1),
            dataset_id: 9,
            ino: 99,
            owner: owner(2, 20, 2),
            start: 0,
            len: 100,
            blocking: true,
            callback_opaque: 77,
            ..match sample_payloads().remove(13) {
                LockPayload::Setlkw(req) => req,
                _ => unreachable!(),
            }
        };
        let ack = leader.setlk(2, blocked, 20, true);
        assert_eq!(ack.status, LockServiceStatus::Queued);
        assert_eq!(leader.stats().queued, 1);
    }

    #[test]
    fn getlk_reports_byte_range_conflict() {
        let mut leader = leader();
        let first = leader.setlk(
            1,
            SetlkRequest {
                dataset_mount_id: DatasetMountId(1),
                dataset_id: 2,
                ino: 8,
                owner: owner(1, 1, 1),
                lock_type: RangeLockType::Write,
                start: 100,
                len: 50,
                term: 1,
                epoch: EpochId::new(1),
                blocking: false,
                callback_opaque: 0,
            },
            1_000,
            false,
        );
        assert_eq!(first.status, LockServiceStatus::Granted);

        let ack = leader.getlk(GetlkRequest {
                dataset_mount_id: DatasetMountId(1),
            dataset_id: 2,
            ino: 8,
            owner: owner(2, 2, 2),
            lock_type: RangeLockType::Read,
            start: 120,
            len: 10,
            term: 1,
            epoch: EpochId::new(1),
        });
        assert_eq!(ack.status, LockServiceStatus::DeniedConflict);
        assert_eq!(ack.conflict.expect("conflict").lease_id, first.lock_id);
    }

    #[test]
    fn recall_and_break_frames_are_events() {
        let mut leader = leader();
        let recall = leader.recall(22, RecallReason::AdminRevoke, 900);
        assert_eq!(recall.kind, LockMessageKind::Event);
        assert_eq!(recall.method, LockMethod::Recall);

        let break_frame = leader.break_lease(22, RecallReason::MembershipChange);
        assert_eq!(break_frame.kind, LockMessageKind::Event);
        assert_eq!(break_frame.method, LockMethod::Break);
        assert_eq!(leader.stats().breaks, 1);
    }

    #[test]
    fn handle_builds_monotonic_requests_and_tracks_grants() {
        let owner = owner(4, 123, 456);
        let mut handle = LockServiceHandle::new(owner);
        let first = handle.build_acquire(
            LeaseTarget::Inode {
                dataset_id: 3,
                ino: 44,
                parent_lease_id: 0,
            },
            LockMode::Shared,
            1,
            EpochId::new(1),
        );
        let second = handle.build_release(1, EpochId::new(1));
        assert_eq!(first.op_id, 1);
        assert_eq!(second.op_id, 2);

        handle.accept_acquire_ack(
            &AcquireAck {
                status: LockStatus::Granted,
                lease_id: 1,
                dataset_mount_id: DatasetMountId(1),
                target: LeaseTarget::Inode {
                    dataset_id: 3,
                    ino: 44,
                    parent_lease_id: 0,
                },
                mode: LockMode::Shared,
                term: 1,
                epoch: EpochId::new(1),
                expires_at_millis: 31_000,
                conflict_holder: None,
                conflict_lease_id: None,
            },
            1_000,
        );
        assert_eq!(handle.held_lease_ids(), vec![1]);
        handle.accept_release_ack(&ReleaseAck {
            lease_id: 1,
            status: LockServiceStatus::Released,
        });
        assert!(handle.held_lease_ids().is_empty());
    }

    #[test]
    fn transport_sink_serializes_frames() {
        let mut transport = LockServiceTransport::new(QueuedLockFrameSink::default());
        let frame = LockFrame::new(7, sample_payloads().remove(0));
        transport
            .send(MemberId::new(99), &frame)
            .expect("send lock frame");
        let mut sink = transport.into_inner();
        assert_eq!(sink.len(), 1);
        let (peer, bytes) = sink.pop().expect("queued frame");
        assert_eq!(peer, MemberId::new(99));
        assert_eq!(LockFrame::decode(&bytes).expect("decode"), frame);
    }

    #[test]
    fn stale_epoch_is_fenced() {
        let mut leader = leader();
        let ack = leader.acquire(
            1,
            AcquireRequest::new(
                LeaseTarget::Inode {
                    dataset_id: 1,
                    ino: 1,
                    parent_lease_id: 0,
                },
                LockMode::Exclusive,
                owner(1, 1, 1),
                DatasetMountId(1),
                99,
                EpochId::new(1),
            ),
            10,
        );
        assert_eq!(ack.status, LockStatus::DeniedFenced);
        assert_eq!(leader.table().grant_count(), 0);
    }
}

/// BLAKE3-verified lock handle binding a lease to a holder and epoch.
///
/// Each lock grant produces a unique handle token derived from the lease
/// identity, owner, epoch, and a caller-supplied domain separator. The
/// token can be verified independently by any peer that knows the
/// derivation parameters, providing tamper-evident proof of lock
/// ownership without a shared secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockHandle {
    pub lease_id: u64,
    pub mode: LockMode,
    pub owner: LockOwner,
    pub epoch: EpochId,
    pub expires_at_millis: u64,
    /// Domain-separated BLAKE3 token unique to this lock grant.
    pub token: [u8; 32],
}

impl LockHandle {
    /// Derive a domain-separated BLAKE3 token for a lock grant.
    pub fn derive_token(
        lease_id: u64,
        owner: &LockOwner,
        epoch: EpochId,
        domain_separator: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Hasher::new_derive_key("TideFS LockHandle grant token v1");
        hasher.update(&lease_id.to_le_bytes());
        hasher.update(&owner.node_id.0.to_le_bytes());
        hasher.update(&owner.pid.to_le_bytes());
        hasher.update(&owner.owner_key.to_le_bytes());
        hasher.update(&epoch.0.to_le_bytes());
        hasher.update(domain_separator);
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    /// Verify the token matches the expected derivation.
    pub fn verify(&self, domain_separator: &[u8]) -> bool {
        let expected = Self::derive_token(self.lease_id, &self.owner, self.epoch, domain_separator);
        // constant-time comparison
        let mut acc = 0u8;
        for (a, b) in self.token.iter().zip(expected.iter()) {
            acc |= a ^ b;
        }
        acc == 0
    }

    /// True when the lock's epoch is behind the current epoch.
    pub fn is_stale(&self, current_epoch: EpochId) -> bool {
        self.epoch.0 < current_epoch.0
    }
}

// ── LockState ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockState {
    pub ino: u64,
    pub start: u64,
    pub end: u64,
    pub mode: LockMode,
    pub owner: LockOwner,
    pub lease_id: u64,
    pub granted_at_millis: u64,
    pub expires_at_millis: u64,
}

// ── AcquireResult ─────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcquireResult {
    Granted { lock: LockState },
    Conflict { holder: Option<LockOwner> },
    Queued,
}
impl AcquireResult {
    /// Return the lease_id if Granted, useful in tests.
    #[cfg(test)]
    pub fn granted_lock_id(&self) -> u64 {
        match self {
            Self::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        }
    }
}

// ── LockService ───────────────────────────────────────────────────────

/// Trait defining the distributed lock service interface.
///
/// Implementations must provide lease-backed lock acquisition, release,
/// upgrade/downgrade, deadlock detection, and epoch gating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockAcquireRequest {
    pub ino: u64,
    pub start: u64,
    pub len: u64,
    pub mode: LockMode,
    pub owner: LockOwner,
    pub blocking: bool,
    pub now_millis: u64,
}

pub trait LockServiceTrait {
    /// Acquire a lock on the given byte range.
    fn acquire_lock(
        &mut self,
        request: LockAcquireRequest,
    ) -> Result<AcquireResult, LockServiceError>;

    /// Release a lock. If start and len are both zero, release all locks
    /// held by the owner on this inode.
    fn release_lock(
        &mut self,
        ino: u64,
        start: u64,
        len: u64,
        owner: LockOwner,
        now_millis: u64,
    ) -> Result<Vec<LockState>, LockServiceError>;

    /// Upgrade a held shared lock to exclusive. Fails if other readers exist.
    fn upgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError>;

    /// Downgrade a held exclusive lock to shared.
    fn downgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError>;

    /// Check whether a pending lock request would create a deadlock cycle.
    fn check_deadlock(
        &self,
        ino: u64,
        start: u64,
        len: u64,
        mode: LockMode,
        waiter: LockOwner,
    ) -> Result<(), LockServiceError>;

    /// Validate that a lock is still valid in the current epoch.
    fn validate_epoch(&self, lease_id: u64, current_epoch: EpochId)
        -> Result<(), LockServiceError>;

    /// Return the BLAKE3-verified handle for a granted lock.
    fn lock_handle(&self, lease_id: u64) -> Option<LockHandle>;
}
pub struct LockService {
    table: LockTable,
    next_lease_id: u64,
    config: LockServiceConfig,
    lease_inode: BTreeMap<u64, u64>,
    lease_owner: BTreeMap<u64, LockOwner>,
    pending_edges: Vec<(u64, u64)>,
}

impl LockService {
    pub fn new(config: LockServiceConfig) -> Self {
        let table = LockTable::new(config.current_term, config.current_epoch);
        Self {
            table,
            next_lease_id: 1,
            config,
            lease_inode: BTreeMap::new(),
            lease_owner: BTreeMap::new(),
            pending_edges: Vec::new(),
        }
    }
    pub fn lock_count(&self) -> usize {
        self.table.grant_count()
    }
    #[cfg(test)]
    pub fn table(&self) -> &LockTable {
        &self.table
    }
    pub fn grants_iter(&self) -> impl Iterator<Item = &LeaseGrant> {
        self.table.grants_iter()
    }
    /// Release every lock and pending request scoped to a dataset mount
    /// identity. Used on unmount or forced unmount.
    pub fn unmount_mount(&mut self, dataset_mount_id: DatasetMountId, epoch: EpochId) -> UnmountAck {
        let released = self.table.release_by_mount(dataset_mount_id.0, epoch);
        UnmountAck {
            dataset_mount_id,
            released,
            status: LockServiceStatus::Released,
        }
    }

    pub fn sweep_pending(&mut self, now_millis: u64) -> Vec<(u64, u64, MemberId, u64)> {
        self.table.sweep_pending(now_millis)
    }

    pub fn acquire(
        &mut self,
        request: LockAcquireRequest,
    ) -> Result<AcquireResult, LockServiceError> {
        let LockAcquireRequest {
            ino,
            start,
            len,
            mode,
            owner,
            blocking,
            now_millis,
        } = request;
        let end = range_end(start, len);
        let domain = LeaseDomain::ByteRange {
            dataset_id: 0,
            ino,
            start,
            end,
        };
        let lease_class = mode.to_lease_class();
        if let Some(conflict_id) = self.table.check_conflict(&domain, lease_class) {
            if !blocking {
                let holder = self.conflict_holder(conflict_id);
                return Ok(AcquireResult::Conflict { holder });
            }
            let pending = PendingLockRequest {
                request_id: self.next_lease_id,
                owner,
                domain: domain.clone(),
                lease_class,
                enqueued_at_millis: now_millis,
                timeout_millis: self.config.pending_timeout_millis,
                callback_node_id: owner.node_id,
                callback_opaque: 0,
            };
            if self.table.enqueue_pending(0, ino, pending).is_err() {
                return Err(LockServiceError::QueueFull);
            }
            // Record waiter→holders edges for deadlock detection
            for conflicting_lease_id in self
                .table
                .grants_iter()
                .filter(|g| {
                    !g.lifecycle.is_terminal()
                        && intervals_overlap(
                            match &g.domain {
                                LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                                _ => (0, 0),
                            }
                            .0,
                            match &g.domain {
                                LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                                _ => (0, 0),
                            }
                            .1,
                            start,
                            end,
                        )
                        && conflict_between(g.lease_class, lease_class)
                })
                .map(|g| g.holder_id.0)
            {
                self.pending_edges
                    .push((owner.node_id.0, conflicting_lease_id));
            }
            return Ok(AcquireResult::Queued);
        }
        let lease_id = self.allocate_lease_id();
        let term_millis = self.config.default_term_millis;
        let grant = LeaseGrant::request(
            lease_id,
            lease_class,
            domain,
            owner.node_id,
            1u64,
            term_millis,
            now_millis,
            self.config.current_epoch,
            self.config.witness_set_id,
            self.config.witness_confirmations,
            self.config.witness_total,
        );
        let expires_at = grant.expires_at_millis;
        self.table.apply(&RaftCommand::Grant { grant });
        self.lease_inode.insert(lease_id, ino);
        self.lease_owner.insert(lease_id, owner);
        Ok(AcquireResult::Granted {
            lock: LockState {
                ino,
                start,
                end,
                mode,
                owner,
                lease_id,
                granted_at_millis: now_millis,
                expires_at_millis: expires_at,
            },
        })
    }

    pub fn release(
        &mut self,
        ino: u64,
        start: u64,
        len: u64,
        owner: LockOwner,
        now_millis: u64,
    ) -> Result<Vec<LockState>, LockServiceError> {
        if start == 0 && len == 0 {
            let released: Vec<LockState> = self
                .owned_locks_on_inode(ino, owner)
                .into_iter()
                .map(|(lease_id, state)| {
                    self.table.apply(&RaftCommand::Release { lease_id });
                    self.lease_inode.remove(&lease_id);
                    self.lease_owner.remove(&lease_id);
                    state
                })
                .collect();
            if released.is_empty() {
                return Err(LockServiceError::NotFound);
            }
            return Ok(released);
        }
        let end = range_end(start, len);
        let lock = self
            .owned_locks_on_inode(ino, owner)
            .into_iter()
            .find(|(_lid, state)| state.start == start && state.end == end);
        match lock {
            Some((lease_id, state)) => {
                self.table.apply(&RaftCommand::Release { lease_id });
                self.lease_inode.remove(&lease_id);
                self.lease_owner.remove(&lease_id);
                self.sweep_pending(now_millis);
                Ok(vec![state])
            }
            None => Err(LockServiceError::NotFound),
        }
    }

    pub fn query(&self, ino: u64, start: u64, len: u64) -> Vec<LockState> {
        let end = range_end(start, len);
        let mut result = Vec::new();
        for grant in self.table.grants_iter() {
            if grant.lifecycle.is_terminal() {
                continue;
            }
            if let LeaseDomain::ByteRange {
                dataset_id: _,
                ino: g_ino,
                start: g_start,
                end: g_end,
            } = &grant.domain
            {
                if *g_ino == ino && intervals_overlap(*g_start, *g_end, start, end) {
                    let owner = self.lookup_owner(grant.lease_id, grant.holder_id);
                    result.push(LockState {
                        ino,
                        start: *g_start,
                        end: *g_end,
                        mode: mode_from_class(grant.lease_class),
                        owner,
                        lease_id: grant.lease_id,
                        granted_at_millis: grant.granted_at_millis,
                        expires_at_millis: grant.expires_at_millis,
                    });
                }
            }
        }
        result.sort_by_key(|s| s.start);
        result
    }

    pub fn sweep_expired(&mut self, now_millis: u64) -> Vec<LockState> {
        let mut expired = Vec::new();
        let to_release: Vec<u64> = self
            .table
            .grants_iter()
            .filter(|g| g.is_expired(now_millis) && !g.lifecycle.is_terminal())
            .map(|g| g.lease_id)
            .collect();
        for lease_id in to_release {
            if let Some(grant) = self.table.get_grant(lease_id).cloned() {
                if let LeaseDomain::ByteRange {
                    dataset_id: _,
                    ino,
                    start,
                    end,
                } = &grant.domain
                {
                    let owner = self.lookup_owner(grant.lease_id, grant.holder_id);
                    expired.push(LockState {
                        ino: *ino,
                        start: *start,
                        end: *end,
                        mode: mode_from_class(grant.lease_class),
                        owner,
                        lease_id,
                        granted_at_millis: grant.granted_at_millis,
                        expires_at_millis: grant.expires_at_millis,
                    });
                }
                self.table.apply(&RaftCommand::Release { lease_id });
                self.lease_owner.remove(&lease_id);
                self.lease_inode.remove(&lease_id);
            }
        }
        expired
    }

    pub fn all_locks(&self) -> Vec<LockState> {
        let mut result = Vec::new();
        for grant in self.table.grants_iter() {
            if grant.lifecycle.is_terminal() {
                continue;
            }
            if let LeaseDomain::ByteRange {
                dataset_id: _,
                ino,
                start,
                end,
            } = &grant.domain
            {
                let owner = self.lookup_owner(grant.lease_id, grant.holder_id);
                result.push(LockState {
                    ino: *ino,
                    start: *start,
                    end: *end,
                    mode: mode_from_class(grant.lease_class),
                    owner,
                    lease_id: grant.lease_id,
                    granted_at_millis: grant.granted_at_millis,
                    expires_at_millis: grant.expires_at_millis,
                });
            }
        }
        result
    }

    // ── upgrade_lock / downgrade_lock ──────────────────────────────

    pub fn upgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError> {
        let grant = self
            .table
            .get_grant(lease_id)
            .ok_or(LockServiceError::NotFound)?;
        if grant.lease_class != LeaseClass::Shared {
            return Err(LockServiceError::NotUpgradeable);
        }
        if grant.holder_id != owner.node_id {
            return Err(LockServiceError::NotFound);
        }
        if grant.lifecycle.is_terminal() {
            return Err(LockServiceError::NotFound);
        }
        // Check for other readers — any additional shared lock on the
        // overlapping range blocks upgrade to exclusive. We cannot use
        // check_conflict because the range tree is not updated on
        // Upgrade/Downgrade and may return the lock itself as a conflict.
        let has_other_readers = self.table.grants_iter().any(|g| {
            g.lease_id != lease_id
                && !g.lifecycle.is_terminal()
                && g.lease_class == LeaseClass::Shared
                && intervals_overlap(
                    match &g.domain {
                        LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                        _ => (0, 0),
                    }
                    .0,
                    match &g.domain {
                        LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                        _ => (0, 0),
                    }
                    .1,
                    match &grant.domain {
                        LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                        _ => (0, 0),
                    }
                    .0,
                    match &grant.domain {
                        LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
                        _ => (0, 0),
                    }
                    .1,
                )
        });
        if has_other_readers {
            return Err(LockServiceError::NotUpgradeable);
        }
        self.table.apply(&RaftCommand::Upgrade { lease_id });
        let grant = self
            .table
            .get_grant(lease_id)
            .ok_or(LockServiceError::NotFound)?;
        let ino = self.lease_inode.get(&lease_id).copied().unwrap_or(0);
        let (start, end) = match &grant.domain {
            LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
            _ => (0, 0),
        };
        Ok(LockState {
            ino,
            start,
            end,
            mode: LockMode::Exclusive,
            owner,
            lease_id,
            granted_at_millis: grant.granted_at_millis,
            expires_at_millis: grant.expires_at_millis,
        })
    }

    pub fn downgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError> {
        let grant = self
            .table
            .get_grant(lease_id)
            .ok_or(LockServiceError::NotFound)?;
        if grant.lease_class != LeaseClass::Exclusive {
            return Err(LockServiceError::NotDowngradeable);
        }
        if grant.holder_id != owner.node_id {
            return Err(LockServiceError::NotFound);
        }
        if grant.lifecycle.is_terminal() {
            return Err(LockServiceError::NotFound);
        }
        self.table.apply(&RaftCommand::Downgrade { lease_id });
        let grant = self
            .table
            .get_grant(lease_id)
            .ok_or(LockServiceError::NotFound)?;
        let ino = self.lease_inode.get(&lease_id).copied().unwrap_or(0);
        let (start, end) = match &grant.domain {
            LeaseDomain::ByteRange { start, end, .. } => (*start, *end),
            _ => (0, 0),
        };
        Ok(LockState {
            ino,
            start,
            end,
            mode: LockMode::Shared,
            owner,
            lease_id,
            granted_at_millis: grant.granted_at_millis,
            expires_at_millis: grant.expires_at_millis,
        })
    }

    // ── check_deadlock ────────────────────────────────────────────

    pub fn check_deadlock(
        &self,
        ino: u64,
        start: u64,
        len: u64,
        mode: LockMode,
        waiter: LockOwner,
    ) -> Result<(), LockServiceError> {
        let end = range_end(start, len);
        let lease_class = mode.to_lease_class();
        let mut edges: Vec<(u64, u64)> = Vec::new();

        // Proposed edge: waiter → each current holder that conflicts.
        for grant in self.table.grants_iter() {
            if grant.lifecycle.is_terminal() {
                continue;
            }
            if let LeaseDomain::ByteRange {
                ino: g_ino,
                start: gs,
                end: ge,
                ..
            } = &grant.domain
            {
                if *g_ino == ino
                    && intervals_overlap(*gs, *ge, start, end)
                    && conflict_between(grant.lease_class, lease_class)
                {
                    edges.push((waiter.node_id.0, grant.holder_id.0));
                }
            }
        }

        // Include pending waiter edges from queued blocking requests.
        edges.extend_from_slice(&self.pending_edges);

        if would_deadlock(waiter.node_id.0, &edges) {
            return Err(LockServiceError::Deadlock);
        }
        Ok(())
    }

    // ── validate_epoch ────────────────────────────────────────────

    pub fn validate_epoch(
        &self,
        lease_id: u64,
        current_epoch: EpochId,
    ) -> Result<(), LockServiceError> {
        let grant = self
            .table
            .get_grant(lease_id)
            .ok_or(LockServiceError::NotFound)?;
        if grant.epoch.0 < current_epoch.0 {
            return Err(LockServiceError::StaleEpoch {
                lock_epoch: grant.epoch,
                current_epoch,
            });
        }
        Ok(())
    }

    // ── lock_handle ───────────────────────────────────────────────

    pub fn lock_handle(&self, lease_id: u64) -> Option<LockHandle> {
        let grant = self.table.get_grant(lease_id)?;
        if grant.lifecycle.is_terminal() {
            return None;
        }
        let mode = mode_from_class(grant.lease_class);
        let owner = self.lookup_owner(lease_id, grant.holder_id);
        let domain_bytes = match &grant.domain {
            LeaseDomain::ByteRange {
                ino, start, end, ..
            } => {
                let mut buf = Vec::with_capacity(24);
                buf.extend_from_slice(&ino.to_le_bytes());
                buf.extend_from_slice(&start.to_le_bytes());
                buf.extend_from_slice(&end.to_le_bytes());
                buf
            }
            _ => return None,
        };
        let token = LockHandle::derive_token(lease_id, &owner, grant.epoch, &domain_bytes);
        Some(LockHandle {
            lease_id,
            mode,
            owner,
            epoch: grant.epoch,
            expires_at_millis: grant.expires_at_millis,
            token,
        })
    }

    fn allocate_lease_id(&mut self) -> u64 {
        let id = self.next_lease_id;
        self.next_lease_id = self.next_lease_id.saturating_add(1).max(1);
        id
    }
    fn lookup_owner(&self, lease_id: u64, holder_id: MemberId) -> LockOwner {
        self.lease_owner
            .get(&lease_id)
            .copied()
            .unwrap_or_else(|| LockOwner::new(holder_id, 0, 0))
    }
    fn conflict_holder(&self, lease_id: u64) -> Option<LockOwner> {
        let grant = self.table.get_grant(lease_id)?;
        Some(self.lookup_owner(lease_id, grant.holder_id))
    }
    fn owned_locks_on_inode(&self, ino: u64, owner: LockOwner) -> Vec<(u64, LockState)> {
        self.table
            .grants_iter()
            .filter(|g| g.holder_id == owner.node_id && !g.lifecycle.is_terminal())
            .filter_map(|g| {
                if let LeaseDomain::ByteRange {
                    dataset_id: _,
                    ino: g_ino,
                    start,
                    end,
                } = &g.domain
                {
                    if *g_ino == ino {
                        let owner = self.lookup_owner(g.lease_id, g.holder_id);
                        return Some((
                            g.lease_id,
                            LockState {
                                ino,
                                start: *start,
                                end: *end,
                                mode: mode_from_class(g.lease_class),
                                owner,
                                lease_id: g.lease_id,
                                granted_at_millis: g.granted_at_millis,
                                expires_at_millis: g.expires_at_millis,
                            },
                        ));
                    }
                }
                None
            })
            .collect()
    }
}

impl LockServiceTrait for LockService {
    fn acquire_lock(
        &mut self,
        request: LockAcquireRequest,
    ) -> Result<AcquireResult, LockServiceError> {
        self.acquire(request)
    }
    fn release_lock(
        &mut self,
        ino: u64,
        start: u64,
        len: u64,
        owner: LockOwner,
        now_millis: u64,
    ) -> Result<Vec<LockState>, LockServiceError> {
        self.release(ino, start, len, owner, now_millis)
    }
    fn upgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError> {
        self.upgrade_lock(lease_id, owner)
    }
    fn downgrade_lock(
        &mut self,
        lease_id: u64,
        owner: LockOwner,
    ) -> Result<LockState, LockServiceError> {
        self.downgrade_lock(lease_id, owner)
    }
    fn check_deadlock(
        &self,
        ino: u64,
        start: u64,
        len: u64,
        mode: LockMode,
        waiter: LockOwner,
    ) -> Result<(), LockServiceError> {
        self.check_deadlock(ino, start, len, mode, waiter)
    }
    fn validate_epoch(
        &self,
        lease_id: u64,
        current_epoch: EpochId,
    ) -> Result<(), LockServiceError> {
        self.validate_epoch(lease_id, current_epoch)
    }
    fn lock_handle(&self, lease_id: u64) -> Option<LockHandle> {
        self.lock_handle(lease_id)
    }
}
fn conflict_between(a: LeaseClass, b: LeaseClass) -> bool {
    matches!(
        (a, b),
        (LeaseClass::Exclusive, _) | (_, LeaseClass::Exclusive)
    )
}

fn would_deadlock(start_node: u64, edges: &[(u64, u64)]) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut stack = std::collections::HashSet::new();
    dfs_cycle(start_node, edges, &mut visited, &mut stack)
}

fn dfs_cycle(
    node: u64,
    edges: &[(u64, u64)],
    visited: &mut std::collections::HashSet<u64>,
    stack: &mut std::collections::HashSet<u64>,
) -> bool {
    if stack.contains(&node) {
        return true;
    }
    if visited.contains(&node) {
        return false;
    }
    visited.insert(node);
    stack.insert(node);
    for &(from, to) in edges {
        if from == node && dfs_cycle(to, edges, visited, stack) {
            return true;
        }
    }
    stack.remove(&node);
    false
}

fn intervals_overlap(a1: u64, b1: u64, a2: u64, b2: u64) -> bool {
    a1 < b2 && a2 < b1
}

// ── LockServiceLocal tests ─────────────────────────────────────────

#[cfg(test)]
mod lock_service_tests {
    use super::*;
    use tidefs_membership_epoch::MemberId;

    fn owner(node: u64, pid: u32, key: u64) -> LockOwner {
        LockOwner::new(MemberId::new(node), pid, key)
    }
    fn svc() -> LockService {
        LockService::new(LockServiceConfig::default())
    }
    fn now() -> u64 {
        1_000_000
    }

    macro_rules! acquire {
        ($svc:expr, $ino:expr, $start:expr, $len:expr, $mode:expr, $owner:expr, $blocking:expr, $now:expr) => {
            $svc.acquire(LockAcquireRequest {
                ino: $ino,
                start: $start,
                len: $len,
                mode: $mode,
                owner: $owner,
                blocking: $blocking,
                now_millis: $now,
            })
        };
    }

    #[test]
    fn shared_locks_are_compatible() {
        let mut s = svc();
        assert!(matches!(
            acquire!(
                s,
                1,
                0,
                100,
                LockMode::Shared,
                owner(1, 100, 1),
                false,
                now()
            ),
            Ok(AcquireResult::Granted { .. })
        ));
        assert!(matches!(
            acquire!(
                s,
                1,
                0,
                100,
                LockMode::Shared,
                owner(2, 200, 2),
                false,
                now()
            ),
            Ok(AcquireResult::Granted { .. })
        ));
        assert_eq!(s.lock_count(), 2);
    }

    #[test]
    fn exclusive_rejects_shared_on_overlap() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                50,
                10,
                LockMode::Shared,
                owner(2, 200, 2),
                false,
                now()
            ),
            Ok(AcquireResult::Conflict { .. })
        ));
    }

    #[test]
    fn shared_rejects_exclusive_on_overlap() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                50,
                10,
                LockMode::Exclusive,
                owner(2, 200, 2),
                false,
                now()
            ),
            Ok(AcquireResult::Conflict { .. })
        ));
    }

    #[test]
    fn exclusive_rejects_exclusive_on_overlap() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                50,
                10,
                LockMode::Exclusive,
                owner(2, 200, 2),
                false,
                now()
            ),
            Ok(AcquireResult::Conflict { .. })
        ));
    }

    #[test]
    fn non_overlapping_exclusive_locks_succeed() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                100,
                100,
                LockMode::Exclusive,
                owner(2, 200, 2),
                false,
                now()
            ),
            Ok(AcquireResult::Granted { .. })
        ));
    }

    #[test]
    fn blocking_requests_are_queued_in_fifo_order() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                0,
                100,
                LockMode::Exclusive,
                owner(2, 200, 2),
                true,
                now()
            ),
            Ok(AcquireResult::Queued)
        ));
        assert!(matches!(
            acquire!(
                s,
                1,
                0,
                100,
                LockMode::Exclusive,
                owner(3, 300, 3),
                true,
                now()
            ),
            Ok(AcquireResult::Queued)
        ));
    }

    #[test]
    fn compatible_shared_requests_proceed_concurrently() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            50,
            10,
            LockMode::Shared,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            acquire!(
                s,
                1,
                25,
                25,
                LockMode::Shared,
                owner(3, 300, 3),
                false,
                now()
            ),
            Ok(AcquireResult::Granted { .. })
        ));
    }

    #[test]
    fn expired_locks_are_released_on_sweep() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert_eq!(s.lock_count(), 1);
        let expired_at = s.all_locks()[0].expires_at_millis;
        let swept =
            s.sweep_expired(expired_at + LockServiceConfig::default().default_term_millis + 10_000);
        assert_eq!(swept.len(), 1);
        assert_eq!(s.lock_count(), 0);
    }

    #[test]
    fn non_expired_locks_are_not_swept() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(s.sweep_expired(now() + 5_000).is_empty());
        assert_eq!(s.lock_count(), 1);
    }

    #[test]
    fn query_returns_all_overlapping_locks() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            50,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            100,
            50,
            LockMode::Shared,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            2,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert_eq!(s.query(1, 0, 200).len(), 2);
    }

    #[test]
    fn query_narrow_range_returns_only_overlapping() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            200,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert_eq!(s.query(1, 250, 10).len(), 1);
    }

    #[test]
    fn query_empty_range_returns_nothing() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(s.query(1, 200, 100).is_empty());
    }

    #[test]
    fn release_all_for_owner_releases_all_inode_locks() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            50,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            100,
            50,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert_eq!(
            s.release(1, 0, 0, owner(1, 100, 1), now()).unwrap().len(),
            2
        );
        assert_eq!(s.lock_count(), 0);
    }

    #[test]
    fn release_specific_range_releases_only_that_lock() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            50,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            100,
            50,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert_eq!(
            s.release(1, 0, 50, owner(1, 100, 1), now()).unwrap().len(),
            1
        );
    }

    #[test]
    fn release_nonexistent_lock_returns_not_found() {
        assert!(matches!(
            svc().release(1, 0, 100, owner(1, 100, 1), now()),
            Err(LockServiceError::NotFound)
        ));
    }

    #[test]
    fn release_by_owner_only_affects_that_owner() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();
        s.release(1, 0, 0, owner(1, 100, 1), now()).unwrap();
        assert_eq!(s.lock_count(), 1);
        assert_eq!(s.all_locks()[0].owner.node_id, MemberId::new(2));
    }

    #[test]
    fn acquire_granted_returns_lock_state_with_lease_info() {
        let mut service = svc();
        match acquire!(
            service,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap()
        {
            AcquireResult::Granted { lock } => {
                assert_eq!(lock.ino, 1);
                assert_eq!(lock.start, 0);
                assert_eq!(lock.end, 100);
                assert_eq!(lock.mode, LockMode::Exclusive);
                assert!(lock.lease_id > 0);
            }
            _ => panic!("expected Granted"),
        }
    }

    #[test]
    fn acquire_conflict_returns_holder_info() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        match acquire!(
            s,
            1,
            50,
            10,
            LockMode::Shared,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap()
        {
            AcquireResult::Conflict { holder } => {
                assert_eq!(holder.map(|h| h.node_id), Some(MemberId::new(1)));
            }
            _ => panic!("expected Conflict"),
        }
    }
    // ── upgrade / downgrade ──────────────────────────────────────

    #[test]
    fn upgrade_shared_to_exclusive_succeeds_when_sole_holder() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        let state = s.upgrade_lock(lid, owner(1, 100, 1)).unwrap();
        assert_eq!(state.mode, LockMode::Exclusive);
        assert_eq!(state.ino, 1);
    }

    #[test]
    fn upgrade_fails_when_other_readers_exist() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(matches!(
            s.upgrade_lock(lid, owner(2, 200, 2)),
            Err(LockServiceError::NotUpgradeable)
        ));
    }

    #[test]
    fn upgrade_fails_for_exclusive_lock() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(matches!(
            s.upgrade_lock(lid, owner(1, 100, 1)),
            Err(LockServiceError::NotUpgradeable)
        ));
    }

    #[test]
    fn upgrade_fails_for_wrong_owner() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(matches!(
            s.upgrade_lock(lid, owner(2, 200, 2)),
            Err(LockServiceError::NotFound)
        ));
    }

    #[test]
    fn downgrade_exclusive_to_shared_succeeds() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        let state = s.downgrade_lock(lid, owner(1, 100, 1)).unwrap();
        assert_eq!(state.mode, LockMode::Shared);
        assert_eq!(state.ino, 1);
        assert_eq!(state.owner, owner(1, 100, 1));
        // Verify the lock's class changed in the table
        let grant = s.table.get_grant(lid).unwrap();
        assert_eq!(grant.lease_class, LeaseClass::Shared);
    }

    #[test]
    fn downgrade_fails_for_shared_lock() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(matches!(
            s.downgrade_lock(lid, owner(1, 100, 1)),
            Err(LockServiceError::NotDowngradeable)
        ));
    }

    // ── deadlock detection ────────────────────────────────────────

    #[test]
    fn deadlock_two_node_inversion_detected() {
        let mut s = svc();
        // Node 1 holds [0, 100).
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        // Node 2 holds [200, 300).
        acquire!(
            s,
            1,
            200,
            100,
            LockMode::Exclusive,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();

        // Node 1 blocks wanting [200, 300) — parked as blocking acquire.
        acquire!(
            s,
            1,
            200,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            true,
            now()
        )
        .unwrap();

        // Node 2 wanting [0, 100) — should detect deadlock
        assert!(matches!(
            s.check_deadlock(1, 0, 100, LockMode::Exclusive, owner(2, 200, 2)),
            Err(LockServiceError::Deadlock)
        ));
    }

    #[test]
    fn no_deadlock_when_no_cycle() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            s.check_deadlock(1, 0, 100, LockMode::Exclusive, owner(2, 200, 2)),
            Ok(())
        ));
    }

    #[test]
    fn three_node_circular_wait_deadlock() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            100,
            100,
            LockMode::Exclusive,
            owner(2, 200, 2),
            false,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            200,
            100,
            LockMode::Exclusive,
            owner(3, 300, 3),
            false,
            now()
        )
        .unwrap();

        acquire!(
            s,
            1,
            100,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            true,
            now()
        )
        .unwrap();
        acquire!(
            s,
            1,
            200,
            100,
            LockMode::Exclusive,
            owner(2, 200, 2),
            true,
            now()
        )
        .unwrap();
        assert!(matches!(
            s.check_deadlock(1, 0, 100, LockMode::Exclusive, owner(3, 300, 3)),
            Err(LockServiceError::Deadlock)
        ));
    }

    // ── epoch validation ──────────────────────────────────────────

    #[test]
    fn validate_epoch_rejects_stale_lock() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(s.validate_epoch(lid, EpochId::new(1)).is_ok());
        assert!(matches!(
            s.validate_epoch(lid, EpochId::new(2)),
            Err(LockServiceError::StaleEpoch { .. })
        ));
    }

    #[test]
    fn validate_epoch_accepts_current_epoch() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Shared,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let lid = match res {
            AcquireResult::Granted { lock } => lock.lease_id,
            _ => panic!("expected Granted"),
        };
        assert!(s.validate_epoch(lid, EpochId::new(1)).is_ok());
    }

    #[test]
    fn validate_epoch_not_found_for_unknown_lease() {
        let s = svc();
        assert!(matches!(
            s.validate_epoch(999, EpochId::new(1)),
            Err(LockServiceError::NotFound)
        ));
    }

    // ── BLAKE3 lock handle ────────────────────────────────────────

    #[test]
    fn lock_handle_token_is_unique_per_lease() {
        let mut s = svc();
        let r1 = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let r2 = acquire!(
            s,
            2,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let h1 = s.lock_handle(r1.granted_lock_id()).unwrap();
        let h2 = s.lock_handle(r2.granted_lock_id()).unwrap();
        assert_ne!(h1.token, h2.token, "BLAKE3 tokens must be unique per lease");
    }

    #[test]
    fn lock_handle_verify_passes_for_valid_token() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let h = s.lock_handle(res.granted_lock_id()).unwrap();
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&1_u64.to_le_bytes());
        buf.extend_from_slice(&0_u64.to_le_bytes());
        buf.extend_from_slice(&100_u64.to_le_bytes());
        assert!(h.verify(&buf));
    }

    #[test]
    fn lock_handle_verify_fails_for_tampered_token() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let mut h = s.lock_handle(res.granted_lock_id()).unwrap();
        h.token[0] ^= 0xFF;
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&1_u64.to_le_bytes());
        buf.extend_from_slice(&0_u64.to_le_bytes());
        buf.extend_from_slice(&100_u64.to_le_bytes());
        assert!(!h.verify(&buf));
    }

    #[test]
    fn lock_handle_is_stale_when_epoch_behind() {
        let mut s = svc();
        let res = acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        let h = s.lock_handle(res.granted_lock_id()).unwrap();
        assert!(!h.is_stale(EpochId::new(1)));
        assert!(h.is_stale(EpochId::new(2)));
    }

    // ── double-release idempotency ────────────────────────────────

    #[test]
    fn double_release_returns_not_found() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        s.release(1, 0, 100, owner(1, 100, 1), now()).unwrap();
        assert!(matches!(
            s.release(1, 0, 100, owner(1, 100, 1), now()),
            Err(LockServiceError::NotFound)
        ));
    }

    #[test]
    fn release_by_owner_ignores_other_owners() {
        let mut s = svc();
        acquire!(
            s,
            1,
            0,
            100,
            LockMode::Exclusive,
            owner(1, 100, 1),
            false,
            now()
        )
        .unwrap();
        assert!(matches!(
            s.release(1, 0, 100, owner(2, 200, 2), now()),
            Err(LockServiceError::NotFound)
        ));
        assert_eq!(s.lock_count(), 1);
    }
}
