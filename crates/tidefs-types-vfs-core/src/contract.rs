//! Adapter-neutral TideFS request and completion contract records.
//!
//! These types are a portable vocabulary only. They do not admit or execute
//! runtime operations, and unsupported adapter operations stay explicit in the
//! request payload instead of becoming implicit filesystem behavior.

use crate::{Errno, FileHandleId, InodeId};

pub const TIDE_CONTRACT_VERSION_V1: ContractVersion = ContractVersion(1);

pub type ContractPayloadWords = [u64; 5];

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContractVersion(pub u16);

impl ContractVersion {
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RequestId(pub [u8; 16]);

impl RequestId {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    pub const ZERO: Self = Self([0_u8; 16]);

    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ContractEpoch(pub u64);

impl ContractEpoch {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DeadlineNs(pub u64);

impl DeadlineNs {
    pub const NONE: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TimeoutNs(pub u64);

impl TimeoutNs {
    pub const NONE: Self = Self(0);

    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BlockDeviceId(pub u64);

impl BlockDeviceId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ControlTargetId(pub u64);

impl ControlTargetId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OffloadObjectId(pub u64);

impl OffloadObjectId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum WorkClass {
    #[default]
    Unspecified = 0,
    Foreground = 1,
    Background = 2,
    Maintenance = 3,
    Recovery = 4,
    Offload = 5,
}

impl WorkClass {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::Foreground),
            2 => Some(Self::Background),
            3 => Some(Self::Maintenance),
            4 => Some(Self::Recovery),
            5 => Some(Self::Offload),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum AdmissionIntent {
    #[default]
    Unspecified = 0,
    RequirePermit = 1,
    AlreadyAdmitted = 2,
    ObserveOnly = 3,
}

impl AdmissionIntent {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::RequirePermit),
            2 => Some(Self::AlreadyAdmitted),
            3 => Some(Self::ObserveOnly),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum BudgetIntent {
    #[default]
    Unspecified = 0,
    Foreground = 1,
    Background = 2,
    Bounded = 3,
}

impl BudgetIntent {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Unspecified),
            1 => Some(Self::Foreground),
            2 => Some(Self::Background),
            3 => Some(Self::Bounded),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum FenceIntent {
    #[default]
    None = 0,
    Read = 1,
    Write = 2,
    Epoch = 3,
}

impl FenceIntent {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Epoch),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum RetryIntent {
    #[default]
    None = 0,
    Idempotent = 1,
    AdapterOnly = 2,
}

impl RetryIntent {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Idempotent),
            2 => Some(Self::AdapterOnly),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum DispositionIntent {
    #[default]
    CompleteOnce = 0,
    MayDefer = 1,
    ExplicitUnsupported = 2,
}

impl DispositionIntent {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::CompleteOnce),
            1 => Some(Self::MayDefer),
            2 => Some(Self::ExplicitUnsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct RequestMetadata {
    pub request_id: RequestId,
    pub epoch: ContractEpoch,
    pub trace_id: TraceId,
    pub work_class: WorkClass,
    pub admission: AdmissionIntent,
    pub budget: BudgetIntent,
    pub fence: FenceIntent,
    pub retry: RetryIntent,
    pub disposition: DispositionIntent,
    pub deadline: DeadlineNs,
    pub timeout: TimeoutNs,
}

impl RequestMetadata {
    #[must_use]
    pub const fn new(request_id: RequestId, epoch: ContractEpoch, trace_id: TraceId) -> Self {
        Self {
            request_id,
            epoch,
            trace_id,
            work_class: WorkClass::Unspecified,
            admission: AdmissionIntent::Unspecified,
            budget: BudgetIntent::Unspecified,
            fence: FenceIntent::None,
            retry: RetryIntent::None,
            disposition: DispositionIntent::CompleteOnce,
            deadline: DeadlineNs::NONE,
            timeout: TimeoutNs::NONE,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TideRequestDomain {
    Vfs = 1,
    Block = 2,
    Control = 3,
    Offload = 4,
}

impl TideRequestDomain {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Vfs),
            2 => Some(Self::Block),
            3 => Some(Self::Control),
            4 => Some(Self::Offload),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum VfsRequestOp {
    GetAttr = 1,
    Read = 2,
    Write = 3,
    Sync = 4,
}

impl VfsRequestOp {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::GetAttr),
            2 => Some(Self::Read),
            3 => Some(Self::Write),
            4 => Some(Self::Sync),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum VfsRequest {
    GetAttr {
        inode_id: InodeId,
    },
    Read {
        inode_id: InodeId,
        file_handle_id: FileHandleId,
        offset: u64,
        length: u64,
    },
    Write {
        inode_id: InodeId,
        file_handle_id: FileHandleId,
        offset: u64,
        length: u64,
    },
    Sync {
        inode_id: InodeId,
        file_handle_id: FileHandleId,
    },
    Unsupported {
        opcode: u16,
        words: ContractPayloadWords,
    },
}

impl VfsRequest {
    #[must_use]
    pub const fn opcode_words(self) -> (u16, ContractPayloadWords) {
        match self {
            Self::GetAttr { inode_id } => {
                (VfsRequestOp::GetAttr.as_u16(), [inode_id.0, 0, 0, 0, 0])
            }
            Self::Read {
                inode_id,
                file_handle_id,
                offset,
                length,
            } => (
                VfsRequestOp::Read.as_u16(),
                [inode_id.0, file_handle_id.0, offset, length, 0],
            ),
            Self::Write {
                inode_id,
                file_handle_id,
                offset,
                length,
            } => (
                VfsRequestOp::Write.as_u16(),
                [inode_id.0, file_handle_id.0, offset, length, 0],
            ),
            Self::Sync {
                inode_id,
                file_handle_id,
            } => (
                VfsRequestOp::Sync.as_u16(),
                [inode_id.0, file_handle_id.0, 0, 0, 0],
            ),
            Self::Unsupported { opcode, words } => (opcode, words),
        }
    }

    #[must_use]
    pub const fn from_opcode_words(opcode: u16, words: ContractPayloadWords) -> Self {
        match VfsRequestOp::from_u16(opcode) {
            Some(VfsRequestOp::GetAttr) => Self::GetAttr {
                inode_id: InodeId(words[0]),
            },
            Some(VfsRequestOp::Read) => Self::Read {
                inode_id: InodeId(words[0]),
                file_handle_id: FileHandleId(words[1]),
                offset: words[2],
                length: words[3],
            },
            Some(VfsRequestOp::Write) => Self::Write {
                inode_id: InodeId(words[0]),
                file_handle_id: FileHandleId(words[1]),
                offset: words[2],
                length: words[3],
            },
            Some(VfsRequestOp::Sync) => Self::Sync {
                inode_id: InodeId(words[0]),
                file_handle_id: FileHandleId(words[1]),
            },
            None => Self::Unsupported { opcode, words },
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BlockRequestOp {
    Read = 1,
    Write = 2,
    Flush = 3,
    Discard = 4,
}

impl BlockRequestOp {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Flush),
            4 => Some(Self::Discard),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BlockRequest {
    Read {
        device_id: BlockDeviceId,
        offset: u64,
        length: u64,
        queue_tag: u64,
    },
    Write {
        device_id: BlockDeviceId,
        offset: u64,
        length: u64,
        queue_tag: u64,
    },
    Flush {
        device_id: BlockDeviceId,
        queue_tag: u64,
    },
    Discard {
        device_id: BlockDeviceId,
        offset: u64,
        length: u64,
        queue_tag: u64,
    },
    Unsupported {
        opcode: u16,
        words: ContractPayloadWords,
    },
}

impl BlockRequest {
    #[must_use]
    pub const fn opcode_words(self) -> (u16, ContractPayloadWords) {
        match self {
            Self::Read {
                device_id,
                offset,
                length,
                queue_tag,
            } => (
                BlockRequestOp::Read.as_u16(),
                [device_id.0, offset, length, queue_tag, 0],
            ),
            Self::Write {
                device_id,
                offset,
                length,
                queue_tag,
            } => (
                BlockRequestOp::Write.as_u16(),
                [device_id.0, offset, length, queue_tag, 0],
            ),
            Self::Flush {
                device_id,
                queue_tag,
            } => (
                BlockRequestOp::Flush.as_u16(),
                [device_id.0, queue_tag, 0, 0, 0],
            ),
            Self::Discard {
                device_id,
                offset,
                length,
                queue_tag,
            } => (
                BlockRequestOp::Discard.as_u16(),
                [device_id.0, offset, length, queue_tag, 0],
            ),
            Self::Unsupported { opcode, words } => (opcode, words),
        }
    }

    #[must_use]
    pub const fn from_opcode_words(opcode: u16, words: ContractPayloadWords) -> Self {
        match BlockRequestOp::from_u16(opcode) {
            Some(BlockRequestOp::Read) => Self::Read {
                device_id: BlockDeviceId(words[0]),
                offset: words[1],
                length: words[2],
                queue_tag: words[3],
            },
            Some(BlockRequestOp::Write) => Self::Write {
                device_id: BlockDeviceId(words[0]),
                offset: words[1],
                length: words[2],
                queue_tag: words[3],
            },
            Some(BlockRequestOp::Flush) => Self::Flush {
                device_id: BlockDeviceId(words[0]),
                queue_tag: words[1],
            },
            Some(BlockRequestOp::Discard) => Self::Discard {
                device_id: BlockDeviceId(words[0]),
                offset: words[1],
                length: words[2],
                queue_tag: words[3],
            },
            None => Self::Unsupported { opcode, words },
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlRequestOp {
    Describe = 1,
    Fence = 2,
}

impl ControlRequestOp {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Describe),
            2 => Some(Self::Fence),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ControlRequest {
    Describe {
        target_id: ControlTargetId,
    },
    Fence {
        target_id: ControlTargetId,
        epoch: ContractEpoch,
    },
    Unsupported {
        opcode: u16,
        words: ContractPayloadWords,
    },
}

impl ControlRequest {
    #[must_use]
    pub const fn opcode_words(self) -> (u16, ContractPayloadWords) {
        match self {
            Self::Describe { target_id } => (
                ControlRequestOp::Describe.as_u16(),
                [target_id.0, 0, 0, 0, 0],
            ),
            Self::Fence { target_id, epoch } => (
                ControlRequestOp::Fence.as_u16(),
                [target_id.0, epoch.0, 0, 0, 0],
            ),
            Self::Unsupported { opcode, words } => (opcode, words),
        }
    }

    #[must_use]
    pub const fn from_opcode_words(opcode: u16, words: ContractPayloadWords) -> Self {
        match ControlRequestOp::from_u16(opcode) {
            Some(ControlRequestOp::Describe) => Self::Describe {
                target_id: ControlTargetId(words[0]),
            },
            Some(ControlRequestOp::Fence) => Self::Fence {
                target_id: ControlTargetId(words[0]),
                epoch: ContractEpoch(words[1]),
            },
            None => Self::Unsupported { opcode, words },
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OffloadRequestOp {
    Copy = 1,
    Checksum = 2,
}

impl OffloadRequestOp {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Copy),
            2 => Some(Self::Checksum),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OffloadRequest {
    Copy {
        source_id: OffloadObjectId,
        destination_id: OffloadObjectId,
        length: u64,
    },
    Checksum {
        source_id: OffloadObjectId,
        offset: u64,
        length: u64,
    },
    Unsupported {
        opcode: u16,
        words: ContractPayloadWords,
    },
}

impl OffloadRequest {
    #[must_use]
    pub const fn opcode_words(self) -> (u16, ContractPayloadWords) {
        match self {
            Self::Copy {
                source_id,
                destination_id,
                length,
            } => (
                OffloadRequestOp::Copy.as_u16(),
                [source_id.0, destination_id.0, length, 0, 0],
            ),
            Self::Checksum {
                source_id,
                offset,
                length,
            } => (
                OffloadRequestOp::Checksum.as_u16(),
                [source_id.0, offset, length, 0, 0],
            ),
            Self::Unsupported { opcode, words } => (opcode, words),
        }
    }

    #[must_use]
    pub const fn from_opcode_words(opcode: u16, words: ContractPayloadWords) -> Self {
        match OffloadRequestOp::from_u16(opcode) {
            Some(OffloadRequestOp::Copy) => Self::Copy {
                source_id: OffloadObjectId(words[0]),
                destination_id: OffloadObjectId(words[1]),
                length: words[2],
            },
            Some(OffloadRequestOp::Checksum) => Self::Checksum {
                source_id: OffloadObjectId(words[0]),
                offset: words[1],
                length: words[2],
            },
            None => Self::Unsupported { opcode, words },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct UnsupportedRequest {
    pub domain: u16,
    pub opcode: u16,
    pub words: ContractPayloadWords,
}

impl UnsupportedRequest {
    #[must_use]
    pub const fn new(domain: u16, opcode: u16, words: ContractPayloadWords) -> Self {
        Self {
            domain,
            opcode,
            words,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TideRequest {
    Vfs(VfsRequest),
    Block(BlockRequest),
    Control(ControlRequest),
    Offload(OffloadRequest),
    Unsupported(UnsupportedRequest),
}

impl TideRequest {
    #[must_use]
    pub const fn domain_opcode_words(self) -> (u16, u16, ContractPayloadWords) {
        match self {
            Self::Vfs(request) => {
                let (opcode, words) = request.opcode_words();
                (TideRequestDomain::Vfs.as_u16(), opcode, words)
            }
            Self::Block(request) => {
                let (opcode, words) = request.opcode_words();
                (TideRequestDomain::Block.as_u16(), opcode, words)
            }
            Self::Control(request) => {
                let (opcode, words) = request.opcode_words();
                (TideRequestDomain::Control.as_u16(), opcode, words)
            }
            Self::Offload(request) => {
                let (opcode, words) = request.opcode_words();
                (TideRequestDomain::Offload.as_u16(), opcode, words)
            }
            Self::Unsupported(request) => (request.domain, request.opcode, request.words),
        }
    }

    #[must_use]
    pub const fn from_domain_opcode_words(
        domain: u16,
        opcode: u16,
        words: ContractPayloadWords,
    ) -> Self {
        match TideRequestDomain::from_u16(domain) {
            Some(TideRequestDomain::Vfs) => Self::Vfs(VfsRequest::from_opcode_words(opcode, words)),
            Some(TideRequestDomain::Block) => {
                Self::Block(BlockRequest::from_opcode_words(opcode, words))
            }
            Some(TideRequestDomain::Control) => {
                Self::Control(ControlRequest::from_opcode_words(opcode, words))
            }
            Some(TideRequestDomain::Offload) => {
                Self::Offload(OffloadRequest::from_opcode_words(opcode, words))
            }
            None => Self::Unsupported(UnsupportedRequest {
                domain,
                opcode,
                words,
            }),
        }
    }
}

impl Default for TideRequest {
    fn default() -> Self {
        Self::Unsupported(UnsupportedRequest::new(0, 0, [0; 5]))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct RequestEnvelope {
    pub version: ContractVersion,
    pub metadata: RequestMetadata,
    pub request: TideRequest,
    pub payload_flags: u32,
}

impl RequestEnvelope {
    #[must_use]
    pub const fn new(metadata: RequestMetadata, request: TideRequest) -> Self {
        Self {
            version: TIDE_CONTRACT_VERSION_V1,
            metadata,
            request,
            payload_flags: 0,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum CompletionStatus {
    #[default]
    Success = 0,
    Failed = 1,
    Unsupported = 2,
    TimedOut = 3,
    Cancelled = 4,
    Deferred = 5,
    Rejected = 6,
}

impl CompletionStatus {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Success),
            1 => Some(Self::Failed),
            2 => Some(Self::Unsupported),
            3 => Some(Self::TimedOut),
            4 => Some(Self::Cancelled),
            5 => Some(Self::Deferred),
            6 => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum CompletionDisposition {
    #[default]
    Final = 0,
    Retryable = 1,
    Deferred = 2,
    Unsupported = 3,
}

impl CompletionDisposition {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Final),
            1 => Some(Self::Retryable),
            2 => Some(Self::Deferred),
            3 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct TideCompletion {
    pub version: ContractVersion,
    pub request_id: RequestId,
    pub trace_id: TraceId,
    pub epoch: ContractEpoch,
    pub status: CompletionStatus,
    pub disposition: CompletionDisposition,
    pub errno: Errno,
    pub completed_bytes: u64,
    pub result_words: [u64; 3],
    pub result_flags: u32,
}

impl TideCompletion {
    #[must_use]
    pub const fn success(request_id: RequestId, trace_id: TraceId, epoch: ContractEpoch) -> Self {
        Self {
            version: TIDE_CONTRACT_VERSION_V1,
            request_id,
            trace_id,
            epoch,
            status: CompletionStatus::Success,
            disposition: CompletionDisposition::Final,
            errno: Errno::SUCCESS,
            completed_bytes: 0,
            result_words: [0; 3],
            result_flags: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_ID: RequestId = RequestId([1; 16]);
    const TRACE_ID: TraceId = TraceId([2; 16]);

    #[test]
    fn request_envelope_defaults_to_v1() {
        let envelope = RequestEnvelope::new(
            RequestMetadata::new(REQUEST_ID, ContractEpoch::new(7), TRACE_ID),
            TideRequest::Vfs(VfsRequest::GetAttr {
                inode_id: InodeId::new(42),
            }),
        );
        assert_eq!(envelope.version, TIDE_CONTRACT_VERSION_V1);
        assert_eq!(envelope.metadata.request_id, REQUEST_ID);
    }

    #[test]
    fn vfs_read_payload_round_trips_wire_words() {
        let request = VfsRequest::Read {
            inode_id: InodeId::new(10),
            file_handle_id: FileHandleId::new(11),
            offset: 4096,
            length: 512,
        };
        let (opcode, words) = request.opcode_words();
        assert_eq!(opcode, VfsRequestOp::Read.as_u16());
        assert_eq!(VfsRequest::from_opcode_words(opcode, words), request);
    }

    #[test]
    fn all_request_domains_keep_unknown_operations_explicit() {
        let words = [1, 2, 3, 4, 5];
        assert_eq!(
            TideRequest::from_domain_opcode_words(1, 99, words),
            TideRequest::Vfs(VfsRequest::Unsupported { opcode: 99, words })
        );
        assert_eq!(
            TideRequest::from_domain_opcode_words(2, 99, words),
            TideRequest::Block(BlockRequest::Unsupported { opcode: 99, words })
        );
        assert_eq!(
            TideRequest::from_domain_opcode_words(3, 99, words),
            TideRequest::Control(ControlRequest::Unsupported { opcode: 99, words })
        );
        assert_eq!(
            TideRequest::from_domain_opcode_words(4, 99, words),
            TideRequest::Offload(OffloadRequest::Unsupported { opcode: 99, words })
        );
        assert_eq!(
            TideRequest::from_domain_opcode_words(99, 7, words),
            TideRequest::Unsupported(UnsupportedRequest::new(99, 7, words))
        );
    }

    #[test]
    fn metadata_tags_reject_unknown_values() {
        assert_eq!(WorkClass::from_u16(6), None);
        assert_eq!(AdmissionIntent::from_u16(4), None);
        assert_eq!(BudgetIntent::from_u16(4), None);
        assert_eq!(FenceIntent::from_u16(4), None);
        assert_eq!(RetryIntent::from_u16(3), None);
        assert_eq!(DispositionIntent::from_u16(3), None);
    }

    #[test]
    fn completion_status_and_disposition_tags_are_bounded() {
        assert_eq!(
            CompletionStatus::from_u16(CompletionStatus::Unsupported.as_u16()),
            Some(CompletionStatus::Unsupported)
        );
        assert_eq!(CompletionStatus::from_u16(7), None);
        assert_eq!(
            CompletionDisposition::from_u16(CompletionDisposition::Retryable.as_u16()),
            Some(CompletionDisposition::Retryable)
        );
        assert_eq!(CompletionDisposition::from_u16(4), None);
    }
}
