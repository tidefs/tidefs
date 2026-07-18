// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

//! Authority type definitions for the per-dataset lifecycle state machine.
//!
//! Defines the source-owned ACTIVE/DESTROYING/TOMBSTONE state machine with
//! mount-time gating, foundational poison types, pinned traversal root types
//! for GC safety, and destroy job tracking types.
//!
//! This crate owns the shared types, mount gating, and validation helpers.
//! Runtime transitions are implemented in `tidefs-dataset-lifecycle`; broader
//! destroy-worker, GC, and consensus behavior remains owned by the crates,
//! validation, and live GitHub issues that implement those slices.

use core::fmt;

#[cfg(all(not(test), feature = "alloc"))]
extern crate alloc;

// ---------------------------------------------------------------------------
// DatasetStateV1 -- lifecycle state enum with u8 discriminant
// ---------------------------------------------------------------------------

/// Lifecycle state of a dataset.
///
/// Values 0x00 and 0x04-0xFF are reserved. Any unrecognized state on disk
/// must be treated as equivalent to `Tombstone` (refuse mount, preserve
/// for observability).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DatasetStateV1 {
    /// Normal operation; mountable; writes allowed.
    #[default]
    Active = 0x01,
    /// Destroy in progress; NOT mountable; writes fenced.
    Destroying = 0x02,
    /// Destroy complete; NOT mountable; retained for cluster consensus.
    Tombstone = 0x03,
}

impl DatasetStateV1 {
    pub const ACTIVE_BYTE: u8 = 0x01;
    pub const DESTROYING_BYTE: u8 = 0x02;
    pub const TOMBSTONE_BYTE: u8 = 0x03;

    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(DatasetStateV1::Active),
            0x02 => Some(DatasetStateV1::Destroying),
            0x03 => Some(DatasetStateV1::Tombstone),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn is_mountable(self) -> bool {
        matches!(self, DatasetStateV1::Active)
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, DatasetStateV1::Tombstone)
    }

    #[must_use]
    pub const fn accepts_writes(self) -> bool {
        matches!(self, DatasetStateV1::Active)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DatasetStateV1::Active => "active",
            DatasetStateV1::Destroying => "destroying",
            DatasetStateV1::Tombstone => "tombstone",
        }
    }
}

impl fmt::Display for DatasetStateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// DestroyFlags -- bitmask of destroy behaviour modifiers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct DestroyFlags(u32);

impl DestroyFlags {
    pub const NONE: Self = DestroyFlags(0);
    pub const FORCE_UNMOUNT: Self = DestroyFlags(1 << 0);
    pub const SKIP_ORPHANS: Self = DestroyFlags(1 << 1);
    pub const NO_TOMBSTONE: Self = DestroyFlags(1 << 2);
    pub const DRY_RUN: Self = DestroyFlags(1 << 3);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(raw: u32) -> Self {
        DestroyFlags(raw)
    }

    #[must_use]
    pub const fn force_unmount(self) -> bool {
        self.0 & Self::FORCE_UNMOUNT.0 != 0
    }

    #[must_use]
    pub const fn skip_orphans(self) -> bool {
        self.0 & Self::SKIP_ORPHANS.0 != 0
    }

    #[must_use]
    pub const fn no_tombstone(self) -> bool {
        self.0 & Self::NO_TOMBSTONE.0 != 0
    }

    #[must_use]
    pub const fn is_dry_run(self) -> bool {
        self.0 & Self::DRY_RUN.0 != 0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for DestroyFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        DestroyFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DestroyFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for DestroyFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        DestroyFlags(self.0 & rhs.0)
    }
}

impl fmt::Display for DestroyFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut write_flag = |name: &str| -> fmt::Result {
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(name)
        };
        if self.force_unmount() {
            write_flag("FORCE_UNMOUNT")?;
        }
        if self.skip_orphans() {
            write_flag("SKIP_ORPHANS")?;
        }
        if self.no_tombstone() {
            write_flag("NO_TOMBSTONE")?;
        }
        if self.is_dry_run() {
            write_flag("DRY_RUN")?;
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TraversalRoot -- GC-pinned root during destroy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum TraversalRootType {
    InodeTable = 0x01,
    ExtentMap = 0x02,
    DirectoryIndex = 0x03,
    XattrStore = 0x04,
    SnapshotCatalog = 0x05,
    FeatureFlags = 0x06,
}

impl TraversalRootType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(TraversalRootType::InodeTable),
            0x02 => Some(TraversalRootType::ExtentMap),
            0x03 => Some(TraversalRootType::DirectoryIndex),
            0x04 => Some(TraversalRootType::XattrStore),
            0x05 => Some(TraversalRootType::SnapshotCatalog),
            0x06 => Some(TraversalRootType::FeatureFlags),
            _ => None,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Logical identity of a committed root used by dataset lifecycle pins.
///
/// The handle is resolved by the subsystem that supplied the committed root;
/// it is not a segment id, byte offset, or other physical placement address.
/// A zero handle is reserved for "no root" and cannot be represented by this
/// type. The generation distinguishes successive publications that reuse the
/// same provider-owned logical handle.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct LifecycleRootIdentityV1 {
    logical_root_handle: u64,
    generation: u64,
}

impl LifecycleRootIdentityV1 {
    pub const MAGIC: [u8; 4] = *b"DLRI";
    pub const FORMAT_VERSION: u16 = 1;
    pub const WIRE_SIZE: usize = 24;

    const VERSION_OFFSET: usize = 4;
    const RESERVED_OFFSET: usize = 6;
    const LOGICAL_ROOT_HANDLE_OFFSET: usize = 8;
    const GENERATION_OFFSET: usize = 16;

    /// Construct a required logical root identity.
    ///
    /// Returns `None` for the reserved zero/absent handle.
    #[must_use]
    pub const fn new(logical_root_handle: u64, generation: u64) -> Option<Self> {
        if logical_root_handle == 0 {
            None
        } else {
            Some(Self {
                logical_root_handle,
                generation,
            })
        }
    }

    #[must_use]
    pub const fn logical_root_handle(self) -> u64 {
        self.logical_root_handle
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn encode(self) -> [u8; Self::WIRE_SIZE] {
        let mut bytes = [0_u8; Self::WIRE_SIZE];
        bytes[..Self::MAGIC.len()].copy_from_slice(&Self::MAGIC);
        bytes[Self::VERSION_OFFSET..Self::RESERVED_OFFSET]
            .copy_from_slice(&Self::FORMAT_VERSION.to_le_bytes());
        bytes[Self::LOGICAL_ROOT_HANDLE_OFFSET..Self::GENERATION_OFFSET]
            .copy_from_slice(&self.logical_root_handle.to_le_bytes());
        bytes[Self::GENERATION_OFFSET..Self::WIRE_SIZE]
            .copy_from_slice(&self.generation.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LifecycleRootIdentityDecodeError> {
        if bytes.len() != Self::WIRE_SIZE {
            return Err(LifecycleRootIdentityDecodeError::InvalidSize {
                actual: bytes.len(),
            });
        }
        if bytes[..Self::MAGIC.len()] != Self::MAGIC {
            return Err(LifecycleRootIdentityDecodeError::InvalidMagic);
        }
        let version =
            u16::from_le_bytes([bytes[Self::VERSION_OFFSET], bytes[Self::VERSION_OFFSET + 1]]);
        if version != Self::FORMAT_VERSION {
            return Err(LifecycleRootIdentityDecodeError::UnsupportedVersion { version });
        }
        let reserved = u16::from_le_bytes([
            bytes[Self::RESERVED_OFFSET],
            bytes[Self::RESERVED_OFFSET + 1],
        ]);
        if reserved != 0 {
            return Err(LifecycleRootIdentityDecodeError::NonzeroReserved { value: reserved });
        }
        let logical_root_handle = u64::from_le_bytes(
            bytes[Self::LOGICAL_ROOT_HANDLE_OFFSET..Self::GENERATION_OFFSET]
                .try_into()
                .expect("lifecycle root handle has fixed width"),
        );
        let generation = u64::from_le_bytes(
            bytes[Self::GENERATION_OFFSET..Self::WIRE_SIZE]
                .try_into()
                .expect("lifecycle root generation has fixed width"),
        );
        Self::new(logical_root_handle, generation)
            .ok_or(LifecycleRootIdentityDecodeError::MissingLogicalRoot)
    }
}

impl fmt::Display for LifecycleRootIdentityV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "logical-root(handle={}, generation={})",
            self.logical_root_handle, self.generation
        )
    }
}

impl fmt::Debug for LifecycleRootIdentityV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleRootIdentityDecodeError {
    InvalidSize { actual: usize },
    InvalidMagic,
    UnsupportedVersion { version: u16 },
    NonzeroReserved { value: u16 },
    MissingLogicalRoot,
}

impl fmt::Display for LifecycleRootIdentityDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize { actual } => write!(
                f,
                "invalid lifecycle root identity size {actual}, expected {}",
                LifecycleRootIdentityV1::WIRE_SIZE
            ),
            Self::InvalidMagic => f.write_str("invalid lifecycle root identity magic"),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported lifecycle root identity version {version}")
            }
            Self::NonzeroReserved { value } => write!(
                f,
                "lifecycle root identity reserved field is nonzero ({value})"
            ),
            Self::MissingLogicalRoot => {
                f.write_str("lifecycle root identity has a zero logical root handle")
            }
        }
    }
}

/// A GC-pinned traversal root recorded at destroy initiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraversalRoot {
    pub root_type: TraversalRootType,
    pub root_identity: LifecycleRootIdentityV1,
    pub estimated_objects: u64,
}

impl TraversalRoot {
    #[must_use]
    pub const fn new(
        root_type: TraversalRootType,
        root_identity: LifecycleRootIdentityV1,
        estimated_objects: u64,
    ) -> Self {
        TraversalRoot {
            root_type,
            root_identity,
            estimated_objects,
        }
    }

    /// Compare the durable root identity without treating an object-count
    /// estimate as part of that identity.
    #[must_use]
    pub const fn same_identity(self, other: Self) -> bool {
        self.root_type.to_u8() == other.root_type.to_u8()
            && self.root_identity.logical_root_handle == other.root_identity.logical_root_handle
            && self.root_identity.generation == other.root_identity.generation
    }
}

// ---------------------------------------------------------------------------
// DestroyJobRecordV1 -- persistent destroy job state
// ---------------------------------------------------------------------------

const DESTROY_JOB_MAGIC: [u8; 4] = [0x44, 0x53, 0x54, 0x52]; // "DSTR"

pub const MAX_TRAVERSAL_ROOTS: usize = 6;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestroyJobRecordV1 {
    pub magic: [u8; 4],
    pub version: u32,
    pub destroy_job_id: u64,
    pub destroy_commit_group: u64,
    pub destroy_flags: DestroyFlags,
    pub pinned_roots: [Option<TraversalRoot>; MAX_TRAVERSAL_ROOTS],
    pub pinned_roots_count: u8,
    pub objects_total: u64,
    pub objects_reclaimed: u64,
    pub bytes_reclaimed: u64,
    pub completion_commit_group: u64,
}

impl DestroyJobRecordV1 {
    #[must_use]
    pub fn new(
        destroy_job_id: u64,
        destroy_commit_group: u64,
        destroy_flags: DestroyFlags,
        pinned_roots: &[TraversalRoot],
        objects_total: u64,
    ) -> Option<Self> {
        if pinned_roots.len() > MAX_TRAVERSAL_ROOTS {
            return None;
        }
        let mut root_array: [Option<TraversalRoot>; MAX_TRAVERSAL_ROOTS] =
            [None; MAX_TRAVERSAL_ROOTS];
        for (i, root) in pinned_roots.iter().enumerate() {
            root_array[i] = Some(*root);
        }
        Some(DestroyJobRecordV1 {
            magic: DESTROY_JOB_MAGIC,
            version: 1,
            destroy_job_id,
            destroy_commit_group,
            destroy_flags,
            pinned_roots: root_array,
            pinned_roots_count: pinned_roots.len() as u8,
            objects_total,
            objects_reclaimed: 0,
            bytes_reclaimed: 0,
            completion_commit_group: 0,
        })
    }

    #[must_use]
    pub fn valid_roots(&self) -> &[Option<TraversalRoot>] {
        let n = (self.pinned_roots_count as usize).min(MAX_TRAVERSAL_ROOTS);
        &self.pinned_roots[..n]
    }

    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.completion_commit_group != 0
    }

    #[must_use]
    pub const fn magic_valid(&self) -> bool {
        self.magic[0] == DESTROY_JOB_MAGIC[0]
            && self.magic[1] == DESTROY_JOB_MAGIC[1]
            && self.magic[2] == DESTROY_JOB_MAGIC[2]
            && self.magic[3] == DESTROY_JOB_MAGIC[3]
    }

    #[must_use]
    pub const fn progress_ppm(&self) -> u64 {
        if self.objects_total == 0 {
            if self.is_completed() {
                return 1_000_000;
            }
            return 0;
        }
        let reclaimed = self.objects_reclaimed;
        if reclaimed >= self.objects_total {
            1_000_000
        } else {
            (reclaimed as u128)
                .saturating_mul(1_000_000)
                .saturating_div(self.objects_total as u128) as u64
        }
    }

    pub fn mark_complete(
        &mut self,
        completion_commit_group: u64,
        bytes_reclaimed: u64,
        objects_reclaimed: u64,
    ) {
        self.completion_commit_group = completion_commit_group;
        self.bytes_reclaimed = bytes_reclaimed;
        self.objects_reclaimed = objects_reclaimed;
    }
}

impl Default for DestroyJobRecordV1 {
    fn default() -> Self {
        DestroyJobRecordV1 {
            magic: DESTROY_JOB_MAGIC,
            version: 1,
            destroy_job_id: 0,
            destroy_commit_group: 0,
            destroy_flags: DestroyFlags::NONE,
            pinned_roots: [None; MAX_TRAVERSAL_ROOTS],
            pinned_roots_count: 0,
            objects_total: 0,
            objects_reclaimed: 0,
            bytes_reclaimed: 0,
            completion_commit_group: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PoisonState -- mount poisoning during DESTROYING
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum PoisonState {
    #[default]
    MountOk,
    PoisonPending,
    PoisonActive,
    MountDead,
}

impl PoisonState {
    /// Decode a u8 discriminant into a PoisonState.
    /// Unknown values map to MountDead (conservative default).
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => PoisonState::MountOk,
            1 => PoisonState::PoisonPending,
            2 => PoisonState::PoisonActive,
            _ => PoisonState::MountDead,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn should_reject_new_ops(self) -> bool {
        matches!(
            self,
            PoisonState::PoisonPending | PoisonState::PoisonActive | PoisonState::MountDead
        )
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, PoisonState::MountDead)
    }

    #[must_use]
    pub const fn is_healthy(self) -> bool {
        matches!(self, PoisonState::MountOk)
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            PoisonState::MountOk => "MOUNT_OK",
            PoisonState::PoisonPending => "POISON_PENDING",
            PoisonState::PoisonActive => "POISON_ACTIVE",
            PoisonState::MountDead => "MOUNT_DEAD",
        }
    }
}

// ---------------------------------------------------------------------------
impl fmt::Display for PoisonState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// PoisonReason -- why a dataset was poisoned
// ---------------------------------------------------------------------------

/// Reason a dataset entered the POISONED state.
///
/// Carried alongside [`PoisonState`] so the FUSE daemon can report a
/// meaningful error to userspace (EIO with diagnostic reason).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum PoisonReason {
    /// Dataset is healthy; no poison reason applicable.
    #[default]
    None = 0x00,
    /// On-disk or in-memory data corruption detected (checksum mismatch).
    CorruptionDetected = 0x01,
    /// Metadata inconsistency found during traversal or verification.
    MetadataInconsistency = 0x02,
    /// Administrator explicitly poisoned the dataset.
    AdminAction = 0x03,
    /// Unrecoverable I/O error from the backing storage layer.
    FatalIOError = 0x04,
    /// Cluster consensus lost: quorum was lost.
    ClusterConsensusLost = 0x05,
}

impl PoisonReason {
    /// Decode a u8 discriminant into a [`PoisonReason`].
    /// Unknown values map to [`PoisonReason::None`].
    #[must_use]
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0x00 => PoisonReason::None,
            0x01 => PoisonReason::CorruptionDetected,
            0x02 => PoisonReason::MetadataInconsistency,
            0x03 => PoisonReason::AdminAction,
            0x04 => PoisonReason::FatalIOError,
            0x05 => PoisonReason::ClusterConsensusLost,
            _ => PoisonReason::None,
        }
    }

    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            PoisonReason::None => "NONE",
            PoisonReason::CorruptionDetected => "CORRUPTION_DETECTED",
            PoisonReason::MetadataInconsistency => "METADATA_INCONSISTENCY",
            PoisonReason::AdminAction => "ADMIN_ACTION",
            PoisonReason::FatalIOError => "FATAL_IO_ERROR",
            PoisonReason::ClusterConsensusLost => "CLUSTER_CONSENSUS_LOST",
        }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        !matches!(self, PoisonReason::None)
    }

    /// POSIX errno for each reason. All active reasons return EIO (5).
    #[must_use]
    pub const fn errno(self) -> i32 {
        match self {
            PoisonReason::None => 0,
            _ => 5,
        }
    }
}

impl fmt::Display for PoisonReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// State transition validation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleError {
    InvalidTransition {
        from: DatasetStateV1,
        to: DatasetStateV1,
        reason: &'static str,
    },
    PreconditionFailed {
        from: DatasetStateV1,
        to: DatasetStateV1,
        reason: &'static str,
    },
    UnknownState {
        raw_byte: u8,
    },
    /// Dataset is not in a state that can be reaped.
    NotTombstone {
        actual: DatasetStateV1,
    },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleError::InvalidTransition { from, to, reason } => {
                write!(
                    f,
                    "invalid lifecycle transition {} -> {}: {}",
                    from.label(),
                    to.label(),
                    reason
                )
            }
            LifecycleError::PreconditionFailed { from, to, reason } => {
                write!(
                    f,
                    "precondition failed for {} -> {}: {}",
                    from.label(),
                    to.label(),
                    reason
                )
            }
            LifecycleError::UnknownState { raw_byte } => {
                write!(f, "unknown dataset state byte: 0x{raw_byte:02x}")
            }
            LifecycleError::NotTombstone { actual } => {
                write!(
                    f,
                    "dataset is in {} state, expected tombstone",
                    actual.label()
                )
            }
        }
    }
}

pub fn validate_transition(from: DatasetStateV1, to: DatasetStateV1) -> Result<(), LifecycleError> {
    match (from, to) {
        (DatasetStateV1::Active, DatasetStateV1::Destroying) => Ok(()),
        (DatasetStateV1::Active, DatasetStateV1::Tombstone) => {
            Err(LifecycleError::InvalidTransition {
                from,
                to,
                reason: "must transition through DESTROYING before TOMBSTONE",
            })
        }
        (DatasetStateV1::Destroying, DatasetStateV1::Active) => Ok(()),
        (DatasetStateV1::Destroying, DatasetStateV1::Tombstone) => Ok(()),
        (DatasetStateV1::Tombstone, DatasetStateV1::Active) => Ok(()),
        (DatasetStateV1::Tombstone, DatasetStateV1::Destroying) => {
            Err(LifecycleError::InvalidTransition {
                from,
                to,
                reason: "cannot re-destroy a tombstone dataset",
            })
        }
        _ => Ok(()),
    }
}

pub const VALID_TRANSITIONS: &[(DatasetStateV1, DatasetStateV1)] = &[
    (DatasetStateV1::Active, DatasetStateV1::Destroying),
    (DatasetStateV1::Destroying, DatasetStateV1::Tombstone),
    (DatasetStateV1::Destroying, DatasetStateV1::Active),
    (DatasetStateV1::Tombstone, DatasetStateV1::Active),
];

// ---------------------------------------------------------------------------
// DatasetOpenGate -- mount-time state checking
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatasetOpenResult {
    ReadWrite,
    ReadOnly,
}

impl DatasetOpenResult {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, DatasetOpenResult::ReadOnly)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatasetOpenError {
    DatasetNotFound {
        dataset_name: &'static str,
        reason: &'static str,
    },
    FeatureGateRefused {
        dataset_name: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for DatasetOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason,
            } => {
                write!(f, "dataset '{dataset_name}' not found: {reason}")
            }
            DatasetOpenError::FeatureGateRefused {
                dataset_name,
                reason,
            } => {
                write!(f, "dataset '{dataset_name}' mount refused: {reason}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DatasetOpenGate {
    _private: (),
}

impl DatasetOpenGate {
    #[must_use]
    pub const fn new() -> Self {
        DatasetOpenGate { _private: () }
    }

    pub fn check_state(
        self,
        state: DatasetStateV1,
        dataset_name: &'static str,
    ) -> Result<(), DatasetOpenError> {
        match state {
            DatasetStateV1::Active => Ok(()),
            DatasetStateV1::Destroying => Err(DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason: "dataset is being destroyed",
            }),
            DatasetStateV1::Tombstone => Err(DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason: "dataset has been destroyed",
            }),
        }
    }

    pub fn check_state_from_u8(
        self,
        raw_state: u8,
        dataset_name: &'static str,
    ) -> Result<DatasetStateV1, DatasetOpenError> {
        match DatasetStateV1::from_u8(raw_state) {
            Some(DatasetStateV1::Active) => Ok(DatasetStateV1::Active),
            Some(DatasetStateV1::Destroying) => Err(DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason: "dataset is being destroyed",
            }),
            Some(DatasetStateV1::Tombstone) => Err(DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason: "dataset has been destroyed",
            }),
            None => Err(DatasetOpenError::DatasetNotFound {
                dataset_name,
                reason: "dataset in unrecognized lifecycle state",
            }),
        }
    }

    #[must_use]
    pub const fn apply_feature_gate(self, feature_read_only: bool) -> DatasetOpenResult {
        if feature_read_only {
            DatasetOpenResult::ReadOnly
        } else {
            DatasetOpenResult::ReadWrite
        }
    }
}

// ---------------------------------------------------------------------------
// TombstoneReaperPolicy — reaper configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TombstoneReaperPolicy {
    /// Minimum time a dataset must spend in TOMBSTONE before reaping (wall-clock seconds).
    pub min_age_secs: u64,
    /// Maximum tombstones to reap in one scan cycle.
    pub max_per_scan: usize,
    /// Interval between reaper scans, in seconds.
    pub scan_interval_secs: u64,
}

impl TombstoneReaperPolicy {
    #[must_use]
    pub const fn new(min_age_secs: u64, max_per_scan: usize, scan_interval_secs: u64) -> Self {
        TombstoneReaperPolicy {
            min_age_secs,
            max_per_scan,
            scan_interval_secs,
        }
    }
}

impl Default for TombstoneReaperPolicy {
    fn default() -> Self {
        TombstoneReaperPolicy {
            min_age_secs: DEFAULT_REAPER_MIN_AGE_SECS,
            max_per_scan: DEFAULT_REAPER_MAX_PER_SCAN,
            scan_interval_secs: DEFAULT_REAPER_SCAN_INTERVAL_SECS,
        }
    }
}

// ---------------------------------------------------------------------------
// TombstoneReaperState — reaper lifecycle
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TombstoneReaperState {
    Running,
    Paused,
    Stopped,
}

// ---------------------------------------------------------------------------
// ReapEligibility — eligibility check result
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReapEligibility {
    Eligible,
    TooYoung {
        age_commit_groups: u64,
        required: u64,
    },
    ConsensusPending,
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DEFAULT_DESTROY_GRACE_SECS: u32 = 30;
/// Default minimum tombstone age in commit_group counts.
///
/// A commit_group commits every ~5-30 seconds under normal load. 100 commit_groups
/// corresponds to approximately 8-50 minutes of wall-clock time.
/// This is deliberately shorter than the 24-hour default in the
/// design spec §7.3; the spec value is the recommended production
/// setting. The const default is tuned for testability.
pub const DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS: u64 = 100;

pub const DEFAULT_REAPER_MIN_AGE_SECS: u64 = 86_400;
pub const DEFAULT_REAPER_MAX_PER_SCAN: usize = 128;
pub const DEFAULT_REAPER_SCAN_INTERVAL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// DatasetRecordV1 -- persistent BLAKE3-verified dataset record
// ---------------------------------------------------------------------------

/// Magic bytes for dataset record wire format: "DSET"
const DATASET_RECORD_MAGIC: [u8; 4] = [0x44, 0x53, 0x45, 0x54];

/// Current dataset record format version.
const DATASET_RECORD_VERSION: u32 = 1;

/// Maximum dataset name length in bytes.
pub const MAX_DATASET_NAME_LEN: usize = 255;

/// Wire-format payload size (everything before the 32-byte BLAKE3 checksum).
const DATASET_RECORD_PAYLOAD_SIZE: usize = 4 + 4 + 1 + MAX_DATASET_NAME_LEN + 8 + 8 + 8;

/// Wire-format total size (payload + 32-byte BLAKE3 checksum).
const DATASET_RECORD_ENCODED_SIZE: usize = DATASET_RECORD_PAYLOAD_SIZE + 32;

/// Dataset creation flags bitmask type.
///
/// Carries creation-time properties (read-only, no-mount, canonical
/// snapshots, encryption mandatory) in a compact `u64` repr.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub struct DatasetCreateFlags(u64);

impl DatasetCreateFlags {
    pub const NONE: Self = DatasetCreateFlags(0);
    pub const READ_ONLY: Self = DatasetCreateFlags(1 << 0);
    pub const NO_MOUNT: Self = DatasetCreateFlags(1 << 1);
    pub const CANONICAL_SNAPSHOTS: Self = DatasetCreateFlags(1 << 2);
    pub const ENCRYPTION_MANDATORY: Self = DatasetCreateFlags(1 << 3);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(raw: u64) -> Self {
        DatasetCreateFlags(raw)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn read_only(self) -> bool {
        self.0 & Self::READ_ONLY.0 != 0
    }

    #[must_use]
    pub const fn no_mount(self) -> bool {
        self.0 & Self::NO_MOUNT.0 != 0
    }

    #[must_use]
    pub const fn canonical_snapshots(self) -> bool {
        self.0 & Self::CANONICAL_SNAPSHOTS.0 != 0
    }

    #[must_use]
    pub const fn encryption_mandatory(self) -> bool {
        self.0 & Self::ENCRYPTION_MANDATORY.0 != 0
    }
}

impl core::ops::BitOr for DatasetCreateFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        DatasetCreateFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for DatasetCreateFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for DatasetCreateFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        DatasetCreateFlags(self.0 & rhs.0)
    }
}

impl fmt::Display for DatasetCreateFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut write_flag = |name: &str| -> fmt::Result {
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(name)
        };
        if self.read_only() {
            write_flag("READ_ONLY")?;
        }
        if self.no_mount() {
            write_flag("NO_MOUNT")?;
        }
        if self.canonical_snapshots() {
            write_flag("CANONICAL_SNAPSHOTS")?;
        }
        if self.encryption_mandatory() {
            write_flag("ENCRYPTION_MANDATORY")?;
        }
        if first {
            f.write_str("NONE")?;
        }
        Ok(())
    }
}

/// Persistent BLAKE3-verified dataset record.
///
/// Encoded as a 320-byte binary record: 4-byte magic "DSET", 4-byte
/// version, 1-byte name length, 255-byte name buffer, 8-byte parent
/// index, 8-byte creation txg, 8-byte flags, and a 32-byte BLAKE3
/// checksum over the preceding 288 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatasetRecordV1 {
    pub name_len: u8,
    pub name_bytes: [u8; MAX_DATASET_NAME_LEN],
    pub parent_index: u64,
    pub creation_txg: u64,
    pub flags: DatasetCreateFlags,
    pub checksum: [u8; 32],
}

impl DatasetRecordV1 {
    /// Create a new dataset record from a name and metadata.
    ///
    /// Returns `None` if `name` is empty or exceeds
    /// [`MAX_DATASET_NAME_LEN`].
    #[must_use]
    pub fn new(
        name: &str,
        parent_index: u64,
        creation_txg: u64,
        flags: DatasetCreateFlags,
    ) -> Option<Self> {
        let name_bytes_slice = name.as_bytes();
        let name_len = name_bytes_slice.len();
        if name_len == 0 || name_len > MAX_DATASET_NAME_LEN {
            return None;
        }
        let mut name_bytes = [0u8; MAX_DATASET_NAME_LEN];
        name_bytes[..name_len].copy_from_slice(name_bytes_slice);

        let checksum = Self::compute_checksum(
            name_len as u8,
            &name_bytes,
            parent_index,
            creation_txg,
            flags.bits(),
        );

        Some(DatasetRecordV1 {
            name_len: name_len as u8,
            name_bytes,
            parent_index,
            creation_txg,
            flags,
            checksum,
        })
    }

    /// Extract the dataset name as `&str`.
    ///
    /// The name is UTF-8 validated at construction time.
    #[must_use]
    pub fn name(&self) -> &str {
        let len = (self.name_len as usize).min(MAX_DATASET_NAME_LEN);
        core::str::from_utf8(&self.name_bytes[..len]).unwrap_or("")
    }

    /// Encode the record into its 320-byte wire format with a fresh
    /// BLAKE3 checksum.
    #[must_use]
    pub fn encode(&self) -> [u8; DATASET_RECORD_ENCODED_SIZE] {
        let mut buf = [0u8; DATASET_RECORD_ENCODED_SIZE];
        let mut pos = 0usize;
        // magic
        buf[pos..pos + 4].copy_from_slice(&DATASET_RECORD_MAGIC);
        pos += 4;
        // version
        buf[pos..pos + 4].copy_from_slice(&DATASET_RECORD_VERSION.to_le_bytes());
        pos += 4;
        // name_len
        buf[pos] = self.name_len;
        pos += 1;
        // name_bytes
        buf[pos..pos + MAX_DATASET_NAME_LEN].copy_from_slice(&self.name_bytes);
        pos += MAX_DATASET_NAME_LEN;
        // parent_index (little-endian)
        buf[pos..pos + 8].copy_from_slice(&self.parent_index.to_le_bytes());
        pos += 8;
        // creation_txg (little-endian)
        buf[pos..pos + 8].copy_from_slice(&self.creation_txg.to_le_bytes());
        pos += 8;
        // flags (little-endian)
        buf[pos..pos + 8].copy_from_slice(&self.flags.bits().to_le_bytes());
        // BLAKE3 checksum over payload (excluding checksum field itself)
        let payload = &buf[..DATASET_RECORD_PAYLOAD_SIZE];
        let checksum = blake3::hash(payload);
        buf[DATASET_RECORD_PAYLOAD_SIZE..].copy_from_slice(checksum.as_bytes());
        buf
    }

    /// Decode a record from its 320-byte wire format.
    ///
    /// Returns `None` if the magic or version don't match, or if the
    /// BLAKE3 checksum fails.
    #[must_use]
    pub fn decode(buf: &[u8; DATASET_RECORD_ENCODED_SIZE]) -> Option<Self> {
        // Verify magic
        if buf[0..4] != DATASET_RECORD_MAGIC {
            return None;
        }
        // Verify version
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != DATASET_RECORD_VERSION {
            return None;
        }
        // Verify checksum
        let payload = &buf[..DATASET_RECORD_PAYLOAD_SIZE];
        let expected = blake3::hash(payload);
        if expected.as_bytes() != &buf[DATASET_RECORD_PAYLOAD_SIZE..] {
            return None;
        }

        let name_len = buf[8];
        if name_len as usize > MAX_DATASET_NAME_LEN {
            return None;
        }
        let mut name_bytes = [0u8; MAX_DATASET_NAME_LEN];
        name_bytes[..(name_len as usize)].copy_from_slice(&buf[9..9 + (name_len as usize)]);
        let parent_index = u64::from_le_bytes([
            buf[264], buf[265], buf[266], buf[267], buf[268], buf[269], buf[270], buf[271],
        ]);
        let creation_txg = u64::from_le_bytes([
            buf[272], buf[273], buf[274], buf[275], buf[276], buf[277], buf[278], buf[279],
        ]);
        let flags_raw = u64::from_le_bytes([
            buf[280], buf[281], buf[282], buf[283], buf[284], buf[285], buf[286], buf[287],
        ]);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&buf[DATASET_RECORD_PAYLOAD_SIZE..]);

        Some(DatasetRecordV1 {
            name_len,
            name_bytes,
            parent_index,
            creation_txg,
            flags: DatasetCreateFlags::from_bits(flags_raw),
            checksum,
        })
    }

    /// Verify the BLAKE3 checksum over the record payload.
    #[must_use]
    pub fn verify_checksum(&self) -> bool {
        let expected = Self::compute_checksum(
            self.name_len,
            &self.name_bytes,
            self.parent_index,
            self.creation_txg,
            self.flags.bits(),
        );
        expected == self.checksum
    }

    /// Compute the BLAKE3 checksum for the given record fields.
    fn compute_checksum(
        name_len: u8,
        name_bytes: &[u8; MAX_DATASET_NAME_LEN],
        parent_index: u64,
        creation_txg: u64,
        flags: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&DATASET_RECORD_MAGIC);
        hasher.update(&DATASET_RECORD_VERSION.to_le_bytes());
        hasher.update(&[name_len]);
        hasher.update(name_bytes);
        hasher.update(&parent_index.to_le_bytes());
        hasher.update(&creation_txg.to_le_bytes());
        hasher.update(&flags.to_le_bytes());
        let hash = hasher.finalize();
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(hash.as_bytes());
        checksum
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip_all_variants() {
        for state in [
            DatasetStateV1::Active,
            DatasetStateV1::Destroying,
            DatasetStateV1::Tombstone,
        ] {
            let byte = state.to_u8();
            let decoded = DatasetStateV1::from_u8(byte);
            assert_eq!(decoded, Some(state));
        }
    }

    #[test]
    fn state_invalid_bytes() {
        assert_eq!(DatasetStateV1::from_u8(0x00), None);
        assert_eq!(DatasetStateV1::from_u8(0x04), None);
        assert_eq!(DatasetStateV1::from_u8(0xFF), None);
    }

    #[test]
    fn state_display() {
        assert_eq!(DatasetStateV1::Active.to_string(), "active");
        assert_eq!(DatasetStateV1::Destroying.to_string(), "destroying");
        assert_eq!(DatasetStateV1::Tombstone.to_string(), "tombstone");
    }

    #[test]
    fn state_default_is_active() {
        assert_eq!(DatasetStateV1::default(), DatasetStateV1::Active);
    }

    #[test]
    fn state_is_mountable() {
        assert!(DatasetStateV1::Active.is_mountable());
        assert!(!DatasetStateV1::Destroying.is_mountable());
        assert!(!DatasetStateV1::Tombstone.is_mountable());
    }

    #[test]
    fn state_is_terminal() {
        assert!(!DatasetStateV1::Active.is_terminal());
        assert!(!DatasetStateV1::Destroying.is_terminal());
        assert!(DatasetStateV1::Tombstone.is_terminal());
    }

    #[test]
    fn state_accepts_writes() {
        assert!(DatasetStateV1::Active.accepts_writes());
        assert!(!DatasetStateV1::Destroying.accepts_writes());
        assert!(!DatasetStateV1::Tombstone.accepts_writes());
    }

    #[test]
    fn state_known_bytes_match_constants() {
        assert_eq!(DatasetStateV1::Active.to_u8(), DatasetStateV1::ACTIVE_BYTE);
        assert_eq!(
            DatasetStateV1::Destroying.to_u8(),
            DatasetStateV1::DESTROYING_BYTE
        );
        assert_eq!(
            DatasetStateV1::Tombstone.to_u8(),
            DatasetStateV1::TOMBSTONE_BYTE
        );
    }

    // -- DestroyFlags --

    #[test]
    fn destroy_flags_default_is_none() {
        let f = DestroyFlags::default();
        assert!(f.is_empty());
        assert!(!f.force_unmount());
        assert!(!f.skip_orphans());
        assert!(!f.no_tombstone());
        assert!(!f.is_dry_run());
    }

    #[test]
    fn destroy_flags_bitor_combines() {
        let f = DestroyFlags::FORCE_UNMOUNT | DestroyFlags::SKIP_ORPHANS;
        assert!(f.force_unmount());
        assert!(f.skip_orphans());
        assert!(!f.no_tombstone());
    }

    #[test]
    fn destroy_flags_bitor_assign() {
        let mut f = DestroyFlags::FORCE_UNMOUNT;
        f |= DestroyFlags::NO_TOMBSTONE;
        assert!(f.force_unmount());
        assert!(f.no_tombstone());
    }

    #[test]
    fn destroy_flags_bitand() {
        let f = (DestroyFlags::FORCE_UNMOUNT | DestroyFlags::DRY_RUN) & DestroyFlags::FORCE_UNMOUNT;
        assert!(f.force_unmount());
        assert!(!f.is_dry_run());
    }

    #[test]
    fn destroy_flags_from_bits_preserves_unknown() {
        let f = DestroyFlags::from_bits(0x8000_0000 | 0x01);
        assert!(f.force_unmount());
        assert_eq!(f.bits(), 0x8000_0001);
    }

    #[test]
    fn destroy_flags_display_all() {
        let f = DestroyFlags::FORCE_UNMOUNT
            | DestroyFlags::SKIP_ORPHANS
            | DestroyFlags::NO_TOMBSTONE
            | DestroyFlags::DRY_RUN;
        let s = f.to_string();
        assert!(s.contains("FORCE_UNMOUNT"));
        assert!(s.contains("SKIP_ORPHANS"));
        assert!(s.contains("NO_TOMBSTONE"));
        assert!(s.contains("DRY_RUN"));
    }

    #[test]
    fn destroy_flags_display_none() {
        assert_eq!(DestroyFlags::NONE.to_string(), "NONE");
    }

    // -- TraversalRoot --

    fn root_identity(handle: u64) -> LifecycleRootIdentityV1 {
        LifecycleRootIdentityV1::new(handle, 7).unwrap()
    }

    #[test]
    fn traversal_root_type_roundtrip() {
        for t in [
            TraversalRootType::InodeTable,
            TraversalRootType::ExtentMap,
            TraversalRootType::DirectoryIndex,
            TraversalRootType::XattrStore,
            TraversalRootType::SnapshotCatalog,
            TraversalRootType::FeatureFlags,
        ] {
            let byte = t.to_u8();
            let decoded = TraversalRootType::from_u8(byte);
            assert_eq!(decoded, Some(t));
        }
    }

    #[test]
    fn traversal_root_type_invalid() {
        assert_eq!(TraversalRootType::from_u8(0x00), None);
        assert_eq!(TraversalRootType::from_u8(0x07), None);
        assert_eq!(TraversalRootType::from_u8(0xFF), None);
    }

    #[test]
    fn lifecycle_root_identity_requires_nonzero_handle() {
        assert_eq!(LifecycleRootIdentityV1::new(0, 7), None);
        assert_eq!(
            LifecycleRootIdentityV1::new(42, 7)
                .unwrap()
                .logical_root_handle(),
            42
        );
    }

    #[test]
    fn lifecycle_root_identity_roundtrip_and_display() {
        let identity = LifecycleRootIdentityV1::new(42, 7).unwrap();
        assert_eq!(identity.generation(), 7);
        assert_eq!(
            LifecycleRootIdentityV1::decode(&identity.encode()),
            Ok(identity)
        );
        assert_eq!(
            identity.to_string(),
            "logical-root(handle=42, generation=7)"
        );
        assert_eq!(format!("{identity:?}"), identity.to_string());
    }

    #[test]
    fn lifecycle_root_identity_decode_fails_closed() {
        let identity = LifecycleRootIdentityV1::new(42, 7).unwrap();

        assert_eq!(
            LifecycleRootIdentityV1::decode(&identity.encode()[..23]),
            Err(LifecycleRootIdentityDecodeError::InvalidSize { actual: 23 })
        );

        let mut invalid_magic = identity.encode();
        invalid_magic[0] ^= 0xff;
        assert_eq!(
            LifecycleRootIdentityV1::decode(&invalid_magic),
            Err(LifecycleRootIdentityDecodeError::InvalidMagic)
        );

        let mut unsupported_version = identity.encode();
        unsupported_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            LifecycleRootIdentityV1::decode(&unsupported_version),
            Err(LifecycleRootIdentityDecodeError::UnsupportedVersion { version: 2 })
        );

        let mut nonzero_reserved = identity.encode();
        nonzero_reserved[6..8].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            LifecycleRootIdentityV1::decode(&nonzero_reserved),
            Err(LifecycleRootIdentityDecodeError::NonzeroReserved { value: 1 })
        );

        let mut missing_root = identity.encode();
        missing_root[8..16].fill(0);
        assert_eq!(
            LifecycleRootIdentityV1::decode(&missing_root),
            Err(LifecycleRootIdentityDecodeError::MissingLogicalRoot)
        );
    }

    #[test]
    fn traversal_root_create() {
        let root = TraversalRoot::new(TraversalRootType::InodeTable, root_identity(100), 5000);
        assert_eq!(root.root_type, TraversalRootType::InodeTable);
        assert_eq!(root.root_identity, root_identity(100));
        assert_eq!(root.estimated_objects, 5000);
        assert!(root.same_identity(TraversalRoot::new(
            TraversalRootType::InodeTable,
            root_identity(100),
            1,
        )));
    }

    // -- DestroyJobRecordV1 --

    #[test]
    fn destroy_job_record_new() {
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, root_identity(1), 100),
            TraversalRoot::new(TraversalRootType::ExtentMap, root_identity(2), 50),
        ];
        let job =
            DestroyJobRecordV1::new(42, 1000, DestroyFlags::FORCE_UNMOUNT, &roots, 150).unwrap();
        assert_eq!(job.destroy_job_id, 42);
        assert_eq!(job.destroy_commit_group, 1000);
        assert!(job.destroy_flags.force_unmount());
        assert_eq!(job.pinned_roots_count, 2);
        assert_eq!(job.objects_total, 150);
        assert_eq!(job.objects_reclaimed, 0);
        assert_eq!(job.bytes_reclaimed, 0);
        assert_eq!(job.completion_commit_group, 0);
        assert!(job.magic_valid());
        assert!(!job.is_completed());
    }

    #[test]
    fn destroy_job_record_too_many_roots() {
        let roots: [TraversalRoot; 7] =
            [TraversalRoot::new(TraversalRootType::InodeTable, root_identity(1), 10); 7];
        let job = DestroyJobRecordV1::new(1, 1, DestroyFlags::NONE, &roots, 70);
        assert!(job.is_none());
    }

    #[test]
    fn destroy_job_record_valid_roots() {
        let roots = [
            TraversalRoot::new(TraversalRootType::InodeTable, root_identity(1), 10),
            TraversalRoot::new(TraversalRootType::ExtentMap, root_identity(2), 20),
        ];
        let job = DestroyJobRecordV1::new(1, 1, DestroyFlags::NONE, &roots, 30).unwrap();
        let valid = job.valid_roots();
        assert_eq!(valid.len(), 2);
        assert!(valid[0].is_some());
        assert_eq!(valid[0].unwrap().root_type, TraversalRootType::InodeTable);
    }

    #[test]
    fn destroy_job_record_mark_complete() {
        let mut job = DestroyJobRecordV1::default();
        assert!(!job.is_completed());
        job.mark_complete(2000, 5000, 10);
        assert!(job.is_completed());
        assert_eq!(job.completion_commit_group, 2000);
        assert_eq!(job.bytes_reclaimed, 5000);
        assert_eq!(job.objects_reclaimed, 10);
    }

    #[test]
    fn destroy_job_record_magic_default_valid() {
        let job = DestroyJobRecordV1::default();
        assert!(job.magic_valid());
    }

    #[test]
    fn destroy_job_record_magic_corrupt() {
        let mut job = DestroyJobRecordV1::default();
        job.magic[0] = 0xFF;
        assert!(!job.magic_valid());
    }

    #[test]
    fn destroy_job_record_progress_ppm() {
        let mut job = DestroyJobRecordV1::default();
        assert_eq!(job.progress_ppm(), 0);
        job.objects_total = 100;
        job.objects_reclaimed = 50;
        assert_eq!(job.progress_ppm(), 500_000);
        job.objects_reclaimed = 100;
        assert_eq!(job.progress_ppm(), 1_000_000);
        let job2 = DestroyJobRecordV1 {
            completion_commit_group: 1,
            ..Default::default()
        };
        assert_eq!(job2.progress_ppm(), 1_000_000);
    }

    // -- PoisonState --

    #[test]
    fn poison_state_should_reject_new_ops() {
        assert!(!PoisonState::MountOk.should_reject_new_ops());
        assert!(PoisonState::PoisonPending.should_reject_new_ops());
        assert!(PoisonState::PoisonActive.should_reject_new_ops());
        assert!(PoisonState::MountDead.should_reject_new_ops());
    }

    #[test]
    fn poison_state_is_terminal() {
        assert!(!PoisonState::MountOk.is_terminal());
        assert!(!PoisonState::PoisonPending.is_terminal());
        assert!(!PoisonState::PoisonActive.is_terminal());
        assert!(PoisonState::MountDead.is_terminal());
    }

    #[test]
    fn poison_state_is_healthy() {
        assert!(PoisonState::MountOk.is_healthy());
        assert!(!PoisonState::PoisonPending.is_healthy());
        assert!(!PoisonState::PoisonActive.is_healthy());
        assert!(!PoisonState::MountDead.is_healthy());
    }

    #[test]
    fn poison_state_default_is_mount_ok() {
        assert_eq!(PoisonState::default(), PoisonState::MountOk);
    }

    #[test]
    fn poison_state_display() {
        assert_eq!(PoisonState::MountOk.to_string(), "MOUNT_OK");
        assert_eq!(PoisonState::PoisonPending.to_string(), "POISON_PENDING");
        assert_eq!(PoisonState::PoisonActive.to_string(), "POISON_ACTIVE");
        assert_eq!(PoisonState::MountDead.to_string(), "MOUNT_DEAD");
    }
    // -- PoisonReason --

    #[test]
    fn poison_reason_default_is_none() {
        assert_eq!(PoisonReason::default(), PoisonReason::None);
        assert!(!PoisonReason::None.is_active());
    }

    #[test]
    fn poison_reason_roundtrip_all_variants() {
        for reason in [
            PoisonReason::None,
            PoisonReason::CorruptionDetected,
            PoisonReason::MetadataInconsistency,
            PoisonReason::AdminAction,
            PoisonReason::FatalIOError,
            PoisonReason::ClusterConsensusLost,
        ] {
            let byte = reason.to_u8();
            let decoded = PoisonReason::from_u8(byte);
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn poison_reason_invalid_byte_maps_to_none() {
        assert_eq!(PoisonReason::from_u8(0x06), PoisonReason::None);
        assert_eq!(PoisonReason::from_u8(0xFF), PoisonReason::None);
    }

    #[test]
    fn poison_reason_active_variants_are_active() {
        assert!(PoisonReason::CorruptionDetected.is_active());
        assert!(PoisonReason::MetadataInconsistency.is_active());
        assert!(PoisonReason::AdminAction.is_active());
        assert!(PoisonReason::FatalIOError.is_active());
        assert!(PoisonReason::ClusterConsensusLost.is_active());
    }

    #[test]
    fn poison_reason_errno_returns_eio_for_active_reasons() {
        assert_eq!(PoisonReason::None.errno(), 0);
        assert_eq!(PoisonReason::CorruptionDetected.errno(), 5);
        assert_eq!(PoisonReason::ClusterConsensusLost.errno(), 5);
    }

    // -- State transitions --

    #[test]
    fn valid_transition_active_to_destroying() {
        assert!(validate_transition(DatasetStateV1::Active, DatasetStateV1::Destroying).is_ok());
    }

    #[test]
    fn valid_transition_destroying_to_tombstone() {
        assert!(validate_transition(DatasetStateV1::Destroying, DatasetStateV1::Tombstone).is_ok());
    }

    #[test]
    fn valid_transition_destroying_to_active_abort() {
        assert!(validate_transition(DatasetStateV1::Destroying, DatasetStateV1::Active).is_ok());
    }

    #[test]
    fn valid_transition_tombstone_to_active_recovery() {
        assert!(validate_transition(DatasetStateV1::Tombstone, DatasetStateV1::Active).is_ok());
    }

    #[test]
    fn invalid_transition_active_to_tombstone() {
        let err =
            validate_transition(DatasetStateV1::Active, DatasetStateV1::Tombstone).unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
        let msg = err.to_string();
        assert!(msg.contains("DESTROYING"));
    }

    #[test]
    fn invalid_transition_tombstone_to_destroying() {
        let err =
            validate_transition(DatasetStateV1::Tombstone, DatasetStateV1::Destroying).unwrap_err();
        assert!(matches!(err, LifecycleError::InvalidTransition { .. }));
        let msg = err.to_string();
        assert!(msg.contains("re-destroy"));
    }

    #[test]
    fn valid_transition_same_state_idempotent() {
        assert!(validate_transition(DatasetStateV1::Active, DatasetStateV1::Active).is_ok());
        assert!(
            validate_transition(DatasetStateV1::Destroying, DatasetStateV1::Destroying).is_ok()
        );
        assert!(validate_transition(DatasetStateV1::Tombstone, DatasetStateV1::Tombstone).is_ok());
    }

    #[test]
    fn valid_transitions_const_is_correct() {
        for &(from, to) in VALID_TRANSITIONS {
            assert!(
                validate_transition(from, to).is_ok(),
                "VALID_TRANSITIONS contains invalid pair: {from:?} -> {to:?}"
            );
        }
        assert_eq!(VALID_TRANSITIONS.len(), 4);
    }

    #[test]
    fn lifecycle_error_display() {
        let e = LifecycleError::InvalidTransition {
            from: DatasetStateV1::Active,
            to: DatasetStateV1::Tombstone,
            reason: "must go through DESTROYING",
        };
        let s = e.to_string();
        assert!(s.contains("active"));
        assert!(s.contains("tombstone"));
    }

    // -- DatasetOpenGate --

    #[test]
    fn open_gate_check_active_allows() {
        let gate = DatasetOpenGate::new();
        assert!(gate.check_state(DatasetStateV1::Active, "testds").is_ok());
    }

    #[test]
    fn open_gate_check_destroying_refuses() {
        let gate = DatasetOpenGate::new();
        let err = gate
            .check_state(DatasetStateV1::Destroying, "testds")
            .unwrap_err();
        assert!(matches!(err, DatasetOpenError::DatasetNotFound { .. }));
        assert!(err.to_string().contains("being destroyed"));
    }

    #[test]
    fn open_gate_check_tombstone_refuses() {
        let gate = DatasetOpenGate::new();
        let err = gate
            .check_state(DatasetStateV1::Tombstone, "testds")
            .unwrap_err();
        assert!(matches!(err, DatasetOpenError::DatasetNotFound { .. }));
        assert!(err.to_string().contains("has been destroyed"));
    }

    #[test]
    fn open_gate_check_from_u8_active() {
        let gate = DatasetOpenGate::new();
        let result = gate.check_state_from_u8(0x01, "testds");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DatasetStateV1::Active);
    }

    #[test]
    fn open_gate_check_from_u8_destroying() {
        let gate = DatasetOpenGate::new();
        let err = gate.check_state_from_u8(0x02, "testds").unwrap_err();
        assert!(err.to_string().contains("being destroyed"));
    }

    #[test]
    fn open_gate_check_from_u8_tombstone() {
        let gate = DatasetOpenGate::new();
        let err = gate.check_state_from_u8(0x03, "testds").unwrap_err();
        assert!(err.to_string().contains("has been destroyed"));
    }

    #[test]
    fn open_gate_check_from_u8_unknown_treated_as_tombstone() {
        let gate = DatasetOpenGate::new();
        let err = gate.check_state_from_u8(0x00, "testds").unwrap_err();
        assert!(err.to_string().contains("unrecognized"));
        let err = gate.check_state_from_u8(0xFF, "testds").unwrap_err();
        assert!(err.to_string().contains("unrecognized"));
    }

    #[test]
    fn open_gate_feature_gate_rw() {
        let gate = DatasetOpenGate::new();
        let result = gate.apply_feature_gate(false);
        assert_eq!(result, DatasetOpenResult::ReadWrite);
        assert!(!result.is_read_only());
    }

    #[test]
    fn open_gate_feature_gate_ro() {
        let gate = DatasetOpenGate::new();
        let result = gate.apply_feature_gate(true);
        assert_eq!(result, DatasetOpenResult::ReadOnly);
        assert!(result.is_read_only());
    }

    #[test]
    fn dataset_open_error_display() {
        let e = DatasetOpenError::DatasetNotFound {
            dataset_name: "myds",
            reason: "test",
        };
        assert!(e.to_string().contains("myds"));
        let e2 = DatasetOpenError::FeatureGateRefused {
            dataset_name: "myds",
            reason: "incompat",
        };
        assert!(e2.to_string().contains("refused"));
    }

    #[test]
    fn constants_reasonable() {
        let defaults = [
            (DEFAULT_DESTROY_GRACE_SECS as u64, 1),
            (DEFAULT_TOMBSTONE_MIN_AGE_COMMIT_GROUPS, 10),
        ];
        for (value, minimum) in defaults {
            assert!(value >= minimum);
        }
    }

    #[test]
    fn destroy_flags_all_single_roundtrip() {
        for flag in [
            DestroyFlags::FORCE_UNMOUNT,
            DestroyFlags::SKIP_ORPHANS,
            DestroyFlags::NO_TOMBSTONE,
            DestroyFlags::DRY_RUN,
        ] {
            assert_eq!(DestroyFlags::from_bits(flag.bits()), flag);
        }
    }

    #[test]
    fn max_traversal_roots_covers_all_types() {
        let traversal_limits = [MAX_TRAVERSAL_ROOTS];
        assert!(traversal_limits[0] >= 6);
    }

    // -- TombstoneReaperPolicy --

    #[test]
    fn tombstone_reaper_policy_default() {
        let p = TombstoneReaperPolicy::default();
        assert_eq!(p.min_age_secs, DEFAULT_REAPER_MIN_AGE_SECS);
        assert_eq!(p.max_per_scan, DEFAULT_REAPER_MAX_PER_SCAN);
        assert_eq!(p.scan_interval_secs, DEFAULT_REAPER_SCAN_INTERVAL_SECS);
    }

    #[test]
    fn tombstone_reaper_policy_new() {
        let p = TombstoneReaperPolicy::new(3600, 42, 30);
        assert_eq!(p.min_age_secs, 3600);
        assert_eq!(p.max_per_scan, 42);
        assert_eq!(p.scan_interval_secs, 30);
    }

    // -- TombstoneReaperState --

    #[test]
    fn tombstone_reaper_state_values_distinct() {
        assert_ne!(TombstoneReaperState::Running, TombstoneReaperState::Paused);
        assert_ne!(TombstoneReaperState::Running, TombstoneReaperState::Stopped);
        assert_ne!(TombstoneReaperState::Paused, TombstoneReaperState::Stopped);
    }

    // -- ReapEligibility --

    #[test]
    fn reap_eligibility_values_distinct() {
        assert_ne!(
            ReapEligibility::Eligible,
            ReapEligibility::TooYoung {
                age_commit_groups: 0,
                required: 1
            }
        );
        assert_ne!(ReapEligibility::Eligible, ReapEligibility::ConsensusPending);
        assert_ne!(
            ReapEligibility::TooYoung {
                age_commit_groups: 0,
                required: 1
            },
            ReapEligibility::ConsensusPending,
        );
    }

    // -- LifecycleError --

    #[test]
    fn lifecycle_error_not_tombstone_display() {
        let e = LifecycleError::NotTombstone {
            actual: DatasetStateV1::Active,
        };
        let s = format!("{e}");
        assert!(!s.is_empty());
        assert!(s.contains("active"));
        assert!(s.contains("tombstone"));
    }

    // -- Reaper constants --

    #[test]
    fn reaper_constants_reasonable() {
        let reaper_defaults = [
            DEFAULT_REAPER_MIN_AGE_SECS,
            DEFAULT_REAPER_MAX_PER_SCAN as u64,
            DEFAULT_REAPER_SCAN_INTERVAL_SECS,
        ];
        assert!(reaper_defaults.iter().all(|value| *value > 0));
    }

    // -- DatasetRecordV1 --

    #[test]
    fn dataset_record_constants_reasonable() {
        assert_eq!(MAX_DATASET_NAME_LEN, 255);
        assert_eq!(DATASET_RECORD_PAYLOAD_SIZE, 288);
        assert_eq!(DATASET_RECORD_ENCODED_SIZE, 320);
    }

    #[test]
    fn create_flags_none_is_empty() {
        let f = DatasetCreateFlags::NONE;
        assert!(f.is_empty());
        assert_eq!(f.bits(), 0);
    }

    #[test]
    fn create_flags_single_bits() {
        assert!(DatasetCreateFlags::READ_ONLY.read_only());
        assert!(!DatasetCreateFlags::READ_ONLY.no_mount());
        assert_eq!(DatasetCreateFlags::READ_ONLY.bits(), 1 << 0);

        assert!(DatasetCreateFlags::NO_MOUNT.no_mount());
        assert_eq!(DatasetCreateFlags::NO_MOUNT.bits(), 1 << 1);

        assert!(DatasetCreateFlags::CANONICAL_SNAPSHOTS.canonical_snapshots());
        assert_eq!(DatasetCreateFlags::CANONICAL_SNAPSHOTS.bits(), 1 << 2);

        assert!(DatasetCreateFlags::ENCRYPTION_MANDATORY.encryption_mandatory());
        assert_eq!(DatasetCreateFlags::ENCRYPTION_MANDATORY.bits(), 1 << 3);
    }

    #[test]
    fn create_flags_bitor_combines() {
        let f = DatasetCreateFlags::READ_ONLY | DatasetCreateFlags::NO_MOUNT;
        assert!(f.read_only());
        assert!(f.no_mount());
        assert!(!f.canonical_snapshots());
    }

    #[test]
    fn create_flags_bitor_assign() {
        let mut f = DatasetCreateFlags::NONE;
        f |= DatasetCreateFlags::READ_ONLY;
        assert!(f.read_only());
        f |= DatasetCreateFlags::CANONICAL_SNAPSHOTS;
        assert!(f.read_only());
        assert!(f.canonical_snapshots());
    }

    #[test]
    fn create_flags_bitand() {
        let f = DatasetCreateFlags::READ_ONLY | DatasetCreateFlags::NO_MOUNT;
        let mask = DatasetCreateFlags::READ_ONLY;
        assert!((f & mask).read_only());
        assert!(!(f & mask).no_mount());
    }

    #[test]
    fn create_flags_from_bits_roundtrip() {
        let flags = DatasetCreateFlags::READ_ONLY | DatasetCreateFlags::CANONICAL_SNAPSHOTS;
        let raw = flags.bits();
        let back = DatasetCreateFlags::from_bits(raw);
        assert_eq!(flags, back);
    }

    #[test]
    fn create_flags_display() {
        let f = DatasetCreateFlags::NONE;
        assert_eq!(format!("{f}"), "NONE");

        let f = DatasetCreateFlags::READ_ONLY;
        assert_eq!(format!("{f}"), "READ_ONLY");

        let f = DatasetCreateFlags::READ_ONLY | DatasetCreateFlags::NO_MOUNT;
        let s = format!("{f}");
        assert!(s.contains("READ_ONLY"));
        assert!(s.contains("NO_MOUNT"));
        assert!(s.contains('|'));
    }

    #[test]
    fn dataset_record_new_rejects_empty_name() {
        assert!(DatasetRecordV1::new("", 0, 1, DatasetCreateFlags::NONE).is_none());
    }

    #[test]
    fn dataset_record_new_rejects_overlong_name() {
        let name = "x".repeat(256);
        assert!(DatasetRecordV1::new(&name, 0, 1, DatasetCreateFlags::NONE).is_none());
    }

    #[test]
    fn dataset_record_new_accepts_max_length() {
        let name = "x".repeat(255);
        let record = DatasetRecordV1::new(&name, 0, 1, DatasetCreateFlags::NONE);
        assert!(record.is_some());
        assert_eq!(record.unwrap().name_len, 255);
    }

    #[test]
    fn dataset_record_encode_decode_roundtrip() {
        let record = DatasetRecordV1::new("test-dataset", 42, 100, DatasetCreateFlags::READ_ONLY)
            .expect("create record");
        let encoded = record.encode();
        let decoded = DatasetRecordV1::decode(&encoded).expect("decode record");
        assert_eq!(record, decoded);
        assert_eq!(decoded.name(), "test-dataset");
        assert_eq!(decoded.parent_index, 42);
        assert_eq!(decoded.creation_txg, 100);
        assert!(decoded.flags.read_only());
    }

    #[test]
    fn dataset_record_encode_decode_with_all_flags() {
        let flags = DatasetCreateFlags::READ_ONLY
            | DatasetCreateFlags::NO_MOUNT
            | DatasetCreateFlags::CANONICAL_SNAPSHOTS
            | DatasetCreateFlags::ENCRYPTION_MANDATORY;
        let record = DatasetRecordV1::new("full-flags", 0, 1, flags).expect("create");
        let encoded = record.encode();
        let decoded = DatasetRecordV1::decode(&encoded).expect("decode");
        assert_eq!(record, decoded);
        assert!(decoded.flags.read_only());
        assert!(decoded.flags.no_mount());
        assert!(decoded.flags.canonical_snapshots());
        assert!(decoded.flags.encryption_mandatory());
    }

    #[test]
    fn dataset_record_decode_rejects_bad_magic() {
        let record = DatasetRecordV1::new("test", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let mut encoded = record.encode();
        encoded[0] ^= 0xFF;
        assert!(DatasetRecordV1::decode(&encoded).is_none());
    }

    #[test]
    fn dataset_record_decode_rejects_bad_version() {
        let record = DatasetRecordV1::new("test", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let mut encoded = record.encode();
        encoded[4] ^= 1;
        assert!(DatasetRecordV1::decode(&encoded).is_none());
    }

    #[test]
    fn dataset_record_tamper_detection() {
        let record = DatasetRecordV1::new("data", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let mut encoded = record.encode();
        // Flip a byte in the name area
        encoded[10] ^= 0x42;
        assert!(DatasetRecordV1::decode(&encoded).is_none());
    }

    #[test]
    fn dataset_record_verify_checksum_passes() {
        let record = DatasetRecordV1::new("valid", 0, 1, DatasetCreateFlags::NONE).expect("create");
        assert!(record.verify_checksum());
    }

    #[test]
    fn dataset_record_verify_checksum_detects_corruption() {
        let mut record =
            DatasetRecordV1::new("valid", 0, 1, DatasetCreateFlags::NONE).expect("create");
        // Corrupt the checksum
        record.checksum[0] ^= 0xFF;
        assert!(!record.verify_checksum());
    }

    #[test]
    fn dataset_record_name_extraction() {
        let record =
            DatasetRecordV1::new("my-dataset", 7, 42, DatasetCreateFlags::NONE).expect("create");
        assert_eq!(record.name(), "my-dataset");
    }

    #[test]
    fn dataset_record_name_empty_bytes() {
        let record = DatasetRecordV1::new("x", 0, 0, DatasetCreateFlags::NONE).expect("create");
        assert_eq!(record.name(), "x");
        assert_eq!(record.name_len, 1);
    }

    #[test]
    fn dataset_record_encode_deterministic() {
        let record = DatasetRecordV1::new("det", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let e1 = record.encode();
        let e2 = record.encode();
        assert_eq!(e1, e2);
        let decoded1 = DatasetRecordV1::decode(&e1).expect("decode1");
        let decoded2 = DatasetRecordV1::decode(&e2).expect("decode2");
        assert_eq!(decoded1, decoded2);
    }

    #[test]
    fn dataset_record_different_names_different_checksums() {
        let r1 = DatasetRecordV1::new("alpha", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let r2 = DatasetRecordV1::new("beta", 0, 1, DatasetCreateFlags::NONE).expect("create");
        assert_ne!(r1.checksum, r2.checksum);
    }

    #[test]
    fn dataset_record_different_parent_different_checksums() {
        let r1 = DatasetRecordV1::new("same", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let r2 = DatasetRecordV1::new("same", 1, 1, DatasetCreateFlags::NONE).expect("create");
        assert_ne!(r1.checksum, r2.checksum);
    }

    #[test]
    fn dataset_record_different_flags_different_checksums() {
        let r1 = DatasetRecordV1::new("same", 0, 1, DatasetCreateFlags::NONE).expect("create");
        let r2 = DatasetRecordV1::new("same", 0, 1, DatasetCreateFlags::READ_ONLY).expect("create");
        assert_ne!(r1.checksum, r2.checksum);
    }
}
